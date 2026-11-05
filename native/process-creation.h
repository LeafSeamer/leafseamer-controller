#pragma once

class WorkerContext {
  Handle held;
public:
  std::wstring path;
  std::string digest;
  WorkerContext(Instance& owner,const std::string& body){try{
    require(body.size()<=16777216,"worker_context_capacity");const auto id=identifier();
    path=owner.path+L"\\worker-start-"+std::wstring(id.begin(),id.end())+L".json";digest=bootstrap::digest(body);
    Handle file(CreateFileW(path.c_str(),GENERIC_WRITE,FILE_SHARE_READ,&owner.security,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr));
    require(file.value!=INVALID_HANDLE_VALUE,"worker_context_create");DWORD count=0;
    require(WriteFile(file.value,body.data(),static_cast<DWORD>(body.size()),&count,nullptr)&&count==body.size()&&FlushFileBuffers(file.value),"worker_context_write");
    file.reset();held.value=CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    require(held.value!=INVALID_HANDLE_VALUE&&bootstrap::digest(runtime::manifestBytes(path))==digest,"worker_context_binding");
    }catch(...){held.reset();if(!path.empty())DeleteFileW(path.c_str());throw;}
  }
  ~WorkerContext(){held.reset();if(!path.empty())DeleteFileW(path.c_str());}
};

class WorkerProcess {
  WorkerGroup& group;
  HANDLE rootJob;
  runtime::Protected& runtime;
  Handle process,thread,inputWriter,proofReader;
  std::unique_ptr<WorkerContext> context;
  std::unique_ptr<ModuleLink> moduleLink;
  std::future<bool> proof;
  bool finished=false,verified=false;
public:
  bootstrap::Exchange exchange;
  std::string creationId=identifier(),observationId=identifier(),observation;
  WorkerProcess(Instance& owner,WorkerGroup& target,HANDLE parent,runtime::Protected& installed,const bootstrap::Domain& core,
      const std::string& launch,const WorkerStored& stored,const loading::Materials& materials,DWORD corePid):group(target),rootJob(parent),runtime(installed),
      exchange(core,launch,stored.intent,stored.member,bootstrap::object({{"group_id",bootstrap::string(stored.group)},
        {"generation",bootstrap::string(stored.generation)},{"backend",bootstrap::string("windows_job")}})){
    using namespace bootstrap;
    moduleLink=std::make_unique<ModuleLink>(owner,exchange.memberBoot,corePid);
    context=std::make_unique<WorkerContext>(owner,object({{"format",string("leafseamer-device-worker-start/2")},{"intent",stored.intent},{"module",materials.moduleContext},
      {"descriptor",core.descriptor},{"identity",object({{"service_id",string(core.policy.service)},{"database_instance_id",string(core.policy.database)}})},
      {"timeout_ms",std::to_string(core.policy.timeout)}}));
  }
  ~WorkerProcess(){try{stop();if(proof.valid())proof.wait();}catch(...){}}
  std::string creation(const std::string& grant,const std::string& loadId,const std::string& rootIdentity)const{
    using namespace bootstrap;
    return object({{"format",string("leafseamer-worker-creation/1")},{"creation_id",string(creationId)},{"authorization",grant},
      {"load_id",string(loadId)},{"root_identity",string(rootIdentity)},{"runtime_digest",string(runtime.digest)},
      {"context_digest",string(context->digest)},{"bootstrap_id",string(exchange.bootstrapId)},{"member_boot_id",string(exchange.memberBoot)},
      {"started_tick_ns",string(std::to_string(exchange.issued))}});
  }
  void create(){
    using namespace bootstrap;require(rootJob&&group.unusedAndEmpty(),"worker_group_initial");
    SECURITY_ATTRIBUTES security{sizeof(security),nullptr,TRUE};Handle input,output,errors;
    require(CreatePipe(&input.value,&inputWriter.value,&security,32768)&&SetHandleInformation(inputWriter.value,HANDLE_FLAG_INHERIT,0),"worker_pipe");
    require(CreatePipe(&proofReader.value,&output.value,&security,32768)&&SetHandleInformation(proofReader.value,HANDLE_FLAG_INHERIT,0),"worker_pipe");
    require(DuplicateHandle(GetCurrentProcess(),GetStdHandle(STD_ERROR_HANDLE),GetCurrentProcess(),&errors.value,0,TRUE,DUPLICATE_SAME_ACCESS),"worker_output");Attributes attributes;HANDLE jobs[]{rootJob,group.native()},inherited[]{input.value,output.value,errors.value};
    require(UpdateProcThreadAttribute(attributes.list,0,PROC_THREAD_ATTRIBUTE_JOB_LIST,jobs,sizeof(jobs),nullptr,nullptr)&&
      UpdateProcThreadAttribute(attributes.list,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,inherited,sizeof(inherited),nullptr,nullptr),"worker_attributes");
    STARTUPINFOEXW startup{};startup.StartupInfo.cb=sizeof(startup);startup.lpAttributeList=attributes.list;startup.StartupInfo.dwFlags=STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput=input.value;startup.StartupInfo.hStdOutput=output.value;startup.StartupInfo.hStdError=errors.value;
    const auto entry=runtime.root+L"\\device-worker-entry.mjs";
    std::wstring command=quote(runtime.node)+L" --disallow-code-generation-from-strings "+quote(entry)+L" --context-file "+quote(context->path)+
      L" --context-digest "+quote(std::wstring(context->digest.begin(),context->digest.end()));
    require(command.size()<32767,"worker_arguments");auto environment=runtime::environment();PROCESS_INFORMATION result{};
    require(CreateProcessW(runtime.node.c_str(),command.data(),nullptr,nullptr,TRUE,EXTENDED_STARTUPINFO_PRESENT|CREATE_SUSPENDED|CREATE_NO_WINDOW|CREATE_UNICODE_ENVIRONMENT,
      environment.data(),runtime.root.c_str(),&startup.StartupInfo,&result)!=0,"worker_create_failed");
    process.value=result.hProcess;thread.value=result.hThread;require(alive()&&group.counts().TotalProcesses==1,"worker_containment");
    std::vector<wchar_t> image(32768);DWORD size=static_cast<DWORD>(image.size());require(QueryFullProcessImageNameW(process.value,0,image.data(),&size),"worker_image");
    Handle actual(CreateFileW(image.data(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,0,nullptr));
    Handle expected(CreateFileW(runtime.node.c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,0,nullptr));
    require(actual.value!=INVALID_HANDLE_VALUE&&expected.value!=INVALID_HANDLE_VALUE&&fileIdentity(actual.value)==fileIdentity(expected.value),"worker_image");
    observation=object({{"format",string("leafseamer-worker-process-observation/1")},{"observation_id",string(observationId)},
      {"creation_id",string(creationId)},{"pid",string(std::to_string(result.dwProcessId))},{"creation_time",string(std::to_string(installation::creation(process.value)))},
      {"image_file_id",string(fileIdentity(actual.value))},{"containment_ref",exchange.containment},{"domain_ref",object({{"clock_domain_id",string(exchange.domainId)},
      {"descriptor_digest",string(exchange.descriptorDigest)}})},{"observed_tick_ns",string(std::to_string(tick()))},{"created_suspended","true"},{"assigned_at_creation","true"}});
  }
  void run(){
    require(bootstrap::tick()<exchange.expires&&ResumeThread(thread.value)!=static_cast<DWORD>(-1),"worker_resume");thread.reset();
    proof=std::async(std::launch::async,[this](){try{bootstrap::write(inputWriter.value,exchange.assignment());
      require(bootstrap::equal(bootstrap::read(proofReader.value,process.value,exchange.expires),exchange.expectedProof()),"worker_proof_mismatch");return true;
      }catch(const std::exception& error){const std::string reason=error.what();const auto code=reason.size()<=96&&reason.find_first_not_of("abcdefghijklmnopqrstuvwxyz_0123456789")==std::string::npos?reason:"worker_bootstrap_internal";
        fprintf(stderr,"{\"event\":\"worker_bootstrap_failure\",\"code\":\"%s\"}\n",code.c_str());fflush(stderr);return false;}});
  }
  bool alive()const{
    if(!process.value||WaitForSingleObject(process.value,0)!=WAIT_TIMEOUT)return false;BOOL own=FALSE,parent=FALSE;
    require(IsProcessInJob(process.value,group.native(),&own)&&IsProcessInJob(process.value,rootJob,&parent),"worker_containment");return own&&parent;
  }
  bool proofDone(){if(proof.valid()&&proof.wait_for(std::chrono::milliseconds(0))==std::future_status::ready){verified=proof.get();finished=true;}return finished;}
  bool qualified(){const bool live=alive(),timely=bootstrap::tick()<exchange.expires;const auto count=group.counts().ActiveProcesses;
    // 根进程身份与定向证明已经核验；运行后后代由同一Job持续纳管，退役须观察整个组为空。
    const bool ok=finished&&verified&&live&&timely&&count>=1;
    if(!ok){fprintf(stderr,"{\"event\":\"worker_qualification_failure\",\"finished\":%d,\"verified\":%d,\"alive\":%d,\"timely\":%d,\"active\":%lu}\n",finished,verified,live,timely,count);fflush(stderr);}return ok;}
  void admit(const bootstrap::Object& receipt){require(qualified(),"worker_bootstrap");bootstrap::write(inputWriter.value,bootstrap::Exchange::frame("ADMISSION",receipt));require(qualified(),"worker_bootstrap");
    SecureZeroMemory(exchange.secret.bytes.data(),exchange.secret.bytes.size());SecureZeroMemory(exchange.nonce.bytes.data(),exchange.nonce.bytes.size());context.reset();}
  bool quiet(){DWORD count=0;return alive()&&PeekNamedPipe(proofReader.value,nullptr,0,nullptr,&count,nullptr)&&count==0;}
  bool moduleCurrent(){try{moduleLink->poll(GetProcessId(process.value));return true;}catch(...){return false;}}
  void stop(){if(process.value)require(TerminateJobObject(group.native(),1)!=0,"worker_termination");}
};
