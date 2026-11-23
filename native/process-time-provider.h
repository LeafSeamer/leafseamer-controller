#pragma once

class TimeProviderProcess {
  ProcessJournal& journal;
  const std::string launch,coreAttempt,intent,intentDigest;
  std::string admittedReceipt;
  Handle job,process,input,proof;
  std::unique_ptr<ModuleLink> link;
public:
  DWORD pid=0,exitCode=1;
  bool forced=false;

  TimeProviderProcess(Instance& instance,ProcessJournal& log,HANDLE rootJob,runtime::Protected& installed,
      const bootstrap::Exchange& exchange,const std::string& launchId,const std::string& coreId,unsigned long long coreExpiry,
      DWORD corePid,const std::string& coreReceipt)
      :journal(log),launch(launchId),coreAttempt(coreId),intent(exchange.intent),intentDigest(exchange.intentDigest){
    const auto& policy=exchange.policy;
    require(!installed.timeProviderDigest.empty()&&policy.manifestDigest==installed.timeProviderDigest,"time_provider_artifact");
    installed.check();
    const auto name=L"Global\\LeafSeamer.Time."+loading::wide(launch);
    job.value=CreateJobObjectW(&instance.security,name.c_str());
    const DWORD jobError=GetLastError();
    require(job.value&&jobError!=ERROR_ALREADY_EXISTS,"time_provider_job");
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE|JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    limits.BasicLimitInformation.ActiveProcessLimit=1;
    require(SetInformationJobObject(job.value,JobObjectExtendedLimitInformation,&limits,sizeof(limits))!=0,"time_provider_job");
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION current{};
    require(QueryInformationJobObject(job.value,JobObjectExtendedLimitInformation,&current,sizeof(current),nullptr)!=0&&
      current.BasicLimitInformation.LimitFlags==limits.BasicLimitInformation.LimitFlags&&
      current.BasicLimitInformation.ActiveProcessLimit==1,"time_provider_job");
    SECURITY_ATTRIBUTES sa{sizeof(sa),nullptr,TRUE};Handle childIn,childOut,childError;
    require(CreatePipe(&childIn.value,&input.value,&sa,32768)!=0&&SetHandleInformation(input.value,HANDLE_FLAG_INHERIT,0)!=0&&
      CreatePipe(&proof.value,&childOut.value,&sa,32768)!=0&&SetHandleInformation(proof.value,HANDLE_FLAG_INHERIT,0)!=0,"time_provider_pipe");
    require(DuplicateHandle(GetCurrentProcess(),GetStdHandle(STD_ERROR_HANDLE),GetCurrentProcess(),&childError.value,0,TRUE,DUPLICATE_SAME_ACCESS)!=0,
      "time_provider_pipe");
    Attributes attributes;
    HANDLE jobs[]={rootJob,job.value},handles[]={childIn.value,childOut.value,childError.value};
    require(UpdateProcThreadAttribute(attributes.list,0,PROC_THREAD_ATTRIBUTE_JOB_LIST,jobs,sizeof(jobs),nullptr,nullptr)!=0&&
      UpdateProcThreadAttribute(attributes.list,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,handles,sizeof(handles),nullptr,nullptr)!=0,
      "time_provider_attributes");
    STARTUPINFOEXW startup{};startup.StartupInfo.cb=sizeof(startup);startup.lpAttributeList=attributes.list;
    startup.StartupInfo.dwFlags=STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput=childIn.value;startup.StartupInfo.hStdOutput=childOut.value;startup.StartupInfo.hStdError=childError.value;
    const auto image=installed.root+L"\\runtime\\reference-time-provider.exe";
    const auto deadline=std::min(coreExpiry,exchange.expires);
    require(bootstrap::tick()<deadline,"time_provider_bootstrap_expired");
    std::wstring command=quote(image)+L" --intent "+quote(loading::wide(exchange.intent))+
      L" --domain "+quote(loading::wide(exchange.descriptor))+L" --timeout-ms "+std::to_wstring(policy.timeout)+
      L" --core-receipt-id "+quote(loading::wide(coreReceipt))+L" --database-instance "+quote(loading::wide(policy.database));
    require(command.size()<32767,"time_provider_command");
    link=std::make_unique<ModuleLink>(instance,exchange.memberBoot,corePid,ModuleLink::Kind::timeProvider);
    journal.beginTimeProvider(coreAttempt,launch,name,policy.body,exchange.intent);
    PROCESS_INFORMATION pi{};auto env=runtime::environment();
    require(CreateProcessW(image.c_str(),command.data(),nullptr,nullptr,TRUE,
      EXTENDED_STARTUPINFO_PRESENT|CREATE_SUSPENDED|CREATE_NO_WINDOW|CREATE_UNICODE_ENVIRONMENT,
      env.data(),installed.root.c_str(),&startup.StartupInfo,&pi)!=0,"time_provider_create");
    process.value=pi.hProcess;Handle thread(pi.hThread);pid=pi.dwProcessId;
    childIn.reset();childOut.reset();childError.reset();
    BOOL inRoot=FALSE,inPrivate=FALSE;
    require(IsProcessInJob(process.value,rootJob,&inRoot)!=0&&inRoot&&
      IsProcessInJob(process.value,job.value,&inPrivate)!=0&&inPrivate&&active(job.value)==1,"time_provider_containment");
    Handle loaded;verifyProcessImage(process.value,image,loaded);
    journal.observeTimeProvider(launch,process.value,pid,loaded.value,bootstrap::tick());
    require(ResumeThread(thread.value)==1,"time_provider_resume");
    thread.reset();
    bootstrap::write(input.value,exchange.assignment());
    const auto reply=bootstrap::read(proof.value,process.value,deadline);
    require(bootstrap::tick()<deadline,"time_provider_bootstrap_expired");
    require(bootstrap::equal(reply,exchange.expectedProof()),"time_provider_proof");
    require(WaitForSingleObject(process.value,0)==WAIT_TIMEOUT,"time_provider_not_live");
    const auto members=active(job.value);
    if(members!=1){
      fprintf(stderr,"{\"event\":\"time_provider_job_members\",\"active_processes\":%lu}\n",members);
      fflush(stderr);
    }
    require(members==1,"time_provider_job_members");
    const auto receipt=exchange.receipt(launch);
    admittedReceipt=bootstrap::object(receipt);
    journal.admitTimeProvider(launch,exchange.receiptId,admittedReceipt);
    require(bootstrap::tick()<deadline,"time_provider_bootstrap_expired");
    bootstrap::write(input.value,bootstrap::Exchange::frame("ADMISSION",receipt));
  }

  bool healthy(){
    DWORD extra=0;
    return WaitForSingleObject(process.value,0)==WAIT_TIMEOUT&&
      PeekNamedPipe(proof.value,nullptr,0,nullptr,&extra,nullptr)!=0&&extra==0;
  }

  void pollLink(){link->poll(pid);}

  const std::string& launchId()const{return launch;}
  const std::string& launchDigest()const{return intentDigest;}

  TimeProviderRecorded currentRecord(){
    BOOL belongs=FALSE;
    if(!healthy()||!IsProcessInJob(process.value,job.value,&belongs)||!belongs||active(job.value)!=1)return {};
    const auto original=journal.timeProviderAdmission(coreAttempt,launch,intent);
    require(original.receipt==admittedReceipt&&original.pid==std::to_string(pid),"time_provider_journal_binding");
    return original;
  }

  void retire(){
    input.reset();
    if(WaitForSingleObject(process.value,2000)!=WAIT_OBJECT_0)forced=true;
    if(active(job.value)!=0){
      forced=true;
      require(TerminateJobObject(job.value,1)!=0,"time_provider_terminate");
    }
    const auto deadline=GetTickCount64()+5000;
    while(active(job.value)!=0){require(GetTickCount64()<deadline,"time_provider_exit_unproven");Sleep(10);}
    require(WaitForSingleObject(process.value,5000)==WAIT_OBJECT_0&&GetExitCodeProcess(process.value,&exitCode)!=0,
      "time_provider_exit_unproven");
    journal.retireTimeProvider(launch,exitCode,forced);
  }
};
