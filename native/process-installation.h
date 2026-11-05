#pragma once
#include <future>
#include <chrono>

// 安装端点只来自可信启动装配；不接受控制帧选择另一进程或管道。
namespace installation {
struct Json {
  sqlite3* db=nullptr;std::unique_ptr<sqlite3,DatabaseCloser> owner;
  explicit Json(){require(sqlite3_open(":memory:",&db)==SQLITE_OK,"installation_parse");owner.reset(db);}
};
class Fields:public WorkerFields {
public:
  Fields(sqlite3* db,const std::string& bytes,const std::string& service="",const std::string& database=""):WorkerFields(db,bytes,service,database){}
  using WorkerFields::text;using WorkerFields::id;using WorkerFields::number;using WorkerFields::digest;using WorkerFields::reference;
  std::string value(const std::string& at){Statement q(db,"SELECT json_extract(?1,?2)");q.bind(1,request);q.bind(2,at);require(sqlite3_step(q.value)==SQLITE_ROW,"installation_frame");return q.text(0);}
};
inline unsigned long long creation(HANDLE process){FILETIME born{},exit{},kernel{},user{};require(GetProcessTimes(process,&born,&exit,&kernel,&user)!=0,"installation_peer");return (static_cast<unsigned long long>(born.dwHighDateTime)<<32)|born.dwLowDateTime;}
inline std::string token(HANDLE process){
  Handle handle;require(OpenProcessToken(process,TOKEN_QUERY,&handle.value)!=0,"installation_peer");DWORD size=0;
  GetTokenInformation(handle.value,TokenUser,nullptr,0,&size);require(size>0&&size<=65536,"installation_peer");std::vector<unsigned char> bytes(size);
  require(GetTokenInformation(handle.value,TokenUser,bytes.data(),size,&size)!=0,"installation_peer");LPWSTR sid=nullptr;
  require(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(bytes.data())->User.Sid,&sid)!=0,"installation_peer");const auto user= utf8(sid);LocalFree(sid);
  TOKEN_STATISTICS statistics{};DWORD session=0,container=0;
  require(GetTokenInformation(handle.value,TokenStatistics,&statistics,sizeof(statistics),&size)&&statistics.TokenType==TokenPrimary&&
    GetTokenInformation(handle.value,TokenSessionId,&session,sizeof(session),&size)&&GetTokenInformation(handle.value,TokenIsAppContainer,&container,sizeof(container),&size)&&!container,"installation_peer");
  return bootstrap::object({{"user_sid",bootstrap::string(user)},{"session_id",std::to_string(session)},
    {"authentication_id",bootstrap::string(std::to_string(static_cast<unsigned long>(statistics.AuthenticationId.HighPart))+":"+std::to_string(statistics.AuthenticationId.LowPart))}});
}
struct Observation {std::string evidence,challenge;unsigned long long issued=0,expires=0;bool verified=false;};
class Client {
  Handle process,pipe;DWORD pid=0;unsigned long long born=0,sequence=1;bool failed=false;
  std::wstring name;std::string identity,channel,host,authority,database,observer;
  void transfer(void* data,DWORD size,bool writing,unsigned long long deadline){
    DWORD offset=0;
    while(offset<size){
      check();require(bootstrap::tick()<deadline,"installation_timeout");Handle event(CreateEventW(nullptr,TRUE,FALSE,nullptr));require(event.value,"installation_io");
      OVERLAPPED io{};io.hEvent=event.value;DWORD count=0;const auto pointer=static_cast<unsigned char*>(data)+offset;
      const BOOL ok=writing?WriteFile(pipe.value,pointer,size-offset,&count,&io):ReadFile(pipe.value,pointer,size-offset,&count,&io);
      const DWORD error=GetLastError();require(ok||error==ERROR_IO_PENDING,"installation_io");
      if(!ok){
        try{
          while(WaitForSingleObject(event.value,10)==WAIT_TIMEOUT){check();require(bootstrap::tick()<deadline,"installation_timeout");}
          require(GetOverlappedResult(pipe.value,&io,&count,FALSE)!=0,"installation_io");
        }catch(...){CancelIoEx(pipe.value,&io);GetOverlappedResult(pipe.value,&io,&count,TRUE);throw;}
      }
      require(count>0&&count<=size-offset,"installation_io");offset+=count;
    }
    check();require(bootstrap::tick()<deadline,"installation_timeout");
  }
  std::string exchange(const std::string& type,const std::string& payload,const std::string& responseType,unsigned long long deadline){
    using namespace bootstrap;require(!failed&&sequence<4096,"installation_closed");
    try{
      if(!pipe.value){
        pipe.value=CreateFileW(name.c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,FILE_FLAG_OVERLAPPED|SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION,nullptr);
        require(pipe.value!=INVALID_HANDLE_VALUE,"installation_connect");
      }
      check();const auto message=identifier(),seq=std::to_string(sequence);
      auto envelope=object({{"ipc_version",string("extension-import/0.1.0-draft.1")},{"type",string(type)},{"channel_id",string(channel)},
        {"sequence",string(seq)},{"message_id",string(message)},{"reply_to","null"},{"payload",payload}});
      require(envelope.size()<=65536,"installation_capacity");unsigned char prefix[4];const auto length=static_cast<unsigned long>(envelope.size());
      for(unsigned i=0;i<4;++i)prefix[i]=static_cast<unsigned char>((length>>(i*8))&255);
      transfer(prefix,4,true,deadline);transfer(envelope.data(),static_cast<DWORD>(envelope.size()),true,deadline);transfer(prefix,4,false,deadline);
      unsigned long count=0;for(unsigned i=0;i<4;++i)count|=static_cast<unsigned long>(prefix[i])<<(i*8);
      require(count>0&&count<=65536,"installation_capacity");std::string response(count,'\0');transfer(response.data(),count,false,deadline);
      Json json;Fields f(json.db,response);require(f.text("$.type")==responseType,"installation_result");
      require(f.text("$.ipc_version")=="extension-import/0.1.0-draft.1"&&f.id("$.channel_id")==channel&&f.number("$.sequence")==seq&&f.id("$.reply_to")==message,"installation_binding");
      const auto body=f.value("$.payload");require(response==object({{"ipc_version",string("extension-import/0.1.0-draft.1")},{"type",string(responseType)},
        {"channel_id",string(channel)},{"sequence",string(seq)},{"message_id",string(f.id("$.message_id"))},{"reply_to",string(message)},{"payload",body}}),"installation_frame");
      ++sequence;return body;
    }catch(...){failed=true;pipe.reset();throw;}
  }
public:
  explicit Client(const std::string& config){
    using namespace bootstrap;require(config.size()<=8192,"installation_config");Json json;Fields f(json.db,config);
    require(f.text("$.format")=="leafseamer-installation-peer/1","installation_config");
    const auto suffix=f.id("$.pipe_suffix");require(suffix.size()<=80,"installation_config");
    for(const char c:suffix)require((c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='-',"installation_config");
    name=L"\\\\.\\pipe\\LeafSeamer.Install."+std::wstring(suffix.begin(),suffix.end());channel=f.id("$.channel_id");
    host=f.id("$.host_installation_id");authority=f.id("$.authority_service_id");database=f.id("$.database_instance_id");
    const auto pidText=f.number("$.server_pid"),created=f.number("$.server_creation_time");const auto parsed=std::stoull(pidText);
    require(parsed>0&&parsed<=MAXDWORD,"installation_config");pid=static_cast<DWORD>(parsed);born=std::stoull(created);
    const auto session=f.number("$.session_id");require(std::stoull(session)<=MAXDWORD,"installation_config");
    identity=object({{"user_sid",string(f.text("$.user_sid"))},{"session_id",session},{"authentication_id",string(f.text("$.authentication_id"))}});
    observer=object({{"clock_domain_id",string(f.id("$.observer_domain.clock_domain_id"))},{"descriptor_digest",string(f.digest("$.observer_domain.descriptor_digest"))}});
    require(config==object({{"format",string("leafseamer-installation-peer/1")},{"pipe_suffix",string(suffix)},{"channel_id",string(channel)},
      {"host_installation_id",string(host)},{"authority_service_id",string(authority)},{"database_instance_id",string(database)},
      {"server_pid",string(pidText)},{"server_creation_time",string(created)},{"session_id",string(session)},
      {"user_sid",string(f.text("$.user_sid"))},{"authentication_id",string(f.text("$.authentication_id"))},{"observer_domain",observer}}),"installation_config");
    process.value=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,pid);require(process.value,"installation_peer");check();
  }
  void check()const{
    require(!failed&&WaitForSingleObject(process.value,0)==WAIT_TIMEOUT&&GetProcessId(process.value)==pid&&creation(process.value)==born&&token(process.value)==identity,"installation_peer");
    if(pipe.value){ULONG actual=0;require(pipe.value!=INVALID_HANDLE_VALUE&&GetNamedPipeServerProcessId(pipe.value,&actual)&&actual==pid,"installation_peer");}
  }
  Observation observe(const std::string& intent,const std::string& intentDigest){
    using namespace bootstrap;Observation result;const auto end=tick()+4000000000ULL;
    Json json;Fields source(json.db,intent);const auto bind="$.extension_binding.";
    const auto intake=source.id(std::string(bind)+"intake_ref.object_id"),service=source.id("$.service_id");
    require(source.id(std::string(bind)+"host_installation_id")==host,"installation_binding");
    const auto intakeResponse=exchange("INTAKE_QUERY",object({{"intake_id",string(intake)},{"target_authority_service_id",string(service)}}),"INTAKE_RESULT",end);
    Fields available(json.db,intakeResponse,authority,database);require(available.text("$.status")=="available"&&available.id("$.intake_id")==intake,"installation_unavailable");
    Object receipt;for(const auto field:{"host_installation_id","import_operation_id","intake_id","target_authority_service_id"})receipt[field]=string(available.id(std::string("$.receipt.")+field));
    for(const auto field:{"host_trust_epoch","package_bytes"})receipt[field]=string(available.number(std::string("$.receipt.")+field));
    for(const auto field:{"manifest_digest","artifact_set_digest","file_inventory_digest","dependency_lock_digest"})receipt[field]=string(available.digest(std::string("$.receipt.")+field));
    for(const auto& pair:std::vector<std::pair<std::string,std::string>>{{"platform_profile_ref","platform_profile"},{"validation_policy_ref","validation_policy"},{"release_authorization_ref","release_authorization"},{"verification_record_ref","verification"}})
      receipt[pair.first]=available.reference("$.receipt."+pair.first,pair.second,true);
    require(available.authorized&&intakeResponse==object({{"intake_id",string(intake)},{"status",string("available")},{"receipt",object(receipt)}}),"installation_receipt");
    const auto intakeRef=object({{"kind",string("intake")},{"authority_service_id",string(authority)},{"database_instance_id",string(database)},
      {"object_id",string(intake)},{"revision",string("1")},{"digest",string(digest(object(receipt)))}});
    require(source.reference(std::string(bind)+"intake_ref","intake")==intakeRef&&receipt.at("intake_id")==string(intake)&&receipt.at("host_installation_id")==string(host)&&
      receipt.at("target_authority_service_id")==string(service)&&receipt.at("platform_profile_ref")==source.reference(std::string(bind)+"platform_profile_ref","platform_profile"),"installation_receipt_binding");
    for(const auto field:{"host_trust_epoch","manifest_digest","artifact_set_digest"})require(receipt.at(field)==string(source.text(std::string(bind)+field)),"installation_receipt_binding");
    result.challenge=identifier();result.issued=tick();result.expires=result.issued+5000000000ULL;
    const auto request=object({{"intake_id",string(intake)},{"target_authority_service_id",string(service)},{"manifest_digest",receipt.at("manifest_digest")},
      {"artifact_set_digest",receipt.at("artifact_set_digest")},{"host_trust_epoch",receipt.at("host_trust_epoch")},{"challenge_id",string(result.challenge)},{"launch_intent_digest",string(intentDigest)}});
    const auto response=exchange("VERIFY_MATERIALIZATION",request,"MATERIALIZATION_RESULT",end);Fields observed(json.db,response);
    result.evidence=observed.id("$.evidence_id");const auto stamp=observed.number("$.observed_tick");
    require(response==object({{"request",request},{"result",string("verified")},{"evidence_id",string(result.evidence)},
      {"observer_domain",observer},{"observed_tick",string(stamp)}})&&tick()<result.expires,"installation_observation");
    check();result.verified=true;return result;
  }
};
}
