#pragma once

// 独立业务字节通路。监督器只转发创建时绑定的核心/worker，不解析或授权设备动作。
// 每方向只有一块有界缓冲，背压不阻塞监督线程，断连不允许重新认领。
class ModuleLink {
  struct Port {
    Handle pipe,connectedEvent,readEvent,writeEvent;
    OVERLAPPED connecting{},reading{},writing{};
    bool connectPending=false,connectInline=false,connected=false,readPending=false,writePending=false;
    std::array<char,65536> input{},output{};
    DWORD inputSize=0,outputSize=0;
    Port(Instance& owner,const std::wstring& name){
      pipe.value=CreateNamedPipeW(name.c_str(),PIPE_ACCESS_DUPLEX|FILE_FLAG_OVERLAPPED|FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,1,65536,65536,0,&owner.security);
      require(pipe.value!=INVALID_HANDLE_VALUE,"module_link_endpoint");
      connectedEvent.value=CreateEventW(nullptr,TRUE,FALSE,nullptr);readEvent.value=CreateEventW(nullptr,TRUE,FALSE,nullptr);writeEvent.value=CreateEventW(nullptr,TRUE,FALSE,nullptr);
      require(connectedEvent.value&&readEvent.value&&writeEvent.value,"module_link_event");
      connecting.hEvent=connectedEvent.value;const BOOL ok=ConnectNamedPipe(pipe.value,&connecting);const auto error=GetLastError();
      connectInline=!ok&&error==ERROR_PIPE_CONNECTED;
      require(ok||connectInline||error==ERROR_IO_PENDING,"module_link_connect");connectPending=true;
      if(ok||connectInline)require(SetEvent(connectedEvent.value)!=0,"module_link_event");
    }
    ~Port(){
      if(pipe.value&&pipe.value!=INVALID_HANDLE_VALUE){
        CancelIoEx(pipe.value,nullptr);DWORD ignored=0;
        if(connectPending&&!connectInline)GetOverlappedResult(pipe.value,&connecting,&ignored,TRUE);
        if(readPending)GetOverlappedResult(pipe.value,&reading,&ignored,TRUE);
        if(writePending)GetOverlappedResult(pipe.value,&writing,&ignored,TRUE);
      }
    }
    void connect(DWORD expected){
      if(connected)return;const auto wait=WaitForSingleObject(connectedEvent.value,0);if(wait==WAIT_TIMEOUT)return;
      require(wait==WAIT_OBJECT_0&&connectPending&&expected!=0,"module_link_connect");DWORD count=0;
      if(!connectInline)require(GetOverlappedResult(pipe.value,&connecting,&count,FALSE)!=0,"module_link_connect");
      connectPending=false;ULONG actual=0;require(GetNamedPipeClientProcessId(pipe.value,&actual)&&actual==expected,"module_link_peer");connected=true;
    }
    void read(){
      if(!connected||inputSize)return;
      if(!readPending){
        require(ResetEvent(readEvent.value)!=0,"module_link_event");reading={};reading.hEvent=readEvent.value;DWORD count=0;
        const BOOL ok=ReadFile(pipe.value,input.data(),static_cast<DWORD>(input.size()),&count,&reading);
        require(ok||GetLastError()==ERROR_IO_PENDING,"module_link_read");readPending=true;
        if(ok)require(SetEvent(readEvent.value)!=0,"module_link_event");
      }
      if(WaitForSingleObject(readEvent.value,0)==WAIT_TIMEOUT)return;DWORD count=0;
      require(GetOverlappedResult(pipe.value,&reading,&count,FALSE)&&count>0&&count<=input.size(),"module_link_read");readPending=false;inputSize=count;
    }
    void flush(){
      if(!writePending)return;if(WaitForSingleObject(writeEvent.value,0)==WAIT_TIMEOUT)return;DWORD count=0;
      require(GetOverlappedResult(pipe.value,&writing,&count,FALSE)&&count==outputSize,"module_link_write");writePending=false;outputSize=0;
    }
    void forward(Port& target){
      if(!inputSize||!target.connected||target.writePending)return;
      std::copy(input.begin(),input.begin()+inputSize,target.output.begin());target.outputSize=inputSize;inputSize=0;
      require(ResetEvent(target.writeEvent.value)!=0,"module_link_event");target.writing={};target.writing.hEvent=target.writeEvent.value;DWORD count=0;
      const BOOL ok=WriteFile(target.pipe.value,target.output.data(),target.outputSize,&count,&target.writing);
      require(ok||GetLastError()==ERROR_IO_PENDING,"module_link_write");target.writePending=true;
      if(ok)require(SetEvent(target.writeEvent.value)!=0,"module_link_event");
    }
  };
  Port core,worker;
  DWORD corePid;
  static std::wstring name(const std::string& boot,const wchar_t* side){
    require(boot.size()==32&&boot.find_first_not_of("0123456789abcdef")==std::string::npos,"module_link_identity");
    return L"\\\\.\\pipe\\LeafSeamer.Module."+std::wstring(boot.begin(),boot.end())+side;
  }
public:
  ModuleLink(Instance& owner,const std::string& boot,DWORD pid):core(owner,name(boot,L".core")),worker(owner,name(boot,L".worker")),corePid(pid){require(pid!=0,"module_link_peer");}
  void poll(DWORD workerPid){
    core.connect(corePid);worker.connect(workerPid);core.flush();worker.flush();core.read();worker.read();core.forward(worker);worker.forward(core);
  }
};
