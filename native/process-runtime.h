#pragma once

// 固定宿主自身安装目录。控制请求不能选择解释器、运行库、入口或环境。
namespace runtime {
inline std::wstring directory(const std::wstring& path){
  const auto at=path.find_last_of(L"\\/");require(at!=std::wstring::npos,"runtime_path");return path.substr(0,at);
}
inline std::wstring installationRoot(){
  std::vector<wchar_t> buffer(32768);const DWORD size=GetModuleFileNameW(nullptr,buffer.data(),static_cast<DWORD>(buffer.size()));
  require(size>0&&size<buffer.size(),"runtime_path");return directory(directory(std::wstring(buffer.data(),size)));
}
inline unsigned long long sizeOf(const std::wstring& path){
  Handle file(CreateFileW(path.c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
  require(file.value!=INVALID_HANDLE_VALUE,"runtime_file");const auto info=content::inspect(file.value,false);
  require(info.EndOfFile.QuadPart>=0,"runtime_file");return static_cast<unsigned long long>(info.EndOfFile.QuadPart);
}
inline std::string manifestBytes(const std::wstring& path){
  Handle file(CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
  require(file.value!=INVALID_HANDLE_VALUE,"runtime_manifest");const auto info=content::inspect(file.value,false);
  require(info.EndOfFile.QuadPart>0&&info.EndOfFile.QuadPart<=1048576,"runtime_manifest");
  std::string bytes(static_cast<size_t>(info.EndOfFile.QuadPart),'\0');DWORD read=0;
  require(ReadFile(file.value,bytes.data(),static_cast<DWORD>(bytes.size()),&read,nullptr)&&read==bytes.size(),"runtime_manifest");return bytes;
}
inline std::vector<wchar_t> environment(){
  std::vector<wchar_t> windows(32768),temporary(32768);const auto count=GetWindowsDirectoryW(windows.data(),static_cast<UINT>(windows.size()));
  const auto tempCount=GetTempPathW(static_cast<DWORD>(temporary.size()),temporary.data());
  require(count>0&&count<windows.size()&&tempCount>0&&tempCount<temporary.size(),"runtime_environment");
  const std::wstring system(windows.data(),count),temp(temporary.data(),tempCount);std::wstring block;
  for(const auto& entry:std::vector<std::wstring>{L"SystemRoot="+system,L"TEMP="+temp,L"TMP="+temp,L"WINDIR="+system}){block+=entry;block.push_back(L'\0');}
  block.push_back(L'\0');return std::vector<wchar_t>(block.begin(),block.end());
}
class Protected {
  std::unique_ptr<content::Pin> pin;
public:
  std::wstring root,node;
  std::string digest;
  explicit Protected(const std::string& expectedManifest){
    using namespace bootstrap;
    root=installationRoot();const auto bytes=manifestBytes(root+L"\\build-manifest.json");
    installation::Json json;installation::Fields fields(json.db,bytes),expected(json.db,expectedManifest);
    require(fields.text("$.format")=="leafseamer-controller-build/1","runtime_manifest");
    std::vector<content::Entry> files;std::string nodeHash;
    Statement rows(json.db,"SELECT key,value,type FROM json_each(?1,'$.artifacts')");rows.bind(1,bytes);
    while(sqlite3_step(rows.value)==SQLITE_ROW){
      require(files.size()<4096&&rows.text(2)=="text","runtime_inventory");const auto name=rows.text(0),hash=rows.text(1);
      require(hash.size()==64&&hash.find_first_not_of("0123456789abcdef")==std::string::npos,"runtime_inventory");
      const auto path=loading::wide(name);content::parts(path,L'/');
      files.push_back({path,sizeOf(root+L"\\"+path),"sha256:"+hash});if(name=="runtime/node.exe")nodeHash=hash;
    }
    require(!nodeHash.empty(),"runtime_node");const auto buildHash=bootstrap::digest(bytes);
    digest=bootstrap::digest(object({{"controller_build_sha256",string(buildHash.substr(7))},{"node_sha256",string(nodeHash)}}));
    require(expected.digest("$.digest")==digest,"runtime_binding");
    files.push_back({L"build-manifest.json",static_cast<unsigned long long>(bytes.size()),buildHash});
    pin=std::make_unique<content::Pin>(root,files,5000);node=root+L"\\runtime\\node.exe";
  }
  void check(){pin->check(1000);}
};
}
