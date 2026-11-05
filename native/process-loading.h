#pragma once
#include "content-root.h"

namespace loading {
inline std::wstring wide(const std::string& value){
  require(!value.empty()&&value.find('\0')==std::string::npos,"load_path");
  const int count=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,value.data(),static_cast<int>(value.size()),nullptr,0);
  require(count>0&&count<=32760,"load_path");std::wstring out(count,L'\0');
  require(MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,value.data(),static_cast<int>(value.size()),out.data(),count)==count,"load_path");return out;
}
inline std::string base64(const std::string& encoded){
  require(!encoded.empty()&&encoded.size()<=65536&&encoded.size()%4==0,"load_chunk");std::string out;
  const auto digit=[](char c)->unsigned{if(c>='A'&&c<='Z')return c-'A';if(c>='a'&&c<='z')return c-'a'+26;
    if(c>='0'&&c<='9')return c-'0'+52;if(c=='+')return 62;if(c=='/')return 63;throw std::runtime_error("load_chunk");};
  for(size_t i=0;i<encoded.size();i+=4){
    const unsigned a=digit(encoded[i]),b=digit(encoded[i+1]);out+=static_cast<char>((a<<2)|(b>>4));
    if(encoded[i+2]=='='){require(i+4==encoded.size()&&encoded[i+3]=='='&&(b&15)==0,"load_chunk");break;}
    const unsigned c=digit(encoded[i+2]);out+=static_cast<char>((b<<4)|(c>>2));
    if(encoded[i+3]=='='){require(i+4==encoded.size()&&(c&3)==0,"load_chunk");break;}
    out+=static_cast<char>((c<<6)|digit(encoded[i+3]));
  }return out;
}
inline unsigned long long integer(sqlite3* db,const std::string& body,const std::string& at){
  Statement q(db,"SELECT json_type(?1,?2),json_extract(?1,?2)");q.bind(1,body);q.bind(2,at);
  require(sqlite3_step(q.value)==SQLITE_ROW&&q.text(0)=="integer"&&sqlite3_column_int64(q.value,1)>=0,"load_number");
  return static_cast<unsigned long long>(sqlite3_column_int64(q.value,1));
}
inline std::string quote(sqlite3* db,const std::string& body,const std::string& at){
  Statement q(db,"SELECT json_quote(json_extract(?1,?2))");q.bind(1,body);q.bind(2,at);require(sqlite3_step(q.value)==SQLITE_ROW,"load_json");return q.text(0);
}
struct Materials {
  std::unique_ptr<content::Pin> pin;
  std::string rootIdentity,entryFile,policyFile,manifestDigest,artifactDigest,moduleContext;
  std::wstring root,entryPath;
  Materials(const std::string& bytes,const std::string& intent){
    using namespace bootstrap;installation::Json json;installation::Fields f(json.db,bytes),target(json.db,intent);
    const auto manifest=f.value("$.manifest"),inventory=f.value("$.inventory"),rootPath=f.text("$.root_path");rootIdentity=f.text("$.root_identity");
    require(rootIdentity.size()==48&&rootIdentity.find_first_not_of("0123456789abcdef")==std::string::npos&&f.text("$.format")=="leafseamer-worker-load/1","load_materials");
    require(bytes==object({{"format",string("leafseamer-worker-load/1")},{"root_path",quote(json.db,bytes,"$.root_path")},
      {"root_identity",string(rootIdentity)},{"manifest",manifest},{"inventory",inventory}}),"load_materials");
    manifestDigest=digest(manifest);artifactDigest=digest(inventory);
    require(manifestDigest==target.digest("$.extension_binding.manifest_digest")&&artifactDigest==target.digest("$.extension_binding.artifact_set_digest")&&
      f.digest("$.manifest.inventory_digest")==artifactDigest&&f.text("$.manifest.kind")=="device_module"&&f.text("$.inventory.inventory_version")=="extension-files/1","load_binding");
    const auto entryId=target.id("$.extension_binding.entry_id");bool selected=false;
    Statement entries(json.db,"SELECT value FROM json_each(?1,'$.manifest.entrypoints')");entries.bind(1,bytes);
    while(sqlite3_step(entries.value)==SQLITE_ROW){const auto body=entries.text(0);installation::Fields entry(json.db,body);
      if(entry.id("$.entry_id")!=entryId)continue;require(!selected&&entry.text("$.kind")=="worker"&&entry.text("$.loader")=="node_module","load_entry");
      selected=true;entryFile=entry.id("$.file_id");policyFile=entry.id("$.io_policy_file_id");}
    require(selected,"load_entry");std::vector<content::Entry> files;std::string previous;bool entryFound=false,policyFound=false;
    Statement rows(json.db,"SELECT value FROM json_each(?1,'$.inventory.files')");rows.bind(1,bytes);
    while(sqlite3_step(rows.value)==SQLITE_ROW){
      require(files.size()<65536,"load_capacity");const auto body=rows.text(0);installation::Fields file(json.db,body);const auto id=file.id("$.file_id");
      require(previous<id,"load_inventory");previous=id;const auto path=wide(file.text("$.path"));const auto role=file.text("$.role");
      const auto size=std::stoull(file.number("$.size_bytes"));files.push_back({path,size,file.digest("$.digest")});
      if(id==entryFile){require(role=="module","load_entry");entryPath=path;entryFound=true;}
      if(id==policyFile){require(role=="policy","load_entry");policyFound=true;}
    }
    require(entryFound&&policyFound,"load_entry");pin=std::make_unique<content::Pin>(wide(rootPath),files,3000);
    require(utf8(pin->rootIdentity)==rootIdentity,"load_root_identity");root=pin->root;
    moduleContext=object({{"root_path",quote(json.db,bytes,"$.root_path")},{"root_identity",string(rootIdentity)},
      {"manifest",manifest},{"inventory",inventory}});
  }
};
struct Record {
  std::string launch,digest,materialsDigest,body,status="receiving";
  unsigned long long length=0,received=0,expires=0;
  std::unique_ptr<Materials> materials;
};
class Store {
  std::map<std::string,Record> records;
  std::map<std::string,std::string> selected;
  std::future<std::unique_ptr<Materials>> future;
  std::string pending;
public:
  void settle(){
    if(future.valid()&&future.wait_for(std::chrono::milliseconds(0))==std::future_status::ready){
      auto& record=records.at(pending);
      try{auto result=future.get();if(record.status=="pending"&&bootstrap::tick()<record.expires){record.materials=std::move(result);record.status="ready";}}
      catch(...){if(record.status=="pending")record.status="unavailable";}record.body.clear();pending.clear();
    }
    for(auto& item:records){auto& r=item.second;if((r.status=="receiving"||r.status=="pending")&&bootstrap::tick()>=r.expires){r.status="unavailable";r.body.clear();}}
  }
  bool busy(const std::string& id)const{return future.valid()&&pending==id;}
  Record* find(const std::string& id){const auto found=records.find(id);return found==records.end()?nullptr:&found->second;}
  bool current(const std::string& id,const Record& r)const{const auto found=selected.find(r.launch);return found!=selected.end()&&found->second==id;}
  void close(Record& r,bool denied=false){r.status=denied?"unavailable":"released";r.body.clear();r.materials.reset();}
  bool begin(const std::string& id,const std::string& launch,const std::string& digest,const std::string& materialsDigest,unsigned long long length){
    if(auto prior=find(id)){require(prior->launch==launch&&prior->digest==digest&&prior->materialsDigest==materialsDigest&&prior->length==length,"load_identity_conflict");return false;}
    require(records.size()<4096&&length>0&&length<=8388608,"load_capacity");size_t active=0;
    for(const auto& item:records)if(item.second.status=="receiving"||item.second.status=="pending"||item.second.status=="ready")++active;
    require(active<4,"load_capacity");const auto previous=selected.find(launch);if(previous!=selected.end())close(records.at(previous->second));
    auto& r=records[id];r.launch=launch;r.digest=digest;r.materialsDigest=materialsDigest;r.length=length;r.expires=bootstrap::tick()+10000000000ULL;selected[launch]=id;return true;
  }
  void chunk(Record& r,unsigned long long offset,const std::string& encoded){
    require(r.status=="receiving"&&offset==r.received&&bootstrap::tick()<r.expires,"load_offset");const auto decoded=base64(encoded);
    require(decoded.size()<=r.length-r.received,"load_capacity");r.body+=decoded;r.received+=decoded.size();
  }
  void finish(const std::string& id,Record& r,const std::string& intent){
    if(r.status!="receiving")return;require(!future.valid()&&r.received==r.length,"load_incomplete");
    require(bootstrap::digest(r.body)==r.materialsDigest,"load_digest");r.status="pending";pending=id;
    const auto bytes=std::move(r.body);future=std::async(std::launch::async,[bytes,intent](){return std::make_unique<Materials>(bytes,intent);});
  }
  template<class Allowed>void invalidate(Allowed allowed){for(auto& item:records){auto& r=item.second;if(r.status!="released"&&r.status!="unavailable"&&!allowed(r.launch,r.digest))close(r,true);}}
};
}
