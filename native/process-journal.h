#pragma once
#include <sddl.h>
#include <sqlite3.h>
#include <memory>
#include "process-journal-sql.h"

static std::string utf8(const std::wstring& s) {
  const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.c_str(), -1, nullptr, 0, nullptr, nullptr);
  require(size > 0, "path_encoding"); std::string out(static_cast<size_t>(size), '\0');
  require(WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.c_str(), -1, out.data(), size, nullptr, nullptr) == size, "path_encoding");
  out.pop_back(); return out;
}
static std::string fileIdentity(HANDLE file) {
  FILE_ID_INFO info{};
  require(GetFileInformationByHandleEx(file, FileIdInfo, &info, sizeof(info)) != 0, "file_identity_unavailable");
  char volume[17]; sprintf_s(volume, "%016llx", info.VolumeSerialNumber); std::string out(volume);
  const char* hex = "0123456789abcdef";
  for (auto b : info.FileId.Identifier) { out += hex[b >> 4]; out += hex[b & 15]; } return out;
}
struct LocalMemory { void* value = nullptr; ~LocalMemory() { if (value) LocalFree(value); } };
struct Instance {
  Handle directory, mutex;
  LocalMemory descriptor;
  SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), nullptr, FALSE};
  std::wstring path; std::string directoryId, owner;
  bool owned = false;
  explicit Instance(const wchar_t* input) {
    directory.value = CreateFileW(input, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    require(directory.value != INVALID_HANDLE_VALUE, "instance_directory_unavailable");
    FILE_STANDARD_INFO standard{};
    require(GetFileInformationByHandleEx(directory.value, FileStandardInfo, &standard, sizeof(standard)) && standard.Directory, "instance_directory_invalid");
    std::vector<wchar_t> name(32768);
    DWORD size = GetFinalPathNameByHandleW(directory.value, name.data(), static_cast<DWORD>(name.size()), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    require(size > 0 && size < name.size(), "instance_directory_path"); path.assign(name.data(), size);
    require(path.rfind(L"\\\\?\\UNC\\", 0) != 0, "instance_remote_directory");
    wchar_t volume[MAX_PATH]{};
    require(GetVolumePathNameW(path.c_str(), volume, MAX_PATH) && GetDriveTypeW(volume) == DRIVE_FIXED, "instance_local_volume");
    directoryId = fileIdentity(directory.value);
    Handle token; require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.value) != 0, "instance_token");
    DWORD length = 0; GetTokenInformation(token.value, TokenUser, nullptr, 0, &length);
    require(length > 0, "instance_token"); std::vector<unsigned char> bytes(length);
    require(GetTokenInformation(token.value, TokenUser, bytes.data(), length, &length) != 0, "instance_token");
    auto user = reinterpret_cast<TOKEN_USER*>(bytes.data()); LocalMemory sid;
    require(ConvertSidToStringSidW(user->User.Sid, reinterpret_cast<LPWSTR*>(&sid.value)) != 0, "instance_sid");
    const std::wstring sidText(static_cast<wchar_t*>(sid.value)); owner = utf8(sidText);
    const std::wstring sddl = L"D:P(A;;GA;;;SY)(A;;GA;;;" + sidText + L")";
    require(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &descriptor.value, nullptr) != 0, "instance_acl");
    security.lpSecurityDescriptor = descriptor.value;
    const std::wstring mutexName = L"Global\\LeafSeamer.Controller." + std::wstring(directoryId.begin(), directoryId.end());
    mutex.value = CreateMutexW(&security, TRUE, mutexName.c_str()); const DWORD error = GetLastError();
    require(mutex.value != nullptr, "instance_mutex_unavailable");
    if (error == ERROR_ALREADY_EXISTS) {
      const DWORD wait = WaitForSingleObject(mutex.value, 0);
      if (wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED) ReleaseMutex(mutex.value);
      throw std::runtime_error(wait == WAIT_ABANDONED ? "instance_abandoned" : "instance_in_use");
    }
    owned = true;
  }
  ~Instance() { if (owned) ReleaseMutex(mutex.value); }
};
struct DatabaseCloser { void operator()(sqlite3* db) const { if (db) sqlite3_close_v2(db); } };
struct Statement {
  sqlite3_stmt* value = nullptr;
  Statement(sqlite3* db, const char* sql) { require(sqlite3_prepare_v2(db, sql, -1, &value, nullptr) == SQLITE_OK, "process_journal_statement"); }
  ~Statement() { sqlite3_finalize(value); }
  void bind(int n, const std::string& text) { require(sqlite3_bind_text(value, n, text.c_str(), static_cast<int>(text.size()), SQLITE_TRANSIENT) == SQLITE_OK, "process_journal_binding"); }
  std::string text(int n) { const auto p = sqlite3_column_text(value, n); require(p != nullptr, "process_journal_value"); return reinterpret_cast<const char*>(p); }
  void done() { require(sqlite3_step(value) == SQLITE_DONE, "process_journal_write"); }
};
struct LaunchFenceItem { std::string launch, digest, disposition; };
struct WorkerStored {
  std::string digest, intent, state, receipt, retirement, member, group, generation;
  bool attempted = false;
};
struct TimeProviderRecorded {
  std::string intent,receipt,pid,creationTime,imageId,observedTick;
};
struct TimeProviderRetired {
  TimeProviderRecorded original;
  std::string coreReceiptId,providerExit,providerForced,coreExit,coreForced;
};
struct WorkerRetired {
  std::string intent,supervisor,receipt,retirement,coreReceipt,exitCode,forced;
};
class ProcessJournal {
  Handle file;
  std::unique_ptr<sqlite3, DatabaseCloser> db;
  void execute(const char* sql) { require(sqlite3_exec(db.get(), sql, nullptr, nullptr, nullptr) == SQLITE_OK, "process_journal_transaction"); }
  std::string scalar(const char* sql) {
    Statement q(db.get(), sql); require(sqlite3_step(q.value) == SQLITE_ROW, "process_journal_read");
    std::string v = q.text(0); require(sqlite3_step(q.value) == SQLITE_DONE, "process_journal_read"); return v;
  }
  static std::string schema(sqlite3* database) {
    Statement q(database, "SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' ORDER BY type,name");
    std::string out; int code;
    while ((code = sqlite3_step(q.value)) == SQLITE_ROW) { for (int i = 0; i < 4; ++i) { out += q.text(i); out += '\0'; } }
    require(code == SQLITE_DONE, "process_journal_schema"); return out;
  }
public:
  enum class Mode { launch, initialize, upgrade, upgradeTimeProvider, retirement, fenceRecovery };
  bool upgraded = false;
  bool timeProviderEnabled = false;
  bool recoveryFenced = false;
  ProcessJournal(Instance& instance, Mode mode) {
    const bool initialize=mode==Mode::initialize, upgradeTimeProvider=mode==Mode::upgradeTimeProvider;
    const bool upgrade=mode==Mode::upgrade||upgradeTimeProvider, observe=mode==Mode::retirement, fence=mode==Mode::fenceRecovery;
    const std::wstring filename = instance.path + L"\\supervisor-journal.db";
    file.value = CreateFileW(filename.c_str(), observe ? GENERIC_READ : GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &instance.security,
      initialize ? CREATE_NEW : OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    require(file.value != INVALID_HANDLE_VALUE, initialize ? "process_journal_exists" : "process_journal_missing");
    LARGE_INTEGER size{};
    require(GetFileSizeEx(file.value, &size) && size.QuadPart <= 16777216, "process_journal_capacity");
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    require(GetFileInformationByHandleEx(file.value, FileAttributeTagInfo, &attributes, sizeof(attributes)) &&
      !(attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT), "process_journal_link");
    if (observe||fence) {
      FILE_STANDARD_INFO standard{}; unsigned char header[20]{}; DWORD bytes = 0;
      require(GetFileInformationByHandleEx(file.value, FileStandardInfo, &standard, sizeof(standard)) && standard.NumberOfLinks == 1 &&
        ReadFile(file.value, header, sizeof(header), &bytes, nullptr) && bytes == sizeof(header) &&
        std::string(reinterpret_cast<char*>(header), 16) == std::string("SQLite format 3\0", 16) &&
        header[18] == 1 && header[19] == 1, "process_journal_observation_file");
    }
    sqlite3* opened = nullptr;
    const int flags = (observe ? SQLITE_OPEN_READONLY : SQLITE_OPEN_READWRITE) | SQLITE_OPEN_NOMUTEX;
    const int code = sqlite3_open_v2(utf8(filename).c_str(), &opened, flags, nullptr);
    db.reset(opened); require(code == SQLITE_OK, "process_journal_open");
    require(std::string(sqlite3_sourceid()) == "2026-07-24 19:02:57 bf7c7f30031888f4e796e429ab3978879485813aaca6f641c7b33e4e09459bcc", "process_journal_engine");
    require(sqlite3_busy_timeout(db.get(), 0) == SQLITE_OK, "process_journal_busy");
    // 只在显式初始化时选择日志模式；运行时错模式拒绝，不隐式修复。
    if (initialize) execute("PRAGMA journal_mode=DELETE");
    require(scalar("PRAGMA journal_mode") == "delete", "process_journal_mode");
    require(scalar("PRAGMA page_size") == "4096" && (observe || scalar("PRAGMA max_page_count=4096") == "4096"), "process_journal_capacity");
    execute("PRAGMA synchronous=EXTRA; PRAGMA foreign_keys=ON; PRAGMA recursive_triggers=ON; PRAGMA trusted_schema=OFF; PRAGMA locking_mode=EXCLUSIVE");
    require(scalar("PRAGMA synchronous") == "3" && scalar("PRAGMA foreign_keys") == "1" && scalar("PRAGMA recursive_triggers") == "1" &&
      scalar("PRAGMA trusted_schema") == "0" && scalar("PRAGMA locking_mode") == "exclusive", "process_journal_profile");
    if (observe) execute("PRAGMA query_only=ON; BEGIN");
    if (initialize) {
      execute("BEGIN IMMEDIATE"); execute(processJournalSql);
      Statement meta(db.get(), "INSERT INTO host_meta VALUES(1,'leafseamer-process-journal/1',?,?,?)");
      meta.bind(1, identifier()); meta.bind(2, instance.directoryId); meta.bind(3, instance.owner); meta.done(); execute("COMMIT");
    }
    require(scalar("PRAGMA application_id") == "1280528456", "process_journal_version");
    const auto version = scalar("PRAGMA user_version");
    const bool oldVersion = version == "1" || version == "2" || version == "3" || version == "4";
    recoveryFenced=version=="7";
    require(!recoveryFenced||observe||fence,"process_recovery_startup_fenced");
    require(version=="5"||version=="6"||recoveryFenced||(upgrade&&oldVersion),"process_journal_migration_required");
    timeProviderEnabled=version=="6"||recoveryFenced;
    require(scalar("PRAGMA integrity_check") == "ok", "process_journal_integrity");
    Statement foreignKeys(db.get(), "PRAGMA foreign_key_check"); require(sqlite3_step(foreignKeys.value) == SQLITE_DONE, "process_journal_foreign_key");
    sqlite3* memory = nullptr; require(sqlite3_open(":memory:", &memory) == SQLITE_OK, "process_journal_schema");
    std::unique_ptr<sqlite3, DatabaseCloser> reference(memory);
    require(sqlite3_exec(memory, version == "1" ? processJournalV1Sql : (version == "2" ? processJournalV2Sql : (version == "3" ? processJournalV3Sql : (version == "4" ? processJournalV4Sql : processJournalSql))), nullptr, nullptr, nullptr) == SQLITE_OK, "process_journal_schema");
    if(timeProviderEnabled)require(sqlite3_exec(memory,processJournalTimeProviderSql,nullptr,nullptr,nullptr)==SQLITE_OK,"process_journal_schema");
    if(recoveryFenced)require(sqlite3_exec(memory,processJournalRecoveryStartupSql,nullptr,nullptr,nullptr)==SQLITE_OK,"process_journal_schema");
    require(schema(memory)==schema(db.get()),"process_journal_schema");
    Statement meta(db.get(), "SELECT directory_id,owner_sid FROM host_meta WHERE singleton=1");
    require(sqlite3_step(meta.value) == SQLITE_ROW && meta.text(0) == instance.directoryId && meta.text(1) == instance.owner, "process_journal_identity");
    require(sqlite3_step(meta.value) == SQLITE_DONE, "process_journal_identity");
    require(scalar("SELECT count(*) FROM core_attempt a LEFT JOIN core_exit e USING(attempt_id) WHERE e.attempt_id IS NULL") == "0", "process_recovery_required");
    if(timeProviderEnabled)require(scalar("SELECT count(*) FROM time_provider_attempt a LEFT JOIN time_provider_exit e USING(launch_id) WHERE e.launch_id IS NULL")=="0","process_recovery_required");
    if(recoveryFenced)require(scalar("SELECT count(*) FROM recovery_startup_fence")=="1","process_retirement_unproven");
    if (oldVersion || (upgradeTimeProvider && !timeProviderEnabled)) {
      // 显式升级才备份并改变DDL；未结束尝试不能通过升级绕开恢复。
      const auto suffix = identifier(); const auto backupPath = instance.path + (upgradeTimeProvider?L"\\supervisor-before-v6-":L"\\supervisor-before-v5-") + std::wstring(suffix.begin(), suffix.end()) + L".db";
      Handle backupFile(CreateFileW(backupPath.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &instance.security, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
      require(backupFile.value != INVALID_HANDLE_VALUE, "process_journal_backup");
      sqlite3* copy = nullptr; require(sqlite3_open_v2(utf8(backupPath).c_str(), &copy, SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOMUTEX, nullptr) == SQLITE_OK, "process_journal_backup");
      std::unique_ptr<sqlite3, DatabaseCloser> backup(copy);
      sqlite3_backup* transfer = sqlite3_backup_init(copy, "main", db.get(), "main"); require(transfer != nullptr, "process_journal_backup");
      const auto step = sqlite3_backup_step(transfer, -1), finish = sqlite3_backup_finish(transfer);
      require(step == SQLITE_DONE && finish == SQLITE_OK, "process_journal_backup");
      execute("BEGIN IMMEDIATE");
      const auto apply=[&](const char* migration){
        execute(migration);
        require(sqlite3_exec(memory,migration,nullptr,nullptr,nullptr)==SQLITE_OK,"process_journal_schema");
      };
      if(oldVersion){
        if(version=="1")apply(processJournalUpgradeSql);
        if(version=="1"||version=="2")apply(processJournalFenceSql);
        if(version!="4")apply(processJournalRetirementSql);
        apply(processJournalCreationSql);
      }
      if(upgradeTimeProvider)apply(processJournalTimeProviderSql);
      require(schema(memory)==schema(db.get()),"process_journal_schema");
      execute("COMMIT");
      timeProviderEnabled=upgradeTimeProvider;
      upgraded = true;
    }
  }
  std::string recoveryRetirement(const std::string& generation,const std::string& service="",const std::string& database="") {
    require(generation.size() == 32 && generation.find_first_not_of("0123456789abcdef") == std::string::npos,
      "process_retirement_generation");
    const std::string providerCount = timeProviderEnabled
      ? "(SELECT count(*) FROM time_provider_attempt t WHERE t.core_attempt_id=a.attempt_id)" : "0";
    const auto query = std::string(
      "SELECT json_object('journal_incarnation',m.incarnation,'directory_id',m.directory_id,"
        "'attempt_id',a.attempt_id,'job_name',a.job_name,'supervisor_pid',a.supervisor_pid,"
        "'core_pid',o.core_pid,'creation_filetime',o.creation_filetime,'image_file_id',o.image_file_id,"
        "'policy',json(b.policy_jcs),'descriptor',json(b.descriptor_jcs),'intent',json(b.intent_jcs),"
        "'receipt_id',c.receipt_id,'receipt',json(c.receipt_jcs),'exit_code',e.exit_code,'forced',e.forced,"
        "'active_processes',e.active_processes,'worker_launches',(SELECT count(*) FROM worker_launch w WHERE w.attempt_id=a.attempt_id),"
        "'time_provider_launches',") + providerCount + ")"
      " FROM core_attempt a JOIN core_observation o USING(attempt_id) JOIN core_bootstrap b USING(attempt_id)"
      " JOIN core_admission c USING(attempt_id) JOIN core_exit e USING(attempt_id) CROSS JOIN host_meta m"
      " WHERE a.rowid=(SELECT max(rowid) FROM core_attempt) AND e.active_processes=0"
      " AND json_extract(b.descriptor_jcs,'$.runtime_generation')=? AND m.singleton=1"
      " AND (?2 IS NULL OR (json_extract(b.policy_jcs,'$.service_id')=?2 AND json_extract(b.policy_jcs,'$.database_instance_id')=?3))";
    Statement q(db.get(), query.c_str()); q.bind(1, generation);
    if(!service.empty()){q.bind(2,service);q.bind(3,database);}
    require(sqlite3_step(q.value) == SQLITE_ROW, "process_retirement_unproven");
    auto body = q.text(0);
    require(sqlite3_step(q.value) == SQLITE_DONE && body.size() <= 49152, "process_retirement_unproven");
    return body;
  }
  std::string recoveryStartupFence(const std::string& evidence) {
    if(!recoveryFenced)return "null";
    Statement q(db.get(),"SELECT json_object('plan_digest',plan_digest,'retirement_id',retirement_id)"
      " FROM recovery_startup_fence WHERE singleton=1 AND attempt_id=json_extract(?,'$.attempt_id')");
    q.bind(1,evidence);
    require(sqlite3_step(q.value)==SQLITE_ROW,"process_retirement_unproven");
    auto body=q.text(0);
    require(sqlite3_step(q.value)==SQLITE_DONE,"process_retirement_unproven");
    return body;
  }
  std::string fenceRecoveryStartup(const std::string& generation,const std::string& service,const std::string& database,
      const std::string& plan,const std::string& retirement) {
    require(!service.empty()&&!database.empty(),"process_retirement_scope");
    const auto evidence=recoveryRetirement(generation,service,database);
    if(recoveryFenced){
      Statement existing(db.get(),"SELECT 1 FROM recovery_startup_fence WHERE singleton=1 AND plan_digest=? AND retirement_id=?");
      existing.bind(1,plan);existing.bind(2,retirement);
      require(sqlite3_step(existing.value)==SQLITE_ROW&&sqlite3_step(existing.value)==SQLITE_DONE,"process_recovery_fence_conflict");
      return evidence;
    }
    execute("BEGIN IMMEDIATE");
    if(!timeProviderEnabled)execute(processJournalTimeProviderSql);
    execute(processJournalRecoveryStartupSql);
    Statement insert(db.get(),"INSERT INTO recovery_startup_fence VALUES(1,json_extract(?,'$.attempt_id'),?,?)");
    insert.bind(1,evidence);insert.bind(2,plan);insert.bind(3,retirement);insert.done();
    execute("COMMIT");
    recoveryFenced=true;
    return evidence;
  }
  void begin(const std::string& id, const std::wstring& job, const std::string& policy = "", const std::string& descriptor = "", const std::string& intent = "") {
    execute("BEGIN IMMEDIATE"); Statement q(db.get(), "INSERT INTO core_attempt VALUES(?,?,?)");
    q.bind(1, id); q.bind(2, utf8(job)); q.bind(3, std::to_string(GetCurrentProcessId())); q.done();
    if (!policy.empty()) { Statement boot(db.get(), "INSERT INTO core_bootstrap VALUES(?,?,?,?)"); boot.bind(1, id); boot.bind(2, policy); boot.bind(3, descriptor); boot.bind(4, intent); boot.done(); }
    execute("COMMIT");
  }
  void observed(const std::string& id, HANDLE process, DWORD pid, HANDLE image) {
    FILETIME created{}, exited{}, kernel{}, user{};
    require(GetProcessTimes(process, &created, &exited, &kernel, &user) != 0, "process_creation_time");
    const ULONGLONG stamp = (static_cast<ULONGLONG>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
    execute("BEGIN IMMEDIATE"); Statement q(db.get(), "INSERT INTO core_observation VALUES(?,?,?,?)");
    q.bind(1, id); q.bind(2, std::to_string(pid)); q.bind(3, std::to_string(stamp)); q.bind(4, fileIdentity(image)); q.done(); execute("COMMIT");
  }
  void retired(const std::string& id, DWORD exit, bool forced) {
    execute("BEGIN IMMEDIATE"); Statement q(db.get(), "INSERT INTO core_exit VALUES(?,?,0,?)");
    q.bind(1, id); q.bind(2, std::to_string(exit)); q.bind(3, forced ? "1" : "0"); q.done(); execute("COMMIT");
  }
  void admitted(const std::string& id, const std::string& receiptId, const std::string& receipt) {
    execute("BEGIN IMMEDIATE"); Statement q(db.get(), "INSERT INTO core_admission VALUES(?,?,?)");
    q.bind(1, id); q.bind(2, receiptId); q.bind(3, receipt); q.done(); execute("COMMIT");
  }
  std::string admission(const std::string& id) {
    Statement q(db.get(), "SELECT a.receipt_jcs FROM core_admission a JOIN core_observation o USING(attempt_id) LEFT JOIN core_exit e USING(attempt_id) WHERE a.attempt_id=? AND e.attempt_id IS NULL");
    q.bind(1, id); require(sqlite3_step(q.value) == SQLITE_ROW, "control_journal_closed");
    const auto body = q.text(0); require(sqlite3_step(q.value) == SQLITE_DONE, "control_journal_binding"); return body;
  }
  void beginTimeProvider(const std::string& core,const std::string& launch,const std::wstring& job,
      const std::string& policy,const std::string& intent){
    require(timeProviderEnabled,"time_provider_journal_required");
    execute("BEGIN IMMEDIATE"); admission(core);
    Statement q(db.get(),"INSERT INTO time_provider_attempt VALUES(?,?,?,?,?)");
    q.bind(1,launch);q.bind(2,core);q.bind(3,utf8(job));q.bind(4,policy);q.bind(5,intent);q.done();execute("COMMIT");
  }
  void observeTimeProvider(const std::string& launch,HANDLE process,DWORD pid,HANDLE image,unsigned long long tick){
    FILETIME created{},exited{},kernel{},user{};
    require(GetProcessTimes(process,&created,&exited,&kernel,&user)!=0,"process_creation_time");
    const ULONGLONG stamp=(static_cast<ULONGLONG>(created.dwHighDateTime)<<32)|created.dwLowDateTime;
    execute("BEGIN IMMEDIATE");Statement q(db.get(),"INSERT INTO time_provider_observation VALUES(?,?,?,?,?)");
    q.bind(1,launch);q.bind(2,std::to_string(pid));q.bind(3,std::to_string(stamp));q.bind(4,fileIdentity(image));q.bind(5,std::to_string(tick));
    q.done();execute("COMMIT");
  }
  void admitTimeProvider(const std::string& launch,const std::string& receiptId,const std::string& receipt){
    execute("BEGIN IMMEDIATE");Statement q(db.get(),"INSERT INTO time_provider_admission VALUES(?,?,?)");
    q.bind(1,launch);q.bind(2,receiptId);q.bind(3,receipt);q.done();execute("COMMIT");
  }
  void retireTimeProvider(const std::string& launch,DWORD exit,bool forced){
    execute("BEGIN IMMEDIATE");Statement q(db.get(),"INSERT INTO time_provider_exit VALUES(?,?,0,?)");
    q.bind(1,launch);q.bind(2,std::to_string(exit));q.bind(3,forced?"1":"0");q.done();execute("COMMIT");
  }
  TimeProviderRecorded timeProviderAdmission(const std::string& core,const std::string& launch,const std::string& intent){
    require(timeProviderEnabled,"time_provider_journal_required");
    Statement q(db.get(),"SELECT a.intent_jcs,r.receipt_jcs,o.provider_pid,o.creation_time,o.image_id,o.observed_tick_ns FROM time_provider_attempt a"
      " JOIN time_provider_admission r USING(launch_id) JOIN time_provider_observation o USING(launch_id)"
      " LEFT JOIN time_provider_exit e USING(launch_id)"
      " LEFT JOIN core_exit c ON c.attempt_id=a.core_attempt_id"
      " WHERE a.core_attempt_id=? AND a.launch_id=? AND e.launch_id IS NULL AND c.attempt_id IS NULL");
    q.bind(1,core);q.bind(2,launch);
    require(sqlite3_step(q.value)==SQLITE_ROW&&q.text(0)==intent,"time_provider_journal_binding");
    const TimeProviderRecorded record{q.text(0),q.text(1),q.text(2),q.text(3),q.text(4),q.text(5)};
    require(sqlite3_step(q.value)==SQLITE_DONE,"time_provider_journal_binding");
    return record;
  }
  TimeProviderRetired timeProviderRetirement(const std::string& current,const std::string& target,
      const std::string& service,const std::string& database){
    if(!timeProviderEnabled)return {};
    Statement q(db.get(),"SELECT a.intent_jcs,r.receipt_jcs,o.provider_pid,o.creation_time,o.image_id,o.observed_tick_ns,"
      " c.receipt_id,e.exit_code,e.forced,x.exit_code,x.forced FROM time_provider_attempt a"
      " JOIN time_provider_admission r USING(launch_id) JOIN time_provider_observation o USING(launch_id)"
      " JOIN time_provider_exit e USING(launch_id) JOIN core_admission c ON c.attempt_id=a.core_attempt_id"
      " JOIN core_exit x ON x.attempt_id=a.core_attempt_id"
      " WHERE a.launch_id=?1 AND a.core_attempt_id<>?2 AND e.active_processes=0 AND x.active_processes=0"
      " AND json_extract(a.policy_jcs,'$.service_id')=?3 AND json_extract(a.policy_jcs,'$.database_instance_id')=?4");
    q.bind(1,target);q.bind(2,current);q.bind(3,service);q.bind(4,database);
    const int found=sqlite3_step(q.value);
    if(found==SQLITE_DONE)return {};
    require(found==SQLITE_ROW,"time_provider_retirement_read");
    TimeProviderRetired record{{q.text(0),q.text(1),q.text(2),q.text(3),q.text(4),q.text(5)},
      q.text(6),q.text(7),q.text(8),q.text(9),q.text(10)};
    require(sqlite3_step(q.value)==SQLITE_DONE,"time_provider_retirement_read");
    return record;
  }
  // 固定scope属于已准入核心attempt；整个快照和历史deny同事务提交后才能ACK。
  std::string fence(const std::string& id, const std::string& revision, const std::string& digest,
      const std::string& body, const std::vector<LaunchFenceItem>& items) {
    admission(id);
    Statement members(db.get(), "SELECT l.launch_id,l.intent_digest,s.state FROM worker_launch l JOIN worker_state s USING(attempt_id,launch_id) WHERE l.attempt_id=?");
    members.bind(1, id); int memberState;
    while ((memberState = sqlite3_step(members.value)) == SQLITE_ROW) {
      const auto key = members.text(0), storedDigest = members.text(1), phase = members.text(2); bool found = false;
      for (const auto& item : items) if (item.launch == key) {
        found = true;
        if (item.digest != storedDigest || (item.disposition == "allow" && (phase == "retired" || phase == "rejected" || phase == "retiring" || phase == "indeterminate"))) return "invalid_binding";
      }
      if (!found && phase != "retired" && phase != "rejected") return "invalid_binding";
    }
    require(memberState == SQLITE_DONE, "process_journal_read");
    Statement current(db.get(), "SELECT c.revision,f.digest,f.snapshot_jcs FROM launch_fence_current c JOIN launch_fence f USING(attempt_id,revision) WHERE c.attempt_id=?");
    current.bind(1, id); const auto state = sqlite3_step(current.value);
    require(state == SQLITE_ROW || state == SQLITE_DONE, "process_journal_read");
    bool exists = state == SQLITE_ROW;
    if (exists) {
      const auto old = current.text(0), previousDigest = current.text(1), previousBody = current.text(2);
      require(sqlite3_step(current.value) == SQLITE_DONE, "process_journal_read");
      if (old == revision) return previousDigest == digest && previousBody == body ? "" : "identity_conflict";
      if (revision.size() < old.size() || (revision.size() == old.size() && revision < old)) return "stale_fence";
    }
    Statement count(db.get(), "SELECT count(*) FROM launch_fence WHERE attempt_id=?"); count.bind(1, id);
    require(sqlite3_step(count.value) == SQLITE_ROW, "process_journal_read");
    if (std::stoul(count.text(0)) >= 4096) return "capacity";
    require(sqlite3_step(count.value) == SQLITE_DONE, "process_journal_read");
    for (const auto& item : items) {
      Statement conflict(db.get(), "SELECT 1 FROM launch_fence_item WHERE attempt_id=? AND launch_id=? AND (intent_digest<>? OR (disposition='deny' AND ?='allow')) LIMIT 1");
      conflict.bind(1, id); conflict.bind(2, item.launch); conflict.bind(3, item.digest); conflict.bind(4, item.disposition);
      const auto result = sqlite3_step(conflict.value); if (result == SQLITE_ROW) return "identity_conflict";
      require(result == SQLITE_DONE, "process_journal_read");
    }
    try {
      execute("BEGIN IMMEDIATE");
      Statement snapshot(db.get(), "INSERT INTO launch_fence VALUES(?,?,?,?)");
      snapshot.bind(1, id); snapshot.bind(2, revision); snapshot.bind(3, digest); snapshot.bind(4, body); snapshot.done();
      for (const auto& item : items) {
        Statement insert(db.get(), "INSERT INTO launch_fence_item VALUES(?,?,?,?,?)");
        insert.bind(1, id); insert.bind(2, revision); insert.bind(3, item.launch); insert.bind(4, item.digest); insert.bind(5, item.disposition); insert.done();
      }
      Statement pointer(db.get(), exists ? "UPDATE launch_fence_current SET revision=?2 WHERE attempt_id=?1" : "INSERT INTO launch_fence_current VALUES(?1,?2)");
      pointer.bind(1, id); pointer.bind(2, revision); pointer.done(); execute("COMMIT");
    } catch (...) {
      sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr); throw;
    }
    return "";
  }
  std::unique_ptr<WorkerStored> worker(const std::string& id, const std::string& launchId) {
    Statement q(db.get(), "SELECT l.intent_digest,l.intent_jcs,s.state,s.creation_attempted,coalesce(s.admission_receipt,'null'),coalesce(s.retirement_evidence,'null'),l.member_id,l.group_id,l.group_generation FROM worker_launch l JOIN worker_state s USING(attempt_id,launch_id) WHERE l.attempt_id=? AND l.launch_id=?");
    q.bind(1, id); q.bind(2, launchId); const auto status = sqlite3_step(q.value);
    if (status == SQLITE_DONE) return nullptr; require(status == SQLITE_ROW, "process_journal_read");
    auto found = std::make_unique<WorkerStored>(); found->digest = q.text(0); found->intent = q.text(1); found->state = q.text(2);
    found->attempted = q.text(3) == "1"; found->receipt = q.text(4); found->retirement = q.text(5);
    found->member = q.text(6); found->group = q.text(7); found->generation = q.text(8);
    require(sqlite3_step(q.value) == SQLITE_DONE, "process_journal_read"); return found;
  }
  WorkerRetired workerRetirement(const std::string& current,const std::string& coreReceiptId,
      const std::string& launchId,const std::string& digest,const std::string& service,const std::string& database) {
    Statement q(db.get(),"SELECT l.intent_jcs,json_extract(l.intent_jcs,'$.supervisor_instance_id'),"
      " s.admission_receipt,s.retirement_evidence,c.receipt_jcs,x.exit_code,x.forced"
      " FROM core_admission c JOIN core_bootstrap b USING(attempt_id) JOIN core_exit x USING(attempt_id)"
      " JOIN worker_launch l USING(attempt_id) JOIN worker_state s USING(attempt_id,launch_id)"
      " WHERE c.receipt_id=?1 AND c.attempt_id<>?2 AND l.launch_id=?3 AND l.intent_digest=?4"
      " AND json_extract(b.policy_jcs,'$.service_id')=?5 AND json_extract(b.policy_jcs,'$.database_instance_id')=?6"
      " AND x.active_processes=0 AND s.state='retired' AND s.creation_attempted=1 AND s.admission_receipt IS NOT NULL"
      " AND json_extract(s.retirement_evidence,'$.result')='confirmed_empty'");
    q.bind(1,coreReceiptId);q.bind(2,current);q.bind(3,launchId);q.bind(4,digest);q.bind(5,service);q.bind(6,database);
    const auto status=sqlite3_step(q.value);
    if(status==SQLITE_DONE)return {};
    require(status==SQLITE_ROW,"worker_retirement_read");
    WorkerRetired found{q.text(0),q.text(1),q.text(2),q.text(3),q.text(4),q.text(5),q.text(6)};
    require(sqlite3_step(q.value)==SQLITE_DONE,"worker_retirement_read");
    return found;
  }
  void reserveWorkerGroup(const std::string& id, const std::string& launchId, const std::string& name, const std::string& reservation) {
    Statement prior(db.get(), "SELECT object_name,reservation_jcs FROM worker_group WHERE attempt_id=? AND launch_id=?");
    prior.bind(1, id); prior.bind(2, launchId); const auto status = sqlite3_step(prior.value);
    if (status == SQLITE_ROW) { require(prior.text(0) == name && prior.text(1) == reservation && sqlite3_step(prior.value) == SQLITE_DONE, "worker_group_identity"); return; }
    require(status == SQLITE_DONE, "process_journal_read");
    try {
      execute("BEGIN IMMEDIATE"); Statement insert(db.get(), "INSERT INTO worker_group VALUES(?,?,?,?)");
      insert.bind(1, id); insert.bind(2, launchId); insert.bind(3, name); insert.bind(4, reservation); insert.done(); execute("COMMIT");
    } catch (...) { sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr); throw; }
  }
  void beginWorkerCreation(const std::string& id,const std::string& launchId,const std::string& creationId,const std::string& record){
    try{execute("BEGIN IMMEDIATE");Statement insert(db.get(),"INSERT INTO worker_creation VALUES(?,?,?,?)");
      insert.bind(1,id);insert.bind(2,launchId);insert.bind(3,creationId);insert.bind(4,record);insert.done();
      Statement update(db.get(),"UPDATE worker_state SET state='creating',creation_attempted=1 WHERE attempt_id=? AND launch_id=? AND state='registered' AND creation_attempted=0");
      update.bind(1,id);update.bind(2,launchId);update.done();require(sqlite3_changes(db.get())==1,"worker_creation_state");execute("COMMIT");
    }catch(...){sqlite3_exec(db.get(),"ROLLBACK",nullptr,nullptr,nullptr);throw;}
  }
  void observeWorker(const std::string& id,const std::string& launchId,const std::string& observationId,const std::string& record){
    try{execute("BEGIN IMMEDIATE");Statement insert(db.get(),"INSERT INTO worker_observation VALUES(?,?,?,?)");
      insert.bind(1,id);insert.bind(2,launchId);insert.bind(3,observationId);insert.bind(4,record);insert.done();
      Statement update(db.get(),"UPDATE worker_state SET state='awaiting_bootstrap' WHERE attempt_id=? AND launch_id=? AND state='creating' AND creation_attempted=1");
      update.bind(1,id);update.bind(2,launchId);update.done();require(sqlite3_changes(db.get())==1,"worker_creation_state");execute("COMMIT");
    }catch(...){sqlite3_exec(db.get(),"ROLLBACK",nullptr,nullptr,nullptr);throw;}
  }
  void admitWorker(const std::string& id,const std::string& launchId,const std::string& receipt){
    Statement update(db.get(),"UPDATE worker_state SET state='admitted_closed',admission_receipt=?3 WHERE attempt_id=?1 AND launch_id=?2 AND state='awaiting_bootstrap' AND creation_attempted=1");
    update.bind(1,id);update.bind(2,launchId);update.bind(3,receipt);update.done();require(sqlite3_changes(db.get())==1,"worker_admission_state");
  }
  void failWorker(const std::string& id,const std::string& launchId){
    Statement update(db.get(),"UPDATE worker_state SET state='indeterminate' WHERE attempt_id=? AND launch_id=? AND state IN('creating','awaiting_bootstrap','admitted_closed')");
    update.bind(1,id);update.bind(2,launchId);update.done();
  }
  void beginWorkerRetirement(const std::string& id, const std::string& launchId) {
    try {
      execute("BEGIN IMMEDIATE");
      Statement update(db.get(), "UPDATE worker_state SET state='retiring' WHERE attempt_id=? AND launch_id=? AND state IN('registered','creating','awaiting_bootstrap','admitted_closed','indeterminate')");
      update.bind(1, id); update.bind(2, launchId); update.done(); require(sqlite3_changes(db.get()) == 1, "worker_retirement_state"); execute("COMMIT");
    } catch (...) { sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr); throw; }
  }
  void finishWorkerRetirement(const std::string& id, const std::string& launchId, const std::string& evidenceId, const std::string& observationId,
      const std::string& request, const std::string& observation, const std::string& evidence) {
    try {
      execute("BEGIN IMMEDIATE"); Statement insert(db.get(), "INSERT INTO worker_retirement VALUES(?,?,?,?,?,?,?)");
      insert.bind(1, id); insert.bind(2, launchId); insert.bind(3, evidenceId); insert.bind(4, observationId);
      insert.bind(5, request); insert.bind(6, observation); insert.bind(7, evidence); insert.done();
      Statement update(db.get(), "UPDATE worker_state SET state='retired',retirement_evidence=?3 WHERE attempt_id=?1 AND launch_id=?2 AND state='retiring'");
      update.bind(1, id); update.bind(2, launchId); update.bind(3, evidence); update.done(); require(sqlite3_changes(db.get()) == 1, "worker_retirement_state"); execute("COMMIT");
    } catch (...) { sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr); throw; }
  }
  std::string workerPermission(const std::string& id, const std::string& launchId, const std::string& digest, const std::string& revision = "") {
    admission(id);
    Statement permission(db.get(), "SELECT c.revision,i.intent_digest,i.disposition FROM launch_fence_current c JOIN launch_fence_item i USING(attempt_id,revision) WHERE c.attempt_id=? AND i.launch_id=?");
    permission.bind(1, id); permission.bind(2, launchId); const auto result = sqlite3_step(permission.value);
    if (result == SQLITE_DONE) return "stale_fence"; require(result == SQLITE_ROW, "process_journal_read");
    if (!revision.empty() && permission.text(0) != revision) return "stale_fence";
    if (permission.text(1) != digest || permission.text(2) != "allow") return "unauthorized";
    require(sqlite3_step(permission.value) == SQLITE_DONE, "process_journal_read");
    return "";
  }
  std::string registerWorker(const std::string& id, const std::string& launchId, const std::string& digest, const std::string& intent,
      const std::string& member, const std::string& group, const std::string& generation, const std::string& authorization, const std::string& revision) {
    admission(id);
    const auto prior = worker(id, launchId);
    if (prior && (prior->digest != digest || prior->intent != intent)) return "identity_conflict";
    if (prior && prior->state != "registered") return "invalid_binding";
    const auto failure = workerPermission(id, launchId, digest, revision); if (!failure.empty()) return failure;
    if (prior) return "";
    Statement limits(db.get(), "SELECT count(*),sum(state NOT IN('retired','rejected')) FROM worker_state WHERE attempt_id=?"); limits.bind(1, id);
    require(sqlite3_step(limits.value) == SQLITE_ROW, "process_journal_read");
    const auto count = std::stoul(limits.text(0)); if (count >= 4096 || (count && std::stoul(limits.text(1)) >= 256)) return "capacity";
    require(sqlite3_step(limits.value) == SQLITE_DONE, "process_journal_read");
    Statement unique(db.get(), "SELECT 1 FROM worker_launch WHERE attempt_id=? AND (member_id=? OR group_id=?) LIMIT 1");
    unique.bind(1, id); unique.bind(2, member); unique.bind(3, group); const auto collision = sqlite3_step(unique.value);
    if (collision == SQLITE_ROW) return "identity_conflict"; require(collision == SQLITE_DONE, "process_journal_read");
    try {
      execute("BEGIN IMMEDIATE");
      Statement insert(db.get(), "INSERT INTO worker_launch VALUES(?,?,?,?,?,?,?,?)");
      insert.bind(1, id); insert.bind(2, launchId); insert.bind(3, digest); insert.bind(4, intent); insert.bind(5, member);
      insert.bind(6, group); insert.bind(7, generation); insert.bind(8, authorization); insert.done();
      Statement state(db.get(), "INSERT INTO worker_state VALUES(?,?,'registered',0,NULL,NULL)"); state.bind(1, id); state.bind(2, launchId); state.done();
      execute("COMMIT");
    } catch (...) { sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr); throw; }
    return "";
  }
};
