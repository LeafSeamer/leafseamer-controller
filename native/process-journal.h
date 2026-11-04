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
  ProcessJournal(Instance& instance, bool initialize) {
    const std::wstring filename = instance.path + L"\\supervisor-journal.db";
    file.value = CreateFileW(filename.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &instance.security,
      initialize ? CREATE_NEW : OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    require(file.value != INVALID_HANDLE_VALUE, initialize ? "process_journal_exists" : "process_journal_missing");
    LARGE_INTEGER size{};
    require(GetFileSizeEx(file.value, &size) && size.QuadPart <= 16777216, "process_journal_capacity");
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    require(GetFileInformationByHandleEx(file.value, FileAttributeTagInfo, &attributes, sizeof(attributes)) &&
      !(attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT), "process_journal_link");
    sqlite3* opened = nullptr; const int code = sqlite3_open_v2(utf8(filename).c_str(), &opened, SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOMUTEX, nullptr);
    db.reset(opened); require(code == SQLITE_OK, "process_journal_open");
    require(std::string(sqlite3_sourceid()) == "2026-07-24 19:02:57 bf7c7f30031888f4e796e429ab3978879485813aaca6f641c7b33e4e09459bcc", "process_journal_engine");
    require(sqlite3_busy_timeout(db.get(), 0) == SQLITE_OK, "process_journal_busy");
    // 只在显式初始化时选择日志模式；运行时错模式拒绝，不隐式修复。
    if (initialize) execute("PRAGMA journal_mode=DELETE");
    require(scalar("PRAGMA journal_mode") == "delete", "process_journal_mode");
    require(scalar("PRAGMA page_size") == "4096" && scalar("PRAGMA max_page_count=4096") == "4096", "process_journal_capacity");
    execute("PRAGMA synchronous=EXTRA; PRAGMA foreign_keys=ON; PRAGMA recursive_triggers=ON; PRAGMA trusted_schema=OFF; PRAGMA locking_mode=EXCLUSIVE");
    require(scalar("PRAGMA synchronous") == "3" && scalar("PRAGMA foreign_keys") == "1" && scalar("PRAGMA recursive_triggers") == "1" &&
      scalar("PRAGMA trusted_schema") == "0" && scalar("PRAGMA locking_mode") == "exclusive", "process_journal_profile");
    if (initialize) {
      execute("BEGIN IMMEDIATE"); execute(processJournalSql);
      Statement meta(db.get(), "INSERT INTO host_meta VALUES(1,'leafseamer-process-journal/1',?,?,?)");
      meta.bind(1, identifier()); meta.bind(2, instance.directoryId); meta.bind(3, instance.owner); meta.done(); execute("COMMIT");
    }
    require(scalar("PRAGMA application_id") == "1280528456" && scalar("PRAGMA user_version") == "1", "process_journal_version");
    require(scalar("PRAGMA integrity_check") == "ok", "process_journal_integrity");
    Statement foreignKeys(db.get(), "PRAGMA foreign_key_check"); require(sqlite3_step(foreignKeys.value) == SQLITE_DONE, "process_journal_foreign_key");
    sqlite3* memory = nullptr; require(sqlite3_open(":memory:", &memory) == SQLITE_OK, "process_journal_schema");
    std::unique_ptr<sqlite3, DatabaseCloser> reference(memory);
    require(sqlite3_exec(memory, processJournalSql, nullptr, nullptr, nullptr) == SQLITE_OK && schema(memory) == schema(db.get()), "process_journal_schema");
    Statement meta(db.get(), "SELECT directory_id,owner_sid FROM host_meta WHERE singleton=1");
    require(sqlite3_step(meta.value) == SQLITE_ROW && meta.text(0) == instance.directoryId && meta.text(1) == instance.owner, "process_journal_identity");
    require(sqlite3_step(meta.value) == SQLITE_DONE, "process_journal_identity");
    require(scalar("SELECT count(*) FROM core_attempt a LEFT JOIN core_exit e USING(attempt_id) WHERE e.attempt_id IS NULL") == "0", "process_recovery_required");
  }
  void begin(const std::string& id, const std::wstring& job) {
    execute("BEGIN IMMEDIATE"); Statement q(db.get(), "INSERT INTO core_attempt VALUES(?,?,?)");
    q.bind(1, id); q.bind(2, utf8(job)); q.bind(3, std::to_string(GetCurrentProcessId())); q.done(); execute("COMMIT");
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
};
