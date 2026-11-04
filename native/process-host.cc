#include <windows.h>
#include <bcrypt.h>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <vector>

// 进程容纳与核心bootstrap；回执保持closed，不授予设备会话或设备写许可。
struct Handle {
  HANDLE value = nullptr;
  Handle() = default;
  explicit Handle(HANDLE h) : value(h) {}
  Handle(const Handle&) = delete;
  Handle& operator=(const Handle&) = delete;
  ~Handle() { reset(); }
  void reset() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); value = nullptr; }
};
static void require(bool ok, const char* reason) { if (!ok) throw std::runtime_error(reason); }
static std::wstring quote(const std::wstring& input) {
  std::wstring out = L"\""; size_t slashes = 0;
  for (wchar_t c : input) {
    if (c == L'\\') { ++slashes; continue; }
    out.append(slashes * (c == L'\"' ? 2 : 1), L'\\'); slashes = 0;
    if (c == L'\"') out += L'\\'; out += c;
  }
  out.append(slashes * 2, L'\\'); return out + L'\"';
}
static bool absolute(const std::wstring& p) {
  return p.size() >= 3 && ((p[1] == L':' && (p[2] == L'\\' || p[2] == L'/')) || (p[0] == L'\\' && p[1] == L'\\'));
}
static std::string identifier() {
  unsigned char bytes[16];
  require(BCryptGenRandom(nullptr, bytes, sizeof(bytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0, "random_unavailable");
  const char* hex = "0123456789abcdef"; std::string s;
  for (auto b : bytes) { s += hex[b >> 4]; s += hex[b & 15]; } return s;
}
#include "process-journal.h"
#include "process-bootstrap.h"
struct Attributes {
  std::vector<unsigned char> buffer; LPPROC_THREAD_ATTRIBUTE_LIST list = nullptr;
  Attributes() {
    SIZE_T size = 0; InitializeProcThreadAttributeList(nullptr, 2, 0, &size);
    require(size > 0, "attributes_size"); buffer.resize(size);
    list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(buffer.data());
    if (!InitializeProcThreadAttributeList(list, 2, 0, &size)) { list = nullptr; throw std::runtime_error("attributes_init"); }
  }
  ~Attributes() { if (list) DeleteProcThreadAttributeList(list); }
};
static DWORD active(HANDLE job) {
  JOBOBJECT_BASIC_ACCOUNTING_INFORMATION info{};
  require(QueryInformationJobObject(job, JobObjectBasicAccountingInformation, &info, sizeof(info), nullptr) != 0, "group_observation_failed");
  return info.ActiveProcesses;
}
int wmain(int argc, wchar_t** argv) {
  try {
    // 低层入口只由本机可信装配使用，不接受 shell 命令或环境指定的解释器。
    const bool initialize = argc == 3 && std::wstring(argv[1]) == L"--initialize";
    const bool upgrade = argc == 3 && std::wstring(argv[1]) == L"--upgrade";
    require(initialize || upgrade ? absolute(argv[2]) : (argc >= 4 && absolute(argv[1]) && absolute(argv[2]) && absolute(argv[3])), "process_arguments");
    require(GetFileType(GetStdHandle(STD_INPUT_HANDLE)) == FILE_TYPE_PIPE, "control_pipe_required");
    require(GetFileType(GetStdHandle(STD_OUTPUT_HANDLE)) == FILE_TYPE_PIPE, "status_pipe_required");
    Instance instance(initialize || upgrade ? argv[2] : argv[1]); ProcessJournal journal(instance, initialize, upgrade);
    if (initialize) { printf("{\"event\":\"process_journal_initialized\",\"runtime_admitted\":false}\n"); fflush(stdout); return 0; }
    if (upgrade) { printf("{\"event\":\"process_journal_upgraded\",\"changed\":%s,\"schema_revision\":\"2\",\"runtime_admitted\":false}\n", journal.upgraded ? "true" : "false"); fflush(stdout); return 0; }
    const std::string id = identifier(); const std::wstring jobName = L"Global\\LeafSeamer.Core." + std::wstring(id.begin(), id.end());
    std::unique_ptr<bootstrap::Policy> policy;
    if (argc >= 7 && std::wstring(argv[4]) == L"contained-core-auth") {
      for (int i = 5; i + 1 < argc; i += 2) if (std::wstring(argv[i]) == L"--bootstrap-policy") { require(!policy, "bootstrap_policy"); policy = std::make_unique<bootstrap::Policy>(utf8(argv[i + 1])); }
      require(policy != nullptr, "bootstrap_policy");
    }
    std::unique_ptr<bootstrap::Exchange> exchange;
    if (policy) exchange = std::make_unique<bootstrap::Exchange>(*policy, id);
    Handle job(CreateJobObjectW(&instance.security, jobName.c_str())); const DWORD jobError = GetLastError();
    require(job.value != nullptr && jobError != ERROR_ALREADY_EXISTS, "job_create_failed");
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    require(SetInformationJobObject(job.value, JobObjectExtendedLimitInformation, &limits, sizeof(limits)) != 0, "job_limits_failed");
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION actual{};
    require(QueryInformationJobObject(job.value, JobObjectExtendedLimitInformation, &actual, sizeof(actual), nullptr) != 0 &&
      actual.BasicLimitInformation.LimitFlags == JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, "job_limits_mismatch");
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE}; Handle coreInput, inputWriter, coreOutput, proofReader, proofWriter;
    require(CreatePipe(&coreInput.value, &inputWriter.value, &sa, 32768) != 0, "core_pipe_failed");
    require(SetHandleInformation(inputWriter.value, HANDLE_FLAG_INHERIT, 0) != 0, "core_pipe_inheritance");
    // 核心输出与监督状态物理分离；核心不能伪造本宿主的状态帧。
    require(DuplicateHandle(GetCurrentProcess(), GetStdHandle(STD_ERROR_HANDLE), GetCurrentProcess(), &coreOutput.value,
      0, TRUE, DUPLICATE_SAME_ACCESS) != 0, "core_output_failed");
    if (exchange) {
      require(CreatePipe(&proofReader.value, &proofWriter.value, &sa, 32768) != 0 && SetHandleInformation(proofReader.value, HANDLE_FLAG_INHERIT, 0) != 0, "bootstrap_pipe");
    }
    Attributes attributes; HANDLE jobs[] = {job.value}; std::vector<HANDLE> inherited{coreInput.value, coreOutput.value};
    if (exchange) inherited.push_back(proofWriter.value);
    require(UpdateProcThreadAttribute(attributes.list, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST, jobs, sizeof(jobs), nullptr, nullptr) != 0, "job_attribute_failed");
    require(UpdateProcThreadAttribute(attributes.list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited.data(), inherited.size() * sizeof(HANDLE), nullptr, nullptr) != 0, "handle_attribute_failed");
    STARTUPINFOEXW si{}; si.StartupInfo.cb = sizeof(si); si.lpAttributeList = attributes.list;
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES; si.StartupInfo.hStdInput = coreInput.value;
    si.StartupInfo.hStdOutput = exchange ? proofWriter.value : coreOutput.value; si.StartupInfo.hStdError = coreOutput.value;
    std::wstring command = quote(argv[2]) + L" --disallow-code-generation-from-strings " + quote(argv[3]);
    for (int i = 4; i < argc; ++i) { require(wcslen(argv[i]) <= 32768, "argument_capacity"); command += L" " + quote(argv[i]); }
    command += L" --data-dir " + quote(instance.path);
    require(command.size() < 32767, "command_capacity"); PROCESS_INFORMATION pi{};
    journal.begin(id, jobName, exchange ? policy->body : "", exchange ? exchange->descriptor : "", exchange ? exchange->intent : "");
    require(CreateProcessW(argv[2], command.data(), nullptr, nullptr, TRUE,
      EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW, nullptr, nullptr, &si.StartupInfo, &pi) != 0, "process_create_failed");
    Handle process(pi.hProcess), thread(pi.hThread); coreInput.reset(); coreOutput.reset(); proofWriter.reset();
    BOOL belongs = FALSE;
    require(IsProcessInJob(process.value, job.value, &belongs) != 0 && belongs && active(job.value) == 1, "process_containment_failed");
    std::vector<wchar_t> image(32768); DWORD imageSize = static_cast<DWORD>(image.size());
    require(QueryFullProcessImageNameW(process.value, 0, image.data(), &imageSize) != 0, "process_image_failed");
    Handle expected(CreateFileW(argv[2], FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr));
    Handle loaded(CreateFileW(image.data(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr));
    BY_HANDLE_FILE_INFORMATION a{}, b{};
    require(expected.value != INVALID_HANDLE_VALUE && loaded.value != INVALID_HANDLE_VALUE &&
      GetFileInformationByHandle(expected.value, &a) && GetFileInformationByHandle(loaded.value, &b) &&
      a.dwVolumeSerialNumber == b.dwVolumeSerialNumber && a.nFileIndexHigh == b.nFileIndexHigh && a.nFileIndexLow == b.nFileIndexLow, "process_image_mismatch");
    journal.observed(id, process.value, pi.dwProcessId, loaded.value);
    require(ResumeThread(thread.value) == 1, "process_resume_failed"); thread.reset();
    if (exchange) {
      bootstrap::write(inputWriter.value, exchange->assignment());
      const auto proof = bootstrap::read(proofReader.value, process.value, exchange->expires);
      require(bootstrap::tick() < exchange->expires && bootstrap::equal(proof, exchange->expectedProof()), "bootstrap_proof");
      require(IsProcessInJob(process.value, job.value, &belongs) != 0 && belongs, "bootstrap_containment");
      const auto receipt = exchange->receipt(id);
      journal.admitted(id, exchange->receiptId, bootstrap::object(receipt));
      require(bootstrap::tick() < exchange->expires, "bootstrap_expired");
      bootstrap::write(inputWriter.value, bootstrap::Exchange::frame("ADMISSION", receipt));
    }
    printf("{\"event\":\"process_contained\",\"containment_id\":\"%s\",\"supervisor_pid\":%lu,\"core_pid\":%lu,\"bootstrap_authenticated\":%s,\"runtime_admitted\":false}\n",
      id.c_str(), GetCurrentProcessId(), pi.dwProcessId, exchange ? "true" : "false"); fflush(stdout);
    exchange.reset(); // 挑战秘密不进入普通运行期或日志。
    bool requested = false, invalid = false; std::string input;
    while (WaitForSingleObject(process.value, 20) == WAIT_TIMEOUT) {
      if (policy) { DWORD extra = 0; if (!PeekNamedPipe(proofReader.value, nullptr, 0, nullptr, &extra, nullptr) || extra) { invalid = true; break; } }
      DWORD count = 0;
      if (!PeekNamedPipe(GetStdHandle(STD_INPUT_HANDLE), nullptr, 0, nullptr, &count, nullptr)) { requested = true; break; }
      if (!count) continue;
      char bytes[16]; DWORD read = 0;
      require(ReadFile(GetStdHandle(STD_INPUT_HANDLE), bytes, count > sizeof(bytes) ? sizeof(bytes) : count, &read, nullptr) != 0, "control_read_failed");
      input.append(bytes, read);
      if (input == "stop\n") { requested = true; break; }
      if (input.size() >= 5 || std::string("stop\n").compare(0, input.size(), input) != 0) { invalid = true; break; }
    }
    // 不再创建任何进程；正常请求给核心两秒关闭库，随后终止全部残留后代。
    bool forced = false;
    if (requested) {
      DWORD written = 0; const char stop[] = "stop\n";
      if (WriteFile(inputWriter.value, stop, 5, &written, nullptr) && written == 5) {
        const ULONGLONG grace = GetTickCount64() + 2000;
        while (active(job.value) != 0 || WaitForSingleObject(process.value, 0) != WAIT_OBJECT_0) {
          if (GetTickCount64() >= grace) { forced = true; break; } Sleep(10);
        }
      } else forced = true;
    }
    inputWriter.reset();
    if (active(job.value) != 0) forced = true;
    require(TerminateJobObject(job.value, 1) != 0, "group_termination_failed");
    const ULONGLONG deadline = GetTickCount64() + 5000;
    while (active(job.value) != 0) { require(GetTickCount64() < deadline, "group_exit_unproven"); Sleep(10); }
    require(WaitForSingleObject(process.value, 5000) == WAIT_OBJECT_0, "core_exit_unproven");
    DWORD code = 1; require(GetExitCodeProcess(process.value, &code) != 0, "core_status_failed");
    journal.retired(id, code, forced);
    printf("{\"event\":\"process_group_empty\",\"containment_id\":\"%s\",\"active_processes\":0,\"core_exit_code\":%lu,\"stop_requested\":%s,\"forced\":%s,\"runtime_admitted\":false}\n",
      id.c_str(), code, requested ? "true" : "false", forced ? "true" : "false"); fflush(stdout);
    return !invalid && code == 0 && !forced ? 0 : 1;
  } catch (const std::exception& e) {
    // 栈展开关闭唯一 Job 句柄；没有观察到空组时不产生 empty 成功帧。
    printf("{\"event\":\"process_host_failed\",\"code\":\"%s\",\"runtime_admitted\":false}\n", e.what()); fflush(stdout); return 1;
  }
}
