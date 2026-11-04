#pragma once

// 独立于bootstrap的已准入核心控制端点；当前接通持久启动查询。
class CoreControl {
  Handle pipe, event;
  OVERLAPPED io{};
  enum class Operation { connecting, reading, writing } operation = Operation::connecting;
  bool pending = false, admitted = false, connectedInline = false;
  unsigned long long deadline = 0;
  std::array<char, 16385> bytes{};
  std::string input, output, sequence = "1", scope, key, launch, intentDigest, supervisor, receiptBody;
  static std::string next(std::string value) {
    for (size_t i = value.size(); i > 0; --i) { if (value[i - 1] != '9') { ++value[i - 1]; return value; } value[i - 1] = '0'; }
    require(value.size() < 20, "control_sequence_exhausted"); return "1" + value;
  }
  void prepare(Operation op) {
    require(!pending, "control_operation"); operation = op;
    require(ResetEvent(event.value) != 0, "control_event"); io = {}; io.hEvent = event.value;
  }
  void complete(BOOL ok, DWORD error) {
    require(ok || error == ERROR_IO_PENDING, "control_io"); pending = true;
    if (ok) require(SetEvent(event.value) != 0, "control_event");
  }
  void read() {
    prepare(Operation::reading); DWORD count = 0;
    const BOOL ok = ReadFile(pipe.value, bytes.data(), static_cast<DWORD>(bytes.size()), &count, &io); complete(ok, GetLastError());
  }
  std::string respond(const std::string& request, ProcessJournal& journal) {
    using namespace bootstrap;
    sqlite3* raw = nullptr; const auto opened = sqlite3_open(":memory:", &raw);
    std::unique_ptr<sqlite3, DatabaseCloser> memory(raw); require(opened == SQLITE_OK, "control_parse");
    const auto value = [&](const char* at) {
      Statement q(raw, "SELECT json_type(?1,?2),json_extract(?1,?2)"); q.bind(1, request); q.bind(2, at);
      require(sqlite3_step(q.value) == SQLITE_ROW && q.text(0) == "text", "control_frame"); const auto v = q.text(1); string(v); return v;
    };
    const auto message = value("$.message_id"), target = value("$.payload.launch_id"), digest = value("$.payload.launch_intent_digest");
    require(digest.size() == 71 && digest.rfind("sha256:", 0) == 0, "control_frame");
    for (size_t i = 7; i < digest.size(); ++i) require((digest[i] >= '0' && digest[i] <= '9') || (digest[i] >= 'a' && digest[i] <= 'f'), "control_frame");
    const auto requestedKey = object({{"launch_id", string(target)}, {"launch_intent_digest", string(digest)}});
    Object frame{{"version", string("supervisor-control/0.1.0-draft.1")}, {"type", string("LAUNCH_QUERY")}, {"scope", scope},
      {"channel_id", string(channel)}, {"sequence", string(sequence)}, {"message_id", string(message)}, {"reply_to", "null"}, {"payload", requestedKey}};
    // 重建完整规范帧同时拒绝重复键、额外字段、错scope/channel/sequence与方向混投。
    require(object(frame) == request, "control_binding");
    frame["message_id"] = string(identifier()); frame["reply_to"] = string(message);
    if (target == launch && digest != intentDigest) {
      frame["type"] = string("ERROR"); frame["payload"] = object({{"code", string("identity_conflict")}, {"retry_action", string("query_only")}});
    } else {
      frame["type"] = string("LAUNCH_RESULT"); std::string record = "null";
      if (target == launch) {
        const auto original = journal.admission(launch); require(original == receiptBody, "control_journal_binding");
        record = object({{"key", key}, {"supervisor_instance_id", string(supervisor)}, {"state", string("admitted_closed")},
          {"creation_attempted", "true"}, {"admission_receipt", original}, {"retirement_evidence", "null"}, {"gate_state", string("closed")}});
      }
      frame["payload"] = object({{"key", requestedKey}, {"record", record}});
    }
    sequence = next(sequence); return object(frame) + '\n';
  }
public:
  std::wstring name;
  std::string channel;
  CoreControl(Instance& instance, const bootstrap::Exchange& exchange) {
    using namespace bootstrap;
    channel = identifier(); name = L"\\\\.\\pipe\\LeafSeamer.Control." + std::wstring(channel.begin(), channel.end());
    launch = exchange.common.at("launch_id"); launch = launch.substr(1, launch.size() - 2);
    intentDigest = exchange.intentDigest; supervisor = exchange.supervisor;
    key = object({{"launch_id", string(launch)}, {"launch_intent_digest", string(intentDigest)}});
    scope = object({{"service_id", string(exchange.policy.service)}, {"database_instance_id", string(exchange.policy.database)},
      {"supervisor_instance_id", string(supervisor)}, {"domain_ref", object({{"clock_domain_id", string(exchange.domainId)}, {"descriptor_digest", string(exchange.descriptorDigest)}})}});
    pipe.value = CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
      PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 32768, 32768, 0, &instance.security);
    require(pipe.value != INVALID_HANDLE_VALUE, "control_endpoint");
    event.value = CreateEventW(nullptr, TRUE, FALSE, nullptr); require(event.value != nullptr, "control_event");
    prepare(Operation::connecting); const BOOL ok = ConnectNamedPipe(pipe.value, &io); const auto error = GetLastError();
    if (!ok && error == ERROR_PIPE_CONNECTED) { pending = true; connectedInline = true; require(SetEvent(event.value) != 0, "control_event"); }
    else complete(ok, error);
  }
  ~CoreControl() {
    if (pending && !connectedInline) { CancelIoEx(pipe.value, &io); DWORD ignored = 0; GetOverlappedResult(pipe.value, &io, &ignored, TRUE); }
  }
  void activate(const std::string& receipt) { require(!admitted, "control_state"); receiptBody = receipt; admitted = true; deadline = GetTickCount64() + 5000; }
  void poll(HANDLE process, DWORD pid, HANDLE job, ProcessJournal& journal) {
    require(admitted && GetTickCount64() < deadline, "control_timeout");
    BOOL belongs = FALSE;
    require(WaitForSingleObject(process, 0) == WAIT_TIMEOUT && IsProcessInJob(process, job, &belongs) && belongs, "control_process");
    const auto wait = WaitForSingleObject(event.value, 0); if (wait == WAIT_TIMEOUT) return;
    require(wait == WAIT_OBJECT_0 && pending, "control_event"); DWORD count = 0;
    if (!connectedInline) require(GetOverlappedResult(pipe.value, &io, &count, FALSE) != 0, "control_closed");
    connectedInline = false; pending = false;
    if (operation == Operation::connecting) {
      ULONG actual = 0; require(GetNamedPipeClientProcessId(pipe.value, &actual) && actual == pid, "control_peer"); read(); return;
    }
    if (operation == Operation::writing) { require(count == output.size(), "control_partial_write"); output.clear(); deadline = GetTickCount64() + 5000; read(); return; }
    require(count > 0 && input.size() + count <= 16385, "control_frame"); input.append(bytes.data(), count);
    const auto end = input.find('\n'); if (end == std::string::npos) { read(); return; }
    require(end == input.size() - 1, "control_frame"); input.pop_back(); output = respond(input, journal); input.clear();
    require(output.size() <= 16385, "control_capacity"); prepare(Operation::writing); DWORD written = 0;
    const BOOL ok = WriteFile(pipe.value, output.data(), static_cast<DWORD>(output.size()), &written, &io); complete(ok, GetLastError());
  }
};
