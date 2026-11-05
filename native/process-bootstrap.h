#pragma once
#include <wincrypt.h>
#include <array>
#include <map>
#include <set>
#include <limits>

namespace bootstrap {
using Object = std::map<std::string, std::string>;
static std::string string(const std::string& value) {
  require(!value.empty() && value.size() <= 128, "bootstrap_value");
  for (const unsigned char c : value) require((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
    (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' || c == ':' || c == '/', "bootstrap_value");
  return "\"" + value + "\"";
}
// 该投影仅含已验证ASCII标识、十进制字符串、常量及嵌套对象，无浮点或任意用户字符串。
static std::string object(const Object& values) {
  std::string out = "{"; bool first = true;
  for (const auto& item : values) { if (!first) out += ','; first = false; out += string(item.first) + ':' + item.second; }
  return out + '}';
}
struct Hash {
  BCRYPT_ALG_HANDLE algorithm = nullptr; BCRYPT_HASH_HANDLE state = nullptr;
  Hash(const unsigned char* key = nullptr, ULONG size = 0) {
    require(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, key ? BCRYPT_ALG_HANDLE_HMAC_FLAG : 0) == 0, "bootstrap_crypto");
    if (BCryptCreateHash(algorithm, &state, nullptr, 0, const_cast<PUCHAR>(key), size, 0) != 0) {
      BCryptCloseAlgorithmProvider(algorithm, 0); algorithm = nullptr; throw std::runtime_error("bootstrap_crypto");
    }
  }
  ~Hash() { if (state) BCryptDestroyHash(state); if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0); }
  std::array<unsigned char, 32> finish(const std::string& bytes) {
    require(bytes.size() <= 8388608 && BCryptHashData(state, reinterpret_cast<PUCHAR>(const_cast<char*>(bytes.data())), static_cast<ULONG>(bytes.size()), 0) == 0, "bootstrap_crypto");
    std::array<unsigned char, 32> value{}; require(BCryptFinishHash(state, value.data(), static_cast<ULONG>(value.size()), 0) == 0, "bootstrap_crypto"); return value;
  }
};
static std::string digest(const std::string& bytes) {
  Hash hash; const auto value = hash.finish(bytes); const char* hex = "0123456789abcdef"; std::string out = "sha256:";
  for (const auto c : value) { out += hex[c >> 4]; out += hex[c & 15]; } return out;
}
static std::string base64(const std::array<unsigned char, 32>& bytes) {
  DWORD size = 0; const DWORD flags = CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF;
  require(CryptBinaryToStringA(bytes.data(), static_cast<DWORD>(bytes.size()), flags, nullptr, &size) != 0, "bootstrap_encoding");
  std::string result(size, '\0'); require(CryptBinaryToStringA(bytes.data(), static_cast<DWORD>(bytes.size()), flags, result.data(), &size) != 0, "bootstrap_encoding");
  while (!result.empty() && (result.back() == '\0' || result.back() == '=')) result.pop_back();
  for (auto& c : result) { if (c == '+') c = '-'; else if (c == '/') c = '_'; }
  require(result.size() == 43, "bootstrap_encoding"); return result;
}
struct Secret {
  std::array<unsigned char, 32> bytes{};
  Secret() { require(BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(bytes.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0, "bootstrap_random"); }
  ~Secret() { SecureZeroMemory(bytes.data(), bytes.size()); }
};
static unsigned long long tick() {
  ULONGLONG value = 0; QueryInterruptTimePrecise(&value);
  require(value <= std::numeric_limits<unsigned long long>::max() / 100, "bootstrap_clock"); return value * 100;
}
struct Policy {
  std::string service, database, manifest, profile, revision, clockRevision, body;
  unsigned long long timeout = 0;
  explicit Policy(const std::string& input) {
    require(input.size() <= 8192, "bootstrap_policy");
    sqlite3* raw = nullptr; require(sqlite3_open(":memory:", &raw) == SQLITE_OK, "bootstrap_policy");
    std::unique_ptr<sqlite3, DatabaseCloser> db(raw);
    const auto fields = [&](const char* at, const std::set<std::string>& expected) {
      Statement type(raw, "SELECT json_valid(?1),json_type(?1,?2)"); type.bind(1, input); type.bind(2, at);
      require(sqlite3_step(type.value) == SQLITE_ROW && type.text(0) == "1" && type.text(1) == "object", "bootstrap_policy");
      Statement rows(raw, "SELECT key FROM json_each(?1,?2)"); rows.bind(1, input); rows.bind(2, at);
      std::set<std::string> found; int code;
      while ((code = sqlite3_step(rows.value)) == SQLITE_ROW) require(found.insert(rows.text(0)).second, "bootstrap_policy");
      require(code == SQLITE_DONE && found == expected, "bootstrap_policy");
    };
    const auto value = [&](const char* at) {
      Statement q(raw, "SELECT json_type(?1,?2),json_extract(?1,?2)"); q.bind(1, input); q.bind(2, at);
      require(sqlite3_step(q.value) == SQLITE_ROW && q.text(0) == "text", "bootstrap_policy");
      const auto result = q.text(1); string(result); return result;
    };
    fields("$", {"format", "service_id", "database_instance_id", "artifact_manifest_ref", "platform_profile_ref", "policy_revision", "bootstrap_timeout_ms", "clock_backend_revision"});
    fields("$.artifact_manifest_ref", {"manifest_id", "revision", "digest"}); fields("$.platform_profile_ref", {"profile_id", "revision"});
    require(value("$.format") == "leafseamer-core-bootstrap-policy/1", "bootstrap_policy");
    service = value("$.service_id"); database = value("$.database_instance_id"); revision = value("$.policy_revision"); clockRevision = value("$.clock_backend_revision");
    const auto decimal = [](const std::string& s) { require(s.size() <= 20 && (s == "0" || s[0] != '0'), "bootstrap_policy");
      for (const char c : s) require(c >= '0' && c <= '9', "bootstrap_policy"); };
    decimal(revision); const auto manifestRevision = value("$.artifact_manifest_ref.revision"), profileRevision = value("$.platform_profile_ref.revision");
    decimal(manifestRevision); decimal(profileRevision); const auto manifestDigest = value("$.artifact_manifest_ref.digest");
    require(manifestDigest.size() == 71 && manifestDigest.rfind("sha256:", 0) == 0, "bootstrap_policy");
    for (size_t i = 7; i < manifestDigest.size(); ++i) require((manifestDigest[i] >= '0' && manifestDigest[i] <= '9') || (manifestDigest[i] >= 'a' && manifestDigest[i] <= 'f'), "bootstrap_policy");
    manifest = object({{"manifest_id", string(value("$.artifact_manifest_ref.manifest_id"))}, {"revision", string(manifestRevision)}, {"digest", string(manifestDigest)}});
    profile = object({{"profile_id", string(value("$.platform_profile_ref.profile_id"))}, {"revision", string(profileRevision)}});
    Statement duration(raw, "SELECT json_type(?1,'$.bootstrap_timeout_ms'),json_extract(?1,'$.bootstrap_timeout_ms')"); duration.bind(1, input);
    require(sqlite3_step(duration.value) == SQLITE_ROW && duration.text(0) == "integer", "bootstrap_policy");
    const auto millis = sqlite3_column_int64(duration.value, 1); require(millis >= 1 && millis <= 60000, "bootstrap_policy"); timeout = static_cast<unsigned long long>(millis);
    body = object({{"format", string("leafseamer-core-bootstrap-policy/1")}, {"service_id", string(service)}, {"database_instance_id", string(database)},
      {"artifact_manifest_ref", manifest}, {"platform_profile_ref", profile}, {"policy_revision", string(revision)},
      {"bootstrap_timeout_ms", std::to_string(timeout)}, {"clock_backend_revision", string(clockRevision)}});
    require(body == input, "bootstrap_policy_canonical");
  }
};
static void write(HANDLE pipe, const std::string& bytes) {
  require(bytes.size() <= 16384, "bootstrap_frame"); const std::string line = bytes + '\n'; DWORD written = 0;
  require(WriteFile(pipe, line.data(), static_cast<DWORD>(line.size()), &written, nullptr) && written == line.size(), "bootstrap_channel_closed");
}
static std::string read(HANDLE pipe, HANDLE process, unsigned long long expires) {
  std::string result;
  for (;;) {
    require(tick() < expires, "bootstrap_expired"); require(WaitForSingleObject(process, 0) == WAIT_TIMEOUT, "bootstrap_process_exit");
    DWORD count = 0; require(PeekNamedPipe(pipe, nullptr, 0, nullptr, &count, nullptr) != 0, "bootstrap_channel_closed");
    if (!count) { Sleep(2); continue; }
    char buffer[4096]; DWORD received = 0;
    require(ReadFile(pipe, buffer, count > sizeof(buffer) ? sizeof(buffer) : count, &received, nullptr) && received > 0, "bootstrap_channel_closed");
    result.append(buffer, received); require(result.size() <= 16385, "bootstrap_frame");
    const auto end = result.find('\n'); if (end == std::string::npos) continue;
    require(end == result.size() - 1, "bootstrap_frame"); result.pop_back(); return result;
  }
}
static bool equal(const std::string& a, const std::string& b) {
  if (a.size() != b.size()) return false; unsigned char difference = 0;
  for (size_t i = 0; i < a.size(); ++i) difference |= static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]);
  return difference == 0;
}
struct Domain {
  const Policy& policy;
  std::string supervisor,generation,descriptor,domainId,descriptorDigest;
  Domain(const Policy& p,const std::string& instance,const std::string& currentGeneration,const std::string& body,const std::string& id,const std::string& digest)
    :policy(p),supervisor(instance),generation(currentGeneration),descriptor(body),domainId(id),descriptorDigest(digest){}
};
struct Exchange {
  const Policy& policy; Secret secret, nonce;
  std::string supervisor, generation, member, memberBoot, bootstrapId, channel, challenge, receiptId, descriptor, intent, containment;
  std::string domainId, descriptorDigest, intentDigest; unsigned long long issued, expires;
  Object common;
  Exchange(const Policy& p, const std::string& attempt) : policy(p) {
    supervisor = identifier(); generation = identifier(); member = identifier(); memberBoot = identifier(); bootstrapId = identifier();
    channel = identifier(); challenge = identifier(); receiptId = identifier(); issued = tick();
    require(issued <= std::numeric_limits<unsigned long long>::max() - policy.timeout * 1000000, "bootstrap_clock"); expires = issued + policy.timeout * 1000000;
    // 平台profile由可信装配选定；os_boot_identity没有平台证据时明确unavailable。
    sqlite3* raw = nullptr; require(sqlite3_open(":memory:", &raw) == SQLITE_OK, "bootstrap_policy"); std::unique_ptr<sqlite3, DatabaseCloser> db(raw);
    Statement q(raw, "SELECT json_extract(?1,'$.profile_id'),json_extract(?1,'$.revision')"); q.bind(1, policy.profile); require(sqlite3_step(q.value) == SQLITE_ROW, "bootstrap_policy");
    Object descriptorBody{{"descriptor_version", string("clock-domain/1")}, {"domain_kind", string("supervised_runtime")}, {"authority_service_id", string(policy.service)},
      {"runtime_generation", string(generation)}, {"supervisor_instance_id", string(supervisor)}, {"clock_backend_id", string("windows_interrupt_precise")},
      {"clock_backend_revision", string(policy.clockRevision)}, {"tick_unit", string("ns")}, {"suspend_accounting", string("included")},
      {"namespace_identity", string("windows-global")}, {"os_boot_identity", "{\"status\":\"unavailable\"}"},
      {"platform_profile_id", string(q.text(0))}, {"platform_profile_revision", string(q.text(1))}};
    descriptorDigest = digest(object(descriptorBody)); domainId = "clock_" + descriptorDigest.substr(7);
    descriptorBody["clock_domain_id"] = string(domainId); descriptorBody["descriptor_digest"] = string(descriptorDigest); descriptor = object(descriptorBody);
    containment = object({{"group_id", string(attempt)}, {"generation", string(generation)}, {"backend", string("windows_job")}});
    intent = object({{"launch_id", string(attempt)}, {"service_id", string(policy.service)}, {"supervisor_instance_id", string(supervisor)}, {"runtime_generation", string(generation)},
      {"member_id", string(member)}, {"role", string("core")}, {"artifact_manifest_ref", policy.manifest}, {"containment_ref", containment}, {"device_ids", "[]"}, {"policy_revision", string(policy.revision)}});
    intentDigest = digest(intent);
    common = {{"bootstrap_version", string("bootstrap/0.1.0-draft.1")}, {"bootstrap_id", string(bootstrapId)}, {"launch_id", string(attempt)},
      {"launch_intent_digest", string(intentDigest)}, {"member_id", string(member)}, {"member_boot_id", string(memberBoot)}, {"role", string("core")},
      {"artifact_manifest_ref", policy.manifest}, {"channel_binding_id", string(channel)}, {"challenge_id", string(challenge)}};
  }
  Exchange(const Domain& parent,const std::string& launch,const std::string& body,const std::string& memberId,const std::string& group):policy(parent.policy){
    supervisor=parent.supervisor;generation=parent.generation;descriptor=parent.descriptor;domainId=parent.domainId;descriptorDigest=parent.descriptorDigest;
    member=memberId;memberBoot=identifier();bootstrapId=identifier();channel=identifier();challenge=identifier();receiptId=identifier();
    intent=body;intentDigest=digest(body);containment=group;issued=tick();
    require(issued<=std::numeric_limits<unsigned long long>::max()-policy.timeout*1000000,"bootstrap_clock");expires=issued+policy.timeout*1000000;
    common={{"bootstrap_version",string("bootstrap/0.1.0-draft.1")},{"bootstrap_id",string(bootstrapId)},{"launch_id",string(launch)},
      {"launch_intent_digest",string(intentDigest)},{"member_id",string(member)},{"member_boot_id",string(memberBoot)},{"role",string("worker")},
      {"artifact_manifest_ref",policy.manifest},{"channel_binding_id",string(channel)},{"challenge_id",string(challenge)}};
  }
  static std::string frame(const char* type, const Object& payload) {
    return object({{"version", string("bootstrap/0.1.0-draft.1")}, {"type", string(type)}, {"payload", object(payload)}});
  }
  std::string assignment() const {
    auto value = common; value["clock_domain_descriptor"] = descriptor; value["challenge_nonce"] = string(base64(nonce.bytes));
    value["issued_tick_ns"] = string(std::to_string(issued)); value["expires_tick_ns"] = string(std::to_string(expires)); value["secret"] = string(base64(secret.bytes)); return frame("ASSIGNMENT", value);
  }
  std::string expectedProof() const {
    auto projection = common; projection["clock_domain_id"] = string(domainId); projection["descriptor_digest"] = string(descriptorDigest);
    auto result = projection; projection["challenge_nonce"] = string(base64(nonce.bytes)); projection["issued_tick_ns"] = string(std::to_string(issued)); projection["expires_tick_ns"] = string(std::to_string(expires));
    std::string prefix = "leafseamer-bootstrap-proof/v1"; prefix += '\0'; Hash mac(secret.bytes.data(), static_cast<ULONG>(secret.bytes.size()));
    result["proof"] = string(base64(mac.finish(prefix + object(projection)))); return frame("PROOF", result);
  }
  Object receipt(const std::string& observation) const {
    auto result = common; result.erase("bootstrap_version"); result.erase("challenge_id");
    result["receipt_id"] = string(receiptId); result["domain_ref"] = object({{"clock_domain_id", string(domainId)}, {"descriptor_digest", string(descriptorDigest)}});
    result["containment_ref"] = containment; result["os_observation_ref"] = string(observation); result["admitted_tick_ns"] = string(std::to_string(tick())); result["gate_state"] = string("closed"); return result;
  }
};
}
