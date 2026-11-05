#pragma once

// 由已认证核心提交完整启动意图；规范重建避免让摘要替代结构、域及授权绑定。
class WorkerFields {
protected:
  sqlite3* db;
  const std::string& request;
  std::string text(const std::string& path) {
    Statement q(db, "SELECT json_type(?1,?2),json_extract(?1,?2)"); q.bind(1, request); q.bind(2, path);
    require(sqlite3_step(q.value) == SQLITE_ROW && q.text(0) == "text", "worker_frame"); return q.text(1);
  }
  std::string id(const std::string& path) {
    auto v = text(path); require(!v.empty() && v.size() <= 128, "worker_id");
    for (size_t i = 0; i < v.size(); ++i) { const char c = v[i]; const bool alnum = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
      require(alnum || (i > 0 && (c == '_' || c == '-' || c == '.' || c == ':')), "worker_id"); }
    return v;
  }
  std::string number(const std::string& path) {
    auto v = text(path); require(!v.empty() && v.size() <= 20 && (v == "0" || v[0] != '0'), "worker_number");
    for (const char c : v) require(c >= '0' && c <= '9', "worker_number"); return v;
  }
  std::string digest(const std::string& path) {
    auto v = text(path); require(v.size() == 71 && v.rfind("sha256:", 0) == 0, "worker_digest");
    for (size_t i = 7; i < v.size(); ++i) require((v[i] >= '0' && v[i] <= '9') || (v[i] >= 'a' && v[i] <= 'f'), "worker_digest"); return v;
  }
  unsigned long length(const std::string& path, unsigned long minimum, unsigned long maximum) {
    Statement q(db, "SELECT json_type(?1,?2),json_array_length(?1,?2)"); q.bind(1, request); q.bind(2, path);
    require(sqlite3_step(q.value) == SQLITE_ROW && q.text(0) == "array", "worker_scope");
    const auto size = std::stoul(q.text(1)); require(size >= minimum && size <= maximum, "worker_scope"); return size;
  }
  std::string reference(const std::string& at, const std::string& kind, bool local = false) {
    using namespace bootstrap;
    require(text(at + ".kind") == kind, "worker_reference");
    const auto owner = id(at + ".authority_service_id"), database = id(at + ".database_instance_id");
    if (local && (owner != service || database != databaseId)) authorized = false;
    return object({{"kind", string(kind)}, {"authority_service_id", string(owner)}, {"database_instance_id", string(database)},
      {"object_id", string(id(at + ".object_id"))}, {"revision", string(number(at + ".revision"))}, {"digest", string(digest(at + ".digest"))}});
  }
  std::string references(const std::string& at, const std::string& kind, unsigned long minimum, unsigned long maximum) {
    std::string result = "[", previous; std::set<std::string> identities;
    const auto size = length(at, minimum, maximum);
    for (unsigned long i = 0; i < size; ++i) {
      const auto path = at + '[' + std::to_string(i) + ']';
      const auto identity = id(path + ".authority_service_id") + '\0' + id(path + ".database_instance_id") + '\0' + id(path + ".object_id");
      const auto key = identity + '\0' + number(path + ".revision") + '\0' + digest(path + ".digest");
      require(key > previous && identities.insert(identity).second, "worker_scope_order"); previous = key;
      if (i) result += ','; result += reference(path, kind, true);
    }
    return result + ']';
  }
public:
  std::string service, databaseId;
  bool authorized = true;
  WorkerFields(sqlite3* database, const std::string& raw, const std::string& serviceId, const std::string& databaseIdentity)
    : db(database), request(raw), service(serviceId), databaseId(databaseIdentity) {}
};

class WorkerGrant : public WorkerFields {
public:
  bootstrap::Object fields;
  std::string authorization, fenceRevision;
  bool expired = false;
  unsigned long long issuedTick=0,deadlineTick=0;
  bool current()const{const auto now=bootstrap::tick();return deadlineTick>issuedTick&&deadlineTick-issuedTick<=2000000000ULL&&now>=issuedTick&&now<deadlineTick;}
  WorkerGrant(sqlite3* database, const std::string& raw, const std::string& serviceId, const std::string& databaseIdentity,
      const std::string& supervisor, const std::string& domain) : WorkerFields(database, raw, serviceId, databaseIdentity) {
    using namespace bootstrap;
    const std::string auth = "$.payload.authorization";
    fields = {{"authorization_ref", reference(auth + ".authorization_ref", "launch_authorization", true)}, {"launch_id", string(id(auth + ".launch_id"))},
      {"launch_intent_digest", string(digest(auth + ".launch_intent_digest"))}, {"supervisor_instance_id", string(id(auth + ".supervisor_instance_id"))},
      {"permissions_digest", string(digest(auth + ".permissions_digest"))}};
    for (const auto& pair : std::vector<std::pair<std::string, std::string>>{{"installation_ref", "installation"}, {"approval_ref", "approval"}, {"role_resolution_ref", "role_resolution"}})
      fields[pair.first] = reference(auth + '.' + pair.first, pair.second, true);
    if (fields["supervisor_instance_id"] != string(supervisor)) authorized = false;
    fenceRevision = number(auth + ".fence_revision"); fields["fence_revision"] = string(fenceRevision);
    const auto clock = object({{"clock_domain_id", string(id(auth + ".lifetime.clock.clock_domain_id"))}, {"descriptor_digest", string(digest(auth + ".lifetime.clock.descriptor_digest"))}});
    const auto issued = number(auth + ".lifetime.issued_tick"), deadline = number(auth + ".lifetime.deadline_tick");
    fields["lifetime"] = object({{"clock", clock}, {"issued_tick", string(issued)}, {"deadline_tick", string(deadline)}});
    if (clock != domain) authorized = false;
    const auto start = std::stoull(issued), end = std::stoull(deadline), now = tick();
    issuedTick=start;deadlineTick=end;expired = end <= start || end - start > 2000000000ULL || now < start || now >= end;
    auto body=fields;body.erase("authorization_ref");
    if(digest(auth+".authorization_ref.digest")!=bootstrap::digest(object(body)))authorized=false;
    authorization = object(fields);
  }
};

class WorkerInput : public WorkerFields {
public:
  std::string launch, member, group, groupGeneration, intent, intentDigest, authorization, fenceRevision, objectKind;
  bool expired = false;
  WorkerInput(sqlite3* database, const std::string& raw, const std::string& serviceId, const std::string& databaseIdentity,
      const std::string& supervisor, const std::string& generation, const std::string& rootGroup, const std::string& rootMember,
      const std::string& manifest, const std::string& policyRevision, const std::string& domain) : WorkerFields(database, raw, serviceId, databaseIdentity) {
    using namespace bootstrap;
    const std::string at = "$.payload.intent", bind = at + ".extension_binding";
    launch = id(at + ".launch_id"); member = id(at + ".member_id"); group = id(at + ".containment_ref.group_id"); groupGeneration = id(at + ".containment_ref.generation");
    Object artifact{{"manifest_id", string(id(at + ".artifact_manifest_ref.manifest_id"))}, {"revision", string(number(at + ".artifact_manifest_ref.revision"))},
      {"digest", string(digest(at + ".artifact_manifest_ref.digest"))}};
    Object containment{{"group_id", string(group)}, {"generation", string(groupGeneration)}, {"backend", string(text(at + ".containment_ref.backend"))}};
    const auto targetService = id(at + ".service_id"), targetSupervisor = id(at + ".supervisor_instance_id"), targetGeneration = id(at + ".runtime_generation"), revision = number(at + ".policy_revision");
    require(text(at + ".role") == "worker", "worker_role");
    authorized = targetService == service && targetSupervisor == supervisor && targetGeneration == generation && group != rootGroup && member != rootMember && launch != rootGroup &&
      text(at + ".containment_ref.backend") == "windows_job" && object(artifact) == manifest && revision == policyRevision;
    Object binding;
    for (const auto& pair : std::vector<std::pair<std::string, std::string>>{{"installation_ref", "installation"}, {"approval_ref", "approval"}, {"review_ref", "review"},
      {"role_resolution_ref", "role_resolution"}, {"configuration_ref", "configuration"}, {"intake_ref", "intake"}, {"platform_profile_ref", "platform_profile"}})
      binding[pair.first] = reference(bind + '.' + pair.first, pair.second, pair.first != "intake_ref" && pair.first != "platform_profile_ref");
    for (const auto& name : {"host_installation_id", "entry_id"}) binding[name] = string(id(bind + '.' + name));
    binding["host_trust_epoch"] = string(number(bind + ".host_trust_epoch"));
    for (const auto& name : {"manifest_digest", "artifact_set_digest", "permissions_digest"}) binding[name] = string(digest(bind + '.' + name));
    objectKind = text(at + ".object_scope.kind"); Object objects{{"kind", string(objectKind)}};
    if (objectKind == "devices") {
      const auto size = length(at + ".object_scope.device_ids", 1, 64); std::string array = "[", previous;
      for (unsigned long i = 0; i < size; ++i) { const auto value = id(at + ".object_scope.device_ids[" + std::to_string(i) + ']');
        require(value > previous, "worker_scope_order"); previous = value; if (i) array += ','; array += string(value); }
      objects["device_ids"] = array + ']';
    } else {
      require(objectKind == "data_sources", "worker_scope"); authorized = false; // Controller不接管Seamer来源进程。
      objects["source_refs"] = references(at + ".object_scope.source_refs", "source", 1, 64);
      objects["data_object_refs"] = references(at + ".object_scope.data_object_refs", "data_object", 0, 128);
    }
    intent = object({{"launch_id", string(launch)}, {"service_id", string(targetService)}, {"supervisor_instance_id", string(targetSupervisor)},
      {"runtime_generation", string(targetGeneration)}, {"member_id", string(member)}, {"role", string("worker")}, {"artifact_manifest_ref", object(artifact)},
      {"containment_ref", object(containment)}, {"object_scope", object(objects)}, {"policy_revision", string(revision)}, {"extension_binding", object(binding)}});
    intentDigest = bootstrap::digest(intent);
    WorkerGrant grant(database, raw, serviceId, databaseIdentity, supervisor, domain);
    for (const auto& name : {"installation_ref", "approval_ref", "role_resolution_ref", "permissions_digest"})
      if (grant.fields.at(name) != binding.at(name)) authorized = false;
    if (!grant.authorized || grant.fields.at("launch_id") != string(launch) || grant.fields.at("launch_intent_digest") != string(intentDigest)) authorized = false;
    expired = grant.expired; authorization = grant.authorization; fenceRevision = grant.fenceRevision;
  }
};

// 每次登记保留独占Job及句柄。重启后不得仅从名称重建当前域的持有证明。
class WorkerGroup {
  Handle job;
public:
  std::string name, nameJcs, reservation;
  explicit WorkerGroup(Instance& instance, const std::string& supervisor, const WorkerInput& worker) {
    using namespace bootstrap;
    const auto unique = identifier(); name = "Global\\LeafSeamer.Worker." + unique;
    // 仅此固定OS名称含反斜杠；不放宽协议标识的ASCII字符串编码器。
    nameJcs = "\"Global\\\\LeafSeamer.Worker." + unique + "\"";
    const std::wstring wide(name.begin(), name.end());
    job.value = CreateJobObjectW(&instance.security, wide.c_str()); const DWORD error = GetLastError();
    require(job.value != nullptr && error != ERROR_ALREADY_EXISTS, "worker_group_create");
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{}; limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    require(SetInformationJobObject(job.value, JobObjectExtendedLimitInformation, &limits, sizeof(limits)) != 0, "worker_group_limits");
    require(unusedAndEmpty(), "worker_group_initial");
    reservation = object({{"format", string("leafseamer-worker-group/1")}, {"supervisor_instance_id", string(supervisor)},
      {"launch_id", string(worker.launch)}, {"launch_intent_digest", string(worker.intentDigest)}, {"group_id", string(worker.group)},
      {"generation", string(worker.groupGeneration)}, {"object_name", nameJcs}, {"created_tick_ns", string(std::to_string(tick()))},
      {"kill_on_close", "true"}, {"breakaway_allowed", "false"}});
  }
  HANDLE native()const{return job.value;}
  JOBOBJECT_BASIC_ACCOUNTING_INFORMATION counts()const{
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION info{};require(QueryInformationJobObject(job.value,JobObjectBasicAccountingInformation,&info,sizeof(info),nullptr)!=0,"worker_group_observation");return info;
  }
  bool unusedAndEmpty() const {
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    require(QueryInformationJobObject(job.value, JobObjectExtendedLimitInformation, &limits, sizeof(limits), nullptr) &&
      limits.BasicLimitInformation.LimitFlags == JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, "worker_group_limits");
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION info{};
    require(QueryInformationJobObject(job.value, JobObjectBasicAccountingInformation, &info, sizeof(info), nullptr) != 0, "worker_group_observation");
    return info.ActiveProcesses == 0 && info.TotalProcesses == 0;
  }
};
