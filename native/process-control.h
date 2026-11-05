#pragma once

// 独立于bootstrap的已准入核心控制端点；接通持久启动查询和完整启动许可快照。
class CoreControl {
  Instance& owner;
  runtime::Protected& protectedRuntime;
  bootstrap::Domain coreDomain;
  HANDLE rootJob=nullptr;
  DWORD corePid=0;
  loading::Store loads;
  std::unique_ptr<installation::Client> installer;
  struct MaterializationJob {std::string launch,digest;bool done=false;installation::Observation result;};
  std::map<std::string,MaterializationJob> observations;
  std::map<std::string,std::string> currentObservation;
  std::string pendingObservation;
  std::future<installation::Observation> observationFuture;
  void settleObservation(){
    if(observationFuture.valid()&&observationFuture.wait_for(std::chrono::milliseconds(0))==std::future_status::ready){
      auto& job=observations.at(pendingObservation);job.result=observationFuture.get();job.done=true;pendingObservation.clear();
    }
  }
  std::map<std::string, std::unique_ptr<WorkerGroup>> groups;
  std::map<std::string,std::unique_ptr<WorkerProcess>> workers;
  void pollWorkers(ProcessJournal& journal){
    for(auto it=workers.begin();it!=workers.end();){
      const auto stored=journal.worker(launch,it->first);require(stored&&stored->attempted,"worker_process_record");auto& process=*it->second;
      if(stored->state=="retired"){it=workers.erase(it);continue;}
      if(stored->state=="retiring"||stored->state=="indeterminate"){process.stop();++it;continue;}
      const bool permitted=fenceSynchronized&&journal.workerPermission(launch,it->first,stored->digest).empty();
      if(!permitted||!process.alive()||(stored->state=="admitted_closed"&&(!process.quiet()||!process.moduleCurrent()))){fprintf(stderr,"{\"event\":\"worker_gate_failure\",\"permitted\":%d,\"alive\":%d}\n",permitted,process.alive());fflush(stderr);process.stop();journal.failWorker(launch,it->first);}
      else if(stored->state=="awaiting_bootstrap"&&process.proofDone()){
        if(!process.qualified()){process.stop();journal.failWorker(launch,it->first);}
        else{const auto receipt=process.exchange.receipt(process.observationId);journal.admitWorker(launch,it->first,bootstrap::object(receipt));
          try{process.admit(receipt);}catch(...){process.stop();journal.failWorker(launch,it->first);}}
      }
      ++it;
    }
  }
  Handle pipe, event;
  OVERLAPPED io{};
  enum class Operation { connecting, reading, writing } operation = Operation::connecting;
  bool pending = false, admitted = false, connectedInline = false, fenceSynchronized = false;
  unsigned long long deadline = 0;
  std::array<char, 262145> bytes{};
  std::string input, output, sequence = "1", scope, key, launch, intentDigest, supervisor, receiptBody, service, databaseId, generation, rootMember, manifest, policyRevision, domain;
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
    const auto id = [&](const std::string& v) {
      require(!v.empty() && v.size() <= 128, "control_identifier");
      for (size_t i = 0; i < v.size(); ++i) { const char c = v[i]; const bool alnum = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
        require(alnum || (i > 0 && (c == '_' || c == '-' || c == '.' || c == ':')), "control_identifier"); }
      return v;
    };
    const auto digestValue = [&](const std::string& v) {
      require(v.size() == 71 && v.rfind("sha256:", 0) == 0, "control_digest");
      for (size_t i = 7; i < v.size(); ++i) require((v[i] >= '0' && v[i] <= '9') || (v[i] >= 'a' && v[i] <= 'f'), "control_digest"); return v;
    };
    const auto message = id(value("$.message_id")), type = value("$.type");
    settleObservation();loads.settle();
    pollWorkers(journal);
    loads.invalidate([&](const std::string& id,const std::string& digest){const auto stored=journal.worker(launch,id);
      return stored&&stored->digest==digest&&stored->state!="retired"&&(stored->attempted|| (fenceSynchronized&&journal.workerPermission(launch,id,digest).empty()));});
    Object frame{{"version", string("supervisor-control/0.4.0-draft.1")}, {"type", string(type)}, {"scope", scope},
      {"channel_id", string(channel)}, {"sequence", string(sequence)}, {"message_id", string(message)}, {"reply_to", "null"}};
    const auto error = [&](const std::string& code) {
      frame["type"] = string("ERROR"); frame["payload"] = object({{"code", string(code)}, {"retry_action", string("query_only")}});
    };
    const auto workerRecord = [&](const std::string& target, const std::string& expectedDigest) {
      const auto found = journal.worker(launch, target); if (!found) return std::string("null");
      require(found->digest == expectedDigest, "worker_query_digest");
      const auto workerKey = object({{"launch_id", string(target)}, {"launch_intent_digest", string(expectedDigest)}});
      return object({{"key", workerKey}, {"supervisor_instance_id", string(supervisor)}, {"state", string(found->state)},
        {"creation_attempted", found->attempted ? "true" : "false"}, {"admission_receipt", found->receipt}, {"retirement_evidence", found->retirement}, {"gate_state", string("closed")}});
    };
    if (type == "LAUNCH_QUERY") {
      const auto target = id(value("$.payload.launch_id")), requestedDigest = digestValue(value("$.payload.launch_intent_digest"));
      const auto requestedKey = object({{"launch_id", string(target)}, {"launch_intent_digest", string(requestedDigest)}});
      frame["payload"] = requestedKey;
      require(object(frame) == request, "control_binding");
      const auto stored = target == launch ? nullptr : journal.worker(launch, target);
      if ((target == launch && requestedDigest != intentDigest) || (stored && stored->digest != requestedDigest)) error("identity_conflict");
      else {
        frame["type"] = string("LAUNCH_RESULT"); std::string record = "null";
        if (target == launch) {
          const auto original = journal.admission(launch); require(original == receiptBody, "control_journal_binding");
          record = object({{"key", key}, {"supervisor_instance_id", string(supervisor)}, {"state", string("admitted_closed")},
            {"creation_attempted", "true"}, {"admission_receipt", original}, {"retirement_evidence", "null"}, {"gate_state", string("closed")}});
        }
        if (target != launch) record = workerRecord(target, requestedDigest);
        frame["payload"] = object({{"key", requestedKey}, {"record", record}});
      }
    } else if (type == "LAUNCH_REGISTER") {
      WorkerInput worker(raw, request, service, databaseId, supervisor, generation, launch, rootMember, manifest, policyRevision, domain);
      frame["payload"] = object({{"intent", worker.intent}, {"authorization", worker.authorization}});
      require(object(frame) == request, "control_binding");
      std::string failure;
      if (!worker.authorized) failure = "unauthorized";
      else if (worker.expired) failure = "expired";
      else if (!fenceSynchronized) failure = "stale_fence";
      else failure = journal.registerWorker(launch, worker.launch, worker.intentDigest, worker.intent, worker.member, worker.group, worker.groupGeneration, worker.authorization, worker.fenceRevision);
      if (!failure.empty()) error(failure);
      else {
        auto group = groups.find(worker.launch);
        if (group == groups.end()) {
          require(groups.size() < 4096, "worker_group_capacity");
          group = groups.emplace(worker.launch, std::make_unique<WorkerGroup>(owner, supervisor, worker)).first;
        }
        journal.reserveWorkerGroup(launch, worker.launch, group->second->name, group->second->reservation);
        frame["type"] = string("LAUNCH_RESULT");
        const auto registeredKey = object({{"launch_id", string(worker.launch)}, {"launch_intent_digest", string(worker.intentDigest)}});
        frame["payload"] = object({{"key", registeredKey}, {"record", workerRecord(worker.launch, worker.intentDigest)}});
      }
    } else if(type=="LAUNCH_MATERIALIZE"){
      const auto target=id(value("$.payload.key.launch_id")),requestedDigest=digestValue(value("$.payload.key.launch_intent_digest")),requestId=id(value("$.payload.observation_request_id"));
      const auto requestedKey=object({{"launch_id",string(target)},{"launch_intent_digest",string(requestedDigest)}});
      frame["payload"]=object({{"key",requestedKey},{"observation_request_id",string(requestId)}});require(object(frame)==request,"control_binding");
      const auto stored=journal.worker(launch,target);std::string failure;
      if(!stored)failure="not_found";else if(stored->digest!=requestedDigest)failure="identity_conflict";
      else if(!installer||!((!stored->attempted&&stored->state=="registered")||(stored->attempted&&stored->state=="admitted_closed")))failure="invalid_binding";
      else if(!fenceSynchronized)failure="stale_fence";
      else failure=journal.workerPermission(launch,target,requestedDigest);
      if(failure.empty()) {
        auto found=observations.find(requestId);
        if(found!=observations.end()&&(found->second.launch!=target||found->second.digest!=requestedDigest||currentObservation[target]!=requestId))failure="identity_conflict";
        else if(found==observations.end()){
          if(observationFuture.valid()||observations.size()>=4096)failure="capacity";
          else{
            currentObservation[target]=requestId;observations.emplace(requestId,MaterializationJob{target,requestedDigest,false,{}});pendingObservation=requestId;
            const auto fixed=stored->intent;observationFuture=std::async(std::launch::async,[this,fixed,requestedDigest](){try{return installer->observe(fixed,requestedDigest);}catch(...){return installation::Observation{};}});
          }
        }
        if(failure.empty()){
          const auto& job=observations.at(requestId);const auto& result=job.result;
          const bool verified=job.done&&result.verified&&!observationFuture.valid()&&tick()>=result.issued&&tick()<result.expires;
          if(verified)installer->check();
          const auto observation=verified?object({{"materialization_evidence_id",string(result.evidence)},{"materialization_challenge_id",string(result.challenge)},
            {"lifetime",object({{"clock",domain},{"issued_tick",string(std::to_string(result.issued))},{"deadline_tick",string(std::to_string(result.expires))}})}}):"null";
          frame["type"]=string("MATERIALIZATION_RESULT");frame["payload"]=object({{"key",requestedKey},{"observation_request_id",string(requestId)},
            {"status",string(!job.done?"pending":verified?"verified":"unavailable")},{"observation",observation}});
        }
      }
      if(!failure.empty())error(failure);
    } else if(type=="LAUNCH_LOAD"){
      const auto target=id(value("$.payload.key.launch_id")),requestedDigest=digestValue(value("$.payload.key.launch_intent_digest"));
      const auto loadId=id(value("$.payload.load_id")),loadOperation=value("$.payload.operation");
      const auto requestedKey=object({{"launch_id",string(target)},{"launch_intent_digest",string(requestedDigest)}});
      Object payload{{"key",requestedKey},{"load_id",string(loadId)},{"operation",string(loadOperation)}};
      installation::Fields fields(raw,request);unsigned long long length=0,offset=0;std::string materialsDigest,encoded;
      if(loadOperation=="begin"){
        length=loading::integer(raw,request,"$.payload.byte_length");materialsDigest=digestValue(value("$.payload.materials_digest"));
        payload["byte_length"]=std::to_string(length);payload["materials_digest"]=string(materialsDigest);
        for(const auto fieldName:{"materialization_evidence_id","materialization_challenge_id"})payload[fieldName]=string(id(fields.text(std::string("$.payload.")+fieldName)));
      }else if(loadOperation=="chunk"){
        offset=loading::integer(raw,request,"$.payload.offset");encoded=fields.text("$.payload.bytes");loading::base64(encoded);
        payload["offset"]=std::to_string(offset);payload["bytes"]="\""+encoded+"\"";
      }else require(loadOperation=="finish"||loadOperation=="release","load_operation");
      frame["payload"]=object(payload);require(object(frame)==request,"control_binding");
      const auto stored=journal.worker(launch,target);auto selected=loads.find(loadId);std::string failure;
      if(!stored)failure="not_found";else if(stored->digest!=requestedDigest)failure="identity_conflict";
      else if(selected&&(selected->launch!=target||selected->digest!=requestedDigest))failure="identity_conflict";
      else if(loadOperation=="release"){
        if(stored->attempted&&stored->state!="retired")failure="indeterminate";
        else if(!selected)failure="not_found";else loads.close(*selected);
      }else if(stored->attempted||stored->state!="registered")failure="invalid_binding";
      else if(!fenceSynchronized)failure="stale_fence";
      else failure=journal.workerPermission(launch,target,requestedDigest);
      if(failure.empty()&&loadOperation!="release"){
        const auto current=currentObservation.find(target);
        if(current==currentObservation.end()||observationFuture.valid())failure="invalid_binding";
        else{const auto& proof=observations.at(current->second);if(!proof.done||!proof.result.verified||proof.digest!=requestedDigest)failure="invalid_binding";
          else if(tick()>=proof.result.expires)failure="expired";
          else if(loadOperation=="begin"&&(proof.result.evidence!=fields.text("$.payload.materialization_evidence_id")||proof.result.challenge!=fields.text("$.payload.materialization_challenge_id")))failure="invalid_binding";
          else installer->check();}
        if(failure.empty())try{
          if(loadOperation=="begin")loads.begin(loadId,target,requestedDigest,materialsDigest,length);
          else{require(selected&&loads.current(loadId,*selected),"load_identity_conflict");
            if(loadOperation=="chunk")loads.chunk(*selected,offset,encoded);else loads.finish(loadId,*selected,stored->intent);}
        }catch(const std::exception& exception){const std::string reason=exception.what();failure=reason=="load_identity_conflict"?"identity_conflict":reason=="load_capacity"?"capacity":"invalid_binding";
          if(auto failed=loads.find(loadId))loads.close(*failed,true);}
      }
      if(!failure.empty())error(failure);
      else{selected=loads.find(loadId);require(selected,"load_record");frame["type"]=string("LOAD_RESULT");
        frame["payload"]=object({{"key",requestedKey},{"load_id",string(loadId)},{"status",string(loadOperation=="release"&&loads.busy(loadId)?"pending":selected->status)},
          {"received_bytes",string(std::to_string(selected->received))},{"root_identity",selected->status=="ready"?string(selected->materials->rootIdentity):"null"}});}
    } else if (type == "LAUNCH_CREATE") {
      const auto target = id(value("$.payload.key.launch_id")), requestedDigest = digestValue(value("$.payload.key.launch_intent_digest"));
      const auto requestedKey = object({{"launch_id", string(target)}, {"launch_intent_digest", string(requestedDigest)}});
      WorkerGrant grant(raw, request, service, databaseId, supervisor, domain);
      frame["payload"] = object({{"key", requestedKey}, {"authorization", grant.authorization},
        {"materialization_evidence_id", string(id(value("$.payload.materialization_evidence_id")))},
        {"materialization_challenge_id", string(id(value("$.payload.materialization_challenge_id")))},{"load_id",string(id(value("$.payload.load_id")))}});
      require(object(frame) == request, "control_binding");
      std::string failure;
      if (!grant.authorized || grant.fields.at("launch_id") != string(target) || grant.fields.at("launch_intent_digest") != string(requestedDigest)) failure = "unauthorized";
      else if (grant.expired) failure = "expired";
      else if (target == launch) failure = "invalid_binding";
      else {
        const auto stored = journal.worker(launch, target);
        if (!stored) failure = "not_found";
        else if (stored->digest != requestedDigest) failure = "identity_conflict";
        else if (stored->attempted) failure = "indeterminate";
        else if (stored->state != "registered") failure = "invalid_binding";
        else {
          // CREATE的授权必须重新核完整持久意图，不能沿用REGISTER时的短期许可。
          const auto checkRequest = object({{"payload", object({{"intent", stored->intent}, {"authorization", grant.authorization}})}});
          WorkerInput worker(raw, checkRequest, service, databaseId, supervisor, generation, launch, rootMember, manifest, policyRevision, domain);
          require(worker.intent == stored->intent && worker.intentDigest == stored->digest, "worker_journal_binding");
          installation::Fields extension(raw,stored->intent),profile(raw,coreDomain.policy.profile);
          if (!worker.authorized) failure = "unauthorized";
          else if (worker.expired) failure = "expired";
          else if(extension.id("$.extension_binding.platform_profile_ref.object_id")!=profile.id("$.profile_id")||
            extension.number("$.extension_binding.platform_profile_ref.revision")!=profile.number("$.revision"))failure="invalid_binding";
          else if (!fenceSynchronized) failure = "stale_fence";
          else failure = journal.workerPermission(launch, target, requestedDigest, worker.fenceRevision);
          if (failure.empty()) {
            const auto selected=currentObservation.find(target);
            if(selected==currentObservation.end()||observationFuture.valid())failure="invalid_binding";
            else{
              const auto& observation=observations.at(selected->second);
              if(!observation.done||!observation.result.verified||observation.digest!=requestedDigest||
                observation.result.evidence!=value("$.payload.materialization_evidence_id")||observation.result.challenge!=value("$.payload.materialization_challenge_id"))failure="invalid_binding";
              else if(tick()>=observation.result.expires)failure="expired";
              else{
                installer->check();protectedRuntime.check();
                const auto loadId=id(value("$.payload.load_id"));auto loaded=loads.find(loadId);
                if(!loaded||loaded->launch!=target||loaded->digest!=requestedDigest||!loads.current(loadId,*loaded)||loaded->status!="ready"||!loaded->materials)failure="invalid_binding";
                if(failure.empty()){
                  const auto group=groups.find(target);if(group==groups.end()||!group->second->unusedAndEmpty())failure="invalid_binding";
                  else{
                    auto process=std::make_unique<WorkerProcess>(owner,*group->second,rootJob,protectedRuntime,coreDomain,target,*stored,*loaded->materials,corePid);
                    if(!grant.current()||tick()>=observation.result.expires)failure="expired";
                    else{
                      journal.beginWorkerCreation(launch,target,process->creationId,process->creation(grant.authorization,loadId,loaded->materials->rootIdentity));
                      workers.emplace(target,std::move(process));auto& child=*workers.at(target);
                      // 持久标记完成后绝不再次CREATE；磁盘延迟使授权过期也保留已尝试状态。
                      if(!grant.current()||tick()>=observation.result.expires){journal.failWorker(launch,target);failure="indeterminate";}
                      else{
                        try{child.create();}catch(...){child.stop();journal.failWorker(launch,target);failure="indeterminate";}
                        if(failure.empty()){
                          journal.observeWorker(launch,target,child.observationId,child.observation);
                          try{child.run();}catch(...){child.stop();journal.failWorker(launch,target);failure="indeterminate";}
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
      if(!failure.empty())error(failure);
      else{frame["type"]=string("LAUNCH_RESULT");frame["payload"]=object({{"key",requestedKey},{"record",workerRecord(target,requestedDigest)}});}
    } else if (type == "RETIRE_REQUEST") {
      const auto target = id(value("$.payload.key.launch_id")), requestedDigest = digestValue(value("$.payload.key.launch_intent_digest"));
      const auto requestedKey = object({{"launch_id", string(target)}, {"launch_intent_digest", string(requestedDigest)}});
      const auto groupId = id(value("$.payload.containment_ref.group_id")), groupGeneration = id(value("$.payload.containment_ref.generation"));
      const auto backend = value("$.payload.containment_ref.backend"), reason = value("$.payload.reason");
      require((backend == "windows_job" || backend == "linux_cgroup_v2" || backend == "container_runtime") &&
        (reason == "revoked" || reason == "shutdown" || reason == "bootstrap_failed" || reason == "recovery"), "control_retirement");
      const auto containment = object({{"group_id", string(groupId)}, {"generation", string(groupGeneration)}, {"backend", string(backend)}});
      const auto body = object({{"key", requestedKey}, {"containment_ref", containment}, {"reason", string(reason)}});
      frame["payload"] = body; require(object(frame) == request, "control_binding");
      const auto stored = journal.worker(launch, target);
      if (target == launch) error("invalid_binding");
      else if (!stored) error("not_found");
      else if (stored->digest != requestedDigest) error("identity_conflict");
      else if (backend != "windows_job" || stored->group != groupId || stored->generation != groupGeneration) error("invalid_binding");
      else if (stored->state == "retired") { frame["type"] = string("RETIRE_RESULT"); frame["payload"] = stored->retirement; }
      else if (stored->state == "rejected") error("invalid_binding");
      else {
        if (stored->state != "retiring") journal.beginWorkerRetirement(launch, target);
        const auto process=workers.find(target);if(process!=workers.end())process->second->stop();
        // 关闭已持久化；缺少同一实例持有的原Job不能创建替代空组来冒充退出。
        const auto group = groups.find(target);
        if (group == groups.end() || group->second->counts().ActiveProcesses!=0) error("indeterminate");
        else {
          const auto observationId = identifier(), evidenceId = identifier(), observed = std::to_string(tick());
          const auto observation = object({{"format", string("leafseamer-worker-group-observation/1")}, {"observation_id", string(observationId)},
            {"supervisor_instance_id", string(supervisor)}, {"launch_id", string(target)}, {"launch_intent_digest", string(requestedDigest)},
            {"containment_ref", containment}, {"object_name", group->second->nameJcs}, {"domain_ref", domain}, {"observed_tick_ns", string(observed)},
            {"active_processes", "0"}, {"total_processes", std::to_string(group->second->counts().TotalProcesses)}, {"kill_on_close", "true"}, {"breakaway_allowed", "false"}});
          const auto evidence = object({{"evidence_id", string(evidenceId)}, {"service_id", string(service)}, {"old_domain_ref", domain},
            {"target_scope", string("member_group")}, {"target_member_ids", '[' + string(stored->member) + ']'}, {"containment_ref", containment},
            {"launch_intake_closed", "true"}, {"os_observation_refs", '[' + string(observationId) + ']'}, {"result", string("confirmed_empty")},
            {"evaluator_domain_ref", domain}, {"observed_tick_ns", string(observed)}});
          journal.finishWorkerRetirement(launch, target, evidenceId, observationId, body, observation, evidence);
          frame["type"] = string("RETIRE_RESULT"); frame["payload"] = evidence;
        }
      }
    } else if (type == "FENCE_PUT") {
      fenceSynchronized = false;
      const auto revision = value("$.payload.revision"), snapshotDigest = digestValue(value("$.payload.digest"));
      require(revision.size() <= 20 && (revision == "0" || revision[0] != '0'), "control_revision");
      for (const char c : revision) require(c >= '0' && c <= '9', "control_revision");
      Statement array(raw, "SELECT json_type(?1,'$.payload.items')"); array.bind(1, request);
      require(sqlite3_step(array.value) == SQLITE_ROW && array.text(0) == "array", "control_fence_items");
      Statement length(raw, "SELECT json_array_length(?1,'$.payload.items')"); length.bind(1, request);
      require(sqlite3_step(length.value) == SQLITE_ROW, "control_fence_items");
      const auto count = std::stoul(length.text(0)); require(count <= 256, "control_fence_capacity");
      std::vector<LaunchFenceItem> items; std::string arrayBody = "[", previous;
      for (unsigned long i = 0; i < count; ++i) {
        const auto at = "$.payload.items[" + std::to_string(i) + "].";
        LaunchFenceItem item{id(value((at + "launch_id").c_str())), digestValue(value((at + "launch_intent_digest").c_str())), value((at + "disposition").c_str())};
        require(item.launch > previous && item.launch != launch && (item.disposition == "allow" || item.disposition == "deny"), "control_fence_items");
        previous = item.launch; if (i) arrayBody += ',';
        arrayBody += object({{"launch_id", string(item.launch)}, {"launch_intent_digest", string(item.digest)}, {"disposition", string(item.disposition)}}); items.push_back(item);
      }
      arrayBody += ']';
      Object snapshot{{"scope", scope}, {"revision", string(revision)}, {"items", arrayBody}};
      require(bootstrap::digest(object(snapshot)) == snapshotDigest, "control_fence_digest"); snapshot["digest"] = string(snapshotDigest);
      const auto body = object(snapshot); frame["payload"] = body;
      // 重建全帧拒绝重复键、额外字段及错scope；不能仅比较来报digest。
      require(object(frame) == request, "control_binding");
      const auto failure = journal.fence(launch, revision, snapshotDigest, body, items);
      if (!failure.empty()) error(failure);
      else {
        fenceSynchronized = true; frame["type"] = string("FENCE_RESULT");
        frame["payload"] = object({{"revision", string(revision)}, {"snapshot_digest", string(snapshotDigest)}, {"journal_committed", "true"}});
      }
    } else throw std::runtime_error("control_direction");
    pollWorkers(journal);
    loads.invalidate([&](const std::string& id,const std::string& digest){const auto stored=journal.worker(launch,id);
      return stored&&stored->digest==digest&&stored->state!="retired"&&(stored->attempted||(fenceSynchronized&&journal.workerPermission(launch,id,digest).empty()));});
    frame["message_id"] = string(identifier()); frame["reply_to"] = string(message);
    sequence = next(sequence); return object(frame) + '\n';
  }
public:
  std::wstring name;
  std::string channel;
  CoreControl(Instance& instance, const bootstrap::Exchange& exchange,runtime::Protected& executableRuntime,std::unique_ptr<installation::Client> installation=nullptr) : owner(instance),protectedRuntime(executableRuntime),coreDomain(exchange.policy,exchange.supervisor,exchange.generation,exchange.descriptor,exchange.domainId,exchange.descriptorDigest),installer(std::move(installation)) {
    using namespace bootstrap;
    channel = identifier(); name = L"\\\\.\\pipe\\LeafSeamer.Control." + std::wstring(channel.begin(), channel.end());
    launch = exchange.common.at("launch_id"); launch = launch.substr(1, launch.size() - 2);
    intentDigest = exchange.intentDigest; supervisor = exchange.supervisor;
    service = exchange.policy.service; databaseId = exchange.policy.database; generation = exchange.generation; rootMember = exchange.member;
    manifest = exchange.policy.manifest; policyRevision = exchange.policy.revision;
    domain = object({{"clock_domain_id", string(exchange.domainId)}, {"descriptor_digest", string(exchange.descriptorDigest)}});
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
    rootJob=job;corePid=pid;pollWorkers(journal);
    const auto wait = WaitForSingleObject(event.value, 0); if (wait == WAIT_TIMEOUT) return;
    require(wait == WAIT_OBJECT_0 && pending, "control_event"); DWORD count = 0;
    if (!connectedInline) require(GetOverlappedResult(pipe.value, &io, &count, FALSE) != 0, "control_closed");
    connectedInline = false; pending = false;
    if (operation == Operation::connecting) {
      ULONG actual = 0; require(GetNamedPipeClientProcessId(pipe.value, &actual) && actual == pid, "control_peer"); read(); return;
    }
    if (operation == Operation::writing) { require(count == output.size(), "control_partial_write"); output.clear(); deadline = GetTickCount64() + 5000; read(); return; }
    require(count > 0 && input.size() + count <= 262145, "control_frame"); input.append(bytes.data(), count);
    const auto end = input.find('\n'); if (end == std::string::npos) { read(); return; }
    require(end == input.size() - 1, "control_frame"); input.pop_back(); output = respond(input, journal); input.clear();
    require(output.size() <= 262145, "control_capacity"); prepare(Operation::writing); DWORD written = 0;
    const BOOL ok = WriteFile(pipe.value, output.data(), static_cast<DWORD>(output.size()), &written, &io); complete(ok, GetLastError());
  }
};
