# LeafSeamer Controller

> **施工中 / Work in progress。** 已提供保护状态的服务启动、持久服务身份、本机健康检查，以及首次管理员的存储事务和受限本机工具。已接通本地可信装配下的 HTTPS 登录、刷新、定向 token、会话读取和注销；生产认证资格、完整身份接口、命令受理、监督器及设备出口尚未完成，不能用于实际直播控制。

可独立使用的直播软硬件控制平台：设备模块、连接、手动控制、资源协调、接管、凭据和状态采集。

总体设计、已确认决策、待落实事项和路线图统一维护于 [LeafSeamer Suite](https://github.com/LeafSeamer/leafseamer-suite)。当前分支为 `main`，按已确认的依赖顺序实施；首期完整功能和设备验收要求保持不变。

## 开发运行

使用 Node 24.22.0、npm 11.19.1。先在相邻 `leafseamer-sdk` 仓库构建与 [sdk-runtime.json](sdk-runtime.json) 摘要一致的 SDK，再安装本仓锁定依赖。构建将固定 SDK 运行文件纳入 Controller 包，独立运行无需邻仓。其余运行依赖固定为 better-sqlite3 13.0.3、argon2 0.45.1、canonicalize 5.1.0、ajv 8.20.0 和 ajv-formats 3.0.1；安装使用锁内完整依赖。

```sh
npm ci --ignore-scripts
npm run build:native -- --headers /absolute/node-v24.22.0/include/node --node-library /absolute/win-x64/node.lib
npm test
npm run build
```

原生构建输入来自 [Node 24.22.0 官方发行目录](https://nodejs.org/dist/v24.22.0/) 的 headers 和 Windows x64 `node.lib`，下载后先核对官方 SHASUMS256.txt。构建脚本再按 `native-inputs.json` 校验四个 N-API 头文件和导入库，当前只接受 Node 24.22.0、x64。Windows 使用 CMake 与 Visual Studio 2022 C++ 工具链；Linux 使用 CMake/C++17，并省略 `--node-library`。先构建原生模块，再运行普通 build/test；源码摘要或制品摘要不符时拒绝打包，不静默退回 JavaScript 时钟。实际验证工具链为 Windows x64、CMake 4.2.1、MSVC 19.44.35222.0、Windows SDK 10.0.26100.0；Linux 构建尚未验证。原生构建清单仅证明本地制品与输入一致，不代替发行签名或运行域批准。

首次显式创建业务库，再启动本机服务。`--data-dir` 必须是绝对路径；以下路径需替换为自己控制的独立目录。

```sh
node --disallow-code-generation-from-strings dist/cli.mjs init-storage --data-dir /absolute/controller-data
npm start -- --data-dir /absolute/controller-data --port 8081
```

Windows 使用绝对目录参数，运行文件与业务数据分开存放。当前为开发启动入口，尚非 C12 的安装器或受监督生产启动流程；Windows 目录 ACL、Linux 服务账户、TLS 和发行制品仍需各自验收。监听仅允许 `127.0.0.1` 或 `::1`，没有将 HTTP 扩展到远端的开关。

### Windows 进程容纳启动

Windows x64 开发包须先显式执行 `node --disallow-code-generation-from-strings dist/cli.mjs init-process-host --data-dir <绝对目录>` 安装启动日志，然后使用 `node --disallow-code-generation-from-strings dist/cli.mjs supervise --data-dir <绝对目录> --port 8081`。该入口先核验包内构建资产，再启动随包的原生进程宿主，由宿主创建 Controller 核心。Node 入口和参数固定解析，不经过 shell；子进程环境仅保留 Windows 系统及临时目录变量，不继承 Node 预加载／调试环境。核心仍使用原有排他业务库与保护态 HTTP，`/health/ready` 返回503。

原生宿主先创建不可继承且每次独立命名的 Job，启用并回读 `KILL_ON_JOB_CLOSE`，关闭 breakaway，使用 `PROC_THREAD_ATTRIBUTE_JOB_LIST` 在创建时纳管暂停的核心；核对实际 Job 归属和映像文件身份后才恢复线程。继承句柄白名单只有核心输入与输出，Job 句柄不交给核心。stdout 专用于宿主生命周期事实，核心的监听及错误输出走 stderr，两者不共享状态管道。`process_contained` 只表示本次 OS 容纳，`runtime_admitted` 始终为 false。（接口依据：[Microsoft 进程属性](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)、[Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)。）

本机装配代码也可调用包内 `startProcessHost({dataDir,host,port,onCoreOutput})`，使用返回的 `close()` 停止、`exited` 等待最终状态。正常停止或启动客户端消失时，宿主给核心两秒关闭库；随后终止残留进程并查询整个 Job 的活跃计数，最多等待五秒取得空组，再确认核心进程句柄退出。只有两项都成立才输出 `process_group_empty`；强停、异常核心退出或畸形控制输入返回失败退出码，即使之后已确认空组。宿主自身被强制终止依靠唯一 Job 句柄关闭终止组内进程，此时没有空组回执，不能从宿主退出推断已取得退役证据。（观察依据：[Job 活跃进程计数](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_accounting_information)、[TerminateJobObject](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-terminatejobobject)。）

当前实现是 DF02 的 Windows 进程容纳基础，已增加下节核心bootstrap与持久绑定，完整监督journal、保护配置／发行制品权威、子Job、worker运行准入和旧域恢复仍未完成；跨交互会话的实际部署验收仍待完成。构建清单不能替代发行签名与加载期间防替换，完整运行域未获批准。该入口没有设备出口、自动重启或任意 worker 启动接口，也不把组退出当作设备效果完成或资源释放。Linux cgroup 版本尚待实现，Linux 不生成该宿主且调用时明确拒绝。现有 `start` 保留用于保护态开发诊断。

本轮 Windows 真实进程测试覆盖正常数据库关闭、核心启动失败／崩溃、残留 detached 后代、宿主强停、启动客户端消失、控制管道断开／畸形及安装资产漂移。新增日志与实例锁后，相关13项Windows用例通过，另1项非Windows用例在当前平台跳过；没有以这些结果宣称 Linux、完整监督协议、浏览器或设备已验收。

`init-storage` 只创建服务存储，不创建管理员或设备权限。数据库已存在时拒绝覆盖；启动时数据库缺失、版本未知、迁移摘要不符或完整性检查失败均拒绝，不自动创建新身份或修复原库。初始化失败留下的文件须按故障检查处理，不能通过重复初始化静默替换。

库中固定 service_id、database_instance_id、control_epoch 和 request_epoch。普通重启保留它们，为每次启动生成新的 service_boot_id；它不充当 DF02 的已批准运行域。启动记录与迁移记录持久保存，正常关闭只结束本次启动记录；强停留下的旧记录不改写成成功关闭。记录中的 UTC 只供诊断，不是认证时钟、业务 NTP 或排序权威。备份恢复换 scope、完整身份生命周期和持久请求账本尚待实现。

SQLite 固定引擎为 3.53.4，并核对 source id；启用外键、WAL、FULL 同步及单连接排他模式，关闭连接自动checkpoint并读回检查。第二个进程不能接管仍被占用的业务库；操作系统释放旧连接后，新进程仍以保护状态启动。排他数据库连接不证明外部 worker 已退役，也不授予设备发送权限。驱动使用原始数组行和显式字段映射，可在禁止动态代码生成时运行。完整业务写入前仍须接入DF04有界checkpoint与WAL容量协调，不能将当前保护态启动用于持续生产写入。（SQLite 行为依据：[locking_mode](https://www.sqlite.org/pragma.html#pragma_locking_mode)、[WAL](https://www.sqlite.org/wal.html)。）

| 本机入口 | 当前结果 |
| --- | --- |
| `GET /health/live` | 200，最小存活状态 |
| `GET /health/ready` | 503；旧库 `bootstrap_incomplete`，schema 3及以上为 `authentication_clock_unqualified` 或故障时 `authentication_clock_unavailable`；身份时钟已具资格时仍为 `business_incomplete` |
| `GET /.well-known/leafseamer-contracts` | 503，无正文；尚无完整就绪的契约处理组合 |

健康接口支持 HEAD，禁止缓存；不暴露数据库路径、版本或凭据。启动时的 JSON 输出包含本次 boot 身份与监听端口，`ready` 为 false。未知路由不进入业务处理，带正文请求不读入无界缓冲；当前没有命令发送、自动重放或自动布防路径。

### 核心bootstrap与启动绑定

可信本机装配可向 `startProcessHost` 提供 `bootstrapPolicy`，普通 `supervise` 不接受批准正文、环境开关或HTTP授权。政策精确包含 `format: leafseamer-core-bootstrap-policy/1`、service_id、database_instance_id、artifact_manifest_ref（manifest_id／revision／digest）、platform_profile_ref（profile_id／revision）、policy_revision、bootstrap_timeout_ms（1—60000整数）及clock_backend_revision。引用由装配者选定；结构合法和挑战成功不构成profile的生产批准。当前仅有集成测试的合成profile，生产可信安装提供者尚未接入。

`installedCoreDigest()` 校验包内清单后返回当前安装输入的摘要：对 `{controller_build_sha256,node_sha256}` 的JCS正文计算SHA-256并加 `sha256:` 前缀。前者是Controller构建清单文件摘要，后者是实际Node可执行文件摘要；政策artifact引用必须与该值相同。该局部组合没有发行签名、完整动态加载闭包或运行期间防替换证明，不能当正式ArtifactManifest审批。

原生宿主在核心创建前提交启动意图、时钟域描述和非秘密政策；核心恢复后，经两条定向继承管道发送ASSIGNMENT并接收PROOF。32字节随机秘密与nonce不进argv、环境或日志；PROOF采用Windows CNG／Node标准HMAC-SHA256、固定域前缀和15字段JCS投影。管道帧使用规范JSON加单个LF，正文上限16KiB，禁止多帧、重复证明和其它方向。期限为同源QueryInterruptTimePrecise的绝对窗口，创建及应答耗时不会续期。原生秘密缓冲区退出时清零；JavaScript字符串不承诺确定性内存擦除。

宿主核证明、实际Job归属和截止后，先在DELETE／EXTRA监督库提交closed的AdmissionReceipt，再发送ADMISSION。核心用SDK解析帧，核服务／数据库、制品／profile、描述摘要与完整启动意图，再用本机原生tick重核窗口。业务schema 11将完整意图、描述、回执和政策与当前service_boot同库不可变绑定，receipt／bootstrap／member_boot禁止跨启动重用。此事务成功后才监听；写入失败关闭业务库，监督已提交的准入历史保留。`bootstrap_authenticated=true`仅描述已完成的握手，客户端仍需观察核心实际监听；`runtime_admitted=false`与ready503保持，不授worker、设备或发送权。

业务库运行 `migrate-storage` 显式升级至当前schema 54，每步保留备份；worker启动准备至少要求schema 12。已有监督日志v1至v4使用 `upgrade-process-host --data-dir <绝对目录>` 显式升级至5。监督日志升级在核DDL、完整性、目录及所有者和无未决尝试后创建唯一备份并同事务新增缺少的bootstrap／admission、启动快照、worker登记、组保留／退役及一次创建／实际观察原件表，既有记录不变；重复升级返回changed=false。host_meta的format继续标识未改变的身份布局，PRAGMA user_version标识schema 5。普通监督启动拒绝v1至v4，不自动修复；未决尝试不能借升级、PID消失或新的挑战绕过旧域恢复。迁移不为旧登记伪造创建原件、Job句柄或退役证据。

当前真实Windows集成覆盖双库绑定后监听、正常退出、错误制品／服务、旧业务库、HMAC／角色／重复帧／EOF／超时拒绝、写入故障、历史迁移和重放拒绝。完整RuntimeBinding、worker子域、保护配置来源、旧域退役恢复、Linux、生产profile及设备验收继续实施。

`bootstrapDeviceWorker`提供Windows设备worker的子进程校验入口。可信启动装配须提供固定完整意图、预期时钟描述、服务／数据库身份及监督器定向继承管道；不能从Assignment反向构造这些预期值。入口在首次等待前复制输入，按SDK核完整扩展意图与设备范围，再核挑战的意图摘要、成员、制品、监督域和profile。HMAC沿既定bootstrap投影；收到ADMISSION后逐项核回执、原子组和原生绝对截止，发proof不会延长窗口。返回深冻结的意图／描述／回执且gate_state仍为closed，不返回挑战秘密、不建立RuntimeBinding或开始设备业务。

该入口既有独立管道用例使用合成监督挑战；现已接入下述原生一次创建流程，并用真实Suite内容、原生宿主和随包Node完成关闭态准入。核心持久RuntimeBinding已按下节接通；扩展执行和设备业务仍待完成。

### 监督控制连接与准入原件查询

已准入核心使用单独的Windows命名管道连接原生宿主，bootstrap的两条继承管道不承载控制帧。宿主创建随机名称、只允许本机、显式当前账户／SYSTEM DACL及FIRST_PIPE_INSTANCE的单实例端点，生命周期内持续持有；名称和channel_id由原生父进程通过固定内部参数交付，普通supervise不能指定。连接后宿主核GetNamedPipeClientProcessId等于所持核心实例PID，并重新检查实际Job归属；同一Job的其它后代也不能取得核心控制通道。控制连接不自动重连。（平台接口依据：[CreateNamedPipe](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea)、[GetNamedPipeClientProcessId](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeclientprocessid)、[overlapped管道I/O](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-server-using-overlapped-i-o)。）

当前连接固定采用SDK独立worker-runtime选择中的supervisor-control/0.4.0-draft.1，不回退旧版本。LAUNCH_QUERY：从同一原生SQLite日志读取既有核心AdmissionReceipt，返回完整JournalView；未知launch返回record=null，同ID异摘要返回identity_conflict且只能query_only。查询不创建、消费或重签bootstrap，不产生新lease，也不把历史closed回执改成Ready。scope固定服务、数据库、监督实例和域；双向序号从1连续，channel及reply_to必须绑定本连接和实际未决请求。输入采用单帧规范JSON加LF、原生256KiB预算和异步I/O；额外字段、重复键、乱序或跨通道帧关闭连接。

核心在持久采用启动绑定前先完成一次原件查询，之后每500ms串行核验。当前开发预算为单次请求2秒、宿主无完整控制交互5秒；期限从原请求起点计算，部分帧和迟到结果不续期，时钟读取异常或回退锁存。它们用于关闭失去监督的开发运行实例，不是经生产测量批准的执行租约或实时调度保证。控制来源先在内存失效，后关闭HTTP、认证监测和业务库；正常关停保持原停止流程。宿主观察到控制故障则终止完整Job，核实际空组与核心退出并持久保存退出原件，结果control_failed=true且进程失败退出；宿主自身崩溃仍没有成功退出证明。

可信本机核心可通过同一连接的`putFence(snapshot)`提交完整FENCE_PUT，接收FENCE_RESULT；请求与周期查询串行、队列至多8项。完整scope、摘要、规范十进制revision及至多256项按launch_id唯一排序的集合均严格核验；核心自身不能作为扩展allow条目。原生监督日志先保存完整JCS、逐项判定和当前指针，再返回ACK。同修订同内容只查原，低修订、同修订异内容、同launch异摘要及历史deny恢复allow均拒绝；即使已从当前集合移除，历史deny仍保留。快照写入失败不恢复旧准入状态，存储错误终止整个Job。每个核心attempt至多4096份快照，仍受原16MiB日志上限约束。

ACK仅证明该快照已提交；它不刷新核心查询期限，不创建worker或RuntimeBinding，不开放设备出口。快照必须覆盖当前监督实例的全部非终态worker登记，缺少registered记录也拒绝，失败后新登记资格保持关闭，直到显式提交并核验完整快照。已验证实际Windows命名管道上的256项完整快照、超过JavaScript安全整数的修订、重复查询、永久拒绝及真实退出，消费者错误ACK另用合成服务端验证；掉电、磁盘耗尽与COMMIT未知尚未验收。

查询来源有效不代表完整RuntimeBindingRef、发行批准或设备发送资格。CREATE已接通固定worker入口，RETIRE覆盖当前域内已登记和已创建成员；不能以未知键null推断旧进程不存在。真实启动授权提供者、旧域恢复、Linux及跨账户部署仍待完成。

### 核心worker启动准备

业务库schema 12提供内部`storage.workerLaunches.prepare(intentBytes)`、`query(LaunchKey)`和`current()`。准备按固定SDK解码完整设备worker意图，在同一事务核本次已持久核心启动、监督实例／运行代、制品／政策／profile、成员与容纳组分离，以及每个设备的实际登记，再保存不可变意图、与意图一致的设备集合和审计提交记录。设备集合不完整或任一写点失败时整体回滚；同launch同摘要查原，异摘要或重复成员／组身份拒绝。

每库至多4096份准备记录、本次核心启动至多256份，超过开发预算拒绝，不截断。`query`保留旧启动历史；普通重启后旧记录的`current_boot=false`，不能用同ID重新准备或移入新域。`current()`仅枚举本次核心启动的准备集合，`current_boot`只表示归属，不证明监督源仍有效。旧版库该入口为null，需显式备份迁移；迁移不生成意图或批准。

schema18的新增准备还须从同库实际审批读取当前状态：完整安装／批准／审阅／配置／角色引用、权限摘要、intake／平台／宿主信任代和清单／库存摘要逐项一致，入口只能是原manifest的node_module worker。设备集合必须覆盖全部当前设备角色绑定，不能只按选中的device_scope删减；其他对象角色缺少提供者时拒绝。准备等待当前Suite内容核验，最终writer再次核审批与角色，等待中撤销不能留下新准备。现有意图／设备关联／审计仍沿原事务保存，不增加另一套启动模型；每实例最多四个等待中的准备。

同请求已保存的准备只返回历史，批准撤销后查原不会生成新授权；跨启动历史仍不可复用。准备本身不能将current_boot或准备成功用作CREATE许可；后续完整虚拟资源、启用受理和业务短授权见对应章节。人员查询和核心内部检查共用实际审批状态读取，但外部查询仍须真实extension.read令牌。


该内部入口不接受HTTP请求，不核成运行审批，也不从调用者给出的安装／审阅引用推导可信来源。后续虚拟资源、当前安装／审批、业务短授权及核心RuntimeBinding见对应章节；完整生命周期和最终出口仍待接通。准备记录不能直接转成allow快照、设备Ready或发送许可。

### 核心worker运行绑定

业务库schema 19提供内部`storage.workerLaunches.runtime`。启动装配在持久核心绑定后通过`bindSource(supervision)`绑定本次已认证监督连接，核完整服务／数据库／监督域及核心回执；不从HTTP接收worker回执或允许替换来源。`adopt(LaunchKey)`只能采用本次启动已保存的意图：先核实际安装审批与当前Suite内容，再从监督器查询admitted_closed，进入业务writer时重核来源资格、完整回执／意图／域和当前审批，把完整运行绑定与审计同事务保存。正文保留完整意图、ClockDomainDescriptor和AdmissionReceipt，RuntimeBindingRef由核心原件摘要生成。

`observeWorker(intent)`返回的观察只能由原监督连接核验。其有效期沿实际查询起点的两秒截止，不因排队、复制或引用回执延长；`assertWorkerObservation`拒绝复制件、过期件和已撤回观察。完整deny提交前先提高本地撤回代，失败的fence响应使已有观察失效；来源关闭会先通知采用者。监督器仍独立核当前组与根进程，两个数据库不宣称原子。

`query(key)`只查不可变历史，`current_boot`不是当前资格。`current(key)`另核内存采用、监督观察及本地审批；最多四个活动／等待采用沿当前加载容量执行，每500ms串行复核该成员和当前安装内容，超过原观察期限即撤回。采用或审计写入失败锁存该实例的采用资格；提交结果未知只允许查原，不自动补发成功。重复adopt只返回已保存历史，不能重新激活撤回记录；重启为旧绑定补记restarted撤回，不继承旧观察。

撤回先关闭内存资格，再持久保存原因；持久失败不恢复资格。审批失效或来源变化会请求原监督器退役，退役请求失败不等于confirmed_empty，资源释放仍依赖原监督器的完整组结果。运行绑定与回执始终为closed，尚未发布安装active_closed、导入扩展模块、建立设备session或取得发送许可。固定虚拟设备的资源与启动依赖封存见下节；人员启用计划、受理和业务短授权见下节。

真实业务SQLite用例覆盖人员审批竞争、错绑定、审计写入回滚、撤回写入失败和重启历史。跨仓用例进一步使用真实Suite封存与人员批准、原生创建及回执，完成业务库采用、deny后撤回和原组退役；业务短授权已按下节接通；平台批准与安装装配仍是明确的测试配置，不能替代正式发行或设备验收。


### 固定虚拟设备资源与启动依赖

业务库schema 20提供可信本机装配接口`storage.configureVirtualDevice({request_id,device_id})`。它只接受已登记的simulator设备，由核心分配固定`core_virtual_device/1`后端的资源身份，并将配置与审计同事务保存。调用方不能指定资源ID、设备引用或外部资源集合；普通HTTP没有此入口。物理设备仍须实际身份和别名提供者，不能通过此接口声明已支持。该登记选择后续必须使用的虚拟后端，不证明模块已经运行或获得设备权限。

新启动准备从当前人员审批、完整角色解析、已验证的能力模板和上述核心登记生成持久依赖原件。它遍历全部绑定设备与全部动作，包括未获本次权限的动作；缺少提供者、模板、未知别名或非空外部依赖均拒绝，不以空集合代替。所有设备必须与完整意图范围相等，同一设备去重，保留每个角色与完整模板摘要。依赖原件与准备记录通过延迟外键在同一事务提交；内容获取及运行采用继续核对原件和当前审批。

`workerLaunches.dependencies(LaunchKey)`只返回本次核心启动中仍匹配的冻结依赖记录。它是固定虚拟后端的资源绑定，不是正式DependencyPlan、LaunchAuthorization、CatalogApproval或发送许可。触发器描述和动作策略仍须在运行目录与采样／执行资格中核验。配置及依赖不可变；升级保留旧准备，但不为其补造资源或依赖，已被旧准备使用的设备不能事后改绑。开发容量为4096个虚拟资源、每意图64个设备与256条角色关联，仍待生产容量验收。


### 安装依赖计划

业务库schema 21将正式DependencyPlan接入当前人员会话：`planExtension(token,{request_id,slot_id,expected_slot_revision,selection})`从已批准候选、角色解析、固定虚拟资源及实际安装服务生成计划。当前支持空disabled槽位的activate／enable选择，必须指定已存在的新target，source与reuse均为null；尚不支持需要旧实例退役／资源核销的切换。其他对象或已有启动／未决命令缺少完整影响提供者时拒绝，不返回删减后的影响集合。

计划绑定完整槽位引用、全局dependency_revision、选择、配置摘要、设备／资源影响、平台／策略及已认证监督域中的30秒固定单调期限；安装平台ID和修订必须与实际核心监督域匹配。当前开发容量为4096份计划、两个并发来源读取；配置、角色、审批、资源或运行记录变化在同writer推进依赖修订。计划正文和审计双向延迟外键绑定，任何一侧失败都回滚，不修改槽位或启动设备。

`lookupExtensionPlan(token,request_id)`按当前人员读权返回原凭据范围的历史；同键重投不续期。`getCurrentExtensionPlan(token,plan_ref)`异步重核当前人员读权、原监督连接、实际安装服务、槽位／依赖修订与完整资源图，截止等号或重启失效。计划的content_digest覆盖除顶层plan_ref／content_digest外的全部字段，Ref回显该摘要。计划不是启用受理、资源占用、LaunchAuthorization或发送许可；人员受理与资源占用见下节，不能把计划查询结果直接用于CREATE。


### 人员启用受理与资源占用

业务库schema 22通过当前人员会话的`activateExtension`／`enableExtension`消费对应用途的正式计划。请求固定request_id、slot_id、expected_slot_revision、target_installation_ref、approval_ref和dependency_plan_ref。服务先核当前权限、近期认证、计划与真实安装来源，在writer内重新核对完整原件；同一事务保存原槽位的新版本、accepted受理、完整资源owner／占用head及审计。相同凭据和请求ID重投只返回原结果，内容或用途不同拒绝；`lookupExtensionActivation`按当前读权查原。受理不分配新安装，也不把候选发布为active_closed。

资源来自计划的完整核心图，两个槽位不能同时占用同一资源。数据库要求受理与槽位操作相互引用，提交前逐项确认完整占用，不能少写一个owner后仍成功。槽位保持active_installation_id=null，同时记录enabled意图、待启动目标和原操作；有待处理操作时拒绝stage覆盖。旧版本槽位／候选／计划原字节保留，迁移不补造受理或占用。

schema 22的新worker准备必须匹配本次服务启动的人员受理、当前审批和仍持有的完整资源。一份受理至多关联一个launch，数据库唯一约束与业务writer同时检查；同launch查原不授新资格。重启保留受理和占用历史，但不能自动恢复旧启动。审批撤回先阻止后续准备，不自动释放资源；释放仍需完整关闭／退役／资源核销路径，当前尚未实现该释放入口。

当前受理结果只为accepted，业务短授权见下节；完整出口登记、运行发布、取消／停用与资源释放仍待接通。内部方法尚未映射正式管理HTTP／GUI，不能据此宣称完整安装生命周期或设备运行已完成。

### 业务启动短授权与撤销同步

业务库schema 23提供核心内部的`workerLaunches.authorization`。`bindSource`只绑定本次核心准入回执、实际监督实例及Windows原生单调时钟；`authorize(LaunchKey)`从已受理操作、当前审批、完整设备／资源依赖及实际安装查询生成两秒LaunchAuthorization，调用者不能提交审批内容或自行缩小设备集合。`register(LaunchKey)`和`create(LaunchKey,proof)`在同一串行队列取得新授权并交给原监督连接；CREATE只接受已有load及物化证明标识。已经尝试创建、退役或失去资格的launch不能续签以再次创建。

核心先将本boot所有已准备launch的完整fence快照持久化，再发送并保存精确ACK，最后同writer复核原件并保存授权；授权正文摘要不包含顶层authorization_ref。ACK等待期间撤销会发送下一版完整deny，旧allow不能生成授权。审批和资源资格每500毫秒复核，`synchronize()`可立即传播当前撤销，`deny(LaunchKey)`永久关闭该launch；任何ACK不确定、授权写入失败或来源丢失都关闭新签发，存储失败会关闭监督连接。快照、ACK、永久deny与授权原件不可改写；重启只有历史，不补造资格。开发上限为每boot4096版快照、每库4096份授权及4个并发请求，仍待生产容量验收。

真实跨仓流程使用独立安装INTAKE_QUERY核当前回执，然后完成业务计划、受理、唯一准备、业务REGISTER／CREATE、关闭态运行采用和人员撤销传播；安装查询不依赖已登记worker。平台批准、可信时间与测试装配仍为明确测试配置。该入口尚未映射正式管理HTTP／GUI，也不发布active_closed、不释放资源owner或生成设备发送许可；受监督模块只读入口见下节。

### 受监督设备模块与候选采样

业务库schema 24增加模块通道、不可变帧及同事务审计；schema25增加只读目录批准和基线样本，旧库须显式备份迁移后才能打开v2模块。核心内部 `workerLaunches.openModule(LaunchKey)` 采用本次启动的当前RuntimeBinding和同库配置原件；原生监督器创建专用双端命名管道，分别核实际核心与worker进程，持续持有加载材料并转发有界字节。worker只在收到匹配运行原件的LOAD后导入批准清单指定入口，要求 `leafseamer-device-module/2` API及 `device-module/3` IPC版本。该内部接口尚未映射管理HTTP／GUI。

返回对象提供 `connectReadOnly(deviceId)`、`captureBaseline(deviceId)`、`stopReadOnly(deviceId)`、`currentBaseline(deviceId)` 和 `close()`。每次连接生成独立session，每次采样生成独立capture ID；回复核原运行、通道、请求、设备、session和截止。通道采用规范JSON、至多1MiB单帧、连续序号及两秒固定窗口；错绑、超时、断连或当前资格失效关闭通道并撤回运行采用，不自动重连或重采样。监督器发现通道断开后停止专属Job，实际退役仍以组为空为准。

发出请求前先持久保存原帧；响应与审计提交成功且资格仍有效后才交给调用方。提交失败或漏写审计不能返回采样成功，已经执行的采样不重发。开发容量为四个活动通道、每库4096个保留通道、16384帧及64MiB帧正文，达到上限拒绝，不自动删除历史。schema23须通过已有备份迁移入口显式升级，迁移不补造通道或样本。

包内 `simulator-module.mjs` 可作为独立批准扩展的入口，提供虚拟连接、当前固定值和逐次采样序号，尚未实现动作写入。CONNECTED中的目录由核心核对实际入口和 `simulator-policy.json` 字节、已审阅状态模板、设备资源、平台引用及当前运行会话，形成固定内存模拟器的只读批准。采样须符合该状态Schema、从1开始逐次递增且保留同域时钟原件，才保存为基线样本；批准与样本各自和审计在同一不可变记录内提交，写入失败或静默忽略均关闭运行。`currentBaseline` 返回当前会话批准及最后接纳的基线，不是持续实时读数；断开、撤销或新会话不能复用旧批准。每库最多4096份目录批准、16384份样本，不自动删除历史。

该批准明确 `write_eligible=false`、`automation_eligible=false`，只适用于包内固定模拟器，其他模块不会因自报相同型号取得资格。物理型号CatalogApproval、事件来源／年龄接纳、设备写出口和资源释放仍待接通。扩展是经过管理员批准的代码，进程监督不构成恶意代码沙箱；没有以模拟器结果批准实际设备。

### 执行会话与初始控制屏障

schema42将人员执行来源改为实际挑战／响应：`beginManualExecutionChallenge`核验人员令牌、当前持有人、权限和运行装配，生成32字节随机nonce，将挑战与提交审计同事务保存；`completeManualExecutionChallenge`核验实际令牌秘密、完整挑战引用和nonce，响应关联与人员来源／审计同事务提交。挑战绑定实际token、会话、凭据、控制原件、完整执行Binding及原核心观察；截止不超过挑战开始后两秒和原观察期限。相同请求只返回仍有效的原件，不换nonce或续期；错误nonce、不同响应内容、过期及旧单步取证入口均拒绝。

挑战受理和响应提交是两个事务：响应漏写回滚人员来源及响应，已可靠受理的挑战仍保留；挑战或其审计缺写连同本次核心观察一起回滚。三个挑战表不可改写，每库至多4096份挑战。显式升级不补造历史挑战，旧人员来源缺少实际挑战时不能作为当前输入。该内部入口尚未接HTTP／SDK，也不构成完整授权Evidence、OPEN或设备写许可。

schema33提供核心内部的人员执行来源采集与当前复核。首次采集验证令牌秘密、精确持有人、显式device.command权限、当前会话／凭证／策略及认证时钟，并绑定真实执行装配和控制物理原件。原件与审计封存同事务，保存两秒取证窗口；使用时仍重核令牌、会话、权限、装配及期限。断开、注销、撤权或到期后的旧原件不能提供当前资格，原件不保存令牌秘密。该入口不新增HTTP接口，不替代设备授权State、恢复、OPEN或ReadyCommit。

schema34将设备授权的保护状态接入控制变更事务。每次新的控制权原件同时写入不可变授权State、前驱、每设备当前指针、审计及保护意图；缺写会连同控制变更一起回滚。人员来源记录采集时的完整State引用。该版布局仅允许`protected`，缺少的内部评估器、设备范围和人员谱系显式为null；保护意图不是关闭确认。迁移不回填历史状态：已有控制来源在新的writer取证时才初始化，使用实际当前采样时刻；没有控制物理来源的设备继续拒绝取证。schema41已补充恢复授权消费与策略选择，schema43补充本机普通手动Evidence采用；实际保护意图派送仍未接通，State存在不构成Ready或发送许可。

schema35保存实际核心运行来源：当前监督连接的完整查询／响应、启动原件、同域采样与固定截止随人员取证同事务封存。只有该连接实际持有的观察可用于当前复核，复制正文、过期原观察或重启后的历史记录不能恢复资格。人员取证的截止同时受该原观察限制，后来的监督刷新不改写旧原件窗口。当前核心运行来源不包含服务主体凭据、内部设备策略或设备范围批准，不能充当完整评估器授权。旧库迁移不从历史启动记录补造当前观察。

schema36提供核心内部的服务身份首次登记链：`createServicePrincipal`先创建disabled服务主体；`approveServicePrincipal`要求当前人员的auth.manage及近期认证，明确本Controller audience、权限清单、已登记设备范围和认证时间有效期；随后`createServiceCredential`暂存opaque凭据，`proveServiceCredential`验证持有，最后由人员调用`activateServiceCredential`激活。服务不创建人员会话，名称和purpose不赋予Seamer或设备控制角色。主体、批准、凭据修订、证明与操作记录同事务保存，迁移保留原人员映射。

凭据秘密仅首次成功创建交付，重投返回原非秘密结果和`secret_delivery=unavailable`；数据库仅存带算法版本的验证值。暂存窗口最长十分钟且不超过凭据和批准期限；证明不延长窗口，到期或撤销后不能因时间回退恢复。`getServicePrincipal`、`getServiceCredential`只供当前人员管理读取，`revokeServiceCredential`关闭本地凭据。当前内部入口尚未接HTTP／GUI，首次批准之后的范围变更、并行轮换、跨服务批准、配对和撤销传播仍待实现；批准清单尚不构成接收方当前授权，active凭据也不能替代设备恢复或OPEN许可。

schema37补充本机定向服务令牌。当前人员凭auth.manage及近期认证调用`approveLocalServicePolicy`，分别保存接收方策略、批准引用、设备范围和有效期；仅有主体批准不能换取令牌。`issueServiceToken`验证active凭据实际秘密，完整核对请求范围与双方授权，首次返回短期opaque秘密；同credential／request只查原，异摘要拒绝，秘密不进入操作正文。开发窗口最多60秒且取凭据、批准及本地策略最早期限，每凭据至多8个活跃令牌，永久保留记录总量有界。`verifyServiceToken`每次重核父凭据及本地策略；凭据撤销、本地策略撤销或观察到期均阻止旧资格，最终签发检查遇到期时保存终态而不交付秘密。当前唯一消费入口`readServiceIdentity`仅允许identity.read读取自身主体，不建立人员会话、不接入人员令牌入口，也不授予设备操作。schema36升级保留身份与凭据，不自动添加本地策略；服务令牌已在受监督核心验证，跨机接收、内部设备评估策略、恢复、OPEN和命令终态仍待实现。

schema38提供内部评估器取证。人员通过当前auth.manage及近期认证明确批准`approveDeviceEvaluatorPolicy`，绑定本服务／数据库、服务主体及批准原件和设备范围；服务名称、purpose或identity.read令牌不能替代该策略。`beginDeviceEvaluatorChallenge`从当前监督连接封存核心观察和随机挑战，期限不超过原核心观察的固定两秒窗口；`completeDeviceEvaluatorChallenge`验证当前active凭据的实际秘密、nonce、完整挑战和当前策略，原件与操作记录同事务保存。重投只查原，不延长窗口或替换来源；错误秘密、错nonce及冲突响应拒绝。`currentDeviceEvaluatorSource`重核运行域、原观察、当前凭据、主体批准和策略，到期拒绝不影响人员会话继续使用。策略撤销和观察到期永久关闭该策略，父凭据撤销立即使存量来源不可用；来源或提交缺写回滚，装配失败退役Worker。

该来源已在真实受监督核心验证，仍是设备授权的输入。人员与评估器来源现保存完整`authentication-monotonic-window/1`，认证采样必须精确匹配当前监督域、服务boot和描述符；独立UUID认证域不能直接用于设备窗口。按整数速率包络求出UTC有效期对应的半开单调截止，再与原认证样本、运行／健康原件、核心观察和挑战期限取交集；当前采样刷新不延长已保存窗口。窗口随来源正文同事务保存，原件读回重算并核当前故障状态；旧历史中缺窗口的来源不能作为当前设备授权输入。真实进程联调使用原生Windows采样，环境和授时批准仍为测试夹具，不能据此声称生产时钟已获资格。

schema39增加核心内部`revokeServicePrincipal`。当前人员须有auth.manage及近期认证，并提交精确主体修订；同一事务将主体转为revoked，同时关闭其全部staged／proven／active凭据，已终止凭据保留原终态。主体及凭据的历史、head与操作记录任一缺写全部回滚；相同请求查原，内容冲突拒绝，另一个主体不受影响。旧服务令牌和评估器来源重新取证时立即拒绝，已撤主体不能重新批准或创建凭据。显式升级保留旧身份字节，不自动撤销任何主体；内部管理响应仅表示本机身份链已关闭，不宣告跨服务传播或物理保护已完成。

schema39的人员及评估器来源同时保存本机授权依赖快照。成员从实际身份、凭据、会话、主体批准和策略原件派生，调用方不能提供删减列表；来源重核在同一身份writer内重建快照并逐项比较。人员侧纳入会话撤销下界及权限削减记录，评估器侧纳入主体／凭据完整修订历史与策略撤销；无关主体变化不改变原快照。快照不含秘密，稳定排序仅用于比较，不表示事件发生顺序。相关撤销、依赖变化、缺项或容量超限均拒绝旧来源。

核心内部`currentManualAuthorizationContext`在同一writer读取人员及评估器当前来源，再核精确设备、控制权与State、服务启动记录、监督成员启动身份、IPC／设备会话和认证时钟域。它从原件生成待选Context、两角色窗口及完整身份依赖，不接受调用方提供lineage、范围摘要或有效窗口。评估器策略原件同时保存其设备范围；该完整Ref用于策略和范围引用。短期挑战／响应更新不改变Context，人员会话／凭据或策略变化必须形成不同Context；最晚有效时刻取两角色窗口交集。此入口只提供恢复采用者所需的当前输入，不写policy_selected、不签发恢复授权、不改变保护状态。

schema40提供核心内部人员恢复受理`requestDeviceAuthorizationRecovery`。请求须有显式`device.recover`和`device.command`、近期人员认证，并匹配当前持有人的会话、凭据及人员来源实际token；初始管理员和升级不会自动取得恢复权限。调用者提交明确请求ID、设备、期望保护状态及待选上下文摘要和两类来源Ref，服务在writer内重读完整原件。请求键绑定目标服务／数据库、issuer三元组、request_epoch、固定操作和幂等键；请求回执、完整RecoveryAuthorization及提交审计同事务，三写点任一缺写均回滚。

相同键同内容只返回历史结果，异内容冲突；`lookupDeviceAuthorizationRecovery`需要当前人员权限，`currentDeviceAuthorizationRecovery`另重核原来源、控制状态、运行绑定与固定有效窗口，已消费授权不能再次取得当前资格。回执包含来源封存，授权期限不超过两角色最早截止；历史查原不续期。开发保留预算4096项、单回执至多64 KiB，满额拒绝，不删除历史。此入口尚未公开为HTTP／SDK恢复操作；返回受理记录不表示设备已恢复。

schema41的核心内部`consumeDeviceAuthorizationRecovery`将实际恢复授权消费与`policy_selected`状态后继、审计／恢复意图和当前指针CAS放在同一writer。采用前后均核当前人员、两类来源、原保护状态、完整运行Binding及原固定窗口；另一请求已改变State时拒绝旧授权。消费、State、commit或head任一缺写全部回滚，原先可靠受理的请求保留。消费主键保证同一授权至多采用一次，重投只返回原状态历史，后续保护不会被历史查询撤销。

人员来源中的State引用在schema41记录采集时的关联；采用者另从当前head取得State，不能把来源内旧Ref当作当前授权。短期刷新保持同一有效谱系与运行绑定时不增加State修订；新来源发现运行绑定、人员谱系变化或尚未采用Evidence的恢复窗口已失效时，先追加protected。当前已实现实际重连后的保护及旧消费查原不移动head；schema43已接通本机普通手动Evidence续约，持续撤销派送和实际保护意图输送仍待实现。policy_selected只表示策略上下文已选定，不改变执行闸的closed状态，也不授予发送资格。

本机身份依赖快照不授予发送资格。schema43在本机ordinary/manual分支中将它与当前扩展、运行和信任来源共同纳入Evidence；跨服务issuer、独立取消及逐命令RunGrant仍须接入各自提供者。首次OPEN／Ready另由schema47／48接入；通用资源恢复和命令终态仍待接入。策略首次批准与撤销已实现，策略更新／重新批准、跨机挑战和公共管理入口尚未实现；不会从历史身份补造策略、挑战或评估器来源。

schema32在每次新的控制变更事务内保存完整物理控制原件，包含独立变更ID、公开修订来源、控制身份、受监督单调域、实际观察时刻和自摘要；同一提交缺少原件即回滚。初始屏障绑定该物理Ref，公开逻辑记录ID不替代内部权威引用。旧控制历史原样保留，不能在已封存提交后补造观察时刻；缺少原件或当前域不符时拒绝后续执行来源。该来源本身不授予OPEN或设备发送许可。

当前SDK选择为`leafseamer.api.v1.product4`，执行通道为`ipc/0.16.0-reference-optional-draft.1`，由`sdk-runtime.json`锁定。显式协商`reference_time_absent`且未选择任何参考时间能力时，OPEN及ACK保留时间字段并允许`null`；字段缺失、未协商使用和时间依赖业务均拒绝。它不授予UTC、定时执行或时间恢复资格。固定内存Worker已装配普通人工执行组件；schema47核心按该固定资格选择能力并接入首次持久OPEN，schema48接入设备Ready，schema50接入无attempt排队命令的持久关闭；发送后的命令终态仍待实现。

schema 30保存真实Execution握手、双向原始帧、领域提交及写尝试；schema 31进一步将初始FENCE与FENCE_ACK接入同一序号日志。Core只从当前人员控制记录、已采用Worker、已批准目录及活设备连接选择关闭屏障，不接收外部提供的控制原件或成功确认。请求和确认各有双向外键绑定的专属写集，领域缺写或写预约失败不交付成功结果。出站字节来自已持久原件，写尝试先提交后入流；结果未知关闭会话并退休Worker，不自动重发。

初始关闭路径要求设备无已接纳命令，初始空账本、零签发及首个屏障尝试；非空切点仍待接入。确认绑定原请求、实际设备出口、控制版本、同域时刻和空账本；重查返回原确认，重连须使用新的装配与屏障。屏障确认仍为closed，不更新公共控制记录为ready，不授予编码或发送许可。schema47另行接入固定内存设备的首次持久OPEN及ACK。已验证真实受监督进程的关闭成功、重连与三种存储故障，真实设备及命令端到端终态尚未验收。

### 人员控制请求与退出屏障

schema26提供人员接管、释放和转交请求存储，使用当前人员Bearer令牌、同会话CSRF、RequestContext及控制版本CAS。接管、释放、提出转交、接受转交分别要求 `control.acquire`、`control.release`、`control.transfer`、`control.accept`；管理员身份不自动授予这些权限。强制接管额外要求 `control.emergency` 和非空理由，服务主体不能使用这些人员入口。

HTTP入口为 `POST /api/v1/devices/{device_id}/control/acquire`、`release`、`transfers`，以及 `POST /api/v1/devices/{device_id}/control/transfers/{transfer_id}/accept`、`cancel`。请求字段及实际路径以SDK当前product1选择为准；响应202表示持久受理，200表示同键查原，均不表示已经生效。通过 `GET /api/v1/control-operations/{operation_id}` 查询操作，通过控制记录查询实际生效版本；`POST /api/v1/control-requests/lookup` 验证当前人员、目标scope及历史请求命名空间后查原。同键异内容拒绝，新请求耗用上下文预算，重放不重复耗用。

接管、释放与接受转交在同一事务预留单调版本、保存完整历史启动集合、pending记录、请求回执和审计通知。pending期间拒绝新增启动准备；旧launch永久拒绝续签。核心内部屏障取得完整deny快照的确认和原监督器的组空退役原件后，才在同一事务更新生效版本。无证据或确认不完整时保留未决及预留版本；事务失败不部分提交。跨boot仅复用已持久保存的完整退出证据，未知旧启动不会视为空集合。当前只适用于没有已接纳命令的设备，后续命令执行必须接入完整命令切点与资源归类。

接管和释放已通过本机真实监督进程、SQLite及HTTPS检查。生效后仍为 `protected`，不提供设备发送许可、不释放扩展资源owner。转交的存储与接口已有实现，多人员管理来源、双人员完整流程及GUI操作尚未接通验收；不能据此宣称完整人工控制交付。当前开发容量为4096份请求、16384次控制提交及每次256个历史启动，达到上限拒绝，不删除历史。

### 完整worker登记

可信核心装配通过`registerWorker(intent, authorization)`提交完整意图，`queryLaunch(key)`查询原登记。Controller只接受devices分支，设备集合1至64项、ASCII排序唯一；数据源分支属于Seamer，不能在Controller取得设备进程身份。完整extension_binding、对象范围、运行组合、组、member及政策进入不可变意图和摘要，REGISTER不启动OS进程。

原生宿主独立重建规范意图与授权，核当前服务／数据库、监督实例、runtime generation、完整权限／安装／批准／解析绑定、当前fence revision及同域两秒授权窗口，再将意图、初始授权和registered状态同事务保存。首次成功登记随后建立独占Windows Job并持久保存组保留原件，两者均完成后才响应REGISTER；失败关闭当前控制运行，不补发成功。Job使用随机名称、当前账户／SYSTEM ACL，拒绝同名既有对象，持续持有不可继承句柄，设置并回读KILL_ON_JOB_CLOSE且不允许breakaway。相同键与内容只查原并复用原Job，不替换初始授权或创建第二条记录；同ID异意图、重复member／组拒绝。登记与状态双向延迟外键防止孤立提交，历史意图不可更新或删除。LAUNCH_QUERY返回registered及creation_attempted=false，不能解释为运行准入。

真实Windows管道／SQLite用例已覆盖规范完整登记、重复查原、短授权过期及未来起点、错域／权限／批准、完整fence遗漏、永久撤销和同ID异范围。独立协议用例中的安装审批与权限Ref为合成输入；跨仓运行用例采用真实业务审批与短授权，Suite可信物化提供者已按下节接通。CREATE仍须重新验证完整审批原件和challenge，并在创建前持久消费一次尝试；当前不提供绕过物化的启动开关或任意worker路径。

`createWorker({key, authorization, load_id, materialization_evidence_id, materialization_challenge_id})`重新核当前完整意图、授权正文摘要、两秒同域窗口、完整fence及profile，并核当前五秒物化观察、ready内容持有和受保护运行包。未知键、错摘要、旧栅栏或无效批准均拒绝；REGISTER的初始授权不替换。合法拒绝响应仅允许query_only，不延长健康查询期限。业务调用使用下述授权提供者；独立协议故障用例保留合成授权。

原生监督器先在schema 5同一事务保存不可变创建原件并将registered改为creating／creation_attempted=true，然后最多调用一次OS创建。进程悬挂创建时即进入原根Job和专属Job，核实际PID、创建时间、映像FILE_ID及组归属，持久观察并转awaiting_bootstrap后才恢复线程。执行入口固定为受保护包内device-worker-entry.mjs；上下文由父进程创建、核摘要并持有，不接收任意模块路径。创建调用失败或已消费后超时均保留indeterminate，重复CREATE不能重试或复活。

worker在原监督域内取得新的定向挑战、秘密和member_boot；证明、实际根进程归属及固定截止全部成立后，先持久closed回执再交付ADMISSION。成功交付后清除挑战秘密并删除临时上下文。awaiting与admitted_closed期间持续核当前fence和根进程；撤销、退出或异常管道进入indeterminate并停止整个专属组。收到closed回执不导入扩展、不连接设备、不生成核心RuntimeBinding。运行后的后代仍纳入同一Job，实际组为空才允许退役。

`retireWorker(intent, reason)`从完整意图生成精确键及containment，原生端核持久摘要和原组／代。registered、creating、awaiting_bootstrap、admitted_closed及indeterminate先持久retiring，再停止持有的专属Job；只有实际活动进程数为零且原组限制未变，才将完整组观察、原请求、RetirementEvidence和retired状态同事务提交。累计进程数来自实际观察，不伪写为零。缺原组或尚未观察空组返回indeterminate；调用方可继续查询或请求退役，不能重复CREATE。原件不可替换或删除，重复退役查原，同ID永久不可复活。撤权和fence失步不阻止退役；retired后才释放监督器持有的运行内容。该流程不证明旧监督域恢复或设备资源释放。（实际计数语义依据：[Microsoft Job accounting](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_accounting_information)。）

### 安装内容与候选实例

业务库schema 13提供可信本机装配接口`storage.extensionInstallations`。`bindSource(host)`在本次打开期间固定Suite安装宿主身份与`describeIntake`方法；`createSlot({request_id,extension_id})`建立空槽位；`stage({request_id,slot_id,expected_slot_revision,intake_ref})`读取当前合格内容，核完整intake引用、目标权威、宿主及清单／库存摘要，分配新的不可变installation。此处为同进程受信任库装配；独立服务的内容传输及管理HTTP入口尚待接通。

候选内容、槽位修订／head、请求原结果与审计在同一writer事务提交；完整引用及延迟外键绑定写集。相同request_id同内容查原，异内容冲突；新请求核槽位CAS，旧请求查原不因槽位推进重新生成实例。`query(request_id)`查历史结果，`content(installation_ref)`按完整引用查固定内容。每库最多4096个保留管理请求，候选正文至多8MiB、全部候选正文合计64MiB，超限拒绝且不删除历史。

这些内部方法仅准备管理原件，尚未映射公开的C09 Context和人员鉴权。候选初始state=verified、approval_ref=null、运行绑定为空；它保存观察时内容，不能代替审批或启动时的当前实物资格。角色解析、人员审阅／批准、撤销传播、启用与运行采用仍须完成。配置原件接口见下节。真实Suite封存内容已验证进入文件业务库、重启查原及信任代撤销后拒绝新候选；逐写故障验证整组回滚。没有执行归档中的模块。

### 安装配置原件

业务库schema 14增加`storage.extensionInstallations.configurations`。来源绑定同时固定Suite的`describeConfigurationSchema`方法；`configure({request_id,installation_ref,expected_revision,bytes})`接收至多1MiB的原始JSON Buffer，在完整安装引用及Schema文件摘要匹配后校验配置，再复查当前来源资格，最后同事务保存配置修订、head、请求结果和审计。新配置期望版本为`"0"`，之后使用当前版本；同一实例保留稳定配置ID和递增版本。`query(request_id)`查原请求，`current(installation_ref)`查当前配置；历史结果不代表当前实物资格。当前仅用于未批准候选，后续批准流程须冻结所选配置版本。

配置原始字节摘要参与幂等比较，因此空白等字节差异也会使同request_id冲突。每库最多4096个配置操作，配置正文合计64MiB，超限拒绝而不删除历史。Schema仅来自清单指定且库存角色为schema的文件；Suite使用受保护的原文件句柄读取，Controller再核文件长度、摘要和完整来源引用。

固定短生命周期校验子进程复用SDK原始JSON解析规则和JSON Schema 2020-12校验，拒绝重复键、不可精确表示的整数、外部引用及未知关键字，不转换类型、填默认值或删除额外属性。核心继续禁止字符串代码生成；只有该固定入口子进程允许编译Schema，且不继承NODE_OPTIONS或预加载配置。并发最多两个，外部截止三秒，输出和输入有字节上限，V8老生代堆64MiB、半空间4MiB；这是校验资源预算，并非完整操作系统内存隔离保证。超时或异常不产生可用配置。

真实文件库测试覆盖版本CAS、幂等、逐写回滚、重开查原和schema13→14显式迁移；真实Suite封存内容与固定校验子进程联调覆盖原Schema读取、约束拒绝和信任代撤销。这些内部接口尚未公开为人员管理HTTP或跨进程内容消息，也不生成批准、LaunchAuthorization或RuntimeBinding。

### 角色解析原件

业务库schema 15增加`storage.extensionInstallations.roles`。`deviceReference(device_id)`从实际设备登记原件产生完整本地Ref；`resolve({request_id,installation_ref,configuration_ref,expected_revision,bindings})`只接受角色绑定，权限模板和用途来自已保存manifest。expected_revision是该候选的解析序列，初次为`"0"`；它不是公开管理接口的installation CAS。每次新解析分配新resolution_id，保留旧原件；`query(request_id)`查历史结果，`current(installation_ref)`核当前配置与对象后查最新结果。推进配置会使旧解析不能作为current使用，但不会删除历史。

解析检查声明与绑定一一对应、kind与基数、同一配置、目标权威／库、完整对象版本与摘要、唯一性和规范排序。八种模板采用固定投影；端点不得为URL或通配符，helper绑定包内文件原字节摘要和制品集合，protocol_io必须引用同集合且同profile的网络权限。客户端不能提交permissions，不执行扩展代码或文本插值。编译后的产品Schema再次校验整个结果；提交前复查当前安装来源，再在同一writer快照内重读配置与对象、重算权限。解析修订、head、查原结果和审计同事务提交，逐写失败全部回滚；每库4096次解析、正文合计64MiB、并发最多两个。

当前业务提供者接通实际设备登记原件。source、data_object、secret_role、filesystem_role、helper_artifact、protocol_profile、validation_policy及run的实际存储提供者尚待接通，缺失时返回object_provider_unavailable；测试中的八类型映射使用合成对象提供者，不能作为这些资源已运行的证据。设备登记当前没有运行能力目录，解析中的action_ids等仅记录模板请求；动作支持、用途政策、人员可见性及收窄批准仍须在后续审阅／审批链验证。角色解析不授予设备权限，不等同于安装审批或启动资格。

### 权限审阅原件

业务库schema 16增加`storage.extensionInstallations.reviews`。`review({request_id,installation_ref,configuration_ref,role_resolution_ref,expected_revision,proposed_permissions})`从当前固定解析取得requested_permissions，不接受客户端上传requested或policy。expected_revision是本实例的审阅序列，首次为`"0"`；每次新审阅分配新review_id。`query(request_id)`查原，`current(installation_ref)`要求角色解析、配置、对象与当前审阅策略仍匹配；配置或解析推进后保留旧历史，但拒绝将旧结果用于当前操作。

提案先用SDK产品Permission定义校验，再执行八类权限收窄：kind与purpose不变，集合仅删减且保持唯一排序，quota_bytes用精确整数比较且不能增加，其余固定字段及完整Ref不变。device_scope与secret_role不能保留空用途；protocol_io必须保留同profile的network_endpoint。可删除整项权限，空提案表示请求不授予任何权限，不隐式恢复manifest的完整范围。

服务在首次成功审阅事务内保存本地validation_policy原件，绑定当前构建清单摘要、产品契约和收窄规则，调用者不能选择其他策略。不同构建产生不同策略身份；旧审阅可查历史，但不能自动作为新构建的current结果。策略、审阅、head、请求结果和审计同事务提交，角色与配置在同writer内重新核对。每库最多4096次审阅、正文合计64MiB、并发最多两个。逐写故障、显式15→16备份迁移和独立进程策略变化拒绝已有验证。

该接口准备后续人员批准所需的固定请求与提案，尚未表达人员确认、会话授权、能力支持或最终用途政策批准。它不生成Approval、LaunchAuthorization或设备权限，也未替代正式C09管理HTTP的Context与installation CAS。其他角色对象提供者及正式人员管理传输继续作为未完成实现；下节提供真实会话的内部批准入口。

### 人员批准、冻结与撤销

业务库schema 17将安装批准接入真实`storage.sessions(clock)`。`extension.manage`进入本地可授予权限目录，但不加入首次管理员默认权限；须由有当前auth.manage权限且处于近期认证窗口的人员显式授予。批准入口只在默认本地权限权威下装配，外部自定义会话权限提供者不能取得该入口。调用者提供真实access token，不能上传principal或自报认证证明。

`sessions.approveExtension(token,{request_id,installation_ref,permission_review_ref,configuration_ref,approved_permission_ids})`要求当前人员令牌含extension.manage且处于既有五分钟近期认证窗口。批准前后核对令牌、会话及当前权限；等待安装来源期间注销或撤权会阻止提交。权限ID须排序、唯一，并从固定review.proposed选择完整权限对象；permissions_digest覆盖完整收窄结果，不能回查manifest扩大范围。schema 18从包内静态模板核对设备动作声明，允许批准与本地设备角色及device_kind相符的非空权限；不依赖启动后才能产生的运行目录。其他资源类型缺少实际能力提供者时仍拒绝。空权限批准只表示不授予扩展任何权限。schema 17保留原有设备目录检查，不自动获得新能力。

批准、完整权限和人员操作审计同事务保存。每个installation至多一次批准；配置、角色解析和审阅的后续插入由数据库触发器拒绝，即使批准已撤销也不能复活旧实例。须重新stage候选，再配置、解析、审阅并批准。`revokeExtensionApproval(token,{request_id,approval_ref,reason})`使用当前人员管理权限保存永久deny；它不依赖安装来源或旧审阅策略仍可用，重复撤销返回原deny。实际worker保护传播尚待运行采用链接通。

`lookupExtensionApproval(token,request_id)`要求extension.read，按当前真实credential与request_id查历史；不同credential不共享请求身份。`getExtensionApproval(token,approval_ref)`要求extension.read，返回本地批准或永久撤销状态；approved还须匹配当前审阅／配置／对象／构建策略及能力。此查询不检查实时安装实物，不生成启动授权，也不能替代启动时的Suite物化复查。历史approve结果在撤销后仍可查原，不能当作当前有效批准。

每库至多4096个批准／撤销请求，结果合计64MiB，单结果4MiB；批准并发至多两个。真实登录、令牌签发、管理权限授予／撤销、近期认证截止、等待中注销、配置冻结、逐写回滚及重开后的永久deny已有文件库验证。认证时钟与平台资格的测试输入仍为合成；人员管理HTTP／GUI、完整对象能力与用途政策仍待完成；业务短授权、一次CREATE与关闭态运行采用见前述章节。

### 包内静态能力与运行目录分离

schema 18通过固定安装来源的`describeCapabilityTemplates`读取清单指定文件，核完整intake／清单／库存／文件身份及原bytes摘要。SDK独立`capability-template`入口严格解码，模板的device_role须为本包声明的设备角色；同角色与device_kind只接受一份模板。SchemaDescriptor摘要须匹配JCS文档，相同schema_id不得代表不同定义；全部Schema在固定子进程内共享编译预算，拒绝外部引用和未知关键字，核心继续禁止动态代码生成。

批准时将权限中的真实设备引用映射到当前角色绑定及device_kind，核动作／触发器ID与当前OS／架构声明。静态模板不携带运行footprint；平台untested可作为待验声明参与安装批准，不能据此宣称平台或设备已通过验收。所有文件总计至多1MiB、唯一Schema至多256，证据正文每项2MiB、每库合计64MiB。模板证据、批准、完整权限和审计同事务写入，失败全部回滚；当前批准重查原模板选择、配置／角色及设备绑定。17→18显式迁移保留旧记录，不补造静态证据。

这是既定的安装前静态批准；启动后的只读身份观测、实际目录、型号／固件／资源足迹、完成与取消资格仍须由运行CatalogApproval核定。非空安装批准不生成LaunchAuthorization，也不允许设备发送。当前仅接通device_scope声明检查，其他资源能力、完整用途政策、正式管理HTTP／GUI和运行采用仍待完成。

### 当前内容锁交接

`storage.workerLaunches.acquireContent(LaunchKey)`仅处理本次核心启动已准备的完整意图，审批与内容提供者由storage固定装配。它从Suite有界交接核完整intake／收据／manifest／inventory，固定worker再按当前库存核原bytes摘要、文件类型、完整目录及root FILE_ID并取得自己的原生只读锁。交接释放前重核Suite资格和本地审批；接收方锁已持有才结束Suite交接。摘要与目录扫描在固定worker中运行，单次原生检查至多三秒，不阻塞核心监督心跳。

返回的`protection`固定根路径／身份、入口文件及相对路径、IO策略文件ID和两个制品摘要；它不是可执行授权。`verify()`重新核Suite当前内容、原生锁和本地审批，失败关闭保护；`close()`和`closed`用于等待实际释放。业务库关闭会主动终止本库持有的内容worker，最多四个等待或已持有的保护。启动器每次消费前仍须核当前批准、完整启用／资源计划、短授权及fence；路径副本不能替代活的保护句柄。

已验证Windows真实句柄交接、防改写／替换、当前信任撤销及业务库关闭后的释放。该入口同时返回冻结的materials，供下述监督通道交接；完整扩展加载器闭包与创建业务编排仍待接通，不把内容保护视为worker已启动或模块已加载。


### 固定 worker 启动运行包

Windows 构建按`worker-runtime-inputs.json`固定 Node 24.22.0 x64、Node 许可及canonicalize原始模块／许可的字节摘要，运行包包含`runtime/node.exe`、`runtime/canonicalize.mjs`及相应许可。构建必须使用该固定Node和同目录LICENSE，摘要不符即拒绝，不从网络获取或选择另一运行时。worker bootstrap、核心bootstrap和监督客户端的规范化库均从包内固定位置导入。

带bootstrap政策启动时，原生宿主从自身安装目录读取完整构建清单，将构建原字节摘要与随包Node摘要合成并核对artifact_manifest_ref；在创建核心前按完整库存检查实际文件、目录、文件身份和内容，再持续持有原生句柄。解释器固定为随包Node，调用方传入的解释器路径不能替换该选择。原生创建时仅交付Windows系统和临时目录环境项，工作目录固定为受保护安装根，不继承NODE_OPTIONS／NODE_PATH。受保护的实际盘符路径用于Windows创建进程，加载后另核真实映像文件身份。

该保护已覆盖当前worker bootstrap所需的Node、JS验证器、规范化库和本地时钟模块，独立副本无需外部npm模块即可运行这条路径。它尚不覆盖核心数据库等包外业务依赖，也不表示扩展动态加载闭包、OS平台组合或正式发行信任已经验收。CREATE采用该固定组合；真实启动授权来源及扩展启用业务继续实施。裸开发容纳模式没有bootstrap政策，不能据其启动成功声称取得上述保护资格。

### 原生监督器持有扩展内容

监督控制0.4增加LAUNCH_LOAD／LOAD_RESULT，`loadWorkerContent(LaunchKey, materials)`先取得当前物化证明，再按begin／chunk／finish传输完整加载材料。材料来自`acquireContent`返回的冻结原件，包含实际根路径／身份、manifest和库存；调用方在交接前后调用原持有对象的verify，监督器ready且复核成功后才释放Controller持有对象。该方法是可信核心内部接口，不能由管理客户端指定任意文件路径。

完整材料最多8MiB，分片最多49152原字节，严格连续offset并绑定完整材料摘要；从begin起固定十秒，不因轮询续期。原生监督器核当前登记、fence、物化观察、完整清单／库存摘要和指定worker入口，后台核实际目录、文件原字节及根FILE_ID并持有自己的句柄；等待与分片之间保留原健康查询。开发容量为四个活动加载、4096个保留load身份和一个后台扫描，未完成生产容量验收。

返回的load_id只标识本监督实例的内容保护。release在后台仍运行时返回pending，确认released后句柄才全部退出；撤销先关闭资格，未完成扫描的结果不得采用。创建尝试已消费时，内容保护保持至实际组退役，不能仅凭deny或通道丢失释放。CREATE还要求独立的新授权、当前物化证明和完整运行组合；load_id本身不能授予启动或设备权限。

真实Windows联调验证超过256KiB的完整材料及连续分片交接、Controller释放后监督器仍阻止改写／替换、显式释放与deny后的实际释放，以及错根身份、manifest摘要和worker入口拒绝。测试中的安装批准、平台资格和启动授权仍为合成配置，不能作为正式运行准入证据。

### 本机普通手动授权Evidence

schema43提供核心内部`selectDeviceAuthorizationEvidence`、`currentDeviceAuthorizationEvidence`及历史读取。选择请求只提供请求ID、设备、期望State／前次Evidence完整Ref，以及实际人员／评估器来源Ref；服务在同一writer中重读来源并构造完整Requirement、两角色窗口和不可变Evidence，调用者不能提交正文或删减依赖。首次选择必须匹配已消费恢复授权的完整Binding并仍在其原窗口内；续约从数据库读取真正的前次选择，核旧、新窗口与当前来源。传null不能绕过已有选择，重复请求只查原，同键异内容拒绝。

`local-manual-device-revocation-cut/1`从两类本机身份原件、当前扩展批准与完整运行装配、固定本机issuer、安装宿主信任代和实际intake引用派生。它记录当前适用集合，不伪造历史入账次序；人员／服务撤销、范围／策略变化、扩展拒绝或运行撤回均使旧选择不能作为当前资格。RunGrant属于逐命令授权，ordinary/manual设备资格不借用某条命令的grant；自动化、取消和跨服务issuer必须接入各自提供者，不能复用该分支。远端安装来源仍受现有实际观察窗口约束，该切点不声称跨服务瞬时撤销。

切点、Evidence、提交审计／通知意图和选择指针四写同事务；任一点缺写回滚本次采用，先前的恢复消费保留。历史对象不可改写，每个State的选择只能严格递进，不能清空或删除。有效设备选择必须同时连接当前授权State；State转为protected后，旧State的选择仅作历史，查原不移动当前指针。新人员取证以当前Evidence的实际截止判断是否需要保护，只有尚无Evidence时才使用首次恢复窗口；合法续约不增加State修订，也不延长任何旧挑战或旧观察。

运行来源增加内部`refreshCurrent`：在当前采用资格仍有效时取得新的真实监督观察，同一运行的并发调用共享一次刷新；失败先撤回，后续刷新不能复活旧运行。它不延长旧观察期限，也不修改持久运行身份。该入口可在进入同步授权事务前刷新来源，事务自身仍重新核验当前资格。

Evidence存在不代表OPEN、Ready或发送许可。当前仅完成本机ordinary/manual分支；首次OPEN／ACK／Ready见schema47／48；通用资源恢复、命令终态及对外HTTP／SDK入口仍待接通。实际设备、生产信任配置和跨平台部署需要各自验收。

### 固定内存设备的初始资源来源

schema44提供核心内部`selectInitialDeviceResources`、`currentInitialDeviceResources`及历史读取。它在同一writer核当前Evidence、实际执行连接、批准的固定内存模块及无外部资源传输配置、零写入基线、初始空屏障的真实ACK，以及该设备全部历史已受理命令和当前出站账本。已有命令、设备写入或其他执行消息时拒绝走初始分支；其他型号不能通过自报零占用取得该证据。

资源原件与提交审计／通知意图双向绑定、原子封存；缺一写即回滚，先前已提交的授权Evidence和恢复消费保留。来源保存实际Binding及授权、控制、目录、基线、屏障、出站原件Ref，期限不晚于所用Evidence。当前读取重新核验来源；新基线、重连、授权变化或过期使旧证据不可用。重复请求和历史查询只返回原件，不刷新期限或恢复资格。

新选择保存`leafseamer-initial-resource-source/2`，同一原件内封存首次手动开放所用的运行与命令空拒绝快照。此分支明确限定schema44／45、全库没有已受理命令、全部持久出站原件仅含允许的手动能力握手与首次零签发空FENCE；跨设备也不能遗漏已有受理或执行历史。读取复核原wire、正文、摘要、会话scope和提交关联，快照自身绑定scope、设备和零水位。新增出站历史使旧来源不再匹配；未来存储版本不能自动沿用首次捕获。旧`/1`原件仍可查历史，但没有两类快照，不能取得新的当前资格。

这是首次开放所需的初始资源输入，不是非空hold的完整资源快照、释放／恢复证明或OPEN许可。后续仍须接通实际非空运行保护／命令取消拒绝账本、资源及Ownership、参考时间提供者、GateAccess、OPEN／Ready和最终命令发送；当前内部入口没有HTTP／SDK映射。首次空快照分支不删减这些首期功能，也不将旧命令历史转换成无风险状态。

schema45增加核心内部`prepareInitialDeviceOpen`、`currentInitialDeviceOpen`与`lookupInitialDeviceOpen`。它从当前初始资源原件、实际控制原件和初始FENCE确认构造资源安全状态、闸安全状态、完整闸前态、资源前态、ordinary GateAccess及开放计划，与提交审计／通知意图原子封存。所有组成对象有独立身份和自摘要，引用实际原件；读取按历史来源重建整份内容再比较，不接受外部指定的安全状态或token。

schema46将当前模块通道升级为`device-module/3`，新增`BIND_EXECUTION`／`EXECUTION_BOUND`，旧帧和引用经备份迁移保留，新通道不回退到旧协议。核心内部`moduleClient.configureExecution(deviceId)`从同库当前目录、基线及执行Binding取得完整装配原件，经受监督模块管道送达固定Worker。Worker复核运行、设备会话、原件摘要、固定模块与政策字节、动作、编码计划、传输配置和出口后，组合编码缓存、Guard及一次传输writer。相同原件重投不重建出口；断开撤回旧会话的编码和写入资格，重连必须重新装配。

固定内存模块的Worker可宣告普通即时人工执行及无参考时间能力；schema47核心按固定模块资格选择这些能力，其他模块保留基础和首次控制屏障能力。Worker已接入编码、拒绝、清理、Guard、一次传输、观察报告和报告回执路由，模块等待不阻塞关闭接收；报告回执不清除屏障账本、不证明命令完成。原生装配、相同原件重投及重连新装配已验证；核心DISPATCH持久业务链、跨进程命令终态和真实设备尚未验收。

旧核心观察过期只使依赖它的当前资格失效，历史原件仍可读取；实际监督通道丢失继续关闭服务。首次开放计划已选定后，同一资源来源即使过期，也不能用新请求重新选取token。

首次计划对每个执行Binding及屏障唯一；同请求只查原，异内容冲突，新请求不能换token或延长期限。源基线变化、授权失效、重连、期限等号均阻止当前资格；历史计划不复活闸。`gate-open-plan/0.4.0-product.1`明确采用当前产品IPC的无参考时间正文。准备接口只保存计划，实际发送由核心执行通道单独处理。

schema47增加持久首次OPEN。核心内部`executionClient.initialOpen(openingRef)`核对当前计划、实际`EXECUTION_BOUND`和完整执行Binding，从持久正文生成共享序号的OPEN帧。唯一发送器实际写出前同步复核资格并可靠登记发送尝试，写入不确定即关闭会话，不重发。ACK必须关联实际请求及发送尝试，精确匹配token、闸修订、快照和GateAccess；ACK、领域提交与审计同事务封存，缺写回滚。当前来源改变或到期后，已有ACK也不能复活资格。

默认OPEN确认仅为`open_observed`，不会创建Ready或命令发送许可。初始资源复核只排除该计划自身已核验的OPEN帧，其他出站或已受理命令仍阻止初始资格。该首次开放路径不签发命令许可；后续schema52至54的命令占用及Guard链见下文，命令终态仍待接入。

schema48允许核心内部调用`executionClient.initialOpen(openingRef,{ready:true})`，将实际ACK与设备Ready在同一SQLite事务采用。Ready保存完整引用链、控制后继及闸后继，后继使用新物理ID和摘要；持有人、模式、控制epoch、有效版本与授权State不变。Ready或控制提交缺写会连同ACK回滚。已有ACK也可通过`initialReady(openingId)`单独采用，但必须重新通过当前资格检查；历史ACK或Ready均不延长窗口。

`currentReady(readyRef)`按提交后的控制头、完整OPEN／ACK原件、当前运行、人员与评估器身份、资源基线及期限核验。人员取证只可跨越经核实的精确Ready后继，保护修订和其他控制变更不能继承该资格。执行客户端持续复核已采用设备的Ready，失效即关闭；会话关闭将仍指向该Ready的控制头和授权状态原子改为保护态，保留稳定的控制权威。关闭原因及保护持久化失败分别记录，数据库故障不冒充保护写入成功。

当前Ready限定固定内存设备的首次空资源路径，不是命令许可。会话默认闸仍为关闭，`ready_devices`列出设备引用，使用时仍须调用当前性核验。schema52至54进一步接入固定内存设备的命令占用、逐命令授权、编码和Guard，发送后终态仍待接线；未完成的设备和部署环境不能宣称支持。

### 监督器取得当前物化证明

监督控制0.3增加`LAUNCH_MATERIALIZE`与`MATERIALIZATION_RESULT`；核心调用`prepareWorkerMaterialization(LaunchKey)`取得监督器持有的观察引用。请求绑定已登记完整意图及当前allow；固定观察请求ID重复查询不会新建challenge。registered及admitted_closed可取得当前物化观察；后者供采用复核，不恢复创建权。监督器后台查询Suite的INTAKE_QUERY及VERIFY_MATERIALIZATION，控制通道快速返回pending，核心在队列外等待后轮询；原500ms健康查询和两秒回执期限保持生效。等待中撤权立即拒绝后续结果，旧观察不能恢复allow。

可信父进程可通过`startProcessHost`的`installationPeer`配置安装端点。原生宿主截留`--installation-peer`，不转交核心；配置包含固定管道后缀、channel、安装宿主／权威／库、进程PID及创建时间、SID／会话／认证LUID和安装库观察域。该配置不来自HTTP或控制消息。原生保留进程句柄，在连接及I/O期间核对实际服务端PID与身份；连接失效后不重连。

监督器核收据完整Ref及摘要、宿主信任代、平台、目标、清单与制品集合，再自行产生challenge并核完整响应回显、固定观察域及本地截止。I/O总预算四秒；证明从challenge生成起最多五秒，返回寿命使用监督器本地域，远端observed_tick不充当本地年龄。CREATE只查本监督器持有的当前证明，并继续核新短授权和当前fence；调用者填写两个字符串不能取得创建资格。每实例最多4096个观察请求，同时只执行一个安装查询；超限拒绝，不自动淘汰或延长。

真实Windows联调覆盖Suite封存原件、SQLite、实际文件重验、双向认证管道、超过两秒的观察等待、错误收据／目标／观察域／challenge／进程创建时间、等待中撤销及超时。安装审批、平台批准与可信时间仍采用合成测试配置。当前物化证明已进入固定运行包的一次创建及核心运行绑定采用；人员启用与业务短授权已接通，受监督只读模块已接通，完整目录批准及设备出口仍待完成。

### 物化文件核验

`openMaterializedContent().pin(root, inventory)`提供Windows x64本机内容核验。调用者须是安装／启动可信代码，输入为已由权威确定的本地payload根及完整`extension-files/1`库存；它不是接受浏览器或worker任意路径的接口。包内路径沿C09的`portable-ascii/1`，文件ID严格排序且唯一；根路径可以使用Unicode。控制文档与payload分开保存，库存不包含`extension.json`或`files.json`。单文件256MiB、总量1GiB、最多65536个文件、路径240字符及每次最多5秒核验窗口沿既定开发预算；这些上限不是吞吐或实时性能承诺。

原生模块逐级持有目录句柄、拒绝reparse和硬链接，以卷GUID路径定位内容根；文件仅共享读取，核实际大小和SHA256，并拒绝未列文件／目录及文件或目录的附加数据流。句柄使用N-API类型标记，不能从JavaScript属性、原型或克隆重建。`verify()`重新核文件身份、库存与数据流，失败释放句柄并永久关闭该对象；`close()`可重复调用。首次核验沿用同一起点，遍历阶段不刷新窗口，晚于截止的结果不成功返回。同步文件操作不能承诺在操作系统阻塞期间立即中止，须放入独立安装工作进程，不能直接占用核心控制循环。（平台依据：[CreateFileW共享语义](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)、[卷GUID路径](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew)、[文件流](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams)。）

目录句柄不阻止新增目录项或数据流，核验也不设置或证明目录ACL。受保护根、加载器的依赖闭包、当前发行信任、installation.db封存记录及原件查询仍须由Suite安装宿主与启动器接通；不能把该对象、rootIdentity或一次摘要相符当作物化凭据或启动批准。当前没有对外生成MaterializationResult，也未据此开放CREATE。6项真实Windows文件测试覆盖跨进程写入／替换拒绝、祖先重命名、内容错配、库存变化后失效、链接／数据流、路径／容量及伪造令牌。Linux、掉电耐久与完整可信安装／加载链尚未验证。

### 实例锁与启动记录

`init-process-host` 只安装当前本机开发身份的 `supervisor-journal.db`，目录须已存在，文件已存在就拒绝覆盖；也可由可信本机装配调用 `initializeProcessHost(dataDir)`。普通 `supervise` 不初始化或补建日志。安装没有创建人员权限、生产宿主批准或已认证运行域。已有开发目录需显式安装该日志后再使用 `supervise`，原 `start` 仍是无设备出口的保护态诊断入口。

原生宿主按已打开目录的卷标识和128位文件ID取得 `Global` 命名互斥锁，显式DACL只允许当前账户和LocalSystem，句柄不继承。目录大小写／junction别名归并至同一实际目录，核心使用从目录句柄解析的路径。重复实例、无法取锁及abandoned均拒绝创建；本轮已验证同会话并发与junction，未验证另一交互会话、服务账户切换或真实abandoned恢复。（接口依据：[Microsoft CreateMutexW](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createmutexw)、[文件身份](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfileinformationbyhandleex)。）

原生启动记录静态链接与业务驱动同源的SQLite 3.53.4，`native-inputs.json`额外锁定既有better-sqlite3包中的sqlite3.c／sqlite3.h；不在运行时下载或调用外部sqlite工具。日志单writer、DELETE／EXTRA，开启外键与递归触发器并回读设置；普通启动检查版本、完整DDL、完整性、外键、原安装目录身份和账户，不在线修复。四张初期表保存安装身份、核心创建尝试、实际进程观察及已确认退出，尚未填充完整DF02的runtime、fence、bootstrap和AdmissionReceipt。（SQLite配置依据：[官方PRAGMA](https://www.sqlite.org/pragma.html)。）

顺序为：取得实例锁→验证日志→提交创建尝试→调用一次OS创建→持久保存实际PID、进程创建时间和映像文件身份→恢复核心。确认空组及核心退出后，提交退出原件再交付成功帧。创建失败、日志提交未知或宿主强停留下未结束尝试，随后返回`process_recovery_required`；即使PID已不存在也不自动清除。当前没有清锁、删记录、恢复重试或覆盖日志的工具；这些情况保留停机状态，等待完整旧域恢复实现。不得删除日志后初始化来绕过恢复。

记录只增，保留最多4096次核心尝试，文件限制16MiB，达到容量停止新建，不删除历史腾空间。目录复制不能继承原宿主身份。该日志既不读取业务SQLite，也不判断设备效果、资源释放或授权状态；原生OS观察与完整运行准入继续分开。真实掉电耐久、存储介质故障、跨用户ACL和旧域恢复仍需各自验收。

## 同源 GUI 静态装配

可信本地 `startController` 工厂可传入 `guiDirectory`，指向已构建 LeafSeamer GUI 的绝对目录；同时必须提供原有 TLS 配置。站点必须固定当前业务库的 service／database 身份和相同 SDK 合同／清单摘要。启动时检查资源路径、大小、摘要及站点字段，固定总量至多32 MiB的资源字节后服务；原目录内容变化不会改写正在运行的站点。

仅提供明确清单内的 HTML、JS、CSS、站点配置与许可文件，根路径对应首页；不回退任意路径、不覆盖身份及健康接口。响应设置严格同源 CSP、禁止框架嵌入和 referrer；核对精确 Host／Origin，保留 no-store／nosniff。身份权限、Cookie／CSRF和认证资格仍由原有处理器执行，健康就绪继续503。

已通过真实 Edge 的 GUI 登录、设备与控制读取、显式续期、退出、权限不足及资格失效检查；使用真实 SQLite／原生采样器，环境批准及账户／设备为合成测试输入。`test/gui-browser-fixture.mjs` 仅用于隔离验收，不能作为生产认证提供者。完整运行域、Seamer、自动化、设备写入和安装组合仍未交付。

## 首次管理员与数据库升级

新建库初始为 schema 1；启动不会自动升级。需要首次管理员存储时，停止本库服务并显式执行：

```sh
node --disallow-code-generation-from-strings dist/cli.mjs migrate-storage --data-dir /absolute/controller-data
```

此操作逐步升级至 schema 49。每一步先通过 SQLite backup 生成同目录的独立旧版文件及 SHA-256，再同事务升级、保留服务 scope、启动历史和已有身份回执、登记迁移摘要和备份引用。成功响应 `steps` 列出本次各步，顶层备份字段指最后一步；已为 v49 时返回 `changed:false`。正在运行、未知版本或不完整迁移拒绝。每一步 DDL 失败只回滚该步；例如 v1→v2 已提交而 v2→v3 失败时保留 v2，不自动降级。旧 v1—v48 库仍可使用对应版本的保护态功能，不自动升级；worker启动准备要求v12，候选安装原件要求v13，配置原件要求v14，角色解析原件要求v15，权限审阅原件要求v16，人员批准与永久撤销要求v17，静态能力批准证据要求v18，核心worker运行绑定要求v19，固定虚拟设备资源与启动依赖封存要求v20，正式安装依赖计划要求v21，人员启用受理与资源占用要求v22，业务启动短授权与fence要求v23，模块通道要求v24，只读目录批准与基线样本要求v25，人员控制请求与退出屏障要求v26，执行会话要求v27，共享帧日志要求v28，执行装配要求v29，真实握手要求v30，初始控制屏障要求v31，完整控制物理原件要求v32，人员执行取证来源要求v33，设备授权保护状态要求v34，当前核心运行来源要求v35，服务身份首次登记链要求v36，本机定向服务令牌要求v37，内部评估器取证要求v38，服务主体整体撤销要求v39，人员设备恢复请求受理要求v40，恢复授权一次消费和策略选择要求v41，人员执行挑战与响应要求v42，本机普通手动授权Evidence要求v43，固定内存初始资源来源要求v44，首次开放前态与计划要求v45，v3模块通道与固定Worker装配要求v46，首次持久OPEN和ACK要求v47，设备Ready原子后继和关闭保护要求v48，即时模拟器命令持久受理和公开初始记录要求v49。备份不能作为另一个活动实例直接使用，正式恢复仍需换 scope 和完整恢复流程。活动库与备份目录的安装 ACL、备份恢复和掉电耐久尚待平台验收。

`enroll-admin --data-dir <绝对目录>` 是供本机安装管理客户端使用的子进程入口。Windows 要求实际提升权限的管理员，首期系统工具固定标准 Windows 安装位置；Linux 要求有效 UID 0。没有在线角色、环境开关或命令参数可替代该检查。当前账户非管理员时，在打开业务库或发出能力前拒绝。父客户端必须用受控继承管道连接 stdin/stdout，终端和文件重定向拒绝；尚未提供交互安装向导。

管道协议为：子进程首先只交付一次 `initialization_capability`，含 `token_id`、32随机字节的规范base64url `secret` 和600秒上限；父客户端通过 stdin 提交一个 UTF-8 JSON 对象后关闭输入，字段精确为 `token_id,secret,login,password,mode`。总输入至多64 KiB，mode为 `standalone` 或 `suite_issuer`。登录名保留精确大小写与字符，不trim或规范化，长度1—128个Unicode标量且不含控制字符；密码长度16—4096个Unicode标量，不接受非法代理项。秘密和密码不放 argv、环境变量、普通日志或磁盘中间文件；父客户端也须遵守一次交付边界。

能力只在本次持库进程和单调10分钟窗口内可消费，密码计算完成后再次核验，截止等号拒绝；关闭或重开使未消费能力失效。首次管理员、human主体映射、本地管理员授权、issuer身份、能力消费与非秘密回执在同一事务提交，最多一次。初始化完成仍保持服务 `protected`，不发会话、token或设备权限；这不是公开 `/auth/bootstrap` 的网络实现。响应丢失可由 OS 管理员执行 `identity-status --data-dir <绝对目录>` 查原，返回非秘密身份与事务引用，不重新初始化或取回秘密。

密码采用 `identity-runtime/1`：Argon2id v19，65536 KiB、3轮、并行度1，独立16字节盐和32字节结果。仅执行登记成本的PHC；驱动0.45.1的参数顺序固定为 `m,p,t`。密码工作全进程同时2项、等待8项，超额报 `password_busy`，不占数据库事务等待计算。高熵opaque验证值按六种具名用途分域，不能代替人员密码。上述数值沿Suite既定profile；实现调用[官方node-argon2](https://github.com/ranisalt/node-argon2/tree/v0.45.1)，不自行实现密码算法。

## 原生时钟诊断

schema 3 服务每500毫秒调用原生采集器。Windows 顺序为 `QueryInterruptTimePrecise → GetSystemTimePreciseAsFileTime → QueryInterruptTimePrecise`，FILETIME 用整数减纪元再转纳秒；Linux 实现使用 `CLOCK_BOOTTIME → CLOCK_REALTIME → CLOCK_BOOTTIME` 并检查时间命名空间。没有 `Date.now()` 或浮点秒替代路径。原生接口依据：[Microsoft 单调时间](https://learn.microsoft.com/en-us/windows/win32/api/realtimeapiset/nf-realtimeapiset-queryinterrupttimeprecise)、[精确系统时间](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemtimepreciseasfiletime)、[Linux clock_gettime](https://www.man7.org/linux/man-pages/man2/clock_gettime.2.html)。

采集括号超过20毫秒、两秒有效期到达等号、时间倒退、连续性变化或采集／存储失败均锁存故障，本 boot 新采样不能解除。Windows 注册电源通知以记录连续性变化；Linux 连续性监测仍未完成。每 boot 保存最新诊断与首故障，记录原生制品摘要；每32次诊断写入执行并核验 PASSIVE checkpoint。它只是当前保护态诊断的有限写入处理，不是完整业务 WAL 容量调度或不可变 AuthenticationClockAcquisition 日志。

当前服务采样仍不具备认证资格：尚未装载获批准的环境误差、量化与速率界、宿主授时健康来源及 DF02 运行域。schema 4 已实现下述可信区间和原件 writer，但服务未装配可信提供者，继续 `protected`，没有登录、会话或设备写入授权。重启只建立新 boot 的诊断，不能恢复或获得认证资格。

## 认证时钟内部服务

`auth-clock.mjs`、`auth-clock-value.mjs` 与 `auth-clock-store.mjs` 实现 DF06 §13 的服务级采集、区间计算与文件库事务。它们是本地服务内部接口，尚未作为 SDK 公开契约发布。所有纳秒运算使用有界 BigInt，固定向外舍入；政策完整绑定 service、运行 profile、原生制品、宿主来源、环境批准及健康 profile。原件摘要使用锁定的 [canonicalize 5.1.0](https://github.com/erdtman/canonicalize/tree/v5.1.0) JCS 与 SHA-256，原始平台采样重新归一化后才参加计算。

受监督提供者的 `read()` 必须返回已从可信安装／运行时来源解析并验证的 `policy`、`runtime`、`health` 原件；原件自带摘要只能证明一致性，不能自证来源可信。提供者负责环境批准、profile、制品和健康／有限holdover引用的真实性及持续有效性。库逐项核对其摘要、scope、policy、运行域与有效期，采集前后和提交前重新读取；不得将HTTP输入、模块输出或普通配置文件直接适配成此提供者。当前没有生产提供者；`startController` 仅提供可信本地工厂装配点，没有CLI／HTTP／环境变量参数绕过它。

每次采集同事务写入政策／运行／健康依赖、不可变 AuthenticationClockAcquisition 与域当前指针。同 ID 同内容只返回原引用，不刷新时间；换内容、区间不相交、连续性丢失和过期使域保护。后续有效区间保留此前预测上下界，不能借新采样收窄旧上界。每次 `current()` 重新核健康、运行域、真实读数和采样期限，返回期限取采样／运行／健康的交集；该返回值不允许被缓存成长期授权。数据库写入／提交失败立即停止本实例提供时间；故障事实也写失败时明确 `durable:false`，不报告安全关闭已完成。

schema 4 的四表分别保存依赖原件、采集原件、当前指针及首故障；故障不可删除或更新。当前 writer 尚待接入完整 DF04 容量／保留调度、DF02 启停与域退役、实际环境／健康提供者以及身份请求事务；没有实际设备出口，因此没有生成 Controller 出口 Binding、关闭计划或宣称物理终止。测试中的合成提供者只用于隔离验收，不允许出现在安装配置中。

## 人员会话内部服务

schema 5 的 `storage.sessions(clock)` 将同库人员会话服务绑定到唯一认证时钟实例，提供 `login/current/refresh/logout`。内部接口本身不是公开契约；下述 HTTPS 路径通过固定产品 SDK 投影公开 Session 和注销结果，完整身份接受集及受控代理仍待实施。没有环境资格时无法登录，不用诊断时间代替认证时钟。服务主体不能通过这条人员密码路径取得身份。

登录使用真实 Argon2id，未知账户也计算同成本的虚拟密码摘要；异步计算期间不持写锁，提交前重读人员状态、修订和密码。每账户最多5次失败／分钟、全入口60次失败／分钟，计算中的尝试预留额度；未认证账户桶最多4096个，达到总界统一节流。该限速当前仅为进程内防护，不是跨重启持久封禁。撤销独立于登录失败预算。人员会话绝对8小时、刷新空闲30分钟、近期认证5分钟；刷新不延长绝对期限或近期认证期限。

刷新秘密使用既定 `session_refresh` 用途的32随机字节，仅保存验证值。CSRF随机值也仅保存独立分域摘要，比较固定长度值；原文仅本次内存交付，普通查询不返回。刷新同事务消费旧凭据并创建仍归原session的新凭据；已消费凭据被再次正确证明时保存复用异常并撤销该session后代。并发刷新由SDK会话客户端拒绝重复进入，响应丢失不能从数据库取回秘密。每次会话读取、刷新、退出及密码计算后的提交都复核当前认证区间；期限等号拒绝并持久保存终态，较早时间不能复活它。

退出同事务关闭会话、保存session拒绝下界、冻结audience与执行／订阅关联目标的并集、写操作原件和逐目标outbox；签发方自身始终在目标中，关闭后禁止追加audience。当前没有传播消费者或目标屏障receipt，全部目标保持 `pending`，结果只表示本地已撤销。它不释放设备持有人，不撤独立组织授权，不代表远端效果已停止。存储故障回滚时不交付成功结果，并停止该会话服务实例，不能继续沿用旧会话缓存。

`npm test` 使用真实文件库、密码库、SDK HTTP客户端、自建子进程与本机构建的原生模块；会话成功路径在真实认证原件服务上使用合成受监督上下文，长时到期用例另用合成认证区间，均不能替代生产环境资格。会话检查覆盖秘密不落库、刷新复用、CSRF拒绝、注销目标并集、登录限速及事务写点故障。Linux、真实休眠／掉电、生产认证时钟资格、提升权限后的管理员CLI全链、真实浏览器、生产TLS与网络认证、跨服务定向token对端、撤销传播、部署和设备均未验收；本机HTTPS集成范围见下文。源码与运行构建在本仓，测试数据和依赖不提交。

## 人员定向访问令牌

schema 6 的会话服务增加内部 `issueToken(sessionInput, request)` 与 `verifyToken(tokenInput, audience)`。同一storage在装配 `sessions(clock, authority)` 时固定当前授权提供者，不能在运行中换成另一来源；缺提供者直接拒绝。schema 7默认装配本地持久权限提供者；更早schema及显式null仍无提供者。公开token路由仅在下述可信本地装配下支持本Controller audience。`authority.resolve()` 必须从当前本地权限、对象范围和实际配对来源同步解析不可变授权原件；调用在writer内，不能执行网络等待。它须稳定绑定issuer三元组、session／credential、主体／会话／策略修订、单audience、权限交集、对象范围摘要及有限期限。摘要仅校验原件一致性，不能使HTTP自报权限或配对变可信。

签发使用 `access_token` 分域的32随机字节，验证值、完整父链、请求身份和session audience同事务写入。每父credential最多8个活跃token，最长60秒，并取会话绝对／空闲及当前授权更早截止；容量不足不产生部分记录。相同credential／request_id及内容只返回非秘密原结果，重复响应的 `secret:null` 不是新签发；不同内容拒绝。秘密只在首次内存响应交付，不写DB或幂等记录。

验证的audience必须从实际已认证的目标服务／mTLS对端导出，不能来自公开body；当前HTTP读取路径使用本Controller固定身份；跨服务mTLS对端边界尚未实现。每次验证重新检查认证时间、会话、原父credential、主体与当前授权原件，并在释放结果前重核。普通刷新消费旧刷新凭据不使其已发短token脱离session；退出、复用异常或会话到期则同事务撤销全体活跃token。token到期或观察到新的有效授权版本后保存终态，较早时间或旧授权不能恢复。退出先提交后不能再签发或新增audience，先签发后退出必须捕获该目标。

新增七项文件库检查覆盖单audience、幂等秘密边界、容量、刷新父链、注销两种排序、到期／授权版本变化及token／audience写点回滚。其中合成授权夹具用于内部故障边界；当前公开路径采用下述真实持久权限。配对mTLS、完整公开身份接口、远端撤销与设备出口继续实施，不能据内部active结果宣称设备授权已完成。

## 身份 HTTP 接收边界

当前 `/auth/sessions`、`/auth/sessions/refresh`、`/auth/service-tokens`、`/api/v1/session` 、`DELETE /auth/sessions/current` 和 `POST /api/v1/request-contexts` 已使用SDK的 `product1` 服务端校验器。默认CLI和缺少TLS装配时，完整合法请求返回结构化 `503 WORKER_NOT_READY` 和 `do_not_retry`；本地可信装配支持下述成功路径。SDK读取相同service／boot身份与契约选择。就绪及发现入口仍为503。当前全系统身份接受集仍待归并，不能据这些路径宣称完整首期契约已启用。

原始头保留至信封校验，重复敏感头、错选择及不支持的编码拒绝；正文严格UTF-8／JSON／Schema校验，拒绝重复键和未知写字段。正文上限16 KiB，同时接收最多16项，接收期限为绝对2秒；分块累计、声明超限、断连和超时均释放容量。选择前失败不回显任意契约；选择后业务错误在发送前再校验。异常响应不包含密码、Cookie或原始报文。健康接口不占身份正文接收额度。

构建从开发依赖 SDK 的产物读入清单，按 [sdk-runtime.json](sdk-runtime.json) 固定清单、选择及许可摘要，再逐文件核验；复制运行文件和许可到 Controller 包内。独立安装不需要SDK邻仓或开发依赖，旧SQLite迁移原件不变。接收边界测试包含实际SDK／HTTP收发、严格拒绝、两类正文超限、慢请求、并发容量与断连回收。

完整身份接受集、生产可信运行来源、受控代理及跨服务对端认证仍待实施；不能将回环测试视为浏览器、生产部署或设备验收。

## 本地持久权限

schema 7将本地权限版本、当前选择、管理操作、固定传播目标和outbox纳入同库writer。首次管理员初始化与初始权限同事务；已有v6管理员在显式迁移时从已保存的administrator角色建立权限，普通查询或登录不自动补建。初始明确授予 `auth.manage`、`auth.read`、`identity.read`、`request.create`、`session.read`、`status.read` 六项本地身份管理／读取权限；当前目录另支持显式授予 `control.read`、`device.read`、`extension.read`。这些权限不自动产生设备控制权、内部配对权或远端服务权限。完整业务权限目录、对象级范围和其它人员角色仍按既定首期范围实施。

`storage.sessions(clock)` 默认使用当前同库权限版本签发及复核token；请求范围必须全部获准，audience必须为本Controller。当前父session、credential、issuer三元组和主体状态重新从库读取，授权原件有限期限取父会话绝对边界，token另取空闲与60秒更早截止。权限来源已是实际持久数据；环境资格尚未落实，时钟成功测试仍明确使用合成提供者。

内部 `localPermissions(sessionInput)` 读取本人当前权限；`replaceLocalPermissions(sessionInput, request)` 核当前auth.manage、CSRF及5分钟近期认证，request包含request_id、principal_id、expected_revision和完整permissions。修订采用精确uint64字符串，写新不可变版本并CAS推进当前选择。每次变更同事务终止该主体已有活跃token、保存操作和全部session audience／执行／订阅关联目标；相同凭据／请求及内容查原，不再递增，异内容拒绝。变更不关闭人员会话，不释放设备holder，也不撤独立服务运行。

纯增收允许按新版本重新取token；减收或混合变更将新权限版本保持pending，阻止重新签发。所有传播目标目前均pending，尚无远端屏障／receipt消费者或减收完成激活入口，不声称applied，也不自动回退旧授权。管理响应丢失后须按现有权限核对，已失管理资格的旧会话不能借幂等请求绕过权限。权限写失败回滚版本、当前选择、token撤销、操作与outbox并停止失败的会话服务实例。

本地权限七项检查覆盖默认持久授权、身份与授权初始化原子性、精确版本／幂等、增收、减收、目标并集、近期认证、v6迁移和逐写点回滚。公开权限管理接口、完整身份接受集、可信运行环境及跨服务配对仍待接通。

## HTTPS 人员身份接线

`startController({dataDir, port, tls: {key, cert, origin}, authenticationProvider})` 是供可信本地监督代码使用的装配入口，仍只监听回环地址。`origin` 必须为精确 HTTPS origin，TLS固定1.2或1.3，密钥及证书由调用方安全供应。提供者工厂接收冻结的 `{scope, source}`，其中source始终为实际原生采样器；必须返回前述可信原件提供者。该工厂不是部署配置或远程插件入口，测试构造不能替代生产批准。普通CLI保持保护态；TLS证书本身不授认证资格。

product1继承四个原有身份路径，支持登录201、刷新200、token签发201和会话读取200，并增加签发方注销202。公开Session来自当前文件库权限及有效会话，响应经SDK完整校验后、发送秘密前再次核当前权限和认证时钟。时间下界向上、上界向下换算为毫秒。Host必须精确匹配配置，写操作Origin必须精确匹配；读取若携Origin也须一致，cross-site请求拒绝。成功路径要求真实TLSSocket，不采信代理自报头。

刷新Cookie使用 `leafseamer_session`，固定 `Path=/auth; Secure; HttpOnly; SameSite=Strict`，不设Domain。Cookie中的凭据和X-CSRF-Token需同时有效；重复目标Cookie拒绝。刷新只交付一次新秘密，正确复用已消费的旧凭据撤销该session全部token。GET会话只接受Bearer，并核本服务audience及session.read；Cookie不能代替它。当前不签扩展委托token。`expires_in` 为签发期限向下取整的秒数提示，服务器始终按原绝对截止重核，响应耗时不续期。当前沿用的签发请求没有客户端request_id，网络调用不自动重试；不能把内部幂等接口宣称为HTTP查原已完成。

SDK的 `createBrowserSessionClient` 管理内存CSRF与token，浏览器保管HttpOnly Cookie，拒绝并发刷新、错误选择及非法CSRF。清本地内存后到达的旧响应不能重新安装凭据；清内存不等于服务端注销。当前注销已进入新product1选择；主体与权限管理接口仍须归并，不向旧panel4偷加路径。

当前身份与命令账本检查通过。十项HTTPS集成实际加载Windows原生模块，使用正常证书校验的本机HTTPS、真实密码库和文件权限库；验证SDK往返、Origin／Host／Cookie／CSRF、刷新复用、来源失效及迟到响应。证书仅在测试内存中临时生成，Cookie容器为测试模拟，环境批准引用与误差界仍为合成。独立安装包另验证相同HTTPS成功路径；真实浏览器、Linux、生产提供者、可信代理、完整跨服务鉴权、部署和设备未验收，业务就绪仍为503。

## 当前会话注销

SDK `logout()` 调用 `DELETE /auth/sessions/current`，只使用当前Cookie、CSRF和精确Origin，不接受目标body，不要求auth.manage或近期认证。既有会话writer同事务撤销当前session及其token、保存拒绝floor、固定audience与执行／订阅目标并写outbox；响应校验后再次核已提交事实和认证时钟才发送202。Cookie随202清除，操作结果不证明远端撤销已应用，不影响独立组织授权或设备holder。

202的operation_ref来自本服务／数据库及不可变操作身份；RevocationRecord的issuer_commit_revision取该session持久撤销floor，audit_id取同一持久事务身份。目标完整保留，receipts当前为空、state为accepted，未实现的传播消费者不会被冒充为applied。旧Cookie重试401并清Cookie，不借已撤凭据查询历史；响应丢失或503不自动重发，SDK清本地内存并保留错误。完整授权查询、传播确认及审计接口继续实施。

最终独立包另验证注销后旧Cookie／token失效、拒绝body目标、数据库中的操作／floor／outbox与响应一致以及来源失信不伪报202。仍使用合成环境批准和模拟Cookie容器，真实浏览器、生产运行环境及远端屏障未验收。

## 持久请求上下文

schema 8增加 `request_context` 原件与关闭状态；显式迁移逐版备份，启动不自动升级。`POST /api/v1/request-contexts` 接受Bearer及精确Origin，使用已有product1请求／结果模型；SDK会话客户端提供 `createRequestContext({audience, operations, ttl_ms, max_unique_requests})` 并自动带入固定选择。服务当前只签发本Controller人员token的上下文，请求须有request.create以及每个目标操作的权限；任一操作未知、用途不符或越权时整项拒绝，不静默缩窄操作集合。

签发与当前token重核在同一writer中完成，绑定服务／数据库、issuer三元组、当前boot和request_epoch、实际session／credential／token及授权／范围摘要。上下文最长60秒，截止同时不超过token；公开毫秒边界向内舍入。开发预算为每上下文至多256个新请求、同主体每60秒至多64次签发、全库至多4096条保留记录，满额拒绝且不自动删历史。这些数值不是经过生产负载验证的容量profile。

内部 `getRequestContext(tokenInput, contextId, operation?)` 每次重核当前凭据及完整操作权限；期限等号关闭且保存终态，较早时间不能复活。token撤销／到期和session关闭同步关闭其活跃上下文；普通重启保留原件及request_epoch，但关闭旧上下文。响应经完整SDK校验后，用规范化内容比较再次确认当前绑定，字段排列不影响结果。

上下文已接入人员控制请求及schema49即时模拟器命令的唯一新请求消费；同键查原不再次扣费，used_count包含控制和命令请求，不能解释为已执行动作数。完整RequestKey的持久查原／冲突／拒收见下节，context_id不进入去重键。上下文本身不授设备持有权、RunGrant或发送资格，不自动重试网络请求。

五项文件库用例验证凭据与权限绑定、期限及容量缩限、到期终态、注销、普通重启、签发预算、写故障回滚和v7升级；HTTPS用例另验证SDK签发、缺权限拒绝和注销后的持久关闭。成功测试仍使用合成环境批准，Cookie容器为模拟；生产提供者、真实浏览器、完整跨服务生命周期及设备验收未完成，业务就绪仍为503。

## 命令请求查原与永久拒收

schema 9采用[请求裁决布局](https://github.com/LeafSeamer/leafseamer-suite/blob/main/docs/contracts/c02-admission/STORAGE.md)的同库唯一键、不可变裁决、拒收操作、提交、审计及通知约束。显式迁移保留旧上下文及身份，升级过程中在同一事务重建依赖服务身份表的触发器；旧迁移原件保持不变。连接启用并核验recursive_triggers，禁止通过REPLACE删除墓碑。

`POST /api/v1/commands/lookup`、`POST /api/v1/commands/reject` 和 `POST /api/v1/commands` 已接入现有HTTPS接收边界。前两者分别要求明确授予的command.read和command.cancel，范围仅限当前人员在本库可验证的自身请求命名空间；初始管理员权限不自动增加这两项。它们不授设备控制权、不取消已执行动作，也不支持服务主体或面板委托。原namespace归属来自本库保存的签发上下文及完整issuer三元组，不接受客户端自报归属；当前token和权限仍须有效，旧context到期或普通重启本身不阻止当前有权人员查询／收紧拒收。

完整RequestKey包含目标服务／数据库、issuer／epoch／principal、request_epoch、固定createCommand和idempotency_key；context_id、request_digest不进入唯一键。CommandContent摘要只排除顶层context_id、idempotency_key、correlation_id，嵌套同名业务字段保留。相同key同摘要查原，异摘要409；拒收操作另按当前actor及rejection_operation_id幂等，换目标或内容也409。

首次拒收同writer保存原内容、不可变rejected裁决、真实commit_ref、拒收操作及审计／通知，任一写点失败全部回滚；成功返回200，command_ref为null。相同拒收操作不追加记录，新拒收操作指向已有裁决时保留原裁决并单独留痕。查原确定不存在返回not_found，存储未知返回503，均不等于永久拒收证明。通知只保存观察事实，尚无传播消费者，不能发送设备动作。开发保留预算为4096个请求键、8192个拒收操作，满额拒绝且不删历史；该预算不是生产测量profile。

submitCommand对已有键先按当前command.read查询原裁决，旧context到期或更换当前读取令牌不改变已提交结果。新键要求显式授予的device.command、该令牌签发的当前submitCommand上下文、未耗尽的请求预算、精确控制版本、无未决接管，以及当前人员作为manual持有人；管理员初始权限不自动包含device.command。检查同库当前监督观察、审批依赖、已握手执行会话和已批准目录／设备连接／装配，断开或重连不能使用旧出口。运行检查在受理writer内完成，来源失效先撤下本地资格，外层回滚后仍独立保存运行撤回。

新键还在同一writer内核验该设备当前控制头对应的持久Ready、完整授权／资源来源和实际期限。会话默认闸保持closed，客户端Ready列表也不能代替设备资格；开闸前的身份取证只读取执行绑定，不反向依赖Ready。schema49允许固定内存模拟器的人员即时命令持久受理：原始命令、accepted裁决、完成／释放政策、实际单调域与受理tick、原排队截止、容量预留、排队claim、上下文扣费、初始公开记录及审计／通知同事务保存。末次当前性检查失败、漏写或异常均回滚，不产生永久拒收证明。首次成功返回202，同键同内容返回200及原裁决，异内容409。

`GET /api/v1/commands/{command_id}`要求当前人员command.read及原命名空间归属，返回静态SDK严格校验的完整当前记录。缺少应用参考时间时`accepted_at`明确为null，不用认证时钟或机器墙钟补填；定时命令拒绝。受理初始记录为`queued/pending/not_sent/clear`、空attempt和空证据，不把受理视为已发送。排队claim不占用设备hold；初始资源当前性只能采用同Ready且无attempt的完整受理后继，任何其他历史或出站帧仍拒绝。

开发限额为4096个保留请求键、4096条命令、每设备8条排队claim，每命令至多一次attempt及8字节编码预算；这些固定限额尚未经过生产容量测量。资格到期后仍可凭当前读取权限查询命令及原受理裁决；新命令拒绝。schema55已接入固定内存首次命令的发送后终态；后续恢复和重复运行资格仍未完成，业务就绪继续503。

schema50增加独立后台队列维护，每次处理至多16条，GET不写状态。原排队截止到达时保存`finished/expired`；Ready到期或执行会话已有持久关闭记录时保存`finished/blocked`。这两类终态仅适用于无attempt、无hold、无Ownership且实际出站日志只有握手、初始FENCE和OPEN的排队命令；它们保持`not_sent/clear`并锁存自动化暂停，不能复活或改写结论。完成后释放排队计数，原请求键、受理裁决、原始元数据和历史初始修订仍保留。

新修订、领域提交、审计／通知及唯一当前指针同事务保存。当前指针每次读取，读者核验完整原件与关闭来源，不以最大修订或缓存头代替；任一漏写全部回滚并锁存投影不可用。关闭依据使用实际同域监督tick或已持久的执行会话结束，不将墙钟、失联或编码结果当作设备释放证明。HTTP响应末核发现修订变化时返回`unavailable`及`retry_action: read_current`，调用方可重新查询，不能据此重提交动作。

schema51将受理后的普通人工命令接入真实编码通道。核心从已封存命令读取原凭据，重新核验人员、用途权限、当前控制权、同Ready和执行绑定；认证窗口映射到实际监督单调域，并取原排队截止、Ready、核心运行和凭据期限中的最早截止。编码授权、身份快照、8字节准备预留、原ENCODE帧及领域提交可靠保存后，才由同一Worker的有序出口发送。跨IPC等待不持有数据库事务；同请求查原不重新编码，未知准备不补投，重启不自动续投。

真实`PREPARE_PACKET`／`PACKET_ENCODING_FAILED`响应按原消息、授权Ref、出口和会话关联；成功字节另核SHA-256、长度、固定编码布局与原参数，保存原报文、原字节和编码证据。接收前重核当前来源，过期结果只可留历史；响应缺写则整个接收事务回滚。编码只使用独立准备容量，不创建设备hold、Guard、issue或发送许可。初始资源检查只允许具有精确准备账本的编码帧作为无设备I/O后继，仍拒绝派发帧。

当前准备容量为固定开发上限256条、每条8字节；成功、失败和到期均不退款。

schema52在真实编码成功后自动执行首次普通命令的T2。唯一writer重新核验编码响应、可靠IPC写入结果、实际人员授权原件、当前控制权、Ready和原截止，再同事务保存设备hold、不可变Ownership、逐传输issue与独立扣费、Guard和TransmissionPermit正文、前后态资源投影、18项来源封存、固定attempt库存及公开第2修订。Guard与派发正文通过当前SDK校验，主体／会话／策略修订来自原授权，不由客户端填写。封存和写后末核均使用原监督单调域；任何漏写整笔回滚，原受理裁决不变。开发传输预算上限4096次、每次8字节，不随超时或故障退款。

T2可靠提交后，用独立短事务记录本机核心的committed观察；观察保存失败时关闭会话，已提交的占用、扣费和公开修订保留。该观察只允许后续重新核验资格，不能重发历史许可。GET从固定原件重建attempt，prepared状态为queued/pending/not_sent/held，发送时间为null，尚无报告或完成证据；同RequestKey查原不增加issue或扣费。

schema53将自动队列推进至Guard安装。T2之后按精确封存Ref、唯一设备hold、公开prepared头、实际人员令牌、控制权、执行绑定、基线及原单调窗口重新核验当前资格；后态资源保留真实占用，不将它解释为空资源。Ready后台检查随该命令转入提交后路径，基线变化或资格到期关闭会话。

GUARD_INSTALL请求、共享FrameRecord、领域桥接及EffectCommit同事务保存；实际管道写入前提交唯一WriteAttempt并再次核验当前来源。GUARD_ACK核完整原请求、Guard／permit／content摘要、授权修订、GateAccess及Ownership，只有原窗口内且来源仍有效的响应可标installed，其余只保存historical。返回查询投影不暴露内部字节缓冲区；相同命令查原，不重复预约或安装；历史查询的qualification为null，不能据原ACK恢复资格。Guard自身不写设备，也不能绕过DISPATCH的后续末核。

受理后的后台队列从下一事件轮开始，先让受理响应完成本轮微任务。HTTP仅对本地生成且受SDK预算限制的响应使用微任务分片校验，避免同步writer占用解析器让出的定时器片导致503；外部请求仍使用默认分片，所有解析预算、真实截止和发送前复核保留。本机错误观察回调只接收操作与错误分类，不含凭据、正文或异常全文。

schema54将自动队列接通DISPATCH。原T2、installed Guard和实际编码共同构造不可变派发正文，提交前与实际管道写入前重新核验当前资格。发送器先同事务保存唯一WriteAttempt、派发预约及公开第3修订，再交给管道；此时为dispatching/pending/possible/held，不能继续标not_sent。

SEND_REPORT与共享帧、领域桥接、EffectCommit及公开第4修订同事务保存；状态为awaiting_evidence/pending/possible/held。观察候选逐项关联原报告、许可、attempt、packet、执行会话、字节数和单调时序，候选本身不裁决成功或释放。无可信参考时间仍返回null发送时间，历史prepared StateRef保持不变；历史查询返回qualification=null，不重发或续期。

本机实际监督器、SQLite和HTTPS已验证一次固定内存写入、目标值及write_sequence=1、重复请求不增加写入，以及十个写集遗漏点的原子回滚。派发后读取仍核验前序prepared修订和完整原件。同一同步writer内复用不可变原件，任意写入即失效；当前头、授权与时钟不缓存。客户端删除了与journal重复的运行遍历，运行监视和实际写入前重核仍保留。正例在创建新授权来源前采集真实认证时钟，未改变已受理命令的原截止；此前窗口到期的失败保留为失败关闭证据，尚无生产延迟承诺。

schema55在发送报告及观察候选后撤下设备Ready，把控制状态持久保护，再通过同一实际出口发送覆盖全部已签发传输的非空FENCE。原请求、完整覆盖ACK、共享帧、效果提交和唯一写尝试相互关联；历史确认不授予新的写资格，FENCE本身不证明模块执行完成。

固定内存完成政策同时核验原报告、实际模块观察、8字节写入、目标值、基线写序号的严格后继及原证据截止。完整关闭和及时完成证据成立时，将DecisionEvidence、ReleaseEvidence、独立hold释放原件、证据快照和公开第5修订原子保存为finished/succeeded/verified/clear。原hold、扣费和prepared StateRef保留；无可信参考时间仍不生成UTC。未满足完成证据时只允许unknown/unresolved并锁存自动化暂停，迟到事实不能重算既有裁决为成功。

`GET /api/v1/commands/{command_id}/evidence`按指定state_revision读取固定快照，支持1—64项及绑定快照的游标；`GET /api/v1/commands/{command_id}/evidence/{evidence_id}/revisions/{revision}`读取不可变证据。两者独立要求command.evidence.read及命名空间归属，command.read不隐含证据权限。读取不补投、不改变状态，旧修订的空证据快照保留。

schema56在终态后依次持久提交DENY_ENCODING及RELEASE_ENCODING，按真实请求和唯一写尝试核验ACK。编码器及消费者静止后释放活缓存，保留准备原件、传输扣费、命令终态及占用账本。unknown命令可以清理编码缓存，但不会因此产生设备资源释放证据；ACK漏写不得形成半提交。

schema57支持同一受监督会话内的后继固定内存人员即时命令。新资格须重新取得人员、评估器、设备观察及OPEN／Ready；旧命令只有在真实成功裁决、hold释放和编码缓存释放均已证明后才从活动库存排除。后继观察绑定上一条真实写入序号，关闭清单包含全部已签发的历史传输。实际双命令验证值7／23与序号1／2、两个hold及release、16字节累计扣费和两次编码清理；56→57的非空历史迁移逐表核对全部业务行摘要，并重新读取命令和清理原件。

当前闭环仍限固定内存人员即时命令；真实设备、面板／自动化、定时命令和完整恢复尚未验收。历史原件不授予新Ready，提交结果未知及跨运行域的完整恢复查询仍待完成。业务就绪继续503。

SDK命令方法使用当前product4类型；命令成功响应是具名裁决、LookupResult或CommandRead正文，不能套用身份接口的data信封。客户端不自动重试，拒收不等于已受理动作停止。实际受监督模拟器与HTTPS验证首次202、重查200、accepted_at为null、当前记录读取、资格到期后查原、冲突及缺读取权限；受理来源或通知漏写时整笔命令及扣费回滚。历史拒收另有文件库、七写点故障、跨context和重启查原回归。真实浏览器、生产资格、跨服务和设备未验收。

## 持久设备目录与初始控制状态

schema 10提供本机安装管理使用的 `register-device --data-dir /absolute/controller-data`，要求当前OS管理员身份、受控stdin/stdout管道及已完成首次管理员初始化。服务须先停止，运行中的排他数据库连接不能被工具绕过。stdin接收单个JSON对象 `{request_id, device_kind, display_name}`；request_id应由调用方持久保存。命令只登记待配置元数据，不接受网络端点、秘密、能力、当前holder或ready状态，也不连接设备。内部可信安装代码可调用 `storage.registerDevice(input)`，普通HTTP没有登记或导入任意控制状态的入口。

服务分配稳定device_id、新控制epoch及不可变回执。同request_id同内容查原，异内容拒绝；设备、初始控制记录、登记回执、审计与观察通知同事务，四写点任一失败连目录修订一起回滚。开发容量为4096个保留设备记录，满额拒绝且不自动删除历史。当前只提供首次登记；显示名编辑、端点配置、模块绑定、删除及依赖核对仍须按既定生命周期实施。

新设备的初始控制状态固定 `automatic`、holder=null、effective_version=reserved_version=0、gate_state=protected。它表示没有人员持有且不允许发送，不表示自动化已经布防。普通重启保留device_id、control_epoch及控制原件；当前没有导入或修改holder、effective或ready的旁路。后续控制变更须在同一设备权威下追加版本化历史，完成完整切点／屏障与当前授权后才生效。

`GET /api/v1/devices` 使用真实目录并核当前device.read；`GET /api/v1/devices/{device_id}/control` 核当前control.read。权限须显式授予；前者返回标准data信封，后者按已有控制契约返回具名ControlRecord正文。SDK分别调用 `listDevices(cursor?)` 和 `getControl(deviceId)`。读取失败不创建观测或控制记录，发响应前重新核权限及原结果。

分页每页至多64项、描述正文合计不超过48 KiB；游标绑定服务／数据库、目录修订及位置。目录变化返回409，调用方须重新列举；伪造或错格式游标拒绝，不能拼接不同修订当作一个快照。当前只保存待配置描述：connection_state=disconnected、actions／triggers为空，state_schema为false。device_kind是配置分类，不是已验证型号支持；没有虚构provider_boot、设备session、能力或新鲜观测。

四项文件库检查覆盖幂等／冲突、重启、分页修订与权限、逐写回滚及v9→v10显式升级；迁移排序按数值处理，避免版本10排在2前。实际HTTPS另验证目录和保护状态读取、缺权与未知设备；独立包和类型检查另行验证。本机未运行提升权限后的新CLI成功全链；受监督虚拟模块的候选连接／采样见上节；完整控制变更、准备／资源来源、浏览器和实际设备均未验收，业务就绪仍为503。

旧 NodeCG 实现及历史保留于 [leafseamer-legacy](https://github.com/ikenainanodesu/leafseamer-legacy)。本仓尚未导入旧业务源码；后续复用时逐项记录来源、历史映射和必要许可声明。

本仓主许可为 [Apache-2.0](LICENSE)。

### 控制释放与来源窗口

Schema 58 在人员控制变更受理时封存设备的完整命令切点和传输水位。未签发的 queued 命令同事务转为 blocked；已有传输必须经真实监督退役后再分类。控制释放生效仍保持 protected，不改变历史命令结果、不释放未知占用，也不退还累计传输扣费。缺写切点整笔回滚；旧 pending 没有受理切点时保留未决，不补造历史。

新签发的人员来源、评估器来源及其核心、Worker运行观察使用显式 `authority-source-window/2`，上限为 5 秒；缺少该标识的旧原件仍按原 2 秒上限验证。实际截止取原始挑战、运行观察、认证有效期和其他资格的交集。新来源不延长旧原件或已受理命令，每次实际发送仍复核当前授权、撤销、运行状态和原截止。监督请求响应期限及连接确认期限仍为 2 秒，主动刷新只产生新观察，不改写旧观察。该上限不是设备完成时限或生产延迟保证。

认证时钟可由可信装配显式选择 `sample_window_policy=authentication-clock-sample/2` 和 `sample_ttl_ns=5000000000`；未选择时仍为旧2秒策略。新截止从原始采样结束tick计算，保持误差外推、500ms调度、20ms采样上限、当前健康与永久故障锁存。运行中不热换policy，旧原件不续期；本机模拟器集成装配显式选择该策略，生产环境批准仍须单独落实。
