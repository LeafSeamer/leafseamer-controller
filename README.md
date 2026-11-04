# LeafSeamer Controller

> **施工中 / Work in progress。** 已提供保护状态的服务启动、持久服务身份、本机健康检查，以及首次管理员的存储事务和受限本机工具。已接通本地可信装配下的 HTTPS 登录、刷新、定向 token 和会话读取；生产认证资格、完整身份接口、命令受理、监督器及设备出口尚未完成，不能用于实际直播控制。

可独立使用的直播软硬件控制平台：设备模块、连接、手动控制、资源协调、接管、凭据和状态采集。

总体设计、已确认决策、待落实事项和路线图统一维护于 [LeafSeamer Suite](https://github.com/LeafSeamer/leafseamer-suite)。当前分支为 `main`，按已确认的依赖顺序实施；首期完整功能和设备验收要求保持不变。

## 开发运行

使用 Node 24.22.0、npm 11.19.1。先在相邻 `leafseamer-sdk` 仓库构建与 [sdk-runtime.json](sdk-runtime.json) 摘要一致的 SDK，再安装本仓锁定依赖。构建将固定 SDK 运行文件纳入 Controller 包，独立运行无需邻仓。其余运行依赖固定为 better-sqlite3 13.0.3、argon2 0.45.1 和 canonicalize 5.1.0；安装使用锁内完整依赖。

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

`init-storage` 只创建服务存储，不创建管理员或设备权限。数据库已存在时拒绝覆盖；启动时数据库缺失、版本未知、迁移摘要不符或完整性检查失败均拒绝，不自动创建新身份或修复原库。初始化失败留下的文件须按故障检查处理，不能通过重复初始化静默替换。

库中固定 service_id、database_instance_id、control_epoch 和 request_epoch。普通重启保留它们，为每次启动生成新的 service_boot_id；它不充当 DF02 的已批准运行域。启动记录与迁移记录持久保存，正常关闭只结束本次启动记录；强停留下的旧记录不改写成成功关闭。记录中的 UTC 只供诊断，不是认证时钟、业务 NTP 或排序权威。备份恢复换 scope、完整身份生命周期和持久请求账本尚待实现。

SQLite 固定引擎为 3.53.4，并核对 source id；启用外键、WAL、FULL 同步及单连接排他模式，关闭连接自动checkpoint并读回检查。第二个进程不能接管仍被占用的业务库；操作系统释放旧连接后，新进程仍以保护状态启动。排他数据库连接不证明外部 worker 已退役，也不授予设备发送权限。驱动使用原始数组行和显式字段映射，可在禁止动态代码生成时运行。完整业务写入前仍须接入DF04有界checkpoint与WAL容量协调，不能将当前保护态启动用于持续生产写入。（SQLite 行为依据：[locking_mode](https://www.sqlite.org/pragma.html#pragma_locking_mode)、[WAL](https://www.sqlite.org/wal.html)。）

| 本机入口 | 当前结果 |
| --- | --- |
| `GET /health/live` | 200，最小存活状态 |
| `GET /health/ready` | 503；旧库 `bootstrap_incomplete`，schema 3及以上为 `authentication_clock_unqualified` 或故障时 `authentication_clock_unavailable`；身份时钟已具资格时仍为 `business_incomplete` |
| `GET /.well-known/leafseamer-contracts` | 503，无正文；尚无完整就绪的契约处理组合 |

健康接口支持 HEAD，禁止缓存；不暴露数据库路径、版本或凭据。启动时的 JSON 输出包含本次 boot 身份与监听端口，`ready` 为 false。未知路由不进入业务处理，带正文请求不读入无界缓冲；当前没有命令发送、自动重放或自动布防路径。

## 首次管理员与数据库升级

新建库初始为 schema 1；启动不会自动升级。需要首次管理员存储时，停止本库服务并显式执行：

```sh
node --disallow-code-generation-from-strings dist/cli.mjs migrate-storage --data-dir /absolute/controller-data
```

此操作逐步升级至 schema 7。每一步先通过 SQLite backup 生成同目录的独立旧版文件及 SHA-256，再同事务升级、保留服务 scope、启动历史和已有身份回执、登记迁移摘要和备份引用。成功响应 `steps` 列出本次各步，顶层备份字段指最后一步；已为 v7 时返回 `changed:false`。正在运行、未知版本或不完整迁移拒绝。每一步 DDL 失败只回滚该步；例如 v1→v2 已提交而 v2→v3 失败时保留 v2，不自动降级。旧 v1/v2/v3/v4/v5/v6 库仍可保护态启动，不自动升级。备份不能作为另一个活动实例直接使用，正式恢复仍需换 scope 和完整恢复流程。活动库与备份目录的安装 ACL、备份恢复和掉电耐久尚待平台验收。

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

schema 5 的 `storage.sessions(clock)` 将同库人员会话服务绑定到唯一认证时钟实例，提供 `login/current/refresh/logout`。内部接口本身不是公开契约；下述四个 HTTPS 路径通过锁定 SDK 投影公开 Session，完整身份接受集及受控代理仍待实施。没有环境资格时无法登录，不用诊断时间代替认证时钟。服务主体不能通过这条人员密码路径取得身份。

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

当前 `/auth/sessions`、`/auth/sessions/refresh`、`/auth/service-tokens` 和 `/api/v1/session` 已使用 SDK 的锁定 `panel4` 服务端校验器。默认CLI和缺少TLS装配时，完整合法请求返回结构化 `503 WORKER_NOT_READY` 和 `do_not_retry`；本地可信装配支持下述成功路径。SDK读取相同service／boot身份与契约选择。就绪及发现入口仍为503。当前全系统身份接受集仍待归并，不能据这四个路径宣称完整契约已启用。

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

四个既有panel4路径支持登录201、刷新200、token签发201和会话读取200。公开Session来自当前文件库权限及有效会话，响应经SDK完整校验后、发送秘密前再次核当前权限和认证时钟。时间下界向上、上界向下换算为毫秒。Host必须精确匹配配置，写操作Origin必须精确匹配；读取若携Origin也须一致，cross-site请求拒绝。成功路径要求真实TLSSocket，不采信代理自报头。

刷新Cookie使用 `leafseamer_session`，固定 `Path=/auth; Secure; HttpOnly; SameSite=Strict`，不设Domain。Cookie中的凭据和X-CSRF-Token需同时有效；重复目标Cookie拒绝。刷新只交付一次新秘密，正确复用已消费的旧凭据撤销该session全部token。GET会话只接受Bearer，并核本服务audience及session.read；Cookie不能代替它。当前不签扩展委托token。`expires_in` 为签发期限向下取整的秒数提示，服务器始终按原绝对截止重核，响应耗时不续期。旧panel4的签发请求没有客户端request_id，网络调用不自动重试；不能把内部幂等接口宣称为HTTP查原已完成。

SDK的 `createBrowserSessionClient` 管理内存CSRF与token，浏览器保管HttpOnly Cookie，拒绝并发刷新、错误选择及非法CSRF。清本地内存后到达的旧响应不能重新安装凭据；清内存不等于服务端注销。完整注销、主体与权限管理接口须进入新身份接受集，不能向旧panel4偷加路径。

当前62项Controller检查通过。新增五项实际加载Windows原生模块，使用正常证书校验的本机HTTPS、真实密码库和文件权限库；验证SDK往返、Origin／Host／Cookie／CSRF、刷新复用、来源失效及迟到响应。证书仅在测试内存中临时生成，Cookie容器为测试模拟，环境批准引用与误差界仍为合成。独立安装包另验证相同HTTPS成功路径；真实浏览器、Linux、生产提供者、可信代理、完整跨服务鉴权、部署和设备未验收，业务就绪仍为503。

旧 NodeCG 实现及历史保留于 [leafseamer-legacy](https://github.com/ikenainanodesu/leafseamer-legacy)。本仓尚未导入旧业务源码；后续复用时逐项记录来源、历史映射和必要许可声明。

本仓主许可为 [Apache-2.0](LICENSE)。
