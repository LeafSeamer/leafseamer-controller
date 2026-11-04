# LeafSeamer Controller

> **施工中 / Work in progress。** 已提供保护状态的服务启动、持久服务身份、本机健康检查，以及首次管理员的存储事务和受限本机工具。网络登录与会话认证、命令受理、监督器及设备出口尚未接通，不能用于实际直播控制。

可独立使用的直播软硬件控制平台：设备模块、连接、手动控制、资源协调、接管、凭据和状态采集。

总体设计、已确认决策、待落实事项和路线图统一维护于 [LeafSeamer Suite](https://github.com/LeafSeamer/leafseamer-suite)。当前分支为 `main`，按已确认的依赖顺序实施；首期完整功能和设备验收要求保持不变。

## 开发运行

使用 Node 24.22.0、npm 11.19.1。先在相邻 `leafseamer-sdk` 仓库构建 SDK `7618b1f` 或其后明确兼容的开发提交，再安装本仓锁定依赖。SDK 目前用于跨仓测试，Controller 运行依赖固定的 better-sqlite3 13.0.3 和 argon2 0.45.1；安装使用锁内完整依赖。

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
| `GET /health/ready` | 503；旧库 `bootstrap_incomplete`，schema 3/4 为 `authentication_clock_unqualified` 或故障时 `authentication_clock_unavailable` |
| `GET /.well-known/leafseamer-contracts` | 503，无正文；尚无完整就绪的契约处理组合 |

健康接口支持 HEAD，禁止缓存；不暴露数据库路径、版本或凭据。启动时的 JSON 输出包含本次 boot 身份与监听端口，`ready` 为 false。未知路由不进入业务处理，带正文请求不读入无界缓冲；当前没有命令发送、自动重放或自动布防路径。

## 首次管理员与数据库升级

新建库初始为 schema 1；启动不会自动升级。需要首次管理员存储时，停止本库服务并显式执行：

```sh
node --disallow-code-generation-from-strings dist/cli.mjs migrate-storage --data-dir /absolute/controller-data
```

此操作逐步升级至 schema 4。每一步先通过 SQLite backup 生成同目录的独立旧版文件及 SHA-256，再同事务升级、保留服务 scope、启动历史和已有身份回执、登记迁移摘要和备份引用。成功响应 `steps` 列出本次各步，顶层备份字段指最后一步；已为 v4 时返回 `changed:false`。正在运行、未知版本或不完整迁移拒绝。每一步 DDL 失败只回滚该步；例如 v1→v2 已提交而 v2→v3 失败时保留 v2，不自动降级。旧 v1/v2/v3 库仍可保护态启动，不自动升级。备份不能作为另一个活动实例直接使用，正式恢复仍需换 scope 和完整恢复流程。活动库与备份目录的安装 ACL、备份恢复和掉电耐久尚待平台验收。

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

受监督提供者的 `read()` 必须返回已从可信安装／运行时来源解析并验证的 `policy`、`runtime`、`health` 原件；原件自带摘要只能证明一致性，不能自证来源可信。提供者负责环境批准、profile、制品和健康／有限holdover引用的真实性及持续有效性。库逐项核对其摘要、scope、policy、运行域与有效期，采集前后和提交前重新读取；不得将HTTP输入、模块输出或普通配置文件直接适配成此提供者。当前没有产品提供者，也没有CLI／HTTP参数绕过它。

每次采集同事务写入政策／运行／健康依赖、不可变 AuthenticationClockAcquisition 与域当前指针。同 ID 同内容只返回原引用，不刷新时间；换内容、区间不相交、连续性丢失和过期使域保护。后续有效区间保留此前预测上下界，不能借新采样收窄旧上界。每次 `current()` 重新核健康、运行域、真实读数和采样期限，返回期限取采样／运行／健康的交集；该返回值不允许被缓存成长期授权。数据库写入／提交失败立即停止本实例提供时间；故障事实也写失败时明确 `durable:false`，不报告安全关闭已完成。

schema 4 的四表分别保存依赖原件、采集原件、当前指针及首故障；故障不可删除或更新。当前 writer 尚待接入完整 DF04 容量／保留调度、DF02 启停与域退役、实际环境／健康提供者以及身份请求事务；没有实际设备出口，因此没有生成 Controller 出口 Binding、关闭计划或宣称物理终止。测试中的合成提供者只用于隔离验收，不允许出现在安装配置中。

`npm test` 使用真实文件库、密码库、SDK HTTP 客户端、自建子进程与本机构建的原生模块；覆盖身份事务、逐步迁移、整数边界、故障锁存、checkpoint复用及HTTP保护态。故障注入使用合成读数，不能替代真实休眠／恢复和系统跳变验收。因运行账户未提升权限，未验证管理员权限下完整CLI成功路径，事务成功与管道输入分别实际验证。Linux、真实休眠、掉电、生产认证时钟资格、TLS、网络登录／会话、部署和设备均未验收。源码与运行构建在本仓，测试数据和依赖不提交。

旧 NodeCG 实现及历史保留于 [leafseamer-legacy](https://github.com/ikenainanodesu/leafseamer-legacy)。本仓尚未导入旧业务源码；后续复用时逐项记录来源、历史映射和必要许可声明。

本仓主许可为 [Apache-2.0](LICENSE)。
