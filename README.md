# LeafSeamer Controller

> **施工中 / Work in progress。** 已提供保护状态的服务启动、持久服务身份和本机健康检查。认证、命令受理、监督器及设备出口尚未接通，不能用于实际直播控制。

可独立使用的直播软硬件控制平台：设备模块、连接、手动控制、资源协调、接管、凭据和状态采集。

总体设计、已确认决策、待落实事项和路线图统一维护于 [LeafSeamer Suite](https://github.com/LeafSeamer/leafseamer-suite)。当前分支为 `main`，按已确认的依赖顺序实施；首期完整功能和设备验收要求保持不变。

## 开发运行

使用 Node 24.22.0、npm 11.19.1。先在相邻 `leafseamer-sdk` 仓库构建 SDK `7618b1f` 或其后明确兼容的开发提交，再安装本仓锁定依赖。SDK 目前用于跨仓测试，Controller 运行入口只依赖固定的 better-sqlite3 13.0.3。

```sh
npm ci --ignore-scripts
npm test
npm run build
```

首次显式创建业务库，再启动本机服务。`--data-dir` 必须是绝对路径；以下路径需替换为自己控制的独立目录。

```sh
node --disallow-code-generation-from-strings dist/cli.mjs init-storage --data-dir /absolute/controller-data
npm start -- --data-dir /absolute/controller-data --port 8081
```

Windows 使用绝对目录参数，运行文件与业务数据分开存放。当前为开发启动入口，尚非 C12 的安装器或受监督生产启动流程；Windows 目录 ACL、Linux 服务账户、TLS 和发行制品仍需各自验收。监听仅允许 `127.0.0.1` 或 `::1`，没有将 HTTP 扩展到远端的开关。

`init-storage` 只创建服务存储，不创建管理员或设备权限。数据库已存在时拒绝覆盖；启动时数据库缺失、版本未知、迁移摘要不符或完整性检查失败均拒绝，不自动创建新身份或修复原库。初始化失败留下的文件须按故障检查处理，不能通过重复初始化静默替换。

库中固定 service_id、database_instance_id、control_epoch 和 request_epoch。普通重启保留它们，为每次启动生成新的 service_boot_id；它不充当 DF02 的已批准运行域。启动记录与迁移记录持久保存，正常关闭只结束本次启动记录；强停留下的旧记录不改写成成功关闭。记录中的 UTC 只供诊断，不是认证时钟、业务 NTP 或排序权威。备份恢复换 scope、管理员初始化和持久请求账本尚待实现。

SQLite 固定引擎为 3.53.4，并核对 source id；启用外键、WAL、FULL 同步及单连接排他模式。第二个进程不能接管仍被占用的业务库；操作系统释放旧连接后，新进程仍以保护状态启动。排他数据库连接不证明外部 worker 已退役，也不授予设备发送权限。驱动使用原始数组行和显式字段映射，可在禁止动态代码生成时运行。（SQLite 行为依据：[locking_mode](https://www.sqlite.org/pragma.html#pragma_locking_mode)、[WAL](https://www.sqlite.org/wal.html)。）

| 本机入口 | 当前结果 |
| --- | --- |
| `GET /health/live` | 200，最小存活状态 |
| `GET /health/ready` | 503，`bootstrap_incomplete` |
| `GET /.well-known/leafseamer-contracts` | 503，无正文；尚无完整就绪的契约处理组合 |

健康接口支持 HEAD，禁止缓存；不暴露数据库路径、版本或凭据。启动时的 JSON 输出包含本次 boot 身份与监听端口，`ready` 为 false。未知路由不进入业务处理，带正文请求不读入无界缓冲；当前没有命令发送、自动重放或自动布防路径。

`npm test` 使用真实文件库、SDK HTTP 客户端和自建子进程，覆盖身份稳定、重复初始化拒绝、排他占用、错误版本／迁移拒绝、存活与就绪分离、强停重启及配置错误。当前验证平台为 Windows x64；未验证 Linux、掉电、生产认证、部署或设备。源码与运行构建在本仓，测试数据和依赖不提交。

旧 NodeCG 实现及历史保留于 [leafseamer-legacy](https://github.com/ikenainanodesu/leafseamer-legacy)。本仓尚未导入旧业务源码；后续复用时逐项记录来源、历史映射和必要许可声明。

本仓主许可为 [Apache-2.0](LICENSE)。
