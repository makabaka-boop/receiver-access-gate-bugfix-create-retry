# grantgate

射电阵列接收机访问闸门：多个无状态 API 进程共享一个 PostgreSQL 后端，
对接收机的 SHARED / EXCLUSIVE 授权做跨进程一致的并发裁决。

## 模型

- 授权记录持久化：`grant_id`、`receiver`、`mode`（`SHARED`/`EXCLUSIVE`）、
  `status`（`ACTIVE`/`UPGRADE_PENDING`/`RELEASED`）、所有者令牌的 SHA-256 摘要。
- 申请可携带幂等键（`Idempotency-Key` 请求头，或请求体 `request_id`）标识同一笔
  业务申请。首个成功提交的申请把结果（授权标识与持有人令牌）登记在该键下；
  之后任何携带同键的重试——无论落到哪个 API 进程——都重放同一结果：返回该授权
  的**当前状态**与原始令牌，而不是新建第二条授权，也不会对调用方自己的授权
  报 `BUSY`。因此提交成功而应答丢失时，调用方凭键重试即可核对并继续操作
  （释放/升级）该授权；同键并发重发在接收机咨询锁与键唯一约束下只产生一条
  授权。`BUSY` 等失败尝试不登记键，障碍解除后同键重试按当时状态重新裁决。
  同键换用不同接收机或模式返回 `409 {"error":"REQUEST_MISMATCH"}` 且不留任何
  记录。不带键的申请保持原有行为。
- 申请 `SHARED`：仅当该接收机没有活动 `EXCLUSIVE` 授权且没有待升级授权时
  创建 `ACTIVE` 授权。
- 申请 `EXCLUSIVE`：仅当该接收机没有任何活动授权且没有待升级授权时成功。
- 升级 `SHARED → EXCLUSIVE`：凭所有者令牌把 `ACTIVE SHARED` 授权**原地**转为
  待升级（`UPGRADE_PENDING`），不释放原授权、不更换令牌；每个接收机最多一条
  待升级授权。若当时已无其他活动授权则立即转为 `ACTIVE EXCLUSIVE`；否则进入
  等待，并从此拒绝该接收机的一切新共享/独占申请（屏障）。最后一个竞争授权
  释放时，释放事务自动把待升级授权晋升为 `ACTIVE EXCLUSIVE`，查询看不到中间
  状态；待升级授权自身被释放则取消升级、恢复正常准入。重复升级幂等；错误
  令牌（`403`）、已释放授权、原生独占授权与第二个升级申请（均 `409`）返回
  稳定错误且不改变授权集合。
- 冲突一律返回 `409 {"error":"BUSY"}`，且事务回滚、不留任何记录。
- 冲突检查与写入在同一事务内完成；事务首先获取
  `pg_advisory_xact_lock(hashtext(receiver))`，按接收机串行化裁决，
  因此两个 API 进程并发申请同一接收机不会产生双重独占。创建、升级、
  释放共用这一串行化机制，且锁顺序固定（先咨询锁、后行锁），不会死锁。
- 所有者令牌只出现在创建应答及其同键重试的重放应答中（即只对该业务申请的
  持键调用方可见）；释放与升级时凭令牌鉴权，错误令牌返回
  `403 {"error":"FORBIDDEN"}`，目标记录与活动集合保持不变。
- 查询接口按插入顺序稳定返回该接收机的授权标识、模式、状态，不含令牌，
  也不含请求键——其他调用方无法据查询结果接管他人授权。
- 状态存于 PostgreSQL，全部进程重启后授权状态（含待升级）、已登记的请求键
  与原令牌效力不变；数据库迁移兼容升级前创建的旧记录。

## API

| 方法 | 路径 | 请求体 | 响应 |
| --- | --- | --- | --- |
| POST | `/receivers/{receiver}/grants` | `{"mode":"SHARED"\|"EXCLUSIVE"}`，可选 `request_id`；可选请求头 `Idempotency-Key`（优先于 `request_id`） | `201` → `{grant_id, receiver, mode, status, owner_token}`；同键重试重放同一结果（含令牌，状态为当前值）；冲突 `409 BUSY`；键被不同接收机/模式复用 `409 REQUEST_MISMATCH` |
| GET | `/receivers/{receiver}/grants` | — | `200` → `{"grants":[{grant_id, receiver, mode, status}, ...]}`（按序稳定，无令牌、无请求键） |
| POST | `/grants/{grant_id}/release` | `{"owner_token":"..."}` | `200` → 更新后的授权；令牌错误 `403 FORBIDDEN`；不存在 `404 NOT_FOUND` |
| POST | `/grants/{grant_id}/upgrade` | `{"owner_token":"..."}` | `200` → 更新后的授权（`ACTIVE EXCLUSIVE` 或 `UPGRADE_PENDING`，幂等）；令牌错误 `403 FORBIDDEN`；不存在 `404 NOT_FOUND`；已释放/原生独占/已有待升级 `409`（分别为 `RELEASED`/`NOT_SHARED`/`UPGRADE_PENDING`） |
| GET | `/healthz` | — | `200` |

## 运行（Docker Compose）

```sh
docker compose up --build
```

发布端口可用环境变量覆盖（默认值见下）：

```sh
API1_PORT=9080 API2_PORT=9081 DB_PORT=55432 docker compose up --build
```

| 变量 | 默认 | 含义 |
| --- | --- | --- |
| `API1_PORT` | 8080 | api1 宿主机端口 |
| `API2_PORT` | 8081 | api2 宿主机端口 |
| `DB_PORT` | 5432 | PostgreSQL 宿主机端口 |
| `POSTGRES_DB` / `POSTGRES_USER` / `POSTGRES_PASSWORD` | grants | 数据库身份 |

## 一次性验收

`verify` 服务对两个真实 API 进程执行完整验收序列（共享共存、409 冲突
不留记录、403 越权释放状态不变、跨进程释放、并发独占竞赛唯一胜者、
共享原地升级：等待/屏障/自动晋升/幂等重试、并发升级竞赛唯一胜者、
释放待升级授权取消屏障、原生独占与已释放授权拒绝升级、同键重试重放
原结果、提交后断开应答凭键恢复授权与令牌、独占丢失应答不再误报 BUSY、
同键并发重发只产生一条授权、恢复的令牌驱动升级与释放、键复用拒绝且
不留记录、重放反映当前状态、查询不泄露令牌与请求键），成功退出码 0：

```sh
docker compose up --build --exit-code-from verify --abort-on-container-exit
echo $?   # 0 = 验收通过
```

## 测试

集成测试用两个真实 API 实例（独立 `http.Server` 与连接池）覆盖并发独占
竞争、共享共存、越权释放、升级等待/屏障/自动晋升/取消、并发升级竞赛、
同键重试重放（含独占不再误报 BUSY）、同键并发重发唯一记录、键复用拒绝、
失败尝试不登记键、请求键跨重启重放并驱动升级/释放、旧模式数据库迁移与
重启后状态/令牌效力。需要一个 PostgreSQL：

```sh
TEST_DATABASE_URL=postgres://grants:grants@localhost:5432/grants?sslmode=disable \
  go test ./... -count=1
```

未设置 `TEST_DATABASE_URL` 时测试自动跳过。

## 布局

```
cmd/server    API 进程入口（DATABASE_URL、LISTEN_ADDR）
cmd/verify    一次性验收程序（API1_URL、API2_URL）
internal/grants  授权存储（事务+按接收机咨询锁）与 HTTP 层
```
