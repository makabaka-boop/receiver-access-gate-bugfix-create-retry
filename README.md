# grantgate

射电阵列接收机访问闸门：多个无状态 API 进程共享一个 PostgreSQL 后端，
对接收机的 SHARED / EXCLUSIVE 授权做跨进程一致的并发裁决。

## 模型

- 授权记录持久化：`grant_id`、`receiver`、`mode`（`SHARED`/`EXCLUSIVE`）、
  `status`（`ACTIVE`/`UPGRADE_PENDING`/`RELEASED`）、所有者令牌的 SHA-256 摘要。
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
- 所有者令牌只在创建响应中出现一次；释放与升级时凭令牌鉴权，错误令牌返回
  `403 {"error":"FORBIDDEN"}`，目标记录与活动集合保持不变。
- 申请体可携带调用方自己的业务标识 `request_key`，用于应对“提交已落库、HTTP
  应答丢失”这类不确定完成：`(receiver, request_key)` 在数据库中唯一，同键请求
  （跨实例重试、同键并发重发、应答丢失后的重发）裁决为**同一条**授权，绝不新增
  第二条有效授权。首个请求返回 `201` 且 `replayed:false`；后续同键请求返回 `200`
  且 `replayed:true`，载荷是该授权的**当前**状态（已释放 / 已升级也如实反映），
  并携带与首次完全一致的 `owner_token`，因此应答丢失后调用方可以核对结果、用
  找回的令牌继续释放或升级。独占申请应答丢失时，属主用同键重试得到的是自己的
  `200` 授权而不是无法分辨的 `409 BUSY`；其他业务键仍只得到 `409 BUSY`。同键
  但 `mode` 不同返回 `422 REQUEST_KEY_CONFLICT` 且不改变任何记录。不带
  `request_key` 的申请保持原有语义：每次创建独立授权与独立随机令牌。
- 带键申请的令牌并非随机后明文保存，而是由全实例共享、存于数据库
  `server_secrets` 表的 32 字节胡椒（pepper）对 `(receiver, request_key)` 做
  HMAC-SHA256 派生；所有实例与重启后派生结果一致，且数据库中不存在可还原令牌的
  明文。持有 `request_key` 是恢复令牌的唯一途径；查询接口既不返回
  `request_key` 也不返回令牌或摘要，仅凭列表中的 `grant_id` 无法释放、升级或
  接管任何授权（拿 `request_key` 冒充 `owner_token` 同样得到 `403`）。
- 查询接口按插入顺序稳定返回该接收机的授权标识、模式、状态，不含令牌。
- 状态存于 PostgreSQL，全部进程重启后授权状态（含待升级）与原令牌效力不变；
  数据库迁移兼容升级前创建的旧记录。

## API

| 方法 | 路径 | 请求体 | 响应 |
| --- | --- | --- | --- |
| POST | `/receivers/{receiver}/grants` | `{"mode":"SHARED"\|"EXCLUSIVE","request_key":"..."}`（`request_key` 可选） | 首次 `201` → `{grant_id, receiver, mode, status, owner_token, replayed:false}`；同键重放 `200` → 同一授权的当前状态与同一 `owner_token`，`replayed:true`；冲突 `409 BUSY`；同键改模式 `422 REQUEST_KEY_CONFLICT`；键超长 `400 BAD_REQUEST_KEY` |
| GET | `/receivers/{receiver}/grants` | — | `200` → `{"grants":[{grant_id, receiver, mode, status}, ...]}`（按序稳定，无令牌） |
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
释放待升级授权取消屏障、原生独占与已释放授权拒绝升级、查询不泄露
令牌，以及不确定完成场景：共享/独占申请提交后断开应答后同键重放唯一
业务结果、同键跨实例并发重发只产生一条有效记录且各响应同 ID 同令牌、
找回令牌可释放且升级可推进、他键只得到 BUSY、列表不泄露 request_key
与令牌、释放/升级后与重启后重放结论一致），成功退出码 0：

```sh
docker compose up --build --exit-code-from verify --abort-on-container-exit
echo $?   # 0 = 验收通过
```

## 测试

集成测试用两个真实 API 实例（独立 `http.Server` 与连接池）覆盖并发独占
竞争、共享共存、越权释放、升级等待/屏障/自动晋升/取消、并发升级竞赛、
旧模式数据库迁移与重启后状态/令牌效力，以及应答丢失的不确定完成：
断开应答后的同键重放不产生重复授权且能找回令牌、独占成功应答丢失后属主
重放可识别自有授权、同键并发重发唯一业务结果、跨重启结论一致。需要一个
PostgreSQL：

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
