# 冷链网关密钥轮换（Cold-Chain Gateway Key Rotation）

冷链网关在**换钥窗口**内会出现「实例阶段分歧」：部分网关实例仍持旧钥、部分已拿到新钥。
本服务保证：

- 换钥期间，`current` / `candidate` / `retiring` 三个**在用角色**的密钥都能验签，不会误拒新报文；
- 一旦旧钥退休，晚于退休点的报文立即被拒，不会放过旧钥；
- 任何并发交错下，每个租户始终满足 **current 恰一把、candidate/retiring 各至多一把**。

## 技术栈

- Python 3.12 + FastAPI + Uvicorn
- PostgreSQL 16（部分唯一索引 + 租户行级锁保证并发不变量）
- Ed25519（`cryptography`），无填充 base64url 签名
- pytest（黑盒验收，运行在一次性 `verify` 服务里）

## 快速开始

```bash
# 启动 API + PostgreSQL（宿主端口默认 8080）
# verify 一次性服务会在 API 健康后自动执行 pytest 并退出
docker compose up --build
docker compose logs verify          # 查看验收结果

# 自定义宿主端口
API_PORT=9090 docker compose up --build

# 手动再跑一次验收
docker compose run --build verify
```

环境变量：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `API_PORT` | `8080` | 宿主机映射端口（容器内恒为 8080） |
| `PLATFORM_ADMIN_TOKEN` | `platform-admin-token` | 平台管理员 Bearer 令牌（生产必须覆盖） |
| `DATABASE_URL` | 指向 compose 中的 `db` | PostgreSQL DSN |

## 角色状态机

```
                 登记（租户首钥）
   (不存在) ───────────────────────► current ──提升新候选──► retiring ──退休──► retired
                     ▲                ▲   │                                   ▲
                     │                │   └───────────────┐                   │
                 登记（无 candidate   │              候选提升（原子）          │
                 且无 retiring）     └──── candidate ◄──登记                  │
```

- **current（当前钥）**：每个租户恰一把。
- **candidate（候选钥）**：至多一把；仅在**无 candidate 且无 retiring** 时允许登记。
- **retiring（退役中钥）**：至多一把；旧 current 在提升时原子转入，**仍可验签**。
- **retired（已退休）**：终态，不再验签。

**提升（promote）原子地**：`candidate → current`、`旧 current → retiring`、
（若有残留）`旧 retiring → retired`，全部在同一个数据库事务内完成。

非法迁移返回 `409`，并在 `authoritativeRole` 中给出该 keyId 在数据库中的真实角色
（另附 `snapshot` 列出全部在用钥），客户端据此做权威纠偏。

并发安全由两层保证：

1. 所有迁移事务先 `SELECT ... FROM tenants WHERE id = $1 FOR UPDATE` 锁租户行，串行化本租户迁移；
2. 三个部分唯一索引兜底（`role = 'current'/'candidate'/'retiring'` 各至多一行）。

## API

所有管理接口需要 `Authorization: Bearer <PLATFORM_ADMIN_TOKEN>`。
报文接口使用建租户时签发的网关令牌 `gwk_...`。

### 租户与令牌

`POST /admin/tenants` → `201`

```json
{ "tenantId": "t-acme",
  "tokens": { "tenant": "ctk_...", "gateway": "gwk_..." } }
```

### 密钥生命周期（均在 `/admin/tenants/{tenantId}/...` 下）

| 方法与路径 | 说明 |
| --- | --- |
| `POST /keys` | 登记 32 字节 Ed25519 公钥（body：`publicKey` base64url，可选 `keyId`）。首钥为 current，之后在槽位空闲时为 candidate |
| `POST /keys/{keyId}/promote` | candidate 提升为 current，旧 current 原子转 retiring |
| `POST /keys/{keyId}/retire` | retiring 标记为 retired |
| `GET /keys` | 列出全部密钥与角色（含 retired） |

### 网关提交报文

`POST /tenants/{tenantId}/ingest`

- 请求体：**0 ～ 1048576 字节原始字节**（`Content-Type: application/octet-stream`）。
- 请求头：
  - `Authorization: Bearer gwk_...`
  - `X-Tenant-Id`、`X-Key-Id`
  - `X-Signature`：对**原始请求体字节**的 Ed25519 签名，无填充 base64url
- 成功 → `202 {"receiptId": "...", "role": "current|candidate|retiring"}`

**线性化点**：事务内读取 `keys.role` 的数据库快照即排序点——

- 快照为 `current` / `candidate` / `retiring`：验签通过即出回执；
- 快照为 `retired`：`409 {"error":"KEY_RETIRED"}`（早于退休的请求已成功，晚于退休的被拒）；
- keyId 不存在或属于其他租户：统一 `404 {"error":"KEY_UNKNOWN"}`，不区分两种情况；
- 签名错误：`400 INVALID_SIGNATURE`，**不生成回执**；
- 报文超过 1048576 字节：`413 PAYLOAD_TOO_LARGE`。

## 错误码与 HTTP 状态

| 状态 | error | 场景 |
| --- | --- | --- |
| 401 | `UNAUTHENTICATED` / `INVALID_TOKEN` | 缺令牌 / 令牌无效 |
| 403 | `FORBIDDEN` | 角色不足或跨租户使用令牌 |
| 404 | `KEY_UNKNOWN` / `TENANT_NOT_FOUND` | 未知或跨租户 keyId / 租户 |
| 409 | `CANDIDATE_BLOCKED` | candidate/retiring 槽位被占时登记 |
| 409 | `ILLEGAL_TRANSITION` | 非法 promote/retire，带 `authoritativeRole` |
| 409 | `KEY_RETIRED` | 报文命中已退休钥 |
| 409 | `KEY_EXISTS` / `TENANT_EXISTS` | 唯一约束冲突 |
| 400 | `INVALID_SIGNATURE` / `MALFORMED_SIGNATURE` 等 | 签名/参数问题 |
| 413 | `PAYLOAD_TOO_LARGE` | 报文超限 |

## 本地开发（无 Docker）

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt pytest httpx
export DATABASE_URL=postgresql://coldchain:coldchain@localhost:5432/coldchain
uvicorn app.main:app --reload --port 8080
pytest -q tests
```
