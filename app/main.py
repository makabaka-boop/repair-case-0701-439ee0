"""冷链网关密钥轮换 API。

角色状态机（每个租户）：
    current （当前钥，唯一）
    candidate （候选钥，至多一把）
    retiring （退役中钥，至多一把；仍可验签）
    retired （已退休，终态，不可再验签）

迁移：
    登记首钥 -> current；仅在无 candidate 且无 retiring 时登记 -> candidate
    提升 candidate：candidate -> current，旧 current -> retiring，旧 retiring -> retired
    退休 retiring -> retired

非法迁移返回 409 并携带权威角色（snapshot）。
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import secrets
from contextlib import asynccontextmanager
from typing import Any

import asyncpg
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import Depends, FastAPI, Header, Request
from pydantic import BaseModel, ConfigDict, Field

from .db import create_pool

MAX_BODY = 1 << 20  # 1048576 字节
SIG_LENGTH = 64
KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
ACTIVE_ROLES = ("current", "candidate", "retiring")


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, **extra: Any):
        self.status = status
        self.code = code
        self.message = message
        self.extra = extra
        super().__init__(message)


# ---------- 工具 ----------

def b64url_decode(data: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))
    except Exception as exc:
        raise ApiError(400, "MALFORMED_SIGNATURE", "签名不是合法的无填充 base64url") from exc


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def verify_ed25519(public_key: bytes, signature: bytes, message: bytes) -> None:
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except InvalidSignature as exc:
        raise ApiError(400, "INVALID_SIGNATURE", "签名验签失败") from exc


# ---------- 认证 ----------

class Principal(BaseModel):
    scope: str
    tenant_id: str | None
    token_id: str


async def authenticate(
    request: Request,
    authorization: str | None = Header(default=None),
) -> Principal:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise ApiError(401, "UNAUTHENTICATED", "缺少 Bearer 令牌")
    token = authorization[7:].strip()
    if not token:
        raise ApiError(401, "UNAUTHENTICATED", "缺少 Bearer 令牌")

    # 平台管理员固定令牌（配置注入，不落库）
    if secrets.compare_digest(token, request.app.state.settings["admin_token"]):
        return Principal(scope="admin", tenant_id=None, token_id="platform-admin")

    row = await request.app.state.pool.fetchrow(
        "SELECT id, tenant_id, scope FROM api_tokens WHERE token_hash = $1",
        hash_token(token),
    )
    if row is None:
        raise ApiError(401, "INVALID_TOKEN", "令牌无效或已吊销")
    return Principal(
        scope=row["scope"], tenant_id=row["tenant_id"], token_id=str(row["id"])
    )


def require_admin(principal: Principal = Depends(authenticate)) -> Principal:
    if principal.scope != "admin":
        raise ApiError(403, "FORBIDDEN", f"需要 admin 权限，当前为 {principal.scope}")
    return principal


# ---------- 请求模型 ----------

class CreateTenantIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant_id: str | None = Field(default=None, max_length=64)
    name: str | None = None


class EnrollKeyIn(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    key_id: str | None = Field(default=None, alias="keyId", max_length=128)
    public_key: str = Field(alias="publicKey")  # base64url，解码后必须恰为 32 字节


# ---------- 应用 ----------

@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.pool = await create_pool(app.state.settings["database_url"])
    yield
    await app.state.pool.close()


def create_app() -> FastAPI:
    settings = {
        "database_url": os.environ.get(
            "DATABASE_URL",
            "postgresql://coldchain:coldchain@db:5432/coldchain",
        ),
        "admin_token": os.environ.get("PLATFORM_ADMIN_TOKEN", "platform-admin-token"),
    }

    app = FastAPI(title="冷链网关密钥轮换", version="1.0.0", lifespan=lifespan)
    app.state.settings = settings

    @app.exception_handler(ApiError)
    async def api_error_handler(request: Request, exc: ApiError):
        from fastapi.responses import JSONResponse

        body: dict[str, Any] = {"error": exc.code, "message": exc.message}
        body.update(exc.extra)
        return JSONResponse(body, status_code=exc.status)

    # ---------- 健康检查 ----------

    @app.get("/healthz")
    async def healthz(request: Request):
        await request.app.state.pool.fetchval("SELECT 1")
        return {"status": "ok"}

    # ---------- 租户与令牌（平台管理员） ----------

    @app.post("/admin/tenants", status_code=201)
    async def create_tenant(
        body: CreateTenantIn,
        request: Request,
        _: Principal = Depends(require_admin),
    ):
        tenant_id = body.tenant_id or f"t-{secrets.token_hex(8)}"
        if not re.fullmatch(r"[a-z0-9]([a-z0-9_-]{0,62}[a-z0-9])?", tenant_id):
            raise ApiError(400, "INVALID_TENANT_ID", "租户 ID 非法")

        tenant_token = "ctk_" + secrets.token_hex(24)
        gateway_token = "gwk_" + secrets.token_hex(24)
        try:
            async with request.app.state.pool.acquire() as conn:
                await conn.execute("INSERT INTO tenants (id) VALUES ($1)", tenant_id)
                await conn.execute(
                    "INSERT INTO api_tokens (tenant_id, scope, token_hash) "
                    "VALUES ($1, 'tenant', $2), ($1, 'gateway', $3)",
                    tenant_id,
                    hash_token(tenant_token),
                    hash_token(gateway_token),
                )
        except asyncpg.UniqueViolationError as exc:
            raise ApiError(409, "TENANT_EXISTS", f"租户 {tenant_id} 已存在") from exc

        return {
            "tenantId": tenant_id,
            "tokens": {"tenant": tenant_token, "gateway": gateway_token},
        }

    # ---------- 密钥生命周期 ----------

    async def _snapshot(conn: asyncpg.Connection, tenant_id: str) -> list[dict[str, str]]:
        rows = await conn.fetch(
            "SELECT id, role FROM keys WHERE tenant_id = $1 AND role = ANY($2) "
            "ORDER BY CASE role WHEN 'current' THEN 0 WHEN 'candidate' THEN 1 ELSE 2 END",
            tenant_id,
            list(ACTIVE_ROLES),
        )
        return [{"keyId": r["id"], "role": r["role"]} for r in rows]

    @app.post("/admin/tenants/{tenant_id}/keys", status_code=201)
    async def enroll_key(
        tenant_id: str,
        body: EnrollKeyIn,
        request: Request,
        _: Principal = Depends(require_admin),
    ):
        raw = b64url_decode(body.public_key)
        if len(raw) != 32:
            raise ApiError(400, "INVALID_PUBLIC_KEY", "Ed25519 公钥必须恰为 32 字节")
        key_id = body.key_id or f"key-{secrets.token_hex(16)}"
        if not KEY_ID_PATTERN.fullmatch(key_id):
            raise ApiError(400, "INVALID_KEY_ID", "keyId 须为 8-128 位字母数字/_-")

        async with request.app.state.pool.acquire() as conn:
            async with conn.transaction():
                # 锁租户行，串行化本租户的迁移
                tenant_exists = await conn.fetchval(
                    "SELECT id FROM tenants WHERE id = $1 FOR UPDATE", tenant_id
                )
                if tenant_exists is None:
                    raise ApiError(404, "TENANT_NOT_FOUND", f"租户 {tenant_id} 不存在")

                # 锁内一次查齐 id / 公钥冲突
                existing = await conn.fetchrow(
                    "SELECT id, role FROM keys "
                    "WHERE tenant_id = $1 AND (id = $2 OR public_key = $3)",
                    tenant_id, key_id, raw,
                )
                if existing is not None:
                    raise ApiError(
                        409, "KEY_EXISTS", "keyId 或公钥已存在",
                        authoritativeRole=existing["role"],
                        duplicateKeyId=existing["id"],
                        snapshot=await _snapshot(conn, tenant_id),
                    )

                role_row = await conn.fetchrow(
                    "SELECT role FROM keys WHERE tenant_id = $1 AND role = ANY($2)",
                    tenant_id, list(ACTIVE_ROLES),
                )
                if role_row is None:
                    role = "current"  # 首个 32 字节公钥为当前钥
                else:
                    blocked = await conn.fetchrow(
                        "SELECT role FROM keys "
                        "WHERE tenant_id = $1 AND role IN ('candidate','retiring')",
                        tenant_id,
                    )
                    if blocked is not None:
                        # 仅无候选与退役中钥时可加候选
                        raise ApiError(
                            409, "CANDIDATE_BLOCKED",
                            "已有候选或退役中钥，无法登记新候选",
                            blockingRole=blocked["role"],
                            snapshot=await _snapshot(conn, tenant_id),
                        )
                    role = "candidate"

                # 保存点：若唯一索引兜底命中（理论上锁内已拦住），
                # 回滚到保存点后仍可读取权威快照
                try:
                    async with conn.transaction():
                        await conn.execute(
                            "INSERT INTO keys (id, tenant_id, public_key, role) "
                            "VALUES ($1, $2, $3, $4)",
                            key_id, tenant_id, raw, role,
                        )
                except asyncpg.UniqueViolationError as exc:
                    dup = await conn.fetchrow(
                        "SELECT id, role FROM keys "
                        "WHERE tenant_id = $1 AND (id = $2 OR public_key = $3)",
                        tenant_id, key_id, raw,
                    )
                    raise ApiError(
                        409, "KEY_EXISTS", "keyId 或公钥已存在",
                        authoritativeRole=dup["role"] if dup else None,
                        duplicateKeyId=dup["id"] if dup else None,
                        snapshot=await _snapshot(conn, tenant_id),
                    ) from exc

                return {
                    "keyId": key_id,
                    "role": role,
                    "snapshot": await _snapshot(conn, tenant_id),
                }

    @app.post("/admin/tenants/{tenant_id}/keys/{key_id}/promote", status_code=200)
    async def promote_key(
        tenant_id: str,
        key_id: str,
        request: Request,
        _: Principal = Depends(require_admin),
    ):
        async with request.app.state.pool.acquire() as conn:
            async with conn.transaction():
                if await conn.fetchval(
                    "SELECT id FROM tenants WHERE id = $1 FOR UPDATE", tenant_id
                ) is None:
                    raise ApiError(404, "TENANT_NOT_FOUND", f"租户 {tenant_id} 不存在")

                key = await conn.fetchrow(
                    "SELECT role FROM keys WHERE tenant_id = $1 AND id = $2",
                    tenant_id, key_id,
                )
                if key is None:
                    # 未知或跨租户 keyId：统一口径
                    raise ApiError(404, "KEY_UNKNOWN", "未知 keyId 或不属于该租户")
                if key["role"] != "candidate":
                    raise ApiError(
                        409, "ILLEGAL_TRANSITION",
                        "仅候选钥可被提升",
                        authoritativeRole=key["role"],
                        snapshot=await _snapshot(conn, tenant_id),
                    )

                # 迁移规则保证：有 candidate 时不可能存在 retiring
                retiring = await conn.fetchrow(
                    "SELECT id FROM keys WHERE tenant_id = $1 AND role = 'retiring'",
                    tenant_id,
                )
                if retiring is not None:
                    raise ApiError(
                        409, "ILLEGAL_TRANSITION",
                        "退役中钥尚未退休，不能提升",
                        authoritativeRole="retiring",
                        blockingRole="retiring",
                        snapshot=await _snapshot(conn, tenant_id),
                    )

                # 原子地：candidate -> current；旧 current -> retiring；（兜底）旧 retiring -> retired
                await conn.execute(
                    "UPDATE keys SET role = 'retired', retired_at = now() "
                    "WHERE tenant_id = $1 AND role = 'retiring'", tenant_id
                )
                await conn.execute(
                    "UPDATE keys SET role = 'retiring' "
                    "WHERE tenant_id = $1 AND role = 'current'", tenant_id
                )
                updated = await conn.execute(
                    "UPDATE keys SET role = 'current' "
                    "WHERE tenant_id = $1 AND id = $2 AND role = 'candidate'",
                    tenant_id, key_id,
                )
                if updated.endswith(" 0"):
                    raise ApiError(
                        409, "ILLEGAL_TRANSITION", "提升失败，状态已变化",
                        snapshot=await _snapshot(conn, tenant_id),
                    )

                return {
                    "keyId": key_id,
                    "role": "current",
                    "snapshot": await _snapshot(conn, tenant_id),
                }

    @app.post("/admin/tenants/{tenant_id}/keys/{key_id}/retire", status_code=200)
    async def retire_key(
        tenant_id: str,
        key_id: str,
        request: Request,
        _: Principal = Depends(require_admin),
    ):
        async with request.app.state.pool.acquire() as conn:
            async with conn.transaction():
                if await conn.fetchval(
                    "SELECT id FROM tenants WHERE id = $1 FOR UPDATE", tenant_id
                ) is None:
                    raise ApiError(404, "TENANT_NOT_FOUND", f"租户 {tenant_id} 不存在")

                key = await conn.fetchrow(
                    "SELECT role FROM keys WHERE tenant_id = $1 AND id = $2",
                    tenant_id, key_id,
                )
                if key is None:
                    raise ApiError(404, "KEY_UNKNOWN", "未知 keyId 或不属于该租户")
                if key["role"] != "retiring":
                    raise ApiError(
                        409, "ILLEGAL_TRANSITION",
                        "仅退役中钥可被退休",
                        authoritativeRole=key["role"],
                        snapshot=await _snapshot(conn, tenant_id),
                    )

                await conn.execute(
                    "UPDATE keys SET role = 'retired', retired_at = now() "
                    "WHERE tenant_id = $1 AND id = $2 AND role = 'retiring'",
                    tenant_id, key_id,
                )
                return {
                    "keyId": key_id,
                    "role": "retired",
                    "snapshot": await _snapshot(conn, tenant_id),
                }

    @app.get("/admin/tenants/{tenant_id}/keys")
    async def list_keys(
        tenant_id: str,
        request: Request,
        _: Principal = Depends(require_admin),
    ):
        rows = await request.app.state.pool.fetch(
            "SELECT id, role, created_at, retired_at "
            "FROM keys WHERE tenant_id = $1 ORDER BY created_at",
            tenant_id,
        )
        return {
            "keys": [
                {
                    "keyId": r["id"],
                    "role": r["role"],
                    "createdAt": r["created_at"].isoformat(),
                    "retiredAt": r["retired_at"].isoformat() if r["retired_at"] else None,
                }
                for r in rows
            ]
        }

    # ---------- 网关报文 ----------

    @app.post("/tenants/{tenant_id}/ingest", status_code=202)
    async def ingest(
        tenant_id: str,
        request: Request,
        x_tenant_id: str | None = Header(default=None),
        x_key_id: str | None = Header(default=None),
        x_signature: str | None = Header(default=None),
        principal: Principal = Depends(authenticate),
    ):
        # 仅网关令牌可提交报文；admin/tenant 令牌即越权
        if principal.scope != "gateway":
            raise ApiError(403, "FORBIDDEN", "仅网关令牌可提交报文")
        # 令牌必须属于路径租户；跨租户即越权
        if principal.tenant_id != tenant_id:
            raise ApiError(403, "FORBIDDEN", "令牌不属于该租户")
        # tenantId 头必须与路径一致（防止重放拼接）
        if x_tenant_id is not None and x_tenant_id != tenant_id:
            raise ApiError(403, "FORBIDDEN", "tenantId 头与路径租户不一致")
        if not x_key_id:
            raise ApiError(400, "MISSING_KEY_ID", "缺少 X-Key-Id 头")
        if not x_signature:
            raise ApiError(400, "MISSING_SIGNATURE", "缺少 X-Signature 头")

        declared = request.headers.get("content-length")
        if declared is not None:
            try:
                length = int(declared)
            except ValueError as exc:
                raise ApiError(400, "BAD_REQUEST", "Content-Length 非法") from exc
            if length > MAX_BODY:
                raise ApiError(413, "PAYLOAD_TOO_LARGE", "报文超过 1048576 字节")
        body = await request.body()
        if len(body) > MAX_BODY:
            raise ApiError(413, "PAYLOAD_TOO_LARGE", "报文超过 1048576 字节")

        # 编码合法性先解码（纯语法）；签名长度属于验签，放到角色快照之后，
        # 保证 KEY_UNKNOWN / KEY_RETIRED 的口径优先于签名格式错误。
        signature = b64url_decode(x_signature)

        pool = request.app.state.pool
        async with pool.acquire() as conn:
            # 线性化点与回执写入在同一事务：本次快照的角色即排序点，
            # 验签通过才落回执；任一裁决失败整体回滚，不留审计脏数据。
            async with conn.transaction():
                # keyId 必须属于路径租户；不存在与跨租户统一 KEY_UNKNOWN。
                key = await conn.fetchrow(
                    "SELECT id, role, public_key FROM keys "
                    "WHERE id = $1 AND tenant_id = $2",
                    x_key_id, tenant_id,
                )
                if key is None:
                    raise ApiError(404, "KEY_UNKNOWN", "未知 keyId")
                # 快照为 retired：晚于退休点的报文立即被拒
                if key["role"] == "retired":
                    raise ApiError(409, "KEY_RETIRED", "该密钥已退休")

                if len(signature) != SIG_LENGTH:
                    raise ApiError(400, "MALFORMED_SIGNATURE", "Ed25519 签名必须为 64 字节")

                # 验签失败抛错，事务回滚，不产生回执
                verify_ed25519(key["public_key"], signature, body)

                # 快照为 current / candidate / retiring：验签通过即出回执。
                # 即使验签期间并发退休，本请求已在退休点之前排序，照常接收。
                receipt_id = await conn.fetchval(
                    "INSERT INTO receipts "
                    "(tenant_id, key_id, role_at_accept, body_sha256, body_length) "
                    "VALUES ($1, $2, $3, $4, $5) RETURNING id",
                    tenant_id, x_key_id, key["role"],
                    hashlib.sha256(body).digest(), len(body),
                )

                return {
                    "receiptId": str(receipt_id),
                    "role": key["role"],
                }

    @app.get("/admin/tenants/{tenant_id}/receipts")
    async def list_receipts(
        tenant_id: str,
        request: Request,
        _: Principal = Depends(require_admin),
        limit: int = 100,
    ):
        limit = max(1, min(limit, 1000))
        rows = await request.app.state.pool.fetch(
            "SELECT id, key_id, role_at_accept, body_length, created_at "
            "FROM receipts WHERE tenant_id = $1 "
            "ORDER BY created_at DESC LIMIT $2",
            tenant_id, limit,
        )
        return {
            "receipts": [
                {
                    "receiptId": str(r["id"]),
                    "keyId": r["key_id"],
                    "role": r["role_at_accept"],
                    "bodyLength": r["body_length"],
                    "createdAt": r["created_at"].isoformat(),
                }
                for r in rows
            ]
        }

    return app


app = create_app()
