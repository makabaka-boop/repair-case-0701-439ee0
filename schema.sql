-- 冷链网关密钥轮换：租户、令牌、租户密钥、回执
-- 不变量（按租户）：已登记状态下恰一把 current；candidate / retiring 各至多一把。

CREATE TABLE IF NOT EXISTS tenants (
    id          TEXT PRIMARY KEY
                CHECK (id ~ '^[a-z0-9]([a-z0-9_-]{0,62}[a-z0-9])?$'),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS api_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   TEXT REFERENCES tenants(id) ON DELETE CASCADE,
    -- 平台管理员令牌 tenant_id 为 NULL
    scope       TEXT NOT NULL CHECK (scope IN ('admin','tenant','gateway')),
    token_hash  TEXT NOT NULL UNIQUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT platform_token_has_no_tenant CHECK (
        (scope = 'admin') = (tenant_id IS NULL)
    )
);

CREATE TABLE IF NOT EXISTS keys (
    id          TEXT PRIMARY KEY
                CHECK (length(id) BETWEEN 8 AND 128),
    tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    public_key  BYTEA NOT NULL CHECK (octet_length(public_key) = 32),
    role        TEXT NOT NULL
                CHECK (role IN ('current','candidate','retiring','retired')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_at  TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS keys_one_current_per_tenant
    ON keys (tenant_id) WHERE role = 'current';
CREATE UNIQUE INDEX IF NOT EXISTS keys_one_candidate_per_tenant
    ON keys (tenant_id) WHERE role = 'candidate';
CREATE UNIQUE INDEX IF NOT EXISTS keys_one_retiring_per_tenant
    ON keys (tenant_id) WHERE role = 'retiring';

-- 同租户公钥不可重复登记
CREATE UNIQUE INDEX IF NOT EXISTS keys_unique_pubkey_per_tenant
    ON keys (tenant_id, public_key);

CREATE TABLE IF NOT EXISTS receipts (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    key_id      TEXT NOT NULL REFERENCES keys(id),
    role_at_accept TEXT NOT NULL
                  CHECK (role_at_accept IN ('current','candidate','retiring')),
    body_sha256 BYTEA NOT NULL,
    body_length INTEGER NOT NULL CHECK (body_length BETWEEN 0 AND 1048576),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS receipts_tenant_idx ON receipts (tenant_id, created_at);
