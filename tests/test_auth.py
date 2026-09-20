"""认证与授权：401 / 403。"""
from conftest import admin_headers, b64url, new_keypair


def test_healthz_ok(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_missing_token_is_401(client, tenant):
    r = client.post(f"/admin/tenants/{tenant['id']}/keys", json={})
    assert r.status_code == 401


def test_bad_token_is_401(client, tenant):
    r = client.post(
        f"/admin/tenants/{tenant['id']}/keys",
        headers={"Authorization": "Bearer definitely-not-a-token"},
        json={},
    )
    assert r.status_code == 401


def test_malformed_authorization_header_is_401(client, tenant):
    r = client.post(
        f"/admin/tenants/{tenant['id']}/keys",
        headers={"Authorization": "Basic abc"},
        json={},
    )
    assert r.status_code == 401


def test_gateway_token_cannot_administer(client, tenant):
    priv, pub = new_keypair()
    r = client.post(
        f"/admin/tenants/{tenant['id']}/keys",
        headers={"Authorization": f"Bearer {tenant['gateway_token']}"},
        json={"publicKey": "AAAA"},
    )
    assert r.status_code == 403


def test_tenant_token_cannot_administer(client, tenant):
    r = client.post(
        f"/admin/tenants/{tenant['id']}/keys",
        headers={"Authorization": f"Bearer {tenant['tenant_token']}"},
        json={"publicKey": "AAAA"},
    )
    assert r.status_code == 403


def test_gateway_token_cannot_ingest_other_tenant(client, tenant):
    # 第二个租户的网关令牌打第一个租户的路径 -> 403
    import uuid
    other = client.post(
        "/admin/tenants",
        headers=admin_headers(),
        json={"tenant_id": f"t-{uuid.uuid4().hex[:16]}"},
    ).json()

    body = b'{"x":1}'
    resp = client.post(
        f"/tenants/{tenant['id']}/ingest",
        headers={
            "Authorization": f"Bearer {other['tokens']['gateway']}",
            "X-Tenant-Id": tenant["id"],
            "X-Key-Id": "key-does-not-matter",
            "X-Signature": "AAAA",
            "Content-Type": "application/octet-stream",
        },
        content=body,
    )
    assert resp.status_code == 403


def test_tenant_token_cannot_ingest(client, tenant):
    resp = client.post(
        f"/tenants/{tenant['id']}/ingest",
        headers={
            "Authorization": f"Bearer {tenant['tenant_token']}",
            "X-Tenant-Id": tenant["id"],
            "X-Key-Id": "k",
            "X-Signature": "AAAA",
        },
        content=b"",
    )
    # tenant 令牌不是 gateway 角色 -> 403（在 key 查询前拒绝）
    assert resp.status_code == 403
