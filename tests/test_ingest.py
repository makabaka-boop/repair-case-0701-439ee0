"""网关报文提交：验签、回执、线性化点、超限。"""
import pytest

from conftest import (
    b64url,
    enroll,
    ingest,
    new_keypair,
    promote,
    receipt_count,
    retire,
    sign,
)


@pytest.fixture
def tenant_with_current(client, tenant):
    priv, pub = new_keypair()
    kid = enroll(client, tenant["id"], pub).json()["keyId"]
    return tenant, kid, priv


def test_empty_body_accepted_with_receipt(client, tenant_with_current):
    tenant, kid, priv = tenant_with_current
    before = receipt_count(client, tenant["id"])
    r = ingest(client, tenant, kid, priv=priv, body=b"")
    assert r.status_code == 202, r.text
    data = r.json()
    assert data["receiptId"]
    assert data["role"] == "current"
    assert receipt_count(client, tenant["id"]) == before + 1


def test_three_active_roles_all_verify(client, tenant):
    p0, pub0 = new_keypair()
    p1, pub1 = new_keypair()
    k0 = enroll(client, tenant["id"], pub0).json()["keyId"]
    k1 = enroll(client, tenant["id"], pub1).json()["keyId"]
    assert promote(client, tenant["id"], k1).status_code == 200
    # 此刻 k1=current, k0=retiring；再登记候选
    p2, pub2 = new_keypair()
    # k0 仍 retiring，登记会被拒；先退休 k0
    assert retire(client, tenant["id"], k0).status_code == 200
    k2 = enroll(client, tenant["id"], pub2).json()["keyId"]

    roles = {k0: ("retired", p0), k1: ("current", p1), k2: ("candidate", p2)}
    body = b"cold-chain-telemetry"

    # current / candidate 在用 -> 202
    for kid in (k1, k2):
        _, priv = roles[kid]
        r = ingest(client, tenant, kid, priv=priv, body=body)
        assert r.status_code == 202, (kid, r.text)

    # 重新构造 retiring 场景：提升 k2 -> k1 变 retiring，k2 current，k0 retired
    assert promote(client, tenant["id"], k2).status_code == 200
    r = ingest(client, tenant, k1, priv=p1, body=body)
    assert r.status_code == 202, r.text
    assert r.json()["role"] == "retiring"


def test_bad_signature_is_400_and_no_receipt(client, tenant_with_current):
    tenant, kid, priv = tenant_with_current
    before = receipt_count(client, tenant["id"])
    r = ingest(client, tenant, kid, priv=priv, body=b"abc",
               signature=b64url(b"\x00" * 64))
    assert r.status_code == 400
    assert r.json()["error"] == "INVALID_SIGNATURE"
    assert receipt_count(client, tenant["id"]) == before


def test_signature_covers_raw_bytes(client, tenant_with_current):
    tenant, kid, priv = tenant_with_current
    body = b"\x00\x01\x02\xff raw \xc3\xa9"
    # 对原始字节签名 -> 通过
    r = ingest(client, tenant, kid, priv=priv, body=body)
    assert r.status_code == 202, r.text
    # 对不同字节的签名 -> 失败
    r2 = ingest(client, tenant, kid, priv=priv, body=body,
                signature=sign(priv, body + b"x"))
    assert r2.status_code == 400


def test_retired_key_after_snapshot_is_key_retired(client, tenant):
    p0, pub0 = new_keypair()
    p1, pub1 = new_keypair()
    k0 = enroll(client, tenant["id"], pub0).json()["keyId"]
    k1 = enroll(client, tenant["id"], pub1).json()["keyId"]
    promote(client, tenant["id"], k1)

    # 退休前（snapshot=retiring）可成功
    r = ingest(client, tenant, k0, priv=p0, body=b"before")
    assert r.status_code == 202

    retire(client, tenant["id"], k0)

    # 退休后 -> KEY_RETIRED
    r = ingest(client, tenant, k0, priv=p0, body=b"after")
    assert r.status_code == 409
    assert r.json()["error"] == "KEY_RETIRED"


def test_unknown_key_is_key_unknown(client, tenant_with_current):
    tenant, _, priv = tenant_with_current
    r = ingest(client, tenant, "key-never-registered", priv=priv, body=b"x")
    assert r.status_code == 404
    assert r.json()["error"] == "KEY_UNKNOWN"


def test_cross_tenant_keyid_is_key_unknown(client, tenant):
    # 别的租户的 keyId 在本租户下也必须是 KEY_UNKNOWN（统一口径）
    import uuid
    other = client.post(
        "/admin/tenants",
        headers={"Authorization": "Bearer platform-admin-token"},
        json={"tenant_id": f"t-{uuid.uuid4().hex[:16]}"},
    )
    other_id = other.json()["tenantId"]

    _, pub = new_keypair()
    from conftest import enroll as _enroll
    kid = _enroll(client, other_id, pub).json()["keyId"]

    # 先为本租户登记一把 current，确保鉴权/大小检查都过
    p_me, pub_me = new_keypair()
    _enroll(client, tenant["id"], pub_me)

    r = ingest(client, tenant, kid, priv=p_me, body=b"x")
    assert r.status_code == 404
    assert r.json()["error"] == "KEY_UNKNOWN"


def test_body_exactly_limit_ok(client, tenant_with_current):
    tenant, kid, priv = tenant_with_current
    body = b"a" * 1048576
    r = ingest(client, tenant, kid, priv=priv, body=body)
    assert r.status_code == 202, r.text


def test_body_over_limit_is_413(client, tenant_with_current):
    tenant, kid, priv = tenant_with_current
    body = b"a" * 1048577
    r = ingest(client, tenant, kid, priv=priv, body=body)
    assert r.status_code == 413
    assert r.json()["error"] == "PAYLOAD_TOO_LARGE"


def test_malformed_signature_encoding_is_400(client, tenant_with_current):
    tenant, kid, priv = tenant_with_current
    r = ingest(client, tenant, kid, body=b"x", signature="@@@not-base64@@@")
    assert r.status_code == 400
    assert r.json()["error"] == "MALFORMED_SIGNATURE"


def test_wrong_length_signature_is_400(client, tenant_with_current):
    tenant, kid, priv = tenant_with_current
    r = ingest(client, tenant, kid, body=b"x", signature=b64url(b"\x01" * 32))
    assert r.status_code == 400
    assert r.json()["error"] == "MALFORMED_SIGNATURE"


def test_missing_headers_are_400(client, tenant):
    headers = {
        "Authorization": f"Bearer {tenant['gateway_token']}",
        "X-Tenant-Id": tenant["id"],
    }
    r = client.post(f"/tenants/{tenant['id']}/ingest", headers=headers, content=b"")
    assert r.status_code == 400
