"""密钥生命周期状态机与角色权威口径。"""
import base64

from conftest import (
    admin_headers,
    assert_invariant,
    b64url,
    enroll,
    list_keys,
    new_keypair,
    promote,
    retire,
)


def test_first_key_becomes_current(client, tenant):
    priv, pub = new_keypair()
    r = enroll(client, tenant["id"], pub)
    assert r.status_code == 201, r.text
    assert r.json()["role"] == "current"
    assert_invariant(client, tenant["id"])


def test_second_key_without_retiring_becomes_candidate(client, tenant):
    _, pub1 = new_keypair()
    _, pub2 = new_keypair()
    enroll(client, tenant["id"], pub1)
    r = enroll(client, tenant["id"], pub2)
    assert r.status_code == 201, r.text
    assert r.json()["role"] == "candidate"
    assert_invariant(client, tenant["id"])


def test_cannot_enroll_when_candidate_exists(client, tenant):
    # current + candidate 已占：第三把必须 409
    for _ in range(2):
        _, pub = new_keypair()
        enroll(client, tenant["id"], pub)
    _, pub3 = new_keypair()
    r = enroll(client, tenant["id"], pub3)
    assert r.status_code == 409
    body = r.json()
    assert body["error"] == "CANDIDATE_BLOCKED"
    roles = {k["role"] for k in body["snapshot"]}
    assert roles == {"current", "candidate"}


def test_cannot_enroll_when_retiring_exists(client, tenant):
    # current + retiring（提升过一次）时登记 -> 409
    _, pub1 = new_keypair()
    _, pub2 = new_keypair()
    k1 = enroll(client, tenant["id"], pub1).json()["keyId"]
    k2 = enroll(client, tenant["id"], pub2).json()["keyId"]
    promote(client, tenant["id"], k2)  # k2->current, k1->retiring

    _, pub3 = new_keypair()
    r = enroll(client, tenant["id"], pub3)
    assert r.status_code == 409
    assert r.json()["error"] == "CANDIDATE_BLOCKED"
    assert r.json()["blockingRole"] == "retiring"
    assert_invariant(client, tenant["id"])


def test_promote_is_atomic(client, tenant):
    _, pub1 = new_keypair()
    _, pub2 = new_keypair()
    k1 = enroll(client, tenant["id"], pub1).json()["keyId"]
    k2 = enroll(client, tenant["id"], pub2).json()["keyId"]

    r = promote(client, tenant["id"], k2)
    assert r.status_code == 200, r.text
    snap = {k["keyId"]: k["role"] for k in r.json()["snapshot"]}
    assert snap[k2] == "current"   # 候选变当前
    assert snap[k1] == "retiring"  # 旧当前变退役中
    assert_invariant(client, tenant["id"])


def test_promote_non_candidate_is_409_with_authoritative_role(client, tenant):
    _, pub1 = new_keypair()
    _, pub2 = new_keypair()
    k1 = enroll(client, tenant["id"], pub1).json()["keyId"]
    k2 = enroll(client, tenant["id"], pub2).json()["keyId"]

    # 当前钥不可提升 -> 409 且权威角色为 current
    r = promote(client, tenant["id"], k1)
    assert r.status_code == 409
    assert r.json()["error"] == "ILLEGAL_TRANSITION"
    assert r.json()["authoritativeRole"] == "current"
    assert any(k["role"] == "current" for k in r.json()["snapshot"])

    # 提升 k2 后 k1 变 retiring；再提升 k2（当前钥）仍是 409
    assert promote(client, tenant["id"], k2).status_code == 200
    r = promote(client, tenant["id"], k2)
    assert r.status_code == 409
    assert r.json()["authoritativeRole"] == "current"


def test_retire_marks_retired(client, tenant):
    _, pub1 = new_keypair()
    _, pub2 = new_keypair()
    k1 = enroll(client, tenant["id"], pub1).json()["keyId"]
    k2 = enroll(client, tenant["id"], pub2).json()["keyId"]
    promote(client, tenant["id"], k2)

    r = retire(client, tenant["id"], k1)
    assert r.status_code == 200, r.text
    assert r.json()["role"] == "retired"
    # 退休后只有 k2 一把 current
    grouped = assert_invariant(client, tenant["id"])
    assert grouped["current"] == [k2]
    assert "retiring" not in grouped


def test_retire_current_is_409_authoritative(client, tenant):
    _, pub1 = new_keypair()
    k1 = enroll(client, tenant["id"], pub1).json()["keyId"]
    r = retire(client, tenant["id"], k1)
    assert r.status_code == 409
    assert r.json()["authoritativeRole"] == "current"


def test_retire_unknown_key_is_key_unknown(client, tenant):
    _, pub = new_keypair()
    enroll(client, tenant["id"], pub)
    r = retire(client, tenant["id"], "key-does-not-exist")
    assert r.status_code == 404
    assert r.json()["error"] == "KEY_UNKNOWN"


def test_full_rotation_cycle_allows_re_enrollment(client, tenant):
    # 退休完成后 retiring 槽位释放，可再登记 candidate
    pairs = [new_keypair() for _ in range(3)]
    k0 = enroll(client, tenant["id"], pairs[0][1]).json()["keyId"]
    k1 = enroll(client, tenant["id"], pairs[1][1]).json()["keyId"]
    promote(client, tenant["id"], k1)
    assert retire(client, tenant["id"], k0).status_code == 200

    k2 = enroll(client, tenant["id"], pairs[2][1])
    assert k2.status_code == 201, k2.text
    assert k2.json()["role"] == "candidate"
    assert_invariant(client, tenant["id"])


def test_duplicate_keyid_is_409(client, tenant):
    import uuid
    kid = f"key-fixed-{uuid.uuid4().hex[:16]}"
    _, pub1 = new_keypair()
    _, pub2 = new_keypair()
    enroll(client, tenant["id"], pub1, key_id=kid)
    r = enroll(client, tenant["id"], pub2, key_id=kid)
    assert r.status_code == 409
    assert r.json()["error"] == "KEY_EXISTS"
    assert r.json()["authoritativeRole"] == "current"


def test_bad_public_key_length_is_400(client, tenant):
    r = client.post(
        f"/admin/tenants/{tenant['id']}/keys",
        headers=admin_headers(),
        json={"publicKey": b64url(b"\x00" * 31)},
    )
    assert r.status_code == 400
    assert r.json()["error"] == "INVALID_PUBLIC_KEY"


def test_keys_of_other_tenant_are_unknown(client, tenant):
    import uuid
    other = client.post(
        "/admin/tenants",
        headers=admin_headers(),
        json={"tenant_id": f"t-{uuid.uuid4().hex[:16]}"},
    )
    other_id = other.json()["tenantId"]

    _, pub = new_keypair()
    kid = enroll(client, other_id, pub).json()["keyId"]

    # 从 tenant 视角看 other 的 keyId -> KEY_UNKNOWN
    r = promote(client, tenant["id"], kid)
    assert r.status_code == 404
    assert r.json()["error"] == "KEY_UNKNOWN"
