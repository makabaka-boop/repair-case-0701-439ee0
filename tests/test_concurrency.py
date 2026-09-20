"""并发压力：角色不变量必须在任意交错下保持。"""
import uuid

from conftest import (
    assert_invariant,
    enroll,
    ingest,
    new_keypair,
    promote,
    receipt_count,
    retire,
    run_concurrently,
)


def test_concurrent_first_enrollment_single_current(client, tenant):
    # 空租户上并发登记：事务在租户行锁上串行化 ——
    # 第一把成 current、第二把合法成 candidate（无 candidate/retiring）、其余 409。
    run = uuid.uuid4().hex[:8]
    pairs = [new_keypair() for _ in range(8)]

    def attempt(i):
        priv, pub = pairs[i]
        return enroll(client, tenant["id"], pub,
                      key_id=f"key-race-first-{run}-{i:04d}").status_code

    codes = run_concurrently(attempt, 8)
    assert codes.count(201) == 2, codes  # current + candidate 各一把
    assert all(c in (201, 409) for c in codes), codes
    grouped = assert_invariant(client, tenant["id"])
    assert len(grouped["current"]) == 1
    assert len(grouped.get("candidate", [])) == 1
    assert "retiring" not in grouped


def test_concurrent_second_enrollment_single_candidate(client, tenant):
    _, pub0 = new_keypair()
    run = uuid.uuid4().hex[:8]
    k0 = enroll(client, tenant["id"], pub0).json()["keyId"]
    assert k0
    pairs = [new_keypair() for _ in range(8)]

    def attempt(i):
        _, pub = pairs[i]
        return enroll(client, tenant["id"], pub,
                      key_id=f"key-race-cand-{run}-{i:04d}").status_code

    codes = run_concurrently(attempt, 8)
    assert codes.count(201) == 1, codes
    assert_invariant(client, tenant["id"])


def test_concurrent_promotions(client, tenant):
    _, pub0 = new_keypair()
    k0 = enroll(client, tenant["id"], pub0).json()["keyId"]
    k1 = enroll(client, tenant["id"], new_keypair()[1]).json()["keyId"]

    # 多个候选并发提升同一把 candidate：恰一个成功
    def attempt(_i):
        return promote(client, tenant["id"], k1).status_code

    codes = run_concurrently(attempt, 6)
    assert codes.count(200) == 1, codes
    assert all(c in (200, 409) for c in codes), codes
    grouped = assert_invariant(client, tenant["id"])
    assert grouped["current"] == [k1]
    assert grouped.get("retiring") == [k0]
    assert "candidate" not in grouped


def test_concurrent_full_rotation_chain(client, tenant):
    """连续轮换：每轮 candidate 登记 -> 提升 -> 旧 retiring 退休，全部并发交错。"""
    _, pub0 = new_keypair()
    run = uuid.uuid4().hex[:8]
    enroll(client, tenant["id"], pub0, key_id=f"key-chain-{run}-0000")
    rounds = 6

    def round_txn(r):
        _, pub = new_keypair()
        kid = f"key-chain-{run}-{r:04d}"
        out = []
        e = enroll(client, tenant["id"], pub, key_id=kid)
        out.append(("enroll", e.status_code))
        if e.status_code == 201 and e.json()["role"] == "candidate":
            p = promote(client, tenant["id"], kid)
            out.append(("promote", p.status_code))
            if p.status_code == 200:
                snap = {k["keyId"]: k["role"] for k in p.json()["snapshot"]}
                old_retiring = next(
                    (k for k, role in snap.items() if role == "retiring"), None
                )
                if old_retiring:
                    rt = retire(client, tenant["id"], old_retiring)
                    out.append(("retire", rt.status_code))
        return out

    results = run_concurrently(round_txn, rounds)
    # 每一步状态码必须合法，不允许 5xx
    for out in results:
        for step, code in out:
            assert code in (200, 201, 409, 404), (step, code, out)

    # 无论怎么交错，不变量始终成立；且最终应能收敛
    grouped = assert_invariant(client, tenant["id"])
    assert len(grouped["current"]) == 1

    # 最终把所有 retiring 退休后，系统应能继续登记（不死锁、不残留脏状态）
    for old in grouped.get("retiring", []):
        assert retire(client, tenant["id"], old).status_code == 200
    _, pub_next = new_keypair()
    r = enroll(client, tenant["id"], pub_next)
    assert r.status_code in (201, 409)
    assert_invariant(client, tenant["id"])


def test_concurrent_ingest_vs_retire_linearizable(client, tenant):
    """退休与验签赛跑：每个请求要么 202 要么 409，绝不 5xx；总数对得上。"""
    priv, pub = new_keypair()
    k0 = enroll(client, tenant["id"], pub).json()["keyId"]
    # 制造 k0=retiring：再上一把候选并提升
    p1, pub1 = new_keypair()
    k1 = enroll(client, tenant["id"], pub1).json()["keyId"]
    assert promote(client, tenant["id"], k1).status_code == 200

    before = receipt_count(client, tenant["id"])
    n_ingest = 8
    accepted = {"n": 0}
    import threading
    lock = threading.Lock()

    def do_ingest(i):
        r = ingest(client, tenant, k0, priv=priv, body=f"msg-{i}".encode())
        with lock:
            if r.status_code == 202:
                accepted["n"] += 1
            else:
                assert r.status_code == 409 and r.json()["error"] == "KEY_RETIRED", r.text
        return r.status_code

    def do_retire(_i):
        return retire(client, tenant["id"], k0).status_code

    # 2 个退休 + 8 个验签同时释放
    results = []

    def combined(i):
        if i < 2:
            return ("retire", do_retire(i))
        return ("ingest", do_ingest(i))

    out = run_concurrently(combined, 2 + n_ingest)
    retire_codes = [c for kind, c in out if kind == "retire"]
    ingest_codes = [c for kind, c in out if kind == "ingest"]

    assert retire_codes.count(200) == 1, retire_codes
    assert all(c in (200, 409) for c in retire_codes)
    assert all(c in (202, 409) for c in ingest_codes)

    after = receipt_count(client, tenant["id"])
    assert after - before == accepted["n"] == ingest_codes.count(202)
    assert_invariant(client, tenant["id"])
