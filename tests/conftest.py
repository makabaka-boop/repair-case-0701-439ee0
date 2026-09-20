"""共享夹具：对运行中的 API 实例做黑盒验收。

环境变量：
    API_BASE_URL           默认 http://localhost:8080
    PLATFORM_ADMIN_TOKEN  默认 platform-admin-token
"""
from __future__ import annotations

import base64
import os
import threading
import time
import uuid

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

API_BASE_URL = os.environ.get("API_BASE_URL", "http://localhost:8080").rstrip("/")
ADMIN_TOKEN = os.environ.get("PLATFORM_ADMIN_TOKEN", "platform-admin-token")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@pytest.fixture(scope="session")
def client() -> httpx.Client:
    with httpx.Client(base_url=API_BASE_URL, timeout=30.0) as c:
        yield c


@pytest.fixture(scope="session", autouse=True)
def _wait_for_api(client: httpx.Client):
    deadline = time.time() + 60
    last = None
    while time.time() < deadline:
        try:
            r = client.get("/healthz")
            if r.status_code == 200:
                return
        except httpx.TransportError as exc:
            last = exc
        time.sleep(0.5)
    pytest.fail(f"API 未就绪: {API_BASE_URL} ({last})")


def admin_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {ADMIN_TOKEN}"}


@pytest.fixture
def tenant(client: httpx.Client) -> dict:
    """创建一个全新租户，返回 {id, tenant_token, gateway_token}。"""
    r = client.post(
        "/admin/tenants",
        headers=admin_headers(),
        json={"tenant_id": f"t-{uuid.uuid4().hex[:16]}"},
    )
    assert r.status_code == 201, r.text
    data = r.json()
    return {
        "id": data["tenantId"],
        "tenant_token": data["tokens"]["tenant"],
        "gateway_token": data["tokens"]["gateway"],
    }


def new_keypair() -> tuple[Ed25519PrivateKey, bytes]:
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key().public_bytes_raw()


def enroll(client: httpx.Client, tenant_id: str, public_key: bytes,
           key_id: str | None = None) -> httpx.Response:
    payload: dict = {"publicKey": b64url(public_key)}
    if key_id:
        payload["keyId"] = key_id
    return client.post(
        f"/admin/tenants/{tenant_id}/keys",
        headers=admin_headers(),
        json=payload,
    )


def promote(client: httpx.Client, tenant_id: str, key_id: str) -> httpx.Response:
    return client.post(
        f"/admin/tenants/{tenant_id}/keys/{key_id}/promote",
        headers=admin_headers(),
    )


def retire(client: httpx.Client, tenant_id: str, key_id: str) -> httpx.Response:
    return client.post(
        f"/admin/tenants/{tenant_id}/keys/{key_id}/retire",
        headers=admin_headers(),
    )


def list_keys(client: httpx.Client, tenant_id: str) -> list[dict]:
    r = client.get(f"/admin/tenants/{tenant_id}/keys", headers=admin_headers())
    assert r.status_code == 200, r.text
    return r.json()["keys"]


def sign(priv: Ed25519PrivateKey, body: bytes) -> str:
    return b64url(priv.sign(body))


def ingest(client: httpx.Client, tenant: dict, key_id: str,
           token: str | None = None, body: bytes = b"",
           signature: str | None = None, priv: Ed25519PrivateKey | None = None,
           extra_headers: dict | None = None) -> httpx.Response:
    headers = {
        "Authorization": f"Bearer {token or tenant['gateway_token']}",
        "X-Tenant-Id": tenant["id"],
        "X-Key-Id": key_id,
        "X-Signature": signature if signature is not None else sign(priv, body),
        "Content-Type": "application/octet-stream",
    }
    if extra_headers:
        headers.update(extra_headers)
    return client.post(
        f"/tenants/{tenant['id']}/ingest",
        headers=headers,
        content=body,
    )


def receipt_count(client: httpx.Client, tenant_id: str) -> int:
    r = client.get(
        f"/admin/tenants/{tenant_id}/receipts?limit=1000",
        headers=admin_headers(),
    )
    assert r.status_code == 200, r.text
    return len(r.json()["receipts"])


def assert_invariant(client: httpx.Client, tenant_id: str) -> dict[str, list[str]]:
    """登记后：current 恰一把；candidate/retiring 各至多一把。"""
    grouped: dict[str, list[str]] = {}
    for k in list_keys(client, tenant_id):
        if k["role"] != "retired":
            grouped.setdefault(k["role"], []).append(k["keyId"])
    assert len(grouped.get("current", [])) == 1, grouped
    assert len(grouped.get("candidate", [])) <= 1, grouped
    assert len(grouped.get("retiring", [])) <= 1, grouped
    return grouped


def run_concurrently(fn, n: int) -> list:
    """用屏障同时释放 n 个线程，尽量制造真实竞态。"""
    barrier = threading.Barrier(n)
    results: list = [None] * n

    def worker(i: int):
        barrier.wait()
        try:
            results[i] = fn(i)
        except Exception as exc:  # 不让异常吞掉断言
            results[i] = exc

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results
