"""数据库连接池与 schema 初始化。"""
from __future__ import annotations

import asyncio
from pathlib import Path

import asyncpg

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schema.sql"


async def create_pool(dsn: str) -> asyncpg.Pool:
    """创建连接池，等待 PostgreSQL 就绪（compose 启动竞态）。"""
    last_error: Exception | None = None
    for attempt in range(60):
        try:
            pool = await asyncpg.create_pool(
                dsn, min_size=2, max_size=10, timeout=10
            )
            break
        except (OSError, asyncpg.PostgresError) as exc:  # pragma: no cover - 启动竞态
            last_error = exc
            await asyncio.sleep(1)
    else:  # pragma: no cover
        raise RuntimeError(f"数据库不可达: {last_error}")

    async with pool.acquire() as conn:
        await conn.execute(SCHEMA_PATH.read_text(encoding="utf-8"))
    return pool
