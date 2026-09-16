"""asyncpg 连接池：支持 unix socket 的 postgresql:// 连接串。"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

import asyncpg
from fastapi import Request

from .config import settings

log = logging.getLogger("archive.db")
_pool: asyncpg.Pool | None = None


def _parse_dsn(dsn: str) -> tuple[str, dict]:
    """把 postgresql://user@/db?host=/tmp 拆成 asyncpg 关键字。"""
    parts = urlsplit(dsn)
    kwargs: dict = {}
    if parts.username:
        kwargs["user"] = unquote(parts.username)
    if parts.password:
        kwargs["password"] = unquote(parts.password)
    kwargs["database"] = parts.path.lstrip("/") or None
    q = parse_qs(parts.query)
    if "host" in q:
        kwargs["host"] = q["host"][0]
    elif parts.hostname:
        kwargs["host"] = parts.hostname
        kwargs["port"] = parts.port or 5432
    kwargs["ssl"] = q.get("sslmode", ["prefer"])[0] in ("require", "verify-full")
    if kwargs["ssl"] is False:
        kwargs.pop("ssl")
    return parts.path.lstrip("/") or "postgres", kwargs


async def init_pool() -> asyncpg.Pool:
    global _pool
    if _pool is None:
        _, kwargs = _parse_dsn(settings.database_url)
        log.info("connecting to PostgreSQL database=%s host=%s",
                 kwargs.get("database"), kwargs.get("host"))

        async def _init_codecs(conn: asyncpg.Connection) -> None:
            import json
            await conn.set_type_codec(
                "jsonb", encoder=lambda v: json.dumps(v, ensure_ascii=False),
                decoder=json.loads, schema="pg_catalog")
            await conn.set_type_codec(
                "json", encoder=lambda v: json.dumps(v, ensure_ascii=False),
                decoder=json.loads, schema="pg_catalog")

        _pool = await asyncpg.create_pool(
            min_size=1, max_size=8, timeout=30,
            server_settings={"application_name": "eml-archive"},
            init=_init_codecs,
            **kwargs,
        )
    return _pool


async def close_pool() -> None:
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None


async def get_pool(request: Request) -> asyncpg.Pool:
    return request.app.state.pool


@asynccontextmanager
async def transaction(pool: asyncpg.Pool):
    async with pool.acquire() as conn:
        async with conn.transaction():
            yield conn


async def apply_schema(pool: asyncpg.Pool, schema_path: Path) -> None:
    sql = schema_path.read_text(encoding="utf-8")
    async with pool.acquire() as conn:
        await conn.execute(sql)
