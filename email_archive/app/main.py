"""FastAPI 应用入口：无前端，只提供 JSON/受控下载接口。"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI

from . import db
from .api import router
from .config import settings
from .logging_setup import configure_logging
from .worker import ReparseWorker

log = logging.getLogger("archive.main")

DB_DIR = Path(__file__).resolve().parent.parent / "db"
SCHEMA_PATH = DB_DIR / "schema.sql"
MIGRATIONS_DIR = DB_DIR / "migrations"


async def _prepare_database(pool) -> None:
    """fresh 库装全量 schema；旧（非版本化）库依次跑迁移。幂等。"""
    async with pool.acquire() as conn:
        has_versions = await conn.fetchval(
            "SELECT to_regclass('public.parse_versions') IS NOT NULL")
        if has_versions:
            # 已是版本化库；幂等补齐新对象
            await conn.execute(SCHEMA_PATH.read_text(encoding="utf-8"))
            return
        has_raw = await conn.fetchval(
            "SELECT to_regclass('public.raw_emls') IS NOT NULL")
        if not has_raw:
            await conn.execute(SCHEMA_PATH.read_text(encoding="utf-8"))
            log.info("initialized fresh schema")
            return
        # 旧库：逐个执行 migrations
        await conn.execute(
            """CREATE TABLE IF NOT EXISTS schema_migrations (
                   name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())""")
        applied = {r["name"] for r in await conn.fetch(
            "SELECT name FROM schema_migrations")}
        for mig in sorted(MIGRATIONS_DIR.glob("*.sql")):
            if mig.name in applied:
                continue
            log.info("applying migration %s", mig.name)
            await conn.execute(mig.read_text(encoding="utf-8"))
            await conn.execute(
                "INSERT INTO schema_migrations(name) VALUES ($1) ON CONFLICT DO NOTHING",
                mig.name)


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    pool = await db.init_pool()
    await _prepare_database(pool)
    app.state.pool = pool

    worker = ReparseWorker(pool)
    app.state.worker = worker
    await worker.startup()
    if not __import__("os").environ.get("DISABLE_WORKER"):
        worker.start()

    log.info("email archive API ready; attachment_dir=%s worker=%s",
             settings.attachment_dir, worker.worker_id)
    yield

    await worker.stop()
    await db.close_pool()


app = FastAPI(
    title="Enterprise EML Archive API",
    version="2.0.0",
    description="Parse EML into immutable, versioned, searchable mail facts. "
                "No UI, no remote fetch, no script execution.",
    lifespan=lifespan,
)
app.include_router(router)


@app.get("/health")
async def health():
    pool = app.state.pool
    ver = await pool.fetchval("SELECT version()")
    return {"status": "ok", "postgresql": ver.split(",")[0]}
