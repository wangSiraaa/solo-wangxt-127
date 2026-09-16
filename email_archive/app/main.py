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

log = logging.getLogger("archive.main")

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "db" / "schema.sql"


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    pool = await db.init_pool()
    # 启动时确保 schema 存在（CREATE TABLE IF NOT EXISTS）
    await db.apply_schema(pool, SCHEMA_PATH)
    app.state.pool = pool
    log.info("email archive API ready; attachment_dir=%s", settings.attachment_dir)
    yield
    await db.close_pool()


app = FastAPI(
    title="Enterprise EML Archive API",
    version="1.0.0",
    description="Parse EML into searchable mail facts. No UI, no remote fetch, no script execution.",
    lifespan=lifespan,
)
app.include_router(router)


@app.get("/health")
async def health():
    pool = app.state.pool
    ver = await pool.fetchval("SELECT version()")
    return {"status": "ok", "postgresql": ver.split(",")[0]}
