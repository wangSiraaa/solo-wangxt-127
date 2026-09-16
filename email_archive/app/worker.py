"""重解析后台 worker：启动恢复过期租约 -> 轮询领取 -> 执行。

- claim_due_job 用行锁 SKIP LOCKED，execute_job 用会话咨询锁保证同 EML 串行；
- 心跳续约；进程崩溃时租约过期，下次启动 recover_stale_running 转回 queued；
- parse_fn 可注入（测试用），默认走标准库解析器。
"""
from __future__ import annotations

import asyncio
import logging
import os
import socket
import uuid

import asyncpg

from . import repository as repo
from .config import settings
from .parser import parse_eml

log = logging.getLogger("archive.worker")


class ReparseWorker:
    def __init__(self, pool: asyncpg.Pool, *,
                 worker_id: str | None = None,
                 poll_interval: float | None = None,
                 lease_seconds: int | None = None,
                 parse_fn=parse_eml):
        self.pool = pool
        self.worker_id = worker_id or f"{socket.gethostname()}-{uuid.uuid4().hex[:8]}"
        self.poll_interval = poll_interval if poll_interval is not None else \
            float(os.environ.get("WORKER_POLL_INTERVAL", "1.0"))
        self.lease_seconds = lease_seconds or \
            int(os.environ.get("WORKER_LEASE_SECONDS", "300"))
        self.parse_fn = parse_fn
        self._stop = asyncio.Event()
        self._task: asyncio.Task | None = None
        self.jobs_processed = 0

    async def startup(self) -> int:
        """恢复过期租约任务，返回转回 queued 的任务数。"""
        n = await repo.recover_stale_running(
            self.pool, self.lease_seconds, self.worker_id)
        if n:
            log.info("recovered %d stale jobs at startup", n)
        return n

    async def run_forever(self) -> None:
        log.info("reparse worker %s started", self.worker_id)
        while not self._stop.is_set():
            try:
                did = await self.run_once()
            except Exception:  # noqa: BLE001
                log.exception("worker iteration error")
                did = False
            if not did:
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=self.poll_interval)
                except asyncio.TimeoutError:
                    pass
        log.info("reparse worker %s stopped", self.worker_id)

    async def run_once(self) -> bool:
        """领取并执行一个到期任务；无任务/被推迟返回 False。"""
        job = await repo.claim_due_job(
            self.pool, self.worker_id, self.lease_seconds)
        if not job:
            return False
        result = await repo.execute_job(
            self.pool, job["id"], parse_fn=self.parse_fn,
            worker_id=self.worker_id, attachment_dir=settings.attachment_dir,
            lease_seconds=self.lease_seconds)
        log.info("job=%s terminal=%s", job["id"], result)
        self.jobs_processed += 1
        return True

    def start(self) -> None:
        self._task = asyncio.create_task(self.run_forever())

    async def stop(self) -> None:
        self._stop.set()
        if self._task:
            try:
                await asyncio.wait_for(self._task, timeout=5)
            except asyncio.TimeoutError:
                self._task.cancel()


async def wait_until_job_settles(pool: asyncpg.Pool, job_id: int,
                                 timeout: float = 10.0) -> dict | None:
    """测试/管理辅助：轮询直到任务进入终态或超时。"""
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        d = await repo.get_job(pool, job_id)
        if d and d["status"] in ("succeeded", "failed", "cancelled"):
            return d
        await asyncio.sleep(0.05)
    return await repo.get_job(pool, job_id)
