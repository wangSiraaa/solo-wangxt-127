"""后台 worker：重解析任务 + 保全到期处置。

每轮：
1. 重解析：claim_due_job/execute_job（租约 + 每-EML 咨询锁）；
2. 到期扫描：expire_due_policies -> 为 expired 策略创建处置运行；
3. 处置批处理：process_disposition_batch（游标恢复，一邮件一事务）；
4. 墓场对账：delete_pending_graveyard（崩溃后补偿物理删文件）。

进程启动时恢复过期 running 重解析任务；处置运行本身无内存状态，重启后从
disposition_run_targets(pending) 游标继续。
"""
from __future__ import annotations

import asyncio
import logging
import os
import socket
import uuid

import asyncpg

from . import holds, repository as repo
from .config import settings
from .parser import parse_eml

log = logging.getLogger("archive.worker")


class ReparseWorker:
    def __init__(self, pool: asyncpg.Pool, *,
                 worker_id: str | None = None,
                 poll_interval: float | None = None,
                 lease_seconds: int | None = None,
                 disposition_batch_size: int = 25,
                 parse_fn=parse_eml):
        self.pool = pool
        self.worker_id = worker_id or f"{socket.gethostname()}-{uuid.uuid4().hex[:8]}"
        self.poll_interval = poll_interval if poll_interval is not None else \
            float(os.environ.get("WORKER_POLL_INTERVAL", "1.0"))
        self.lease_seconds = lease_seconds or \
            int(os.environ.get("WORKER_LEASE_SECONDS", "300"))
        self.batch_size = disposition_batch_size
        self.parse_fn = parse_fn
        self._stop = asyncio.Event()
        self._task: asyncio.Task | None = None
        self.jobs_processed = 0

    async def startup(self) -> int:
        """恢复过期租约任务，返回转回 queued 的任务数。"""
        return await repo.recover_stale_running(
            self.pool, self.lease_seconds, self.worker_id)

    async def run_forever(self) -> None:
        log.info("worker %s started", self.worker_id)
        while not self._stop.is_set():
            try:
                busy = await self.run_once()
            except Exception:  # noqa: BLE001
                log.exception("worker iteration error")
                busy = True
            if not busy:
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=self.poll_interval)
                except asyncio.TimeoutError:
                    pass
        log.info("worker %s stopped", self.worker_id)

    async def run_once(self) -> bool:
        """执行一轮：有活返回 True（下轮立即继续），无活返回 False。"""
        did = False

        # 1) 重解析：一轮排空所有可领取任务，避免被处置运行长期抢占
        while True:
            job = await repo.claim_due_job(
                self.pool, self.worker_id, self.lease_seconds)
            if not job:
                break
            result = await repo.execute_job(
                self.pool, job["id"], parse_fn=self.parse_fn,
                worker_id=self.worker_id, attachment_dir=settings.attachment_dir,
                lease_seconds=self.lease_seconds)
            log.info("reparse job=%s terminal=%s", job["id"], result)
            self.jobs_processed += 1
            did = True

        # 2) 到期策略 -> 处置运行
        try:
            due = await holds.expire_due_policies(self.pool)
            for pid in due:
                run, created = await holds.create_expiry_disposition_run(
                    self.pool, pid, actor=self.worker_id)
                log.info("expired hold %s disposition run=%s created=%s",
                         pid, run["id"], created)
                did = True
        except holds.PolicyStateError:
            pass  # 已被其他 worker 处理

        # 3) 处置批处理
        n = await holds.process_disposition_batch(
            self.pool, self.batch_size, settings.attachment_dir)
        if n:
            log.info("disposition processed %d targets", n)
            did = True

        # 4) 墓场对账（崩溃后 pending 文件补偿）
        deleted = await holds.delete_pending_graveyard(
            self.pool, settings.attachment_dir, limit=200)
        if deleted:
            log.info("graveyard reconciled %d files", deleted)
            did = True

        return did

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
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        d = await repo.get_job(pool, job_id)
        if d and d["status"] in ("succeeded", "failed", "cancelled"):
            return d
        await asyncio.sleep(0.05)
    return await repo.get_job(pool, job_id)


async def wait_until_run_settles(pool: asyncpg.Pool, run_id: int,
                                 timeout: float = 10.0) -> dict | None:
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        d = await holds.get_run_detail(pool, run_id)
        if d and d["status"] in ("completed", "aborted", "failed"):
            return d
        await asyncio.sleep(0.05)
    return await holds.get_run_detail(pool, run_id)
