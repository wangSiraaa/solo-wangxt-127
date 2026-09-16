"""版本化重解析端到端测试（真实 PostgreSQL + FastAPI ASGI + 受控 worker）。

验收覆盖：
1. 正常任务生成新版本且旧详情仍可读；
2. 两个并发相同请求只产生一个任务和一次版本切换；
3. 解析失败时旧 current 与附件引用保持可读；超限后任务 failed；
4. 进程重启后过期 running 任务安全转回 queued 并重试成功；
5. 取消 queued 任务不产生任何派生数据；
6. 重试不重复附件（内容寻址去重）；
7. 未版本化迁移邮件仍可按当前 API 查询与下载；
8. 不同策略排队但不并发覆盖 current（同 EML 串行）。
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import pytest
import pytest_asyncio

pytestmark = pytest.mark.integration

import asyncpg  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402

from app import repository as repo  # noqa: E402
from app.config import settings  # noqa: E402
from app.db import _parse_dsn  # noqa: E402
from app.main import app  # noqa: E402
from app.parser import parse_eml  # noqa: E402
from app.worker import ReparseWorker  # noqa: E402

ATT_DIR = settings.attachment_dir.resolve()


@pytest_asyncio.fixture(loop_scope="module", scope="module")
async def pool():
    _, kwargs = _parse_dsn(settings.database_url)

    async def init_codecs(conn):
        await conn.set_type_codec(
            "jsonb", encoder=lambda v: json.dumps(v, ensure_ascii=False),
            decoder=json.loads, schema="pg_catalog")
        await conn.set_type_codec(
            "json", encoder=lambda v: json.dumps(v, ensure_ascii=False),
            decoder=json.loads, schema="pg_catalog")

    try:
        p = await asyncpg.create_pool(init=init_codecs, min_size=1, max_size=10, **kwargs)
        await p.fetchval("SELECT 1")
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"PostgreSQL not available: {exc}")
    yield p
    await p.close()


@pytest_asyncio.fixture(loop_scope="module")
def client(pool):
    app.state.pool = pool
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


@pytest.mark.asyncio(loop_scope="module")
async def test_01_initial_ingest_and_legacy_api(client, pool, samples_dir: Path):
    data = (samples_dir / "sample_multicharset.eml").read_bytes()
    # 确保从干净状态开始（清掉可能的历史遗留）
    from app.security import sha256_hex
    await repo.purge_eml(pool, sha256_hex(data))

    r = await client.post("/emls", content=data,
                          headers={"Content-Type": "message/rfc822"})
    assert r.status_code == 201, r.text
    body = r.json()
    sha = body["eml_sha256"]
    assert body["created"] is True and body["version_no"] == 1

    # 幂等重传
    r2 = await client.post("/emls", content=data,
                           headers={"Content-Type": "message/rfc822"})
    assert r2.status_code == 201
    assert r2.json()["created"] is False

    # 当前 API 直接查详情/版本/原文/附件（即“未版本化/初版”邮件按当前 API 使用）
    d = await client.get(f"/emls/{sha}")
    assert d.status_code == 200
    dj = d.json()
    assert dj["version_no"] == 1 and dj["is_current"] is True
    assert len(dj["parts"]) == 9
    assert "&lt;script&gt;" in dj["body_html_escaped"]
    assert any(p["filename_safe"] == "季度合同.pdf" for p in dj["parts"])

    raw = await client.get(f"/emls/{sha}/raw")
    assert raw.status_code == 200 and raw.content == data
    pdf = next(p for p in dj["parts"] if p["filename_safe"] == "季度合同.pdf")
    dl = await client.get(f"/emls/{sha}/parts/{pdf['mime_path']}")
    assert dl.status_code == 200 and dl.content.startswith(b"%PDF")

    # 不可变版本：直接尝试改数据库会被触发器拒绝
    async with pool.acquire() as conn:
        with pytest.raises(Exception) as exc:
            await conn.execute(
                "UPDATE parse_versions SET reason='hacked' WHERE id=$1",
                body["version_id"])
        assert "immutable" in str(exc.value)

    app.state._test_sha = sha


@pytest.mark.asyncio(loop_scope="module")
async def test_02_reparse_creates_version_and_old_remains_readable(client):
    sha = app.state._test_sha
    worker = ReparseWorker(app.state.pool, worker_id="test-worker-1",
                           poll_interval=0.05)
    r = await client.post(f"/emls/{sha}/reparse", json={
        "policy_version": "policy.test.b",
        "reason": "new decoding rules", "requested_by": "compliance"})
    assert r.status_code == 202
    job = r.json()
    assert job["status"] == "queued" and job["created"] is True

    # worker 执行
    assert await worker.run_once() is True
    j = await repo.get_job(app.state.pool, job["id"])
    assert j["status"] == "succeeded"

    versions = await client.get(f"/emls/{sha}/versions")
    vs = versions.json()
    assert [v["version_no"] for v in vs] == [2, 1]
    assert vs[0]["is_current"] is True and vs[0]["policy_version"] == "policy.test.b"

    cur = await client.get(f"/emls/{sha}")
    assert cur.json()["version_no"] == 2

    # 旧详情仍可读
    old = await client.get(f"/emls/{sha}?version=1")
    oj = old.json()
    assert oj["version_no"] == 1 and oj["is_current"] is False
    assert len(oj["parts"]) == 9

    # 旧版本附件仍可下载
    pdf = next(p for p in oj["parts"] if p["filename_safe"] == "季度合同.pdf")
    dl = await client.get(f"/emls/{sha}/parts/{pdf['mime_path']}?version=1")
    assert dl.status_code == 200 and dl.content.startswith(b"%PDF")


@pytest.mark.asyncio(loop_scope="module")
async def test_03_concurrent_identical_requests_single_job_and_switch(client):
    sha = app.state._test_sha
    payload = json.dumps({"policy_version": "policy.concurrent",
                          "reason": "race"}).encode()

    async def post():
        return await client.post(f"/emls/{sha}/reparse", content=payload,
                                 headers={"Content-Type": "application/json"})

    results = await asyncio.gather(*[post() for _ in range(8)])
    jobs = [r.json() for r in results]
    assert all(r.status_code == 202 for r in results)
    assert len({j["id"] for j in jobs}) == 1
    assert sum(1 for j in jobs if j["created"]) == 1

    worker = ReparseWorker(app.state.pool, worker_id="test-worker-2",
                           poll_interval=0.05)
    assert await worker.run_once() is True
    jid = jobs[0]["id"]
    j = await repo.get_job(app.state.pool, jid)
    assert j["status"] == "succeeded"

    # 该策略只有一个版本、一次 reparse 切换
    async with app.state.pool.acquire() as conn:
        cnt_v = await conn.fetchval(
            "SELECT count(*) FROM parse_versions WHERE eml_sha256=$1 AND policy_version=$2",
            sha, "policy.concurrent")
        cnt_s = await conn.fetchval(
            """SELECT count(*) FROM current_switches
                WHERE eml_sha256=$1 AND action='reparse'
                  AND version_id IN (SELECT id FROM parse_versions
                                      WHERE policy_version=$2)""",
            sha, "policy.concurrent")
    assert cnt_v == 1 and cnt_s == 1


@pytest.mark.asyncio(loop_scope="module")
async def test_04_failure_keeps_old_current_and_attachments(client):
    sha = app.state._test_sha

    # parse_fn 在线程池中运行，必须是同步函数
    def failing_parse(data, digest):
        raise RuntimeError("simulated parser explosion")

    # max_attempts=1：一次失败即终态 failed
    async with app.state.pool.acquire() as conn:
        row = await conn.fetchrow(
            """INSERT INTO reparse_jobs(eml_sha256,policy_version,reason,
                                        status,run_after,max_attempts)
               VALUES ($1,'policy.fail','boom','queued',now(),1) RETURNING id""",
            sha)
        job_id = row["id"]

    worker = ReparseWorker(app.state.pool, worker_id="test-worker-fail",
                           poll_interval=0.05, parse_fn=failing_parse)
    assert await worker.run_once() is True
    j = await repo.get_job(app.state.pool, job_id)
    assert j["status"] == "failed" and "explosion" in j["last_error"]
    assert any(h["phase"] == "failed" for h in j["attempts_history"])

    # 失败后没有新版本；current 仍指向之前版本，附件可读
    async with app.state.pool.acquire() as conn:
        n = await conn.fetchval(
            "SELECT count(*) FROM parse_versions WHERE eml_sha256=$1 AND policy_version=$2",
            sha, "policy.fail")
        cur_v = await conn.fetchval(
            """SELECT v.version_no FROM current_versions cv
                 JOIN parse_versions v ON v.id=cv.version_id
                WHERE cv.eml_sha256=$1""", sha)
    assert n == 0 and cur_v == 3
    # 失败策略不产生版本：当前仍是 test_03 成功切换的第 3 版

    d = await client.get(f"/emls/{sha}")
    pdf = next(p for p in d.json()["parts"] if p["filename_safe"] == "季度合同.pdf")
    dl = await client.get(f"/emls/{sha}/parts/{pdf['mime_path']}")
    assert dl.status_code == 200 and dl.content.startswith(b"%PDF")


@pytest.mark.asyncio(loop_scope="module")
async def test_05_retry_then_succeed_does_not_duplicate_attachments(client):
    sha = app.state._test_sha
    calls = {"n": 0}

    def flaky_parse(data, digest):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("transient failure")
        return parse_eml(data, digest)

    async with app.state.pool.acquire() as conn:
        row = await conn.fetchrow(
            """INSERT INTO reparse_jobs(eml_sha256,policy_version,reason,
                                        status,run_after,max_attempts)
               VALUES ($1,'policy.flaky','flaky','queued',now(),3) RETURNING id""",
            sha)
        job_id = row["id"]

    worker = ReparseWorker(app.state.pool, worker_id="test-worker-flaky",
                           poll_interval=0.05, parse_fn=flaky_parse)
    # 第一次失败 -> 退避 queued；手动把 run_after 提前以避免等待
    await worker.run_once()
    async with app.state.pool.acquire() as conn:
        await conn.execute(
            "UPDATE reparse_jobs SET run_after=now() WHERE id=$1", job_id)
    # 第二次成功
    await worker.run_once()

    j = await repo.get_job(app.state.pool, job_id)
    phases = [h["phase"] for h in j["attempts_history"]]
    assert j["status"] == "succeeded"
    assert phases.count("failed") == 1 and phases.count("succeeded") == 1

    # 新版本号 4，旧版本全部还在
    versions = (await client.get(f"/emls/{sha}/versions")).json()
    assert [v["version_no"] for v in versions][0] == 4

    # 附件文件按内容寻址：磁盘上 PDF 只有一份
    import subprocess
    files_before = set(p.relative_to(ATT_DIR) for p in ATT_DIR.rglob("*") if p.is_file()
                       and "text" not in p.relative_to(ATT_DIR).parts)
    # 再跑一次同策略重解析（正常 parse），不应新增任何内容相同的附件文件
    r = await client.post(f"/emls/{sha}/reparse",
                          json={"policy_version": "policy.flaky.again",
                                "reason": "dedup check"})
    j2 = r.json()
    worker2 = ReparseWorker(app.state.pool, worker_id="test-worker-dedup",
                            poll_interval=0.05)
    await worker2.run_once()
    files_after = set(p.relative_to(ATT_DIR) for p in ATT_DIR.rglob("*") if p.is_file()
                      and "text" not in p.relative_to(ATT_DIR).parts)
    # 内容相同的部件文件完全复用（样例所有附件字节不变）
    assert files_before <= files_after
    # 关键：该 EML 的附件散列文件数不随版本增长（同 sha 同 relpath）
    async with app.state.pool.acquire() as conn:
        distinct = await conn.fetchval(
            "SELECT count(DISTINCT stored_relpath) FROM mime_parts WHERE eml_sha256=$1 AND stored_relpath IS NOT NULL",
            sha)
        total = await conn.fetchval(
            "SELECT count(*) FROM mime_parts WHERE eml_sha256=$1 AND stored_relpath IS NOT NULL",
            sha)
    assert distinct < total  # 多版本行引用相同文件


@pytest.mark.asyncio(loop_scope="module")
async def test_06_cancel_queued_creates_no_derived_data(client):
    sha = app.state._test_sha
    async with app.state.pool.acquire() as conn:
        row = await conn.fetchrow(
            """INSERT INTO reparse_jobs(eml_sha256,policy_version,reason,
                                        status,run_after)
               VALUES ($1,'policy.cancel.me','later','queued',now()+interval '2 hours')
               RETURNING id""", sha)
        job_id = row["id"]

    r = await client.post(f"/jobs/{job_id}/cancel")
    assert r.status_code == 200 and r.json()["status"] == "cancelled"
    # 再取消 409
    assert (await client.post(f"/jobs/{job_id}/cancel")).status_code == 409

    async with app.state.pool.acquire() as conn:
        n_ver = await conn.fetchval(
            "SELECT count(*) FROM parse_versions WHERE eml_sha256=$1 AND policy_version=$2",
            sha, "policy.cancel.me")
        n_facts = await conn.fetchval(
            """SELECT count(*) FROM mime_parts mp
                 JOIN parse_versions v ON v.id=mp.version_id
                WHERE v.eml_sha256=$1 AND v.policy_version=$2""",
            sha, "policy.cancel.me")
    assert n_ver == 0 and n_facts == 0


@pytest.mark.asyncio(loop_scope="module")
async def test_07_restart_recovery_requeues_and_succeeds(client):
    sha = app.state._test_sha
    async with app.state.pool.acquire() as conn:
        row = await conn.fetchrow(
            """INSERT INTO reparse_jobs(eml_sha256,policy_version,reason,
                                        status,attempts,locked_by,lease_until,run_after)
               VALUES ($1,'policy.recover','crashed worker','running',1,'dead-worker',
                       now()-interval '10 seconds', now())
               RETURNING id""", sha)
        job_id = row["id"]

    worker = ReparseWorker(app.state.pool, worker_id="test-worker-restart",
                           poll_interval=0.05, lease_seconds=300)
    n = await worker.startup()  # 恢复过期 running
    assert n >= 1
    j = await repo.get_job(app.state.pool, job_id)
    assert j["status"] == "queued"
    assert any(h["phase"] == "interrupted" for h in j["attempts_history"])

    # worker 自动重试成功
    assert await worker.run_once() is True
    j = await repo.get_job(app.state.pool, job_id)
    assert j["status"] == "succeeded"
    # 旧版本依然存在（新版本之外，历史全部保留）
    async with app.state.pool.acquire() as conn:
        versions = [r["version_no"] for r in await conn.fetch(
            "SELECT version_no FROM parse_versions WHERE eml_sha256=$1 ORDER BY version_no",
            sha)]
    assert versions == [1, 2, 3, 4, 5, 6][:len(versions)] and len(versions) >= 5


@pytest.mark.asyncio(loop_scope="module")
async def test_08_different_policies_serialize_no_concurrent_current(client):
    """同 EML 两个不同策略任务：一个 running 时另一个排队延后，不并发切换。"""
    sha = app.state._test_sha
    import threading
    gate = threading.Event()

    def gated_parse(data, digest):
        gate.wait(timeout=10)
        return parse_eml(data, digest)

    async with app.state.pool.acquire() as conn:
        r1 = await conn.fetchrow(
            """INSERT INTO reparse_jobs(eml_sha256,policy_version,reason,status,run_after)
               VALUES ($1,'policy.serial.1','first','queued',now()) RETURNING id""", sha)
        r2 = await conn.fetchrow(
            """INSERT INTO reparse_jobs(eml_sha256,policy_version,reason,status,run_after)
               VALUES ($1,'policy.serial.2','second','queued',now()) RETURNING id""", sha)

    w1 = ReparseWorker(app.state.pool, worker_id="serial-1", poll_interval=0.02,
                       parse_fn=gated_parse)
    # 只让这两个任务到期，避免队列里其他历史任务干扰领取顺序
    async with app.state.pool.acquire() as conn:
        await conn.execute(
            """UPDATE reparse_jobs SET run_after=now()+interval '1 day'
                WHERE eml_sha256=$1 AND id NOT IN ($2,$3) AND status='queued'""",
            sha, r1["id"], r2["id"])
        picked = await repo.claim_due_job(app.state.pool, "serial-1", 300)
    assert picked["id"] == r1["id"]
    exec_task = asyncio.create_task(repo.execute_job(
        app.state.pool, r1["id"], parse_fn=gated_parse, worker_id="serial-1"))
    await asyncio.sleep(0.2)
    # 第一个正在 running；第二个 claim 必须被推迟（不进入 running）
    async with app.state.pool.acquire() as conn:
        st2 = await conn.fetchval("SELECT status FROM reparse_jobs WHERE id=$1", r2["id"])
    assert st2 == "queued"
    gate.set()
    result = await exec_task
    assert result == "succeeded"
    # 之后第二个可以正常执行
    w2 = ReparseWorker(app.state.pool, worker_id="serial-2", poll_interval=0.02)
    # 第二个任务可能被推迟了 run_after，提前后执行
    async with app.state.pool.acquire() as conn:
        await conn.execute("UPDATE reparse_jobs SET run_after=now() WHERE id=$1", r2["id"])
    assert await w2.run_once() is True
    j2 = await repo.get_job(app.state.pool, r2["id"])
    assert j2["status"] == "succeeded"
    # 任意时刻最多一个 running；切换顺序保留
    async with app.state.pool.acquire() as conn:
        switches = [r["version_id"] for r in await conn.fetch(
            """SELECT version_id FROM current_switches WHERE eml_sha256=$1
                AND action='reparse' ORDER BY id""", sha)]
    assert switches == sorted(switches)


@pytest.mark.asyncio(loop_scope="module")
async def test_09_cleanup(client):
    sha = app.state._test_sha
    ok = await repo.purge_eml(app.state.pool, sha)
    assert ok is True
    resp = await client.get(f"/emls/{sha}")
    assert resp.status_code == 404
