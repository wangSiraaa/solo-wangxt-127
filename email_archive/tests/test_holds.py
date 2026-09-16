"""证据保全与到期处置端到端测试（真实 PostgreSQL）。

覆盖验收：
- 正常到期策略仅清除无保全且无活动任务的邮件，留下不可篡改审计；
- 并发相同策略/处置请求只生成一个策略与一个活动运行；
- 处置期间版本回退与重解析被一致协调（409）；
- 清除批次中恢复保全：目标跳过 / 策略重新激活整单中止；
- worker 崩溃重启后从游标继续、墓场对账物理删文件，不产生双向孤儿、不重复审计；
- 无策略邮件与 legacy 形态邮件的查询/下载/重解析保持可用。
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path

import pytest
import pytest_asyncio

pytestmark = pytest.mark.integration

import asyncpg  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402

from app import holds, repository as repo  # noqa: E402
from app.config import settings  # noqa: E402
from app.db import _parse_dsn  # noqa: E402
from app.main import app  # noqa: E402
from app.parser import parse_eml  # noqa: E402
from app.security import sha256_hex  # noqa: E402
from app.worker import ReparseWorker  # noqa: E402

ATT = settings.attachment_dir.resolve()


def _make_eml(mid: str, subject: str = "disposition test",
              pdf: bytes = b"%PDF-1.4 attachment-bytes\n") -> bytes:
    m = EmailMessage()
    m["From"] = "owner@example.cn"
    m["To"] = "archive@example.cn"
    m["Subject"] = subject
    m["Message-ID"] = f"<{mid}>"
    m["Date"] = "Tue, 16 Sep 2026 09:00:00 +0000"
    m.set_content("body text\n")
    m.add_attachment(pdf, maintype="application", subtype="pdf", filename="f.pdf")
    return m.as_bytes()


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
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


async def _ingest(pool, eml: bytes) -> str:
    sha = sha256_hex(eml)
    fact = parse_eml(eml, sha)
    await repo.ingest_initial(pool, fact, eml, None)
    return sha


@pytest_asyncio.fixture(loop_scope="module")
async def scenario(pool, client):
    """构造三封邮件：to_purge / re_held（处置中被另一策略重新保全）/
    with_job（处置时有活动重解析任务）。"""
    e_purge = _make_eml("disp-purge@x", subject="will-purge")
    e_held = _make_eml("disp-reheld@x", subject="will-rehold")
    e_job = _make_eml("disp-job@x", subject="will-job")
    s_purge = await _ingest(pool, e_purge)
    s_held = await _ingest(pool, e_held)
    s_job = await _ingest(pool, e_job)
    shas = {"purge": s_purge, "held": s_held, "job": s_job}
    yield shas, e_purge
    # 清理残余（审计表 append-only 触发器需受控豁免；仅测试使用）
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SET LOCAL app.archive_purge='on'")
            await conn.execute(
                "DELETE FROM disposition_runs WHERE actor IN ('holds-test','system')")
            await conn.execute(
                "DELETE FROM hold_policies WHERE created_by='holds-test'")
    for s in shas.values():
        await repo.purge_eml(pool, s, allow_held=True)


@pytest.mark.asyncio(loop_scope="module")
async def test_01_normal_expiry_purges_only_unheld_unjobbed(client, pool, scenario):
    (shas, eml_purge) = scenario
    now = datetime.now(timezone.utc)

    # 到期策略只覆盖“将被清除”的目标（单封）
    p, created = await holds.create_policy(
        pool, name="case-42", hold_type="single", reason="litigation",
        created_by="holds-test", eml_sha256=shas["purge"],
        expires_at=now + timedelta(hours=1), activate=True)
    # 查询式到期策略也只匹配 purge（验证 query 快照）
    pq, _ = await holds.create_policy(
        pool, name="case-42-q", hold_type="query", reason="litigation",
        created_by="holds-test",
        query_filter={"message_id": "disp-purge@x"},
        expires_at=now + timedelta(hours=1), activate=True)
    policy_q = pq["id"]

    # 另一个目标 held 有未到期保全
    await holds.create_policy(
        pool, name="case-held", hold_type="single", reason="litigation",
        created_by="holds-test", eml_sha256=shas["held"],
        expires_at=now + timedelta(days=1), activate=True)
    # job 目标无保全、但有活动重解析任务（在下方创建后形成 skipped_active_job）

    # 到期
    async with pool.acquire() as conn:
        await conn.execute("UPDATE hold_policies SET expires_at=now()-interval '1 hour', "
                           "status='expired', updated_at=now() WHERE id=ANY($1)",
                           [p["id"], pq["id"]])
        await conn.execute(
            """INSERT INTO hold_policy_events(policy_id,action,actor,detail)
                   SELECT id,'expired','holds-test','tt' FROM hold_policies WHERE id=ANY($1)""",
            [p["id"], pq["id"]])

    # re_held 被另一个 active 策略重新保全
    await holds.create_policy(
        pool, name="ongoing-case", hold_type="single", reason="new matter",
        created_by="holds-test", eml_sha256=shas["held"],
        idempotency_key="holds-test-ongoing", activate=True)

    # with_job 有活动重解析任务
    job, _ = await repo.create_reparse_job(
        pool, shas["job"], "policy.x", "active during disposition", "holds-test")

    # 处置运行显式覆盖三个目标（手动构造：单封到期策略只含 purge，
    # 其余两个目标由本运行纳入，用于验证“仍受保全/有活动任务”的跳过判定）
    run, _ = await holds.create_manual_retention_run(
        pool, actor="holds-test", reason="case-42 expiry",
        idempotency_key="holds-test-case42-run",
        shas=[shas["purge"], shas["held"], shas["job"]])
    # 把该运行挂到到期查询策略上（模拟策略触发），并置策略 purging
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE disposition_runs SET kind='hold_expiry', hold_policy_id=$2 WHERE id=$1",
            run["id"], policy_q)
        await conn.execute(
            "UPDATE hold_policies SET status='purging' WHERE id=$1", policy_q)
    run_id = run["id"]
    # 同一策略重复提交处置 -> 同一运行
    run2, created2 = await holds.create_expiry_disposition_run(
        pool, policy_q, actor="holds-test")
    assert created2 is False and run2["id"] == run_id

    # 第一批：purge 删除、held 跳过；job 因有活动任务待处理
    n = await holds.process_disposition_batch(pool, 10, ATT)
    assert n >= 1
    detail = await holds.get_run_detail(pool, run_id)
    states = {t["eml_sha256"]: t["state"] for t in detail["targets"]}
    assert states[shas["purge"]] == "purged"
    assert states[shas["held"]] == "skipped_held"
    assert states[shas["job"]] == "skipped_active_job"
    # 运行仍在 running（等待活动任务结束），未提前终态
    assert detail["status"] == "running"

    # 被清除的邮件已不可查
    assert (await client.get(f"/emls/{shas['purge']}")).status_code == 404
    # 受保护/有任务的仍可查
    assert (await client.get(f"/emls/{shas['held']}")).status_code == 200
    assert (await client.get(f"/emls/{shas['job']}")).status_code == 200

    # 附件已物理删除（墓场两阶段完成）且无残留 pending
    import time
    for _ in range(20):
        left = await pool.fetchval(
            "SELECT count(*) FROM file_graveyard WHERE run_id=$1 AND state IN ('pending','failed')",
            run_id)
        if not left:
            break
        time.sleep(0.05)
    assert left == 0
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT relpath,state FROM file_graveyard WHERE run_id=$1 ORDER BY id", run_id)
    assert rows and all(r["state"] == "deleted" for r in rows)
    # 文件确实不在磁盘
    for r in rows:
        assert not (ATT / r["relpath"]).exists()

    # 不可篡改审计存在且完整（该邮件无重解析任务，故无 reparse_job 条目）
    audit = await holds.list_audit(pool, shas["purge"])
    kinds = {a["object_type"] for a in audit}
    assert {"raw_eml", "parse_version", "attachment_file"} <= kinds
    raw_audit = next(a for a in audit if a["object_type"] == "raw_eml")
    assert raw_audit["summary"]["version_count"] == 1
    async with pool.acquire() as conn:
        with pytest.raises(Exception) as exc:
            await conn.execute(
                "UPDATE disposition_audit SET reason='hacked' WHERE id=$1",
                audit[0]["id"])
        assert "append-only" in str(exc.value)

    # 取消活动重解析任务后，下一轮游标清除该邮件
    await repo.cancel_job(pool, job["id"])
    # 取消后该邮件无活动任务、无保全；游标 reopen，排空直到本运行终态
    final = await _settle(pool, run_id)
    assert next(t for t in final["targets"]
                if t["eml_sha256"] == shas["job"])["state"] == "purged"

    # 仍受另一策略保护的邮件保留；本运行应已完成（held 被跳过）
    assert next(t for t in final["targets"]
                if t["eml_sha256"] == shas["held"])["state"] == "skipped_held"
    assert final["status"] == "completed"


@pytest.mark.asyncio(loop_scope="module")
async def test_02_concurrent_identical_requests_single_policy_and_run(pool, scenario):
    shas, _ = scenario
    key = "holds-test-concurrent-single"

    async def create():
        return await holds.create_policy(
            pool, name="concurrent", hold_type="single", reason="r",
            created_by="holds-test", eml_sha256=shas["held"],
            idempotency_key=key, activate=True)

    results = await asyncio_gather(create, 8)
    ids = {r[0]["id"] for r in results}
    assert len(ids) == 1
    assert sum(1 for r in results if r[1]) == 1

    # 手动到期处置：相同 idempotency_key 并发也只一个运行
    async def manual():
        return await holds.create_manual_retention_run(
            pool, actor="holds-test", reason="concurrent manual",
            idempotency_key="holds-test-manual-concurrent",
            shas=[shas["held"]])
    mr = await asyncio_gather(manual, 6)
    run_ids = {r[0]["id"] for r in mr}
    assert len(run_ids) == 1
    assert sum(1 for r in mr if r[1]) == 1
    # 该目标受保全，处置应跳过而不删除
    detail = await _settle(pool, next(iter(run_ids)))
    assert next(t for t in detail["targets"]
                if t["eml_sha256"] == shas["held"])["state"] == "skipped_held"


async def asyncio_gather(fn, n: int):
    import asyncio
    return await asyncio.gather(*[fn() for _ in range(n)])


async def _settle(pool, run_id, rounds: int = 50):
    """驱动批次直到指定运行进入终态（批次总是取最旧 running 运行，故循环排空）。"""
    import asyncio
    for _ in range(rounds):
        await holds.process_disposition_batch(pool, 10, ATT)
        d = await holds.get_run_detail(pool, run_id)
        if d["status"] in ("completed", "aborted", "failed"):
            return d
        await asyncio.sleep(0.02)
    return await holds.get_run_detail(pool, run_id)


@pytest.mark.asyncio(loop_scope="module")
async def test_03_reparse_and_rollback_blocked_during_disposition(pool, client, scenario):
    # 自建邮件与保全，避免依赖前序用例可能已处置的 scenario 目标
    target = await _ingest(pool, _make_eml("disp-block@x"))
    try:
        await holds.create_policy(
            pool, name="block-hold", hold_type="single", reason="held",
            created_by="holds-test", eml_sha256=target,
            idempotency_key="holds-test-block-hold", activate=True)
        # 一个 pending 处置运行覆盖受保护邮件（它会先 skipped_held，但运行仍 running）
        run, _ = await holds.create_manual_retention_run(
            pool, actor="holds-test", reason="block check",
            idempotency_key="holds-test-block-run", shas=[target])

        # 处置运行的游标中存在该 EML（pending）-> 拒绝新建重解析
        with pytest.raises(repo.HeldByDisposition):
            await repo.create_reparse_job(
                pool, target, "policy.blocked", "x", "holds-test")
        r = await client.post(f"/emls/{target}/reparse",
                              json={"policy_version": "policy.blocked", "reason": "x"})
        assert r.status_code == 409

        # 版本回退同样被协调拒绝（运行未结束）
        r2 = await client.post(f"/emls/{target}/versions/1/activate")
        assert r2.status_code == 409

        # 运行处理完（目标 skipped_held，运行 completed）后恢复允许
        await holds.process_disposition_batch(pool, 10, ATT)
        detail = await holds.get_run_detail(pool, run["id"])
        assert detail["status"] == "completed"
        job, created = await repo.create_reparse_job(
            pool, target, "policy.after", "x", "holds-test")
        assert created
        worker = ReparseWorker(pool, worker_id="holds-test-worker", poll_interval=.01)
        await worker.run_once()
        j = await repo.get_job(pool, job["id"])
        assert j["status"] == "succeeded"
    finally:
        await repo.purge_eml(pool, target, allow_held=True)


@pytest.mark.asyncio(loop_scope="module")
async def test_04_mid_batch_rehold_skips_target_and_policy_reactivation_aborts(pool, scenario):
    # 两封新邮件：a 先删，b 在删前被新策略重新保全 -> skipped_held
    sa = await _ingest(pool, _make_eml("disp-mid-a@x"))
    sb = await _ingest(pool, _make_eml("disp-mid-b@x"))
    try:
        run, _ = await holds.create_manual_retention_run(
            pool, actor="holds-test", reason="mid-batch",
            idempotency_key="holds-test-midbatch", shas=[sa, sb])
        # 只处理一批中的一个（batch_size=1）
        await holds.process_disposition_batch(pool, 1, ATT)
        d = await holds.get_run_detail(pool, run["id"])
        assert next(t for t in d["targets"] if t["eml_sha256"] == sa)["state"] == "purged"

        # 在继续前恢复对 sb 的保全
        await holds.create_policy(
            pool, name="late-hold", hold_type="single", reason="late",
            created_by="holds-test", eml_sha256=sb,
            idempotency_key="holds-test-late", activate=True)
        await holds.process_disposition_batch(pool, 10, ATT)
        d = await holds.get_run_detail(pool, run["id"])
        assert next(t for t in d["targets"] if t["eml_sha256"] == sb)["state"] == "skipped_held"
        assert await pool.fetchval("SELECT 1 FROM raw_emls WHERE eml_sha256=$1", sb)

        # 策略型运行在处置中被重新激活 -> 整单安全中止，未处理目标保持完整
        sc = await _ingest(pool, _make_eml("disp-abort@x"))
        try:
            pol, _ = await holds.create_policy(
                pool, name="abort-case", hold_type="single", reason="x",
                created_by="holds-test", eml_sha256=sc,
                expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
                activate=False)
            # 直接置 expired 并建运行
            async with pool.acquire() as conn:
                await conn.execute("UPDATE hold_policies SET status='expired' WHERE id=$1", pol["id"])
            erun, _ = await holds.create_expiry_disposition_run(
                pool, pol["id"], actor="holds-test")
            # 处置中策略被重新激活（操作员紧急恢复保全）
            async with pool.acquire() as conn:
                await conn.execute(
                    "UPDATE hold_policies SET status='active', updated_at=now() WHERE id=$1",
                    pol["id"])
            import asyncio
            for _ in range(60):
                await holds.process_disposition_batch(pool, 10, ATT)
                ed = await holds.get_run_detail(pool, erun["id"])
                if ed["status"] in ("completed", "aborted", "failed"):
                    break
                await asyncio.sleep(0.02)
            ed = await holds.get_run_detail(pool, erun["id"])
            assert ed["status"] == "aborted"
            # 未处理的邮件完整可读
            assert await pool.fetchval("SELECT 1 FROM raw_emls WHERE eml_sha256=$1", sc)
            assert (await repo.get_version_detail(pool, sc)) is not None
        finally:
            await repo.purge_eml(pool, sc, allow_held=True)
    finally:
        await repo.purge_eml(pool, sa, allow_held=True)
        await repo.purge_eml(pool, sb, allow_held=True)


@pytest.mark.asyncio(loop_scope="module")
async def test_05_crash_recovery_cursor_and_graveyard_no_orphans(pool, scenario):
    """模拟：一邮件已删库但文件未删（崩溃在物理删除前），重启后对账；
    游标 pending 目标继续处理；审计不重复。"""
    sa = await _ingest(pool, _make_eml("disp-crash-a@x"))
    sb = await _ingest(pool, _make_eml("disp-crash-b@x"))
    rels = []
    try:
        run, _ = await holds.create_manual_retention_run(
            pool, actor="holds-test", reason="crash",
            idempotency_key="holds-test-crash", shas=[sa, sb])
        # 处理 sa
        await holds.process_disposition_batch(pool, 1, ATT)
        # 正常路径已删文件；把文件放回去并把墓场行重置为 pending，模拟“库已删、文件未删”
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT id,relpath FROM file_graveyard WHERE run_id=$1 AND eml_sha256=$2",
                run["id"], sa)
        # 重新造一个占位文件（模拟崩溃残留）
        for r in rows:
            fp = ATT / r["relpath"]
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_bytes(b"orphan-on-disk")
            assert fp.exists()
            rels.append((r["relpath"], fp))
        async with pool.acquire() as conn:
            await conn.execute(
                """UPDATE file_graveyard SET state='pending', deleted_at=NULL,
                       attempts=0, last_error=NULL WHERE run_id=$1 AND eml_sha256=$2""",
                run["id"], sa)

        # 模拟进程重启：新 worker 只做对账 + 继续游标（幂等重复调用）
        await holds.delete_pending_graveyard(pool, ATT)
        await holds.delete_pending_graveyard(pool, ATT)  # 第二次不应报错/重复
        for rel, fp in rels:
            assert not fp.exists(), f"orphan file survived: {rel}"

        # 游标继续处理 sb
        await holds.process_disposition_batch(pool, 10, ATT)
        d = await holds.get_run_detail(pool, run["id"])
        assert {t["eml_sha256"]: t["state"] for t in d["targets"]} == \
            {sa: "purged", sb: "purged"}
        assert d["status"] == "completed"

        # 审计每对象仅一条（UNIQUE 去重，恢复未重复写）
        async with pool.acquire() as conn:
            dup = await conn.fetch(
                """SELECT eml_sha256,object_type,object_ref,count(*) c
                     FROM disposition_audit WHERE run_id=$1
                    GROUP BY 1,2,3 HAVING count(*)>1""", run["id"])
        assert dup == []
        # 被删版本摘要可追溯
        raw = next(a for a in d["audit"] if a["object_type"] == "raw_eml"
                   and a["eml_sha256"] == sa)
        assert raw["object_ref"] == sa
    finally:
        await repo.purge_eml(pool, sa, allow_held=True)
        await repo.purge_eml(pool, sb, allow_held=True)


@pytest.mark.asyncio(loop_scope="module")
async def test_06_hold_blocks_direct_delete_and_keeps_legacy_access(pool, client, scenario):
    shas, eml_purge = scenario
    # 自建一个 active 保全，避免依赖跨用例状态
    await holds.create_policy(
        pool, name="direct-delete-guard", hold_type="single", reason="guard",
        created_by="holds-test", eml_sha256=shas["held"],
        idempotency_key="holds-test-direct-guard", activate=True)
    # 受 active 保全：直接受控清除被拒
    with pytest.raises(repo.RepoError):
        await repo.purge_eml(pool, shas["held"])

    # 未设置策略的普通邮件：查询、下载、重解析全部可用（与 legacy-v1 同路径）
    free = await _ingest(pool, _make_eml("disp-free@x"))
    try:
        d = await client.get(f"/emls/{free}")
        assert d.status_code == 200 and d.json()["version_no"] == 1
        detail = d.json()
        part = next(p for p in detail["parts"] if p["filename_safe"] == "f.pdf")
        dl = await client.get(f"/emls/{free}/parts/{part['mime_path']}")
        assert dl.status_code == 200 and dl.content.startswith(b"%PDF")
        job, created = await repo.create_reparse_job(
            pool, free, "policy.free", "no hold applies", "holds-test")
        assert created
        worker = ReparseWorker(pool, worker_id="holds-free", poll_interval=.01)
        assert await worker.run_once() is True
        j = await repo.get_job(pool, job["id"])
        assert j["status"] == "succeeded"
        versions = (await client.get(f"/emls/{free}/versions")).json()
        assert [v["version_no"] for v in versions] == [2, 1]
    finally:
        await repo.purge_eml(pool, free)
