"""端到端集成测试：真实 PostgreSQL（asyncpg）+ FastAPI ASGI。

需要数据库可连，否则整体 skip。会清理本测试产生的 sha 行。
"""
from __future__ import annotations

from pathlib import Path

import pytest
import pytest_asyncio

pytestmark = pytest.mark.integration

from httpx import ASGITransport, AsyncClient  # noqa: E402

from app.main import app  # noqa: E402


@pytest_asyncio.fixture(loop_scope="module", scope="module")
async def pool():
    import asyncpg
    from app.config import settings
    from app.db import _parse_dsn
    _, kwargs = _parse_dsn(settings.database_url)
    import json

    async def init_codecs(conn):
        await conn.set_type_codec(
            "jsonb", encoder=lambda v: json.dumps(v, ensure_ascii=False),
            decoder=json.loads, schema="pg_catalog")
        await conn.set_type_codec(
            "json", encoder=lambda v: json.dumps(v, ensure_ascii=False),
            decoder=json.loads, schema="pg_catalog")

    try:
        p = await asyncpg.create_pool(init=init_codecs, min_size=1, max_size=8, **kwargs)
        await p.fetchval("SELECT 1")
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"PostgreSQL not available: {exc}")
    yield p
    await p.close()


@pytest_asyncio.fixture(loop_scope="module")
def client(pool):
    app.state.pool = pool  # ASGITransport 不触发 lifespan，手动注入
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


@pytest.mark.asyncio(loop_scope="module")
async def test_ingest_samples_and_relations(client, pool, samples_dir: Path):
    uploaded = []
    # 先上环的三封
    for name in ("thread_cycle_a.eml", "thread_cycle_b.eml", "thread_cycle_c.eml",
                 "thread_no_mid.eml", "sample_multicharset.eml",
                 "sample_corrupt_wrong_boundary.eml",
                 "sample_corrupt_truncated_b64.eml",
                 "sample_corrupt_no_boundary.eml",
                 "thread_dup_mid.eml"):
        data = (samples_dir / name).read_bytes()
        resp = await client.post(
            "/emls", content=data,
            headers={"Content-Type": "message/rfc822"})
        assert resp.status_code == 201, resp.text
        uploaded.append(resp.json()["eml_sha256"])

    # 多编码邮件的详情
    async with pool.acquire() as conn:
        mc = await conn.fetchrow(
            "SELECT * FROM messages WHERE eml_sha256=ANY($1) "
            "AND subject LIKE '%季度报告%'", uploaded)
    assert mc is not None
    sha = mc["eml_sha256"]

    detail = await client.get(f"/emls/{sha}")
    assert detail.status_code == 200
    body = detail.json()
    assert body["parse_status"] == "ok"
    assert body["body_html"] is None  # 默认不回原始 HTML
    assert "&lt;script&gt;" in body["body_html_escaped"]
    assert any(p["filename_safe"] == "季度合同.pdf" for p in body["parts"])
    assert len(body["addresses"]) >= 2

    # include_raw_html 显式取回
    raw_html = await client.get(f"/emls/{sha}?include_raw_html=true")
    assert "<script>" in raw_html.json()["body_html"]

    # 外部资源登记
    assert "https://img.example.com/tracker.png?user=42" in \
        body["html_external_refs"]

    # 附件落盘且可下载（PDF）
    pdf_part = next(p for p in body["parts"] if p["filename_safe"] == "季度合同.pdf")
    dl = await client.get(f"/emls/{sha}/parts/{pdf_part['mime_path']}")
    assert dl.status_code == 200
    assert dl.content.startswith(b"%PDF")
    assert "attachment" in dl.headers["content-disposition"]
    assert "nosniff" in dl.headers["x-content-type-options"]

    # 内联 GIF 下载
    gif = next(p for p in body["parts"] if p["cid_norm"] == "logo-1@archive.example")
    dl2 = await client.get(f"/emls/{sha}/parts/{gif['mime_path']}")
    assert dl2.status_code == 200 and dl2.content[:3] == b"GIF"

    # 原文下载
    raw = await client.get(f"/emls/{sha}/raw")
    assert raw.status_code == 200
    assert raw.content == (samples_dir / "sample_multicharset.eml").read_bytes()

    # 全文检索
    search = await client.get("/search", params={"q": "营收增长"})
    assert search.status_code == 200
    assert any(h["eml_sha256"] == sha for h in search.json())

    # 环检测
    async with pool.acquire() as conn:
        cyc = await conn.fetch(
            "SELECT DISTINCT message_id FROM identity_conflicts "
            "WHERE conflict_type='reference_cycle'")
    cyc_ids = {r["message_id"] for r in cyc}
    assert {"cycle-a@archive.example", "cycle-b@archive.example",
            "cycle-c@archive.example"} <= cyc_ids

    # 强线程：a 与 b/c 在同一强线程
    async with pool.acquire() as conn:
        a_sha = await conn.fetchval(
            "SELECT eml_sha256 FROM messages WHERE message_id=$1",
            "cycle-a@archive.example")
    thr = await client.get(f"/emls/{a_sha}/thread")
    assert thr.status_code == 200
    strong_ids = {m["message_id"] for m in thr.json()["strong_thread"]}
    assert {"cycle-a@archive.example", "cycle-b@archive.example",
            "cycle-c@archive.example"} <= strong_ids
    # 无 ID 同主题邮件不在强线程中（只能弱候选）
    weak_shas = {w["eml_sha256"] for w in thr.json()["weak_subject_candidates"]}

    # 重复 Message-ID 冲突
    async with pool.acquire() as conn:
        dup = await conn.fetchval(
            "SELECT count(*) FROM identity_conflicts "
            "WHERE conflict_type='duplicate_message_id_in_header' AND eml_sha256=ANY($1)",
            uploaded)
    assert dup >= 1

    # 失败可定位
    fails = await client.get("/failures")
    assert fails.status_code == 200
    fail_shas = {f["eml_sha256"] for f in fails.json()}
    async with pool.acquire() as conn:
        wrong = await conn.fetchrow(
            "SELECT eml_sha256 FROM parse_runs WHERE parse_status='failed' "
            "AND eml_sha256=ANY($1) LIMIT 1", uploaded)
    assert wrong["eml_sha256"] in fail_shas
    one = next(f for f in fails.json() if f["eml_sha256"] == wrong["eml_sha256"])
    assert any(i["kind"] == "StartBoundaryNotFoundDefect" and i["location"] == "1"
               for i in one["issues"])

    # 越界路径必须 400
    bad = await client.get(f"/emls/{sha}/parts/..%2f..%2fetc")
    assert bad.status_code in (400, 404)

    # 清理
    async with pool.acquire() as conn:
        await conn.execute("DELETE FROM raw_emls WHERE eml_sha256=ANY($1)", uploaded)
