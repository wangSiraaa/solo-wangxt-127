"""版本化持久化与重解析编排。

写入模型
- 初次入库：raw_emls + parse_versions(v1, source=ingest) + 全部版本化事实
  + current_versions 指针 + current_switches 审计；幂等（同 sha 直接返回当前版本）。
- 重解析：worker 为任务创建新 parse_versions 与事实；只有全部成功后，在同一事务内
  更新 current_versions 指针。失败时旧版本与附件引用完全不动。
- parse_versions 由数据库触发器禁止改删；受控清除须 SET LOCAL app.archive_purge='on'。
- 附件按内容寻址，跨版本天然去重；任务失败留下的孤儿文件无害且重试时复用。
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

import asyncpg

from . import threads
from .config import PARSER_VERSION, settings
from .parser import MailFact
from .security import storage_relpath, write_attachment

log = logging.getLogger("archive.repo")

DEFAULT_POLICY_VERSION = "policy.v2.0"


class RepoError(Exception):
    pass


# ============================================================ 版本事实写入

async def _write_part_files(fact: MailFact, base_dir: Path) -> dict[str, str]:
    """叶子部件落受控目录，返回 mime_path -> relpath。内容寻址，重复执行不产生重复文件。"""
    paths: dict[str, str] = {}
    for p in fact.parts:
        if p.payload is None or p.is_container:
            continue
        should_store = (
            p.is_attachment
            or p.is_inline
            or p.content_type.lower() == "message/rfc822"
            or not p.content_type.startswith("text/")
            or (p.content_type.startswith("text/") and not p.is_body)
        )
        if not should_store or not p.sha256:
            continue
        rel = storage_relpath(fact.eml_sha256, p.sha256)
        size = await asyncio.to_thread(write_attachment, base_dir, rel, p.payload)
        paths[p.mime_path] = rel
        log.info("stored part eml=%s path=%s type=%s size=%d",
                 fact.eml_sha256[:12], p.mime_path, p.content_type, size)
    return paths


def _spill_text(text: str | None, eml_sha: str, version_no: int, label: str,
                base_dir: Path, limit: int) -> tuple[str | None, str | None]:
    if text is None:
        return None, None
    if len(text) <= limit:
        return text, None
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:24]
    rel = f"text/{eml_sha[:2]}/{eml_sha[2:4]}/v{version_no}-{digest}-{label}.txt"
    target = base_dir / rel
    if not str(target.resolve()).startswith(str(base_dir.resolve()) + "/"):
        raise RepoError("text path traversal blocked")
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        target.write_text(text, encoding="utf-8")
    return None, rel


async def _insert_version_facts(conn: asyncpg.Connection, fact: MailFact,
                                version_id: int, version_no: int,
                                stored: dict[str, str], base_dir: Path) -> None:
    """在已开启的事务内向指定版本写入全部事实。不触碰 current 指针。"""
    sha = fact.eml_sha256
    body_text, body_text_path = _spill_text(
        fact.body_text, sha, version_no, "body-text", base_dir, settings.inline_text_limit)
    body_html, body_html_path = _spill_text(
        fact.body_html, sha, version_no, "body-html", base_dir, settings.inline_text_limit)
    body_esc, body_esc_path = _spill_text(
        fact.body_html_escaped, sha, version_no, "body-html-escaped",
        base_dir, settings.inline_text_limit)

    await conn.execute(
        """INSERT INTO messages(
               version_id, eml_sha256, message_id, message_id_raw, message_id_count,
               subject, subject_raw, date_raw, sent_at,
               from_raw, sender_raw, reply_to_raw, to_raw, cc_raw, bcc_raw,
               in_reply_to, in_reply_to_raw, references_list, references_raw,
               raw_headers, body_text, body_text_path, body_html,
               body_html_escaped, body_html_path, body_html_escaped_path,
               body_charset, html_external_refs, has_attachments)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,
                   $16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29)""",
        version_id, sha, fact.message_id, fact.message_id_raw, fact.message_id_count,
        fact.subject, fact.subject_raw, fact.date_raw, fact.sent_at,
        fact.from_raw, fact.sender_raw, fact.reply_to_raw,
        fact.to_raw, fact.cc_raw, fact.bcc_raw,
        fact.in_reply_to, fact.in_reply_to_raw, fact.references_list,
        fact.references_raw, fact.raw_headers,
        body_text, body_text_path, body_html,
        body_esc, body_html_path, body_esc_path, fact.body_charset,
        fact.html_external_refs, any(p.is_attachment for p in fact.parts),
    )

    # 参与方
    for a in fact.addresses:
        row = await conn.fetchrow(
            """INSERT INTO addresses(email_norm, email_raw)
               VALUES ($1,$2)
               ON CONFLICT (email_norm) DO UPDATE SET email_raw=EXCLUDED.email_raw
               RETURNING id""",
            a["email_norm"], a["email"] or "")
        await conn.execute(
            """INSERT INTO message_addresses(version_id, eml_sha256, address_id,
                                             role, position, display_name)
               VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING""",
            version_id, sha, row["id"], a["role"], a["position"], a["display_name"])

    # MIME 部件
    for p in fact.parts:
        await conn.execute(
            """INSERT INTO mime_parts(
                   version_id, eml_sha256, part_no, mime_path, depth, content_type,
                   content_type_params, disposition, filename_raw, filename_safe,
                   charset, content_id, cid_norm, transfer_encoding, size_bytes,
                   is_container, is_attachment, is_inline, is_body,
                   stored_relpath, sha256, nested_message_id, nested_subject)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,
                       $16,$17,$18,$19,$20,$21,$22,$23)""",
            version_id, sha, p.part_no, p.mime_path, p.depth, p.content_type,
            p.content_type_params, p.disposition, p.filename_raw, p.filename_safe,
            p.charset, p.content_id, p.cid_norm, p.transfer_encoding, p.size_bytes,
            p.is_container, p.is_attachment, p.is_inline, p.is_body,
            stored.get(p.mime_path), p.sha256, p.nested_message_id, p.nested_subject)

    # 会话边
    pos = 0
    if fact.in_reply_to:
        await conn.execute(
            """INSERT INTO message_links(version_id, eml_sha256, link_type, position,
                                         target_message_id, target_raw)
               VALUES ($1,$2,'in_reply_to',$3,$4,$5)""",
            version_id, sha, pos, fact.in_reply_to, fact.in_reply_to_raw)
        pos += 1
    for i, ref in enumerate(fact.references_list):
        await conn.execute(
            """INSERT INTO message_links(version_id, eml_sha256, link_type, position,
                                         target_message_id, target_raw)
               VALUES ($1,$2,'references',$3,$4,NULL)""",
            version_id, sha, i, ref)

    # 引用解析（对当前库内消息）
    targets = ([fact.in_reply_to] if fact.in_reply_to else []) + fact.references_list
    for t in dict.fromkeys(targets):
        hit = await conn.fetchval(
            """SELECT m.eml_sha256 FROM messages m
                 JOIN current_versions cv ON cv.version_id = m.version_id
                WHERE lower(m.message_id) = lower($1)""", t)
        link_rows = await conn.fetch(
            """SELECT id FROM message_links
                WHERE version_id=$1 AND lower(target_message_id)=lower($2)""",
            version_id, t)
        for lr in link_rows:
            await conn.execute(
                """INSERT INTO link_resolutions(message_link_id, resolved, target_eml_sha256)
                   VALUES ($1,$2,$3) ON CONFLICT (message_link_id) DO UPDATE
                     SET resolved=$2, target_eml_sha256=$3""",
                lr["id"], bool(hit), hit)

    # 问题
    await conn.executemany(
        """INSERT INTO parse_issues(version_id, eml_sha256, issue_no, severity,
                                    kind, location, detail)
           VALUES ($1,$2,$3,$4,$5,$6,$7)""",
        [(version_id, sha, i.issue_no, i.severity, i.kind, i.location, i.detail)
         for i in fact.issues])

    # 版本内标识冲突（信头事实，随版本快照不可变）
    if fact.message_id_count > 1:
        await conn.execute(
            """INSERT INTO version_conflicts(version_id, conflict_type, message_id, detail)
               VALUES ($1,'duplicate_message_id_in_header',$2,$3) ON CONFLICT DO NOTHING""",
            version_id, fact.message_id,
            f"{fact.message_id_count} Message-ID headers; first retained")
    if not fact.message_id:
        await conn.execute(
            """INSERT INTO version_conflicts(version_id, conflict_type, message_id, detail)
               VALUES ($1,'missing_message_id',NULL,$2) ON CONFLICT DO NOTHING""",
            version_id, "no usable Message-ID; subject is weak candidate only")
    if fact.message_id:
        if fact.in_reply_to and fact.in_reply_to.lower() == fact.message_id.lower():
            await conn.execute(
                """INSERT INTO version_conflicts(version_id, conflict_type, message_id, detail)
                   VALUES ($1,'self_reference',$2,$3) ON CONFLICT DO NOTHING""",
                version_id, fact.message_id, "In-Reply-To self reference")
        if any(r.lower() == fact.message_id.lower() for r in fact.references_list):
            await conn.execute(
                """INSERT INTO version_conflicts(version_id, conflict_type, message_id, detail)
                   VALUES ($1,'self_reference',$2,$3) ON CONFLICT DO NOTHING""",
                version_id, fact.message_id, "References self reference")


async def _create_version_row(conn: asyncpg.Connection, fact: MailFact, *,
                              source: str, policy_version: str,
                              reason: str | None, requested_by: str | None,
                              job_id: int | None) -> asyncpg.Record:
    row = await conn.fetchrow(
        """INSERT INTO parse_versions(
               eml_sha256, version_no, parser_version, policy_version, parse_status,
               part_count, attachment_count, source, reason, requested_by, job_id)
        VALUES ($1,
                COALESCE((SELECT max(version_no) FROM parse_versions WHERE eml_sha256=$1),0)+1,
                $2,$3,$4,$5,$6,$7,$8,$9,$10)
        RETURNING id, version_no""",
        fact.eml_sha256, PARSER_VERSION, policy_version, fact.parse_status,
        len(fact.parts), sum(1 for p in fact.parts if p.is_attachment),
        source, reason, requested_by, job_id)
    return row


async def _recompute_global_conflicts(conn: asyncpg.Connection) -> None:
    """基于所有 current 版本全量重算图级冲突（ID 重用/悬空/环）。

    与指针切换同事务，保证读到的“当前图”与展示版本一致。
    """
    await conn.execute("DELETE FROM identity_conflicts")

    # Message-ID 重用：同一规范化 ID 出现在多封不同 EML 的当前版本中
    await conn.execute(
        """INSERT INTO identity_conflicts(conflict_type, message_id, eml_sha256, detail)
           WITH cur AS (
                SELECT lower(m.message_id) AS key_id,
                       min(m.message_id) AS sample_id, m.eml_sha256
                  FROM messages m JOIN current_versions cv ON cv.version_id=m.version_id
                 WHERE m.message_id IS NOT NULL
              GROUP BY lower(m.message_id), m.eml_sha256
           ), dup AS (
                SELECT key_id, sample_id, eml_sha256,
                       count(*) OVER (PARTITION BY key_id) AS cnt
                  FROM cur
           )
           SELECT 'reassigned_message_id', sample_id, eml_sha256,
                  'Message-ID reused by '||cnt||' different messages; not merged'
             FROM dup WHERE cnt > 1
           ON CONFLICT DO NOTHING""")

    # 悬空引用：当前版本的边指向库中不存在（或无当前版本）的 ID
    await conn.execute(
        """INSERT INTO identity_conflicts(conflict_type, message_id, eml_sha256, detail)
           SELECT 'dangling_reference', l.target_message_id, l.eml_sha256,
                  'referenced Message-ID not present in archive current versions'
             FROM message_links l
             JOIN current_versions cv ON cv.version_id = l.version_id
            WHERE NOT EXISTS (
                SELECT 1 FROM messages m2
                 JOIN current_versions cv2 ON cv2.version_id = m2.version_id
                 WHERE lower(m2.message_id) = lower(l.target_message_id))
           ON CONFLICT DO NOTHING""")

    # 引用环（Tarjan SCC 在应用层 threads.find_cycles 中完成）
    edge_rows = await conn.fetch(
        """SELECT lower(m.message_id) AS src, lower(l.target_message_id) AS dst
             FROM message_links l
             JOIN current_versions cv ON cv.version_id = l.version_id
             JOIN messages m ON m.version_id = l.version_id
            WHERE m.message_id IS NOT NULL""")
    edges = [(r["src"], r["dst"]) for r in edge_rows if r["src"] and r["dst"]]
    for comp in threads.find_cycles(edges):
        members = await conn.fetch(
            """SELECT m.message_id, m.eml_sha256 FROM messages m
                JOIN current_versions cv ON cv.version_id=m.version_id
               WHERE lower(m.message_id) = ANY($1)""", comp)
        detail = "reference cycle among: " + ", ".join(sorted(comp))[:400]
        for m in members:
            await conn.execute(
                """INSERT INTO identity_conflicts(conflict_type, message_id, eml_sha256, detail)
                   VALUES ('reference_cycle',$1,$2,$3) ON CONFLICT DO NOTHING""",
                m["message_id"], m["eml_sha256"], detail)


# ============================================================ 初次入库

async def ingest_initial(pool: asyncpg.Pool, fact: MailFact, eml_bytes: bytes,
                         eml_filename: str | None, attachment_dir: Path | None = None,
                         policy_version: str = DEFAULT_POLICY_VERSION) -> dict:
    """初次入库；同 sha 重复 POST 为幂等 no-op，返回当前版本信息。"""
    base_dir = (attachment_dir or settings.attachment_dir).resolve()
    async with pool.acquire() as conn:
        existing = await conn.fetchval(
            "SELECT id FROM raw_emls WHERE eml_sha256=$1", fact.eml_sha256)
        if existing:
            cur = await conn.fetchrow(
                """SELECT v.id, v.version_no, v.policy_version, v.parse_status
                     FROM current_versions cv JOIN parse_versions v ON v.id=cv.version_id
                    WHERE cv.eml_sha256=$1""", fact.eml_sha256)
            log.info("ingest idempotent sha=%s current=v%s",
                     fact.eml_sha256[:12], cur["version_no"] if cur else "?")
            return {"eml_sha256": fact.eml_sha256, "created": False,
                    "version_id": cur["id"], "version_no": cur["version_no"],
                    "policy_version": cur["policy_version"],
                    "status": cur["parse_status"]}

        async with conn.transaction():
            await conn.execute(
                """INSERT INTO raw_emls(eml_sha256, eml_filename, eml_size, eml_bytes)
                   VALUES ($1,$2,$3,$4)""",
                fact.eml_sha256, eml_filename, fact.eml_size, eml_bytes)
            stored = await _write_part_files(fact, base_dir)
            vrow = await _create_version_row(
                conn, fact, source="ingest", policy_version=policy_version,
                reason=None, requested_by=None, job_id=None)
            await _insert_version_facts(conn, fact, vrow["id"], vrow["version_no"],
                                        stored, base_dir)
            await conn.execute(
                "INSERT INTO current_versions(eml_sha256, version_id) VALUES ($1,$2)",
                fact.eml_sha256, vrow["id"])
            await conn.execute(
                """INSERT INTO current_switches(eml_sha256, version_id, action, actor)
                   VALUES ($1,$2,'initial','api')""", fact.eml_sha256, vrow["id"])
            await _recompute_global_conflicts(conn)

    log.info("ingest new sha=%s version=v1 status=%s parts=%d issues=%d",
             fact.eml_sha256[:12], fact.parse_status, len(fact.parts), len(fact.issues))
    return {"eml_sha256": fact.eml_sha256, "created": True,
            "version_id": vrow["id"], "version_no": vrow["version_no"],
            "policy_version": policy_version, "status": fact.parse_status}


# ============================================================ 重解析任务

class JobConflict(Exception):
    pass


class HeldByDisposition(Exception):
    """邮件正在被到期处置：拒绝新建重解析（要求稍后重试）。"""


async def create_reparse_job(pool: asyncpg.Pool, sha: str, policy_version: str,
                             reason: str | None, requested_by: str | None
                             ) -> tuple[asyncpg.Record, bool]:
    """创建任务；同 EML+同策略存在未终态任务时返回该任务（created=False）。

    处置协调：该 EML 正在处置运行（游标中）时拒绝新建，避免处置与解析竞争。
    """
    async with pool.acquire() as conn:
        raw = await conn.fetchval("SELECT eml_sha256 FROM raw_emls WHERE eml_sha256=$1", sha)
        if not raw:
            raise RepoError("eml not found")
        disposing = await conn.fetchval(
            """SELECT 1 FROM disposition_run_targets t
                 JOIN disposition_runs r ON r.id=t.run_id
                WHERE t.eml_sha256=$1 AND r.status='running' LIMIT 1""", sha)
        if disposing:
            raise HeldByDisposition(
                "eml is in an active disposition run; reparse is rejected until it settles")
        try:
            row = await conn.fetchrow(
                """INSERT INTO reparse_jobs(eml_sha256, policy_version, reason,
                                            requested_by, status)
                   VALUES ($1,$2,$3,$4,'queued')
                   RETURNING *""", sha, policy_version, reason, requested_by)
            return row, True
        except asyncpg.UniqueViolationError:
            row = await conn.fetchrow(
                """SELECT * FROM reparse_jobs
                    WHERE eml_sha256=$1 AND policy_version=$2
                      AND status IN ('queued','running')
                    ORDER BY created_at DESC LIMIT 1""", sha, policy_version)
            return row, False


async def list_jobs(pool: asyncpg.Pool, sha: str | None, limit: int) -> list[dict]:
    if sha:
        rows = await pool.fetch(
            "SELECT * FROM reparse_jobs WHERE eml_sha256=$1 ORDER BY created_at DESC LIMIT $1",
            sha, limit)
    else:
        rows = await pool.fetch(
            "SELECT * FROM reparse_jobs ORDER BY created_at DESC LIMIT $1", limit)
    return [dict(r) for r in rows]


async def get_job(pool: asyncpg.Pool, job_id: int) -> dict | None:
    row = await pool.fetchrow("SELECT * FROM reparse_jobs WHERE id=$1", job_id)
    if not row:
        return None
    d = dict(row)
    d["attempts_history"] = [dict(r) for r in await pool.fetch(
        "SELECT attempt_no,phase,detail,at FROM reparse_attempts WHERE job_id=$1 ORDER BY id",
        job_id)]
    d["versions"] = [dict(r) for r in await pool.fetch(
        """SELECT v.id,v.version_no,v.policy_version,v.parse_status,v.created_at
             FROM parse_versions v WHERE v.job_id=$1 ORDER BY v.version_no""", job_id)]
    return d


async def cancel_job(pool: asyncpg.Pool, job_id: int) -> dict:
    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                "SELECT * FROM reparse_jobs WHERE id=$1 FOR UPDATE", job_id)
            if not row:
                raise RepoError("job not found")
            if row["status"] != "queued":
                raise JobConflict(
                    f"job is {row['status']}; only queued jobs can be cancelled")
            await conn.execute(
                """UPDATE reparse_jobs SET status='cancelled', finished_at=now()
                    WHERE id=$1""", job_id)
            await conn.execute(
                """INSERT INTO reparse_attempts(job_id, attempt_no, phase, detail)
                   VALUES ($1,$2,'cancelled','cancelled before execution')""",
                job_id, row["attempts"] + 1)
    return await get_job(pool, job_id)


async def retry_job(pool: asyncpg.Pool, job_id: int) -> dict:
    """允许对 failed/cancelled 重新排队（同策略去重仍生效）。"""
    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                "SELECT * FROM reparse_jobs WHERE id=$1 FOR UPDATE", job_id)
            if not row:
                raise RepoError("job not found")
            if row["status"] not in ("failed", "cancelled"):
                raise JobConflict(f"job is {row['status']}; cannot retry")
            # 同策略已有活跃任务则合并
            active = await conn.fetchrow(
                """SELECT id FROM reparse_jobs
                    WHERE eml_sha256=$1 AND policy_version=$2
                      AND status IN ('queued','running') LIMIT 1""",
                row["eml_sha256"], row["policy_version"])
            if active:
                return await get_job(pool, active["id"])
            await conn.execute(
                """UPDATE reparse_jobs SET status='queued', run_after=now(),
                       locked_by=NULL, lease_until=NULL, last_error=NULL,
                       finished_at=NULL
                 WHERE id=$1""", job_id)
    return await get_job(pool, job_id)


# -------- worker: 领取 / 恢复 / 执行

def _advisory_key(sha: str) -> int:
    """EML -> 32 位稳定 bigint 键，用于会话级咨询锁（同 EML 任务串行）。"""
    import zlib
    return (zlib.crc32(("eml-reparse:" + sha).encode()) & 0x7fffffff) + 1


async def recover_stale_running(pool: asyncpg.Pool, lease_seconds: int,
                                worker_id: str) -> int:
    """进程重启恢复：租约过期的 running 任务安全转回 queued，并留 interrupted 尝试。

    只改租约超时的任务；真正仍在运行（心跳持续续约）的任务不受影响。
    """
    async with pool.acquire() as conn:
        async with conn.transaction():
            rows = await conn.fetch(
                """UPDATE reparse_jobs
                      SET status='queued', locked_by=NULL, lease_until=NULL,
                          run_after=now()
                    WHERE status='running'
                      AND (lease_until IS NULL OR lease_until < now())
                    RETURNING id, attempts""")
            for r in rows:
                # interrupted 记录“死去的那次尝试”序号（attempts），
                # worker 再次领取时会自增到 attempts+1，两者序号不冲突。
                await conn.execute(
                    """INSERT INTO reparse_attempts(job_id, attempt_no, phase, detail)
                       VALUES ($1,$2,'interrupted',$3)""",
                    r["id"], max(r["attempts"], 1),
                    f"worker lease (>={lease_seconds}s) expired; recovered to queued by {worker_id}")
    if rows:
        log.warning("recovered %d stale running jobs", len(rows))
    return len(rows)


async def claim_due_job(pool: asyncpg.Pool, worker_id: str,
                        lease_seconds: int) -> dict | None:
    """挑出一个到期 queued 任务：跳过同 EML 正在运行（其他策略）的情况。

    使用 FOR UPDATE SKIP LOCKED，多 worker 并发不会领同一个；该事务提交后释放行锁，
    真正的跨 worker/跨策略互斥在 execute_job 的咨询锁上完成。
    """
    while True:
        async with pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    """SELECT * FROM reparse_jobs
                        WHERE status='queued' AND run_after <= now()
                        ORDER BY created_at
                        LIMIT 1 FOR UPDATE SKIP LOCKED""")
                if not row:
                    return None
                busy = await conn.fetchval(
                    """SELECT 1 FROM reparse_jobs
                        WHERE eml_sha256=$1 AND status='running' AND id<>$2
                        LIMIT 1""", row["eml_sha256"], row["id"])
                if busy:
                    # 同 EML 不同策略排队：延后，去挑别的 EML
                    await conn.execute(
                        "UPDATE reparse_jobs SET run_after=now()+interval '10 seconds' WHERE id=$1",
                        row["id"])
                    continue
                new_attempts = row["attempts"] + 1
                await conn.execute(
                    """UPDATE reparse_jobs
                          SET status='running', locked_by=$2, attempts=$3,
                              started_at=COALESCE(started_at, now()),
                              finished_at=NULL,
                              lease_until=now()+make_interval(secs => $4),
                              last_error=NULL
                        WHERE id=$1 AND status='queued'""",
                    row["id"], worker_id, new_attempts, lease_seconds)
                await conn.execute(
                    """INSERT INTO reparse_attempts(job_id, attempt_no, phase, detail)
                       VALUES ($1,$2,'started',$3)""",
                    row["id"], new_attempts, f"claimed by {worker_id}")
                return dict(row) | {"attempts": new_attempts}


async def execute_job(pool: asyncpg.Pool, job_id: int, *,
                      parse_fn, worker_id: str,
                      attachment_dir: Path | None = None,
                      lease_seconds: int = 300,
                      heartbeat_seconds: int = 15) -> str:
    """执行已领取的任务：咨询锁互斥 -> 解析 -> 新版本 -> 原子切换 current。

    任何失败都不触碰旧版本与附件引用；未超 max_attempts 退避重排队。
    """
    base_dir = (attachment_dir or settings.attachment_dir).resolve()
    conn = await pool.acquire()
    job: dict | None = None
    beat_task = None
    try:
        row = await conn.fetchrow("SELECT * FROM reparse_jobs WHERE id=$1", job_id)
        if not row:
            return "missing"
        job = dict(row)
        if job["status"] != "running":
            return job["status"]
        locked = await conn.fetchval(
            "SELECT pg_try_advisory_lock($1)", _advisory_key(job["eml_sha256"]))
        if not locked:
            # 极少情况（同 EML 另一任务正在执行）：退回队列
            await conn.execute(
                """UPDATE reparse_jobs SET status='queued', locked_by=NULL,
                       lease_until=NULL, run_after=now()+interval '10 seconds'
                 WHERE id=$1""", job_id)
            return "deferred"

        stop_beat = asyncio.Event()

        async def _heartbeat():
            while not stop_beat.is_set():
                try:
                    await asyncio.wait_for(stop_beat.wait(), timeout=heartbeat_seconds)
                except asyncio.TimeoutError:
                    try:
                        await conn.execute(
                            """UPDATE reparse_jobs
                                  SET lease_until=now()+make_interval(secs => $1)
                                WHERE id=$2 AND status='running'""",
                            lease_seconds, job_id)
                    except Exception:
                        pass

        beat_task = asyncio.create_task(_heartbeat())
        raw_row = await conn.fetchrow(
            "SELECT eml_bytes FROM raw_emls WHERE eml_sha256=$1", job["eml_sha256"])
        if not raw_row:
            raise RepoError("raw eml disappeared")

        fact = await asyncio.to_thread(parse_fn, bytes(raw_row["eml_bytes"]),
                                       job["eml_sha256"])
        stored = await _write_part_files(fact, base_dir)

        async with conn.transaction():
            vrow = await _create_version_row(
                conn, fact, source="reparse",
                policy_version=job["policy_version"],
                reason=job["reason"], requested_by=job["requested_by"], job_id=job_id)
            await _insert_version_facts(conn, fact, vrow["id"], vrow["version_no"],
                                        stored, base_dir)
            # 成功后才在同一事务原子切换 current + 审计 + 任务终态 + 重算全局图
            await conn.execute(
                "UPDATE current_versions SET version_id=$2, updated_at=now() WHERE eml_sha256=$1",
                job["eml_sha256"], vrow["id"])
            await conn.execute(
                """INSERT INTO current_switches(eml_sha256, version_id, action,
                                                job_id, actor)
                   VALUES ($1,$2,'reparse',$3,$4)""",
                job["eml_sha256"], vrow["id"], job_id, worker_id)
            await conn.execute(
                """UPDATE reparse_jobs
                      SET status='succeeded', result_version_id=$2,
                          finished_at=now(), locked_by=NULL, lease_until=NULL
                    WHERE id=$1""", job_id, vrow["id"])
            await conn.execute(
                """INSERT INTO reparse_attempts(job_id, attempt_no, phase, detail)
                   VALUES ($1,$2,'succeeded',$3)""",
                job_id, job["attempts"], f"version v{vrow['version_no']} activated")
            await _recompute_global_conflicts(conn)

        log.info("reparse job=%s succeeded sha=%s version=v%s",
                 job_id, job["eml_sha256"][:12], vrow["version_no"])
        return "succeeded"

    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001
        detail = f"{type(exc).__name__}: {exc}"[:800]
        log.error("reparse job=%s failed: %s", job_id, type(exc).__name__)
        if job is not None:
            await _fail_or_requeue(conn, job, detail)
        return "failed"
    finally:
        if beat_task is not None:
            beat_task.cancel()
        if job is not None:
            try:
                await conn.fetchval("SELECT pg_advisory_unlock($1)",
                                    _advisory_key(job["eml_sha256"]))
            except Exception:
                pass
        await pool.release(conn)


async def _fail_or_requeue(conn: asyncpg.Connection, job: dict, detail: str) -> None:
    """失败记账：未超 max_attempts 指数退避重排队；超限置 failed。旧版本不受影响。"""
    try:
        async with conn.transaction():
            await conn.execute(
                """INSERT INTO reparse_attempts(job_id, attempt_no, phase, detail)
                   VALUES ($1,$2,'failed',$3)""",
                job["id"], job["attempts"], detail)
            if job["attempts"] >= job["max_attempts"]:
                await conn.execute(
                    """UPDATE reparse_jobs SET status='failed', last_error=$2,
                           finished_at=now(), locked_by=NULL, lease_until=NULL
                         WHERE id=$1""", job["id"], detail)
            else:
                backoff = min(300, 5 * (2 ** (job["attempts"] - 1)))
                await conn.execute(
                    """UPDATE reparse_jobs SET status='queued', last_error=$2,
                           run_after=now()+make_interval(secs => $3),
                           locked_by=NULL, lease_until=NULL
                         WHERE id=$1""", job["id"], detail, backoff)
    except Exception as exc2:  # noqa: BLE001
        log.error("failed to record job failure job=%s: %s", job["id"], exc2)



# ============================================================ 版本查询/回退

async def list_versions(pool: asyncpg.Pool, sha: str) -> list[dict]:
    rows = await pool.fetch(
        """SELECT v.*, (cv.version_id IS NOT NULL) AS is_current
             FROM parse_versions v
             LEFT JOIN current_versions cv
                    ON cv.eml_sha256=v.eml_sha256 AND cv.version_id=v.id
            WHERE v.eml_sha256=$1
            ORDER BY v.version_no DESC""", sha)
    return [dict(r) for r in rows]


async def get_version_detail(pool: asyncpg.Pool, sha: str,
                             version_no: int | None = None) -> dict | None:
    async with pool.acquire() as conn:
        if version_no is None:
            vrow = await conn.fetchrow(
                """SELECT v.*, true AS is_current FROM parse_versions v
                     JOIN current_versions cv ON cv.version_id=v.id
                    WHERE v.eml_sha256=$1""", sha)
        else:
            vrow = await conn.fetchrow(
                """SELECT v.*, (cv.version_id IS NOT NULL) AS is_current
                     FROM parse_versions v
                     LEFT JOIN current_versions cv
                            ON cv.eml_sha256=v.eml_sha256 AND cv.version_id=v.id
                    WHERE v.eml_sha256=$1 AND v.version_no=$2""", sha, version_no)
        if not vrow:
            return None
        return await _load_version_detail(conn, vrow)


async def _load_version_detail(conn: asyncpg.Connection, vrow) -> dict:
    d = dict(vrow)
    mid = vrow["id"]
    m = await conn.fetchrow("SELECT * FROM messages WHERE version_id=$1", mid)
    d["message"] = dict(m) if m else None
    if d.get("message"):
        msg = d["message"]
        for col, path_col in (("body_text", "body_text_path"),
                              ("body_html", "body_html_path"),
                              ("body_html_escaped", "body_html_escaped_path")):
            if msg.get(col) is None and msg.get(path_col):
                fp = settings.attachment_dir / msg[path_col]
                if fp.is_file() and str(fp.resolve()).startswith(
                        str(settings.attachment_dir.resolve()) + "/"):
                    msg[col] = fp.read_text(encoding="utf-8")
    d["parts"] = [dict(r) for r in await conn.fetch(
        "SELECT * FROM mime_parts WHERE version_id=$1 ORDER BY part_no", mid)]
    d["issues"] = [dict(r) for r in await conn.fetch(
        "SELECT issue_no,severity,kind,location,detail FROM parse_issues WHERE version_id=$1 ORDER BY issue_no", mid)]
    d["addresses"] = [dict(r) for r in await conn.fetch(
        """SELECT ma.role,ma.position,ma.display_name,a.email_norm,a.email_raw
             FROM message_addresses ma JOIN addresses a ON a.id=ma.address_id
            WHERE ma.version_id=$1 ORDER BY ma.role,ma.position""", mid)]
    d["links"] = [dict(r) for r in await conn.fetch(
        "SELECT link_type,position,target_message_id FROM message_links WHERE version_id=$1 ORDER BY position", mid)]
    d["version_conflicts"] = [dict(r) for r in await conn.fetch(
        "SELECT conflict_type,message_id,detail FROM version_conflicts WHERE version_id=$1", mid)]
    d["identity_conflicts"] = [dict(r) for r in await conn.fetch(
        "SELECT conflict_type,message_id,detail,detected_at FROM identity_conflicts WHERE eml_sha256=$1 ORDER BY detected_at",
        vrow["eml_sha256"])]
    return d


async def activate_version(pool: asyncpg.Pool, sha: str, version_no: int,
                           actor: str = "api") -> dict:
    """原子回退/切换当前展示版本；不重新解析，不改变不可变版本。

    协调：与处置删除共用每-EML 事务锁；处置运行期间拒绝回退。
    """
    async with pool.acquire() as conn:
        async with conn.transaction():
            # 处置游标中有该 EML 时拒绝（保持“处置与回退一致协调”）
            disposing = await conn.fetchval(
                """SELECT 1 FROM disposition_run_targets t
                     JOIN disposition_runs r ON r.id=t.run_id
                    WHERE t.eml_sha256=$1 AND r.status='running' LIMIT 1""", sha)
            if disposing:
                raise JobConflict(
                    "eml is in an active disposition run; rollback rejected")
            # 与重解析执行/处置删除互斥（事务结束自动释放）
            await conn.fetchval("SELECT pg_advisory_xact_lock($1)", _advisory_key(sha))
            cur = await conn.fetchrow(
                "SELECT version_id FROM current_versions WHERE eml_sha256=$1 FOR UPDATE", sha)
            if not cur:
                raise RepoError("eml not found")
            vrow = await conn.fetchrow(
                "SELECT id FROM parse_versions WHERE eml_sha256=$1 AND version_no=$2 FOR UPDATE",
                sha, version_no)
            if not vrow:
                raise RepoError("version not found")
            if cur["version_id"] == vrow["id"]:
                changed = False
            else:
                await conn.execute(
                    "UPDATE current_versions SET version_id=$2, updated_at=now() WHERE eml_sha256=$1",
                    sha, vrow["id"])
                await conn.execute(
                    """INSERT INTO current_switches(eml_sha256, version_id, action, actor)
                       VALUES ($1,$2,'rollback',$3)""", sha, vrow["id"], actor)
                await _recompute_global_conflicts(conn)
                changed = True
    detail = await get_version_detail(pool, sha, version_no)
    detail["switched"] = changed
    return detail


# ============================================================ 当前版本查询

_CURRENT_SELECT = """
    FROM messages m JOIN current_versions cv ON cv.version_id=m.version_id"""


async def list_messages(pool: asyncpg.Pool, limit: int, offset: int) -> list[dict]:
    rows = await pool.fetch(
        f"""SELECT m.eml_sha256, m.message_id, m.subject, m.sent_at,
                  m.from_raw, m.to_raw, m.has_attachments,
                  v.version_no, v.parse_status, r.received_at
             FROM messages m
             JOIN current_versions cv ON cv.version_id=m.version_id
             JOIN parse_versions v ON v.id=cv.version_id
             JOIN raw_emls r ON r.eml_sha256=m.eml_sha256
            ORDER BY r.received_at DESC
            LIMIT $1 OFFSET $2""", limit, offset)
    return [dict(r) for r in rows]


async def get_message_current(pool: asyncpg.Pool, sha: str) -> dict | None:
    return await get_version_detail(pool, sha, None)


async def search_messages(pool: asyncpg.Pool, query: str, limit: int) -> list[dict]:
    """simple FTS + trigram 子串回退（CJK/短词），仅检索当前版本。"""
    like = "%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    rows = await pool.fetch(
        r"""
        WITH fts AS (
            SELECT m.version_id,
                   ts_rank(m.search_tsv, websearch_to_tsquery('simple', $1)) AS rank
              FROM messages m JOIN current_versions cv ON cv.version_id=m.version_id
             WHERE m.search_tsv @@ websearch_to_tsquery('simple', $1)
        ),
        tri AS (
            SELECT m.version_id, 0.05 AS rank
              FROM messages m JOIN current_versions cv ON cv.version_id=m.version_id
             WHERE m.subject ILIKE $2 ESCAPE '\'
                OR m.body_text ILIKE $2 ESCAPE '\'
                OR m.from_raw ILIKE $2 ESCAPE '\'
                OR m.to_raw ILIKE $2 ESCAPE '\'
                OR m.message_id ILIKE $2 ESCAPE '\'
        )
        SELECT DISTINCT ON (m.eml_sha256)
               m.eml_sha256, m.message_id, m.subject, m.sent_at, m.from_raw,
               v.version_no,
               COALESCE(f.rank,0)+COALESCE(t.rank,0) AS rank
          FROM messages m
          JOIN current_versions cv ON cv.version_id=m.version_id
          JOIN parse_versions v ON v.id=cv.version_id
          LEFT JOIN fts f ON f.version_id=m.version_id
          LEFT JOIN tri t ON t.version_id=m.version_id
         WHERE f.version_id IS NOT NULL OR t.version_id IS NOT NULL
         ORDER BY m.eml_sha256, rank DESC
         LIMIT $3
        """, query, like, limit)
    out = [dict(r) for r in rows]
    out.sort(key=lambda r: r["rank"], reverse=True)
    return out


async def get_thread(pool: asyncpg.Pool, sha: str) -> dict:
    root = await pool.fetchrow(
        """SELECT m.message_id, m.subject FROM messages m
            JOIN current_versions cv ON cv.version_id=m.version_id
           WHERE m.eml_sha256=$1""", sha)
    if not root:
        return {"found": False}
    mid, subject = root["message_id"], root["subject"]
    edges_rows = await pool.fetch(
        """SELECT lower(m.message_id) AS src, lower(l.target_message_id) AS dst
             FROM message_links l
             JOIN current_versions cv ON cv.version_id=l.version_id
             JOIN messages m ON m.version_id=l.version_id
            WHERE m.message_id IS NOT NULL""")
    edges = [(r["src"], r["dst"]) for r in edges_rows]

    strong_ids: set[str] = set()
    if mid:
        key = mid.lower()
        strong_ids = {key}
        strong_ids.update(threads.ancestors(edges, key))
        strong_ids.update(threads.descendants(edges, key))
    strong_rows = await pool.fetch(
        """SELECT m.eml_sha256, m.message_id, m.subject, m.sent_at,
                  m.in_reply_to, m.references_list
             FROM messages m JOIN current_versions cv ON cv.version_id=m.version_id
            WHERE m.message_id IS NOT NULL AND lower(m.message_id)=ANY($1)
            ORDER BY m.sent_at NULLS LAST""", list(strong_ids))

    weak_rows = []
    if subject:
        candidates = await pool.fetch(
            r"""SELECT m.eml_sha256, m.message_id, m.subject, m.sent_at
                  FROM messages m JOIN current_versions cv ON cv.version_id=m.version_id
                 WHERE m.eml_sha256 <> $1
                   AND regexp_replace(coalesce(m.subject,''),
                                      '(?i)^(re|fwd|aw|wg)(\[[0-9]+\])?:\s*', '') =
                       regexp_replace($2, '(?i)^(re|fwd|aw|wg)(\[[0-9]+\])?:\s*', '')
                 ORDER BY m.sent_at NULLS LAST""", sha, subject.strip())
        strong_shas = {r["eml_sha256"] for r in strong_rows}
        weak_rows = [dict(r) for r in candidates if r["eml_sha256"] not in strong_shas]

    return {
        "found": True,
        "root_eml_sha256": sha,
        "root_message_id": mid,
        "strong_thread": [dict(r) for r in strong_rows],
        "weak_subject_candidates": weak_rows,
        "weak_note": "same normalized subject only; NOT joined without References/In-Reply-To",
    }


async def get_raw(pool: asyncpg.Pool, sha: str) -> dict | None:
    row = await pool.fetchrow(
        "SELECT eml_sha256,eml_filename,eml_size,eml_bytes,received_at FROM raw_emls WHERE eml_sha256=$1",
        sha)
    return dict(row) if row else None


async def get_part_for_download(pool: asyncpg.Pool, sha: str, mime_path: str,
                                version_no: int | None = None) -> dict | None:
    """取部件行；默认当前版本，version_no 指定旧版本（历史附件仍可读）。"""
    if version_no is None:
        row = await pool.fetchrow(
            """SELECT mp.*, v.version_no FROM mime_parts mp
                 JOIN current_versions cv ON cv.version_id=mp.version_id
                 JOIN parse_versions v ON v.id=mp.version_id
                WHERE mp.eml_sha256=$1 AND mp.mime_path=$2""", sha, mime_path)
    else:
        row = await pool.fetchrow(
            """SELECT mp.*, v.version_no FROM mime_parts mp
                 JOIN parse_versions v ON v.id=mp.version_id
                WHERE mp.eml_sha256=$1 AND mp.mime_path=$2 AND v.version_no=$3""",
            sha, mime_path, version_no)
    return dict(row) if row else None


async def list_failures(pool: asyncpg.Pool, limit: int) -> dict:
    """当前展示版本中的非 ok 解析 + 最近失败任务，均可定位到问题/尝试。"""
    vrows = await pool.fetch(
        """SELECT v.eml_sha256, r.eml_filename, v.version_no, v.parse_status,
                  v.created_at
             FROM parse_versions v
             JOIN current_versions cv ON cv.version_id=v.id
             JOIN raw_emls r ON r.eml_sha256=v.eml_sha256
            WHERE v.parse_status <> 'ok'
            ORDER BY v.created_at DESC LIMIT $1""", limit)
    versions = []
    for r in vrows:
        d = dict(r)
        d["issues"] = [dict(x) for x in await pool.fetch(
            """SELECT issue_no,severity,kind,location,detail FROM parse_issues i
                JOIN parse_versions v ON v.id=i.version_id
                JOIN current_versions cv ON cv.version_id=v.id
               WHERE v.eml_sha256=$1 AND v.version_no=$2
               ORDER BY issue_no LIMIT 20""", r["eml_sha256"], r["version_no"])]
        versions.append(d)
    jobs = [dict(r) for r in await pool.fetch(
        """SELECT id,eml_sha256,policy_version,attempts,last_error,finished_at
             FROM reparse_jobs WHERE status='failed'
            ORDER BY finished_at DESC NULLS LAST LIMIT $1""", limit)]
    return {"current_version_failures": versions, "failed_jobs": jobs}


async def purge_eml(pool: asyncpg.Pool, sha: str, *, allow_held: bool = False) -> bool:
    """受控清除（测试/管理员直删路径）。

    默认尊重证据保全：受 active 保全保护的 EML 拒绝删除。处置工作流使用 holds.py
    并写处置审计/墓场，不经过此函数。
    """
    async with pool.acquire() as conn:
        async with conn.transaction():
            exists = await conn.fetchval("SELECT 1 FROM raw_emls WHERE eml_sha256=$1", sha)
            if not exists:
                return False
            if not allow_held and await conn.fetchval("SELECT eml_is_held($1)", sha):
                raise RepoError("eml is protected by an active legal hold")
            await conn.execute("SET LOCAL app.archive_purge='on'")
            await conn.execute("DELETE FROM current_switches WHERE eml_sha256=$1", sha)
            await conn.execute("DELETE FROM identity_conflicts WHERE eml_sha256=$1", sha)
            await conn.execute("DELETE FROM raw_emls WHERE eml_sha256=$1", sha)
            await _recompute_global_conflicts(conn)
    return True
