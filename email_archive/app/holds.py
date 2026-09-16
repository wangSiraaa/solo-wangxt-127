"""证据保全（Legal Hold）与到期处置编排。

一致性要点
- 保全保护判定 eml_is_held()：存在 active 且未到期策略的 held 目标。suspended/expired
  不保护。
- 处置删除按“每封 EML 独立连接 + 独立事务”进行：每-EML 咨询事务锁（与重解析执行、
  版本回退同一把锁）-> 删除前再次校验保全与活动任务 -> 同事务写不可篡改审计 +
  file_graveyard(pending) -> 提交后才物理删文件。崩溃后由游标恢复、由墓场对账，
  杜绝“库已删附件仍可访问”或反向孤儿。
- 游标即 disposition_run_targets(pending)：重启从同一 run 继续；唯一约束保证不重复
  删除/审计。
- 查询条件策略在“激活时”快照目标集合，之后范围不再随查询变化。
- 处置运行期间 hold_expiry 策略被重新激活 -> 整单安全中止；单个目标被其他策略重新
  保全 -> skipped_held。
"""
from __future__ import annotations

import json
import logging
import zlib
from datetime import datetime
from pathlib import Path

import asyncpg

from .config import settings
from .security import safe_resolve

log = logging.getLogger("archive.holds")


def advisory_key(sha: str) -> int:
    """与 repository._advisory_key 相同的命名空间：同一把每-EML 锁。"""
    return (zlib.crc32(("eml-reparse:" + sha).encode()) & 0x7fffffff) + 1


class HoldError(Exception):
    pass


class PolicyStateError(HoldError):
    pass


def _jsonable(obj):
    """递归把 asyncpg Record/datetime 转为 jsonb codec 可序列化的 JSON 基础类型。"""
    import datetime as _dt
    if isinstance(obj, dict) or hasattr(obj, "keys"):
        return {k: _jsonable(obj[k]) for k in obj.keys()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v) for v in obj]
    if isinstance(obj, (_dt.datetime, _dt.date)):
        return obj.isoformat()
    return obj


# ---------------------------------------------------------- 查询过滤（白名单 DSL）

_ALLOWED_FILTERS = {
    "subject_contains": "m.subject ILIKE ('%' || $p::text || '%') ESCAPE '\\'",
    "body_contains": "m.body_text ILIKE ('%' || $p::text || '%') ESCAPE '\\'",
    "from_contains": "m.from_raw ILIKE ('%' || $p::text || '%') ESCAPE '\\'",
    "to_contains": "m.to_raw ILIKE ('%' || $p::text || '%') ESCAPE '\\'",
    "message_id": "lower(m.message_id) = lower($p::text)",
    "has_attachments": "m.has_attachments = $p::boolean",
    "sent_before": "m.sent_at < $p::timestamptz",
    "sent_after": "m.sent_at > $p::timestamptz",
}


def _build_target_query(query_filter: dict) -> tuple[str, list]:
    where, params = [], []
    for key, value in query_filter.items():
        if key not in _ALLOWED_FILTERS:
            raise HoldError(f"unsupported filter field: {key}")
        params.append(value)
        where.append("(" + _ALLOWED_FILTERS[key].replace("$p", f"${len(params)}") + ")")
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    return f"""
        SELECT DISTINCT m.eml_sha256
          FROM messages m JOIN current_versions cv ON cv.version_id = m.version_id
        {clause}
        ORDER BY 1""", params


# ---------------------------------------------------------- 策略生命周期

async def create_policy(pool: asyncpg.Pool, *, name: str, hold_type: str,
                        reason: str, created_by: str, query_filter: dict | None = None,
                        eml_sha256: str | None = None, expires_at: datetime | None = None,
                        idempotency_key: str | None = None,
                        activate: bool = False) -> tuple[asyncpg.Record, bool]:
    if hold_type == "single" and not eml_sha256:
        raise HoldError("single hold requires eml_sha256")
    query_filter = query_filter or {}
    if hold_type == "query":
        _build_target_query(query_filter)  # 提前校验
    if idempotency_key:
        async with pool.acquire() as conn:
            existing = await conn.fetchrow(
                "SELECT * FROM hold_policies WHERE idempotency_key=$1", idempotency_key)
        if existing:
            return existing, False

    async with pool.acquire() as conn:
        try:
            async with conn.transaction():
                if eml_sha256:
                    if not await conn.fetchval(
                            "SELECT 1 FROM raw_emls WHERE eml_sha256=$1", eml_sha256):
                        raise HoldError("eml not found")
                row = await conn.fetchrow(
                    """INSERT INTO hold_policies(name, hold_type, query_filter, reason,
                                                 created_by, status, expires_at,
                                                 idempotency_key)
                       VALUES ($1,$2,$3,$4,$5,'draft',$6,$7) RETURNING *""",
                    name, hold_type, query_filter, reason,
                    created_by, expires_at, idempotency_key)
                await conn.execute(
                    """INSERT INTO hold_policy_events(policy_id, action, actor, detail)
                       VALUES ($1,'created',$2,$3)""", row["id"], created_by, reason)
                if hold_type == "single":
                    await conn.execute(
                        """INSERT INTO hold_policy_targets(policy_id, eml_sha256)
                           VALUES ($1,$2) ON CONFLICT DO NOTHING""", row["id"], eml_sha256)
                pid = row["id"]
        except asyncpg.UniqueViolationError:
            # 并发同 idempotency_key：事务回滚后再读已有策略
            async with conn.transaction():
                row = await conn.fetchrow(
                    "SELECT * FROM hold_policies WHERE idempotency_key=$1",
                    idempotency_key)
            return row, False
        except HoldError:
            raise

    if activate:
        return await activate_policy(pool, pid, actor=created_by), True
    return await _get_policy(pool, pid), True


async def _get_policy(pool: asyncpg.Pool, policy_id: int) -> asyncpg.Record:
    async with pool.acquire() as conn:
        return await conn.fetchrow("SELECT * FROM hold_policies WHERE id=$1", policy_id)


async def activate_policy(pool: asyncpg.Pool, policy_id: int, *, actor: str
                          ) -> asyncpg.Record:
    """draft/suspended -> active；query 策略在此时快照目标集合。"""
    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                "SELECT * FROM hold_policies WHERE id=$1 FOR UPDATE", policy_id)
            if not row:
                raise HoldError("policy not found")
            if row["status"] not in ("draft", "suspended"):
                raise PolicyStateError(
                    f"cannot activate policy in status {row['status']}")
            if row["hold_type"] == "query":
                qf = row["query_filter"]
                if isinstance(qf, str):  # 未注册 jsonb codec 的连接兜底
                    qf = json.loads(qf)
                sql, params = _build_target_query(qf)
                targets = await conn.fetch(sql, *params)
                await conn.executemany(
                    """INSERT INTO hold_policy_targets(policy_id, eml_sha256, state)
                       VALUES ($1,$2,'held') ON CONFLICT DO NOTHING""",
                    [(policy_id, r["eml_sha256"]) for r in targets])
                snap_n = len(targets)
            else:
                snap_n = await conn.fetchval(
                    "SELECT count(*) FROM hold_policy_targets WHERE policy_id=$1",
                    policy_id)
                await conn.execute(
                    "UPDATE hold_policy_targets SET state='held' WHERE policy_id=$1",
                    policy_id)
            await conn.execute(
                """UPDATE hold_policies
                      SET status='active', activated_at=COALESCE(activated_at, now()),
                          updated_at=now() WHERE id=$1""", policy_id)
            action = "activated" if row["status"] == "draft" else "resumed"
            await conn.execute(
                """INSERT INTO hold_policy_events(policy_id, action, actor, detail)
                   VALUES ($1,$2,$3,$4)""", policy_id, action, actor, f"{snap_n} targets")
    return await _get_policy(pool, policy_id)


async def suspend_policy(pool: asyncpg.Pool, policy_id: int, *, actor: str,
                         detail: str | None = None) -> asyncpg.Record:
    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                "SELECT * FROM hold_policies WHERE id=$1 FOR UPDATE", policy_id)
            if not row:
                raise HoldError("policy not found")
            if row["status"] != "active":
                raise PolicyStateError("only active policies can be suspended")
            await conn.execute(
                "UPDATE hold_policies SET status='suspended', updated_at=now() WHERE id=$1",
                policy_id)
            await conn.execute(
                """INSERT INTO hold_policy_events(policy_id, action, actor, detail)
                   VALUES ($1,'suspended',$2,$3)""", policy_id, actor, detail)
    return await _get_policy(pool, policy_id)


async def resume_policy(pool: asyncpg.Pool, policy_id: int, *, actor: str
                        ) -> asyncpg.Record:
    return await activate_policy(pool, policy_id, actor=actor)


async def list_policies(pool: asyncpg.Pool, status: str | None = None) -> list[dict]:
    sql = """SELECT p.*, (SELECT count(*) FROM hold_policy_targets t
                           WHERE t.policy_id=p.id) AS target_count
               FROM hold_policies p {w} ORDER BY p.created_at DESC"""
    async with pool.acquire() as conn:
        if status:
            rows = await conn.fetch(sql.format(w="WHERE p.status=$1"), status)
        else:
            rows = await conn.fetch(sql.format(w=""))
    return [dict(r) for r in rows]


async def get_policy_detail(pool: asyncpg.Pool, policy_id: int) -> dict | None:
    async with pool.acquire() as conn:
        p = await conn.fetchrow("SELECT * FROM hold_policies WHERE id=$1", policy_id)
        if not p:
            return None
        d = dict(p)
        d["targets"] = [dict(r) for r in await conn.fetch(
            "SELECT eml_sha256,state,added_at FROM hold_policy_targets WHERE policy_id=$1 ORDER BY id",
            policy_id)]
        d["events"] = [dict(r) for r in await conn.fetch(
            "SELECT action,actor,detail,at FROM hold_policy_events WHERE policy_id=$1 ORDER BY id",
            policy_id)]
        d["runs"] = [dict(r) for r in await conn.fetch(
            """SELECT id,status,total_targets,purged_count,skipped_count,
                      created_at,finished_at,last_note
                 FROM disposition_runs WHERE hold_policy_id=$1 ORDER BY id""", policy_id)]
    return d


async def expire_due_policies(pool: asyncpg.Pool) -> list[int]:
    """把已到期 active/suspended 策略标记为 expired。"""
    async with pool.acquire() as conn:
        async with conn.transaction():
            rows = await conn.fetch(
                """UPDATE hold_policies SET status='expired', updated_at=now()
                    WHERE expires_at IS NOT NULL AND expires_at <= now()
                      AND status IN ('active','suspended')
                    RETURNING id""")
            for r in rows:
                await conn.execute(
                    """INSERT INTO hold_policy_events(policy_id, action, actor, detail)
                       VALUES ($1,'expired','system','hold_until reached')""", r["id"])
    return [r["id"] for r in rows]


# ---------------------------------------------------------- 处置运行

async def create_expiry_disposition_run(pool: asyncpg.Pool, policy_id: int, *,
                                        actor: str = "system",
                                        reason: str | None = None
                                        ) -> tuple[asyncpg.Record, bool]:
    """为已到期策略创建处置运行（幂等：同策略只有一个 running）。"""
    async with pool.acquire() as conn:
        async with conn.transaction():
            p = await conn.fetchrow(
                "SELECT * FROM hold_policies WHERE id=$1 FOR UPDATE", policy_id)
            if not p:
                raise HoldError("policy not found")
            if p["status"] not in ("expired", "purging"):
                raise PolicyStateError(
                    f"policy status {p['status']} is not eligible for disposition")
            existing = await conn.fetchrow(
                """SELECT * FROM disposition_runs
                    WHERE hold_policy_id=$1 AND status='running'""", policy_id)
            if existing:
                return existing, False
            run = await conn.fetchrow(
                """INSERT INTO disposition_runs(kind, hold_policy_id, reason, actor,
                                                status, idempotency_key)
                   VALUES ('hold_expiry',$1,$2,$3,'running',$4) RETURNING *""",
                policy_id, reason or f"hold {policy_id} expired", actor,
                f"hold-{policy_id}-expiry")
            trows = await conn.fetch(
                "SELECT eml_sha256 FROM hold_policy_targets WHERE policy_id=$1", policy_id)
            await conn.executemany(
                """INSERT INTO disposition_run_targets(run_id, eml_sha256)
                   VALUES ($1,$2) ON CONFLICT DO NOTHING""",
                [(run["id"], r["eml_sha256"]) for r in trows])
            await conn.execute(
                "UPDATE disposition_runs SET total_targets=$2 WHERE id=$1",
                run["id"], len(trows))
            await conn.execute(
                "UPDATE hold_policies SET status='purging', updated_at=now() WHERE id=$1",
                policy_id)
            await conn.execute(
                """INSERT INTO hold_policy_events(policy_id, action, actor, detail)
                   VALUES ($1,'disposition_started',$2,$3)""",
                policy_id, actor, f"run {run['id']} targets={len(trows)}")
            return run, True


async def create_manual_retention_run(pool: asyncpg.Pool, *, actor: str, reason: str,
                                      idempotency_key: str | None = None,
                                      shas: list[str] | None = None
                                      ) -> tuple[asyncpg.Record, bool]:
    """手动到期处置：目标为所有（或指定）“无保全且无活动任务”的现有邮件。"""
    if idempotency_key:
        async with pool.acquire() as conn:
            existing = await conn.fetchrow(
                "SELECT * FROM disposition_runs WHERE idempotency_key=$1", idempotency_key)
        if existing:
            return existing, False
    async with pool.acquire() as conn:
        try:
            async with conn.transaction():
                run = await conn.fetchrow(
                    """INSERT INTO disposition_runs(kind, reason, actor, idempotency_key)
                       VALUES ('manual_retention',$1,$2,$3) RETURNING *""",
                    reason, actor, idempotency_key)
                if shas is not None:
                    targets = list(dict.fromkeys(shas))
                else:
                    trows = await conn.fetch(
                        """SELECT r.eml_sha256 FROM raw_emls r
                            WHERE NOT eml_is_held(r.eml_sha256)
                              AND NOT EXISTS (SELECT 1 FROM reparse_jobs j
                                               WHERE j.eml_sha256=r.eml_sha256
                                                 AND j.status IN ('queued','running'))""")
                    targets = [r["eml_sha256"] for r in trows]
                await conn.executemany(
                    """INSERT INTO disposition_run_targets(run_id, eml_sha256)
                       VALUES ($1,$2) ON CONFLICT DO NOTHING""",
                    [(run["id"], s) for s in targets])
                await conn.execute(
                    "UPDATE disposition_runs SET total_targets=$2 WHERE id=$1",
                    run["id"], len(targets))
                return run, True
        except asyncpg.UniqueViolationError:
            async with conn.transaction():
                existing = await conn.fetchrow(
                    "SELECT * FROM disposition_runs WHERE idempotency_key=$1",
                    idempotency_key)
            return existing, False


# ---------------------------------------------------------- 单邮件删除（一邮件一事务）

async def _collect_object_summary(conn: asyncpg.Connection, sha: str) -> dict:
    versions = [dict(r) for r in await conn.fetch(
        """SELECT id, version_no, parser_version, policy_version, parse_status,
                  part_count, attachment_count, source, reason, job_id, created_at
             FROM parse_versions WHERE eml_sha256=$1 ORDER BY version_no""", sha)]
    cur = await conn.fetchrow(
        "SELECT version_id FROM current_versions WHERE eml_sha256=$1", sha)
    files = [r["stored_relpath"] for r in await conn.fetch(
        """SELECT DISTINCT stored_relpath FROM mime_parts
            WHERE eml_sha256=$1 AND stored_relpath IS NOT NULL""", sha)]
    spills = [r["p"] for r in await conn.fetch(
        """SELECT DISTINCT x.p FROM messages m,
                  LATERAL (VALUES (body_text_path),(body_html_path),
                                 (body_html_escaped_path)) AS x(p)
            WHERE m.eml_sha256=$1 AND x.p IS NOT NULL""", sha)]
    jobs = [r["id"] for r in await conn.fetch(
        "SELECT id FROM reparse_jobs WHERE eml_sha256=$1 ORDER BY id", sha)]
    return {
        "versions": versions,
        "current_version_id": cur["version_id"] if cur else None,
        "version_count": len(versions),
        "attachment_count": sum(v["attachment_count"] for v in versions),
        "file_count": len(files) + len(spills),
        "reparse_job_ids": jobs,
        "files": files,
        "spills": spills,
    }


async def purge_one_in_run(pool: asyncpg.Pool, run_id: int, target_id: int,
                           sha: str, reason: str, actor: str) -> str:
    """删除单封邮件（独立事务）。返回状态名。

    purged / skipped_held / skipped_active_job / skipped_missing / failed
    """
    async with pool.acquire() as conn:
        try:
            # 每-EML 咨询事务锁：与重解析执行、版本回退互斥；锁不到说明有活动，稍后重试
            locked = await conn.fetchval(
                "SELECT pg_try_advisory_xact_lock($1)", advisory_key(sha))
            if not locked:
                return "skipped_active_job"
            if await conn.fetchval("SELECT eml_is_held($1)", sha):
                return "skipped_held"
            if await conn.fetchval(
                    """SELECT 1 FROM reparse_jobs
                        WHERE eml_sha256=$1 AND status IN ('queued','running') LIMIT 1""",
                    sha):
                return "skipped_active_job"
            if not await conn.fetchval(
                    "SELECT 1 FROM raw_emls WHERE eml_sha256=$1", sha):
                return "skipped_missing"

            async with conn.transaction():
                summary = await _collect_object_summary(conn, sha)
                audit_payload = {k: v for k, v in summary.items()
                                 if k not in ("files", "spills")}
                # jsonb codec 接收 Python 对象；先把 datetime 转为 ISO 字符串
                audit_payload = _jsonable(audit_payload)
                await conn.execute(
                    """INSERT INTO disposition_audit(run_id, eml_sha256, object_type,
                                                     object_ref, summary, reason, actor)
                       VALUES ($1,$2,'raw_eml',$3,$4,$5,$6)
                       ON CONFLICT DO NOTHING""",
                    run_id, sha, sha, audit_payload, reason, actor)
                for v in summary["versions"]:
                    await conn.execute(
                        """INSERT INTO disposition_audit(run_id, eml_sha256, object_type,
                                                         object_ref, summary, reason, actor)
                           VALUES ($1,$2,'parse_version',$3,$4,$5,$6)
                           ON CONFLICT DO NOTHING""",
                        run_id, sha, f"v{v['version_no']}", _jsonable(v), reason, actor)
                for jid in summary["reparse_job_ids"]:
                    await conn.execute(
                        """INSERT INTO disposition_audit(run_id, eml_sha256, object_type,
                                                         object_ref, summary, reason, actor)
                           VALUES ($1,$2,'reparse_job',$3,'{}'::jsonb,$4,$5)
                           ON CONFLICT DO NOTHING""",
                        run_id, sha, str(jid), reason, actor)

                for rel in summary["files"]:
                    size = await conn.fetchval(
                        "SELECT max(size_bytes) FROM mime_parts WHERE stored_relpath=$1",
                        rel)
                    await conn.execute(
                        """INSERT INTO file_graveyard(run_id, eml_sha256, relpath, kind,
                                                      size_bytes)
                           VALUES ($1,$2,$3,'attachment',$4) ON CONFLICT DO NOTHING""",
                        run_id, sha, rel, size)
                    await conn.execute(
                        """INSERT INTO disposition_audit(run_id, eml_sha256, object_type,
                                                         object_ref, summary, reason, actor)
                           VALUES ($1,$2,'attachment_file',$3,'{}'::jsonb,$4,$5)
                           ON CONFLICT DO NOTHING""",
                        run_id, sha, rel, reason, actor)
                for rel in summary["spills"]:
                    await conn.execute(
                        """INSERT INTO file_graveyard(run_id, eml_sha256, relpath, kind)
                           VALUES ($1,$2,$3,'spill') ON CONFLICT DO NOTHING""",
                        run_id, sha, rel)
                    await conn.execute(
                        """INSERT INTO disposition_audit(run_id, eml_sha256, object_type,
                                                         object_ref, summary, reason, actor)
                           VALUES ($1,$2,'spill_file',$3,'{}'::jsonb,$4,$5)
                           ON CONFLICT DO NOTHING""",
                        run_id, sha, rel, reason, actor)

                # 无 FK 兜底表先清
                await conn.execute(
                    "DELETE FROM current_switches WHERE eml_sha256=$1", sha)
                await conn.execute(
                    "DELETE FROM identity_conflicts WHERE eml_sha256=$1", sha)
                # 授权处置路径：允许级联删除不可变版本（仅此子事务生效）
                await conn.execute("SET LOCAL app.archive_purge='on'")
                # raw_emls 级联：versions/facts/jobs/current_versions
                await conn.execute("DELETE FROM raw_emls WHERE eml_sha256=$1", sha)
            return "purged"
        except Exception as exc:  # noqa: BLE001
            log.error("purge failed sha=%s: %s", sha[:12], exc)
            await _mark_target(pool, target_id, "failed", str(exc)[:500], None)
            return "failed"


async def _mark_target(pool: asyncpg.Pool, target_id: int, state: str,
                       error: str | None, summary) -> None:
    async with pool.acquire() as conn:
        if state == "purged":
            await conn.execute(
                """UPDATE disposition_run_targets
                      SET state='purged', deleted_summary=$2, processed_at=now()
                    WHERE id=$1""", target_id, summary)
        elif state == "failed":
            await conn.execute(
                """UPDATE disposition_run_targets
                      SET state='failed', attempts=attempts+1, last_error=$2,
                          processed_at=now()
                    WHERE id=$1""", target_id, error)
        else:
            await conn.execute(
                """UPDATE disposition_run_targets SET state=$2, processed_at=now()
                    WHERE id=$1""", target_id, state)


# ---------------------------------------------------------- 批处理（游标恢复）

async def process_disposition_batch(pool: asyncpg.Pool, batch_size: int = 25,
                                    attachment_dir: Path | None = None) -> int:
    """处理一个运行的一批 pending 目标。重启后从同一游标继续。返回处理数。"""
    base_dir = (attachment_dir or settings.attachment_dir).resolve()
    async with pool.acquire() as conn:
        run = await conn.fetchrow(
            "SELECT * FROM disposition_runs WHERE status='running' ORDER BY id LIMIT 1")
    if not run:
        return 0
    run_id = run["id"]

    # hold_expiry：策略处置中被重新激活 -> 安全中止整单（已删不回滚，未删保持完整）
    if run["hold_policy_id"]:
        async with pool.acquire() as conn:
            pstatus = await conn.fetchval(
                "SELECT status FROM hold_policies WHERE id=$1", run["hold_policy_id"])
        if pstatus == "active":
            async with pool.acquire() as conn:
                async with conn.transaction():
                    await conn.execute(
                        """UPDATE disposition_runs SET status='aborted', last_note=$2,
                               finished_at=now() WHERE id=$1""",
                        run_id, "hold policy re-activated during disposition; aborted")
                    await conn.execute(
                        """INSERT INTO hold_policy_events(policy_id, action, actor, detail)
                           VALUES ($1,'disposition_completed','system',
                                   'aborted: policy re-activated')""",
                        run["hold_policy_id"])
            log.warning("disposition run %s aborted: policy re-activated", run_id)
            return 0

    # 先把活动任务已结束、之前因占用跳过的目标置回 pending，使本批能立即继续
    async with pool.acquire() as conn:
        await conn.execute(
            """UPDATE disposition_run_targets SET state='pending', processed_at=NULL
                WHERE run_id=$1 AND state='skipped_active_job'
                  AND NOT EXISTS (SELECT 1 FROM reparse_jobs j
                                   WHERE j.eml_sha256=disposition_run_targets.eml_sha256
                                     AND j.status IN ('queued','running'))""",
            run_id)

    async with pool.acquire() as conn:
        targets = await conn.fetch(
            """SELECT * FROM disposition_run_targets
                WHERE run_id=$1 AND state='pending'
                ORDER BY id LIMIT $2::int FOR UPDATE SKIP LOCKED""",
            run_id, batch_size)

    if not targets:
        await delete_pending_graveyard(pool, base_dir, run_id=run_id)
        await _try_finalize_run(pool, run_id)
        return 0

    processed = 0
    purged_shas: list[str] = []
    for t in targets:
        outcome = await purge_one_in_run(
            pool, run_id, t["id"], t["eml_sha256"], run["reason"], run["actor"])
        if outcome == "purged":
            summary = await _raw_audit_summary(pool, run_id, t["eml_sha256"])
            await _mark_target(pool, t["id"], "purged", None, summary)
            purged_shas.append(t["eml_sha256"])
        elif outcome != "failed":
            await _mark_target(pool, t["id"], outcome, None, None)
        processed += 1

    # 数据库事务均已提交后，物理删除本批墓场文件（两阶段，崩溃可对账）
    await delete_pending_graveyard(pool, base_dir, run_id=run_id)

    await _try_finalize_run(pool, run_id)
    return processed


async def _raw_audit_summary(pool: asyncpg.Pool, run_id: int, sha: str):
    async with pool.acquire() as conn:
        return await conn.fetchval(
            """SELECT summary FROM disposition_audit
                WHERE run_id=$1 AND eml_sha256=$2 AND object_type='raw_eml'""",
            run_id, sha)


async def _try_finalize_run(pool: asyncpg.Pool, run_id: int) -> None:
    async with pool.acquire() as conn:
        async with conn.transaction():
            pending = await conn.fetchval(
                "SELECT count(*) FROM disposition_run_targets WHERE run_id=$1 AND state='pending'",
                run_id)
            failed = await conn.fetchval(
                "SELECT count(*) FROM disposition_run_targets WHERE run_id=$1 AND state='failed'",
                run_id)
            graveyard_left = await conn.fetchval(
                """SELECT count(*) FROM file_graveyard
                    WHERE run_id=$1 AND state IN ('pending','failed')""", run_id)
            # pending 中若有目标正被活动重解析/回退占用，或仍有 skipped_active_job，
            # 等待其结束，不提前终态
            active_pending = await conn.fetchval(
                """SELECT count(*) FROM (
                      SELECT 1 FROM disposition_run_targets t
                       WHERE t.run_id=$1 AND t.state='pending'
                         AND EXISTS (SELECT 1 FROM reparse_jobs j
                                      WHERE j.eml_sha256=t.eml_sha256
                                        AND j.status IN ('queued','running'))
                      UNION ALL
                      SELECT 1 FROM disposition_run_targets
                       WHERE run_id=$1 AND state='skipped_active_job'
                   ) wait""", run_id)
            if pending or graveyard_left or active_pending:
                return  # 还有活动任务未决或文件待删，等待下轮
            stats = await conn.fetchrow(
                """SELECT sum((state='purged')::int) AS purged,
                          sum((state LIKE 'skipped%')::int) AS skipped
                     FROM disposition_run_targets WHERE run_id=$1""", run_id)
            final_status = "failed" if failed else "completed"
            await conn.execute(
                """UPDATE disposition_runs
                      SET status=$2, purged_count=$3, skipped_count=$4, finished_at=now()
                    WHERE id=$1 AND status='running'""",
                run_id, final_status, stats["purged"] or 0, stats["skipped"] or 0)
            run = await conn.fetchrow(
                "SELECT * FROM disposition_runs WHERE id=$1", run_id)
            if run and run["hold_policy_id"] and final_status == "completed":
                await conn.execute(
                    """UPDATE hold_policies SET status='completed',
                           completed_at=now(), updated_at=now() WHERE id=$1""",
                    run["hold_policy_id"])
                await conn.execute(
                    """INSERT INTO hold_policy_events(policy_id, action, actor, detail)
                       VALUES ($1,'disposition_completed',$2,$3)""",
                    run["hold_policy_id"], run["actor"],
                    f"purged={stats['purged']} skipped={stats['skipped']}")
    log.info("disposition run %s finalized status=%s purged=%s skipped=%s failed=%s",
             run_id, final_status, stats["purged"], stats["skipped"], failed)


# ---------------------------------------------------------- 文件墓场物理删除

async def delete_pending_graveyard(pool: asyncpg.Pool, base_dir: Path, *,
                                   run_id: int | None = None,
                                   limit: int = 500) -> int:
    """物理删除已提交墓场文件；引用复核 + 幂等。供 worker 周期对账。"""
    async with pool.acquire() as conn:
        if run_id is not None:
            rows = await conn.fetch(
                """SELECT * FROM file_graveyard
                    WHERE run_id=$1 AND state IN ('pending','failed')
                    ORDER BY id LIMIT $2::int""", run_id, limit)
        else:
            rows = await conn.fetch(
                """SELECT * FROM file_graveyard
                    WHERE state IN ('pending','failed') ORDER BY id LIMIT $1::int""",
                limit)
    deleted = 0
    for r in rows:
        rel = r["relpath"]
        try:
            if rel.startswith("text/"):
                target = base_dir / rel
                if not str(target.resolve()).startswith(str(base_dir.resolve()) + "/"):
                    raise ValueError("spill path escapes attachment dir")
            else:
                target = safe_resolve(base_dir, rel)
            if target.exists():
                # 引用复核：任何版本仍引用则保留（跨版本共享保护）
                async with pool.acquire() as conn:
                    in_use = await conn.fetchval(
                        "SELECT 1 FROM mime_parts WHERE stored_relpath=$1 LIMIT 1", rel)
                    in_use_spill = await conn.fetchval(
                        """SELECT 1 FROM messages WHERE
                            $1::text IN (body_text_path, body_html_path,
                                         body_html_escaped_path) LIMIT 1""",
                        rel)
                if in_use or in_use_spill:
                    await _mark_graveyard(pool, r["id"], "failed",
                                          "still referenced; retained")
                    continue
                target.unlink()
            await _mark_graveyard(pool, r["id"], "deleted", None)
            deleted += 1
        except Exception as exc:  # noqa: BLE001
            log.error("graveyard delete failed rel=%s: %s", rel, exc)
            await _mark_graveyard(pool, r["id"], "failed", str(exc)[:300])
    return deleted


async def _mark_graveyard(pool: asyncpg.Pool, graveyard_id: int, state: str,
                          error: str | None) -> None:
    async with pool.acquire() as conn:
        await conn.execute(
            """UPDATE file_graveyard
                  SET state=$2, last_error=$3, attempts=attempts+1,
                      deleted_at=CASE WHEN $2='deleted' THEN now() ELSE deleted_at END
                WHERE id=$1""", graveyard_id, state, error)


# ---------------------------------------------------------- 查询

async def list_runs(pool: asyncpg.Pool, limit: int = 100) -> list[dict]:
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM disposition_runs ORDER BY created_at DESC LIMIT $1::int", limit)
        out = []
        for r in rows:
            d = dict(r)
            d["targets_by_state"] = dict(await conn.fetch(
                """SELECT state, count(*) FROM disposition_run_targets
                    WHERE run_id=$1 GROUP BY state""", r["id"]))
            out.append(d)
    return out


async def get_run_detail(pool: asyncpg.Pool, run_id: int) -> dict | None:
    async with pool.acquire() as conn:
        r = await conn.fetchrow(
            "SELECT * FROM disposition_runs WHERE id=$1", run_id)
        if not r:
            return None
        d = dict(r)
        d["targets"] = [dict(x) for x in await conn.fetch(
            """SELECT eml_sha256,state,attempts,last_error,processed_at,deleted_summary
                 FROM disposition_run_targets WHERE run_id=$1 ORDER BY id""", run_id)]
        d["audit"] = [dict(x) for x in await conn.fetch(
            """SELECT eml_sha256,object_type,object_ref,reason,actor,at
                 FROM disposition_audit WHERE run_id=$1 ORDER BY id LIMIT 500""", run_id)]
    return d


async def list_audit(pool: asyncpg.Pool, sha: str | None = None, limit: int = 100):
    async with pool.acquire() as conn:
        if sha:
            rows = await conn.fetch(
                "SELECT * FROM disposition_audit WHERE eml_sha256=$1 ORDER BY at DESC LIMIT $2::int",
                sha, limit)
        else:
            rows = await conn.fetch(
                "SELECT * FROM disposition_audit ORDER BY at DESC LIMIT $1::int",
                limit)
    return [dict(r) for r in rows]
