"""持久化层：信头、关系、MIME 树、附件落盘、会话冲突检测。

所有写操作在单个事务内完成；附件字节仅写入受控目录，绝不进入日志。
"""
from __future__ import annotations

import logging
from pathlib import Path

import asyncpg

from . import threads
from .config import PARSER_VERSION, settings
from .parser import MailFact
from .security import (
    storage_relpath,
    write_attachment,
)

log = logging.getLogger("archive.repo")

# 文本部件多大开始落文件
_TEXT_PART_LIMIT = 200_000


class RepoError(Exception):
    pass


# ============================================================ 入库

async def ingest(pool: asyncpg.Pool, fact: MailFact, eml_bytes: bytes,
                 eml_filename: str | None, attachment_dir: Path | None = None) -> dict:
    """按 eml_sha256 幂等入库。返回简要结果（不含任何正文/附件内容）。"""
    base_dir = (attachment_dir or settings.attachment_dir).resolve()
    async with pool.acquire() as conn:
        async with conn.transaction():
            # 1) 原始 EML（幂等：同摘要直接返回已存在；重新解析先清派生数据）
            existed = await conn.fetchval(
                "SELECT id FROM raw_emls WHERE eml_sha256=$1", fact.eml_sha256)
            if existed:
                # 重新解析：清掉派生事实，保留 raw_emls
                await _delete_derived(conn, fact.eml_sha256)
                reparse = True
                log.info("reparsing eml sha=%s size=%d", fact.eml_sha256[:16], fact.eml_size)
            else:
                reparse = False
                await conn.execute(
                    """INSERT INTO raw_emls(eml_sha256, eml_filename, eml_size, eml_bytes)
                       VALUES ($1,$2,$3,$4)""",
                    fact.eml_sha256, eml_filename, fact.eml_size, eml_bytes)

            # 2) 附件/正文大对象先落受控目录（数据库不持有大字节）
            stored_paths = await _store_parts(conn, fact, base_dir)

            # 3) 信头主记录
            body_text, body_text_path = _persist_large_text(
                fact.body_text, fact.eml_sha256, "body-text", base_dir, settings.inline_text_limit)
            body_html, body_html_path = _persist_large_text(
                fact.body_html, fact.eml_sha256, "body-html", base_dir, settings.inline_text_limit)
            body_esc, body_esc_path = _persist_large_text(
                fact.body_html_escaped, fact.eml_sha256, "body-html-escaped",
                base_dir, settings.inline_text_limit)

            await conn.execute(
                """INSERT INTO messages(
                       eml_sha256, message_id, message_id_raw, message_id_count,
                       subject, subject_raw, date_raw, sent_at,
                       from_raw, sender_raw, reply_to_raw, to_raw, cc_raw, bcc_raw,
                       in_reply_to, in_reply_to_raw, references_list, references_raw,
                       raw_headers, body_text, body_text_path, body_html,
                       body_html_escaped, body_html_path, body_html_escaped_path,
                       body_charset, html_external_refs,
                       has_attachments)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,
                           $15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28)""",
                fact.eml_sha256, fact.message_id, fact.message_id_raw, fact.message_id_count,
                fact.subject, fact.subject_raw, fact.date_raw, fact.sent_at,
                fact.from_raw, fact.sender_raw, fact.reply_to_raw,
                fact.to_raw, fact.cc_raw, fact.bcc_raw,
                fact.in_reply_to, fact.in_reply_to_raw, fact.references_list,
                fact.references_raw, fact.raw_headers,
                body_text, body_text_path, body_html,
                body_esc, body_html_path, body_esc_path, fact.body_charset or None,
                fact.html_external_refs,
                any(p.is_attachment for p in fact.parts),
            )

            # 4) 地址与关系
            await _store_addresses(conn, fact)

            # 5) MIME 部件
            await _store_parts_rows(conn, fact, stored_paths)

            # 6) 会话边 + 标识冲突（信内重复/缺失已在 parse_issues，这里落冲突表）
            await _store_links(conn, fact)
            await _store_identity_conflicts(conn, fact)

            # 7) 解析问题
            await conn.execute(
                "DELETE FROM parse_issues WHERE eml_sha256=$1", fact.eml_sha256)
            await conn.executemany(
                """INSERT INTO parse_issues(eml_sha256, issue_no, severity, kind, location, detail)
                   VALUES ($1,$2,$3,$4,$5,$6)""",
                [(fact.eml_sha256, i.issue_no, i.severity, i.kind, i.location, i.detail)
                 for i in fact.issues],
            )

            # 8) 解析批次
            att_count = sum(1 for p in fact.parts if p.is_attachment)
            await conn.execute(
                """INSERT INTO parse_runs(eml_sha256, parser_version, parse_status,
                                          part_count, attachment_count)
                   VALUES ($1,$2,$3,$4,$5)
                   ON CONFLICT (eml_sha256) DO UPDATE
                     SET parsed_at=now(), parser_version=$2, parse_status=$3,
                         part_count=$4, attachment_count=$5""",
                fact.eml_sha256, PARSER_VERSION, fact.parse_status,
                len(fact.parts), att_count)

    # 9) 事务提交后做图级检测（环 / 悬空 / 重用），单独事务写冲突表
    await _detect_graph_conflicts(pool, fact)

    return {
        "eml_sha256": fact.eml_sha256,
        "status": fact.parse_status,
        "reparsed": reparse,
        "parts": len(fact.parts),
        "issues": len(fact.issues),
        "message_id": fact.message_id,
    }


async def _delete_derived(conn: asyncpg.Connection, sha: str) -> None:
    for table in ("parse_issues", "parse_runs", "message_addresses", "mime_parts",
                  "message_links", "identity_conflicts"):
        await conn.execute(f"DELETE FROM {table} WHERE eml_sha256=$1", sha)
    await conn.execute("DELETE FROM messages WHERE eml_sha256=$1", sha)


# ---------------------------------------------------------- 附件落盘

async def _store_parts(conn: asyncpg.Connection, fact: MailFact,
                       base_dir: Path) -> dict[str, str]:
    """把需要落盘的叶子部件写入受控目录。返回 mime_path -> relpath。"""
    paths: dict[str, str] = {}
    for p in fact.parts:
        if p.payload is None or p.is_container:
            continue
        should_store = (
            p.is_attachment
            or p.is_inline
            or (p.content_type.lower() == "message/rfc822")
            or (p.content_type.startswith("text/") and not p.is_body)
            or (not p.content_type.startswith("text/") and not p.is_body)
        )
        if not should_store:
            continue
        assert p.sha256
        rel = storage_relpath(fact.eml_sha256, p.sha256)
        # 在线程池里写文件（同步 IO）
        import asyncio
        size = await asyncio.to_thread(write_attachment, base_dir, rel, p.payload)
        paths[p.mime_path] = rel
        # 释放内存中的 payload 引用由调用方控制；这里不修改 fact，便于测试
        log.info("stored part eml=%s path=%s type=%s size=%d",
                 fact.eml_sha256[:12], p.mime_path, p.content_type, size)
    return paths


def _persist_large_text(text: str | None, eml_sha: str, label: str,
                        base_dir: Path, limit: int) -> tuple[str | None, str | None]:
    """正文优先入库；超过上限则落受控目录，库里只留路径。"""
    if text is None:
        return None, None
    if len(text) <= limit:
        return text, None
    import hashlib
    digest = hashlib.sha256((label + ":" + text[:4096]).encode()).hexdigest()[:16]
    rel = f"text/{eml_sha[:2]}/{eml_sha[2:4]}/{digest}-{label}.txt"
    # text 路径不符合 safe_resolve 的严格格式，因此使用专用写入
    target = (base_dir / rel)
    if not str(target.resolve()).startswith(str(base_dir.resolve()) + "/"):
        raise RepoError("text path traversal blocked")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    log.info("large %s spilled to file for eml=%s chars=%d", label, eml_sha[:12], len(text))
    return None, rel


# ---------------------------------------------------------- 行存储

async def _store_addresses(conn: asyncpg.Connection, fact: MailFact) -> None:
    for a in fact.addresses:
        key = a["email_norm"] or a["email"] or a["display_name"]
        if not key:
            continue
        row = await conn.fetchrow(
            """INSERT INTO addresses(email_norm, email_raw)
               VALUES ($1,$2)
               ON CONFLICT (email_norm) DO UPDATE SET email_raw=EXCLUDED.email_raw
               RETURNING id""",
            a["email_norm"], a["email"] or "",
        )
        await conn.execute(
            """INSERT INTO message_addresses(eml_sha256, address_id, role, position, display_name)
               VALUES ($1,$2,$3,$4,$5)
               ON CONFLICT DO NOTHING""",
            fact.eml_sha256, row["id"], a["role"], a["position"], a["display_name"],
        )


async def _store_parts_rows(conn: asyncpg.Connection, fact: MailFact,
                            stored: dict[str, str]) -> None:
    import json
    for p in fact.parts:
        await conn.execute(
            """INSERT INTO mime_parts(
                   eml_sha256, part_no, mime_path, depth, content_type, content_type_params,
                   disposition, filename_raw, filename_safe, charset, content_id, cid_norm,
                   transfer_encoding, size_bytes, is_container, is_attachment, is_inline,
                   is_body, stored_relpath, sha256, nested_message_id, nested_subject)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,
                       $18,$19,$20,$21,$22)""",
            fact.eml_sha256, p.part_no, p.mime_path, p.depth, p.content_type,
            json.dumps(p.content_type_params, ensure_ascii=False),
            p.disposition, p.filename_raw, p.filename_safe, p.charset,
            p.content_id, p.cid_norm, p.transfer_encoding, p.size_bytes,
            p.is_container, p.is_attachment, p.is_inline, p.is_body,
            stored.get(p.mime_path), p.sha256, p.nested_message_id, p.nested_subject,
        )


async def _store_links(conn: asyncpg.Connection, fact: MailFact) -> None:
    pos = 0
    if fact.in_reply_to:
        await conn.execute(
            """INSERT INTO message_links(eml_sha256, link_type, position, target_message_id, target_raw)
               VALUES ($1,'in_reply_to',$2,$3,$4)""",
            fact.eml_sha256, pos, fact.in_reply_to, fact.in_reply_to_raw)
        pos += 1
    for i, ref in enumerate(fact.references_list):
        await conn.execute(
            """INSERT INTO message_links(eml_sha256, link_type, position, target_message_id, target_raw)
               VALUES ($1,'references',$2,$3,$4)""",
            fact.eml_sha256, i, ref, None)


async def _store_identity_conflicts(conn: asyncpg.Connection, fact: MailFact) -> None:
    if fact.message_id_count > 1:
        await conn.execute(
            """INSERT INTO identity_conflicts(conflict_type, message_id, eml_sha256, detail)
               VALUES ('duplicate_message_id_in_header',$1,$2,$3)
               ON CONFLICT DO NOTHING""",
            fact.message_id, fact.eml_sha256,
            f"{fact.message_id_count} Message-ID headers; first retained")
    if not fact.message_id:
        await conn.execute(
            """INSERT INTO identity_conflicts(conflict_type, message_id, eml_sha256, detail)
               VALUES ('missing_message_id',NULL,$1,$2)
               ON CONFLICT DO NOTHING""",
            fact.eml_sha256, "message has no usable Message-ID; subject is weak candidate only")
    if fact.message_id:
        key = fact.message_id.lower()
        if fact.in_reply_to and fact.in_reply_to.lower() == key:
            await conn.execute(
                """INSERT INTO identity_conflicts(conflict_type, message_id, eml_sha256, detail)
                   VALUES ('self_reference',$1,$2,$3) ON CONFLICT DO NOTHING""",
                fact.message_id, fact.eml_sha256, "In-Reply-To self reference")
        for ref in fact.references_list:
            if ref.lower() == key:
                await conn.execute(
                    """INSERT INTO identity_conflicts(conflict_type, message_id, eml_sha256, detail)
                       VALUES ('self_reference',$1,$2,$3) ON CONFLICT DO NOTHING""",
                    fact.message_id, fact.eml_sha256, "References self reference")
                break


# ---------------------------------------------------------- 图级冲突

async def _detect_graph_conflicts(pool: asyncpg.Pool, fact: MailFact) -> None:
    """入库后基于全库引用图检测：Message-ID 重用、悬空引用、引用环。

    说明：全库图适合中小规模档案；超大库应改为受影响子图增量检测（README 注明）。
    """
    async with pool.acquire() as conn:
        # Message-ID 重用：同一规范化 ID 对应多个不同 eml
        if fact.message_id:
            rows = await conn.fetch(
                """SELECT eml_sha256 FROM messages
                   WHERE lower(message_id) = lower($1) AND eml_sha256 <> $2""",
                fact.message_id, fact.eml_sha256)
            for r in rows:
                await conn.execute(
                    """INSERT INTO identity_conflicts(conflict_type, message_id, eml_sha256, detail)
                       VALUES ('reassigned_message_id',$1,$2,$3) ON CONFLICT DO NOTHING""",
                    fact.message_id, fact.eml_sha256,
                    f"same Message-ID reused by eml {r['eml_sha256'][:16]}; not merged")
                # 对方那封也记一笔，便于双向定位
                await conn.execute(
                    """INSERT INTO identity_conflicts(conflict_type, message_id, eml_sha256, detail)
                       VALUES ('reassigned_message_id',$1,$2,$3) ON CONFLICT DO NOTHING""",
                    fact.message_id, r["eml_sha256"],
                    f"same Message-ID reused by eml {fact.eml_sha256[:16]}; not merged")

        # 悬空引用
        if fact.in_reply_to or fact.references_list:
            targets = []
            if fact.in_reply_to:
                targets.append(fact.in_reply_to)
            targets.extend(fact.references_list)
            for t in dict.fromkeys(targets):
                hit = await conn.fetchval(
                    "SELECT eml_sha256 FROM messages WHERE lower(message_id)=lower($1)", t)
                await conn.execute(
                    """INSERT INTO link_resolutions(message_link_id, resolved, target_eml_sha256)
                       SELECT id, $2, $3 FROM message_links
                        WHERE eml_sha256=$1 AND lower(target_message_id)=lower($4)
                        ON CONFLICT (message_link_id) DO UPDATE
                          SET resolved=$2, target_eml_sha256=$3""",
                    fact.eml_sha256, bool(hit), hit, t)
                if not hit:
                    await conn.execute(
                        """INSERT INTO identity_conflicts(conflict_type, message_id, eml_sha256, detail)
                           VALUES ('dangling_reference',$1,$2,$3) ON CONFLICT DO NOTHING""",
                        t, fact.eml_sha256, "referenced Message-ID not present in archive")

        # 环：取全库边（source 为邮件自身 ID，target 为被引 ID；忽略无 ID 的邮件）
        edge_rows = await conn.fetch(
            """SELECT lower(m.message_id) AS src, lower(l.target_message_id) AS dst
                 FROM message_links l
                 JOIN messages m ON m.eml_sha256 = l.eml_sha256
                WHERE m.message_id IS NOT NULL""")
        edges = [(r["src"], r["dst"]) for r in edge_rows if r["src"] and r["dst"]]
        cycles = threads.find_cycles(edges)
        for comp in cycles:
            comp_set = set(comp)
            # 找环中当前库内真实存在的邮件记录
            members = await conn.fetch(
                """SELECT message_id, eml_sha256 FROM messages
                    WHERE lower(message_id) = ANY($1)""",
                comp)
            detail = "reference cycle among: " + ", ".join(sorted(comp))[:400]
            for m in members:
                await conn.execute(
                    """INSERT INTO identity_conflicts(conflict_type, message_id, eml_sha256, detail)
                       VALUES ('reference_cycle',$1,$2,$3) ON CONFLICT DO NOTHING""",
                    m["message_id"], m["eml_sha256"], detail)


# ============================================================ 查询

async def list_messages(pool: asyncpg.Pool, limit: int, offset: int) -> list[dict]:
    rows = await pool.fetch(
        """SELECT m.eml_sha256, m.message_id, m.subject, m.sent_at,
                  m.from_raw, m.to_raw, m.has_attachments, r.received_at
             FROM messages m JOIN raw_emls r ON r.eml_sha256 = m.eml_sha256
            ORDER BY r.received_at DESC
            LIMIT $1 OFFSET $2""", limit, offset)
    return [dict(r) for r in rows]


async def get_message(pool: asyncpg.Pool, sha: str) -> dict | None:
    row = await pool.fetchrow(
        """SELECT m.*, p.parse_status, p.part_count, p.attachment_count, p.parsed_at
             FROM messages m
             LEFT JOIN parse_runs p ON p.eml_sha256 = m.eml_sha256
            WHERE m.eml_sha256=$1""", sha)
    if not row:
        return None
    d = dict(row)
    # 正文若溢出到文件则回读（受控目录校验）
    readback = (
        ("body_text", "body_text_path"),
        ("body_html", "body_html_path"),
        ("body_html_escaped", "body_html_escaped_path"),
    )
    for col, path_col in readback:
        if d.get(col) is None and d.get(path_col):
            fp = settings.attachment_dir / d[path_col]
            if fp.is_file() and str(fp.resolve()).startswith(
                    str(settings.attachment_dir.resolve()) + "/"):
                d[col] = fp.read_text(encoding="utf-8")
            else:
                d[col] = None
    d["parts"] = [dict(r) for r in await pool.fetch(
        "SELECT * FROM mime_parts WHERE eml_sha256=$1 ORDER BY part_no", sha)]
    d["issues"] = [dict(r) for r in await pool.fetch(
        "SELECT issue_no,severity,kind,location,detail FROM parse_issues WHERE eml_sha256=$1 ORDER BY issue_no", sha)]
    d["addresses"] = [dict(r) for r in await pool.fetch(
        """SELECT ma.role, ma.position, ma.display_name, a.email_norm, a.email_raw
             FROM message_addresses ma JOIN addresses a ON a.id=ma.address_id
            WHERE ma.eml_sha256=$1 ORDER BY ma.role, ma.position""", sha)]
    d["conflicts"] = [dict(r) for r in await pool.fetch(
        "SELECT conflict_type,message_id,detail,detected_at FROM identity_conflicts WHERE eml_sha256=$1 ORDER BY detected_at", sha)]
    return d


async def get_raw(pool: asyncpg.Pool, sha: str) -> dict | None:
    row = await pool.fetchrow(
        "SELECT eml_sha256, eml_filename, eml_size, eml_bytes, received_at FROM raw_emls WHERE eml_sha256=$1",
        sha)
    return dict(row) if row else None


async def get_part_for_download(pool: asyncpg.Pool, sha: str,
                                mime_path: str) -> dict | None:
    row = await pool.fetchrow(
        "SELECT * FROM mime_parts WHERE eml_sha256=$1 AND mime_path=$2",
        sha, mime_path)
    return dict(row) if row else None


async def search_messages(pool: asyncpg.Pool, query: str, limit: int) -> list[dict]:
    """检索：simple 全文检索（拉丁/编号）+ trigram ILIKE 子串回退（CJK/短词）。

    LIKE 通配符由参数转义；两路子集 UNION 去重，全文命中权重更高。
    """
    like = "%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    rows = await pool.fetch(
        r"""
        WITH fts AS (
            SELECT eml_sha256,
                   ts_rank(search_tsv, websearch_to_tsquery('simple', $1)) AS rank
              FROM messages
             WHERE search_tsv @@ websearch_to_tsquery('simple', $1)
        ),
        tri AS (
            SELECT eml_sha256, 0.05 AS rank
              FROM messages
             WHERE subject ILIKE $2 ESCAPE '\'
                OR body_text ILIKE $2 ESCAPE '\'
                OR from_raw ILIKE $2 ESCAPE '\'
                OR to_raw ILIKE $2 ESCAPE '\'
                OR message_id ILIKE $2 ESCAPE '\'
        )
        SELECT DISTINCT ON (m.eml_sha256)
               m.eml_sha256, m.message_id, m.subject, m.sent_at, m.from_raw,
               COALESCE(f.rank, 0) + COALESCE(t.rank, 0) AS rank
          FROM messages m
          LEFT JOIN fts f ON f.eml_sha256 = m.eml_sha256
          LEFT JOIN tri t ON t.eml_sha256 = m.eml_sha256
         WHERE f.eml_sha256 IS NOT NULL OR t.eml_sha256 IS NOT NULL
         ORDER BY m.eml_sha256, rank DESC
         LIMIT $3
        """, query, like, limit)
    out = [dict(r) for r in rows]
    out.sort(key=lambda r: r["rank"], reverse=True)
    return out


async def get_thread(pool: asyncpg.Pool, sha: str) -> dict:
    """强线程：沿 Message-ID 引用边双向遍历；主题相同仅作弱候选单独返回。"""
    root = await pool.fetchrow(
        "SELECT message_id, subject FROM messages WHERE eml_sha256=$1", sha)
    if not root:
        return {"found": False}
    mid = root["message_id"]
    edges_rows = await pool.fetch(
        """SELECT lower(m.message_id) AS src, lower(l.target_message_id) AS dst
             FROM message_links l JOIN messages m ON m.eml_sha256=l.eml_sha256
            WHERE m.message_id IS NOT NULL""")
    edges = [(r["src"], r["dst"]) for r in edges_rows]

    strong_ids: set[str] = set()
    if mid:
        key = mid.lower()
        strong_ids = {key}
        strong_ids.update(threads.ancestors(edges, key))
        strong_ids.update(threads.descendants(edges, key))
    strong_rows = await pool.fetch(
        """SELECT eml_sha256, message_id, subject, sent_at,
                  in_reply_to, references_list
             FROM messages
            WHERE message_id IS NOT NULL AND lower(message_id) = ANY($1)
            ORDER BY sent_at NULLS LAST""", list(strong_ids))

    # 弱候选：规范化主题相同，但没有任何强引用关系 —— 仅候选，不合并
    weak_rows = []
    if root["subject"]:
        subj_norm = _normalize_subject(root["subject"])
        candidates = await pool.fetch(
            """SELECT eml_sha256, message_id, subject, sent_at
                 FROM messages
                WHERE eml_sha256 <> $1
                  AND regexp_replace(coalesce(subject,''), '(?i)^(re|fwd|aw|wg)(\[[0-9]+\])?:\s*', '') = $2
                ORDER BY sent_at NULLS LAST""",
            sha, subj_norm)
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


async def list_failures(pool: asyncpg.Pool, limit: int) -> list[dict]:
    rows = await pool.fetch(
        """SELECT r.eml_sha256, r.eml_filename, p.parse_status, p.parsed_at,
                  (SELECT count(*) FROM parse_issues i WHERE i.eml_sha256=r.eml_sha256) AS issue_count
             FROM raw_emls r JOIN parse_runs p ON p.eml_sha256=r.eml_sha256
            WHERE p.parse_status <> 'ok'
            ORDER BY p.parsed_at DESC LIMIT $1""", limit)
    out = []
    for r in rows:
        d = dict(r)
        d["issues"] = [dict(x) for x in await pool.fetch(
            """SELECT issue_no,severity,kind,location,detail FROM parse_issues
                WHERE eml_sha256=$1 ORDER BY issue_no LIMIT 20""", r["eml_sha256"])]
        out.append(d)
    return out


def _normalize_subject(subject: str) -> str:
    import re
    s = re.sub(r"^(?i:(re|fwd|aw|wg))(\[[0-9]+\])?:\s*", "", subject.strip())
    return s.strip()
