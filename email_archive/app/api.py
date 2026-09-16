"""FastAPI 路由：上传解析、版本/任务管理、检索、受控下载、线程、失败定位。"""
from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response, StreamingResponse

from . import repository as repo
from .config import settings
from .db import get_pool
from .parser import parse_eml
from .schemas import (
    IngestResult,
    MessageSummary,
    ReparseCreate,
    SearchHit,
    ThreadResult,
    VersionOut,
)
from .security import download_header_filename, safe_resolve, sha256_hex

log = logging.getLogger("archive.api")
router = APIRouter()

POLICY_RE = r"^[A-Za-z0-9._-]{1,64}$"
import re as _re
_POLICY_RE = _re.compile(POLICY_RE)


# ------------------------------------------------------------ 上传解析

async def _read_limited(request: Request) -> bytes:
    cl = request.headers.get("content-length")
    if cl and int(cl) > settings.max_upload_bytes:
        raise HTTPException(413, "upload too large (content-length exceeds limit)")
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > settings.max_upload_bytes:
            raise HTTPException(413, "upload too large (stream exceeded limit)")
        chunks.append(chunk)
    return b"".join(chunks)


def _extract_eml(request: Request, body: bytes) -> tuple[bytes, str | None]:
    ctype = request.headers.get("content-type", "")
    if ctype.startswith("multipart/form-data"):
        import email
        import email.policy
        header = (f"Content-Type: {ctype}\r\n\r\n").encode()
        msg = email.message_from_bytes(header + body, policy=email.policy.default)
        file_part = None
        for part in msg.iter_parts():
            if part.get_filename() or file_part is None:
                file_part = part
        if file_part is None:
            raise HTTPException(400, "multipart request without file part")
        return file_part.get_payload(decode=True) or b"", file_part.get_filename()
    return body, None


@router.post("/emls", response_model=IngestResult, status_code=201)
async def upload_eml(request: Request, pool=Depends(get_pool)) -> IngestResult:
    body = await _read_limited(request)
    if not body:
        raise HTTPException(400, "empty body")
    eml_bytes, filename = _extract_eml(request, body)
    digest = sha256_hex(eml_bytes)
    log.info("ingest start sha=%s bytes=%d", digest[:12], len(eml_bytes))
    fact = await asyncio.to_thread(parse_eml, eml_bytes, digest)
    result = await repo.ingest_initial(pool, fact, eml_bytes, filename)
    log.info("ingest sha=%s created=%s version=v%s status=%s",
             digest[:12], result["created"], result["version_no"], result["status"])
    return IngestResult(**result)


# ------------------------------------------------------------ 当前版本查询

@router.get("/emls", response_model=list[MessageSummary])
async def list_emls(limit: int = Query(50, ge=1, le=500),
                    offset: int = Query(0, ge=0),
                    pool=Depends(get_pool)):
    return await repo.list_messages(pool, limit, offset)


@router.get("/search", response_model=list[SearchHit])
async def search(q: str = Query(..., min_length=1, max_length=500),
                 limit: int = Query(50, ge=1, le=200),
                 pool=Depends(get_pool)):
    return await repo.search_messages(pool, q, limit)


def _serialize_detail(d: dict, include_raw_html: bool) -> dict:
    msg = d.pop("message") or {}
    if not include_raw_html:
        msg.pop("body_html", None)
    out = {
        "eml_sha256": d["eml_sha256"],
        "version_id": d["id"],
        "version_no": d["version_no"],
        "policy_version": d["policy_version"],
        "parse_status": d["parse_status"],
        "is_current": d["is_current"],
        "created_at": d["created_at"],
        "message_id": msg.get("message_id"),
        "message_id_raw": msg.get("message_id_raw"),
        "message_id_count": msg.get("message_id_count", 1),
        "subject": msg.get("subject"),
        "date_raw": msg.get("date_raw"),
        "sent_at": msg.get("sent_at"),
        "from_raw": msg.get("from_raw"),
        "to_raw": msg.get("to_raw"),
        "cc_raw": msg.get("cc_raw"),
        "bcc_raw": msg.get("bcc_raw"),
        "in_reply_to": msg.get("in_reply_to"),
        "references_list": msg.get("references_list") or [],
        "body_text": msg.get("body_text"),
        "body_html_escaped": msg.get("body_html_escaped"),
        "body_html": msg.get("body_html"),
        "body_charset": msg.get("body_charset"),
        "html_external_refs": msg.get("html_external_refs") or [],
        "has_attachments": msg.get("has_attachments", False),
        "raw_headers": msg.get("raw_headers"),
        "parts": d["parts"],
        "issues": d["issues"],
        "addresses": d["addresses"],
        "links": d.get("links", []),
        "version_conflicts": d["version_conflicts"],
        "identity_conflicts": d["identity_conflicts"],
    }
    return out


@router.get("/emls/{sha}")
async def get_eml(sha: str, include_raw_html: bool = False,
                  version: int | None = Query(None, ge=1),
                  pool=Depends(get_pool)):
    _validate_sha(sha)
    detail = await repo.get_version_detail(pool, sha, version)
    if not detail:
        raise HTTPException(404, "eml/version not found")
    return _serialize_detail(detail, include_raw_html)


@router.get("/emls/{sha}/thread", response_model=ThreadResult)
async def get_thread(sha: str, pool=Depends(get_pool)):
    _validate_sha(sha)
    result = await repo.get_thread(pool, sha)
    if not result.get("found"):
        raise HTTPException(404, "eml not found")
    return result


@router.get("/failures")
async def failures(limit: int = Query(50, ge=1, le=200), pool=Depends(get_pool)):
    return await repo.list_failures(pool, limit)


# ------------------------------------------------------------ 版本管理

@router.get("/emls/{sha}/versions", response_model=list[VersionOut])
async def get_versions(sha: str, pool=Depends(get_pool)):
    _validate_sha(sha)
    versions = await repo.list_versions(pool, sha)
    if not versions:
        raise HTTPException(404, "eml not found")
    return versions


@router.post("/emls/{sha}/versions/{version_no}/activate")
async def activate_version(sha: str, version_no: int, request: Request,
                           pool=Depends(get_pool)):
    _validate_sha(sha)
    if version_no < 1:
        raise HTTPException(400, "invalid version_no")
    actor = request.headers.get("x-actor", "api")
    try:
        detail = await repo.activate_version(pool, sha, version_no, actor=actor)
    except repo.RepoError as exc:
        raise HTTPException(404, str(exc))
    return _serialize_detail(detail, include_raw_html=False) | {
        "switched": detail["switched"]}


# ------------------------------------------------------------ 重解析任务

@router.post("/emls/{sha}/reparse", status_code=202)
async def create_reparse(sha: str, body: ReparseCreate, request: Request,
                         pool=Depends(get_pool)):
    _validate_sha(sha)
    if not _POLICY_RE.match(body.policy_version):
        raise HTTPException(400, "invalid policy_version")
    actor = body.requested_by or request.headers.get("x-actor", "api")
    try:
        job, created = await repo.create_reparse_job(
            pool, sha, body.policy_version, body.reason, actor)
    except repo.RepoError:
        raise HTTPException(404, "eml not found")
    d = dict(job)
    d.update({"attempts_history": [], "versions": []})
    return {**d, "created": created,
            "note": None if created else "merged into existing active job "
                                        "for same eml+policy"}


@router.get("/jobs")
async def jobs(eml_sha256: str | None = None,
               limit: int = Query(100, ge=1, le=500),
               pool=Depends(get_pool)):
    if eml_sha256:
        _validate_sha(eml_sha256)
    return await repo.list_jobs(pool, eml_sha256, limit)


@router.get("/jobs/{job_id}")
async def get_job(job_id: int, pool=Depends(get_pool)):
    d = await repo.get_job(pool, job_id)
    if not d:
        raise HTTPException(404, "job not found")
    return d


@router.post("/jobs/{job_id}/cancel")
async def cancel_job(job_id: int, pool=Depends(get_pool)):
    try:
        return await repo.cancel_job(pool, job_id)
    except repo.RepoError:
        raise HTTPException(404, "job not found")
    except repo.JobConflict as exc:
        raise HTTPException(409, str(exc))


@router.post("/jobs/{job_id}/retry", status_code=202)
async def retry_job(job_id: int, pool=Depends(get_pool)):
    try:
        return await repo.retry_job(pool, job_id)
    except repo.RepoError:
        raise HTTPException(404, "job not found")
    except repo.JobConflict as exc:
        raise HTTPException(409, str(exc))


# ------------------------------------------------------------ 受控下载

@router.get("/emls/{sha}/raw")
async def download_raw(sha: str, pool=Depends(get_pool)) -> Response:
    _validate_sha(sha)
    row = await repo.get_raw(pool, sha)
    if not row:
        raise HTTPException(404, "eml not found")
    filename = download_header_filename(row["eml_filename"], f"{sha[:16]}.eml")
    return Response(
        content=row["eml_bytes"],
        media_type="message/rfc822",
        headers={
            "Content-Disposition":
                f'attachment; filename="{sha[:16]}.eml"; filename*=UTF-8\'\'{_h(filename)}',
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'",
        },
    )


@router.get("/emls/{sha}/parts/{mime_path:path}")
async def download_part(sha: str, mime_path: str, request: Request,
                        version: int | None = Query(None, ge=1),
                        pool=Depends(get_pool)):
    _validate_sha(sha)
    _validate_mime_path(mime_path)
    part = await repo.get_part_for_download(pool, sha, mime_path, version)
    if not part or not part["stored_relpath"]:
        raise HTTPException(404, "stored part not found")
    try:
        target = safe_resolve(settings.attachment_dir, part["stored_relpath"])
    except ValueError:
        raise HTTPException(400, "invalid storage path")
    if not target.is_file():
        raise HTTPException(404, "file missing on storage")

    media_type = part["content_type"] or "application/octet-stream"
    if media_type.lower() in ("text/html", "image/svg+xml"):
        media_type = "application/octet-stream"
    safe_name = download_header_filename(
        part["filename_safe"], f"part-{part['part_no']}.bin")

    def iterfile():
        with open(target, "rb") as fh:
            while True:
                buf = fh.read(64 * 1024)
                if not buf:
                    break
                yield buf

    return StreamingResponse(
        iterfile(),
        media_type=media_type if _is_safe_display(media_type) else "application/octet-stream",
        headers={
            "Content-Disposition":
                f"attachment; filename=part-{part['part_no']}.bin; filename*=UTF-8''{_h(safe_name)}",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'",
            "X-Version-No": str(part.get("version_no") or ""),
        },
    )


# ------------------------------------------------------------ 辅助

def _validate_sha(sha: str) -> None:
    if not (len(sha) == 64 and all(c in "0123456789abcdef" for c in sha.lower())):
        raise HTTPException(400, "invalid sha256")


def _validate_mime_path(path: str) -> None:
    if not path or not all(p.isdigit() for p in path.split(".")):
        raise HTTPException(400, "invalid mime path")


def _h(value: str) -> str:
    from urllib.parse import quote
    return quote(value, safe="")


def _is_safe_display(media_type: str) -> bool:
    mt = media_type.lower()
    return any(mt == p or mt.startswith(p) for p in
               ("image/", "video/", "audio/")) or mt in (
        "text/plain", "application/pdf")
