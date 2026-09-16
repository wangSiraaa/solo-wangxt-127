"""FastAPI 路由：上传解析、检索、原文/附件受控下载、线程、失败定位。"""
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
    MessageDetail,
    MessageSummary,
    SearchHit,
    ThreadResult,
)
from .security import (
    download_header_filename,
    safe_resolve,
    sha256_hex,
)

log = logging.getLogger("archive.api")
router = APIRouter()


# ------------------------------------------------------------ 上传解析

async def _read_limited(request: Request) -> bytes:
    """读取整个请求体并执行大小上限；不流式落盘到附件区。"""
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
        # 用标准库 email 解析 multipart 表单，避免框架对文件名的隐式处理
        import email
        import email.policy
        header = (f"Content-Type: {ctype}\r\n\r\n").encode()
        msg = email.message_from_bytes(header + body, policy=email.policy.default)
        file_part = None
        for part in msg.iter_parts():
            # 跳过空字段，优先选择带文件名的部件
            if part.get_filename() or file_part is None:
                file_part = part
        if file_part is None:
            raise HTTPException(400, "multipart request without file part")
        return file_part.get_payload(decode=True) or b"", file_part.get_filename()
    # application/octet-stream 或 message/rfc822
    return body, None


@router.post("/emls", response_model=IngestResult, status_code=201)
async def upload_eml(request: Request, pool=Depends(get_pool)) -> IngestResult:
    body = await _read_limited(request)
    if not body:
        raise HTTPException(400, "empty body")
    eml_bytes, filename = _extract_eml(request, body)
    digest = sha256_hex(eml_bytes)
    log.info("ingest start sha=%s bytes=%d filename=%s",
             digest[:12], len(eml_bytes), filename or "-")

    # CPU 密集解析放线程池；解析器不发网络、不写日志正文
    fact = await asyncio.to_thread(parse_eml, eml_bytes, digest)

    # 即使 fatal 也入库（raw + issues），保证“解析失败可定位”
    result = await repo.ingest(pool, fact, eml_bytes, filename)
    log.info("ingest done sha=%s status=%s parts=%d issues=%d",
             digest[:12], result["status"], result["parts"], result["issues"])
    return IngestResult(**result)


# ------------------------------------------------------------ 查询

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


@router.get("/emls/{sha}", response_model=MessageDetail)
async def get_eml(sha: str, include_raw_html: bool = False,
                  pool=Depends(get_pool)):
    _validate_sha(sha)
    detail = await repo.get_message(pool, sha)
    if not detail:
        raise HTTPException(404, "eml not found")
    if not include_raw_html:
        detail["body_html"] = None  # 默认只给转义版，杜绝前端误渲染
    return detail


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
async def download_part(sha: str, mime_path: str, pool=Depends(get_pool)):
    _validate_sha(sha)
    _validate_mime_path(mime_path)
    part = await repo.get_part_for_download(pool, sha, mime_path)
    if not part or not part["stored_relpath"]:
        raise HTTPResponse(404, "stored part not found")
    try:
        target = safe_resolve(settings.attachment_dir, part["stored_relpath"])
    except ValueError:
        raise HTTPException(400, "invalid storage path")
    if not target.is_file():
        raise HTTPException(404, "file missing on storage")

    media_type = part["content_type"] or "application/octet-stream"
    if media_type.lower() in ("text/html", "image/svg+xml"):
        # HTML/SVG 可能含脚本：强制下载、禁止渲染
        media_type = "application/octet-stream"
    safe_name = download_header_filename(
        part["filename_safe"], f"part-{part['part_no']}.bin")

    def iterfile():
        # 分块读取，避免把大附件全部装入内存
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


_SAFE_DISPLAY_PREFIXES = ("image/", "video/", "audio/", "text/plain",
                          "application/pdf")


def _is_safe_display(media_type: str) -> bool:
    mt = media_type.lower()
    return any(mt == p or mt.startswith(p) for p in
               ("image/", "video/", "audio/")) or mt in (
        "text/plain", "application/pdf")
