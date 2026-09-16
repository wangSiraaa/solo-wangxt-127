"""API 响应模型：只输出元数据与文本事实，不直接回吐未净化的 HTML 内容类型。"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel


class IngestResult(BaseModel):
    eml_sha256: str
    status: str
    reparsed: bool
    parts: int
    issues: int
    message_id: str | None = None


class IssueOut(BaseModel):
    issue_no: int
    severity: str
    kind: str
    location: str | None = None
    detail: str


class PartOut(BaseModel):
    part_no: int
    mime_path: str
    depth: int
    content_type: str
    disposition: str | None = None
    filename_raw: str | None = None
    filename_safe: str | None = None
    charset: str | None = None
    cid_norm: str | None = None
    size_bytes: int | None = None
    is_container: bool
    is_attachment: bool
    is_inline: bool
    is_body: bool
    stored_relpath: str | None = None
    sha256: str | None = None
    nested_message_id: str | None = None
    nested_subject: str | None = None


class AddressOut(BaseModel):
    role: str
    position: int
    display_name: str | None = None
    email_norm: str | None = None
    email_raw: str | None = None


class ConflictOut(BaseModel):
    conflict_type: str
    message_id: str | None = None
    detail: str
    detected_at: datetime


class MessageDetail(BaseModel):
    eml_sha256: str
    message_id: str | None = None
    message_id_raw: str | None = None
    message_id_count: int
    subject: str | None = None
    date_raw: str | None = None
    sent_at: datetime | None = None
    from_raw: str | None = None
    to_raw: str | None = None
    cc_raw: str | None = None
    bcc_raw: str | None = None
    in_reply_to: str | None = None
    references_list: list[str]
    body_text: str | None = None
    # 默认输出转义后的 HTML；原始 HTML 通过 ?include_raw_html=1 显式获取
    body_html_escaped: str | None = None
    body_html: str | None = None
    body_charset: str | None = None
    html_external_refs: list[str]
    has_attachments: bool
    parse_status: str | None = None
    part_count: int | None = None
    attachment_count: int | None = None
    parts: list[PartOut]
    issues: list[IssueOut]
    addresses: list[AddressOut]
    conflicts: list[ConflictOut]
    raw_headers: Any = None


class MessageSummary(BaseModel):
    eml_sha256: str
    message_id: str | None = None
    subject: str | None = None
    sent_at: datetime | None = None
    from_raw: str | None = None
    to_raw: str | None = None
    has_attachments: bool


class SearchHit(BaseModel):
    eml_sha256: str
    message_id: str | None = None
    subject: str | None = None
    sent_at: datetime | None = None
    from_raw: str | None = None
    rank: float


class ThreadMember(BaseModel):
    eml_sha256: str
    message_id: str | None = None
    subject: str | None = None
    sent_at: datetime | None = None
    in_reply_to: str | None = None
    references_list: list[str] | None = None


class ThreadResult(BaseModel):
    found: bool
    root_eml_sha256: str | None = None
    root_message_id: str | None = None
    strong_thread: list[ThreadMember] = []
    weak_subject_candidates: list[dict[str, Any]] = []
    weak_note: str | None = None


class FailureOut(BaseModel):
    eml_sha256: str
    eml_filename: str | None = None
    parse_status: str
    parsed_at: datetime
    issue_count: int
    issues: list[IssueOut]
