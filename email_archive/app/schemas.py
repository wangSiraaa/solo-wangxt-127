"""API 响应模型。"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel


class IngestResult(BaseModel):
    eml_sha256: str
    created: bool
    version_id: int
    version_no: int
    policy_version: str
    status: str


class ReparseJobOut(BaseModel):
    id: int
    eml_sha256: str
    policy_version: str
    reason: str | None = None
    requested_by: str | None = None
    status: str
    attempts: int
    max_attempts: int
    run_after: datetime
    locked_by: str | None = None
    lease_until: datetime | None = None
    last_error: str | None = None
    result_version_id: int | None = None
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    attempts_history: list[dict[str, Any]] = []
    versions: list[dict[str, Any]] = []


class ReparseCreate(BaseModel):
    policy_version: str = "policy.v2.0"
    reason: str | None = None
    requested_by: str | None = None


class VersionOut(BaseModel):
    id: int
    eml_sha256: str
    version_no: int
    parser_version: str
    policy_version: str
    parse_status: str
    part_count: int
    attachment_count: int
    source: str
    reason: str | None = None
    requested_by: str | None = None
    job_id: int | None = None
    created_at: datetime
    is_current: bool | None = None
    switched: bool | None = None


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
    detected_at: datetime | None = None


class MessageDetail(BaseModel):
    eml_sha256: str
    version_no: int
    version_id: int
    policy_version: str
    parse_status: str
    is_current: bool
    created_at: datetime
    message_id: str | None = None
    message_id_raw: str | None = None
    message_id_count: int = 1
    subject: str | None = None
    date_raw: str | None = None
    sent_at: datetime | None = None
    from_raw: str | None = None
    to_raw: str | None = None
    cc_raw: str | None = None
    bcc_raw: str | None = None
    in_reply_to: str | None = None
    references_list: list[str] = []
    body_text: str | None = None
    body_html_escaped: str | None = None
    body_html: str | None = None
    body_charset: str | None = None
    html_external_refs: list[str] = []
    has_attachments: bool = False
    parts: list[PartOut]
    issues: list[IssueOut]
    addresses: list[AddressOut]
    version_conflicts: list[ConflictOut]
    identity_conflicts: list[ConflictOut]
    links: list[dict[str, Any]] = []
    message: Any = None
    raw_headers: Any = None


class MessageSummary(BaseModel):
    eml_sha256: str
    message_id: str | None = None
    subject: str | None = None
    sent_at: datetime | None = None
    from_raw: str | None = None
    to_raw: str | None = None
    has_attachments: bool
    version_no: int
    parse_status: str


class SearchHit(BaseModel):
    eml_sha256: str
    message_id: str | None = None
    subject: str | None = None
    sent_at: datetime | None = None
    from_raw: str | None = None
    version_no: int
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


# ---------------- 证据保全 / 处置

class HoldCreate(BaseModel):
    name: str
    reason: str
    created_by: str
    hold_type: str = "single"            # single | query
    eml_sha256: str | None = None
    query_filter: dict[str, Any] = {}
    expires_at: datetime | None = None
    idempotency_key: str | None = None
    activate: bool = True


class HoldOut(BaseModel):
    id: int
    name: str
    hold_type: str
    reason: str
    created_by: str
    status: str
    expires_at: datetime | None = None
    activated_at: datetime | None = None
    completed_at: datetime | None = None
    target_count: int | None = None
    created: bool | None = None


class ManualDispositionCreate(BaseModel):
    reason: str
    actor: str = "admin"
    idempotency_key: str | None = None
    eml_sha256: list[str] | None = None   # 缺省=全库无保全无活动任务邮件
