"""EML 解析核心：仅使用 Python email 标准库，纯函数式产出，不触碰网络与磁盘日志。

产出 MailFact：
- 信头事实（Message-ID/References/In-Reply-To 原文与规范化值并存）
- 完整 MIME 树（容器 + 叶子，含 mime_path/深度/缺陷位置）
- 正文（text/html 原文 + 转义；text/plain）
- 附件与内嵌资源（含解码后的文件名与 CID）
- 可定位 issues（哪个 part、什么 defect、错误还是警告）

解析器不写盘；附件字节挂在 PartFact.payload（bytes|None）上，由仓储层落到受控目录。
"""
from __future__ import annotations

import binascii
import email
import email.errors
import email.header
import email.message
import email.policy
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from . import normalizers
from .security import classify_html_refs, sanitize_filename, sha256_hex

# 拒绝拒绝拒绝炸弹之外的异常规模（炸弹防护在 API 层做总量限制；这里做部件数兜底）
MAX_PARTS = 5000

# 按内容类型识别的容器
MULTIPART_PREFIX = "multipart/"
RFC822_TYPES = {"message/rfc822", "message/global"}

# email 库 defects 中的致命类名子串（小写匹配）
_FATAL_MARKERS = ("startboundarynotfound", "startboundary", "invalidbase64",
                  "noboundaryinmultipart", "missingboundary",
                  "nocharset", "nomultipartcharset", "boundaryerror",
                  "closeboundary", "firstboundary", "multipartboundary",
                  "undecodablebytes", "invaliddate", "addresserror",
                  "invalidmessageid", "invalidcontenttype", "invalidheader")


@dataclass
class Issue:
    severity: str            # error / warning / info
    kind: str
    detail: str
    location: str | None = None
    issue_no: int = 0


@dataclass
class PartFact:
    part_no: int
    mime_path: str
    depth: int
    content_type: str
    content_type_params: dict[str, str]
    disposition: str | None
    filename_raw: str | None
    filename_safe: str | None
    charset: str | None
    content_id: str | None
    cid_norm: str | None
    transfer_encoding: str | None
    size_bytes: int | None
    is_container: bool
    is_attachment: bool
    is_inline: bool
    is_body: bool = False
    payload: bytes | None = None        # 已解码字节（容器为 None）
    text: str | None = None             # 文本部件解码结果
    decode_error: str | None = None
    sha256: str | None = None
    nested_message_id: str | None = None
    nested_subject: str | None = None
    nested_date_raw: str | None = None


@dataclass
class MailFact:
    # 原始字节
    eml_sha256: str
    eml_size: int
    # 信头
    message_id: str | None
    message_id_raw: str | None
    message_id_count: int
    subject: str | None
    subject_raw: str | None
    date_raw: str | None
    sent_at: datetime | None
    from_raw: str | None
    sender_raw: str | None
    reply_to_raw: str | None
    to_raw: str | None
    cc_raw: str | None
    bcc_raw: str | None
    in_reply_to: str | None
    in_reply_to_raw: str | None
    references_list: list[str]
    references_raw: str | None
    raw_headers: list[dict[str, Any]]
    addresses: list[dict[str, Any]]
    # 正文
    body_text: str | None = None
    body_text_path_meta: str | None = None   # mime_path
    body_html: str | None = None
    body_html_escaped: str | None = None
    body_html_path_meta: str | None = None
    body_charset: str | None = None
    html_cids: list[str] = field(default_factory=list)
    html_external_refs: list[str] = field(default_factory=list)
    # 结构
    parts: list[PartFact] = field(default_factory=list)
    issues: list[Issue] = field(default_factory=list)
    # 解析状态
    fatal: bool = False

    @property
    def attachment_parts(self) -> list[PartFact]:
        return [p for p in self.parts if p.is_attachment and not p.is_container]

    @property
    def inline_parts(self) -> list[PartFact]:
        return [p for p in self.parts if p.is_inline]

    @property
    def parse_status(self) -> str:
        if self.fatal:
            return "failed"
        if any(i.severity == "error" for i in self.issues):
            return "ok_with_issues"
        return "ok"


# ================================================================ 入口

def parse_eml(data: bytes, eml_sha256: str | None = None) -> MailFact:
    """解析原始 EML 字节。任何意外异常都转成 fatal issue，不向上抛。"""
    digest = eml_sha256 or sha256_hex(data)
    builder = _FactBuilder(data, digest)
    return builder.build()


class _FactBuilder:
    def __init__(self, data: bytes, digest: str):
        self.data = data
        self.digest = digest
        self.issues: list[Issue] = []
        self.parts: list[PartFact] = []
        self._counter = 0
        # (location, kind, detail) 去重；walk 可能在容器与入口处重复访问 defects
        self._seen_issues: set[tuple[str | None, str, str]] = set()

    def _add_issue(self, severity: str, kind: str, detail: str,
                   location: str | None = None) -> None:
        key = (location, kind, detail)
        if key in self._seen_issues:
            return
        self._seen_issues.add(key)
        self.issues.append(Issue(severity, kind, detail, location))

    # ---- 主流程
    def build(self) -> MailFact:
        msg: email.message.Message
        try:
            msg = email.message_from_bytes(self.data, policy=email.policy.default)
        except Exception as exc:  # 极端情况下字节无法构造成 Message
            self._add_issue("error", type(exc).__name__,
                            f"failed to construct message: {exc}"[:300])
            return self._finalize(None, fatal=True)

        # 顶层缺陷（多为 boundary 级结构问题）
        self._collect_defects(msg, "1")

        fact = self._extract_headers(msg)

        # 递归 MIME 树
        try:
            self._walk(msg, mime_path="1", depth=0)
        except _PartLimit:
            self._add_issue("error", "PartLimit",
                            f"MIME part count exceeded {MAX_PARTS}")

        fact_fatal = len(self.parts) >= MAX_PARTS

        # 选择正文并交叉校验内嵌资源
        self._select_body()
        return self._finalize(fact, fatal=fact_fatal, msg=msg)

    # ---- 信头
    def _extract_headers(self, msg: email.message.Message) -> MailFact:
        def header_all(name: str) -> list[str]:
            try:
                vals = msg.get_all(name, [])
            except Exception:
                vals = []
            return [str(v) for v in vals] if vals else []

        def header_first(name: str) -> str | None:
            vals = header_all(name)
            return vals[0] if vals else None

        # 保序多值信头快照
        raw_headers: list[dict[str, Any]] = []
        try:
            for k, v in msg.raw_items():
                raw_headers.append({"name": k, "value": str(v)})
        except Exception as exc:
            self._add_issue("warning", type(exc).__name__,
                            f"raw header enumeration failed: {exc}"[:300])

        # Message-ID：重复/多值保留冲突
        mid_values = header_all("Message-ID")
        mid_raw = mid_values[0] if mid_values else None
        mid = normalizers.normalize_message_id(mid_raw)
        mid_count = len(mid_values)
        if mid_count > 1:
            self._add_issue("error", "DuplicateMessageID",
                            f"{mid_count} Message-ID headers present; kept first, conflict retained",
                            "header:Message-ID")
        if not mid:
            self._add_issue("warning", "MissingMessageID",
                            "no usable Message-ID; threading falls back to weak subject candidates",
                            "header:Message-ID")

        # Subject：尝试标准解码，原文保留
        subject_raw = header_first("Subject")
        subject = self._decode_header_text(subject_raw)
        if subject_raw is not None and subject is None:
            self._add_issue("warning", "UndecodableSubject",
                            "subject could not be decoded", "header:Subject")

        # Date：缺失/裸时间为警告，真正无法解析为错误
        date_raw = header_first("Date")
        sent_at, date_issue = normalizers.parse_date(date_raw)
        if date_issue:
            if date_issue.startswith("unparseable"):
                sev = "error"
            else:
                sev = "warning"
            self._add_issue(sev, "DateParse", date_issue, "header:Date")

        # In-Reply-To（可能含多个 <id>，标准只取第一个，其余登记）
        irt_raw = header_first("In-Reply-To")
        irt_ids = normalizers.parse_id_list([irt_raw] if irt_raw else [])
        irt = irt_ids[0] if irt_ids else None
        if len(irt_ids) > 1:
            self._add_issue("warning", "MultipleInReplyTo",
                            f"In-Reply-To contained {len(irt_ids)} ids; first used as parent, all kept in links",
                            "header:In-Reply-To")
        if irt_raw and not irt_ids:
            self._add_issue("warning", "MalformedInReplyTo",
                            "In-Reply-To present but no parseable id", "header:In-Reply-To")

        # References
        refs_values = header_all("References")
        refs = normalizers.parse_id_list(refs_values)
        refs_raw = " ".join(refs_values) if refs_values else None

        # 地址信头
        addr_roles = [
            ("from", header_first("From")),
            ("sender", header_first("Sender")),
            ("reply_to", header_first("Reply-To")),
            ("to", header_first("To")),
            ("cc", header_first("Cc")),
            ("bcc", header_first("Bcc")),
        ]
        addresses: list[dict[str, Any]] = []
        for role, raw in addr_roles:
            parsed = normalizers.parse_address_header(raw)
            if raw and not parsed:
                self._add_issue("warning", "UnparseableAddress",
                                f"{role} address header present but no address parsed",
                                f"header:{role}")
            for pos, a in enumerate(parsed):
                addresses.append({"role": role, "position": pos, **a})

        # 自引用：IRO/References 指向自己的 Message-ID
        if mid:
            mid_key = mid.lower()
            if irt and irt.lower() == mid_key:
                self._add_issue("warning", "SelfReference",
                                "In-Reply-To points to the message's own Message-ID",
                                "header:In-Reply-To")
            if any(r.lower() == mid_key for r in refs):
                self._add_issue("warning", "SelfReference",
                                "References contain the message's own Message-ID",
                                "header:References")

        return MailFact(
            eml_sha256=self.digest,
            eml_size=len(self.data),
            message_id=mid,
            message_id_raw=mid_raw,
            message_id_count=mid_count,
            subject=subject,
            subject_raw=subject_raw,
            date_raw=date_raw,
            sent_at=sent_at,
            from_raw=header_first("From"),
            sender_raw=header_first("Sender"),
            reply_to_raw=header_first("Reply-To"),
            to_raw=header_first("To"),
            cc_raw=header_first("Cc"),
            bcc_raw=header_first("Bcc"),
            in_reply_to=irt,
            in_reply_to_raw=irt_raw,
            references_list=refs,
            references_raw=refs_raw,
            raw_headers=raw_headers,
            addresses=addresses,
            issues=self.issues,
            parts=self.parts,
        )

    # ---- MIME 树
    def _walk(self, part: email.message.Message, mime_path: str, depth: int) -> None:
        if len(self.parts) >= MAX_PARTS:
            raise _PartLimit()
        self._counter += 1
        ctype = self._safe_content_type(part, mime_path)
        disp = self._safe_disposition(part)
        ctype_params = self._safe_content_type_params(part)
        filename_raw = self._safe_filename(part)
        cid_raw = self._safe_content_id(part)
        cid_norm = cid_raw[1:-1].strip() if cid_raw and cid_raw.startswith("<") \
            and cid_raw.endswith(">") else (cid_raw.strip() if cid_raw else None)

        is_multipart = ctype.startswith(MULTIPART_PREFIX)
        is_rfc822 = ctype.lower() in RFC822_TYPES

        pf = PartFact(
            part_no=self._counter,
            mime_path=mime_path,
            depth=depth,
            content_type=ctype,
            content_type_params=ctype_params,
            disposition=disp,
            filename_raw=filename_raw,
            filename_safe=sanitize_filename(filename_raw),
            charset=ctype_params.get("charset"),
            content_id=cid_raw,
            cid_norm=cid_norm,
            transfer_encoding=(part.get("Content-Transfer-Encoding") or "").strip() or None,
            size_bytes=None,
            is_container=is_multipart or is_rfc822,
            is_attachment=disp == "attachment" or (disp is None and bool(filename_raw) and not is_multipart),
            is_inline=disp == "inline" or (disp is None and bool(cid_raw)),
        )
        self.parts.append(pf)
        self._collect_defects(part, mime_path)

        if is_multipart:
            # multipart/*：遍历所有子段（defects 中的 boundary 问题已在上面收集）
            for i, child in enumerate(part.iter_parts(), start=1):
                self._walk(child, f"{mime_path}.{i}", depth + 1)
            # multipart 的 boundary 参数可能缺失：保证“无 boundary”一定显式可见
            if "boundary" not in ctype_params:
                self._add_issue("error", "MissingBoundary",
                                "multipart part without boundary parameter",
                                mime_path)
            return

        if is_rfc822:
            # 内嵌 message/rfc822：保存内部信原始字节并登记内部信标识。
            # 标准库对带 Content-Transfer-Encoding（如 base64）的 message/rfc822
            # 不会自动把内部信解码为结构化 Message，需要：
            # 1) 取传输解码后的字节；2) 再解析一次。
            inner: email.message.Message | None = None
            raw: bytes | None = None
            if part.is_multipart():
                try:
                    candidate = part.get_payload(0)
                except Exception:
                    candidate = None
                if isinstance(candidate, email.message.Message) and candidate.keys():
                    inner = candidate
            if inner is None:
                raw = self._decode_rfc822_payload(part, pf, mime_path)
            if raw is None:
                self._add_issue("warning", "EmptyPayload",
                                "message/rfc822 part has no extractable bytes", mime_path)
            if inner is None and raw:
                stripped = raw.lstrip(b"\r\n")
                try:
                    inner = email.message_from_bytes(stripped,
                                                     policy=email.policy.default)
                    if not inner.keys():
                        inner = None
                except Exception:
                    inner = None
            # 落盘的“内部信原文”应是解码后的真实信；as_bytes() 对结构对象可靠
            if isinstance(inner, email.message.Message):
                try:
                    raw = inner.as_bytes()
                except Exception:
                    pass
                pf.nested_message_id = normalizers.normalize_message_id(
                    inner.get("Message-ID"))
                pf.nested_subject = self._decode_header_text(inner.get("Subject"))
                pf.nested_date_raw = inner.get("Date")
                self._collect_defects(inner, f"{mime_path}.0")
                if part.get("Content-Transfer-Encoding"):
                    self._add_issue("info", "NestedMessageTransferDecoded",
                                    "message/rfc822 carried with "
                                    f"{part.get('Content-Transfer-Encoding')} CTE; inner message decoded from bytes",
                                    mime_path)
            pf.payload = raw
            pf.size_bytes = len(raw) if raw is not None else None
            pf.sha256 = sha256_hex(raw) if raw is not None else None
            return

        # 叶子段：解码
        raw = self._decode_payload(part, pf, mime_path)
        pf.payload = raw
        pf.size_bytes = len(raw) if raw is not None else None
        pf.sha256 = sha256_hex(raw) if raw is not None else None

        if ctype.startswith("text/") and raw is not None:
            self._decode_text(part, pf, raw, mime_path)

    # ---- payload 解码
    def _decode_payload(self, part: email.message.Message, pf: PartFact,
                        mime_path: str) -> bytes | None:
        before = set(id(d) for d in getattr(part, "defects", []))
        try:
            payload = part.get_payload(decode=True)
        except (UnicodeError, binascii.Error, ValueError) as exc:
            self._add_issue("error", type(exc).__name__,
                            f"transfer-decode failed: {exc}"[:300], mime_path)
            return self._raw_payload_fallback(part, mime_path)
        except Exception as exc:  # 罕见解析器异常
            self._add_issue("error", type(exc).__name__,
                            f"unexpected decode failure: {exc}"[:300], mime_path)
            return self._raw_payload_fallback(part, mime_path)

        # 解码后 email 库可能把 base64 缺陷挂到 defects
        for d in getattr(part, "defects", []):
            if id(d) not in before:
                self._record_defect(d, mime_path)
        if payload is None:
            self._add_issue("warning", "EmptyPayload", "part has no payload", mime_path)
        return payload

    def _decode_rfc822_payload(self, part: email.message.Message, pf: PartFact,
                               mime_path: str) -> bytes | None:
        """message/rfc822 可能带 7bit/quoted-printable/base64 CTE。

        标准库对 message/* 的 get_payload(decode=True) 在部分 CTE 下返回 None，
        这里手工取未处理载荷并按声明的 CTE 解码。
        """
        cte = (part.get("Content-Transfer-Encoding") or "").strip().lower()
        # 带 CTE 时标准库可能把载荷解析成一个“无头子 Message”，decode=True 返回 None。
        # 直接从该对象取字符串载荷手工解码。
        raw_obj = part.get_payload(decode=False)
        if isinstance(raw_obj, list) and raw_obj and isinstance(
                raw_obj[0], email.message.Message):
            raw_obj = raw_obj[0].get_payload(decode=False)
        if isinstance(raw_obj, list):
            return None
        if raw_obj is None:
            # 最后尝试标准解码路径
            try:
                return part.get_payload(decode=True)
            except Exception:
                return None
        raw = raw_obj if isinstance(raw_obj, bytes) else \
            str(raw_obj).encode("ascii", errors="surrogateescape")
        if not cte:
            return raw
        import base64
        import quopri
        try:
            if cte == "base64":
                return base64.b64decode(b"".join(raw.split()))
            if cte in ("quoted-printable", "quotedprintable"):
                return quopri.decodestring(raw)
            if cte in ("7bit", "8bit", "binary"):
                return raw
        except Exception as exc:
            self._add_issue("error", type(exc).__name__,
                            f"rfc822 manual {cte} decode failed: {exc}"[:300], mime_path)
        return raw

    def _raw_payload_fallback(self, part: email.message.Message,
                              mime_path: str) -> bytes | None:
        """解码失败时保留未处理字节，保证证据不丢（仍受存储策略约束）。"""
        try:
            raw = part.get_payload(decode=False)
        except Exception:
            return None
        if isinstance(raw, bytes):
            return raw
        if isinstance(raw, str):
            return raw.encode("utf-8", errors="replace")
        if isinstance(raw, list):
            return None
        return None

    def _decode_text(self, part: email.message.Message, pf: PartFact,
                     raw: bytes, mime_path: str) -> None:
        charset = pf.charset
        candidates = []
        if charset:
            candidates.append(charset)
        # 尝试从 part.get_content_charset()（会做别名规范化）
        try:
            cs = part.get_content_charset()
            if cs and cs not in candidates:
                candidates.append(cs)
        except Exception:
            pass
        candidates += ["utf-8", "latin-1"]

        text: str | None = None
        used: str | None = None
        for enc in candidates:
            try:
                text = raw.decode(enc)
                used = enc
                break
            except (UnicodeDecodeError, LookupError):
                continue
        if text is None:
            text = raw.decode(charset or "utf-8", errors="replace")
            used = charset or "utf-8"
            self._add_issue("error", "CharsetDecode",
                            f"text not decodable in declared/guessed charsets; replaced bytes",
                            mime_path)
        elif charset and used and used.lower().replace("-", "") != \
                charset.lower().replace("-", ""):
            self._add_issue("warning", "CharsetFallback",
                            f"declared charset {charset!r} failed; decoded as {used!r}",
                            mime_path)
        elif not charset:
            self._add_issue("info", "CharsetGuessed",
                            f"no charset declared; decoded as {used!r}", mime_path)
        pf.text = text
        pf.charset = used

    # ---- 正文选择
    def _select_body(self) -> None:
        if not self.parts:
            return
        text_parts = [p for p in self.parts
                      if not p.is_container and not p.is_attachment
                      and p.content_type.startswith("text/") and p.text is not None]
        # html 优先 multipart/alternative 的语义；这里取第一个 html，否则第一个 plain
        html_part = next((p for p in text_parts
                          if p.content_type.lower() == "text/html"), None)
        plain_part = next((p for p in text_parts
                           if p.content_type.lower() == "text/plain"), None)

        chosen_text = plain_part or (None if html_part else (text_parts[0] if text_parts else None))
        chosen_html = html_part

        if len([p for p in text_parts if p.content_type.lower() == "text/plain"]) > 1:
            self._add_issue("info", "MultipleBodies",
                            "multiple text/plain parts found; first selected", None)
        if len([p for p in text_parts if p.content_type.lower() == "text/html"]) > 1:
            self._add_issue("info", "MultipleBodies",
                            "multiple text/html parts found; first selected", None)

        if chosen_text:
            chosen_text.is_body = True
        if chosen_html:
            chosen_html.is_body = True

        # 结果在 _finalize 里装配（避免循环依赖 self.parts）
        self._chosen_text = chosen_text          # type: ignore[attr-defined]
        self._chosen_html = chosen_html          # type: ignore[attr-defined]

    # ---- defects
    def _collect_defects(self, part: email.message.Message, mime_path: str) -> None:
        for d in getattr(part, "defects", []):
            self._record_defect(d, mime_path)

    def _record_defect(self, defect: Any, mime_path: str) -> None:
        name = type(defect).__name__
        desc = str(defect)[:300] or name
        severity = "error" if self._is_fatal_defect(name) else "warning"
        self._add_issue(severity, name, desc, mime_path)

    @staticmethod
    def _is_fatal_defect(name: str) -> bool:
        low = name.lower()
        return any(m in low for m in _FATAL_MARKERS)

    # ---- 安全取信头（解析坏信头不致命时给默认值）
    @staticmethod
    def _safe_content_type(part: email.message.Message, mime_path: str) -> str:
        try:
            return part.get_content_type()
        except Exception:
            raw = part.get("Content-Type")
            if raw:
                token = raw.split(";", 1)[0].strip().lower()
                if token:
                    return token
            return "application/octet-stream"

    def _safe_content_type_params(self, part: email.message.Message) -> dict[str, str]:
        try:
            params = part.get_params()
        except Exception:
            params = None
        out: dict[str, str] = {}
        if params:
            for k, v in params:
                if k:  # 首项 key 为 None 或 ''
                    out[str(k).lower()] = str(v)
        return out

    @staticmethod
    def _safe_disposition(part: email.message.Message) -> str | None:
        try:
            disp = part.get_content_disposition()
            return disp.lower() if disp else None
        except Exception:
            raw = part.get("Content-Disposition")
            if raw:
                return raw.split(";", 1)[0].strip().lower() or None
            return None

    def _safe_filename(self, part: email.message.Message) -> str | None:
        """优先用标准库 RFC2231/2047 解码；失败再手工兜底参数。"""
        try:
            fn = part.get_filename()  # policy.default 会解码 encoded-word/2231
            if fn:
                return fn
        except Exception:
            pass
        # 兜底：直接从 Content-Disposition / Content-Type 参数找 filename
        for header_name in ("Content-Disposition", "Content-Type"):
            raw = part.get(header_name)
            if not raw:
                continue
            m = re.search(r'filename\*?\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^;]+))',
                          raw, re.IGNORECASE)
            if m:
                val = next(g for g in m.groups() if g is not None)
                # RFC 2047 encoded-word
                try:
                    decoded = email.header.decode_header(val.strip())
                    pieces = []
                    for text, enc in decoded:
                        if isinstance(text, bytes):
                            pieces.append(text.decode(enc or "utf-8", errors="replace"))
                        else:
                            pieces.append(text)
                    return "".join(pieces)
                except Exception:
                    return val.strip()
        return None

    @staticmethod
    def _safe_content_id(part: email.message.Message) -> str | None:
        cid = part.get("Content-ID")
        return cid.strip() if cid else None

    @staticmethod
    def _decode_header_text(raw: str | None) -> str | None:
        if raw is None:
            return None
        try:
            from email.base64mime import header_decode  # noqa: F401
            pieces = email.header.decode_header(raw)
            out = []
            for text, enc in pieces:
                if isinstance(text, bytes):
                    out.append(text.decode(enc or "ascii", errors="replace"))
                else:
                    out.append(text)
            return "".join(out)
        except Exception:
            return raw

    # ---- 收尾
    def _finalize(self, fact: MailFact | None, fatal: bool,
                  msg: email.message.Message | None = None) -> MailFact:
        if fact is None:
            # 构造 Message 都失败：最小空壳
            fact = MailFact(
                eml_sha256=self.digest, eml_size=len(self.data),
                message_id=None, message_id_raw=None, message_id_count=0,
                subject=None, subject_raw=None, date_raw=None, sent_at=None,
                from_raw=None, sender_raw=None, reply_to_raw=None,
                to_raw=None, cc_raw=None, bcc_raw=None,
                in_reply_to=None, in_reply_to_raw=None,
                references_list=[], references_raw=None,
                raw_headers=[], addresses=[],
                issues=self.issues, parts=self.parts,
            )
        # 正文装配
        chosen_text = getattr(self, "_chosen_text", None)
        chosen_html = getattr(self, "_chosen_html", None)
        if chosen_text:
            fact.body_text = chosen_text.text
            fact.body_text_path_meta = chosen_text.mime_path
            fact.body_charset = chosen_text.charset
        if chosen_html and chosen_html.text is not None:
            from .security import escape_html
            fact.body_html = chosen_html.text
            fact.body_html_escaped = escape_html(chosen_html.text)
            fact.body_html_path_meta = chosen_html.mime_path
            cids, external = classify_html_refs(chosen_html.text)
            fact.html_cids = cids
            fact.html_external_refs = external
            # CID 交叉校验：HTML 引用但邮件里没有对应 inline 部件 → 登记
            have = {p.cid_norm for p in self.parts if p.cid_norm}
            for cid in cids:
                if cid not in have:
                    self._add_issue("warning", "UnresolvedCid",
                                    f"HTML references cid:{cid} but no matching inline part",
                                    chosen_html.mime_path)
            if external:
                self._add_issue("info", "ExternalResourceNotLoaded",
                                f"{len(external)} external resource reference(s) recorded, never fetched",
                                chosen_html.mime_path)
        # 附件名缺失但被判定为附件（在编号之前追加，保证 issue_no 连续）
        for p in fact.parts:
            if p.is_attachment and not p.filename_safe and not p.is_container:
                p.filename_safe = f"unnamed-part-{p.part_no}.bin"
                self._add_issue("info", "UnnamedAttachment",
                                "attachment without usable filename; server-side placeholder used as metadata",
                                p.mime_path)
        # issue 编号（按出现顺序）
        for i, iss in enumerate(self.issues, start=1):
            iss.issue_no = i
        # fatal: 构造失败，或存在 start boundary 级致命结构缺陷
        fatal_structure = any(
            i.severity == "error" and i.kind in (
                "StartBoundaryNotFoundDefect", "NoBoundaryInMultipartDefect",
                "MissingBoundary", "PartLimit")
            for i in self.issues
        )
        fact.fatal = bool(fatal or fatal_structure)
        return fact


class _PartLimit(Exception):
    pass
