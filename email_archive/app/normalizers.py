"""信头规范化：Message-ID、地址、日期。纯函数，便于单测。"""
from __future__ import annotations

import email.utils
import re
from datetime import datetime, timezone
from email.headerregistry import Address

# Message-ID 的标准形态是 <left@right>；兼容裸 ID。
_MSGID_RE = re.compile(r"<([^<>]+)>")


def normalize_message_id(value: str | None) -> str | None:
    """提取尖括号内内容并 strip；空值返回 None。

    不做大小写折叠（部分本地系统区分大小写），保留原样右侧，
    只做首尾空白与折叠空白处理。冲突检测时另用 lower 形态。
    """
    if value is None:
        return None
    m = _MSGID_RE.search(value)
    token = m.group(1) if m else value.strip()
    token = re.sub(r"\s+", "", token)  # id 内折叠空白非法，直接去除
    return token or None


def message_id_key(value: str | None) -> str | None:
    """用于比对/去重的键：规范化后小写。"""
    nid = normalize_message_id(value)
    return nid.lower() if nid else None


def parse_id_list(values: list[str]) -> list[str]:
    """解析 References 等可能含多个 <id>、折叠多行的信头；保序去重。"""
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if not value:
            continue
        for m in _MSGID_RE.finditer(value):
            token = re.sub(r"\s+", "", m.group(1))
            if token and token.lower() not in seen:
                seen.add(token.lower())
                out.append(token)
    return out


# ---------------------------------------------------------------- 地址

_COMMENT_RE = re.compile(r"\([^()]*\)")


def normalize_email(addr_spec: str | None) -> str | None:
    if not addr_spec:
        return None
    addr = addr_spec.strip()
    if "@" in addr:
        local, _, domain = addr.rpartition("@")
        addr = local.strip() + "@" + domain.strip().lower()
    return addr or None


def parse_address_header(raw: str | None) -> list[dict]:
    """解析地址信头为 [{display_name, email, email_norm}]。

    使用 email.utils.getaddresses（容忍畸形输入），显示名尝试 RFC2047 解码。
    """
    if not raw:
        return []
    result: list[dict] = []
    # getaddresses 接收 list
    for name, addr in email.utils.getaddresses([raw]):
        if not addr and not name:
            continue
        display = _decode_display_name(name)
        norm = normalize_email(addr)
        result.append(
            {
                "display_name": display or None,
                "email": addr or None,
                "email_norm": norm,
            }
        )
    return result


def _decode_display_name(name: str) -> str:
    if not name:
        return ""
    try:
        parts = email.header.decode_header(name)
        out = []
        for text, enc in parts:
            if isinstance(text, bytes):
                out.append(text.decode(enc or "utf-8", errors="replace"))
            else:
                out.append(text)
        return str(Address(display_name="".join(out)).display_name) or "".join(out)
    except Exception:
        return name

# ---------------------------------------------------------------- 日期

def parse_date(raw: str | None) -> tuple[datetime | None, str | None]:
    """返回 (UTC aware datetime 或 None, 问题描述或 None)。

    缺 Date 或裸时间都不是结构致命错误，调用方按 warning/info 记录。
    """
    if not raw:
        return None, "missing Date header"
    try:
        dt = email.utils.parsedate_to_datetime(raw)
    except (TypeError, ValueError, IndexError):
        return None, f"unparseable Date header: {raw[:120]!r}"
    if dt is None:
        return None, f"unparseable Date header: {raw[:120]!r}"
    if dt.tzinfo is None:
        # RFC 5322 要求 -0000 表示未知时区；裸时间统一按 UTC 解释并标记
        return dt.replace(tzinfo=timezone.utc), "naive date assumed UTC"
    return dt.astimezone(timezone.utc), None
