"""纯解析测试：多层 MIME、字符集、内嵌资源、附件名、损坏边界。"""
from __future__ import annotations

from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path

import pytest

from app.parser import parse_eml


def test_simple_plain():
    m = EmailMessage()
    m["From"] = "a@example.com"
    m["To"] = "b@example.com"
    m["Subject"] = "hi"
    m["Message-ID"] = "<x1@example.com>"
    m["Date"] = formatdate(1_700_000_000, usegmt=True)
    m.set_content("hello\n")
    f = parse_eml(m.as_bytes())
    assert f.parse_status == "ok"
    assert f.message_id == "x1@example.com"
    assert f.body_text.strip() == "hello"
    assert len(f.parts) == 1


def test_multicharset_sample(samples_dir: Path):
    f = parse_eml((samples_dir / "sample_multicharset.eml").read_bytes())
    assert f.parse_status == "ok"
    # 三层结构：mixed > alternative > related(+gif)，附件 pdf/xls/eml
    paths = {p.mime_path for p in f.parts}
    assert {"1", "1.1", "1.1.1", "1.1.2", "1.1.2.1", "1.1.2.2",
            "1.2", "1.3", "1.4"} <= paths
    # GB2312 正文可解码
    assert "营收增长" in f.body_text
    # RFC2047 主题与显示名
    assert "季度报告" in f.subject
    # 中文附件名（2231 与 RFC2047 B 编码两种）
    names = {p.filename_safe for p in f.attachment_parts}
    assert "季度合同.pdf" in names
    assert "数据明细.xls" in names
    # 内嵌资源
    logo = next(p for p in f.parts if p.cid_norm == "logo-1@archive.example")
    assert logo.is_inline
    assert logo.sha256 and logo.size_bytes == 43
    # HTML 脚本被转义；远程资源只登记不抓取（解析器无网络代码路径）
    assert "&lt;script&gt;" in f.body_html_escaped
    refs = set(f.html_external_refs)
    assert "https://img.example.com/tracker.png?user=42" in refs
    assert "https://css.example.com/bg.png" in refs
    # 内嵌 message/rfc822 的内部信标识被提取
    nested = next(p for p in f.parts if p.mime_path == "1.4")
    assert nested.nested_message_id == "inner-msg@example.cn"
    assert nested.payload and b"From: boss@example.cn" in nested.payload


def test_corrupt_wrong_boundary_is_failed_and_locatable(samples_dir: Path):
    f = parse_eml((samples_dir / "sample_corrupt_wrong_boundary.eml").read_bytes())
    assert f.parse_status == "failed"
    kinds = [i.kind for i in f.issues]
    assert "StartBoundaryNotFoundDefect" in kinds
    # 问题带 mime_path 可定位
    err = next(i for i in f.issues if i.kind == "StartBoundaryNotFoundDefect")
    assert err.location == "1" and err.severity == "error"


def test_corrupt_truncated_base64_keeps_issue(samples_dir: Path):
    f = parse_eml((samples_dir / "sample_corrupt_truncated_b64.eml").read_bytes())
    assert f.parse_status == "ok_with_issues"
    assert any("Base64" in i.kind and i.location == "1.2" for i in f.issues)
    # 附件部件仍然存在
    assert len(f.attachment_parts) == 1


def test_corrupt_no_boundary(samples_dir: Path):
    f = parse_eml((samples_dir / "sample_corrupt_no_boundary.eml").read_bytes())
    assert f.parse_status == "failed"
    assert any(i.kind == "NoBoundaryInMultipartDefect" and i.severity == "error"
               for i in f.issues)


def test_duplicate_and_missing_message_id(samples_dir: Path):
    dup = parse_eml((samples_dir / "thread_dup_mid.eml").read_bytes())
    assert dup.message_id_count == 2
    assert any(i.kind == "DuplicateMessageID" for i in dup.issues)
    # 保留第一个，不合并/不丢弃整信
    assert dup.message_id == "cycle-a@archive.example"

    noid = parse_eml((samples_dir / "thread_no_mid.eml").read_bytes())
    assert noid.message_id is None
    assert noid.in_reply_to == "cycle-a@archive.example"
    assert any(i.kind == "MissingMessageID" for i in noid.issues)


def test_garbage_bytes_do_not_raise():
    # 完全随机的垃圾字节也必须返回结构（可能 failed），不抛异常
    f = parse_eml(bytes(range(256)) * 4)
    assert f.eml_sha256
    assert f.parse_status in ("ok", "ok_with_issues", "failed")


def test_declared_charset_fallback():
    raw = (
        "Content-Type: text/plain; charset=iso-8859-1\r\n"
        "Content-Transfer-Encoding: base64\r\n\r\n"
    ).encode() + b"SmV1IH0="  # "Jeu }" latin-1
    f = parse_eml(raw)
    assert f.parts[0].text == "Jeu }"
