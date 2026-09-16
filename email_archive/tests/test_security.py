"""安全测试：路径越界、文件名净化、HTML 转义与远程资源识别。"""
from __future__ import annotations

import pytest

from app.security import (
    classify_html_refs,
    escape_html,
    safe_resolve,
    sanitize_filename,
    storage_relpath,
)


def test_storage_relpath_shape():
    rel = storage_relpath("a" * 64, "b" * 64)
    parts = rel.split("/")
    assert len(parts) == 3 and parts[0] == "aa" and parts[1] == "aa"
    assert len(parts[2]) == 64


def test_safe_resolve_blocks_traversal(tmp_path):
    with pytest.raises(ValueError):
        safe_resolve(tmp_path, "../../etc/passwd")
    with pytest.raises(ValueError):
        safe_resolve(tmp_path, "aa/bb/" + "c" * 63)  # 长度不对
    with pytest.raises(ValueError):
        safe_resolve(tmp_path, "../" + "a" * 2 + "/" + "b" * 2 + "/" + "0" * 64)


def test_safe_resolve_accepts_valid(tmp_path):
    rel = storage_relpath("a" * 64, "c" * 64)
    # 文件不存在时 resolve 仍返回路径（父目录未建），这里只验证不抛越界
    p = safe_resolve(tmp_path, rel)
    assert str(p).startswith(str(tmp_path))


@pytest.mark.parametrize("raw,expected", [
    ("../../etc/passwd", "passwd"),
    ("/etc/shadow", "shadow"),
    ("C:\\Windows\\win.ini", "win.ini"),
    ("normal.xlsx", "normal.xlsx"),
    ("a/b/c.pdf", "c.pdf"),
    ("..", None),
    ("", None),
    ("nul", None),
    ("con.txt", "con.txt"),   # 带扩展名不是设备名
    ("report%20Q3.pdf", "report Q3.pdf"),
])
def test_sanitize_filename(raw, expected):
    assert sanitize_filename(raw) == expected


def test_escape_html_neutralizes_script():
    src = "<script>alert(1)</script><img src=x onerror=alert(2)>"
    out = escape_html(src)
    assert "<script>" not in out
    assert "&lt;script&gt;" in out
    assert "onerror=alert(2)" in out  # 属性文本存在但标签已失效


def test_classify_refs_separates_cid_and_external():
    html = (
        '<img src="cid:logo@x">'
        '<img src="https://t.example/a.png">'
        '<img src="//proto.example/b.png">'
        '<a href="ftp://f.example/f.txt">f</a>'
        "<style>body{background:url('https://css.example/c.css')}</style>"
        '<a href="#section">s</a>'
    )
    cids, ext = classify_html_refs(html)
    assert cids == ["logo@x"]
    assert "https://t.example/a.png" in ext
    assert "https://proto.example/b.png" in ext
    assert "ftp://f.example/f.txt" in ext
    assert "https://css.example/c.css" in ext
    assert not any("#section" in e for e in ext)
