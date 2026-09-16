"""生成损坏边界样例：

1. sample_corrupt_wrong_boundary.eml
   Content-Type 声明的 boundary 与正文实际分隔符不一致
   -> StartBoundaryNotFoundDefect（致命结构错误，解析必须 failed/可定位）

2. sample_corrupt_truncated_b64.eml
   有效 multipart，但附件的 base64 载荷被截断
   -> InvalidBase64...Defect + 附件仍保留原始字节

3. sample_corrupt_no_boundary.eml
   multipart 容器声明缺失 boundary 参数
   -> NoBoundaryInMultipartDefect

输出到 tests/samples/
"""
from __future__ import annotations

import base64
from pathlib import Path

OUT = Path(__file__).resolve().parent / "samples"

CORRECT_MIXED = """\
From: sender@example.com
To: rcpt@example.com
Subject: corrupted boundary demo
Message-ID: <corrupt-1@archive.example>
Date: Wed, 16 Sep 2026 08:00:00 +0000
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="GOOD-BOUNDARY"

--GOOD-BOUNDARY
Content-Type: text/plain; charset=utf-8

可见正文。
--GOOD-BOUNDARY
Content-Type: application/octet-stream; name=data.bin
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename=data.bin

{payload}
--GOOD-BOUNDARY--
"""


def build() -> dict[str, bytes]:
    out: dict[str, bytes] = {}

    # 1) 声明 BOUNDARY-A，正文用 GOOD-BOUNDARY
    wrong = CORRECT_MIXED.format(
        payload=base64.b64encode(b"hello attachment").decode())
    wrong = wrong.replace('boundary="GOOD-BOUNDARY"', 'boundary="BOUNDARY-A"')
    out["sample_corrupt_wrong_boundary.eml"] = wrong.encode()

    # 2) base64 截断（去掉尾部且故意制造非法填充）
    truncated_b64 = base64.b64encode(b"x" * 50).decode()[:-3] + "@@@"
    out["sample_corrupt_truncated_b64.eml"] = CORRECT_MIXED.format(
        payload=truncated_b64).encode()

    # 3) multipart 无 boundary
    no_boundary = """\
From: sender@example.com
To: rcpt@example.com
Subject: no boundary demo
Message-ID: <corrupt-3@archive.example>
Date: Wed, 16 Sep 2026 08:00:00 +0000
MIME-Version: 1.0
Content-Type: multipart/mixed

本应是 multipart 但没有 boundary 参数。
"""
    out["sample_corrupt_no_boundary.eml"] = no_boundary.encode()
    return out


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    for name, data in build().items():
        (OUT / name).write_bytes(data)
        print("wrote", name, len(data), "bytes")
