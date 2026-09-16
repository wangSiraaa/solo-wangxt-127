"""生成三封互相引用形成有向环的邮件，以及缺失/重复 Message-ID 的样例。

环结构（每封的 References 指向下一封）：
  cycle-a -> cycle-b -> cycle-c -> cycle-a
另外：
  cycle-dup.eml  : 同一封内出现两个 Message-ID 信头（重复标识）
  cycle-noid.eml : 无 Message-ID，主题相同，只能作为弱候选

输出: tests/samples/thread_cycle_a.eml, thread_cycle_b.eml, thread_cycle_c.eml,
      thread_dup_mid.eml, thread_no_mid.eml
"""
from __future__ import annotations

from email.message import EmailMessage
from email.utils import formatdate
from pathlib import Path

OUT = Path(__file__).resolve().parent / "samples"

IDS = {
    "a": "<cycle-a@archive.example>",
    "b": "<cycle-b@archive.example>",
    "c": "<cycle-c@archive.example>",
}

# a 引用 b；b 引用 c；c 引用 a  => 环
EDGES = {"a": ["b"], "b": ["c"], "c": ["a"]}
SUBJECT = "采购审批流程 #8821"


def _msg(key: str) -> EmailMessage:
    m = EmailMessage()
    m["From"] = "user-a@example.cn"
    m["To"] = "archive@example.cn"
    m["Subject"] = ("Re: " if key != "a" else "") + SUBJECT
    m["Date"] = formatdate(1_789_000_000 + ord(key), usegmt=True)
    m["Message-ID"] = IDS[key]
    targets = " ".join(IDS[t] for t in EDGES[key])
    m["References"] = targets
    m["In-Reply-To"] = targets
    m.set_content(f"第 {key} 封，引用了 {EDGES[key]}。\n")
    return m


def build() -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for key in ("a", "b", "c"):
        out[f"thread_cycle_{key}.eml"] = _msg(key).as_bytes()

    # 重复 Message-ID：手工拼接双信头
    dup = _msg("a")
    raw = dup.as_bytes()
    raw = raw.replace(b"Message-ID: <cycle-a@archive.example>",
                      b"Message-ID: <cycle-a@archive.example>\r\n"
                      b"Message-ID: <cycle-a-DUPLICATE@archive.example>", 1)
    out["thread_dup_mid.eml"] = raw

    # 缺失 Message-ID，主题相同（弱候选）
    noid = EmailMessage()
    noid["From"] = "user-b@example.cn"
    noid["To"] = "archive@example.cn"
    noid["Subject"] = "Re: " + SUBJECT
    noid["Date"] = formatdate(1_789_000_100, usegmt=True)
    noid["In-Reply-To"] = IDS["a"]
    noid.set_content("没有 Message-ID 的回复。\n")
    out["thread_no_mid.eml"] = noid.as_bytes()
    return out


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    for name, data in build().items():
        (OUT / name).write_bytes(data)
        print("wrote", name, len(data), "bytes")
