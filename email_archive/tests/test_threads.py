"""会话图与信头规范化的纯函数测试。"""
from __future__ import annotations

from app import threads
from app.normalizers import (
    message_id_key,
    normalize_message_id,
    parse_date,
    parse_id_list,
)


def test_normalize_message_id():
    assert normalize_message_id("<abc@example.com>") == "abc@example.com"
    assert normalize_message_id("  <x@y>  ") == "x@y"
    assert normalize_message_id("bare-id") == "bare-id"
    assert normalize_message_id("") is None
    assert normalize_message_id(None) is None


def test_message_id_key_casefold():
    assert message_id_key("<A@EXAMPLE.COM>") == "a@example.com"


def test_parse_id_list_order_dedup():
    ids = parse_id_list(["<a@x> <b@x>", "<b@x> <c@x>"])
    assert ids == ["a@x", "b@x", "c@x"]


def test_parse_date_naive_assumed_utc():
    dt, issue = parse_date("Tue, 16 Sep 2026 10:00:00 +0200")
    assert dt is not None and dt.utcoffset().total_seconds() == 0
    assert issue is None
    dt2, issue2 = parse_date("Tue, 16 Sep 2026 10:00:00")
    assert issue2 == "naive date assumed UTC"
    assert dt2.hour == 10
    dt3, issue3 = parse_date("not a date")
    assert dt3 is None and issue3.startswith("unparseable")


def test_find_cycles():
    # a->b->c->a 环 + d->a 悬挂在环上
    edges = [("a", "b"), ("b", "c"), ("c", "a"), ("d", "a")]
    cycles = threads.find_cycles(edges)
    assert cycles == [["a", "b", "c"]]
    # 自环
    assert threads.find_cycles([("x", "x")]) == [["x"]]
    # 无环
    assert threads.find_cycles([("a", "b"), ("b", "c")]) == []


def test_ancestors_descendants_safe_on_cycle():
    edges = [("a", "b"), ("b", "c"), ("c", "a")]
    anc = set(threads.ancestors(edges, "a"))
    assert anc == {"b", "c"}
    desc = set(threads.descendants(edges, "a"))
    assert desc == {"b", "c"}
