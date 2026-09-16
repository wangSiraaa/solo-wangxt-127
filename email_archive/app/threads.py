"""会话图纯函数：环检测（Tarjan SCC）与线程遍历。

节点是规范化（小写）的 Message-ID，边为 子 -> 父（来自 References/In-Reply-To）。
重复或缺失标识不在这里合并，仅按图计算，冲突由仓储层另行保留。
"""
from __future__ import annotations

from collections import defaultdict


def find_cycles(edges: list[tuple[str, str]]) -> list[list[str]]:
    """在有向图中找非平凡强连通分量（即环成员）。

    edges: [(source, target)]，自环也算。返回按成员排序的 SCC 列表。
    """
    graph: dict[str, set[str]] = defaultdict(set)
    nodes: set[str] = set()
    for src, dst in edges:
        nodes.add(src)
        nodes.add(dst)
        graph[src].add(dst)

    index_of: dict[str, int] = {}
    lowlink: dict[str, int] = {}
    on_stack: dict[str, bool] = {}
    stack: list[str] = []
    counter = [0]
    cycles: list[list[str]] = []

    def strongconnect(v: str) -> None:
        index_of[v] = counter[0]
        lowlink[v] = counter[0]
        counter[0] += 1
        stack.append(v)
        on_stack[v] = True
        for w in graph[v]:
            if w not in index_of:
                strongconnect(w)
                lowlink[v] = min(lowlink[v], lowlink[w])
            elif on_stack.get(w):
                lowlink[v] = min(lowlink[v], index_of[w])
        if lowlink[v] == index_of[v]:
            comp: list[str] = []
            while True:
                w = stack.pop()
                on_stack[w] = False
                comp.append(w)
                if w == v:
                    break
            if len(comp) > 1 or (len(comp) == 1 and comp[0] in graph[comp[0]]):
                cycles.append(sorted(comp))

    for n in sorted(nodes):
        if n not in index_of:
            strongconnect(n)
    return cycles


def ancestors(edges: list[tuple[str, str]], start: str) -> list[str]:
    """沿 子->父 边向上收集（不含起点；去重、保序、环安全）。"""
    out: list[str] = []
    seen: set[str] = {start}
    stack_nodes = [start]
    adj: dict[str, list[str]] = defaultdict(list)
    for s, t in edges:
        adj[s].append(t)
    while stack_nodes:
        cur = stack_nodes.pop()
        for nxt in adj.get(cur, []):
            if nxt in seen:
                continue
            seen.add(nxt)
            out.append(nxt)
            stack_nodes.append(nxt)
    return out


def descendants(edges: list[tuple[str, str]], start: str) -> list[str]:
    """沿 父->子 反向向下收集（不含起点；环安全）。"""
    reverse: dict[str, list[str]] = defaultdict(list)
    for s, t in edges:
        reverse[t].append(s)
    out: list[str] = []
    seen = {start}
    stack_nodes = [start]
    while stack_nodes:
        cur = stack_nodes.pop()
        for nxt in reverse.get(cur, []):
            if nxt in seen:
                continue
            seen.add(nxt)
            out.append(nxt)
            stack_nodes.append(nxt)
    return out
