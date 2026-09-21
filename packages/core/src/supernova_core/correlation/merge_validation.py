"""合并层确定性校验与拼装（spec 2026-08-27 §6）——零推断。

- validate_vuln_refs：vuln_id 幻觉防护——不在对应 service queue 的 ID 集 → 标
  invalid_ref（透明单列，不删）。
- assemble_multi_hop_chains：边邻接启发——首边有攻击链（flows）且下游邻接边有
  calls 即拼链，basis/confidence 显式标注为 edge-adjacency / structural，不做
  函数级可达声明（留 spec §14）。
- sanitize_adjudication_cards：裁决卡 direction 与 conclusion 矛盾、或 direction
  与 finding_ref.origin 不配 → 拦下标 needs-review（不丢弃，供人工复核）。
- enforce_maintain_evidence：dismissed 的维持卡必须引用跨仓证据或
  correlation-context 调用面数据，纯本仓复读 → needs-review
  （spec 2026-09-21 §3.2 举证门槛）。
"""
from __future__ import annotations

import copy

# direction → 该方向下自洽的 conclusion 集合；不在表内的 direction 不校验
_CONSISTENT_CONCLUSIONS = {
    "upgrade": {"vulnerable"},
    "confirm": {"vulnerable"},
    "downgrade": {"downgraded", "not-vulnerable"},
    "maintain": {"not-vulnerable"},
}

# origin → 该来源下合法的 direction 集合（spec 2026-09-21 §3.4）；origin 缺失
# 或不在表内不校验（老数据/占位卡宽容）。
_CONSISTENT_DIRECTIONS = {
    "queue": {"confirm", "downgrade"},
    "dismissed": {"upgrade", "maintain"},
}


def validate_vuln_refs(edges: list[dict],
                       per_service_id_sets: dict[str, set[str]]) -> list[dict]:
    """对 merged edges 中 flows 的 vuln_refs 标注幻觉引用（返回深拷贝）。

    只有「service 在 ID 集映射里 且 vuln_id 非空 且 不在集合」才标 invalid_ref——
    agent-discovered（无 vuln_id）与未知 service（无 queue）不属幻觉引用。
    """
    out = copy.deepcopy(edges)
    for e in out:
        for f in e.get("flows", []):
            for ref in f.get("vuln_refs", []):
                vid = ref.get("vuln_id")
                id_set = per_service_id_sets.get(ref.get("service"))
                if vid and id_set is not None and vid not in id_set:
                    ref["invalid_ref"] = True
    return out


def assemble_multi_hop_chains(edges: list[dict]) -> list[dict]:
    """边邻接启发拼多跳链：攻击链到达 X（某边 flows 非空）+ X 作为 from 的
    下游边有 calls → 候选链延伸。防环（路径节点不重复）；结果有界。

    每跳附确定性上下文（2026-09-21，回答「多跳怎么走」而不只是「可能通」）：
    - 首跳（种子边）带 entry（该边首个 flow 的入口接口）+ rpc（该边 calls 的
      method 列表）+ vuln_refs（flow 引用的子仓漏洞，保序去重）；
    - 后续跳带 rpc（该边 calls 的 method 列表）。
    字段全部来自边上已有产物，零 LLM、不做函数级可达声明（留 spec §14）。
    """
    by_from: dict[str, list[dict]] = {}
    for e in edges:
        by_from.setdefault(e["from"], []).append(e)

    def _rpcs(e: dict) -> list[str]:
        return [c.get("method", "") for c in (e.get("calls") or []) if c.get("method")]

    chains: list[dict] = []

    def _hop(e: dict, seed: bool) -> dict:
        hop: dict = {"from": e["from"], "to": e["to"], "rpc": _rpcs(e)}
        if seed:
            flows = e.get("flows") or []
            if flows:
                hop["entry"] = flows[0].get("entry", "")
                refs: list[dict] = []
                seen: set[tuple] = set()
                for f in flows:
                    for r in (f.get("vuln_refs") or []):
                        key = (r.get("service"), r.get("vuln_id"))
                        if key not in seen:
                            seen.add(key)
                            refs.append(r)
                if refs:
                    hop["vuln_refs"] = refs
        return hop

    def extend(path: list[str], hops: list[dict]) -> None:
        for e in by_from.get(path[-1], []):
            if not e.get("calls"):
                continue
            if e["to"] in path:
                continue    # 防环
            new_path = path + [e["to"]]
            new_hops = hops + [_hop(e, seed=False)]
            chains.append({"path": new_path, "hops": new_hops,
                           "basis": "edge-adjacency", "confidence": "structural"})
            extend(new_path, new_hops)

    for start in edges:
        if start.get("flows"):
            extend([start["from"], start["to"]], [_hop(start, seed=True)])
    return chains


def sanitize_adjudication_cards(cards: list[dict]) -> list[dict]:
    """direction/conclusion 矛盾、direction/origin 不配 → conclusion 改
    needs-review（其余不动）。"""
    for c in cards:
        allowed = _CONSISTENT_CONCLUSIONS.get(c.get("direction"))
        if allowed and c.get("conclusion") not in allowed:
            c["conclusion"] = "needs-review"
            continue    # 已拦的卡无需再查 origin（结论已落人工池）
        allowed_dirs = _CONSISTENT_DIRECTIONS.get(
            (c.get("finding_ref") or {}).get("origin"))
        if allowed_dirs and c.get("direction") not in allowed_dirs:
            c["conclusion"] = "needs-review"
    return cards


def enforce_maintain_evidence(cards: list[dict]) -> list[dict]:
    """maintain 举证门槛（spec 2026-09-21 §3.2）：dismissed 的维持卡若证据里
    既无本服务以外的 repo、也无 correlation-context: 前缀的调用面引用
    （纯本仓复读 dismiss 理由）→ conclusion 改 needs-review。

    「correlation-context: 引用」是合法维持依据：确定性调用面（inbound_surface）
    查无调用记录本身就是跨仓视角下的有效论据。只动 conclusion=="not-vulnerable"
    的维持卡——已被前道（sanitize）拦成 needs-review 的不再碰。
    """
    for c in cards:
        if c.get("direction") != "maintain" or c.get("conclusion") != "not-vulnerable":
            continue
        service = (c.get("finding_ref") or {}).get("service")
        evidence = c.get("verification_evidence") or []
        has_cross_repo = any(
            isinstance(e, dict) and e.get("repo") and e.get("repo") != service
            for e in evidence)
        has_ctx_ref = any(
            isinstance(e, dict)
            and str(e.get("location") or "").startswith("correlation-context:")
            for e in evidence)
        if not (has_cross_repo or has_ctx_ref):
            c["conclusion"] = "needs-review"
    return cards
