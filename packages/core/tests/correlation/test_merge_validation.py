"""合并层确定性校验与拼装（spec 2026-08-27 §6）——零推断，防幻觉与结构性拼装。

- validate_vuln_refs：vuln_id 不在对应 service queue 的 ID 集 → 标 invalid_ref（不删）
- assemble_multi_hop_chains：边邻接启发拼多跳链（basis/confidence 显式标注）
- sanitize_adjudication_cards：direction 与 conclusion 矛盾 → 拦下标 needs-review；
  direction 与 origin 不配（queue 批只许 confirm/downgrade 等）→ 同上
- enforce_maintain_evidence：dismissed 的维持卡无跨仓证据也无 correlation-context
  引用 → needs-review（spec 2026-09-21 §3.2 举证门槛）
"""
import copy

from supernova_core.correlation.merge_validation import (
    assemble_multi_hop_chains, enforce_maintain_evidence,
    sanitize_adjudication_cards, validate_vuln_refs,
)


def _edge(f, t, flows=None, calls=None):
    return {"from": f, "to": t, "protocol": "grpc", "status": "ok",
            "calls": calls or [], "flows": flows or []}


def _flow(**over):
    base = {"entry": "POST /x", "method": "svc/M", "call_site": {"file": "a.ts", "line": 1, "snippet": "s"},
            "vuln_refs": [], "confidence": "high", "evidence": "e"}
    base.update(over)
    return base


# ---------------------------------------------------------------------------
# validate_vuln_refs
# ---------------------------------------------------------------------------

def test_valid_vuln_id_not_flagged():
    edges = [_edge("g", "b", flows=[_flow(vuln_refs=[
        {"vuln_id": "INJ-001", "service": "b", "source": "queue"}])])]
    out = validate_vuln_refs(copy.deepcopy(edges), {"b": {"INJ-001"}})
    assert "invalid_ref" not in out[0]["flows"][0]["vuln_refs"][0]


def test_invalid_vuln_id_flagged_not_deleted():
    edges = [_edge("g", "b", flows=[_flow(vuln_refs=[
        {"vuln_id": "INJ-999", "service": "b", "source": "queue"}])])]
    out = validate_vuln_refs(edges, {"b": {"INJ-001"}})
    ref = out[0]["flows"][0]["vuln_refs"][0]
    assert ref["invalid_ref"] is True        # 透明标注
    assert ref["vuln_id"] == "INJ-999"       # 不删


def test_missing_vuln_id_not_flagged():
    """agent-discovered 的 ref 无 vuln_id——不是幻觉引用，不标。"""
    edges = [_edge("g", "b", flows=[_flow(vuln_refs=[
        {"service": "b", "source": "agent-discovered"}])])]
    out = validate_vuln_refs(edges, {"b": {"INJ-001"}})
    assert "invalid_ref" not in out[0]["flows"][0]["vuln_refs"][0]


def test_unknown_service_tolerated():
    """service 不在 ID 集映射里（如 from 仓无 queue）——容错不标。"""
    edges = [_edge("g", "b", flows=[_flow(vuln_refs=[
        {"vuln_id": "INJ-001", "service": "nope", "source": "queue"}])])]
    out = validate_vuln_refs(edges, {"b": {"INJ-001"}})
    assert "invalid_ref" not in out[0]["flows"][0]["vuln_refs"][0]


# ---------------------------------------------------------------------------
# assemble_multi_hop_chains
# ---------------------------------------------------------------------------

def test_two_hop_chain_assembled_with_basis_labels():
    edges = [
        _edge("gateway", "order", flows=[_flow()]),                 # 攻击链到达 order
        _edge("order", "payment", calls=[{"method": "pay/Charge",
                                          "call_site": {"file": "o.go", "line": 2, "snippet": "c"},
                                          "confidence": "high", "evidence": "e"}]),
    ]
    chains = assemble_multi_hop_chains(edges)
    assert len(chains) == 1
    c = chains[0]
    assert c["path"] == ["gateway", "order", "payment"]
    assert c["basis"] == "edge-adjacency"
    assert c["confidence"] == "structural"


def test_multi_hop_hops_carry_entry_rpc_vuln_refs():
    """逐跳上下文（2026-09-21）：首跳带种子边 flow 的 entry + vuln_refs（去重保序），
    每跳带该边 calls 的 rpc method 列表——回答「多跳怎么走」而非只给服务名骨架。"""
    edges = [
        _edge("gateway", "order", flows=[
            _flow(entry="POST /orders", method="order/Create", vuln_refs=[
                {"vuln_id": "INJ-001", "service": "order", "source": "queue"},
                {"vuln_id": "INJ-001", "service": "order", "source": "queue"},  # 重复 → 去重
            ]),
        ], calls=[{"method": "order/Create",
                   "call_site": {"file": "g.ts", "line": 9, "snippet": "s"},
                   "confidence": "high", "evidence": "e"}]),
        _edge("order", "payment", calls=[
            {"method": "pay/Charge", "call_site": {"file": "o.go", "line": 2, "snippet": "c"},
             "confidence": "high", "evidence": "e"},
            {"method": "pay/Refund", "call_site": {"file": "o.go", "line": 7, "snippet": "c"},
             "confidence": "low", "evidence": "e"},
        ]),
    ]
    chains = assemble_multi_hop_chains(edges)
    assert len(chains) == 1
    hops = chains[0]["hops"]
    assert [h["from"] for h in hops] == ["gateway", "order"]
    assert [h["to"] for h in hops] == ["order", "payment"]
    # 首跳：entry + rpc + vuln_refs（去重保序）
    assert hops[0]["entry"] == "POST /orders"
    assert hops[0]["rpc"] == ["order/Create"]
    assert hops[0]["vuln_refs"] == [{"vuln_id": "INJ-001", "service": "order", "source": "queue"}]
    # 后续跳：rpc = 该边 calls method 列表
    assert hops[1]["rpc"] == ["pay/Charge", "pay/Refund"]
    assert "entry" not in hops[1] and "vuln_refs" not in hops[1]


def test_no_flow_no_chain():
    """首边无 flows（无攻击链到达 to）→ 不成多跳链。"""
    edges = [
        _edge("gateway", "order"),
        _edge("order", "payment", calls=[{"method": "m", "call_site": {"file": "f", "line": 1, "snippet": "s"},
                                          "confidence": "low", "evidence": "e"}]),
    ]
    assert assemble_multi_hop_chains(edges) == []


def test_no_calls_no_chain():
    """邻接边无 calls → 无调用证据，不成链。"""
    edges = [
        _edge("gateway", "order", flows=[_flow()]),
        _edge("order", "payment", calls=[]),
    ]
    assert assemble_multi_hop_chains(edges) == []


def test_cycle_terminated():
    """环（order→payment→order）不死循环，产出有限链集。"""
    edges = [
        _edge("gateway", "order", flows=[_flow()]),
        _edge("order", "payment", calls=[{"method": "m", "call_site": {"file": "f", "line": 1, "snippet": "s"},
                                          "confidence": "high", "evidence": "e"}]),
        _edge("payment", "order", calls=[{"method": "m2", "call_site": {"file": "f", "line": 2, "snippet": "s"},
                                          "confidence": "high", "evidence": "e"}]),
    ]
    chains = assemble_multi_hop_chains(edges)
    for c in chains:
        assert len(c["path"]) == len(set(c["path"]))   # 无重复节点
    assert all(len(c["path"]) <= 3 for c in chains)     # 有界


# ---------------------------------------------------------------------------
# sanitize_adjudication_cards
# ---------------------------------------------------------------------------

def _card(direction, conclusion):
    return {"direction": direction, "conclusion": conclusion,
            "finding_ref": {"service": "b", "vuln_id": "X", "origin": "queue"},
            "cross_service_context": "", "analysis_process": [],
            "verification_evidence": [], "reasoning": "", "confidence": "low"}


def test_contradiction_intercepted_to_needs_review():
    cards = [_card("upgrade", "not-vulnerable"),   # 翻案却判非漏洞——矛盾
             _card("confirm", "not-vulnerable")]   # 确认却判非漏洞——矛盾
    out = sanitize_adjudication_cards(cards)
    assert all(c["conclusion"] == "needs-review" for c in out)


def test_consistent_cards_untouched():
    cards = [_card("confirm", "vulnerable"),
             _card("upgrade", "vulnerable"),
             _card("downgrade", "downgraded"),
             _card("downgrade", "not-vulnerable"),
             _card("maintain", "not-vulnerable")]
    # direction↔origin 合法搭配显式配齐（queue: confirm/downgrade；dismissed:
    # upgrade/maintain）——helper 默认 origin=queue 会拦 dismissed 方向
    cards[0]["finding_ref"]["origin"] = "queue"
    cards[1]["finding_ref"]["origin"] = "dismissed"
    cards[2]["finding_ref"]["origin"] = "queue"
    cards[3]["finding_ref"]["origin"] = "queue"
    cards[4]["finding_ref"]["origin"] = "dismissed"
    out = sanitize_adjudication_cards(cards)
    assert [c["conclusion"] for c in out] == [
        "vulnerable", "vulnerable", "downgraded", "not-vulnerable", "not-vulnerable"]


def test_unknown_direction_tolerated():
    out = sanitize_adjudication_cards([_card("weird", "vulnerable")])
    assert out[0]["conclusion"] == "vulnerable"


# ---------------------------------------------------------------------------
# sanitize_adjudication_cards：direction↔origin 一致性（spec 2026-09-21 §3.4）
# ---------------------------------------------------------------------------

def test_direction_origin_mismatch_intercepted():
    cards = [_card("upgrade", "vulnerable"),     # queue 批只能 confirm/downgrade
             _card("maintain", "not-vulnerable"),  # queue 批不能 maintain
             _card("confirm", "vulnerable"),      # dismissed 批不能 confirm
             _card("downgrade", "downgraded")]    # dismissed 批不能 downgrade
    cards[0]["finding_ref"]["origin"] = "queue"
    cards[1]["finding_ref"]["origin"] = "queue"
    cards[2]["finding_ref"]["origin"] = "dismissed"
    cards[3]["finding_ref"]["origin"] = "dismissed"
    out = sanitize_adjudication_cards(cards)
    assert all(c["conclusion"] == "needs-review" for c in out)


def test_direction_origin_consistent_untouched():
    cards = [_card("confirm", "vulnerable"),
             _card("downgrade", "downgraded"),
             _card("upgrade", "vulnerable"),
             _card("maintain", "not-vulnerable")]
    cards[0]["finding_ref"]["origin"] = "queue"
    cards[1]["finding_ref"]["origin"] = "queue"
    cards[2]["finding_ref"]["origin"] = "dismissed"
    cards[3]["finding_ref"]["origin"] = "dismissed"
    out = sanitize_adjudication_cards(cards)
    assert [c["conclusion"] for c in out] == [
        "vulnerable", "downgraded", "vulnerable", "not-vulnerable"]


def test_error_direction_bypasses_origin_check():
    card = _card("error", "needs-review")   # 占位卡 direction 不在校验表内
    out = sanitize_adjudication_cards([card])
    assert out[0]["conclusion"] == "needs-review"   # 原样保留


# ---------------------------------------------------------------------------
# enforce_maintain_evidence：maintain 举证门槛（spec 2026-09-21 §3.2）
# ---------------------------------------------------------------------------

def _maintain_card(evidence, origin="dismissed"):
    c = _card("maintain", "not-vulnerable")
    c["finding_ref"]["origin"] = origin
    c["finding_ref"]["service"] = "svc-a"
    c["verification_evidence"] = evidence
    return c


def test_maintain_without_cross_evidence_redirected():
    """纯本仓证据的维持卡（复读 dismiss 理由）→ needs-review。"""
    card = _maintain_card([{"repo": "svc-a", "location": "a.go:10",
                            "snippet": "...", "note": "..."}])
    out = enforce_maintain_evidence([card])
    assert out[0]["conclusion"] == "needs-review"


def test_maintain_with_cross_repo_evidence_kept():
    card = _maintain_card([
        {"repo": "svc-a", "location": "a.go:10", "snippet": "", "note": ""},
        {"repo": "svc-b", "location": "b.go:20", "snippet": "", "note": "调用方以结构化方式消费"}])
    out = enforce_maintain_evidence([card])
    assert out[0]["conclusion"] == "not-vulnerable"


def test_maintain_with_correlation_context_ref_kept():
    """引用调用面数据（确定性层查无调用记录/引用映射）是合法维持依据。"""
    card = _maintain_card([
        {"repo": "svc-a", "location": "a.go:10", "snippet": "", "note": ""},
        {"repo": "svc-a", "location": "correlation-context:inbound_surface 空",
         "snippet": "", "note": "确定性层未发现指向本方法的跨仓调用"}])
    out = enforce_maintain_evidence([card])
    assert out[0]["conclusion"] == "not-vulnerable"


def test_enforce_leaves_non_maintain_cards_alone():
    cards = [_card("confirm", "vulnerable"),
             _card("upgrade", "vulnerable"),
             _maintain_card([], origin="queue"),        # queue 无 maintain 语义
             _maintain_card([{"repo": "svc-a", "location": "a.go:1",
                              "snippet": "", "note": ""}],
                            origin="dismissed")]
    cards[0]["finding_ref"]["origin"] = "queue"
    cards[1]["finding_ref"]["origin"] = "dismissed"
    cards[2]["conclusion"] = "needs-review"   # 已被前道拦的卡不再动
    out = enforce_maintain_evidence(cards)
    assert [c["conclusion"] for c in out] == [
        "vulnerable", "vulnerable", "needs-review", "needs-review"]
