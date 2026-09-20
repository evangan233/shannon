import json
from supernova_core.correlation.schemas import (
    CallSite, Call, TopologyEdge, ServiceNode, CrossServiceTopology,
    TrustBoundary, CorrelationResult,
)


def test_topology_serialization_roundtrip():
    topo = CrossServiceTopology(
        services=[ServiceNode(name="gateway", role="entrypoint", repo="/r/gw")],
        edges=[TopologyEdge(
            from_="gateway", to="order-svc", protocol="grpc",
            calls=[Call(method="order.v1.OrderService/CreateOrder",
                        call_site=CallSite(file="src/c.ts", line=42, snippet="client.createOrder(req)"),
                        confidence="high",
                        evidence="POST /orders handler calls CreateOrder")],
            status="ok", error=None,
        )],
    )
    data = json.loads(topo.to_json())
    assert data["services"][0]["role"] == "entrypoint"
    assert data["edges"][0]["calls"][0]["method"] == "order.v1.OrderService/CreateOrder"
    # spec §7.1: JSON 字段名是 `from`(不带下划线)
    assert "from" in data["edges"][0]
    assert "from_" not in data["edges"][0]
    assert data["edges"][0]["from"] == "gateway"
    roundtrip = CrossServiceTopology.from_json(topo.to_json())
    assert roundtrip.edges[0].from_ == "gateway"


def test_boundary_serialization():
    b = TrustBoundary(service="order-svc", method="order.v1.OrderService/CreateOrder",
                      exposure="external", reachable_from=["gateway"],
                      reason="via POST /orders", confidence="high")
    data = json.loads(b.to_json())
    assert data["exposure"] == "external"


def test_boundary_from_dict_tolerates_missing_and_extra_fields():
    """2026-09-11 cross-repo-20260910-193903 attempt1 崩溃回归锚点：edge agent
    LLM 输出偶发缺 reachable_from（曾致 TrustBoundary(**b) TypeError 炸整单
    correlation，靠 temporal 重试运气兜底）。from_dict 对齐 TopologyEdge.from_json
    （final-review MINOR 7）防御语义：可选字段补默认、未知键过滤、核心字段缺 →
    None 丢弃（调用方 warning 记账）。"""
    full = {"service": "community", "method": "/debug/pprof/*",
            "exposure": "external", "reachable_from": ["web"],
            "reason": "routes.go:43-45", "confidence": "high"}
    b = TrustBoundary.from_dict(full)
    assert b is not None
    assert b.reachable_from == ["web"] and b.confidence == "high"

    # 缺 reachable_from → []（可达来源未断定，exposure/reason 仍有安全价值）
    b2 = TrustBoundary.from_dict(
        {k: v for k, v in full.items() if k != "reachable_from"})
    assert b2 is not None and b2.reachable_from == []

    # 缺 confidence/reason → low/""；未知键过滤不炸
    b3 = TrustBoundary.from_dict(
        {"service": "s", "method": "m", "exposure": "internal", "bogus": "x"})
    assert b3 is not None and b3.confidence == "low" and b3.reason == ""

    # 核心字段（service/method/exposure）缺 → None 丢弃；非 dict → None
    assert TrustBoundary.from_dict({"service": "s", "method": "m"}) is None
    assert TrustBoundary.from_dict("not-a-dict") is None


def test_edge_status_declared_missing():
    e = TopologyEdge(from_="gateway", to="ghost-svc", protocol="grpc",
                     calls=[], status="declared-missing", error=None)
    assert json.loads(e.to_json())["status"] == "declared-missing"


def test_edge_from_json_tolerates_extra_llm_fields():
    """final-review MINOR 7 回归锚点:LLM 多吐的未知键不应触发 TypeError。
    from_json 应过滤到已知键(calls 单独重建)。"""
    raw = json.dumps({
        "from": "gateway", "to": "order-svc", "protocol": "grpc",
        "status": "ok", "error": None, "calls": [],
        "extra_llm_field": "noise", "confidence_overall": "high",
    })
    e = TopologyEdge.from_json(raw)
    assert e.from_ == "gateway"
    assert e.to == "order-svc"
    assert e.calls == []


def test_flow_serialization_roundtrip():
    from supernova_core.correlation.schemas import CrossServiceFlow, CallSite
    f = CrossServiceFlow(
        edge_from="gateway", edge_to="order-svc", entry="POST /orders",
        method="order.v1.OrderService/CreateOrder",
        call_site=CallSite(file="src/grpc-client.ts", line=42, snippet="client.createOrder(req)"),
        vuln_refs=[{"service": "order-svc", "title": "SQL Injection",
                     "severity": "high", "location": "internal/dao/order.go:88"}],
        confidence="high", evidence="handler concatenates SQL from request")
    data = json.loads(f.to_json())
    assert data["edge_from"] == "gateway"
    assert data["vuln_refs"][0]["service"] == "order-svc"
    rt = CrossServiceFlow.from_json(f.to_json())
    assert rt.call_site.line == 42


def test_service_node_serializes_legacy_role_and_roles():
    from supernova_core.correlation.schemas import ServiceNode
    node = ServiceNode(name="gateway", role="entrypoint", roles=["entrypoint", "backend"], repo="/r/gw")
    data = json.loads(node_to_json(node))
    assert data["role"] == "entrypoint"
    assert data["roles"] == ["entrypoint", "backend"]


def node_to_json(node):
    import json as _json
    return _json.dumps(node.__dict__, ensure_ascii=False)


def test_flows_file_written(tmp_path):
    from supernova_core.correlation.report import write_correlation_deliverables
    from supernova_core.correlation.schemas import (
        CrossServiceTopology, ServiceNode, CrossServiceFlow, CallSite)
    topo = CrossServiceTopology(services=[ServiceNode("g", "entrypoint", "/r/g")], edges=[])
    flows = [CrossServiceFlow(edge_from="g", edge_to="o", entry="POST /x", method="m",
                               call_site=CallSite("a.ts", 1, "s"), vuln_refs=[],
                               confidence="low", evidence="e")]
    write_correlation_deliverables(tmp_path, topo, [], {}, "# r", flows=flows)
    data = json.loads((tmp_path / "cross-service-flows.json").read_text(encoding="utf-8"))
    # spec 2026-08-27 §8:flows json 对象形态 {"flows": [...], "multi_hop_chains": [...]}
    assert data["flows"][0]["method"] == "m"
    assert data["multi_hop_chains"] == []


def test_drift_warnings_file_written(tmp_path):
    """2026-09-20 接线：drift_warnings 落盘 drift-warnings.json（None 不落盘），
    web API 侧经 assemble_correlation_detail 读取（此前只进 md 的断链修复）。"""
    from supernova_core.correlation.report import write_correlation_deliverables
    from supernova_core.correlation.schemas import (
        CrossServiceTopology, ServiceNode)
    topo = CrossServiceTopology(services=[ServiceNode("g", "entrypoint", "/r/g")], edges=[])
    write_correlation_deliverables(tmp_path, topo, [], {}, "# r",
                                   drift_warnings=["svc: 复用产物,源码版本可能漂移"])
    data = json.loads((tmp_path / "drift-warnings.json").read_text(encoding="utf-8"))
    assert data == ["svc: 复用产物,源码版本可能漂移"]
    # None（显式不传/旧调用方）不落盘——保持产物面最小
    out2 = tmp_path / "b"
    write_correlation_deliverables(out2, topo, [], {}, "# r")
    assert not (out2 / "drift-warnings.json").exists()
