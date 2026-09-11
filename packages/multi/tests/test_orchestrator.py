import pytest
from supernova_core.models.multi_repo_config import MultiRepoConfig, RepoSpec, Relation, CorrelationConfig
from supernova_multi.orchestrator import plan_repo_scans, RepoScanPlan


def _cfg(**overrides):
    repos = {
        "gateway": RepoSpec(path="/r/gw", role="entrypoint"),
        "order-svc": RepoSpec(path="/r/order", workspace="existing-order", role="backend"),
        "payment-svc": RepoSpec(path="/r/pay", role="backend"),
    }
    return MultiRepoConfig(
        repos=repos,
        relations=[Relation(**{"from": "gateway", "to": "order-svc"})],
        correlation=CorrelationConfig(out_workspace="out"),
        **overrides,
    )


def test_reuse_when_workspace_declared():
    plans = plan_repo_scans(_cfg())
    by_svc = {p.service: p for p in plans}
    # order-svc 声明了 workspace → 复用
    assert by_svc["order-svc"].reuse is True
    assert by_svc["order-svc"].workspace == "existing-order"
    # gateway 只给 path → 现扫
    assert by_svc["gateway"].reuse is False
    assert by_svc["gateway"].repo_path == "/r/gw"


def test_all_three_repos_planned():
    plans = plan_repo_scans(_cfg())
    assert {p.service for p in plans} == {"gateway", "order-svc", "payment-svc"}


# ---------------------------------------------------------------------------
# Task A6: per-edge asyncio + 单边隔离 + merge
# ---------------------------------------------------------------------------
import asyncio  # noqa: E402
from supernova_multi.orchestrator import _run_edge, _merge_edge_results  # noqa: E402


def _edge_result(from_, to, status="ok"):
    return {"from": from_, "to": to, "protocol": "grpc",
            "calls": [], "status": status, "boundaries": []}


@pytest.mark.asyncio
async def test_single_edge_failure_does_not_break_others():
    edges = [("gateway", "order-svc"), ("gateway", "payment-svc"), ("gateway", "broken-svc")]

    async def fake_edge(f, t):
        if t == "broken-svc":
            raise RuntimeError("boom")
        return _edge_result(f, t)

    results = await asyncio.gather(*[_run_edge(f, t, runner=fake_edge) for f, t in edges],
                                   return_exceptions=False)
    statuses = {r["status"] for r in results}
    # 失败的边标 error,其余 ok,不抛
    assert "error" in statuses
    assert "ok" in statuses
    assert len(results) == 3


def test_merge_edges_collects_all():
    merged = _merge_edge_results([_edge_result("g", "a"), _edge_result("g", "b")])
    assert len(merged["edges"]) == 2


def test_prompts_dir_is_absolute_and_points_to_real_prompts():
    """final-review IMPORTANT 1 回归锚点:prompts 路径必须绝对且指向真实 prompts 目录,
    防止非 repo-root CWD 调用时 Prompt file not found 崩溃回归。"""
    from supernova_multi.orchestrator import _prompts_dir
    d = _prompts_dir()
    assert d.is_absolute()
    assert (d / "cross-repo-correlation.txt").exists()


def test_write_correlation_deliverables_writes_all_files(tmp_path):
    """Task A6: report.py 落盘 helper 写齐四类产物。"""
    from supernova_core.correlation.report import write_correlation_deliverables
    from supernova_core.correlation.schemas import (
        CrossServiceTopology, ServiceNode, TopologyEdge, TrustBoundary,
    )
    topology = CrossServiceTopology(
        services=[ServiceNode(name="gateway", role="entrypoint", repo="/r/gw")],
        edges=[TopologyEdge(from_="gateway", to="order-svc", protocol="grpc")],
    )
    boundaries = [TrustBoundary(service="gateway", method="Checkout",
                                exposure="public", reachable_from=["*"],
                                reason="rbac", confidence="high")]
    merged_queues = {"injection": [
        {"title": "t", "description": "d", "severity": "high",
         "location": "f:1", "service": "gateway"}]}
    out = tmp_path / "deliverables"
    write_correlation_deliverables(out, topology, boundaries, merged_queues, "# report")
    assert (out / "cross-service-topology.json").exists()
    assert (out / "trust-boundaries.json").exists()
    assert (out / "correlation-report.md").read_text() == "# report"
    assert (out / "injection_exploitation_queue.json").exists()


# ---------------------------------------------------------------------------
# Task A3: run_correlation_phase 拆出(参数化 paths/event_file/provider/scan_end)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_run_correlation_phase_writes_flows_and_respects_paths(tmp_path, monkeypatch):
    """phase 参数化：repo_workspace_paths/out_ws_dir/event_file 全显式注入；
    write_scan_end=False 不写 scan_end；flows 落盘。Agent 以 stub 代（不打 LLM）。"""
    import json as _json
    from supernova_multi.orchestrator import run_correlation_phase

    # 两个子仓 workspace 目录：造 deliverables + 一个 queue
    gw_ws, be_ws = tmp_path / "gw-scan", tmp_path / "be-scan"
    for w in (gw_ws, be_ws):
        (w / "deliverables").mkdir(parents=True)
    (be_ws / "deliverables" / "injection_exploitation_queue.json").write_text(
        _json.dumps({"vulnerabilities": [
            {"title": "SQLi", "description": "d", "severity": "high",
             "location": "dao.go:8"}]}), encoding="utf-8")
    out_ws = tmp_path / "corr-scan"
    out_ws.mkdir()
    event_file = tmp_path / "corr-scan" / "events.ndjson"

    cfg = MultiRepoConfig(
        repos={"gateway": RepoSpec(path="/r/gw", role="entrypoint",
                                    roles=["entrypoint", "backend"]),
               "order-svc": RepoSpec(path="/r/be", role="backend")},
        relations=[Relation(**{"from": "gateway", "to": "order-svc"})],
        correlation=CorrelationConfig(out_workspace="corr-scan"))

    captured_role_map = None

    async def fake_execute(self, **kw):
        nonlocal captured_role_map
        captured_role_map = kw["prompt_variables"]["role_map"]

        class _M:  # 最小 metrics stub:edge_runner 只读 structured_output 属性
            structured_output = {
                "from": "gateway", "to": "order-svc", "protocol": "grpc",
                "calls": [], "status": "ok", "boundaries": [],
                "flows": [{"entry": "POST /orders",
                           "method": "order.v1.OrderService/CreateOrder",
                           "call_site": {"file": "c.ts", "line": 1, "snippet": "x"},
                           "vuln_refs": [{"service": "order-svc", "title": "SQLi",
                                           "severity": "high", "location": "dao.go:8"}],
                           "confidence": "high", "evidence": "e"}]}
        return _M()

    # patch 源头类(orchestrator 在函数内 import AgentExecutor,模块级无该属性)
    import supernova_core.agents.executor as executor_mod
    monkeypatch.setattr(executor_mod.AgentExecutor, "execute", fake_execute)

    result = await run_correlation_phase(
        cfg, {"gateway": gw_ws, "order-svc": be_ws}, out_ws, event_file,
        write_scan_end=False)

    dlv = out_ws / "deliverables"
    flows_obj = _json.loads(
        (dlv / "cross-service-flows.json").read_text(encoding="utf-8"))
    # spec 2026-08-27 §8:flows json 对象形态(含 multi_hop_chains)
    assert flows_obj["flows"][0]["method"] == "order.v1.OrderService/CreateOrder"
    assert flows_obj["multi_hop_chains"] == []
    assert _json.loads(captured_role_map)["gateway"] == ["entrypoint", "backend"]
    topology = _json.loads((dlv / "cross-service-topology.json").read_text(encoding="utf-8"))
    gateway = next(service for service in topology["services"] if service["name"] == "gateway")
    assert gateway["role"] == "entrypoint"
    assert gateway["roles"] == ["entrypoint", "backend"]
    merged = _json.loads((dlv / "injection_exploitation_queue.json").read_text(encoding="utf-8"))
    assert merged["vulnerabilities"][0]["service"] == "order-svc"
    events = [_json.loads(l) for l in event_file.read_text(encoding="utf-8").splitlines() if l]
    assert all(e["type"] != "scan_end" for e in events)   # write_scan_end=False
    assert result["edge_statuses"] == ["ok"]


@pytest.mark.asyncio
async def test_run_correlation_phase_emits_edge_agent_events(tmp_path, monkeypatch):
    """edge agent 细粒度事件（2026-09-10 live tab）：execute 的 tool_audit_logger 回调 +
    agent start/end 包裹 → AgentEvent/ToolCallEvent/LlmTurnEvent 落主行 events.ndjson，
    agent_name=edge:<f>→<t>（前端零改动渲染）。"""
    import json as _json
    from supernova_multi.orchestrator import run_correlation_phase

    gw_ws, be_ws = tmp_path / "gw-scan", tmp_path / "be-scan"
    for w in (gw_ws, be_ws):
        (w / "deliverables").mkdir(parents=True)
    (be_ws / "deliverables" / "injection_exploitation_queue.json").write_text(
        _json.dumps({"vulnerabilities": [
            {"title": "SQLi", "description": "d", "severity": "high",
             "location": "dao.go:8"}]}), encoding="utf-8")
    out_ws = tmp_path / "corr-scan"
    out_ws.mkdir()
    event_file = out_ws / "events.ndjson"

    cfg = MultiRepoConfig(
        repos={"gateway": RepoSpec(path="/r/gw", role="entrypoint"),
               "order-svc": RepoSpec(path="/r/be", role="backend")},
        relations=[Relation(**{"from": "gateway", "to": "order-svc"})],
        correlation=CorrelationConfig(out_workspace="corr-scan"))

    async def fake_execute(self, **kw):
        tl = kw.get("tool_audit_logger")
        if tl is not None:
            await tl.log_tool_start("Grep", {"q": "grpc"})
            await tl.log_assistant_turn(1, "分析调用关系")

        class _M:
            structured_output = {"from": "gateway", "to": "order-svc",
                                 "protocol": "grpc", "calls": [], "status": "ok",
                                 "boundaries": []}
            duration_ms = 42
            cost_usd = 0.1
            cost_currency = "CNY"
            input_tokens = 10
            output_tokens = 5
        return _M()

    import supernova_core.agents.executor as executor_mod
    monkeypatch.setattr(executor_mod.AgentExecutor, "execute", fake_execute)

    await run_correlation_phase(cfg, {"gateway": gw_ws, "order-svc": be_ws},
                                out_ws, event_file, write_scan_end=False)

    events = [_json.loads(l) for l in event_file.read_text(encoding="utf-8").splitlines() if l]
    agents = [e for e in events if e["type"] == "AgentEvent"]
    assert agents and agents[0]["event"] == "start"
    assert agents[0]["agent_name"] == "edge:gateway→order-svc"
    assert agents[-1]["event"] == "end" and agents[-1]["success"] is True
    assert agents[-1]["duration_ms"] == 42 and agents[-1]["cost_currency"] == "CNY"
    tools = [e for e in events if e["type"] == "ToolCallEvent"]
    assert tools and tools[0]["tool_name"] == "Grep"
    assert tools[0]["agent_name"] == "edge:gateway→order-svc"
    llm = [e for e in events if e["type"] == "LlmTurnEvent"]
    assert llm and llm[0]["turn"] == 1 and llm[0]["content"].startswith("分析调用关系")


@pytest.mark.asyncio
async def test_run_correlation_phase_write_scan_end_true(tmp_path, monkeypatch):
    """write_scan_end=True（CLI 默认）→ scan_end 事件落 ndjson。"""
    from supernova_multi.orchestrator import run_correlation_phase
    import json as _json
    cfg = MultiRepoConfig(
        repos={"gateway": RepoSpec(path="/r/gw", role="entrypoint"),
               "order-svc": RepoSpec(path="/r/be", role="backend")},
        relations=[],  # 无边：不调 Agent，纯事件路径
        correlation=CorrelationConfig(out_workspace="corr-scan"))
    out_ws = tmp_path / "corr-scan"
    out_ws.mkdir()
    event_file = out_ws / "events.ndjson"
    await run_correlation_phase(cfg, {"gateway": out_ws}, out_ws, event_file,
                                write_scan_end=True)
    events = [_json.loads(l) for l in event_file.read_text(encoding="utf-8").splitlines() if l]
    assert any(e["type"] == "scan_end" and e["status"] == "completed" for e in events)


# ---------------------------------------------------------------------------
# spec 2026-08-27: 两阶段化——阶段 A(关联,guide+ID 引用) + 合并层校验 + 阶段 B(裁决)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_run_correlation_phase_two_stage(tmp_path, monkeypatch):
    """端到端（stub Agent）：guide 注入 / vuln_id 校验 / flows 对象形态 /
    adjudication-log 落盘 / 报告裁决章节 / adjudication phase 事件。"""
    import json as _json
    from supernova_multi.orchestrator import run_correlation_phase

    gw_ws, be_ws = tmp_path / "gw-scan", tmp_path / "be-scan"
    for w in (gw_ws, be_ws):
        (w / "deliverables").mkdir(parents=True)
    (be_ws / "deliverables" / "injection_exploitation_queue.json").write_text(
        _json.dumps({"vulnerabilities": [
            {"ID": "INJ-001", "title": "SQLi", "description": "d",
             "severity": "high", "location": "dao.go:8"}]}), encoding="utf-8")
    (be_ws / "deliverables" / "dismissed_findings.json").write_text(
        _json.dumps({"dismissed": [
            {"ID": "INJ-D1", "vuln_class": "injection",
             "dismiss_reason": "internal not reachable from entrypoint"}]}),
        encoding="utf-8")
    (gw_ws / "deliverables" / "entry_points.json").write_text(
        _json.dumps({"endpoints": []}), encoding="utf-8")

    out_ws = tmp_path / "corr-scan"
    out_ws.mkdir()
    event_file = out_ws / "events.ndjson"
    cfg = MultiRepoConfig(
        repos={"gateway": RepoSpec(path="/r/gw", role="entrypoint",
                                    roles=["entrypoint", "backend"]),
               "order-svc": RepoSpec(path="/r/be", role="backend")},
        relations=[Relation(**{"from": "gateway", "to": "order-svc"})],
        correlation=CorrelationConfig(out_workspace="corr-scan"))

    async def fake_execute(self, agent_name=None, **kw):
        name = getattr(agent_name, "value", agent_name)

        class _R:
            def __init__(self, payload):
                self.structured_output = payload

        if name == "cross-repo-adjudication":
            bj = kw["prompt_variables"]["batch_json"]
            if "INJ-D1" in bj:
                return _R({"cards": [{
                    "direction": "upgrade",
                    "finding_ref": {"service": "order-svc", "vuln_id": "INJ-D1",
                                    "origin": "dismissed"},
                    "conclusion": "vulnerable",
                    "cross_service_context": "via gateway",
                    "analysis_process": ["s1"], "verification_evidence": [],
                    "reasoning": "reachable now", "confidence": "high"}]})
            return _R({"cards": [{
                "direction": "confirm",
                "finding_ref": {"service": "order-svc", "vuln_id": "INJ-001",
                                "origin": "queue"},
                "conclusion": "vulnerable",
                "cross_service_context": "via gateway",
                "analysis_process": ["s1"], "verification_evidence": [],
                "reasoning": "confirmed", "confidence": "high"}]})
        # 阶段 A：edge payload,含一个有效 ID + 一个幻觉 ID
        kw_edge = kw
        assert "artifacts_guide" in kw_edge["prompt_variables"], (
            "阶段 A prompt_vars 须注入 artifacts_guide")
        return _R({"from": "gateway", "to": "order-svc", "protocol": "grpc",
                   "calls": [], "status": "ok", "boundaries": [],
                   "flows": [{"entry": "POST /orders",
                              "method": "order.v1.OrderService/CreateOrder",
                              "call_site": {"file": "c.ts", "line": 1, "snippet": "x"},
                              "vuln_refs": [
                                  {"vuln_id": "INJ-001", "service": "order-svc",
                                   "source": "queue"},
                                  {"vuln_id": "INJ-BAD", "service": "order-svc",
                                   "source": "queue"}],
                              "confidence": "high", "evidence": "e"}]})

    import supernova_core.agents.executor as executor_mod
    monkeypatch.setattr(executor_mod.AgentExecutor, "execute", fake_execute)

    result = await run_correlation_phase(
        cfg, {"gateway": gw_ws, "order-svc": be_ws}, out_ws, event_file,
        write_scan_end=False)

    dlv = out_ws / "deliverables"
    # 1) flows 对象形态 + 幻觉 ID 标注
    flows_obj = _json.loads(
        (dlv / "cross-service-flows.json").read_text(encoding="utf-8"))
    assert set(flows_obj) == {"flows", "multi_hop_chains"}
    refs = flows_obj["flows"][0]["vuln_refs"]
    by_id = {r["vuln_id"]: r for r in refs}
    assert "invalid_ref" not in by_id["INJ-001"]
    assert by_id["INJ-BAD"]["invalid_ref"] is True
    # 2) adjudication-log：queue confirm + dismissed upgrade 都有卡
    log = _json.loads(
        (dlv / "adjudication-log.json").read_text(encoding="utf-8"))
    cards = log["cards"] if isinstance(log, dict) else log
    by_vid = {c["finding_ref"]["vuln_id"]: c for c in cards}
    assert by_vid["INJ-001"]["direction"] == "confirm"
    assert by_vid["INJ-D1"]["direction"] == "upgrade"
    # 3) 报告裁决章节（非漏洞与漏洞同表留证）
    report = (dlv / "correlation-report.md").read_text(encoding="utf-8")
    assert "跨仓裁决" in report
    assert "INJ-D1" in report          # dismissed 项（翻案候选）进报告
    # 4) adjudication phase 事件(对齐 CorrelationEventWriter schema:
    #    type=correlation_progress, node=phase, name=adjudication)
    events = [_json.loads(l) for l in
              event_file.read_text(encoding="utf-8").splitlines() if l]

    def _phase_evts(name_status: str):
        return [e for e in events
                if e.get("type") == "correlation_progress"
                and e.get("node") == "phase" and e.get("name") == "adjudication"
                and e.get("status") == name_status]
    assert _phase_evts("started")
    assert _phase_evts("completed")
    # 5) 合并 queue 不变（决策 #5：裁决不回写）
    merged = _json.loads(
        (dlv / "injection_exploitation_queue.json").read_text(encoding="utf-8"))
    assert merged["vulnerabilities"][0]["service"] == "order-svc"
    assert result["edge_statuses"] == ["ok"]


@pytest.mark.asyncio
async def test_adjudication_failure_does_not_break_phase_a(tmp_path, monkeypatch):
    """阶段 B 整体异常 → 阶段 A 产物照常交付,scan 终态不受影响。"""
    import json as _json
    from supernova_multi.orchestrator import run_correlation_phase

    be_ws = tmp_path / "be-scan"
    (be_ws / "deliverables").mkdir(parents=True)
    (be_ws / "deliverables" / "injection_exploitation_queue.json").write_text(
        _json.dumps({"vulnerabilities": [
            {"ID": "INJ-001", "title": "t", "description": "d",
             "severity": "high", "location": "f:1"}]}), encoding="utf-8")
    gw_ws = tmp_path / "gw-scan"
    (gw_ws / "deliverables").mkdir(parents=True)
    out_ws = tmp_path / "corr-scan"
    out_ws.mkdir()
    event_file = out_ws / "events.ndjson"
    cfg = MultiRepoConfig(
        repos={"gateway": RepoSpec(path="/r/gw", role="entrypoint"),
               "order-svc": RepoSpec(path="/r/be", role="backend")},
        relations=[],
        correlation=CorrelationConfig(out_workspace="corr-scan"))

    async def fake_execute(self, **kw):
        raise RuntimeError("adjudication infra down")

    import supernova_core.agents.executor as executor_mod
    monkeypatch.setattr(executor_mod.AgentExecutor, "execute", fake_execute)

    result = await run_correlation_phase(
        cfg, {"gateway": gw_ws, "order-svc": be_ws}, out_ws, event_file,
        write_scan_end=True)
    dlv = out_ws / "deliverables"
    assert (dlv / "injection_exploitation_queue.json").exists()   # A 产物在
    assert (dlv / "adjudication-log.json").exists()               # error 留档在
    log = _json.loads((dlv / "adjudication-log.json").read_text(encoding="utf-8"))
    cards = log["cards"] if isinstance(log, dict) else log
    assert cards and cards[0]["direction"] == "error"
    assert result["edge_statuses"] == []                          # 无边,不抛


@pytest.mark.asyncio
async def test_run_correlation_phase_tolerates_llm_boundary_missing_fields(
        tmp_path, monkeypatch):
    """2026-09-11 cross-repo-20260910-193903 attempt1 崩溃回归锚点：edge agent 输出的
    boundary 缺 reachable_from/confidence（LLM 偶发漏字段，实证 edge:web→community
    的 /debug/pprof/* 条目）不应 TypeError 炸整单 correlation——补默认保留条目 +
    events 记 warning；核心字段缺的条目丢弃不炸。"""
    import json as _json
    from supernova_multi.orchestrator import run_correlation_phase

    gw_ws, be_ws = tmp_path / "gw-scan", tmp_path / "be-scan"
    for w in (gw_ws, be_ws):
        (w / "deliverables").mkdir(parents=True)
    out_ws = tmp_path / "corr-scan"
    out_ws.mkdir()
    event_file = out_ws / "events.ndjson"
    cfg = MultiRepoConfig(
        repos={"gateway": RepoSpec(path="/r/gw", role="entrypoint"),
               "order-svc": RepoSpec(path="/r/be", role="backend")},
        relations=[Relation(**{"from": "gateway", "to": "order-svc"})],
        correlation=CorrelationConfig(out_workspace="corr-scan"))

    async def fake_execute(self, **kw):
        class _M:
            structured_output = {
                "from": "gateway", "to": "order-svc", "protocol": "grpc",
                "calls": [], "status": "ok",
                "boundaries": [
                    # 实证样本：缺 reachable_from + confidence
                    {"service": "community", "method": "/debug/pprof/*",
                     "exposure": "external",
                     "reason": "routes.go:43-45 DEBUG=1 挂载 pprof，无认证"},
                    # 核心字段缺（exposure）→ 丢弃
                    {"service": "ghost", "method": "m", "reason": "r"},
                ],
            }
        return _M()

    import supernova_core.agents.executor as executor_mod
    monkeypatch.setattr(executor_mod.AgentExecutor, "execute", fake_execute)

    result = await run_correlation_phase(
        cfg, {"gateway": gw_ws, "order-svc": be_ws}, out_ws, event_file,
        write_scan_end=False)

    dlv = out_ws / "deliverables"
    boundaries = _json.loads(
        (dlv / "trust-boundaries.json").read_text(encoding="utf-8"))
    assert len(boundaries) == 1                       # 核心字段缺的丢弃，其余保留
    kept = boundaries[0]
    assert kept["method"] == "/debug/pprof/*"
    assert kept["reachable_from"] == []               # 补默认（未断定）
    assert kept["confidence"] == "low"
    # 可观测性：丢弃/补默认落 events.ndjson warning，不留到构造点才炸
    events = [_json.loads(l) for l in
              event_file.read_text(encoding="utf-8").splitlines() if l]
    warn_txt = _json.dumps(events, ensure_ascii=False)
    assert "ghost" in warn_txt and "reachable_from" in warn_txt
    assert result["edge_statuses"] == ["ok"]


@pytest.mark.asyncio
async def test_edge_output_schema_constrains_boundary_items(tmp_path, monkeypatch):
    """生产端收紧（2026-09-11 双防线之一）：boundaries item 写完整 JSON Schema——
    openai 引擎 structured outputs 对嵌套 required 有强制力（LLM 漏字段在引擎侧
    即被拒），claude 引擎无害；字段契约与 cross-repo-correlation.txt 对齐。
    消费端容错见 test_run_correlation_phase_tolerates_llm_boundary_missing_fields。"""
    import json as _json
    from supernova_multi.orchestrator import run_correlation_phase

    gw_ws, be_ws = tmp_path / "gw-scan", tmp_path / "be-scan"
    for w in (gw_ws, be_ws):
        (w / "deliverables").mkdir(parents=True)
    out_ws = tmp_path / "corr-scan"
    out_ws.mkdir()
    event_file = out_ws / "events.ndjson"
    cfg = MultiRepoConfig(
        repos={"gateway": RepoSpec(path="/r/gw", role="entrypoint"),
               "order-svc": RepoSpec(path="/r/be", role="backend")},
        relations=[Relation(**{"from": "gateway", "to": "order-svc"})],
        correlation=CorrelationConfig(out_workspace="corr-scan"))

    captured: dict = {}

    async def fake_execute(self, **kw):
        captured["schema"] = kw.get("structured_output_schema")

        class _M:
            structured_output = {"from": "gateway", "to": "order-svc",
                                 "protocol": "grpc", "calls": [], "status": "ok",
                                 "boundaries": []}
        return _M()

    import supernova_core.agents.executor as executor_mod
    monkeypatch.setattr(executor_mod.AgentExecutor, "execute", fake_execute)

    await run_correlation_phase(
        cfg, {"gateway": gw_ws, "order-svc": be_ws}, out_ws, event_file,
        write_scan_end=False)

    items = captured["schema"]["properties"]["boundaries"].get("items")
    assert isinstance(items, dict), "boundaries item 必须有 schema 约束"
    assert set(items.get("required", [])) >= {
        "service", "method", "exposure", "reachable_from",
        "reason", "confidence"}
    props = items.get("properties", {})
    assert props.get("reachable_from") == {"type": "array", "items": {"type": "string"}}


@pytest.mark.asyncio
async def test_run_correlation_phase_installs_failure_redirect(tmp_path, monkeypatch):
    """2026-09-11 日志串台修复接线：corr 主行装 temporalio redirect 到本会话目录
    ——corr 的 activity failure traceback 不再落并发 wb 会话目录（NodeGoat 目录
    躺 corr 崩溃的实证）。activity 上下文外 workflow_id=None → 注册为 fallback，
    无 id record 落 corr 目录。"""
    import logging as _logging
    from supernova_multi.orchestrator import run_correlation_phase

    gw_ws, be_ws = tmp_path / "gw-scan", tmp_path / "be-scan"
    for w in (gw_ws, be_ws):
        (w / "deliverables").mkdir(parents=True)
    out_ws = tmp_path / "corr-scan"
    out_ws.mkdir()
    event_file = out_ws / "events.ndjson"
    cfg = MultiRepoConfig(
        repos={"gateway": RepoSpec(path="/r/gw", role="entrypoint"),
               "order-svc": RepoSpec(path="/r/be", role="backend")},
        relations=[],
        correlation=CorrelationConfig(out_workspace="corr-scan"))

    async def fake_execute(self, **kw):
        raise RuntimeError("not used")   # 无 edge，不执行

    import supernova_core.agents.executor as executor_mod
    monkeypatch.setattr(executor_mod.AgentExecutor, "execute", fake_execute)

    await run_correlation_phase(
        cfg, {"gateway": gw_ws, "order-svc": be_ws}, out_ws, event_file,
        write_scan_end=False)

    # corr 安装后：temporalio failure record 落 corr 会话目录（fallback 被接管）
    _logging.getLogger("temporalio.activity").warning(
        "Completing activity as failed ({'activity_type': 'run_correlation_activity'})")
    assert "run_correlation_activity" in (
        out_ws / "activity_failures.log").read_text(encoding="utf-8")
