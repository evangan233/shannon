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

    captured_ctx: dict = {}

    async def fake_execute(self, agent_name=None, **kw):
        name = getattr(agent_name, "value", agent_name)

        class _R:
            def __init__(self, payload):
                self.structured_output = payload

        if name == "cross-repo-adjudication":
            captured_ctx.update(
                _json.loads(kw["prompt_variables"]["correlation_context"]))
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
                   "calls": [{"method": "order.v1.OrderService/CreateOrder",
                              "call_site": {"file": "c.ts", "line": 18,
                                            "snippet": "x"},
                              "confidence": "high", "evidence": "client stub"}],
                   "status": "ok",
                   "boundaries": [{"service": "order-svc",
                                   "method": "order.v1.OrderService/CreateOrder",
                                   "exposure": "external",
                                   "reachable_from": ["gateway POST /orders"],
                                   "reason": "r", "confidence": "high"}],
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
    # 2b) correlation_context 下发 inbound_surface（spec 2026-09-21 §3.1：
    #     dismissed 批翻案原料——谁调用 + 哪个入口可达 + entry_points 指路）
    surface = captured_ctx["inbound_surface"]["order-svc"]
    assert surface["inbound_calls"] == [{
        "from_service": "gateway",
        "rpc_method": "order.v1.OrderService/CreateOrder",
        "call_site": "c.ts:18"}]
    assert surface["reachable_entries"] == [{
        "rpc_method": "order.v1.OrderService/CreateOrder",
        "exposure": "external", "via": ["gateway POST /orders"]}]
    # 3) 报告结论章节（成立漏洞 + 翻案候选；全量裁决卡撤出报告改由 json 留档）
    report = (dlv / "correlation-report.md").read_text(encoding="utf-8")
    assert "全量裁决留档" in report
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


# ---------------------------------------------------------------------------
# 2026-09-20 报告充实：结论统计 + 成立漏洞全文 + 消掉/存疑清单（裁决后重渲染）
# ---------------------------------------------------------------------------
def _report_topology():
    from supernova_core.correlation.schemas import (
        CrossServiceTopology, ServiceNode, TopologyEdge)
    return CrossServiceTopology(
        services=[ServiceNode(name="gateway", role="entrypoint", repo="/r/gw")],
        edges=[TopologyEdge(from_="gateway", to="order-svc", protocol="grpc")])


def test_render_report_first_version_has_adjudication_pending_note():
    """阶段 A 首版（无 cards）：报告尾部标注裁决进行中，无结论章节。"""
    from supernova_multi.orchestrator import _render_report
    md = _render_report(_report_topology(), [], {}, [])
    assert "裁决阶段进行中" in md
    assert "结论统计" not in md


def test_render_report_full_verdict_sections():
    """裁决后：结论统计一行（per-vuln 口径）+ 成立漏洞全文（接口/问题点/POC/修复）
    + 翻案卡全文 + 消掉/存疑清单 + 单仓否决复核行 + 既有裁决五组列表。"""
    from supernova_multi.orchestrator import _render_report
    merged = {"injection": [{
        "ID": "INJ-01", "service": "order-svc", "title": "SQL 注入", "severity": "critical",
        "impact": "拖库", "remediation": "参数化查询",
        "location": "db.py:10",
        "report_endpoints": [{"method": "POST", "path": "/orders", "params": ["q"],
                              "auth": "public", "route_registered_at": "api.py:12"}],
        "report_problem_points": [{"location": "db.py:10", "description": "拼接 SQL",
                                   "snippet": "query(sql)"}],
        "report_poc": {"curl": "curl -X POST /orders", "steps": ["1. 注入"],
                       "preconditions": "可公网达", "expected_response": "行数异常"},
    }], "xss": [{
        "ID": "XSS-01", "service": "order-svc", "title": "反射 XSS", "severity": "high",
    }]}
    cards = [
        {"direction": "confirm",
         "finding_ref": {"service": "order-svc", "vuln_id": "INJ-01", "origin": "queue"},
         "conclusion": "vulnerable", "cross_service_context": "via gateway",
         "exploit_path": {
             "entry_service": "gateway", "entry_endpoint": "POST /orders",
             "hops": [{"from": "gateway", "to": "order-svc",
                       "rpc": "order.v1.OrderService/CreateOrder", "call_site": "g.ts:9"}],
             "sink": "db.py:10", "user_controlled": "q 参数全程透传",
             "poc": {"preconditions": "可公网达入口",
                     "steps": ["1. 构造注入参数"],
                     "curl": "curl -X POST 'http://ENTRY/orders' -d '{\"q\":\"1 OR 1=1\"}'",
                     "notes": "响应行数异常即命中"}},
         "refined_finding": {
             "impact": "外部用户经入口接口可拖库（跨仓可达后危害升级）",
             "cause": "sink 信任上游透传的客户端可控 q 参数",
             "severity": "high"},
         "analysis_process": [], "verification_evidence": [], "reasoning": "可达", "confidence": "high"},
        {"direction": "downgrade",
         "finding_ref": {"service": "order-svc", "vuln_id": "XSS-01", "origin": "queue"},
         "conclusion": "not-vulnerable", "cross_service_context": "",
         "analysis_process": [], "verification_evidence": [], "reasoning": "出口转义", "confidence": "high"},
        {"direction": "upgrade",
         "finding_ref": {"service": "order-svc", "vuln_id": "INJ-09", "origin": "dismissed"},
         "conclusion": "vulnerable", "cross_service_context": "经 gateway 可达",
         "analysis_process": ["① 读 dismissed"], "verification_evidence": [],
         "reasoning": "翻案", "confidence": "high"},
    ]
    md = _render_report(_report_topology(), [], merged, ["svc: drifted"], cards=cards)
    # per-vuln 口径：成立 1 / 消掉 1（XSS-01 在合并漏洞里才计数——卡有而漏洞无不计）
    assert "## 结论统计" in md and "成立 1" in md and "消掉 1" in md and "未重审 0" in md
    # 单仓否决复核行（1 条 dismissed 卡 = 翻案 1）
    assert "单仓已否决复核：维持 0 · 翻案 1" in md
    # 成立全文：confirm 关联 queue 条目渲染全文
    assert "## 成立的漏洞（跨仓确认 + 翻案）" in md
    assert "[INJ-01] order-svc — SQL 注入（critical，跨仓定级建议: high）" in md
    # 跨仓触发路径（source→sink 流程：入口接口 → 逐跳 RPC → 触达点 + 可控性）
    assert "- 跨仓触发路径:" in md
    assert "- 入口: gateway `POST /orders`" in md
    assert "- RPC: gateway → order-svc · order.v1.OrderService/CreateOrder（g.ts:9）" in md
    assert "- 触达点: db.py:10" in md
    assert "- 用户可控性: q 参数全程透传" in md
    # 跨仓 PoC（从入口接口触发）优先渲染
    assert "- 跨仓 PoC（从入口接口触发）:" in md
    assert "curl -X POST 'http://ENTRY/orders'" in md
    assert "- 说明: 响应行数异常即命中" in md
    # 单仓接口/PoC 降级标注（内部面不可达，防复核者拿错 PoC）
    assert "- 单仓接口（后端内部面，非公网入口）: POST /orders" in md
    assert "- 单仓 PoC（直连后端内部接口；跨仓场景请用上方跨仓 PoC）:" in md
    assert "curl -X POST /orders" in md
    assert "参数化查询" in md
    # 跨仓修订（按需）：标题定级建议 + 成因补充 + 危害修订版优先（单仓原文保留）
    assert "（critical，跨仓定级建议: high）" in md
    assert "- 成因补充（跨仓）: sink 信任上游透传的客户端可控 q 参数" in md
    assert "- 危害: 外部用户经入口接口可拖库（跨仓可达后危害升级）" in md
    assert "（跨仓修订；单仓原表述: 拖库）" in md
    # 翻案：裁决卡全文（无 queue 条目）
    assert "### 翻案候选（单仓已否决 → 跨仓可达，待人工复核）" in md
    assert "① 读 dismissed" in md
    # 消掉清单一行一条
    assert "## 消掉/存疑清单" in md
    assert "[XSS-01] order-svc（消掉, confidence: high）— 出口转义" in md
    # 全量裁决章节已撤（2026-09-21 精简）：确认卡融入成立全文、消掉论证在清单、
    # 维持是纯噪音——留档指引并入统计节尾 + 漂移保留
    assert "## 跨仓裁决(阶段 B)" not in md
    assert "> 全量裁决留档：3 张卡见 adjudication-log.json。" in md
    assert "svc: drifted" in md
    assert "## 版本漂移警告" in md
    # 有 exploit_path 时跨仓上下文散文行不再重复
    assert "- 跨仓上下文: via gateway" not in md
    # 目录优化（2026-09-21）：速览表当章首目录 + 章节序结论区在前背景区垫底
    assert "| ID | 服务 | 严重度 | 定级建议 | 标题 |" in md
    assert "| INJ-01 | order-svc | critical | high | SQL 注入 |" in md
    assert "| INJ-09 | order-svc | — | — | 翻案：" in md
    assert md.index("## 结论统计") < md.index("## 成立的漏洞") \
        < md.index("## 消掉/存疑清单") < md.index("## 服务拓扑")


def test_render_report_error_cards_kept_and_prose_context_fallback():
    """error 占位卡单列留档（故障信号）；旧卡无 exploit_path 时跨仓上下文散文行保留。"""
    from supernova_multi.orchestrator import _render_report
    merged = {"xss": [{"ID": "X-1", "service": "s", "title": "t"}]}
    cards = [
        {"direction": "confirm",
         "finding_ref": {"service": "s", "vuln_id": "X-1", "origin": "queue"},
         "conclusion": "vulnerable", "cross_service_context": "经 gateway 的 /x 可达",
         "analysis_process": [], "verification_evidence": [], "reasoning": "可达",
         "confidence": "high"},
        {"direction": "error",
         "finding_ref": {"service": "s", "vuln_id": "X-9", "origin": "queue"},
         "conclusion": "needs-review", "cross_service_context": "",
         "analysis_process": [], "verification_evidence": [],
         "reasoning": "adjudication batch failed: llm down", "confidence": "low"},
    ]
    md = _render_report(_report_topology(), [], merged, [], cards=cards)
    assert "## 裁决失败(占位留档)" in md
    assert "adjudication batch failed: llm down" in md
    # 旧卡（无 exploit_path）：跨仓上下文散文行兜底保留
    assert "- 跨仓上下文: 经 gateway 的 /x 可达" in md


def test_render_report_trust_boundaries_appendix():
    """信任边界附录（2026-09-21 页面撤章后信息落位 md）：service/method/exposure/
    可达来源/reason 一行一条；空边界省略章节。"""
    from supernova_core.correlation.schemas import TrustBoundary
    from supernova_multi.orchestrator import _render_report
    md = _render_report(_report_topology(), [], {}, [])
    assert "## 信任边界" not in md
    tb = TrustBoundary(service="order-svc", method="order.CreateOrder",
                       exposure="internal", reachable_from=["gateway"],
                       reason="仅集群内 grpc 可达，未挂网关", confidence="high")
    md = _render_report(_report_topology(), [tb], {}, [])
    assert "## 信任边界" in md
    assert "- order-svc · order.CreateOrder（high）— internal，可达来源: gateway" \
           " · 仅集群内 grpc 可达，未挂网关" in md


def test_render_report_caliber_matches_page():
    """口径对齐结果页（2026-09-20）：confirm 卡含 needs-review → 存疑不进成立；
    dismissed 维持卡不进消掉清单（只在复核行计数）；卡有而合并漏洞无 → 不计。"""
    from supernova_multi.orchestrator import _render_report
    merged = {"xss": [{"ID": "X-1", "service": "s", "title": "t1"},
                      {"ID": "X-2", "service": "s", "title": "t2"}]}
    cards = [
        # confirm 卡但 conclusion=needs-review → 存疑（旧口径会误计成立）
        {"direction": "confirm",
         "finding_ref": {"service": "s", "vuln_id": "X-1", "origin": "queue"},
         "conclusion": "needs-review", "cross_service_context": "",
         "analysis_process": [], "verification_evidence": [],
         "reasoning": "信息不足", "confidence": "low"},
        # dismissed 维持卡：不进消掉清单
        {"direction": "maintain",
         "finding_ref": {"service": "s", "vuln_id": "DIS-1", "origin": "dismissed"},
         "conclusion": "not-vulnerable", "cross_service_context": "",
         "analysis_process": [], "verification_evidence": [],
         "reasoning": "维持否决", "confidence": "high"},
        # 卡有而合并漏洞无：不参与计数
        {"direction": "downgrade",
         "finding_ref": {"service": "s", "vuln_id": "GHOST-1", "origin": "queue"},
         "conclusion": "downgraded", "cross_service_context": "",
         "analysis_process": [], "verification_evidence": [],
         "reasoning": "幽灵卡", "confidence": "high"},
    ]
    md = _render_report(_report_topology(), [], merged, [], cards=cards)
    assert "成立 0 ｜ 翻案 0 ｜ 消掉 0 ｜ 存疑 1 ｜ 未重审 1（合并漏洞共 2 条）" in md
    assert "单仓已否决复核：1 条全部维持原判，无翻案。" in md
    # X-1 以存疑进清单；维持卡与幽灵卡全篇不出现（全量裁决章节已撤）
    assert "[X-1] s（存疑, confidence: low）— 信息不足" in md
    assert "维持否决" not in md
    assert "幽灵卡" not in md
    assert "[X-2] s（存疑" not in md  # 未重审不进清单


def test_render_report_unadjudicated_counted():
    """queue 条目无卡 → 未重审计数（error 卡占位算已出位但仍计存疑）。"""
    from supernova_multi.orchestrator import _render_report
    merged = {"xss": [{"ID": "X-1", "service": "s"}, {"ID": "X-2", "service": "s"}]}
    cards = [{"direction": "error",
              "finding_ref": {"service": "s", "vuln_id": "X-1", "origin": "queue"},
              "conclusion": "needs-review", "cross_service_context": "",
              "analysis_process": [], "verification_evidence": [],
              "reasoning": "batch failed", "confidence": "low"}]
    md = _render_report(_report_topology(), [], merged, [], cards=cards)
    assert "存疑 1 ｜ 未重审 1（合并漏洞共 2 条）" in md


# ---------------------------------------------------------------------------
# inbound_surface + 防护类否决分桶（spec 2026-09-21 §3.1/§3.3）
# ---------------------------------------------------------------------------

def test_build_inbound_surface_groups_by_target_service():
    """纯数据搬运零推断：边 calls → inbound_calls；边界 → reachable_entries；
    entry_points 指路；空方法/空边界容忍。"""
    from types import SimpleNamespace
    from supernova_multi.orchestrator import _build_inbound_surface
    edges = [{"from": "gw", "to": "order-svc",
              "calls": [{"method": "order.v1.Svc/Create",
                         "call_site": {"file": "c.ts", "line": 18},
                         "confidence": "high"},
                        {"method": "", "call_site": {}}]},
             {"from": "gw", "to": "be2", "calls": []}]
    boundaries = [SimpleNamespace(service="order-svc",
                                  method="order.v1.Svc/Create",
                                  exposure="external",
                                  reachable_from=["gw POST /orders"]),
                  SimpleNamespace(service="order-svc", method="",
                                  exposure="internal", reachable_from=[])]
    arts = {"order-svc": SimpleNamespace(entry_points="/r/be/entry_points.json"),
            "gw": SimpleNamespace(entry_points=None)}
    surface = _build_inbound_surface(edges, boundaries, arts)
    assert surface["order-svc"]["inbound_calls"] == [
        {"from_service": "gw", "rpc_method": "order.v1.Svc/Create",
         "call_site": "c.ts:18"}]
    assert surface["order-svc"]["reachable_entries"] == [
        {"rpc_method": "order.v1.Svc/Create", "exposure": "external",
         "via": ["gw POST /orders"]}]
    assert surface["order-svc"]["entry_points_ref"] == "/r/be/entry_points.json"
    assert "be2" not in surface          # 无 calls 无边界不建 slot
    assert "gw" not in surface           # entry_points=None 不建 slot


def test_render_report_skipped_dismissed_note():
    """防护类否决留痕节：报告一句话说明 + 明细指向 json。"""
    from supernova_multi.orchestrator import _render_report
    md = _render_report(_report_topology(), [], {}, [],
                        cards=[],
                        skipped_dismissed=[{"ID": "D1", "service": "s"}])
    assert "防护类否决(未进跨仓审查)" in md
    assert "共 1 条" in md and "skipped_dismissed" in md


def test_render_report_cards_empty_with_skip_is_not_pending():
    """cards=[] + skipped 非空 ≠ 裁决进行中（None 才是进行中）。"""
    from supernova_multi.orchestrator import _render_report
    md = _render_report(_report_topology(), [], {}, [],
                        cards=[], skipped_dismissed=[{"ID": "D1"}])
    assert "裁决阶段进行中" not in md


@pytest.mark.asyncio
async def test_defensive_dismissed_skipped_with_audit_trail(tmp_path, monkeypatch):
    """防护类否决不进批（默认开），留痕落 adjudication-log.json + 报告；
    env 关掉后恢复全量进批（spec 2026-09-21 §3.3）。"""
    import json as _json
    from supernova_multi.orchestrator import run_correlation_phase

    gw_ws, be_ws = tmp_path / "gw-scan", tmp_path / "be-scan"
    for w in (gw_ws, be_ws):
        (w / "deliverables").mkdir(parents=True)
    (be_ws / "deliverables" / "injection_exploitation_queue.json").write_text(
        _json.dumps({"vulnerabilities": [
            {"ID": "INJ-001", "title": "SQLi", "severity": "high"}]}),
        encoding="utf-8")
    (be_ws / "deliverables" / "dismissed_findings.json").write_text(
        _json.dumps({"dismissed": [
            {"ID": "INJ-D1", "vuln_class": "injection",
             "dismiss_reason": "SQL 参数化查询，无拼接"},
            {"ID": "INJ-D2", "vuln_class": "injection",
             "dismiss_reason": "internal not reachable from entrypoint"}]}),
        encoding="utf-8")
    out_ws = tmp_path / "corr-scan"
    out_ws.mkdir()
    event_file = out_ws / "events.ndjson"
    cfg = MultiRepoConfig(
        repos={"gateway": RepoSpec(path="/r/gw", role="entrypoint",
                                   roles=["entrypoint", "backend"]),
               "order-svc": RepoSpec(path="/r/be", role="backend")},
        relations=[Relation(**{"from": "gateway", "to": "order-svc"})],
        correlation=CorrelationConfig(out_workspace="corr-scan"))

    seen_batch_ids: list[str] = []

    async def fake_execute(self, agent_name=None, **kw):
        name = getattr(agent_name, "value", agent_name)

        class _R:
            def __init__(self, payload):
                self.structured_output = payload

        if name == "cross-repo-adjudication":
            bj = kw["prompt_variables"]["batch_json"]
            seen_batch_ids.extend(
                f["ID"] for f in _json.loads(bj))
            return _R({"cards": []})   # 空卡 → 漏判补位 error 卡，不影响断言
        return _R({"from": "gateway", "to": "order-svc", "protocol": "grpc",
                   "calls": [], "status": "ok", "boundaries": [], "flows": []})

    import supernova_core.agents.executor as executor_mod
    monkeypatch.setattr(executor_mod.AgentExecutor, "execute", fake_execute)

    await run_correlation_phase(
        cfg, {"gateway": gw_ws, "order-svc": be_ws}, out_ws, event_file,
        write_scan_end=False)
    dlv = out_ws / "deliverables"
    log = _json.loads(
        (dlv / "adjudication-log.json").read_text(encoding="utf-8"))
    # 防护类跳过留痕；可达性类照常进批；queue 批不受影响
    assert [s["ID"] for s in log["skipped_dismissed"]] == ["INJ-D1"]
    assert log["skipped_dismissed"][0]["matched_defense_hint"]
    assert "INJ-D2" in seen_batch_ids and "INJ-D1" not in seen_batch_ids
    assert "INJ-001" in seen_batch_ids
    report = (dlv / "correlation-report.md").read_text(encoding="utf-8")
    assert "防护类否决(未进跨仓审查)" in report

    # env 关 → 全量进批，无留痕键
    out_ws2 = tmp_path / "corr-scan-2"
    out_ws2.mkdir()
    monkeypatch.setenv("SUPERNOVA_ADJUDICATION_SKIP_DEFENSIVE", "0")
    await run_correlation_phase(
        cfg, {"gateway": gw_ws, "order-svc": be_ws}, out_ws2, event_file,
        write_scan_end=False)
    log2 = _json.loads((out_ws2 / "deliverables" / "adjudication-log.json")
                       .read_text(encoding="utf-8"))
    assert "INJ-D1" in seen_batch_ids
    assert log2["skipped_dismissed"] == []


def test_render_report_dismissed_uncertain_counted_separately():
    """maintain 举证门槛拦下的 needs-review 卡不计"维持"，单列存疑
    （spec 2026-09-21 §3.2 报告口径）。"""
    from supernova_multi.orchestrator import _render_report

    def _d(direction, conclusion):
        return {"direction": direction, "conclusion": conclusion,
                "finding_ref": {"service": "s", "vuln_id": f"D-{direction}",
                                "origin": "dismissed"},
                "cross_service_context": "", "analysis_process": [],
                "verification_evidence": [], "reasoning": "", "confidence": "low"}

    cards = [_d("maintain", "not-vulnerable"),      # 合格维持
             _d("maintain", "needs-review"),       # 门槛拦截
             _d("error", "needs-review")]          # 批失败占位
    md = _render_report(_report_topology(), [], {}, [], cards=cards)
    assert "单仓已否决复核：维持 1 · 存疑 2（举证不足/裁决失败，待人工）" in md
