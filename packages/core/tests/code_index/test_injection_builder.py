import pytest
from types import SimpleNamespace

from supernova_core.code_index.vuln_chain_builders.injection_builder import (
    build_injection_findings,
)
from supernova_core.code_index.chain_verdict import ChainVerdict
from supernova_core.code_index.parameter_models import (
    DangerousSlot, SlotContext, SinkCallSite, SinkCategory,
    ParameterPropagationGraph, TaintFlow, PropagationStep,
)
from supernova_core.code_index.models import EntryPoint, ParameterSource
from supernova_core.models.queue_schemas import InjectionVulnerability


def _agent(payload: str = ""):
    """fake verdict_agent（SimpleNamespace 模拟 ClaudeRunResult，text 兜底解析）。"""
    async def agent(prompt, *, output_format=None, agent_name=None):
        return SimpleNamespace(success=True, structured_output=None,
                               text=payload, error=None)
    return agent


def _never_agent():
    """不应被调用的守卫 agent（调用即断言失败）。"""
    async def agent(prompt, *, output_format=None, agent_name=None):
        raise AssertionError("verdict agent must not be called")
    return agent


def _ep(func_block_id="app.py:handler:1", route="/search", http_method="POST"):
    return EntryPoint(
        func_block_id=func_block_id, entry_type="http_route", route=route,
        http_method=http_method, confidence=1.0, evidence="annot",
        needs_llm_review=False,
    )


def _flow(slot, steps=None):
    return TaintFlow(
        flow_id="app.py:handler:1#app.py:handler:db.execute:5:0",
        entry_point_id="app.py:handler:1", source_param="q",
        source_type=ParameterSource.QUERY_PARAM,
        sink_call_site_id="app.py:handler:db.execute:5:0",
        sink_slot=slot, propagation_steps=steps or [],
    )


def _step(tf):
    return PropagationStep(step_id="s", from_func_id="f", from_param="q",
                           to_func_id="f", to_param="x", transformation=tf,
                           code_location="app.py:3")


@pytest.mark.asyncio
async def test_build_injection_findings_vulnerable_chain():
    pgraph = ParameterPropagationGraph(
        taint_flows=[_flow("sql_value", steps=[_step("concat")])],
        language_coverage=["python"],
    )

    findings = await build_injection_findings(pgraph, verdict_agent=_agent(
            '{"verdict":"vulnerable","witness_payload":"\'","evidence_chain":'
            '"q->db.exec","mismatch_reason":"concat into value slot","confidence":"high"}'))
    assert len(findings) == 1
    f = findings[0]
    assert isinstance(f, InjectionVulnerability)
    assert f.vulnerability_type == "injection"
    assert f.verdict == "vulnerable"
    assert f.slot_type == "SQL-val"  # sql_value -> SQL-val mapping
    assert f.sink_call == "app.py:handler:db.execute:5:0"
    assert f.witness_payload == "'"
    # GitNexus-track evidence chain
    assert f.evidence_chain == "q->db.exec"
    assert f.source_track == "gitnexus"


@pytest.mark.asyncio
async def test_build_injection_flags_post_sanitize_concat():
    steps = [_step("sanitize_hint:html.escape"), _step("concat")]
    pgraph = ParameterPropagationGraph(
        taint_flows=[_flow("sql_value", steps=steps)], language_coverage=["python"],
    )

    findings = await build_injection_findings(pgraph, verdict_agent=_agent(
            '{"verdict":"vulnerable","witness_payload":"\'","evidence_chain":'
            '"q->db","mismatch_reason":"post-sanitize concat","confidence":"high"}'))
    assert len(findings) == 1
    assert "post-sanitize concat" in (findings[0].concat_occurrences or "").lower()


@pytest.mark.asyncio
async def test_build_injection_empty_pgraph_returns_empty():
    pgraph = ParameterPropagationGraph(taint_flows=[], language_coverage=["python"])


    findings = await build_injection_findings(pgraph, verdict_agent=_never_agent())
    assert findings == []


@pytest.mark.asyncio
async def test_build_injection_skips_non_injection_slots():
    # ssrf url slot should NOT be picked up by injection builder
    pgraph = ParameterPropagationGraph(
        taint_flows=[_flow("url")], language_coverage=["python"],
    )


    findings = await build_injection_findings(pgraph, verdict_agent=_never_agent())
    assert findings == []


@pytest.mark.asyncio
async def test_build_injection_findings_reports_chain_progress(monkeypatch):
    """progress_cb receives a tick per candidate + a final summary sample."""
    samples: list = []

    async def cb(s):
        samples.append(s)

    # 3 injection candidate chains
    pgraph = ParameterPropagationGraph(
        taint_flows=[
            _flow("sql_value", steps=[_step("concat")]),
            _flow("sql_value", steps=[_step("concat")]),
            _flow("sql_value", steps=[_step("concat")]),
        ],
        language_coverage=["python"],
    )

    call_count = {"n": 0}

    async def fake_judge(chain, *, verdict_agent=None, agent_name=None):
        call_count["n"] += 1
        # first chain vulnerable, others safe
        is_vuln = (call_count["n"] == 1)
        return ChainVerdict(
            verdict="vulnerable" if is_vuln else "safe",
            witness_payload="'" if is_vuln else None,
            evidence_chain="q->db",
            mismatch_reason=None,
            confidence="high",
        )

    monkeypatch.setattr(
        "supernova_core.code_index.chain_verdict.judge_chain_verdict",
        fake_judge,
    )


    findings = await build_injection_findings(
        pgraph, verdict_agent=_never_agent(), progress_cb=cb)

    assert len(findings) == 3
    # 3 candidates -> 3 non-final ticks
    non_final = [s for s in samples if not s.final]
    assert len(non_final) == 3
    assert samples[-1].final is True
    assert samples[-1].total == 3
    # one hit (first chain vulnerable) -> hit sample with INJ-GN- detail prefix
    hit_samples = [s for s in non_final if s.detail]
    assert len(hit_samples) == 1
    assert hit_samples[0].detail.startswith("INJ-GN-01")
    assert hit_samples[0].hits == 1
    # safe chains have empty detail
    safe_samples = [s for s in non_final if not s.detail]
    assert len(safe_samples) == 2


@pytest.mark.asyncio
async def test_build_injection_findings_progress_cb_none_no_raise():
    """cb=None (default) must run without raising."""
    pgraph = ParameterPropagationGraph(
        taint_flows=[_flow("sql_value", steps=[_step("concat")])],
        language_coverage=["python"],
    )

    findings = await build_injection_findings(pgraph, verdict_agent=_agent(
            '{"verdict":"vulnerable","witness_payload":"\'","evidence_chain":'
            '"q->db","mismatch_reason":null,"confidence":"high"}'))
    assert len(findings) == 1


@pytest.mark.asyncio
async def test_build_injection_accepts_sink_call_sites_param():
    """inj builder accepts sink_call_sites (forwarding contract).

    sink_expressions reaching the verdict PROMPT is covered by Task 6 (prompt
    wiring) and the Task 7 end-to-end test (asserts the expression is in the
    prompt). Here we only lock the builder signature + that forwarding does
    not break extract→judge.
    """
    sid = "app.py:handler:db.execute:5:0"
    sink = SinkCallSite(
        id=sid, caller_id="app.py:handler", callee_name="execute",
        callee_receiver="db", category=SinkCategory.SQL,
        sink_subtype="sql_raw_query", file_path="app.py", line=5, column=10,
        dangerous_slots=[DangerousSlot(
            arg_index=0, slot=SlotContext.SQL_VALUE,
            expression="'SELECT * FROM t WHERE id=' + q", is_entry_hint=True)],
        rule_id="py-sql-execute",
    )
    pgraph = ParameterPropagationGraph(
        taint_flows=[_flow("sql_value")], language_coverage=["python"],
    )

    findings = await build_injection_findings(
        pgraph, verdict_agent=_agent(
            '{"verdict":"vulnerable","witness_payload":"\'","evidence_chain":'
            '"q->db","mismatch_reason":"x","confidence":"high"}'), sink_call_sites={sid: sink})
    assert isinstance(findings, list)
    assert len(findings) == 1


@pytest.mark.asyncio
async def test_build_injection_finding_carries_title():
    """chain verdict 的 title 透传到 InjectionVulnerability.title。"""
    pgraph = ParameterPropagationGraph(
        taint_flows=[_flow("sql_value", steps=[_step("concat")])],
        language_coverage=["python"],
    )

    findings = await build_injection_findings(pgraph, verdict_agent=_agent(
            '{"verdict":"vulnerable","witness_payload":"\'","evidence_chain":'
            '"q->db.exec","mismatch_reason":"concat","confidence":"high",'
            '"title":"SQL Injection via q param"}'))
    assert findings[0].title == "SQL Injection via q param"


@pytest.mark.asyncio
async def test_build_injection_entry_points_prefixes_path_with_route():
    """O2 前半：entry_points join 命中 → path 带 "METHOD /path" 前缀（PoC 模板层
    derive_method_path 直接命中），evidence 不丢。"""
    pgraph = ParameterPropagationGraph(
        taint_flows=[_flow("sql_value", steps=[_step("concat")])],
        language_coverage=["python"],
    )

    findings = await build_injection_findings(
        pgraph, verdict_agent=_agent(
            '{"verdict":"vulnerable","witness_payload":"\'","evidence_chain":'
            '"q->db.exec","mismatch_reason":"x","confidence":"high"}'), entry_points={"app.py:handler:1": _ep()})
    assert findings[0].path == "POST /search → q->db.exec"
    assert findings[0].evidence_chain == "q->db.exec"


@pytest.mark.asyncio
async def test_build_injection_entry_points_miss_keeps_path():
    """join miss（不传 kwarg / 无路由 / 无 method）→ path 保持 evidence 原样。"""
    pgraph = ParameterPropagationGraph(
        taint_flows=[_flow("sql_value", steps=[_step("concat")])],
        language_coverage=["python"],
    )

    findings = await build_injection_findings(pgraph, verdict_agent=_agent(
            '{"verdict":"vulnerable","witness_payload":"\'","evidence_chain":'
            '"q->db.exec","mismatch_reason":null,"confidence":"high"}'))
    assert findings[0].path == "q->db.exec"
    findings = await build_injection_findings(
        pgraph, verdict_agent=_agent(
            '{"verdict":"vulnerable","witness_payload":"\'","evidence_chain":'
            '"q->db.exec","mismatch_reason":null,"confidence":"high"}'),
        entry_points={"app.py:handler:1": _ep(route=None)})
    assert findings[0].path == "q->db.exec"
    findings = await build_injection_findings(
        pgraph, verdict_agent=_agent(
            '{"verdict":"vulnerable","witness_payload":"\'","evidence_chain":'
            '"q->db.exec","mismatch_reason":null,"confidence":"high"}'),
        entry_points={"app.py:handler:1": _ep(http_method=None)})
    # RPC 接口关联 spec §3.2：route 有 + method 无 → 裸 route label（行为变更，
    # 旧行为不发 label）
    assert findings[0].path == "/search → q->db.exec"
    assert findings[0].endpoint == "/search"


@pytest.mark.asyncio
async def test_build_injection_affected_parameters_placement_note():
    """placement 分层（Agent 判定优先，source_type 确定性兜底）落 finding：
    - verdict 带 source_param_location → 注记用它（Agent 判定优先于规则）；
    - verdict 缺失 → source_type 确定性注记（query → '(query)'）；
    - 两者皆无对应位（path 等）→ 不注（不虚构位置）。"""
    def _flow_st(source_type):
        return TaintFlow(
            flow_id="app.py:handler:1#app.py:handler:db.execute:5:0",
            entry_point_id="app.py:handler:1", source_param="q",
            source_type=source_type,
            sink_call_site_id="app.py:handler:db.execute:5:0",
            sink_slot="sql_value", propagation_steps=[_step("concat")],
        )

    async def agent_with(loc):
        async def _f(prompt, *, output_format=None, agent_name=None):
            extra = f',"source_param_location":"{loc}"' if loc else ""
            return SimpleNamespace(success=True, structured_output=None, error=None,
                                   text=('{"verdict":"vulnerable","witness_payload":"\'",'
                                         '"evidence_chain":"q->db.exec","confidence":"high"' + extra + '}'))
        return _f

    # A: Agent 判定 body，flow source_type=query → Agent 优先
    pgraph = ParameterPropagationGraph(
        taint_flows=[_flow_st(ParameterSource.QUERY_PARAM)], language_coverage=["python"])
    findings = await build_injection_findings(
        pgraph, verdict_agent=await agent_with("body"))
    assert findings[0].affected_parameters == ["q (body)"]

    # B: Agent 缺失 → source_type=query 确定性注记
    pgraph = ParameterPropagationGraph(
        taint_flows=[_flow_st(ParameterSource.QUERY_PARAM)], language_coverage=["python"])
    findings = await build_injection_findings(
        pgraph, verdict_agent=await agent_with(None))
    assert findings[0].affected_parameters == ["q (query)"]

    # C: Agent 缺失 + source_type=path（无 HTTP placement 对应）→ 不注
    pgraph = ParameterPropagationGraph(
        taint_flows=[_flow_st(ParameterSource.PATH_PARAM)], language_coverage=["python"])
    findings = await build_injection_findings(
        pgraph, verdict_agent=await agent_with(None))
    assert findings[0].affected_parameters is None


# ===== spec 2026-08-27 §3：多轮 agent 透传 + 候选链护栏 =====

@pytest.mark.asyncio
async def test_build_injection_passes_agent_name_and_verdict_agent(monkeypatch):
    """builder 逐链传 verdict_agent + 唯一 agent_name（chain-verdict-{vc}-{i:02d}，
    防 metrics.agents 同名覆盖）。"""
    pgraph = ParameterPropagationGraph(
        taint_flows=[_flow("sql_value")], language_coverage=["python"],
    )
    calls = []

    class _AgentResult:
        success = True
        error = None
        text = ('{"verdict":"vulnerable","witness_payload":"\'",'
                '"evidence_chain":"q->db","confidence":"high"}')
        structured_output = None

    async def fake_agent(prompt, *, output_format=None, agent_name=None):
        calls.append(agent_name)
        return _AgentResult()

    findings = await build_injection_findings(pgraph, verdict_agent=fake_agent)
    assert len(findings) == 1
    assert calls == ["chain-verdict-injection-01"]


@pytest.mark.asyncio
async def test_build_injection_respects_verdict_budget(monkeypatch):
    """SUPERNOVA_CHAIN_VERDICT_MAX_AGENTS=1、2 条候选链 → 只跑 1 个 agent，
    第 2 条 unadjudicated 保守进 findings（不烧 token、不静默丢——「没判成 ≠
    非漏洞」，防大仓 runaway）。"""
    from supernova_core.code_index.parameter_models import TaintFlow
    flows = [TaintFlow(
        flow_id=f"app.py:handler:1#app.py:handler:db.execute:{5 + i}:0",
        entry_point_id="app.py:handler:1", source_param=f"q{i}",
        source_type=ParameterSource.QUERY_PARAM,
        sink_call_site_id=f"app.py:handler:db.execute:{5 + i}:0",
        sink_slot="sql_value", propagation_steps=[],
    ) for i in range(2)]
    pgraph = ParameterPropagationGraph(taint_flows=flows, language_coverage=["python"])

    agent_calls = []

    class _AgentResult:
        success = True
        error = None
        text = ('{"verdict":"vulnerable","witness_payload":"\'",'
                '"evidence_chain":"q->db","confidence":"high"}')
        structured_output = None

    async def fake_agent(prompt, *, output_format=None, agent_name=None):
        agent_calls.append(agent_name)
        return _AgentResult()

    monkeypatch.setenv("SUPERNOVA_CHAIN_VERDICT_MAX_AGENTS", "1")
    findings = await build_injection_findings(pgraph, verdict_agent=fake_agent)
    assert len(agent_calls) == 1  # 第 2 条不再烧 agent
    assert len(findings) == 2     # 超限链保守进 findings
    over = findings[1]
    assert over.verdict == "vulnerable"
    assert over.confidence == "unadjudicated"
    assert "budget" in (over.mismatch_reason or "").lower()
