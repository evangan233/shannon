import pytest

from supernova_core.code_index.chain_verdict import (
    CHAIN_VERDICT_SCHEMA,
    CandidateChain,
    _parse_verdict_json,
    extract_candidate_chains,
    http_route_label,
    judge_chain_verdict,
    ChainVerdict,
)
from supernova_core.code_index.parameter_models import (
    DangerousSlot,
    SlotContext,
    ParameterPropagationGraph,
    SinkCallSite,
    SinkCategory,
    TaintFlow,
    PropagationStep,
)
from supernova_core.code_index.models import EntryPoint, ParameterSource


class _AgentResult:
    """ClaudeRunResult-like：judge 只消费 success/structured_output/text/error。"""

    def __init__(self, *, success=True, structured_output=None, text="", error=None):
        self.success = success
        self.structured_output = structured_output
        self.text = text
        self.error = error


def _agent_returning(payload: str = "", *, calls=None, prompts=None):
    """fake verdict_agent：text=payload（text 兜底解析路径）。可选记次数/捕 prompt。"""
    async def agent(prompt, *, output_format=None, agent_name=None):
        if calls is not None:
            calls["n"] += 1
        if prompts is not None:
            prompts.append(prompt)
        return _AgentResult(text=payload)
    return agent


def _flow(sink_slot, source="q", source_type=ParameterSource.QUERY_PARAM, steps=None,
          sink_id="app.py:handler:db.execute:1:0"):
    return TaintFlow(
        flow_id="ep#sink1", entry_point_id="app.py:handler:1",
        source_param=source, source_type=source_type,
        sink_call_site_id=sink_id,
        sink_slot=sink_slot,
        propagation_steps=steps or [],
    )


def _step(tf, code_location="app.py:5"):
    return PropagationStep(
        step_id="s1", from_func_id="f", from_param="q",
        to_func_id="f", to_param="x", transformation=tf, code_location=code_location,
    )


def _xss_sink(sink_id, sink_subtype="xss_innerhtml"):
    return SinkCallSite(
        id=sink_id, caller_id="app.py:handler", callee_name="innerHTML",
        callee_receiver="el", category=SinkCategory.XSS, sink_subtype=sink_subtype,
        file_path="app.py", line=5, column=10, dangerous_slots=[], rule_id="xss-rule",
    )


def test_extract_injection_routes_sql_and_command_sinks():
    pgraph = ParameterPropagationGraph(
        taint_flows=[_flow("sql_value"), _flow("cmd_argument")],
        language_coverage=["python"],
    )
    chains = extract_candidate_chains(pgraph, vuln_class="injection")
    assert len(chains) == 2
    assert all(c.vuln_class == "injection" for c in chains)
    assert all(c.direction_hint == "backward" for c in chains)


def test_extract_xss_routes_only_xss_sinks():
    """No sink_call_sites provided → xss cannot resolve render context → no chains."""
    pgraph = ParameterPropagationGraph(
        taint_flows=[_flow("sql_value"), _flow("generic")],
        language_coverage=["python"],
    )
    chains = extract_candidate_chains(pgraph, vuln_class="xss")
    # sink_slot "generic"/"sql_value" carry no render context → no chain
    assert chains == []


def test_extract_xss_routes_by_sink_call_site_category():
    """xss routes via SinkCallSite.category == XSS (SlotContext has no render context)."""
    sid = "app.py:handler:innerHTML:5:0"
    pgraph = ParameterPropagationGraph(
        taint_flows=[_flow("generic", sink_id=sid), _flow("sql_value")],
        language_coverage=["typescript"],
    )
    chains = extract_candidate_chains(
        pgraph, vuln_class="xss",
        sink_call_sites={sid: _xss_sink(sid, sink_subtype="xss_innerhtml")},
    )
    assert len(chains) == 1
    c = chains[0]
    assert c.vuln_class == "xss"
    assert c.direction_hint == "backward"
    assert c.render_context == "html_body"  # innerHTML → HTML body context


def test_extract_ssrf_routes_only_url_sinks():
    pgraph = ParameterPropagationGraph(
        taint_flows=[_flow("url"), _flow("sql_value")],
        language_coverage=["python"],
    )
    chains = extract_candidate_chains(pgraph, vuln_class="ssrf")
    assert len(chains) == 1
    assert chains[0].vuln_class == "ssrf"
    assert chains[0].direction_hint == "backward"


def test_extract_empty_pgraph_returns_empty():
    pgraph = ParameterPropagationGraph(taint_flows=[], language_coverage=["python"])
    assert extract_candidate_chains(pgraph, vuln_class="injection") == []


def test_post_sanitize_concat_detected_when_concat_after_sanitizer():
    steps = [_step("sanitize_hint:html.escape"), _step("concat")]
    pgraph2 = ParameterPropagationGraph(
        taint_flows=[_flow("sql_value", steps=steps)],
        language_coverage=["python"],
    )
    chains = extract_candidate_chains(pgraph2, vuln_class="injection")
    assert len(chains) == 1
    assert chains[0].post_sanitize_concat is True


def test_post_sanitize_concat_false_when_no_concat_after():
    steps = [_step("sanitize_hint:html.escape"), _step("format")]
    pgraph = ParameterPropagationGraph(
        taint_flows=[_flow("sql_value", steps=steps)], language_coverage=["python"],
    )
    chains = extract_candidate_chains(pgraph, vuln_class="injection")
    assert len(chains) == 1
    assert chains[0].post_sanitize_concat is False


def test_post_sanitize_concat_detected_from_summary_step_marker():
    """summary step 的 transformation 含 |post_concat 标记 → post_sanitize_concat=True.

    覆盖 Task 2/3 产的 summary step 形态(sanitize_hint:<desc>|post_concat)。
    """
    steps = [_step("sanitize_hint:html.escape|post_concat")]
    pgraph = ParameterPropagationGraph(
        taint_flows=[_flow("sql_value", steps=steps)],
        language_coverage=["python"],
    )
    chains = extract_candidate_chains(pgraph, vuln_class="injection")
    assert len(chains) == 1
    assert chains[0].post_sanitize_concat is True


@pytest.mark.asyncio
async def test_judge_chain_verdict_agent_text_parses_verdict():
    """verdict agent 返回 verdict JSON（text 兜底）-> ChainVerdict parsed."""
    chain = CandidateChain(
        vuln_class="injection", flow_id="f1", entry_point_id="ep",
        source_param="q", source_type="query", sink_call_site_id="db.execute:1",
        sink_slot="sql_value", propagation_steps=[_step("concat")],
        sanitizer_annotations=[], direction_hint="forward",
        post_sanitize_concat=True,
    )

    async def fake_agent(prompt, *, output_format=None, agent_name=None):
        # agent final message is a compact verdict JSON
        return _AgentResult(text=(
            '{"verdict":"vulnerable","witness_payload":"\'","evidence_chain":'
            '"q -> db.execute(L1)","mismatch_reason":"concat into sql value slot",'
            '"confidence":"high"}'))

    verdict = await judge_chain_verdict(chain, verdict_agent=fake_agent)
    assert isinstance(verdict, ChainVerdict)
    assert verdict.verdict == "vulnerable"
    assert verdict.witness_payload == "'"
    assert "db.execute" in verdict.evidence_chain
    assert verdict.confidence == "high"


@pytest.mark.asyncio
async def test_judge_chain_verdict_defaults_conservative_on_agent_failure():
    """verdict agent raises/fails → conservative: treat as needs_review, do not crash."""
    chain = CandidateChain(
        vuln_class="ssrf", flow_id="f1", entry_point_id="ep",
        source_param="url", source_type="query", sink_call_site_id="fetch:1",
        sink_slot="url", propagation_steps=[], sanitizer_annotations=[],
        direction_hint="backward", post_sanitize_concat=False,
    )

    async def failing_agent(prompt, *, output_format=None, agent_name=None):
        raise RuntimeError("verdict agent not available")

    verdict = await judge_chain_verdict(chain, verdict_agent=failing_agent)
    # graceful: never crash; verdict stays conservative-vulnerable (OR-friendly)
    # spec 2026-08-26 §5.7：判定通道失败 → confidence="unadjudicated"（不再用 low
    # 冒充已判定——low 是「LLM 判了且结论低置信」，通道失败是另一语义）
    assert verdict.confidence == "unadjudicated"
    assert verdict.verdict == "vulnerable"
    assert "needs_review" in (verdict.mismatch_reason or "") or verdict.verdict in ("safe", "vulnerable")


@pytest.mark.asyncio
async def test_judge_no_agent_channel_unadjudicated():
    """判定通道未配置（verdict_agent=None，SUPERNOVA_GITNEXUS_LLM_ENABLED=0）
    → 直接保守 unadjudicated，不 crash、不落任何单次判定形态。"""
    verdict = await judge_chain_verdict(_chain())
    assert verdict.confidence == "unadjudicated"
    assert verdict.verdict == "vulnerable"
    assert verdict.witness_payload is None


def _slot_sink(sink_id, slot=SlotContext.SQL_VALUE, expr="req.query.q"):
    return SinkCallSite(
        id=sink_id, caller_id="app.py:handler", callee_name="execute",
        callee_receiver="db", category=SinkCategory.SQL, sink_subtype="sql_raw_query",
        file_path="app.py", line=5, column=10,
        dangerous_slots=[DangerousSlot(arg_index=0, slot=slot, expression=expr, is_entry_hint=True)],
        rule_id="py-sql-execute",
    )


def test_extract_fills_sink_expressions_from_dangerous_slots():
    """injection 路径:sink_call_sites 的 dangerous_slots.expression → CandidateChain.sink_expressions。"""
    sid = "app.py:handler:db.execute:5:0"
    pgraph = ParameterPropagationGraph(
        taint_flows=[_flow("sql_value", sink_id=sid)],
        language_coverage=["python"],
    )
    chains = extract_candidate_chains(
        pgraph, vuln_class="injection",
        sink_call_sites={sid: _slot_sink(sid, SlotContext.SQL_VALUE, "q + suffix")},
    )
    assert len(chains) == 1
    assert chains[0].sink_expressions == ["q + suffix"]


def test_extract_sink_expressions_empty_when_no_sink_call_sites():
    """inj/ssrf 未传 sink_call_sites → sink_expressions 默认空(向后兼容,不报错)。"""
    pgraph = ParameterPropagationGraph(
        taint_flows=[_flow("sql_value")],
        language_coverage=["python"],
    )
    chains = extract_candidate_chains(pgraph, vuln_class="injection")   # 不传 sink_call_sites
    assert len(chains) == 1
    assert chains[0].sink_expressions == []


@pytest.mark.asyncio
async def test_judge_chain_verdict_prompt_includes_sink_expressions_and_intermediate_vars():
    """prompt 含 sink_expressions + steps_repr 含 intermediate_vars(判定信息密度)。"""
    chain = CandidateChain(
        vuln_class="injection", flow_id="f1", entry_point_id="ep",
        source_param="q", source_type="query", sink_call_site_id="db.execute:1",
        sink_slot="sql_value",
        propagation_steps=[PropagationStep(
            step_id="s1", from_func_id="f", from_param="q", to_func_id="f", to_param="sink",
            transformation="sanitize_hint:html.escape", code_location="app.py:5",
            intermediate_vars=["raw", "esc"],
        )],
        sanitizer_annotations=[], direction_hint="backward",
        post_sanitize_concat=False,
        sink_expressions=["'sel ' + q"],
    )
    captured = {}

    async def fake_agent(prompt, *, output_format=None, agent_name=None):
        captured["prompt"] = prompt
        return _AgentResult(text='{"verdict":"safe","witness_payload":null,"evidence_chain":"q->db","mismatch_reason":null,"confidence":"high"}')

    await judge_chain_verdict(chain, verdict_agent=fake_agent)
    assert "'sel ' + q" in captured["prompt"]            # sink_expressions 进 prompt
    assert "raw" in captured["prompt"] and "esc" in captured["prompt"]   # intermediate_vars 进 steps_repr


# --- title 字段（spec 2026-08-06）：chain verdict 产描述性标题 ---

def test_chain_verdict_schema_includes_title():
    """CHAIN_VERDICT_SCHEMA 含 title（string|null）—— LLM 输出契约。"""
    assert "title" in CHAIN_VERDICT_SCHEMA["properties"]
    assert "null" in CHAIN_VERDICT_SCHEMA["properties"]["title"]["type"]


def test_chain_verdict_dataclass_has_title_field():
    """ChainVerdict dataclass 含 title，缺省 None。"""
    cv = ChainVerdict(
        verdict="vulnerable", witness_payload="'", evidence_chain="q->db",
        mismatch_reason="concat", confidence="high",
    )
    assert cv.title is None


@pytest.mark.asyncio
async def test_judge_chain_verdict_parses_title_from_llm():
    """LLM 输出 JSON 含 title → ChainVerdict.title 解析出来。"""
    chain = CandidateChain(
        vuln_class="injection", flow_id="f1", entry_point_id="ep",
        source_param="q", source_type="query", sink_call_site_id="db.execute:1",
        sink_slot="sql_value", propagation_steps=[_step("concat")],
        sanitizer_annotations=[], direction_hint="backward",
        post_sanitize_concat=True,
    )

    async def fake_agent(prompt, *, output_format=None, agent_name=None):
        return _AgentResult(text=(
            '{"verdict":"vulnerable","witness_payload":"\'","evidence_chain":'
            '"q -> db.execute(L1)","mismatch_reason":"concat into sql value slot",'
            '"confidence":"high","title":"SQL Injection via search q param"}'))

    verdict = await judge_chain_verdict(chain, verdict_agent=fake_agent)
    assert verdict.title == "SQL Injection via search q param"


@pytest.mark.asyncio
async def test_judge_chain_verdict_title_none_when_agent_omits():
    """agent 不返 title（旧/兜底分支）→ ChainVerdict.title=None，不崩。"""
    chain = CandidateChain(
        vuln_class="ssrf", flow_id="f1", entry_point_id="ep",
        source_param="url", source_type="query", sink_call_site_id="fetch:1",
        sink_slot="url", propagation_steps=[], sanitizer_annotations=[],
        direction_hint="backward", post_sanitize_concat=False,
    )

    async def fake_agent(prompt, *, output_format=None, agent_name=None):
        return _AgentResult(text=(
            '{"verdict":"safe","witness_payload":null,"evidence_chain":"url->fetch",'
            '"mismatch_reason":null,"confidence":"high"}'))

    verdict = await judge_chain_verdict(chain, verdict_agent=fake_agent)
    assert verdict.title is None


# --------------------------------------------------------------------------- #
# O2 后半：unparseable 有界重试 + 保守分支语义（此前 0 覆盖）。
# --------------------------------------------------------------------------- #

# 无任何 JSON 结构的纯 Markdown 叙述（fenced JSON 可被 L0 容错恢复，不算
# unparseable；真正打穿 L0 的是无 {} 的叙述/截断输出——spec R5 的失败形态）。
_GLM_MARKDOWN = (
    "## 判定结论\n\n该链路存在 SQL 注入风险：参数 q 未经参数化直接拼接进入"
    "SQL 值槽位，现有转义不覆盖该槽位。建议使用参数化查询修复。"
)
_VERDICT_JSON = (
    '{"verdict":"vulnerable","witness_payload":"\' OR \'1\'=\'1",'
    '"evidence_chain":"q -> db.execute(L1)","mismatch_reason":"concat",'
    '"confidence":"high","title":"SQL 注入"}'
)


def _chain():
    return CandidateChain(
        vuln_class="injection", flow_id="f1", entry_point_id="ep",
        source_param="q", source_type="query", sink_call_site_id="db.execute:1",
        sink_slot="sql_value", propagation_steps=[_step("concat")],
        sanitizer_annotations=[], direction_hint="forward",
        post_sanitize_concat=True,
    )


@pytest.mark.asyncio
async def test_judge_recovers_from_markdown_via_agent_rerun():
    """agent 首跑 text=GLM Markdown → 重跑 agent（原 prompt + JSON-only 提示）
    恢复合法 JSON。单次判定路径（轻量转格式）已拆除——重试与首跑同形态。"""
    prompts: list[str] = []

    async def fake_agent(prompt, *, output_format=None, agent_name=None):
        prompts.append(prompt)
        return _AgentResult(
            text=_GLM_MARKDOWN if len(prompts) == 1 else _VERDICT_JSON)

    verdict = await judge_chain_verdict(_chain(), verdict_agent=fake_agent)
    assert verdict.verdict == "vulnerable"
    assert verdict.witness_payload == "' OR '1'='1"
    assert len(prompts) == 2                       # 1 次原跑 + 1 次重跑 agent
    assert prompts[1].startswith(prompts[0])       # 全量重发（同链 prompt）
    assert "NOT valid JSON" in prompts[1]          # 加强 JSON-only 指令
    assert "待转换文本" not in prompts[1]          # 不再有轻量转格式形态


@pytest.mark.asyncio
async def test_judge_unparseable_after_retries_is_conservative():
    """全部尝试仍 Markdown → 保守分支：不丢报、witness=None、置信度 low。"""
    calls = {"n": 0}

    async def fake_agent(prompt, *, output_format=None, agent_name=None):
        calls["n"] += 1
        return _AgentResult(text=_GLM_MARKDOWN)

    verdict = await judge_chain_verdict(_chain(), verdict_agent=fake_agent)
    assert calls["n"] == 3                          # 1 原始 + 2 重试（默认）
    assert verdict.verdict == "vulnerable"          # OR 友好，不静默清除
    assert verdict.witness_payload is None
    # spec 2026-08-26 §5.7：unparseable 降级同属判定通道失败 → unadjudicated
    assert verdict.confidence == "unadjudicated"
    assert "unparseable output after all attempts" in verdict.mismatch_reason


@pytest.mark.asyncio
async def test_judge_empty_output_after_retries_distinguishes_reason():
    """空输出与非法输出分流：mismatch_reason 报 empty 而非 unparseable。"""
    async def fake_agent(prompt, *, output_format=None, agent_name=None):
        return _AgentResult(text="")

    verdict = await judge_chain_verdict(_chain(), verdict_agent=fake_agent)
    assert verdict.verdict == "vulnerable"
    assert verdict.confidence == "unadjudicated"
    assert "empty output" in verdict.mismatch_reason


# --------------------------------------------------------------------------- #
# spec 2026-08-26-report-generation-agent-design §5.7：chain_verdict 失败显式化。
# 「LLM 判了且结论 low confidence」≠「判定通道根本没成功」——后者 unadjudicated，
# 前者仍是 LLM 的真实判定，confidence 原样透传。
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_judge_llm_low_confidence_verdict_is_not_unadjudicated():
    """agent 成功判定且自评 low → confidence 透传 "low"（不被改写 unadjudicated）。"""
    async def fake_agent(prompt, *, output_format=None, agent_name=None):
        return _AgentResult(text=(
            '{"verdict":"vulnerable","witness_payload":"\'","evidence_chain":'
            '"q -> db.execute(L1)","mismatch_reason":"weak signal",'
            '"confidence":"low","title":"SQLi"}'))

    verdict = await judge_chain_verdict(_chain(), verdict_agent=fake_agent)
    assert verdict.confidence == "low"
    assert verdict.verdict == "vulnerable"


@pytest.mark.asyncio
async def test_judge_agent_failure_unadjudicated_keeps_conservative_fields():
    """通道失败分支：verdict 保守 vulnerable + witness=None + 兜底 title（不丢报）。"""
    async def failing_agent(prompt, *, output_format=None, agent_name=None):
        raise RuntimeError("provider down")

    verdict = await judge_chain_verdict(_chain(), verdict_agent=failing_agent)
    assert verdict.confidence == "unadjudicated"
    assert verdict.verdict == "vulnerable"
    assert verdict.witness_payload is None
    assert verdict.title is not None          # 确定性兜底标题仍在
    assert "llm-pass-failed" in verdict.evidence_chain


@pytest.mark.asyncio
async def test_judge_no_retry_when_env_zero(monkeypatch):
    """SUPERNOVA_CHAIN_VERDICT_RETRIES=0 → 只打 1 次，直接保守降级。"""
    monkeypatch.setenv("SUPERNOVA_CHAIN_VERDICT_RETRIES", "0")
    calls = {"n": 0}

    async def fake_agent(prompt, *, output_format=None, agent_name=None):
        calls["n"] += 1
        return _AgentResult(text=_GLM_MARKDOWN)

    verdict = await judge_chain_verdict(_chain(), verdict_agent=fake_agent)
    assert calls["n"] == 1
    assert verdict.verdict == "vulnerable"
    assert verdict.witness_payload is None


@pytest.mark.asyncio
async def test_judge_retry_call_exception_falls_conservative():
    """重试调用本身 raise → 放弃重试，保守降级（不 crash）。"""
    calls = {"n": 0}

    async def fake_agent(prompt, *, output_format=None, agent_name=None):
        calls["n"] += 1
        if calls["n"] == 1:
            return _AgentResult(text=_GLM_MARKDOWN)
        raise RuntimeError("provider down")

    verdict = await judge_chain_verdict(_chain(), verdict_agent=fake_agent)
    assert calls["n"] == 2
    assert verdict.verdict == "vulnerable"
    assert verdict.witness_payload is None


@pytest.mark.asyncio
async def test_judge_single_call_when_parseable():
    """合法 JSON 一次到位 → 不触发任何重试。"""
    calls = {"n": 0}

    async def fake_agent(prompt, *, output_format=None, agent_name=None):
        calls["n"] += 1
        return _AgentResult(text=_VERDICT_JSON)

    verdict = await judge_chain_verdict(_chain(), verdict_agent=fake_agent)
    assert calls["n"] == 1
    assert verdict.verdict == "vulnerable"


@pytest.mark.asyncio
async def test_judge_prompt_asks_for_concrete_witness():
    """prompt 含具体 witness 指令（MINIMAL concrete attack input）。"""
    prompts: list[str] = []

    async def fake_agent(prompt, *, output_format=None, agent_name=None):
        prompts.append(prompt)
        return _AgentResult(text=_VERDICT_JSON)

    await judge_chain_verdict(_chain(), verdict_agent=fake_agent)
    assert "MINIMAL concrete attack input" in prompts[0]


def test_schema_requires_witness_payload():
    """witness_payload 入 required（可 null）——prompt-only 约束下防模型省略。"""
    assert "witness_payload" in CHAIN_VERDICT_SCHEMA["required"]


def test_parse_verdict_json_recovers_fenced_json():
    assert _parse_verdict_json('```json\n{"verdict":"safe"}\n```') == {"verdict": "safe"}


def test_parse_verdict_json_rejects_invalid_values():
    assert _parse_verdict_json('{"verdict":"maybe"}') is None      # 非法枚举
    assert _parse_verdict_json('["not","object"]') is None         # 非 object
    assert _parse_verdict_json("") is None                         # 空输出
    assert _parse_verdict_json(None) is None
    assert _parse_verdict_json("no braces at all") is None


# --------------------------------------------------------------------------- #
# O2 前半：http_route_label（builder 路由 join 的共享 helper）。
# --------------------------------------------------------------------------- #

def _route_ep(func_block_id="app.py:h:1", route="/search", http_method="POST",
              entry_type="http_route"):
    return EntryPoint(
        func_block_id=func_block_id, entry_type=entry_type, route=route,
        http_method=http_method, confidence=1.0, evidence="annot",
        needs_llm_review=False,
    )


def test_http_route_label_hit():
    assert http_route_label("app.py:h:1", {"app.py:h:1": _route_ep()}) == "POST /search"


def test_http_route_label_normalizes_route_and_method():
    ep = _route_ep(route="search", http_method="post")
    assert http_route_label("app.py:h:1", {"app.py:h:1": ep}) == "POST /search"


def test_http_route_label_miss_variants():
    assert http_route_label("app.py:h:1", {}) is None                       # 空 map
    assert http_route_label("app.py:h:1", None) is None                     # 不传
    assert http_route_label(None, {"a": _route_ep()}) is None               # 无 id
    assert http_route_label(
        "app.py:h:1", {"app.py:h:1": _route_ep(route=None)}) is None        # 无路由
    assert http_route_label(
        "app.py:x:9", {"app.py:h:1": _route_ep()}) is None                  # join miss


def test_http_route_label_rpc_bare_route():
    """RPC 接口关联 spec §3.2：route 有 + http_method 无（join 后的
    grpc_service entry）→ 返回裸 route（无 METHOD 前缀）。RPC label 不参与
    PoC method 推导，旧「缺 method 不发」的保守理由不适用。"""
    ep = _route_ep(entry_type="grpc_service",
                   route="/SetupOrder/SetupOrderCreate", http_method=None)
    assert http_route_label(
        "app.py:h:1", {"app.py:h:1": ep}) == "/SetupOrder/SetupOrderCreate"


def test_http_route_label_route_without_method_bare():
    """route 有 + method 无（不限 entry_type）→ 裸 route（行为变更点）。"""
    ep = _route_ep(http_method=None)
    assert http_route_label("app.py:h:1", {"app.py:h:1": ep}) == "/search"


# ===== spec 2026-08-21 修复点 D 配套: xss_server_render render_context =====

def test_render_context_for_server_template_render():
    """xss_server_render(ts-res-render)→server_template:服务端模板 locals 渲染,
    verdict LLM 需知道判定面是模板 autoescape 而非 DOM innerHTML。"""
    from supernova_core.code_index.chain_verdict import _render_context_for
    assert _render_context_for("xss_server_render") == "server_template"


def test_render_context_for_dom_subtypes_unchanged():
    """既有 DOM 子型映射不回归(xss_dom→html_body 默认)。"""
    from supernova_core.code_index.chain_verdict import _render_context_for
    assert _render_context_for("xss_dom") == "html_body"


@pytest.mark.asyncio
async def test_judge_verdict_parses_source_param_location():
    """判定输出带 source_param_location（PoC 参数位的 Agent 判定）→ 透传。"""
    chain = CandidateChain(
        vuln_class="injection", flow_id="f1", entry_point_id="ep",
        source_param="preTax", source_type="body", sink_call_site_id="db.eval:1",
        sink_slot="cmd_argument", propagation_steps=[_step("concat")],
        sanitizer_annotations=[], direction_hint="forward",
        post_sanitize_concat=True,
    )

    async def fake_agent(prompt, *, output_format=None, agent_name=None):
        return _AgentResult(text=(
            '{"verdict":"vulnerable","witness_payload":"1;id","evidence_chain":'
            '"preTax -> eval","mismatch_reason":"eval on body param",'
            '"confidence":"high","source_param_location":"body"}'))

    verdict = await judge_chain_verdict(chain, verdict_agent=fake_agent)
    assert verdict.source_param_location == "body"


@pytest.mark.asyncio
async def test_judge_verdict_normalizes_bad_source_param_location():
    """位置值归一：大小写折叠；非法值（header/空）→ None（不虚构位置，
    留给确定性 source_type 兜底与 method 启发式）。"""
    chain = CandidateChain(
        vuln_class="ssrf", flow_id="f1", entry_point_id="ep",
        source_param="url", source_type="query", sink_call_site_id="http.get:1",
        sink_slot="url", propagation_steps=[_step("concat")],
        sanitizer_annotations=[], direction_hint="forward",
        post_sanitize_concat=True,
    )

    async def agent_returns(loc):
        async def _f(prompt, *, output_format=None, agent_name=None):
            return _AgentResult(text=(
                '{"verdict":"vulnerable","witness_payload":"http://x/",'
                '"evidence_chain":"url -> get","confidence":"medium",'
                f'"source_param_location":"{loc}"' + '}'))
        return _f

    v = await judge_chain_verdict(chain, verdict_agent=await agent_returns("QUERY"))
    assert v.source_param_location == "query"      # 大小写折叠
    v = await judge_chain_verdict(chain, verdict_agent=await agent_returns("header"))
    assert v.source_param_location is None          # 非法 → None
    v = await judge_chain_verdict(chain, verdict_agent=await agent_returns(""))
    assert v.source_param_location is None


@pytest.mark.asyncio
async def test_judge_verdict_fallback_location_none():
    """判定通道失败（llm-pass-failed）→ source_param_location=None（Agent 判定
    不可用，位置由 builder 的 source_type 确定性注记兜底）。"""
    chain = CandidateChain(
        vuln_class="xss", flow_id="f1", entry_point_id="ep",
        source_param="memo", source_type="body", sink_call_site_id="render:1",
        sink_slot="template_expr", propagation_steps=[_step("concat")],
        sanitizer_annotations=[], direction_hint="forward",
        post_sanitize_concat=True,
    )

    async def boom(prompt, *, output_format=None, agent_name=None):
        raise RuntimeError("llm down")

    verdict = await judge_chain_verdict(chain, verdict_agent=boom)
    assert verdict.confidence == "unadjudicated"
    assert verdict.source_param_location is None


# ===== spec 2026-08-27 §3：多轮 verdict agent 路径（逐条深判，2026-09-01 起唯一形态）=====

def test_single_pass_path_removed():
    """单次判定路径已拆除（2026-09-01 用户决策「不认同单次判定理念」）：
    模块不再有单次模板 / 轻量转格式 / llm_client 注入口——判定只有多轮 agent
    一种形态。仿 test_static_dataflow_hints_decoupling 的锁定测试先例，防回潮。"""
    import supernova_core.code_index.chain_verdict as cv
    import inspect
    assert not hasattr(cv, "_VERDICT_PROMPT")       # 单次版模板
    assert not hasattr(cv, "_reformat_prompt")      # 轻量转格式重试
    # judge 签名不再接受 llm_client
    assert "llm_client" not in inspect.signature(cv.judge_chain_verdict).parameters
    assert "llm_client" not in inspect.signature(
        cv.gather_verdicts_concurrently).parameters


def _agent_chain():
    return CandidateChain(
        vuln_class="injection", flow_id="f1", entry_point_id="ep",
        source_param="q", source_type="query", sink_call_site_id="db.execute:1",
        sink_slot="sql_value", propagation_steps=[_step("concat")],
        sanitizer_annotations=[], direction_hint="forward",
        post_sanitize_concat=True,
    )


@pytest.mark.asyncio
async def test_judge_chain_verdict_agent_runner_structured_output():
    """verdict_agent 路径：structured_output（dict）优先 → JSON str 解析；
    agent 收到 CHAIN_VERDICT_SCHEMA（output_format 透传）与 agent_name。"""
    calls = []

    async def fake_agent(prompt, *, output_format=None, agent_name=None):
        calls.append({"prompt": prompt, "output_format": output_format,
                      "agent_name": agent_name})
        return _AgentResult(structured_output={
            "verdict": "vulnerable", "witness_payload": "'",
            "evidence_chain": "q -> db.execute(L1)",
            "mismatch_reason": "concat into sql value slot",
            "confidence": "high", "title": "SQLi in search",
        })

    verdict = await judge_chain_verdict(
        _agent_chain(), verdict_agent=fake_agent, agent_name="chain-verdict-injection-01")
    assert verdict.verdict == "vulnerable"
    assert verdict.witness_payload == "'"
    assert verdict.title == "SQLi in search"
    assert len(calls) == 1
    assert calls[0]["output_format"] is CHAIN_VERDICT_SCHEMA
    assert calls[0]["agent_name"] == "chain-verdict-injection-01"
    # agent prompt 引导自主读码（多轮形态），不再是单次快照假设
    assert "grep" in calls[0]["prompt"].lower() or "read" in calls[0]["prompt"].lower()


@pytest.mark.asyncio
async def test_judge_chain_verdict_agent_runner_text_fallback():
    """agent 无 structured_output → text 兜底解析。"""
    async def fake_agent(prompt, *, output_format=None, agent_name=None):
        return _AgentResult(text='{"verdict":"safe","witness_payload":null,'
                                 '"evidence_chain":"q -> db(ORM)","confidence":"high"}')

    verdict = await judge_chain_verdict(_agent_chain(), verdict_agent=fake_agent)
    assert verdict.verdict == "safe"


@pytest.mark.asyncio
async def test_judge_chain_verdict_agent_failure_conservative():
    """agent 返回 success=False → 保守 unadjudicated（通道失败 ≠ 判非漏洞，
    对齐 agent 异常路径）。"""
    async def failing_agent(prompt, *, output_format=None, agent_name=None):
        return _AgentResult(success=False, error="max turns reached")

    verdict = await judge_chain_verdict(_agent_chain(), verdict_agent=failing_agent)
    assert verdict.confidence == "unadjudicated"
    assert verdict.verdict == "vulnerable"


# ---------- gather_verdicts_concurrently（逐链并行研判，spec 并行化） ----------

import asyncio
from types import SimpleNamespace


def _cand(i: int, vc: str = "xss") -> CandidateChain:
    return CandidateChain(
        vuln_class=vc, flow_id=f"flow#{i}", entry_point_id="app.py:handler:1",
        source_param=f"p{i}", source_type="query_param",
        sink_call_site_id=f"sink:{i}", sink_slot="generic",
        propagation_steps=[], sanitizer_annotations=[],
        direction_hint="backward", post_sanitize_concat=False,
    )


def _vuln_result(i: int):
    """fake verdict agent 返回：title 带链序号，供保序断言。"""
    return SimpleNamespace(structured_output={
        "verdict": "vulnerable", "confidence": "high",
        "evidence_chain": f"p{i} -> sink:{i}", "title": f"t{i:02d}",
    }, text="")


def _tracking_agent(state, delay=0.02):
    """fake verdict_agent：记录 in-flight 峰值；delay 让重叠可见。"""
    async def agent(prompt, *, output_format=None, agent_name=None):
        state["in_flight"] += 1
        state["max_seen"] = max(state["max_seen"], state["in_flight"])
        state["names"].append(agent_name)
        await asyncio.sleep(delay)
        state["in_flight"] -= 1
        state["calls"] += 1
        return _vuln_result(int(prompt.split("source: p")[1].split()[0]))
    return agent


@pytest.mark.asyncio
async def test_gather_verdicts_concurrency_capped():
    """并发上限生效：8 链并发 4 → 同时 in-flight 峰值恰为 4（不多不少）。"""
    from supernova_core.code_index.chain_verdict import gather_verdicts_concurrently

    state = {"in_flight": 0, "max_seen": 0, "calls": 0, "names": []}
    verdicts = await gather_verdicts_concurrently(
        [_cand(i) for i in range(1, 9)], vc="xss",
        verdict_agent=_tracking_agent(state),
        max_agents=100, concurrency=4)
    assert len(verdicts) == 8
    assert state["max_seen"] == 4
    assert state["calls"] == 8
    # agent_name 唯一记账（chain-verdict-{vc}-{i:02d}）
    assert len(set(state["names"])) == 8
    assert "chain-verdict-xss-09" not in state["names"]


@pytest.mark.asyncio
async def test_gather_verdicts_preserves_order():
    """完成乱序（后发链先完成）→ 返回仍按候选顺序（gather 保序，ID 语义不变）。"""
    from supernova_core.code_index.chain_verdict import gather_verdicts_concurrently

    async def agent(prompt, *, output_format=None, agent_name=None):
        i = int(prompt.split("source: p")[1].split()[0])
        await asyncio.sleep((6 - i) * 0.02)   # 链 5 最先完成、链 1 最后
        return _vuln_result(i)

    verdicts = await gather_verdicts_concurrently(
        [_cand(i) for i in range(1, 6)], vc="xss",
        verdict_agent=agent, max_agents=100, concurrency=5)
    assert [v.title for v in verdicts] == [f"t{i:02d}" for i in range(1, 6)]


@pytest.mark.asyncio
async def test_gather_verdicts_budget_overflow_unadjudicated():
    """超预算链不跑 agent → unadjudicated 保守；预算内照常并行；tick 全量计数。"""
    from supernova_core.code_index.chain_verdict import gather_verdicts_concurrently
    from supernova_core.code_index.progress import ProgressEmitter

    ticks = []

    async def cb(sample):
        ticks.append(sample)

    state = {"in_flight": 0, "max_seen": 0, "calls": 0, "names": []}
    emitter = ProgressEmitter("chain-verdict", 5, cb)
    verdicts = await gather_verdicts_concurrently(
        [_cand(i) for i in range(1, 6)], vc="xss",
        verdict_agent=_tracking_agent(state),
        emitter=emitter, max_agents=3, concurrency=2)
    assert state["calls"] == 3                       # 只预算内 3 条跑了 agent
    assert len(verdicts) == 5
    for v in verdicts[:3]:
        assert v.verdict == "vulnerable"
    for v in verdicts[3:]:
        assert v.confidence == "unadjudicated"
        assert "beyond verdict budget" in (v.mismatch_reason or "")
    # tick：5 条全计数（含超预算 2 条）；未传 detail_of → detail 恒 None，
    # hits 按 vulnerable 口径（3 判定 + 2 unadjudicated 保守条，对齐原 for 循环）。
    assert ticks[-1].done == 5
    assert len(ticks) == 5
    assert all(t.detail is None for t in ticks)
    assert sum(t.hits for t in [ticks[-1]]) == 5


@pytest.mark.asyncio
async def test_gather_verdicts_detail_drives_hits():
    """detail_of 返回 str → hit（hits_delta=1）；None → 非命中（second_order 的
    write_tainted 语义由闭包表达）。"""
    from supernova_core.code_index.chain_verdict import gather_verdicts_concurrently
    from supernova_core.code_index.progress import ProgressEmitter

    samples = []

    async def cb(sample):
        samples.append(sample)

    async def agent(prompt, *, output_format=None, agent_name=None):
        i = int(prompt.split("source: p")[1].split()[0])
        so = {"verdict": "vulnerable", "confidence": "high",
              "evidence_chain": f"p{i} -> sink:{i}"}
        if i == 2:   # 链 2 判 safe（detail_of 返回 None）
            so["verdict"] = "safe"
        return SimpleNamespace(structured_output=so, text="")

    emitter = ProgressEmitter("chain-verdict", 3, cb)
    verdicts = await gather_verdicts_concurrently(
        [_cand(i) for i in range(1, 4)], vc="xss",
        verdict_agent=agent, emitter=emitter,
        max_agents=10, concurrency=3,
        detail_of=lambda i, item, v: (
            f"XSS-GN-{i:02d} vulnerable: p{i}" if v.verdict == "vulnerable" else None))
    assert [v.verdict for v in verdicts] == ["vulnerable", "safe", "vulnerable"]
    assert emitter._hits == 2
    assert [s.detail for s in samples if s.detail] == [
        "XSS-GN-01 vulnerable: p1", "XSS-GN-03 vulnerable: p3"]


@pytest.mark.asyncio
async def test_gather_verdicts_default_concurrency_from_env(monkeypatch):
    """concurrency 缺省 → 读 SUPERNOVA_CHAIN_VERDICT_CONCURRENCY。"""
    from supernova_core.code_index.chain_verdict import gather_verdicts_concurrently

    monkeypatch.setenv("SUPERNOVA_CHAIN_VERDICT_CONCURRENCY", "2")
    state = {"in_flight": 0, "max_seen": 0, "calls": 0, "names": []}
    await gather_verdicts_concurrently(
        [_cand(i) for i in range(1, 7)], vc="xss",
        verdict_agent=_tracking_agent(state), max_agents=100)
    assert state["max_seen"] == 2


@pytest.mark.asyncio
async def test_gather_verdicts_chain_of_for_second_order():
    """chain_of 提取判定链（second_order 判 read_side_chain）+ vc 前缀进 agent_name。"""
    from supernova_core.code_index.chain_verdict import gather_verdicts_concurrently

    state = {"in_flight": 0, "max_seen": 0, "calls": 0, "names": []}
    verdicts = await gather_verdicts_concurrently(
        [SimpleNamespace(read_side_chain=_cand(i)) for i in range(1, 3)],
        vc="2nd", verdict_agent=_tracking_agent(state),
        chain_of=lambda item: item.read_side_chain,
        max_agents=10, concurrency=2)
    assert len(verdicts) == 2
    assert all(n.startswith("chain-verdict-2nd-") for n in state["names"])


@pytest.mark.asyncio
async def test_gather_verdicts_shared_semaphore_caps_total():
    """共享 semaphore：两类（inj/xss）并发各判 4 链，总 in-flight ≤ 4——
    activity 层三类 builder 共享并发预算的基石。"""
    import asyncio
    from supernova_core.code_index.chain_verdict import gather_verdicts_concurrently

    state = {"in_flight": 0, "max_seen": 0}

    async def agent(prompt, *, output_format=None, agent_name=None):
        state["in_flight"] += 1
        state["max_seen"] = max(state["max_seen"], state["in_flight"])
        await asyncio.sleep(0.02)
        state["in_flight"] -= 1
        return _vuln_result(int(prompt.split("source: p")[1].split()[0]))

    shared = asyncio.Semaphore(4)
    await asyncio.gather(
        gather_verdicts_concurrently(
            [_cand(i, vc="injection") for i in range(1, 5)], vc="injection",
            verdict_agent=agent, semaphore=shared),
        gather_verdicts_concurrently(
            [_cand(i, vc="xss") for i in range(1, 5)], vc="xss",
            verdict_agent=agent, semaphore=shared),
    )
    assert state["max_seen"] <= 4
    assert state["max_seen"] == 4   # 预算被两批竞争填满（非各自为政 ×4）


@pytest.mark.asyncio
async def test_gather_verdicts_shared_semaphore():
    """外部共享 semaphore：类间并发共用一个预算（concurrency 参数不再各自建闸），
    防三类 builder 并发时并发数乘法爆炸。"""
    from supernova_core.code_index.chain_verdict import gather_verdicts_concurrently

    sem = asyncio.Semaphore(2)
    state = {"in_flight": 0, "max_seen": 0, "calls": 0, "names": []}
    # concurrency=10 但共享 sem=2 → 实际同时 in-flight 峰值 = 2
    verdicts = await gather_verdicts_concurrently(
        [_cand(i) for i in range(1, 7)], vc="xss",
        verdict_agent=_tracking_agent(state),
        semaphore=sem, max_agents=100, concurrency=10)
    assert len(verdicts) == 6
    assert state["max_seen"] == 2
