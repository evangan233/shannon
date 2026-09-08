"""spec 2026-08-03 黑盒端点 live 验证 agent 测试。

黑盒 exploitation 前插入端点验证 agent:读白盒 queue 端点清单 + auth-state,对每端点
做 live 验证 + 路由转发前缀智能探测,产 endpoint_verify.json 到 blackbox/。
功能性失败(agent 崩/超时/无产出) → 降级 exploit 全打(零回归)。
"""
import json

import pytest
from temporalio import activity
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker
from unittest.mock import AsyncMock, MagicMock

from supernova_core.models.agents import AGENTS, AgentName
from supernova_core.models.metrics import AgentMetrics
from supernova_blackbox.agents.endpoint_verify_executor import EndpointVerifyExecutor
from supernova_blackbox.pipeline.workflows import BlackboxScanWorkflow
from supernova_core.services import scan_gate as gate_mod
from supernova_blackbox.pipeline.shared import BlackboxPipelineInput
from supernova_blackbox.services.exploitation_checker import QueueValidationResult


# ─── B1: agent 登记 ────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _reset_gate():
    """闸门接线后 run() 首个 activity 是 scan_gate_try_acquire（真实现）——
    进程级 gate 单例跨测试清态，防槽残留互扰。"""
    gate_mod.reset_gate_for_tests()
    yield
    gate_mod.reset_gate_for_tests()

def test_endpoint_verify_agent_registered():
    """endpoint-verify agent 登记:prompt_template + 产 json 不产 md(不校验 md deliverable)。

    endpoint_verify.json 由 activity 拿 structured_output 自落盘到 blackbox/(非 md,
    故 deliverable_filename=None,validate_deliverable 直接放行)。
    """
    assert hasattr(AgentName, "ENDPOINT_VERIFY")
    assert AgentName.ENDPOINT_VERIFY.value == "endpoint-verify"
    defn = AGENTS[AgentName.ENDPOINT_VERIFY]
    assert defn.prompt_template == "blackbox-endpoint-verify"
    assert defn.deliverable_filename is None


# ─── B2: _collect_endpoint_manifest 读白盒所有 queue ───────────────────────────

@pytest.mark.asyncio
async def test_collect_endpoint_manifest_reads_all_queues(tmp_path):
    """_collect_endpoint_manifest 读白盒所有 {vt}_exploitation_queue.json,合并成
    端点清单(json)。endpoint_verify agent 跨类验证,需端点全集。缺失 queue 跳过。"""
    dlv = tmp_path / "deliverables"
    (dlv / "whitebox").mkdir(parents=True)
    (dlv / "whitebox" / "injection_exploitation_queue.json").write_text(
        '{"vulnerabilities": [{"ID": "INJ-1", "source_endpoint": "/api/search"}]}')
    (dlv / "whitebox" / "authz_exploitation_queue.json").write_text(
        '{"vulnerabilities": [{"ID": "AUTHZ-1", "endpoint": "/api/users/{id}"}]}')
    # auth queue 不存在 → 跳过

    ex = EndpointVerifyExecutor(MagicMock())
    manifest = await ex._collect_endpoint_manifest(dlv, ["injection", "authz", "auth"])

    data = json.loads(manifest)
    assert "injection" in data and "authz" in data
    assert "auth" not in data  # queue 缺失 → 跳过


@pytest.mark.asyncio
async def test_collect_endpoint_manifest_empty_when_no_queues(tmp_path):
    """无任何白盒 queue → 空串(无端点,execute 据此降级)。"""
    dlv = tmp_path / "deliverables"
    (dlv / "whitebox").mkdir(parents=True)
    ex = EndpointVerifyExecutor(MagicMock())
    manifest = await ex._collect_endpoint_manifest(dlv, ["injection", "xss"])
    assert manifest == ""


# ─── B3: execute() 拿 structured_output → 写 blackbox/endpoint_verify.json ─────

@pytest.mark.asyncio
async def test_execute_writes_endpoint_verify_json(tmp_path):
    """execute 拿 structured_output → 写 blackbox/endpoint_verify.json(spec 5.3 schema)。

    传给底层 executor:structured_output_schema(强制结构化输出) + skip_artifact_postprocess=True
    (activity 自落盘 blackbox/,不让 executor 写顶层 queue)。
    """
    dlv = tmp_path / "deliverables"
    (dlv / "whitebox").mkdir(parents=True)
    (dlv / "whitebox" / "injection_exploitation_queue.json").write_text(
        '{"vulnerabilities": [{"ID": "INJ-1", "source_endpoint": "/api/search"}]}')

    fake_metrics = AgentMetrics(
        duration_ms=100, cost_usd=0.01, num_turns=2, model="stub",
        structured_output={
            "GET /api/search": {
                "live_status": "live", "resolved_path": "/api/search",
                "source_path": "/api/search", "evidence": "200 OK business body",
            },
        })
    stub_executor = MagicMock()
    stub_executor.execute = AsyncMock(return_value=fake_metrics)

    ex = EndpointVerifyExecutor(stub_executor)
    result = await ex.execute(
        deliverables_path=dlv, workspace_path=dlv.parent,
        web_url="https://t.com", vuln_classes=["injection"])

    # endpoint_verify.json 落 blackbox/
    ev = json.loads((dlv / "blackbox" / "endpoint_verify.json").read_text())
    assert ev["GET /api/search"]["live_status"] == "live"
    assert result["endpoint_verify"] is not None
    # 传给底层 executor 的关键参数
    _, kwargs = stub_executor.execute.call_args
    assert kwargs.get("agent_name") == AgentName.ENDPOINT_VERIFY
    assert kwargs.get("structured_output_schema") is not None
    assert kwargs.get("skip_artifact_postprocess") is True
    # endpoints_manifest 注入 prompt_variables
    assert "endpoints_manifest" in kwargs.get("prompt_variables", {})


# ─── B4: 功能性失败 → 降级(不写盘,exploit 全打) ────────────────────────────────

@pytest.mark.asyncio
async def test_execute_degrades_when_no_structured_output(tmp_path):
    """agent 无 structured_output(崩/超时/失忆) → 不写 endpoint_verify.json + 降级标记。

    降级语义:exploit 照打(无验证记录 = 现状,零回归)。"""
    dlv = tmp_path / "deliverables"
    (dlv / "whitebox").mkdir(parents=True)
    (dlv / "whitebox" / "injection_exploitation_queue.json").write_text(
        '{"vulnerabilities": [{"ID": "INJ-1"}]}')
    fake_metrics = AgentMetrics(duration_ms=100, cost_usd=0.01, num_turns=2, model="stub",
                                structured_output=None)
    stub_executor = MagicMock()
    stub_executor.execute = AsyncMock(return_value=fake_metrics)

    ex = EndpointVerifyExecutor(stub_executor)
    result = await ex.execute(
        deliverables_path=dlv, workspace_path=dlv.parent,
        web_url="https://t.com", vuln_classes=["injection"])

    assert result["endpoint_verify"] is None  # 降级
    assert not (dlv / "blackbox" / "endpoint_verify.json").exists()  # 不写盘
    # 降级 dict 须含 cost_currency:run_endpoint_verify 成功分支用 result.get("cost_currency")
    # 构造 AgentEndResult(cost_currency: str),降级 dict 缺 key → .get() 得 None → Pydantic 校验崩
    # (真机 NodeGoat 扫描 endpoint-verify failed 的直接根因)。
    assert result["cost_currency"] == "USD"


@pytest.mark.asyncio
async def test_execute_degrades_when_no_endpoints(tmp_path):
    """无白盒端点(queue 全缺) → 不调 agent,直接降级(省预算)。"""
    dlv = tmp_path / "deliverables"
    (dlv / "whitebox").mkdir(parents=True)
    stub_executor = MagicMock()
    stub_executor.execute = AsyncMock()

    ex = EndpointVerifyExecutor(stub_executor)
    result = await ex.execute(
        deliverables_path=dlv, workspace_path=dlv.parent,
        web_url="https://t.com", vuln_classes=["injection", "xss"])

    assert result["endpoint_verify"] is None
    stub_executor.execute.assert_not_called()  # 无端点不调 agent
    # 降级 dict 须含 cost_currency(同上,activities 成功分支 .get() 取,缺 key 则校验崩)。
    assert result["cost_currency"] == "USD"


# ─── B6: prompt 契约(回归守卫) ─────────────────────────────────────────────────

def test_endpoint_verify_prompt_contract():
    """blackbox-endpoint-verify.txt 关键契约:复用 auth-state + 端点清单注入 + 三态。

    config 类回归守卫:未来改 prompt 不得丢失这些关键不变量。"""
    from pathlib import Path

    prompt = (Path(__file__).resolve().parents[3] / "prompts"
              / "blackbox-endpoint-verify.txt").read_text("utf-8")
    assert "@include(shared/_shared-session.txt)" in prompt  # 复用 preflight auth-state
    assert "{{ENDPOINTS_MANIFEST}}" in prompt  # 端点清单注入(manager 通用 fallback)
    assert "{{WEB_URL}}" in prompt  # live target
    for status in ("live", "not_live", "param_invalid"):  # spec 三态
        assert status in prompt


# ─── Part C: workflow 插入端点验证阶段(mock activity 驱动) ───────────────────────

def _build_exploit_chain_mocks(call_order: list, endpoint_verify_return: dict) -> list:
    """建 exploit=True + has_whitebox=True 完整链的 mock activity 集合。

    endpoint_verify_return 控制 run_endpoint_verify 的返回(正常 path / 降级 None)。
    validate→exploit 记入 call_order,供顺序断言。
    """
    @activity.defn
    async def setup_display(i): pass
    @activity.defn
    async def log_phase_start_activity(i, steps=None, intents=None): pass
    @activity.defn
    async def run_blackbox_preflight(i): pass
    @activity.defn
    async def resolve_blackbox_engine(i): return "agent-browser"
    @activity.defn
    async def detect_whitebox_results(dp, vc, corr):
        return {"has_whitebox_results": True, "found_classes": ["injection"],
                "corr_classes": [], "has_recon_deliverable": True}
    @activity.defn
    async def log_info_activity(i): pass
    @activity.defn
    async def run_endpoint_verify(i):
        call_order.append("endpoint_verify")
        return endpoint_verify_return
    @activity.defn
    async def validate_exploitation_queue(i) -> QueueValidationResult:
        call_order.append("validate")
        return QueueValidationResult(valid=True, reason="ok", vuln_count=1)
    @activity.defn
    async def write_engine_config_for_session(repo, sess, eng): pass
    @activity.defn
    async def run_exploit_agent(i):
        call_order.append("exploit")
        return {"duration_ms": 1, "cost_usd": 0.0, "cost_currency": "USD"}
    @activity.defn
    async def assemble_report(i): pass
    @activity.defn
    async def run_report_agent(i): return {"duration_ms": 1, "cost_usd": 0.0}
    @activity.defn
    async def finalize_report(i): pass
    @activity.defn
    async def cleanup_engine_configs(rp, eng): pass
    @activity.defn
    async def cleanup_auth_state_activity(ws): pass
    @activity.defn
    async def finalize_summary(i, summary): pass
    return [setup_display, log_phase_start_activity, run_blackbox_preflight,
            resolve_blackbox_engine, detect_whitebox_results, log_info_activity,
            run_endpoint_verify, validate_exploitation_queue,
            write_engine_config_for_session, run_exploit_agent,
            assemble_report, run_report_agent, finalize_report,
            cleanup_engine_configs, cleanup_auth_state_activity, finalize_summary]


async def _run_workflow(acts, inp, wid, tq):
    async with await WorkflowEnvironment.start_local() as env:
        async with Worker(env.client, task_queue=tq, workflows=[BlackboxScanWorkflow],
                          # gate activity 用真实现：闸门接线后 run() 首个 activity 即过闸
                          activities=[*acts, gate_mod.scan_gate_try_acquire,
                                      gate_mod.scan_gate_release]):
            return await env.client.execute_workflow(
                BlackboxScanWorkflow.run, inp, id=wid, task_queue=tq)


def _exploit_input(tmp_path):
    return BlackboxPipelineInput(
        web_url="https://example.com", repo_path=str(tmp_path / "repo"),
        workspace_name="bb-ev", workspaces_root=str(tmp_path / "workspaces"),
        deliverables_subdir="deliverables", exploit=True,
        event_file=str(tmp_path / "events.ndjson"))


@pytest.mark.asyncio
async def test_workflow_runs_endpoint_verify_before_exploit(tmp_path):
    """spec 2026-08-03: exploit=True + 有白盒产物 → exploitation 前调 run_endpoint_verify,
    且在 validate_exploitation_queue 循环前。

    RED: workflow 不调 run_endpoint_verify → call_order 不含 endpoint_verify。
    GREEN: exploit 块开头插入 run_endpoint_verify 调用。
    """
    call_order: list = []
    acts = _build_exploit_chain_mocks(
        call_order, {"endpoint_verify": "/x/endpoint_verify.json", "verified_count": 1})
    await _run_workflow(acts, _exploit_input(tmp_path), "w-ev1", "tq-ev1")

    assert "endpoint_verify" in call_order, "workflow 应在 exploitation 前调 run_endpoint_verify"
    assert call_order.index("endpoint_verify") < call_order.index("validate"), (
        "run_endpoint_verify 应在 validate_exploitation_queue 循环前调用")


@pytest.mark.asyncio
async def test_workflow_endpoint_verify_degradation_runs_full_exploit(tmp_path):
    """spec 2026-08-03 降级:run_endpoint_verify 返回 endpoint_verify=None(agent 崩/超时/无产出)
    → exploit 仍全跑 + workflow 正常完成(零回归,不中断)。

    RED: workflow 因 endpoint_verify=None 中断或跳过 exploit。
    GREEN: workflow 无视 endpoint_verify=None,继续 exploit(降级=现状)。
    """
    call_order: list = []
    acts = _build_exploit_chain_mocks(
        call_order, {"endpoint_verify": None, "reason": "degraded"})
    result = await _run_workflow(acts, _exploit_input(tmp_path), "w-ev2", "tq-ev2")

    assert "exploit" in call_order, "降级后 exploit 应仍全跑(零回归)"
    assert result.status == "completed", (
        f"降级不应中断 workflow,status 应 completed,实际 {result.status}")


# ─── Part D: exploit 衔接 endpoint_verify.json(ExploitExecutor 注入) ────────────

@pytest.mark.asyncio
async def test_exploit_executor_injects_endpoint_verify(tmp_path):
    """spec 2026-08-03 Part D:ExploitExecutor 读 blackbox/endpoint_verify.json,注入
    prompt_variables['endpoint_verify'](供 exploit prompt 衔接:not_live 跳过 / live 用
    resolved_path / param_invalid 仍打)。"""
    from supernova_blackbox.agents.exploit_executor import ExploitExecutor
    dlv = tmp_path / "deliverables"
    (dlv / "whitebox").mkdir(parents=True)
    (dlv / "whitebox" / "injection_exploitation_queue.json").write_text(
        '{"vulnerabilities": [{"ID": "INJ-1", "source_endpoint": "/api/search"}]}')
    (dlv / "blackbox").mkdir(parents=True)
    (dlv / "blackbox" / "endpoint_verify.json").write_text(json.dumps({
        "GET /api/search": {"live_status": "live", "resolved_path": "/api/search",
                            "source_path": "/api/search", "evidence": "200 OK"}}))

    stub_executor = MagicMock()
    stub_executor.execute = AsyncMock(
        return_value=AgentMetrics(duration_ms=10, cost_usd=0.0, num_turns=1, model="stub"))
    ex = ExploitExecutor(stub_executor)
    await ex.execute(agent_name=AgentName.INJECTION_EXPLOIT, vuln_type="injection",
                     workspace_path=tmp_path, deliverables_path=dlv, web_url="https://x.com")

    pv = stub_executor.execute.call_args.kwargs.get("prompt_variables", {})
    assert "endpoint_verify" in pv, "应注入 endpoint_verify 供 exploit prompt 衔接"
    assert "GET /api/search" in pv["endpoint_verify"]


@pytest.mark.asyncio
async def test_exploit_executor_no_endpoint_verify_degrades(tmp_path):
    """endpoint_verify.json 不存在(降级 / 未跑验证 / 无 web_url) → 不注入 endpoint_verify,
    exploit 照打(零回归,= 现状)。"""
    from supernova_blackbox.agents.exploit_executor import ExploitExecutor
    dlv = tmp_path / "deliverables"
    (dlv / "whitebox").mkdir(parents=True)
    (dlv / "whitebox" / "injection_exploitation_queue.json").write_text(
        '{"vulnerabilities": [{"ID": "INJ-1"}]}')
    # 无 blackbox/endpoint_verify.json

    stub_executor = MagicMock()
    stub_executor.execute = AsyncMock(
        return_value=AgentMetrics(duration_ms=10, cost_usd=0.0, num_turns=1, model="stub"))
    ex = ExploitExecutor(stub_executor)
    await ex.execute(agent_name=AgentName.INJECTION_EXPLOIT, vuln_type="injection",
                     workspace_path=tmp_path, deliverables_path=dlv, web_url="https://x.com")

    pv = stub_executor.execute.call_args.kwargs.get("prompt_variables", {})
    # 无文件 → 注入空串占位(避免裸 {{ENDPOINT_VERIFY}} 残留 + manager warning),partial 据此"照打"
    assert pv.get("endpoint_verify") == "", "无 endpoint_verify.json 应注入空串占位"


# ─── Part D 契约:exploit prompt @include + partial 占位符(回归守卫) ─────────────

def test_all_exploit_prompts_include_endpoint_verify_hint():
    """spec 2026-08-03 Part D:所有 5 个 exploit prompt @include _endpoint-verify-hint
    (衔接 endpoint_verify:not_live 跳过 / live 用 resolved_path)。"""
    from pathlib import Path
    prompts_dir = Path(__file__).resolve().parents[3] / "prompts"
    for vt in ("injection", "xss", "auth", "ssrf", "authz"):
        text = (prompts_dir / f"{vt}-exploit.txt").read_text("utf-8")
        assert "@include(shared/_endpoint-verify-hint.txt)" in text, (
            f"{vt}-exploit.txt 应 @include _endpoint-verify-hint(衔接 endpoint_verify)")


def test_endpoint_verify_hint_partial_has_placeholder():
    """_endpoint-verify-hint.txt 含 {{ENDPOINT_VERIFY}}(ExploitExecutor 注入)+ 三态说明。"""
    from pathlib import Path
    partial = (Path(__file__).resolve().parents[3] / "prompts" / "shared"
               / "_endpoint-verify-hint.txt").read_text("utf-8")
    assert "{{ENDPOINT_VERIFY}}" in partial
    for status in ("live", "not_live", "param_invalid"):
        assert status in partial
