"""黑盒主 workflow（BlackboxScanWorkflow）的 phase steps 声明 —— 进度条数据源。

根因修复（2026-08-21）：主 workflow 4 处 log_phase_start_activity 曾全传 [],[]
→ PhaseEvent(steps=[]) → 详情页顶部进度条在黑盒段消失（组合归并流上还会清掉白盒
段已显示的 phase_units）。本文件锁定三段声明：

  - auth-validation：AUTH_VALIDATION_PROGRESS 4 步（SSOT，与独立 AuthValidationWorkflow
    / log_milestone 工具同源）——StepEvent/AgentEvent 已在发，声明即推进。
  - exploitation：动态 [endpoint-verify（有 web_url 时）] + [{vt}-exploit（selected_classes）]，
    白盒 vulnerability-analysis 的 vuln_phase_steps 同模式，靠既有 AgentEvent 推进。
  - reporting：["report"]（与 run_report_agent 的 AgentEvent(agent_name="report") 对齐）。

preflight 段有意不声明（2026-08-21 决策：数十秒确定性预检、无事件驱动，补 steps
须改 activity 层，成本不成比例）——此处一并锁定其保持空。

Mock 链复用 test_workflow_proxy_orchestration 的全集（config_path 置位多走
run_blackbox_auth_validation 一站）。断言 steps/intents 声明，非真实渲染。
"""
import pytest
from temporalio import activity
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from supernova_core.agents.progress_tool import AUTH_VALIDATION_PROGRESS
from supernova_core.services import scan_gate as gate_mod
from supernova_blackbox.pipeline.workflows import BlackboxScanWorkflow
from supernova_blackbox.pipeline.shared import BlackboxPipelineInput
from supernova_blackbox.services.exploitation_checker import QueueValidationResult


@pytest.fixture(autouse=True)
def _reset_gate():
    """闸门接线后 run() 首个 activity 是 scan_gate_try_acquire（真实现）——
    进程级 gate 单例跨测试清态，防槽残留互扰。"""
    gate_mod.reset_gate_for_tests()
    yield
    gate_mod.reset_gate_for_tests()


def _build_phase_steps_mocks(declared: list) -> list:
    """完整 mock activity 链（log_phase_start_activity 捕获 (phase, steps, intents)）。

    覆盖 config_path + web_url + exploit 全路径；detect_whitebox_results 返回
    injection 命中，validate_exploitation_queue 恒 valid（exploit agent 正常调度）。
    """

    @activity.defn
    async def setup_display(i): pass

    @activity.defn
    async def log_phase_start_activity(i, steps=None, intents=None):
        phase = getattr(i, "phase", None) or (
            i.get("phase") if isinstance(i, dict) else None)
        declared.append((phase, list(steps or []), list(intents or [])))

    @activity.defn
    async def run_host_proxy_setup(i): return ""

    @activity.defn
    async def run_blackbox_preflight(i): pass

    @activity.defn
    async def resolve_blackbox_engine(i): return "agent-browser"

    @activity.defn
    async def run_blackbox_auth_validation(i): pass

    @activity.defn
    async def detect_whitebox_results(dp, vc, corr):
        return {"has_whitebox_results": True, "found_classes": ["injection"],
                "corr_classes": [], "has_recon_deliverable": True}

    @activity.defn
    async def log_info_activity(i): pass

    @activity.defn
    async def run_endpoint_verify(i):
        return {"endpoint_verify": None, "cost_currency": "USD"}

    @activity.defn
    async def validate_exploitation_queue(i) -> QueueValidationResult:
        return QueueValidationResult(valid=True, reason="ok", vuln_count=1)

    @activity.defn
    async def write_engine_config_for_session(repo, sess, eng, proxy_url=None):
        pass

    @activity.defn
    async def run_exploit_agent(i):
        return {"duration_ms": 1, "cost_usd": 0.0, "cost_currency": "USD"}

    @activity.defn
    async def assemble_report(i): pass

    @activity.defn
    async def run_report_agent(i): return {"duration_ms": 1, "cost_usd": 0.0}

    @activity.defn
    async def verify_report_vuln_blocks(i): pass

    @activity.defn
    async def finalize_report(i): pass

    @activity.defn
    async def cleanup_engine_configs(rp, eng): pass

    @activity.defn
    async def cleanup_auth_state_activity(ws): pass

    @activity.defn
    async def stop_host_proxy(proxy_url): pass

    @activity.defn
    async def finalize_summary(i, summary): pass

    @activity.defn
    async def persist_completed_agents(i, completed_agents): pass

    return [gate_mod.scan_gate_try_acquire, gate_mod.scan_gate_release,
            setup_display, log_phase_start_activity, run_host_proxy_setup,
            run_blackbox_preflight, resolve_blackbox_engine,
            run_blackbox_auth_validation, detect_whitebox_results,
            log_info_activity, run_endpoint_verify,
            validate_exploitation_queue, write_engine_config_for_session,
            run_exploit_agent, assemble_report, run_report_agent,
            verify_report_vuln_blocks, finalize_report, cleanup_engine_configs,
            cleanup_auth_state_activity, stop_host_proxy, finalize_summary,
            persist_completed_agents]


def _pipeline_input(tmp_path, web_url: str) -> BlackboxPipelineInput:
    return BlackboxPipelineInput(
        web_url=web_url, repo_path=str(tmp_path / "repo"),
        workspace_name="bb-steps", workspaces_root=str(tmp_path / "ws"),
        deliverables_subdir="deliverables", exploit=True,
        event_file=str(tmp_path / "events.ndjson"),
        config_path="/c.yaml",           # 走 auth-validation 段（172 行 if input.config_path）
        vuln_classes=["injection"],      # selected_classes 精确可控 → steps 可精确断言
    )


async def _run_and_collect(tmp_path, web_url: str) -> dict[str, tuple[list, list]]:
    declared: list = []
    acts = _build_phase_steps_mocks(declared)
    inp = _pipeline_input(tmp_path, web_url)
    async with await WorkflowEnvironment.start_local() as env:
        async with Worker(env.client, task_queue="tq-bb-steps",
                          workflows=[BlackboxScanWorkflow], activities=acts):
            await env.client.execute_workflow(
                BlackboxScanWorkflow.run, inp, id="w-bb-steps",
                task_queue="tq-bb-steps")
    # phase → 最后一次声明（同 phase 重复声明时取最新；当前每 phase 只声明一次）
    by_phase: dict[str, tuple[list, list]] = {}
    for phase, steps, intents in declared:
        by_phase[phase] = (steps, intents)
    return by_phase


@pytest.mark.asyncio
async def test_scan_workflow_declares_phase_steps(tmp_path):
    """三段声明齐全（进度条数据源）：auth-validation 4 步 SSOT / exploitation 动态
    endpoint-verify + {vt}-exploit / reporting report；preflight 保持空（决策锁定）。"""
    by_phase = await _run_and_collect(tmp_path, web_url="https://example.com")

    # preflight：有意不声明（2026-08-21 决策，防将来误填）
    assert by_phase.get("preflight", ([], []))[0] == []

    # auth-validation：与独立 AuthValidationWorkflow / log_milestone 同源（SSOT）
    assert "auth-validation" in by_phase, "config_path 置位必须声明 auth-validation 段"
    av_steps, av_intents = by_phase["auth-validation"]
    assert av_steps == list(AUTH_VALIDATION_PROGRESS.step_keys)
    assert av_intents == [s.intent for s in AUTH_VALIDATION_PROGRESS.steps]

    # exploitation：endpoint-verify（web_url 有值）+ 各调度类的 {vt}-exploit
    assert "exploitation" in by_phase
    ex_steps, ex_intents = by_phase["exploitation"]
    assert ex_steps == ["endpoint-verify", "injection-exploit"]
    assert len(ex_intents) == len(ex_steps), "intents 与 steps 平行等长"

    # reporting：与 run_report_agent 的 AgentEvent(agent_name="report") 对齐
    assert by_phase.get("reporting", ([], []))[0] == ["report"]


@pytest.mark.asyncio
async def test_exploitation_steps_omit_endpoint_verify_without_web_url(tmp_path):
    """web_url 为空（黑盒无 live target）→ run_endpoint_verify 不跑（workflow 323 行
    if input.web_url）→ steps 不得声明 endpoint-verify，否则永远 pending 的死步骤。"""
    by_phase = await _run_and_collect(tmp_path, web_url="")
    ex_steps, _ = by_phase["exploitation"]
    assert "endpoint-verify" not in ex_steps
    assert ex_steps == ["injection-exploit"]
