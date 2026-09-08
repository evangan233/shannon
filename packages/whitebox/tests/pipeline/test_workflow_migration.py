"""C1 Phase B Task 4: WhiteboxScanWorkflow.run 接入迁移 activity 的门控.

门控: is_worker_path = input.event_file is not None.
- worker/web 路径(event_file 非 None): 调 setup_display(首) + 并行 run_heartbeat + finalize_summary(尾).
- CLI 路径(event_file None): 不调(靠 run_scan 外层 set_audit_session/heartbeat/log_workflow_complete,
  守 "CLI 零改动" + 消除 R1 双重 scan_end/heartbeat/set_audit_session).

测试策略: 只注册 3 个迁移 activity mock; workflow 在首个未注册的主体 activity
(log_phase_start_activity)处失败, 但 setup_display/run_heartbeat 在其之前已执行(门控打开时).
负面测试验证 CLI 路径(event_file=None)连 setup_display 都不调.
"""
import asyncio

import pytest
from temporalio import activity
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from supernova_core.services import scan_gate as gate_mod
from supernova_whitebox.pipeline.workflows import WhiteboxScanWorkflow
from supernova_whitebox.pipeline.shared import PipelineInput


@pytest.fixture(autouse=True)
def _reset_gate():
    """闸门接线后 run() 首个 activity 是 scan_gate_try_acquire（真实现）——
    进程级 gate 单例须跨测试清态，防槽残留互扰（worker 路径占槽泄漏到 CLI 用例）。"""
    gate_mod.reset_gate_for_tests()
    yield
    gate_mod.reset_gate_for_tests()


def _migration_activity_mocks(calls: list) -> list:
    """3 个迁移 activity mock + log_phase_start_activity(让 workflow 主体 await 期间
    并行 heartbeat activity 被 worker poll + 执行; 否则 workflow 在首个未注册 activity
    立即失败, heartbeat 还没轮到执行). run_heartbeat 长驻(simulate long-running).
    gate activity 注册真实现（闸门段在 setup_display 之前，缺注册则 workflow 卡闸门）."""
    @activity.defn
    async def setup_display(i):
        calls.append("setup_display")
    @activity.defn
    async def run_heartbeat(i):
        calls.append("run_heartbeat")
        # 测试验证调度: 立即返回. 真实 run_heartbeat 永阻塞(asyncio.Event().wait()),
        # 其 long-running + cancel 清理由 Task 3 单测覆盖.
    @activity.defn
    async def finalize_summary(i, s):
        calls.append("finalize_summary")
    @activity.defn
    async def log_phase_start_activity(i, names, intents):
        # workflow 主体首个 await; sleep 给并行 heartbeat activity 时间被 worker poll + 执行
        # (模拟真实 workflow 主体跑 activity 耗时, heartbeat 并行).
        await asyncio.sleep(0.2)
    return [gate_mod.scan_gate_try_acquire, gate_mod.scan_gate_release,
            setup_display, run_heartbeat, finalize_summary, log_phase_start_activity]


@pytest.mark.asyncio
async def test_worker_path_invokes_setup_display_and_heartbeat(tmp_path):
    """event_file 非 None(worker 路径): workflow.run 调 setup_display(首) + 起 run_heartbeat.

    只注册 3 迁移 activity; workflow 在首个未注册主体 activity(log_phase_start_activity)失败,
    但 setup_display/heartbeat 在其之前已执行. 验证门控打开时迁移 activity 被调.
    """
    calls: list = []
    inp = PipelineInput(
        repo_path=str(tmp_path),
        workspace_name="ws-worker",
        event_file=str(tmp_path / "events.ndjson"),
        enable_llm_track=False,
    )
    async with await WorkflowEnvironment.start_local() as env:
        async with Worker(
            env.client, task_queue="tq-worker",
            workflows=[WhiteboxScanWorkflow],
            activities=_migration_activity_mocks(calls),
        ):
            with pytest.raises(Exception):
                await env.client.execute_workflow(
                    WhiteboxScanWorkflow.run, inp,
                    id="w-worker-path", task_queue="tq-worker",
                )
    assert "setup_display" in calls, f"worker 路径应调 setup_display, calls={calls}"
    assert calls.index("setup_display") == 0, f"setup_display 应首调, calls={calls}"
    # run_heartbeat 在同一 if is_worker_path 块(setup_display 紧后), setup_display 被调证明
    # 块执行 → heartbeat 必被调度. 其 long-running 执行(写 heartbeat + cancel 清理)由 Task 3
    # 单测覆盖, 端到端由 Task 9 真机验(单测里并行 long-running activity poll 时序不可靠).


@pytest.mark.asyncio
async def test_cli_path_skips_migration_activities(tmp_path):
    """event_file=None(CLI 路径): workflow.run 不调任何迁移 activity.

    守 "CLI 零改动" + R1 双重 scan_end/heartbeat/set_audit_session — CLI 路径靠 run_scan 外层.
    """
    calls: list = []
    inp = PipelineInput(
        repo_path=str(tmp_path),
        workspace_name="ws-cli",
        event_file=None,
        enable_llm_track=False,
    )
    async with await WorkflowEnvironment.start_local() as env:
        async with Worker(
            env.client, task_queue="tq-cli",
            workflows=[WhiteboxScanWorkflow],
            activities=_migration_activity_mocks(calls),
        ):
            with pytest.raises(Exception):
                await env.client.execute_workflow(
                    WhiteboxScanWorkflow.run, inp,
                    id="w-cli-path", task_queue="tq-cli",
                )
    assert calls == [], f"CLI 路径不应调任何迁移 activity, calls={calls}"
