"""BlackboxScanWorkflow 闸门段集成测（spec §5）：过闸顺序、排队、释放。

模式对齐 whitebox test_workflow_gate：只注册 gate activity（真实现）+
setup_display，workflow 死于其后首个未注册的主体 activity——用失败证明前导已执行。
"""

import asyncio

import pytest
from temporalio import activity
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from supernova_core.services import scan_gate as gate_mod
from supernova_blackbox.pipeline.workflows import BlackboxScanWorkflow
from supernova_blackbox.pipeline.shared import BlackboxPipelineInput


@pytest.fixture(autouse=True)
def _gate_env(monkeypatch):
    monkeypatch.setattr(gate_mod, "GATE_POLL_SECONDS", 0.05)
    monkeypatch.setenv("SUPERNOVA_SCAN_GATE_CAPACITY", "1")
    gate_mod.reset_gate_for_tests()
    yield
    gate_mod.reset_gate_for_tests()


def _inp(tmp_path):
    return BlackboxPipelineInput(
        web_url="https://api.example.com",
        workspace_name="ws-bb-gate",
        workspaces_root=str(tmp_path),
        event_file=str(tmp_path / "ws-bb-gate" / "scans" / "s1" / "events.ndjson"),
    )


def _acts(calls: list) -> list:
    @activity.defn
    async def setup_display(i):
        calls.append("setup_display")
    return [gate_mod.scan_gate_try_acquire, gate_mod.scan_gate_release,
            setup_display]


@pytest.mark.asyncio
async def test_blackbox_gate_then_setup_display(tmp_path):
    calls: list = []
    async with await WorkflowEnvironment.start_local() as env:
        async with Worker(env.client, task_queue="tq-bb-gate",
                          workflows=[BlackboxScanWorkflow],
                          activities=_acts(calls)):
            with pytest.raises(Exception):   # 死于 setup_display 后首个未注册 activity
                await asyncio.wait_for(
                    env.client.execute_workflow(
                        BlackboxScanWorkflow.run, _inp(tmp_path),
                        id="w-bb-gate", task_queue="tq-bb-gate"),
                    timeout=30)
            # release activity task 在 workflow FAILED 后才被 worker poll——
            # 测试须在 worker shutdown 前轮询等它跑完
            for _ in range(50):
                if "w-bb-gate" not in gate_mod._gate().candidate_ids():
                    break
                await asyncio.sleep(0.1)
    assert "setup_display" in calls
    assert gate_mod._gate().candidate_ids() == []


@pytest.mark.asyncio
async def test_blackbox_queues_until_slot_released(tmp_path):
    g = gate_mod._gate()
    g.try_acquire("holder", {"kind": "whitebox"})
    calls: list = []
    async with await WorkflowEnvironment.start_local() as env:
        async with Worker(env.client, task_queue="tq-bb-gate",
                          workflows=[BlackboxScanWorkflow],
                          activities=_acts(calls)):
            handle = await env.client.start_workflow(
                BlackboxScanWorkflow.run, _inp(tmp_path),
                id="w-bb-queued", task_queue="tq-bb-gate")
            await asyncio.sleep(0.5)
            assert calls == []                # 排队中未到 setup_display
            g.release("holder")
            with pytest.raises(Exception):
                await asyncio.wait_for(handle.result(), timeout=30)
            for _ in range(50):
                if "w-bb-queued" not in g.candidate_ids():
                    break
                await asyncio.sleep(0.1)
    assert "setup_display" in calls
    assert g.candidate_ids() == []
