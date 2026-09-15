"""CorrelationScanWorkflow 闸门段集成测（spec §5）：关联阶段占 1 槽、排队、释放。"""

import asyncio

import pytest
from temporalio import activity
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from supernova_core.services import scan_gate as gate_mod
from supernova_multi.pipeline.workflows import CorrelationScanWorkflow
from supernova_multi.pipeline.shared import CorrelationPipelineInput


@pytest.fixture(autouse=True)
def _gate_env(monkeypatch):
    monkeypatch.setattr(gate_mod, "GATE_POLL_SECONDS", 0.05)
    monkeypatch.setenv("SUPERNOVA_SCAN_GATE_CAPACITY", "1")
    gate_mod.reset_gate_for_tests()
    yield
    gate_mod.reset_gate_for_tests()


def _inp(tmp_path, **kw):
    return CorrelationPipelineInput(
        config_path=str(tmp_path / "config.yaml"),
        repo_workspace_paths={"checkout": str(tmp_path / "ws" / "checkout"),
                              "payment": str(tmp_path / "ws" / "payment")},
        out_ws_dir=str(tmp_path / "ws" / "scans" / "corr-main"),
        event_file=str(tmp_path / "ws" / "scans" / "corr-main" / "events.ndjson"),
        **kw,
    )


@pytest.mark.asyncio
async def test_correlation_passes_gate_and_runs(tmp_path):
    done: list = []

    @activity.defn
    async def run_correlation_activity(inp):
        done.append(True)
        return {"status": "completed"}

    async with await WorkflowEnvironment.start_local() as env:
        async with Worker(env.client, task_queue="tq-corr-gate",
                          workflows=[CorrelationScanWorkflow],
                          activities=[gate_mod.scan_gate_try_acquire,
                                      gate_mod.scan_gate_release,
                                      run_correlation_activity]):
            r = await asyncio.wait_for(
                env.client.execute_workflow(
                    CorrelationScanWorkflow.run, _inp(tmp_path),
                    id="w-corr-gate", task_queue="tq-corr-gate"),
                timeout=30)
    assert done == [True]
    assert gate_mod._gate().candidate_ids() == []  # finally release 已清


@pytest.mark.asyncio
async def test_correlation_gate_descriptor_carries_ws_cap(tmp_path):
    """ws 并发上限随 descriptor 进闸门（对齐 whitebox/blackbox 同名测试；关联
    阶段的 ws 从 event_file 反推，cap 照样归属主 ws——跨仓子仓同理各占一槽
    全算主 ws 持有）。"""
    g = gate_mod._gate()
    captured: list = []

    @activity.defn
    async def run_correlation_activity(inp):
        captured.append(dict(g.held["w-corr-cap"].descriptor))
        return {"status": "completed"}

    async with await WorkflowEnvironment.start_local() as env:
        async with Worker(env.client, task_queue="tq-corr-gate",
                          workflows=[CorrelationScanWorkflow],
                          activities=[gate_mod.scan_gate_try_acquire,
                                      gate_mod.scan_gate_release,
                                      run_correlation_activity]):
            await asyncio.wait_for(
                env.client.execute_workflow(
                    CorrelationScanWorkflow.run,
                    _inp(tmp_path, env_overrides={
                        "SUPERNOVA_WS_SCAN_CONCURRENCY": "2"}),
                    id="w-corr-cap", task_queue="tq-corr-gate"),
                timeout=30)
    assert captured and captured[0]["ws_cap"] == 2


@pytest.mark.asyncio
async def test_correlation_queues_until_slot_released(tmp_path):
    g = gate_mod._gate()
    g.try_acquire("holder", {"kind": "whitebox"})
    done: list = []

    @activity.defn
    async def run_correlation_activity(inp):
        done.append(True)
        return {"status": "completed"}

    async with await WorkflowEnvironment.start_local() as env:
        async with Worker(env.client, task_queue="tq-corr-gate",
                          workflows=[CorrelationScanWorkflow],
                          activities=[gate_mod.scan_gate_try_acquire,
                                      gate_mod.scan_gate_release,
                                      run_correlation_activity]):
            handle = await env.client.start_workflow(
                CorrelationScanWorkflow.run, _inp(tmp_path),
                id="w-corr-queued", task_queue="tq-corr-gate")
            await asyncio.sleep(0.5)
            assert done == []                    # 仍在排队
            g.release("holder")
            await asyncio.wait_for(handle.result(), timeout=30)
    assert done == [True]
