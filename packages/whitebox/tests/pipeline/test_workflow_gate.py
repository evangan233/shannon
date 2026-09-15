"""WhiteboxScanWorkflow 闸门段集成测（spec §5）：排队→放行、queue_full、前导顺序。

模式对齐 test_workflow_migration：mock activity 闭包 + 只注册部分 activity，
workflow 在首个未注册的主体 activity 处失败——用失败证明前导（闸门/setup_display）
已执行。gate activity 注册**真实现**（进程级 gate 单例 + env 容量 1）。
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
def _fast_poll(monkeypatch):
    monkeypatch.setattr(gate_mod, "GATE_POLL_SECONDS", 0.05)
    monkeypatch.setenv("SUPERNOVA_SCAN_GATE_CAPACITY", "1")
    monkeypatch.setenv("SUPERNOVA_SCAN_GATE_MAX_WAITING", "1")
    gate_mod.reset_gate_for_tests()
    yield
    gate_mod.reset_gate_for_tests()


def _gate_activities(calls: list) -> list:
    @activity.defn
    async def setup_display(i):
        calls.append("setup_display")

    # gate activity 用真实现（排队的 granted/queue_full 逻辑即被测对象）
    return [gate_mod.scan_gate_try_acquire, gate_mod.scan_gate_release, setup_display]


def _inp(tmp_path, **kw):
    return PipelineInput(
        repo_path=str(tmp_path / "repo"),
        workspace_name="ws-gate",
        event_file=str(tmp_path / "events.ndjson"),
        enable_llm_track=False,
        **kw,
    )


def _failure_chain_text(exc: BaseException) -> str:
    """client 侧 WorkflowFailureError 的 message 是笼统的 'Workflow execution
    failed'——沿 __cause__/__context__ 链收集真实消息（workflow 内 raise 的
    ApplicationError 文案）。"""
    parts, seen, cur = [], set(), exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        parts.append(f"{type(cur).__name__}: {cur}")
        cur = cur.__cause__ or cur.__context__
    return " | ".join(parts)


@pytest.mark.asyncio
async def test_gate_grants_when_capacity_free(tmp_path):
    """空闸门：workflow 直接过闸并到达 setup_display（其后的主体 activity 未注册
    会让 workflow 失败——用失败证明前导已执行，对齐 test_workflow_migration 模式）。"""
    calls: list = []
    async with await WorkflowEnvironment.start_local() as env:
        async with Worker(env.client, task_queue="tq-gate",
                          workflows=[WhiteboxScanWorkflow],
                          activities=_gate_activities(calls)):
            with pytest.raises(Exception):
                await asyncio.wait_for(
                    env.client.execute_workflow(
                        WhiteboxScanWorkflow.run, _inp(tmp_path),
                        id="w-gate-free", task_queue="tq-gate"),
                    timeout=30)
    assert "setup_display" in calls


@pytest.mark.asyncio
async def test_gate_queues_until_slot_released(tmp_path):
    """槽被占：workflow 排队（不完成）；释放后放行到 setup_display。"""
    g = gate_mod._gate()
    g.try_acquire("holder-wf", {"kind": "whitebox"})  # 占住唯一槽
    calls: list = []
    async with await WorkflowEnvironment.start_local() as env:
        async with Worker(env.client, task_queue="tq-gate",
                          workflows=[WhiteboxScanWorkflow],
                          activities=_gate_activities(calls)):
            handle = await env.client.start_workflow(
                WhiteboxScanWorkflow.run, _inp(tmp_path),
                id="w-gate-queued", task_queue="tq-gate")
            await asyncio.sleep(0.5)
            # 仍在排队：轮询多次但未到 setup_display
            assert not any(c == "setup_display" for c in calls)
            g.release("holder-wf")
            with pytest.raises(Exception):  # 放行后死于未注册的主体 activity
                await asyncio.wait_for(handle.result(), timeout=30)
            # release activity task 在 workflow FAILED 后才被 worker poll（生产
            # worker 常驻必然执行）；测试须在 worker shutdown 前轮询等它跑完
            for _ in range(50):
                if "w-gate-queued" not in g.candidate_ids():
                    break
                await asyncio.sleep(0.1)
    assert "setup_display" in calls
    # finally release 尽力执行过
    assert g.candidate_ids() == []


@pytest.mark.asyncio
async def test_gate_descriptor_carries_ws_cap(tmp_path):
    """ws 并发上限随 descriptor 进闸门：env_overrides 的
    SUPERNOVA_WS_SCAN_CONCURRENCY 解析为 int 塞进 descriptor（闸门双维判定的
    输入；闸门段先于 setup_display 的 set_scan_env，ws_getenv 层不可用）。"""
    g = gate_mod._gate()
    captured: list = []
    calls: list = []

    @activity.defn
    async def setup_display(i):
        calls.append("setup_display")
        captured.append(dict(g.held["w-gate-cap"].descriptor))

    async with await WorkflowEnvironment.start_local() as env:
        async with Worker(env.client, task_queue="tq-gate",
                          workflows=[WhiteboxScanWorkflow],
                          activities=[gate_mod.scan_gate_try_acquire,
                                      gate_mod.scan_gate_release, setup_display]):
            with pytest.raises(Exception):  # 死于未注册的主体 activity
                await asyncio.wait_for(
                    env.client.execute_workflow(
                        WhiteboxScanWorkflow.run,
                        _inp(tmp_path, env_overrides={
                            "SUPERNOVA_WS_SCAN_CONCURRENCY": "2"}),
                        id="w-gate-cap", task_queue="tq-gate"),
                    timeout=30)
            for _ in range(50):
                if "w-gate-cap" not in g.candidate_ids():
                    break
                await asyncio.sleep(0.1)
    assert "setup_display" in calls
    assert captured and captured[0]["ws_cap"] == 2


@pytest.mark.asyncio
async def test_gate_descriptor_omits_ws_cap_when_unset(tmp_path):
    """未配置的 ws 不带 ws_cap 键（快照/面板据键存在性区分「配置了上限」）。"""
    g = gate_mod._gate()
    captured: list = []
    calls: list = []

    @activity.defn
    async def setup_display(i):
        calls.append("setup_display")
        captured.append(dict(g.held["w-gate-nocap"].descriptor))

    async with await WorkflowEnvironment.start_local() as env:
        async with Worker(env.client, task_queue="tq-gate",
                          workflows=[WhiteboxScanWorkflow],
                          activities=[gate_mod.scan_gate_try_acquire,
                                      gate_mod.scan_gate_release, setup_display]):
            with pytest.raises(Exception):
                await asyncio.wait_for(
                    env.client.execute_workflow(
                        WhiteboxScanWorkflow.run,
                        _inp(tmp_path, env_overrides={"SUPERNOVA_LLM_TRACK_ENABLED": "1"}),
                        id="w-gate-nocap", task_queue="tq-gate"),
                    timeout=30)
            for _ in range(50):
                if "w-gate-nocap" not in g.candidate_ids():
                    break
                await asyncio.sleep(0.1)
    assert "setup_display" in calls
    assert captured and "ws_cap" not in captured[0]


@pytest.mark.asyncio
async def test_gate_queue_full_fails_workflow(tmp_path):
    g = gate_mod._gate()
    g.preload(["holder-1"])            # capacity=1 占满
    g.try_acquire("waiter-1", {})      # max_waiting=1 占满
    calls: list = []
    async with await WorkflowEnvironment.start_local() as env:
        async with Worker(env.client, task_queue="tq-gate",
                          workflows=[WhiteboxScanWorkflow],
                          activities=_gate_activities(calls)):
            with pytest.raises(Exception) as ei:
                await asyncio.wait_for(
                    env.client.execute_workflow(
                        WhiteboxScanWorkflow.run, _inp(tmp_path),
                        id="w-gate-full", task_queue="tq-gate"),
                    timeout=30)
            assert "排队已满" in _failure_chain_text(ei.value)
    assert "setup_display" not in calls
