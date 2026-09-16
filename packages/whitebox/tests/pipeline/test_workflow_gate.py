"""WhiteboxScanWorkflow 闸门段集成测（spec §5）：排队→放行、queue_full、前导顺序。

模式对齐 test_workflow_migration：mock activity 闭包 + 只注册部分 activity，
workflow 在首个未注册的主体 activity 处失败——用失败证明前导（闸门/setup_display）
已执行。gate activity 注册**真实现**（进程级 gate 单例 + env 容量 1）。

2026-09-16 增补：排队不限时 + continue-as-new（spec
2026-09-16-scan-budget-queue-unlimited）——长 stint 重开 run 防事件历史膨胀，
获槽重启让预算从获槽起算；CAN 机制本身在共享 scan_gate.acquire_gate_slot，
whitebox 侧覆盖完整链路，blackbox/multi 只测各自 call-site 签名。
"""

import asyncio
from datetime import timedelta

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


@pytest.mark.asyncio
async def test_gate_long_queue_continue_as_new_keeps_fifo(tmp_path, monkeypatch):
    """排队不限时 + continue-as-new：stint 超阈值重开 run（run_id 更替、事件
    历史清零防 50k 上限），workflow_id 不变 → waiting 条目 first_seen 保留
    （FIFO 不丢）；释放后经获槽重启（held 幂等路径）照常放行到 setup_display。"""
    monkeypatch.setattr(gate_mod, "GATE_CONTINUE_AFTER", timedelta(seconds=0.3))
    g = gate_mod._gate()
    g.try_acquire("holder-wf", {"kind": "whitebox"})  # 占住唯一槽
    calls: list = []
    async with await WorkflowEnvironment.start_local() as env:
        async with Worker(env.client, task_queue="tq-gate",
                          workflows=[WhiteboxScanWorkflow],
                          activities=_gate_activities(calls)):
            handle = await env.client.start_workflow(
                WhiteboxScanWorkflow.run, _inp(tmp_path),
                id="w-gate-can", task_queue="tq-gate")
            first_run_id = handle.first_execution_run_id
            # 等排队入列，锚定 FIFO 位置（first_seen）
            for _ in range(50):
                if "w-gate-can" in g.waiting:
                    break
                await asyncio.sleep(0.1)
            first_seen = g.waiting["w-gate-can"].first_seen
            # 等 CAN 发生：describe 的 run_id 更替
            changed = False
            for _ in range(100):
                desc = await env.client.get_workflow_handle(
                    "w-gate-can").describe()
                if desc.run_id != first_run_id:
                    changed = True
                    break
                await asyncio.sleep(0.1)
            assert changed, "排队 stint 超阈值未发生 continue-as-new"
            # 仍在排队且 FIFO 位置保持（未误摘/未重排）
            assert "w-gate-can" in g.waiting
            assert g.waiting["w-gate-can"].first_seen == first_seen
            g.release("holder-wf")
            with pytest.raises(Exception):  # 放行后死于未注册的主体 activity
                await asyncio.wait_for(handle.result(), timeout=30)
            for _ in range(50):
                if "w-gate-can" not in g.candidate_ids():
                    break
                await asyncio.sleep(0.1)
    assert "setup_display" in calls
    assert g.candidate_ids() == []


@pytest.mark.asyncio
async def test_gate_grant_without_queue_skips_continue_as_new(tmp_path):
    """免排队快路径：stint==0 直接获槽原地进扫描，不发生 continue-as-new
    （run_id 不变——扫描预算即提交时设定的满额）。"""
    g = gate_mod._gate()
    calls: list = []
    async with await WorkflowEnvironment.start_local() as env:
        async with Worker(env.client, task_queue="tq-gate",
                          workflows=[WhiteboxScanWorkflow],
                          activities=_gate_activities(calls)):
            handle = await env.client.start_workflow(
                WhiteboxScanWorkflow.run, _inp(tmp_path),
                id="w-gate-fast", task_queue="tq-gate")
            first_run_id = handle.first_execution_run_id
            with pytest.raises(Exception):  # 死于未注册的主体 activity
                await asyncio.wait_for(handle.result(), timeout=30)
            desc = await env.client.get_workflow_handle("w-gate-fast").describe()
            assert desc.run_id == first_run_id  # 无 continue-as-new
    assert "setup_display" in calls


@pytest.mark.asyncio
async def test_gate_poll_timeout_tolerated(tmp_path, monkeypatch):
    """轮询超时容忍（排队不限时的最后一种死法封堵）：worker 过载时 poll activity
    撞 start-to-close 超时——2026-09-16 事故 cloud_sync_svr 排队 47min 死于此。
    注入方式：acquire_gate_slot 硬编码调真 activity scan_gate_try_acquire，无法换
    假实现——改把 _ACTIVITY_TIMEOUT 压到 1µs（首轮必超时），0.5s 后定时恢复 30s
    （此时轮询放行）。超时轮视同未获槽重试 → setup_display 出现即容忍生效；若
    不容忍，workflow 死在首轮 TimeoutError，setup_display 永不出现（判别面）。"""
    monkeypatch.setattr(gate_mod, "_ACTIVITY_TIMEOUT", timedelta(microseconds=1))
    asyncio.get_running_loop().call_later(
        0.5, lambda: setattr(gate_mod, "_ACTIVITY_TIMEOUT", timedelta(seconds=30)))
    calls: list = []
    async with await WorkflowEnvironment.start_local() as env:
        async with Worker(env.client, task_queue="tq-gate",
                          workflows=[WhiteboxScanWorkflow],
                          activities=_gate_activities(calls)):
            with pytest.raises(Exception):  # 放行后死于未注册的主体 activity
                await asyncio.wait_for(
                    env.client.execute_workflow(
                        WhiteboxScanWorkflow.run, _inp(tmp_path),
                        id="w-gate-ttl", task_queue="tq-gate"),
                    timeout=60)
    assert "setup_display" in calls
