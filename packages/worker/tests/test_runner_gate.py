"""runner 闸门挂载测试：bootstrap 预占两分支、janitor 单轮回收、三 worker 注册。"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from supernova_core.services import scan_gate as gate_mod


@pytest.fixture(autouse=True)
def _clean_gate():
    gate_mod.reset_gate_for_tests()
    yield
    gate_mod.reset_gate_for_tests()


def _flist(items):
    """mock list_workflows 的 async-iterable 返回值。"""
    async def gen():
        for it in items:
            yield it
    return gen()


class _W:  # 轻量 workflow handle 摘要
    def __init__(self, id):
        self.id = id


@pytest.mark.asyncio
async def test_bootstrap_preloads_running_scan_workflows(monkeypatch):
    monkeypatch.setenv("SUPERNOVA_SCAN_GATE_CAPACITY", "5")
    from supernova_worker import runner

    client = MagicMock()
    client.list_workflows = MagicMock(
        return_value=_flist([_W("a"), _W("b")]))
    await runner._gate_bootstrap(client)
    assert set(gate_mod.gate_candidate_ids()) == {"a", "b"}


@pytest.mark.asyncio
async def test_bootstrap_falls_back_to_workflow_type_query(monkeypatch):
    """TaskQueue visibility 查询不被支持时退化为 WorkflowType 过滤（spec §6）。"""
    monkeypatch.setenv("SUPERNOVA_SCAN_GATE_CAPACITY", "5")
    from supernova_worker import runner

    client = MagicMock()
    client.list_workflows = MagicMock(
        side_effect=[RuntimeError("unsupported attribute: TaskQueue"),
                     _flist([_W("c")])])
    await runner._gate_bootstrap(client)
    assert gate_mod.gate_candidate_ids() == ["c"]
    q2 = client.list_workflows.call_args_list[1].kwargs.get("query", "")
    assert "WorkflowType" in q2


@pytest.mark.asyncio
async def test_janitor_once_reaps_dead_workflows(monkeypatch):
    monkeypatch.setenv("SUPERNOVA_SCAN_GATE_CAPACITY", "5")
    from supernova_worker import runner
    from temporalio.client import WorkflowExecutionStatus

    gate_mod.preload_gate(["alive", "dead"])
    live_desc = MagicMock()
    live_desc.status = WorkflowExecutionStatus.RUNNING
    ok_handle = MagicMock()
    ok_handle.describe = AsyncMock(return_value=live_desc)
    dead_handle = MagicMock()
    dead_handle.describe = AsyncMock(side_effect=RuntimeError("not found"))

    client = MagicMock()
    client.get_workflow_handle = MagicMock(
        side_effect=lambda wf_id: {"alive": ok_handle, "dead": dead_handle}[wf_id])
    await runner._gate_janitor_once(client)
    assert gate_mod.gate_candidate_ids() == ["alive"]


@pytest.mark.asyncio
async def test_run_worker_registers_gate_activities_on_all_three_workers():
    """守护：漏注册 gate activity = 排队 workflow 的 activity 无处执行直接超时。"""
    from unittest.mock import AsyncMock, MagicMock, patch
    from supernova_worker import runner

    wb = MagicMock(); wb.run = AsyncMock(return_value=None)
    bb = MagicMock(); bb.run = AsyncMock(return_value=None)
    corr = MagicMock(); corr.run = AsyncMock(return_value=None)
    with patch("supernova_worker.runner.Client.connect",
               AsyncMock(return_value=MagicMock())), \
         patch("supernova_worker.runner.Worker",
               side_effect=[wb, bb, corr]) as mw, \
         patch("supernova_worker.runner._gate_bootstrap", new=AsyncMock()), \
         patch("supernova_worker.runner._gate_janitor", new=AsyncMock()):
        await runner.run_worker("temporal:7233")
    for call in mw.call_args_list:
        acts = call.kwargs["activities"]
        assert gate_mod.scan_gate_try_acquire in acts
        assert gate_mod.scan_gate_release in acts
