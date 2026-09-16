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
    # 隔离真实部署 env：STATE_FILE 指向生产快照时 restore 会混入真实条目
    monkeypatch.delenv("SUPERNOVA_SCAN_GATE_STATE_FILE", raising=False)
    from supernova_worker import runner

    client = MagicMock()
    client.list_workflows = MagicMock(
        return_value=_flist([_W("a"), _W("b")]))
    await runner._gate_bootstrap(client)
    assert set(gate_mod.gate_candidate_ids()) == {"a", "b"}
    # 主查询双过滤：TaskQueue（排 CLI）AND WorkflowType（排 AuthValidation/
    # Topology 等非闸门 workflow——预占它们白吃容量且永不 release）
    q = client.list_workflows.call_args.kwargs.get("query", "")
    assert "TaskQueue" in q and "WorkflowType" in q


@pytest.mark.asyncio
async def test_bootstrap_restores_held_from_state_file(monkeypatch, tmp_path):
    """bootstrap 第一步从 gate_state.json 恢复 held（真实 ws descriptor 存活
    ws cap），visibility 只兜底预占快照外的 RUNNING（2026-09-16 排队者被
    自动放行事故的修复链路）。"""
    import json
    sf = tmp_path / "gate_state.json"
    sf.write_text(json.dumps({
        "capacity": 5, "max_waiting": 10,
        "held": [{"workflow_id": "w0", "kind": "whitebox", "ws": "金融",
                  "scan_id": "s0", "since": 1.0}],
        "waiting": [{"workflow_id": "w3", "kind": "whitebox", "ws": "金融",
                     "scan_id": "s3", "since": 2.0}],
    }, ensure_ascii=False))
    monkeypatch.setenv("SUPERNOVA_SCAN_GATE_CAPACITY", "5")
    monkeypatch.setenv("SUPERNOVA_SCAN_GATE_STATE_FILE", str(sf))
    from supernova_worker import runner

    client = MagicMock()
    client.list_workflows = MagicMock(
        return_value=_flist([_W("w0"), _W("w3"), _W("w9")]))
    await runner._gate_bootstrap(client)
    gate = gate_mod._gate()
    # w0 快照恢复：真实 ws、无 preloaded 标记（幂等放行语义保留给真持有者）
    assert gate.held["w0"].descriptor["ws"] == "金融"
    assert gate.held["w0"].preloaded is False
    # w3/w9 visibility 兜底预占：未知 descriptor + preloaded 标记（首 poll 摘除）
    assert gate.held["w3"].preloaded is True
    assert gate.held["w9"].preloaded is True
    # 快照 waiting 不恢复（排队者轮询自愈）；w3 预占在 held、不在 waiting
    assert "w3" not in gate.waiting


@pytest.mark.asyncio
async def test_bootstrap_state_file_missing_degrades_to_preload(monkeypatch, tmp_path):
    """state file 未设/缺失 → restore 静默跳过，visibility 兜底照常（降级 =
    旧行为 + 首 poll 摘除，不再无条件放行）。"""
    monkeypatch.setenv("SUPERNOVA_SCAN_GATE_CAPACITY", "5")
    monkeypatch.delenv("SUPERNOVA_SCAN_GATE_STATE_FILE", raising=False)
    from supernova_worker import runner

    client = MagicMock()
    client.list_workflows = MagicMock(
        return_value=_flist([_W("x")]))
    await runner._gate_bootstrap(client)  # 不 raise
    assert gate_mod.gate_candidate_ids() == ["x"]


@pytest.mark.asyncio
async def test_bootstrap_falls_back_to_workflow_type_query(monkeypatch):
    """TaskQueue visibility 查询不被支持时退化为 WorkflowType 过滤（spec §6）。"""
    monkeypatch.setenv("SUPERNOVA_SCAN_GATE_CAPACITY", "5")
    monkeypatch.delenv("SUPERNOVA_SCAN_GATE_STATE_FILE", raising=False)
    from supernova_worker import runner

    client = MagicMock()
    client.list_workflows = MagicMock(
        side_effect=[RuntimeError("unsupported attribute: TaskQueue"),
                     _flist([_W("c")])])
    ok = await runner._gate_bootstrap(client)
    assert ok is True
    assert gate_mod.gate_candidate_ids() == ["c"]
    q2 = client.list_workflows.call_args_list[1].kwargs.get("query", "")
    assert "WorkflowType" in q2


@pytest.mark.asyncio
async def test_bootstrap_returns_false_when_both_queries_fail(monkeypatch):
    """回归锁（2026-09-16 复盘）：两级 visibility 查询均失败 → 预占不全 = 带着
    空闸门放行排队者（重启超卖事故的第三口子）。_gate_bootstrap 返回 False，
    由 until_ready 循环挡住 worker 消费——不再 fail-open。"""
    monkeypatch.setenv("SUPERNOVA_SCAN_GATE_CAPACITY", "5")
    monkeypatch.delenv("SUPERNOVA_SCAN_GATE_STATE_FILE", raising=False)
    from supernova_worker import runner

    client = MagicMock()
    client.list_workflows = MagicMock(
        side_effect=RuntimeError("visibility backend down"))
    ok = await runner._gate_bootstrap(client)
    assert ok is False
    assert gate_mod.gate_candidate_ids() == []


@pytest.mark.asyncio
async def test_bootstrap_until_ready_retries_then_starts(monkeypatch):
    """查询失败 → 重试等待（不启动消费），成功后才返回——「bootstrap 失败就
    暂停扫描，不能继续放行」。interval=0 防真等。"""
    monkeypatch.setenv("SUPERNOVA_SCAN_GATE_CAPACITY", "5")
    monkeypatch.delenv("SUPERNOVA_SCAN_GATE_STATE_FILE", raising=False)
    from supernova_worker import runner

    booted = []
    async def fake_bootstrap(_client):
        booted.append(1)
        return len(booted) >= 3  # 前两次失败，第三次成功

    client = MagicMock()
    with patch("supernova_worker.runner._gate_bootstrap",
               side_effect=fake_bootstrap):
        await runner._gate_bootstrap_until_ready(client, interval=0)
    assert len(booted) == 3


@pytest.mark.asyncio
async def test_janitor_once_reaps_dead_workflows(monkeypatch):
    monkeypatch.setenv("SUPERNOVA_SCAN_GATE_CAPACITY", "5")
    from supernova_worker import runner
    from temporalio.client import WorkflowExecutionStatus
    from temporalio.service import RPCError, RPCStatusCode

    gate_mod.preload_gate(["alive", "dead", "ghosted"])
    live_desc = MagicMock()
    live_desc.status = WorkflowExecutionStatus.RUNNING
    finished_desc = MagicMock()
    finished_desc.status = WorkflowExecutionStatus.COMPLETED
    ok_handle = MagicMock()
    ok_handle.describe = AsyncMock(return_value=live_desc)
    # NOT_FOUND = workflow 已终结被回收（确凿死亡）；终态可见（COMPLETED）同摘
    dead_handle = MagicMock()
    dead_handle.describe = AsyncMock(
        side_effect=RPCError("workflow not found", RPCStatusCode.NOT_FOUND, b""))
    ghosted_handle = MagicMock()
    ghosted_handle.describe = AsyncMock(return_value=finished_desc)

    client = MagicMock()
    client.get_workflow_handle = MagicMock(side_effect=lambda wf_id: {
        "alive": ok_handle, "dead": dead_handle, "ghosted": ghosted_handle}[wf_id])
    await runner._gate_janitor_once(client)
    assert gate_mod.gate_candidate_ids() == ["alive"]


@pytest.mark.asyncio
async def test_janitor_once_survives_query_errors_without_reaping(monkeypatch):
    """回归锁（2026-09-16）：describe 网络抖动/服务端错误 ≠ 死亡——误摘会把槽
    放空让排队者超卖获槽（与 bootstrap 抢跑事故同后果的第二口子）。非 NOT_FOUND
    异常一律跳过本轮，条目保留等下轮再校验。"""
    monkeypatch.setenv("SUPERNOVA_SCAN_GATE_CAPACITY", "5")
    from supernova_worker import runner
    from temporalio.service import RPCError, RPCStatusCode

    gate_mod.preload_gate(["flaky", "server_err"])
    timeout_handle = MagicMock()
    timeout_handle.describe = AsyncMock(side_effect=TimeoutError("describe timed out"))
    rpc_err_handle = MagicMock()
    rpc_err_handle.describe = AsyncMock(side_effect=RPCError(
        "unavailable", RPCStatusCode.UNAVAILABLE, b""))

    client = MagicMock()
    client.get_workflow_handle = MagicMock(side_effect=lambda wf_id: {
        "flaky": timeout_handle, "server_err": rpc_err_handle}[wf_id])
    await runner._gate_janitor_once(client)
    assert set(gate_mod.gate_candidate_ids()) == {"flaky", "server_err"}


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
         patch("supernova_worker.runner._gate_bootstrap_until_ready",
               new=AsyncMock()), \
         patch("supernova_worker.runner._gate_janitor", new=AsyncMock()):
        await runner.run_worker("temporal:7233")
    for call in mw.call_args_list:
        acts = call.kwargs["activities"]
        assert gate_mod.scan_gate_try_acquire in acts
        assert gate_mod.scan_gate_release in acts
