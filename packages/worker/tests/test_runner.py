"""run_worker：连接 temporal，起三个常驻 Worker（白盒/黑盒/跨仓关联固定 queue），注册对应 workflow+activities。"""
import os
from unittest.mock import ANY, AsyncMock, MagicMock, call, patch

import pytest

from supernova_core.services.temporal_infra import (
    WEB_TASK_QUEUE_WHITEBOX,
    WEB_TASK_QUEUE_BLACKBOX,
    WEB_TASK_QUEUE_CORRELATION,
)
from supernova_whitebox.pipeline.workflows import WhiteboxScanWorkflow
from supernova_blackbox.pipeline.workflows import BlackboxScanWorkflow
from supernova_multi.pipeline.workflows import CorrelationScanWorkflow


@pytest.fixture(autouse=True)
def _skip_gate_bootstrap(monkeypatch):
    """闸门 bootstrap 重试循环与本文件断言无关：mock client 的 visibility 查询
    必失败，而 2026-09-16 起 bootstrap 失败语义从 fail-open 改为重试等待
    （预占不全不放行）——不跳过会让 _gate_bootstrap_until_ready 死循环重试
    挂住测试。connect 失败用例不受影响（在 bootstrap 前已抛）。"""
    monkeypatch.setattr("supernova_worker.runner._gate_bootstrap_until_ready",
                        AsyncMock())


@pytest.mark.asyncio
async def test_run_worker_connects_and_registers_three_workers(monkeypatch):
    """run_worker 连 temporal + 起三个 Worker（白盒/黑盒/跨仓关联固定 queue）+ 并行 run。"""
    from supernova_worker.runner import run_worker

    monkeypatch.delenv("SUPERNOVA_WORKER_MAX_CONCURRENT_WF", raising=False)
    mock_client = AsyncMock()

    wb_worker = MagicMock()
    wb_worker.run = AsyncMock(return_value=None)
    bb_worker = MagicMock()
    bb_worker.run = AsyncMock(return_value=None)
    corr_worker = MagicMock()
    corr_worker.run = AsyncMock(return_value=None)

    with (
        patch("supernova_worker.runner.Client.connect",
              AsyncMock(return_value=mock_client)) as mock_connect,
        patch("supernova_worker.runner.Worker",
              side_effect=[wb_worker, bb_worker, corr_worker]) as mock_worker_cls,
    ):
        await run_worker("temporal:7233")

    # 连接 temporal
    mock_connect.assert_awaited_once_with("temporal:7233")

    # 三个 Worker 创建，task_queue + workflows 正确
    assert mock_worker_cls.call_count == 3
    wb_call, bb_call, corr_call = mock_worker_cls.call_args_list
    assert wb_call.kwargs["client"] is mock_client
    assert wb_call.kwargs["task_queue"] == WEB_TASK_QUEUE_WHITEBOX
    assert WhiteboxScanWorkflow in wb_call.kwargs["workflows"]
    assert len(wb_call.kwargs["activities"]) >= 20  # 白盒 ~25 activities
    assert bb_call.kwargs["client"] is mock_client
    assert bb_call.kwargs["task_queue"] == WEB_TASK_QUEUE_BLACKBOX
    assert BlackboxScanWorkflow in bb_call.kwargs["workflows"]
    assert len(bb_call.kwargs["activities"]) >= 10  # 黑盒 ~16 activities
    assert corr_call.kwargs["client"] is mock_client
    assert corr_call.kwargs["task_queue"] == WEB_TASK_QUEUE_CORRELATION
    assert CorrelationScanWorkflow in corr_call.kwargs["workflows"]
    assert len(corr_call.kwargs["activities"]) >= 1  # 跨仓关联 run_correlation_activity

    # P3c 阶段 3：contextvar 化（AuditSession/LogBus/heartbeat 按 workflow_id 隔离）后
    # 并发不再串台。max_concurrent 读 SUPERNOVA_WORKER_MAX_CONCURRENT_WF（默认 4）。
    assert bb_call.kwargs["max_concurrent_workflow_tasks"] == 4

    # 三个 worker 都 run（并行 gather）
    wb_worker.run.assert_awaited_once()
    bb_worker.run.assert_awaited_once()
    corr_worker.run.assert_awaited_once()


@pytest.mark.asyncio
async def test_run_worker_registers_all_defined_activities(monkeypatch):
    """护栏：wb/bb 常驻 Worker 必须注册 activities 模块里所有 @activity.defn。

    根因(2026-08-05 NodeGoat 黑盒 scan failed)：spec 2026-08-03 新增 run_endpoint_verify
    时只同步了 CLI blackbox/worker.py，漏改 Web 常驻 runner.py → 网页发起的黑盒扫描
    exploitation 阶段调 run_endpoint_verify 时 temporalio NotFoundError → 整条 workflow
    FAILED。既有的 ``len(activities) >= N`` 弱数量断言拦不住单点漏注(17 vs 18 都 ≥10)，
    改精确集合比对。注册的是真实函数对象，读 __name__ 即 defn 名(bb_assemble_report 等
    import 别名自动解析回 assemble_report——@activity.defn 无显式 name=，defn 名 == 函数名)。
    一次覆盖 wb+bb+corr 三 Worker，顺带防 whitebox 侧同类漏注。
    """
    from pathlib import Path
    from supernova_worker.runner import run_worker
    from supernova_whitebox.pipeline import activities as wb_activities
    from supernova_blackbox.pipeline import activities as bb_activities
    from supernova_core.testing.activity_registration import _activity_def_names

    monkeypatch.delenv("SUPERNOVA_WORKER_MAX_CONCURRENT_WF", raising=False)
    mock_client = AsyncMock()
    wb_worker = MagicMock()
    wb_worker.run = AsyncMock(return_value=None)
    bb_worker = MagicMock()
    bb_worker.run = AsyncMock(return_value=None)
    corr_worker = MagicMock()
    corr_worker.run = AsyncMock(return_value=None)

    with (
        patch("supernova_worker.runner.Client.connect",
              AsyncMock(return_value=mock_client)),
        patch("supernova_worker.runner.Worker",
              side_effect=[wb_worker, bb_worker, corr_worker]) as mock_worker_cls,
    ):
        await run_worker("temporal:7233")

    wb_call, bb_call, corr_call = mock_worker_cls.call_args_list
    wb_registered = {getattr(f, "__name__", f) for f in wb_call.kwargs["activities"]}
    bb_registered = {getattr(f, "__name__", f) for f in bb_call.kwargs["activities"]}
    corr_registered = {getattr(f, "__name__", f) for f in corr_call.kwargs["activities"]}

    wb_expected = _activity_def_names(
        Path(wb_activities.__file__).read_text(encoding="utf-8"))
    # MR 增量前置 activities 定义在独立模块 mr_activities（spec 2026-09-03），注册
    # wb 队列——预存漏扫（模块拆分后本测试未跟上，extra=MR 5 名恒红）。
    from supernova_whitebox.pipeline import mr_activities
    wb_expected |= _activity_def_names(
        Path(mr_activities.__file__).read_text(encoding="utf-8"))
    bb_expected = _activity_def_names(
        Path(bb_activities.__file__).read_text(encoding="utf-8"))
    # corr 的 @activity.defn 定义在 multi pipeline workflows 模块（单 activity 直通）。
    from supernova_multi.pipeline import workflows as corr_workflows
    multi_defined = _activity_def_names(
        Path(corr_workflows.__file__).read_text(encoding="utf-8"))
    # 预分析 activity 定义在 multi workflows 但注册 bb 队列（spec 2026-09-03 拓扑
    # 预分析迁 worker：bb = 交互式轻任务的家；corr 队列跑小时级扫描会饿死预分析）。
    topology_activity = {"run_topology_analysis_activity"}
    bb_expected |= topology_activity
    corr_expected = multi_defined - topology_activity
    # 全局扫描闸门（spec 2026-09-08-worker-scan-gate §4.1）：定义在 core scan_gate
    # 模块（不在上面扫的 wb/bb/multi 源文件里），三 Worker 都要注册（跨 queue 过闸）。
    gate_activities = {"scan_gate_try_acquire", "scan_gate_release"}
    wb_expected |= gate_activities
    bb_expected |= gate_activities
    corr_expected |= gate_activities

    assert wb_registered == wb_expected, (
        f"whitebox worker 注册不一致：missing={sorted(wb_expected - wb_registered)}, "
        f"extra={sorted(wb_registered - wb_expected)}")
    assert bb_registered == bb_expected, (
        f"blackbox worker 注册不一致：missing={sorted(bb_expected - bb_registered)}, "
        f"extra={sorted(bb_registered - bb_expected)}")
    assert corr_registered == corr_expected, (
        f"correlation worker 注册不一致：missing={sorted(corr_expected - corr_registered)}, "
        f"extra={sorted(corr_registered - corr_expected)}")


@pytest.mark.asyncio
async def test_run_worker_activity_names_unique(monkeypatch):
    """护栏：同一 Worker 的 activities 列表内名字必须唯一。

    根因(2026-08-28 NodeGoat-20260828-142253「刚开就中断」)：1bd18a44 与 3e99fff1
    两个提交先后在 bb_worker 注册 bb_persist_completed_agents（同一取消事故的两次
    follow-up，后者未察觉前者已加）→ temporalio Worker.__init__ 校验 defn 名唯一，
    "More than one activity named persist_completed_agents" → worker 容器 crash
    loop，task queue 无消费者，网页发起的扫描 session 落盘后零事件僵死。
    既有 registers_all_defined_activities 用 set 收集注册名（去重后比对），重复
    注册不可见 → 补显式唯一性断言（对齐 temporalio _ActivityWorker 的构造校验）。
    """
    from supernova_worker.runner import run_worker

    monkeypatch.delenv("SUPERNOVA_WORKER_MAX_CONCURRENT_WF", raising=False)
    mock_client = AsyncMock()
    wb_worker, bb_worker, corr_worker = MagicMock(), MagicMock(), MagicMock()
    wb_worker.run = AsyncMock(return_value=None)
    bb_worker.run = AsyncMock(return_value=None)
    corr_worker.run = AsyncMock(return_value=None)

    with (
        patch("supernova_worker.runner.Client.connect",
              AsyncMock(return_value=mock_client)),
        patch("supernova_worker.runner.Worker",
              side_effect=[wb_worker, bb_worker, corr_worker]) as mock_worker_cls,
    ):
        await run_worker("temporal:7233")

    wb_call, bb_call, corr_call = mock_worker_cls.call_args_list
    for label, wk_call in (("whitebox", wb_call), ("blackbox", bb_call),
                           ("correlation", corr_call)):
        names = [getattr(f, "__name__", f) for f in wk_call.kwargs["activities"]]
        dups = sorted({n for n in names if names.count(n) > 1})
        assert not dups, f"{label} worker 重复注册 activity：{dups}"


@pytest.mark.asyncio
async def test_run_worker_propagates_connect_failure():
    """temporal 连不上时 run_worker 抛错（fail-fast，不静默吞）。"""
    from supernova_worker.runner import run_worker

    with patch("supernova_worker.runner.Client.connect",
               AsyncMock(side_effect=RuntimeError("temporal down"))):
        with pytest.raises(RuntimeError, match="temporal down"):
            await run_worker("bad:7233")


@pytest.mark.asyncio
async def test_run_worker_whitebox_concurrent_and_migration_activities(monkeypatch):
    """白盒 Worker: 注册 setup_display/finalize_summary（display 生命周期 activity）。

    P3c 阶段 3：contextvar 化后 max_concurrent 放开（默认 4）。run_heartbeat 非注册
    activity（heartbeat 由 setup_display 内 HeartbeatManager 启动），旧断言过时已删。
    """
    from supernova_worker.runner import run_worker

    monkeypatch.delenv("SUPERNOVA_WORKER_MAX_CONCURRENT_WF", raising=False)
    mock_client = AsyncMock()
    wb_worker = MagicMock()
    wb_worker.run = AsyncMock()
    bb_worker = MagicMock()
    bb_worker.run = AsyncMock()
    corr_worker = MagicMock()
    corr_worker.run = AsyncMock()

    with patch("supernova_worker.runner.Client.connect",
               AsyncMock(return_value=mock_client)), \
         patch("supernova_worker.runner.Worker",
               side_effect=[wb_worker, bb_worker, corr_worker]) as mw:
        await run_worker("temporal:7233")

    wb_call = mw.call_args_list[0]
    assert wb_call.kwargs["max_concurrent_workflow_tasks"] == 4, \
        "白盒 Worker 并发默认 4(contextvar 化后放开)"
    activity_names = {getattr(a, "__name__", a) for a in wb_call.kwargs["activities"]}
    assert "setup_display" in activity_names, "白盒 Worker 须注册 setup_display"
    assert "finalize_summary" in activity_names, "白盒 Worker 须注册 finalize_summary"
    # auth GitNexus 轨已删(plan zazzy-roaming-shamir, 2026-07-14):
    # run_auth_config_scan/run_auth_gitnexus_judge 不再存在, 不注册.


@pytest.mark.asyncio
async def test_worker_max_concurrent_reads_env(monkeypatch):
    """max_concurrent_workflow_tasks 读 SUPERNOVA_WORKER_MAX_CONCURRENT_WF（默认 4，env 可配）。"""
    from supernova_worker.runner import run_worker

    monkeypatch.setenv("SUPERNOVA_WORKER_MAX_CONCURRENT_WF", "8")
    mock_client = AsyncMock()
    wb_worker = MagicMock()
    wb_worker.run = AsyncMock()
    bb_worker = MagicMock()
    bb_worker.run = AsyncMock()
    corr_worker = MagicMock()
    corr_worker.run = AsyncMock()
    with patch("supernova_worker.runner.Client.connect",
               AsyncMock(return_value=mock_client)), \
         patch("supernova_worker.runner.Worker",
               side_effect=[wb_worker, bb_worker, corr_worker]) as mw:
        await run_worker("temporal:7233")
    assert mw.call_args_list[0].kwargs["max_concurrent_workflow_tasks"] == 8
    assert mw.call_args_list[1].kwargs["max_concurrent_workflow_tasks"] == 8
    assert mw.call_args_list[2].kwargs["max_concurrent_workflow_tasks"] == 8


def test_main_loads_profile_env_before_starting_worker():
    """main() 启动时先 load_env()——锁住「worker 入口必须加载 profile 凭证」不变量。

    根因(2026-07-15 真机 trip_1784107863): worker runner.main() 漏调 load_env(),
    profile 的 SUPERNOVA_AI_PROVIDER / SUPERNOVA_OPENAI_* 不进进程环境 → 引擎回落
    anthropic_api(claude CLI)→ deepseek-openai profile 无 ANTHROPIC 凭证 →
    claude CLI 子进程 "Not logged in · Please run /login" → pre-recon 失败 →
    扫描卡死、WEB 各页全空。对齐 CLI 入口(whitebox/blackbox/combined main.py
    均首行 load_env())。
    """
    from supernova_worker import runner

    # 同一 parent Mock 记录调用顺序，验证 load_env 先于 asyncio.run。
    # patch run_worker 避免真起 temporal 连接 + 不留未 await coroutine。
    parent = MagicMock()
    with patch.object(runner, "load_env", parent.load_env), \
         patch.object(runner, "asyncio", parent.asyncio), \
         patch.object(runner, "run_worker", return_value="worker-coroutine"), \
         patch.dict(os.environ, {"SUPERNOVA_TEMPORAL_HOST": "th", "SUPERNOVA_TEMPORAL_PORT": "tp"}):
        runner.main()

    # load_env 必须在起 worker 之前调用（profile 凭证先于 provider 配置加载）
    parent.assert_has_calls([call.load_env(), call.asyncio.run(ANY)])
    parent.load_env.assert_called_once()
    parent.asyncio.run.assert_called_once()


# ── 协作式取消桥（2026-08-28 取消失效治本，方案 B）──────────────────────────
# 根因：web cancel ② 轨写 cancel.requested，但 worker 容器路径的 activity
# start_heartbeat(on_cancel=None) 不消费协作信号（只有 CLI 路径 HeartbeatManager
# 挂 ctrl._trigger_graceful）——owner=web 扫描的协作通道整个不存在。本桥把文件
# 信号转回 temporal cancel，复用 temporalio 对 async activity 的 task.cancel 传导。

@pytest.mark.asyncio
async def test_cancel_bridge_cancels_workflow_on_signal(tmp_path, monkeypatch):
    """cancel.requested 存在 → 删信号文件 + 对注册表里的 wf_id 发 temporal cancel。"""
    from supernova_worker import runner

    ws_dir = tmp_path / "scan-1"
    ws_dir.mkdir()
    (ws_dir / "cancel.requested").write_text("")

    def _snapshot():
        return {"WS-scan-1": ws_dir}
    monkeypatch.setattr(runner, "snapshot_heartbeat_workflows", _snapshot)

    get_handle = AsyncMock()
    mock_client = AsyncMock()
    mock_client.get_workflow_handle = MagicMock(return_value=get_handle)

    await runner._process_cancel_signals(mock_client)

    mock_client.get_workflow_handle.assert_called_once_with("WS-scan-1")
    get_handle.cancel.assert_awaited_once()
    assert not (ws_dir / "cancel.requested").exists()  # 删后不重复触发


@pytest.mark.asyncio
async def test_cancel_bridge_ignores_absent_signal(tmp_path, monkeypatch):
    """无信号文件 → 不发 cancel（活跃 scan 不误伤）。"""
    from supernova_worker import runner

    ws_dir = tmp_path / "scan-1"
    ws_dir.mkdir()

    def _snapshot():
        return {"WS-scan-1": ws_dir}
    monkeypatch.setattr(runner, "snapshot_heartbeat_workflows", _snapshot)

    mock_client = AsyncMock()

    await runner._process_cancel_signals(mock_client)

    mock_client.get_workflow_handle.assert_not_called()


@pytest.mark.asyncio
async def test_cancel_bridge_survives_cancel_error(tmp_path, monkeypatch):
    """handle.cancel 抛（workflow 不存在/已终态/temporal 抖动）→ 不炸、信号仍删
    （防下一轮重复触发对已终态 workflow 空转）。"""
    from supernova_worker import runner

    ws_dir = tmp_path / "scan-1"
    ws_dir.mkdir()
    (ws_dir / "cancel.requested").write_text("")

    def _snapshot():
        return {"WS-scan-1": ws_dir}
    monkeypatch.setattr(runner, "snapshot_heartbeat_workflows", _snapshot)

    get_handle = AsyncMock()
    get_handle.cancel = AsyncMock(side_effect=RuntimeError("already terminated"))
    mock_client = AsyncMock()
    mock_client.get_workflow_handle = MagicMock(return_value=get_handle)

    await runner._process_cancel_signals(mock_client)  # 不抛

    assert not (ws_dir / "cancel.requested").exists()


@pytest.mark.asyncio
async def test_run_worker_starts_cancel_bridge(monkeypatch):
    """run_worker 起协作取消桥后台 task（与三 Worker 并行；worker 退出时桥一并取消）。"""
    from supernova_worker import runner

    monkeypatch.delenv("SUPERNOVA_WORKER_MAX_CONCURRENT_WF", raising=False)
    mock_client = AsyncMock()
    wb_worker, bb_worker, corr_worker = MagicMock(), MagicMock(), MagicMock()
    wb_worker.run = AsyncMock()
    bb_worker.run = AsyncMock()
    corr_worker.run = AsyncMock()

    with patch("supernova_worker.runner.Client.connect",
               AsyncMock(return_value=mock_client)), \
         patch("supernova_worker.runner.Worker",
               side_effect=[wb_worker, bb_worker, corr_worker]), \
         patch.object(runner, "_cancel_signal_bridge", new=AsyncMock()) as bridge_mock:
        await runner.run_worker("temporal:7233")

    bridge_mock.assert_called_once()
