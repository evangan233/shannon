"""T6: _add_blackbox_run — 给已有白盒任务加一个嵌套黑盒 run（spec §6/§7.1 #8）。

手动加黑盒入口（API POST /blackbox-runs + rerun 复用）：create_blackbox_run → 任务级进入
running（剥旧 scan_end + status=running + submitted_at 刷新）→ fire _add_run_kickoff
（precheck → _rerun_orchestrator）。预验证 fail → run 标 failed。

run 运行态如实上浮任务级（2026-08-17 根因修）：run 在跑期间任务级 status=running
（列表取消按钮/轮询/Dashboard 聚合依赖 is_running），收尾由 _ensure_scan_end 写回终态。
"""
import asyncio
import json
from unittest.mock import AsyncMock, patch

import pytest


def _mgr(tmp_path):
    from supernova_web.components.scan_manager import ScanManager
    return ScanManager(workspaces_dir=tmp_path, repos_dir=tmp_path, config_store=object())


def _ready_whitebox(scan_dir):
    """让 _whitebox_deliverables_ready 通过：recon + 非空 queue。"""
    wb = scan_dir / "deliverables" / "whitebox"
    wb.mkdir(parents=True, exist_ok=True)
    (wb / "recon_deliverable.md").write_text("recon")
    (wb / "injection_exploitation_queue.json").write_text(
        '{"vulnerabilities":[{"id":1}]}')


def test_count_nonempty_queues_reads_intermediate(tmp_path):
    """tiering 回归：queue 是中间产物落 whitebox/intermediate/ ->
    _count_nonempty_queues 必须数到（曾 glob 不递归数 0 -> 黑盒阶段整体被跳过）。"""
    from supernova_core.utils.paths import INTERMEDIATE_SUBDIR
    wb = tmp_path / "scan" / "deliverables" / "whitebox"
    (wb / INTERMEDIATE_SUBDIR).mkdir(parents=True)
    (wb / INTERMEDIATE_SUBDIR / "injection_exploitation_queue.json").write_text(
        '{"vulnerabilities":[{"id":1}]}')

    n = _mgr(tmp_path)._count_nonempty_queues(tmp_path / "scan")

    assert n == 1, "intermediate/ 下非空 queue 应被计入"


def _task_session(scan_dir) -> dict:
    return json.loads((scan_dir / "session.json").read_text("utf-8"))


async def _add_and_drain(mgr, ws, wb_id):
    """_add_blackbox_run + 等待 kickoff task 跑完（fire-and-forget，测试里显式 await）。"""
    run_id = await mgr._add_blackbox_run(ws, wb_id)
    task = mgr._orchestrator_tasks[(ws, wb_id)]
    await task
    return run_id


async def test_add_blackbox_run_creates_run_and_fires_orchestrator(tmp_path):
    from supernova_web.components.scan_store import ScanStore
    mgr = _mgr(tmp_path)
    store = ScanStore(tmp_path); mgr._store = store
    wb_id, scan_dir = store.create_scan("ws", "http://t", "/code/x")
    _ready_whitebox(scan_dir)
    with patch.object(mgr, "_run_precheck", new=AsyncMock(return_value=True)), \
         patch.object(mgr, "_rerun_orchestrator", new=AsyncMock()) as orch:
        run_id = await _add_and_drain(mgr, "ws", wb_id)
    assert run_id == "run-1"
    assert (scan_dir / "blackbox-runs" / "run-1" / "session.json").exists()
    orch.assert_awaited()  # 编排被 fire


async def test_add_blackbox_run_marks_task_running_and_strips_old_scan_end(tmp_path):
    """根因修核心：run 启动即任务级进入 running（剥旧 scan_end + status/completed_at +
    submitted_at 刷新）——否则任务级停在 completed，列表无取消按钮、收尾无人写终态、
    SSE 回放旧 scan_end、reconciler 的 has_scan_end 门短路组合恢复。"""
    from supernova_web.components.scan_store import ScanStore
    mgr = _mgr(tmp_path)
    store = ScanStore(tmp_path); mgr._store = store
    wb_id, scan_dir = store.create_scan("ws", "http://t", "/code/x")
    _ready_whitebox(scan_dir)
    # 模拟已完成 run-1：任务级 completed + events 尾部旧 scan_end
    store.create_blackbox_run("ws", wb_id)
    store.update_blackbox_run("ws", wb_id, "run-1", status="completed", phase="completed")
    (scan_dir / "events.ndjson").write_text(
        '{"type":"PhaseEvent","phase":"whitebox"}\n'
        '{"type":"scan_end","status":"completed"}\n')
    from supernova_core.session import SessionManager
    SessionManager(scan_dir.parent).update_session(
        scan_dir, {"status": "completed", "completed_at": 1750000000.0})

    with patch.object(mgr, "_run_precheck", new=AsyncMock(return_value=True)), \
         patch.object(mgr, "_rerun_orchestrator", new=AsyncMock()):
        run_id = await mgr._add_blackbox_run("ws", wb_id)
        assert run_id == "run-2"
        # 立即返回时（kickoff 未完成）任务级已是 running——列表/详情即时翻转
        sess = _task_session(scan_dir)
        assert sess["status"] == "running"
        assert sess["completed_at"] is None
        assert sess.get("submitted_at") is not None
        lines = (scan_dir / "events.ndjson").read_text().splitlines()
        assert not any('"scan_end"' in l for l in lines), "旧 scan_end 必须剥掉"
        assert any('"PhaseEvent"' in l for l in lines), "普通事件保留"
        await mgr._orchestrator_tasks[("ws", wb_id)]


async def test_manual_run_completion_marks_task_terminal(tmp_path):
    """run 正常完成 → _rerun_orchestrator finally 经 _ensure_scan_end 写新 scan_end +
    任务级 status=completed（旧 scan_end 已在启动时剥除，不再 no-op 卡旧值）。"""
    from supernova_web.components.scan_store import ScanStore
    mgr = _mgr(tmp_path)
    store = ScanStore(tmp_path); mgr._store = store
    wb_id, scan_dir = store.create_scan("ws", "http://t", "/code/x")
    _ready_whitebox(scan_dir)
    (scan_dir / "events.ndjson").write_text(
        '{"type":"PhaseEvent","phase":"whitebox"}\n'
        '{"type":"scan_end","status":"completed"}\n')

    async def _phase_ok(scan_dir, ws, scan_id, auth_ref, run_id, workflow_id_suffix=""):
        # 黑盒正常结束：run 标 completed（真 store），scan_end 交编排 finally 补写
        await mgr._mark_run(scan_dir, run_id, "completed", status="completed")

    with patch.object(mgr, "_run_precheck", new=AsyncMock(return_value=True)), \
         patch.object(mgr, "_run_blackbox_phase", new=_phase_ok):
        run_id = await _add_and_drain(mgr, "ws", wb_id)
    assert run_id == "run-1"
    sess = _task_session(scan_dir)
    assert sess["status"] == "completed"
    assert sess.get("completed_at") is not None
    lines = (scan_dir / "events.ndjson").read_text().splitlines()
    assert any('"scan_end"' in l and '"completed"' in l for l in lines), (
        "run 收尾必须写新 scan_end")


async def test_add_blackbox_run_precheck_fail_marks_run_failed(tmp_path):
    from supernova_web.components.scan_store import ScanStore
    mgr = _mgr(tmp_path)
    store = ScanStore(tmp_path); mgr._store = store
    wb_id, scan_dir = store.create_scan("ws", "http://t", "/code/x")
    _ready_whitebox(scan_dir)
    (scan_dir / "scan-config.yaml").write_text("url: http://t")  # 有认证 → 走 precheck
    with patch.object(mgr, "_run_precheck", new=AsyncMock(return_value=False)), \
         patch.object(mgr, "_mark_run", new=AsyncMock()) as mr, \
         patch.object(mgr, "_ensure_scan_end", new=AsyncMock()):
        run_id = await _add_and_drain(mgr, "ws", wb_id)
    assert run_id == "run-1"
    mr.assert_awaited_with(
        scan_dir, "run-1", "failed", reason="auth_failed", status="failed",
        extra={"bb_failure_point": None, "bb_failure_detail": None})


async def test_add_blackbox_run_precheck_runs_in_background_task(tmp_path):
    """precheck 在 kickoff task 内异步跑：_add_blackbox_run 立即返回（端点 202 语义，
    不再阻塞数分钟），precheck 未决时 run 已建 + 任务级 running。"""
    from supernova_web.components.scan_store import ScanStore
    mgr = _mgr(tmp_path)
    store = ScanStore(tmp_path); mgr._store = store
    wb_id, scan_dir = store.create_scan("ws", "http://t", "/code/x")
    _ready_whitebox(scan_dir)
    (scan_dir / "scan-config.yaml").write_text("url: http://t")

    gate = asyncio.Event()

    async def _slow_precheck(*a, **k):
        await gate.wait()
        return True

    with patch.object(mgr, "_run_precheck", new=_slow_precheck), \
         patch.object(mgr, "_rerun_orchestrator", new=AsyncMock()):
        run_id = await mgr._add_blackbox_run("ws", wb_id)
        assert run_id == "run-1"
        # 立即返回：precheck 未决，kickoff task 在跑且已注册（cancel 在 precheck 期间可达）
        assert ("ws", wb_id) in mgr._orchestrator_tasks
        assert _task_session(scan_dir)["status"] == "running"
        gate.set()
        await mgr._orchestrator_tasks[("ws", wb_id)]


async def test_add_blackbox_run_second_run_monotonic(tmp_path):
    from supernova_web.components.scan_store import ScanStore
    mgr = _mgr(tmp_path)
    store = ScanStore(tmp_path); mgr._store = store
    wb_id, scan_dir = store.create_scan("ws", "http://t", "/code/x")
    _ready_whitebox(scan_dir)
    store.create_blackbox_run("ws", wb_id)  # 已有 run-1
    # run-1 标终态（在跑守卫放行终态 latest，对齐 rerun_blackbox 门）
    store.update_blackbox_run("ws", wb_id, "run-1", status="completed", phase="completed")
    with patch.object(mgr, "_run_precheck", new=AsyncMock(return_value=True)), \
         patch.object(mgr, "_rerun_orchestrator", new=AsyncMock()):
        run_id = await _add_and_drain(mgr, "ws", wb_id)
    assert run_id == "run-2"  # 序号 per-task 单调递增


async def test_add_blackbox_run_rejects_missing_target_url(tmp_path):
    """纯白盒任务（bb_url/web_url 皆空）→ ValueError（端点 422）：黑盒无目标不打空跑。
    黑盒 workflow 对空 web_url 不 fail-fast（preflight 仅在有 URL 时校验可达性，exploit
    agent 拿空 web_url 照跑一轮 LLM），须在入口拦。"""
    from supernova_web.components.scan_store import ScanStore
    mgr = _mgr(tmp_path)
    store = ScanStore(tmp_path); mgr._store = store
    wb_id, scan_dir = store.create_scan("ws", "", "/code/x")  # 纯白盒：web_url 空
    _ready_whitebox(scan_dir)
    with pytest.raises(ValueError, match="目标 URL"):
        await mgr._add_blackbox_run("ws", wb_id)


async def test_add_blackbox_run_rejects_active_latest_run(tmp_path):
    """latest run 非终态（pending/running）→ 拒绝叠加：防并发 run 同打一目标 +
    _orchestrator_tasks[key] 被覆盖（cancel 只能取消 latest）。对齐 rerun_blackbox 状态门。"""
    from supernova_web.components.scan_store import ScanStore
    mgr = _mgr(tmp_path)
    store = ScanStore(tmp_path); mgr._store = store
    wb_id, scan_dir = store.create_scan("ws", "http://t", "/code/x")
    _ready_whitebox(scan_dir)
    store.create_blackbox_run("ws", wb_id)  # run-1（status=pending，非终态）
    with pytest.raises(ValueError, match="仍在进行"):
        await mgr._add_blackbox_run("ws", wb_id)


def _mgr_with_host_profiles(tmp_path):
    """ScanManager + 真 HostProfileStore（含一个无 source_url 的档案 → 解析不走网络）。"""
    from supernova_web.components.host_profile_store import (
        HostMapping, HostProfile, HostProfileStore)
    from supernova_web.components.scan_manager import ScanManager
    hp = HostProfileStore(tmp_path)
    hp.upsert_profile("ws", HostProfile(
        id="host-1", name="金融",
        mappings=[HostMapping(ip="10.254.19.209", host="test-futu-webapi.futuoa.com")]))
    return ScanManager(workspaces_dir=tmp_path, repos_dir=tmp_path,
                       config_store=object(), host_profile_store=hp)


async def test_add_blackbox_run_without_req_host_keeps_existing_snapshot(tmp_path):
    """req 不带 HOST 来源 → 不解析不覆盖：沿用主 session 既有 host_config 快照
    （老任务若带映射续用；空 body 直连模式同理零变化）。"""
    from supernova_web.components.scan_store import ScanStore
    from supernova_core.session import SessionManager
    from supernova_web.models import ScanRequest
    mgr = _mgr_with_host_profiles(tmp_path)
    store = ScanStore(tmp_path); mgr._store = store
    wb_id, scan_dir = store.create_scan("ws", "http://t.internal", "/code/x")
    _ready_whitebox(scan_dir)
    (scan_dir / "scan-config.yaml").write_text("url: http://t.internal")
    # 主 session 预置旧快照（resolved_at 标记守卫：未被覆盖）
    SessionManager(scan_dir.parent).update_session(scan_dir, {"host_config": {
        "enabled": True, "source": "profile", "profile_id": "host-old",
        "mappings": {"t.internal": "10.0.0.2"}, "warnings": [],
        "resolved_at": 123.0}})
    req = ScanRequest(type="whitebox", workspace="ws", url="http://t.internal")

    captured = {}

    async def _capture_precheck(scan_dir, ws, scan_id, web_url, config_path,
                                host_mappings=None):
        captured["host_mappings"] = host_mappings
        return True

    with patch.object(mgr, "_run_precheck", new=_capture_precheck), \
         patch.object(mgr, "_rerun_orchestrator", new=AsyncMock()):
        await mgr._add_blackbox_run("ws", wb_id, req)
        await mgr._orchestrator_tasks[("ws", wb_id)]

    cfg = _task_session(scan_dir)["host_config"]
    assert cfg["resolved_at"] == 123.0, "无 HOST 的 req 不得覆盖旧快照"
    assert captured["host_mappings"] == {"t.internal": "10.0.0.2"}, \
        "下游须沿用旧快照映射"


async def test_add_blackbox_run_with_req_host_writes_snapshot_and_feeds_precheck(tmp_path):
    """2026-09-15 gw_trade 事故：add-run 请求带 HOST 档案 → 须解析快照写主 session
    （_run_blackbox_phase 提交 worker 读它）+ kickoff precheck 拿映射。曾 req 分支只
    处理认证、HOST 字段被静默丢弃 → 内网域名 preflight 走公网 DNS 秒败
    （Cannot resolve hostname，run-1 session.json host_mappings={} 实锤）。"""
    from supernova_web.components.scan_store import ScanStore
    from supernova_web.models import ScanRequest
    mgr = _mgr_with_host_profiles(tmp_path)
    store = ScanStore(tmp_path); mgr._store = store
    wb_id, scan_dir = store.create_scan("ws", "http://test-futu-webapi.futuoa.com", "/code/x")
    _ready_whitebox(scan_dir)
    # 有认证文件 → kickoff 走 precheck（捕获 host_mappings 的观测点）
    (scan_dir / "scan-config.yaml").write_text("url: http://test-futu-webapi.futuoa.com")
    req = ScanRequest(type="whitebox", workspace="ws",
                      url="http://test-futu-webapi.futuoa.com",
                      host_profile_ids=["host-1"])

    captured = {}

    async def _capture_precheck(scan_dir, ws, scan_id, web_url, config_path,
                                host_mappings=None):
        captured["host_mappings"] = host_mappings
        return True

    with patch.object(mgr, "_run_precheck", new=_capture_precheck), \
         patch.object(mgr, "_rerun_orchestrator", new=AsyncMock()):
        run_id = await mgr._add_blackbox_run("ws", wb_id, req)
        await mgr._orchestrator_tasks[("ws", wb_id)]

    assert run_id == "run-1"
    cfg = _task_session(scan_dir).get("host_config")
    assert cfg and cfg.get("mappings") == {
        "test-futu-webapi.futuoa.com": "10.254.19.209"}, (
        "主 session 须落 host_config 快照（_run_blackbox_phase/详情重跑预填读它）")
    assert captured["host_mappings"] == {
        "test-futu-webapi.futuoa.com": "10.254.19.209"}, (
        "kickoff precheck 须拿到映射（登录目标站走 pinned host）")


async def test_add_blackbox_run_host_profile_missing_rejects_before_run_creation(tmp_path):
    """req 带 HOST 来源但解析失败（档案不存在）→ 创建 run 之前 raise（API 层 422），
    不留 ghost run——对齐 start() 的「HOST 解析在目录创建前」防幽灵语义。"""
    from supernova_web.components.scan_store import ScanStore
    from supernova_web.models import ScanRequest
    mgr = _mgr_with_host_profiles(tmp_path)
    store = ScanStore(tmp_path); mgr._store = store
    wb_id, scan_dir = store.create_scan("ws", "http://t", "/code/x")
    _ready_whitebox(scan_dir)
    req = ScanRequest(type="whitebox", workspace="ws", url="http://t",
                      host_profile_ids=["ghost-profile"])

    with pytest.raises(ValueError, match="不存在"):
        await mgr._add_blackbox_run("ws", wb_id, req)
    assert not (scan_dir / "blackbox-runs").exists() or \
        not list((scan_dir / "blackbox-runs").iterdir()), "失败须发生在 run 创建之前"
