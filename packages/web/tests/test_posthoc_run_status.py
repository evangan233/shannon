"""加 run 式任务的失败归属（2026-09-15 现场根因修）。

现场（金融/gw_trade-20260910-191453）：白盒本体 completed → 黑盒表单选该任务加 run →
run 失败 → 任务级被写 scan_end failed + session.status=failed → 从表单候选消失、无法
再次发起黑盒。语义修正：**手动加 run（含 rerun）的失败是 run 级事件**——任务（白盒本体）
状态只由白盒生命周期决定；run 进行中如实上浮 running（2026-08-17 根因修保留），run
终态（failed/skipped/completed）写回预跑白盒终态，不翻任务级 failed。

区分信号（与真组合提交）：任务级 bb_phase 只在组合提交/编排路径写（start 组合分支
_mark_bb），加 run 路径（create_blackbox_run）从不写——combined ∧ 任务级 bb_phase
缺失 ⇒ 加 run 式任务。真组合提交（任务级 bb_phase 存在）行为不变（run 失败仍翻 failed，
续跑守卫/换认证重跑路径依赖）。
"""
import json
from unittest.mock import AsyncMock, patch

from supernova_core.session import SessionManager


def _mgr(tmp_path):
    from supernova_web.components.scan_manager import ScanManager
    return ScanManager(workspaces_dir=tmp_path, repos_dir=tmp_path, config_store=object())


def _ready_whitebox(scan_dir):
    wb = scan_dir / "deliverables" / "whitebox"
    wb.mkdir(parents=True, exist_ok=True)
    (wb / "recon_deliverable.md").write_text("recon")
    (wb / "injection_exploitation_queue.json").write_text(
        '{"vulnerabilities":[{"id":1}]}')


def _task_session(scan_dir) -> dict:
    return json.loads((scan_dir / "session.json").read_text("utf-8"))


def _mk_posthoc_scan(store, ws="WS", status="completed"):
    """白盒任务 + 已收尾 + 一个失败 run（加 run 式：不写任务级 bb_phase）。"""
    wb_id, wb_dir = store.create_scan(ws, "http://t", "/code/x")
    _ready_whitebox(wb_dir)
    SessionManager(wb_dir.parent).update_session(
        wb_dir, {"status": status, "completed_at": 1750000000.0})
    run_id, run_dir = store.create_blackbox_run(ws, wb_id)
    store.update_blackbox_run(ws, wb_id, run_id, status="failed", phase="failed",
                              reason="boom")
    return wb_id, wb_dir, run_id


# ── 投影侧：effective_scan_status / _summarize / progress ────────────────────

def test_reconnecting_is_not_overridden_by_combined_phase():
    """心跳 stale 的组合扫描仍须等待 Temporal 对账，不能被 pending/running phase 伪装运行中。"""
    from supernova_web.components.scan_store import effective_scan_status
    assert effective_scan_status("reconnecting", True, "running") == "reconnecting"

def test_posthoc_run_failure_keeps_task_completed_in_list(tmp_path):
    """加 run 失败不上浮任务级：list 状态仍 completed（表单候选口径依赖）。"""
    from supernova_web.components.scan_store import ScanStore
    store = ScanStore(tmp_path)
    _mk_posthoc_scan(store)
    s = store.list_scans("WS")[0]
    assert s.status == "completed", "失败属于 run，不属于白盒任务"
    assert s.bb_phase == "failed"  # run 级失败仍如实透出（run 徽章/续跑守卫消费）
    assert s.progress_pct == 100.0


def test_posthoc_run_skipped_keeps_task_completed(tmp_path):
    from supernova_web.components.scan_store import ScanStore
    store = ScanStore(tmp_path)
    wb_id, wb_dir = store.create_scan("WS", "http://t", "/code/x")
    _ready_whitebox(wb_dir)
    SessionManager(wb_dir.parent).update_session(
        wb_dir, {"status": "completed", "completed_at": 1750000000.0})
    run_id, _ = store.create_blackbox_run("WS", wb_id)
    store.update_blackbox_run("WS", wb_id, run_id, status="skipped", phase="skipped")
    assert store.list_scans("WS")[0].status == "completed"


def test_posthoc_run_inflight_still_running(tmp_path):
    """run 在跑期间任务级如实上浮 running（取消按钮/轮询/is_running 依赖，零回归）。"""
    from supernova_web.components.scan_store import ScanStore
    store = ScanStore(tmp_path)
    wb_id, wb_dir = store.create_scan("WS", "http://t", "/code/x")
    SessionManager(wb_dir.parent).update_session(wb_dir, {"status": "running"})
    run_id, run_dir = store.create_blackbox_run("WS", wb_id)
    SessionManager(run_dir.parent).update_session(run_dir, {"bb_phase": "running"})
    assert store.list_scans("WS")[0].status == "running"


def test_true_combined_run_failure_still_failed(tmp_path):
    """真组合提交（任务级 bb_phase 存在）零回归：run 失败仍翻任务 failed。"""
    from supernova_web.components.scan_store import ScanStore
    store = ScanStore(tmp_path)
    wb_id, wb_dir = store.create_scan("WS", "http://t", "/code/x")
    _ready_whitebox(wb_dir)
    # 组合提交在 start 组合分支写任务级 bb_phase（停在 pending）
    SessionManager(wb_dir.parent).update_session(
        wb_dir, {"status": "completed", "combined": True, "bb_phase": "pending"})
    run_id, _ = store.create_blackbox_run("WS", wb_id)
    store.update_blackbox_run("WS", wb_id, run_id, status="failed", phase="failed")
    s = store.list_scans("WS")[0]
    assert s.status == "failed"
    assert s.progress_pct == 0.0


def test_detail_status_posthoc_run_failure_completed(authed_client, tmp_workspaces):
    """detail 与 list 同视图：加 run 失败后详情页状态仍 completed（「加黑盒」按钮
    whiteboxAddable 口径——任务不因 run 失败从可加黑盒集合消失）。"""
    from supernova_web.components.scan_store import ScanStore
    wb_id, _, _ = _mk_posthoc_scan(ScanStore(tmp_workspaces))
    d = authed_client.get(f"/api/workspaces/WS/scans/{wb_id}").json()
    assert d["status"] == "completed"
    assert d["bb_phase"] == "failed"  # run 级失败如实（详情两段时间线消费）


# ── 写入侧：加 run 失败收尾写回白盒预跑终态 ──────────────────────────────────

async def test_rerun_orchestrator_run_failure_writes_back_whitebox_terminal(tmp_path):
    """run 失败（异常路径）→ 任务级收尾写回预跑白盒终态 completed，不写 failed；
    run 自身标 failed（run 级可见）。"""
    from supernova_web.components.scan_store import ScanStore
    mgr = _mgr(tmp_path)
    store = ScanStore(tmp_path); mgr._store = store
    wb_id, scan_dir = store.create_scan("ws", "http://t", "/code/x")
    _ready_whitebox(scan_dir)
    SessionManager(scan_dir.parent).update_session(
        scan_dir, {"status": "completed", "completed_at": 1750000000.0})

    async def _phase_boom(*a, **k):
        raise RuntimeError("blackbox workflow failed")

    with patch.object(mgr, "_run_blackbox_phase", new=_phase_boom), \
         patch.object(mgr, "_mark_run", new=AsyncMock()) as mr:
        await mgr._rerun_orchestrator(("ws", wb_id), scan_dir, "ws", wb_id,
                                      {"profile_id": None}, "run-1", "-bb-1")
    mr.assert_awaited()  # run 标 failed
    assert any(call.args[2] == "failed" for call in mr.await_args_list)
    sess = _task_session(scan_dir)
    assert sess["status"] == "completed", "任务级收尾应写回白盒预跑终态"
    lines = (scan_dir / "events.ndjson").read_text().splitlines()
    assert any('"scan_end"' in l and '"completed"' in l for l in lines)


async def test_rerun_orchestrator_preserves_cancelled_pre_run_status(tmp_path):
    """预跑 cancelled（取消过 run 的白盒产物完好）→ run 失败后任务回到 cancelled，
    不被升级成 completed。走真实入口 _add_blackbox_run（stash 在进入 running 前写入）。"""
    from supernova_web.components.scan_store import ScanStore
    mgr = _mgr(tmp_path)
    store = ScanStore(tmp_path); mgr._store = store
    wb_id, scan_dir = store.create_scan("ws", "http://t", "/code/x")
    _ready_whitebox(scan_dir)
    SessionManager(scan_dir.parent).update_session(
        scan_dir, {"status": "cancelled", "completed_at": 1750000000.0})

    async def _phase_boom(*a, **k):
        raise RuntimeError("boom")

    with patch.object(mgr, "_run_precheck", new=AsyncMock(return_value=True)), \
         patch.object(mgr, "_run_blackbox_phase", new=_phase_boom), \
         patch.object(mgr, "_mark_run", new=AsyncMock()):
        await mgr._add_blackbox_run("ws", wb_id)
        await mgr._orchestrator_tasks[("ws", wb_id)]
    assert _task_session(scan_dir)["status"] == "cancelled"


async def test_add_run_precheck_failure_keeps_task_terminal(tmp_path):
    """precheck（认证预验证）失败 → run 标 failed，任务级收尾写回白盒终态（原写
    failed——现场 gw_trade 即此路径族）。"""
    from supernova_web.components.scan_store import ScanStore
    mgr = _mgr(tmp_path)
    store = ScanStore(tmp_path); mgr._store = store
    wb_id, scan_dir = store.create_scan("ws", "http://t", "/code/x")
    _ready_whitebox(scan_dir)
    (scan_dir / "scan-config.yaml").write_text("url: http://t")
    SessionManager(scan_dir.parent).update_session(
        scan_dir, {"status": "completed", "completed_at": 1750000000.0})

    with patch.object(mgr, "_run_precheck", new=AsyncMock(return_value=False)), \
         patch.object(mgr, "_mark_run", new=AsyncMock()) as mr:
        run_id = await mgr._add_blackbox_run("ws", wb_id)
        await mgr._orchestrator_tasks[("ws", wb_id)]
    assert run_id == "run-1"
    assert any(call.args[2] == "failed" for call in mr.await_args_list)
    assert _task_session(scan_dir)["status"] == "completed"
