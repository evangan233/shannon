"""组合扫描崩溃恢复（T11）：_reconcile_combined_scan 按 bb_runs[] 逐 run 补报告/补 scan_end。

核心契约（spec §7.5 崩溃恢复，版本化 run 模型）：
- 非组合扫描 → 立即返回（零回归）。
- 白盒 workflow 仍 RUNNING → 不干预（wf_active，不补 scan_end）。
- 逐 run：非终态 run 探测其 -bb-{K} workflow——COMPLETED → 补 per-run 融合报告 +
  _mark_run(completed)；RUNNING → wf_active（不干预）；其余 → fall-through 补 scan_end。
- 取代旧 task-level bb_phase 分支（不再 reconcile 内 kickoff 黑盒；续跑由 resume/orchestrator）。
"""
import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from supernova_web.components.scan_manager import ScanManager
from supernova_web.components.scan_store import ScanStore


@pytest.fixture
def mgr(tmp_path):
    return ScanManager(workspaces_dir=tmp_path, repos_dir=tmp_path, config_store=object())


def _make_combined(tmp_path, ws="ws", scan_id="scan-1", *, with_scan_end=False):
    """建组合 scan_dir（<tmp>/<ws>/scans/<scan_id>/）+ session.json + events.ndjson。

    combined=True（run 状态由 ScanStore.create_blackbox_run 写 bb_runs[]）。session 无
    bb_phase 字段（旧形态）→ reconcile 不走 precheck 分流，finally 默认 completed 收口。
    """
    scan_dir = tmp_path / ws / "scans" / scan_id
    scan_dir.mkdir(parents=True)
    (scan_dir / "session.json").write_text(json.dumps({
        "scan_type": "whitebox", "status": "running", "combined": True,
        "bb_url": "http://t/", "bb_auth_ref": {"profile_id": None},
    }))
    events = '{"type":"PhaseEvent","phase":"whitebox"}\n'
    if with_scan_end:
        events += '{"type":"scan_end","status":"completed"}\n'
    (scan_dir / "events.ndjson").write_text(events)
    return scan_dir


# ── 非组合扫描零回归 ───────────────────────────────────────────────────────
async def test_non_combined_scan_returns_early(mgr, tmp_path):
    """非组合扫描 → 立即返回，不调任何组合方法（零回归）。"""
    scan_dir = _make_combined(tmp_path)
    # 覆盖 session 为非 combined
    (scan_dir / "session.json").write_text(json.dumps({
        "scan_type": "whitebox", "status": "running"}))
    with patch.object(mgr, "_generate_combined_report", new=AsyncMock()) as gcr, \
         patch.object(mgr, "_query_workflow_status", new=AsyncMock()) as qs, \
         patch.object(mgr, "_ensure_scan_end", new=AsyncMock()) as ese:
        await mgr._reconcile_combined_scan(scan_dir)
        gcr.assert_not_awaited()
        qs.assert_not_awaited()
        ese.assert_not_awaited()


# ── run 黑盒 COMPLETED → 补 per-run 报告 + 标 completed ──────────────────────
async def test_reconcile_completed_run_generates_report(mgr, tmp_path):
    """run-1 非终态 + 其 -bb-1 workflow COMPLETED → 补 _generate_combined_report(scan_dir,
    run-1) + _mark_run(completed)；run 索引条目 status→completed。"""
    scan_dir = _make_combined(tmp_path)
    store = ScanStore(tmp_path); mgr._store = store
    store.create_blackbox_run("ws", "scan-1")  # run-1 非终态
    with patch.object(mgr, "_query_workflow_status",
                      new=AsyncMock(return_value="completed")) as qs, \
         patch.object(mgr, "_generate_combined_report", new=AsyncMock()) as gcr, \
         patch.object(mgr, "_ensure_scan_end", new=AsyncMock()):
        await mgr._reconcile_combined_scan(scan_dir)
    gcr.assert_awaited_with(scan_dir, "run-1")
    runs = store.list_blackbox_runs("ws", "scan-1")
    assert runs[-1]["status"] == "completed"


# ── run 黑盒 RUNNING → 不干预 ────────────────────────────────────────────────
async def test_reconcile_running_run_no_intervention(mgr, tmp_path):
    """run-1 + 其 workflow RUNNING → 不补报告、不补 scan_end（让 temporal 自然完成）。"""
    scan_dir = _make_combined(tmp_path)
    store = ScanStore(tmp_path); mgr._store = store
    store.create_blackbox_run("ws", "scan-1")
    store.update_blackbox_run("ws", "scan-1", "run-1", phase="running", status="running")
    with patch.object(mgr, "_query_workflow_status",
                      new=AsyncMock(return_value="running")), \
         patch.object(mgr, "_generate_combined_report", new=AsyncMock()) as gcr, \
         patch.object(mgr, "_ensure_scan_end", new=AsyncMock()) as ese:
        await mgr._reconcile_combined_scan(scan_dir)
    gcr.assert_not_awaited()
    ese.assert_not_awaited()  # wf_active → 不补 scan_end


# ── 无活跃 workflow + 无 scan_end → _ensure_scan_end 补写 ────────────────────
async def test_reconcile_ensures_scan_end_when_absent(mgr, tmp_path):
    """无 run / 白盒 not-found + events 无 scan_end → _ensure_scan_end 补写。"""
    scan_dir = _make_combined(tmp_path, with_scan_end=False)
    with patch.object(mgr, "_query_workflow_status",
                      new=AsyncMock(return_value=None)), \
         patch.object(mgr, "_ensure_scan_end", new=AsyncMock()) as ese:
        await mgr._reconcile_combined_scan(scan_dir)
    ese.assert_awaited_once_with(scan_dir, status="completed")


# ── events 有 scan_end → 幂等 no-op ──────────────────────────────────────────
async def test_reconcile_scan_end_present_no_double_write(mgr, tmp_path):
    """events 已有 scan_end → _write_scan_end 不被调（_ensure_scan_end 幂等 no-op）。"""
    scan_dir = _make_combined(tmp_path, with_scan_end=True)
    store = ScanStore(tmp_path); mgr._store = store
    store.create_blackbox_run("ws", "scan-1")
    with patch.object(mgr, "_query_workflow_status",
                      new=AsyncMock(return_value="completed")), \
         patch.object(mgr, "_generate_combined_report", new=AsyncMock()), \
         patch.object(mgr, "_write_scan_end", new=AsyncMock()) as ws_end:
        await mgr._reconcile_combined_scan(scan_dir)
    ws_end.assert_not_awaited()


# ── reconcile 内部异常 → finally 仍补 scan_end ──────────────────────────────
async def test_reconcile_report_raises_still_ensures_scan_end(mgr, tmp_path):
    """_generate_combined_report raise → except 捕获 + finally _ensure_scan_end 补 scan_end。"""
    scan_dir = _make_combined(tmp_path)
    store = ScanStore(tmp_path); mgr._store = store
    store.create_blackbox_run("ws", "scan-1")
    with patch.object(mgr, "_query_workflow_status",
                      new=AsyncMock(return_value="completed")), \
         patch.object(mgr, "_generate_combined_report",
                      new=AsyncMock(side_effect=RuntimeError("report boom"))), \
         patch.object(mgr, "_ensure_scan_end", new=AsyncMock()) as ese:
        await mgr._reconcile_combined_scan(scan_dir)  # 不应 raise
    ese.assert_awaited_once_with(scan_dir, status="completed")


# ── 逐 run：多 run 各自探测 ─────────────────────────────────────────────────
async def test_reconcile_skips_terminal_runs(mgr, tmp_path):
    """终态 run（completed/failed）跳过探测；只查非终态 run 的 workflow。"""
    scan_dir = _make_combined(tmp_path)
    store = ScanStore(tmp_path); mgr._store = store
    store.create_blackbox_run("ws", "scan-1")  # run-1
    store.update_blackbox_run("ws", "scan-1", "run-1", status="failed", phase="failed")
    store.create_blackbox_run("ws", "scan-1")  # run-2 非终态
    queried = []

    async def _qs(wf_id):
        queried.append(wf_id)
        return None  # 都 not-found

    with patch.object(mgr, "_query_workflow_status", new=_qs), \
         patch.object(mgr, "_generate_combined_report", new=AsyncMock()) as gcr, \
         patch.object(mgr, "_ensure_scan_end", new=AsyncMock()):
        await mgr._reconcile_combined_scan(scan_dir)
    # 查白盒 base（ws-scan-1）+ run-2 的 -bb-2（run-1 终态跳过）
    assert "ws-scan-1" in queried, f"应查白盒 base，实际: {queried}"
    assert any(q.endswith("-bb-2") for q in queried), f"应查 run-2 的 -bb-2，实际: {queried}"
    assert not any(q.endswith("-bb-1") for q in queried), "run-1 终态不应被查"
    gcr.assert_not_awaited()


# ── run workflow 不存在（编排随 web 重启丢失）→ run 标 failed 收口 ──────────
async def test_reconcile_not_found_run_marked_failed(mgr, tmp_path):
    """run-1 非终态 + 其 -bb-1 workflow 不存在（None）→ run 标 failed。否则 bb_runs 永久
    卡非终态，delete 的 bb_runs 门与加 run 的在跑守卫被永久禁用（2026-08-17 根因修）。"""
    scan_dir = _make_combined(tmp_path)
    store = ScanStore(tmp_path); mgr._store = store
    store.create_blackbox_run("ws", "scan-1")  # run-1 非终态
    with patch.object(mgr, "_query_workflow_status",
                      new=AsyncMock(return_value=None)), \
         patch.object(mgr, "_ensure_scan_end", new=AsyncMock()) as ese:
        await mgr._reconcile_combined_scan(scan_dir)
    runs = store.list_blackbox_runs("ws", "scan-1")
    assert runs[-1]["status"] == "failed"
    assert runs[-1].get("reason") == "编排中断（web 重启），run 未完成"
    ese.assert_awaited_once_with(scan_dir, status="completed")  # 无活跃 workflow → 补 scan_end


# ── orphan_reconciler 接入：reconcile_orphaned → kick 组合恢复 ──────────────
async def test_reconcile_orphaned_delegates_combined_to_scan_manager(tmp_path):
    from supernova_web.components.orphan_reconciler import (
        WorkflowProbe, WorkflowProbeResult, reconcile_orphaned)
    scan_dir = tmp_path / "ws" / "scans" / "scan-1"
    scan_dir.mkdir(parents=True)
    (scan_dir / "session.json").write_text(json.dumps({
        "scan_type": "whitebox", "status": "running", "combined": True}))
    (scan_dir / "events.ndjson").write_text('{"type":"PhaseEvent"}\n')
    fake_mgr = MagicMock()
    with patch("supernova_web.components.orphan_reconciler.is_scan_alive", return_value=False), \
         patch("supernova_web.components.orphan_reconciler._probe_workflow",
               new=AsyncMock(return_value=WorkflowProbeResult(WorkflowProbe.CLOSED))):
        await reconcile_orphaned(scan_dir, False, scan_manager=fake_mgr)
        fake_mgr._kick_combined_reconcile.assert_called_once_with(scan_dir)


async def test_reconcile_orphaned_non_combined_writes_scan_end_as_before(tmp_path):
    from supernova_web.components.orphan_reconciler import (
        WorkflowProbe, WorkflowProbeResult, reconcile_orphaned, _has_scan_end)
    scan_dir = tmp_path / "ws" / "scans" / "scan-1"
    scan_dir.mkdir(parents=True)
    (scan_dir / "session.json").write_text(json.dumps({
        "scan_type": "whitebox", "status": "running"}))  # 无 combined → 非组合
    (scan_dir / "events.ndjson").write_text('{"type":"PhaseEvent"}\n')
    fake_mgr = MagicMock()
    with patch("supernova_web.components.orphan_reconciler.is_scan_alive", return_value=False), \
         patch("supernova_web.components.orphan_reconciler._probe_workflow",
               new=AsyncMock(return_value=WorkflowProbeResult(WorkflowProbe.CLOSED))):
        result = await reconcile_orphaned(scan_dir, False, scan_manager=fake_mgr)
        assert result is True
        assert _has_scan_end(scan_dir / "events.ndjson")
        fake_mgr._kick_combined_reconcile.assert_not_called()


# ── _kick_combined_reconcile 非阻塞 + 幂等 ───────────────────────────────────
async def test_kick_combined_reconcile_is_non_blocking_and_idempotent(mgr, tmp_path):
    scan_dir = _make_combined(tmp_path)
    call_count = 0

    async def _slow_reconcile(sd):
        nonlocal call_count
        call_count += 1
        await asyncio.sleep(0.05)

    with patch.object(mgr, "_reconcile_combined_scan", new=_slow_reconcile):
        mgr._kick_combined_reconcile(scan_dir)
        mgr._kick_combined_reconcile(scan_dir)  # 幂等
        assert call_count == 0
        assert ("ws", "scan-1") in mgr._reconcile_tasks
        await asyncio.gather(*mgr._reconcile_tasks.values())
        assert call_count == 1
        assert ("ws", "scan-1") not in mgr._reconcile_tasks
