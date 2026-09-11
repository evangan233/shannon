"""黑盒 run 终态回填吞 workflow status=failed 的口径矛盾（2026-09-11 NodeGoat 根因）。

真实形态锚定：web 经 start_workflow(BlackboxScanWorkflow.run) 提交，temporalio 按返回
类型注解 BlackboxPipelineState 反序列化 → handle.result() 是 **dataclass 实例而非 dict**
（实机验证 isinstance(result, dict) == False）。三个 run 终态消费点曾各自漏判：

1. _run_blackbox_phase：isinstance(result, dict) 单形态检查 → dataclass 恒跳过；
2. _combined_report_orchestrator（resume re-attach 路径）：返回值整体丢弃，无条件 completed；
3. _reconcile_combined_scan：只读 temporal 执行态（COMPLETED），不读返回值业务 status
   ——黑盒 workflow「正常 return status=failed 不 raise」时执行态就是 COMPLETED。

后果：workflow 明明返回 status=failed + failed_agents 非空，run 却被标 completed 且
生成融合报告（NodeGoat-20260911-032558：injection-exploit 2400s 撞墙失败被吞）。

本文件用真实 dataclass 形态钉死三处：failed → run 标 failed、不生成融合报告。
"""
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from supernova_web.components.scan_manager import ScanManager
from supernova_web.components.scan_store import ScanStore


@pytest.fixture
def mgr(tmp_path):
    return ScanManager(workspaces_dir=tmp_path, repos_dir=tmp_path, config_store=object())


def _failed_state():
    """真实形态的失败返回值：BlackboxPipelineState dataclass（非 dict）。

    对齐 NodeGoat-20260911-032558 实况（failed_agents=["injection-exploit"]、
    errors=["injection-exploit: Activity task failed"]、error_code="TransientError"）。
    """
    from supernova_blackbox.pipeline.shared import BlackboxPipelineState
    return BlackboxPipelineState(
        status="failed",
        errors=["injection-exploit: Activity task failed"],
        error_code="TransientError",
        failed_agents=["injection-exploit"],
        completed_agents=["xss-exploit", "report"],
    )


def _make_ready_scan(tmp_path):
    """白盒产物齐备的组合 scan_dir + run-1（_run_blackbox_phase 预检通过所需）。"""
    scan_dir = tmp_path / "repo-ts"
    scan_dir.mkdir()
    (scan_dir / "deliverables" / "whitebox").mkdir(parents=True)
    (scan_dir / "deliverables" / "whitebox" / "recon_deliverable.md").write_text("x")
    (scan_dir / "deliverables" / "whitebox" / "injection_exploitation_queue.json").write_text(
        '{"vulnerabilities":[{"id":1}]}')
    (scan_dir / "events.ndjson").write_text('{"type":"PhaseEvent","phase":"whitebox"}\n')
    (scan_dir / "blackbox-runs" / "run-1").mkdir(parents=True)
    return scan_dir


# ── 1. _run_blackbox_phase：dataclass 形态 failed → run 标 failed、不融合 ──────
async def test_run_blackbox_phase_marks_failed_for_dataclass_result(mgr, tmp_path):
    scan_dir = _make_ready_scan(tmp_path)
    with patch.object(mgr, "_submit_blackbox", new=AsyncMock(return_value=MagicMock())), \
         patch.object(mgr, "_await_workflow_result",
                      new=AsyncMock(return_value=_failed_state())), \
         patch.object(mgr, "_generate_combined_report", new=AsyncMock()) as gcr, \
         patch.object(mgr, "_mark_run", new=AsyncMock()) as mr:
        await mgr._run_blackbox_phase(scan_dir, "ws", "repo-ts", {"profile_id": None}, "run-1")
        gcr.assert_not_awaited()  # 失败 run 不产融合报告
        mr.assert_awaited_with(scan_dir, "run-1", "failed",
                               status="failed", reason="injection-exploit: Activity task failed")


# ── 2. _combined_report_orchestrator：resume 路径同样认 failed ────────────────
async def test_combined_report_orchestrator_marks_failed_for_dataclass_result(mgr, tmp_path):
    scan_dir = _make_ready_scan(tmp_path)
    with patch.object(mgr, "_await_workflow_result",
                      new=AsyncMock(return_value=_failed_state())), \
         patch.object(mgr, "_generate_combined_report", new=AsyncMock()) as gcr, \
         patch.object(mgr, "_mark_run", new=AsyncMock()) as mr, \
         patch.object(mgr, "_ensure_scan_end", new=AsyncMock()):
        await mgr._combined_report_orchestrator(("ws", "repo-ts"), MagicMock(),
                                                scan_dir, "run-1")
        gcr.assert_not_awaited()
        mr.assert_awaited_with(scan_dir, "run-1", "failed",
                               status="failed", reason="injection-exploit: Activity task failed")


# ── 3. reconcile：执行态 COMPLETED 但返回值 failed → run 标 failed ────────────
async def test_reconcile_completed_workflow_with_failed_result_marks_run_failed(mgr, tmp_path):
    scan_dir = tmp_path / "ws" / "scans" / "scan-1"
    scan_dir.mkdir(parents=True)
    (scan_dir / "session.json").write_text(json.dumps({
        "scan_type": "whitebox", "status": "running", "combined": True,
        "bb_url": "http://t/", "bb_auth_ref": {"profile_id": None},
    }))
    (scan_dir / "events.ndjson").write_text('{"type":"PhaseEvent","phase":"whitebox"}\n')
    store = ScanStore(tmp_path); mgr._store = store
    store.create_blackbox_run("ws", "scan-1")
    with patch.object(mgr, "_query_workflow_status",
                      new=AsyncMock(return_value="completed")), \
         patch.object(mgr, "_fetch_workflow_result_status",
                      new=AsyncMock(return_value="failed")) as frs, \
         patch.object(mgr, "_generate_combined_report", new=AsyncMock()) as gcr, \
         patch.object(mgr, "_ensure_scan_end", new=AsyncMock()):
        await mgr._reconcile_combined_scan(scan_dir)
    gcr.assert_not_awaited()
    runs = store.list_blackbox_runs("ws", "scan-1")
    assert runs[-1]["status"] == "failed"
    frs.assert_awaited_once()


# ── 零回归：成功 dataclass（status=completed）照旧生成报告 ─────────────────────
async def test_run_blackbox_phase_completed_dataclass_still_reports(mgr, tmp_path):
    from supernova_blackbox.pipeline.shared import BlackboxPipelineState
    scan_dir = _make_ready_scan(tmp_path)
    ok_state = BlackboxPipelineState(status="completed")
    with patch.object(mgr, "_submit_blackbox", new=AsyncMock(return_value=MagicMock())), \
         patch.object(mgr, "_await_workflow_result", new=AsyncMock(return_value=ok_state)), \
         patch.object(mgr, "_generate_combined_report", new=AsyncMock()) as gcr, \
         patch.object(mgr, "_mark_run", new=AsyncMock()) as mr:
        await mgr._run_blackbox_phase(scan_dir, "ws", "repo-ts", {"profile_id": None}, "run-1")
        gcr.assert_awaited_with(scan_dir, "run-1")
        mr.assert_awaited_with(scan_dir, "run-1", "completed", status="completed")
