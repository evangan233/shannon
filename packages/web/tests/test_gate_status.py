"""排队状态计算：_compute_status queued 档 + reconciler 不误杀排队中扫描（spec §7）。"""

import json

from supernova_web.components.workspaces_indexer import _compute_status


def _mk_scan(tmp_path, ws="prod", scan_id="20260908-120000"):
    scan_dir = tmp_path / "workspaces" / ws / "scans" / scan_id
    scan_dir.mkdir(parents=True)
    (scan_dir / "session.json").write_text("{}")
    return scan_dir


def _write_gate(tmp_path, waiting):
    (tmp_path / "workspaces" / "gate_state.json").write_text(
        json.dumps({"capacity": 5, "held": [], "waiting": waiting}))


def test_compute_status_queued_when_in_gate_waiting(tmp_path):
    scan_dir = _mk_scan(tmp_path)
    _write_gate(tmp_path, [{"ws": "prod", "scan_id": "20260908-120000",
                            "kind": "whitebox", "label": "r@main", "since": 1.0}])
    # 无 heartbeat、超宽限 → 旧逻辑判 interrupted；新逻辑判 queued
    assert _compute_status(scan_dir, None) == "queued"


def test_compute_status_queued_beats_submit_grace(tmp_path):
    """提交宽限期内 + 闸门 waiting 命中 → queued（2026-09-15 修「排队中显示运行中」）。

    旧顺序 alive（含 120s 提交宽限）先于 queued 档：批量发起槽满排队时，排队任务
    在头 120s 误显「运行中」。闸门 waiting = workflow 尚未获槽的权威信号，先于
    宽限门的「可能还在冷启动」猜测。
    """
    import time
    scan_dir = _mk_scan(tmp_path)
    (scan_dir / "session.json").write_text(json.dumps({"submitted_at": time.time()}))
    _write_gate(tmp_path, [{"ws": "prod", "scan_id": "20260908-120000",
                            "kind": "whitebox", "label": "r@main", "since": 1.0}])
    assert _compute_status(scan_dir, None) == "queued"


def test_compute_status_reconnecting_when_gate_miss(tmp_path):
    scan_dir = _mk_scan(tmp_path)
    _write_gate(tmp_path, [{"ws": "prod", "scan_id": "other-scan",
                            "kind": "whitebox", "label": "x", "since": 1.0}])
    assert _compute_status(scan_dir, None) == "reconnecting"


def test_compute_status_terminal_still_wins(tmp_path):
    scan_dir = _mk_scan(tmp_path)
    _write_gate(tmp_path, [{"ws": "prod", "scan_id": "20260908-120000",
                            "kind": "whitebox", "label": "r", "since": 1.0}])
    assert _compute_status(scan_dir, "completed") == "completed"


def test_compute_status_corr_main_queued_via_children(tmp_path):
    """跨仓主行：主行自身不在 waiting，但 corr_children 里非 reused 子仓在排队。"""
    main_dir = _mk_scan(tmp_path, scan_id="corr-main")
    (main_dir / "session.json").write_text(json.dumps({
        "corr_children": [
            {"service": "checkout", "scan_id": "child-1", "reused": False},
            {"service": "payment", "scan_id": "old-9", "reused": True},
        ]}))
    _write_gate(tmp_path, [{"ws": "prod", "scan_id": "child-1",
                            "kind": "whitebox", "label": "c", "since": 1.0}])
    assert _compute_status(main_dir, None) == "queued"


def test_reconciler_skips_queued(tmp_path):
    """orphan_reconciler：排队中（gate waiting 命中）不 reconcile（spec §7.5）。"""
    import asyncio
    from unittest.mock import MagicMock
    from supernova_web.components import orphan_reconciler as orc

    scan_dir = _mk_scan(tmp_path)
    _write_gate(tmp_path, [{"ws": "prod", "scan_id": "20260908-120000",
                            "kind": "whitebox", "label": "r", "since": 1.0}])
    called = []

    async def _fake_still_running(ws_dir):
        called.append(True)
        return False

    orig = orc._workflow_still_running
    orc._workflow_still_running = _fake_still_running
    try:
        r = asyncio.run(orc.reconcile_orphaned(scan_dir, False, None))
    finally:
        orc._workflow_still_running = orig
    assert r is False
    assert called == []          # queued 短路在 temporal 查询之前
    # 未被误标 interrupted
    sess = json.loads((scan_dir / "session.json").read_text())
    assert sess.get("status") != "interrupted"
