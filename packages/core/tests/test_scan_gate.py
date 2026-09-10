"""ScanGate 单测：FIFO 授予 / 幂等 / queue_full / release / reap / preload / 快照原子写。"""

import json
from unittest.mock import MagicMock, patch

from supernova_core.services.scan_gate import (
    ScanGate, read_gate_snapshot_file, reset_gate_for_tests,
)


def _mk(capacity=2, max_waiting=3, state_path=None):
    return ScanGate(capacity, max_waiting, state_path)


def test_first_acquire_granted_immediately():
    g = _mk()
    assert g.try_acquire("w1", {"kind": "whitebox"})["granted"] is True


def test_fifo_earliest_waiter_wins_slot():
    g = _mk(capacity=1)
    g.try_acquire("w1", {})
    assert g.try_acquire("w2", {})["granted"] is False
    assert g.try_acquire("w3", {})["granted"] is False
    g.release("w1")
    # w2 是最早等待者：w3 先 poll 也不能插队（近似 FIFO，spec §4）
    assert g.try_acquire("w3", {})["granted"] is False
    assert g.try_acquire("w2", {})["granted"] is True
    assert g.try_acquire("w3", {})["granted"] is False


def test_idempotent_reacquire():
    g = _mk(capacity=1)
    g.try_acquire("w1", {})
    assert g.try_acquire("w1", {})["granted"] is True


def test_queue_full_rejects_new_waiter():
    g = _mk(capacity=1, max_waiting=1)
    g.try_acquire("w1", {})
    assert g.try_acquire("w2", {})["granted"] is False  # w2 占住唯一 waiting 位
    assert g.try_acquire("w3", {})["queue_full"] is True


def test_position_reports_queue_rank():
    g = _mk(capacity=1, max_waiting=10)
    g.try_acquire("w1", {})
    g.try_acquire("w2", {})
    g.try_acquire("w3", {})
    assert g.try_acquire("w3", {})["position"] == 2  # 第 2 位


def test_release_and_reap_clear_state():
    g = _mk()
    g.try_acquire("w1", {})
    g.try_acquire("w2", {})  # waiting
    g.release("w1")
    assert "w1" not in g.held
    g.reap(["w2"])
    assert "w2" not in g.waiting


def test_preload_counts_as_held():
    g = _mk(capacity=2)
    g.preload(["a", "b"])
    assert g.try_acquire("c", {})["granted"] is False  # 槽被预占满
    assert g.try_acquire("a", {})["granted"] is True   # 预占者幂等命中


def test_candidate_ids_union():
    g = _mk()
    g.try_acquire("w1", {})
    g.try_acquire("w2", {})
    assert set(g.candidate_ids()) == {"w1", "w2"}


def test_snapshot_written_atomically(tmp_path):
    sf = tmp_path / "gate_state.json"
    g = _mk(state_path=sf)
    g.try_acquire("w1", {"kind": "whitebox", "ws": "prod",
                         "scan_id": "s1", "label": "repo@main"})
    data = json.loads(sf.read_text())
    assert data["capacity"] == 2
    assert data["held"][0]["scan_id"] == "s1"
    assert not sf.with_suffix(".json.tmp").exists()  # 原子写无残留 tmp


def test_snapshot_includes_waiter_on_enqueue(tmp_path):
    """新 waiter 入列也要落盘：web queued 档判定 + 面板 waiting 都吃快照。
    修「排队任务 120s 提交宽限后误显已中断、扫描并发面板看不到排队」——
    try_acquire 的 not-granted 路径曾漏 _persist，快照停留在最后一次
    granted/release 的状态（waiting 永不出现，直到有人 release 才刷新）。"""
    sf = tmp_path / "gate_state.json"
    g = _mk(capacity=1, state_path=sf)
    g.try_acquire("w1", {"kind": "whitebox", "ws": "prod",
                         "scan_id": "s1", "label": "repo@main"})
    g.try_acquire("w2", {"kind": "whitebox", "ws": "prod",
                         "scan_id": "s2", "label": "repo2@main"})
    data = json.loads(sf.read_text())
    assert [w["scan_id"] for w in data["waiting"]] == ["s2"]


def test_snapshot_state_path_none_is_noop(tmp_path):
    g = _mk(state_path=None)
    g.try_acquire("w1", {})  # 不应抛错


def test_read_gate_snapshot_file_missing_returns_none(tmp_path):
    assert read_gate_snapshot_file(tmp_path / "nope.json") is None


def test_gate_scan_id_from_event_file():
    from supernova_core.services.scan_gate import gate_scan_id_from_event_file
    assert gate_scan_id_from_event_file(
        "/app/workspaces/prod/scans/20260908-120000/events.ndjson") == "20260908-120000"
    assert gate_scan_id_from_event_file(None) == ""
    assert gate_scan_id_from_event_file("") == ""


def test_gate_ws_from_path():
    from supernova_core.services.scan_gate import gate_ws_from_path
    assert gate_ws_from_path(
        "/app/workspaces/prod/scans/x/events.ndjson") == "prod"
    assert gate_ws_from_path("/app/workspaces/prod") == "prod"
    assert gate_ws_from_path("") == ""


def test_gate_ws_for_descriptor_prefers_event_file_workspace():
    """web workspace_name=scan_id 不能当 ws 展示；event_file 路径才是权威来源。"""
    from supernova_core.services.scan_gate import gate_ws_for_descriptor

    assert gate_ws_for_descriptor(
        "s1", "/app/workspaces/prod/scans/s1/events.ndjson") == "prod"
    # CLI 的临时 event 路径不含 workspaces 段：不把文件名误判成 ws。
    assert gate_ws_for_descriptor("cli-ws", "/tmp/cli/events.ndjson") == "cli-ws"
    # CLI 无 event_file：workspace_name 本来就是真实 ws。
    assert gate_ws_for_descriptor("cli-ws", None) == "cli-ws"
    assert gate_ws_for_descriptor(None, None) == ""


def test_activity_wrappers_delegate_to_gate():
    """activity 包装：workflow_id 取 activity.info()，逻辑委托进程级 gate。"""
    import asyncio
    from supernova_core.services import scan_gate as mod

    reset_gate_for_tests()
    info = MagicMock()
    info.workflow_id = "wf-abc"
    with patch.object(mod.activity, "info", return_value=info), \
         patch.dict("os.environ", {"SUPERNOVA_SCAN_GATE_CAPACITY": "1"}):
        r = asyncio.run(mod.scan_gate_try_acquire({"kind": "whitebox"}))
        assert r["granted"] is True
        asyncio.run(mod.scan_gate_release())
        assert mod._gate().candidate_ids() == []
    reset_gate_for_tests()
