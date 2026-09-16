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
    # 预占者首 poll：摘除自身预占 → 无更早 waiter → 正常准入拿回槽
    assert g.try_acquire("a", {})["granted"] is True
    assert g.try_acquire("c", {})["granted"] is False  # 槽满（a 持有 + b 预占）


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


# ── per-workspace 并发上限（SUPERNOVA_WS_SCAN_CONCURRENCY，2026-09-15）──

def test_ws_cap_blocks_second_same_ws_when_global_has_room():
    """全局有空槽但本 ws 持有已达上限 → 不授予（用户需求核心：ws 配 2 只跑 2）。"""
    g = _mk(capacity=3)
    g.try_acquire("a1", {"ws": "A", "ws_cap": 2})
    g.try_acquire("a2", {"ws": "A", "ws_cap": 2})
    r = g.try_acquire("a3", {"ws": "A", "ws_cap": 2})
    assert r["granted"] is False
    assert r["queue_full"] is False  # 是本 ws 满，不是队满


def test_ws_cap_skips_blocked_earliest_grants_other_ws():
    """earliest 被自己 ws cap 挡住时不许 head-of-line 全局饿死：后面的其他 ws 先走。"""
    g = _mk(capacity=3)
    g.try_acquire("a1", {"ws": "A", "ws_cap": 2})
    g.try_acquire("a2", {"ws": "A", "ws_cap": 2})
    assert g.try_acquire("a3", {"ws": "A", "ws_cap": 2})["granted"] is False  # a3 排队
    # b1 排在 a3 之后：全局有空槽（3-2=1）且 a3 被自己 cap 挡 → b1 越过 a3 获授
    assert g.try_acquire("b1", {"ws": "B"})["granted"] is True
    # a3 依旧被挡（A 持有 2 未变）
    assert g.try_acquire("a3", {"ws": "A", "ws_cap": 2})["granted"] is False


def test_ws_cap_release_restores_same_ws_admission():
    """本 ws 释放后同 ws 等待者可进（cap 是滑动窗口，非死锁）。"""
    g = _mk(capacity=3)
    g.try_acquire("a1", {"ws": "A", "ws_cap": 2})
    g.try_acquire("a2", {"ws": "A", "ws_cap": 2})
    g.try_acquire("a3", {"ws": "A", "ws_cap": 2})  # 排队
    g.release("a1")
    assert g.try_acquire("a3", {"ws": "A", "ws_cap": 2})["granted"] is True


def test_ws_cap_clamped_to_global_capacity_in_snapshot(tmp_path):
    """ws 配 8 > 全局 2：授予行为无差异（全局先挡），但快照展示生效值 = min(8, 2)。

    clamp 是「无论怎么配都不会大于全局」的规范化出口——前端面板吃快照显示 x/cap，
    生效值才是不误导的口径（配置原文 8 显示成 2/8 会谎报全局约束力）。
    """
    sf = tmp_path / "gate_state.json"
    g = _mk(capacity=2, state_path=sf)
    g.try_acquire("a1", {"ws": "A", "ws_cap": 8, "scan_id": "s1"})
    g.try_acquire("a2", {"ws": "A", "ws_cap": 8, "scan_id": "s2"})
    g.try_acquire("b1", {"ws": "B", "scan_id": "s3"})  # 全局满排队
    data = json.loads(sf.read_text())
    assert all(h["ws_cap"] == 2 for h in data["held"])
    assert data["waiting"][0].get("ws_cap") is None  # 未配置的 ws 不带键


def test_ws_cap_earlier_unblocked_waiter_still_wins():
    """跳过只发生在「被自己 ws cap 挡住」的 waiter 上：未被挡的更早者照旧优先。

    锁死原 FIFO 语义（test_fifo_earliest_waiter_wins_slot 的 ws-cap 版）——
    b1（ws=B 无 cap）排在 a3（ws=A 被挡）之前时，b1 poll 也不许越过未受阻的更早者。
    """
    g = _mk(capacity=1)
    g.try_acquire("x1", {"ws": "X"})          # 唯一槽
    g.try_acquire("b1", {"ws": "B"})          # earliest，未被挡
    g.try_acquire("a3", {"ws": "A", "ws_cap": 1})  # 更晚，且 A 持有 0 < 1 未挡
    g.release("x1")
    # a3 poll：b1 在前且未被挡 → a3 不能插队
    assert g.try_acquire("a3", {"ws": "A", "ws_cap": 1})["granted"] is False
    assert g.try_acquire("b1", {"ws": "B"})["granted"] is True


def test_preload_empty_ws_not_counted_for_ws_cap():
    """bootstrap 预占的 descriptor ws 为空串：不归属任何 ws 计数（重启窗口保守）。"""
    g = _mk(capacity=5)
    g.preload(["ghost1", "ghost2"])           # ws=""
    g.try_acquire("a1", {"ws": "A", "ws_cap": 1})   # A 计数 0（ghost 不算 A）
    g.try_acquire("a2", {"ws": "A", "ws_cap": 1})   # A 持有 1 >= 1 → 排队
    assert "a1" in g.held and "a2" in g.waiting


# ---- 重启恢复（2026-09-16 现场事故：ws cap 3 下排队 2 个突然自动开跑） ----

def test_preloaded_first_poll_respects_capacity():
    """bootstrap 未知预占者首次轮询：摘除自身预占后走正常准入，不无条件幂等放行。

    事故形态：worker 重启 → bootstrap 把闸门**排队中**的 workflow（排队者也是
    RUNNING）一并预占进 held → 排队者下一轮 try_acquire 命中幂等分支
    granted=True 直接开跑，绕过全局容量与 ws cap。capacity=1 时首 poll 必须
    仍受容量约束（预占同伴还占着唯一槽）。
    """
    g = _mk(capacity=1)
    g.preload(["a", "b"])                       # 模拟 bootstrap 预占两个 RUNNING
    assert g.try_acquire("a", {})["granted"] is False  # 摘除自身预占；b 的预占占着唯一槽
    assert g.try_acquire("b", {})["granted"] is False  # b 摘除预占；a 已先入列，FIFO 不插队
    assert g.try_acquire("a", {})["granted"] is True   # a earliest，容量空 → 正常准入


def test_restart_restore_keeps_ws_cap_queued(tmp_path):
    """复现 2026-09-16 现场：ws cap=3、同 ws 5 任务（3 跑 2 排队）→ worker 重启
    （快照恢复 held + visibility 预占全部 RUNNING）→ 排队者仍须被 ws cap 挡住。

    修复前：visibility 预占把排队者收进 held，其下一轮 poll 命中幂等放行直接
    开跑（用户看到「排队的突然自动跑了」+ 原 3 个因重启心跳停写显示已中断）。
    """
    sf = tmp_path / "gate_state.json"
    g = _mk(capacity=5, max_waiting=10, state_path=sf)
    desc = {"kind": "whitebox", "ws": "金融", "ws_cap": 3, "label": "r@main"}
    for i in range(3):
        g.try_acquire(f"w{i}", {**desc, "scan_id": f"s{i}"})
    assert g.try_acquire("w3", {**desc, "scan_id": "s3"})["granted"] is False
    assert g.try_acquire("w4", {**desc, "scan_id": "s4"})["granted"] is False

    # 模拟重启：内存闸门清零；bootstrap 先恢复快照 held，再 visibility 兜底预占
    g2 = _mk(capacity=5, max_waiting=10, state_path=sf)
    snap = read_gate_snapshot_file(sf)
    g2.restore_held(snap["held"])
    g2.preload(["w0", "w1", "w2", "w3", "w4"])
    assert g2.try_acquire("w3", {**desc, "scan_id": "s3"})["granted"] is False
    assert g2.try_acquire("w4", {**desc, "scan_id": "s4"})["granted"] is False
    assert set(g2.waiting) == {"w3", "w4"}


def test_restore_held_skips_waiting_no_ghost_fifo_blockers(tmp_path):
    """快照恢复只回 held（带真实 ws descriptor）：waiting 不恢复——排队 workflow
    5s 轮询自愈重新入列；恢复的幽灵 waiter 会永远挡 FIFO 头（已过闸者不再
    poll，无从确认存活）。恢复的真实 holder 幂等放行语义不变（continue-as-new
    交叉窗口依赖它）。"""
    sf = tmp_path / "gate_state.json"
    g = _mk(capacity=2, state_path=sf)
    g.try_acquire("h1", {"kind": "whitebox", "ws": "A", "scan_id": "s1"})
    g.try_acquire("w1", {"kind": "whitebox", "ws": "A", "scan_id": "s2"})

    g2 = _mk(capacity=2, state_path=sf)
    snap = read_gate_snapshot_file(sf)
    g2.restore_held(snap["held"])
    assert "h1" in g2.held and g2.held["h1"].descriptor["ws"] == "A"
    assert g2.waiting == {}
    # 真实 holder 再 poll（continue-as-new 交叉窗口）→ 幂等放行
    assert g2.try_acquire("h1", {"kind": "whitebox", "ws": "A"})["granted"] is True


def test_gate_ws_cap_from_overrides_parsing():
    """提交端解析 helper：int>=1 生效；未设/畸形/<=0 → None（不限），不 raise。"""
    from supernova_core.services.scan_gate import gate_ws_cap_from_overrides
    assert gate_ws_cap_from_overrides({"SUPERNOVA_WS_SCAN_CONCURRENCY": "2"}) == 2
    assert gate_ws_cap_from_overrides({"SUPERNOVA_WS_SCAN_CONCURRENCY": " 3 "}) == 3
    assert gate_ws_cap_from_overrides({}) is None
    assert gate_ws_cap_from_overrides(None) is None
    assert gate_ws_cap_from_overrides({"SUPERNOVA_WS_SCAN_CONCURRENCY": "abc"}) is None
    assert gate_ws_cap_from_overrides({"SUPERNOVA_WS_SCAN_CONCURRENCY": "0"}) is None
    assert gate_ws_cap_from_overrides({"SUPERNOVA_WS_SCAN_CONCURRENCY": "-1"}) is None


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
