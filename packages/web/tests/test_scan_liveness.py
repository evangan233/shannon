"""scan_liveness 判活测试:基于 heartbeat 文件 mtime(取代 workflow.log)。

设计见 docs/superpowers/specs/2026-07-09-web-scan-liveness-deep-rework-design.md §4.3/§5。
判活靠 heartbeat:scan worker 进程级 HeartbeatManager 周期写,worker 死则停写、mtime 转 stale。
"""
from __future__ import annotations

import json
import os
import time

from supernova_web.components.scan_liveness import is_scan_recently_active


def test_heartbeat_fresh_is_active(tmp_path):
    """heartbeat 存在且 mtime fresh → scan 存活。"""
    (tmp_path / "heartbeat").write_text(f"{time.time()}\n")
    assert is_scan_recently_active(tmp_path) is True


def test_heartbeat_stale_not_active(tmp_path):
    """heartbeat mtime 远古(>窗口)→ 已死/停滞。"""
    hb = tmp_path / "heartbeat"
    hb.write_text("x\n")
    old = time.time() - 3600
    os.utime(hb, (old, old))
    assert is_scan_recently_active(tmp_path) is False


def test_no_heartbeat_not_active(tmp_path):
    """无 heartbeat 文件 → 不判活(非 scan 或 scan 未起心跳)。"""
    assert is_scan_recently_active(tmp_path) is False


def test_workflow_log_no_longer_signals_active(tmp_path):
    """回归:判活信号源已从 workflow.log 换成 heartbeat。workflow.log fresh 不再判活。"""
    (tmp_path / "workflow.log").write_text("scan running\n")
    assert is_scan_recently_active(tmp_path) is False


def test_threshold_param_overrides_default(tmp_path):
    """threshold_seconds 参数显式覆盖窗口。"""
    hb = tmp_path / "heartbeat"
    hb.write_text("x\n")
    age = time.time() - 5
    os.utime(hb, (age, age))
    assert is_scan_recently_active(tmp_path, threshold_seconds=10) is True
    assert is_scan_recently_active(tmp_path, threshold_seconds=1) is False


def test_default_window_is_90(monkeypatch, tmp_path):
    """窗口默认 90s(原 900s 的回归窗口太宽,改 90 压缩「卡 Running」;spec §5)。"""
    monkeypatch.delenv("SUPERNOVA_SCAN_LIVENESS_SECONDS", raising=False)
    hb = tmp_path / "heartbeat"
    hb.write_text(f"{time.time()}\n")  # <90s → 活
    assert is_scan_recently_active(tmp_path) is True
    old = time.time() - 95  # >90s → 死
    os.utime(hb, (old, old))
    assert is_scan_recently_active(tmp_path) is False


# ---- 提交宽限门(C1 Phase B: worker 冷启动窗口防误杀) ----
# 根因:web 提交 workflow 后,worker 容器 poll 到 task + 写首个 heartbeat 前有几秒冷启动窗口。
# 此前 reconcile/_status_of 仅看 heartbeat → 提交后 1s 内前端 poll 即误判 interrupted(不可逆)。
# is_scan_alive = heartbeat fresh OR 提交宽限内(读 session.json submitted_at,回退 created_at)。

def test_submitted_at_within_grace_judged_alive(tmp_path, monkeypatch):
    """无 heartbeat + submitted_at 新(提交宽限内)→ is_scan_alive True。
    覆盖冷启动窗口:workflow 刚提交、worker 还没写首个 heartbeat。"""
    monkeypatch.setenv("SUPERNOVA_SCAN_LIVENESS_SUBMIT_GRACE_SECONDS", "120")
    (tmp_path / "session.json").write_text(json.dumps({"submitted_at": time.time()}))
    from supernova_web.components.scan_liveness import is_scan_alive
    assert is_scan_alive(tmp_path) is True


def test_created_at_fallback_when_no_submitted_at(tmp_path, monkeypatch):
    """老 session 无 submitted_at → 回退 created_at 判宽限(向后兼容历史 session)。"""
    monkeypatch.setenv("SUPERNOVA_SCAN_LIVENESS_SUBMIT_GRACE_SECONDS", "120")
    (tmp_path / "session.json").write_text(json.dumps({"created_at": time.time()}))
    from supernova_web.components.scan_liveness import (
        is_scan_alive, is_scan_within_submit_grace,
    )
    assert is_scan_within_submit_grace(tmp_path) is True
    assert is_scan_alive(tmp_path) is True


def test_is_scan_alive_heartbeat_or_grace(tmp_path):
    """is_scan_alive = heartbeat fresh OR 提交宽限内(任一 True)。heartbeat fresh 即可。"""
    from supernova_web.components.scan_liveness import is_scan_alive
    (tmp_path / "heartbeat").write_text(f"{time.time()}\n")
    assert is_scan_alive(tmp_path) is True


def test_submit_grace_expired_not_alive(tmp_path, monkeypatch):
    """提交超宽限 + 无 heartbeat → is_scan_alive False(真孤儿:worker 没起/已退出)。"""
    monkeypatch.setenv("SUPERNOVA_SCAN_LIVENESS_SUBMIT_GRACE_SECONDS", "120")
    old = time.time() - 3600
    (tmp_path / "session.json").write_text(json.dumps({"submitted_at": old}))
    from supernova_web.components.scan_liveness import is_scan_alive
    assert is_scan_alive(tmp_path) is False


# ---- 组合扫描 run 级 heartbeat（黑盒 run 阶段判活，2026-08-17 根因修） ----
# 黑盒 run 阶段 worker 的 workspace_path=run 子目录（按 event_file.parent 推导），heartbeat
# 落 blackbox-runs/run-K/heartbeat，任务根 heartbeat 随白盒 finalize stop 而 stale——判活
# 须覆盖子目录，否则 run 阶段 > 提交宽限(120s) 后被误判 interrupted。

def test_run_heartbeat_fresh_is_active(tmp_path, monkeypatch):
    """任务根 heartbeat stale + run-K heartbeat fresh → 活（黑盒 run 阶段）。"""
    monkeypatch.delenv("SUPERNOVA_SCAN_LIVENESS_SUBMIT_GRACE_SECONDS", raising=False)
    (tmp_path / "session.json").write_text(json.dumps({"submitted_at": time.time() - 3600}))
    run_hb = tmp_path / "blackbox-runs" / "run-1" / "heartbeat"
    run_hb.parent.mkdir(parents=True)
    run_hb.write_text(f"{time.time()}\n")
    from supernova_web.components.scan_liveness import is_scan_alive
    assert is_scan_recently_active(tmp_path) is True
    assert is_scan_alive(tmp_path) is True


def test_authcheck_heartbeat_fresh_is_active(tmp_path, monkeypatch):
    """认证预验证段：.authcheck/heartbeat fresh → 活（precheck 可达数分钟）。"""
    monkeypatch.delenv("SUPERNOVA_SCAN_LIVENESS_SUBMIT_GRACE_SECONDS", raising=False)
    (tmp_path / "session.json").write_text(json.dumps({"submitted_at": time.time() - 3600}))
    probe = tmp_path / ".authcheck"
    probe.mkdir()
    (probe / "heartbeat").write_text(f"{time.time()}\n")
    from supernova_web.components.scan_liveness import is_scan_alive
    assert is_scan_alive(tmp_path) is True


def test_all_heartbeats_stale_not_active(tmp_path, monkeypatch):
    """任务根 + 多个 run heartbeat 全 stale → 死（worker 全退）。"""
    monkeypatch.delenv("SUPERNOVA_SCAN_LIVENESS_SUBMIT_GRACE_SECONDS", raising=False)
    (tmp_path / "session.json").write_text(json.dumps({"submitted_at": time.time() - 3600}))
    old = time.time() - 3600
    for hb in (tmp_path / "heartbeat",
               tmp_path / "blackbox-runs" / "run-1" / "heartbeat",
               tmp_path / "blackbox-runs" / "run-2" / "heartbeat"):
        hb.parent.mkdir(parents=True, exist_ok=True)
        hb.write_text("x\n")
        os.utime(hb, (old, old))
    from supernova_web.components.scan_liveness import is_scan_alive
    assert is_scan_alive(tmp_path) is False


def test_compute_status_running_via_run_heartbeat(tmp_path, monkeypatch):
    """集成：任务级 status=running（run 阶段）+ run heartbeat fresh → _compute_status
    running；heartbeat 全 stale → reconnecting（等待 Temporal 对账，不可直接续跑）。"""
    monkeypatch.delenv("SUPERNOVA_SCAN_LIVENESS_SUBMIT_GRACE_SECONDS", raising=False)
    (tmp_path / "session.json").write_text(json.dumps({
        "status": "running", "submitted_at": time.time() - 3600}))
    run_hb = tmp_path / "blackbox-runs" / "run-1" / "heartbeat"
    run_hb.parent.mkdir(parents=True)
    run_hb.write_text(f"{time.time()}\n")
    from supernova_web.components.workspaces_indexer import _compute_status
    assert _compute_status(tmp_path, "running") == "running"
    old = time.time() - 3600
    os.utime(run_hb, (old, old))
    assert _compute_status(tmp_path, "running") == "reconnecting"
