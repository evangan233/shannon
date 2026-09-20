"""scan_manager.rerun（2026-09-20 批量重跑）：终态 scan 读 session.json 重建 ScanRequest
-> start() 起新 scan（新 scan_id，原行不动）。字段映射对齐 _scan_detail 重跑预填口径
（前端 onRerun 同源）：source_repo / mr refs+commits / bb_url / bb_auth_ref(profile 引用)
/ scan-config.yaml inline authentication / host_config(profile 引用|url)。

重建不可行 -> ValueError（端点层转 skipped）：
- correlation：多仓 yaml 配置不可从 session 重建（单行重跑走手填表单）；
- blackbox：与单行重跑口径一致（黑盒是白盒下游段，无独立重跑）；
- 非终态 / 不存在：状态门（对齐 batch-cancel/batch-delete 服务端挡漂移先例）。
"""
import json
import time
from pathlib import Path

import pytest

from supernova_web.models import RepoSource, ScanRequest
from supernova_web.components.scan_manager import ScanManager


def _make_scan_dir(workspaces_dir, ws, scan_id="20260727-120000", status="cancelled", **sess):
    """直写 session.json（不经 start，免 temporal）；额外字段经 kwargs 落盘。"""
    scan_dir = Path(workspaces_dir) / ws / "scans" / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)
    data = {"status": status, "scan_type": "whitebox", "created_at": time.time(),
            "web_url": "", "repo_path": ""}
    data.update(sess)
    (scan_dir / "session.json").write_text(json.dumps(data))
    return scan_dir


def _capture_start(monkeypatch, mgr, new_scan_id="new-scan-1"):
    """mock mgr.start：捕获重建后的 ScanRequest，免走 temporal 链路（start 自身有测）。"""
    captured: dict = {}

    async def fake_start(req):
        captured["req"] = req
        return ("WS", new_scan_id)

    monkeypatch.setattr(mgr, "start", fake_start)
    return captured


# ── 白盒重建 ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_rerun_whitebox_rebuilds_repo_source(tmp_path, monkeypatch):
    """白盒：source_repo -> source=repo；type/workspace 透传；起新 scan_id。"""
    mgr = ScanManager(tmp_path, tmp_path / "repos", None)
    _make_scan_dir(tmp_path, "WS", "s1", status="failed", source_repo="group/repo-a")
    captured = _capture_start(monkeypatch, mgr)

    new_ws, new_scan_id = await mgr.rerun("WS", "s1")

    assert (new_ws, new_scan_id) == ("WS", "new-scan-1")
    req = captured["req"]
    assert req.type == "whitebox"
    assert req.workspace == "WS"
    assert req.source == RepoSource(kind="repo", value="group/repo-a")
    assert req.url is None


@pytest.mark.asyncio
async def test_rerun_whitebox_source_repo_falls_back_to_repo_path_basename(tmp_path, monkeypatch):
    """存量行缺 source_repo（precheck 失败时序 bug）-> repo_path basename 兜底，
    对齐 _scan_detail 重跑预填口径。"""
    mgr = ScanManager(tmp_path, tmp_path / "repos", None)
    _make_scan_dir(tmp_path, "WS", "s1", status="cancelled", repo_path="/code/group/repo-b")
    captured = _capture_start(monkeypatch, mgr)

    await mgr.rerun("WS", "s1")

    assert captured["req"].source == RepoSource(kind="repo", value="repo-b")


# ── 组合（whitebox + 黑盒段）重建 ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_rerun_combined_carries_url_profile_auth_and_hosts(tmp_path, monkeypatch):
    """组合：bb_url -> url；bb_auth_ref profile 引用 -> auth_profile_id/cred_ids；
    host_config profile 源 -> host_profile_ids。profile 模式不带 inline authentication
    （ScanRequest _auth_profile_xor_inline 互斥）。"""
    mgr = ScanManager(tmp_path, tmp_path / "repos", None)
    _make_scan_dir(tmp_path, "WS", "s1", status="cancelled",
                   source_repo="repo-a", bb_url="http://target",
                   bb_auth_ref={"profile_id": "p1", "cred_id": None, "cred_ids": ["c1", "c2"]},
                   host_config={"enabled": True, "source": "profile",
                                "profile_ids": ["h1", "h2"], "profile_id": "h1",
                                "mappings": {}})
    captured = _capture_start(monkeypatch, mgr)

    await mgr.rerun("WS", "s1")

    req = captured["req"]
    assert req.type == "whitebox"
    assert req.url == "http://target"
    assert req.auth_profile_id == "p1"
    assert req.auth_credential_ids == ["c1", "c2"]
    assert req.authentication is None
    assert req.host_profile_ids == ["h1", "h2"]


@pytest.mark.asyncio
async def test_rerun_combined_inline_auth_read_from_scan_config(tmp_path, monkeypatch):
    """inline 认证：bb_auth_ref.profile_id=None -> 从 scan-config.yaml 回读明文
    （认证明文不进 session.json（D2），唯一来源是该文件——与单行重跑预填同源）。"""
    mgr = ScanManager(tmp_path, tmp_path / "repos", None)
    scan_dir = _make_scan_dir(tmp_path, "WS", "s1", status="cancelled",
                              source_repo="repo-a", bb_url="http://target",
                              bb_auth_ref={"profile_id": None})
    inline_auth = {"login_type": "form", "login_url": "http://target/login",
                   "credentials": [{"username": "u", "password": "p"}]}
    (scan_dir / "scan-config.yaml").write_text(
        json.dumps({"authentication": inline_auth}))  # JSON ⊂ YAML，免 yaml 依赖差异
    captured = _capture_start(monkeypatch, mgr)

    await mgr.rerun("WS", "s1")

    req = captured["req"]
    assert req.authentication == inline_auth
    assert req.auth_profile_id is None


@pytest.mark.asyncio
async def test_rerun_combined_host_url_source(tmp_path, monkeypatch):
    """HOST url 源：host_config.source_url -> host_url（无档案引用）。"""
    mgr = ScanManager(tmp_path, tmp_path / "repos", None)
    _make_scan_dir(tmp_path, "WS", "s1", status="failed",
                   source_repo="repo-a", bb_url="http://target",
                   host_config={"enabled": True, "source": "url",
                                "source_url": "http://hosts/file", "mappings": {}})
    captured = _capture_start(monkeypatch, mgr)

    await mgr.rerun("WS", "s1")

    req = captured["req"]
    assert req.host_url == "http://hosts/file"
    assert req.host_profile_ids is None


# ── MR 重建 ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_rerun_mr_carries_refs_and_commits(tmp_path, monkeypatch):
    """MR：refs + merged 改道 commit 对全透传（重跑走 commit 对，不撞已删源分支）。"""
    mgr = ScanManager(tmp_path, tmp_path / "repos", None)
    _make_scan_dir(tmp_path, "WS", "s1", status="cancelled", scan_type="mr",
                   source_repo="repo-a", mr_base_ref="main", mr_head_ref="feat/x",
                   mr_head_commit="abc1234", mr_base_commit="def5678")
    captured = _capture_start(monkeypatch, mgr)

    await mgr.rerun("WS", "s1")

    req = captured["req"]
    assert req.type == "mr"
    assert req.source == RepoSource(kind="repo", value="repo-a")
    assert req.base_ref == "main"
    assert req.head_ref == "feat/x"
    assert req.head_commit == "abc1234"
    assert req.base_commit == "def5678"


# ── 拒绝路径 ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_rerun_rejects_correlation(tmp_path, monkeypatch):
    """correlation 多仓 yaml 不可重建 -> ValueError；不触 start。"""
    mgr = ScanManager(tmp_path, tmp_path / "repos", None)
    _make_scan_dir(tmp_path, "WS", "s1", status="completed", scan_type="correlation")
    captured = _capture_start(monkeypatch, mgr)

    with pytest.raises(ValueError, match="跨仓"):
        await mgr.rerun("WS", "s1")
    assert "req" not in captured


@pytest.mark.asyncio
async def test_rerun_rejects_blackbox(tmp_path, monkeypatch):
    """黑盒与单行重跑口径一致（白盒下游段，无独立重跑）-> ValueError。"""
    mgr = ScanManager(tmp_path, tmp_path / "repos", None)
    _make_scan_dir(tmp_path, "WS", "s1", status="completed", scan_type="blackbox")
    captured = _capture_start(monkeypatch, mgr)

    with pytest.raises(ValueError, match="黑盒"):
        await mgr.rerun("WS", "s1")
    assert "req" not in captured


@pytest.mark.asyncio
async def test_rerun_state_gate_rejects_running(tmp_path, monkeypatch):
    """状态门：running 拒绝（防勾选到确认间状态漂移——对齐批量取消服务端挡先例）。"""
    mgr = ScanManager(tmp_path, tmp_path / "repos", None)
    _make_scan_dir(tmp_path, "WS", "s1", status="running")
    captured = _capture_start(monkeypatch, mgr)

    with pytest.raises(ValueError, match="状态"):
        await mgr.rerun("WS", "s1")
    assert "req" not in captured


@pytest.mark.asyncio
async def test_rerun_missing_scan_rejected(tmp_path, monkeypatch):
    """不存在 -> ValueError（非终态集成员之外的 None 同门处理）。"""
    mgr = ScanManager(tmp_path, tmp_path / "repos", None)
    captured = _capture_start(monkeypatch, mgr)

    with pytest.raises(ValueError, match="不存在"):
        await mgr.rerun("WS", "nope")
    assert "req" not in captured
