"""组合扫描 precheck 失败时 source_repo 仍须落盘（2026-09-04 重跑不预填仓库事故）。

根因：source_repo 原只在 precheck 成功后的 _submit_whitebox 旁写入（start 同步分支
+ _combined_kickoff），precheck 失败（认证失败 / 目标不可达）提前 return → 永不写入。
重跑最常发生在 failed 扫描上 → ScanList.onRerun 拿不到 detail.source_repo → 仓库不预填。

契约：
- 组合分支在 precheck 之前（写 combined/bb_url 的同一 update_session）写 source_repo
  ——同步路径（公开目标）与异步路径（带认证 kickoff）都覆盖，precheck 结果不再影响。
- _scan_detail 对历史存量（precheck 失败 + 未写 source_repo 的 session）从 repo_path
  basename 兜底（web 入口仓库名默认 flat 命名 = basename），重跑预填可恢复。
"""
import json
import time
from unittest.mock import AsyncMock, patch

from supernova_web.components.scan_manager import ScanManager
from supernova_web.models import RepoSource, ScanRequest


def _mgr(tmp_path):
    return ScanManager(tmp_path, tmp_path / "repos", None)


async def _ok():
    return None


def _make_repo(tmp_path, ws="WS", name="nodegoat"):
    """建 workspaces/<ws>/repos/<name>/（无 meta 文件 → state=ready 默认）。"""
    repo_dir = tmp_path / ws / "repos" / name
    repo_dir.mkdir(parents=True)
    return repo_dir


def _combined_req(**kw) -> ScanRequest:
    base = {
        "type": "whitebox",
        "source": RepoSource(kind="repo", value="nodegoat"),
        "url": "http://target.example/",
        "workspace": "WS",
    }
    base.update(kw)
    return ScanRequest(**base)


def _session(tmp_path, scan_id):
    return json.loads(
        (tmp_path / "WS" / "scans" / scan_id / "session.json").read_text("utf-8"))


async def _drain(mgr):
    for t in list(mgr._orchestrator_tasks.values()):
        if not t.done():
            await t


# ── 写路径：precheck 失败也落 source_repo ──────────────────────────────────

async def test_combined_auth_precheck_fail_still_writes_source_repo(tmp_path, monkeypatch):
    """带认证组合（异步 kickoff 路径）precheck 失败 → session 仍有 source_repo + failed 终态。

    事故场景（NodeGoat-20260901-173719）：带 form 认证提交组合扫描，目标容器挂了 →
    precheck Connection error → 任务 failed，但重跑需要 source_repo。
    """
    mgr = _mgr(tmp_path)
    monkeypatch.setattr(mgr, "_check_temporal", _ok)
    _make_repo(tmp_path)

    with patch.object(mgr, "_run_precheck", new=AsyncMock(return_value=False)):
        ws, scan_id = await mgr.start(_combined_req(authentication={
            "login_type": "form", "login_url": "http://target.example/login",
            "credentials": {"username": "a", "password": "secret"}}))
    await _drain(mgr)

    sess = _session(tmp_path, scan_id)
    assert sess["status"] == "failed"  # 场景锚定：precheck 失败终态
    assert sess["combined"] is True
    assert sess["source_repo"] == "nodegoat"


async def test_combined_public_precheck_fail_still_writes_source_repo(tmp_path, monkeypatch):
    """公开目标组合（同步路径，无认证）precheck 失败 → 同样落 source_repo。"""
    mgr = _mgr(tmp_path)
    monkeypatch.setattr(mgr, "_check_temporal", _ok)
    _make_repo(tmp_path)

    with patch.object(mgr, "_run_precheck", new=AsyncMock(return_value=False)):
        ws, scan_id = await mgr.start(_combined_req())
    await _drain(mgr)

    sess = _session(tmp_path, scan_id)
    assert sess["status"] == "failed"
    assert sess["source_repo"] == "nodegoat"


# ── 读路径：历史存量兜底（repo_path basename）─────────────────────────────

def _detail(tmp_path, session: dict):
    from supernova_web.api.scans import _scan_detail
    scan_dir = tmp_path / "WS" / "scans" / "s1"
    scan_dir.mkdir(parents=True)
    session.setdefault("created_at", time.time())
    session.setdefault("scan_type", "whitebox")
    (scan_dir / "session.json").write_text(json.dumps(session), encoding="utf-8")

    class _FakeIndexer:
        def _status_of(self, scan_dir, raw):
            return session.get("status", "failed")

    class _FakeState:
        indexer = _FakeIndexer()

    class _FakeApp:
        state = _FakeState()

    class _FakeRequest:
        app = _FakeApp()

    return _scan_detail(_FakeRequest(), "WS", "s1", scan_dir)


def test_scan_detail_falls_back_to_repo_path_basename(tmp_path):
    """历史组合扫描（source_repo 缺失 + precheck 失败终态）→ repo_path basename 兜底。"""
    d = _detail(tmp_path, {
        "status": "failed", "combined": True, "bb_phase": "failed",
        "repo_path": "/app/repos/NodeGoat", "web_url": "http://e", "owner": "web"})
    assert d["source_repo"] == "NodeGoat"


def test_scan_detail_prefers_persisted_source_repo(tmp_path):
    """已有 source_repo（含 group/repo 形态）优先——兜底不覆盖正路写入。"""
    d = _detail(tmp_path, {
        "status": "completed", "repo_path": "/app/repos/group/repo-a",
        "source_repo": "group/repo-a", "web_url": "http://e", "owner": "web"})
    assert d["source_repo"] == "group/repo-a"


def test_scan_detail_no_repo_path_keeps_none(tmp_path):
    """无 repo_path（如黑盒复用行 repo_path=""）→ source_repo 维持 None（不造假值）。"""
    d = _detail(tmp_path, {
        "status": "failed", "repo_path": "", "web_url": "http://e", "owner": "web"})
    assert d["source_repo"] is None
