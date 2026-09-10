"""扫完即删（delete_repo_on_finish，2026-09-10）：

启动扫描可勾选「扫完即删」（默认不勾）——扫描到任意终态后删除对应仓库。
- 标志挂扫描行 session（delete_repo_on_finish）；correlation 传播给本次新建子仓行
  （复用已有 scan 的子项无新行，不涉及）。
- 删除 = web 侧仓库级 sweep：该 repo 存在带标志的终态扫描 && 无任何引用它的扫描
  在跑/排队（scan_end 事件 + effective status 判活，组合扫描看黑盒 run 阶段）&&
  非 linked 仓（linked 完全不处理）→ repo_manager.delete()（私有克隆 rmtree）。
- 触发点：_watch finally（扫描终态）/ web 启动全量兜底。
"""
import asyncio
import json
import time
from pathlib import Path

import pytest

from supernova_web.components.repo_manager import RepoManager, read_linked_repos, write_linked_repos
from supernova_web.components.scan_manager import ScanManager
from supernova_web.models import RepoSource, ScanRequest


# ── 构造 helpers ────────────────────────────────────────────────────────────

def _mk_repo(ws_root: Path, ws: str, name: str) -> Path:
    """造 ws 内私有克隆仓库目录（.git + meta，repo_manager.delete 认的真仓库）。"""
    d = ws_root / ws / "repos" / name
    d.mkdir(parents=True, exist_ok=True)
    (d / ".git").mkdir(exist_ok=True)
    (d / ".supernova-repo.json").write_text(json.dumps(
        {"name": name, "state": "ready"}))
    return d


def _mk_scan(ws_root: Path, ws: str, scan_id: str, *, status="completed",
             source_repo=None, flag=False, scan_end=True, extra=None):
    """直接落一个 scan 行（不经 start，免 temporal）。scan_end=True 写终态事件。"""
    sd = ws_root / ws / "scans" / scan_id
    sd.mkdir(parents=True, exist_ok=True)
    sess = {"status": status, "scan_type": "whitebox", "created_at": time.time(),
            "web_url": "", "repo_path": source_repo or "", "owner": "web"}
    if source_repo:
        sess["source_repo"] = source_repo
    if flag:
        sess["delete_repo_on_finish"] = True
    sess.update(extra or {})
    (sd / "session.json").write_text(json.dumps(sess))
    if scan_end:
        (sd / "events.ndjson").write_text(
            json.dumps({"type": "scan_end", "status": status}) + "\n")
    return sd


def _mk_mgr(ws_root: Path, with_rm=True, config_store=None) -> tuple[ScanManager, RepoManager | None]:
    rm = RepoManager(ws_root, None) if with_rm else None
    return ScanManager(ws_root, ws_root / "_global_repos", config_store,
                       repo_manager=rm), rm


# ── sweep 条件分支 ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_sweep_deletes_flagged_terminal_repo(tmp_path):
    """带标志终态扫描 + 无活跃引用 → 仓库被删，返回仓库名。"""
    ws_root = tmp_path / "ws-root"
    repo = _mk_repo(ws_root, "ws1", "r1")
    _mk_scan(ws_root, "ws1", "s1", source_repo="r1", flag=True)
    mgr, _rm = _mk_mgr(ws_root)
    deleted = await mgr.sweep_delete_flagged_repos("ws1")
    assert deleted == ["r1"]
    assert not repo.exists()


@pytest.mark.asyncio
async def test_sweep_keeps_unflagged_repo(tmp_path):
    """无标志（默认）→ 永不动仓库。"""
    ws_root = tmp_path / "ws-root"
    repo = _mk_repo(ws_root, "ws1", "r1")
    _mk_scan(ws_root, "ws1", "s1", source_repo="r1", flag=False)
    mgr, _rm = _mk_mgr(ws_root)
    assert await mgr.sweep_delete_flagged_repos("ws1") == []
    assert repo.exists()


@pytest.mark.asyncio
async def test_sweep_keeps_repo_while_flag_scan_running(tmp_path):
    """标志扫描还在跑（无 scan_end + 心跳新鲜）→ 不删。"""
    ws_root = tmp_path / "ws-root"
    repo = _mk_repo(ws_root, "ws1", "r1")
    sd = _mk_scan(ws_root, "ws1", "s1", status="running",
                  source_repo="r1", flag=True, scan_end=False)
    (sd / "heartbeat").write_text("{}")  # 心跳新鲜 → is_scan_alive → running
    mgr, _rm = _mk_mgr(ws_root)
    assert await mgr.sweep_delete_flagged_repos("ws1") == []
    assert repo.exists()


@pytest.mark.asyncio
async def test_sweep_protects_shared_repo_with_other_running_scan(tmp_path):
    """共享仓库：标志扫描终态，但同仓另一扫描在跑（内存引用锁）→ 不删。"""
    ws_root = tmp_path / "ws-root"
    repo = _mk_repo(ws_root, "ws1", "r1")
    _mk_scan(ws_root, "ws1", "s1", source_repo="r1", flag=True)
    _mk_scan(ws_root, "ws1", "s2", status="running",
             source_repo="r1", flag=False, scan_end=False)
    mgr, _rm = _mk_mgr(ws_root)
    # s2 在跑：内存登记（start 时真实路径；此处直填模拟）
    mgr._active_reqs[("ws1", "s2")] = ScanRequest(
        type="whitebox", source=RepoSource(kind="repo", value="r1"), workspace="ws1")
    assert await mgr.sweep_delete_flagged_repos("ws1") == []
    assert repo.exists()


@pytest.mark.asyncio
async def test_sweep_skips_linked_repo_entirely(tmp_path):
    """linked 仓不处理：不删源目录、不解引用（linked_repos.json 原样）。"""
    ws_root = tmp_path / "ws-root"
    ext = tmp_path / "external" / "shared"
    ext.mkdir(parents=True)
    (ext / ".git").mkdir()
    write_linked_repos(ws_root / "ws1", [
        {"name": "linked-r", "path": str(ext), "linked_at": "x"}])
    _mk_scan(ws_root, "ws1", "s1", source_repo="linked-r", flag=True)
    mgr, _rm = _mk_mgr(ws_root)
    assert await mgr.sweep_delete_flagged_repos("ws1") == []
    assert ext.exists()  # 源目录不动
    links = read_linked_repos(ws_root / "ws1")
    assert [l["name"] for l in links] == ["linked-r"]  # 引用记录不动


@pytest.mark.asyncio
async def test_sweep_noop_without_repo_manager(tmp_path):
    """repo_manager 未注入（旧测试/CLI 兜底构造）→ no-op 不炸。"""
    ws_root = tmp_path / "ws-root"
    repo = _mk_repo(ws_root, "ws1", "r1")
    _mk_scan(ws_root, "ws1", "s1", source_repo="r1", flag=True)
    mgr, _rm = _mk_mgr(ws_root, with_rm=False)
    assert await mgr.sweep_delete_flagged_repos("ws1") == []
    assert repo.exists()


@pytest.mark.asyncio
async def test_sweep_combined_scan_protected_until_bb_done(tmp_path):
    """组合扫描：白盒 session 已 completed 但黑盒 run 还在跑 → 保护；
    黑盒阶段完成 + scan_end → 删除。"""
    ws_root = tmp_path / "ws-root"
    repo = _mk_repo(ws_root, "ws1", "r1")
    _mk_scan(ws_root, "ws1", "s1", status="completed", source_repo="r1", flag=True,
             scan_end=False, extra={"combined": True, "latest_bb_run": "run-1",
                                    "bb_runs": [{"run_id": "run-1", "status": "running"}]})
    run_dir = ws_root / "ws1" / "scans" / "s1" / "blackbox-runs" / "run-1"
    run_dir.mkdir(parents=True)
    (run_dir / "session.json").write_text(json.dumps({"bb_phase": "running"}))
    mgr, _rm = _mk_mgr(ws_root)
    assert await mgr.sweep_delete_flagged_repos("ws1") == []  # 黑盒在跑 → 不删
    assert repo.exists()
    # 黑盒完成 + scan_end 落盘 → 可删
    (run_dir / "session.json").write_text(json.dumps({"bb_phase": "completed"}))
    (ws_root / "ws1" / "scans" / "s1" / "events.ndjson").write_text(
        json.dumps({"type": "scan_end", "status": "completed"}) + "\n")
    assert await mgr.sweep_delete_flagged_repos("ws1") == ["r1"]
    assert not repo.exists()


@pytest.mark.asyncio
async def test_sweep_deletes_after_interrupted_scan(tmp_path):
    """任何终态都删：interrupted（无 scan_end、心跳死且超提交宽限）也算完毕。"""
    ws_root = tmp_path / "ws-root"
    repo = _mk_repo(ws_root, "ws1", "r1")
    # created_at 拨回 2h 前：模拟真实孤儿（刚提交的行在提交宽限内会被正确保护）。
    sd = _mk_scan(ws_root, "ws1", "s1", status="running",
                  source_repo="r1", flag=True, scan_end=False)
    sess_path = sd / "session.json"
    sess = json.loads(sess_path.read_text())
    sess["created_at"] = time.time() - 7200
    sess_path.write_text(json.dumps(sess))
    mgr, _rm = _mk_mgr(ws_root)
    assert await mgr.sweep_delete_flagged_repos("ws1") == ["r1"]
    assert not repo.exists()


@pytest.mark.asyncio
async def test_sweep_missing_repo_dir_is_noop(tmp_path):
    """仓库已被手动删除 → 扫描行残留标志也无害（不炸、不重复报）。"""
    ws_root = tmp_path / "ws-root"
    _mk_scan(ws_root, "ws1", "s1", source_repo="gone", flag=True)
    mgr, _rm = _mk_mgr(ws_root)
    assert await mgr.sweep_delete_flagged_repos("ws1") == []


@pytest.mark.asyncio
async def test_sweep_nonexistent_ws_is_noop(tmp_path):
    mgr, _rm = _mk_mgr(tmp_path / "ws-root")
    assert await mgr.sweep_delete_flagged_repos("nope") == []


# ── 触发点 ──────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_watch_finish_triggers_sweep(tmp_path):
    """_watch 退出（见 scan_end）的 finally 触发 sweep → 仓库被删。"""
    ws_root = tmp_path / "ws-root"
    repo = _mk_repo(ws_root, "ws1", "r1")
    sd = _mk_scan(ws_root, "ws1", "s1", source_repo="r1", flag=True)
    mgr, _rm = _mk_mgr(ws_root)
    await mgr._watch(("ws1", "s1"), sd / "events.ndjson", sd)
    assert not repo.exists()


@pytest.mark.asyncio
async def test_sweep_all_workspaces_startup_entry(tmp_path):
    """启动兜底：全量 sweep 各 ws（一个可删、一个不可删）。"""
    ws_root = tmp_path / "ws-root"
    dele = _mk_repo(ws_root, "ws1", "r1")
    keep = _mk_repo(ws_root, "ws2", "r2")
    _mk_scan(ws_root, "ws1", "s1", source_repo="r1", flag=True)
    _mk_scan(ws_root, "ws2", "s2", source_repo="r2", flag=False)
    mgr, _rm = _mk_mgr(ws_root)
    n = await mgr.sweep_all_workspaces()
    assert n == 1
    assert not dele.exists()
    assert keep.exists()


# ── 标志落盘（start 链路）──────────────────────────────────────────────────

async def _temporal_ok():
    return None


@pytest.mark.asyncio
async def test_start_whitebox_persists_delete_flag(tmp_path, monkeypatch):
    """start（白盒）勾选 → scan session 落 delete_repo_on_finish=True。"""
    from unittest.mock import AsyncMock, MagicMock
    ws_root = tmp_path / "ws-root"
    _mk_repo(ws_root, "ws1", "r1")
    mgr, _rm = _mk_mgr(ws_root)
    monkeypatch.setattr(mgr, "_check_temporal", _temporal_ok)
    mock_client = AsyncMock()
    mock_client.start_workflow = AsyncMock(return_value=MagicMock())
    monkeypatch.setattr("supernova_web.components.scan_manager.Client.connect",
                        AsyncMock(return_value=mock_client))
    ws, scan_id = await mgr.start(ScanRequest(
        type="whitebox", source=RepoSource(kind="repo", value="r1"),
        workspace="ws1", delete_repo_on_finish=True))
    sess = json.loads((ws_root / ws / "scans" / scan_id / "session.json").read_text())
    assert sess["delete_repo_on_finish"] is True
    assert sess["source_repo"] == "r1"


@pytest.mark.asyncio
async def test_start_whitebox_default_no_flag(tmp_path, monkeypatch):
    """默认不勾 → session 无该键（字节不变，向后兼容）。"""
    from unittest.mock import AsyncMock, MagicMock
    ws_root = tmp_path / "ws-root"
    _mk_repo(ws_root, "ws1", "r1")
    mgr, _rm = _mk_mgr(ws_root)
    monkeypatch.setattr(mgr, "_check_temporal", _temporal_ok)
    mock_client = AsyncMock()
    mock_client.start_workflow = AsyncMock(return_value=MagicMock())
    monkeypatch.setattr("supernova_web.components.scan_manager.Client.connect",
                        AsyncMock(return_value=mock_client))
    _ws, scan_id = await mgr.start(ScanRequest(
        type="whitebox", source=RepoSource(kind="repo", value="r1"),
        workspace="ws1"))
    sess = json.loads((ws_root / "ws1" / "scans" / scan_id / "session.json").read_text())
    assert "delete_repo_on_finish" not in sess


@pytest.mark.asyncio
async def test_start_correlation_propagates_flag_to_new_children(tmp_path, monkeypatch):
    """跨仓勾选 → 本次新建子仓行落 flag + source_repo；复用子仓不落（无新行）。"""
    ws_root = tmp_path / "ws-root"
    _mk_repo(ws_root, "ws", "frontend")
    _mk_repo(ws_root, "ws", "order-svc")
    # 种可复用白盒（order-svc 换成复用，验证复用子仓不传播）
    reused_dir = ws_root / "ws" / "scans" / "reused-1"
    reused_dir.mkdir(parents=True)
    (reused_dir / "session.json").write_text(json.dumps(
        {"status": "completed", "scan_type": "whitebox", "created_at": time.time(),
         "web_url": "", "repo_path": "x", "source_repo": "order-svc"}))
    (reused_dir / "deliverables").mkdir()
    (reused_dir / "deliverables" / "injection_exploitation_queue.json").write_text(
        json.dumps({"vulnerabilities": []}))

    from supernova_web.components.multi_repo_config_store import MultiRepoConfigStore
    mgr, _rm = _mk_mgr(ws_root, config_store=MultiRepoConfigStore(ws_root / "configs"))
    monkeypatch.setattr(mgr, "_check_temporal", _temporal_ok)

    class _FakeHandle:
        def __init__(self, tag):
            self.tag = tag

    async def fake_submit_whitebox(self, target, ws, scan_id, scan_dir, event_file,
                                   web_url, combined=False):
        return _FakeHandle(f"wb:{scan_id}")

    async def fake_submit_correlation(self, config_path, repo_workspace_paths,
                                      out_ws_dir, event_file, ws):
        return _FakeHandle("corr")

    async def fake_await(self, handle, attempts=5, backoff_base=2.0):
        return {"status": "completed"}

    monkeypatch.setattr(type(mgr), "_submit_whitebox", fake_submit_whitebox)
    monkeypatch.setattr(type(mgr), "_submit_correlation", fake_submit_correlation)
    monkeypatch.setattr(type(mgr), "_await_workflow_result", fake_await)

    yaml_text = (
        "repos:\n"
        "  frontend: {path: frontend, role: entrypoint}\n"
        "  order-svc: {workspace: reused-1}\n"
        "relations:\n  - {from: frontend, to: order-svc, protocol: grpc}\n"
        "correlation:\n  out_workspace: placeholder\n")
    ws, scan_id = await mgr.start(ScanRequest(
        type="correlation", workspace="ws", config_content=yaml_text,
        delete_repo_on_finish=True))
    # 等编排 task 跑完（fake await 即时完成）
    orch = mgr._orchestrator_tasks.get((ws, scan_id))
    if orch is not None:
        await orch
    watch = mgr._tasks.get((ws, scan_id))
    if watch is not None:
        try:
            await asyncio.wait_for(asyncio.shield(watch), timeout=5)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            pass

    from supernova_web.components.scan_store import ScanStore
    scans = ScanStore(ws_root).list_scans("ws")
    by_type = {s.scan_id: s for s in scans}
    assert scan_id in by_type and by_type[scan_id].scan_type == "correlation"
    # 主行不携带仓库引用（repos 在 yaml 里，不在 source）
    main_sess = json.loads(
        (ws_root / "ws" / "scans" / scan_id / "session.json").read_text())
    assert "delete_repo_on_finish" not in main_sess
    # 新建子仓行（frontend）落 flag + source_repo
    child = next(s for s in scans
                 if s.scan_type == "whitebox" and s.repo == "frontend")
    child_sess = json.loads(
        (ws_root / "ws" / "scans" / child.scan_id / "session.json").read_text())
    assert child_sess["delete_repo_on_finish"] is True
    assert child_sess["source_repo"] == "frontend"
    # 复用子仓行无 flag
    reused_sess = json.loads((reused_dir / "session.json").read_text())
    assert "delete_repo_on_finish" not in reused_sess
