"""C1 Phase B + T3: ScanManager 改 temporal workflow 提交者 + 1 ws : N scans。

start -> Client.connect + start_workflow(固定 queue supernova-wb-web)；返回 (ws, scan_id)。
T3: ScanStore.create_scan 建 scans/<scan_id>/session.json；_handles/_tasks/_active_reqs key
= (ws, scan_id)；同 ws 多 scan 不互斥。cancel(ws, scan_id) 精确 / cancel(ws) shim latest。
_watch -> tail events.ndjson 直到 scan_end; cancel -> handle.cancel(temporal 原生) +
② ③ 轨(heartbeat/cancel.requested 文件, 兼容 host CLI). active_pids 返空.
"""
import asyncio
import json
import os
import time
from datetime import timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from supernova_web.models import PathSource, RepoSource, ScanRequest
from supernova_web.components.scan_manager import ScanManager, ScanRunning, TemporalUnavailable


async def _ok():
    return None


def _patch_temporal_ok(monkeypatch, mgr):
    """跳过 _check_temporal socket 探活."""
    monkeypatch.setattr(mgr, "_check_temporal", _ok)


def _patch_client(monkeypatch, handle=None):
    """mock Client.connect -> mock_client(start_workflow -> handle). 返回 mock_client."""
    mock_handle = handle or MagicMock()
    mock_handle.id = "ws-mock"
    mock_client = AsyncMock()
    mock_client.start_workflow = AsyncMock(return_value=mock_handle)
    monkeypatch.setattr("supernova_web.components.scan_manager.Client.connect",
                       AsyncMock(return_value=mock_client))
    return mock_client


def _make_scan_dir(workspaces_dir, ws, scan_id="20260727-120000", status="running"):
    """在 workspaces/<ws>/scans/<scan_id>/ 写 session.json（新模型 scan 目录）。"""
    scan_dir = Path(workspaces_dir) / ws / "scans" / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "session.json").write_text(json.dumps({
        "status": status, "scan_type": "whitebox", "created_at": time.time(),
        "web_url": "", "repo_path": "",
    }))
    return scan_dir


# ── start: fork -> start_workflow ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_start_submits_workflow_to_fixed_queue(tmp_path, monkeypatch):
    """start 改 start_workflow: 连 temporal + 提交到 WEB_TASK_QUEUE_WHITEBOX + 存 handle."""
    from supernova_core.services.temporal_infra import WEB_TASK_QUEUE_WHITEBOX
    from supernova_whitebox.pipeline.shared import PipelineInput

    mgr = ScanManager(tmp_path, tmp_path / "repos", None)
    _patch_temporal_ok(monkeypatch, mgr)
    mock_client = _patch_client(monkeypatch)

    ws, scan_id = await mgr.start(ScanRequest(type="whitebox",
                                              source=PathSource(kind="path", value="/code/x"),
                                              url="http://e", workspace="WS1"))
    assert ws == "WS1"
    assert scan_id  # T3: 返回 scan_id
    mock_client.start_workflow.assert_awaited_once()
    call = mock_client.start_workflow.call_args
    assert call.kwargs["task_queue"] == WEB_TASK_QUEUE_WHITEBOX
    assert call.kwargs["id"]  # workflow_id 由 web 算
    wf_input = call.args[1]  # (WhiteboxScanWorkflow.run, inp, id=, task_queue=)
    assert isinstance(wf_input, PipelineInput)
    assert wf_input.event_file.endswith("events.ndjson")
    # T3: workspace_name = scan_id（worker 据 event_file.parent 推导 scan_dir）
    assert wf_input.workspace_name == scan_id
    assert ("WS1", scan_id) in mgr._handles  # handle 存进 _handles(供 cancel)


@pytest.mark.asyncio
async def test_start_lands_scan_in_scans_subdir(tmp_path, monkeypatch):
    """T3: start 建 scans/<scan_id>/session.json（ws 根不再写 session.json）。"""
    mgr = ScanManager(tmp_path, tmp_path / "repos", None)
    _patch_temporal_ok(monkeypatch, mgr)
    _patch_client(monkeypatch)
    ws, scan_id = await mgr.start(ScanRequest(type="whitebox",
                                              source=PathSource(kind="path", value="/x"),
                                              url="u", workspace="WOWN"))
    scan_dir = tmp_path / "WOWN" / "scans" / scan_id
    assert (scan_dir / "session.json").exists()
    assert not (tmp_path / "WOWN" / "session.json").exists()  # ws 根无 session.json
    sess = json.loads((scan_dir / "session.json").read_text())
    assert sess.get("owner") == "web"  # _mark_owner 标 scan session
    assert sess.get("source_repo") == "/x"  # 白盒持久化 repo 名供重跑预填


@pytest.mark.asyncio
async def test_start_writes_submitted_at(tmp_path, monkeypatch):
    """start 提交 workflow 成功后写 scan session.json submitted_at(提交宽限门锚点,防冷启动误杀).

    submitted_at 每次 start_workflow 提交刷新 -> resume 场景也准确(resume 时 created_at 是老的).
    提交失败(start_workflow 抛)不写此字段(start 已抛, 不到此分支).
    """
    mgr = ScanManager(tmp_path, tmp_path / "repos", None)
    _patch_temporal_ok(monkeypatch, mgr)
    _patch_client(monkeypatch)
    before = time.time()
    ws, scan_id = await mgr.start(ScanRequest(type="whitebox",
                                              source=PathSource(kind="path", value="/x"),
                                              url="u", workspace="WSUB"))
    after = time.time()
    sess = json.loads((tmp_path / "WSUB" / "scans" / scan_id / "session.json").read_text())
    assert "submitted_at" in sess
    assert before <= sess["submitted_at"] <= after


@pytest.mark.asyncio
async def test_start_cleanup_active_reqs_on_submit_failure(tmp_path, monkeypatch):
    """提交失败(start_workflow 抛)-> _active_reqs 必须清理, 否则 active_repo_sources 误报."""
    mgr = ScanManager(tmp_path, tmp_path / "repos", None)
    _patch_temporal_ok(monkeypatch, mgr)
    mock_client = AsyncMock()
    mock_client.start_workflow = AsyncMock(side_effect=RuntimeError("temporal reject"))
    monkeypatch.setattr("supernova_web.components.scan_manager.Client.connect",
                       AsyncMock(return_value=mock_client))
    with pytest.raises(RuntimeError, match="temporal reject"):
        await mgr.start(ScanRequest(type="whitebox",
                                    source=PathSource(kind="path", value="/x"),
                                    url="u", workspace="WFAIL"))
    # T3: key=(ws, scan_id)，提交失败已清理 -> 无 WFAIL 开头的 key
    assert not any(k[0] == "WFAIL" for k in mgr._active_reqs)
    assert mgr.active_repo_sources() == set()


@pytest.mark.asyncio
async def test_start_same_ws_two_scans_not_mutually_exclusive(tmp_path, monkeypatch):
    """T3: 同 ws 起两个 scan 不互斥（_handles 两键，不触发 TooManyScans）。"""
    mgr = ScanManager(tmp_path, tmp_path / "repos", None)
    _patch_temporal_ok(monkeypatch, mgr)
    _patch_client(monkeypatch)
    ws1, id1 = await mgr.start(ScanRequest(type="whitebox",
                                           source=PathSource(kind="path", value="/x"),
                                           url="u", workspace="WS"))
    ws2, id2 = await mgr.start(ScanRequest(type="whitebox",
                                           source=PathSource(kind="path", value="/x"),
                                           url="u", workspace="WS"))
    assert ws1 == ws2 == "WS"
    assert id1 != id2  # 两个不同 scan_id
    assert len(mgr._handles) == 2
    assert ("WS", id1) in mgr._handles and ("WS", id2) in mgr._handles


@pytest.mark.asyncio
async def test_start_no_longer_rejects_when_handles_full(tmp_path, monkeypatch):
    """并发闸门下沉 worker 后（spec 2026-09-08-worker-scan-gate §7）：web 不再拒绝。

    _handles 占满（甚至塞超）也应照常走 start 流程——排队发生在 worker 闸门。"""
    mgr = ScanManager(tmp_path, tmp_path / "r", None)
    _patch_temporal_ok(monkeypatch, mgr)
    _patch_client(monkeypatch)
    mgr._handles[("existing", "s1")] = object()  # 占位（历史在跑）
    mgr._handles[("existing", "s2")] = object()  # 超过旧上限也无妨
    ws, scan_id = await mgr.start(ScanRequest(type="whitebox",
                                              source=PathSource(kind="path", value="/x"),
                                              url="u", workspace="W2"))
    assert ws == "W2"
    assert ("W2", scan_id) in mgr._handles  # 照常登记（_watch/cancel 簿记）


@pytest.mark.asyncio
async def test_temporal_unavailable_raises(tmp_path, monkeypatch):
    mgr = ScanManager(tmp_path, tmp_path / "r", None)

    async def _fail():
        raise TemporalUnavailable()

    monkeypatch.setattr(mgr, "_check_temporal", _fail)
    with pytest.raises(TemporalUnavailable):
        await mgr.start(ScanRequest(type="whitebox",
                                    source=PathSource(kind="path", value="/x"),
                                    url="u", workspace="W"))


# ── _resolve_workflow_id: 读 resumeAttempts 算 -resume-N ──────────────────

def test_resolve_workflow_id_fresh_no_suffix(tmp_path):
    """T3: 无 resumeAttempts -> workflow_id = {ws}-{scan_id}（无后缀）."""
    mgr = ScanManager(tmp_path, tmp_path / "r", None)
    _make_scan_dir(tmp_path, "WS", scan_id="20260727-120000", status="running")
    assert mgr._resolve_workflow_id("WS", "20260727-120000") == "WS-20260727-120000"


def test_resolve_workflow_id_resume_appends_n(tmp_path):
    """T3: 有 N 条 resumeAttempts -> workflow_id = {ws}-{scan_id}-resume-N."""
    mgr = ScanManager(tmp_path, tmp_path / "r", None)
    scan_dir = _make_scan_dir(tmp_path, "WS", scan_id="20260727-120000")
    sess = json.loads((scan_dir / "session.json").read_text())
    sess["resumeAttempts"] = [
        {"workflowId": "WS-20260727-120000-resume-1"},
        {"workflowId": "WS-20260727-120000-resume-2"},
    ]
    (scan_dir / "session.json").write_text(json.dumps(sess))
    assert mgr._resolve_workflow_id("WS", "20260727-120000") == "WS-20260727-120000-resume-2"


# ── cancel: handle.cancel(①) + ② ③ 轨 ─────────────────────────────────────

@pytest.mark.asyncio
async def test_cancel_web_started_scan_calls_handle_cancel(tmp_path):
    """① web 自起 scan(_handles 有) -> handle.cancel(temporal 原生), 不再 SIGINT 子进程."""
    mgr = ScanManager(tmp_path, tmp_path / "r", None)
    mock_handle = AsyncMock()
    scan_dir = _make_scan_dir(tmp_path, "ws", scan_id="s1")
    mgr._handles[("ws", "s1")] = mock_handle
    result = await mgr.cancel("ws", "s1")
    mock_handle.cancel.assert_awaited_once()
    assert result == {"cancelled": "s1"}


@pytest.mark.asyncio
async def test_cancel_web_started_scan_marks_cancelled_and_writes_scan_end(tmp_path):
    """① web 自起 scan 取消后必须标终态 + 写 scan_end(根因修复):

    轨 ① 只调 handle.cancel(temporal 原生) 不够--worker 的 workflow except CancelledError
    分支不写 scan_end / 不更新 session(只有 try 正常完成分支调 finalize_summary)。若 web 端
    不兜底标记: ① session 卡 running -> heartbeat stale 后误显 interrupted(非 cancelled);
    ② _watch 等不到 scan_end 永不退出 -> _handles 占死（闸门下沉 worker 后仅簿记泄漏）,
    新扫描再也起不来。故轨 ① 须像 ②/③ 一样调 _mark_cancelled(写 session.status=cancelled
    + scan_end) -> _status_of 终态优先显 cancelled + _watch 见 scan_end 退出释放槽位。
    """
    mgr = ScanManager(tmp_path, tmp_path / "r", None)
    scan_dir = _make_scan_dir(tmp_path, "WEB1", scan_id="s1", status="running")
    sess = json.loads((scan_dir / "session.json").read_text())
    sess["owner"] = "web"
    (scan_dir / "session.json").write_text(json.dumps(sess))
    mock_handle = AsyncMock()
    mgr._handles[("WEB1", "s1")] = mock_handle

    result = await mgr.cancel("WEB1", "s1")

    mock_handle.cancel.assert_awaited_once()
    assert result == {"cancelled": "s1"}
    sess = json.loads((scan_dir / "session.json").read_text())
    assert sess["status"] == "cancelled"
    assert sess.get("completed_at") is not None
    event_text = (scan_dir / "events.ndjson").read_text()
    assert '"scan_end"' in event_text and '"cancelled"' in event_text


@pytest.mark.asyncio
async def test_cancel_host_running_writes_signal_and_marks_cancelled(tmp_path):
    """② owner=host(heartbeat fresh, web 无 handle)-> 写 cancel.requested + 标 cancelled + via:signal."""
    mgr = ScanManager(tmp_path, tmp_path / "r", None)
    scan_dir = _make_scan_dir(tmp_path, "HOST1", scan_id="s1", status="running")
    (scan_dir / "heartbeat").write_text(f"{time.time()}\n")  # fresh -> host 在跑
    result = await mgr.cancel("HOST1", "s1")
    assert result == {"cancelled": "s1", "via": "signal"}
    assert (scan_dir / "cancel.requested").exists()
    sess = json.loads((scan_dir / "session.json").read_text())
    assert sess["status"] == "cancelled"
    assert sess["completed_at"] is not None


@pytest.mark.asyncio
async def test_cancel_dead_marks_cancelled_was_dead(tmp_path):
    """③ heartbeat stale(已死)-> 标 cancelled + was_dead:true(不写 cancel.requested)."""
    mgr = ScanManager(tmp_path, tmp_path / "r", None)
    scan_dir = _make_scan_dir(tmp_path, "DEAD1", scan_id="s1", status="running")
    (scan_dir / "heartbeat").write_text("x\n")
    old = time.time() - 3600
    import os
    os.utime(scan_dir / "heartbeat", (old, old))  # stale -> 已死
    result = await mgr.cancel("DEAD1", "s1")
    assert result == {"cancelled": "s1", "was_dead": True}
    assert not (scan_dir / "cancel.requested").exists()
    sess = json.loads((scan_dir / "session.json").read_text())
    assert sess["status"] == "cancelled"


@pytest.mark.asyncio
async def test_cancel_unknown_scan_returns_none(tmp_path):
    """scan 不存在 -> None(唯一 404 情况)."""
    mgr = ScanManager(tmp_path, tmp_path / "r", None)
    _make_scan_dir(tmp_path, "ws", scan_id="s1")
    assert await mgr.cancel("ws", "nope") is None  # scan_id 不存在


# ── cancel ②③ 轨补真 temporal cancel（2026-08-28 取消失效治本）───────────────
# 根因（NodeGoat-20260827-103736 跑 25h 实证）：_handles 是 web 进程内存，重启即丢；
# 旧 ② 轨只写 cancel.requested——worker 容器路径的 activity start_heartbeat(on_cancel=None)
# 不消费协作信号；旧 ③ 轨纯标记。web 自起(owner=web)扫描一旦 handle 丢失，取消＝状态
# 翻转而 worker 永不停。修复对齐 _cancel_combined 既有模式：②③ 轨也 re-attach + 真 cancel。

@pytest.mark.asyncio
async def test_cancel_host_running_also_sends_temporal_cancel(tmp_path, monkeypatch):
    """② 轨补真 cancel：heartbeat fresh 且 _handles 无 handle（web 重启后 owner=web 同样
    落此轨）→ 除写 cancel.requested 外，必须 re-attach 对 {ws}-{scan_id} 发 temporal
    handle.cancel()——协作式信号此前在 worker 容器路径无消费者，是死信。"""
    mgr = ScanManager(tmp_path, tmp_path / "r", None)
    scan_dir = _make_scan_dir(tmp_path, "HOST2", scan_id="s1", status="running")
    (scan_dir / "heartbeat").write_text(f"{time.time()}\n")  # fresh -> ② 轨

    get_handle = AsyncMock()
    mock_client = AsyncMock()
    mock_client.get_workflow_handle = MagicMock(return_value=get_handle)
    monkeypatch.setattr(
        "supernova_web.components.scan_manager.Client.connect",
        AsyncMock(return_value=mock_client))

    result = await mgr.cancel("HOST2", "s1")

    assert result == {"cancelled": "s1", "via": "signal"}
    mock_client.get_workflow_handle.assert_called_once_with("HOST2-s1")
    get_handle.cancel.assert_awaited_once()
    assert (scan_dir / "cancel.requested").exists()  # 协作式信号保留(host CLI 兼容)
    sess = json.loads((scan_dir / "session.json").read_text())
    assert sess["status"] == "cancelled"


@pytest.mark.asyncio
async def test_cancel_dead_also_sends_temporal_cancel(tmp_path, monkeypatch):
    """③ 轨补真 cancel：heartbeat stale 可能是误判（心跳线程终态自停/写路径异常而 worker
    活着），同样 re-attach 发 temporal cancel——对真死的 workflow cancel 无害（不存在/已
    终态即抛错忽略），对误判则是唯一止损。"""
    mgr = ScanManager(tmp_path, tmp_path / "r", None)
    scan_dir = _make_scan_dir(tmp_path, "DEAD2", scan_id="s1", status="running")
    (scan_dir / "heartbeat").write_text("x\n")
    old = time.time() - 3600
    os.utime(scan_dir / "heartbeat", (old, old))  # stale -> ③ 轨

    get_handle = AsyncMock()
    mock_client = AsyncMock()
    mock_client.get_workflow_handle = MagicMock(return_value=get_handle)
    monkeypatch.setattr(
        "supernova_web.components.scan_manager.Client.connect",
        AsyncMock(return_value=mock_client))

    result = await mgr.cancel("DEAD2", "s1")

    assert result == {"cancelled": "s1", "was_dead": True}
    mock_client.get_workflow_handle.assert_called_once_with("DEAD2-s1")
    get_handle.cancel.assert_awaited_once()


@pytest.mark.asyncio
async def test_cancel_temporal_unreachable_still_marks_cancelled(tmp_path, monkeypatch):
    """temporal 不可达（Client.connect 抛）→ best-effort：cancel 不阻断标终态
    （对齐 _cancel_combined 语义，前端照常翻转 cancelled）。"""
    mgr = ScanManager(tmp_path, tmp_path / "r", None)
    scan_dir = _make_scan_dir(tmp_path, "HOST3", scan_id="s1", status="running")
    (scan_dir / "heartbeat").write_text(f"{time.time()}\n")  # fresh -> ② 轨

    async def _boom(*a, **kw):
        raise RuntimeError("temporal unreachable")
    monkeypatch.setattr(
        "supernova_web.components.scan_manager.Client.connect", _boom)

    result = await mgr.cancel("HOST3", "s1")

    assert result == {"cancelled": "s1", "via": "signal"}
    sess = json.loads((scan_dir / "session.json").read_text())
    assert sess["status"] == "cancelled"


# ── _watch: tail events.ndjson 直到 scan_end ──────────────────────────────

@pytest.mark.asyncio
async def test_watch_tails_events_until_scan_end(tmp_path):
    """_watch tail events.ndjson, 见 scan_end 后退出 + 清理 _handles/_active_reqs."""
    scan_dir = _make_scan_dir(tmp_path, "ws", scan_id="s1")
    event_file = scan_dir / "events.ndjson"
    mgr = ScanManager(tmp_path, tmp_path / "r", None)
    scan_key = ("ws", "s1")
    mgr._handles[scan_key] = MagicMock()
    mgr._active_reqs[scan_key] = ScanRequest(type="whitebox", url="u")

    async def write_end():
        await asyncio.sleep(0.15)
        event_file.write_text('{"type":"scan_end","status":"completed"}\n')

    asyncio.create_task(write_end())
    await mgr._watch(scan_key, event_file, scan_dir)
    assert scan_key not in mgr._handles  # finally 清理
    assert scan_key not in mgr._active_reqs


@pytest.mark.asyncio
async def test_watch_timeout_writes_timeout_scan_end(tmp_path):
    """scan_timeout 到且无 scan_end -> 兜底写 timeout scan_end + 清理."""
    scan_dir = _make_scan_dir(tmp_path, "wt", scan_id="s1")
    event_file = scan_dir / "events.ndjson"
    mgr = ScanManager(tmp_path, tmp_path / "r", None, scan_timeout=0.3)
    scan_key = ("wt", "s1")
    mgr._handles[scan_key] = MagicMock()
    await mgr._watch(scan_key, event_file, scan_dir)
    text = event_file.read_text()
    assert '"scan_end"' in text and '"timeout"' in text
    assert scan_key not in mgr._handles


@pytest.mark.asyncio
async def test_watch_crashed_fallback_when_no_scan_end(tmp_path):
    """_watch 超时无 scan_end -> 兜底写(scan_end 缺失时 finally 补写).

    注: 纯 cancel 场景 finally 的 await 不可靠(asyncio CancelledError 中断 await), 故
    用 timeout 路径验证兜底写逻辑(timeout 路径 finally 的 if-not-has_scan_end 同源).
    """
    scan_dir = _make_scan_dir(tmp_path, "wc", scan_id="s1")
    event_file = scan_dir / "events.ndjson"
    mgr = ScanManager(tmp_path, tmp_path / "r", None, scan_timeout=0.2)
    scan_key = ("wc", "s1")
    mgr._handles[scan_key] = MagicMock()
    await mgr._watch(scan_key, event_file, scan_dir)
    text = event_file.read_text()
    assert '"scan_end"' in text  # 兜底写了


# ── active_repo_sources / active_pids ─────────────────────────────────────

def test_active_repo_sources_tracks_running_then_clears(tmp_path):
    """active_repo_sources(): 在途 scan 引用的 (ws, repo) 出现于集合, scan 结束后消失.

    T3: _active_reqs key=(ws, scan_id)，返回 set[tuple[str,str]]--delete_repo 用
    (ws, name) in ... 判引用, ws 维度必须参与（防 ws-A 的 scan 误锁 ws-B 的同名 repo）。
    """
    mgr = ScanManager(tmp_path, tmp_path / "r", None)
    assert mgr.active_repo_sources() == set()
    mgr._active_reqs[("ws1", "s1")] = ScanRequest(
        type="whitebox", source=RepoSource(kind="repo", value="foo"), url="http://e")
    assert ("ws1", "foo") in mgr.active_repo_sources()
    mgr._active_reqs.pop(("ws1", "s1"), None)
    assert mgr.active_repo_sources() == set()


def test_active_pids_returns_empty(tmp_path):
    """C1: web 无本机 pid(扫描跑在 worker 容器), active_pids 恒空."""
    mgr = ScanManager(tmp_path, tmp_path / "r", None)
    mgr._handles[("ws", "s1")] = MagicMock()
    assert mgr.active_pids() == {}


# ── correlation: traversal 校验仍触发(Phase C 前 raise ValueError) ────────

@pytest.mark.asyncio
async def test_correlation_config_name_traversal_rejected(tmp_path, monkeypatch):
    """config_name="../evil" 必须被 store 遍历校验拦截(在 C1 raise ValueError 前)."""
    from supernova_web.components.multi_repo_config_store import MultiRepoConfigStore
    store = MultiRepoConfigStore(tmp_path / "configs")
    mgr = ScanManager(tmp_path, tmp_path / "r", store)
    _patch_temporal_ok(monkeypatch, mgr)
    with pytest.raises(ValueError):
        await mgr.start(ScanRequest(type="correlation", config_name="../evil"))


# ── delete: 真删目录（spec §5.1 DELETE）──────────────────────────────────────

@pytest.mark.asyncio
async def test_delete_completed_scan_removes_dir(tmp_path):
    """非 running scan 删除：调 ScanStore.delete_scan 真删目录，返 {deleted:id}。"""
    mgr = ScanManager(tmp_path, tmp_path / "r", None)
    scan_dir = _make_scan_dir(tmp_path, "ws", scan_id="s1", status="completed")
    result = await mgr.delete("ws", "s1")
    assert result == {"deleted": "s1"}
    assert not scan_dir.exists()


@pytest.mark.asyncio
async def test_delete_running_scan_raises_scan_running(tmp_path):
    """running scan 删除被拒 -> ScanRunning（端点转 409，先 cancel 再删）。

    对齐 delete_workspace：删在跑 workflow 的目录会致 _watch 描述不存在的 workflow / 槽位泄漏。
    """
    mgr = ScanManager(tmp_path, tmp_path / "r", None)
    scan_dir = _make_scan_dir(tmp_path, "ws", scan_id="s1", status="running")
    (scan_dir / "heartbeat").write_text(f"{time.time()}\n")  # fresh -> running
    with pytest.raises(ScanRunning):
        await mgr.delete("ws", "s1")
    assert scan_dir.exists()  # 未删


@pytest.mark.asyncio
async def test_delete_unknown_returns_none(tmp_path):
    """scan 不存在 -> None（端点据此 404）。"""
    mgr = ScanManager(tmp_path, tmp_path / "r", None)
    _make_scan_dir(tmp_path, "ws", scan_id="s1")
    assert await mgr.delete("ws", "nope") is None


@pytest.mark.asyncio
async def test_delete_clears_stale_registrations(tmp_path):
    """删除成功后清理残留 _handles/_active_reqs（防御：非 running 时 _watch finally 通常已清）。"""
    mgr = ScanManager(tmp_path, tmp_path / "r", None)
    _make_scan_dir(tmp_path, "ws", scan_id="s1", status="completed")
    scan_key = ("ws", "s1")
    mgr._handles[scan_key] = MagicMock()
    mgr._active_reqs[scan_key] = ScanRequest(type="whitebox", url="u")
    await mgr.delete("ws", "s1")
    assert scan_key not in mgr._handles
    assert scan_key not in mgr._active_reqs


# ── C1: correlated_workspace 穿透（跨仓关联扫描，Phase C）────────────────────

@pytest.mark.asyncio
async def test_run_blackbox_phase_forwards_correlated_workspace(tmp_path, monkeypatch):
    """C1: _run_blackbox_phase 把 correlated_workspace 透传给 _submit_blackbox
    （显式传值 + 不传默认 None 零回归），workflow_id_suffix 照旧不受影响。"""
    import inspect
    from supernova_web.components import scan_manager as m
    assert "correlated_workspace" in inspect.signature(
        m.ScanManager._run_blackbox_phase).parameters

    mgr = ScanManager(tmp_path, tmp_path / "r", None)
    scan_dir = _make_scan_dir(tmp_path, "ws", scan_id="scan-1", status="running")
    (scan_dir / "session.json").write_text(json.dumps({
        "status": "running", "combined": True, "bb_url": "http://t/",
    }))
    wb = scan_dir / "deliverables" / "whitebox"; wb.mkdir(parents=True)
    (wb / "recon_deliverable.md").write_text("recon")
    (wb / "injection_exploitation_queue.json").write_text(
        '{"vulnerabilities":[{"id":1}]}')

    captured = {}

    async def fake_submit(self, repo_path, ws, scan_id, scan_dir, event_file,
                          web_url, config_path, host_mappings=None,
                          workflow_id_suffix="", correlated_workspace=None):
        captured["correlated_workspace"] = correlated_workspace
        captured["suffix"] = workflow_id_suffix
        return object()

    async def fake_await(self, handle, attempts=5, backoff_base=2.0):
        return {"status": "completed"}

    monkeypatch.setattr(m.ScanManager, "_submit_blackbox", fake_submit)
    monkeypatch.setattr(m.ScanManager, "_await_workflow_result", fake_await)
    monkeypatch.setattr(m.ScanManager, "_mark_run", AsyncMock())
    monkeypatch.setattr(m.ScanManager, "_generate_combined_report", AsyncMock())

    await mgr._run_blackbox_phase(
        scan_dir, "ws", "scan-1", {}, "run-1",
        workflow_id_suffix="-bb-1", correlated_workspace="scan-1")
    assert captured["correlated_workspace"] == "scan-1"
    assert captured["suffix"] == "-bb-1"

    captured.clear()
    await mgr._run_blackbox_phase(
        scan_dir, "ws", "scan-1", {}, "run-1", workflow_id_suffix="-bb-1")
    assert captured["correlated_workspace"] is None  # 不传 → None（零回归）


@pytest.mark.asyncio
async def test_submit_blackbox_passes_correlated_workspace_to_input(tmp_path, monkeypatch):
    """C1: _submit_blackbox 把 correlated_workspace 灌进 BlackboxPipelineInput
    （显式传值 + 不传默认 None 零回归，字段 B1 已在上游定义）。"""
    import inspect
    from supernova_blackbox.pipeline.shared import BlackboxPipelineInput
    from supernova_web.components import scan_manager as m
    assert "correlated_workspace" in inspect.signature(
        m.ScanManager._submit_blackbox).parameters

    mgr = ScanManager(tmp_path, tmp_path / "r", None)
    scan_dir = _make_scan_dir(tmp_path, "ws", scan_id="scan-1", status="running")
    monkeypatch.setattr(mgr, "_mark_submitted_at", lambda _scan_dir: None)
    mock_client = _patch_client(monkeypatch)

    await mgr._submit_blackbox(
        repo_path="/repo", ws="ws", scan_id="scan-1", scan_dir=scan_dir,
        event_file=scan_dir / "events.ndjson", web_url="http://t/",
        config_path=None, correlated_workspace="scan-1")
    inp = mock_client.start_workflow.call_args.args[1]
    assert isinstance(inp, BlackboxPipelineInput)
    assert inp.correlated_workspace == "scan-1"

    await mgr._submit_blackbox(
        repo_path="/repo", ws="ws", scan_id="scan-1", scan_dir=scan_dir,
        event_file=scan_dir / "events.ndjson", web_url="http://t/",
        config_path=None)  # 不传 correlated_workspace → 字段默认 None
    inp2 = mock_client.start_workflow.call_args.args[1]
    assert inp2.correlated_workspace is None


# ── C2: 复用子仓校验 + _submit_correlation + corr_children 血缘（跨仓关联 Phase C）──

def _make_manager_with_store(tmp_path):
    """构造 ScanManager + 其内部 ScanStore（C2 用；ScanManager 自建 store，直接复用）。"""
    mgr = ScanManager(tmp_path, tmp_path / "r", None)
    return mgr, mgr._store


@pytest.mark.asyncio
async def test_validate_reused_children_ok(tmp_path):
    """C2: 复用子仓合法（scan 存在 + scan_type=whitebox + deliverables 有 queue 文件）
    → 返回 {service: scan_dir}。"""
    sm, store = _make_manager_with_store(tmp_path)
    scan_id, scan_dir = store.create_scan("ws", "", "repo-a", "whitebox")
    (scan_dir / "deliverables").mkdir(parents=True, exist_ok=True)
    (scan_dir / "deliverables" / "injection_exploitation_queue.json").write_text(
        '{"vulnerabilities": [{"title": "t", "description": "d", "severity": "high", "location": "f:1"}]}',
        encoding="utf-8")
    from supernova_core.models.multi_repo_config import MultiRepoConfig, RepoSpec, CorrelationConfig
    # 注：MultiRepoConfig 校验器要求至少一个 entrypoint（brief 草稿的 backend-only 会
    # ValidationError）——单仓用 entrypoint 角色，仍是复用 workspace 子仓。
    cfg = MultiRepoConfig(
        repos={"a": RepoSpec(workspace=scan_id, role="entrypoint")},
        relations=[],
        correlation=CorrelationConfig(out_workspace="corr-1"))
    paths = sm._validate_reused_children("ws", cfg)
    assert paths == {"a": scan_dir}


@pytest.mark.asyncio
async def test_validate_reused_children_missing_queue(tmp_path):
    """C2: 无 queue 文件 → ValueError("复用扫描不可用: a: ...")（API 层转 422）。"""
    sm, store = _make_manager_with_store(tmp_path)
    scan_id, scan_dir = store.create_scan("ws", "", "repo-a", "whitebox")
    # 无 queue 文件 → 拒
    from supernova_core.models.multi_repo_config import MultiRepoConfig, RepoSpec, CorrelationConfig
    cfg = MultiRepoConfig(
        repos={"a": RepoSpec(workspace=scan_id, role="entrypoint")},
        relations=[], correlation=CorrelationConfig(out_workspace="corr-1"))
    with pytest.raises(ValueError, match="复用扫描不可用"):
        sm._validate_reused_children("ws", cfg)


@pytest.mark.asyncio
async def test_validate_reused_children_scan_missing_and_wrong_type(tmp_path):
    """C2: workspace 指向不存在的 scan / 非白盒 scan_type → 同样 ValueError 拒绝；
    path 型 repo（无 workspace）不参与复用校验。"""
    sm, store = _make_manager_with_store(tmp_path)
    from supernova_core.models.multi_repo_config import MultiRepoConfig, RepoSpec, CorrelationConfig
    # ① 不存在的 scan_id
    cfg_missing = MultiRepoConfig(
        repos={"a": RepoSpec(workspace="nope-20260101-000000", role="entrypoint")},
        relations=[], correlation=CorrelationConfig(out_workspace="corr-1"))
    with pytest.raises(ValueError, match="复用扫描不可用: a"):
        sm._validate_reused_children("ws", cfg_missing)
    # ② scan_type 非 whitebox（blackbox 复用链）→ 拒
    bb_id, _bb_dir = store.create_scan("ws", "", "repo-b", "blackbox",
                                       lineage="wb-20260101-000000")
    cfg_bb = MultiRepoConfig(
        repos={"a": RepoSpec(workspace=bb_id, role="entrypoint")},
        relations=[], correlation=CorrelationConfig(out_workspace="corr-1"))
    with pytest.raises(ValueError, match="复用扫描不可用"):
        sm._validate_reused_children("ws", cfg_bb)
    # ③ path 型 repo（无 spec.workspace）不进复用校验 → 空 dict 放行
    cfg_path = MultiRepoConfig(
        repos={"a": RepoSpec(path="/repo/a", role="entrypoint")},
        relations=[], correlation=CorrelationConfig(out_workspace="corr-1"))
    assert sm._validate_reused_children("ws", cfg_path) == {}


def test_scan_summary_corr_children(tmp_path):
    """C2: summary 透传 corr_children（session 写 → list_scans 断言）；非关联扫描 None。"""
    sm, store = _make_manager_with_store(tmp_path)
    from supernova_core.session import SessionManager
    scan_id, scan_dir = store.create_scan("ws", "", "corr-x", "correlation")
    children = [
        {"service": "a", "scan_id": "wb-1", "reused": True, "status": "completed"},
        {"service": "b", "scan_id": "wb-2", "reused": False},
    ]
    SessionManager(scan_dir.parent).update_session(scan_dir, {"corr_children": children})
    target = next(s for s in store.list_scans("ws") if s.scan_id == scan_id)
    assert target.corr_children == children
    assert target.as_dict()["corr_children"] == children
    # 非关联扫描未写字段 → None（零回归）
    other_id, _ = store.create_scan("ws", "", "repo-b", "whitebox")
    other = next(s for s in store.list_scans("ws") if s.scan_id == other_id)
    assert other.corr_children is None


@pytest.mark.asyncio
async def test_submit_correlation_to_correlation_queue(tmp_path, monkeypatch):
    """C2: _submit_correlation 镜像 _submit_whitebox —— WEB_TASK_QUEUE_CORRELATION 提交、
    workflow_id 加 -corr、CorrelationPipelineInput 全 str 路径、成功后锚定 submitted_at。"""
    from supernova_core.runtime.workflow_timeout import scan_budget
    from supernova_core.services.temporal_infra import WEB_TASK_QUEUE_CORRELATION
    from supernova_multi.pipeline.shared import CorrelationPipelineInput

    sm, store = _make_manager_with_store(tmp_path)
    scan_id, out_ws_dir = store.create_scan("ws", "", "corr-1", "correlation")
    repo_ws = tmp_path / "ws" / "scans" / "wb-1"
    repo_ws.mkdir(parents=True)
    mock_client = _patch_client(monkeypatch)
    # 预算调小（3h）验证 4.5h 下限仍生效（final-fix ④ 的被测分支）
    monkeypatch.setenv("SUPERNOVA_SCAN_BUDGET_HOURS", "3")

    handle = await sm._submit_correlation(
        config_path=tmp_path / "web-multi-x.yaml",
        repo_workspace_paths={"a": repo_ws},
        out_ws_dir=out_ws_dir,
        event_file=out_ws_dir / "events.ndjson",
        ws="ws")
    assert handle is mock_client.start_workflow.return_value
    call = mock_client.start_workflow.call_args
    assert call.kwargs["task_queue"] == WEB_TASK_QUEUE_CORRELATION
    assert call.kwargs["id"] == f"ws-{scan_id}-corr"
    # final-fix ④：corr run_timeout 须严格大于 activity 预算 4h —— max(预算, 4.5h)，
    # 预算 3h 时抬到 4.5h（防预算 workflow 掐死 4h activity）；预算默认 5h > 4.5h
    # 时尊重预算，此处以调小档锁下限分支。
    assert call.kwargs["run_timeout"] == max(
        scan_budget(), timedelta(hours=4, minutes=30))
    assert call.kwargs["run_timeout"] == timedelta(hours=4, minutes=30)
    inp = call.args[1]
    assert isinstance(inp, CorrelationPipelineInput)
    assert inp.config_path == str(tmp_path / "web-multi-x.yaml")
    assert inp.repo_workspace_paths == {"a": str(repo_ws)}
    assert inp.out_ws_dir == str(out_ws_dir)
    assert inp.event_file == str(out_ws_dir / "events.ndjson")
    assert inp.provider_config  # ws/全局解析出的 provider 配置穿线
    assert inp.env_overrides == {}
    assert inp.write_scan_end is False  # web 编排收尾（_ensure_scan_end），worker 不写终态
    # 提交成功后锚定 submitted_at（对齐 _submit_whitebox 的 scan_liveness 宽限锚点）
    sess = json.loads((out_ws_dir / "session.json").read_text("utf-8"))
    assert "submitted_at" in sess


# ── C3: start() correlation 分支 + _correlation_orchestrator（三段接力）──────

class _FakeHandle:
    """测试用 workflow 句柄（tag 区分白盒子仓 / 关联阶段，供 fake await 分流）。"""

    def __init__(self, tag: str) -> None:
        self.tag = tag


def _seed_repo(workspaces_dir, ws, name):
    """ws 下造 repos/<name> 目录（现扫子仓 _resolve_repo_path 的解析目标）。"""
    repo_dir = Path(workspaces_dir) / ws / "repos" / name
    repo_dir.mkdir(parents=True, exist_ok=True)
    return repo_dir


def _seed_reusable_whitebox(workspaces_dir, ws, name):
    """造可复用白盒 scan 行：scan_type=whitebox + deliverables 下 queue 文件。

    用独立 ScanStore（同 workspaces_dir 即同视图），供调用方先种行再拼 yaml。"""
    from supernova_web.components.scan_store import ScanStore
    store = ScanStore(workspaces_dir)
    scan_id, scan_dir = store.create_scan(ws, "", name, "whitebox")
    dlv = scan_dir / "deliverables"
    dlv.mkdir(parents=True, exist_ok=True)
    (dlv / "injection_exploitation_queue.json").write_text(
        '{"vulnerabilities": [{"title": "t", "description": "d", '
        '"severity": "high", "location": "f:1"}]}', encoding="utf-8")
    return scan_id


def _corr_yaml(frontend: str, backend: str) -> str:
    """两仓 correlation yaml（frontend 恒 entrypoint；out_workspace 占位、web 覆写）。

    注：MultiRepoConfig 要求 correlation.out_workspace 必填 + ≥1 entrypoint
    （brief 草稿的 yaml 略去了 correlation 段，会 ValidationError）。"""
    return (
        "repos:\n"
        f"  frontend: {{{frontend}}}\n"
        f"  order-svc: {{{backend}}}\n"
        "relations:\n  - {from: frontend, to: order-svc, protocol: grpc}\n"
        "correlation:\n  out_workspace: placeholder\n"
    )


async def _start_corr_env(tmp_path, monkeypatch, *, yaml_text, url=None,
                          fail_child=False, host_url=None, authentication=None):
    """C3 四用例共享构造（brief 注：抽文件内 helper 避免复制）。

    只 mock workflow 提交边界（_submit_whitebox / _submit_correlation /
    _await_workflow_result / _run_blackbox_phase）；store / session / yaml 落盘 /
    CorrelationEventWriter 事件全真跑。start 返回后等编排 task 跑完（fake await
    即时完成，无真实等待）再返回，同步断言接力结果。

    host_url 给定时 mock fetch_and_parse_hosts（不触网，fix ② 用例）；authentication
    给定时透传进 ScanRequest（fix round 2 段③认证用例）。

    返回 (sm, store, submitted, pre_ids, ws_name, scan_id)——pre_ids = start 前
    ws 内已有 scan_id 集（复用用例断言「仅新增主行」用）。"""
    from supernova_web.components.multi_repo_config_store import MultiRepoConfigStore

    sm = ScanManager(tmp_path, tmp_path / "r",
                     MultiRepoConfigStore(tmp_path / "configs"))
    _patch_temporal_ok(monkeypatch, sm)
    submitted = {"wb": [], "corr": 0, "corr_paths": {}, "bb": None}
    if host_url is not None:
        from supernova_web.components.host_profile_store import HostMapping

        async def fake_fetch(_url, timeout=15):
            return ([HostMapping(ip="10.0.0.2", host="gw.test")], [])

        monkeypatch.setattr(
            "supernova_web.components.scan_manager.fetch_and_parse_hosts", fake_fetch)

    async def fake_submit_whitebox(self, target, ws, scan_id, scan_dir, event_file,
                                   web_url, combined=False):
        submitted["wb"].append((ws, scan_id, target))
        return _FakeHandle(f"wb:{scan_id}")

    async def fake_submit_correlation(self, config_path, repo_workspace_paths,
                                      out_ws_dir, event_file, ws):
        submitted["corr"] += 1
        submitted["corr_paths"] = dict(repo_workspace_paths)
        return _FakeHandle("corr")

    async def fake_await(self, handle, attempts=5, backoff_base=2.0):
        if fail_child and getattr(handle, "tag", "").startswith("wb:"):
            return {"status": "failed"}
        return {"status": "completed"}

    async def fake_bb_phase(self, scan_dir, ws, scan_id, auth_ref, run_id,
                            workflow_id_suffix="-bb-1", correlated_workspace=None):
        submitted["bb"] = (run_id, correlated_workspace)

    monkeypatch.setattr(type(sm), "_submit_whitebox", fake_submit_whitebox)
    monkeypatch.setattr(type(sm), "_submit_correlation", fake_submit_correlation)
    monkeypatch.setattr(type(sm), "_await_workflow_result", fake_await)
    monkeypatch.setattr(type(sm), "_run_blackbox_phase", fake_bb_phase)

    pre_ids = {s.scan_id for s in sm._store.list_scans("ws")}
    req = ScanRequest(type="correlation", workspace="ws",
                      config_content=yaml_text, url=url, host_url=host_url,
                      authentication=authentication)
    ws_name, scan_id = await sm.start(req)
    # 等三段接力编排 task 跑完（fake await 即时完成）再断言。
    orch = sm._orchestrator_tasks.get((ws_name, scan_id))
    if orch is not None:
        await orch
    # 主行 _watch：scan_end 已由编排收尾写入，等它退出（hygiene：清 _active_reqs）。
    watch = sm._tasks.get((ws_name, scan_id))
    if watch is not None:
        try:
            await asyncio.wait_for(asyncio.shield(watch), timeout=5)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            pass
    return sm, sm._store, submitted, pre_ids, ws_name, scan_id


@pytest.mark.asyncio
async def test_start_correlation_creates_main_and_children(tmp_path, monkeypatch):
    """C3 现扫提交：主行 + 2 现扫子仓白盒行 + corr_children 血缘 + 接力已跑
    （corr 提交 1 次、repo_workspace_paths 覆盖两子仓 scan_dir）。"""
    _seed_repo(tmp_path, "ws", "frontend")
    _seed_repo(tmp_path, "ws", "order-svc")
    sm, store, submitted, pre_ids, ws_name, scan_id = await _start_corr_env(
        tmp_path, monkeypatch,
        yaml_text=_corr_yaml("path: frontend, role: entrypoint",
                             "path: order-svc"))
    assert ws_name == "ws"
    # 主行 + 2 现扫子仓行（同 ws scans 下共 3 目录）
    scans = store.list_scans("ws")
    assert len(scans) == 3
    main = next(s for s in scans if s.scan_id == scan_id)
    assert main.is_correlation  # R3：真实 ScanSummary 字段（scan_type 派生）
    assert main.scan_type == "correlation"
    # 主任务名显式带 cross-repo 前缀，不和同秒创建的仓库子任务同名/同名 -2。
    assert scan_id.startswith("cross-repo-")
    assert len(main.corr_children) == 2
    assert {c["service"] for c in main.corr_children} == {"frontend", "order-svc"}
    assert all(c["reused"] is False for c in main.corr_children)
    # 子仓行 = 标准白盒行，scan_id 与血缘登记一致
    child_ids = {c["scan_id"] for c in main.corr_children}
    child_rows = [s for s in scans if s.scan_id in child_ids]
    assert len(child_rows) == 2
    assert all(s.scan_type == "whitebox" for s in child_rows)
    # 现扫子仓提交 2 次，target = ws 内仓库路径（repo 名语义解析）
    assert len(submitted["wb"]) == 2
    assert {Path(t).name for (_w, _sid, t) in submitted["wb"]} == {"frontend", "order-svc"}
    assert scan_id not in child_ids
    # 接力同步段已跑（fake await 即时完成）：corr 提交 1 次、paths 覆盖两子仓
    assert submitted["corr"] == 1
    assert set(submitted["corr_paths"]) == {"frontend", "order-svc"}
    assert {p.name for p in submitted["corr_paths"].values()} == child_ids
    assert main.status == "completed"
    # yaml 落盘（out_workspace 覆写为主行 scan_id）+ config_path 入 session
    sess = json.loads((tmp_path / "ws" / "scans" / scan_id / "session.json").read_text())
    from supernova_core.config.parser import parse_multi_repo_config
    cfg2 = parse_multi_repo_config(Path(sess["config_path"]))
    assert cfg2.correlation.out_workspace == scan_id
    # 主行 events.ndjson：真 CorrelationEventWriter 的 repo/phase 事件 + scan_end 收尾
    events = [json.loads(l) for l in
              (tmp_path / "ws" / "scans" / scan_id / "events.ndjson").read_text().splitlines()
              if l.strip()]
    types = [e.get("type") for e in events]
    assert types.count("correlation_progress") >= 5  # 2 repo started + 2 completed + 2 phase
    # 段① phase 事件（2026-09-20 跨仓 live 阶段）：repo-scan started/completed 领先
    # 于 correlation——前端「当前阶段」槽段①显示 repo-scan + 阶段轨点亮。
    phase_events = [(e.get("name"), e.get("status")) for e in events
                    if e.get("type") == "correlation_progress" and e.get("node") == "phase"]
    assert phase_events == [("repo-scan", "started"), ("repo-scan", "completed"),
                            ("correlation", "started"), ("correlation", "completed")]
    assert "scan_end" in types
    assert (ws_name, scan_id) not in sm._orchestrator_tasks  # 编排 finally 自清
    assert (ws_name, scan_id) not in sm._active_reqs  # _watch 退出清引用


@pytest.mark.asyncio
async def test_start_correlation_reuse_no_child_rows(tmp_path, monkeypatch):
    """C3 复用子仓不建行：仅新增主行 + corr_children reused=True + 不提交白盒。"""
    front_id = _seed_reusable_whitebox(tmp_path, "ws", "frontend")
    order_id = _seed_reusable_whitebox(tmp_path, "ws", "order-svc")
    sm, store, submitted, pre_ids, ws_name, scan_id = await _start_corr_env(
        tmp_path, monkeypatch,
        yaml_text=_corr_yaml(f"workspace: {front_id}, role: entrypoint",
                             f"workspace: {order_id}"))
    scans = store.list_scans("ws")
    # 复用子仓不建行：start 仅新增主行（pre_ids = 2 个预种的复用白盒行）
    assert len(scans) == len(pre_ids) + 1
    main = next(s for s in scans if s.scan_id == scan_id)
    assert main.is_correlation
    children = main.corr_children
    assert len(children) == 2
    assert children[0]["reused"] is True
    assert all(c["reused"] is True for c in children)
    assert {c["scan_id"] for c in children} == {front_id, order_id}
    assert submitted["wb"] == []  # 无现扫子仓提交
    assert submitted["corr"] == 1  # 关联照常（输入全复用）
    # 复用子仓路径 = 既有白盒 scan 目录（_validate_reused_children 产物直通）
    assert submitted["corr_paths"]["frontend"] == tmp_path / "ws" / "scans" / front_id
    assert submitted["corr_paths"]["order-svc"] == tmp_path / "ws" / "scans" / order_id
    assert main.status == "completed"


@pytest.mark.asyncio
async def test_start_correlation_form_yaml_defaults_and_abs_paths(
        tmp_path, monkeypatch):
    """final-fix ①+②：表单形 yaml（formToYaml 产物——无 correlation 段、path=仓库
    名、复用仓无 path）经 start() 全程不 422：

    ① 缺 correlation 段被注入默认占位（store validate + start 解析两处兜底），
      占位 out_workspace 被 C3 覆写为主行 scan_id 落进 worker yaml；
    ② 落盘 worker yaml 的 repos path 回填为绝对仓库目录（关联 agent 源码可达 +
      漂移检测不再静默跳过）——现扫子仓用已解析目录，复用子仓 best-effort
      （仓仍在 ws → 回填；已删 → null，见本用例第二段）。
    """
    import yaml
    _seed_repo(tmp_path, "ws", "frontend")   # 现扫子仓
    _seed_repo(tmp_path, "ws", "order-svc")  # 复用子仓的源仓仍在 ws
    order_id = _seed_reusable_whitebox(tmp_path, "ws", "order-svc")
    # formToYaml 形状：只有 repos/relations；path=仓库名；复用仓仅 workspace
    form_yaml = (
        "repos:\n"
        "  frontend:\n    path: frontend\n    role: entrypoint\n"
        f"  order-svc:\n    workspace: {order_id}\n"
        "relations:\n  - {from: frontend, to: order-svc, protocol: grpc}\n"
    )
    sm, store, submitted, pre_ids, ws_name, scan_id = await _start_corr_env(
        tmp_path, monkeypatch, yaml_text=form_yaml)
    # 无 422（start 返回即证）；现扫仅 frontend 一仓，order-svc 复用不建行
    assert len(submitted["wb"]) == 1
    assert submitted["corr"] == 1
    # worker yaml：注入的 correlation.out_workspace == 主行 scan_id（占位被覆写）
    sess = json.loads((tmp_path / "ws" / "scans" / scan_id / "session.json").read_text())
    dumped = Path(sess["config_path"])
    assert dumped.name == f"{scan_id}-multi-repo.yaml"
    raw = yaml.safe_load(dumped.read_text("utf-8"))
    assert raw["correlation"]["out_workspace"] == scan_id
    # repos path 全为绝对目录（非裸仓库名）：现扫 = 解析出的仓库目录；复用仓
    # best-effort 回填（源仓仍在 ws）
    assert Path(raw["repos"]["frontend"]["path"]) == (
        tmp_path / "ws" / "repos" / "frontend").resolve()
    assert Path(raw["repos"]["order-svc"]["path"]) == (
        tmp_path / "ws" / "repos" / "order-svc").resolve()
    assert raw["repos"]["frontend"]["path"] != "frontend"

    # 复用仓已不在 ws（best-effort 失败）→ path 保持 null（漂移跳过是正解）
    import shutil
    shutil.rmtree(tmp_path / "ws" / "repos" / "order-svc")
    gone_id = _seed_reusable_whitebox(tmp_path, "ws", "pay-svc")
    form_yaml2 = (
        "repos:\n"
        "  frontend:\n    path: frontend\n    role: entrypoint\n"
        f"  pay-svc:\n    workspace: {gone_id}\n"
        "relations:\n  - {from: frontend, to: pay-svc, protocol: grpc}\n"
    )
    _sm2, _store2, _sub2, _pre2, _ws2, scan_id2 = await _start_corr_env(
        tmp_path, monkeypatch, yaml_text=form_yaml2)
    sess2 = json.loads(
        (tmp_path / "ws" / "scans" / scan_id2 / "session.json").read_text())
    raw2 = yaml.safe_load(Path(sess2["config_path"]).read_text("utf-8"))
    assert raw2["repos"]["pay-svc"]["path"] is None
    assert Path(raw2["repos"]["frontend"]["path"]) == (
        tmp_path / "ws" / "repos" / "frontend").resolve()


@pytest.mark.asyncio
async def test_start_correlation_failed_child_short_circuits(tmp_path, monkeypatch):
    """C3 现扫子仓失败 → 不进关联阶段（corr 不提交）、主行 failed、scan_end 落盘。"""
    _seed_repo(tmp_path, "ws", "frontend")
    _seed_repo(tmp_path, "ws", "order-svc")
    sm, store, submitted, pre_ids, ws_name, scan_id = await _start_corr_env(
        tmp_path, monkeypatch, fail_child=True,
        yaml_text=_corr_yaml("path: frontend, role: entrypoint",
                             "path: order-svc"))
    assert submitted["corr"] == 0  # 子仓失败短路：关联阶段不提交
    main = next(s for s in store.list_scans("ws") if s.scan_id == scan_id)
    assert main.status == "failed"
    events_text = (tmp_path / "ws" / "scans" / scan_id / "events.ndjson").read_text()
    assert '"scan_end"' in events_text and '"failed"' in events_text
    assert (ws_name, scan_id) not in sm._orchestrator_tasks  # 编排 finally 自清


@pytest.mark.asyncio
async def test_start_correlation_gateway_url_runs_blackbox(tmp_path, monkeypatch):
    """C3 gateway url → 关联完成后建 run-1 且 correlated_workspace=主行 scan_id。"""
    _seed_repo(tmp_path, "ws", "frontend")
    _seed_repo(tmp_path, "ws", "order-svc")
    sm, store, submitted, pre_ids, ws_name, scan_id = await _start_corr_env(
        tmp_path, monkeypatch, url="http://gw",
        yaml_text=_corr_yaml("path: frontend, role: entrypoint",
                             "path: order-svc"))
    assert submitted["corr"] == 1  # 关联先跑完
    assert submitted["bb"] is not None  # 段③黑盒验证被触发
    run_id, correlated_ws = submitted["bb"]
    assert run_id == "run-1"
    assert correlated_ws == scan_id  # gateway 验证挂主行（黑盒复用其 topology）
    runs = store.list_blackbox_runs("ws", scan_id)
    assert [r["run_id"] for r in runs] == ["run-1"]


# ── C3 fix ①：段③就绪门/进度分母 correlation-aware（真实流不被 skip）──────────

@pytest.mark.asyncio
async def test_whitebox_deliverables_ready_correlation_layout(tmp_path):
    """fix ①：correlation 主行就绪门查 deliverables/ 根合并 queue（非空 → ready；
    空/缺失 → not ready）；白盒行行为字节不变（仍要求 whitebox/recon + whitebox/ 下
    queue，仅根级 queue 不放行——证明是分流而非放宽）。"""
    sm, store = _make_manager_with_store(tmp_path)
    # ① correlation 行 + 根级非空合并 queue → ready（关联段产物布局）
    _cid, cdir = store.create_scan("ws", "http://gw", "corr-a", "correlation")
    dlv = cdir / "deliverables"
    dlv.mkdir(parents=True)
    (dlv / "injection_exploitation_queue.json").write_text(
        '{"vulnerabilities": [{"title": "t"}]}', encoding="utf-8")
    assert sm._whitebox_deliverables_ready(cdir) is True
    assert sm._count_nonempty_queues(cdir) == 1
    # ② correlation 行 + 空合并 queue → not ready
    _cid2, cdir2 = store.create_scan("ws", "http://gw", "corr-b", "correlation")
    dlv2 = cdir2 / "deliverables"
    dlv2.mkdir(parents=True)
    (dlv2 / "xss_exploitation_queue.json").write_text(
        '{"vulnerabilities": []}', encoding="utf-8")
    assert sm._whitebox_deliverables_ready(cdir2) is False
    assert sm._count_nonempty_queues(cdir2) == 0
    # ③ 白盒行不变：仅根级 queue（无 whitebox/recon_deliverable.md）→ not ready
    _wid, wdir = store.create_scan("ws", "", "repo-w", "whitebox")
    wdlv = wdir / "deliverables"
    wdlv.mkdir(parents=True)
    (wdlv / "injection_exploitation_queue.json").write_text(
        '{"vulnerabilities": [{"title": "t"}]}', encoding="utf-8")
    assert sm._whitebox_deliverables_ready(wdir) is False
    assert sm._count_nonempty_queues(wdir) == 0  # 白盒口径不看 deliverables 根


@pytest.mark.asyncio
async def test_run_blackbox_phase_correlation_row_proceeds_past_gate(
        tmp_path, monkeypatch):
    """fix ①：correlation 主行（根级合并 queue）→ _run_blackbox_phase 过就绪门真提交
    黑盒（mock 仅 _submit_blackbox 提交边界，对齐 C1 测试范式）+ expected.blackbox
    分母 = 非空合并 queue 数（correlation 口径）；无 queue 的 correlation 行 →
    skipped 不提交。"""
    from supernova_core.session import SessionManager
    sm, store = _make_manager_with_store(tmp_path)
    scan_id, scan_dir = store.create_scan("ws", "http://gw", "corr-gw", "correlation")
    dlv = scan_dir / "deliverables"
    dlv.mkdir(parents=True)
    (dlv / "injection_exploitation_queue.json").write_text(
        '{"vulnerabilities": [{"title": "t"}]}', encoding="utf-8")
    submitted = {}

    async def fake_submit_blackbox(self, repo_path, ws, scan_id, scan_dir, event_file,
                                   web_url, config_path, host_mappings=None,
                                   workflow_id_suffix="", correlated_workspace=None):
        submitted["kwargs"] = dict(
            web_url=web_url, repo_path=repo_path,
            correlated_workspace=correlated_workspace, host_mappings=host_mappings)
        return object()

    async def fake_await(self, handle, attempts=5, backoff_base=2.0):
        return {"status": "completed"}

    mark_run = AsyncMock()
    monkeypatch.setattr(type(sm), "_submit_blackbox", fake_submit_blackbox)
    monkeypatch.setattr(type(sm), "_await_workflow_result", fake_await)
    monkeypatch.setattr(type(sm), "_mark_run", mark_run)
    monkeypatch.setattr(type(sm), "_generate_combined_report", AsyncMock())

    await sm._run_blackbox_phase(
        scan_dir, "ws", scan_id, {}, "run-1",
        workflow_id_suffix="-bb-1", correlated_workspace=scan_id)
    assert submitted["kwargs"]["correlated_workspace"] == scan_id
    assert submitted["kwargs"]["web_url"] == "http://gw"  # bb_url 缺失回落 web_url
    # expected_agents.blackbox 分母（correlation 口径）= 非空合并 queue 数
    sess = SessionManager(scan_dir.parent).get_session_data(scan_dir)
    assert sess["expected_agents"]["blackbox"] == 1

    # 无合并 queue 的 correlation 行 → 就绪门拦下，标 skipped、不提交黑盒
    submitted.clear()
    scan_id2, scan_dir2 = store.create_scan("ws", "http://gw", "corr-empty", "correlation")
    (scan_dir2 / "deliverables").mkdir(parents=True)
    await sm._run_blackbox_phase(
        scan_dir2, "ws", scan_id2, {}, "run-1", workflow_id_suffix="-bb-1")
    assert submitted == {}
    assert any(c.args[2] == "skipped" for c in mark_run.await_args_list)


# ── C3 fix ②：correlation+url 解析 HOST 快照进主行 session ───────────────────

@pytest.mark.asyncio
async def test_start_correlation_gateway_url_resolves_host(tmp_path, monkeypatch):
    """fix ②：correlation + gateway url + host_url → HOST 解析并落主行 session
    （不可变 host_config 快照 + legacy bb_host_mappings，镜像组合分支的 session 写）。"""
    from supernova_core.session import SessionManager
    _seed_repo(tmp_path, "ws", "frontend")
    _seed_repo(tmp_path, "ws", "order-svc")
    sm, store, submitted, pre_ids, ws_name, scan_id = await _start_corr_env(
        tmp_path, monkeypatch, url="http://gw", host_url="https://h.test/get?id=1",
        yaml_text=_corr_yaml("path: frontend, role: entrypoint", "path: order-svc"))
    scan_dir = tmp_path / "ws" / "scans" / scan_id
    sess = SessionManager(scan_dir.parent).get_session_data(scan_dir)
    assert sess["host_config"]["mappings"] == {"gw.test": "10.0.0.2"}
    assert sess["bb_host_mappings"] == {"gw.test": "10.0.0.2"}


@pytest.mark.asyncio
async def test_start_correlation_without_url_ignores_host_fields(tmp_path, monkeypatch):
    """fix ② 零回归：correlation 无 url（无段③黑盒验证）→ HOST 字段仍忽略，
    主行 session 无 host 键（既有行为保留）。"""
    from supernova_core.session import SessionManager
    _seed_repo(tmp_path, "ws", "frontend")
    _seed_repo(tmp_path, "ws", "order-svc")
    sm, store, submitted, pre_ids, ws_name, scan_id = await _start_corr_env(
        tmp_path, monkeypatch, host_url="https://h.test/get?id=1",
        yaml_text=_corr_yaml("path: frontend, role: entrypoint", "path: order-svc"))
    scan_dir = tmp_path / "ws" / "scans" / scan_id
    sess = SessionManager(scan_dir.parent).get_session_data(scan_dir)
    assert "host_config" not in sess
    assert "bb_host_mappings" not in sess


def test_scan_request_correlation_url_enforces_host_xor():
    """fix ②：correlation+url 同组合模式校验 HOST 双源互斥（→ ValidationError）；
    无 url 仍忽略 HOST 字段（既有行为由 test_correlation_ignores_legacy_host_fields
    在 test_scan_request_combined.py 锁定）。"""
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        ScanRequest(type="correlation", workspace="ws", url="http://gw",
                    config_content="x",
                    host_profile_id="host_p", host_url="https://h.test/get?id=1")
    # 单源合法
    r = ScanRequest(type="correlation", workspace="ws", url="http://gw",
                    config_content="x", host_url="https://h.test/get?id=1")
    assert r.host_url == "https://h.test/get?id=1"


# ── C3 fix round 2：correlation gateway 黑盒认证落地（spec §5.3 段③「+认证可选」）──

# _start_corr_env 把类级 _run_blackbox_phase 换成 fake；round 2 用例需驱动真实段③
# （仅 mock _submit_blackbox 提交边界）--import 时保存原函数对象（早于任何打补丁）。
_REAL_RUN_BLACKBOX_PHASE = ScanManager._run_blackbox_phase


async def _run_real_bb_phase_capture(sm, monkeypatch, scan_dir, ws, scan_id):
    """真 _run_blackbox_phase 跑一遍（mock 仅 _submit_blackbox/_mark_run/
    _generate_combined_report；_await_workflow_result 沿用 _start_corr_env 的
    fake），返回捕获的 _submit_blackbox kwargs。先在主行 deliverables/ 根种一个
    非空合并 queue 过 fix ① 的就绪门（模拟关联段产物）。"""
    captured = {}

    async def fake_submit_blackbox(self, repo_path, ws, scan_id, scan_dir,
                                   event_file, web_url, config_path,
                                   host_mappings=None, workflow_id_suffix="",
                                   correlated_workspace=None):
        # 参数名须与真 _submit_blackbox 签名一致（_run_blackbox_phase 按关键字调用）。
        captured["config_path"] = config_path
        captured["web_url"] = web_url
        captured["correlated_workspace"] = correlated_workspace
        return object()

    monkeypatch.setattr(type(sm), "_submit_blackbox", fake_submit_blackbox)
    monkeypatch.setattr(type(sm), "_mark_run", AsyncMock())
    monkeypatch.setattr(type(sm), "_generate_combined_report", AsyncMock())
    dlv = scan_dir / "deliverables"
    dlv.mkdir(parents=True, exist_ok=True)
    (dlv / "injection_exploitation_queue.json").write_text(
        '{"vulnerabilities": [{"title": "t"}]}', encoding="utf-8")
    await _REAL_RUN_BLACKBOX_PHASE(
        sm, scan_dir, ws, scan_id, {}, "run-1",
        workflow_id_suffix="-bb-1", correlated_workspace=scan_id)
    return captured


@pytest.mark.asyncio
async def test_start_correlation_gateway_url_dumps_auth_config(tmp_path, monkeypatch):
    """fix round 2：correlation + url + inline 认证 -> 镜像组合分支 dump 认证配置到
    主行（scan-config.yaml + session bb_auth_ref），_run_blackbox_phase（真函数、仅
    mock _submit_blackbox）收到的 config_path 指向该文件（黑盒 workflow 会跑登录）。"""
    import yaml
    from supernova_core.session import SessionManager
    _seed_repo(tmp_path, "ws", "frontend")
    _seed_repo(tmp_path, "ws", "order-svc")
    sm, store, submitted, pre_ids, ws_name, scan_id = await _start_corr_env(
        tmp_path, monkeypatch, url="http://gw",
        authentication={"login_type": "form", "login_url": "http://gw/login",
                        "credentials": {"username": "a", "password": "b"}},
        yaml_text=_corr_yaml("path: frontend, role: entrypoint", "path: order-svc"))
    scan_dir = tmp_path / "ws" / "scans" / scan_id
    # 认证配置 dump 到主行 + bb_auth_ref 引用落 session（inline 模式 profile_id=None）
    cfg_file = scan_dir / "scan-config.yaml"
    assert cfg_file.exists()
    payload = yaml.safe_load(cfg_file.read_text("utf-8"))
    assert "authentication" in payload
    sess = SessionManager(scan_dir.parent).get_session_data(scan_dir)
    assert sess["bb_auth_ref"] == {"profile_id": None}
    # 真实段③：config_path 解析到 dump 的文件（非 None）
    captured = await _run_real_bb_phase_capture(sm, monkeypatch, scan_dir, "ws", scan_id)
    assert captured["config_path"] == str(cfg_file)
    assert captured["correlated_workspace"] == scan_id


@pytest.mark.asyncio
async def test_start_correlation_gateway_url_without_auth_no_config(tmp_path, monkeypatch):
    """fix round 2 零回归：correlation + url 无认证 -> 不 dump scan-config.yaml，
    _run_blackbox_phase 收到的 config_path 为 None（黑盒跳过登录段）。"""
    _seed_repo(tmp_path, "ws", "frontend")
    _seed_repo(tmp_path, "ws", "order-svc")
    sm, store, submitted, pre_ids, ws_name, scan_id = await _start_corr_env(
        tmp_path, monkeypatch, url="http://gw",
        yaml_text=_corr_yaml("path: frontend, role: entrypoint", "path: order-svc"))
    scan_dir = tmp_path / "ws" / "scans" / scan_id
    assert not (scan_dir / "scan-config.yaml").exists()
    captured = await _run_real_bb_phase_capture(sm, monkeypatch, scan_dir, "ws", scan_id)
    assert captured["config_path"] is None


# ── C4: correlation cancel 级联 + resume 收口 ──────────────────────────────

def _fake_wf_handle_factory(wf_cancels: list):
    """Client.get_workflow_handle 替身：按 id 造 handle，cancel 记录进 wf_cancels。"""

    def fake_get_handle(wf_id, *args, **kwargs):
        h = MagicMock()
        h.id = wf_id
        h.cancel = AsyncMock(side_effect=lambda: wf_cancels.append(wf_id))
        return h

    return fake_get_handle


@pytest.mark.asyncio
async def test_cancel_correlation_cascades(tmp_path, monkeypatch):
    """C4: 取消 correlation 主行级联——编排 task cancel+pop、主/子仓 _handles cancel、
    现扫子仓白盒 + -corr 关联 workflow re-attach cancel（复用子仓已终态不碰）、
    heartbeat fresh 写协作式信号、主行标 cancelled + scan_end。"""
    from supernova_core.session import SessionManager
    sm, store = _make_manager_with_store(tmp_path)
    scan_id, scan_dir = store.create_scan("ws", "", "frontend", "correlation")
    c1_id, _c1_dir = store.create_scan("ws", "", "frontend", "whitebox")
    c2_id, _c2_dir = store.create_scan("ws", "", "order-svc", "whitebox")
    SessionManager(scan_dir.parent).update_session(scan_dir, {"corr_children": [
        {"service": "frontend", "scan_id": c1_id, "reused": False},
        {"service": "order-svc", "scan_id": c2_id, "reused": True},
    ]})
    # 编排 task 占位（挂起协程；cancel 后应 cancelled 且 key 被 pop）
    orch = asyncio.ensure_future(asyncio.sleep(60))
    sm._orchestrator_tasks[("ws", scan_id)] = orch
    # 主行 + 现扫子仓 handle 登记（AsyncMock cancel）；复用子仓无 handle
    main_h, c1_h = AsyncMock(), AsyncMock()
    sm._handles[("ws", scan_id)] = main_h
    sm._handles[("ws", c1_id)] = c1_h
    # Temporal re-attach mock：记录被 cancel 的 workflow id
    wf_cancels: list = []
    mock_client = _patch_client(monkeypatch)
    mock_client.get_workflow_handle = _fake_wf_handle_factory(wf_cancels)
    # heartbeat fresh → 协作式信号兜底
    (scan_dir / "heartbeat").write_text(f"{time.time()}\n")

    result = await sm.cancel("ws", scan_id)

    assert result == {"cancelled": scan_id}
    assert ("ws", scan_id) not in sm._orchestrator_tasks  # 编排 task 已 pop
    await asyncio.sleep(0)  # 让 cancel 传播到挂起协程
    assert orch.cancelled()
    main_h.cancel.assert_awaited_once()   # 主行 handle（登记路径）
    c1_h.cancel.assert_awaited_once()     # 现扫子仓 handle（登记路径）
    assert f"ws-{c1_id}" in wf_cancels    # 现扫子仓 workflow re-attach cancel
    assert f"ws-{scan_id}-corr" in wf_cancels  # 关联 workflow cancel
    assert f"ws-{c2_id}" not in wf_cancels     # 复用子仓（已终态）不碰
    assert f"ws-{scan_id}" not in wf_cancels   # 主行无白盒 base workflow（区别于组合路径）
    assert (scan_dir / "cancel.requested").exists()  # heartbeat fresh → 信号
    sess = json.loads((scan_dir / "session.json").read_text())
    assert sess["status"] == "cancelled"
    assert sess.get("completed_at") is not None
    assert '"scan_end"' in (scan_dir / "events.ndjson").read_text()


@pytest.mark.asyncio
async def test_cancel_correlation_with_active_bb_run(tmp_path, monkeypatch):
    """C4: 段③黑盒 run 在跑（latest 非终态）→ run workflow re-attach cancel + 标
    cancelled（防永久 pending 禁用 delete/续跑门）。段③建 run 会给主行 session 写
    combined=True（create_blackbox_run 副作用）——路由仍按 scan_type=correlation 级联
    （不进 _cancel_combined：base/authcheck workflow 不被 cancel）。"""
    sm, store = _make_manager_with_store(tmp_path)
    scan_id, scan_dir = store.create_scan("ws", "", "gw", "correlation")
    run_id, _run_dir = store.create_blackbox_run("ws", scan_id)
    assert json.loads((scan_dir / "session.json").read_text()).get("combined") is True
    wf_cancels: list = []
    mock_client = _patch_client(monkeypatch)
    mock_client.get_workflow_handle = _fake_wf_handle_factory(wf_cancels)

    result = await sm.cancel("ws", scan_id)

    assert result == {"cancelled": scan_id}
    assert f"ws-{scan_id}-bb-1" in wf_cancels       # 活跃 run 的黑盒 workflow
    assert f"ws-{scan_id}-corr" in wf_cancels       # 走 correlation 级联（非组合路径）
    assert f"ws-{scan_id}" not in wf_cancels        # 组合路径的 base cancel 未发生
    assert f"ws-{scan_id}-authcheck" not in wf_cancels  # 组合路径的 authcheck 未发生
    runs = store.list_blackbox_runs("ws", scan_id)
    assert runs[-1]["status"] == "cancelled"        # run 收终态
    sess = json.loads((scan_dir / "session.json").read_text())
    assert sess["status"] == "cancelled"            # 主行照标 cancelled


@pytest.mark.asyncio
async def test_cancel_correlation_temporal_unreachable_still_marks(tmp_path, monkeypatch):
    """C4: Temporal 不可达（Client.connect 抛）→ re-attach 全跳过，仍标 cancelled
    （对齐 _cancel_combined 的 best-effort 语义：不可达不阻断终态）。"""
    from supernova_core.session import SessionManager
    sm, store = _make_manager_with_store(tmp_path)
    scan_id, scan_dir = store.create_scan("ws", "", "gw", "correlation")
    c1_id, _c1_dir = store.create_scan("ws", "", "frontend", "whitebox")
    SessionManager(scan_dir.parent).update_session(scan_dir, {"corr_children": [
        {"service": "frontend", "scan_id": c1_id, "reused": False}]})

    async def boom(*args, **kwargs):
        raise RuntimeError("temporal down")

    monkeypatch.setattr(
        "supernova_web.components.scan_manager.Client.connect", boom)
    result = await sm.cancel("ws", scan_id)
    assert result == {"cancelled": scan_id}
    sess = json.loads((scan_dir / "session.json").read_text())
    assert sess["status"] == "cancelled"
    assert '"scan_end"' in (scan_dir / "events.ndjson").read_text()


@pytest.mark.asyncio
async def test_resume_correlation_alive_noop(tmp_path):
    """C4: correlation 主行 heartbeat 判活 → resume no-op（ValueError 拒绝；不动
    session、不提交 workflow）。session 显式 interrupted 但 worker 复活的 race 由
    纯心跳门兜底；分支位于 _check_temporal 之前（ValueError 而非 Temporal 侧错误）。"""
    from supernova_core.session import SessionManager
    sm, store = _make_manager_with_store(tmp_path)
    scan_id, scan_dir = store.create_scan("ws", "", "frontend", "correlation")
    SessionManager(scan_dir.parent).update_session(scan_dir, {"status": "interrupted"})
    (scan_dir / "heartbeat").write_text(f"{time.time()}\n")  # fresh → 判活
    before = (scan_dir / "session.json").read_text()

    with pytest.raises(ValueError, match="仍在运行"):
        await sm.resume("ws", scan_id)

    assert (scan_dir / "session.json").read_text() == before  # session 零改动
    assert not sm._handles and not sm._orchestrator_tasks     # 零提交


@pytest.mark.asyncio
async def test_resume_correlation_stale_marks_interrupted(tmp_path):
    """C4: stale correlation 主行（session running + 无心跳，web 崩溃未及 reconcile）→
    resume 标 interrupted 终态（补 scan_end + session）+ ValueError 引导重扫；不重入
    接力（零 workflow 提交、不写 resumeAttempts——不走白盒 resume 机器）。"""
    from supernova_core.session import SessionManager
    sm, store = _make_manager_with_store(tmp_path)
    scan_id, scan_dir = store.create_scan("ws", "", "frontend", "correlation")
    sess = json.loads((scan_dir / "session.json").read_text())
    sess["status"] = "running"
    sess["created_at"] = time.time() - 3600  # 越过提交宽限门（created_at 回落锚点）
    (scan_dir / "session.json").write_text(json.dumps(sess))
    # 无 heartbeat + 宽限外 → _compute_status 判 interrupted → 过 resumable 门

    with pytest.raises(ValueError, match="不支持断点恢复"):
        await sm.resume("ws", scan_id)

    sess = json.loads((scan_dir / "session.json").read_text())
    assert sess["status"] == "interrupted"
    assert sess.get("completed_at") is not None
    events = (scan_dir / "events.ndjson").read_text()
    assert '"scan_end"' in events and '"interrupted"' in events
    assert "resumeAttempts" not in sess              # 不走白盒 resume 重提交机器
    assert not sm._handles and not sm._orchestrator_tasks

    # 幂等：已收口后再 resume 不覆写终态（同 ValueError、scan_end 不双写）
    with pytest.raises(ValueError, match="不支持断点恢复"):
        await sm.resume("ws", scan_id)
    assert (scan_dir / "events.ndjson").read_text().count('"scan_end"') == 1


# ── resume 接通 agent 级断点续传（spec 2026-08-27-web-resume-breakpoint §4.1/4.2）──

class _StubResumeState:
    def __init__(self, completed_agents=None, aborted=False, abort_reason=None,
                 warnings=None, interrupted_agent=None):
        self.completed_agents = completed_agents or []
        self.aborted = aborted
        self.abort_reason = abort_reason
        self.warnings = warnings or []
        self.interrupted_agent = interrupted_agent


class _StubResumeBuilder:
    """wiring 级替身：记录 build/cleanup 调用、返回受控 state。
    builder 本体（G∧F 对账）在 whitebox 侧测试覆盖，web 层只验接线。"""

    def __init__(self):
        self.build_calls = []
        self.cleanup_calls = []
        self._next_state = _StubResumeState()

    def set_state(self, state):
        self._next_state = state

    async def build(self, *, mode, workspace, deliverables, repo_path, **kw):
        self.build_calls.append({"mode": mode, "workspace": workspace,
                                 "deliverables": deliverables,
                                 "repo_path": repo_path})
        return self._next_state

    async def cleanup(self, *, mode, deliverables, completed_agents, **kw):
        self.cleanup_calls.append({"mode": mode, "deliverables": deliverables,
                                   "completed_agents": list(completed_agents)})


@pytest.fixture
def stub_resume_builder(monkeypatch):
    import supernova_web.components.scan_manager as scm
    inst = _StubResumeBuilder()
    monkeypatch.setattr(scm, "WhiteboxResumeStateBuilder", lambda: inst)
    return inst


def _set_status(scan_dir, status):
    from supernova_core.session import SessionManager
    SessionManager(scan_dir.parent).update_session(scan_dir, {"status": status})


@pytest.mark.asyncio
async def test_resume_whitebox_reconciles_and_passes_completed_agents(
        tmp_path, monkeypatch, stub_resume_builder):
    """§4.2：resume 白盒行先对账（builder）+ cleanup 删半成品，再把
    completed_agents 透传进 PipelineInput（workflow L105-107 激活跳过守卫），
    并写续跑摘要 InfoEvent 进 events.ndjson（live 流可见）。"""
    from supernova_core.session import SessionManager
    sm, store = _make_manager_with_store(tmp_path)
    scan_id, scan_dir = store.create_scan("ws", "", "/repo/a", "whitebox")
    SessionManager(scan_dir.parent).update_session(scan_dir, {"status": "interrupted"})
    stub_resume_builder.set_state(_StubResumeState(
        completed_agents=["pre-recon", "recon"], interrupted_agent="injection-vuln"))

    _patch_temporal_ok(monkeypatch, sm)
    mock_client = _patch_client(monkeypatch)
    with patch.object(sm, "_watch", new=AsyncMock()):
        await sm.resume("ws", scan_id)

    call = stub_resume_builder.build_calls[0]
    assert call["mode"] == "auto"
    assert call["workspace"] == scan_dir
    assert call["deliverables"] == scan_dir / "deliverables" / "whitebox"
    assert stub_resume_builder.cleanup_calls[0]["completed_agents"] == ["pre-recon", "recon"]
    inp = mock_client.start_workflow.call_args.args[1]
    assert inp.resume_completed_agents == ["pre-recon", "recon"]
    events = (scan_dir / "events.ndjson").read_text()
    assert '"InfoEvent"' in events
    assert "pre-recon" in events


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["failed", "cancelled", "killed", "crashed", "interrupted"])
async def test_resume_status_gate_allows_non_completed_terminal_states(
        tmp_path, monkeypatch, stub_resume_builder, status):
    """§4.1：_RESUMABLE_STATUSES 扩集——failed（最常见中断出口）/cancelled/killed
    全部放行（无心跳时）；不再只有 interrupted/crashed。"""
    sm, store = _make_manager_with_store(tmp_path)
    scan_id, scan_dir = store.create_scan("ws", "", "/repo/a", "whitebox")
    _set_status(scan_dir, status)

    _patch_temporal_ok(monkeypatch, sm)
    _patch_client(monkeypatch)
    with patch.object(sm, "_watch", new=AsyncMock()):
        ws, sid = await sm.resume("ws", scan_id)  # 不抛「不可恢复」即过门
    assert (ws, sid) == ("ws", scan_id)


@pytest.mark.asyncio
async def test_resume_completed_status_still_rejected(tmp_path):
    """completed 仍不可续跑（重跑语义走新建 scan）。"""
    sm, store = _make_manager_with_store(tmp_path)
    scan_id, scan_dir = store.create_scan("ws", "", "/repo/a", "whitebox")
    _set_status(scan_dir, "completed")
    with pytest.raises(ValueError, match="不可恢复"):
        await sm.resume("ws", scan_id)


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["killed", "crashed", "interrupted"])
async def test_resume_fresh_heartbeat_rejected(tmp_path, monkeypatch, status):
    """§4.1：非 failed 状态 + 心跳新鲜 → 撞车拒绝（防与残留 workflow 撞车），
    零提交零 session 改动。"""
    sm, store = _make_manager_with_store(tmp_path)
    scan_id, scan_dir = store.create_scan("ws", "", "/repo/a", "whitebox")
    _set_status(scan_dir, status)
    (scan_dir / "heartbeat").write_text(f"{time.time()}\n")  # fresh
    before = (scan_dir / "session.json").read_text()

    _patch_temporal_ok(monkeypatch, sm)
    mock_client = _patch_client(monkeypatch)
    with pytest.raises(ValueError, match="仍在运行"):
        await sm.resume("ws", scan_id)

    assert (scan_dir / "session.json").read_text() == before
    mock_client.start_workflow.assert_not_called()


@pytest.mark.asyncio
async def test_resume_cancelled_fresh_heartbeat_transient_message(
        tmp_path, monkeypatch):
    """§4.1：cancelled + 心跳新鲜（worker 退出收尾窗口）→ 拒绝但文案引导「等待
    worker 退出」（区别于 worker 复活 race 的「仍在运行」），零提交零 session 改动。"""
    sm, store = _make_manager_with_store(tmp_path)
    scan_id, scan_dir = store.create_scan("ws", "", "/repo/a", "whitebox")
    _set_status(scan_dir, "cancelled")
    (scan_dir / "heartbeat").write_text(f"{time.time()}\n")  # fresh
    before = (scan_dir / "session.json").read_text()

    _patch_temporal_ok(monkeypatch, sm)
    mock_client = _patch_client(monkeypatch)
    with pytest.raises(ValueError, match="等待 worker 退出"):
        await sm.resume("ws", scan_id)

    assert (scan_dir / "session.json").read_text() == before
    mock_client.start_workflow.assert_not_called()


@pytest.mark.asyncio
async def test_resume_failed_bypasses_heartbeat_gate(tmp_path, monkeypatch, stub_resume_builder):
    """§4.1：failed = Temporal 已 FAILED 终态，无并发风险——即使心跳文件残留也直接放行。"""
    sm, store = _make_manager_with_store(tmp_path)
    scan_id, scan_dir = store.create_scan("ws", "", "/repo/a", "whitebox")
    _set_status(scan_dir, "failed")
    (scan_dir / "heartbeat").write_text(f"{time.time()}\n")  # 残留心跳不拦 failed

    _patch_temporal_ok(monkeypatch, sm)
    _patch_client(monkeypatch)
    with patch.object(sm, "_watch", new=AsyncMock()):
        await sm.resume("ws", scan_id)


@pytest.mark.asyncio
async def test_resume_builder_abort_raises_with_reason(
        tmp_path, monkeypatch, stub_resume_builder):
    """§4.2/§4.6：G∧¬F 产物丢失 → builder abort → ValueError 带 abort_reason
    （API 层映射 422），不 cleanup、不提交 workflow。"""
    sm, store = _make_manager_with_store(tmp_path)
    scan_id, scan_dir = store.create_scan("ws", "", "/repo/a", "whitebox")
    _set_status(scan_dir, "interrupted")
    stub_resume_builder.set_state(_StubResumeState(
        aborted=True, abort_reason="resume 中止：recon 有 deliverable commit 但产出物文件缺失"))

    _patch_temporal_ok(monkeypatch, sm)
    mock_client = _patch_client(monkeypatch)
    with pytest.raises(ValueError, match="产出物文件缺失"):
        await sm.resume("ws", scan_id)

    assert stub_resume_builder.cleanup_calls == []
    mock_client.start_workflow.assert_not_called()


# ── resume-preview（spec 2026-08-27-web-resume-breakpoint §4.5）──────────────

@pytest.mark.asyncio
async def test_resume_preview_whitebox_full(tmp_path, monkeypatch, stub_resume_builder):
    """白盒行可续跑：builder 对账结果 + step 简表（无 marker → missing）+ 摘要
    字段齐全；只读——不调 cleanup、不提交 workflow。"""
    sm, store = _make_manager_with_store(tmp_path)
    from supernova_core.session import SessionManager
    scan_id, scan_dir = store.create_scan("ws", "", "/repo/a", "whitebox")
    _set_status(scan_dir, "failed")
    SessionManager(scan_dir.parent).update_session(
        scan_dir, {"resumeAttempts": [{"workflowId": "x"}, {"workflowId": "y"}]})
    stub_resume_builder.set_state(_StubResumeState(
        completed_agents=["pre-recon", "recon"], interrupted_agent="injection-vuln",
        warnings=["xss-vuln: 半成品，将重跑"]))

    result = await sm.resume_preview("ws", scan_id)

    assert result["resumable"] is True
    assert result["status"] == "failed"
    assert result["scan_type"] == "whitebox"
    assert result["completed_agents"] == ["pre-recon", "recon"]
    assert result["interrupted_agent"] == "injection-vuln"
    assert result["warnings"] == ["xss-vuln: 半成品，将重跑"]
    assert result["resume_attempts"] == 2
    assert {r["step"] for r in result["steps"]} == {
        "authz-gitnexus-judge", "gitnexus-chain-verdict"}
    assert all(r["state"] == "missing" for r in result["steps"])
    assert stub_resume_builder.cleanup_calls == []  # 只读不动状态


@pytest.mark.asyncio
async def test_resume_preview_abort_maps_unresumable(tmp_path, stub_resume_builder):
    """G∧¬F abort → resumable:false + abort_reason（前端引导重跑），不 cleanup。"""
    sm, store = _make_manager_with_store(tmp_path)
    scan_id, scan_dir = store.create_scan("ws", "", "/repo/a", "whitebox")
    _set_status(scan_dir, "interrupted")
    stub_resume_builder.set_state(_StubResumeState(
        aborted=True, abort_reason="resume 中止：recon 产出物文件缺失"))

    result = await sm.resume_preview("ws", scan_id)

    assert result["resumable"] is False
    assert "产出物文件缺失" in result["abort_reason"]
    assert stub_resume_builder.cleanup_calls == []


@pytest.mark.asyncio
async def test_resume_preview_correlation_unresumable(tmp_path):
    """correlation 主行：resumable:false + 引导重新提交（子仓产物可复用）。"""
    sm, store = _make_manager_with_store(tmp_path)
    scan_id, scan_dir = store.create_scan("ws", "", "frontend", "correlation")
    _set_status(scan_dir, "interrupted")

    result = await sm.resume_preview("ws", scan_id)

    assert result["resumable"] is False
    assert "重新提交" in result["reason"]


@pytest.mark.asyncio
async def test_resume_preview_blackbox_unresumable(tmp_path):
    """黑盒行：resumable:false（黑盒走 rerun 语义）。"""
    from supernova_core.session import SessionManager
    sm, store = _make_manager_with_store(tmp_path)
    scan_id, scan_dir = store.create_scan("ws", "", "/repo/a", "whitebox")
    SessionManager(scan_dir.parent).update_session(
        scan_dir, {"scan_type": "blackbox", "status": "interrupted"})

    result = await sm.resume_preview("ws", scan_id)

    assert result["resumable"] is False


@pytest.mark.asyncio
async def test_resume_preview_completed_unresumable(tmp_path):
    sm, store = _make_manager_with_store(tmp_path)
    scan_id, scan_dir = store.create_scan("ws", "", "/repo/a", "whitebox")
    _set_status(scan_dir, "completed")

    result = await sm.resume_preview("ws", scan_id)

    assert result["resumable"] is False
    assert result["reason"]


@pytest.mark.asyncio
@pytest.mark.parametrize("status,expect_transient", [
    ("cancelled", True),
    ("interrupted", False),  # worker 复活 race：非瞬态语义，维持「仍在运行」
])
async def test_resume_preview_fresh_heartbeat_reason_split(
        tmp_path, status, expect_transient):
    """心跳新鲜两分叉：cancelled（取消收尾窗口）→ transient:true + 「等待 worker
    退出」引导文案；interrupted 等 race 场景 → 原「仍在运行」。"""
    sm, store = _make_manager_with_store(tmp_path)
    scan_id, scan_dir = store.create_scan("ws", "", "/repo/a", "whitebox")
    _set_status(scan_dir, status)
    (scan_dir / "heartbeat").write_text(f"{time.time()}\n")

    result = await sm.resume_preview("ws", scan_id)

    assert result["resumable"] is False
    assert result["transient"] is expect_transient
    if expect_transient:
        assert "等待 worker 退出" in result["reason"]
    else:
        assert "仍在运行" in result["reason"]


@pytest.mark.asyncio
async def test_resume_preview_resumable_not_transient(tmp_path, monkeypatch,
                                                      stub_resume_builder):
    """可续跑（心跳已 stale）→ transient 缺省 False——前端据此停轮询。"""
    sm, store = _make_manager_with_store(tmp_path)
    scan_id, scan_dir = store.create_scan("ws", "", "/repo/a", "whitebox")
    _set_status(scan_dir, "cancelled")  # 心跳不存在 = stale

    result = await sm.resume_preview("ws", scan_id)

    assert result["resumable"] is True
    assert result["transient"] is False


@pytest.mark.asyncio
async def test_resume_preview_missing_scan_raises(tmp_path):
    sm, _ = _make_manager_with_store(tmp_path)
    with pytest.raises(ValueError, match="不存在"):
        await sm.resume_preview("ws", "nope")


# ── 2026-09-18 假终态事故：web 关停 cancel 编排/收口协程不写终态 ───────────────
# CancelledError 是 BaseException，except Exception 接不住；此前编排协程 finally 无条件
# _ensure_scan_end(final_status=completed)，部署重启会把 Temporal 里还在跑的扫描写成
# 假 completed（cross-repo-20260918-064512：主行 completed 而关联 workflow 仍 RUNNING）。
# 修法：except CancelledError → re-raise + finally 跳过收口，留 running 交
# orphan_reconcile 按 Temporal 状态收口。


async def _hang(*_a, **_k):
    """永挂的 fake await 点：编排协程 cancel 测试统一注入（只能被 cancel 打断）。"""
    await asyncio.Event().wait()


def _seed_running_scan(sm, name, scan_type="whitebox", extra=None):
    """种一个 running scan 行，返回 (scan_key, scan_dir)。"""
    from supernova_core.session import SessionManager

    scan_id, scan_dir = sm._store.create_scan("ws", "", name, scan_type)
    SessionManager(scan_dir.parent).update_session(
        scan_dir, {"status": "running", **(extra or {})})
    return ("ws", scan_id), scan_dir


async def _cancel_and_assert_raised(task):
    """cancel task 并断言 CancelledError 原样上抛（不吞取消语义）。"""
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


def _make_bare_manager(tmp_path, monkeypatch):
    from supernova_web.components.multi_repo_config_store import MultiRepoConfigStore

    sm = ScanManager(tmp_path, tmp_path / "r", MultiRepoConfigStore(tmp_path / "configs"))
    _patch_temporal_ok(monkeypatch, sm)
    return sm


@pytest.mark.asyncio
async def test_correlation_orchestrator_cancel_writes_no_scan_end(tmp_path, monkeypatch):
    """编排协程被 cancel：不写 scan_end、session 保持 running、登记已清。"""
    sm = _make_bare_manager(tmp_path, monkeypatch)
    monkeypatch.setattr(type(sm), "_await_workflow_result", _hang)
    scan_key, scan_dir = _seed_running_scan(sm, "corr-x", "correlation")
    orch = asyncio.create_task(sm._correlation_orchestrator(
        scan_key, {"svc": ("child-1", _FakeHandle("wb:child-1"))}, scan_dir,
        ScanRequest(type="correlation", workspace="ws"),
        Path("corr.yaml"), {"svc": scan_dir}))
    sm._orchestrator_tasks[scan_key] = orch
    await asyncio.sleep(0.01)  # 进入挂起的 fake await
    await _cancel_and_assert_raised(orch)
    assert not sm._has_scan_end(scan_dir / "events.ndjson")
    sess = json.loads((scan_dir / "session.json").read_text("utf-8"))
    assert sess["status"] == "running"
    assert scan_key not in sm._orchestrator_tasks


@pytest.mark.asyncio
async def test_combined_orchestrator_cancel_writes_no_scan_end(tmp_path, monkeypatch):
    sm = _make_bare_manager(tmp_path, monkeypatch)
    monkeypatch.setattr(type(sm), "_await_workflow_result", _hang)
    scan_key, scan_dir = _seed_running_scan(sm, "comb-x")
    orch = asyncio.create_task(sm._combined_orchestrator(
        scan_key, _FakeHandle("wb"), scan_dir,
        ScanRequest(type="whitebox", workspace="ws")))
    sm._orchestrator_tasks[scan_key] = orch
    await asyncio.sleep(0.01)
    await _cancel_and_assert_raised(orch)
    assert not sm._has_scan_end(scan_dir / "events.ndjson")
    assert scan_key not in sm._orchestrator_tasks


@pytest.mark.asyncio
async def test_combined_report_orchestrator_cancel_writes_no_scan_end(
        tmp_path, monkeypatch):
    sm = _make_bare_manager(tmp_path, monkeypatch)
    monkeypatch.setattr(type(sm), "_await_workflow_result", _hang)
    scan_key, scan_dir = _seed_running_scan(sm, "crep-x")
    orch = asyncio.create_task(sm._combined_report_orchestrator(
        scan_key, _FakeHandle("bb"), scan_dir, "run-1"))
    sm._orchestrator_tasks[scan_key] = orch
    await asyncio.sleep(0.01)
    await _cancel_and_assert_raised(orch)
    assert not sm._has_scan_end(scan_dir / "events.ndjson")
    assert scan_key not in sm._orchestrator_tasks


@pytest.mark.asyncio
async def test_rerun_orchestrator_cancel_writes_no_scan_end_and_keeps_run(
        tmp_path, monkeypatch):
    """cancel 不把 run 标 failed（run 没失败，是 web 关停）。"""
    sm = _make_bare_manager(tmp_path, monkeypatch)
    monkeypatch.setattr(type(sm), "_run_blackbox_phase", _hang)
    scan_key, scan_dir = _seed_running_scan(
        sm, "rerun-x", extra={"bb_pre_run_status": "completed"})
    orch = asyncio.create_task(sm._rerun_orchestrator(
        scan_key, scan_dir, "ws", scan_key[1], {}, "run-1", "-bb-1"))
    sm._orchestrator_tasks[scan_key] = orch
    await asyncio.sleep(0.01)
    await _cancel_and_assert_raised(orch)
    assert not sm._has_scan_end(scan_dir / "events.ndjson")
    runs = sm._store.list_blackbox_runs("ws", scan_key[1])
    assert all(r.get("status") != "failed" for r in runs)
    assert scan_key not in sm._orchestrator_tasks


@pytest.mark.asyncio
async def test_watch_cancel_writes_no_crashed_scan_end(tmp_path, monkeypatch):
    """_watch 被 cancel：不补 crashed（"worker 未写 scan_end" 兜底只对 workflow 真死
    成立），登记清理仍执行。"""
    sm = _make_bare_manager(tmp_path, monkeypatch)
    scan_key, scan_dir = _seed_running_scan(sm, "watch-x")
    event_file = scan_dir / "events.ndjson"
    watch = asyncio.create_task(sm._watch(scan_key, event_file, scan_dir))
    sm._tasks[scan_key] = watch
    await asyncio.sleep(0.01)
    await _cancel_and_assert_raised(watch)
    assert not sm._has_scan_end(event_file)
    assert scan_key not in sm._tasks
    assert scan_key not in sm._handles
    assert scan_key not in sm._active_reqs


@pytest.mark.asyncio
async def test_reconcile_combined_scan_cancel_writes_no_scan_end(tmp_path, monkeypatch):
    """reconcile 后台 task 被 cancel：finally 不收口（下次启动幂等重来）。"""
    sm = _make_bare_manager(tmp_path, monkeypatch)
    monkeypatch.setattr(type(sm), "_query_workflow_status", _hang)
    _scan_key, scan_dir = _seed_running_scan(
        sm, "recmb-x", extra={"combined": True})
    task = asyncio.create_task(sm._reconcile_combined_scan(scan_dir))
    await asyncio.sleep(0.01)
    await _cancel_and_assert_raised(task)
    assert not sm._has_scan_end(scan_dir / "events.ndjson")
