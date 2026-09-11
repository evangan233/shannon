"""T3: 1 ws : N scans 多 scan 独立性 + resume 语义测试。

同 ws 多 scan 不互斥；cancel 按 scan_id 精确；_watch 各 scan 独立 tail 各自 events.ndjson；
active_repo_sources 多 ws 多 scan；resume 放行已停未完成态（interrupted/crashed/failed/
cancelled/killed，spec 2026-08-27 §4.1 扩集），completed/running -> ValueError（用重扫起 scan）。
"""
import asyncio
import json
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from supernova_web.models import RepoSource, ScanRequest
from supernova_web.components.scan_manager import ScanManager


def _make_scan_dir(workspaces_dir, ws, scan_id, status="running",
                   repo_path="/code/x", web_url="http://e"):
    scan_dir = Path(workspaces_dir) / ws / "scans" / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "session.json").write_text(json.dumps({
        "status": status, "scan_type": "whitebox", "created_at": time.time(),
        "web_url": web_url, "repo_path": repo_path,
    }))
    return scan_dir


def _patch_temporal_ok(monkeypatch, mgr):
    async def _ok():
        return None
    monkeypatch.setattr(mgr, "_check_temporal", _ok)


def _patch_client(monkeypatch, handle=None):
    mock_handle = handle or MagicMock()
    mock_client = AsyncMock()
    mock_client.start_workflow = AsyncMock(return_value=mock_handle)
    monkeypatch.setattr("supernova_web.components.scan_manager.Client.connect",
                       AsyncMock(return_value=mock_client))
    return mock_client


# ── 多 scan 独立性 ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_watch_each_scan_independent(tmp_path):
    """两 scan 各自 _watch tail 各自 events.ndjson，互不串台。"""
    mgr = ScanManager(tmp_path, tmp_path / "r", None)
    d1 = _make_scan_dir(tmp_path, "WS", scan_id="s1")
    d2 = _make_scan_dir(tmp_path, "WS", scan_id="s2")
    f1, f2 = d1 / "events.ndjson", d2 / "events.ndjson"
    k1, k2 = ("WS", "s1"), ("WS", "s2")
    mgr._handles[k1] = MagicMock()
    mgr._handles[k2] = MagicMock()

    async def write_end(f):
        await asyncio.sleep(0.15)
        f.write_text('{"type":"scan_end","status":"completed"}\n')

    asyncio.create_task(write_end(f1))
    asyncio.create_task(write_end(f2))
    await asyncio.gather(mgr._watch(k1, f1, d1), mgr._watch(k2, f2, d2))
    assert k1 not in mgr._handles and k2 not in mgr._handles
    assert '"scan_end"' in f1.read_text() and '"scan_end"' in f2.read_text()


@pytest.mark.asyncio
async def test_cancel_by_scan_id_precise(tmp_path):
    """cancel scan A 不影响 scan B（按 (ws, scan_id) 精确取消）。"""
    mgr = ScanManager(tmp_path, tmp_path / "r", None)
    _make_scan_dir(tmp_path, "WS", scan_id="s1", status="running")
    _make_scan_dir(tmp_path, "WS", scan_id="s2", status="running")
    h1, h2 = AsyncMock(), AsyncMock()
    mgr._handles[("WS", "s1")] = h1
    mgr._handles[("WS", "s2")] = h2

    await mgr.cancel("WS", "s1")

    h1.cancel.assert_awaited_once()
    h2.cancel.assert_not_awaited()  # B 未被取消
    # 注: cancel ① 轨不自行 pop _handles（_watch finally 见 scan_end 才 pop）；
    # 此处仅验 h2 未被动 + h1 被精确取消。


def test_active_repo_sources_multi_ws_multi_scan(tmp_path):
    """active_repo_sources 多 ws 多 scan 聚合 (ws, repo) 集。"""
    mgr = ScanManager(tmp_path, tmp_path / "r", None)
    mgr._active_reqs[("wsA", "s1")] = ScanRequest(
        type="whitebox", source=RepoSource(kind="repo", value="foo"), url="u")
    mgr._active_reqs[("wsA", "s2")] = ScanRequest(
        type="whitebox", source=RepoSource(kind="repo", value="bar"), url="u")
    mgr._active_reqs[("wsB", "s1")] = ScanRequest(
        type="whitebox", source=RepoSource(kind="repo", value="foo"), url="u")
    srcs = mgr.active_repo_sources()
    assert srcs == {("wsA", "foo"), ("wsA", "bar"), ("wsB", "foo")}


# ── resume 语义（用户决策：仅 interrupted/crashed 可 resume）─────────────────

@pytest.mark.asyncio
async def test_resume_interrupted_increments_attempts_and_submits(tmp_path, monkeypatch):
    """interrupted scan -> resume：resumeAttempts+1 + 提交 workflow_id={ws}-{scan_id}-resume-1。"""
    mgr = ScanManager(tmp_path, tmp_path / "r", None)
    _patch_temporal_ok(monkeypatch, mgr)
    mock_client = _patch_client(monkeypatch)
    scan_dir = _make_scan_dir(tmp_path, "WS", scan_id="20260727-120000",
                              status="interrupted")

    ws, scan_id = await mgr.resume("WS", "20260727-120000")

    assert ws == "WS" and scan_id == "20260727-120000"
    call = mock_client.start_workflow.call_args
    assert call.kwargs["id"] == "WS-20260727-120000-resume-1"  # -resume-N 后缀
    sess = json.loads((scan_dir / "session.json").read_text())
    assert len(sess["resumeAttempts"]) == 1
    assert sess["status"] == "running"
    assert ("WS", "20260727-120000") in mgr._handles


@pytest.mark.asyncio
async def test_resume_crashed_allowed(tmp_path, monkeypatch):
    """crashed scan 也可 resume（已停未完成，与 interrupted 同档）。"""
    mgr = ScanManager(tmp_path, tmp_path / "r", None)
    _patch_temporal_ok(monkeypatch, mgr)
    _patch_client(monkeypatch)
    _make_scan_dir(tmp_path, "WS", scan_id="s1", status="crashed")
    ws, scan_id = await mgr.resume("WS", "s1")
    assert scan_id == "s1"


@pytest.mark.asyncio
async def test_resume_completed_raises(tmp_path):
    """completed scan 不可 resume -> ValueError（用重扫 POST /api/scan 起 scan）。"""
    mgr = ScanManager(tmp_path, tmp_path / "r", None)
    _make_scan_dir(tmp_path, "WS", scan_id="s1", status="completed")
    with pytest.raises(ValueError, match="不可恢复"):
        await mgr.resume("WS", "s1")


@pytest.mark.asyncio
async def test_resume_failed_allowed(tmp_path, monkeypatch):
    """failed scan 可 resume（spec 2026-08-27 §4.1 扩集：最常见中断出口，Temporal
    已 FAILED 终态无并发风险；80dd1968 起提交前还 terminate 在途 execution 兜底）。

    旧断言「不可恢复」与 _RESUMABLE_STATUSES 含 failed 矛盾（预存失败，2026-09-11
    80dd1968 commit message 标注），对齐现语义。"""
    mgr = ScanManager(tmp_path, tmp_path / "r", None)
    _patch_temporal_ok(monkeypatch, mgr)
    _patch_client(monkeypatch)
    _make_scan_dir(tmp_path, "WS", scan_id="s1", status="failed")
    ws, scan_id = await mgr.resume("WS", "s1")
    assert scan_id == "s1"


@pytest.mark.asyncio
async def test_resume_running_raises(tmp_path):
    """running scan（fresh heartbeat，在跑）不可 resume -> ValueError（避免重复 workflow）。"""
    mgr = ScanManager(tmp_path, tmp_path / "r", None)
    scan_dir = _make_scan_dir(tmp_path, "WS", scan_id="s1", status="running")
    (scan_dir / "heartbeat").write_text(f"{time.time()}\n")  # fresh -> 有效 running
    with pytest.raises(ValueError, match="不可恢复"):
        await mgr.resume("WS", "s1")


@pytest.mark.asyncio
async def test_resume_unknown_scan_raises(tmp_path):
    """scan 不存在 -> ValueError（404）。"""
    mgr = ScanManager(tmp_path, tmp_path / "r", None)
    with pytest.raises(ValueError, match="不存在"):
        await mgr.resume("WS", "nope")


@pytest.mark.asyncio
async def test_resume_strips_trailing_scan_end(tmp_path, monkeypatch):
    """resume 剥掉 events.ndjson 末尾旧 scan_end，让 _watch 能 tail 新 workflow。"""
    mgr = ScanManager(tmp_path, tmp_path / "r", None)
    _patch_temporal_ok(monkeypatch, mgr)
    _patch_client(monkeypatch)
    scan_dir = _make_scan_dir(tmp_path, "WS", scan_id="s1", status="interrupted")
    # 写一条普通事件 + 末尾 scan_end（中断时 orphan_reconciler 写的）
    (scan_dir / "events.ndjson").write_text(
        '{"type":"log","msg":"中途"}\n'
        '{"type":"scan_end","status":"interrupted"}\n')
    await mgr.resume("WS", "s1")
    lines = (scan_dir / "events.ndjson").read_text().splitlines()
    # scan_end 被剥掉，普通事件保留
    assert not any('"scan_end"' in l for l in lines)
    assert any('"log"' in l for l in lines)


@pytest.mark.asyncio
async def test_resume_second_time_appends_resume_2(tmp_path, monkeypatch):
    """第二次 resume -> workflow_id={ws}-{scan_id}-resume-2（resumeAttempts 累加）。"""
    mgr = ScanManager(tmp_path, tmp_path / "r", None)
    _patch_temporal_ok(monkeypatch, mgr)
    mock_client = _patch_client(monkeypatch)
    scan_dir = _make_scan_dir(tmp_path, "WS", scan_id="s1", status="interrupted")
    sess = json.loads((scan_dir / "session.json").read_text())
    sess["resumeAttempts"] = [{"workflowId": "WS-s1-resume-1"}]  # 已 resume 过 1 次
    (scan_dir / "session.json").write_text(json.dumps(sess))

    await mgr.resume("WS", "s1")

    call = mock_client.start_workflow.call_args
    assert call.kwargs["id"] == "WS-s1-resume-2"


@pytest.mark.asyncio
async def test_resume_no_longer_rejects_when_handles_full(tmp_path, monkeypatch):
    """并发闸门下沉 worker 后（spec 2026-09-08-worker-scan-gate §7）：resume 不再拒绝。"""
    mgr = ScanManager(tmp_path, tmp_path / "r", None)
    _patch_temporal_ok(monkeypatch, mgr)
    _patch_client(monkeypatch)
    mgr._handles[("other", "s0")] = object()  # 占位（历史在跑）
    _make_scan_dir(tmp_path, "WS", scan_id="s1", status="interrupted")
    await mgr.resume("WS", "s1")  # 不抛 TooManyScans，照常续跑


# ── resume 双跑守卫（2026-09-11 NodeGoat-20260910-193720 实证）─────────────────

def _patch_client_with_prior_handle(monkeypatch, prior_handle):
    mock_client = AsyncMock()
    mock_client.start_workflow = AsyncMock(return_value=MagicMock())
    mock_client.get_workflow_handle = MagicMock(return_value=prior_handle)
    monkeypatch.setattr("supernova_web.components.scan_manager.Client.connect",
                       AsyncMock(return_value=mock_client))
    return mock_client


@pytest.mark.asyncio
async def test_resume_terminates_inflight_prior_execution(tmp_path, monkeypatch):
    """failed（免判活路径）resume 前若上一 workflow execution 仍 RUNNING（挂在
    activity 无限重试中「阴魂不散」），先 terminate 再提交 resume-N——否则双跑：
    agent 并发翻倍撞 429 + checkpoint last-writer-wins 覆写丢审查结论。"""
    from temporalio.client import WorkflowExecutionStatus
    mgr = ScanManager(tmp_path, tmp_path / "r", None)
    _patch_temporal_ok(monkeypatch, mgr)
    prior = AsyncMock()
    prior.describe.return_value = MagicMock(status=WorkflowExecutionStatus.RUNNING)
    mock_client = _patch_client_with_prior_handle(monkeypatch, prior)
    _make_scan_dir(tmp_path, "WS", scan_id="20260911-010101", status="failed")

    await mgr.resume("WS", "20260911-010101")

    prior.terminate.assert_awaited_once()   # 在途先终止
    got = mock_client.get_workflow_handle.call_args
    assert got.args[0] == "WS-20260911-010101"   # 上一个（原始）workflow id
    assert mock_client.start_workflow.call_args.kwargs["id"] \
        == "WS-20260911-010101-resume-1"


@pytest.mark.asyncio
async def test_resume_skips_terminate_when_prior_finished(tmp_path, monkeypatch):
    """上一 execution 已终态（COMPLETED/FAILED）→ 不 terminate，直接提交。"""
    from temporalio.client import WorkflowExecutionStatus
    mgr = ScanManager(tmp_path, tmp_path / "r", None)
    _patch_temporal_ok(monkeypatch, mgr)
    prior = AsyncMock()
    prior.describe.return_value = MagicMock(
        status=WorkflowExecutionStatus.COMPLETED)
    mock_client = _patch_client_with_prior_handle(monkeypatch, prior)
    _make_scan_dir(tmp_path, "WS", scan_id="20260911-010102", status="failed")

    await mgr.resume("WS", "20260911-010102")

    prior.terminate.assert_not_awaited()
    assert mock_client.start_workflow.await_count == 1


@pytest.mark.asyncio
async def test_resume_prior_absent_does_not_block(tmp_path, monkeypatch):
    """describe 抛（execution 不存在/网络错）→ best-effort 跳过，resume 照常提交。"""
    mgr = ScanManager(tmp_path, tmp_path / "r", None)
    _patch_temporal_ok(monkeypatch, mgr)
    prior = AsyncMock()
    prior.describe.side_effect = RuntimeError("workflow not found")
    mock_client = _patch_client_with_prior_handle(monkeypatch, prior)
    _make_scan_dir(tmp_path, "WS", scan_id="20260911-010103", status="failed")

    await mgr.resume("WS", "20260911-010103")

    prior.terminate.assert_not_awaited()
    assert mock_client.start_workflow.await_count == 1
