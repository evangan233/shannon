# packages/web/tests/test_orphan_reconciler.py
"""孤儿 scan 对账：容器重启后 scan_manager._watch 丢失，session 卡 running 且无 scan_end。
reconcile_orphaned 应补 scan_end(interrupted)+失败原因+session completed_at，且幂等/不误伤。
"""
import json
import os
import time

import pytest

from supernova_web.components.orphan_reconciler import reconcile_orphaned, _has_scan_end


def test_closed_temporal_status_maps_to_business_terminal():
    """明确的 Temporal 关闭态不能一概降为 interrupted。"""
    from temporalio.client import WorkflowExecutionStatus
    from supernova_web.components.orphan_reconciler import _closed_business_status
    assert _closed_business_status(WorkflowExecutionStatus.FAILED) == "failed"
    assert _closed_business_status(WorkflowExecutionStatus.TIMED_OUT) == "failed"
    assert _closed_business_status(WorkflowExecutionStatus.CANCELED) == "cancelled"
    assert _closed_business_status(WorkflowExecutionStatus.TERMINATED) == "killed"
    # 没有 workflow 返回值时，COMPLETED 仍不足以证明业务 completed。
    assert _closed_business_status(WorkflowExecutionStatus.COMPLETED) == "interrupted"


@pytest.mark.asyncio
async def test_completed_temporal_execution_uses_workflow_business_result(tmp_path, monkeypatch):
    """workflow 正常返回的 failed 不能因 Temporal COMPLETED 被误标 interrupted。"""
    from temporalio.client import WorkflowExecutionStatus
    from supernova_web.components import orphan_reconciler as reconciler

    async def _failed_result(_scan_dir):
        return "failed"

    monkeypatch.setattr(reconciler, "_closed_workflow_result_status", _failed_result)
    assert await reconciler._reconciled_closed_status(
        tmp_path, WorkflowExecutionStatus.COMPLETED) == "failed"


def _make_ws(tmp_path, status="running", scan_end_status=None, with_activity_log=False):
    """构造一个**死掉的孤儿** ws(无 fresh heartbeat):写完所有文件后把 mtime 设远古
    (历史遗留;新判活只看 heartbeat,故无 heartbeat 即死)。活 scan 场景另建 fresh heartbeat。"""
    ws_dir = tmp_path / "workspaces" / "ws1"
    ws_dir.mkdir(parents=True)
    session = {
        "web_url": "", "repo_path": "/repo", "scan_type": "whitebox",
        "status": status, "completed_at": None,
        "session": {"id": "ws1", "status": "in-progress"},
    }
    (ws_dir / "session.json").write_text(json.dumps(session), encoding="utf-8")
    if scan_end_status:
        (ws_dir / "events.ndjson").write_text(
            json.dumps({"type": "scan_end", "status": scan_end_status,
                        "ts": "t", "category": "CONTROL"}) + "\n",
            encoding="utf-8",
        )
    if with_activity_log:
        (ws_dir / "activity_failures.log").write_text(
            "temporalio.exceptions.TimeoutError: activity StartToClose timeout\n",
            encoding="utf-8",
        )
    old = time.time() - 3600  # 远古 mtime = scan 早已停写
    for f in (ws_dir / "session.json", ws_dir / "events.ndjson", ws_dir / "activity_failures.log"):
        if f.exists():
            os.utime(f, (old, old))
    return ws_dir


@pytest.mark.asyncio
async def test_orphan_running_not_alive_writes_scan_end(tmp_path):
    ws_dir = _make_ws(tmp_path, status="running")
    wrote = await reconcile_orphaned(ws_dir, is_running=False)
    assert wrote is True
    ef = ws_dir / "events.ndjson"
    assert ef.exists()
    line = json.loads(ef.read_text(encoding="utf-8").strip())
    assert line["type"] == "scan_end"
    assert line["status"] == "interrupted"
    # session 标完成时间 + interrupted
    sess = json.loads((ws_dir / "session.json").read_text(encoding="utf-8"))
    assert sess["completed_at"] is not None
    assert sess["status"] == "interrupted"


@pytest.mark.asyncio
async def test_orphan_attaches_activity_failure_tail(tmp_path):
    ws_dir = _make_ws(tmp_path, status="running", with_activity_log=True)
    await reconcile_orphaned(ws_dir, is_running=False)
    line = json.loads((ws_dir / "events.ndjson").read_text(encoding="utf-8").strip())
    assert "StartToClose timeout" in line["stderr_tail"]


@pytest.mark.asyncio
async def test_orphan_alive_skip(tmp_path):
    ws_dir = _make_ws(tmp_path, status="running")
    wrote = await reconcile_orphaned(ws_dir, is_running=True)
    assert wrote is False
    assert not (ws_dir / "events.ndjson").exists()


@pytest.mark.asyncio
async def test_orphan_completed_skip(tmp_path):
    ws_dir = _make_ws(tmp_path, status="completed")
    wrote = await reconcile_orphaned(ws_dir, is_running=False)
    assert wrote is False
    assert not (ws_dir / "events.ndjson").exists()


@pytest.mark.asyncio
async def test_orphan_idempotent_has_scan_end(tmp_path):
    ws_dir = _make_ws(tmp_path, status="running", scan_end_status="crashed")
    wrote = await reconcile_orphaned(ws_dir, is_running=False)
    assert wrote is False
    # 不重复写
    assert _has_scan_end(ws_dir / "events.ndjson")
    lines = [l for l in ws_dir.joinpath("events.ndjson").read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(lines) == 1


@pytest.mark.asyncio
async def test_orphan_no_session_skip(tmp_path):
    """非 scan 工作区（无 session.json，如 default/ logs/）不处理。"""
    ws_dir = tmp_path / "workspaces" / "default"
    ws_dir.mkdir(parents=True)
    wrote = await reconcile_orphaned(ws_dir, is_running=False)
    assert wrote is False


@pytest.mark.asyncio
async def test_orphan_recently_active_skip(tmp_path):
    """回归:heartbeat fresh(host CLI 起的活 scan,web 的 scan_manager 看不到其 pid)→
    reconcile_orphaned 不得据「无 pid」就写假 scan_end
    (kol_mapping_service_20260708-193139 被误显 interrupted 即此 bug)。
    判活信号源已从 workflow.log 换成 heartbeat(进程级、不受 LLM 卡顿影响)。"""
    ws_dir = _make_ws(tmp_path, status="running")  # session.json 已被设远古 mtime
    # scan 进程仍存活:HeartbeatManager 刚写了 heartbeat(mtime=now)
    (ws_dir / "heartbeat").write_text(f"{time.time()}\n", encoding="utf-8")
    wrote = await reconcile_orphaned(ws_dir, is_running=False)  # web 看不到 host pid
    assert wrote is False
    assert not _has_scan_end(ws_dir / "events.ndjson")  # 没写假 scan_end
    # session 也不应被改成 interrupted
    sess = json.loads((ws_dir / "session.json").read_text(encoding="utf-8"))
    assert sess["status"] == "running"


@pytest.mark.asyncio
async def test_reconcile_skips_within_submit_grace(tmp_path):
    """提交宽限内(刚 start_workflow, worker 还没写首个 heartbeat)→ 不写假 scan_end.

    覆盖冷启动窗口:此前提交后 1s 内前端首次 poll /events 即触发 reconcile, 那时 worker 连首个
    heartbeat 都没写 → 误判 interrupted, 且 _status_of 终态优先致误杀不可逆(hr_1784014329 即此).
    """
    ws_dir = tmp_path / "workspaces" / "ws1"
    ws_dir.mkdir(parents=True)
    (ws_dir / "session.json").write_text(json.dumps({
        "status": "running", "submitted_at": time.time(),
    }), encoding="utf-8")
    # 无 heartbeat + 无 scan_end + 非终态 + submitted_at 新 → 宽限内 → 不干预
    wrote = await reconcile_orphaned(ws_dir, is_running=False)
    assert wrote is False
    assert not (ws_dir / "events.ndjson").exists()
    sess = json.loads((ws_dir / "session.json").read_text(encoding="utf-8"))
    assert sess["status"] == "running"  # 未被改 interrupted


@pytest.mark.asyncio
async def test_reconcile_reason_mentions_worker_not_started(tmp_path):
    """超宽限 + 无 heartbeat 真孤儿 → scan_end.stderr_tail 指向「worker 容器可能未启动」.

    取代笼统「扫描因服务重启被中断」——后者误导(非服务重启, 是 worker 没起/已退出),
    直接指向最常见根因, 便于用户定位(本 bug 即 worker 容器从未被 up.sh 启动).
    """
    ws_dir = tmp_path / "workspaces" / "ws1"
    ws_dir.mkdir(parents=True)
    old = time.time() - 3600
    (ws_dir / "session.json").write_text(json.dumps({
        "status": "running", "submitted_at": old,  # 提交已久 → 超宽限
    }), encoding="utf-8")
    wrote = await reconcile_orphaned(ws_dir, is_running=False)
    assert wrote is True
    line = json.loads((ws_dir / "events.ndjson").read_text(encoding="utf-8").strip())
    assert "worker 容器可能未启动" in line["stderr_tail"]


def _running_workflow_client(monkeypatch, status):
    """patch temporalio.client.Client.connect 返回 fake client,其 workflow handle
    describe() 返回给定 status。用于 reconcile 的 temporal workflow 状态校验测试。"""
    import temporalio.client

    class _Desc:
        pass
    _Desc.status = status
    class _Handle:
        async def describe(self):
            return _Desc()
    class _FakeClient:
        def get_workflow_handle(self, workflow_id):
            return _Handle()
    async def _fake_connect(addr):
        return _FakeClient()
    monkeypatch.setattr(temporalio.client.Client, "connect", _fake_connect)


@pytest.mark.asyncio
async def test_reconcile_skips_when_workflow_running(tmp_path, monkeypatch):
    """并发排队超提交宽限 + 无 heartbeat,但 temporal workflow 仍 RUNNING → 不判孤儿。

    对症(2026-08-04):两个白盒 scan 并发,第二个在 worker 队列排队 >120s(被第一个占着),
    提交宽限失效 + 期间无 heartbeat → 被 reconcile 误判 interrupted(终态不可逆),
    而 workflow 实际仍 RUNNING、scan 后来正常跑(成幽灵 scan)。查 temporal 见 RUNNING 即不干预。
    """
    import temporalio.client

    scan_dir = tmp_path / "workspaces" / "ws1" / "scans" / "NodeGoat-20260804-102704"
    scan_dir.mkdir(parents=True)
    old = time.time() - 3600
    (scan_dir / "session.json").write_text(json.dumps({
        "status": "running", "submitted_at": old,  # 提交已久 → 超宽限
    }), encoding="utf-8")
    # 无 heartbeat + 无 scan_end + 超宽限 → 旧逻辑必判孤儿;新逻辑查 temporal RUNNING 应跳过

    _running_workflow_client(monkeypatch, temporalio.client.WorkflowExecutionStatus.RUNNING)

    wrote = await reconcile_orphaned(scan_dir, is_running=False)
    assert wrote is False
    assert not (scan_dir / "events.ndjson").exists()
    sess = json.loads((scan_dir / "session.json").read_text("utf-8"))
    assert sess["status"] == "running"  # 未被改成 interrupted


@pytest.mark.asyncio
async def test_reconcile_keeps_reconnecting_for_continued_as_new(tmp_path, monkeypatch):
    """continue-as-new 代表 chain 仍可推进，不能被旧 run 的关闭态误收尾。"""
    import temporalio.client

    scan_dir = tmp_path / "workspaces" / "ws1" / "scans" / "continued-20260916"
    scan_dir.mkdir(parents=True)
    old = time.time() - 3600
    (scan_dir / "session.json").write_text(json.dumps({
        "status": "running", "submitted_at": old,
    }), encoding="utf-8")
    _running_workflow_client(
        monkeypatch, temporalio.client.WorkflowExecutionStatus.CONTINUED_AS_NEW)

    assert await reconcile_orphaned(scan_dir, is_running=False) is False
    assert not (scan_dir / "events.ndjson").exists()


@pytest.mark.asyncio
async def test_reconcile_does_not_probe_explicit_terminal(tmp_path, monkeypatch):
    """显式业务终态是最高优先级，后台轮询不应额外 describe Temporal。"""
    from supernova_web.components import orphan_reconciler as reconciler

    ws_dir = _make_ws(tmp_path, status="interrupted")

    async def _unexpected_probe(_scan_dir):
        raise AssertionError("terminal scan must not probe Temporal")

    monkeypatch.setattr(reconciler, "_probe_workflow", _unexpected_probe)
    assert await reconcile_orphaned(ws_dir, is_running=False) is False


@pytest.mark.asyncio
async def test_reconcile_orphan_when_workflow_terminal(tmp_path, monkeypatch):
    """workflow 已终态(FAILED 等)→ 回退 heartbeat 逻辑,stale + 超宽限则照常判孤儿。

    确保新增的 RUNNING 检查只在 RUNNING 时跳过:workflow 已结束(worker 不再推进,heartbeat
    必 stale)时仍按原逻辑收尾,不破坏真孤儿对账。
    """
    import temporalio.client

    scan_dir = tmp_path / "workspaces" / "ws1" / "scans" / "dead-20260804"
    scan_dir.mkdir(parents=True)
    old = time.time() - 3600
    (scan_dir / "session.json").write_text(json.dumps({
        "status": "running", "submitted_at": old,
    }), encoding="utf-8")

    _running_workflow_client(monkeypatch, temporalio.client.WorkflowExecutionStatus.FAILED)

    written = {}

    async def _capture_scan_end(_event_file, status, returncode, stderr_tail):
        written.update(status=status, returncode=returncode, stderr_tail=stderr_tail)

    monkeypatch.setattr(
        "supernova_web.components.orphan_reconciler._write_scan_end", _capture_scan_end)

    wrote = await reconcile_orphaned(scan_dir, is_running=False)
    assert wrote is True  # Temporal FAILED + stale → 收口为业务 failed
    assert written["status"] == "failed"
    assert json.loads((scan_dir / "session.json").read_text("utf-8"))["status"] == "failed"


@pytest.mark.asyncio
async def test_reconcile_keeps_reconnecting_when_temporal_unreachable(tmp_path, monkeypatch):
    """Temporal 不可达是 UNKNOWN，不得把可能仍活的 web workflow 落盘为 interrupted。"""
    import temporalio.client

    scan_dir = tmp_path / "workspaces" / "ws1" / "scans" / "hostscan-20260804"
    scan_dir.mkdir(parents=True)
    old = time.time() - 3600
    (scan_dir / "session.json").write_text(json.dumps({
        "status": "running", "submitted_at": old,
    }), encoding="utf-8")

    async def _connect_raises(addr):
        raise RuntimeError("temporal unreachable")
    monkeypatch.setattr(temporalio.client.Client, "connect", _connect_raises)

    wrote = await reconcile_orphaned(scan_dir, is_running=False)
    assert wrote is False
    assert not (scan_dir / "events.ndjson").exists()
    assert json.loads((scan_dir / "session.json").read_text())["status"] == "running"


@pytest.mark.asyncio
async def test_reconcile_keeps_reconnecting_when_temporal_query_slow(tmp_path, monkeypatch):
    """Temporal 查询超时是 UNKNOWN：不阻塞 reconcile，也绝不写不可逆终态。

    守 /events 端点：reconcile 每次 poll 同步 await，Client.connect 无内置超时，temporal
    抖动时可卡数十秒。限时后超时即回退(视同查不到 → heartbeat 逻辑)，真孤儿仍收尾，
    且 live 页 SSE 不会被卡死。
    """
    import asyncio
    import temporalio.client

    scan_dir = tmp_path / "workspaces" / "ws1" / "scans" / "slow-20260804"
    scan_dir.mkdir(parents=True)
    old = time.time() - 3600
    (scan_dir / "session.json").write_text(json.dumps({
        "status": "running", "submitted_at": old,
    }), encoding="utf-8")

    async def _connect_hang(addr):
        await asyncio.sleep(60)  # 模拟 temporal 卡死(connect 无返回)
    monkeypatch.setattr(temporalio.client.Client, "connect", _connect_hang)
    # 压低限时阈值，测试不等 60s(验证 wait_for 超时生效)
    monkeypatch.setenv("SUPERNOVA_RECONCILE_TEMPORAL_TIMEOUT_SECONDS", "0.1")

    wrote = await reconcile_orphaned(scan_dir, is_running=False)
    assert wrote is False
    assert not (scan_dir / "events.ndjson").exists()
