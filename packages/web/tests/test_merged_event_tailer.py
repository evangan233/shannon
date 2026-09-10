# packages/web/tests/test_merged_event_tailer.py
"""MergedEventTailer 多源归并（认证/白盒/黑盒 run-K → 单条 ts 序流）。

核心回归：NodeGoat-20260817-132940 事故——编排器误写任务级 scan_end failed 时黑盒 run
还在跑（实际 16:04 才完）。归并流必须扣住 wb scan_end 继续推 run 事件，等 run 自己的
scan_end + 宽限期后才以 wb scan_end 收尾（不能提前关流骗用户「黑盒失败」）。
"""
import asyncio
import json

import pytest

from supernova_web.components.merged_event_tailer import MergedEventTailer


def _line(d: dict) -> str:
    return json.dumps(d, ensure_ascii=False) + "\n"


def _append(path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a") as fh:
        fh.write(text)


def _msgs(events: list[dict]) -> list[str]:
    return [e["message"] for e in events if e.get("message")]


class _Collector:
    """on_event 收集器：events/ids + 见 wb 终态 scan_end 的完成信号。"""

    def __init__(self) -> None:
        self.events: list[dict] = []
        self.ids: list[str] = []
        self.done = asyncio.Event()

    async def cb(self, data: dict, event_id) -> None:
        self.events.append(data)
        if event_id is not None:
            self.ids.append(str(event_id))
        if data.get("type") == "scan_end":
            self.done.set()


async def _collect(tailer: MergedEventTailer, **kw) -> _Collector:
    c = _Collector()
    await tailer.tail(c.cb, poll_interval=0.01, close_grace=0.05, **kw)
    return c


async def _cancel(task: "asyncio.Task") -> None:
    """取消 tail 任务并回收（任务已自然结束则 await 直接过，不视为异常）。"""
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


# ---- 纯函数 ----

def test_parse_last_event_id():
    assert MergedEventTailer.parse_last_event_id("ac=0&wb=123&run-1=45") == {
        "ac": 0, "wb": 123, "run-1": 45}
    # 畸形段容忍：缺 = / 空 label 丢弃；未知 label 保留（无害——不匹配任何源）
    parsed = MergedEventTailer.parse_last_event_id("wb=5&junk&=3")
    assert parsed == {"wb": 5}
    assert MergedEventTailer.parse_last_event_id(None) == {}


# ---- 归并顺序与 scan_end 三态 ----

@pytest.mark.asyncio
async def test_orders_by_ts_across_sources(tmp_path):
    """认证/白盒/黑盒按 ts 归并；ac scan_end 丢弃；run scan_end 改写 run_end；
    wb scan_end 扣到最后（终态 + 宽限后作为流末条）。"""
    scan = tmp_path / "scan"
    scan.mkdir()
    _append(scan / "authcheck-events.ndjson",
            _line({"type": "InfoEvent", "ts": "2026-08-17T13:29:41Z", "message": "ac-1"})
            + _line({"type": "scan_end", "ts": "2026-08-17T13:36:45Z", "status": "completed"}))
    _append(scan / "events.ndjson",
            _line({"type": "InfoEvent", "ts": "2026-08-17T13:36:46Z", "message": "wb-1"})
            + _line({"type": "scan_end", "ts": "2026-08-17T15:31:56Z", "status": "failed"}))
    _append(scan / "blackbox-runs/run-1/events.ndjson",
            _line({"type": "InfoEvent", "ts": "2026-08-17T15:41:00Z", "message": "bb-1"})
            + _line({"type": "scan_end", "ts": "2026-08-17T16:04:21Z", "status": "completed"}))

    c = await _collect(MergedEventTailer(scan))
    # ts 序：认证 → 白盒 → 黑盒；ac 的 scan_end 不出现。
    # stream_ready 位于首轮历史回放之后、最终 scan_end 之前，供前端一次性切换到
    # 当前进度，不能把回放中的中间 phase 比例逐条画出来。
    assert _msgs(c.events) == ["ac-1", "wb-1", "bb-1"]
    ready_i = next(i for i, e in enumerate(c.events) if e["type"] == "stream_ready")
    assert ready_i > 0 and c.events[ready_i].get("src") is None
    assert c.events[ready_i]["type"] == "stream_ready"
    # run 收尾改写 run_end 并带 run 标签
    run_end = next(e for e in c.events if e["type"] == "run_end")
    assert run_end["run"] == "run-1" and run_end["status"] == "completed"
    # wb scan_end（被扣的）最后发：status 保持原样
    assert c.events[-1]["type"] == "scan_end" and c.events[-1]["status"] == "failed"


@pytest.mark.asyncio
async def test_ts_missing_falls_back_to_source_priority(tmp_path):
    """ts 非法/缺失：按源优先级稳定兜底（ac < wb < run-K），不炸不丢。"""
    scan = tmp_path / "scan"
    scan.mkdir()
    _append(scan / "blackbox-runs/run-1/events.ndjson",
            _line({"type": "InfoEvent", "ts": "garbage", "message": "bb"})
            + _line({"type": "scan_end", "ts": "garbage", "status": "completed"}))
    _append(scan / "events.ndjson",
            _line({"type": "InfoEvent", "ts": "garbage", "message": "wb"})
            + _line({"type": "scan_end", "ts": "garbage", "status": "completed"}))
    _append(scan / "authcheck-events.ndjson",
            _line({"type": "InfoEvent", "ts": "garbage", "message": "ac"}))
    c = await _collect(MergedEventTailer(scan))
    assert _msgs(c.events) == ["ac", "wb", "bb"]


@pytest.mark.asyncio
async def test_pure_whitebox_closes_after_grace(tmp_path):
    """无 run 时：wb scan_end 扣住 → 宽限后发出收尾（无早关、无重复）。"""
    scan = tmp_path / "scan"
    scan.mkdir()
    _append(scan / "events.ndjson",
            _line({"type": "InfoEvent", "ts": "2026-08-17T13:00:00Z", "message": "a"})
            + _line({"type": "scan_end", "ts": "2026-08-17T15:00:00Z", "status": "completed"}))
    c = await _collect(MergedEventTailer(scan))
    assert _msgs(c.events) == ["a"]
    assert c.events[-1]["type"] == "scan_end"


# ---- 事故回归：wb scan_end 先到、run 仍在写 ----

@pytest.mark.asyncio
async def test_wb_scan_end_held_while_run_streams(tmp_path):
    """NodeGoat-20260817 回归：任务级 scan_end failed 已落盘、黑盒 run 仍在跑 →
    流不关，run 新事件持续可推；run scan_end 到后才收尾（wb scan_end 最后）。"""
    scan = tmp_path / "scan"
    scan.mkdir()
    _append(scan / "events.ndjson",
            _line({"type": "InfoEvent", "ts": "2026-08-17T13:36:46Z", "message": "wb"})
            + _line({"type": "scan_end", "ts": "2026-08-17T15:31:56Z", "status": "failed"}))
    _append(scan / "blackbox-runs/run-1/events.ndjson",
            _line({"type": "InfoEvent", "ts": "2026-08-17T15:29:00Z", "message": "bb-1"}))

    tailer = MergedEventTailer(scan)
    c = _Collector()
    task = asyncio.create_task(
        tailer.tail(c.cb, poll_interval=0.01, close_grace=0.05))
    try:
        await asyncio.sleep(0.3)
        assert not c.done.is_set()
        assert _msgs(c.events) == ["wb", "bb-1"]

        # run 还在写（15:41 的 agent 事件）→ 继续推送
        _append(scan / "blackbox-runs/run-1/events.ndjson", _line(
            {"type": "InfoEvent", "ts": "2026-08-17T15:41:00Z", "message": "bb-2"}))
        for _ in range(100):
            if len(_msgs(c.events)) >= 3:
                break
            await asyncio.sleep(0.02)
        assert _msgs(c.events) == ["wb", "bb-1", "bb-2"]
        assert not c.done.is_set()  # 仍未关流

        # run 自己的 scan_end 到达 → 宽限后以 wb scan_end 收尾
        _append(scan / "blackbox-runs/run-1/events.ndjson", _line(
            {"type": "scan_end", "ts": "2026-08-17T16:04:21Z", "status": "completed"}))
        await asyncio.wait_for(c.done.wait(), timeout=3)
        assert c.events[-1]["type"] == "scan_end" and c.events[-1]["status"] == "failed"
        assert any(e["type"] == "run_end" for e in c.events)  # run 收尾改写转发
    finally:
        await _cancel(task)


@pytest.mark.asyncio
async def test_new_run_picked_up_mid_stream(tmp_path):
    """流开着时新增 run 目录（续跑/叠加）自动纳入（宽限期覆盖创建竞态）。"""
    scan = tmp_path / "scan"
    scan.mkdir()
    _append(scan / "events.ndjson",
            _line({"type": "scan_end", "ts": "2026-08-17T15:31:56Z", "status": "failed"}))
    _append(scan / "blackbox-runs/run-1/events.ndjson",
            _line({"type": "scan_end", "ts": "2026-08-17T16:04:21Z", "status": "completed"}))

    tailer = MergedEventTailer(scan)
    c = _Collector()
    task = asyncio.create_task(
        tailer.tail(c.cb, poll_interval=0.01, close_grace=0.4))
    try:
        await asyncio.sleep(0.15)  # 进入宽限窗口但未满
        assert not c.done.is_set()
        # 宽限内新增 run-2（reset closable → 继续流）
        _append(scan / "blackbox-runs/run-2/events.ndjson",
                _line({"type": "InfoEvent", "ts": "2026-08-17T17:00:00Z", "message": "bb-run2"})
                + _line({"type": "scan_end", "ts": "2026-08-17T17:30:00Z", "status": "completed"}))
        await asyncio.wait_for(c.done.wait(), timeout=3)
        assert _msgs(c.events) == ["bb-run2"]
        assert c.events[-1]["type"] == "scan_end"
    finally:
        await _cancel(task)


# ---- run 空闲兜底（wb scan_end 已扣住、run 源无 scan_end 且停更） ----

@pytest.mark.asyncio
async def test_stalled_run_synthesizes_run_end_and_closes(tmp_path):
    """wb scan_end 已扣住 + run 源再无写入且无自己的 scan_end（取消/run_timeout/
    worker 崩溃且 web 收口缺失）→ 空闲兜底合成 run_end{synthetic} 后关流，wb
    scan_end 仍作末条（live 页不再永久「已连接」）。"""
    scan = tmp_path / "scan"
    scan.mkdir()
    _append(scan / "events.ndjson",
            _line({"type": "InfoEvent", "ts": "2026-08-17T13:36:46Z", "message": "wb"})
            + _line({"type": "scan_end", "ts": "2026-08-17T15:31:56Z", "status": "cancelled"}))
    _append(scan / "blackbox-runs/run-1/events.ndjson",
            _line({"type": "InfoEvent", "ts": "2026-08-17T15:29:00Z", "message": "bb"}))

    c = await _collect(MergedEventTailer(scan), run_idle_timeout=0.05)
    assert _msgs(c.events) == ["wb", "bb"]
    syn = [e for e in c.events if e.get("synthetic")]
    assert len(syn) == 1, "应恰好合成一条 run_end（synthetic）"
    assert syn[0]["type"] == "run_end" and syn[0]["run"] == "run-1"
    assert c.events[-1]["type"] == "scan_end" and c.events[-1]["status"] == "cancelled"


@pytest.mark.asyncio
async def test_idle_fallback_spares_active_run(tmp_path):
    """run 仍在写（last_active 持续刷新）→ 空闲兜底不误伤（NodeGoat「误写任务级
    scan_end 而 run 实际在跑」保护不回归）；停更超窗后才合成 run_end 收口。"""
    scan = tmp_path / "scan"
    scan.mkdir()
    _append(scan / "events.ndjson",
            _line({"type": "scan_end", "ts": "2026-08-17T15:31:56Z", "status": "failed"}))
    run_events = scan / "blackbox-runs/run-1/events.ndjson"
    _append(run_events, _line({"type": "InfoEvent", "ts": "2026-08-17T15:29:00Z", "message": "bb-1"}))

    tailer = MergedEventTailer(scan)
    c = _Collector()
    task = asyncio.create_task(tailer.tail(
        c.cb, poll_interval=0.01, close_grace=0.05, run_idle_timeout=0.25))
    try:
        stop = asyncio.Event()

        async def _writer():
            i = 2
            while not stop.is_set():
                _append(run_events, _line(
                    {"type": "InfoEvent", "ts": "2026-08-17T15:30:00Z", "message": f"bb-{i}"}))
                i += 1
                await asyncio.sleep(0.05)

        writer = asyncio.create_task(_writer())
        await asyncio.sleep(0.6)  # > 2× 空闲窗口，但写入持续 → 不得合成
        assert not any(e.get("synthetic") for e in c.events), \
            "run 持续写入时不得合成 run_end"
        assert not c.done.is_set()
        stop.set()
        await writer
        await asyncio.wait_for(c.done.wait(), timeout=3)
        syn = [e for e in c.events if e.get("synthetic")]
        assert len(syn) == 1 and syn[0]["type"] == "run_end" and syn[0]["run"] == "run-1"
        assert c.events[-1]["type"] == "scan_end" and c.events[-1]["status"] == "failed"
    finally:
        await _cancel(task)


# ---- 断点续传（复合 id） ----

@pytest.mark.asyncio
async def test_resume_from_composite_last_event_id(tmp_path):
    """Last-Event-ID = 全源 offset 快照：重连不重放已发事件、跨源断点各自恢复。"""
    scan = tmp_path / "scan"
    scan.mkdir()
    _append(scan / "authcheck-events.ndjson", _line(
        {"type": "InfoEvent", "ts": "2026-08-17T13:29:41Z", "message": "ac-1"}))
    _append(scan / "events.ndjson", _line(
        {"type": "InfoEvent", "ts": "2026-08-17T13:36:46Z", "message": "wb-1"}))

    # 第一段：消费 ac-1 + wb-1 后取消（拿最后 id）
    tailer = MergedEventTailer(scan)
    c1 = _Collector()
    task = asyncio.create_task(
        tailer.tail(c1.cb, poll_interval=0.01, close_grace=0.05))
    for _ in range(100):
        if len(c1.events) >= 2:
            break
        await asyncio.sleep(0.02)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    last_id = c1.ids[-1]

    # 两源各新增一条（wb 侧为终态 scan_end），带 last_event_id 续传：只收新增
    _append(scan / "authcheck-events.ndjson", _line(
        {"type": "InfoEvent", "ts": "2026-08-17T13:30:00Z", "message": "ac-2"}))
    _append(scan / "events.ndjson", _line(
        {"type": "scan_end", "ts": "2026-08-17T15:31:56Z", "status": "completed"}))
    c2 = await _collect(MergedEventTailer(scan), last_event_id=last_id)
    assert _msgs(c2.events) == ["ac-2"]  # wb-1 未重放
    assert c2.events[-1]["type"] == "scan_end"  # wb 终态照常扣发收尾


# ---- 源标记注入（组合扫描列表进度三阶段加权判段，2026-08-28） ----

@pytest.mark.asyncio
async def test_events_carry_src_label(tmp_path):
    """转发事件带 src 源标记（ac/wb/run-K）：组合扫描列表行走三阶段加权
    （ac 0-5% / wb 5+50% / run-K 55+100%）需要判「当前段」，而 phase 名判据被
    authcheck 撞破——独立 AuthValidationWorkflow（ac 源）与黑盒 run 的 auth-validation
    段发同名 PhaseEvent(phase="auth-validation")，前端无从区分。源标记是 tailer
    本就知道的可靠信号（run_end 改写/synthetic 合成/wb 扣发 scan_end 同样带）。
    """
    scan = tmp_path / "scan"
    scan.mkdir()
    _append(scan / "authcheck-events.ndjson",
            _line({"type": "InfoEvent", "ts": "2026-08-17T13:29:41Z", "message": "ac-1"}))
    _append(scan / "events.ndjson",
            _line({"type": "InfoEvent", "ts": "2026-08-17T13:36:46Z", "message": "wb-1"})
            + _line({"type": "scan_end", "ts": "2026-08-17T15:31:56Z", "status": "failed"}))
    _append(scan / "blackbox-runs/run-1/events.ndjson",
            _line({"type": "InfoEvent", "ts": "2026-08-17T15:41:00Z", "message": "bb-1"})
            + _line({"type": "scan_end", "ts": "2026-08-17T16:04:21Z", "status": "completed"}))
    c = await _collect(MergedEventTailer(scan))
    by_msg = {e["message"]: e for e in c.events if e.get("message")}
    assert by_msg["ac-1"]["src"] == "ac"
    assert by_msg["wb-1"]["src"] == "wb"
    assert by_msg["bb-1"]["src"] == "run-1"
    # run 收尾改写（run_end）与 wb 终态扣发（scan_end）同样带源标记
    run_end = next(e for e in c.events if e["type"] == "run_end")
    assert run_end["src"] == "run-1"
    assert c.events[-1]["type"] == "scan_end" and c.events[-1]["src"] == "wb"


@pytest.mark.asyncio
async def test_synthetic_run_end_carries_src_label(tmp_path):
    """空闲兜底合成的 run_end 同样带 src 标记（前端判段不因合成事件断链）。"""
    scan = tmp_path / "scan"
    scan.mkdir()
    _append(scan / "events.ndjson",
            _line({"type": "scan_end", "ts": "2026-08-17T15:31:56Z", "status": "cancelled"}))
    _append(scan / "blackbox-runs/run-1/events.ndjson",
            _line({"type": "InfoEvent", "ts": "2026-08-17T15:29:00Z", "message": "bb"}))
    c = await _collect(MergedEventTailer(scan), run_idle_timeout=0.05)
    syn = next(e for e in c.events if e.get("synthetic"))
    assert syn["type"] == "run_end" and syn["src"] == "run-1"


@pytest.mark.asyncio
async def test_truncated_file_resets_and_replays(tmp_path):
    """源文件被截断/重建（run 删除重建）→ offset 归零重读，流仍能收尾。"""
    scan = tmp_path / "scan"
    scan.mkdir()
    f = scan / "events.ndjson"
    # 两条长事件撑大 file_off，使重建后的单行 scan_end 文件更短（触发 size < file_off reset）
    _append(f,
            _line({"type": "InfoEvent", "ts": "2026-08-17T13:00:00Z",
                   "message": "old-event-with-padding-padding-padding"})
            + _line({"type": "InfoEvent", "ts": "2026-08-17T13:05:00Z",
                     "message": "old-event-with-more-padding-padding-padding"}))

    tailer = MergedEventTailer(scan)
    c = _Collector()
    task = asyncio.create_task(
        tailer.tail(c.cb, poll_interval=0.01, close_grace=0.05))
    for _ in range(100):
        if len(c.events) >= 2:
            break
        await asyncio.sleep(0.02)
    # 截断重建：新文件更短
    with open(f, "w") as fh:
        fh.write(_line({"type": "scan_end", "ts": "2026-08-17T15:00:00Z", "status": "completed"}))
    await asyncio.wait_for(c.done.wait(), timeout=3)
    await _cancel(task)
    assert c.events[-1]["type"] == "scan_end"


# ---- correlation 现扫子仓源（2026-09-10 主行 live：子仓日志归并）----

def _write_session(scan_dir, children: list[dict]) -> None:
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "session.json").write_text(
        json.dumps({"scan_type": "correlation", "corr_children": children}),
        encoding="utf-8")


@pytest.mark.asyncio
async def test_child_sources_merged_with_service_tag(tmp_path):
    """主行 session corr_children（reused=False）→ 子仓 events 并入归并流：
    src=c-<scan_id> + service=<svc> 注入；reused 子仓不纳入。"""
    scan = tmp_path / "scan"
    _write_session(scan, [
        {"service": "gateway", "scan_id": "gw-123", "reused": False},
        {"service": "order-svc", "scan_id": "ord-456", "reused": False},
        {"service": "pay-svc", "scan_id": "old-789", "reused": True},
    ])
    _append(tmp_path / "gw-123" / "events.ndjson",
            _line({"type": "AgentEvent", "ts": "2026-09-10T10:00:01Z",
                   "agent_name": "vuln-injection", "event": "start"}))
    _append(tmp_path / "old-789" / "events.ndjson",
            _line({"type": "InfoEvent", "ts": "2026-09-10T10:00:02Z", "message": "stale"}))
    _append(scan / "events.ndjson",
            _line({"type": "correlation_progress", "ts": "2026-09-10T10:00:03Z",
                   "node": "repo", "name": "gateway", "status": "completed"})
            + _line({"type": "scan_end", "ts": "2026-09-10T11:00:00Z", "status": "completed"}))

    c = await _collect(MergedEventTailer(scan))
    gw = [e for e in c.events if e.get("src") == "c-gw-123"]
    assert gw and gw[0]["type"] == "AgentEvent"
    assert gw[0]["service"] == "gateway"  # [svc] 归属展示用（LogStream 前缀）
    assert not any(e.get("src") == "c-old-789" for e in c.events)  # reused 不纳入
    assert c.events[-1]["type"] == "scan_end"  # wb 收口照常


@pytest.mark.asyncio
async def test_child_scan_end_becomes_run_end_named_by_service(tmp_path):
    """子仓 scan_end 改写 run_end{run: <svc>}（复用 RUN 行渲染，不造新 type）；
    子仓终态不参与流关闭判定（无 run 时 wb scan_end 即可收口）。"""
    scan = tmp_path / "scan"
    _write_session(scan, [{"service": "gateway", "scan_id": "gw-123", "reused": False}])
    _append(tmp_path / "gw-123" / "events.ndjson",
            _line({"type": "InfoEvent", "ts": "2026-09-10T10:00:00Z", "message": "gw-1"})
            + _line({"type": "scan_end", "ts": "2026-09-10T10:30:00Z", "status": "completed"}))
    _append(scan / "events.ndjson",
            _line({"type": "scan_end", "ts": "2026-09-10T11:00:00Z", "status": "completed"}))

    c = await _collect(MergedEventTailer(scan))
    child_end = next(e for e in c.events
                     if e["type"] == "run_end" and e.get("service") == "gateway")
    assert child_end["run"] == "gateway" and child_end["status"] == "completed"
    assert child_end["src"] == "c-gw-123"
    # wb scan_end 仍是流末条（子仓终态不阻塞也不提前关流）
    assert c.events[-1]["type"] == "scan_end" and c.events[-1]["status"] == "completed"


@pytest.mark.asyncio
async def test_child_offset_in_sse_id_snapshot(tmp_path):
    """重连断点：SSE id 快照含 c-<scan_id> 段（Last-Event-ID 恢复子仓各自 offset）。"""
    scan = tmp_path / "scan"
    _write_session(scan, [{"service": "gateway", "scan_id": "gw-123", "reused": False}])
    _append(tmp_path / "gw-123" / "events.ndjson",
            _line({"type": "InfoEvent", "ts": "2026-09-10T10:00:00Z", "message": "gw-1"}))
    _append(scan / "events.ndjson",
            _line({"type": "scan_end", "ts": "2026-09-10T11:00:00Z", "status": "completed"}))

    c = await _collect(MergedEventTailer(scan))
    assert any("c-gw-123=" in i for i in c.ids)


@pytest.mark.asyncio
async def test_no_corr_children_session_no_child_sources(tmp_path):
    """非 correlation 主行（session 无 corr_children）→ 零子仓源，既有行为不变。"""
    scan = tmp_path / "scan"
    scan.mkdir()
    (scan / "session.json").write_text(json.dumps({"scan_type": "whitebox"}),
                                       encoding="utf-8")
    _append(tmp_path / "gw-123" / "events.ndjson",
            _line({"type": "InfoEvent", "ts": "2026-09-10T10:00:00Z", "message": "stray"}))
    _append(scan / "events.ndjson",
            _line({"type": "scan_end", "ts": "2026-09-10T11:00:00Z", "status": "completed"}))
    c = await _collect(MergedEventTailer(scan))
    assert not any(str(e.get("src", "")).startswith("c-") for e in c.events)
