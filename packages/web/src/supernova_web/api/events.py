# packages/web/src/supernova_web/api/events.py
"""scan events SSE 构造（build_scan_events_response / build_single_events_response）。

旧 ws-scoped GET /{ws}/events shim 已移除（Phase 2 前端切 scan-scoped
GET /{ws}/scans/{scan_id}/events，零前端调用，联合验收确认）。scan-scoped 路由在
api/scans.py，调本模块的 build_scan_events_response（全量归并流）；
build_single_events_response 供 run 级 events 端点（单文件语义不变）。
"""
from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi import Request
from fastapi.responses import StreamingResponse

from supernova_web.components.event_tailer import EventTailer
from supernova_web.components.merged_event_tailer import MergedEventTailer


async def build_scan_events_response(request: Request, scan_dir: Path) -> StreamingResponse:
    """构造 scan events SSE StreamingResponse（MergedEventTailer 全量归并 + 孤儿对账）。

    scans.py 的 GET /{ws}/scans/{scan_id}/events 调本函数。认证(authcheck)/白盒(任务根
    events)/黑盒(所有 run-K events)按 ts 归并为一条流，SSE id 为全源 offset 快照支持
    Last-Event-ID 按源断点续传；首轮历史回放完成后发送一次 ``stream_ready`` 控制事件，
    让列表在回放期间继续使用 GET 快照，避免把历史 phase 中间态画成进度跳变；wb 的
    scan_end 扣发直到全 run 终态（防任务级误判提前关流）。孤儿对账 per-scan：scan 非
    在跑 + 无 scan_end -> 补 scan_end（让 SSE 立即有关流信号 + 失败原因，而非空等
    idle_timeout 后关流再被前端重连死循环）。
    """
    # 判活 per-scan（heartbeat），非 ws 级 pid（C1 容器无本机 pid）。
    from supernova_core.session import SessionManager
    from supernova_web.components.workspaces_indexer import _compute_status
    idx = request.app.state.indexer
    idx.sync_active(request.app.state.scan_manager.active_pids())
    mgr = SessionManager(scan_dir.parent)
    is_running = _compute_status(scan_dir, mgr.get_status(scan_dir)) == "running"
    if not is_running:
        from supernova_web.components.orphan_reconciler import reconcile_orphaned
        await reconcile_orphaned(
            scan_dir, False, scan_manager=request.app.state.scan_manager)

    last = request.headers.get("last-event-id")
    # wb scan_end 扣发宽限（默认 10s：覆盖「白盒收尾、run 目录未建」竞态 + 续跑缝隙；
    # 测试/CI 可调小）。env 读取在请求期——monkeypatch 即时生效。
    import os
    grace = float(os.environ.get("SUPERNOVA_EVENTS_CLOSE_GRACE_SECONDS", "10"))
    if not is_running:
        # 已终态扫描免宽限：源文件不再增长、新 run 目录不会再出现，宽限防的竞态
        # 不存在，纯属延迟——「中断扫描打开 live 页 spinner 空转 ~10s 才变 ‖」即此
        # （2026-09-09 中断体感 follow-up）。min 保住测试 env 调更小的值。
        grace = min(grace, 0.5)
    # run 源空闲兜底窗口（默认 300s：黑盒 workflow 未 finalize 且 web 收口缺失时合成
    # run_end 关流的最后防线；run 仍在写则不触发。负值禁用）。
    run_idle = float(os.environ.get("SUPERNOVA_EVENTS_RUN_IDLE_SECONDS", "300"))

    async def gen():
        queue: asyncio.Queue = asyncio.Queue()
        tailer = MergedEventTailer(scan_dir)

        async def on_event(data: dict, event_id: object) -> None:
            await queue.put(EventTailer.encode_sse(data, event_id))
            if data.get("type") == "scan_end":
                await queue.put(None)  # sentinel：关流（仅 wb 终态 scan_end 会到这里）

        task = asyncio.create_task(
            tailer.tail(on_event, last_event_id=last, close_grace=grace,
                        run_idle_timeout=run_idle))
        try:
            while True:
                item = await queue.get()
                if item is None:
                    break
                yield item
        finally:
            task.cancel()

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


async def build_single_events_response(request: Request, events_dir: Path) -> StreamingResponse:
    """单文件 events SSE（run 级端点用）：tail events_dir/events.ndjson，见 scan_end 关流。

    与归并流不同：不做多源归并/扣发（run 自己的 scan_end 即终态）、不做孤儿对账
    （run 生命周期由任务级编排管理）。
    """
    ndjson = events_dir / "events.ndjson"
    last = request.headers.get("last-event-id")
    last_offset = int(last) if last and last.isdigit() else None

    async def gen():
        queue: asyncio.Queue = asyncio.Queue()
        tailer = EventTailer(ndjson)

        async def on_event(data: dict, event_id: int) -> None:
            await queue.put(EventTailer.encode_sse(data, event_id))
            if data.get("type") == "scan_end":
                await queue.put(None)  # sentinel：关流

        task = asyncio.create_task(tailer.tail(on_event, last_event_id=last_offset))
        try:
            while True:
                item = await queue.get()
                if item is None:
                    break
                yield item
        finally:
            task.cancel()

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


async def build_verify_events_response(
    ndjson: Path, last_event_id: int | None = None,
) -> StreamingResponse:
    """构造 auth 验证过程 SSE（tail ndjson + 遇 scan_end 关流）。

    与 build_scan_events_response 同源（EventTailer + scan_end sentinel），但**无孤儿对账**
    ——auth 验证是独立短 workflow（AuthValidationWorkflow），其 scan_end 由 finalize_summary
    写；worker 崩溃致 scan_end 缺失时，前端 useEventSource 的 onerror 重连 + verify-status
    轮询兜底（spec §8 降级）。last_event_id 支持 Last-Event-ID 断点续传。
    """
    async def gen():
        queue: asyncio.Queue = asyncio.Queue()
        tailer = EventTailer(ndjson)

        async def on_event(data: dict, event_id: int):
            await queue.put(EventTailer.encode_sse(data, event_id))
            if data.get("type") == "scan_end":
                await queue.put(None)  # sentinel：关流

        task = asyncio.create_task(tailer.tail(on_event, last_event_id=last_event_id))
        try:
            while True:
                item = await queue.get()
                if item is None:
                    break
                yield item
        finally:
            task.cancel()

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
