"""共享扫描运行时：优雅退出（SIGINT 双击 + Temporal 协作式取消）。

设计见 docs/superpowers/specs/2026-06-15-graceful-shutdown-design.md。
清理范围：只关连接/子进程 + 还原临时注入配置，不删 deliverables / workflow.log。
"""

import asyncio
import contextlib
import os
import signal
from datetime import timedelta
from typing import Any

from temporalio.client import Client
from temporalio.worker import Worker

from supernova_core.logging import print_line
from supernova_core.runtime.workflow_timeout import scan_budget
from supernova_core.services.temporal_infra import generate_task_queue


class ScanCancelled(Exception):
    """扫描被用户中断（Ctrl+C / SIGTERM）时由 run_scan_graceful 抛出。"""


class ShutdownController:
    """管理 SIGINT 双击 + SIGTERM 直接优雅的退出语义。

    - 第 1 次 SIGINT：set 事件（主协程 await wait() 醒来走取消流程）。
    - 第 2 次 SIGINT：os._exit(130) 立即强制退出。
    - SIGTERM：直接 set 事件（不计数；docker stop / kill 的确定性终止）。
    """

    def __init__(self) -> None:
        self._event = asyncio.Event()
        self._count = 0
        self._loop = None
        self._cleanup_callback = None

    def install(
        self,
        loop: asyncio.AbstractEventLoop,
        cleanup_callback: "callable | None" = None,
    ) -> None:
        """在给定 event loop 上注册信号 handler（仅 Unix）。

        cleanup_callback(session_ids=None) 在 _force_exit 的 os._exit 前同步调用,
        用于回收 browser 子进程(强退路径,不能 await)。
        """
        self._loop = loop
        self._cleanup_callback = cleanup_callback
        loop.add_signal_handler(signal.SIGINT, self._on_signal, signal.SIGINT)
        loop.add_signal_handler(signal.SIGTERM, self._on_signal, signal.SIGTERM)

    def _on_signal(self, signum: int) -> None:
        if signum == signal.SIGTERM:
            self._trigger_graceful()
            return
        # SIGINT：双击语义
        self._count += 1
        if self._count >= 2:
            self._force_exit()
        else:
            self._trigger_graceful()

    def _trigger_graceful(self) -> None:
        if not self._event.is_set():
            print()  # 视觉分隔：和正在输出的进度行/仪表盘分开
            print_line("SCAN", "", "正在优雅取消…（再按一次 Ctrl+C 立即退出）")
            self._event.set()

    def _force_exit(self) -> None:
        print()
        print_line("SCAN", "", "强制退出")
        if self._cleanup_callback is not None:
            try:
                self._cleanup_callback(session_ids=None)
            except Exception:  # noqa: BLE001 - 清理绝不阻塞退出
                pass
        os._exit(130)

    def is_set(self) -> bool:
        return self._event.is_set()

    @property
    def cleanup_callback(self) -> "callable | None":
        """暴露 _force_exit/_do_cancel 用的清理回调(供 await_workflow_with_shutdown 传递)。"""
        return self._cleanup_callback

    async def wait(self) -> None:
        await self._event.wait()

    def uninstall(self) -> None:
        if self._loop is None:
            return
        self._loop.remove_signal_handler(signal.SIGINT)
        self._loop.remove_signal_handler(signal.SIGTERM)


async def poll_progress(
    handle: Any,
    progress_type: Any,
    total: int = 13,
    interval_seconds: int = 30,
) -> None:
    """周期性查询 workflow 进度并打印一行（取代三个 worker 里复制的版本）。

    progress_type 由各 worker 注入（whitebox/blackbox 各自的 PipelineProgress），
    保持 core 不依赖上层包类型。
    """
    while True:
        try:
            progress = await handle.query("PipelineProgress", result_type=progress_type)
            elapsed = int(progress.elapsed_ms / 1000)
            phase = progress.current_phase or "unknown"
            agent = progress.current_agent or "none"
            completed = len(progress.completed_agents)
            print(
                f"[{elapsed}s] Phase: {phase} | Agent: {agent} | Completed: {completed}/{total}",
                flush=True,
            )
        except Exception:
            pass  # workflow 可能已完成或暂时不可查询
        await asyncio.sleep(interval_seconds)


async def await_workflow_with_shutdown(
    handle: Any,
    ctrl: "ShutdownController",
    *,
    progress_type: Any = None,
    total: int = 13,
    cancel_grace_seconds: float = 15.0,
) -> Any:
    """在已注册的 ShutdownController 下等待 workflow 完成；被中断时协作式取消并抛 ScanCancelled。

    调用方负责 ctrl 的 install/uninstall 生命周期。progress_type=None 时不启动
    轮询（调用方用 Rich 仪表盘等其它进度展示代替 poll 打印）。
    """
    poll_task = (
        asyncio.create_task(poll_progress(handle, progress_type=progress_type, total=total))
        if progress_type is not None
        else None
    )
    result_task = asyncio.ensure_future(handle.result())
    shutdown_wait_task = asyncio.create_task(ctrl.wait())
    try:
        await asyncio.wait(
            {result_task, shutdown_wait_task},
            return_when=asyncio.FIRST_COMPLETED,
        )
        if ctrl.is_set():
            await _do_cancel(
                handle, result_task, cancel_grace_seconds,
                cleanup_callback=ctrl.cleanup_callback,
            )
            raise ScanCancelled()
        return result_task.result()
    finally:
        # result_task 不在此取消：正常路径已由 result_task.result() 消费，
        # 取消路径由 _do_cancel 兜底(give-up 时显式 cancel; _do_cancel 用
        # asyncio.wait 不自动取消, 故 give-up 显式 cancel result_task)。
        for task in (poll_task, shutdown_wait_task):
            if task is None:
                continue
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task


async def run_scan_graceful(
    *,
    temporal_address: str,
    task_queue_prefix: str,
    workflow_cls,
    workflow_input,
    activities: list,
    progress_type,
    progress_total: int = 13,
    cancel_grace_seconds: float = 15.0,
) -> Any:
    """连接 Temporal、起 worker、跑 workflow；支持 SIGINT/SIGTERM 优雅取消。

    成功返回 workflow result；被用户中断时抛 ScanCancelled（由调用方捕获）。
    清理范围只含连接/子进程 + 临时注入配置（由 workflow 已有的 finally 触发），
    不删 deliverables / workflow.log。
    """
    client = await Client.connect(temporal_address)
    task_queue = generate_task_queue(task_queue_prefix)
    worker = Worker(
        client=client,
        task_queue=task_queue,
        workflows=[workflow_cls],
        activities=activities,
        graceful_shutdown_timeout=timedelta(seconds=10),
    )

    ctrl = ShutdownController()
    ctrl.install(asyncio.get_running_loop())

    async with worker:
        workflow_id = (
            getattr(workflow_input, "workspace_name", None)
            or f"{task_queue_prefix}-scan"
        )
        handle = await client.start_workflow(
            workflow_cls.run,
            workflow_input,
            id=workflow_id,
            task_queue=task_queue,
            run_timeout=scan_budget(),
        )
        try:
            return await await_workflow_with_shutdown(
                handle,
                ctrl,
                progress_type=progress_type,
                total=progress_total,
                cancel_grace_seconds=cancel_grace_seconds,
            )
        finally:
            ctrl.uninstall()


async def _do_cancel(
    handle,
    result_task,
    cancel_grace_seconds: float,
    cleanup_callback: "callable | None" = None,
    terminate_settle_seconds: float = 5.0,
) -> None:
    """发协作式 cancel，grace 期内等结果；超时升级 terminate 强制收尾。

    取消链路：协作式 cancel（handle.cancel）→ 等 grace → 仍无响应则升级 terminate。
    terminate 兜住"activity 同步阻塞 event loop 导致 cancel 注入不进"的场景：
    server 直接置 workflow Terminated，result_task 随之 resolve，client 不再干等。
    """
    print_line("CANCEL", "", "正在取消 Temporal workflow…")
    try:
        await handle.cancel()
    except Exception as exc:
        print_line("CANCEL", "", f"cancel 请求失败（忽略）: {exc}")

    # grace 期内协作取消。用 asyncio.wait 而非 wait_for：超时不取消 result_task，
    # 保留给 escalate 后的 settle 继续观察（wait_for 超时会 cancel task，使后续无法再等）。
    done, _ = await asyncio.wait({result_task}, timeout=cancel_grace_seconds)
    if result_task in done:
        # 完成了（正常返回或抛 temporalio cancel 异常）——吞异常视为已结束
        with contextlib.suppress(Exception):
            result_task.result()
        return

    # grace 超时：升级 terminate（兜底，覆盖不可中断的同步 activity）
    print_line(
        "CANCEL", "",
        f"{cancel_grace_seconds}s 内 workflow 未响应取消，升级 terminate…",
    )
    try:
        await handle.terminate(
            reason=f"client cancel grace timeout ({cancel_grace_seconds}s): "
            f"workflow unresponsive, escalating from cooperative cancel to terminate"
        )
    except Exception as exc:
        print_line("CANCEL", "", f"terminate 失败（忽略）: {exc}")

    # terminate 后给 result_task 一个 settle 窗口（terminate 让 result() raise TerminatedError）
    done, _ = await asyncio.wait({result_task}, timeout=terminate_settle_seconds)
    if result_task in done:
        # terminate 后完成 → retrieve 异常防 "Task exception was never retrieved"
        with contextlib.suppress(Exception):
            result_task.result()
    else:
        print_line(
            "CANCEL", "",
            f"terminate 后 {terminate_settle_seconds}s 仍未结束，放弃等待",
        )
        # give-up: cancel result_task 防 orphan(持 gRPC stream); 旧版从 wait_for 改
        # asyncio.wait 后漏了这步 → terminate 双超时路径 result_task 泄漏。
        result_task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await result_task

    # client 即将退出：best-effort 回收子进程（browser 等），无论 settle 与否
    if cleanup_callback is not None:
        try:
            cleanup_callback(session_ids=None)
        except Exception:  # noqa: BLE001 - best-effort
            pass

