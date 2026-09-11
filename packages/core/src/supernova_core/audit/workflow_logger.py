from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from supernova_core.display.dispatcher import DisplayDispatcher
from supernova_core.display.events import (
    AgentEvent, AgentMetric, ErrorEvent, GitnexusLlmEvent, InfoEvent, LlmTurnEvent,
    PhaseEvent, ResumeEvent, StepEvent, SummaryEvent, ToolCallEvent, WorkflowHeader,
)
from supernova_core.display.file_renderer import FileLogRenderer
from supernova_core.display.formatters import format_log_time
from supernova_core.logging.temporalio_redirect import (
    current_temporal_workflow_id, install_temporalio_log_redirect,
)
from supernova_core.models.audit import AgentLogDetails, ResumeInfo, WorkflowSummary
from supernova_core.models.metrics import SessionMetadata
from .log_stream import LogStream
from .utils import generate_workflow_log_path

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from rich.console import Console
    from supernova_core.display.live_dashboard import LiveDashboardRenderer


def _web_ui_url(workflow_id: str | None) -> str | None:
    if not workflow_id:
        return None
    port = os.environ.get("TEMPORAL_WEB_UI_PORT", "8233")
    return f"http://localhost:{port}/namespaces/default/workflows/{workflow_id}"


def _logs_cmd(workspace: str | None) -> str | None:
    if not workspace:
        return None
    return f"supernova-whitebox logs {workspace} --follow"


class WorkflowLogger:
    """Emits DisplayEvents through a dispatcher.

    The dispatcher fans events to FileLogRenderer (writes workflow.log via the
    injected LogStream) and, optionally, a RichConsoleRenderer for live stdout.
    """

    def __init__(self, session_metadata: SessionMetadata, use_rich: bool = False,
                 console: Console | None = None,
                 dashboard: LiveDashboardRenderer | None = None) -> None:
        self._meta = session_metadata
        self._workflow_id: str | None = None
        self._stream: LogStream | None = None
        self._dispatcher: DisplayDispatcher | None = None
        self._use_rich = use_rich
        self._console = console
        self._dashboard = dashboard
        # Per-workspace failure-log redirect path; set by the redirect installer
        # (Part A / Task 5) during initialize(). None => detail_path=None.
        self._activity_failure_log_path: str | None = None

    async def initialize(self, workflow_id: str | None = None, *,
                         event_file: str | None = None) -> None:
        self._workflow_id = workflow_id
        path = generate_workflow_log_path(self._meta)
        self._stream = LogStream(path)
        await self._stream.open()
        # Divert temporalio worker/activity logging to a sibling file (same dir
        # as workflow.log) BEFORE renderers consume any events, so the first
        # ERROR can already point at detail_path. Degrades silently. 默认(WARNING)
        # 只收 activity failure tracebacks; SUPERNOVA_TEMPORALIO_LOG_LEVEL=DEBUG 时也收
        # worker 执行边界日志(Running/Completing activity), 排 10min 无日志空窗之用。
        self._install_failure_redirect()

        renderers: list = [FileLogRenderer(self._stream)]
        if self._console is not None:
            from supernova_core.display.rich_renderer import RichConsoleRenderer
            renderers.append(RichConsoleRenderer(
                self._console,
                show_phase=True,                  # rich/plain 都显示 PHASE 分隔行（恢复结构感）
                show_steps=True,                 # rich: 放开 STEP 行
                show_tools=not self._use_rich,   # rich: 隐藏 🔧（仍写 workflow.log）
            ))
        if self._use_rich and self._dashboard is not None:
            renderers.append(self._dashboard)
        # 【新增】Web 事件落盘 renderer（env 启用，未设=零影响）。
        # 挂载独立的 StructuredEventRenderer，把原子 DisplayEvent 序列化成 ndjson 行，
        # 供 supernova-web 后端 SSE 通道 tail/重放。env 未设时整段跳过，行为零变化。
        # C1: event_file 参数优先(来自 PipelineInput.event_file, web 提交端塞);
        # None 时回落 env SUPERNOVA_WEB_EVENT_FILE(CLI run_scan 经 wire_web_event_file 设 env, 零改动)。
        web_event_file = event_file or os.environ.get("SUPERNOVA_WEB_EVENT_FILE")
        if web_event_file:
            from supernova_core.display.structured_event_renderer import StructuredEventRenderer
            renderers.append(StructuredEventRenderer(web_event_file))
        self._dispatcher = DisplayDispatcher(renderers)
        # 解耦(2026-08-05 multi-scan-concurrency-fix):dispatch 非阻塞入队,需先起
        # drain task 消费,否则所有事件堆积不入盘(workflow.log/events.ndjson 全空)。
        # 必须在 WorkflowHeader 首事件 dispatch 之前 start。
        await self._dispatcher.start()

        ws = workflow_id or self._meta.id
        mode = self._meta.web_url or "offline (source code analysis)"
        await self._dispatcher.dispatch(WorkflowHeader(
            timestamp=format_log_time(), category="HEADER",
            workflow_id=workflow_id, target_url=self._meta.web_url or None,
            repo_path=self._meta.repo_path,
            mode=mode,
            web_ui_url=_web_ui_url(workflow_id),
            logs_cmd=_logs_cmd(ws),
            workspace=ws,
        ))

    def _install_failure_redirect(self) -> None:
        """Install the temporalio worker/activity -> file redirect; set detail_path hint.

        Redirect target is the same-source sibling of workflow.log
        (``<audit_dir>/activity_failures.log``), so the live display's ERROR line
        can hint at where the full traceback lives. The file also captures worker
        execution-boundary logs (``Running/Completing activity``) when
        ``SUPERNOVA_TEMPORALIO_LOG_LEVEL=DEBUG``; the default WARNING keeps only
        failure tracebacks (zero-regression). On any install failure we degrade
        silently (tracebacks may appear on terminal) — never break the scan.
        ``log_error`` then emits with ``detail_path=None``.
        """
        try:
            failure_path: Path = generate_workflow_log_path(self._meta).with_name(
                "activity_failures.log")
            # 具名注册（2026-09-11 日志串台修复）：本会话的 activity failure
            # record 按消息内 workflow_id（-resume-N 变体前缀匹配）路由回本目录，
            # 不再被并发会话（corr 等）的最后安装抢走/反向抢走别人。无 id record
            # 仍 fallback 到最近安装目录（旧行为）。
            # id 优先取 activity 运行时上下文的真实 temporal workflow_id（record
            # 消息里的形态，如 "__legacy__-<scan>-resume-1"）；_workflow_id 是
            # scan_id（无 ws 前缀），前缀匹配对不上 record，仅作回落。
            install_temporalio_log_redirect(
                failure_path,
                workflow_id=current_temporal_workflow_id()
                or getattr(self, "_workflow_id", None))
            self._activity_failure_log_path = str(failure_path)
        except Exception:
            logger.warning(
                "temporalio log redirect install failed; "
                "activity tracebacks may appear on terminal", exc_info=True)
            self._activity_failure_log_path = None

    async def log_phase(self, phase: str, event: Literal["start", "complete"],
                        steps: tuple[str, ...] = (),
                        step_intents: tuple[str | None, ...] = ()) -> None:
        if self._dispatcher is None:
            return
        await self._dispatcher.dispatch(PhaseEvent(
            timestamp=format_log_time(), category="PHASE", phase=phase,
            event=event, steps=tuple(steps), step_intents=tuple(step_intents)))

    async def log_info(self, message: str, level: Literal["info", "warning"] = "info") -> None:
        """Emit a user-facing info/warning line.

        Routes through the dispatcher (not bare logging → stderr), so the line
        scrolls above the Live footer and is persisted to workflow.log — avoids
        the stderr/footer collision that bare ``logger.warning`` causes in the
        workflow sandbox thread.
        """
        if self._dispatcher is None:
            return
        await self._dispatcher.dispatch(InfoEvent(
            timestamp=format_log_time(), category="INFO",
            message=message, level=level,
        ))

    async def log_step(self, name: str, phase: str, event: Literal["start", "complete"],
                       duration_ms: int | None = None, error: str | None = None,
                       intent: str | None = None) -> None:
        if self._dispatcher is None:
            return
        await self._dispatcher.dispatch(StepEvent(
            timestamp=format_log_time(), category="STEP", name=name, phase=phase,
            event=event, duration_ms=duration_ms, error=error, intent=intent))

    async def log_agent(self, agent_name: str, event: Literal["start", "end"],
                        details: AgentLogDetails | None = None) -> None:
        if self._dispatcher is None:
            return
        d = details or AgentLogDetails(attempt_number=1)
        await self._dispatcher.dispatch(AgentEvent(
            timestamp=format_log_time(), category="AGENT", agent_name=agent_name,
            event=event, attempt=d.attempt_number, duration_ms=d.duration_ms,
            cost_usd=d.cost_usd, cost_currency=d.cost_currency, success=d.success,
            error=d.error,
            input_tokens=d.input_tokens, output_tokens=d.output_tokens,
            cache_read_tokens=d.cache_read_tokens, cache_creation_tokens=d.cache_creation_tokens))

    async def log_tool_start(self, agent_name: str, tool_name: str, parameters: Any) -> None:
        if self._dispatcher is None:
            return
        await self._dispatcher.dispatch(ToolCallEvent(
            timestamp=format_log_time(), category="TOOL", agent_name=agent_name,
            tool_name=tool_name, parameters=parameters))

    async def log_llm_response(self, agent_name: str, turn: int, content: str) -> None:
        if self._dispatcher is None:
            return
        await self._dispatcher.dispatch(LlmTurnEvent(
            timestamp=format_log_time(), category="LLM", agent_name=agent_name,
            turn=turn, content=content))

    async def log_gitnexus_progress(self, phase: str, kind: str, done: int,
                                    total: int, hits: int,
                                    detail: str | None = None) -> None:
        """Emit a GitNexus-track LLM progress line (sink/source/taint/chain-verdict).

        Routed through the dispatcher like other events → scrolls above the Live
        footer and persists to workflow.log. best-effort: no-op when no dispatcher.
        """
        if self._dispatcher is None:
            return
        await self._dispatcher.dispatch(GitnexusLlmEvent(
            timestamp=format_log_time(), category="GN-LLM", phase=phase, kind=kind,
            done=done, total=total, hits=hits, detail=detail,
        ))

    async def log_event(self, event_type: str, message: str) -> None:
        """Log a generic categorized event.

        Writes directly to the file stream (bypassing the dispatcher), so generic
        events appear in workflow.log but NOT on Rich stdout when use_rich=True.
        This is intentional: generic events are rare and don't warrant a dedicated
        DisplayEvent type. If Rich output of generic events becomes needed, introduce
        a GenericEvent type and route through the dispatcher.
        """
        if self._dispatcher is None:
            return
        await self._stream.write(f"[{format_log_time()}] [{event_type}] {message}\n")

    @staticmethod
    def _retry_silent_enabled() -> bool:
        """SUPERNOVA_SILENT_RETRY 真值 → attempt 级失败静默(不进终端 UI)。

        对齐 TS progress-indicator 不渲染 attempt 级(只 spinner)。仅影响 retryable 且
        未用尽的 attempt 级;用尽/non-retryable 的 ERROR 不受影响(真失败必须可见)。
        """
        return os.getenv("SUPERNOVA_SILENT_RETRY", "").strip().lower() in (
            "1", "true", "yes", "on")

    async def log_error(self, error: Exception, context: str | None = None,
                        *, attempt: int | None = None,
                        max_attempts: int | None = None) -> None:
        if self._dispatcher is None:
            return
        # Same-source classification as Temporal (models/errors.py) — keeps the
        # live display's error label identical to what drives retry decisions.
        from supernova_core.models.errors import classify_error_for_temporal
        etype, retryable = classify_error_for_temporal(error)
        # 对齐原始 TS createVulnValidator 的 logger.warn(shannon/session-manager.ts:143):
        # retryable 且未用尽(attempt < max)→ WARNING(可恢复,Temporal 会自动重试);
        # 用尽 / non-retryable → ERROR(最终失败)。PY 此前硬编码 ERROR,导致 attempt 级
        # 失败(如 exploitation_queue 缺失待重试)满屏 ERROR 误导读作真失败。
        in_progress_retry = (
            retryable and bool(attempt) and bool(max_attempts) and attempt < max_attempts
        )
        # SUPERNOVA_SILENT_RETRY=1: attempt 级失败静默(不进终端 UI,对齐 TS progress-indicator
        # 不渲染 attempt 级)。用尽/non-retryable 不受影响(真失败必须可见)。
        if in_progress_retry and self._retry_silent_enabled():
            return
        category = "WARNING" if in_progress_retry else "ERROR"
        await self._dispatcher.dispatch(ErrorEvent(
            timestamp=format_log_time(), category=category,
            error_type=type(error).__name__, message=str(error), context=context,
            classified=etype, display_retryable=retryable,
            attempt=attempt, max_attempts=max_attempts,
            detail_path=self._activity_failure_log_path))

    async def log_workflow_complete(self, summary: WorkflowSummary) -> None:
        if self._dispatcher is None:
            return
        # AgentMetricsSummary has no success field; agents listed in a completed
        # summary are assumed to have succeeded. If per-agent failure state is needed
        # later, thread a success flag through AgentMetricsSummary first.
        agents = [
            AgentMetric(name=n, duration_ms=m.duration_ms, cost_usd=m.cost_usd,
                        cost_currency=m.cost_currency, success=True,
                        input_tokens=m.input_tokens, output_tokens=m.output_tokens,
                        cache_read_tokens=m.cache_read_tokens,
                        cache_creation_tokens=m.cache_creation_tokens)
            for n, m in summary.agent_metrics.items()
        ]
        await self._dispatcher.dispatch(SummaryEvent(
            timestamp=format_log_time(), category="SUMMARY", status=summary.status,
            total_duration_ms=summary.total_duration_ms, total_cost_usd=summary.total_cost_usd,
            cost_currency=summary.cost_currency, agents=agents, error=summary.error,
            total_input_tokens=summary.total_input_tokens,
            total_output_tokens=summary.total_output_tokens,
            total_cache_read_tokens=summary.total_cache_read_tokens,
            total_cache_creation_tokens=summary.total_cache_creation_tokens))

    async def log_resume_header(self, resume_info: ResumeInfo) -> None:
        if self._dispatcher is None:
            return
        await self._dispatcher.dispatch(ResumeEvent(
            timestamp=format_log_time(), category="RESUME",
            previous_workflow_id=resume_info.previous_workflow_id,
            new_workflow_id=resume_info.new_workflow_id,
            checkpoint_hash=resume_info.checkpoint_hash,
            completed_agents=resume_info.completed_agents))

    async def close(self) -> None:
        # 【新增】遍历 renderers 调 close：Web renderer（StructuredEventRenderer）需
        # flush+关 ndjson 文件句柄；其它 renderer（FileLogRenderer/RichConsoleRenderer/
        # LiveDashboardRenderer）目前无 close 方法 → getattr 取不到就跳过，行为不变。
        # 必须在关 stream 之前做，避免 renderer 持有的引用在 stream 关闭后失效。
        if self._dispatcher is not None:
            # 解耦收尾(2026-08-05):先排空队列(graceful——不丢已入队事件)再 cancel
            # drain,必须在关 stream/renderer 句柄之前,否则 drain 仍在写已关闭的句柄。
            await self._dispatcher.close()
            for r in getattr(self._dispatcher, "_renderers", []):
                close_fn = getattr(r, "close", None)
                if close_fn is not None:
                    try:
                        await close_fn()
                    except Exception:
                        # 任何一个 renderer close 失败都不能阻断其它 renderer / stream 关闭。
                        logger.warning("renderer close failed: %s", type(r).__name__, exc_info=True)
        if self._stream is not None:
            await self._stream.close()
            self._stream = None
        self._dispatcher = None  # all log_* methods check dispatcher and no-op after close
