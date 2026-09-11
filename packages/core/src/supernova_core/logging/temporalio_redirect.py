"""Redirect temporalio's worker-scope logging to a per-workspace file.

Two concerns are served by diverting these loggers off the terminal and into a
file, controlled by ``SUPERNOVA_TEMPORALIO_LOG_LEVEL`` (default ``WARNING``):

1. **Noise suppression (default behavior, zero-regression).** temporalio 1.27.2
   logs every activity failure with a full chained traceback via
   ``temporalio.activity.logger.warning("Completing activity as failed", exc_info=True)``
   (worker/_activity.py:474). With no logging config in supernova that record hits
   stderr via root's lastResort handler — scary, redundant noise next to our own
   clean [ERROR] line. We divert it to a file and keep the terminal clean.

2. **Worker observability (opt-in via env).** temporalio's activity *execution
   boundary* is logged at DEBUG on a *different* logger — ``temporalio.worker._activity``
   (worker/_activity.py:315 ``Running activity <type>``, :521 ``Completing activity``).
   By default these DEBUG records are filtered (root is INFO); the worker layer
   (schedule→poll→execute) is a black box, which is why a worker that fails to poll
   an activity task for minutes produces *zero* visible log. Setting
   ``SUPERNOVA_TEMPORALIO_LOG_LEVEL=DEBUG`` surfaces these records into the same file,
   so the next reproduction of a "10-min log gap" shows whether the worker ever took
   the activity task (``Running activity`` present?) and what else it was running.

Managed loggers (each gets its own FileHandler on *log_path*):

- ``temporalio.activity`` — failure tracebacks (WARNING) + heartbeats (DEBUG).
- ``temporalio.worker`` — covers the ``_activity`` / ``_workflow`` / ``_worker``
  subtree; attaching here + ``propagate=False`` captures child DEBUG records
  (e.g. ``temporalio.worker._activity``) and truncates their walk to root.

Two mechanisms keep the terminal clean, only one of which is currently load-bearing:

- The ``SUPERNOVA_TEMPORALIO_LOG_LEVEL``-gated ``FileHandler`` attached to each managed
  logger is what *currently* suppresses ``lastResort`` on stderr: Python's
  lastResort only fires for an unhandled record, and because this handler processes
  the record it is no longer unhandled — so lastResort never engages, regardless of
  ``propagate``.
- ``propagate=False`` is a *defense in depth*: it blocks the record from walking up
  to root, so a future root-level stderr handler (e.g. an app that configures the
  root logger, or the LogBusHandler that feeds the live display) would not
  double-emit the traceback / spew DEBUG worker noise into the display stream.
"""
from __future__ import annotations

import logging
import os
import re
import threading
from pathlib import Path

_LOGGER_NAME = "temporalio.activity"
# 管理的 logger 集合: temporalio.activity(现有, failure trace) + temporalio.worker
# 子树(新增, 覆盖 _activity :315/:521 执行边界 DEBUG)。父 logger temporalio.worker
# 挂 handler + propagate=False 即截断整子树(_activity/_workflow/_worker)到 root 的传播。
_MANAGED_LOGGERS = ("temporalio.activity", "temporalio.worker")

_DEFAULT_LEVEL = "WARNING"

# record 消息内 workflow_id 提取：temporalio 的 activity failure record 把 details
# dict repr 嵌进 message（"{'workflow_id': 'ws-x-corr', ...}"，2026-09-11 实证），
# kwargs 形态（workflow_id='...'）一并覆盖。
_WORKFLOW_ID_RE = re.compile(r"workflow_id['\"]?\s*[:=]\s*['\"]([^'\"]+)['\"]")


def _resolve_level() -> int:
    """``SUPERNOVA_TEMPORALIO_LOG_LEVEL`` → logging level int (default WARNING, 零回归).

    合法 level 名(DEBUG/INFO/WARNING/ERROR/CRITICAL)→ 对应 int; 非法值回落 WARNING
    + warning, 绝不抛(logging 故障不上行成扫描故障)。
    """
    raw = os.getenv("SUPERNOVA_TEMPORALIO_LOG_LEVEL", _DEFAULT_LEVEL).upper()
    level = logging.getLevelName(raw)
    if not isinstance(level, int):
        logging.getLogger(__name__).warning(
            "SUPERNOVA_TEMPORALIO_LOG_LEVEL=%r 不是合法 level 名, 回落 %s",
            raw, _DEFAULT_LEVEL,
        )
        return logging.WARNING
    return level


def _resolved_handler_path(h: logging.FileHandler) -> Path | None:
    """FileHandler 的 resolved baseFilename；resolve 失败返 None（比较时视为不匹配）。"""
    try:
        return Path(h.baseFilename).resolve()
    except OSError:
        return None


class _WorkflowRoutingHandler(logging.Handler):
    """按 record 消息内 workflow_id 路由到所属会话目录的共享 handler。

    2026-09-11 日志串台修复：常驻 worker 单进程消费 wb/bb/corr 多个 task queue，
    进程级 logger 是全局单例——旧「每次 install 挂自己的 FileHandler + 摘别人的」
    语义在并发会话下变成「最后安装者赢」，corr 的崩溃 traceback 落进 wb 会话目录
    （NodeGoat-20260910-193720 实证，排查方向被带偏）。

    新语义：每个被管 logger 挂同一 routing handler 实例；registry 维护
    workflow_id → FileHandler（前缀匹配覆盖 -resume-N / -corr 等后缀变体，多 key
    命中取最长）；无 workflow_id 的 record（worker 执行边界 DEBUG 等）fallback 到
    最近 install 的目标（与旧行为对齐）。level 过滤由本 handler 承担（env 决定），
    内部 FileHandler 恒不过滤——``Handler.handle`` 不查 level，直接转发会绕过。
    """

    def __init__(self, level: int) -> None:
        super().__init__(level=level)
        self.setLevel(level)
        self._lock = threading.Lock()
        self._targets: dict[str, logging.FileHandler] = {}
        self._fallback: logging.FileHandler | None = None

    def register(self, handler: logging.FileHandler,
                 workflow_id: str | None) -> None:
        """注册目标：workflow_id 具名注册（有 id record 按前缀路由至此）；无论
        是否具名都接管 fallback（无 id record 落最近安装目录，对齐旧行为）——
        wb/corr 任一会话后装时，无 id 的 worker 边界 DEBUG 落它目录，与旧
        「最后安装者赢」一致；有 id record 不受 fallback 换代影响。"""
        with self._lock:
            self._replace("_fallback", handler)
            if workflow_id is not None:
                self._replace(workflow_id, handler)

    def _replace(self, key: str, handler: logging.FileHandler) -> None:
        old = self._targets.get(key)
        self._targets[key] = handler
        # 换代关旧（防双写/句柄泄漏，2026-08-18 同款隐患）——但同一 handler 可同时
        # 挂在 _fallback 与具名 key（register 双注册），fallback 换代不得 close 仍被
        # 具名引用的 handler（否则 stream=None → 该会话 record 静默丢失）。
        if (old is not None and old is not handler
                and old not in self._targets.values()):
            old.close()

    def _match(self, workflow_id: str) -> logging.FileHandler | None:
        """精确 or 前缀（key + "-"）匹配；多 key 命中取最长（防前缀重叠误路由）。"""
        best_key: str | None = None
        for key in self._targets:
            if workflow_id == key or workflow_id.startswith(key + "-"):
                if best_key is None or len(key) > len(best_key):
                    best_key = key
        return self._targets.get(best_key) if best_key is not None else None

    def emit(self, record: logging.LogRecord) -> None:
        try:
            m = _WORKFLOW_ID_RE.search(record.getMessage())
            with self._lock:
                h = (self._match(m.group(1))
                     if m else None) or self._targets.get("_fallback")
                if h is None or h.stream is None:
                    return
                h.emit(record)
        except Exception:  # logging 故障不上行成扫描故障（对齐 _resolve_level）
            self.handleError(record)


_routing_handler: _WorkflowRoutingHandler | None = None


def _get_routing_handler(level: int) -> _WorkflowRoutingHandler:
    global _routing_handler
    if _routing_handler is None:
        _routing_handler = _WorkflowRoutingHandler(level)
    else:
        _routing_handler.setLevel(level)   # env 变化时同步（重装跟随最新 env）
    return _routing_handler


def current_temporal_workflow_id() -> str | None:
    """activity 运行时上下文里的真实 temporal workflow_id；不在 activity 上下文
    （CLI/测试）返回 None。注册 key 用它（与 record 消息内的 id 同形态），
    scan_id 形态（无 ws 前缀）前缀匹配不上 record。"""
    try:
        import temporalio.activity as _ta
        if not _ta.in_activity():
            return None
        return _ta.info().workflow_id
    except Exception:  # temporalio 未装/上下文异常 → None（调用方回落）
        return None


def install_temporalio_log_redirect(log_path: Path,
                                    *, workflow_id: str | None = None) -> Path:
    """Divert every managed temporalio logger's records to *log_path*; suppress from terminal.

    - 每个被管 logger(``_MANAGED_LOGGERS``)挂**共享** routing handler，级别由
      ``SUPERNOVA_TEMPORALIO_LOG_LEVEL`` 决定(默认 ``WARNING`` = 现状零回归, 只收
      failure trace; ``DEBUG`` 收 activity 执行边界日志, 排 10min 空窗之用)。
    - ``workflow_id`` 提供 → record 按消息内 workflow_id（前缀匹配，覆盖
      -resume-N/-corr 变体）路由到本目录；``None`` → 本目录设为 fallback
      （无 id record 落最近安装目录，与旧「最后安装者赢」行为对齐）。
    - ``propagate=False`` → 截断到 root LogBus, DEBUG 不污染 display 流(终端干净)。
    - ``logger.setLevel(DEBUG)`` → logger 不滤, handler 按 env 决定(不丢任何 record)。
    - 幂等: 共享 handler 只挂一次；同 workflow_id 重装换代（旧 FileHandler close，
      防双写/句柄泄漏）；不再摘其它会话的目标（并发会话各自路由，2026-09-11 修复）。
    """
    log_path = Path(log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    routing = _get_routing_handler(_resolve_level())
    handler = logging.FileHandler(log_path)
    routing.register(handler, workflow_id)

    for name in _MANAGED_LOGGERS:
        logger = logging.getLogger(name)
        # 防御迁移：摘掉旧形态直挂的 FileHandler（历史版本残留），统一走 routing。
        # 不摘则 record 被 routing + 旧 handler 双写。
        for h in list(logger.handlers):
            if isinstance(h, logging.FileHandler) and h is not routing:
                logger.removeHandler(h)
                h.close()
        if not any(h is routing for h in logger.handlers):
            logger.addHandler(routing)
        logger.propagate = False
        logger.setLevel(logging.DEBUG)   # don't filter at logger level; handler decides

    return log_path
