"""孤儿 scan 对账：容器重启等场景下 scan_manager._watch 丢失，session 卡 running
且无 scan_end。本模块在启动 / events 端点惰性触发时为这类孤儿补写 scan_end
(interrupted) + 失败原因，让 live SSE 能正常关流、前端显「已中断」。

判定孤儿：session 非完成/失败态 + 进程不存活 + events.ndjson 无 scan_end。
不触碰仍存活（is_running=True）或已结案（completed/failed）的 scan。
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

import aiofiles
from temporalio.client import Client, WorkflowExecutionStatus
from temporalio.service import RPCError, RPCStatusCode

from supernova_core.session import SessionManager

from .scan_liveness import is_scan_alive

_log = logging.getLogger(__name__)

# activity_failures.log 尾部截断长度（与 scan_manager.stderr_tail 对齐）
_TAIL_BYTES = 2048


class WorkflowProbe(str, Enum):
    """Temporal execution 对账结果。

    UNKNOWN 不是「已死」：网络抖动、超时和权限/服务端错误都必须保守保留 scan。
    UNTRACKED 仅用于 legacy/CLI 扫描：它们没有可反推的 Temporal workflow id，沿用
    已有 heartbeat 孤儿收尾路径，避免改变非 Temporal 扫描语义。
    """

    RUNNING = "running"
    CLOSED = "closed"
    ABSENT = "absent"
    UNKNOWN = "unknown"
    UNTRACKED = "untracked"


@dataclass(frozen=True)
class WorkflowProbeResult:
    kind: WorkflowProbe
    temporal_status: WorkflowExecutionStatus | None = None


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _has_scan_end(event_file: Path) -> bool:
    """events.ndjson 末 5 行是否含 scan_end（与 ScanManager._has_scan_end 同口径）。"""
    if not event_file.exists():
        return False
    for line in event_file.read_text("utf-8", errors="replace").splitlines()[-5:]:
        try:
            if json.loads(line).get("type") == "scan_end":
                return True
        except json.JSONDecodeError:
            continue
    return False


def _failure_tail(ws_dir: Path) -> str:
    """读 activity_failures.log 尾部（若有）作为失败原因上送 live 页。"""
    f = ws_dir / "activity_failures.log"
    if not f.exists():
        return ""
    return f.read_text("utf-8", errors="replace")[-_TAIL_BYTES:]


async def _write_scan_end(event_file: Path, status: str,
                          returncode: int, stderr_tail: str) -> None:
    payload = {
        "ts": _now_iso(), "category": "CONTROL", "type": "scan_end",
        "status": status, "returncode": returncode, "stderr_tail": stderr_tail,
    }
    async with aiofiles.open(event_file, "a") as fh:
        await fh.write(json.dumps(payload, ensure_ascii=False) + "\n")


def _temporal_address() -> str:
    """temporal 地址（与 scan_manager._temporal_address 同口径）。web 容器内 temporal 在
    compose 服务名 `temporal` 上（非 localhost），靠 env SUPERNOVA_TEMPORAL_HOST:PORT。"""
    host = os.environ.get("SUPERNOVA_TEMPORAL_HOST", "localhost")
    port = int(os.environ.get("SUPERNOVA_TEMPORAL_PORT", "7233"))
    return f"{host}:{port}"


def _workflow_id_from_scan_dir(scan_dir: Path) -> str | None:
    """从 scan_dir 反推 temporal workflow_id = {ws}-{scan_id}[-resume-N]。

    scan_dir = <workspaces>/<ws>/scans/<scan_id>（T3 1:N 结构）。非此结构（legacy 平铺 ws 根
    scan、或 default/ logs/ 等辅助目录）→ None，上层据此回退纯 heartbeat 判活。
    resume 后缀读 session.json resumeAttempts（与 scan_manager._resolve_workflow_id 同口径）。
    """
    scans_dir = scan_dir.parent
    if scans_dir.name != "scans":  # legacy 根 scan / 辅助目录 → 无可靠 workflow_id
        return None
    ws = scans_dir.parent.name
    scan_id = scan_dir.name
    n = 0
    session_file = scan_dir / "session.json"
    if session_file.exists():
        try:
            att = json.loads(session_file.read_text("utf-8")).get("resumeAttempts") or []
            if isinstance(att, list):
                n = len(att)
        except (OSError, ValueError):
            n = 0
    return f"{ws}-{scan_id}-resume-{n}" if n else f"{ws}-{scan_id}"


def _temporal_query_timeout() -> float:
    """reconcile 查 temporal workflow 状态的限时(秒)。Client.connect 无内置连接超时，而
    reconcile 在 /events 每次 poll 路径同步 await——temporal 抖动时 connect 可卡数十秒(OS
    TCP 超时)，不限时会让 live 页 SSE 阻塞。默认 5s(正常 connect+describe <1s，5s 容抖动)。"""
    return float(os.environ.get("SUPERNOVA_RECONCILE_TEMPORAL_TIMEOUT_SECONDS", "5"))


async def _probe_workflow(scan_dir: Path) -> WorkflowProbeResult:
    """返回 scan 的 Temporal 生命周期探测结果（含 legacy/CLI 的 UNTRACKED）。

    RUNNING = workflow 已提交、尚未终态，**含 worker 还未 poll 到 task 的排队阶段**——这正是
    「并发排队超 120s 提交宽限」的合法存活态，绝非孤儿。查到 RUNNING 即不干预（对症幽灵 scan）。

    整个查询(connect + describe)经 asyncio.wait_for 限时（见 _temporal_query_timeout）：Client.connect
    无内置超时，而 reconcile 在 /events 每次 poll 同步 await，temporal 抖动时卡死会阻塞 live 页 SSE。

    关键不变量：查询失败与 workflow 已关闭不同。只有服务明确返回 NOT_FOUND 才是
    ABSENT；超时、断连和任何其他 RPC 错误都是 UNKNOWN，调用方不得写 interrupted。
    """
    workflow_id = _workflow_id_from_scan_dir(scan_dir)
    if workflow_id is None:
        return WorkflowProbeResult(WorkflowProbe.UNTRACKED)

    async def _describe() -> WorkflowProbeResult:
        client = await Client.connect(_temporal_address())
        desc = await client.get_workflow_handle(workflow_id).describe()
        # continue-as-new 的旧 run 已关闭，但同一 workflow chain 仍在推进；对账无法
        # 在这里可靠分辨最新 run 时宁可 fail-open，不能把它写成 interrupted。
        live_statuses = {
            WorkflowExecutionStatus.RUNNING,
            WorkflowExecutionStatus.CONTINUED_AS_NEW,
        }
        return WorkflowProbeResult(
            WorkflowProbe.RUNNING if desc.status in live_statuses else WorkflowProbe.CLOSED,
            desc.status)

    try:
        return await asyncio.wait_for(_describe(), timeout=_temporal_query_timeout())
    except RPCError as err:
        if err.status is RPCStatusCode.NOT_FOUND:
            return WorkflowProbeResult(WorkflowProbe.ABSENT)
        _log.debug("reconcile workflow probe unknown (wf=%s): %r", workflow_id, err)
        return WorkflowProbeResult(WorkflowProbe.UNKNOWN)
    except Exception as e:
        _log.debug("reconcile workflow probe unknown (wf=%s): %r", workflow_id, e)
        return WorkflowProbeResult(WorkflowProbe.UNKNOWN)


async def _workflow_still_running(scan_dir: Path) -> bool:
    """兼容旧调用方的 bool 包装；新对账必须直接消费 ``_probe_workflow``。"""
    return (await _probe_workflow(scan_dir)).kind is WorkflowProbe.RUNNING


def _closed_business_status(temporal_status: WorkflowExecutionStatus | None) -> str:
    """仅凭 Temporal 关闭事件可安全归类的业务终态。

    COMPLETED 不能直接等同 completed：本项目 workflow 可以正常 return 一个
    ``status=failed`` 的业务结果；对账正是在 session/scan_end 缺失时运行。因此
    仅知 COMPLETED 时保守记录为 interrupted。
    """
    if temporal_status in {WorkflowExecutionStatus.FAILED, WorkflowExecutionStatus.TIMED_OUT}:
        return "failed"
    if temporal_status is WorkflowExecutionStatus.CANCELED:
        return "cancelled"
    if temporal_status is WorkflowExecutionStatus.TERMINATED:
        return "killed"
    return "interrupted"


async def _closed_workflow_result_status(scan_dir: Path) -> str | None:
    """读取已关闭 workflow 的业务结果，补足 Temporal COMPLETED 的语义盲区。"""
    workflow_id = _workflow_id_from_scan_dir(scan_dir)
    if workflow_id is None:
        return None

    async def _result() -> str | None:
        client = await Client.connect(_temporal_address())
        value = await client.get_workflow_handle(workflow_id).result()
        if isinstance(value, str):
            return value
        if isinstance(value, dict):
            status = value.get("status")
        else:
            status = getattr(value, "status", None)
        return status if isinstance(status, str) else None

    try:
        return await asyncio.wait_for(_result(), timeout=_temporal_query_timeout())
    except Exception as exc:  # closed result is best-effort; never turn a query failure into success
        _log.debug("reconcile workflow result unavailable (scan=%s): %r", scan_dir.name, exc)
        return None


async def _reconciled_closed_status(scan_dir: Path,
                                    temporal_status: WorkflowExecutionStatus | None) -> str:
    """结合 Temporal close status 与 workflow 返回的业务 status 生成最终状态。"""
    fallback = _closed_business_status(temporal_status)
    if temporal_status is not WorkflowExecutionStatus.COMPLETED:
        return fallback
    result_status = await _closed_workflow_result_status(scan_dir)
    if result_status in {"completed", "failed", "cancelled", "killed", "crashed", "interrupted"}:
        return result_status
    return fallback


async def reconcile_orphaned(ws_dir: Path, is_running: bool,
                             scan_manager: object | None = None) -> bool:
    """若 ws 是孤儿（非完成/失败 + 不存活 + 无 scan_end），补写 scan_end + 标 session 完成。

    返回是否实际写了 scan_end（或对组合扫描委托了恢复）。任何异常都不应阻塞调用方
    （启动 / 请求），故内部兜底。

    scan_manager（spec §7.5，Task 5）：传入时，对 **组合扫描**（session.combined=true）
    委托 ``scan_manager._reconcile_combined_scan``——按 bb_phase 补接力/补报告/补 scan_end，
    **不**在此写 scan_end=interrupted（避免与组合接力 scan_end 双写冲突）。非组合扫描
    行为不变（零回归）。scan_manager=None 时所有 scan 走原有 interrupted 路径。
    """
    try:
        _log.debug("reconcile_orphaned enter: %s is_running=%s", ws_dir.name, is_running)
        session_file = ws_dir / "session.json"
        if not session_file.exists():
            return False  # 非 scan 工作区（如 default/ logs/ 等辅助目录）
        if is_running:
            return False  # web 托管且仍存活，绝不干预

        # 跨 host/容器边界存活信号:heartbeat fresh(worker 在跑)OR 提交宽限内(workflow 刚提交、
        # worker 还没写首个 heartbeat 的冷启动窗口)。后者防「提交后 1s 内前端首次 poll /events 即
        # 触发 reconcile 误判 interrupted」(hr_1784014329 即此, _status_of 终态优先致误杀不可逆)。
        # 回归:kol_mapping_service_20260708-193139(host CLI 起的活 scan)被误判即缺 heartbeat 门。
        if is_scan_alive(ws_dir):
            return False

        # 排队中（worker 闸门 waiting 命中）：正常等待态，心跳不更新是预期
        # （spec 2026-09-08-worker-scan-gate §7.5）——temporal 查询前短路。
        from supernova_web.components.workspaces_indexer import _is_queued_in_gate
        if _is_queued_in_gate(ws_dir):
            return False

        mgr = SessionManager(ws_dir.parent)
        status = mgr.get_status(ws_dir)
        if status in {"completed", "failed", "cancelled", "killed", "crashed", "interrupted"}:
            return False  # 已有业务终态，绝不由存活探测改写

        event_file = ws_dir / "events.ndjson"
        if _has_scan_end(event_file):
            return False  # 幂等：已有 scan_end（_watch 或 StructuredEventRenderer 已收尾）

        # RUNNING（含任务队列等待/retry backoff）和 UNKNOWN 都不能收尾：前者明确
        # 活着，后者没有足够证据。此前把查询失败折叠为 False 会在 Temporal 抖动时
        # 写入不可逆 interrupted + scan_end，造成列表/详情/SSE 三方口径分裂。
        probe = await _probe_workflow(ws_dir)
        if probe.kind in (WorkflowProbe.RUNNING, WorkflowProbe.UNKNOWN):
            return False

        # 组合扫描委托（spec §7.5，Task 5）：combined=true + 传了 scan_manager → 交给
        # _reconcile_combined_scan 按 bb_phase 恢复（补接力/补报告/补 scan_end），不在此写
        # interrupted（避免与接力 scan_end 双写）。非组合 → 走原有 interrupted 路径（零回归）。
        if scan_manager is not None:
            try:
                combined = bool(json.loads(
                    session_file.read_text("utf-8", errors="replace")).get("combined"))
            except (OSError, ValueError):
                combined = False
            if combined:
                # Fire-and-forget（review fix #2）：_reconcile_combined_scan 可能调
                # _run_blackbox_phase → await 黑盒 result（分钟~小时级）。inline await
                # 会阻塞 app 启动 + 串行阻塞其他孤儿 scan 恢复。故 kick 为 background
                # task（对齐 start() fire _combined_orchestrator 的 create_task 模式），
                # 立即返回。task 内部幂等追踪 + 自清 _reconcile_tasks。
                scan_manager._kick_combined_reconcile(ws_dir)  # type: ignore[attr-defined]
                _log.info("reconcile_orphaned kicked combined recovery: %s", ws_dir.name)
                return True

        final_status = (await _reconciled_closed_status(ws_dir, probe.temporal_status)
                        if probe.kind is WorkflowProbe.CLOSED else "interrupted")
        reason = ("扫描未检测到 worker 心跳——worker 容器可能未启动或已退出"
                  "（worker 应在扫描提交后数秒内写首个 heartbeat；持续无心跳请检查"
                  " worker 容器是否运行，如 ./scripts/up.sh 是否已带起 worker）")
        tail = _failure_tail(ws_dir)
        if tail:
            reason = reason + "；activity 失败日志尾部：\n" + tail
        await _write_scan_end(event_file, final_status, -1, reason)

        # session.json 标完成时间，让列表/概览不再显永卡 running。Temporal 明确的
        # FAILED/TIMED_OUT/CANCELED/TERMINATED 按对应业务终态收尾；无业务结果的
        # COMPLETED/ABSENT/legacy 才使用 interrupted。
        mgr.update_session(ws_dir, {
            "completed_at": time.time(),
            "status": final_status,
        })
        _log.info("reconcile_orphaned reaped orphan scan: %s (wrote scan_end=%s)",
                  ws_dir.name, final_status)
        return True
    except Exception:
        # 对账是兜底增强，绝不因单 ws 异常拖垮启动或请求。
        # L3：此前 bare except 静默吞所有异常（含真实 bug），致惰性 reconcile 失效无从排查
        # （2026-08-06 hk-user-view 卡 running 疑点）。改 logger.exception 记录，不再静默。
        _log.exception("reconcile_orphaned failed for %s", ws_dir)
        return False
