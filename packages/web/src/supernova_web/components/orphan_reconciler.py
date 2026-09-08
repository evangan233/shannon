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
from datetime import datetime, timezone
from pathlib import Path

import aiofiles
from temporalio.client import Client, WorkflowExecutionStatus

from supernova_core.session import SessionManager

from .scan_liveness import is_scan_alive

_log = logging.getLogger(__name__)

# activity_failures.log 尾部截断长度（与 scan_manager.stderr_tail 对齐）
_TAIL_BYTES = 2048


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


async def _workflow_still_running(scan_dir: Path) -> bool:
    """scan 对应 temporal workflow 是否仍 RUNNING。

    RUNNING = workflow 已提交、尚未终态，**含 worker 还未 poll 到 task 的排队阶段**——这正是
    「并发排队超 120s 提交宽限」的合法存活态，绝非孤儿。查到 RUNNING 即不干预（对症幽灵 scan）。

    整个查询(connect + describe)经 asyncio.wait_for 限时（见 _temporal_query_timeout）：Client.connect
    无内置超时，而 reconcile 在 /events 每次 poll 同步 await，temporal 抖动时卡死会阻塞 live 页 SSE。

    降级：无法反推 workflow_id / 查询超时 / temporal 不可达 / workflow 不存在（host CLI scan 无 temporal
    workflow、或 workflow 已被回收）→ 一律返 False，回退上层 heartbeat 判活（保持原行为：既不
    误杀活 scan，也不放任真死 scan）。temporal 查询 best-effort，异常绝不阻塞 reconcile。
    """
    workflow_id = _workflow_id_from_scan_dir(scan_dir)
    if workflow_id is None:
        return False

    async def _probe() -> bool:
        client = await Client.connect(_temporal_address())
        desc = await client.get_workflow_handle(workflow_id).describe()
        return desc.status == WorkflowExecutionStatus.RUNNING

    try:
        return await asyncio.wait_for(_probe(), timeout=_temporal_query_timeout())
    except Exception as e:
        # 超时 / 断连 / workflow 不存在 -> 保守回退，不据「查不到」误判。
        # L3：此前静默吞，致惰性 reconcile 失效无从排查（2026-08-06 hk-user-view 卡 running
        # 疑点即此）。补 debug 日志：记 workflow_id + 异常类型，让 reconcile 决策链可观测。
        _log.debug("reconcile _workflow_still_running fallback (wf=%s): %r", workflow_id, e)
        return False


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

        # temporal workflow 仍 RUNNING（含 worker 队列排队等执行的阶段）→ scan 绝非孤儿，
        # 不写 scan_end。对症并发排队超提交宽限被误判 interrupted（2026-08-04 幽灵 scan）：
        # 第二个白盒 scan 被第一个占着 worker，排队 >120s 期间无 heartbeat，旧逻辑据 heartbeat
        # stale 误判；workflow RUNNING 是比 heartbeat 更可靠的「已提交存活」信号——heartbeat 仅
        # 反映 worker 是否已开始执行，不反映「已提交、排队中」的合法存活态。
        if await _workflow_still_running(ws_dir):
            return False

        mgr = SessionManager(ws_dir.parent)
        status = mgr.get_status(ws_dir)
        if status in ("completed", "failed"):
            return False  # 已结案

        event_file = ws_dir / "events.ndjson"
        if _has_scan_end(event_file):
            return False  # 幂等：已有 scan_end（_watch 或 StructuredEventRenderer 已收尾）

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

        reason = ("扫描未检测到 worker 心跳——worker 容器可能未启动或已退出"
                  "（worker 应在扫描提交后数秒内写首个 heartbeat；持续无心跳请检查"
                  " worker 容器是否运行，如 ./scripts/up.sh 是否已带起 worker）")
        tail = _failure_tail(ws_dir)
        if tail:
            reason = reason + "；activity 失败日志尾部：\n" + tail
        await _write_scan_end(event_file, "interrupted", -1, reason)

        # session.json 标完成时间，让列表/概览不再显永卡 running；status 设 interrupted
        # （_status_of 对非 completed/failed + 不存活一律归 interrupted，设不设都归此；
        #  设上是为了 completed_at + 显式语义，方便排查）。
        mgr.update_session(ws_dir, {
            "completed_at": time.time(),
            "status": "interrupted",
        })
        _log.info("reconcile_orphaned reaped orphan scan: %s (wrote scan_end=interrupted)", ws_dir.name)
        return True
    except Exception:
        # 对账是兜底增强，绝不因单 ws 异常拖垮启动或请求。
        # L3：此前 bare except 静默吞所有异常（含真实 bug），致惰性 reconcile 失效无从排查
        # （2026-08-06 hk-user-view 卡 running 疑点）。改 logger.exception 记录，不再静默。
        _log.exception("reconcile_orphaned failed for %s", ws_dir)
        return False
