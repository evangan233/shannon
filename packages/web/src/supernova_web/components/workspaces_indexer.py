from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path

from .scan_liveness import is_scan_alive


def _to_unix(v) -> float | None:
    """归一 created_at/completed_at 为 unix float|None:float|int 直用、ISO str 解析、None/异常→None。
    前端 Workspace.created_at/SessionData.created_at 期望 number(unix);修后端透传 ISO str
    致前端 new Date(unix*1000) Invalid Date 的契约断裂。"""
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        try:
            return datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    return None


def _created_at_key(row: dict) -> float:
    """sort key:复用 _to_unix,缺失/异常→0.0(排最后)。
    修 sort 时 float 与 None-fallback-str 不可比、曾致 /api/workspaces 500 的 bug。"""
    return _to_unix(row.get("created_at")) or 0.0


_TERMINAL_STATUSES = frozenset(
    {"completed", "failed", "interrupted", "cancelled", "killed", "crashed"}
)


def _compute_status(path: Path, session_status: str | None) -> str:
    """scan 状态计算（scan_dir/ws_dir 通用）：终态优先 + heartbeat 判活 + 兜底 interrupted。

    抽成模块级函数供 ScanStore 与 WorkspacesIndexer 共用（1 ws : N scans 后两者都
    需在 scan_dir 维度算状态），避免判活逻辑重复。
    """
    # 终态优先(强信号,立即定):session.json 显式标了终态 -> 该终态。取代旧「只认
    # completed/failed + 兜底推断 interrupted」的混乱(spec §4.3)。
    if session_status in _TERMINAL_STATUSES:
        return session_status
    # 判活:heartbeat fresh(worker 在跑)OR 提交宽限内(workflow 刚提交、worker 还没写首个
    # heartbeat 的冷启动窗口)。pid 表不参与判活(只服务 cancel)。回归:
    # kol_mapping_service_20260708-193139(host CLI 活 scan)被误标 interrupted 即缺 heartbeat 门;
    # hr_1784014329(提交后 1s 误杀)即缺提交宽限门。
    if is_scan_alive(path):
        return "running"
    # queued 档（spec 2026-09-08-worker-scan-gate §7.4）：非终态 + 心跳死但命中
    # worker 闸门 waiting——修「排队 >120s 无心跳误显已中断」的预存 bug（排队期间
    # workflow 在闸门轮询、不写 heartbeat 是预期行为）。
    if _is_queued_in_gate(path):
        return "queued"
    # 无终态 + 无 fresh heartbeat = 未正常结束(死掉的孤儿/容器重启后子进程同死)。
    return "interrupted"


def _gate_state_file_for(p: Path) -> Path | None:
    """从 scan_dir/ws_dir 反推 workspaces 根下的 gate_state.json（worker 落盘约定）。

    scan_dir = <workspaces_root>/<ws>/scans/<scan_id>：scans 段上退两级才是根。"""
    for anc in p.parents:
        if anc.name == "scans":
            return anc.parent.parent / "gate_state.json"
    for anc in p.parents:
        if anc.name == "workspaces":
            return anc / "gate_state.json"
    return None


def _ws_and_scan_of(path: Path) -> tuple[str, str]:
    """scan_dir=…/<ws>/scans/<scan_id> → (ws, scan_id)；ws_dir 场景 scan_id 空。"""
    parts = path.parts
    if len(parts) >= 3 and parts[-2] == "scans":
        return parts[-3], parts[-1]
    return (parts[-1] if parts else "", "")


def _is_queued_in_gate(path: Path) -> bool:
    """非终态 + 心跳死时查闸门快照：本 scan（或 corr 非 reused 子仓）在 waiting。"""
    from supernova_core.services.scan_gate import read_gate_snapshot_file

    sf = _gate_state_file_for(path)
    if sf is None:
        return False
    snap = read_gate_snapshot_file(sf)
    if not snap:
        return False
    waiting = {(w.get("ws", ""), w.get("scan_id", ""))
               for w in snap.get("waiting", [])}
    if not waiting:
        return False
    ws, scan_id = _ws_and_scan_of(path)
    if (ws, scan_id) in waiting:
        return True
    # 跨仓主行：corr_children 非 reused 子仓在排队 → 主行 queued（spec §7.4）
    try:
        sess = json.loads((path / "session.json").read_text())
    except (OSError, ValueError):
        return False
    for child in (sess or {}).get("corr_children") or []:
        if not child.get("reused") and (ws, child.get("scan_id", "")) in waiting:
            return True
    return False


class WorkspacesIndexer:
    def __init__(self, workspaces_dir: Path) -> None:
        self._dir = Path(workspaces_dir)
        self._active_pids: dict[str, int] = {}

    def set_active_pid(self, ws: str, pid: int | None) -> None:
        if pid is None:
            self._active_pids.pop(ws, None)
        else:
            self._active_pids[ws] = pid

    def sync_active(self, pids: dict[str, int]) -> None:
        """ScanManager 每次 list 时注入当前在跑 pid 表（替换式，避免 stale）。"""
        self._active_pids = dict(pids)

    @staticmethod
    def _pid_alive(pid: int) -> bool:
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except Exception:
            return False

    def is_running(self, ws: str) -> bool:
        """公开访问器：ws 是否有 alive pid（替换外部对 _active_pids/_pid_alive 的私有 reach）。"""
        pid = self._active_pids.get(ws)
        return pid is not None and self._pid_alive(pid)

    def _status_of(self, ws_path: Path, session_status: str | None) -> str:
        """ws/scan 状态：委托模块级 _compute_status（保留实例方法兼容现有调用方）。"""
        return _compute_status(ws_path, session_status)

    def list_workspaces(self) -> list[dict]:
        """列 workspace（1 ws : N scans 后）：扫 workspaces/*/ 识别 ws（workspace.json
        优先，回退 legacy ws 根 session.json），每 ws 经 ScanStore.list_scans 聚合
        scan_count/latest_status/latest_created_at；ws 行状态/时间字段取 latest scan，
        统计字段（vuln/cost/duration）取最近 completed scan（回落 latest）。

        空 ws（workspace.json 但无 scan）-> scan_count=0、status=completed（idle，不显
        spinner，对齐旧 POST /api/workspaces 写 status=completed 的行为）。
        """
        # lazy import 避免 scan_store ↔ workspaces_indexer 循环导入
        #（scan_store 顶层 from .workspaces_indexer import _compute_status, _to_unix）。
        from .scan_store import ScanStore, read_workspace_meta
        store = ScanStore(self._dir)
        out: list[dict] = []
        if not self._dir.is_dir():
            return out
        for ws_dir in sorted(self._dir.iterdir()):
            if not ws_dir.is_dir() or ws_dir.is_symlink():
                continue
            if ws_dir.name.startswith("."):
                continue  # 保留段（.system 等）不进 ws 列表，对齐 app.py dot-dir 约定
            meta = read_workspace_meta(ws_dir)
            if meta is None:
                continue  # 非 ws（无 workspace.json 且无 session.json）
            name = ws_dir.name
            scans = store.list_scans(name)
            if scans:
                latest = scans[0]  # list_scans 已按 created_at 倒序
                # 统计字段取最近 completed scan：running/failed/interrupted scan 无产出
                # （或仅部分产出），取它会掩盖上一个 completed 的已知结果（回归：
                # Brightli 43 漏洞被新起 running scan 的 vuln_counts={} 清零）。
                # 无 completed（failed-only ws）回落 latest，维持原行为不清零。
                stats = next((s for s in scans if s.status == "completed"), latest)
                out.append({
                    "name": name,
                    "scan_type": latest.scan_type,
                    "status": latest.status,
                    "vuln_counts": stats.vuln_counts,
                    "vuln_count": stats.vuln_count,
                    "total_cost_usd": stats.total_cost_usd,
                    "cost_currency": stats.cost_currency,
                    "total_duration_ms": stats.total_duration_ms,
                    "links": latest.links,
                    "created_at": latest.created_at,
                    "completed_at": latest.completed_at,
                    "is_correlation": latest.is_correlation,
                    "scan_count": len(scans),
                    "latest_status": latest.status,
                    "latest_created_at": latest.created_at,
                })
            else:
                # 空 ws：无 scan。status=completed（idle），created_at 取 ws 元数据。
                ws_created = _to_unix(meta.get("created_at"))
                scan_type = meta.get("scan_type", "whitebox")
                out.append({
                    "name": name,
                    "scan_type": scan_type,
                    "status": "completed",
                    "vuln_counts": {},
                    "vuln_count": 0,
                    "total_cost_usd": None,
                    "cost_currency": None,
                    "total_duration_ms": None,
                    "links": {},
                    "created_at": ws_created,
                    "completed_at": None,
                    "is_correlation": scan_type == "correlation",
                    "scan_count": 0,
                    "latest_status": "completed",
                    "latest_created_at": ws_created,
                })
        out.sort(key=_created_at_key, reverse=True)
        return out
