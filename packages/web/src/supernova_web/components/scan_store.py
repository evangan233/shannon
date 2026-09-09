"""T1: 1 ws : N scans 存储层（web 层 ScanStore）。

core SessionManager 的读写方法（get_session_data/update_session/get_status/
get_created_at/...）只收 workspace_path、不依赖 workspaces_dir；create_workspace/
list_workspaces 用 self.workspaces_dir。故 SessionManager(ws_dir/"scans") 把 scans
目录当 workspaces 根即可复用全部 scan 读写--create_workspace(name=scan_id) 即在
scans/<scan_id>/session.json 建 scan；list_workspaces() 即列该 ws 的 scans。
**core session.py 源码零改动**（CLAUDE.md §1 铁律不碰）。

双源兼容（design decision 7）：list_scans 同时识别
  ① workspaces/<ws>/scans/<scan_id>/session.json（新模型，web 建）
  ② workspaces/<ws>/session.json（legacy：CLI/worker.py 旧路径产出，或未迁移的 web scan）
统一列为 scan，按 created_at 倒序。worker.py:122-123 据 event_file.parent 推导
workspace_path=scan_dir，产物自然落 scan 子目录（worker 零改动）。
"""
from __future__ import annotations

import json
import re
import shutil
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from supernova_core.session import SessionManager
from supernova_core.utils.paths import (
    blackbox_run_dir, blackbox_runs_dir, combined_run_dir)
from supernova_core.workspace import get_workspace_vuln_counts

from .scan_liveness import is_scan_alive  # noqa: F401  (语义导出，便于测试 monkeypatch)
from .workspaces_indexer import _compute_status, _to_unix


def _now_local() -> datetime:
    """scan_id 时间戳取本地时区 now（抽函数便于测试 monkeypatch 同秒碰撞）。"""
    return datetime.now()


def combined_wallclock_ms(data: dict, created: float | None,
                          completed: float | None) -> float | None:
    """组合扫描墙钟用时(ms)：end = max(任务级 completed_at, 各 bb_run completed_at)，
    无任何终态（在跑/中断）时 end=now（列表 10s 轮询下用时随时间推进）。

    组合扫描的任务级 metrics.total_duration_ms 只由白盒 run 的 MetricsTracker 累积
    （黑盒 run 的 metrics 落 run-K/session.json，从不合并进任务级），只读 metrics 会
    显示偏小（真机 NodeGoat-20260820-174548：白盒 32.3min vs 墙钟 50.3min）。墙钟
    口径涵盖预验证+白盒+黑盒+编排间隙=全部用时，且不依赖 metrics 合并、天然覆盖
    历史数据（旁路目录时代的旧组合扫描也直接正确）。list(_summarize)/detail
    (_scan_detail) 共用，保口径一致。纯白盒/纯黑盒不走本口径（仍读 metrics）。
    """
    if not created:
        return None
    ends: list[float] = []
    if completed:
        ends.append(completed)
    for r in (data.get("bb_runs") or []):
        if isinstance(r, dict):
            ts = _to_unix(r.get("completed_at"))
            if ts:
                ends.append(ts)
    end = max(ends) if ends else time.time()
    return max(0.0, (end - created) * 1000)


def _is_combined_scan(data: dict, combined: object) -> bool:
    """组合扫描判据：session combined=True 或 bb_runs[] 非空（手动 _add_blackbox_run
    亦写 combined=True，两信号取 OR 容错半写状态）。"""
    if combined is True:
        return True
    runs = data.get("bb_runs")
    return bool(runs) if isinstance(runs, list) else False


# run_id 校验：^run-\d+$（K = per-task 单调序号，从 1 起）。get/create/list run 据此
# 拒绝越界（../）/ 非法格式（run-x），避免路径穿越读其他目录。
_RUN_ID_RE = re.compile(r"^run-(\d+)$")


def merge_latest_run_view(scan_dir: Path, data: dict) -> tuple[str | None, str | None, dict]:
    """组合任务的任务级视图合并：bb_phase/bb_reason 取 latest run，completed_agents 拼接。

    run 版本化重构（spec 2026-08-14 §5.2）把 bb_phase/bb_reason 下沉到 run 级 session 后，
    任务级 bb_phase 停在 precheck/pending（仅启动编排写）；而消费方（列表徽章/详情两段
    时间线/进度概览的 eventsUrl 切换/progress_pct）都需要「当前 run 的 phase」。list
    （_summarize）与 detail（api/scans._scan_detail）共用本视图，保证两端口径一致。

    非组合 / 无 run / run session 缺失 → 原值透传（零回归）。返回
    (bb_phase, bb_reason, progress_data)；progress_data 仅在合并时替换（浅拷贝 +
    completed_agents 拼接），供 _compute_progress_pct 用白盒+黑盒累积分子。
    """
    if not isinstance(data, dict) or not data.get("combined"):
        return (data.get("bb_phase") if isinstance(data, dict) else None,
                data.get("bb_reason") if isinstance(data, dict) else None, data)
    latest = data.get("latest_bb_run")
    if not latest:
        return data.get("bb_phase"), data.get("bb_reason"), data
    run_dir = blackbox_run_dir(scan_dir, latest)
    if not (run_dir / "session.json").exists():
        return data.get("bb_phase"), data.get("bb_reason"), data
    run_data = SessionManager(run_dir.parent).get_session_data(run_dir)
    merged = dict(data)
    merged["completed_agents"] = list(data.get("completed_agents") or []) + \
        list(run_data.get("completed_agents") or [])
    return run_data.get("bb_phase", data.get("bb_phase")), \
        run_data.get("bb_reason", data.get("bb_reason")), merged


def effective_scan_status(status: str, combined: bool | None,
                          bb_phase: str | None) -> str:
    """返回组合扫描对外可见的整体状态。

    组合扫描的白盒 workflow 会先在任务根 session 写入 ``status=completed``，
    但黑盒接力阶段的真实状态写在 latest blackbox run。对外状态必须以后者为准，
    否则会在「白盒完成、黑盒待接力/运行中」期间提前显示整个扫描已完成。

    非组合扫描以及缺失/未知阶段保持原状态，兼容历史 session。
    """
    if combined is not True:
        return status
    # 显式取消/失败是更强的终态信号，不能被残留的 pending/running phase 覆盖。
    if status in {"failed", "cancelled", "killed", "crashed", "skipped"}:
        return status
    if bb_phase in {"precheck", "pending", "running"}:
        return "running"
    if bb_phase == "failed":
        return "failed"
    if bb_phase == "skipped":
        return "skipped"
    if bb_phase == "completed":
        return "completed"
    return status


def _compute_progress_pct(status: str, combined: bool | None,
                          bb_phase: str | None, data: dict) -> float:
    """收起态粗略进度 0-100（spec §9.2 三阶段加权）。

    组合扫描（combined=True）按三阶段加权：
        precheck        → 0%（预验证期无 completed）
        白盒中(pending) → 5 + 50 × (wb_completed / wb_expected)
        黑盒中(running) → 55 + 45 × (bb_completed / bb_expected)
        completed       → 100%
        failed/skipped  → 0%（终态，非成功完成）
    纯白盒/纯黑盒（combined 非 True）：completed / expected × 100（expected 缺失 → 0）。

    收起态精度门槛低（用户不展开不细看），故除零保护 + 容错缺失字段。
    """
    expected = data.get("expected_agents") or {} if isinstance(data, dict) else {}
    completed = data.get("completed_agents") or [] if isinstance(data, dict) else []
    completed_n = len(completed) if isinstance(completed, list) else 0

    if combined is True:
        if status in ("failed", "cancelled", "killed", "crashed", "skipped"):
            return 0.0
        # 三阶段加权（spec §9.2）：precheck 0-5% / 白盒 5-50% / 黑盒 55-45%。
        wb_expected = expected.get("whitebox", 0) or 0
        bb_expected = expected.get("blackbox", 0) or 0
        # completed_agents 不分白盒/黑盒（累积），用 bb_phase 判当前阶段 + 白盒/黑盒 expected
        # 拆分子（pending 期分子=白盒 agent 数；running 期分子需扣白盒 expected，算黑盒增量）。
        if bb_phase == "precheck":
            return 0.0
        if bb_phase in ("pending", None):
            # 白盒中：completed 中属白盒阶段的进度。completed_n 可能跨阶段累积，用 wb_expected 截断。
            wb_done = min(completed_n, wb_expected) if wb_expected > 0 else 0
            ratio = (wb_done / wb_expected) if wb_expected > 0 else 0.0
            return round(5 + 50 * ratio, 1)
        if bb_phase == "running":
            # 黑盒中：白盒段已满 50% + 黑盒增量 45%。
            bb_done = max(completed_n - wb_expected, 0) if bb_expected > 0 else 0
            ratio = (bb_done / bb_expected) if bb_expected > 0 else 0.0
            return round(55 + 45 * ratio, 1)
        if bb_phase == "completed":
            return 100.0
        if bb_phase in ("failed", "cancelled", "skipped"):
            return 0.0
        # 未知阶段保留旧 session 的 status 兜底；正常组合阶段均已在上面处理。
        return 100.0 if status == "completed" else 0.0

    if status == "completed":
        return 100.0
    if status in ("failed", "cancelled", "skipped"):
        return 0.0

    # 纯白盒/纯黑盒：completed / expected × 100。
    wb_expected = expected.get("whitebox", 0) or 0
    if wb_expected > 0:
        return round(min(completed_n / wb_expected, 1.0) * 100, 1)
    return 0.0


def _repo_label(repo_path: str) -> str:
    """从 repo_path 派生仓库名标签（scan_id 前缀）：basename 合法化为目录名/标识符安全
    字符——连续的路径分隔符 / 空白 / 点 -> 单个 '-'，去首尾 '-'，空 fallback 'repo'。
    对齐 core _default_workspace_name 的 hostname 推导（Path.name.replace('.', '-')）。"""
    name = Path(repo_path).name
    label = re.sub(r"[/\\\s.]+", "-", name).strip("-")
    return label or "repo"


# 分支快照文件（spec 2026-08-21 §4）：提交扫描时仓库当前 branch/commit，报告区分
# 「同一仓扫不同分支」的来源。scan_id 只含仓库名+时间戳，切分支后仅靠它分不清。
REPO_SNAPSHOT_FILE = "repo-snapshot.json"


def _repo_branch_commit(repo_path: str) -> tuple[str | None, str | None]:
    """读仓库当前 (branch, commit)：私有克隆读 .supernova-repo.json 的 source；
    linked 仓（无 meta）读 .git/HEAD 的 ref（commit 无来源 → None）。全缺失 → (None, None)。"""
    p = Path(repo_path)
    meta_file = p / ".supernova-repo.json"
    if meta_file.exists():
        try:
            src = json.loads(meta_file.read_text("utf-8", errors="replace")).get("source", {})
            return src.get("branch"), src.get("commit")
        except json.JSONDecodeError:
            pass
    head_file = p / ".git" / "HEAD"
    if head_file.exists():
        m = re.match(r"ref: refs/heads/(.+)",
                     head_file.read_text("utf-8", errors="replace").strip())
        if m:
            return m.group(1), None
    return None, None


def write_repo_snapshot(scan_dir: Path, repo_path: str) -> None:
    """把仓库当前 branch/commit 快照进 scan_dir/repo-snapshot.json。

    两来源皆缺失（裸目录/损坏）→ 不写文件（读侧缺失 → None，前端不显示）。
    """
    branch, commit = _repo_branch_commit(repo_path)
    if branch or commit:
        (Path(scan_dir) / REPO_SNAPSHOT_FILE).write_text(
            json.dumps({"branch": branch, "commit": commit}), encoding="utf-8")


def read_repo_snapshot(scan_dir: Path) -> dict:
    """读快照；未写/损坏 → {}（调用方 .get() 兜 None）。"""
    try:
        data = json.loads((Path(scan_dir) / REPO_SNAPSHOT_FILE).read_text("utf-8", errors="replace"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _repo_snapshot_fields(scan_dir: Path) -> dict:
    """ScanSummary 构造用的快照字段展开（repo_branch/repo_commit）。"""
    snap = read_repo_snapshot(scan_dir)
    return {"repo_branch": snap.get("branch"), "repo_commit": snap.get("commit")}


def _strip_ws_prefix(ws: str, value: str) -> str:
    """剥展示名的 {ws}- 前缀：web scheme 真实 workflow_id {ws}-{scan_id} -> 展示名 {scan_id}
    （前端任务名不带工作区名，ws 上下文前端已知 / 跨 ws 表格另有独立 ws 列）；
    CLI scheme workspace_name 不以 {ws}- 开头 -> 不剥，原样。"""
    prefix = f"{ws}-"
    return value[len(prefix):] if value.startswith(prefix) else value


def resolve_workflow_id(ws: str, scan_dir: Path, scan_id: str) -> str:
    """前端「扫描任务名」展示名（= 真实 temporal workflow_id 剥 {ws}- 前缀）。

    真实 temporal workflow_id 仍是 {ws}-{scan_id}[-resume-N]（scan_manager 提交 / worker 写
    ndjson / resume 命名空间不变）；本函数返回**展示用**名——剥掉开头的 {ws}- 前缀，即
    {scan_id}[-resume-N]（= {repo}-{时间戳}），让任务名不再重复带工作区名。

    优先读 scan_dir/events.ndjson 首行 WorkflowHeader.workflow_id —— 真实 temporal id 的
    single source of truth：CLI/legacy scan 的 workflow_id = workspace_name（CLI scheme，如
    sentinel_dashboard_20260721-201435），与 web scan 的 {ws}-{scan_id}（web scheme）不同，
    算不出来只能读。web scan 的 ndjson WorkflowHeader.workflow_id 亦是 {ws}-{scan_id}
    （scan_manager 提交时由 worker 写入），与 fallback 一致。

    读不到（无 events.ndjson，如未启动 scan）才 fallback 算 {ws}-{scan_id}[-resume-N]
    （读 session.json resumeAttempts 算 N，对齐 scan_manager._resolve_workflow_id）。
    """
    wf = _read_workflow_id_from_ndjson(scan_dir)
    if wf:
        return _strip_ws_prefix(ws, wf)
    n = 0
    session_file = scan_dir / "session.json"
    if session_file.exists():
        try:
            data = json.loads(session_file.read_text("utf-8"))
            attempts = data.get("resumeAttempts") or []
            if isinstance(attempts, list):
                n = len(attempts)
        except (json.JSONDecodeError, OSError):
            n = 0
    base = f"{ws}-{scan_id}"
    raw = f"{base}-resume-{n}" if n > 0 else base
    return _strip_ws_prefix(ws, raw)


def _read_workflow_id_from_ndjson(scan_dir: Path) -> str | None:
    """读 events.ndjson 首行 WorkflowHeader.workflow_id（scan 启动即写，真实 temporal id）。

    WorkflowHeader 是 scan 首个 event（必为首行）；只读首个非空行即停，避免扫整个大 ndjson。
    损坏 / 首行非 WorkflowHeader -> None（调用方 fallback 算）。
    """
    ndjson = scan_dir / "events.ndjson"
    if not ndjson.exists():
        return None
    try:
        with ndjson.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                evt = json.loads(line)
                if isinstance(evt, dict) and evt.get("type") == "WorkflowHeader":
                    wf = evt.get("workflow_id")
                    if isinstance(wf, str) and wf:
                        return wf
                break  # 首个非空行非 WorkflowHeader -> 放弃（不扫全文件）
    except (json.JSONDecodeError, OSError):
        return None
    return None


# ws 级保留目录/文件（非 scan 产物）：T5 legacy 整体搬迁时留在 ws 根不动。
# indexer 列 ws 也据此区分 ws 级元数据 vs scan 产物。
WORKSPACE_META_FILENAME = "workspace.json"


def read_workspace_meta(ws_dir: Path) -> dict | None:
    """读 ws 元数据：workspace.json 优先，回退 legacy ws 根 session.json（无 workspace.json
    的旧 ws）。两者皆无 -> None（不是 ws）。供 indexer 列 ws 用。"""
    wf = ws_dir / WORKSPACE_META_FILENAME
    if wf.exists():
        try:
            data = json.loads(wf.read_text("utf-8"))
            if isinstance(data, dict):
                return data
        except (json.JSONDecodeError, OSError):
            pass
    sf = ws_dir / "session.json"
    if sf.exists():
        try:
            data = json.loads(sf.read_text("utf-8"))
            if isinstance(data, dict):
                return data
        except (json.JSONDecodeError, OSError):
            pass
    return None


def write_workspace_meta(ws_dir: Path, name: str, owner: str,
                         description: str | None = None,
                         created_at: str | None = None) -> None:
    """写 workspace.json = {name, created_at, owner, description?}。

    created_at 缺省取 now（ISO）；迁移场景可传入既有时间戳保真。
    """
    data = {
        "name": name,
        "created_at": created_at or datetime.now(timezone.utc).isoformat(),
        "owner": owner,
    }
    if description is not None:
        data["description"] = description
    (ws_dir / WORKSPACE_META_FILENAME).write_text(
        json.dumps(data, indent=2), encoding="utf-8")


@dataclass
class ScanSummary:
    """ws 内单个 scan 的摘要（GET /{ws}/scans 与 GET /{ws} 的 scans[] 共用）。

    含 indexer 旧 row 所需的全部 scan 级字段（vuln_counts/total_duration_ms/links/
    is_correlation），使 1 ws : N scans 后 ws 列表行能从 latest scan 聚合，兼容旧前端。

    组合扫描字段（2026-08-13 Task 1，spec §6.2/§9.2）：
    - combined：是否组合扫描（纯白盒/纯黑盒为 False/None）；
    - bb_phase：组合扫描黑盒阶段（precheck/pending/running/completed/failed/skipped）；
    - bb_reason：组合扫描失败/跳过原因；
    - progress_pct：收起态粗略进度（0-100，spec §9.2 三阶段加权），由 list_scans 构建。
    """
    scan_id: str
    scan_type: str
    status: str
    created_at: float | None
    completed_at: float | None
    vuln_count: int
    vuln_counts: dict
    total_cost_usd: float | None
    cost_currency: str | None
    total_duration_ms: float | None
    links: dict
    is_running: bool
    is_correlation: bool
    workflow_id: str  # temporal workflow 标识 {ws}-{scan_id}[-resume-N]，前端任务名展示
    # 组合扫描字段（默认值兼容纯白盒/纯黑盒：combined=False/None、bb_phase=None、progress_pct=0）。
    combined: bool | None = None
    bb_phase: str | None = None
    bb_reason: str | None = None
    progress_pct: float = 0.0
    # 版本化黑盒 run（spec §5.2）：任务级索引 bb_runs[] + latest_bb_run。纯白盒为 None/[]。
    bb_runs: list[dict] | None = None
    latest_bb_run: str | None = None
    # 仓库维度（概览重设计 2026-08-14）：repo=仓库名标签（_repo_label(repo_path)，与
    # scan_id 前缀同源）；repo_url=git 来源地址（session.web_url）。黑盒/旧 session 缺失
    # -> None，前端 '—' 兜底。
    repo: str | None = None
    repo_url: str | None = None
    # 分支快照（spec 2026-08-21 §4）：提交扫描时仓库当前 branch/commit（repo-snapshot.json）。
    # 切分支后报告靠此区分来源；存量报告/黑盒无快照 → None，前端不显示。
    repo_branch: str | None = None
    repo_commit: str | None = None
    # 跨仓关联血缘（C2，spec 2026-08-24）：session.corr_children 透传——
    # [{service, scan_id, reused, status?}]（提交时 web 写 SessionManager.update_session）。
    # 纯白盒/纯黑盒未写 → None（零回归）。
    corr_children: list[dict] | None = None
    # MR 增量扫描 refs（spec 2026-09-03 §6）：session.mr_base_ref/mr_head_ref 透传
    # （_submit_mr 提交时写）。列表行「MR」徽标 + base..head 标识与重跑预填用；
    # 非 MR 扫描未写 → None（零回归）。
    mr_base_ref: str | None = None
    mr_head_ref: str | None = None
    # merged 改道把手（2026-09-04）：session.mr_head_commit/mr_base_commit 透传——
    # 已合并 + 源分支已删的 MR 实际按 commit 对扫描，重跑预填沿用；未写 → None。
    mr_head_commit: str | None = None
    mr_base_commit: str | None = None

    def as_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "scan_type": self.scan_type,
            "status": self.status,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
            "vuln_count": self.vuln_count,
            "vuln_counts": self.vuln_counts,
            "total_cost_usd": self.total_cost_usd,
            "cost_currency": self.cost_currency,
            "total_duration_ms": self.total_duration_ms,
            "links": self.links,
            "is_running": self.is_running,
            "is_correlation": self.is_correlation,
            "workflow_id": self.workflow_id,
            "combined": self.combined,
            "bb_phase": self.bb_phase,
            "bb_reason": self.bb_reason,
            "progress_pct": self.progress_pct,
            "bb_runs": self.bb_runs,
            "latest_bb_run": self.latest_bb_run,
            "repo": self.repo,
            "repo_url": self.repo_url,
            "repo_branch": self.repo_branch,
            "repo_commit": self.repo_commit,
            "corr_children": self.corr_children,
            "mr_base_ref": self.mr_base_ref,
            "mr_head_ref": self.mr_head_ref,
            "mr_head_commit": self.mr_head_commit,
            "mr_base_commit": self.mr_base_commit,
        }


class ScanStore:
    """1 ws : N scans 存储：每个 scan 独立 scans/<scan_id>/ 子目录，兼容 legacy ws 根 scan。"""

    def __init__(self, workspaces_dir: Path) -> None:
        self._dir = Path(workspaces_dir)

    # ---- 创建 ----
    def create_scan(self, ws: str, web_url: str, repo_path: str,
                    scan_type: str = "whitebox",
                    lineage: str | None = None,
                    id_label: str | None = None) -> tuple[str, Path]:
        """在 ws 内建新 scan_id 目录 + session.json（不复位 resume；重扫=新 scan）。

        返回 (scan_id, scan_dir)。
        - whitebox/correlation: scan_id = <repo>-YYYYMMDD-HHMMSS，同秒碰撞 -2/-3。
          ``id_label`` 可把任务名前缀和 ``repo_path`` 展示名解耦（如跨仓主任务用
          ``cross-repo``，避免占用某个仓库现扫任务的命名空间）。
        - blackbox: scan_id = <wb_scan_id>~<N>（lineage=白盒 scan_id，N=该白盒已有黑盒序号，
          per-ws 单调）。lineage 仅 blackbox 用，白盒忽略。
        """
        ws_dir = self._dir / ws
        scans_dir = ws_dir / "scans"
        scan_id = self._gen_scan_id(
            scans_dir, repo_path, scan_type, lineage, id_label=id_label)
        # SessionManager(scans_dir) 复用 create_workspace：建 scans/<scan_id>/session.json。
        # core 零改动；幂等（session.json 已存在则不覆盖），但 scan_id 经碰撞规避保证新。
        mgr = SessionManager(scans_dir)
        scan_dir = mgr.create_workspace(
            web_url=web_url, repo_path=repo_path, name=scan_id, scan_type=scan_type)
        return scan_id, scan_dir

    # ---- 黑盒 run（嵌套 run-K 子目录，spec §4/§5.1）----
    def _next_blackbox_run_seq(self, wb_dir: Path) -> int:
        """per-task run 序号：扫 wb_dir/blackbox-runs/run-<N> 取 max+1（从 1 起）。

        非扫盘发现 run——仅用于序号分配（run 的存在性/列表以任务 session 的 bb_runs[]
        为准，spec §3 铁律）。序号并发由 ScanManager 的 _create_scan_lock 串行化。
        """
        runs_dir = blackbox_runs_dir(wb_dir)
        if not runs_dir.is_dir():
            return 1
        seqs: list[int] = []
        for d in runs_dir.iterdir():
            m = _RUN_ID_RE.match(d.name)
            if m and d.is_dir():
                seqs.append(int(m.group(1)))
        return (max(seqs) + 1) if seqs else 1

    def create_blackbox_run(self, ws: str, wb_scan_id: str, *,
                            auth_ref: dict | None = None,
                            reason: str | None = None) -> tuple[str, Path]:
        """在白盒任务根下分配 run-K 子目录（spec §4/§5.1）。

        - 建 blackbox-runs/run-K/ + run 级 session.json（status=pending, bb_phase=pending）。
        - 任务级 session 追加 bb_runs[] 条目 + 设 latest_bb_run + combined=True。
        返回 (run_id, run_dir)。序号并发由调用方经 _create_scan_lock 串行化。
        """
        wb_dir = self.get_scan_dir(ws, wb_scan_id)
        if wb_dir is None:
            raise ValueError(f"白盒任务不存在: {wb_scan_id}")
        k = self._next_blackbox_run_seq(wb_dir)
        run_id = f"run-{k}"
        run_dir = blackbox_run_dir(wb_dir, run_id)
        run_dir.mkdir(parents=True, exist_ok=True)
        # run 级 session（spec §5.3：bb_phase/bb_reason 下沉到此）
        SessionManager(blackbox_runs_dir(wb_dir)).update_session(run_dir, {
            "status": "pending", "bb_phase": "pending",
            "started_at": _now_local().isoformat(),
            "expected_agents": {}, "completed_agents": [], "host_mappings": {},
        })
        # 任务级索引：bb_runs[] + latest_bb_run + combined。auth_ref/reason 仅在提供时
        # 入条目（默认 run 条目只 {run_id, status}；profile_id 非空才记 auth_ref）。
        task_mgr = SessionManager(wb_dir.parent)
        task_data = task_mgr.get_session_data(wb_dir)
        runs = list(task_data.get("bb_runs") or [])
        entry: dict = {"run_id": run_id, "status": "pending"}
        if auth_ref:
            entry["auth_ref"] = auth_ref
        if reason:
            entry["reason"] = reason
        runs.append(entry)
        task_mgr.update_session(wb_dir, {
            "bb_runs": runs, "latest_bb_run": run_id, "combined": True})
        return run_id, run_dir

    def get_blackbox_run_dir(self, ws: str, wb_scan_id: str, run_id: str) -> Path | None:
        """定位 run 子目录（spec §7.1 #1）。run_id 须 ^run-\\d+$；不存在/越界 → None。"""
        if not run_id or not _RUN_ID_RE.match(run_id):
            return None
        wb_dir = self.get_scan_dir(ws, wb_scan_id)
        if wb_dir is None:
            return None
        run_dir = blackbox_run_dir(wb_dir, run_id)
        return run_dir if (run_dir / "session.json").exists() else None

    def list_blackbox_runs(self, ws: str, wb_scan_id: str) -> list[dict]:
        """从任务 session bb_runs[] 读 run 列表（非扫盘发现，spec §3 铁律）。"""
        wb_dir = self.get_scan_dir(ws, wb_scan_id)
        if wb_dir is None:
            return []
        data = SessionManager(wb_dir.parent).get_session_data(wb_dir)
        return list(data.get("bb_runs") or [])

    def update_blackbox_run(self, ws: str, wb_scan_id: str, run_id: str, *,
                            status: str | None = None, phase: str | None = None,
                            reason: str | None = None,
                            completed_at: str | None = None,
                            extra: dict | None = None) -> None:
        """更新 run 级 session（bb_phase/bb_reason/status/completed_at）+ 任务 bb_runs[]
        条目状态。不改 latest_bb_run（仅 create/delete 决定 latest）。run 不存在 → ValueError。
        extra：附加键值（如 bb_failure_point/detail）同时并入 run session 与 bb_runs[] 条目。
        """
        run_dir = self.get_blackbox_run_dir(ws, wb_scan_id, run_id)
        if run_dir is None:
            raise ValueError(f"run 不存在: {run_id}")
        patch: dict = {}
        if phase is not None:
            patch["bb_phase"] = phase
        if reason is not None:
            patch["bb_reason"] = reason
        if status is not None:
            patch["status"] = status
        if completed_at is not None:
            patch["completed_at"] = completed_at
        if extra:
            patch.update(extra)
        if patch:
            SessionManager(run_dir.parent).update_session(run_dir, patch)
        # 任务索引条目状态同步（不重算 latest）
        wb_dir = self.get_scan_dir(ws, wb_scan_id)
        task_mgr = SessionManager(wb_dir.parent)
        data = task_mgr.get_session_data(wb_dir)
        runs = list(data.get("bb_runs") or [])
        for r in runs:
            if r.get("run_id") == run_id:
                if status is not None:
                    r["status"] = status
                if completed_at is not None:
                    r["completed_at"] = completed_at
                if reason is not None:
                    r["reason"] = reason
                if extra:
                    r.update(extra)
        task_mgr.update_session(wb_dir, {"bb_runs": runs})

    def delete_blackbox_run(self, ws: str, wb_scan_id: str, run_id: str) -> bool:
        """删单 run：rmtree run 子目录 + combined/run-K + 移除 bb_runs[] 条目（spec §7.1 #4）。

        删的是 latest 则 latest_bb_run 回退到上一个 run。run 不存在 → False。
        """
        run_dir = self.get_blackbox_run_dir(ws, wb_scan_id, run_id)
        if run_dir is None:
            return False
        wb_dir = self.get_scan_dir(ws, wb_scan_id)
        shutil.rmtree(run_dir, ignore_errors=True)
        shutil.rmtree(combined_run_dir(wb_dir, run_id), ignore_errors=True)
        task_mgr = SessionManager(wb_dir.parent)
        data = task_mgr.get_session_data(wb_dir)
        runs = [r for r in (data.get("bb_runs") or []) if r.get("run_id") != run_id]
        latest = runs[-1]["run_id"] if runs else None
        patch: dict = {"bb_runs": runs, "latest_bb_run": latest}
        # 删光最后一个 run 时对称回滚 create_blackbox_run 设的组合标记（combined=True +
        # bb_phase/bb_reason）：否则留 combined=True + bb_runs=[] 的名存实亡态，旧前端仍按
        # 组合卡渲染展开按钮（spec §6.2 combined 语义＝任务下确有黑盒 run）。
        if not runs:
            patch.update({"combined": False, "bb_phase": None, "bb_reason": None})
        task_mgr.update_session(wb_dir, patch)
        return True

    def _gen_scan_id(self, scans_dir: Path, repo_path: str,
                     scan_type: str = "whitebox",
                     lineage: str | None = None,
                     id_label: str | None = None) -> str:
        """生成 scan_id。

        blackbox: <wb_scan_id>~<N>（整段白盒 scan_id 作血缘前缀 + per-ws 单调序号；
          lineage=wb_scan_id 必填）。序号并发由 ScanManager 的 create_scan lock 串行化，
          此处 while-exists 兜底防同序号目录竞态。
        whitebox/correlation（默认）: <repo>-YYYYMMDD-HHMMSS（仓库名前缀 + 本地时区紧凑秒级）；
          同秒碰撞 -2/-3。仓库名前缀让扫描目录一眼可辨（对齐 legacy NodeGoat_<ts> 可读性）。
          ``id_label`` 只改任务名前缀，不改 session.repo_path 的仓库展示语义。
        """
        if scan_type == "blackbox":
            if not lineage:
                raise ValueError("blackbox scan_id 需要 lineage（=白盒 scan_id）")
            n = self._next_blackbox_seq(scans_dir, lineage)
            scan_id = f"{lineage}~{n}"
            while (scans_dir / scan_id / "session.json").exists():
                n += 1
                scan_id = f"{lineage}~{n}"
            return scan_id
        base = f"{_repo_label(id_label or repo_path)}-{_now_local().strftime('%Y%m%d-%H%M%S')}"
        scan_id = base
        i = 2
        while (scans_dir / scan_id / "session.json").exists():
            scan_id = f"{base}-{i}"
            i += 1
        return scan_id

    def _next_blackbox_seq(self, scans_dir: Path, lineage: str) -> int:
        """数 scans_dir 下 {lineage}~<N> 已有黑盒序号，返回 max+1（从 1 起）。

        lineage 含 '-'，故用 re.escape；匹配锚定末尾（~<N>$，防 repo 名含 lineage
        前缀的误匹配）。scans_dir 不存在时返回 1（首个黑盒）。
        """
        pat = re.compile(re.escape(lineage) + r"~(\d+)$")
        existing: list[int] = []
        if scans_dir.is_dir():
            for entry in scans_dir.iterdir():
                m = pat.match(entry.name)
                if m:
                    existing.append(int(m.group(1)))
        return (max(existing) + 1) if existing else 1

    # ---- 列举（双源）----
    def _scan_entries(self, ws: str) -> list[tuple[str, Path]]:
        """返回 (scan_id, scan_dir) 双源列表，按 created_at 倒序。

        源 ① scans/<id>/session.json（新模型）；源 ② ws 根 session.json（legacy）。
        """
        ws_dir = self._dir / ws
        if not ws_dir.is_dir() or ws_dir.is_symlink():
            return []
        entries: list[tuple[str, Path, float]] = []  # (scan_id, scan_dir, created_at_unix)
        # 源 ①
        scans_dir = ws_dir / "scans"
        if scans_dir.is_dir():
            mgr = SessionManager(scans_dir)
            for scan_dir in mgr.list_workspaces():
                # legacy 平级 <wb>~N 黑盒（旧模型）隐藏：黑盒 run 已嵌套进 blackbox-runs/，
                # 残留的 ~N 作只读遗留不进顶层 scan 列表（spec §10）。
                if "~" in scan_dir.name and scan_dir.name.rsplit("~", 1)[-1].isdigit():
                    continue
                created = _to_unix(mgr.get_created_at(scan_dir)) or 0.0
                entries.append((scan_dir.name, scan_dir, created))
        # 源 ② legacy ws 根 session.json
        root_session = ws_dir / "session.json"
        if root_session.exists():
            legacy_id = self._legacy_scan_id(ws_dir)
            root_mgr = SessionManager(ws_dir.parent)
            created = _to_unix(root_mgr.get_created_at(ws_dir)) or 0.0
            entries.append((legacy_id, ws_dir, created))
        entries.sort(key=lambda e: e[2], reverse=True)
        return [(eid, edir) for eid, edir, _ in entries]

    def list_scans(self, ws: str) -> list[ScanSummary]:
        return [self._summarize(ws, scan_dir, scan_id)
                for scan_id, scan_dir in self._scan_entries(ws)]

    def _summarize(self, ws: str, scan_dir: Path, scan_id: str) -> ScanSummary:
        """聚合单个 scan 的摘要。SessionManager 读写只依赖 workspace_path，parent 作
        workspaces_dir 仅供 list/delete（此处不用）。"""
        mgr = SessionManager(scan_dir.parent)
        data = mgr.get_session_data(scan_dir)
        raw_status = _compute_status(scan_dir, mgr.get_status(scan_dir))
        metrics = data.get("metrics", {}) if isinstance(data, dict) else {}
        try:
            vuln_counts = get_workspace_vuln_counts(scan_dir)
        except Exception:
            vuln_counts = {}
        scan_type = mgr.get_scan_type(scan_dir)
        links = data.get("links", {}) if isinstance(data, dict) else {}
        # 组合扫描字段（spec §6.2）：从 session.json 读 combined/bb_phase/bb_reason。
        combined = data.get("combined") if isinstance(data, dict) else None
        bb_runs = data.get("bb_runs") if isinstance(data, dict) else None
        latest_bb_run = data.get("latest_bb_run") if isinstance(data, dict) else None
        # 跨仓关联血缘（C2）：session.corr_children 透传（读法对齐 bb_runs；未写 → None）。
        corr_children = data.get("corr_children") if isinstance(data, dict) else None
        # 版本化 run（spec §5.2/§5.3）：bb_phase/bb_reason/completed_agents 下沉到 run 级
        # session；任务级进度经 merge_latest_run_view 合并白盒(任务 session
        # completed_agents) + latest run completed_agents，bb_phase/bb_reason 取自 latest
        # run（与 api/scans._scan_detail 同一视图，list/detail 口径一致）。
        bb_phase, bb_reason, progress_data = merge_latest_run_view(scan_dir, data)
        status = effective_scan_status(raw_status, combined, bb_phase)
        progress_pct = _compute_progress_pct(status, combined, bb_phase, progress_data)
        # 组合扫描用时走墙钟口径（含黑盒段+预验证+间隙；metrics 只含白盒，见
        # combined_wallclock_ms docstring）。纯白盒/纯黑盒仍读 metrics。
        duration_ms = metrics.get("total_duration_ms")
        if _is_combined_scan(data, combined):
            duration_ms = combined_wallclock_ms(
                data, _to_unix(mgr.get_created_at(scan_dir)),
                _to_unix(mgr.get_completed_at(scan_dir)))
        return ScanSummary(
            scan_id=scan_id,
            scan_type=scan_type,
            status=status,
            created_at=_to_unix(mgr.get_created_at(scan_dir)),
            completed_at=_to_unix(mgr.get_completed_at(scan_dir)),
            vuln_count=sum(vuln_counts.values()) if vuln_counts else 0,
            vuln_counts=vuln_counts,
            total_cost_usd=metrics.get("total_cost_usd"),
            cost_currency=metrics.get("cost_currency"),
            total_duration_ms=duration_ms,
            links=links,
            is_running=(status == "running"),
            is_correlation=(scan_type == "correlation"),
            workflow_id=resolve_workflow_id(ws, scan_dir, scan_id),
            combined=bool(combined) if combined is not None else None,
            bb_phase=bb_phase,
            bb_reason=bb_reason,
            progress_pct=progress_pct,
            bb_runs=bb_runs,
            latest_bb_run=latest_bb_run,
            repo=(_repo_label(rp) or None) if (rp := (data.get("repo_path") if isinstance(data, dict) else None)) else None,
            repo_url=mgr.get_web_url(scan_dir),
            # 分支快照（spec 2026-08-21 §4）：存量报告/黑盒无快照 → None
            **_repo_snapshot_fields(scan_dir),
            corr_children=corr_children,
            # MR refs（spec 2026-09-03 §6）：非 MR 扫描未写 → None（读法对齐 corr_children）
            mr_base_ref=data.get("mr_base_ref") if isinstance(data, dict) else None,
            mr_head_ref=data.get("mr_head_ref") if isinstance(data, dict) else None,
            # merged 改道把手（2026-09-04）：读法同上
            mr_head_commit=data.get("mr_head_commit") if isinstance(data, dict) else None,
            mr_base_commit=data.get("mr_base_commit") if isinstance(data, dict) else None,
        )

    def _legacy_scan_id(self, ws_dir: Path) -> str:
        """legacy ws 根 scan 的 scan_id：从 created_at 派生 YYYYMMDD-HHMMSS（本地时区），
        缺失/异常回退 ws 目录名。get_scan_dir/list_scans 双源定位用同一派生口径。"""
        mgr = SessionManager(ws_dir.parent)
        ts = _to_unix(mgr.get_created_at(ws_dir))
        if ts:
            return datetime.fromtimestamp(ts).strftime("%Y%m%d-%H%M%S")
        return ws_dir.name

    # ---- 定位 ----
    def get_scan_dir(self, ws: str, scan_id: str) -> Path | None:
        """按 scan_id 定位 scan 目录（双源）。路径校验：scan_id 不得含分隔符/越界。"""
        if not scan_id or "/" in scan_id or "\\" in scan_id or ".." in scan_id:
            return None
        # 源 ① scans/<scan_id>/
        scan_dir = self._dir / ws / "scans" / scan_id
        if (scan_dir / "session.json").exists():
            return scan_dir
        # 源 ② legacy ws 根（派生 legacy_id 匹配）
        ws_dir = self._dir / ws
        if ws_dir.is_symlink():
            return None
        if (ws_dir / "session.json").exists() and self._legacy_scan_id(ws_dir) == scan_id:
            return ws_dir
        return None

    # ws 级保留项（非 scan 产物）：删 legacy 根 scan 时保留，勿 rmtree 整个 ws 根。
    # workspace.json=config.yaml=ws 级元数据；scans=其他新 scan 子目录；repos=P2 仓库隔离目录。
    _WS_LEVEL_KEEP = frozenset({"workspace.json", "config.yaml", "scans", "repos"})

    def delete_scan(self, ws: str, scan_id: str) -> bool:
        """删除单个 scan（删 scan 不删 ws，spec §5.1 DELETE 真删）。

        源① scans/<scan_id>/（新模型）：rmtree 整个独立 scan 目录（含产物）。
        源② legacy ws 根 scan（迁移残留）：ws 根同时是 workspace 容器，不能 rmtree 整目录——
        仅删 scan 产物，保留 ws 级（_WS_LEVEL_KEEP）。

        scan 不存在 / 路径越界（..///） -> False（端点据此返 404）；成功 -> True。
        复用 get_scan_dir 的路径校验 + 双源定位，删除范围与定位口径一致。
        """
        scan_dir = self.get_scan_dir(ws, scan_id)
        if scan_dir is None:
            return False
        scans_root = self._dir / ws / "scans"
        if scan_dir.parent == scans_root:
            # 源①：独立 scan 子目录，整删（含 session.json/events.ndjson/deliverables/agents/...）。
            shutil.rmtree(scan_dir)
        else:
            # 源② legacy ws 根：删 scan 产物，保留 ws 级元数据 / 其他 scan / repo。
            # 启动收纳机制已退役（2026-08-27，随 __legacy__ 概念移除），此处为历史形态
            # 的读兼容兜底。
            for entry in scan_dir.iterdir():
                if entry.name in self._WS_LEVEL_KEEP:
                    continue
                if entry.is_dir() and not entry.is_symlink():
                    shutil.rmtree(entry)
                else:
                    entry.unlink()
        return True

    def latest_scan(self, ws: str) -> Path | None:
        """ws 内「最新」scan 目录（spec §5.2 shim 用）：active 优先，否则 max created_at。

        active 优先 = 找一个 status=running（heartbeat fresh，worker 在跑）的 scan；
        多个 running 取最新（_scan_entries 已按 created_at 倒序，首个 running 即最新 running）。
        无 running -> 取最新（entries[0]）。无 scan -> None。

        shim DELETE /api/scan/{ws}（cancel latest/active）依赖此正确性：同 ws 多 scan 时
        应 cancel 正在跑的那个，而非更新的已完成 scan。
        """
        entries = self._scan_entries(ws)
        if not entries:
            return None
        for _scan_id, scan_dir in entries:
            mgr = SessionManager(scan_dir.parent)
            if _compute_status(scan_dir, mgr.get_status(scan_dir)) == "running":
                return scan_dir
        return entries[0][1]
