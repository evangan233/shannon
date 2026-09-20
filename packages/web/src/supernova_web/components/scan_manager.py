from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import aiofiles

_log = logging.getLogger(__name__)

from temporalio.client import Client

from supernova_core.models.multi_repo_config import MultiRepoConfig
from supernova_core.services.temporal_infra import WEB_TASK_QUEUE_WHITEBOX
from supernova_core.runtime.workflow_timeout import scan_budget
from supernova_core.session import SessionManager
from supernova_core.utils.paths import (
    INTERMEDIATE_SUBDIR, WHITEBOX_SUBDIR, blackbox_dir, blackbox_run_dir,
    combined_run_dir, deliverables_dir_for_workspace, whitebox_dir)
from supernova_multi.correlation_event_writer import CorrelationEventWriter
from supernova_multi.orchestrator import plan_repo_scans
from supernova_whitebox.pipeline.workflows import WhiteboxScanWorkflow, MrScanWorkflow
from supernova_whitebox.pipeline.shared import PipelineInput
from supernova_whitebox.pipeline.whitebox_resume import WhiteboxResumeStateBuilder
from supernova_web.models import ScanRequest
from .host_profile_store import (
    HostMapping,
    HostProfileRefreshEmpty,
    fetch_and_parse_hosts,
)
from .repo_manager import _resolve_repo_dir, _validate_ws_segment, resolve_linked_repo_path
from .scan_liveness import is_scan_recently_active
from .scan_store import (
    ScanStore,
    _read_workflow_id_from_ndjson,
    effective_scan_status,
    is_post_hoc_runs_task,
    merge_latest_run_view,
    write_repo_snapshot,
)
from .workspaces_indexer import _compute_status


class TemporalUnavailable(Exception):
    pass


class ScanRunning(Exception):
    """删除 running scan 被拒（应先 cancel 再删，对齐 delete_workspace 删 ws 前要求无 running scan）。

    删在跑 workflow 的目录会致 _watch describe 不存在的 workflow（_handles 降级为簿记后已无闸门影响）。
    """
    def __init__(self, scan_id: str) -> None:
        self.scan_id = scan_id
        super().__init__(f"扫描正在运行，请先取消再删除：{scan_id}")


# run 级 session status 终态集合：非此集合（pending/running/precheck/None）= 在跑/待跑，
# 删除被拒（ScanRunning）。与 scan 级 delete 的 running 口径对齐。
_RUN_TERMINAL_STATUSES = frozenset({
    "completed", "done", "failed", "skipped", "cancelled", "crashed", "killed"})

# terminate 保险丝宽限（spec 2026-08-28-temporal-native-cancel-design 修 E2）：cancel 后
# 心跳路径预期 ≤~40s 全停；仍 RUNNING 超 60s = 取消链断（activity 不心跳回归等）→ 升级
# terminate（对齐 host 侧 core/runtime/scan_runner.py _do_cancel 的 grace→terminate 语义）。
_CANCEL_FUSE_DELAY = 60.0


class AuthValidationPending(Exception):
    """认证验证 workflow 仍在运行，结果未就绪（块2：get_result 非阻塞查询）。

    verify-status 端点 catch 后转 503，前端继续轮询——修轮询超时误判：workflow 实测跑 88–153s
    而前端轮询上限 120s，阻塞 result() 致 HTTP 挂死 → 成功被显示成失败。改 describe() 非阻塞：
    RUNNING → 抛本异常（秒级返回）；终态 → result()（已就绪不阻塞）。对前端 "running" 与
    "Temporal down" 都是 "继续轮询"，故端点统一 503 不细分。
    """


# resume 放行的状态：已停未完成（有部分进度可续）。spec 2026-08-27-web-resume-
# breakpoint §4.1 扩集——failed（最常见中断出口，Temporal 已 FAILED 终态无并发
# 风险）/ cancelled / killed 全部放行（后三者先 heartbeat 判活防撞车，见 resume）。
# completed（已完成）/ running（在跑，resume 会重复提交）-> 不可 resume，用重扫
# （POST /api/scan 起新 scan_id，旧记录保留）。
_RESUMABLE_STATUSES = frozenset(
    {"interrupted", "crashed", "failed", "cancelled", "killed"})

# 扫完即删状态门：running / queued 与 heartbeat stale 但尚未确认关闭的 reconnecting
# 都可能仍被 Temporal worker 使用仓库；只有明确业务终态才允许 sweep。
_SWEEP_ACTIVE_STATUSES = frozenset({"running", "queued", "reconnecting"})


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _auth_probe_timeout_seconds(env_overrides: dict[str, str] | None) -> int:
    """authcheck probe 窗口（秒）：SUPERNOVA_AUTH_VALIDATION_TIMEOUT_SECONDS。

    ws env 段优先（SCAN_ENV_KEYS 白名单内）→ web 进程 env → 默认 600（=原 10min，
    不改变现有行为）。容量铁律（CLAUDE.md §1）同型：authcheck 3×10min 全超时白烧
    30 分钟（NodeGoat-20260827-152204），窗口须可按 provider 实测重估。sandbox 禁
    os.getenv（RestrictedWorkflowAccessError），env 在此（sandbox 外）解析后经
    BlackboxAuthValidationInput.probe_timeout_seconds 传入 workflow。
    """
    raw = (env_overrides or {}).get("SUPERNOVA_AUTH_VALIDATION_TIMEOUT_SECONDS")
    if raw is None:
        raw = os.environ.get("SUPERNOVA_AUTH_VALIDATION_TIMEOUT_SECONDS")
    try:
        value = int(str(raw).strip())
        return value if value > 0 else 600
    except (TypeError, ValueError):
        return 600


def _find_queue_files(dlv: Path) -> list[Path]:
    """收集 deliverables/ 下的 *_exploitation_queue.json（跨仓关联 C2 复用校验用）。

    三处 glob 与 multi orchestrator 的 queue 收集（orchestrator.py 三段 dict 合并）完全
    同序：whitebox/intermediate/（tiering 新结构）→ whitebox/（老结构）→ deliverables
    根（更老结构）；同名仅补白（intermediate 优先）。glob 不递归，三处合并去重。
    """
    queue_files: dict[str, Path] = {}
    for q in (dlv / WHITEBOX_SUBDIR / INTERMEDIATE_SUBDIR).glob("*_exploitation_queue.json"):
        queue_files[q.name] = q
    for q in (dlv / WHITEBOX_SUBDIR).glob("*_exploitation_queue.json"):
        queue_files.setdefault(q.name, q)
    for q in dlv.glob("*_exploitation_queue.json"):
        queue_files.setdefault(q.name, q)
    return list(queue_files.values())


def _dump_multi_repo_yaml(config: MultiRepoConfig, path: Path) -> None:
    """MultiRepoConfig 落盘（跨仓关联 C3）：out_workspace 覆写后 dump 成 worker 侧
    parse_multi_repo_config 可直读的 yaml（关联 workflow / 漂移检测读此文件）。

    by_alias 保 relations 的 from 键（Relation.from_ alias "from"），round-trip 已验：
    dump → parse 回同构 config（含 out_workspace 覆写值）。
    """
    import yaml
    path.write_text(
        yaml.safe_dump(config.model_dump(by_alias=True), allow_unicode=True),
        encoding="utf-8")


# ── final-fix ①（Critical）：表单 correlation yaml 缺 correlation 段的兜底注入 ──
# 前端 formToYaml（locked，勿改）只产 repos/relations，而 MultiRepoConfig.correlation
# 必填（out_workspace 无默认）→ 表单提交的关联扫描恒 422。web 提交通道在两处注入
# 默认段（temp 文件 / start 解析），用户存档（save_as 写入的 config_store 内容、
# multi-configs API）保持原文 verbatim 不注入；core 的 parse_multi_repo_config 与
# MultiRepoConfig 零改动（CLI 零回归）。占位 out_workspace 永不达 worker——C3 落盘
# 前必被主行 scan_id 覆写（见 start() correlation 分支 ④）。
_CORR_OUT_WS_PLACEHOLDER = "web-pending"


def _corr_raw_with_default_section(raw: Any) -> Any:
    """dict 顶层且 correlation 缺失（或为 dict）时注入默认 out_workspace 占位。

    其余形状（顶层非 dict / correlation 非 dict / yaml 语法错）原样返回——交给
    MultiRepoConfig.model_validate 报真 422，不在此猜测修复。"""
    if not isinstance(raw, dict):
        return raw
    corr = raw.get("correlation")
    if corr is None:
        corr = raw["correlation"] = {}
    if not isinstance(corr, dict):
        return raw  # 形状错（如 list/str）→ 校验报错
    corr.setdefault("out_workspace", _CORR_OUT_WS_PLACEHOLDER)
    return raw


def _corr_yaml_text_with_default_section(text: str) -> str:
    """文本版注入（_resolve_correlation_yaml 的 config_content → write_temp 前用）：
    store 的 validate 会跑 parse_multi_repo_config，无段内容在此就 422——这正是
    表单提交 422 的首发现场，须在写 temp 前注入（temp 非用户面，注入无损）。"""
    import yaml
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError:
        return text  # 语法错误留给 store 校验报真错
    if not isinstance(raw, dict):
        return text  # 形状错误（顶层 list/标量）留给校验报
    return yaml.safe_dump(
        _corr_raw_with_default_section(raw), allow_unicode=True, sort_keys=False)


def _parse_corr_config_with_defaults(path: Path) -> MultiRepoConfig:
    """web 提交通道的宽容解析（start() correlation 分支用，替代裸
    parse_multi_repo_config）：缺 correlation 段注入默认占位后再 model_validate。
    config_content 路径已在写 temp 时注入（此处 no-op），config_name 存档缺段在此
    兜底；存档文件本身不改（verbatim）。"""
    import yaml
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return MultiRepoConfig.model_validate(_corr_raw_with_default_section(raw))


class ScanManager:
    """C1 Phase B + T3: web 提交端改为 temporal workflow 提交者(不再 fork CLI 子进程).

    T3: 1 ws : N scans -- _handles/_tasks/_active_reqs key 由 ws 改 (ws, scan_id)；
    ScanStore.create_scan 建 scans/<scan_id>/session.json（ws 根不再写 session.json）；
    event_file=scan_dir/events.ndjson（worker 据其 parent 推导产物目录，零改动）。
    同 ws 多 scan 不互斥（key 不同）；并发权威 = worker 全局扫描闸门（spec 2026-09-08-worker-scan-gate）。
    start -> Client.connect + start_workflow; _watch -> tail events.ndjson 直到 scan_end;
    cancel(ws, scan_id) 精确取消（scan_id 强制；旧 cancel(ws) shim + DELETE /api/scan/{ws} 已于 e1406473 移除）;
    resume(ws, scan_id) 续跑 interrupted/crashed scan（completed/failed/cancelled/running 拒）。active_pids 返空(判活靠 heartbeat mtime)。
    """

    def __init__(self, workspaces_dir: Path, repos_dir: Path, config_store: Any,
                 scan_timeout: float = 0.0,
                 ws_config_store: Any = None,
                 auth_profile_store: Any = None,
                 host_profile_store: Any = None,
                 repo_manager: Any = None) -> None:
        self._workspaces_dir = Path(workspaces_dir)
        self._repos_dir = Path(repos_dir)
        self._config_store = config_store
        self._scan_timeout = scan_timeout
        # 扫完即删（2026-09-10）：sweep 委托 repo_manager.delete（私有克隆 rmtree）。
        # None=旧测试/CLI 兜底构造（sweep no-op，不影响既有流程）。
        self._repo_manager = repo_manager
        # T3: _handles/_tasks/_active_reqs key = (ws, scan_id)（同 ws 多 scan 不互斥）。
        self._handles: dict[tuple[str, str], Any] = {}
        self._tasks: dict[tuple[str, str], asyncio.Task] = {}
        # terminate 保险丝 tasks（修 E2）：done 后自动 discard，防 GC。
        self._cancel_fuse_tasks: set[asyncio.Task] = set()
        # 进行中的 scan 请求快照（(ws, scan_id) -> ScanRequest），供 active_repo_sources() 判引用
        self._active_reqs: dict[tuple[str, str], ScanRequest] = {}
        # P3c 阶段 2：per-ws 配置解析（None=CLI/旧测试兜底，走全局 env）
        self._ws_config_store = ws_config_store
        # 认证档案库（Task 4）：认证管理页"测试登录"探针读写 verify_status 的 store;
        # None=旧测试/CLI 兜底（不调 start_auth_validation 即不影响既有流程）。
        self._auth_profile_store = auth_profile_store
        # HOST 档案库（Task 11 会用）：domain→IP 映射注入扫描前 resolve_host。
        # None=旧测试/CLI 兜底（不影响既有流程）；T10 仅声明参数让 app 能 boot。
        self.host_profile_store = host_profile_store
        # T3: ScanStore 复用 core SessionManager 做 scan 读写（core 零改动）。
        self._store = ScanStore(self._workspaces_dir)
        # 串行化黑盒 create_scan，保证 <wb>~<N> 序号分配原子（防并发同白盒争同序号）。
        self._create_scan_lock = asyncio.Lock()
        # 组合扫描接力编排 task（spec §7.2）：key=(ws, scan_id) → asyncio.Task。
        # start 组合分支 asyncio.create_task(_combined_orchestrator) 登记；orchestrator
        # finally 自 pop。用于 cancel/delete 时取消接力 + 诊断（fire-and-forget，不阻塞 start）。
        self._orchestrator_tasks: dict[tuple[str, str], asyncio.Task] = {}
        # 组合扫描崩溃恢复 task（spec §7.5，Task 5）：key=(ws, scan_id) → asyncio.Task。
        # orphan_reconciler 经 _kick_combined_reconcile fire-and-forget 登记；恢复完成
        # （或异常）后 finally 自 pop。防止 re-entry 重复 fire（幂等）+ 诊断。
        self._reconcile_tasks: dict[tuple[str, str], asyncio.Task] = {}
    def active_pids(self) -> dict[str, int]:
        # C1: web 无本机 pid(扫描跑在 worker 容器). 判活完全靠 scan_liveness.is_scan_recently_active
        # (heartbeat mtime). orphan_reconciler 的 is_scan_recently_active 门兜底(不误杀活 workflow).
        return {}

    def active_repo_sources(self) -> set[tuple[str, str]]:
        """当前正在跑的 scan 引用的 (ws, repo 名) 集合（DELETE /repos 判引用用）。

        T3: _active_reqs key 改 (ws, scan_id) 元组，值仍含 req.workspace -- 派生 (ws, name)
        不受 key 变化影响（ws 维度仍参与引用判定，防 ws-A 的 scan 误锁 ws-B 的同名 repo）。
        """
        out: set[tuple[str, str]] = set()
        for (ws, _scan_id), req in self._active_reqs.items():
            if req.source is not None and req.source.kind == "repo":
                out.add((ws, req.source.value))
        return out

    # ---- 扫完即删（2026-09-10）：仓库级 sweep ----

    async def sweep_delete_flagged_repos(self, ws: str) -> list[str]:
        """对 ws 做仓库级 sweep，删除「扫描已全部完毕」的带标志仓库，返删除名单。

        删除条件（合取，对应「任何终态都删 + 不误删共享仓」）：
          - 该 repo 存在 ≥1 个 session 带 ``delete_repo_on_finish`` 的扫描行；
          - 该 repo 的**所有**引用扫描（source_repo 命中，含不带标志的）都已完毕
            （events.ndjson 有 scan_end，或 effective status 非活跃——组合扫描看
            黑盒 run 阶段，与列表/详情同口径）；
          - (ws, repo) 不在本进程活跃引用（active_repo_sources，提交冷启动窗口带）；
          - 非 linked 仓（linked 完全不处理：不删源目录、不解引用）。
        满足 → repo_manager.delete()（私有克隆 rmtree + 空组目录清理）。幂等 best-effort：
        仓库已删/正忙/单行读失败 → 跳过不抛。repo_manager 未注入（旧测试/CLI）→ no-op。
        """
        if self._repo_manager is None:
            return []
        ws_dir = self._workspaces_dir / ws
        if not ws_dir.is_dir() or ws_dir.is_symlink():
            return []
        by_repo: dict[str, list[tuple[Path, dict]]] = {}
        for _scan_id, scan_dir in self._store._scan_entries(ws):
            try:
                data = SessionManager(scan_dir.parent).get_session_data(scan_dir)
            except Exception:  # noqa: BLE001 - 单行读失败不阻塞整个 sweep
                continue
            repo = data.get("source_repo") if isinstance(data, dict) else None
            if repo:
                by_repo.setdefault(repo, []).append((scan_dir, data))
        active = self.active_repo_sources()
        deleted: list[str] = []
        for repo, entries in by_repo.items():
            if not any(d.get("delete_repo_on_finish") for _, d in entries):
                continue
            if (ws, repo) in active:
                continue
            if any(self._scan_still_needs_repo(sd, d) for sd, d in entries):
                continue
            if not (ws_dir / "repos" / repo).is_dir():
                continue  # 仓库已不在（手动删过）；linked 仓不在 repos/ 下也走此跳过
            if self._repo_manager._is_linked(ws, repo):
                continue  # linked 仓不处理（源目录共享，可能他 ws 仍用）
            try:
                await self._repo_manager.delete(ws, repo)
            except (ValueError, OSError) as exc:
                _log.warning("扫完即删跳过 %s/%s: %s", ws, repo, exc)
                continue
            deleted.append(repo)
            _log.info("扫完即删：%s/%s 已删除（引用扫描均已终态）", ws, repo)
        return deleted

    def _scan_still_needs_repo(self, scan_dir: Path, data: dict) -> bool:
        """该扫描是否仍需要仓库文件（sweep 保护判定）。

        events.ndjson 已有 scan_end = 已收尾（completed/failed/cancelled/… 全算
        「完毕」）；无 scan_end 时看 effective status：组合扫描白盒段完成但黑盒 run
        在跑（merge_latest_run_view + effective_scan_status）仍是 running，queued =
        worker 闸门排队中——两者保护仓库，其余（含 interrupted：心跳死的孤儿）放行。
        """
        if self._has_scan_end(scan_dir / "events.ndjson"):
            return False
        raw = _compute_status(
            scan_dir, SessionManager(scan_dir.parent).get_status(scan_dir))
        combined = data.get("combined") if isinstance(data, dict) else None
        bb_phase, _bb_reason, _merged = merge_latest_run_view(scan_dir, data)
        status = effective_scan_status(
            raw, combined, bb_phase,
            post_hoc_runs=is_post_hoc_runs_task(data)
            if isinstance(data, dict) else False)
        return status in _SWEEP_ACTIVE_STATUSES

    async def sweep_all_workspaces(self) -> int:
        """启动兜底：对全部 ws 各跑一次 sweep（_watch 随上次进程退出丢失的补删）。

        返回删除仓库总数。单 ws 失败记日志继续（不阻塞其余 ws 与启动流程）。
        """
        if self._repo_manager is None or not self._workspaces_dir.is_dir():
            return 0
        n = 0
        for ws_dir in self._workspaces_dir.iterdir():
            if not ws_dir.is_dir() or ws_dir.is_symlink():
                continue
            try:
                n += len(await self.sweep_delete_flagged_repos(ws_dir.name))
            except Exception:  # noqa: BLE001
                _log.exception("扫完即删 sweep 失败: ws=%s", ws_dir.name)
        return n

    async def _sweep_ws_quiet(self, ws: str) -> None:
        """best-effort sweep（各触发点统一入口）：失败仅记日志，绝不影响宿主流程。"""
        try:
            await self.sweep_delete_flagged_repos(ws)
        except Exception:  # noqa: BLE001
            _log.exception("扫完即删 sweep 失败: ws=%s", ws)

    async def reap_zombies(self) -> None:
        """lifespan 启动时扫无主子进程。C1 后 web 无子进程 -> no-op."""
        return None

    def reap_stale_probes(self) -> int:
        """启动期清残留 probe 的明文凭据(worker/web 异常退出滞留的 scan-config.yaml)。

        收窄(2026-08-17):只删明文 scan-config.yaml,保留 events.ndjson/auth-state.json 供
        verify-log 回看/诊断(对齐 get_auth_validation_result finally 的收窄清理——整目录 rmtree
        会销毁卡 running 案例的过程证据);清空后的空目录顺手移除。running cred 的 probe 跳过:
        重启时验证仍在跑(batch 后续 cred 尚未跑),删其 scan-config 会让下一 cred activity
        读不到配置。返清理文件数。
        """
        protected = self._running_probe_dirs()
        n = 0
        if not self._workspaces_dir.is_dir():
            return 0
        for ws_dir in self._workspaces_dir.iterdir():
            probes = ws_dir / "auth-probes"
            if not probes.is_dir():
                continue
            for probe in probes.iterdir():
                if not probe.is_dir() or probe.resolve() in protected:
                    continue
                cfg = probe / "scan-config.yaml"
                if cfg.exists():
                    try:
                        cfg.unlink()
                        n += 1
                    except OSError:
                        pass
                try:
                    probe.rmdir()  # 仅清空后成(留 events 的 probe 保回看)
                except OSError:
                    pass
            try:
                probes.rmdir()
            except OSError:
                pass
        return n

    async def start(self, req: ScanRequest) -> tuple[str, str]:
        """T3: 提交新 scan -> (ws, scan_id)。

        HOST source is resolved before ``ScanStore.create_scan`` so invalid or empty
        mappings cannot leave a ghost scan.  Once the directory exists, the immutable
        ``host_config`` snapshot is written before auth config/workflow submission.
        """
        await self._check_temporal()
        # 并发闸门已下沉 worker（spec 2026-09-08-worker-scan-gate §7）：web 不再
        # 拒绝，超出容量的扫描在 worker 闸门排队（temporal workflow RUNNING）。
        target, yaml_path = await self._resolve_inputs(req)
        # C3（跨仓关联）：主行落请求 ws——旧 _resolve_out_workspace（从 yaml 推 ws）已随
        # D7 清理删除：out_workspace 由下方 correlation 分支覆写为主行 scan_id 落盘 yaml。
        ws = req.workspace

        # HOST only belongs to a blackbox stage.  Resolve it before creating a scan
        # directory; pure whitebox (no url) intentionally ignores legacy HOST fields.
        # correlation + gateway url 有段③黑盒验证（C3 fix ②）——同组合模式解析 HOST，
        # 供 _run_blackbox_phase 从主行 session 读映射；无 url 的 correlation 忽略。
        host_config = None
        if req.type == "blackbox" or (
                (req.type == "whitebox" or req.type == "correlation") and req.url):
            host_config = await self._resolve_host_config(req, ws)

        ws_dir = self._workspaces_dir / ws
        ws_dir.mkdir(parents=True, exist_ok=True)

        # ── correlation 前置解析（C3，spec 2026-08-24 §5.3 步骤 1-2）────────────
        # yaml 解析 + 复用子仓校验 + 现扫子仓 repo 解析，全部在任何 scan 行落盘前完成：
        # 任一失败 raise ValueError（API 层转 422），不留 ghost 主行 / 部分提交的子仓
        # workflow。corr_repo_paths 由 _validate_reused_children 填复用子仓 scan_dir，
        # 下方现扫子仓补齐自己的 c_dir 后整体传 _submit_correlation。
        corr_config: MultiRepoConfig | None = None
        corr_repo_paths: dict[str, Path] = {}
        corr_repo_dirs: dict[str, str] = {}
        # 扫完即删（2026-09-10）：svc → ws 内仓库名（此刻 plan.repo_path 仍是名字；
        # 下方 final-fix ② 会把 spec.path 回填成绝对路径，子仓循环里名字已丢）。
        corr_repo_names: dict[str, str] = {}
        if req.type == "correlation":
            # final-fix ①：宽容解析（缺 correlation 段注入默认占位，详见模块级
            # _parse_corr_config_with_defaults 注释）；后续校验/规划消费同一对象。
            corr_config = _parse_corr_config_with_defaults(yaml_path)
            corr_repo_paths = self._validate_reused_children(ws, corr_config)
            for plan in plan_repo_scans(corr_config):
                if not plan.reuse:
                    # path 语义 = ws 内仓库名（web 提交通道；_resolve_repo_path 做
                    # linked 仓优先 + 防遍历 + state=ready 校验，同白盒 source=repo）。
                    corr_repo_names[plan.service] = plan.repo_path or plan.service
                    corr_repo_dirs[plan.service] = self._resolve_repo_path(
                        ws, plan.repo_path or "")

        lineage: str | None = None
        if req.type == "blackbox":
            if not req.reuse_whitebox_scan_id:
                raise ValueError("blackbox 扫描必须复用白盒结果（reuse_whitebox_scan_id）")
            if self._store.get_scan_dir(ws, req.reuse_whitebox_scan_id) is None:
                raise ValueError(f"要复用的白盒扫描不存在: {req.reuse_whitebox_scan_id}")
            lineage = req.reuse_whitebox_scan_id

        if req.type == "blackbox":
            async with self._create_scan_lock:
                scan_id, scan_dir = self._store.create_scan(
                    ws, req.url or "", target or "", req.type, lineage=lineage)
        elif req.type == "correlation":
            # 主行（C3）：repo 保留 entrypoint 作展示锚；但任务名显式用 cross-repo。
            # 若主行也用 <entrypoint>-<ts>，同一秒创建的子仓 <entrypoint>-<ts> 会被迫
            # 变成 -2，用户看到的“主任务”就冒充了仓库扫描名。
            entry_svc = next((svc for svc, spec in corr_config.repos.items()
                              if spec.role == "entrypoint"), "")
            scan_id, scan_dir = self._store.create_scan(
                ws, req.url or "", entry_svc, "correlation", id_label="cross-repo")
        else:
            scan_id, scan_dir = self._store.create_scan(
                ws, req.url or "", target or "", req.type)
        self._mark_owner(scan_dir, "web")
        # 扫完即删（2026-09-10）：勾选标志随扫描行落盘（whitebox/mr 单仓；blackbox
        # 禁 source 天然不涉及；correlation 主行无 source、由子仓循环逐仓传播给新建
        # 行）。提交前落盘——precheck 失败等提前终态路径的行同样可被 sweep 到。
        if req.delete_repo_on_finish and req.source is not None \
                and req.source.kind == "repo":
            SessionManager(scan_dir.parent).update_session(
                scan_dir, {"delete_repo_on_finish": True})
        # 分支快照（spec 2026-08-21 §4）：repo 来源提交时快照仓库当前 branch/commit
        # 进 scan_dir——切分支后报告靠此区分来源（scan_id 只含仓库名+时间戳）。
        self._maybe_write_repo_snapshot(req, target, scan_dir)
        event_file = scan_dir / "events.ndjson"
        scan_key = (ws, scan_id)
        self._active_reqs[scan_key] = req

        try:
            # Snapshot before auth config and before Temporal submission.
            if host_config is not None:
                host_patch: dict = {"host_config": host_config}
                if req.type == "correlation":
                    # C3 fix ②：镜像组合分支补 legacy bb_host_mappings（旧读方 /
                    # reconcile 路径；_session_host_mappings 优先读上方 host_config
                    # 快照，此键是兜底）——gateway 黑盒验证段据此起 host proxy。
                    host_patch["bb_host_mappings"] = self._host_config_mappings(
                        host_config)
                SessionManager(scan_dir.parent).update_session(
                    scan_dir, host_patch)
            # C3 fix round 2：correlation + gateway url 的认证落地（spec §5.3 段③
            # 「+认证可选」）--镜像组合分支的 _dump_auth_config 调用点 + bb_auth_ref
            # session 写。_run_blackbox_phase 的 config_path 解析（scan_dir/
            # scan-config.yaml 存在即取）零改动接住。无认证字段 -> 返 None 不落文件，
            # config_path 保持 None（黑盒跳过登录段，零回归）。
            if req.type == "correlation" and req.url:
                corr_auth_path = await self._dump_auth_config(req, ws, scan_dir)
                if corr_auth_path:
                    SessionManager(scan_dir.parent).update_session(
                        scan_dir, {"bb_auth_ref": self._snapshot_auth_ref(req)})

            if req.type == "whitebox":
                if req.url:
                    # 组合扫描（whitebox + url）：先 dump 认证配置，据 config_path 决定同步/异步。
                    config_path = await self._dump_auth_config(req, ws, scan_dir)
                    host_mappings = self._host_config_mappings(host_config)
                    SessionManager(scan_dir.parent).update_session(scan_dir, {
                        "combined": True,
                        "bb_url": req.url,
                        # Keep the legacy field for old readers/reconcile paths.
                        "bb_host_mappings": host_mappings,
                        "bb_auth_ref": self._snapshot_auth_ref(req),
                        "bb_phase": "precheck",
                        # 进度分母（spec §9.5）：白盒部分提交时写；blackbox 部分由
                        # _run_blackbox_phase 在白盒 queue 已知后补（按发现的 vuln 类）。
                        "expected_agents": self._compute_expected_agents(req),
                        # 重跑预填 repo 名（2026-09-04）：属提交请求固有属性，须在 precheck
                        # 之前落盘——原位置在 _submit_whitebox 旁（precheck 之后），组合扫描
                        # precheck 失败（认证失败/目标不可达）提前 return 永不写入，failed
                        # 任务重跑拿不到 source_repo（下方同步分支/kickoff 内的同款写入
                        # 由此变为幂等重复，保留无害）。
                        "source_repo": req.source.value if req.source else None,
                    })
                    if config_path:
                        # 带认证 → precheck 登录目标站（可达数分钟）。异步化：写完 session
                        # （bb_phase=precheck）后把 precheck → 白盒提交 → 接力编排 fire-and-forget
                        # 到 _combined_kickoff，start 立即返回 scan_id。否则 POST /api/scan 阻塞
                        # 致前端 submitting 卡死、不跳转。前端据 bb_phase=precheck 显「预验证中」
                        # + 跳 live 页跟踪进度（live 页已 merge authcheck-events.ndjson）。
                        kickoff = asyncio.create_task(self._combined_kickoff(
                            scan_key, scan_dir, req, config_path, host_mappings,
                            target, event_file))
                        self._orchestrator_tasks[scan_key] = kickoff
                        return ws, scan_id
                    # 公开目标（无认证）→ config_path=None → _run_precheck 立即 True。
                    # 走原同步路径（precheck 瞬时，不阻塞；保留提交失败抛异常的契约）。
                    ok = await self._run_precheck(
                        scan_dir, ws, scan_id, req.url, config_path,
                        host_mappings=host_mappings)
                    if not ok:
                        await self._mark_bb(scan_dir, "failed", "auth_failed")
                        await self._ensure_scan_end(scan_dir, status="failed")
                        self._active_reqs.pop(scan_key, None)
                        # 扫完即删：precheck 失败 = 已终态（此路径无 _watch），在此触发。
                        await self._sweep_ws_quiet(ws)
                        return ws, scan_id
                    await self._mark_bb(scan_dir, "pending")
                handle = await self._submit_whitebox(
                    target, ws, scan_id, scan_dir, event_file, req.url or "",
                    combined=bool(req.url))
                SessionManager(scan_dir.parent).update_session(
                    scan_dir, {"source_repo": req.source.value if req.source else None})
                if req.url:
                    orch = asyncio.create_task(
                        self._combined_orchestrator(scan_key, handle, scan_dir, req))
                    self._orchestrator_tasks[scan_key] = orch
            elif req.type == "blackbox":
                config_path, repo_path = await self._resolve_blackbox_inputs(
                    req, ws, scan_dir, target)
                host_mappings = self._host_config_mappings(host_config)
                handle = await self._submit_blackbox(
                    repo_path, ws, scan_id, scan_dir, event_file, req.url or "",
                    config_path, host_mappings=host_mappings)
                SessionManager(scan_dir.parent).update_session(
                    scan_dir, {"reuse_whitebox_scan_id": req.reuse_whitebox_scan_id})
            elif req.type == "correlation":
                # ── 跨仓三段接力提交（C3，spec 2026-08-24 §5.3 步骤 3-5）─────────
                # ④ 覆写 out_workspace=主行 scan_id 落盘 yaml（关联 workflow / 漂移
                # 检测读此文件；表单/yaml 预览中该字段省略，此 dump 是 worker 读到的真值）。
                corr_config.correlation.out_workspace = scan_id
                # final-fix ②：落盘前把 spec.path 回填为绝对仓库目录。web 表单的
                # path 是仓库名（或复用仓 null），worker 侧 orchestrator 会把
                # spec.path 喂关联 agent 的 repo_paths 上下文（读源码）+ 漂移检测
                # （Path(spec.path).exists()）——裸名字在 worker 容器不可读 → 源码
                # 读不到、漂移静默跳过。回填仅动此刻的这个对象（复用/规划已在上
                # 方用名字语义跑完；下方子仓循环只用 spec.workspace/corr_repo_dirs，
                # 不消费 plan.repo_path）。复用子仓 best-effort：仓仍在 ws → 回填
                # （恢复漂移+源码可达）；已删/未就绪 → 留 null（漂移跳过是正解）。
                for svc, spec in corr_config.repos.items():
                    if svc in corr_repo_dirs:
                        spec.path = str(corr_repo_dirs[svc])
                    elif spec.workspace and spec.path is None:
                        try:
                            spec.path = self._resolve_repo_path(ws, svc)
                        except ValueError:
                            pass  # 仓不在 ws/未就绪 → 保持 null，不阻塞提交
                dumped = yaml_path.parent / f"{scan_id}-multi-repo.yaml"
                _dump_multi_repo_yaml(corr_config, dumped)
                corr_writer = CorrelationEventWriter(event_file)
                # ⑤ 子仓登记：现扫子仓逐仓建标准白盒行 + 提交（url 空、combined=False
                # ——纯白盒，终态自写）；复用子仓零动作（路径已在 corr_repo_paths）。
                children: list[dict] = []
                child_handles: dict[str, tuple[str, Any]] = {}
                for plan in plan_repo_scans(corr_config):
                    svc = plan.service
                    if plan.reuse:
                        children.append({"service": svc, "scan_id": plan.workspace,
                                         "reused": True})
                        await corr_writer.repo(svc, "completed", detail="reused")
                        continue
                    c_scan_id, c_dir = self._store.create_scan(ws, "", svc, "whitebox")
                    self._mark_owner(c_dir, "web")
                    # 扫完即删（2026-09-10）：主表单勾选传播给本次新建子仓行（带
                    # source_repo=ws 内仓库名供 sweep 分组；复用子仓无新行，天然不传播）。
                    if req.delete_repo_on_finish:
                        SessionManager(c_dir.parent).update_session(c_dir, {
                            "delete_repo_on_finish": True,
                            "source_repo": corr_repo_names.get(svc, svc),
                        })
                    await corr_writer.repo(svc, "started")
                    wb_handle = await self._submit_whitebox(
                        corr_repo_dirs[svc], ws, c_scan_id, c_dir,
                        c_dir / "events.ndjson", "")
                    child_handles[svc] = (c_scan_id, wb_handle)
                    corr_repo_paths[svc] = c_dir
                    children.append({"service": svc, "scan_id": c_scan_id,
                                     "reused": False})
                SessionManager(scan_dir.parent).update_session(scan_dir, {
                    "corr_children": children,
                    "config_path": str(dumped),
                })
                # ⑥ 三段接力编排（fire-and-forget；镜像 _combined_orchestrator 的
                # try/except/finally + _ensure_scan_end 幂等收尾）。cancel/delete 经
                # _orchestrator_tasks 可达（级联取消子仓/关联 workflow 属 D 阶段）。
                orch = asyncio.create_task(self._correlation_orchestrator(
                    scan_key, child_handles, scan_dir, req, dumped, corr_repo_paths))
                self._orchestrator_tasks[scan_key] = orch
                # 主行自起 _watch（tail events.ndjson 至编排收尾的 scan_end；finally
                # 清 _active_reqs/_tasks）。主行无单一 workflow handle（子仓/关联句柄由
                # 编排持有）——不进 _handles，提前返回不走下方通用登记。
                self._tasks[scan_key] = asyncio.create_task(
                    self._watch(scan_key, event_file, scan_dir))
                return ws, scan_id
            elif req.type == "mr":
                # MR 增量扫描（spec 2026-09-03 §3.2）：纯白盒语义 + diff 前置，
                # 无组合/认证/HOST。提交 MrScanWorkflow（worker 内 child 跑全量主体）。
                # head/base_commit = merged 改道把手（源分支已删的已合并 MR，2026-09-04）。
                handle = await self._submit_mr(
                    target, ws, scan_id, scan_dir, event_file,
                    req.base_ref, req.head_ref, req.head_commit, req.base_commit)
                SessionManager(scan_dir.parent).update_session(
                    scan_dir, {"source_repo": req.source.value if req.source else None,
                               "mr_base_ref": req.base_ref, "mr_head_ref": req.head_ref,
                               "mr_head_commit": req.head_commit,
                               "mr_base_commit": req.base_commit})
        except BaseException as exc:
            self._active_reqs.pop(scan_key, None)
            self._handles.pop(scan_key, None)
            self._tasks.pop(scan_key, None)
            self._orchestrator_tasks.pop(scan_key, None)
            # A directory was already created, so never leave it in running state.
            await self._mark_submission_failed(scan_dir, event_file, exc)
            # 扫完即删：提交失败 = 已终态（此路径无 _watch），best-effort 触发后照常抛。
            await self._sweep_ws_quiet(ws)
            raise
        self._handles[scan_key] = handle
        self._tasks[scan_key] = asyncio.create_task(self._watch(scan_key, event_file, scan_dir))
        return ws, scan_id

    async def resume(self, ws: str, scan_id: str) -> tuple[str, str]:
        """T3: resume 已停未完成的 scan（interrupted/crashed）-> 续跑。

        递增 scan_dir/session.json 的 resumeAttempts + 提交 resume workflow（workflow_id =
        {ws}-{scan_id}-resume-N，由 _resolve_workflow_id 读递增后的 resumeAttempts 算）。
        completed/failed/cancelled/running -> ValueError（用重扫 POST /api/scan 起新 scan）。
        """
        scan_dir = self._store.get_scan_dir(ws, scan_id)
        if scan_dir is None:
            raise ValueError("scan 不存在")
        mgr = SessionManager(scan_dir.parent)
        status = _compute_status(scan_dir, mgr.get_status(scan_dir))
        if status not in _RESUMABLE_STATUSES:
            raise ValueError(f"该扫描状态为 {status}，不可恢复，请重新扫描")

        # ── correlation 主行 resume（C4）：首版不做接力重入 ─────────────────────
        # 接力恢复依赖重新提交子仓白盒（编排协程/子仓 handle 随 web 进程丢失，主行无
        # 单一可 re-attach 的 workflow），不在首版范围；行为对齐白盒 stale 判活语义收口：
        # - heartbeat 判活（纯心跳，对齐 cancel ② 轨口径）→ no-op 拒绝：兜底「session
        #   已显式标 interrupted 但 worker 复活」的 race，不动 session、零提交；
        # - stale（session 仍 running，reconciler 未及收口）→ 标 interrupted 终态
        #   （scan_end 缺失才补 + session status/completed_at，_ensure_scan_end 同款
        #   幂等口径）；已终态（interrupted/crashed）不覆写。
        # 两路均 ValueError → API 422 引导重新提交（对齐 resume 契约「不可恢复→重扫」）。
        # 分支置于 _check_temporal 之前：不提交任何 workflow，无需 Temporal。
        if self._scan_row_is_correlation(scan_dir):
            if is_scan_recently_active(scan_dir):
                raise ValueError("该关联扫描仍在运行，无需恢复")
            if mgr.get_status(scan_dir) == "running":
                event_file = scan_dir / "events.ndjson"
                if not self._has_scan_end(event_file):
                    await self._write_scan_end(
                        event_file, "interrupted", -1,
                        "编排随 web 进程重启丢失（关联扫描暂不支持断点恢复）",
                        scan_dir=scan_dir)
                mgr.update_session(scan_dir, {
                    "status": "interrupted", "completed_at": time.time()})
            raise ValueError(
                "关联扫描暂不支持断点恢复，请重新提交关联扫描（子仓白盒产物保留可复用）")

        # §4.1 判活：failed = Temporal 已 FAILED 终态无并发风险直接放行；其余续跑
        # 状态（cancelled/killed/crashed/interrupted）先 heartbeat 判活——心跳新鲜
        # 说明 worker 仍在跑，拒绝防撞车。cancelled（取消收尾窗口，worker 异步真退）
        # 与 race 场景文案分开：前者引导「稍等再续」，后者维持「仍在运行」。
        if status != "failed" and is_scan_recently_active(scan_dir):
            if status == "cancelled":
                raise ValueError("已取消，等待 worker 退出后可续跑（约 1-2 分钟）")
            raise ValueError("该扫描仍在运行，无需恢复")

        await self._check_temporal()
        # 并发闸门已下沉 worker（spec §7）：resume 同样不拒绝，排队在 worker 闸门。
        # 双跑守卫（2026-09-11 NodeGoat-20260910-193720 实证）：failed 免判活放行的
        # 假设「Temporal 已终态」不总成立——activity 挂在 temporal 默认无限重试中时
        # execution 阴魂不散，resume-N 提交后双跑（agent 并发翻倍撞 429 + checkpoint
        # last-writer-wins 覆写丢审查结论）。提交前 terminate 上一个在途 execution。
        await self._terminate_inflight_prior_execution(ws, scan_id)
        data = mgr.get_session_data(scan_dir)
        event_file = scan_dir / "events.ndjson"
        scan_key = (ws, scan_id)

        # ── 组合扫描 resume（spec §11.4）──────────────────────────────────────
        # 读 session combined/bb_phase/bb_rerun_attempts 分阶段：
        # - pending/precheck → 重交白盒（-resume-N）+ 重启完整 _combined_orchestrator（接力续跑）。
        # - running → 黑盒 workflow 仍在 Temporal 跑 → re-attach handle + 仅做报告的编排 task。
        # 零回归：仅 combined 真时触发；非组合走下方既有路径不变。
        if data.get("combined"):
            # 续跑前剥掉旧 scan_end（所有分支共享；否则 _watch 见旧 scan_end 立即退出）。
            self._strip_trailing_scan_end(event_file)
            mgr.update_session(scan_dir, {"status": "running", "completed_at": None})
            # 重建 ScanRequest 供 _active_reqs（active_repo_sources 引用锁）+ 编排 task。
            req = self._build_combined_resume_req(data, ws)
            self._active_reqs[scan_key] = req

            # 版本化 run（spec §11.4）：bb_phase 下沉到 run 级 session——读 latest run 的 phase
            # 分支（取代旧 task-level bb_phase/bb_rerun_attempts）。
            runs = self._store.list_blackbox_runs(ws, scan_id)
            latest = runs[-1] if runs else None
            latest_phase = None
            if latest:
                rd = self._store.get_blackbox_run_dir(ws, scan_id, latest["run_id"])
                if rd is not None:
                    latest_phase = SessionManager(rd.parent).get_session_data(rd).get("bb_phase")

            if latest and latest_phase == "running":
                # run 黑盒 workflow 仍在 Temporal 跑（scan_manager 进程死了，Temporal 留活）→
                # re-attach handle（-bb-{K}，不重 submit——workflow_id 已固定）+ 仅做报告编排 task。
                bb_wf_id = self._resolve_run_workflow_id(ws, scan_id, latest["run_id"])
                try:
                    client = await Client.connect(self._temporal_address())
                    handle = client.get_workflow_handle(bb_wf_id)
                except BaseException as exc:
                    self._active_reqs.pop(scan_key, None)
                    await self._mark_submission_failed(scan_dir, event_file, exc)
                    raise
                # 附仅做报告的编排 task（接力已发生、黑盒已 submit；只 await 完成 → per-run 融合报告）。
                orch = asyncio.create_task(
                    self._combined_report_orchestrator(
                        scan_key, handle, scan_dir, latest["run_id"]))
                self._orchestrator_tasks[scan_key] = orch
            else:
                # pending/precheck（白盒阶段中断）→ 重交白盒 workflow（-resume-N，复用
                # _submit_whitebox）+ 重启完整 _combined_orchestrator（白盒完成后接力黑盒 + 报告）。
                attempts = data.get("resumeAttempts") or []
                if not isinstance(attempts, list):
                    attempts = []
                n = len(attempts) + 1
                attempts = list(attempts) + [
                    {"workflowId": f"{ws}-{scan_id}-resume-{n}", "ts": time.time()}]
                mgr.update_session(scan_dir, {"resumeAttempts": attempts})
                repo_path = data.get("repo_path") or ""
                web_url = data.get("web_url") or ""
                # §4.2：组合白盒段与独立白盒行同通路——agent 级对账 + 跳过透传。
                rstate = await self._reconcile_whitebox_resume(
                    scan_dir, repo_path, event_file)
                try:
                    handle = await self._submit_whitebox(
                        repo_path, ws, scan_id, scan_dir, event_file, web_url,
                        combined=True,
                        resume_completed_agents=rstate.completed_agents)
                except BaseException as exc:
                    self._active_reqs.pop(scan_key, None)
                    await self._mark_submission_failed(scan_dir, event_file, exc)
                    raise
                orch = asyncio.create_task(
                    self._combined_orchestrator(scan_key, handle, scan_dir, req))
                self._orchestrator_tasks[scan_key] = orch
            self._handles[scan_key] = handle
            self._tasks[scan_key] = asyncio.create_task(
                self._watch(scan_key, event_file, scan_dir))
            return ws, scan_id

        # ── 非组合：既有 resume 路径（零回归）──────────────────────────────────
        repo_path = data.get("repo_path") or ""
        web_url = data.get("web_url") or ""
        scan_type = mgr.get_scan_type(scan_dir) or "whitebox"
        # blackbox reuse：凭 session.reuse_whitebox_scan_id 重解析 wb_scan_dir（修 reuse resume
        # fail-fast：create_scan target="" → repo_path 读空 → workflow detect_whitebox_results=False）。
        reuse_whitebox_scan_id = data.get("reuse_whitebox_scan_id")
        # 递增 resumeAttempts -> _resolve_workflow_id 算 -resume-N 后缀
        attempts = data.get("resumeAttempts") or []
        if not isinstance(attempts, list):
            attempts = []
        n = len(attempts) + 1
        attempts = list(attempts) + [
            {"workflowId": f"{ws}-{scan_id}-resume-{n}", "ts": time.time()}]
        mgr.update_session(scan_dir, {
            "resumeAttempts": attempts, "status": "running", "completed_at": None})

        # 续跑前剥掉旧 scan_end（中断时 orphan_reconciler/_watch 写的），否则 _watch 见旧
        # scan_end 立即退出，无法 tail 新 workflow。旧中断事件从 ndjson 末尾移除（session
        # 的 resumeAttempts 已记 resume 次数，历史可追溯）。
        self._strip_trailing_scan_end(event_file)

        # 重构 ScanRequest 供 _active_reqs（active_repo_sources 判引用用）。blackbox 必须带
        # reuse_whitebox_scan_id 过 model_validator（_blackbox_requires_reuse），否则 ValidationError。
        req_kwargs: dict = dict(type=scan_type, url=web_url or None, workspace=ws)
        if scan_type == "blackbox" and reuse_whitebox_scan_id:
            req_kwargs["reuse_whitebox_scan_id"] = reuse_whitebox_scan_id
        req = ScanRequest(**req_kwargs)
        self._active_reqs[scan_key] = req
        try:
            if scan_type == "blackbox":
                # resume 黑盒：config_path 从 scan_dir/scan-config.yaml 回填（原 auth 配置）。
                cfg = scan_dir / "scan-config.yaml"
                config_path = str(cfg) if cfg.exists() else None
                # reuse 黑盒：凭 reuse_whitebox_scan_id 重解析 wb_scan_dir 作 repo_path（修 fail-fast：
                # start 已落 reuse_id；此处对齐 _resolve_blackbox_inputs 的 get_scan_dir 口径，
                # 随 workspaces_dir 配置走，不存易失绝对路径）。无 reuse_id（legacy）回落 repo_path。
                if reuse_whitebox_scan_id:
                    wb_scan_dir = self._store.get_scan_dir(ws, reuse_whitebox_scan_id)
                    if wb_scan_dir is None:
                        raise ValueError(f"要复用的白盒扫描已不存在: {reuse_whitebox_scan_id}")
                    repo_path = str(wb_scan_dir)
                handle = await self._submit_blackbox(
                    repo_path or None, ws, scan_id, scan_dir, event_file, web_url, config_path,
                    host_mappings=self._session_host_mappings(data))
            else:
                # §4.2：白盒行 agent 级对账（builder G∧F + cleanup 半成品）——
                # 假续跑根因修复：resume_completed_agents 进 PipelineInput，
                # 激活 workflow 既有跳过守卫（黑盒行走上方分支，维持原状）。
                rstate = await self._reconcile_whitebox_resume(
                    scan_dir, repo_path, event_file)
                handle = await self._submit_whitebox(
                    repo_path, ws, scan_id, scan_dir, event_file, web_url,
                    resume_completed_agents=rstate.completed_agents)
        except BaseException as exc:
            self._active_reqs.pop(scan_key, None)
            await self._mark_submission_failed(scan_dir, event_file, exc)
            raise
        self._handles[scan_key] = handle
        self._tasks[scan_key] = asyncio.create_task(self._watch(scan_key, event_file, scan_dir))
        return ws, scan_id

    async def _terminate_inflight_prior_execution(self, ws: str,
                                                  scan_id: str) -> None:
        """resume 双跑守卫：terminate 上一个 workflow 的在途 execution（best-effort）。

        2026-09-11 NodeGoat-20260910-193720 实证：session 已标 failed（web 判死）但
        temporal execution 挂在 activity 默认无限重试中并未终态——resume 提交后新旧
        两个 execution 并发：agent 并发翻倍撞 429（injection-02 三连挂）+ checkpoint
        last-writer-wins 覆写丢审查结论。prior id = 递增 resumeAttempts 前的
        _resolve_workflow_id（读盘即时值，组合/非组合两分支共用）。describe 异常
        （不存在/网络）与已终态均跳过，不阻断 resume（守卫不引入新失败面）。
        """
        prior_id = self._resolve_workflow_id(ws, scan_id)
        try:
            from temporalio.client import WorkflowExecutionStatus
            client = await Client.connect(self._temporal_address())
            handle = client.get_workflow_handle(prior_id)
            desc = await handle.describe()
            if desc.status == WorkflowExecutionStatus.RUNNING:
                await handle.terminate(
                    reason=f"superseded by resume of {ws}/{scan_id}")
                _log.info("resume %s/%s: terminated inflight execution %s",
                          ws, scan_id, prior_id)
        except Exception:
            _log.info("resume %s/%s: prior execution %s absent/terminal; "
                      "skip terminate", ws, scan_id, prior_id, exc_info=True)

    async def resume_preview(self, ws: str, scan_id: str) -> dict:
        """断点详情（spec 2026-08-27-web-resume-breakpoint §4.5，只读不动状态）。

        复用 WhiteboxResumeStateBuilder.build()（不调 cleanup、不 abort 抛异常——
        abort 映射 resumable:false + abort_reason）+ step_cache.preview_steps 读
        marker 简表。correlation / blackbox / 不可续跑状态 / 心跳新鲜 → resumable:false
        带 reason；scan 不存在 → ValueError（API 层 404）。
        """
        from supernova_whitebox.pipeline.step_cache import preview_steps
        scan_dir = self._store.get_scan_dir(ws, scan_id)
        if scan_dir is None:
            raise ValueError("scan 不存在")
        mgr = SessionManager(scan_dir.parent)
        status = _compute_status(scan_dir, mgr.get_status(scan_dir))
        scan_type = mgr.get_scan_type(scan_dir) or "whitebox"
        data = mgr.get_session_data(scan_dir)
        attempts = data.get("resumeAttempts") or []
        base: dict = {
            "status": status, "scan_type": scan_type, "reason": None,
            "completed_agents": [], "interrupted_agent": None,
            "steps": [], "warnings": [], "abort_reason": None,
            "transient": False,
            "resume_attempts": len(attempts) if isinstance(attempts, list) else 0,
        }

        if self._scan_row_is_correlation(scan_dir):
            base.update(resumable=False,
                        reason="关联扫描暂不支持断点恢复，请重新提交关联扫描（子仓白盒产物保留可复用）")
            return base
        if scan_type == "blackbox":
            base.update(resumable=False,
                        reason="黑盒扫描非幂等，不支持断点续跑（失败走整体重跑）")
            return base
        if status not in _RESUMABLE_STATUSES:
            base.update(resumable=False,
                        reason=f"该扫描状态为 {status}，不可续跑（completed 用重跑、running 在跑）")
            return base
        if status != "failed" and is_scan_recently_active(scan_dir):
            if status == "cancelled":
                # 取消收尾窗口（web 已标终态、worker 异步退出 + 心跳 90s 判活窗）——
                # 瞬态：窗口一过即 resumable，前端凭 transient:true 轮询重拉、按钮自动出现。
                base.update(resumable=False, transient=True,
                            reason="已取消，等待 worker 退出后可续跑（约 1-2 分钟）")
            else:
                # worker 复活 race（session 显式终态但 worker 仍在跑）——非瞬态语义。
                base.update(resumable=False, reason="该扫描仍在运行，无需恢复")
            return base

        deliverables = scan_dir / "deliverables" / "whitebox"
        rstate = await WhiteboxResumeStateBuilder().build(
            mode="auto", workspace=scan_dir, deliverables=deliverables,
            repo_path=Path(data.get("repo_path") or ""))
        if rstate.aborted:
            base.update(resumable=False, abort_reason=rstate.abort_reason,
                        reason=rstate.abort_reason)
            return base
        base.update(
            resumable=True,
            completed_agents=rstate.completed_agents,
            interrupted_agent=rstate.interrupted_agent,
            warnings=rstate.warnings,
            steps=preview_steps(deliverables),
        )
        return base

    async def _reconcile_whitebox_resume(
        self, scan_dir: Path, repo_path: str, event_file: Path,
    ) -> Any:
        """agent 级对账（spec 2026-08-27-web-resume-breakpoint §4.2）。

        builder 以 git deliverable commit（G）∧ 产物存在（F）对账出 completed_agents；
        G∧¬F abort → ValueError（API 层映射 422 带 abort_reason，引导重跑）；
        cleanup 删 ¬G 半成品；续跑摘要以 InfoEvent（同 log_info_activity 落盘形态）
        写进 events.ndjson，用户在 live 流可见「跳过 N 项、从哪继续」。
        """
        builder = WhiteboxResumeStateBuilder()
        rstate = await builder.build(
            mode="auto", workspace=scan_dir,
            deliverables=scan_dir / "deliverables" / "whitebox",
            repo_path=Path(repo_path or ""))
        if rstate.aborted:
            raise ValueError(rstate.abort_reason)
        await builder.cleanup(
            mode="auto", deliverables=scan_dir / "deliverables" / "whitebox",
            completed_agents=rstate.completed_agents)
        skipped = "、".join(rstate.completed_agents) or "无"
        summary = (f"续跑：跳过已完成 agent（{skipped}），"
                   f"从 {rstate.interrupted_agent or '未定位中断点'} 继续")
        if rstate.warnings:
            summary += "；" + "；".join(rstate.warnings)
        try:
            async with aiofiles.open(event_file, "a") as fh:
                await fh.write(json.dumps({
                    "ts": _now_iso(), "category": "INFO", "type": "InfoEvent",
                    "message": summary, "level": "info",
                }, ensure_ascii=False) + "\n")
        except OSError:
            pass  # best-effort：显示通道失败不阻塞续跑
        return rstate

    async def _submit_whitebox(self, target: str | None, ws: str, scan_id: str,
                               scan_dir: Path, event_file: Path, web_url: str,
                               combined: bool = False,
                               resume_completed_agents: list[str] | None = None,
                               ) -> Any:
        """算 workflow_id(读 resumeAttempts) + Client.connect + start_workflow 到固定 queue.

        T3: workspace_name=scan_id（worker 据此 + event_file.parent 推导 scan_dir 产物目录，
        workspace_name 对 web 路径仅作展示）。event_file 塞进 PipelineInput(worker 容器
        setup_display 据此挂 StructuredEventRenderer)。workflow_id 在提交时定(activity 不能改).

        combined=True（组合扫描）：白盒 finalize_summary 走 log_phase_complete 分支（写
        PhaseEvent 阶段边界，不写终态 scan_end），终态留给黑盒段——漏传会让白盒 finalize
        提前写 scan_end 把整条组合扫描收掉（黑盒接不上）。
        """
        # 先解析并校验 workspace-owned Provider 配置，缺配置时不要连接或提交 Temporal。
        provider_config = self._resolve_provider_config(ws)
        client = await Client.connect(self._temporal_address())
        workflow_id = self._resolve_workflow_id(ws, scan_id)
        inp = PipelineInput(
            repo_path=target or "",
            web_url=web_url or "",
            workspace_name=scan_id,
            event_file=str(event_file),
            provider_config=provider_config,
            env_overrides=self._resolve_env_overrides(ws),
            enable_llm_track=self._resolve_llm_track(ws),
            combined=combined,
            resume_completed_agents=list(resume_completed_agents or []),
        )
        handle = await client.start_workflow(
            WhiteboxScanWorkflow.run, inp, id=workflow_id,
            task_queue=WEB_TASK_QUEUE_WHITEBOX,
            run_timeout=scan_budget(),
        )
        # 提交成功后锚定 submitted_at(scan_liveness 提交宽限门据此判冷启动窗口, 防误杀).
        # 失败分支(start_workflow 抛)不会到达此处 -> 提交失败不写 submitted_at.
        self._mark_submitted_at(scan_dir)
        return handle

    async def _submit_mr(self, target: str | None, ws: str, scan_id: str,
                         scan_dir: Path, event_file: Path,
                         base_ref: str | None, head_ref: str | None,
                         head_commit: str | None = None,
                         base_commit: str | None = None) -> Any:
        """提交 MrScanWorkflow（MR 增量扫描，spec 2026-09-03 §3.2）。

        与 _submit_whitebox 同源：先解析 provider 配置，再 start_workflow 到
        WEB_TASK_QUEUE_WHITEBOX（worker 注册了 MrScanWorkflow）。base/head ref
        经 PipelineInput.mr_base_ref/mr_head_ref 穿给 workflow 前置 activities；
        head/base_commit（merged 改道，2026-09-04）经同路径穿 mr_head_commit/
        mr_base_commit——worker 前置 activity 有 commit 对时按 commit 定位增量。
        """
        provider_config = self._resolve_provider_config(ws)
        client = await Client.connect(self._temporal_address())
        workflow_id = self._resolve_workflow_id(ws, scan_id)
        inp = PipelineInput(
            repo_path=target or "",
            web_url="",
            workspace_name=scan_id,
            event_file=str(event_file),
            provider_config=provider_config,
            env_overrides=self._resolve_env_overrides(ws),
            enable_llm_track=self._resolve_llm_track(ws),
            mr_base_ref=base_ref,
            mr_head_ref=head_ref,
            mr_head_commit=head_commit,
            mr_base_commit=base_commit,
        )
        handle = await client.start_workflow(
            MrScanWorkflow.run, inp, id=workflow_id,
            task_queue=WEB_TASK_QUEUE_WHITEBOX,
            run_timeout=scan_budget(),
        )
        self._mark_submitted_at(scan_dir)
        return handle

    async def _dump_auth_config(
        self, req: ScanRequest, ws: str, scan_dir: Path,
    ) -> str | None:
        """展开认证配置 → 写 scan_dir/scan-config.yaml，返 config_path（无认证返 None）。

        原 _resolve_blackbox_inputs 的 config_path 段抽出，供组合分支 t0 预验证复用（组合模式
        无 reuse_whitebox_scan_id，不走 _resolve_blackbox_inputs 的 repo_path/reuse 段）。auth→YAML
        展开逻辑（profile 三子模式 + inline 多角色）零改动——core 合流点 parse_config 直读明文 YAML。

        三互斥子模式（model_validator _auth_profile_xor_inline 已保证互斥）：
          - profile_id + cred_ids[] = 子集：展开选中 credentials → accounts[]；
          - profile_id + cred_id     = 单角色（旧契约）：展开该 credential → 单 authentication；
          - profile_id 单独          = 全角色：展开所有 credentials → accounts[]。
          - authentication(inline)   = Authentication.model_validate → dump（+ auth_accounts 多角色）。
        无认证字段 → None（公开目标不登录，预验证/黑盒均跳过 auth 段）。
        """
        import yaml
        from supernova_core.models.config import Authentication
        from .auth_profile_store import credential_to_authentication

        def _dump_auth_payload(payload: dict) -> str:
            cfg_file = scan_dir / "scan-config.yaml"
            cfg_file.write_text(
                yaml.safe_dump(payload, allow_unicode=True, sort_keys=False),
                encoding="utf-8")
            return str(cfg_file)

        def _expand_multi_identity(profile, creds: list) -> str:
            """多身份展开：creds 列表 → authentication(primary=首个low) + accounts[](其余)。

            子集模式与全角色模式共用：调用方负责筛 creds 子集（子集）或传全量（全角色）。
            primary = 首个 low（无 low 回落首个，兜底防全 high 时无 primary）。
            """
            from supernova_core.utils.authz_identity import derive_privilege_tier, slugify_account_id
            # high_priv_names 硬编码（plan 作者认可简化；env 化推迟）。
            high_priv_names = ["admin"]

            def _tier_of(c):
                return derive_privilege_tier(c.role, high_priv_names)

            lows = [c for c in creds if _tier_of(c) == "low"]
            primary = lows[0] if lows else (creds[0] if creds else None)
            if primary is None:
                raise ValueError(f"认证档案无凭据: {req.auth_profile_id}")
            primary_auth = credential_to_authentication(profile, primary)
            accounts = []
            used_ids: set[str] = set()
            for c in creds:
                if c.id == primary.id:
                    continue
                creds_d = {"username": c.username, "password": c.password}
                if getattr(c, "totp_secret", None):
                    creds_d["totp_secret"] = c.totp_secret
                accounts.append({
                    # 存量凭据 ID 含下划线（cred_xxx），须清洗成 core 认可的 slug
                    "id": slugify_account_id(c.id, used_ids),
                    "role": c.role,
                    "tier": _tier_of(c),
                    "credentials": creds_d,
                })
            payload = {
                "authentication": primary_auth.model_dump(exclude_none=True, mode="json"),
                "accounts": accounts,
            }
            return _dump_auth_payload(payload)

        if req.auth_profile_id and req.auth_credential_ids:
            # 子集模式（2026-08-06）：展开选中的 credentials → accounts[]（默认前端全选）。
            if self._auth_profile_store is None:
                raise RuntimeError("auth_profile_store 未注入，无法展开认证档案")
            profile = self._auth_profile_store.get(ws, req.auth_profile_id)
            if profile is None:
                raise ValueError(f"认证档案不存在: {req.auth_profile_id}")
            selected_ids = set(req.auth_credential_ids)
            selected = [c for c in profile.credentials if c.id in selected_ids]
            if not selected:
                raise ValueError(f"选中的角色凭据不存在: {req.auth_credential_ids}")
            return _expand_multi_identity(profile, selected)
        if req.auth_profile_id and req.auth_credential_id:
            # 单角色模式（旧契约，向后兼容）：展开该 credential → 单 authentication。
            if self._auth_profile_store is None:
                raise RuntimeError("auth_profile_store 未注入，无法展开认证档案")
            profile = self._auth_profile_store.get(ws, req.auth_profile_id)
            if profile is None:
                raise ValueError(f"认证档案不存在: {req.auth_profile_id}")
            cred = next((c for c in profile.credentials if c.id == req.auth_credential_id), None)
            if cred is None:
                raise ValueError(f"角色凭据不存在: {req.auth_credential_id}")
            auth = credential_to_authentication(profile, cred)
            return _dump_auth_payload(
                {"authentication": auth.model_dump(exclude_none=True, mode="json")})
        if req.auth_profile_id:
            # 全角色模式（子项目2 T10）：展开所有 credentials → accounts[]。
            if self._auth_profile_store is None:
                raise RuntimeError("auth_profile_store 未注入，无法展开认证档案")
            profile = self._auth_profile_store.get(ws, req.auth_profile_id)
            if profile is None:
                raise ValueError(f"认证档案不存在: {req.auth_profile_id}")
            return _expand_multi_identity(profile, profile.credentials)
        if req.authentication:
            try:
                auth = Authentication.model_validate(req.authentication)
            except Exception as exc:
                raise ValueError(f"登录配置无效: {exc}") from exc
            payload = {"authentication": auth.model_dump(exclude_none=True, mode="json")}
            # inline 多角色（2026-08-07）：auth_accounts 非空 → 展开 accounts[]（id=角色 slug 去重、
            # tier=derive_privilege_tier、totp_secret 透传）。形状对齐 profile 模式 _expand_multi_identity。
            if req.auth_accounts:
                from supernova_core.utils.authz_identity import derive_privilege_tier, slugify_account_id
                used_ids: set[str] = set()
                accounts = []
                for acc in req.auth_accounts:
                    role = (acc.get("role") or "").strip() or "role"
                    creds = {"username": acc.get("username", ""), "password": acc.get("password", "")}
                    if acc.get("totp_secret"):
                        creds["totp_secret"] = acc["totp_secret"]
                    accounts.append({
                        "id": slugify_account_id(role, used_ids),
                        "role": role,
                        "tier": derive_privilege_tier(role, ["admin"]),
                        "credentials": creds,
                    })
                payload["accounts"] = accounts
            return _dump_auth_payload(payload)
        return None  # 无认证字段（公开目标）

    async def _resolve_blackbox_inputs(
        self, req: ScanRequest, ws: str, scan_dir: Path, target: str | None,
    ) -> tuple[str | None, str | None]:
        """解析黑盒提交的 config_path(登录 YAML) + repo_path(复用白盒 / 指定仓库 / standalone)。

        config_path 委托 _dump_auth_config（auth→YAML 展开，profile 三子模式 + inline 多角色）；
        blackbox workflow `if input.config_path:` 据此跑 run_blackbox_auth_validation。校验失败 raise ValueError。
        repo_path: req.reuse_whitebox_scan_id → 该白盒 scan_dir 作 repo_path
          （detect_whitebox_results 在 Path(repo_path)/deliverables 找白盒 queue；wb scan_dir/
          deliverables 即白盒产物落点，blackbox 自身产物靠 workspace_path 另落 bb scan_dir）；
          否则 target（req.source.repo 经 _resolve_inputs 解析）；standalone（无 reuse 无 source）→ None。
        """
        config_path = await self._dump_auth_config(req, ws, scan_dir)
        # 黑盒 = 白盒下游 exploitation-only（阶段 2）：恒复用白盒结果，无 standalone/repo 兜底。
        # model_validator 已在请求层拦 reuse 缺失；此处工作层独立兜底（不依赖 pydantic，防 model 层被误改）。
        if not req.reuse_whitebox_scan_id:
            raise ValueError("blackbox 扫描必须复用白盒结果（reuse_whitebox_scan_id）")
        wb_scan_dir = self._store.get_scan_dir(ws, req.reuse_whitebox_scan_id)
        if wb_scan_dir is None:
            raise ValueError(f"要复用的白盒扫描不存在: {req.reuse_whitebox_scan_id}")
        repo_path: str | None = str(wb_scan_dir)
        return config_path, repo_path

    @staticmethod
    def _normalize_host_mapping_dict(mappings: Any, *, allow_empty: bool = False) -> dict[str, str]:
        """Validate and normalize either HostMapping objects, lists, or snapshot dicts."""
        if isinstance(mappings, dict):
            items = mappings.items()
        elif mappings is None:
            items = []
        else:
            items = (
                (m.get("host"), m.get("ip")) if isinstance(m, dict)
                else (getattr(m, "host", None), getattr(m, "ip", None))
                for m in mappings
            )
        normalized: dict[str, str] = {}
        for host, ip in items:
            mapping = HostMapping(ip=str(ip), host=str(host))
            previous = normalized.get(mapping.host)
            if previous is not None and previous != mapping.ip:
                raise ValueError(f"HOST host {mapping.host!r} maps to multiple IPs")
            normalized[mapping.host] = mapping.ip
        if not normalized and not allow_empty:
            raise ValueError("HOST 配置没有有效 mapping，拒绝回退到默认 DNS")
        return normalized

    @staticmethod
    def _host_config_mappings(host_config: dict | None) -> dict[str, str]:
        if not host_config:
            return {}
        if not host_config.get("enabled", True):
            return {}
        return ScanManager._normalize_host_mapping_dict(host_config.get("mappings"))

    def _session_host_mappings(self, data: dict) -> dict[str, str]:
        """Read the immutable snapshot; only legacy combined fields are fallback."""
        if "host_config" in data and data.get("host_config") is not None:
            cfg = data.get("host_config")
            if not isinstance(cfg, dict):
                raise ValueError("HOST snapshot 损坏，无法安全恢复")
            if not cfg.get("enabled", True):
                return {}
            return self._normalize_host_mapping_dict(cfg.get("mappings"))
        # Pre-snapshot combined scans stored this field; empty means legacy no-HOST.
        if "bb_host_mappings" in data:
            return self._normalize_host_mapping_dict(
                data.get("bb_host_mappings") or {}, allow_empty=True)
        return {}

    async def _resolve_host_config_sources(
        self, host_profile_ids: list[str] | None, host_url: str | None, ws: str,
    ) -> dict | None:
        """Resolve HOST sources (profile ids xor url) into an immutable snapshot.

        核心解析逻辑，扫描启动（经 ``_resolve_host_config`` 从 ScanRequest 取字段）
        与认证测试（选中 HOST → per-cred proxy；都不选 → 直连）共用——复用同一套
        refresh / warnings / fetch_and_parse_hosts，避免重复造轮子。

        多选（2026-09-11）：host_profile_ids 多档案逐个 refresh + 归一化后合并——
        同 host 同 IP 自然去重；同 host 不同 IP → ValueError 带两档案名 + host +
        两个 IP（用户能看出选错了哪两个环境档案），API 层转 422。快照
        profile_ids = 完整列表（detail 重跑预填吃），profile_id = 第一个（旧读方
        兼容）。单档案路径行为字节不变（含 per-档案 refresh 失败回落快照）。
        """
        if not host_profile_ids and host_url is None:
            return None

        warnings: list[str] = []
        if host_profile_ids:
            if self.host_profile_store is None:
                raise RuntimeError("host_profile_store 未注入，无法解析 HOST 档案")
            merged: dict[str, str] = {}
            # host -> (档案名, ip)：冲突定位报错用（同档案内冲突已被 store 校验拒绝）。
            owner: dict[str, tuple[str, str]] = {}
            source_urls: list[str] = []
            for pid in host_profile_ids:
                profile = self.host_profile_store.get(ws, pid)
                if profile is None:
                    raise ValueError(f"HOST 档案不存在: {pid}")
                if profile.source_url:
                    source_urls.append(profile.source_url)
                    try:
                        refreshed = await self.host_profile_store.refresh(ws, pid)
                        if refreshed is not None:
                            profile = refreshed
                        get_warnings = getattr(self.host_profile_store, "refresh_warnings", None)
                        if get_warnings is not None:
                            warnings.extend(get_warnings(ws, pid))
                    except HostProfileRefreshEmpty as exc:
                        raise ValueError(str(exc)) from exc
                    except Exception as exc:
                        if profile.mappings:
                            warnings.append(f"HOST profile refresh failed: {exc}")
                        else:
                            raise ValueError(f"HOST profile refresh failed: {exc}") from exc
                for host, ip in self._normalize_host_mapping_dict(profile.mappings).items():
                    prev = owner.get(host)
                    if prev is not None and prev[1] != ip:
                        raise ValueError(
                            f"HOST 档案映射冲突: {host} 在档案「{prev[0]}」指向 {prev[1]}"
                            f"，在档案「{profile.name}」指向 {ip}")
                    if prev is None:
                        owner[host] = (profile.name, ip)
                    merged[host] = ip
            single = len(host_profile_ids) == 1
            return {
                "enabled": True,
                "source": "profile",
                "profile_ids": list(host_profile_ids),
                "profile_id": host_profile_ids[0],
                # 兼容键：单档案 = 该档案来源（字节不变）；多档案各档来源见 source_urls。
                "source_url": source_urls[0] if single and source_urls else None,
                "source_urls": source_urls,
                "mappings": merged,
                "warnings": warnings,
                "resolved_at": time.time(),
            }

        mappings, fetch_warnings = await fetch_and_parse_hosts(host_url)
        normalized = self._normalize_host_mapping_dict(mappings)
        warnings.extend(fetch_warnings)
        return {
            "enabled": True,
            "source": "url",
            "profile_ids": [],
            "profile_id": None,
            "source_url": host_url,
            "mappings": normalized,
            "warnings": warnings,
            "resolved_at": time.time(),
        }

    @staticmethod
    def _coalesce_host_profile_ids(
        host_profile_id: str | None, host_profile_ids: list[str] | None,
    ) -> list[str] | None:
        """单/复数字段归一成 ids 列表（复数优先；空列表 = 未选 → None 直连）。"""
        if host_profile_ids is not None:
            return host_profile_ids or None
        return [host_profile_id] if host_profile_id else None

    async def _resolve_host_config(
        self, req: ScanRequest, ws: str,
    ) -> dict | None:
        """ScanRequest → source fields → 核心解析（薄封装，保签名兼容既有调用/测试）。"""
        return await self._resolve_host_config_sources(
            self._coalesce_host_profile_ids(req.host_profile_id, req.host_profile_ids),
            req.host_url, ws)

    async def _resolve_host_mappings(
        self, req: ScanRequest, ws: str,
    ) -> dict[str, str]:
        """Backward-compatible wrapper returning only the resolved mapping dict."""
        config = await self._resolve_host_config(req, ws)
        return self._host_config_mappings(config)

    async def _submit_blackbox(
        self, repo_path: str | None, ws: str, scan_id: str, scan_dir: Path,
        event_file: Path, web_url: str, config_path: str | None,
        host_mappings: dict[str, str] | None = None,
        workflow_id_suffix: str = "",
        correlated_workspace: str | None = None,
    ) -> Any:
        """提交黑盒 scan 到 supernova-bb-web queue。参照 _submit_whitebox。

        BlackboxPipelineInput.event_file 非 None → workflow 走 worker 路径（setup_display 注入
        StructuredEventRenderer 写 events.ndjson，web live 页可见）。workspaces_root 用 web 已知
        的 self._workspaces_dir（worker 容器共享同 volume，路径一致）。

        workflow_id_suffix（spec §7.6，组合接力复用本方法的关键）：默认 ""（零回归，既有调用
        workflow_id 不变）；组合接力首跑传 "-bb"、续跑传 "-bb-rerun-N"。不手写 chained 版
        （原草案手写版漏传 host_mappings 等字段，重复造轮子——见 spec §5）。

        correlated_workspace（跨仓关联 C1）：默认 None（零回归）；组合关联扫描传入关联
        workspace id，灌入 BlackboxPipelineInput（字段 B1 已定义）供黑盒复用其 topology。
        """
        from supernova_blackbox.pipeline.shared import BlackboxPipelineInput
        from supernova_blackbox.pipeline.workflows import BlackboxScanWorkflow
        from supernova_core.services.temporal_infra import WEB_TASK_QUEUE_BLACKBOX

        # 与白盒路径一致：配置不完整时在连接 Temporal 前失败。
        provider_config = self._resolve_provider_config(ws)
        client = await Client.connect(self._temporal_address())
        workflow_id = self._resolve_workflow_id(ws, scan_id) + workflow_id_suffix
        inp = BlackboxPipelineInput(
            web_url=web_url,
            repo_path=repo_path,
            workspace_name=scan_id,
            config_path=config_path,
            event_file=str(event_file),
            provider_config=provider_config,
            env_overrides=self._resolve_env_overrides(ws),
            workspaces_root=str(self._workspaces_dir),
            exploit=True,
            host_mappings=host_mappings or {},
            correlated_workspace=correlated_workspace,
        )
        handle = await client.start_workflow(
            BlackboxScanWorkflow.run, inp, id=workflow_id,
            task_queue=WEB_TASK_QUEUE_BLACKBOX,
            run_timeout=scan_budget(),
        )
        self._mark_submitted_at(scan_dir)
        return handle

    async def _submit_correlation(self, config_path: Path,
                                  repo_workspace_paths: dict[str, Path],
                                  out_ws_dir: Path, event_file: Path,
                                  ws: str) -> Any:
        """提交关联阶段 workflow 到 supernova-corr-web queue（跨仓关联 C2，镜像 _submit_whitebox）。

        config_path = correlation yaml（_resolve_correlation_yaml 产物，worker 侧
        parse_multi_repo_config 直读）；repo_workspace_paths = {service: 复用白盒 scan_dir}
        （_validate_reused_children 产物，worker 据此收集各仓 exploitation queue）；
        out_ws_dir = workspaces/<ws>/scans/<scan_id>（关联主行 scan 目录，worker 侧
        SessionManager 幂等建 workspace）；ws = 请求 workspace（event_file 所在 ws，
        provider/env 解析亦按它——yaml 的 out_workspace 已被 C3 覆写为主行 scan_id，
        非 ws）。write_scan_end 保持默认 False——终态由 web 编排收尾
        （_ensure_scan_end），worker 不写。
        """
        from supernova_multi.pipeline.workflows import CorrelationScanWorkflow
        from supernova_multi.pipeline.shared import CorrelationPipelineInput
        from supernova_core.services.temporal_infra import WEB_TASK_QUEUE_CORRELATION

        # 与白盒/黑盒路径一致：配置不完整时在连接 Temporal 前失败。
        provider_config = self._resolve_provider_config(ws)
        client = await Client.connect(self._temporal_address())
        workflow_id = self._resolve_workflow_id(ws, out_ws_dir.name) + "-corr"
        inp = CorrelationPipelineInput(
            config_path=str(config_path),
            repo_workspace_paths={k: str(v) for k, v in repo_workspace_paths.items()},
            out_ws_dir=str(out_ws_dir),
            event_file=str(event_file),
            provider_config=provider_config,
            env_overrides=self._resolve_env_overrides(ws),
        )
        # final-fix ④（Important）：run_timeout 必须严格大于 workflow 内 activity 的
        # start_to_close_timeout（CorrelationScanWorkflow 关联 activity 预算 4h）——
        # 裸 scan_budget()（默认 5h）会先掐死 4h activity，大 multi-edge run
        # 必 TIMED_OUT。取扫描预算与 4.5h（4h activity + 30min 余量）的较大者：预算
        # 调小（如 3h）时抬到 4.5h，预算 ≥4.5h 时尊重预算。wb/bb 提交不受影响（零回归）。
        corr_run_timeout = max(scan_budget(), timedelta(hours=4, minutes=30))
        handle = await client.start_workflow(
            CorrelationScanWorkflow.run, inp, id=workflow_id,
            task_queue=WEB_TASK_QUEUE_CORRELATION,
            run_timeout=corr_run_timeout,
        )
        # 提交成功后锚定 submitted_at（scan_liveness 提交宽限门防冷启动误杀；
        # start_workflow 抛错不达此处，提交失败不写）。
        self._mark_submitted_at(out_ws_dir)
        return handle

    async def start_auth_validation(self, ws: str, profile_id: str, cred_id: str,
                                    *, host_profile_id: str | None = None,
                                    host_profile_ids: list[str] | None = None,
                                    host_url: str | None = None) -> dict:
        """认证管理页"测试登录":写 probe scan-config.yaml + 起 AuthValidationWorkflow。

        probe 目录 = workspaces/<ws>/auth-probes/probe-<uuid8>，内含明文 scan-config.yaml
        （core 合流点 parse_config 直读 YAML，无对象通道——明文债收窄到此目录，get_result 后删）。
        workflow_id = authval-<ws>-probe-<uuid8>（与扫描 workflow namespace 隔离）。
        返 {workflow_id, probe_dir} dict（前端轮询 verify-status 端点需两者）。
        """
        import yaml
        from uuid import uuid4
        from supernova_blackbox.pipeline.shared import BlackboxAuthValidationInput
        from supernova_blackbox.pipeline.workflows import AuthValidationWorkflow
        from supernova_core.services.temporal_infra import WEB_TASK_QUEUE_BLACKBOX
        from .auth_profile_store import credential_to_authentication

        if self._auth_profile_store is None:
            raise RuntimeError("auth_profile_store 未注入，无法启动认证验证探针")
        profile = self._auth_profile_store.get(ws, profile_id)
        if profile is None:
            raise ValueError(f"认证档案不存在: {profile_id}")
        cred = next((c for c in profile.credentials if c.id == cred_id), None)
        if cred is None:
            raise ValueError(f"角色凭据不存在: {cred_id}")
        # 完整 provider 配置（base_url+key+模型）穿线——与黑盒/白盒扫描提交一致。
        # 仅传 api_key 会让 base_url/模型回落 worker env profile，key 与端点来自两套
        # 配置时 LLM 401（2026-08-17 NodeGoat 探针根因）。
        # 测试登录不降级（2026-08-17 决策）：工作区模型配置缺失/错误 → 直接抛（API 层
        # 转 422 provider_incomplete 指引去工作区设置）——没有可用模型就驱动不了登录
        # agent。原 except→None env 兜底会静默换一套 LLM 跑，掩盖配置问题。
        # 解析放在删旧 probe/写新 probe 之前：失败时不留明文 scan-config.yaml、不破坏回看产物。
        provider_config = self._resolve_provider_config(ws)
        # 块3c：覆盖清理——同 (profile,cred) 上次验证留的旧 probe（VerifyStatus.probe_dir）删掉，
        # 防 auth-probes/ 无限堆积（每次验证一个 probe-<uuid8>）。越界守护：只删 auth-probes/ 下的
        # （VerifyStatus 若被污染指向任意路径，不删——容器以 root 跑，防任意路径删除）。
        if cred.verify_status.probe_dir:
            import shutil
            old_probe = Path(cred.verify_status.probe_dir).resolve()
            allowed = (self._workspaces_dir / ws / "auth-probes").resolve()
            if old_probe.is_relative_to(allowed):
                shutil.rmtree(old_probe, ignore_errors=True)
        probe_id = f"probe-{uuid4().hex[:8]}"
        probe_dir = self._workspaces_dir / ws / "auth-probes" / probe_id
        probe_dir.mkdir(parents=True, exist_ok=True)
        auth = credential_to_authentication(profile, cred)
        cfg_file = probe_dir / "scan-config.yaml"
        cfg_file.write_text(
            yaml.safe_dump({"authentication": auth.model_dump(exclude_none=True, mode="json")},
                           allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )
        client = await Client.connect(self._temporal_address())
        # HOST 档案：选中（单/多选，_coalesce 归一）→ mappings（单 cred workflow 据此起
        # host proxy）；都不传 → {} 直连。
        host_mappings = self._host_config_mappings(
            await self._resolve_host_config_sources(
                self._coalesce_host_profile_ids(host_profile_id, host_profile_ids),
                host_url, ws))
        _env_ov = self._resolve_env_overrides(ws)
        inp = BlackboxAuthValidationInput(
            web_url=profile.login_url,
            config_path=str(cfg_file),
            workspace_path=str(probe_dir),
            api_key=provider_config.get("api_key") if provider_config else None,
            host_mappings=host_mappings,
            provider_config=provider_config,
            # 块1c：event_file 落点 = probe_dir/events.ndjson。workflow 经 setup_display 把
            # agent 登录每步写此文件（验证过程可见），verify-log 端点读它回看/实时观看。
            event_file=str(probe_dir / "events.ndjson"),
            env_overrides=_env_ov,
            probe_timeout_seconds=_auth_probe_timeout_seconds(_env_ov),
        )
        handle = await client.start_workflow(
            AuthValidationWorkflow.run, inp,
            id=f"authval-{ws}-{probe_id}", task_queue=WEB_TASK_QUEUE_BLACKBOX,
        )
        # 写 running 中间态——前端重载过程页时识别 state=running → 重挂 VerifyLivePanel 重连 SSE
        # 恢复实时观测（EventTailer 从头重放 events.ndjson 追上现实）。必须在 start_workflow 成功
        # 之后写，避免 connect/start 抛错致 running 滞留；终态由 get_auth_validation_result 覆盖回填。
        # workflow_id/probe_dir 与下方 return 同源，天然满足 get_auth_validation_result 的越界守护。
        from .auth_profile_store import VerifyStatus
        self._auth_profile_store.set_verify_status(
            ws, profile_id, cred_id,
            VerifyStatus(state="running", probe_dir=str(probe_dir), workflow_id=handle.id),
        )
        return {"workflow_id": handle.id, "probe_dir": str(probe_dir)}

    async def start_batch_auth_validation(self, ws: str, profile_id: str,
                                          cred_ids: list[str] | None, *,
                                          host_profile_id: str | None = None,
                                          host_profile_ids: list[str] | None = None,
                                          host_url: str | None = None) -> dict:
        """档案级批量认证验证(认证管理页"测试登录"多选角色):逐个独立验证每个选中角色能否登录。

        语义(对齐 spec §2):串行 N 次 Branch A 单次登录(非越权对比)。为每个选中 cred 建独立
        probe_dir + scan-config.yaml(role 不入 YAML)→ 起 BatchAuthValidationWorkflow(串行)→
        写首 cred running verify_status(前端轮询 profile 定位 running 订阅其 verify-events)→
        起 watcher 周期回填各 cred 终态。返回 {workflow_id}(batch workflow id)。

        cred_ids None/空 = 全选;cred_ids 子集 = 仅选中。cred_id 越界守护:必须属该 pid profile
        (防注入任意 id 越界)。各 cred 覆盖清理旧 probe(复用单 cred 覆盖逻辑,防 auth-probes/ 堆积)。
        """
        import shutil
        import yaml
        from uuid import uuid4
        from supernova_blackbox.pipeline.shared import (
            BlackboxAuthValidationBatchInput, BlackboxAuthValidationBatchItem)
        from supernova_blackbox.pipeline.workflows import BatchAuthValidationWorkflow
        from supernova_core.services.temporal_infra import WEB_TASK_QUEUE_BLACKBOX
        from .auth_profile_store import credential_to_authentication, VerifyStatus

        if self._auth_profile_store is None:
            raise RuntimeError("auth_profile_store 未注入，无法启动批量认证验证")
        profile = self._auth_profile_store.get(ws, profile_id)
        if profile is None:
            raise ValueError(f"认证档案不存在: {profile_id}")
        valid_ids = {c.id for c in profile.credentials}
        if cred_ids:
            bad = [i for i in cred_ids if i not in valid_ids]
            if bad:
                raise ValueError(f"角色凭据不属于该档案: {bad}")
            selected = [c for c in profile.credentials if c.id in set(cred_ids)]
        else:
            selected = list(profile.credentials)
        if not selected:
            raise ValueError("未选择任何角色凭据")
        # 同单 cred 探针：完整 provider 配置穿线；测试登录不降级（2026-08-17 决策）——
        # 工作区模型配置缺失/错误 → 直接抛（API 层转 422 provider_incomplete），不 env 兜底。
        # 解析放在删旧 probe/写新 probe 之前：失败时不留明文 scan-config.yaml、不破坏回看产物。
        provider_config = self._resolve_provider_config(ws)
        # 各 cred 覆盖清旧 probe + 建 probe_dir + 写 scan-config.yaml(role 不入 YAML)
        # HOST 档案：选中（单/多选，_coalesce 归一）→ mappings（每个 cred item 同值，
        # batch workflow 据此起 per-cred host proxy）；都不传 → {} 直连。解析一次复用
        # 到所有 item（同一不可变快照）。
        host_mappings = self._host_config_mappings(
            await self._resolve_host_config_sources(
                self._coalesce_host_profile_ids(host_profile_id, host_profile_ids),
                host_url, ws))
        allowed_parent = (self._workspaces_dir / ws / "auth-probes").resolve()
        items: list = []
        cred_probe_map: dict[str, dict] = {}
        for cred in selected:
            if cred.verify_status.probe_dir:
                old_probe = Path(cred.verify_status.probe_dir).resolve()
                if old_probe.is_relative_to(allowed_parent):
                    shutil.rmtree(old_probe, ignore_errors=True)
            probe_id = f"probe-{uuid4().hex[:8]}"
            probe_dir = self._workspaces_dir / ws / "auth-probes" / probe_id
            probe_dir.mkdir(parents=True, exist_ok=True)
            auth = credential_to_authentication(profile, cred)
            cfg_file = probe_dir / "scan-config.yaml"
            cfg_file.write_text(
                yaml.safe_dump({"authentication": auth.model_dump(exclude_none=True, mode="json")},
                               allow_unicode=True, sort_keys=False),
                encoding="utf-8",
            )
            items.append(BlackboxAuthValidationBatchItem(
                cred_id=cred.id,
                web_url=profile.login_url,
                config_path=str(cfg_file),
                workspace_path=str(probe_dir),
                event_file=str(probe_dir / "events.ndjson"),
                host_mappings=host_mappings,
            ))
            cred_probe_map[cred.id] = {"probe_dir": str(probe_dir)}
        inp = BlackboxAuthValidationBatchInput(
            items=items,
            api_key=provider_config.get("api_key") if provider_config else None,
            provider_config=provider_config,
            env_overrides=self._resolve_env_overrides(ws))
        client = await Client.connect(self._temporal_address())
        batch_wf_id = f"authval-batch-{ws}-{uuid4().hex[:8]}"
        handle = await client.start_workflow(
            BatchAuthValidationWorkflow.run, inp,
            id=batch_wf_id, task_queue=WEB_TASK_QUEUE_BLACKBOX,
        )
        # 写首 cred running —— 前端轮询 profile 定位 running → 订阅其 verify-events 实时观测。
        # 其余 cred 保持 unverified,watcher 在各 cred 终态时回填(避免一次写全 running 致前端误判并发)。
        first = selected[0]
        self._auth_profile_store.set_verify_status(
            ws, profile_id, first.id,
            VerifyStatus(state="running", probe_dir=cred_probe_map[first.id]["probe_dir"],
                         workflow_id=handle.id),
        )
        # 起 watcher(Slice 3):周期 query batch_progress → 回填各 cred 终态 verify_status + 删其
        # scan-config(保留 events.ndjson)。fire-and-forget;watcher 全终态后自退。
        asyncio.create_task(self._watch_batch_progress(
            ws, profile_id, handle.id, cred_probe_map))
        return {"workflow_id": handle.id}

    async def _watch_batch_progress(self, ws: str, profile_id: str, workflow_id: str,
                                    cred_probe_map: dict[str, dict]) -> None:
        """批量认证验证 watcher:周期(~2s)query batch_progress → 回填各 cred verify_status。

        分层(spec §4.4):blackbox activity 不调 web store;web 层本 watcher 周期 query temporal
        workflow 的 batch_progress handler,发现某 cred 刚终态 → set_verify_status + 删该 cred
        scan-config.yaml(密码卫生,保留 events.ndjson 供回看)+ probe_dir 越界守护。running 的 cred
        写 running verify_status(前端轮询 profile 定位 running 订阅其 verify-events)。全部终态
        (all_done)→ 退出。fire-and-forget(start_batch 起 asyncio.create_task)。

        query 抛错恢复(2026-08-17 单 cred batch 卡 running 根因):workflow 把最后 cred 置终态
        与 run() 返回(完成)在同一 workflow task 内,query 永远观测不到它的终态——下一次 query
        撞已完成 workflow 必抛错。describe 分流:终态 → result() 回填收尾;仍 RUNNING(Temporal
        抖动)→ 容错续轮询。不再一错即死(旧行为 except pass 静默吞,终态永不回填)。
        """
        from temporalio.client import WorkflowExecutionStatus
        from supernova_blackbox.pipeline.workflows import BatchAuthValidationWorkflow

        allowed_parent = (self._workspaces_dir / ws / "auth-probes").resolve()
        backfilled: set[str] = set()
        try:
            client = await Client.connect(self._temporal_address())
            handle = client.get_workflow_handle(workflow_id)
            while True:
                try:
                    progress = await handle.query(BatchAuthValidationWorkflow.batch_progress)
                except Exception as query_err:
                    try:
                        desc = await handle.describe()
                    except Exception:
                        _log.warning("batch watcher describe %s 失败,续轮询: %r",
                                     workflow_id, query_err)
                        await asyncio.sleep(2)
                        continue
                    if desc.status == WorkflowExecutionStatus.RUNNING:
                        await asyncio.sleep(2)  # 抖动 → 容错续轮询
                        continue
                    # 终态:最后 cred 的终态 query 观测不到 → result() 回填全部收尾
                    await self._backfill_batch_from_result(
                        handle, ws, profile_id, workflow_id,
                        cred_probe_map, allowed_parent, backfilled)
                    return
                for item in progress.get("items", []):
                    cred_id = item.get("cred_id")
                    if not cred_id or cred_id not in cred_probe_map:
                        continue  # 未追踪的 cred(防回填意外实体)
                    state = item.get("state")
                    probe_dir = cred_probe_map[cred_id]["probe_dir"]
                    if state in ("success", "failed"):
                        if cred_id in backfilled:
                            continue
                        self._apply_batch_cred_terminal(
                            ws, profile_id, cred_id, item, probe_dir, workflow_id, allowed_parent)
                        backfilled.add(cred_id)
                    elif state == "running":
                        # 首 cred 已在 start 写 running;后续 cred 在前一个终态后变 running → 补写
                        self._ensure_batch_cred_running(
                            ws, profile_id, cred_id, probe_dir, workflow_id)
                if progress.get("all_done"):
                    break
                await asyncio.sleep(2)
        except Exception:
            _log.exception("batch watcher %s 异常退出(verify_status 可能滞留 running,待启动对账收尾)",
                           workflow_id)

    async def _backfill_batch_from_result(self, handle, ws: str, profile_id: str,
                                          workflow_id: str, cred_probe_map: dict[str, dict],
                                          allowed_parent: Path, backfilled: set[str]) -> None:
        """workflow 终态后从 result() 回填(query 观测不到最后 cred 的终态,见 watcher 注释)。

        result=per-cred dict list;result() 抛(FAILED/CANCELED 等非 COMPLETED 终态)→ 无 per-cred
        结果可依:只把 store 中当前仍 running 的 cred 标 failed/out_of_band;unverified(从未开始,
        没测≠失败)与已终态(幂等不覆盖)不写状态,仅删其 scan-config(密码卫生,对齐
        reap_stale_probes 启动期清理)。幂等:backfilled 记录已回填 cred 不重写。"""
        try:
            raw = await handle.result()
        except Exception as e:
            raw = None
            fail_detail = f"{type(e).__name__}: {e}"
        profile = self._auth_profile_store.get(ws, profile_id) if self._auth_profile_store else None
        states = {c.id: c.verify_status.state for c in profile.credentials} if profile else {}
        for cred_id, entry in cred_probe_map.items():
            if cred_id in backfilled:
                continue
            if raw is None and states.get(cred_id) != "running":
                # 异常终态(取消/崩溃)且该 cred 不在跑:未开始或已终态 → 状态不动,只删明文配置
                self._delete_probe_scan_config(entry["probe_dir"], allowed_parent)
                continue
            item = next(
                (r for r in raw if isinstance(r, dict) and r.get("cred_id") == cred_id), None) \
                if raw is not None else None
            if item is None:
                item = {"cred_id": cred_id, "state": "failed", "failure_point": "out_of_band",
                        "failure_detail": fail_detail if raw is None
                        else f"batch result 缺 cred {cred_id} 条目"}
            self._apply_batch_cred_terminal(
                ws, profile_id, cred_id, item, entry["probe_dir"], workflow_id, allowed_parent)
            backfilled.add(cred_id)

    def _delete_probe_scan_config(self, probe_dir: str, allowed_parent: Path) -> None:
        """删 probe 的明文 scan-config.yaml(密码卫生,保留 events.ndjson)。越界 probe_dir 不动。"""
        resolved = Path(probe_dir).resolve()
        if not resolved.is_relative_to(allowed_parent):
            return  # 越界守护(防任意路径删除)
        cfg = resolved / "scan-config.yaml"
        if cfg.exists():
            try:
                cfg.unlink()
            except OSError:
                pass

    async def cancel_auth_validation(self, ws: str, profile_id: str,
                                     workflow_id: str) -> dict:
        """用户停止认证测试(批量/单 cred 通用,auth-test-cancel spec §3)。

        顺序:先回填状态后 cancel(Temporal 不可达也不卡 running)。
        1) 守护:workflow_id 须 authval-{ws}-/authval-batch-{ws}- 前缀且绑该档案某 cred;
        2) 绑此 wf 且 running 的 cred → failed/cancelled + 删 scan-config(保留 events);
           unverified 不动(没测≠失败;其残留 scan-config 由 watcher 终态回填时清理——
           probe_dir 不在 store,只有 running 过的 cred 才写);
        3) handle.cancel() best-effort(吞异常)。无 running → 幂等 already_finished,不 cancel。"""
        from .auth_profile_store import VerifyStatus
        if self._auth_profile_store is None:
            raise RuntimeError("auth_profile_store 未注入，无法取消认证验证")
        if not workflow_id.startswith((f"authval-{ws}-", f"authval-batch-{ws}-")):
            raise ValueError(
                f"workflow_id 越界(必须以 authval-{ws}- 或 authval-batch-{ws}- 开头): {workflow_id}")
        profile = self._auth_profile_store.get(ws, profile_id)
        if profile is None:
            raise ValueError(f"认证档案不存在: {profile_id}")
        bound = [c for c in profile.credentials
                 if c.verify_status.workflow_id == workflow_id]
        if not bound:
            raise ValueError(f"workflow 未绑定该档案任何凭据: {workflow_id}")
        allowed_parent = (self._workspaces_dir / ws / "auth-probes").resolve()
        running = [c for c in bound if c.verify_status.state == "running"]
        for cred in running:
            if cred.verify_status.probe_dir:
                self._apply_batch_cred_terminal(
                    ws, profile_id, cred.id,
                    {"cred_id": cred.id, "state": "failed", "failure_point": "cancelled",
                     "failure_detail": "用户取消测试"},
                    cred.verify_status.probe_dir, workflow_id, allowed_parent)
            else:  # 无 probe_dir(防御):直接写状态,无配置可删
                self._auth_profile_store.set_verify_status(
                    ws, profile_id, cred.id,
                    VerifyStatus(state="failed", failure_point="cancelled",
                                 failure_detail="用户取消测试",
                                 last_verified_at=datetime.now(timezone.utc).isoformat(),
                                 workflow_id=workflow_id))
        if not running:
            return {"cancelled": workflow_id, "already_finished": True}
        try:
            client = await Client.connect(self._temporal_address())
            await client.get_workflow_handle(workflow_id).cancel()
        except Exception:
            _log.warning("auth validation cancel %s: temporal 取消失败(best-effort,状态已回填)",
                         workflow_id, exc_info=True)
        return {"cancelled": workflow_id}

    def _iter_ws_names(self) -> list[str]:
        """workspaces/ 下用户 ws 名(跳点目录/文件;.system 档案只读 seed,无验证生命周期)。"""
        if not self._workspaces_dir.is_dir():
            return []
        return sorted(d.name for d in self._workspaces_dir.iterdir()
                      if d.is_dir() and not d.name.startswith("."))

    def _running_probe_dirs(self) -> set[Path]:
        """所有 state=running 凭据的 probe_dir(resolve 后)——启动清理须保护(验证仍在跑)。"""
        out: set[Path] = set()
        if self._auth_profile_store is None:
            return out
        for ws in self._iter_ws_names():
            try:
                profiles = self._auth_profile_store.read(ws)
            except Exception:
                continue
            for prof in profiles:
                for cred in prof.credentials:
                    vs = cred.verify_status
                    if vs.state == "running" and vs.probe_dir:
                        out.add(Path(vs.probe_dir).resolve())
        return out

    async def reconcile_auth_validation(self) -> int:
        """启动对账:watcher 随旧 web 进程死亡后,verify_status=running 的凭据成永久孤儿
        (batch 前端不轮询 verify-status → 页面永久卡"测试中",2026-08-17 单 cred batch 必现)。
        对齐 scan 的 reconcile_orphaned 语义:

        - workflow 已终态 → 回填(batch: per-cred result;单 cred: 复用 get_auth_validation_result)
        - workflow 仍 RUNNING → batch 重挂 watcher / 单 cred 起有界轮询续跟
        - workflow 查不到(Temporal 历史被清)→ failed/out_of_band(running 永无终态)
        - workflow_id 越界 → 跳过不动(不猜终态)

        返 0(未注入 store/无孤儿/Temporal 不可达)或回填数。best-effort:单组失败不阻断其余。
        """
        from temporalio.client import WorkflowExecutionStatus
        from .auth_profile_store import VerifyStatus
        if self._auth_profile_store is None:
            return 0
        # (ws, workflow_id) -> [(profile_id, cred_id, probe_dir)]
        groups: dict[tuple[str, str], list[tuple[str, str, str | None]]] = {}
        for ws in self._iter_ws_names():
            try:
                profiles = self._auth_profile_store.read(ws)
            except Exception:
                _log.warning("auth validation reconcile: 读 ws %s auth-profiles 失败,跳过", ws,
                             exc_info=True)
                continue
            for prof in profiles:
                for cred in prof.credentials:
                    vs = cred.verify_status
                    if vs.state != "running" or not vs.workflow_id:
                        continue
                    if not vs.workflow_id.startswith((f"authval-{ws}-", f"authval-batch-{ws}-")):
                        _log.warning("auth validation reconcile: cred %s/%s workflow_id 越界,跳过: %s",
                                     prof.id, cred.id, vs.workflow_id)
                        continue
                    groups.setdefault((ws, vs.workflow_id), []).append(
                        (prof.id, cred.id, vs.probe_dir))
        if not groups:
            return 0
        try:
            client = await Client.connect(self._temporal_address())
        except Exception:
            _log.exception("auth validation reconcile: Temporal 不可达,跳过(下次重启再对账)")
            return 0
        n = 0
        for (ws, wf_id), creds in groups.items():
            is_batch = wf_id.startswith(f"authval-batch-{ws}-")
            allowed_parent = (self._workspaces_dir / ws / "auth-probes").resolve()
            try:
                handle = client.get_workflow_handle(wf_id)
                desc = await handle.describe()
            except Exception as e:
                # workflow 不存在(历史被清/误删):running 永无终态 → 判 failed 结案
                detail = f"{type(e).__name__}: {e}"
                for profile_id, cred_id, probe_dir in creds:
                    self._auth_profile_store.set_verify_status(
                        ws, profile_id, cred_id,
                        VerifyStatus(state="failed", failure_point="out_of_band",
                                     failure_detail=f"workflow 不存在或不可查: {detail}",
                                     last_verified_at=datetime.now(timezone.utc).isoformat(),
                                     probe_dir=probe_dir, workflow_id=wf_id))
                    n += 1
                _log.warning("auth validation reconcile: %s 查不到, %d 个 running cred 判 failed",
                             wf_id, len(creds))
                continue
            if desc.status == WorkflowExecutionStatus.RUNNING:
                # 重启时验证真在跑:重挂跟踪(watcher 已随旧进程死亡)
                if is_batch:
                    profile_id = creds[0][0]
                    cred_probe_map = {cid: {"probe_dir": pd or ""} for _, cid, pd in creds}
                    asyncio.create_task(self._watch_batch_progress(
                        ws, profile_id, wf_id, cred_probe_map))
                else:
                    for profile_id, cred_id, probe_dir in creds:
                        asyncio.create_task(self._follow_single_auth_validation(
                            ws, profile_id, cred_id, wf_id, probe_dir or ""))
                _log.info("auth validation reconcile: %s 仍在跑,重挂跟踪(%d cred)", wf_id, len(creds))
                continue
            if is_batch:
                await self._backfill_batch_from_result(
                    handle, ws, creds[0][0], wf_id,
                    {cid: {"probe_dir": pd or ""} for _, cid, pd in creds},
                    allowed_parent, set())
                n += len(creds)
            elif desc.status == WorkflowExecutionStatus.COMPLETED:
                for profile_id, cred_id, probe_dir in creds:
                    try:
                        await self.get_auth_validation_result(
                            ws, wf_id, probe_dir or "", profile_id, cred_id)
                        n += 1
                    except Exception:
                        _log.exception("auth validation reconcile: 单 cred %s 回填失败", wf_id)
            else:
                # FAILED/CANCELLED/TERMINATED 等:running 永无 success → failed 结案
                for profile_id, cred_id, probe_dir in creds:
                    self._auth_profile_store.set_verify_status(
                        ws, profile_id, cred_id,
                        VerifyStatus(state="failed", failure_point="out_of_band",
                                     failure_detail=f"workflow 终态 {desc.status}",
                                     last_verified_at=datetime.now(timezone.utc).isoformat(),
                                     probe_dir=probe_dir, workflow_id=wf_id))
                    n += 1
            _log.info("auth validation reconcile: %s 终态对账完成", wf_id)
        return n

    async def _follow_single_auth_validation(self, ws: str, profile_id: str, cred_id: str,
                                             workflow_id: str, probe_dir: str,
                                             deadline_s: float = 900.0) -> None:
        """单 cred 验证重启续跟:周期 get_auth_validation_result 直到终态(有界防泄漏)。

        RUNNING → AuthValidationPending 续等;终态 → 内部已回填;不可恢复错误 → 放弃留待下次
        启动对账。fire-and-forget(reconcile 起 asyncio.create_task)。"""
        start = time.monotonic()
        while time.monotonic() - start < deadline_s:
            try:
                await self.get_auth_validation_result(
                    ws, workflow_id, probe_dir, profile_id, cred_id)
                return
            except AuthValidationPending:
                await asyncio.sleep(5)
            except Exception:
                _log.exception("follow single auth validation %s 失败,放弃(留待启动对账)",
                               workflow_id)
                return
        _log.warning("follow single auth validation %s 超时放弃(留待启动对账)", workflow_id)

    def _apply_batch_cred_terminal(self, ws: str, profile_id: str, cred_id: str, item: dict,
                                   probe_dir: str, workflow_id: str, allowed_parent: Path) -> None:
        """回填某 cred 终态 verify_status + 删其 scan-config(密码卫生)。越界 probe_dir 不动。"""
        from .auth_profile_store import VerifyStatus
        resolved = Path(probe_dir).resolve()
        if not resolved.is_relative_to(allowed_parent):
            return  # 越界守护:不回填不删(防 map 污染致任意路径删除)
        status = VerifyStatus(
            state="success" if item.get("state") == "success" else "failed",
            failure_point=item.get("failure_point"),
            failure_detail=item.get("failure_detail"),
            last_verified_at=datetime.now(timezone.utc).isoformat(),
            probe_dir=probe_dir,
            workflow_id=workflow_id,
        )
        self._auth_profile_store.set_verify_status(ws, profile_id, cred_id, status)
        cfg = resolved / "scan-config.yaml"
        if cfg.exists():
            try:
                cfg.unlink()
            except Exception:
                pass

    def _ensure_batch_cred_running(self, ws: str, profile_id: str, cred_id: str,
                                   probe_dir: str, workflow_id: str) -> None:
        """running 的 cred 若仍 unverified → 写 running(前端定位 running 订阅其 events)。
        幂等:已 running/终态不覆盖(首 cred start 已写;终态 watcher 已回填)。"""
        from .auth_profile_store import VerifyStatus
        profile = self._auth_profile_store.get(ws, profile_id)
        if profile is None:
            return
        cred = next((c for c in profile.credentials if c.id == cred_id), None)
        if cred is None or cred.verify_status.state != "unverified":
            return  # 已 running/终态 → 不覆盖
        self._auth_profile_store.set_verify_status(
            ws, profile_id, cred_id,
            VerifyStatus(state="running", probe_dir=probe_dir, workflow_id=workflow_id))

    async def get_auth_validation_result(
        self, ws: str, workflow_id: str, probe_dir: str,
        profile_id: str, cred_id: str,
    ) -> "VerifyStatus":
        """取 workflow result → 回填 verify_status → 删 probe 目录(含明文 YAML)。

        Temporal SDK 对 dataclass result 反序列化为实例（Task 2 实测），但保持双模解析
        （dict 兜底）以防御 SDK 版本差异。失败时 failure_point 缺失回落 out_of_band
        （对齐 validate_authentication.AUTH_VALIDATION_SCHEMA 的 enum）。

        try/finally 包裹:即使 Temporal fetch / set_verify_status 抛错,明文 probe 目录也必清
        （否则 scan-config.yaml 含明文密码会滞留磁盘至下次 worker 重启）。

        守护(2026-08-05 fix-wave):probe_dir 必须 resolve 到 workspaces/<ws>/auth-probes/ 下,
        workflow_id 必须以 authval-<ws>- 开头。二者均在校验失败时 ValueError(不 rmtree),
        防最低权限 workspace_member 经 verify-status 端点任意删路径 / 跨 ws 读结果。
        """
        from pathlib import Path
        from datetime import datetime, timezone
        from .auth_profile_store import VerifyStatus

        if self._auth_profile_store is None:
            raise RuntimeError("auth_profile_store 未注入，无法回填认证验证结果")
        # 守护①:probe_dir 必须在 workspaces/<ws>/auth-probes/ 下(防任意路径删除)。
        # get_workflow_handle(bogus_id).result() 对不存在 workflow 抛错 → finally 必跑,
        # 故纯 client-side 校验是唯一防线(不允许靠 Temporal 抛错触发 rmtree)。
        allowed_parent = (self._workspaces_dir / ws / "auth-probes").resolve()
        resolved_probe = Path(probe_dir).resolve()
        if not resolved_probe.is_relative_to(allowed_parent):
            raise ValueError(f"probe_dir 越界(必须在 {allowed_parent} 下): {probe_dir}")
        # 守护②:workflow_id 必须绑本 ws(start_auth_validation 产 authval-<ws>-probe-<uuid8>),
        # 防 ws-A 成员读 ws-B 的 auth 验证 workflow 结果(跨 ws 信息泄露)。
        if not workflow_id.startswith((f"authval-{ws}-", f"authval-batch-{ws}-")):
            raise ValueError(
                f"workflow_id 越界(必须以 authval-{ws}- 或 authval-batch-{ws}- 开头): {workflow_id}")
        try:
            client = await Client.connect(self._temporal_address())
            handle = client.get_workflow_handle(workflow_id)
            # 块2：describe() 非阻塞查状态；RUNNING → 抛 AuthValidationPending（端点转 503，
            # 前端继续轮询），绝不阻塞 result()——修轮询超时误判（workflow 跑 88–153s > 前端 120s
            # 上限，阻塞 result() 致 HTTP 挂死 → COMPLETED+success 被 UI 误判 failed）。终态才 result()。
            from temporalio.client import WorkflowExecutionStatus
            desc = await handle.describe()
            if desc.status == WorkflowExecutionStatus.RUNNING:
                raise AuthValidationPending(f"验证 workflow 仍在运行: {workflow_id}")
            raw = await handle.result()
            now = datetime.now(timezone.utc).isoformat()
            # 批量 workflow result = per-cred dict list(守护②已放行 authval-batch- 前缀,解析
            # 须同步支持):按 cred_id 精确取条目,不能按单 cred 语义误判(否则 list 无 success
            # 字段 → 恒 failed)。
            if isinstance(raw, list):
                entry = next(
                    (r for r in raw if isinstance(r, dict) and r.get("cred_id") == cred_id), None)
                if entry is None:
                    raise ValueError(f"批量 result 缺 cred {cred_id} 条目: {workflow_id}")
                status = VerifyStatus(
                    state="success" if entry.get("state") == "success" else "failed",
                    failure_point=entry.get("failure_point"),
                    failure_detail=entry.get("failure_detail"),
                    last_verified_at=now, probe_dir=probe_dir, workflow_id=workflow_id)
                self._auth_profile_store.set_verify_status(ws, profile_id, cred_id, status)
                return status
            # AuthValidationResult 经 Temporal 序列化:本 SDK 下为实例,dict 模式防御 SDK 差异。
            success = raw.get("success") if isinstance(raw, dict) else getattr(raw, "success", False)
            if success:
                status = VerifyStatus(state="success", last_verified_at=now,
                                      probe_dir=probe_dir, workflow_id=workflow_id)
            else:
                fp = (raw.get("failure_point") if isinstance(raw, dict)
                      else getattr(raw, "failure_point", None)) or "out_of_band"
                fd = (raw.get("failure_detail") if isinstance(raw, dict)
                      else getattr(raw, "failure_detail", None))
                status = VerifyStatus(
                    state="failed", failure_point=fp, failure_detail=fd, last_verified_at=now,
                    probe_dir=probe_dir, workflow_id=workflow_id,
                )
            self._auth_profile_store.set_verify_status(ws, profile_id, cred_id, status)
            return status
        finally:
            # 块3a：收窄清理——只删明文 scan-config.yaml（密码卫生），保留 events.ndjson +
            # auth-state.json 供 verify-log 回看/诊断（spec 块3）。整目录 rmtree 会清掉刚落的
            # 过程记录。用 resolved_probe（已校验在 allowed_parent 下）防 TOCTOU 改原始 probe_dir 串。
            cfg = resolved_probe / "scan-config.yaml"
            if cfg.exists():
                try:
                    cfg.unlink()
                except OSError:
                    pass

    async def get_auth_validation_log(
        self, ws: str, workflow_id: str, probe_dir: str, tail: int | None = None,
    ) -> list[dict]:
        """读 probe_dir/events.ndjson 验证过程记录（块3b）。越界守护同 get_result（probe_dir
        须在 workspaces/<ws>/auth-probes/ 下、workflow_id 须 authval-<ws>- 开头，防任意路径读 /
        跨 ws 读 events）。tail=N 取末 N 条（实时观看减传输）;默认全量（事后回看）。文件不存在 →
        []（workflow 未跑/未落盘，前端显示暂无记录）。非法 JSON 行容错跳过。
        """
        import json
        allowed_parent = (self._workspaces_dir / ws / "auth-probes").resolve()
        resolved_probe = Path(probe_dir).resolve()
        if not resolved_probe.is_relative_to(allowed_parent):
            raise ValueError(f"probe_dir 越界(必须在 {allowed_parent} 下): {probe_dir}")
        if not workflow_id.startswith((f"authval-{ws}-", f"authval-batch-{ws}-")):
            raise ValueError(
                f"workflow_id 越界(必须以 authval-{ws}- 或 authval-batch-{ws}- 开头): {workflow_id}")
        events_file = resolved_probe / "events.ndjson"
        if not events_file.exists():
            return []
        lines = [ln for ln in events_file.read_text("utf-8").splitlines() if ln.strip()]
        if tail is not None and tail > 0:
            lines = lines[-tail:]
        out: list[dict] = []
        for ln in lines:
            try:
                parsed = json.loads(ln)
            except (ValueError, TypeError):
                continue
            if isinstance(parsed, dict):
                out.append(parsed)
        return out

    async def auth_validation_events_path(
        self, ws: str, workflow_id: str, probe_dir: str,
    ) -> Path:
        """verify-events SSE 的落点解析 + 越界守护（块4）。

        复用 get_auth_validation_log 的两道守护（probe_dir 须在 workspaces/<ws>/auth-probes/
        下、workflow_id 须 authval-<ws>- 开头，防任意路径读 / 跨 ws 读 events），返回 resolved
        ``events.ndjson`` Path（文件可能尚未落盘——EventTailer 会等它出现）。守护失败 ValueError
        （端点转 403）。
        """
        allowed_parent = (self._workspaces_dir / ws / "auth-probes").resolve()
        resolved_probe = Path(probe_dir).resolve()
        if not resolved_probe.is_relative_to(allowed_parent):
            raise ValueError(f"probe_dir 越界(必须在 {allowed_parent} 下): {probe_dir}")
        if not workflow_id.startswith((f"authval-{ws}-", f"authval-batch-{ws}-")):
            raise ValueError(
                f"workflow_id 越界(必须以 authval-{ws}- 或 authval-batch-{ws}- 开头): {workflow_id}")
        return resolved_probe / "events.ndjson"


    def _resolve_provider_config(self, ws: str) -> dict:
        """P3c 阶段 2：per-ws 解析（ws_config_store）；None -> 全局 env 兜底（阶段1/CLI）。

        ws_config_store 非None 时严格使用 workspace-owned 字段并校验完整性，不从全局配置
        补字段。None（CLI/旧测试）走全局 env。
        """
        if self._ws_config_store is not None:
            from .ws_config_store import validate_ws_config
            validate_ws_config(self._ws_config_store.read(ws))
            return self._ws_config_store.resolve_provider_config(ws)
        from dataclasses import asdict
        from supernova_core.agents.providers import build_provider_config
        return asdict(build_provider_config())

    def _resolve_env_overrides(self, ws: str) -> dict[str, str]:
        """per-ws 扫描期 env 覆盖（scan_env 覆盖层用）；无配置且无定价覆盖时返 {}。

        定价覆盖（<ws>/pricing.override.json，spec 2026-08-28 §4.2）存在时追加
        SUPERNOVA_PRICING_OVERRIDE=<该文件路径> 并**压过** env 文本段手写键——
        覆盖 SSOT = 文件存在性，不写 ws config env 段（「文本=完整定义」回显契约，
        程序写键会被用户下次保存 env 文本静默清除）。无覆盖文件 → 手写键照常生效。
        """
        env: dict[str, str] = {}
        if self._ws_config_store is not None:
            env = self._ws_config_store.resolve_env_overrides(ws)
        pricing_override = self._workspaces_dir / ws / "pricing.override.json"
        if pricing_override.exists():
            env["SUPERNOVA_PRICING_OVERRIDE"] = str(pricing_override)
        return env

    def _resolve_llm_track(self, ws: str) -> bool:
        """enable_llm_track: ws env_overrides 的 LLM_TRACK 优先，否则全局 is_llm_track_enabled()。

        web 路径不经 CLI main.py（那里读 env 注入 input），故在此显式定型，使全局 .env 的
        LLM_TRACK 对 web 扫描也生效，且 ws 覆盖优先。
        """
        env_ov = self._resolve_env_overrides(ws)
        if "SUPERNOVA_LLM_TRACK_ENABLED" in env_ov:
            return env_ov["SUPERNOVA_LLM_TRACK_ENABLED"].strip().lower() not in {"0", "false", "no", "off"}
        from supernova_core.config.concurrency import is_llm_track_enabled
        return is_llm_track_enabled()

    def _snapshot_auth_ref(self, req: ScanRequest) -> dict:
        """认证明文不进 session.json（D2）。只存 profile_id（非敏感引用）；
        inline 模式存 None——认证明文已在 scan-config.yaml（t0 dump），不重复存。"""
        if req.auth_profile_id:
            return {"profile_id": req.auth_profile_id,
                    "cred_id": req.auth_credential_id,
                    "cred_ids": req.auth_credential_ids}
        return {"profile_id": None}  # inline 认证在 scan-config.yaml

    def _compute_expected_agents(self, req: ScanRequest) -> dict:
        """进度分母：预期白盒 agent 数（spec §9.5）。

        返回 {"whitebox": N}（blackbox 部分在黑盒 submit 时补，见 Task 4——黑盒只 exploit
        白盒发现的类，expected.blackbox 须等白盒 queue 已知才能算）。

        口径（够准即可，收起态精度门槛低，spec §9.2/§9.5）：
        - 白盒默认跑全部 5 vuln 类（inj/xss/ssrf/auth/authz）；
        - SUPERNOVA_LLM_TRACK_ENABLED=0 时，taint 类（inj/xss/ssrf，DEGRADABLE_VULN_CLASSES）
          的 vuln agent 关闭（GitNexus chain_verdict 主干兜底，非 vuln agent，不计入），
          authz/auth 的 LLM 全保留；故关轨时 vuln agent 数减少。
        - 固定骨架 agent：pre-recon + recon + attack-chain + report（与 vuln agent 无关，恒计）。

        N = 4（骨架）+ vuln_agent_count（开轨 5 / 关轨 2）。
        """
        from supernova_core.config.concurrency import is_llm_track_enabled
        from supernova_core.models.agents import ALL_VULN_CLASSES, DEGRADABLE_VULN_CLASSES

        # 白盒默认全跑（web ScanRequest 无 vuln_classes 选择入口）。
        selected = list(ALL_VULN_CLASSES)
        if is_llm_track_enabled():
            vuln_agent_count = len(selected)
        else:
            # 关轨：taint 类 vuln agent 关（GitNexus 兜底，非 vuln agent），仅 authz/auth 跑。
            vuln_agent_count = sum(1 for vc in selected
                                   if vc not in DEGRADABLE_VULN_CLASSES)
        # 骨架 agent（恒跑，与 vuln 类选择 / LLM 轨无关）：pre-recon / recon / attack-chain / report。
        skeleton = 4
        return {"whitebox": skeleton + vuln_agent_count}

    def _resolve_workflow_id(self, ws: str, scan_id: str) -> str:
        """T3: 读 scan_dir/session.json top-level resumeAttempts, 算 -resume-N 后缀。

        workflow_id = {ws}-{scan_id}[-resume-N]（新 scheme）。复用 worker.py
        resolve_workflow_id 语义(resume_attempt>0 加 -resume-N); web 端读 scan_dir
        session.json 算 n(等价 run_scan:209-224 的读法)。
        """
        scan_dir = self._workspaces_dir / ws / "scans" / scan_id
        session_file = scan_dir / "session.json"
        n = 0
        if session_file.exists():
            try:
                data = json.loads(session_file.read_text("utf-8"))
                attempts = data.get("resumeAttempts") or []
                if isinstance(attempts, list):
                    n = len(attempts)
            except (json.JSONDecodeError, OSError):
                n = 0
        base = f"{ws}-{scan_id}"
        return f"{base}-resume-{n}" if n > 0 else base

    def _resolve_run_workflow_id(self, ws: str, scan_id: str, run_id: str) -> str:
        """run 黑盒 workflow_id = 白盒 base + '-bb-{K}'（spec §7.6，取代旧 -bb/-bb-rerun-N）。

        优先读 run 子目录 events.ndjson 首行 WorkflowHeader.workflow_id（真实 temporal id，
        resume re-attach 用真值）；读不到则 base + '-bb-{K}'（K 从 run_id 派生）。
        """
        scan_dir = self._workspaces_dir / ws / "scans" / scan_id
        run_dir = blackbox_run_dir(scan_dir, run_id)
        wf = _read_workflow_id_from_ndjson(run_dir)
        if wf:
            return wf
        k = int(run_id.split("-")[1])
        return self._resolve_workflow_id(ws, scan_id) + f"-bb-{k}"

    def scan_status(self, ws: str, scan_id: str) -> str | None:
        """读 scan 当前对外状态（列表行同口径：_compute_status + 组合黑盒段合并）。

        批量取消端点的状态门用：cancel 自身无状态门（对任意状态裸调都会
        _mark_cancelled 覆写成 cancelled——单行按钮靠 UI 条件挡，批量必须服务端
        挡「勾选到确认之间任务自己跑完」的漂移）。不存在 -> None。
        """
        scan_dir = self._store.get_scan_dir(ws, scan_id)
        if scan_dir is None:
            return None
        mgr = SessionManager(scan_dir.parent)
        raw = _compute_status(scan_dir, mgr.get_status(scan_dir))
        data = mgr.get_session_data(scan_dir)
        bb_phase, _reason, _merged = merge_latest_run_view(scan_dir, data)
        return effective_scan_status(
            raw, data.get("combined"), bb_phase,
            post_hoc_runs=is_post_hoc_runs_task(data))

    async def cancel(self, ws: str, scan_id: str) -> dict | None:
        """取消 scan 三轨(C1 后):
        ① _handles 有(web 自起) -> handle.cancel()(temporal 原生, 传播到 workflow + heartbeat activity).
        ② heartbeat fresh(owner=host 在跑) -> 写 cancel.requested(协作式兜底, 兼容 host CLI).
        ③ heartbeat stale(已死) -> 标 cancelled + was_dead.

        scan_id 必填（scan-scoped DELETE /api/workspaces/{ws}/scans/{scan_id}）。ws 列表行无
        scan_id 的取消由前端 cancelActiveScan 先 listScans 解析出在跑 scan 再调本方法。
        web 侧立即返回(不等 worker 真退)-> 状态立即翻转 -> Delete 立即可用.
        """
        scan_dir = self._store.get_scan_dir(ws, scan_id)
        if scan_dir is None:
            return None  # scan 不存在 -> 404

        scan_key = (ws, scan_id)

        # ── 跨仓关联 cancel 级联（C4，spec 2026-08-24 §11）──────────────────────
        # correlation 主行按 scan_type 分流到 _cancel_correlation（编排协程 + 子仓/
        # 关联 workflow + 主行终态）。优先于 combined 检查：段③建黑盒 run 会给主行
        # session 写 combined=True（create_blackbox_run 副作用），但级联目标（现扫子仓
        # 白盒 + -corr 关联 workflow）与组合扫描不同，必须按行类型分派；组合行
        # scan_type=whitebox 不受影响（零回归）。
        if self._scan_row_is_correlation(scan_dir):
            return await self._cancel_correlation(ws, scan_id, scan_dir, scan_key)

        # ── 组合扫描 cancel（spec §11.5）──────────────────────────────────────
        # 按 bb_phase/bb_rerun_attempts 算 workflow_id → re-attach + handle.cancel()；
        # orchestrator task 一并取消（防后台接力继续 submit 黑盒/写 scan_end 与终态竞争）。
        # 零回归：仅 combined 真时触发；非组合走下方既有 ①②③ 轨不变。
        try:
            _combined = SessionManager(scan_dir.parent).get_session_data(scan_dir).get("combined")
        except Exception:  # noqa: BLE001 - session 读失败 → 当非组合处理（零回归）
            _combined = None
        if _combined:
            return await self._cancel_combined(ws, scan_id, scan_dir, scan_key)

        # ① web 自起: handle.cancel(temporal 原生) + _mark_cancelled 兜底标记.
        # 必须兜底: worker 的 workflow except CancelledError 分支不写 scan_end / 不更新
        # session(仅 try 正常完成分支调 finalize_summary)。web 不标 -> session 卡 running
        # (heartbeat stale 后误显 interrupted, 非 cancelled) + _watch 等不到 scan_end 永不
        # 退出 -> _handles 占死（闸门下沉 worker 后仅簿记泄漏，不再挡新扫描）。标终态则
        # _status_of 终态优先显 cancelled + _watch 见 scan_end 退出释放槽位(对齐 ②/③ 轨).
        handle = self._handles.get(scan_key)
        if handle is not None:
            try:
                await handle.cancel()
            except Exception:
                pass  # best-effort; temporal 侧 workflow cancel
            # terminate 保险丝（修 E2）：非 LLM 长 activity（code_index/auth probe/playwright）
            # 不经 run_claude_prompt 心跳层——「跑完当前 activity」窗口由保险丝兜底收口。
            self._spawn_cancel_fuse(self._resolve_workflow_id(ws, scan_id))
            await self._mark_cancelled(scan_dir)
            return {"cancelled": scan_id}
        # ②/③ 轨补真 cancel（2026-08-28 取消失效治本）：_handles 是 web 进程内存，重启即
        # 丢——owner=web 的在跑 scan 一旦 handle 丢失即落入此分支，而旧实现 ② 只写
        # cancel.requested（worker 容器路径的 activity start_heartbeat 不挂 on_cancel，
        # 协作信号无消费者＝死信）、③ 纯标记，worker 永不停止（NodeGoat-20260827-103736
        # 跑 25h 实证）。对齐 _cancel_combined 既有模式：re-attach + handle.cancel()
        # best-effort（temporal 不可达/已终态不阻断标 cancelled）；cancel.requested 照写
        # （host CLI 路径 HeartbeatManager on_cancel 消费 + worker 容器协作桥兜底）。
        await self._temporal_cancel_best_effort(ws, scan_id)
        # ②/③ owner=host 或已死:标 cancelled(③ 不写协作式信号)
        if is_scan_recently_active(scan_dir):
            (scan_dir / "cancel.requested").write_text("", encoding="utf-8")
            await self._mark_cancelled(scan_dir)
            return {"cancelled": scan_id, "via": "signal"}
        await self._mark_cancelled(scan_dir)
        return {"cancelled": scan_id, "was_dead": True}

    async def delete(self, ws: str, scan_id: str) -> dict | None:
        """删除单个 scan（真删目录，spec §5.1 DELETE）。

        running scan -> ScanRunning（端点转 409，先 cancel 再删，避免删在跑 workflow 的目录致
        _watch describe 不存在的 workflow）；不存在 -> None（端点 404）。
        删除范围由 ScanStore.delete_scan 决定（源①整删 scans/<id>/，源② legacy 根仅删产物保 ws 壳）。
        """
        scan_dir = self._store.get_scan_dir(ws, scan_id)
        if scan_dir is None:
            return None
        mgr = SessionManager(scan_dir.parent)
        if _compute_status(scan_dir, mgr.get_status(scan_dir)) in {
                "running", "queued", "reconnecting"}:
            raise ScanRunning(scan_id)
        # bb_runs 非终态（手动加的黑盒 run 在跑/待跑）同样拒删：任务级 running 门通常已拦
        # （_add_blackbox_run 会把任务级标 running），此门防 race 与 legacy 状态（run 在跑
        # 而任务级停终态的旧数据）。取消（_cancel_combined 标 run cancelled）后可删。
        runs = mgr.get_session_data(scan_dir).get("bb_runs") or []
        if any(r.get("status") not in _RUN_TERMINAL_STATUSES for r in runs):
            raise ScanRunning(scan_id)
        # 防御：清残留登记（非 running 时 _watch finally 通常已清，此处兜底防异常路径泄漏）。
        scan_key = (ws, scan_id)
        self._handles.pop(scan_key, None)
        self._tasks.pop(scan_key, None)
        self._active_reqs.pop(scan_key, None)
        self._orchestrator_tasks.pop(scan_key, None)  # 组合接力 task（已 self-pop，兜底）
        self._store.delete_scan(ws, scan_id)
        return {"deleted": scan_id}

    async def delete_blackbox_run(self, ws: str, wb_scan_id: str, run_id: str) -> dict | None:
        """删单个黑盒 run（spec §7.1 #4，DELETE /blackbox-runs/{run_id} 的 manager 包装）。

        运行中 run（run 级 session status 非终态）-> ScanRunning（端点转 409，先 cancel 再删）；
        run 不存在 -> None（端点 404）。终态 -> store.delete_blackbox_run（rmtree run + combined +
        移除 bb_runs[] 条目 + latest 回退）。删的是 latest 则 store 已回退到上一个 run。
        """
        run_dir = self._store.get_blackbox_run_dir(ws, wb_scan_id, run_id)
        if run_dir is None:
            return None
        # 运行中拒删（同 scan 级 delete 的 ScanRunning 口径）：run 级 status 非终态 = 在跑/待跑。
        data = SessionManager(run_dir.parent).get_session_data(run_dir)
        if data.get("status") not in _RUN_TERMINAL_STATUSES:
            raise ScanRunning(run_id)
        self._store.delete_blackbox_run(ws, wb_scan_id, run_id)
        return {"deleted": run_id}

    def _mark_owner(self, scan_dir: Path, owner: str) -> None:
        """标 scan session.json owner(web/host)。best-effort:子进程 MetricsTracker 用
        dict(existing) 浅拷贝保留 top-level key。owner 只服务 cancel 分轨诊断。"""
        session_file = scan_dir / "session.json"
        try:
            data = json.loads(session_file.read_text("utf-8")) if session_file.exists() else {}
            if not isinstance(data, dict):
                data = {}
            data["owner"] = owner
            session_file.write_text(json.dumps(data), encoding="utf-8")
        except (OSError, ValueError):
            pass

    def _mark_submitted_at(self, scan_dir: Path) -> None:
        """提交成功后写 scan session.json submitted_at(scan_liveness 提交宽限门锚点, 防冷启动误杀).

        best-effort read-modify-write(与 _mark_owner 同模式); 仅 _submit_whitebox 提交成功后调.
        每次 start_workflow 提交刷新 -> resume 场景也准确(resume 时 created_at 是原始建 scan 时间,
        不能用作「最近提交」锚点).
        """
        session_file = scan_dir / "session.json"
        try:
            data = json.loads(session_file.read_text("utf-8")) if session_file.exists() else {}
            if not isinstance(data, dict):
                data = {}
            data["submitted_at"] = time.time()
            session_file.write_text(json.dumps(data), encoding="utf-8")
        except (OSError, ValueError):
            pass

    async def _temporal_cancel_best_effort(self, ws: str, scan_id: str) -> None:
        """re-attach + handle.cancel()，best-effort（②③ 轨取消传导）。

        _resolve_workflow_id 解析真实 temporal id（events.ndjson 首行 WorkflowHeader，
        resume -resume-N 后缀），不依赖 web 进程内存 _handles。temporal 不可达 /
        workflow 不存在或已终态（cancel 抛错）均吞掉——取消标记流程照常走，前端照常
        翻转 cancelled（对齐 _cancel_combined 的 best-effort 语义）。
        """
        try:
            wf_id = self._resolve_workflow_id(ws, scan_id)
            client = await Client.connect(self._temporal_address())
            handle = client.get_workflow_handle(wf_id)
            await handle.cancel()
        except Exception:  # noqa: BLE001 - best-effort; 不可达/已终态均不阻断
            pass

    async def _mark_cancelled(self, scan_dir: Path) -> None:
        """标 session.status=cancelled + completed_at + 写 scan_end(若无)。让 _status_of
        因终态优先立即返 cancelled(列表/详情翻转,Delete 立即可用)。"""
        event_file = scan_dir / "events.ndjson"
        if not self._has_scan_end(event_file):
            await self._write_scan_end(event_file, "cancelled", -1, "用户取消(web Cancel)")
        try:
            SessionManager(scan_dir.parent).update_session(
                scan_dir, {"status": "cancelled", "completed_at": time.time()})
        except Exception:  # noqa: BLE001 - 标记是 best-effort,不阻塞 cancel
            pass

    def _spawn_cancel_fuse(self, wf_id: str) -> None:
        """挂 terminate 保险丝（修 E2，fire-and-forget）：cancel 后 _CANCEL_FUSE_DELAY
        仍 RUNNING 且 run_id 未变 → 升级 terminate。run_id 复查防「cancel 后重建同 id
        workflow」误杀（-corr 固定 id 场景的硬需求）。"""
        task = asyncio.create_task(self._cancel_fuse(wf_id))
        self._cancel_fuse_tasks.add(task)
        task.add_done_callback(self._cancel_fuse_tasks.discard)

    async def _cancel_fuse(self, wf_id: str) -> None:
        try:
            client = await Client.connect(self._temporal_address())
            handle = client.get_workflow_handle(wf_id)
            first = await handle.describe()
            first_run_id = getattr(first, "run_id", None)
            await asyncio.sleep(_CANCEL_FUSE_DELAY)
            desc = await handle.describe()
            status = getattr(desc, "status", None)
            if getattr(status, "name", str(status)) != "RUNNING":
                return  # 已停（CANCELED/COMPLETED/...）——原生取消生效
            if getattr(desc, "run_id", None) != first_run_id:
                return  # 同 id 重建，不是当初那个执行 → 不误杀
            await handle.terminate(
                reason="cancel fuse: workflow still RUNNING after cancel grace")
        except Exception:  # noqa: BLE001 - 保险丝 best-effort，不阻断
            pass

    async def _mark_submission_failed(
        self, scan_dir: Path, event_file: Path, error: BaseException
    ) -> None:
        """Finalize a scan whose directory exists but whose workflow was not submitted."""
        try:
            if self._has_scan_end(event_file):
                SessionManager(scan_dir.parent).update_session(
                    scan_dir, {"status": "failed", "completed_at": time.time()})
            else:
                await self._write_scan_end(
                    event_file, "failed", -1, str(error),
                    session_status="failed", scan_dir=scan_dir)
        except Exception:  # noqa: BLE001 - cleanup must not hide the original submit error
            _log.exception("failed to finalize scan submission failure: %s", scan_dir)

    # ---- 钩子（可 monkeypatch）----
    def _temporal_address(self) -> str:
        """SUPERNOVA_TEMPORAL_HOST:PORT（默认 localhost:7233）。web 容器内 temporal 在
        compose 服务名 `temporal` 上(非 localhost), Client.connect 必须用它."""
        host = os.environ.get("SUPERNOVA_TEMPORAL_HOST", "localhost")
        port = int(os.environ.get("SUPERNOVA_TEMPORAL_PORT", "7233"))
        return f"{host}:{port}"

    async def _await_workflow_result(self, handle: Any,
                                     attempts: int = 5,
                                     backoff_base: float = 2.0) -> Any:
        """await workflow 终态，对长轮询瞬态 RPC 错误重取 handle 续等。

        temporalio 的 handle.result() 走 GetWorkflowExecutionHistory 长轮询，core 对
        UserLongPoll 每次 poll 有 70s 硬 gRPC 超时且 DeadlineExceeded 不重试（对比
        TaskLongPoll 放行）——一次网络抖动即抛 "context deadline exceeded"，曾致组合
        扫描黑盒 run 被误标 failed（workflow 服务端仍在跑，NodeGoat-20260817-132940）。
        DEADLINE_EXCEEDED / UNAVAILABLE 视为瞬态：退避后重取 handle 继续 result()（新
        handle 从头拉 history 再续等，语义无损）。其余错误（含 WorkflowFailureError，
        非 RPCError）原样上抛。"""
        from temporalio.service import RPCError, RPCStatusCode
        workflow_id = handle.id
        for attempt in range(attempts):
            try:
                return await handle.result()
            except RPCError as exc:
                transient = exc.status in (
                    RPCStatusCode.DEADLINE_EXCEEDED, RPCStatusCode.UNAVAILABLE)
                if not transient or attempt == attempts - 1:
                    raise
                _log.warning(
                    "workflow %s result() 瞬态 RPC 错误(%s)，第 %d/%d 次重试",
                    workflow_id, exc.status.name, attempt + 2, attempts)
                await asyncio.sleep(backoff_base ** attempt)
                client = await Client.connect(self._temporal_address())
                handle = client.get_workflow_handle(workflow_id)
        raise AssertionError("unreachable")

    @staticmethod
    def _workflow_result_status(result: Any) -> str | None:
        """workflow 返回值业务 status 双形态读取（dict 或 PipelineState dataclass）。

        temporalio 按返回类型注解反序列化：start_workflow(XxxWorkflow.run) 的
        handle.result() 返回 dataclass 实例而非 dict（无类型 handle 才是 dict）——
        isinstance(result, dict) 单分支对真实形态恒 False，曾致黑盒 run 终态漏判
        failed、被标 completed（2026-09-11 NodeGoat-20260911-032558 口径矛盾根因）。
        照搬 _combined_orchestrator 白盒双形态范式收编各 run 终态消费点。"""
        if isinstance(result, dict):
            return result.get("status")
        return getattr(result, "status", None)

    @staticmethod
    def _workflow_result_error(result: Any) -> str:
        """workflow 返回值失败原因双形态读取（对齐 _workflow_result_status）。

        dict 分支兼容测试 mock 的 error 单键；dataclass 分支取 errors 列表 join /
        error_code（真实 BlackboxPipelineState 字段），兜底文案与调用方原值一致。"""
        if isinstance(result, dict):
            return str(result.get("error")
                       or "; ".join(result.get("errors") or [])
                       or "blackbox workflow failed")
        errs = getattr(result, "errors", None) or []
        if errs:
            return "; ".join(errs)
        return str(getattr(result, "error_code", None)
                   or "blackbox workflow failed")

    async def _check_temporal(self) -> None:
        import socket

        host = os.environ.get("SUPERNOVA_TEMPORAL_HOST", "localhost")
        port = int(os.environ.get("SUPERNOVA_TEMPORAL_PORT", "7233"))

        def _probe() -> bool:
            try:
                with socket.create_connection((host, port), timeout=1.0):
                    return True
            except OSError:
                return False

        loop = asyncio.get_running_loop()
        if not await loop.run_in_executor(None, _probe):
            raise TemporalUnavailable()

    # ---- 内部 ----
    async def _resolve_inputs(self, req: ScanRequest) -> tuple[str | None, Path | None]:
        target: str | None = None
        yaml_path: Path | None = None
        if req.source is not None:
            if req.source.kind == "repo":
                target = self._resolve_repo_path(req.workspace, req.source.value)
            else:  # path
                target = req.source.value
        if req.type == "correlation":
            yaml_path = await self._resolve_correlation_yaml(req)
        return target, yaml_path

    def _maybe_write_repo_snapshot(self, req: ScanRequest, target: str | None,
                                   scan_dir: Path) -> None:
        """repo 来源提交时写 repo-snapshot.json（快照逻辑在 scan_store）。

        非 repo 来源（url/黑盒 reuse 的 source=None）不写；correlation 走 yaml 多仓、
        但其 source=repo 时 target 仍为单仓路径，写快照属实无害。"""
        if req.source is None or req.source.kind != "repo" or not target:
            return
        write_repo_snapshot(scan_dir, target)

    def _resolve_repo_path(self, ws: str, name: str) -> str:
        """将 repo 名（可为 group/repo）解析为 workspaces/<ws>/repos 内绝对路径，
        并校验 state==ready。

        T3: P2 隔离后 repo 路径从全局 repos/ 改为 workspaces/<ws>/repos（RepoManager
        per-ws 落地）；ws 来自 P1 的 req.workspace（scan 路由已校验 ws 存在 + 用户为
        成员），这里再过一道 _validate_ws_segment 是 defense-in-depth（与 RepoManager
        ._repos_root 同档约束）。
        """
        _validate_ws_segment(ws)
        # 关联仓库优先：命中 linked_repos.json → 返回其存储路径（无 state 校验，关联仓库
        # 无 clone 状态；多 ws 可共享同一路径）。name 与私有克隆不重名（link 时禁碰撞）。
        linked = resolve_linked_repo_path(self._workspaces_dir, ws, name)
        if linked is not None:
            return linked
        repo_dir = _resolve_repo_dir(self._workspaces_dir / ws / "repos", name)
        if not repo_dir.is_dir():
            raise ValueError(f"仓库不存在：{name}")
        meta_file = repo_dir / ".supernova-repo.json"
        state = "ready"
        if meta_file.exists():
            try:
                state = json.loads(meta_file.read_text("utf-8", errors="replace")).get("state", "ready")
            except json.JSONDecodeError:
                state = "ready"  # 元数据损坏不阻塞扫描
        if state != "ready":
            raise ValueError(f"仓库未就绪（state={state}），请先在 ws 内完成 clone")
        return str(repo_dir)

    async def _resolve_correlation_yaml(self, req: ScanRequest) -> Path:
        assert self._config_store is not None, "correlation 需 config_store"
        if req.config_name:
            # 走 store 的校验路径(禁止 "/" / ".." / 空), 不能直接拼 web-multi-{name}.yaml
            # 否则 config_name="../evil" 路径遍历绕过 store 校验.
            return self._config_store.path_for(req.config_name)
        if req.config_content:
            if req.save_as:
                return self._config_store.write(req.save_as, req.config_content)
            # final-fix ①：表单 yaml（formToYaml 产物，无 correlation 段）须注入后
            # 写 temp——store 的 validate 跑 parse_multi_repo_config，无段内容在此
            # 422（表单提交的首发现场）。save_as 存档路径保持原文 verbatim 不注入。
            return self._config_store.write_temp(
                _corr_yaml_text_with_default_section(req.config_content))
        raise ValueError("correlation 扫描需 config_name 或 config_content")

    def _validate_reused_children(self, ws: str,
                                  config: MultiRepoConfig) -> dict[str, Path]:
        """校验 correlation yaml 里每个 spec.workspace 复用子仓（跨仓关联 C2）。

        逐 service 检查三项：① get_scan_dir(ws, spec.workspace) 存在；② session
        scan_type == "whitebox"（只有白盒产物可作关联输入）；③ deliverables/ 下至少
        一个 *_exploitation_queue.json（_find_queue_files 三处 glob，同 orchestrator
        收集口径）。全部通过 → 返回 {service: scan_dir}（供 _submit_correlation 的
        repo_workspace_paths）；任一不合法 raise ValueError（API 层转 422，前端提示
        改重新扫）。path 型 repo（spec.workspace 为空，白盒新扫）不参与复用校验。
        """
        out: dict[str, Path] = {}
        for service, spec in config.repos.items():
            reused_id = spec.workspace
            if not reused_id:
                continue  # path 型 repo（关联时新扫白盒），非复用子仓
            scan_dir = self._store.get_scan_dir(ws, reused_id)
            if scan_dir is None:
                raise ValueError(
                    f"复用扫描不可用: {service}: 复用的扫描不存在: {reused_id}")
            scan_type = SessionManager(scan_dir.parent).get_scan_type(scan_dir)
            if scan_type != "whitebox":
                raise ValueError(
                    f"复用扫描不可用: {service}: 复用的扫描类型为 {scan_type}，"
                    f"需白盒（{reused_id}）")
            if not _find_queue_files(deliverables_dir_for_workspace(scan_dir)):
                raise ValueError(
                    f"复用扫描不可用: {service}: deliverables 下无 "
                    f"*_exploitation_queue.json（白盒无可利用产物，请重新扫描）")
            out[service] = scan_dir
        return out

    async def _watch(self, scan_key: tuple[str, str], event_file: Path,
                     scan_dir: Path) -> None:
        """C1: tail events.ndjson 直到 scan_end(worker finalize_summary 写)或超时.

        T3: scan_key=(ws, scan_id) 用于 _handles 查询；scan_dir 用于 session-status 同步。
        session-status 同步:周期 handle.describe() 轮询 workflow 状态,发现 FAILED /
        TIMED_OUT / TERMINATED 时(worker 进程崩溃/容器死/被 terminate,workflow except
        跑不到)自行写 scan_end + session.status=failed.
        """
        from temporalio.client import WorkflowExecutionStatus
        # describe() 见到的终态集合 -> 标 failed
        _FAILED_STATES = {
            WorkflowExecutionStatus.FAILED,
            WorkflowExecutionStatus.TIMED_OUT,
            WorkflowExecutionStatus.TERMINATED,
        }
        cancelled = False  # web 关停 cancel：跳过 finally 的 crashed 兜底（见 except）
        try:
            deadline = (time.monotonic() + self._scan_timeout) if self._scan_timeout > 0 else None
            describe_tick = 0
            while not self._has_scan_end(event_file):
                if deadline is not None and time.monotonic() > deadline:
                    if not self._has_scan_end(event_file):
                        await self._write_scan_end(event_file, "timeout", -1, "web 超时收尾")
                    break
                # 每 ~15s describe 一次(0.5s sleep × 30 = 15s)
                describe_tick += 1
                if describe_tick >= 30:
                    describe_tick = 0
                    handle = self._handles.get(scan_key)
                    if handle is not None:
                        try:
                            desc = await handle.describe()
                            if desc.status in _FAILED_STATES:
                                await self._write_scan_end(
                                    event_file, "failed", -1,
                                    f"workflow {desc.status.name}",
                                    session_status="failed", scan_dir=scan_dir,
                                )
                                break
                        except Exception:
                            pass  # temporal 断连等:忽略,下个 tick 重试
                await asyncio.sleep(0.5)
        except asyncio.CancelledError:
            # web 进程关停取消 tail 循环：_watch 死 ≠ workflow 死——"worker 未写 scan_end"
            # 的 crashed 兜底只对 workflow 真死成立，此时补写会把 Temporal 里还活着的扫描
            # 打成 crashed（2026-09-18 假终态事故同源）。不写，留 running 交
            # orphan_reconcile 按 Temporal 状态收口。re-raise 保 task 取消语义。
            cancelled = True
            raise
        finally:
            # 兜底: 若 worker 未写 scan_end(异常/crash), 补一条（web 关停 cancel 例外，
            # 见 except CancelledError）
            if not cancelled and not self._has_scan_end(event_file):
                await self._write_scan_end(event_file, "crashed", -1, "worker 未写 scan_end")
            # 清理登记必须兜底: 即便 _write_scan_end 抛出, _handles/_tasks/_active_reqs 也得释放,
            # 否则 active_repo_sources() 误报引用.
            self._handles.pop(scan_key, None)
            self._tasks.pop(scan_key, None)
            self._active_reqs.pop(scan_key, None)
            # 扫完即删（2026-09-10）：扫描终态触发该 ws 的仓库级 sweep。放在登记
            # 清理之后——本扫描不再自锁仓库；best-effort，失败不影响 _watch 收尾。
            await self._sweep_ws_quiet(scan_key[0])

    @staticmethod
    def _has_scan_end(event_file: Path) -> bool:
        if not event_file.exists():
            return False
        for line in event_file.read_text("utf-8", errors="replace").splitlines()[-5:]:
            try:
                if json.loads(line).get("type") == "scan_end":
                    return True
            except json.JSONDecodeError:
                continue
        return False

    async def _write_scan_end(self, event_file: Path, status: str,
                              returncode: int, stderr_tail: str,
                              session_status: str | None = None,
                              scan_dir: Path | None = None) -> None:
        payload = {
            "ts": _now_iso(), "category": "CONTROL", "type": "scan_end",
            "status": status, "returncode": returncode, "stderr_tail": stderr_tail,
        }
        # session-status 同步:先写 session.json 再写 events.ndjson -- 若 session 写失败,
        # events 不写(_watch 下个 describe tick 重试);若 session 成功而 events 失败,
        # session 已是终态(failed),finally 的 crashed 兜底补 events(scan_end)。
        # (顺序反过来会让 events 有 scan_end 而 session 永远 running = 重现 ghost-scan)
        if session_status and scan_dir is not None:
            SessionManager(scan_dir.parent).update_session(
                scan_dir, {"status": session_status, "completed_at": time.time()})
        async with aiofiles.open(event_file, "a") as fh:
            await fh.write(json.dumps(payload, ensure_ascii=False) + "\n")

    @staticmethod
    def _strip_trailing_scan_end(event_file: Path) -> None:
        """剥掉 events.ndjson 末尾的 scan_end 行（resume 续跑前清障，让 _watch 能 tail 新 workflow）。

        中断/崩溃时 orphan_reconciler/_watch 在末尾写了 scan_end；resume 续跑后 _watch 的
        _has_scan_end 会因旧 scan_end 立即返 True 而退出，无法跟踪新 workflow。故续跑前移除
        末尾连续的 scan_end 行（保留之前的事件历史）。文件不存在则 no-op。
        """
        if not event_file.exists():
            return
        try:
            lines = event_file.read_text("utf-8", errors="replace").splitlines()
        except OSError:
            return
        while lines:
            try:
                if json.loads(lines[-1]).get("type") == "scan_end":
                    lines.pop()
                    continue
            except (json.JSONDecodeError, ValueError):
                pass
            break
        event_file.write_text(
            ("\n".join(lines) + "\n") if lines else "", encoding="utf-8")

    # ── 组合扫描接力编排（spec §7，Task 4）───────────────────────────────────

    async def _cancel_combined(self, ws: str, scan_id: str, scan_dir: Path,
                               scan_key: tuple[str, str]) -> dict:
        """组合扫描 cancel（spec §11.5）：按 latest run 状态算 workflow_id → re-attach +
        handle.cancel()；orchestrator task 一并取消 + 标终态 cancelled。

        取消目标：latest run 非终态且 phase=running → {ws}-{scan_id}-bb-{K}；否则 →
        {ws}-{scan_id}（白盒，白盒阶段取消/legacy）。precheck workflow（-authcheck）另做
        无条件 best-effort 取消（pending/precheck 段唯一在跑的 workflow）。

        orchestrator task（_orchestrator_tasks 登记）取消：防后台接力继续 submit 黑盒 / 写
        scan_end 与 _mark_cancelled 终态竞争。_handles 同步清（白盒 handle 残留 running 阶段）。
        Temporal 连接/cancel best-effort（不可达仍标 cancelled——对齐既有 cancel ③ 轨语义）。
        """
        # 版本化 run（spec §11.5）：latest run 非终态（pending/precheck/running）即本次
        # 取消对象——running 取消 -bb-{K} workflow；pending/precheck 段黑盒尚未提交，
        # 取消白盒 base 不存在（首跑）或非目标，实际在跑的是认证预验证（-authcheck，
        # 下方无条件 best-effort 取消覆盖两种 precheck 路径）。run 一并标 cancelled
        # （否则永久 pending，删除/新增的非终态门永久禁用）。
        runs = self._store.list_blackbox_runs(ws, scan_id)
        latest = runs[-1] if runs else None
        active_run_id: str | None = None
        latest_phase: str | None = None
        if latest and latest.get("status") not in _RUN_TERMINAL_STATUSES:
            active_run_id = latest["run_id"]
            rd = self._store.get_blackbox_run_dir(ws, scan_id, active_run_id)
            if rd is not None:
                latest_phase = SessionManager(rd.parent).get_session_data(rd).get(
                    "bb_phase")
        # 算 workflow_id（latest run running → -bb-{K}；否则白盒 base）
        if active_run_id is not None and latest_phase == "running":
            wf_id = self._resolve_run_workflow_id(ws, scan_id, active_run_id)
        else:
            wf_id = self._resolve_workflow_id(ws, scan_id)
        # submit→标 running 竞态窗口兜底（修 E1，2026-08-28）：latest 非终态但 phase 未及
        # 标 running 时 -bb-{K} 可能已 submit——无条件 best-effort cancel 之（窗口期
        # events.ndjson 未写 → id 回落公式仍正确；黑盒未提交时 cancel 不存在 workflow
        # 抛错即忽略）。
        bb_wf_id = (self._resolve_run_workflow_id(ws, scan_id, active_run_id)
                    if active_run_id is not None else None)
        # 取消编排 task（fire-and-forget，不再 submit 黑盒 / 不与终态竞争）
        orch = self._orchestrator_tasks.pop(scan_key, None)
        if orch is not None and not orch.done():
            orch.cancel()
        # re-attach + handle.cancel()（best-effort；Temporal 不可达不阻断标终态）
        try:
            client = await Client.connect(self._temporal_address())
            handle = client.get_workflow_handle(wf_id)
            await handle.cancel()
        except Exception:  # noqa: BLE001 - best-effort; temporal 不可达仍标 cancelled
            pass
        if bb_wf_id is not None and bb_wf_id != wf_id:
            try:
                client = await Client.connect(self._temporal_address())
                await client.get_workflow_handle(bb_wf_id).cancel()
            except Exception:  # noqa: BLE001 - 未提交/不可达均忽略
                pass
        # terminate 保险丝（修 E2）：心跳路径预期 ≤~40s 全停；仍 RUNNING 超 grace =
        # 取消链断 → 升级 terminate（防 activity 不心跳回归烧钱）。
        self._spawn_cancel_fuse(wf_id)
        if bb_wf_id is not None and bb_wf_id != wf_id:
            self._spawn_cancel_fuse(bb_wf_id)
        # precheck workflow（-authcheck）无条件 best-effort 取消：首跑 kickoff 与手动加 run
        # 两条 precheck 路径都用该固定 id；不在跑（不存在/已结束）时 cancel 抛错即忽略。
        try:
            client = await Client.connect(self._temporal_address())
            handle = client.get_workflow_handle(f"{ws}-{scan_id}-authcheck")
            await handle.cancel()
        except Exception:  # noqa: BLE001 - best-effort; 不在跑/不可达均忽略
            pass
        # 标取消的 run cancelled（run 级 session + bb_runs[] 条目；best-effort）。走
        # _mark_run 而非直调 store：终态钩子顺带给 run events.ndjson 补 scan_end——
        # 被取消的黑盒 workflow 走 except CancelledError 直接 return（不 finalize），
        # run 事件文件无人写终态行，归并流会永不关流（MergedEventTailer 关流条件
        # 依赖每个已发现 run 源见到自己的 scan_end）。
        if active_run_id is not None:
            await self._mark_run(scan_dir, active_run_id, "cancelled", status="cancelled")
        # 清残留 handle 登记（白盒 handle 在 running 阶段仍挂 _handles；对齐 delete 清理）
        self._handles.pop(scan_key, None)
        await self._mark_cancelled(scan_dir)
        return {"cancelled": scan_id}

    async def _cancel_correlation(self, ws: str, scan_id: str, scan_dir: Path,
                                  scan_key: tuple[str, str]) -> dict:
        """跨仓关联 cancel 级联（C4，镜像 _cancel_combined 模式）：

        取消顺序：
        ① 编排协程（_orchestrator_tasks）——停三段接力（不再提交关联/黑盒 run、
          不写 scan_end 与 _mark_cancelled 终态竞争）；orchestrator finally 自 pop
          同 key（幂等兜底）。
        ② _handles 中主/子仓 handle 逐个 cancel——现 C3 实现子仓 handle 由编排协程
          局部持有、不进 _handles（主行亦然），此循环覆盖登记路径/遗留 handle；
          未登记的 key 直接跳过（真正的 workflow 停止靠 ③ re-attach）。
        ③ Temporal re-attach best-effort：现扫子仓白盒 workflow（{ws}-{c_id}；复用
          子仓在提交时已终态，不碰）+ 关联 workflow（{ws}-{scan_id}-corr）。编排协程
          被 cancel 只停「等待」，workflow 本体须 re-attach cancel 才真停。
        ④ 段③活跃黑盒 run（latest 非终态）re-attach cancel（-bb-{K}）+ _mark_run
          标 cancelled——否则 run 永久 pending，delete/续跑的非终态门被永久禁用
          （对齐 _cancel_combined 的 run 收口语义）。
        ⑤ heartbeat fresh → cancel.requested 协作式信号（对齐 cancel ② 轨）+ 主行
          _mark_cancelled 收终态。

        Temporal 连接/cancel 全 best-effort（不可达仍标 cancelled——对齐 _cancel_combined
        的「不可达不阻断终态」语义）。
        """
        # ① 取消编排协程（fire-and-forget：不再 submit 关联/黑盒、不与终态竞争）
        orch = self._orchestrator_tasks.pop(scan_key, None)
        if orch is not None and not orch.done():
            orch.cancel()
        # ② _handles 直达取消：主行 + 现扫子仓 key（best-effort，逐个隔离异常）
        session = SessionManager(scan_dir.parent).get_session_data(scan_dir)
        children = [c for c in (session.get("corr_children") or [])
                    if c.get("scan_id") and not c.get("reused")]
        for k in [scan_key] + [(ws, c["scan_id"]) for c in children]:
            handle = self._handles.get(k)
            if handle is not None:
                try:
                    await handle.cancel()
                except Exception:  # noqa: BLE001 - best-effort; 不阻断后续取消
                    pass
        # ③ re-attach cancel 现扫子仓白盒 + 关联 workflow（best-effort）
        try:
            client = await Client.connect(self._temporal_address())
            for c in children:
                try:
                    await client.get_workflow_handle(
                        f"{ws}-{c['scan_id']}").cancel()
                except Exception:  # noqa: BLE001 - 单仓失败不阻断其余取消
                    pass
            try:
                await client.get_workflow_handle(f"{ws}-{scan_id}-corr").cancel()
            except Exception:  # noqa: BLE001 - 不在跑/不可达均忽略
                pass
        except Exception:  # noqa: BLE001 - Client.connect 失败 → 跳过 re-attach 段
            pass
        # ④ 段③活跃黑盒 run：re-attach cancel + 标 cancelled（防永久 pending）
        runs = self._store.list_blackbox_runs(ws, scan_id)
        latest = runs[-1] if runs else None
        if latest and latest.get("status") not in _RUN_TERMINAL_STATUSES:
            run_id = latest["run_id"]
            try:
                client = await Client.connect(self._temporal_address())
                await client.get_workflow_handle(
                    self._resolve_run_workflow_id(ws, scan_id, run_id)).cancel()
            except Exception:  # noqa: BLE001 - best-effort; 不可达仍标终态
                pass
            await self._mark_run(scan_dir, run_id, "cancelled", status="cancelled")
        # terminate 保险丝（修 E2）：关联 workflow + 活跃黑盒 run 的取消链兜底
        self._spawn_cancel_fuse(f"{ws}-{scan_id}-corr")
        if latest and latest.get("status") not in _RUN_TERMINAL_STATUSES:
            self._spawn_cancel_fuse(
                self._resolve_run_workflow_id(ws, scan_id, latest["run_id"]))
        # ⑤ 协作式信号兜底（heartbeat fresh，兼容 host 侧协作式取消）+ 主行标 cancelled
        if is_scan_recently_active(scan_dir):
            (scan_dir / "cancel.requested").write_text("", encoding="utf-8")
        await self._mark_cancelled(scan_dir)
        return {"cancelled": scan_id}

    async def _combined_kickoff(self, scan_key: tuple[str, str], scan_dir: Path,
                                req: ScanRequest, config_path: str | None,
                                host_mappings: dict[str, str] | None,
                                target: str | None, event_file: Path) -> None:
        """组合扫描后台启动（spec §8.2 异步预验证）：precheck → 白盒提交 → 接力编排。

        start() 组合分支把 precheck（登录目标站，可达数分钟）+ 白盒提交 + orchestrator 整体
        fire-and-forget 到本 task，自身立即返回 scan_id（否则 POST /api/scan 阻塞致前端
        submitting 卡死、不跳转）。_orchestrator_tasks[scan_key] 登记本 task，cancel/delete
        经 _cancel_combined 取消本 task 即终止整条链。

        流程（保留原同步路径语义，零行为变更仅异步化）：
          - precheck fail → 标 bb_phase=failed/auth_failed + scan_end（白盒不跑，fail-fast）。
          - precheck pass → 标 pending → 提交白盒 → 登记 _handles/_watch → await orchestrator
            （串行接力：白盒完成 → 黑盒 run-1 → 融合报告）。
          - CancelledError（cancel 路径）：向上抛出，finally 清理 _active_reqs/_orchestrator_tasks。
          - 其他异常：_mark_submission_failed 标终态（与 start 的 except BaseException 同口径）。

        _handles/_watch 登记挪到此（白盒提交后）：start 组合分支提前返回不再走 start 末尾的
        统一登记。_orchestrator_tasks[scan_key] 登记本 kickoff task；orchestrator（await 内联）
        自身 finally 也 pop 同一 key（幂等——pass 路径 orchestrator 完成时摘，kickoff finally
        再摘为 no-op；precheck-fail 路径 orchestrator 未跑，kickoff finally 摘）。cancel 一个
        task 即取消 precheck+白盒+接力全链。
        """
        ws, scan_id = scan_key
        try:
            ok = await self._run_precheck(
                scan_dir, ws, scan_id, req.url, config_path,
                host_mappings=host_mappings)
            if not ok:
                await self._mark_bb(scan_dir, "failed", "auth_failed")
                await self._ensure_scan_end(scan_dir, status="failed")
                return
            await self._mark_bb(scan_dir, "pending")
            handle = await self._submit_whitebox(
                target, ws, scan_id, scan_dir, event_file, req.url or "",
                combined=True)
            SessionManager(scan_dir.parent).update_session(
                scan_dir, {"source_repo": req.source.value if req.source else None})
            self._handles[scan_key] = handle
            self._tasks[scan_key] = asyncio.create_task(
                self._watch(scan_key, event_file, scan_dir))
            # 串行 await orchestrator（不再 create_task）：cancel 本 task 即取消接力。
            await self._combined_orchestrator(scan_key, handle, scan_dir, req)
        except asyncio.CancelledError:
            # cancel 路径（_cancel_combined 取消本 task）：向上抛出，终态由 _mark_cancelled 负责。
            raise
        except BaseException as exc:
            # 白盒提交/orchestrator 异常：标终态（对齐 start 的 except BaseException）。
            # _handles/_tasks 此时通常未登记（提交前抛）或 _watch finally 会清；兜底摘防泄漏。
            self._handles.pop(scan_key, None)
            self._tasks.pop(scan_key, None)
            await self._mark_submission_failed(scan_dir, event_file, exc)
        finally:
            # _active_reqs：precheck-fail 路径未起 _watch，须在此清；pass 路径 _watch 的 finally
            # 也会清（幂等）。_handles/_tasks 不在此清——pass 路径它们由 _watch 的 finally 拥有
            # （kickoff finally 早于 _watch 退出，先 pop 会让 _watch 的 describe() 查不到 handle）。
            self._active_reqs.pop(scan_key, None)
            # _orchestrator_tasks（本 task 自身登记）正常完成/失败/cancel 都摘（cancel 路径
            # _cancel_combined 已 pop，此处兜底幂等）。cancel 时不在此标终态——_cancel_combined/
            # _mark_cancelled 负责。
            self._orchestrator_tasks.pop(scan_key, None)
            # 扫完即删（2026-09-10）：precheck-fail 路径未起 _watch（pass 路径由 _watch
            # finally 触发，此处幂等重扫无害）。
            await self._sweep_ws_quiet(ws)

    async def _combined_orchestrator(self, scan_key: tuple[str, str], wb_handle: Any,
                                     scan_dir: Path, req: ScanRequest) -> None:
        """组合接力编排（spec §7.2）：await 白盒完成 → _run_blackbox_phase；try/except/finally
        统一经 _ensure_scan_end（幂等）收尾。

        ws 取自 scan_key[0]（修原 bug #4：曾误用 scan_dir.parent.name 致跨 ws 错配；scan_dir
        在 scans/<id>/ 下，parent.name 是 scan_id 非 ws）。

        调用方：① start() 公开目标组合分支（precheck 瞬时同步后 create_task 起本协程）；
        ② _combined_kickoff（带认证 precheck pass 后 await 本协程）。两种调用下
        _orchestrator_tasks[scan_key] 都最终指向本协程能被 cancel 的 task（① 直接登记本协程；
        ② 登记的是 kickoff，但本协程是 kickoff 的 await 点，cancel kickoff 即取消本协程的
        await），故 finally 自 pop _orchestrator_tasks 在两路径都幂等正确。

        scan_end 不变量（spec §7.4）：成功路径黑盒 finalize 已写 scan_end → _ensure_scan_end
        no-op；异常/跳过/提交失败 → _ensure_scan_end 补写防 _watch 永久 tail。绝不在此裸调
        _write_scan_end（原草案 bug：成功路径写了第二条 scan_end）。
        """
        ws, scan_id = scan_key
        run_id: str | None = None
        final_status = "completed"
        cancelled = False  # web 关停 cancel：跳过 finally 收口（见 except CancelledError）
        try:
            wb_result = await self._await_workflow_result(wb_handle)
            # 白盒正常返回 status=failed（部分 agent 失败，workflow 未 raise）：停止接力，不建黑盒 run。
            # 防御 dict/dataclass 访问（照搬 :1044-1046 范式；真实 PipelineState 字段为 errors(list)/
            # error_code，测试 mock 用 error 键）。raise 路径（workflow 级崩溃）仍由下方 except 兜底。
            wb_status = (wb_result.get("status")
                         if isinstance(wb_result, dict)
                         else getattr(wb_result, "status", None))
            if wb_status == "failed":
                if isinstance(wb_result, dict):
                    reason = (wb_result.get("error")
                              or "; ".join(wb_result.get("errors") or [])
                              or "whitebox workflow failed")
                else:
                    errs = getattr(wb_result, "errors", None) or []
                    reason = ("; ".join(errs) if errs
                              else (getattr(wb_result, "error_code", None)
                                    or "whitebox workflow failed"))
                await self._mark_bb(scan_dir, "failed", reason)
                final_status = "failed"
                return  # finally 走 _ensure_scan_end(failed) + pop _orchestrator_tasks
            # 版本化多 run（spec §7.2）：白盒完成后建 run-1（与手动 _add_blackbox_run
            # 同路径 → by-construction 一致），再 _run_blackbox_phase(run-1, -bb-1)。
            async with self._create_scan_lock:
                run_id, _ = self._store.create_blackbox_run(
                    ws, scan_id, auth_ref=self._snapshot_auth_ref(req))
            k = int(run_id.split("-")[1])
            await self._run_blackbox_phase(
                scan_dir, ws, scan_id, self._snapshot_auth_ref(req), run_id,
                workflow_id_suffix=f"-bb-{k}")
        except asyncio.CancelledError:
            # web 进程关停取消编排协程：web 编排死了 ≠ 扫描死了——workflow 仍在 Temporal
            # 跑。CancelledError 是 BaseException，except Exception 接不住，若放行到
            # finally 会把在跑扫描收口成假 completed（2026-09-18 cross-repo-20260918-064512
            # 事故：部署重启把整个在跑关联扫描写成 completed）。不写终态、不标 run failed，
            # 留 running 交 orphan_reconcile 按 Temporal 状态收口；终态由取消方/对账方负责
            # （对齐 _add_run_kickoff 既有 cancel 语义）。必须 re-raise：吞掉会破坏 task
            # 取消语义（uvicorn 关停卡死）。
            cancelled = True
            raise
        except Exception as exc:
            final_status = "failed"
            # 接力任意阶段失败：run 已建则标该 run failed；白盒失败（run 未建）则 run_id
            # 为 None 不标（白盒 workflow 自身终态已落 session）。
            if run_id is not None:
                await self._mark_run(scan_dir, run_id, "failed",
                                     reason=str(exc), status="failed")
        finally:
            self._orchestrator_tasks.pop(scan_key, None)
            if not cancelled:
                # 幂等收尾：成功路径黑盒已写 scan_end → no-op；异常/跳过 → 补写。
                await self._ensure_scan_end(scan_dir, status=final_status)

    async def _combined_report_orchestrator(self, scan_key: tuple[str, str],
                                            bb_handle: Any, scan_dir: Path,
                                            run_id: str) -> None:
        """仅做报告的组合编排（spec §11.4，resume latest run running 分支）。

        run 的黑盒 workflow 已在跑（resume 前 submit 过），scan_manager 进程崩溃后 resume
        re-attach 了该 run 的 handle。本 task 镜像 _combined_orchestrator 的「await handle →
        生成报告」尾段，但不重 submit 黑盒：

        await bb_handle.result() → ``_generate_combined_report(scan_dir, run_id)`` →
        ``_mark_run(scan_dir, run_id, completed)``；try/except/finally 经 _ensure_scan_end
        （幂等）收尾（与 _combined_orchestrator 同构）。
        """
        final_status = "completed"
        cancelled = False  # web 关停 cancel：跳过 finally 收口（同 _combined_orchestrator）
        try:
            bb_result = await self._await_workflow_result(bb_handle)
            # 对齐 _run_blackbox_phase 终态口径：workflow 正常返回 status=failed（未
            # raise）→ run 标 failed、不生成融合报告。返回值此前被整体丢弃（resume
            # 路径无条件 completed，吞失败——2026-09-11 口径矛盾同族缺口）。
            if self._workflow_result_status(bb_result) == "failed":
                await self._mark_run(scan_dir, run_id, "failed",
                                     reason=self._workflow_result_error(bb_result),
                                     status="failed")
                return
            await self._generate_combined_report(scan_dir, run_id)
            await self._mark_run(scan_dir, run_id, "completed", status="completed")
        except asyncio.CancelledError:
            # web 编排死了 ≠ 扫描死了，不写终态留 running 交 orphan_reconcile
            # （2026-09-18 假 completed 事故，详见 _combined_orchestrator 同款注释）。
            cancelled = True
            raise
        except Exception as exc:
            final_status = "failed"
            await self._mark_run(scan_dir, run_id, "failed",
                                 reason=str(exc), status="failed")
        finally:
            self._orchestrator_tasks.pop(scan_key, None)
            if not cancelled:
                await self._ensure_scan_end(scan_dir, status=final_status)

    async def _correlation_orchestrator(self, scan_key: tuple[str, str],
                                        child_handles: dict[str, tuple[str, Any]],
                                        scan_dir: Path, req: ScanRequest,
                                        config_path: Path,
                                        repo_workspace_paths: dict[str, Path]) -> None:
        """跨仓三段接力编排（C3，spec 2026-08-24 §5.3）：子仓白盒 → 关联 →（可选）黑盒验证。

        child_handles 值 = (子仓 scan_id, wb handle)——start 提交段登记；本编排 await
        全部现扫子仓（任一失败 → 主行 failed、不进关联阶段），全成功后 _submit_correlation
        （write_scan_end=False，phase 不写终态），再按 gateway URL 决定段③黑盒验证 run。

        scan_end 不变量：任务级终态事件恒由 finally 的 _ensure_scan_end 幂等收口——
        events 已有 scan_end 则 no-op（绝不写第二条），绝不裸调 _write_scan_end。
        _run_blackbox_phase 不写任务级 scan_end（其 _mark_run 终态钩子只补 run 级
        events），故成功路径的任务级终态也是此处写的；子仓失败/关联异常/跳过段③
        同样经此收口，防 _watch 永久 tail。
        """
        ws, scan_id = scan_key
        final_status = "completed"
        run_id: str | None = None
        cancelled = False  # web 关停 cancel：跳过 finally 收口（见 except CancelledError）
        event_file = scan_dir / "events.ndjson"
        corr_writer = CorrelationEventWriter(event_file)
        try:
            # 段①：await 全部现扫子仓（dict 序 = 提交序）；任一子仓 workflow 返回
            # status=failed（或 raise，走下方 except）→ 主行 failed，不进关联阶段。
            for svc, (_c_scan_id, wb_handle) in child_handles.items():
                result = await self._await_workflow_result(wb_handle)
                status = (result.get("status") if isinstance(result, dict)
                          else getattr(result, "status", None))
                if status == "failed":
                    await corr_writer.repo(svc, "failed", detail="scan failed")
                    final_status = "failed"
                    return  # finally 走 _ensure_scan_end(failed) + pop _orchestrator_tasks
                await corr_writer.repo(svc, "completed")
            # 段②：关联阶段（repo_workspace_paths = 复用 scan_dir ∪ 现扫 c_dir）。
            await corr_writer.phase("correlation", "started")
            handle = await self._submit_correlation(
                Path(config_path), repo_workspace_paths, scan_dir, event_file, ws)
            await self._await_workflow_result(handle)
            await corr_writer.phase("correlation", "completed")
            # 段③（可选）：gateway URL → 黑盒验证 run-1（correlated_workspace=主行
            # scan_id，黑盒 recon-skip 消费主行合并 queue / topology）。
            if req.url:
                async with self._create_scan_lock:
                    run_id, _ = self._store.create_blackbox_run(
                        ws, scan_id, auth_ref=self._snapshot_auth_ref(req))
                k = int(run_id.split("-")[1])
                await self._run_blackbox_phase(
                    scan_dir, ws, scan_id, self._snapshot_auth_ref(req), run_id,
                    workflow_id_suffix=f"-bb-{k}",
                    correlated_workspace=scan_id)
        except asyncio.CancelledError:
            # web 进程关停取消编排协程：web 编排死了 ≠ 扫描死了——correlation workflow
            # 恒在 Temporal（write_scan_end=False，任务级终态 100% 依赖本编排收口）。
            # CancelledError 穿透 except Exception 落到 finally 会把在跑扫描收口成假
            # completed（2026-09-18 cross-repo-20260918-064512 事故：部署重启时本协程
            # 被 cancel，主行被写成 completed 而关联 workflow 还在跑）。不写终态，留
            # running 交 orphan_reconcile 按 Temporal 状态收口。必须 re-raise：吞掉会
            # 破坏 task 取消语义（uvicorn 关停卡死）。
            cancelled = True
            raise
        except Exception as exc:
            final_status = "failed"
            # 接力任意阶段失败：黑盒 run 已建则标该 run failed；关联/子仓阶段（run 未建）
            # run_id 为 None 不标（子仓 workflow 自身终态已落各自 session）。
            if run_id is not None:
                await self._mark_run(scan_dir, run_id, "failed",
                                     reason=str(exc), status="failed")
        finally:
            self._orchestrator_tasks.pop(scan_key, None)
            if not cancelled:
                # 幂等收口（同 _combined_orchestrator）：events 无 scan_end 才写（唯一的
                # 任务级终态事件；run 级 scan_end 由 _mark_run 终态钩子/黑盒 finalize 管）。
                await self._ensure_scan_end(scan_dir, status=final_status)

    def _build_combined_resume_req(self, data: dict, ws: str) -> ScanRequest:
        """从 session data 重建组合扫描 ScanRequest（resume 编排 task 用）。

        编排 task 读 req 的 url + _snapshot_auth_ref（auth 引用）。url 优先 bb_url（组合目标），
        回落 web_url。auth 字段从 bb_auth_ref 对称重建（_snapshot_auth_ref 的逆），保证
        _run_blackbox_phase 拿到与 start 时一致的 auth_ref dict。

        type=whitebox + url → _whitebox_combined_optional 校验组合模式认证字段互斥（与 start 同）。
        """
        url = data.get("bb_url") or data.get("web_url")
        req_kwargs: dict = dict(type="whitebox", url=url, workspace=ws)
        auth_ref = data.get("bb_auth_ref") or {}
        pid = auth_ref.get("profile_id")
        if pid:
            req_kwargs["auth_profile_id"] = pid
            if auth_ref.get("cred_id"):
                req_kwargs["auth_credential_id"] = auth_ref["cred_id"]
            if auth_ref.get("cred_ids"):
                req_kwargs["auth_credential_ids"] = auth_ref["cred_ids"]
        return ScanRequest(**req_kwargs)

    async def _run_blackbox_phase(self, scan_dir: Path, ws: str, scan_id: str,
                                  auth_ref: dict, run_id: str,
                                  workflow_id_suffix: str = "-bb-1",
                                  correlated_workspace: str | None = None) -> None:
        """组合接力公共段（spec §7.3）：预检白盒产物 → 复用 _submit_blackbox（suffix 后缀）→
        等黑盒 → 融合报告。

        单目录接力的核心：repo_path/event_file/config_path 全指回白盒 scan_dir，黑盒产物落
        scan_dir/deliverables/blackbox/（黑盒 workflow 零代码改动，spec §5）。本方法**不直接
        写 scan_end**——收尾交 _combined_orchestrator / _rerun_orchestrator 的
        _ensure_scan_end（幂等）。

        workflow_id_suffix（Task 7 扩展）：默认 "-bb"（Task 4 首跑，零回归）；rerun_blackbox
        传 "-bb-rerun-N"（D5 续跑，每次起新黑盒 workflow id）。透传给 _submit_blackbox。

        correlated_workspace（跨仓关联 C1）：默认 None（零回归，既有组合扫描行为不变）；
        关联扫描场景由编排层传入，透传给 _submit_blackbox。

        _generate_combined_report 由 Task 8 实现；本任务仅保留调用点（单测 mock 之）。
        """
        # 预检产物（recon_deliverable.md + 至少一个非空 queue；correlation 主行改查
        # deliverables/ 根的非空合并 queue——C3 fix ①）。不全 → 跳过黑盒。
        if not self._whitebox_deliverables_ready(scan_dir):
            await self._mark_run(scan_dir, run_id, "skipped",
                                 reason="白盒无可利用产物", status="skipped")
            return
        # 读 session 取黑盒目标 URL + HOST 映射（start 组合分支 dump scan-config.yaml
        # + 写 bb_url/bb_host_mappings 到 session）。bb_url 缺失回落 web_url。
        session = SessionManager(scan_dir.parent).get_session_data(scan_dir)
        bb_url = session.get("bb_url") or session.get("web_url") or ""
        host_mappings = self._session_host_mappings(session)
        # 按白盒发现的非空 queue vuln 类补 expected_agents.blackbox（黑盒只 exploit 白盒发现的类，
        # spec §9.5）：进度分母动态化，收起态百分比更准。
        bb_expected = self._count_nonempty_queues(scan_dir)
        if bb_expected > 0:
            expected = dict(session.get("expected_agents") or {})
            expected["blackbox"] = bb_expected
            try:
                SessionManager(scan_dir.parent).update_session(
                    scan_dir, {"expected_agents": expected})
            except Exception:  # noqa: BLE001 - best-effort 进度分母，不阻塞接力
                pass
        # event_file 指 run 子目录（黑盒从 event_file.parent 推 workspace_path → 产物落
        # run-K/deliverables/blackbox/，spec §4）；repo_path/config_path 仍指白盒任务根
        # （黑盒读 deliverables/whitebox/ queue）。公开目标（无认证）没有 scan-config.yaml
        # → config_path=None（黑盒 workflow 据 None 跳过 auth 阶段；传不存在路径会误触
        # 登录活动）。
        scan_config = scan_dir / "scan-config.yaml"
        run_dir = blackbox_run_dir(scan_dir, run_id)
        bb_handle = await self._submit_blackbox(
            repo_path=str(scan_dir), ws=ws, scan_id=scan_id, scan_dir=scan_dir,
            event_file=run_dir / "events.ndjson", web_url=bb_url,
            config_path=str(scan_config) if scan_config.exists() else None,
            host_mappings=host_mappings, workflow_id_suffix=workflow_id_suffix,
            correlated_workspace=correlated_workspace)
        await self._mark_run(scan_dir, run_id, "running", status="running")
        bb_result = await self._await_workflow_result(bb_handle)
        # 黑盒 workflow 正常返回 status=failed（未 raise）：不生成融合报告，run 标
        # failed（融合报告仅成功路径产出 → combined/run-K/；raise 路径由编排层
        # except 兜底）。status 经 _workflow_result_status 双形态读取——temporalio
        # 按返回注解反序列化出 dataclass，dict 单分支恒漏判（2026-09-11 口径矛盾）。
        if self._workflow_result_status(bb_result) == "failed":
            await self._mark_run(scan_dir, run_id, "failed",
                                 reason=self._workflow_result_error(bb_result),
                                 status="failed")
            return
        await self._generate_combined_report(scan_dir, run_id)  # → combined/run-K/
        await self._mark_run(scan_dir, run_id, "completed", status="completed")

    async def rerun_blackbox(self, ws: str, scan_id: str,
                             new_auth: ScanRequest | None = None) -> str:
        """换认证续跑 = 新建下一个 run（spec §8/§11.3，runs 版本化折叠）。

        前置：白盒产物完好；latest run 状态为 failed/skipped（或尚无 run）。返回新 run_id
        （run-K+1，或无 run 时 run-1）。new_auth 非空 → ``_add_blackbox_run`` 内重 dump
        scan-config.yaml 覆盖 + 预验证；fail → 新 run 标 failed。

        取代旧 ``-bb-rerun-{N}`` / ``bb_rerun_attempts``：续跑即下一个版本化 run（workflow_id
        ``{ws}-{scan_id}-bb-{K+1}``），旧产物（run-1..K）保留可对比。
        """
        scan_dir = self._store.get_scan_dir(ws, scan_id)
        if scan_dir is None:
            raise ValueError("scan 不存在")
        if not self._whitebox_deliverables_ready(scan_dir):
            raise ValueError("白盒产物需完好才能续跑黑盒")
        runs = self._store.list_blackbox_runs(ws, scan_id)
        latest = runs[-1] if runs else None
        # 守卫（spec 2026-09-03 §7 扩展）：failed/skipped/无 run 可续跑；
        # completed + verification_gaps 信号（agent 业务失败缺口，非 run 失败）
        # 同样放行——用户看到缺口原因后自行决定补测。
        if latest:
            status = latest.get("status")
            has_gaps = bool(latest.get("verification_gaps"))
            rerunnable = status in ("failed", "skipped", None) or (
                status == "completed" and has_gaps)
            if not rerunnable:
                raise ValueError("仅 latest run 失败/跳过/有验证缺口时可续跑（新建 run）")
        return await self._add_blackbox_run(ws, scan_id, new_auth)

    async def _rerun_orchestrator(self, scan_key: tuple[str, str], scan_dir: Path,
                                  ws: str, scan_id: str, auth_ref: dict,
                                  run_id: str, suffix: str) -> None:
        """run 版编排（spec §7.3，与 _combined_orchestrator 同构）：调
        ``_run_blackbox_phase(run_id, suffix)`` → try/except/finally 经幂等
        ``_ensure_scan_end`` 收尾。finally 自 pop ``_orchestrator_tasks``。

        成功路径黑盒 finalize 已写 scan_end → ``_ensure_scan_end`` no-op；异常/提交失败
        → 补写 scan_end 防 _watch 永久 tail。

        任务级终态口径（2026-09-15 失败归属修正）：run 的成败属于那一次 run（run 级
        session/bb_runs[] 徽章/续跑守卫消费），任务级回落白盒预跑终态（_posthoc_run_task_terminal
        读 stash）——run 失败不再把整个白盒任务翻 failed（现场 gw_trade：run 失败后任务从
        黑盒表单候选消失，无法再次发起黑盒）。
        """
        final_status = self._posthoc_run_task_terminal(scan_dir)
        cancelled = False  # web 关停 cancel：跳过 finally 收口（见 except CancelledError）
        try:
            await self._run_blackbox_phase(
                scan_dir, ws, scan_id, auth_ref, run_id, workflow_id_suffix=suffix)
        except asyncio.CancelledError:
            # web 编排死了 ≠ 扫描死了：不写任务级终态、也不把 run 标 failed（run 没失败，
            # 是 web 关停），留 running 交 orphan_reconcile（2026-09-18 假 completed 事故，
            # 详见 _combined_orchestrator 同款注释）。
            cancelled = True
            raise
        except Exception as exc:
            await self._mark_run(scan_dir, run_id, "failed",
                                 reason=str(exc), status="failed")
        finally:
            self._orchestrator_tasks.pop(scan_key, None)
            if not cancelled:
                await self._ensure_scan_end(scan_dir, status=final_status)

    @staticmethod
    def _posthoc_pre_run_status(data: dict) -> str:
        """加 run 前的任务级终态（stash 值计算）：仅收 _write_scan_end 可写的
        session_status 值（done/缺失 → completed——产物完好的常态值）。"""
        pre = data.get("status") if isinstance(data, dict) else None
        return pre if pre in ("completed", "cancelled", "failed") else "completed"

    def _posthoc_run_task_terminal(self, scan_dir: Path) -> str:
        """加 run 收尾的任务级终态：预跑白盒终态（bb_pre_run_status stash）。

        加 run 的前置是白盒产物完好（_whitebox_deliverables_ready）——run 失败/成功都
        不改变白盒本体的完成事实。stash 取 _add_blackbox_run 进入 running 前的任务
        状态（completed 常态；cancelled 保留——预跑取消语义不被 run 结果抹掉/升级）；
        缺失（历史数据/极端路径）回落 completed。"""
        try:
            pre = SessionManager(scan_dir.parent).get_session_data(scan_dir) \
                .get("bb_pre_run_status")
        except Exception:  # noqa: BLE001 - 读不到回落 completed（产物完好的常态值）
            pre = None
        return pre if pre in ("completed", "cancelled", "failed") else "completed"

    async def _add_blackbox_run(self, ws: str, wb_scan_id: str,
                                req: ScanRequest | None = None) -> str:
        """给已有白盒任务加一个黑盒 run（spec §6/§7.1 #8 手动入口）。

        流程：白盒产物就绪检查 → （req 给了认证则重 dump scan-config.yaml + 更新 bb_url/
        bb_auth_ref）→ 在跑守卫 → 串行分配 run-K（_create_scan_lock）→ 任务级进入 running
        → fire-and-forget ``_add_run_kickoff``（precheck → _rerun_orchestrator）→ 立即返回
        run_id。precheck 在 kickoff task 内异步跑（可达数分钟）——端点立即返回（202 语义），
        且 precheck 期间 cancel 经 ``_orchestrator_tasks`` 可达（同步内联时取消无效）。

        req=None（沿用现盘 scan-config.yaml）：无 scan-config.yaml → 公开目标，跳过预验证。
        """
        scan_dir = self._store.get_scan_dir(ws, wb_scan_id)
        if scan_dir is None:
            raise ValueError("白盒任务不存在")
        if not self._whitebox_deliverables_ready(scan_dir):
            raise ValueError("白盒产物未就绪，不能加黑盒")
        mgr = SessionManager(scan_dir.parent)
        data = mgr.get_session_data(scan_dir)
        cfg = scan_dir / "scan-config.yaml"
        if req is not None:
            await self._dump_auth_config(req, ws, scan_dir)
            # HOST（2026-09-15 gw_trade 事故）：req 带 HOST 来源（档案/URL）→ 解析快照
            # 写主 session（对齐 start() 的 immutable host_config 语义；下游
            # _session_host_mappings 统一读快照 → kickoff precheck / _run_blackbox_phase
            # 提交 worker 全链生效）；req 不带 HOST → 沿用旧快照不抹。解析失败（档案
            # 不存在/refresh 失败/映射冲突）在创建 run 之前 raise → API 层 422，不留
            # ghost run。曾此分支只处理认证、HOST 字段被静默丢弃 → 内网域名 preflight
            # 公网 DNS 解析秒败（Cannot resolve hostname）。
            host_config = await self._resolve_host_config(req, ws)
            bb_url = req.url or data.get("bb_url") or data.get("web_url") or ""
            session_patch: dict = {
                "bb_url": bb_url,
                "bb_auth_ref": self._snapshot_auth_ref(req),
            }
            if host_config is not None:
                session_patch["host_config"] = host_config
            mgr.update_session(scan_dir, session_patch)
            data = mgr.get_session_data(scan_dir)  # 刷新（bb_url/bb_auth_ref/host_config 已写）
        config_path = str(cfg) if cfg.exists() else None
        bb_url = data.get("bb_url") or data.get("web_url") or ""
        # 空 bb_url 守卫：纯白盒任务（未填 url）无黑盒目标。黑盒 workflow 不 fail-fast
        # （preflight 仅在有 URL 时校验可达性，exploit agent 拿空 web_url 也照跑一轮 LLM），
        # 会产出一个无意义 run。此处 422 拦截（rerun_blackbox 委托本方法，同样受护）。
        if not bb_url:
            raise ValueError("该白盒任务没有目标 URL，无法加黑盒（纯白盒任务请用组合扫描提供 url）")
        auth_ref = data.get("bb_auth_ref") or {"profile_id": None}
        # 在跑守卫（对齐 rerun_blackbox 的 latest 状态门）：latest run 非终态（pending/
        # running/precheck）时叠加新 run 会并发打同一目标，且 _orchestrator_tasks[key] 被
        # 新 run 覆盖（cancel 只能取消 latest）。终态（含 failed/skipped/cancelled）→ 放行。
        runs = self._store.list_blackbox_runs(ws, wb_scan_id)
        if runs and runs[-1].get("status") not in _RUN_TERMINAL_STATUSES:
            raise ValueError(
                f"黑盒 run {runs[-1].get('run_id')} 仍在进行，请等待完成或先取消再新增")
        # 序号分配须串行（与 create_scan 同 lock 口径，防并发同序号）。
        async with self._create_scan_lock:
            run_id, _run_dir = self._store.create_blackbox_run(
                ws, wb_scan_id, auth_ref=auth_ref)
        # 任务级进入 running（resume 组合分支同款三步）：run 运行态如实上浮任务级 status
        # （列表取消按钮/轮询/Dashboard 聚合依赖 is_running）。剥旧 scan_end 让收尾
        # _ensure_scan_end 能写新终态（旧 scan_end 在尾则 no-op，任务级 status 无人更新），
        # 且 SSE 不回放旧 scan_end、orphan_reconciler 的 has_scan_end 门不短路组合恢复。
        # 刷新 submitted_at 盖 precheck 冷启动（run/.authcheck heartbeat 由判活候选覆盖，
        # 宽限只补 worker 起写前的空窗）。
        # bb_pre_run_status stash（2026-09-15 失败归属修正）：收尾写回白盒预跑终态——
        # run 失败属于 run，不翻任务级 failed。
        self._strip_trailing_scan_end(scan_dir / "events.ndjson")
        mgr.update_session(scan_dir, {
            "status": "running", "completed_at": None,
            "bb_pre_run_status": self._posthoc_pre_run_status(data)})
        self._mark_submitted_at(scan_dir)
        k = int(run_id.split("-")[1])
        scan_key = (ws, wb_scan_id)
        self._orchestrator_tasks[scan_key] = asyncio.create_task(
            self._add_run_kickoff(
                scan_key, scan_dir, ws, wb_scan_id, run_id, k, config_path, bb_url,
                auth_ref, self._session_host_mappings(data)))
        return run_id

    async def _add_run_kickoff(self, scan_key: tuple[str, str], scan_dir: Path,
                               ws: str, wb_scan_id: str, run_id: str, k: int,
                               config_path: str | None, bb_url: str,
                               auth_ref: dict,
                               host_mappings: dict[str, str] | None) -> None:
        """手动加 run 的后台启动（镜像 _combined_kickoff 模式）：precheck → _rerun_orchestrator。

        precheck（登录目标站，可达数分钟）在后台 task 内跑：POST /blackbox-runs 立即返回；
        cancel 经 _orchestrator_tasks 取消本 task 即终止 precheck + 黑盒全链（同步内联时
        precheck 期间 cancel 无效——orchestrator 未注册，precheck 过后黑盒照常提交）。

        - precheck fail → run 标 failed（读回 bb_failure_* 供横幅）+ 任务级写回白盒
          预跑终态（2026-09-15：认证失败属于这次 run，不翻白盒任务 failed）。
        - CancelledError（cancel 路径）：向上抛出，终态由 _cancel_combined/_mark_cancelled 负责。
        - finally 幂等 pop _orchestrator_tasks（_rerun_orchestrator finally 已 pop，兜底防
          precheck-fail 路径泄漏）。
        """
        try:
            if config_path and not await self._run_precheck(
                    scan_dir, ws, wb_scan_id, bb_url, config_path,
                    host_mappings=host_mappings):
                # precheck 失败详情已由 _run_precheck 落任务 session，读回并入 run（横幅用）。
                try:
                    pdata = SessionManager(scan_dir.parent).get_session_data(scan_dir)
                except Exception:  # noqa: BLE001 - 读不到就只标笼统 auth_failed
                    pdata = {}
                await self._mark_run(
                    scan_dir, run_id, "failed", reason="auth_failed", status="failed",
                    extra={"bb_failure_point": pdata.get("bb_failure_point"),
                           "bb_failure_detail": pdata.get("bb_failure_detail")})
                # 任务级写回白盒预跑终态（2026-09-15）：认证失败属于这次 run，不翻白盒
                # 任务 failed（失败详情已在 run 级 bb_failure_* 供横幅/排查）。
                await self._ensure_scan_end(
                    scan_dir, status=self._posthoc_run_task_terminal(scan_dir))
                return
            await self._rerun_orchestrator(
                scan_key, scan_dir, ws, wb_scan_id, auth_ref, run_id, f"-bb-{k}")
        except asyncio.CancelledError:
            # cancel 路径（_cancel_combined 取消本 task）：向上抛出，终态由 _mark_cancelled 负责。
            raise
        finally:
            self._orchestrator_tasks.pop(scan_key, None)

    async def _run_precheck(self, scan_dir: Path, ws: str, scan_id: str,
                            web_url: str, config_path: str | None,
                            host_mappings: dict[str, str] | None = None) -> bool:
        """D4 t0 预验证：复用 AuthValidationWorkflow 登一次目标站，pass 返 True。

        event_file 用独立文件 authcheck-events.ndjson（不写主 events——预验证 workflow finalize
        可能写 scan_end，混入主 events 流会提前触发 _watch 退出）。黑盒 workflow 零代码改动，
        起一个独立的 AuthValidationWorkflow（与认证管理页「测试登录」探针同源）。

        config_path=None（公开目标无认证）→ 跳过预验证直接 pass（无登录可验）。

        workspace_path 必须同样隔离到 .authcheck scratch 目录：finalize_summary 成功收尾会往
        <workspace_path>/session.json 写终态 status=completed，且 heartbeat daemon 有「见终态
        自停」。若指向 scan_dir，白盒尚未提交主扫描 session.json 就被标 completed（2026-08-16
        NodeGoat：白盒进行中却显示已完成 + 白盒 heartbeat 自停成 stale），event_file 的隔离
        只挡住了 scan_end 这一半副作用。
        """
        if not config_path:
            return True  # 公开目标无认证 → 无需预验证
        from supernova_blackbox.pipeline.workflows import AuthValidationWorkflow
        from supernova_blackbox.pipeline.shared import BlackboxAuthValidationInput
        from supernova_core.services.temporal_infra import WEB_TASK_QUEUE_BLACKBOX
        client = await Client.connect(self._temporal_address())
        probe_dir = scan_dir / ".authcheck"
        probe_dir.mkdir(parents=True, exist_ok=True)
        # 完整 provider 配置穿线（同认证管理页探针，2026-08-17）：仅 api_key 会让 base_url
        # 回落 worker env profile → key/端点错配 401。预验证提交前 ws provider 已由
        # _submit_whitebox 校验过完整性，此处解析失败罕见；仍兜底 None 走 env。
        try:
            provider_config = self._resolve_provider_config(ws)
        except Exception:
            provider_config = None
        _env_ov = self._resolve_env_overrides(ws)
        inp = BlackboxAuthValidationInput(
            web_url=web_url, config_path=config_path,
            workspace_path=str(probe_dir),
            event_file=str(scan_dir / "authcheck-events.ndjson"),  # 独立 events
            api_key=provider_config.get("api_key") if provider_config else None,
            provider_config=provider_config,
            env_overrides=_env_ov,
            probe_timeout_seconds=_auth_probe_timeout_seconds(_env_ov),
            host_mappings=host_mappings or {})
        handle = await client.start_workflow(
            AuthValidationWorkflow.run, inp,
            id=f"{ws}-{scan_id}-authcheck", task_queue=WEB_TASK_QUEUE_BLACKBOX)
        result = await handle.result()  # AuthValidationResult
        if result and getattr(result, "success", False):
            return True
        # no_verdict = agent ran but produced no structured login_success verdict
        # (provider anomaly), NOT a deterministic login rejection. Kill-the-scan here
        # mislabels it auth_failed — 2026-08-14 NodeGoat: GLM logged in successfully
        # but emitted a Markdown summary, the missing verdict fail-fasted the whole
        # combined scan before whitebox started. Pass through instead: auth is
        # re-validated by the t2 blackbox auth phase (fail → D5 rerun, whitebox
        # results survive). Deterministic rejections still fail-fast below.
        if result and getattr(result, "failure_point", None) == "no_verdict":
            _log.warning(
                "combined precheck %s/%s: auth agent produced no structured verdict "
                "(%s); proceeding — auth deferred to blackbox phase",
                ws, scan_id, getattr(result, "failure_detail", ""))
            SessionManager(scan_dir.parent).update_session(scan_dir, {
                "bb_precheck_warning": (
                    "auth agent produced no structured login verdict; proceeding — "
                    "authentication will be re-validated by the blackbox phase")})
            return True
        # 确定性拒绝（登录失败/目标不可达）：把 verdict 落 session 供 API/横幅展示，
        # 调用方只拿到 False + 笼统 bb_reason="auth_failed"，详情丢了用户无从排查。
        point = getattr(result, "failure_point", None) if result else None
        detail = getattr(result, "failure_detail", None) if result else None
        try:
            SessionManager(scan_dir.parent).update_session(scan_dir, {
                "bb_failure_point": point,
                "bb_failure_detail": detail[:500] if detail else detail})
        except Exception:  # noqa: BLE001 - best-effort，不阻塞 fail-fast
            pass
        return False

    async def _generate_combined_report(self, scan_dir: Path, run_id: str) -> None:
        """生成 per-run 融合报告（T8，spec 2026-08-26-report-generation-agent §6.2）。

        主路径：白盒 report_data.json + 黑盒 report_data.json →
        ``fuse_report_data``（cross_verification 三态 + verification_gaps，
        白盒叙事 × 黑盒实测证据融合卡）→ ``combined/run-K/report_data.json``
        （前端 report-data 端点消费）+ ``combined_report.md``（md 导出，
        /report?track=combined 兼容）。
        降级：fusion 任一步失败 → 旧 ``combined_report_renderer``（md 链路不断）。
        供 ``_run_blackbox_phase`` / reconcile 在黑盒完成后 await。
        """
        run_dir = blackbox_run_dir(scan_dir, run_id)
        out_dir = combined_run_dir(scan_dir, run_id)
        try:
            from supernova_core.models.report_data import ScanMeta
            from supernova_core.services import report_data_builder
            from supernova_core.services.report_data_blackbox import (
                build_blackbox_report_data,
                build_class_meta,
            )
            from supernova_core.services.report_fusion import fuse_report_data
            from supernova_core.services.report_markdown_exporter import (
                export_report_markdown,
            )

            scan_meta = ScanMeta(id=scan_dir.name, track="whitebox")
            wb_rd = await report_data_builder.build_report_data(
                whitebox_dir(scan_dir / "deliverables"), scan_meta)
            # 黑盒 builder 期望 deliverables 根（内部经 resolve_track_deliverable
            # 自拼 blackbox/intermediate/），与白盒（直接吃白盒桶）口径不同。
            bb_rd = await build_blackbox_report_data(
                run_dir / "deliverables",
                scan_meta.model_copy(update={"track": "blackbox"}))
            # not-covered 成因判据（spec 2026-09-03 §6）：各类 verdicts 存在性 + 验证范围
            class_meta = await build_class_meta(run_dir / "deliverables")
            fused = fuse_report_data(wb_rd, bb_rd, blackbox_class_meta=class_meta)
            # run 收尾缺口聚合（spec 2026-09-03 §7）：completed + verification_gaps
            # 信号 → 续跑守卫放行依据（status 仍 completed，不标 failed——多数类
            # 可能已成功）。best-effort：信号写失败不阻塞报告产出。
            gaps_signal = {vc: m["gap_count"] for vc, m in class_meta.items()
                           if m.get("gap_count")}
            if gaps_signal:
                try:
                    self._store.update_blackbox_run(
                        self._ws_of(scan_dir), self._scan_id_of(scan_dir), run_id,
                        extra={"verification_gaps": gaps_signal})
                except Exception:  # noqa: BLE001 — best-effort 缺口信号
                    pass
            out_dir.mkdir(parents=True, exist_ok=True)
            await report_data_builder.write_report_data(
                fused, out_dir / "report_data.json")
            (out_dir / "combined_report.md").write_text(
                export_report_markdown(fused), encoding="utf-8")
        except Exception:  # noqa: BLE001 — fusion 失败回退旧 renderer（md 链路不断）
            from supernova_web.components.combined_report_renderer import (
                render_combined_report)
            render_combined_report(
                whitebox_root=whitebox_dir(scan_dir / "deliverables"),
                blackbox_root=blackbox_dir(run_dir / "deliverables"),
                out_dir=out_dir)

    async def _ensure_scan_end(self, scan_dir: Path, status: str = "completed") -> None:
        """幂等收尾（spec §7.4，修原 bug）：events 无 scan_end 才补写。

        成功路径黑盒 finalize 已写 scan_end → no-op（**不写第二条**，核心不变量）；
        异常/跳过/提交失败 → 补写 scan_end 防 _watch 永久 tail（_watch 纯 tail 认 scan_end 退出）。
        _watch 的 finally 兜底（"worker 未写 scan_end" 补写）仍作最后一道防线。

        假完成保险丝（2026-08-27 NodeGoat-20260827-152204 事故）：combined 扫描
        bb_phase 停在 precheck/pending + 零 completed_agents + 无白盒产物时，收口
        completed 必为假（白盒从未启动；正常完成必有 agent/产物双信号）——降级
        failed + bb_failure_detail 落盘。防任何新路径把「从未开始」标成「已完成」
        （completed 不可续跑，resume spec 状态集排除 = 死局）。
        """
        if self._has_scan_end(scan_dir / "events.ndjson"):
            return
        if status == "completed":
            fuse_reason = self._fake_combined_completion_reason(scan_dir)
            if fuse_reason:
                SessionManager(scan_dir.parent).update_session(scan_dir, {
                    "bb_failure_point": "fake_completed",
                    "bb_failure_detail": fuse_reason})
                _log.warning(
                    "fake-completion fuse tripped for %s: demoted scan_end to failed",
                    scan_dir.name)
                status = "failed"
        session_status = status if status in {"completed", "failed", "cancelled", "crashed", "timeout", "interrupted"} else None
        tail = f"combined {status}"
        if status == "failed":
            # 失败详情透出（precheck 落的 bb_failure_detail / 编排器落的 bb_reason）：
            # 裸 "combined failed" 无信息量，live 页 stderr_tail 块即刻变可读。
            try:
                data = SessionManager(scan_dir.parent).get_session_data(scan_dir)
            except Exception:  # noqa: BLE001 - 读不到就退回默认 tail
                data = {}
            extra = data.get("bb_failure_detail") or data.get("bb_reason")
            if extra:
                tail = f"{tail}: {str(extra)[:300]}"
        await self._write_scan_end(
            scan_dir / "events.ndjson", status, 0, tail,
            session_status=session_status, scan_dir=scan_dir)

    def _fake_combined_completion_reason(self, scan_dir: Path) -> str | None:
        """假完成保险丝判定（_ensure_scan_end 消费）：返降级原因 str（拦）或 None（放行）。

        拦截条件（合取，任一不满足即放行）：combined + bb_phase∈{precheck,pending} 前置
        阶段 + completed_agents 空 + deliverables/whitebox 产物不存在。零信号缺失容错：
        session 读失败 → 放行（保险丝只兜「从未开始」，不赌「读不到」）。
        已有 bb_failure_detail（上层已落过更具体原因，如 reconcile 的 authcheck 分流）
        → 沿用之，不覆盖。
        """
        try:
            data = SessionManager(scan_dir.parent).get_session_data(scan_dir)
        except Exception:  # noqa: BLE001 - 读不到不拦（保守放行）
            return None
        if not data.get("combined"):
            return None
        if data.get("bb_phase") not in ("precheck", "pending"):
            return None
        if data.get("completed_agents"):
            return None
        if (scan_dir / "deliverables" / "whitebox").exists():
            return None
        return data.get("bb_failure_detail") or (
            "收口校验：组合扫描被标记 completed 时零 agent 产出、无白盒产物"
            f"（bb_phase={data.get('bb_phase')}）——白盒从未启动，判定为假完成并降级 failed")

    def _scan_row_is_correlation(self, scan_dir: Path) -> bool:
        """scan 行是否 correlation 主行（C3 fix ①：段③就绪门/进度分母按行类型分流）。

        检测口径同 resume/_validate_reused_children：SessionManager.get_scan_type。"""
        try:
            return SessionManager(scan_dir.parent).get_scan_type(scan_dir) == "correlation"
        except Exception:  # noqa: BLE001 - session 读失败按非 correlation 处理（零回归）
            return False

    def _whitebox_deliverables_ready(self, scan_dir: Path) -> bool:
        """预检白盒产物可被黑盒利用（spec §7.3）：

        True iff deliverables/whitebox/recon_deliverable.md 存在 AND 至少一个非空
        {vt}_exploitation_queue.json（vulnerabilities 列表非空）。黑盒只 exploit 白盒发现的
        类，缺其一则跳过黑盒（bb_phase=skipped）。

        correlation 主行（C3 fix ①，spec 2026-08-24 §5.3 段③）：关联段产物落
        deliverables/ 根（write_correlation_deliverables：merged queue / topology /
        report），无 whitebox/ 子结构与 recon_deliverable.md——就绪门改查「至少一个
        非空合并 queue」（_count_nonempty_queues 的 correlation 分支收集）。
        """
        if self._scan_row_is_correlation(scan_dir):
            return self._count_nonempty_queues(scan_dir) > 0
        wb_dir = scan_dir / "deliverables" / "whitebox"
        if not (wb_dir / "recon_deliverable.md").is_file():
            return False
        return self._count_nonempty_queues(scan_dir) > 0

    def _count_nonempty_queues(self, scan_dir: Path) -> int:
        """数非空的 {vt}_exploitation_queue.json 数（vulnerabilities 列表非空）。用于
        段③预检 + expected_agents.blackbox 分母（spec §9.5）。

        白盒/组合行：deliverables/whitebox/ 下（tiering（spec 2026-08-18）：queue 是
        中间产物落 whitebox/intermediate/，老结构在桶顶层。glob 不递归，双 glob 覆盖
        ——intermediate 有则用之，同名不共存于两种结构）。
        correlation 主行（C3 fix ①）：关联段合并 queue 落 deliverables/ 根——用
        _find_queue_files 三处 glob 同序收集（对齐 multi orchestrator 的 queue 收集）。
        """
        if self._scan_row_is_correlation(scan_dir):
            queue_files = _find_queue_files(scan_dir / "deliverables")
        else:
            wb_dir = scan_dir / "deliverables" / "whitebox"
            if not wb_dir.is_dir():
                return 0
            queue_files = list(
                (wb_dir / INTERMEDIATE_SUBDIR).glob("*_exploitation_queue.json")
            ) or list(wb_dir.glob("*_exploitation_queue.json"))
        n = 0
        for qf in queue_files:
            try:
                data = json.loads(qf.read_text("utf-8", errors="replace"))
            except (json.JSONDecodeError, OSError):
                continue
            if isinstance(data, dict) and isinstance(data.get("vulnerabilities"), list) \
                    and len(data["vulnerabilities"]) > 0:
                n += 1
        return n

    async def _mark_bb(self, scan_dir: Path, phase: str,
                       reason: str | None = None) -> None:
        """写 session.json 的 bb_phase（+ bb_reason）。phase 取自
        {precheck, pending, running, completed, failed, skipped}（spec §9.2 分段）。

        best-effort（对齐 _mark_owner / _mark_submitted_at 的 read-modify-write 模式，
        经 SessionManager.update_session 合并，不覆盖其他 top-level key）。标记失败不阻塞接力。
        """
        data: dict = {"bb_phase": phase}
        if reason is not None:
            data["bb_reason"] = reason
        try:
            SessionManager(scan_dir.parent).update_session(scan_dir, data)
        except Exception:  # noqa: BLE001 - 标记 best-effort，不阻塞接力
            pass

    async def _mark_run(self, scan_dir: Path, run_id: str, phase: str,
                        reason: str | None = None,
                        status: str | None = None,
                        extra: dict | None = None) -> None:
        """run 级 phase 写入（spec §5.2/§5.3，取代 _mark_bb 对 run 的调用）：
        写 run 级 session（bb_phase/bb_reason/status）+ 任务 bb_runs[] 条目 + latest_bb_run。
        extra 并入 run session 与 bb_runs[] 条目（如 precheck 失败详情 bb_failure_*）。

        best-effort（对齐 _mark_bb）：经 ``_store.update_blackbox_run`` 合并，标记失败不阻塞
        接力。终态 status（completed/failed/skipped）顺带写 completed_at 时间戳。
        """
        try:
            self._store.update_blackbox_run(
                self._ws_of(scan_dir), self._scan_id_of(scan_dir), run_id,
                status=status, phase=phase, reason=reason, extra=extra,
                completed_at=_now_iso() if status in ("completed", "failed", "skipped",
                                                      "cancelled") else None)
        except Exception:  # noqa: BLE001 - best-effort，不阻塞接力
            pass
        if status in _RUN_TERMINAL_STATUSES:
            # run 事件文件补终态行（取消/run_timeout/worker 崩溃时黑盒 workflow 不跑
            # finalize，归并流依赖每源自己的 scan_end 判关流）——独立 best-effort：
            # session 标记失败不应连带跳过事件收口，反之亦然。
            try:
                await self._ensure_run_scan_end(scan_dir, run_id, status, reason)
            except Exception:  # noqa: BLE001
                pass

    async def _ensure_run_scan_end(self, scan_dir: Path, run_id: str,
                                   status: str, reason: str | None = None) -> None:
        """run 级 events.ndjson 的 scan_end 兜底（修归并流永不关流）。

        MergedEventTailer 的关流条件是「wb scan_end 已扣住 + 每个已发现 run 源见过
        scan_end」。黑盒 workflow 未走到 finalize 时 run-K/events.ndjson 不会有自己的
        scan_end——取消（except CancelledError 直接 return）、run_timeout 服务端判超时
        （代码内 except 不执行）、worker 崩溃后 finalize activity 无法执行、finalize
        自身 best-effort 失败（黑盒 workflows.py:503-507 指望的「web _watch 兜底」对
        run 子目录失效——_watch 只盯任务根）。旧收口（_mark_run/_reconcile）只写
        session，流因此永不关流（live 页永久「已连接」）。本方法统一在 run 标终态时
        补写事件行。

        幂等：run events 已有 scan_end（黑盒正常完成/失败的 finalize 已写）→ no-op；
        文件不存在（黑盒未提交，tailer 不会发现该源）→ no-op。
        """
        events = blackbox_run_dir(scan_dir, run_id) / "events.ndjson"
        if not events.exists() or self._has_scan_end(events):
            return
        await self._write_scan_end(
            events, status, -1, reason or f"run {status}（web 收口）")

    @staticmethod
    def _ws_of(scan_dir: Path) -> str:
        """从 scan_dir 派生 ws：<workspaces>/<ws>/scans/<scan_id> → <ws>。"""
        return scan_dir.parent.parent.name

    @staticmethod
    def _scan_id_of(scan_dir: Path) -> str:
        """从 scan_dir 派生 scan_id：scans/<scan_id> → <scan_id>。"""
        return scan_dir.name

    # ── 组合扫描崩溃恢复（spec §7.5，Task 5）────────────────────────────────

    async def _query_workflow_status(self, workflow_id: str) -> str | None:
        """查 temporal workflow 执行状态，返状态名小写（'running'/'completed'/…）或 None。

        None = 查询超时 / workflow 不存在 / temporal 不可达（best-effort，异常绝不阻塞
        reconcile）。对齐 orphan_reconciler._workflow_still_running 的 describe() 查询模式，
        但返完整状态名供 _reconcile_combined_scan 分支决策（completed vs running vs not-found）。
        """
        timeout = float(
            os.environ.get("SUPERNOVA_RECONCILE_TEMPORAL_TIMEOUT_SECONDS", "5"))

        async def _probe() -> str | None:
            client = await Client.connect(self._temporal_address())
            desc = await client.get_workflow_handle(workflow_id).describe()
            return desc.status.name.lower()  # RUNNING→"running", COMPLETED→"completed"

        try:
            return await asyncio.wait_for(_probe(), timeout=timeout)
        except Exception:  # noqa: BLE001 - 超时/断连/workflow 不存在 → None
            return None

    async def _fetch_workflow_result_status(self, workflow_id: str) -> str | None:
        """读**已终结** workflow 返回值里的业务 status（temporal 执行态 ≠ 业务终态）。

        黑盒 workflow「正常 return state.status=failed 不 raise」时 temporal 执行态是
        COMPLETED——_query_workflow_status 只见 COMPLETED 会吞业务失败（2026-09-11
        口径矛盾同族缺口）。终结后 result() 即时返回（非长轮询）。无类型 handle →
        dict，经 _workflow_result_status 双形态读取。best-effort：异常/超时 → None
        （reconcile 不阻塞，None 时回落原 completed 口径）。"""
        timeout = float(
            os.environ.get("SUPERNOVA_RECONCILE_TEMPORAL_TIMEOUT_SECONDS", "5"))

        async def _probe() -> str | None:
            client = await Client.connect(self._temporal_address())
            result = await client.get_workflow_handle(workflow_id).result()
            return self._workflow_result_status(result)

        try:
            return await asyncio.wait_for(_probe(), timeout=timeout)
        except Exception:  # noqa: BLE001 - 超时/断连/result 解码失败 → None
            return None

    async def _reconcile_combined_scan(self, scan_dir: Path) -> None:
        """进程重启后对组合扫描（combined=true）按 bb_phase 补接力/补报告/补 scan_end
        （spec §7.5 崩溃恢复）。

        组合接力是 scan_manager 进程内 asyncio task（非 Temporal durable），容器重启后
        _combined_orchestrator 协程丢失 → session 卡 running 且 events 无 scan_end。本方法
        在 orphan_reconciler 的 per-scan 恢复后被调用，按 bb_phase 分支恢复：

        - precheck + authcheck workflow COMPLETED + 白盒 COMPLETED → 补 _run_blackbox_phase。
        - pending + 白盒 workflow COMPLETED → 补 _run_blackbox_phase（接力）。
        - running + 黑盒 workflow COMPLETED → 读返回值业务 status：failed → run 标
          failed；否则补 _generate_combined_report + _mark_bb(completed)（执行态
          COMPLETED ≠ 业务成功，2026-09-11 口径矛盾修复）。
        - run 非终态 + workflow 不存在（编排随重启丢失、无可续执行）→ run 标 failed 收口
          （防 bb_runs 永久卡非终态，堵 delete/加 run 的状态门）。
        - 任意 bb_phase + workflow 仍 RUNNING → 不干预（让 temporal 自然完成）。
        - 任意 bb_phase + workflow 不活跃 + events 无 scan_end → _ensure_scan_end 补写。
        - precheck/pending + 主 workflow 不存在（2026-08-27 假完成事故分流）→ 查
          -authcheck workflow：RUNNING 不收口；FAILED → failed + 失败尾部透出；
          其余 → interrupted（编排丢失）。绝不默认 completed——「主 workflow 不存在」
          在这个阶段是「从未提交」不是「已完成」（completed 不可续跑 = 死局）。

        **非组合扫描立即返回（零回归）**——纯白盒/纯黑盒恢复路径不受影响。

        ws/scan_id 从 scan_dir 路径派生（<workspaces>/<ws>/scans/<scan_id>），与
        orphan_reconciler._workflow_id_from_scan_dir 同口径（不用 scan_dir.parent.name——
        那是 "scans" 非 ws，是原 bug #4 的根因）。
        """
        # 派生 ws/scan_id（与 _workflow_id_from_scan_dir 同口径，守 bug #4）
        if scan_dir.parent.name != "scans":
            return  # legacy 根 scan / 辅助目录 → 无可靠 ws/scan_id
        ws = scan_dir.parent.parent.name
        scan_id = scan_dir.name

        session_file = scan_dir / "session.json"
        if not session_file.exists():
            return
        try:
            data = json.loads(session_file.read_text("utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if not data.get("combined"):
            return  # 非组合 → 零回归（纯白盒/纯黑盒恢复路径不受影响）

        bb_runs = data.get("bb_runs") or []
        wf_active = False  # 白盒或某 run 的 workflow 仍 RUNNING → 跳过 scan_end 补写
        final_status = "completed"  # precheck 分流改写（failed/interrupted）；其余维持默认
        cancelled = False  # web 关停 cancel：跳过 finally 收口（见 except CancelledError）

        try:
            # 白盒 workflow：仍 running → 不干预（让 temporal 自然完成写 scan_end）。
            wb_status = await self._query_workflow_status(
                self._resolve_workflow_id(ws, scan_id))
            if wb_status == "running":
                wf_active = True
            elif data.get("bb_phase") in ("precheck", "pending"):
                # 假完成事故分流（2026-08-27 NodeGoat-20260827-152204）：主 workflow
                # 不在跑 + bb_phase 停在 precheck/pending →「主 workflow 不存在」的
                # 语义是「白盒从未提交」（precheck 未过 / 提交瞬间编排丢失），不是
                # 「已完成」。查 authcheck workflow（对账器此前不认识的 -authcheck
                # 后缀，precheck 阶段唯一在跑的 workflow）定收口语义：
                #   RUNNING → 不收口（worker 死了但 workflow 还在等 start_to_close
                #             超时窗口，收口会早于终态；等下次 reconcile 再处理）；
                #   FAILED  → failed + authcheck 失败尾部透出（stderr_tail，live 页
                #             即刻可读，对症事故里 3 次 LLM 超时的 CancelledError）；
                #   其余    → interrupted（编排丢失，留给 resume 续跑口——completed
                #             是死局，resume spec 状态集排除 completed）。
                ac_status = await self._query_workflow_status(
                    f"{ws}-{scan_id}-authcheck")
                if ac_status == "running":
                    wf_active = True
                elif ac_status == "failed":
                    SessionManager(scan_dir.parent).update_session(scan_dir, {
                        "bb_failure_point": "authcheck",
                        "bb_failure_detail": self._authcheck_failure_tail(scan_dir)})
                    final_status = "failed"
                else:
                    SessionManager(scan_dir.parent).update_session(scan_dir, {
                        "bb_reason": "编排随 web 重启丢失于白盒提交前后"
                                     "（authcheck 已结束，白盒未启动）"})
                    final_status = "interrupted"
            # 版本化 run（spec §7.5）：逐 run 探测其 -bb-{K} workflow 状态兜底。
            for r in bb_runs:
                run_id = r.get("run_id")
                if not run_id or r.get("status") in (
                        "completed", "failed", "skipped", "cancelled"):
                    continue
                bb_status = await self._query_workflow_status(
                    self._resolve_run_workflow_id(ws, scan_id, run_id))
                if bb_status == "running":
                    wf_active = True
                elif bb_status == "completed":
                    # run 黑盒完成（接力最后一步崩溃）→ 补 per-run 融合报告 + 标
                    # completed。执行态 COMPLETED ≠ 业务成功（黑盒失败走正常 return
                    # status=failed 不 raise）——须读返回值业务 status 分流，否则
                    # reconcile 吞失败（2026-09-11 口径矛盾同族缺口）。result 读不
                    # 到（None，best-effort）→ 维持原 completed 收口不回归。
                    if await self._fetch_workflow_result_status(
                            self._resolve_run_workflow_id(ws, scan_id, run_id)) == "failed":
                        await self._mark_run(
                            scan_dir, run_id, "failed", status="failed",
                            reason="blackbox workflow failed (reconciled)")
                    else:
                        await self._generate_combined_report(scan_dir, run_id)
                        await self._mark_run(scan_dir, run_id, "completed", status="completed")
                else:
                    # workflow 不存在/不可达（None）→ 编排随 web 重启丢失且无 Temporal 执行
                    # 可续 → run 标 failed 收口。否则 bb_runs 永久卡非终态，delete 的 bb_runs
                    # 门与加 run 的在跑守卫被永久禁用。口径与 finally 补 scan_end 的激进性
                    # 一致（_query_workflow_status 不可达也返 None）。
                    await self._mark_run(
                        scan_dir, run_id, "failed",
                        reason="编排中断（web 重启），run 未完成", status="failed")
        except asyncio.CancelledError:
            # web 关停取消 reconcile 后台 task：与编排协程 cancel 同理不收口（对账被
            # 中断 ≠ 扫描死了，写终态会把 Temporal 里还活着的组合扫描收成假终态）。
            # 下次启动 reconcile 幂等重来（2026-09-18 假终态事故同源）。
            cancelled = True
            raise
        except Exception:  # noqa: BLE001 - reconcile 是兜底增强，绝不因单 scan 异常拖垮
            _log.exception("_reconcile_combined_scan failed for %s", scan_dir)
        finally:
            # scan_end 不变量（review fix #1）：必须在 finally——即使 reconcile 内部
            # raise（如 Task-8 _generate_combined_report NotImplementedError stub、或
            # _run_blackbox_phase 提交后抛），也要确保 events 有 scan_end，否则 scan
            # 永久卡 running（orphan_reconciler 已委托本方法、未写 interrupted 兜底）。
            # workflow 仍活跃（wf_active=True）→ 跳过（让 temporal 自然完成写 scan_end）；
            # web 关停 cancel（cancelled=True）→ 跳过（同上，重启后对账幂等补收口）。
            if not wf_active and not cancelled:
                try:
                    await self._ensure_scan_end(scan_dir, status=final_status)
                except Exception:  # noqa: BLE001 - finally 内 best-effort
                    _log.exception(
                        "_ensure_scan_end failed in reconcile finally for %s", scan_dir)

    @staticmethod
    def _authcheck_failure_tail(scan_dir: Path) -> str:
        """authcheck 失败原因尾部（.authcheck/activity_failures.log 末 2048 字节）。

        事故形态：3 次 LLM 流挂死超时的 CancelledError 栈就落在这个 scratch 子目录
        （orphan_reconciler._failure_tail 只读任务根的 activity_failures.log，读不到
        authcheck 的）。供 _reconcile_combined_scan 的 authcheck-FAILED 分流落
        bb_failure_detail → _ensure_scan_end(failed) 拼 stderr_tail → live 页可见。
        """
        f = scan_dir / ".authcheck" / "activity_failures.log"
        if not f.exists():
            return "authcheck workflow failed（无 activity_failures.log 可读）"
        return ("认证预验证（authcheck）workflow 失败；日志尾部：\n"
                + f.read_text("utf-8", errors="replace")[-2048:])

    def _kick_combined_reconcile(self, scan_dir: Path) -> None:
        """Fire-and-forget 组合扫描恢复（review fix #2：非阻塞，防 startup 阻塞）。

        _reconcile_combined_scan 可能调 _run_blackbox_phase → await bb_handle.result()
        阻塞整个黑盒运行（分钟~小时级）。若在 orphan_reconciler.reconcile_orphaned 里
        inline await（startup 遍历 / events 触发），会阻塞 app 启动完成 + 串行阻塞其他
        孤儿 scan 恢复。故 reconcile_orphaned 调本方法（sync、立即返回），本方法内部
        asyncio.create_task 在后台跑 _reconcile_combined_scan（对齐 start() fire
        _combined_orchestrator 的 create_task 模式）。

        幂等：同一 (ws, scan_id) 已有在途恢复 task → 不重复 fire（防 re-entry 多重
        黑盒提交）。task 完成/异常后 finally 自 pop _reconcile_tasks。
        """
        if scan_dir.parent.name != "scans":
            return
        ws = scan_dir.parent.parent.name
        scan_id = scan_dir.name
        scan_key = (ws, scan_id)
        if scan_key in self._reconcile_tasks:
            return  # 已在恢复中（幂等）

        async def _run() -> None:
            try:
                await self._reconcile_combined_scan(scan_dir)
            except Exception:  # noqa: BLE001 - background task 必须自兜底（不崩 event loop）
                _log.exception(
                    "_reconcile_combined_scan background task failed for %s", scan_dir)
            finally:
                self._reconcile_tasks.pop(scan_key, None)

        self._reconcile_tasks[scan_key] = asyncio.create_task(_run())
