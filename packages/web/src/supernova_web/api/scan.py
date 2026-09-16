from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from supernova_web.auth.dependencies import current_user, workspace_member
from supernova_web.components.workspace_provisioner import is_global_admin, is_safe_workspace_name
from supernova_web.auth.models import User
from supernova_web.components.scan_manager import TemporalUnavailable
from supernova_web.components.ws_config_store import ProviderConfigIncomplete
from supernova_web.models import (
    BatchScanAccepted, BatchScanRequest, BatchScanResultItem, RepoSource, ScanAccepted, ScanRequest,
)

router = APIRouter(prefix="/api/scan", tags=["scan"])


def _repair_gate_ws(entries: list[dict]) -> None:
    """旧闸门快照的 ws 展示修复：从 web workflow_id 反推真实 workspace。

    web 的 workflow_id = ``{ws}-{scan_id}[-resume-N|-bb|-corr]``；早期 descriptor
    曾把 T3 契约里的 ``workspace_name=scan_id`` 直接填进 ws。这里只在 ws 缺失
    或等于 scan_id 时修复，CLI 的非空真实 ws 不受影响。
    """

    for e in entries:
        wf = e.get("workflow_id")
        scan_id = e.get("scan_id")
        ws = e.get("ws")
        if not wf or not scan_id or (ws and ws != scan_id):
            continue
        marker = f"-{scan_id}"
        idx = wf.rfind(marker)
        if idx > 0:
            e["ws"] = wf[:idx]


_GATE_ACTIVE_STATUSES = frozenset({"running", "queued"})
_GATE_TERMINAL_STATUSES = frozenset({
    "completed", "done", "failed", "interrupted", "cancelled", "killed",
    "crashed", "skipped", "timeout",
})
_BLACKBOX_RUN_ID = re.compile(r"^run-\d+$")


def _gate_entry_is_live(entry: dict, store: object) -> bool:
    """判断闸门快照条目是否仍应展示。

    ``gate_state.json`` 是 worker 的展示快照，worker 停止或 janitor 尚未运行时
    可能残留已中断任务。这里仅过滤 API 返回，不修改快照，也不参与 worker 的真实
    并发控制。无法把条目映射回 web scan（例如 CLI 扫描）时保留，避免误隐藏未知
    来源的有效闸门条目。

    黑盒 workflow 的 descriptor.scan_id 是 ``run-N``，而不是顶层 scan_id，因此
    需要在对应 workspace 的扫描目录下补一次 run 目录查找。
    """
    ws = entry.get("ws")
    scan_id = entry.get("scan_id")
    if not isinstance(ws, str) or not isinstance(scan_id, str) or not ws or not scan_id:
        return True

    from supernova_core.session import SessionManager
    from supernova_web.components.workspaces_indexer import _compute_status

    scan_dir = store.get_scan_dir(ws, scan_id)  # type: ignore[attr-defined]
    if scan_dir is not None:
        mgr = SessionManager(scan_dir.parent)
        # 与扫描列表使用同一状态计算口径：显式终态和已推断的 interrupted
        # 都不能继续出现在「占用/排队」展示中。
        status = _compute_status(scan_dir, mgr.get_status(scan_dir))
        return status in _GATE_ACTIVE_STATUSES

    if not _BLACKBOX_RUN_ID.fullmatch(scan_id):
        return True  # CLI/旧数据等无法按顶层 scan 目录解析的条目，保守保留

    # 黑盒 run 只有 run 目录，不会作为顶层 ScanStore scan 列出。
    for _task_id, task_dir in store._scan_entries(ws):  # type: ignore[attr-defined]
        run_dir = task_dir / "blackbox-runs" / scan_id
        if not (run_dir / "session.json").exists():
            continue
        task_status = SessionManager(task_dir.parent).get_status(task_dir)
        status = SessionManager(run_dir.parent).get_status(run_dir)
        # run 的 pending/running 仍可能尚未写首个 heartbeat；条目既已在闸门
        # 快照中，不能用心跳反向误删。只按明确终态过滤。
        return (status not in _GATE_TERMINAL_STATUSES
                and task_status not in _GATE_TERMINAL_STATUSES)
    return True


def _filter_stale_gate_entries(entries: list[dict], store: object) -> list[dict]:
    """从展示快照中移除已终态/已中断的 web 扫描条目。"""
    return [entry for entry in entries if _gate_entry_is_live(entry, store)]


@router.post("", response_model=ScanAccepted, status_code=202)
async def create_scan(req: ScanRequest, request: Request,
                      user: User = Depends(current_user)):
    # P1: scan 必须在 admin 预建好的 ws 内跑 (替代原 scan 创建 manager 模型)。
    # ws 先于 scan 存在, 为 P2 repo 隔离铺路; 这里只校验, 不创建。
    ws = req.workspace
    if not ws or not is_safe_workspace_name(ws):
        raise HTTPException(422, "workspace 不存在，请先让 admin 创建")
    ws_dir = request.app.state.config.workspaces_dir / ws
    if not ws_dir.is_dir() or ws_dir.is_symlink():
        raise HTTPException(422, "workspace 不存在，请先让 admin 创建")
    if not is_global_admin(user) and request.app.state.auth_store.get_workspace_member_role(
            ws, user.id) is None:
        raise HTTPException(403, "非该 workspace 成员")
    sm = request.app.state.scan_manager
    try:
        # Web workspace scan 必须使用完整的 workspace-owned Provider 配置，不能把全局
        # env/model 当作缺省值。API 层先检一遍，避免 fake/替代 scan manager 绕过约束。
        try:
            request.app.state.ws_config_store.resolve_provider_config(ws)
        except ProviderConfigIncomplete as e:
            # 工作区缺 LLM 凭据等必填字段 → 结构化错误，让前端区分于真正的 yaml 校验失败，
            # 显示「请前往工作区设置补全凭据」而非「yaml 校验失败」（HTTPException 穿透下方
            # 通用 except ValueError）。
            raise HTTPException(422, detail={"code": "provider_incomplete", "missing": e.missing})
        ws_name, scan_id = await sm.start(req)
    except TemporalUnavailable:
        raise HTTPException(400, "Temporal 服务未运行，请先 docker-compose up -d")
    except PermissionError as e:
        # OS-level EACCES/EPERM from ws_dir.mkdir()（git-creds 来源已于 Task 3 移除）
        raise HTTPException(400, str(e))
    except ValueError as e:
        raise HTTPException(422, str(e))
    except ValidationError as e:  # correlation yaml 校验失败
        raise HTTPException(422, detail=e.errors())
    # 组合扫描：start 已写 bb_phase=precheck 到 session（precheck 在后台 kickoff 跑）。
    # 读回透传给前端显「预验证中」+ 跳 live 页跟踪进度（spec §8.2）。best-effort：scan_dir
    # 不存在 / session 无 bb_phase → None（纯白盒/黑盒）。
    bb_phase = None
    if scan_id:
        from supernova_core.session import SessionManager
        scan_dir = request.app.state.config.workspaces_dir / ws_name / "scans" / scan_id
        if scan_dir.is_dir():
            try:
                bb_phase = SessionManager(scan_dir.parent).get_session_data(scan_dir).get("bb_phase")
            except Exception:  # noqa: BLE001 - 读 session best-effort，不阻塞提交响应
                bb_phase = None
    return ScanAccepted(workspace=ws_name, scan_id=scan_id, bb_phase=bb_phase)


@router.post("/batch", response_model=BatchScanAccepted, status_code=202)
async def create_scan_batch(req: BatchScanRequest, request: Request,
                            user: User = Depends(current_user)):
    """批量白盒扫描（spec 2026-09-11-batch-whitebox-scan §3）。

    端点层逐仓循环调既有 sm.start()——scan_manager 零改动；单仓失败（未就绪/
    不存在/排队满/Temporal 异常）只计入该仓 results，不阻断整批。有任何成功 →
    202；全部失败 → 422 附 results。并发由 worker ScanGate 排队（web 不限）。
    """
    ws = req.workspace
    if not ws or not is_safe_workspace_name(ws):
        raise HTTPException(422, "workspace 不存在，请先让 admin 创建")
    ws_dir = request.app.state.config.workspaces_dir / ws
    if not ws_dir.is_dir() or ws_dir.is_symlink():
        raise HTTPException(422, "workspace 不存在，请先让 admin 创建")
    if not is_global_admin(user) and request.app.state.auth_store.get_workspace_member_role(
            ws, user.id) is None:
        raise HTTPException(403, "非该 workspace 成员")
    try:
        request.app.state.ws_config_store.resolve_provider_config(ws)
    except ProviderConfigIncomplete as e:
        raise HTTPException(422, detail={"code": "provider_incomplete", "missing": e.missing})

    sm = request.app.state.scan_manager
    results: list[BatchScanResultItem] = []
    for repo in req.repos:
        single = ScanRequest(
            type="whitebox",
            source=RepoSource(kind="repo", value=repo),
            url=req.url,
            workspace=req.workspace,
            authentication=req.authentication,
            auth_accounts=req.auth_accounts,
            auth_profile_id=req.auth_profile_id,
            auth_credential_ids=req.auth_credential_ids,
            host_profile_id=req.host_profile_id,
            host_profile_ids=req.host_profile_ids,
            host_url=req.host_url,
            delete_repo_on_finish=req.delete_repo_on_finish,
        )
        try:
            _, scan_id = await sm.start(single)
            results.append(BatchScanResultItem(repo=repo, ok=True, scan_id=scan_id))
        except TemporalUnavailable:
            results.append(BatchScanResultItem(
                repo=repo, ok=False, error="Temporal 服务未运行，请先 docker-compose up -d"))
        except PermissionError as e:
            results.append(BatchScanResultItem(repo=repo, ok=False, error=str(e)))
        except ValueError as e:
            results.append(BatchScanResultItem(repo=repo, ok=False, error=str(e)))

    submitted = sum(1 for r in results if r.ok)
    failed = len(results) - submitted
    if submitted == 0:
        # 全失败 → 422，body 顶层即 BatchScanAccepted（results 不裹 detail——
        # 端点测试锁 body["results"]；与 provider_incomplete 的 detail 包裹不同）。
        return JSONResponse(
            status_code=422,
            content=BatchScanAccepted(
                workspace=ws, submitted=0, failed=failed, results=results).model_dump())
    return BatchScanAccepted(workspace=ws, submitted=submitted, failed=failed, results=results)


@router.get("/gate")
async def get_scan_gate(request: Request, user: User = Depends(current_user)):
    """全局扫描闸门快照（排队可视化，spec 2026-09-08-worker-scan-gate §8.1）。

    快照由 worker 闸门原子写（<workspaces_root>/gate_state.json）；文件缺失/损坏
    = worker 未起或未配置落盘 → 空快照。**全员可见完整快照，不按 ws 成员过滤**
    （2026-09-09 用户裁定）：闸门是共享调度器，其存在意义就是让所有用户看到全局
    占用与自己的排队位次——成员过滤会让「为什么排队」的答案本身缺失。条目只含
    ws/类型/标签/时刻，不含报告或漏洞数据。
    """
    from supernova_core.services.scan_gate import read_gate_snapshot_file
    sf = request.app.state.config.workspaces_dir / "gate_state.json"
    snap = read_gate_snapshot_file(sf) or {
        "capacity": 5, "max_waiting": 500, "held": [], "waiting": []}
    _repair_gate_ws(snap.get("held", []))
    _repair_gate_ws(snap.get("waiting", []))
    # gate_state.json 不是权威状态，worker 停止/janitor 延迟时可能残留幽灵条目。
    # 按当前 scan 状态过滤展示结果；不改共享快照，真实闸门仍由 worker 管理。
    from supernova_web.components.scan_store import ScanStore
    scan_store = ScanStore(request.app.state.config.workspaces_dir)
    snap["held"] = _filter_stale_gate_entries(snap.get("held", []), scan_store)
    snap["waiting"] = _filter_stale_gate_entries(snap.get("waiting", []), scan_store)
    return snap
