from __future__ import annotations

import shutil

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from supernova_web.auth.dependencies import current_user, require_admin, workspace_manager
from supernova_web.components.workspace_provisioner import (
    ensure_global_admin_members,
    is_global_admin,
    is_safe_workspace_name,
)
from supernova_web.components.ws_config_store import default_ws_config
from supernova_web.auth.models import User

router = APIRouter(prefix="/api/workspaces", tags=["workspaces"])


def _workspace_path(request: Request, ws: str):
    if not is_safe_workspace_name(ws):
        raise HTTPException(422, "invalid workspace name")
    p = request.app.state.config.workspaces_dir / ws
    if p.is_symlink() or not p.exists():
        raise HTTPException(404, "workspace not found")
    return p


class CreateWorkspaceIn(BaseModel):
    name: str


@router.post("", status_code=201)
async def create_workspace(body: CreateWorkspaceIn, request: Request,
                           user: User = Depends(require_admin)):
    """P1: admin 显式建 workspace (替代原 scan 创建 manager 模型)。

    ws 先于 scan 存在, 为 P2 repo 隔离铺路; admin 自动成为 manager,
    其他成员由 admin 预分配 (P1 Task 5/6)。

    T2: 写 workspace.json（ws 元数据 {name, created_at, owner, description?}）替代旧
    minimal session.json。1 ws : N scans 后 ws 元数据与 scan 状态机解耦--ws 级元数据
    在 workspace.json，scan 状态机在各 scans/<scan_id>/session.json。空 ws 经
    indexer 聚合 scan_count=0 可见（read_workspace_meta 认 workspace.json）。
    """
    from supernova_web.components.scan_store import write_workspace_meta
    ws = body.name
    if not is_safe_workspace_name(ws):
        # 点前缀是系统保留段（.system 存全局共享档案），拒防路径碰撞 + UI 混淆
        raise HTTPException(422, "workspace 名不可以点开头")
    ws_dir = request.app.state.config.workspaces_dir / ws
    if ws_dir.exists() or ws_dir.is_symlink():
        raise HTTPException(409, "workspace already exists")
    ws_dir.mkdir(parents=True)
    write_workspace_meta(ws_dir, name=ws, owner=user.username)
    request.app.state.ws_config_store.write(ws, default_ws_config())
    store = request.app.state.auth_store
    store.add_workspace_member(ws, user.id, "manager")
    ensure_global_admin_members(ws, store)
    return {"name": ws}


@router.get("")
async def list_workspaces(request: Request, user: User = Depends(current_user)):
    idx = request.app.state.indexer
    idx.sync_active(request.app.state.scan_manager.active_pids())
    all_ws = idx.list_workspaces()
    if is_global_admin(user):
        return all_ws
    allowed = set(request.app.state.auth_store.list_user_workspaces(user.id))
    return [w for w in all_ws if w["name"] in allowed]


@router.delete("/{ws}")
async def delete_workspace(ws: str, request: Request, _: User = Depends(workspace_manager)):
    p = _workspace_path(request, ws)  # 404 if 不存在
    idx = request.app.state.indexer
    # 活跃判定：1 ws : N scans 后改为「任意 scan 在跑」-> 409 先 cancel。
    # ScanStore.list_scans 双源（新 scans/<id>/ + legacy ws 根 session.json），
    # _compute_status 终态优先 + heartbeat 判活。heartbeat stale 但尚未 Temporal 对账的
    # reconnecting 仍可能在 retry/接管，和 running/queued 一样禁止删工作区。
    from supernova_web.components.scan_store import ScanStore
    store = ScanStore(request.app.state.config.workspaces_dir)
    if any(s.status in {"running", "queued", "reconnecting"}
           for s in store.list_scans(ws)):
        raise HTTPException(status_code=409, detail="workspace running, cancel scan first")
    shutil.rmtree(p)
    idx.set_active_pid(ws, None)
    request.app.state.auth_store.delete_workspace_members(ws)
    return {"deleted": ws}


# 注：旧 ws-scoped GET shim（GET /{ws}、/{ws}/deliverables|report|logs、/{ws}/events）
# 已移除（Phase 2 前端全切 scan-scoped /{ws}/scans/{scan_id}/...，零前端调用，联合验收确认）。
# scan-scoped 等价端点见 api/scans.py。DELETE /api/scan/{ws}（旧 cancel-latest shim）也已于
# e1406473 移除（前端 WorkspaceListPage 改 cancelActiveScan 走 scan-scoped）；POST /api/scan 保留（真端点，api/scan.py）。
