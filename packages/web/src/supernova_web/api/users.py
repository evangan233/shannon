# packages/web/src/supernova_web/api/users.py
from __future__ import annotations

import shutil

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from typing import Literal

from supernova_web.auth.csrf import verify_csrf
from supernova_web.auth.dependencies import current_user, require_admin
from supernova_web.auth.models import User
from supernova_web.auth.routes import clear_login_failures
from supernova_web.auth.passwords import (
    DEFAULT_NEW_USER_PASSWORD,
    NEW_PASSWORD_MIN_LEN,
    hash_password,
)
from supernova_web.components.workspace_provisioner import (
    ensure_global_admin_access,
    ensure_user_workspace,
    is_global_admin,
    is_safe_workspace_name,
)

router = APIRouter(prefix="/api/users", tags=["users"])


class PinnedWorkspaceIn(BaseModel):
    workspace: str


# per-user UI 主题白名单（2026-08-28）＝前端 theme.ts 的 ThemeId 全集（THEMES + "system"）。
# 新增主题时须同步：tokens.css/theme.ts/i18n 之外的第 5 处（见 memory 新增主题步骤）。
# 严格白名单而非宽松存：新主题忘加此处是显式失败（422 可排查），优于脏值静默入库。
VALID_THEMES = frozenset({
    "system", "charcoal", "warm-paper", "mac", "midnight", "graphite",
    "sentry", "arc", "mission", "ember",
    "catppuccin", "rose-pine", "gruvbox", "dracula",
    "github", "notion", "kami", "blueprint", "openai",
    "catppuccin-latte", "rose-pine-dawn", "gruvbox-light", "solarized-light",
})


class ThemeIn(BaseModel):
    theme: str


@router.put("/me/theme")
async def set_theme(body: ThemeIn, request: Request,
                    user: User = Depends(current_user)):
    """per-user UI 主题（跟账号走，跨设备一致，与工作区无关）。任何登录用户可自配。"""
    _check_csrf(request)
    if body.theme not in VALID_THEMES:
        raise HTTPException(422, f"invalid theme: {body.theme!r}")
    request.app.state.auth_store.update_theme(user.id, body.theme)
    return {"theme": body.theme}


@router.put("/me/pinned-workspace")
async def set_pinned_workspace(body: PinnedWorkspaceIn, request: Request,
                               user: User = Depends(current_user)):
    """per-user 置顶工作区（IA 重设计 §2.3）。只能 pin 有权限的 ws
    （admin 全部、其他用户需为成员）。"""
    _check_csrf(request)
    if not is_safe_workspace_name(body.workspace):
        raise HTTPException(422, "invalid workspace name")
    # workspace_member 依赖项的 ws 来自路径参数，此处 ws 来自 body，手动复用同款鉴权。
    # 顺序：先 403（成员检查）后 404（存在性）--非成员对任意 ws 一律 403，不泄露 ws 存在性，
    # 与 workspace_member 依赖项语义一致；admin 跳过 403 后命中 404。get_workspace_member_role
    # 对不存在的 ws 返 None -> 403，故非成员探测不到存在性。
    if not is_global_admin(user):
        role = request.app.state.auth_store.get_workspace_member_role(body.workspace, user.id)
        if role is None:
            raise HTTPException(403, "not a workspace member")
    ws_dir = request.app.state.config.workspaces_dir / body.workspace
    if not ws_dir.exists():
        raise HTTPException(404, "workspace not found")
    request.app.state.auth_store.update_pinned_workspace(user.id, body.workspace)
    return {"pinned": body.workspace}


class CreateUserIn(BaseModel):
    username: str
    password: str = ""  # 留空 -> 落 DEFAULT_NEW_USER_PASSWORD（免 admin 手填）
    role: Literal["admin", "user"] = "user"


class UpdateRoleIn(BaseModel):
    role: Literal["admin", "user"]


class ResetPasswordIn(BaseModel):
    new_password: str


def _user_out(u: User) -> dict:
    return {"id": u.id, "username": u.username, "role": u.role,
            "must_change_password": u.must_change_password, "created_at": u.created_at}


def _check_csrf(request: Request) -> None:
    if not verify_csrf(request.headers.get("x-csrf-token"), request.cookies.get("sn-csrf")):
        raise HTTPException(status_code=403, detail="invalid csrf token")


def _admin_count(store) -> int:
    return sum(1 for u in store.list_all_users() if u.role == "admin")


@router.get("")
async def list_users(request: Request, _: User = Depends(require_admin)):
    store = request.app.state.auth_store
    return {"users": [_user_out(u) for u in store.list_all_users()]}


@router.post("")
async def create_user(body: CreateUserIn, request: Request, _: User = Depends(require_admin)):
    _check_csrf(request)
    # 留空 -> 默认密码（6 位，同 bootstrap admin 语义，must_change=True 兜底）；
    # 手填 -> 仍走长度校验。
    if not body.password:
        password = DEFAULT_NEW_USER_PASSWORD
    elif len(body.password) < NEW_PASSWORD_MIN_LEN:
        raise HTTPException(400, f"password must be at least {NEW_PASSWORD_MIN_LEN} characters")
    else:
        password = body.password
    store = request.app.state.auth_store
    if store.get_user_by_username(body.username) is not None:
        raise HTTPException(409, "username exists")
    if not is_safe_workspace_name(body.username):
        raise HTTPException(422, "invalid username for workspace")
    workspaces_dir = request.app.state.config.workspaces_dir
    workspace_path = workspaces_dir / body.username
    workspace_preexisted = workspace_path.exists() or workspace_path.is_symlink()
    if workspace_preexisted:
        raise HTTPException(409, "workspace already exists for username")

    u = store.create_user(body.username, hash_password(password),
                          role=body.role, must_change=True)
    try:
        ensure_user_workspace(workspaces_dir, store, u)
        ensure_global_admin_access(workspaces_dir, store)
    except FileExistsError:
        store.delete_user(u.id)
        raise HTTPException(409, "workspace already exists for username")
    except Exception:
        store.delete_user(u.id)
        if not workspace_preexisted and workspace_path.is_dir() and not workspace_path.is_symlink():
            shutil.rmtree(workspace_path, ignore_errors=True)
        raise HTTPException(500, "failed to provision user workspace")
    return {"user": _user_out(u)}


@router.delete("/{user_id}")
async def delete_user(user_id: int, request: Request, admin: User = Depends(require_admin)):
    _check_csrf(request)
    store = request.app.state.auth_store
    target = store.get_user(user_id)
    if target is None:
        raise HTTPException(404, "user not found")
    if target.id == admin.id:
        raise HTTPException(409, "cannot delete self")
    if target.role == "admin" and _admin_count(store) <= 1:
        raise HTTPException(409, "cannot delete last admin")
    store.delete_user(user_id)
    return {"ok": True}


@router.patch("/{user_id}")
async def update_role(user_id: int, body: UpdateRoleIn, request: Request,
                      admin: User = Depends(require_admin)):
    _check_csrf(request)
    store = request.app.state.auth_store
    target = store.get_user(user_id)
    if target is None:
        raise HTTPException(404, "user not found")
    if target.id == admin.id and body.role != "admin":
        raise HTTPException(409, "cannot demote self")
    if target.role == "admin" and body.role != "admin" and _admin_count(store) <= 1:
        raise HTTPException(409, "cannot demote last admin")
    previous_role = target.role
    store.update_role(user_id, body.role)
    if body.role == "admin":
        ensure_global_admin_access(request.app.state.config.workspaces_dir, store)
    elif previous_role == "admin":
        store.remove_user_from_workspaces(target.id)
        own_workspace = request.app.state.config.workspaces_dir / target.username
        if own_workspace.is_dir():
            store.ensure_workspace_member(target.username, target.id, "manager")
    return {"ok": True}


@router.post("/{user_id}/reset-password")
async def reset_password(user_id: int, body: ResetPasswordIn, request: Request,
                         _: User = Depends(require_admin)):
    _check_csrf(request)
    if len(body.new_password) < NEW_PASSWORD_MIN_LEN:
        raise HTTPException(400, f"password must be at least {NEW_PASSWORD_MIN_LEN} characters")
    store = request.app.state.auth_store
    target = store.get_user(user_id)
    if target is None:
        raise HTTPException(404, "user not found")
    store.reset_password(user_id, hash_password(body.new_password))
    # 重置即解锁：用户多半是因反复输错被 BruteGuard 锁住才找 admin 重置的，
    # 旧凭证已作废，失败计数/锁定一并清除（否则正确的新密码也 429）。
    clear_login_failures(target.username)
    return {"ok": True}


@router.get("/{user_id}/workspaces")
async def user_workspaces(user_id: int, request: Request, _: User = Depends(require_admin)):
    store = request.app.state.auth_store
    if store.get_user(user_id) is None:
        raise HTTPException(404, "user not found")
    pairs = store.list_user_workspaces_with_role(user_id)
    return {"workspaces": [{"workspace": w, "role": r} for w, r in pairs]}
