from __future__ import annotations

import logging
import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel

from . import sso as sso_mod
from .brute import BruteGuard
from .csrf import generate_csrf_token, verify_csrf
from .dependencies import current_user, require_admin
from .models import SsoConfig, User
from .passwords import hash_password, verify_password
from supernova_web.components.workspace_provisioner import ensure_user_workspace

router = APIRouter(prefix="/api/auth", tags=["auth"])

_brute = BruteGuard()
_log = logging.getLogger("supernova_web.auth")


def clear_login_failures(username: str) -> None:
    """清除某用户的登录失败计数/锁定（供 admin 重置密码后调用）。

    重置语义 = 旧凭证全部作废，锁定的依据（失败计数）无继续存在的理由；
    现场场景：用户反复输错被锁 5 分钟（正确密码也 429），找 admin 重置后
    应立即可用新密码登录，而非再等锁过期。
    """
    _brute.reset(username)


class LoginIn(BaseModel):
    username: str
    password: str


class ChangePasswordIn(BaseModel):
    old_password: str
    new_password: str


# 新密码最小长度（change-password 校验）。弱默认密码（如 123456）改密时应强制
# 不少于 8 位，避免用户把默认弱密码改成另一个弱密码。
_NEW_PASSWORD_MIN_LEN = 8


def _user_out(u: User) -> dict:
    return {"id": u.id, "username": u.username, "role": u.role,
            "must_change_password": u.must_change_password,
            "last_visited_workspace": u.last_visited_workspace,
            "avatar_url": u.avatar_url,
            "auth_provider": u.auth_provider,
            "theme": u.theme}


def _check_csrf(request: Request) -> None:
    """写端点显式 CSRF 校验（名字/签名对齐 api/users.py 同名惯例；无效 token → 403）。"""
    if not verify_csrf(request.headers.get("x-csrf-token"), request.cookies.get("sn-csrf")):
        raise HTTPException(status_code=403, detail="invalid csrf token")


def _cookie_secure(cfg, request: Request) -> bool:
    """sn-sid/sn-csrf 是否打 Secure 标志。

    - cfg.cookie_secure=True（env SUPERNOVA_WEB_COOKIE_SECURE=1）→ 无条件 secure
    - 否则按请求实际 scheme：HTTPS（含反代 X-Forwarded-Proto）才 secure
    修复：曾一律用 cfg.cookie_secure 且默认 True，而 main() 纯 HTTP 启动 →
    http:// 下浏览器丢弃 cookie → 登录循环。
    """
    if cfg.cookie_secure:
        return True
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme).lower()
    return scheme == "https"


def _cookie_kwargs(cfg, request: Request, ttl_hours: int | None = None) -> dict:
    ttl = ttl_hours if ttl_hours is not None else cfg.session_ttl_hours
    return {"httponly": True, "samesite": "lax", "secure": _cookie_secure(cfg, request),
            "max_age": ttl * 3600}


@router.get("/csrf")
def csrf(request: Request):
    cfg = request.app.state.config
    tok = generate_csrf_token()
    resp = JSONResponse({"csrf_token": tok})
    resp.set_cookie("sn-csrf", tok, httponly=False, samesite="lax",
                    secure=_cookie_secure(cfg, request))
    return resp


@router.post("/login")
def login(body: LoginIn, request: Request):
    cfg = request.app.state.config
    if not verify_csrf(request.headers.get("x-csrf-token"), request.cookies.get("sn-csrf")):
        raise HTTPException(status_code=403, detail="invalid csrf token")
    if _brute.is_locked(body.username):
        raise HTTPException(status_code=429, detail="too many attempts, try later")
    store = request.app.state.auth_store
    user = store.get_user_by_username(body.username)
    pw_hash = store.get_password_hash(body.username) if user else None
    ok = pw_hash is not None and verify_password(body.password, pw_hash)
    if not ok:
        _brute.record_failure(body.username)
        raise HTTPException(status_code=401, detail="invalid credentials")
    _brute.reset(body.username)
    sid = request.app.state.session_manager.create(user.id)
    resp = JSONResponse({"user": _user_out(user)})
    resp.set_cookie("sn-sid", sid, **_cookie_kwargs(cfg, request))
    tok = generate_csrf_token()  # 登录后续签 csrf
    resp.set_cookie("sn-csrf", tok, httponly=False, samesite="lax",
                    secure=_cookie_secure(cfg, request),
                    max_age=cfg.session_ttl_hours * 3600)
    return resp


@router.post("/change-password")
def change_password(body: ChangePasswordIn, request: Request, user: User = Depends(current_user)):
    """已登录用户改密码。需 CSRF + 登录态；校验旧密码正确、新密码合法后改 hash
    并清 must_change_password。默认账号（must_change_password=True）改密后即脱提醒。"""
    if not verify_csrf(request.headers.get("x-csrf-token"), request.cookies.get("sn-csrf")):
        raise HTTPException(status_code=403, detail="invalid csrf token")
    if len(body.new_password) < _NEW_PASSWORD_MIN_LEN:
        raise HTTPException(status_code=400, detail=f"new password must be at least {_NEW_PASSWORD_MIN_LEN} characters")
    if body.new_password == body.old_password:
        raise HTTPException(status_code=400, detail="new password must differ from old")
    store = request.app.state.auth_store
    pw_hash = store.get_password_hash(user.username)
    if pw_hash is None or not verify_password(body.old_password, pw_hash):
        raise HTTPException(status_code=401, detail="invalid credentials")
    store.update_password(user.id, hash_password(body.new_password))
    return {"ok": True}


# ── SSO（富途 OA passport，spec 2026-08-25 §5.2；配置运行时化 spec 2026-08-26）─────

def _sso_rt(request: Request) -> SsoConfig:
    """SSO 运行时配置（spec 2026-08-26 §7.2）：每请求直读 auth.db sso_config 单行表
    （admin 设置页 PUT 即时生效，无重启），public_base_url 空 → resolve_runtime 回落。"""
    return sso_mod.resolve_runtime(request.app.state.auth_store.get_sso_config())


@router.get("/sso/config")
def sso_config(request: Request):
    """公开：前端登录页据此渲染/隐藏「使用 OA 账号登录」按钮。"""
    return {"enabled": _sso_rt(request).enabled}


@router.get("/sso/login")
def sso_login(request: Request, next: str = "/"):
    sc = _sso_rt(request)
    if not sc.enabled:
        raise HTTPException(status_code=404, detail="sso disabled")
    url = sso_mod.build_passport_login_url(sc.passport_base, sc.public_base_url, next)
    return RedirectResponse(url, status_code=302)


@router.get("/sso/callback")
def sso_callback(request: Request, AUTH_TICKET: str = "", next: str = "/"):
    """OA 登录后 302 回调。校验链（spec §5.2）：开关→ticket 存在→防重放→
    validateTicket→白名单→按 nick 查找/创建账号→确保工作区→建 session。
    任一失败 302 /login?sso_error=<code>。"""
    cfg = request.app.state.config
    sc = _sso_rt(request)
    store = request.app.state.auth_store
    if not sc.enabled:
        raise HTTPException(status_code=404, detail="sso disabled")
    next_path = sso_mod.safe_next(next)

    def _fail(code: str) -> RedirectResponse:
        return RedirectResponse(f"/login?sso_error={code}", status_code=302)

    if not AUTH_TICKET:
        return _fail("missing_ticket")
    if store.is_ticket_used(AUTH_TICKET):
        return _fail("replayed_ticket")
    try:
        info = sso_mod.validate_ticket(sc.passport_base, sc.auth_domain, AUTH_TICKET)
    except sso_mod.SsoTicketError as exc:
        # 安全收口：只落机器码 + ticket 前 8 位掩码——upstream_error 的 message 含完整
        # validateTicket URL（即 ticket 明文），禁 str(exc)/__cause__/traceback 入日志。
        _log.warning("sso ticket rejected: %s (ticket=%s…)", exc.code, AUTH_TICKET[:8])
        return _fail(exc.code)
    # 白名单为运行时开关管控（admin 可在设置页关闭=全员可登录）。
    # Passport 已在服务端完成 ticket / authDomain 校验；按当前业务约定，OA
    # 返回的 nick 是权威身份，后续应复用同 nick 的既有本地账号，而不是再做
    # 一层会让合法 SSO 登录失败的本地账号冲突拦截。
    if store.get_whitelist_enabled() and not store.is_nick_whitelisted(info.nick):
        _log.warning("sso nick not whitelisted: %r", info.nick)
        return _fail("not_whitelisted")
    store.mark_ticket_used(AUTH_TICKET)

    # OA 是本部署的权威身份源：已有账号（无论原先是 password 还是 sso）
    # 直接复用其 id / role / 本地密码；不会改密码或角色。新账号使用
    # “用户名+@123”作为初始本地密码，并只保存 bcrypt hash。
    user = store.get_user_by_username(info.nick)
    created = False
    if user is None:
        try:
            user = store.create_user(info.nick, hash_password(f"{info.nick}@123"),
                                     role="user", auth_provider="sso")
            created = True
        except sqlite3.IntegrityError:
            # 两个不同 ticket 并发首次登录同一 OA nick 时，唯一约束可能由
            # 另一请求先完成；重新读取后按既有账号路径继续，避免偶发 500。
            user = store.get_user_by_username(info.nick)
            if user is None:
                raise

    # SSO 首次登录必须同时具备同名工作区和成员关系；对既有账号也做幂等
    # reconciliation，修复历史账号/启动对账尚未完成时的登录空窗。
    try:
        ensure_user_workspace(request.app.state.config.workspaces_dir, store, user)
    except Exception:
        if created:
            try:
                store.delete_user(user.id)
            except Exception:
                _log.exception("failed to roll back SSO user after workspace provisioning failure")
        _log.exception("sso workspace provisioning failed for nick=%r", info.nick)
        return _fail("workspace_provision_failed")

    store.update_avatar(user.id, info.avatar_url)

    sid = request.app.state.session_manager.create(
        user.id, ttl_hours=sc.session_ttl_hours, auth_method="sso")
    resp = RedirectResponse(next_path, status_code=302)
    resp.set_cookie("sn-sid", sid, **_cookie_kwargs(cfg, request, ttl_hours=sc.session_ttl_hours))
    tok = generate_csrf_token()  # 对齐账密登录：建会话后续签 csrf
    resp.set_cookie("sn-csrf", tok, httponly=False, samesite="lax",
                    secure=_cookie_secure(cfg, request),
                    max_age=sc.session_ttl_hours * 3600)
    return resp


class WhitelistIn(BaseModel):
    nick: str


@router.get("/sso/whitelist")
def sso_whitelist_list(request: Request):
    # 关闭态 404 必须先于 admin 判定：Depends(require_admin) 在函数体之前执行，
    # 未登录请求会先撞 401（spec「SSO 关闭 404」且不向未认证方泄露端点存在），
    # 故此处函数体内先查开关再手动调 require_admin（其读 request.state.user，直接调用等价）。
    if not _sso_rt(request).enabled:
        raise HTTPException(status_code=404, detail="sso disabled")
    require_admin(request)
    rows = request.app.state.auth_store.get_sso_whitelist()
    # enabled=白名单运行时开关现值（前端 toggle 回显，无行默认开）
    return {"whitelist": [{"nick": r[0], "added_by": r[1], "created_at": r[2]} for r in rows],
            "enabled": request.app.state.auth_store.get_whitelist_enabled()}


@router.post("/sso/whitelist")
def sso_whitelist_add(body: WhitelistIn, request: Request, admin: User = Depends(require_admin)):
    # 写端点显式 CSRF（最终审查采纳项）：对齐 users.py/_check_csrf 惯例；
    # 前端 client.ts 对 POST/DELETE 自动注入 X-CSRF-Token，零适配成本。
    _check_csrf(request)
    nick = body.nick.strip()
    if not nick:
        raise HTTPException(status_code=422, detail="nick must not be blank")
    request.app.state.auth_store.add_sso_whitelist(nick, admin.username)
    return {"ok": True}


@router.delete("/sso/whitelist/{nick}")
def sso_whitelist_remove(nick: str, request: Request, _admin: User = Depends(require_admin)):
    _check_csrf(request)  # 同上：写端点显式 CSRF
    request.app.state.auth_store.remove_sso_whitelist(nick)
    return {"ok": True}


class WhitelistToggleIn(BaseModel):
    enabled: bool


@router.post("/sso/whitelist/enabled")
def sso_whitelist_set_enabled(body: WhitelistToggleIn, request: Request, admin: User = Depends(require_admin)):
    """运行时切换白名单管控：关闭=所有 OA 认证用户可登录（JIT 建户照常）。"""
    # 检查顺序照抄同文件白名单写端点（sso_whitelist_add）：Depends(require_admin)
    # 先于函数体（未登录 401 / 非 admin 403）→ _check_csrf（403）→ SSO 关闭 404。
    _check_csrf(request)
    if not _sso_rt(request).enabled:
        raise HTTPException(status_code=404, detail="sso disabled")
    request.app.state.auth_store.set_whitelist_enabled(body.enabled, admin.username)
    return {"ok": True, "enabled": body.enabled}


# ── SSO 运行时配置 admin API（spec 2026-08-26 §7.1）───────────────────────────
# 注意：本组端点不受 sso_enabled 404 短路——它就是用来在 SSO 关闭时配置并开启的。

class SsoConfigIn(BaseModel):
    """PUT body：全量更新 5 项（spec §6 校验在端点内）。"""
    enabled: bool
    auth_domain: str = ""
    public_base_url: str = ""
    passport_base: str = "https://passport.futuoa.com"
    session_ttl_hours: int = 24


@router.get("/sso/admin/config")
def sso_admin_config_get(request: Request, _admin: User = Depends(require_admin)):
    """SSO 5 项运行时配置现值 + updated_at/by（public_base_url 回显原始值，回落不落库）。"""
    return request.app.state.auth_store.get_sso_config()


@router.put("/sso/admin/config")
def sso_admin_config_put(body: SsoConfigIn, request: Request, admin: User = Depends(require_admin)):
    """全量更新 SSO 配置，即时生效（校验链 spec 2026-08-26 §6——原启动 fail-fast 迁移至此）。"""
    _check_csrf(request)
    if not body.passport_base.startswith("https://"):
        raise HTTPException(status_code=400, detail="passport_base must start with https://")
    if body.enabled and not body.auth_domain.strip():
        raise HTTPException(status_code=400, detail="auth_domain is required when enabled")
    if body.public_base_url and not body.public_base_url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="public_base_url must start with http:// or https://")
    if not 1 <= body.session_ttl_hours <= 168:
        raise HTTPException(status_code=400, detail="session_ttl_hours must be within 1-168")
    cfg = SsoConfig(**body.model_dump())
    request.app.state.auth_store.update_sso_config(cfg, admin.username)
    return request.app.state.auth_store.get_sso_config()


@router.post("/logout")
def logout(request: Request):
    if not verify_csrf(request.headers.get("x-csrf-token"), request.cookies.get("sn-csrf")):
        raise HTTPException(status_code=403, detail="invalid csrf token")
    cfg = request.app.state.config
    sc = _sso_rt(request)
    sid = request.cookies.get("sn-sid")
    # SSO 会话登出：响应带 OA 登出跳转 URL（前端清态后 assign；账密会话为 None 维持原行为）。
    # 顺序铁律：先 get_session 拿 auth_method 再 revoke——revoke 后 get_session 返 None。
    sso_logout_url = None
    if sc.enabled and sid:
        row = request.app.state.auth_store.get_session(sid)
        if row is not None and row.auth_method == "sso":
            sso_logout_url = sso_mod.build_passport_logout_url(
                sc.passport_base, sc.public_base_url)
    if sid:
        request.app.state.session_manager.revoke(sid)
    resp = JSONResponse({"ok": True, "sso_logout_url": sso_logout_url})
    resp.delete_cookie("sn-sid")
    resp.delete_cookie("sn-csrf")
    return resp


@router.get("/me")
def me(user: User = Depends(current_user)):
    return {"user": _user_out(user)}
