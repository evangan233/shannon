"""认证档案 CRUD API(workspace 级,脱敏读写,空串 secret = 不改)。

test/verify-status 端点在本文件追加(Task 6)。鉴权:看/用 workspace_member,改/删 workspace_manager。
范式镜像 api/ws_config.py。"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from supernova_web.auth.dependencies import workspace_member, workspace_manager
from supernova_web.components.auth_profile_store import (
    AuthProfileStore, AuthProfile, AuthProfileCredential, EmailLoginCred,
    AlreadyForked, _CRED_SECRET_FIELDS,
)

router = APIRouter(prefix="/api/workspaces", tags=["auth-profiles"])


def _store(request: Request) -> AuthProfileStore:
    return request.app.state.auth_profile_store


def _build_profile(payload: dict) -> AuthProfile:
    creds = [AuthProfileCredential(**{"id": "", **c}) for c in payload.get("credentials", [])]
    return AuthProfile(
        id=payload.get("id", ""),
        name=payload["name"],
        login_url=payload["login_url"],
        login_type=payload["login_type"],
        login_flow=payload.get("login_flow"),
        credentials=creds,
    )


@router.get("/{ws}/auth-profiles")
async def list_profiles(ws: str, request: Request, user=Depends(workspace_member)):
    return [p.model_dump(mode="json") for p in _store(request).read_masked(ws)]


@router.post("/{ws}/auth-profiles")
async def create_profile(ws: str, payload: dict, request: Request,
                         user=Depends(workspace_manager)):
    store = _store(request)
    # 唯一性:ws 内 name 唯一
    if any(p.name == payload.get("name") for p in store.read(ws)):
        raise HTTPException(422, f"档案名已存在: {payload.get('name')}")
    profile = store.upsert_profile(ws, _build_profile(payload))
    return next(m for m in store.read_masked(ws) if m.id == profile.id).model_dump(mode="json")


@router.get("/{ws}/auth-profiles/{pid}")
async def get_profile(ws: str, pid: str, request: Request, user=Depends(workspace_member)):
    # 单次脱敏读 + 按 id 匹配:防 get 与 read_masked 之间档案被删致 masked=None.model_dump() 500。
    masked = next((m for m in _store(request).read_masked(ws) if m.id == pid), None)
    if masked is None:
        raise HTTPException(404, "认证档案不存在")
    return masked.model_dump(mode="json")


@router.put("/{ws}/auth-profiles/{pid}")
async def update_profile(ws: str, pid: str, payload: dict, request: Request,
                         user=Depends(workspace_manager)):
    store = _store(request)
    existing = store.get(ws, pid)
    if existing is None:
        raise HTTPException(404, "认证档案不存在")
    if existing.scope == "system":
        raise HTTPException(403, "系统档案只读，请修改 configs 文件后重启")
    # profile 级字段覆盖
    existing.name = payload.get("name", existing.name)
    existing.login_url = payload.get("login_url", existing.login_url)
    existing.login_type = payload.get("login_type", existing.login_type)
    existing.login_flow = payload.get("login_flow", existing.login_flow)
    # credentials:逐条 upsert,空串 secret = 保留原值
    existing_by_id = {c.id: c for c in existing.credentials}
    for c_in in payload.get("credentials", []):
        cid = c_in.get("id")
        if cid and cid in existing_by_id:  # 更新现有
            c = existing_by_id[cid]
            c.role = c_in.get("role", c.role)
            c.username = c_in.get("username", c.username)
            for f in _CRED_SECRET_FIELDS:
                v = c_in.get(f, "")
                if v:
                    setattr(c, f, v)   # 非空 → 更新;空串 → 保留
            if c_in.get("email_login"):
                el = c.email_login or EmailLoginCred(address="", password=None)
                el.address = c_in["email_login"].get("address", el.address)
                for f in _CRED_SECRET_FIELDS:
                    v = c_in["email_login"].get(f, "")
                    if v:
                        setattr(el, f, v)
                c.email_login = el
        else:  # 新增 credential
            # 显式 allow-list 过滤客户端键:未知键 → pydantic ValidationError → 500(缺陷)。
            # 只接收模型已知字段,防客户端塞 __class__ 等脏键致 500/注入。
            _cred_fields = ("role", "username", "password", "totp_secret",
                            "email_login", "verify_status")
            filtered = {k: v for k, v in c_in.items() if k in _cred_fields}
            existing.credentials.append(AuthProfileCredential(id="", **filtered))
    # 全量 diff（2026-08-07 多角色编辑删角色）：payload 显式带 credentials[] 时视为完整目标列表，
    # existing 有但 payload 没有的 id → 删除；本轮新增（id 空）保留。不带 credentials 键 → 不动（兼容局部更新）。
    if "credentials" in payload:
        keep_ids = {c_in.get("id") for c_in in payload.get("credentials", []) if c_in.get("id")}
        existing.credentials = [c for c in existing.credentials if c.id in keep_ids or not c.id]
    store.upsert_profile(ws, existing)
    return {"ok": True}


@router.delete("/{ws}/auth-profiles/{pid}")
async def delete_profile(ws: str, pid: str, request: Request,
                         user=Depends(workspace_manager)):
    store = _store(request)
    existing = store.get(ws, pid)
    if existing is None:
        raise HTTPException(404, "认证档案不存在")
    if existing.scope == "system":
        raise HTTPException(403, "系统档案只读，请修改 configs 文件后重启")
    if not store.delete_profile(ws, pid):
        raise HTTPException(404, "认证档案不存在")
    return {"ok": True}


@router.post("/{ws}/auth-profiles/{pid}/fork")
async def fork_profile(ws: str, pid: str, request: Request,
                       user=Depends(workspace_manager)):
    """把系统档案 fork 成本工作区可编辑副本（保留系统 profile.id，ws-priority 覆盖）。
    ws 段已有同 id 副本 → 409；ws 档案（系统段无该 id）→ 422；不存在 → 404。

    注：fork_from_system 内部封装「ws 段已有同 id → AlreadyForked」，故放前判 409；
    None 后再用 get 区分 422（ws 档案）vs 404（不存在）—— 避免 get 的 ws-priority 在
    已 fork 时把 409 误判成 422。"""
    store = _store(request)
    try:
        forked = store.fork_from_system(ws, pid)
    except AlreadyForked:
        raise HTTPException(409, "已复制到本工作区")
    if forked is None:
        if store.get(ws, pid) is not None:
            raise HTTPException(422, "该档案已在工作区，可直接编辑")
        raise HTTPException(404, "认证档案不存在")
    return next(m for m in store.read_masked(ws) if m.id == forked.id).model_dump(mode="json")


@router.post("/{ws}/auth-profiles/{pid}/credentials/{cid}/test")
async def test_credential(ws: str, pid: str, cid: str, request: Request,
                          host_profile_id: str | None = None,
                          host_profile_ids: list[str] | None = Query(None),
                          host_url: str | None = None,
                          user=Depends(workspace_member)):
    """触发真实登录验证 → 起 AuthValidationWorkflow,返 {workflow_id, probe_dir}(前端轮询)。

    host_profile_id/host_profile_ids/host_url(query)：选中 HOST（单选=旧参数、多选=
    host_profile_ids 重复 query 参数 `?host_profile_ids=a&host_profile_ids=b`）→
    多档案合并后走代理；都不传 → 直连（复用黑盒 HOST 能力）。
    工作区模型配置缺失/错误 → 422 provider_incomplete（测试登录不降级，对齐 /api/scan 契约）。"""
    from supernova_web.components.ws_config_store import ProviderConfigIncomplete
    try:
        return await request.app.state.scan_manager.start_auth_validation(
            ws, pid, cid, host_profile_id=host_profile_id,
            host_profile_ids=host_profile_ids, host_url=host_url)
    except ProviderConfigIncomplete as e:
        raise HTTPException(422, detail={"code": "provider_incomplete", "missing": e.missing})
    except ValueError as e:
        raise HTTPException(422, str(e))


@router.post("/{ws}/auth-profiles/{pid}/test-batch")
async def test_batch(ws: str, pid: str, request: Request,
                     body: dict | None = None, user=Depends(workspace_member)):
    """档案级批量测试登录(多选角色 → 串行逐个独立验证每个角色能否登录,spec §2)。

    body {cred_ids?: string[]}:空/省略 = 全选该档案所有角色。返 {workflow_id}(batch workflow)。
    各 cred 实时过程仍走 per-cred verify-events 订阅(用 batch workflow_id + 该 cred probe_dir,
    守护已放宽接受 authval-batch-{ws}- 前缀)。cred_id 越界 / profile 不存在等 ValueError → 422。
    """
    cred_ids = (body or {}).get("cred_ids")
    host_profile_id = (body or {}).get("host_profile_id")
    host_profile_ids = (body or {}).get("host_profile_ids")
    host_url = (body or {}).get("host_url")
    from supernova_web.components.ws_config_store import ProviderConfigIncomplete
    try:
        return await request.app.state.scan_manager.start_batch_auth_validation(
            ws, pid, cred_ids, host_profile_id=host_profile_id,
            host_profile_ids=host_profile_ids, host_url=host_url)
    except ProviderConfigIncomplete as e:
        # 测试登录不降级（2026-08-17）：工作区模型配置缺失/错误 → 结构化 422，对齐 /api/scan 契约。
        raise HTTPException(422, detail={"code": "provider_incomplete", "missing": e.missing})
    except ValueError as e:
        raise HTTPException(422, str(e))


@router.post("/{ws}/auth-profiles/{pid}/cancel-test")
async def cancel_test(ws: str, pid: str, request: Request, body: dict | None = None,
                      user=Depends(workspace_member)):
    """用户停止认证测试(批量/单 cred 通用,auth-test-cancel spec §3)。

    body {workflow_id}: 批量 = test-batch 返的 batch workflow_id;单 cred = test 返的 workflow_id。
    manager 侧先回填状态(绑此 wf 且 running 的 cred → failed/cancelled + 删明文 scan-config)
    再 handle.cancel() best-effort。ValueError(越界/未绑定) → 422(对齐 test-batch 错误映射)。"""
    workflow_id = (body or {}).get("workflow_id")
    if not workflow_id:
        raise HTTPException(422, "workflow_id 必填")
    try:
        return await request.app.state.scan_manager.cancel_auth_validation(ws, pid, workflow_id)
    except ValueError as e:
        raise HTTPException(422, str(e))


@router.get("/{ws}/auth-profiles/{pid}/credentials/{cid}/verify-status")
async def verify_status(ws: str, pid: str, cid: str, workflow_id: str,
                        probe_dir: str, request: Request,
                        user=Depends(workspace_member)):
    """轮询验证结果 → 回填 verify_status → 删 probe 目录。Temporal 未就绪抛错前端提示重试。"""
    try:
        status = await request.app.state.scan_manager.get_auth_validation_result(
            ws, workflow_id, probe_dir, pid, cid)
    except Exception as e:
        raise HTTPException(503, f"验证结果暂时不可用,请重试: {e}")
    return status.model_dump(mode="json")


@router.get("/{ws}/auth-profiles/{pid}/credentials/{cid}/verify-log")
async def verify_log(ws: str, pid: str, cid: str, workflow_id: str, probe_dir: str,
                     request: Request, tail: int | None = None,
                     user=Depends(workspace_member)):
    """读验证过程 events.ndjson（块3b，过程可见）。tail=N 取末 N 条（实时观看），默认全量（回看）。
    越界守护 ValueError → 403（拒绝，非暂不可用）；其他异常 → 503。"""
    try:
        events = await request.app.state.scan_manager.get_auth_validation_log(
            ws, workflow_id, probe_dir, tail=tail)
    except ValueError as e:
        raise HTTPException(403, str(e))
    except Exception as e:
        raise HTTPException(503, f"验证日志暂时不可用: {e}")
    return {"events": events}


@router.get("/{ws}/auth-profiles/{pid}/credentials/{cid}/verify-events")
async def verify_events(ws: str, pid: str, cid: str, workflow_id: str, probe_dir: str,
                        request: Request, user=Depends(workspace_member)):
    """验证过程 SSE 实时流（块4，步骤条 + 实时日志）。tail probe_dir/events.ndjson，遇 scan_end
    关流。越界守护 ValueError → 403。Last-Event-ID 头支持断点续传。"""
    from supernova_web.api.events import build_verify_events_response

    try:
        ndjson = await request.app.state.scan_manager.auth_validation_events_path(
            ws, workflow_id, probe_dir)
    except ValueError as e:
        raise HTTPException(403, str(e))
    except Exception as e:
        raise HTTPException(503, f"验证过程流暂时不可用: {e}")
    last = request.headers.get("last-event-id")
    last_offset = int(last) if last else None
    return await build_verify_events_response(ndjson, last_event_id=last_offset)
