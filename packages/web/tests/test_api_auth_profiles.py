"""auth_profiles CRUD API + 权限(workspace_member 看 / workspace_manager 改删)。"""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, MagicMock

from supernova_web.api import auth_profiles
from supernova_web.auth.dependencies import current_user, workspace_member, workspace_manager
from supernova_web.components.auth_profile_store import (
    AuthProfileStore, AuthProfile, AuthProfileCredential,
)
from supernova_web.components.credential_vault import CredentialVault


class _U:
    role = "admin"
    id = 1


def _client(tmp_path):
    store = AuthProfileStore(tmp_path, CredentialVault(tmp_path / ".mk"))
    app = FastAPI()
    app.state.auth_profile_store = store
    app.state.scan_manager = MagicMock()
    app.include_router(auth_profiles.router)
    # 测试绕过鉴权(admin 短路,但 dependency_overrides 更稳)
    app.dependency_overrides[current_user] = lambda: _U()
    app.dependency_overrides[workspace_member] = lambda: _U()
    app.dependency_overrides[workspace_manager] = lambda: _U()
    return TestClient(app), store


def test_create_list_get_delete(tmp_path):
    c, _store = _client(tmp_path)
    body = {"name": "NG", "login_url": "http://t/", "login_type": "form",
            "credentials": [{"role": "admin", "username": "admin", "password": "pw"}]}
    r = c.post("/api/workspaces/ws1/auth-profiles", json=body)
    assert r.status_code == 200, r.text
    pid = r.json()["id"]
    # list 脱敏
    lst = c.get("/api/workspaces/ws1/auth-profiles").json()
    assert lst[0]["name"] == "NG"
    assert lst[0]["credentials"][0]["password"] == "••••"
    # get 脱敏
    assert c.get(f"/api/workspaces/ws1/auth-profiles/{pid}").status_code == 200
    # delete
    assert c.delete(f"/api/workspaces/ws1/auth-profiles/{pid}").status_code == 200
    assert c.get("/api/workspaces/ws1/auth-profiles").json() == []


def test_put_empty_secret_keeps_existing(tmp_path):
    c, store = _client(tmp_path)
    pid = c.post("/api/workspaces/ws1/auth-profiles", json={
        "name": "NG", "login_url": "http://t/", "login_type": "form",
        "credentials": [{"role": "admin", "username": "admin", "password": "pw"}]}).json()["id"]
    cred_id = c.get(f"/api/workspaces/ws1/auth-profiles/{pid}").json()["credentials"][0]["id"]
    # PUT 空串 password = 不改
    c.put(f"/api/workspaces/ws1/auth-profiles/{pid}", json={
        "name": "NG2", "login_url": "http://t/", "login_type": "form",
        "credentials": [{"id": cred_id, "role": "admin", "username": "admin", "password": ""}]})
    cred = store.read("ws1")[0].credentials[0]
    assert cred.password == "pw"  # 保留


def test_put_omitted_credential_is_deleted(tmp_path):
    """PUT 全量 diff：payload 不含的已有 credential id 被删（编辑态删角色）。"""
    c, store = _client(tmp_path)
    pid = c.post("/api/workspaces/ws1/auth-profiles", json={
        "name": "NG", "login_url": "http://t/", "login_type": "form",
        "credentials": [
            {"role": "admin", "username": "admin", "password": "pw"},
            {"role": "user", "username": "user1", "password": "pw2"},
        ]}).json()["id"]
    creds = c.get(f"/api/workspaces/ws1/auth-profiles/{pid}").json()["credentials"]
    admin_id = next(cr["id"] for cr in creds if cr["role"] == "admin")
    # PUT 只保留 admin（omit user）→ user 应被删
    c.put(f"/api/workspaces/ws1/auth-profiles/{pid}", json={
        "name": "NG", "login_url": "http://t/", "login_type": "form",
        "credentials": [{"id": admin_id, "role": "admin", "username": "admin", "password": ""}]})
    stored = store.read("ws1")[0].credentials
    assert {cr.role for cr in stored} == {"admin"}  # user 被删


@pytest.mark.asyncio
async def test_test_endpoint_starts_workflow(tmp_path, monkeypatch):
    c, store = _client(tmp_path)
    # 预置档案
    pid = c.post("/api/workspaces/ws1/auth-profiles", json={
        "name": "NG", "login_url": "http://t/", "login_type": "form",
        "credentials": [{"role": "admin", "username": "admin", "password": "pw"}]}).json()["id"]
    cred_id = store.read("ws1")[0].credentials[0].id
    sm = c.app.state.scan_manager
    # Task 6 reconciliation: start_auth_validation 返 dict {workflow_id, probe_dir}
    sm.start_auth_validation = AsyncMock(
        return_value={"workflow_id": "wf-xyz", "probe_dir": "/p/probe"})
    r = c.post(f"/api/workspaces/ws1/auth-profiles/{pid}/credentials/{cred_id}/test")
    assert r.status_code == 200, r.text
    assert r.json()["workflow_id"] == "wf-xyz"
    sm.start_auth_validation.assert_awaited_once_with(
        "ws1", pid, cred_id, host_profile_id=None, host_profile_ids=None, host_url=None)


@pytest.mark.asyncio
async def test_test_batch_endpoint_starts_workflow(tmp_path):
    """POST test-batch:多选角色 → start_batch_auth_validation → 返 {workflow_id}(batch)。"""
    c, store = _client(tmp_path)
    pid = c.post("/api/workspaces/ws1/auth-profiles", json={
        "name": "NG", "login_url": "http://t/", "login_type": "form",
        "credentials": [{"role": "admin", "username": "admin", "password": "pw"},
                        {"role": "user", "username": "u1", "password": "pw"}]}).json()["id"]
    sm = c.app.state.scan_manager
    sm.start_batch_auth_validation = AsyncMock(
        return_value={"workflow_id": "authval-batch-ws1-x"})
    r = c.post(f"/api/workspaces/ws1/auth-profiles/{pid}/test-batch",
               json={"cred_ids": ["c1", "c2"]})
    assert r.status_code == 200, r.text
    assert r.json()["workflow_id"] == "authval-batch-ws1-x"
    sm.start_batch_auth_validation.assert_awaited_once_with(
        "ws1", pid, ["c1", "c2"], host_profile_id=None, host_profile_ids=None, host_url=None)


@pytest.mark.asyncio
async def test_test_batch_endpoint_full_selection_no_body(tmp_path):
    """POST test-batch 无 body / 空 cred_ids = 全选(start_batch 收到 None/[])。"""
    c, _store = _client(tmp_path)
    pid = c.post("/api/workspaces/ws1/auth-profiles", json={
        "name": "NG", "login_url": "http://t/", "login_type": "form",
        "credentials": [{"role": "admin", "username": "admin", "password": "pw"}]}).json()["id"]
    sm = c.app.state.scan_manager
    sm.start_batch_auth_validation = AsyncMock(return_value={"workflow_id": "wf-batch"})
    r = c.post(f"/api/workspaces/ws1/auth-profiles/{pid}/test-batch")
    assert r.status_code == 200, r.text
    # 无 body → cred_ids 透传为 None(全选)
    sm.start_batch_auth_validation.assert_awaited_once_with(
        "ws1", pid, None, host_profile_id=None, host_profile_ids=None, host_url=None)


@pytest.mark.asyncio
async def test_test_batch_endpoint_value_error_is_422(tmp_path):
    """cred_id 越界 / profile 不存在等 ValueError → 422(客户端错误,非 500)。"""
    c, _store = _client(tmp_path)
    sm = c.app.state.scan_manager
    sm.start_batch_auth_validation = AsyncMock(side_effect=ValueError("角色凭据不属于该档案: ['cred_evil']"))
    r = c.post("/api/workspaces/ws1/auth-profiles/prof_1/test-batch",
               json={"cred_ids": ["cred_evil"]})
    assert r.status_code == 422
    assert "不属于" in r.json()["detail"]


@pytest.mark.asyncio
async def test_test_endpoint_provider_incomplete_is_structured_422(tmp_path):
    """测试登录不降级(2026-08-17)：工作区模型配置缺失 → 422 code=provider_incomplete
    (对齐 /api/scan 契约,前端显示「前往工作区设置补全 LLM 凭据」)。"""
    from supernova_web.components.ws_config_store import ProviderConfigIncomplete

    c, _store = _client(tmp_path)
    sm = c.app.state.scan_manager
    sm.start_auth_validation = AsyncMock(
        side_effect=ProviderConfigIncomplete(["SUPERNOVA_OPENAI_API_KEY"]))
    r = c.post("/api/workspaces/ws1/auth-profiles/prof_1/credentials/cred_1/test")
    assert r.status_code == 422
    assert r.json()["detail"] == {
        "code": "provider_incomplete", "missing": ["SUPERNOVA_OPENAI_API_KEY"]}


@pytest.mark.asyncio
async def test_test_batch_endpoint_provider_incomplete_is_structured_422(tmp_path):
    """批量测试登录同样不降级：工作区模型配置缺失 → 422 code=provider_incomplete。"""
    from supernova_web.components.ws_config_store import ProviderConfigIncomplete

    c, _store = _client(tmp_path)
    sm = c.app.state.scan_manager
    sm.start_batch_auth_validation = AsyncMock(
        side_effect=ProviderConfigIncomplete(["SUPERNOVA_OPENAI_API_KEY"]))
    r = c.post("/api/workspaces/ws1/auth-profiles/prof_1/test-batch", json={})
    assert r.status_code == 422
    assert r.json()["detail"]["code"] == "provider_incomplete"
    assert r.json()["detail"]["missing"] == ["SUPERNOVA_OPENAI_API_KEY"]


@pytest.mark.asyncio
async def test_test_endpoint_threads_host_profile_id(tmp_path):
    """POST test?host_profile_id=... → start_auth_validation 透传 host_profile_id（query 参数）。"""
    c, store = _client(tmp_path)
    pid = c.post("/api/workspaces/ws1/auth-profiles", json={
        "name": "NG", "login_url": "http://t/", "login_type": "form",
        "credentials": [{"role": "admin", "username": "admin", "password": "pw"}]}).json()["id"]
    cred_id = store.read("ws1")[0].credentials[0].id
    sm = c.app.state.scan_manager
    sm.start_auth_validation = AsyncMock(
        return_value={"workflow_id": "wf-h", "probe_dir": "/p"})
    r = c.post(f"/api/workspaces/ws1/auth-profiles/{pid}/credentials/{cred_id}/test",
               params={"host_profile_id": "host_p1"})
    assert r.status_code == 200, r.text
    sm.start_auth_validation.assert_awaited_once_with(
        "ws1", pid, cred_id, host_profile_id="host_p1", host_profile_ids=None, host_url=None)


@pytest.mark.asyncio
async def test_test_batch_threads_host_fields(tmp_path):
    """POST test-batch body 带 host_profile_id/host_url → start_batch 透传。"""
    c, _store = _client(tmp_path)
    sm = c.app.state.scan_manager
    sm.start_batch_auth_validation = AsyncMock(return_value={"workflow_id": "wf-bh"})
    r = c.post("/api/workspaces/ws1/auth-profiles/prof_1/test-batch",
               json={"cred_ids": ["c1"], "host_profile_id": "host_p1",
                     "host_url": "https://h.test/get?id=1"})
    assert r.status_code == 200, r.text
    sm.start_batch_auth_validation.assert_awaited_once_with(
        "ws1", "prof_1", ["c1"], host_profile_id="host_p1",
        host_profile_ids=None, host_url="https://h.test/get?id=1")


@pytest.mark.asyncio
async def test_verify_log_endpoint_returns_events(tmp_path):
    """块3b: GET verify-log 读 events.ndjson → {events: [...]}。tail 透传到 scan_manager。"""
    c, store = _client(tmp_path)
    pid = c.post("/api/workspaces/ws1/auth-profiles", json={
        "name": "NG", "login_url": "http://t/", "login_type": "form",
        "credentials": [{"role": "admin", "username": "admin", "password": "pw"}]}).json()["id"]
    cred_id = store.read("ws1")[0].credentials[0].id
    sm = c.app.state.scan_manager
    sm.get_auth_validation_log = AsyncMock(return_value=[{"i": 1, "msg": "navigate"}])
    r = c.get(
        f"/api/workspaces/ws1/auth-profiles/{pid}/credentials/{cred_id}/verify-log",
        params={"workflow_id": "authval-ws1-probe-1", "probe_dir": "/p/probe", "tail": 5})
    assert r.status_code == 200, r.text
    assert r.json() == {"events": [{"i": 1, "msg": "navigate"}]}
    sm.get_auth_validation_log.assert_awaited_once_with(
        "ws1", "authval-ws1-probe-1", "/p/probe", tail=5)


@pytest.mark.asyncio
async def test_verify_log_endpoint_out_of_containment_is_403(tmp_path):
    """块3b: 越界守护 ValueError → 403（拒绝），非 503（暂不可用语义）。"""
    c, _store = _client(tmp_path)
    sm = c.app.state.scan_manager
    sm.get_auth_validation_log = AsyncMock(side_effect=ValueError("probe_dir 越界"))
    r = c.get(
        "/api/workspaces/ws1/auth-profiles/prof_x/credentials/cred_y/verify-log",
        params={"workflow_id": "authval-ws1-probe-1", "probe_dir": "/evil"})
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_verify_events_endpoint_out_of_containment_is_403(tmp_path):
    """块4: verify-events SSE 越界守护 ValueError → 403（与 verify-log 同语义）。"""
    c, _store = _client(tmp_path)
    sm = c.app.state.scan_manager
    sm.auth_validation_events_path = AsyncMock(side_effect=ValueError("probe_dir 越界"))
    r = c.get(
        "/api/workspaces/ws1/auth-profiles/prof_x/credentials/cred_y/verify-events",
        params={"workflow_id": "authval-ws1-probe-1", "probe_dir": "/evil"})
    assert r.status_code == 403


def test_get_profile_does_single_masked_read(tmp_path, monkeypatch):
    """IMPORTANT 1 回归:get_profile 合并成单次 read_masked 查找,防两次读之间档案被删
    致 masked=None.model_dump() → 500(get 与 read_masked 之间的 TOCTOU race)。
    """
    c, store = _client(tmp_path)
    pid = c.post("/api/workspaces/ws1/auth-profiles", json={
        "name": "NG", "login_url": "http://t/", "login_type": "form",
        "credentials": [{"role": "admin", "username": "admin", "password": "pw"}]}).json()["id"]
    # spy read_masked:确认 get 路径只调一次(合并后),且不调 get()
    call_count = {"read_masked": 0, "get": 0}
    orig_read_masked = store.read_masked
    orig_get = store.get

    def counting_read_masked(ws):
        call_count["read_masked"] += 1
        return orig_read_masked(ws)

    def counting_get(ws, pid):
        call_count["get"] += 1
        return orig_get(ws, pid)

    monkeypatch.setattr(store, "read_masked", counting_read_masked)
    monkeypatch.setattr(store, "get", counting_get)
    r = c.get(f"/api/workspaces/ws1/auth-profiles/{pid}")
    assert r.status_code == 200, r.text
    assert call_count["read_masked"] == 1  # 单次合并读
    assert call_count["get"] == 0  # 不再走分离的 get()
    # 不存在的 pid → 404(不 500)
    assert c.get("/api/workspaces/ws1/auth-profiles/nope").status_code == 404


def test_update_profile_new_credential_with_unknown_key_does_not_500(tmp_path):
    """IMPORTANT 2 回归:update_profile 新增 credential 时未知客户端键不再致
    pydantic ValidationError → 500(allow-list 过滤后忽略未知键,凭据正常建)。
    """
    c, store = _client(tmp_path)
    pid = c.post("/api/workspaces/ws1/auth-profiles", json={
        "name": "NG", "login_url": "http://t/", "login_type": "form",
        "credentials": [{"role": "admin", "username": "admin", "password": "pw"}]}).json()["id"]
    # 带 __class__ / 任意未知键的新 credential:不再 500
    r = c.put(f"/api/workspaces/ws1/auth-profiles/{pid}", json={
        "name": "NG", "login_url": "http://t/", "login_type": "form",
        "credentials": [{"role": "user", "username": "u2", "password": "pw2",
                         "__class__": "malicious", "unknown_key": "drop-me"}]})
    assert r.status_code == 200, r.text
    # 新 credential 被建(未知键被 allow-list 过滤)
    prof = store.read("ws1")[0]
    roles = {c.role for c in prof.credentials}
    assert "user" in roles


# ---------------------------------------------------------------------------
# 系统档案只读守卫：PUT/DELETE scope=system 档案 → 403
# ---------------------------------------------------------------------------

def _seed_system_profile(store):
    store.write(".system", [AuthProfile(
        id="prof_sys", name="futunn", login_url="http://s/", login_type="form",
        scope="system",
        credentials=[AuthProfileCredential(id="cred_s", role="primary",
                                           username="u", password="p")])])


def test_update_system_profile_forbidden(tmp_path):
    c, store = _client(tmp_path)
    _seed_system_profile(store)
    r = c.put("/api/workspaces/ws1/auth-profiles/prof_sys", json={
        "name": "futunn2", "login_url": "http://s/", "login_type": "form",
        "credentials": [{"role": "primary", "username": "u"}]})
    assert r.status_code == 403
    # 未污染 ws1（系统档案不该被复制进 ws 段）
    assert store._read_segment("ws1") == []


def test_delete_system_profile_forbidden(tmp_path):
    c, store = _client(tmp_path)
    _seed_system_profile(store)
    r = c.delete("/api/workspaces/ws1/auth-profiles/prof_sys")
    assert r.status_code == 403
    # 系统档案仍在
    assert any(p.id == "prof_sys" for p in store.read(".system"))


# ---------------------------------------------------------------------------
# fork 端点：POST /{ws}/auth-profiles/{pid}/fork —— 系统档案 → ws 可编辑副本
# ---------------------------------------------------------------------------

def test_fork_endpoint_creates_ws_copy(tmp_path):
    c, store = _client(tmp_path)
    _seed_system_profile(store)   # .system 有 prof_sys
    r = c.post("/api/workspaces/ws1/auth-profiles/prof_sys/fork")
    assert r.status_code == 200, r.text
    forked = r.json()
    assert forked["id"] == "prof_sys"
    assert forked["scope"] == "workspace"
    assert forked["credentials"][0]["password"] == "••••"   # masked 返回
    # ws 段已持久化副本
    assert any(p.id == "prof_sys" for p in store._read_segment("ws1"))


def test_fork_endpoint_ws_profile_is_422(tmp_path):
    # ws 档案（非系统）fork → 422（已在工作区，可直接编辑）
    c, store = _client(tmp_path)
    pid = c.post("/api/workspaces/ws1/auth-profiles", json={
        "name": "NG", "login_url": "http://t/", "login_type": "form",
        "credentials": [{"role": "admin", "username": "admin", "password": "pw"}]}).json()["id"]
    r = c.post(f"/api/workspaces/ws1/auth-profiles/{pid}/fork")
    assert r.status_code == 422


def test_fork_endpoint_duplicate_is_409(tmp_path):
    # 重复 fork → 409（已复制到本工作区）
    c, store = _client(tmp_path)
    _seed_system_profile(store)
    assert c.post("/api/workspaces/ws1/auth-profiles/prof_sys/fork").status_code == 200
    r = c.post("/api/workspaces/ws1/auth-profiles/prof_sys/fork")
    assert r.status_code == 409


def test_fork_endpoint_unknown_profile_is_404(tmp_path):
    c, store = _client(tmp_path)
    _seed_system_profile(store)
    r = c.post("/api/workspaces/ws1/auth-profiles/nope/fork")
    assert r.status_code == 404


def test_fork_endpoint_requires_workspace_manager(tmp_path):
    # fork 是改操作 → workspace_manager 拒 → 403
    c, store = _client(tmp_path)
    _seed_system_profile(store)

    def deny():
        from fastapi import HTTPException
        raise HTTPException(403, "forbidden")

    c.app.dependency_overrides[workspace_manager] = deny
    r = c.post("/api/workspaces/ws1/auth-profiles/prof_sys/fork")
    assert r.status_code == 403


# ---- POST cancel-test（2026-08-17 auth-test-cancel spec §3.1）----


@pytest.mark.asyncio
async def test_cancel_test_endpoint_calls_manager(tmp_path):
    """POST cancel-test body {workflow_id} → cancel_auth_validation → 透传结果。"""
    c, _store = _client(tmp_path)
    sm = c.app.state.scan_manager
    sm.cancel_auth_validation = AsyncMock(
        return_value={"cancelled": "authval-batch-ws1-x"})
    r = c.post("/api/workspaces/ws1/auth-profiles/prof_1/cancel-test",
               json={"workflow_id": "authval-batch-ws1-x"})
    assert r.status_code == 200, r.text
    assert r.json() == {"cancelled": "authval-batch-ws1-x"}
    sm.cancel_auth_validation.assert_awaited_once_with(
        "ws1", "prof_1", "authval-batch-ws1-x")


@pytest.mark.asyncio
async def test_cancel_test_endpoint_missing_workflow_id_is_422(tmp_path):
    """缺 workflow_id → 422（不进 manager）。"""
    c, _store = _client(tmp_path)
    sm = c.app.state.scan_manager
    sm.cancel_auth_validation = AsyncMock()
    r = c.post("/api/workspaces/ws1/auth-profiles/prof_1/cancel-test", json={})
    assert r.status_code == 422
    sm.cancel_auth_validation.assert_not_awaited()


@pytest.mark.asyncio
async def test_cancel_test_endpoint_value_error_is_422(tmp_path):
    """越界 workflow_id / 未绑定档案等 ValueError → 422（对齐 test-batch 错误映射）。"""
    c, _store = _client(tmp_path)
    sm = c.app.state.scan_manager
    sm.cancel_auth_validation = AsyncMock(
        side_effect=ValueError("workflow_id 越界(必须以 authval-ws1- 或 authval-batch-ws1- 开头): evil"))
    r = c.post("/api/workspaces/ws1/auth-profiles/prof_1/cancel-test",
               json={"workflow_id": "evil"})
    assert r.status_code == 422
    assert "越界" in r.json()["detail"]
