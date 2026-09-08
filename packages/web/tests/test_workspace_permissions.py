import json

import pytest
from fastapi import HTTPException, Request
from starlette.testclient import TestClient

from supernova_web.app import create_app
from supernova_web.auth.dependencies import workspace_member, workspace_manager
from supernova_web.auth.models import User
from supernova_web.auth.passwords import hash_password


class _FakeStore:
    def __init__(self, role_map): self._m = role_map  # {(ws,uid): role}
    def get_workspace_member_role(self, ws, uid): return self._m.get((ws, uid))


def _req(user, store):
    class _App: pass
    app = _App()
    app.state = type("S", (), {"auth_store": store})()
    r = Request({"type": "http", "app": app})
    r.state.user = user
    return r


def test_admin_passes_workspace_member():
    admin = User(id=1, username="admin", role="admin")
    assert workspace_member(_req(admin, _FakeStore({})), "ws1", admin).role == "admin"


def test_member_passes():
    alice = User(id=2, username="alice", role="user")
    store = _FakeStore({("ws1", 2): "member"})
    assert workspace_member(_req(alice, store), "ws1", alice).id == 2


def test_non_member_forbidden():
    alice = User(id=2, username="alice", role="user")
    with pytest.raises(HTTPException) as e:
        workspace_member(_req(alice, _FakeStore({})), "ws1", alice)
    assert e.value.status_code == 403


def test_member_not_manager():
    alice = User(id=2, username="alice", role="user")
    store = _FakeStore({("ws1", 2): "member"})
    with pytest.raises(HTTPException) as e:
        workspace_manager(_req(alice, store), "ws1", alice)
    assert e.value.status_code == 403


def test_manager_passes_workspace_manager():
    alice = User(id=2, username="alice", role="user")
    store = _FakeStore({("ws1", 2): "manager"})
    assert workspace_manager(_req(alice, store), "ws1", alice).id == 2


# --- P1 Task 5: 端到端 (经 TestClient) 验证非成员 403、成员可读 ---


@pytest.fixture
def _prod_app(tmp_workspaces, monkeypatch):
    monkeypatch.setenv("SUPERNOVA_WEB_COOKIE_SECURE", "0")
    # tmp_workspaces 把 SUPERNOVA_WORKER_ROOT 设成 tmp_path/"workspaces", 而
    # resolve_workspaces_dir() 会再追加 /"workspaces" -> 嵌套一层不存在目录,
    # 致 AuthStore.init_schema() 建不了 auth.db。rebase 到父目录使解析结果
    # 恰好等于 tmp_workspaces (同 conftest.app_with_ws 模式)。
    monkeypatch.setenv("SUPERNOVA_WORKER_ROOT", str(tmp_workspaces.parent))
    app = create_app()
    st = app.state.auth_store
    st.create_user("alice", hash_password("p"))
    st.create_user("bob", hash_password("p"))
    # 写 minimal session.json: get_session_data 在缺文件时返 {} (不 500), 但为让
    # test_member_can_read 拿到有意义 200 (非赖边缘行为), 写一份最小合法 session。
    ws_alice = app.state.config.workspaces_dir / "ws_alice"
    ws_alice.mkdir()
    (ws_alice / "session.json").write_text(json.dumps({
        "status": "completed", "scan_type": "whitebox",
        "created_at": "2026-07-02T10:00:00Z", "completed_at": "2026-07-02T10:05:00Z",
    }))
    st.add_workspace_member("ws_alice", st.get_user_by_username("alice").id, "manager")
    return app


def _login(app, username):
    c = TestClient(app)
    tok = c.get("/api/auth/csrf").json()["csrf_token"]
    c.post("/api/auth/login", json={"username": username, "password": "p"}, headers={"X-CSRF-Token": tok})
    return c


def test_non_member_cannot_read_workspace(_prod_app):
    bob = _login(_prod_app, "bob")     # bob 非 ws_alice 成员
    # scan-scoped 端点 enforce workspace_member（旧 ws-scoped GET shim 已移除）
    assert bob.get("/api/workspaces/ws_alice/scans").status_code == 403
    assert bob.get("/api/workspaces/ws_alice/scans/any/report").status_code == 403
    assert bob.get("/api/workspaces/ws_alice/scans/any/logs").status_code == 403
    assert bob.get("/api/workspaces/ws_alice/scans/any/events").status_code == 403


def test_member_can_read(_prod_app):
    alice = _login(_prod_app, "alice")
    assert alice.get("/api/workspaces/ws_alice/scans").status_code == 200  # 成员可读 scan 列表


# --- P1 Task 6: DELETE workspace 需 manager 权限 + 清成员 ---


def test_member_cannot_delete_workspace(_prod_app):
    # 让 bob 也成为 ws_alice 的 member（非 manager）
    st = _prod_app.state.auth_store
    st.add_workspace_member("ws_alice", st.get_user_by_username("bob").id, "member")
    bob = _login(_prod_app, "bob")
    tok = bob.get("/api/auth/csrf").json()["csrf_token"]
    r = bob.delete("/api/workspaces/ws_alice", headers={"X-CSRF-Token": tok})
    assert r.status_code == 403


def test_manager_delete_clears_members(_prod_app):
    st = _prod_app.state.auth_store
    alice = _login(_prod_app, "alice")
    tok = alice.get("/api/auth/csrf").json()["csrf_token"]
    r = alice.delete("/api/workspaces/ws_alice", headers={"X-CSRF-Token": tok})
    assert r.status_code == 200
    assert st.list_workspace_members("ws_alice") == []  # 成员关系已清


def test_admin_bypasses_workspace_membership():
    ops = User(id=2, username="ops", role="admin")
    assert workspace_member(_req(ops, _FakeStore({})), "ws1", ops).id == 2
    assert workspace_manager(_req(ops, _FakeStore({})), "ws1", ops).id == 2
