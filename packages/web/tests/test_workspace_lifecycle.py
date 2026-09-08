import pytest
from starlette.testclient import TestClient
from supernova_web.app import create_app
from supernova_web.auth.passwords import hash_password


@pytest.fixture
def _app(tmp_workspaces, monkeypatch):
    # 与 conftest.app_with_ws / test_workspace_filter._setup 同模式:
    # tmp_workspaces 设 SUPERNOVA_WORKER_ROOT=tmp_path/workspaces, 但
    # resolve_workspaces_dir() 再追加 /workspaces -> 嵌套一层且不存在, auth.db 打不开.
    # 改回 tmp_workspaces.parent 使 workspaces_dir == tmp_workspaces.
    monkeypatch.setenv("SUPERNOVA_WORKER_ROOT", str(tmp_workspaces.parent))
    monkeypatch.setenv("SUPERNOVA_WEB_COOKIE_SECURE", "0")
    app = create_app()
    st = app.state.auth_store
    st.create_user("admin", hash_password("p"), role="admin")
    st.create_user("alice", hash_password("p"))
    return app


def _login(app, username):
    c = TestClient(app)
    tok = c.get("/api/auth/csrf").json()["csrf_token"]
    c.post("/api/auth/login", json={"username": username, "password": "p"}, headers={"X-CSRF-Token": tok})
    return c


def test_admin_creates_workspace(_app):
    c = _login(_app, "admin")
    tok = c.get("/api/auth/csrf").json()["csrf_token"]
    r = c.post("/api/workspaces", json={"name": "ws1"}, headers={"X-CSRF-Token": tok})
    assert r.status_code == 201
    ws_dir = _app.state.config.workspaces_dir / "ws1"
    assert ws_dir.is_dir()
    assert (ws_dir / "config.yaml").exists()
    cfg = _app.state.ws_config_store.read("ws1").provider
    assert cfg.ai_provider == "openai_compatible"
    assert cfg.base_url == "https://llm-proxy.futuoa.com/v1"
    assert cfg.small_model == "glm-5.2-coder"
    assert cfg.medium_model == "glm-5.2-coder"
    assert cfg.large_model == "glm-5.2-coder"
    assert cfg.api_key is None
    admin = _app.state.auth_store.get_user_by_username("admin")
    assert _app.state.auth_store.get_workspace_member_role("ws1", admin.id) == "manager"


def test_non_admin_cannot_create_workspace(_app):
    c = _login(_app, "alice")
    tok = c.get("/api/auth/csrf").json()["csrf_token"]
    assert c.post("/api/workspaces", json={"name": "ws2"}, headers={"X-CSRF-Token": tok}).status_code == 403


def test_create_workspace_conflict(_app):
    c = _login(_app, "admin")
    tok = c.get("/api/auth/csrf").json()["csrf_token"]
    c.post("/api/workspaces", json={"name": "ws1"}, headers={"X-CSRF-Token": tok})
    assert c.post("/api/workspaces", json={"name": "ws1"}, headers={"X-CSRF-Token": tok}).status_code == 409


def test_scan_requires_existing_workspace(_app, monkeypatch):
    async def _fake_start(req):
        return req.workspace, "20260727-120000"  # T3: (ws, scan_id)
    _app.state.scan_manager.start = _fake_start
    c = _login(_app, "alice")
    tok = c.get("/api/auth/csrf").json()["csrf_token"]
    r = c.post("/api/scan", json={"type": "whitebox", "workspace": "nope", "url": "http://x"},
               headers={"X-CSRF-Token": tok})
    assert r.status_code == 422  # ws 不存在


def test_created_workspace_visible_in_list(_app):
    # final-review I1: POST /api/workspaces 建的 ws 必须在 GET /api/workspaces 可见。
    # create_workspace 原本只 mkdir + add_workspace_member, 未写 session.json ->
    # list_workspaces 经 SessionManager.list_workspaces 过滤 (p/session.json).exists()
    # -> 新建 ws 不可见。修复: create_workspace 写最小 session.json(status=completed)。
    c = _login(_app, "admin")
    tok = c.get("/api/auth/csrf").json()["csrf_token"]
    r = c.post("/api/workspaces", json={"name": "ws1"}, headers={"X-CSRF-Token": tok})
    assert r.status_code == 201
    names = [w["name"] for w in c.get("/api/workspaces").json()]
    assert "ws1" in names


def test_scan_requires_membership(_app, monkeypatch):
    admin_c = _login(_app, "admin")
    atok = admin_c.get("/api/auth/csrf").json()["csrf_token"]
    admin_c.post("/api/workspaces", json={"name": "ws1"}, headers={"X-CSRF-Token": atok})  # admin 建 ws1
    async def _fake_start(req):
        return req.workspace, "20260727-120000"  # T3: (ws, scan_id)
    _app.state.scan_manager.start = _fake_start
    alice_c = _login(_app, "alice")
    altok = alice_c.get("/api/auth/csrf").json()["csrf_token"]
    r = alice_c.post("/api/scan", json={"type": "whitebox", "workspace": "ws1", "url": "http://x"},
                     headers={"X-CSRF-Token": altok})
    assert r.status_code == 403  # alice 非 ws1 成员


def test_post_workspace_writes_workspace_json(_app):
    """T2: POST /api/workspaces 写 workspace.json（ws 元数据），非 ws 根 session.json。

    1 ws : N scans 后 ws 元数据与 scan 状态机解耦：ws 级 workspace.json，scan 状态机在
    scans/<scan_id>/session.json。空 ws 经 indexer 聚合 scan_count=0 可见。
    """
    import json
    c = _login(_app, "admin")
    tok = c.get("/api/auth/csrf").json()["csrf_token"]
    r = c.post("/api/workspaces", json={"name": "ws_meta"}, headers={"X-CSRF-Token": tok})
    assert r.status_code == 201
    ws_dir = _app.state.config.workspaces_dir / "ws_meta"
    assert (ws_dir / "workspace.json").exists()
    meta = json.loads((ws_dir / "workspace.json").read_text())
    assert meta["name"] == "ws_meta"
    assert meta["owner"] == "admin"
    # ws 根不再写 session.json（scan 状态机下沉到 scans/<id>/）
    assert not (ws_dir / "session.json").exists()


def test_other_admin_creates_workspace_and_all_admins_are_added(_app):
    st = _app.state.auth_store
    st.create_user("ops", hash_password("p"), role="admin")
    c = _login(_app, "ops")
    tok = c.get("/api/auth/csrf").json()["csrf_token"]

    r = c.post("/api/workspaces", json={"name": "ws-ops"}, headers={"X-CSRF-Token": tok})

    assert r.status_code == 201
    admin = st.get_user_by_username("admin")
    ops = st.get_user_by_username("ops")
    assert st.get_workspace_member_role("ws-ops", admin.id) == "manager"
    assert st.get_workspace_member_role("ws-ops", ops.id) == "manager"


def test_other_admin_lists_all_workspaces(_app):
    st = _app.state.auth_store
    st.create_user("ops", hash_password("p"), role="admin")

    admin_c = _login(_app, "admin")
    admin_tok = admin_c.get("/api/auth/csrf").json()["csrf_token"]
    assert admin_c.post("/api/workspaces", json={"name": "ws-admin"},
                        headers={"X-CSRF-Token": admin_tok}).status_code == 201

    ops_c = _login(_app, "ops")
    ops_tok = ops_c.get("/api/auth/csrf").json()["csrf_token"]
    assert ops_c.post("/api/workspaces", json={"name": "ws-ops"},
                      headers={"X-CSRF-Token": ops_tok}).status_code == 201

    names = {row["name"] for row in ops_c.get("/api/workspaces").json()}
    assert names == {"ws-admin", "ws-ops"}
