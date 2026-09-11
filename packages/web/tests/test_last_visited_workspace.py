import pytest
from starlette.testclient import TestClient

from supernova_web.app import create_app
from supernova_web.auth.passwords import hash_password


@pytest.fixture
def admin_client(tmp_workspaces, monkeypatch):
    monkeypatch.setenv("SUPERNOVA_WEB_COOKIE_SECURE", "0")
    from supernova_core.utils.paths import resolve_workspaces_dir
    monkeypatch.setenv("SUPERNOVA_WORKER_ROOT", str(tmp_workspaces.parent))
    assert resolve_workspaces_dir() == tmp_workspaces
    app = create_app()
    app.state.auth_store.create_user("admin", hash_password("admin-pw"), role="admin")
    # 建一个真实 ws 目录 + workspace.json，使 workspace_member 依赖项能命中
    from supernova_web.components.scan_store import write_workspace_meta
    (tmp_workspaces / "ws-a").mkdir()
    write_workspace_meta(tmp_workspaces / "ws-a", name="ws-a", owner="admin")
    c = TestClient(app)
    tok = c.get("/api/auth/csrf").json()["csrf_token"]
    c.post("/api/auth/login", json={"username": "admin", "password": "admin-pw"},
           headers={"X-CSRF-Token": tok})
    return c, app


def _csrf(c):
    return c.cookies.get("sn-csrf") or c.get("/api/auth/csrf").json()["csrf_token"]


def test_me_returns_last_visited_field_default_none(admin_client):
    c, _ = admin_client
    r = c.get("/api/auth/me")
    assert r.status_code == 200
    assert r.json()["user"]["last_visited_workspace"] is None


def test_record_last_visited_success(admin_client):
    c, app = admin_client
    r = c.put("/api/users/me/last-visited-workspace", json={"workspace": "ws-a"},
              headers={"X-CSRF-Token": _csrf(c)})
    assert r.status_code == 200
    assert r.json()["last_visited"] == "ws-a"
    # /auth/me 现在返 last_visited
    assert c.get("/api/auth/me").json()["user"]["last_visited_workspace"] == "ws-a"


def test_record_nonexistent_workspace_404(admin_client):
    c, _ = admin_client
    r = c.put("/api/users/me/last-visited-workspace", json={"workspace": "no-such-ws"},
              headers={"X-CSRF-Token": _csrf(c)})
    assert r.status_code == 404


def test_record_non_member_forbidden(tmp_workspaces, monkeypatch):
    """普通用户记录非归属 ws -> 403。"""
    monkeypatch.setenv("SUPERNOVA_WEB_COOKIE_SECURE", "0")
    from supernova_core.utils.paths import resolve_workspaces_dir
    monkeypatch.setenv("SUPERNOVA_WORKER_ROOT", str(tmp_workspaces.parent))
    assert resolve_workspaces_dir() == tmp_workspaces
    app = create_app()
    st = app.state.auth_store
    st.create_user("alice", hash_password("alice-pw"), role="user")
    from supernova_web.components.scan_store import write_workspace_meta
    (tmp_workspaces / "ws-a").mkdir()
    write_workspace_meta(tmp_workspaces / "ws-a", name="ws-a", owner="admin")
    c = TestClient(app)
    tok = c.get("/api/auth/csrf").json()["csrf_token"]
    c.post("/api/auth/login", json={"username": "alice", "password": "alice-pw"},
           headers={"X-CSRF-Token": tok})
    # alice 非 ws-a 成员 -> 403
    r = c.put("/api/users/me/last-visited-workspace", json={"workspace": "ws-a"},
              headers={"X-CSRF-Token": _csrf(c)})
    assert r.status_code == 403


def test_record_without_csrf_rejected(admin_client):
    """缺少 CSRF token 的 PUT 必须被拒（403），防止 route 漏检 CSRF 回归。"""
    c, _ = admin_client
    # 故意不带 X-CSRF-Token header（cookie 仍在，但 header 缺失 -> verify_csrf 返 False）
    r = c.put("/api/users/me/last-visited-workspace", json={"workspace": "ws-a"})
    assert r.status_code == 403


def test_admin_can_record_nonmember_workspace(tmp_workspaces, monkeypatch):
    monkeypatch.setenv("SUPERNOVA_WEB_COOKIE_SECURE", "0")
    from supernova_core.utils.paths import resolve_workspaces_dir
    monkeypatch.setenv("SUPERNOVA_WORKER_ROOT", str(tmp_workspaces.parent))
    assert resolve_workspaces_dir() == tmp_workspaces
    app = create_app()
    st = app.state.auth_store
    st.create_user("admin", hash_password("admin-pw"), role="admin")
    st.create_user("ops", hash_password("ops-pw"), role="admin")
    from supernova_web.components.scan_store import write_workspace_meta
    (tmp_workspaces / "ws-a").mkdir()
    write_workspace_meta(tmp_workspaces / "ws-a", name="ws-a", owner="admin")
    c = TestClient(app)
    tok = c.get("/api/auth/csrf").json()["csrf_token"]
    c.post("/api/auth/login", json={"username": "ops", "password": "ops-pw"},
           headers={"X-CSRF-Token": tok})

    r = c.put("/api/users/me/last-visited-workspace", json={"workspace": "ws-a"},
              headers={"X-CSRF-Token": _csrf(c)})
    assert r.status_code == 200
    assert app.state.auth_store.get_user_by_username("ops").last_visited_workspace == "ws-a"
