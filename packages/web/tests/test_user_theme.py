"""per-user 主题（2026-08-28）：PUT /api/users/me/theme + /auth/me 与 login 下发。

主题是用户偏好（跟账号走、跨设备一致、与工作区无关），存 auth.db users.theme 列。
白名单 = 前端 ThemeId 全集（theme.ts THEMES + "system"），非法值 422。
模式照抄 per-user 偏好先例（现 test_last_visited_workspace.py）。"""
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
    c = TestClient(app)
    tok = c.get("/api/auth/csrf").json()["csrf_token"]
    c.post("/api/auth/login", json={"username": "admin", "password": "admin-pw"},
           headers={"X-CSRF-Token": tok})
    return c, app


def _csrf(c):
    return c.cookies.get("sn-csrf") or c.get("/api/auth/csrf").json()["csrf_token"]


def test_set_theme_success(admin_client):
    c, _ = admin_client
    r = c.put("/api/users/me/theme", json={"theme": "graphite"},
              headers={"X-CSRF-Token": _csrf(c)})
    assert r.status_code == 200
    assert r.json()["theme"] == "graphite"
    # /auth/me 回读
    assert c.get("/api/auth/me").json()["user"]["theme"] == "graphite"


def test_me_returns_theme_default_none(admin_client):
    c, _ = admin_client
    r = c.get("/api/auth/me")
    assert r.status_code == 200
    assert r.json()["user"]["theme"] is None


def test_set_theme_invalid_422(admin_client):
    c, _ = admin_client
    r = c.put("/api/users/me/theme", json={"theme": "hot-dog-stand"},
              headers={"X-CSRF-Token": _csrf(c)})
    assert r.status_code == 422
    # 未写入
    assert c.get("/api/auth/me").json()["user"]["theme"] is None


def test_set_theme_without_csrf_rejected(admin_client):
    """缺少 CSRF header 的 PUT 必须被拒（403）。"""
    c, _ = admin_client
    r = c.put("/api/users/me/theme", json={"theme": "graphite"})
    assert r.status_code == 403


def test_set_theme_requires_login(tmp_workspaces, monkeypatch):
    """未登录 -> 401。"""
    monkeypatch.setenv("SUPERNOVA_WEB_COOKIE_SECURE", "0")
    from supernova_core.utils.paths import resolve_workspaces_dir
    monkeypatch.setenv("SUPERNOVA_WORKER_ROOT", str(tmp_workspaces.parent))
    assert resolve_workspaces_dir() == tmp_workspaces
    app = create_app()
    c = TestClient(app)
    r = c.put("/api/users/me/theme", json={"theme": "graphite"})
    assert r.status_code == 401


def test_login_response_carries_theme(admin_client):
    """login 响应 user 带主题（前端登录路径免二次请求直接校准）。"""
    c, _ = admin_client
    assert c.put("/api/users/me/theme", json={"theme": "openai"},
                 headers={"X-CSRF-Token": _csrf(c)}).status_code == 200
    # 登出再登录（login 响应即应携带）
    c.post("/api/auth/logout")
    tok = c.get("/api/auth/csrf").json()["csrf_token"]
    r = c.post("/api/auth/login", json={"username": "admin", "password": "admin-pw"},
               headers={"X-CSRF-Token": tok})
    assert r.status_code == 200
    assert r.json()["user"]["theme"] == "openai"


def test_pre_theme_db_migrates_on_init(tmp_path):
    """pre-theme 老库（users 无 theme 列）init_schema 后补列，读写不崩。"""
    import sqlite3
    from supernova_web.auth.store import AuthStore
    db = str(tmp_path / "auth.db")
    # 手工建 pre-theme 库：不含 theme 列的最小 users 表 + 一个用户
    with sqlite3.connect(db) as c:
        c.execute(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, "
            "password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', "
            "created_at TEXT NOT NULL, must_change_password INTEGER NOT NULL DEFAULT 0, "
            "pinned_workspace TEXT, avatar_url TEXT, auth_provider TEXT DEFAULT 'password')"
        )
        c.execute(
            "INSERT INTO users(username, password_hash, role, created_at) "
            "VALUES('old', 'h', 'user', '2026-01-01')"
        )
    s = AuthStore(db)
    s.init_schema()  # ALTER 补 theme 列（已存 -> 吞）
    s.init_schema()  # 二次 init 幂等
    got = s.get_user_by_username("old")
    assert got is not None and got.theme is None  # 老用户默认未自配
    s.update_theme(got.id, "graphite")
    assert s.get_user(got.id).theme == "graphite"
