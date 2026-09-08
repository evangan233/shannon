import pytest
from starlette.testclient import TestClient

from supernova_web.app import create_app
from supernova_web.auth.passwords import hash_password


@pytest.fixture
def admin_client(tmp_workspaces, monkeypatch):
    """建 admin + 普通 user 两个账号，以 admin 身份登录返回 client。"""
    monkeypatch.setenv("SUPERNOVA_WEB_COOKIE_SECURE", "0")
    from supernova_core.utils.paths import resolve_workspaces_dir
    monkeypatch.setenv("SUPERNOVA_WORKER_ROOT", str(tmp_workspaces.parent))
    assert resolve_workspaces_dir() == tmp_workspaces
    app = create_app()
    st = app.state.auth_store
    st.create_user("admin", hash_password("admin-pw"), role="admin")
    st.create_user("alice", hash_password("alice-pw"), role="user")
    c = TestClient(app)
    tok = c.get("/api/auth/csrf").json()["csrf_token"]
    c.post("/api/auth/login", json={"username": "admin", "password": "admin-pw"},
           headers={"X-CSRF-Token": tok})
    return c, app


@pytest.fixture
def user_client(admin_client):
    """以普通 user 身份登录（测 403 收紧）。"""
    c, app = admin_client
    c2 = TestClient(app)
    tok = c2.get("/api/auth/csrf").json()["csrf_token"]
    c2.post("/api/auth/login", json={"username": "alice", "password": "alice-pw"},
            headers={"X-CSRF-Token": tok})
    return c2


def _csrf(c):
    return c.cookies.get("sn-csrf") or c.get("/api/auth/csrf").json()["csrf_token"]


def _alice_id(app):
    return app.state.auth_store.get_user_by_username("alice").id


# --- GET 收紧 ---

def test_list_users_requires_admin(user_client):
    """非 admin 访问 GET /api/users -> 403（收紧）。"""
    assert user_client.get("/api/users").status_code == 403


def test_list_users_admin_ok(admin_client):
    c, app = admin_client
    r = c.get("/api/users")
    assert r.status_code == 200
    names = [u["username"] for u in r.json()["users"]]
    assert set(names) == {"admin", "alice"}
    # 带新字段
    alice = next(u for u in r.json()["users"] if u["username"] == "alice")
    assert "must_change_password" in alice and "created_at" in alice


# --- 创建 ---

def test_create_user_success(admin_client):
    c, app = admin_client
    r = c.post("/api/users", json={"username": "bob", "password": "bob-pw-1", "role": "user"},
               headers={"X-CSRF-Token": _csrf(c)})
    assert r.status_code == 200
    bob = app.state.auth_store.get_user_by_username("bob")
    admin = app.state.auth_store.get_user_by_username("admin")
    assert bob.must_change_password is True
    assert (app.state.config.workspaces_dir / "bob" / "workspace.json").exists()
    assert app.state.auth_store.get_workspace_member_role("bob", bob.id) == "manager"
    assert app.state.auth_store.get_workspace_member_role("bob", admin.id) == "manager"


def test_create_user_adds_all_admins_to_workspace(admin_client):
    c, app = admin_client
    ops = app.state.auth_store.create_user("ops", "h", role="admin")

    r = c.post("/api/users", json={"username": "bob", "password": "bob-pw-1", "role": "user"},
               headers={"X-CSRF-Token": _csrf(c)})

    assert r.status_code == 200
    assert app.state.auth_store.get_workspace_member_role("bob", ops.id) == "manager"


def test_create_user_dup_409(admin_client):
    c, app = admin_client
    r = c.post("/api/users", json={"username": "alice", "password": "x1234567", "role": "user"},
               headers={"X-CSRF-Token": _csrf(c)})
    assert r.status_code == 409


def test_create_user_short_pw_400(admin_client):
    c, app = admin_client
    r = c.post("/api/users", json={"username": "bob", "password": "123", "role": "user"},
               headers={"X-CSRF-Token": _csrf(c)})
    assert r.status_code == 400


def test_create_user_bad_role_422(admin_client):
    c, app = admin_client
    r = c.post("/api/users", json={"username": "bob", "password": "x1234567", "role": "superuser"},
               headers={"X-CSRF-Token": _csrf(c)})
    assert r.status_code == 422


def test_create_user_empty_password_uses_default(admin_client):
    """密码留空 -> 落默认密码 123456（与 bootstrap admin 同语义），must_change=True，
    且新用户能用默认密码登录（登录后弹一次可稍后的改密提醒，不阻断）。"""
    c, app = admin_client
    r = c.post("/api/users", json={"username": "bob", "password": "", "role": "user"},
               headers={"X-CSRF-Token": _csrf(c)})
    assert r.status_code == 200
    bob = app.state.auth_store.get_user_by_username("bob")
    assert bob.must_change_password is True
    fresh = TestClient(app)
    tok = fresh.get("/api/auth/csrf").json()["csrf_token"]
    r = fresh.post("/api/auth/login", json={"username": "bob", "password": "123456"},
                   headers={"X-CSRF-Token": tok})
    assert r.status_code == 200


def test_create_user_missing_password_field_defaults(admin_client):
    """password 字段整个不传 -> 等价留空，同样落默认密码。"""
    c, app = admin_client
    r = c.post("/api/users", json={"username": "bob", "role": "user"},
               headers={"X-CSRF-Token": _csrf(c)})
    assert r.status_code == 200


def test_create_user_explicit_default_pw_still_400(admin_client):
    """手填 "123456"（6 位 < 8）仍 400 —— 只有留空才走默认密码，手填路径校验不变。"""
    c, app = admin_client
    r = c.post("/api/users", json={"username": "bob", "password": "123456", "role": "user"},
               headers={"X-CSRF-Token": _csrf(c)})
    assert r.status_code == 400


# --- 删除 ---

def test_delete_user_clears_members(admin_client):
    c, app = admin_client
    aid = _alice_id(app)
    app.state.auth_store.add_workspace_member("ws-a", aid, "member")
    r = c.delete(f"/api/users/{aid}", headers={"X-CSRF-Token": _csrf(c)})
    assert r.status_code == 200
    assert app.state.auth_store.get_user(aid) is None
    assert app.state.auth_store.list_workspace_members("ws-a") == []


def test_delete_self_409(admin_client):
    c, app = admin_client
    me = app.state.auth_store.get_user_by_username("admin").id
    r = c.delete(f"/api/users/{me}", headers={"X-CSRF-Token": _csrf(c)})
    assert r.status_code == 409


def test_delete_last_admin_409(admin_client):
    c, app = admin_client
    me = app.state.auth_store.get_user_by_username("admin").id
    # 只有一个 admin，删自己即删最后 admin -> 409（同自删，覆盖最后 admin 护栏分支）
    r = c.delete(f"/api/users/{me}", headers={"X-CSRF-Token": _csrf(c)})
    assert r.status_code == 409


# --- 改全局角色 ---

def test_patch_role_success(admin_client):
    c, app = admin_client
    aid = _alice_id(app)
    r = c.patch(f"/api/users/{aid}", json={"role": "admin"},
                headers={"X-CSRF-Token": _csrf(c)})
    assert r.status_code == 200
    assert app.state.auth_store.get_user(aid).role == "admin"


def test_patch_role_self_demote_409(admin_client):
    c, app = admin_client
    me = app.state.auth_store.get_user_by_username("admin").id
    r = c.patch(f"/api/users/{me}", json={"role": "user"},
                headers={"X-CSRF-Token": _csrf(c)})
    assert r.status_code == 409


# --- 重置密码 ---

def test_reset_password_sets_must_change(admin_client):
    c, app = admin_client
    aid = _alice_id(app)
    r = c.post(f"/api/users/{aid}/reset-password", json={"new_password": "new-pw-12"},
               headers={"X-CSRF-Token": _csrf(c)})
    assert r.status_code == 200
    assert app.state.auth_store.get_user(aid).must_change_password is True


def test_reset_password_short_400(admin_client):
    c, app = admin_client
    aid = _alice_id(app)
    r = c.post(f"/api/users/{aid}/reset-password", json={"new_password": "123"},
               headers={"X-CSRF-Token": _csrf(c)})
    assert r.status_code == 400


def test_reset_password_clears_brute_lock(admin_client):
    """admin 重置密码应清除该用户的登录失败锁定（BruteGuard）。

    现场场景：新用户反复输错 ≥5 次 → BruteGuard 锁 5 分钟（正确密码也 429，
    前端显示笼统 "Login failed"）→ admin 重置密码。重置语义 = 旧凭证全部作废，
    锁定无继续存在的理由 → 用户应能立即用新密码登录。用独立用户名，避免
    routes.py 模块级 _brute 单例被其他用例的 alice 失败计数污染。
    """
    c, app = admin_client
    # 建独立用户 lockme（走 API，对齐现场：admin 创建 → 用户尝试登录）
    r = c.post("/api/users", json={"username": "lockme", "password": "lockme-pw", "role": "user"},
               headers={"X-CSRF-Token": _csrf(c)})
    assert r.status_code == 200
    lid = app.state.auth_store.get_user_by_username("lockme").id
    # 连续输错 5 次（BruteGuard 默认 threshold=5）→ 锁定
    for i in range(5):
        anon = TestClient(app)
        tok = anon.get("/api/auth/csrf").json()["csrf_token"]
        r = anon.post("/api/auth/login", json={"username": "lockme", "password": f"bad-{i}"},
                      headers={"X-CSRF-Token": tok})
        assert r.status_code == 401
    anon = TestClient(app)
    tok = anon.get("/api/auth/csrf").json()["csrf_token"]
    r = anon.post("/api/auth/login", json={"username": "lockme", "password": "lockme-pw"},
                  headers={"X-CSRF-Token": tok})
    assert r.status_code == 429  # 锁定确认：正确密码也被拒
    # admin 重置密码 → 锁定应随之清除
    r = c.post(f"/api/users/{lid}/reset-password", json={"new_password": "reset-pw-1"},
               headers={"X-CSRF-Token": _csrf(c)})
    assert r.status_code == 200
    fresh = TestClient(app)
    tok = fresh.get("/api/auth/csrf").json()["csrf_token"]
    r = fresh.post("/api/auth/login", json={"username": "lockme", "password": "reset-pw-1"},
                   headers={"X-CSRF-Token": tok})
    assert r.status_code == 200  # 修复前：429


# --- 归属 ---

def test_get_user_workspaces(admin_client):
    c, app = admin_client
    aid = _alice_id(app)
    app.state.auth_store.add_workspace_member("ws-a", aid, "member")
    r = c.get(f"/api/users/{aid}/workspaces")
    assert r.status_code == 200
    assert {"workspace": "ws-a", "role": "member"} in r.json()["workspaces"]


# --- CSRF ---

def test_create_user_requires_csrf(admin_client):
    c, app = admin_client
    r = c.post("/api/users", json={"username": "bob", "password": "x1234567", "role": "user"})
    assert r.status_code == 403


def test_demoting_admin_clears_workspace_memberships(tmp_workspaces, monkeypatch):
    monkeypatch.setenv("SUPERNOVA_WEB_COOKIE_SECURE", "0")
    from supernova_core.utils.paths import resolve_workspaces_dir
    monkeypatch.setenv("SUPERNOVA_WORKER_ROOT", str(tmp_workspaces.parent))
    assert resolve_workspaces_dir() == tmp_workspaces
    app = create_app()
    st = app.state.auth_store
    admin = st.create_user("admin", hash_password("admin-pw"), role="admin")
    ops = st.create_user("ops", hash_password("ops-pw"), role="admin")
    from supernova_web.components.scan_store import write_workspace_meta
    ws = tmp_workspaces / "ws-a"
    ws.mkdir()
    write_workspace_meta(ws, name="ws-a", owner="seed")
    st.add_workspace_member("ws-a", admin.id, "manager")

    c = TestClient(app)
    tok = c.get("/api/auth/csrf").json()["csrf_token"]
    c.post("/api/auth/login", json={"username": "ops", "password": "ops-pw"},
           headers={"X-CSRF-Token": tok})
    r = c.patch(f"/api/users/{admin.id}", json={"role": "user"},
                headers={"X-CSRF-Token": _csrf(c)})

    assert r.status_code == 200
    assert st.get_workspace_member_role("ws-a", admin.id) is None
