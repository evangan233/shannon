import pytest
from starlette.testclient import TestClient
from supernova_web.app import create_app
from supernova_web.auth.passwords import hash_password


@pytest.fixture
def _app(tmp_workspaces, monkeypatch):
    # tmp_workspaces 设 SUPERNOVA_WORKER_ROOT=tmp_path/workspaces, 但
    # resolve_workspaces_dir 会再追加 /workspaces → 嵌套。remount 到父目录,
    # 让 workspaces_dir == tmp_workspaces(与 conftest.app_with_ws 同款)。
    monkeypatch.setenv("SUPERNOVA_WORKER_ROOT", str(tmp_workspaces.parent))
    monkeypatch.setenv("SUPERNOVA_WEB_COOKIE_SECURE", "0")
    app = create_app()
    st = app.state.auth_store
    st.create_user("admin", hash_password("p"), role="admin")
    st.create_user("alice", hash_password("p"))
    st.create_user("bob", hash_password("p"))
    (app.state.config.workspaces_dir / "ws1").mkdir()
    st.add_workspace_member("ws1", st.get_user_by_username("alice").id, "manager")
    return app


def _login(app, username):
    c = TestClient(app)
    tok = c.get("/api/auth/csrf").json()["csrf_token"]
    c.post("/api/auth/login", json={"username": username, "password": "p"}, headers={"X-CSRF-Token": tok})
    return c


def test_member_lists_repos(_app, monkeypatch):
    monkeypatch.setattr(_app.state.repo_manager, "list_repos", lambda ws: [{"name": "r1"}])
    c = _login(_app, "alice")
    r = c.get("/api/workspaces/ws1/repos")
    assert r.status_code == 200 and r.json() == [{"name": "r1"}]


def test_non_member_forbidden(_app):
    bob = _login(_app, "bob")  # bob 非 ws1 成员
    assert bob.get("/api/workspaces/ws1/repos").status_code == 403


def test_admin_accesses_any_ws(_app, monkeypatch):
    monkeypatch.setattr(_app.state.repo_manager, "list_repos", lambda ws: [])
    admin = _login(_app, "admin")
    assert admin.get("/api/workspaces/ws1/repos").status_code == 200


def test_clone_into_ws(_app, monkeypatch):
    async def _fake_clone(ws, url, branch, commit, name, group=None):
        return name or "y"
    monkeypatch.setattr(_app.state.repo_manager, "clone", _fake_clone)
    monkeypatch.setattr(_app.state.repo_manager._git, "available", lambda ws=None: True)
    alice = _login(_app, "alice")
    tok = alice.get("/api/auth/csrf").json()["csrf_token"]
    r = alice.post("/api/workspaces/ws1/repos", json={"git_url": "https://x/y.git"}, headers={"X-CSRF-Token": tok})
    assert r.status_code == 202


# ---- batch-clone（批量克隆，2026-09-09）----

def _csrf(c):
    return {"X-CSRF-Token": c.get("/api/auth/csrf").json()["csrf_token"]}


def test_batch_clone_returns_summary(_app, monkeypatch):
    async def _fake(ws, urls, group=None):
        return {"submitted": ["a", "b"], "queued": ["c"],
                "skipped": [{"url": "https://x/d.git", "reason": "exists"}]}
    monkeypatch.setattr(_app.state.repo_manager, "clone_batch", _fake)
    alice = _login(_app, "alice")
    r = alice.post("/api/workspaces/ws1/repos/batch-clone",
                   json={"urls": ["https://x/a.git", "https://x/b.git", "https://x/d.git"]},
                   headers=_csrf(alice))
    assert r.status_code == 202
    assert r.json() == {"submitted": ["a", "b"], "queued": ["c"],
                        "skipped": [{"url": "https://x/d.git", "reason": "exists"}]}


def test_batch_clone_no_creds_503(_app, monkeypatch):
    async def _fake(ws, urls, group=None):
        raise PermissionError("no creds")
    monkeypatch.setattr(_app.state.repo_manager, "clone_batch", _fake)
    alice = _login(_app, "alice")
    r = alice.post("/api/workspaces/ws1/repos/batch-clone",
                   json={"urls": ["https://x/a.git"]}, headers=_csrf(alice))
    assert r.status_code == 503


def test_batch_clone_validation_422(_app, monkeypatch):
    async def _fake(ws, urls, group=None):
        raise ValueError("urls 不能为空")
    monkeypatch.setattr(_app.state.repo_manager, "clone_batch", _fake)
    alice = _login(_app, "alice")
    r = alice.post("/api/workspaces/ws1/repos/batch-clone",
                   json={"urls": []}, headers=_csrf(alice))
    assert r.status_code == 422


def test_batch_clone_non_member_forbidden(_app):
    bob = _login(_app, "bob")
    r = bob.post("/api/workspaces/ws1/repos/batch-clone",
                 json={"urls": ["https://x/a.git"]}, headers=_csrf(bob))
    assert r.status_code == 403
