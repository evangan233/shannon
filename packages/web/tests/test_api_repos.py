"""Legacy repos API tests, ported to ws-scoped routes (P2: /api/workspaces/{ws}/repos/...).

T2 moved every repo route under the workspace context + added workspace_member authz.
These cases cover repo CRUD/SSE behavior (not membership) — admin bypasses the
member check. Membership-specific cases live in test_repos_routes_ws.py.
"""
import json
import pytest
from fastapi.testclient import TestClient
from supernova_web.app import create_app


WS = "ws1"  # test workspace
BASE = f"/api/workspaces/{WS}/repos"


def _app(tmp_path, monkeypatch, repos):
    """repos: dict[repo_name -> state], laid out under workspaces/WS1/repos/.

    T1 made RepoManager per-ws (workspaces_dir/<ws>/repos); SUPERNOVA_REPOS_DIR no
    longer drives RepoManager. tmp_workspaces-style remount: SUPERNOVA_WORKER_ROOT
    = tmp_path so resolve_workspaces_dir() == tmp_path/"workspaces".
    """
    ws_root = tmp_path / "workspaces"
    ws_dir = ws_root / WS
    repos_dir = ws_dir / "repos"
    repos_dir.mkdir(parents=True, exist_ok=True)
    for name, state in repos.items():
        d = repos_dir / name; d.mkdir()
        (d / ".supernova-repo.json").write_text(json.dumps({"name": name, "state": state}))
        # 注：commit 628f2844（pre-T11）把 list_repos 顶层判定从 _is_repo 改为
        # (sub/.git).exists()；测试 setup 加 .git 模拟真 clone 产物（装配补全，非断言改动）。
        (d / ".git").mkdir()
    # T11 auth cascade: auth.db 落在 workspaces_dir/auth.db，必须先建好该目录，
    # 否则 AuthStore.init_schema() → sqlite3.OperationalError。remount 到 tmp_path
    # 让 workspaces_dir == ws_root（已 mkdir）。
    monkeypatch.setenv("SUPERNOVA_WORKER_ROOT", str(tmp_path))
    monkeypatch.setenv("SUPERNOVA_WEB_COOKIE_SECURE", "0")
    from supernova_web.config import get_config; get_config.cache_clear()
    return create_app()


def _authed(app):
    """构造已登录的 admin TestClient + 创建测试用户。返回 TestClient。

    使用 admin，使这些用例聚焦 repo CRUD/SSE 行为本身（成员鉴权另见 test_repos_routes_ws.py）。
    """
    from supernova_web.auth.passwords import hash_password
    store = app.state.auth_store
    if store.get_user_by_username("admin") is None:
        store.create_user("admin", hash_password("test-pw"), role="admin")
    c = TestClient(app)
    tok = c.get("/api/auth/csrf").json()["csrf_token"]
    c.post("/api/auth/login", json={"username": "admin", "password": "test-pw"},
           headers={"X-CSRF-Token": tok})
    return c


def _csrf(c):
    return c.get("/api/auth/csrf").json()["csrf_token"]


def test_list_repos(tmp_path, monkeypatch):
    app = _app(tmp_path, monkeypatch, {"foo": "ready", "bar": "failed"})
    client = _authed(app)
    r = client.get(BASE)
    assert r.status_code == 200
    names = [x["name"] for x in r.json()]
    assert names == ["bar", "foo"]
    states = {x["name"]: x["state"] for x in r.json()}
    assert states["foo"] == "ready" and states["bar"] == "failed"


def test_get_repo_detail(tmp_path, monkeypatch):
    app = _app(tmp_path, monkeypatch, {"foo": "ready"})
    client = _authed(app)
    r = client.get(f"{BASE}/foo")
    assert r.status_code == 200 and r.json()["name"] == "foo"
    assert client.get(f"{BASE}/missing").status_code == 404


def test_post_repo_503_no_creds(tmp_path, monkeypatch):
    monkeypatch.delenv("GITLAB_USER", raising=False)
    monkeypatch.delenv("GITLAB_TOKEN", raising=False)
    app = _app(tmp_path, monkeypatch, {})
    client = _authed(app)
    tok = _csrf(client)
    r = client.post(BASE, json={"git_url": "https://x/foo.git"}, headers={"X-CSRF-Token": tok})
    assert r.status_code == 503


def test_post_repo_409_conflict(tmp_path, monkeypatch):
    monkeypatch.setenv("GITLAB_USER", "u"); monkeypatch.setenv("GITLAB_TOKEN", "t")
    app = _app(tmp_path, monkeypatch, {"foo": "ready"})
    client = _authed(app)
    tok = _csrf(client)
    r = client.post(BASE, json={"git_url": "https://x/foo.git"}, headers={"X-CSRF-Token": tok})
    assert r.status_code == 409


@pytest.mark.asyncio
async def test_delete_busy_409(tmp_path, monkeypatch):
    # 注：brief 原版为 sync + asyncio.create_task —— 3.12 无 running loop 会 RuntimeError。
    # 改 async（与 test_sse_events 同模式）即可让 asyncio.create_task 取得 loop。
    import asyncio
    import httpx
    app = _app(tmp_path, monkeypatch, {"foo": "cloning"})
    # T1: _jobs 键改为 (ws, name) 元组
    app.state.repo_manager._jobs[(WS, "foo")] = asyncio.create_task(asyncio.sleep(10))
    # 直接生成 session + csrf 注入 cookie（ASGITransport 不走 TestClient cookie jar）
    from supernova_web.auth.csrf import generate_csrf_token
    from supernova_web.auth.passwords import hash_password
    store = app.state.auth_store
    if store.get_user_by_username("admin") is None:
        store.create_user("admin", hash_password("test-pw"), role="admin")
    sid = app.state.session_manager.create(store.get_user_by_username("admin").id)
    tok = generate_csrf_token()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t",
                                 cookies={"sn-sid": sid, "sn-csrf": tok}) as c:
        r = await c.delete(f"{BASE}/foo", headers={"X-CSRF-Token": tok})
    assert r.status_code == 409


@pytest.mark.asyncio
async def test_sse_events(tmp_path, monkeypatch):
    import httpx
    app = _app(tmp_path, monkeypatch, {"foo": "ready"})
    (tmp_path / "workspaces" / WS / "repos" / "foo" / "clone.ndjson").write_text(
        json.dumps({"ts": "t1", "phase": "cloning", "progress": 40, "status": "progress"}) + "\n"
        + json.dumps({"ts": "t2", "type": "clone_end", "status": "ready"}) + "\n")
    # 直接生成 session 注入 cookie
    store = app.state.auth_store
    if store.get_user_by_username("admin") is None:
        from supernova_web.auth.passwords import hash_password
        store.create_user("admin", hash_password("test-pw"), role="admin")
    sid = app.state.session_manager.create(store.get_user_by_username("admin").id)
    transport = httpx.ASGITransport(app=app)
    lines = []
    async with httpx.AsyncClient(transport=transport, base_url="http://t", timeout=5,
                                 cookies={"sn-sid": sid}) as c:
        async with c.stream("GET", f"{BASE}/foo/events") as r:
            assert r.status_code == 200
            async for line in r.aiter_lines():
                lines.append(line)
                if line.startswith("data:") and "clone_end" in line:
                    break
    assert any("40" in l for l in lines if l.startswith("data:"))


def test_get_repo_grouped_path(tmp_path, monkeypatch):
    """{name:path} 吃 group/repo 含 '/' 的路径，返回 group 字段。"""
    app = _app(tmp_path, monkeypatch, {})
    client = _authed(app)
    base = tmp_path / "workspaces" / WS / "repos"
    d = base / "frontend" / "foo"; d.mkdir(parents=True)
    (d / ".supernova-repo.json").write_text(json.dumps({"name": "frontend/foo", "state": "ready"}))
    r = client.get(f"{BASE}/frontend/foo")
    assert r.status_code == 200
    assert r.json()["name"] == "frontend/foo"
    assert r.json()["group"] == "frontend"
    # 分组目录本身 404
    assert client.get(f"{BASE}/frontend").status_code == 404


# ---- 关联仓库 API（POST /repos/link, admin-only, 关联只读）----

def _authed_as(app, username="tester", role="admin"):
    from supernova_web.auth.passwords import hash_password
    store = app.state.auth_store
    if store.get_user_by_username(username) is None:
        store.create_user(username, hash_password("test-pw"), role=role)
    c = TestClient(app)
    tok = c.get("/api/auth/csrf").json()["csrf_token"]
    c.post("/api/auth/login", json={"username": username, "password": "test-pw"},
           headers={"X-CSRF-Token": tok})
    return c


def _ext_repo(tmp_path, name="ext"):
    d = tmp_path / "external" / name
    d.mkdir(parents=True)
    (d / ".git").mkdir()
    return d


def test_list_repos_includes_linked(tmp_path, monkeypatch):
    target = _ext_repo(tmp_path)
    app = _app(tmp_path, monkeypatch, {"foo": "ready"})
    app.state.repo_manager.link_repo(WS, "ftoa", str(target))  # 造关联数据
    client = _authed(app)
    names = [x["name"] for x in client.get(BASE).json()]
    assert "ftoa" in names and "foo" in names


def test_delete_linked_unlinks_keeps_files(tmp_path, monkeypatch):
    target = _ext_repo(tmp_path)
    (target / "README.md").write_text("x")
    app = _app(tmp_path, monkeypatch, {})
    app.state.repo_manager.link_repo(WS, "ftoa", str(target))
    client = _authed(app)
    tok = _csrf(client)
    r = client.delete(f"{BASE}/ftoa", headers={"X-CSRF-Token": tok})
    assert r.status_code == 200
    assert "ftoa" not in [x["name"] for x in client.get(BASE).json()]
    assert target.exists() and (target / "README.md").exists()  # 源文件未删


def _real_ext_repo(tmp_path, name="shared"):
    """真 git 工作仓（main/dev 两分支、bare origin 作 remote、dev 带 upstream）——
    linked 可写 API 测试用（spec 2026-09-04）。"""
    import subprocess
    target = tmp_path / "external" / name
    origin = tmp_path / "external" / f"{name}.origin.git"
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(origin)], check=True)
    subprocess.run(["git", "clone", "-q", str(origin), str(target)], check=True)
    for cfg in (("user.email", "t@t.t"), ("user.name", "t")):
        subprocess.run(["git", "-C", str(target), "config", *cfg], check=True)
    (target / "README.md").write_text("main content")
    subprocess.run(["git", "-C", str(target), "add", "."], check=True)
    subprocess.run(["git", "-C", str(target), "commit", "-qm", "init"], check=True)
    subprocess.run(["git", "-C", str(target), "push", "-q", "origin", "main"], check=True)
    subprocess.run(["git", "-C", str(target), "checkout", "-qb", "dev"], check=True)
    (target / "README.md").write_text("dev content")
    subprocess.run(["git", "-C", str(target), "add", "."], check=True)
    subprocess.run(["git", "-C", str(target), "commit", "-qm", "dev"], check=True)
    subprocess.run(["git", "-C", str(target), "push", "-q", "-u", "origin", "dev"], check=True)
    subprocess.run(["git", "-C", str(target), "checkout", "-q", "main"], check=True)
    return target


def test_pull_and_checkout_linked_405(tmp_path, monkeypatch):
    """[2026-09-04 spec 推翻旧断言] 旧：linked 只读 405。新：admin 可写、ws 成员 403。
    保留函数名改语义同 TDD 改写；详见 spec 2026-09-04 §5。"""
    target = _real_ext_repo(tmp_path)
    app = _app(tmp_path, monkeypatch, {})
    app.state.repo_manager.link_repo(WS, "ftoa", str(target))
    admin = _authed(app)
    tok = _csrf(admin)
    # admin：branches（含 dev）→ checkout → pull 全通
    r = admin.get(f"{BASE}/ftoa/branches")
    assert r.status_code == 200
    assert "dev" in r.json()["branches"]
    r = admin.post(f"{BASE}/ftoa/checkout", json={"branch": "dev"},
                   headers={"X-CSRF-Token": tok})
    assert r.status_code == 200
    assert "dev content" in (target / "README.md").read_text()
    assert admin.post(f"{BASE}/ftoa/pull", headers={"X-CSRF-Token": tok}).status_code == 202
    # 共享目录零写入（spec §7）
    assert not (target / ".supernova-repo.json").exists()
    # ws 成员（user 角色）：三端点 403（admin-only），且打不改文件
    from supernova_web.auth.passwords import hash_password
    store = app.state.auth_store
    if store.get_user_by_username("member") is None:
        store.create_user("member", hash_password("test-pw"), role="user")
    store.ensure_workspace_member(WS, store.get_user_by_username("member").id, "member")
    member = TestClient(app)
    mtok = member.get("/api/auth/csrf").json()["csrf_token"]
    member.post("/api/auth/login", json={"username": "member", "password": "test-pw"},
                headers={"X-CSRF-Token": mtok})
    assert member.get(f"{BASE}/ftoa/branches").status_code == 403
    assert member.post(f"{BASE}/ftoa/pull", headers={"X-CSRF-Token": mtok}).status_code == 403
    assert member.post(f"{BASE}/ftoa/checkout", json={"branch": "main"},
                       headers={"X-CSRF-Token": mtok}).status_code == 403
    assert "dev content" in (target / "README.md").read_text()


def test_checkout_linked_scan_ref_409_and_dirty_422(tmp_path, monkeypatch):
    """spec §5.3 错误档：扫描引用中 checkout → 409；dirty 冲突 → 422 带 git 原文。"""
    target = _real_ext_repo(tmp_path)
    app = _app(tmp_path, monkeypatch, {})
    app.state.repo_manager.link_repo(WS, "ftoa", str(target))
    admin = _authed(app)
    tok = _csrf(admin)
    # 扫描引用锁（spec 2026-08-21 §2b 同款，linked 直读共享路径同样适用）
    app.state.scan_manager.active_repo_sources = lambda: {(WS, "ftoa")}
    r = admin.post(f"{BASE}/ftoa/checkout", json={"branch": "dev"},
                   headers={"X-CSRF-Token": tok})
    assert r.status_code == 409
    assert "扫描" in r.json()["detail"]
    # 解除引用 → dirty 冲突 422（git 原文在 detail）
    app.state.scan_manager.active_repo_sources = lambda: set()
    (target / "README.md").write_text("dirty local work")
    r = admin.post(f"{BASE}/ftoa/checkout", json={"branch": "dev"},
                   headers={"X-CSRF-Token": tok})
    assert r.status_code == 422
    assert "未提交改动" in r.json()["detail"]
    assert "README.md" in r.json()["detail"]


@pytest.mark.asyncio
async def test_events_linked_empty_stream(tmp_path, monkeypatch):
    import httpx
    target = _ext_repo(tmp_path)
    app = _app(tmp_path, monkeypatch, {})
    app.state.repo_manager.link_repo(WS, "ftoa", str(target))
    store = app.state.auth_store
    if store.get_user_by_username("admin") is None:
        from supernova_web.auth.passwords import hash_password
        store.create_user("admin", hash_password("test-pw"), role="admin")
    sid = app.state.session_manager.create(store.get_user_by_username("admin").id)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", timeout=3,
                                 cookies={"sn-sid": sid}) as c:
        async with c.stream("GET", f"{BASE}/ftoa/events") as r:
            assert r.status_code == 200
            lines = [line async for line in r.aiter_lines()]
    assert lines == []  # 关联仓库无 clone 进度，空流


# ---- 批量关联目录 API（POST /repos/link-dir, admin-only）----

def _proj_with_repos(tmp_path):
    proj = tmp_path / "proj"
    (proj / "frontend" / ".git").mkdir(parents=True)
    (proj / "services" / "auth" / ".git").mkdir(parents=True)
    return proj


def test_link_dir_admin_imports(tmp_path, monkeypatch):
    proj = _proj_with_repos(tmp_path)
    app = _app(tmp_path, monkeypatch, {})
    client = _authed(app)
    tok = _csrf(client)
    r = client.post(f"{BASE}/link-dir", json={"path": str(proj)},
                    headers={"X-CSRF-Token": tok})
    assert r.status_code == 200, r.text
    body = r.json()
    names = {x["name"] for x in body["imported"]}
    assert names == {"frontend", "services/auth"}


def test_link_dir_non_admin_403(tmp_path, monkeypatch):
    proj = _proj_with_repos(tmp_path)
    app = _app(tmp_path, monkeypatch, {})
    client = _authed_as(app, "member", "user")
    tok = _csrf(client)
    r = client.post(f"{BASE}/link-dir", json={"path": str(proj)},
                    headers={"X-CSRF-Token": tok})
    assert r.status_code == 403


def test_link_dir_bad_path_422(tmp_path, monkeypatch):
    app = _app(tmp_path, monkeypatch, {})
    client = _authed(app)
    tok = _csrf(client)
    r = client.post(f"{BASE}/link-dir", json={"path": str(tmp_path / "nope")},
                    headers={"X-CSRF-Token": tok})
    assert r.status_code == 422


# ---- 批量删除/取消关联 API（POST /repos/batch-delete）----
# 一个端点同时承担「批量物理删除」（私有克隆）和「批量取消关联」（linked 仓）——
# 复用 RepoManager.delete_one 的自动分叉。部分被占用则跳过、收集 skipped（对齐 link-dir）。

def test_batch_delete_mixed_classifies_deleted_and_unlinked(tmp_path, monkeypatch):
    """混合提交：私有克隆→deleted（目录 rmtree），关联仓→unlinked（源文件保留）。"""
    target = _ext_repo(tmp_path, "linked-src")
    (target / "README.md").write_text("x")
    app = _app(tmp_path, monkeypatch, {"foo": "ready", "bar": "ready"})
    app.state.repo_manager.link_repo(WS, "ftoa", str(target))
    client = _authed(app)
    tok = _csrf(client)
    r = client.post(f"{BASE}/batch-delete", json={"names": ["foo", "bar", "ftoa"]},
                    headers={"X-CSRF-Token": tok})
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body["deleted"]) == {"foo", "bar"}
    assert body["unlinked"] == ["ftoa"]
    assert body["skipped"] == []
    # 私有克隆目录被删；关联源文件保留
    assert not (tmp_path / "workspaces" / WS / "repos" / "foo").exists()
    assert target.exists() and (target / "README.md").exists()


def test_batch_delete_skips_scanning(tmp_path, monkeypatch):
    """部分仓库被在跑 scan 引用（active_repo_sources）→ skipped(scanning)，其余成功。"""
    app = _app(tmp_path, monkeypatch, {"foo": "ready", "bar": "ready"})
    monkeypatch.setattr(app.state.scan_manager, "active_repo_sources",
                        lambda: {(WS, "foo")})
    client = _authed(app)
    tok = _csrf(client)
    r = client.post(f"{BASE}/batch-delete", json={"names": ["foo", "bar"]},
                    headers={"X-CSRF-Token": tok})
    assert r.status_code == 200
    body = r.json()
    assert body["deleted"] == ["bar"]
    assert {"name": "foo", "reason": "scanning"} in body["skipped"]


def test_batch_delete_skips_not_found(tmp_path, monkeypatch):
    """不存在的 name → skipped(not_found)。返回 200（而非 404）也隐含证明 POST
    /repos/batch-delete 命中了本端点——若被 create_repo(POST /repos) 吞会因缺 git_url
    报 422 field required，拿不到这个 200 + skipped 结构。"""
    app = _app(tmp_path, monkeypatch, {"foo": "ready"})
    client = _authed(app)
    tok = _csrf(client)
    r = client.post(f"{BASE}/batch-delete", json={"names": ["foo", "ghost"]},
                    headers={"X-CSRF-Token": tok})
    assert r.status_code == 200
    body = r.json()
    assert body["deleted"] == ["foo"]
    assert {"name": "ghost", "reason": "not_found"} in body["skipped"]


@pytest.mark.asyncio
async def test_batch_delete_skips_busy(tmp_path, monkeypatch):
    """部分仓库在 _jobs（clone/pull 中）→ skipped(busy)，其余成功（async：注入 task 需 loop）。"""
    import asyncio
    import httpx
    app = _app(tmp_path, monkeypatch, {"foo": "ready", "bar": "ready"})
    app.state.repo_manager._jobs[(WS, "foo")] = asyncio.create_task(asyncio.sleep(10))
    from supernova_web.auth.csrf import generate_csrf_token
    from supernova_web.auth.passwords import hash_password
    store = app.state.auth_store
    if store.get_user_by_username("admin") is None:
        store.create_user("admin", hash_password("test-pw"), role="admin")
    sid = app.state.session_manager.create(store.get_user_by_username("admin").id)
    tok = generate_csrf_token()
    transport = httpx.ASGITransport(app=app)
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://t",
                                     cookies={"sn-sid": sid, "sn-csrf": tok}) as c:
            r = await c.post(f"{BASE}/batch-delete", json={"names": ["foo", "bar"]},
                             headers={"X-CSRF-Token": tok})
        assert r.status_code == 200
        body = r.json()
        assert body["deleted"] == ["bar"]
        assert {"name": "foo", "reason": "busy"} in body["skipped"]
    finally:
        t = app.state.repo_manager._jobs.pop((WS, "foo"), None)
        if t:
            t.cancel()


def test_batch_delete_path_traversal_422(tmp_path, monkeypatch):
    """路径穿越 name → 422 拒整批（绝不进处理流），合法的 foo 也不被删。"""
    app = _app(tmp_path, monkeypatch, {"foo": "ready"})
    client = _authed(app)
    tok = _csrf(client)
    r = client.post(f"{BASE}/batch-delete", json={"names": ["foo", "../evil"]},
                    headers={"X-CSRF-Token": tok})
    assert r.status_code == 422
    assert (tmp_path / "workspaces" / WS / "repos" / "foo").exists()  # 整批拒绝


def test_batch_delete_empty_422(tmp_path, monkeypatch):
    app = _app(tmp_path, monkeypatch, {})
    client = _authed(app)
    tok = _csrf(client)
    r = client.post(f"{BASE}/batch-delete", json={"names": []},
                    headers={"X-CSRF-Token": tok})
    assert r.status_code == 422


def test_batch_delete_too_many_422(tmp_path, monkeypatch):
    """超出单次上限 → 422（远超 200 的合理上限即触发）。"""
    app = _app(tmp_path, monkeypatch, {})
    client = _authed(app)
    tok = _csrf(client)
    too_many = [f"r{i}" for i in range(1000)]
    r = client.post(f"{BASE}/batch-delete", json={"names": too_many},
                    headers={"X-CSRF-Token": tok})
    assert r.status_code == 422


def test_batch_delete_deduplicates(tmp_path, monkeypatch):
    """重复 name 去重，结果里每项只出现一次。"""
    app = _app(tmp_path, monkeypatch, {"foo": "ready"})
    client = _authed(app)
    tok = _csrf(client)
    r = client.post(f"{BASE}/batch-delete", json={"names": ["foo", "foo"]},
                    headers={"X-CSRF-Token": tok})
    assert r.status_code == 200
    assert r.json()["deleted"] == ["foo"]


def test_batch_delete_non_member_403(tmp_path, monkeypatch):
    """非 ws 成员（user 角色且非 admin）→ workspace_member 拒 403。"""
    app = _app(tmp_path, monkeypatch, {"foo": "ready"})
    client = _authed_as(app, "outsider", "user")
    tok = _csrf(client)
    r = client.post(f"{BASE}/batch-delete", json={"names": ["foo"]},
                    headers={"X-CSRF-Token": tok})
    assert r.status_code == 403
