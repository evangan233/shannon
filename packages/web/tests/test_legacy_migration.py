# packages/web/tests/test_legacy_migration.py
from starlette.testclient import TestClient
from supernova_web.app import create_app


def test_legacy_workspace_assigned_to_canonical_admin(tmp_workspaces, monkeypatch):
    monkeypatch.setenv("SUPERNOVA_WEB_COOKIE_SECURE", "0")
    # tmp_workspaces 设 SUPERNOVA_WORKER_ROOT=tmp_path/"workspaces"，而
    # resolve_workspaces_dir() 会再追加 /"workspaces" -> 嵌套一层不存在的目录，
    # 导致 create_app() 里 auth_db_path 创建失败。改回父目录使解析结果恰等于
    # tmp_workspaces（与 conftest.app_with_ws 同款 rebase）。
    monkeypatch.setenv("SUPERNOVA_WORKER_ROOT", str(tmp_workspaces.parent))
    app = create_app()
    admin = app.state.auth_store.create_user("admin", "h", role="admin")
    legacy = app.state.config.workspaces_dir / "legacy_ws"
    legacy.mkdir()
    assert app.state.auth_store.list_workspace_members("legacy_ws") == []  # 迁移前无记录
    with TestClient(app):  # 触发 lifespan -> 迁移
        pass
    assert app.state.auth_store.get_workspace_member_role("legacy_ws", admin.id) == "manager"


def test_workspace_with_members_gets_all_admins_without_reassigning_members(
    tmp_workspaces, monkeypatch
):
    monkeypatch.setenv("SUPERNOVA_WEB_COOKIE_SECURE", "0")
    # 同上 rebase，使 workspaces_dir == tmp_workspaces。
    monkeypatch.setenv("SUPERNOVA_WORKER_ROOT", str(tmp_workspaces.parent))
    app = create_app()
    admin = app.state.auth_store.create_user("admin", "h", role="admin")
    ops = app.state.auth_store.create_user("ops", "h", role="admin")
    alice = app.state.auth_store.create_user("alice", "h")
    (app.state.config.workspaces_dir / "ws1").mkdir()
    app.state.auth_store.add_workspace_member("ws1", alice.id, "manager")  # 已有成员
    with TestClient(app):
        pass
    members = app.state.auth_store.list_workspace_members("ws1")
    assert app.state.auth_store.get_workspace_member_role("ws1", admin.id) == "manager"
    assert app.state.auth_store.get_workspace_member_role("ws1", ops.id) == "manager"
    assert app.state.auth_store.get_workspace_member_role("ws1", alice.id) == "manager"
    assert len(members) == 3


def test_startup_provisions_historical_user_workspaces(tmp_workspaces, monkeypatch):
    monkeypatch.setenv("SUPERNOVA_WEB_COOKIE_SECURE", "0")
    monkeypatch.setenv("SUPERNOVA_WORKER_ROOT", str(tmp_workspaces.parent))
    app = create_app()
    st = app.state.auth_store
    admin = st.create_user("admin", "h", role="admin")
    ops = st.create_user("ops", "h", role="admin")
    alice = st.create_user("alice", "h")
    ws = app.state.config.workspaces_dir / "existing"
    ws.mkdir()
    from supernova_web.components.scan_store import write_workspace_meta
    write_workspace_meta(ws, name="existing", owner="seed")
    st.add_workspace_member("existing", alice.id, "member")

    with TestClient(app):
        pass

    assert (app.state.config.workspaces_dir / "alice" / "workspace.json").exists()
    assert st.get_workspace_member_role("alice", alice.id) == "manager"
    assert st.get_workspace_member_role("alice", admin.id) == "manager"
    assert st.get_workspace_member_role("alice", ops.id) == "manager"
    assert st.get_workspace_member_role("existing", admin.id) == "manager"
    assert st.get_workspace_member_role("existing", alice.id) == "member"
    assert st.get_workspace_member_role("existing", ops.id) == "manager"


def test_user_named_stale_dir_blocks_ws_provisioning_without_touching_it(
    tmp_workspaces, monkeypatch,
):
    """启动对账退役收纳（2026-08-27）后的新语义守护：残留同名目录（历史根平铺 scan
    形态）不被启动移动/改造——ensure_all_user_workspaces 遇 FileExistsError 跳过该
    用户（绝不覆盖已有目录内容），session.json 原样保留，不产生 __legacy__。"""
    monkeypatch.setenv("SUPERNOVA_WEB_COOKIE_SECURE", "0")
    monkeypatch.setenv("SUPERNOVA_WORKER_ROOT", str(tmp_workspaces.parent))
    app = create_app()
    st = app.state.auth_store
    admin = st.create_user("admin", "h", role="admin")
    alice = st.create_user("alice", "h")
    stale_dir = app.state.config.workspaces_dir / "alice"
    stale_dir.mkdir()
    (stale_dir / "session.json").write_text(
        '{"status":"completed","scan_type":"whitebox","created_at":"2026-08-01T00:00:00Z"}'
    )

    with TestClient(app):
        pass

    # 残留目录原样保留：不被搬走、不被改造为 ws（无 workspace.json）
    assert (stale_dir / "session.json").exists()
    assert not (stale_dir / "workspace.json").exists()
    # 成员关系照常登记（DB 层 alice=manager、admin 兜底 manager）——目录不被覆盖是
    # 守护重点，ws 登记与文件改造解耦
    assert st.get_workspace_member_role("alice", alice.id) == "manager"
    assert st.get_workspace_member_role("alice", admin.id) == "manager"
    # 不产生 __legacy__
    assert not (app.state.config.workspaces_dir / "__legacy__").exists()
