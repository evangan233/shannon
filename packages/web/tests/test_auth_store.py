from supernova_web.auth.models import User, SessionRow
from supernova_web.auth.store import AuthStore


def test_init_schema_idempotent(tmp_path):
    db = tmp_path / "auth.db"
    s = AuthStore(str(db))
    s.init_schema()
    s.init_schema()  # 再次建表不报错
    assert db.exists()


def test_create_and_get_user(tmp_path):
    s = AuthStore(str(tmp_path / "auth.db")); s.init_schema()
    u = s.create_user("alice", "$2b$12$hash", role="user")
    assert u.id is not None and u.username == "alice" and u.role == "user"
    got = s.get_user_by_username("alice")
    assert got is not None and got.id == u.id
    assert s.get_user_by_username("nobody") is None
    assert s.get_user(u.id).username == "alice"


def test_get_password_hash(tmp_path):
    s = AuthStore(str(tmp_path / "auth.db")); s.init_schema()
    s.create_user("alice", "$2b$12$xxx")
    assert s.get_password_hash("alice") == "$2b$12$xxx"
    assert s.get_password_hash("nobody") is None


def test_create_user_default_must_change_false(tmp_path):
    """新建用户默认 must_change_password=False。"""
    s = AuthStore(str(tmp_path / "auth.db")); s.init_schema()
    u = s.create_user("alice", "h")
    assert u.must_change_password is False
    got = s.get_user(u.id)
    assert got is not None and got.must_change_password is False


def test_create_user_with_must_change_true(tmp_path):
    """create_user 可显式置 must_change_password=True（默认账号场景）。"""
    s = AuthStore(str(tmp_path / "auth.db")); s.init_schema()
    u = s.create_user("admin", "h", role="admin", must_change=True)
    assert u.must_change_password is True
    got = s.get_user_by_username("admin")
    assert got is not None and got.must_change_password is True


def test_update_password_clears_must_change(tmp_path):
    """update_password 改 hash 并把 must_change_password 置 False（改密即脱提醒）。"""
    s = AuthStore(str(tmp_path / "auth.db")); s.init_schema()
    u = s.create_user("admin", "$2b$12$old", must_change=True)
    assert s.get_user(u.id).must_change_password is True
    s.update_password(u.id, "$2b$12$new")
    assert s.get_password_hash("admin") == "$2b$12$new"
    got = s.get_user(u.id)
    assert got is not None and got.must_change_password is False


def test_must_change_column_migration_idempotent(tmp_path):
    """init_schema 多次调用不报错（ALTER TABLE ADD COLUMN 幂等：列已存则跳过）。"""
    s = AuthStore(str(tmp_path / "auth.db")); s.init_schema()
    s.init_schema()  # 二次 init_schema 不应因列已存在而崩
    s.create_user("alice", "h", must_change=True)
    assert s.get_user_by_username("alice").must_change_password is True


def test_username_unique(tmp_path):
    import pytest
    s = AuthStore(str(tmp_path / "auth.db")); s.init_schema()
    s.create_user("alice", "h")
    with pytest.raises(Exception):
        s.create_user("alice", "h")


def test_session_crud_and_purge(tmp_path):
    s = AuthStore(str(tmp_path / "auth.db")); s.init_schema()
    u = s.create_user("alice", "h")
    s.insert_session(SessionRow(id="sid-1", user_id=u.id, expires_at="2099-01-01T00:00:00", last_seen_at="2026-01-01T00:00:00"))
    s.insert_session(SessionRow(id="sid-old", user_id=u.id, expires_at="2020-01-01T00:00:00", last_seen_at="2019-01-01T00:00:00"))
    assert s.get_session("sid-1").user_id == u.id
    assert s.get_session("missing") is None
    s.update_session_seen("sid-1", "2026-06-01T00:00:00")
    n = s.purge_expired("2026-01-01T00:00:00")
    assert n == 1  # sid-old 过期被删
    assert s.get_session("sid-old") is None
    s.delete_session("sid-1")
    assert s.get_session("sid-1") is None


def test_list_all_users_includes_created_at_and_must_change(tmp_path):
    """list_all_users 返回的 User 必须带 created_at 与 must_change_password。"""
    s = AuthStore(str(tmp_path / "auth.db")); s.init_schema()
    s.create_user("alice", "h", role="user")
    s.create_user("admin", "h", role="admin", must_change=True)
    users = s.list_all_users()
    by_name = {u.username: u for u in users}
    assert by_name["alice"].created_at != ""          # create_user 写了 created_at
    assert by_name["admin"].must_change_password is True


def test_delete_user_clears_members_and_sessions(tmp_path):
    """删用户必须单事务清 workspace_members + sessions + users（FK 不强制，手动清）。"""
    s = AuthStore(str(tmp_path / "auth.db")); s.init_schema()
    u = s.create_user("alice", "h")
    s.add_workspace_member("ws-a", u.id, "member")
    s.insert_session(SessionRow(id="sid-1", user_id=u.id,
                                expires_at="2099-01-01T00:00:00",
                                last_seen_at="2026-01-01T00:00:00"))
    assert s.list_workspace_members("ws-a") != []      # 前置：有成员
    s.delete_user(u.id)
    assert s.get_user(u.id) is None                     # 本体已删
    assert s.list_workspace_members("ws-a") == []       # 成员记录已清
    assert s.get_session("sid-1") is None               # session 已清


def test_update_role(tmp_path):
    s = AuthStore(str(tmp_path / "auth.db")); s.init_schema()
    u = s.create_user("alice", "h", role="user")
    s.update_role(u.id, "admin")
    assert s.get_user(u.id).role == "admin"


def test_reset_password_sets_must_change(tmp_path):
    """reset_password 写新 hash 并置 must_change=1（与 update_password 置 0 相对）。"""
    s = AuthStore(str(tmp_path / "auth.db")); s.init_schema()
    u = s.create_user("alice", "$2b$12$old")
    s.reset_password(u.id, "$2b$12$new")
    assert s.get_password_hash("alice") == "$2b$12$new"
    assert s.get_user(u.id).must_change_password is True


def test_list_user_workspaces_with_role(tmp_path):
    s = AuthStore(str(tmp_path / "auth.db")); s.init_schema()
    u = s.create_user("alice", "h")
    s.add_workspace_member("ws-a", u.id, "manager")
    s.add_workspace_member("ws-b", u.id, "member")
    got = dict(s.list_user_workspaces_with_role(u.id))
    assert got == {"ws-a": "manager", "ws-b": "member"}


def test_update_workspace_member_role(tmp_path):
    s = AuthStore(str(tmp_path / "auth.db")); s.init_schema()
    u = s.create_user("alice", "h")
    s.add_workspace_member("ws-a", u.id, "member")
    s.update_workspace_member_role("ws-a", u.id, "manager")
    assert s.get_workspace_member_role("ws-a", u.id) == "manager"


def test_last_visited_workspace_column_migration_and_update(tmp_path):
    """旧库（无 pinned/last_visited 列）启动补列不崩；update/get 读写 last_visited。"""
    import sqlite3
    from supernova_web.auth.store import AuthStore
    from supernova_web.auth.passwords import hash_password

    db = tmp_path / "auth.db"
    # 模拟旧库：手动建无 pinned_workspace/last_visited_workspace 列的 users 表 + 一条用户
    with sqlite3.connect(db) as c:
        c.execute(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, "
            "password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', "
            "created_at TEXT NOT NULL, must_change_password INTEGER NOT NULL DEFAULT 0)"
        )
        c.execute(
            "INSERT INTO users(username, password_hash, role, created_at, must_change_password) "
            "VALUES(?,?,?,?,?)",
            ("alice", hash_password("pw"), "user", "2026-01-01T00:00:00Z", 0),
        )

    store = AuthStore(str(db))
    store.init_schema()  # 旧库补列，不崩

    u = store.get_user_by_username("alice")
    assert u is not None
    assert u.last_visited_workspace is None  # 旧库补列后默认 None

    store.update_last_visited_workspace(u.id, "ws-alpha")
    assert store.get_user(u.id).last_visited_workspace == "ws-alpha"

    # 新建用户 last_visited_workspace 默认 None
    new = store.create_user("bob", hash_password("pw"), role="user")
    assert store.get_user(new.id).last_visited_workspace is None


def test_pinned_workspace_renamed_with_value_preserved(tmp_path):
    """置顶→最近访问替换迁移（2026-09-11）：旧库 pinned_workspace 列（含存量值）经
    RENAME 成 last_visited_workspace，值保留为初值（置顶过的 ws = 想回去的 ws，无缝）。"""
    import sqlite3
    from supernova_web.auth.store import AuthStore
    from supernova_web.auth.passwords import hash_password

    db = tmp_path / "auth.db"
    with sqlite3.connect(db) as c:
        c.execute(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, "
            "password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', "
            "created_at TEXT NOT NULL, must_change_password INTEGER NOT NULL DEFAULT 0, "
            "pinned_workspace TEXT)"
        )
        c.execute(
            "INSERT INTO users(username, password_hash, role, created_at, must_change_password, pinned_workspace) "
            "VALUES(?,?,?,?,?,?)",
            ("alice", hash_password("pw"), "user", "2026-01-01T00:00:00Z", 0, "ws-legacy"),
        )

    store = AuthStore(str(db))
    store.init_schema()  # RENAME pinned_workspace -> last_visited_workspace

    u = store.get_user_by_username("alice")
    assert u is not None
    # 存量置顶值无缝成为最近访问初值
    assert u.last_visited_workspace == "ws-legacy"

    # 二次 init（已改名库，RENAME 报 no such column）幂等不崩
    store.init_schema()
    assert store.get_user(u.id).last_visited_workspace == "ws-legacy"
