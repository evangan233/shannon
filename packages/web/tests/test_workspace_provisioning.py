from pathlib import Path

import pytest

from supernova_web.auth.models import User
from supernova_web.auth.store import AuthStore
from supernova_web.components.scan_store import write_workspace_meta
from supernova_web.components.workspace_provisioner import (
    ensure_global_admin_access,
    ensure_user_workspace,
    is_global_admin,
)


def _store(tmp_path: Path) -> AuthStore:
    store = AuthStore(str(tmp_path / "auth.db"))
    store.init_schema()
    return store


def test_is_global_admin_requires_admin_role():
    assert is_global_admin(User(id=1, username="admin", role="admin")) is True
    assert is_global_admin(User(id=2, username="root", role="admin")) is True
    assert is_global_admin(User(id=3, username="admin", role="user")) is False


def test_ensure_user_workspace_creates_metadata_and_manager_memberships(tmp_path):
    store = _store(tmp_path)
    alice = store.create_user("alice", "h", role="user")
    first_admin = store.create_user("admin", "h", role="admin")
    second_admin = store.create_user("ops", "h", role="admin")

    ws_dir = ensure_user_workspace(tmp_path / "workspaces", store, alice)

    assert ws_dir == tmp_path / "workspaces" / "alice"
    assert (ws_dir / "workspace.json").exists()
    assert store.get_workspace_member_role("alice", alice.id) == "manager"
    assert store.get_workspace_member_role("alice", first_admin.id) == "manager"
    assert store.get_workspace_member_role("alice", second_admin.id) == "manager"


def test_ensure_user_workspace_is_idempotent(tmp_path):
    store = _store(tmp_path)
    admin = store.create_user("admin", "h", role="admin")
    alice = store.create_user("alice", "h", role="user")

    first = ensure_user_workspace(tmp_path / "workspaces", store, alice)
    second = ensure_user_workspace(tmp_path / "workspaces", store, alice)

    assert first == second
    assert {row[:2] for row in store.list_workspace_members("alice")} == {
        (admin.id, "admin"),
        (alice.id, "alice"),
    }
    assert all(role == "manager" for _, _, role in store.list_workspace_members("alice"))


def test_ensure_user_workspace_rejects_unsafe_username(tmp_path):
    store = _store(tmp_path)
    user = store.create_user("alice/../escape", "h")

    with pytest.raises(ValueError, match="unsafe workspace name"):
        ensure_user_workspace(tmp_path / "workspaces", store, user)


def test_ensure_global_admin_access_adds_all_admins_to_all_workspaces(tmp_path):
    store = _store(tmp_path)
    admin = store.create_user("admin", "h", role="admin")
    other_admin = store.create_user("ops", "h", role="admin")
    alice = store.create_user("alice", "h", role="user")
    workspaces = tmp_path / "workspaces"
    for name in ("one", "two"):
        ws = workspaces / name
        ws.mkdir(parents=True)
        write_workspace_meta(ws, name=name, owner="seed")
    store.add_workspace_member("one", alice.id, "member")

    ensure_global_admin_access(workspaces, store)

    assert store.get_workspace_member_role("one", admin.id) == "manager"
    assert store.get_workspace_member_role("two", admin.id) == "manager"
    assert store.get_workspace_member_role("one", other_admin.id) == "manager"
    assert store.get_workspace_member_role("two", other_admin.id) == "manager"
    assert store.get_workspace_member_role("one", alice.id) == "member"


def test_ensure_user_workspace_upgrades_owner_to_manager(tmp_path):
    store = _store(tmp_path)
    admin = store.create_user("admin", "h", role="admin")
    alice = store.create_user("alice", "h", role="user")
    workspaces = tmp_path / "workspaces"
    ws = workspaces / "alice"
    ws.mkdir(parents=True)
    write_workspace_meta(ws, name="alice", owner="alice")
    store.add_workspace_member("alice", alice.id, "member")

    ensure_user_workspace(workspaces, store, alice)

    assert store.get_workspace_member_role("alice", alice.id) == "manager"
    assert store.get_workspace_member_role("alice", admin.id) == "manager"


def test_ensure_global_admin_access_upgrades_existing_admin_membership(tmp_path):
    store = _store(tmp_path)
    admin = store.create_user("admin", "h", role="admin")
    workspaces = tmp_path / "workspaces"
    ws = workspaces / "one"
    ws.mkdir(parents=True)
    write_workspace_meta(ws, name="one", owner="seed")
    store.add_workspace_member("one", admin.id, "member")

    ensure_global_admin_access(workspaces, store)

    assert store.get_workspace_member_role("one", admin.id) == "manager"
