import json
import pytest
from starlette.testclient import TestClient

from supernova_web.app import create_app
from supernova_web.auth.passwords import hash_password


def _seed_scan(ws_dir, scan_id, created_at_iso, status="completed"):
    """在 ws/scans/<scan_id>/ 建一个最小 session.json（ScanStore.list_scans 可读）。"""
    from supernova_web.components.scan_store import write_workspace_meta
    scan_dir = ws_dir / "scans" / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)
    write_workspace_meta(ws_dir, name=ws_dir.name, owner="admin")
    (scan_dir / "session.json").write_text(json.dumps({
        "scan_id": scan_id, "scan_type": "whitebox", "status": status,
        "created_at": created_at_iso, "vuln_count": 0,
    }), encoding="utf-8")


@pytest.fixture
def setup(tmp_workspaces, monkeypatch):
    monkeypatch.setenv("SUPERNOVA_WEB_COOKIE_SECURE", "0")
    from supernova_core.utils.paths import resolve_workspaces_dir
    monkeypatch.setenv("SUPERNOVA_WORKER_ROOT", str(tmp_workspaces.parent))
    assert resolve_workspaces_dir() == tmp_workspaces
    app = create_app()
    st = app.state.auth_store
    st.create_user("admin", hash_password("admin-pw"), role="admin")
    alice = st.create_user("alice", hash_password("alice-pw"), role="user")
    ops = st.create_user("ops", hash_password("ops-pw"), role="admin")
    # ws-a：admin + alice 都是成员；ws-b：仅 admin
    for ws in ("ws-a", "ws-b"):
        (tmp_workspaces / ws).mkdir()
    st.add_workspace_member("ws-a", alice.id, "member")
    st.add_workspace_member("ws-a", ops.id, "member")
    _seed_scan(tmp_workspaces / "ws-a", "20260727-100000", "2026-07-27T10:00:00Z", "completed")
    _seed_scan(tmp_workspaces / "ws-b", "20260727-110000", "2026-07-27T11:00:00Z", "running")
    c = TestClient(app)
    return c, app, alice


def _login(c, username, password):
    tok = c.get("/api/auth/csrf").json()["csrf_token"]
    c.post("/api/auth/login", json={"username": username, "password": password},
           headers={"X-CSRF-Token": tok})


def test_admin_sees_all_ws_scans(setup):
    c, _, _ = setup
    _login(c, "admin", "admin-pw")
    r = c.get("/api/scans")
    assert r.status_code == 200
    scans = r.json()
    assert len(scans) == 2
    ws_names = {s["workspace"] for s in scans}
    assert ws_names == {"ws-a", "ws-b"}
    # 每条都有 workspace 字段
    assert all("workspace" in s for s in scans)
    # 按 created_at 倒序（11:00 在前）
    assert scans[0]["scan_id"] == "20260727-110000"


def test_normal_user_sees_only_member_ws_scans(setup):
    c, _, _ = setup
    _login(c, "alice", "alice-pw")
    r = c.get("/api/scans")
    assert r.status_code == 200
    scans = r.json()
    assert len(scans) == 1
    assert scans[0]["workspace"] == "ws-a"


def test_unauth_401(setup):
    c, _, _ = setup
    assert c.get("/api/scans").status_code == 401


def test_admin_sees_all_ws_scans_without_membership(setup):
    c, _, _ = setup
    _login(c, "ops", "ops-pw")
    r = c.get("/api/scans")
    assert r.status_code == 200
    scans = r.json()
    assert len(scans) == 2
    assert {scan["workspace"] for scan in scans} == {"ws-a", "ws-b"}
