"""详情与列表共享存活状态：heartbeat stale 只显示 reconnecting，等待统一对账。"""
import json

import httpx
import pytest


@pytest.fixture
def _authed_cookies(app_with_ws, monkeypatch):
    monkeypatch.setenv("SUPERNOVA_WEB_COOKIE_SECURE", "0")
    app = app_with_ws
    store = app.state.auth_store
    if store.get_user_by_username("admin") is None:
        store.create_user("admin", __import__("supernova_web.auth.passwords", fromlist=["hash_password"]).hash_password("test-pw"), role="admin")
    sid = app.state.session_manager.create(store.get_user_by_username("admin").id)
    return app, {"sn-sid": sid}


def _make_stale_scan(tmp_workspaces, ws="E", scan_id="20260911-040000"):
    """心跳 stale 的非终态 scan：created_at=epoch 1（宽限窗外）、无 heartbeat 文件、
    session.status=running —— _compute_status 对此推断 interrupted（事故形态）。"""
    scan_dir = tmp_workspaces / ws / "scans" / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "session.json").write_text(json.dumps(
        {"status": "running", "scan_type": "whitebox",
         "created_at": 1, "repo_path": "/code/x", "web_url": "http://e"}))
    return scan_dir


@pytest.mark.asyncio
async def test_detail_stale_heartbeat_is_reconnecting(
        _authed_cookies, tmp_workspaces):
    """详情不再以额外 describe 覆写列表状态，避免 interrupted/running 跳变。"""
    app, cookies = _authed_cookies
    _make_stale_scan(tmp_workspaces)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", cookies=cookies) as client:
        r = await client.get("/api/workspaces/E/scans/20260911-040000")
    assert r.status_code == 200
    assert r.json()["status"] == "reconnecting"
