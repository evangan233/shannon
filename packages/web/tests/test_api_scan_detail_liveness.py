"""detail API 判活盲区二次确认（2026-09-11 NodeGoat-20260910-193720 事故钉死）。

_compute_status 判活只看 scan 心跳文件：activity 在 Temporal 重试等待期
（backoff ~5min ×3，如 ActivityNotRegistered 重试）无 activity 执行 → 心跳停更
→ 推断 interrupted——但主 workflow 仍 RUNNING。详情页显示「已中断」+ 续跑入口，
误导用户点续跑（80dd1968 的 terminate 守卫防住了双跑，但用户在扫描实际推进中
被引导 terminate 掉它）。detail 是用户决策入口：interrupted 时用
orphan_reconciler._workflow_still_running describe 二次确认，RUNNING → running。
"""
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


def _patch_workflow_still_running(monkeypatch, running: bool):
    async def _fake(scan_dir):
        return running
    monkeypatch.setattr(
        "supernova_web.components.orphan_reconciler._workflow_still_running", _fake)


@pytest.mark.asyncio
async def test_detail_interrupted_refined_to_running_when_workflow_alive(
        _authed_cookies, tmp_workspaces, monkeypatch):
    """心跳 stale 但 workflow 仍 RUNNING（activity 重试等待）→ detail 显示 running。"""
    app, cookies = _authed_cookies
    _make_stale_scan(tmp_workspaces)
    _patch_workflow_still_running(monkeypatch, running=True)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", cookies=cookies) as client:
        r = await client.get("/api/workspaces/E/scans/20260911-040000")
    assert r.status_code == 200
    assert r.json()["status"] == "running"


@pytest.mark.asyncio
async def test_detail_interrupted_kept_when_workflow_terminal(
        _authed_cookies, tmp_workspaces, monkeypatch):
    """workflow 已终态/查不到 → 维持 interrupted（真孤儿语义不变）。"""
    app, cookies = _authed_cookies
    _make_stale_scan(tmp_workspaces)
    _patch_workflow_still_running(monkeypatch, running=False)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", cookies=cookies) as client:
        r = await client.get("/api/workspaces/E/scans/20260911-040000")
    assert r.status_code == 200
    assert r.json()["status"] == "interrupted"
