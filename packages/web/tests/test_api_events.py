# packages/web/tests/test_api_events.py
"""scan-scoped events SSE（GET /{ws}/scans/{scan_id}/events）。

旧 ws-scoped GET /{ws}/events shim 已移除（联合验收确认零前端调用）。
"""
import json

import httpx
import pytest


@pytest.fixture
def _authed_cookies(app_with_ws, monkeypatch):
    """返 (app, cookies) 供 ASGITransport 用（admin，注入 session cookie）。

    归并流 wb scan_end 扣发宽限调小：SSE 测试等关流信号，默认 10s 会撞 httpx timeout。"""
    monkeypatch.setenv("SUPERNOVA_WEB_COOKIE_SECURE", "0")
    monkeypatch.setenv("SUPERNOVA_EVENTS_CLOSE_GRACE_SECONDS", "0.1")
    app = app_with_ws
    store = app.state.auth_store
    if store.get_user_by_username("admin") is None:
        store.create_user("admin", __import__("supernova_web.auth.passwords", fromlist=["hash_password"]).hash_password("test-pw"), role="admin")
    sid = app.state.session_manager.create(store.get_user_by_username("admin").id)
    return app, {"sn-sid": sid}


def _make_scan(tmp_workspaces, ws="E", scan_id="20260727-120000"):
    scan_dir = tmp_workspaces / ws / "scans" / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "session.json").write_text(json.dumps(
        {"status": "running", "scan_type": "whitebox", "created_at": 1}))
    return scan_dir


@pytest.mark.asyncio
async def test_sse_streams_until_scan_end(_authed_cookies, tmp_workspaces):
    """GET /{ws}/scans/{scan_id}/events tail events.ndjson 直到 scan_end。"""
    app, cookies = _authed_cookies
    scan_dir = _make_scan(tmp_workspaces)
    ef = scan_dir / "events.ndjson"
    ef.write_text(
        json.dumps({"type": "InfoEvent", "ts": "t1", "category": "INFO", "message": "hi"}) + "\n"
        + json.dumps({"type": "scan_end", "ts": "t2", "category": "CONTROL", "status": "completed"}) + "\n"
    )
    transport = httpx.ASGITransport(app=app)
    lines: list[str] = []
    async with httpx.AsyncClient(transport=transport, base_url="http://t", timeout=5, cookies=cookies) as client:
        async with client.stream("GET", "/api/workspaces/E/scans/20260727-120000/events") as r:
            assert r.status_code == 200
            async for line in r.aiter_lines():
                lines.append(line)
                if line.startswith("data:") and "scan_end" in line:
                    break
    assert any("data:" in l and "hi" in l for l in lines)
    assert any("id:" in l for l in lines)  # 带事件 id（Last-Event-ID 用）


@pytest.mark.asyncio
async def test_sse_404_unknown_scan(_authed_cookies, tmp_workspaces):
    """scan 不存在 -> 404。"""
    app, cookies = _authed_cookies
    _make_scan(tmp_workspaces, scan_id="s1")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", cookies=cookies) as client:
        r = await client.get("/api/workspaces/E/scans/nope/events")
        assert r.status_code == 404


@pytest.mark.asyncio
async def test_sse_terminal_scan_skips_close_grace(_authed_cookies, tmp_workspaces, monkeypatch):
    """已终态扫描免 close_grace 宽限（2026-09-09 中断体感 follow-up）。

    默认 grace=10s 防的是「扫描在跑、run 目录未建」竞态；扫描已终态（session
    status=interrupted，现场=chatbot-20260909-030342）时宽限纯属延迟——live 页
    spinner 空转 ~10s 才等到 scan_end 变 ‖。修复：is_running=False → grace 压到
    0.5s。本测试不设 grace env（真实默认），断言 scan_end 在 3s 内到达（修复前
    要等满 10s，撞 5s timeout 即 red）。"""
    import time
    monkeypatch.delenv("SUPERNOVA_EVENTS_CLOSE_GRACE_SECONDS", raising=False)
    app, cookies = _authed_cookies
    scan_dir = _make_scan(tmp_workspaces, ws="E", scan_id="20260909-030342")
    (scan_dir / "session.json").write_text(json.dumps(
        {"status": "interrupted", "scan_type": "whitebox", "created_at": 1}))
    (scan_dir / "events.ndjson").write_text(
        json.dumps({"type": "PhaseEvent", "ts": "t1", "category": "PHASE",
                    "phase": "recon", "event": "start"}) + "\n"
        + json.dumps({"type": "scan_end", "ts": "t2", "category": "CONTROL",
                      "status": "interrupted"}) + "\n"
    )
    transport = httpx.ASGITransport(app=app)
    lines: list[str] = []
    t0 = time.monotonic()
    async with httpx.AsyncClient(transport=transport, base_url="http://t", timeout=5, cookies=cookies) as client:
        async with client.stream("GET", "/api/workspaces/E/scans/20260909-030342/events") as r:
            assert r.status_code == 200
            async for line in r.aiter_lines():
                lines.append(line)
                if line.startswith("data:") and '"scan_end"' in line:
                    break
    elapsed = time.monotonic() - t0
    assert any('"interrupted"' in l for l in lines if l.startswith("data:"))
    assert elapsed < 3.0, f"终态扫描 scan_end 迟到 {elapsed:.1f}s（close_grace 未跳过）"


@pytest.mark.asyncio
async def test_sse_merges_authcheck_precheck_events(_authed_cookies, tmp_workspaces):
    """组合扫描 precheck(auth-validation 预验证)事件在独立 authcheck-events.ndjson(刻意隔离,
    scan_manager._run_precheck)。实时页合并显示 precheck 过程(authcheck 历史先 dump),但其
    scan_end 必须丢弃——前端 useEventSource 见 scan_end 就关流,而 authcheck 的 scan_end 是预验证
    finalize 写、非主扫描结束;主 events 的 scan_end 才正常关流。
    (2026-08-14:precheck 失败/白盒不跑时实时页空白的可观测性修复)"""
    app, cookies = _authed_cookies
    scan_dir = _make_scan(tmp_workspaces)
    # 主 events:precheck 失败场景只有 scan_end(白盒从未 submit)
    (scan_dir / "events.ndjson").write_text(
        json.dumps({"type": "scan_end", "ts": "t2", "category": "CONTROL", "status": "failed"}) + "\n"
    )
    # authcheck:precheck 全过程 + 自身 scan_end(AuthValidationWorkflow finalize 写)
    (scan_dir / "authcheck-events.ndjson").write_text(
        json.dumps({"type": "PhaseEvent", "ts": "t1", "category": "PHASE",
                    "phase": "auth-validation", "event": "start"}) + "\n"
        + json.dumps({"type": "scan_end", "ts": "t9", "category": "CONTROL", "status": "completed"}) + "\n"
    )
    transport = httpx.ASGITransport(app=app)
    lines: list[str] = []
    async with httpx.AsyncClient(transport=transport, base_url="http://t", timeout=5, cookies=cookies) as client:
        async with client.stream("GET", "/api/workspaces/E/scans/20260727-120000/events") as r:
            assert r.status_code == 200
            async for line in r.aiter_lines():
                lines.append(line)
                if line.startswith("data:") and '"scan_end"' in line:
                    break
    data_lines = [l for l in lines if l.startswith("data:")]
    # precheck 过程事件透传到实时页(修复前:authcheck 不被读 → 空白)
    assert any("auth-validation" in l for l in data_lines)
    # authcheck 的 scan_end(completed)被丢弃,流里只剩主 scan_end(failed)——不提前关流
    scan_end_lines = [l for l in data_lines if '"scan_end"' in l]
    assert len(scan_end_lines) == 1
    assert '"failed"' in scan_end_lines[0]
