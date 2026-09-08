"""工作区定价覆盖 API + scan_manager 覆盖注入。

spec: docs/superpowers/specs/2026-08-28-global-pricing-console-design.md §4.2
SSOT = <ws>/pricing.override.json 文件存在性；scan_manager 注入压过 env 文本段手写键。
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from starlette.testclient import TestClient

from supernova_web.app import create_app
from supernova_web.auth.passwords import hash_password


@pytest.fixture(autouse=True)
def _clean_pricing_env(monkeypatch):
    monkeypatch.delenv("SUPERNOVA_PRICING_OVERRIDE", raising=False)
    monkeypatch.delenv("SUPERNOVA_GLOBAL_PRICING", raising=False)


@pytest.fixture
def app(tmp_path, monkeypatch):
    (tmp_path / "workspaces").mkdir()
    monkeypatch.setenv("SUPERNOVA_WORKER_ROOT", str(tmp_path))
    monkeypatch.setenv("SUPERNOVA_WEB_COOKIE_SECURE", "0")
    a = create_app()
    (a.state.config.workspaces_dir / "ws-a").mkdir()
    return a


def _login(app, username, role, member_of=None, member_role="member"):
    app.state.auth_store.create_user(username, hash_password(f"{username}-pw"), role=role)
    c = TestClient(app)
    tok = c.get("/api/auth/csrf").json()["csrf_token"]
    assert c.post("/api/auth/login", json={"username": username, "password": f"{username}-pw"},
                  headers={"X-CSRF-Token": tok}).status_code == 200
    if member_of:
        user_id = app.state.auth_store.get_user_by_username(username).id
        app.state.auth_store.add_workspace_member(member_of, user_id, role=member_role)
    return c


def _tiers(i=1.0, o=2.0, cr=0.5, cc=0.0):
    return {"input": i, "output": o, "cache_read": cr, "cache_creation": cc}


def _put_ws(c, ws, body):
    csrf = c.get("/api/auth/csrf").json()["csrf_token"]
    return c.put(f"/api/workspaces/{ws}/pricing", json=body, headers={"X-CSRF-Token": csrf})


def _delete_ws(c, ws):
    csrf = c.get("/api/auth/csrf").json()["csrf_token"]
    return c.delete(f"/api/workspaces/{ws}/pricing", headers={"X-CSRF-Token": csrf})


# ---- GET ----


def test_member_get_defaults_to_inheritance(app):
    member = _login(app, "alice", "user", member_of="ws-a")
    r = member.get("/api/workspaces/ws-a/pricing")
    assert r.status_code == 200
    body = r.json()
    assert body["override_exists"] is False
    assert body["table_corrupt"] is False
    assert body["builtin_defaults"]["glm-5.2"]["input"] == 8.0
    by_model = {m["model"]: m for m in body["models"]}
    assert by_model["glm-5.2"]["source"] == "builtin"


def test_non_member_get_403(app):
    outsider = _login(app, "bob", "user")   # 非 ws-a 成员
    assert outsider.get("/api/workspaces/ws-a/pricing").status_code == 403


def test_invalid_ws_name_422(app):
    admin = _login(app, "root", "admin")
    assert admin.get("/api/workspaces/../evil/pricing").status_code in (404, 422)


# ---- PUT / DELETE ----


def test_put_ws_model_currency_roundtrip(app):
    """PUT 带模型级 currency → ws 覆盖文件保留 + GET 行兄弟字段透出。"""
    manager = _login(app, "cara", "user", member_of="ws-a", member_role="manager")
    r = _put_ws(manager, "ws-a", {"currency": "CNY", "models": {
        "m-usd": {**_tiers(), "currency": "USD"}, "m-follow": _tiers()}})
    assert r.status_code == 200
    data = json.loads(
        (app.state.config.workspaces_dir / "ws-a" / "pricing.override.json").read_text("utf-8"))
    assert data["models"]["m-usd"]["currency"] == "USD"
    body = manager.get("/api/workspaces/ws-a/pricing").json()
    by_model = {m["model"]: m for m in body["models"]}
    assert by_model["m-usd"]["currency"] == "USD"
    assert by_model["m-follow"]["currency"] is None


def test_put_ws_bad_model_currency_400(app):
    manager = _login(app, "gina", "user", member_of="ws-a", member_role="manager")
    r = _put_ws(manager, "ws-a", {"currency": "CNY", "models": {"m": {**_tiers(), "currency": "EUR"}}})
    assert r.status_code == 400
    assert "currency" in r.json()["detail"]


def test_manager_put_writes_override_file(app):
    manager = _login(app, "carol", "user", member_of="ws-a", member_role="manager")
    r = _put_ws(manager, "ws-a", {"currency": "CNY", "models": {"glm-5.2": _tiers(9, 30, 3)}})
    assert r.status_code == 200
    f = app.state.config.workspaces_dir / "ws-a" / "pricing.override.json"
    data = json.loads(f.read_text("utf-8"))
    assert data["models"]["glm-5.2"]["input"] == 9.0
    # GET 反映：override_exists + workspace 来源压过一切
    body = manager.get("/api/workspaces/ws-a/pricing").json()
    assert body["override_exists"] is True
    assert body["currency"] == "CNY"
    by_model = {m["model"]: m for m in body["models"]}
    assert by_model["glm-5.2"]["source"] == "workspace"
    assert by_model["glm-5.2"]["prices"]["input"] == 9.0


def test_member_put_delete_403(app):
    member = _login(app, "dave", "user", member_of="ws-a")   # member 非 manager
    assert _put_ws(member, "ws-a", {"currency": "CNY", "models": {"m": _tiers()}}).status_code == 403
    assert _delete_ws(member, "ws-a").status_code == 403


def test_admin_bypasses_membership(app):
    # workspace_member/manager 的 admin 直通由 is_global_admin 判定
    admin = _login(app, "admin", "admin")
    assert _put_ws(admin, "ws-a", {"currency": "USD", "models": {"m": _tiers()}}).status_code == 200


def test_manager_delete_restores_inheritance_and_idempotent(app):
    manager = _login(app, "erin", "user", member_of="ws-a", member_role="manager")
    _put_ws(manager, "ws-a", {"currency": "CNY", "models": {"glm-5.2": _tiers()}})
    r = _delete_ws(manager, "ws-a")
    assert r.status_code == 200
    assert not (app.state.config.workspaces_dir / "ws-a" / "pricing.override.json").exists()
    body = manager.get("/api/workspaces/ws-a/pricing").json()
    assert body["override_exists"] is False
    assert {m["model"]: m for m in body["models"]}["glm-5.2"]["source"] == "builtin"
    assert _delete_ws(manager, "ws-a").status_code == 200   # 幂等


def test_put_validation_400(app):
    manager = _login(app, "frank", "user", member_of="ws-a", member_role="manager")
    r = _put_ws(manager, "ws-a", {"currency": "CNY", "models": {"glm-5.2": _tiers(), "GLM-5.2[1m]": _tiers()}})
    assert r.status_code == 400
    assert "冲突" in r.json()["detail"]


# ---- scan_manager._resolve_env_overrides 注入 ----


def _scan_manager(tmp_path, ws_config_store=None):
    from supernova_web.components.scan_manager import ScanManager
    return ScanManager(workspaces_dir=tmp_path, repos_dir=tmp_path,
                       config_store=object(), ws_config_store=ws_config_store)


def test_env_overrides_inject_when_override_file_exists(tmp_path):
    (tmp_path / "ws-a").mkdir()
    f = tmp_path / "ws-a" / "pricing.override.json"
    f.write_text(json.dumps({"currency": "CNY", "models": {"m": {}}}), encoding="utf-8")
    # env 文本段手写键存在 → 覆盖文件路径压过手写（UI 覆盖存在即接管）
    store = SimpleNamespace(resolve_env_overrides=lambda ws: {
        "SUPERNOVA_PRICING_OVERRIDE": "hand-written.json", "SUPERNOVA_LLM_TRACK_ENABLED": "0"})
    m = _scan_manager(tmp_path, ws_config_store=store)
    ov = m._resolve_env_overrides("ws-a")
    assert ov["SUPERNOVA_PRICING_OVERRIDE"] == str(f)
    assert ov["SUPERNOVA_LLM_TRACK_ENABLED"] == "0"   # 其他键不受影响


def test_env_overrides_handwritten_key_kept_without_override_file(tmp_path):
    (tmp_path / "ws-a").mkdir()
    store = SimpleNamespace(resolve_env_overrides=lambda ws: {
        "SUPERNOVA_PRICING_OVERRIDE": "hand-written.json"})
    m = _scan_manager(tmp_path, ws_config_store=store)
    ov = m._resolve_env_overrides("ws-a")
    assert ov["SUPERNOVA_PRICING_OVERRIDE"] == "hand-written.json"   # 无 UI 覆盖 → 手写键照常


def test_env_overrides_inject_even_without_ws_config_store(tmp_path):
    # 覆盖文件是文件系统 SSOT：无 ws_config_store（CLI/旧形态）时也注入
    (tmp_path / "ws-a").mkdir()
    f = tmp_path / "ws-a" / "pricing.override.json"
    f.write_text("{}", encoding="utf-8")
    m = _scan_manager(tmp_path)
    assert m._resolve_env_overrides("ws-a") == {"SUPERNOVA_PRICING_OVERRIDE": str(f)}


def test_env_overrides_empty_when_nothing(tmp_path):
    (tmp_path / "ws-a").mkdir()
    store = SimpleNamespace(resolve_env_overrides=lambda ws: {})
    m = _scan_manager(tmp_path, ws_config_store=store)
    assert m._resolve_env_overrides("ws-a") == {}
    assert m._resolve_env_overrides("ws-b") == {}   # ws 目录不存在 → 无注入
