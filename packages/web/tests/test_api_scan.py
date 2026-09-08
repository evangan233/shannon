import pytest
from fastapi.testclient import TestClient

from supernova_web.app import create_app
from supernova_web.components.scan_manager import TemporalUnavailable
from supernova_web.components.ws_config_store import default_ws_config


class FakeSM:
    def __init__(self):
        self.started = []
        self.exc = None
        self.cancelled = []

    async def start(self, req):
        if self.exc:
            raise self.exc
        self.started.append(req)
        return "WSX", "20260727-120000"  # T3: (ws, scan_id)

    def active_pids(self):
        return {}


_BODY = {"type": "whitebox", "source": {"kind": "path", "value": "/x"}, "url": "http://e",
        "workspace": "WSX"}


@pytest.fixture
def _authed_app(tmp_workspaces, monkeypatch):
    """T11 后 /api/scan 要求登录 + 写操作 CSRF；返 (app, csrf_getter)。

    create_app 之前需把 cookie_secure 关掉（get_config lru_cache）。

    Task 4 起 /api/scan 还要求 ws 已存在 + 当前用户成员/admin。使用 admin
    + 预建 WSX 目录, 使现有 6 个测试 (测 endpoint 错误处理, 非测成员) 不受影响。
    成员语义由 test_workspace_lifecycle.py 覆盖。
    """
    from supernova_core.utils.paths import resolve_workspaces_dir
    monkeypatch.setenv("SUPERNOVA_WORKER_ROOT", str(tmp_workspaces.parent))
    assert resolve_workspaces_dir() == tmp_workspaces
    monkeypatch.setenv("SUPERNOVA_WEB_COOKIE_SECURE", "0")
    from supernova_web.auth.passwords import hash_password
    app = create_app()
    app.state.auth_store.create_user("admin", hash_password("test-pw"), role="admin")
    # 预建 WSX 目录, 使 create_scan 的 ws-exists 校验通过; FakeSM.start 仍返 "WSX"。
    # per-test create_app(overrides=...) 共享同一 workspaces_dir (经 env), WSX 可见。
    app.state.config.workspaces_dir.joinpath("WSX").mkdir(parents=True, exist_ok=True)
    cfg = default_ws_config()
    cfg.provider.api_key = "test-key"
    app.state.ws_config_store.write("WSX", cfg)
    return app


def _authed_client(app):
    """构造已登录的 TestClient（业务路由要走 HTTP，cookie_secure 已关）。"""
    c = TestClient(app)
    tok = c.get("/api/auth/csrf").json()["csrf_token"]
    c.post("/api/auth/login", json={"username": "admin", "password": "test-pw"},
           headers={"X-CSRF-Token": tok})
    return c


def _csrf(c):
    return c.get("/api/auth/csrf").json()["csrf_token"]


def test_post_scan_202(_authed_app):
    fake = FakeSM()
    app = create_app(overrides={"scan_manager": fake})
    # 把 _authed_app 的 auth_store/session_manager 复用过来（同 db 文件）
    app.state.auth_store = _authed_app.state.auth_store
    app.state.session_manager = _authed_app.state.session_manager
    client = _authed_client(app)
    tok = _csrf(client)
    r = client.post("/api/scan", json=_BODY, headers={"X-CSRF-Token": tok})
    assert r.status_code == 202
    # bb_phase：组合扫描透传 "precheck"；FakeSM 不建真实 scan_dir → None。
    body = r.json()
    assert body["workspace"] == "WSX"
    assert body["scan_id"] == "20260727-120000"
    assert body.get("bb_phase") is None
    assert len(fake.started) == 1


def test_post_scan_400_temporal(_authed_app):
    fake = FakeSM()
    fake.exc = TemporalUnavailable()
    app = create_app(overrides={"scan_manager": fake})
    app.state.auth_store = _authed_app.state.auth_store
    app.state.session_manager = _authed_app.state.session_manager
    client = _authed_client(app)
    tok = _csrf(client)
    assert client.post("/api/scan", json=_BODY, headers={"X-CSRF-Token": tok}).status_code == 400


def test_post_scan_422_when_workspace_provider_config_missing(_authed_app):
    """工作区缺 API key 时返回结构化错误（code=provider_incomplete + missing 字段列表），
    让前端能把它和真正的 yaml 校验失败区分开，显示「请前往工作区设置补全凭据」而非「yaml 校验失败」。"""
    fake = FakeSM()
    app = create_app(overrides={"scan_manager": fake})
    app.state.auth_store = _authed_app.state.auth_store
    app.state.session_manager = _authed_app.state.session_manager
    app.state.ws_config_store.write("WSX", default_ws_config())
    client = _authed_client(app)
    tok = _csrf(client)

    response = client.post("/api/scan", json=_BODY, headers={"X-CSRF-Token": tok})

    assert response.status_code == 422
    detail = response.json()["detail"]
    assert isinstance(detail, dict)
    assert detail["code"] == "provider_incomplete"
    assert "SUPERNOVA_OPENAI_API_KEY" in detail["missing"]
    assert fake.started == []


def test_post_scan_workspace_field_name_contract(_authed_app):
    """C2 final-review 回归：锁定 /api/scan 请求体的 ws 字段名为 ``workspace``（非 ``workspace_name``）。

    Root cause（final-review C2）：backend ``ScanRequest``（models.py:25）字段是 ``workspace``，
    pydantic v2 默认不容未知键 → 前端发 ``workspace_name`` 被静默丢弃 → ``req.workspace is None``
    → ``api/scan.py:19-22`` 抛 422。**每个前端扫描提交在 prod 都 422**（frontend 测试用 MSW
    mock 绕过，backend 测试用 ``ScanRequest(workspace=...)`` 直构绕过，故双方都没抓到）。

    Fix 方向：align frontend to backend contract（types.ts ScanRequest + ScanNewPage buildBody
    发 ``workspace``，backend 不动）。本测试固化 backend 契约——
      - 正确字段名 ``workspace`` → 202 + ``req.workspace == "WSX"``（经 HTTP 序列化层后端真收到）；
      - 错误字段名 ``workspace_name`` → 422 + ``req.workspace is None``（pydantic 丢弃未知键）。
    """
    fake = FakeSM()
    app = create_app(overrides={"scan_manager": fake})
    app.state.auth_store = _authed_app.state.auth_store
    app.state.session_manager = _authed_app.state.session_manager
    client = _authed_client(app)
    tok = _csrf(client)

    # 正确字段名 `workspace` → 202 + 后端收到的 req.workspace 有值
    body_ok = {"type": "whitebox", "source": {"kind": "path", "value": "/x"},
               "url": "http://e", "workspace": "WSX"}
    r = client.post("/api/scan", json=body_ok, headers={"X-CSRF-Token": tok})
    assert r.status_code == 202, r.text
    # bb_phase：组合扫描（whitebox+url+认证）异步预验证时透传 "precheck"；FakeSM 不建真实
    # scan_dir → best-effort 读返 None。此处断言核心字段（workspace/scan_id）+ bb_phase 键存在。
    body = r.json()
    assert body["workspace"] == "WSX"
    assert body["scan_id"] == "20260727-120000"
    assert "bb_phase" in body and body["bb_phase"] is None
    assert len(fake.started) == 1
    # 关键断言：经 pydantic HTTP 序列化层后，ScanRequest.workspace 真的收到了值
    assert fake.started[0].workspace == "WSX"

    # 错误字段名 `workspace_name` → pydantic 丢弃 → req.workspace is None → 422
    body_wrong = {"type": "whitebox", "source": {"kind": "path", "value": "/x"},
                  "url": "http://e", "workspace_name": "WSX"}
    r2 = client.post("/api/scan", json=body_wrong, headers={"X-CSRF-Token": tok})
    assert r2.status_code == 422  # workspace 不存在
    # start 没被第二次调用（422 在 sm.start 之前抛）
    assert len(fake.started) == 1


# ── GET /api/scan/gate：全局扫描闸门快照（spec 2026-09-08-worker-scan-gate §8.1）──

def _write_gate_file(app, payload):
    import json as _json
    app.state.config.workspaces_dir.joinpath("gate_state.json").write_text(
        _json.dumps(payload))


def test_get_scan_gate_returns_snapshot(_authed_app):
    """正常：读 gate_state.json 返回快照。"""
    _write_gate_file(_authed_app, {
        "capacity": 5, "max_waiting": 50,
        "held": [{"ws": "w1", "scan_id": "s1", "kind": "whitebox",
                  "label": "r@main", "since": 1.0}],
        "waiting": [{"ws": "w2", "scan_id": "s2", "kind": "mr",
                     "label": "u!12", "since": 2.0}]})
    client = _authed_client(_authed_app)
    resp = client.get("/api/scan/gate")
    assert resp.status_code == 200
    body = resp.json()
    assert body["capacity"] == 5
    assert body["held"][0]["ws"] == "w1"
    assert body["waiting"][0]["kind"] == "mr"


def test_get_scan_gate_missing_file_empty(_authed_app):
    """worker 未起/未落盘：空快照不 500。"""
    client = _authed_client(_authed_app)
    resp = client.get("/api/scan/gate")
    assert resp.status_code == 200
    assert resp.json() == {"capacity": 5, "max_waiting": 50, "held": [], "waiting": []}


def test_get_scan_gate_filters_by_ws_membership(_authed_app):
    """非全局 admin：无权 ws 的条目过滤，容量计数保留（spec §8.1）。"""
    from supernova_web.auth.passwords import hash_password
    app = _authed_app
    app.state.auth_store.create_user("alice", hash_password("test-pw"), role="user")
    app.state.auth_store.add_workspace_member("w1", app.state.auth_store.get_user_by_username("alice").id)
    _write_gate_file(app, {
        "capacity": 5, "max_waiting": 50,
        "held": [{"ws": "w1", "scan_id": "s1", "kind": "whitebox", "label": "a", "since": 1.0},
                 {"ws": "w2", "scan_id": "s2", "kind": "whitebox", "label": "b", "since": 1.0}],
        "waiting": [{"ws": "w3", "scan_id": "s3", "kind": "blackbox", "label": "c", "since": 2.0}]})
    client = TestClient(app)
    tok = client.get("/api/auth/csrf").json()["csrf_token"]
    client.post("/api/auth/login", json={"username": "alice", "password": "test-pw"},
                headers={"X-CSRF-Token": tok})
    resp = client.get("/api/scan/gate")
    body = resp.json()
    assert [e["ws"] for e in body["held"]] == ["w1"]
    assert body["waiting"] == []
    assert body["capacity"] == 5
