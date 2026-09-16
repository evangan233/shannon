"""POST /api/scan/batch 契约测试（spec 2026-09-11-batch-whitebox-scan）。

Task 1 先锁 pydantic 校验语义（不发 HTTP）；Task 2 加端点行为测试。
"""
import pytest
from pydantic import ValidationError

from supernova_web.models import BatchScanRequest, ScanIdsBatchRequest


def _base(**kw):
    body = {"workspace": "WSX", "repos": ["backend-gateway", "auth-service"]}
    body.update(kw)
    return BatchScanRequest(**body)


class TestBatchScanRequestValidation:
    def test_minimal_ok(self):
        req = _base()
        assert req.repos == ["backend-gateway", "auth-service"]

    def test_repos_empty_rejected(self):
        with pytest.raises(ValidationError):
            _base(repos=[])

    def test_repos_dedup(self):
        req = _base(repos=["a", "a", "b"])
        assert sorted(req.repos) == ["a", "b"]

    def test_repos_over_500_rejected(self):
        with pytest.raises(ValidationError):
            _base(repos=[f"r{i}" for i in range(501)])


class TestBatchScanMaxReposEnv:
    """SUPERNOVA_BATCH_SCAN_MAX_REPOS（2026-09-16 由硬编码 50 改 env 可配，
    同日默认 50→500——闸门管真并发，此处仅单次提交防呆）。

    运维参数（全局资源防呆），走全局 env 直读——按白名单准入原则不进
    SCAN_ENV_KEYS / ws 文本框。容错对齐 get_max_concurrent：未设/畸形/<1
    回落默认 500 + warning，绝不 crash 请求。"""

    def test_env_overrides_limit(self, monkeypatch):
        # env 调大有区分性：501 超默认 500（若 env 不生效会被拒），600 放行
        monkeypatch.setenv("SUPERNOVA_BATCH_SCAN_MAX_REPOS", "600")
        req = _base(repos=[f"r{i}" for i in range(501)])
        assert len(req.repos) == 501

    def test_env_over_limit_rejected_with_effective_value(self, monkeypatch):
        monkeypatch.setenv("SUPERNOVA_BATCH_SCAN_MAX_REPOS", "200")
        with pytest.raises(ValidationError) as ei:
            _base(repos=[f"r{i}" for i in range(201)])
        assert "200" in str(ei.value)
        assert "SUPERNOVA_BATCH_SCAN_MAX_REPOS" in str(ei.value)

    def test_env_malformed_falls_back_500(self, monkeypatch):
        monkeypatch.setenv("SUPERNOVA_BATCH_SCAN_MAX_REPOS", "abc")
        with pytest.raises(ValidationError):
            _base(repos=[f"r{i}" for i in range(501)])

    def test_env_nonpositive_falls_back_500(self, monkeypatch):
        monkeypatch.setenv("SUPERNOVA_BATCH_SCAN_MAX_REPOS", "0")
        with pytest.raises(ValidationError):
            _base(repos=[f"r{i}" for i in range(501)])

    def test_default_500(self, monkeypatch):
        monkeypatch.delenv("SUPERNOVA_BATCH_SCAN_MAX_REPOS", raising=False)
        req = _base(repos=[f"r{i}" for i in range(500)])
        assert len(req.repos) == 500

    def test_scan_ids_batch_follows_env(self, monkeypatch):
        # 批量取消/续跑同一上限（对齐语义：批量操作逐项起副作用）。
        # env 调小有区分性：201 超过 env=200（若 scan_ids 不跟随 env，
        # 201 < 默认 500 会通过）
        monkeypatch.setenv("SUPERNOVA_BATCH_SCAN_MAX_REPOS", "200")
        with pytest.raises(ValidationError):
            ScanIdsBatchRequest(scan_ids=[f"s{i}" for i in range(201)])

    def test_combined_url_with_auth_profile_ok(self):
        # 组合模式（带 url）：认证字段合法（profile 子集模式）
        req = _base(url="http://target.example",
                    auth_profile_id="p1", auth_credential_ids=["c1"])
        assert req.auth_profile_id == "p1"

    def test_pure_whitebox_rejects_auth(self):
        # 纯白盒（无 url）禁认证字段（移植 _whitebox_combined_optional）
        with pytest.raises(ValidationError):
            _base(auth_profile_id="p1")

    def test_auth_profile_xor_inline(self):
        with pytest.raises(ValidationError):
            _base(url="http://t", auth_profile_id="p1",
                  authentication={"login_type": "form"})

    def test_cred_without_profile_rejected(self):
        with pytest.raises(ValidationError):
            _base(url="http://t", auth_credential_ids=["c1"])

    def test_host_profile_xor_url(self):
        with pytest.raises(ValidationError):
            _base(url="http://t", host_profile_id="h1", host_url="http://hosts")

    def test_host_url_scheme_checked(self):
        with pytest.raises(ValidationError):
            _base(url="http://t", host_url="ftp://bad")

    def test_shared_fields_default(self):
        req = _base()
        assert req.url is None
        assert req.delete_repo_on_finish is False


# —— 端点行为测试（Task 2）——
from fastapi.testclient import TestClient

from supernova_web.app import create_app
from supernova_web.components.scan_manager import TemporalUnavailable
from supernova_web.components.ws_config_store import default_ws_config


class FakeSM:
    """与 test_api_scan.FakeSM 同款，加 per-repo 失败注入（fail_repos）。"""

    def __init__(self):
        self.started = []
        self.fail_repos: set[str] = set()
        self.exc = None  # 全局异常（TemporalUnavailable 等）

    async def start(self, req):
        if self.exc:
            raise self.exc
        name = req.source.value if req.source else ""
        if name in self.fail_repos:
            raise ValueError(f"仓库未就绪（state=cloning），请先在 ws 内完成 clone")
        self.started.append(req)
        return "WSX", f"scan-{len(self.started):04d}"

    def active_pids(self):
        return {}


@pytest.fixture
def _authed_app(tmp_workspaces, monkeypatch):
    from supernova_core.utils.paths import resolve_workspaces_dir
    monkeypatch.setenv("SUPERNOVA_WORKER_ROOT", str(tmp_workspaces.parent))
    assert resolve_workspaces_dir() == tmp_workspaces
    monkeypatch.setenv("SUPERNOVA_WEB_COOKIE_SECURE", "0")
    from supernova_web.auth.passwords import hash_password
    app = create_app()
    app.state.auth_store.create_user("admin", hash_password("test-pw"), role="admin")
    app.state.config.workspaces_dir.joinpath("WSX").mkdir(parents=True, exist_ok=True)
    cfg = default_ws_config()
    cfg.provider.api_key = "test-key"
    app.state.ws_config_store.write("WSX", cfg)
    return app


def _client_of(_authed_app, fake):
    app = create_app(overrides={"scan_manager": fake})
    app.state.auth_store = _authed_app.state.auth_store
    app.state.session_manager = _authed_app.state.session_manager
    c = TestClient(app)
    tok = c.get("/api/auth/csrf").json()["csrf_token"]
    c.post("/api/auth/login", json={"username": "admin", "password": "test-pw"},
           headers={"X-CSRF-Token": tok})
    return c, c.get("/api/auth/csrf").json()["csrf_token"]


def _batch_body(repos, **kw):
    body = {"workspace": "WSX", "repos": repos}
    body.update(kw)
    return body


class TestCreateScanBatch:
    def test_fanout_all_ok_202(self, _authed_app):
        fake = FakeSM()
        c, tok = _client_of(_authed_app, fake)
        r = c.post("/api/scan/batch", json=_batch_body(["repo-a", "repo-b"]),
                   headers={"X-CSRF-Token": tok})
        assert r.status_code == 202
        body = r.json()
        assert body["workspace"] == "WSX"
        assert body["submitted"] == 2 and body["failed"] == 0
        assert all(item["ok"] and item["scan_id"] for item in body["results"])
        assert len(fake.started) == 2
        # 每条都是独立白盒 ScanRequest（source 指向对应 repo，公共字段共享）
        assert [s.source.value for s in fake.started] == ["repo-a", "repo-b"]
        assert all(s.type == "whitebox" for s in fake.started)

    def test_partial_failure_202(self, _authed_app):
        fake = FakeSM()
        fake.fail_repos = {"repo-b"}
        c, tok = _client_of(_authed_app, fake)
        r = c.post("/api/scan/batch", json=_batch_body(["repo-a", "repo-b"]),
                   headers={"X-CSRF-Token": tok})
        assert r.status_code == 202
        body = r.json()
        assert body["submitted"] == 1 and body["failed"] == 1
        by_repo = {item["repo"]: item for item in body["results"]}
        assert by_repo["repo-a"]["ok"] is True
        assert by_repo["repo-b"]["ok"] is False
        assert "未就绪" in by_repo["repo-b"]["error"]

    def test_all_failed_422_with_results(self, _authed_app):
        fake = FakeSM()
        fake.fail_repos = {"repo-a", "repo-b"}
        c, tok = _client_of(_authed_app, fake)
        r = c.post("/api/scan/batch", json=_batch_body(["repo-a", "repo-b"]),
                   headers={"X-CSRF-Token": tok})
        assert r.status_code == 422
        body = r.json()
        assert len(body["results"]) == 2
        assert all(not item["ok"] for item in body["results"])

    def test_provider_incomplete_422_zero_fanout(self, _authed_app):
        fake = FakeSM()
        c, tok = _client_of(_authed_app, fake)
        # 覆写 WSX 配置为缺 key 的默认值
        c.app.state.ws_config_store.write("WSX", default_ws_config())
        r = c.post("/api/scan/batch", json=_batch_body(["repo-a"]),
                   headers={"X-CSRF-Token": tok})
        assert r.status_code == 422
        detail = r.json()["detail"]
        assert detail["code"] == "provider_incomplete"
        assert fake.started == []

    def test_shared_fields_forwarded(self, _authed_app):
        fake = FakeSM()
        c, tok = _client_of(_authed_app, fake)
        r = c.post("/api/scan/batch",
                   json=_batch_body(["repo-a", "repo-b"], url="http://t.example",
                                    delete_repo_on_finish=True),
                   headers={"X-CSRF-Token": tok})
        assert r.status_code == 202
        for s in fake.started:
            assert s.url == "http://t.example"
            assert s.delete_repo_on_finish is True

    def test_workspace_not_exist_422(self, _authed_app):
        fake = FakeSM()
        c, tok = _client_of(_authed_app, fake)
        r = c.post("/api/scan/batch", json=_batch_body(["repo-a"], **{"workspace": "NOPE"}),
                   headers={"X-CSRF-Token": tok})
        assert r.status_code == 422
        assert fake.started == []

    def test_non_member_403(self, _authed_app):
        """权限：普通用户非该 ws 成员且非全局 admin → 403，0 次 fan-out（spec §6）。"""
        fake = FakeSM()
        app = create_app(overrides={"scan_manager": fake})
        app.state.auth_store = _authed_app.state.auth_store
        app.state.session_manager = _authed_app.state.session_manager
        from supernova_web.auth.passwords import hash_password
        app.state.auth_store.create_user("outsider", hash_password("test-pw"), role="user")
        c = TestClient(app)
        tok = c.get("/api/auth/csrf").json()["csrf_token"]
        c.post("/api/auth/login", json={"username": "outsider", "password": "test-pw"},
               headers={"X-CSRF-Token": tok})
        r = c.post("/api/scan/batch", json=_batch_body(["repo-a"]),
                   headers={"X-CSRF-Token": tok})
        assert r.status_code == 403
        assert fake.started == []
