"""HOST 档案多选（2026-09-11）：host_profile_ids 复数字段 + 多档案合并解析。

三层：
- models: ScanRequest/BatchScanRequest 加 host_profile_ids（与单数字段/urls 互斥、
  strip/去重归一、空列表拒绝）；
- scan_manager: _resolve_host_config_sources 接受 ids 列表——逐档案 refresh+归一化
  → 合并 dict；同 host 不同 IP 冲突 ValueError 带档案名；快照 profile_ids（旧
  profile_id=第一个兼容）；认证测试单/batch kwarg；
- API: auth test 端点 query 列表 / test-batch body / /api/scan/batch / scans detail
  回传 host_profile_ids（旧单数快照兜底包数组）。
"""
import pytest
from pydantic import ValidationError

from supernova_web.models import BatchScanRequest, ScanRequest


# ---------------------------------------------------------------------------
# ScanRequest model: host_profile_ids 复数字段 + 互斥/归一校验
# ---------------------------------------------------------------------------

def _bb(**kw):
    base = {"type": "blackbox", "reuse_whitebox_scan_id": "wb-1",
            "workspace": "ws1", "url": "http://x.test"}
    base.update(kw)
    return ScanRequest(**base)


def test_scan_request_accepts_host_profile_ids():
    r = _bb(host_profile_ids=["host_a", "host_b"])
    assert r.host_profile_ids == ["host_a", "host_b"]
    assert r.host_profile_id is None and r.host_url is None


def test_scan_request_host_profile_ids_xor_url():
    with pytest.raises(ValidationError):
        _bb(host_profile_ids=["host_a"], host_url="https://h.test/get?id=1")


def test_scan_request_host_profile_ids_xor_legacy_single():
    """单复同时指定 → 422（避免来源歧义）。"""
    with pytest.raises(ValidationError):
        _bb(host_profile_ids=["host_a"], host_profile_id="host_b")


def test_scan_request_host_profile_ids_normalizes():
    """strip 每项 + 过滤空项 + 保序去重。"""
    r = _bb(host_profile_ids=[" host_a ", "", "host_a", "host_b"])
    assert r.host_profile_ids == ["host_a", "host_b"]


def test_scan_request_host_profile_ids_empty_rejected():
    """启用多选但一个没选（空列表 / 全空项过滤后）→ 422，对齐单数字段空串语义。"""
    with pytest.raises(ValidationError):
        _bb(host_profile_ids=[])
    with pytest.raises(ValidationError):
        _bb(host_profile_ids=["", "  "])


def test_scan_request_host_profile_ids_combined_whitebox_ok():
    """组合模式（whitebox+url）HOST 多选合法（与单数字段同分支）。"""
    r = ScanRequest(type="whitebox", workspace="ws1", url="http://x.test",
                    source=None, host_profile_ids=["host_a", "host_b"])
    assert r.host_profile_ids == ["host_a", "host_b"]


def test_scan_request_host_profile_ids_pure_whitebox_ignored():
    """纯白盒（无 url）不校验 HOST 字段（无黑盒阶段，HOST 无意义）——对齐单数行为。"""
    r = ScanRequest(type="whitebox", workspace="ws1",
                    source=None, host_profile_ids=["host_a"])
    assert r.host_profile_ids == ["host_a"]


# ---------------------------------------------------------------------------
# BatchScanRequest model: 同规则
# ---------------------------------------------------------------------------

def _batch(**kw):
    body = {"workspace": "WSX", "repos": ["backend-gateway"]}
    body.update(kw)
    return BatchScanRequest(**body)


def test_batch_scan_request_accepts_host_profile_ids():
    req = _batch(url="http://t", host_profile_ids=["host_a", "host_b"])
    assert req.host_profile_ids == ["host_a", "host_b"]


def test_batch_scan_request_host_profile_ids_xor_url():
    with pytest.raises(ValidationError):
        _batch(url="http://t", host_profile_ids=["host_a"], host_url="http://hosts")


def test_batch_scan_request_host_profile_ids_xor_legacy_single():
    with pytest.raises(ValidationError):
        _batch(url="http://t", host_profile_ids=["host_a"], host_profile_id="host_b")


def test_batch_scan_request_host_profile_ids_empty_rejected():
    with pytest.raises(ValidationError):
        _batch(url="http://t", host_profile_ids=[])


# ---------------------------------------------------------------------------
# scan_manager: 多档案解析合并
# ---------------------------------------------------------------------------

def _mk_store(tmp_path):
    from supernova_web.components.host_profile_store import HostProfileStore
    return HostProfileStore(tmp_path)


@pytest.mark.asyncio
async def test_resolve_host_mappings_merges_multiple_profiles(tmp_path):
    """两个档案不同 host → 并集 dict。"""
    from supernova_web.components.scan_manager import ScanManager
    from supernova_web.components.host_profile_store import (
        HostMapping, HostProfile)

    store = _mk_store(tmp_path)
    store.upsert_profile("ws1", HostProfile(
        id="host_p1", name="P1", mappings=[HostMapping(ip="10.0.0.1", host="x.test")]))
    store.upsert_profile("ws1", HostProfile(
        id="host_p2", name="P2", mappings=[HostMapping(ip="10.0.0.2", host="y.test")]))

    sm = ScanManager(workspaces_dir=tmp_path, repos_dir=tmp_path,
                     config_store=object(), host_profile_store=store)
    req = _bb(host_profile_ids=["host_p1", "host_p2"])
    hm = await sm._resolve_host_mappings(req, "ws1")
    assert hm == {"x.test": "10.0.0.1", "y.test": "10.0.0.2"}


@pytest.mark.asyncio
async def test_resolve_host_mappings_same_host_same_ip_dedup(tmp_path):
    """跨档案同 host 同 IP → 自然去重，不报错。"""
    from supernova_web.components.scan_manager import ScanManager
    from supernova_web.components.host_profile_store import (
        HostMapping, HostProfile)

    store = _mk_store(tmp_path)
    store.upsert_profile("ws1", HostProfile(
        id="host_p1", name="P1", mappings=[HostMapping(ip="10.0.0.1", host="x.test")]))
    store.upsert_profile("ws1", HostProfile(
        id="host_p2", name="P2", mappings=[
            HostMapping(ip="10.0.0.1", host="x.test"),
            HostMapping(ip="10.0.0.2", host="y.test")]))

    sm = ScanManager(workspaces_dir=tmp_path, repos_dir=tmp_path,
                     config_store=object(), host_profile_store=store)
    req = _bb(host_profile_ids=["host_p1", "host_p2"])
    hm = await sm._resolve_host_mappings(req, "ws1")
    assert hm == {"x.test": "10.0.0.1", "y.test": "10.0.0.2"}


@pytest.mark.asyncio
async def test_resolve_host_mappings_conflict_raises_with_names(tmp_path):
    """跨档案同 host 不同 IP → ValueError 带两档案名 + host + 两个 IP（用户能看出选错哪两个）。"""
    from supernova_web.components.scan_manager import ScanManager
    from supernova_web.components.host_profile_store import (
        HostMapping, HostProfile)

    store = _mk_store(tmp_path)
    store.upsert_profile("ws1", HostProfile(
        id="host_p1", name="华南环境",
        mappings=[HostMapping(ip="10.0.0.1", host="api.test")]))
    store.upsert_profile("ws1", HostProfile(
        id="host_p2", name="华东环境",
        mappings=[HostMapping(ip="10.0.0.2", host="api.test")]))

    sm = ScanManager(workspaces_dir=tmp_path, repos_dir=tmp_path,
                     config_store=object(), host_profile_store=store)
    req = _bb(host_profile_ids=["host_p1", "host_p2"])
    with pytest.raises(ValueError) as ei:
        await sm._resolve_host_mappings(req, "ws1")
    msg = str(ei.value)
    assert "api.test" in msg and "华南环境" in msg and "华东环境" in msg
    assert "10.0.0.1" in msg and "10.0.0.2" in msg


@pytest.mark.asyncio
async def test_resolve_host_config_snapshot_has_profile_ids(tmp_path):
    """多选快照：profile_ids=完整列表；profile_id=第一个（旧读方兼容）。"""
    from supernova_web.components.scan_manager import ScanManager
    from supernova_web.components.host_profile_store import (
        HostMapping, HostProfile)

    store = _mk_store(tmp_path)
    store.upsert_profile("ws1", HostProfile(
        id="host_p1", name="P1", mappings=[HostMapping(ip="10.0.0.1", host="x.test")]))
    store.upsert_profile("ws1", HostProfile(
        id="host_p2", name="P2", mappings=[HostMapping(ip="10.0.0.2", host="y.test")]))

    sm = ScanManager(workspaces_dir=tmp_path, repos_dir=tmp_path,
                     config_store=object(), host_profile_store=store)
    req = _bb(host_profile_ids=["host_p1", "host_p2"])
    cfg = await sm._resolve_host_config(req, "ws1")
    assert cfg["profile_ids"] == ["host_p1", "host_p2"]
    assert cfg["profile_id"] == "host_p1"
    assert cfg["source"] == "profile"


@pytest.mark.asyncio
async def test_resolve_host_config_legacy_single_field_wraps_list(tmp_path):
    """旧单数字段向后兼容：快照 profile_ids=[单个]。"""
    from supernova_web.components.scan_manager import ScanManager
    from supernova_web.components.host_profile_store import (
        HostMapping, HostProfile)

    store = _mk_store(tmp_path)
    store.upsert_profile("ws1", HostProfile(
        id="host_p1", name="P1", mappings=[HostMapping(ip="10.0.0.1", host="x.test")]))

    sm = ScanManager(workspaces_dir=tmp_path, repos_dir=tmp_path,
                     config_store=object(), host_profile_store=store)
    req = _bb(host_profile_id="host_p1")
    cfg = await sm._resolve_host_config(req, "ws1")
    assert cfg["profile_ids"] == ["host_p1"]
    assert cfg["profile_id"] == "host_p1"


@pytest.mark.asyncio
async def test_resolve_host_mappings_partial_refresh_failure_fallback(tmp_path, monkeypatch):
    """一档案 refresh 抛异常回落快照、另一档案正常——per-档案 fallback 互不影响。"""
    from supernova_web.components.scan_manager import ScanManager
    from supernova_web.components.host_profile_store import (
        HostMapping, HostProfile)

    store = _mk_store(tmp_path)
    store.upsert_profile("ws1", HostProfile(
        id="host_p1", name="P1", source_url="https://h.test/get?id=1",
        mappings=[HostMapping(ip="10.0.0.1", host="x.test")]))
    store.upsert_profile("ws1", HostProfile(
        id="host_p2", name="P2",
        mappings=[HostMapping(ip="10.0.0.2", host="y.test")]))

    real_refresh = store.refresh

    async def flaky_refresh(ws, pid):
        if pid == "host_p1":
            raise OSError("disk full")
        return await real_refresh(ws, pid)

    monkeypatch.setattr(store, "refresh", flaky_refresh)

    sm = ScanManager(workspaces_dir=tmp_path, repos_dir=tmp_path,
                     config_store=object(), host_profile_store=store)
    req = _bb(host_profile_ids=["host_p1", "host_p2"])
    hm = await sm._resolve_host_mappings(req, "ws1")
    assert hm == {"x.test": "10.0.0.1", "y.test": "10.0.0.2"}


@pytest.mark.asyncio
async def test_resolve_host_mappings_one_missing_raises(tmp_path):
    """多选中任一档案不存在 → ValueError（档案不存在）。"""
    from supernova_web.components.scan_manager import ScanManager
    from supernova_web.components.host_profile_store import (
        HostMapping, HostProfile)

    store = _mk_store(tmp_path)
    store.upsert_profile("ws1", HostProfile(
        id="host_p1", name="P1", mappings=[HostMapping(ip="10.0.0.1", host="x.test")]))

    sm = ScanManager(workspaces_dir=tmp_path, repos_dir=tmp_path,
                     config_store=object(), host_profile_store=store)
    req = _bb(host_profile_ids=["host_p1", "host_missing"])
    with pytest.raises(ValueError, match="host_missing"):
        await sm._resolve_host_mappings(req, "ws1")


# ---------------------------------------------------------------------------
# scan_manager: 认证测试入口接受 host_profile_ids
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_start_auth_validation_accepts_host_profile_ids(tmp_path):
    """start_auth_validation(host_profile_ids=[...]) → 合并 mappings 灌 Input。"""
    from unittest.mock import AsyncMock, MagicMock, patch
    from supernova_web.components.scan_manager import ScanManager
    from supernova_web.components.host_profile_store import (
        HostMapping, HostProfile, HostProfileStore)
    from supernova_web.components.auth_profile_store import (
        AuthProfile, AuthProfileStore, AuthProfileCredential)
    from supernova_web.components.credential_vault import CredentialVault

    host_store = HostProfileStore(tmp_path / "hosts")
    host_store.upsert_profile("ws1", HostProfile(
        id="host_p1", name="P1", mappings=[HostMapping(ip="10.0.0.1", host="x.test")]))
    host_store.upsert_profile("ws1", HostProfile(
        id="host_p2", name="P2", mappings=[HostMapping(ip="10.0.0.2", host="y.test")]))

    auth_store = AuthProfileStore(tmp_path, CredentialVault(tmp_path / ".master.key"))
    auth_store.upsert_profile("ws1", AuthProfile(
        id="prof_1", name="NG", login_url="http://t/", login_type="form",
        credentials=[AuthProfileCredential(id="cred_a", role="admin",
                                           username="a", password="b")]))

    sm = ScanManager(workspaces_dir=tmp_path, repos_dir=tmp_path, config_store=MagicMock(),
                     host_profile_store=host_store, auth_profile_store=auth_store)

    client = MagicMock()
    client.start_workflow = AsyncMock(return_value=MagicMock(id="wf-1"))
    with patch("supernova_web.components.scan_manager.Client") as ClientCls:
        ClientCls.connect = AsyncMock(return_value=client)
        await sm.start_auth_validation(
            "ws1", "prof_1", "cred_a", host_profile_ids=["host_p1", "host_p2"])
    sent = client.start_workflow.call_args.args[1]
    assert sent.host_mappings == {"x.test": "10.0.0.1", "y.test": "10.0.0.2"}


@pytest.mark.asyncio
async def test_start_batch_auth_validation_accepts_host_profile_ids(tmp_path):
    """start_batch_auth_validation(host_profile_ids=[...]) → 每个 item 同值快照。"""
    from unittest.mock import AsyncMock, MagicMock, patch
    from supernova_web.components.scan_manager import ScanManager
    from supernova_web.components.host_profile_store import (
        HostMapping, HostProfile, HostProfileStore)
    from supernova_web.components.auth_profile_store import (
        AuthProfile, AuthProfileStore, AuthProfileCredential)
    from supernova_web.components.credential_vault import CredentialVault

    host_store = HostProfileStore(tmp_path / "hosts")
    host_store.upsert_profile("ws1", HostProfile(
        id="host_p1", name="P1", mappings=[HostMapping(ip="10.0.0.1", host="x.test")]))
    host_store.upsert_profile("ws1", HostProfile(
        id="host_p2", name="P2", mappings=[HostMapping(ip="10.0.0.2", host="y.test")]))

    auth_store = AuthProfileStore(tmp_path, CredentialVault(tmp_path / ".master.key"))
    auth_store.upsert_profile("ws1", AuthProfile(
        id="prof_1", name="NG", login_url="http://t/", login_type="form",
        credentials=[AuthProfileCredential(id="cred_a", role="a", username="a", password="b"),
                     AuthProfileCredential(id="cred_b", role="u", username="u", password="c")]))

    sm = ScanManager(workspaces_dir=tmp_path, repos_dir=tmp_path, config_store=MagicMock(),
                     host_profile_store=host_store, auth_profile_store=auth_store)

    client = MagicMock()
    client.start_workflow = AsyncMock(return_value=MagicMock(id="wf-b1"))
    with patch("supernova_web.components.scan_manager.Client") as ClientCls, \
         patch.object(sm, "_watch_batch_progress", new=AsyncMock()):
        ClientCls.connect = AsyncMock(return_value=client)
        await sm.start_batch_auth_validation(
            "ws1", "prof_1", None, host_profile_ids=["host_p1", "host_p2"])
    sent = client.start_workflow.call_args.args[1]
    merged = {"x.test": "10.0.0.1", "y.test": "10.0.0.2"}
    assert all(item.host_mappings == merged for item in sent.items)


# ---------------------------------------------------------------------------
# API 层：auth test 端点 / test-batch / scan batch / scans detail
# ---------------------------------------------------------------------------

def _bare_client():
    """裸 FastAPI + 鉴权短路 + MagicMock scan_manager（镜像 test_api_auth_profiles._client）。"""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from unittest.mock import MagicMock
    from supernova_web.api import auth_profiles
    from supernova_web.auth.dependencies import current_user, workspace_member

    class _U:
        role = "admin"
        id = 1

    app = FastAPI()
    app.state.scan_manager = MagicMock()
    app.include_router(auth_profiles.router)
    app.dependency_overrides[current_user] = lambda: _U()
    app.dependency_overrides[workspace_member] = lambda: _U()
    return TestClient(app)


def test_test_endpoint_threads_host_profile_ids():
    """POST test?host_profile_ids=a&host_profile_ids=b → start_auth_validation 透传列表。"""
    from unittest.mock import AsyncMock
    c = _bare_client()
    sm = c.app.state.scan_manager
    sm.start_auth_validation = AsyncMock(
        return_value={"workflow_id": "wf-h", "probe_dir": "/p"})

    r = c.post("/api/workspaces/ws1/auth-profiles/prof_1/credentials/cred_1/test",
               params=[("host_profile_ids", "host_p1"), ("host_profile_ids", "host_p2")])
    assert r.status_code == 200, r.text
    sm.start_auth_validation.assert_awaited_once_with(
        "ws1", "prof_1", "cred_1",
        host_profile_id=None, host_profile_ids=["host_p1", "host_p2"], host_url=None)


def test_test_batch_threads_host_profile_ids():
    """POST test-batch body 带 host_profile_ids → start_batch 透传列表。"""
    from unittest.mock import AsyncMock
    c = _bare_client()
    sm = c.app.state.scan_manager
    sm.start_batch_auth_validation = AsyncMock(return_value={"workflow_id": "wf-bh"})

    r = c.post("/api/workspaces/ws1/auth-profiles/prof_1/test-batch",
               json={"cred_ids": ["c1"], "host_profile_ids": ["host_p1", "host_p2"]})
    assert r.status_code == 200, r.text
    sm.start_batch_auth_validation.assert_awaited_once_with(
        "ws1", "prof_1", ["c1"],
        host_profile_id=None, host_profile_ids=["host_p1", "host_p2"], host_url=None)


def _detail_scan(tmp_workspaces, ws, scan_id, host_config):
    import json as _json
    scan_dir = tmp_workspaces / ws / "scans" / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)
    sess = {"status": "completed", "scan_type": "blackbox", "created_at": 1780000000.0,
            "web_url": "http://e", "repo_path": "/code", "owner": "web",
            "host_config": host_config}
    (scan_dir / "session.json").write_text(_json.dumps(sess))
    return scan_dir


def test_scan_detail_host_profile_ids_multi(authed_client, tmp_workspaces):
    """多选快照 → detail 回传 host_profile_ids 完整列表（重跑预填吃复数字段）。"""
    _detail_scan(tmp_workspaces, "WS", "bb-multi", {
        "enabled": True, "source": "profile",
        "profile_ids": ["host_p1", "host_p2"], "profile_id": "host_p1",
        "mappings": {"x.test": "10.0.0.1", "y.test": "10.0.0.2"},
    })
    d = authed_client.get("/api/workspaces/WS/scans/bb-multi").json()
    assert d["host_profile_ids"] == ["host_p1", "host_p2"]
    assert d["host_profile_id"] == "host_p1"
    assert d["host_source"] == "profile"
    assert d["host_mapping_count"] == 2


def test_scan_detail_host_profile_ids_legacy_single_fallback(authed_client, tmp_workspaces):
    """旧快照只有 profile_id（无 profile_ids）→ 回传包成 [profile_id]（前端统一吃数组）。"""
    _detail_scan(tmp_workspaces, "WS", "bb-legacy", {
        "enabled": True, "source": "profile", "profile_id": "host_p1",
        "mappings": {"x.test": "10.0.0.1"},
    })
    d = authed_client.get("/api/workspaces/WS/scans/bb-legacy").json()
    assert d["host_profile_ids"] == ["host_p1"]
    assert d["host_profile_id"] == "host_p1"


def test_scan_detail_host_profile_ids_url_source_empty(authed_client, tmp_workspaces):
    """url 源快照 → host_profile_ids == []（无档案，前端不预填档案模式）。"""
    _detail_scan(tmp_workspaces, "WS", "bb-url", {
        "enabled": True, "source": "url", "profile_id": None,
        "source_url": "https://h.test/get?id=1",
        "mappings": {"z.test": "10.0.0.9"},
    })
    d = authed_client.get("/api/workspaces/WS/scans/bb-url").json()
    assert d["host_profile_ids"] == []
    assert d["host_profile_id"] is None
    assert d["host_url"] == "https://h.test/get?id=1"


class _FakeBatchSM:
    def __init__(self):
        self.started = []

    async def start(self, req):
        self.started.append(req)
        return "WSX", f"scan-{len(self.started):04d}"

    def active_pids(self):
        return {}


def test_batch_scan_endpoint_threads_host_profile_ids(tmp_workspaces, monkeypatch):
    """POST /api/scan/batch body host_profile_ids → 逐仓 ScanRequest 透传。"""
    from fastapi.testclient import TestClient
    from supernova_web.app import create_app
    from supernova_web.components.ws_config_store import default_ws_config

    monkeypatch.setenv("SUPERNOVA_WORKER_ROOT", str(tmp_workspaces.parent))
    monkeypatch.setenv("SUPERNOVA_WEB_COOKIE_SECURE", "0")
    from supernova_web.auth.passwords import hash_password
    app = create_app(overrides={"scan_manager": _FakeBatchSM()})
    app.state.auth_store.create_user("admin", hash_password("test-pw"), role="admin")
    app.state.config.workspaces_dir.joinpath("WSX").mkdir(parents=True, exist_ok=True)
    cfg = default_ws_config()
    cfg.provider.api_key = "test-key"
    app.state.ws_config_store.write("WSX", cfg)

    c = TestClient(app)
    tok = c.get("/api/auth/csrf").json()["csrf_token"]
    c.post("/api/auth/login", json={"username": "admin", "password": "test-pw"},
           headers={"X-CSRF-Token": tok})
    r = c.post("/api/scan/batch", json={
        "workspace": "WSX", "repos": ["repo-a"], "url": "http://t",
        "host_profile_ids": ["host_p1", "host_p2"]},
        headers={"X-CSRF-Token": tok})
    assert r.status_code == 202, r.text
    fake = app.state.scan_manager
    assert len(fake.started) == 1
    assert fake.started[0].host_profile_ids == ["host_p1", "host_p2"]
