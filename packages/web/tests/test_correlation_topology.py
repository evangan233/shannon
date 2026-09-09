from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from supernova_web.components.topology_analysis import (
    TooManyTopologyAnalyses,
    TopologyAnalysisManager,
    TopologyAnalysisStore,
    TopologyValidationError,
)


def _make_repos(root: Path, ws: str = "ws1") -> dict[str, Path]:
    out: dict[str, Path] = {}
    for name in ("gateway", "order-svc", "user-svc", "slow"):
        path = root / "workspaces" / ws / "repos" / name
        (path / ".git").mkdir(parents=True, exist_ok=True)
        (path / "README.md").write_text(f"# {name}\n", encoding="utf-8")
        out[name] = path
    return out


@pytest.mark.asyncio
async def test_store_atomic_cache_recovery_and_cleanup(tmp_path):
    store = TopologyAnalysisStore(tmp_path / "workspaces")
    state = store.create("ws1", {
        "analysis_id": "topology-aaaaaaaaaaaa", "workspace": "ws1", "status": "running",
        "repos": ["a", "b"], "fingerprint": "f1", "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z", "progress": 10,
    })
    assert (tmp_path / "workspaces" / "ws1" / "correlation-topology" / "analyses" / "topology-aaaaaaaaaaaa" / "state.json").exists()
    assert store.get("ws1", "topology-aaaaaaaaaaaa") == state
    assert not list((tmp_path / "workspaces" / "ws1" / "correlation-topology" / "analyses" / "topology-aaaaaaaaaaaa").glob("*.tmp"))

    completed = dict(state, status="completed", updated_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))
    store.write(completed)
    assert store.find_cached("ws1", "f1", ttl_seconds=3600)["analysis_id"] == "topology-aaaaaaaaaaaa"
    assert store.find_cached("ws1", "f1", ttl_seconds=0) is None

    interrupted = store.recover_interrupted()
    # completed stays completed; now create a running orphan and recover it
    store.write(dict(state, analysis_id="topology-bbbbbbbbbbbb", status="queued", fingerprint="f2"))
    assert store.recover_interrupted() == ["topology-bbbbbbbbbbbb"]
    assert store.get("ws1", "topology-bbbbbbbbbbbb")["status"] == "interrupted"

    for i in range(12):
        store.write(dict(state, analysis_id=f"topology-{i:012x}", status="completed", fingerprint=f"f{i}"))
    store.cleanup(max_records=10)
    assert len(store.list("ws1")) == 10

    # Explicit history delete removes the whole analysis directory, including audit logs.
    audit_dir = store.path("ws1", "topology-aaaaaaaaaaaa")
    (audit_dir / "tool-audit.ndjson").write_text("{}", encoding="utf-8")
    assert store.remove("ws1", "topology-aaaaaaaaaaaa") is True
    assert store.get("ws1", "topology-aaaaaaaaaaaa") is None
    assert not audit_dir.exists()
    assert store.remove("ws1", "topology-aaaaaaaaaaaa") is False


@pytest.mark.parametrize("ws", ["__legacy__", "_internal", "中文空间", "ws-1", "a.b", "sp ace"])
def test_store_accepts_provisioner_legal_workspace_names(tmp_path, ws):
    # 回归 2026-09-03：存量迁移 ws `__legacy__` 通过正式校验 is_safe_workspace_name
    # （不以 . 开头即可），却被 store 的 _SAFE_WS 首字符规则拒绝 -> start_analysis
    # 未捕获 ValueError -> 500 纯文本 -> 前端 json() 失败后 fallback text() 抛
    # "body stream already read"。store 的 ws 校验不得严于正式校验。
    store = TopologyAnalysisStore(tmp_path / "workspaces")
    state = store.create(ws, {
        "analysis_id": "topology-aaaaaaaaaaaa", "workspace": ws, "status": "running",
        "repos": ["a", "b"], "fingerprint": "f1",
        "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z",
        "progress": 10,
    })
    assert store.get(ws, "topology-aaaaaaaaaaaa") == state
    assert [s["workspace"] for s in store.list(ws)] == [ws]
    completed = dict(state, status="completed",
                     updated_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))
    store.write(completed)
    assert store.find_cached(ws, "f1", ttl_seconds=3600)["analysis_id"] == "topology-aaaaaaaaaaaa"
    # recover_interrupted/cleanup 的目录扫描同样不得跳过此类 ws
    store.write(dict(state, analysis_id="topology-bbbbbbbbbbbb", status="queued", fingerprint="f2"))
    assert store.recover_interrupted() == ["topology-bbbbbbbbbbbb"]


@pytest.mark.parametrize("ws", ["", ".", "..", ".system", "../evil", "a/b", "a\\b", "bad\x7f", "ta\tb"])
def test_store_still_rejects_unsafe_workspace_names(tmp_path, ws):
    store = TopologyAnalysisStore(tmp_path / "workspaces")
    with pytest.raises(ValueError):
        store.create(ws, {"analysis_id": "topology-aaaaaaaaaaaa", "workspace": ws})


def test_store_ws_validation_agrees_with_provisioner():
    # 锁定两套校验一致（分叉即红）：store 判定 vs 正式校验 is_safe_workspace_name。
    from supernova_core.topology.store import _safe_ws
    from supernova_web.components.workspace_provisioner import is_safe_workspace_name
    names = ["__legacy__", "_x", "中文", "ws1", "-x", ".x", ".", "..", "", "a/b",
             "a\\b", "sp ace", "ta\tb", "x" * 64, "nul\x00", "del\x7f"]
    for name in names:
        assert _safe_ws(name) == is_safe_workspace_name(name), name


class _FakeHandle:
    """Fake WorkflowHandle：result() 挂在 future 上，测试控制完成/抛错/取消。"""

    def __init__(self, workflow_id: str, inp):
        self.id = workflow_id
        self.input = inp
        self.cancel_calls = 0
        self.cancelled = False
        self._done: asyncio.Future | None = None

    def _future(self) -> asyncio.Future:
        if self._done is None:
            self._done = asyncio.get_running_loop().create_future()
        return self._done

    async def result(self):
        if self.cancelled:
            raise asyncio.CancelledError()  # temporal cancel 后 await result() 即抛
        return await self._future()

    async def cancel(self):
        self.cancel_calls += 1
        self.cancelled = True
        fut = self._done
        if fut is not None and not fut.done():
            fut.cancel()

    async def describe(self):
        class _Desc:
            status = "RUNNING"
        return _Desc()


class _FakeTemporal:
    """Fake temporal client factory：记录提交、返回可控 handle。"""

    def __init__(self):
        self.submitted: list[tuple] = []
        self.fail_submit = False
        self.handles: dict[str, _FakeHandle] = {}

    async def connect(self):
        return self

    async def start_workflow(self, run, inp, *, id: str, task_queue: str):
        if self.fail_submit:
            raise RuntimeError("temporal unreachable")
        handle = _FakeHandle(id, inp)
        self.submitted.append((run, inp, id, task_queue))
        self.handles[id] = handle
        return handle

    def get_workflow_handle(self, workflow_id: str) -> _FakeHandle:
        # 默认：describe 成功 → workflow 视为在跑（recover 不打断）；测试按需覆盖
        return _FakeHandle(workflow_id, None)


def _finish(handle: _FakeHandle, value) -> None:
    handle._future().set_result(value)


@pytest.mark.asyncio
async def test_manager_submits_to_worker_and_completes(tmp_path, monkeypatch):
    # 迁移后核心链路（spec §4.3）：_start 保留全部前置（校验/manifest/fingerprint/
    # 缓存/store.create），执行段换 temporal 提交 bb 队列；终态由 worker activity
    # 写（此处 fake handle 模拟），web await result 后不重复写。
    _make_repos(tmp_path)
    temporal = _FakeTemporal()
    manager = TopologyAnalysisManager(
        tmp_path / "workspaces", repo_manager=None, temporal_client_factory=temporal.connect)
    analysis_id = await manager.start("ws1", ["gateway", "order-svc", "user-svc"])

    assert manager.get("ws1", analysis_id)["status"] == "queued"
    run, inp, wid, queue = temporal.submitted[0]
    assert wid == f"topo-ws1-{analysis_id}"
    assert queue == "supernova-bb-web"  # bb 队列 = 交互式轻任务的家（spec §3）
    assert inp.analysis_id == analysis_id and inp.ws == "ws1"
    assert inp.repos == ["gateway", "order-svc", "user-svc"]
    assert inp.repo_paths["gateway"].endswith("/repos/gateway")
    assert inp.manifest["repositories"] == ["gateway", "order-svc", "user-svc"]
    assert inp.workspaces_dir == str(manager._root)
    assert inp.timeout_seconds == manager.timeout_seconds
    assert inp.max_turns == manager.max_turns

    # 模拟 worker activity 写终态后 workflow 返回（时间戳须新鲜，缓存 TTL 判定用）
    state = manager.get("ws1", analysis_id)
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    state.update({"status": "completed", "progress": 100,
                  "updated_at": now, "completed_at": now})
    manager.store.write(state)
    _finish(temporal.handles[wid], {"status": "completed"})
    await manager.wait(analysis_id)
    completed = manager.get("ws1", analysis_id)
    assert completed["status"] == "completed"  # web 未复写终态

    # 缓存命中不重复提交（fingerprint 24h 缓存零变化）
    cached_id = await manager.start("ws1", ["user-svc", "gateway", "order-svc"])
    assert cached_id == analysis_id and len(temporal.submitted) == 1

    with pytest.raises(TopologyValidationError):
        await manager.start("ws1", ["gateway"])
    with pytest.raises(TopologyValidationError):
        await manager.start("ws1", ["gateway", "missing"])


@pytest.mark.asyncio
async def test_manager_start_ignores_dot_reserved_dirs(tmp_path):
    # workspaces 根下的 dot 保留段（.system=全局认证档案、.master_key 等）不是 ws：
    # _recover_orphans 首跑遍历目录名 → store.list('.system') 曾被 ws 名校验拒绝，
    # 抛 ValueError 落 route 兜底 422 invalid_workspace——进程首点"自动关联分析"
    # 必挂且 _recovered 不置位次次挂（2026-09-03 admin ws 实证）。对齐
    # workspaces_indexer 的 dot-dir 约定：保留段不进 ws 名单。
    _make_repos(tmp_path)
    reserved = tmp_path / "workspaces" / ".system"
    reserved.mkdir()
    (reserved / "auth-profiles.yaml").write_text("profiles: []\n", encoding="utf-8")
    temporal = _FakeTemporal()
    manager = TopologyAnalysisManager(
        tmp_path / "workspaces", repo_manager=None, temporal_client_factory=temporal.connect)
    analysis_id = await manager.start("ws1", ["gateway", "order-svc"])
    assert manager.get("ws1", analysis_id)["status"] == "queued"
    assert len(temporal.submitted) == 1


@pytest.mark.asyncio
async def test_manager_submit_failure_fails_analysis(tmp_path):
    # temporal 不可达（提交失败）→ 写 failed/provider_failed 终态并返回 id——
    # 前端轮询即见失败，用户重跑（spec：失败重跑哲学，不自动重试）。
    _make_repos(tmp_path)
    temporal = _FakeTemporal()
    temporal.fail_submit = True
    manager = TopologyAnalysisManager(
        tmp_path / "workspaces", repo_manager=None, temporal_client_factory=temporal.connect)
    analysis_id = await manager.start("ws1", ["gateway", "order-svc"])
    await manager.wait(analysis_id)
    failed = manager.get("ws1", analysis_id)
    assert failed["status"] == "failed"
    assert failed["error"]["code"] == "provider_failed"
    assert "temporal" in failed["error"]["message"]


@pytest.mark.asyncio
async def test_manager_workflow_failure_fails_active_analysis(tmp_path):
    # workflow 失败（worker 崩溃 / activity 未写终态）→ web await 兜底写 failed，
    # state 不卡 running（spec §4.3 兜底路径）。
    _make_repos(tmp_path)
    temporal = _FakeTemporal()
    manager = TopologyAnalysisManager(
        tmp_path / "workspaces", repo_manager=None, temporal_client_factory=temporal.connect)
    analysis_id = await manager.start("ws1", ["gateway", "order-svc"])
    wid = f"topo-ws1-{analysis_id}"
    state = manager.get("ws1", analysis_id)
    state.update({"status": "running", "progress": 20})
    manager.store.write(state)
    temporal.handles[wid]._future().set_exception(RuntimeError("worker crashed"))
    await manager.wait(analysis_id)
    failed = manager.get("ws1", analysis_id)
    assert failed["status"] == "failed"
    assert failed["error"]["code"] == "provider_failed"
    assert "worker crashed" in failed["error"]["message"]


@pytest.mark.asyncio
async def test_manager_cancel_writes_terminal_before_handle_cancel(tmp_path):
    # cancel 顺序锁定：先写 cancelled 终态再 handle.cancel()（worker 侧 status
    # guard 据此跳过晚到结果，spec R2）。
    _make_repos(tmp_path)
    temporal = _FakeTemporal()
    manager = TopologyAnalysisManager(
        tmp_path / "workspaces", repo_manager=None, temporal_client_factory=temporal.connect)
    analysis_id = await manager.start("ws1", ["gateway", "order-svc"])
    wid = f"topo-ws1-{analysis_id}"
    state = manager.get("ws1", analysis_id)
    state.update({"status": "running", "progress": 20})
    manager.store.write(state)

    cancelled = await manager.cancel("ws1", analysis_id)
    assert cancelled["status"] == "cancelled"
    assert cancelled["error"]["code"] == "cancelled"
    assert temporal.handles[wid].cancel_calls == 1
    await manager.wait(analysis_id)  # cancel 是终态：wait 正常返回（不向 caller 抛）
    # cancel 后并发槽释放：下一个分析能提交
    next_id = await manager.start("ws1", ["gateway", "order-svc"], refresh=True)
    assert manager.get("ws1", next_id)["status"] == "queued"


@pytest.mark.asyncio
async def test_manager_concurrency_gate_reads_store(tmp_path):
    # 跨进程后并发门必须读 store（web 重启内存归零但 worker 仍在跑，spec §4.3）。
    _make_repos(tmp_path)
    store = TopologyAnalysisStore(tmp_path / "workspaces")
    store.create("ws1", {
        "analysis_id": "topology-cccccccccccc", "workspace": "ws1", "status": "running",
        "repos": ["gateway", "order-svc"], "fingerprint": "f",
        "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z",
    })
    temporal = _FakeTemporal()
    manager = TopologyAnalysisManager(
        tmp_path / "workspaces", repo_manager=None, temporal_client_factory=temporal.connect)
    assert manager._active_count == 1  # 从 store 数出 running
    with pytest.raises(TooManyTopologyAnalyses):
        await manager.start("ws1", ["gateway", "order-svc"])


@pytest.mark.asyncio
async def test_manager_restart_leaves_worker_running_analysis_alone(tmp_path):
    # recover 语义修正（spec §4.3，行为变更正向）：running 的执行者是 worker——
    # web 重启不得标 interrupted；queued 且 temporal 查无 workflow 的孤儿才清。
    _make_repos(tmp_path)
    store = TopologyAnalysisStore(tmp_path / "workspaces")
    store.create("ws1", {
        "analysis_id": "topology-cccccccccccc", "workspace": "ws1", "status": "running",
        "repos": ["gateway", "order-svc"], "fingerprint": "f",
        "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z",
    })
    store.create("ws1", {
        "analysis_id": "topology-dddddddddddd", "workspace": "ws1", "status": "queued",
        "repos": ["gateway", "order-svc"], "fingerprint": "f2",
        "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z",
    })
    temporal = _FakeTemporal()

    class _MissingWorkflowHandle:
        async def describe(self):
            raise KeyError("workflow not found")  # queued 孤儿：temporal 查无此 workflow

    def get_workflow_handle(workflow_id: str):
        if workflow_id == "topo-ws1-topology-dddddddddddd":
            return _MissingWorkflowHandle()
        return _FakeHandle(workflow_id, None)  # running：workflow 在跑

    temporal.get_workflow_handle = get_workflow_handle
    manager = TopologyAnalysisManager(
        tmp_path / "workspaces", repo_manager=None, temporal_client_factory=temporal.connect)
    # 首次 _start 触发 recover：running 不打断（worker 仍占并发槽），queued 孤儿清
    running_state = store.get("ws1", "topology-cccccccccccc")
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    running_state.update({"status": "completed", "progress": 100,
                          "updated_at": now, "completed_at": now})  # 模拟 worker 跑完腾出槽位
    store.write(running_state)
    await manager.start("ws1", ["gateway", "order-svc"])
    assert manager.get("ws1", "topology-cccccccccccc")["status"] == "completed"  # 未被打断
    assert manager.get("ws1", "topology-dddddddddddd")["status"] == "interrupted"  # 孤儿清


@pytest.mark.asyncio
async def test_api_delete_history_removes_terminal_analysis(authed_client, tmp_path):
    """/delete 真删历史档案；旧 DELETE 仍保持取消语义，active 删除拒绝 409。"""
    app = authed_client.app
    store = TopologyAnalysisStore(tmp_path / "workspaces")
    app.state.topology_manager = TopologyAnalysisManager(
        tmp_path / "workspaces", repo_manager=None)
    csrf = authed_client.get("/api/auth/csrf").json()["csrf_token"]

    def _state(aid: str, status: str) -> dict:
        return {"analysis_id": aid, "workspace": "ws1", "status": status,
                "repos": ["a", "b"], "fingerprint": aid,
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z", "progress": 100}

    completed = _state("topology-00000000000a", "completed")
    store.create("ws1", completed)
    audit = store.path("ws1", completed["analysis_id"]) / "tool-audit.ndjson"
    audit.write_text("{}", encoding="utf-8")
    active = _state("topology-00000000000b", "running")
    store.create("ws1", active)

    url = "/api/workspaces/ws1/correlation-topology/analyses/topology-00000000000a/delete"
    assert authed_client.post(url, headers={"X-CSRF-Token": csrf}).status_code == 200
    assert store.get("ws1", completed["analysis_id"]) is None
    assert not audit.exists()
    assert authed_client.post(url, headers={"X-CSRF-Token": csrf}).status_code == 404

    active_url = "/api/workspaces/ws1/correlation-topology/analyses/topology-00000000000b/delete"
    r = authed_client.post(active_url, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "analysis_active"
    assert store.get("ws1", active["analysis_id"]) is not None
    # Legacy DELETE is cancel, not delete.
    cancel_url = "/api/workspaces/ws1/correlation-topology/analyses/topology-00000000000b"
    r = authed_client.delete(cancel_url, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200 and r.json()["status"] == "cancelled"
    assert store.get("ws1", active["analysis_id"]) is not None


@pytest.mark.asyncio
async def test_api_start_invalid_workspace_returns_422_not_500(authed_client, tmp_path):
    # 回归 2026-09-03：store 层 ValueError（ws 名不合法路径）曾未被端点捕获 ->
    # 500 纯文本 -> 前端只见 "body stream already read"。须转 422 JSON 且 body
    # 可解析，前端才拿得到 code/message。（auth 依赖层先按 is_safe_workspace_name
    # 拦真非法名，此处 stub 触达的是「过 auth 但 store 拒」的残余分叉面——defense
    # in depth：即使未来再分叉也不许 500。）
    app = authed_client.app
    # global admin 直通 workspace_member，无需建 ws 目录/成员关系
    class RaisingManager(TopologyAnalysisManager):
        async def start(self, ws, repos, refresh=False):
            raise ValueError(f"invalid workspace: {ws!r}")

    app.state.topology_manager = RaisingManager(
        tmp_path / "workspaces", repo_manager=None)
    csrf = authed_client.get("/api/auth/csrf").json()["csrf_token"]
    bad = authed_client.post(
        "/api/workspaces/ws1/correlation-topology/analyses",
        json={"repos": ["gateway", "order-svc"]},
        headers={"X-CSRF-Token": csrf},
    )
    assert bad.status_code == 422
    assert bad.json()["detail"]["code"] == "invalid_workspace"


@pytest.mark.asyncio
async def test_api_lifecycle_errors_auth_and_no_scan_side_effects(authed_client, tmp_path):
    app = authed_client.app
    _make_repos(tmp_path)
    temporal = _FakeTemporal()

    class Manager(TopologyAnalysisManager):
        async def _resolve_repo_path(self, ws: str, name: str) -> Path:
            return tmp_path / "workspaces" / ws / "repos" / name

    app.state.topology_manager = Manager(
        tmp_path / "workspaces", repo_manager=app.state.repo_manager,
        temporal_client_factory=temporal.connect)
    csrf = authed_client.get("/api/auth/csrf").json()["csrf_token"]
    created = authed_client.post(
        "/api/workspaces/ws1/correlation-topology/analyses",
        json={"repos": ["gateway", "order-svc", "user-svc"]},
        headers={"X-CSRF-Token": csrf},
    )
    assert created.status_code == 202
    analysis_id = created.json()["analysis_id"]
    # 模拟 worker 写终态（api 层测试只关心 API 契约：直接写 completed state）
    state = app.state.topology_manager.get("ws1", analysis_id)
    state.update({"status": "completed", "progress": 100,
                  "result": {"edges": [], "nodes": [], "raw": None}})
    app.state.topology_manager.store.write(state)
    state = authed_client.get(f"/api/workspaces/ws1/correlation-topology/analyses/{analysis_id}").json()
    assert state["status"] == "completed"
    assert "manifest" not in state
    assert "repo_paths" not in state
    assert "raw_output" not in state
    assert not (tmp_path / "workspaces" / "ws1" / "scans").exists()

    bad = authed_client.post(
        "/api/workspaces/ws1/correlation-topology/analyses",
        json={"repos": ["gateway"]}, headers={"X-CSRF-Token": csrf},
    )
    assert bad.status_code == 422
    assert bad.json()["detail"]["code"] == "invalid_repositories"
    assert authed_client.get("/api/workspaces/ws1/correlation-topology/analyses/missing").status_code == 404
    cancelled = authed_client.delete(
        f"/api/workspaces/ws1/correlation-topology/analyses/{analysis_id}",
        headers={"X-CSRF-Token": csrf},
    )
    assert cancelled.status_code == 200
    assert "repo_paths" not in cancelled.json()
    assert "manifest" not in cancelled.json()

    # A non-member ordinary user cannot read another workspace's analysis.
    from supernova_web.auth.passwords import hash_password
    app.state.auth_store.create_user("outsider", hash_password(" outsider-pw"), role="user")
    outsider = TestClient(app)
    token = outsider.get("/api/auth/csrf").json()["csrf_token"]
    outsider.post("/api/auth/login", json={"username": "outsider", "password": " outsider-pw"},
                  headers={"X-CSRF-Token": token})
    response = outsider.get(f"/api/workspaces/ws1/correlation-topology/analyses/{analysis_id}")
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_manager_ignores_system_workspace_directory(tmp_path):
    """跨仓自动关联 422 回归：`.system` 是全局存储目录，不是 workspace。

    `_workspace_names()` 若把它交给 topology store，`list('.system')` 会被
    `_safe_ws` 拒绝并抛 ValueError，API 兜底成 422。恢复/并发扫描必须跳过。
    """
    _make_repos(tmp_path)
    system_dir = tmp_path / "workspaces" / ".system"
    system_dir.mkdir()
    (system_dir / "auth-profiles.yaml").write_text("profiles: []\n", encoding="utf-8")
    temporal = _FakeTemporal()
    manager = TopologyAnalysisManager(
        tmp_path / "workspaces", repo_manager=None, temporal_client_factory=temporal.connect)

    assert manager._workspace_names() == ["ws1"]
    analysis_id = await manager.start("ws1", ["gateway", "order-svc"])

    assert manager.get("ws1", analysis_id)["status"] == "queued"
    assert len(temporal.submitted) == 1


def _write_audit(store: TopologyAnalysisStore, ws: str, analysis_id: str, lines: list[dict]) -> None:
    """模拟 worker 的 _NdjsonToolAuditLogger 落盘 tool-audit.ndjson。"""
    state_dir = store.path(ws, analysis_id)
    state_dir.mkdir(parents=True, exist_ok=True)
    import json as _json
    payload = "".join(_json.dumps({"ts": "2026-09-03T18:00:00Z", **line},
                                  ensure_ascii=False, separators=(",", ":")) + "\n"
                      for line in lines)
    (state_dir / "tool-audit.ndjson").write_text(payload, encoding="utf-8")


@pytest.mark.asyncio
async def test_api_analysis_log_tail_incremental_and_summarized(authed_client, tmp_path):
    # 过程日志端点：after 行号游标增量、服务端裁剪摘要（result/parameters 不回传全文）。
    app = authed_client.app
    store = TopologyAnalysisStore(tmp_path / "workspaces")
    store.create("ws1", {
        "analysis_id": "topology-aaaaaaaaaaaa", "workspace": "ws1", "status": "running",
        "repos": ["a", "b"], "fingerprint": "f1",
        "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z",
        "progress": 20,
    })
    _write_audit(store, "ws1", "topology-aaaaaaaaaaaa", [
        {"type": "tool_start", "tool": "read_file", "parameters": "{'path': '/repos/gw/main.go'}"},
        {"type": "tool_end", "result": "x" * 500},  # 长 result 必须被裁剪
        {"type": "assistant_turn", "turn": 3, "content": "找到 gateway 调用 identity"},
        {"type": "error", "error": "boom"},
    ])
    app.state.topology_manager = TopologyAnalysisManager(
        tmp_path / "workspaces", repo_manager=None)

    r = authed_client.get("/api/workspaces/ws1/correlation-topology/analyses/topology-aaaaaaaaaaaa/log")
    assert r.status_code == 200
    body = r.json()
    assert [line["no"] for line in body["lines"]] == [0, 1, 2, 3]
    assert body["next"] == 3
    kinds = [line["type"] for line in body["lines"]]
    assert kinds == ["tool_start", "tool_end", "assistant_turn", "error"]
    assert body["lines"][0]["tool"] == "read_file"
    assert "main.go" in body["lines"][0]["summary"]
    assert len(body["lines"][1]["summary"]) <= 121  # 裁剪上限 120 + 省略号
    assert "identity" in body["lines"][2]["summary"]
    assert body["lines"][3]["summary"] == "boom"

    # 游标增量：只要 after 之后的行
    r2 = authed_client.get(
        "/api/workspaces/ws1/correlation-topology/analyses/topology-aaaaaaaaaaaa/log?after=2")
    assert [line["no"] for line in r2.json()["lines"]] == [3]
    assert r2.json()["next"] == 3

    # analysis 不存在 → 404（与 get_analysis 同语义）
    assert authed_client.get(
        "/api/workspaces/ws1/correlation-topology/analyses/topology-zzzzzzzzzzzz/log").status_code == 404

    # 无日志文件（分析未启动）→ 空行而非 404
    store.create("ws1", {
        "analysis_id": "topology-bbbbbbbbbbbb", "workspace": "ws1", "status": "queued",
        "repos": ["a", "b"], "fingerprint": "f2",
        "created_at": "2026-01-02T00:00:00Z", "updated_at": "2026-01-02T00:00:00Z",
        "progress": 5,
    })
    r3 = authed_client.get(
        "/api/workspaces/ws1/correlation-topology/analyses/topology-bbbbbbbbbbbb/log")
    assert r3.status_code == 200 and r3.json()["lines"] == [] and r3.json()["next"] == -1


@pytest.mark.asyncio
async def test_api_latest_analysis_for_refresh_recovery(authed_client, tmp_path):
    # 刷新恢复端点：最近一条（created_at 降序）；无记录 404；路径不得被
    # /analyses/{analysis_id} 动态段吞掉（latest 必须先注册）。
    app = authed_client.app
    store = TopologyAnalysisStore(tmp_path / "workspaces")
    app.state.topology_manager = TopologyAnalysisManager(
        tmp_path / "workspaces", repo_manager=None)
    assert authed_client.get(
        "/api/workspaces/ws1/correlation-topology/analyses/latest").status_code == 404

    def _state(aid: str, status: str, created: str) -> dict:
        return {"analysis_id": aid, "workspace": "ws1", "status": status,
                "repos": ["a", "b"], "fingerprint": aid,
                "created_at": created, "updated_at": created, "progress": 100}

    store.create("ws1", _state("topology-00000000000a", "completed", "2026-01-01T00:00:00Z"))
    store.create("ws1", _state("topology-00000000000b", "running", "2026-01-02T00:00:00Z"))
    r = authed_client.get("/api/workspaces/ws1/correlation-topology/analyses/latest")
    assert r.status_code == 200
    assert r.json()["analysis_id"] == "topology-00000000000b"
    assert r.json()["status"] == "running"


@pytest.mark.asyncio
async def test_api_list_analyses_history(authed_client, tmp_path):
    # 分析历史列表（摘要）：created_at 降序；只带历史行渲染所需摘要字段——
    # result/usage/error 大字段不下发（单条 {analysis_id} 才拉全量）。
    app = authed_client.app
    store = TopologyAnalysisStore(tmp_path / "workspaces")
    app.state.topology_manager = TopologyAnalysisManager(
        tmp_path / "workspaces", repo_manager=None)

    r = authed_client.get("/api/workspaces/ws1/correlation-topology/analyses")
    assert r.status_code == 200 and r.json() == []

    def _state(aid: str, status: str, created: str, repos: list[str],
               result: dict | None = None, ws: str = "ws1") -> dict:
        state = {"analysis_id": aid, "workspace": ws, "status": status,
                 "repos": repos, "fingerprint": aid,
                 "created_at": created, "updated_at": created, "progress": 100,
                 "cache_hit": False}
        if result is not None:
            state["result"] = result
        return state

    store.create("ws1", _state("topology-00000000000a", "completed", "2026-01-01T00:00:00Z",
                               ["a", "b"], {"nodes": [], "edges": [], "uncertain": [], "coverage": []}))
    store.create("ws1", _state("topology-00000000000b", "failed", "2026-01-03T00:00:00Z", ["c", "d"]))
    store.create("ws2", _state("topology-00000000000c", "completed", "2026-01-02T00:00:00Z",
                               ["x", "y"], ws="ws2"))

    r = authed_client.get("/api/workspaces/ws1/correlation-topology/analyses")
    assert r.status_code == 200
    body = r.json()
    assert [a["analysis_id"] for a in body] == ["topology-00000000000b", "topology-00000000000a"]
    assert body[0]["repos"] == ["c", "d"] and body[0]["status"] == "failed"
    for a in body:
        assert not a.get("result") and not a.get("usage") and not a.get("error")

    # 单条仍带 result（选中历史后前端拉全量重建拓扑）
    r2 = authed_client.get(
        "/api/workspaces/ws1/correlation-topology/analyses/topology-00000000000a")
    assert r2.status_code == 200 and r2.json()["result"] is not None
