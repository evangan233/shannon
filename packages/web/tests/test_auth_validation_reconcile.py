"""reconcile_auth_validation 启动对账：watcher 随旧 web 进程死亡后，verify_status=running
的凭据成永久孤儿（batch 前端不轮询 verify-status → 页面永久卡"测试中"，2026-08-17 根因）。
对齐 scan 的 reconcile_orphaned 语义：终态补结案、在跑重挂跟踪、查不到判 failed。"""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from supernova_web.components.auth_profile_store import (
    AuthProfile, AuthProfileCredential, AuthProfileStore, VerifyStatus)
from supernova_web.components.credential_vault import CredentialVault
from supernova_web.components.scan_manager import ScanManager


def _desc(status):
    d = MagicMock()
    d.status = status
    return d


def _client_with_handle(handle):
    client = MagicMock()
    client.get_workflow_handle = MagicMock(return_value=handle)
    return client, handle


def _recovery_client(desc_status=None, result=None):
    """describe 返回指定状态(或抛) + result 返回值(或抛) 的 client/handle。"""
    handle = MagicMock()
    handle.describe = (AsyncMock(return_value=desc_status)
                       if not isinstance(desc_status, Exception)
                       else AsyncMock(side_effect=desc_status))
    handle.result = (AsyncMock(return_value=result)
                     if not isinstance(result, Exception)
                     else AsyncMock(side_effect=result))
    return _client_with_handle(handle)


def _store_with_running(tmp_path, workflow_id, probe_dir, state="running"):
    vault = CredentialVault(tmp_path / ".master.key")
    s = AuthProfileStore(tmp_path, vault)
    s.write("ws1", [AuthProfile(
        id="prof_1", name="NG", login_url="http://t/", login_type="form",
        credentials=[
            AuthProfileCredential(
                id="cred_a", role="admin", username="admin", password="pw",
                verify_status=VerifyStatus(
                    state=state, workflow_id=workflow_id, probe_dir=str(probe_dir))),
            # 对照组：非 running 不动
            AuthProfileCredential(id="cred_b", role="user", username="user1", password="pw"),
        ])])
    return s


def _mgr(tmp_path, store):
    return ScanManager(
        workspaces_dir=tmp_path, repos_dir=tmp_path / "repos", config_store=MagicMock(),
        scan_timeout=0.0, ws_config_store=MagicMock(),
        auth_profile_store=store,
    )


def _probe(tmp_path, name="probe-a"):
    probe = tmp_path / "ws1" / "auth-probes" / name
    probe.mkdir(parents=True)
    (probe / "scan-config.yaml").write_text("authentication: {}", "utf-8")
    (probe / "events.ndjson").write_text('{"i":1}\n', "utf-8")
    return probe


@pytest.mark.asyncio
async def test_reconcile_backfills_completed_batch_workflow(tmp_path):
    """running + batch workflow 已 COMPLETED（result=per-cred list）→ 回填真实终态。
    生产卡死同款场景：单 cred batch，watcher 已死，状态停在 running。"""
    from temporalio.client import WorkflowExecutionStatus
    probe = _probe(tmp_path)
    wf = "authval-batch-ws1-deadbeef"
    store = _store_with_running(tmp_path, wf, probe)
    mgr = _mgr(tmp_path, store)
    client, _ = _recovery_client(
        desc_status=_desc(WorkflowExecutionStatus.COMPLETED),
        result=[{"cred_id": "cred_a", "state": "success"}])
    with patch("supernova_web.components.scan_manager.Client") as ClientCls:
        ClientCls.connect = AsyncMock(return_value=client)
        n = await mgr.reconcile_auth_validation()
    assert n == 1
    by_id = {c.id: c for c in store.read("ws1")[0].credentials}
    assert by_id["cred_a"].verify_status.state == "success"
    assert by_id["cred_b"].verify_status.state == "unverified"  # 对照组不动


@pytest.mark.asyncio
async def test_reconcile_backfills_completed_single_workflow(tmp_path):
    """running + 单 cred workflow 已 COMPLETED（result=AuthValidationResult 语义）→ 回填。"""
    from temporalio.client import WorkflowExecutionStatus
    probe = _probe(tmp_path)
    wf = "authval-ws1-probe-abcd1234"
    store = _store_with_running(tmp_path, wf, probe)
    mgr = _mgr(tmp_path, store)
    client, _ = _recovery_client(
        desc_status=_desc(WorkflowExecutionStatus.COMPLETED),
        result={"success": True})
    with patch("supernova_web.components.scan_manager.Client") as ClientCls:
        ClientCls.connect = AsyncMock(return_value=client)
        n = await mgr.reconcile_auth_validation()
    assert n == 1
    by_id = {c.id: c for c in store.read("ws1")[0].credentials}
    assert by_id["cred_a"].verify_status.state == "success"


@pytest.mark.asyncio
async def test_reconcile_marks_failed_when_workflow_missing(tmp_path):
    """workflow 查不到（Temporal 历史被清/误删）→ running 永无终态，判 failed/out_of_band。"""
    probe = _probe(tmp_path)
    wf = "authval-batch-ws1-gone11111"
    store = _store_with_running(tmp_path, wf, probe)
    mgr = _mgr(tmp_path, store)
    # describe 也抛（workflow 不存在）
    client, _ = _recovery_client(desc_status=Exception("workflow not found"))
    with patch("supernova_web.components.scan_manager.Client") as ClientCls:
        ClientCls.connect = AsyncMock(return_value=client)
        n = await mgr.reconcile_auth_validation()
    assert n == 1
    by_id = {c.id: c for c in store.read("ws1")[0].credentials}
    vs = by_id["cred_a"].verify_status
    assert vs.state == "failed"
    assert vs.failure_point == "out_of_band"


@pytest.mark.asyncio
async def test_reconcile_respawns_watcher_for_running_batch(tmp_path):
    """workflow 仍 RUNNING（重启时验证真在跑）→ 重挂 watcher 续跟，而非留孤儿。"""
    from temporalio.client import WorkflowExecutionStatus
    probe = _probe(tmp_path)
    wf = "authval-batch-ws1-live12345"
    store = _store_with_running(tmp_path, wf, probe)
    mgr = _mgr(tmp_path, store)
    client, _ = _recovery_client(desc_status=_desc(WorkflowExecutionStatus.RUNNING))
    with patch("supernova_web.components.scan_manager.Client") as ClientCls, \
         patch.object(mgr, "_watch_batch_progress", new=AsyncMock()) as watch:
        ClientCls.connect = AsyncMock(return_value=client)
        await mgr.reconcile_auth_validation()
        await asyncio.sleep(0)  # 让 create_task 起跑
    watch.assert_awaited_once()
    args = watch.await_args
    assert args.args[2] == wf
    assert "cred_a" in args.args[3]
    # 状态保持 running（交给重挂的 watcher 回填）
    by_id = {c.id: c for c in store.read("ws1")[0].credentials}
    assert by_id["cred_a"].verify_status.state == "running"


@pytest.mark.asyncio
async def test_reconcile_follows_running_single_workflow(tmp_path):
    """单 cred workflow 仍 RUNNING → 起有界轮询 task 续跟（不阻塞启动）。"""
    from temporalio.client import WorkflowExecutionStatus
    probe = _probe(tmp_path)
    wf = "authval-ws1-probe-live1234"
    store = _store_with_running(tmp_path, wf, probe)
    mgr = _mgr(tmp_path, store)
    client, _ = _recovery_client(desc_status=_desc(WorkflowExecutionStatus.RUNNING))
    with patch("supernova_web.components.scan_manager.Client") as ClientCls, \
         patch.object(mgr, "_follow_single_auth_validation", new=AsyncMock()) as follow:
        ClientCls.connect = AsyncMock(return_value=client)
        await mgr.reconcile_auth_validation()
        await asyncio.sleep(0)
    follow.assert_awaited_once()


@pytest.mark.asyncio
async def test_reconcile_skips_out_of_scope_workflow_id(tmp_path):
    """workflow_id 不带本 ws 前缀（异常状态）→ 跳过不动，不猜终态。"""
    probe = _probe(tmp_path)
    store = _store_with_running(tmp_path, "authval-ws2-evil00001", probe)
    mgr = _mgr(tmp_path, store)
    client = MagicMock()
    with patch("supernova_web.components.scan_manager.Client") as ClientCls:
        ClientCls.connect = AsyncMock(return_value=client)
        n = await mgr.reconcile_auth_validation()
    assert n == 0
    client.get_workflow_handle.assert_not_called()
    by_id = {c.id: c for c in store.read("ws1")[0].credentials}
    assert by_id["cred_a"].verify_status.state == "running"


@pytest.mark.asyncio
async def test_reconcile_no_store_is_noop(tmp_path):
    """auth_profile_store 未注入 → no-op 返 0（对齐 start_batch 守卫）。"""
    mgr = ScanManager(tmp_path, tmp_path / "repos", MagicMock())
    assert await mgr.reconcile_auth_validation() == 0
