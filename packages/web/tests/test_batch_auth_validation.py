"""scan_manager 档案级批量认证验证:选 cred 子集 / 各建 probe / 起 BatchAuthValidationWorkflow /
写首 cred running / 起 watcher(Slice 3) / cred_id 越界守护。语义=逐个独立验证(spec §2)。"""
import asyncio

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from supernova_web.components.auth_profile_store import (
    AuthProfileStore, AuthProfile, AuthProfileCredential,
)
from supernova_web.components.credential_vault import CredentialVault
from supernova_web.components.scan_manager import ScanManager


def _multi_store(tmp_path):
    """3 角色 profile(admin/user/guest)。"""
    vault = CredentialVault(tmp_path / ".master.key")
    s = AuthProfileStore(tmp_path, vault)
    s.write("ws1", [AuthProfile(
        id="prof_1", name="NG", login_url="http://t/", login_type="form",
        credentials=[
            AuthProfileCredential(id="cred_a", role="admin", username="admin", password="pw"),
            AuthProfileCredential(id="cred_b", role="user", username="user1", password="pw"),
            AuthProfileCredential(id="cred_c", role="guest", username="guest", password="pw"),
        ])])
    return s


def _mgr(tmp_path, store):
    # ws_config_store 不传（None → _resolve_provider_config 走全局 env 兜底构造，
    # 测试关注 batch 编排而非 provider 解析——不降级行为另有专测）。
    return ScanManager(
        workspaces_dir=tmp_path, repos_dir=tmp_path / "repos", config_store=MagicMock(),
        scan_timeout=0.0,
        auth_profile_store=store,
    )


def _patch_client(handle_id="authval-batch-ws1-abc12345"):
    fake_handle = MagicMock()
    fake_handle.id = handle_id
    client = MagicMock()
    client.start_workflow = AsyncMock(return_value=fake_handle)
    return client, fake_handle


@pytest.mark.asyncio
async def test_start_batch_full_selection_creates_probe_per_cred(tmp_path):
    """全选(cred_ids None)→ 为每个 cred 建 probe_dir + scan-config.yaml + 起 batch workflow + 起 watcher。"""
    store = _multi_store(tmp_path)
    mgr = _mgr(tmp_path, store)
    client, handle = _patch_client()
    with patch("supernova_web.components.scan_manager.Client") as ClientCls, \
         patch.object(mgr, "_watch_batch_progress", new=AsyncMock()) as watch:
        ClientCls.connect = AsyncMock(return_value=client)
        result = await mgr.start_batch_auth_validation("ws1", "prof_1", None)
    assert result["workflow_id"] == handle.id
    # 3 个 probe(scan-config.yaml),每 probe 含对应 username
    probes = sorted((tmp_path / "ws1" / "auth-probes").glob("*/scan-config.yaml"))
    assert len(probes) == 3
    bodies = "||".join(p.read_text("utf-8") for p in probes)
    assert "admin" in bodies and "user1" in bodies and "guest" in bodies
    # 起 BatchAuthValidationWorkflow(传 items=3)
    sent_input = client.start_workflow.call_args.args[1]
    assert len(sent_input.items) == 3
    # watcher 被起
    assert watch.called


@pytest.mark.asyncio
async def test_start_batch_subset_only_selected_creds(tmp_path):
    """cred_ids 子集 → 只为选中的建 probe(未选的不建)。"""
    store = _multi_store(tmp_path)
    mgr = _mgr(tmp_path, store)
    client, _ = _patch_client()
    with patch("supernova_web.components.scan_manager.Client") as ClientCls, \
         patch.object(mgr, "_watch_batch_progress", new=AsyncMock()):
        ClientCls.connect = AsyncMock(return_value=client)
        await mgr.start_batch_auth_validation("ws1", "prof_1", ["cred_a", "cred_c"])
    probes = list((tmp_path / "ws1" / "auth-probes").glob("*/scan-config.yaml"))
    assert len(probes) == 2
    bodies = "||".join(p.read_text("utf-8") for p in probes)
    assert "admin" in bodies and "guest" in bodies and "user1" not in bodies
    sent_input = client.start_workflow.call_args.args[1]
    assert [it.cred_id for it in sent_input.items] == ["cred_a", "cred_c"]


@pytest.mark.asyncio
async def test_start_batch_provider_incomplete_no_degrade(tmp_path):
    """测试登录不降级（2026-08-17）：工作区模型配置缺失/错误 → 直接抛 ProviderConfigIncomplete，
    不 env 兜底、不起 batch workflow、不删旧 probe、不写任何明文 scan-config.yaml。"""
    from supernova_web.components.auth_profile_store import VerifyStatus
    from supernova_web.components.ws_config_store import ProviderConfigIncomplete

    store = _multi_store(tmp_path)
    old_probe = tmp_path / "ws1" / "auth-probes" / "probe-old"
    old_probe.mkdir(parents=True)
    (old_probe / "events.ndjson").write_text('{"old":1}', "utf-8")
    store.set_verify_status("ws1", "prof_1", "cred_a", VerifyStatus(
        state="failed", probe_dir=str(old_probe), workflow_id="authval-batch-ws1-old"))
    mgr = _mgr(tmp_path, store)
    client, _ = _patch_client()

    def _raise(ws):
        raise ProviderConfigIncomplete(["SUPERNOVA_OPENAI_API_KEY"])

    with patch("supernova_web.components.scan_manager.Client") as ClientCls, \
         patch.object(mgr, "_resolve_provider_config", side_effect=_raise), \
         patch.object(mgr, "_watch_batch_progress", new=AsyncMock()) as watch:
        ClientCls.connect = AsyncMock(return_value=client)
        with pytest.raises(ProviderConfigIncomplete):
            await mgr.start_batch_auth_validation("ws1", "prof_1", None)

    client.start_workflow.assert_not_awaited(), "配置错误时不应起 batch workflow"
    assert not watch.called, "配置错误时不应起 watcher"
    assert old_probe.exists(), "配置错误时不应删旧 probe"
    assert not list((tmp_path / "ws1" / "auth-probes").glob("probe-*/scan-config.yaml")), \
        "配置错误时不应写任何明文 scan-config.yaml"


@pytest.mark.asyncio
async def test_start_batch_rejects_cred_id_not_in_profile(tmp_path):
    """cred_ids 含不属于该 profile 的 id → ValueError(防注入任意 id 越界)。"""
    store = _multi_store(tmp_path)
    mgr = _mgr(tmp_path, store)
    client, _ = _patch_client()
    with patch("supernova_web.components.scan_manager.Client") as ClientCls, \
         patch.object(mgr, "_watch_batch_progress", new=AsyncMock()):
        ClientCls.connect = AsyncMock(return_value=client)
        with pytest.raises(ValueError, match="不属于"):
            await mgr.start_batch_auth_validation("ws1", "prof_1", ["cred_a", "cred_evil"])
    # 不应起任何 probe / workflow
    assert not list((tmp_path / "ws1" / "auth-probes").glob("*/scan-config.yaml"))
    assert not client.start_workflow.called


@pytest.mark.asyncio
async def test_start_batch_rejects_missing_profile(tmp_path):
    store = _multi_store(tmp_path)
    mgr = _mgr(tmp_path, store)
    with pytest.raises(ValueError, match="认证档案不存在"):
        await mgr.start_batch_auth_validation("ws1", "prof_missing", None)


@pytest.mark.asyncio
async def test_start_batch_role_not_in_yaml(tmp_path):
    """role 不入 scan-config.yaml(保持 Branch A 纯单次登录,spec §2)——credential_to_authentication 丢 role。"""
    store = _multi_store(tmp_path)
    mgr = _mgr(tmp_path, store)
    client, _ = _patch_client()
    with patch("supernova_web.components.scan_manager.Client") as ClientCls, \
         patch.object(mgr, "_watch_batch_progress", new=AsyncMock()):
        ClientCls.connect = AsyncMock(return_value=client)
        await mgr.start_batch_auth_validation("ws1", "prof_1", ["cred_a"])
    body = next((tmp_path / "ws1" / "auth-probes").glob("*/scan-config.yaml")).read_text("utf-8")
    assert "admin" in body  # username
    assert "role" not in body  # role 字段不入 YAML


@pytest.mark.asyncio
async def test_start_batch_workflow_id_naming(tmp_path):
    """workflow_id = authval-batch-{ws}-{uuid8}(越界守护前缀,供 verify-events 守护放宽识别)。"""
    store = _multi_store(tmp_path)
    mgr = _mgr(tmp_path, store)
    client, _ = _patch_client()
    with patch("supernova_web.components.scan_manager.Client") as ClientCls, \
         patch.object(mgr, "_watch_batch_progress", new=AsyncMock()):
        ClientCls.connect = AsyncMock(return_value=client)
        result = await mgr.start_batch_auth_validation("ws1", "prof_1", None)
    assert result["workflow_id"].startswith("authval-batch-ws1-")


@pytest.mark.asyncio
async def test_start_batch_writes_first_cred_running(tmp_path):
    """起 workflow 后写首 cred running verify_status(带 probe_dir/workflow_id)——前端轮询 profile
    发现 running → 订阅其 verify-events。其余 cred 保持 unverified(watcher 终态时回填)。"""
    store = _multi_store(tmp_path)
    mgr = _mgr(tmp_path, store)
    client, _ = _patch_client()
    with patch("supernova_web.components.scan_manager.Client") as ClientCls, \
         patch.object(mgr, "_watch_batch_progress", new=AsyncMock()):
        ClientCls.connect = AsyncMock(return_value=client)
        result = await mgr.start_batch_auth_validation("ws1", "prof_1", None)
    profile = store.read("ws1")[0]
    by_id = {c.id: c for c in profile.credentials}
    # 首 cred running(带 probe_dir/workflow_id)
    assert by_id["cred_a"].verify_status.state == "running"
    assert by_id["cred_a"].verify_status.workflow_id == result["workflow_id"]
    assert by_id["cred_a"].verify_status.probe_dir is not None
    # 其余 cred 仍 unverified(watcher 回填)
    assert by_id["cred_b"].verify_status.state == "unverified"
    assert by_id["cred_c"].verify_status.state == "unverified"


@pytest.mark.asyncio
async def test_start_batch_cleans_previous_probes_per_cred(tmp_path):
    """各 cred 覆盖清理旧 probe(复用单 cred 覆盖逻辑)——防 auth-probes/ 无限堆积。"""
    store = _multi_store(tmp_path)
    # 预置 cred_a 旧 probe(VerifyStatus 指向它)
    old_probe = tmp_path / "ws1" / "auth-probes" / "probe-old-a"
    old_probe.mkdir(parents=True)
    (old_probe / "events.ndjson").write_text('{"old":1}', "utf-8")
    from supernova_web.components.auth_profile_store import VerifyStatus
    store.set_verify_status("ws1", "prof_1", "cred_a", VerifyStatus(
        state="failed", probe_dir=str(old_probe), workflow_id="authval-ws1-probe-old-a"))
    mgr = _mgr(tmp_path, store)
    client, _ = _patch_client()
    with patch("supernova_web.components.scan_manager.Client") as ClientCls, \
         patch.object(mgr, "_watch_batch_progress", new=AsyncMock()):
        ClientCls.connect = AsyncMock(return_value=client)
        await mgr.start_batch_auth_validation("ws1", "prof_1", ["cred_a", "cred_b"])
    # 旧 probe 被清,只剩 2 个新 probe
    assert not old_probe.exists()
    new_probes = [p for p in (tmp_path / "ws1" / "auth-probes").iterdir() if p.is_dir()]
    assert len(new_probes) == 2


# ---- watcher 回填 verify_status(Slice 3)----


def _prep_probe(tmp_path, cred_id, ws="ws1"):
    """预置一个 probe 目录(模拟 start_batch 已建):scan-config.yaml + events.ndjson。"""
    probe = tmp_path / ws / "auth-probes" / f"probe-{cred_id}"
    probe.mkdir(parents=True)
    (probe / "scan-config.yaml").write_text(f"authentication: {{username: {cred_id}}}", "utf-8")
    (probe / "events.ndjson").write_text('{"i":1}\n', "utf-8")
    return probe


def _mock_query_client(progress_seq):
    """handle.query 按 progress_seq 顺序返回(side_effect);末轮须 all_done=True 致 watcher 退出。"""
    handle = MagicMock()
    handle.query = AsyncMock(side_effect=list(progress_seq))
    client = MagicMock()
    client.get_workflow_handle = MagicMock(return_value=handle)
    return client, handle


@pytest.mark.asyncio
async def test_watcher_backfills_terminal_creds_and_deletes_config(tmp_path):
    """终态 cred → 回填 verify_status(success/failed + failure_point/detail + last_verified_at)+
    删 scan-config(密码卫生),保留 events.ndjson 供回看。"""
    store = _multi_store(tmp_path)
    probe_a = _prep_probe(tmp_path, "cred_a")
    probe_b = _prep_probe(tmp_path, "cred_b")
    mgr = _mgr(tmp_path, store)
    cred_probe_map = {"cred_a": {"probe_dir": str(probe_a)},
                      "cred_b": {"probe_dir": str(probe_b)}}
    progress = {"items": [
        {"cred_id": "cred_a", "state": "success"},
        {"cred_id": "cred_b", "state": "failed", "failure_point": "totp_secret", "failure_detail": "bad"},
    ], "all_done": True}
    client, _ = _mock_query_client([progress])
    with patch("supernova_web.components.scan_manager.Client") as ClientCls:
        ClientCls.connect = AsyncMock(return_value=client)
        await mgr._watch_batch_progress("ws1", "prof_1", "authval-batch-ws1-x", cred_probe_map)
    by_id = {c.id: c for c in store.read("ws1")[0].credentials}
    assert by_id["cred_a"].verify_status.state == "success"
    assert by_id["cred_b"].verify_status.state == "failed"
    assert by_id["cred_b"].verify_status.failure_point == "totp_secret"
    assert by_id["cred_a"].verify_status.last_verified_at is not None
    assert by_id["cred_a"].verify_status.probe_dir == str(probe_a)
    # scan-config 删(密码卫生),events 保留
    assert not (probe_a / "scan-config.yaml").exists()
    assert (probe_a / "events.ndjson").exists()
    assert not (probe_b / "scan-config.yaml").exists()
    assert (probe_b / "events.ndjson").exists()


@pytest.mark.asyncio
async def test_watcher_writes_running_for_in_flight_cred(tmp_path):
    """running 的 cred → 写 running verify_status(前端轮询 profile 定位 running 订阅其 verify-events)。
    两轮:第一轮 running + not done → 写 running + sleep;第二轮 success + done → 回填 + 退出。"""
    store = _multi_store(tmp_path)
    probe_b = _prep_probe(tmp_path, "cred_b")
    mgr = _mgr(tmp_path, store)
    client, _ = _mock_query_client([
        {"items": [{"cred_id": "cred_b", "state": "running"}], "all_done": False},
        {"items": [{"cred_id": "cred_b", "state": "success"}], "all_done": True},
    ])
    with patch("supernova_web.components.scan_manager.Client") as ClientCls, \
         patch.object(asyncio, "sleep", new=AsyncMock()):
        ClientCls.connect = AsyncMock(return_value=client)
        await mgr._watch_batch_progress("ws1", "prof_1", "authval-batch-ws1-x",
                                        {"cred_b": {"probe_dir": str(probe_b)}})
    by_id = {c.id: c for c in store.read("ws1")[0].credentials}
    assert by_id["cred_b"].verify_status.state == "success"  # 最终终态


@pytest.mark.asyncio
async def test_watcher_rejects_out_of_containment_probe_dir(tmp_path):
    """cred_probe_map 含越界 probe_dir → 不删该路径不回填(守护,防 map 污染致任意路径删除)。"""
    store = _multi_store(tmp_path)
    evil = tmp_path / "evil-target"
    evil.mkdir()
    (evil / "scan-config.yaml").write_text("secret", "utf-8")
    mgr = _mgr(tmp_path, store)
    cred_probe_map = {"cred_a": {"probe_dir": str(evil)}}  # 越界(不在 auth-probes/ 下)
    client, _ = _mock_query_client([{"items": [
        {"cred_id": "cred_a", "state": "success"}], "all_done": True}])
    with patch("supernova_web.components.scan_manager.Client") as ClientCls:
        ClientCls.connect = AsyncMock(return_value=client)
        await mgr._watch_batch_progress("ws1", "prof_1", "authval-batch-ws1-x", cred_probe_map)
    # 越界目录不删
    assert (evil / "scan-config.yaml").read_text("utf-8") == "secret"
    # 不回填(保持 unverified)
    by_id = {c.id: c for c in store.read("ws1")[0].credentials}
    assert by_id["cred_a"].verify_status.state == "unverified"


@pytest.mark.asyncio
async def test_watcher_exits_when_all_done(tmp_path):
    """all_done=True → watcher 退出(只 query 一次,不无限循环)。"""
    store = _multi_store(tmp_path)
    probe_a = _prep_probe(tmp_path, "cred_a")
    mgr = _mgr(tmp_path, store)
    client, handle = _mock_query_client([{"items": [
        {"cred_id": "cred_a", "state": "success"}], "all_done": True}])
    with patch("supernova_web.components.scan_manager.Client") as ClientCls:
        ClientCls.connect = AsyncMock(return_value=client)
        await mgr._watch_batch_progress("ws1", "prof_1", "authval-batch-ws1-x",
                                        {"cred_a": {"probe_dir": str(probe_a)}})
    assert handle.query.call_count == 1


@pytest.mark.asyncio
async def test_watcher_skips_unknown_cred_id(tmp_path):
    """query 返回的 cred_id 不在 cred_probe_map → 跳过(防 watcher 回填未追踪的 cred)。"""
    store = _multi_store(tmp_path)
    probe_a = _prep_probe(tmp_path, "cred_a")
    mgr = _mgr(tmp_path, store)
    client, _ = _mock_query_client([{"items": [
        {"cred_id": "cred_a", "state": "success"},
        {"cred_id": "cred_unknown", "state": "success"},  # 不在 map
    ], "all_done": True}])
    with patch("supernova_web.components.scan_manager.Client") as ClientCls:
        ClientCls.connect = AsyncMock(return_value=client)
        await mgr._watch_batch_progress("ws1", "prof_1", "authval-batch-ws1-x",
                                        {"cred_a": {"probe_dir": str(probe_a)}})
    by_id = {c.id: c for c in store.read("ws1")[0].credentials}
    assert by_id["cred_a"].verify_status.state == "success"  # 已知 cred 正常回填
    # cred_unknown 不在 profile → 不影响(KeyError 不抛,跳过)


# ---- watcher query 撞已完成 workflow 的恢复（2026-08-17 单 cred batch 卡 running 根因）----
# workflow 把最后 cred 置终态与 run() 返回（完成）在同一 workflow task 内，query 永远观测
# 不到它的终态；watcher 下一次 query 撞已完成 workflow 抛错。旧行为 except pass 静默死 →
# 终态永不回填 → 前端永久卡"测试中"。恢复路径：describe 分流——终态 → result() 回填收尾。

def _desc(status):
    from temporalio.client import WorkflowExecutionStatus
    d = MagicMock()
    d.status = status
    return d


def _mock_recovery_client(query_error=None, desc_status=None, result=None):
    """handle.query 抛错 + describe 返回指定状态(或抛) + result 返回值(或抛)。"""
    handle = MagicMock()
    handle.query = AsyncMock(side_effect=query_error or Exception("query: already completed"))
    handle.describe = (AsyncMock(return_value=desc_status)
                       if not isinstance(desc_status, Exception)
                       else AsyncMock(side_effect=desc_status))
    handle.result = AsyncMock(return_value=result) if not isinstance(result, Exception) \
        else AsyncMock(side_effect=result)
    client = MagicMock()
    client.get_workflow_handle = MagicMock(return_value=handle)
    return client, handle


@pytest.mark.asyncio
async def test_watcher_recovers_terminal_from_result_when_query_unobservable(tmp_path):
    """query 抛错(已完成不可 query)+describe=COMPLETED → result() 回填全部 cred 终态并退出。
    单 cred batch（唯一 cred 即最后 cred，query 必然观测不到其终态）的必现路径。"""
    from temporalio.client import WorkflowExecutionStatus
    store = _multi_store(tmp_path)
    probe_a = _prep_probe(tmp_path, "cred_a")
    mgr = _mgr(tmp_path, store)
    client, handle = _mock_recovery_client(
        desc_status=_desc(WorkflowExecutionStatus.COMPLETED),
        result=[{"cred_id": "cred_a", "state": "success"}])
    with patch("supernova_web.components.scan_manager.Client") as ClientCls, \
         patch.object(asyncio, "sleep", new=AsyncMock()):
        ClientCls.connect = AsyncMock(return_value=client)
        await mgr._watch_batch_progress(
            "ws1", "prof_1", "authval-batch-ws1-x", {"cred_a": {"probe_dir": str(probe_a)}})
    by_id = {c.id: c for c in store.read("ws1")[0].credentials}
    assert by_id["cred_a"].verify_status.state == "success"
    assert by_id["cred_a"].verify_status.last_verified_at is not None
    # 密码卫生同既有路径：删 scan-config，保留 events
    assert not (probe_a / "scan-config.yaml").exists()
    assert (probe_a / "events.ndjson").exists()


@pytest.mark.asyncio
async def test_watcher_survives_transient_query_error_while_running(tmp_path):
    """query 抛错但 describe=RUNNING（Temporal 抖动）→ 续轮询而非一错即死。"""
    from temporalio.client import WorkflowExecutionStatus
    store = _multi_store(tmp_path)
    probe_a = _prep_probe(tmp_path, "cred_a")
    mgr = _mgr(tmp_path, store)
    handle = MagicMock()
    handle.query = AsyncMock(side_effect=[
        Exception("transient rpc error"),
        {"items": [{"cred_id": "cred_a", "state": "success"}], "all_done": True},
    ])
    handle.describe = AsyncMock(return_value=_desc(WorkflowExecutionStatus.RUNNING))
    client = MagicMock()
    client.get_workflow_handle = MagicMock(return_value=handle)
    with patch("supernova_web.components.scan_manager.Client") as ClientCls, \
         patch.object(asyncio, "sleep", new=AsyncMock()):
        ClientCls.connect = AsyncMock(return_value=client)
        await mgr._watch_batch_progress(
            "ws1", "prof_1", "authval-batch-ws1-x", {"cred_a": {"probe_dir": str(probe_a)}})
    by_id = {c.id: c for c in store.read("ws1")[0].credentials}
    assert by_id["cred_a"].verify_status.state == "success"


@pytest.mark.asyncio
async def test_watcher_marks_failed_when_result_raises(tmp_path):
    """describe 终态 但 result() 抛（workflow 失败终态收尾）→ 当前仍 running 的 cred 记
    failed/out_of_band（failure_detail 带底层错误），不留 running。
    （2026-08-17 auth-test-cancel 起未开始的 cred 不再连带标 failed，另见
    test_watcher_backfill_abnormal_terminal_marks_only_running_creds。）"""
    from temporalio.client import WorkflowExecutionStatus
    from supernova_web.components.auth_profile_store import VerifyStatus
    store = _multi_store(tmp_path)
    probe_a = _prep_probe(tmp_path, "cred_a")
    store.set_verify_status("ws1", "prof_1", "cred_a", VerifyStatus(
        state="running", probe_dir=str(probe_a), workflow_id="authval-batch-ws1-x"))
    mgr = _mgr(tmp_path, store)
    client, _ = _mock_recovery_client(
        desc_status=_desc(WorkflowExecutionStatus.COMPLETED),
        result=Exception("workflow execution failed"))
    with patch("supernova_web.components.scan_manager.Client") as ClientCls, \
         patch.object(asyncio, "sleep", new=AsyncMock()):
        ClientCls.connect = AsyncMock(return_value=client)
        await mgr._watch_batch_progress(
            "ws1", "prof_1", "authval-batch-ws1-x", {"cred_a": {"probe_dir": str(probe_a)}})
    by_id = {c.id: c for c in store.read("ws1")[0].credentials}
    vs = by_id["cred_a"].verify_status
    assert vs.state == "failed"
    assert vs.failure_point == "out_of_band"
    assert "workflow execution failed" in (vs.failure_detail or "")


# ---- 取消/崩溃等非 COMPLETED 终态的回填语义（2026-08-17 auth-test-cancel）----
# 未开始（unverified）的 cred 不该被连带标 failed：没测 ≠ 失败。回填只写 store 中当前仍
# running 的 cred；未开始的仅删 scan-config（密码卫生，对齐 reap_stale_probes 启动期清理）。


@pytest.mark.asyncio
async def test_watcher_backfill_abnormal_terminal_marks_only_running_creds(tmp_path):
    """非 COMPLETED 终态（取消/崩溃，result() 抛）→ 只回填当前仍 running 的 cred
    （failed/out_of_band），未开始（unverified）的保持 unverified；两者 scan-config 都删
    （密码卫生），events.ndjson 保留供回看。"""
    from temporalio.client import WorkflowExecutionStatus
    store = _multi_store(tmp_path)
    probe_a = _prep_probe(tmp_path, "cred_a")
    probe_b = _prep_probe(tmp_path, "cred_b")
    from supernova_web.components.auth_profile_store import VerifyStatus
    store.set_verify_status("ws1", "prof_1", "cred_a", VerifyStatus(
        state="running", probe_dir=str(probe_a), workflow_id="authval-batch-ws1-x"))
    mgr = _mgr(tmp_path, store)
    client, _ = _mock_recovery_client(
        desc_status=_desc(WorkflowExecutionStatus.CANCELED),
        result=Exception("workflow cancelled"))
    with patch("supernova_web.components.scan_manager.Client") as ClientCls, \
         patch.object(asyncio, "sleep", new=AsyncMock()):
        ClientCls.connect = AsyncMock(return_value=client)
        await mgr._watch_batch_progress(
            "ws1", "prof_1", "authval-batch-ws1-x",
            {"cred_a": {"probe_dir": str(probe_a)}, "cred_b": {"probe_dir": str(probe_b)}})
    by_id = {c.id: c for c in store.read("ws1")[0].credentials}
    assert by_id["cred_a"].verify_status.state == "failed"       # 在跑的 → failed
    assert by_id["cred_a"].verify_status.failure_point == "out_of_band"
    assert by_id["cred_b"].verify_status.state == "unverified"   # 未开始的 → 不动
    # 密码卫生：两个 probe 的 scan-config 都删，events 保留
    assert not (probe_a / "scan-config.yaml").exists()
    assert (probe_a / "events.ndjson").exists()
    assert not (probe_b / "scan-config.yaml").exists()
    assert (probe_b / "events.ndjson").exists()


@pytest.mark.asyncio
async def test_watcher_backfill_abnormal_terminal_skips_already_terminal_creds(tmp_path):
    """已终态（success/failed，watcher 正常轮询已回填）的 cred 不被异常终态回填覆盖——
    幂等：谁先到谁写，后到者不重写。"""
    from temporalio.client import WorkflowExecutionStatus
    store = _multi_store(tmp_path)
    probe_a = _prep_probe(tmp_path, "cred_a")
    from supernova_web.components.auth_profile_store import VerifyStatus
    store.set_verify_status("ws1", "prof_1", "cred_a", VerifyStatus(
        state="success", probe_dir=str(probe_a), workflow_id="authval-batch-ws1-x"))
    mgr = _mgr(tmp_path, store)
    client, _ = _mock_recovery_client(
        desc_status=_desc(WorkflowExecutionStatus.CANCELED),
        result=Exception("workflow cancelled"))
    with patch("supernova_web.components.scan_manager.Client") as ClientCls, \
         patch.object(asyncio, "sleep", new=AsyncMock()):
        ClientCls.connect = AsyncMock(return_value=client)
        await mgr._watch_batch_progress(
            "ws1", "prof_1", "authval-batch-ws1-x", {"cred_a": {"probe_dir": str(probe_a)}})
    by_id = {c.id: c for c in store.read("ws1")[0].credentials}
    assert by_id["cred_a"].verify_status.state == "success"  # 不被覆盖成 failed


@pytest.mark.asyncio
async def test_get_auth_validation_result_parses_batch_list_for_cred(tmp_path):
    """verify-status 端点守护已放行 authval-batch- 前缀，结果解析须同步支持批量 result
    （per-cred dict list）——按 cred_id 取条目回填，而非误判单 cred 语义成 failed。"""
    store = _multi_store(tmp_path)
    mgr = _mgr(tmp_path, store)
    probe_b = _prep_probe(tmp_path, "cred_b")
    from temporalio.client import WorkflowExecutionStatus
    client, _ = _mock_recovery_client(
        desc_status=_desc(WorkflowExecutionStatus.COMPLETED),
        result=[{"cred_id": "cred_a", "state": "failed", "failure_point": "engine",
                 "failure_detail": "boom"},
                {"cred_id": "cred_b", "state": "success"}])
    with patch("supernova_web.components.scan_manager.Client") as ClientCls:
        ClientCls.connect = AsyncMock(return_value=client)
        status = await mgr.get_auth_validation_result(
            "ws1", "authval-batch-ws1-x", str(probe_b), "prof_1", "cred_b")
    assert status.state == "success"
    by_id = {c.id: c for c in store.read("ws1")[0].credentials}
    assert by_id["cred_b"].verify_status.state == "success"
    # 其余 cred 不被连带回填（按 cred_id 精确取条目）
    assert by_id["cred_a"].verify_status.state == "unverified"


# ---- workflow_id 前缀守护放宽(Slice 4:接受 authval-batch-{ws}-)----


@pytest.mark.asyncio
async def test_events_path_accepts_batch_workflow_id_prefix(tmp_path):
    """verify-events 守护放宽:接受 authval-batch-{ws}- 前缀(批量产物订阅实时日志)。"""
    store = _multi_store(tmp_path)
    mgr = _mgr(tmp_path, store)
    probe = _prep_probe(tmp_path, "cred_a")
    ndjson = await mgr.auth_validation_events_path(
        "ws1", workflow_id="authval-batch-ws1-deadbeef", probe_dir=str(probe))
    assert ndjson == probe.resolve() / "events.ndjson"


@pytest.mark.asyncio
async def test_verify_log_accepts_batch_workflow_id_prefix(tmp_path):
    """verify-log 守护放宽:接受 authval-batch-{ws}- 前缀(批量产物事后回看)。"""
    store = _multi_store(tmp_path)
    mgr = _mgr(tmp_path, store)
    probe = _prep_probe(tmp_path, "cred_a")
    events = await mgr.get_auth_validation_log(
        "ws1", workflow_id="authval-batch-ws1-deadbeef", probe_dir=str(probe))
    assert len(events) == 1  # _prep_probe 写了 1 行 events


@pytest.mark.asyncio
async def test_events_path_rejects_batch_prefix_other_ws(tmp_path):
    """守护②:authval-batch-{其他ws}- → 拒(防跨 ws 读 events)。"""
    store = _multi_store(tmp_path)
    mgr = _mgr(tmp_path, store)
    probe = _prep_probe(tmp_path, "cred_a")
    with pytest.raises(ValueError, match="workflow_id 越界"):
        await mgr.auth_validation_events_path(
            "ws1", workflow_id="authval-batch-ws2-deadbeef", probe_dir=str(probe))


# ---------------------------------------------------------------------------
# HOST 档案透传（2026-08-14：认证测试复用黑盒 HOST 能力——选中 HOST 才走代理、不选直连）
# ---------------------------------------------------------------------------

def _host_store(tmp_path):
    """HOST 档案 store：1 个档案 host_p1（x.test→10.0.0.1）。"""
    from supernova_web.components.host_profile_store import (
        HostProfileStore, HostProfile, HostMapping)
    store = HostProfileStore(tmp_path / "hosts")
    store.upsert_profile("ws1", HostProfile(
        id="host_p1", name="P1",
        mappings=[HostMapping(ip="10.0.0.1", host="x.test")]))
    return store


@pytest.mark.asyncio
async def test_start_batch_threads_host_profile_to_each_item(tmp_path):
    """start_batch(host_profile_id=...) → 解析 HOST 档案 → 每个 BatchItem.host_mappings 同值
    （batch workflow 据此为每个 cred 起 host proxy）。"""
    store = _multi_store(tmp_path)
    mgr = _mgr(tmp_path, store)
    mgr.host_profile_store = _host_store(tmp_path)
    client, _ = _patch_client()
    with patch("supernova_web.components.scan_manager.Client") as ClientCls, \
         patch.object(mgr, "_watch_batch_progress", new=AsyncMock()):
        ClientCls.connect = AsyncMock(return_value=client)
        await mgr.start_batch_auth_validation(
            "ws1", "prof_1", None, host_profile_id="host_p1")
    sent_input = client.start_workflow.call_args.args[1]
    assert len(sent_input.items) == 3
    assert all(it.host_mappings == {"x.test": "10.0.0.1"} for it in sent_input.items)


@pytest.mark.asyncio
async def test_start_batch_no_host_empty_mappings_per_item(tmp_path):
    """不传 host_profile_id/host_url → 每个 BatchItem.host_mappings == {}（直连，零回归）。"""
    store = _multi_store(tmp_path)
    mgr = _mgr(tmp_path, store)
    client, _ = _patch_client()
    with patch("supernova_web.components.scan_manager.Client") as ClientCls, \
         patch.object(mgr, "_watch_batch_progress", new=AsyncMock()):
        ClientCls.connect = AsyncMock(return_value=client)
        await mgr.start_batch_auth_validation("ws1", "prof_1", None)
    sent_input = client.start_workflow.call_args.args[1]
    assert all(it.host_mappings == {} for it in sent_input.items)


@pytest.mark.asyncio
async def test_start_batch_threads_host_url_to_each_item(tmp_path, monkeypatch):
    """host_url → fetch_and_parse_hosts → 每个 item.host_mappings 同值（URL 来源，对齐黑盒）。"""
    from supernova_web.components.host_profile_store import HostMapping

    async def fake_fetch(url, timeout=15):
        return ([HostMapping(ip="10.0.0.2", host="y.test")], [])

    monkeypatch.setattr(
        "supernova_web.components.scan_manager.fetch_and_parse_hosts", fake_fetch)
    store = _multi_store(tmp_path)
    mgr = _mgr(tmp_path, store)
    client, _ = _patch_client()
    with patch("supernova_web.components.scan_manager.Client") as ClientCls, \
         patch.object(mgr, "_watch_batch_progress", new=AsyncMock()):
        ClientCls.connect = AsyncMock(return_value=client)
        await mgr.start_batch_auth_validation(
            "ws1", "prof_1", None, host_url="https://h.test/get?id=1")
    sent_input = client.start_workflow.call_args.args[1]
    assert all(it.host_mappings == {"y.test": "10.0.0.2"} for it in sent_input.items)


@pytest.mark.asyncio
async def test_start_auth_validation_threads_host_profile_to_input(tmp_path):
    """start_auth_validation(host_profile_id=...) → 解析 → BlackboxAuthValidationInput.host_mappings。
    单 cred AuthValidationWorkflow 已有 proxy 编排，故只需把 mappings 灌进 input。"""
    store = _multi_store(tmp_path)
    mgr = _mgr(tmp_path, store)
    mgr.host_profile_store = _host_store(tmp_path)
    client, _ = _patch_client()
    with patch("supernova_web.components.scan_manager.Client") as ClientCls:
        ClientCls.connect = AsyncMock(return_value=client)
        await mgr.start_auth_validation(
            "ws1", "prof_1", "cred_a", host_profile_id="host_p1")
    sent_input = client.start_workflow.call_args.args[1]
    assert sent_input.host_mappings == {"x.test": "10.0.0.1"}


@pytest.mark.asyncio
async def test_start_auth_validation_no_host_empty_mappings(tmp_path):
    """不传 host → host_mappings == {}（直连，零回归）。"""
    store = _multi_store(tmp_path)
    mgr = _mgr(tmp_path, store)
    client, _ = _patch_client()
    with patch("supernova_web.components.scan_manager.Client") as ClientCls:
        ClientCls.connect = AsyncMock(return_value=client)
        await mgr.start_auth_validation("ws1", "prof_1", "cred_a")
    sent_input = client.start_workflow.call_args.args[1]
    assert sent_input.host_mappings == {}


# ---------------------------------------------------------------------------
# 用户停止认证测试 cancel_auth_validation（2026-08-17 auth-test-cancel spec §3）
# 顺序：先回填状态后 cancel workflow（Temporal 不可达也不卡 running）。
# unverified cred 不动（其残留 scan-config 由 watcher 终态回填时清理——probe_dir 不在 store）。
# ---------------------------------------------------------------------------


def _mock_cancel_client():
    """Client.connect → client；get_workflow_handle → handle（cancel AsyncMock 可断言）。"""
    handle = MagicMock()
    handle.cancel = AsyncMock()
    client = MagicMock()
    client.get_workflow_handle = MagicMock(return_value=handle)
    return client, handle


@pytest.mark.asyncio
async def test_cancel_marks_running_cred_failed_and_cancels_workflow(tmp_path):
    """停止：绑此 wf 且 running 的 cred → failed/cancelled + 删 scan-config（保留 events）；
    unverified 的兄弟不动；handle.cancel() 被调。"""
    from supernova_web.components.auth_profile_store import VerifyStatus
    store = _multi_store(tmp_path)
    probe_a = _prep_probe(tmp_path, "cred_a")
    store.set_verify_status("ws1", "prof_1", "cred_a", VerifyStatus(
        state="running", probe_dir=str(probe_a), workflow_id="authval-batch-ws1-x"))
    mgr = _mgr(tmp_path, store)
    client, handle = _mock_cancel_client()
    with patch("supernova_web.components.scan_manager.Client") as ClientCls:
        ClientCls.connect = AsyncMock(return_value=client)
        result = await mgr.cancel_auth_validation("ws1", "prof_1", "authval-batch-ws1-x")
    assert result == {"cancelled": "authval-batch-ws1-x"}
    handle.cancel.assert_awaited_once()
    by_id = {c.id: c for c in store.read("ws1")[0].credentials}
    vs = by_id["cred_a"].verify_status
    assert vs.state == "failed"
    assert vs.failure_point == "cancelled"
    assert vs.last_verified_at is not None
    assert not (probe_a / "scan-config.yaml").exists()   # 密码卫生
    assert (probe_a / "events.ndjson").exists()          # 过程证据保留
    assert by_id["cred_b"].verify_status.state == "unverified"  # 未开始的不动


@pytest.mark.asyncio
async def test_cancel_supports_single_cred_workflow_prefix(tmp_path):
    """单 cred 测试（authval-{ws}- 前缀）同走取消——同一端点覆盖两个页面。"""
    from supernova_web.components.auth_profile_store import VerifyStatus
    store = _multi_store(tmp_path)
    probe_a = _prep_probe(tmp_path, "cred_a")
    store.set_verify_status("ws1", "prof_1", "cred_a", VerifyStatus(
        state="running", probe_dir=str(probe_a), workflow_id="authval-ws1-y"))
    mgr = _mgr(tmp_path, store)
    client, handle = _mock_cancel_client()
    with patch("supernova_web.components.scan_manager.Client") as ClientCls:
        ClientCls.connect = AsyncMock(return_value=client)
        result = await mgr.cancel_auth_validation("ws1", "prof_1", "authval-ws1-y")
    assert result["cancelled"] == "authval-ws1-y"
    handle.cancel.assert_awaited_once()
    by_id = {c.id: c for c in store.read("ws1")[0].credentials}
    assert by_id["cred_a"].verify_status.state == "failed"


@pytest.mark.asyncio
async def test_cancel_rejects_out_of_bounds_workflow_id(tmp_path):
    """前缀越界（他 ws / 任意串）→ ValueError，不写状态不调 cancel。"""
    from supernova_web.components.auth_profile_store import VerifyStatus
    store = _multi_store(tmp_path)
    probe_a = _prep_probe(tmp_path, "cred_a")
    store.set_verify_status("ws1", "prof_1", "cred_a", VerifyStatus(
        state="running", probe_dir=str(probe_a), workflow_id="authval-batch-ws1-x"))
    mgr = _mgr(tmp_path, store)
    client, handle = _mock_cancel_client()
    with patch("supernova_web.components.scan_manager.Client") as ClientCls:
        ClientCls.connect = AsyncMock(return_value=client)
        with pytest.raises(ValueError, match="越界"):
            await mgr.cancel_auth_validation("ws1", "prof_1", "authval-batch-ws2-x")
        with pytest.raises(ValueError, match="越界"):
            await mgr.cancel_auth_validation("ws1", "prof_1", "scan-ws1-evil")
    handle.cancel.assert_not_awaited()
    by_id = {c.id: c for c in store.read("ws1")[0].credentials}
    assert by_id["cred_a"].verify_status.state == "running"  # 状态不动


@pytest.mark.asyncio
async def test_cancel_rejects_workflow_not_bound_to_profile(tmp_path):
    """前缀合法但未绑该档案任何 cred → ValueError（防取消同 ws 其他档案的测试）。"""
    from supernova_web.components.auth_profile_store import VerifyStatus
    store = _multi_store(tmp_path)
    probe_a = _prep_probe(tmp_path, "cred_a")
    store.set_verify_status("ws1", "prof_1", "cred_a", VerifyStatus(
        state="running", probe_dir=str(probe_a), workflow_id="authval-batch-ws1-x"))
    mgr = _mgr(tmp_path, store)
    client, handle = _mock_cancel_client()
    with patch("supernova_web.components.scan_manager.Client") as ClientCls:
        ClientCls.connect = AsyncMock(return_value=client)
        with pytest.raises(ValueError, match="未绑定"):
            await mgr.cancel_auth_validation("ws1", "prof_1", "authval-batch-ws1-other")
    handle.cancel.assert_not_awaited()


@pytest.mark.asyncio
async def test_cancel_idempotent_when_no_running_cred(tmp_path):
    """无 running（已结束）→ 幂等返 already_finished=True，不再调 handle.cancel。"""
    from supernova_web.components.auth_profile_store import VerifyStatus
    store = _multi_store(tmp_path)
    probe_a = _prep_probe(tmp_path, "cred_a")
    store.set_verify_status("ws1", "prof_1", "cred_a", VerifyStatus(
        state="failed", probe_dir=str(probe_a), workflow_id="authval-batch-ws1-x"))
    mgr = _mgr(tmp_path, store)
    client, handle = _mock_cancel_client()
    with patch("supernova_web.components.scan_manager.Client") as ClientCls:
        ClientCls.connect = AsyncMock(return_value=client)
        result = await mgr.cancel_auth_validation("ws1", "prof_1", "authval-batch-ws1-x")
    assert result["already_finished"] is True
    handle.cancel.assert_not_awaited()


@pytest.mark.asyncio
async def test_cancel_finalizes_state_even_when_temporal_unreachable(tmp_path):
    """Temporal 连不上 → 状态仍回填（先写状态后 cancel），异常吞掉不抛（best-effort）。"""
    from supernova_web.components.auth_profile_store import VerifyStatus
    store = _multi_store(tmp_path)
    probe_a = _prep_probe(tmp_path, "cred_a")
    store.set_verify_status("ws1", "prof_1", "cred_a", VerifyStatus(
        state="running", probe_dir=str(probe_a), workflow_id="authval-batch-ws1-x"))
    mgr = _mgr(tmp_path, store)
    with patch("supernova_web.components.scan_manager.Client") as ClientCls:
        ClientCls.connect = AsyncMock(side_effect=Exception("temporal down"))
        result = await mgr.cancel_auth_validation("ws1", "prof_1", "authval-batch-ws1-x")
    assert result["cancelled"] == "authval-batch-ws1-x"
    by_id = {c.id: c for c in store.read("ws1")[0].credentials}
    assert by_id["cred_a"].verify_status.state == "failed"  # 不卡 running
