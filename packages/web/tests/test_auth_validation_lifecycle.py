"""scan_manager 探针生命周期:写 probe YAML + 起 workflow + 取 result 回填 + 删 probe 目录。"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from pathlib import Path

from supernova_web.components.auth_profile_store import (
    AuthProfileStore, AuthProfile, AuthProfileCredential, VerifyStatus,
)
from supernova_web.components.credential_vault import CredentialVault
from supernova_web.components.scan_manager import ScanManager
from supernova_core.services.validate_authentication import AuthValidationResult


def _store(tmp_path):
    vault = CredentialVault(tmp_path / ".master.key")
    s = AuthProfileStore(tmp_path, vault)
    s.write("ws1", [AuthProfile(
        id="prof_1", name="NG", login_url="http://t/", login_type="form",
        credentials=[AuthProfileCredential(id="cred_a", role="admin", username="admin", password="pw")])])
    return s


def _mgr(tmp_path, store):
    # 最小构造:scan_manager 只用到 _workspaces_dir / auth_profile_store / _temporal_address。
    # ws_config_store 不传（None → _resolve_provider_config 走全局 env 兜底构造，
    # 测试关注探针生命周期而非 provider 解析——不降级行为另有专测）。
    return ScanManager(
        workspaces_dir=tmp_path, repos_dir=tmp_path / "repos", config_store=MagicMock(),
        scan_timeout=0.0,
        auth_profile_store=store,
    )


@pytest.mark.asyncio
async def test_start_auth_validation_writes_probe_yaml_and_starts_workflow(tmp_path):
    store = _store(tmp_path)
    mgr = _mgr(tmp_path, store)
    fake_handle = MagicMock()
    fake_handle.id = "wf-123"
    with patch("supernova_web.components.scan_manager.Client") as ClientCls, \
         patch("supernova_web.components.scan_manager.validate_authentication", create=True):
        ClientCls.connect = AsyncMock(return_value=MagicMock(
            start_workflow=AsyncMock(return_value=fake_handle)))
        wf_id = await mgr.start_auth_validation("ws1", "prof_1", "cred_a")
    assert wf_id["workflow_id"] == "wf-123"
    # probe 目录 + scan-config.yaml 被写(含 authentication 段,明文)
    probe_yamls = list((tmp_path / "ws1" / "auth-probes").glob("*/scan-config.yaml"))
    assert probe_yamls, "probe scan-config.yaml 应被写"
    body = probe_yamls[0].read_text("utf-8")
    assert "authentication" in body and "admin" in body and "pw" in body
    # 块1c：event_file 必须穿线进 BlackboxAuthValidationInput（启用 agent 过程落盘）。
    sent_inp = ClientCls.connect.return_value.start_workflow.call_args.args[1]
    assert sent_inp.event_file is not None, "应传 event_file 启用过程落盘"
    assert sent_inp.event_file.endswith("events.ndjson")
    assert "auth-probes" in sent_inp.event_file


@pytest.mark.asyncio
async def test_start_auth_validation_cleans_previous_probe(tmp_path):
    """块3c: 同 (profile,cred) 上次验证留了旧 probe（VerifyStatus.probe_dir 记录）,下次"测试
    登录"先删旧 probe 再建新——防 auth-probes/ 无限堆积（每次验证一个 probe-<uuid8>）。"""
    store = _store(tmp_path)
    # 预置旧 probe + VerifyStatus 指向它（模拟上次验证后留的产物）
    old_probe = tmp_path / "ws1" / "auth-probes" / "probe-old"
    old_probe.mkdir(parents=True)
    (old_probe / "events.ndjson").write_text('{"old":1}', "utf-8")
    store.set_verify_status("ws1", "prof_1", "cred_a", VerifyStatus(
        state="failed", probe_dir=str(old_probe), workflow_id="authval-ws1-probe-old"))
    mgr = _mgr(tmp_path, store)
    fake_handle = MagicMock()
    fake_handle.id = "wf-new"
    with patch("supernova_web.components.scan_manager.Client") as ClientCls, \
         patch("supernova_web.components.scan_manager.validate_authentication", create=True):
        ClientCls.connect = AsyncMock(return_value=MagicMock(
            start_workflow=AsyncMock(return_value=fake_handle)))
        await mgr.start_auth_validation("ws1", "prof_1", "cred_a")
    # 旧 probe 被覆盖清理（防堆积）
    assert not old_probe.exists(), "旧 probe 应被覆盖清理"
    # 只剩新 probe（新 probe-<uuid8>）
    new_probes = [p for p in (tmp_path / "ws1" / "auth-probes").iterdir() if p.is_dir()]
    assert len(new_probes) == 1, "应只剩新 probe（旧的已清）"


@pytest.mark.asyncio
async def test_start_auth_validation_provider_incomplete_no_degrade(tmp_path):
    """测试登录不降级（2026-08-17）：工作区模型配置缺失/错误 → 直接抛 ProviderConfigIncomplete，
    不 env 兜底、不起 workflow、不删旧 probe、不写明文 scan-config.yaml。"""
    from supernova_web.components.ws_config_store import ProviderConfigIncomplete

    store = _store(tmp_path)
    old_probe = tmp_path / "ws1" / "auth-probes" / "probe-old"
    old_probe.mkdir(parents=True)
    (old_probe / "events.ndjson").write_text('{"old":1}', "utf-8")
    store.set_verify_status("ws1", "prof_1", "cred_a", VerifyStatus(
        state="failed", probe_dir=str(old_probe), workflow_id="authval-ws1-probe-old"))
    mgr = _mgr(tmp_path, store)

    def _raise(ws):
        raise ProviderConfigIncomplete(["SUPERNOVA_OPENAI_API_KEY"])

    with patch("supernova_web.components.scan_manager.Client") as ClientCls, \
         patch.object(mgr, "_resolve_provider_config", side_effect=_raise):
        ClientCls.connect = AsyncMock()
        with pytest.raises(ProviderConfigIncomplete):
            await mgr.start_auth_validation("ws1", "prof_1", "cred_a")

    ClientCls.connect.assert_not_awaited(), "配置错误时不应连 Temporal 起 workflow"
    assert old_probe.exists(), "配置错误时不应删旧 probe（回看产物保留）"
    assert not list(old_probe.parent.glob("probe-*/scan-config.yaml")), \
        "配置错误时不应写明文 scan-config.yaml"
    cred = store.read("ws1")[0].credentials[0]
    assert cred.verify_status.workflow_id == "authval-ws1-probe-old", \
        "verify_status 不应被改写"


@pytest.mark.asyncio
async def test_start_auth_validation_writes_running_status(tmp_path):
    """测试登录 workflow 启动后立即写 running 中间态——前端重载过程页时识别 running →
    重连 SSE 恢复实时观测。workflow_id/probe_dir 与返回 dict 同源（handle.id），须满足
    get_result 越界守护（authval-<ws>- 前缀 + auth-probes/ 下），否则前端重载后用这俩字段
    轮询 verify-status 会被 403/ValueError 拒。"""
    store = _store(tmp_path)
    mgr = _mgr(tmp_path, store)
    fake_handle = MagicMock()
    fake_handle.id = "authval-ws1-probe-deadbeef"
    with patch("supernova_web.components.scan_manager.Client") as ClientCls, \
         patch("supernova_web.components.scan_manager.validate_authentication", create=True):
        ClientCls.connect = AsyncMock(return_value=MagicMock(
            start_workflow=AsyncMock(return_value=fake_handle)))
        result = await mgr.start_auth_validation("ws1", "prof_1", "cred_a")
    cred = store.read("ws1")[0].credentials[0]
    assert cred.verify_status.state == "running"
    # workflow_id/probe_dir 与返回 dict 同源（handle.id / str(probe_dir)）
    assert cred.verify_status.workflow_id == result["workflow_id"] == "authval-ws1-probe-deadbeef"
    assert cred.verify_status.probe_dir == result["probe_dir"]
    # 满足 get_auth_validation_result 越界守护
    assert cred.verify_status.workflow_id.startswith("authval-ws1-")
    assert "auth-probes" in cred.verify_status.probe_dir


@pytest.mark.asyncio
async def test_get_result_backfills_and_keeps_events_deletes_only_config(tmp_path):
    """块3a: get_result 回填 verify_status 后,只删明文 scan-config.yaml（密码卫生）,
    保留 events.ndjson + auth-state.json 供 verify-log 回看/诊断（spec 块3）。"""
    store = _store(tmp_path)
    mgr = _mgr(tmp_path, store)
    # 预置一个 probe 目录(模拟 start 已写 + 过程产物已落盘)
    probe_dir = tmp_path / "ws1" / "auth-probes" / "probe-1"
    probe_dir.mkdir(parents=True)
    (probe_dir / "scan-config.yaml").write_text("authentication: {}", "utf-8")
    (probe_dir / "events.ndjson").write_text('{"event":"agent_step"}\n', "utf-8")
    (probe_dir / "auth-state.json").write_text('{"cookies":[]}', "utf-8")
    from temporalio.client import WorkflowExecutionStatus
    desc = MagicMock(status=WorkflowExecutionStatus.COMPLETED)
    with patch("supernova_web.components.scan_manager.Client") as ClientCls:
        ClientCls.connect = AsyncMock(return_value=MagicMock(
            get_workflow_handle=MagicMock(return_value=MagicMock(
                describe=AsyncMock(return_value=desc),
                result=AsyncMock(return_value=AuthValidationResult(
                    success=False, failure_point="username_or_password", failure_detail="bad pw"))))))
        status = await mgr.get_auth_validation_result(
            "ws1", workflow_id="authval-ws1-probe-1", probe_dir=str(probe_dir),
            profile_id="prof_1", cred_id="cred_a",
        )
    assert status.state == "failed"
    assert status.failure_point == "username_or_password"
    # 回填进 store
    cred = store.read("ws1")[0].credentials[0]
    assert cred.verify_status.state == "failed"
    # 块3c：回填 probe_dir/workflow_id（verify-log 定位 + 下次覆盖清理）
    assert cred.verify_status.probe_dir == str(probe_dir)
    assert cred.verify_status.workflow_id == "authval-ws1-probe-1"
    # 块3a：明文 scan-config 必删（密码卫生）;events/auth-state 保留供回看;probe_dir 仍在
    assert not (probe_dir / "scan-config.yaml").exists()
    assert (probe_dir / "events.ndjson").exists(), "events.ndjson 应保留供回看"
    assert (probe_dir / "auth-state.json").exists(), "auth-state.json 应保留供诊断"
    assert probe_dir.exists(), "probe_dir 应保留（只删 config）"


@pytest.mark.asyncio
async def test_get_result_pending_when_workflow_running(tmp_path):
    """块2: workflow 仍 RUNNING → get_result 抛 AuthValidationPending（端点转 503,前端继续轮询）,
    且绝不阻塞调 result()——修轮询超时误判（workflow 跑 >前端轮询上限时,成功被显示成失败）。"""
    from temporalio.client import WorkflowExecutionStatus
    from supernova_web.components.scan_manager import AuthValidationPending
    store = _store(tmp_path)
    mgr = _mgr(tmp_path, store)
    probe_dir = tmp_path / "ws1" / "auth-probes" / "probe-run"
    probe_dir.mkdir(parents=True)
    (probe_dir / "scan-config.yaml").write_text("authentication: {}", "utf-8")
    desc = MagicMock(status=WorkflowExecutionStatus.RUNNING)
    result_mock = AsyncMock(return_value=AuthValidationResult(success=True))
    with patch("supernova_web.components.scan_manager.Client") as ClientCls:
        ClientCls.connect = AsyncMock(return_value=MagicMock(
            get_workflow_handle=MagicMock(return_value=MagicMock(
                describe=AsyncMock(return_value=desc),
                result=result_mock))))
        with pytest.raises(AuthValidationPending):
            await mgr.get_auth_validation_result(
                "ws1", workflow_id="authval-ws1-probe-run", probe_dir=str(probe_dir),
                profile_id="prof_1", cred_id="cred_a",
            )
    # RUNNING 时绝不阻塞等 result()（修轮询误判核心）
    result_mock.assert_not_called()


@pytest.mark.asyncio
async def test_get_result_success_when_completed(tmp_path):
    """块2: workflow COMPLETED + result.success=True → VerifyStatus(success)。覆盖终态 success
    分支（backfills 测 failed,此处补 success,防 success 分支 regression）。"""
    from temporalio.client import WorkflowExecutionStatus
    store = _store(tmp_path)
    mgr = _mgr(tmp_path, store)
    probe_dir = tmp_path / "ws1" / "auth-probes" / "probe-ok"
    probe_dir.mkdir(parents=True)
    (probe_dir / "scan-config.yaml").write_text("authentication: {}", "utf-8")
    desc = MagicMock(status=WorkflowExecutionStatus.COMPLETED)
    with patch("supernova_web.components.scan_manager.Client") as ClientCls:
        ClientCls.connect = AsyncMock(return_value=MagicMock(
            get_workflow_handle=MagicMock(return_value=MagicMock(
                describe=AsyncMock(return_value=desc),
                result=AsyncMock(return_value=AuthValidationResult(success=True))))))
        status = await mgr.get_auth_validation_result(
            "ws1", workflow_id="authval-ws1-probe-ok", probe_dir=str(probe_dir),
            profile_id="prof_1", cred_id="cred_a",
        )
    assert status.state == "success"


@pytest.mark.asyncio
async def test_get_result_overwrites_running_to_terminal(tmp_path):
    """running 中间态在终态时被覆盖——预置 running（模拟 start 已写、workflow 现刚跑完）→
    get_result(COMPLETED+failed) → state 从 running 被覆盖为 failed，无 running 残留
    （防 worker 终态后前端仍误判进行中、按钮永久 disable）。"""
    from temporalio.client import WorkflowExecutionStatus
    store = _store(tmp_path)
    probe_dir = tmp_path / "ws1" / "auth-probes" / "probe-run2"
    probe_dir.mkdir(parents=True)
    (probe_dir / "scan-config.yaml").write_text("authentication: {}", "utf-8")
    store.set_verify_status("ws1", "prof_1", "cred_a", VerifyStatus(
        state="running", probe_dir=str(probe_dir), workflow_id="authval-ws1-probe-run2"))
    mgr = _mgr(tmp_path, store)
    desc = MagicMock(status=WorkflowExecutionStatus.COMPLETED)
    with patch("supernova_web.components.scan_manager.Client") as ClientCls:
        ClientCls.connect = AsyncMock(return_value=MagicMock(
            get_workflow_handle=MagicMock(return_value=MagicMock(
                describe=AsyncMock(return_value=desc),
                result=AsyncMock(return_value=AuthValidationResult(
                    success=False, failure_point="username_or_password", failure_detail="bad"))))))
        status = await mgr.get_auth_validation_result(
            "ws1", workflow_id="authval-ws1-probe-run2", probe_dir=str(probe_dir),
            profile_id="prof_1", cred_id="cred_a",
        )
    assert status.state == "failed"
    cred = store.read("ws1")[0].credentials[0]
    assert cred.verify_status.state == "failed", "running 须被终态覆盖，无残留"


@pytest.mark.asyncio
async def test_get_result_deletes_probe_dir_even_when_result_fetch_raises(tmp_path):
    """try/finally 不变量:Temporal result fetch 抛错时,明文 probe 目录也必清。

    workflow_id 用 start_auth_validation 产出的 authval-<ws>-probe-<uuid8> 形态
    (2026-08-05 fix-wave 加了 workflow_id 绑 ws 校验)。
    """
    store = _store(tmp_path)
    mgr = _mgr(tmp_path, store)
    probe_dir = tmp_path / "ws1" / "auth-probes" / "probe-err"
    probe_dir.mkdir(parents=True)
    (probe_dir / "scan-config.yaml").write_text(
        "authentication: {username: admin, password: leak-me}", "utf-8")
    with patch("supernova_web.components.scan_manager.Client") as ClientCls:
        ClientCls.connect = AsyncMock(side_effect=RuntimeError("temporal down"))
        with pytest.raises(RuntimeError, match="temporal down"):
            await mgr.get_auth_validation_result(
                "ws1", workflow_id="authval-ws1-probe-err", probe_dir=str(probe_dir),
                profile_id="prof_1", cred_id="cred_a",
            )
    # 块3a：明文 scan-config 必删（密码卫生）即便 fetch 抛错;probe_dir 可留（保留诊断产物）
    assert not (probe_dir / "scan-config.yaml").exists(), "明文 config 必清防密码滞留"


@pytest.mark.asyncio
async def test_get_result_rejects_out_of_containment_probe_dir(tmp_path):
    """守护①:probe_dir 越界(不在 workspaces/<ws>/auth-probes/ 下) → ValueError 且不删该路径。

    防最低权限 workspace_member 经 verify-status 端点传 probe_dir=/tmp 等任意路径 +
    bogus workflow_id(Temporal 抛错触发 finally rmtree)致任意路径删除(容器以 root 跑)。
    """
    store = _store(tmp_path)
    mgr = _mgr(tmp_path, store)
    # 构造一个越界目录(模拟攻击者想删的目标)
    evil_dir = tmp_path / "evil-target"
    evil_dir.mkdir()
    (evil_dir / "secret.txt").write_text("do-not-delete", "utf-8")
    # 校验在 Client.connect 之前,Temporal 不应被调用
    with patch("supernova_web.components.scan_manager.Client") as ClientCls:
        ClientCls.connect = AsyncMock(side_effect=AssertionError("不应连 Temporal"))
        with pytest.raises(ValueError, match="probe_dir 越界"):
            await mgr.get_auth_validation_result(
                "ws1", workflow_id="authval-ws1-probe-evil",
                probe_dir=str(evil_dir),
                profile_id="prof_1", cred_id="cred_a",
            )
    # 越界目录不被删(防任意路径删除)
    assert evil_dir.exists()
    assert (evil_dir / "secret.txt").read_text("utf-8") == "do-not-delete"


@pytest.mark.asyncio
async def test_get_result_rejects_probe_dir_outside_auth_probes_subtree(tmp_path):
    """守护①(变体):probe_dir 在 workspaces/<ws>/ 下但不在 auth-probes/ 子树 → 拒。

    防攻击者把 probe_dir 指向 workspaces/<ws>/scans/<id> 删他人扫描产物
    (路径形态合法但不在 auth-probes/ 下)。
    """
    store = _store(tmp_path)
    mgr = _mgr(tmp_path, store)
    # 构造一个 ws 下但非 auth-probes 的目录(模拟攻击者想删的扫描产物)
    sibling_dir = tmp_path / "ws1" / "scans" / "scan-999"
    sibling_dir.mkdir(parents=True)
    (sibling_dir / "session.json").write_text('{"status":"running"}', "utf-8")
    with patch("supernova_web.components.scan_manager.Client") as ClientCls:
        ClientCls.connect = AsyncMock(side_effect=AssertionError("不应连 Temporal"))
        with pytest.raises(ValueError, match="probe_dir 越界"):
            await mgr.get_auth_validation_result(
                "ws1", workflow_id="authval-ws1-probe-x",
                probe_dir=str(sibling_dir),
                profile_id="prof_1", cred_id="cred_a",
            )
    assert sibling_dir.exists()  # 不被删


@pytest.mark.asyncio
async def test_get_result_rejects_workflow_id_not_bound_to_ws(tmp_path):
    """守护②:workflow_id 不以 authval-<ws>- 开头 → ValueError(防跨 ws 信息泄露)。

    防 ws-A 成员传 workflow_id=authval-wsB-... 读 ws-B 的 auth 验证结果(workflow result
    含登录成败细节,属跨 ws 信息泄露 cousin)。
    """
    store = _store(tmp_path)
    mgr = _mgr(tmp_path, store)
    # probe_dir 合法(在 ws1/auth-probes/ 下),仅 workflow_id 绑别的 ws
    probe_dir = tmp_path / "ws1" / "auth-probes" / "probe-x"
    probe_dir.mkdir(parents=True)
    (probe_dir / "scan-config.yaml").write_text("authentication: {}", "utf-8")
    with patch("supernova_web.components.scan_manager.Client") as ClientCls:
        ClientCls.connect = AsyncMock(side_effect=AssertionError("不应连 Temporal"))
        with pytest.raises(ValueError, match="workflow_id 越界"):
            await mgr.get_auth_validation_result(
                "ws1", workflow_id="authval-ws2-probe-x",  # 绑 ws2,攻击者想读 ws2 结果
                probe_dir=str(probe_dir),
                profile_id="prof_1", cred_id="cred_a",
            )


# ---- 块3b: verify-log（读 events.ndjson 过程记录）----


@pytest.mark.asyncio
async def test_get_auth_validation_log_returns_all_events(tmp_path):
    """块3b: get_auth_validation_log 读 probe_dir/events.ndjson 全量事件（事后回看）。"""
    store = _store(tmp_path)
    mgr = _mgr(tmp_path, store)
    probe_dir = tmp_path / "ws1" / "auth-probes" / "probe-log"
    probe_dir.mkdir(parents=True)
    (probe_dir / "events.ndjson").write_text(
        '{"i":1,"msg":"navigate"}\n{"i":2,"msg":"fill"}\n{"i":3,"msg":"submit"}\n', "utf-8")
    events = await mgr.get_auth_validation_log(
        "ws1", workflow_id="authval-ws1-probe-log", probe_dir=str(probe_dir))
    assert len(events) == 3
    assert events[0]["msg"] == "navigate"
    assert events[2]["msg"] == "submit"


@pytest.mark.asyncio
async def test_get_auth_validation_log_tail_n(tmp_path):
    """块3b: tail=N 取末 N 条（实时观看只取末尾,减传输）。"""
    store = _store(tmp_path)
    mgr = _mgr(tmp_path, store)
    probe_dir = tmp_path / "ws1" / "auth-probes" / "probe-tail"
    probe_dir.mkdir(parents=True)
    (probe_dir / "events.ndjson").write_text(
        "\n".join(f'{{"i":{i}}}' for i in range(1, 6)) + "\n", "utf-8")
    events = await mgr.get_auth_validation_log(
        "ws1", workflow_id="authval-ws1-probe-tail", probe_dir=str(probe_dir), tail=2)
    assert [e["i"] for e in events] == [4, 5]


@pytest.mark.asyncio
async def test_get_auth_validation_log_rejects_out_of_containment(tmp_path):
    """块3b: verify-log 复用越界守护——probe_dir 越界 → ValueError（防任意路径读 events）。"""
    store = _store(tmp_path)
    mgr = _mgr(tmp_path, store)
    evil_dir = tmp_path / "evil"
    evil_dir.mkdir()
    (evil_dir / "events.ndjson").write_text('{"secret":"leak"}', "utf-8")
    with pytest.raises(ValueError, match="probe_dir 越界"):
        await mgr.get_auth_validation_log(
            "ws1", workflow_id="authval-ws1-probe-evil", probe_dir=str(evil_dir))


@pytest.mark.asyncio
async def test_get_auth_validation_log_missing_file_returns_empty(tmp_path):
    """块3b: events.ndjson 不存在（workflow 未落盘/未跑完）→ 返回 [] 而非抛错（前端显示暂无记录）。"""
    store = _store(tmp_path)
    mgr = _mgr(tmp_path, store)
    probe_dir = tmp_path / "ws1" / "auth-probes" / "probe-empty"
    probe_dir.mkdir(parents=True)
    events = await mgr.get_auth_validation_log(
        "ws1", workflow_id="authval-ws1-probe-empty", probe_dir=str(probe_dir))
    assert events == []


# ---- verify-events SSE（实时过程流，块4）----


@pytest.mark.asyncio
async def test_auth_validation_events_path_returns_ndjson_path(tmp_path):
    """verify-events 守卫：合法 probe_dir/workflow_id → 返回 resolved events.ndjson Path。"""
    store = _store(tmp_path)
    mgr = _mgr(tmp_path, store)
    probe_dir = tmp_path / "ws1" / "auth-probes" / "probe-ev"
    probe_dir.mkdir(parents=True)
    ndjson = await mgr.auth_validation_events_path(
        "ws1", workflow_id="authval-ws1-probe-ev", probe_dir=str(probe_dir))
    assert ndjson == probe_dir.resolve() / "events.ndjson"


@pytest.mark.asyncio
async def test_auth_validation_events_path_rejects_out_of_containment(tmp_path):
    """verify-events 守卫①：probe_dir 越界 → ValueError（防任意路径读 events，对齐 verify-log）。"""
    store = _store(tmp_path)
    mgr = _mgr(tmp_path, store)
    evil_dir = tmp_path / "evil"
    evil_dir.mkdir()
    with pytest.raises(ValueError, match="probe_dir 越界"):
        await mgr.auth_validation_events_path(
            "ws1", workflow_id="authval-ws1-probe-evil", probe_dir=str(evil_dir))


@pytest.mark.asyncio
async def test_auth_validation_events_path_rejects_bad_workflow_id(tmp_path):
    """verify-events 守卫②：workflow_id 不绑本 ws → ValueError（防跨 ws 读 events）。"""
    store = _store(tmp_path)
    mgr = _mgr(tmp_path, store)
    probe_dir = tmp_path / "ws1" / "auth-probes" / "probe-x"
    probe_dir.mkdir(parents=True)
    with pytest.raises(ValueError, match="workflow_id 越界"):
        await mgr.auth_validation_events_path(
            "ws1", workflow_id="authval-ws2-probe-x", probe_dir=str(probe_dir))


@pytest.mark.asyncio
async def test_build_verify_events_response_streams_until_scan_end(tmp_path):
    """verify-events SSE：tail events.ndjson，逐事件编码 SSE frame，遇 scan_end 关流终止。"""
    from supernova_web.api.events import build_verify_events_response

    ndjson = tmp_path / "events.ndjson"
    ndjson.write_text(
        '{"type":"PhaseEvent","event":"start","phase":"auth-validation"}\n'
        '{"type":"scan_end","status":"completed"}\n', "utf-8")
    response = await build_verify_events_response(ndjson)
    assert response.media_type == "text/event-stream"
    chunks = []
    async for chunk in response.body_iterator:
        chunks.append(chunk)
    body = "".join(chunks)
    assert "PhaseEvent" in body
    assert "scan_end" in body

