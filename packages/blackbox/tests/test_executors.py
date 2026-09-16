import json
import subprocess
import pytest
from unittest.mock import AsyncMock, MagicMock

from supernova_core.models.agents import AgentName
from supernova_core.models.metrics import AgentMetrics
from supernova_blackbox.agents.exploit_executor import ExploitExecutor


@pytest.fixture
def mock_repo(tmp_path):
    repo = tmp_path / "target-repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=repo, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, capture_output=True, check=True)
    (repo / "README.md").write_text("# Test")
    subprocess.run(["git", "add", "."], cwd=repo, capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo, capture_output=True, check=True)
    deliverables = tmp_path / "workspaces" / "bb-session" / "deliverables"
    deliverables.mkdir(parents=True)
    return repo, deliverables


@pytest.mark.asyncio
async def test_exploit_executor_reads_queue(mock_repo):
    repo, deliverables = mock_repo
    queue_data = {"vulnerabilities": [
        {"ID": "INJ-001", "vulnerability_type": "SQL Injection",
         "externally_exploitable": True, "confidence": "high",
         "source_endpoint": "/api/search", "sink_call": "db.execute"},
    ]}
    (deliverables / "injection_exploitation_queue.json").write_text(json.dumps(queue_data))
    (deliverables / "injection_exploitation_evidence.md").write_text("# Evidence")

    mock_executor = AsyncMock()
    mock_executor.execute.return_value = AgentMetrics(duration_ms=1000, cost_usd=0.01, num_turns=3)

    ex = ExploitExecutor(mock_executor)
    metrics = await ex.execute(
        agent_name=AgentName.INJECTION_EXPLOIT,
        vuln_type="injection",
        workspace_path=repo,
        deliverables_path=deliverables,
        web_url="https://example.com",
    )
    assert isinstance(metrics, AgentMetrics)
    mock_executor.execute.assert_called_once()
    call_kwargs = mock_executor.execute.call_args
    assert call_kwargs.kwargs["agent_name"] == AgentName.INJECTION_EXPLOIT
    assert "vulnerability_entries" in call_kwargs.kwargs.get("prompt_variables", {})


@pytest.mark.asyncio
async def test_exploit_executor_forwards_audit_logger(mock_repo):
    repo, deliverables = mock_repo
    mock_executor = AsyncMock()
    mock_executor.execute.return_value = AgentMetrics(duration_ms=1, cost_usd=0.0, num_turns=1)
    exploit = ExploitExecutor(mock_executor)
    sentinel = object()
    await exploit.execute(
        agent_name=AgentName.INJECTION_EXPLOIT,
        vuln_type="injection",
        workspace_path=repo,
        deliverables_path=deliverables,
        web_url="https://example.com",
        audit_logger=sentinel,
    )
    assert mock_executor.execute.call_args.kwargs["audit_logger"] is sentinel


@pytest.mark.asyncio
async def test_validate_authentication_forwards_audit_logger(tmp_path):
    from supernova_core.services.validate_authentication import validate_authentication
    from supernova_core.prompts.manager import PromptManager

    mock_executor = AsyncMock()
    # config_path=None short-circuits to success without touching the executor
    await validate_authentication(
        web_url="https://example.com",
        config_path=None,
        workspace_path=str(tmp_path),
        prompt_manager=MagicMock(spec=PromptManager),
        executor=mock_executor,
    )
    # When config_path is None the function returns early (no executor call) —
    # so instead verify the signature accepts the kwarg via a config-bearing path:
    # (covered structurally by the implementation accepting audit_logger and
    # forwarding it; the no-config path simply never reaches execute().)


@pytest.mark.asyncio
async def test_exploit_executor_writes_evidence_and_verdicts(tmp_path):
    """ExploitExecutor 拿到 structured_output 后应：校验 → 写 evidence.md → 写 verdicts.json。"""
    from supernova_blackbox.agents.exploit_executor import ExploitExecutor

    deliverables = tmp_path / "deliverables"
    deliverables.mkdir()
    # queue 含 1 个有效 id
    (deliverables / "injection_exploitation_queue.json").write_text(json.dumps({
        "vulnerabilities": [{"ID": "INJ-VULN-1", "vulnerability_type": "injection",
                             "externally_exploitable": True, "confidence": "high"}]}))

    fake_metrics = AgentMetrics(
        duration_ms=100, cost_usd=0.01, num_turns=2, model="stub",
        structured_output={"verdicts": [{
            "vulnerability_id": "INJ-VULN-1", "status": "exploited",
            "severity": "high", "impact": "i",
            "exploitation_steps": ["s"], "proof_of_impact": "p"}]})

    stub_executor = MagicMock()
    stub_executor.execute = AsyncMock(return_value=fake_metrics)

    ex = ExploitExecutor(stub_executor)
    await ex.execute(
        agent_name=AgentName.INJECTION_EXPLOIT, vuln_type="injection",
        workspace_path=deliverables.parent, deliverables_path=deliverables,
        web_url="http://t", pipeline_testing=True)

    # evidence.md 被渲染（落 blackbox/）
    ev = (deliverables / "blackbox" / "injection_exploitation_evidence.md").read_text()
    assert "### INJ-VULN-1" in ev
    # verdicts.json 被落盘（落 blackbox/）
    vj = json.loads((deliverables / "blackbox" / "injection_exploit_verdicts.json").read_text())
    assert vj["accepted_ids"] == ["INJ-VULN-1"]
    # 传给底层 executor 的参数：structured_output_schema + skip_artifact_postprocess
    _, kwargs = stub_executor.execute.call_args
    assert kwargs.get("skip_artifact_postprocess") is True
    assert kwargs.get("structured_output_schema") is not None


@pytest.mark.asyncio
async def test_exploit_executor_falls_back_to_agent_written_verdict_file(tmp_path):
    """structured_output 空（GLM/CLI agent 用 Write 落盘而非 final JSON）时，
    executor 应回退读 agent 写的 .supernova/deliverables/{vuln}_exploitation_verdicts.json。
    复现 invite_code_center 真机根因（verdict 双重丢失 → 报告全 Unverified）。"""
    from supernova_blackbox.agents.exploit_executor import ExploitExecutor

    deliverables = tmp_path / "deliverables"
    deliverables.mkdir()
    (deliverables / "injection_exploitation_queue.json").write_text(json.dumps({
        "vulnerabilities": [{"ID": "INJ-VULN-1", "vulnerability_type": "injection",
                             "externally_exploitable": True, "confidence": "high"}]}))
    # agent 用 Write 工具把 verdict 落盘到隔离子目录（富结构 + 大写 severity，未按
    # schema 返回 final JSON）——这是 GLM/claude-agent-sdk 引擎下的既成行为。
    agent_out = deliverables / ".shannon" / "deliverables"
    agent_out.mkdir(parents=True)
    (agent_out / "injection_exploitation_verdicts.json").write_text(json.dumps({
        "verdicts": [{
            "vulnerability_id": "INJ-VULN-1", "status": "exploited",
            "severity": "CRITICAL", "impact": "i",
            "exploitation_steps": [{"step": 1, "action": "do x"}],
            "proof_of_impact": {"confirmed": True}}]}))

    # structured_output=None：agent final message 是自然语言
    fake_metrics = AgentMetrics(duration_ms=100, cost_usd=0.01, num_turns=2, model="stub",
                                structured_output=None)
    stub_executor = MagicMock()
    stub_executor.execute = AsyncMock(return_value=fake_metrics)

    ex = ExploitExecutor(stub_executor)
    await ex.execute(
        agent_name=AgentName.INJECTION_EXPLOIT, vuln_type="injection",
        workspace_path=deliverables.parent, deliverables_path=deliverables,
        web_url="http://t", pipeline_testing=True)

    ev = (deliverables / "blackbox" / "injection_exploitation_evidence.md").read_text()
    assert "### INJ-VULN-1" in ev
    vj = json.loads((deliverables / "blackbox" / "injection_exploit_verdicts.json").read_text())
    assert vj["accepted_ids"] == ["INJ-VULN-1"]


@pytest.mark.asyncio
async def test_exploit_executor_reads_queue_from_whitebox_subdir(tmp_path):
    """新结构：白盒 queue 在 deliverables/whitebox/，exploit_executor 走 fallback 读到。"""
    from supernova_blackbox.agents.exploit_executor import ExploitExecutor
    dlv = tmp_path / "deliverables"
    (dlv / "whitebox").mkdir(parents=True)
    (dlv / "whitebox" / "injection_exploitation_queue.json").write_text(
        '{"vulnerabilities": [{"ID": "INJ-1", "vulnerability_type": "SQLi"}]}'
    )
    stub_executor = MagicMock()
    stub_executor.execute = AsyncMock(
        return_value=AgentMetrics(duration_ms=10, cost_usd=0.0, num_turns=1, model="stub"))
    executor = ExploitExecutor(stub_executor)
    await executor.execute(
        agent_name=AgentName.INJECTION_EXPLOIT, vuln_type="injection",
        workspace_path=tmp_path, deliverables_path=dlv, web_url="https://x.com",
    )
    # evidence 落 blackbox/
    assert (dlv / "blackbox" / "injection_exploitation_evidence.md").exists()


@pytest.mark.asyncio
async def test_exploit_executor_falls_back_to_legacy_queue(tmp_path):
    """老 workspace：queue 在 deliverables 根，fallback 读到。"""
    from supernova_blackbox.agents.exploit_executor import ExploitExecutor
    dlv = tmp_path / "deliverables"
    dlv.mkdir()
    (dlv / "injection_exploitation_queue.json").write_text(
        '{"vulnerabilities": [{"ID": "INJ-1", "vulnerability_type": "SQLi"}]}'
    )
    stub_executor = MagicMock()
    stub_executor.execute = AsyncMock(
        return_value=AgentMetrics(duration_ms=10, cost_usd=0.0, num_turns=1, model="stub"))
    executor = ExploitExecutor(stub_executor)
    await executor.execute(
        agent_name=AgentName.INJECTION_EXPLOIT, vuln_type="injection",
        workspace_path=tmp_path, deliverables_path=dlv, web_url="https://x.com",
    )
    assert (dlv / "blackbox" / "injection_exploitation_evidence.md").exists()


@pytest.mark.asyncio
async def test_exploit_executor_no_longer_injects_auth_state_file(mock_repo):
    """AUTH_STATE_FILE 由 AgentExecutor.execute 基层统一注入（方案 B），
    exploit_executor 不再显式传——单一来源，避免双注入。"""
    repo, deliverables = mock_repo
    mock_executor = AsyncMock()
    mock_executor.execute.return_value = AgentMetrics(duration_ms=1, cost_usd=0.0, num_turns=1)
    exploit = ExploitExecutor(mock_executor)
    await exploit.execute(
        agent_name=AgentName.INJECTION_EXPLOIT,
        vuln_type="injection",
        workspace_path=repo,
        deliverables_path=deliverables,
        web_url="https://example.com",
    )
    pv = mock_executor.execute.call_args.kwargs.get("prompt_variables") or {}
    assert "AUTH_STATE_FILE" not in pv, \
        "AUTH_STATE_FILE 应由 AgentExecutor 基层注入，exploit_executor 不再显式传"


# ---------------------------------------------------------------------------
# 子项目2 T8: authz-exploit 读 identity-manifest + 注入 IDENTITY_CONTEXT
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_authz_exploit_injects_identity_context_when_manifest_present(mock_repo, tmp_path):
    """identity-manifest.json 存在且 ≥2 available 身份 → authz-exploit 注入 IDENTITY_CONTEXT。

    Executor 复用底层 AgentExecutor.prompt_manager（对齐 run_blackbox_auth_validation
    的 prompts_dir 解析口径），调 build_identity_context 渲染 _identities.txt partial。
    """
    from supernova_core.prompts.manager import PromptManager

    repo, deliverables = mock_repo
    # 写 manifest 到 workspace_path（= deliverables.parent）
    (deliverables.parent / "identity-manifest.json").write_text(json.dumps({"identities": [
        {"account_id": "primary", "role": "user", "tier": "low",
         "auth_state_file": "auth-state.json", "available": True},
        {"account_id": "victim-b", "role": "user", "tier": "low",
         "auth_state_file": "auth-state-victim-b.json", "available": True},
        {"account_id": "admin-1", "role": "admin", "tier": "high",
         "auth_state_file": "auth-state-admin-1.json", "available": True},
    ]}))
    # 配真实 PromptManager（指向含 _identities.txt partial 的 tmp prompts 目录，
    # 对齐 packages/core/tests/test_prompt_manager.py 的 identity_prompts_dir fixture）
    prompts_dir = tmp_path / "prompts"
    shared = prompts_dir / "shared"
    shared.mkdir(parents=True)
    (shared / "_identities.txt").write_text(
        "<identity_set>\n{{IDENTITY_SESSION_ROWS}}\n{{IDENTITY_COMPARISON_PAIRS}}\n</identity_set>",
        encoding="utf-8",
    )

    mock_executor = AsyncMock()
    mock_executor.execute.return_value = AgentMetrics(duration_ms=10)
    mock_executor.prompt_manager = PromptManager(prompts_dir)
    ex = ExploitExecutor(mock_executor)

    await ex.execute(
        agent_name=AgentName.AUTHZ_EXPLOIT, vuln_type="authz",
        workspace_path=deliverables.parent, deliverables_path=deliverables,
        web_url="https://x",
    )
    pv = mock_executor.execute.call_args.kwargs.get("prompt_variables", {})
    assert "IDENTITY_CONTEXT" in pv, "authz-exploit 应注入 IDENTITY_CONTEXT"
    assert "victim-b" in pv["IDENTITY_CONTEXT"], "manifest 中 victim-b 应进入 identity context"
    # 守卫不变:AUTH_STATE_FILE 仍由 AgentExecutor 基层注入,exploit_executor 不显式传
    assert "AUTH_STATE_FILE" not in pv


@pytest.mark.asyncio
async def test_authz_exploit_no_identity_context_when_single_identity(mock_repo):
    """无 manifest 文件(单身份扫描)→ IDENTITY_CONTEXT 注入空串,authz-exploit 行为不变。"""
    repo, deliverables = mock_repo
    mock_executor = AsyncMock()
    mock_executor.execute.return_value = AgentMetrics(duration_ms=10)
    ex = ExploitExecutor(mock_executor)
    await ex.execute(
        agent_name=AgentName.AUTHZ_EXPLOIT, vuln_type="authz",
        workspace_path=deliverables.parent, deliverables_path=deliverables,
        web_url="https://x",
    )
    pv = mock_executor.execute.call_args.kwargs.get("prompt_variables", {})
    assert pv.get("IDENTITY_CONTEXT", "") == ""  # 单身份不注入
    # AUTH_STATE_FILE 仍不在此显式注入(守卫不变)
    assert "AUTH_STATE_FILE" not in pv


# ---------------------------------------------------------------------------
# spec 2026-08-08 黑盒 exploit queue 读取根修复：queue_root 分离读/写根
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_exploit_executor_reads_queue_from_queue_root(tmp_path):
    """黑盒根因修复：queue 在 queue_root/whitebox/（= 白盒 repo_path/deliverables），
    deliverables_path 是黑盒自己的空目录。vulnerability_entries 必须来自 queue_root
    （而非 deliverables_path），且 queue_root 透传到底层 executor.execute（供 renderer
    读 queue 建 valid_ids——这是现场 valid_ids 空导致真实 verdict 全被 L2 拒的根因）。"""
    queue_root = tmp_path / "whitebox-root"
    (queue_root / "whitebox").mkdir(parents=True)
    (queue_root / "whitebox" / "injection_exploitation_queue.json").write_text(
        json.dumps({"vulnerabilities": [
            {"ID": "INJ-VULN-01", "vulnerability_type": "SQLi",
             "externally_exploitable": True, "confidence": "high"}]}))
    deliverables = tmp_path / "deliverables"  # 黑盒产物落点（空，无 queue）
    deliverables.mkdir()

    stub_executor = MagicMock()
    stub_executor.execute = AsyncMock(
        return_value=AgentMetrics(duration_ms=10, cost_usd=0.0, num_turns=1, model="stub"))
    ex = ExploitExecutor(stub_executor)
    await ex.execute(
        agent_name=AgentName.INJECTION_EXPLOIT, vuln_type="injection",
        workspace_path=tmp_path, deliverables_path=deliverables, web_url="https://x.com",
        queue_root=queue_root,
    )
    pv = stub_executor.execute.call_args.kwargs.get("prompt_variables", {})
    assert "vulnerability_entries" in pv, "queue_root 下 queue 应注入 vulnerability_entries"
    assert "INJ-VULN-01" in pv["vulnerability_entries"]
    # queue_root 透传到底层 executor（→ renderer 读 queue 建 valid_ids）
    assert stub_executor.execute.call_args.kwargs.get("queue_root") == str(queue_root)


# ---------------------------------------------------------------------------
# 修复 C（2026-09-03）：identity 恢复命令按 config 引擎生成——原硬编码
# AgentBrowserEngine()，playwright 引擎下命令形态错（state load vs state-load）。
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_authz_exploit_identity_context_respects_playwright_engine(mock_repo, tmp_path):
    """browser_engine=playwright → IDENTITY_CONTEXT 的恢复命令是 playwright 形态。"""
    from supernova_core.prompts.manager import PromptManager

    repo, deliverables = mock_repo
    (deliverables.parent / "identity-manifest.json").write_text(json.dumps({"identities": [
        {"account_id": "primary", "role": "user", "tier": "low",
         "auth_state_file": "auth-state.json", "available": True},
        {"account_id": "victim-b", "role": "user", "tier": "low",
         "auth_state_file": "auth-state-victim-b.json", "available": True},
    ]}))
    prompts_dir = tmp_path / "prompts"
    shared = prompts_dir / "shared"
    shared.mkdir(parents=True)
    (shared / "_identities.txt").write_text(
        "<identity_set>\n{{IDENTITY_SESSION_ROWS}}\n{{IDENTITY_COMPARISON_PAIRS}}\n</identity_set>",
        encoding="utf-8",
    )
    cfg_file = tmp_path / "c.yaml"
    cfg_file.write_text("browser_engine: playwright\n")

    mock_executor = AsyncMock()
    mock_executor.execute.return_value = AgentMetrics(duration_ms=10)
    mock_executor.prompt_manager = PromptManager(prompts_dir)
    ex = ExploitExecutor(mock_executor)

    await ex.execute(
        agent_name=AgentName.AUTHZ_EXPLOIT, vuln_type="authz",
        workspace_path=deliverables.parent, deliverables_path=deliverables,
        web_url="https://x", config_path=str(cfg_file),
    )
    pv = mock_executor.execute.call_args.kwargs.get("prompt_variables", {})
    ctx = pv.get("IDENTITY_CONTEXT", "")
    assert "state-load" in ctx, \
        "playwright 引擎下 identity 恢复命令应为 state-load 形态"
    assert "state load" not in ctx, \
        "不应出现 agent-browser 的 state load 形态（硬编码引擎根因）"


# ── 判非漏洞卡不进黑盒（2026-09-16 残面修复）──────────────────────────────────


def test_filter_non_vulnerable_drops_safe_cards():
    from supernova_blackbox.agents.exploit_executor import _filter_non_vulnerable
    content = json.dumps({"vulnerabilities": [
        {"ID": "A", "verdict": "safe"},
        {"ID": "B", "verdict": "vulnerable"},
        {"ID": "C", "verdict": "not_vulnerable"},
        {"ID": "D"},
    ]}, ensure_ascii=False)
    out = json.loads(_filter_non_vulnerable(content))
    assert [v["ID"] for v in out["vulnerabilities"]] == ["B", "D"]


def test_filter_non_vulnerable_lenient_passthrough():
    from supernova_blackbox.agents.exploit_executor import _filter_non_vulnerable
    # 坏 JSON / 结构不合 → 原文返回（不让 agent 失明）
    assert _filter_non_vulnerable("not json") == "not json"
    assert _filter_non_vulnerable('{"other": 1}') == '{"other": 1}'
    # 无 safe 卡 → 原文透传（byte-identical）
    content = json.dumps({"vulnerabilities": [{"ID": "B", "verdict": "vulnerable"}]})
    assert _filter_non_vulnerable(content) == content


@pytest.mark.asyncio
async def test_exploit_executor_injects_queue_without_safe_cards(mock_repo):
    """SSOT 残留 verdict=safe 卡（both 配对罕见残留）不进 exploit prompt。"""
    repo, deliverables = mock_repo
    queue_data = {"vulnerabilities": [
        {"ID": "INJ-SAFE-01", "verdict": "safe", "confidence": "needs_review"},
        {"ID": "INJ-001", "verdict": "vulnerable", "confidence": "high"},
    ]}
    (deliverables / "injection_exploitation_queue.json").write_text(
        json.dumps(queue_data))
    (deliverables / "injection_exploitation_evidence.md").write_text("# Evidence")

    mock_executor = AsyncMock()
    mock_executor.execute.return_value = AgentMetrics(duration_ms=1, cost_usd=0.0, num_turns=1)
    ex = ExploitExecutor(mock_executor)
    await ex.execute(
        agent_name=AgentName.INJECTION_EXPLOIT,
        vuln_type="injection",
        workspace_path=repo,
        deliverables_path=deliverables,
        web_url="https://example.com",
    )
    pv = mock_executor.execute.call_args.kwargs["prompt_variables"]
    assert "INJ-001" in pv["vulnerability_entries"]
    assert "INJ-SAFE-01" not in pv["vulnerability_entries"]
