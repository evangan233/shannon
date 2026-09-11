"""blackbox activity 各路径的 agent_end end_reason（可观测性缺口修复）。

背景（memory audit-agent-end-success-blindspot）：黑盒 poc-agent-xss 4 次启动
agents log 全记 success=true（2026-09-02 NodeGoat 实证）——close 只有
{success, duration_ms}。与 whitebox run_agent 对齐：三路径都写真实结束原因。
"""

import pytest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from supernova_core.models.errors import ErrorCode, PentestError
from supernova_core.models.metrics import AgentMetrics
from supernova_core.services.validate_authentication import AuthValidationResult
from supernova_blackbox.pipeline.activities import (
    run_blackbox_auth_validation,
    run_endpoint_verify,
    run_exploit_agent,
)
from supernova_blackbox.pipeline.shared import BlackboxActivityInput


def _wire(monkeypatch, session, logger):
    monkeypatch.setattr(
        "supernova_blackbox.pipeline.activities.activity.info",
        lambda: SimpleNamespace(attempt=1, workflow_id="w"))
    monkeypatch.setattr(
        "supernova_blackbox.pipeline.activities.ensure_audit_session", AsyncMock())
    monkeypatch.setattr(
        "supernova_core.audit.session_registry.get_audit_session", lambda: session)
    monkeypatch.setattr(
        "supernova_core.audit.session_tool_audit_logger.SessionToolAuditLogger",
        MagicMock(return_value=logger))


def _session():
    session = MagicMock()
    session.start_agent = AsyncMock()
    session.end_agent = AsyncMock()
    session.log_error = AsyncMock()
    return session


def _logger():
    logger = MagicMock()
    logger.initialize = AsyncMock()
    logger.close = AsyncMock()
    return logger


@pytest.mark.asyncio
async def test_auth_validation_failed_verdict_end_reason(monkeypatch, tmp_path):
    """validate_authentication 正常返回 success=False → close end_reason='auth_login_failed'
    （对齐紧随的 PentestError AUTH_LOGIN_FAILED 语义）。"""
    session = _session()
    logger = _logger()
    _wire(monkeypatch, session, logger)

    with patch(
        "supernova_core.services.validate_authentication.validate_authentication",
        new=AsyncMock(return_value=AuthValidationResult(
            success=False, failure_point="username_or_password")),
    ):
        with pytest.raises(Exception):
            await run_blackbox_auth_validation(BlackboxActivityInput(
                web_url="http://t/", config_path="/c.yaml",
                workspace_path=str(tmp_path), repo_path=""))

    assert logger.close.call_args.kwargs.get("end_reason") == "auth_login_failed"


@pytest.mark.asyncio
async def test_exploit_success_truncated_end_reason(monkeypatch, tmp_path):
    """exploit 成功 + metrics.stop_reason=max_tokens（截断假成功场景）→
    close end_reason='truncated'。"""
    session = _session()
    logger = _logger()
    _wire(monkeypatch, session, logger)
    monkeypatch.setattr(
        "supernova_blackbox.pipeline.activities._get_deliverables_path",
        lambda i: tmp_path)
    monkeypatch.setattr(
        "supernova_blackbox.pipeline.activities._cleanup_browser_session", AsyncMock())

    metrics = AgentMetrics(duration_ms=1, cost_usd=0.0, num_turns=1, model="test",
                           stop_reason="max_tokens")
    exploit_executor = MagicMock()
    exploit_executor.execute = AsyncMock(return_value=metrics)

    async def _run():
        with patch("supernova_blackbox.agents.exploit_executor.ExploitExecutor",
                   MagicMock(return_value=exploit_executor)), \
             patch("supernova_blackbox.pipeline.activities.PromptManager", MagicMock()), \
             patch("supernova_blackbox.pipeline.activities.AgentExecutor", MagicMock()):
            await run_exploit_agent(BlackboxActivityInput(
                web_url="http://t/", config_path="/c.yaml",
                workspace_path=str(tmp_path), repo_path="",
                vuln_type="xss"))

    await _run()
    assert logger.close.call_args.kwargs.get("end_reason") == "truncated"


@pytest.mark.asyncio
async def test_exploit_pentest_error_end_reason(monkeypatch, tmp_path):
    """exploit PentestError → close end_reason=error_code 值。"""
    session = _session()
    logger = _logger()
    _wire(monkeypatch, session, logger)
    monkeypatch.setattr(
        "supernova_blackbox.pipeline.activities._get_deliverables_path",
        lambda i: tmp_path)
    monkeypatch.setattr(
        "supernova_blackbox.pipeline.activities._cleanup_browser_session", AsyncMock())

    exploit_executor = MagicMock()
    exploit_executor.execute = AsyncMock(side_effect=PentestError(
        "rate limited", "validation", retryable=True,
        error_code=ErrorCode.API_RATE_LIMITED))

    async def _run():
        with patch("supernova_blackbox.agents.exploit_executor.ExploitExecutor",
                   MagicMock(return_value=exploit_executor)), \
             patch("supernova_blackbox.pipeline.activities.PromptManager", MagicMock()), \
             patch("supernova_blackbox.pipeline.activities.AgentExecutor", MagicMock()):
            await run_exploit_agent(BlackboxActivityInput(
                web_url="http://t/", config_path="/c.yaml",
                workspace_path=str(tmp_path), repo_path="",
                vuln_type="xss"))

    with pytest.raises(Exception):
        await _run()
    assert logger.close.call_args.kwargs.get("end_reason") == "API_RATE_LIMITED"


@pytest.mark.asyncio
async def test_endpoint_verify_exception_end_reason(monkeypatch, tmp_path):
    """endpoint-verify 异常降级路径 → close end_reason='unexpected_error'。"""
    session = _session()
    logger = _logger()
    _wire(monkeypatch, session, logger)
    monkeypatch.setattr(
        "supernova_blackbox.pipeline.activities._get_deliverables_path",
        lambda i: tmp_path)
    monkeypatch.setattr(
        "supernova_blackbox.pipeline.activities._cleanup_browser_session", AsyncMock())

    verifier = MagicMock()
    verifier.execute = AsyncMock(side_effect=RuntimeError("boom"))

    async def _run():
        with patch("supernova_blackbox.agents.endpoint_verify_executor.EndpointVerifyExecutor",
                   MagicMock(return_value=verifier)), \
             patch("supernova_blackbox.pipeline.activities.PromptManager", MagicMock()), \
             patch("supernova_blackbox.pipeline.activities.AgentExecutor", MagicMock()):
            return await run_endpoint_verify(BlackboxActivityInput(
                web_url="http://t/", config_path="/c.yaml",
                workspace_path=str(tmp_path), repo_path=""))

    ret = await _run()  # 降级不 raise
    assert ret.get("endpoint_verify") is None
    assert logger.close.call_args.kwargs.get("end_reason") == "unexpected_error"
