"""run_gitnexus_verdict_agent 的 finally close 传 end_reason。

2026-09-09 client-release-frontend 实证：gitnexus-verdict 撞 max_turns=30，
agents log 的 agent_end 仍写 success=true（close 保守值）且无任何结束原因。
close 的 success 保守值保留（best-effort 层），但 end_reason 必须带上
result.stop_reason 的归一值——截断/撞顶在 per-agent log 可见。
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from supernova_core.agents.runner import ClaudeRunResult
from supernova_whitebox.pipeline import activities


@pytest.mark.asyncio
async def test_verdict_close_carries_stop_reason_end_reason():
    """run_claude_prompt 正常返回（success=True, stop_reason=max_turns）→
    finally 的 close 带 end_reason='max_turns'。"""
    logger = MagicMock()
    logger.initialize = AsyncMock()
    logger.close = AsyncMock()
    audit_session = MagicMock()
    audit_session.start_agent = AsyncMock()
    audit_session.end_agent = AsyncMock()

    result = ClaudeRunResult(text="...", success=True, stop_reason="max_turns", turns=30)

    async def fake_run_claude_prompt(**kwargs):
        return result

    with patch("supernova_core.agents.runner.run_claude_prompt",
               side_effect=fake_run_claude_prompt), \
         patch("supernova_whitebox.audit.session_tool_audit_logger.SessionToolAuditLogger",
               return_value=logger):
        got = await activities.run_gitnexus_verdict_agent(
            prompt="p", repo_path="/tmp/repo",
            audit_session=audit_session, provider_config=None)

    assert got is result
    kwargs = logger.close.call_args.kwargs
    assert kwargs.get("end_reason") == "max_turns"


@pytest.mark.asyncio
async def test_verdict_close_end_reason_none_on_normal_end():
    logger = MagicMock()
    logger.initialize = AsyncMock()
    logger.close = AsyncMock()
    audit_session = MagicMock()
    audit_session.start_agent = AsyncMock()
    audit_session.end_agent = AsyncMock()

    result = ClaudeRunResult(text="...", success=True, stop_reason="end_turn", turns=5)

    async def fake_run_claude_prompt(**kwargs):
        return result

    with patch("supernova_core.agents.runner.run_claude_prompt",
               side_effect=fake_run_claude_prompt), \
         patch("supernova_whitebox.audit.session_tool_audit_logger.SessionToolAuditLogger",
               return_value=logger):
        await activities.run_gitnexus_verdict_agent(
            prompt="p", repo_path="/tmp/repo",
            audit_session=audit_session, provider_config=None)

    assert logger.close.call_args.kwargs.get("end_reason") is None
