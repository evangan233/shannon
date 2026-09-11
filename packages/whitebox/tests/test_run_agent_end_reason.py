"""run_agent 三路径的 agent_end end_reason 传递（可观测性缺口修复）。

背景（memory audit-agent-end-success-blindspot）：agents log 的 agent_end 只有
{success, duration_ms}——success=True 时截断（max_tokens）不可见、success=False
时失败类别（429/timeout/max_turns）不可见。三路径都应把真实结束原因写进
agent_end.end_reason：
- 成功路径：end_reason_from_stop_reason(metrics.stop_reason)（截断/max_turns 检测）
- PentestError 路径：error_code 值（API_RATE_LIMITED / SPENDING_CAP_REACHED / …）
- 通用 Exception 路径："unexpected_error"
"""

from contextlib import ExitStack
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from supernova_core.models.errors import ErrorCode, PentestError
from supernova_core.models.metrics import AgentMetrics
from supernova_whitebox.pipeline import activities


def _runtime_patches(metrics=None, exc: Exception | None = None):
    session = MagicMock()
    session.start_agent = AsyncMock()
    session.end_agent = AsyncMock()
    session.log_error = AsyncMock()

    logger = MagicMock()
    logger.initialize = AsyncMock()
    logger.close = AsyncMock()

    if exc is not None:
        async def fake_execute(**kwargs):
            raise exc
    else:
        async def fake_execute(**kwargs):
            return metrics or AgentMetrics(duration_ms=1, cost_usd=0.0, num_turns=1, model="test")

    executor = MagicMock()
    executor.execute = fake_execute

    return logger, (
        patch.object(activities.activity, "info", return_value=MagicMock(attempt=1)),
        patch("supernova_whitebox.audit.session_registry.get_audit_session", return_value=session),
        patch("supernova_whitebox.audit.session_tool_audit_logger.SessionToolAuditLogger", return_value=logger),
        patch.object(activities, "AgentExecutor", return_value=executor),
    )


def _fake_input():
    class FakeInput:
        agent_name = "recon"
        web_url = None
        repo_path = "/tmp/repo"
        config_path = None
        api_key = None
        pipeline_testing_mode = False
        prompt_override = None
        workspace_name = "ws"
        provider_config = None
        mr_meta = None
    return FakeInput()


async def _run(input_obj, metrics=None, exc=None):
    logger, patches = _runtime_patches(metrics=metrics, exc=exc)
    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)
        try:
            await activities.run_agent(input_obj)
        except Exception:
            pass  # 失败路径按预期抛 ApplicationFailure，这里只验证 close 传参
    return logger


def _make_repo(tmp_path):
    deliverables = tmp_path / "deliverables"
    deliverables.mkdir(exist_ok=True)
    (deliverables / "code_index.json").write_text("{}")
    return deliverables


@pytest.mark.asyncio
async def test_success_truncated_stop_reason_reaches_close(tmp_path):
    """成功 + stop_reason=max_tokens（截断假成功场景）→ close 收到 end_reason='truncated'。"""
    deliverables = _make_repo(tmp_path)
    metrics = AgentMetrics(duration_ms=1, cost_usd=0.0, num_turns=1, model="test",
                           stop_reason="max_tokens")
    with patch.object(activities, "_get_paths", return_value=(tmp_path, deliverables, tmp_path)):
        logger = await _run(_fake_input(), metrics=metrics)
    assert logger.close.call_args.kwargs.get("end_reason") == "truncated"


@pytest.mark.asyncio
async def test_success_normal_end_reason_none(tmp_path):
    """正常完成（stop_reason=None/end_turn）→ end_reason=None。"""
    deliverables = _make_repo(tmp_path)
    with patch.object(activities, "_get_paths", return_value=(tmp_path, deliverables, tmp_path)):
        logger = await _run(_fake_input())
    assert logger.close.call_args.kwargs.get("end_reason") is None


@pytest.mark.asyncio
async def test_pentest_error_end_reason_is_error_code(tmp_path):
    """PentestError 路径 → close 收到 error_code 值（失败类别可见）。"""
    deliverables = _make_repo(tmp_path)
    exc = PentestError("rate limited", "validation", retryable=True,
                       error_code=ErrorCode.API_RATE_LIMITED)
    with patch.object(activities, "_get_paths", return_value=(tmp_path, deliverables, tmp_path)):
        logger = await _run(_fake_input(), exc=exc)
    assert logger.close.call_args.kwargs.get("end_reason") == "API_RATE_LIMITED"


@pytest.mark.asyncio
async def test_unexpected_exception_end_reason(tmp_path):
    """通用 Exception 路径 → end_reason='unexpected_error'。"""
    deliverables = _make_repo(tmp_path)
    with patch.object(activities, "_get_paths", return_value=(tmp_path, deliverables, tmp_path)):
        logger = await _run(_fake_input(), exc=RuntimeError("boom"))
    assert logger.close.call_args.kwargs.get("end_reason") == "unexpected_error"
