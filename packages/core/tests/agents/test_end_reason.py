"""stop_reason → end_reason 归一化（agent_end 可观测性缺口修复）。

背景（memory audit-agent-end-success-blindspot）：agents log 的 agent_end
success=true 在截断/max_turns 下撒谎（2026-09-02 NodeGoat poc-agent 假成功、
2026-09-09 client-release-frontend gitnexus-verdict 撞顶全记 success）。
end_reason 是独立于 success 的真实结束原因，语义映射复用
providers_anthropic._STOP_REASON_HINTS 的已知值域。
"""

import pytest

from supernova_core.models.metrics import end_reason_from_stop_reason


@pytest.mark.parametrize("stop_reason,expected", [
    # 截断（memory 实证的「响应截断假成功」主力来源：anthropic max_tokens）
    ("max_tokens", "truncated"),
    ("max_turns", "max_turns"),
    ("max_duration", "max_duration"),
    ("refusal", "refusal"),
    # 良性/正常完成 → None（end_reason 缺席 = 正常结束）
    ("end_turn", None),
    ("stop_sequence", None),
    (None, None),
    ("", None),
    # 未知值原样透传（诊断价值优先，不吞信号）
    ("weird_budget_stop", "weird_budget_stop"),
])
def test_end_reason_from_stop_reason(stop_reason, expected):
    assert end_reason_from_stop_reason(stop_reason) == expected
