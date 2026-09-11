from pydantic import BaseModel

# stop_reason → end_reason 归一映射（良性值 → None，语义值见键）。
# 已知值域与 providers_anthropic._STOP_REASON_HINTS 对齐；未知值原样透传
# （诊断价值优先，不吞信号）。消费方：run_agent / run_gitnexus_verdict_agent
# 的 agent_end.end_reason（memory audit-agent-end-success-blindspot 缺口）。
_BENIGN_STOP_REASONS = frozenset({"end_turn", "stop_sequence", "", None})
_STOP_REASON_TO_END_REASON = {
    "max_tokens": "truncated",
    "max_turns": "max_turns",
    "max_duration": "max_duration",
    "refusal": "refusal",
}


def end_reason_from_stop_reason(stop_reason: str | None) -> str | None:
    """SDK stop_reason → 语义 end_reason；正常完成返回 None。

    "max_tokens" 映射 "truncated"（单次响应输出截断——anthropic 引擎截断时
    success 仍 True 的假成功主力来源，2026-09-02 NodeGoat poc-agent 实证）。
    """
    if stop_reason in _BENIGN_STOP_REASONS:
        return None
    return _STOP_REASON_TO_END_REASON.get(stop_reason, stop_reason)


class AgentMetrics(BaseModel):
    duration_ms: int
    input_tokens: int | None = None
    output_tokens: int | None = None
    cache_read_tokens: int | None = None
    cache_creation_tokens: int | None = None
    cost_usd: float | None = None
    cost_currency: str = "USD"
    num_turns: int | None = None
    model: str | None = None
    structured_output: dict | None = None
    stop_reason: str | None = None

class SessionMetadata(BaseModel):
    model_config = {"extra": "allow"}
    id: str
    web_url: str | None = None
    repo_path: str | None = None
    output_path: str | None = None
