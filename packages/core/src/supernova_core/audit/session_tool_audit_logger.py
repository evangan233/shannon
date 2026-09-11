"""SessionToolAuditLogger — bridges core ToolAuditLogger events to AuditSession.

Holds per-agent state (agent_name + AgentLogger) so concurrent agents never race
on shared session fields. The MessageDispatcher/StreamCollector call
log_assistant_turn/log_tool_start/etc.; this logger routes each event to its own
per-agent JSON log AND to the shared workflow log with explicit agent attribution.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from supernova_core.agents.tool_audit_logger import ToolAuditLogger
from supernova_core.audit.agent_logger import AgentLogger

if TYPE_CHECKING:
    from .session import AuditSession


class _NullAgentLogger:
    """No-op AgentLogger stand-in：session 未绑定（NullAuditSession）时用。

    NullAuditSession 按设计只镜像 AuditSession 的公开方法、不暴露私有 ``_meta``
    （SessionMetadata 实例，Null 无对应物）。故 ``AgentLogger(session._meta)`` 在 Null
    上会 AttributeError。此 stand-in 镜像 AgentLogger 被 SessionToolAuditLogger 用到的
    公开面（initialize/log_event/close），使审计调用 no-op、业务逻辑继续——审计是日志层，
    session 缺失不应崩在 agent 启动前（曾致 temporal retry 无效 + activity_failures.log
    噪音，2026-07-22 NodeGoat_1784743576）。
    """

    async def initialize(self) -> None: pass
    async def log_event(self, event_type: str, event_data: Any) -> None: pass
    async def close(self) -> None: pass


class SessionToolAuditLogger(ToolAuditLogger):
    def __init__(self, session: "AuditSession", agent_name: str, attempt: int = 1) -> None:
        self._session = session
        self._agent_name = agent_name
        # NullAuditSession 不暴露私有 _meta（只镜像公开方法）→ 用 no-op logger，使审计调用
        # no-op、业务逻辑继续（getattr 解耦，免 import NullAuditSession）。
        meta = getattr(session, "_meta", None)
        self._agent_logger = (
            AgentLogger(meta, agent_name, attempt) if meta is not None else _NullAgentLogger()
        )

    async def initialize(self) -> None:
        """Open the per-agent JSON log and write its header + agent_start event."""
        await self._agent_logger.initialize()

    async def log_tool_start(self, tool_name: str, parameters: Any) -> None:
        await self._agent_logger.log_event("tool_start", {"toolName": tool_name, "parameters": parameters})
        await self._session.log_tool_call(self._agent_name, tool_name, parameters)

    async def log_tool_end(self, result: Any) -> None:
        # tool_end has no workflow.log surface; recorded to the per-agent JSON only.
        await self._agent_logger.log_event("tool_end", {"result": str(result)[:200]})

    async def log_assistant_turn(self, turn: int, content: str) -> None:
        await self._agent_logger.log_event("llm_response", {"turn": turn, "content": content})
        await self._session.log_llm_turn(self._agent_name, turn, content)

    async def log_error(self, error: str, *, turn_count: int = 0, duration_ms: int = 0) -> None:
        await self._session.log_error(
            RuntimeError(error), context=f"turn={turn_count}, {duration_ms}ms")

    async def close(self, success: bool, duration_ms: int,
                    end_reason: str | None = None) -> None:
        """Write agent_end to the per-agent JSON log and close its stream.

        end_reason：真实结束原因（truncated/max_turns/max_duration/refusal/
        ErrorCode 值/unexpected_error），独立于 success——success 在截断/限流
        等场景不可信（memory audit-agent-end-success-blindspot），正常完成为
        None。键恒写（None 也写），消费方统一读键。
        """
        await self._agent_logger.log_event(
            "agent_end",
            {"success": success, "duration_ms": duration_ms,
             "end_reason": end_reason})
        await self._agent_logger.close()
