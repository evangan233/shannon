"""联动编排器层进度事件 writer：把 repo/phase/edge 级状态写到 correlation workspace 的 ndjson。

asyncio.Lock 保护 append（多 repo 顺序 + edge 并发需串行化）。
edge 内部 agent 细粒度事件经 EdgeAgentEventLogger（2026-09-10）落同文件——executor 的
tool_audit_logger 钩子转标准事件形状（AgentEvent/ToolCallEvent/LlmTurnEvent/ErrorEvent），
前端 LogStream/顶部概览零改动渲染。
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiofiles

from supernova_core.agents.tool_audit_logger import ToolAuditLogger

# edge() 层单点映射：orchestrator 透传的 raw edge 状态（TopologyEdge.status）
# → spec L469 钉死的硬契约状态（started|completed|failed）。
# repo()/phase()/scan_end() 已用 spec 值，不动。
# TopologyEdge.status 允许 ok|low|unverified|error|declared-missing（schemas.py:31），
# 全量映射：ok/unverified→completed；low/error/declared-missing→failed（low 信任
# 判定为未通过；raw 仍进 detail 保信息）。
_EDGE_STATUS_MAP = {
    "ok": "completed",
    "unverified": "completed",
    "low": "failed",
    "error": "failed",
    "declared-missing": "failed",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class CorrelationEventWriter:
    def __init__(self, ndjson_path: Path) -> None:
        self._path = Path(ndjson_path)
        self._lock = asyncio.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)

    async def _append(self, payload: dict) -> None:
        async with self._lock:
            async with aiofiles.open(self._path, "a") as fh:
                await fh.write(json.dumps(payload, ensure_ascii=False) + "\n")
                await fh.flush()

    async def raw(self, payload: dict) -> None:
        """通用 ndjson 通道（补 ts + 同锁串行）：EdgeAgentEventLogger 专用。

        形状契约由调用方保证：对齐 core StructuredEventRenderer 的序列化
        （{ts, category, type, ...事件字段}），让前端既有渲染零改动。
        """
        await self._append(payload)

    async def repo(self, name: str, status: str, detail: str | None = None) -> None:
        await self._append({"ts": _now_iso(), "category": "CONTROL",
                            "type": "correlation_progress", "node": "repo",
                            "name": name, "status": status, "detail": detail})

    async def phase(self, name: str, status: str) -> None:
        await self._append({"ts": _now_iso(), "category": "CONTROL",
                            "type": "correlation_progress", "node": "phase",
                            "name": name, "status": status})

    async def edge(self, name: str, status: str, detail: str | None = None) -> None:
        mapped = _EDGE_STATUS_MAP.get(status, status)
        if mapped != status:  # 发生映射，保留 raw 进 detail 以便追溯
            detail = f"raw={status}" if detail is None else f"{detail} (raw={status})"
        await self._append({"ts": _now_iso(), "category": "CONTROL",
                            "type": "correlation_progress", "node": "edge",
                            "name": name, "status": mapped, "detail": detail})

    async def scan_end(self, status: str) -> None:
        await self._append({"ts": _now_iso(), "category": "CONTROL",
                            "type": "scan_end", "status": status})


class EdgeAgentEventLogger(ToolAuditLogger):
    """edge 判定 agent 细粒度事件 → 主行 events.ndjson（标准事件形状，前端零改动渲染）。

    实现 core ToolAuditLogger（executor.execute(tool_audit_logger=...) 钩子；executor
    自动再包 BufferingToolAuditLogger 缓冲 tool_events 供 verdicts 端点痕迹匹配，不冲突）。
    agent start/end 不在该接口里——edge_runner 在 execute 前后手动调（end 拆
    AgentMetrics 字段传）。经 writer.raw 共享同一把锁，与 repo/phase/edge 控制行
    并发写不交错。agent_name 合成 "edge:<f>→<t>"——与子仓/黑盒 agent 区分（前端
    LogStream gutter 归属色带按 agent_name 分组）。
    """

    def __init__(self, writer: CorrelationEventWriter, agent_name: str) -> None:
        self._writer = writer
        self._agent = agent_name

    async def _emit(self, payload: dict) -> None:
        await self._writer.raw(payload)

    async def agent_start(self, attempt: int = 1) -> None:
        await self._emit({"category": "AGENT", "type": "AgentEvent",
                          "agent_name": self._agent, "event": "start",
                          "attempt": attempt})

    async def agent_end(self, *, duration_ms: int | None = None,
                        cost_usd: float | None = None,
                        cost_currency: str | None = None,
                        input_tokens: int | None = None,
                        output_tokens: int | None = None,
                        success: bool = True, error: str | None = None,
                        attempt: int = 1) -> None:
        await self._emit({"category": "AGENT", "type": "AgentEvent",
                          "agent_name": self._agent, "event": "end",
                          "attempt": attempt, "duration_ms": duration_ms,
                          "cost_usd": cost_usd, "cost_currency": cost_currency,
                          "success": success, "error": error,
                          "input_tokens": input_tokens,
                          "output_tokens": output_tokens})

    async def log_tool_start(self, tool_name: str, parameters: Any) -> None:
        await self._emit({"category": "TOOL", "type": "ToolCallEvent",
                          "agent_name": self._agent, "tool_name": tool_name,
                          "parameters": parameters})

    async def log_tool_end(self, result: Any) -> None:
        return  # 前端无对应渲染（core WorkflowLogger 也只发 tool_start）→ 不写行

    async def log_error(self, error: str, *, turn_count: int = 0,
                        duration_ms: int = 0) -> None:
        await self._emit({"category": "ERROR", "type": "ErrorEvent",
                          "error_type": "EdgeAgentError", "message": error,
                          "context": self._agent, "turn_count": turn_count,
                          "duration_ms": duration_ms})

    async def log_assistant_turn(self, turn: int, content: str) -> None:
        await self._emit({"category": "LLM", "type": "LlmTurnEvent",
                          "agent_name": self._agent, "turn": turn,
                          "content": content})
