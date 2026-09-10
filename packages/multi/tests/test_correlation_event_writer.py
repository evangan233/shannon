import asyncio
import json

import pytest

from supernova_multi.correlation_event_writer import CorrelationEventWriter, EdgeAgentEventLogger


def _rows(p):
    return [json.loads(l) for l in p.read_text("utf-8").splitlines() if l.strip()]


@pytest.mark.asyncio
async def test_repo_event_format(tmp_path):
    w = CorrelationEventWriter(tmp_path / "e.ndjson")
    await w.repo("svc-a", "started")
    r = _rows(tmp_path / "e.ndjson")[-1]
    assert r["category"] == "CONTROL"
    assert r["type"] == "correlation_progress"
    assert r["node"] == "repo" and r["name"] == "svc-a" and r["status"] == "started"
    assert "ts" in r


@pytest.mark.asyncio
async def test_phase_and_edge(tmp_path):
    w = CorrelationEventWriter(tmp_path / "e.ndjson")
    await w.phase("correlation", "started")
    await w.edge("svc-a->svc-b", "completed", detail="grpc")
    rows = _rows(tmp_path / "e.ndjson")
    assert rows[0]["node"] == "phase" and rows[0]["name"] == "correlation"
    assert rows[1]["node"] == "edge" and rows[1]["detail"] == "grpc"


@pytest.mark.asyncio
async def test_scan_end(tmp_path):
    w = CorrelationEventWriter(tmp_path / "e.ndjson")
    await w.scan_end("completed")
    r = _rows(tmp_path / "e.ndjson")[-1]
    assert r["type"] == "scan_end" and r["status"] == "completed"


@pytest.mark.asyncio
async def test_concurrent_edges_no_interleave(tmp_path):
    w = CorrelationEventWriter(tmp_path / "e.ndjson")
    await asyncio.gather(*(w.edge(f"a->b:{i}", "completed") for i in range(30)))
    rows = _rows(tmp_path / "e.ndjson")
    assert len(rows) == 30  # 每行完整可 parse = Lock 串行无交错


@pytest.mark.asyncio
async def test_creates_parent_dir(tmp_path):
    w = CorrelationEventWriter(tmp_path / "nested" / "dir" / "e.ndjson")
    await w.phase("correlation", "started")
    assert (tmp_path / "nested" / "dir" / "e.ndjson").exists()


@pytest.mark.asyncio
async def test_edge_maps_ok_to_completed(tmp_path):
    w = CorrelationEventWriter(tmp_path / "e.ndjson")
    await w.edge("a->b", "ok")
    r = _rows(tmp_path / "e.ndjson")[-1]
    assert r["status"] == "completed"
    assert "raw=ok" in r["detail"]


@pytest.mark.asyncio
async def test_edge_maps_error_to_failed(tmp_path):
    w = CorrelationEventWriter(tmp_path / "e.ndjson")
    await w.edge("a->b", "error", "network down")
    r = _rows(tmp_path / "e.ndjson")[-1]
    assert r["status"] == "failed"
    assert "network down" in r["detail"]
    assert "raw=error" in r["detail"]


@pytest.mark.asyncio
async def test_edge_maps_low_to_failed(tmp_path):
    """low 信任 → 视作未通过 → failed（TopologyEdge.status 允许 low，final-review Finding 2）。"""
    w = CorrelationEventWriter(tmp_path / "e.ndjson")
    await w.edge("a->b", "low")
    r = _rows(tmp_path / "e.ndjson")[-1]
    assert r["status"] == "failed"
    assert "raw=low" in r["detail"]


@pytest.mark.asyncio
async def test_edge_maps_declared_missing_to_failed(tmp_path):
    """declared-missing → failed（TopologyEdge.status 允许 declared-missing，final-review Finding 2）。"""
    w = CorrelationEventWriter(tmp_path / "e.ndjson")
    await w.edge("a->b", "declared-missing")
    r = _rows(tmp_path / "e.ndjson")[-1]
    assert r["status"] == "failed"
    assert "raw=declared-missing" in r["detail"]


@pytest.mark.asyncio
async def test_edge_passes_through_spec_status(tmp_path):
    w = CorrelationEventWriter(tmp_path / "e.ndjson")
    await w.edge("a->b", "completed")
    r = _rows(tmp_path / "e.ndjson")[-1]
    assert r["status"] == "completed"
    assert r["detail"] is None  # spec 值透传，无 raw 追加


# === EdgeAgentEventLogger（2026-09-10 live tab：edge 判定 agent 细粒度事件落盘）===
# 形状契约：对齐 core StructuredEventRenderer 的 ndjson 序列化（ts/category/type +
# dataclass 字段），agent_name 合成 edge:<f>→<t>——前端 LogStream/顶部概览零改动渲染。


@pytest.mark.asyncio
async def test_edge_logger_agent_start_end(tmp_path):
    w = CorrelationEventWriter(tmp_path / "e.ndjson")
    lg = EdgeAgentEventLogger(w, "edge:svc-a→svc-b")
    await lg.agent_start()
    await lg.agent_end(duration_ms=1234, cost_usd=0.5, cost_currency="CNY",
                       input_tokens=100, output_tokens=20)
    rows = _rows(tmp_path / "e.ndjson")
    assert rows[0]["type"] == "AgentEvent" and rows[0]["category"] == "AGENT"
    assert rows[0]["agent_name"] == "edge:svc-a→svc-b"
    assert rows[0]["event"] == "start" and rows[0]["attempt"] == 1
    assert rows[-1]["event"] == "end" and rows[-1]["success"] is True
    assert rows[-1]["duration_ms"] == 1234
    assert rows[-1]["cost_usd"] == 0.5 and rows[-1]["cost_currency"] == "CNY"
    assert rows[-1]["input_tokens"] == 100 and rows[-1]["output_tokens"] == 20


@pytest.mark.asyncio
async def test_edge_logger_failed_end(tmp_path):
    w = CorrelationEventWriter(tmp_path / "e.ndjson")
    lg = EdgeAgentEventLogger(w, "edge:a→b")
    await lg.agent_start()
    await lg.agent_end(success=False, error="boom")
    r = _rows(tmp_path / "e.ndjson")[-1]
    assert r["event"] == "end" and r["success"] is False and r["error"] == "boom"


@pytest.mark.asyncio
async def test_edge_logger_tool_start(tmp_path):
    w = CorrelationEventWriter(tmp_path / "e.ndjson")
    lg = EdgeAgentEventLogger(w, "edge:a→b")
    await lg.log_tool_start("Read", {"file_path": "/tmp/x.py"})
    r = _rows(tmp_path / "e.ndjson")[-1]
    assert r["type"] == "ToolCallEvent" and r["category"] == "TOOL"
    assert r["agent_name"] == "edge:a→b"
    assert r["tool_name"] == "Read" and r["parameters"] == {"file_path": "/tmp/x.py"}


@pytest.mark.asyncio
async def test_edge_logger_assistant_turn(tmp_path):
    w = CorrelationEventWriter(tmp_path / "e.ndjson")
    lg = EdgeAgentEventLogger(w, "edge:a→b")
    await lg.log_assistant_turn(3, "分析边 a→b 的调用关系…")
    r = _rows(tmp_path / "e.ndjson")[-1]
    assert r["type"] == "LlmTurnEvent" and r["category"] == "LLM"
    assert r["agent_name"] == "edge:a→b" and r["turn"] == 3
    assert r["content"].startswith("分析边")


@pytest.mark.asyncio
async def test_edge_logger_error(tmp_path):
    w = CorrelationEventWriter(tmp_path / "e.ndjson")
    lg = EdgeAgentEventLogger(w, "edge:a→b")
    await lg.log_error("timeout", turn_count=5, duration_ms=900)
    r = _rows(tmp_path / "e.ndjson")[-1]
    assert r["type"] == "ErrorEvent" and r["category"] == "ERROR"
    assert r["message"] == "timeout" and r["context"] == "edge:a→b"


@pytest.mark.asyncio
async def test_edge_logger_tool_end_noop(tmp_path):
    """log_tool_end 无前端渲染对应（core WorkflowLogger 也只发 tool_start）→ 不写行。"""
    w = CorrelationEventWriter(tmp_path / "e.ndjson")
    lg = EdgeAgentEventLogger(w, "edge:a→b")
    await lg.log_tool_end({"ok": True})
    assert not (tmp_path / "e.ndjson").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("emit", [
    lambda lg: lg.agent_start(),
    lambda lg: lg.agent_end(duration_ms=1),
    lambda lg: lg.log_tool_start("Read", {}),
    lambda lg: lg.log_error("boom"),
    lambda lg: lg.log_assistant_turn(1, "内容"),
])
async def test_edge_logger_events_carry_ts(tmp_path, emit):
    """live 页时间列读 ev.ts（LogsTab: ev.ts ?? ev.timestamp ?? ""）——edge 细粒度
    事件缺 ts 则时间列空白（2026-09-11 cross-repo-20260910-193903 实测 52 条
    AGENT/TOOL/LLM 全无 ts）。契约对齐 core StructuredEventRenderer：每行必有 ts。"""
    w = CorrelationEventWriter(tmp_path / "e.ndjson")
    lg = EdgeAgentEventLogger(w, "edge:a→b")
    await emit(lg)
    r = _rows(tmp_path / "e.ndjson")[-1]
    assert "ts" in r and r["ts"]  # 非空 ISO 时间戳


@pytest.mark.asyncio
async def test_raw_does_not_overwrite_caller_ts(tmp_path):
    """raw() 是「补」ts（setdefault 语义）：调用方自带 ts 时不覆盖。"""
    w = CorrelationEventWriter(tmp_path / "e.ndjson")
    await w.raw({"ts": "2026-09-10T19:39:03Z", "category": "AGENT",
                 "type": "AgentEvent"})
    r = _rows(tmp_path / "e.ndjson")[-1]
    assert r["ts"] == "2026-09-10T19:39:03Z"


@pytest.mark.asyncio
async def test_edge_logger_shares_writer_lock(tmp_path):
    """edge 细粒度事件与 repo/phase/edge 控制行并发写同一 ndjson：锁串行无交错。"""
    w = CorrelationEventWriter(tmp_path / "e.ndjson")
    loggers = [EdgeAgentEventLogger(w, f"edge:a→b:{i}") for i in range(15)]
    await asyncio.gather(*(
        lg.log_tool_start("Grep", {"q": i}) for i, lg in enumerate(loggers)),
        *(w.edge(f"a->b:{i}", "completed") for i in range(15)))
    rows = _rows(tmp_path / "e.ndjson")
    assert len(rows) == 30  # 每行完整可 parse = 串行无交错
