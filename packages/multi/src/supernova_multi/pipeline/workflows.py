"""CorrelationScanWorkflow + TopologyAnalysisWorkflow：web 提交的 worker 执行段。

形态对齐 whitebox/blackbox 的 pipeline 包；均为单 activity 直通
（编排逻辑在各自执行函数，无中间状态机）。
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from temporalio import activity, workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ApplicationError

with workflow.unsafe.imports_passed_through():
    from supernova_core.services.scan_gate import (
        acquire_gate_slot, release_gate_slot,
        gate_scan_id_from_event_file, gate_ws_from_path,
        gate_ws_cap_from_overrides)
    from supernova_core.agents.runner import UsageSink, run_claude_prompt
    from supernova_core.agents.tool_audit_logger import ToolAuditLogger
    from supernova_core.config.parser import parse_multi_repo_config
    from supernova_core.prompts.manager import PromptManager
    from supernova_core.topology.discovery import normalize_topology_result
    from supernova_core.topology.schema import TOPOLOGY_DISCOVERY_SCHEMA
    from supernova_core.topology.store import TopologyAnalysisStore
    from supernova_multi.orchestrator import run_correlation_phase
    from supernova_multi.pipeline.shared import CorrelationPipelineInput, TopologyAnalysisInput


@activity.defn
async def run_correlation_activity(inp: CorrelationPipelineInput) -> dict:
    # env_overrides 走 per-scan 覆盖层（brief「若既有 helper 则复用」）：复用
    # supernova_core.config.scan_env.set_scan_env——与 whitebox/blackbox 的
    # setup_display activity 同一模式。worker 是长驻进程、并发扫描共享 os.environ，
    # 直接 os.environ.update 会互相串台（scan_env 模块的存在理由）；core 的
    # SUPERNOVA_* 读取点经 ws_getenv 命中本覆盖层。单 activity 直通 → finally
    # 清层，等价 whitebox setup_display(set)/finalize(clear) 的生命周期配对。
    from supernova_core.config.scan_env import clear_scan_env, set_scan_env

    set_scan_env(inp.env_overrides)
    try:
        config = parse_multi_repo_config(Path(inp.config_path))
        return await run_correlation_phase(
            config,
            {svc: Path(p) for svc, p in inp.repo_workspace_paths.items()},
            Path(inp.out_ws_dir), Path(inp.event_file),
            pipeline_testing=inp.pipeline_testing,
            provider_config=inp.provider_config,
            write_scan_end=inp.write_scan_end,
        )
    finally:
        clear_scan_env()


@workflow.defn
class CorrelationScanWorkflow:
    @workflow.run
    async def run(self, inp: CorrelationPipelineInput) -> dict:
        # 全局扫描闸门（spec 2026-09-08-worker-scan-gate §5）：关联阶段占 1 槽。
        # corr input 无 workspace_name——ws 从 event_file/out_ws_dir 反推（仅展示用）。
        await acquire_gate_slot({
            "kind": "correlation",
            "ws": gate_ws_from_path(inp.event_file or inp.out_ws_dir),
            "scan_id": gate_scan_id_from_event_file(inp.event_file or None),
            "label": " + ".join(sorted(inp.repo_workspace_paths)) or "correlation",
            # ws 并发上限（2026-09-15）：关联阶段与跨仓子仓的 ws 都从 event_file
            # 反推主 ws——cap 归属主 ws，跨仓 N 子仓各占一槽全计主 ws 持有。
            **({} if (ws_cap := gate_ws_cap_from_overrides(inp.env_overrides))
               is None else {"ws_cap": ws_cap}),
        })
        try:
            return await workflow.execute_activity(
                run_correlation_activity, inp,
                start_to_close_timeout=timedelta(hours=4),
            )
        finally:
            # 尽力释放：异常时由 runner 的闸门 janitor 兜底回收（spec §6）
            await release_gate_slot()


class _NdjsonToolAuditLogger(ToolAuditLogger):
    """预分析 tool 审计落盘（自 web 包平移，2026-09-03 迁移 worker）。"""

    def __init__(self, path: Path):
        self._path = path
        self._lock = asyncio.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.touch(exist_ok=True)

    async def log_tool_start(self, tool_name: str, parameters: Any) -> None:
        await self._write({"type": "tool_start", "tool": tool_name,
                           "parameters": str(parameters)[:2000]})

    async def log_tool_end(self, result: Any) -> None:
        await self._write({"type": "tool_end", "result": str(result)[:2000]})

    async def log_error(self, error: str, *, turn_count: int = 0, duration_ms: int = 0) -> None:
        await self._write({"type": "error", "error": error, "turn_count": turn_count,
                           "duration_ms": duration_ms})

    async def log_assistant_turn(self, turn: int, content: str) -> None:
        await self._write({"type": "assistant_turn", "turn": turn, "content": content[:2000]})

    async def _write(self, event: dict[str, Any]) -> None:
        payload = json.dumps({"ts": _topo_now_iso(), **event}, ensure_ascii=False,
                             separators=(",", ":")) + "\n"
        async with self._lock:
            await asyncio.to_thread(self._append_sync, payload)

    def _append_sync(self, payload: str) -> None:
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(payload)
            fh.flush()


def _topo_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _topo_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _usage(result: Any) -> dict[str, Any]:
    tokens = result.tokens
    return {
        "input_tokens": tokens.input_tokens,
        "output_tokens": tokens.output_tokens,
        "cache_read_tokens": tokens.cache_read_input_tokens,
        "cache_creation_tokens": tokens.cache_creation_input_tokens,
        "cost_usd": result.cost,
        "cost_currency": result.cost_currency,
        "model": result.model,
        "turns": result.turns,
    }


def _usage_from_sink(sink: UsageSink) -> dict[str, Any] | None:
    if not any((sink.input_tokens, sink.output_tokens, sink.cache_read_tokens,
                sink.cache_creation_tokens, sink.cost_usd)):
        return None
    return {
        "input_tokens": sink.input_tokens,
        "output_tokens": sink.output_tokens,
        "cache_read_tokens": sink.cache_read_tokens,
        "cache_creation_tokens": sink.cache_creation_tokens,
        "cost_usd": sink.cost_usd,
        "cost_currency": sink.cost_currency or "USD",
        "model": sink.model,
        "turns": 0,
    }


async def _run_topology_analysis(inp: TopologyAnalysisInput) -> dict:
    """预分析执行段（自 web TopologyAnalysisManager._run/_run_agent 平移，2026-09-03）。

    结果分类与 error.code 同 web 现状分类表逐一对齐（前端按这些渲染）：
    timeout / provider_failed / malformed_output / cancelled；写终态前 status
    guard（非 queued/running 跳过）化解 web cancel 与本侧完成的竞态（spec R2）。
    """
    store = TopologyAnalysisStore(Path(inp.workspaces_dir))
    state = store.get(inp.ws, inp.analysis_id)
    if state is None:
        return {"status": "skipped", "reason": "state_missing"}
    if state.get("status") != "queued":
        # cancel 已写终态（cancelled）→ 跳过防复写。
        return {"status": "skipped", "reason": f"status={state.get('status')}"}

    state.update({"status": "running", "progress": 20, "updated_at": _topo_now_iso()})
    store.write(state)

    state_dir = store.path(inp.ws, inp.analysis_id)
    sink = UsageSink()
    repositories = dict(inp.repo_paths)
    prompt = PromptManager(Path(__file__).resolve().parents[5] / "prompts").load_sync(
        "cross-repo-topology-discovery",
        {
            "repositories_json": _topo_json(repositories),
            "navigation_manifest_json": _topo_json(inp.manifest),
        },
    )

    def _fail(error: dict[str, Any], *, result: Any = None) -> dict:
        latest = store.get(inp.ws, inp.analysis_id) or state
        latest.update({
            "status": "failed", "progress": 100, "updated_at": _topo_now_iso(),
            "error": error,
            "usage": (
                _usage(result) if result is not None
                else _usage_from_sink(sink) or latest.get("usage")
            ),
            "raw_output": getattr(result, "text", None) if result is not None
            else latest.get("raw_output"),
        })
        store.write(latest)
        return {"status": "failed", "error": error}

    try:
        result = await asyncio.wait_for(
            run_claude_prompt(
                prompt=prompt,
                model_tier="large",
                structured_output_schema=TOPOLOGY_DISCOVERY_SCHEMA,
                provider_config=inp.provider_config,
                repo_path=str(state_dir),
                tool_audit_logger=_NdjsonToolAuditLogger(state_dir / "tool-audit.ndjson"),
                max_turns=inp.max_turns,
                usage_sink=sink,
                allowed_roots=list(inp.repo_paths.values()),
                tool_policy="readonly-code",
            ),
            timeout=inp.timeout_seconds,
        )
    except asyncio.TimeoutError:
        return _fail({
            "code": "timeout", "message": f"analysis exceeded {inp.timeout_seconds:g}s",
            "retryable": True,
        })
    except asyncio.CancelledError:
        # web cancel() 先写 cancelled 终态再 handle.cancel()——此分支到达时终态多为
        # cancelled：guard 跳过复写、保留 sink 晚到 usage；state 仍 active（web 崩溃
        # 没来得及写）则兜底写 cancelled 终态。对齐 web 现状 CancelledError 分支。
        latest = store.get(inp.ws, inp.analysis_id)
        if latest is not None and latest.get("status") in {"queued", "running"}:
            latest.update({
                "status": "cancelled", "progress": 100, "updated_at": _topo_now_iso(),
                "error": {"code": "cancelled", "message": "analysis cancelled",
                          "retryable": True},
            })
            store.write(latest)
        elif latest is not None:
            sink_usage = _usage_from_sink(sink)
            if sink_usage is not None:
                latest["usage"] = sink_usage
                store.write(latest)
        raise
    except Exception as exc:  # provider infrastructure failures must not auto-retry
        return _fail({
            "code": "provider_failed", "message": str(exc), "retryable": True,
        })

    if not result.success:
        return _fail({
            "code": "provider_failed", "message": result.error or "provider returned failure",
            "retryable": bool(result.retryable),
        }, result=result)
    payload = result.structured_output
    if not isinstance(payload, dict):
        return _fail({
            "code": "malformed_output", "message": "agent did not return a JSON object",
            "retryable": True,
        }, result=result)
    normalized = normalize_topology_result(
        payload, {name: Path(p) for name, p in inp.repo_paths.items()})
    if any(item.reason == "malformed_output" for item in normalized.invalid):
        return _fail({
            "code": "malformed_output", "message": "agent output failed schema validation",
            "retryable": True,
        }, result=result)

    latest = store.get(inp.ws, inp.analysis_id) or state
    latest.update({
        "status": "completed", "progress": 100,
        "completed_at": _topo_now_iso(), "updated_at": _topo_now_iso(),
        "result": normalized.model_dump(by_alias=True, exclude_none=True),
        "raw_output": payload, "usage": _usage(result), "error": None,
    })
    store.write(latest)
    return {"status": "completed"}


@activity.defn
async def run_topology_analysis_activity(inp: TopologyAnalysisInput) -> dict:
    # env_overrides 走 per-scan 覆盖层，与 run_correlation_activity 同一模式（长驻
    # worker 共享 os.environ，直接 update 会串台）。
    from supernova_core.config.scan_env import clear_scan_env, set_scan_env

    set_scan_env(inp.env_overrides)
    try:
        return await _run_topology_analysis(inp)
    finally:
        clear_scan_env()


@workflow.defn
class TopologyAnalysisWorkflow:
    """跨仓拓扑预分析（web 表单「自动关联分析」）：web 提交，worker 执行。

    韧性 = 失败重跑（用户拍板）：activity 失败不自动重试（重试会重复烧 LLM 调用），
    失败经 activity 内部转结果写终态，正常返回。
    """

    @workflow.run
    async def run(self, inp: TopologyAnalysisInput) -> dict:
        if not inp.analysis_id or not inp.ws or not inp.workspaces_dir:
            # non_retryable：输入校验错误重试无意义，对齐 AuthValidationWorkflow
            # fail-fast 模式（plain ValueError 默认 retryable → workflow task 无限重试）。
            raise ApplicationError(
                "TopologyAnalysisInput.analysis_id/ws/workspaces_dir is required",
                non_retryable=True)
        return await workflow.execute_activity(
            run_topology_analysis_activity, inp,
            # activity 内部 asyncio.wait_for 先超时（写 timeout 终态后正常返回），
            # 本窗口 = timeout + 60s 兜底（进程卡死等极端场景）。
            start_to_close_timeout=timedelta(seconds=inp.timeout_seconds + 60),
            retry_policy=RetryPolicy(maximum_attempts=1),
        )
