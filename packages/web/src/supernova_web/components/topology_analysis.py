"""Asynchronous, workspace-isolated cross-repo topology analysis manager.

2026-09-03 迁移 worker（spec 2026-09-03-topology-preanalysis-worker-migration）：
agent 执行段经 temporal 提交 worker（TopologyAnalysisWorkflow，bb 队列），web 只做
前置校验/manifest/fingerprint/缓存/建 state + 提交 + await 兜底——**web 进程不再
执行任何 agent / 加载任何 prompt**（守护测试 test_web_never_runs_agents 锁定）。
执行段实现见 supernova_multi.pipeline.workflows（worker 侧）。
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable

from supernova_core.topology.discovery import (
    build_topology_fingerprint,
    collect_navigation_manifest,
)
from supernova_core.topology.store import TopologyAnalysisStore

logger = logging.getLogger(__name__)


class TopologyValidationError(ValueError):
    def __init__(self, message: str, *, repos: list[str] | None = None):
        self.repos = repos or []
        super().__init__(message)


class TooManyTopologyAnalyses(RuntimeError):
    pass


class AnalysisNotFound(KeyError):
    pass


class TopologyProviderConfigError(ValueError):
    pass


class TopologyAnalysisActive(RuntimeError):
    """Analysis is queued/running and must be cancelled before deletion."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _clip(text: str, limit: int = 120) -> str:
    """单行摘要裁剪：压平换行（ndjson 单行展示）+ 超限加省略号。"""
    flat = " ".join(str(text).split())
    return flat if len(flat) <= limit else flat[:limit] + "…"


def _audit_summary(event: dict) -> str:
    """tool-audit 行 → 一行摘要。与 worker _NdjsonToolAuditLogger 的 4 种事件对齐。"""
    kind = event.get("type")
    if kind == "tool_start":
        return _clip(event.get("parameters", ""))
    if kind == "tool_end":
        return _clip(event.get("result", ""))
    if kind == "assistant_turn":
        return _clip(f"turn {event.get('turn', '?')}: {event.get('content', '')}")
    if kind == "error":
        return _clip(event.get("error", ""))
    return _clip(str(event))


class TopologyAnalysisManager:
    def __init__(
        self,
        workspaces_dir: Path,
        *,
        repo_manager: Any | None,
        ws_config_store: Any | None = None,
        temporal_client_factory: Callable[[], Awaitable[Any]] | None = None,
    ) -> None:
        self._root = Path(workspaces_dir).resolve()
        self.store = TopologyAnalysisStore(self._root)
        self._repo_manager = repo_manager
        self._ws_config_store = ws_config_store
        self._temporal_client_factory = temporal_client_factory
        self._client: Any | None = None  # 懒连接 + 复用（勿每次提交新建）
        self._tasks: dict[str, asyncio.Task] = {}
        self._handles: dict[str, Any] = {}
        self._task_ws: dict[str, str] = {}
        self._start_lock = asyncio.Lock()
        self._recovered = False  # 孤儿 recover 懒触发一次/进程（需 async，构造不宜）
        self.store.cleanup(max_records=self.max_stored_analyses)

    @property
    def max_repos(self) -> int:
        return max(2, int(os.getenv("SUPERNOVA_TOPOLOGY_MAX_REPOS", "8")))

    @property
    def max_concurrent(self) -> int:
        return max(1, int(os.getenv("SUPERNOVA_TOPOLOGY_MAX_CONCURRENT", "1")))

    @property
    def timeout_seconds(self) -> float:
        return max(0.01, float(os.getenv("SUPERNOVA_TOPOLOGY_TIMEOUT_SECONDS", "900")))

    @property
    def max_turns(self) -> int:
        return max(1, int(os.getenv("SUPERNOVA_TOPOLOGY_MAX_TURNS", "30")))

    @property
    def cache_ttl_seconds(self) -> int:
        return max(0, int(os.getenv("SUPERNOVA_TOPOLOGY_CACHE_TTL_SECONDS", "86400")))

    @property
    def max_stored_analyses(self) -> int:
        return max(1, int(os.getenv("SUPERNOVA_TOPOLOGY_MAX_STORED_ANALYSES", "100")))

    @property
    def _active_count(self) -> int:
        """并发门读 store：跨进程后内存计数在 web 重启归零但 worker 仍在跑，
        store 的 active（queued/running）计数才正确（spec §4.3）。"""
        return sum(
            len([s for s in self.store.list(ws) if s.get("status") in {"queued", "running"}])
            for ws in self._workspace_names()
        )

    def _workspace_names(self) -> list[str]:
        if not self._root.exists():
            return []
        # dot 开头是保留段（.system=全局认证档案、.master_key），不是 ws——列进去
        # 会让 store.list 校验抛 ValueError 落 route 兜底 422，start 每次必挂
        # （_recovered 不置位）。对齐 workspaces_indexer 的 dot-dir 约定。
        return sorted(p.name for p in self._root.iterdir()
                      if p.is_dir() and not p.name.startswith("."))

    async def start(self, ws: str, repos: list[str], *, refresh: bool = False) -> str:
        # Serialize validation/cache/task creation to prevent duplicate cache misses.
        async with self._start_lock:
            if not self._recovered:
                await self._recover_orphans()
                self._recovered = True
            return await self._start(ws, repos, refresh=refresh)

    async def _start(self, ws: str, repos: list[str], *, refresh: bool = False) -> str:
        names = sorted(set(repos))
        if len(names) < 2:
            raise TopologyValidationError("at least two repositories are required", repos=names)
        if len(names) > self.max_repos:
            raise TopologyValidationError(
                f"at most {self.max_repos} repositories are allowed", repos=names)
        if self._active_count >= self.max_concurrent:
            raise TooManyTopologyAnalyses(self.max_concurrent)

        paths = {name: await self._resolve_repo_path(ws, name) for name in names}
        provider_config = self._provider_config(ws)
        manifest = await asyncio.to_thread(collect_navigation_manifest, paths)
        fingerprint = await asyncio.to_thread(build_topology_fingerprint, paths)
        if not refresh:
            cached = self.store.find_cached(ws, fingerprint.value, ttl_seconds=self.cache_ttl_seconds)
            if cached is not None:
                cached["cache_hit"] = True
                cached["updated_at"] = _now_iso()
                self.store.write(cached)
                return cached["analysis_id"]

        analysis_id = f"topology-{uuid.uuid4().hex[:12]}"
        now = _now_iso()
        state = {
            "analysis_id": analysis_id,
            "workspace": ws,
            "status": "queued",
            "repos": names,
            "fingerprint": fingerprint.value,
            "fingerprint_detail": fingerprint.model_dump(),
            "manifest": manifest.model_dump(),
            "repo_paths": {name: str(path) for name, path in paths.items()},
            "created_at": now,
            "updated_at": now,
            "progress": 5,
            "cache_hit": False,
            "result": None,
            "raw_output": None,
            "usage": None,
            "error": None,
        }
        self.store.create(ws, state)
        self._task_ws[analysis_id] = ws

        from supernova_core.services.temporal_infra import WEB_TASK_QUEUE_BLACKBOX
        from supernova_multi.pipeline.shared import TopologyAnalysisInput
        from supernova_multi.pipeline.workflows import TopologyAnalysisWorkflow

        try:
            client = await self._temporal()
            handle = await client.start_workflow(
                TopologyAnalysisWorkflow.run,
                TopologyAnalysisInput(
                    analysis_id=analysis_id, ws=ws,
                    workspaces_dir=str(self._root),
                    repos=names,
                    repo_paths={name: str(path) for name, path in paths.items()},
                    manifest=manifest.model_dump(),
                    provider_config=provider_config,
                    timeout_seconds=self.timeout_seconds,
                    max_turns=self.max_turns,
                ),
                id=f"topo-{ws}-{analysis_id}",
                task_queue=WEB_TASK_QUEUE_BLACKBOX,
            )
        except Exception as exc:
            # 提交失败（temporal 不可达等）→ 写 failed 终态返回 id：前端轮询即见
            # provider_failed，用户重跑（失败重跑哲学，不自动重试）。
            await self._fail(ws, analysis_id, {
                "code": "provider_failed", "message": f"temporal submit failed: {exc}",
                "retryable": True,
            })
            return analysis_id

        self._handles[analysis_id] = handle
        task = asyncio.create_task(self._await_workflow(handle, ws, analysis_id),
                                   name=analysis_id)
        self._tasks[analysis_id] = task
        task.add_done_callback(lambda _task, analysis_id=analysis_id: self._cleanup_analysis(analysis_id, _task))
        return analysis_id

    async def _temporal(self) -> Any:
        if self._client is None:
            if self._temporal_client_factory is not None:
                self._client = await self._temporal_client_factory()
            else:
                from temporalio.client import Client
                self._client = await Client.connect(self._temporal_address())
        return self._client

    def _temporal_address(self) -> str:
        """SUPERNOVA_TEMPORAL_HOST:PORT（默认 localhost:7233），与 scan_manager
        同语义：web 容器内 temporal 在 compose 服务名 `temporal` 上（非 localhost）。"""
        host = os.environ.get("SUPERNOVA_TEMPORAL_HOST", "localhost")
        port = int(os.environ.get("SUPERNOVA_TEMPORAL_PORT", "7233"))
        return f"{host}:{port}"

    async def _await_workflow(self, handle: Any, ws: str, analysis_id: str) -> None:
        """await workflow 结果。终态由 worker activity 写——web 只做兜底：
        正常返回但 state 仍 active（activity 没写终态的异常路径）/ workflow 失败
        （worker 崩溃）时写 failed，state 不卡 running。"""
        try:
            await handle.result()
            state = self.store.get(ws, analysis_id)
            if state is not None and state.get("status") in {"queued", "running"}:
                logger.warning(
                    "topology workflow %s returned without terminal state", analysis_id)
                await self._fail(ws, analysis_id, {
                    "code": "provider_failed",
                    "message": "workflow returned without terminal state",
                    "retryable": True,
                })
        except asyncio.CancelledError:
            raise  # cancel() 路径：终态已由 cancel() 先写
        except Exception as exc:
            state = self.store.get(ws, analysis_id)
            if state is not None and state.get("status") in {"queued", "running"}:
                await self._fail(ws, analysis_id, {
                    "code": "provider_failed", "message": f"workflow failed: {exc}",
                    "retryable": True,
                })
        finally:
            self.store.cleanup(max_records=self.max_stored_analyses)

    async def _recover_orphans(self) -> None:
        """进程启动后的孤儿清理（弱化版 recover，spec §4.3 语义修正）：
        running 的执行者是 worker——web 重启不得打断，让 workflow 跑完自写终态；
        仅「temporal 查无 workflow」的 active 态才是孤儿（提交前 web 崩的窗口），
        标 interrupted。temporal 不可达时保守不动（不误杀在跑分析），只记 warning。"""
        orphans: list[tuple[str, str, dict]] = []
        for ws in self._workspace_names():
            for state in self.store.list(ws):
                if state.get("status") in {"queued", "running"}:
                    orphans.append((ws, state["analysis_id"], state))
        if not orphans:
            return
        try:
            client = await self._temporal()
        except Exception:
            logger.warning("topology recover: temporal unreachable, leaving %d active "
                           "analyses untouched", len(orphans))
            return
        for ws, analysis_id, state in orphans:
            handle = client.get_workflow_handle(f"topo-{ws}-{analysis_id}")
            alive = False
            try:
                await handle.describe()
                alive = True
            except Exception:
                alive = False
            if not alive:
                state.update({
                    "status": "interrupted",
                    "error": {"code": "interrupted",
                              "message": "analysis orphaned before worker pickup",
                              "retryable": True},
                    "updated_at": _now_iso(),
                })
                self.store.write(state)
                logger.info("topology recover: orphan %s marked interrupted", analysis_id)

    async def wait(self, analysis_id: str) -> None:
        task = self._tasks.get(analysis_id)
        if task is not None:
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                # A cancelled topology task is a terminal state, not a caller failure.
                if task is not asyncio.current_task() and task.cancelled():
                    return
                raise

    def get(self, ws: str, analysis_id: str) -> dict[str, Any]:
        state = self.store.get(ws, analysis_id)
        if state is None:
            raise AnalysisNotFound(analysis_id)
        return state

    async def delete(self, ws: str, analysis_id: str) -> dict[str, Any]:
        """Explicitly remove one terminal analysis and all of its on-disk state.

        Active jobs are refused because a worker may still write `state.json`
        after removal; clients cancel first, then retry deletion."""
        state = self.get(ws, analysis_id)
        if state.get("status") in {"queued", "running"}:
            raise TopologyAnalysisActive(analysis_id)
        # A terminal analysis may still have a web await task (worker wrote the
        # state, workflow return is pending). Release it before dropping disk;
        # the status guard prevents the late workflow path from rewriting state.
        self._cleanup_analysis(analysis_id)
        self.store.remove(ws, analysis_id)
        return {"ok": True, "analysis_id": analysis_id}

    async def cancel(self, ws: str, analysis_id: str) -> dict[str, Any]:
        state = self.get(ws, analysis_id)
        if state.get("status") in {"queued", "running"}:
            # 先写终态再 cancel：worker 侧 status guard 据此跳过晚到结果（spec R2）。
            state.update({
                "status": "cancelled", "updated_at": _now_iso(), "progress": 100,
                "error": {"code": "cancelled", "message": "analysis cancelled by user", "retryable": True},
            })
            self.store.write(state)
            handle = self._handles.get(analysis_id)
            if handle is not None:
                try:
                    await handle.cancel()
                except Exception:
                    logger.warning("topology cancel rpc failed for %s (guard converges)",
                                   analysis_id, exc_info=True)
        return self.get(ws, analysis_id)

    async def _resolve_repo_path(self, ws: str, name: str) -> Path:
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", name or ""):
            raise TopologyValidationError(f"invalid repository name: {name!r}", repos=[name])
        if self._repo_manager is None:
            candidate = (self._root / ws / "repos" / name).resolve()
            if not candidate.is_relative_to(self._root.resolve()) or not candidate.is_dir():
                raise TopologyValidationError(f"repository not found: {name}", repos=[name])
            return candidate
        view = self._repo_manager.get_repo(ws, name)
        if view is None:
            raise TopologyValidationError(f"repository not found: {name}", repos=[name])
        if view.get("state") not in (None, "ready"):
            raise TopologyValidationError(f"repository is not ready: {name}", repos=[name])
        if view.get("linked"):
            from .repo_manager import resolve_linked_repo_path
            linked = resolve_linked_repo_path(self._root, ws, name)
            if not linked:
                raise TopologyValidationError(f"linked repository path missing: {name}", repos=[name])
            return Path(linked).resolve()
        try:
            candidate = self._repo_manager._repo_dir(ws, name)
        except ValueError as exc:
            raise TopologyValidationError(str(exc), repos=[name]) from exc
        if not candidate.is_relative_to(self._root.resolve()) or not candidate.is_dir():
            raise TopologyValidationError(f"repository path is not available: {name}", repos=[name])
        return candidate

    def _cleanup_analysis(self, analysis_id: str, task: asyncio.Task | None = None) -> None:
        """Idempotently release registry state for every terminal path."""
        current_task = self._tasks.get(analysis_id)
        if task is not None and current_task is not None and current_task is not task:
            return
        self._tasks.pop(analysis_id, None)
        self._task_ws.pop(analysis_id, None)
        self._handles.pop(analysis_id, None)

    def tail_log(self, ws: str, analysis_id: str, *, after: int = -1,
                 limit: int = 200) -> dict[str, Any]:
        """过程日志尾读：worker 的 tool-audit.ndjson 按 after 行号游标增量返回。

        服务端裁剪成一行摘要（result/parameters 可达 2000 字符，不回传全文）；
        文件未创建（分析未启动）→ 空行而非 404——前端零日志态正常。
        """
        state = self.get(ws, analysis_id)
        if state is None:
            raise AnalysisNotFound(analysis_id)
        audit = self.store.path(ws, analysis_id) / "tool-audit.ndjson"
        lines: list[dict[str, Any]] = []
        next_no = after
        if audit.exists():
            with audit.open("r", encoding="utf-8", errors="replace") as fh:
                for no, raw in enumerate(fh):
                    if no <= after or len(lines) >= limit:
                        continue
                    try:
                        event = json.loads(raw)
                    except json.JSONDecodeError:
                        event = {"type": "unparsed", "summary": raw.strip()[:120]}
                    lines.append({
                        "no": no,
                        "ts": event.get("ts"),
                        "type": event.get("type"),
                        "tool": event.get("tool"),
                        "summary": _audit_summary(event),
                    })
                    next_no = no
        return {"lines": lines, "next": next_no}

    def latest(self, ws: str) -> dict[str, Any]:
        """刷新恢复：最近一条 analysis（created_at 降序）。无记录 → AnalysisNotFound。"""
        records = self.store.list(ws)
        if not records:
            raise AnalysisNotFound("latest")
        newest = max(records, key=lambda s: s.get("created_at") or "")
        return self.api_view(ws, newest["analysis_id"])

    def list_analyses(self, ws: str) -> list[dict[str, Any]]:
        """分析历史（摘要）：created_at 降序。只带历史行渲染所需字段——
        result/usage/error 大字段不下发，选中条目后前端经 get(api_view) 拉全量。"""
        records = sorted(self.store.list(ws),
                         key=lambda s: s.get("created_at") or "", reverse=True)
        return [{
            "analysis_id": s.get("analysis_id"), "workspace": s.get("workspace"),
            "status": s.get("status"), "repos": s.get("repos"),
            "progress": s.get("progress"), "cache_hit": s.get("cache_hit"),
            "fingerprint": s.get("fingerprint"),
            "created_at": s.get("created_at"), "updated_at": s.get("updated_at"),
        } for s in records]

    def api_view(self, ws: str, analysis_id: str) -> dict[str, Any]:
        """Minimal frontend response; persisted paths/manifests/raw output stay server-side."""
        state = self.get(ws, analysis_id)
        if state is None:
            raise AnalysisNotFound(analysis_id)
        result = state.get("result")
        if isinstance(result, dict):
            result = {**result, "raw": None}
            result["invalid"] = [
                {**item, "raw": {}} if isinstance(item, dict) else item
                for item in result.get("invalid", [])
            ]
        return {
            "analysis_id": state.get("analysis_id"), "workspace": state.get("workspace"),
            "status": state.get("status"), "repos": state.get("repos"),
            "progress": state.get("progress"), "cache_hit": state.get("cache_hit"),
            "fingerprint": state.get("fingerprint"), "result": result,
            "usage": state.get("usage"), "error": state.get("error"),
            "created_at": state.get("created_at"), "updated_at": state.get("updated_at"),
            "completed_at": state.get("completed_at"),
        }

    def _provider_config(self, ws: str) -> dict:
        if self._ws_config_store is not None:
            from .ws_config_store import ProviderConfigIncomplete, validate_ws_config
            try:
                validate_ws_config(self._ws_config_store.read(ws))
            except ProviderConfigIncomplete:
                raise
            except ValueError as exc:
                raise TopologyProviderConfigError(str(exc)) from exc
            provider_config = self._ws_config_store.resolve_provider_config(ws)
            pricing_override = self._root / ws / "pricing.override.json"
            if pricing_override.is_file():
                provider_config = {**provider_config, "pricing_override": str(pricing_override)}
            return provider_config
        from supernova_core.agents.providers import build_provider_config
        from dataclasses import asdict
        return asdict(build_provider_config())

    async def _fail(self, ws: str, analysis_id: str, error: dict[str, Any]) -> None:
        state = self.get(ws, analysis_id)
        state.update({
            "status": "failed", "progress": 100, "updated_at": _now_iso(), "error": error,
        })
        self.store.write(state)


__all__ = [
    "AnalysisNotFound", "TopologyAnalysisManager", "TopologyAnalysisStore",
    "TooManyTopologyAnalyses", "TopologyAnalysisActive", "TopologyValidationError",
]
