# Worker 侧全局扫描闸门（worker-scan-gate）实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 全系统扫描类 workflow 实际并发 ≤5（env 可配），超出在 temporal 里排队（近似 FIFO）不再 409 拒绝；UI 显示排队任务与排队原因（哪个工作区的什么任务占着槽）。

**Architecture:** 闸门 = worker 进程内全局信号量（单 worker 副本部署假设）；三类扫描 workflow（Whitebox/Blackbox/Correlation）`run()` 开头过「闸门段」（try_acquire 轮询 activity），排队持久化在 temporal 里；janitor 周期校验持有者存活性回收泄漏槽；worker 重启 bootstrap 预占防超卖；web 层删 `TooManyScans` 拒绝门；`gate_state.json` 快照（workspaces bind mount 共享）→ `GET /api/scan/gate` → 前端排队徽章 + 并发概览面板。

**Tech Stack:** Python 3.11 / temporalio（workflow + activity + testing.WorkflowEnvironment）/ FastAPI / React + SWR + vitest。

**Spec:** `docs/superpowers/specs/2026-09-08-worker-scan-gate-design.md`（本计划从 spec 论证，执行者须同时读 spec）。

## Global Constraints

- 注释与文档用中文，风格对齐周边代码（说明 why 的短注释）。
- **只跑改动相关的测试文件**，勿广跑全套 pytest（CLAUDE.md：全套有预存挂起/失败）。
- 前端提交前必须本地跑 `cd packages/web/frontend && npx tsc -b`（vitest 不查类型，docker build 才爆）。本地 pnpm `@types/react` 双版本导致的 LogsTab 报错是伪影勿修。
- 前端 `packages/web/frontend/src/pages/ScanNewPage.tsx` 与 `src/components/ScanFormFields.tsx` 当前有**并行会话的未提交改动**——涉及这两个文件的步骤以 grep 重新定位锚点为准，不要假设行号。
- 环境变量命名：`SUPERNOVA_SCAN_GATE_CAPACITY`（默认 5）/ `SUPERNOVA_SCAN_GATE_MAX_WAITING`（默认 50）/ `SUPERNOVA_SCAN_GATE_STATE_FILE`（默认空=不落盘）。
- 退役 `SUPERNOVA_WEB_MAX_CONCURRENT`（web env + config 字段 + compose 透传）；**不动** `SUPERNOVA_WORKER_MAX_CONCURRENT_WF`。
- 测试命令模式：`cd packages/<pkg> && python -m pytest tests/<file> -v`。

---

### Task 1: ScanGate 核心类 + 闸门 activity + workflow 侧 helper（core 包）

**Files:**
- Create: `packages/core/src/supernova_core/services/scan_gate.py`
- Test: `packages/core/tests/test_scan_gate.py`

**Interfaces:**
- Consumes: 无（全新模块）。
- Produces（后续任务依赖的精确签名）:
  - `ScanGate(capacity: int, max_waiting: int, state_path: Path | None)`
  - `scan_gate_try_acquire(descriptor: dict) -> dict`（`@activity.defn`；返回 `{"granted": bool, "queue_full": bool, "position": int, "max_waiting": int}`）
  - `scan_gate_release() -> None`（`@activity.defn`，无参）
  - `async acquire_gate_slot(descriptor: dict) -> None`（workflow 上下文调用；满队 raise `ApplicationError(non_retryable=True)`）
  - `async release_gate_slot() -> None`（workflow 上下文调用；尽力释放吞异常）
  - `reset_gate_for_tests() -> None`
  - `read_gate_snapshot_file(state_file: Path) -> dict | None`
  - `preload_gate(workflow_ids: list[str]) -> None` / `reap_ids(workflow_ids: list[str]) -> None` / `gate_candidate_ids() -> list[str]`（模块级包装，runner 用）
  - `gate_scan_id_from_event_file(event_file: str | None) -> str`
  - `gate_ws_from_path(p: str) -> str`

- [ ] **Step 1: 写失败测试**

创建 `packages/core/tests/test_scan_gate.py`：

```python
"""ScanGate 单测：FIFO 授予 / 幂等 / queue_full / release / reap / preload / 快照原子写。"""

import json
from unittest.mock import MagicMock, patch

from supernova_core.services.scan_gate import (
    ScanGate, read_gate_snapshot_file, reset_gate_for_tests,
)


def _mk(capacity=2, max_waiting=3, state_path=None):
    return ScanGate(capacity, max_waiting, state_path)


def test_first_acquire_granted_immediately():
    g = _mk()
    assert g.try_acquire("w1", {"kind": "whitebox"})["granted"] is True


def test_fifo_earliest_waiter_wins_slot():
    g = _mk(capacity=1)
    g.try_acquire("w1", {})
    assert g.try_acquire("w2", {})["granted"] is False
    assert g.try_acquire("w3", {})["granted"] is False
    g.release("w1")
    # w2 是最早等待者：w3 先 poll 也不能插队（近似 FIFO，spec §4）
    assert g.try_acquire("w3", {})["granted"] is False
    assert g.try_acquire("w2", {})["granted"] is True
    assert g.try_acquire("w3", {})["granted"] is False


def test_idempotent_reacquire():
    g = _mk(capacity=1)
    g.try_acquire("w1", {})
    assert g.try_acquire("w1", {})["granted"] is True


def test_queue_full_rejects_new_waiter():
    g = _mk(capacity=1, max_waiting=1)
    g.try_acquire("w1", {})
    assert g.try_acquire("w2", {})["granted"] is False  # w2 占住唯一 waiting 位
    assert g.try_acquire("w3", {})["queue_full"] is True


def test_position_reports_queue_rank():
    g = _mk(capacity=1, max_waiting=10)
    g.try_acquire("w1", {})
    g.try_acquire("w2", {})
    g.try_acquire("w3", {})
    assert g.try_acquire("w3", {})["position"] == 2  # 第 2 位


def test_release_and_reap_clear_state():
    g = _mk()
    g.try_acquire("w1", {})
    g.try_acquire("w2", {})  # waiting
    g.release("w1")
    assert "w1" not in g.held
    g.reap(["w2"])
    assert "w2" not in g.waiting


def test_preload_counts_as_held():
    g = _mk(capacity=2)
    g.preload(["a", "b"])
    assert g.try_acquire("c", {})["granted"] is False  # 槽被预占满
    assert g.try_acquire("a", {})["granted"] is True   # 预占者幂等命中


def test_candidate_ids_union():
    g = _mk()
    g.try_acquire("w1", {})
    g.try_acquire("w2", {})
    assert set(g.candidate_ids()) == {"w1", "w2"}


def test_snapshot_written_atomically(tmp_path):
    sf = tmp_path / "gate_state.json"
    g = _mk(state_path=sf)
    g.try_acquire("w1", {"kind": "whitebox", "ws": "prod",
                         "scan_id": "s1", "label": "repo@main"})
    data = json.loads(sf.read_text())
    assert data["capacity"] == 2
    assert data["held"][0]["scan_id"] == "s1"
    assert not sf.with_suffix(".json.tmp").exists()  # 原子写无残留 tmp


def test_snapshot_state_path_none_is_noop(tmp_path):
    g = _mk(state_path=None)
    g.try_acquire("w1", {})  # 不应抛错


def test_read_gate_snapshot_file_missing_returns_none(tmp_path):
    assert read_gate_snapshot_file(tmp_path / "nope.json") is None


def test_gate_scan_id_from_event_file():
    from supernova_core.services.scan_gate import gate_scan_id_from_event_file
    assert gate_scan_id_from_event_file(
        "/app/workspaces/prod/scans/20260908-120000/events.ndjson") == "20260908-120000"
    assert gate_scan_id_from_event_file(None) == ""
    assert gate_scan_id_from_event_file("") == ""


def test_gate_ws_from_path():
    from supernova_core.services.scan_gate import gate_ws_from_path
    assert gate_ws_from_path(
        "/app/workspaces/prod/scans/x/events.ndjson") == "prod"
    assert gate_ws_from_path("/app/workspaces/prod") == "prod"
    assert gate_ws_from_path("") == ""


def test_activity_wrappers_delegate_to_gate():
    """activity 包装：workflow_id 取 activity.info()，逻辑委托进程级 gate。"""
    import asyncio
    from supernova_core.services import scan_gate as mod

    reset_gate_for_tests()
    info = MagicMock()
    info.workflow_id = "wf-abc"
    with patch.object(mod.activity, "info", return_value=info), \
         patch.dict("os.environ", {"SUPERNOVA_SCAN_GATE_CAPACITY": "1"}):
        r = asyncio.run(mod.scan_gate_try_acquire({"kind": "whitebox"}))
        assert r["granted"] is True
        asyncio.run(mod.scan_gate_release())
        assert mod._gate().candidate_ids() == []
    reset_gate_for_tests()
```

- [ ] **Step 2: 跑测试确认失败**

```bash
cd packages/core && python -m pytest tests/test_scan_gate.py -v
```

预期：全部 FAIL（`ModuleNotFoundError: supernova_core.services.scan_gate`）。

- [ ] **Step 3: 写实现**

创建 `packages/core/src/supernova_core/services/scan_gate.py`：

```python
"""worker 侧全局扫描闸门：扫描类 workflow 实际并发 ≤ 容量，超出排队（近似 FIFO）。

spec: docs/superpowers/specs/2026-09-08-worker-scan-gate-design.md

架构不变量：
- 闸门是 worker **进程内**信号量（部署假设单 worker 副本；多副本时信号量分裂，
  需迁共享存储——runner.py 的挂载注释同此口径，不预做）。
- 排队发生在 temporal 里：workflow 在闸门段轮询 try_acquire 直到获槽，
  workflow 活着 = 在排队，持久化/重启恢复免费。
- 槽泄漏兜底 = runner 的 janitor（周期校验持有者存活性，spec §6）；
  worker 重启防超卖 = bootstrap 预占（所有 RUNNING 扫描类 workflow 计槽）。
- gate_state.json 快照仅供 web 展示（env 指定路径；CLI 未设 = 不落盘优雅降级），
  丢了/旧了只影响显示不影响闸门正确性。
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

from temporalio import activity

GATE_POLL_SECONDS = 5.0          # workflow 侧排队轮询间隔；测试 monkeypatch 调小
_ACTIVITY_TIMEOUT = timedelta(seconds=30)


@dataclass
class _Holder:
    descriptor: dict
    acquired_at: float


@dataclass
class _Waiter:
    descriptor: dict
    first_seen: float


class ScanGate:
    """进程级扫描并发闸门。非线程安全：worker 单事件循环，activity 同循环调度。"""

    def __init__(self, capacity: int, max_waiting: int,
                 state_path: Path | None = None) -> None:
        self.capacity = capacity
        self.max_waiting = max_waiting
        self.state_path = state_path
        self.held: dict[str, _Holder] = {}
        self.waiting: dict[str, _Waiter] = {}  # dict 保插入序 = first_seen 序

    def try_acquire(self, workflow_id: str, descriptor: dict) -> dict:
        r_base = {"max_waiting": self.max_waiting}
        if workflow_id in self.held:  # 幂等：bootstrap 预占/重试对齐（spec §4）
            return {**r_base, "granted": True, "queue_full": False, "position": 0}
        if (workflow_id not in self.waiting
                and len(self.waiting) >= self.max_waiting):  # 防雪崩第二道门
            return {**r_base, "granted": False, "queue_full": True,
                    "position": self.max_waiting}
        if workflow_id not in self.waiting:
            self.waiting[workflow_id] = _Waiter(dict(descriptor), time.time())
        earliest = next(iter(self.waiting))
        if len(self.held) < self.capacity and workflow_id == earliest:
            self.held[workflow_id] = _Holder(
                self.waiting.pop(workflow_id).descriptor, time.time())
            self._persist()
            return {**r_base, "granted": True, "queue_full": False, "position": 0}
        return {**r_base, "granted": False, "queue_full": False,
                "position": list(self.waiting).index(workflow_id) + 1}

    def release(self, workflow_id: str) -> None:
        changed = self.held.pop(workflow_id, None) is not None
        changed = self.waiting.pop(workflow_id, None) is not None or changed
        if changed:
            self._persist()

    def reap(self, workflow_ids: list[str]) -> None:
        """janitor 校验死亡后回收（held/waiting 皆摘——幽灵排队者会挡 FIFO）。"""
        for wf in workflow_ids:
            self.held.pop(wf, None)
            self.waiting.pop(wf, None)
        self._persist()

    def preload(self, workflow_ids: list[str]) -> None:
        """worker 启动预占：RUNNING 扫描类 workflow 一律计槽（保守，防重启超卖）。"""
        for wf in workflow_ids:
            if wf not in self.held:
                self.held[wf] = _Holder(
                    {"kind": "unknown", "ws": "", "scan_id": "", "label": wf},
                    time.time())
        self._persist()

    def candidate_ids(self) -> list[str]:
        return list(self.held) + list(self.waiting)

    def snapshot(self) -> dict:
        return {
            "capacity": self.capacity,
            "max_waiting": self.max_waiting,
            "held": [{"workflow_id": wf, **h.descriptor, "since": h.acquired_at}
                     for wf, h in self.held.items()],
            "waiting": [{"workflow_id": wf, **w.descriptor, "since": w.first_seen}
                        for wf, w in self.waiting.items()],
        }

    def _persist(self) -> None:
        if self.state_path is None:
            return
        tmp = self.state_path.with_suffix(".json.tmp")
        tmp.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps(self.snapshot(), ensure_ascii=False))
        os.replace(tmp, self.state_path)


_GATE: ScanGate | None = None


def _gate() -> ScanGate:
    """调用时才读 env 构造（对齐 settings_writer 的测试友好惯例）。"""
    global _GATE
    if _GATE is None:
        state_file = os.environ.get("SUPERNOVA_SCAN_GATE_STATE_FILE", "")
        _GATE = ScanGate(
            capacity=int(os.environ.get("SUPERNOVA_SCAN_GATE_CAPACITY", "5")),
            max_waiting=int(os.environ.get("SUPERNOVA_SCAN_GATE_MAX_WAITING", "50")),
            state_path=Path(state_file) if state_file else None,
        )
    return _GATE


def reset_gate_for_tests() -> None:
    global _GATE
    _GATE = None


def preload_gate(workflow_ids: list[str]) -> None:
    _gate().preload(workflow_ids)


def reap_ids(workflow_ids: list[str]) -> None:
    _gate().reap(workflow_ids)


def gate_candidate_ids() -> list[str]:
    return _gate().candidate_ids()


def read_gate_snapshot_file(state_file: Path) -> dict | None:
    """web 侧读快照：文件缺失/损坏返回 None（worker 未起/未配置落盘）。"""
    try:
        return json.loads(Path(state_file).read_text())
    except (OSError, ValueError):
        return None


def gate_scan_id_from_event_file(event_file: str | None) -> str:
    """workspaces/<ws>/scans/<scan_id>/events.ndjson → <scan_id>；解析失败置空（仅展示降级）。"""
    if not event_file:
        return ""
    parts = Path(event_file).parts
    return parts[-2] if len(parts) >= 2 else ""


def gate_ws_from_path(p: str) -> str:
    """从任意 ws 内路径反推工作区名：找 workspaces 段的下一级；无则取末段。"""
    if not p:
        return ""
    parts = Path(p).parts
    if "workspaces" in parts:
        i = parts.index("workspaces")
        if i + 1 < len(parts):
            return parts[i + 1]
    return parts[-1] if parts else ""


@activity.defn
async def scan_gate_try_acquire(descriptor: dict) -> dict:
    return _gate().try_acquire(activity.info().workflow_id, descriptor)


@activity.defn
async def scan_gate_release() -> None:
    _gate().release(activity.info().workflow_id)


async def acquire_gate_slot(descriptor: dict) -> None:
    """workflow 侧闸门段（workflow 上下文调用）：排队轮询直到获槽；满队 raise。

    cancel 传导：temporal cancel 在 sleep/execute_activity await 点抛 CancelledError，
    此时尚未获槽、无需 release——waiting 残留由 janitor 回收（spec §6）。
    """
    from temporalio import workflow
    from temporalio.exceptions import ApplicationError
    while True:
        r = await workflow.execute_activity(
            scan_gate_try_acquire, descriptor,
            start_to_close_timeout=_ACTIVITY_TIMEOUT,
        )
        if r.get("granted"):
            return
        if r.get("queue_full"):
            # 文案数字来自 activity 返回值：workflow sandbox 不 import worker 进程常量
            raise ApplicationError(
                f"扫描排队已满（上限 {r.get('max_waiting')}），请稍后重试",
                non_retryable=True)
        await workflow.sleep(GATE_POLL_SECONDS)


async def release_gate_slot() -> None:
    """workflow 侧释放（finally 调用）：尽力释放，失败吞掉由 janitor 兜底。"""
    from temporalio import workflow
    try:
        await workflow.execute_activity(
            scan_gate_release, start_to_close_timeout=_ACTIVITY_TIMEOUT)
    except Exception:
        pass
```

- [ ] **Step 4: 跑测试确认通过**

```bash
cd packages/core && python -m pytest tests/test_scan_gate.py -v
```

预期：15 个全部 PASS。

- [ ] **Step 5: Commit**

```bash
git add packages/core/src/supernova_core/services/scan_gate.py packages/core/tests/test_scan_gate.py
git commit -m "feat(core): ScanGate 全局扫描闸门——进程内信号量(容量/max_waiting env)+近似FIFO(first_seen优先)+幂等acquire+原子快照落盘+闸门activity与workflow侧helper(spec 2026-09-08-worker-scan-gate §4)"
```

---

### Task 2: WhiteboxScanWorkflow 闸门接线

**Files:**
- Modify: `packages/whitebox/src/supernova_whitebox/pipeline/workflows.py`（imports_passed_through 块 L89-93；`run()` L161 起）
- Test: `packages/whitebox/tests/pipeline/test_workflow_gate.py`（新建）

**Interfaces:**
- Consumes: `acquire_gate_slot` / `release_gate_slot` / `gate_scan_id_from_event_file`（Task 1）。
- Produces: Whitebox workflow 过闸模式（Task 3 照抄结构）；MR 子 workflow 自动占槽（`mr_meta` 非空 → kind="mr"）。

- [ ] **Step 1: 写失败的集成测试**

创建 `packages/whitebox/tests/pipeline/test_workflow_gate.py`（模式对齐 `test_workflow_migration.py`：mock activity 闭包 + 只注册部分 activity）：

```python
"""WhiteboxScanWorkflow 闸门段集成测（spec §5）：排队→放行、queue_full、前导顺序。"""

import asyncio

import pytest
from temporalio import activity
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from supernova_core.services import scan_gate as gate_mod
from supernova_whitebox.pipeline.workflows import WhiteboxScanWorkflow
from supernova_whitebox.pipeline.shared import PipelineInput


def _gate_activities(calls: list) -> list:
    @activity.defn
    async def scan_gate_try_acquire(descriptor):
        calls.append(("gate_try", descriptor))
        return gate_mod._gate().try_acquire(
            activity.info().workflow_id, descriptor)

    @activity.defn
    async def scan_gate_release():
        calls.append(("gate_release",))

    @activity.defn
    async def setup_display(i):
        calls.append("setup_display")

    return [scan_gate_try_acquire, scan_gate_release, setup_display]


def _inp(tmp_path, **kw):
    return PipelineInput(
        repo_path=str(tmp_path / "repo"),
        workspace_name="ws-gate",
        event_file=str(tmp_path / "events.ndjson"),
        enable_llm_track=False,
        **kw,
    )


@pytest.fixture(autouse=True)
def _fast_poll(monkeypatch):
    monkeypatch.setattr(gate_mod, "GATE_POLL_SECONDS", 0.05)
    gate_mod.reset_gate_for_tests()
    yield
    gate_mod.reset_gate_for_tests()


@pytest.mark.asyncio
async def test_gate_grants_when_capacity_free(tmp_path):
    """空闸门：workflow 直接过闸并到达 setup_display（其后的主体 activity 未注册
    会让 workflow 失败——用失败证明前导已执行，对齐 test_workflow_migration 模式）。"""
    calls: list = []
    async with await WorkflowEnvironment.start_local() as env:
        async with Worker(env.client, task_queue="tq-gate",
                          workflows=[WhiteboxScanWorkflow],
                          activities=_gate_activities(calls)):
            with pytest.raises(Exception):
                await asyncio.wait_for(
                    env.client.execute_workflow(
                        WhiteboxScanWorkflow.run, _inp(tmp_path),
                        id="w-gate-free", task_queue="tq-gate"),
                    timeout=30)
    assert calls[0][0] == "gate_try"
    assert "setup_display" in calls


@pytest.mark.asyncio
async def test_gate_queues_until_slot_released(tmp_path):
    """槽被占：workflow 排队（不完成）；释放后放行到 setup_display。"""
    g = gate_mod._gate()
    g.try_acquire("holder-wf", {"kind": "whitebox"})  # 占住唯一槽
    calls: list = []
    async with await WorkflowEnvironment.start_local() as env:
        async with Worker(env.client, task_queue="tq-gate",
                          workflows=[WhiteboxScanWorkflow],
                          activities=_gate_activities(calls)):
            handle = await env.client.start_workflow(
                WhiteboxScanWorkflow.run, _inp(tmp_path),
                id="w-gate-queued", task_queue="tq-gate")
            await asyncio.sleep(0.5)
            # 仍在排队：轮询多次但未到 setup_display
            assert not any(c == "setup_display" for c in calls)
            g.release("holder-wf")
            with pytest.raises(Exception):  # 放行后死于未注册的主体 activity
                await asyncio.wait_for(handle.result(), timeout=30)
    assert "setup_display" in calls
    # finally release 尽力执行过
    assert ("gate_release",) in calls


@pytest.mark.asyncio
async def test_gate_queue_full_fails_workflow(tmp_path):
    g = gate_mod._gate()
    g.preload(["holder-1"])            # capacity=1 占满
    g.try_acquire("waiter-1", {})      # max_waiting=1 占满
    calls: list = []
    async with await WorkflowEnvironment.start_local() as env:
        async with Worker(env.client, task_queue="tq-gate",
                          workflows=[WhiteboxScanWorkflow],
                          activities=_gate_activities(calls)):
            with pytest.raises(Exception) as ei:
                await asyncio.wait_for(
                    env.client.execute_workflow(
                        WhiteboxScanWorkflow.run, _inp(tmp_path),
                        id="w-gate-full", task_queue="tq-gate"),
                    timeout=30)
            assert "排队已满" in str(ei.value)
    assert "setup_display" not in calls
```

注意：测试环境的 gate 容量/max_waiting 用 env 缺省（capacity=5）会让「占满」不成立——在 `_fast_poll` fixture 里补 monkeypatch env 再 reset：

```python
@pytest.fixture(autouse=True)
def _fast_poll(monkeypatch, tmp_path):
    monkeypatch.setattr(gate_mod, "GATE_POLL_SECONDS", 0.05)
    monkeypatch.setenv("SUPERNOVA_SCAN_GATE_CAPACITY", "1")
    monkeypatch.setenv("SUPERNOVA_SCAN_GATE_MAX_WAITING", "1")
    gate_mod.reset_gate_for_tests()
    yield
    gate_mod.reset_gate_for_tests()
```

（`test_gate_grants_when_capacity_free` 与 `test_gate_queues_until_slot_released` 里手动占槽的 `holder-wf` 即唯一的 1 个容量；`test_gate_queue_full_fails_workflow` 里 preload 1 + waiting 1 = 触发 queue_full。）

- [ ] **Step 2: 跑测试确认失败**

```bash
cd packages/whitebox && python -m pytest tests/pipeline/test_workflow_gate.py -v
```

预期：FAIL——workflow 未接闸门，`calls[0][0] == "gate_try"` 断言失败（首调用是别的）或 queue_full 用例直接到了 setup_display。

- [ ] **Step 3: 接线 WhiteboxScanWorkflow**

`packages/whitebox/src/supernova_whitebox/pipeline/workflows.py`：

(a) imports_passed_through 块（L89-93）追加一行：

```python
with workflow.unsafe.imports_passed_through():
    from . import activities
    from supernova_core.services.settings_writer import sync_code_path_deny_rules, cleanup_settings
    from supernova_core.services.scan_gate import (
        acquire_gate_slot, release_gate_slot, gate_scan_id_from_event_file)
    from supernova_core.models.retry import retry_for
    from supernova_core.models.errors import classify_error_for_temporal
```

(b) 模块级加 label helper（放在 `_derive_workspace_path` 附近）：

```python
def _gate_label(input: PipelineInput) -> str:
    """闸门快照展示标签：仓库名（MR 追加 !MR号，兜底 web_url）。"""
    from pathlib import Path
    repo = Path(input.repo_path).name if input.repo_path else ""
    if input.mr_meta:
        mr_id = (input.mr_meta.get("mr_iid") or input.mr_meta.get("mr_id") or "")
        return f"{repo}!{mr_id}" if mr_id else repo
    return repo or input.web_url
```

（`pathlib.Path` 若文件顶部已 import 则复用，去掉函数内 import。）

(c) `WhiteboxScanWorkflow.run()`（L161-162）改造——**run 体全部原有代码（从 L163 `# resume: 预填...` 注释起至方法末尾）整体包进 `try:`（缩进 +4），方法体最前加闸门段，末尾加 finally**：

```python
    @workflow.run
    async def run(self, input: PipelineInput) -> PipelineState:
        # 全局扫描闸门（spec 2026-09-08-worker-scan-gate §5）：排队轮询直到获得全局槽。
        # 放最前：排队期间不推进任何 pipeline 逻辑，start_time 亦在放行后才记
        # （duration 不含排队）。MR 的白盒子 workflow 也走这里（mr_meta 非空 → kind=mr）。
        await acquire_gate_slot({
            "kind": "mr" if input.mr_meta else "whitebox",
            "ws": input.workspace_name or gate_ws_from_path(input.event_file),
            "scan_id": gate_scan_id_from_event_file(input.event_file),
            "label": _gate_label(input),
        })
        try:
            ...（原 run 体 L163 起的全部代码，整体缩进 +4）...
        finally:
            await release_gate_slot()
```

`gate_ws_from_path` 也要加进 (a) 的 import（`from supernova_core.services.scan_gate import acquire_gate_slot, release_gate_slot, gate_scan_id_from_event_file, gate_ws_from_path`）。

同文件 `MrScanWorkflow.run()`（L1003 起）**不加闸门**（其子 WhiteboxScanWorkflow 占槽；MR 前置 activities 轻量，spec §5）。

- [ ] **Step 4: 跑测试确认通过**

```bash
cd packages/whitebox && python -m pytest tests/pipeline/test_workflow_gate.py tests/pipeline/test_workflow_migration.py tests/pipeline/test_mr_scan_workflow.py -v
```

预期：新 3 例 PASS；migration/MR 既有测试不回归（它们 mock 不到 gate activity 会怎样？——migration 测试只注册部分 activity：闸门 activity 未注册 → workflow 第一个 activity 就失败 → `pytest.raises(Exception)` 仍成立但 `calls` 断言会翻（setup_display 不再被调用）。**所以这两个既有测试的 activities 列表要补注册真 gate activity**：从 `supernova_core.services.scan_gate` import `scan_gate_try_acquire, scan_gate_release` 加进它们的 activity mock 列表/Worker 注册，并在测试里 `reset_gate_for_tests()` 清态（否则跨测试槽泄漏互扰）。若测试有共享 fixture 则加 autouse 清理。）

- [ ] **Step 5: Commit**

```bash
git add packages/whitebox/src/supernova_whitebox/pipeline/workflows.py packages/whitebox/tests/pipeline/test_workflow_gate.py packages/whitebox/tests/pipeline/test_workflow_migration.py packages/whitebox/tests/pipeline/test_mr_scan_workflow.py
git commit -m "feat(whitebox): WhiteboxScanWorkflow 接全局扫描闸门——run 开头排队轮询+finally 尽力释放，MR 子 workflow 自动占槽(kind=mr)；既有 workflow 测试补注册 gate activity(spec §5)"
```

---

### Task 3: Blackbox + Correlation workflow 闸门接线

**Files:**
- Modify: `packages/blackbox/src/supernova_blackbox/pipeline/workflows.py`（imports_passed_through L50-63；`run()` L71-72）
- Modify: `packages/multi/src/supernova_multi/pipeline/workflows.py`（imports L18-27；`CorrelationScanWorkflow.run` L55-62）
- Test: `packages/blackbox/tests/test_workflow_gate.py`（新建）、`packages/multi/tests/test_corr_gate.py`（新建）

**Interfaces:**
- Consumes: Task 1 的 gate helper；Task 2 的接线模式。
- Produces: 三类扫描 workflow 全部过闸（Whitebox/MR 在 Task 2，本任务补齐 Blackbox/Correlation）。

- [ ] **Step 1: 写失败的集成测试**

`packages/multi/tests/test_corr_gate.py`（corr 是单 activity 直通，最好测——mock `run_correlation_activity` 即全流程）：

```python
"""CorrelationScanWorkflow 闸门段集成测（spec §5）。"""

import asyncio

import pytest
from temporalio import activity
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from supernova_core.services import scan_gate as gate_mod
from supernova_multi.pipeline.workflows import CorrelationScanWorkflow
from supernova_multi.pipeline.shared import CorrelationPipelineInput


@pytest.fixture(autouse=True)
def _gate_env(monkeypatch):
    monkeypatch.setattr(gate_mod, "GATE_POLL_SECONDS", 0.05)
    monkeypatch.setenv("SUPERNOVA_SCAN_GATE_CAPACITY", "1")
    gate_mod.reset_gate_for_tests()
    yield
    gate_mod.reset_gate_for_tests()


def _inp(tmp_path):
    return CorrelationPipelineInput(
        config_path=str(tmp_path / "config.yaml"),
        repo_workspace_paths={"checkout": str(tmp_path / "ws" / "checkout"),
                              "payment": str(tmp_path / "ws" / "payment")},
        out_ws_dir=str(tmp_path / "ws" / "scans" / "corr-main"),
        event_file=str(tmp_path / "ws" / "scans" / "corr-main" / "events.ndjson"),
    )


@pytest.mark.asyncio
async def test_correlation_passes_gate_and_runs(tmp_path):
    done: list = []

    @activity.defn
    async def run_correlation_activity(inp):
        done.append(True)
        return {"status": "completed"}

    async with await WorkflowEnvironment.start_local() as env:
        async with Worker(env.client, task_queue="tq-corr-gate",
                          workflows=[CorrelationScanWorkflow],
                          activities=[gate_mod.scan_gate_try_acquire,
                                      gate_mod.scan_gate_release,
                                      run_correlation_activity]):
            r = await asyncio.wait_for(
                env.client.execute_workflow(
                    CorrelationScanWorkflow.run, _inp(tmp_path),
                    id="w-corr-gate", task_queue="tq-corr-gate"),
                timeout=30)
    assert done == [True]
    assert gate_mod._gate().candidate_ids() == []  # finally release 已清


@pytest.mark.asyncio
async def test_correlation_queues_until_slot_released(tmp_path):
    g = gate_mod._gate()
    g.try_acquire("holder", {"kind": "whitebox"})
    done: list = []

    @activity.defn
    async def run_correlation_activity(inp):
        done.append(True)
        return {"status": "completed"}

    async with await WorkflowEnvironment.start_local() as env:
        async with Worker(env.client, task_queue="tq-corr-gate",
                          workflows=[CorrelationScanWorkflow],
                          activities=[gate_mod.scan_gate_try_acquire,
                                      gate_mod.scan_gate_release,
                                      run_correlation_activity]):
            handle = await env.client.start_workflow(
                CorrelationScanWorkflow.run, _inp(tmp_path),
                id="w-corr-queued", task_queue="tq-corr-gate")
            await asyncio.sleep(0.5)
            assert done == []                    # 仍在排队
            g.release("holder")
            await asyncio.wait_for(handle.result(), timeout=30)
    assert done == [True]
```

`packages/blackbox/tests/test_workflow_gate.py`（bb 前导链长，用「gate 后首个 activity 是 setup_display，其后未注册即失败」模式）：

```python
"""BlackboxScanWorkflow 闸门段集成测（spec §5）。"""

import asyncio

import pytest
from temporalio import activity
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from supernova_core.services import scan_gate as gate_mod
from supernova_blackbox.pipeline.workflows import BlackboxScanWorkflow
from supernova_blackbox.pipeline.shared import BlackboxPipelineInput


@pytest.fixture(autouse=True)
def _gate_env(monkeypatch):
    monkeypatch.setattr(gate_mod, "GATE_POLL_SECONDS", 0.05)
    monkeypatch.setenv("SUPERNOVA_SCAN_GATE_CAPACITY", "1")
    gate_mod.reset_gate_for_tests()
    yield
    gate_mod.reset_gate_for_tests()


def _inp(tmp_path):
    return BlackboxPipelineInput(
        web_url="https://api.example.com",
        workspace_name="ws-bb-gate",
        workspaces_root=str(tmp_path),
        event_file=str(tmp_path / "ws-bb-gate" / "scans" / "s1" / "events.ndjson"),
    )


def _acts(calls: list) -> list:
    @activity.defn
    async def setup_display(i):
        calls.append("setup_display")
    return [gate_mod.scan_gate_try_acquire, gate_mod.scan_gate_release,
            setup_display]


@pytest.mark.asyncio
async def test_blackbox_gate_then_setup_display(tmp_path):
    calls: list = []
    async with await WorkflowEnvironment.start_local() as env:
        async with Worker(env.client, task_queue="tq-bb-gate",
                          workflows=[BlackboxScanWorkflow],
                          activities=_acts(calls)):
            with pytest.raises(Exception):   # 死于 setup_display 后首个未注册 activity
                await asyncio.wait_for(
                    env.client.execute_workflow(
                        BlackboxScanWorkflow.run, _inp(tmp_path),
                        id="w-bb-gate", task_queue="tq-bb-gate"),
                    timeout=30)
    assert "setup_display" in calls


@pytest.mark.asyncio
async def test_blackbox_queues_until_slot_released(tmp_path):
    g = gate_mod._gate()
    g.try_acquire("holder", {"kind": "whitebox"})
    calls: list = []
    async with await WorkflowEnvironment.start_local() as env:
        async with Worker(env.client, task_queue="tq-bb-gate",
                          workflows=[BlackboxScanWorkflow],
                          activities=_acts(calls)):
            handle = await env.client.start_workflow(
                BlackboxScanWorkflow.run, _inp(tmp_path),
                id="w-bb-queued", task_queue="tq-bb-gate")
            await asyncio.sleep(0.5)
            assert calls == []                # 排队中未到 setup_display
            g.release("holder")
            with pytest.raises(Exception):
                await asyncio.wait_for(handle.result(), timeout=30)
    assert "setup_display" in calls
```

- [ ] **Step 2: 跑测试确认失败**

```bash
cd packages/multi && python -m pytest tests/test_corr_gate.py -v
cd ../blackbox && python -m pytest tests/test_workflow_gate.py -v
```

预期：FAIL（workflow 未接闸门——`candidate_ids() == []` 断言失败或 `done == []` 排队断言失败）。

- [ ] **Step 3: 接线两个 workflow**

(a) `packages/blackbox/src/supernova_blackbox/pipeline/workflows.py`：

imports_passed_through 块（L50-63）追加：

```python
    from supernova_core.services.scan_gate import (
        acquire_gate_slot, release_gate_slot, gate_scan_id_from_event_file)
```

`BlackboxScanWorkflow.run()`（L71-72）——run 体全部原有代码（L73 `self._state.start_time = ...` 起至方法末尾）包进 `try:`（缩进 +4），方法最前加：

```python
    @workflow.run
    async def run(self, input: BlackboxPipelineInput) -> BlackboxPipelineState:
        # 全局扫描闸门（spec 2026-09-08-worker-scan-gate §5）
        await acquire_gate_slot({
            "kind": "blackbox",
            "ws": input.workspace_name or "",
            "scan_id": gate_scan_id_from_event_file(input.event_file),
            "label": input.web_url,
        })
        try:
            ...（原 run 体整体缩进 +4）...
        finally:
            await release_gate_slot()
```

注意：黑盒文件顶部异常类直接叫 `ApplicationError`（无别名），与闸门 helper 内部实现无关，无需改 import。

(b) `packages/multi/src/supernova_multi/pipeline/workflows.py`：

imports_passed_through 块（L18-27 附近）追加：

```python
    from supernova_core.services.scan_gate import (
        acquire_gate_slot, release_gate_slot,
        gate_scan_id_from_event_file, gate_ws_from_path)
```

`CorrelationScanWorkflow`（L55-62）整体替换为：

```python
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
        })
        try:
            return await workflow.execute_activity(
                run_correlation_activity, inp,
                start_to_close_timeout=timedelta(hours=4),
            )
        finally:
            await release_gate_slot()
```

- [ ] **Step 4: 跑测试确认通过（含既有回归）**

```bash
cd packages/multi && python -m pytest tests/test_corr_gate.py tests/test_corr_workflow.py -v
cd ../blackbox && python -m pytest tests/test_workflow_gate.py tests/test_auth_validation_workflow.py tests/test_workflow_phase_steps.py -v
```

黑盒既有 workflow 测试（auth_validation 等）注册的是 `AuthValidationWorkflow`——**辅助 workflow 不过闸门（Task 未动它），既有测试零影响**。若跑出其它白盒侧受闸门影响的测试文件同理处理（补注册 gate activity + reset 清态）。

- [ ] **Step 5: Commit**

```bash
git add packages/blackbox/src/supernova_blackbox/pipeline/workflows.py packages/multi/src/supernova_multi/pipeline/workflows.py packages/blackbox/tests/test_workflow_gate.py packages/multi/tests/test_corr_gate.py
git commit -m "feat(blackbox,multi): Blackbox/Correlation workflow 接全局扫描闸门——三类扫描 workflow 全过闸；corr ws 从路径反推(无 workspace_name 字段)(spec §5)"
```

---

### Task 4: runner 挂载——activity 注册 ×3 + bootstrap 预占 + janitor 兜底 + compose env

**Files:**
- Modify: `packages/worker/src/supernova_worker/runner.py`（import 区 L18-23 后；三 Worker activities 列表；`run_worker` 尾部 L205-211）
- Modify: `docker-compose.yml`（worker 服务 environment 段 L88-91）
- Test: `packages/worker/tests/test_runner_gate.py`（新建）、`packages/worker/tests/test_runner.py`（更新守护测试）

**Interfaces:**
- Consumes: `scan_gate_try_acquire` / `scan_gate_release` / `preload_gate` / `reap_ids` / `gate_candidate_ids`（Task 1）。
- Produces: worker 进程内闸门生效（三 queue 的扫描 workflow 都能执行 gate activity）；`_gate_bootstrap(client)` / `_gate_janitor(client)` / `_gate_janitor_once(client)`。

- [ ] **Step 1: 写失败测试**

创建 `packages/worker/tests/test_runner_gate.py`：

```python
"""runner 闸门挂载测试：bootstrap 预占两分支、janitor 单轮回收、三 worker 注册。"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from supernova_core.services import scan_gate as gate_mod


@pytest.fixture(autouse=True)
def _clean_gate():
    gate_mod.reset_gate_for_tests()
    yield
    gate_mod.reset_gate_for_tests()


def _flist(items):
    """mock list_workflows 的 async-iterable 返回值。"""
    async def gen():
        for it in items:
            yield it
    return gen()


class _W:  # 轻量 workflow handle 摘要
    def __init__(self, id):
        self.id = id


@pytest.mark.asyncio
async def test_bootstrap_preloads_running_scan_workflows(monkeypatch):
    monkeypatch.setenv("SUPERNOVA_SCAN_GATE_CAPACITY", "5")
    from supernova_worker import runner

    client = MagicMock()
    client.list_workflows = MagicMock(
        return_value=_flist([_W("a"), _W("b")]))
    await runner._gate_bootstrap(client)
    assert set(gate_mod.gate_candidate_ids()) == {"a", "b"}


@pytest.mark.asyncio
async def test_bootstrap_falls_back_to_workflow_type_query(monkeypatch):
    """TaskQueue visibility 查询不被支持时退化为 WorkflowType 过滤（spec §6）。"""
    monkeypatch.setenv("SUPERNOVA_SCAN_GATE_CAPACITY", "5")
    from supernova_worker import runner

    client = MagicMock()
    client.list_workflows = MagicMock(
        side_effect=[RuntimeError("unsupported attribute: TaskQueue"),
                     _flist([_W("c")])])
    await runner._gate_bootstrap(client)
    assert gate_mod.gate_candidate_ids() == ["c"]
    q2 = client.list_workflows.call_args_list[1].kwargs.get("query", "")
    assert "WorkflowType" in q2


@pytest.mark.asyncio
async def test_janitor_once_reaps_dead_workflows(monkeypatch):
    monkeypatch.setenv("SUPERNOVA_SCAN_GATE_CAPACITY", "5")
    from supernova_worker import runner
    from temporalio.client import WorkflowExecutionStatus

    gate_mod.preload_gate(["alive", "dead"])
    live_desc = MagicMock()
    live_desc.status = WorkflowExecutionStatus.RUNNING
    ok_handle = MagicMock()
    ok_handle.describe = AsyncMock(return_value=live_desc)
    dead_handle = MagicMock()
    dead_handle.describe = AsyncMock(side_effect=RuntimeError("not found"))

    client = MagicMock()
    client.get_workflow_handle = MagicMock(
        side_effect=lambda wf_id: {"alive": ok_handle, "dead": dead_handle}[wf_id])
    await runner._gate_janitor_once(client)
    assert gate_mod.gate_candidate_ids() == ["alive"]


@pytest.mark.asyncio
async def test_run_worker_registers_gate_activities_on_all_three_workers():
    """守护：漏注册 gate activity = 排队 workflow 的 activity 无处执行直接超时。"""
    from supernova_worker import runner

    wb = MagicMock(); wb.run = AsyncMock(return_value=None)
    bb = MagicMock(); bb.run = AsyncMock(return_value=None)
    corr = MagicMock(); corr.run = AsyncMock(return_value=None)
    with patch("supernova_worker.runner.Client.connect",
               AsyncMock(return_value=MagicMock())), \
         patch("supernova_worker.runner.Worker",
               side_effect=[wb, bb, corr]) as mw, \
         patch("supernova_worker.runner._gate_bootstrap", new=AsyncMock()), \
         patch("supernova_worker.runner._gate_janitor", new=AsyncMock()):
        await runner.run_worker("temporal:7233")
    for call in mw.call_args_list:
        acts = call.kwargs["activities"]
        assert gate_mod.scan_gate_try_acquire in acts
        assert gate_mod.scan_gate_release in acts
```

上面第 4 个测试需要 `from unittest.mock import AsyncMock, MagicMock, patch`（文件顶部 import 补齐 `patch`）。

```python
@pytest.mark.asyncio
async def test_run_worker_registers_gate_activities_on_all_three_workers():
    from unittest.mock import AsyncMock, MagicMock, patch
    from supernova_worker import runner

    wb = MagicMock(); wb.run = AsyncMock(return_value=None)
    bb = MagicMock(); bb.run = AsyncMock(return_value=None)
    corr = MagicMock(); corr.run = AsyncMock(return_value=None)
    with patch("supernova_worker.runner.Client.connect",
               AsyncMock(return_value=MagicMock())), \
         patch("supernova_worker.runner.Worker",
               side_effect=[wb, bb, corr]) as mw, \
         patch("supernova_worker.runner._gate_bootstrap", new=AsyncMock()), \
         patch("supernova_worker.runner._gate_janitor", new=AsyncMock()):
        await runner.run_worker("temporal:7233")
    for call in mw.call_args_list:
        acts = call.kwargs["activities"]
        assert gate_mod.scan_gate_try_acquire in acts
        assert gate_mod.scan_gate_release in acts
```

（写文件时直接用这版第 4 个测试，删掉草稿版。）

- [ ] **Step 2: 跑测试确认失败**

```bash
cd packages/worker && python -m pytest tests/test_runner_gate.py -v
```

预期：FAIL（`runner._gate_bootstrap` / `_gate_janitor_once` 不存在；注册断言失败）。

- [ ] **Step 3: 实现 runner 挂载**

`packages/worker/src/supernova_worker/runner.py`：

(a) import 区（L73 `from supernova_core.runtime.heartbeat import snapshot_heartbeat_workflows` 之后）追加：

```python
from supernova_core.services.scan_gate import (
    scan_gate_try_acquire, scan_gate_release,
    preload_gate, reap_ids, gate_candidate_ids,
)
```

(b) 常量区（`_CANCEL_BRIDGE_INTERVAL_SECONDS = 5.0` L83 后）追加：

```python
# 闸门 janitor 轮询周期（spec §6）：槽泄漏兜底，最坏多占一个周期。
_GATE_JANITOR_INTERVAL_SECONDS = 10.0
# bootstrap 预占的扫描类 workflow 类型（退化查询用；TaskQueue 查询优先）
_SCAN_WORKFLOW_TYPES = (
    "BlackboxScanWorkflow", "CorrelationScanWorkflow",
    "MrScanWorkflow", "WhiteboxScanWorkflow",
)
```

(c) 取消桥函数后（`_cancel_signal_bridge` 定义之后、`run_worker` 之前）追加三个函数：

```python
async def _gate_bootstrap(client: Client) -> None:
    """worker 启动预占：所有 RUNNING 扫描类 workflow 计槽（spec §6 防重启超卖）。

    重启后内存闸门清零，但已过闸的 workflow 重放不会重新 acquire（event-sourced
    history 恢复 granted 结果直接跳过闸门段）——不预占则新排队者立即拿空闸门超卖。
    TaskQueue visibility 查询优先（排除 CLI 随机 queue 的同类型 workflow）；
    当前 temporal 版本不支持该 search attribute 时退化为 WorkflowType 过滤
    （接受 CLI 干扰：保守少槽，无害，spec §11）。
    """
    queues = "','".join(
        (WEB_TASK_QUEUE_WHITEBOX, WEB_TASK_QUEUE_BLACKBOX, WEB_TASK_QUEUE_CORRELATION))
    types = "','".join(_SCAN_WORKFLOW_TYPES)
    try:
        ids = [w.id async for w in client.list_workflows(
            query=f"TaskQueue IN ('{queues}')")]
    except Exception:
        ids = [w.id async for w in client.list_workflows(
            query=f"WorkflowType IN ('{types}')")]
    preload_gate(ids)


async def _gate_janitor_once(client: Client) -> None:
    """单轮闸门回收：校验持有/等待者存活性，死 key 摘除（spec §6）。

    覆盖一切异常释放路径：cancel 保险丝 terminate（不给清理机会）、cancel 时
    cleanup 没跑成、workflow 崩溃。waiting 死 key 同摘——幽灵排队者会挡 FIFO。
    """
    from temporalio.client import WorkflowExecutionStatus
    for wf_id in gate_candidate_ids():
        try:
            desc = await client.get_workflow_handle(wf_id).describe()
            alive = desc.status == WorkflowExecutionStatus.RUNNING
        except Exception:
            alive = False  # 查不到 = 死 key，best-effort 回收
        if not alive:
            reap_ids([wf_id])


async def _gate_janitor(client: Client) -> None:
    """闸门 janitor 主循环（worker 常驻后台 task，进程退出即止；对齐取消桥模式）。"""
    while True:
        await asyncio.sleep(_GATE_JANITOR_INTERVAL_SECONDS)
        try:
            await _gate_janitor_once(client)
        except Exception:  # noqa: BLE001 - janitor 绝不因单轮异常退出
            pass
```

(d) 三个 Worker 的 `activities=[...]` 列表（wb L131-157、bb L167-183、corr L196）各追加两项 `scan_gate_try_acquire, scan_gate_release`。

(e) `run_worker` 尾部（L205-211）改为：

```python
    # 闸门 bootstrap 预占必须在 worker 消费前（spec §6）
    await _gate_bootstrap(client)

    # 协作取消桥（方案 B）：把 web cancel ② 轨的 cancel.requested 文件信号转发为
    # temporal cancel（worker 容器路径协作通道的唯一消费者）。worker 全退时一并取消。
    bridge = asyncio.create_task(_cancel_signal_bridge(client))
    gate_janitor_task = asyncio.create_task(_gate_janitor(client))
    try:
        await asyncio.gather(wb_worker.run(), bb_worker.run(), corr_worker.run())
    finally:
        bridge.cancel()
        gate_janitor_task.cancel()
```

(f) `docker-compose.yml` worker 服务 environment 段（L88-91）追加三行：

```yaml
    environment:
      - SUPERNOVA_TEMPORAL_HOST=temporal
      - SUPERNOVA_TEMPORAL_PORT=7233
      - SUPERNOVA_TEMPORALIO_LOG_LEVEL=${SUPERNOVA_TEMPORALIO_LOG_LEVEL:-WARNING}
      - SUPERNOVA_SCAN_GATE_CAPACITY=${SUPERNOVA_SCAN_GATE_CAPACITY:-5}
      - SUPERNOVA_SCAN_GATE_MAX_WAITING=${SUPERNOVA_SCAN_GATE_MAX_WAITING:-50}
      - SUPERNOVA_SCAN_GATE_STATE_FILE=/app/workspaces/gate_state.json
```

（worker 与 web 容器都挂 `./workspaces:/app/workspaces`，bind mount 共享——`scan_liveness` 已验证此通道。）

- [ ] **Step 4: 更新守护测试 + 跑全部**

`packages/worker/tests/test_runner.py` 的 `test_run_worker_registers_all_defined_activities`（L70-131，用 `_activity_def_names` 精确集合比对）——expected 集合加 `"scan_gate_try_acquire"` 与 `"scan_gate_release"`（对齐该测试现有的名字推导方式：它扫的是 workflow 包里定义的全部 activity 还是显式列表——按其现逻辑把两个新名字补进期望集合）。

既有 `test_run_worker_connects_and_registers_three_workers`（L17-66）与 `test_worker_max_concurrent_reads_env`（L216-236）会因 `run_worker` 新增 `await _gate_bootstrap(client)` 挂掉（mock client 的 list_workflows 不可迭代）——两个测试的 patch 块各补一行：

```python
        patch("supernova_worker.runner._gate_bootstrap", new=AsyncMock()),
        patch("supernova_worker.runner._gate_janitor", new=AsyncMock()),
```

`test_run_worker_starts_cancel_bridge`（L340-358）同理补 patch（若其已 patch `_cancel_signal_bridge` 则照它的样式加两行）。

```bash
cd packages/worker && python -m pytest tests/test_runner_gate.py tests/test_runner.py -v
```

预期：全部 PASS。

- [ ] **Step 5: Commit**

```bash
git add packages/worker/src/supernova_worker/runner.py packages/worker/tests/test_runner_gate.py packages/worker/tests/test_runner.py docker-compose.yml
git commit -m "feat(worker): 闸门挂载——三 worker 注册 gate activity + bootstrap 重启预占(TaskQueue 查询退化 WorkflowType) + janitor 10s 周期回收死槽(对齐取消桥模式) + compose 三 env(spec §6)"
```

---

### Task 5: web 删门——TooManyScans 全链退役

**Files:**
- Modify: `packages/web/src/supernova_web/components/scan_manager.py`（L46-49 类、L311-312/L598-599 raise、`__init__` 的 `max_concurrent` 参数）
- Modify: `packages/web/src/supernova_web/api/scan.py`（L9 import、L44-45 except）
- Modify: `packages/web/src/supernova_web/api/scans.py`（L670 import、L681-682 except）
- Modify: `packages/web/src/supernova_web/config.py`（L12-13）
- Modify: `packages/web/src/supernova_web/app.py`（L297-299 构造参数）
- Modify: `docker-compose.yml`（web 服务 L54 删透传）
- Modify: `packages/web/frontend/src/pages/ScanNewPage.tsx`（L391 的 409 分支；**有并行会话改动，先 grep 重新定位**）
- Modify: `packages/web/frontend/src/locales/zh.json` + `en.json`（L358 `scan.errors.concurrent` 键）
- Test: 删改 `packages/web/tests/test_scan_manager.py`、`test_scan_manager_multi.py`、`test_api_scan.py`

**Interfaces:**
- Consumes: 无。
- Produces: web 不再有并发拒绝门（排队权威在 worker 闸门）；`_handles` 保留仅供 `_watch`/cancel（非闸门）。

- [ ] **Step 1: 先改测试（删除断言拒绝的用例，新增不拒绝的用例）**

`packages/web/tests/test_scan_manager.py`：
- import 行 L20 收窄：去掉 `TooManyScans`。
- 删除 `test_concurrency_limit_raises`（L157-165 整个函数）。
- 新增替代测试（同文件）：

```python
@pytest.mark.asyncio
async def test_start_no_longer_rejects_when_handles_full(tmp_path, monkeypatch):
    """并发闸门下沉 worker 后（spec 2026-09-08-worker-scan-gate §7）：web 不再拒绝。

    _handles 占满（甚至塞超）也应照常走 start 流程——排队发生在 worker 闸门。"""
    sm = ScanManager(tmp_path, tmp_path, MagicMock())
    sm._handles[("ws", "s-old-1")] = object()
    sm._handles[("ws", "s-old-2")] = object()
    # 只验证不再抛 TooManyScans：走 _check_temporal 失败即返回（伪造 temporal 不可用）
    async def _boom():
        raise TemporalUnavailable("down")
    monkeypatch.setattr(sm, "_check_temporal", _boom)
    with pytest.raises(TemporalUnavailable):
        await sm.start(_minimal_start_request(tmp_path))
```

（`_minimal_start_request` 若文件里没有现成构造 helper，参考 `test_concurrency_limit_raises` 原来怎么构造 start 入参——它必然构造过（占 `_handles` 后调 start 期待 TooManyScans），把那段构造逻辑抽成本地 helper 复用。）

`packages/web/tests/test_scan_manager_multi.py`：
- import 行 L16 收窄。
- 删除 `test_resume_too_many_scans_raises`（L205-212 整个函数）。

`packages/web/tests/test_api_scan.py`：
- import 行 L5 收窄（去掉 TooManyScans）。
- 删除 `test_post_scan_409_concurrent`（L97-105 整个函数）。

- [ ] **Step 2: 跑测试确认失败**

```bash
cd packages/web && python -m pytest tests/test_scan_manager.py tests/test_scan_manager_multi.py tests/test_api_scan.py -v
```

预期：新用例 FAIL（`TooManyScans` 仍被 raise——尽管 monkeypatch 了 `_check_temporal`？不：`_check_temporal` 先抛 `TemporalUnavailable` 说明检查在其后。若实际代码顺序是检查在 `_check_temporal` **之后**（L303→311），`_boom` 抛 TemporalUnavailable 时还没走到 TooManyScans 检查——那测试就不 FAIL 了。**正确写法**：不 monkeypatch `_check_temporal`，而是让 start 走到检查点——用与被删测试相同的「让 `_check_temporal` 通过」的手段（看被删测试怎么 mock 的，照搬），断言 `TooManyScans` 不再出现且流程继续（后续失败于别的预期点，如 repo 不存在 ValueError）。以被删用例的 mock 设施为准调整断言。）

- [ ] **Step 3: 删除 web 门**

(a) `scan_manager.py`：
- 删 `TooManyScans` 类（L46-49）。
- 删 start 检查（L311-312）：`if len(self._handles) >= self._max_concurrent: raise TooManyScans(self._max_concurrent)`（连同其注释行）。
- 删 resume 检查（L597-599 同款）。
- `__init__` 签名删 `max_concurrent` 参数与 `self._max_concurrent` 赋值（`grep -n "max_concurrent" packages/web/src/supernova_web/` 找全：定义、赋值、所有引用）。

(b) `api/scan.py`：L9 import 收窄为只留 `TemporalUnavailable`（及原有其它项）；删 L44-45 两行 except 块。

(c) `api/scans.py`：L670 函数内 import 收窄；删 L681-682 except 块。

(d) `config.py`：删 L12-13（注释 + `self.max_concurrent = ...`）。

(e) `app.py` L297-299：构造调用删 `max_concurrent=cfg.max_concurrent,`。

(f) `docker-compose.yml` web 服务删 `- SUPERNOVA_WEB_MAX_CONCURRENT=${SUPERNOVA_WEB_MAX_CONCURRENT:-4}`（L54）。

(g) 前端：`grep -n "errors.concurrent\|status === 409" packages/web/frontend/src/pages/ScanNewPage.tsx` 重新定位（并行会话在改此文件），删除 `if (e.status === 409) return t("scan.errors.concurrent");` 行；`zh.json`/`en.json` 删 `scan.errors.concurrent` 键（原 L358）。

- [ ] **Step 4: 跑测试确认通过 + 前端类型门**

```bash
cd packages/web && python -m pytest tests/test_scan_manager.py tests/test_scan_manager_multi.py tests/test_api_scan.py -v
cd frontend && npx tsc -b && npx vitest run src/pages/ScanNewPage.test.tsx 2>/dev/null || true
```

（ScanNewPage 若无测试文件则跳过 vitest；`tsc -b` 必须零错误。）

- [ ] **Step 5: Commit**

```bash
git add packages/web/src/supernova_web/components/scan_manager.py packages/web/src/supernova_web/api/scan.py packages/web/src/supernova_web/api/scans.py packages/web/src/supernova_web/config.py packages/web/src/supernova_web/app.py docker-compose.yml packages/web/frontend/src/pages/ScanNewPage.tsx packages/web/frontend/src/locales/zh.json packages/web/frontend/src/locales/en.json packages/web/tests/test_scan_manager.py packages/web/tests/test_scan_manager_multi.py packages/web/tests/test_api_scan.py
git commit -m "feat(web): 删并发拒绝门——TooManyScans/409/SUPERNOVA_WEB_MAX_CONCURRENT 全链退役，_handles 降级为 _watch/cancel 内部簿记；排队权威移交 worker 闸门(spec §7)"
```

---

### Task 6: `_compute_status` queued 档 + orphan_reconciler 短路

**Files:**
- Modify: `packages/web/src/supernova_web/components/workspaces_indexer.py`（`_compute_status` L37-56）
- Modify: `packages/web/src/supernova_web/components/orphan_reconciler.py`（`reconcile_orphaned` L169 附近）
- Test: `packages/web/tests/test_gate_status.py`（新建）

**Interfaces:**
- Consumes: `read_gate_snapshot_file`（Task 1）；`gate_state.json` 约定路径 `<workspaces_root>/gate_state.json`（Task 4 compose）。
- Produces: `_compute_status` 返回 `"queued"`；`_is_queued_in_gate(path: Path) -> bool`（Task 8 前端经 scans API 间接受益）。

- [ ] **Step 1: 写失败测试**

创建 `packages/web/tests/test_gate_status.py`：

```python
"""排队状态计算：_compute_status queued 档 + reconciler 不误杀排队中扫描（spec §7）。"""

import json

from supernova_web.components.workspaces_indexer import _compute_status
from supernova_web.components.scan_liveness import is_scan_alive  # noqa: F401（确认导入面）


def _mk_scan(tmp_path, ws="prod", scan_id="20260908-120000"):
    scan_dir = tmp_path / "workspaces" / ws / "scans" / scan_id
    scan_dir.mkdir(parents=True)
    (scan_dir / "session.json").write_text("{}")
    return scan_dir


def _write_gate(tmp_path, waiting):
    (tmp_path / "workspaces" / "gate_state.json").write_text(
        json.dumps({"capacity": 5, "held": [], "waiting": waiting}))


def test_compute_status_queued_when_in_gate_waiting(tmp_path):
    scan_dir = _mk_scan(tmp_path)
    _write_gate(tmp_path, [{"ws": "prod", "scan_id": "20260908-120000",
                            "kind": "whitebox", "label": "r@main", "since": 1.0}])
    # 无 heartbeat、超宽限 → 旧逻辑判 interrupted；新逻辑判 queued
    assert _compute_status(scan_dir, None) == "queued"


def test_compute_status_interrupted_when_gate_miss(tmp_path):
    scan_dir = _mk_scan(tmp_path)
    _write_gate(tmp_path, [{"ws": "prod", "scan_id": "other-scan",
                            "kind": "whitebox", "label": "x", "since": 1.0}])
    assert _compute_status(scan_dir, None) == "interrupted"


def test_compute_status_terminal_still_wins(tmp_path):
    scan_dir = _mk_scan(tmp_path)
    _write_gate(tmp_path, [{"ws": "prod", "scan_id": "20260908-120000",
                            "kind": "whitebox", "label": "r", "since": 1.0}])
    assert _compute_status(scan_dir, "completed") == "completed"


def test_compute_status_corr_main_queued_via_children(tmp_path):
    """跨仓主行：主行自身不在 waiting，但 corr_children 里非 reused 子仓在排队。"""
    main_dir = _mk_scan(tmp_path, scan_id="corr-main")
    (main_dir / "session.json").write_text(json.dumps({
        "corr_children": [
            {"service": "checkout", "scan_id": "child-1", "reused": False},
            {"service": "payment", "scan_id": "old-9", "reused": True},
        ]}))
    _write_gate(tmp_path, [{"ws": "prod", "scan_id": "child-1",
                            "kind": "whitebox", "label": "c", "since": 1.0}])
    assert _compute_status(main_dir, None) == "queued"


def test_reconciler_skips_queued(tmp_path):
    """orphan_reconciler：排队中（gate waiting 命中）不 reconcile（spec §7.5）。"""
    import asyncio
    from unittest.mock import MagicMock
    from supernova_web.components import orphan_reconciler as orc

    scan_dir = _mk_scan(tmp_path)
    _write_gate(tmp_path, [{"ws": "prod", "scan_id": "20260908-120000",
                            "kind": "whitebox", "label": "r", "since": 1.0}])
    called = []

    async def _fake_still_running(ws_dir):
        called.append(True)
        return False

    orig = orc._workflow_still_running
    orc._workflow_still_running = _fake_still_running
    try:
        r = asyncio.run(orc.reconcile_orphaned(scan_dir, False, None))
    finally:
        orc._workflow_still_running = orig
    assert r is False
    assert called == []          # queued 短路在 temporal 查询之前
    # 未被误标 interrupted
    sess = json.loads((scan_dir / "session.json").read_text())
    assert sess.get("status") != "interrupted"
```

- [ ] **Step 2: 跑测试确认失败**

```bash
cd packages/web && python -m pytest tests/test_gate_status.py -v
```

预期：FAIL（`_compute_status` 返回 "interrupted"，无 queued 档）。

- [ ] **Step 3: 实现**

(a) `workspaces_indexer.py`——`_compute_status` 与新 helper：

```python
def _compute_status(path: Path, session_status: str | None) -> str:
    """……（原 docstring 保留）……
    queued 档（spec 2026-09-08-worker-scan-gate §7.4）：非终态 + 心跳死但命中
    worker 闸门 waiting——修复「排队 >120s 显示已中断」的预存 bug。"""
    if session_status in _TERMINAL_STATUSES:
        return session_status
    if is_scan_alive(path):
        return "running"
    if _is_queued_in_gate(path):
        return "queued"
    return "interrupted"
```

模块级新增（放在 `_compute_status` 后）：

```python
def _gate_state_file_for(p: Path) -> Path | None:
    """从 scan_dir/ws_dir 反推 workspaces 根下的 gate_state.json（Task 4 落盘约定）。"""
    for anc in p.parents:
        if anc.name == "scans":
            return anc.parent / "gate_state.json"
    for anc in p.parents:
        if anc.name == "workspaces":
            return anc / "gate_state.json"
    return None


def _ws_and_scan_of(path: Path) -> tuple[str, str]:
    """scan_dir=…/<ws>/scans/<scan_id> → (ws, scan_id)；ws_dir 场景 scan_id 空。"""
    parts = path.parts
    if len(parts) >= 3 and parts[-2] == "scans":
        return parts[-3], parts[-1]
    return (parts[-1] if parts else "", "")


def _is_queued_in_gate(path: Path) -> bool:
    """非终态 + 心跳死时查闸门快照：本 scan（或 corr 非 reused 子仓）在 waiting。"""
    from supernova_core.services.scan_gate import read_gate_snapshot_file

    sf = _gate_state_file_for(path)
    if sf is None:
        return False
    snap = read_gate_snapshot_file(sf)
    if not snap:
        return False
    waiting = {(w.get("ws", ""), w.get("scan_id", ""))
               for w in snap.get("waiting", [])}
    if not waiting:
        return False
    ws, scan_id = _ws_and_scan_of(path)
    if (ws, scan_id) in waiting:
        return True
    # 跨仓主行：corr_children 非 reused 子仓在排队 → 主行 queued（spec §7.4）
    try:
        sess = json.loads((path / "session.json").read_text())
    except (OSError, ValueError):
        return False
    for child in (sess or {}).get("corr_children") or []:
        if not child.get("reused") and (ws, child.get("scan_id", "")) in waiting:
            return True
    return False
```

（`workspaces_indexer.py` 顶部若无 `import json` 则补。）

(b) `orphan_reconciler.py`——`reconcile_orphaned` 的 `_workflow_still_running` 检查处（L169 `if await _workflow_still_running(ws_dir): return False` 前）插入短路：

```python
    # 排队中（worker 闸门 waiting 命中）：正常等待态，心跳不更新是预期（spec §7.5）
    from supernova_web.components.workspaces_indexer import _is_queued_in_gate
    if _is_queued_in_gate(ws_dir):
        return False
```

- [ ] **Step 4: 跑测试确认通过（含既有回归）**

```bash
cd packages/web && python -m pytest tests/test_gate_status.py tests/test_scan_liveness.py -v
```

（`test_scan_liveness.py:146-159` 用到 `_compute_status`——确认无回归。）

- [ ] **Step 5: Commit**

```bash
git add packages/web/src/supernova_web/components/workspaces_indexer.py packages/web/src/supernova_web/components/orphan_reconciler.py packages/web/tests/test_gate_status.py
git commit -m "feat(web): _compute_status 补 queued 档(修排队>120s 误显已中断)+reconciler 排队短路——gate_state.json waiting 命中判定，corr 主行经 corr_children 非 reused 子仓联动(spec §7)"
```

---

### Task 7: `GET /api/scan/gate` 快照端点

**Files:**
- Modify: `packages/web/src/supernova_web/api/scan.py`（router prefix `/api/scan`，加 GET `/gate` → `/api/scan/gate`）
- Test: `packages/web/tests/test_api_scan.py`（追加）

**Interfaces:**
- Consumes: `read_gate_snapshot_file`（Task 1）；`current_user` / `is_global_admin` / `auth_store.list_user_workspaces`（现有 auth 惯例，见 `api/workspaces.py:63-71` 范例）。
- Produces: `GET /api/scan/gate` → `{"capacity": int, "max_waiting": int, "held": [...], "waiting": [...]}`；waiting 按 first_seen 序（= 排队位次）。

- [ ] **Step 1: 写失败测试**

`packages/web/tests/test_api_scan.py` 追加：

```python
@pytest.mark.asyncio
async def test_get_scan_gate_returns_snapshot(tmp_path, monkeypatch):
    """正常：读 gate_state.json 返回快照。"""
    import json
    app = _create_app_with_workspaces(tmp_path)  # 对齐本文件现有 app 构造 helper
    gate = tmp_path / "gate_state.json"
    gate.write_text(json.dumps({
        "capacity": 5, "max_waiting": 50,
        "held": [{"ws": "w1", "scan_id": "s1", "kind": "whitebox",
                  "label": "r@main", "since": 1.0}],
        "waiting": [{"ws": "w2", "scan_id": "s2", "kind": "mr",
                     "label": "u!12", "since": 2.0}]}))
    resp = await app.test_client.get("/api/scan/gate", headers=_auth_headers())
    assert resp.status_code == 200
    body = resp.json()
    assert body["capacity"] == 5
    assert body["held"][0]["ws"] == "w1"


@pytest.mark.asyncio
async def test_get_scan_gate_missing_file_empty(tmp_path):
    """worker 未起/未落盘：空快照不 500。"""
    app = _create_app_with_workspaces(tmp_path)
    resp = await app.test_client.get("/api/scan/gate", headers=_auth_headers())
    assert resp.status_code == 200
    assert resp.json() == {"capacity": 5, "max_waiting": 50, "held": [], "waiting": []}


@pytest.mark.asyncio
async def test_get_scan_gate_filters_by_ws_membership(tmp_path):
    """非全局 admin：无权 ws 的条目过滤，容量计数保留（spec §8.1）。"""
    import json
    app = _create_app_with_workspaces(tmp_path, role="member", member_of={"w1"})
    gate = tmp_path / "gate_state.json"
    gate.write_text(json.dumps({
        "capacity": 5, "max_waiting": 50,
        "held": [{"ws": "w1", "scan_id": "s1", "kind": "whitebox", "label": "a", "since": 1.0},
                 {"ws": "w2", "scan_id": "s2", "kind": "whitebox", "label": "b", "since": 1.0}],
        "waiting": [{"ws": "w3", "scan_id": "s3", "kind": "blackbox", "label": "c", "since": 2.0}]}))
    resp = await app.test_client.get("/api/scan/gate", headers=_auth_headers())
    body = resp.json()
    assert [e["ws"] for e in body["held"]] == ["w1"]
    assert body["waiting"] == []
    assert body["capacity"] == 5
```

（`_create_app_with_workspaces` / `_auth_headers`：对齐本文件现有的 app/user 构造方式——看 `test_post_scan_409_concurrent` 原来怎么建 app 与登录态，抽公共 helper；若本文件无此设施，参考 `packages/web/tests/` 里其它 api 测试的 app fixture 模式。权限用例需构造普通 member 用户 + `auth_store.list_user_workspaces` 返回 `["w1"]` 的 mock，对齐 `api/workspaces.py:70` 的调用面。）

- [ ] **Step 2: 跑测试确认失败**

```bash
cd packages/web && python -m pytest tests/test_api_scan.py -v -k scan_gate
```

预期：FAIL（404，端点不存在）。

- [ ] **Step 3: 实现端点**

`api/scan.py` 顶部 import 区补（对齐该文件现有 import 分组）：

```python
from supernova_core.services.scan_gate import read_gate_snapshot_file
from supernova_web.auth.dependencies import current_user
from supernova_web.components.workspace_provisioner import is_global_admin
```

（`current_user`/`is_global_admin` 若已被该文件 import 则不重复；`Depends` 已有。）

文件尾部追加：

```python
@router.get("/gate")
async def get_scan_gate(request: Request, user=Depends(current_user)):
    """全局扫描闸门快照（排队可视化，spec §8.1）：held/waiting + 容量。

    快照由 worker 闸门原子写（gate_state.json）；文件缺失/损坏 = worker 未起或
    未配置落盘 → 空快照。非全局 admin 按工作区成员资格过滤条目，容量计数保留
    （全局数字无害）。
    """
    sf = request.app.state.config.workspaces_dir / "gate_state.json"
    data = read_gate_snapshot_file(sf) or {
        "capacity": 5, "max_waiting": 50, "held": [], "waiting": []}
    if not is_global_admin(user):
        allowed = set(request.app.state.auth_store.list_user_workspaces(user.id))
        data = {**data,
                "held": [e for e in data.get("held", []) if e.get("ws") in allowed],
                "waiting": [e for e in data.get("waiting", [])
                            if e.get("ws") in allowed]}
    return data
```

- [ ] **Step 4: 跑测试确认通过**

```bash
cd packages/web && python -m pytest tests/test_api_scan.py -v
```

- [ ] **Step 5: Commit**

```bash
git add packages/web/src/supernova_web/api/scan.py packages/web/tests/test_api_scan.py
git commit -m "feat(web): GET /api/scan/gate 闸门快照端点——held/waiting/容量，非全局 admin 按 ws 成员过滤条目、文件缺失返回空快照(spec §8.1)"
```

---

### Task 8: 前端——queued 徽章 + 并发概览面板 + 排队位次

**Files:**
- Modify: `packages/web/frontend/src/api/types.ts`（L115-117 WorkspaceStatus）
- Modify: `packages/web/frontend/src/api/client.ts`（L208 `listScans` 附近加 `getScanGate`）
- Modify: `packages/web/frontend/src/components/StatusBadge.tsx`（MAP L4-13）
- Create: `packages/web/frontend/src/components/ScanGatePanel.tsx`
- Modify: `packages/web/frontend/src/routes/WorkspaceDetail/ScanList.tsx`（顶部挂面板；L488 状态单元格加位次）
- Modify: `packages/web/frontend/src/locales/zh.json` + `en.json`（workspaces.status 段 L236-245）
- Test: `packages/web/frontend/src/components/StatusBadge.test.tsx`（追加）、`packages/web/frontend/src/components/ScanGatePanel.test.tsx`（新建）

**Interfaces:**
- Consumes: `GET /api/scan/gate`（Task 7）；`_compute_status` 的 "queued"（Task 6）。
- Produces: `getScanGate()`、`ScanGateSnapshot`/`ScanGateEntry` 类型、`<ScanGatePanel />`。

- [ ] **Step 1: 写失败测试**

`StatusBadge.test.tsx` 追加（对齐现有用例风格）：

```tsx
it("queued → ⏳ + 排队中", () => {
  render(<StatusBadge status="queued" />);
  expect(screen.getByText("排队中")).toBeInTheDocument();
});
```

新建 `ScanGatePanel.test.tsx`：

```tsx
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import i18n from "@/i18n";
import { ScanGatePanel } from "./ScanGatePanel";
import type { ScanGateSnapshot } from "@/api/client";

beforeEach(() => i18n.changeLanguage("zh"));

vi.mock("@/api/client", () => ({
  getScanGate: vi.fn(),
}));

const snap: ScanGateSnapshot = {
  capacity: 5,
  max_waiting: 50,
  held: [
    { ws: "prod", scan_id: "s1", kind: "whitebox", label: "payment-svc@main", since: 1 },
  ],
  waiting: [
    { ws: "dev", scan_id: "s2", kind: "mr", label: "user-svc!12", since: 2 },
  ],
};

describe("ScanGatePanel", () => {
  it("空快照不渲染", () => {
    const { container } = render(<ScanGatePanel snapshot={{ capacity: 5, max_waiting: 50, held: [], waiting: [] }} />);
    expect(container.querySelector("[data-testid=scan-gate-panel]")).toBeNull();
  });

  it("渲染运行中/排队中两栏 + 工作区/标签/位次", () => {
    render(<ScanGatePanel snapshot={snap} />);
    const panel = screen.getByTestId("scan-gate-panel");
    expect(panel).toHaveTextContent("1/5");
    expect(panel).toHaveTextContent("payment-svc@main");
    expect(panel).toHaveTextContent("user-svc!12");
    expect(panel).toHaveTextContent("第 1 位");
  });

  it("kind 徽章 i18n（whitebox→白盒）", () => {
    render(<ScanGatePanel snapshot={snap} />);
    expect(screen.getByText("白盒")).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: 跑测试确认失败**

```bash
cd packages/web/frontend && npx vitest run src/components/ScanGatePanel.test.tsx src/components/StatusBadge.test.tsx
```

预期：FAIL（组件/类型/键不存在）。

- [ ] **Step 3: 实现**

(a) `types.ts` L115-117：

```ts
export type WorkspaceStatus =
  | "running" | "in-progress" | "interrupted" | "queued"
  | "completed" | "failed" | "killed" | "crashed";
```

(b) `client.ts`（`listScans` L208 附近）：

```ts
// === 全局扫描闸门（spec 2026-09-08-worker-scan-gate §8）：排队可视化 ===
export type ScanGateEntry = {
  workflow_id?: string;
  ws?: string;
  scan_id?: string;
  kind?: string;
  label?: string;
  since?: number;
};
export type ScanGateSnapshot = {
  capacity: number;
  max_waiting?: number;
  held: ScanGateEntry[];
  waiting: ScanGateEntry[];
};
/** 闸门快照（GET /api/scan/gate）：held=占槽者、waiting 按排队序（=位次）。 */
export const getScanGate = () =>
  apiGet<ScanGateSnapshot>("/scan/gate");
```

（`apiGet` 是本文件既有 helper——`listScans` 同款；path 不含 `/api` 前缀。）

(c) `StatusBadge.tsx` MAP 加一行（interrupted 行后）：

```tsx
  queued:       { icon: "⏳", cls: "border-yellow/40 text-yellow" },
```

(d) 新建 `ScanGatePanel.tsx`：

```tsx
import { useTranslation } from "react-i18next";
import { Badge } from "@/components/ui/badge";
import type { ScanGateEntry, ScanGateSnapshot } from "@/api/client";

/** since（unix 秒）→「Xm/Xh」粗粒度时长（面板跟随列表刷新节奏，无需实时跳秒）。 */
function fmtSince(since?: number): string {
  if (!since) return "";
  const mins = Math.max(0, Math.floor((Date.now() / 1000 - since) / 60));
  if (mins < 60) return `${mins}m`;
  return `${Math.floor(mins / 60)}h`;
}

function EntryRow({ e, running }: { e: ScanGateEntry; running?: boolean }) {
  const { t } = useTranslation();
  const kind = e.kind && e.kind !== "unknown"
    ? t(`scanGate.kinds.${e.kind}`, e.kind) : "";
  return (
    <div className="flex items-center gap-2 text-sm">
      <span className={running ? "text-cyan" : "text-dim"}>{running ? "●" : "○"}</span>
      <span className="w-20 truncate text-dim">{e.ws}</span>
      {kind && <Badge variant="outline" className="text-xs">{kind}</Badge>}
      <span className="flex-1 truncate">{e.label}</span>
      <span className="text-xs text-dim">{fmtSince(e.since)}</span>
    </div>
  );
}

/** 并发概览面板（spec §8.2）：仅当 held/waiting 非空时显示——「为什么排队」的答案。 */
export function ScanGatePanel({ snapshot }: { snapshot: ScanGateSnapshot | null }) {
  const { t } = useTranslation();
  if (!snapshot || (!snapshot.held.length && !snapshot.waiting.length)) return null;
  const rank = (i: number) => t("scanGate.rank", { n: i + 1 });
  return (
    <div data-testid="scan-gate-panel"
         className="rounded-lg border border-border p-3 mb-3 space-y-2">
      <div className="flex items-center justify-between">
        <span className="font-medium">{t("scanGate.title")}</span>
        <span className="text-sm text-dim">
          {t("scanGate.usage", { held: snapshot.held.length, capacity: snapshot.capacity })}
        </span>
      </div>
      <div className="space-y-1">
        {snapshot.held.map((e) => (
          <EntryRow key={e.workflow_id ?? e.scan_id} e={e} running />
        ))}
      </div>
      {snapshot.waiting.length > 0 && (
        <div className="space-y-1">
          <div className="text-xs text-dim">{t("scanGate.waiting", { n: snapshot.waiting.length })}</div>
          {snapshot.waiting.map((e, i) => (
            <div key={e.workflow_id ?? e.scan_id} className="flex items-center gap-2 text-sm">
              <span className="w-4 text-dim">{rank(i)}</span>
              <div className="flex-1"><EntryRow e={e} /></div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
```

（样式 class 对齐项目现有 token：`text-dim`/`border-border` 在现有组件中出现；若项目用别的 token 名，以 `grep -rn "text-dim" src/components | head` 的实际惯例为准替换。）

(e) `ScanList.tsx`：顶部（列表表格容器之前）挂面板 + 行内 queued 位次：

```tsx
import useSWR from "swr";
import { getScanGate } from "@/api/client";
import { ScanGatePanel } from "@/components/ScanGatePanel";

// 组件内：
const { data: gateSnap } = useSWR(["scan-gate"], getScanGate, {
  // 与 useScans 同款条件轮询：有占用/排队才 10s 刷（spec §8.2 不独立常驻轮询）
  refreshInterval: (latest?: ScanGateSnapshot) =>
    latest && latest.held.length + latest.waiting.length > 0 ? 10_000 : 0,
});

// 表格前：
<ScanGatePanel snapshot={gateSnap ?? null} />

// L488 状态单元格改为：
<TableCell>
  <div className="flex items-center gap-1">
    <StatusBadge status={scan.status} correlation={isCorr} />
    {scan.status === "queued" && (() => {
      const pos = gateSnap?.waiting.findIndex((e) => e.scan_id === scan.scan_id) ?? -1;
      return pos >= 0 ? <span className="text-xs text-dim">#{pos + 1}</span> : null;
    })()}
  </div>
</TableCell>
```

（`useSWR` 的 import 方式对齐 `useScans.ts` 的现有写法；ScanList 顶部已有 SWR 依赖。）

(f) i18n——`zh.json` 的 `workspaces.status` 段（L236-245）加 `"queued": "排队中"`；新增 `scanGate` 段（顶层）：

```json
  "scanGate": {
    "title": "扫描并发",
    "usage": "{{held}}/{{capacity}} 运行中",
    "waiting": "排队中 ({{n}})",
    "rank": "第 {{n}} 位",
    "kinds": {
      "whitebox": "白盒",
      "mr": "MR",
      "blackbox": "黑盒",
      "correlation": "跨仓"
    }
  },
```

`en.json` 对应（`"queued": "Queued"`；`"title": "Scan Concurrency"`、`"usage": "{{held}}/{{capacity}} running"`、`"waiting": "Queued ({{n}})"`、`"rank": "#{{n}}"`、kinds：`Whitebox`/`MR`/`Blackbox`/`Correlation`）。

- [ ] **Step 4: 跑测试 + 类型门**

```bash
cd packages/web/frontend && npx vitest run src/components/ScanGatePanel.test.tsx src/components/StatusBadge.test.tsx src/routes/WorkspaceDetail/ScanList.test.tsx && npx tsc -b
```

预期：新用例 PASS；ScanList 既有测试不回归（若其 mock 层因新增 `useSWR(["scan-gate"])` 需要 gate 快照数据，在其 mock setup 里补 `getScanGate` mock——vi.mock "@/api/client" 处加 `getScanGate: vi.fn().mockResolvedValue({ capacity: 5, held: [], waiting: [] })`）。`tsc -b` 零错误。

- [ ] **Step 5: Commit**

```bash
git add packages/web/frontend/src/api/types.ts packages/web/frontend/src/api/client.ts packages/web/frontend/src/components/StatusBadge.tsx packages/web/frontend/src/components/StatusBadge.test.tsx packages/web/frontend/src/components/ScanGatePanel.tsx packages/web/frontend/src/components/ScanGatePanel.test.tsx packages/web/frontend/src/routes/WorkspaceDetail/ScanList.tsx packages/web/frontend/src/locales/zh.json packages/web/frontend/src/locales/en.json
git commit -m "feat(web-fe): 排队可视化——queued 徽章+第N位、ScanGatePanel 并发概览面板(工作区·类型·标签·时长·位次,空态隐藏,条件轮询10s)、i18n zh/en(spec §8.2)"
```

---

## Self-Review 记录

- **Spec 覆盖**：§4 ScanGate（Task 1）、§5 三类 workflow 闸门段（Task 2/3）、§6 janitor+bootstrap（Task 4）、§7 web 删门 + queued 档 + reconciler（Task 5/6）、§8.1 API（Task 7）、§8.2 前端（Task 8）、§9 配置（Task 4 compose worker env / Task 5 compose web env 退役）。spec §5 queue_full 语义（Task 2 测试第 3 例）、§8.1 权限过滤（Task 7 测试第 3 例）均有对应用例。
- **占位符扫描**：Task 2 Step 4 的既有测试适配、Task 5 Step 1 的 `_minimal_start_request`、Task 7 的 `_create_app_with_workspaces`/`_auth_headers` 均标注了「对齐被删用例/本文件现有构造方式」的取材来源（这些设施存在于被引用位置，属复用指引而非待定项）。Task 8 的样式 token 给了验证命令。
- **类型一致性**：`ScanGateEntry`/`ScanGateSnapshot` 在 client.ts 定义、panel 与测试消费一致；`acquire_gate_slot`/`release_gate_slot`/`gate_scan_id_from_event_file`/`gate_ws_from_path` 的签名在 Task 1 定义、Task 2/3 消费一致；`_gate_janitor_once` 在 Task 4 定义并测试。
