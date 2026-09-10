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
            self._persist()  # 入列即落盘：web queued 档 + 面板 waiting 吃快照
            # （granted/release/reap/preload 之外唯一的状态变化路径，曾漏——
            # 快照停在旧状态致排队任务误显已中断、面板看不到排队队列）
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


def gate_ws_for_descriptor(workspace_name: str | None, event_file: str | None) -> str:
    """闸门快照的工作区名：web event_file 路径优先，CLI workspace_name 兜底。

    web 提交端把 ``workspace_name`` 填成 scan_id（worker 目录契约），不能直接当
    工作区名展示；web event_file 固定在 workspaces/<ws>/scans/<scan_id>/ 下，
    是权威来源。CLI 没有 workspaces 路径时，workspace_name 才是真实工作区名。
    """
    if event_file and "workspaces" in Path(event_file).parts:
        return gate_ws_from_path(event_file) or (workspace_name or "")
    return workspace_name or ""


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
    retry_policy=maximum_attempts=1：activity 是读内存 dict 的瞬时操作，失败无重试
    价值（轮询循环下一轮天然重试）；且默认无限重试会把 unregistered activity
    （CLI worker 漏注册等部署不一致）变成「workflow 永挂闸门」而非快速失败。
    """
    from temporalio import workflow
    from temporalio.common import RetryPolicy
    from temporalio.exceptions import ApplicationError
    while True:
        r = await workflow.execute_activity(
            scan_gate_try_acquire, descriptor,
            start_to_close_timeout=_ACTIVITY_TIMEOUT,
            retry_policy=RetryPolicy(maximum_attempts=1),
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
    from temporalio.common import RetryPolicy
    try:
        await workflow.execute_activity(
            scan_gate_release, start_to_close_timeout=_ACTIVITY_TIMEOUT,
            retry_policy=RetryPolicy(maximum_attempts=1))
    except Exception:
        pass
