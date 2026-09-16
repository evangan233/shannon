"""worker 侧全局扫描闸门：扫描类 workflow 实际并发 ≤ 容量，超出排队（近似 FIFO）。

spec: docs/superpowers/specs/2026-09-08-worker-scan-gate-design.md

架构不变量：
- 闸门是 worker **进程内**信号量（部署假设单 worker 副本；多副本时信号量分裂，
  需迁共享存储——runner.py 的挂载注释同此口径，不预做）。
- 排队发生在 temporal 里：workflow 在闸门段轮询 try_acquire 直到获槽，
  workflow 活着 = 在排队，持久化/重启恢复免费。排队不限时（2026-09-16）：
  长 stint 靠 acquire_gate_slot 周期性 continue-as-new 防事件历史膨胀，
  workflow_id 不变故 waiting/held 语义对 CAN 透明。
- 槽泄漏兜底 = runner 的 janitor（周期校验持有者存活性，spec §6）；
  worker 重启防超卖 = bootstrap 预占（所有 RUNNING 扫描类 workflow 计槽）。
- gate_state.json 快照仅供 web 展示（env 指定路径；CLI 未设 = 不落盘优雅降级），
  丢了/旧了只影响显示不影响闸门正确性。
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

from temporalio import activity

GATE_POLL_SECONDS = 5.0          # workflow 侧排队轮询间隔；测试 monkeypatch 调小
# 排队 stint 超此时长即 continue-as-new 重开 run（实效 = min(本值, run_timeout/3)）：
# 5s 轮询每圈 ~11 events，20min ≈ 2.6k events/run，远低于 temporal 单 workflow
# ~50k 事件历史上限——排队不限时的前提下靠周期重开防历史膨胀。测试 monkeypatch 调小。
GATE_CONTINUE_AFTER = timedelta(minutes=20)
_ACTIVITY_TIMEOUT = timedelta(seconds=30)

# per-workspace 并发上限键（2026-09-15）：ws 配置页 env 文本框 → SCAN_ENV_KEYS 白名单
# → PipelineInput.env_overrides → 闸门 descriptor 携带。闸门段先于 setup_display
# （set_scan_env 注入点），ws_getenv 覆盖层在闸门 activity 里尚不可用，故走 descriptor。
WS_CAP_ENV_KEY = "SUPERNOVA_WS_SCAN_CONCURRENCY"

_log = logging.getLogger(__name__)


def gate_ws_cap_from_overrides(overrides: dict[str, str] | None) -> int | None:
    """提交端从 env overrides 解析 ws 并发上限（三类 workflow 构造 descriptor 用）。

    返回 int>=1；未设 / 畸形 / <=0 → None（= 该 ws 不设专属上限，仅受全局容量）。
    容错契约对齐 concurrency.get_max_concurrent：畸形值 warning 不 raise——
    ws 文本框手输，不许崩扫描。clamp 到全局容量在闸门侧（_effective_ws_cap），
    workflow sandbox 不 import worker 进程常量。
    """
    raw = (overrides or {}).get(WS_CAP_ENV_KEY)
    if raw is None:
        return None
    try:
        val = int(raw.strip())
    except ValueError:
        _log.warning("%s=%r not an int; ws cap ignored", WS_CAP_ENV_KEY, raw)
        return None
    if val < 1:
        _log.warning("%s=%d must be >=1; ws cap ignored", WS_CAP_ENV_KEY, val)
        return None
    return val


@dataclass
class _Holder:
    descriptor: dict
    acquired_at: float
    # bootstrap 未知预占标记（2026-09-16）：visibility 只能回答「RUNNING」，
    # 分不清「已过闸持有」还是「闸门排队中」（排队 workflow 同样 RUNNING）。
    # 预占条目首 poll 即摘除走正常准入——无条件幂等放行会把排队者直接放跑。
    preloaded: bool = False


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
        if workflow_id in self.held:
            holder = self.held[workflow_id]
            if holder.preloaded:
                # 未知预占者首 poll = 重启前它在闸门排队（或过闸-重启交叉窗）。
                # 摘除自身预占、落下方正常准入：无条件幂等放行会让排队者绕过
                # 全局容量与 ws cap 直接开跑（2026-09-16 现场事故：ws cap 3 下
                # 排队 2 个突然自动跑了）。真实 holder（授予/快照恢复）不带此
                # 标记，continue-as-new 交叉窗口的幂等放行语义不变。
                self.held.pop(workflow_id)
                self._persist()
            else:
                # 幂等：已持有者重试/continue-as-new 新 run 首轮对齐（spec §4）
                return {**r_base, "granted": True, "queue_full": False,
                        "position": 0}
        if (workflow_id not in self.waiting
                and len(self.waiting) >= self.max_waiting):  # 防雪崩第二道门
            return {**r_base, "granted": False, "queue_full": True,
                    "position": self.max_waiting}
        if workflow_id not in self.waiting:
            self.waiting[workflow_id] = _Waiter(dict(descriptor), time.time())
            self._persist()  # 入列即落盘：web queued 档 + 面板 waiting 吃快照
            # （granted/release/reap/preload 之外唯一的状态变化路径，曾漏——
            # 快照停在旧状态致排队任务误显已中断、面板看不到排队队列）
        if len(self.held) < self.capacity:
            # per-ws 上限下的近似 FIFO（2026-09-15）：按 first_seen 序找第一个未被
            # 自己 ws cap 挡住的 waiter——是调用者则授予；被挡的跳过（否则一个 ws
            # 大批量排队会 head-of-line 全局饿死）；未被挡的更早者照旧优先（授予
            # 只发生在该 waiter 自己 poll 时，轮询语义不变）。
            for wf in self.waiting:
                if self._ws_admission_blocked(self.waiting[wf].descriptor):
                    continue
                if wf != workflow_id:
                    break
                self.held[workflow_id] = _Holder(
                    self.waiting.pop(workflow_id).descriptor, time.time())
                self._persist()
                return {**r_base, "granted": True, "queue_full": False, "position": 0}
        return {**r_base, "granted": False, "queue_full": False,
                "position": list(self.waiting).index(workflow_id) + 1}

    def _effective_ws_cap(self, descriptor: dict) -> int | None:
        """descriptor 的生效 ws 上限：未配置 / 空 ws → None（仅全局容量）；
        否则 clamp 到全局容量——「无论怎么配都不会大于全局」的规范化出口。"""
        ws_cap = descriptor.get("ws_cap")
        if not descriptor.get("ws") or not isinstance(ws_cap, int):
            return None
        return min(ws_cap, self.capacity)

    def _ws_admission_blocked(self, descriptor: dict) -> bool:
        """该 descriptor 的 ws 持有数已达其上限 → 挡住（空 ws 的 bootstrap 预占
        条目不归属任何 ws，不计数——重启窗口内 ws cap 可能短暂虚高，全局容量
        仍由 len(held) < capacity 硬保证，保守无害方向）。"""
        cap = self._effective_ws_cap(descriptor)
        if cap is None:
            return False
        ws = descriptor["ws"]
        held_in_ws = sum(
            1 for h in self.held.values() if h.descriptor.get("ws") == ws)
        return held_in_ws >= cap

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
        """worker 启动预占：RUNNING 扫描类 workflow 一律计槽（保守，防重启超卖）。

        预占集**含闸门排队者**（排队 workflow 也是 RUNNING，visibility 分不清），
        故条目带 preloaded 标记：首 poll 摘除走正常准入（见 try_acquire），不会
        被幂等分支误放行。快照恢复的真实 holder（restore_held）优先于本兜底。
        """
        for wf in workflow_ids:
            if wf not in self.held:
                self.held[wf] = _Holder(
                    {"kind": "unknown", "ws": "", "scan_id": "", "label": wf},
                    time.time(), preloaded=True)
        self._persist()

    def restore_held(self, held_entries: list[dict]) -> None:
        """worker 重启时从落盘快照恢复 held（真实 descriptor 带 ws）。

        ws cap 的归属计数靠 holder descriptor 的 ws——只从 visibility 预占
        （ws=""）会让重启窗口 ws cap 失效；快照恢复把真实 ws 带回来，排队者
        重新轮询时仍被自己的 ws cap 正确挡住。waiting **不恢复**：排队
        workflow 每 GATE_POLL_SECONDS 轮询自愈重新入列（first_seen 重置可
        接受）；恢复的幽灵 waiter 会永远挡 FIFO 头（已过闸者不再 poll）。
        已在 held 的条目不覆盖（bootstrap 时序：restore 先于 preload 兜底，
        真实 descriptor 优先于未知预占）。幽灵 holder（快照落盘后 workflow
        才死的）由 janitor 周期回收。
        """
        for e in held_entries or []:
            wf = e.get("workflow_id")
            if not wf or wf in self.held:
                continue
            d = {k: v for k, v in e.items()
                 if k not in ("workflow_id", "since")}
            try:
                since = float(e.get("since") or time.time())
            except (TypeError, ValueError):
                since = time.time()
            self.held[wf] = _Holder(d, since)
        self._persist()

    def candidate_ids(self) -> list[str]:
        return list(self.held) + list(self.waiting)

    def snapshot(self) -> dict:
        def _desc_view(d: dict) -> dict:
            # ws_cap 展示生效值（clamp 到全局容量）：面板显示 x/cap 用不误导的
            # 口径——配置原文 8 显示成 2/8 会谎报全局约束力。
            d = dict(d)
            if isinstance(d.get("ws_cap"), int):
                d["ws_cap"] = min(d["ws_cap"], self.capacity)
            return d
        return {
            "capacity": self.capacity,
            "max_waiting": self.max_waiting,
            "held": [{"workflow_id": wf, **_desc_view(h.descriptor),
                      "since": h.acquired_at} for wf, h in self.held.items()],
            "waiting": [{"workflow_id": wf, **_desc_view(w.descriptor),
                         "since": w.first_seen} for wf, w in self.waiting.items()],
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
            # 默认 500（2026-09-16，原 50）：对齐批量提交上限 SUPERNOVA_BATCH_SCAN_
            # MAX_REPOS 默认 500——批量场景第 56 个起 queue_full 秒拒（金融平台
            # 事故 139 个秒败）违背「排队不限时」语义；防雪崩靠 workflow 侧
            # continue-as-new（历史膨胀已治）+ 轮询超时容忍，不靠拒绝。
            max_waiting=int(os.environ.get("SUPERNOVA_SCAN_GATE_MAX_WAITING", "500")),
            state_path=Path(state_file) if state_file else None,
        )
    return _GATE


def reset_gate_for_tests() -> None:
    global _GATE
    _GATE = None


def preload_gate(workflow_ids: list[str]) -> None:
    _gate().preload(workflow_ids)


def restore_gate_held_from_file() -> None:
    """bootstrap 第一步：从 gate_state.json 恢复 held（真实 ws descriptor）。

    state file 在 web/worker 共享的 workspaces 挂载上（compose 约定），重启前
    最后一次 _persist 的快照就在那里；未设 env（CLI worker）/文件缺失/损坏
    → 静默跳过，visibility 兜底照常（降级 = 旧行为 + 首 poll 摘除）。
    """
    state_file = os.environ.get("SUPERNOVA_SCAN_GATE_STATE_FILE", "")
    if not state_file:
        return
    snap = read_gate_snapshot_file(Path(state_file))
    if snap:
        _gate().restore_held(snap.get("held"))


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


async def acquire_gate_slot(descriptor: dict, input) -> None:
    """workflow 侧闸门段（workflow 上下文调用）：排队轮询直到获槽；满队 raise。

    2026-09-16 排队不限时 + continue-as-new（spec 2026-09-16-scan-budget-queue-unlimited）：
    - 排队 stint ≥ min(GATE_CONTINUE_AFTER, run_timeout/3) → ``continue_as_new(args=[input])``
      重开 run：事件历史清零防 temporal ~50k 上限；workflow_id 不变 → worker 内存
      gate 的 waiting 条目（含 first_seen）原样保留，FIFO 位置不丢。新 run 重入本
      函数继续轮询，排队多久都等（对齐 scan-gate spec「不做排队超时」）。
    - 获槽时若已排过队（stint>0）同样重开：新 run 首次 try_acquire 走 ``held`` 幂等
      路径（try_acquire 对 held 中 workflow_id 直接 granted），扫描预算（run_timeout，
      提交端按 scan_budget() 设定）满额从**获槽**起算。免排队快路径（stint==0）不
      重启、原地进扫描。
    - 安全性：三个扫描 workflow 的调用点都在 run() 的 try/finally（release_gate_slot）
      **之前**——ContinueAsNewError 是 BaseException 子类（不被 except Exception 吞）
      直接展开出 run，finally release 不会误摘 waiting 条目。

    cancel 传导：temporal cancel 在 sleep/execute_activity await 点抛 CancelledError，
    此时尚未获槽、无需 release——waiting 残留由 janitor 回收（spec §6）。
    retry_policy=maximum_attempts=1：activity 是读内存 dict 的瞬时操作，失败无重试
    价值（轮询循环下一轮天然重试）；且默认无限重试会把 unregistered activity
    （CLI worker 漏注册等部署不一致）变成「workflow 永挂闸门」而非快速失败。
    唯一例外：**超时**（ActivityError 且 cause 是 TimeoutError） tolerated——worker
    过载时轮询 activity 可能撞 30s start-to-close，排队不限时原则下不允许此死法
    （2026-09-16 事故 cloud_sync_svr 排队 47min 死于此），本轮视同未获槽重试；
    非超时 ActivityError 照旧上抛快速失败。
    """
    from temporalio import workflow
    from temporalio.common import RetryPolicy
    from temporalio.exceptions import ActivityError, ApplicationError
    from temporalio.exceptions import TimeoutError as ActivityTimeoutError
    stint = 0.0
    while True:
        timed_out = False
        try:
            r = await workflow.execute_activity(
                scan_gate_try_acquire, descriptor,
                start_to_close_timeout=_ACTIVITY_TIMEOUT,
                retry_policy=RetryPolicy(maximum_attempts=1),
            )
        except ActivityTimeoutError:
            # server TIMEOUT failure 直接转 TimeoutError（不包 ActivityError）
            timed_out = True
        except ActivityError as err:
            if not isinstance(err.cause, ActivityTimeoutError):
                raise  # 漏注册等部署不一致照旧快速失败（maximum_attempts=1 的初衷）
            timed_out = True
        if timed_out:
            # 排队中轮询超时（worker 过载打满 activity 并发——2026-09-16 事故
            # cloud_sync_svr 排队 47min 死于 30s poll 超时的死法）：排队不限时
            # 原则下不容忍此死法，本轮视同未获槽，睡一拍重试（轮询幂等）。
            await workflow.sleep(GATE_POLL_SECONDS)
            stint += GATE_POLL_SECONDS
            continue
        if r.get("granted"):
            if stint > 0:
                # 获槽重启：预算满额从获槽起算（held 幂等路径兜住新 run 首轮 try_acquire）
                workflow.continue_as_new(args=[input])
            return
        if r.get("queue_full"):
            # 文案数字来自 activity 返回值：workflow sandbox 不 import worker 进程常量
            raise ApplicationError(
                f"扫描排队已满（上限 {r.get('max_waiting')}），请稍后重试",
                non_retryable=True)
        if stint >= _continue_after_seconds():
            # 排队重启：history 清零；waiting 条目按 workflow_id 保留（FIFO 不丢）
            workflow.continue_as_new(args=[input])
        await workflow.sleep(GATE_POLL_SECONDS)
        stint += GATE_POLL_SECONDS


def _continue_after_seconds() -> float:
    """实效 CAN 间隔秒数 = min(GATE_CONTINUE_AFTER, run_timeout/3)；run_timeout
    缺省（None/零，提交方未设时 temporal 返回 None）用常量。

    /3 防小预算自掐：stint 消耗的是当前排队 run 自己的 run_timeout，预算 <1h 时
    20min stint 会占掉大头，排队 run 可能在获槽前先被 run_timeout 杀掉。
    """
    from temporalio import workflow
    cont = GATE_CONTINUE_AFTER
    rt = workflow.info().run_timeout
    if rt:
        cont = min(cont, rt / 3)
    return cont.total_seconds()


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
