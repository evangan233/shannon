"""多源归并事件 tailer：认证/白盒/黑盒 run-K 的 ndjson 按时间归并为一条流。

设计要点（详见 live 全量合并方案）：

- **源**：``ac``=authcheck-events.ndjson（认证预检）、``wb``=events.ndjson（任务根，
  组合扫描即白盒段，独立黑盒扫描即其本体）、``run-K``=blackbox-runs/run-K/events.ndjson。
  run 目录周期重扫，流开着时新增 run（rerun/add run）自动纳入。
- **correlation 子仓源**（2026-09-10 主行 live）：主行 session 的 ``corr_children``
  （reused=False 现扫子仓）→ ``c-<scan_id>`` 源（同级 scans/ 目录下 events.ndjson）。
  转发注入 ``src=c-<scan_id>`` + ``service=<svc>``（LogStream [svc] 归属前缀）；
  子仓 scan_end 改写 ``run_end{run:<svc>}``（复用 RUN 行渲染）；子仓终态不参与
  流关闭判定（主行 wb scan_end 才收口）。前端 ScanProgressOverview 按 src 前缀
  过滤子仓事件（防其白盒 PhaseEvent 重置主行 correlation 网格）。
- **源标记**：转发的事件统一注入 ``src``（=源 label）。前端判「组合扫描当前段」不能靠
  phase 名——authcheck（独立 AuthValidationWorkflow）与黑盒 run 的 auth-validation 段
  发同名 PhaseEvent，无从区分；源标记是 tailer 本就知道的可靠信号（2026-08-28 组合
  扫描列表进度三阶段加权判段）。
- **SSE id = 全源 emit offset 快照**（``ac=0&wb=123&run-1=456``）：重连只需单个
  Last-Event-ID 即可恢复每源各自断点，无服务端会话状态；重放幂等（前端按 id 去重）。
  offset 全程按**字节**计（ndjson 含多字节 UTF-8，按字符计会漂移丢事件）。
- **scan_end 语义**：
  - ``ac`` 的 scan_end 丢弃（预验证收尾非扫描终态，混入会提前关流）；
  - ``wb`` 的 scan_end **扣住不发**，待「wb 终态 + 所有已见 run 终态 + 宽限期」
    全部满足后作为流的最后一条发出（前端见 scan_end 关流）。NodeGoat-20260817-132940
    事故：编排器 15:31 误写任务级 scan_end failed 而黑盒 run 实际跑到 16:04——扣住
    后 run 的事件仍持续可推；
  - ``run-K`` 的 scan_end 改写 type=run_end 转发（run 收尾对全量流非终态）。
- **run 空闲兜底**：wb scan_end 已扣住而某 run 源 ``run_idle_timeout`` 秒无新增且
  无自己的 scan_end（黑盒 workflow 未 finalize：取消/run_timeout/worker 崩溃，且
  web 侧收口缺失）→ 合成 ``run_end{synthetic:true}`` 视为终态，防流永不关流
  （live 页永久「已连接」）。run 仍在写则 last_active 持续刷新，不会误伤上述
  「误写任务级 scan_end 而 run 实际在跑」的场景。负值禁用。
- **顺序**：每轮 poll 内各源新增行按 ``ts`` 排序输出（解析失败/缺失按源优先级稳定
  兜底：ac < wb < run-K）。各段（认证→白盒→黑盒）时间上不重叠，ts 排序为防御。
- **首轮边界**：首次 poll 归并完已有文件后发送一次 ``stream_ready`` 控制帧；它不带
  SSE id、也不进入磁盘事件历史，只告诉前端可以从 GET 快照切换到实时 fold。
"""
from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Awaitable, Callable

import aiofiles

from .event_tailer import EventTailer

RUN_DIR_RE = re.compile(r"^run-(\d+)$")
ID_SEP = "&"

OnEvent = Callable[[dict, Any], Awaitable[None]]


def _parse_ts(value: Any) -> datetime | None:
    """事件 ts → datetime；非法/缺失返 None（排序时按源优先级兜底）。"""
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


@dataclass
class _Source:
    label: str
    path: Path
    priority: int
    kind: str = "fixed"    # fixed(ac/wb) | run(run-K) | child(c-<scan_id>，correlation 子仓)
    service: str | None = None  # child 源的 svc 名（转发注入 service 字段）
    file_off: int = 0      # 已从磁盘读到的字节（截断检测/续读基准）
    line_pos: int = 0      # 下一行起始字节（per-line end offset 的累积基准）
    emit_off: int = 0      # 已计入 SSE id 快照的字节（≤ line_pos）
    carry: bytes = b""     # 未终结行的半截字节
    # 待发事件：(ts or None, 行尾字节 offset, data)
    pending: list[tuple[datetime | None, int, dict]] = field(default_factory=list)
    seen_end: bool = False  # 已见本源 scan_end
    last_active: float = 0.0  # 最近一次读到新字节的 loop 时钟（run 空闲兜底判据）

    def reset(self) -> None:
        """文件被截断/重建：归零重读（重放由前端 id 去重吸收）。"""
        self.file_off = self.line_pos = self.emit_off = 0
        self.carry = b""
        self.pending.clear()


class MergedEventTailer:
    """tail scan_dir 下多事件源并归并推送；``tail()`` 返回即流结束。"""

    def __init__(self, scan_dir: Path) -> None:
        self._dir = Path(scan_dir)
        self._sources: dict[str, _Source] = {}
        self._held_end: dict | None = None  # 扣住的 wb scan_end（终态判定满足后最后发）
        self._children_confirmed = False  # 子仓源发现完成（读到 corr_children 或确认非 corr）

    # ---- 源发现与断点恢复 ----

    def _discover_child_sources(self, resume: dict[str, int], now: float) -> None:
        """correlation 主行子仓源（2026-09-10）：session corr_children 的现扫（reused=False）。

        corr_children 在 start 请求内写（children 全建后 update_session）——若 SSE 首连
        早于其落盘（提交后秒开 live 页），未确认前每轮重读；读到或确认 scan_type 非
        correlation 后停读。session 缺失/损坏按「无子仓」确认（回落既有行为）。
        """
        if self._children_confirmed:
            return
        session_file = self._dir / "session.json"
        try:
            data = json.loads(session_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return  # 尚未创建：下轮再读（source_wait_timeout 兜底整体退出）
        children = data.get("corr_children") or []
        if not children and data.get("scan_type") != "correlation":
            self._children_confirmed = True  # 非主行：永远不会有 corr_children
            return
        if not children:
            return  # correlation 但 children 未写：下轮再读
        self._children_confirmed = True
        for i, child in enumerate(children):
            if child.get("reused"):
                continue  # 复用子仓不跑，无新日志
            scan_id = str(child.get("scan_id") or "")
            svc = str(child.get("service") or scan_id)
            if not scan_id or "&" in scan_id or "=" in scan_id:
                continue  # label 会进 SSE id 快照（&/= 分隔），含特殊字符的不纳入
            label = f"c-{scan_id}"
            if label not in self._sources:
                self._sources[label] = _Source(
                    label, self._dir.parent / scan_id / "events.ndjson",
                    500 + i, kind="child", service=svc,
                    file_off=resume.get(label, 0),
                    line_pos=resume.get(label, 0),
                    emit_off=resume.get(label, 0),
                    last_active=now)

    def _discover(self, resume: dict[str, int]) -> None:
        """补齐源表：固定 ac/wb + 重扫 blackbox-runs/run-K（新 run 流中自动纳入）
        + correlation 现扫子仓（session corr_children）。

        仅在 ``tail()``（运行中的 event loop）内调用，可安全取 loop 时钟初始化
        ``last_active``（run 空闲兜底的计时起点）。
        """
        now = asyncio.get_running_loop().time()
        fixed = [
            ("ac", self._dir / "authcheck-events.ndjson", 0),
            ("wb", self._dir / "events.ndjson", 1),
        ]
        for label, path, priority in fixed:
            if label not in self._sources:
                self._sources[label] = _Source(label, path, priority,
                                               file_off=resume.get(label, 0),
                                               line_pos=resume.get(label, 0),
                                               emit_off=resume.get(label, 0),
                                               last_active=now)
        self._discover_child_sources(resume, now)
        runs_root = self._dir / "blackbox-runs"
        if runs_root.is_dir():
            for entry in runs_root.iterdir():
                m = RUN_DIR_RE.match(entry.name)
                if not m or not (entry / "events.ndjson").is_file():
                    continue
                label = entry.name
                if label not in self._sources:
                    self._sources[label] = _Source(
                        label, entry / "events.ndjson", 1000 + int(m.group(1)),
                        kind="run",
                        file_off=resume.get(label, 0),
                        line_pos=resume.get(label, 0),
                        emit_off=resume.get(label, 0),
                        last_active=now)

    @staticmethod
    def parse_last_event_id(raw: str | None) -> dict[str, int]:
        """Last-Event-ID（"ac=0&wb=123&run-1=45"）→ {label: offset}；容忍畸形段。"""
        if not raw:
            return {}
        offsets: dict[str, int] = {}
        for part in raw.split(ID_SEP):
            label, sep, value = part.partition("=")
            if sep and label and value.isdigit():
                offsets[label] = int(value)
        return offsets

    def _id_snapshot(self) -> str:
        return ID_SEP.join(
            f"{self._sources[s].label}={self._sources[s].emit_off}"
            for s in sorted(self._sources, key=lambda k: self._sources[k].priority))

    # ---- 主循环 ----

    async def tail(self, on_event: OnEvent, last_event_id: str | None = None,
                   poll_interval: float = 0.2, close_grace: float = 10.0,
                   source_wait_timeout: float = 300.0,
                   run_idle_timeout: float = 300.0) -> None:
        """归并推送直到终态（wb scan_end 扣发 + 全 run 终态 + 宽限）或源等待超时。

        - ``close_grace``：终态条件首次全满足后再等的窗口——覆盖「白盒刚收尾、
          run-1 目录尚未建」的创建竞态，也留出用户点续跑的缝隙。
        - ``source_wait_timeout``：所有源文件都未出现时的等待上限（对齐 EventTailer
          的文件出现等待；超时返程，前端 EventSource 重连后重试）。
        - ``run_idle_timeout``：wb scan_end 已扣住而某 run 源此窗口内无新增且无自己
          的 scan_end → 合成 ``run_end{synthetic:true}`` 终态（web 侧 _ensure_run_scan_end
          收口漏网时的最后防线；run 仍在写则 last_active 刷新不误伤）。负值禁用。
        """
        resume = self.parse_last_event_id(last_event_id)
        waited = 0.0
        closable_since: float | None = None
        loop = asyncio.get_running_loop()
        # 首轮 poll 结束后给前端一个明确的「历史回放已追平」边界。
        # EventSource 初次连接不会携带 Last-Event-ID，前端会从 offset=0 收到整段
        # events.ndjson；没有边界时列表会把历史 PhaseEvent 逐条当成实时进度，出现
        # 5→22→38→5→49… 的回放抖动。ready 本身不带 SSE id，沿用上一条真实事件
        # 的 Last-Event-ID，避免和同 offset 的真实 scan_end 产生伪重复。
        stream_ready_sent = False
        while True:
            self._discover(resume)
            for source in self._sources.values():
                await self._pump(source)
            emitted = await self._drain(on_event)
            if not stream_ready_sent:
                await on_event(
                    {"ts": datetime.now().isoformat(),
                     "category": "CONTROL", "type": "stream_ready"},
                    None)
                stream_ready_sent = True
            if emitted:
                waited = 0.0
            # 终态判定：wb scan_end 已见（扣住）+ 所有已见 run 源各自见过 scan_end
            # （child 子仓源不参与——主行 wb scan_end 才是流终态权威）
            runs = [s for s in self._sources.values() if s.kind == "run"]
            closable = (self._held_end is not None
                        and all(s.seen_end for s in runs))
            if (not closable and self._held_end is not None
                    and run_idle_timeout >= 0):
                now = loop.time()
                for s in runs:
                    if not s.seen_end and now - s.last_active >= run_idle_timeout:
                        s.seen_end = True
                        await on_event(
                            {"ts": datetime.now().isoformat(),
                             "category": "CONTROL", "type": "run_end",
                             "run": s.label, "status": "unknown",
                             "synthetic": True, "src": s.label},
                            self._id_snapshot())
                closable = (self._held_end is not None
                            and all(s.seen_end for s in runs))
            if closable:
                if closable_since is None:
                    closable_since = loop.time()
                elif loop.time() - closable_since >= close_grace:
                    await on_event(dict(self._held_end, src="wb"),
                                   self._id_snapshot())
                    return
            else:
                closable_since = None
            if not emitted:
                if not any(s.path.exists() for s in self._sources.values()):
                    # 全量源文件都未出现（扫描尚未启动/预检中）——对齐 EventTailer 等待语义
                    waited += poll_interval
                    if waited > source_wait_timeout:
                        return
                await asyncio.sleep(poll_interval)

    # ---- 单源读取 ----

    async def _pump(self, source: _Source) -> None:
        """读源文件新增字节 → 按**字节**切完整行入 pending（跨源排序由 _drain 统一做）。"""
        if not source.path.exists():
            return
        try:
            async with aiofiles.open(source.path, "rb") as fh:
                size = await fh.seek(0, 2)
                if size < source.file_off:
                    source.reset()
                await fh.seek(source.file_off)
                chunk = await fh.read()
        except OSError:
            return  # 读取竞态（写入中重建等）：下轮再试
        if not chunk:
            return
        source.file_off += len(chunk)
        source.last_active = asyncio.get_running_loop().time()
        lines = (source.carry + chunk).split(b"\n")
        source.carry = lines.pop()  # 未终结的半截行留待下轮
        for raw in lines:
            source.line_pos += len(raw) + 1
            line = raw.decode("utf-8", "replace").strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(data, dict):
                continue
            source.pending.append((_parse_ts(data.get("ts")), source.line_pos, data))

    async def _drain(self, on_event: OnEvent) -> int:
        """跨源按 ts 归并发出 pending 事件（含 scan_end 三态处理），返发出条数。"""
        batch: list[tuple[_Source, datetime | None, int, dict]] = []
        for source in self._sources.values():
            batch.extend((source, ts, end_off, data)
                         for ts, end_off, data in source.pending)
            source.pending.clear()
        if not batch:
            return 0
        batch.sort(key=lambda item: (
            item[1] is None, item[1] or datetime.min, item[0].priority, item[2]))
        emitted = 0
        for source, _ts, end_off, data in batch:
            source.emit_off = end_off
            if data.get("type") == "scan_end":
                if source.label == "ac":
                    continue  # 预验证收尾：跳过不发（emit_off 已推进，续传不重读）
                if source.label == "wb":
                    self._held_end = data  # 扣住，终态判定满足后最后发
                    source.seen_end = True
                    continue
                if source.kind == "child":
                    # 子仓收尾：改写 run_end{run:<svc>}（复用 RUN 行渲染），标终态
                    # 但不参与流关闭判定（见 tail() 的 runs 过滤）。
                    await on_event(dict(data, type="run_end", run=source.service,
                                        service=source.service, src=source.label),
                                   self._id_snapshot())
                    source.seen_end = True
                    emitted += 1
                    continue
                # run-K 收尾：改写 type 转发（对全量流非终态），标该 run 终态
                await on_event(dict(data, type="run_end", run=source.label,
                                    src=source.label),
                               self._id_snapshot())
                source.seen_end = True
                emitted += 1
                continue
            if source.kind == "child":
                # 子仓事件注入 service（LogStream [svc] 归属前缀用）
                await on_event(dict(data, src=source.label, service=source.service),
                               self._id_snapshot())
            else:
                await on_event(dict(data, src=source.label), self._id_snapshot())
            emitted += 1
        return emitted
