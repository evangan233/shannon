# 全局扫描槽位闸门 + 排队设计（global-scan-slot-queue）

> 日期：2026-09-08。状态：spec 待审。
> 需求：全系统所有扫描最多同时 5 个任务（按实际并发 workflow 计数），超出的排队轮着来——**从「拒绝」改为「排队」**。

## 1. 背景与现状

### 1.1 现有三层并发，语义不一致

| 层 | 配置 | 现状 |
|---|---|---|
| web 全局层 | `SUPERNOVA_WEB_MAX_CONCURRENT`（默认 4，`config.py:13`） | 按主行 scan 计数（`len(self._handles)`），超了抛 `TooManyScans` → API 层 429 **拒绝**（`api/scan.py:44`、`api/scans.py:681`），**不排队** |
| worker 层 | `SUPERNOVA_WORKER_MAX_CONCURRENT_WF`（默认 4，`worker/runner.py:159`） | 3 个 task queue（wb/bb/corr）**各有** 4 个 workflow 槽；超出的 workflow 在 temporal queue 里天然排队 |
| temporal 层 | — | task queue 自带排队（workflow 任务等 worker 槽） |

### 1.2 计数单位错位（本设计要治的根因）

跨仓扫描（correlation）在 web 层算 **1 个 scan**（`_correlation_orchestrator` 前的 start 提交段一次性把全部子仓白盒 workflow 提交完——`scan_manager.py:494-510` 的 `for plan in plan_repo_scans(...)` 循环），但在 worker 层 = N 个子仓 workflow + 1 个关联 workflow + 可选 1 个黑盒 workflow。web 的编排协程（`scan_manager.py:2868-2878`）只是**串行 await** 已全部提交的子仓——**提交全并行、收结果串行**。后果：一个 5 仓跨仓扫描可占掉 wb worker 全部 4 槽，其他扫描饿死；「全局限 4 个扫描」名不副实（4 个跨仓扫描背后可能是 20+ 仓同时跑）。

### 1.3 为什么闸门放 web 层

web 是全系统唯一的 temporal 提交端（web 进程零 agent 执行点，CLAUDE.md §2；所有 workflow 都经 `scan_manager` / `topology_analysis` 提交）。闸门收口在提交端 = 天然的全系统闸门，temporal / worker 零改动。

## 2. 目标 / 非目标

**目标**

1. 全系统扫描类 workflow 实际并发 ≤ N（默认 5，env 可配），超出**排队**（FIFO），不再 429 拒绝。
2. 计数单位 = 实际并发 workflow：单仓白盒/MR/黑盒各占 1 槽；跨仓扫描的每个子仓各占 1 槽、轮着扫（滑动窗口），关联阶段、黑盒段各占 1 槽。
3. 排队中可取消、可删除；web 重启后排队任务自动恢复入队；UI 显示「排队中」。
4. 辅助 workflow（认证验证 AuthValidation / 拓扑分析 TopologyAnalysis / 批量认证 BatchAuthValidation）**不过闸门**——否则辅助操作会被大扫描挤到排队。

**非目标**

- 不改 temporal / worker 代码逻辑（worker 只调默认槽位配置）。
- 不做排队超时（排多久都等；后续有需要再加旋钮）。
- 不做排队位置/预计等待时间展示（前端只显示状态）。
- 不改 CLI 直跑路径（CLI 不经 web 提交端，本来就不受此闸门管）。

## 3. 核心概念

- **槽（slot）**：一个「正在跑的扫描类 workflow」的占用凭证。容量 = `SUPERNOVA_WEB_MAX_CONCURRENT`（默认改 5，语义从「拒绝阈值」变「并发槽位」）。
- **占槽主体（component）**：gate 持有者 key = `(ws, scan_id, component)`，component 形如 `wb:<svc>`（子仓白盒）/ `corr`（关联）/ `bb:<run_id>`（黑盒 run）/ `main`（单仓白盒、MR 的主 workflow）。cancel/delete 按 `(ws, scan_id)` 前缀摘除该 scan 名下全部排队者。
- **排队（queued）**：scan 已登记落盘（session.json `status="queued"`）、校验全过、但首个扫描类 workflow 尚未提交。FIFO 先到先扫。
- **启动序列**：排队轮到后到提交成功之间的同步段（如组合扫描的 precheck 认证预验证）。**启动序列持槽执行**——实现简单、时序清晰，代价是 precheck 期间（分钟级）槽在「启动中」不跑 workflow；组合扫描占比低，可接受。

## 4. 架构：SlotGate（新文件 `packages/web/src/supernova_web/components/slot_gate.py`）

```python
class SlotGate:
    def __init__(self, max_slots: int): ...
    async def acquire(self, key: tuple) -> None:   # FIFO 等待；已持有则幂等
    def release(self, key: tuple) -> None:          # 唤醒队首 waiter
    def cancel_waiter(self, key_prefix: tuple) -> list[tuple]:  # 摘除排队者
    def waiting_prefix(self, key_prefix: tuple) -> bool:        # 是否在排队
    @property def held(self) -> int                 # 当前持有数（诊断/测试）
```

- **自实现 FIFO**（`collections.deque[future]`），不用 `asyncio.Semaphore`——后者 cancel/超时会打乱唤醒顺序，且拿不到「排队序」。
- `acquire` 返回即持有；持有者**必须**在 workflow 终态路径 `release`（挂 finally，防泄漏——2026-09-04 `db6b5298` 的槽泄漏教训）。
- 不持久化：gate 状态 = web 进程内存 + 启动时从 session.json 重建（见 §7）。

## 5. scan_manager 改造

### 5.1 start()：拒绝 → 排队（`scan_manager.py:303`）

现状顺序：`_check_temporal` → 槽检查（`TooManyScans`）→ `_resolve_inputs` → create_scan 落盘 → auth/host 快照 → 提交 workflow → 编排 task。

改为：

1. `_check_temporal` → **`_resolve_inputs` 与全部前置校验保持同步**（422/400 即时返回，不让必败请求躺队列）。
2. create_scan 落盘 + auth/host 快照照旧 → `SessionManager.update_session({"status": "queued"})` → `asyncio.create_task(启动序列)`（任务第一步 `gate.acquire`，在 FIFO 中排队即「登记等待」）→ **立即返回 `(ws, scan_id)`**（API 层不再抛 `TooManyScans`）。
3. 启动序列（新私有协程 `_queued_kickoff`）：`gate.acquire((ws, scan_id, "main"))` → 清 queued 标记（`update_session({"status": None})`，状态交回心跳判活）→ 执行原提交流程（按 type 分支，即现状 `scan_manager.py:381-549` 的 try 块整体后移）→ 提交失败走现有 `_mark_submission_failed`（539-546 的 BaseException 分支不变）。
4. release 点：单仓白盒/MR 挂在 `_watch` 观察到 scan_end 的 finally（`_watch` 已是终态唯一汇聚点）；组合扫描白盒 workflow 终态释放后，黑盒段重新 acquire（见 5.3）。

**排队上限防雪崩**：等待队列长度 > `SUPERNOVA_WEB_MAX_QUEUED`（新 env，默认 50）仍抛 `TooManyScans`（429 保留，语义变为「排队满了」）。

### 5.2 跨仓扫描：一次性全提交 → 滑动窗口

- start() correlation 分支（`scan_manager.py:466-526`）：**只保留落盘与 yaml dump**（⑤ 子仓登记循环中「复用子仓登记」的纯登记部分保留），**子仓 `_submit_whitebox` 调用挪出 start**——`child_handles` 不再在 start 期产出；`corr_children`、`corr_repo_paths`、`dumped` 等编排输入照旧落盘；`corr_writer.repo(svc, "started")` 事件随窗口化提交改到编排协程里发。
- `_correlation_orchestrator`（`scan_manager.py:2845`）段①重写为窗口化：

```
pending = [现扫子仓列表]        # 提交序
running: dict[svc, (task, key)] = {}
while pending or running:
    while pending and gate.held < capacity:          # 有空槽就补位
        svc = pending.pop(0)
        await gate.acquire(key=(ws, scan_id, f"wb:{svc}"))
        submit + corr_writer.repo(svc, "started")
        running[svc] = create_task(_await_workflow_result(handle))
    done = await 率先完成的任一 running task（asyncio.wait FIRST_COMPLETED）
    校验 status；failed → 主行 failed（现语义不变）；成功 release 该子仓槽
# 段②：gate.acquire(corr) → _submit_correlation → await → release
# 段③：gate.acquire(bb:run-1) → _run_blackbox_phase → release
```

- 「任一子仓失败 → 主行 failed」语义**不变**，但失败后**必须 drain**：已 in-flight 的兄弟子仓继续 await 至各自终态并逐一 release，全部收尾后主行才写 failed。原因：现状是首个失败即 return、兄弟 workflow 成无人等待的孤儿继续跑；若新编排也提前释放槽而 workflow 还在跑，等于**超卖槽位**（新人进来后实际并发 >5）。drain 保证不变量「workflow 在跑 ⇔ 槽被占」。复用子仓不占槽（无 workflow）。
- 段②关联、段③黑盒照旧串行接力，只是各自套 acquire/release。

### 5.3 组合扫描（whitebox + url）与黑盒 run

- `_combined_orchestrator` / `_rerun_orchestrator` 的 `_run_blackbox_phase` 调用点：白盒槽释放后 `acquire(bb:<run_id>)` → 跑黑盒 → finally release。
- `rerun_blackbox` / `resume` 重提的黑盒 run 同样占槽（同一封装函数内做，单点收口）。

### 5.4 cancel / delete / resume

- `cancel`（`scan_manager.py:2076` 起）：`gate.waiting_prefix((ws, scan_id))` 为真 → 摘全部排队者 + `update_session({"status": "cancelled"})` + `_ensure_scan_end` + 清 `_active_reqs`/`_orchestrator_tasks`，**不碰 temporal**（尚无 workflow）；已 running 的照现状走。
- `delete` 排队中 scan：先 cancel 语义摘除再删目录。
- `resume`（`scan_manager.py:563`）：`queued` 不进 `_RESUMABLE_STATUSES`——排队中无可恢复，提示等待或取消。

## 6. 状态机扩展：queued

- `_TERMINAL_STATUSES`（`workspaces_indexer.py:32`）**不加** queued（非终态）。
- `_compute_status`（`workspaces_indexer.py:37`）在「终态优先」之后、「心跳判活」之前插入：`session_status == "queued" → 返回 "queued"`。**顺序关键**：不加此分支会落到「兜底 interrupted」（queued 无心跳）——排队中的扫描被显示成「已中断」，这是最容易踩的坑。
- queued 是**瞬时标记**：提交成功即清（§5.1 步骤 3），不存在「queued + 心跳活」组合，状态机无特例。
- `_RUN_TERMINAL_STATUSES`（run 级，`scan_manager.py:64`）不动——黑盒 run 级不引入 queued。

## 7. 重启恢复

web 重启后 gate 清零、编排协程消失。启动时（lifespan，`app.py`）新恢复流程：

1. 遍历全部 ws 的 scans 读 session.json：
   - `status=="queued"` → 按目录创建序重新入 gate FIFO（重新 `create_task(_queued_kickoff)`；queued 未提交过 workflow，重入队无副作用）。
   - 非终态且心跳活（`is_scan_recently_active`）的扫描按其**独立 scan_dir 心跳**精确计槽：
     - 单仓白盒 / MR / 组合 / 黑盒 scan：心跳活非终态 → 占 1 槽。
     - correlation 主行：自身无 workflow，不按主行计——其 `corr_children` 中非 reused 子仓各有独立 scan_dir 与心跳，逐子仓按上述规则计。
     - 关联 / 黑盒阶段无独立 scan_dir 可锚 → 主行心跳活时**额外保守 +1**（宁可虚占一槽，不放超卖窗口）；偏差由 worker 槽兜底（§8）。
2. 心跳死且非终态 → 现状 `interrupted` 语义不变（用户手动 resume）。
3. `orphan_reconciler` / `_status_of` 路径跳过 queued（排队中心跳不更新是**正常态**，不得误杀/误标——与 §6 的 `_compute_status` 分支同因）。

## 8. 配置联动

| 配置 | 旧 | 新 | 说明 |
|---|---|---|---|
| `SUPERNOVA_WEB_MAX_CONCURRENT` | 默认 4，语义=拒绝阈值 | **默认 5**，语义=并发槽位 | 全局闸门容量 |
| `SUPERNOVA_WEB_MAX_QUEUED` | 不存在 | 新增，默认 50 | 排队长度上限，超出仍 429 |
| `SUPERNOVA_WORKER_MAX_CONCURRENT_WF` | 默认 4 | **默认 5** | 全局闸门放行 5 时 worker 不做二次排队；bb queue 上 authval/topology 与黑盒共槽，辅助占 1 槽时扫描峰值短暂 4，可接受 |

部署注意：现网若 env 已显式设 `SUPERNOVA_WEB_MAX_CONCURRENT=4`，升级后需同步改 5 才跑满（不设则取新默认）。

## 9. 前端

- `StatusBadge.tsx`：MAP 加 `queued: { icon: "⏳", cls: "border-yellow/40 text-yellow" }`（图标/色以实现时与既有视觉协调为准）；i18n 加 `workspaces.status.queued`（zh「排队中」/ en「Queued」）——`StatusBadge` 对未知状态有原值 fallback，漏 i18n 不会白屏但会露英文键，必须补。
- live 页：queued 状态进入时显示排队态（无 workflow id、进度 0%），不渲染「已中断」。
- `api/types.ts` 状态枚举补 `queued`。

## 10. 测试

- **SlotGate 单测**（新 `packages/web/tests/test_slot_gate.py`）：FIFO 唤醒序、release 后队首补位、cancel_waiter 按 prefix 摘除、容量边界、持有泄漏检测（acquire 未 release 的测试断言）。
- **scan_manager**（扩展现有 `test_scan_manager*.py`）：
  - queued 生命周期：容量满时 start 返回 queued（不抛 TooManyScans）→ 槽释放后自动提交 → 终态。
  - correlation 窗口化：5 子仓 + 容量 2 → 断言提交时序（最多 2 个 in-flight，完成一个才提交下一个）；子仓失败 → 主行 failed + 槽全释放。
  - cancel queued / delete queued / resume queued 拒绝。
  - `_compute_status` queued 分支 + reconciler 不误杀 queued。
  - 重启恢复：queued 重入队序、活跃扫描占槽重建。
- **API 层**：排队满 429、正常排队 200 返回 scan_id。
- **前端**：StatusBadge queued 渲染 + i18n（vitest，注意 feed 后端真实状态值字符串）。

## 11. 风险与边界

- **挂死 workflow 永久占槽**：scan_timeout=0（生产无 deadline）下挂死子仓占住槽——与现状 worker 槽占用同风险，不新增，但影响面从「单个 queue」扩大到「全局 5 槽」。缓解：temporal workflow 本身有 retry/heartbeat 失效判定，且可 cancel（cancel 释放槽）。
- **重启重建计数偏差**：保守少占 → 实际并发短暂超 5 → worker 槽（5）兜底，行为仍是排队不是过载。
- **precheck 持槽空窗**（§3 启动序列）：组合扫描 precheck 数分钟内槽在「启动中」。若实践发现组合扫描密集导致槽空转，再把 acquire 细分到 precheck 之后（预留优化点，首版不做）。
- **公平性**：FIFO 纯先到先扫，不做优先级/插队（非目标）。
- **CLI 直跑不受限**：闸门在 web 提交端，CLI 绕过——现状 CLI 也绕过 web 全局上限，行为不变。
- 守护测试 `test_web_never_runs_agents.py` 不受影响：SlotGate 纯编排，不 import agent 层。
