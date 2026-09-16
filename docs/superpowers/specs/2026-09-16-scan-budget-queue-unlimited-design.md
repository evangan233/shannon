# 扫描预算（获槽起算）+ 排队不限时 设计

> 2026-09-16。金融平台-2026h2 批量事故（一次提交 190 个白盒扫描：139 个秒败排队满 + 37 个排队 3h 被 run_timeout 整点收割，一个 phase 都没跑）驱动。

## 1. 问题

1. **run_timeout 从提交起算**：`SUPERNOVA_WORKFLOW_TIMEOUT_HOURS`（默认 3h）的 run_timeout 由提交端设置，temporal 从 `WorkflowExecutionStarted` 起算；而扫描闸门（spec 2026-09-08）的排队发生在 **workflow 内部轮询**（`acquire_gate_slot`），排队时间全额吃掉预算——排队中的扫描不是「还没开始」，在 temporal 眼里一直在活跃执行。
2. **事件历史天花板**：temporal 单 workflow 事件历史 ~50k 上限（超限直接 fail）。闸门轮询每 5s 一圈 ~11 events，排队 ~6.5h 必撞——单纯调大超时躲不开（金融平台实测：排队 3h 的 workflow 累积 22,773 events）。

两者叠加 = 「调大 run_timeout 保排队」与「排队不限时」不可兼得，必须换机制。

## 2. 设计

### 2.1 语义（用户拍板）

- **排队不限时**：对齐 scan-gate spec 原意「不做排队超时，排多久都等」（2026-09-08 spec §2 非目标）。
- **单扫预算默认 5h，从获槽起算**：env `SUPERNOVA_SCAN_BUDGET_HOURS`（替代废弃的 `SUPERNOVA_WORKFLOW_TIMEOUT_HOURS`）。token 防失控目的完整保留——排队零 LLM 消耗，预算收口在获槽后即兜住全部 token 消耗。实测单扫中位 109min（26-179min），5h ≈ 2.7× 余量。
- 超预算 = temporal 服务端 TIMED_OUT → web `_watch` describe 轮询既有路径标 failed，零新消费点。

### 2.2 机制：acquire_gate_slot 周期 continue-as-new

排队 stint ≥ `min(GATE_CONTINUE_AFTER=20min, run_timeout/3)` 或获槽且 stint>0 时，`workflow.continue_as_new(args=[input])` 重开 run：

- **排队期重开**：事件历史清零（每 run ≤ ~2.6k events，5s 轮询）；workflow_id 不变 → worker 内存 gate 的 waiting 条目（含 first_seen）原样保留，**FIFO 位置不丢**；新 run 重入轮询，排多久都等。
- **获槽重启**（stint>0 时）：新 run 首次 try_acquire 走 `held` 幂等路径（`scan_gate.try_acquire` 对 held 中 workflow_id 直接 granted），预算（run_timeout，每 run 独立计时）**满额从获槽起算**。免排队快路径（stint==0）不重启、原地进扫描。
- **run_timeout/3 兜底**：stint 消耗当前 run 自己的 run_timeout，预算调很小时防排队 run 在获槽前被预算杀掉。
- 实效 CAN 间隔 = min(20min, 预算/3)：预算 5h → 20min；预算 30min → 10min。

### 2.3 安全性论证（实现前逐项核实）

| 约束 | 论证 |
|---|---|
| release 不误摘排队条目 | 三个扫描 workflow 的 `acquire_gate_slot` 都在 run() 的 try/finally（`release_gate_slot`）**之前**；ContinueAsNewError 是 **BaseException** 子类（temporalio 1.27.2 实测 MRO），不被 `except Exception` 吞，直接展开出 run，finally 不执行 |
| FIFO 不丢 | waiting 按 workflow_id 键控；重开 run 的 try_acquire 见 workflow_id 已在 waiting → 不重复入列、first_seen 不动（`ScanGate.try_acquire`） |
| 获槽幂等 | `ScanGate.try_acquire` 对 held 中 workflow_id 直接 granted（既有路径，spec §4） |
| 重放安全（2026-09-08 spec §5.138 论证的 CAN 续篇） | 每 run 各自 history 持有各自 try_acquire 结果（重放不重执行）；跨 run 的闸门状态 SSOT 是 worker 内存 gate dict（workflow_id 键控），与 history 无关 |
| janitor/bootstrap | 按 workflow_id + describe RUNNING 判定（runner.py），CAN 链 describe 恒 RUNNING，透明 |
| web 状态 | `_status_of` 文件驱动：queued 档读 gate_state.json 快照（`_is_queued_in_gate`）→ 排队恒 queued，不误判 interrupted（批量事故中排队 3h 未误杀已实证）；`handle.result()` 默认 `follow_runs=True` 跟随 CAN 链；句柄均未钉 run_id |
| 事件流 | CAN 本身只加 ContinuedAsNew + 新 Started 两事件；排队期无 phase 事件，events.ndjson 零写入（web queued 档不依赖事件） |

### 2.4 已知例外与边界

- **MR 增量扫描**：父 `MrScanWorkflow` 不过闸门（child 全量白盒才过），child 的闸门排队时间仍计入父预算（既有语义）。MR 不走批量场景；如需 MR 排队不限时，须让父周期重开（涉及 child 生命周期语义），另立 spec。child run_timeout clamp 到父剩余预算（`max(min(6h, 父剩余), 30min)`，防 6h child > 5h 父先死白跑）。
- **corr 关联扫描**：activity 预算 4h，提交端保持 `max(scan_budget(), 4h30m)` 下限（final-fix ④）。
- AuthValidationWorkflow / topology：不套预算，现状不变。
- **gate worker 侧（ScanGate 类 / janitor / bootstrap）零改动**：CAN 对其透明。

## 3. 改动面

- `core/runtime/workflow_timeout.py`：`workflow_run_timeout()` → `scan_budget()`，env `SUPERNOVA_SCAN_BUDGET_HOURS` 默认 5，容错契约不变（畸形/<1 回落 + warning）。
- `core/services/scan_gate.py`：`acquire_gate_slot(descriptor, input)` + `GATE_CONTINUE_AFTER` 常量 + `_continue_after_seconds()`。
- whitebox/blackbox/multi 三 workflow 调用点透传 input；web `scan_manager` 4 处 + CLI `whitebox/worker.py`、`blackbox/worker.py`、`core/scan_runner.py` 改用 `scan_budget()`；MR child clamp。
- 测试：core 单测重写；whitebox +2（排队 CAN 全链路 / 免排队无 CAN）、blackbox +1（CAN 输入类型路径，机制本体 whitebox 覆盖）；web corr max 下限测试改 env 调小档锁下限分支。
- 文档：`docs/scan-time-gates.md` §一/二.1/二.2/三/七 同步；`.env.example`。

## 4. 容量口径

排队上限默认 50 → **500**（同日追加，对齐批量提交默认 `SUPERNOVA_BATCH_SCAN_MAX_REPOS=500`；金融平台事故 139 个 queue_full 秒拒违背排队不限时语义，queue_full 的防雪崩职责由 continue-as-new + 轮询超时容忍接手——排队中轮询 activity 撞 30s start-to-close（事故 cloud_sync_svr 排队 47min 死于此）现视同未获槽重试）。容量（capacity 5）不变；吞吐 = capacity × 单扫速度（中位 109min），190 个 ≈ 3 天。排队不限时解决「排队被误杀/误拒」，不创造容量。
