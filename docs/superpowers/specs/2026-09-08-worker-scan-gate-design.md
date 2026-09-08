# worker 侧全局扫描闸门设计（worker-scan-gate）

> 日期：2026-09-08。状态：spec 待审。
> 需求：全系统所有扫描最多同时 5 个任务，超出排队轮着来（不是拒绝）；UI 显示排队中任务 + 排队原因（当前哪个工作区的什么任务在扫描）。
> 取代被否决的 web 层 SlotGate 方案（原 `2026-09-08-global-scan-slot-queue-design.md`，已删；否决理由见 §12）。

## 1. 背景与现状

### 1.1 现有并发控制的三宗罪

**① web 门 = 拒绝，不是排队。** `scan_manager.py:311-312`（start）与 `:597-599`（resume）：`len(self._handles) >= self._max_concurrent → raise TooManyScans`，API 层转 **409**（`api/scan.py:44-45`、`api/scans.py:681-682`）。用户要么等要么重试，系统不帮忙排。

**② 跨仓扫描完全绕过计数。** correlation 主行与全部子仓 workflow **都不进 `_handles`**（`scan_manager.py:521-523`、`:2625-2627` 注释明示）：start 分支 `:495-513` 单循环内一次性提交全部子仓白盒 workflow（无任何 per-child 闸门），编排协程 `:2868-2877` 纯串行 await 收结果。一个 5 仓跨仓扫描可占满 wb worker 的并发承载，而 web 计数为 0。

**③ 检查无锁 + 重启清零。** 检查（:311）与登记（:547）之间无锁，并发请求可竞态超限；`_handles` 是进程内存态，web 重启即丢，配额白送。

### 1.2 temporal 天然排队已存在（本设计的地基）

worker 槽满时，新 workflow 留在 temporal task queue 里**已启动（RUNNING）、未开跑**——这段「排队态」机器里已有人正确处理：

- `orphan_reconciler.py:105-109`：明确把 RUNNING（含 worker 尚未 poll 的排队阶段）视为合法存活态，不误标 interrupted；
- `scan_liveness.py:81`：提交宽限 120s（`SUBMIT_GRACE_DEFAULT_SECONDS`），判活 = heartbeat fresh OR 宽限内。

但显示层有预存 bug：`workspaces_indexer.py:37-56` `_compute_status` 只看文件系统（终态 → 心跳活 running → 兜底 interrupted），排队 >120s 无心跳即显示「已中断」。

### 1.3 为什么闸门不能调 temporal worker 参数

worker 三 queue 各自 `max_concurrent_workflow_tasks=4`（`runner.py:159-161/186-188/198-200`），该参数限制的是**同时执行的 workflow task 数**（毫秒级编排推进；workflow 等 activity 时让出槽），不是「同时存活的扫描 workflow 数」。调它实现不了「全局同时 5 个扫描」的语义，直接排除。

### 1.4 部署形态（架构假设）

- worker：**单容器单进程**，进程内 3 个 temporalio Worker（wb/bb/corr queue）共享一个 asyncio 事件循环（`runner.py:209` gather；docker-compose 无 replicas）→ 进程内信号量即全局信号量，无需分布式协调。
- web：**单 uvicorn 进程**（Dockerfile CMD 无 `--workers`）。
- worker/web 容器共享 workspaces bind mount（`scan_liveness` 已验证此跨容器文件通道）。

## 2. 目标 / 非目标

**目标**

1. 全系统扫描类 workflow 实际并发 ≤ N（默认 5），超出在 temporal 里**排队**（近似 FIFO），不再 409 拒绝。
2. 计数单位 = 实际在跑的扫描 workflow：单仓白盒 / MR（经子白盒）/ 黑盒 run / 关联阶段各占 1 槽；跨仓的每个子仓各占 1 槽，与其他扫描公平竞争（滑动窗口自动涌现，无需专门编排）。
3. UI：扫描列表显示「排队中」状态与排队位次；并发概览面板显示 5 个槽被哪些工作区的什么任务占用（排队原因）。
4. 槽泄漏最坏情况从「永久占用直到人工干预」降为「janitor 周期内自动回收」。

**非目标**

- 不改 web 的 cancel/delete/resume/`_watch`/orphan_reconciler 链路（janitor 兜底后无需 web 侧槽纪律）。
- 不动 worker `max_concurrent_workflow_tasks`（它是编排推进并发，闸门才是扫描并发权威）。
- 不做排队超时、优先级/插队（排多久都等，纯先到先扫）。
- 不做多 worker 副本支持（单副本是部署现状；多副本时进程内信号量分裂，需迁共享存储——见 §11 注记，不预做）。
- CLI 直跑不受此闸门约束语义变化（CLI 独立进程独立 gate 实例，单扫描直接通过）。

## 3. 核心概念

- **闸门（ScanGate）**：worker 进程内的全局扫描并发信号量。容量 = `SUPERNOVA_SCAN_GATE_CAPACITY`（默认 5）。
- **占槽主体**：扫描类 workflow 实例，key = `activity.info().workflow_id`（天然幂等：重复 acquire 同一 workflow_id 视为已持有）。
- **排队（waiting）**：workflow 已 RUNNING、闸门段轮询中、尚未获得槽。排队状态持久化在 temporal 里（workflow 活着就在排队），web/worker 重启不丢。
- **闸门段（gate loop）**：扫描类 workflow `run()` 开头的 `while not try_acquire: sleep(5)` 循环 + `finally release`。
- **描述符（descriptor）**：acquire 时随参数传入的 `{ws, scan_id, kind, label}`，从 workflow input 现成字段派生，用于快照展示（「哪个工作区的什么任务」），web 零拼装。
- **janitor**：worker 进程内周期任务，校验持有/等待者的 temporal 存活性，回收死 key——槽泄漏的统一兜底。
- **bootstrap 预占**：worker 启动时把所有 RUNNING 的扫描类 workflow 预占进闸门，防重启超卖。

## 4. 架构：ScanGate（新文件 `packages/core/src/supernova_core/services/scan_gate.py`）

```python
class ScanGate:                       # 进程级单例（模块级实例）
    capacity: int                     # env SUPERNOVA_SCAN_GATE_CAPACITY，默认 5
    max_waiting: int                  # env SUPERNOVA_SCAN_GATE_MAX_WAITING，默认 50
    held: dict[workflow_id, {descriptor, acquired_at}]
    waiting: OrderedDict[workflow_id, {descriptor, first_seen_at}]   # 首次尝试序

    def try_acquire(workflow_id, descriptor) -> dict:
        # {"granted": bool, "queue_full": bool, "position": int}
        # 1. workflow_id 已在 held → granted=True（幂等；bootstrap 预占后对齐）
        # 2. 不在 waiting → 记 first_seen
        # 3. len(held) < capacity 且本 key 是 waiting 中 first_seen 最早 → 授予，
        #    从 waiting 摘除，落快照
        # 4. len(waiting) > max_waiting → queue_full=True（防雪崩第二道门）
    def release(workflow_id) -> None           # 摘 held，落快照
    def reap(workflow_ids: list[str]) -> None  # janitor 校验死后回收（held/waiting 皆可摘）
    def snapshot_path(self) -> Path | None     # env SUPERNOVA_SCAN_GATE_STATE_FILE，空=不落盘
```

- **近似 FIFO**：轮询模式下没有 waiter 队列，用 first_seen 时间戳做「有空槽时优先授予最早等待者」。公平性误差 = 一个轮询周期（5s）。若最早者恰在 sleep，槽空等到它醒来（最多 5s 空转），可接受。
- **快照落盘**：每次 held/waiting 变化原子写 `gate_state.json`（路径 = env `SUPERNOVA_SCAN_GATE_STATE_FILE`，生产 compose 指到 workspaces 挂载内）。CLI 未设此 env → 不落盘（CLI 不需要给 web 看），优雅降级。
- 状态文件是**展示快照不是权威状态**：权威 = 进程内 dict + temporal 里活着的 workflow；文件丢了/旧了只影响显示，不影响闸门正确性。

### 4.1 闸门 activity（同文件）

```python
@activity.defn
async def scan_gate_try_acquire(descriptor: dict) -> dict:
    wf_id = activity.info().workflow_id      # key 不需参数传
    return _GATE.try_acquire(wf_id, descriptor)

@activity.defn
async def scan_gate_release() -> None:
    _GATE.release(activity.info().workflow_id)
```

activity 跑在 worker 正常环境（不受 workflow sandbox 限制），直接操作进程级 `_GATE`。两个 activity 注册进**全部三个** Worker 的 activities 列表（`runner.py` wb/bb/corr 三处，跨 queue workflow 都要过闸）。

## 5. workflow 闸门段（三类扫描 workflow）

**加闸门的**（= 真跑 agent 的 workflow）：`WhiteboxScanWorkflow`（`whitebox/pipeline/workflows.py:107`）、`BlackboxScanWorkflow`（`blackbox/pipeline/workflows.py:66`）、`CorrelationScanWorkflow`（`multi/pipeline/workflows.py:55`）。

**不加的**：`MrScanWorkflow`（其子 WhiteboxScanWorkflow 占槽——MR 的重活就是白盒子扫描，前置 MR activities 轻量不占）；`AuthValidationWorkflow` / `BatchAuthValidationWorkflow` / `TopologyAnalysisWorkflow`（辅助操作，不该被大扫描挤队）。

`run()` 开头插入（以 Whitebox 为例，三类同构）：

```python
@workflow.run
async def run(self, input: PipelineInput) -> PipelineState:
    gate_desc = _gate_descriptor(input)      # {ws, scan_id, kind, label}，从 input 现成字段派生
    while True:
        r = await workflow.execute_activity(
            scan_gate_try_acquire, gate_desc, start_to_close_timeout=timedelta(seconds=30))
        if r["granted"]:
            break
        if r["queue_full"]:
            # 文案不带具体数值：workflow sandbox 不 import worker 进程常量，
            # 上限数字由 gate activity 返回值随 descriptor 透传（实现细节）
            raise ApplicationFailure(
                f"扫描排队已满（{r.get('max_waiting', '')}），请稍后重试",
                non_retryable=True)
        await workflow.sleep(5)              # 排队轮询；持久化在 temporal 里
    try:
        ...原有逻辑整体后移，零改动...
    finally:
        await workflow.execute_activity(scan_gate_release, start_to_close_timeout=timedelta(seconds=30))
```

- **descriptor 派生**（各 workflow 从自己 input 现成字段）：
  - 白盒：`ws` = `input.workspace_name` 或 event_file 派生；`label` = `Path(input.repo_path).name` + MR 时 `!{mr_meta 的 MR 号}`；`kind` = `"whitebox"`（MR 子 workflow 标 `"mr"`）。
  - 黑盒：`ws` = `input.workspace_name`；`label` = 目标 url；`kind` = `"blackbox"`。
  - 关联：`ws` + 仓组名；`kind` = `"correlation"`。
  - `scan_id` 从 event_file 路径段（`workspaces/<ws>/scans/<scan_id>/events.ndjson`）解析；解析不出置空（快照展示降级，闸门不受影响）。
- **event-sourced 重放安全**：worker 重启后已过闸的 workflow 重放时，闸门段的 try_acquire activity 结果从 history 恢复（granted=True），循环直接跳出，**不会重新排队**——正确性不依赖内存状态。
- **cancel 传导**：temporal cancel workflow → `workflow.sleep`/`execute_activity` await 点抛 CancelledError → finally 的 release activity 尽力执行。SDK 层面 cancelled workflow 中执行 cleanup activity 是允许的；即便失败（如已被保险丝 terminate），janitor 兜底（§6）。
- **queue_full 语义**：workflow 以 ApplicationFailure 终结 → 现有 `_mark_submission_failed`/`_watch` describe FAILED 链路把 scan 标 failed，提示文案含「排队已满」。这是防雪崩权威门；比 409 体验略差（提交后才失败），换取 web 零改动。

### 5.1 跨仓 / 组合 / 黑盒 run 的槽位语义（全部零改动涌现）

- **跨仓**：start 保持一次性全提交（`:495-513` 不动），N 个子仓 Whitebox 各自排队，全局并发被闸到 ≤5，滑动窗口自动涌现。任一子仓失败 → 主行 failed 语义不变（兄弟子仓继续跑到各自终态、各自释放自己的槽——槽跟 workflow 绑定，无超卖可能）。编排协程 `:2868-2877` 零改动。关联 workflow、黑盒段接力时各自 acquire。
- **组合扫描（whitebox+url）**：白盒槽释放后黑盒段 acquire（编排协程现状接力，自动过闸）。precheck（AuthValidation，辅助）不占槽。
- **rerun/resume 重提的黑盒 run**：同 BlackboxScanWorkflow，自动过闸。

## 6. janitor + bootstrap（`runner.py`，取消桥同款模式）

worker 已有跨三 queue 的进程内周期机制先例（协作取消桥 `runner.py:87-120`：5s 扫 `cancel.requested` 转发 temporal cancel）。janitor 完全同构：

```python
async def _gate_janitor(client: Client) -> None:
    while True:
        await asyncio.sleep(_GATE_JANITOR_INTERVAL_SECONDS)   # 10s
        for wf_id in _GATE.candidate_ids():                    # held + waiting 全体
            try:
                desc = await client.get_workflow_handle(wf_id).describe()
                if desc.status not in (WorkflowRunStatus.RUNNING,):   # 终态/不存在 → 回收
                    _GATE.reap([wf_id])
            except Exception:
                _GATE.reap([wf_id])          # 查不到 = 死 key，best-effort 回收
```

- 覆盖一切异常释放路径：cancel 保险丝 terminate（`scan_manager.py:2231-2255`，900s 后强杀不给清理机会）、cancel 时 cleanup 没跑成、workflow 崩溃。槽多占上限 = janitor 周期（10s）。
- waiting 里的死 key（排队中 cancel/terminate）同样被 reap——防「幽灵排队者」挡住 first_seen FIFO。
- describe 成本：候选 ≤ capacity + max_waiting = 55 个 × 每 10s 一次，可忽略。
- janitor 随 `run_worker` 主循环创建（与取消桥并列），进程退出即止。

**bootstrap 预占**（`run_worker` 内、三 worker `.run()` 之前）：

```python
async def _gate_bootstrap(client: Client) -> None:
    q = "TaskQueue IN ('supernova-wb-web', 'supernova-bb-web', 'supernova-corr-web')"
    try:
        flows = [f async for f in client.list_workflows(query=q)]
    except Exception:
        flows = [f async for f in client.list_workflows(  # 退化：类型过滤
            query="WorkflowType IN ('WhiteboxScanWorkflow','BlackboxScanWorkflow',"
                  "'CorrelationScanWorkflow','MrScanWorkflow')")]
    _GATE.preload([f.id for f in flows])    # 全部预占，workflow_id 为 key
```

- 治重启超卖：重启后内存闸门清零，新排队者会立即拿空闸门 → 与恢复中的在跑 workflow 超卖。预占所有 RUNNING 扫描类 workflow 后无超卖；已过闸者重放时 try_acquire 幂等命中预占 key，排队者按 first_seen 继续等。
- 预占把「排队中」也计入（保守，不区分过闸与否）——重启后短暂少放行，容量内语义无损。
- TaskQueue visibility 过滤若当前 temporal 版本不支持则退化按类型过滤，接受把 CLI 同类型 workflow 误预占（CLI 扫描期间 web 侧少一个槽，保守无害；CLI 使用频率低）。

## 7. web 改动（最小化：只删门，不加东西）

1. **删并发拒绝**：`scan_manager.py:311-312`（start）与 `:597-599`（resume）的 `TooManyScans` 检查删除；`TooManyScans` 异常类（`:46-49`）与 API 层 409 映射（`api/scan.py:44-45`、`api/scans.py:681-682`）删除；前端对应的 409 提示文案清理。
2. **`_handles` 保留**：`_watch` describe（`:2455-2461`）、cancel（`:2101`）等用途不变，只是不再是闸门——就算泄漏也无害化（不影响新扫描进入）。
3. **`SUPERNOVA_WEB_MAX_CONCURRENT` 退役**：`config.py:13`、`app.py:297-299`、`docker-compose.yml:54` 移除读取（env 传了不再读；部署文档注明）。并发权威 = worker 的 `SUPERNOVA_SCAN_GATE_CAPACITY`。
4. **`_compute_status` 补 queued 判定**（`workspaces_indexer.py:37-56`）：终态优先之后、心跳判活之前插一档——scan 非终态 且 (ws, scan_id) 命中 gate 快照 waiting 集（descriptor 匹配，不依赖 workflow_id 格式知识）→ 返回 `"queued"`。**顺序关键**：不加此档，排队 >120s 无心跳会落「兜底 interrupted」（§1.2 预存 bug，顺带修掉）。现状 `_compute_status` 对跨仓主行无专门聚合（纯通用三档），跨仓主行 queued 判定：主行非终态 + 心跳死（关联阶段未在跑）+ 主行 scan_id（corr workflow descriptor 挂主行）或其 `corr_children` 登记的任一子仓 scan_id 命中 waiting → 主行 queued（子仓清单从主行已落盘的 corr_children 读，不新增落盘）。
5. **orphan_reconciler 兼容**：现有 `_workflow_still_running`（temporal describe）已保护排队中扫描不被误标 interrupted，无需改；gate waiting 命中时同样跳过（新增一个短路条件，防御性）。

## 8. 快照 → API → 前端

### 8.1 `GET /api/scan-gate`（新端点）

读 `<workspaces_root>/gate_state.json` 返回：

```json
{
  "capacity": 5,
  "held":    [{"ws": "prod", "scan_id": "…", "kind": "whitebox", "label": "payment-svc@main", "since": "…"}],
  "waiting": [{"ws": "prod", "scan_id": "…", "kind": "mr", "label": "user-svc!1234", "since": "…"}]
}
```

- waiting 按 first_seen 序返回（= 排队位次）。
- **权限过滤**：按现有工作区权限模型，无权工作区的条目过滤隐藏，容量计数（x/5）保留全局数字（计数无害）。
- 文件缺失/过期（worker 未起/刚重启）→ 返回 `{capacity, held: [], waiting: []}`，前端面板不显示。

### 8.2 前端

- **StatusBadge**：MAP 加 `queued`（zh「排队中」/ en「Queued」）；`api/types.ts` 状态枚举补 `queued`。现状 `cancelled`/`timeout` 走 "?" fallback 的债不在本 spec 范围（不顺手扩）。
- **live 页 / 扫描详情**：queued 状态显示「排队中 · 第 N 位」（N 从 gate 快照序算），不渲染进度空壳。
- **并发概览面板（新组件 `ScanGatePanel`）**：扫描列表页顶部，仅当 held 或 waiting 非空时出现：

```
┌─ 扫描并发  3/5 运行中 ──────────────────────────────┐
│ 运行中                                               │
│  ● prod      白盒  payment-svc@main        已运行 23m │
│  ● prod      MR    user-svc!1234           已运行 11m │
│  ● staging   黑盒  https://api.example.com  已运行 42m │
│ 排队中 (4)                                            │
│  ○ prod      跨仓  checkout 仓组（5 子仓）    第 1 位  │
│  ○ dev       白盒  admin-portal@feat-x      第 2 位  │
└──────────────────────────────────────────────────────┘
```

  每行：工作区 · 类型徽章 · 任务标签 · 已运行时长 / 排队位次。「为什么排队」一目了然：5 槽被谁占、我排第几。
- **刷新节奏**：跟随列表页现有刷新，不独立轮询（gate_state.json 读取代价极低，将来要实时再加 SSE 不贵）。
- i18n：zh/en 全量补（topology 子系统已有 `queued` 前端先例，模式照搬）。

## 9. 配置汇总

| 配置 | 位置 | 默认 | 说明 |
|---|---|---|---|
| `SUPERNOVA_SCAN_GATE_CAPACITY` | worker env | `5` | 全局扫描并发槽位（用户需求的「5」） |
| `SUPERNOVA_SCAN_GATE_MAX_WAITING` | worker env | `50` | 排队长度上限（防雪崩 + 压轮询负载：50 × 每 5s = 10 activity/s） |
| `SUPERNOVA_SCAN_GATE_STATE_FILE` | worker env | 空=不落盘 | 快照路径；生产 compose 指 `<workspaces_mount>/gate_state.json` |
| `SUPERNOVA_WEB_MAX_CONCURRENT` | web env | — | **退役**（曾默认 4） |
| `SUPERNOVA_WORKER_MAX_CONCURRENT_WF` | worker env | `4` | **不动**（workflow task 编排推进并发，与闸门正交） |

compose 变更：worker 服务加三个新 env；web 服务删 `SUPERNOVA_WEB_MAX_CONCURRENT` 透传（docker-compose.yml:54）。

## 10. 测试策略

- **core 单测**（新 `packages/core/tests/test_scan_gate.py`）：
  - FIFO：first_seen 优先授予；最早者 sleep 中槽空等不跳位。
  - 幂等：重复 acquire 同 workflow_id → granted。
  - queue_full 边界：waiting 达上限后新等待者 queue_full。
  - release / reap：摘除后下一个最早者可授予；快照原子写内容正确（held/waiting/since）。
- **workflow 集成测**（TestWorkflowEnvironment，mock gate activity）：
  - 白盒 workflow：满槽时排队（sleep 循环）→ 槽释放后放行 → 原逻辑跑完 → finally release。
  - cancel 中途：CancelledError 后 release 尽力执行；模拟 cleanup 失败 → janitor reap 回收（黑盒/关联同构抽参数化）。
  - queue_full → ApplicationError 且 scan 落 failed（接现有 `_watch` describe FAILED 链路的断言）。
- **worker 集成测**（`packages/worker/tests/`）：bootstrap 预占（list RUNNING mock）、janitor 周期回收（describe mock 终态/异常两路）、三 Worker activities 列表含两个 gate activity（防漏注册——漏了 = 排队 workflow 的 activity 无处执行直接超时）。
- **web 测试**：
  - start/resume 不再抛 TooManyScans（并发提交 N 个全受理）。
  - `_compute_status` queued 档：非终态 + waiting 命中 → queued；不命中 + 心跳死 → interrupted（回归）。
  - `/api/scan-gate`：正常返回、文件缺失空返回、ws 权限过滤。
- **前端**（vitest）：StatusBadge queued 渲染 + i18n 键、ScanGatePanel 两栏渲染与空态隐藏（feed 后端真实状态值字符串，勿造假数据）。
- **守护**：`test_web_never_runs_agents.py` 不受影响（gate 纯编排，web 侧只读快照文件）。

## 11. 风险与边界

- **单 worker 副本假设**：进程内信号量在多副本下分裂（每副本独立容量 5 → 总 10）。部署现状单副本；将来 scale 时把 gate 迁共享存储（Redis/DB 租约）。**不预做**，在 runner.py 注释注明此假设。
- **cancel 后 release 依赖**：finally 的 release activity 尽力执行，失败由 janitor 10s 兜底。与旧方案的「泄漏到人工干预」相比数量级改善；残余风险 = 多占 ≤10s。
- **轮询负载**：排队者每 5s 一个短 activity（读内存 dict 即返回）。上限 50 排队者 = 10 activity/s，三 queue 分摊，可忽略。
- **资源联动**：闸门 5 × 每扫描内部 3 并发 agent（`SUPERNOVA_MAX_CONCURRENT`）≈ 15 并发 LLM（现状 4×3=12），worker 8cpu/4g 可扛；黑盒内部另有 Semaphore 不变。
- **bootstrap 保守性**：TaskQueue visibility 过滤不可用时 CLI 同类型 workflow 被误预占（web 侧短暂少槽，保守无害）。
- **快照新鲜度**：gate_state.json 只在 worker 进程内变化时写；worker 挂了文件停在旧态 → 面板显示僵尸条目，直到 worker 恢复。缓解：API 读文件时对 `since` 超过阈值（如 2h）的 held 条目标记 stale（前端弱化显示）。首版可只做时间展示，用户自行判断。
- **queue_full 体验**：提交成功后 scan 才 failed（非提交时 409）。上限 50 足够宽，正常使用碰不到；碰到时提示明确。

## 12. 与被否决方案的关系（历史记录）

同日早前的 `global-scan-slot-queue-design.md`（web 层 SlotGate）被否决，核心理由：

1. 在 web 进程里重新发明 temporal 已白送的排队系统（持久化/FIFO/重启恢复），代价是内存 gate + session 状态标记 + 心跳计槽重建三套状态手工同步，其 §7 整节（逐子仓心跳计槽 + 关联/黑盒「保守 +1 宁可虚占」）全是一致性补丁。
2. 闸门纪律散布在 web 每个提交/编排/取消点（acquire/release/drain），`db6b5298` 槽泄漏事故已证明手工纪律脆弱；terminate 保险丝路径在旧方案下依然泄漏、无兜底。
3. 跨仓滑动窗口需要重写编排协程（窗口化 + drain 兄弟），而 worker 闸门下零改动涌现。
4. 旧 spec 对现状的事实认定有误（称 API 返回 429，实际 409；称跨仓算 1 个 scan，实际算 0 个）。

本方案把排队下沉到 temporal（workflow 活着 = 在排队），闸门纪律收口在 workflow 模板一处 + janitor 兜底，web 只删门不加门。
