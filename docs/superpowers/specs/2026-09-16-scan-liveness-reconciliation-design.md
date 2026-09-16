# 扫描存活性对账与中断语义收口

> 日期：2026-09-16。状态：已实施。
> 范围：web 扫描状态机、Temporal 存活对账、前端展示、worker gate 快照展示口径。
> 本设计修复「心跳短暂丢失显示已中断，随后又显示运行中」以及由此诱发的错误 resume / gate 展示不一致。

## 1. 背景与问题

当前系统存在三套不同的信号：

| 信号 | 现状 | 能回答的问题 | 不能回答的问题 |
|---|---|---|---|
| `session.json` / `scan_end` | 应用业务状态 | 是否已有明确业务收尾 | workflow 是否仍在 Temporal 中存活 |
| heartbeat 文件 | 90 秒内是否有 worker 执行扫描代码 | worker 最近是否正在执行 | workflow 是否在 Temporal 排队、retry backoff 或等待重新被 worker 接管 |
| Temporal `describe()` | workflow execution 生命周期 | execution 是否 `RUNNING` 或已经关闭 | 本项目业务结果应显示 completed / failed / cancelled 的哪一种 |

`_compute_status()` 目前在无显式终态且 heartbeat stale 时直接返回 `interrupted`。但 Temporal workflow 在 activity retry backoff、worker 重启、任务队列等待时仍可能是 `RUNNING`；扫描详情会额外 `describe()` 并改回 `running`。这不是 workflow 被重新提交或“复活”，而是弱心跳信号被错误地当成了终态。

更危险的是 `interrupted` 属于 `_RESUMABLE_STATUSES`。当 heartbeat stale 的实际运行 workflow 被用户续跑时，现有 resume 路径会调用 `_terminate_inflight_prior_execution()` 后提交 `-resume-N`，可能人为终止仍在 retry 的原 execution。

并发面板的 `gate_state.json` 是 worker gate 的展示快照：held/waiting 表示 Temporal 尚在运行、应占用容量的 workflow。它不能用 web 的心跳推断状态反向过滤；否则会把仍在执行或重试的真实占用隐藏，容量数字与 worker 实际 gate 分裂。

## 2. 目标与非目标

### 2.1 目标

1. 心跳 stale 不再直接产生 `interrupted` 终态或 resume 入口。
2. 只有确认 workflow 已无法继续、且业务收尾不能归类时，才持久化 `interrupted`。
3. Temporal 查询错误绝不写终态、绝不关闭 SSE、绝不释放 worker gate。
4. 扫描列表、详情、Live 页、删除/resume 状态门与并发面板使用兼容且可解释的口径。
5. Gate 容量始终反映 worker 侧实际 held/waiting，不因前端展示状态漂移而少计。

### 2.2 非目标

- 不改变用户主动取消的 API 语义和 cancel fuse；`cancelled` 仍表示用户已请求停止。
- 不以每次扫描列表轮询触发 N 次 Temporal `describe()`。
- 不在本设计内改变 Temporal workflow 的 retry policy、activity heartbeat 周期或 gate 的 FIFO / 容量算法。
- 不要求历史已落盘 `interrupted` 自动回写；仅保证新逻辑不再制造该类误终态，并提供诊断信息。

## 3. 术语与状态模型

### 3.1 Temporal 状态与应用状态分层

Temporal 没有 `interrupted` 状态；其 execution 状态包括 `RUNNING`、`COMPLETED`、`FAILED`、`CANCELED`、`TERMINATED`、`TIMED_OUT`、`CONTINUED_AS_NEW`。本项目的 `interrupted` 是业务层的异常收尾状态，绝不直接映射某一个 Temporal enum。

应用层分为两类：

- **持久业务终态**：`completed`、`failed`、`cancelled`、`killed`、`crashed`、`interrupted`。写入 `session.json`，并且（扫描级）有对应 `scan_end`。一旦写入不因 heartbeat 复鲜而反转。
- **派生的活跃/过渡态**：`queued`、`running`、`reconnecting`。不写入 `session.status`，由 gate、heartbeat 和 Temporal probe 计算；不可 resume、不可 delete。

新增 `reconnecting` 的含义为：**没有 fresh heartbeat，尚未获得“已关闭且可收尾”的确认**。它不是失败、不是用户取消，也不代表 workflow 一定会自动成功。

### 3.2 状态决策表

优先级从上到下：

| 条件 | 对外状态 | 持久化 | gate / 操作 |
|---|---|---|---|
| session 有业务终态 | 该终态 | 已有 | 不因 heartbeat 改写；gate 面板仍按 Temporal 实际 held 显示 |
| gate waiting 命中 | `queued` | 否 | 占等待位；不可 resume/delete |
| heartbeat fresh 或提交宽限内 | `running` | 否 | 活跃；不可 resume/delete |
| heartbeat stale，Temporal probe=`RUNNING` | `reconnecting` | 否 | 仍占 held/waiting；不可 resume/delete |
| heartbeat stale，Temporal probe=`UNKNOWN` | `reconnecting` | 否 | 保守保留；不可 resume/delete |
| heartbeat stale，Temporal probe 确认 execution 已关闭 | 进入业务结果收尾 | 是 | gate janitor 按 Temporal 终态摘除 |
| heartbeat stale，已确认 workflow 不存在且无可归类业务结果 | `interrupted` | 是 | 可 resume/delete |

`cancelled` 是特殊终态：用户调用 cancel 后 web 会立即写入该业务意图，但 Temporal 可能仍处于取消传播窗口。此时扫描列表可显示“已取消”，而并发面板必须继续显示实际 held，并标注“取消中”，直至 janitor 观察到 execution 关闭。

## 4. Temporal probe：三态，不再用 bool

将 `_workflow_still_running() -> bool` 改为内部三态结果，而不是“任何异常都返回 False”：

```python
class WorkflowProbe(Enum):
    RUNNING = "running"       # describe 成功，status == RUNNING
    CLOSED = "closed"         # describe 成功，status 为任意关闭态；携带原始 status
    ABSENT = "absent"         # 服务明确返回 RPC NOT_FOUND
    UNKNOWN = "unknown"       # 超时、网络错误、认证/服务端错误
    UNTRACKED = "untracked"   # legacy / CLI：没有可可靠推导的 Temporal workflow id
```

规则：

1. 只有 `CLOSED` / `ABSENT` 是可用于推进收尾的事实；`UNKNOWN` 必须 fail-open。
2. `ABSENT` 对有明确 Temporal workflow 身份的 web 扫描，可作为“execution 不存在”的证据；legacy / host CLI 扫描返回 `UNTRACKED`，仍走其既有本地存活策略。`UNKNOWN` 专指本应可查询、但本轮查询不可信。
3. `CLOSED` 不能一律写 `interrupted`：优先读取 workflow result、已有 `scan_end` 和 session 业务字段，按 completed / failed / cancelled / timeout 等正确收尾；仅无正常结果的异常关闭才落 `interrupted`。
4. Temporal `CONTINUED_AS_NEW` 视为同一 workflow chain 存活，probe 必须 follow run chain 或识别新 run，不能把它当关闭的扫描。

该设计与 worker gate janitor 的口径对齐：仅 `NOT_FOUND` 或明确非 `RUNNING` 才回收；查询异常跳过本轮。

## 5. Web 对账与状态计算

### 5.1 `_compute_status` 的职责收窄

`_compute_status` 是同步、文件系统路径，不能查询 Temporal。它只负责：

1. 显式业务终态 → 原样返回。
2. gate waiting → `queued`。
3. fresh heartbeat / 提交宽限 → `running`。
4. 其余 → `reconnecting`，**不得返回 `interrupted`**。

扫描列表因此不会发起 Temporal 网络请求；它在旧心跳窗口展示“重连中 / 正在确认任务状态”，而不是错误提供“续跑”按钮。

### 5.2 对账触发与落盘

保留 app 启动和 events 请求中的 orphan reconciliation，并新增有界的后台对账：每 60 秒触发一轮；`reconcile_orphaned()` 会在文件系统层短路显式终态、已有 `scan_end`、queued、fresh heartbeat，仅对剩余的 `reconnecting` 扫描 probe。每轮按扫描串行处理，配合 5 秒 probe 超时，避免工作区多时打满 Temporal；60 秒即同一扫描的最短 probe 冷却窗口。

对账状态机：

```text
reconnecting
  ├─ probe RUNNING / UNKNOWN ──────────────> reconnecting（不写文件，稍后再查）
  ├─ probe CLOSED + 可解析业务结果 ────────> 对应业务终态
  └─ probe CLOSED/ABSENT + 无业务收尾依据 ─> interrupted + scan_end
```

对账在写 `scan_end` 前须二次读取 session 与事件尾部，保证与 cancel、正常 `_watch` 收尾并发时不覆盖新终态。任何写入失败不改变内存态；下一轮继续 `reconnecting`。

### 5.3 Resume、删除与 SSE

- `reconnecting` 不在 `_RESUMABLE_STATUSES`，resume API 返回“任务仍由 Temporal 管理或状态暂不可确认，请等待对账”。不得调用 `_terminate_inflight_prior_execution()`。
- `reconnecting` 不是可删除状态；删除同样拒绝，避免删除仍由 worker 使用的 workspace 文件。
- Live 页在 `reconnecting` 时保持可重连，不以 `scan_end` 关流；显示“worker 无心跳，正在向 Temporal 确认”。
- 显式 `interrupted` 仍是可续跑终态，保留现有断点预览与产物复用语义。

## 6. Gate 快照与 API

Gate 是 worker 可用容量的事实来源，`gate_state.json` 是其展示快照，不是扫描业务状态的缓存。

1. `GET /api/scan/gate` 不得调用 `_compute_status()` 来过滤 held 或 waiting；移除/替换当前基于心跳的过滤逻辑。
2. worker janitor 继续是唯一负责从 held/waiting 回收终态 workflow 的组件。它对 probe 异常 fail-open。
3. API 仅做权限过滤、字段规范化和无效/无法解析的展示降级；不得因 scan 行显示 `reconnecting`、`cancelled` 或 `interrupted` 而更改容量计数。
4. 面板每项可附带展示提示：`reconnecting` → “等待 worker 重连”；`cancelled` 但仍 held → “取消请求处理中”。这不改变 held/waiting 计数。

这也取代提交 `99e34c9a` 中“以 `_compute_status` 过滤 gate 条目”的做法：该过滤只适用于**已由 Temporal janitor 摘除后仍残留的无效快照**，而不能将 heartbeat stale 当作无效依据。若需要 API 兜底清理，只能基于明确的 Temporal 已关闭证据或下一次 worker janitor 结果。

## 7. 前端与 API 契约

### 7.1 类型与文案

- `ScanStatus`、列表/详情响应、`StatusBadge` 增加 `reconnecting`。
- 中文：`重连中`；辅助文案：`暂未收到 Worker 心跳，正在确认 Temporal 任务状态。`
- 英文：`Reconnecting`；辅助文案：`No recent worker heartbeat; confirming the Temporal workflow state.`
- `reconnecting` 使用中性/等待样式，不使用代表失败的红色或代表终态的暂停图标。

### 7.2 操作矩阵

| 状态 | 取消 | 续跑 | 删除 | 并发面板 |
|---|---:|---:|---:|---|
| queued / running | 可用 | 不可用 | 不可用 | waiting / held |
| reconnecting | 可用 | 不可用 | 不可用 | held 或 waiting；提示等待确认 |
| cancelled | 不可用 | 取消收尾完成后可用 | 现有语义 | 若仍 held，显示取消中 |
| interrupted | 不可用 | 可用 | 可用 | 通常不应出现；残留由 janitor 处理 |
| completed / failed / killed / crashed | 不可用 | 保持既有契约 | 可用 | 不应出现 |

前端不得把 `reconnecting` 当作 `interrupted` 的别名，也不得在该状态预加载 resume preview。

## 8. 改动面与测试

### 8.1 后端

- `packages/web/src/supernova_web/components/workspaces_indexer.py`：兜底状态改为 `reconnecting`。
- `packages/web/src/supernova_web/components/orphan_reconciler.py`：bool probe 升级为三态；查询异常 fail-open；补业务终态映射与有界后台对账。
- `packages/web/src/supernova_web/api/scans.py`：删除详情页对 `interrupted -> running` 的临时覆写，改消费统一对账状态。
- `packages/web/src/supernova_web/components/scan_manager.py`：resume/delete 状态门增加 `reconnecting`；只让确认的 `interrupted` 进入 resume。
- `packages/web/src/supernova_web/api/scan.py`：撤销基于 `_compute_status` 的 gate held/waiting 过滤，保留权限过滤与 schema 修复。
- `packages/worker/src/supernova_worker/runner.py`：行为无需改变；补回归测试锁定 janitor 的 fail-open 口径。

### 8.2 前端

- `packages/web/frontend/src/api/types.ts`、API 类型、`StatusBadge`、i18n：加入 `reconnecting`。
- 扫描列表、详情、Live 页：展示等待确认，不展示续跑/删除操作。
- `ScanGatePanel`：以 gate held/waiting 原样计数；展示 scan 状态只作说明，绝不作为过滤条件。

### 8.3 必测场景

1. activity retry backoff 超过 heartbeat 窗口、Temporal `RUNNING`：列表/详情均为 `reconnecting`，gate held 保留，resume/delete 被拒。
2. worker 重启、随后接管成功：`reconnecting -> running`，不写 `scan_end`，不产生新的 workflow id。
3. Temporal 查询超时/500：维持 `reconnecting`，不写 `interrupted`，gate 不回收。
4. Temporal 明确 `NOT_FOUND` 或异常关闭且无业务收尾：只写一次 `scan_end=interrupted`，可 resume。
5. Temporal `COMPLETED` / `FAILED` / `CANCELED`：按可读的 workflow 结果映射业务终态，不笼统降为 `interrupted`。
6. 用户取消后 Temporal 仍 `RUNNING`：列表维持 cancelled 业务意图，gate 面板仍计 held 并标“取消中”；janitor 确认关闭后才消失。
7. 旧 session 已显式 `interrupted`：保持历史终态，不因 heartbeat / probe 改写；可按既有 resume 继续。
8. 扫描列表包含大量 `reconnecting` 行：不产生逐行 `describe()`；后台 probe 有并发和冷却上限。

## 9. 验收标准

1. 任何页面不再出现同一未操作扫描在“已中断”和“运行中”之间跳变。
2. 未经 Temporal 明确关闭确认，不写 `interrupted`、不关闭 SSE、不给 resume。
3. Gate 面板的 held/waiting 数与 worker gate 快照一致；心跳 stale 的 `RUNNING` workflow 仍被计入。
4. Temporal 故障期间系统保守：可能长期显示“重连中”，但不会误杀、误删、误续跑或超卖并发。
5. `cancelled` 与 `interrupted` 的区别可由用户意图和事件证据追溯：前者来自主动取消，后者来自确认的异常收尾。
