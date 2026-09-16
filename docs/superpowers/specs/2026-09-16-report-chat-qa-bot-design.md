# 报告页漏洞问答聊天机器人 设计

> 2026-09-16。需求：用户对扫描结论/过程不满意时，在报告页与 AI 追问，机器人能读报告与被扫仓库回答。复用扫描引擎配置（profile 配什么引擎就用什么），多轮对话。评估结论：做（架构通路全部有现成模板，中等规模，无阻塞性风险）。

## 1. 目标 / 非目标

**目标**
- ReportTab 内嵌可折叠聊天面板；每个（scan, 用户）一个会话，多轮追问。
- 引擎跟随扫描配置：worker 容器 `.env.profiles` 全局 profile + per-ws `provider_config` 覆盖，双引擎（claude-agent-sdk / openai-agents）统一走 `run_claude_prompt`，零引擎新代码。
- 机器人可读：本次报告产物（deliverables/）+ 被扫仓库源码；答案带 file:line 引用。
- 全程只读工具档；成本逐轮计量展示；护栏完备（并发/轮数/时长/max_turns）。

**非目标（P1 再议）**
- 逐 token 流式输出（provider 抽象是整段返回；做需改双引擎 provider 层）。MVP 用工具活动进度流（SSE）给"正在分析"感知。
- 跨 tab（Evidence/Deliverables）入口、全局抽屉。
- 结构化 messages 历史（provider 层加 messages 参数）；MVP 历史拼进 prompt。
- 聊天驱动的扫描重跑 / 结论写回 / 白名单操作。
- 关联（correlation）扫描的问答（多仓 repo_path 语义未定，见 §7）。

## 2. 架构：每轮一个 workflow（已定）

仓内零 signal/update 长活 workflow 先例，跨请求状态的既有范式是"磁盘 + 每任务一 workflow"（topology 先例）。聊天每轮 = 一个短 workflow，历史由 web 显式传入 Input：

```
前端 ChatPanel ──POST 发问──▶ web api/chat.py ──▶ chat_manager
   ▲                              │  ① 校验(权限/inflight/轮数上限/长度)
   │ SSE 进度+轮询                │  ② chat_store 追加 user turn（原子写）
   │                              │  ③ start_workflow(ReportChatWorkflow, id=chat-{ws}-{scan}-{user}-{n})
   │                              ▼
   │                     temporal queue: supernova-chat-web（新，第 4 个 Worker）
   │                              ▼
   └──────────────── worker activity：PromptManager 组 prompt（系统头+报告导航+历史窗口+本轮问题）
                          → run_claude_prompt(tool_policy="readonly-code",
                                              allowed_roots=[repo_path, scan_dir],
                                              cwd=scan_dir)
                          → 追加 assistant turn + usage/cost 到 chat_store
                          → 工具活动逐条追加 tool-audit.ndjson（SSE 源）
```

选每轮一 workflow 的理由：worker 崩溃只损单轮（maximum_attempts=1 不重烧）；历史落盘天然恢复；完全套 TopologyAnalysisWorkflow 模板；历史拼 prompt 前缀稳定，GLM provider 端 cache 友好。

## 3. 决策定版

| 决策点 | 定版 | 理由 |
|---|---|---|
| workflow 粒度 | 每轮一个 | §2；长活 workflow 需自建 signal/心跳/生命周期，风险不成比例 |
| task queue | 新独立 `WEB_TASK_QUEUE_CHAT="supernova-chat-web"`，worker runner.py 第 4 个 Worker | 聊天单轮 60–180s，挂 bb 队列会挤占扫描 workflow 槽（每 Worker max_concurrent=4）；runner 三 Worker 结构易扩 |
| 工具面 | **强制** `tool_policy="readonly-code"` + `allowed_roots=[repo_path, scan_dir]`，双引擎同档 | openai 默认工具面含 bash/write_file 且 allowed_roots 默认空=放行，聊天绝不可走默认；readonly 档两引擎现成（Topology 已验证） |
| cwd | scan_dir（报告就在手边，agent 按需 Read deliverables） | prompt 不整份塞报告（大报告爆 token），给路径导航 |
| 会话归属 | 每（scan, 用户）私有一个会话，存 `<scan_dir>/chat/<safe_username>.json` | 避免多成员互串上下文；随 scan_dir 删除、鉴权天然复用 workspace_member；username 做 sanitize（去 `/\..` 等，SSO nick 可能含特殊字符） |
| 历史传递 | web 读 store 组 history 列表传入 Input；worker 只追加 assistant turn | 输入即快照，worker 无需回读 store 判并发；inflight=1 守卫保证写者唯一 |
| 成本归属 | chat_store 自记逐轮 usage/cost（Topology 先例），**不进 session.json** | 不污染扫描成本口径；展示层前端渲染 |
| 模型档 | medium 默认 | 报告解读需一定推理力；env 可调 |
| 位置 | workflow+activity 放 `packages/multi`（Topology 同包同模式）；store 放 `core/services/chat_store.py`（web 与 worker 共用，Topology store 在 core 同理） | multi 已是"web 触发分析型 workflow"宿主；core 无 agent import，web 引用不违守护 |

## 4. 护栏（web 读 env 组进 Input，worker 不读 env；对齐 multi/shared.py 约定）

| env | 默认 | 语义 |
|---|---|---|
| `SUPERNOVA_CHAT_ENABLED` | `"1"` | 总开关；`"0"` 时端点 404，成本 kill-switch |
| `SUPERNOVA_CHAT_MODEL_TIER` | `medium` | 传 run_claude_prompt model_tier |
| `SUPERNOVA_CHAT_AGENT_MAX_TURNS` | `30` | 单轮 agent 工具循环上限（对齐 verdict agent 档） |
| `SUPERNOVA_CHAT_TURN_TIMEOUT_SECONDS` | `300` | 单轮 wall-clock：activity `asyncio.wait_for` 先超时写终态，workflow activity start_to_close=+60s 兜底 |
| `SUPERNOVA_CHAT_SESSION_TURN_LIMIT` | `50` | 每会话轮数硬顶；达顶只读，可 DELETE 重开 |
| `SUPERNOVA_CHAT_HISTORY_WINDOW` | `20` | 拼 prompt 的最近 N 轮窗口（更早的不进 prompt 但留 store） |
| `SUPERNOVA_WORKER_CHAT_MAX_CONCURRENT` | `2` | worker 第 4 个 Worker 的 max_concurrent_workflow_tasks（worker 侧直读） |

- 每用户 inflight=1：web 侧守卫，inflight 未收口再发问 409（确定性 workflow_id `chat-{ws}-{scan}-{user}-{turn_no}` 天然防重复提交）。
- `RetryPolicy(maximum_attempts=1)`：失败不重试（防重复烧 LLM），用户手动重发。
- 问题长度上限 4000 字符（422）；Input 体积可控（20 轮 × 数 KB ≪ temporal 4MB 消息上限）。
- env 容错契约对齐 `get_max_concurrent`：畸形/<1 回落默认 + warning 不 crash。

## 5. Prompt 设计（`prompts/chat_report_qa.txt`，新模板）

- 任务头：漏洞报告问答助手；只读分析；**答案必须带 file:line 引用，读不到/仓库里不存在就明说，禁止编造**；语言跟随全局语言约束（narration 默认 zh，不动）。
- 上下文导航（路径清单，非内容）：`deliverables/{track}/report_data.json`、报告 md、`scan-config.yaml`、`repo-snapshot.json`、repo 根路径、scan 类型/仓库名。
- 历史块：最近 `HISTORY_WINDOW` 轮 `用户:/助手:` 逐字转写（store 里的原文）。
- 本轮问题插值。
- **不 @include 任何确定性层产物**（守 CLAUDE.md 铁律；本功能非检测轨，报告 md/json 是已交付用户的成品，作为导航目标无独立性问题是另一回事——但中间产物一律不给）。
- worker 侧 PromptManager 加载（multi activity 既有 `parents[5]/prompts` 派生），worker 容器已 COPY prompts。

## 6. 改动面

- **core**：`services/temporal_infra.py` +`WEB_TASK_QUEUE_CHAT`；`services/chat_store.py`（纯 JSON 原子读写：append_turn / get_session / reset / inflight 标记）。
- **multi**：`pipeline/workflows.py` +`ReportChatWorkflow`（Input dataclass：scan_dir/repo_path/question/history/turn_no/provider_config/model_tier/max_turns/timeout_seconds）+ activity（状态机 queued→running→completed/failed/timeout/cancelled 写 store + status guard 防晚到复写，照抄 Topology）。
- **worker**：`runner.py` 第 4 个 Worker（workflows=[ReportChatWorkflow]，queue=chat，max_concurrent env）。
- **prompts**：`chat_report_qa.txt`。
- **web**：`components/chat_manager.py`（提交/inflight 守卫/取消，照抄 topology_analysis.py）；`api/chat.py` 端点（scan-scoped，`Depends(workspace_member)` 同 scans.py 口径）：`GET/POST/DELETE /api/workspaces/{ws}/scans/{id}/chat` + `POST .../chat/cancel` + `GET .../chat/events`（SSE，tail `chat/tool-audit.ndjson`，`build_verify_events_response` 式）；app.py 挂路由。
- **前端**：`src/components/chat/ChatPanel.tsx`（ReportTab 右侧内嵌可折叠；消息列表 react-markdown 渲染 + 输入框 + 进度事件行 + 逐轮 cost 小字 + 轮数余量 + 达顶只读/重开钮）；`useChat.ts`（SWR + useEventSource 复用）；zh/en `chat.*` 词条。
- **`.env.example`**：新 env 全量登记。
- **文档**：`docs/architecture/overview.md` 补一段（web→chat queue→worker 通路）。

## 7. 边界与已知取舍

- **correlation 扫描不可问答**：session.json 无单一 repo_path，MVP 直接 400 明示不支持（P1 定义多仓语义再放开）。
- **openai 引擎 readonly 档无子代理**（subagent_run=None）：聊天 MVP 单 agent 自主 grep 足够。
- **readonly 档不能跑命令**：不能"验证 PoC 能否打通"这类问题只能静态推理回答——如实告知用户，属安全取舍。
- **worker 重启于轮中**：maximum_attempts=1 → 该轮标 failed，历史无损，用户重发即可。
- **temporal 不可用**：503（对齐扫描提交路径 `_check_temporal`）。
- **并发写 store**：web（user turn，提交前）与 worker（assistant turn，收口时）时序天然错开 + inflight=1 守卫 + 原子写，无锁。
- **test_web_never_runs_agents 不动**：chat_manager/api 只 import core 的 store + temporal client，零 prompts/runner import。

## 8. 测试

- **multi**：workflow/activity 单测（stub `run_claude_prompt`）：readonly policy + allowed_roots 传递断言、completed/failed/timeout/cancelled 四态 + status guard、usage 落 store、prompt 组装含历史窗口裁剪。
- **core**：chat_store 原子写/追加/reset/sanitize 单测。
- **web**：chat_manager（inflight 409/轮数上限 422/长度上限/ENABLED=0 404/provider_config 透传）+ api 测试（workspace_member 门、scan 不存在 404、SSE 端点冒烟）。
- **worker**：runner 注册测试（第 4 Worker + queue 常量）。
- **前端**：vitest ChatPanel（渲染历史/发送乐观态/进度事件/错误/达顶只读）+ locales 完整性。
- **守护**：`test_web_never_runs_agents` 保持绿。

## 9. 分期

- **P0（本 spec 范围）**：上述全部。
- **P1 备选**：结构化 messages 历史入 provider（openai `Runner.run` 收 list input，anthropic SDK resume）、逐 token 流式、Evidence/Deliverables tab 入口 + 全局抽屉、correlation 多仓问答、会话摘要压缩（超窗口轮次摘要替代丢弃）。
