# 白盒双轨合并后对抗性审查阶段（adversarial-review）—— 设计 spec

日期：2026-09-10
状态：已确认（用户口径锁定）
分支：feat/fork-py

## 0. 背景与动机

当前白盒误报控制内嵌在判定 agent 自身（chain_verdict 的证伪式读码验证、
vuln prompt 的 false_positives_to_avoid），**没有独立的对抗性审查层**：

- `docs/openant-paper-notes.md` §5 明确记录：OpenAnt 第 5 阶段「对抗性验证」
  （攻击者模拟 + 多路径探索 + 受害者要求）在 supernova **无对应**，是其降假阳性的
  核心利器（评估中 49.5% 候选被排除，主因：输入清洗实际阻断、认证屏障无法绕过、
  漏洞只影响攻击者自己、平台保护机制）。
- 优化项 O-3（同文 §6，2026-06-26 提出）至今未落地；2026-08-27 的 chain_verdict
  多轮化是「读码验证」，不是「对抗性反驳」。
- 双轨合并（`dual_track_merger.py` verdict OR）是保守并集，一轨 safe + 一轨
  vulnerable 直接保留 vulnerable，无任何下游复核；合并产物直接进富化与报告。

用户决策（2026-09-10 口径锁定）：在 GitNexus 轨与 LLM 轨**合并之后**新增
对抗性审查阶段——专职反驳漏洞证据，想办法证明是误报；**无法反驳才放行**。
反驳前后状态与反驳原因全量落盘。仅白盒阶段，与黑盒无关。

## 1. 口径表（用户口径锁定）

| 决策点 | 结论 |
|---|---|
| 审查范围 | 全部白盒 vuln 类（injection/xss/ssrf/authz/auth），读五类 SSOT `{vc}_exploitation_queue.json`（auth 走 llm-only 透传分支也在 SSOT 内，天然覆盖，无需单独接线） |
| 插入位置 | `run_merge_dual_track_queues` 之后、`run_gn_finding_enrichment` 之前（vulnerability-analysis 相）；反驳掉的卡不再消耗富化/POC/polish 的逐卡 LLM 成本 |
| fatal 语义 | **non-fatal**（对齐富化层：审查挂了保守放行，不毁扫描） |
| 组织形态 | POC 生成同款（`_write_agent_pocs` 骨架）：sink 文件聚类分片 + 片间并发（scan 级共享 Semaphore），每片一次多轮 agent（`run_gitnexus_verdict_agent` 载体，可 grep/read 回读源码） |
| 审查框架 | **固定 7 维度**逐项反驳（§3），维度枚举代码/prompt/schema 三处锁定，agent 不得自创维度 |
| 审查档位 | 全部 positive 卡逐卡过 gate + 预算护栏（超限保守放行 + `unreviewed` 标记） |
| 反驳成功处置 | **剔出 queue SSOT + 归档留痕**：`dismissed_findings.json` 新档 `dismissed_at_stage="adversarial-review"`（带失败维度与证据）；不进报告 |
| 失败维度标记 | `failed_dimensions[]` **只挂产物**（`adversarial_review.json` record + dismissed 归档条目），供后续按维度筛选；`BaseVulnerability` **零侵入**，queue 存活卡不带任何审查字段（YAGNI：筛选拒绝跨文件 join 的需求不存在） |
| 降级语义 | 片失败/JSON 打捞失败/预算超限 → `unreviewed` 保守放行（审查通道失败 ≠ 判了误报，对齐 unadjudicated 哲学） |
| checkpoint | 产物即 checkpoint：`adversarial_review.json` 已有终态记录（survived/refuted）的卡不重审，重试只跑残余 |
| 默认开关 | `SUPERNOVA_ADVERSARIAL_REVIEW_ENABLED`，默认 `"1"`（经 `ws_getenv` 支持 per-workspace 覆盖） |
| 防过驳（over-refutation）防线 | ①**证据存在性机器校验**（§6 L4：refuted 证据的文件须在 repo 存在 + snippet 须能匹配到，纯确定性零 LLM，打幻觉证据）②**prompt 姿态校准**（§4.1：诚实怀疑者非辩护人，survived 是正常结论、驳回是需铁证的例外，维度判据从严写陷阱反例）。低置信 refuted 不做特殊处理（confidence 自评校准差、防护空间被 L3/L4 挤压，2026-09-11 已裁 YAGNI）；dry-run 首跑模式不做 |
| refuted 可见入口 | **web 扫描详情页新 Tab**（§4.8）：读 adversarial_review.json 全量透传，三态徽标 + failed_dimensions 筛选，展开看反驳论证与证据；白盒报告不展示被驳回项（维持 §9） |

## 2. 架构定位与铁律关系

```
WhiteboxScanWorkflow（vulnerability-analysis 相，现状 → 改造后）

  run_merge_dual_track_queues (fatal, 2min)          ← 五类 SSOT queue 成型
      │
      ▼
  ★ run_adversarial_review (non-fatal)               ← 本设计新增
      │  逐类：positive 卡 → 已审跳过 → sink 聚类分片
      │  → 片 agent（固定维度逐卡反驳）→ validate
      │  → refuted 卡剔出 queue + append_dismissed
      │  → adversarial_review.json 落盘
      ▼
  run_gn_finding_enrichment (non-fatal)              ← 之后链路零改动
      ▼
  run_endpoint_enrichment → run_assemble_dataflow_view
      ▼
  attack-chain 相 → reporting 相（assemble/polish/export）
```

**与双轨独立性铁律的关系**：本阶段在**合并之后**消费 SSOT，是独立的第三
阶段，不是 LLM 轨 vuln agent——不把确定性产物喂进 LLM 轨 prompt，双轨
生成期的独立性不受影响（合并后消费 queue 卡的先例：跨仓裁决
`prompts/cross-repo-adjudication.txt`、GN 富化、POC 生成，均已在线上）。

**剔除 both 卡是新语义**：`dual_track_merger.py:291-302` 只对 GN-only 的
safe 卡有兜底丢弃；本阶段反驳掉 both/llm-only 卡属于刻意新增的报告准入门，
由高门槛 validate（§6）约束误杀面。

## 3. 固定审查维度框架

反驳不是自由探索，而是固定维度清单逐项检查。维度枚举在代码常量、prompt、
输出 schema 三处锁定。

| 维度 key | 适用类 | 反驳含义（成立 = 该 finding 在此维度被驳倒） |
|---|---|---|
| `defense_effective` | injection/xss/ssrf | 存在真实有效防御：sanitizer/encoding 实现匹配该 slot 且路径上生效、无 post-sanitize concatenation |
| `unreachable` | 全部 5 类 | 路径不可达：路由未注册 / 参数未绑定 / 死代码 / 前置条件不可满足 |
| `attacker_uncontrolled` | injection/xss/ssrf | sink 实参不受攻击者控制：来源是常量 / 服务端生成 / 枚举白名单 |
| `self_impact` | 全部 5 类 | 自影响无第三方受害者：攻击者只能影响自己的数据（OpenAnt 受害者要求） |
| `platform_protection` | 全部 5 类 | 平台级兜底：框架默认转义 / 中间件统一防护 / 同源策略 / 云访问控制 |
| `authn_enforced` | **auth 专用** | 认证实际存在且该路径不可绕过（authz 卡默认在认证之后，此维度不适用） |
| `authz_guard` | **authz 专用** | 角色 / owner 检查实际覆盖该操作（对齐 authz judge 现有 rejected 语义 'ownership guard dominates sink via middleware X'） |

适用维度数：taint 三类 5 个（defense_effective/unreachable/attacker_uncontrolled/
self_impact/platform_protection）、auth 4 个（unreachable/self_impact/
platform_protection/authn_enforced）、authz 4 个（unreachable/self_impact/
platform_protection/authz_guard）。

**多路径硬约束**（O-3 借鉴）：agent 必须对片内每张卡**逐个尝试全部适用维度**
才能下 `survived`；不允许只查一两个维度就宣布无法反驳。

## 4. 组件设计

### 4.1 prompt `prompts/adversarial-review.txt`

结构对齐 `cross-repo-adjudication.txt`（角色/目标/维度清单/输出格式四段）：

- `<role>`：Adversarial Reviewer——**诚实怀疑的对抗审查者**（honest skeptic），
  从受限远程攻击者视角审视：任务是**努力反驳、诚实汇报**，不是「必须驳倒的
  辩护人」。只读工具（grep/read），禁 Task/写文件。
- **姿态校准硬规则**（防激励偏置 → 防过驳）：`survived` 是**正常且常见的
  结论**（not a failure）；`refuted` 是需要 file:line 铁证的**例外**。禁止
  为驳回而驳回——找不到具体代码证据就诚实判 survived；证据只允许来自本次
  真实读到的代码，禁止凭记忆/推测/卡内声称构造。
- `<dimensions>`：§3 七维度清单逐条展开（每维度的反驳判据、什么证据算
  成立），并按 vuln_class 标注适用集；**每维度附「不成立的常见陷阱」反例**，
  判据从严——例：`platform_protection` 不得拿「框架默认转义」驳回走了
  转义豁免通道的 sink（`dangerouslySetInnerHTML` / `v-html` / `|safe`
  filter / `innerHTML` 赋值）；`defense_effective` 须确认防御匹配该 slot
  且 sanitize 后无再拼接。
- `<methodology>`：逐卡流程——读卡（sink/endpoint/数据流声称）→ 逐适用维度
  尝试反驳（每维度真实读码，证据必须是自己读到的 file:line，不得引用卡内声称）
  → 汇总裁定。**负面结论与正面结论同举证强度**（借鉴跨仓裁决 Rules）：
  判 refuted 的每个维度必须有 file:line 铁证；「看起来不像」「觉得悬」不算。
- `<output-format>`：JSON schema（§4.2），片内逐卡一裁定，不跳不并。
- 变量：`{{VULN_CLASS}}` / `{{REPO_ROOT}}` / `{{FINDING_CARDS}}`（该片卡 JSON）。

### 4.2 agent 输出 schema（ADVERSARIAL_REVIEW_SCHEMA）

```json
{
  "cards": [
    {
      "vulnerability_id": "INJ-...",
      "review_verdict": "refuted | survived",
      "dimension_results": [
        {
          "dimension": "defense_effective",
          "rebutted": true,
          "reason": "sanitizer X 覆盖该 slot 且无 post-sanitize concat",
          "evidence": [{"location": "app.js:88", "snippet": "escape(...)"}]
        },
        {
          "dimension": "unreachable",
          "rebutted": false,
          "reason": "路由已注册且参数绑定",
          "evidence": [{"location": "routes.js:12", "snippet": "app.post('/contributions', ...)"}]
        }
      ],
      "failed_dimensions": ["defense_effective"],
      "rebuttal_reason": "（refuted 必填）完整反驳论证：为何误报",
      "survival_reason": "（survived 必填）各适用维度为何都驳不倒",
      "confidence": "high | medium | low"
    }
  ]
}
```

校验不变量（validate 层强制，§6）：`failed_dimensions` 非空 ⟺ 
`review_verdict="refuted"`；refuted 的每个 failed 维度在 `dimension_results`
里有对应 `rebutted=true` 且 evidence 至少一条含 file:line。

### 4.3 activity `run_adversarial_review`

骨架对齐 `write_agent_poc`（`packages/whitebox/src/supernova_whitebox/pipeline/activities.py:2367`）：

1. `ensure_audit_session` → `_get_paths` → `track_step`（phase slug
   `adversarial-review`）。
2. 开关关闭 → 直接 return（queue 原样）。
3. 五类并行（对齐 POC 类间 gather）：读 `{vc}_exploitation_queue.json` →
   positive 过滤（`verdict != "not_vulnerable"` 的卡；现状 queue 里理论无
   非漏洞卡，防线保留）→ checkpoint 过滤（`adversarial_review.json` 已有
   survived/refuted 终态记录的卡跳过）→ 预算护栏计数。
4. 分片：**复用 `_sink_file_key`（activities.py:2388）+ `_group_poc_targets`
   同款聚类逻辑**（sink 文件聚类 → 同 key 相邻装片 → 超限裂片，输入序稳定；
   authz/auth 无 sink 归 unknown 桶同类聚片，恰好共享 handler/middleware 读码
   语境）。分片函数是否与 POC 共用一份实现，由实施计划定（倾向抽公共函数，
   两处调用）。
5. 片 agent：`prompt_manager.load_sync("adversarial-review", variables={...})`
   → `run_gitnexus_verdict_agent`（structured_output_schema=
   ADVERSARIAL_REVIEW_SCHEMA，max_turns=旋钮，agent_name=
   `adv-review-{vc}-{idx:02d}`），scan 级 `asyncio.Semaphore(旋钮)` 限流。
6. 片产出打捞兜底（对齐 POC：structured_output=None 时从 text 裸 JSON/花括号
   平衡段解析，不改写内容；救不回该片 `unreviewed`）。
7. validate（§6）→ 类级单点写盘三次原子写：剔卡后的 queue
   `{"vulnerabilities": [...]}`、追加后的 `adversarial_review.json`、
   `append_dismissed` 归档（每 refute 一条 append，复用读-合并-原子写）。
8. PentestError/Exception 双 `classify_error_for_temporal` 转
   `ApplicationFailure`（对齐既有 activity 骨架）。

### 4.4 产物 `intermediate/adversarial_review.json`

```json
{
  "summary": {
    "total": 23,
    "refuted": 4,
    "survived": 17,
    "unreviewed": 2,
    "by_class": {"injection": {"total": 8, "refuted": 2, "survived": 6, "unreviewed": 0}, "...": {}}
  },
  "records": [
    {
      "vuln_class": "injection",
      "finding_id": "INJ-0003",
      "reviewed_at": "2026-09-10T12:34:56+08:00",
      "before": {
        "title": "SQL injection in /contributions",
        "verdict": "vulnerable",
        "merge_source": "both",
        "confidence": "high",
        "source_track": "llm"
      },
      "review_verdict": "refuted",
      "dimension_results": [ ... ],
      "failed_dimensions": ["defense_effective"],
      "rebuttal_reason": "...",
      "survival_reason": null,
      "evidence": [{"location": "app.js:88", "snippet": "...", "note": "..."}],
      "after": {"action": "dismissed", "dismissed_stage": "adversarial-review"}
    }
  ]
}
```

`before` = 反驳前状态快照（卡的关键判定字段）、`after` = 处置结果
（`kept|dismissed`）——**反驳前、反驳后、反驳原因三类信息全落盘**（用户口径）。
survived 卡 `after.action="kept"`、`failed_dimensions=[]`。重跑幂等：已终态
卡不重审，records 按 finding_id 覆盖合并（同 ID 后写覆盖，对齐 dismissed
归档语义）。

### 4.5 归档（复用 dismissed_archive）

refuted 卡逐条 `append_dismissed`（`packages/core/src/supernova_core/services/dismissed_archive.py`）：

- 新档 `dismissed_at_stage="adversarial-review"`。
- `dismiss_reason` = `"{failed_dimensions 逗号连接}: {rebuttal_reason 摘要}"`，
  条目 `evidence` 保留 file:line 证据——**归档侧天然可按维度筛选**（用户口径：
  失败维度标记字段）。
- 跨仓裁决已有 dismissed 消费方（`packages/multi/.../orchestrator.py` 建
  `dismissed_by_service`），新档自动进入其视野，无需改动。

### 4.6 旋钮（`packages/core/src/supernova_core/config/concurrency.py` 模式）

| env | 默认 | 语义 |
|---|---|---|
| `SUPERNOVA_ADVERSARIAL_REVIEW_ENABLED` | `"1"` | 总开关（ws_getenv，per-workspace 可覆盖） |
| `SUPERNOVA_ADVERSARIAL_REVIEW_CONCURRENCY` | 4 | scan 级共享 Semaphore（类间+片间统一限流，防 429 放大） |
| `SUPERNOVA_ADVERSARIAL_REVIEW_MAX_TURNS` | 40 | 片 agent turn 预算（对齐 POC 片换算：≤3 卡/片 × ~9 turns/卡 + 余量） |
| `SUPERNOVA_ADVERSARIAL_REVIEW_SHARD_MAX_CARDS` | 3 | 片大小上限（同 sink 文件超限裂片） |
| `SUPERNOVA_ADVERSARIAL_REVIEW_MAX_AGENTS` | 50 | 预算护栏：超出的卡 `unreviewed` 保守放行（对齐 CHAIN_VERDICT_MAX_AGENTS 模式） |

容量铁律（对齐 CLAUDE.md chain_verdict 教训）：改片大小/turn 预算/并发度时，
同步重估 activity 窗口（总量 ≈ 片数 ÷ 并发 × 单片耗时）；activity 窗口初值
20min（对齐富化层窗口），实施时按首轮实测校准。畸形值回退默认 + warning
不 crash（concurrency.py 既有模式）。

### 4.7 接线清单（动点）

1. `packages/whitebox/src/supernova_whitebox/pipeline/activities.py`：
   新 activity + 分片复用 + validate 调用 + 三处写盘。
2. `packages/whitebox/src/supernova_whitebox/pipeline/workflows.py`：
   merge 之后插入，non-fatal 包裹（`is_cancellation` 放行 +
   `_activity_not_registered_hint` fail-fast + `log_info_activity` 降级，
   样板 :637-662），窗口 20min + `retry_for("standard")`。
3. `packages/whitebox/src/supernova_whitebox/worker.py`：import + activities
   列表两处（漏注册 = 静默降级，测试钉死）。
4. `packages/whitebox/src/supernova_whitebox/pipeline/step_intents.py`：
   `PHASE_STEPS["vulnerability-analysis"]` 加 `StepSpec`。
5. `prompts/adversarial-review.txt`（PromptManager 加载，parents[5]/prompts
   路径模式）。
6. `packages/core/src/supernova_core/models/agents.py`：
   `AGENT_PHASE_MAP["adversarial-review"] = "vulnerability-analysis"`
   （agent 记账聚合；agent_name 为自由字符串 `adv-review-*`，不进 AgentName
   枚举——对齐 gn-enrich-* 先例）。

validate 层 + schema + 旋钮落 `packages/core`（对齐 collectors/poc.py 模式：
POC_AGENT_OUTPUT_SCHEMA/validate_pocs 在 core，activity 在 whitebox 调用）。

### 4.8 web 扫描详情页「对抗审查」视图（refuted 可见入口）

**后端**（`packages/web/src/supernova_web/api/scans.py`）：

- 新端点 `GET /api/workspaces/{ws}/scans/{scan_id}/adversarial-review`，照抄
  `scan_dataflow` 端点壳（:516-522）+ `_dataflow_view_for` 直读模式
  （:232-250）：`resolve_intermediate(scan_dir/"deliverables"/WHITEBOX_SUBDIR,
  "adversarial_review.json")` → 缺失/坏 JSON 一律 `HTTPException(404,
  "... not generated")`，存在则 `json.loads` **全量透传**（不经
  DeliverablesReader——端点返 JSON 非 text/plain 截断）。
- 权限 `workspace_member`（scans.py 模块约定，:3-4）。web 只读 JSON 文件，
  零 agent、零 temporal、零写盘——不触 `test_web_never_runs_agents.py`
  红线（import 仅 `supernova_core.utils.paths`，combined_report_renderer
  已有同款先例）。
- 不做 scan_type 条件拒绝（黑盒/correlation 扫描缺产物自然 404 → 前端
  显空态，比 422 分支简单）。

**前端**（`packages/web/frontend`，六文件动点对齐 Tab 新增样板）：

- 新 Tab 路由段 `adversarial`（单词段，对齐 router.tsx:136 约定）：
  `SCAN_TABS` 加行（ScanDetail.tsx:24-31）+ router 子路由（router.tsx
  lazyWithRetry + per-scan children）+ `AdversarialReviewTab.tsx`。
- 数据：`useSWR` 一次性拉取（终态产物无轮询，照抄 DataFlowTab.tsx:33-36）。
- UI 结构（筛选照抄 DataFlowTab SummaryBar 模式——本地 useState + useMemo
  从数据派生选项 + 原生 select；卡片照抄 CorrelationTab 的
  AdjudicationCardView :291-357 同构样式）：
  - 顶部 summary 计数条（total/refuted/survived/unreviewed，全量口径
    不随筛选缩水）；
  - 两个筛选：`review_verdict` 三态、`failed_dimensions`（选项从
    `records.flatMap(r => r.failed_dimensions)` 派生）；
  - records 卡片：verdict 徽标 + `before` 快照（反驳前状态）+
    `dimension_results` 逐维度列表（rebutted 标记 + reason）+ `evidence`
    file:line 列表 + `rebuttal_reason`/`survival_reason` 段落。
- i18n：zh/en 双侧 camelCase 键（kebab→camel 陷阱，memory
  `web-theme-system-architecture`；`locales.test.ts` 锁 key 集合一致）。

**前端文件动点清单**：`types.ts`（AdversarialReview/ReviewRecord/
DimensionResult 接口）/ `client.ts`（fetchAdversarialReview）/
`router.tsx` / `ScanDetail.tsx` / `AdversarialReviewTab.tsx`（新建）/
`zh.json` + `en.json`。

**协调注意点**：同日在途工作「接口证据页」（spec
`2026-09-10-api-evidence-matrix-design.md` + plan，core 聚合器已在
工作区未提交）同样要加 Tab + 端点，撞 `ScanDetail.tsx` SCAN_TABS 与
`ScanDetail.test.tsx:44` 的 tab 总数断言（`toHaveLength(6)`）——两工作
落地时协调，后落地者按实际 tab 数更新断言。

## 5. 数据流（单类内）

```
{vc}_exploitation_queue.json
  → 读卡 → positive 过滤 → checkpoint 过滤（已有终态跳过）→ 预算计数
  → sink 文件聚类分片（≤3 卡/片，稳定序）
  → 片 agent 并发（Semaphore 限流，固定维度逐卡反驳）
  → structured_output 优先 / text 打捞兜底 / 双失败 → 该片 unreviewed
  → validate：幻觉 ID 拒收（valid_ids 限片内）+ refuted 证据门槛强制
  → gather 后类级单点写盘 ×3（原子写）：
      queue（剔卡后）+ adversarial_review.json（records 追加）+ dismissed 归档
```

## 6. 校验与错误处理

**validate_review（对齐 validate_pocs L0-L3 模式）**：

- L0 归一：verdict/dimension 枚举宽容归一（大小写、别名映射到规范枚举）。
- L1 schema：pydantic 校验卡片结构。
- L2 幂等防幻觉：`vulnerability_id` 不在片内 valid_ids → 拒收整卡（agent
  幻觉返回别片 ID 不越片生效）。
- L3 **反驳高门槛**：`review_verdict="refuted"` 但 `failed_dimensions` 为空、
  或任一 failed 维度缺 file:line 证据、或 dimension_results 无对应
  `rebutted=true` → **拒收降级为 survived（零维度失败、带拒因记账）**——
  宁可漏反驳不误杀（防误降级优先于防误报，对齐 implementation-review.md:513
  的 over-seed 原则）。
- L4 **证据存在性校验**（防幻觉证据，纯确定性零 LLM，2026-09-11 过驳风险
  分析后加）：refuted 卡的每条 evidence——`location` 的文件部分相对
  `repo_root` 必须真实存在；`snippet` 归一化空白（strip + collapse
  whitespace）后必须能在该文件内容中子串匹配到。任一失败 → 整卡降级
  survived + 拒因记账（对齐 L3 降级语义）。函数签名带
  `repo_root: Path | None`，None 时跳过本层（测试/离线复用友好）。

**降级矩阵**：

| 情形 | 处置 |
|---|---|
| 片 agent 抛错 | 该片卡 `unreviewed`，不炸类（对齐 POC 诚实缺失） |
| structured_output=None 且打捞失败 | 同上 |
| 预算护栏超出 | 未开审的卡 `unreviewed` 保守放行 |
| validate 拒收 refuted（L3 证据门槛不过 / L4 存在性校验失败） | 降级 survived + warning 记账 |
| LLM 全不可用（stub） | 全部 unreviewed，queue 原样（审查是增强层，不阻塞） |
| Temporal 取消 | workflow 层 `is_cancellation` 直接 raise（铁律：吞掉=幽灵扫描） |
| 开关关闭 | activity 直读 return，零产物零改动 |

`unreviewed` 卡留在 queue 进报告（保守放行），在 adversarial_review.json
records 里有 `review_verdict="unreviewed"` + `after.action="kept"` 留痕。

## 7. checkpoint / resume

产物即 checkpoint（比 verdict_checkpoint 指纹简单一档，语义够用）：

- 已终态（survived/refuted）卡的判定**不重审**——重试/重跑只对残余卡重新
  分片执行（分片在过滤之后，对齐 POC「回炉 only_ids 可复算」模式）。
- `unreviewed` 不算终态：预算放开/故障恢复后重跑会补审。
- queue 剔除写回与 records 追加在同一 activity 尾部落盘，崩溃窗口内最坏
  情况 = 重复审查部分卡（幂等覆盖，无害）。

## 8. 测试计划（TDD）

- **validate_review**：枚举归一 / 幻觉 ID 拒收 / refuted 无证据降级 survived /
  failed_dimensions 与 verdict 一致性不变量 / dimension 适用集校验（auth 卡
  返回 authz_guard 维度 → 拒收或忽略，按适用表）/ **L4 证据存在性校验**
  （location 文件不存在 → 降级；snippet 归一化后匹配不到 → 降级；
  `repo_root=None` 跳过本层；survived 卡的证据不做存在性要求）。
- **分片**：sink 聚类复用逻辑的适用性（若抽公共函数则改两处调用方测试）。
- **产物 schema 与幂等**：records 同 ID 覆盖合并 / 重跑不重审（终态过滤）/
  unreviewed 卡重跑补审 / summary 计数与 records 一致。
- **剔除写回**：refuted 卡从 queue 消失、survived/unreviewed 卡保留、卡序
  稳定；queue 写回后 VulnerabilityQueue 可重新解析。
- **归档**：`dismissed_at_stage="adversarial-review"` 条目字段完整
  （含 failed_dimensions 与证据）、与既有 GN/LLM 档共存合并。
- **接线契约**：worker 注册（对齐 `test_worker_registers_authz_judge.py`
  钉死模式）/ workflow 步骤存在性与顺序（merge 之后、gn-enrichment 之前）/
  step_intents StepSpec 注册。
- **web 后端**：`test_scans_adversarial_review.py`（照抄
  `test_scans_dataflow.py` 四用例：200 直读 / 404 缺产物 / tier fallback
  平铺 / 404 scan 不存在；fixtures 走 conftest `authed_client`）。
- **web 前端**：`AdversarialReviewTab.test.tsx`（msw + MemoryRouter +
  SWRConfig 独立 cache + i18n zh，照抄 DataFlowTab.test.tsx 骨架；筛选
  交互断言照 class-select 用例）；`ScanDetail.test.tsx` tab 数断言更新
  （注意与接口证据页在途工作协调，§4.8）；提交前本地 `npx tsc -b`
  （vitest 不查类型，memory `frontend-tsc-build-gates`）。
- **prompt**：变量渲染完整 / 不含确定性 hints 桥梁（对齐
  test_static_dataflow_hints_decoupling.py 的守护思路——本 prompt 只吃合并
  queue 卡与维度清单，本就无确定性层直连，守恒即可）。
- **旋钮**：畸形值回退默认 + warning / 开关关闭零行为。

## 9. 非目标与未来扩展

- **不做**：白盒报告附录展示被驳回项（web 详情页视图 §4.8 已是用户可见
  入口，dismissed 归档 + adversarial_review.json 可审计）；跨轨分歧对抗
  仲裁（spec 2026-08-27 §10 已裁 YAGNI，维持）。
- **不做**：黑盒侧任何改动（用户口径：与黑盒无关）。
- **未来可扩**：按 failed_dimensions 维度反哺 vuln prompt 的
  false_positives_to_avoid 清单（驳回原因→上游提示词进化，闭环但不自动——
  注意铁律：反哺目标只能是 GitNexus 轨规则或独立审查层，不得喂 LLM 轨
  prompt）。
