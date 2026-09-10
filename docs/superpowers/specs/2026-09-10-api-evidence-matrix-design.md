# 接口证据页（api evidence matrix）— 设计 spec

- 日期：2026-09-10
- 状态：已实现（2026-09-10，plan `plans/2026-09-10-api-evidence-matrix.md` 7 任务 TDD 全绿 + 真实 NodeGoat 扫描抽查通过；实现中发现 plan 代码 glob 前缀笔误 `deliverables/blackbox-runs/`——§3 本表路径为准：`blackbox-runs/` 与 `deliverables/` 平级，已修正）

## 1. 背景与需求

用户诉求：扫描完成后，**以 WEB 接口为维度**记录扫描证据——每个接口「为什么有问题、为什么没问题」，且**白盒阶段分析证据与黑盒验证证据独立成两栏**，落 web **独立证据页**（与报告页平级，不是报告页内的一节）。

现状：这些证据已全部存在于扫描产物中，但散落在十几个文件里、数据流向是「漏洞 → endpoints」（正向），没有「接口 → 证据」的倒排视图，web 上也没有接口维度的浏览入口。

## 2. 目标 / 非目标

**目标**

1. 新中间产物 `deliverables/api_evidence_matrix.json`：接口底册 + 每接口白盒/黑盒两栏证据 + coverage 标注。
2. 纯确定性聚合器（零新增 LLM 成本）：只读现有产物，不改扫描流程、不改任何现有产物 schema。
3. web 独立「证据」tab（与 report 平级）+ API endpoint；**旧扫描 lazy 回填**（首次请求时生成并落盘缓存）。
4. 挂不上接口的证据不丢弃，顶层 `unmatched` 可见（保守匹配，不硬凑）。

**非目标**

- 不做纯黑盒扫描（blackbox track）的独立接口底册——matrix 锚白盒 `entry_points.json`；纯黑盒扫描无此文件，matrix 为空并在顶层注明（后续可扩）。
- 不做 correlation 扫描的证据页（`CORRELATION_SCAN_TABS` 不加 evidence）。
- 不做每接口 LLM 总结（用户已确认走确定性聚合；证据原文直出）。
- 不区分「接口未进扫描范围」与「扫过无发现」——entry_points 本身就是 code_index 全量 adjudication 的产物，底册外的接口系统本来就不知道。

## 3. 现状锚点（实现时核对）

以下产物字段已在 NodeGoat 真实扫描（`workspaces/__legacy__/scans/NodeGoat-20260827-040049` 白盒 + `NodeGoat-20260820-135941` 黑盒 runs）实测验证：

| 产物 | 路径（scan_dir 相对） | 关键字段 | 角色 |
|---|---|---|---|
| 接口底册 | `deliverables/whitebox/intermediate/entry_points.json` | `adjudicated_entry_points[]: {func_block_id, verdict, entry_type, route, http_method, evidence, source}` | 全量接口清单 |
| 白盒 finding（结构化锚点） | `deliverables/whitebox/report_data.json` | `vulnerabilities[].endpoints[]: {method, path, role, auth, params, route_registered_at, source_location, sink_location}` | 漏洞→接口归属（多级兜底填充） |
| 白盒 finding（证据原文） | 同上 `vulnerabilities[]` + `intermediate/{vc}_gitnexus_queue.json` / `{vc}_exploitation_queue.json` | `evidence_chain / source_detail / witness_payload / verdict / mismatch_reason / sink_call / affected_parameters` | 「为什么有问题」 |
| 白盒安全结论 | `intermediate/{vc}_safe_vectors.json` | `vectors[]: {subject, defense_mechanism, location}`（authz 的 subject 是 "GET /profile" 式接口级描述） | 「为什么没问题」 |
| 白盒驳回 | `intermediate/dismissed_findings.json` | `dismissed[]: {ID, source_track, vuln_class, title, dismiss_reason, evidence, dismissed_at_stage}` | 近似接口级（title/位置） |
| 黑盒验证 | `blackbox-runs/run-*/deliverables/blackbox/intermediate/{vc}_exploit_verdicts.json` | `{vuln_class, accepted_ids, verdicts[]: {vulnerability_id, status, severity, impact, exploitation_steps[], proof_of_impact}, rejected[]}` | 黑盒实测证据 |

关联键链：黑盒 verdict `.vulnerability_id` → 白盒 finding ID → `report_data.vulnerabilities[].endpoints[]` → 底册 `route + http_method`。

管线挂载点：`packages/whitebox/src/supernova_whitebox/pipeline/activities.py` 的 `assemble_report` activity（`_build_report_data_initial` 落盘 `report_data.json` 之后）。

web 先例：`dataflow` tab（P5 数据流视图，`GET /{ws}/scans/{scan_id}/dataflow`，缺产物 404）——evidence endpoint 与之同构但 lazy 生成；correlation 产物「写在 deliverables/ 根（无 track 桶）」是跨 track 顶层产物的先例，evidence matrix 沿用。

## 4. 产物 schema

`deliverables/api_evidence_matrix.json`（deliverables 根，无 track 桶——含黑盒证据，跨 track 视角）：

```jsonc
{
  "schema_version": 1,
  "scan_id": "...",
  "generated_at": "ISO8601",
  "sources": { "entry_points": true, "report_data": true, "blackbox_runs": 1 },  // 缺哪个标哪个（前端提示证据不全）
  "endpoints": [{
    // 底册行
    "method": "GET",
    "path": "/allocations/:userId",        // 归一化后（见 §5）
    "raw_route": "/allocations/:userId",   // 底册原文
    "func_block_id": "app/routes/index.js:index:11",
    "entry_verdict": "confirmed",
    "entry_evidence": "Express route: app.get('/')",
    // 🟦 白盒栏（独立）
    "whitebox": {
      "findings": [{
        "id": "XSS-GN-01", "vuln_class": "xss", "severity": "high",
        "confidence": "high", "title": "...",
        "evidence_chain": "...", "witness_payload": "...",
        "verdict": "vulnerable", "mismatch_reason": "...",
        "params": ["userId (query)"], "auth_required": "isLoggedIn",
        "source_location": "...", "sink_location": "..."
      }],
      "safe": [{ "subject": "...", "defense_mechanism": "...", "location": "...",
                 "contains_live_probe": false }],
      "dismissed": [{ "ID": "AUTH-LLM-SAFE-01", "vuln_class": "auth",
                      "title": "...", "dismiss_reason": "...", "dismissed_at_stage": "llm-exploration" }]
    },
    // 🟧 黑盒栏（独立）
    "blackbox": {
      "verdicts": [{ "vulnerability_id": "INJ-VULN-01", "vuln_class": "injection",
                     "status": "exploited", "severity": "critical",
                     "impact": "...", "exploitation_steps": ["..."],
                     "proof_of_impact": "...", "run_id": "run-1" }],
      "rejected": [{ /* 验证被拒条目，字段以 verdicts 文件 rejected[] 实际产物为准 */ }]
    },
    // 覆盖标注
    "coverage": "findings"   // findings | defended | clean
  }],
  "unmatched": {
    "findings": [ /* 挂不上底册的白盒 finding（id+title+原因） */ ],
    "safe_dismissed": [ /* 提不出接口的 safe_vector/dismissed 原文（kind: "safe"|"dismissed"） */ ],
    "verdicts": [ /* 挂不上白盒 finding 或接口的黑盒 verdict */ ]
  }
}
```

coverage 语义（互斥，按优先级）：

- `findings`：whitebox.findings 非空（无论黑盒验没验）。
- `defended`：findings 空，但 safe / dismissed 非空（有「为什么没问题」的结论）。
- `clean`：底册里存在，但白盒/黑盒证据均未命中（已识别、扫描无发现）。

## 5. 归属匹配规则（保守，不硬凑）

1. **结构化优先**：`report_data.vulnerabilities[].endpoints[]` 的 `method+path` ↔ 底册 `http_method+route`。
2. **path 归一化**：`:param` / `{param}` / `<param>` / `*param` 统一为单段占位 `:param`；query string 剥离；尾部 `/` 归一（空 path 保持 `/`）。
3. **参数名无关匹配**：归一化后按「method 相同 + 段数相同 + 非参数段全等 + 参数段位置一致」匹配（`:userId` ≡ `:id`）。**歧义（同 method 下多个底册行同时命中）→ 该 finding 进 `unmatched`，不挂**。
4. **自由文本兜底**（safe_vectors.subject、dismissed.title）：正则提 `(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)?\s*/path`，方法缺失时视为任意方法（仅当 path 唯一命中一个 method 时才挂）；提不出接口的进 `unmatched.safe_dismissed`（原文保留，`kind` 区分来源，不丢）。
5. **黑盒**：verdict `.vulnerability_id` → 白盒 finding → 接口；白盒 finding 缺失（黑盒独立发现/ID 漂移）→ 尝试 verdict 自身文本提接口；再失败进 `unmatched.verdicts`。
6. **多 endpoint finding**（`endpoints[]` 多行）：每个命中接口都挂（role 字段保留 `trigger` / `reachable` 区分）。

## 6. core 聚合器

新文件 `packages/core/src/supernova_core/services/api_evidence_matrix.py`：

- `async def build_api_evidence_matrix(scan_dir: Path) -> dict`：纯读产物 → 返回 matrix dict。入口产物缺失（如纯黑盒扫描无 entry_points.json）返回 `{schema_version, scan_id, sources: {...}, endpoints: [], unmatched: {...}, note: "..."}`，不抛错。
- `async def write_api_evidence_matrix(scan_dir: Path) -> Path | None`：build + 落盘 `deliverables/api_evidence_matrix.json`。
- 单 finding 字段以 `report_data.json`（合并后 SSOT）为主；queue 独有证据字段（`witness_payload / mismatch_reason` 等）按 finding ID 从 intermediate queue 回查补充（queue 缺失容忍——字段留空）。

**管线挂载**：`assemble_report` activity 里 `_build_report_data_initial` 之后追加 `write_api_evidence_matrix`（同一 track_step 内，非 fatal——matrix 失败不挡报告，warning 即可；报告是根交付物，matrix 是衍生视图）。

## 7. web API

`packages/web/src/supernova_web/api/scans.py`：

```
GET /api/workspaces/{ws}/scans/{scan_id}/evidence-matrix   (workspace_member)
```

- 产物已存在 → 直接读返。
- 不存在但 scan 有 `deliverables/whitebox/report_data.json` → **web 进程内跑 `build_api_evidence_matrix`（纯确定性 JSON 处理，不起 agent，不违「web 零 agent 执行点」铁律，`test_web_never_runs_agents.py` 守护测试不受影响）**，落盘缓存后返回。写盘失败（只读挂载等）→ 降级只返数据不缓存。
- 两者皆无 → 404 `"evidence matrix not available"`（前端显示「该扫描无证据产物」空态）。

## 8. 前端证据页

- `SCAN_TABS`（`ScanDetail.tsx`）加 `{ value: "evidence", labelKey: "workspaceDetail.tabs.evidence" }`，置于 report 之后、deliverables 之前；`CORRELATION_SCAN_TABS` 不加。
- 路由：`router.tsx` per-scan 子路由加 `{ path: "evidence", element: <EvidenceTab /> }`（lazy chunk，对齐 ReportTab）。
- 新组件 `routes/WorkspaceDetail/EvidenceTab.tsx`：
  - **左列**：接口清单（method 徽标 + path + coverage 徽标 + findings/verdicts 计数），coverage / method 可筛选，默认 coverage=findings 在前。
  - **右侧**：选中接口的详情——白盒栏（蓝）/ 黑盒栏（橙）两栏布局，证据卡片直出原文：
    - 白盒-问题：title、severity/confidence、evidence_chain（数据流链）、witness_payload、verdict/mismatch_reason。
    - 白盒-安全：defense_mechanism、location、`contains_live_probe` 徽标。
    - 黑盒：status（5 档）、severity、impact、exploitation_steps（编号步骤）、proof_of_impact（等宽块）。
  - `unmatched` 非空时顶部提示条（「N 条证据未能关联到接口」可展开）。
  - 两栏空态文案区分：「白盒无发现」vs「黑盒未验证」（blackbox.verdicts 空）。
- i18n：`workspaceDetail.tabs.evidence` 等新键进词典（en/zh，注意 kebab→camel 转换陷阱）。

## 9. `contains_live_probe` 轻量识别

白盒 safe / dismissed 文本含黑盒实测特征时打标（发生在白盒 agent 探索内的顺手实测，归属白盒栏、仅打标记）：关键词集 `["黑盒实测", "probe-transcript", "实测"]` 命中即 true。识别不出不打标（非关键功能，宁缺勿滥）。

## 10. 测试

- **聚合器单测**（core，`tests/services/test_api_evidence_matrix.py`）：fixture 产物树覆盖——①结构化命中 + 黑盒 verdict 关联；②参数名无关匹配（`:userId` ≡ `:id`）；③歧义进 unmatched；④自由文本 safe_vector 挂载；⑤缺黑盒产物 / 缺 entry_points（空 matrix 不抛错）；⑥coverage 三档判定。
- **web API 测试**：产物存在直读；不存在 lazy 生成 + 落盘；皆无 404。
- **前端测试**（EvidenceTab.test.tsx）：接口列表渲染 + 选中接口两栏证据渲染 + unmatched 提示 + 空态。
- 只跑改动相关测试文件（CLAUDE.md §3 测试陷阱约定）。

## 11. 边界与开放问题

- **MR 增量扫描 / resume**：matrix 每次 assemble_report 全量重建（幂等覆盖），无增量语义——产物小、重建廉价。
- **组合扫描（combined）**：`blackbox-runs/run-*/` 多 run 全部并入（verdict 带 `run_id` 区分）；combined 融合 report（`combined/run-K/report_data.json`）不单独消费，白盒锚点仍用主 report_data。
- **path 大小写 / 多语言路由**：归一化不做大小写折叠（Express/常见框架大小写敏感），保持字节级对比。
- **开放**：safe_vectors 的 GN 轨覆盖（部分 vuln 类无 safe_vectors 文件）——存在性探测、缺则空列表，后续 GN 轨若产安全结论自然并入。
