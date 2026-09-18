# 接口证据关联可靠性改造设计

- 日期：2026-09-18
- 状态：设计中
- 前置/取代关系：落实并扩展 `2026-08-31-endpoint-registry-lazy-enrichment-design.md` 中尚未实施的 Endpoint Registry 方向；本 spec 以证据页可靠性为验收目标，并取代其后续实施范围。

## 1. 背景

证据页的价值在于回答“这个接口为什么有问题、为什么没有问题、是否已经黑盒验证”。因此，**接口底册和 finding 到接口的关联不是展示装饰，而是证据页的正确性前提**。

`金融 / optexercise-20260910-070514` 暴露了当前链路的断裂：`report_data.json` 有 9 张漏洞卡，均带有明确或近似明确的 HTTP 接口；但 `code_index.json` 和 `entry_points.json` 均为 0 条入口。证据矩阵据此将全部卡片归为 `no-route-entries`，接口列表为空。该仓库实际是 Egg.js HTTP 应用，扫描记录识别到多条 `/api/*` 路由，故“RPC/CLI 项目”只是空底册的错误推断，不是事实。

该事件不自动否定 finding 的漏洞结论，但会使接口维度的审阅、黑盒验证追踪、覆盖率表达和修复优先级失真。对“有 HTTP 路由但接口底册为零”的扫描，必须视为产物质量降级，而不是正常 unmatched。

## 2. 目标与非目标

### 2.1 目标

1. 为每次白盒扫描建立有来源、可审计的 canonical HTTP 接口注册表；支持 Express、Egg/Koa 风格顶层 `router.ts`、OpenAPI 和既有框架探测能力。
2. 让 finding 到接口的最终挂载以稳定 `endpoint_id` 为键、确定性完成；支持一张 finding 对多个接口。
3. 显式表达全局配置问题、非 HTTP 入口和真正无法判定的引用，避免把它们错误称为“未关联接口”。
4. 对存量扫描提供安全的页面级回填：底册缺失时可展示有明确 `METHOD + path` 的 finding 声明接口，但必须标注其并非已验证底册，且不得据此宣称接口覆盖率。
5. 在扫描和证据页暴露关联健康度、来源及失败原因；出现“HTTP finding 很多但底册为零”时可诊断、可告警。

### 2.2 非目标

- 不以 LLM 猜测代替确定性路由识别，也不允许页面请求时启动 Agent。
- 不为了提高关联率把同形路由、方法不明的路径或自由文本硬挂到任意接口。
- 不改变漏洞 verdict、双轨 OR、黑盒执行和报告正文的安全判定语义。
- 不保证下游 RPC、框架闭源代码或运行环境中不可见的授权逻辑可被静态证明。

## 3. 核心决策与不变量

### 3.1 “接口是什么”与“漏洞是否成立”分层

接口注册表是扫描基础设施；漏洞 finding 是分析结论。二者必须分别有来源和置信状态：

```text
源码 / OpenAPI / 框架路由声明
  -> endpoint registry（确定性、全量）
  -> finding endpoint resolver（确定性 join）
  -> report / evidence matrix

LLM finding 中的 endpoint 文本
  -> 仅作为 resolver 的声明输入或 gap 候选
  -> 不可直接成为“已确认的接口底册”
```

LLM 仍可分析漏洞、输出它认为受影响的接口、补充问题点；但它输出的路径只能被标为 `declared`，直到被源码/OpenAPI/可验证路由坐标确认。证据页的最终关系必须保留 `provenance`。

### 3.2 双轨独立性不变

注册表构建与 finding resolver 在 merge 后执行；不得把 GitNexus 或 registry 产物注入 LLM 漏洞轨 prompt。Resolver 只消费已落盘的最终 finding，不影响双轨各自独立产生 verdict 的规则。

### 3.3 保守关联不变

只有唯一、可解释的命中才自动绑定。多候选、路径不完整或没有可靠底册时保留未决状态；“没有错挂”优先于“所有证据都有接口”。

### 3.4 全局问题不是 unmatched

Cookie 密钥、TLS/HSTS、统一认证中间件、全局响应头等 finding 的有效范围可能是整个应用或一组接口。它们必须用 `scope=global` 表达，允许附带受影响接口集合，但不伪造单一 `METHOD path`。

## 4. 目标数据模型

沿用 2026-08-31 spec 的产物名，新建：

`deliverables/whitebox/intermediate/endpoint_inventory.json`

```jsonc
{
  "schema_version": 1,
  "status": "healthy", // healthy | degraded | unavailable
  "repository": "/repo",
  "endpoints": [{
    "endpoint_id": "ep_...",
    "entry_type": "http_route",
    "method": "POST",
    "path": "/api/orders/:id",
    "handler_id": "server/app/controller/orders.ts:change:88",
    "route_registered_at": "server/app/router.ts:42",
    "authentication": "isLoggedIn",
    "evidence": "router.post('/api/orders/:id', ...)",
    "provenance": ["framework-route"],
    "adjudication_verdict": "confirmed"
  }],
  "diagnostics": {
    "detected_http_routes": 17,
    "openapi_routes": 0,
    "unsupported_router_files": [],
    "recovery_attempted": false
  }
}
```

`BaseVulnerability` 追加兼容字段（旧产物均可缺省）：

```jsonc
{
  "endpoint_refs": [{
    "endpoint_id": "ep_...",
    "relation": "affected", // affected | trigger | reachable
    "resolution": "registry_id", // registry_id | handler_chain | normalized_declaration | llm_gap
    "provenance": "framework-route"
  }],
  "endpoint_scope": {
    "kind": "endpoint", // endpoint | global | non_http | unresolved
    "reason": null,
    "declared_endpoints": [{"method": "POST", "path": "/api/orders/:id"}]
  }
}
```

`endpoint_ids` 若已在分支实现可作为 `endpoint_refs` 的兼容投影；新写入一律以 `endpoint_refs` 为 SSOT。

全局 finding 的 `endpoint_refs=[]`、`endpoint_scope.kind="global"`；它可选 `affected_endpoint_ids`，用于显示影响面而非声称唯一归属。

## 5. 注册表构建与恢复

### 5.1 新扫描的主路径

在 `run_save_adjudication` 后构建 inventory，并在漏洞分析前落盘：

```text
code index / OpenAPI / framework route extraction
  -> entry point adjudication
  -> build endpoint inventory（确定性）
  -> vuln agents / dual-track merge
  -> resolve finding endpoints（确定性）
  -> optional endpoint gap enrichment
  -> report assembly / evidence matrix
```

构建器聚合以下来源，并对每一行记录 provenance：

- AST/文本框架规则：包括 Express 和 Egg/Koa 风格 `router.get/post/...`；顶层路由文件识别须覆盖 `router.ts` / `router.js`，以及常见 `app/router.*` 路径，不能只依赖 `routes/` 目录。
- OpenAPI/Swagger 路径和方法；schema-only route 允许没有 handler。
- 已有 route chains、framework analysis、可验证的 handler/中间件信息。

同一 method/path 的不同 handler 不得静默合并；保留多行并使 resolver 进入 ambiguity，除非路由注册坐标和 handler 都相同。

### 5.2 确定性恢复

若初次 index 产出零 HTTP route，但仓库存在 TypeScript/JavaScript 路由信号或 OpenAPI 文件，执行一次有界 `route_registry_recovery`：只重扫候选路由文件与 OpenAPI，不调用 LLM。恢复结果覆盖 inventory 并记录 `recovery_attempted=true`。

恢复后仍为零时，inventory 状态为 `degraded`。扫描继续完成，不丢 finding，但在 report、evidence API、活动记录中写入诊断：`http-route-registry-empty`。不得把它自动描述为 RPC/CLI 项目；只有识别到非 HTTP 入口且无 HTTP 证据时才可给出该说明。

## 6. Finding → Endpoint 的确定性 resolver

Resolver 在 merge 后运行，按以下优先级为最终 finding 产生 `endpoint_refs`：

1. 已有 `endpoint_id` / `endpoint_refs`：检查 ID 存在且类型匹配，直接保留。
2. 调用链或 handler ID：通过 inventory 的 handler 索引绑定；同 handler 多路由时保留多个可达接口或记录 ambiguity。
3. 结构化 finding 声明：仅接受独立字段的 `method` 与纯 path；规范化 path 参数、query、尾部 `/` 后唯一匹配 inventory。
4. 受限 gap 补全：仅针对无匹配且存在源码定位的唯一候选，允许 Agent 提出“候选 endpoint_id + 源码坐标”；输出必须经过 deterministic source-coordinate / method/path 校验后才能写入。无法验证则保持 `unresolved`。

`ALL /api/* (说明文字)`、`/path (备注)`、没有 method 的自由文本都不能作为结构化接口写入。它们进入 `endpoint_scope`：可证实为全局的标 `global`，否则标 `unresolved` 并保留原文。

Resolver 输出统计：`registry_id`、`handler_chain`、`normalized_declaration`、`llm_gap_verified`、`ambiguous`、`unresolved`、`global`。这些统计是每个扫描产物的一部分。

## 7. 证据矩阵与存量扫描兼容

### 7.1 正常路径

`api_evidence_matrix` 以 `endpoint_inventory.endpoints` 为唯一接口清单，以 `finding.endpoint_refs` 为挂载键。它不再从 LLM 写入的展示字符串反向猜接口。黑盒仍经 `vulnerability_id -> finding -> endpoint_refs` 关联。

coverage 只能在 inventory `status=healthy` 时显示 `clean` / `defended` / `findings`。若 `degraded`，前端必须显示“接口底册不完整，不能据此判断无发现”，不展示暗示完整覆盖的 clean 语义。

### 7.2 存量扫描的 lazy 回填

若旧扫描没有 inventory 且无法重扫源码，web 的纯函数回填可从 `report_data.vulnerabilities[].endpoints[]` 构造 `declared` 临时接口节点，条件为：method 属于标准 HTTP 方法且 path 是纯绝对路径。

- 临时节点明确标为“finding 声明，未由接口底册验证”；仅展示已挂 finding/黑盒证据，不显示 clean/defended 覆盖率。
- 全局、非 HTTP、含解释文字或歧义声明继续进入“范围/待解析”区域，不强行建接口。
- 回填产物可缓存，但不得回写为新的 `endpoint_inventory.json`，避免把 LLM 输出污染为 canonical registry。

对本次 optexercise 扫描，预期可回填 `GET /api/apply-record`、`POST /api/apply/cancel`、`POST /api/modify-number`、`GET /api/apply-records` 等声明接口；Cookie 密钥类 finding 显示为全局认证影响，而非接口未关联。

### 7.3 unmatched 重新分类

现有 `no-route-entries` 拆为：

- `registry-degraded`：仓库疑似 HTTP，但底册失败；系统问题，需修复/重扫。
- `global-scope`：有效的全局配置/统一控制问题；不是失败。
- `non-http-entry`：RPC、消息消费、CLI/任务等非 HTTP 入口；不是 HTTP 页失败。
- `unresolved-declaration`：finding 没有可验证的接口信息。
- `ambiguous-route`：多个 registry endpoint 同时命中；保守保留。

原有 `no-endpoint-match` 保留为“底册健康但 finding 声明确无匹配”的诊断。

## 8. 前端与 API

Evidence 页增加“关联健康度”区域，至少展示：接口底册状态、confirmed/provisional endpoint 数、finding resolver 分布、未决原因分布和源码/产物来源。`registry-degraded` 用错误级提示，并提供“查看诊断”和“重新扫描”入口；不得仅显示空接口列表。

接口卡显式区分：

- `已验证接口`：来自 inventory，显示路由注册证据与 handler。
- `finding 声明接口`：存量回填的 provisional 节点，显示来源 finding 和“不可用于覆盖率”标记。
- `全局影响`：单独面板，按影响范围显示，不进入左侧 HTTP 接口列表。

API schema 递增版本；旧前端收到旧矩阵时降级为现有 unmatched 视图，不得崩溃。所有 web 路径保持纯读/纯聚合，不运行 Agent。

## 9. 可观测性、门禁与验收

每个扫描记录 `endpoint_association_health`：

```jsonc
{
  "registry_status": "healthy|degraded|unavailable",
  "http_registry_count": 0,
  "declared_http_finding_count": 9,
  "resolved_finding_count": 0,
  "provisional_finding_count": 0,
  "reasons": {"registry-degraded": 9}
}
```

当 `http_registry_count==0` 且存在结构化 HTTP finding、OpenAPI route 或框架路由信号时，扫描标记为 `degraded` 并写 warning event；不阻断安全 finding 与报告生成。工作区/运维视图应可聚合该指标，识别持续失败的框架或提取器回归。

必测场景：

1. Egg.js 顶层 `server/app/router.ts` 的 `router.get/post`：完整提取 HTTP 底册，并能确定性挂载 finding。
2. Express、OpenAPI、参数名不同的同形路径：唯一命中；不同 handler 的真歧义不得硬挂。
3. 一个 finding 影响多个写接口：全部按 `endpoint_refs` 挂载。
4. 全局 Cookie/TLS/缓存配置：进入 global 面板，不进入 `unmatched`，不伪造接口路径。
5. 旧扫描底册为零但 report 有纯 `METHOD + path`：生成 provisional 节点；无 clean 覆盖率。
6. 底册为零且存在 HTTP 信号：诊断为 `registry-degraded`，绝不写“RPC/CLI 项目”。
7. 黑盒 verdict 通过 finding ID 映射到已验证和 provisional 两种 endpoint；ID 漂移仍保留 unmatched。
8. resolver / evidence 页面不增加 LLM 调用，且 LLM 漏洞轨 prompt 不消费 registry 产物。

验收门槛：对 optexercise 同类 Egg fixture，HTTP inventory 不得为零；直接接口 finding 的关联率为 100%，全局 finding 的 scope 分类率为 100%，错误硬挂率为 0。真实扫描若出现“HTTP finding > 0 且 inventory=0”，必须在 UI 与扫描诊断中可见，不能静默变成普通 unmatched。

## 10. 改动边界与迁移

- Core：`code_index` 的框架路由探测、endpoint inventory 模型/构建器、finding resolver、`api_evidence_matrix`。
- Whitebox：adjudication 后的 inventory/recovery activity，merge 后 resolver activity，扫描事件与健康度落盘。
- Web：evidence API schema、lazy provisional fallback、健康度与 scope UI、i18n、重扫入口复用既有扫描能力。
- Tests：core extractor/resolver/matrix、whitebox activity 顺序、web API/页面及旧产物兼容。

迁移不要求重写历史 finding。新扫描走完整 registry；旧扫描首次访问证据页时生成临时视图。只有用户显式重新扫描或原仓库仍可访问并触发确定性重建时，才获得 verified registry。

## 11. 风险与待决项

- 路由声明的框架覆盖无法一次穷尽；应以 fixture 和 `registry-degraded` 指标驱动逐框架补齐，不能由 LLM 静默掩盖。
- 同路径多 handler、网关前缀、动态拼接 route 可能天然无法唯一归属；保留 ambiguity 是正确结果。
- `auth` 与 `authz` 对同一根因的重复 finding 是报告去重/关系图问题，和本 spec 的关联正确性解耦；本次只要求它们可指向同一 endpoint，不在 resolver 内擅自合并 verdict。
- 是否允许用户在 UI 上确认 provisional endpoint 并保存人工映射，留作后续独立设计；本期不引入人工写回，避免污染扫描证据。
