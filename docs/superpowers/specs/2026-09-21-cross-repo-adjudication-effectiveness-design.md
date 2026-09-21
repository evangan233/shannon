# 跨仓对抗审查有效性改造（dismissed 侧翻案）— 设计 spec

- 日期：2026-09-21
- 状态：已实现（feat/fork-py 本地未提交；四改动全部落地，见 §7 落地记录）
- 数据依据：`workspaces/金融平台-2026h2/scans/cross-repo-20260920-092147` 实测统计（下文所有数字来自这次真实扫描）

---

## 0. 人话版摘要（先读这个）

跨仓扫描的最后一步叫**对抗审查**（adjudication）：单仓扫描报上来的漏洞、和单仓扫描否决掉的疑似漏洞，都拿到跨服务的上下文里再审一遍。理想中它能干两件事：

- 报上来的 → 再确认一遍，或者**降级**（发现另一边的代码其实有防护）；
- 否决掉的 → 看看**别的服务调用它时会不会让否决理由失效**，能就**翻案**。

实测结果（259 张审查卡）：

| 审查方向 | 数量 | 说明 |
|---|---|---|
| 维持否决（maintain） | 150 | **单仓否决的 143 条，跨仓审查翻了 0 条** |
| 确认漏洞（confirm） | 73 | |
| 降级（downgrade） | 31 | 单仓报的 116 条里降级了 27%——这一侧其实干得不错 |
| 翻案（upgrade） | 4 | 而且 4 条都是标错了类别的（见 §1.4） |
| 出错占位（error） | 1 | |

**"否决掉的 143 条全被维持"不是模型偷懒，是我们没给它翻案的材料：**

1. **循环论证**。审查提示词要求 agent"查拓扑判断这个被否决的发现从外部能不能到达"。但我们喂给它的拓扑里只有 7 条服务连线、2 条攻击链、0 条多跳链——而这些链全部来自"已报漏洞"的发现。被否决的发现**天生不在里面**（实测 118 条能提取方法名的，在拓扑里 0 命中）。拿一份"只记录已破案件"的卷宗问法官"被告有没有不在场证明"，答案永远是"查无记录"。
2. **维持原判零成本**。提示词只要求"翻案/降级"必须给出代码级证据；"维持"不需要任何新证据——把单仓的否决理由复述一遍、引两句本仓代码就算合规。142 张维持卡里 140 张就是这么写的，只有 20% 引用了本仓以外的代码。审查变成了**复读机**。
3. **钱花错了地方**。143 条被否决的发现里，约 128 条的否决理由是"代码里有防护"（参数化查询、输出脱敏、无渲染上下文……）。这类否决**跨仓视角本来就翻不了**——SQL 参数化不会因为调用方多了就失效。真正可能被跨仓视角翻案的（"内部接口、外部不可达"这类可达性假设）只有约 15 条。但我们把 55% 的审查预算平摊给了前者。

另一个实测发现：**翻案材料其实已经存在**。阶段 A 产出的 `trust-boundaries.json` 里有 12 条"哪个入口的哪个 HTTP 路由 → 能到达哪个后端 RPC 方法"的映射，只是从来没喂给审查 agent。

---

## 1. 背景与问题细节

### 1.1 对抗审查现在怎么跑

```
阶段 A（关联）: 按声明的服务关系逐条边跑 edge agent
              → edges（服务连线+RPC 调用点）、boundaries（暴露面+可达入口）、flows（攻击链）
阶段 B（裁决）: 把发现按 (服务 × 漏洞类 × 来源 queue|dismissed) 分批，每批 ≤15 条
              → 每批一个 agent，对照 correlation_context（edges/flows/多跳链）逐条出卡
```

关键代码：

| 位置 | 职责 |
|---|---|
| `packages/core/src/supernova_core/correlation/adjudication.py` | 批组织（queue 与 dismissed 各自成批） |
| `packages/multi/src/supernova_multi/orchestrator.py:383-433` | 组装 correlation_context、调用阶段 B |
| `packages/multi/src/supernova_multi/adjudication_phase.py` | 批并发执行、漏判补位 |
| `packages/core/src/supernova_core/correlation/merge_validation.py` | 确定性校验（direction/conclusion 矛盾 → needs-review） |
| `prompts/cross-repo-adjudication.txt` | 审查 agent 的提示词 |

### 1.2 循环论证（最要命）

提示词方法论第 2 步（`cross-repo-adjudication.txt:36-38`）：

> Check cross-service reachability: is the finding's method / location reachable
> from an entrypoint **via the correlation topology / flows / multi-hop chains**?

但 flows 和多跳链是从"已报漏洞"的攻击链拼出来的（`assemble_multi_hop_chains` 的种子边要求 `flows` 非空）；0920 那次扫描的 context 里连 RPC 方法明细都没有（"edges 带 calls"是 09-21 本地未提交的修改）。于是：**被否决的方法不在判据里 → 判"不可达" → 维持否决**。整个 dismissed 侧的审查在结构上就是空转。

### 1.3 举证责任不对称

提示词规则（`:72-78`）：upgrade/downgrade 要 concrete file:line 证据；maintain 没有独立举证要求。实测 142 张维持卡：140 张的 reasoning 是"dismiss 理由与源码一致，维持，不翻案"句式；只有 28 张（20%）的证据引用了本仓以外的代码。agent 干的是"单仓复核"，不是"跨仓重审"。

### 1.4 方向语义漏网

提示词规定 queue 的发现只能出 confirm/downgrade、dismissed 只能出 upgrade/maintain，但确定性校验（`sanitize_adjudication_cards`）只查 direction 与 conclusion 的搭配，**不查 direction 与 origin 的搭配**。本次 4 张 upgrade 卡 origin=queue、8 张 queue 批出了 maintain——全部漏网进了正式结果。

### 1.5 被审样本构成（分桶的依据）

5 个被审服务共 160 条 dismissed，进了 143 条。按否决理由粗分：

- **防护类**（~69 条）：参数化、脱敏、过滤、框架统一序列化……——sink 处的防护与"谁调用我"无关，跨仓视角翻不了；
- **可达性类**（~15 条）："内部接口""无调用点不可达"……——**这才是跨仓审查的目标客户**；
- 其余两类关键词都不沾的（~59 条）：归类存疑，宁可多审。

其中 127/143 条来自 llm-exploration 阶段（单仓 LLM 深判后的安全向量），底子本就不差——所以翻案上限天然低，预算更该集中。

---

## 2. 目标 / 非目标

**目标**

1. dismissed 批的 agent 拿得到"翻案原料"：本服务被谁调用、从哪个入口可达（确定性数据，不靠 agent 盲找）。
2. maintain 不再是零成本路径：给不出跨仓证据、也没引用调用面数据的维持卡，自动落 `needs-review` 人工池。
3. 防护类否决不再占用审查预算（跳过 + 留痕可审计），省下的预算集中在可达性类。
4. direction 与 origin 的搭配进确定性校验，语义漏网卡落 needs-review。
5. 三个可验证指标：dismissed 翻案数 > 0、maintain 卡跨仓证据引用率显著上升、dismissed 侧审查 token 下降。

**非目标**

- 不动双轨铁律：不给 LLM 轨喂任何确定性产物（本 spec 全部改动都在跨仓裁决阶段，该阶段本来就是"确定性产物喂给裁决 agent"的轨道）；
- 不改阶段 A 的边发现逻辑（boundaries/calls 覆盖少是上游问题，另立 spec；本设计只做"已有数据的喂法"）；
- 不改 queue 侧流程（27% 降级率说明它工作正常，只顺带修 origin 校验）；
- 不做 finding 级的确定性方法名匹配（evidence 格式五花八门，脆；方法名对不上调用面数据的活交给 agent，它擅长）。

---

## 3. 设计（四个改动）

### 3.1 改动一：correlation_context 增加 `inbound_surface`（喂翻案原料）

**数据源（全部已存在，零新增扫描）：**

- `boundaries`：12 条"RPC 方法 → exposure(external/internal) → reachable_from(入口服务+HTTP 路由)"；
- `validated_edges` 带 `calls`：每条服务连线上的 RPC 调用点（method + call_site file:line）——含 09-21 未提交的"edges 带 calls"修改；
- 各仓 `entry_points.json` 路径（已经过 artifacts_guide 可读，此处只给指路不复制内容）。

**组装（`orchestrator.py` 阶段 B 前）：** 按 `to` 服务分组，生成：

```json
"inbound_surface": {
  "backend/asset_transfer": {
    "inbound_calls": [
      {"from_service": "stock-internal-transfer",
       "rpc_method": "AssetTransfer/GetAccountAssetList",
       "call_site": "internal/.../client.go:88"}
    ],
    "reachable_entries": [
      {"rpc_method": "AssetTransfer/GetAccountAssetList",
       "exposure": "external",
       "via": "stock-internal-transfer GET /api/transfer/assetList (webLogin)"}
    ],
    "entry_points_ref": "<该仓 entry_points.json 路径，供 agent 自查>"
  }
}
```

全量随 correlation_context 下发（7 边规模很小，不按批裁剪；数据大了再优化）。09-21 已把 edges.calls 放进 context，本改动是把 boundaries 的 `reachable_from`（**入口级可达映射，翻案最关键的料**）和 entry_points 指路补齐，并按服务分组让 agent 一眼看到"谁调我、从哪进来"。

### 3.2 改动二：maintain 举证门槛（提示词 + 确定性校验双管）

**提示词（`cross-repo-adjudication.txt`）：**

- 方法论第 2 步判据改写：可达性不只看 flows/多跳链（它们只覆盖已报漏洞的链），**先查 `inbound_surface` 里有没有指向本发现方法的调用，再决定要不要去源码里 grep 调用方**；
- maintain 卡的规则：必须满足其一——
  a. 证据里至少一条**本服务以外**的 file:line（调用方如何消费本发现的输出、为何不构成新攻击面）；或
  b. 引用 `inbound_surface`（格式约定：`verification_evidence` 里一条 `location` 以 `correlation-context:` 开头的记录，说明"确定性层未发现指向该方法的跨仓调用"或引用了某条映射）；
  两者皆无 → 结论必须写 `needs-review`，不许写 maintain。

**确定性校验（`merge_validation.py`，与现有 sanitize 同模式、零推断）：**

```
origin=dismissed 且 direction=maintain 的卡：
  证据中既无「repo ≠ 本服务」的条目、也无「location 以 correlation-context: 开头」的条目
  → conclusion 改 needs-review（卡保留，透明可审计）
```

env 开关 `SUPERNOVA_ADJUDICATION_MAINTAIN_GATE`（默认开，`"0"` 关）——首轮观察 needs-review 比例用。

> 顺序依赖：**改动一必须先于改动二上线**，否则 agent 手里没料、门槛只会在把大量卡推进 needs-review 人工池。

### 3.3 改动三：dismissed 分桶，预算重配

**分类（`adjudication.py` 新增纯函数，与现有 `_reachability_rank` 同处）：**

- dismiss_reason 命中**防护关键词**（参数化 / prepared / 脱敏 / 转义 / escape / sanitiz / 过滤 / 白名单 / 强类型 / 框架统一序列化……）**且不命中**可达性关键词（不可达 / 内部 / 未对外 / 暴露 / reach / exposure……）→ `defensive`，**不进批**；
- 其余（可达性类、两类都不沾的、两类都沾的）→ `reviewable`，正常进批。宁可多审，不搞激进漏筛。

**留痕（跳过必须可审计）：** 被跳过的条目写入 `adjudication-log.json` 的 `skipped_dismissed` 段（含 vuln_id、dismiss_reason、命中的关键词），报告 md 一句话说明"N 条防护类否决未占用跨仓审查"。不产卡、不占 direction 枚举。

env 开关 `SUPERNOVA_ADJUDICATION_SKIP_DEFENSIVE`（默认开，`"0"` 关——全量进批的老行为一键恢复）。

**预期量级（按 0920 数据）：** 143 条里 ~69 条 defensive 跳过，省约一半 dismissed 侧审查 token；剩余 ~74 条里携带调用面数据的获得实质更深的审查。

### 3.4 改动四：sanitize 补 direction↔origin 校验

`merge_validation.py` 新增：

```
origin=queue     允许 direction: confirm | downgrade
origin=dismissed 允许 direction: upgrade | maintain
违者 → conclusion 改 needs-review（卡保留）
```

error 卡（direction="error"）不在校验表内，行为不变。

---

## 4. 上线顺序

1. **先部署 09-21 已写未提交的修改**（edges 带 calls、exploit_path 强求、批并发）——这是本次诊断的直接产物，独立有效；
2. 改动一 + 改动四（纯确定性层 + 纯校验，风险最低）；
3. 改动二 + 改动三（提示词 + 分桶）；
4. 下一次跨仓扫描跑试金石（§5）。

## 5. 验证

**单测（改动相关文件，不广跑全套）：**

- `merge_validation`：origin 校验、maintain 举证校验（有跨仓证据 / 有 correlation-context 引用 / 两者皆无 → needs-review）；
- `adjudication`：分桶纯函数（防护类跳、可达性类进、两不沾进、留痕字段全）；
- `orchestrator` / `adjudication_phase`：inbound_surface 组装与下发（不破坏既有 prompt_variables 契约）；
- 既有锁定测试不动：`test_static_dataflow_hints_decoupling.py`（LLM 轨独立性不受影响——本 spec 不碰 LLM 轨）。

**试金石（下一次真实跨仓扫描，对比 0920 基线）：**

| 指标 | 0920 基线 | 期望 |
|---|---|---|
| dismissed 翻案（upgrade）数 | 0 / 143 | > 0（哪怕 1-3 条也证明链路通了） |
| maintain 卡含跨仓证据 / correlation-context 引用 | 28 / 142（20%） | 大幅上升；裸复述卡落 needs-review |
| dismissed 侧审查条目数 | 143 | ~74（defensive 跳过生效） |
| queue 侧降级率 | 27% | 不回退（对照组） |

## 6. 风险与回滚

| 风险 | 缓解 |
|---|---|
| 分桶错杀（真翻案机会被标 defensive） | 规则保守（命中防护且**无**可达性词才跳）；留痕可人工复核；env 开关一键回全量 |
| maintain 门槛过严 → needs-review 洪峰 | 改动一先行供料；门槛有 env 开关；首轮扫描后按数据调提示词措辞 |
| inbound_surface 依赖阶段 A 产量（boundaries/calls 覆盖少） | 空数据时 agent 走"correlation-context: 无调用记录"分支合规 maintain，门槛自洽；上游覆盖问题另立 spec |
| correlation_context 变大 | 7 边规模可忽略；数据量大后再做按批裁剪 |

---

## 7. 落地记录（2026-09-21）

| 改动 | 位置 | 说明 |
|---|---|---|
| §3.1 inbound_surface | `orchestrator.py::_build_inbound_surface` + correlation_context 新键 | 边 calls → `inbound_calls`；边界 → `reachable_entries`；`entry_points_ref` 指路；纯数据搬运零推断 |
| §3.2 maintain 举证门槛 | `merge_validation.py::enforce_maintain_evidence` + `adjudication_phase.py` 接线 + prompt Rules/方法论步骤 2 改写 | 维持卡须跨仓证据或 `correlation-context:` 引用，否则 needs-review；env `SUPERNOVA_ADJUDICATION_MAINTAIN_GATE`（默认开） |
| §3.3 分桶 | `adjudication.py::classify_dismissed` / `split_dismissed_by_service` + `orchestrator.py` 接线 + `report.py` skipped 落盘 + 报告留痕节 | 防护类跳过留痕 `skipped_dismissed`；关键词保守（不含"校验/验证"泛词）；env `SUPERNOVA_ADJUDICATION_SKIP_DEFENSIVE`（默认开） |
| §3.4 origin 校验 | `merge_validation.py::_CONSISTENT_DIRECTIONS` | queue: confirm/downgrade；dismissed: upgrade/maintain；违者 needs-review；error/未知 direction 宽容放行 |
| 报告口径联动 | `orchestrator.py::_render_verdict_stats` | needs-review 的维持卡不计"维持"，单列"存疑（举证不足/裁决失败，待人工）"；`cards=[]` + skipped ≠ "进行中" |

测试（worker 容器内，全绿）：core `tests/correlation`（65，含分桶/origin/举证门槛新用例）+ `test_cross_repo_prompts_contract`；multi `test_orchestrator`（25，含 inbound_surface 端到端 + 分桶开关端到端 + 报告口径）+ `test_adjudication_phase`（10）。

待验证（试金石，见 §5）：下一次真实跨仓扫描对比 0920 基线四指标。
