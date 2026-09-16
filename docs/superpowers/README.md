# docs/superpowers — Spec & Plan 索引

本目录存放 shannon-py 各项工作的 **设计 spec**（`specs/`）与 **实现 plan**（`plans/`）。每个工作通常 spec+plan 成对、同名配对：plan = `plans/YYYY-MM-DD-<topic>.md`，spec = `specs/YYYY-MM-DD-<topic>-design.md`。

## 组织规则

- **活跃层**（`specs/`、`plans/` 顶层）：近期在途工作，文件名日期 `> 2026-06-15`。
- **归档区**（`specs/archive/`、`plans/archive/`）：历史已完成工作，文件名日期 `≤ 2026-06-15`。
- **归档切点**：`2026-06-15`（2026-06-29 设定）。定期把越过切点的活跃文档批量 `git mv` 进 archive。
- **从 archive 拉回**：`git mv specs/archive/<file> specs/<file>`（plans 同理）。
- **查 spec**：plan 链接里的 `plans/` 换 `specs/`、文件名加 `-design` 即对 spec（部分 topic 仅有 spec 或仅有 plan，见各条标注）。

## 活跃层（按主题主线）

> 状态：✅已merge ｜ 🔧待冒烟/待merge ｜ 📐设计中/进行中 ｜ (空)=未记录，查 memory / git log

### 双轨 dual-track
- [whitebox-dual-track-merge-architecture](specs/2026-06-24-whitebox-dual-track-merge-architecture-design.md) — 白盒双轨合并器（verdict OR）架构
- [dual-track-merger-plan](plans/2026-06-24-dual-track-merger-plan.md) — `dual_track_merger.py` 实现
- [auth-dual-track-plan](plans/2026-06-24-auth-dual-track-plan.md) — auth 双轨
- [authz-dual-track-plan](plans/2026-06-24-authz-dual-track-plan.md) — authz GitNexus 双轨（IDOR 候选+LLM 判定）🔧
- [inj-xss-ssrf-dual-track-plan](plans/2026-06-24-inj-xss-ssrf-dual-track-plan.md) — injection/xss/ssrf 双轨
- [recon-dual-track-plan](plans/2026-06-24-recon-dual-track-plan.md) / [pre-recon-dual-track-plan](plans/2026-06-24-pre-recon-dual-track-plan.md) — recon/pre-recon 双轨
- [framework-analyzer-wiring-plan](plans/2026-06-24-framework-analyzer-wiring-plan.md) — 框架分析器接线
- [dual-track-decoupling](plans/2026-06-27-dual-track-decoupling.md) / [spec](specs/2026-06-27-dual-track-decoupling-design.md) — 拆确定性→LLM 轨 prompt 注入 🔧
- [dual-track-dedup-mvp](plans/2026-09-03-dual-track-dedup-mvp.md) / [spec](specs/2026-09-03-dual-track-dedup-mvp-design.md) — 双轨去重断裂修复 MVP（vtype/占位符/标点归一 + endpoint 白名单回填 + 观测；NodeGoat 15 条 XSS 实证驱动）📐

### GitNexus 轨
- [gitnexus-track-lifecycle-completion](plans/2026-06-27-gitnexus-track-lifecycle-completion.md) / [spec](specs/2026-06-27-gitnexus-track-lifecycle-completion-design.md) — GitNexus 轨生命周期（A1+A4 done，A2/A3/B open）📐
- [authz-gitnexus-track-observability](plans/2026-06-29-authz-gitnexus-track-observability.md) / [spec](specs/2026-06-29-authz-gitnexus-track-observability-design.md) — authz GitNexus 轨可观测性 + AZ-4 防回退
- [gitnexus-index-degradation-plan](plans/2026-06-24-gitnexus-index-degradation-plan.md) — 索引降级（detect_language 误判等）
- [gitnexus-intra-taint-deterministic-fallback](plans/2026-06-26-gitnexus-intra-taint-deterministic-fallback.md) / [spec](specs/2026-06-26-gitnexus-intra-taint-deterministic-fallback-design.md) — intra-taint 确定性 fallback（is_entry_hint 分层）🔧
- [gitnexus-llm-sink-discovery](plans/2026-06-26-gitnexus-llm-sink-discovery.md) / [spec](specs/2026-06-26-gitnexus-llm-sink-discovery-design.md) — 半 sink 模式 LLM 补召回 📐
- [taint-persist-plan](plans/2026-06-24-taint-persist-plan.md) — taint 落盘 ✅
- [injection-recall-port](plans/2026-06-25-injection-recall-port.md) / [spec](specs/2026-06-25-injection-recall-port-design.md) — injection 召回 port（跨服务全链 leak-free）🔧
- [llm-track-vuln-parity-restoration](plans/2026-06-28-llm-track-vuln-parity-restoration.md) / [spec](specs/2026-06-28-llm-track-vuln-parity-restoration-design.md) — LLM 轨 vuln 对齐 TS（max_turns/方法论补回）🔧
- [second-order-storage-taint-dual-track](specs/2026-07-21-second-order-storage-taint-dual-track-design.md) - 二阶存储中转双轨（子项⑤，GitNexus 确定性 join + LLM 二阶方法论）🔧
- [second-order-recall-rules-join-hardening](plans/2026-07-22-second-order-recall-rules-join-hardening.md) / [spec](specs/2026-07-22-second-order-recall-rules-join-hardening-design.md) - 二阶召回强化：写规则补 token + join 实体类↔表名归一化（不上 agent）📐

### 显示 UX
- [whitebox-display-clarity](plans/2026-06-16-whitebox-display-clarity.md) / [spec](specs/2026-06-16-whitebox-display-clarity-design.md) — 白盒 live 显示重设计 🔧
- [whitebox-live-step-intent-display](plans/2026-06-16-whitebox-live-step-intent-display.md) / [spec](specs/2026-06-16-whitebox-live-step-intent-display-design.md) — step intent 显示
- [rich-display-layout-fix](plans/2026-06-16-rich-display-layout-fix.md) / [spec](specs/2026-06-16-rich-display-layout-fix-design.md) — rich 布局修复
- [provider-agnostic-turn-logging](plans/2026-06-17-provider-agnostic-turn-logging.md) / [spec](specs/2026-06-17-provider-agnostic-turn-logging-design.md) — provider 无关逐轮日志 🔧
- [rich-log-visibility](plans/2026-06-19-rich-log-visibility.md) / [spec](specs/2026-06-19-rich-log-visibility-design.md) — rich 显示可见性 🔧
- [log-format-redesign](plans/2026-06-22-log-format-redesign.md) / [spec](specs/2026-06-22-log-format-redesign-design.md) — 日志格式重设计
- [log-label-alignment](plans/2026-06-23-log-label-alignment.md) / [spec](specs/2026-06-23-log-label-alignment-design.md) — 日志标签列对齐 🔧
- [report-render-stop-bleed](plans/2026-06-22-report-render-stop-bleed.md) — report 渲染停止 bleed（[spec](specs/2026-06-22-report-render-queue-format-fix.md)）
- [live-dashboard-ghost-frame-fix](plans/2026-06-25-live-dashboard-ghost-frame-fix.md) / [spec](specs/2026-06-25-live-dashboard-ghost-frame-fix-design.md) — dashboard 残影帧修复
- [chinese-comprehensive-report](plans/2026-06-22-chinese-comprehensive-report.md) / [spec](specs/2026-06-22-chinese-comprehensive-report-design.md) — 中文综合报告 🔧
- [display-ux-polish](plans/2026-06-27-display-ux-polish.md) / [spec](specs/2026-06-27-display-ux-polish-design.md) — 白盒显示 UX 优化 ✅
- [workflow-info-display-channel](plans/2026-06-28-workflow-info-display-channel.md) / [spec](specs/2026-06-28-workflow-info-display-channel-design.md) — workflow InfoEvent 显示通道 🔧
- [cli-workflow-failure-friendly-display](plans/2026-06-28-cli-workflow-failure-friendly-display.md) / [spec](specs/2026-06-28-cli-workflow-failure-friendly-display-design.md) — CLI workflow 失败友好展示 🔧
- [prompt-output-language-core](specs/2026-08-28-prompt-output-language-core-design.md) — 13 个辅助 prompt 补通用语言约束（叙述散文随 LANG、技术标识保英文）📐 仅 spec 未实施

### 引擎 engine
- [openai-agents-engine](plans/2026-06-17-openai-agents-engine.md) / [spec](specs/2026-06-17-openai-agents-engine-design.md) — openai-agents 引擎（[smoke](plans/2026-06-17-openai-agents-engine-smoke.md)）
- [dual-engine-decoupling-fix](plans/2026-06-27-dual-engine-decoupling-fix.md) / [spec](specs/2026-06-27-dual-engine-decoupling-fix-design.md) — 双引擎解耦修复（契约硬化+语义对齐）🔧
- [blackbox-agent-browser-default-engine](plans/2026-06-28-blackbox-agent-browser-default-engine.md) / [spec](specs/2026-06-28-blackbox-agent-browser-default-engine-design.md) — 黑盒默认引擎切 agent-browser 🔧

### env / config
- [env-config-profiles](plans/2026-06-18-env-config-profiles.md) / [spec](specs/2026-06-18-env-config-design.md) · [anthropic-env-prefix](specs/2026-06-18-anthropic-env-prefix-design.md) — env profile 化 🔧
- [max-concurrent-env](plans/2026-06-22-max-concurrent-env.md) / [spec](specs/2026-06-22-max-concurrent-env-design.md) — 最大并发 env
- [token-caching](specs/2026-06-26-token-caching-design.md) — token 缓存（仅 spec）📐
- [remove-minimal-fallback-hard-fail](plans/2026-06-24-remove-minimal-fallback-hard-fail.md) / [spec](specs/2026-06-24-remove-minimal-fallback-hard-fail-design.md) — 移除 minimal fallback 硬失败
- [global-pricing-console](specs/2026-08-28-global-pricing-console-design.md) — 全局 + 工作区两级定价管理 web 控制台（定价分层 内置<profile env<全局表<工作区覆盖 + PricingEditor 复用组件 + 界面保存即接管）🔧 已实施（TDD 直接实现无独立 plan；E2E 冒烟 web API 全链 + core 计费生效链通过）

### resume / rerun
- [resume](plans/2026-06-18-resume.md) / [spec](specs/2026-06-18-resume-design.md) · [resume-and-rerun](specs/2026-06-19-resume-and-rerun-design.md) — resume/rerun 机制
- [whitebox-resume](plans/2026-06-19-whitebox-resume.md)（[smoke](plans/2026-06-19-whitebox-resume-smoke.md)）— 白盒 resume 🔧
- [blackbox-rerun](plans/2026-06-19-blackbox-rerun.md)（[smoke](plans/2026-06-19-blackbox-rerun-smoke.md)）— 黑盒 rerun 🔧

### deliverables / prompt
- [deliverables-to-session](plans/2026-06-21-deliverables-to-session.md) / [spec](specs/2026-06-19-deliverables-to-session-design.md) — deliverables 迁入 session
- [prompt-deliverables-migration](plans/2026-06-21-prompt-deliverables-migration.md) / [spec](specs/2026-06-21-prompt-deliverables-migration-design.md) — prompt deliverables 迁移
- [prompt-optimization](plans/2026-06-23-prompt-optimization.md) / [spec](specs/2026-06-23-prompt-optimization-design.md) — prompt 优化（authz IDOR/recon-static/manager 占位符）🔧
- [deliverables-git-isolation](plans/2026-06-22-deliverables-git-isolation.md) / [spec](specs/2026-06-22-deliverables-git-isolation-design.md) — deliverables git 隔离

### retry / 健壮性
- [retry-policy-alignment](plans/2026-06-22-retry-policy-alignment.md) / [spec](specs/2026-06-22-retry-policy-alignment-design.md) — retry policy 对齐 TS 🔧
- [glm-529-retry-resilience](specs/2026-06-22-glm-529-retry-resilience-design.md) — GLM 529 retry 韧性（仅 spec）
- [exploit-coverage-closure](plans/2026-06-22-exploit-coverage-closure.md) / [spec](specs/2026-06-22-exploit-coverage-closure-design.md) — exploit 覆盖收口

### 黑盒 / 跨仓
- [cross-repo-microservice-correlation](plans/2026-06-23-cross-repo-microservice-correlation.md) / [spec](specs/2026-06-22-cross-repo-microservice-scanning-design.md) — 跨仓微服务关联
- [cross-repo-correlation-web-revival](plans/2026-08-24-cross-repo-correlation-web-revival.md) / [spec](specs/2026-08-24-cross-repo-correlation-web-revival-design.md) — 跨仓关联扫描 web 复活（三段接力 C1 化 + 前端重做）
- [blackbox-exploit-outcome-field-mapping](plans/2026-06-29-blackbox-exploit-outcome-field-mapping.md) / [spec](specs/2026-06-29-blackbox-exploit-outcome-field-mapping-design.md) — 黑盒 exploit AgentOutcome 字段映射 🔧
- [blackbox-exploit-structured-output](plans/2026-06-29-blackbox-exploit-structured-output.md) / [spec](specs/2026-06-29-blackbox-exploit-structured-output-design.md) — 黑盒 exploit 产物结构化校验护栏
- [combined-finalize-run-awareness](specs/2026-08-28-combined-finalize-run-awareness-design.md) — combined 收口感知 run 终态（根级 completed 携带 failed_runs 明细不掩盖 / 全 run 失败降级）📐 仅 spec 未实施
- [topology-preanalysis-worker-migration](specs/2026-09-03-topology-preanalysis-worker-migration-design.md) — 拓扑预分析迁 worker（web 零 agent 执行点 + 守护测试；TDD 直实施无 plan）🔧

### 报告增强 / PoC
- [exploitable-poc-generation](plans/2026-07-02-exploitable-poc-generation.md) / [spec](specs/2026-07-02-exploitable-poc-generation-design.md) — 外部可达漏洞 curl/Burp PoC 自动生成（黑白盒通用）🔧
- [poc-deterministic-layered](plans/2026-07-22-poc-deterministic-layered.md) / [spec](specs/2026-07-22-poc-deterministic-layered-design.md) — PoC 分层确定性化 + 可靠性加固（分组补缺/checkpoint/非阻塞）🔧
- [poc-accuracy-speed-overhaul](specs/2026-08-19-poc-accuracy-speed-overhaul-design.md) — PoC 准确性+速度治理 P0+P1（witness 解析/路由 join/lint/authz 鉴别力/auth 并行/checkpoint v2）🔧
- [whitebox-report-readability](specs/2026-08-25-whitebox-report-readability-design.md) — 白盒报告可读性改造（四要素卡/接口级归并/速查表/风格指南/severity 数据化）🔧
- [vuln-card-consolidation](specs/2026-08-26-vuln-card-consolidation-design.md) — 漏洞卡片信息归并 + 双轨呈现一致性（细节区收敛/问题点三要素/接口+参数/LLM 配对归并/GN-only 补全）📐
- [api-evidence-matrix](specs/2026-09-10-api-evidence-matrix-design.md) — 接口证据页（接口级倒排证据矩阵：白盒/黑盒两栏独立 + coverage 标注 + 独立 web tab + 旧扫描 lazy 回填）📐
- [report-chat-qa-bot](specs/2026-09-16-report-chat-qa-bot-design.md) — 报告页漏洞问答聊天机器人（每轮一 workflow + 只读工具档 + 独立 chat 队列 + 引擎跟随扫描 profile）📐

### 认证档案 auth-profile
- [auth-profile-vault](specs/2026-08-05-auth-profile-vault-design.md) — per-ws 加密档案库 + 独立验证 + 黑盒扫描复用 🔧
- [auth-profile-system-seed](specs/2026-08-06-auth-profile-system-seed-design.md) — configs/*.yaml 启动 seed 成全局共享系统档案（store 透明 fallback + .system 保留段）📐

### web 登录 / SSO
- [sso-auth](plans/2026-08-25-sso-auth.md) / [spec](specs/2026-08-25-sso-auth-design.md) — 富途 OA passport SSO 接入（账密共存 + nick 白名单 JIT 建户 + 防重放 + 头像展示）🔧

### audit / attribution
- [audit-session-agent-attribution](plans/2026-06-22-audit-session-agent-attribution.md) / [spec](specs/2026-06-22-audit-session-agent-attribution-design.md) — AuditSession 归因 race 🔧

### workspace
- [workspace-human-readable-timestamp](plans/2026-06-28-workspace-human-readable-timestamp.md) / [spec](specs/2026-06-28-workspace-human-readable-timestamp-design.md) — workspace 目录名人类可读化 🔧
- [linked-repos-checkout-pull](specs/2026-09-04-linked-repos-checkout-pull-design.md) — 关联仓库放开 checkout/pull/branches（admin-only + 共享目录零写入 + GIT_TERMINAL_PROMPT 护栏；推翻 2026-07-29 linked 只读决策）🔧

### MR 增量扫描
- [mr-incremental-scan](specs/2026-09-03-mr-incremental-scan-design.md) — 合并请求 diff 扫描：MrScanWorkflow 独立编排 + 轻量单索引 + 三来源增量范围合成（新增代码/新入口/删防护反向链）+ 双轨铁律合规接入 📐

### 黑盒验证缺口留痕
- [blackbox-verification-gap-traceability](specs/2026-09-03-blackbox-verification-gap-traceability-design.md) — 黑盒验证失败留痕：verdicts.json 扩 gaps/agent_run/端点痕迹 + 融合四态（已实证/复验失败/中断未结论/未覆盖）+ run 级缺口信号传导放行手动续跑 🔧 已实施（TDD 直实现无独立 plan；core/blackbox/web/fe 全链测试绿，真机冒烟待重扫）

### authz 演进
- [authz-attack-chain-confidence](specs/2026-06-17-authz-attack-chain-confidence-design.md) — authz 攻击链置信度（仅 spec）📐
- [authz-optimization-roadmap](specs/2026-06-17-authz-optimization-roadmap-design.md) — authz 优化路线图（仅 spec）📐

### 元 / 维护
- [superpowers-docs-archiving](plans/2026-06-29-superpowers-docs-archiving.md) / [spec](specs/2026-06-29-superpowers-docs-archiving-design.md) — 本目录的归档与索引导航（本次）📐

## 归档区

历史已完成工作位于 `specs/archive/`（54 个）与 `plans/archive/`（55 个），文件名日期 `≤ 2026-06-15`，合计 109 个。需要查阅时直接进入对应 archive 子目录按文件名日期查找。
