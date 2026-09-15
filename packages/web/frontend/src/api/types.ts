// === ndjson 事件 schema（主 spec §ndjson 三方硬契约）===
// 通用字段每行必有；各 type 附加字段见主 spec 表。

export type EventCategory =
  | "PHASE" | "STEP" | "AGENT" | "TOOL" | "LLM" | "ERROR"
  | "INFO" | "WARN" | "RESUME" | "SUMMARY" | "HEADER" | "GITNEXUS" | "CONTROL"
  // GN-LLM：GitnexusLlmEvent 内部 subtype（events.py：category 字段保留 GN-LLM）
  | "GN-LLM";

interface CommonFields {
  ts: string;          // 事件时间戳。历史 ndjson 为 worker 容器 UTC 墙钟 "YYYY-MM-DD HH:MM:SS"（无时区）；
                       // P2 后新扫描为 UTC ISO8601 带 Z。前端经 utils/eventTs.parseEventTs 归一化当 UTC 解析。
  category: EventCategory;
}

export interface WorkflowHeaderEvent extends CommonFields {
  type: "WorkflowHeader";
  workflow_id: string; target_url: string; repo_path: string;
  mode: string; web_ui_url: string; logs_cmd: string; workspace: string;
}
export interface PhaseEvent extends CommonFields {
  type: "PhaseEvent"; phase: string; event: "start" | "complete";
  steps: string[]; step_intents: string[];
}
export interface StepEvent extends CommonFields {
  type: "StepEvent"; name: string; phase: string; event: "start" | "complete";
  duration_ms?: number; error?: string; intent?: string;
}
export interface AgentEvent extends CommonFields {
  type: "AgentEvent"; agent_name: string; event: "start" | "end";
  attempt: number; duration_ms?: number; cost_usd?: number; cost_currency?: string;
  input_tokens?: number; output_tokens?: number; cache_read_tokens?: number; cache_creation_tokens?: number;
  success?: boolean; error?: string;
}
export interface ToolCallEvent extends CommonFields {
  type: "ToolCallEvent"; agent_name: string; tool_name: string; parameters?: unknown;
}
export interface LlmTurnEvent extends CommonFields {
  type: "LlmTurnEvent"; agent_name: string; turn: number; content: string;
}
export interface InfoEvent extends CommonFields {
  type: "InfoEvent"; message: string; level: "info" | "warning";
}
export interface ErrorEvent extends CommonFields {
  type: "ErrorEvent"; error_type: string; message: string; context?: string;
  classified?: string; display_retryable?: boolean; attempt?: number;
  max_attempts?: number; detail_path?: string;
}
export interface SummaryEvent extends CommonFields {
  type: "SummaryEvent"; status: string; total_duration_ms?: number;
  total_cost_usd?: number; cost_currency?: string;
  total_input_tokens?: number; total_output_tokens?: number;
  total_cache_read_tokens?: number; total_cache_creation_tokens?: number;
  agents?: Array<{ name: string; duration_ms?: number; cost_usd?: number; cost_currency?: string;
    success?: boolean; input_tokens?: number; output_tokens?: number;
    cache_read_tokens?: number; cache_creation_tokens?: number }>;
  error?: string;
}
export interface ResumeEvent extends CommonFields {
  type: "ResumeEvent"; previous_workflow_id: string; new_workflow_id: string;
  checkpoint_hash: string; completed_agents: string[];
}
export interface GitnexusLlmEvent extends CommonFields {
  type: "GitnexusLlmEvent";
  // 具体字段随 events.py GitnexusLlmEvent（2026-08-28 前端 fold chain-verdict 进度用）；
  // 其余字段按需透传
  phase: string;
  kind: "progress" | "hit" | "summary" | "note";
  done: number;
  total: number;
  hits: number;
  detail?: string | null;
  [k: string]: unknown;
}
export interface LogEventEvent {
  ts: string;
  // category=levelname 动态值(INFO/WARNING/ERROR/DEBUG), 非 EventCategory 枚举(只有 WARN 无 WARNING)
  category: string;
  type: "LogEvent";
  logger_name: string;
  level: string;       // "INFO" | "WARNING" | "ERROR" | "DEBUG" | "NOTSET"
  message: string;
  exc_txt?: string;
}
export interface ScanEndEvent extends CommonFields {
  // 后端编排层实际终态全集（scan_manager/orphan_reconciler）：completed / failed /
  // killed / crashed / interrupted（心跳丢失 orphan）/ cancelled（用户取消）——
  // 前两者外的非自然终态曾漏出联合类型（2026-09-09 中断体感修复顺带补齐）。
  type: "scan_end"; status: "completed" | "failed" | "killed" | "crashed" | "interrupted" | "cancelled";
  returncode?: number; stderr_tail?: string;
}
/** 黑盒 run 级收尾（归并流把 run 的 scan_end 改写为 run_end 转发：对全量流非终态）。 */
export interface RunEndEvent extends CommonFields {
  type: "run_end"; status: string; run: string;
  returncode?: number; stderr_tail?: string;
}
export interface CorrelationProgressEvent extends CommonFields {
  type: "correlation_progress"; node: "repo" | "phase" | "edge"; name: string;
  status: "started" | "completed" | "failed"; detail?: string;
}
/** 归并 SSE 的首轮回放边界；不是磁盘事件，不参与 dashboard fold。 */
export interface StreamReadyEvent extends CommonFields {
  type: "stream_ready";
}

// src：归并流源标记（MergedEventTailer 注入：ac=认证预检 / wb=任务根（组合即白盒段）/
// run-K=黑盒 run / c-<scan_id>=correlation 现扫子仓；单文件流与旧后端不带）。组合扫描
// 列表进度三阶段加权判段用（2026-08-28）——phase 名判段不可行：authcheck 与黑盒 run
// 发同名 auth-validation PhaseEvent，前端无从区分。
// service：子仓源的 svc 名（src=c-* 行的 LogStream [svc] 归属前缀；ScanProgressOverview
// 按 src 前缀过滤子仓事件防网格重置——2026-09-10）。
export type NdjsonEvent =
  ((WorkflowHeaderEvent | PhaseEvent | StepEvent | AgentEvent | ToolCallEvent
  | LlmTurnEvent | InfoEvent | ErrorEvent | SummaryEvent | ResumeEvent
  | GitnexusLlmEvent | ScanEndEvent | RunEndEvent | CorrelationProgressEvent | StreamReadyEvent
  | LogEventEvent
  ) & { src?: string; service?: string });

// === API 响应类型（对齐 backend-design.md）===
export type WorkspaceStatus =
  | "running" | "in-progress" | "interrupted" | "queued"
  | "completed" | "failed" | "killed" | "crashed";

export interface Workspace {
  name: string;
  scan_type: "whitebox" | "blackbox" | "correlation" | "mr";
  status: WorkspaceStatus;          // 归一后（见 §3.1 status 矛盾兜底）= latest scan 聚合
  created_at: number;               // unix（= latest scan created_at）
  completed_at?: number | null;
  vuln_count?: number;
  total_cost_usd?: number;
  cost_currency?: string;
  total_duration_ms?: number;
  links?: { parent_workspace?: string | null; child_workspaces?: string[] };
  is_correlation?: boolean;
  // ws-scan 解耦（spec §5.3）：ws 是容器，scan_count/latest_* 从该 ws 的 scans 聚合。
  // 旧后端（Phase 1 未上线）不返这些字段 -> 可选，消费方 null-safe。
  scan_count?: number;
  latest_status?: WorkspaceStatus | string;
  latest_created_at?: number;
}

/**
 * ws 内单个 scan 的摘要（spec §4.2）。GET /workspaces/{ws}/scans 返该数组；
 * GET /workspaces/{ws} 的 scans[] 兼容字段也用此 shape。
 *
 * Phase 1 scan_store.ScanSummary 额外聚合了 vuln_counts/total_duration_ms/links/
 * is_correlation（供 ws 列表行从 latest scan 聚合），此处设可选兼容，前端按需用。
 */
/** 版本化黑盒 run（spec §5.2）：白盒任务下 blackbox-runs/run-K 子目录的 run 摘要。
 *  GET /workspaces/{ws}/scans/{id}/blackbox-runs 返该数组；ScanSummary.bb_runs 透传简化版。*/
export interface BlackboxRunSummary {
  run_id: string;
  status?: string;
  started_at?: string;
  completed_at?: string;
  auth_ref?: { profile_id?: string | null };
  reason?: string | null;
  bb_phase?: string;
  // precheck 失败详情（scan_manager 落 session + update_blackbox_run extra 并入）：
  // RunFailureBanner 展示原始 verdict（如 "Target unreachable: ..."）。历史 run 无 -> 可选。
  bb_failure_point?: string | null;
  bb_failure_detail?: string | null;
  // 验证缺口信号（spec 2026-09-03 §7）：{vulnClass: gapCount}——run completed 但
  // 黑盒 agent 有未出结论条目时由融合收尾写入；续跑守卫据此放行。无缺口 → 缺席。
  verification_gaps?: Record<string, number>;
}

export interface ScanSummary {
  scan_id: string;
  scan_type: "whitebox" | "blackbox" | "correlation" | "mr";
  status: WorkspaceStatus | string;   // 归一后（终态优先 + heartbeat）
  created_at: number;                  // unix
  completed_at?: number | null;
  vuln_count: number;
  total_cost_usd?: number | null;
  cost_currency?: string | null;
  is_running: boolean;
  // temporal workflow 标识 {ws}-{scan_id}[-resume-N]（前端「扫描任务名」展示用，替代纯日期 scan_id）。
  // 旧后端不返 -> 可选，消费方 ?? scan_id 兜底。
  workflow_id?: string;
  // Phase 1 额外聚合字段（兼容，spec §4.2 未列但 scan_store 已产出）
  vuln_counts?: Record<string, number>;
  total_duration_ms?: number | null;
  links?: { parent_workspace?: string | null; child_workspaces?: string[] };
  is_correlation?: boolean;
  // IA 重设计 §3：跨 ws 聚合（GET /api/scans）注入的归属工作区名。per-ws listScans 不返此字段。
  workspace?: string;
  // 组合扫描（spec 2026-08-12 §6.2）：白盒+黑盒一键组合，scan_type 仍是 whitebox，靠 session.combined 标记。
  // combined=true 时卡片收起显 progress_pct + 阶段名（bb_phase 映射），展开按需读 events 推步级。
  // 纯白盒/纯黑盒不返这些字段 -> 可选，消费方 null-safe（非 combined 走原单段渲染，零回归）。
  combined?: boolean;
  bb_phase?: string;        // precheck | pending | running | completed | failed | skipped
  bb_reason?: string;       // 失败/跳过原因（precheck fail / skipped 无产物 等）
  progress_pct?: number;    // 后端预算（三阶段加权，spec §9.2）；前端只显示不重算
  // 版本化黑盒 run（spec 2026-08-14 §5.2）：任务级索引 bb_runs[] + latest_bb_run。
  // combined 任务透传；纯白盒/纯黑盒不返 -> 可选。
  bb_runs?: BlackboxRunSummary[];
  latest_bb_run?: string | null;
  // 仓库维度（概览重设计 2026-08-14）：repo=仓库名标签（scan_id 前缀同源）、
  // repo_url=git 来源地址（session.web_url）。旧后端不返 -> 可选，消费方 '—' 兜底。
  repo?: string | null;
  repo_url?: string | null;
  // 分支快照（spec 2026-08-21 §4）：提交扫描时仓库当前 branch/commit。切分支后
  // 同一仓扫不同分支靠此区分来源；存量报告/黑盒不返 -> 可选，消费方不显示。
  repo_branch?: string | null;
  repo_commit?: string | null;
  // 跨仓关联血缘（C2，spec 2026-08-24）：correlation 主行 session.corr_children 透传
  // （scan_manager 提交子仓时写 {service, scan_id, reused}）。非 correlation scan 不返
  // -> 可选，消费方 null-safe。
  corr_children?: { service: string; scan_id: string; reused: boolean }[] | null;
  // MR 增量扫描 refs（spec 2026-09-03 §6）：session.mr_base_ref/mr_head_ref 透传。
  // 列表「MR」徽标 base..head 标识 + 重跑预填用；非 MR 扫描不返 -> 可选。
  mr_base_ref?: string | null;
  mr_head_ref?: string | null;
  // merged 改道把手（2026-09-04）：session.mr_head_commit/mr_base_commit 透传，
  // 重跑预填沿用；未写 -> 可选。
  mr_head_commit?: string | null;
  mr_base_commit?: string | null;
}

export interface SessionMetrics {
  // 以下字段运行时可能缺失:session.py create_workspace 初始仅写 {"agents":{}},
  // normalize_metrics 不补 phases/totals(phases 透传不动);pre-recon 产出后才齐。
  // 故全可选,消费方(OverviewTab)须 null-safe —— Object.entries/keys(x ?? {})。
  total_duration_ms?: number;
  total_cost_usd?: number;
  cost_currency?: string;
  total_input_tokens?: number; total_output_tokens?: number;
  total_cache_read_tokens?: number; total_cache_creation_tokens?: number;
  // 阶段集动态（NodeGoat: pre-recon/recon/vulnerability-analysis/reporting）
  phases?: Record<string, {
    duration_ms: number; duration_percentage: number; cost_usd: number; agent_count: number;
    // 最终态失败的 unique agent 数（2026-09-01 聚合含失败 agent）；旧 session
    // 无此字段 → ?? 0 = 全成功展示（现行为）。
    failed_agent_count?: number;
    cost_currency?: string;
    input_tokens?: number; output_tokens?: number; cache_read_tokens?: number; cache_creation_tokens?: number;
  }>;
  agents?: Record<string, {
    duration_ms: number; cost_usd: number; cost_currency?: string; success: boolean;
    attempt_number: number; model: string; error?: string;
    input_tokens?: number; output_tokens?: number; cache_read_tokens?: number; cache_creation_tokens?: number;
  }>;
}

export interface SessionData {
  web_url?: string; repo_path?: string; created_at?: number;
  // 服务端墙钟基准（unix 秒）——_scan_detail 返 time.time()。前端用它做时钟 offset 校正
  // （server_now*1000 - Date.now()），消除浏览器/服务端时钟不同步时「总耗时负数」的根因。
  server_now?: number;
  scan_type?: string;
  status?: string;                // 顶层（可能未回写）
  completed_at?: number | null;
  links?: { parent_workspace?: string | null; child_workspaces?: string[] };
  metrics?: SessionMetrics;
  session?: { status?: string; createdAt?: string; id?: string };  // 嵌套旧格式
  workflow_id?: string;  // temporal workflow 标识（ScanDetail header 任务名展示）
  // 组合扫描字段（_scan_detail 透传 session.json，spec 2026-08-12 §6.2/§9.2）：
  // ScanDetail 据此渲染两段时间线 + 黑盒失败续跑入口。纯白盒/纯黑盒不返（undefined）。
  combined?: boolean | null;
  bb_phase?: string | null;        // precheck | pending | running | completed | failed | skipped
  bb_reason?: string | null;
  // precheck/编排失败详情（_scan_detail 透传 session.json）：任务级失败横幅展示。
  // 历史扫描无此键 -> null，横幅降级为只显示 reason 分类。
  bb_failure_point?: string | null;
  bb_failure_detail?: string | null;
  // 进度分母/分子（_scan_detail 透传）：expected_agents.whitebox>0 且 completed_agents
  // 空 + status=completed → 假完成警告横幅（2026-08-27 事故：白盒从未启动却被收口
  // completed，报告全空用户无从排查）。旧后端/纯白盒可能缺 -> 可选。
  expected_agents?: { whitebox?: number; blackbox?: number } | null;
  completed_agents?: string[] | null;
  progress_pct?: number | null;
  // 重跑预填用（_scan_detail 补返）：白盒 repo 名 / 黑盒复用白盒 scan_id / 黑盒登录配置。
  source_repo?: string | null;
  reuse_whitebox_scan_id?: string | null;
  authentication?: ScanAuthentication | null;
  // auth-profile-vault（Task 14）：profile 模式重跑预填（后端已返，读 bb_auth_ref）。
  // 与 authentication 互斥。
  auth_profile_id?: string | null;
  // 组合扫描黑盒目标（session.json bb_url 透传）：列表「重跑」预填 url + combined 开关。
  bb_url?: string | null;
  // 多角色子集（2026-08-06）：profile 模式选多个角色，空=全选该档案所有角色。
  auth_credential_ids?: string[] | null;
  // HOST source for new-scan rerun; resolved mappings remain scan-scoped and are not exposed.
  host_profile_id?: string | null;
  // 多选（2026-09-11）：完整档案 id 列表（旧任务 detail 只有单数字段 → 后端包数组）。
  host_profile_ids?: string[];
  host_url?: string | null;
  host_source?: "profile" | "url" | null;
  host_mapping_count?: number;
  // 版本化黑盒 run（spec 2026-08-14 §5.2）：详情透传任务级 bb_runs[] + latest_bb_run。
  bb_runs?: BlackboxRunSummary[];
  latest_bb_run?: string | null;
  // MR 增量扫描 refs（spec 2026-09-03 §6）：重跑预填 base/head（非 MR 不返）。
  mr_base_ref?: string | null;
  mr_head_ref?: string | null;
  // merged 改道把手（2026-09-04）：重跑预填实际扫描 commit 对（未写 -> 分支名模式）。
  mr_head_commit?: string | null;
  mr_base_commit?: string | null;
}

export type MergeSource = "llm-only" | "gitnexus-only" | "both" | string;

export interface Vulnerability {
  ID: string;
  vulnerability_type: string;
  externally_exploitable: boolean;
  confidence?: string;
  title?: string;            // 一句话描述性标题（spec 2026-08-06）；空时退化 vulnerability_type
  source_endpoint?: string;
  vulnerable_code_location?: string;
  vulnerable_parameter?: string;
  merge_source?: MergeSource;       // exploitation_queue 独有
  missing_defense?: string;
  exploitation_hypothesis?: string;
  suggested_exploit_technique?: string;
  notes?: string;
  // exploitation_queue 里常 null 的字段（保留可选）
  evidence_chain?: unknown; source_track?: unknown;
  witness_payload?: string | null; path?: string | null; verdict?: string | null;
}

/** 漏洞危害等级（前端推断，非后端权威字段——见 lib/vuln-block.ts inferSeverity）。 */
export type Severity = "Critical" | "High" | "Medium" | "Low";

/** 从 markdown `### XXX-VULN-NN` 块解析出的单个 kv 字段。 */
export interface ParsedVulnField {
  key: string;
  val: string;
}

/**
 * 从报告 markdown 解析出的单个漏洞块（`### XXX-VULN-NN — 标题` + 后续 kv-list + witness fenced code）。
 * 由 splitByVulnBlocks + parseVulnBlock 产出，供报告渲染（MarkdownView 按严重度着色 + 完整原始 markdown 渲染）、inferSeverity 推断等级。
 */
export interface ParsedVulnBlock {
  id: string;                       // "XSS-VULN-04"
  prefix: string;                   // "XSS"（ID 前缀，用于类型着色）
  title: string;                    // 标题描述（去 ★ 后）
  starred: boolean;                 // 标题含 ★ 首要标记
  vulnType: string;                 // vulnerability_type 字段值
  fields: ParsedVulnField[];        // 块内 kv-list
  witnessPayload?: string;          // fenced code 内容（PoC）
  externallyExploitable: boolean | null;
  authRequired: boolean | null;
  confidence: string | null;        // 归一化小写：high | med | low | null
  verdict: string | null;
  raw: string;                      // 原始块 markdown（调试）
}

// === report_data.json（spec 2026-08-26-report-generation-agent-design §4，T6）===
// 三轨（whitebox/blackbox/combined）统一报告 SSOT：GET .../report-data 返回，前端
// ReportView 组件族纯渲染（不做解析/推断/归并）。字段名与 core pydantic schema
// （models/report_data.py）严格一致，snake_case 直传不改名；agent 产物字段全部
// 可选（组装时 LLM 步骤可能未跑/失败，报告永远完整产出）。

/** 扫描元信息。 */
export interface ReportScanMeta {
  id: string;
  track: "whitebox" | "blackbox" | "combined" | string;
  repo?: string | null;
  date?: string | null;
  duration_ms?: number | null;
  cost?: number | null;
  currency?: string | null;
  model?: string | null;
  // MR 增量扫描元信息（spec 2026-09-03 §6）：builder 从 intermediate/mr/ 补；
  // 全量扫描为 null。
  base_commit?: string | null;
  head_commit?: string | null;
  diff_stat?: { files?: number; insertions?: number; deletions?: number } | null;
}

/** 接口一体表行：接口 + 参数 + 认证 + 三处行号（file:line）。 */
export interface EndpointEntry {
  method?: string | null;
  path: string;
  role?: string | null;            // write/trigger/read
  auth?: string | null;            // isLoggedIn/public/isAdmin
  params: string[];
  route_registered_at?: string | null;
  source_location?: string | null;
  sink_location?: string | null;
}

/** 完整可复现 HTTP 请求（POC 增强 agent 产物；黑盒为实际发出的请求）。 */
export interface PocRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string | null;
}

/** 预期响应特征（判定依据）。 */
export interface PocExpectedResponse {
  indicator: string;
  success_criteria?: string | null;
}

/** POC 块——双轨共用（白盒 poc-agent 直产文本 / 黑盒重放证据转录）。
 *  白盒（2026-08-27-poc-agent-direct-design）：curl/raw_http/steps 是 agent 原文
 *  透传；self_check 为正确性自检结论（pass|fail）；expected_response 为 string。
 *  黑盒：request 对象 + expected_response 对象（PocExpectedResponse）+ curl/
 *  raw_http 由 request 确定性导出（复制/导出用）。 */
export interface PocBlock {
  curl?: string | null;
  raw_http?: string | null;
  steps?: string[];
  preconditions?: string | null;
  self_check?: string | null;
  notes?: string | null;
  request?: PocRequest | null;
  expected_response?: string | PocExpectedResponse | null;
}

/** 卡片叙事三段（cause=成因/impact=危害/remediation=修复建议，md 文本）。 */
export interface VulnNarrative {
  cause?: string | null;
  impact?: string | null;
  remediation?: string | null;
}

/** 问题点三要素（spec 2026-08-26-vuln-card-seven-sections §3 节 3）：位置 + 说明 +
 *  代码片段。endpoint 富化 agent 读源码产出，builder 纯透传（不合成不推断）。 */
export interface ProblemPoint {
  location: string;
  description?: string | null;
  snippet?: string | null;
}

/** 黑盒验证单步（生成层结构化）：action + command（可复制人工复验）+ result。 */
export interface VerifyStep {
  action: string;
  command?: string | null;
  result?: string | null;
}

/** 验证证据：verification=dynamic 时 dynamic_evidence 为黑盒实测输出（突出显示）。 */
export interface VulnEvidence {
  verification: "static" | "dynamic";
  dynamic_evidence?: string | null;
  /** 黑盒验证步骤（新采集结构化 / 旧落盘归一化）；白盒 static 轨为空。 */
  steps?: VerifyStep[];
  verdict?: string | null;
  code_snippet?: string | null;
  notes?: string | null;
}

/** 报告漏洞卡（queue SSOT 条目的报告视图超集；severity 由数据带出，前端不推断）。 */
export interface ReportVulnerability {
  id: string;
  type: string;                    // injection/xss/ssrf/auth/authz
  vulnerability_type?: string | null;
  title?: string | null;
  severity?: string | null;        // critical/high/medium/low
  confidence?: string | null;      // high/needs_review/unadjudicated
  cvss?: string | null;
  cwe_id?: string | null;
  owasp_category?: string | null;
  externally_exploitable?: boolean | null;
  authentication_required?: string | null;
  merge_source?: string | null;    // both/llm-only/gitnexus-only
  merged_from: string[];           // ①归并终审产物（跨轨同洞合并）
  narrative?: VulnNarrative | null;
  problem_points?: ProblemPoint[];   // 旧 report_data 无此字段 → 渲染兜底链（endpoints 行号 + evidence.code_snippet）
  endpoints: EndpointEntry[];
  affected_entries: Record<string, unknown>[];
  dataflow_steps: Array<{ label?: string | null; file?: string | null; line?: number | null; protection?: string | null } & Record<string, unknown>>;
  poc?: PocBlock | null;
  evidence?: VulnEvidence | null;
  attack_chain_refs: string[];
  // MR 增量来源标注（spec 2026-09-03 §6）：只标 GitNexus 轨可归因发现（C>B>A 归并）；
  // LLM 轨产物与全量扫描为 null。
  trigger_source?: "new_code" | "new_entry" | "removed_protection" | null;
}

/** 执行摘要「最高风险发现」单条。 */
export interface ReportTopRisk {
  vuln_id: string;
  reason?: string | null;
  priority?: "P0" | "P1" | null;
}

/** ④执行摘要 agent 产物（组装期缺省；LLM 失败回退确定性摘要）。 */
export interface ReportExecutiveSummary {
  narrative?: string | null;
  risk_level?: string | null;
  top_risks: ReportTopRisk[];
  remediation_order?: string | null;
}

/** 单类型聚合（确定性，组装器算——零计数类型也在数据里，前端不补全）。 */
export interface ReportTypeStats {
  count: number;
  severity_range?: string | null;
  key_findings?: string | null;
  /** 融合轨分列数（该类白盒/黑盒报告各自卡数）；单轨为 null——
   *  两字段都非 null 才渲染「白盒 N · 黑盒 M」。 */
  whitebox_count?: number | null;
  blackbox_count?: number | null;
}

export interface ReportStatsData {
  by_type: Record<string, ReportTypeStats>;
  by_severity: Record<string, number>;
}

/** ⑤QA agent 产物：失败不阻塞（qa.passed=false 显式呈现）。 */
export interface ReportQA {
  passed: boolean;
  checks: Array<{ check: string; failed_ids: string[] }>;
  reworked_ids: string[];
}

/** 漏洞速查表行（spec 2026-08-26-report-single-source-rendering §5）：builder 确定性
 *  产（vulnerabilities + affected_parameters），前端与 md 都只渲染不派生。 */
export interface QuickReferenceRow {
  id: string;
  title?: string | null;
  params: string[];
  endpoints: string[];
  severity?: string | null;
  verification?: string | null;
  confidence?: string | null;
}

/** MR 增量摘要 · 新增入口行（来源 B 攻击面明细；join miss 只留 func_block_id）。 */
export interface MrNewEntryPoint {
  func_block_id: string;
  function?: string | null;
  route?: string | null;
  method?: string | null;
  authentication?: string | null;
}

/** MR 增量摘要 · 删除防护行（来源 C；followed_by_chains=false 函数被删未追链供人审）。 */
export interface MrRemovedProtection {
  file: string;
  line: number;
  kind: string;
  function?: string | null;
  rationale?: string | null;
  followed_by_chains: boolean;
}

/** MR 增量扫描报告顶部摘要段（spec 2026-09-03 §6；仅 MR 扫描出现）。 */
export interface IncrementalSummary {
  degraded: boolean;
  new_entry_points: MrNewEntryPoint[];
  removed_protections: MrRemovedProtection[];
  flow_counts: {
    new_code?: number;
    new_entry?: number;
    removed_protection?: number;
    affected_flows?: number;
  };
}

/** 顶层 SSOT。attack_chains 步骤为自由 dict（组装器透传）。 */
export interface ReportData {
  schema_version: number;
  scan: ReportScanMeta;
  executive_summary?: ReportExecutiveSummary | null;
  stats?: ReportStatsData | null;
  vulnerabilities: ReportVulnerability[];
  attack_chains: Array<{ id: string; steps?: Record<string, unknown>[]; narrative?: string | null }>;
  quick_reference?: QuickReferenceRow[];
  // 验证缺口清单（spec 2026-09-03-blackbox-verification-gap-traceability）：
  // 融合报告产 [{vuln_id, reason}]——reason 是真实成因（中断元数据/端点痕迹/
  // 登记被拒拒因/未跑类）。纯白盒报告无此字段。
  verification_gaps?: Array<{ vuln_id: string; reason?: string | null }>;
  qa?: ReportQA | null;
  // MR 增量扫描专属（spec 2026-09-03 §6）；全量扫描为 null。
  incremental_summary?: IncrementalSummary | null;
}

export interface DeliverablesFile {
  path: string;        // 相对 deliverables/{track}/ 的路径
  size: number;
  kind: "md" | "exploitation_queue" | "llm_queue" | "gitnexus_queue"
      | "empty_json" | "big_json" | "other_json" | "other";
  // tiering（spec 2026-08-18）：intermediate = 管线中间产物（FileTree 收进折叠组）。
  // 旧后端数据无此字段 → 按 deliverable 处理（兼容）。
  tier?: "deliverable" | "intermediate";
}

export interface DeliverablesSummary {
  // 组合扫描三桶（spec §10）：combined_report.md 存在时 backend _infer_track 返 "combined"。
  track: "whitebox" | "blackbox" | "combined";
  files: DeliverablesFile[];
  // 聚合用：跨所有 *_exploitation_queue.json 的 vulnerabilities
  aggregated_vulnerabilities: Vulnerability[];
  notes?: { injection_has_no_queue?: boolean };
}

// === 数据流视图（spec 2026-08-20 §3，对齐 core services/dataflow_view.py 产出 schema）===
// 写时组装产物：5 类 intermediate + LLM queue → dataflow_view.json（schema_version=1）。
// 字段名与 core assemble_dataflow_view 返回值严格一致（snake_case）。
/** taint 树中间节点（propagation step）。有故事的步（transformation 非空 / sanitizer
 *  所在步）才存 code；纯透传步 has_code=false。LLM 枝节点无源码 → has_code:false。 */
export interface DataflowNode {
  func: string | null;
  /** LLM 枝叙事句原句（label 归一为短标识符后全文进此，tooltip/明细行消费）。 */
  note?: string | null;
  file: string | null;
  line: number | null;
  transformation?: string | null;
  intermediate_vars: string[];
  code?: string | null;
  has_code: boolean;
}
/** 枝 sanitizer：effective 语义=枝 verdict（safe→有效 / vulnerable→无效 / unknown→null）。 */
export interface DataflowSanitizer {
  name: string | null;
  defense_type?: string | null;
  file?: string | null;
  line?: number | null;
  effective: boolean | null;
}
/** 枝 source（入口/存储起点）。2ND 枝 type="storage"，write 侧 file:line 并入 label。 */
export interface DataflowSource {
  label: string | null;
  /** LLM 枝叙事句原句（label 归一后全文进此）。 */
  note?: string | null;
  type: string | null;            // "storage" | entry source_type | null
  entry?: string | null;
  file?: string | null;
  line?: number | null;
}
/** 数据流枝（一条 source→sink 传播路径）。track=gitnexus 来自 chain_verdicts；
 *  llm 来自 exploitation_queue 自述 steps；2ND-* 枝 track=gitnexus source.type=storage。 */
export interface DataflowBranch {
  branch_id: string | null;
  track: "gitnexus" | "llm";
  verdict: "vulnerable" | "safe" | "unknown";
  verdict_reason?: string | null;
  source: DataflowSource;
  nodes: DataflowNode[];
  sanitizers: DataflowSanitizer[];
}
/** 漏洞聚合条目（挂在树 findings[]，跨轨去重后）。 */
export interface DataflowFinding {
  id: string | null;
  merge_source?: string | null;
  title?: string | null;
  confidence?: string | null;
  witness_payload?: string | null;
  mismatch_reason?: string | null;
}
/** sink 元信息（树粒度=sink）。GN 侧有 rule_id/category/code；LLM 自立树只有位置。 */
export interface DataflowSink {
  label: string | null;
  /** LLM 自立树叙事句原句（label 归一后全文进此）。 */
  note?: string | null;
  file: string | null;
  line: number | null;
  rule_id?: string | null;
  category?: string | null;
  code?: string | null;
}
/** taint 树（injection/xss/ssrf）：一个 sink 一棵树，挂 GN + LLM + 2ND 枝 + findings。 */
export interface DataflowTree {
  tree_id: string;
  vuln_class: string;
  sink: DataflowSink;
  findings: DataflowFinding[];
  branches: DataflowBranch[];
}
/** auth/authz 关卡链节点（status ∈ ok/missing/ineffective，非树形）。 */
export interface ControlChainStep {
  label: string | null;
  status: "ok" | "missing" | "ineffective";
  detail?: string | null;
  file?: string | null;
  line?: number | null;
}
/** auth/authz 防护位关卡链（control_findings，非 taint 树）。 */
export interface ControlFinding {
  id: string | null;
  vuln_class: string;
  endpoint: string | null;
  chain: ControlChainStep[];
}
/** 顶层 safe_vectors 区（未匹配到 sink 树的 LLM 安全向量，去重后）。 */
export interface SafeVector {
  subject: string | null;
  location: string | null;
  defense_mechanism: string | null;
  render_context?: string | null;
}
/** 数据流视图顶层 schema（GET /workspaces/{ws}/scans/{id}/dataflow）。
 *  全产物缺 → 后端 404（不产文件）；有任一产物 → schema_version=1 + summary/trees/... */
export interface DataflowView {
  schema_version: number;
  summary: {
    total_sinks: number;
    vulnerable_sinks: number;     // findings 非空的树数
    safe_only_sinks: number;     // branches 非空但 findings 空的树数
  };
  trees: DataflowTree[];
  control_findings: ControlFinding[];
  safe_vectors: SafeVector[];
}

// ── 对抗性审查（spec 2026-09-10 对抗审查阶段；core adversarial_review 产物）──

export interface ReviewEvidence { location: string; snippet?: string; note?: string }
export interface DimensionResult {
  dimension: string; rebutted: boolean; reason?: string | null;
  evidence?: ReviewEvidence[];
}
export interface ReviewRecord {
  vuln_class: string; finding_id: string; reviewed_at?: string;
  before?: Record<string, unknown>;
  review_verdict: "refuted" | "survived" | "unreviewed";
  dimension_results: DimensionResult[];
  failed_dimensions: string[];
  rebuttal_reason?: string | null;
  survival_reason?: string | null;
  evidence?: ReviewEvidence[];
  confidence?: string | null;
  after?: { action?: string } | null;
}
export interface AdversarialReview {
  summary: { total: number; refuted: number; survived: number; unreviewed: number };
  records: ReviewRecord[];
}

// ── 接口证据矩阵（spec 2026-09-10 §4；core api_evidence_matrix.py 产物）──

export interface EvidenceFinding {
  id: string | null;
  vuln_class: string | null;
  severity: string | null;
  confidence: string | null;
  title: string | null;
  evidence_chain: string | null;
  witness_payload: string | null;
  verdict: string | null;
  mismatch_reason: string | null;
  params: string[];
  auth_required: string | null;
  source_location: string | null;
  sink_location: string | null;
  role?: string | null;
}

export interface EvidenceSafeVector {
  subject: string | null;
  defense_mechanism: string | null;
  location: string | null;
  contains_live_probe: boolean;
}

export interface EvidenceDismissed {
  ID: string | null;
  vuln_class: string | null;
  title: string | null;
  dismiss_reason: string | null;
  dismissed_at_stage: string | null;
}

export interface EvidenceVerdict {
  vulnerability_id: string | null;
  vuln_class: string | null;
  status: string | null;
  severity: string | null;
  impact: string | null;
  exploitation_steps: string[];
  proof_of_impact: string | null;
  run_id: string | null;
}

export interface EvidenceEndpoint {
  method: string;
  path: string;
  raw_route: string | null;
  func_block_id: string | null;
  entry_verdict: string | null;
  entry_evidence: string | null;
  whitebox: {
    findings: EvidenceFinding[];
    safe: EvidenceSafeVector[];
    dismissed: EvidenceDismissed[];
  };
  blackbox: {
    verdicts: EvidenceVerdict[];
    rejected: Record<string, unknown>[];
  };
  coverage: "findings" | "defended" | "clean";
}

export interface EvidenceMatrix {
  schema_version: number;
  scan_id: string | null;
  generated_at: string | null;
  sources: Record<string, unknown>;
  endpoints: EvidenceEndpoint[];
  unmatched: {
    findings: Record<string, unknown>[];
    safe_dismissed: Record<string, unknown>[];
    verdicts: Record<string, unknown>[];
  };
  note?: string | null;
}

// === 跨仓关联视图（spec 2026-08-24，对齐 web api/scans.py assemble_correlation_detail，Task C5）===
// GET /workspaces/{ws}/scans/{id}/correlation 返回值；422=非 correlation scan。
// 缺文件语义（关联未跑完）：topology/report_md → null、boundaries/flows → []、
// {vc}_exploitation_queue.json 缺 → merged_vulns 键缺席（前端显「进行中/未开始」）。
// 产物 schema 同源：core correlation/schemas.py（Call/TopologyEdge/TrustBoundary/CrossServiceFlow）。
/** 拓扑边上的单次跨服务调用证据（schemas.py Call）。 */
export interface CorrCall {
  method: string;
  call_site: { file: string; line: number; snippet: string };
  confidence: string;
  evidence: string;
}
/** 候选跨服务攻击链（schemas.py CrossServiceFlow）：前端仓入口 → RPC method → 后端仓漏洞。 */
export interface CorrFlow {
  edge_from: string;
  edge_to: string;
  entry: string;
  method: string;
  call_site: { file: string; line: number; snippet: string };
  vuln_refs: { vuln_id?: string; service: string; title: string;
               severity: string; location: string;
               source?: string; invalid_ref?: boolean }[];
  confidence: string;
  evidence: string;
}
/** 多跳候选链（spec 2026-08-27 §6.2）：边邻接启发拼装，basis/confidence 显式标注。 */
export interface CorrMultiHopChain {
  path: string[];
  basis: string;
  confidence: string;
}
/** 裁决卡（spec 2026-08-27 §7.3）：双向留证——正反结论同构带完整证据链。 */
export interface AdjudicationCard {
  direction: "upgrade" | "downgrade" | "confirm" | "maintain" | "error" | string;
  finding_ref: { service: string; vuln_id: string; origin: string };
  conclusion: string;
  cross_service_context: string;
  analysis_process: string[];
  verification_evidence: { repo: string; location: string;
                           snippet: string; note: string }[];
  reasoning: string;
  confidence: string;
}
export interface AdjudicationLog {
  cards?: AdjudicationCard[];
  error?: string;
}
/** merged_vulns 单项：{vc}_exploitation_queue.json 的 vulnerabilities 元素（宽松 dict）。 */
export interface CorrVuln {
  title: string;
  description?: string;
  severity?: string;
  location?: string;
  service?: string;
  [k: string]: unknown;
}
export interface CorrelationDetail {
  topology: { services: { name: string; role: string; repo: string }[];
              edges: { from: string; to: string; protocol: string; status: string;
                       calls: CorrCall[]; error?: string | null }[] } | null;
  boundaries: { service: string; method: string; exposure: string;
                reachable_from: string[]; reason: string; confidence: string }[];
  flows: CorrFlow[];
  multi_hop_chains: CorrMultiHopChain[];
  adjudication: AdjudicationLog | null;
  merged_vulns: Record<string, CorrVuln[]>;
  // 首版保守恒 []（后端不解析 correlation-report.md；后续版本从事件/report 提取）。
  drift_warnings: unknown[];
  corr_children: { service: string; scan_id: string; reused: boolean }[];
  report_md: string | null;
}

/** 多仓配置摘要（GET /api/multi-configs）。backend MultiRepoConfigStore.list_configs()
 *  返 list[str]——仅配置名（已排序），无对象元数据，故摘要即 string（勿包 {name} 壳）。 */
export type MultiConfigSummary = string;

// === Cross-repository topology pre-analysis (candidate graph before scan submission) ===
export type CorrelationTopologyStatus =
  | "queued" | "running" | "completed" | "failed" | "cancelled" | "interrupted";

export interface CorrelationTopologyEvidence {
  repo: string;
  file: string;
  line?: number | null;
  snippet?: string;
  kind?: "client" | "handler" | "config" | "capability" | string;
  valid?: boolean | null;
  validation_errors?: string[];
}

export interface CorrelationTopologyNode {
  repo: string;
  roles: Array<"entrypoint" | "backend">;
  capabilities?: Array<{
    role: "entrypoint" | "backend";
    confidence: "high" | "medium" | "low";
    evidence: CorrelationTopologyEvidence[];
  }>;
}

export interface CorrelationTopologyEdge {
  from: string;
  to: string;
  protocol: "grpc" | "http" | "graphql";
  confidence?: "high" | "medium" | "low";
  service?: string | null;
  method?: string | null;
  client_evidence?: CorrelationTopologyEvidence[];
  handler_evidence?: CorrelationTopologyEvidence[];
}

export interface CorrelationTopologyResult {
  nodes: CorrelationTopologyNode[];
  edges: CorrelationTopologyEdge[];
  uncertain: Array<{
    repo: string;
    message: string;
    protocol_hint?: string | null;
    evidence?: CorrelationTopologyEvidence[];
  }>;
  coverage: Array<{ repo: string; complete: boolean; reason?: string }>;
  invalid?: Array<{ reason: string; message: string; raw?: Record<string, unknown> }>;
  raw?: CorrelationTopologyResult | null;
}

export interface CorrelationTopologyUsage {
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens?: number;
  cache_creation_tokens?: number;
  cost_usd: number;
  cost_currency: string;
  model?: string | null;
  turns?: number;
}

export interface CorrelationTopologyAnalysis {
  analysis_id: string;
  workspace: string;
  status: CorrelationTopologyStatus;
  repos: string[];
  progress?: number;
  cache_hit?: boolean;
  fingerprint?: string;
  result?: CorrelationTopologyResult | null;
  usage?: CorrelationTopologyUsage | null;
  error?: { code: string; message: string; retryable?: boolean } | null;
  created_at?: string;
  updated_at?: string;
}

/** 拓扑预分析过程日志行（tool-audit.ndjson 尾读，服务端已裁剪成一行摘要）。 */
export interface TopologyAuditLine {
  no: number;
  ts?: string;
  type: "tool_start" | "tool_end" | "assistant_turn" | "error" | "unparsed";
  tool?: string;
  summary: string;
}

export interface TopologyAuditTail {
  lines: TopologyAuditLine[];
  next: number;
}

/** 黑盒登录配置（对齐 core Authentication schema：models/config.py:29-45）。
 *  字段名（snake_case）与后端 pydantic 模型一致——scan_manager Authentication.model_validate 校验。*/
export interface ScanAuthentication {
  login_type: "form" | "sso" | "api" | "basic";
  login_url: string;
  credentials: {
    username: string;
    password?: string;
    totp_secret?: string;
    email_login?: { address: string; password: string; totp_secret?: string };
  };
  login_flow?: string[];
}

// === 认证档案库（auth-profile-vault, Task 10 契约）===
// 对齐 backend auth_profile_store / auth_profiles.py 响应 payload。
export type VerifyState = "unverified" | "running" | "success" | "failed";
export interface VerifyStatus {
  state: VerifyState;
  // engine = LLM 引擎/provider 调用失败（与目标站登录无关，2026-08-17 起）；
  // no_verdict = agent 跑完但无结构化结论（内部值，见 auth_profile_store.VerifyStatus）；
  // cancelled = 用户主动停止测试（auth-test-cancel，2026-08-17 起）。
  failure_point?: "username_or_password" | "totp_secret" | "out_of_band" | "engine" | "no_verdict" | "cancelled";
  failure_detail?: string;
  last_verified_at?: string;
  // 块3c：最近一次验证的 probe 目录 + workflow_id（verify-log 定位 + 下次覆盖清理）。
  probe_dir?: string;
  workflow_id?: string;
}
export interface AuthProfileCredential {
  id: string;
  role: string;
  username: string;
  password?: string;        // GET 返 "••••" if 有值（后端不回传明文）
  totp_secret?: string;
  email_login?: { address: string; password?: string; totp_secret?: string };
  verify_status: VerifyStatus;
}
export interface AuthProfile {
  id: string;
  name: string;
  login_url: string;
  login_type: "form" | "sso" | "api" | "basic";
  login_flow?: string[];
  credentials: AuthProfileCredential[];
  created_at?: string;
  updated_at?: string;
  scope?: "workspace" | "system";  // system = configs seed 的全局共享只读档案
}

// === HOST 档案库（blackbox-host-profile, Task 9-11 契约）===
// 对齐 backend host_profile_store / host_profiles.py 响应 payload。
// mappings: domain→IP 的 hosts 映射，黑盒扫描时注入 agent-browser 代理 / DNS 覆盖。
export interface HostMapping {
  ip: string;
  host: string;
}
export interface HostProfile {
  id: string;
  name: string;
  source_url?: string | null;   // 生成来源的 /etc/hosts 风格文本 URL（null=手填）
  mappings: HostMapping[];
  scope?: "workspace" | "system";  // system = 全局共享只读档案（configs seed）
  created_at?: string;
  updated_at?: string;
}

export interface ScanRequest {
  type: "whitebox" | "blackbox" | "correlation" | "mr";
  // 扫描入口已收窄为「工作区已下载仓库」——本地路径入口移除（source.kind 恒为 repo）。
  source?: { kind: "repo"; value: string };
  url?: string;
  // MR 增量扫描（spec 2026-09-03）：type="mr" 必填 base/head ref（分支名或 commit sha）。
  base_ref?: string;
  head_ref?: string;
  // MR merged 改道（2026-09-04）：源分支已删的已合并 MR 的 commit 把手（后端同名字段）。
  head_commit?: string;
  base_commit?: string;
  // final-review C2: 字段名必须与 backend ScanRequest (models.py) 一致 = `workspace`。
  // pydantic v2 默认不容未知键, 旧 `workspace_name` 会被静默丢弃 -> req.workspace=None -> 422。
  workspace?: string;
  // 黑盒「复用白盒结果」：指定要复用的白盒 scan_id（工作区内某个 whitebox scan）。
  // 黑盒恒复用白盒结果（exploitation-only），此字段必填；无 repo/standalone 分支。
  reuse_whitebox_scan_id?: string;
  // 黑盒登录配置（仅 blackbox + auth.enabled 时发送）。后端写 scan-config.yaml → blackbox workflow
  // config_path → run_blackbox_auth_validation（agent-browser 登录 + auth-state 落盘）。
  authentication?: ScanAuthentication;
  // 认证档案库（auth-profile-vault）：黑盒复用已验证的登录档案，免每次手填。
  // 后端按 auth_profile_id 加载档案、按 auth_credential_ids 选 credentials[] 中哪些角色
  // （空=全选该档案所有角色）。与上方 `authentication?` 互斥（二者全无时黑盒按 unauthenticated 处理）。
  auth_profile_id?: string;
  auth_credential_ids?: string[];
  // inline 多角色附加账号（#2，2026-08-07）：与 authentication 同存，每条 {role,username,password,totp_secret?}。
  // 后端 scan_manager 展开成 accounts[]（多身份对比）；仅 inline 模式（authentication 存在）时合法。
  auth_accounts?: { role: string; username: string; password: string; totp_secret?: string }[];
  // HOST 档案库（blackbox-host-profile）：黑盒扫描时选 HOST 档案注入 domain→IP 映射
  // （agent-browser --proxy 覆盖 DNS），或 host_url 临时拉取一份 /etc/hosts 风格文本。
  // host_profile_ids（2026-09-11 多选）：多档案后端合并 mappings；单选也走此复数字段。
  host_profile_id?: string;
  host_profile_ids?: string[];
  host_url?: string;
  config_name?: string;
  // correlation（spec 2026-08-24，backend models.py 已有——D2 漏加的前端类型补齐）：
  // 多仓拓扑 YAML 内容（与 config_name 二选一，前端表单直发派生 YAML）。
  config_content?: string;
  // 可选：提交时把 config_content 另存为命名配置（multi-config store）。
  save_as?: string;
  // 扫完即删（2026-09-10）：勾选后扫描到任意终态由 web 仓库级 sweep 删除对应仓库
  //（correlation 传播给本次新建子仓；linked 仓后端不处理）。仅 true 时发送（默认不发键）。
  delete_repo_on_finish?: boolean;
}

export interface ScanResponse {
  workspace: string;
  // ws-scan 解耦（spec §5.2）：POST /api/scan 的 ScanAccepted 增 scan_id。
  // 可选--过渡期 Phase 1 未上线时后端不返 scan_id，前端 F4 回退跳旧 ws-scoped live 路由。
  scan_id?: string;
  // 组合扫描（Task 9，spec §8.2）：后端 passthrough 的黑盒阶段标记。白盒+url 组合提交后，
  // 后端先跑黑盒认证预验证——此时 bb_phase="precheck"；前端据此显「预验证中」态。
  // 纯白盒/纯黑盒不返此字段（undefined）。
  bb_phase?: "precheck" | "running" | "done" | string;
}

/** 批量白盒扫描（2026-09-11）：POST /api/scan/batch——N 个仓库共享其余白盒配置，
 *  各自产生独立扫描。字段名与 backend models.py BatchScanRequest 一致。 */
export interface BatchScanRequest {
  workspace: string;
  repos: string[];
  url?: string;
  authentication?: ScanAuthentication;
  auth_accounts?: { role: string; username: string; password: string; totp_secret?: string }[];
  auth_profile_id?: string;
  auth_credential_ids?: string[];
  host_profile_id?: string;
  host_profile_ids?: string[];
  host_url?: string;
  delete_repo_on_finish?: boolean;
}

export interface BatchScanResultItem {
  repo: string;
  ok: boolean;
  scan_id?: string;
  error?: string;
}

/** 批量提交汇总：202（部分/全部成功）与全失败 422 的 body 同为此顶层形状
 *  （422 无 detail 包裹——spec §3.3 要求前端在全失败时也展示全部失败明细）。 */
export interface BatchScanResponse {
  workspace: string;
  submitted: number;
  failed: number;
  results: BatchScanResultItem[];
}

/** 批量取消/续跑单项结果（2026-09-15）：skipped=true 为服务端状态门前置筛掉
 *  （未触副作用），与「尝试了但失败」区分——横幅分别计数。 */
export interface ScanBatchResultItem {
  scan_id: string;
  ok: boolean;
  skipped?: boolean;
  error?: string;
}

/** 批量取消/续跑汇总：202（部分/全部成功）与零成功 422（全跳过/全失败）的 body
 *  同为此顶层形状（无 detail 包裹，对齐 BatchScanResponse 契约）。 */
export interface ScanBatchResponse {
  workspace: string;
  submitted: number;
  skipped?: number;
  failed: number;
  results: ScanBatchResultItem[];
}

export interface FsEntry {
  name: string;
  type: "dir" | "file";
  size?: number;
  mtime?: number;
}
export interface FsBrowseResult {
  path: string;
  parent: string | null;
  entries: FsEntry[];
  truncated?: boolean;
}

export type RepoState = "ready" | "cloning" | "pulling" | "extracting" | "failed" | "stale" | "empty";

export interface Repo {
  name: string;
  group?: string | null;  // 分组名（如 frontend/backend）；扁平仓库为 null
  /** kind=upload：拖拽上传的 zip。zip 自带 .git 时 url/branch/commit 呈现真实远端信息
   *  （凭据剥净）；可切本地分支（不走远端），但不可 pull（凭据未进 ws auth，更新=重新上传）。 */
  source?: { kind: "git" | "linked" | "upload" | "unknown" | string; url?: string; branch?: string; commit?: string };
  state: RepoState;
  /** 关联仓库（admin 按绝对路径关联的已存在目录，非本 ws 私有克隆）→ true；只读（禁 pull/checkout）。 */
  linked?: boolean;
  size_bytes?: number;
  cloned_at?: string;
  last_pull_at?: string;
  last_error?: string | null;
  progress?: number | null;
}

/** 统一链接解析结果（POST /workspaces/{ws}/resolve-link，2026-09-03 仓库入口整合 A 段）：
 *  kind=mr 附 base_ref/head_ref（GitLab API 查回的 target/source 分支）；
 *  repo_state=cloning 表示仓库不在工作区、后端已异步触发 clone（前端轮询 repos 至 ready）。
 *  merged 改道（2026-09-04）：已合并 + 源分支已删的 MR 附 mr_merged=true + head_commit
 *  （merge_commit_sha 把手）+ base_commit（FF 形态 diff_refs.base_sha；true merge 为 null，
 *  worker 解 first-parent）——提交时透传，表单显示改道提示。 */
export interface ResolveLinkResult {
  kind: "mr" | "repo";
  repo: string;
  repo_state: "ready" | "cloning";
  base_ref?: string;
  head_ref?: string;
  mr_merged?: boolean;
  head_commit?: string;
  base_commit?: string | null;
}

export interface RepoDetail extends Repo {
  recent_events?: Array<Record<string, unknown>>;
}

/** 批量克隆结果（POST /workspaces/{ws}/repos/batch-clone，2026-09-09）：
 *  submitted=已提交后台 clone 的仓库名；queued=撞并发上限、由后端排队任务
 *  补位提交的仓库名（稍后出现在列表 cloning 态）；skipped=跳过明细
 *  （reason: exists=目录已存在 / duplicate=输入重复）。 */
export interface BatchCloneResult {
  submitted: string[];
  queued: string[];
  skipped: Array<{ url: string; reason: "exists" | "duplicate" | string }>;
}
