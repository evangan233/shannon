import type {
  BlackboxRunSummary, CorrelationDetail, DataflowView, FsBrowseResult,
  MultiConfigSummary, Repo, RepoDetail, ScanRequest, ScanSummary, SessionData,
  CorrelationTopologyAnalysis, TopologyAuditTail,
} from "./types";

export class ApiError extends Error {
  constructor(public status: number, public body: unknown) {
    super(`API ${status}`);
    this.name = "ApiError";
  }
}

export type ReqOptions = { silent?: boolean; signal?: AbortSignal };

function defaultUnauthorizedHandler(): void {
  // 已在 /login 时不重复跳转--防 BrandProvider 等全局组件在未登录 /login 页发
  // 非 silent 401 -> assign("/login?expired=1") -> 整页刷新 -> 重新 mount -> 循环
  // （login 页"一直在重复刷新"的根治防御）。
  if (window.location.pathname === "/login") return;
  window.location.assign("/login?expired=1");
}
let onUnauthorized: () => void = defaultUnauthorizedHandler;
export function setUnauthorizedHandler(fn: () => void) {
  onUnauthorized = fn;
}
export function resetUnauthorizedHandler() {
  onUnauthorized = defaultUnauthorizedHandler;
}

function readCookie(name: string): string | null {
  const m = document.cookie.match(
    new RegExp("(?:^|; )" + name.replace(/([.$?*|{}()[\]\\/+^])/g, "\\$1") + "=([^;]*)"),
  );
  return m ? decodeURIComponent(m[1]) : null;
}

const WRITE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

async function request<T>(path: string, init?: RequestInit, opts?: ReqOptions): Promise<T> {
  const method = init?.method?.toUpperCase();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...((init?.headers as Record<string, string>) ?? {}),
  };
  if (method && WRITE_METHODS.has(method)) {
    const tok = readCookie("sn-csrf");
    if (tok) headers["X-CSRF-Token"] = tok;
  }
  const res = await fetch(`/api${path}`, {
    ...init,
    headers,
    credentials: "include",
    signal: opts?.signal,
  });
  if (!res.ok) {
    if (res.status === 401 && !opts?.silent) onUnauthorized();
    // 单次 text() 后再 parse：json() 失败时 body stream 已被消费，fallback 再
    // text() 会抛 "body stream already read"（500 纯文本/代理 502 HTML 必踩），
    // 掩盖真实状态码（2026-09-03 __legacy__ 自动关联分析 500 回归）。
    const text = await res.text();
    let body: unknown = text;
    try {
      body = JSON.parse(text);
    } catch {
      /* 非 JSON 错误体保留原文 */
    }
    throw new ApiError(res.status, body);
  }
  // 204/无 body
  const text = await res.text();
  return (text ? JSON.parse(text) : {}) as T;
}

export const apiGet = <T>(path: string, opts?: ReqOptions) => request<T>(path, undefined, opts);
export const apiPost = <T>(path: string, body: unknown, opts?: ReqOptions) =>
  request<T>(path, { method: "POST", body: JSON.stringify(body) }, opts);
export const apiPut = <T>(path: string, body: unknown, opts?: ReqOptions) =>
  request<T>(path, { method: "PUT", body: JSON.stringify(body) }, opts);
export const apiDelete = <T>(path: string, opts?: ReqOptions) =>
  request<T>(path, { method: "DELETE" }, opts);
export const apiPatch = <T>(path: string, body: unknown, opts?: ReqOptions) =>
  request<T>(path, { method: "PATCH", body: JSON.stringify(body) }, opts);

export const browseFs = (path: string) =>
  apiGet<FsBrowseResult>(`/fs/browse?path=${encodeURIComponent(path)}`);
export const createWorkspace = (name: string) =>
  apiPost<{ name: string }>("/workspaces", { name });
export const deleteWorkspace = (ws: string) =>
  apiDelete<{ deleted: string }>(`/workspaces/${encodeURIComponent(ws)}`);
export type CancelResult = { cancelled: string; via?: string; was_dead?: boolean };
// ws-scan 解耦：cancelScan 走 scan-scoped POST /cancel（动作型 POST，对齐 resume POST；
// DELETE /scans/{id} 已让位给真删除）。ws 列表行只有 ws 名、无 scan_id -> 用 cancelActiveScan
// 先 listScans 解析出在跑的 scan 再取消。
export function cancelScan(ws: string, scanId: string): Promise<CancelResult> {
  return apiPost<CancelResult>(`/workspaces/${encWs(ws)}/scans/${encWs(scanId)}/cancel`, {});
}

/** 取消该 ws 正在跑的 scan（ws 列表行用：无 scan_id，先 listScans 找 active/latest running，再 scan-scoped 取消）。
 *  对齐旧 DELETE /api/scan/{ws} shim 语义（cancel latest/active）。无在跑 scan -> 抛错（对应旧 shim 的 404）。 */
export async function cancelActiveScan(ws: string): Promise<CancelResult> {
  const scans = await listScans(ws);
  const active = scans.find((s) => s.is_running || s.status === "running");
  if (!active) {
    throw new Error("该工作区当前无在跑的扫描");
  }
  return cancelScan(ws, active.scan_id);
}

/** 仓库名（可为 group/repo）按段 encode：保留 `/` 作路径分隔，每段安全转义。
 *  /workspaces/<ws>/repos/frontend/foo 直接命中后端 {name:path}，含空格等特殊字符的段也安全。 */
const encRepo = (name: string) => name.split("/").map(encodeURIComponent).join("/");

/** workspace 名整体 encode（不允许 `/`，作为单段 path 参数）。 */
const encWs = (ws: string) => encodeURIComponent(ws);

// P2: 仓库已迁到 ws 内——所有 repo API 路径前置 /workspaces/<ws>，对齐后端
//     POST/GET/DELETE /api/workspaces/{ws}/repos[/{name:path}] (+ /pull, /checkout, /events)
export const listRepos = (ws: string) =>
  apiGet<Repo[]>(`/workspaces/${encWs(ws)}/repos`);
export const getRepo = (ws: string, name: string) =>
  apiGet<RepoDetail>(`/workspaces/${encWs(ws)}/repos/${encRepo(name)}`);
export const createRepo = (
  ws: string,
  body: { git_url: string; branch?: string; commit?: string; name?: string; group?: string },
) => apiPost<{ name: string }>(`/workspaces/${encWs(ws)}/repos`, body);

/** 批量克隆（2026-09-09）：贴多条 git URL 一次全下。202 立即返回汇总——
 *  clone 均为后端后台任务（列表轮询可见 cloning → ready），撞并发上限的余量
 *  由后端排队任务补位提交（queued），HTTP 不悬挂。 */
export const batchClone = (ws: string, body: { urls: string[]; group?: string }) =>
  apiPost<import("./types").BatchCloneResult>(`/workspaces/${encWs(ws)}/repos/batch-clone`, body);

/** 统一链接解析（2026-09-03 仓库入口整合 A 段）：仓库/MR 链接 → 匹配工作区仓库
 *  （不存在则后端异步 clone，repo_state="cloning"）；MR 附 base/head refs。 */
export const resolveLink = (ws: string, url: string) =>
  apiPost<import("./types").ResolveLinkResult>(`/workspaces/${encWs(ws)}/resolve-link`, { url });

/** 批量关联父目录下所有 git 仓库。admin-only；返回 {imported, skipped}。 */
export const linkReposInDir = (ws: string, body: { path: string }) =>
  apiPost<{ imported: { name: string; path: string }[]; skipped: { name?: string; path: string; reason: string }[] }>(
    `/workspaces/${encWs(ws)}/repos/link-dir`, body);

/** 上传 zip 添加仓库（所有成员，与 clone 一致）。返回 202 {name}——解压 + git 快照在
 *  后端后台进行（state=extracting → ready，列表轮询/SSE 可见进度）。
 *  fetch 无上传进度，故用 XHR；multipart 不手设 Content-Type（浏览器自动带 boundary）。 */
export function uploadRepoZip(
  ws: string,
  file: File,
  opts: { name?: string; group?: string } = {},
  onProgress?: (pct: number) => void,
): Promise<{ name: string }> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", `/api/workspaces/${encWs(ws)}/repos/upload`);
    xhr.withCredentials = true;
    const tok = readCookie("sn-csrf");
    if (tok) xhr.setRequestHeader("X-CSRF-Token", tok);
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable && onProgress) onProgress(Math.round((e.loaded / e.total) * 100));
    };
    xhr.onload = () => {
      let body: unknown = null;
      try { body = JSON.parse(xhr.responseText); } catch { /* 非 JSON 错误体 */ }
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(body as { name: string });
      } else {
        if (xhr.status === 401) onUnauthorized();
        reject(new ApiError(xhr.status, body));
      }
    };
    xhr.onerror = () => reject(new Error("network error"));
    xhr.onabort = () => reject(new Error("aborted"));
    const fd = new FormData();
    fd.append("file", file);
    if (opts.name) fd.append("name", opts.name);
    if (opts.group) fd.append("group", opts.group);
    xhr.send(fd);
  });
}
export const deleteRepo = (ws: string, name: string) =>
  apiDelete<{ deleted: string }>(`/workspaces/${encWs(ws)}/repos/${encRepo(name)}`);

export type BatchDeleteResult = {
  deleted: string[];
  unlinked: string[];
  skipped: { name: string; reason: string }[];
};

/** 批量删除/取消关联：私有克隆→删除目录，关联仓→取消关联（不删源文件）。
 *  names 走 request body（非 path 段），含 group/repo 形态直接传字符串数组。 */
export const deleteRepos = (ws: string, names: string[]) =>
  apiPost<BatchDeleteResult>(`/workspaces/${encWs(ws)}/repos/batch-delete`, { names });
export const pullRepo = (ws: string, name: string) =>
  apiPost<{ pulling: string }>(`/workspaces/${encWs(ws)}/repos/${encRepo(name)}/pull`, {});
export const checkoutRepo = (ws: string, name: string, branch: string) =>
  apiPost<{ checked_out: string }>(`/workspaces/${encWs(ws)}/repos/${encRepo(name)}/checkout`, { branch });

/** 列远端分支（ls-remote --heads，spec 2026-08-21 §2a）：分支列 combobox 数据源。 */
export const listBranches = (ws: string, name: string) =>
  apiGet<{ branches: string[] }>(`/workspaces/${encWs(ws)}/repos/${encRepo(name)}/branches`);

/** CloneProgress SSE 路径——client 这层不直接消费（CloneProgress 自管 useEventSource），
 *  暴露给组件层用，避免各处再写一遍 ws+name 拼接。 */
export const repoEventsUrl = (ws: string, name: string) =>
  `/api/workspaces/${encWs(ws)}/repos/${encRepo(name)}/events`;

// === ws-scan 解耦（spec §5.1）：scan-scoped API helper ===
// scan_id 是 ws 内单段（YYYYMMDD-HHMMSS[-N]，不含 `/`），用 encWs 单段 encode 即安全。
// Path helper 返不含 /api 前缀的 path（喂 apiGet/apiGetText，内部加 /api）；
// scanEventsUrl 返含 /api 完整 URL（喂 EventSource，对齐 repoEventsUrl 约定）。

/** 列该 ws 的 scans（ScanSummary[]，按 created_at 倒序）。 */
export const listScans = (ws: string) =>
  apiGet<ScanSummary[]>(`/workspaces/${encWs(ws)}/scans`);

/** 跨 ws 聚合所有 scans（IA 重设计 §3，GET /api/scans）。返回项注入 workspace 字段。 */
export const listAllScans = () => apiGet<ScanSummary[]>("/scans");

/** 置顶当前用户的工作区（IA 重设计 §2.3，PUT /api/users/me/pinned-workspace）。 */
export const setPinnedWorkspace = (ws: string) =>
  apiPut<{ pinned: string }>("/users/me/pinned-workspace", { workspace: ws });

/** scan 详情（同旧 GET /workspaces/{ws} payload shape，读 scan_dir）。 */
export const getScan = (ws: string, scanId: string) =>
  apiGet<SessionData>(`/workspaces/${encWs(ws)}/scans/${encWs(scanId)}`);

/** 综合报告 + PoC（text/plain）path--喂 apiGetText。
 *  track 可选（spec 2026-08-12 §10.1 三视图）：组合扫描传 whitebox/blackbox/combined
 *  分别取该桶报告；不传（纯白盒/纯黑盒）走 backend auto-infer（零回归）。 */
export const scanReportPath = (ws: string, scanId: string, track?: "whitebox" | "blackbox" | "combined") =>
  track
    ? `/workspaces/${encWs(ws)}/scans/${encWs(scanId)}/report?track=${track}`
    : `/workspaces/${encWs(ws)}/scans/${encWs(scanId)}/report`;

/** 产物摘要（无 file）或单产物文件内容（带 file path）--摘要喂 apiGet，文件喂 apiGetText。 */
export const scanDeliverablesPath = (ws: string, scanId: string, file?: string) =>
  file
    ? `/workspaces/${encWs(ws)}/scans/${encWs(scanId)}/deliverables?path=${encodeURIComponent(file)}`
    : `/workspaces/${encWs(ws)}/scans/${encWs(scanId)}/deliverables`;

/** 日志文件列表（无 file）或单日志内容（带 file）--都喂 apiGet。 */
export const scanLogsPath = (ws: string, scanId: string, file?: string) =>
  file
    ? `/workspaces/${encWs(ws)}/scans/${encWs(scanId)}/logs?file=${encodeURIComponent(file)}`
    : `/workspaces/${encWs(ws)}/scans/${encWs(scanId)}/logs`;

/** 黑盒 run 日志文件列表（无 file）或单日志内容（带 file）--组合任务 LogsTab 黑盒侧用。 */
export const blackboxRunLogsPath = (ws: string, scanId: string, runId: string, file?: string) =>
  file
    ? `/workspaces/${encWs(ws)}/scans/${encWs(scanId)}/blackbox-runs/${encWs(runId)}/logs?file=${encodeURIComponent(file)}`
    : `/workspaces/${encWs(ws)}/scans/${encWs(scanId)}/blackbox-runs/${encWs(runId)}/logs`;

/** scan events SSE URL（tail scan_dir/events.ndjson）--喂 EventSource，含 /api 前缀。 */
export const scanEventsUrl = (ws: string, scanId: string) =>
  `/api/workspaces/${encWs(ws)}/scans/${encWs(scanId)}/events`;

/** 恢复未完成 scan（仅非终态放行，终态后端 422）。返回对齐 ScanAccepted 风格。 */
export type ResumeResult = { workspace: string; scan_id: string };
export const resumeScan = (ws: string, scanId: string) =>
  apiPost<ResumeResult>(`/workspaces/${encWs(ws)}/scans/${encWs(scanId)}/resume`, {});

/** 断点详情（spec 2026-08-27-web-resume-breakpoint §4.5，只读）：
 *  agent 对账（completed_agents/interrupted_agent/warnings）+ step 缓存简表
 *  （done/stale/missing）+ resumable 判定（false 带 reason/abort_reason）。 */
export type ResumePreviewStep = {
  step: string;
  state: "done" | "stale" | "missing";
  ts?: number | null;
  reason?: string | null;
};
export type ResumePreview = {
  status: string;
  resumable: boolean;
  reason: string | null;
  scan_type: string;
  completed_agents: string[];
  interrupted_agent: string | null;
  steps: ResumePreviewStep[];
  warnings: string[];
  abort_reason: string | null;
  /** 瞬态不可续（取消收尾窗口，心跳判活未过期）——前端据此定时重拉，窗口一过自动转出按钮 */
  transient?: boolean;
  resume_attempts: number;
};
export const getResumePreview = (ws: string, scanId: string) =>
  apiGet<ResumePreview>(`/workspaces/${encWs(ws)}/scans/${encWs(scanId)}/resume-preview`);

/** 组合扫描黑盒续跑（spec §11.3 / D5）：黑盒 failed 后换认证续跑，复用白盒产物。
 *  body 可选——无 body 沿用原认证；有 body（ScanRequest）换认证。前端只 POST 不读 body。 */
export const rerunBlackbox = (ws: string, scanId: string) =>
  apiPost<{ workspace: string; scan_id: string; run_id?: string }>(
    `/workspaces/${encWs(ws)}/scans/${encWs(scanId)}/combined/rerun-blackbox`, {});

// ── 版本化黑盒 run（spec 2026-08-14 §5.2/§7.1）───────────────────────────────
/** run 列表（GET /blackbox-runs，从任务 session bb_runs[]）。 */
export const listBlackboxRuns = (ws: string, scanId: string) =>
  apiGet<BlackboxRunSummary[]>(
    `/workspaces/${encWs(ws)}/scans/${encWs(scanId)}/blackbox-runs`);

/** 单 run 详情（GET /blackbox-runs/{run_id}，读 run 级 session）。 */
export const getBlackboxRun = (ws: string, scanId: string, runId: string) =>
  apiGet<BlackboxRunSummary & Record<string, unknown>>(
    `/workspaces/${encWs(ws)}/scans/${encWs(scanId)}/blackbox-runs/${encWs(runId)}`);

/** 给已有白盒任务加一个黑盒 run（POST /blackbox-runs）。body=空对象=无认证直连。 */
export const addBlackboxToWhitebox = (ws: string, scanId: string, body?: Partial<ScanRequest>) =>
  apiPost<{ workspace: string; scan_id: string; run_id: string }>(
    `/workspaces/${encWs(ws)}/scans/${encWs(scanId)}/blackbox-runs`, body ?? {});

/** 删单个黑盒 run（DELETE /blackbox-runs/{run_id}，spec §7.1 #4）。运行中 run 后端返 409。 */
export const deleteBlackboxRun = (ws: string, scanId: string, runId: string) =>
  apiDelete<{ deleted: string }>(
    `/workspaces/${encWs(ws)}/scans/${encWs(scanId)}/blackbox-runs/${encWs(runId)}`);

/** run 级报告 path（喂 apiGetText）。track=combined 读 combined/run-K/combined_report.md。 */
export const blackboxRunReportPath = (
  ws: string, scanId: string, runId: string, track?: "blackbox" | "combined") =>
  track === "combined"
    ? `/workspaces/${encWs(ws)}/scans/${encWs(scanId)}/blackbox-runs/${encWs(runId)}/report?track=combined`
    : `/workspaces/${encWs(ws)}/scans/${encWs(scanId)}/blackbox-runs/${encWs(runId)}/report`;

// ── report_data.json（spec 2026-08-26 §7.1，T6）───────────────────────────────
// 结构化报告 SSOT（三轨统一 schema），前端 ReportView 纯渲染的优先数据源；
// 旧 scan 无产物时端点 404 → ReportTab 回退上方 md 渲染路径。

/** scan 级 report-data path（喂 apiGet，JSON）。track=whitebox|blackbox；
 *  combined 是 per-run 产物，走 blackboxRunReportDataPath。 */
export const scanReportDataPath = (
  ws: string, scanId: string, track: "whitebox" | "blackbox") =>
  `/workspaces/${encWs(ws)}/scans/${encWs(scanId)}/report-data?track=${track}`;

/** run 级 report-data path：track=combined 读 combined/run-K/report_data.json；
 *  默认 track 读 run 黑盒桶。 */
export const blackboxRunReportDataPath = (
  ws: string, scanId: string, runId: string, track: "blackbox" | "combined" = "blackbox") =>
  track === "combined"
    ? `/workspaces/${encWs(ws)}/scans/${encWs(scanId)}/blackbox-runs/${encWs(runId)}/report-data?track=combined`
    : `/workspaces/${encWs(ws)}/scans/${encWs(scanId)}/blackbox-runs/${encWs(runId)}/report-data`;

/** run 级产物摘要（无 file）或单产物（带 file）path。 */
export const blackboxRunDeliverablesPath = (
  ws: string, scanId: string, runId: string, file?: string) =>
  file
    ? `/workspaces/${encWs(ws)}/scans/${encWs(scanId)}/blackbox-runs/${encWs(runId)}/deliverables?path=${encodeURIComponent(file)}`
    : `/workspaces/${encWs(ws)}/scans/${encWs(scanId)}/blackbox-runs/${encWs(runId)}/deliverables`;

// ── 产物下载（FileStage 下载按钮）──────────────────────────────────────────────
// 后端同端点 ?download=1 → FileResponse 附件（磁盘原文：无 preview_limit 截断、
// big_json/empty_json/other 也可下）。cookie 认证自动附带（GET 无 CSRF），
// URL 含 /api 前缀直接喂 <a href>（与 scanEventsUrl 的完整 URL 约定一致）。

/** scan 级产物文件下载 URL。 */
export const scanDeliverablesDownloadUrl = (ws: string, scanId: string, file: string) =>
  `/api${scanDeliverablesPath(ws, scanId, file)}&download=1`;

/** run 级产物文件下载 URL（run 视图，selectedRun 非空时用）。 */
export const blackboxRunDeliverablesDownloadUrl = (
  ws: string, scanId: string, runId: string, file: string) =>
  `/api${blackboxRunDeliverablesPath(ws, scanId, runId, file)}&download=1`;

/** run events SSE URL（tail run-K/events.ndjson）。 */
export const blackboxRunEventsUrl = (ws: string, scanId: string, runId: string) =>
  `/api/workspaces/${encWs(ws)}/scans/${encWs(scanId)}/blackbox-runs/${encWs(runId)}/events`;

// ── 数据流视图（spec 2026-08-20 §3）───────────────────────────────────────────
// GET /workspaces/{ws}/scans/{id}/dataflow → dataflow_view.json（写时组装产物）。
// 全产物缺 → 后端 404（不产文件）；fetcher 抛 ApiError(404)，消费方据此显空态。
export const fetchDataflowView = (ws: string, scanId: string) =>
  apiGet<DataflowView>(`/workspaces/${encWs(ws)}/scans/${encWs(scanId)}/dataflow`);

// ── 跨仓关联视图（spec 2026-08-24，Task C5 后端）───────────────────────────────
// GET /workspaces/{ws}/scans/{id}/correlation → assemble_correlation_detail 产物。
// 404=scan 不存在；422=非 correlation scan；产物未生成时各字段 null/[]（前端显
// 「关联阶段进行中/未开始」）。
export function getCorrelationDetail(ws: string, scanId: string): Promise<CorrelationDetail> {
  return apiGet<CorrelationDetail>(`/workspaces/${encWs(ws)}/scans/${encWs(scanId)}/correlation`);
}

// === Cross-repo topology pre-analysis lifecycle ===
export function startCorrelationTopologyAnalysis(
  ws: string, body: { repos: string[]; refresh?: boolean },
): Promise<{ analysis_id: string }> {
  return apiPost<{ analysis_id: string }>(
    `/workspaces/${encWs(ws)}/correlation-topology/analyses`, body);
}
export function getCorrelationTopologyAnalysis(
  ws: string, analysisId: string,
): Promise<CorrelationTopologyAnalysis> {
  return apiGet<CorrelationTopologyAnalysis>(
    `/workspaces/${encWs(ws)}/correlation-topology/analyses/${encWs(analysisId)}`);
}
export function cancelCorrelationTopologyAnalysis(
  ws: string, analysisId: string,
): Promise<CorrelationTopologyAnalysis> {
  // 旧 DELETE 语义仍是「取消」；真删除走动作型 /delete，避免破坏既有客户端契约。
  return apiDelete<CorrelationTopologyAnalysis>(
    `/workspaces/${encWs(ws)}/correlation-topology/analyses/${encWs(analysisId)}`);
}
export function deleteCorrelationTopologyAnalysis(
  ws: string, analysisId: string,
): Promise<{ ok: true; analysis_id: string }> {
  return apiPost<{ ok: true; analysis_id: string }>(
    `/workspaces/${encWs(ws)}/correlation-topology/analyses/${encWs(analysisId)}/delete`, {});
}
// 过程日志尾读（after 行号游标增量；404=analysis 不存在，空 lines=未启动/无日志）
export function getTopologyAnalysisLog(
  ws: string, analysisId: string, after = -1,
): Promise<TopologyAuditTail> {
  return apiGet<TopologyAuditTail>(
    `/workspaces/${encWs(ws)}/correlation-topology/analyses/${encWs(analysisId)}/log?after=${after}`);
}
// 刷新恢复：最近一条 analysis；404=该 ws 从未发起过
export function getLatestTopologyAnalysis(ws: string): Promise<CorrelationTopologyAnalysis> {
  return apiGet<CorrelationTopologyAnalysis>(
    `/workspaces/${encWs(ws)}/correlation-topology/analyses/${encWs("latest")}`);
}
// 分析历史（摘要列表，created_at 降序；不含 result——选中条目经 getCorrelationTopologyAnalysis 拉全量）
export function listCorrelationTopologyAnalyses(ws: string): Promise<CorrelationTopologyAnalysis[]> {
  return apiGet<CorrelationTopologyAnalysis[]>(
    `/workspaces/${encWs(ws)}/correlation-topology/analyses`);
}

// ── 多仓配置（对齐 backend api/multi_configs.py + MultiRepoConfigStore）─────────
// GET /api/multi-configs → 配置名 list[str]（sorted）；POST 返 201 {name}
// （ValidationError→422 / 非法名→400）；GET /{name} → {name, content}（无 → 404）。
export function listMultiConfigs(): Promise<MultiConfigSummary[]> {
  return apiGet<MultiConfigSummary[]>("/multi-configs");
}
export function saveMultiConfig(name: string, content: string): Promise<{ name: string }> {
  return apiPost<{ name: string }>("/multi-configs", { name, content });
}
export function getMultiConfig(name: string): Promise<{ name: string; content: string }> {
  return apiGet<{ name: string; content: string }>(`/multi-configs/${encodeURIComponent(name)}`);
}

// ── 组合扫描阶段判定（live 阶段徽章 / report ?run= 用；events 流已全量归并）──────
// 2026-08-18 起 events 端点在后端按 ts 归并 认证/白盒/所有 run-K 为一条流，前端不再
// 按段切 URL；本集合仅回答「当前处于哪个段」（徽章文案 / 查看报告带 ?run=）。
const BLACKBOX_PHASES = new Set(["running", "completed", "failed", "skipped"]);

/** 组合扫描是否已进入黑盒段（徽章/报告入口按 run 维度展示）。 */
export function isBlackboxSegmentActive(opts: {
  combined?: boolean | null;
  bbPhase?: string | null;
  selectedRun?: string | null;
}): boolean {
  const { combined, bbPhase, selectedRun } = opts;
  return combined === true && !!selectedRun && !!bbPhase && BLACKBOX_PHASES.has(bbPhase);
}

/** 全量归并流 SSE URL（认证/白盒/黑盒 run-K 按 ts 归并，单一事实来源）。
 *  rev 仅用于强制重开流：服务端在「任务终态 + 全 run 终态 + 宽限」后关流，之后新增
 *  run（续跑/叠加）靠 rev 变化换 URL 重连，重放部分由前端 id 去重吸收。 */
export const mergedScanEventsUrl = (ws: string, scanId: string, rev?: number | string) =>
  scanEventsUrl(ws, scanId) + (rev !== undefined ? `?rev=${rev}` : "");

/** 删除单个 scan（删 scan 不删 ws，spec §5.1 DELETE）。 */
export const deleteScan = (ws: string, scanId: string) =>
  apiDelete<{ deleted: string }>(`/workspaces/${encWs(ws)}/scans/${encWs(scanId)}`);

// ── SSO（spec 2026-08-25 §5.2）：公开配置，登录页据此渲染 OA 登录按钮 ──────────
// silent：未登录 /login 页拉取，401/不可达不触发 session 过期整页跳转；
// 调用侧（LoginPage）catch 后按 disabled 处理（按钮不渲染，不阻塞账密登录）。
export const getSsoConfig = () => apiGet<{ enabled: boolean }>("/auth/sso/config", { silent: true });

/** report 端点返 text/plain，deliverables?path= 单文件内容也走文本。不做 JSON.parse。
 *  注：此端点不经统一 request()，故不带 CSRF/401 处理——仅为兼容现有 text 调用。 */
export async function apiGetText(path: string): Promise<string> {
  const res = await fetch(`/api${path}`, { credentials: "include" });
  if (!res.ok) throw new ApiError(res.status, await res.text());
  return res.text();
}

// === 全局扫描闸门（spec 2026-09-08-worker-scan-gate §8）：排队可视化 ===
export type ScanGateEntry = {
  workflow_id?: string;
  ws?: string;
  scan_id?: string;
  kind?: string;
  label?: string;
  since?: number;
};
export type ScanGateSnapshot = {
  capacity: number;
  max_waiting?: number;
  held: ScanGateEntry[];
  waiting: ScanGateEntry[];
};
/** 闸门快照（GET /api/scan/gate）：held=占槽者、waiting 按排队序（=位次）。 */
export const getScanGate = () =>
  apiGet<ScanGateSnapshot>("/scan/gate");
