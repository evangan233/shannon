import { useEffect, useRef, useState } from "react";
import { useNavigate, useSearchParams, useLocation } from "react-router-dom";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { toast } from "sonner";
import type { CorrelationTopologyAnalysis, ScanRequest, ScanResponse, TopologyAuditLine, Workspace, ScanAuthentication } from "../api/types";
import { apiGet, apiPost, ApiError, cancelCorrelationTopologyAnalysis, deleteCorrelationTopologyAnalysis, getCorrelationTopologyAnalysis, getLatestTopologyAnalysis, getTopologyAnalysisLog, listCorrelationTopologyAnalyses, startCorrelationTopologyAnalysis } from "../api/client";
import { useScans } from "../routes/WorkspaceDetail/useScans";
import { ScanFormFields } from "../components/ScanFormFields";
import { RepoCombobox } from "../components/RepoCombobox";
import { LinkResolveBox } from "../components/LinkResolveBox";
import { RefRangeInput } from "../components/RefRangeInput";
import { RepoQuickActions } from "../components/RepoQuickActions";
import type { ResolveLinkResult } from "../api/types";
import { useRepos } from "../api/useRepos";
import { CorrelationFormFields } from "../components/correlation/CorrelationFormFields";
import { CorrelationGraphTab } from "../components/correlation/CorrelationGraphTab";
import { CorrelationSourceRail } from "../components/correlation/CorrelationSourceRail";
import { CorrelationGatewayFields } from "../components/correlation/CorrelationGatewayFields";
import { TopologyConfirmBar } from "../components/correlation/TopologyConfirmBar";
import { YamlPanel } from "../components/correlation/YamlPanel";
import type { CredentialDraft } from "../components/auth/CredentialRows";
import { AlertCircle, Play } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/PageHeader";
import { GroupLabel } from "@/components/GroupLabel";
import { Card } from "@/components/ui/card";
import {
  formToYaml, yamlToForm, validateForm, CorrYamlError, type CorrFormState,
} from "@/lib/correlation-yaml";
import {
  confirmTopologyDraft, corrFormToTopologyDraft, createTopologyDraft, topologyDraftFingerprint,
  topologyDraftToCorrForm, updateTopologyRepositories, validateTopologyDraft,
  type TopologyDraftState,
} from "@/lib/correlation-topology-draft";
import { latestReusableScanId } from "@/lib/correlation-reuse";

/** 页面可达类型（D3）：白盒 | MR 增量 | 跨仓关联，顶部 segmented 切换（顺序=频率与
 *  表单复杂度，见下方 segmented 注释）。黑盒只读分支已删除——
 *  黑盒一律是组合任务的嵌套 run 或经 ScanDetail addBlackboxToWhitebox，无独立创建入口。 */
type ScanType = "whitebox" | "correlation" | "mr";

/** 跨仓关联三视图子页（2026-09-04 tabs 重组）：图 | 表单 | YAML——同一拓扑的三个透镜，
 *  实时三方同步；原 auto/manual 模式分页删除。 */
export type CorrView = "graph" | "form" | "yaml";

export type LoginType = "form" | "sso" | "api" | "basic";

/** 黑盒登录配置表单态（独立于 ScanAuthentication 契约：含 enabled 开关 + emailLoginEnabled
 *  + loginFlow 多行文本；buildBody 时 buildAuthPayload 转成 ScanAuthentication）。
 *
 *  auth-profile-vault（Task 14）：enabled=true 时按 `source` 切换两条来源——
 *    - "inline"：临时手填（即下方 loginType/loginUrl/credentials/loginFlow），buildBody 发 `authentication`。
 *    - "profile"：复用工作区已验证档案（profileId + credentialIds 指向 profile.credentials[] 哪些角色），
 *      buildBody 发 `auth_profile_id` + `auth_credential_ids`（与 `authentication` 互斥，后端 Task 7 XOR 校验）。
 *  enabled=false 时 source 无意义（关闭即不登录）。 */
export interface AuthFormState {
  enabled: boolean;
  /** enabled=true 时的来源分支（disabled 模式下无意义，默认 inline 保留兼容）。 */
  source: "inline" | "profile";
  /** profile 模式：选定的认证档案 id（GET /workspaces/{ws}/auth-profiles 列表中一项）。 */
  profileId: string;
  /** profile 模式：选定档案下哪些角色凭据 id（profile.credentials[] 子集；空=后端全选，前端默认全选）。 */
  credentialIds: string[];
  loginType: LoginType;
  loginUrl: string;
  /** inline 凭据（统一多角色）：accounts[0]=primary（不可删，默认 role="admin"）→ buildAuthPayload 发
   *  authentication.credentials；accounts.slice(1)=附加角色 → buildBody 发 auth_accounts（多身份对比）。 */
  accounts: CredentialDraft[];
  loginFlow: string; // textarea 多行；buildBody 时 split 成 string[]
}

export const DEFAULT_AUTH: AuthFormState = {
  enabled: false,
  // 默认使用档案（profile）——展开认证配置时优先复用工作区已验证档案，与 segmented 顺序一致（使用档案居左）。
  source: "profile",
  profileId: "",
  credentialIds: [],
  loginType: "form",
  loginUrl: "",
  accounts: [{ role: "admin", username: "", password: "" }],
  loginFlow: "",
};

/** HOST 解析表单态（blackbox-host-profile, Task 13）。镜像 AuthFormState 的双来源结构：
 *    - enabled=false：不起代理（向后兼容，直连目标）。
 *    - mode="profile"：复用工作区 HOST 档案（host_profile_id，Task 12 已落 backend）。
 *    - mode="url"：临时填 /etc/hosts 风格文本 URL（host_url，后端拉取解析为 mappings）。
 *  与 auth 独立（非互斥）——二者各管各的：auth 管登录态，host 管 DNS 覆盖。 */
export interface HostFormState {
  enabled: boolean;
  mode: "profile" | "url";
  /** profile 模式：选定的 HOST 档案 id（GET /workspaces/{ws}/host-profiles 列表中一项）。 */
  profileId: string;
  /** url 模式：/etc/hosts 风格文本 URL（后端 POST /parse?url=<URL> 拉取解析，不落盘）。 */
  hostUrl: string;
}

export const DEFAULT_HOST: HostFormState = {
  enabled: false,
  mode: "profile",
  profileId: "",
  hostUrl: "",
};

/** AuthFormState → ScanAuthentication（对齐后端 core Authentication schema，snake_case 字段名）。
 *  微调（2026-08-06）：inline 模式不再采集 email_login（删邮箱登录框）；role 仅用于存档不发。 */
export function buildAuthPayload(a: AuthFormState): ScanAuthentication {
  const primary = a.accounts[0];
  const credentials: ScanAuthentication["credentials"] = { username: (primary?.username ?? "").trim() };
  if (primary?.password) credentials.password = primary.password;
  const payload: ScanAuthentication = {
    login_type: a.loginType,
    login_url: a.loginUrl.trim(),
    credentials,
  };
  const flow = a.loginFlow.split("\n").map((s) => s.trim()).filter(Boolean);
  if (flow.length) payload.login_flow = flow;
  return payload;
}

/** ScanAuthentication -> AuthFormState（buildAuthPayload 的逆映射，供重跑预填黑盒登录配置）。
 *  始终返回 inline 模式（auth-profile-vault Task 14：profile 模式由 presetToAuthState 单独判定）。 */
export function authFromPayload(auth: ScanAuthentication): AuthFormState {
  const c = auth.credentials ?? { username: "" };
  return {
    enabled: true,
    source: "inline",
    profileId: "",
    credentialIds: [],
    loginType: auth.login_type ?? "form",
    loginUrl: auth.login_url ?? "",
    accounts: [{ role: "admin", username: c.username ?? "", password: c.password ?? "" }],
    loginFlow: Array.isArray(auth.login_flow) ? auth.login_flow.join("\n") : "",
  };
}

/** 重跑预填数据（ScanList.onRerun 经 location.state 传入，优先于 query param）。
 *  D3：黑盒只读分支已删——type:"blackbox" 的历史 preset 落到白盒渲染（不触发黑盒表单）。 */
export interface RerunPreset {
  type?: "whitebox" | "blackbox" | "correlation" | "mr";
  workspace?: string;
  repo?: string;
  url?: string;
  reuseScanId?: string;
  /** inline 模式登录配置（旧字段，与 authProfileId 互斥）。 */
  auth?: ScanAuthentication;
  /** 组合扫描标志（2026-09-03）：ScanList.onRerun 对组合任务（bb_url 非空）传 true——
   *  不传则 url 填了也被 buildBody 剥掉，重跑退化纯白盒、黑盒段丢失。 */
  combined?: boolean;
  /** profile 模式（auth-profile-vault Task 14）：原扫描使用了某条认证档案+角色，
   *  重跑时预填到 source=profile 分支。后端 _scan_detail 暂未返此字段（前端先就位）。 */
  authProfileId?: string;
  authCredentialIds?: string[];
  /** HOST 解析（Task 13）：原扫描启用了 HOST 解析，重跑时预填。
   *  hostProfileId 非空 → profile 模式；仅 hostUrl → url 模式；后端 _scan_detail 暂未返（前端先就位）。 */
  hostProfileId?: string;
  hostUrl?: string;
  /** MR 增量（spec 2026-09-03 §6）：原扫描的 base/head refs，重跑时预填。
   *  merged 改道（2026-09-04）：mrHeadCommit/mrBaseCommit 是实际扫描 commit 把手
   *  （源分支已删的已合并 MR），重跑预填沿用——仍按改道扫而非撞已删分支。 */
  mrBaseRef?: string;
  mrHeadRef?: string;
  mrHeadCommit?: string;
  mrBaseCommit?: string | null;
}

/** RerunPreset → AuthFormState：profile 模式（authProfileId 非空）优先于 inline（auth）。
 *  与 buildBody 一致：profile 模式发 auth_profile_id + auth_credential_ids（空数组=后端全选），
 *  inline 模式发 authentication。 */
export function presetToAuthState(preset: RerunPreset): AuthFormState {
  if (preset.authProfileId) {
    return {
      ...DEFAULT_AUTH,
      enabled: true,
      source: "profile",
      profileId: preset.authProfileId,
      credentialIds: preset.authCredentialIds ?? [],
    };
  }
  if (preset.auth) return authFromPayload(preset.auth);
  return DEFAULT_AUTH;
}

/** RerunPreset → HostFormState：profile 模式（hostProfileId 非空）优先于 url 模式（hostUrl）。
 *  与 buildBody 一致：profile 模式发 host_profile_id，url 模式发 host_url。 */
export function presetToHostState(preset: RerunPreset): HostFormState {
  if (preset.hostProfileId) {
    return { ...DEFAULT_HOST, enabled: true, mode: "profile", profileId: preset.hostProfileId };
  }
  if (preset.hostUrl) {
    return { ...DEFAULT_HOST, enabled: true, mode: "url", hostUrl: preset.hostUrl };
  }
  return DEFAULT_HOST;
}

function hostValidationKey(h: HostFormState): string | null {
  if (!h.enabled) return null;
  if (h.mode === "profile") {
    return h.profileId.trim() ? null : "scan.errors.hostProfileRequired";
  }
  const url = h.hostUrl.trim();
  if (!url) return "scan.errors.hostUrlRequired";
  try {
    const parsed = new URL(url);
    return parsed.protocol === "http:" || parsed.protocol === "https:"
      ? null
      : "scan.errors.hostUrlScheme";
  } catch {
    return "scan.errors.hostUrlScheme";
  }
}

/** HOST enabled state must always have a concrete, safe source. */
export function validateHost(h: HostFormState, t: TFunction): string | null {
  const key = hostValidationKey(h);
  return key ? t(key) : null;
}

export function validateAuth(a: AuthFormState, t: TFunction): string | null {
  if (!a.enabled) return null;
  // profile 模式：必须选定档案 + 至少一个角色（前端默认全选；取消全选则拦空）。
  // 错误文案用 scan.errors.auth{Profile,Credential}Required（与 ProfilePicker 的
  // SelectValue placeholder「选择认证档案/选择登录角色」不同文本，避免 getByText 多义）。
  if (a.source === "profile") {
    if (!a.profileId) return t("scan.errors.authProfileRequired");
    if (!a.credentialIds.length) return t("scan.errors.authCredentialRequired");
    return null;
  }
  if (!a.loginUrl.trim()) return t("scan.errors.authLoginUrlEmpty");
  if (!/^https?:\/\//.test(a.loginUrl.trim())) return t("scan.errors.authLoginUrl");
  // primary（accounts[0]）须用户名；附加角色（slice(1)）每条须用户名 + 密码（可登录），否则拦空。
  const primary = a.accounts[0];
  if (!primary || !primary.username.trim()) return t("scan.errors.authUsername");
  for (const acc of a.accounts.slice(1)) {
    if (!acc.username.trim() || !acc.password) return t("scan.errors.authAccountIncomplete");
  }
  return null;
}

/** 链接解析触发的下载监视（2026-09-03 仓库入口整合 B 段）：resolve-link 返回
 *  repo_state=cloning 时由页面挂起，轮询 SWR 共享 key ["repos", ws]（两张表单的
 *  仓库下拉同缓存，refresh 一处全局生效），repo 脱离忙态即停。
 *
 *  放页面级而非 LinkResolveBox 内：组件随表单切换卸载，提示与轮询态不能随之丢失。 */
const CLONE_POLL_MS = 2000;
const CLONE_BUSY_STATES = new Set(["cloning", "pulling", "extracting", "empty"]);

function CloneWatch({ workspace, name, onDone }: { workspace: string; name: string; onDone: () => void }) {
  const { repos, refresh } = useRepos(workspace || undefined);
  useEffect(() => {
    const target = repos.find((r) => r.name === name);
    if (target && !CLONE_BUSY_STATES.has(target.state)) {
      onDone();
      return;
    }
    const timer = window.setInterval(() => void refresh(), CLONE_POLL_MS);
    return () => window.clearInterval(timer);
  }, [repos, name, refresh, onDone]);
  // 纯轮询引擎：显示由表单的仓库 state 区承担（MR 表单 cloning 文案 / 白盒 CloneProgress），
  // 避免两处渲染同一文案。
  return null;
}

export interface FormState {
  /** 扫描仓库（白盒必选）。入口已收窄——仅工作区已下载仓库，无本地路径。 */
  selectedRepo: string;
  /** 白盒=组合扫描目标 URL；correlation=黑盒验证 gateway URL（CorrelationFormFields 的
   *  gatewayUrl 即此字段，避免新 state）。可选——空则纯白盒 / 纯关联。 */
  url: string;
  /** 历史「黑盒复用白盒」字段：黑盒分支已删（D3），仅为 ScanFormFields 兼容保留，不再提交。 */
  reuseScanId: string;
  /** 登录配置（组合扫描 / correlation gateway 非空时用）。 */
  auth: AuthFormState;
  /** HOST 解析（与 auth 独立，非互斥）。disabled=不起代理，向后兼容。 */
  host: HostFormState;
  yaml: string;
  /** 白盒「同时发起黑盒扫描」组合开关（Task 9）。可选——旧 FormState 字面量（如单测 baseF）不传 = false。
   *  true 时 buildBody whitebox 分支附 url + 认证字段，后端 Task 1 识别为组合扫描。 */
  combined?: boolean;
  /** MR 增量扫描（spec 2026-09-03）：type="mr" 用的 base/head ref（分支名或 commit sha）。
   *  merged 改道（2026-09-04）：mrHeadCommit 非空 = 按合入 commit 对扫描（源分支已删
   *  的已合并 MR）；mrBaseCommit 为 null 时 base 交给 worker 解 first-parent。 */
  mrBaseRef?: string;
  mrHeadRef?: string;
  mrHeadCommit?: string;
  mrBaseCommit?: string | null;
}

/** 将 AuthFormState 写入 ScanRequest 认证字段（auth-profile-vault 双来源）：
 *    - inline 模式 → authentication（+附加角色 auth_accounts）。
 *    - profile 模式 → auth_profile_id + auth_credential_ids（空数组=后端全选）。
 *  黑盒与白盒组合扫描共用（Task 9），保证两条分支字段映射一致。 */
function assignAuthToBody(body: ScanRequest, a: AuthFormState): void {
  if (a.source === "profile") {
    body.auth_profile_id = a.profileId || undefined;
    body.auth_credential_ids = a.credentialIds.length ? a.credentialIds : undefined;
  } else {
    body.authentication = buildAuthPayload(a);
    // 附加角色（accounts.slice(1)）→ auth_accounts（后端 scan_manager 展开成 accounts[]）。
    // guard 用 slice(1) 后长度：accounts[0] 恒为 primary，若用 accounts.length 会发空 auth_accounts:[]。
    const extra = a.accounts.slice(1);
    if (extra.length) {
      body.auth_accounts = extra.map((acc) => ({
        role: acc.role.trim() || "role",
        username: acc.username.trim(),
        password: acc.password,
      }));
    }
  }
}

/** 将 HostFormState 写入 ScanRequest 的 HOST 字段（与 assignAuthToBody 同款共享）：
 *    - profile 模式 -> host_profile_id；url 模式 -> host_url。
 *    - enabled 时发；disabled 不发（向后兼容——不起代理，直连目标）。
 *    - 空值兜底 || undefined（不发空串）。
 *  白盒组合扫描与 correlation（gateway url 开）共用，保证分支字段映射一致。HOST 与认证独立、非互斥。
 *  仅组合模式（combined && url）/correlation+url 调——纯白盒/纯关联（无 url）不发 host
 *  （无黑盒阶段，HOST 代理无意义）。 */
function assignHostToBody(body: ScanRequest, h: HostFormState): void {
  if (!h.enabled) return;
  if (h.mode === "profile") body.host_profile_id = h.profileId || undefined;
  else body.host_url = h.hostUrl || undefined;
}

/**
 * 构造 /scan 提交 body。
 * P2 (2026-07-26): `workspace` 来自父组件显式选定的 workspace（替代 pre-P1 的
 * 自动生成/可选 wsName 字段）。扫描目标 ws 必须是用户可访问的已有 ws（P1 已过滤）。
 *
 * final-review C2: 字段名必须与 backend `ScanRequest` (models.py) 一致 = `workspace`。
 * pydantic v2 默认不容未知键, 发 `workspace_name` 会被静默丢弃 -> req.workspace=None -> 422
 * （P2 final-review 抓到的 prod-blocking bug: 每个前端扫描提交都 422）。
 *
 * D3：黑盒分支已删（黑盒一律是组合任务嵌套 run）；correlation 分支重写——config_content
 * 必带（表单派生 YAML），gateway url（f.url）非空 = 段③黑盒验证，附认证/HOST
 * （与白盒组合扫描共用 assignAuthToBody/assignHostToBody，字段映射一致）。
 */
export function buildBody(type: ScanType, f: FormState, workspace: string, corrYaml = ""): ScanRequest {
  if (type === "mr") {
    // MR 增量扫描（spec 2026-09-03）：repo + base_ref/head_ref，纯白盒语义（无 url/认证/HOST）。
    // merged 改道（2026-09-04）：附 head_commit/base_commit——worker 按 commit 对定位增量
    //（源分支已删的已合并 MR）；base_commit null 省略（worker 解 first-parent）。
    const body: ScanRequest = { type, workspace: workspace || undefined };
    body.source = { kind: "repo", value: f.selectedRepo };
    body.base_ref = f.mrBaseRef?.trim() || undefined;
    body.head_ref = f.mrHeadRef?.trim() || undefined;
    body.head_commit = f.mrHeadCommit?.trim() || undefined;
    body.base_commit = f.mrBaseCommit?.trim() || undefined;
    return body;
  }
  if (type === "correlation") {
    // gateway url 开 = 段③黑盒验证：HOST 同组合模式校验（enabled 须有具体来源，拒绝静默降级）。
    if (f.url.trim()) {
      const hostError = hostValidationKey(f.host);
      if (hostError) throw new Error(hostError);
    }
    const body: ScanRequest = { type, workspace: workspace || undefined };
    if (corrYaml) body.config_content = corrYaml;
    if (f.url.trim()) {
      body.url = f.url.trim();
      if (f.auth.enabled) assignAuthToBody(body, f.auth);
      assignHostToBody(body, f.host);
    }
    return body;
  }
  const hostIsActive = !!f.combined && !!f.url;
  if (hostIsActive) {
    const hostError = hostValidationKey(f.host);
    if (hostError) throw new Error(hostError);
  }
  const body: ScanRequest = { type, url: f.url || undefined, workspace: workspace || undefined };
  body.source = { kind: "repo", value: f.selectedRepo };
  // 组合扫描（Task 9）：开关开 + url → 同一 body 携带 url + 认证，后端 Task 1 validator
  // 识别 type=whitebox + url → 组合扫描，先跑黑盒认证预验证（bb_phase=precheck）。
  // 开关关 → 纯白盒：即便 f.url 有草稿也不发（strip 上方 line 设的 url），零回归。
  if (f.combined && f.url) {
    body.url = f.url;
    if (f.auth.enabled) assignAuthToBody(body, f.auth);
    assignHostToBody(body, f.host);
  } else {
    body.url = undefined;
  }
  return body;
}

function renderError(e: ApiError, t: TFunction): string {
  if (e.status === 400) return t("scan.errors.temporal");
  if (e.status === 422) {
    const detail = (e.body as { detail?: unknown })?.detail;
    // string detail = 后端 ValueError 族原文（scan API except ValueError 转来：仓库未就绪 /
    // 认证档案不存在 / 黑盒复用缺失等，全是面向用户的中文）——直接透传展示。
    // 不套「yaml 校验失败」：白盒扫描根本没有 yaml，误导排查（2026-08-27 仓库 pull 失败事故）。
    if (typeof detail === "string" && detail) return detail;
    // 工作区缺 LLM 凭据（后端 ProviderConfigIncomplete）→ 结构化错误 code=provider_incomplete。
    // 友好提示去工作区设置补全凭据，不误报「yaml 校验失败」（detail 是 dict 而非 array）。
    if (detail && typeof detail === "object" && !Array.isArray(detail)
        && (detail as { code?: string }).code === "provider_incomplete") {
      return t("scan.errors.providerMissing");
    }
    const detailArr = Array.isArray(detail) ? detail : undefined;
    const msg = detailArr && detailArr.length > 0 ? detailArr[0]?.msg : undefined;
    return msg ? t("scan.errors.yamlInvalidWithMsg", { msg }) : t("scan.errors.yamlInvalid");
  }
  return t("scan.errors.submitFailed", { status: e.status });
}

/** 仓库校验：白盒必选仓库。本地路径入口已移除——不再校验绝对路径。 */
function validateSource(selectedRepo: string, t: TFunction): string | null {
  return selectedRepo ? null : t("scan.errors.selectRepo");
}

/** URL 校验（可选字段）：非空时须 http(s)（白盒组合扫描 gateway / correlation gateway 同款）。 */
function validateUrl(v: string, t: TFunction): string | null {
  if (!v.trim()) return null;
  return /^https?:\/\//.test(v) ? null : t("scan.errors.urlScheme");
}

/** YAML 文本 canonical 化（语义比较用，2026-09-04 双向同步）：解析失败回落原文
 *  （错误路径由 yamlErr 兜底，这里只服务「注释/排版差异不算编辑」的等价判断）。 */
function canonicalYaml(y: string): string {
  try { return formToYaml(yamlToForm(y)); } catch { return y; }
}

export function ScanNewPage() {
  const { t } = useTranslation();
  const nav = useNavigate();
  const [params] = useSearchParams();
  const presetRepo = params.get("repo");
  const presetWs = params.get("workspace");
  // 重跑预填：ScanList.onRerun 经 location.state 传入原扫描配置（优先于 query param）。
  const preset = (useLocation().state ?? {}) as RerunPreset;
  // 类型切换（D3）：白盒 | 跨仓关联 segmented。黑盒只读分支已删——历史黑盒 preset
  // （location.state.type="blackbox"，ScanList 旧入口）落到白盒渲染；correlation preset
  // 直达跨仓表单；mr preset（ScanList MR 行重跑）直达 MR 表单并预填 refs。
  const [type, setType] = useState<ScanType>(
    preset.type === "correlation" ? "correlation" : preset.type === "mr" ? "mr" : "whitebox");
  const [f, setF] = useState<FormState>({
    selectedRepo: preset.repo ?? presetRepo ?? "",
    url: preset.url ?? "",
    reuseScanId: preset.reuseScanId ?? "",
    auth: presetToAuthState(preset),
    host: presetToHostState(preset),
    yaml: "repos:\n  a:\n    url: https://gitlab.example/a.git\n    branch: main",
    // 组合任务重跑预填：开关随 preset 打开（显式字段——correlation preset 也带 url
    // 但不吃 combined，不按 url 推导误开）。
    combined: preset.combined ?? false,
    // MR 重跑预填（spec 2026-09-03 §6）：base/head refs 原样回填；merged 改道把手
    //（2026-09-04）随行——改道扫描的重跑仍走 commit 对，不撞已删源分支。
    mrBaseRef: preset.mrBaseRef ?? "",
    mrHeadRef: preset.mrHeadRef ?? "",
    mrHeadCommit: preset.mrHeadCommit ?? undefined,
    mrBaseCommit: preset.mrBaseCommit ?? undefined,
  });
  // —— 跨仓关联三方同步（2026-09-04 tabs 重组）：表单 / 拓扑图 / YAML 是同一拓扑的三个
  //    透镜（corrView 切换），谁被编辑谁就是源——扇出到其他两方、不回写源：
  //    表单路径 updateCorr（→图+YAML）、图路径 applyTopologyState（→表单+YAML）、文本路径
  //    onCorrYaml（→表单+图，仅解析成功；非法中间态保持上次有效态+报错）。原 auto/manual
  //    模式分页删除——AI 自动分析收进图 tab 折叠区块，确认门禁改跟拓扑来源
  //    （topologyState.analysis 存在=AI 产物须确认；纯手工免确认）。 ——
  const [corrState, setCorrState] = useState<CorrFormState>({ repos: [], relations: [] });
  const [corrYaml, setCorrYaml] = useState<string>(() => formToYaml({ repos: [], relations: [] }));
  const [yamlErr, setYamlErr] = useState<CorrYamlError | null>(null);
  const [corrView, setCorrView] = useState<CorrView>("graph");
  /** 图 tab「自动分析」折叠区块开关：默认展开（自动分析是主路径）；收起时挂起
   *  latest/历史恢复查询（手工用户零噪音请求），分析轮询不受影响（后台照跑）。 */
  const [analysisOpen, setAnalysisOpen] = useState(true);
  const [selectedTopologyRepos, setSelectedTopologyRepos] = useState<string[]>([]);
  const [analysisId, setAnalysisId] = useState<string | null>(null);
  const [analysis, setAnalysis] = useState<CorrelationTopologyAnalysis | null>(null);
  // 分析历史（摘要列表）：「换一组仓库」不用重新分析——点历史条目恢复该次世界
  const [analysisHistory, setAnalysisHistory] = useState<CorrelationTopologyAnalysis[]>([]);
  const [analysisStarting, setAnalysisStarting] = useState(false);
  const [historyDeletingId, setHistoryDeletingId] = useState<string | null>(null);
  const [analysisError, setAnalysisError] = useState<string | null>(null);
  // 过程日志：after 行号游标 + 前端保留窗（200 行，更早累计进 dropped）
  const [logLines, setLogLines] = useState<TopologyAuditLine[]>([]);
  const [logDropped, setLogDropped] = useState(0);
  const logCursor = useRef(-1);
  const resetLog = () => { logCursor.current = -1; setLogLines([]); setLogDropped(0); };
  const [topologyState, setTopologyState] = useState<TopologyDraftState | null>(null);
  /** 表单路径扇出（表单是源）：重生成 YAML（canonical 派生态）+ 重建图（位置/AI 证据按
   *  identity 继承，语义相同原样返回不惊动确认态——corrFormToTopologyDraft 契约）。 */
  const updateCorr = (s: CorrFormState) => {
    setCorrState(s);
    setCorrYaml(formToYaml(s));
    setTopologyState((prev) => corrFormToTopologyDraft(s, prev));
    setYamlErr(null);
  };
  /** 图路径扇出（图是源，2026-09-04 三方同步）：拓扑态变化的同时刷新 corrState/corrYaml
   *  （草稿派生）。文本/表单侧编辑不经过这里，用户输入中的文本不被派生回写覆盖。 */
  const applyTopologyState = (next: TopologyDraftState | null) => {
    setTopologyState(next);
    if (!next) return;
    const form = topologyDraftToCorrForm(next.draft);
    setCorrState(form);
    setCorrYaml(formToYaml(form));
    setYamlErr(null);
  };
  /** YAML 路径扇出（文本是源）：解析成功即重建表单+图（贴 YAML 长拓扑/改文本改图），
   *  用户原文保留（不 canonical 化回写）；失败仅报错，表单/图保持上次有效态。 */
  const onCorrYaml = (y: string) => {
    setCorrYaml(y);
    try {
      const form = yamlToForm(y);
      setCorrState(form);
      setTopologyState((prev) => corrFormToTopologyDraft(form, prev));
      setYamlErr(null);
    } catch (e) {
      // D1 已知限制：病态 relations（非列表）抛裸 TypeError——与 CorrYamlError 同道展示。
      setYamlErr(e instanceof CorrYamlError
        ? e
        : new CorrYamlError([e instanceof TypeError ? e.message : String(e)]));
    }
  };
  // P2: 扫描目标 ws 必须显式选定——选项来自 /workspaces（P1 后端已按当前用户可见性过滤）
  const [workspace, setWorkspace] = useState(preset.workspace ?? presetWs ?? "");
  const [wsList, setWsList] = useState<Workspace[]>([]);
  // ws 列表加载中标志：初始 [] 与"加载完真的为空"都表现为 wsList=[]，需区分以防空态提示闪现
  const [wsLoading, setWsLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const set = (patch: Partial<FormState>) => setF((prev) => ({ ...prev, ...patch }));
  const topologyReposEnabled = type === "correlation";
  const { repos: topologyRepos } = useRepos(topologyReposEnabled ? workspace : "");
  // MR 表单仓库下拉（与上面同 ["repos", ws] SWR key——浏览过仓库 tab / 白盒表单后即时填充）
  const { repos: mrRepos } = useRepos(type === "mr" ? workspace : "");
  // MR 表单选中仓库对象（C 段快捷操作条 + state 显示）
  const mrSelectedRepo = mrRepos.find((r) => r.name === f.selectedRepo);
  const { scans } = useScans(type === "correlation" ? workspace : "");
  // 来源智能默认（2026-09-09）：仓库首次进入跨仓配置时，默认复用该仓最新一次成功白盒
  // 扫描（无成功/未扫过 → 现扫）。只在新进入时算一次；用户改过或已配置过的仓库不覆盖。
  const defaultSourceFor = (repo: string) => latestReusableScanId(scans, repo);
  const setAuth = (patch: Partial<AuthFormState>) => setF((prev) => ({ ...prev, auth: { ...prev.auth, ...patch } }));
  const setHost = (patch: Partial<HostFormState>) => setF((prev) => ({ ...prev, host: { ...prev.host, ...patch } }));

  useEffect(() => {
    if (presetRepo) set({ selectedRepo: presetRepo });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [presetRepo]);

  // 拉取 ws 列表（用户可见的 ws，P1 后端已过滤）——供两张表单的 ws 下拉使用
  useEffect(() => {
    apiGet<Workspace[]>("/workspaces")
      .then(setWsList)
      .catch(() => {})
      .finally(() => setWsLoading(false));
  }, []);

  const analysisStatus = analysis?.status;
  useEffect(() => {
    if (!analysisId || (analysisStatus && analysisStatus !== "queued" && analysisStatus !== "running")) return;
    let cancelled = false;
    const poll = async () => {
      try {
        const next = await getCorrelationTopologyAnalysis(workspace, analysisId);
        if (!cancelled) setAnalysis(next);
      } catch {
        /* GET 失败保留上一帧；下一次轮询继续。 */
      }
      // 状态帧后顺带拉日志增量（游标幂等；终态帧也拉最后一次，收齐尾部）。
      try {
        const tail = await getTopologyAnalysisLog(workspace, analysisId, logCursor.current);
        if (!cancelled && tail.lines.length) {
          logCursor.current = tail.next;
          setLogLines((prev) => {
            const merged = [...prev, ...tail.lines];
            const keep = merged.slice(-200);
            setLogDropped((d) => d + merged.length - keep.length);
            return keep;
          });
        }
      } catch {
        /* 日志拉取失败不影响状态轮询 */
      }
    };
    void poll();
    const timer = window.setInterval(poll, 2000);
    return () => { cancelled = true; window.clearInterval(timer); };
  }, [analysisId, analysisStatus, workspace]);

  // 刷新恢复：进入页面（ws 确定且本会话未发起过新分析）时找回最近一条 analysis，
  // active → 恢复状态/日志轮询；终态 → 直接展示结果（retry 语义不变）。404 静默。
  // 仅 correlation+auto 模式查——白盒/MR 无拓扑分析，不白发请求。
  // 完成态回填勾选仓库（2026-09-04 恢复断链修复）：此前只回状态帧不回 repos，
  // 草稿 effect 因勾选为空短路 → 图/YAML 全空像「没分析过」。函数式 set——
  // 用户已手选仓库时不覆盖其选择。
  useEffect(() => {
    if (type !== "correlation" || !analysisOpen || !workspace || analysisId) return;
    let cancelled = false;
    getLatestTopologyAnalysis(workspace)
      .then((a) => {
        if (cancelled) return;
        resetLog();
        setAnalysis(a);
        setAnalysisId(a.analysis_id);
        if (a.status === "completed" && a.result) {
          setSelectedTopologyRepos((prev) => (prev.length ? prev : a.repos));
        }
      })
      .catch(() => {});
    // 分析历史（同页拉取）：历史条目选择器数据源；失败静默=无历史可恢复
    listCorrelationTopologyAnalyses(workspace)
      .then((list) => { if (!cancelled) setAnalysisHistory(list); })
      .catch(() => {});
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [type, analysisOpen, workspace]);

  useEffect(() => {
    if (analysis?.status !== "completed" || !selectedTopologyRepos.length) return;
    if (topologyState?.analysis?.analysis_id === analysis.analysis_id) return;
    // 用户已在编辑（手贴 YAML / 手选仓库建过图）→ 恢复不覆盖其工作
    if (topologyState) return;
    const sources = Object.fromEntries(corrState.repos.map((repo) => [repo.repo, repo.reuseScanId]));
    applyTopologyState(createTopologyDraft(selectedTopologyRepos, analysis, sources, defaultSourceFor));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [analysis, selectedTopologyRepos]);

  // 当前 analysis upsert 进历史列表：新发起的分析入列置顶、轮询推进的状态实时反映
  useEffect(() => {
    if (!analysis) return;
    setAnalysisHistory((prev) => [
      { ...analysis, result: undefined },
      ...prev.filter((e) => e.analysis_id !== analysis.analysis_id),
    ]);
  }, [analysis]);

  /** 历史条目选择：换回该次分析的世界——回填勾选仓库、拉全量（list 摘要无
   *  result）、清当前草稿 → 完成→草稿 effect 重建拓扑/YAML，全程零重新分析。
   *  active 条目（running/queued）同样可选：恢复后轮询 effect 自动接管。 */
  const selectHistoryEntry = async (entry: CorrelationTopologyAnalysis) => {
    if (!workspace || entry.analysis_id === analysisId) return;
    resetLog();
    setAnalysisError(null);
    setTopologyState(null);
    setSelectedTopologyRepos(entry.repos);
    setAnalysisId(entry.analysis_id);
    if (entry.status === "completed") {
      // completed 只在全量到达后 setAnalysis（2026-09-09 修确认拓扑不生效）：摘要无
      // result，若先行 set，草稿 effect 会用「空拓扑」抢先建 draft 且摘要写进
      // topologyState.analysis，全量到达时被同 analysis_id 短路——AI roles/edges 永
      // 丢，校验必挂 → 确认恒不生效。null→full 一步到位与刷新恢复/轮询路径同形态
      //（await 窗口轮询 effect 也会拉同一 GET，幂等无竞态）。
      try {
        setAnalysis(await getCorrelationTopologyAnalysis(workspace, entry.analysis_id));
      } catch (e) {
        setAnalysisError(e instanceof Error ? e.message : String(e));
      }
    } else {
      // running/queued 轮询自动推进；failed 等终态摘要是完整帧
      setAnalysis(entry);
    }
  };

  const deleteHistoryEntry = async (entry: CorrelationTopologyAnalysis) => {
    if (!workspace || historyDeletingId) return;
    try {
      setHistoryDeletingId(entry.analysis_id);
      await deleteCorrelationTopologyAnalysis(workspace, entry.analysis_id);
      setAnalysisHistory((prev) => prev.filter((e) => e.analysis_id !== entry.analysis_id));
      // 删除当前载入的分析来源：清空图/YAML，避免「历史档案已删但右侧仍可确认提交」。
      if (analysisId === entry.analysis_id) {
        setAnalysisId(null); setAnalysis(null); setTopologyState(null);
        resetLog(); setAnalysisError(null);
      }
      toast.success(t("scan.correlation.analysis.history.deleted"));
    } catch (e) {
      setAnalysisError(e instanceof Error ? e.message : String(e));
    } finally {
      setHistoryDeletingId(null);
    }
  };

  const startTopologyAnalysis = async (refresh = false) => {
    if (!workspace || selectedTopologyRepos.length < 2) return;
    try {
      setAnalysisStarting(true); setAnalysisError(null);
      const result = await startCorrelationTopologyAnalysis(workspace, { repos: selectedTopologyRepos, refresh });
      resetLog();
      setAnalysisId(result.analysis_id); setAnalysis(null); setTopologyState(null);
    } catch (e) {
      setAnalysisError(e instanceof Error ? e.message : String(e));
    } finally { setAnalysisStarting(false); }
  };
  const cancelTopologyAnalysis = async () => {
    if (!workspace || !analysisId) return;
    try { setAnalysis(await cancelCorrelationTopologyAnalysis(workspace, analysisId)); }
    catch (e) { setAnalysisError(e instanceof Error ? e.message : String(e)); }
  };
  /** 链接解析回填（2026-09-03 仓库入口整合 B 段；2026-09-08 白盒侧链接框删除，
   *  仅剩 MR 表单 hero 框触发）：仓库立即选中（cloning 也选中，下载提示由页面级
   *  CloneWatch 承担）；MR 链接附 refs 回填。
   *  MR refs 回填时同步 mrFlashAt（2026-09-04 重排）：RefRangeInput 收到新时间戳做
   *  一次 coral 环脉冲——回填成功的「答案式」确认动效。 */
  const [pendingClone, setPendingClone] = useState<string | null>(null);
  const [mrFlashAt, setMrFlashAt] = useState(0);
  const handleLinkResolved = (r: ResolveLinkResult) => {
    const patch: Partial<FormState> = { selectedRepo: r.repo };
    if (r.kind === "mr") {
      patch.mrBaseRef = r.base_ref ?? "";
      patch.mrHeadRef = r.head_ref ?? "";
      // merged 改道（2026-09-04）：commit 把手随行；非改道 MR 显式清空——用户先贴
      // 改道 MR 再贴普通 MR 时，不得残留上一条的 commit 对（会误导 worker 按旧把手扫）。
      patch.mrHeadCommit = r.mr_merged ? (r.head_commit ?? undefined) : undefined;
      patch.mrBaseCommit = r.mr_merged ? (r.base_commit ?? undefined) : undefined;
    }
    set(patch);
    if (r.repo_state === "cloning") setPendingClone(r.repo);
    if (r.kind === "mr") setMrFlashAt(Date.now());
  };

  const selectTopologyRepos = (repos: string[]) => {
    setSelectedTopologyRepos(repos);
    setAnalysisId(null); setAnalysis(null); setAnalysisError(null); resetLog();
    // Selector changes are table-compatible graph edits: preserve compatible nodes/edges/sources.
    applyTopologyState(topologyState ? updateTopologyRepositories(topologyState, repos, defaultSourceFor) : null);
  };

  const confirmCurrentTopology = () => {
    if (!topologyState) return;
    let next = confirmTopologyDraft(topologyState);
    if (next.confirmation.status === "confirmed") {
      // 快照对齐当前 YAML 文本（2026-09-04 双向同步）：确认时 corrYaml 与草稿语义恒一致
      // （图路径=canonical 派生 / 文本路径=拓扑由文本重建），保留用户原文（注释/排版）
      // 作为提交 payload——不重写 textarea（updateCorr 会 canonical 化，故此处只同步 corrState）。
      if (!yamlErr) next = { ...next, confirmation: { ...next.confirmation, yaml: corrYaml } };
      setTopologyState(next);
      setCorrState(topologyDraftToCorrForm(next.draft));
      setYamlErr(null);
    } else {
      setTopologyState(next);
    }
  };

  // 校验：白盒 = repo + url(可选) + ws；correlation = validateForm(corrState) 空 + 无
  // YAML 错 + ws（gateway url 可选，开了才纳入 url/auth/host 校验——同白盒组合扫描）。
  const combined = type === "whitebox" && !!f.combined;
  const corrGatewayOn = type === "correlation" && !!f.url.trim();
  const sourceErr = type === "whitebox" || type === "mr" ? validateSource(f.selectedRepo, t) : null;
  const mrRefsErr = type === "mr"
    ? (f.mrBaseRef?.trim() && f.mrHeadRef?.trim() ? null : t("scan.errors.selectRefs"))
    : null;
  const urlErr = combined
    ? (f.url.trim() ? (/^https?:\/\//.test(f.url.trim()) ? null : t("scan.errors.urlScheme")) : t("scan.errors.urlEmpty"))
    : validateUrl(f.url, t);
  const authErr = (combined || corrGatewayOn) ? validateAuth(f.auth, t) : null;
  const hostErr = (combined || corrGatewayOn) ? validateHost(f.host, t) : null;
  const corrIssues = type === "correlation" ? validateForm(corrState) : [];
  const confirmedTopologyYaml = topologyState?.confirmation.yaml ?? null;
  // 确认门禁跟拓扑来源（2026-09-04 tabs 重组）：拓扑带 AI 分析来源（analysis 非 null，
  // 哪怕手工改过）须显式确认才能提交；纯手搭拓扑免确认（自己搭的即确认）。
  const topologyNeedsConfirm = !!topologyState?.analysis;
  const topologyConfirmed = !topologyNeedsConfirm || (
    topologyState?.confirmation.status === "confirmed"
    && topologyState.confirmation.fingerprint === topologyDraftFingerprint(topologyState.draft)
    && validateTopologyDraft(topologyState.draft).length === 0
    // YAML 侧按 canonical 语义比较（2026-09-04）：注释/排版差异不算编辑——真语义
    // 变化已由「文本→图重建重置确认」拦下，这里只放行语义等价的文本抖动。
    && (confirmedTopologyYaml === null || canonicalYaml(corrYaml) === canonicalYaml(confirmedTopologyYaml))
  );
  const isValid = !sourceErr && !urlErr && !authErr && !hostErr && !mrRefsErr && !!workspace
    && (type === "mr" || type === "whitebox" || (corrIssues.length === 0 && !yamlErr && topologyConfirmed));

  async function onSubmit() {
    try {
      setSubmitting(true);
      // 提交 payload（2026-09-04 tabs 重组统一）：带分析来源 → 确认快照原文（锁定确认
      // 那一刻的文本）；纯手工 → 当前 corrYaml（实时文本即所想即所得）。
      const submissionYaml = topologyNeedsConfirm
        ? topologyState?.confirmation.yaml ?? ""
        : corrYaml;
      const r = await apiPost<ScanResponse>("/scan", buildBody(type, f, workspace, submissionYaml));

      // 组合扫描预验证态（Task 9，spec §8.2）：后端 passthrough bb_phase=precheck 表示
      // 黑盒认证预验证先行——提示用户「预验证中」，再跳 live 页跟踪进度。
      if (r.bb_phase === "precheck") toast.info(t("scan.precheckStatus"));
      // ws-scan 解耦：scan_id 有则跳 scan-scoped live（精确到刚建的 scan）；
      // 过渡期 Phase 1 未返 scan_id 时回退旧 ws-scoped live（LegacyWsTabRedirect 兜底）。
      nav(r.scan_id ? `/p/${r.workspace}/scans/${r.scan_id}/live` : `/p/${r.workspace}/live`);
    } catch (e) {
      if (e instanceof ApiError) toast.error(renderError(e, t));
    } finally {
      setSubmitting(false);
    }
  }

  const subtitleKey = type === "correlation" ? "scan.correlation.subtitle"
    : type === "mr" ? "scan.subtitleMr" : "scan.subtitleWhitebox";
  // 提交按钮文案统一「开始扫描」（2026-09-09 v3，用户点名）：扫描类型由顶部
  // segmented 表达（白盒/MR 增量/跨仓关联），按钮只说动词——三类同一动作同一名。
  const submitLabel = t("scan.submit");
  const footerHint = type === "correlation" ? t("scan.correlation.footerHint")
    : type === "mr" ? t("scan.mrBaseHeadHint") : t("scan.footerHintWhitebox");
  // ws 空态判定（mr 表单 ws 下拉 + 提示共用；与 CorrelationFormFields/ScanFormFields 同式）
  const wsEmpty = !wsLoading && wsList.length === 0;

  return (
    <div className="space-y-4">
      {/* 页面标题 */}
      <PageHeader title={t("scan.title")} subtitle={t(subtitleKey)} />

      {/* 整张卡片：类型 segmented + 单栏表单 + 底部操作 */}
      <Card className="overflow-hidden">
        <div className="p-5 space-y-4">
          {/* 类型切换 segmented（D3）：白盒 | MR 增量 | 跨仓关联（黑盒无独立入口——组合任务的嵌套 run）。
              顺序即频率与复杂度（2026-09-04 重排）：MR 增量（spec 2026-09-03，base..head、纯白盒
              语义）是日常高频且表单最简，紧跟白盒成「单仓检测」组；跨仓关联（多仓拓扑/YAML/编辑器）
              是低频深度分析、表单最重，殿后。
              跨仓关联的 ws 在来源轨道首字段（2026-09-09 重排；2026-09-04 曾挂本行右端——
              控制远离效果域，未选 ws 的提示与下拉分离视线跳跃）。三种类型 IA 统一：ws 恒为
              表单首字段（白盒/MR 在 ① 工作区列，跨仓在来源轨道顶）。 */}
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="inline-flex items-center gap-1 rounded-lg border border-border bg-muted/40 p-1">
              {(["whitebox", "mr", "correlation"] as const).map((v) => (
                <button
                  key={v}
                  type="button"
                  onClick={() => setType(v)}
                  aria-pressed={type === v}
                  data-testid={`scan-type-${v}`}
                  className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                    type === v ? "bg-card text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground"
                  }`}
                >
                  {t(`scan.type.${v}`)}
                </button>
              ))}
            </div>
          </div>

          {/* 表单区：白盒由 ScanFormFields 内 lg:grid-cols-2 把 ① 工作区 / ② 仓库 并排铺满，③ 满宽；
              跨仓关联 = 三视图 tabs（图|表单|YAML，同一拓扑三透镜实时同步）。 */}
          {type === "whitebox" ? (
            <ScanFormFields
              type="whitebox"
              f={f}
              set={set}
              sourceErr={sourceErr}
              reuseErr={null}
              urlErr={urlErr}
              authErr={authErr}
              hostErr={hostErr}
              workspace={workspace}
              wsList={wsList}
              onWorkspaceChange={setWorkspace}
              wsLoading={wsLoading}
            />
          ) : type === "mr" ? (
            /* MR 增量扫描（spec 2026-09-03 §3.1/§6；2026-09-04 布局重排）：
               ① 工作区 + 仓库 两列并排（对齐白盒布局语言；IA 不变量：repo 按 ws
               隔离，选仓前必须先选 ws）→ ② MR 链接导入（hero 粘贴框，贴链接自动回填
               仓库 + refs）→ ③ 变更范围区间控件（base⟷head 一体 + swap + 就绪摘要）。
               必须在跨仓关联（corr tabs）判断之前，否则 mr 会错渲染跨仓表单。
               base/head 为手输文本（分支名或 commit sha 均可，
               BranchCombobox 是行内切换控件非表单样式，且枚举分支列表对 commit sha
               无增益）。纯白盒语义——无 url/认证/HOST。 */
            <div className="space-y-5" data-testid="mr-form">
              <div className="grid gap-4 sm:grid-cols-2">
                {/* ①a 工作区 */}
                <section className="space-y-2">
                  <GroupLabel>{t("scan.fields.wsSelectLabel")}</GroupLabel>
                  <div className="space-y-1.5">
                    <Select value={workspace} onValueChange={setWorkspace}>
                      <SelectTrigger className="w-full font-mono text-xs">
                        <SelectValue placeholder={t("scan.fields.wsSelectPlaceholder")} />
                      </SelectTrigger>
                      <SelectContent>
                        {wsEmpty ? (
                          <SelectItem value="__empty__" disabled>{t("scan.fields.wsEmptyOption")}</SelectItem>
                        ) : wsList.map((w) => (
                          <SelectItem key={w.name} value={w.name}>{w.name}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    {wsEmpty && (
                      <div className="flex items-center gap-1.5 text-xs text-amber">
                        <AlertCircle className="h-3.5 w-3.5" />{t("scan.fields.wsEmptyHintUser")}
                      </div>
                    )}
                  </div>
                </section>
                {/* ①b 仓库：repo 复用 RepoCombobox（与白盒/跨仓同一选择器）+
                    state 显示 + 快捷操作条（cloning/pulling 进度、ready 切分支/更新）。 */}
                <section className="space-y-2">
                  <GroupLabel>{t("scan.steps.source")}</GroupLabel>
                  {!workspace ? (
                    <div className="text-xs text-muted-foreground">{t("scan.fields.selectWsFirst")}</div>
                  ) : (
                    <div className="space-y-3">
                      <RepoCombobox
                        repos={mrRepos}
                        value={f.selectedRepo || null}
                        onChange={(v) => set({ selectedRepo: v })}
                        onClear={() => set({ selectedRepo: "" })}
                        clearLabel={t("scan.repo.clearLabel")}
                        placeholder={t("scan.repo.selectPlaceholder")}
                        searchPlaceholder={t("scan.repo.searchPlaceholder")}
                        emptyText={t("scan.repo.noMatch")}
                        ungroupedLabel={t("scan.repo.ungrouped")}
                        linkedLabel={t("repos.linkedBadge")}
                      />
                      {sourceErr && <div className="text-destructive text-xs">{sourceErr}</div>}
                      {f.selectedRepo && mrSelectedRepo && mrSelectedRepo.state !== "ready" && (
                        mrSelectedRepo.state === "cloning" || mrSelectedRepo.state === "pulling"
                          ? <div className="text-xs text-muted-foreground">{t("scan.link.cloning", { name: f.selectedRepo })}</div>
                          : <div className="text-xs text-destructive">{t("scan.repo.notReady", { state: mrSelectedRepo.state })}</div>
                      )}
                      {mrSelectedRepo?.state === "ready" && (
                        <RepoQuickActions workspace={workspace} repo={mrSelectedRepo} />
                      )}
                    </div>
                  )}
                </section>
              </div>

              {workspace && (
                <>
                  {/* ② 从 MR 链接导入（hero）：贴 GitLab MR 链接自动回填仓库 + refs——
                      MR 场景最高频入口（回填后区间控件一次 coral 脉冲确认）。 */}
                  <section className="space-y-2">
                    <GroupLabel>{t("scan.mr.importGroup")}</GroupLabel>
                    <LinkResolveBox
                      workspace={workspace}
                      accepts={["mr"]}
                      onResolved={handleLinkResolved}
                    />
                  </section>

                  {/* ③ 变更范围：base⟷head 区间控件（swap + 就绪摘要 base..head）。 */}
                  <section className="space-y-2">
                    <GroupLabel hint={t("scan.mr.rangeHint")}>{t("scan.mr.rangeGroup")}</GroupLabel>
                    <RefRangeInput
                      base={f.mrBaseRef ?? ""}
                      head={f.mrHeadRef ?? ""}
                      onBase={(v) => set({ mrBaseRef: v })}
                      onHead={(v) => set({ mrHeadRef: v })}
                      error={mrRefsErr}
                      flashAt={mrFlashAt}
                    />
                    {/* merged 改道（2026-09-04）：源分支已删的已合并 MR——refs 展示仍是
                        分支名，实际按合入 commit 扫。琥珀提示显式告知，用户不困惑
                        「分支不是没了吗怎么还能扫」。 */}
                    {f.mrHeadCommit && (
                      <p data-testid="mr-merged-hint"
                         className="flex items-center gap-1.5 text-xs text-amber">
                        {t("scan.mr.mergedFallbackHint",
                           { commit: f.mrHeadCommit.slice(0, 8) })}
                      </p>
                    )}
                  </section>
                </>
              )}
            </div>
          ) : (
            <div className="space-y-4">
              {/* 双列工作台（2026-09-09 重排）：左 = 来源轨道（tabs 外常驻——工作区 → 服务清单
                  → AI 分析是拓扑的来源，图|表单|YAML 只是同一拓扑的三个透镜，切透镜不丢来源，
                  与黑盒验证同理）；右 = 视图区。tabs 只管辖视图区、不再横跨全宽压在轨道上方；
                  ws 撤出 segmented 行右上角进轨道首字段（控制紧贴效果域——仓库列表按 ws
                  隔离）。轨道「服务与分析」段收起时列宽收窄为 ws 段（15rem），画布尽量占满。 */}
              <div className={`grid gap-4 ${
                analysisOpen
                  ? "xl:grid-cols-[320px_minmax(0,1fr)]"
                  : "xl:grid-cols-[minmax(0,15rem)_minmax(0,1fr)]"
              }`}>
                <CorrelationSourceRail
                  workspace={workspace}
                  wsList={wsList}
                  wsLoading={wsLoading}
                  onWorkspaceChange={(ws) => {
                    setWorkspace(ws);
                    // ws 切换 → 仓库域隔离：清分析勾选与进行中的分析态（对齐原 auto 分支行为）
                    selectTopologyRepos([]);
                  }}
                  repos={topologyRepos}
                  selectedRepos={selectedTopologyRepos}
                  onSelectRepos={selectTopologyRepos}
                  analysis={analysis}
                  starting={analysisStarting}
                  logLines={logLines}
                  logDropped={logDropped}
                  analysisError={analysisError}
                  historyEntries={analysisHistory}
                  historyActiveId={analysisId}
                  onSelectHistoryEntry={(entry) => void selectHistoryEntry(entry)}
                  onDeleteHistoryEntry={(entry) => void deleteHistoryEntry(entry)}
                  historyDeletingId={historyDeletingId}
                  onStart={() => void startTopologyAnalysis(false)}
                  onRetry={() => void startTopologyAnalysis(true)}
                  onCancel={() => void cancelTopologyAnalysis()}
                  analysisOpen={analysisOpen}
                  onAnalysisOpen={setAnalysisOpen}
                />
              {/* 三视图子页（2026-09-04 tabs 重组）：图 | 表单 | YAML——同一拓扑的三个透镜，
                  改任何一方其他两方实时生成（updateCorr / applyTopologyState / onCorrYaml 三扇出）。
                  tab 标签状态点把别处视图的问题带到眼前：表单校验错 / YAML 错 → 红点，
                  图有分析来源未确认 → 琥珀点。tabs 行右侧挂确认门禁状态条（三视图共享——
                  2026-09-04 工作台化上移：AI 草稿须确认才可提交，不该埋在图编辑器底部）。 */}
              <Tabs value={corrView} onValueChange={(v) => setCorrView(v as CorrView)}>
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <TabsList data-testid="corr-view-tabs">
                    <TabsTrigger value="graph" data-testid="corr-tab-graph">
                      {t("scan.correlation.view.graph")}
                      {topologyNeedsConfirm && !topologyConfirmed && (
                        <span data-testid="corr-tab-dot-graph" aria-label={t("scan.correlation.view.dotUnconfirmed")}
                          className="ml-1.5 inline-block size-1.5 rounded-full bg-amber" />
                      )}
                    </TabsTrigger>
                    <TabsTrigger value="form" data-testid="corr-tab-form">
                      {t("scan.correlation.view.form")}
                      {corrIssues.length > 0 && (
                        <span data-testid="corr-tab-dot-form" aria-label={t("scan.correlation.view.dotError")}
                          className="ml-1.5 inline-block size-1.5 rounded-full bg-destructive" />
                      )}
                    </TabsTrigger>
                    <TabsTrigger value="yaml" data-testid="corr-tab-yaml">
                      {t("scan.correlation.view.yaml")}
                      {yamlErr && (
                        <span data-testid="corr-tab-dot-yaml" aria-label={t("scan.correlation.view.dotError")}
                          className="ml-1.5 inline-block size-1.5 rounded-full bg-destructive" />
                      )}
                    </TabsTrigger>
                  </TabsList>
                  <TopologyConfirmBar needsConfirm={topologyNeedsConfirm} confirmed={topologyConfirmed}
                    onConfirm={confirmCurrentTopology} />
                </div>
                <TabsContent value="graph">
                  <CorrelationGraphTab
                    topologyState={topologyState}
                    onTopologyState={applyTopologyState}
                    onViewChange={setCorrView}
                    onRemoveNode={(repo) => selectTopologyRepos(selectedTopologyRepos.filter((name) => name !== repo))}
                    scans={scans}
                  />
                </TabsContent>
                <TabsContent value="form">
                  <CorrelationFormFields state={corrState} onState={updateCorr} workspace={workspace} />
                </TabsContent>
                <TabsContent value="yaml">
                  <YamlPanel yaml={corrYaml} onChange={onCorrYaml} error={yamlErr} synced />
                </TabsContent>
              </Tabs>
              </div>
              {/* 黑盒验证（可选）：gateway + 认证/HOST——三视图共用，放 tabs 外 */}
              <CorrelationGatewayFields
                workspace={workspace}
                gatewayUrl={f.url}
                onGatewayUrl={(v) => set({ url: v })}
                gatewayErr={urlErr}
                auth={f.auth}
                setAuth={setAuth}
                authErr={authErr}
                host={f.host}
                setHost={setHost}
                hostErr={hostErr}
              />
            </div>
          )}
          {/* 链接解析触发的下载提示（表单区末尾，MR hero 触发；白盒侧链接框已删
              2026-09-08——新仓库走「+ 添加仓库」弹窗，克隆提示仍由 CloneWatch 承担） */}
          {pendingClone && (
            <CloneWatch workspace={workspace} name={pendingClone} onDone={() => setPendingClone(null)} />
          )}
        </div>

        {/* 底部操作栏：主命令按钮（三按钮家族 v3 2026-09-09）——三类扫描（白盒/MR/
            跨仓）共用同一按钮同一文案「开始扫描」+ 实心 Play；「发射特效」只挂此处
            不进 cta variant（其余页面主按钮保持纯实色）：暖彩流动渐变（primary↔
            --c-orange，cta-flow 9s 无缝流转）+ 辉光呼吸（cta-breathe，--shadow-cta
            ↔hover 之间起伏，主题自适应）。就绪才发光：disabled 停转去渐变回纯色；
            motion-safe 尊重 reduced-motion（渐变静止不闪）。!size-3.5 须 important
            （基类 [&_svg]:size-4 父级选择器 specificity 高于图标自身类）；gap-1.5 经
            cn 的 tailwind-merge 覆盖基类 gap-2；bg-[linear-gradient] 与 cta 的
            bg-primary 分属 image/color 通道共存，disabled:bg-none 去渐变露底色。 */}
        <div className="flex items-center justify-between px-5 py-3.5 border-t border-border bg-card">
          <Button variant="cta" onClick={onSubmit} disabled={!isValid || submitting}
            className="gap-1.5 bg-[linear-gradient(110deg,hsl(var(--primary))_25%,color-mix(in_srgb,hsl(var(--primary))_65%,white)_50%,hsl(var(--primary))_75%)] bg-[length:200%_100%] motion-safe:animate-[cta-flow_9s_linear_infinite,cta-breathe_3.6s_ease-in-out_infinite] disabled:animate-none disabled:bg-none disabled:shadow-none">
            <Play fill="currentColor" stroke="none" className="!size-3.5" aria-hidden />
            {submitLabel}
          </Button>
          <span className="text-xs text-muted-foreground">{footerHint}</span>
        </div>
      </Card>
    </div>
  );
}
