import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router-dom";
import { ChevronDown, ExternalLink } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { MergeSourceBadge } from "@/components/VulnCard";
import type { CorrExploitPath, CorrFlow, CorrMultiHopChain, CorrRefinedFinding, CorrVuln } from "@/api/types";
import type { CorrVerdictGroup } from "@/lib/correlation-verdict";
import { SEV_CAP, SEV_PILL, SEV_DOT, SEV_EDGE } from "@/lib/severity-visual";
import { highlightCode, langFromPath } from "@/lib/highlight-code";
import { CopyableCodePanel } from "@/components/report/CopyableCodePanel";
import { splitCvss } from "@/components/report/VulnerabilityCard";

/**
 * 跨仓漏洞卡（2026-09-18 成立/消掉视图配套）：吃 merged_vulns 条目（宽松 dict），
 * 纯渲染。与单仓 DeliverablesTab 的共享 VulnCard 分离——合并队列条目字段更富
 * （severity/report_endpoints/report_problem_points/report_poc/impact/remediation），
 * 视觉锚定 report/VulnerabilityCard（七节结构 + SEV 药丸），折叠交互对齐 VulnCard
 * （默认收起，ID 在卡头可见）。
 */

const CODE_CLS =
  "code-panel overflow-x-auto p-2 font-mono text-[11.5px] leading-relaxed";
const SEC_LABEL_CLS = "font-mono text-[10px] uppercase tracking-wider text-muted-foreground";
const SEC_CLS = "border-t border-border pt-3";

/** report_endpoints 归一行（宽松 dict 防御后）。 */
export interface CorrEndpointRow {
  method?: string;
  path: string;
  params: string[];
  role?: string;
  auth?: string;
  route_registered_at?: string;
  source_location?: string;
  sink_location?: string;
}
/** report_problem_points 归一行。 */
export interface CorrProblemPoint {
  location: string;
  description?: string;
  snippet?: string;
}
/** report_poc 归一（curl/raw_http/steps 为主，附说明字段）。 */
export interface CorrPoc {
  curl?: string;
  raw_http?: string;
  steps: string[];
  preconditions?: string;
  expected?: string;
  notes?: string;
}
/** 防御归一后的视图：组件零防御纯渲染。 */
export interface CorrVulnView {
  id: string;
  title?: string;
  vulnType?: string;
  severity?: "Critical" | "High" | "Medium" | "Low";
  confidence?: string;
  service?: string;
  mergeSource?: string;
  externallyExploitable: boolean;
  endpoint?: string;
  location?: string;
  impact?: string;
  remediation?: string;
  cvss?: string;
  cweId?: string;
  owasp?: string;
  endpoints: CorrEndpointRow[];
  problemPoints: CorrProblemPoint[];
  poc?: CorrPoc;
  notes?: string;
}

/** 跨仓裁决归一视图（父级由裁决卡 join 算好传入，组件纯渲染）：无卡 = 未重审。 */
export interface CorrVerdictView {
  group: CorrVerdictGroup;
  direction?: string;
  conclusion?: string;
  confidence?: string;
  crossServiceContext?: string;
  reasoning?: string;
  /** 结构化跨仓触发路径（confirm 卡 exploit_path；历史卡缺省）。 */
  exploitPath?: CorrExploitPath;
  /** 跨仓修订（按需）：危害重述/成因补充/定级建议。 */
  refined?: CorrRefinedFinding;
}

/** 结论组 → 卡头徽标视觉（语义色走主题 token green/red/amber，同 AttackChainCard）。 */
export const VERDICT_BADGE_CLS: Record<CorrVerdictGroup, string> = {
  confirmed: "border-green/40 bg-green/10 text-green",
  refuted: "border-red/40 bg-red/10 text-red",
  uncertain: "border-amber/40 bg-amber/10 text-amber",
  unadjudicated: "border-border text-muted-foreground",
};

/** 漏洞卡 DOM 锚点 id（ID 可能含空白/特殊字符，统一安全化）——跨仓 tab 的定位
 *  （攻击链引用点击 / 总览 severity 药丸）与卡身 id 同源，改一处两处同步。 */
export function corrVulnAnchorId(id: string): string {
  return `corr-vuln-${id.replace(/[^a-zA-Z0-9_-]/g, "_")}`;
}

const asStr = (x: unknown): string | undefined =>
  typeof x === "string" && x ? x : undefined;
const asStrList = (x: unknown): string[] =>
  Array.isArray(x) ? x.filter((s): s is string => typeof s === "string") : [];
const asObjList = (x: unknown): Record<string, unknown>[] =>
  Array.isArray(x)
    ? x.filter(
        (o): o is Record<string, unknown> =>
          typeof o === "object" && o !== null && !Array.isArray(o),
      )
    : [];

/** 位置兜底链：authz/auth 有 vulnerable_code_location；inj/xss 只有
 *  path/sink_function/sink_call；都缺再退 report_problem_points[0]/location。 */
function pickLocation(v: CorrVuln, problemPoints: CorrProblemPoint[]): string | undefined {
  return (
    asStr(v.vulnerable_code_location) ??
    asStr(v.sink_call) ??
    (() => {
      const p = asStr(v.path);
      const f = asStr(v.sink_function);
      return p && f ? `${p} · ${f}` : (p ?? f);
    })() ??
    problemPoints[0]?.location ??
    asStr(v.location)
  );
}

/** 宽松 dict → 强类型视图（导出便于单测）：全部防御拾取，缺字段安全缺省。 */
export function toCorrVulnView(v: CorrVuln): CorrVulnView {
  const endpoints: CorrEndpointRow[] = asObjList(v.report_endpoints)
    .map((ep) => ({
      method: asStr(ep.method),
      path: asStr(ep.path) ?? "",
      params: asStrList(ep.params),
      role: asStr(ep.role),
      auth: asStr(ep.auth),
      route_registered_at: asStr(ep.route_registered_at),
      source_location: asStr(ep.source_location),
      sink_location: asStr(ep.sink_location),
    }))
    .filter((ep) => ep.path || ep.method);
  const problemPoints: CorrProblemPoint[] = asObjList(v.report_problem_points)
    .map((p) => ({
      location: asStr(p.location) ?? "",
      description: asStr(p.description),
      snippet: asStr(p.snippet),
    }))
    .filter((p) => p.location || p.description || p.snippet);
  const rawPoc =
    typeof v.report_poc === "object" && v.report_poc !== null && !Array.isArray(v.report_poc)
      ? (v.report_poc as Record<string, unknown>)
      : undefined;
  const poc: CorrPoc | undefined = rawPoc
    ? {
        curl: asStr(rawPoc.curl),
        raw_http: asStr(rawPoc.raw_http),
        steps: asStrList(rawPoc.steps),
        preconditions: asStr(rawPoc.preconditions),
        expected: asStr(rawPoc.expected_response),
        notes: asStr(rawPoc.notes),
      }
    : undefined;
  const pocUsable =
    poc && (!!poc.curl || !!poc.raw_http || !!poc.preconditions || !!poc.expected
      || !!poc.notes || poc.steps.length > 0)
      ? poc
      : undefined;
  const sevRaw = asStr(v.severity)?.toLowerCase() ?? "";
  const endpointsEntry =
    asStr(v.source_endpoint) ??
    asStr(v.endpoint) ??
    (endpoints[0]
      ? `${endpoints[0].method ?? ""} ${endpoints[0].path}`.trim()
      : undefined);
  return {
    id: asStr(v.ID) ?? "CORR-VULN-?",
    title: asStr(v.title),
    vulnType: asStr(v.vulnerability_type),
    severity: (SEV_CAP[sevRaw] as CorrVulnView["severity"]) ?? undefined,
    confidence: asStr(v.confidence),
    service: asStr(v.service),
    mergeSource: asStr(v.merge_source),
    externallyExploitable: v.externally_exploitable === true,
    endpoint: endpointsEntry,
    location: pickLocation(v, problemPoints),
    impact: asStr(v.impact),
    remediation: asStr(v.remediation),
    cvss: asStr(v.cvss),
    cweId: asStr(v.cwe_id),
    owasp: asStr(v.owasp_category),
    endpoints,
    problemPoints,
    poc: pocUsable,
    notes: asStr(v.notes),
  };
}

/**
 * 跨仓漏洞卡：卡头（ID + 结论徽标 + severity 药丸 + 标题 + 双轨/置信度/可达 + 入口接口）
 * 折叠按钮，展开体（空数据整节省略）：跨仓上下文（裁决结论 + 所在链 + 单仓入口）
 * → 危害 → 相关接口 → 问题点 → POC（curl ↔ Burp 双 tab）→ 修复建议 → 漏洞细节
 * （CVSS/CWE/OWASP）→ notes。
 * 折叠支持受控（collapsed/onToggleCollapse，ReportView 集中 state 模式——跨仓 tab 的
 * 全部收起/展开 + 定位联动需在父级持有）；缺省走内部 state（非受控，向后兼容）。
 */
export function CorrVulnCard({ view, anchorId, collapsed, onToggleCollapse, verdict, chains, multiHops, entrySelfServed, childScanHref }: {
  view: CorrVulnView;
  /** DOM 锚点 id（定位目标），缺省不挂。 */
  anchorId?: string;
  /** 受控折叠态；undefined = 非受控（内部 state）。 */
  collapsed?: boolean;
  /** 受控时的切换回调（非受控忽略）。 */
  onToggleCollapse?: () => void;
  /** 跨仓裁决结论（父级 join 裁决卡所得；缺省 = 未重审）。 */
  verdict?: CorrVerdictView;
  /** 漏洞所在跨服候选链（父级 findChainsForVuln 反查）。 */
  chains?: CorrFlow[];
  /** 漏洞所在多跳候选链（父级 findMultiHopsForVuln：path 经过本服务）。 */
  multiHops?: CorrMultiHopChain[];
  /** 漏洞所在服务本身是拓扑入口：单仓自证可达，无需跨服务链。 */
  entrySelfServed?: boolean;
  /** 子仓扫描详情页路由（父级由 corr_children 映射；缺省不显「查看单仓结果」）。 */
  childScanHref?: string;
}) {
  const { t } = useTranslation();
  const [innerOpen, setInnerOpen] = useState(false);
  const [pocTab, setPocTab] = useState<"curl" | "burp">("curl");
  const open = collapsed === undefined ? innerOpen : !collapsed;
  const toggleOpen = () => {
    if (onToggleCollapse) onToggleCollapse();
    else setInnerOpen((o) => !o);
  };
  const { poc } = view;
  const curl = poc?.curl ?? null;
  const rawHttp = poc?.raw_http ?? null;
  const cv = view.cvss ? splitCvss(view.cvss) : null;
  const group: CorrVerdictGroup = verdict?.group ?? "unadjudicated";
  const chainList = chains ?? [];

  return (
    <section
      data-testid="corr-vuln-card"
      data-severity={view.severity ?? ""}
      id={anchorId}
      className={`space-y-4 rounded-md border border-border bg-card p-4 shadow-[var(--shadow-card)]${
        view.severity ? ` ${SEV_EDGE[view.severity]}` : ""
      }`}
    >
      <button
        type="button"
        data-testid="corr-vuln-card-head"
        aria-expanded={open}
        onClick={toggleOpen}
        className="flex w-full items-start justify-between gap-2 rounded-sm text-left focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary focus-visible:outline-offset-2"
      >
        <div className="min-w-0 flex-1 space-y-1.5">
          {/* 结论行：只放结论四件套 + 可达标记（来源/置信/CWE/接口降为 meta 行）——
              折叠态扫视时结论信号不被来源徽标稀释 */}
          <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
            <span className="shrink-0 font-mono text-[13px] font-semibold text-foreground">
              {view.id}
            </span>
            {verdict && (
              <span
                data-testid="corr-vuln-verdict"
                className={`inline-flex shrink-0 items-center gap-1 rounded-full border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wide ${VERDICT_BADGE_CLS[group]}`}
              >
                {t(`scan.correlation.verdict.${group}`)}
                {verdict.confidence ? ` · ${verdict.confidence}` : ""}
              </span>
            )}
            {view.severity && (
              <span
                data-testid="corr-vuln-sev"
                className={`inline-flex shrink-0 items-center gap-1 rounded-full px-2 py-0.5 font-mono text-[10px] uppercase tracking-wide ${SEV_PILL[view.severity]}`}
              >
                <span className={`sev-dot ${SEV_DOT[view.severity]}`} aria-hidden="true" />
                {t(`vuln.severity.${view.severity}`, { defaultValue: view.severity })}
              </span>
            )}
            {verdict?.refined?.severity && (
              // 定级建议是 severity 同维度的跨仓修订，紧跟药丸以「→」衔接读作
              // 「Critical → 建议 high」，不再做成并列徽标稀释结论行。
              <span
                data-testid="corr-vuln-sev-refined"
                title={t("scan.correlation.refinedSevHint", { severity: verdict.refined.severity })}
                className="inline-flex shrink-0 items-center gap-0.5 font-mono text-[10.5px] text-amber"
              >
                <span aria-hidden>→</span>
                {t("scan.correlation.refinedSev", { severity: verdict.refined.severity })}
              </span>
            )}
            {view.externallyExploitable && (
              <Badge variant="outline" className="text-foreground/75">
                ⌖ {t("vuln.reachable")}
              </Badge>
            )}
          </div>
          {(view.title || view.vulnType) && (
            <h3 className="break-words text-[15px] font-semibold leading-snug tracking-tight text-foreground">
              {view.title ?? view.vulnType}
            </h3>
          )}
          {/* meta 行：双轨来源 / 单仓置信度 / CWE / 入口接口（小字 mono，可与
              结论行同 key 的 confidence 此处加 title 消歧——此为单仓分析置信度，
              结论徽标内为跨仓裁决置信度） */}
          {(view.mergeSource || view.confidence || view.cweId || view.endpoint) && (
            <div className="flex min-w-0 flex-wrap items-center gap-x-2.5 gap-y-0.5 font-mono text-[11px] text-muted-foreground">
              <MergeSourceBadge src={view.mergeSource ?? undefined} />
              {view.confidence && (
                <span title={t("scan.correlation.srcConfidence")}>{view.confidence}</span>
              )}
              {view.cweId && <span>{view.cweId}</span>}
              {view.endpoint && (
                <span className="min-w-0 break-all">{view.endpoint}</span>
              )}
            </div>
          )}
        </div>
        <ChevronDown
          className={`mt-1 size-4 shrink-0 text-muted-foreground transition-transform duration-150 ${open ? "" : "-rotate-90"}`}
          aria-hidden="true"
        />
      </button>

      {open && (
        <div className="space-y-4">
          {/* 跨仓触发路径（2026-09-21）：回答「用户如何可控地触发该漏洞」——
              ①裁决卡结构化 exploit_path ②flow 反查 ③入口服务单仓自证
              ④未建链诚实提示；多跳候选链每卡附带。 */}
          {(verdict || chainList.length > 0 || childScanHref || entrySelfServed) && (
            <div data-testid="corr-cross-ctx" className={SEC_CLS}>
              <div className={`mb-1.5 ${SEC_LABEL_CLS}`}>
                {t("scan.correlation.crossCtxTitle")}
              </div>
              <div className="space-y-2">
                {verdict?.reasoning && (
                  <p data-testid="corr-verdict-reasoning" className="text-xs leading-relaxed text-foreground/85">
                    {verdict.reasoning}
                  </p>
                )}
                {verdict?.crossServiceContext && (
                  <div data-testid="corr-cross-context" className="text-xs text-foreground/80">
                    <span className={SEC_LABEL_CLS}>{t("scan.correlation.adjContext")}: </span>
                    {verdict.crossServiceContext}
                  </div>
                )}
                <ExploitPathBlock
                  path={verdict?.exploitPath}
                  chains={chainList}
                  entrySelfServed={entrySelfServed}
                  entryEndpoint={view.endpoint}
                />
                {(multiHops?.length ?? 0) > 0 && (
                  <div data-testid="corr-vuln-multihops" className="space-y-1">
                    <div className={SEC_LABEL_CLS}>{t("scan.correlation.multiHopRefTitle")}</div>
                    {multiHops!.map((h, i) => (
                      <div key={i} data-testid="corr-vuln-multihop" className="space-y-0.5">
                        <div className="font-mono text-[11px] text-muted-foreground">
                          {h.path.join(" → ")}{" "}
                          <Badge variant="outline" className="ml-1 font-sans text-[10px]">
                            {h.basis} · {h.confidence}
                          </Badge>
                        </div>
                        {(h.hops ?? []).some((hp) => hp.entry || (hp.rpc?.length ?? 0) > 0) && (
                          <div className="space-y-0.5 pl-3">
                            {h.hops!.map((hp, hi) => (
                              <div key={hi} data-testid="corr-vuln-multihop-hop"
                                className="font-mono text-[10.5px] text-muted-foreground">
                                {hp.entry && (
                                  <span className="text-foreground/80">{hp.entry} </span>
                                )}
                                {hp.from}→{hp.to}
                                {(hp.rpc?.length ?? 0) > 0 && (
                                  <span className="text-cyan"> · {hp.rpc!.join(", ")}</span>
                                )}
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
                {childScanHref && (
                  <Link
                    to={childScanHref}
                    data-testid="corr-child-link"
                    className="inline-flex items-center gap-1 text-xs text-primary underline-offset-4 hover:underline focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary"
                  >
                    <ExternalLink className="size-3.5" aria-hidden="true" />
                    {t("scan.correlation.childScanLink")}
                  </Link>
                )}
              </div>
            </div>
          )}

          {/* 危害（跨仓修订版优先，单仓原文折叠保留可审计） */}
          {(view.impact || verdict?.refined?.impact) && (
            <div data-testid="corr-impact" className={SEC_CLS}>
              <div className={`mb-1.5 flex items-center gap-2 ${SEC_LABEL_CLS}`}>
                {t("report.impact")}
                {verdict?.refined?.impact && (
                  <Badge variant="outline" className="border-amber/40 font-sans text-[10px] text-amber">
                    {t("scan.correlation.refinedBadge")}
                  </Badge>
                )}
              </div>
              <p className="whitespace-pre-wrap text-xs leading-relaxed text-foreground/85">
                {verdict?.refined?.impact ?? view.impact}
              </p>
              {verdict?.refined?.impact && view.impact && (
                <details className="mt-1">
                  <summary className="cursor-pointer text-[11px] text-muted-foreground">
                    {t("scan.correlation.refinedOriginal")}
                  </summary>
                  <p className="mt-1 whitespace-pre-wrap text-[11px] text-muted-foreground">
                    {view.impact}
                  </p>
                </details>
              )}
            </div>
          )}

          {/* 成因补充（跨仓，按需）：跨仓分析才看得出的根因细节 */}
          {verdict?.refined?.cause && (
            <div data-testid="corr-refined-cause" className={SEC_CLS}>
              <div className={`mb-1.5 ${SEC_LABEL_CLS}`}>{t("scan.correlation.refinedCause")}</div>
              <p className="whitespace-pre-wrap text-xs leading-relaxed text-foreground/85">
                {verdict.refined.cause}
              </p>
            </div>
          )}

          {/* 相关接口（exploit_path 有跨仓跳时标注：单仓接口是内部面，入口见路径块） */}
          {view.endpoints.length > 0 && (
            <div data-testid="corr-vuln-endpoints" className={SEC_CLS}>
              <div className={`mb-1.5 ${SEC_LABEL_CLS}`}>{t("report.endpoints")}</div>
              {verdict?.exploitPath?.hops?.length ? (
                <p data-testid="corr-endpoints-note" className="mb-2 text-[11px] text-muted-foreground">
                  {t("scan.correlation.endpointsInternalNote")}
                </p>
              ) : null}
              <div className="space-y-2">
                {view.endpoints.map((ep, i) => (
                  <div key={i} data-testid="corr-endpoint-block">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className="font-mono text-xs font-semibold text-foreground">
                        {`${ep.method ?? ""} ${ep.path}`.trim()}
                      </span>
                      {ep.role && (
                        <Badge variant="outline" className="font-mono text-[10px] text-muted-foreground">
                          {ep.role}
                        </Badge>
                      )}
                    </div>
                    {(ep.params.length > 0 || ep.auth || ep.route_registered_at) && (
                      <div className="mt-0.5 text-[11px] text-muted-foreground">
                        {[
                          ep.params.length > 0
                            ? `${t("report.colParams")}: ${ep.params.join(", ")}`
                            : null,
                          ep.auth ? `${t("report.colAuth")}: ${ep.auth}` : null,
                          ep.route_registered_at
                            ? `${t("report.colRoute")}: ${ep.route_registered_at}`
                            : null,
                        ]
                          .filter(Boolean)
                          .join(" · ")}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* 问题点 */}
          {view.problemPoints.length > 0 && (
            <div className={SEC_CLS}>
              <div className={`mb-1.5 ${SEC_LABEL_CLS}`}>{t("report.problemPoints")}</div>
              <div className="space-y-2">
                {view.problemPoints.map((p, i) => (
                  <div key={i} data-testid="corr-problem-point" className="space-y-1">
                    {p.location && (
                      <code data-testid="corr-problem-point-location" className="font-mono text-[11.5px] text-cyan">
                        {p.location}
                      </code>
                    )}
                    {p.description && (
                      <div className="text-xs text-foreground/80">{p.description}</div>
                    )}
                    {p.snippet && (
                      <CopyableCodePanel
                        value={p.snippet}
                        testId="corr-problem-point-snippet"
                        className={CODE_CLS}
                      >
                        {highlightCode(p.snippet, langFromPath(p.location))}
                      </CopyableCodePanel>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* POC：curl ↔ Burp 双 tab + 步骤（对齐 report 卡交互）；有跨仓 PoC 时
              单仓 PoC 降级——打的是后端内部接口，跨仓场景不可达 */}
          {poc && (
            <div data-testid="corr-poc" className={`space-y-2 ${SEC_CLS}`}>
              <div className="flex flex-wrap items-center gap-2">
                <span className={SEC_LABEL_CLS}>{t("markdown.pocSection")}</span>
                {verdict?.exploitPath?.poc && (
                  <span data-testid="corr-poc-single-note" className="text-[10.5px] text-muted-foreground">
                    {t("scan.correlation.pocSingleNote")}
                  </span>
                )}
                {(curl || rawHttp) && (
                  <div className="flex items-center gap-0.5" role="tablist">
                    {curl && (
                      <button
                        type="button"
                        role="tab"
                        aria-selected={pocTab === "curl"}
                        data-testid="corr-poc-tab-curl"
                        onClick={() => setPocTab("curl")}
                        className={`rounded-sm px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wide transition-colors ${
                          pocTab === "curl"
                            ? "bg-muted font-semibold text-foreground"
                            : "text-muted-foreground hover:text-foreground"
                        }`}
                      >
                        {t("report.pocCurl")}
                      </button>
                    )}
                    {rawHttp && (
                      <button
                        type="button"
                        role="tab"
                        aria-selected={pocTab === "burp"}
                        data-testid="corr-poc-tab-burp"
                        onClick={() => setPocTab("burp")}
                        className={`rounded-sm px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wide transition-colors ${
                          pocTab === "burp"
                            ? "bg-muted font-semibold text-foreground"
                            : "text-muted-foreground hover:text-foreground"
                        }`}
                      >
                        {t("report.pocBurp")}
                      </button>
                    )}
                  </div>
                )}
              </div>
              {poc.preconditions && (
                <div className="text-xs text-foreground/80">
                  <span className={SEC_LABEL_CLS}>{t("report.preconditions")}: </span>
                  {poc.preconditions}
                </div>
              )}
              {poc.expected && (
                <div className="text-xs text-foreground/80">
                  <span className={SEC_LABEL_CLS}>{t("report.expectedResponse")}: </span>
                  {poc.expected}
                </div>
              )}
              {poc.steps.length > 0 && (
                <ol
                  data-testid="corr-poc-steps"
                  className="list-decimal space-y-0.5 pl-5 text-xs text-foreground/80"
                >
                  {poc.steps.map((s, i) => (
                    <li key={i}>{s}</li>
                  ))}
                </ol>
              )}
              {pocTab === "curl" && curl && (
                <CopyableCodePanel
                  value={curl}
                  testId="corr-poc-curl"
                  copyTestId="copy-poc-curl"
                  copyLabel={t("report.copyCurl")}
                  className={CODE_CLS}
                >
                  {highlightCode(curl, "bash")}
                </CopyableCodePanel>
              )}
              {pocTab === "burp" && rawHttp && (
                <CopyableCodePanel
                  value={rawHttp}
                  testId="corr-poc-raw-http"
                  copyTestId="copy-poc-raw-http"
                  copyLabel={t("report.pocBurp")}
                  className={CODE_CLS}
                >
                  {highlightCode(rawHttp, "http")}
                </CopyableCodePanel>
              )}
              {poc.notes && <div className="text-xs text-muted-foreground">{poc.notes}</div>}
            </div>
          )}

          {/* 修复建议 */}
          {view.remediation && (
            <div data-testid="corr-remediation" className={SEC_CLS}>
              <div className={`mb-1.5 ${SEC_LABEL_CLS}`}>{t("report.remediation")}</div>
              <p className="whitespace-pre-wrap text-xs leading-relaxed text-foreground/85">
                {view.remediation}
              </p>
            </div>
          )}

          {/* 漏洞细节：位置 + CVSS（尾分数提亮，与 report 卡同规则）+ OWASP */}
          {(view.location || cv || view.owasp) && (
            <div className={SEC_CLS}>
              <div className={SEC_LABEL_CLS}>{t("report.details")}</div>
              <div data-testid="corr-vuln-meta" className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1.5">
                {view.location && (
                  <code className="font-mono text-[11px] text-cyan">{view.location}</code>
                )}
                {cv && (
                  <span className="inline-flex items-baseline gap-1.5">
                    <span className="font-mono text-[10.5px] text-muted-foreground">{cv.vector}</span>
                    {cv.score && (
                      <span className="font-mono text-[14px] font-semibold leading-none text-foreground">
                        {cv.score}
                      </span>
                    )}
                  </span>
                )}
                {view.owasp && (
                  <Badge variant="outline" className="font-mono text-[10px] text-muted-foreground">
                    {view.owasp}
                  </Badge>
                )}
              </div>
            </div>
          )}

          {/* notes */}
          {view.notes && (
            <p className={SEC_CLS + " text-xs text-muted-foreground"}>{view.notes}</p>
          )}
        </div>
      )}
    </section>
  );
}

/**
 * 跨仓触发路径块（2026-09-21）：四级降级回答「用户如何可控触发」——
 * ①裁决卡结构化 exploit_path（入口接口 → 逐跳 RPC → 触达点 + 用户可控性）
 * ②flow 反查（entry 接口 → RPC method + 调用点证据）
 * ③入口服务单仓自证（漏洞接口即对外入口，无需跨服务链）
 * ④未建链诚实提示（可达性论证在跨仓上下文，不给假路径）。
 * 纯渲染；宽松防御拾取（exploit_path 是新字段，历史卡/后端版本可缺）。
 */
function ExploitPathBlock({ path, chains, entrySelfServed, entryEndpoint }: {
  path?: CorrExploitPath;
  chains: CorrFlow[];
  entrySelfServed?: boolean;
  entryEndpoint?: string;
}) {
  const { t } = useTranslation();
  const hops = Array.isArray(path?.hops) ? path!.hops! : [];
  const hasStructured = !!path && (!!path.entry_endpoint || hops.length > 0 || !!path.sink);
  // 跨仓 PoC 宽松防御拾取（新字段，历史卡/残缺数据可缺）。
  const rawPoc = (path?.poc && typeof path.poc === "object" ? path.poc : undefined) as
    | { curl?: unknown; raw_http?: unknown; steps?: unknown;
        preconditions?: unknown; notes?: unknown } | undefined;
  const rawSteps = Array.isArray(rawPoc?.steps)
    ? rawPoc!.steps.filter((s): s is string => typeof s === "string") : [];
  const pocBlock = rawPoc && (asStr(rawPoc.curl) || asStr(rawPoc.raw_http)
      || asStr(rawPoc.preconditions) || asStr(rawPoc.notes) || rawSteps.length > 0)
    ? { curl: asStr(rawPoc.curl), raw_http: asStr(rawPoc.raw_http),
        preconditions: asStr(rawPoc.preconditions), notes: asStr(rawPoc.notes),
        steps: rawSteps }
    : undefined;

  if (hasStructured) {
    return (
      <div data-testid="corr-exploit-path" className="rounded-md border border-border/70 bg-muted/30 p-3">
        <div className={SEC_LABEL_CLS}>{t("scan.correlation.pathTitle")}</div>
        {/* timeline：入口/触达点是节点（色点 + 连线），RPC 是连线上的边注记——
            攻击链方向感是本块的视觉锚点，读作 自上而下：入口 → RPC ×N → 触达 */}
        <ol className="mt-2">
          {path?.entry_endpoint && (
            <li data-testid="corr-exploit-entry" className="flex gap-3">
              <div className="flex flex-col items-center">
                <span aria-hidden className="mt-1 size-2 shrink-0 rounded-full bg-green" />
                {(hops.length > 0 || path.sink) && (
                  <span aria-hidden className="w-px flex-1 bg-border" />
                )}
              </div>
              <div className="min-w-0 pb-3">
                <div className="flex flex-wrap items-baseline gap-x-2">
                  <span className="text-[11px] font-medium leading-5 text-green">
                    {t("scan.correlation.pathEntry")}
                  </span>
                  <span className="font-mono text-[11px] text-muted-foreground">
                    {path.entry_service}
                  </span>
                </div>
                <div className="mt-0.5 break-all font-mono text-[12.5px] font-semibold text-foreground">
                  {path.entry_endpoint}
                </div>
              </div>
            </li>
          )}
          {hops.map((h, i) => (
            <li key={i} data-testid="corr-exploit-hop" className="flex gap-3">
              <div className="flex flex-col items-center">
                {(i > 0 || path?.entry_endpoint) && (
                  <span aria-hidden className="w-px flex-1 bg-border" />
                )}
                {(i < hops.length - 1 || path?.sink) && (
                  <span aria-hidden className="w-px flex-1 bg-border" />
                )}
              </div>
              <div className="min-w-0 py-0.5">
                <div className="flex flex-wrap items-baseline gap-x-2 font-mono">
                  <span className="text-[10px] uppercase tracking-wide text-muted-foreground">
                    RPC {i + 1}
                  </span>
                  <span className="break-all text-[12px] font-medium leading-5 text-cyan">
                    {h.rpc}
                  </span>
                </div>
                <div className="mt-0.5 font-mono text-[11px] text-muted-foreground">
                  {h.from} → {h.to}
                  {h.call_site ? ` · @ ${h.call_site}` : ""}
                </div>
              </div>
            </li>
          ))}
          {path?.sink && (
            <li data-testid="corr-exploit-sink" className="flex gap-3">
              <div className="flex flex-col items-center">
                {(hops.length > 0 || path?.entry_endpoint) && (
                  <span aria-hidden className="w-px flex-1 bg-border" />
                )}
                <span
                  aria-hidden
                  className="mt-1 size-2 shrink-0 rounded-full bg-red ring-2 ring-red/20"
                />
              </div>
              <div className="min-w-0">
                <div className="flex flex-wrap items-baseline gap-x-2">
                  <span className="text-[11px] font-medium leading-5 text-red">
                    {t("scan.correlation.pathSink")}
                  </span>
                  <span className="break-all font-mono text-[12.5px] font-semibold text-foreground/90">
                    {path.sink}
                  </span>
                </div>
              </div>
            </li>
          )}
        </ol>
        {path?.user_controlled && (
          <div data-testid="corr-exploit-ctrl" className="mt-2 border-t border-border/60 pt-2 text-[11.5px] text-foreground/85">
            <span className={SEC_LABEL_CLS}>{t("scan.correlation.pathCtrl")}: </span>
            {path.user_controlled}
          </div>
        )}
        {pocBlock && (
          <div data-testid="corr-exploit-poc" className="mt-2 space-y-1.5 border-t border-border/60 pt-2">
            <div className={SEC_LABEL_CLS}>{t("scan.correlation.crossPocTitle")}</div>
            {pocBlock.preconditions && (
              <div className="text-[11px] text-foreground/80">
                <span className={SEC_LABEL_CLS}>{t("report.preconditions")}: </span>
                {pocBlock.preconditions}
              </div>
            )}
            {pocBlock.steps.length > 0 && (
              <ol className="list-decimal space-y-0.5 pl-5 text-[11px] text-foreground/80">
                {pocBlock.steps.map((s, i) => <li key={i}>{s}</li>)}
              </ol>
            )}
            {pocBlock.curl && (
              <CopyableCodePanel
                value={pocBlock.curl}
                testId="corr-exploit-poc-curl"
                copyTestId="copy-exploit-poc-curl"
                copyLabel={t("report.copyCurl")}
                className={CODE_CLS}
              >
                {highlightCode(pocBlock.curl, "bash")}
              </CopyableCodePanel>
            )}
            {pocBlock.raw_http && (
              <CopyableCodePanel
                value={pocBlock.raw_http}
                testId="corr-exploit-poc-raw-http"
                copyTestId="copy-exploit-poc-raw-http"
                copyLabel={t("report.pocBurp")}
                className={CODE_CLS}
              >
                {highlightCode(pocBlock.raw_http, "http")}
              </CopyableCodePanel>
            )}
            {pocBlock.notes && (
              <div className="text-[11px] text-muted-foreground">{pocBlock.notes}</div>
            )}
          </div>
        )}
      </div>
    );
  }

  if (chains.length > 0) {
    return (
      <div data-testid="corr-vuln-chains" className="space-y-1.5">
        <div className={SEC_LABEL_CLS}>{t("scan.correlation.pathTitle")}</div>
        {chains.map((f, i) => (
          <div key={i} data-testid="corr-vuln-chain" className="space-y-0.5">
            <div className="flex flex-wrap items-center gap-1.5 font-mono text-[11px]">
              <span className="text-foreground">{f.entry}</span>
              <span className="text-muted-foreground">→</span>
              <span className="text-cyan">{f.method}</span>
              <Badge variant="outline" className="font-sans text-[10px] text-muted-foreground">
                {f.confidence}
              </Badge>
            </div>
            {f.evidence && (
              <p className="line-clamp-2 text-[11px] text-muted-foreground">{f.evidence}</p>
            )}
          </div>
        ))}
      </div>
    );
  }

  if (entrySelfServed) {
    return (
      <div data-testid="corr-exploit-self" className="text-[11px] text-foreground/80">
        <Badge variant="outline" className="mr-1.5 font-sans text-[10px] text-green">
          {t("scan.correlation.pathEntry")}
        </Badge>
        {t("scan.correlation.pathSelfServed")}
        {entryEndpoint && (
          <span className="ml-1 font-mono text-foreground/85">{entryEndpoint}</span>
        )}
      </div>
    );
  }

  return (
    <div data-testid="corr-exploit-unlinked" className="text-[11px] text-muted-foreground">
      {t("scan.correlation.pathUnlinked")}
    </div>
  );
}
