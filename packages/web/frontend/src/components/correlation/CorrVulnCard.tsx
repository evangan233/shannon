import { useState } from "react";
import { useTranslation } from "react-i18next";
import { ChevronDown } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { MergeSourceBadge } from "@/components/VulnCard";
import type { CorrVuln } from "@/api/types";
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
 * 跨仓漏洞卡：卡头（ID + severity 药丸 + 标题 + 双轨/置信度/可达 + 入口接口）折叠按钮，
 * 展开体七节（空数据整节省略）：危害 → 相关接口 → 问题点 → POC（curl ↔ Burp 双 tab）
 * → 修复建议 → 漏洞细节（CVSS/CWE/OWASP）→ notes。
 */
export function CorrVulnCard({ view }: { view: CorrVulnView }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const [pocTab, setPocTab] = useState<"curl" | "burp">("curl");
  const { poc } = view;
  const curl = poc?.curl ?? null;
  const rawHttp = poc?.raw_http ?? null;
  const cv = view.cvss ? splitCvss(view.cvss) : null;

  return (
    <section
      data-testid="corr-vuln-card"
      data-severity={view.severity ?? ""}
      className={`space-y-4 rounded-md border border-border bg-card p-4 shadow-[var(--shadow-card)]${
        view.severity ? ` ${SEV_EDGE[view.severity]}` : ""
      }`}
    >
      <button
        type="button"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-start justify-between gap-2 rounded-sm text-left focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary focus-visible:outline-offset-2"
      >
        <div className="min-w-0 flex-1 space-y-1.5">
          <div className="flex min-w-0 flex-wrap items-center gap-x-2.5 gap-y-1.5">
            <span className="shrink-0 font-mono text-[13px] font-semibold text-foreground">
              {view.id}
            </span>
            {view.severity && (
              <span
                data-testid="corr-vuln-sev"
                className={`inline-flex shrink-0 items-center gap-1 rounded-full px-2 py-0.5 font-mono text-[10px] uppercase tracking-wide ${SEV_PILL[view.severity]}`}
              >
                <span className={`sev-dot ${SEV_DOT[view.severity]}`} aria-hidden="true" />
                {t(`vuln.severity.${view.severity}`, { defaultValue: view.severity })}
              </span>
            )}
            <MergeSourceBadge src={view.mergeSource ?? undefined} />
            {view.confidence && (
              <Badge variant="outline" className="font-mono text-muted-foreground">
                {view.confidence}
              </Badge>
            )}
            {view.externallyExploitable && (
              <Badge variant="outline" className="text-foreground/75">
                ⌖ {t("vuln.reachable")}
              </Badge>
            )}
            {view.cweId && (
              <span className="font-mono text-[11px] text-muted-foreground">{view.cweId}</span>
            )}
            {view.endpoint && (
              <span className="truncate font-mono text-[11px] text-muted-foreground">
                {view.endpoint}
              </span>
            )}
          </div>
          {(view.title || view.vulnType) && (
            <h3 className="break-words text-[15px] font-semibold leading-snug tracking-tight text-foreground">
              {view.title ?? view.vulnType}
            </h3>
          )}
        </div>
        <ChevronDown
          className={`mt-1 size-4 shrink-0 text-muted-foreground transition-transform duration-150 ${open ? "" : "-rotate-90"}`}
          aria-hidden="true"
        />
      </button>

      {open && (
        <div className="space-y-4">
          {/* 危害 */}
          {view.impact && (
            <div data-testid="corr-impact" className={SEC_CLS}>
              <div className={`mb-1.5 ${SEC_LABEL_CLS}`}>{t("report.impact")}</div>
              <p className="whitespace-pre-wrap text-xs leading-relaxed text-foreground/85">
                {view.impact}
              </p>
            </div>
          )}

          {/* 相关接口 */}
          {view.endpoints.length > 0 && (
            <div data-testid="corr-vuln-endpoints" className={SEC_CLS}>
              <div className={`mb-1.5 ${SEC_LABEL_CLS}`}>{t("report.endpoints")}</div>
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

          {/* POC：curl ↔ Burp 双 tab + 步骤（对齐 report 卡交互） */}
          {poc && (
            <div data-testid="corr-poc" className={`space-y-2 ${SEC_CLS}`}>
              <div className="flex flex-wrap items-center gap-2">
                <span className={SEC_LABEL_CLS}>{t("markdown.pocSection")}</span>
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
