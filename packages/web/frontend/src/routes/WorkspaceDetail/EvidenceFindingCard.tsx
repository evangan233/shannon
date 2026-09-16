import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import type { EvidenceFinding } from "@/api/types";
import { CopyableCodePanel } from "@/components/report/CopyableCodePanel";
import { highlightCode, langFromPath } from "@/lib/highlight-code";

/**
 * 白盒 finding 富证据卡（2026-09-16 证据页 v2）。
 *
 * 挂载态（接口两栏）与 unmatched（未挂载区一等公民）同构复用——v1 的
 * unmatched 只剩 id/title 黑洞，用户（尤其 Go/RPC 项目底册无 route 行、
 * 全部 finding 落 unmatched）在证据页看不到任何「为什么有问题」的实质内容。
 *
 * 节全部非空才渲染（旧 v1 产物缺字段自然空白）；样式对齐报告页
 * VulnerabilityCard 七节语言（mono 小节头 + CopyableCodePanel 高亮）。
 */

const SEC_LABEL_CLS = "font-mono text-[10px] uppercase tracking-wider text-muted-foreground";
const CODE_CLS =
  "code-panel overflow-x-auto p-2 font-mono text-[11.5px] leading-relaxed";

const L = (k: string) => `workspaceDetail.evidence.${k}`;

/** per-class 证据字段 → i18n 标签键（分组渲染顺序）。 */
const FIELD_LABELS: Array<[keyof EvidenceFinding, string]> = [
  // auth / authz 共用「判定依据」组
  ["missing_defense", "fldMissingDefense"],
  ["guard_evidence", "fldGuardEvidence"],
  ["role_context", "fldRoleContext"],
  ["reason", "fldReason"],
  ["exploitation_hypothesis", "fldExploitationHypothesis"],
  ["suggested_exploit_technique", "fldSuggestedTechnique"],
  ["side_effect", "fldSideEffect"],
  ["minimal_witness", "fldMinimalWitness"],
  ["vulnerable_code_location", "fldVulnerableCodeLocation"],
  ["source_endpoint", "fldSourceEndpoint"],
  // taint 细节组
  ["source", "fldSource"],
  ["sink_call", "fldSinkCall"],
  ["sink_function", "fldSinkFunction"],
  ["slot_type", "fldSlotType"],
  ["vulnerable_parameter", "fldVulnerableParameter"],
  ["sanitization_observed", "fldSanitizationObserved"],
  ["render_context", "fldRenderContext"],
  ["encoding_observed", "fldEncodingObserved"],
  ["path", "fldPath"],
  ["source_track", "fldSourceTrack"],
  ["sanitizer_annotations", "fldSanitizerAnnotations"],
  ["accessible_routes", "fldAccessibleRoutes"],
];

/** 字段值宽容渲染：string 直显，数组逐行，其余 JSON（数据侧形状外键不丢）。 */
function FieldValue({ value }: { value: unknown }) {
  if (typeof value === "string") return <span className="break-words">{value}</span>;
  if (Array.isArray(value)) {
    return (
      <span className="break-words">
        {value.map((v) => (typeof v === "string" ? v : JSON.stringify(v))).join("；")}
      </span>
    );
  }
  if (value == null) return null;
  return <span className="break-words">{JSON.stringify(value)}</span>;
}

export function EvidenceFindingCard({
  f,
  reason,
  dataflowTreeId,
}: {
  f: EvidenceFinding;
  /** unmatched 专属：挂载失败原因徽标（no-route-entries 等）。 */
  reason?: string | null;
  /** finding_id → dataflow tree_id（EvidenceTab 建，无映射不渲染链接）。 */
  dataflowTreeId?: string | null;
}) {
  const { t } = useTranslation();
  const poc = f.poc;
  const evidence = f.evidence;
  const fields = FIELD_LABELS.filter(([key]) => {
    const v = f[key];
    return v != null && !(typeof v === "string" && !v.trim());
  });
  return (
    <article data-testid="evidence-finding-card" className="space-y-2.5 rounded border p-2 text-xs">
      {/* 头部：id · title + 徽标组 */}
      <div className="font-medium">
        <span className="font-mono">{f.id}</span> · {f.title}
        {f.vuln_class && (
          <span className="ml-1 rounded bg-muted px-1 text-[10px] text-muted-foreground">
            {f.vuln_class}
          </span>
        )}
        {f.severity && <SeverityTag severity={f.severity} />}
        {f.confidence && (
          <span className="ml-1 rounded bg-muted px-1 text-[10px] text-muted-foreground">
            {f.confidence}
          </span>
        )}
        {f.cwe_id && (
          <span className="ml-1 rounded bg-muted px-1 text-[10px] text-muted-foreground">
            {f.cwe_id}
          </span>
        )}
        {f.externally_exploitable != null && (
          <span className={`ml-1 rounded px-1 text-[10px] ${f.externally_exploitable ? "bg-red-500/10 text-red-600" : "bg-muted text-muted-foreground"}`}>
            {f.externally_exploitable ? t(L("externallyExploitable")) : t(L("notExternallyExploitable"))}
          </span>
        )}
        {reason && (
          <span className="ml-1 rounded bg-amber-500/15 px-1 text-[10px] text-amber-600"
                data-testid="unmatched-reason">
            {t(L(`reason.${reason}`), reason)}
          </span>
        )}
      </div>

      {/* 判定与理由（v1 类型已有、零渲染的核心判据） */}
      {(f.verdict || f.mismatch_reason) && (
        <div>
          {f.verdict && (
            <span className="mr-1 rounded bg-muted px-1 text-[10px] font-mono" data-testid="finding-verdict">
              {f.verdict}
            </span>
          )}
          {f.mismatch_reason && (
            <span className="text-muted-foreground">{f.mismatch_reason}</span>
          )}
        </div>
      )}

      {/* 涉及参数 / 认证要求 / witness（v1 卡片既有内容，重构不得丢失） */}
      {f.params.length > 0 && (
        <p>
          <span className="text-muted-foreground">{t(L("paramsLabel"))}：</span>
          {f.params.join("、")}
        </p>
      )}
      {f.auth_required && (
        <p>
          <span className="text-muted-foreground">{t(L("authLabel"))}：</span>
          {f.auth_required}
        </p>
      )}
      {f.evidence_chain && (
        <p className="whitespace-pre-wrap break-words">
          <span className="text-muted-foreground">{t(L("evidenceChain"))}：</span>
          {f.evidence_chain}
        </p>
      )}
      {f.witness_payload && (
        <CopyableCodePanel value={f.witness_payload} testId="ev-witness" className="code-panel overflow-x-auto p-2 font-mono text-[11.5px] leading-relaxed">
          {f.witness_payload}
        </CopyableCodePanel>
      )}

      {/* 成因 / 危害 / 修复（report_data narrative，复用报告页文案） */}
      {f.narrative?.cause && (
        <div data-testid="ev-cause">
          <div className={SEC_LABEL_CLS}>{t("report.cause")}</div>
          <p className="mt-0.5 whitespace-pre-wrap break-words text-foreground/85">{f.narrative.cause}</p>
        </div>
      )}
      {f.narrative?.impact && (
        <div data-testid="ev-impact">
          <div className={SEC_LABEL_CLS}>{t("report.impact")}</div>
          <p className="mt-0.5 whitespace-pre-wrap break-words text-foreground/85">{f.narrative.impact}</p>
        </div>
      )}
      {f.narrative?.remediation && (
        <div data-testid="ev-remediation">
          <div className={SEC_LABEL_CLS}>{t("report.remediation")}</div>
          <p className="mt-0.5 whitespace-pre-wrap break-words text-foreground/85">{f.narrative.remediation}</p>
        </div>
      )}

      {/* 问题点：位置 mono + 说明 + 源码片段高亮 */}
      {(f.problem_points?.length ?? 0) > 0 && (
        <div data-testid="ev-problem-points">
          <div className={SEC_LABEL_CLS}>{t("report.problemPoints")}</div>
          <div className="mt-1 space-y-2">
            {f.problem_points!.map((p, i) => (
              <div key={i} data-testid="ev-problem-point" className="space-y-1">
                {p.location && (
                  <code className="font-mono text-[11px] text-cyan">{p.location}</code>
                )}
                {p.description && <div className="text-foreground/80">{p.description}</div>}
                {p.snippet && (
                  <CopyableCodePanel value={p.snippet} testId="ev-problem-snippet" className={CODE_CLS}>
                    {highlightCode(p.snippet, p.location ? langFromPath(p.location) : null)}
                  </CopyableCodePanel>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* PoC：curl / raw_http / request 代码面板 + 前置条件小字 */}
      {poc && (
        <div data-testid="ev-poc">
          <div className={SEC_LABEL_CLS}>{t("markdown.pocSection")}</div>
          <div className="mt-1 space-y-2">
            {poc.curl && (
              <CopyableCodePanel value={poc.curl} testId="ev-poc-curl" className={CODE_CLS}>
                {highlightCode(poc.curl, "bash")}
              </CopyableCodePanel>
            )}
            {poc.raw_http && (
              <CopyableCodePanel value={poc.raw_http} testId="ev-poc-raw-http" className={CODE_CLS}>
                {poc.raw_http}
              </CopyableCodePanel>
            )}
            {poc.request != null && (
              <CopyableCodePanel
                value={typeof poc.request === "string" ? poc.request : JSON.stringify(poc.request, null, 2)}
                testId="ev-poc-request"
                className={CODE_CLS}
              >
                {typeof poc.request === "string" ? poc.request : JSON.stringify(poc.request, null, 2)}
              </CopyableCodePanel>
            )}
            {(poc.preconditions || poc.expected_response || poc.notes) && (
              <p className="text-[11px] text-muted-foreground">
                {poc.preconditions && (
                  <>前置：{Array.isArray(poc.preconditions) ? poc.preconditions.join("；") : poc.preconditions}{" "}</>
                )}
                {poc.expected_response && <>预期：{poc.expected_response}{" "}</>}
                {poc.notes && <>{poc.notes}</>}
              </p>
            )}
          </div>
        </div>
      )}

      {/* 数据流步骤：时间线（证据页以判断为目的，默认展开） */}
      {(f.dataflow_steps?.length ?? 0) > 0 && (
        <div data-testid="ev-dataflow">
          <div className={SEC_LABEL_CLS}>{t("report.dataflowSteps")}</div>
          <ol className="mt-1 space-y-1 border-l border-border/60 pl-4">
            {f.dataflow_steps!.map((s, i) => (
              <li key={i} data-testid="ev-dataflow-step" className="leading-relaxed">
                <span className="font-medium text-foreground/85">{s.label}</span>
                {s.file && (
                  <code className="ml-1.5 font-mono text-[11px] text-cyan">
                    {s.file}{s.line != null ? `:${s.line}` : ""}
                  </code>
                )}
                {s.protection && (
                  <span className="ml-1.5 text-muted-foreground">
                    {t("report.stepProtection")}: {s.protection}
                  </span>
                )}
              </li>
            ))}
          </ol>
        </div>
      )}

      {/* per-class 证据字段（auth/authz 判定依据 + taint 细节） */}
      {fields.length > 0 && (
        <div data-testid="ev-fields" className="space-y-0.5">
          {fields.map(([key, labelKey]) => (
            <div key={String(key)} className="leading-relaxed">
              <span className="text-muted-foreground">{t(L(labelKey))}：</span>
              <FieldValue value={f[key]} />
            </div>
          ))}
        </div>
      )}

      {/* 验证证据子块：verification 徽章 + 实测步骤 + 动态证据 */}
      {evidence && (
        <div data-testid="ev-evidence" className="space-y-1.5 border-t border-border pt-2">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className={SEC_LABEL_CLS}>{t("report.evidence")}</span>
            {evidence.verification && (
              <span className={`rounded px-1 text-[10px] ${evidence.verification === "dynamic" ? "bg-emerald-500/10 text-emerald-600" : "bg-muted text-muted-foreground"}`}>
                {evidence.verification === "dynamic"
                  ? t("report.verificationDynamic")
                  : t("report.verificationStatic")}
              </span>
            )}
            {evidence.verdict && (
              <span className="rounded bg-muted px-1 font-mono text-[10px]">{evidence.verdict}</span>
            )}
          </div>
          {(evidence.steps?.length ?? 0) > 0 && (
            <ol className="space-y-1.5 border-l border-border/60 pl-4">
              {evidence.steps!.map((step, i) => (
                <li key={i} data-testid="ev-verify-step" className="space-y-1">
                  <div className="leading-relaxed">
                    <span className="mr-1.5 font-mono text-[10px] text-muted-foreground">
                      {String(i + 1).padStart(2, "0")}
                    </span>
                    <span className="font-medium text-foreground/85">{step.action}</span>
                  </div>
                  {step.command && (
                    <CopyableCodePanel value={step.command} testId="ev-verify-command" className={CODE_CLS}>
                      {highlightCode(step.command, "bash")}
                    </CopyableCodePanel>
                  )}
                  {step.result && (
                    <p className="text-[11px] text-muted-foreground">→ {step.result}</p>
                  )}
                </li>
              ))}
            </ol>
          )}
          {evidence.dynamic_evidence && (
            <CopyableCodePanel
              value={evidence.dynamic_evidence}
              testId="ev-dynamic-evidence"
              className="code-panel code-panel-ok p-2 font-mono text-[11.5px] leading-relaxed"
            >
              {evidence.dynamic_evidence}
            </CopyableCodePanel>
          )}
          {evidence.code_snippet && (
            <CopyableCodePanel value={evidence.code_snippet} testId="ev-code-snippet" className={CODE_CLS}>
              {evidence.code_snippet}
            </CopyableCodePanel>
          )}
          {evidence.notes && <p className="text-[11px] text-muted-foreground">{evidence.notes}</p>}
        </div>
      )}

      {/* 互链：数据流树（有映射才渲染）+ 报告卡锚点 */}
      {(dataflowTreeId || f.id) && (
        <div className="flex flex-wrap gap-3 border-t border-border pt-2">
          {dataflowTreeId && (
            <Link
              to={`../dataflow?tree=${encodeURIComponent(dataflowTreeId)}`}
              data-testid="evidence-dataflow-link"
              className="inline-flex items-center gap-1 text-primary hover:underline"
            >
              {t("vuln.viewDataflow")} <span aria-hidden>→</span>
            </Link>
          )}
          {f.id && (
            <Link
              to={`../report#${f.id}`}
              data-testid="evidence-report-link"
              className="inline-flex items-center gap-1 text-primary hover:underline"
            >
              {t(L("reportLink"))} <span aria-hidden>→</span>
            </Link>
          )}
        </div>
      )}
    </article>
  );
}

export function SeverityTag({ severity }: { severity: string }) {
  return (
    <span className="ml-1 rounded bg-red-500/10 px-1 text-[10px] text-red-600">
      {severity}
    </span>
  );
}
