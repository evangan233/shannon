import { useMemo, useState } from "react";
import useSWR from "swr";
import { useParams } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { ApiError, fetchEvidenceMatrix, fetchDataflowView } from "@/api/client";
import type {
  EvidenceEndpoint,
  EvidenceMatrix,
  EvidenceUnmatchedVerdict,
  EvidenceVerdict,
} from "@/api/types";
import { buildFindingTreeMap } from "@/components/dataflow/findingTreeMap";
import { CopyableCodePanel } from "@/components/report/CopyableCodePanel";
import { Empty } from "@/components/Empty";
import { Skeleton } from "@/components/ui/skeleton";
import { EvidenceFindingCard, SeverityTag } from "./EvidenceFindingCard";

/**
 * 接口证据 tab（spec 2026-09-10 §8；2026-09-16 证据页 v2 详细化）。
 *
 * 左列接口清单（coverage/method 筛选）+ 右侧选中接口的白盒（蓝）/黑盒（橙）
 * 两栏证据；unmatched 一等公民化——banner 切换右侧全宽面板，finding 出完整
 * 证据卡（Go/RPC 项目底册无 route 行时全部证据在此，不再只剩标题黑洞）。
 * 404 = 无证据产物（旧版/纯黑盒扫描）→ Empty 空态。
 * SWR 拉 GET /workspaces/{ws}/scans/{id}/evidence-matrix（web lazy 重建，
 * mtime + schema_version 失效语义见后端）。
 */
const COVERAGE_ORDER = { findings: 0, defended: 1, clean: 2 } as const;
const COVERAGE_KEY = {
  findings: "workspaceDetail.evidence.coverageFindings",
  defended: "workspaceDetail.evidence.coverageDefended",
  clean: "workspaceDetail.evidence.coverageClean",
};

export function EvidenceTab() {
  const { t } = useTranslation();
  const { workspace, scanId } = useParams<{ workspace: string; scanId: string }>();
  const ws = workspace ?? "";
  const id = scanId ?? "";
  const { data, error, isLoading } = useSWR<EvidenceMatrix>(
    ws && id ? ["evidence-matrix", ws, id] : null,
    () => fetchEvidenceMatrix(ws, id),
  );
  // 数据流跳转映射（与 DataFlowTab/DeliverablesTab 同 SWR key → 共享缓存零额外
  // 请求；404/失败 → 无映射 → 卡上「查看数据流」链接不渲染）。
  const { data: dataflow } = useSWR(
    ws && id ? ["dataflow", ws, id] : null,
    () => fetchDataflowView(ws, id),
  );
  const treeByFindingId = useMemo(() => buildFindingTreeMap(dataflow), [dataflow]);

  const [coverageFilter, setCoverageFilter] = useState<string>("all");
  const [methodFilter, setMethodFilter] = useState<string>("all");
  const [selectedPath, setSelectedPath] = useState<string | null>(null);
  // unmatched 全宽面板（v2 一等公民化）：banner 点击切换右侧显示，选接口自动退回。
  const [showUnmatched, setShowUnmatched] = useState(false);

  const methods = useMemo(
    () => [...new Set((data?.endpoints ?? []).map((e) => e.method))].sort(),
    [data],
  );
  const endpoints = useMemo(() => {
    const list = (data?.endpoints ?? []).filter((e) =>
      (coverageFilter === "all" || e.coverage === coverageFilter) &&
      (methodFilter === "all" || e.method === methodFilter));
    return [...list].sort((a, b) =>
      COVERAGE_ORDER[a.coverage] - COVERAGE_ORDER[b.coverage] ||
      `${a.method} ${a.path}`.localeCompare(`${b.method} ${b.path}`));
  }, [data, coverageFilter, methodFilter]);

  const selected = useMemo(
    () => endpoints.find((e) => `${e.method} ${e.path}` === selectedPath)
      ?? endpoints[0] ?? null,
    [endpoints, selectedPath],
  );

  const unmatchedTotal = data
    ? data.unmatched.findings.length + data.unmatched.safe_dismissed.length
      + data.unmatched.verdicts.length
    : 0;
  const sourcesMissing = data
    ? !data.sources?.entry_points || !data.sources?.report_data
    : false;

  if (error instanceof ApiError && error.status === 404) {
    return (
      <Empty title={t("workspaceDetail.evidence.emptyTitle")}
             hint={t("workspaceDetail.evidence.emptyHint")} />
    );
  }
  if (isLoading || !data) return <Skeleton className="h-96 w-full" />;

  return (
    <div className="flex h-full min-h-0 gap-4">
      {/* 左列：接口清单 */}
      <aside className="w-72 shrink-0 overflow-y-auto" data-testid="evidence-list">
        <div className="mb-2 flex gap-2">
          <select aria-label="coverage" value={coverageFilter}
                  onChange={(e) => setCoverageFilter(e.target.value)}
                  className="rounded border bg-background px-2 py-1 text-xs">
            <option value="all">{t("workspaceDetail.evidence.filterAll")}</option>
            <option value="findings">{t(COVERAGE_KEY.findings)}</option>
            <option value="defended">{t(COVERAGE_KEY.defended)}</option>
            <option value="clean">{t(COVERAGE_KEY.clean)}</option>
          </select>
          <select aria-label="method" value={methodFilter}
                  onChange={(e) => setMethodFilter(e.target.value)}
                  className="rounded border bg-background px-2 py-1 text-xs">
            <option value="all">{t("workspaceDetail.evidence.filterAll")}</option>
            {methods.map((m) => <option key={m} value={m}>{m}</option>)}
          </select>
        </div>
        {unmatchedTotal > 0 && (
          <div className="mb-2">
            <button
              data-testid="unmatched-banner"
              aria-expanded={showUnmatched}
              onClick={() => setShowUnmatched(!showUnmatched)}
              className={`flex w-full items-center gap-1 rounded border px-2 py-1 text-left text-xs ${showUnmatched ? "border-amber-500 bg-amber-500/20 text-amber-700 dark:text-amber-300" : "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-400"}`}
            >
              <span className="shrink-0">{showUnmatched ? "▾" : "▸"}</span>
              {t("workspaceDetail.evidence.unmatchedBanner", { n: unmatchedTotal })}
            </button>
          </div>
        )}
        <ul>
          {endpoints.map((e) => {
            const key = `${e.method} ${e.path}`;
            const active = !showUnmatched && selected
              && `${selected.method} ${selected.path}` === key;
            return (
              <li key={key}>
                <button
                  onClick={() => { setSelectedPath(key); setShowUnmatched(false); }}
                  className={`flex w-full items-center gap-2 rounded px-2 py-1.5 text-left text-sm hover:bg-accent ${active ? "bg-accent" : ""}`}
                >
                  <span className="font-mono text-xs font-semibold">{e.method}</span>
                  <span className="flex-1 truncate font-mono text-xs">{e.path}</span>
                  <CoverageDot coverage={e.coverage} />
                  {(e.whitebox.findings.length > 0 || e.blackbox.verdicts.length > 0) && (
                    <span className="rounded-full bg-muted px-1.5 text-[10px]">
                      {e.whitebox.findings.length}/{e.blackbox.verdicts.length}
                    </span>
                  )}
                </button>
              </li>
            );
          })}
        </ul>
      </aside>

      {/* 右侧：unmatched 全宽面板 或 选中接口两栏证据 */}
      <div className="min-w-0 flex-1 overflow-y-auto">
        {showUnmatched ? (
          <UnmatchedPanel data={data} treeByFindingId={treeByFindingId} />
        ) : selected ? (
          <>
            <header className="mb-4">
              <h2 className="font-mono text-base font-semibold">
                <span className="mr-2 rounded bg-muted px-1.5 py-0.5 text-xs">
                  {selected.method}
                </span>
                {selected.path}
                {selected.raw_route && selected.raw_route !== selected.path && (
                  <span className="ml-2 font-mono text-xs font-normal text-muted-foreground">
                    ({selected.raw_route})
                  </span>
                )}
                {selected.entry_verdict && (
                  <EntryVerdictTag verdict={selected.entry_verdict} />
                )}
              </h2>
              {selected.entry_evidence && (
                <p className="mt-1 text-xs text-muted-foreground">{selected.entry_evidence}</p>
              )}
            </header>
            {sourcesMissing && (
              <div data-testid="evidence-sources-hint"
                   className="mb-3 rounded border border-amber-500/40 bg-amber-500/10 p-2 text-xs text-amber-700 dark:text-amber-400">
                {t("workspaceDetail.evidence.sourcesHint")}
              </div>
            )}
            <div className="grid gap-4 lg:grid-cols-2">
              <WhiteboxColumn endpoint={selected} treeByFindingId={treeByFindingId} />
              <BlackboxColumn endpoint={selected} />
            </div>
          </>
        ) : data.note ? (
          // 底册缺失 / RPC 项目无 route 行时 core 产 note——展示缘由而非误导性的
          // 「选择接口」空态（v2：完整证据在未挂载区，banner 点开即见）。
          <div data-testid="evidence-note"
               className="rounded border border-amber-500/40 bg-amber-500/10 p-3 text-sm">
            {data.note}
          </div>
        ) : (
          <Empty title={t("workspaceDetail.evidence.selectEndpoint")} />
        )}
      </div>
    </div>
  );
}

function CoverageDot({ coverage }: { coverage: EvidenceEndpoint["coverage"] }) {
  const color = coverage === "findings" ? "bg-red-500"
    : coverage === "defended" ? "bg-emerald-500" : "bg-muted-foreground/30";
  return <span className={`h-2 w-2 shrink-0 rounded-full ${color}`} aria-label={coverage} />;
}

/** 底册入口判定徽章（v2：该接口为什么被认定真实入口的判定结论可见）。 */
function EntryVerdictTag({ verdict }: { verdict: string }) {
  const cls = verdict === "confirmed" ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-600"
    : verdict === "rejected" ? "border-red-500/40 bg-red-500/10 text-red-600"
    : "border-amber-500/40 bg-amber-500/10 text-amber-600";
  return (
    <span className={`ml-2 inline-block rounded border px-1.5 py-0.5 align-middle text-[10px] font-normal ${cls}`}
          data-testid="entry-verdict">
      {verdict}
    </span>
  );
}

/** 黑盒验证卡（v2：5 态 discriminated union 按态渲染各自判定依据——
 *  blocked 的拦截原因与已试绕过、false_positive/out_of_scope 的判否理由、
 *  potential 的降级原因；v1 只渲染 exploited 形态，其他态整卡只剩 status）。 */
export function EvidenceVerdictCard({ v, reason }: {
  v: EvidenceVerdict | EvidenceUnmatchedVerdict;
  reason?: string | null;
}) {
  const { t } = useTranslation();
  const L = (k: string) => `workspaceDetail.evidence.${k}`;
  const status = v.status;
  return (
    <article data-testid="evidence-verdict-card" className="rounded border p-2 text-xs">
      <div className="font-medium">
        <span className="font-mono">{v.vulnerability_id}</span> · {status}
        {v.vuln_class && (
          <span className="ml-1 rounded bg-muted px-1 text-[10px] text-muted-foreground">
            {v.vuln_class}
          </span>
        )}
        {v.severity && <SeverityTag severity={v.severity} />}
        {v.confidence && (
          <span className="ml-1 rounded bg-muted px-1 text-[10px] text-muted-foreground">
            {v.confidence}
          </span>
        )}
        {v.run_id && (
          <span className="ml-1 rounded bg-muted px-1 text-[10px] text-muted-foreground">
            {v.run_id}
          </span>
        )}
        {reason && (
          <span className="ml-1 rounded bg-amber-500/15 px-1 text-[10px] text-amber-600">
            {t(L(`reason.${reason}`), reason)}
          </span>
        )}
      </div>
      {status === "blocked_by_security" ? (
        <div className="mt-1 space-y-1" data-testid="verdict-blocked">
          <Row label={t(L("currentBlocker"))} value={v.current_blocker} />
          <Row label={t(L("whatWeTried"))} value={v.what_we_tried} />
          <Row label={t(L("evidenceOfVulnerability"))} value={v.evidence_of_vulnerability} />
          <Row label={t(L("expectedImpact"))} value={v.expected_impact} />
        </div>
      ) : status === "potential" ? (
        <div className="mt-1 space-y-1" data-testid="verdict-potential">
          <Row label={t(L("downgradeReason"))} value={v.downgrade_reason} />
          <Row label={t(L("evidenceOfVulnerability"))} value={v.evidence_of_vulnerability} />
        </div>
      ) : status === "false_positive" || status === "out_of_scope_internal" ? (
        <div className="mt-1 space-y-1" data-testid="verdict-rejected-reason">
          <Row label={t(L("reasonLabel"))} value={v.reason} />
          <Row label={t(L("evidenceLabel"))} value={v.evidence} />
        </div>
      ) : (
        <p className="mt-1">{v.impact}</p>
      )}
      {(v.exploitation_steps?.length ?? 0) > 0 && (
        <ol className="mt-1 list-decimal space-y-1 pl-4">
          {v.exploitation_steps.map((s, j) => <li key={j}>{s}</li>)}
        </ol>
      )}
      {v.proof_of_impact && (
        <CopyableCodePanel value={v.proof_of_impact} testId="verdict-proof" className="code-panel mt-1 overflow-x-auto p-2 font-mono text-[11.5px] leading-relaxed">
          {v.proof_of_impact}
        </CopyableCodePanel>
      )}
      {(v.cwe_id || v.cvss) && (
        <p className="mt-1 text-[10px] text-muted-foreground">
          {[v.cwe_id, v.cvss, v.owasp_category].filter(Boolean).join(" · ")}
        </p>
      )}
    </article>
  );
}

function Row({ label, value }: { label: string; value: string | null | undefined }) {
  if (!value) return null;
  return (
    <p className="leading-relaxed">
      <span className="text-muted-foreground">{label}：</span>
      <span className="break-words">{value}</span>
    </p>
  );
}

/** unmatched 全宽面板（v2 一等公民化）：finding 完整证据卡 + 类筛选；
 *  safe/dismissed/verdicts 补 v2 富字段渲染。 */
function UnmatchedPanel({ data, treeByFindingId }: {
  data: EvidenceMatrix;
  treeByFindingId: Map<string, string>;
}) {
  const { t } = useTranslation();
  const L = (k: string) => `workspaceDetail.evidence.${k}`;
  const [classFilter, setClassFilter] = useState<string>("all");
  const { findings, safe_dismissed, verdicts } = data.unmatched;
  const vulnClasses = useMemo(
    () => [...new Set(findings.map((f) => f.vuln_class ?? ""))].filter(Boolean).sort(),
    [findings],
  );
  const filteredFindings = useMemo(
    () => classFilter === "all"
      ? findings
      : findings.filter((f) => (f.vuln_class ?? "") === classFilter),
    [findings, classFilter],
  );
  return (
    <div data-testid="unmatched-detail" className="space-y-4 text-xs">
      {findings.length > 0 && (
        <section>
          <div className="mb-1.5 flex items-center gap-2">
            <span className="font-medium text-muted-foreground">
              {t(L("unmatchedFindingsLabel"))}（{findings.length}）
            </span>
            <select aria-label="vuln class" value={classFilter}
                    onChange={(e) => setClassFilter(e.target.value)}
                    data-testid="unmatched-class-filter"
                    className="rounded border bg-background px-1.5 py-0.5 text-xs">
              <option value="all">{t(L("filterAll"))}</option>
              {vulnClasses.map((c) => <option key={c} value={c}>{c}</option>)}
            </select>
          </div>
          <div className="space-y-3">
            {filteredFindings.map((f, i) => (
              <EvidenceFindingCard
                key={f.id ?? i}
                f={f}
                reason={f.reason}
                dataflowTreeId={f.id ? treeByFindingId.get(f.id) ?? null : null}
              />
            ))}
          </div>
        </section>
      )}
      {safe_dismissed.length > 0 && (
        <section>
          <div className="mb-1.5 font-medium text-muted-foreground">
            {t(L("unmatchedSafeLabel"))}（{safe_dismissed.length}）
          </div>
          <div className="space-y-2">
            {safe_dismissed.map((s, i) => {
              const str = (k: string) => (s[k] != null ? String(s[k]) : null);
              const kind = str("kind");
              return (
                <article key={i}
                         className={`rounded border p-2 ${kind === "dismissed" ? "border-dashed opacity-90" : "border-emerald-500/30"}`}>
                  <div className="font-medium">
                    {str("subject") ?? str("title")}
                    {kind && (
                      <span className="ml-1 rounded bg-muted px-1 text-[10px]">{kind}</span>
                    )}
                    {str("vuln_class") && (
                      <span className="ml-1 rounded bg-muted px-1 text-[10px] text-muted-foreground">
                        {str("vuln_class")}
                      </span>
                    )}
                    {str("confidence") && (
                      <span className="ml-1 rounded bg-muted px-1 text-[10px] text-muted-foreground">
                        {str("confidence")}
                      </span>
                    )}
                  </div>
                  {(str("defense_mechanism") || str("dismiss_reason")) && (
                    <p className="mt-1 break-words">
                      {str("defense_mechanism") ?? str("dismiss_reason")}
                    </p>
                  )}
                  {(str("location") || str("evidence")) && (
                    <p className="mt-1 font-mono opacity-70">{str("location") ?? str("evidence")}</p>
                  )}
                  {str("source_track") && (
                    <p className="mt-0.5 text-[10px] text-muted-foreground">
                      {t(L("fldSourceTrack"))}：{str("source_track")}
                    </p>
                  )}
                </article>
              );
            })}
          </div>
        </section>
      )}
      {verdicts.length > 0 && (
        <section>
          <div className="mb-1.5 font-medium text-muted-foreground">
            {t(L("unmatchedVerdictsLabel"))}（{verdicts.length}）
          </div>
          <div className="space-y-2">
            {verdicts.map((v, i) =>
              v.kind === "rejected" ? (
                <article key={i} className="rounded border border-dashed p-2 opacity-90">
                  <div className="font-medium">
                    <span className="font-mono">{String(v.vulnerability_id ?? "")}</span>
                    {v.vuln_class && (
                      <span className="ml-1 rounded bg-muted px-1 text-[10px] text-muted-foreground">
                        {v.vuln_class}
                      </span>
                    )}
                    {v.run_id && (
                      <span className="ml-1 rounded bg-muted px-1 text-[10px] text-muted-foreground">
                        {v.run_id}
                      </span>
                    )}
                  </div>
                  {v.reason && <p className="mt-1 break-words">{v.reason}</p>}
                </article>
              ) : (
                <EvidenceVerdictCard key={i} v={v} reason={v.reason} />
              ),
            )}
          </div>
        </section>
      )}
    </div>
  );
}

function WhiteboxColumn({ endpoint, treeByFindingId }: {
  endpoint: EvidenceEndpoint;
  treeByFindingId: Map<string, string>;
}) {
  const { t } = useTranslation();
  const { findings, safe, dismissed } = endpoint.whitebox;
  return (
    <section className="space-y-3 rounded-lg border border-blue-500/30 p-3"
             data-testid="evidence-whitebox">
      <h3 className="text-sm font-semibold text-blue-600 dark:text-blue-400">
        {t("workspaceDetail.evidence.whiteboxTrack")}
      </h3>
      {findings.length === 0 && safe.length === 0 && dismissed.length === 0 ? (
        <p className="text-xs text-muted-foreground">
          {t("workspaceDetail.evidence.whiteboxEmpty")}</p>
      ) : (
        <>
          {findings.map((f) => (
            <EvidenceFindingCard
              key={f.id}
              f={f}
              dataflowTreeId={f.id ? treeByFindingId.get(f.id) ?? null : null}
            />
          ))}
          {safe.map((s, i) => (
            <article key={i} className="rounded border border-emerald-500/30 p-2 text-xs">
              <div className="font-medium">
                {s.subject}
                {s.contains_live_probe && (
                  <span className="ml-1 rounded bg-amber-500/15 px-1 text-[10px] text-amber-600">
                    {t("workspaceDetail.evidence.liveProbe")}
                  </span>
                )}
              </div>
              <p className="mt-1">{s.defense_mechanism}</p>
              {s.location && <p className="mt-1 font-mono opacity-70">{s.location}</p>}
            </article>
          ))}
          {dismissed.map((d) => (
            <article key={d.ID} className="rounded border border-dashed p-2 text-xs opacity-80">
              <div className="font-medium">
                {d.title}
                {d.vuln_class && (
                  <span className="ml-1 rounded bg-muted px-1 text-[10px] text-muted-foreground">
                    {d.vuln_class}
                  </span>
                )}
                {d.confidence && (
                  <span className="ml-1 rounded bg-muted px-1 text-[10px] text-muted-foreground">
                    {d.confidence}
                  </span>
                )}
              </div>
              <p className="mt-1">
                {t("workspaceDetail.evidence.dismissReason")}：{d.dismiss_reason}
              </p>
              {(d.evidence || d.sink_call) && (
                <p className="mt-1 font-mono opacity-70">{d.evidence ?? d.sink_call}</p>
              )}
              {d.source_track && (
                <p className="mt-0.5 text-[10px] text-muted-foreground">
                  {t("workspaceDetail.evidence.fldSourceTrack")}：{d.source_track}
                </p>
              )}
            </article>
          ))}
        </>
      )}
    </section>
  );
}

function BlackboxColumn({ endpoint }: { endpoint: EvidenceEndpoint }) {
  const { t } = useTranslation();
  const { verdicts, rejected } = endpoint.blackbox;
  return (
    <section className="space-y-3 rounded-lg border border-orange-500/30 p-3"
             data-testid="evidence-blackbox">
      <h3 className="text-sm font-semibold text-orange-600 dark:text-orange-400">
        {t("workspaceDetail.evidence.blackboxTrack")}
      </h3>
      {verdicts.length === 0 && rejected.length === 0 ? (
        <p className="text-xs text-muted-foreground">
          {t("workspaceDetail.evidence.blackboxEmpty")}</p>
      ) : (
        <>
          {verdicts.map((v, i) => <EvidenceVerdictCard key={i} v={v} />)}
          {rejected.length > 0 && (
            <div data-testid="blackbox-rejected" className="space-y-1">
              <div className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                {t("workspaceDetail.evidence.rejectedLabel")}（{rejected.length}）
              </div>
              {rejected.map((r, i) => (
                <div key={i} className="rounded border border-dashed p-1.5 opacity-80">
                  <span className="font-mono">{String(r.id ?? r.vulnerability_id ?? "")}</span>
                  {r.reason != null && <span className="ml-1 break-words">{String(r.reason)}</span>}
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </section>
  );
}
