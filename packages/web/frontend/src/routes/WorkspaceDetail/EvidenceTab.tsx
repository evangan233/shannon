import { useMemo, useState } from "react";
import useSWR from "swr";
import { useParams } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { ApiError, fetchEvidenceMatrix } from "@/api/client";
import type { EvidenceEndpoint, EvidenceMatrix } from "@/api/types";
import { Empty } from "@/components/Empty";
import { Skeleton } from "@/components/ui/skeleton";

/**
 * 接口证据 tab（spec 2026-09-10 §8）。
 *
 * 左列接口清单（coverage/method 筛选）+ 右侧选中接口的白盒（蓝）/黑盒（橙）
 * 两栏证据。404 = 无证据产物（旧版/纯黑盒扫描）→ Empty 空态。
 * SWR 拉 GET /workspaces/{ws}/scans/{id}/evidence-matrix（web lazy 重建，
 * 黑盒 run 完成后自动刷新——mtime 失效语义见后端）。
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

  const [coverageFilter, setCoverageFilter] = useState<string>("all");
  const [methodFilter, setMethodFilter] = useState<string>("all");
  const [selectedPath, setSelectedPath] = useState<string | null>(null);
  // unmatched 明细（spec §8「可展开」）：banner 点击 toggle，默认收起只显计数。
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
              className="flex w-full items-center gap-1 rounded border border-amber-500/40 bg-amber-500/10 px-2 py-1 text-left text-xs text-amber-700 dark:text-amber-400"
            >
              <span className="shrink-0">{showUnmatched ? "▾" : "▸"}</span>
              {t("workspaceDetail.evidence.unmatchedBanner", { n: unmatchedTotal })}
            </button>
            {showUnmatched && <UnmatchedDetail data={data} />}
          </div>
        )}
        <ul>
          {endpoints.map((e) => {
            const key = `${e.method} ${e.path}`;
            const active = selected && `${selected.method} ${selected.path}` === key;
            return (
              <li key={key}>
                <button
                  onClick={() => setSelectedPath(key)}
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

      {/* 右侧：选中接口两栏证据 */}
      <div className="min-w-0 flex-1 overflow-y-auto">
        {selected ? (
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
              </h2>
            </header>
            <div className="grid gap-4 lg:grid-cols-2">
              <WhiteboxColumn endpoint={selected} />
              <BlackboxColumn endpoint={selected} />
            </div>
          </>
        ) : data.note ? (
          // 底册缺失（如纯黑盒/旧版扫描）时 core 会产 note——展示缘由而非误导性的
          // 「选择接口」空态（spec §4「缺哪个标哪个，前端提示证据不全」）。
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

/** unmatched 三桶明细（spec §8「可展开」的展开体）。条目为松类型（Record<string,
 *  unknown>，core 侧保守保留原文），渲染一律 String() 收敛，缺字段自然空白。 */
function UnmatchedDetail({ data }: { data: EvidenceMatrix }) {
  const { t } = useTranslation();
  const L = (k: string) => `workspaceDetail.evidence.${k}`;
  const { findings, safe_dismissed, verdicts } = data.unmatched;
  return (
    <div data-testid="unmatched-detail"
         className="mt-1 space-y-2 rounded border border-amber-500/30 p-2 text-xs">
      {findings.length > 0 && (
        <section>
          <div className="font-medium text-muted-foreground">{t(L("unmatchedFindingsLabel"))}</div>
          <ul className="mt-0.5 space-y-0.5">
            {findings.map((f, i) => (
              <li key={i}>
                <span className="font-mono">{String(f.id ?? "")}</span> · {String(f.title ?? "")}
                {f.reason != null && <span className="ml-1 opacity-60">({String(f.reason)})</span>}
              </li>
            ))}
          </ul>
        </section>
      )}
      {safe_dismissed.length > 0 && (
        <section>
          <div className="font-medium text-muted-foreground">{t(L("unmatchedSafeLabel"))}</div>
          <ul className="mt-0.5 space-y-0.5">
            {safe_dismissed.map((s, i) => (
              <li key={i}>
                {String(s.subject ?? s.title ?? "")}
                {s.kind != null && (
                  <span className="ml-1 rounded bg-muted px-1 text-[10px]">{String(s.kind)}</span>
                )}
              </li>
            ))}
          </ul>
        </section>
      )}
      {verdicts.length > 0 && (
        <section>
          <div className="font-medium text-muted-foreground">{t(L("unmatchedVerdictsLabel"))}</div>
          <ul className="mt-0.5 space-y-0.5">
            {verdicts.map((v, i) => (
              <li key={i}>
                <span className="font-mono">{String(v.vulnerability_id ?? "")}</span>
                {v.run_id != null && <span className="ml-1 opacity-70">{String(v.run_id)}</span>}
                {v.reason != null && <span className="ml-1 opacity-60">({String(v.reason)})</span>}
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}

function WhiteboxColumn({ endpoint }: { endpoint: EvidenceEndpoint }) {
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
            <article key={f.id} className="rounded border p-2 text-xs">
              <div className="font-medium">
                {f.id} · {f.title}
                {f.severity && <SeverityTag severity={f.severity} />}
                {f.confidence && (
                  <span className="ml-1 rounded bg-muted px-1 text-[10px] text-muted-foreground">
                    {f.confidence}
                  </span>
                )}
              </div>
              {f.params.length > 0 && (
                <p className="mt-1">
                  <span className="text-muted-foreground">
                    {t("workspaceDetail.evidence.paramsLabel")}：
                  </span>
                  {f.params.join("、")}
                </p>
              )}
              {f.auth_required && (
                <p className="mt-1">
                  <span className="text-muted-foreground">
                    {t("workspaceDetail.evidence.authLabel")}：
                  </span>
                  {f.auth_required}
                </p>
              )}
              {f.evidence_chain && (
                <p className="mt-1 whitespace-pre-wrap break-words">
                  {t("workspaceDetail.evidence.evidenceChain")}：{f.evidence_chain}
                </p>
              )}
              {f.witness_payload && (
                <pre className="mt-1 overflow-x-auto rounded bg-muted p-1.5 font-mono">
                  {f.witness_payload}
                </pre>
              )}
            </article>
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
              <div className="font-medium">{d.title}</div>
              <p className="mt-1">
                {t("workspaceDetail.evidence.dismissReason")}：{d.dismiss_reason}
              </p>
            </article>
          ))}
        </>
      )}
    </section>
  );
}

function BlackboxColumn({ endpoint }: { endpoint: EvidenceEndpoint }) {
  const { t } = useTranslation();
  const { verdicts } = endpoint.blackbox;
  return (
    <section className="space-y-3 rounded-lg border border-orange-500/30 p-3"
             data-testid="evidence-blackbox">
      <h3 className="text-sm font-semibold text-orange-600 dark:text-orange-400">
        {t("workspaceDetail.evidence.blackboxTrack")}
      </h3>
      {verdicts.length === 0 ? (
        <p className="text-xs text-muted-foreground">
          {t("workspaceDetail.evidence.blackboxEmpty")}</p>
      ) : verdicts.map((v, i) => (
        <article key={i} className="rounded border p-2 text-xs">
          <div className="font-medium">
            {v.vulnerability_id} · {v.status}
            {v.severity && <SeverityTag severity={v.severity} />}
          </div>
          {v.impact && <p className="mt-1">{v.impact}</p>}
          {v.exploitation_steps.length > 0 && (
            <ol className="mt-1 list-decimal space-y-1 pl-4">
              {v.exploitation_steps.map((s, j) => <li key={j}>{s}</li>)}
            </ol>
          )}
          {v.proof_of_impact && (
            <pre className="mt-1 overflow-x-auto rounded bg-muted p-1.5 font-mono">
              {v.proof_of_impact}
            </pre>
          )}
        </article>
      ))}
    </section>
  );
}

function SeverityTag({ severity }: { severity: string }) {
  return (
    <span className="ml-1 rounded bg-red-500/10 px-1 text-[10px] text-red-600">
      {severity}
    </span>
  );
}
