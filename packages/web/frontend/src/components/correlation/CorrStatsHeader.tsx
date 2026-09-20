import { useTranslation } from "react-i18next";
import type { CorrelationDetail } from "@/api/types";
import { SEV_CAP, SEV_PILL, SEV_DOT } from "@/lib/severity-visual";

/**
 * 跨仓关联结果总览头（2026-09-20 可读性批次）：对齐 report StatsRow 视觉——
 * 数字卡（服务/攻击链/多跳候选/合并漏洞，裁决卡仅 log 就绪时出现）+ severity
 * 药丸行（计数 >0 可点击定位到该等级第一条漏洞卡，联动父级折叠展开）。
 * 聚合全部前端现算（detail 已整包在内存，量级 ≤ 数百条，无需后端预聚合）。
 */

const SEV_ORDER = ["critical", "high", "medium", "low"] as const;
export type SevKey = (typeof SEV_ORDER)[number];

/** severity 计数（宽松 dict 防御）：SEV_CAP 归一（大小写容错），未知等级忽略。 */
export function countBySeverity(
  vulns: Record<string, { severity?: unknown }[]>,
): Record<SevKey, number> {
  const counts: Record<SevKey, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const list of Object.values(vulns)) {
    for (const v of list) {
      const cap = SEV_CAP[typeof v.severity === "string" ? v.severity.toLowerCase() : ""];
      if (cap) counts[cap.toLowerCase() as SevKey] += 1;
    }
  }
  return counts;
}

/** stats 数字卡条目（导出便于单测）：adjudication log 未落盘（null）时该卡缺席。 */
export function corrStatCards(detail: CorrelationDetail): { key: string; labelKey: string; count: number }[] {
  const cards = [
    { key: "services", labelKey: "scan.correlation.statsServices", count: detail.topology?.services.length ?? 0 },
    { key: "flows", labelKey: "scan.correlation.statsFlows", count: detail.flows.length },
    { key: "multihop", labelKey: "scan.correlation.statsMultihop", count: detail.multi_hop_chains.length },
    { key: "vulns", labelKey: "scan.correlation.statsVulns",
      count: Object.values(detail.merged_vulns).reduce((a, l) => a + l.length, 0) },
  ];
  if (detail.adjudication) {
    cards.push({
      key: "adjudication",
      labelKey: "scan.correlation.statsAdjudication",
      count: detail.adjudication.cards?.length ?? 0,
    });
  }
  return cards;
}

export function CorrStatsHeader({ detail, onLocateSev }: {
  detail: CorrelationDetail;
  /** severity 药丸点击定位（跨仓 tab 传 locateVuln 衍生回调）；缺省纯展示。 */
  onLocateSev?: (sev: SevKey) => void;
}) {
  const { t } = useTranslation();
  const cards = corrStatCards(detail);
  const sevCounts = countBySeverity(detail.merged_vulns);
  return (
    <section data-testid="corr-stats" className="space-y-3" aria-label={t("scan.correlation.statsTitle")}>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        {cards.map((c) => (
          <article
            key={c.key}
            data-testid={`corr-stat-${c.key}`}
            className="relative overflow-hidden rounded-md border border-border bg-card p-3.5 shadow-[var(--shadow-card)]"
          >
            <div className="font-mono text-[11px] uppercase tracking-wide text-muted-foreground">
              {t(c.labelKey)}
            </div>
            <div className="mt-1.5 text-[34px] font-bold leading-none tracking-tight">{c.count}</div>
          </article>
        ))}
      </div>
      <div
        data-testid="corr-stat-severity"
        className="flex flex-wrap items-center gap-x-4 gap-y-2 rounded-md border border-border bg-card p-3 shadow-[var(--shadow-card)]"
      >
        <span className="font-mono text-[11px] uppercase tracking-wide text-muted-foreground">
          {t("report.bySeverity")}
        </span>
        {SEV_ORDER.map((sev) => {
          const cap = SEV_CAP[sev];
          const count = sevCounts[sev];
          const label = (
            <>
              <span className={`sev-dot ${SEV_DOT[cap]}`} aria-hidden="true" />
              {cap} <b className="font-medium">{count}</b>
            </>
          );
          const cls = `inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 font-mono text-[10.5px] ${SEV_PILL[cap]}`;
          return count > 0 && onLocateSev ? (
            <button
              key={sev}
              type="button"
              data-testid={`corr-stat-sev-${sev}`}
              title={t("scan.correlation.locateSevHint", { sev: cap })}
              onClick={() => onLocateSev(sev)}
              className={`${cls} transition-opacity hover:opacity-80 focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary`}
            >
              {label}
            </button>
          ) : (
            <span key={sev} data-testid={`corr-stat-sev-${sev}`} className={cls}>
              {label}
            </span>
          );
        })}
      </div>
    </section>
  );
}
