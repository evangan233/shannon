import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import type { CorrelationDetail } from "@/api/types";
import { SEV_CAP, SEV_PILL, SEV_DOT, SEV_ORDER } from "@/lib/severity-visual";
import type { CorrVerdictCounts } from "@/lib/correlation-verdict";

/**
 * 跨仓关联结果总览头（2026-09-21 设计批次：结论优先）——页面的主角是裁决结论
 * 而非扫描过程量：第一行 = 结论四件套大数字（成立/翻案/消掉/存疑，点击定位到
 * 对应结论组）+ 右侧 actions（报告下载挂点）；第二行 = 成立口径 severity 药丸
 * （此前数全量含消掉条目、点击会跳进消掉组——修正为只数成立）+ 右端过程量小字
 * （服务/攻击链/多跳候选/合并漏洞，降为一行 mono 脚注）。原五张 34px 过程量
 * 数字卡撤除——「裁决卡数」等内部量不上页面（全量留档在 adjudication-log）。
 * 聚合全部前端现算（detail 已整包在内存，量级 ≤ 数百条，无需后端预聚合）。
 */

/** severity 计数（宽松 dict 防御）：SEV_CAP 归一（大小写容错），未知等级忽略。 */
export function countBySeverity(
  vulns: { severity?: unknown }[],
): Record<string, number> {
  const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const v of vulns) {
    const cap = SEV_CAP[typeof v.severity === "string" ? v.severity.toLowerCase() : ""];
    if (cap) counts[cap.toLowerCase()] += 1;
  }
  return counts;
}

export type CorrStatGroup = "confirmed" | "upgraded" | "refuted" | "uncertain";

/** 结论组 → 数字旁色点（语义对齐 VERDICT_BADGE_CLS：成立绿 / 消掉红 / 留意 amber）。 */
const GROUP_DOT_CLS: Record<CorrStatGroup | "unadjudicated", string> = {
  confirmed: "bg-green",
  upgraded: "bg-amber",
  refuted: "bg-red",
  uncertain: "bg-amber",
  unadjudicated: "bg-muted-foreground",
};

export function CorrStatsHeader({ detail, counts, confirmedSevCounts, onLocateSev, onLocateGroup, actions }: {
  detail: CorrelationDetail;
  /** 结论四件套计数（父级由 verdictSplit/upgraded 汇出，口径与漏洞分组单源）。 */
  counts: CorrVerdictCounts;
  /** 成立口径 severity 计数（只数结论=成立的条目）。 */
  confirmedSevCounts: Record<string, number>;
  /** severity 药丸点击定位（成立组内该等级第一条）。 */
  onLocateSev?: (sev: string) => void;
  /** 结论数字点击定位（对应结论组组头 / 翻案置顶块）。 */
  onLocateGroup?: (group: CorrStatGroup) => void;
  /** 行 1 右端挂点（报告下载按钮）。 */
  actions?: ReactNode;
}) {
  const { t } = useTranslation();
  const mergedTotal = Object.values(detail.merged_vulns).reduce((a, l) => a + l.length, 0);
  const verdictStats: { group: CorrStatGroup | "unadjudicated"; count: number; label: string }[] = [
    { group: "confirmed", count: counts.confirmed, label: t("scan.correlation.verdict.confirmed") },
    { group: "upgraded", count: counts.upgraded, label: t("scan.correlation.verdict.upgraded") },
    { group: "refuted", count: counts.refuted, label: t("scan.correlation.verdict.refuted") },
    { group: "uncertain", count: counts.uncertain, label: t("scan.correlation.verdict.uncertain") },
  ];
  if (counts.unadjudicated > 0) {
    verdictStats.push({
      group: "unadjudicated",
      count: counts.unadjudicated,
      label: t("scan.correlation.verdict.unadjudicated"),
    });
  }
  return (
    <section
      data-testid="corr-stats"
      aria-label={t("scan.correlation.statsTitle")}
      className="rounded-md border border-border bg-card p-4 shadow-[var(--shadow-card)]"
    >
      {/* 行 1：结论四件套（点击定位）+ actions 挂点 */}
      <div className="flex flex-wrap items-end justify-between gap-x-6 gap-y-3">
        <div className="flex flex-wrap items-end gap-x-7 gap-y-3">
          {verdictStats.map(({ group, count, label }) => {
            const clickable = count > 0 && onLocateGroup && group !== "unadjudicated";
            const body = (
              <>
                <span className="flex items-baseline gap-1.5">
                  <span className="text-[28px] font-bold leading-none tracking-tight text-foreground">
                    {count}
                  </span>
                  <span aria-hidden className={`size-2 rounded-full ${GROUP_DOT_CLS[group]}`} />
                </span>
                <span className="text-[11px] text-muted-foreground">{label}</span>
              </>
            );
            return clickable ? (
              <button
                key={group}
                type="button"
                data-testid={`corr-stat-${group}`}
                aria-label={label}
                onClick={() => onLocateGroup?.(group as CorrStatGroup)}
                className="flex flex-col items-start gap-1 rounded-sm transition-opacity hover:opacity-75 focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary"
              >
                {body}
              </button>
            ) : (
              <div key={group} data-testid={`corr-stat-${group}`} className="flex flex-col items-start gap-1">
                {body}
              </div>
            );
          })}
        </div>
        {actions}
      </div>
      {/* 行 2：成立口径 severity 药丸（点击定位）+ 过程量 mono 脚注 */}
      <div className="mt-3.5 flex flex-wrap items-center gap-x-4 gap-y-2 border-t border-border pt-3">
        <span className="font-mono text-[11px] uppercase tracking-wide text-muted-foreground">
          {t("scan.correlation.sevConfirmed")}
        </span>
        {SEV_ORDER.map((sev) => {
          const cap = SEV_CAP[sev];
          const count = confirmedSevCounts[sev] ?? 0;
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
        <span data-testid="corr-stat-process" className="ml-auto font-mono text-[11px] text-muted-foreground">
          {[
            `${detail.topology?.services.length ?? 0} ${t("scan.correlation.statsServices")}`,
            `${detail.flows.length} ${t("scan.correlation.statsFlows")}`,
            `${detail.multi_hop_chains.length} ${t("scan.correlation.statsMultihop")}`,
            `${t("scan.correlation.statsVulns")} ${mergedTotal}`,
          ].join(" · ")}
        </span>
      </div>
    </section>
  );
}
