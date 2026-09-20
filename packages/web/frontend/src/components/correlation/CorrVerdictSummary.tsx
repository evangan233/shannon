import { useState } from "react";
import { useTranslation } from "react-i18next";
import type { AdjudicationCard } from "@/api/types";
import type { CorrVerdictGroup, CorrVerdictCounts } from "@/lib/correlation-verdict";
import { VERDICT_BADGE_CLS } from "@/components/correlation/CorrVulnCard";
import { AdjudicationCardView } from "@/components/correlation/AdjudicationCardView";
import { Badge } from "@/components/ui/badge";

/**
 * 跨仓结论摘要区（2026-09-20 结论优先批次，页面第一屏）：回答「哪些成立、哪些
 * 消掉、为什么」——五向结论卡（成立/消掉/存疑/翻案/未重审）+ 每向可展开清单
 * （ID + 标题 + reasoning 一句话 + confidence），清单条目点击定位到漏洞卡；
 * 翻案组展开直接渲染裁决卡完整论证（翻案条目无漏洞卡，不参与定位）。
 * 裁决 running → 进度占位；failed → 透明提示。纯渲染，join 纯函数在
 * lib/correlation-verdict.ts，数据由 CorrelationTab 算好传入。
 */

/** 结论清单条目（父级由漏洞条目 + 裁决卡归一）。 */
export interface VerdictEntry {
  id: string;
  title?: string;
  service?: string;
  severity?: string;
  reason?: string;
  confidence?: string;
}

/** 摘要卡展示顺序（成立优先，未重审垫底）。 */
const SUMMARY_ORDER: (CorrVerdictGroup | "upgraded")[] = [
  "confirmed", "refuted", "uncertain", "upgraded", "unadjudicated",
];

/** 清单最多直渲染条数，超出收进「还有 N 条」徽标（防百条级列表淹第一屏）。 */
const ENTRY_CAP = 12;

/** 翻案组单张裁决卡（本地折叠 state，默认收起——完整论证点卡头展开）。 */
function UpgradedCardItem({ card }: { card: AdjudicationCard }) {
  const [collapsed, setCollapsed] = useState(true);
  return (
    <AdjudicationCardView
      card={card}
      collapsed={collapsed}
      onToggleCollapse={() => setCollapsed((c) => !c)}
    />
  );
}

export function CorrVerdictSummary({ counts, entries, upgraded, running, failed, coverage, onLocateVuln }: {
  counts: CorrVerdictCounts;
  entries: Record<CorrVerdictGroup, VerdictEntry[]>;
  upgraded: AdjudicationCard[];
  /** 裁决阶段进行中（adjudication_status === "running"）。 */
  running: boolean;
  /** 裁决阶段失败（failed）。 */
  failed: boolean;
  /** 覆盖进度（origin=queue 卡数 / queue 总数）。 */
  coverage: { total: number; covered: number };
  /** 清单条目点击定位（翻案组不回调——无漏洞卡可定位）。 */
  onLocateVuln: (id: string) => void;
}) {
  const { t } = useTranslation();
  const countOf = (key: CorrVerdictGroup | "upgraded"): number => counts[key];
  return (
    <section data-testid="corr-verdict-summary" className="space-y-2" aria-label={t("scan.correlation.verdict.title")}>
      <h3 className="font-medium">{t("scan.correlation.verdict.title")}</h3>
      {running && (
        <div data-testid="corr-verdict-running" className="rounded-md border border-amber/40 bg-amber/10 p-3 text-sm text-amber">
          {t("scan.correlation.verdict.running", { covered: coverage.covered, total: coverage.total })}
        </div>
      )}
      {failed && (
        <div data-testid="corr-verdict-failed" className="rounded-md border border-red/40 bg-red/10 p-3 text-sm text-red">
          {t("scan.correlation.verdict.failed")}
        </div>
      )}
      <div className="grid grid-cols-2 gap-2 md:grid-cols-5">
        {SUMMARY_ORDER.map((key) => {
          const count = countOf(key);
          const list = key === "upgraded" ? [] : entries[key];
          const isUpgraded = key === "upgraded";
          // 无结论且未在跑 → 卡淡显（保持五向占位，一眼看清全景）
          const dim = count === 0;
          return (
            <details key={key} data-testid={`corr-verdict-card-${key}`} className="group rounded-md border border-border bg-card shadow-[var(--shadow-card)]">
              <summary
                className={`flex cursor-pointer list-none items-center justify-between gap-2 p-3 focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary ${dim ? "opacity-50" : ""}`}
              >
                <span className={`inline-flex items-center rounded-full border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wide ${VERDICT_BADGE_CLS[key === "upgraded" ? "confirmed" : key]}`}>
                  {t(`scan.correlation.verdict.${key}`)}
                </span>
                <span className="text-[22px] font-bold leading-none">{count}</span>
              </summary>
              <div className="border-t border-border p-2">
                {isUpgraded ? (
                  upgraded.length === 0 ? (
                    <p className="p-1 text-xs text-muted-foreground">{t("scan.correlation.verdict.empty")}</p>
                  ) : (
                    <div data-testid="corr-verdict-upgraded-list" className="max-h-72 space-y-2 overflow-y-auto">
                      {upgraded.map((card, i) => (
                        <UpgradedCardItem key={i} card={card} />
                      ))}
                    </div>
                  )
                ) : list.length === 0 ? (
                  <p className="p-1 text-xs text-muted-foreground">{t("scan.correlation.verdict.empty")}</p>
                ) : (
                  <ul data-testid={`corr-verdict-list-${key}`} className="max-h-72 space-y-1.5 overflow-y-auto">
                    {list.slice(0, ENTRY_CAP).map((e) => (
                      <li key={e.id}>
                        <button
                          type="button"
                          data-testid="corr-verdict-entry"
                          onClick={() => onLocateVuln(e.id)}
                          className="w-full rounded-sm p-1 text-left text-xs transition-colors hover:bg-accent focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary"
                        >
                          <span className="font-mono font-medium text-foreground">{e.id}</span>
                          {e.severity && (
                            <span className="ml-1 font-mono text-[10px] uppercase text-muted-foreground">{e.severity}</span>
                          )}
                          {e.title && (
                            <span className="mt-0.5 line-clamp-1 block text-foreground/80">{e.title}</span>
                          )}
                          {e.reason && (
                            <span className="mt-0.5 line-clamp-2 block text-muted-foreground">{e.reason}</span>
                          )}
                        </button>
                      </li>
                    ))}
                    {list.length > ENTRY_CAP && (
                      <li className="p-1">
                        <Badge variant="outline" className="font-sans text-[10px] text-muted-foreground">
                          {t("scan.correlation.verdict.more", { count: list.length - ENTRY_CAP })}
                        </Badge>
                      </li>
                    )}
                  </ul>
                )}
              </div>
            </details>
          );
        })}
      </div>
    </section>
  );
}
