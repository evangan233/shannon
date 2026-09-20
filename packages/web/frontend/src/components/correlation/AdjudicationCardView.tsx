import { useTranslation } from "react-i18next";
import { ChevronDown } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import type { AdjudicationCard } from "@/api/types";

/**
 * 单张裁决卡（spec 2026-08-27 §9，2026-09-20 从 CorrelationTab 提取为独立组件——
 * 结论摘要区翻案组复用，避免路由组件 ↔ 摘要组件循环 import）：正反结论同构——
 * 卡头（direction/conclusion 徽标 + ID + service·origin + confidence）折叠，
 * 展开体（跨仓上下文 + 分析过程（有序列表）+ 验证证据（file:line）+ 论证）。
 * 受控折叠：父级集中 state（默认非 error 收起、error 卡必见）。
 */

/** 裁决方向 → i18n key（spec 2026-08-27 §7.3 五向 + error 占位）。 */
export const ADJ_DIRECTION_KEY: Record<string, string> = {
  upgrade: "scan.correlation.adjUpgrade",
  downgrade: "scan.correlation.adjDowngrade",
  confirm: "scan.correlation.adjConfirm",
  maintain: "scan.correlation.adjMaintain",
  error: "scan.correlation.adjError",
};
/** direction 聚合徽标行展示顺序（正反结论同构，error 垫底）。 */
export const DIRECTION_ORDER = ["upgrade", "downgrade", "confirm", "maintain", "error"] as const;

export function AdjudicationCardView({ card, collapsed, onToggleCollapse }: {
  card: AdjudicationCard;
  /** 受控折叠态（父级传入）；undefined = 展开（兜底直接渲染场景）。 */
  collapsed?: boolean;
  /** 折叠切换回调（卡头 button；缺省卡头退化为非交互行）。 */
  onToggleCollapse?: () => void;
}) {
  const { t } = useTranslation();
  const dirKey = ADJ_DIRECTION_KEY[card.direction] ?? card.direction;
  const isError = card.direction === "error";
  const isUpgrade = card.direction === "upgrade";
  const open = collapsed !== true;
  // 语义色走 --c-red/--c-amber token（逐主题校对比），不用 tailwind 原生色阶
  const frame = isError
    ? "border-red/40 bg-red/5"
    : isUpgrade
      ? "border-amber/40 bg-amber/5"
      : "border-border";
  return (
    <div data-testid="corr-adj-card" className={`rounded-md border p-3 text-sm ${frame}`}>
      {onToggleCollapse ? (
        <button
          type="button"
          data-testid="corr-adj-card-head"
          aria-expanded={open}
          onClick={onToggleCollapse}
          className="flex w-full flex-wrap items-center gap-2 rounded-sm text-left focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary focus-visible:outline-offset-2"
        >
          <HeadBadges card={card} dirKey={dirKey} isError={isError} t={t} />
          <ChevronDown
            className={`ml-auto size-4 shrink-0 text-muted-foreground transition-transform duration-150 ${open ? "" : "-rotate-90"}`}
            aria-hidden="true"
          />
        </button>
      ) : (
        <div className="flex flex-wrap items-center gap-2">
          <HeadBadges card={card} dirKey={dirKey} isError={isError} t={t} />
        </div>
      )}
      {open && (
        <div className="mt-2 space-y-1 text-xs">
          {card.cross_service_context && (
            <div>
              <span className="text-muted-foreground">
                {t("scan.correlation.adjContext")}:
              </span>{" "}
              {card.cross_service_context}
            </div>
          )}
          {card.analysis_process.length > 0 && (
            <div>
              <div className="text-muted-foreground">
                {t("scan.correlation.adjProcess")}
              </div>
              <ol className="list-decimal pl-5">
                {card.analysis_process.map((step, i) => (
                  <li key={i}>{step}</li>
                ))}
              </ol>
            </div>
          )}
          {card.verification_evidence.length > 0 && (
            <div>
              <div className="text-muted-foreground">
                {t("scan.correlation.adjEvidence")}
              </div>
              <ul className="list-disc pl-5">
                {card.verification_evidence.map((ev, i) => (
                  <li key={i}>
                    <span className="font-mono">{ev.location}</span>
                    {ev.note ? ` — ${ev.note}` : ""}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {card.reasoning && (
            <p>{card.reasoning}</p>
          )}
        </div>
      )}
    </div>
  );
}

/** 裁决卡卡头徽标行（direction/conclusion/ID/service·origin/confidence）——折叠
 *  button 与非受控 div 两种卡头共用。 */
function HeadBadges({ card, dirKey, isError, t }: {
  card: AdjudicationCard;
  dirKey: string;
  isError: boolean;
  t: (k: string, opts?: { defaultValue?: string }) => string;
}) {
  return (
    <>
      <Badge variant="outline" className={isError ? "text-red" : undefined}>
        {t(dirKey, { defaultValue: card.direction })}
      </Badge>
      <span className="font-mono font-medium">{card.finding_ref.vuln_id || "?"}</span>
      <span className="text-xs text-muted-foreground">
        {card.finding_ref.service} · {card.finding_ref.origin}
      </span>
      <Badge variant="secondary">{card.conclusion}</Badge>
      <span className="text-xs text-muted-foreground">
        confidence: {card.confidence}
      </span>
    </>
  );
}
