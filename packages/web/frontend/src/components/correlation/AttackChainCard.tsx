import { useTranslation } from "react-i18next";
import type { CorrFlow } from "@/api/types";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

/**
 * 跨服务攻击链卡（D5，spec 2026-08-24 §5.4）：三段式横排
 * entry@call_site → method → vuln_refs 列表 + confidence 徽标 + evidence 折叠。
 * 概率性 Agent 推断产物（供人工复核）——confidence 仅作提示不作结论。
 * vuln_refs 带 vuln_id 且父级给 onLocateRef 时渲染为定位按钮（滚到分组漏洞卡），
 * 旧数据（无 id）/ 未传回调保持纯文本。
 */

/** confidence → 徽标语义色（high=green / medium=amber / 其余低调灰）。 */
function confidenceCls(value: string): string {
  if (value === "high") return "border-green/40 text-green";
  if (value === "medium") return "border-amber/40 text-amber";
  return "text-muted-foreground";
}

export function AttackChainCard({ flow, onLocateRef }: {
  flow: CorrFlow;
  /** 带漏洞卡的定位回调（跨仓 tab 传 locateVuln）；缺省 = 引用纯文本。 */
  onLocateRef?: (vulnId: string) => void;
}) {
  const { t } = useTranslation();
  return (
    <Card data-testid="attack-chain" className="space-y-2 p-4">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        {/* 段1：入口 + 调用点 */}
        <span className="flex flex-col">
          <span className="font-mono text-xs">{flow.entry}</span>
          <span className="font-mono text-[11px] text-muted-foreground">
            @{flow.call_site.file}:{flow.call_site.line}
          </span>
        </span>
        <span aria-hidden className="text-muted-foreground">→</span>
        {/* 段2：RPC method */}
        <span className="font-mono text-xs">{flow.method}</span>
        <span aria-hidden className="text-muted-foreground">→</span>
        {/* 段3：后端仓漏洞引用列表（带 id 可点定位） */}
        {flow.vuln_refs.map((v, i) => {
          const inner = (
            <>
              <span className="font-mono text-muted-foreground">[{v.service}]</span>
              <span>{v.title}</span>
              <span className="text-muted-foreground">
                {v.severity} · {v.location}
              </span>
            </>
          );
          return onLocateRef && v.vuln_id ? (
            <button
              key={i}
              type="button"
              data-testid="chain-vuln-ref"
              title={t("scan.correlation.locateRefHint")}
              onClick={() => onLocateRef(v.vuln_id!)}
              className="flex flex-wrap items-baseline gap-1 rounded-sm text-left text-xs transition-colors hover:text-primary focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary"
            >
              {inner}
            </button>
          ) : (
            <span key={i} className="flex flex-wrap items-baseline gap-1 text-xs">
              {inner}
            </span>
          );
        })}
        <Badge
          variant="outline"
          data-testid="chain-confidence"
          className={`ml-auto font-mono ${confidenceCls(flow.confidence)}`}
        >
          {flow.confidence}
        </Badge>
      </div>
      {/* evidence 折叠（<details> 原生收起，默认不喧宾） */}
      <details>
        <summary className="cursor-pointer text-xs text-muted-foreground">
          {t("scan.correlation.evidence")}
        </summary>
        <p className="mt-1 text-xs">{flow.evidence}</p>
        <pre className="mt-1 overflow-auto rounded-md bg-muted/50 p-2 font-mono text-xs">
          {flow.call_site.snippet}
        </pre>
      </details>
    </Card>
  );
}
