import { useEffect, useRef } from "react";
import { useTranslation } from "react-i18next";
import { AlertTriangle, RefreshCw, StopCircle, Wand2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { fmtCost } from "@/utils/currency";
import { parseEventTs, fmtClock } from "@/utils/eventTs";
import type { CorrelationTopologyAnalysis, TopologyAuditLine } from "@/api/types";
import { TopologyHistoryList } from "./TopologyHistoryList";

interface Props {
  analysis: CorrelationTopologyAnalysis | null;
  starting: boolean;
  error: string | null;
  logLines: TopologyAuditLine[];
  logDropped?: number;
  onStart: () => void;
  onRetry: () => void;
  onCancel: () => void;
  historyEntries?: CorrelationTopologyAnalysis[];
  historyActiveId?: string | null;
  onSelectHistoryEntry?: (entry: CorrelationTopologyAnalysis) => void;
  onDeleteHistoryEntry?: (entry: CorrelationTopologyAnalysis) => void;
  historyDeletingId?: string | null;
}

/** 过程日志行 → log-row 网格描述（icon/tag/body/类型色），与 tool-audit 事件类型一一对应。
 *  对齐扫描 live 页 LogStream 的行语言（events.css .log-row + ev-* 语义色）：三处日志框
 *  （live / 跨仓关联 / 认证测试）统一视觉——tool_start=ToolCallEvent（↳ TOOL ev-tool）、
 *  assistant_turn=LlmTurnEvent（› LLM ev-llm）、error=ErrorEvent（✗ ERROR ev-error）、
 *  tool_end 对齐 LogsTab 的 ⇢ RESULT muted 分支。 */
function lineDesc(line: TopologyAuditLine): { icon: string; tag: string; cls: string; body: string } {
  switch (line.type) {
    case "tool_start":
      return { icon: "↳", tag: "TOOL", cls: "ev-tool",
        body: `${line.tool ?? "tool"}${line.summary ? `: ${line.summary}` : ""}` };
    case "tool_end":
      return { icon: "⇢", tag: "RESULT", cls: "text-muted-foreground", body: `→ ${line.summary}` };
    case "assistant_turn":
      return { icon: "›", tag: "LLM", cls: "ev-llm", body: line.summary };
    case "error":
      return { icon: "✗", tag: "ERROR", cls: "ev-error", body: line.summary };
    default:
      return { icon: "·", tag: "LOG", cls: "text-muted-foreground", body: line.summary };
  }
}

// 行渲染走与 live 页 LogStream 同款 CSS class（log-gutter|log-ts|log-icon|log-tag|log-body|
// log-metrics），非自拼串——固定列网格免列参差；窄列 ellipsis，行 title 渐进披露完整 ts+内容。
function AuditLineRow({ line }: { line: TopologyAuditLine }) {
  const d = lineDesc(line);
  const epoch = parseEventTs(line.ts);
  const clock = Number.isNaN(epoch) ? (line.ts ?? "") : fmtClock(epoch);
  const title = [line.ts, line.tool, line.summary].filter(Boolean).join("  ");
  return (
    <div className={`log-row ${d.cls}`} data-type={line.type} title={title}>
      <span className="log-gutter" aria-hidden />
      <span className="log-ts">{clock}</span>
      <span className="log-icon" aria-hidden>{d.icon}</span>
      <span className="log-tag">{d.tag}</span>
      <span className="log-body">{d.body}</span>
      <span className="log-metrics" />
    </div>
  );
}

/** 过程日志尾窗：近底自动跟随（用户上翻查看历史时不拽回），新行到达才滚。
 *  容器与 live 页 LogStream 同款（rounded border bg-background p-2 font-mono text-xs）。 */
function AuditTrail({ lines, dropped }: { lines: TopologyAuditLine[]; dropped?: number }) {
  const ref = useRef<HTMLDivElement | null>(null);
  const lastNo = lines.length ? lines[lines.length - 1].no : -1;
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 48;
    if (nearBottom) el.scrollTop = el.scrollHeight;
  }, [lastNo]);
  return (
    <div ref={ref}
      className="h-40 overflow-y-auto rounded-md border border-border bg-background p-2 font-mono text-xs">
      {dropped ? (
        <div className="text-muted-foreground/60">… {dropped} ↑</div>
      ) : null}
      {lines.map((line) => <AuditLineRow key={line.no} line={line} />)}
      {lines.length === 0 && !dropped ? (
        <div className="text-muted-foreground/60">…</div>
      ) : null}
    </div>
  );
}

export function CorrelationTopologyAnalysisPanel({
  analysis, starting, error, logLines, logDropped, onStart, onRetry, onCancel,
  historyEntries, historyActiveId, onSelectHistoryEntry,
  onDeleteHistoryEntry, historyDeletingId,
}: Props) {
  const { t } = useTranslation();
  const active = analysis?.status === "queued" || analysis?.status === "running";
  const terminalFailure = analysis?.status === "failed" || analysis?.status === "cancelled"
    || analysis?.status === "interrupted";
  return (
    <section className="space-y-2 rounded-lg border border-border bg-card p-3" aria-label={t("scan.correlation.analysis.panel")}>
      <div className="flex flex-wrap items-center gap-2">
        {/* ai variant（三按钮家族 2026-09-09，v2 gutter 竖条版）：AI 辅助动作不实色——
            与提交同为 bg-primary 会争层级（把「分析」当「扫描」点）；左缘 2px 信号竖条
            （默认 primary）+ 图标同色；取消态竖条与图标一起转 destructive（[--ai-signal]
            经 arbitrary property 换信号色）。 */}
        <Button type="button" variant="ai" size="sm"
          className={active ? "[--ai-signal:var(--destructive)]" : undefined}
          onClick={active ? onCancel : terminalFailure || analysis?.status === "completed" ? onRetry : onStart}
          disabled={starting}>
          {active ? <StopCircle className="h-3.5 w-3.5 text-destructive" /> : terminalFailure ? <RefreshCw className="h-3.5 w-3.5 text-primary" /> : <Wand2 className="h-3.5 w-3.5 text-primary" />}
          {active ? t("scan.correlation.analysis.cancel") : terminalFailure || analysis?.status === "completed" ? t("scan.correlation.analysis.retry") : t("scan.correlation.analysis.start")}
        </Button>
        {analysis && (
          <span className="rounded-full border border-border bg-card px-2 py-0.5 text-[11px] font-semibold">
            {t(`scan.correlation.analysis.status.${analysis.status}`)}
          </span>
        )}
        {analysis?.cache_hit && (
          <span className="rounded-full border border-border bg-card px-2 py-0.5 text-[11px] text-muted-foreground">
            {t("scan.correlation.analysis.cache")}
          </span>
        )}
        {typeof analysis?.progress === "number" && (
          <span className="text-[11px] text-muted-foreground">{analysis.progress}%</span>
        )}
      </div>
      {analysis && (logLines.length > 0 || active) && (
        <AuditTrail lines={logLines} dropped={logDropped} />
      )}
      {analysis?.usage && (
        <p className="text-xs text-muted-foreground">
          {t("scan.correlation.analysis.usage", {
            tokens: (analysis.usage.input_tokens ?? 0) + (analysis.usage.output_tokens ?? 0),
            cost: fmtCost(analysis.usage.cost_usd, analysis.usage.cost_currency),
          })}
        </p>
      )}
      {analysis?.status === "failed" || analysis?.status === "interrupted" ? (
        <p className="text-xs text-destructive">{analysis.error?.message ?? t("scan.correlation.analysis.failed")}</p>
      ) : null}
      {error && <p className="flex items-center gap-1 text-xs text-destructive"><AlertTriangle className="h-3.5 w-3.5" />{error}</p>}
      {onSelectHistoryEntry && (
        <TopologyHistoryList entries={historyEntries ?? []} activeId={historyActiveId ?? null}
          onSelect={onSelectHistoryEntry} onDelete={onDeleteHistoryEntry}
          deletingId={historyDeletingId} />
      )}
    </section>
  );
}
