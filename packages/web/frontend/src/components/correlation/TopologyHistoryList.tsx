import { useTranslation } from "react-i18next";
import { Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import type { CorrelationTopologyAnalysis, CorrelationTopologyStatus } from "@/api/types";

interface Props {
  entries: CorrelationTopologyAnalysis[];
  activeId: string | null;
  onSelect: (entry: CorrelationTopologyAnalysis) => void;
  onDelete?: (entry: CorrelationTopologyAnalysis) => void;
  deletingId?: string | null;
}

/** 分析历史条目时间：当年「MM-DD HH:mm」，跨年补「YY-」消歧。无效/缺失返空串。 */
function fmtWhen(iso?: string): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  const p = (n: number) => String(n).padStart(2, "0");
  const now = new Date();
  const prefix = d.getFullYear() === now.getFullYear() ? "" : `${String(d.getFullYear()).slice(2)}-`;
  return `${prefix}${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

const FAILURE_STATES: ReadonlySet<CorrelationTopologyStatus> = new Set(["failed", "cancelled", "interrupted"]);

/** 分析历史档案行：点击即恢复该次分析的世界（勾选仓库 + 拓扑 + YAML）。
 *  识别键是 repo 组合（mono 首行，truncate + title 全串）；次级行 = 时间 · 状态 ·
 *  缓存标记。当前载入条目左缘 coral 竖条 + 淡底——与拓扑图 entrypoint 节点同一
 *  「左缘竖条 = 命中」结构语言（子元素视觉父离子，非装饰）。失败态状态词升
 *  destructive（危险语义色，结构信号）；成功态保持 muted 安静。空历史不渲染。 */
export function TopologyHistoryList({ entries, activeId, onSelect, onDelete, deletingId }: Props) {
  const { t } = useTranslation();
  if (!entries.length) return null;
  return (
    <div data-testid="topology-history" className="space-y-1 border-t border-border pt-2">
      <div className="flex items-center gap-1.5 text-[11px] font-medium text-muted-foreground">
        {t("scan.correlation.analysis.history.title")}
        <span className="rounded-full bg-muted px-1.5 tabular-nums">{entries.length}</span>
      </div>
      <ul className="max-h-44 overflow-y-auto">
        {entries.map((entry) => {
          const active = entry.analysis_id === activeId;
          const failure = FAILURE_STATES.has(entry.status);
          return (
            <li key={entry.analysis_id} className="relative">
              <button
                type="button"
                aria-current={active ? "true" : undefined}
                onClick={() => onSelect(entry)}
                className={`relative flex w-full flex-col gap-0.5 rounded-md py-1.5 pl-2 pr-9 text-left ${
                  active ? "bg-primary/5" : "hover:bg-muted/60"
                }`}
              >
                {active && (
                  <span aria-hidden className="absolute left-0 top-1/2 h-[calc(100%-10px)] w-[3px] -translate-y-1/2 rounded-full bg-primary" />
                )}
                <span className="truncate font-mono text-xs" title={entry.repos.join(", ")}>
                  {entry.repos.join(", ")}
                </span>
                <span className={`flex items-center gap-1 text-[11px] ${failure ? "text-destructive" : "text-muted-foreground"}`}>
                  {fmtWhen(entry.created_at) && <span className="tabular-nums">{fmtWhen(entry.created_at)}</span>}
                  <span>{t(`scan.correlation.analysis.status.${entry.status}`)}</span>
                  {entry.cache_hit && (
                    <span data-testid={`topology-history-cache-${entry.analysis_id}`}
                      className="rounded-full border border-border px-1.5">
                      {t("scan.correlation.analysis.cache")}
                    </span>
                  )}
                </span>
              </button>
              {onDelete && (
                <Button
                  type="button"
                  variant="ghost"
                  size="icon-sm"
                  className="absolute right-1 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-destructive"
                  data-testid={`topology-history-delete-${entry.analysis_id}`}
                  aria-label={t("scan.correlation.analysis.history.deleteAria", { analysisId: entry.analysis_id })}
                  title={t("scan.correlation.analysis.history.delete")}
                  disabled={entry.status === "queued" || entry.status === "running" || deletingId === entry.analysis_id}
                  onClick={(e) => { e.stopPropagation(); onDelete(entry); }}
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </Button>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
