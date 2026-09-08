import { useTranslation } from "react-i18next";
import { Badge } from "@/components/ui/badge";
import type { ScanGateEntry, ScanGateSnapshot } from "@/api/client";

/** since（unix 秒）→「Xm/Xh」粗粒度时长（面板跟随列表刷新节奏，无需实时跳秒）。 */
function fmtSince(since?: number): string {
  if (!since) return "";
  const mins = Math.max(0, Math.floor((Date.now() / 1000 - since) / 60));
  if (mins < 60) return `${mins}m`;
  return `${Math.floor(mins / 60)}h`;
}

function EntryRow({ e, running }: { e: ScanGateEntry; running?: boolean }) {
  const { t } = useTranslation();
  const kind = e.kind && e.kind !== "unknown"
    ? t(`scanGate.kinds.${e.kind}`, e.kind) : "";
  return (
    <div className="flex items-center gap-2 text-sm">
      <span className={running ? "text-cyan" : "text-muted-foreground"}>
        {running ? "●" : "○"}
      </span>
      <span className="w-20 truncate text-muted-foreground">{e.ws}</span>
      {kind && <Badge variant="outline" className="text-xs">{kind}</Badge>}
      <span className="flex-1 truncate">{e.label}</span>
      <span className="text-xs text-muted-foreground">{fmtSince(e.since)}</span>
    </div>
  );
}

/** 并发概览面板（spec 2026-09-08-worker-scan-gate §8.2）：仅当 held/waiting 非空时
 *  显示——「为什么排队」的答案：5 槽被哪个工作区的什么任务占着、我排第几。 */
export function ScanGatePanel({ snapshot }: { snapshot: ScanGateSnapshot | null }) {
  const { t } = useTranslation();
  if (!snapshot || (!snapshot.held.length && !snapshot.waiting.length)) return null;
  return (
    <div data-testid="scan-gate-panel"
         className="rounded-lg border border-border p-3 space-y-2">
      <div className="flex items-center justify-between">
        <span className="font-medium">{t("scanGate.title")}</span>
        <span className="text-sm text-muted-foreground">
          {t("scanGate.usage", { held: snapshot.held.length, capacity: snapshot.capacity })}
        </span>
      </div>
      <div className="space-y-1">
        {snapshot.held.map((e) => (
          <EntryRow key={e.workflow_id ?? e.scan_id} e={e} running />
        ))}
      </div>
      {snapshot.waiting.length > 0 && (
        <div className="space-y-1">
          <div className="text-xs text-muted-foreground">
            {t("scanGate.waiting", { n: snapshot.waiting.length })}
          </div>
          {snapshot.waiting.map((e, i) => (
            <div key={e.workflow_id ?? e.scan_id} className="flex items-center gap-2 text-sm">
              <span className="w-12 shrink-0 text-xs text-muted-foreground">
                {t("scanGate.rank", { n: i + 1 })}
              </span>
              <div className="flex-1 min-w-0"><EntryRow e={e} /></div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
