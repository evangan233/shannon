import { useMemo } from "react";
import { useNavigate, useParams, useOutletContext } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { useEventSource } from "../../api/useEventSource";
import { isBlackboxSegmentActive, mergedScanEventsUrl } from "../../api/client";
import type { ScanEndEvent } from "../../api/types";
import { LogStream } from "../../components/LogStream";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

const STATUS_MAP: Record<string, { labelKey: string; cls: string }> = {
  open: { labelKey: "workspaceDetail.live.statusOpen", cls: "border-cyan/40 text-cyan" },
  error: { labelKey: "workspaceDetail.live.statusError", cls: "border-yellow/40 text-yellow" },
  closed: { labelKey: "workspaceDetail.live.statusClosed", cls: "border-muted-foreground/40 text-muted-foreground" },
};

// scan_end 非完成态的中文标签 key（失败/中断/被杀/崩溃）
const END_LABEL: Record<string, string> = {
  failed: "workspaceDetail.live.endFailed",
  interrupted: "workspaceDetail.live.endInterrupted",
  killed: "workspaceDetail.live.endKilled",
  crashed: "workspaceDetail.live.endCrashed",
};

/** ScanDetail 经 Outlet context 下发的组合段信息（live/logs 等 tab 按需消费）。 */
interface LiveTabCtx {
  selectedRun?: string | null;
  combined?: boolean | null;
  bbPhase?: string | null;
  /** bb_runs 数量：变化即换 rev 重开流（服务端关流后新增 run 仍能续看实时日志）。 */
  runsCount?: number | null;
  /** meta.scan_type：correlation 主行终态按钮跳「跨仓关联」（结果页）而非 report。 */
  scanType?: string | null;
}

/**
 * live tab：实时日志流（LogStream）+ 连接态徽章 + 阶段徽章 + 结束态提示。
 *
 * 实时「当前阶段 / 步级 / 正在跑的 Agent」在详情页顶部 ScanProgressOverview（全 tab 常驻），
 * 本 tab 聚焦实时日志流（spec 进度两层粒度 · 详情页）。瘦身后移除了 DashboardPanel 及其
 * 时钟/getScan 逻辑（耗时/花费在 overview tab 的 metrics）。
 *
 * 单一归并流：后端把 认证(authcheck)/白盒(任务根)/黑盒(所有 run-K) 按 ts 归并为一条
 * SSE（任意时刻打开/刷新都是全量日志，Last-Event-ID 按源断点续传）。wb 的 scan_end 由
 * 后端扣到「全 run 终态」后才作为流末条发出，因此此处见 scan_end 即真终态。rev（run 数）
 * 变化换 URL 重开流，续跑/叠加新 run 的日志继续可看。
 */
export default function LiveTab() {
  const { t } = useTranslation();
  const { workspace, scanId } = useParams<{ workspace: string; scanId: string }>();
  const navigate = useNavigate();
  // 无 Outlet 父级（单测直挂）时 context 为 null——兜底空对象退回归并流（无 rev）。
  const ctx = useOutletContext<LiveTabCtx | null>() ?? {};
  const isCorrelation = ctx.scanType === "correlation";
  const seg = { combined: ctx.combined ?? null, bbPhase: ctx.bbPhase ?? null, selectedRun: ctx.selectedRun ?? null };
  const inBlackboxSegment = isBlackboxSegmentActive(seg);
  const { events, status } = useEventSource(
    workspace && scanId
      ? mergedScanEventsUrl(workspace, scanId, ctx.runsCount ?? undefined)
      : "",
  );

  // scan_end 真实信号是 events 出现 scan_end 事件（status==="closed" 既能是 scan_end 也能是初始未连接，不可靠）
  const scanEnd = useMemo<ScanEndEvent | null>(() => {
    for (let i = events.length - 1; i >= 0; i--) {
      if (events[i].type === "scan_end") return events[i] as ScanEndEvent;
    }
    return null;
  }, [events]);
  const endedCompleted = scanEnd?.status === "completed";
  const endedFailed = scanEnd !== null && !endedCompleted;

  // 重连态 + 空 events + 无 scan_end：扫描可能已中断或暂无进度，纯空面板不友好
  const stalled = status === "error" && events.length === 0 && scanEnd === null;
  const sm = STATUS_MAP[status] ?? STATUS_MAP.closed;

  // 根 h-full 吃 ScanDetail 的 flex-1 tab 容器；连接态徽章 shrink-0 钉顶，LogStream fill 撑满。
  return (
    <div className="flex h-full flex-col gap-3">
      <div className="flex shrink-0 items-center justify-between">
        <div className="flex items-center gap-2">
          <Badge variant="outline" className={`gap-1 ${sm.cls}`}>
            <span aria-hidden>●</span>{t(sm.labelKey)}
          </Badge>
          {/* 组合任务阶段徽章：当前流读的是哪一段（白盒 / 黑盒 run-K），切段随 URL 同步切换 */}
          {ctx.combined === true && (
            <Badge variant="outline" className="font-mono text-muted-foreground" data-testid="live-phase-badge">
              {inBlackboxSegment && ctx.selectedRun
                ? t("workspaceDetail.live.phaseBlackbox", { run: ctx.selectedRun })
                : t("workspaceDetail.live.phaseWhitebox")}
            </Badge>
          )}
        </div>
      </div>
      <LogStream events={events} fill />
      {stalled && (
        <div role="status" className="shrink-0 rounded-md border border-border bg-card p-3 text-sm text-muted-foreground">
          {t("workspaceDetail.live.stalledHint")}
        </div>
      )}
      {endedCompleted && (
        <div role="status" className="flex shrink-0 items-center gap-3 rounded-md border border-border bg-card p-3 text-sm">
          <span className="text-cyan">{t("workspaceDetail.live.endedTitle")}</span>
          <span className="text-muted-foreground">{t("workspaceDetail.live.endedHint")}</span>
          <Button size="sm" variant="outline" onClick={() => navigate(
            isCorrelation
              ? `/p/${workspace}/scans/${scanId}/correlation`
              : `/p/${workspace}/scans/${scanId}/report${inBlackboxSegment && ctx.selectedRun ? `?run=${ctx.selectedRun}` : ""}`,
          )}>
            {isCorrelation
              ? t("workspaceDetail.live.viewCorrelation")
              : t("workspaceDetail.live.viewReport")}
          </Button>
        </div>
      )}
      {endedFailed && (
        <div role="status" className="shrink-0 space-y-2 rounded-md border border-yellow/40 bg-card p-3 text-sm">
          <div className="flex items-center gap-2">
            <span className="text-yellow font-medium">
              {t(END_LABEL[scanEnd!.status] ?? "workspaceDetail.live.endIncomplete")}（{scanEnd!.status}）
            </span>
          </div>
          {scanEnd!.stderr_tail && (
            <pre className="whitespace-pre-wrap break-all rounded bg-muted/40 p-2 text-xs text-muted-foreground">
              {scanEnd!.stderr_tail}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}
