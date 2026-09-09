import type { ReactElement } from "react";
import { useEffect, useMemo, useRef } from "react";
import { useTranslation } from "react-i18next";
import { ChevronDown } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { mergedScanEventsUrl } from "@/api/client";
import { useEventSource } from "@/api/useEventSource";
import { dashboardReducer, emptyState, type DashboardState } from "@/state/dashboardReducer";
import { ScanPhaseRail } from "./ScanPhaseRail";

/**
 * 详情页进度概览（spec 2026-08-14 进度两层粒度 · 详情页细粒度）。
 *
 * 顶部全 tab 常驻且随页 sticky 固定（ScanDetail 里与 tabs 同块）。压缩为恒定单行：
 * 当前阶段 + 分段迷你进度条（每步一段，悬停看步骤名/intent）+ 进度计数 + 运行中
 * Agent 芯片（悬停看在调什么工具）+ 连接态；完整步级列表与 Agent 详情收进 chevron
 * Popover 浮层（悬浮不挤压布局——logs/live 是定高 flex 链，平铺列表会吃掉日志区）。
 * 建单条 SSE（全量归并流：认证/白盒/黑盒 run-K 按 ts 归并，与 LiveTab 同 URL 共享
 * 同一 store），events 经 dashboardReducer fold 成 DashboardState（1:1 复刻 core；
 * 各段 phase 依时序覆盖，「当前阶段」即最新段）。精简于 DashboardPanel（不含耗时/
 * 花费指标——那些在 overview tab 的 metrics）。
 */

// 连接态徽章（复用 live tab 的 status key）。
const STATUS_MAP: Record<string, { labelKey: string; cls: string }> = {
  open: { labelKey: "workspaceDetail.live.statusOpen", cls: "border-cyan/40 text-cyan" },
  error: { labelKey: "workspaceDetail.live.statusError", cls: "border-yellow/40 text-yellow" },
  closed: { labelKey: "workspaceDetail.live.statusClosed", cls: "border-muted-foreground/40 text-muted-foreground" },
};

const UNIT_STATUS_CLS: Record<string, string> = {
  running: "text-cyan",
  done: "text-green",
  failed: "text-red",
};

// 进度条分段底色（与列表状态色同源：绿=完成 / 青=运行 / 红=失败 / muted=未开始）。
const SEGMENT_CLS: Record<string, string> = {
  running: "bg-cyan motion-reduce:animate-none animate-pulse",
  done: "bg-green",
  failed: "bg-red",
  pending: "bg-muted",
};

function unitGlyph(st: string | undefined): string {
  return st === "running" ? "○" : st === "done" ? "✓" : st === "failed" ? "✗" : "·";
}

/** 计数组：进度 X/Y · Agent N/M · ✗F（有失败才显，红色）。单行常驻与 Popover 头部共用。 */
function ProgressCounts({
  state, agentTotal,
}: { state: DashboardState; agentTotal: number }): ReactElement {
  const { t } = useTranslation();
  const showProgress = state.total_units > 0;
  const failed = state.phase_units.filter((u) => state.unit_status[u] === "failed").length;
  return (
    <span className="flex flex-wrap items-center gap-x-2 gap-y-0.5 font-mono text-xs text-muted-foreground">
      {showProgress && <span>{t("dashboard.progress")} {state.completed_units}/{state.total_units}</span>}
      {showProgress && agentTotal > 0 && <span aria-hidden className="opacity-40">·</span>}
      {agentTotal > 0 && <span>Agent {state.completed_count}/{agentTotal}</span>}
      {failed > 0 && (
        <>
          <span aria-hidden className="opacity-40">·</span>
          <span className="text-red" data-testid="progress-failed-count">✗{failed}</span>
        </>
      )}
    </span>
  );
}

export interface ScanProgressOverviewProps {
  ws: string;
  scanId: string;
  /** bb_runs 数量：变化即换 rev 重开流（与 LiveTab 的 rev 同源，URL 一致共享 store）。 */
  runsCount?: number;
  /** events 流出现 scan_end 时回调一次（ScanDetail 用于重拉 meta——失败横幅/状态徽章
   *  随失败实时出现，不必等用户刷新）。复用本组件已有 SSE，不再开第三条连接。 */
  onScanEnd?: () => void;
  /** 扫描类型（meta.scan_type）：驱动全程阶段轨道（ScanPhaseRail）的计划序——
   *  whitebox/combined→白盒 7 阶段、blackbox→黑盒 4 阶段、correlation/缺省→
   *  不渲染（见 ScanPhaseRail）。缺省不渲染保证既有调用方/测试零变化。 */
  scanType?: string | null;
}

export function ScanProgressOverview({
  ws, scanId, runsCount, onScanEnd, scanType,
}: ScanProgressOverviewProps): ReactElement {
  const { t } = useTranslation();
  const eventsUrl = mergedScanEventsUrl(ws, scanId, runsCount);
  const { events, status } = useEventSource(eventsUrl);
  const state = useMemo(() => events.reduce(dashboardReducer, emptyState()), [events]);
  // 同一 eventsUrl 只通知一次（切换 run 换 URL 后重新通知）；历史回放里的 scan_end 也会
  // 触发一次首拉刷新，幂等无害。
  const endedFor = useRef<string | null>(null);
  useEffect(() => {
    if (!onScanEnd || endedFor.current === eventsUrl) return;
    if (events.some((e) => e.type === "scan_end")) {
      endedFor.current = eventsUrl;
      onScanEnd();
    }
  }, [events, eventsUrl, onScanEnd]);
  const running = Object.values(state.agents).filter((a) => a.status === "running");
  const agentTotal = Object.keys(state.agents).length;
  const showProgress = state.total_units > 0;
  const sm = STATUS_MAP[status] ?? STATUS_MAP.closed;

  return (
    <TooltipProvider>
      <div
        className="rounded-md border border-border bg-card p-2.5 shadow-[var(--shadow-card)]"
        data-testid="scan-progress-overview"
      >
        {/* 主行：当前阶段 + 步级分段 + 计数 + Agent 芯片 + 连接态 + 详情浮层 */}
        <div className="flex min-w-0 items-center gap-3">
        {/* 当前阶段（coral 主角） */}
        <span className="shrink-0 truncate font-sans text-base font-semibold leading-tight text-primary">
          {state.current_phase ?? "—"}
        </span>

        {/* 分段迷你进度条：每步一段，悬停 Tooltip 看步骤名 + intent（替代平铺列表） */}
        {state.phase_units.length > 0 && (
          <div
            className="flex h-1.5 min-w-16 flex-1 items-stretch gap-px"
            data-testid="progress-strip"
          >
            {state.phase_units.map((unit) => {
              const st = state.unit_status[unit] ?? "pending";
              return (
                <Tooltip key={unit}>
                  <TooltipTrigger asChild>
                    <span
                      data-status={st}
                      data-unit={unit}
                      className={`flex-1 cursor-default rounded-full transition-colors ${SEGMENT_CLS[st] ?? SEGMENT_CLS.pending}`}
                    />
                  </TooltipTrigger>
                  <TooltipContent className="max-w-64">
                    <span className="font-mono text-xs">{unit}</span>
                    {state.unit_intent[unit] && (
                      <div className="text-xs text-muted-foreground">{state.unit_intent[unit]}</div>
                    )}
                  </TooltipContent>
                </Tooltip>
              );
            })}
          </div>
        )}

        {/* 进度计数（含失败 ✗N） */}
        {(showProgress || agentTotal > 0) && (
          <div className="shrink-0">
            <ProgressCounts state={state} agentTotal={agentTotal} />
          </div>
        )}

        {/* 运行中 Agent 芯片：最多 2 个 + "+N"，悬停看在调什么工具 */}
        {running.length > 0 && (
          <div className="flex min-w-0 shrink items-center gap-1 overflow-hidden" data-testid="progress-agents">
            {running.slice(0, 2).map((a) => (
              <Tooltip key={a.name}>
                <TooltipTrigger asChild>
                  <span className="flex shrink-0 items-center gap-1 rounded border border-border bg-background px-1.5 py-0.5 font-mono text-xs">
                    <span className="supernova-spinner" aria-hidden /> {a.name}{" "}
                    <span className="text-muted-foreground">t{a.turn}</span>
                  </span>
                </TooltipTrigger>
                <TooltipContent className="max-w-72 break-all font-mono text-xs">
                  {a.last_action_detail ?? a.last_action ?? a.name}
                </TooltipContent>
              </Tooltip>
            ))}
            {running.length > 2 && (
              <span
                className="shrink-0 font-mono text-xs text-muted-foreground"
                title={running.slice(2).map((a) => a.name).join(", ")}
              >
                +{running.length - 2}
              </span>
            )}
          </div>
        )}

        {/* 连接态徽章 */}
        <Badge variant="outline" className={`shrink-0 gap-1 ${sm.cls}`}>
          <span aria-hidden>●</span>{t(sm.labelKey)}
        </Badge>

        {/* 详情浮层：完整步级列表 + Agent 详情（悬浮，不挤压布局） */}
        <Popover>
          <PopoverTrigger asChild>
            <Button
              variant="ghost"
              size="icon-sm"
              className="shrink-0"
              aria-label={t("workspaceDetail.live.progressDetails")}
              data-testid="progress-details-trigger"
            >
              <ChevronDown className="size-4" />
            </Button>
          </PopoverTrigger>
          <PopoverContent align="end" className="w-80 p-3" data-testid="progress-details">
            <div className="flex items-center justify-between gap-2">
              <span className="font-sans text-sm font-semibold text-primary">
                {state.current_phase ?? "—"}
              </span>
              {(showProgress || agentTotal > 0) && (
                <ProgressCounts state={state} agentTotal={agentTotal} />
              )}
            </div>

            {/* 当前阶段的步级列表（✓/○/✗ + intent，与旧版一致） */}
            {state.phase_units.length > 0 && (
              <div className="mt-2 space-y-0.5 text-xs">
                {state.phase_units.map((unit) => {
                  const st = state.unit_status[unit];
                  return (
                    <div key={unit} className="flex gap-2">
                      <span className={UNIT_STATUS_CLS[st ?? ""] ?? "text-muted-foreground"}>
                        {unitGlyph(st)}
                      </span>
                      <span className="text-foreground">{unit}</span>
                      {state.unit_intent[unit] && (
                        <span className="text-muted-foreground">- {state.unit_intent[unit]}</span>
                      )}
                    </div>
                  );
                })}
              </div>
            )}

            {/* GitNexus 深判单行聚合（2026-08-28 Agent 盲区修复）：30+ 个 chain-verdict-*
                短命 agent 的正确形态是一行 done/total·hits（GitnexusLlmEvent fold），
                非平铺；最新命中链摘要一行（⚑ + 截断，title 悬停看全文）。 */}
            {state.gitnexus_progress && (
              <div className="mt-2 border-t border-border pt-2" data-testid="progress-gn">
                <div className="flex items-center justify-between gap-2 font-mono text-xs">
                  <span className="text-foreground">{t("workspaceDetail.live.gnVerdict")}</span>
                  <span className="shrink-0 text-muted-foreground">
                    {state.gitnexus_progress.done}/{state.gitnexus_progress.total}
                    {" · "}
                    {t("workspaceDetail.live.gnHits")} {state.gitnexus_progress.hits}
                  </span>
                </div>
                {state.gitnexus_progress.detail && (
                  <div
                    className="mt-0.5 truncate text-xs text-green"
                    data-testid="progress-gn-hit"
                    title={state.gitnexus_progress.detail}
                  >
                    ⚑ {state.gitnexus_progress.detail}
                  </div>
                )}
              </div>
            )}

            {/* 正在跑的 Agent（spinner + 名 + 第几轮 + 在调什么工具） */}
            {running.length > 0 && (
              <div className="mt-2 space-y-1 border-t border-border pt-2">
                {running.map((a) => (
                  <div key={a.name} className="break-all font-mono text-xs">
                    <span className="supernova-spinner" aria-hidden /> {a.name}{" "}
                    <span className="text-muted-foreground">t{a.turn}</span>{" "}
                    {a.last_action_detail ?? a.last_action ?? ""}
                  </div>
                ))}
              </div>
            )}
          </PopoverContent>
        </Popover>
        </div>
        {/* 全程阶段轨道：所有阶段走到哪了（计划序常驻 + SSE 实时状态），见 ScanPhaseRail */}
        <ScanPhaseRail state={state} scanType={scanType} />
      </div>
    </TooltipProvider>
  );
}
