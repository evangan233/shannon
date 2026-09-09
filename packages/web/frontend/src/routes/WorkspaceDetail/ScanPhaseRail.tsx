import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";
import { ChevronRight } from "lucide-react";
import type { DashboardState } from "@/state/dashboardReducer";

/**
 * 全程阶段轨道（2026-09-09 详情页阶段进度）：回答「所有阶段走到哪了」——
 * ScanProgressOverview 的步级分段只覆盖当前阶段（phase_units 每阶段重置），
 * 本轨道常驻展示整个编排旅程（白盒 7 阶段 / 黑盒 4 阶段），随 SSE fold
 * （DashboardState.phase_status，PhaseEvent 序列不重置）实时更新。
 *
 * 计划序由前端静态持有（先例：ScanDetail 的 BREAKPOINT_AGENT_ORDER——
 * whitebox step_intents.PHASE_STEPS / workflows 发射序对齐）；观察序
 * （phase_status/resumed_completed）只补状态不补顺序——计划外观察到的阶段
 * （如组合扫描黑盒段 preflight/exploitation）不进轨道，段级语义由
 * CombinedDetailTimeline 叙述。阶段 slug 保持原文（与日志/current_phase
 * 同源，不造翻译层）。correlation 不渲染（三段接力的网格模型在
 * phase_units/进度条，计划序不适用）。
 */

// 白盒旅程（step_intents.PHASE_STEPS 键序 = workflows PhaseEvent 发射序）。
const WHITEBOX_PHASES = [
  "setup", "pre-recon", "recon", "risk-scoring",
  "vulnerability-analysis", "attack-chain", "reporting",
] as const;

// 黑盒旅程（blackbox workflows：preflight → auth-validation → exploitation → reporting）。
const BLACKBOX_PHASES = ["preflight", "auth-validation", "exploitation", "reporting"] as const;

function planFor(scanType: string | null | undefined): readonly string[] | null {
  if (scanType === "whitebox" || scanType === "combined") return WHITEBOX_PHASES;
  if (scanType === "blackbox") return BLACKBOX_PHASES;
  return null;
}

// Resume 种子：agent 名 → 阶段名（仅 1:1 阶段；vuln agents 都在
// vulnerability-analysis 里、部分完成≠阶段完成，不映射——该阶段 resume 时
// 会重发 PhaseEvent start 自然点亮）。
const RESUME_SEED_PHASE: Record<string, string> = {
  "pre-recon": "pre-recon",
  "recon": "recon",
};

export type PhaseMark = "pending" | "running" | "done" | "failed" | "halted";

/** 阶段状态合成：观察序 phase_status 优先；无观察时用 Resume 种子（续跑跳过
 *  的已完成阶段不重发 PhaseEvent）；都无 → pending（计划内未跑到）。 */
function phaseMark(state: DashboardState, phase: string): PhaseMark {
  const observed = state.phase_status[phase];
  if (observed) return observed;
  const seedAgent = Object.entries(RESUME_SEED_PHASE)
    .find(([agent, p]) => p === phase && state.resumed_completed.includes(agent));
  return seedAgent ? "done" : "pending";
}

// 轨道 glyph：与步级明细（unitGlyph）/进度条分段同色系——绿✓/红✗/muted·，
// running 用 supernova-spinner + primary（与运行 Agent 芯片、当前阶段主角同语言）。
// halted（interrupted/cancelled 非自然中止，2026-09-09）= ‖ 暂停双竖线 + 黄——
// ≠ failed（不盗红✗的「出错」语义）≠ done，黄与 live 页中断横幅（endInterrupted）
// 同语言；spinner 只属于真在跑的流。所有阶段通用（phaseMark 不区分阶段）。
const MARK_GLYPH_CLS: Record<Exclude<PhaseMark, "running">, string> = {
  done: "text-green",
  failed: "text-red",
  halted: "text-yellow",
  pending: "text-muted-foreground/50",
};
const HALTED_GLYPH = "‖";
const NAME_CLS: Record<PhaseMark, string> = {
  done: "text-muted-foreground",
  running: "font-medium text-primary",
  failed: "text-foreground",
  halted: "text-foreground",
  pending: "text-muted-foreground/60",
};

export function ScanPhaseRail({
  state, scanType,
}: {
  state: DashboardState;
  scanType: string | null | undefined;
}): ReactElement | null {
  const { t } = useTranslation();
  const plan = planFor(scanType);
  if (!plan) return null;
  return (
    <div
      className="mt-2 flex flex-wrap items-center gap-x-2 gap-y-1 border-t border-border pt-2"
      data-testid="scan-phase-rail"
      aria-label={t("workspaceDetail.scans.phaseProgress")}
    >
      <span className="shrink-0 text-xs text-muted-foreground">
        {t("workspaceDetail.scans.phaseProgress")}
      </span>
      {plan.map((phase, i) => {
        const mark = phaseMark(state, phase);
        return (
          <span key={phase} className="inline-flex items-center gap-x-2">
            {i > 0 && <ChevronRight aria-hidden className="size-3 text-muted-foreground/30" />}
            <span
              className="inline-flex items-center gap-1 text-xs"
              data-phase={phase}
              data-status={mark}
            >
              {mark === "running" ? (
                <span className="supernova-spinner" aria-hidden />
              ) : (
                <span aria-hidden className={MARK_GLYPH_CLS[mark]}>
                  {mark === "done" ? "✓" : mark === "failed" ? "✗" : mark === "halted" ? HALTED_GLYPH : "·"}
                </span>
              )}
              <span className={NAME_CLS[mark]}>{phase}</span>
            </span>
          </span>
        );
      })}
    </div>
  );
}
