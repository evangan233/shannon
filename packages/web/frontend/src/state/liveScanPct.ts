// liveScanPct：SSE 归并流 events → 列表/磁贴行实时进度（2026-08-28 组合扫描进度修复）。
//
// 根因：dashboardReducer 是「当前 phase」口径（PhaseEvent(start) 重置 phase_units/
// unit_status）——fold 的 completed/total 只代表最后一个 phase。列表行把它当全任务
// 进度，组合扫描在白盒最后 phase 收尾后显示 100%（黑盒未跑）、黑盒段又从 0% 爬。
//
// 修复口径（对齐后端 scan_store._compute_progress_pct / spec §9.2 三阶段加权）：
// 用事件 src 源标记（MergedEventTailer 注入）判段，把段内 ratio 映射到全程轴：
//   ac（认证预检） → 5 × ratio        （0-5%）
//   wb（白盒）     → 5 + 50 × ratio   （5-55%；白盒满格 = 55%，不再是 100%）
//   run-K（黑盒）  → 55 + 45 × ratio  （55-100%）
// total=0（段未声明 steps，如黑盒 preflight）→ ratio=0（段起点值）。段判据不能靠
// phase 名：authcheck（独立 AuthValidationWorkflow）与黑盒 run 的 auth-validation
// 段发同名 PhaseEvent，前端无从区分。
//
// 非组合行保持既有口径：纯白盒单段即全部（fold 直读）；correlation 主行是
// correlation_progress 累积网格（reducer 不重置 units，fold 直读即三段全程），
// 即使 combined=true 也不套三阶段。
import { dashboardReducer, emptyState } from "./dashboardReducer";
import type { NdjsonEvent } from "../api/types";

const BB_RUN_SRC = /^run-\d+$/;

/** 尾向找最后一条带 src 的事件（ts 归并流，末条事件即当前活跃源）。 */
function lastSrc(events: NdjsonEvent[]): string | null {
  for (let i = events.length - 1; i >= 0; i--) {
    const s = events[i].src;
    if (typeof s === "string" && s) return s;
  }
  return null;
}

export function liveScanPct(
  events: NdjsonEvent[],
  scan: { combined?: boolean | null; scan_type: string },
): number | null {
  // 子仓源（src=c-<scan_id>，2026-09-10 归并流扩子仓）不进列表行进度 fold——分流
  // 2026-09-20 已收进 dashboardReducer（c-* 源只透传阶段进 repo 行 detail，网格/
  // 终态不动），此处 reduce 前过滤为冗余防御保留。子仓行各自订阅自己的流（无
  // c-* 源），不受影响。
  const mainEvents = events.filter((e) => !String(e.src ?? "").startsWith("c-"));
  const state = mainEvents.reduce(dashboardReducer, emptyState());
  const ratio = state.total_units > 0
    ? state.completed_units / state.total_units
    : 0;

  if (scan.combined === true && scan.scan_type !== "correlation") {
    const src = lastSrc(mainEvents);
    if (src === null) return null; // 旧后端流无源标记：判不了段，回退 progress_pct
    if (src === "ac") return Math.round(5 * ratio);
    if (src === "wb") return Math.round(5 + 50 * ratio);
    if (BB_RUN_SRC.test(src)) return Math.round(55 + 45 * ratio);
    return null; // 未知源标记：保守回退
  }

  return state.total_units > 0 ? Math.round(ratio * 100) : null;
}
