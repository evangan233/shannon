// 1:1 复刻 packages/core/src/supernova_core/display/dashboard_state.py:70-132 DashboardState.apply。
// 前端独立可信的 SSE 状态累积器（spec §4.1）。纯函数、不可变、无 IO、无时间调用。
import type { NdjsonEvent } from "../api/types";
import { firstNonemptyLine, humanizeToolCall } from "./formatters";

export type AgentStatus = "running" | "done" | "failed";

export interface AgentRow {
  name: string;
  status: AgentStatus;
  attempt: number;
  turn: number;
  last_action: string | null;
  last_action_detail: string | null;
  last_turn_text: string | null;
  duration_ms: number | null;
  cost_usd: number | null;
  cost_currency?: string;
  error: string | null;
}

/** GitNexus 深判（chain-verdict）单行聚合进度（GitnexusLlmEvent fold，2026-08-28）。 */
export interface GitnexusProgress {
  done: number;
  total: number;
  hits: number;
  /** 最新一条 hit 的 detail（命中链摘要）；非 hit 事件不覆盖。 */
  detail: string | null;
}

export interface DashboardState {
  current_phase: string | null;
  agents: Record<string, AgentRow>;
  phase_units: string[];
  unit_status: Record<string, string>;
  unit_intent: Record<string, string>;
  /** 全程阶段轨道（前端扩展，core 无此字段——gitnexus_progress 先例，2026-09-09）：
   *  PhaseEvent 序列折叠成 阶段名→running/done/failed，不随下一阶段 start 重置
   *  （phase_units 是单阶段步级、每阶段重置）。ScanPhaseRail 与前端静态计划序
   *  （白盒 7 阶段）合并渲染「到哪个阶段了」。 */
  phase_status: Record<string, "running" | "done" | "failed">;
  /** ResumeEvent.completed_agents 累积（多次续跑合并去重）：resume 时 pre-recon/
   *  recon 等已完成 agent 不重发 PhaseEvent，渲染侧用此种子把对应阶段标 done。 */
  resumed_completed: string[];
  /** GitNexus 深判聚合进度（前端扩展，core 无此字段——correlation_progress 先例）；
   *  null = 本流尚无 chain-verdict 事件。PhaseEvent start 不清（终态跨 phase 保留）。 */
  gitnexus_progress: GitnexusProgress | null;
  // 派生（core 是 @property；TS 在 reducer 末尾计算并挂上，便于组件直接读）
  completed_count: number;
  total_cost: number;
  cost_currency?: string;
  total_units: number;
  completed_units: number;
  running_units: string[];
}

export function emptyState(): DashboardState {
  return {
    current_phase: null, agents: {}, phase_units: [], unit_status: {}, unit_intent: {},
    phase_status: {}, resumed_completed: [],
    gitnexus_progress: null,
    completed_count: 0, total_cost: 0, cost_currency: "USD", total_units: 0, completed_units: 0, running_units: [],
  };
}

function row(name: string): AgentRow {
  return {
    name, status: "running", attempt: 1, turn: 0,
    last_action: null, last_action_detail: null, last_turn_text: null,
    duration_ms: null, cost_usd: null, cost_currency: "USD", error: null,
  };
}

// 对齐 DashboardState._set_unit：仅当 name ∈ phase_units 才更新，未声明的 unit 忽略。
function setUnit(state: DashboardState, name: string, status: string): DashboardState {
  if (!state.phase_units.includes(name)) return state;
  return { ...state, unit_status: { ...state.unit_status, [name]: status } };
}

// 对齐 DashboardState 的 @property 派生属性。
function derive(s: DashboardState): DashboardState {
  const agents = Object.values(s.agents);
  return {
    ...s,
    completed_count: agents.filter((a) => a.status === "done" || a.status === "failed").length,
    total_cost: agents.reduce((sum, a) => sum + (a.cost_usd ?? 0), 0),
    total_units: s.phase_units.length,
    completed_units: Object.values(s.unit_status).filter((st) => st === "done" || st === "failed").length,
    running_units: s.phase_units.filter((n) => s.unit_status[n] === "running"),
  };
}

/**
 * 1:1 复刻 core DashboardState.apply：fold 一个 ndjson 事件，返回新 state（不可变）。
 * 6 个状态变化分支（PhaseEvent / StepEvent / ResumeEvent / AgentEvent / ToolCallEvent /
 * LlmTurnEvent）+ SummaryEvent/scan_end 终态收敛 + correlation_progress（web 编排层
 * 专属事件，前端扩展映射，见 case 注释）+ GitnexusLlmEvent→gitnexus_progress（chain-verdict
 * 深判单行聚合，前端扩展，2026-08-28）+ 其余 type 无 dashboard 状态变化（return state）。
 */
export function dashboardReducer(state: DashboardState, event: NdjsonEvent): DashboardState {
  let next: DashboardState = state;

  switch (event.type) {
    case "PhaseEvent": {
      // 阶段轨道 fold（前端扩展，见 DashboardState.phase_status 注释）：start 把其余
      // running 阶段隐式收成 done（complete 事件丢失/乱序兜底——白盒 phase 严格串行，
      // 下一阶段 start 即前序完结的证据），本阶段置 running（done 后重启=同名重开，
      // 组合扫描黑盒 reporting 复用白盒阶段名场景）；complete 置 done。running 中重复
      // start 幂等（不新建对象，避免无谓渲染）。
      if (event.event === "start") {
        // 对齐 core：intents = {n: i for n,i in zip(steps, step_intents) if i}
        // 守卫：steps/step_intents 可能缺失（畸形/降级事件），裸 [..undefined] 会抛
        // TypeError → .reduce 整批中断 → state 冻结在 emptyState（live 页恒显 0/0）。
        const steps = Array.isArray(event.steps) ? event.steps : [];
        const stepIntents = Array.isArray(event.step_intents) ? event.step_intents : [];
        const intents: Record<string, string> = {};
        for (let i = 0; i < steps.length; i++) {
          const it = stepIntents[i];
          if (it) intents[steps[i]] = it;
        }
        let ps = state.phase_status;
        let psChanged = false;
        for (const [k, v] of Object.entries(ps)) {
          if (v === "running" && k !== event.phase) {
            if (!psChanged) { ps = { ...ps }; psChanged = true; }
            ps[k] = "done";
          }
        }
        if (ps[event.phase] !== "running") {
          if (!psChanged) { ps = { ...ps }; psChanged = true; }
          ps[event.phase] = "running";
        }
        next = {
          ...state,
          current_phase: event.phase,
          phase_units: [...steps],
          unit_status: {},
          unit_intent: intents,
          phase_status: ps,
        };
      } else {
        // complete: keep units（对齐 core）
        const ps = state.phase_status[event.phase] === "done"
          ? state.phase_status
          : { ...state.phase_status, [event.phase]: "done" as const };
        next = { ...state, current_phase: event.phase, phase_status: ps };
      }
      break;
    }

    case "StepEvent": {
      const status: string = event.event === "start" ? "running" : (event.error ? "failed" : "done");
      let s = setUnit(state, event.name, status);
      if (event.intent) {
        s = { ...s, unit_intent: { ...s.unit_intent, [event.name]: event.intent } };
      }
      next = s;
      break;
    }

    case "ResumeEvent": {
      const agents = { ...state.agents };
      for (const name of event.completed_agents) {
        agents[name] = { ...row(name), status: "done" };
      }
      // resumed_completed 累积合并（保序去重）：多次续跑各自带增量 completed_agents。
      const merged = state.resumed_completed.filter((n) => !event.completed_agents.includes(n));
      next = {
        ...state,
        agents,
        resumed_completed: [...merged, ...event.completed_agents],
      };
      break;
    }

    case "AgentEvent": {
      const agents = { ...state.agents };
      const cur = agents[event.agent_name] ?? row(event.agent_name);
      if (event.event === "start") {
        agents[event.agent_name] = { ...cur, status: "running", attempt: event.attempt, error: null };
        next = setUnit(state, event.agent_name, "running");
      } else {
        // 对齐 core：success 默认 falsy → failed；但 event.success 可能 undefined，
        // core 用 `event.success`（truthy 判定），TS 用 === false 对齐"未带 success 视为失败"。
        // 实际 core AgentEvent.success 字段语义：end 时通常显式给 True/False；
        // 为对齐 core `event.success`（None 为 falsy → failed），保持 === false 不变。
        const status: AgentStatus = event.success === false ? "failed" : "done";
        agents[event.agent_name] = {
          ...cur,
          status,
          duration_ms: event.duration_ms ?? cur.duration_ms,
          cost_usd: event.cost_usd ?? cur.cost_usd,
          cost_currency: event.cost_currency ?? cur.cost_currency,
          error: event.error ?? null,
        };
        next = setUnit(state, event.agent_name, status);
      }
      // session 内币种一致：取 AgentEvent 的 cost_currency（end 时带）
      next = { ...next, agents, cost_currency: event.cost_currency ?? next.cost_currency };
      break;
    }

    case "ToolCallEvent": {
      const agents = { ...state.agents };
      const cur = agents[event.agent_name];
      if (cur) {
        const detail = humanizeToolCall(event.tool_name, event.parameters ?? {});
        agents[event.agent_name] = { ...cur, last_action: event.tool_name, last_action_detail: detail };
      }
      next = { ...state, agents };
      break;
    }

    case "LlmTurnEvent": {
      const agents = { ...state.agents };
      const cur = agents[event.agent_name];
      if (cur) {
        const line = firstNonemptyLine(event.content);
        agents[event.agent_name] = {
          ...cur,
          turn: event.turn,
          last_turn_text: line || cur.last_turn_text,
        };
      }
      next = { ...state, agents };
      break;
    }

    case "SummaryEvent":
    case "scan_end": {
      // 终态收敛（修报告页已完成扫描常驻显示 N/M<N）：扫描成功结束时，最后一个 phase 声明却
      // 未发 StepEvent 的 step（如 reporting 的 run-report-agent / inject-* 后处理步骤直接执行、
      // 不走 step 事件协议）应视为完成，否则详情页常驻一个未收敛的中间计数，与 status=completed
      // 矛盾。仅 status=completed 收敛；failed/killed/crashed 保留失败现场不动。对齐 core。无
      // phase_units（emptyState）则无副作用。
      if (event.status === "completed" && state.phase_units.length > 0) {
        const unit_status: Record<string, string> = {};
        for (const u of state.phase_units) unit_status[u] = "done";
        next = { ...state, unit_status };
      } else {
        next = state;
      }
      // 阶段轨道终态收敛（同语义）：completed → running 阶段收 done；failed/killed/
      // crashed → running 阶段标 failed（停在出事阶段，保留失败现场）；未观察阶段
      // 不动（未跑到就是未跑到，不粉饰）。
      const conv: "done" | "failed" | null =
        event.status === "completed" ? "done"
        : ["failed", "killed", "crashed"].includes(String(event.status)) ? "failed"
        : null;
      if (conv !== null && Object.values(next.phase_status).some((v) => v === "running")) {
        const phase_status: DashboardState["phase_status"] = {};
        for (const [k, v] of Object.entries(next.phase_status)) {
          phase_status[k] = v === "running" ? conv : v;
        }
        next = { ...next, phase_status };
      }
      break;
    }

    case "correlation_progress": {
      // 跨仓关联主行编排事件（D6，spec 2026-08-24）：web CorrelationEventWriter 写主行
      // events.ndjson 的三段接力进度——node=repo/edge → 累积成网格行（首次见到即声明，
      // 事件序 = 展示序）+ 状态映射 started→running / completed→done / failed→failed，
      // detail（如 reused / raw=ok）进 unit_intent；node=phase → current_phase。
      // 注意与 core DashboardState.apply 的 1:1 复刻关系在此分支有意偏离：core 走 default
      // 忽略——此类 CONTROL 事件只在 web 编排层产生（core CLI 端无此流），前端把 repo/
      // phase/edge 映射进既有 phase_units/unit_status 模型，ScanProgressOverview 的进度
      // 条/步级列表零改动即可渲染关联网格。phase start 不清既有行——三段接力是单一
      // 累积网格（repo 段成果保留到 edge 段；段③黑盒 run 的常规 PhaseEvent start 进来
      // 才按既有语义重置）。
      if (event.node === "phase") {
        next = { ...state, current_phase: event.name };
        break;
      }
      const status: string =
        event.status === "completed" ? "done"
        : event.status === "failed" ? "failed"
        : "running"; // started / 未知值保守视为进行中
      const phase_units = state.phase_units.includes(event.name)
        ? state.phase_units
        : [...state.phase_units, event.name];
      next = {
        ...state,
        phase_units,
        unit_status: { ...state.unit_status, [event.name]: status },
      };
      if (event.detail) {
        next = { ...next, unit_intent: { ...next.unit_intent, [event.name]: event.detail } };
      }
      break;
    }

    case "GitnexusLlmEvent": {
      // chain-verdict 深判单行聚合（2026-08-28 实时页 Agent 盲区修复，读侧）：
      // phase=chain-verdict 的 progress/hit/summary fold 成 done/total/hits，
      // detail 只留最新 hit（summary 的汇总文本不作命中摘要）。note 与其他 phase
      // （taint-analysis / sink-discovery 等一次性判定）不进本行。畸形事件
      // Number()||0 回落防 NaN。PhaseEvent start 不清——深判终态是本 scan 的
      // 既成事实，晚进页面的读者仍可见（见 case PhaseEvent 不动此字段）。
      if (event.phase === "chain-verdict" && event.kind !== "note") {
        const prev = state.gitnexus_progress;
        next = {
          ...state,
          gitnexus_progress: {
            done: Number(event.done) || 0,
            total: Number(event.total) || 0,
            hits: Number(event.hits) || 0,
            detail: (event.kind === "hit" && event.detail) ? event.detail : prev?.detail ?? null,
          },
        };
      }
      break;
    }

    // ErrorEvent / WorkflowHeader / InfoEvent →
    // 无 dashboard 状态变化（对齐 core default）。
    default:
      next = state;
  }

  return derive(next);
}
