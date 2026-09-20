import { describe, it, expect } from "vitest";
import { dashboardReducer, emptyState } from "./dashboardReducer";
import { firstNonemptyLine, humanizeToolCall } from "./formatters";
import type { NdjsonEvent } from "../api/types";

// 测试辅助：构造 NdjsonEvent，填默认公共字段。
function ev(e: Partial<NdjsonEvent> & { type: NdjsonEvent["type"] }): NdjsonEvent {
  return { ts: "2026-07-02T09:44:01.123Z", category: "PHASE", ...e } as NdjsonEvent;
}

describe("dashboardReducer — 对齐 core DashboardState.apply", () => {
  it("initial state is empty", () => {
    const s = emptyState();
    expect(s.current_phase).toBeNull();
    expect(s.agents).toEqual({});
    expect(s.completed_count).toBe(0);
    expect(s.total_cost).toBe(0);
  });

  it("PhaseEvent start: 设 current_phase + 重置 phase_units/unit_status", () => {
    const s = dashboardReducer(emptyState(), ev({
      type: "PhaseEvent", category: "PHASE", phase: "recon", event: "start",
      steps: ["s1", "s2"], step_intents: ["", ""],
    }));
    expect(s.current_phase).toBe("recon");
    expect(s.phase_units).toEqual(["s1", "s2"]);
    expect(s.unit_status).toEqual({});
    expect(s.total_units).toBe(2);
    expect(s.completed_units).toBe(0);
  });

  it("PhaseEvent start 缺 steps/step_intents 不崩（守 state 不冻结成 0/0）", () => {
    // 完全缺 steps + step_intents
    const s1 = dashboardReducer(emptyState(), ev({
      type: "PhaseEvent", category: "PHASE", phase: "recon", event: "start",
    }));
    expect(s1.current_phase).toBe("recon");
    expect(s1.phase_units).toEqual([]);
    expect(s1.total_units).toBe(0);
    // 有 steps 但缺 step_intents
    const s2 = dashboardReducer(emptyState(), ev({
      type: "PhaseEvent", category: "PHASE", phase: "recon", event: "start", steps: ["a", "b"],
    }));
    expect(s2.phase_units).toEqual(["a", "b"]);
    expect(s2.unit_intent).toEqual({});
  });

  it("PhaseEvent complete: 保留 units", () => {
    const s1 = dashboardReducer(emptyState(), ev({
      type: "PhaseEvent", category: "PHASE", phase: "recon", event: "start",
      steps: ["s1"], step_intents: [""],
    }));
    const s2 = dashboardReducer(s1, ev({
      type: "PhaseEvent", category: "PHASE", phase: "recon", event: "complete",
      steps: ["s1"], step_intents: [""],
    }));
    expect(s2.phase_units).toEqual(["s1"]); // complete 不清空
    expect(s2.current_phase).toBe("recon");
  });

  it("StepEvent start/complete: 更新 unit_status（_set_unit 仅声明的 unit）", () => {
    let s = dashboardReducer(emptyState(), ev({
      type: "PhaseEvent", phase: "recon", event: "start", steps: ["s1"], step_intents: [""],
    }));
    s = dashboardReducer(s, ev({ type: "StepEvent", category: "STEP", name: "s1", phase: "recon", event: "start" }));
    expect(s.unit_status["s1"]).toBe("running");
    s = dashboardReducer(s, ev({ type: "StepEvent", name: "s1", phase: "recon", event: "complete" }));
    expect(s.unit_status["s1"]).toBe("done");
    // 未声明的 unit 被忽略
    s = dashboardReducer(s, ev({ type: "StepEvent", name: "ghost", phase: "recon", event: "start" }));
    expect(s.unit_status["ghost"]).toBeUndefined();
  });

  it("StepEvent complete with error: unit_status=failed", () => {
    let s = dashboardReducer(emptyState(), ev({
      type: "PhaseEvent", phase: "p", event: "start", steps: ["u"], step_intents: [""],
    }));
    s = dashboardReducer(s, ev({ type: "StepEvent", name: "u", phase: "p", event: "complete", error: "boom" }));
    expect(s.unit_status["u"]).toBe("failed");
    expect(s.completed_units).toBe(1); // terminal
  });

  it("AgentEvent start/end: agents[name] 状态流转 + _set_unit", () => {
    let s = dashboardReducer(emptyState(), ev({
      type: "PhaseEvent", phase: "vulnerability-analysis", event: "start",
      steps: ["Injection"], step_intents: [""],
    }));
    s = dashboardReducer(s, ev({
      type: "AgentEvent", category: "AGENT", agent_name: "Injection", event: "start", attempt: 1,
    }));
    expect(s.agents["Injection"]?.status).toBe("running");
    expect(s.agents["Injection"]?.attempt).toBe(1);
    expect(s.unit_status["Injection"]).toBe("running");
    s = dashboardReducer(s, ev({
      type: "AgentEvent", agent_name: "Injection", event: "end",
      attempt: 1, duration_ms: 42000, cost_usd: 0.5, success: true,
    }));
    expect(s.agents["Injection"]?.status).toBe("done");
    expect(s.agents["Injection"]?.cost_usd).toBe(0.5);
    expect(s.agents["Injection"]?.duration_ms).toBe(42000);
    expect(s.unit_status["Injection"]).toBe("done");
    expect(s.completed_count).toBe(1);
    expect(s.total_cost).toBe(0.5);
  });

  it("AgentEvent end failed: status=failed (terminal still counts)", () => {
    let s = dashboardReducer(emptyState(), ev({
      type: "PhaseEvent", phase: "p", event: "start", steps: ["A"], step_intents: [""],
    }));
    s = dashboardReducer(s, ev({ type: "AgentEvent", agent_name: "A", event: "start", attempt: 1 }));
    s = dashboardReducer(s, ev({
      type: "AgentEvent", agent_name: "A", event: "end", attempt: 1, success: false, error: "boom",
    }));
    expect(s.agents["A"]?.status).toBe("failed");
    expect(s.agents["A"]?.error).toBe("boom");
    expect(s.completed_count).toBe(1);
  });

  it("AgentEvent retry: end→start updates attempt back to running", () => {
    let s = dashboardReducer(emptyState(), ev({
      type: "PhaseEvent", phase: "p", event: "start", steps: ["A"], step_intents: [""],
    }));
    s = dashboardReducer(s, ev({ type: "AgentEvent", agent_name: "A", event: "start", attempt: 1 }));
    s = dashboardReducer(s, ev({ type: "AgentEvent", agent_name: "A", event: "end", attempt: 1, success: false, error: "boom" }));
    s = dashboardReducer(s, ev({ type: "AgentEvent", agent_name: "A", event: "start", attempt: 2 }));
    expect(s.agents["A"]?.status).toBe("running");
    expect(s.agents["A"]?.attempt).toBe(2);
    expect(s.agents["A"]?.error).toBeNull(); // start clears error
  });

  it("AgentEvent end without cost/duration: retains prior values", () => {
    let s = dashboardReducer(emptyState(), ev({
      type: "PhaseEvent", phase: "p", event: "start", steps: ["A"], step_intents: [""],
    }));
    s = dashboardReducer(s, ev({ type: "AgentEvent", agent_name: "A", event: "start", attempt: 1 }));
    s = dashboardReducer(s, ev({
      type: "AgentEvent", agent_name: "A", event: "end", attempt: 1, duration_ms: 100, cost_usd: 2.0, success: true,
    }));
    s = dashboardReducer(s, ev({
      type: "AgentEvent", agent_name: "A", event: "end", attempt: 1, success: true,
    }));
    expect(s.agents["A"]?.duration_ms).toBe(100);
    expect(s.agents["A"]?.cost_usd).toBe(2.0);
  });

  it("ToolCallEvent: 更新 last_action + last_action_detail (humanizeToolCall)", () => {
    let s = dashboardReducer(emptyState(), ev({
      type: "PhaseEvent", phase: "p", event: "start", steps: ["A"], step_intents: [""],
    }));
    s = dashboardReducer(s, ev({ type: "AgentEvent", agent_name: "A", event: "start", attempt: 1 }));
    s = dashboardReducer(s, ev({
      type: "ToolCallEvent", category: "TOOL", agent_name: "A", tool_name: "Bash", parameters: { command: "rg -n eval" },
    }));
    expect(s.agents["A"]?.last_action).toBe("Bash");
    expect(s.agents["A"]?.last_action_detail).toBe("command=rg -n eval");
  });

  it("ToolCallEvent on unknown agent: dropped (cur undefined)", () => {
    const s = dashboardReducer(emptyState(), ev({
      type: "ToolCallEvent", agent_name: "Ghost", tool_name: "Bash", parameters: { command: "ls" },
    }));
    expect(s.agents["Ghost"]).toBeUndefined();
  });

  it("LlmTurnEvent: 更新 turn + last_turn_text (firstNonemptyLine)", () => {
    let s = dashboardReducer(emptyState(), ev({
      type: "PhaseEvent", phase: "p", event: "start", steps: ["A"], step_intents: [""],
    }));
    s = dashboardReducer(s, ev({ type: "AgentEvent", agent_name: "A", event: "start", attempt: 1 }));
    s = dashboardReducer(s, ev({
      type: "LlmTurnEvent", category: "LLM", agent_name: "A", turn: 3, content: "\n\nAnalyzing sinks...\n",
    }));
    expect(s.agents["A"]?.turn).toBe(3);
    expect(s.agents["A"]?.last_turn_text).toBe("Analyzing sinks...");
  });

  it("LlmTurnEvent empty content: keeps prior last_turn_text", () => {
    let s = dashboardReducer(emptyState(), ev({
      type: "PhaseEvent", phase: "p", event: "start", steps: ["A"], step_intents: [""],
    }));
    s = dashboardReducer(s, ev({ type: "AgentEvent", agent_name: "A", event: "start", attempt: 1 }));
    s = dashboardReducer(s, ev({ type: "LlmTurnEvent", agent_name: "A", turn: 1, content: "Keep me" }));
    s = dashboardReducer(s, ev({ type: "LlmTurnEvent", agent_name: "A", turn: 2, content: "   \n\n  " }));
    expect(s.agents["A"]?.turn).toBe(2);
    expect(s.agents["A"]?.last_turn_text).toBe("Keep me");
  });

  it("ResumeEvent: completed_agents 标 done", () => {
    const s = dashboardReducer(emptyState(), ev({
      type: "ResumeEvent", category: "RESUME", previous_workflow_id: "x", new_workflow_id: "y",
      checkpoint_hash: "h", completed_agents: ["Injection", "Xss"],
    }));
    expect(s.agents["Injection"]?.status).toBe("done");
    expect(s.agents["Xss"]?.status).toBe("done");
    expect(s.completed_count).toBe(2);
  });

  it("ErrorEvent/SummaryEvent/WorkflowHeader: 无状态变化（SummaryEvent 仅记 end_status）", () => {
    const s0 = emptyState();
    const s1 = dashboardReducer(s0, ev({ type: "ErrorEvent", category: "ERROR", error_type: "X", message: "m" }));
    const s2 = dashboardReducer(s1, ev({ type: "SummaryEvent", category: "SUMMARY", status: "completed" }));
    const s3 = dashboardReducer(s2, ev({
      type: "WorkflowHeader", category: "HEADER", workflow_id: "w", target_url: "u",
      repo_path: "/", mode: "whitebox", web_ui_url: "", logs_cmd: "", workspace: "ws",
    }));
    expect(s3).toEqual({ ...s0, end_status: "completed" });
  });

  it("apply is immutable: original state unchanged", () => {
    const s0 = emptyState();
    const s1 = dashboardReducer(s0, ev({
      type: "PhaseEvent", phase: "recon", event: "start", steps: [], step_intents: [],
    }));
    expect(s0.current_phase).toBeNull();
    expect(s1.current_phase).toBe("recon");
  });

  it("派生: completed_count / total_cost / total_units / completed_units / running_units", () => {
    let s = dashboardReducer(emptyState(), ev({
      type: "PhaseEvent", phase: "p", event: "start", steps: ["A", "B"], step_intents: ["", ""],
    }));
    s = dashboardReducer(s, ev({ type: "AgentEvent", agent_name: "A", event: "start", attempt: 1 }));
    s = dashboardReducer(s, ev({
      type: "AgentEvent", agent_name: "A", event: "end", attempt: 1, success: true, cost_usd: 1.5,
    }));
    s = dashboardReducer(s, ev({ type: "AgentEvent", agent_name: "B", event: "start", attempt: 1 }));
    expect(s.completed_count).toBe(1); // A done
    expect(s.total_cost).toBe(1.5);
    expect(s.total_units).toBe(2);
    expect(s.completed_units).toBe(1); // A unit done
    expect(s.running_units).toEqual(["B"]);
  });

  it("PhaseEvent start resets unit_intent across phases", () => {
    let s = dashboardReducer(emptyState(), ev({
      type: "PhaseEvent", phase: "pre-recon", event: "start",
      steps: ["code-index"], step_intents: ["构建调用图"],
    }));
    s = dashboardReducer(s, ev({
      type: "PhaseEvent", phase: "recon", event: "start",
      steps: ["recon"], step_intents: ["侦察"],
    }));
    expect(s.unit_intent).toEqual({ recon: "侦察" });
  });

  it("StepEvent records intent when provided", () => {
    let s = dashboardReducer(emptyState(), ev({
      type: "PhaseEvent", phase: "pre-recon", event: "start", steps: ["code-index"], step_intents: [""],
    }));
    s = dashboardReducer(s, ev({
      type: "StepEvent", name: "code-index", phase: "pre-recon", event: "start", intent: "构建调用图",
    }));
    expect(s.unit_intent["code-index"]).toBe("构建调用图");
  });

  it("running_units lists in-flight agents and steps", () => {
    let s = dashboardReducer(emptyState(), ev({
      type: "PhaseEvent", phase: "pre-recon", event: "start",
      steps: ["code-index", "pre-recon"], step_intents: ["", ""],
    }));
    s = dashboardReducer(s, ev({ type: "StepEvent", name: "code-index", phase: "pre-recon", event: "start" }));
    s = dashboardReducer(s, ev({ type: "AgentEvent", agent_name: "pre-recon", event: "start", attempt: 1 }));
    expect(s.running_units.sort()).toEqual(["code-index", "pre-recon"]);
    expect(s.completed_units).toBe(0);
  });

  // === 终态收敛（修报告页已完成扫描常驻显示 2/5）===
  // 真实现场：reporting phase 声明 5 个 step，仅前 2 个发 StepEvent complete（run-report-agent /
  // inject-* 后处理步骤直接执行、不发 step 事件）→ phase complete 保留 units → 扫描 SummaryEvent
  // completed 终态。修复前 reducer 在终态不做收敛，completed_units 永久卡在 2，详情页常驻显示 2/5。
  it("SummaryEvent(status=completed) 终态收敛：未发事件的声明 step 标 done", () => {
    let s = dashboardReducer(emptyState(), ev({
      type: "PhaseEvent", phase: "reporting", event: "start",
      steps: ["render-findings", "assemble-report", "run-report-agent",
              "inject-attack-chains", "inject-gitnexus-track-status"],
      step_intents: ["", "", "", "", ""],
    }));
    s = dashboardReducer(s, ev({ type: "StepEvent", name: "render-findings", phase: "reporting", event: "complete" }));
    s = dashboardReducer(s, ev({ type: "StepEvent", name: "assemble-report", phase: "reporting", event: "complete" }));
    s = dashboardReducer(s, ev({ type: "PhaseEvent", phase: "reporting", event: "complete" }));
    // 收敛前：5 声明 / 2 完成（bug 现场）
    expect(s.total_units).toBe(5);
    expect(s.completed_units).toBe(2);
    // 扫描成功结束 → 收敛
    s = dashboardReducer(s, ev({ type: "SummaryEvent", category: "SUMMARY", status: "completed" }));
    expect(s.completed_units).toBe(5); // 终态收敛 → N/N
    expect(s.unit_status["inject-gitnexus-track-status"]).toBe("done");
  });

  it("scan_end(status=completed) 同样终态收敛 unit_status", () => {
    let s = dashboardReducer(emptyState(), ev({
      type: "PhaseEvent", phase: "reporting", event: "start",
      steps: ["a", "b"], step_intents: ["", ""],
    }));
    s = dashboardReducer(s, ev({ type: "StepEvent", name: "a", phase: "reporting", event: "complete" }));
    s = dashboardReducer(s, ev({ type: "scan_end", category: "CONTROL", status: "completed" }));
    expect(s.completed_units).toBe(2);
    expect(s.total_units).toBe(2);
  });

  it("终态失败(scan_end failed)不收敛：未发事件的 step 保持空（保留失败现场）", () => {
    let s = dashboardReducer(emptyState(), ev({
      type: "PhaseEvent", phase: "reporting", event: "start",
      steps: ["a", "b", "c"], step_intents: ["", "", ""],
    }));
    s = dashboardReducer(s, ev({ type: "StepEvent", name: "a", phase: "reporting", event: "complete" }));
    // b、c 未发 step 事件
    s = dashboardReducer(s, ev({ type: "scan_end", category: "CONTROL", status: "failed" }));
    expect(s.unit_status["b"]).toBeUndefined();
    expect(s.unit_status["c"]).toBeUndefined();
    expect(s.completed_units).toBe(1);
    expect(s.total_units).toBe(3);
  });

  it("终态收敛对 emptyState（无 phase_units）无副作用", () => {
    const s = dashboardReducer(emptyState(), ev({ type: "SummaryEvent", category: "SUMMARY", status: "completed" }));
    expect(s.total_units).toBe(0);
    expect(s.completed_units).toBe(0);
  });

  // === phase_status（全程阶段轨道 fold，2026-09-09 详情页阶段进度）===
  // PhaseEvent 序列折叠成 name→status（core DashboardState 无此字段，前端扩展——
  // 先例 gitnexus_progress）。渲染侧（ScanPhaseRail）与前端静态计划序（白盒 7 阶段）
  // 合并出「到哪个阶段了」；phase_units 是单阶段步级、每阶段重置，回答不了这个问题。
  it("PhaseEvent start/complete → phase_status 记录（不随下一阶段重置）", () => {
    let s = dashboardReducer(emptyState(), ev({ type: "PhaseEvent", phase: "setup", event: "start" }));
    expect(s.phase_status["setup"]).toBe("running");
    s = dashboardReducer(s, ev({ type: "PhaseEvent", phase: "setup", event: "complete" }));
    expect(s.phase_status["setup"]).toBe("done");
    s = dashboardReducer(s, ev({ type: "PhaseEvent", phase: "pre-recon", event: "start", steps: [], step_intents: [] }));
    expect(s.phase_status["pre-recon"]).toBe("running");
    expect(s.phase_status["setup"]).toBe("done"); // 前序阶段保留
  });

  it("新阶段 start 隐式完成前一 running 阶段（complete 事件丢失兜底）", () => {
    let s = dashboardReducer(emptyState(), ev({ type: "PhaseEvent", phase: "setup", event: "start" }));
    s = dashboardReducer(s, ev({ type: "PhaseEvent", phase: "pre-recon", event: "start" }));
    expect(s.phase_status["setup"]).toBe("done");
  });

  it("同名阶段重启（组合扫描黑盒 reporting 复用白盒阶段名）→ done 重开为 running", () => {
    let s = dashboardReducer(emptyState(), ev({ type: "PhaseEvent", phase: "reporting", event: "start" }));
    s = dashboardReducer(s, ev({ type: "PhaseEvent", phase: "reporting", event: "complete" }));
    s = dashboardReducer(s, ev({ type: "PhaseEvent", phase: "reporting", event: "start" }));
    expect(s.phase_status["reporting"]).toBe("running");
  });

  it("running 中重复 start 同名 → 幂等无副作用", () => {
    let s = dashboardReducer(emptyState(), ev({ type: "PhaseEvent", phase: "recon", event: "start" }));
    s = dashboardReducer(s, ev({ type: "PhaseEvent", phase: "recon", event: "start" }));
    expect(s.phase_status["recon"]).toBe("running");
  });

  it("终态收敛：completed → running 标 done；failed → running 标 failed（保留失败现场，未观察阶段不动）", () => {
    let s = dashboardReducer(emptyState(), ev({ type: "PhaseEvent", phase: "setup", event: "start" }));
    s = dashboardReducer(s, ev({ type: "PhaseEvent", phase: "setup", event: "complete" }));
    s = dashboardReducer(s, ev({ type: "PhaseEvent", phase: "recon", event: "start" }));
    s = dashboardReducer(s, ev({ type: "scan_end", category: "CONTROL", status: "completed" }));
    expect(s.phase_status["recon"]).toBe("done");
    let f = dashboardReducer(emptyState(), ev({ type: "PhaseEvent", phase: "recon", event: "start" }));
    f = dashboardReducer(f, ev({ type: "scan_end", category: "CONTROL", status: "failed" }));
    expect(f.phase_status["recon"]).toBe("failed");
  });

  // 2026-09-09 中断体感修复：心跳丢失/orphan 写 scan_end(interrupted)、用户取消写
  // (cancelled)——此前两者不在收敛名单，phase_status 永停 running → 阶段轨道 spinner
  // 永转（recon 转圈让用户以为还在跑）。非自然中止 ≠ 失败（不盗 ✗红）≠ 完成：收敛为
  // halted（渲染层 ‖ 黄，见 ScanPhaseRail）。end_status 记录终态供呈现层重解释
  // running agent/分段条（ScanProgressOverview）。
  it("终态收敛：interrupted/cancelled → running 阶段标 halted + end_status 记录", () => {
    let s = dashboardReducer(emptyState(), ev({ type: "PhaseEvent", phase: "pre-recon", event: "start" }));
    s = dashboardReducer(s, ev({ type: "PhaseEvent", phase: "pre-recon", event: "complete" }));
    s = dashboardReducer(s, ev({ type: "PhaseEvent", phase: "recon", event: "start" }));
    expect(s.end_status).toBeNull();
    s = dashboardReducer(s, ev({ type: "scan_end", category: "CONTROL", status: "interrupted" }));
    expect(s.phase_status["recon"]).toBe("halted");
    expect(s.phase_status["pre-recon"]).toBe("done"); // 已完成阶段不粉饰
    expect(s.end_status).toBe("interrupted");
    // 用户取消同语义
    let c = dashboardReducer(emptyState(), ev({ type: "PhaseEvent", phase: "exploitation", event: "start" }));
    c = dashboardReducer(c, ev({ type: "scan_end", category: "CONTROL", status: "cancelled" }));
    expect(c.phase_status["exploitation"]).toBe("halted");
    expect(c.end_status).toBe("cancelled");
  });

  it("end_status：SummaryEvent 同样记录；无终态事件保持 null", () => {
    let s = dashboardReducer(emptyState(), ev({ type: "PhaseEvent", phase: "recon", event: "start" }));
    expect(s.end_status).toBeNull();
    s = dashboardReducer(s, ev({ type: "SummaryEvent", category: "SUMMARY", status: "completed" }));
    expect(s.end_status).toBe("completed");
  });

  it("end_status 续跑复位：终态后新 PhaseEvent start → null（running agent 不被误判中止）", () => {
    let s = dashboardReducer(emptyState(), ev({ type: "PhaseEvent", phase: "recon", event: "start" }));
    s = dashboardReducer(s, ev({ type: "AgentEvent", agent_name: "recon", event: "start" }));
    s = dashboardReducer(s, ev({ type: "scan_end", category: "CONTROL", status: "interrupted" }));
    expect(s.end_status).toBe("interrupted");
    // 归并流全量重放：上一 run 终态事件之后跟续跑 run 的 PhaseEvent start
    s = dashboardReducer(s, ev({ type: "PhaseEvent", phase: "recon", event: "start" }));
    expect(s.end_status).toBeNull();
    expect(s.phase_status["recon"]).toBe("running"); // halted 重开为 running
  });

  it("ResumeEvent → resumed_completed 累积合并（多次续跑去重）", () => {
    let s = dashboardReducer(emptyState(), ev({
      type: "ResumeEvent", category: "RESUME", previous_workflow_id: "x",
      new_workflow_id: "y", checkpoint_hash: "h", completed_agents: ["pre-recon", "recon"],
    }));
    expect(s.resumed_completed).toEqual(["pre-recon", "recon"]);
    s = dashboardReducer(s, ev({
      type: "ResumeEvent", category: "RESUME", previous_workflow_id: "y",
      new_workflow_id: "z", checkpoint_hash: "h", completed_agents: ["recon", "injection-vuln"],
    }));
    expect(s.resumed_completed).toEqual(["pre-recon", "recon", "injection-vuln"]);
  });
});

// === correlation_progress（跨仓关联主行编排事件，D6，spec 2026-08-24）===
// 事件源：web CorrelationEventWriter（scan_manager 三段接力编排写主行 events.ndjson），
// shape（correlation_event_writer.py）：{type:"correlation_progress", category:"CONTROL",
// node:"repo"|"phase"|"edge", name, status:"started"|"completed"|"failed", detail?}。
// 段序：repo(started→completed|failed)×N → phase("correlation",started) →
// edge("from->to",…)×M → phase("correlation",completed) → scan_end。
// 前端映射（core DashboardState.apply 走 default 忽略——此类事件只在 web 编排层产生，
// core 端无此流；前端把 repo/edge 行累积进 phase_units 网格 + 状态徽标供进度条渲染）。
describe("dashboardReducer — correlation_progress 事件", () => {
  const corr = (
    node: "repo" | "phase" | "edge",
    name: string,
    status: "started" | "completed" | "failed",
    detail?: string,
  ) => ev({ type: "correlation_progress", category: "CONTROL", node, name, status, detail });

  it("repo 事件：追加网格行 + 状态映射 started→running / completed→done / failed→failed", () => {
    let s = dashboardReducer(emptyState(), corr("repo", "frontend", "started"));
    expect(s.phase_units).toEqual(["frontend"]);
    expect(s.unit_status["frontend"]).toBe("running");
    expect(s.total_units).toBe(1);
    expect(s.running_units).toEqual(["frontend"]);
    s = dashboardReducer(s, corr("repo", "frontend", "completed"));
    expect(s.unit_status["frontend"]).toBe("done");
    expect(s.completed_units).toBe(1);
    s = dashboardReducer(s, corr("repo", "order-svc", "started"));
    s = dashboardReducer(s, corr("repo", "order-svc", "failed", "scan error"));
    expect(s.phase_units).toEqual(["frontend", "order-svc"]); // 事件序 = 展示序
    expect(s.unit_status["order-svc"]).toBe("failed");
    expect(s.unit_intent["order-svc"]).toBe("scan error");
    expect(s.completed_units).toBe(2); // done + failed 都是终态
  });

  it("repo completed + detail=reused（提交即复用）：直接 done 行 + intent 标注", () => {
    const s = dashboardReducer(emptyState(), corr("repo", "users", "completed", "reused"));
    expect(s.phase_units).toEqual(["users"]);
    expect(s.unit_status["users"]).toBe("done");
    expect(s.unit_intent["users"]).toBe("reused");
    expect(s.completed_units).toBe(1);
  });

  it("phase 事件：设 current_phase；start 不清既有 repo 行（三段接力累积网格）", () => {
    let s = dashboardReducer(emptyState(), corr("repo", "frontend", "completed"));
    s = dashboardReducer(s, corr("phase", "correlation", "started"));
    expect(s.current_phase).toBe("correlation");
    expect(s.phase_units).toEqual(["frontend"]); // 与 PhaseEvent 不同：不重置
    expect(s.unit_status["frontend"]).toBe("done");
  });

  it("phase completed：current_phase 保持（对齐 PhaseEvent complete 语义）", () => {
    let s = dashboardReducer(emptyState(), corr("phase", "correlation", "started"));
    s = dashboardReducer(s, corr("phase", "correlation", "completed"));
    expect(s.current_phase).toBe("correlation");
  });

  it("edge 事件（name=from->to）：与 repo 行同网格追加（writer 已把 ok/low/error 归一）", () => {
    let s = dashboardReducer(emptyState(), corr("repo", "frontend", "completed"));
    s = dashboardReducer(s, corr("phase", "correlation", "started"));
    s = dashboardReducer(s, corr("edge", "frontend->order-svc", "completed", "raw=ok"));
    s = dashboardReducer(s, corr("edge", "frontend->users", "failed", "raw=low"));
    expect(s.phase_units).toEqual(["frontend", "frontend->order-svc", "frontend->users"]);
    expect(s.unit_status["frontend->order-svc"]).toBe("done");
    expect(s.unit_status["frontend->users"]).toBe("failed");
    expect(s.total_units).toBe(3);
    expect(s.completed_units).toBe(3); // done + done + failed 全终态
  });

  it("scan_end completed：未完结的 repo/edge 行终态收敛 done（复用既有收敛行为）", () => {
    let s = dashboardReducer(emptyState(), corr("repo", "frontend", "completed"));
    s = dashboardReducer(s, corr("phase", "correlation", "started"));
    s = dashboardReducer(s, corr("edge", "frontend->order-svc", "started"));
    expect(s.completed_units).toBe(1);
    s = dashboardReducer(s, ev({ type: "scan_end", category: "CONTROL", status: "completed" }));
    expect(s.unit_status["frontend->order-svc"]).toBe("done");
    expect(s.completed_units).toBe(2);
    expect(s.total_units).toBe(2);
  });

  it("PhaseEvent start（段③黑盒 run 事件经归并流混入）：重置网格——常规 workflow 语义优先", () => {
    let s = dashboardReducer(emptyState(), corr("repo", "frontend", "completed"));
    s = dashboardReducer(s, corr("edge", "frontend->order-svc", "completed"));
    s = dashboardReducer(s, ev({
      type: "PhaseEvent", category: "PHASE", phase: "recon", event: "start",
      steps: ["recon"], step_intents: [""],
    }));
    expect(s.phase_units).toEqual(["recon"]);
    expect(s.current_phase).toBe("recon");
  });

  // ── 2026-09-20 跨仓 live 阶段透传：node=phase 写 phase_status（阶段轨可点亮）──
  it("phase started/completed：写 phase_status；started 把其余 running 阶段隐式收 done", () => {
    let s = dashboardReducer(emptyState(), corr("phase", "repo-scan", "started"));
    expect(s.phase_status["repo-scan"]).toBe("running");
    s = dashboardReducer(s, corr("phase", "correlation", "started"));
    expect(s.phase_status["repo-scan"]).toBe("done"); // 下一阶段 start = 前序完结兜底
    expect(s.phase_status["correlation"]).toBe("running");
    s = dashboardReducer(s, corr("phase", "correlation", "completed"));
    expect(s.phase_status["correlation"]).toBe("done");
  });

  it("phase failed：phase_status 标 failed（停在出事阶段）", () => {
    const s = dashboardReducer(emptyState(), corr("phase", "correlation", "failed"));
    expect(s.phase_status["correlation"]).toBe("failed");
  });

  it("repo started/completed：点亮 phase_status[repo-scan]=running（旧事件流回放兼容）", () => {
    // 无编排 phase("repo-scan") 事件的历史流：首个 repo 行出现即段① running；
    // 收 done 走 node=phase started 兜底（correlation start 隐式收前序）。
    let s = dashboardReducer(emptyState(), corr("repo", "frontend", "started"));
    expect(s.phase_status["repo-scan"]).toBe("running");
    s = dashboardReducer(s, corr("phase", "correlation", "started"));
    expect(s.phase_status["repo-scan"]).toBe("done");
    // reused-only：repo completed 直发（无 started）同样点亮
    let r = dashboardReducer(emptyState(), corr("repo", "users", "completed", "reused"));
    expect(r.phase_status["repo-scan"]).toBe("running");
  });

  // ── 2026-09-20 子仓源（src=c-*）分流：阶段透传进 repo 行，其余全忽略 ──
  it("子仓源 PhaseEvent：阶段写进 repo 行 unit_intent[service]，不动主网格/current_phase/phase_status", () => {
    let s = dashboardReducer(emptyState(), corr("repo", "frontend", "started"));
    s = dashboardReducer(s, corr("repo", "order-svc", "started"));
    s = dashboardReducer(s, ev({
      type: "PhaseEvent", category: "PHASE", phase: "recon", event: "start",
      src: "c-os-456", service: "order-svc",
    }));
    expect(s.current_phase).toBeNull(); // 不冒充主行阶段
    expect(s.phase_units).toEqual(["frontend", "order-svc"]); // 网格不重置
    expect(s.unit_status).toEqual({ frontend: "running", "order-svc": "running" });
    expect(s.unit_intent["order-svc"]).toBe("recon"); // 子仓当前阶段进行 detail
    expect(s.phase_status).toEqual({ "repo-scan": "running" }); // 不写子仓阶段
    // 阶段推进覆盖 detail（最新阶段名）
    s = dashboardReducer(s, ev({
      type: "PhaseEvent", category: "PHASE", phase: "vulnerability-analysis", event: "start",
      src: "c-os-456", service: "order-svc",
    }));
    expect(s.unit_intent["order-svc"]).toBe("vulnerability-analysis");
  });

  it("子仓源其余事件全忽略：AgentEvent 不进 agents、scan_end 不污染主行 end_status", () => {
    let s = dashboardReducer(emptyState(), corr("repo", "frontend", "started"));
    s = dashboardReducer(s, ev({
      type: "AgentEvent", category: "AGENT", agent_name: "vuln-injection",
      event: "start", attempt: 1, src: "c-gw-123", service: "gateway",
    }));
    expect(s.agents).toEqual({}); // 子仓 agent 归子行详情页
    s = dashboardReducer(s, ev({
      type: "scan_end", category: "CONTROL", status: "completed",
      src: "c-gw-123", service: "gateway",
    }));
    expect(s.end_status).toBeNull(); // 子仓终态不是主行终态
    expect(s.unit_status["frontend"]).toBe("running"); // 收敛也不发生
  });
});

describe("formatters — 对齐 core formatters.py", () => {
  it("firstNonemptyLine: first non-blank stripped line", () => {
    expect(firstNonemptyLine("\n\nAnalyzing sinks...\n")).toBe("Analyzing sinks...");
    expect(firstNonemptyLine("   \n\n  ")).toBe("");
    expect(firstNonemptyLine(null)).toBe("");
    expect(firstNonemptyLine(undefined)).toBe("");
  });

  it("humanizeToolCall: Bash -> command=key", () => {
    expect(humanizeToolCall("Bash", { command: "rg -n eval" })).toBe("command=rg -n eval");
  });

  it("humanizeToolCall: Bash long command truncated", () => {
    const long = "x".repeat(100);
    const out = humanizeToolCall("Bash", { command: long });
    expect(out.startsWith("command=")).toBe(true);
    expect(out.length).toBeLessThan(100);
    expect(out.endsWith("...")).toBe(true);
  });

  it("humanizeToolCall: Read -> file_path", () => {
    expect(humanizeToolCall("Read", { file_path: "/a/b.ts" })).toBe("file_path=/a/b.ts");
  });

  it("humanizeToolCall: Task -> launching description", () => {
    expect(humanizeToolCall("Task", { description: "deep-analysis" })).toBe("🚀 Launching deep-analysis");
    expect(humanizeToolCall("Task", {})).toBe("🚀 Launching analysis agent");
  });

  it("humanizeToolCall: TodoWrite -> summarize completed/in_progress", () => {
    expect(humanizeToolCall("TodoWrite", { todos: [{ status: "completed", content: "done thing" }] })).toBe("✅ done thing");
    expect(humanizeToolCall("TodoWrite", { todos: [{ status: "in_progress", content: "wip" }] })).toBe("🔄 wip");
    expect(humanizeToolCall("TodoWrite", { todos: [] })).toBe("TodoWrite");
  });

  it("humanizeToolCall: agent-browser navigate -> 🌐 Navigating", () => {
    const out = humanizeToolCall("Bash", { command: "agent-browser --session s1 navigate https://example.com/path" });
    expect(out).toBe("🌐 Navigating to example.com");
  });

  it("humanizeToolCall: playwright-cli click -> 🖱️ Clicking", () => {
    const out = humanizeToolCall("Bash", { command: "playwright-cli -s=abc click #submit" });
    expect(out).toBe("🖱️ Clicking #submit");
  });

  it("humanizeToolCall: unknown tool -> first 2 params", () => {
    expect(humanizeToolCall("Custom", { a: 1, b: 2 })).toBe("a=1, b=2");
    expect(humanizeToolCall("Custom", { a: 1, b: 2, c: 3 })).toBe("a=1, b=2, ...");
  });

  it("humanizeToolCall: non-object params -> safe default", () => {
    expect(humanizeToolCall("Custom", null)).toBe("");
    expect(humanizeToolCall("Custom", "string")).toBe("");
  });
});

// === GitnexusLlmEvent → gitnexus_progress（2026-08-28 实时页 Agent 盲区修复，读侧）===
// 事件源：core workflow_logger.log_gitnexus_progress（chain-verdict 深判每链完成 tick），
// shape（events.py）：{type:"GitnexusLlmEvent", category:"GN-LLM", phase:"chain-verdict",
// kind:"progress"|"hit"|"summary", done, total, hits, detail?}。
// 前端映射（core DashboardState.apply 走 default 忽略——correlation_progress 先例：前端
// 扩展映射）：phase=chain-verdict 的进度计数 fold 成单行聚合（done/total/hits + 最新命中
// detail），供 ScanProgressOverview Popover「GitNexus 深判」行渲染——30+ 个 chain-verdict-*
// 短命 agent 的正确形态是一行聚合而非平铺（写侧补 start 后 running 明细另有芯片区）。
describe("dashboardReducer — GitnexusLlmEvent 事件", () => {
  const gn = (kind: "progress" | "hit" | "summary" | "note", done: number,
              total: number, hits: number, detail?: string) => ev({
    type: "GitnexusLlmEvent", category: "GN-LLM", phase: "chain-verdict",
    kind, done, total, hits, detail,
  });

  it("chain-verdict hit：fold 成 gitnexus_progress（done/total/hits + 命中 detail）", () => {
    const s = dashboardReducer(emptyState(), gn("hit", 5, 69, 3,
      "XSS-GN-05 vulnerable: source=firstName → sink=render:51"));
    expect(s.gitnexus_progress).toEqual({
      done: 5, total: 69, hits: 3,
      detail: "XSS-GN-05 vulnerable: source=firstName → sink=render:51",
    });
  });

  it("多条事件最新覆盖（计数单调推进）", () => {
    let s = dashboardReducer(emptyState(), gn("progress", 1, 69, 0));
    s = dashboardReducer(s, gn("hit", 5, 69, 3, "XSS-GN-05 vulnerable"));
    s = dashboardReducer(s, gn("summary", 69, 69, 27));
    expect(s.gitnexus_progress).toEqual({
      done: 69, total: 69, hits: 27, detail: "XSS-GN-05 vulnerable",
    });
  });

  it("非 hit 事件不带覆盖 detail（summary 的汇总文本不留作最新命中）", () => {
    let s = dashboardReducer(emptyState(), gn("hit", 5, 69, 3, "XSS-GN-05 hit"));
    s = dashboardReducer(s, gn("progress", 6, 69, 3));
    expect(s.gitnexus_progress?.detail).toBe("XSS-GN-05 hit");
  });

  it("hit 的 detail 缺失/null：保留既有（不清空）", () => {
    let s = dashboardReducer(emptyState(), gn("hit", 5, 69, 3, "XSS-GN-05 hit"));
    s = dashboardReducer(s, gn("hit", 6, 69, 4));
    expect(s.gitnexus_progress?.done).toBe(6);
    expect(s.gitnexus_progress?.detail).toBe("XSS-GN-05 hit");
  });

  it("非 chain-verdict phase（taint-analysis/sink-discovery）忽略——本行只聚合深判", () => {
    const s = dashboardReducer(emptyState(), ev({
      type: "GitnexusLlmEvent", category: "GN-LLM", phase: "taint-analysis",
      kind: "hit", done: 3, total: 10, hits: 1,
    }));
    expect(s.gitnexus_progress).toBeNull();
  });

  it("kind=note 忽略（杂注不推进计数）", () => {
    const s = dashboardReducer(emptyState(), gn("note", 1, 69, 0));
    expect(s.gitnexus_progress).toBeNull();
  });

  it("PhaseEvent start 不清 gitnexus_progress（深判终态跨 phase 保留——晚进页面的读者仍可见）", () => {
    let s = dashboardReducer(emptyState(), gn("summary", 69, 69, 27));
    s = dashboardReducer(s, ev({
      type: "PhaseEvent", category: "PHASE", phase: "reporting", event: "start",
      steps: ["report"], step_intents: [""],
    }));
    expect(s.gitnexus_progress?.done).toBe(69);
  });

  it("缺 done/total/hits 的畸形事件安全回落（不 NaN）", () => {
    const s = dashboardReducer(emptyState(), ev({
      type: "GitnexusLlmEvent", category: "GN-LLM", phase: "chain-verdict", kind: "hit",
    }));
    expect(s.gitnexus_progress).toEqual({ done: 0, total: 0, hits: 0, detail: null });
  });
});
