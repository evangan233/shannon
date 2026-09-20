import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import i18n from "@/i18n";
import { ScanProgressOverview } from "./ScanProgressOverview";

// === mergedScanEventsUrl 纯函数（全量归并流：认证/白盒/黑盒 run-K 单一 URL）===
describe("mergedScanEventsUrl", () => {
  const base = "/api/workspaces/ws1/scans/scan1/events";
  it("无 rev → 裸归并流 URL", async () => {
    const { mergedScanEventsUrl } = await import("@/api/client");
    expect(mergedScanEventsUrl("ws1", "scan1")).toBe(base);
  });
  it("有 rev → ?rev= 后缀（run 数变化强制重开流）", async () => {
    const { mergedScanEventsUrl } = await import("@/api/client");
    expect(mergedScanEventsUrl("ws1", "scan1", 2)).toBe(`${base}?rev=2`);
  });
  it("isBlackboxSegmentActive 仅作阶段徽章判定（不再决定流 URL）", async () => {
    const { isBlackboxSegmentActive } = await import("@/api/client");
    expect(isBlackboxSegmentActive({ combined: true, bbPhase: "running", selectedRun: "run-1" })).toBe(true);
    expect(isBlackboxSegmentActive({ combined: true, bbPhase: "precheck", selectedRun: "run-1" })).toBe(false);
    expect(isBlackboxSegmentActive({ combined: false, bbPhase: "running", selectedRun: "run-1" })).toBe(false);
  });
});

// === ScanProgressOverview 组件 ===
const eventsState: { events: any[]; status: string } = { events: [], status: "open" };
vi.mock("@/api/useEventSource", () => ({ useEventSource: () => eventsState }));

const TS = "2026-08-14T00:00:00.000Z";
function phaseStart(phase: string, steps: string[] = [], intents: string[] = []) {
  return { ts: TS, category: "PHASE", type: "PhaseEvent", phase, event: "start", steps, step_intents: intents };
}
function stepComplete(name: string, phase: string, error?: string) {
  return { ts: TS, category: "STEP", type: "StepEvent", name, phase, event: "complete", error };
}
function agentStart(name: string) {
  return { ts: TS, category: "AGENT", type: "AgentEvent", agent_name: name, event: "start", attempt: 1 };
}
function toolCall(agent: string, tool: string, parameters: Record<string, unknown> = {}) {
  return { ts: TS, category: "TOOL", type: "ToolCallEvent", agent_name: agent, tool_name: tool, parameters };
}
function gnEvent(kind: "progress" | "hit" | "summary", done: number, total: number, hits: number, detail?: string) {
  return { ts: TS, category: "GN-LLM", type: "GitnexusLlmEvent", phase: "chain-verdict", kind, done, total, hits, detail };
}

beforeEach(() => { i18n.changeLanguage("zh"); eventsState.events = []; eventsState.status = "open"; });

describe("ScanProgressOverview", () => {
  it("渲染当前阶段（PhaseEvent fold → current_phase）", () => {
    eventsState.events = [phaseStart("recon")];
    render(<ScanProgressOverview ws="ws" scanId="s1" />);
    expect(screen.getByText("recon")).toBeInTheDocument();
  });

  it("进度条分段渲染 phase_units（含状态），步级明细在 Popover 内", () => {
    eventsState.events = [
      phaseStart("recon", ["pre-recon", "route-map"], ["侦察", "路由图"]),
      stepComplete("pre-recon", "recon"),
    ];
    render(<ScanProgressOverview ws="ws" scanId="s1" />);
    // 常驻态：分段进度条（不展开列表）
    const strip = screen.getByTestId("progress-strip");
    const segs = strip.querySelectorAll("[data-unit]");
    expect(segs).toHaveLength(2);
    expect(strip.querySelector('[data-unit="pre-recon"]')).toHaveAttribute("data-status", "done");
    expect(strip.querySelector('[data-unit="route-map"]')).toHaveAttribute("data-status", "pending");
    expect(screen.queryByText("route-map")).not.toBeInTheDocument();
    // 点 chevron 打开浮层 → 完整步级列表（名 + intent）
    fireEvent.click(screen.getByTestId("progress-details-trigger"));
    expect(screen.getByText("route-map")).toBeInTheDocument();
    expect(screen.getByText("- 路由图")).toBeInTheDocument();
  });

  it("中断（scan_end interrupted）→ 转圈换 ‖ 黄：agent 芯片/Popover 行不再 spinner，running 分段静止黄", () => {
    // 现场复刻 chatbot-20260909-030342：recon agent 无 end 事件停 running，spinner 永转
    eventsState.events = [
      phaseStart("recon", ["route-map", "deep-recon"]),
      { ts: TS, category: "STEP", type: "StepEvent", name: "route-map", phase: "recon", event: "start" },
      agentStart("recon-agent"),
      toolCall("recon-agent", "Task", { description: "auth analysis" }),
      { ts: TS, category: "CONTROL", type: "scan_end", status: "interrupted" },
    ];
    render(<ScanProgressOverview ws="ws" scanId="s1" />);
    // 主行芯片仍在（最后现场）但 spinner → ‖ 黄（不再假装在跑）
    const chips = screen.getByTestId("progress-agents");
    expect(chips.querySelector(".supernova-spinner")).toBeNull();
    expect(chips.textContent).toContain("‖");
    expect(chips.querySelector(".text-yellow")).not.toBeNull();
    // running 分段重解释 halted：静止黄段（不 pulse）
    const seg = screen.getByTestId("progress-strip").querySelector('[data-unit="route-map"]');
    expect(seg).toHaveAttribute("data-status", "halted");
    expect(seg!.className).not.toContain("animate-pulse");
    // Popover 内 agent 行同样 ‖ 非 spinner；步级 ○ → ‖
    fireEvent.click(screen.getByTestId("progress-details-trigger"));
    const details = screen.getByTestId("progress-details");
    expect(details.querySelector(".supernova-spinner")).toBeNull();
    expect(details.textContent).toContain("‖");
  });

  it("渲染正在跑的 Agent 芯片，详情在 Popover 内", () => {
    eventsState.events = [
      phaseStart("recon", ["pre-recon"]),
      agentStart("recon-agent"),
      toolCall("recon-agent", "Task", { description: "auth analysis" }),
    ];
    render(<ScanProgressOverview ws="ws" scanId="s1" />);
    // 常驻态：芯片显示 agent 名（spinner + t{turn}）
    expect(screen.getByText(/recon-agent/)).toBeInTheDocument();
    // 浮层内展示工具调用详情
    fireEvent.click(screen.getByTestId("progress-details-trigger"));
    expect(screen.getByTestId("progress-details")).toHaveTextContent("auth analysis");
  });

  it("失败步骤 → ✗N 红色计数 + 分段标红", () => {
    eventsState.events = [
      phaseStart("recon", ["a", "b"]),
      stepComplete("a", "recon", "boom"),
    ];
    render(<ScanProgressOverview ws="ws" scanId="s1" />);
    expect(screen.getByTestId("progress-failed-count")).toHaveTextContent("✗1");
    expect(screen.getByTestId("progress-strip").querySelector('[data-unit="a"]'))
      .toHaveAttribute("data-status", "failed");
  });

  it("连接态 open → 已连接徽章", () => {
    eventsState.status = "open";
    render(<ScanProgressOverview ws="ws" scanId="s1" />);
    expect(screen.getByText("已连接")).toBeInTheDocument();
  });

  it("连接态 error → 重连中徽章", () => {
    eventsState.status = "error";
    render(<ScanProgressOverview ws="ws" scanId="s1" />);
    expect(screen.getByText("重连中")).toBeInTheDocument();
  });

  it("无 events 时不崩（current_phase 占位）", () => {
    eventsState.events = [];
    render(<ScanProgressOverview ws="ws" scanId="s1" />);
    // 组件根始终挂载
    expect(screen.getByTestId("scan-progress-overview")).toBeInTheDocument();
  });

  // === 全程阶段轨道（scanType prop → ScanPhaseRail 第二行）===
  it("scanType=whitebox → 轨道常驻且随 events 更新；缺省 scanType → 不渲染", () => {
    eventsState.events = [
      phaseStart("setup"),
      phaseStart("pre-recon", ["pre-recon"], ["扫描架构"]),
    ];
    const { rerender } = render(<ScanProgressOverview ws="ws" scanId="s1" scanType="whitebox" />);
    const rail = screen.getByTestId("scan-phase-rail");
    expect(rail.querySelector('[data-phase="setup"]')).toHaveAttribute("data-status", "done");
    expect(rail.querySelector('[data-phase="pre-recon"]')).toHaveAttribute("data-status", "running");
    expect(rail.querySelector('[data-phase="reporting"]')).toHaveAttribute("data-status", "pending");
    // 缺省 scanType（既有调用方/测试）→ 轨道不渲染，主行为零变化
    rerender(<ScanProgressOverview ws="ws" scanId="s1" />);
    expect(screen.queryByTestId("scan-phase-rail")).not.toBeInTheDocument();
  });

  // === GitNexus 深判聚合行（2026-08-28 实时页 Agent 盲区修复，读侧）===
  // 30+ 个 chain-verdict-* 短命 agent 的形态是一行聚合（GitnexusLlmEvent fold），
  // 非平铺；running 明细仍走下方 Agent 区（写侧补 start 后自然出现）。
  it("GitnexusLlmEvent → Popover 深判聚合行 + 最新命中摘要", () => {
    eventsState.events = [
      phaseStart("vulnerability-analysis", ["xss-vuln"]),
      agentStart("xss-vuln"),
      gnEvent("hit", 5, 69, 3, "XSS-GN-05 vulnerable: source=firstName → sink=render:51"),
    ];
    render(<ScanProgressOverview ws="ws" scanId="s1" />);
    fireEvent.click(screen.getByTestId("progress-details-trigger"));
    const gn = screen.getByTestId("progress-gn");
    expect(gn).toHaveTextContent("GitNexus 深判");
    expect(gn).toHaveTextContent("5/69");
    expect(gn).toHaveTextContent("命中 3");
    expect(screen.getByTestId("progress-gn-hit")).toHaveTextContent("XSS-GN-05");
  });

  it("无 GitnexusLlmEvent → 深判区不渲染", () => {
    eventsState.events = [phaseStart("recon", ["pre-recon"])];
    render(<ScanProgressOverview ws="ws" scanId="s1" />);
    fireEvent.click(screen.getByTestId("progress-details-trigger"));
    expect(screen.queryByTestId("progress-gn")).not.toBeInTheDocument();
  });

  it("深判有计数但无命中 detail → 只显聚合行（无 hit 摘要行）", () => {
    eventsState.events = [
      phaseStart("vulnerability-analysis", ["xss-vuln"]),
      gnEvent("progress", 6, 69, 0),
    ];
    render(<ScanProgressOverview ws="ws" scanId="s1" />);
    fireEvent.click(screen.getByTestId("progress-details-trigger"));
    expect(screen.getByTestId("progress-gn")).toHaveTextContent("6/69");
    expect(screen.queryByTestId("progress-gn-hit")).not.toBeInTheDocument();
  });
});

// === correlation 子仓源分流（2026-09-20 阶段透传；原 2026-09-10 reduce 前过滤收进 reducer）===
// 归并流把现扫子仓（src=c-<scan_id>）白盒日志也送进来——dashboardReducer 对 c-* 源
// 分流：子仓 PhaseEvent 的阶段名写进 repo 行 detail（网格不被重置语义清掉），其余
// 子仓事件（Agent/终态）忽略。组件全量 fold，不再 reduce 前过滤。
describe("ScanProgressOverview 子仓源分流", () => {
  it("src=c-* 的 PhaseEvent：阶段进 repo 行 detail，不重置网格 / 不冒充主行阶段", () => {
    eventsState.events = [
      { ts: TS, category: "CONTROL", type: "correlation_progress", node: "repo", name: "gateway", status: "completed", src: "wb" },
      { ts: TS, category: "PHASE", type: "PhaseEvent", phase: "precheck", event: "start", src: "c-gw-123", service: "gateway" },
    ];
    render(<ScanProgressOverview ws="ws" scanId="s1" scanType="correlation" />);
    const strip = screen.getByTestId("progress-strip");
    const segs = strip.querySelectorAll("[data-unit]");
    expect(segs).toHaveLength(1);  // 仅 repo 行——子仓 PhaseEvent 没把网格清掉
    expect(strip.querySelector('[data-unit="gateway"]')).toHaveAttribute("data-status", "done");
    // 主行未发 phase 事件：当前阶段槽仍是 "—"（子仓阶段不冒充）
    expect(screen.getByText("—")).toBeInTheDocument();
    // 步级明细（Popover）：repo 行 detail 显示子仓当前阶段
    fireEvent.click(screen.getByTestId("progress-details-trigger"));
    expect(screen.getByText(/- precheck/)).toBeInTheDocument();
  });

  it("src=c-* 的 AgentEvent 不进顶部 Agent 概览（子仓 agent 归子行详情页看）", () => {
    eventsState.events = [
      { ts: TS, category: "AGENT", type: "AgentEvent", agent_name: "vuln-injection", event: "start", attempt: 1, src: "c-gw-123", service: "gateway" },
    ];
    render(<ScanProgressOverview ws="ws" scanId="s1" scanType="correlation" />);
    expect(screen.queryByText(/vuln-injection/)).not.toBeInTheDocument();
  });

  it("src=c-* 的 scan_end 不触发 onScanEnd（子仓终态不是主行终态）", () => {
    eventsState.events = [
      { ts: TS, category: "CONTROL", type: "scan_end", status: "completed", src: "c-gw-123", service: "gateway" },
    ];
    const onScanEnd = vi.fn();
    render(<ScanProgressOverview ws="ws" scanId="s1" scanType="correlation" onScanEnd={onScanEnd} />);
    expect(onScanEnd).not.toHaveBeenCalled();
  });

  it("wb 源 correlation_progress 照常进网格（分流只针对子仓源）", () => {
    eventsState.events = [
      { ts: TS, category: "CONTROL", type: "correlation_progress", node: "edge", name: "gateway->order", status: "running", src: "wb" },
    ];
    render(<ScanProgressOverview ws="ws" scanId="s1" scanType="correlation" />);
    const strip = screen.getByTestId("progress-strip");
    expect(strip.querySelectorAll("[data-unit]")).toHaveLength(1);
    expect(strip.querySelector('[data-unit="gateway->order"]')).toHaveAttribute("data-status", "running");
  });
});
