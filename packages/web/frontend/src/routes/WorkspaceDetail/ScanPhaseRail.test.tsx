import { describe, it, expect, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import i18n from "@/i18n";
import { ScanPhaseRail } from "./ScanPhaseRail";
import { dashboardReducer, emptyState } from "@/state/dashboardReducer";

// === ScanPhaseRail 全程阶段轨道（2026-09-09 详情页阶段进度）===
// 计划序静态持有（whitebox 7 / blackbox 4），状态来自 dashboardReducer 的
// phase_status fold + ResumeEvent 种子（见 dashboardReducer.test 同名段）。
const ev = (e: Record<string, unknown>) =>
  ({ ts: "2026-09-09T00:00:00.000Z", category: "PHASE", ...e }) as never;

function foldState(events: ReturnType<typeof ev>[]) {
  return events.reduce(dashboardReducer, emptyState());
}

beforeEach(() => i18n.changeLanguage("zh"));

describe("ScanPhaseRail", () => {
  it("whitebox 计划序：7 阶段常驻（含未开始），标签「阶段进度」", () => {
    render(<ScanPhaseRail state={emptyState()} scanType="whitebox" />);
    const rail = screen.getByTestId("scan-phase-rail");
    const chips = rail.querySelectorAll("[data-phase]");
    expect(Array.from(chips).map((c) => c.getAttribute("data-phase"))).toEqual([
      "setup", "pre-recon", "recon", "risk-scoring",
      "vulnerability-analysis", "attack-chain", "reporting",
    ]);
    chips.forEach((c) => expect(c).toHaveAttribute("data-status", "pending"));
    expect(screen.getByText("阶段进度")).toBeInTheDocument();
  });

  it("PhaseEvent 序列 → 前 done / 当前 running / 后 pending（隐式完成前一阶段）", () => {
    const state = foldState([
      ev({ type: "PhaseEvent", phase: "setup", event: "start" }),
      ev({ type: "PhaseEvent", phase: "pre-recon", event: "start" }),
    ]);
    render(<ScanPhaseRail state={state} scanType="whitebox" />);
    const rail = screen.getByTestId("scan-phase-rail");
    expect(rail.querySelector('[data-phase="setup"]')).toHaveAttribute("data-status", "done");
    expect(rail.querySelector('[data-phase="pre-recon"]')).toHaveAttribute("data-status", "running");
    expect(rail.querySelector('[data-phase="recon"]')).toHaveAttribute("data-status", "pending");
    expect(rail.querySelector('[data-phase="reporting"]')).toHaveAttribute("data-status", "pending");
  });

  it("running chip 带 spinner（与运行 Agent 芯片同语言）", () => {
    const state = foldState([ev({ type: "PhaseEvent", phase: "recon", event: "start" })]);
    render(<ScanPhaseRail state={state} scanType="whitebox" />);
    const chip = screen.getByTestId("scan-phase-rail").querySelector('[data-phase="recon"]');
    expect(chip).not.toBeNull();
    expect(chip!.querySelector(".supernova-spinner")).not.toBeNull();
  });

  it("scan_end failed → 停在出事阶段标 failed（保留失败现场）", () => {
    const state = foldState([
      ev({ type: "PhaseEvent", phase: "setup", event: "start" }),
      ev({ type: "PhaseEvent", phase: "pre-recon", event: "start" }),
      ev({ type: "scan_end", category: "CONTROL", status: "failed" }),
    ]);
    render(<ScanPhaseRail state={state} scanType="whitebox" />);
    const rail = screen.getByTestId("scan-phase-rail");
    expect(rail.querySelector('[data-phase="setup"]')).toHaveAttribute("data-status", "done");
    expect(rail.querySelector('[data-phase="pre-recon"]')).toHaveAttribute("data-status", "failed");
    expect(rail.querySelector('[data-phase="reporting"]')).toHaveAttribute("data-status", "pending");
  });

  it("Resume 种子：pre-recon/recon 标 done；vuln agent 不映射（vulnerability-analysis 保持 pending）", () => {
    const state = foldState([ev({
      type: "ResumeEvent", category: "RESUME", previous_workflow_id: "x",
      new_workflow_id: "y", checkpoint_hash: "h",
      completed_agents: ["pre-recon", "recon", "injection-vuln"],
    })]);
    render(<ScanPhaseRail state={state} scanType="whitebox" />);
    const rail = screen.getByTestId("scan-phase-rail");
    expect(rail.querySelector('[data-phase="pre-recon"]')).toHaveAttribute("data-status", "done");
    expect(rail.querySelector('[data-phase="recon"]')).toHaveAttribute("data-status", "done");
    expect(rail.querySelector('[data-phase="vulnerability-analysis"]')).toHaveAttribute("data-status", "pending");
  });

  it("blackbox → 黑盒 4 阶段计划", () => {
    render(<ScanPhaseRail state={emptyState()} scanType="blackbox" />);
    const chips = screen.getByTestId("scan-phase-rail").querySelectorAll("[data-phase]");
    expect(Array.from(chips).map((c) => c.getAttribute("data-phase"))).toEqual([
      "preflight", "auth-validation", "exploitation", "reporting",
    ]);
  });

  it("combined → 白盒计划；计划外观察到的黑盒阶段（preflight）不进轨道", () => {
    const state = foldState([ev({ type: "PhaseEvent", phase: "preflight", event: "start" })]);
    render(<ScanPhaseRail state={state} scanType="combined" />);
    const rail = screen.getByTestId("scan-phase-rail");
    const chips = rail.querySelectorAll("[data-phase]");
    expect(chips).toHaveLength(7);
    expect(rail.querySelector('[data-phase="preflight"]')).toBeNull();
  });

  it("correlation / 缺省 scanType → 不渲染", () => {
    const { rerender } = render(<ScanPhaseRail state={emptyState()} scanType="correlation" />);
    expect(screen.queryByTestId("scan-phase-rail")).not.toBeInTheDocument();
    rerender(<ScanPhaseRail state={emptyState()} scanType={undefined} />);
    expect(screen.queryByTestId("scan-phase-rail")).not.toBeInTheDocument();
    rerender(<ScanPhaseRail state={emptyState()} scanType={null} />);
    expect(screen.queryByTestId("scan-phase-rail")).not.toBeInTheDocument();
  });
});
