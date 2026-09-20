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

  it("scan_end interrupted/cancelled → 停在半路阶段标 halted：‖ 符号替代 spinner（2026-09-09 中断体感修复）", () => {
    // 现场复刻 chatbot-20260909-030342：心跳丢失 orphan 写 scan_end(interrupted)，
    // 修复前 phase_status 停 running → recon 转圈永转像还在跑
    const state = foldState([
      ev({ type: "PhaseEvent", phase: "setup", event: "start" }),
      ev({ type: "PhaseEvent", phase: "pre-recon", event: "start" }),
      ev({ type: "PhaseEvent", phase: "recon", event: "start" }),
      ev({ type: "scan_end", category: "CONTROL", status: "interrupted" }),
    ]);
    render(<ScanPhaseRail state={state} scanType="whitebox" />);
    const rail = screen.getByTestId("scan-phase-rail");
    const recon = rail.querySelector('[data-phase="recon"]');
    expect(recon).toHaveAttribute("data-status", "halted");
    expect(recon!.querySelector(".supernova-spinner")).toBeNull(); // 不再转圈
    expect(recon!.textContent).toContain("‖"); // 暂停双竖线
    expect(recon!.querySelector(".text-yellow")).not.toBeNull(); // 与 live 中断横幅同色
    // 已完成阶段不粉饰、后续阶段不虚构
    expect(rail.querySelector('[data-phase="pre-recon"]')).toHaveAttribute("data-status", "done");
    expect(rail.querySelector('[data-phase="risk-scoring"]')).toHaveAttribute("data-status", "pending");
  });

  it("scan_end cancelled → 同 halted 语义（所有阶段通用）", () => {
    const state = foldState([
      ev({ type: "PhaseEvent", phase: "preflight", event: "start" }),
      ev({ type: "scan_end", category: "CONTROL", status: "cancelled" }),
    ]);
    render(<ScanPhaseRail state={state} scanType="blackbox" />);
    const chip = screen.getByTestId("scan-phase-rail").querySelector('[data-phase="preflight"]');
    expect(chip).toHaveAttribute("data-status", "halted");
    expect(chip!.querySelector(".supernova-spinner")).toBeNull();
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

  // === correlation 四节点轨（2026-09-20 跨仓 live 阶段）===
  it("correlation 计划序：repo-scan → correlation → adjudication → blackbox-verify 常驻", () => {
    render(<ScanPhaseRail state={emptyState()} scanType="correlation" />);
    const chips = screen.getByTestId("scan-phase-rail").querySelectorAll("[data-phase]");
    expect(Array.from(chips).map((c) => c.getAttribute("data-phase"))).toEqual([
      "repo-scan", "correlation", "adjudication", "blackbox-verify",
    ]);
    chips.forEach((c) => expect(c).toHaveAttribute("data-status", "pending"));
  });

  it("correlation 三段事件流：repo-scan done（新 phase 事件）/ correlation running / 后续 pending", () => {
    const state = foldState([
      ev({ type: "correlation_progress", category: "CONTROL", node: "repo", name: "frontend", status: "started" }),
      ev({ type: "correlation_progress", category: "CONTROL", node: "phase", name: "repo-scan", status: "completed" }),
      ev({ type: "correlation_progress", category: "CONTROL", node: "phase", name: "correlation", status: "started" }),
    ]);
    render(<ScanPhaseRail state={state} scanType="correlation" />);
    const rail = screen.getByTestId("scan-phase-rail");
    expect(rail.querySelector('[data-phase="repo-scan"]')).toHaveAttribute("data-status", "done");
    expect(rail.querySelector('[data-phase="correlation"]')).toHaveAttribute("data-status", "running");
    expect(rail.querySelector('[data-phase="adjudication"]')).toHaveAttribute("data-status", "pending");
    expect(rail.querySelector('[data-phase="blackbox-verify"]')).toHaveAttribute("data-status", "pending");
  });

  it("旧事件流回放（无 repo-scan phase 事件）：repo 行点亮 + correlation started 兜底收 done", () => {
    const state = foldState([
      ev({ type: "correlation_progress", category: "CONTROL", node: "repo", name: "frontend", status: "completed" }),
      ev({ type: "correlation_progress", category: "CONTROL", node: "phase", name: "correlation", status: "started" }),
    ]);
    render(<ScanPhaseRail state={state} scanType="correlation" />);
    const rail = screen.getByTestId("scan-phase-rail");
    expect(rail.querySelector('[data-phase="repo-scan"]')).toHaveAttribute("data-status", "done");
    expect(rail.querySelector('[data-phase="correlation"]')).toHaveAttribute("data-status", "running");
  });

  it("blackbox-verify 聚合段③ run 观察：有 running → running；全 done → done；无观察 → pending", () => {
    // 段③黑盒 run 的 PhaseEvent（run-K 源不经 c- 过滤）写 phase_status
    const runningState = foldState([
      ev({ type: "PhaseEvent", phase: "preflight", event: "start" }),
      ev({ type: "PhaseEvent", phase: "auth-validation", event: "start" }), // preflight 隐式收 done
    ]);
    const { rerender } = render(<ScanPhaseRail state={runningState} scanType="correlation" />);
    expect(screen.getByTestId("scan-phase-rail").querySelector('[data-phase="blackbox-verify"]'))
      .toHaveAttribute("data-status", "running");

    const allDone = foldState([
      ev({ type: "PhaseEvent", phase: "preflight", event: "start" }),
      ev({ type: "PhaseEvent", phase: "auth-validation", event: "start" }),
      ev({ type: "PhaseEvent", phase: "exploitation", event: "start" }),
      ev({ type: "PhaseEvent", phase: "reporting", event: "start" }),
      ev({ type: "scan_end", category: "CONTROL", status: "completed" }),
    ]);
    rerender(<ScanPhaseRail state={allDone} scanType="correlation" />);
    expect(screen.getByTestId("scan-phase-rail").querySelector('[data-phase="blackbox-verify"]'))
      .toHaveAttribute("data-status", "done");

    rerender(<ScanPhaseRail state={emptyState()} scanType="correlation" />);
    expect(screen.getByTestId("scan-phase-rail").querySelector('[data-phase="blackbox-verify"]'))
      .toHaveAttribute("data-status", "pending");
  });

  it("缺省 scanType → 不渲染（correlation 已开放，缺省保持既有零变化）", () => {
    const { rerender } = render(<ScanPhaseRail state={emptyState()} scanType={undefined} />);
    expect(screen.queryByTestId("scan-phase-rail")).not.toBeInTheDocument();
    rerender(<ScanPhaseRail state={emptyState()} scanType={null} />);
    expect(screen.queryByTestId("scan-phase-rail")).not.toBeInTheDocument();
  });
});
