import { describe, it, expect, afterEach } from "vitest";
import { render, screen } from "@testing-library/react";
import i18n from "@/i18n";
import { DashboardPanel } from "./DashboardPanel";
import { emptyState } from "../state/dashboardReducer";
import type { DashboardState } from "../state/dashboardReducer";

const state: DashboardState = {
  current_phase: "vulnerability-analysis", agents: {}, phase_units: ["Injection", "Xss"],
  unit_status: { Injection: "done", Xss: "running" }, unit_intent: {},
  phase_status: {}, resumed_completed: [],
  gitnexus_progress: null,
  completed_count: 1, total_cost: 0.5, total_units: 2, completed_units: 1, running_units: ["Xss"],
};
(state as any).agents = {
  Xss: { name: "Xss", status: "running", attempt: 1, turn: 2, last_action: "Bash", last_action_detail: "Bash grep", last_turn_text: "scanning", duration_ms: null, cost_usd: null, error: null },
};

describe("DashboardPanel", () => {
  it("状态条：phase + step N/M + elapsed + cost", () => {
    render(<DashboardPanel state={state} elapsedMs={134000} />);
    expect(screen.getByText(/vulnerability-analysis/)).toBeInTheDocument();
    expect(screen.getByText(/1\/2/)).toBeInTheDocument();       // completed/total units
    expect(screen.getByText(/2m 14s/)).toBeInTheDocument();       // 134000ms → 2m 14s
    expect(screen.getByText(/\$0\.50/)).toBeInTheDocument();
  });
  it("运行中 agent 行：spinner + name + turn + last_action", () => {
    const { container } = render(<DashboardPanel state={state} elapsedMs={0} />);
    expect(container.querySelector(".supernova-spinner")).toBeInTheDocument();
    // Xss 现在既作为 phase_units 单元名出现，也作为运行中 agent 名出现
    expect(screen.getAllByText(/Xss/).length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText(/t2/)).toBeInTheDocument();
    expect(screen.getByText(/Bash grep/)).toBeInTheDocument();
  });

  it("渲染 step 进度与 intent（unit_status 三态 + unit_intent 文案）", () => {
    const intentState = {
      ...emptyState(),
      current_phase: "vuln",
      phase_units: ["injection"],
      unit_status: { injection: "running" },
      unit_intent: { injection: "SQLi 候选识别" },
      completed_units: 0,
      total_units: 1,
      running_units: ["injection"],
    } as DashboardState;
    render(<DashboardPanel state={intentState} elapsedMs={0} />);
    // intent 文案渲染（unique 文本，可直接 getByText）
    expect(screen.getByText(/SQLi 候选识别/)).toBeInTheDocument();
    // unit 名称渲染
    expect(screen.getByText(/^injection$/)).toBeInTheDocument();
  });

  it("Agent 计数：agents 非空显 N/M；空时隐藏（不再显 Agent 0/0）", () => {
    // 非空：2 agents, completed_count=1 → "Agent 1/2"
    const withAgents = {
      ...emptyState(),
      current_phase: "recon",
      phase_units: ["discover"],
      unit_status: {},
      unit_intent: {},
      completed_count: 1,
      total_cost: 0,
      completed_units: 0,
      total_units: 1,
    } as DashboardState;
    (withAgents as any).agents = {
      "pre-recon": { name: "pre-recon", status: "done", attempt: 1, turn: 0, last_action: null, last_action_detail: null, last_turn_text: null, duration_ms: null, cost_usd: null, error: null },
      recon: { name: "recon", status: "running", attempt: 1, turn: 0, last_action: null, last_action_detail: null, last_turn_text: null, duration_ms: null, cost_usd: null, error: null },
    };
    const { rerender } = render(<DashboardPanel state={withAgents} elapsedMs={0} />);
    expect(screen.getByText(/Agent\s+1\/2/)).toBeInTheDocument();
    // 空 agents：Agent 计数整段隐藏，不再显 "Agent 0/0"
    rerender(<DashboardPanel state={emptyState()} elapsedMs={0} />);
    expect(screen.queryByText(/Agent\s+0\/0/)).not.toBeInTheDocument();
  });

  it("进度 0/0 隐藏：total_units=0 时不显进度（仅显事件计数）", () => {
    // emptyState: total_units=0, agents={} → 进度与 Agent 都不显，只剩事件
    render(<DashboardPanel state={emptyState()} elapsedMs={0} eventsCount={5} />);
    // 不显 "进度 0/0"（progress 文案 + 0/0）
    expect(screen.queryByText(/0\/0/)).not.toBeInTheDocument();
    // 事件计数仍显
    expect(screen.getByText(/5/)).toBeInTheDocument();
  });

  describe("i18n: 「无运行中 agent」文案已移除", () => {
    afterEach(() => i18n.changeLanguage("zh"));

    it("中文：无 running agent 时不显该文案", () => {
      i18n.changeLanguage("zh");
      render(<DashboardPanel state={emptyState()} elapsedMs={0} />);
      expect(screen.queryByText(/无运行中 agent/)).not.toBeInTheDocument();
    });

    it("英文：不显 No running agents", () => {
      i18n.changeLanguage("en");
      render(<DashboardPanel state={emptyState()} elapsedMs={0} />);
      expect(screen.queryByText(/No running agents/)).not.toBeInTheDocument();
    });
  });

  // ── 问题 2：开始时间 / 总耗时 / 阶段耗时 / SSE 实时性指示 ──
  describe("扩展展示：开始时间 / 总耗时 / 实时性", () => {
    afterEach(() => i18n.changeLanguage("zh"));

    it("传 startedAtMs 渲染开始时间（含年份，非 -）", () => {
      const startedAtMs = Date.UTC(2026, 7, 4, 2, 49, 10);
      render(<DashboardPanel state={emptyState()} elapsedMs={0} startedAtMs={startedAtMs} />);
      expect(screen.getByText(/开始时间/)).toBeInTheDocument();
      expect(screen.getByText(/2026/)).toBeInTheDocument();
    });

    it("未传 startedAtMs 时不渲染开始时间区块", () => {
      render(<DashboardPanel state={emptyState()} elapsedMs={0} />);
      expect(screen.queryByText(/开始时间/)).not.toBeInTheDocument();
    });

    it("传 totalElapsedMs 渲染总耗时（与阶段耗时区分）", () => {
      render(
        <DashboardPanel
          state={emptyState()} elapsedMs={5000} totalElapsedMs={3600000}
        />,
      );
      // 阶段耗时 5000ms -> 5s；总耗时 3600000ms -> 1h 00m 00s
      expect(screen.getByText(/5s/)).toBeInTheDocument();
      expect(screen.getByText(/1h 00m 00s/)).toBeInTheDocument();
    });

    it("fmtMs 负数兜底为 0s（防御跨时钟残差，不显 -Xs）", () => {
      render(
        <DashboardPanel
          state={emptyState()} elapsedMs={-1000} totalElapsedMs={-70000}
        />,
      );
      // 两路负值都夹紧到 0s，不出现负数耗时串
      // /^-\d/ 排除 current_phase 占位 "-"（null → "-"），只匹配 "-1s" 这类负数耗时
      expect(screen.queryAllByText(/^-\d/)).toEqual([]);
      expect(screen.getAllByText(/^0s$/).length).toBe(2);
    });

    it("SSE 实时性：最后事件秒前 + 事件计数", () => {
      const lastEventMs = Date.now() - 3000; // 3 秒前
      render(
        <DashboardPanel
          state={emptyState()} elapsedMs={0}
          lastEventMs={lastEventMs} eventsCount={42}
        />,
      );
      // 最后事件 3 秒前
      expect(screen.getByText(/3\s*秒前|3s ago/)).toBeInTheDocument();
      // 事件计数
      expect(screen.getByText(/42/)).toBeInTheDocument();
    });

    it("无 lastEventMs 时实时性降级（不显秒前，仅可能显计数）", () => {
      render(
        <DashboardPanel state={emptyState()} elapsedMs={0} eventsCount={0} />,
      );
      // 无 lastEventMs -> 无「秒前」文案
      expect(screen.queryByText(/秒前|s ago/)).not.toBeInTheDocument();
    });

    it("切英文 label", () => {
      i18n.changeLanguage("en");
      const startedAtMs = Date.UTC(2026, 7, 4, 2, 49, 10);
      render(
        <DashboardPanel
          state={emptyState()} elapsedMs={5000} totalElapsedMs={3600000}
          startedAtMs={startedAtMs}
        />,
      );
      expect(screen.getByText(/Started|Start time/i)).toBeInTheDocument();
      expect(screen.getByText(/Total|Total time/i)).toBeInTheDocument();
    });
  });
});
