import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { MemoryRouter, Routes, Route, Outlet } from "react-router-dom";
import i18n from "@/i18n";
import LiveTab from "./LiveTab";

// mock useEventSource 返回受控 events + status（module-level mutable，每 test 改写）；
// lastUrl 捕获本次渲染传入的 SSE URL（断言组合段切流）。
const eventsState: { events: any[]; status: string } = { events: [], status: "open" };
let lastUrl = "";
vi.mock("../../api/useEventSource", () => ({
  useEventSource: (url: string) => { lastUrl = url; return eventsState; },
}));

// scanEventsUrl 等为纯拼 URL（无 IO）；LiveTab 瘦身后不再调 getScan。
vi.mock("../../api/client", async () => {
  const actual = await vi.importActual<typeof import("../../api/client")>("../../api/client");
  return { ...actual };
});

function renderLive() {
  return render(
    <MemoryRouter initialEntries={["/p/ws/scans/scan1/live"]}>
      <Routes><Route path="/p/:workspace/scans/:scanId/live" element={<LiveTab />} /></Routes>
    </MemoryRouter>,
  );
}

// 经 Outlet context 下发组合段信息（复刻 ScanDetail 的下发路径）。
function renderLiveCtx(ctx: Record<string, unknown>) {
  const CtxRoute = () => <Outlet context={ctx} />;
  return render(
    <MemoryRouter initialEntries={["/p/ws/scans/scan1/live"]}>
      <Routes>
        <Route path="/p/:workspace/scans/:scanId" element={<CtxRoute />}>
          <Route path="live" element={<LiveTab />} />
          <Route path="report" element={<div>rp-content</div>} />
          <Route path="correlation" element={<div>corr-content</div>} />
        </Route>
      </Routes>
    </MemoryRouter>,
  );
}

// jsdom navigator.language 默认 en；现有断言依赖中文渲染，逐测试钉回 zh。
beforeEach(() => { i18n.changeLanguage("zh"); eventsState.events = []; eventsState.status = "open"; lastUrl = ""; });

describe("LiveTab", () => {
  it("渲染 LogStream 容器（aria-live）", () => {
    renderLive();
    expect(document.querySelector('[aria-live="polite"]')).toBeInTheDocument();
  });

  it("连接态徽章显示 已连接（status=open）", () => {
    eventsState.status = "open";
    renderLive();
    expect(screen.getByText("已连接")).toBeInTheDocument();
  });

  it("连接态徽章显示 重连中（status=error）", () => {
    eventsState.status = "error";
    renderLive();
    expect(screen.getByText("重连中")).toBeInTheDocument();
  });

  it("scan_end completed 后显示查看报告按钮", () => {
    eventsState.events = [
      { type: "scan_end", status: "completed", ts: "2026-01-01T00:00:00Z", category: "CONTROL" },
    ];
    eventsState.status = "closed";
    renderLive();
    expect(screen.getByRole("button", { name: /查看报告/ })).toBeInTheDocument();
  });

  it("scan_end=interrupted 显失败原因、不显查看报告", () => {
    eventsState.events = [
      { type: "scan_end", status: "interrupted", stderr_tail: "扫描因服务重启被中断", ts: "2026-01-01T00:00:00Z", category: "CONTROL" },
    ];
    eventsState.status = "closed";
    renderLive();
    expect(screen.getByText(/扫描已中断/)).toBeInTheDocument();
    expect(screen.getByText(/扫描因服务重启被中断/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /查看报告/ })).not.toBeInTheDocument();
  });

  it("error + 空 events 显重连/无进度提示", () => {
    eventsState.events = [];
    eventsState.status = "error";
    renderLive();
    expect(screen.getByText(/正在重连实时通道|暂无进度数据/)).toBeInTheDocument();
  });
});

describe("LiveTab 全量归并流（单流，不切段）", () => {
  it("无 context（非组合/单测直挂）→ 归并流 URL 无 rev，无阶段徽章", () => {
    renderLive();
    expect(lastUrl).toBe("/api/workspaces/ws/scans/scan1/events");
    expect(screen.queryByTestId("live-phase-badge")).not.toBeInTheDocument();
  });

  it("组合 bbPhase=running + selectedRun → 仍归并流（带 rev），黑盒阶段徽章", () => {
    renderLiveCtx({ combined: true, bbPhase: "running", selectedRun: "run-1", runsCount: 1 });
    expect(lastUrl).toBe("/api/workspaces/ws/scans/scan1/events?rev=1");
    expect(screen.getByTestId("live-phase-badge")).toHaveTextContent("黑盒 · run-1");
  });

  it("runsCount 变化 → rev 变化（强制重开流：关流后新增 run 仍可续看）", () => {
    renderLiveCtx({ combined: true, bbPhase: "running", selectedRun: "run-2", runsCount: 2 });
    expect(lastUrl).toBe("/api/workspaces/ws/scans/scan1/events?rev=2");
  });

  it("组合 bbPhase=precheck（认证/白盒段）→ 归并流 + 白盒阶段徽章", () => {
    renderLiveCtx({ combined: true, bbPhase: "precheck", selectedRun: "run-1", runsCount: 1 });
    expect(lastUrl).toBe("/api/workspaces/ws/scans/scan1/events?rev=1");
    expect(screen.getByTestId("live-phase-badge")).toHaveTextContent("白盒阶段");
  });

  it("黑盒段 scan_end completed → 查看报告跳选中 run 的报告（?run=）", () => {
    eventsState.events = [
      { type: "scan_end", status: "completed", ts: "2026-01-01T00:00:00Z", category: "CONTROL" },
    ];
    eventsState.status = "closed";
    renderLiveCtx({ combined: true, bbPhase: "running", selectedRun: "run-1" });
    fireEvent.click(screen.getByRole("button", { name: /查看报告/ }));
    expect(screen.getByText("rp-content")).toBeInTheDocument();
  });
});

// === correlation 主行 live（2026-09-10）：段②编排 + 段③黑盒验证共用归并流 ===
describe("LiveTab correlation 主行", () => {
  it("scanType=correlation + scan_end completed → 查看关联结果跳 correlation tab", () => {
    eventsState.events = [
      { type: "scan_end", status: "completed", ts: "2026-01-01T00:00:00Z", category: "CONTROL" },
    ];
    eventsState.status = "closed";
    renderLiveCtx({ scanType: "correlation" });
    fireEvent.click(screen.getByRole("button", { name: /查看关联结果/ }));
    expect(screen.getByText("corr-content")).toBeInTheDocument();
  });

  it("scanType=correlation + scan_end failed → 失败横幅照常，无跳转按钮", () => {
    eventsState.events = [
      { type: "scan_end", status: "failed", stderr_tail: "edge 推断异常", ts: "2026-01-01T00:00:00Z", category: "CONTROL" },
    ];
    eventsState.status = "closed";
    renderLiveCtx({ scanType: "correlation" });
    expect(screen.getByText(/扫描失败/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /查看关联结果/ })).not.toBeInTheDocument();
  });
});

describe("LiveTab i18n", () => {
  afterEach(() => i18n.changeLanguage("zh"));

  it("切英文后连接态徽章变 Connected", async () => {
    eventsState.events = [];
    eventsState.status = "open";
    renderLive();
    expect(screen.getByText("已连接")).toBeInTheDocument();
    await i18n.changeLanguage("en");
    expect(await screen.findByText("Connected")).toBeInTheDocument();
  });

  it("切英文后 scan_end completed 显示 View report 按钮", async () => {
    eventsState.events = [
      { type: "scan_end", status: "completed", ts: "2026-01-01T00:00:00Z", category: "CONTROL" },
    ];
    eventsState.status = "closed";
    renderLive();
    expect(screen.getByRole("button", { name: /查看报告/ })).toBeInTheDocument();
    await i18n.changeLanguage("en");
    expect(await screen.findByRole("button", { name: /View report/ })).toBeInTheDocument();
  });

  it("切英文后 scan_end interrupted 显示 Scan interrupted", async () => {
    eventsState.events = [
      { type: "scan_end", status: "interrupted", stderr_tail: "扫描因服务重启被中断", ts: "2026-01-01T00:00:00Z", category: "CONTROL" },
    ];
    eventsState.status = "closed";
    renderLive();
    expect(screen.getByText(/扫描已中断/)).toBeInTheDocument();
    await i18n.changeLanguage("en");
    expect(await screen.findByText(/Scan interrupted/)).toBeInTheDocument();
    // stderr_tail 是事件流数据，不随语言变化
    expect(screen.getByText(/扫描因服务重启被中断/)).toBeInTheDocument();
  });
});
