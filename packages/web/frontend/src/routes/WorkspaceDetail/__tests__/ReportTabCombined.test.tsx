import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach, vi } from "vitest";
import { render, screen, waitFor, fireEvent, cleanup, act } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { SWRConfig } from "swr";
import { setupServer } from "msw/node";
import { http, HttpResponse } from "msw";
import i18n from "@/i18n";
import ScanDetail from "../ScanDetail";
import { ReportTab } from "../ReportTab";
import { DeliverablesTab } from "../DeliverablesTab";
import { downloadTextFile } from "@/lib/download";

// 下载器真测在 lib/download.test.ts；此处 mock 只验组件接线（md + 文件名）。
vi.mock("@/lib/download", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/download")>();
  return { ...actual, downloadTextFile: vi.fn() };
});
beforeEach(() => vi.mocked(downloadTextFile).mockClear());

// toast 隔离（续跑反馈用），避免 sonner 全局副作用。
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn(), info: vi.fn() } }));

// ScanDetail header 的 WorkspaceSwitcher 依赖隔离（对齐 ScanDetail.test.tsx）。
vi.mock("@/auth/AuthContext", () => ({
  useAuth: () => ({
    user: { id: 1, username: "admin", role: "admin", must_change_password: false },
    loading: false, login: vi.fn(), logout: vi.fn(), refreshUser: vi.fn(),
  }),
}));
vi.mock("@/api/useWorkspaces", () => ({
  useWorkspaces: () => ({ data: [], loading: false, lastUpdated: new Date(), error: null, refresh: vi.fn() }),
}));

// === Fake EventSource（详情两段时间线按需拉 events 用）===
class FakeES {
  static last?: FakeES;
  onmessage: ((e: { data: string; lastEventId?: string }) => void) | null = null;
  onerror: (() => void) | null = null;
  onopen: (() => void) | null = null;
  closed = false;
  constructor(public url: string) { FakeES.last = this; }
  emit(data: string) { this.onmessage?.({ data }); }
  close() { this.closed = true; }
}
vi.stubGlobal("EventSource", FakeES);
const lastFakeES = () => FakeES.last;

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
beforeEach(() => { i18n.changeLanguage("zh"); FakeES.last = undefined; });
afterEach(() => { server.resetHandlers(); cleanup(); });
afterAll(() => server.close());

// === Fixtures ===
// 组合扫描详情（getScan payload）：combined=true, bb_phase=running。
const combinedScan = {
  scan_type: "whitebox", status: "running", repo_path: "/root/code",
  workflow_id: "ws-c1", combined: true, bb_phase: "running", progress_pct: 80,
} as const;

// 组合扫描 + 黑盒失败（续跑入口）。
const combinedFailed = {
  scan_type: "whitebox", status: "failed", repo_path: "/root/code",
  workflow_id: "ws-c1", combined: true, bb_phase: "failed", bb_reason: "auth_failed", progress_pct: 70,
} as const;

// ndjson 事件行。
function phaseStart(phase: string, steps: string[]) {
  return JSON.stringify({
    ts: "2026-08-13T00:00:00.000Z", category: "PHASE", type: "PhaseEvent",
    phase, event: "start", steps, step_intents: [],
  });
}
function stepComplete(name: string, phase: string) {
  return JSON.stringify({
    ts: "2026-08-13T00:00:01.000Z", category: "STEP", type: "StepEvent",
    name, phase, event: "complete",
  });
}

function renderDetail(path = "/p/ws/scans/c1/report") {
  return render(
    <SWRConfig value={{ provider: () => new Map() }}>
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/p/:workspace/scans/:scanId" element={<ScanDetail />}>
          <Route path="overview" element={<div>ov</div>} />
          <Route path="report" element={<div>rp</div>} />
          <Route path="deliverables" element={<div>dl</div>} />
        </Route>
      </Routes>
    </MemoryRouter>,
    </SWRConfig>
  );
}

function renderReport() {
  return render(
    <SWRConfig value={{ provider: () => new Map() }}>
    <MemoryRouter initialEntries={["/p/ws/scans/c1/report"]}>
      <Routes>
        <Route path="/p/:workspace/scans/:scanId/report" element={<ReportTab />} />
      </Routes>
    </MemoryRouter>,
    </SWRConfig>
  );
}

function renderDeliverables() {
  return render(
    <SWRConfig value={{ provider: () => new Map() }}>
    <MemoryRouter initialEntries={["/p/ws/scans/c1/deliverables"]}>
      <Routes>
        <Route path="/p/:workspace/scans/:scanId/deliverables" element={<DeliverablesTab />} />
      </Routes>
    </MemoryRouter>,
    </SWRConfig>
  );
}

// =================================================================
// ScanDetail —— 两段时间线
// =================================================================
describe("ScanDetail 组合扫描 - 两段时间线", () => {
  it("combined 渲染「白盒段」+「黑盒段」两个时间段", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId", () => HttpResponse.json(combinedScan)),
    );
    renderDetail();
    await waitFor(() => expect(screen.getByText(/白盒段/)).toBeInTheDocument());
    expect(screen.getByText(/黑盒段/)).toBeInTheDocument();
  });

  it("步级 PhaseEvent 推进顶部概览进度（recon 2/3）", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId", () => HttpResponse.json(combinedScan)),
    );
    renderDetail();
    await waitFor(() => expect(lastFakeES()).toBeDefined());
    act(() => {
      lastFakeES()!.emit(phaseStart("recon", ["pre-recon", "route-map", "summary"]));
      lastFakeES()!.emit(stepComplete("pre-recon", "recon"));
      lastFakeES()!.emit(stepComplete("route-map", "recon"));
    });
    // 步级进度现由顶部 ScanProgressOverview 渲染（completed/total 计数，如「进度 2/3」）
    await waitFor(() => expect(screen.getByText(/2\/3/)).toBeInTheDocument());
  });
});

// =================================================================
// ScanDetail —— 黑盒失败续跑入口
// =================================================================
describe("ScanDetail 组合扫描 - 黑盒失败续跑", () => {
  it("bb_phase=failed 显示「续扫黑盒」按钮", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId", () => HttpResponse.json(combinedFailed)),
    );
    renderDetail();
    expect(await screen.findByRole("button", { name: /续扫黑盒/ })).toBeInTheDocument();
  });

  it("bb_phase=running 不显示续扫按钮", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId", () => HttpResponse.json(combinedScan)),
    );
    renderDetail();
    await waitFor(() => expect(screen.getByText(/黑盒段/)).toBeInTheDocument());
    expect(screen.queryByRole("button", { name: /续扫黑盒/ })).not.toBeInTheDocument();
  });

  it("点续扫 → 确认 → POST rerun-blackbox（无 body，沿用原认证）", async () => {
    const posted = vi.fn();
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId", () => HttpResponse.json(combinedFailed)),
      http.post("/api/workspaces/:ws/scans/:scanId/combined/rerun-blackbox",
        () => {
          // 无新认证：body 应为空（沿用原认证）。
          posted();
          return HttpResponse.json({ workspace: "ws", scan_id: "c1" }, { status: 202 });
        }),
    );
    renderDetail();
    fireEvent.click(await screen.findByRole("button", { name: /续扫黑盒/ }));
    // 确认弹窗
    fireEvent.click(await screen.findByRole("button", { name: /^确认$|确认续扫/ }));
    await waitFor(() => expect(posted).toHaveBeenCalledTimes(1));
  });
});

// =================================================================
// ReportTab —— 三子 tab（白盒 / 黑盒 / 融合）
// =================================================================
describe("ReportTab 组合扫描 - 三子 tab", () => {
  it("combined 渲染「白盒报告 / 黑盒报告 / 融合报告」三个子 tab", async () => {
    const fetched: string[] = [];
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId", () => HttpResponse.json(combinedScan)),
      http.get("/api/workspaces/:ws/scans/:scanId/report", ({ request }) => {
        const track = new URL(request.url).searchParams.get("track") ?? "whitebox";
        fetched.push(track);
        const body = track === "combined" ? "# 融合报告" : track === "blackbox" ? "# 黑盒报告" : "# 白盒报告";
        return new HttpResponse(body, { headers: { "content-type": "text/plain" } });
      }),
    );
    renderReport();
    expect(await screen.findByRole("tab", { name: /白盒报告/ })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /黑盒报告/ })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /融合报告/ })).toBeInTheDocument();
  });

  it("点「融合报告」→ 拉 ?track=combined 并渲染融合报告内容", async () => {
    const fetched: string[] = [];
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId", () => HttpResponse.json(combinedScan)),
      http.get("/api/workspaces/:ws/scans/:scanId/report", ({ request }) => {
        const track = new URL(request.url).searchParams.get("track") ?? "whitebox";
        fetched.push(track);
        const body = track === "combined" ? "# 融合报告" : track === "blackbox" ? "# 黑盒报告" : "# 白盒报告";
        return new HttpResponse(body, { headers: { "content-type": "text/plain" } });
      }),
    );
    renderReport();
    await screen.findByRole("tab", { name: /融合报告/ });
    // mouseDown（非 click）：Radix TabsTrigger 激活在 onMouseDown，裸 click 不触发切换。
    fireEvent.mouseDown(screen.getByRole("tab", { name: /融合报告/ }));
    await waitFor(() => {
      expect(fetched).toContain("combined");
      expect(screen.getByRole("heading", { level: 1, name: /融合报告/ })).toBeInTheDocument();
    });
  });
});

// =================================================================
// DeliverablesTab —— 三桶（白盒 / 黑盒 / 融合）
// =================================================================
describe("DeliverablesTab 组合扫描 - 三桶", () => {
  it("combined 统一文件树按 track 前缀分桶（白盒 / 黑盒 / 融合友好名目录）", async () => {
    const combinedSummary = {
      track: "combined",
      files: [
        { path: "whitebox/xss_exploitation_queue.json", size: 120, kind: "exploitation_queue" },
        { path: "whitebox/comprehensive_report.md", size: 500, kind: "md" },
        { path: "blackbox/injection_exploit_verdicts.json", size: 200, kind: "other_json" },
        { path: "combined/combined_report.md", size: 300, kind: "md" },
      ],
      aggregated_vulnerabilities: [],
      notes: {},
    };
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId/deliverables", () => HttpResponse.json(combinedSummary)),
    );
    renderDeliverables();
    // track 目录友好名（重设计 2026-08-17：一棵树，白盒/黑盒/融合为顶层目录）
    expect(await screen.findByText("白盒")).toBeInTheDocument();
    expect(screen.getByText("黑盒")).toBeInTheDocument();
    expect(screen.getByText("融合")).toBeInTheDocument();
    // 各桶含对应文件名（顶层目录默认展开）
    expect(screen.getByText("xss_exploitation_queue.json")).toBeInTheDocument();
    expect(screen.getByText("combined_report.md")).toBeInTheDocument();
  });
});

// =================================================================
// ReportTab —— 下载 .md 原文
// =================================================================
describe("ReportTab 报告下载", () => {
  function trackReportHandler() {
    return http.get("/api/workspaces/:ws/scans/:scanId/report", ({ request }) => {
      const track = new URL(request.url).searchParams.get("track") ?? "whitebox";
      const body = track === "combined" ? "# 融合报告" : track === "blackbox" ? "# 黑盒报告" : "# 白盒报告";
      return new HttpResponse(body, { headers: { "content-type": "text/plain" } });
    });
  }

  // T6（spec 2026-08-26 §7.1）：报告页先探 report-data（结构化 SSOT）。本组用例为
  // 旧 scan md 流--404 -> ReportTab 回退 md 渲染路径。
  function reportData404() {
    return http.get("/api/workspaces/:ws/scans/:scanId/blackbox-runs/:run/report-data",
      () => new HttpResponse("", { status: 404 }));
  }

  it("组合默认融合 tab：点「下载 .md」→ c1-report-combined.md + 融合报告全文", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId", () => HttpResponse.json(combinedScan)),
      trackReportHandler(),
    );
    renderReport();
    fireEvent.click(await screen.findByRole("button", { name: /下载 \.md/ }));
    expect(vi.mocked(downloadTextFile)).toHaveBeenCalledWith("c1-report-combined.md", "# 融合报告");
  });

  it("run 级黑盒 tab：点「下载 .md」→ c1-run-run-2-report-blackbox.md + 该 run 报告全文", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId", () => HttpResponse.json({
        ...combinedScan, status: "completed", bb_phase: "completed",
        latest_bb_run: "run-2",
        bb_runs: [{ run_id: "run-2", status: "completed" }],
      })),
      trackReportHandler(),
      http.get("/api/workspaces/:ws/scans/:scanId/blackbox-runs/:run/report-data",
        () => new HttpResponse(null, { status: 404 })),
      http.get("/api/workspaces/:ws/scans/:scanId/blackbox-runs/:run/report",
        () => new HttpResponse("# 黑盒报告 run2", { headers: { "content-type": "text/plain" } })),
      reportData404(),
    );
    renderDetailReport();
    // Radix TabsTrigger（1.1.17）激活在 onMouseDown（button=0 非 ctrl），无 onClick——
    // 裸 fireEvent.click 不触发 onValueChange（诊断对照实验 2026-08-25）。
    const tab = await screen.findByRole("tab", { name: /黑盒报告/ });
    fireEvent.mouseDown(tab);
    fireEvent.click(await screen.findByRole("button", { name: /下载 \.md/ }));
    expect(vi.mocked(downloadTextFile))
      .toHaveBeenCalledWith("c1-run-run-2-report-blackbox.md", "# 黑盒报告 run2");
  });
});

// 嵌套 ScanDetail 父：ReportTab 的 runSummary 经 Outlet context 传入（spec 2026-08-14 可见性）。
function renderDetailReport() {
  return render(
    <SWRConfig value={{ provider: () => new Map() }}>
    <MemoryRouter initialEntries={["/p/ws/scans/c1/report"]}>
      <Routes>
        <Route path="/p/:workspace/scans/:scanId" element={<ScanDetail />}>
          <Route path="report" element={<ReportTab />} />
        </Route>
      </Routes>
    </MemoryRouter>,
    </SWRConfig>
  );
}

describe("ReportTab 失败 run 横幅", () => {
  it("combined + 黑盒子 tab：run failed → 显失败原因横幅（非通用 empty）", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId", () => HttpResponse.json({
        scan_type: "whitebox", status: "failed", repo_path: "/code",
        workflow_id: "ws-c1", combined: true, bb_phase: "failed", progress_pct: 50,
        latest_bb_run: "run-1",
        bb_runs: [{ run_id: "run-1", status: "failed",
          reason: "workspace provider config incomplete; missing: SUPERNOVA_OPENAI_API_KEY" }],
      })),
      // run 失败 → 无报告，黑盒/融合子 tab report 请求 404。
      http.get("/api/workspaces/:ws/scans/:scanId/blackbox-runs/:run/report",
        () => new HttpResponse("", { status: 404 })),
      // T6：report-data 探测同样 404（旧 scan md 流语义）。
      http.get("/api/workspaces/:ws/scans/:scanId/blackbox-runs/:run/report-data",
        () => new HttpResponse("", { status: 404 })),
    );
    renderDetailReport();
    // 默认 combined track → 失败横幅。
    expect(await screen.findAllByText(/工作区 LLM 凭据未配置/)).not.toHaveLength(0);
    // 切到黑盒子 tab 仍显横幅（runSummary 经 outlet context 透传）。
    // mouseDown（非 click）：Radix TabsTrigger 激活在 onMouseDown，裸 click 不触发切换
    // （此前此用例实际从未真正切到黑盒 tab——假验证，2026-08-25 修正）。
    fireEvent.mouseDown(await screen.findByRole("tab", { name: /黑盒报告/ }));
    expect(await screen.findAllByText(/工作区 LLM 凭据未配置/)).not.toHaveLength(0);
  });
});
