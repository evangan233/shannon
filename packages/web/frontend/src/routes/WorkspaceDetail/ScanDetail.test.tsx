import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, cleanup, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { setupServer } from "msw/node";
import { http, HttpResponse, delay } from "msw";
import { SWRConfig } from "swr";
import i18n from "@/i18n";
import ScanDetail from "./ScanDetail";
import { DefaultScanTab } from "@/router";

// useEventSource mock（可控 events）：回归测试注入历史回放含 scan_end；其余测试空事件
// （等价 jsdom 无 EventSource 时的 no-op）。
const sse = vi.hoisted(() => ({
  events: [] as Array<Record<string, unknown>>,
  status: "open" as string,
}));
vi.mock("@/api/useEventSource", () => ({
  useEventSource: () => ({ events: sse.events, status: sse.status, lastEventId: undefined }),
}));

const server = setupServer(
  http.get("/api/workspaces/:ws/scans/:scanId", () =>
    HttpResponse.json({ status: "running", scan_type: "whitebox", repo_path: "/root/code" }),
  ),
);

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
beforeEach(() => { i18n.changeLanguage("zh"); sse.events = []; sse.status = "open"; });
afterEach(() => { server.resetHandlers(); cleanup(); i18n.changeLanguage("zh"); });
afterAll(() => server.close());

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      {/* SWR 迁移适配（spec §6.5）：独立 cache，防全局缓存跨测试污染
          （onScanEnd 死循环回归测试依赖 server.use 换 handler 后真的重新 fetch）。 */}
      <SWRConfig value={{ provider: () => new Map() }}>
        <Routes>
          <Route path="/p/:workspace/scans/:scanId" element={<ScanDetail />}>
            <Route index element={<div>default-content</div>} />
            <Route path="overview" element={<div>ov-content</div>} />
            <Route path="report" element={<div>rp-content</div>} />
            <Route path="deliverables" element={<div>dl-content</div>} />
            <Route path="dataflow" element={<div>df-content</div>} />
            <Route path="correlation" element={<div>corr-content</div>} />
            <Route path="logs" element={<div>lg-content</div>} />
            <Route path="live" element={<div>lv-content</div>} />
          </Route>
        </Routes>
      </SWRConfig>
    </MemoryRouter>,
  );
}

describe("ScanDetail per-scan 视图", () => {
  it("渲染 scan_id + 6 scan tabs（overview/report/deliverables/dataflow/logs/live）+ 返回 ws 链接", () => {
    renderAt("/p/ws/scans/s1/live");
    expect(screen.getByText("s1")).toBeInTheDocument();
    expect(screen.getByRole("tablist")).toBeInTheDocument();
    expect(screen.getAllByRole("tab")).toHaveLength(6);
    // dataflow tab 已注册
    expect(screen.getByRole("tab", { name: "数据流" })).toBeInTheDocument();
    // 返回 ws 概览链接（/p/ws）
    expect(screen.getByRole("link", { name: /返回工作区/ }).getAttribute("href")).toBe("/p/ws");
  });

  it("当前 tab aria-selected（live）", () => {
    renderAt("/p/ws/scans/s1/live");
    expect(screen.getByRole("tab", { name: "实时" })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("tab", { name: "概览" })).toHaveAttribute("aria-selected", "false");
  });

  it("点 tab 触发导航", () => {
    renderAt("/p/ws/scans/s1/live");
    fireEvent.mouseDown(screen.getByRole("tab", { name: "报告" }));
    expect(screen.getByText("rp-content")).toBeInTheDocument();
  });

  it("scan header 显 status/scan_type/repo_path", async () => {
    const { container } = renderAt("/p/ws/scans/s1/live");
    await waitFor(() => expect(screen.getByText("whitebox")).toBeInTheDocument());
    expect(screen.getByText("/root/code")).toBeInTheDocument();
    expect(container.querySelector("[title='running']")).toBeInTheDocument();
  });

  it("i18n 英文 tab 标签 + 返回 ws 链接", () => {
    i18n.changeLanguage("en");
    renderAt("/p/ws/scans/s1/live");
    expect(screen.getByRole("tab", { name: "Overview" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Report" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Live" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Back to workspace/ })).toBeInTheDocument();
  });
});

// === onScanEnd 静默刷新（防死循环回归，2026-08-17 报告页疯狂刷新 bug）===
// 终态扫描的事件历史回放必含 scan_end。若 onScanEnd 走带 loading 的 load：loading 翻转
// 卸载 ScanProgressOverview → endedFor ref 销毁 → 重挂载后回放的 scan_end 再次触发
// onScanEnd → getScan 循环。回归断言：scan_end 只静默重拉一次（共 2 次 getScan），稳定。
describe("ScanDetail onScanEnd 静默刷新", () => {
  it("历史回放含 scan_end：只补拉一次 meta，不进入 getScan 死循环", async () => {
    let scanGets = 0;
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId", async () => {
        scanGets += 1;
        // 真实网络延迟：让 setLoading(true) 先渲染、卸载 ScanProgressOverview——
        // 无延迟时 MSW 同微任务解析，true/false 两次 setState 被批处理合并，卸载路径走不到。
        await delay(30);
        return HttpResponse.json({ status: "completed", scan_type: "whitebox" });
      }),
    );
    sse.events = [{ ts: "2026-08-17T00:00:00.000Z", type: "scan_end" }];
    renderAt("/p/ws/scans/s1/report");
    // 初次加载完成 → 进度概览挂载
    await waitFor(() => expect(screen.getByTestId("scan-progress-overview")).toBeInTheDocument());
    // scan_end 触发一次静默重拉（getScan #2），随后稳定不再增长（死循环则持续增长）
    await waitFor(() => expect(scanGets).toBe(2));
    await new Promise((r) => setTimeout(r, 300));
    expect(scanGets).toBe(2);
    // 进度概览全程不卸载（死循环的可见症状：卸载/重挂载闪烁）
    expect(screen.getByTestId("scan-progress-overview")).toBeInTheDocument();
  });
});

// === 加黑盒入口门控（后端 422 兜底，前端先拦免空跑）===
// 纯白盒任务无目标 URL（黑盒无目标可打，workflow 不 fail-fast 会空跑一轮 LLM）。
// 2026-08-17 根因修后：run 在跑期间任务级 status=running（后端 _add_blackbox_run 上浮），
// 按钮随 status 自然隐藏；「status=completed + run 在跑」只作为 legacy 状态兜底（禁用）。
// cancelled（取消过手动 run，白盒产物完好）→ 按钮仍可用（后端 deliverables_ready 兜底）。
describe("ScanDetail 加黑盒入口门控", () => {
  it("纯白盒（无 web_url）→ 按钮禁用 + title 提示无目标 URL", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId", () =>
        HttpResponse.json({ status: "completed", scan_type: "whitebox", web_url: "" })),
    );
    renderAt("/p/ws/scans/s1/report");
    const btn = await screen.findByRole("button", { name: /加黑盒扫描/ });
    expect(btn).toBeDisabled();
    expect(btn.getAttribute("title")).toContain("目标 URL");
  });

  it("run 进行中（任务级 status=running，新口径）→ 按钮隐藏", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId", () =>
        HttpResponse.json({
          status: "running", scan_type: "whitebox", web_url: "http://t",
          combined: true, latest_bb_run: "run-1",
          bb_runs: [{ run_id: "run-1", status: "running" }],
        })),
    );
    renderAt("/p/ws/scans/s1/report");
    await screen.findByText("s1"); // header 就绪
    expect(screen.queryByRole("button", { name: /加黑盒扫描/ })).not.toBeInTheDocument();
  });

  it("run 进行中 + 任务级停在 completed（legacy 状态）→ 按钮禁用 + title 提示等待", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId", () =>
        HttpResponse.json({
          status: "completed", scan_type: "whitebox", web_url: "http://t",
          combined: true, latest_bb_run: "run-1",
          bb_runs: [{ run_id: "run-1", status: "running" }],
        })),
    );
    renderAt("/p/ws/scans/s1/report");
    const btn = await screen.findByRole("button", { name: /加黑盒扫描/ });
    expect(btn).toBeDisabled();
    expect(btn.getAttribute("title")).toContain("进行中");
  });

  it("有目标 URL 且 run 终态 → 按钮可点", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId", () =>
        HttpResponse.json({
          status: "completed", scan_type: "whitebox", web_url: "http://t",
          combined: true, latest_bb_run: "run-1",
          bb_runs: [{ run_id: "run-1", status: "completed" }],
        })),
    );
    renderAt("/p/ws/scans/s1/report");
    const btn = await screen.findByRole("button", { name: /加黑盒扫描/ });
    await waitFor(() => expect(btn).toBeEnabled());
  });

  it("任务级 cancelled（取消过手动 run，白盒产物完好）→ 按钮可点（可再加黑盒）", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId", () =>
        HttpResponse.json({
          status: "cancelled", scan_type: "whitebox", web_url: "http://t",
          combined: true, latest_bb_run: "run-1",
          bb_runs: [{ run_id: "run-1", status: "cancelled" }],
        })),
    );
    renderAt("/p/ws/scans/s1/report");
    const btn = await screen.findByRole("button", { name: /加黑盒扫描/ });
    await waitFor(() => expect(btn).toBeEnabled());
  });
});

// === correlation 主行 tab 组（D6，spec 2026-08-24 §8）===
// 关联主行 tab 列表按 scan_type 分支：概览 | 跨仓关联 | 产物 | 日志——无 report/
// dataflow/live（结果在专属跨仓关联 tab；实时进度在顶部 ScanProgressOverview 经
// correlation_progress 事件渲染）。
describe("ScanDetail correlation 主行 tab 组", () => {
  it("correlation scan：渲染 4 tab（概览/跨仓关联/产物/日志），不含 report/dataflow/live", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId", () =>
        HttpResponse.json({ status: "running", scan_type: "correlation" })),
    );
    renderAt("/p/ws/scans/s1/logs");
    await waitFor(() =>
      expect(screen.getByRole("tab", { name: "跨仓关联" })).toBeInTheDocument());
    expect(screen.getAllByRole("tab")).toHaveLength(4);
    for (const name of ["概览", "跨仓关联", "产物", "日志"]) {
      expect(screen.getByRole("tab", { name })).toBeInTheDocument();
    }
    for (const absent of ["报告", "数据流", "实时"]) {
      expect(screen.queryByRole("tab", { name: absent })).not.toBeInTheDocument();
    }
  });

  it("correlation tab 点击导航到 correlation 路由段", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId", () =>
        HttpResponse.json({ status: "running", scan_type: "correlation" })),
    );
    renderAt("/p/ws/scans/s1/logs");
    await waitFor(() =>
      expect(screen.getByRole("tab", { name: "跨仓关联" })).toBeInTheDocument());
    fireEvent.mouseDown(screen.getByRole("tab", { name: "跨仓关联" }));
    expect(screen.getByText("corr-content")).toBeInTheDocument();
  });

  it("correlation 当前 tab aria-selected", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId", () =>
        HttpResponse.json({ status: "running", scan_type: "correlation" })),
    );
    renderAt("/p/ws/scans/s1/correlation");
    await waitFor(() =>
      expect(screen.getByRole("tab", { name: "跨仓关联" })).toHaveAttribute("aria-selected", "true"));
    expect(screen.getByRole("tab", { name: "概览" })).toHaveAttribute("aria-selected", "false");
  });

  it("i18n 英文：跨仓关联 tab 标签 Correlation", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId", () =>
        HttpResponse.json({ status: "running", scan_type: "correlation" })),
    );
    i18n.changeLanguage("en");
    renderAt("/p/ws/scans/s1/logs");
    await waitFor(() =>
      expect(screen.getByRole("tab", { name: "Correlation" })).toBeInTheDocument());
    expect(screen.getAllByRole("tab")).toHaveLength(4);
  });
});

// === DefaultScanTab correlation 默认概览（D6）===
// 关联主行 tab 组无 report/live——默认落「概览」（简版 CorrelationOverview：三段横幅 +
// children 状态网格），不再按终态分落 report/live。
describe("DefaultScanTab correlation 默认概览", () => {
  function renderDefault(path: string) {
    return render(
      <MemoryRouter initialEntries={[path]}>
        <SWRConfig value={{ provider: () => new Map() }}>
          <Routes>
            {/* 镜像真实 router.tsx：DefaultScanTab 挂 index 路由，tab 子路由平铺 */}
            <Route path="/p/:workspace/scans/:scanId">
              <Route index element={<DefaultScanTab />} />
              <Route path="overview" element={<div>ov-content</div>} />
              <Route path="report" element={<div>rp-content</div>} />
              <Route path="live" element={<div>lv-content</div>} />
            </Route>
          </Routes>
        </SWRConfig>
      </MemoryRouter>,
    );
  }

  it("correlation 主行（进行中）默认落概览而非 live", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId", () =>
        HttpResponse.json({ status: "running", scan_type: "correlation" })),
    );
    renderDefault("/p/ws/scans/s1");
    await waitFor(() => expect(screen.getByText("ov-content")).toBeInTheDocument());
  });

  it("correlation 主行（completed）仍落概览（tab 组无 report）", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId", () =>
        HttpResponse.json({ status: "completed", scan_type: "correlation" })),
    );
    renderDefault("/p/ws/scans/s1");
    await waitFor(() => expect(screen.getByText("ov-content")).toBeInTheDocument());
  });

  it("whitebox 回归：running → live / completed → report 不变", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId", () =>
        HttpResponse.json({ status: "running", scan_type: "whitebox" })),
    );
    const { unmount } = renderDefault("/p/ws/scans/s1");
    await waitFor(() => expect(screen.getByText("lv-content")).toBeInTheDocument());
    unmount();
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId", () =>
        HttpResponse.json({ status: "completed", scan_type: "whitebox" })),
    );
    renderDefault("/p/ws/scans/s2");
    await waitFor(() => expect(screen.getByText("rp-content")).toBeInTheDocument());
  });
});

// ── 续跑详情卡（spec 2026-08-27-web-resume-breakpoint §4.6；2026-09-09 由
// 「断点详情」改名——全程阶段进度已常驻 ScanPhaseRail，本卡专注续跑细节）──────

describe("续跑详情卡", () => {
  it("failed 白盒行：agent 状态列表 + 步骤缓存简表 + 续跑确认流", async () => {
    const resumeCalls: string[] = [];
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId", () =>
        HttpResponse.json({ status: "failed", scan_type: "whitebox",
                            repo_path: "/root/code", workflow_id: "ws-s1" })),
      http.get("/api/workspaces/:ws/scans/:scanId/resume-preview", () =>
        HttpResponse.json({
          status: "failed", resumable: true, reason: null, scan_type: "whitebox",
          completed_agents: ["pre-recon", "recon"], interrupted_agent: "injection-vuln",
          steps: [{ step: "gitnexus-chain-verdict", state: "done", ts: 1 }],
          warnings: [], abort_reason: null, resume_attempts: 1,
        })),
      http.post("/api/workspaces/:ws/scans/:scanId/resume", ({ params }) => {
        resumeCalls.push(`${params.ws}/${params.scanId}`);
        return HttpResponse.json({ workspace: params.ws, scan_id: params.scanId });
      }),
    );
    renderAt("/p/ws/scans/s1/live");
    // 卡片：标题 + 已完成 agent + 继续点 + 步骤缓存条目
    expect(await screen.findByText("续跑详情")).toBeInTheDocument();
    // agent 名限定在卡内断言——全程阶段轨道（scan-phase-rail）也有同名 chip
    const card = screen.getByTestId("resume-breakpoint");
    expect(within(card).getByText(/pre-recon/)).toBeInTheDocument();
    expect(screen.getByText(/将从此继续/)).toBeInTheDocument();
    expect(screen.getByText(/gitnexus-chain-verdict/)).toBeInTheDocument();
    // 续跑 → 确认弹窗（摘要）→ POST resume
    fireEvent.click(screen.getByRole("button", { name: "续跑" }));
    expect(await screen.findByText(/已完成 2 项/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "确认" }));
    await waitFor(() => expect(resumeCalls).toEqual(["ws/s1"]));
  });

  it("resumable:false：卡内直示原因，无续跑按钮", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId", () =>
        HttpResponse.json({ status: "failed", scan_type: "whitebox",
                            repo_path: "/root/code", workflow_id: "ws-s1" })),
      http.get("/api/workspaces/:ws/scans/:scanId/resume-preview", () =>
        HttpResponse.json({
          status: "failed", resumable: false,
          reason: "resume 中止：recon 产出物文件缺失", scan_type: "whitebox",
          completed_agents: [], interrupted_agent: null, steps: [], warnings: [],
          abort_reason: "resume 中止：recon 产出物文件缺失", resume_attempts: 0,
        })),
    );
    renderAt("/p/ws/scans/s1/live");
    expect(await screen.findByText(/产出物文件缺失/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "续跑" })).not.toBeInTheDocument();
  });

  it("running 行不渲染续跑详情卡", async () => {
    renderAt("/p/ws/scans/s1/live");
    await waitFor(() => expect(screen.getByText("whitebox")).toBeInTheDocument());
    expect(screen.queryByText("续跑详情")).not.toBeInTheDocument();
  });
});
