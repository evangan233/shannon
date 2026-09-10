import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach, vi } from "vitest";
import { screen, waitFor, fireEvent, cleanup, within } from "@testing-library/react";
import { renderWithSwr } from "@/test/swr-render";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { setupServer } from "msw/node";
import { http, HttpResponse } from "msw";
import i18n from "@/i18n";
import { ScanList } from "./ScanList";

// toast 在 ScanList 用于操作反馈；隔离避免 sonner 全局副作用。
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn(), info: vi.fn() } }));

// 捕获 useNavigate 调用以断言重跑的 location.state 预填（MemoryRouter 仍用 actual）。
const { navMock } = vi.hoisted(() => ({ navMock: vi.fn() }));
vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return { ...actual, useNavigate: () => navMock };
});

// SSE mock（2026-08-27 列表进度不动修复）：useEventSource 的 events 可控——运行行
// 进度条应由 events fold（dashboardReducer，详情页同机制）实时驱动。默认空数组
// （等价 jsdom 无 EventSource 的现状），既有用例零影响。
const { sseState } = vi.hoisted(() => ({
  sseState: { events: [] as unknown[], hydrated: true },
}));
vi.mock("@/api/useEventSource", () => ({
  useEventSource: () => ({ events: sseState.events, status: "closed" as const, hydrated: sseState.hydrated }),
}));

const running = {
  scan_id: "s1", scan_type: "whitebox", status: "running", created_at: 1000,
  completed_at: null, vuln_count: 0, total_cost_usd: 1.5, cost_currency: "USD", is_running: true,
  // 后端 session.json completed_agents 运行中不落盘 → progress_pct 阶段内恒定（本 bug
  // 根因）；取 5 断言「SSE 进度优先、progress_pct 仅兜底」。
  progress_pct: 5,
} as const;
const completed = {
  scan_id: "s2", scan_type: "blackbox", status: "completed", created_at: 2000,
  completed_at: 3000, vuln_count: 3, total_cost_usd: 2, cost_currency: "USD", is_running: false,
} as const;
const interrupted = {
  scan_id: "s3", scan_type: "whitebox", status: "interrupted", created_at: 3000,
  completed_at: null, vuln_count: 1, total_cost_usd: 0.5, cost_currency: "USD", is_running: false,
} as const;
// 续跑（spec 2026-08-27 §4.6）：failed 是最常见中断出口——白盒 failed 行有续跑。
const failedWb = {
  scan_id: "s9", scan_type: "whitebox", status: "failed", created_at: 7000,
  completed_at: null, vuln_count: 2, total_cost_usd: 1, cost_currency: "USD",
  is_running: false, workflow_id: "ws-s9",
} as const;
// 关联主行（非 completed 也一样）：无续跑入口（重新提交语义）。
const corrFailed = {
  scan_id: "corr-9", scan_type: "correlation", status: "failed", created_at: 7100,
  completed_at: null, vuln_count: 0, total_cost_usd: 0, cost_currency: "USD",
  is_running: false, workflow_id: "ws-corr-9",
} as const;
// resume-preview 响应（§4.5 形状）。
const previewOk = {
  status: "interrupted", resumable: true, reason: null, scan_type: "whitebox",
  completed_agents: ["pre-recon", "recon"], interrupted_agent: "injection-vuln",
  steps: [
    { step: "gitnexus-chain-verdict", state: "done", ts: 1756272000 },
    { step: "authz-gitnexus-judge", state: "missing" },
  ],
  warnings: [], abort_reason: null, resume_attempts: 1,
} as const;
// cancelled（2026-08-17 根因修）：取消手动黑盒 run 后任务级落 cancelled——现口径
// 亦可续跑（spec 2026-08-27 §4.1 扩集）。
const cancelled = {
  scan_id: "s4", scan_type: "whitebox", status: "cancelled", created_at: 4000,
  completed_at: 5000, vuln_count: 0, total_cost_usd: 1, cost_currency: "USD", is_running: false,
} as const;
// 已完成白盒（D4）：黑盒历史行重跑入口已删（ScanNewPage 无黑盒表单），测重跑/
// 终态按钮显隐的用例须用白盒终态行，不再复用黑盒 `completed`。
const wbDone = {
  scan_id: "s5", scan_type: "whitebox", status: "completed", created_at: 4500,
  completed_at: 4600, vuln_count: 2, total_cost_usd: 1, cost_currency: "USD",
  is_running: false, workflow_id: "ws-s5",
} as const;

// ── D4（2026-08-24）：correlation 主行 + 嵌套子行列 fixtures ─────────────────
// 现扫子仓白盒行由后端建在同 ws（scan_manager 提交时 create_scan(ws,…,"whitebox")），
// 故列表同时含子行主行 + corr 主行——嵌套子行按 scan_id 从全量列表富化状态/漏洞数。
const corrChildScan = {
  scan_id: "child-1", scan_type: "whitebox", status: "completed", created_at: 5100,
  completed_at: 5200, vuln_count: 2, total_cost_usd: 1, cost_currency: "USD",
  is_running: false, workflow_id: "ws-child-1", repo: "frontend",
} as const;
const corrHistScan = {
  scan_id: "hist-9", scan_type: "whitebox", status: "completed", created_at: 900,
  completed_at: 950, vuln_count: 4, total_cost_usd: 0.5, cost_currency: "USD",
  is_running: false, workflow_id: "ws-hist-9", repo: "order",
} as const;
// corr 主行：现扫子仓（child-1）+ 复用子仓（hist-9）+ 段③黑盒验证 run-1。
// bb_runs 非空时后端 create_blackbox_run 亦置 combined=True——fixture 如实带，
// 锁定「关联行即使 combined=True 也只归「跨仓关联」档，不漏进「组合」」。
const corrMain = {
  scan_id: "corr-1", scan_type: "correlation", status: "completed", created_at: 5000,
  completed_at: 6000, vuln_count: 5, total_cost_usd: 3, cost_currency: "USD",
  is_running: false, workflow_id: "ws-corr-1", combined: true,
  corr_children: [
    { service: "frontend", scan_id: "child-1", reused: false },
    { service: "order", scan_id: "hist-9", reused: true },
  ],
  bb_runs: [{
    run_id: "run-1", status: "completed", bb_phase: "completed",
    started_at: null, completed_at: "2026-08-24T10:00:00Z",
  }],
  latest_bb_run: "run-1",
} as const;

let listCalls = 0;
const server = setupServer(
  http.get("/api/workspaces/:ws/scans", () => { listCalls++; return HttpResponse.json([]); }),
);

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
beforeEach(() => {
  i18n.changeLanguage("zh"); listCalls = 0; navMock.mockClear();
  sseState.events = [];
  sseState.hydrated = true;
});
afterEach(() => { server.resetHandlers(); cleanup(); });
afterAll(() => server.close());

function renderList() {
  return renderWithSwr(
    <MemoryRouter initialEntries={["/p/ws"]}>
      <Routes><Route path="/p/:workspace" element={<ScanList />} /></Routes>
    </MemoryRouter>,
  );
}

describe("ScanList 扫描列表", () => {
  it("渲染标题 + 新建扫描按钮 + 多个 scan 卡片", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([running, completed])),
    );
    renderList();
    expect(screen.getByText("扫描任务")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /新建扫描/ })).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText("s1")).toBeInTheDocument());
    expect(screen.getByText("s2")).toBeInTheDocument();
  });

  it("空态：无 scan -> 显空态 + 新建扫描按钮", async () => {
    server.use(http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([])));
    renderList();
    await waitFor(() => expect(screen.getByText(/尚无扫描任务/)).toBeInTheDocument());
    // v4：列表头 CTA 隐藏，空态卡是唯一「新建扫描」link
    expect(screen.getAllByRole("link", { name: /新建扫描/ }).length).toBeGreaterThanOrEqual(1);
  });

  it("新建扫描链接预填 ?workspace=<ws>", async () => {
    server.use(http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([])));
    renderList();
    await waitFor(() =>
      expect(screen.getAllByRole("link", { name: /新建扫描/ }).length).toBeGreaterThan(0),
    );
    expect(screen.getAllByRole("link", { name: /新建扫描/ })[0].getAttribute("href")).toContain(
      "/scan/new?workspace=ws",
    );
  });

  it("任务名展示 workflow_id（{ws}-{scan_id}），路由仍用 scan_id", async () => {
    // 后端 ScanSummary 透传 workflow_id；前端任务名展示它，路由/定位仍走 scan_id。
    const wf = { ...running, workflow_id: "ws-s1" };
    server.use(
      http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([wf])),
    );
    renderList();
    await waitFor(() =>
      expect(screen.getByRole("link", { name: "ws-s1" })).toBeInTheDocument(),
    );
    // 显示 workflow_id，但链接路由仍是 scan_id（s1）—— 显示与定位解耦。
    expect(screen.getByRole("link", { name: "ws-s1" }).getAttribute("href")).toBe(
      "/p/ws/scans/s1/live",
    );
  });

  it("仓库格显示 repo@branch（分支快照），commit 前 8 位进 title；无快照行不显示 @", async () => {
    // spec 2026-08-21 §4：切分支后同一仓扫不同分支，报告靠快照区分来源。
    server.use(
      http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([
        { ...completed, scan_id: "with-snap", repo: "app", repo_url: "https://x/app.git",
          repo_branch: "dev", repo_commit: "abc123def456" },
        { ...completed, scan_id: "no-snap", repo: "old", repo_branch: null, repo_commit: null },
      ])),
    );
    renderList();
    // repo 与 @branch 分属两个 span（样式分档），默认 text matcher 只看单文本节点 →
    // 用 textContent 函数匹配
    const repoCell = await waitFor(() => {
      const hits = screen.getAllByText((_, el) => el?.textContent === "app@dev");
      expect(hits.length).toBeGreaterThan(0);
      const td = hits[0].closest("td");
      expect(td).not.toBeNull();
      return td as HTMLElement;
    });
    // commit 前 8 位 hover 可见（title 属性）
    expect(repoCell).toHaveAttribute("title", "abc123de");
    // 存量报告（无快照）不显示 @ 分支
    expect(screen.getByText("old")).toBeInTheDocument();
    expect(screen.queryByText((_, el) => (el?.textContent ?? "").includes("old@"))).not.toBeInTheDocument();
  });
});

describe("ScanList 卡片操作按钮按 status 显隐", () => {
  it("running scan：显取消，不显恢复", async () => {
    server.use(http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([running])));
    renderList();
    await waitFor(() => expect(screen.getByText("s1")).toBeInTheDocument());
    // running -> 显取消（common.cancel）
    expect(screen.getAllByRole("button", { name: "取消" }).length).toBeGreaterThan(0);
    // running -> 不显续跑
    expect(screen.queryByRole("button", { name: "续跑" })).not.toBeInTheDocument();
  });

  it("interrupted scan：显续跑，不显取消", async () => {
    server.use(http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([interrupted])));
    renderList();
    await waitFor(() => expect(screen.getByText("s3")).toBeInTheDocument());
    expect(screen.getByRole("button", { name: "续跑" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "取消" })).not.toBeInTheDocument();
  });

  it("completed scan：不显恢复/取消，显删除/重跑/查看", async () => {
    // D4：重跑入口黑盒行已删——终态按钮显隐用白盒终态行断言。
    server.use(http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([wbDone])));
    renderList();
    await waitFor(() => expect(screen.getByText("ws-s5")).toBeInTheDocument());
    expect(screen.queryByRole("button", { name: "恢复" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "取消" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /重跑/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /删除/ })).toBeInTheDocument();
    // 查看是 Link（role=link）
    expect(screen.getByRole("link", { name: /查看/ })).toBeInTheDocument();
  });

  it("cancelled scan：不显恢复/取消，显删除/重跑/查看（终态口径）", async () => {
    server.use(http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([cancelled])));
    renderList();
    await waitFor(() => expect(screen.getByText("s4")).toBeInTheDocument());
    expect(screen.queryByRole("button", { name: "恢复" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "取消" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /重跑/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /删除/ })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /查看/ })).toBeInTheDocument();
  });

  it("查看链接按 status 智能指向：完成 -> report", async () => {
    server.use(http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([completed])));
    renderList();
    await waitFor(() => expect(screen.getByRole("link", { name: /查看/ })).toBeInTheDocument());
    // 完成 -> report（看结果），与 router.tsx DefaultScanTab 一致
    expect(screen.getByRole("link", { name: /查看/ }).getAttribute("href")).toBe("/p/ws/scans/s2/report");
    // scan_id 链接同策略
    expect(screen.getByRole("link", { name: "s2" }).getAttribute("href")).toBe("/p/ws/scans/s2/report");
  });

  it("查看链接：running scan -> live（看实时）", async () => {
    server.use(http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([running])));
    renderList();
    await waitFor(() => expect(screen.getByRole("link", { name: /查看/ })).toBeInTheDocument());
    expect(screen.getByRole("link", { name: /查看/ }).getAttribute("href")).toBe("/p/ws/scans/s1/live");
  });
});

describe("ScanList 操作调 API + 列表刷新", () => {
  it("取消 running scan -> POST cancel scan-scoped -> 刷新列表", async () => {
    const cancelCalls: string[] = [];
    server.use(
      http.get("/api/workspaces/:ws/scans", () => { listCalls++; return HttpResponse.json([running]); }),
      http.post("/api/workspaces/:ws/scans/:scanId/cancel", ({ params }) => {
        cancelCalls.push(`${params.ws}/${params.scanId}`);
        return HttpResponse.json({ cancelled: params.scanId as string });
      }),
    );
    renderList();
    await waitFor(() => expect(screen.getByText("s1")).toBeInTheDocument());
    const listCallsBefore = listCalls;
    // 点卡片「取消」-> Dialog 开
    fireEvent.click(screen.getByRole("button", { name: "取消" }));
    expect(await screen.findByText(/取消扫描 s1/)).toBeInTheDocument();
    // 点「确认」-> POST cancel
    fireEvent.click(screen.getByRole("button", { name: "确认" }));
    await waitFor(() => expect(cancelCalls).toEqual(["ws/s1"]));
    // 刷新：listScans 再拉一次
    await waitFor(() => expect(listCalls).toBeGreaterThan(listCallsBefore));
  });

  it("删除 scan -> DELETE -> 刷新列表", async () => {
    const deleteCalls: string[] = [];
    server.use(
      http.get("/api/workspaces/:ws/scans", () => { listCalls++; return HttpResponse.json([completed]); }),
      http.delete("/api/workspaces/:ws/scans/:scanId", ({ params }) => {
        deleteCalls.push(`${params.ws}/${params.scanId}`);
        return HttpResponse.json({ deleted: params.scanId as string });
      }),
    );
    renderList();
    await waitFor(() => expect(screen.getByText("s2")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: /删除/ }));
    expect(await screen.findByText(/删除扫描 s2/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "确认" }));
    await waitFor(() => expect(deleteCalls).toEqual(["ws/s2"]));
  });

  // ── 续跑（spec 2026-08-27-web-resume-breakpoint §4.6：preview 弹窗 → 确认 → POST）──

  it("续跑按钮显示矩阵：failed/cancelled/interrupted 白盒行显示；completed 白盒行与 correlation 行不显示", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([
        failedWb, cancelled, interrupted, wbDone, corrFailed])),
    );
    renderList();
    await waitFor(() => expect(screen.getByText("ws-s9")).toBeInTheDocument());
    // failed(s9) / cancelled(s4) / interrupted(s3) 三行有续跑；wbDone(completed)、corrFailed(关联) 无
    expect(screen.getAllByRole("button", { name: "续跑" })).toHaveLength(3);
  });

  it("续跑确认流：GET resume-preview → 弹窗摘要 → 确认 -> POST resume", async () => {
    const resumeCalls: string[] = [];
    server.use(
      http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([interrupted])),
      http.get("/api/workspaces/:ws/scans/:scanId/resume-preview", () =>
        HttpResponse.json(previewOk)),
      http.post("/api/workspaces/:ws/scans/:scanId/resume", ({ params }) => {
        resumeCalls.push(`${params.ws}/${params.scanId}`);
        return HttpResponse.json({ workspace: params.ws as string, scan_id: params.scanId as string });
      }),
    );
    renderList();
    await waitFor(() => expect(screen.getByText("s3")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "续跑" }));
    // 弹窗摘要：已完成 2 项 + 继续点 + 缓存命中 1 项
    expect(await screen.findByText(/已完成 2 项/)).toBeInTheDocument();
    expect(screen.getByText(/injection-vuln/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "确认" }));
    await waitFor(() => expect(resumeCalls).toEqual(["ws/s3"]));
  });

  it("resumable:false -> 弹窗展示原因、确认禁用、不 POST", async () => {
    const resumeCalls: string[] = [];
    server.use(
      http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([failedWb])),
      http.get("/api/workspaces/:ws/scans/:scanId/resume-preview", () =>
        HttpResponse.json({ ...previewOk, resumable: false,
                            reason: "resume 中止：recon 产出物文件缺失" })),
      http.post("/api/workspaces/:ws/scans/:scanId/resume", ({ params }) => {
        resumeCalls.push(`${params.ws}/${params.scanId}`);
        return HttpResponse.json({ workspace: params.ws as string, scan_id: params.scanId as string });
      }),
    );
    renderList();
    await waitFor(() => expect(screen.getByText("ws-s9")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "续跑" }));
    expect(await screen.findByText(/产出物文件缺失/)).toBeInTheDocument();
    const confirm = screen.getByRole("button", { name: "确认" });
    expect(confirm).toBeDisabled();
    fireEvent.click(confirm);
    expect(resumeCalls).toEqual([]);
  });

  it("重跑入口（D4 黑盒历史行移除）：黑盒行无重跑按钮；白盒重跑不受影响", async () => {
    // D3 删 ScanNewPage 黑盒表单后，黑盒 preset 只会落坏表单——D4 把 ScanList 侧
    // 黑盒行的重跑入口一并移除（白盒/组合不受影响）。
    server.use(
      http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([completed, wbDone])),
      http.get("/api/workspaces/:ws/scans/:scanId", () =>
        HttpResponse.json({ scan_type: "whitebox", source_repo: "group/repo-a" })),
    );
    renderList();
    await waitFor(() => expect(screen.getByText("s2")).toBeInTheDocument());
    // 全列表唯一重跑按钮 = 白盒行（黑盒 s2 无）
    expect(screen.getAllByRole("button", { name: /重跑/ })).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: /重跑/ }));
    await waitFor(() => expect(navMock).toHaveBeenCalled());
    expect(navMock).toHaveBeenCalledWith("/scan/new?workspace=ws", {
      state: { type: "whitebox", workspace: "ws", repo: "group/repo-a" },
    });
  });

  it("重跑（白盒）-> 预填 source_repo", async () => {
    server.use(
      // 重跑仅终态行有（interrupted 走「恢复」）——用已完成的白盒扫描做 fixture。
      http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([
        { scan_id: "s3", scan_type: "whitebox", status: "completed", created_at: 3000,
          completed_at: 4000, vuln_count: 1, total_cost_usd: 0.5, cost_currency: "USD",
          is_running: false, workflow_id: "ws-s3" }])),
      http.get("/api/workspaces/:ws/scans/:scanId", () =>
        HttpResponse.json({ scan_type: "whitebox", source_repo: "group/repo-a" })),
    );
    renderList();
    await waitFor(() => expect(screen.getByText("ws-s3")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: /重跑/ }));
    await waitFor(() => expect(navMock).toHaveBeenCalled());
    expect(navMock).toHaveBeenCalledWith("/scan/new?workspace=ws", {
      state: { type: "whitebox", workspace: "ws", repo: "group/repo-a" },
    });
  });

  it("重跑（组合扫描）-> 预填黑盒目标 + 认证档案 + HOST 来源 + combined 开关", async () => {
    // D3 黑盒并入组合扫描后，组合任务重跑是重建黑盒段的唯一路径——detail 的
    // bb_url/auth_profile_id/host_* 须全部进 location.state（ScanNewPage preset）。
    server.use(
      http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([
        { scan_id: "s-c", scan_type: "whitebox", status: "failed", created_at: 5000,
          completed_at: 6000, vuln_count: 2, total_cost_usd: 1.0, cost_currency: "USD",
          is_running: false, workflow_id: "ws-s-c", combined: true }])),
      http.get("/api/workspaces/:ws/scans/:scanId", () =>
        HttpResponse.json({
          scan_type: "whitebox", source_repo: "group/repo-a",
          combined: true, bb_url: "https://target.example.com",
          auth_profile_id: "auth_profile_1", auth_credential_ids: ["cred-a", "cred-b"],
          host_profile_id: "host_profile_1",
        })),
    );
    renderList();
    await waitFor(() => expect(screen.getByText("ws-s-c")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: /重跑/ }));
    await waitFor(() => expect(navMock).toHaveBeenCalled());
    expect(navMock).toHaveBeenCalledWith("/scan/new?workspace=ws", {
      state: {
        type: "whitebox", workspace: "ws", repo: "group/repo-a",
        url: "https://target.example.com",
        combined: true,
        authProfileId: "auth_profile_1",
        authCredentialIds: ["cred-a", "cred-b"],
        hostProfileId: "host_profile_1",
      },
    });
  });

  it("重跑（组合扫描 inline 认证）-> authentication 走 auth 兜底，无档案字段", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([
        { scan_id: "s-i", scan_type: "whitebox", status: "failed", created_at: 5000,
          completed_at: 6000, vuln_count: 0, total_cost_usd: 0.1, cost_currency: "USD",
          is_running: false, workflow_id: "ws-s-i", combined: true }])),
      http.get("/api/workspaces/:ws/scans/:scanId", () =>
        HttpResponse.json({
          scan_type: "whitebox", source_repo: "group/repo-a",
          bb_url: "https://target.example.com",
          auth_profile_id: null, auth_credential_ids: [],
          authentication: { login_type: "form", login_url: "https://target.example.com/login",
                            credentials: { username: "admin" } },
          host_url: "https://hosts.example/hosts",
        })),
    );
    renderList();
    await waitFor(() => expect(screen.getByText("ws-s-i")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: /重跑/ }));
    await waitFor(() => expect(navMock).toHaveBeenCalled());
    expect(navMock).toHaveBeenCalledWith("/scan/new?workspace=ws", {
      state: {
        type: "whitebox", workspace: "ws", repo: "group/repo-a",
        url: "https://target.example.com",
        combined: true,
        auth: { login_type: "form", login_url: "https://target.example.com/login",
                credentials: { username: "admin" } },
        hostUrl: "https://hosts.example/hosts",
      },
    });
  });

  it("重跑 getScan 失败 -> 降级跳转（无 state）+ toast 提示", async () => {
    const { toast } = await import("sonner");
    server.use(
      // D4：重跑仅白盒/组合/correlation 行有——黑盒 fixture 换白盒终态行。
      http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([wbDone])),
      http.get("/api/workspaces/:ws/scans/:scanId", () =>
        HttpResponse.json({ detail: "boom" }, { status: 500 })),
    );
    renderList();
    await waitFor(() => expect(screen.getByText("ws-s5")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: /重跑/ }));
    await waitFor(() => expect(navMock).toHaveBeenCalledWith("/scan/new?workspace=ws"));
    // 降级：仅 path 参数，无 state。
    expect(navMock.mock.calls.some(([p, o]) => p === "/scan/new?workspace=ws" && !o)).toBe(true);
    expect(toast.error).toHaveBeenCalled();
  });
});

// === MR 增量扫描（spec 2026-09-03 §6）：「MR」徽标 + base..head 标识 + 独立类型档 + 重跑预填 ===
describe("ScanList MR 增量扫描", () => {
  const mrScan = {
    scan_id: "mr-1", scan_type: "mr", status: "completed", created_at: 8000,
    completed_at: 8100, vuln_count: 1, total_cost_usd: 0.2, cost_currency: "CNY",
    is_running: false, workflow_id: "ws-mr-1",
    mr_base_ref: "main", mr_head_ref: "feature/xss",
  } as const;

  it("mr 行显「MR」徽标 + base..head refs；白盒行类型不变", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([mrScan, wbDone])),
    );
    renderList();
    await waitFor(() => expect(screen.getByText("ws-mr-1")).toBeInTheDocument());
    expect(screen.getByText("MR")).toBeInTheDocument();
    expect(screen.getByText("main..feature/xss")).toBeInTheDocument();
    // 白盒行类型格仍显 scan_type 原文
    expect(screen.getByText("whitebox")).toBeInTheDocument();
  });

  it("类型筛选「MR 增量」档只留 mr 行（白盒/组合档不含 mr）", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([mrScan, wbDone])),
    );
    renderList();
    await waitFor(() => expect(screen.getByText("ws-mr-1")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("combobox", { name: "类型筛选" }));
    fireEvent.click(await screen.findByRole("option", { name: "MR 增量" }));
    await waitFor(() => expect(screen.queryByText("ws-s5")).toBeNull());
    expect(screen.getByText("ws-mr-1")).toBeInTheDocument();
  });

  it("mr 行无续跑入口（resume 语义后续定）；重跑预填 repo + base/head refs", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([mrScan])),
      http.get("/api/workspaces/:ws/scans/:scanId", () =>
        HttpResponse.json({
          scan_type: "mr", source_repo: "nodegoat",
          mr_base_ref: "main", mr_head_ref: "feature/xss",
        })),
    );
    renderList();
    await waitFor(() => expect(screen.getByText("ws-mr-1")).toBeInTheDocument());
    expect(screen.queryByRole("button", { name: /续跑/ })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: /重跑/ }));
    await waitFor(() => expect(navMock).toHaveBeenCalled());
    expect(navMock).toHaveBeenCalledWith("/scan/new?workspace=ws", {
      state: {
        type: "mr", workspace: "ws", repo: "nodegoat",
        mrBaseRef: "main", mrHeadRef: "feature/xss",
      },
    });
  });
});

describe("ScanList 表格设计不变量（重设计 2026-08-15：漏洞数 hero 呈现）", () => {
  it("vuln_count > 0：漏洞数以 mono + 红色呈现（醒目）", async () => {
    server.use(http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([completed])));
    renderList();
    await waitFor(() => expect(screen.getByText("s2")).toBeInTheDocument());
    // 漏洞单元格：mono 大号 + text-red
    const v = screen.getByTestId("row-vulns-s2");
    expect(v.textContent).toBe("3");
    expect(v.className).toMatch(/font-mono/);
    expect(v.className).toMatch(/text-red/);
  });

  it("vuln_count = 0：漏洞值中性色（不染红，避免空扫描虚警）", async () => {
    server.use(http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([running])));
    renderList();
    await waitFor(() => expect(screen.getByText("s1")).toBeInTheDocument());
    const v = screen.getByTestId("row-vulns-s1");
    expect(v.textContent).toBe("0");
    expect(v.className).toMatch(/font-mono/);
    expect(v.className).not.toMatch(/text-red/);
    // v4：0 进一步弱化为 muted（低于正文亮度，视觉降噪）
    expect(v.className).toMatch(/text-muted-foreground/);
  });

  it("花费以 mono 呈现", async () => {
    server.use(http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([completed])));
    renderList();
    await waitFor(() => expect(screen.getByText("s2")).toBeInTheDocument());
    expect(screen.getByText("$2.00")).toBeInTheDocument();
  });

  it("状态分段过滤：点「已完成」只剩 completed 行", async () => {
    server.use(http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([running, completed])));
    renderList();
    await waitFor(() => expect(screen.getByText("s1")).toBeInTheDocument());
    // 分段计数：全部按钮 textContent = 「全部2」（直接文本 + 计数 span）
    const allBtn = screen.getByText("全部", { selector: "button" });
    expect(allBtn.textContent).toBe("全部2");
    fireEvent.click(screen.getByText("已完成", { selector: "button" }));
    expect(screen.queryByText("s1")).not.toBeInTheDocument();
    expect(screen.getByText("s2")).toBeInTheDocument();
  });
});

// v4（workspace-page-preview-v4.html）：整行可点 + 空工作区收敛。
describe("ScanList 运行行实时进度（2026-08-27 修复：列表进度不动）", () => {
  // 根因：progress_pct 分子 completed_agents 只在 workflow 结束落盘 session.json，
  // 运行中恒定 → 列表进度条钉死。修复：运行行 fold 已订阅的 SSE 归并流（与详情页
  // ScanProgressOverview 同一 dashboardReducer 口径）取 completed_units/total_units。
  it("SSE 事件驱动进度：2 步完成 1 步 -> 50%（非 progress_pct 的 5%）", async () => {
    sseState.events = [
      { type: "PhaseEvent", phase: "recon", event: "start", steps: ["step-a", "step-b"], step_intents: ["", ""] },
      { type: "StepEvent", name: "step-a", phase: "recon", event: "complete" },
    ];
    server.use(http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([running])));
    renderList();
    expect(await screen.findByText("50%")).toBeInTheDocument();
  });

  it("SSE 无事件回退 progress_pct（连接建立前 / precheck 期无 PhaseEvent）", async () => {
    sseState.events = [];
    server.use(http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([running])));
    renderList();
    expect(await screen.findByText("5%")).toBeInTheDocument();
  });

  it("SSE 事件但 phase 未声明 steps（total=0）-> 仍回退 progress_pct", async () => {
    sseState.events = [
      { type: "PhaseEvent", phase: "precheck", event: "start" },
    ];
    server.use(http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([running])));
    renderList();
    expect(await screen.findByText("5%")).toBeInTheDocument();
  });

  // 2026-08-28 组合口径修正：reducer 是「当前 phase」口径（PhaseEvent(start) 重置
  // units），白盒最后 phase 收尾后 fold=N/N=100% 而黑盒未跑——列表行按 src 源标记
  // 套三阶段加权（白盒 5+50×ratio / 黑盒 55+45×ratio，对齐后端 _compute_progress_pct）。
  it("首轮 SSE 回放未追平时保持 API 快照，ready 后再切实时值", async () => {
    sseState.events = [
      { type: "PhaseEvent", phase: "recon", event: "start", steps: ["a", "b"], step_intents: ["", ""] },
      { type: "StepEvent", name: "a", phase: "recon", event: "complete" },
    ];
    sseState.hydrated = false;
    server.use(http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([running])));
    const view = renderList();
    expect(await screen.findByText("5%" /* API progress_pct */)).toBeInTheDocument();

    sseState.hydrated = true;
    view.rerender(
      <MemoryRouter initialEntries={["/p/ws"]}>
        <Routes><Route path="/p/:workspace" element={<ScanList />} /></Routes>
      </MemoryRouter>,
    );
    expect(screen.getByText("50%")).toBeInTheDocument();
  });

  it("历史回放切 phase 时进度不倒退", async () => {
    sseState.events = [
      { type: "PhaseEvent", phase: "setup", event: "start", steps: ["a", "b"], step_intents: ["", ""], src: "wb" },
      { type: "StepEvent", name: "a", phase: "setup", event: "complete", src: "wb" },
    ];
    server.use(http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([running])));
    const view = renderList();
    expect(await screen.findByText("50%")).toBeInTheDocument();

    // 新 phase 的当前 fold 回到 0；列表展示应保持已走过的 50%。
    sseState.events = [
      ...sseState.events,
      { type: "PhaseEvent", phase: "recon", event: "start", steps: ["next"], step_intents: [""], src: "wb" },
    ];
    view.rerender(
      <MemoryRouter initialEntries={["/p/ws"]}>
        <Routes><Route path="/p/:workspace" element={<ScanList />} /></Routes>
      </MemoryRouter>,
    );
    expect(screen.getByText("50%")).toBeInTheDocument();
    expect(screen.queryByText("0%")).not.toBeInTheDocument();
  });

  it("组合扫描白盒段满格 -> 55% 而非 100%（黑盒未跑不谎报完成）", async () => {
    sseState.events = [
      { type: "PhaseEvent", phase: "recon", event: "start", steps: ["step-a", "step-b"], step_intents: ["", ""], src: "wb" },
      { type: "StepEvent", name: "step-a", phase: "recon", event: "complete", src: "wb" },
      { type: "StepEvent", name: "step-b", phase: "recon", event: "complete", src: "wb" },
    ];
    server.use(http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([
      { ...running, scan_id: "s-comb", workflow_id: "ws-s-comb", combined: true, bb_phase: "pending" },
    ])));
    renderList();
    expect(await screen.findByText("55%")).toBeInTheDocument();
    expect(screen.queryByText("100%")).not.toBeInTheDocument();
  });

  it("组合扫描黑盒段（run-K 源）-> 55+45×ratio；2 步完成 1 -> 78%", async () => {
    sseState.events = [
      { type: "PhaseEvent", phase: "exploitation", event: "start", steps: ["inj-exploit", "xss-exploit"], step_intents: ["", ""], src: "run-1" },
      { type: "StepEvent", name: "inj-exploit", phase: "exploitation", event: "complete", src: "run-1" },
    ];
    server.use(http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([
      { ...running, scan_id: "s-comb", workflow_id: "ws-s-comb", combined: true, bb_phase: "running" },
    ])));
    renderList();
    expect(await screen.findByText("78%")).toBeInTheDocument();
  });

  it("组合扫描黑盒 preflight 空窗（run-K 源、steps=[]）-> 55% 起点非 0/非回退", async () => {
    sseState.events = [
      { type: "PhaseEvent", phase: "preflight", event: "start", steps: [], step_intents: [], src: "run-1" },
    ];
    server.use(http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([
      { ...running, scan_id: "s-comb", workflow_id: "ws-s-comb", combined: true, bb_phase: "running" },
    ])));
    renderList();
    expect(await screen.findByText("55%")).toBeInTheDocument();
  });
});

describe("ScanList v4：整行可点 + 空态收敛", () => {
  it("点击行非交互区 -> 导航到默认 tab（completed -> report）", async () => {
    server.use(http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([completed])));
    renderList();
    await waitFor(() => expect(screen.getByText("s2")).toBeInTheDocument());
    // 点花费单元格（非交互且文案唯一——「已完成」会同时命中状态徽标与过滤分段按钮）
    fireEvent.click(screen.getByText("$2.00"));
    await waitFor(() => expect(navMock).toHaveBeenCalledWith("/p/ws/scans/s2/report"));
  });

  it("操作按钮点击不触发行导航（stopPropagation）", async () => {
    server.use(http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([completed])));
    renderList();
    await waitFor(() => expect(screen.getByText("s2")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: /删除/ }));
    expect(await screen.findByText(/删除扫描 s2/)).toBeInTheDocument();
    expect(navMock).not.toHaveBeenCalled();
  });

  it("空态：过滤器 + 列表头 CTA 隐藏；空态卡唯一 CTA + 仓库/认证次级入口", async () => {
    server.use(http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([])));
    renderList();
    await waitFor(() => expect(screen.getByText(/尚无扫描任务/)).toBeInTheDocument());
    // 过滤器整体隐藏（无对象可过滤）
    expect(screen.queryByText("全部", { selector: "button" })).not.toBeInTheDocument();
    expect(screen.queryByPlaceholderText("搜索 scan / workflow / repo…")).not.toBeInTheDocument();
    // CTA 唯一化：列表头 CTA 移除，仅空态卡一个「新建扫描」
    expect(screen.getAllByRole("link", { name: /新建扫描/ })).toHaveLength(1);
    // 次级入口：先配置仓库 / 配置认证档案（对应命令栏入口）
    expect(screen.getByRole("link", { name: /先配置仓库/ })).toHaveAttribute("href", "/p/ws/repos");
    expect(screen.getByRole("link", { name: /配置认证档案/ })).toHaveAttribute("href", "/p/ws/auth-profiles");
  });
});

// D4（2026-08-24）：correlation 主行 + 嵌套子行列——类型过滤「跨仓关联」档、
// 🔗 状态徽标、展开三种子行（现扫子仓白盒 / 黑盒验证 run / 复用引用）。
describe("ScanList correlation 主行 + 嵌套子行（D4）", () => {
  it("corr 主行默认收起；展开后三种子行：现扫子仓白盒 / 黑盒验证 run / 复用引用", async () => {
    server.use(http.get("/api/workspaces/:ws/scans",
      () => HttpResponse.json([corrMain, corrChildScan, corrHistScan])));
    renderList();
    await waitFor(() => expect(screen.getByText("ws-corr-1")).toBeInTheDocument());
    // 收起态：三种子行均不渲染（嵌套行默认收起，列表扫读优先）
    expect(screen.queryByTestId("nested-runs")).not.toBeInTheDocument();
    expect(screen.queryByTestId("corr-child-child-1")).not.toBeInTheDocument();
    expect(screen.queryByTestId("corr-child-hist-9")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "展开关联子行" }));
    // ① 现扫子仓白盒行：链接 /p/{ws}/scans/{child.scan_id} + 同 ws 列表富化
    //    （service 名 / 状态徽标 / 漏洞数），列对齐主表网格
    const fresh = await screen.findByTestId("corr-child-child-1");
    expect(within(fresh).getByRole("link", { name: "ws-child-1" })).toHaveAttribute(
      "href", "/p/ws/scans/child-1");
    expect(within(fresh).getByText("frontend")).toBeInTheDocument();
    expect(within(fresh).getByText("已完成")).toBeInTheDocument();
    expect(within(fresh).getByTestId("corr-child-vulns-child-1").textContent).toBe("2");
    // ② 黑盒验证 run 行：既有 NestedBlackboxRuns 渲染复用（?run= 选中）
    const runs = screen.getByTestId("nested-runs");
    expect(within(runs).getByRole("link", { name: "run-1" })).toHaveAttribute(
      "href", "/p/ws/scans/corr-1?run=run-1");
    // ③ 复用子仓引用行：链接历史 scan + 「复用」标注
    const reused = screen.getByTestId("corr-child-hist-9");
    expect(within(reused).getByRole("link", { name: "ws-hist-9" })).toHaveAttribute(
      "href", "/p/ws/scans/hist-9");
    expect(within(reused).getByText("复用")).toBeInTheDocument();
  });

  it("corr 主行状态徽标与普通行同构（无 🔗 后缀）；跨仓类型归属在类型列徽标", async () => {
    server.use(http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([corrMain])));
    renderList();
    await waitFor(() => expect(screen.getByText("ws-corr-1")).toBeInTheDocument());
    // 2026-09-10 状态图标统一：状态徽标 = 图标 + 状态文案（无 🔗 后缀——曾撑爆
    // 112px 状态列致换行挤两行）；「跨仓关联」类型徽标在类型列承载归属。
    // 「已完成」与过滤器分段按钮同名，用 title 精确定位状态徽标本体
    const badge = screen.queryByTitle("completed");
    expect(badge).toBeInTheDocument();
    expect(badge?.textContent).toBe("已完成");
    expect(screen.queryByText(/🔗/)).not.toBeInTheDocument();
    expect(screen.getByText("跨仓关联")).toBeInTheDocument();
  });

  it("类型过滤「跨仓关联」档：关联行入选；combined=True 也不漏进「组合」档", async () => {
    server.use(http.get("/api/workspaces/:ws/scans",
      () => HttpResponse.json([running, corrMain])));
    renderList();
    await waitFor(() => expect(screen.getByText("s1")).toBeInTheDocument());
    // 选「组合」：纯白盒 s1 与关联主行（虽 combined=True）都不在
    fireEvent.click(screen.getByText("全部类型").closest("button")!);
    fireEvent.click(await screen.findByRole("option", { name: "组合（白盒+黑盒）" }));
    expect(screen.queryByText("s1")).not.toBeInTheDocument();
    expect(screen.queryByText("ws-corr-1")).not.toBeInTheDocument();
    // 切「跨仓关联」：只剩关联主行
    fireEvent.click(screen.getByText("组合（白盒+黑盒）").closest("button")!);
    fireEvent.click(await screen.findByRole("option", { name: "跨仓关联" }));
    expect(screen.queryByText("s1")).not.toBeInTheDocument();
    expect(screen.getByText("ws-corr-1")).toBeInTheDocument();
  });

  it("复用子仓引用行链接历史 scan；历史行已删（不在列表）仍可渲染跳转（富化 null-safe）", async () => {
    server.use(http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([
      { ...corrMain, corr_children: [{ service: "order", scan_id: "gone-1", reused: true }] },
    ])));
    renderList();
    await waitFor(() => expect(screen.getByText("ws-corr-1")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "展开关联子行" }));
    const reused = await screen.findByTestId("corr-child-gone-1");
    // 标签回落 scan_id（无富化 workflow_id），链接仍指历史 scan
    expect(within(reused).getByRole("link", { name: "gone-1" })).toHaveAttribute(
      "href", "/p/ws/scans/gone-1");
    expect(within(reused).getByText("复用")).toBeInTheDocument();
    // 富化缺失：漏洞数弱「—」占位（不空白不报错）
    expect(within(reused).getByTestId("corr-child-vulns-gone-1").textContent).toBe("—");
  });
});

// === correlation 主行：子仓源事件不进列表行进度/阶段（2026-09-10 归并流扩子仓）===
describe("ScanList correlation 主行子仓源过滤", () => {
  const corrRunning = {
    scan_id: "corr-1", scan_type: "correlation", status: "running", created_at: 1000,
    completed_at: null, vuln_count: 0, total_cost_usd: 0, cost_currency: "USD",
    is_running: true, progress_pct: 5, combined: true,
  } as const;

  it("子仓白盒 PhaseEvent（src=c-*）不重置 correlation 网格——进度仍是主行 repo 完成度", async () => {
    sseState.events = [
      { type: "correlation_progress", node: "repo", name: "gateway", status: "completed", ts: "t1", category: "CONTROL", src: "wb" },
      { type: "correlation_progress", node: "repo", name: "order-svc", status: "completed", ts: "t2", category: "CONTROL", src: "wb" },
      { type: "PhaseEvent", phase: "recon", event: "start", steps: ["a", "b"], step_intents: ["", ""], ts: "t3", category: "PHASE", src: "c-gw-123", service: "gateway" },
      { type: "StepEvent", name: "a", phase: "recon", event: "complete", ts: "t4", category: "STEP", src: "c-gw-123" },
    ];
    server.use(http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([corrRunning])));
    renderList();
    expect(await screen.findByText("100%")).toBeInTheDocument();
  });

  it("子仓 PhaseEvent 不冒充主行阶段副标签（过滤后无 PhaseEvent → 无后缀）", async () => {
    sseState.events = [
      { type: "PhaseEvent", phase: "recon", event: "start", ts: "t1", category: "PHASE", src: "c-gw-123", service: "gateway" },
    ];
    server.use(http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([corrRunning])));
    renderList();
    await screen.findByText("corr-1");
    expect(screen.queryByText(/recon/)).not.toBeInTheDocument();
  });
});
