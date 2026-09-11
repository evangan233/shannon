import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach } from "vitest";
import { screen, cleanup, waitFor, fireEvent } from "@testing-library/react";
import { renderWithSwr } from "@/test/swr-render";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { setupServer } from "msw/node";
import { http, HttpResponse } from "msw";
import i18n from "@/i18n";
import WorkspaceDetail from "./index";

// MemberManagerDialog 依赖 AuthProvider + 自有成员 API；ws 概览测试聚焦 header/入口/404，
// 隔离该子组件（其行为在 MemberManagerDialog.test.tsx 独立覆盖）。
vi.mock("@/components/MemberManagerDialog", () => ({
  MemberManagerDialog: () => null,
}));

// Task 9：WorkspaceDetail header 新增置顶按钮（useAuth）+ WorkspaceSwitcher 入口
// （useAuth + useWorkspaces）。ws 概览测试聚焦 header/入口/404，隔离这些 hook 的真实
// 网络与 provider 依赖（其行为在 WorkspaceSwitcher.test.tsx 独立覆盖）。
vi.mock("@/auth/AuthContext", () => ({
  useAuth: () => ({
    user: { id: 1, username: "admin", role: "admin", must_change_password: false },
    loading: false,
    login: vi.fn(),
    logout: vi.fn(),
    refreshUser: vi.fn(),
  }),
}));

vi.mock("@/api/useWorkspaces", () => ({
  useWorkspaces: () => ({
    data: [],
    loading: false,
    lastUpdated: new Date(),
    error: null,
    refresh: vi.fn(),
  }),
}));

const server = setupServer(
  // Hero/指标条聚合数据源：GET /workspaces/{ws}/scans（旧 GET /workspaces/{ws} shim 已移除）。
  http.get("/api/workspaces/:ws/scans", () =>
    HttpResponse.json([
      { scan_id: "s1", scan_type: "whitebox", status: "running", created_at: 2000,
        vuln_count: 0, is_running: true, workflow_id: "ws-s1" },
      { scan_id: "s2", scan_type: "blackbox", status: "completed", created_at: 1000,
        completed_at: 1500, vuln_count: 0, is_running: false, workflow_id: "ws-s2" },
    ]),
  ),
);

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
beforeEach(() => i18n.changeLanguage("zh"));
afterEach(() => {
  server.resetHandlers();
  cleanup();
  i18n.changeLanguage("zh");
});
afterAll(() => server.close());

// index/repos/settings 用占位 div 替换，聚焦 WorkspaceDetail 布局本身（header + Outlet），
// 不引入 ScanList/ReposTab 的自有请求。
function renderAt(initialPath: string) {
  return renderWithSwr(
    <MemoryRouter initialEntries={[initialPath]}>
      <Routes>
        <Route path="/p/:workspace" element={<WorkspaceDetail />}>
          <Route index element={<div>scanlist-content</div>} />
          <Route path="repos" element={<div>repos-content</div>} />
          <Route path="settings" element={<div>settings-content</div>} />
          <Route path="auth-profiles" element={<div>auth-profiles-content</div>} />
          <Route path="auth-profiles/:pid" element={<div>auth-profile-test-content</div>} />
          <Route path="host-profiles" element={<div>host-profiles-content</div>} />
        </Route>
      </Routes>
    </MemoryRouter>,
  );
}

describe("WorkspaceDetail ws 概览", () => {
  it("渲染 ws 名 + 返回列表链接 + 仓库/settings 入口", async () => {
    renderAt("/p/ws");
    expect(screen.getByText("ws")).toBeInTheDocument();
    expect(screen.getByText(/返回列表/)).toBeInTheDocument();
    // 仓库入口链接（含「仓库」文案）
    expect(screen.getByRole("link", { name: /仓库/ })).toBeInTheDocument();
    // settings 入口（齿轮，aria-label 来自 wsConfig.openSettings）
    expect(screen.getByRole("link", { name: /配置|settings/i })).toBeInTheDocument();
    // index Outlet 渲染扫描列表占位
    expect(screen.getByText("scanlist-content")).toBeInTheDocument();
  });

  it("Hero 显扫描任务数聚合（scans.length），不显 latest 状态徽标", async () => {
    renderAt("/p/ws");
    // 聚合 2 条扫描 → 「扫描任务 · 2」；成功/失败是单项扫描任务的概念，头部无状态徽标
    await waitFor(() => expect(screen.getByText(/扫描任务 · 2/)).toBeInTheDocument());
    expect(document.querySelector("[title='running']")).not.toBeInTheDocument();
  });

  it("累计发现大数字（Hero 威胁信号）", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans", () =>
        HttpResponse.json([
          { scan_id: "s1", scan_type: "whitebox", status: "completed", created_at: 1000,
            completed_at: 2000, vuln_count: 3, vuln_counts: { xss: 2, ssrf: 1 }, is_running: false },
        ]),
      ),
    );
    renderAt("/p/ws");
    // 3 发现 → 红色大数字 + 谱带图例（类别 xss/ssrf；锚定整词避免命中指标条 ctx 副行）
    const big = await screen.findByTestId("ws-hero-findings");
    expect(big.textContent).toBe("3");
    expect(big.className).toMatch(/text-red/);
    // mini 谱带：红色威胁通道（与红数字同语义），非品牌色 primary（mac 下蓝会弱化危害感）
    const bar = document.querySelector('[data-testid="ws-composition-bar"]');
    expect(bar?.innerHTML).toContain("bg-red");
    expect(bar?.innerHTML).not.toContain("bg-primary");
    expect(screen.getByText(/^xss 2$/)).toBeInTheDocument();
    expect(screen.getByText(/^ssrf 1$/)).toBeInTheDocument();
  });

  it("点击仓库入口 -> 导航到 repos", async () => {
    renderAt("/p/ws");
    const { fireEvent } = await import("@testing-library/react");
    fireEvent.click(screen.getByRole("link", { name: /仓库/ }));
    await waitFor(() => expect(screen.getByText("repos-content")).toBeInTheDocument());
  });

  it("渲染认证管理入口 + 导航到 auth-profiles", async () => {
    renderAt("/p/ws");
    // header 显「认证」入口（aria-label = authProfiles.openLabel）
    const authLink = await screen.findByRole("link", { name: "认证" });
    expect(authLink).toBeInTheDocument();
    const { fireEvent } = await import("@testing-library/react");
    fireEvent.click(authLink);
    await waitFor(() => expect(screen.getByText("auth-profiles-content")).toBeInTheDocument());
  });

  it("返回列表链接渲染（中文）", () => {
    renderAt("/p/ws");
    expect(screen.getByText(/返回列表/)).toBeInTheDocument();
  });
});

// 区段导航（2026-08-17）：命令栏 ‖ 右侧 = 扫描(index)/仓库/认证/HOST/设置 五区段，
// 当前区段 secondary 高亮（aria-current=page）；子页可点「扫描」回任务列表
// （此前 index 路由无入口，点进子页只能靠浏览器后退）。
describe("WorkspaceDetail 区段导航", () => {
  it("index 下「扫描」高亮，其余区段不高亮", () => {
    renderAt("/p/ws");
    expect(screen.getByRole("link", { name: "扫描" })).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("link", { name: /仓库/ })).not.toHaveAttribute("aria-current");
    expect(screen.getByRole("link", { name: "认证" })).not.toHaveAttribute("aria-current");
    expect(screen.getByRole("link", { name: "HOST" })).not.toHaveAttribute("aria-current");
  });

  it("repos 子页：「仓库」高亮 + 点「扫描」回到扫描列表", async () => {
    renderAt("/p/ws/repos");
    expect(screen.getByRole("link", { name: /仓库/ })).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("link", { name: "扫描" })).not.toHaveAttribute("aria-current");
    fireEvent.click(screen.getByRole("link", { name: "扫描" }));
    await waitFor(() => expect(screen.getByText("scanlist-content")).toBeInTheDocument());
  });

  it("auth-profiles 子页：点「扫描」回到扫描列表", async () => {
    renderAt("/p/ws/auth-profiles");
    fireEvent.click(screen.getByRole("link", { name: "扫描" }));
    await waitFor(() => expect(screen.getByText("scanlist-content")).toBeInTheDocument());
  });

  it("认证详情子路由（auth-profiles/:pid）：「认证」父区段保持高亮", () => {
    renderAt("/p/ws/auth-profiles/p1");
    expect(screen.getByRole("link", { name: "认证" })).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("link", { name: "扫描" })).not.toHaveAttribute("aria-current");
  });

  it("HOST 入口存在且导航到 host-profiles", async () => {
    renderAt("/p/ws");
    fireEvent.click(screen.getByRole("link", { name: "HOST" }));
    await waitFor(() => expect(screen.getByText("host-profiles-content")).toBeInTheDocument());
  });

  it("settings 子页：设置按钮高亮", () => {
    renderAt("/p/ws/settings");
    expect(screen.getByRole("link", { name: /配置|settings/i })).toHaveAttribute("aria-current", "page");
  });
});

describe("WorkspaceDetail ws 概览 i18n", () => {
  it("切英文 -> 返回列表 + 仓库入口为英文", async () => {
    i18n.changeLanguage("en");
    renderAt("/p/ws");
    expect(screen.getByText(/Back to list/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Repositories/ })).toBeInTheDocument();
  });
});

describe("WorkspaceDetail ws 概览 notFound", () => {
  it("404 -> 显 notFound 消息（中文）", async () => {
    server.use(http.get("/api/workspaces/:ws/scans", () => HttpResponse.json({ detail: "nope" }, { status: 404 })));
    renderAt("/p/ghost");
    await waitFor(() => expect(screen.getByText(/工作区不存在或已被删除/)).toBeInTheDocument());
    expect(screen.getByText(/返回列表/)).toBeInTheDocument();
  });

  it("404 + 切英文 -> notFound 消息英文", async () => {
    i18n.changeLanguage("en");
    server.use(http.get("/api/workspaces/:ws/scans", () => HttpResponse.json({ detail: "nope" }, { status: 404 })));
    renderAt("/p/ghost");
    await waitFor(() => expect(screen.getByText(/does not exist or has been deleted/i)).toBeInTheDocument());
    expect(screen.getByText(/Back to list/)).toBeInTheDocument();
  });
});

// v2（overview-workspace-redesign-preview 2026-08-16）：工作台头（两行紧凑卡）替代
// Hero 大卡 + 四格指标条——r1 徽标 + r2 一行 mono 统计摘要。
describe("WorkspaceDetail v2 工作台头统计摘要（r2）", () => {
  it("r2 = 累计发现 + 运行中 + 需关注 + 分币种花费 + 最新；旧四格标签（最近完成/平均耗时）不再渲染", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans", () =>
        HttpResponse.json([
          { scan_id: "s1", scan_type: "whitebox", status: "completed", created_at: 4000,
            completed_at: 5000, vuln_count: 34, vuln_counts: { xss: 34 }, is_running: false, workflow_id: "ws-s1",
            total_duration_ms: 3_600_000, total_cost_usd: 16.47, cost_currency: "CNY" },
          { scan_id: "s2", scan_type: "whitebox", status: "completed", created_at: 2000,
            completed_at: 3000, vuln_count: 0, is_running: false,
            total_duration_ms: 7_200_000, total_cost_usd: 28.75, cost_currency: "USD" },
          { scan_id: "s3", scan_type: "blackbox", status: "failed", created_at: 3000,
            vuln_count: 0, is_running: false },
          { scan_id: "s4", scan_type: "blackbox", status: "interrupted", created_at: 1000,
            vuln_count: 0, is_running: false },
        ]),
      ),
    );
    renderAt("/p/ws");
    // 累计发现 34（红色）+ mini 谱带图例
    const big = await screen.findByTestId("ws-hero-findings");
    expect(big.textContent).toBe("34");
    expect(big.className).toMatch(/text-red/);
    expect(screen.getByText(/^xss 34$/)).toBeInTheDocument();
    // r2 各段标签与值
    expect(screen.getByText("累计花费")).toBeInTheDocument();
    expect(screen.getByText("需关注")).toBeInTheDocument();
    // 分币种：金额降序 USD 在前——紧凑「$29 + ¥16」
    expect(screen.getByTestId("ws-cost-num").textContent).toBe("$29 + ¥16");
    // 需关注：失败 1 + 中断 1 = 2（ctx 逐项标注）
    expect(screen.getByTestId("ws-attn-ctx").textContent).toContain("失败 1 · 中断 1");
    // 运行中段（0 运行中也渲染标签）
    expect(screen.getByText("运行中")).toBeInTheDocument();
    // 旧四格标签不再渲染（最近完成/平均耗时移除；耗时摘要归 ScanList 标题行）
    expect(screen.queryByText("最近完成")).not.toBeInTheDocument();
    expect(screen.queryByText("平均耗时")).not.toBeInTheDocument();
  });

  it("最新段链接化：latest completed -> 报告链接", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans", () =>
        HttpResponse.json([
          { scan_id: "s1", scan_type: "whitebox", status: "completed", created_at: 1000,
            completed_at: 2000, vuln_count: 1, is_running: false, workflow_id: "ws-s1" },
        ]),
      ),
    );
    renderAt("/p/ws");
    expect((await screen.findByRole("link", { name: "ws-s1" })).getAttribute("href"))
      .toBe("/p/ws/scans/s1/report");
  });

  it("组合 latest：r1 显「组合」徽标（类型模型只有白盒+组合）", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans", () =>
        HttpResponse.json([
          { scan_id: "s1", scan_type: "whitebox", status: "completed", created_at: 1000,
            completed_at: 2000, vuln_count: 0, is_running: false, combined: true },
        ]),
      ),
    );
    renderAt("/p/ws");
    expect(await screen.findByText("组合")).toBeInTheDocument();
  });

  it("运行中 latest：最新链接指向 live 且带进度百分比", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans", () =>
        HttpResponse.json([
          { scan_id: "s1", scan_type: "whitebox", status: "running", created_at: 1000,
            vuln_count: 0, is_running: true, workflow_id: "ws-s1", progress_pct: 64 },
        ]),
      ),
    );
    renderAt("/p/ws");
    expect((await screen.findByRole("link", { name: "ws-s1" })).getAttribute("href"))
      .toBe("/p/ws/scans/s1/live");
    expect(screen.getByText(/64%/)).toBeInTheDocument();
  });
});

describe("WorkspaceDetail v2 空工作区（从未扫描）", () => {
  it("中性「尚未扫描」徽标（不用绿色一切正常）+ 引导文案；r2 摘要整体不渲染", async () => {
    server.use(http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([])));
    renderAt("/p/ws");
    expect(await screen.findByText("尚未扫描")).toBeInTheDocument();
    // 绝不出现绿色 all-clear 文案
    expect(screen.queryByText("一切正常")).not.toBeInTheDocument();
    expect(screen.getByText(/开始第一次扫描以建立安全基线/)).toBeInTheDocument();
    // r2 统计摘要整体不渲染（空工作区无数字可显）
    expect(screen.queryByText("累计花费")).not.toBeInTheDocument();
    expect(screen.queryByText("需关注")).not.toBeInTheDocument();
    expect(screen.queryByTestId("ws-hero-findings")).not.toBeInTheDocument();
  });
});
