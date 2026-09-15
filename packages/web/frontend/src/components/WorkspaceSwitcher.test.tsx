import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import i18n from "@/i18n";
import { WorkspaceSwitcher } from "./WorkspaceSwitcher";

const { mockRefresh, mockDeleteWorkspace, mockNav, mockUseAuth } = vi.hoisted(() => ({
  mockRefresh: vi.fn().mockResolvedValue(undefined),
  mockDeleteWorkspace: vi.fn().mockResolvedValue({ deleted: "ws-a" }),
  mockNav: vi.fn(),
  mockUseAuth: vi.fn(),
}));

vi.mock("@/api/useWorkspaces", () => ({
  useWorkspaces: () => ({
    data: [
      { name: "ws-a", status: "running", scan_type: "whitebox", created_at: 1, scan_count: 2, vuln_count: 5, total_cost_usd: 3.42, cost_currency: "CNY" },
      { name: "ws-b", status: "completed", scan_type: "blackbox", created_at: 2, scan_count: 1, vuln_count: 0, total_cost_usd: 1.1, cost_currency: "USD" },
      // ws-c 模拟旧后端（Phase 1 未上线）缺字段 → null-safe 回退 0/—
      { name: "ws-c", status: "failed", scan_type: "whitebox", created_at: 3 },
      // ws-d 模拟新后端：cost_by_currency 分币种（跨全部 scans 聚合）
      { name: "ws-d", status: "completed", scan_type: "whitebox", created_at: 4, scan_count: 7, vuln_count: 4, cost_by_currency: { CNY: 7.8, USD: 2.5 } },
    ],
    loading: false, lastUpdated: new Date(), error: null, refresh: mockRefresh,
  }),
}));

vi.mock("@/auth/AuthContext", () => ({ useAuth: () => mockUseAuth() }));

vi.mock("@/api/client", () => ({ deleteWorkspace: (...a: any[]) => mockDeleteWorkspace(...a) }));

vi.mock("react-router-dom", async (orig) => {
  const actual = await orig() as any;
  return { ...actual, useNavigate: () => mockNav };
});

vi.mock("@/components/CreateWorkspaceDialog", () => ({
  CreateWorkspaceDialog: () => <div data-testid="create-ws-dialog" />,
}));

const userAdmin = { id: 1, username: "admin", role: "admin", must_change_password: false };
const userUser = { id: 2, username: "alice", role: "user", must_change_password: false };

// jsdom navigator.language 默认 en，LanguageDetector 会把 i18n 切到 en；
// 断言依赖中文渲染（getByRole button name=/切换/i），逐测试钉回 zh。
beforeEach(() => {
  vi.clearAllMocks();
  mockUseAuth.mockReturnValue({ user: userAdmin });
  return i18n.changeLanguage("zh");
});

function renderIt(currentWs = "ws-a") {
  return render(<MemoryRouter><WorkspaceSwitcher currentWorkspace={currentWs} /></MemoryRouter>);
}

describe("WorkspaceSwitcher", () => {
  it("opens drawer on trigger click and lists workspaces", async () => {
    renderIt();
    fireEvent.click(screen.getByRole("button", { name: /切换/i }));
    await waitFor(() => expect(screen.getByText("ws-a")).toBeInTheDocument());
    expect(screen.getByText("ws-b")).toBeInTheDocument();
  });

  it("highlights current workspace", async () => {
    renderIt("ws-a");
    fireEvent.click(screen.getByRole("button", { name: /切换/i }));
    await waitFor(() => expect(screen.getByText("ws-a")).toBeInTheDocument());
    expect(screen.getByText("ws-a").closest("[data-current]")).toHaveAttribute("data-current", "true");
  });

  it("search filters list", async () => {
    renderIt();
    fireEvent.click(screen.getByRole("button", { name: /切换/i }));
    fireEvent.change(screen.getByPlaceholderText(/搜索/), { target: { value: "ws-b" } });
    expect(screen.queryByText("ws-a")).not.toBeInTheDocument();
    expect(screen.getByText("ws-b")).toBeInTheDocument();
  });

  it("shows create-workspace entry for admin", async () => {
    renderIt();
    fireEvent.click(screen.getByRole("button", { name: /切换/i }));
    await waitFor(() => expect(screen.getByTestId("create-ws-dialog")).toBeInTheDocument());
  });
});

describe("WorkspaceSwitcher 状态卡重做（spec 2026-07-28：加宽 + 详情 + 单 X）", () => {
  beforeEach(() => {
    mockUseAuth.mockReturnValue({ user: userAdmin });
  });

  it("仅渲染一个关闭按钮（修复双 X bug）", async () => {
    renderIt();
    fireEvent.click(screen.getByRole("button", { name: /切换/i }));
    await waitFor(() => expect(screen.getByText("ws-a")).toBeInTheDocument());
    // DialogContent 内置单个 close（sr-only "Close"），不再有手写 X
    expect(screen.getAllByRole("button", { name: /^close$/i })).toHaveLength(1);
  });

  it("每行展示漏洞/花费/扫描详情（aria-label 含完整口径）", async () => {
    renderIt("ws-a");
    fireEvent.click(screen.getByRole("button", { name: /切换/i }));
    await waitFor(() => expect(screen.getByText("ws-a")).toBeInTheDocument());
    const rowA = screen.getByText("ws-a").closest("[data-current]") as HTMLElement;
    expect(rowA.getAttribute("aria-label")).toContain("5 个漏洞");
    expect(rowA.getAttribute("aria-label")).toContain("¥3.42");
    expect(rowA.getAttribute("aria-label")).toContain("2 次扫描");
  });

  it("缺字段回退 null-safe（旧后端 ws-c：0 漏洞 / — 花费 / 0 扫描）", async () => {
    renderIt("ws-a");
    fireEvent.click(screen.getByRole("button", { name: /切换/i }));
    await waitFor(() => expect(screen.getByText("ws-c")).toBeInTheDocument());
    const rowC = screen.getByText("ws-c").closest("[data-current]") as HTMLElement;
    expect(rowC.getAttribute("aria-label")).toContain("0 个漏洞");
    expect(rowC.getAttribute("aria-label")).toContain("—");
    expect(rowC.getAttribute("aria-label")).toContain("0 次扫描");
  });

  it("顶部舰队汇总：累计漏洞 + 累计花费（分币种，跨币种直加是错值）", async () => {
    renderIt();
    fireEvent.click(screen.getByRole("button", { name: /切换/i }));
    await waitFor(() => expect(screen.getByText("ws-a")).toBeInTheDocument());
    // 漏洞 5+0+0+4=9；花费按币种分组：CNY 3.42+7.8≈11 / USD 1.1+2.5≈4 →「¥11 + $4」
    // （旧口径「币种取首个 ws + 直加」把 CNY/USD 加成一个数——¥4.52 是错值，已弃）
    expect(screen.getByText(/累计花费/)).toHaveTextContent("¥11 + $4");
  });

  it("行卡片花费：cost_by_currency 多币种紧凑渲染（新后端字段）", async () => {
    renderIt();
    fireEvent.click(screen.getByRole("button", { name: /切换/i }));
    await waitFor(() => expect(screen.getByText("ws-d")).toBeInTheDocument());
    const rowD = screen.getByText("ws-d").closest("[data-current]") as HTMLElement;
    expect(rowD.getAttribute("aria-label")).toContain("¥8 + $3");
    expect(rowD.getAttribute("aria-label")).toContain("4 个漏洞");
    expect(rowD.getAttribute("aria-label")).toContain("7 次扫描");
  });
});

describe("WorkspaceSwitcher admin 删除入口（spec 2026-07-27 下线 WorkspaceListPage：删除并入切换器）", () => {
  beforeEach(() => {
    mockUseAuth.mockReturnValue({ user: userAdmin });
  });

  it("admin: 每行显示 trash 删除按钮", async () => {
    renderIt();
    fireEvent.click(screen.getByRole("button", { name: /切换/i }));
    await waitFor(() => expect(screen.getByText("ws-a")).toBeInTheDocument());
    expect(screen.queryByTestId("switcher-delete-ws-a")).toBeInTheDocument();
    expect(screen.queryByTestId("switcher-delete-ws-b")).toBeInTheDocument();
  });

  it("admin: 点 trash→确认 Dialog→调 deleteWorkspace(name) + refresh（删非 current 不跳转）", async () => {
    mockDeleteWorkspace.mockResolvedValue({ deleted: "ws-b" });
    renderIt("ws-a"); // current=ws-a，删 ws-b
    fireEvent.click(screen.getByRole("button", { name: /切换/i }));
    await waitFor(() => expect(screen.getByText("ws-b")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("switcher-delete-ws-b"));
    const confirm = await screen.findByRole("button", { name: /^确认$/ });
    fireEvent.click(confirm);
    await waitFor(() => expect(mockDeleteWorkspace).toHaveBeenCalledWith("ws-b"));
    expect(mockRefresh).toHaveBeenCalled();
    expect(mockNav).not.toHaveBeenCalled();
  });

  it("admin: 删的是 currentWorkspace → nav('/')", async () => {
    renderIt("ws-a"); // current=ws-a，删自己
    fireEvent.click(screen.getByRole("button", { name: /切换/i }));
    await waitFor(() => expect(screen.getByText("ws-a")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("switcher-delete-ws-a"));
    const confirm = await screen.findByRole("button", { name: /^确认$/ });
    fireEvent.click(confirm);
    await waitFor(() => expect(mockDeleteWorkspace).toHaveBeenCalledWith("ws-a"));
    expect(mockNav).toHaveBeenCalledWith("/");
  });

  it("普通用户:无 trash 按钮（gate）", async () => {
    mockUseAuth.mockReturnValue({ user: userUser });
    renderIt();
    fireEvent.click(screen.getByRole("button", { name: /切换/i }));
    await waitFor(() => expect(screen.getByText("ws-a")).toBeInTheDocument());
    expect(screen.queryByTestId("switcher-delete-ws-a")).not.toBeInTheDocument();
  });
});
