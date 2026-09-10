import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, act } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { TopBar } from "./TopBar";
import i18n from "@/i18n";

// TopBar 集成 UserMenu（T17），UserMenu 用 useAuth。本测试聚焦 TopBar 业务（导航/i18n/sticky），
// 不测 auth 行为，故 stub useAuth 注入固定 user 避免 "useAuth 必须在 AuthProvider 内使用"。
// 用 vi.hoisted 暴露 mockUseAuth，逐测试切换 user.role 验证 admin 专属「工作区管理」入口。
const { mockUseAuth } = vi.hoisted(() => ({ mockUseAuth: vi.fn() }));
vi.mock("@/auth/AuthContext", () => ({ useAuth: () => mockUseAuth() }));
// TopBar 含 ThemeToggle（消费 useTheme）；本测试聚焦 TopBar 业务不测主题切换，stub useTheme 避免必须 ThemeProvider。
vi.mock("@/lib/theme-context", () => ({ useTheme: () => ({ theme: "dark", setTheme: vi.fn() }) }));

const userUser = { id: 1, username: "alice", role: "user", must_change_password: false };
const userAdmin = { id: 2, username: "root", role: "admin", must_change_password: false };

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="*" element={<TopBar />} />
      </Routes>
    </MemoryRouter>
  );
}

// 默认普通用户（admin 入口不渲染）；admin 专属 describe 内 beforeEach 覆写。
beforeEach(() => {
  mockUseAuth.mockReturnValue({ user: userUser, loading: false, login: vi.fn(), logout: vi.fn() });
});

describe("TopBar", () => {
  beforeEach(() => i18n.changeLanguage("zh"));

  it("品牌字标 Supernova + 主导航", () => {
    renderAt("/");
    expect(screen.getByText(/Supernova/i)).toBeInTheDocument();
    expect(screen.getByText("工作区")).toBeInTheDocument();
    expect(screen.getByText("扫描")).toBeInTheDocument();
  });

  it("Dashboard / Settings DSF 阶段 disabled（非 <a>）", () => {
    renderAt("/");
    const dash = screen.getByText("概览");
    const settings = screen.getByText("设置");
    expect(dash.tagName).not.toBe("A");
    expect(settings.tagName).not.toBe("A");
    expect(dash.closest("[aria-disabled='true']") ?? dash.parentElement?.closest("[aria-disabled='true']") ?? dash).toBeTruthy();
  });

  it("当前 /scan/new → Scan NavLink data-active=true", () => {
    renderAt("/scan/new");
    expect(screen.getByText("扫描").getAttribute("data-active")).toBe("true");
  });

  it("非当前路由 NavLink data-active=false", () => {
    renderAt("/");
    expect(screen.getByText("扫描").getAttribute("data-active")).toBe("false");
  });

  it("含主题切换入口", () => {
    renderAt("/");
    expect(screen.getByRole("button", { name: /切换主题/ })).toBeInTheDocument();
  });
});

describe("TopBar i18n", () => {
  beforeEach(() => i18n.changeLanguage("zh"));

  it("中文渲染主导航文本（工作区 + 扫描）", () => {
    render(
      <MemoryRouter>
        <TopBar />
      </MemoryRouter>
    );
    expect(screen.getByText("工作区")).toBeInTheDocument();
    expect(screen.getByText("扫描")).toBeInTheDocument();
  });

  it("切英文后导航 Workspaces / Scan 文本切换", async () => {
    render(
      <MemoryRouter>
        <TopBar />
      </MemoryRouter>
    );
    await act(async () => {
      await i18n.changeLanguage("en");
    });
    expect(screen.getByText("Workspaces")).toBeInTheDocument();
    expect(screen.getByText("Scan")).toBeInTheDocument();
  });

  it("P2: 顶级 /repos nav 已撤销（仓库迁入 ws 内 tab）", () => {
    render(
      <MemoryRouter>
        <TopBar />
      </MemoryRouter>
    );
    // 「仓库」/ Repositories 不再作为顶级 nav 项
    expect(screen.queryByText("仓库")).not.toBeInTheDocument();
  });

  it("渲染语言切换器", () => {
    render(
      <MemoryRouter>
        <TopBar />
      </MemoryRouter>
    );
    expect(screen.getByLabelText("切换语言")).toBeInTheDocument();
  });
});

describe("TopBar 工作区 nav active 判定", () => {
  beforeEach(() => i18n.changeLanguage("zh"));

  // 回归（2026-09-01 用户反馈）：「工作区」nav 的 to 是三段跳转中转 /workspaces-entry
  // （WorkspacesEntry 渲染 null 后立即 replace 走人，永不停留），真实工作区页在
  // /p/:ws 前缀下。NavLink 默认匹配只看 to → 在 /p/:ws 时工作区项永不高亮。
  it("/p/:ws 工作区详情页 → 工作区 data-active=true", () => {
    renderAt("/p/demo-ws");
    expect(screen.getByText("工作区").getAttribute("data-active")).toBe("true");
  });

  it("/p/:ws/scans/:id/... 扫描子页（隶属工作区）→ 工作区 data-active=true", () => {
    renderAt("/p/demo-ws/scans/scan-123/report");
    expect(screen.getByText("工作区").getAttribute("data-active")).toBe("true");
  });

  it("/workspaces-entry 中转（loading 瞬时停留）→ 工作区 data-active=true", () => {
    renderAt("/workspaces-entry");
    expect(screen.getByText("工作区").getAttribute("data-active")).toBe("true");
  });

  it("非工作区路由 → 工作区 data-active=false（不误亮）", () => {
    renderAt("/settings");
    expect(screen.getByText("工作区").getAttribute("data-active")).toBe("false");
  });
});

// 2026-09-10 用户反馈：点击顶栏「工作区」时，你在哪个工作区就跳回哪个工作区，
// 不强制跳到置顶（pinned）工作区。点击后 URL 已变 /workspaces-entry、来源丢失，
// 故由 TopBar 渲染时按当前路径覆写 to：命中 /p/:ws 直达本 ws；否则保持三段中转。
describe("TopBar 工作区入口跳回当前工作区", () => {
  beforeEach(() => i18n.changeLanguage("zh"));

  it("/p/:ws 扫描子页 →「工作区」直达本 ws 首页 /p/demo-ws（不走 /workspaces-entry）", () => {
    renderAt("/p/demo-ws/scans/scan-123/live");
    const link = screen.getByText("工作区").closest("a");
    expect(link).toHaveAttribute("href", "/p/demo-ws");
  });

  it("/p/:ws 首页 →「工作区」指向本 ws 自身", () => {
    renderAt("/p/demo-ws");
    const link = screen.getByText("工作区").closest("a");
    expect(link).toHaveAttribute("href", "/p/demo-ws");
  });

  it("非工作区路由（/scan/new）→ 保持 /workspaces-entry 三段跳转中转", () => {
    renderAt("/scan/new");
    const link = screen.getByText("工作区").closest("a");
    expect(link).toHaveAttribute("href", "/workspaces-entry");
  });
});

describe("TopBar sticky 吸顶", () => {
  beforeEach(() => i18n.changeLanguage("zh"));

  it("header 含 sticky/top-0/z-40/print:static（全局吸顶，低于弹窗 z-50）", () => {
    render(
      <MemoryRouter>
        <TopBar />
      </MemoryRouter>
    );
    const header = screen.getByTestId("topbar");
    expect(header.tagName).toBe("HEADER");
    expect(header.className).toContain("sticky");
    expect(header.className).toContain("top-0");
    expect(header.className).toContain("z-40");
    expect(header.className).toContain("print:static");
  });

  it("导航=浮层材质档（2026-08-25 mac 玻璃减法：TopBar 随浮层留玻璃，卡片实色）", () => {
    render(
      <MemoryRouter>
        <TopBar />
      </MemoryRouter>
    );
    const header = screen.getByTestId("topbar");
    // 2026-08-26 材质补课：--topbar-bg 消费（github #f6f8fa 灰带等主题级顶栏底色；
    // 未定义主题回落 popover——mac 半透磨砂/其余白）。与 --radius-cta 同一套
    // 「未定义即回落」var idiom。
    expect(header.className).toContain("bg-[hsl(var(--topbar-bg,var(--popover)))]");
    expect(header.className).toContain("[backdrop-filter:var(--backdrop-float,none)]");
  });

  it("nav 项挂 topbar-nav-item 语义类（mac 分段控件 CSS 的主题级挂钩）", () => {
    renderAt("/scan/new");
    const scan = screen.getByText("扫描");
    expect(scan.className).toContain("topbar-nav-item");
    expect(scan.getAttribute("data-active")).toBe("true");
  });
});

describe("TopBar admin 入口", () => {
  beforeEach(() => {
    i18n.changeLanguage("zh");
    mockUseAuth.mockReturnValue({ user: userAdmin, loading: false, login: vi.fn(), logout: vi.fn() });
  });

  it("下线 WorkspaceListPage：admin 也不再有「工作区管理」入口", () => {
    renderAt("/");
    expect(screen.queryByTestId("nav-workspace-manage")).not.toBeInTheDocument();
    expect(screen.queryByText("工作区管理")).not.toBeInTheDocument();
  });

  it("普通用户同样无「工作区管理」入口", () => {
    mockUseAuth.mockReturnValue({ user: userUser, loading: false, login: vi.fn(), logout: vi.fn() });
    renderAt("/");
    expect(screen.queryByTestId("nav-workspace-manage")).not.toBeInTheDocument();
  });

  it("顶栏「工作区」入口跳 /workspaces-entry（IA 重设计 §2.3）", () => {
    renderAt("/workspaces-entry");
    const link = screen.getByText("工作区").closest("a");
    expect(link).toHaveAttribute("href", "/workspaces-entry");
  });
});
