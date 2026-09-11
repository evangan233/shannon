import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach } from "vitest";
import { screen, waitFor, cleanup } from "@testing-library/react";
import { renderWithSwr } from "@/test/swr-render";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { setupServer } from "msw/node";
import { http, HttpResponse } from "msw";
import i18n from "@/i18n";
import WorkspaceDetail from "./index";

// MemberManagerDialog 依赖 AuthProvider + 自有成员 API；header 测试聚焦元信息/降级/404，
// 隔离该子组件（其行为在 MemberManagerDialog.test.tsx 独立覆盖）。
vi.mock("@/components/MemberManagerDialog", () => ({
  MemberManagerDialog: () => null,
}));
// WorkspaceSwitcher（Task 9 入口）依赖 useAuth + useWorkspaces（GET /api/workspaces）；
// header 测试不断言切换器，隔离避免 AuthProvider + workspaces API 噪音（行为在
// WorkspaceSwitcher.test.tsx 独立覆盖）。
vi.mock("@/components/WorkspaceSwitcher", () => ({
  WorkspaceSwitcher: () => null,
}));
// 隔离 useAuth（置顶按钮已随 2026-09-11 置顶→最近访问替换删除）：避免
// AuthProvider + /auth/me 请求噪音。
vi.mock("@/auth/AuthContext", () => ({
  useAuth: () => ({
    user: { id: 1, username: "admin", role: "admin", must_change_password: false },
    refreshUser: vi.fn(),
  }),
}));

const server = setupServer();

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
// jsdom navigator.language 默认 en；现有断言依赖中文渲染，逐测试钉回 zh。
beforeEach(() => i18n.changeLanguage("zh"));
afterEach(() => { server.resetHandlers(); cleanup(); i18n.changeLanguage("zh"); });
afterAll(() => server.close());

// ws 概览：/p/:ws index 渲染扫描列表占位（不引入 ScanList 自有 listScans 请求）。
function renderAt(path: string) {
  return renderWithSwr(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/p/:workspace" element={<WorkspaceDetail />}>
          <Route index element={<div>scanlist-content</div>} />
        </Route>
      </Routes>
    </MemoryRouter>,
  );
}

describe("WorkspaceDetail header", () => {
  it("显返回链接 + workspace 名 + 元信息（latest scan_type 徽标；无状态徽标）", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans", () =>
        HttpResponse.json([
          { scan_id: "s2", scan_type: "blackbox", status: "completed", created_at: 1000,
            completed_at: 2000, vuln_count: 0, is_running: false },
          // latest（created_at 最新）→ 类型徽标取这条
          { scan_id: "s1", scan_type: "whitebox", status: "running", created_at: 3000,
            vuln_count: 0, is_running: true },
        ]),
      ),
    );
    const { container } = renderAt("/p/ws1");
    expect(screen.getByText("返回列表")).toBeInTheDocument();
    expect(screen.getByText("ws1")).toBeInTheDocument();
    // Hero 类型徽标 + 指标条「运行中」ctx 都会出现 whitebox —— 至少一处即证明 latest 元信息渲染
    await waitFor(() => expect(screen.getAllByText("whitebox").length).toBeGreaterThan(0));
    // 成功/失败是单项扫描任务的概念，头部不显 latest 状态徽标
    expect(container.querySelector("[title='running']")).not.toBeInTheDocument();
  });

  it("fetch 失败降级显 workspace 名（不阻塞 Outlet）", async () => {
    server.use(http.get("/api/workspaces/:ws/scans", () => new HttpResponse(null, { status: 500 })));
    renderAt("/p/ws1");
    await waitFor(() => expect(screen.getByText("ws1")).toBeInTheDocument());
    expect(screen.getByText("返回列表")).toBeInTheDocument();
    // Outlet 仍渲染（降级不阻塞子路由）
    expect(screen.getByText("scanlist-content")).toBeInTheDocument();
  });

  it("404 显工作区不存在/已删除", async () => {
    server.use(http.get("/api/workspaces/:ws/scans", () =>
      HttpResponse.json({ detail: "workspace not found" }, { status: 404 }),
    ));
    renderAt("/p/ws1");
    await waitFor(() => expect(screen.getByText(/工作区不存在或已被删除/)).toBeInTheDocument());
    expect(screen.getByText("返回列表")).toBeInTheDocument();
  });
});
