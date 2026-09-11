// Task 13: ScanFormFields HOST 选择区（segmented toggle profile/url + 档案下拉）。
// Harness 镜像 ScanNewPage.test.tsx + HostProfilesPage.test.tsx：
//   msw + MemoryRouter + i18n.changeLanguage("zh") + fireEvent（无 user-event 依赖）。
// 这里直接渲染 ScanFormFields（type="blackbox"）——构造 FormState 直传，免走 ScanNewPage 的 ws 选择链，
// 更窄地覆盖 HOST 区交互（折叠/展开、segmented toggle 切换、档案下拉选项渲染）。
import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, cleanup, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { setupServer } from "msw/node";
import { http, HttpResponse } from "msw";
import i18n from "@/i18n";
import { ScanFormFields } from "./ScanFormFields";
import { AuthFormState, FormState } from "../pages/ScanNewPage";

// ScanFormFields 内部用 useAuth()（admin 判定，黑盒区不用但 hook 必须在 Provider 内）——
// 镜像 ScanNewPage.test.tsx 的 hoisted mock 范式绕过 AuthProvider。
const { mockUseAuth } = vi.hoisted(() => ({ mockUseAuth: vi.fn() }));
vi.mock("@/auth/AuthContext", () => ({ useAuth: () => mockUseAuth() }));

const DEFAULT_AUTH: AuthFormState = {
  enabled: false, source: "inline", profileId: "", credentialIds: [],
  loginType: "form", loginUrl: "",
  accounts: [{ role: "admin", username: "", password: "" }], loginFlow: "",
};

function makeForm(overrides: Partial<FormState> = {}): FormState {
  return {
    selectedRepo: "",
    // 白盒仓库多选（2026-09-11 批量白盒）：本文件只覆盖 HOST/认证区，不选仓库。
    selectedRepos: [],
    url: "http://example.com",
    reuseScanId: "20260731-1200",
    auth: DEFAULT_AUTH,
    host: { enabled: false, mode: "profile", profileIds: [], hostUrl: "" },
    yaml: "",
    ...overrides,
  };
}

const HOST_FIXTURE = [
  {
    id: "host_1", name: "华南生产", mappings: [
      { ip: "10.0.0.1", host: "api.test" },
      { ip: "10.0.0.2", host: "app.test" },
    ],
  },
  {
    id: "host_2", name: "灰度集群", mappings: [{ ip: "10.1.0.1", host: "canary.test" }],
  },
];

const server = setupServer(
  http.get("/api/workspaces/:ws/repos", () => HttpResponse.json([])),
  http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([])),
  http.get("/api/workspaces/:ws/auth-profiles", () => HttpResponse.json([])),
  http.get("/api/workspaces/:ws/host-profiles", () => HttpResponse.json(HOST_FIXTURE)),
);

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
beforeEach(() => {
  i18n.changeLanguage("zh");
  mockUseAuth.mockReturnValue({ user: { id: 1, username: "alice", role: "user", must_change_password: false } });
});
afterEach(() => { server.resetHandlers(); cleanup(); });
afterAll(() => server.close());

function renderFields(f: FormState, set: (patch: Partial<FormState>) => void = () => {}, type: "whitebox" | "blackbox" = "blackbox") {
  return render(
    <MemoryRouter>
      <ScanFormFields
        type={type}
        f={f}
        set={set}
        sourceErr={null}
        reuseErr={null}
        urlErr={null}
        authErr={null}
        workspace="ws1"
        wsList={[{ name: "ws1", scan_type: "blackbox", status: "completed", created_at: 0 }]}
        onWorkspaceChange={() => {}}
        wsLoading={false}
      />
    </MemoryRouter>,
  );
}

describe("ScanFormFields HOST 解析区", () => {
  it("折叠态：显标题 + 未启用状态文案 + 配置按钮（不显 segmented toggle）", () => {
    renderFields(makeForm());
    expect(screen.getByText("HOST 解析")).toBeInTheDocument();
    expect(screen.getByText(/未启用 HOST 解析/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /配置 HOST/ })).toBeInTheDocument();
    // 折叠态不显 segmented toggle 按钮
    expect(screen.queryByRole("button", { name: /使用档案/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /填写链接/ })).toBeNull();
  });

  it("展开 + profile 模式（默认）：多选列表显 fixture 档案名，勾选回写 profileIds", async () => {
    const set = vi.fn();
    renderFields(makeForm({ host: { enabled: true, mode: "profile", profileIds: [], hostUrl: "" } }), set);
    // segmented toggle 显两按钮
    expect(screen.getByRole("button", { name: /使用档案/ })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: /填写链接/ })).toHaveAttribute("aria-pressed", "false");
    // 多选列表（平铺 checkbox，非下拉）：等 HostProfilePicker 跑完 loading 后显档案名
    const picker = await screen.findByTestId("host-profile-picker");
    expect(within(picker).getByText("华南生产")).toBeInTheDocument();
    expect(within(picker).getByText("灰度集群")).toBeInTheDocument();
    // 勾选第一个档案 → set profileIds=["host_1"]（多选追加语义；checkbox accessible name=label 文本）
    fireEvent.click(within(picker).getByRole("checkbox", { name: /华南生产/ }));
    expect(set).toHaveBeenCalledWith(expect.objectContaining({
      host: expect.objectContaining({ profileIds: ["host_1"] }),
    }));
  });

  it("多选：已选一个再勾第二个 → profileIds 追加（不覆盖）", async () => {
    const set = vi.fn();
    renderFields(makeForm({ host: { enabled: true, mode: "profile", profileIds: ["host_1"], hostUrl: "" } }), set);
    const picker = await screen.findByTestId("host-profile-picker");
    fireEvent.click(within(picker).getByRole("checkbox", { name: /灰度集群/ }));
    expect(set).toHaveBeenCalledWith(expect.objectContaining({
      host: expect.objectContaining({ profileIds: ["host_1", "host_2"] }),
    }));
    // 已选计数文案显 1（初始态）
    expect(within(picker).getByText(/已选 1 个档案/)).toBeInTheDocument();
  });

  it("切到 url 模式 → 出现 URL 输入框（profile 多选列表消失）", () => {
    renderFields(makeForm({ host: { enabled: true, mode: "url", profileIds: [], hostUrl: "" } }));
    expect(screen.getByRole("button", { name: /填写链接/ })).toHaveAttribute("aria-pressed", "true");
    // url 模式显 placeholder
    expect(screen.getByPlaceholderText(/https:\/\/example\.com\/hosts\.txt/)).toBeInTheDocument();
    // profile 模式列表不显
    expect(screen.queryByTestId("host-profile-picker")).toBeNull();
  });

  it("点「配置 HOST」→ set({host:{enabled:true}}) 回写父级（驱动 enabled 翻转）", () => {
    const set = vi.fn();
    renderFields(makeForm(), set);
    fireEvent.click(screen.getByRole("button", { name: /配置 HOST/ }));
    expect(set).toHaveBeenCalledWith(expect.objectContaining({ host: expect.objectContaining({ enabled: true }) }));
  });

  it("切模式：点「填写链接」→ set host.mode=url；点「使用档案」→ set host.mode=profile", () => {
    const set = vi.fn();
    renderFields(makeForm({ host: { enabled: true, mode: "profile", profileIds: [], hostUrl: "" } }), set);
    fireEvent.click(screen.getByRole("button", { name: /填写链接/ }));
    expect(set).toHaveBeenCalledWith(expect.objectContaining({ host: expect.objectContaining({ mode: "url" }) }));
    fireEvent.click(screen.getByRole("button", { name: /使用档案/ }));
    expect(set).toHaveBeenCalledWith(expect.objectContaining({ host: expect.objectContaining({ mode: "profile" }) }));
  });
});


// === 白盒组合展开区 HOST 入口（2026-08-13：组合开关打开时展开区渲染共享 HostFields） ===
describe("ScanFormFields 白盒组合展开区 HOST", () => {
  it("组合开关开 + host enabled -> 展开区渲染 HOST 区块（显 segmented 切换）", () => {
    renderFields(
      makeForm({ combined: true, host: { enabled: true, mode: "profile", profileIds: [], hostUrl: "" } }),
      () => {},
      "whitebox",
    );
    // HostFields 展开态显 segmented（与黑盒分支同款，复用同一组件）
    expect(screen.getByRole("button", { name: /使用档案/ })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: /填写链接/ })).toBeInTheDocument();
  });

  it("组合开关开 + host disabled -> 显「配置 HOST」按钮（折叠态不显 segmented）", () => {
    renderFields(
      makeForm({ combined: true, host: { enabled: false, mode: "profile", profileIds: [], hostUrl: "" } }),
      () => {},
      "whitebox",
    );
    expect(screen.getByRole("button", { name: /配置 HOST/ })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /使用档案/ })).toBeNull();
  });

  it("组合开关关 -> 不渲染 HOST 区块（纯白盒无 HOST 入口，零回归）", () => {
    renderFields(makeForm({ combined: false }), () => {}, "whitebox");
    expect(screen.queryByRole("button", { name: /配置 HOST/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /使用档案/ })).toBeNull();
  });
});
