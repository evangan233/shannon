/**
 * Task 9: 白盒+黑盒一键组合扫描——前端开关 + 共享认证 + 预验证态。
 *
 * 覆盖：
 *  - buildBody 纯函数：combined 关 → 纯白盒（无 url/认证）；combined 开 → body 含 url + 认证。
 *  - UI：白盒页 Switch 开关 → 展开 URL 输入 + 共享认证区；提交 body 字段断言；纯白盒零回归。
 *  - 预验证态：组合提交响应 bb_phase=precheck → toast「预验证中」。
 *
 * 受控 state 结构（ScanNewPage.tsx）：FormState.combined?: boolean（默认 false）；
 * buildBody whitebox 分支据 f.combined && f.url 决定是否附 url + 认证字段。
 */
import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor, cleanup, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { setupServer } from "msw/node";
import { http, HttpResponse } from "msw";
import { toast } from "sonner";
import i18n from "@/i18n";
import { ScanNewPage, buildBody, type FormState, type AuthFormState } from "../../pages/ScanNewPage";

const { mockUseAuth } = vi.hoisted(() => ({ mockUseAuth: vi.fn() }));
vi.mock("@/auth/AuthContext", () => ({ useAuth: () => mockUseAuth() }));

const WS_LIST = [
  { name: "ws1", scan_type: "whitebox", status: "completed", created_at: 0 },
];

const server = setupServer(
  http.get("/api/workspaces", () => HttpResponse.json(WS_LIST)),
  http.get("/api/workspaces/:ws/repos", () => HttpResponse.json([])),
  http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([])),
  // 认证展开默认 source=profile（2026-08-14）→ BottomProfileBlock mount 即拉 auth-profiles；默认空列表。
  http.get("/api/workspaces/:ws/auth-profiles", () => HttpResponse.json([])),
);

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
beforeEach(() => {
  i18n.changeLanguage("zh");
  mockUseAuth.mockReturnValue({ user: { id: 1, username: "alice", role: "user", must_change_password: false } });
});
afterEach(() => {
  server.resetHandlers();
  vi.restoreAllMocks();
  cleanup();
});
afterAll(() => server.close());

function renderPage(initialPath = "/scan/new", state?: unknown) {
  return render(
    <MemoryRouter initialEntries={[state ? { pathname: initialPath, state } : initialPath]}>
      <ScanNewPage />
    </MemoryRouter>,
  );
}

async function selectOption(triggerText: RegExp | string, optionName: RegExp | string) {
  const trigger = screen.getByText(triggerText).closest("button")!;
  fireEvent.click(trigger);
  const opt = await screen.findByRole("option", { name: optionName });
  fireEvent.click(opt);
}

async function selectWorkspace(name: string) {
  await selectOption("选择 workspace", name);
}

// inline 凭据 Label 无 htmlFor——按文本定位同处 div 里的 input（同 ScanNewPage.test 范式）。
function inputByLabel(labelText: RegExp | string) {
  const label = screen.getByText(labelText);
  return label.parentElement?.querySelector("input") as HTMLInputElement;
}

async function fillValidRepo() {
  server.use(
    http.get("/api/workspaces/:ws/repos", () =>
      HttpResponse.json([
        { name: "foo", state: "ready", source: { kind: "git", url: "https://gitlab.example/foo.git" } },
      ]),
    ),
  );
  await selectWorkspace("ws1");
  await waitFor(() => screen.getByRole("button", { name: /\+ 添加新仓库/ }));
  // 白盒仓库多选（2026-09-11 批量白盒）：勾选 topology-repo-selector 内 foo 的 checkbox
  const selector = await screen.findByTestId("topology-repo-selector");
  fireEvent.click(await within(selector).findByRole("checkbox", { name: /foo/ }));
}

// === buildBody 纯函数：组合开关决定是否附 url + 认证 ===
const DISABLED_AUTH: AuthFormState = {
  enabled: false, source: "inline", profileId: "", credentialIds: [],
  loginType: "form", loginUrl: "",
  accounts: [{ role: "admin", username: "", password: "" }], loginFlow: "",
};
const INLINE_AUTH: AuthFormState = {
  enabled: true, source: "inline", profileId: "", credentialIds: [],
  loginType: "form", loginUrl: "http://t/login",
  accounts: [{ role: "admin", username: "alice", password: "pw" }], loginFlow: "",
};

function wbForm(overrides: Partial<FormState> = {}): FormState {
  return {
    selectedRepo: "foo",
    selectedRepos: ["foo"],
    url: "",
    reuseScanId: "",
    auth: DISABLED_AUTH,
    host: { enabled: false, mode: "profile", profileIds: [], hostUrl: "" },
    yaml: "",
    combined: false,
    ...overrides,
  };
}

describe("buildBody 组合扫描（白盒 + 黑盒）", () => {
  it("combined 关 → 纯白盒：无 url 无 authentication（即便 f.url 有草稿也不发）", () => {
    const body = buildBody("whitebox", wbForm({ url: "http://x", combined: false }), "ws1");
    expect(body.type).toBe("whitebox");
    expect(body.source).toEqual({ kind: "repo", value: "foo" });
    expect(body.url).toBeUndefined();
    expect(body.authentication).toBeUndefined();
    expect(body.auth_profile_id).toBeUndefined();
    expect(body.auth_credential_ids).toBeUndefined();
  });

  it("combined 开 + url + inline auth.enabled → body 含 url + authentication", () => {
    const body = buildBody("whitebox", wbForm({
      combined: true, url: "http://target.example", auth: INLINE_AUTH,
    }), "ws1");
    expect(body.type).toBe("whitebox");
    expect(body.source).toEqual({ kind: "repo", value: "foo" });
    expect(body.url).toBe("http://target.example");
    expect(body.authentication).toBeDefined();
    expect(body.authentication!.credentials.username).toBe("alice");
    expect(body.authentication!.login_url).toBe("http://t/login");
  });

  it("combined 开但 url 空 → 等价纯白盒（不发 url/authentication）", () => {
    const body = buildBody("whitebox", wbForm({ combined: true, url: "", auth: INLINE_AUTH }), "ws1");
    expect(body.url).toBeUndefined();
    expect(body.authentication).toBeUndefined();
  });

  it("combined 开 + url + auth 未启用 → 仅发 url，不发 authentication", () => {
    const body = buildBody("whitebox", wbForm({
      combined: true, url: "http://x", auth: { ...INLINE_AUTH, enabled: false },
    }), "ws1");
    expect(body.url).toBe("http://x");
    expect(body.authentication).toBeUndefined();
  });

  it("combined 开 + profile 模式 → 发 auth_profile_id + auth_credential_ids（无 authentication）", () => {
    const body = buildBody("whitebox", wbForm({
      combined: true, url: "http://x",
      auth: { enabled: true, source: "profile", profileId: "p1", credentialIds: ["c1"],
        loginType: "form", loginUrl: "", accounts: [{ role: "admin", username: "", password: "" }], loginFlow: "" },
    }), "ws1");
    expect(body.auth_profile_id).toBe("p1");
    expect(body.auth_credential_ids).toEqual(["c1"]);
    expect(body.authentication).toBeUndefined();
  });
});

// === UI：白盒页组合开关 + 展开区 + 提交 ===
describe("ScanNewPage 白盒组合开关（UI）", () => {
  beforeEach(() => i18n.changeLanguage("zh"));

  it("默认白盒不显组合展开区；打开 Switch → 显 URL 输入 + 认证配置入口", async () => {
    renderPage();
    await fillValidRepo();
    // 开关关 → 无组合 URL 输入
    expect(screen.queryByPlaceholderText(/http:\/\/target/)).toBeNull();
    // 打开组合开关（radix Switch role=switch）
    fireEvent.click(screen.getByRole("switch", { name: /同时发起黑盒扫描/ }));
    // 显组合 URL 输入 + 认证「配置登录」按钮
    await waitFor(() => expect(screen.getByPlaceholderText(/http:\/\/target/)).toBeInTheDocument());
    expect(screen.getByRole("button", { name: /配置登录/ })).toBeInTheDocument();
  });

  it("开关开 + 填 url + 启用认证填凭据 → 提交 body 含 url + authentication（type=whitebox）", async () => {
    let posted: Record<string, unknown> | undefined;
    server.use(
      http.post("/api/scan", async ({ request }) => {
        posted = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json({ workspace: "ws1", scan_id: "s1" });
      }),
    );
    renderPage();
    await fillValidRepo();
    fireEvent.click(screen.getByRole("switch", { name: /同时发起黑盒扫描/ }));
    // 填组合 URL
    fireEvent.change(screen.getByPlaceholderText(/http:\/\/target/), { target: { value: "http://target.example" } });
    // 启用认证 + 填 inline 凭据（共享 AuthFields → BottomInlineBlock）
    fireEvent.click(screen.getByRole("button", { name: /配置登录/ }));
    await waitFor(() => expect(screen.getByText(/已启用登录/)).toBeInTheDocument());
    // 默认 source=profile（2026-08-14）→ 切「临时填写」进 inline 模式
    fireEvent.click(screen.getByRole("button", { name: /临时填写/ }));
    fireEvent.change(screen.getByPlaceholderText("https://example.com/login"), { target: { value: "http://t/login" } });
    fireEvent.change(inputByLabel("用户名"), { target: { value: "alice" } });
    // 提交
    await waitFor(() => expect(screen.getByRole("button", { name: /开始扫描/ })).toBeEnabled());
    fireEvent.click(screen.getByRole("button", { name: /开始扫描/ }));
    await waitFor(() => expect(posted).toBeDefined());
    expect(posted!.type).toBe("whitebox");
    expect(posted!.source).toEqual({ kind: "repo", value: "foo" });
    expect(posted!.url).toBe("http://target.example");
    expect(posted!.authentication).toBeDefined();
    const auth = posted!.authentication as { credentials: { username: string }; login_url: string };
    expect(auth.credentials.username).toBe("alice");
    expect(auth.login_url).toBe("http://t/login");
  });

  it("开关关 → 提交 body 不含 url/authentication（纯白盒零回归）", async () => {
    let posted: Record<string, unknown> | undefined;
    server.use(
      http.post("/api/scan", async ({ request }) => {
        posted = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json({ workspace: "ws1", scan_id: "s1" });
      }),
    );
    renderPage();
    await fillValidRepo();
    await waitFor(() => expect(screen.getByRole("button", { name: /开始扫描/ })).toBeEnabled());
    fireEvent.click(screen.getByRole("button", { name: /开始扫描/ }));
    await waitFor(() => expect(posted).toBeDefined());
    expect(posted!.url).toBeUndefined();
    expect(posted!.authentication).toBeUndefined();
    expect(posted!.auth_profile_id).toBeUndefined();
  });

  it("组合开关开但未填 url → 提交 disabled（url 必填）", async () => {
    renderPage();
    await fillValidRepo();
    fireEvent.click(screen.getByRole("switch", { name: /同时发起黑盒扫描/ }));
    // 未填组合 url → 校验拦空，提交 disabled
    await waitFor(() => expect(screen.getByRole("button", { name: /开始扫描/ })).toBeDisabled());
    // 填上 url → enabled
    fireEvent.change(screen.getByPlaceholderText(/http:\/\/target/), { target: { value: "http://t.example" } });
    await waitFor(() => expect(screen.getByRole("button", { name: /开始扫描/ })).toBeEnabled());
  });

  it("组合提交返回 bb_phase=precheck → toast「预验证中」", async () => {
    const spy = vi.spyOn(toast, "info");
    server.use(
      http.post("/api/scan", () =>
        HttpResponse.json({ workspace: "ws1", scan_id: "s1", bb_phase: "precheck" })),
    );
    renderPage();
    await fillValidRepo();
    fireEvent.click(screen.getByRole("switch", { name: /同时发起黑盒扫描/ }));
    fireEvent.change(screen.getByPlaceholderText(/http:\/\/target/), { target: { value: "http://target.example" } });
    await waitFor(() => expect(screen.getByRole("button", { name: /开始扫描/ })).toBeEnabled());
    fireEvent.click(screen.getByRole("button", { name: /开始扫描/ }));
    await waitFor(() => expect(spy).toHaveBeenCalledWith(expect.stringMatching(/预验证中/)));
  });
});
