// AuthProfileTestPage: 档案级多选角色测试页——默认全选 + 计数 + toggle + 全选切换 + 发起 test-batch +
// 重载恢复 running（订阅 VerifyLivePanel）。回看面板依赖 react-window,jsdom 只验"不崩 + 被触发"。
import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach, vi } from "vitest";
import { render, screen, waitFor, fireEvent, cleanup } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { setupServer } from "msw/node";
import { http, HttpResponse } from "msw";
import i18n from "@/i18n";
import { AuthProfileTestPage, hostToParams } from "./AuthProfileTestPage";
import type { AuthProfile } from "@/api/types";
import type { HostFormState } from "./ScanNewPage";

// 恢复/发起后订阅 VerifyLivePanel → useEventSource → new EventSource；jsdom 无原生 EventSource，
// mock 返空流（只验"识别 running → 进 live 态/发起成功"，不验 SSE 事件本身）。
vi.mock("@/api/useEventSource", () => ({
  useEventSource: () => ({ events: [], status: "open" as const, lastEventId: undefined }),
}));

const prof: AuthProfile = {
  id: "prof_1", name: "NG", login_url: "http://t/", login_type: "form",
  credentials: [
    { id: "c1", role: "admin", username: "admin", verify_status: { state: "unverified" } },
    { id: "c2", role: "user", username: "u1", verify_status: { state: "unverified" } },
    { id: "c3", role: "guest", username: "g1", verify_status: { state: "unverified" } },
  ],
};
const runningProf: AuthProfile = {
  id: "prof_1", name: "NG", login_url: "http://t/", login_type: "form",
  credentials: [
    { id: "c1", role: "admin", username: "admin",
      verify_status: { state: "running", workflow_id: "authval-batch-ws1-running1", probe_dir: "/p/probe-r1" } },
    { id: "c2", role: "user", username: "u1", verify_status: { state: "unverified" } },
    { id: "c3", role: "guest", username: "g1", verify_status: { state: "unverified" } },
  ],
};

let currentProf: AuthProfile;
let batchCalls = 0;
let batchBody: unknown;
const server = setupServer(
  http.get("/api/workspaces/:ws/auth-profiles/:pid", () => HttpResponse.json(currentProf)),
  http.post("/api/workspaces/:ws/auth-profiles/:pid/test-batch", async ({ request }) => {
    batchCalls++;
    batchBody = await request.json();
    return HttpResponse.json({ workflow_id: "authval-batch-ws1-abc" });
  }),
);
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
beforeEach(() => { i18n.changeLanguage("zh"); batchCalls = 0; batchBody = undefined; });
afterEach(() => { server.resetHandlers(); cleanup(); });
afterAll(() => server.close());

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/p/ws1/auth-profiles/prof_1"]}>
      <Routes>
        <Route path="/p/:workspace/auth-profiles/:pid" element={<AuthProfileTestPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("hostToParams", () => {
  const base: HostFormState = { enabled: false, mode: "profile", profileIds: [], hostUrl: "" };
  it("未启用 → 空（直连）", () => {
    expect(hostToParams(base)).toEqual({});
  });
  it("profile 模式多选 → hostProfileIds 数组", () => {
    expect(hostToParams({ ...base, enabled: true, mode: "profile", profileIds: ["host_p1", "host_p2"] }))
      .toEqual({ hostProfileIds: ["host_p1", "host_p2"] });
  });
  it("profile 模式空选 → 空（等价直连，不发空数组）", () => {
    expect(hostToParams({ ...base, enabled: true, mode: "profile", profileIds: [] }))
      .toEqual({});
  });
  it("url 模式 → hostUrl", () => {
    expect(hostToParams({ ...base, enabled: true, mode: "url", hostUrl: "https://h.test/get" }))
      .toEqual({ hostUrl: "https://h.test/get" });
  });
});

describe("AuthProfileTestPage", () => {
  it("加载档案: 默认全选 + 计数 3/3 + 角色列表 + 开始按钮", async () => {
    currentProf = prof;
    renderPage();
    await waitFor(() => expect(screen.getByText("NG")).toBeInTheDocument());
    expect(screen.getAllByText(/admin/).length).toBeGreaterThan(0);
    expect(screen.getByText(/3\/3/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "开始测试" })).toBeInTheDocument();
    // 3 个 toggle 全选中（aria-pressed=true）
    expect(screen.getAllByRole("button", { pressed: true })).toHaveLength(3);
  });

  it("取消一个角色 → 计数 2/3", async () => {
    currentProf = prof;
    renderPage();
    await waitFor(() => expect(screen.getByText(/3\/3/)).toBeInTheDocument());
    const toggles = screen.getAllByRole("button", { pressed: true });
    fireEvent.click(toggles[0]);  // 取消第一个角色
    await waitFor(() => expect(screen.getByText(/2\/3/)).toBeInTheDocument());
    expect(screen.getAllByRole("button", { pressed: true })).toHaveLength(2);
  });

  it("取消全选 → 0 选 + 开始按钮 disabled; 再全选 → 3 选", async () => {
    currentProf = prof;
    renderPage();
    await waitFor(() => expect(screen.getByText(/3\/3/)).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "取消全选" }));
    await waitFor(() => expect(screen.getByText(/0\/3/)).toBeInTheDocument());
    expect(screen.getByRole("button", { name: "开始测试" })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "全选" }));
    await waitFor(() => expect(screen.getByText(/3\/3/)).toBeInTheDocument());
    expect(screen.getByRole("button", { name: "开始测试" })).not.toBeDisabled();
  });

  it("发起测试 → POST test-batch（全选省略 cred_ids）", async () => {
    currentProf = prof;
    renderPage();
    await waitFor(() => expect(screen.getByText(/3\/3/)).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "开始测试" }));
    await waitFor(() => expect(batchCalls).toBe(1));
    // 全选 → cred_ids 省略（body 不含 cred_ids 键 → JSON {}）
    expect(batchBody).toEqual({});
  });

  it("发起测试（子集）→ POST test-batch 带 cred_ids", async () => {
    currentProf = prof;
    renderPage();
    await waitFor(() => expect(screen.getByText(/3\/3/)).toBeInTheDocument());
    // 取消第二个（c2）
    const toggles = screen.getAllByRole("button", { pressed: true });
    fireEvent.click(toggles[1]);
    await waitFor(() => expect(screen.getByText(/2\/3/)).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "开始测试" }));
    await waitFor(() => expect(batchCalls).toBe(1));
    expect(batchBody).toEqual({ cred_ids: ["c1", "c3"] });  // c2 被取消
  });

  it("重载发现 running cred → 恢复（按钮变「停止测试」可用、不落空态）", async () => {
    currentProf = runningProf;
    renderPage();
    await waitFor(() => expect(screen.getByText("NG")).toBeInTheDocument());
    // 恢复 effect 识别 running → setPolling + setTesting；wf id 取自 running cred 的
    // verify_status.workflow_id → 按钮为「停止测试」且可点。核心：重载不落空态、自动恢复轮询。
    await waitFor(() => expect(screen.getByRole("button", { name: "停止测试" })).toBeEnabled());
  });

  it("渲染 HOST 解析入口（复用黑盒 HOST 能力：选 HOST 走代理、不选直连）", async () => {
    currentProf = prof;
    renderPage();
    await waitFor(() => expect(screen.getByText("NG")).toBeInTheDocument());
    expect(screen.getByText("HOST 解析")).toBeInTheDocument();
  });

  it("非 system 档案渲染编辑按钮 → 打开编辑对话框（预填档案名 + 全量角色）", async () => {
    currentProf = prof;
    renderPage();
    await waitFor(() => expect(screen.getByText("NG")).toBeInTheDocument());
    const editBtn = screen.getByRole("button", { name: "编辑" });
    expect(editBtn).toBeInTheDocument();
    fireEvent.click(editBtn);
    // AuthProfileDialog editing 模式：标题「编辑」+ 档案名/URL 预填；提交走 PATCH
    await waitFor(() => expect(screen.getByRole("dialog")).toBeInTheDocument());
    expect(screen.getByText("编辑")).toBeInTheDocument();  // DialogTitle
    expect(screen.getByLabelText("档案名")).toHaveValue("NG");
    expect(screen.getByLabelText("登录地址")).toHaveValue("http://t/");
  });

  it("system 档案隐藏编辑按钮（只读对齐列表页）", async () => {
    currentProf = { ...prof, scope: "system" };
    renderPage();
    await waitFor(() => expect(screen.getByText("NG")).toBeInTheDocument());
    expect(screen.queryByRole("button", { name: "编辑" })).not.toBeInTheDocument();
  });
});

describe("AuthProfileTestPage 失败提示（VerifyFailureNote）", () => {
  it("engine 失败 → 显示引擎提示（与账号无关 + 指向 LLM 配置）+ 折叠技术详情", async () => {
    currentProf = {
      ...prof,
      credentials: [{
        id: "c1", role: "admin", username: "admin",
        verify_status: {
          state: "failed", failure_point: "engine",
          failure_detail: "PentestError: Error code: 401 - {'error': {'code': '401', 'message': '令牌已过期或验证不正确'}}",
        },
      }],
    };
    renderPage();
    await waitFor(() => expect(screen.getByText("验证引擎调用失败（与目标站账号密码无关）")).toBeInTheDocument());
    expect(screen.getByText(/工作区设置 → LLM 配置/)).toBeInTheDocument();
    expect(screen.getByText(/Key 与接口地址不匹配/)).toBeInTheDocument();  // 401 子码提示
    expect(screen.getByText("技术详情")).toBeInTheDocument();
    // 原始异常串默认折叠（在 details 内、不可见），展开后可见
    expect(screen.queryByText(/PentestError/)).not.toBeVisible();
  });

  it("旧记录兜底：failure_point=out_of_band 但 detail 含 401 签名 → 按 engine 渲染", async () => {
    currentProf = {
      ...prof,
      credentials: [{
        id: "c1", role: "admin", username: "admin",
        verify_status: {
          state: "failed", failure_point: "out_of_band",
          failure_detail: "PentestError: Error code: 401 - {'error': {'code': '401', 'message': '令牌已过期或验证不正确'}}",
        },
      }],
    };
    renderPage();
    await waitFor(() => expect(screen.getByText("验证引擎调用失败（与目标站账号密码无关）")).toBeInTheDocument());
  });

  it("username_or_password 失败 → 账号密码提示（不误报引擎）", async () => {
    currentProf = {
      ...prof,
      credentials: [{
        id: "c1", role: "admin", username: "admin",
        verify_status: { state: "failed", failure_point: "username_or_password", failure_detail: "wrong password" },
      }],
    };
    renderPage();
    await waitFor(() => expect(screen.getByText("登录失败：用户名或密码错误")).toBeInTheDocument());
    expect(screen.queryByText(/验证引擎调用失败/)).not.toBeInTheDocument();
  });
});

describe("AuthProfileTestPage 停止测试（auth-test-cancel）", () => {
  // cancel-test 捕获（body.workflow_id 断言）
  let cancelCalls = 0;
  let cancelBody: unknown;
  beforeEach(() => {
    cancelCalls = 0; cancelBody = undefined;
    server.use(
      http.post("/api/workspaces/:ws/auth-profiles/:pid/cancel-test", async ({ request }) => {
        cancelCalls++;
        cancelBody = await request.json();
        return HttpResponse.json({ cancelled: "ok" });
      }),
    );
  });

  it("恢复 running 态 → 显示停止按钮；点停止 → POST cancel-test 用 running cred 的 workflow_id", async () => {
    currentProf = runningProf;  // c1 running（wf=authval-batch-ws1-running1），batchWfId 为 null（恢复态）
    renderPage();
    await waitFor(() => expect(screen.getByRole("button", { name: "停止测试" })).toBeEnabled());
    fireEvent.click(screen.getByRole("button", { name: "停止测试" }));
    await waitFor(() => expect(cancelCalls).toBe(1));
    expect(cancelBody).toEqual({ workflow_id: "authval-batch-ws1-running1" });
  });

  it("发起后点停止 → 用 test-batch 返回的 workflow_id（batchWfId 优先于 profile）", async () => {
    currentProf = prof;
    renderPage();
    await waitFor(() => expect(screen.getByText(/3\/3/)).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "开始测试" }));
    await waitFor(() => expect(batchCalls).toBe(1));
    // 发起后按钮换"停止测试"（batchWfId 来自 test-batch response=authval-batch-ws1-abc，
    // 而 profile 里 c1 unverified 无 wf——验证取的是 batchWfId）
    const stop = await screen.findByRole("button", { name: "停止测试" });
    await waitFor(() => expect(stop).toBeEnabled());
    fireEvent.click(stop);
    await waitFor(() => expect(cancelCalls).toBe(1));
    expect(cancelBody).toEqual({ workflow_id: "authval-batch-ws1-abc" });
  });

  it("停止成功 → 重拉 profile 落终态 → 轮询停、按钮回「开始测试」", async () => {
    // 停止后后端已回填：c1 failed(cancelled)、其余 unverified → 批次结束
    const cancelledProf: AuthProfile = {
      ...runningProf,
      credentials: [
        { id: "c1", role: "admin", username: "admin",
          verify_status: { state: "failed", failure_point: "cancelled", workflow_id: "authval-batch-ws1-running1" } },
        { id: "c2", role: "user", username: "u1", verify_status: { state: "unverified" } },
        { id: "c3", role: "guest", username: "g1", verify_status: { state: "unverified" } },
      ],
    };
    currentProf = runningProf;
    renderPage();
    const stop = await screen.findByRole("button", { name: "停止测试" });
    await waitFor(() => expect(stop).toBeEnabled());
    currentProf = cancelledProf;   // 点停止后 msw 返回新终态
    fireEvent.click(stop);
    await waitFor(() => expect(cancelCalls).toBe(1));
    await waitFor(() => expect(screen.getByRole("button", { name: "开始测试" })).toBeEnabled());
  });
});
