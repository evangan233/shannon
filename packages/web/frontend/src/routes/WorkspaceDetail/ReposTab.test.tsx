import { describe, it, expect, vi } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { SWRConfig } from "swr";
import { AuthProvider } from "@/auth/AuthContext";
import { ReposTab } from "./ReposTab";

vi.mock("react-i18next", () => {
  // t 引用必须在多次渲染间稳定：ReposTab 的 refresh = useCallback([t, workspace]) +
  // useEffect([refresh, user]) 依赖链，若 t 每次新引用 → refresh 每次新 → useEffect 无限重跑
  // → listRepos 无限调用 → event loop 饥饿、waitFor 永不 resolve。工厂内定义一次、复用。
  const t = (k: string) => k;
  return { useTranslation: () => ({ t }) };
});
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn(), warning: vi.fn(), info: vi.fn() } }));

describe("ReposTab", () => {
  it("列出 ws 内仓库", async () => {
    const fm = vi.spyOn(window, "fetch");
    // AuthProvider 首拉 /auth/me（user 解析成功 → 后续 ReposTab 的 listRepos 才会发起）
    fm.mockResolvedValueOnce(
      new Response(JSON.stringify({ user: { id: 1, username: "alice", role: "user" } }), { status: 200 }),
    );
    // 之后所有 fetch（listRepos("ws1")）返回仓库列表
    fm.mockResolvedValue(
      new Response(JSON.stringify([{ name: "r1", state: "ready" }]), { status: 200 }),
    );
    render(
      <AuthProvider>
        <SWRConfig value={{ provider: () => new Map() }}>
          <MemoryRouter>
            <ReposTab workspace="ws1" />
          </MemoryRouter>
        </SWRConfig>
      </AuthProvider>,
    );
    await waitFor(() => expect(screen.getByText("r1")).toBeTruthy());
    // "新建仓库" 入口存在（i18n mock → key 字符串）
    expect(screen.getByText("repos.addRepo")).toBeTruthy();
  });

  it("关联仓库：显关联徽标、无更新按钮、删除按钮为「取消关联」", async () => {
    const fm = vi.spyOn(window, "fetch");
    fm.mockResolvedValueOnce(
      new Response(JSON.stringify({ user: { id: 1, username: "alice", role: "user" } }), { status: 200 }),
    );
    fm.mockResolvedValue(
      new Response(JSON.stringify([
        { name: "ftoa", linked: true, state: "ready", source: { kind: "linked" } },
      ]), { status: 200 }),
    );
    render(
      <AuthProvider><SWRConfig value={{ provider: () => new Map() }}><MemoryRouter><ReposTab workspace="ws1" /></MemoryRouter></SWRConfig></AuthProvider>,
    );
    await waitFor(() => expect(screen.getByText("ftoa")).toBeTruthy());
    expect(screen.getByText("repos.linkedBadge")).toBeTruthy();   // 关联徽标
    expect(screen.queryByLabelText("repos.updateAria")).toBeNull();  // 无更新(pull)按钮（icon-only）
    expect(screen.getByLabelText("repos.unlinkAria")).toBeTruthy(); // 取消关联（icon-only，文字在 tooltip）
  });

  it("私有克隆：有更新按钮、删除按钮为「删除」、无关联徽标", async () => {
    const fm = vi.spyOn(window, "fetch");
    fm.mockResolvedValueOnce(
      new Response(JSON.stringify({ user: { id: 1, username: "alice", role: "user" } }), { status: 200 }),
    );
    fm.mockResolvedValue(
      new Response(JSON.stringify([{ name: "r1", state: "ready" }]), { status: 200 }),
    );
    render(
      <AuthProvider><SWRConfig value={{ provider: () => new Map() }}><MemoryRouter><ReposTab workspace="ws1" /></MemoryRouter></SWRConfig></AuthProvider>,
    );
    await waitFor(() => expect(screen.getByText("r1")).toBeTruthy());
    expect(screen.queryByText("repos.linkedBadge")).toBeNull();
    expect(screen.getByLabelText("repos.updateAria")).toBeTruthy();  // icon-only 更新
    expect(screen.getByLabelText("repos.deleteAria")).toBeTruthy();  // icon-only 删除
  });

  it("上传仓库：来源显 kind 文案、分支列可切（本地 refs）、无更新按钮（pull 405）、有删除", async () => {
    const fm = vi.spyOn(window, "fetch");
    fm.mockResolvedValueOnce(
      new Response(JSON.stringify({ user: { id: 1, username: "alice", role: "user" } }), { status: 200 }),
    );
    fm.mockResolvedValue(
      new Response(JSON.stringify([
        { name: "up1", state: "ready",
          source: { kind: "upload", branch: "main", commit: "abc1234" } },
      ]), { status: 200 }),
    );
    render(
      <AuthProvider><SWRConfig value={{ provider: () => new Map() }}><MemoryRouter><ReposTab workspace="ws1" /></MemoryRouter></SWRConfig></AuthProvider>,
    );
    await waitFor(() => expect(screen.getByText("up1")).toBeTruthy());
    // 来源列：无 url → 本地化 kind 文案（i18n mock 返回 key）
    expect(screen.getByText("repos.kinds.upload")).toBeTruthy();
    // 分支列：upload 也走 combobox（后端枚举本地分支，可切换；点开才拉，渲染零请求）
    expect(screen.getByLabelText("repoDetail.switchAria")).toBeTruthy();
    expect(screen.getByText("main")).toBeTruthy();
    // 无 pull（凭据未进 ws auth，更新=重新上传），删除仍可用
    expect(screen.queryByLabelText("repos.updateAria")).toBeNull();
    expect(screen.getByLabelText("repos.deleteAria")).toBeTruthy();
  });

  it("解压中仓库：轮询刷新启用（extracting → 定时 listRepos 直到 ready）", async () => {
    vi.useFakeTimers();
    try {
      const fm = vi.spyOn(window, "fetch");
      fm.mockResolvedValueOnce(
        new Response(JSON.stringify({ user: { id: 1, username: "alice", role: "user" } }), { status: 200 }),
      );
      let calls = 0;
      fm.mockImplementation(async () => {
        calls += 1;
        // 首拉（extracting）→ 轮询第 1 次（ready）→ 停
        const body = calls <= 1
          ? [{ name: "up1", state: "extracting", source: { kind: "upload" } }]
          : [{ name: "up1", state: "ready", source: { kind: "upload", branch: "main" } }];
        return new Response(JSON.stringify(body), { status: 200 });
      });
      render(
        <AuthProvider><SWRConfig value={{ provider: () => new Map() }}><MemoryRouter><ReposTab workspace="ws1" /></MemoryRouter></SWRConfig></AuthProvider>,
      );
      await vi.waitFor(() => expect(screen.getByText("up1")).toBeTruthy());
      const listCallsAfterFirst = calls;
      await vi.advanceTimersByTimeAsync(2100);  // 越过一个 2s 轮询周期
      expect(calls).toBeGreaterThan(listCallsAfterFirst);  // 轮询确实发生
      // ready 后（下一次刷新）轮询停止：再等一个周期不新增请求
      await vi.advanceTimersByTimeAsync(2100);
      const settled = calls;
      await vi.advanceTimersByTimeAsync(2100);
      expect(calls).toBe(settled);
    } finally {
      vi.useRealTimers();
    }
  });

  it("批量删除：勾全选 → 删除选中 → 确认 → POST batch-delete 带 names 并刷新", async () => {
    const fm = vi.spyOn(window, "fetch");
    fm.mockImplementation(async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : (input as Request).url;
      if (url.includes("/auth/me")) {
        return new Response(JSON.stringify({ user: { id: 1, username: "alice", role: "user" } }), { status: 200 });
      }
      if (url.includes("/repos/batch-delete")) {
        return new Response(JSON.stringify({ deleted: ["r1", "r2"], unlinked: [], skipped: [] }), { status: 200 });
      }
      return new Response(JSON.stringify([
        { name: "r1", state: "ready" }, { name: "r2", state: "ready" },
      ]), { status: 200 });
    });
    render(
      <AuthProvider><SWRConfig value={{ provider: () => new Map() }}><MemoryRouter><ReposTab workspace="ws1" /></MemoryRouter></SWRConfig></AuthProvider>,
    );
    await waitFor(() => expect(screen.getByText("r1")).toBeTruthy());
    // 初始无批量删除入口
    expect(screen.queryByText("repos.bulk.deleteSelected")).toBeNull();
    // 勾全选（名称列头 checkbox）
    fireEvent.click(screen.getByLabelText("repos.bulk.selectAll"));
    // 批量操作栏出现
    expect(screen.getByText("repos.bulk.deleteSelected")).toBeTruthy();
    // 点「删除选中」→「确认」
    fireEvent.click(screen.getByText("repos.bulk.deleteSelected"));
    fireEvent.click(screen.getByText("common.confirm"));
    // POST /repos/batch-delete 被调用，body.names 含 r1/r2
    await waitFor(() => {
      expect(fm.mock.calls.some(([u]) => String(u).includes("/repos/batch-delete"))).toBeTruthy();
    });
    const batchCall = fm.mock.calls.find(([u]) => String(u).includes("/repos/batch-delete"));
    const init = batchCall?.[1] as RequestInit | undefined;
    const names: string[] = JSON.parse(init?.body as string).names;
    expect([...names].sort()).toEqual(["r1", "r2"]);
  });

  it("扁平列表：列头唯一、单个 table、所在目录独立成列", async () => {
    const fm = vi.spyOn(window, "fetch");
    fm.mockImplementation(async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : (input as Request).url;
      if (url.includes("/auth/me")) {
        return new Response(JSON.stringify({ user: { id: 1, username: "alice", role: "user" } }), { status: 200 });
      }
      return new Response(JSON.stringify([
        { name: "alpha/r1", group: "alpha", state: "ready" },
        { name: "beta/r2", group: "beta", state: "ready" },
      ]), { status: 200 });
    });
    const { container } = render(
      <AuthProvider><SWRConfig value={{ provider: () => new Map() }}><MemoryRouter><ReposTab workspace="ws1" /></MemoryRouter></SWRConfig></AuthProvider>,
    );
    await waitFor(() => expect(screen.getByText("r1")).toBeTruthy());
    // 列头只出现一次（重构前每个分组一张独立表，列头重复 N 次）
    expect(screen.getAllByText("repos.table.name")).toHaveLength(1);
    // 整页只有一个 table 元素（重构前 N 分组 = N 张表）
    expect(container.querySelectorAll("table")).toHaveLength(1);
    // 所在目录列头存在
    expect(screen.getByText("repos.table.directory")).toBeTruthy();
    // 目录名落在「目录」列（扁平列表，不再有分组行）
    expect(screen.getByText("alpha")).toBeTruthy();
    expect(screen.getByText("beta")).toBeTruthy();
  });

  it("空壳目录：显示 empty 徽标、无更新按钮、有删除按钮（占位可清理）", async () => {
    const fm = vi.spyOn(window, "fetch");
    fm.mockImplementation(async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : (input as Request).url;
      if (url.includes("/auth/me")) {
        return new Response(JSON.stringify({ user: { id: 1, username: "alice", role: "user" } }), { status: 200 });
      }
      return new Response(JSON.stringify([
        { name: "frontend", state: "empty", source: { kind: "unknown" } },
      ]), { status: 200 });
    });
    render(
      <AuthProvider><SWRConfig value={{ provider: () => new Map() }}><MemoryRouter><ReposTab workspace="ws1" /></MemoryRouter></SWRConfig></AuthProvider>,
    );
    await waitFor(() => expect(screen.getByText("frontend")).toBeTruthy());
    expect(screen.getByText("repos.states.empty")).toBeTruthy();     // 空目录徽标（i18n mock → key）
    expect(screen.queryByLabelText("repos.updateAria")).toBeNull(); // 无更新(pull)按钮——空壳 pull 必 409
    expect(screen.getByLabelText("repos.deleteAria")).toBeTruthy(); // 有删除按钮（icon-only）
  });

  // ---- 分支列行内切换（spec 2026-08-21 §3）：ready+git+私有克隆 → BranchCombobox ----

  function mockFetchByRoute(handlers: Record<string, unknown>, role = "user") {
    const fm = vi.spyOn(window, "fetch");
    fm.mockImplementation(async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : (input as Request).url;
      if (url.includes("/auth/me")) {
        return new Response(JSON.stringify({ user: { id: 1, username: "alice", role } }), { status: 200 });
      }
      for (const [frag, body] of Object.entries(handlers)) {
        if (url.includes(frag)) return new Response(JSON.stringify(body), { status: 200 });
      }
      return new Response(JSON.stringify([]), { status: 200 });
    });
    return fm;
  }

  it("分支列：ready+git+私有克隆渲染切换下拉（显示当前分支），linked 保持只读", async () => {
    mockFetchByRoute({ "/repos": [
      { name: "app", state: "ready", source: { kind: "git", url: "https://x/app.git", branch: "main" } },
      { name: "ftoa", linked: true, state: "ready", source: { kind: "linked" } },
    ] });
    render(
      <AuthProvider><SWRConfig value={{ provider: () => new Map() }}><MemoryRouter><ReposTab workspace="ws1" /></MemoryRouter></SWRConfig></AuthProvider>,
    );
    await waitFor(() => expect(screen.getByText("app")).toBeTruthy());
    // 私有克隆：分支列是 combobox 触发器（icon-only，aria 在触发器上）
    expect(screen.getByLabelText("repoDetail.switchAria")).toBeTruthy();
    expect(screen.getByText("main")).toBeTruthy();
    // linked：无切换入口（后端 405），只有一处 switchAria（私有克隆行）
    expect(screen.getAllByLabelText("repoDetail.switchAria")).toHaveLength(1);
  });

  it("分支列：admin 看 linked 仓库渲染切换下拉 + 更新按钮（spec 2026-09-04）", async () => {
    mockFetchByRoute({ "/repos": [
      { name: "ftoa", linked: true, state: "ready", source: { kind: "linked", branch: "main" } },
    ] }, "admin");
    render(
      <AuthProvider><SWRConfig value={{ provider: () => new Map() }}><MemoryRouter><ReposTab workspace="ws1" /></MemoryRouter></SWRConfig></AuthProvider>,
    );
    await waitFor(() => expect(screen.getByText("ftoa")).toBeTruthy());
    expect(screen.getByLabelText("repoDetail.switchAria")).toBeTruthy(); // admin：linked 也有切换下拉
    expect(screen.getByLabelText("repos.updateAria")).toBeTruthy();     // admin：linked 也有更新(pull)
  });

  it("分支列：非 ready（cloning）保持只读，不渲染下拉", async () => {
    mockFetchByRoute({ "/repos": [
      { name: "busy", state: "cloning", source: { kind: "git", branch: "main" } },
    ] });
    render(
      <AuthProvider><SWRConfig value={{ provider: () => new Map() }}><MemoryRouter><ReposTab workspace="ws1" /></MemoryRouter></SWRConfig></AuthProvider>,
    );
    await waitFor(() => expect(screen.getByText("busy")).toBeTruthy());
    expect(screen.queryByLabelText("repoDetail.switchAria")).toBeNull();
    expect(screen.getByText("main")).toBeTruthy(); // 只读文本仍显示分支
  });

  // ---- 分组筛选（2026-09-16）：搜索框右侧 Select（全部/各分组/未分组），与搜索词 AND ----

  it("分组筛选：选某组只显该组行、未分组档只显扁平仓", async () => {
    mockFetchByRoute({ "/repos": [
      { name: "alpha/r1", group: "alpha", state: "ready" },
      { name: "alpha/r2", group: "alpha", state: "ready" },
      { name: "beta/r3", group: "beta", state: "ready" },
      { name: "solo", state: "ready" },
    ] });
    render(
      <AuthProvider><SWRConfig value={{ provider: () => new Map() }}><MemoryRouter><ReposTab workspace="ws1" /></MemoryRouter></SWRConfig></AuthProvider>,
    );
    await waitFor(() => expect(screen.getByText("r1")).toBeTruthy());
    // 默认「全部」：四个仓全在
    expect(screen.getByText("r3")).toBeTruthy();
    expect(screen.getByText("solo")).toBeTruthy();
    // 选 alpha 组：beta/扁平仓出局
    fireEvent.click(screen.getByRole("combobox", { name: "repos.groupFilter.label" }));
    fireEvent.click(await screen.findByRole("option", { name: /^alpha$/ }));
    await waitFor(() => expect(screen.queryByText("r3")).toBeNull());
    expect(screen.getByText("r1")).toBeTruthy();
    expect(screen.getByText("r2")).toBeTruthy();
    expect(screen.queryByText("solo")).toBeNull();
    // 切「未分组」：只剩无 group 的扁平仓
    fireEvent.click(screen.getByRole("combobox", { name: "repos.groupFilter.label" }));
    fireEvent.click(await screen.findByRole("option", { name: "repos.ungrouped" }));
    await waitFor(() => expect(screen.queryByText("r1")).toBeNull());
    expect(screen.getByText("solo")).toBeTruthy();
  });

  it("分组筛选与搜索词 AND 叠加：组内再按名收窄", async () => {
    mockFetchByRoute({ "/repos": [
      { name: "alpha/web", group: "alpha", state: "ready" },
      { name: "alpha/api", group: "alpha", state: "ready" },
      { name: "beta/web", group: "beta", state: "ready" },
    ] });
    render(
      <AuthProvider><SWRConfig value={{ provider: () => new Map() }}><MemoryRouter><ReposTab workspace="ws1" /></MemoryRouter></SWRConfig></AuthProvider>,
    );
    await waitFor(() => expect(screen.getByText("api")).toBeTruthy());
    expect(screen.getAllByText("web")).toHaveLength(2); // alpha/web + beta/web（名称列渲染 basename）
    fireEvent.click(screen.getByRole("combobox", { name: "repos.groupFilter.label" }));
    fireEvent.click(await screen.findByRole("option", { name: /^alpha$/ }));
    // 名称列是 basename，beta/web 出局 = "web" 只剩一处
    await waitFor(() => expect(screen.getAllByText("web")).toHaveLength(1));
    // 组筛选后再搜 "api"：只剩 alpha/api（beta/web 已被组筛掉、alpha/web 被词筛掉）
    fireEvent.change(screen.getByLabelText("repos.searchPlaceholder"), { target: { value: "api" } });
    await waitFor(() => expect(screen.queryByText("web")).toBeNull());
    expect(screen.getByText("api")).toBeTruthy();
  });

  it("全部仓库都无分组：不渲染分组筛选 Select（避免噪音控件）", async () => {
    mockFetchByRoute({ "/repos": [
      { name: "r1", state: "ready" },
      { name: "r2", state: "ready" },
    ] });
    render(
      <AuthProvider><SWRConfig value={{ provider: () => new Map() }}><MemoryRouter><ReposTab workspace="ws1" /></MemoryRouter></SWRConfig></AuthProvider>,
    );
    await waitFor(() => expect(screen.getByText("r1")).toBeTruthy());
    expect(screen.queryByRole("combobox", { name: "repos.groupFilter.label" })).toBeNull();
  });

  it("切分支：选中其他分支 → POST /checkout + 成功 toast + 刷新列表", async () => {
    const fm = mockFetchByRoute({
      "/branches": { branches: ["dev", "main"] },
      "/repos": [
        { name: "app", state: "ready", source: { kind: "git", url: "https://x/app.git", branch: "main" } },
      ],
    });
    render(
      <AuthProvider><SWRConfig value={{ provider: () => new Map() }}><MemoryRouter><ReposTab workspace="ws1" /></MemoryRouter></SWRConfig></AuthProvider>,
    );
    await waitFor(() => expect(screen.getByLabelText("repoDetail.switchAria")).toBeTruthy());
    fireEvent.click(screen.getByLabelText("repoDetail.switchAria"));
    const dev = await screen.findByRole("option", { name: /^dev$/ });
    fireEvent.click(dev);
    await waitFor(() => {
      expect(fm.mock.calls.some(([u]) => String(u).includes("/repos/app/checkout"))).toBeTruthy();
    });
    const call = fm.mock.calls.find(([u]) => String(u).includes("/repos/app/checkout"));
    const init = call?.[1] as RequestInit | undefined;
    expect(JSON.parse(init?.body as string)).toEqual({ branch: "dev" });
    const { toast } = await import("sonner");
    await waitFor(() => expect(toast.success).toHaveBeenCalled());
  });
});
