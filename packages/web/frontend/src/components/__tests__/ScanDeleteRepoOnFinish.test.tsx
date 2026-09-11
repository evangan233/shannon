/**
 * 扫完即删（delete_repo_on_finish，2026-09-10）：启动扫描可勾选，默认不勾；
 * 勾选后扫描到任意终态由 web 仓库级 sweep 删除对应仓库（跨仓传播给新建子仓）。
 *
 * 覆盖：
 *  - buildBody 纯函数：默认不发该键（wire format 字节不变）；勾选 → true（白盒/MR/跨仓三分支）。
 *  - 白盒整页：勾选 → 提交 body 携带 delete_repo_on_finish:true；不勾 → 键缺省。
 *  - ScanFormFields 直渲染：linked 仓 → checkbox 禁用 + 提示。
 *  - CorrelationFormFields：勾选回传 onCheckboxChange。
 */
import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach, vi } from "vitest";
import { useState } from "react";
import { render, screen, fireEvent, waitFor, cleanup, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { setupServer } from "msw/node";
import { http, HttpResponse } from "msw";
import i18n from "@/i18n";
import { ScanNewPage, buildBody, type FormState, type AuthFormState } from "../../pages/ScanNewPage";
import { ScanFormFields } from "../ScanFormFields";
import { CorrelationFormFields } from "../correlation/CorrelationFormFields";
import type { CorrFormState } from "@/lib/correlation-yaml";
import { SWRConfig } from "swr";

const { mockUseAuth } = vi.hoisted(() => ({ mockUseAuth: vi.fn() }));
vi.mock("@/auth/AuthContext", () => ({ useAuth: () => mockUseAuth() }));

const WS_LIST = [
  { name: "ws1", scan_type: "whitebox", status: "completed", created_at: 0 },
];

const server = setupServer(
  http.get("/api/workspaces", () => HttpResponse.json(WS_LIST)),
  http.get("/api/workspaces/:ws/repos", () => HttpResponse.json([])),
  http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([])),
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

const DISABLED_AUTH: AuthFormState = {
  enabled: false, source: "inline", profileId: "", credentialIds: [],
  loginType: "form", loginUrl: "",
  accounts: [{ role: "admin", username: "", password: "" }], loginFlow: "",
};

function form(overrides: Partial<FormState> = {}): FormState {
  return {
    selectedRepo: "foo",
    selectedRepos: ["foo"],
    url: "",
    reuseScanId: "",
    auth: DISABLED_AUTH,
    host: { enabled: false, mode: "profile", profileIds: [], hostUrl: "" },
    yaml: "",
    ...overrides,
  };
}

// === buildBody 纯函数 ===

describe("buildBody 扫完即删（delete_repo_on_finish）", () => {
  it("白盒默认不勾 → 不发该键（wire format 字节不变）", () => {
    const body = buildBody("whitebox", form(), "ws1");
    expect("delete_repo_on_finish" in body).toBe(false);
  });

  it("白盒勾选 → delete_repo_on_finish=true", () => {
    const body = buildBody("whitebox", form({ deleteRepoOnFinish: true }), "ws1");
    expect(body.delete_repo_on_finish).toBe(true);
  });

  it("MR 勾选 → delete_repo_on_finish=true", () => {
    const body = buildBody("mr", form({
      deleteRepoOnFinish: true, mrBaseRef: "main", mrHeadRef: "feature/x",
    }), "ws1");
    expect(body.delete_repo_on_finish).toBe(true);
  });

  it("MR 默认不勾 → 不发该键", () => {
    const body = buildBody("mr", form({ mrBaseRef: "main", mrHeadRef: "feature/x" }), "ws1");
    expect("delete_repo_on_finish" in body).toBe(false);
  });

  it("跨仓勾选 → delete_repo_on_finish=true", () => {
    const body = buildBody("correlation", form({ deleteRepoOnFinish: true }), "ws1", "repos: {}");
    expect(body.delete_repo_on_finish).toBe(true);
  });

  it("跨仓默认不勾 → 不发该键", () => {
    const body = buildBody("correlation", form(), "ws1", "repos: {}");
    expect("delete_repo_on_finish" in body).toBe(false);
  });
});

// === 白盒整页提交 ===

async function selectOption(triggerText: RegExp | string, optionName: RegExp | string) {
  const trigger = screen.getAllByText(triggerText)[0].closest("button")!;
  fireEvent.click(trigger);
  const opt = await screen.findByRole("option", { name: optionName });
  fireEvent.click(opt);
}

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/scan/new"]}>
      <SWRConfig value={{ provider: () => new Map() }}>
        <ScanNewPage />
      </SWRConfig>
    </MemoryRouter>,
  );
}

async function fillWhiteboxRepo() {
  server.use(
    http.get("/api/workspaces/:ws/repos", () =>
      HttpResponse.json([
        { name: "foo", state: "ready", source: { kind: "git", url: "https://gitlab.example/foo.git" } },
      ])),
  );
  await selectOption("选择 workspace", "ws1");
  await waitFor(() => screen.getByRole("button", { name: /\+ 添加新仓库/ }));
  // 白盒仓库多选（2026-09-11 批量白盒）：勾选 topology-repo-selector 内 foo 的 checkbox
  const selector = await screen.findByTestId("topology-repo-selector");
  fireEvent.click(await within(selector).findByRole("checkbox", { name: /foo/ }));
}

describe("白盒表单扫完即删 checkbox", () => {
  it("默认不勾 → 提交 body 无该键；勾选 → 提交携带 true", async () => {
    const captured: Record<string, unknown>[] = [];
    server.use(http.post("/api/scan", async ({ request }) => {
      captured.push(await request.json() as Record<string, unknown>);
      return HttpResponse.json({ workspace: "ws1", scan_id: "foo-1" }, { status: 202 });
    }));
    renderPage();
    await fillWhiteboxRepo();

    const box = screen.getByRole("checkbox", { name: /扫完即删/ });
    expect(box).toHaveAttribute("aria-checked", "false"); // 默认不勾

    fireEvent.click(screen.getByRole("button", { name: /开始扫描/ }));
    await waitFor(() => expect(captured).toHaveLength(1));
    expect("delete_repo_on_finish" in captured[0]).toBe(false);

    // 勾选后再提交
    fireEvent.click(box);
    expect(box).toHaveAttribute("aria-checked", "true");
    fireEvent.click(screen.getByRole("button", { name: /开始扫描/ }));
    await waitFor(() => expect(captured).toHaveLength(2));
    expect(captured[1].delete_repo_on_finish).toBe(true);
  });

  it("linked 仓选中 → checkbox 禁用并提示不适用", async () => {
    server.use(
      http.get("/api/workspaces/:ws/repos", () =>
        HttpResponse.json([
          { name: "ext", state: "ready", linked: true, source: { kind: "linked", url: "" } },
        ])),
    );
    render(
      <MemoryRouter>
        <ScanFormFields
          type="whitebox"
          f={form({ selectedRepo: "ext", selectedRepos: ["ext"] })}
          set={() => {}}
          sourceErr={null}
          reuseErr={null}
          urlErr={null}
          authErr={null}
          hostErr={null}
          workspace="ws1"
          wsList={WS_LIST as never[]}
          onWorkspaceChange={() => {}}
          wsLoading={false}
        />
      </MemoryRouter>,
    );
    const box = await screen.findByRole("checkbox", { name: /扫完即删/ });
    expect(box).toBeDisabled();
    expect(screen.getByText(/关联仓库/)).toBeInTheDocument();
  });
});

// === CorrelationFormFields 透传 ===

describe("CorrelationFormFields 扫完即删 checkbox", () => {
  it("默认不勾；点击 → 回调 true", async () => {
    const onChange = vi.fn();
    const Harness = () => {
      const [state, setState] = useState<CorrFormState>({ repos: [], relations: [] });
      return (
        <MemoryRouter>
          <CorrelationFormFields
            state={state}
            onState={setState}
            workspace="ws1"
            deleteRepoOnFinish={false}
            onDeleteRepoFinishChange={onChange}
          />
        </MemoryRouter>
      );
    };
    render(<Harness />);
    const box = await screen.findByRole("checkbox", { name: /扫完即删/ });
    expect(box).toHaveAttribute("aria-checked", "false");
    fireEvent.click(box);
    expect(onChange).toHaveBeenCalledWith(true);
  });
});
