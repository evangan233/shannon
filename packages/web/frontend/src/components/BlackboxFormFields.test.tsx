import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach, vi } from "vitest";
import { useState } from "react";
import { screen, fireEvent, cleanup, waitFor } from "@testing-library/react";
import { renderWithSwr } from "@/test/swr-render";
import { setupServer } from "msw/node";
import { http, HttpResponse } from "msw";
import i18n from "@/i18n";
import { BlackboxFormFields } from "./BlackboxFormFields";
import {
  DEFAULT_AUTH, DEFAULT_HOST, type AuthFormState, type FormState, type HostFormState,
} from "@/pages/ScanNewPage";
import type { Workspace } from "@/api/types";

// 黑盒验证表单（D3 入口回归，2026-09-10）：选已完成白盒任务 + 补填目标 URL/认证/HOST。
// 选择器口径与 ScanDetail「加黑盒」按钮一致（scan_type=whitebox ∧ status ∈ 终态白盒产物集）；
// 选中后 getScan 拉原任务黑盒配置（bb_url/认证/HOST）预填——对齐组合扫描重跑预填语义。

const WS_LIST: Workspace[] = [
  { name: "ws1", scan_type: "whitebox", status: "completed", created_at: 0 },
];

/** 候选集：s1=completed（可选）、s2=running（不可选）、s3=failed（不可选——产物口径外）、
 *  s4=cancelled（可选——取消过黑盒 run 的任务白盒产物仍完好）、s5=blackbox 类型（不可选）、
 *  s6=correlation（不可选）。 */
const scansPayload = [
  { scan_id: "wb-s1", scan_type: "whitebox", status: "completed", created_at: 1000,
    completed_at: 2000, vuln_count: 3, is_running: false, workflow_id: "ws1-wb-s1", repo: "foo" },
  { scan_id: "wb-s2", scan_type: "whitebox", status: "running", created_at: 1100,
    vuln_count: 0, is_running: true, workflow_id: "ws1-wb-s2", repo: "bar" },
  { scan_id: "wb-s3", scan_type: "whitebox", status: "failed", created_at: 1200,
    vuln_count: 0, is_running: false, workflow_id: "ws1-wb-s3", repo: "baz" },
  { scan_id: "wb-s4", scan_type: "whitebox", status: "cancelled", created_at: 1300,
    vuln_count: 1, is_running: false, workflow_id: "ws1-wb-s4", repo: "qux" },
  { scan_id: "bb-s5", scan_type: "blackbox", status: "completed", created_at: 1400,
    vuln_count: 0, is_running: false, workflow_id: "ws1-bb-s5" },
  { scan_id: "co-s6", scan_type: "correlation", status: "completed", created_at: 1500,
    vuln_count: 0, is_running: false, workflow_id: "ws1-co-s6" },
];

const server = setupServer(
  http.get("/api/workspaces/:ws/scans", () => HttpResponse.json(scansPayload)),
  http.get("/api/workspaces/:ws/scans/:scanId", ({ params }) =>
    HttpResponse.json({
      web_url: "", scan_type: "whitebox", workflow_id: `ws1-${params.scanId}`,
      bb_url: params.scanId === "wb-s1" ? "http://target.example.com" : "",
      auth_profile_id: params.scanId === "wb-s1" ? "ap-1" : null,
      auth_credential_ids: params.scanId === "wb-s1" ? ["cred-1"] : null,
      host_profile_id: params.scanId === "wb-s1" ? "hp-1" : null,
    })),
  http.get("/api/workspaces/:ws/auth-profiles", () => HttpResponse.json([])),
  http.get("/api/workspaces/:ws/host-profiles", () => HttpResponse.json([])),
);

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
beforeEach(() => i18n.changeLanguage("zh"));
afterEach(() => { server.resetHandlers(); cleanup(); });
afterAll(() => server.close());

/** 受控 harness：持 FormState，透传 set/setAuth/setHost；dump 出 url/auth.source/host.enabled
 *  供选中预填断言（避免窥探组件内部实现）。 */
function Harness() {
  const [f, setF] = useState<FormState>({
    selectedRepo: "", url: "", reuseScanId: "",
    auth: DEFAULT_AUTH, host: DEFAULT_HOST, yaml: "",
  });
  const set = (patch: Partial<FormState>) => setF((prev) => ({ ...prev, ...patch }));
  const setAuth = (patch: Partial<AuthFormState>) =>
    setF((prev) => ({ ...prev, auth: { ...prev.auth, ...patch } }));
  const setHost = (patch: Partial<HostFormState>) =>
    setF((prev) => ({ ...prev, host: { ...prev.host, ...patch } }));
  return (
    <div>
      <BlackboxFormFields
        f={f} set={set} setAuth={setAuth} setHost={setHost}
        scanErr={null} urlErr={null} authErr={null} hostErr={null}
        workspace="ws1" wsList={WS_LIST} onWorkspaceChange={vi.fn()} wsLoading={false}
      />
      <div data-testid="state-dump" data-url={f.url}
        data-auth-source={f.auth.source} data-host-enabled={String(f.host.enabled)}
        data-reuse={f.reuseScanId} />
    </div>
  );
}

function renderForm() {
  return renderWithSwr(<Harness />);
}

/** Radix Select：click trigger 打开下拉（jsdom 已验证姿势，见 ScanNewPage.test）。 */
function selectOption(triggerText: RegExp | string, optionName: RegExp | string) {
  const trigger = screen.getByText(triggerText).closest("button")!;
  fireEvent.click(trigger);
  return screen.findByRole("option", { name: optionName }).then((opt) => {
    fireEvent.click(opt);
  });
}

describe("BlackboxFormFields 黑盒验证表单", () => {
  it("渲染工作区选择 + 白盒任务选择器 + 目标 URL 三段结构", async () => {
    renderForm();
    expect(screen.getByText("工作区")).toBeInTheDocument();
    expect(screen.getByText("白盒任务")).toBeInTheDocument();
    expect(screen.getByText("目标 URL")).toBeInTheDocument();
    await screen.findByText("ws1"); // 工作区已选回显
  });

  it("任务选择器只列白盒终态任务（completed/cancelled），排除 running/failed/黑盒/跨仓", async () => {
    renderForm();
    fireEvent.click(screen.getByText("选择要验证的白盒任务").closest("button")!);
    await waitFor(() => screen.getByRole("option", { name: /wb-s1/ }));
    expect(screen.getByRole("option", { name: /wb-s1/ })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: /wb-s4/ })).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: /wb-s2/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("option", { name: /wb-s3/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("option", { name: /bb-s5/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("option", { name: /co-s6/ })).not.toBeInTheDocument();
  });

  it("选中任务后 getScan 预填 bb_url 为目标 URL + 认证/HOST 原配置", async () => {
    renderForm();
    await selectOption("选择要验证的白盒任务", /wb-s1/);
    const dump = await waitFor(() => {
      const el = screen.getByTestId("state-dump");
      expect(el.dataset.url).toBe("http://target.example.com");
      return el;
    });
    expect(dump.dataset.reuse).toBe("wb-s1");
    expect(dump.dataset.authSource).toBe("profile");
    expect(dump.dataset.hostEnabled).toBe("true");
  });

  it("无候选任务时选择器显示空态提示", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans", () => HttpResponse.json([])),
    );
    renderForm();
    fireEvent.click(screen.getByText("选择要验证的白盒任务").closest("button")!);
    expect(await screen.findByRole("option", { name: "暂无可加黑盒的白盒任务" })).toBeInTheDocument();
  });
});
