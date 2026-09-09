// 跨仓关联表单 tab 组件（2026-09-04 tabs 重组瘦身：只留仓库行列表——ws/YAML/黑盒验证
// 上提 tabs 外，relations chips 撤除）。三方同步（表单→图/YAML）在 ScanNewPage.test.tsx
// 端到端锁定；本文件聚焦行内交互：增删行/角色/星型边补齐/来源与复用候选/校验。
// 风格对齐 ScanFormFields.test.tsx：msw + MemoryRouter + i18n zh + fireEvent。
import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach } from "vitest";
import { useState } from "react";
import { render, screen, fireEvent, waitFor, cleanup, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { setupServer } from "msw/node";
import { http, HttpResponse } from "msw";
import i18n from "@/i18n";
import { CorrelationFormFields } from "./CorrelationFormFields";
import type { CorrFormState } from "@/lib/correlation-yaml";

const REPOS_FIXTURE = [
  { name: "frontend", state: "ready", source: { kind: "git", url: "https://gitlab.example/frontend.git" } },
  { name: "order-svc", state: "ready", source: { kind: "git", url: "https://gitlab.example/order-svc.git" } },
  { name: "pay-svc", state: "ready", source: { kind: "git", url: "https://gitlab.example/pay-svc.git" } },
];

// 复用候选 fixture：order-svc 一条白盒（应命中）+ frontend 一条白盒（应被 repo 过滤掉）。
// 智能默认（2026-09-09）补：order-svc 再挂更旧成功 + 更新失败（默认只认最新 completed）；
// pay-svc 只有失败扫描（→ 默认现扫）。
const WB_SCANS = [
  {
    scan_id: "20260801-120000", workflow_id: "ws1-order-20260801-120000", scan_type: "whitebox",
    repo: "order-svc", status: "completed", created_at: 1722400000, vuln_count: 1, is_running: false,
  },
  {
    scan_id: "20260801-110000", workflow_id: "ws1-order-20260801-110000", scan_type: "whitebox",
    repo: "order-svc", status: "completed", created_at: 1722300000, vuln_count: 1, is_running: false,
  },
  {
    scan_id: "20260801-140000", workflow_id: "ws1-order-20260801-140000", scan_type: "whitebox",
    repo: "order-svc", status: "failed", created_at: 1722400200, vuln_count: 0, is_running: false,
  },
  {
    scan_id: "20260801-150000", workflow_id: "ws1-pay-20260801-150000", scan_type: "whitebox",
    repo: "pay-svc", status: "failed", created_at: 1722400300, vuln_count: 0, is_running: false,
  },
  {
    scan_id: "20260801-999999", workflow_id: "ws1-front-20260801-999999", scan_type: "whitebox",
    repo: "frontend", status: "completed", created_at: 1722400100, vuln_count: 0, is_running: false,
  },
];

const server = setupServer(
  http.get("/api/workspaces/:ws/repos", () => HttpResponse.json(REPOS_FIXTURE)),
  http.get("/api/workspaces/:ws/scans", () => HttpResponse.json(WB_SCANS)),
);

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
beforeEach(() => { i18n.changeLanguage("zh"); });
afterEach(() => { server.resetHandlers(); cleanup(); });
afterAll(() => server.close());

/** 复刻页面的表单路径（onState 三方扇出的源侧）：记录每次上抛的 state 供断言
 *  （relations 不再在表单渲染——星型边补齐经 captured state 断言）。 */
let captured: CorrFormState[] = [];
function Harness() {
  const [state, setState] = useState<CorrFormState>({ repos: [], relations: [] });
  return (
    <MemoryRouter>
      <CorrelationFormFields
        state={state}
        onState={(s) => { captured.push(s); setState(s); }}
        workspace="ws1"
      />
    </MemoryRouter>
  );
}
const lastState = () => captured.at(-1)!;

// RepoCombobox 触发器（未选中显 placeholder「选择仓库」）——按卡片 scope 取。
function openRepoPicker(card: HTMLElement) {
  fireEvent.click(within(card).getByText("选择仓库"));
}

async function pickRepo(name: string) {
  fireEvent.click(await screen.findByText(name));
}

describe("CorrelationFormFields", () => {
  beforeEach(() => { captured = []; });

  it("添加两个仓库 + 角色默认第一个 entrypoint → 命名 backend 时自动补星型边", async () => {
    render(<Harness />);
    // 无卡片 → 添加两次（第一张默认 entrypoint，第二张默认 backend）
    fireEvent.click(screen.getByRole("button", { name: "+ 添加仓库" }));
    fireEvent.click(screen.getByRole("button", { name: "+ 添加仓库" }));
    const cards = screen.getAllByTestId("corr-repo-row");
    expect(cards).toHaveLength(2);
    expect(within(cards[0]).getByRole("button", { name: "入口" })).toHaveAttribute("aria-pressed", "true");
    expect(within(cards[1]).getByRole("button", { name: "后端" })).toHaveAttribute("aria-pressed", "true");
    // 分别选仓库（frontend 入口 / order-svc 后端）
    openRepoPicker(cards[0]);
    await pickRepo("frontend");
    openRepoPicker(cards[1]);
    await pickRepo("order-svc");
    // 星型边自动补齐（entrypoint → backend，协议取卡片默认 grpc）——经上抛 state 断言
    // （chips 摘要已随 tabs 重组撤除，边的可视化主场在图 tab）
    await waitFor(() => expect(lastState().relations).toEqual([
      { from: "frontend", to: "order-svc", protocol: "grpc" },
    ]));
  });

  it("复用模式选历史扫描 → state 记 reuseScanId（候选按 repo 过滤）", async () => {
    render(<Harness />);
    fireEvent.click(screen.getByRole("button", { name: "+ 添加仓库" }));
    const card = screen.getByTestId("corr-repo-row");
    openRepoPicker(card);
    await pickRepo("order-svc");
    // 智能默认（2026-09-09）：命名即预选最新成功扫描 120000——来源已是「复用历史」，
    // trigger 显已选项而非占位文案；点开 trigger 手动改选更旧的 110000。
    fireEvent.click(within(card).getByText(/20260801-120000/).closest("button")!);
    // 候选下拉：order-svc 的白盒在列；frontend 的白盒被 repo 过滤掉
    fireEvent.click(await screen.findByRole("option", { name: /20260801-110000/ }));
    expect(screen.queryByRole("option", { name: /20260801-999999/ })).toBeNull();
    // 上抛 state 记录复用选择（formToYaml 语义：复用卡写 workspace: <scan_id>，页面级 YAML 测）
    expect(lastState().repos[0].reuseScanId).toBe("20260801-110000");
  });

  it("智能默认：有成功白盒的仓库命名即默认复用最新 completed；只有失败/未扫过 → 现扫", async () => {
    render(<Harness />);
    fireEvent.click(screen.getByRole("button", { name: "+ 添加仓库" }));
    fireEvent.click(screen.getByRole("button", { name: "+ 添加仓库" }));
    const cards = screen.getAllByTestId("corr-repo-row");
    // order-svc：两条 completed（120000 新于 110000）+ 一条更新的 failed → 默认 120000
    openRepoPicker(cards[0]);
    await pickRepo("order-svc");
    await waitFor(() => expect(lastState().repos[0].reuseScanId).toBe("20260801-120000"));
    // pay-svc：只有 failed 扫描 → 保持现扫（null）
    openRepoPicker(cards[1]);
    await pickRepo("pay-svc");
    await waitFor(() => expect(lastState().repos[1].repo).toBe("pay-svc"));
    expect(lastState().repos[1].reuseScanId).toBeNull();
  });

  it("改名到别的仓库：携带的复用 id 不在新仓库候选 → 重置为新仓库智能默认", async () => {
    render(<Harness />);
    fireEvent.click(screen.getByRole("button", { name: "+ 添加仓库" }));
    const card = screen.getByTestId("corr-repo-row");
    openRepoPicker(card);
    await pickRepo("order-svc");
    await waitFor(() => expect(lastState().repos[0].reuseScanId).toBe("20260801-120000"));
    // 改名 pay-svc（无成功扫描）→ 旧 id 重置为 null（现扫）
    fireEvent.click(within(card).getByText("order-svc"));
    await pickRepo("pay-svc");
    await waitFor(() => expect(lastState().repos[0].reuseScanId).toBeNull());
    // 改回 order-svc → 重新应用智能默认
    fireEvent.click(within(card).getByText("pay-svc"));
    await pickRepo("order-svc");
    await waitFor(() => expect(lastState().repos[0].reuseScanId).toBe("20260801-120000"));
  });

  it("缺 entrypoint 提交校验拦截（唯一卡片切 backend → 显校验问题）", async () => {
    render(<Harness />);
    fireEvent.click(screen.getByRole("button", { name: "+ 添加仓库" }));
    const card = screen.getByTestId("corr-repo-row");
    // 唯一卡片从默认 entrypoint 切成 backend → 无 entrypoint
    fireEvent.click(within(card).getByRole("button", { name: "后端" }));
    await waitFor(() =>
      expect(screen.getByTestId("corr-form-issues").textContent).toContain("至少需要一个 entrypoint"));
    // 切回 entrypoint → entrypoint 问题消失（卡片未命名的另一 issue 合法保留）
    fireEvent.click(within(card).getByRole("button", { name: "入口" }));
    await waitFor(() =>
      expect(screen.getByTestId("corr-form-issues").textContent).not.toContain("entrypoint"));
  });

  it("删除仓库行 → 引用该仓的星型边同步清除", async () => {
    render(<Harness />);
    fireEvent.click(screen.getByRole("button", { name: "+ 添加仓库" }));
    fireEvent.click(screen.getByRole("button", { name: "+ 添加仓库" }));
    const cards = screen.getAllByTestId("corr-repo-row");
    openRepoPicker(cards[0]);
    await pickRepo("frontend");
    openRepoPicker(cards[1]);
    await pickRepo("order-svc");
    await waitFor(() => expect(lastState().relations.length).toBe(1));
    // 删 order-svc 行 → 边引用清除（图 tab 侧同步由页面扇出保证）
    fireEvent.click(within(cards[1]).getByRole("button", { name: "删除仓库" }));
    await waitFor(() => expect(lastState().relations).toEqual([]));
    expect(lastState().repos.map((r) => r.repo)).toEqual(["frontend"]);
  });
});
