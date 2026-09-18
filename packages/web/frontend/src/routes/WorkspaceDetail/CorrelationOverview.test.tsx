// D6：简版 CorrelationOverview——三段阶段横幅（子仓白盒|跨仓关联|黑盒验证，状态从
// getScan + getCorrelationDetail + listScans 富化推导）+ corr_children 子仓状态网格
//（现扫在前、复用殿后，D4 NestedCorrChildren 同源约定）。
// 风格对齐 CorrelationTab.test：msw + MemoryRouter + SWRConfig 独立 cache + i18n zh。
import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach } from "vitest";
import { render, screen, within, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { setupServer } from "msw/node";
import { http, HttpResponse } from "msw";
import { SWRConfig } from "swr";
import i18n from "@/i18n";
import { CorrelationOverview, deriveCorrelationSegments } from "./CorrelationOverview";
import type { CorrelationDetail, ScanSummary } from "@/api/types";

// fixture：2 子仓（frontend 现扫 / order-svc 复用）+ 关联未完成（topology null）。
const detail: CorrelationDetail = {
  topology: null,
  boundaries: [],
  flows: [],
  multi_hop_chains: [],
  adjudication: null,
  merged_vulns: {},
  drift_warnings: [],
  corr_children: [
    { service: "frontend", scan_id: "20260824-000001", reused: false },
    { service: "order-svc", scan_id: "20260824-000002", reused: true },
  ],
  dismissed: [],
  adjudication_status: null,
  report_md: null,
};

const scan = (over: Partial<ScanSummary> = {}): ScanSummary => ({
  scan_id: "x", scan_type: "whitebox", status: "completed", created_at: 0,
  vuln_count: 0, is_running: false, ...over,
});

const server = setupServer();

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
beforeEach(() => i18n.changeLanguage("zh"));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

function mount() {
  return render(
    <MemoryRouter>
      <SWRConfig value={{ provider: () => new Map() }}>
        <CorrelationOverview ws="w1" scanId="s1" />
      </SWRConfig>
    </MemoryRouter>,
  );
}

/** 挂三端点 mock（getScan / correlation detail / listScans）并等横幅出现。 */
async function mountWith(opts: {
  meta?: Record<string, unknown>;
  d?: CorrelationDetail;
  scans?: ScanSummary[];
  until?: string;
}) {
  server.use(
    http.get("/api/workspaces/:ws/scans/:scanId", () =>
      HttpResponse.json({ status: "running", scan_type: "correlation", ...opts.meta })),
    http.get("/api/workspaces/:ws/scans/:scanId/correlation", () =>
      HttpResponse.json(opts.d ?? detail)),
    http.get("/api/workspaces/:ws/scans", () =>
      HttpResponse.json(opts.scans ?? [])),
  );
  mount();
  await waitFor(() =>
    expect(screen.getByTestId(opts.until ?? "corr-overview-segs")).toBeInTheDocument());
}

// === 纯函数：三段状态推导 ===
describe("deriveCorrelationSegments", () => {
  it("运行中 + 现扫子仓在跑：段①进行中 / 段②待接力 / 段③待接力", () => {
    expect(deriveCorrelationSegments({
      scanStatus: "running", childrenCount: 2,
      freshChildStatuses: ["running"], topologyReady: false,
    })).toEqual(["inProgress", "pending", "pending"]);
  });

  it("全部复用（无现扫子仓）：段①已完成；扫描进行中段②进行中", () => {
    expect(deriveCorrelationSegments({
      scanStatus: "running", childrenCount: 2,
      freshChildStatuses: [], topologyReady: false,
    })).toEqual(["done", "inProgress", "pending"]);
  });

  it("子仓全终态（成功）：段①已完成 / 段②进行中（关联跑着，topology 未出）", () => {
    expect(deriveCorrelationSegments({
      scanStatus: "running", childrenCount: 1,
      freshChildStatuses: ["completed"], topologyReady: false,
    })).toEqual(["done", "inProgress", "pending"]);
  });

  it("子仓失败 → 主行 failed：段①失败 / 段②失败 / 段③已跳过", () => {
    expect(deriveCorrelationSegments({
      scanStatus: "failed", childrenCount: 1,
      freshChildStatuses: ["failed"], topologyReady: false,
    })).toEqual(["failed", "failed", "skipped"]);
  });

  it("topology 就绪 → 段②已完成；run completed → 段③已完成", () => {
    expect(deriveCorrelationSegments({
      scanStatus: "completed", childrenCount: 2,
      freshChildStatuses: ["completed"], topologyReady: true,
      latestRunStatus: "completed",
    })).toEqual(["done", "done", "done"]);
  });

  it("黑盒验证 run failed → 段③失败（段①②已完成）", () => {
    expect(deriveCorrelationSegments({
      scanStatus: "failed", childrenCount: 1,
      freshChildStatuses: ["completed"], topologyReady: true,
      latestRunStatus: "failed",
    })).toEqual(["done", "done", "failed"]);
  });

  it("run 运行中 → 段③进行中；终态无 run（未配网关）→ 段③已跳过", () => {
    expect(deriveCorrelationSegments({
      scanStatus: "running", childrenCount: 1,
      freshChildStatuses: ["completed"], topologyReady: true,
      latestRunStatus: "running",
    })[2]).toBe("inProgress");
    expect(deriveCorrelationSegments({
      scanStatus: "completed", childrenCount: 1,
      freshChildStatuses: ["completed"], topologyReady: true,
    })[2]).toBe("skipped");
  });

  it("子仓状态查不到（历史行被删）：按任务级状态兜底不误报进行中", () => {
    expect(deriveCorrelationSegments({
      scanStatus: "failed", childrenCount: 1,
      freshChildStatuses: [undefined], topologyReady: false,
    })).toEqual(["done", "failed", "skipped"]);
  });
});

// === 集成：横幅 + 子仓网格渲染 ===
describe("CorrelationOverview", () => {
  it("三段横幅渲染（标签 + 推导状态）", async () => {
    await mountWith({
      scans: [scan({ scan_id: "20260824-000001", status: "running" })],
    });
    // SWR 数据落地后状态文本出现（横幅容器先行渲染，状态异步补全）
    await waitFor(() =>
      expect(screen.getByTestId("corr-seg-children").textContent).toContain("进行中"));
    const segs = screen.getByTestId("corr-overview-segs");
    expect(within(segs).getByTestId("corr-seg-children").textContent).toContain("子仓白盒");
    expect(within(segs).getByTestId("corr-seg-correlation").textContent).toContain("跨仓关联");
    expect(within(segs).getByTestId("corr-seg-correlation").textContent).toContain("待接力");
    expect(within(segs).getByTestId("corr-seg-verify").textContent).toContain("黑盒验证");
    expect(within(segs).getByTestId("corr-seg-verify").textContent).toContain("待接力");
  });

  it("子仓状态网格：现扫在前 + listScans 富化状态 + 复用/新扫标注", async () => {
    await mountWith({
      scans: [
        scan({ scan_id: "20260824-000001", status: "running" }),
        scan({ scan_id: "20260824-000002", status: "completed" }),
      ],
    });
    const grid = screen.getByTestId("corr-ov-children");
    // 子行随 corr detail 落地出现（网格容器先渲染骨架）
    await waitFor(() =>
      expect(within(grid).getAllByTestId(/^corr-ov-child-/)).toHaveLength(2));
    const rows = within(grid).getAllByTestId(/^corr-ov-child-/);
    expect(rows).toHaveLength(2);
    // 现扫在前（frontend），复用殿后（order-svc）
    expect(rows[0].getAttribute("data-testid")).toBe("corr-ov-child-20260824-000001");
    expect(rows[1].getAttribute("data-testid")).toBe("corr-ov-child-20260824-000002");
    expect(within(rows[0]).getByText("frontend")).toBeInTheDocument();
    expect(within(rows[0]).getByText("新扫")).toBeInTheDocument();
    expect(within(rows[1]).getByText("复用")).toBeInTheDocument();
    // 状态徽标（Badge title=原始状态；label 走 workspaces.status.* 本地化）
    expect(rows[0].querySelector("[title='running']")).toBeInTheDocument();
    expect(rows[1].querySelector("[title='completed']")).toBeInTheDocument();
    // 子仓链接到对应 scan 详情
    expect(within(rows[0]).getByRole("link", { name: /20260824-000001/ }).getAttribute("href"))
      .toBe("/p/w1/scans/20260824-000001");
  });

  it("关联完成：段②已完成 + 合并漏洞计数 + 跳转跨仓关联 tab 链接", async () => {
    await mountWith({
      meta: {
        status: "completed",
        bb_runs: [{ run_id: "run-1", status: "completed" }],
        latest_bb_run: "run-1",
      },
      d: {
        ...detail,
        topology: {
          services: [
            { name: "frontend", role: "entrypoint", repo: "frontend" },
            { name: "order-svc", role: "backend", repo: "order-svc" },
          ],
          edges: [],
        },
        merged_vulns: { injection: [{ title: "a" }, { title: "b" }] },
      },
      scans: [scan({ scan_id: "20260824-000001", status: "completed" })],
      until: "corr-ov-result",
    });
    const segs = screen.getByTestId("corr-overview-segs");
    expect(within(segs).getByTestId("corr-seg-children").textContent).toContain("已完成");
    expect(within(segs).getByTestId("corr-seg-correlation").textContent).toContain("已完成");
    expect(within(segs).getByTestId("corr-seg-verify").textContent).toContain("已完成");
    const result = screen.getByTestId("corr-ov-result");
    expect(result.textContent).toContain("2");
    expect(within(result).getByRole("link").getAttribute("href"))
      .toBe("/p/w1/scans/s1/correlation");
  });

  it("关联详情加载失败 → 错误态", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId", () =>
        HttpResponse.json({ status: "running", scan_type: "correlation" })),
      http.get("/api/workspaces/:ws/scans/:scanId/correlation", () =>
        new HttpResponse("nope", { status: 500 })),
      http.get("/api/workspaces/:ws/scans", () =>
        HttpResponse.json([])),
    );
    mount();
    await waitFor(() =>
      expect(screen.getByTestId("corr-ov-error")).toBeInTheDocument());
  });
});
