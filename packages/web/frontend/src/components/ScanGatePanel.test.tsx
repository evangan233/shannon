import { describe, it, expect, vi, beforeEach } from "vitest";
import type { ReactElement } from "react";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import i18n from "@/i18n";
import { ScanGatePanel } from "./ScanGatePanel";
import type { ScanGateSnapshot } from "@/api/client";

beforeEach(() => i18n.changeLanguage("zh"));

vi.mock("@/api/client", () => ({
  getScanGate: vi.fn(),
}));

/** Link 需要 Router 上下文（条目链接到扫描详情）。 */
const renderPanel = (ui: ReactElement) => render(<MemoryRouter>{ui}</MemoryRouter>);

const snap: ScanGateSnapshot = {
  capacity: 5,
  max_waiting: 50,
  held: [
    { ws: "prod", scan_id: "s1", kind: "whitebox", label: "payment-svc@main", since: 1 },
  ],
  waiting: [
    { ws: "dev", scan_id: "s2", kind: "mr", label: "user-svc!12", since: 2 },
  ],
};

describe("ScanGatePanel", () => {
  it("空快照不渲染", () => {
    const { container } = renderPanel(
      <ScanGatePanel snapshot={{ capacity: 5, max_waiting: 50, held: [], waiting: [] }} />);
    expect(container.querySelector("[data-testid=scan-gate-panel]")).toBeNull();
  });

  it("无折叠：明细常驻直出（任务名/类型/时刻都可见）+ 标题行 x/capacity 计数", () => {
    renderPanel(<ScanGatePanel snapshot={snap} />);
    const panel = screen.getByTestId("scan-gate-panel");
    // 两段明细无需任何交互即可见（2026-09-15 用户裁定去折叠）
    expect(panel).toHaveTextContent("payment-svc@main");
    expect(panel).toHaveTextContent("user-svc!12");
    expect(screen.getByText("白盒")).toBeInTheDocument();
    expect(screen.getByText("MR")).toBeInTheDocument();
    // 标题行计数答「空几格」
    expect(panel).toHaveTextContent("1/5");
    // 无展开按钮（折叠机制已移除）
    expect(screen.queryByRole("button")).toBeNull();
  });

  it("段标行右侧微提示：两段时刻列语义不同（since=acquired_at vs first_seen）", () => {
    renderPanel(<ScanGatePanel snapshot={snap} />);
    expect(screen.getByText("启动 · 已运行")).toBeInTheDocument();
    expect(screen.getByText("入队 · 已等待")).toBeInTheDocument();
  });

  it("时刻列显式展示（非 hover-only）：HH:mm · 时长", () => {
    renderPanel(<ScanGatePanel snapshot={snap} />);
    const times = screen.getAllByTestId("gate-time");
    expect(times.length).toBe(2);
    for (const el of times) expect(el.textContent).toMatch(/\d{2}:\d{2} · .+[mhd<]/);
  });

  it("队列按快照顺序渲染，不显示位次文案", () => {
    renderPanel(<ScanGatePanel snapshot={snap} />);
    expect(screen.queryByText(/我排第/)).not.toBeInTheDocument();
    expect(screen.queryByText(/^#\d+$/)).not.toBeInTheDocument();
    expect(screen.getByText("排队中 (1)")).toBeInTheDocument();
  });

  it("长排队全量渲染在限高滚动容器内（全局透明不截断，面板高度仍有界）", () => {
    const waiting = Array.from({ length: 7 }, (_, i) => ({
      ws: "dev", scan_id: `s${i}`, kind: "mr", label: `user-svc!${i}`, since: 2,
    }));
    renderPanel(<ScanGatePanel snapshot={{ capacity: 5, max_waiting: 50, held: [], waiting }} />);
    // 全量渲染：第 6、7 名也可见（滚动可达），段头计数即总数
    expect(screen.getByText("user-svc!5")).toBeInTheDocument();
    expect(screen.getByText("user-svc!6")).toBeInTheDocument();
    expect(screen.getByText("排队中 (7)")).toBeInTheDocument();
    // 限高滚动容器：max-h + overflow + 防滚动穿透
    const scroll = screen.getByTestId("gate-waiting-scroll");
    expect(scroll.className).toContain("max-h-56");
    expect(scroll.className).toContain("overflow-y-auto");
    expect(scroll.className).toContain("overscroll-contain");
  });

  it("本工作区标记：淡底 + 左缘竖线（2026-09-15 美化，文字恒中性），无位次文案", () => {
    renderPanel(<ScanGatePanel snapshot={snap} currentWs="dev" />);
    expect(screen.queryByText(/我排第/)).not.toBeInTheDocument();
    const ownRow = screen.getByTitle("本工作区");
    // 「当前行」范式：gutter 竖线 + 极淡底；ws 名不再染 primary（文字层恒中性）
    expect(ownRow.className).toContain("border-l-primary");
    expect(ownRow.className).toContain("bg-primary/[0.045]");
    expect(ownRow.querySelector("span.text-primary")).toBeNull();
  });

  it("ws+scan_id 齐全的条目链接到扫描详情", () => {
    renderPanel(<ScanGatePanel snapshot={snap} />);
    expect(screen.getByRole("link", { name: "payment-svc@main" }))
      .toHaveAttribute("href", "/p/prod/scans/s1");
    expect(screen.getByRole("link", { name: "user-svc!12" }))
      .toHaveAttribute("href", "/p/dev/scans/s2");
  });
});
