import { describe, it, expect, vi, beforeEach } from "vitest";
import type { ReactElement } from "react";
import { render, screen, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import i18n from "@/i18n";
import { ScanGatePanel } from "./ScanGatePanel";
import type { ScanGateSnapshot } from "@/api/client";

beforeEach(() => i18n.changeLanguage("zh"));

vi.mock("@/api/client", () => ({
  getScanGate: vi.fn(),
}));

/** Link 需要 Router 上下文（芯片/条目链接到扫描详情）。 */
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

  it("默认摘要自描述：谁的仓/开始或入队时刻/历时/空闲格/排队顺序都可见", () => {
    renderPanel(<ScanGatePanel snapshot={snap} />);
    const panel = screen.getByTestId("scan-gate-panel");
    // 占用芯片带 ws + 时刻·历时（不展开也答「谁在跑/何时/多久」）
    expect(screen.getByText("prod")).toBeInTheDocument();
    // 排队芯片只按顺序展示 ws/时刻，不逐项标 #N
    expect(screen.getByText("dev")).toBeInTheDocument();
    expect(screen.queryByText(/^#\d+$/)).not.toBeInTheDocument();
    const chipTimes = screen.getAllByTestId("gate-chip-time");
    expect(chipTimes).toHaveLength(2);
    for (const el of chipTimes) {
      expect(el.textContent).toMatch(/\d{2}:\d{2} · .+[mhd<]/);
    }
    // 空闲槽：capacity 5 - held 1 = 4 格
    expect(screen.getAllByTestId("gate-free")).toHaveLength(4);
    expect(panel).toHaveTextContent("1/5");
    // 任务名明细不在收起态
    expect(screen.queryByText("payment-svc@main")).toBeNull();
    expect(screen.getByRole("button")).toHaveAttribute("aria-expanded", "false");
  });

  it("手动点开：任务名明细 + 启动/入队时刻语义提示", () => {
    renderPanel(<ScanGatePanel snapshot={snap} />);
    fireEvent.click(screen.getByRole("button"));
    const panel = screen.getByTestId("scan-gate-panel");
    expect(panel).toHaveTextContent("payment-svc@main");
    expect(panel).toHaveTextContent("user-svc!12");
    // 队列按快照顺序渲染，不逐项显示「第 N 位」
    expect(panel).not.toHaveTextContent("第 1 位");
    // 段标行右侧微提示：两段时刻列语义不同（since=acquired_at vs first_seen）
    expect(panel).toHaveTextContent("启动 · 已运行");
    expect(panel).toHaveTextContent("入队 · 已等待");
    // 时刻列显式展示（非 hover-only）：HH:mm · 时长
    const times = screen.getAllByTestId("gate-time");
    expect(times.length).toBe(2);
    for (const el of times) expect(el.textContent).toMatch(/\d{2}:\d{2} · .+[mhd<]/);
    expect(screen.getByRole("button")).toHaveAttribute("aria-expanded", "true");
  });

  it("展开态摘要条让位收起（drill-down 去重：明细是芯片信息超集），再收起恢复", () => {
    renderPanel(<ScanGatePanel snapshot={snap} />);
    expect(screen.getByTestId("scan-gate-rail")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button"));
    expect(screen.queryByTestId("scan-gate-rail")).toBeNull();
    // 计数与明细仍在（「空几格」语义由 x/capacity 接管）
    expect(screen.getByTestId("scan-gate-panel")).toHaveTextContent("1/5");
    expect(screen.getByText("payment-svc@main")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button"));
    expect(screen.getByTestId("scan-gate-rail")).toBeInTheDocument();
  });

  it("kind 徽章 i18n（whitebox→白盒）", () => {
    renderPanel(<ScanGatePanel snapshot={snap} />);
    fireEvent.click(screen.getByRole("button"));
    expect(screen.getByText("白盒")).toBeInTheDocument();
  });

  it("摘要条长队列：全量渲染并横向滚动（不折叠 +N）", () => {
    const waiting = Array.from({ length: 9 }, (_, i) => ({
      ws: "dev", scan_id: `s${i}`, kind: "mr", label: `q-${i}`, since: 2,
    }));
    renderPanel(<ScanGatePanel snapshot={{ capacity: 5, max_waiting: 50, held: [], waiting }} />);
    expect(screen.queryAllByTestId("gate-slot")).toHaveLength(0);
    expect(screen.getAllByTestId("gate-free")).toHaveLength(5);
    expect(screen.getAllByTestId("gate-waiting")).toHaveLength(9);
    expect(screen.queryByText("+6")).not.toBeInTheDocument();
    const scroll = screen.getByTestId("gate-waiting-chips-scroll");
    expect(scroll.className).toContain("overflow-x-auto");
    expect(scroll.className).toContain("overscroll-x-contain");
  });

  it("展开后长排队全量渲染在限高滚动容器内（全局透明不截断，面板高度仍有界）", () => {
    const waiting = Array.from({ length: 7 }, (_, i) => ({
      ws: "dev", scan_id: `s${i}`, kind: "mr", label: `user-svc!${i}`, since: 2,
    }));
    renderPanel(<ScanGatePanel snapshot={{ capacity: 5, max_waiting: 50, held: [], waiting }} />);
    fireEvent.click(screen.getByRole("button"));
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

  it("本工作区标记：收起态摘要行「我排第 N 位」+ 芯片 ws coral + 展开行 gutter", () => {
    renderPanel(<ScanGatePanel snapshot={snap} currentWs="dev" />);
    // 收起态短标
    expect(screen.getByText("我排第 1 位")).toBeInTheDocument();
    // 排队芯片（ws=dev）coral：testid gate-waiting 内 ws span 带 text-primary
    const chip = screen.getByTestId("gate-waiting");
    expect(chip.querySelector("span.text-primary")).not.toBeNull();
    // 展开行 gutter title
    fireEvent.click(screen.getByRole("button"));
    expect(screen.getByTitle("本工作区")).toBeInTheDocument();
  });

  it("ws+scan_id 齐全的条目链接到扫描详情（芯片与明细行都通）", () => {
    renderPanel(<ScanGatePanel snapshot={snap} />);
    expect(screen.getByRole("link", { name: /prod/ }))
      .toHaveAttribute("href", "/p/prod/scans/s1");
    fireEvent.click(screen.getByRole("button"));
    expect(screen.getByRole("link", { name: "payment-svc@main" }))
      .toHaveAttribute("href", "/p/prod/scans/s1");
  });
});
