import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import i18n from "@/i18n";
import { ScanGatePanel } from "./ScanGatePanel";
import type { ScanGateSnapshot } from "@/api/client";

beforeEach(() => i18n.changeLanguage("zh"));

vi.mock("@/api/client", () => ({
  getScanGate: vi.fn(),
}));

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
    const { container } = render(
      <ScanGatePanel snapshot={{ capacity: 5, max_waiting: 50, held: [], waiting: [] }} />);
    expect(container.querySelector("[data-testid=scan-gate-panel]")).toBeNull();
  });

  it("渲染运行中/排队中两栏 + 工作区/标签/位次", () => {
    render(<ScanGatePanel snapshot={snap} />);
    const panel = screen.getByTestId("scan-gate-panel");
    expect(panel).toHaveTextContent("1/5");
    expect(panel).toHaveTextContent("payment-svc@main");
    expect(panel).toHaveTextContent("user-svc!12");
    expect(panel).toHaveTextContent("第 1 位");
  });

  it("kind 徽章 i18n（whitebox→白盒）", () => {
    render(<ScanGatePanel snapshot={snap} />);
    expect(screen.getByText("白盒")).toBeInTheDocument();
  });
});
