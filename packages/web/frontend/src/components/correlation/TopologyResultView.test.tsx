// 结果页服务拓扑（只读 TopologyEditor 复用）组件级测试（2026-09-21）：节点/边
// 渲染（入口身份条 / status 语义色与虚线）、只读无编辑工具（undo/redo/手柄）、
// 点边右栏 calls 表、点节点只读面板。自 TopologyGraph.test 组件断言等价迁移。
import { describe, it, expect, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import i18n from "@/i18n";
import { TopologyResultView } from "./TopologyResultView";
import type { CorrelationDetail } from "@/api/types";

type Topology = NonNullable<CorrelationDetail["topology"]>;

const topology: Topology = {
  services: [
    { name: "frontend", role: "entrypoint", repo: "frontend" },
    { name: "order-svc", role: "backend", repo: "order-svc" },
  ],
  edges: [
    {
      from: "frontend",
      to: "order-svc",
      protocol: "grpc",
      status: "ok",
      calls: [
        {
          method: "order.CreateOrder",
          call_site: { file: "checkout.ts", line: 42, snippet: "await stub.create(order)" },
          confidence: "high",
          evidence: "grpc client stub 直连 order-svc",
        },
      ],
    },
  ],
};

beforeEach(() => i18n.changeLanguage("zh"));

describe("TopologyResultView（只读 TopologyEditor 画布）", () => {
  it("渲染服务节点与角色（入口/后端），无编辑工具条与连线手柄", () => {
    render(<TopologyResultView topology={topology} />);
    expect(screen.getByTestId("topology-node-frontend")).toBeInTheDocument();
    expect(screen.getByTestId("topology-node-order-svc")).toBeInTheDocument();
    // 只读：无 undo/redo/重排按钮
    expect(screen.queryByText("撤销")).not.toBeInTheDocument();
    expect(screen.queryByText("重置布局")).not.toBeInTheDocument();
    // 画布仍可 pan/zoom：缩放条在
    expect(screen.getByTitle("全图适配视口")).toBeInTheDocument();
  });

  it("点边 → 右栏 status 徽标 + 该边 calls 表（method / file:line / evidence）", () => {
    render(<TopologyResultView topology={topology} />);
    expect(screen.queryByTestId("topo-calls")).not.toBeInTheDocument();
    // draft edge id = scan:from->to:protocol，testid 经非法字符替换得下划线串
    fireEvent.click(screen.getByTestId("topology-edge-scan_frontend-_order-svc_grpc"));
    expect(screen.getByTestId("topology-edge-status")).toHaveTextContent("ok");
    const calls = screen.getByTestId("topo-calls");
    expect(calls).toBeInTheDocument();
    expect(screen.getByText("order.CreateOrder")).toBeInTheDocument();
    expect(screen.getByText("checkout.ts:42")).toBeInTheDocument();
    expect(screen.getByText("grpc client stub 直连 order-svc")).toBeInTheDocument();
  });

  it("declared-missing 边虚线（status 语义），点节点 → 只读面板（名称+角色）", () => {
    const withMissing: Topology = {
      services: [
        ...topology.services,
        { name: "admin", role: "backend", repo: "admin" },
      ],
      edges: [
        ...topology.edges,
        { from: "admin", to: "order-svc", protocol: "http", status: "declared-missing", calls: [] },
      ],
    };
    render(<TopologyResultView topology={withMissing} />);
    const line = document.querySelector(
      'line[data-testid="topology-edge-scan_admin-_order-svc_http"]');
    expect(line?.getAttribute("stroke-dasharray")).toBe("4 4");
    // 点节点 → 只读面板（选中走 pointerdown/up 序列，对齐编辑器交互）
    fireEvent.pointerDown(screen.getByTestId("topology-node-order-svc"));
    fireEvent.pointerUp(screen.getByTestId("topology-node-order-svc"));
    const panel = screen.getByTestId("topology-node-panel");
    expect(panel).toHaveTextContent("order-svc");
    expect(panel).toHaveTextContent("后端");
  });
});
