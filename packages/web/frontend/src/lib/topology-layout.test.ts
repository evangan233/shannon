// layout 纯函数（调用层级分层）——自 TopologyGraph.test 迁入（2026-09-21
// TopologyGraph 组件由只读 TopologyEditor 取代，布局函数迁 lib/topology-layout）。
import { describe, it, expect } from "vitest";
import { layout } from "./topology-layout";

const services = [
  { name: "frontend", role: "entrypoint" },
  { name: "order-svc", role: "backend" },
  { name: "admin", role: "backend" },
];
const edges = [
  { from: "frontend", to: "order-svc" },
  { from: "admin", to: "order-svc" },
];

describe("layout 纯函数（调用层级分层）", () => {
  it("入口与无前驱 backend 同落第 0 层，被调方严格右侧分层", () => {
    const { nodes } = layout(services, edges);
    const frontend = nodes.find((n) => n.name === "frontend")!;
    const order = nodes.find((n) => n.name === "order-svc")!;
    const admin = nodes.find((n) => n.name === "admin")!;
    expect(frontend.role).toBe("entrypoint");
    // frontend(E)、admin(无前驱 backend)同层；order-svc 被两者调用 → 第 1 层
    expect(frontend.x).toBe(admin.x);
    expect(order.x).toBeGreaterThan(frontend.x);
    // 同层内垂直均分：frontend 在 admin 上方（services 原序）
    expect(frontend.y).toBeLessThan(admin.y);
  });

  it("多跳链逐层右移：a→b→c 三层 x 严格递增", () => {
    const chain = [
      { name: "a", role: "entrypoint" },
      { name: "b", role: "backend" },
      { name: "c", role: "backend" },
    ];
    const { nodes } = layout(chain, [{ from: "a", to: "b" }, { from: "b", to: "c" }]);
    const x = (n: string) => nodes.find((v) => v.name === n)!.x;
    expect(x("a")).toBeLessThan(x("b"));
    expect(x("b")).toBeLessThan(x("c"));
  });

  it("环边不死循环（迭代收敛，节点仍有确定层）", () => {
    const pair = [
      { name: "a", role: "entrypoint" },
      { name: "b", role: "backend" },
    ];
    const { nodes } = layout(pair, [{ from: "a", to: "b" }, { from: "b", to: "a" }]);
    expect(nodes).toHaveLength(2);
    expect(nodes.every((n) => Number.isFinite(n.x) && Number.isFinite(n.y))).toBe(true);
  });

  it("单层居中；height = max(各层节点数, 1) × heightPerNode + 40，空服务不塌缩", () => {
    expect(layout([]).height).toBe(1 * 90 + 40);
    expect(layout(services, edges).height).toBe(Math.max(2, 1) * 90 + 40);
    expect(layout([{ name: "fe", role: "entrypoint" }]).height).toBe(1 * 90 + 40);
    // 孤立服务全落第 0 层 → 单列居中
    const single = layout([{ name: "fe", role: "entrypoint" }, { name: "iso", role: "backend" }]);
    const x = new Set(single.nodes.map((n) => n.x));
    expect(x.size).toBe(1);
  });
});
