// prune/edges.tsx 自定义边测试（T10，TDD 先行）——verdict 着色 class + data-branch 锚点
// + 联动态 + 同名弧。边路径从 data.rect 自算（不依赖 RF handle 测量，jsdom 确定性）。
import { fireEvent, render } from "@testing-library/react";
import { expect, beforeAll, describe, it, vi } from "vitest";
import i18next from "i18next";
import { BranchEdge, SamelineEdge } from "../prune/edges";
import { BranchEventsContext } from "../prune/events";
import type { BranchEdgeData, SamelineEdgeData } from "../prune/edges";

beforeAll(() => {
  i18next.changeLanguage("zh");
});

const events = { onHover: vi.fn(), onSelect: vi.fn(), onFoldToggle: vi.fn() };
const eventsRef = { onHover: vi.fn(), onSelect: vi.fn(), onFoldToggle: vi.fn() };
events.onHover.mockImplementation((id: string | null) => eventsRef.onHover(id));

const rect = (x: number, y: number): { x: number; y: number; w: number; h: number } => ({
  x,
  y,
  w: 160,
  h: 50,
});

const branchData = (p: Partial<BranchEdgeData> = {}): BranchEdgeData => ({
  verdict: "vulnerable",
  branchId: "B-1",
  hovered: false,
  selected: false,
  sourceRect: rect(12, 20),
  targetRect: rect(216, 30),
  ...p,
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function renderEdge(Cmp: React.ComponentType<any>, data: unknown) {
  render(<BranchEventsContext.Provider value={events}>{<Cmp data={data} />}</BranchEventsContext.Provider>);
}

describe("BranchEdge", () => {
  it("vulnerable：path class 含 branch-vuln，不含常驻 flow（动效只 hovered/selected 触发）", () => {
    renderEdge(BranchEdge, branchData());
    const path = document.querySelector("path[data-branch='vulnerable']")!;
    expect(path).toBeTruthy();
    expect(path.getAttribute("class")).toContain("branch-vuln");
    expect(path.getAttribute("class")).not.toContain("flow");
  });

  it("safe/unknown verdict class", () => {
    renderEdge(BranchEdge, branchData({ verdict: "safe" }));
    expect(document.querySelector("path[data-branch='safe']")!.getAttribute("class")).toContain("branch-safe");
    renderEdge(BranchEdge, branchData({ verdict: "unknown" }));
    expect(document.querySelector("path[data-branch='unknown']")!.getAttribute("class")).toContain(
      "branch-unknown",
    );
  });

  it("g[data-branch-id] 锚点 + hover/selected 联动态 class 与属性", () => {
    renderEdge(BranchEdge, branchData({ hovered: true }));
    const g = document.querySelector("g[data-branch-id='B-1']")!;
    expect(g).toBeTruthy();
    expect(g.hasAttribute("data-hovered")).toBe(true);
    expect(g.querySelector("path")!.getAttribute("class")).toContain("hovered");
    renderEdge(BranchEdge, branchData({ selected: true }));
    const g2 = document.querySelectorAll("g[data-branch-id='B-1']")[1];
    expect(g2.hasAttribute("data-selected")).toBe(true);
    expect(g2.querySelector("path")!.getAttribute("class")).toContain("selected");
  });

  it("hover g → onHover(branchId)；离开 → onHover(null)；点击 → onSelect", () => {
    renderEdge(BranchEdge, branchData());
    const g = document.querySelector("g[data-branch-id='B-1']")!;
    fireEvent.mouseEnter(g);
    expect(events.onHover).toHaveBeenCalledWith("B-1");
    fireEvent.mouseLeave(g);
    expect(events.onHover).toHaveBeenCalledWith(null);
    fireEvent.click(g);
    expect(events.onSelect).toHaveBeenCalledWith("B-1");
  });

  it("命中层存在（interactionWidth 20px 透明 path，细线可点）", () => {
    renderEdge(BranchEdge, branchData());
    const hit = document.querySelector("path.prune-edge-hit")! as unknown as SVGElement;
    expect(hit).toBeTruthy();
    expect(hit.style.strokeWidth).toBe("20px");
  });

  it("路径 d 非空（rect 自算几何：贝塞尔 M/C 指令）", () => {
    renderEdge(BranchEdge, branchData());
    const d = document.querySelector("path[data-branch='vulnerable']")!.getAttribute("d")!;
    expect(d.startsWith("M")).toBe(true);
    expect(d).toContain("C"); // 贝塞尔
  });
});

describe("SamelineEdge", () => {
  const sameData = (p: Partial<SamelineEdgeData> = {}): SamelineEdgeData => ({
    from: { x: 12, y: 20, w: 160, h: 50 },
    to: { x: 12, y: 150, w: 160, h: 50 },
    ...p,
  });

  it("g[data-sameline] + path.sameline 类 + 无文字标注（语义在 LegendBar）", () => {
    renderEdge(SamelineEdge, sameData());
    const g = document.querySelector("g[data-sameline]")!;
    expect(g).toBeTruthy();
    expect(g.querySelector("path.sameline")).toBeTruthy();
    expect(g.querySelector("text")).toBeNull();
  });

  it("二次贝塞尔弧（Q 指令，控制点上抬）", () => {
    renderEdge(SamelineEdge, sameData());
    const d = document.querySelector("g[data-sameline] path")!.getAttribute("d")!;
    expect(d).toContain("Q");
  });
});
