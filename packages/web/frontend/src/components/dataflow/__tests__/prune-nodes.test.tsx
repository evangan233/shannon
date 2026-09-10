// prune/nodes.tsx 自定义节点测试（T9，TDD 先行）——语义锚点平移自旧 PruningTreeFig.test：
// data-* 锚点（data-source/-node/-sink-target/-scissors/-remnant/-pubfunc/-storage-relay/
// -collapsed-safe…）+ 原生 tooltip（HTML title 属性，旧 SVG <title> 等价）+ 键盘可达。
import { fireEvent, render, screen } from "@testing-library/react";
import { expect, beforeAll, describe, it, vi } from "vitest";
import i18next from "i18next";
import type { StepNodeData, SourceNodeData, SinkNodeData, FoldNodeData } from "../prune/types";
import { FoldNode, SinkNode, SourceNode, StepNode } from "../prune/nodes";
import { BranchEventsContext } from "../prune/events";
import type { DataflowNode } from "@/api/types";

beforeAll(() => {
  i18next.changeLanguage("zh"); // 旧 PruningTreeFig.test 惯例：文案断言锁 zh
});

const events = { onHover: vi.fn(), onSelect: vi.fn(), onFoldToggle: vi.fn() };
function withEvents(ui: React.ReactElement) {
  return <BranchEventsContext.Provider value={events}>{ui}</BranchEventsContext.Provider>;
}

/** 直渲染 helper：NodeProps 的 RF 内部必填字段（id/type/selected/dragging…）与组件自身
 *  渲染无关，测试只验组件内容——宽松组件类型绕过（tsc 豁免点，语义同旧直渲染）。 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function renderNode(Cmp: React.ComponentType<any>, data: unknown, ctx = true) {
  const el = <Cmp data={data} />;
  render(ctx ? withEvents(el) : el);
}

function dataNode(func: string, line: number, note?: string): DataflowNode {
  return { func, note: note ?? null, file: "app.js", line, intermediate_vars: [], has_code: false };
}

const srcData = (p: Partial<SourceNodeData> = {}): SourceNodeData => ({
  kind: "source",
  branchId: "B-1",
  verdict: "vulnerable",
  sinkLabel: "eval",
  label: "req.body.q",
  metaText: "body · GET /x",
  isStorage: false,
  note: null,
  crossTreeSinks: null,
  hovered: false,
  selected: false,
  ...p,
});

const stepData = (p: Partial<StepNodeData> = {}): StepNodeData => ({
  kind: "step",
  branchId: "B-1",
  step: 2,
  fullLabel: "dao.find:88",
  lines: ["dao.find:88"],
  node: dataNode("dao.find", 88),
  isVuln: true,
  isCut: false,
  shield: "none",
  pub: null,
  hovered: false,
  selected: false,
  ...p,
});

const sinkData = (p: Partial<SinkNodeData> = {}): SinkNodeData => ({
  kind: "sink",
  hasVuln: true,
  label: "eval",
  lines: ["eval"],
  note: null,
  ...p,
});

describe("SourceNode", () => {
  it("data-source/data-node=0/data-branch 锚点 + label/meta 文本", () => {
    renderNode(SourceNode, srcData());
    const el = document.querySelector("[data-source]")!;
    expect(el.getAttribute("data-node")).toBe("0");
    expect(el.getAttribute("data-branch")).toBe("vulnerable");
    expect(el.getAttribute("data-branch-id")).toBe("B-1");
    expect(screen.getByText("req.body.q")).toBeTruthy();
    expect(screen.getByText("body · GET /x")).toBeTruthy();
    expect(el.className).toContain("prune-source");
  });

  it("tooltip：note 叙事原句优先 + 跨树提示并存拼接", () => {
    renderNode(SourceNode, srcData({ note: "用户输入经路由直达 DAO 查询", crossTreeSinks: "mongo.$where" }));
    const title = document.querySelector("[data-source]")!.getAttribute("title")!;
    expect(title).toContain("用户输入经路由直达 DAO 查询");
    expect(title).toContain("同一入口还流向");
    expect(title).toContain("mongo.$where");
  });

  it("无 note → 退 label·type·entry 兜底", () => {
    renderNode(SourceNode, srcData());
    expect(document.querySelector("[data-source]")!.getAttribute("title")).toBe(
      "req.body.q · body · GET /x",
    );
  });

  it("storage 枝：琥珀 ⟳ 存储中转标记 + tooltip 白话全句", () => {
    renderNode(SourceNode, srcData({ isStorage: true, metaText: null, label: "db.row.x" }));
    const el = document.querySelector("[data-storage-relay]")!;
    expect(el.textContent).toContain("存储中转");
    const title = document.querySelector("[data-source]")!.getAttribute("title")!;
    expect(title).toContain("先存进数据库，读出来才发起请求");
  });

  it("键盘可达：role=button + aria 含 source/sink/判定 + Enter/Space toggle 选中", () => {
    renderNode(SourceNode, srcData());
    const el = document.querySelector("[data-source]")!;
    expect(el.getAttribute("role")).toBe("button");
    expect(el.getAttribute("aria-label")).toContain("req.body.q");
    expect(el.getAttribute("aria-label")).toContain("eval");
    fireEvent.keyDown(el, { key: "Enter" });
    expect(events.onSelect).toHaveBeenCalledWith("B-1");
    fireEvent.keyDown(el, { key: " " });
    expect(events.onSelect).toHaveBeenCalledTimes(2);
  });

  it("hover/selected 联动态：data-hovered/data-selected", () => {
    renderNode(SourceNode, srcData({ hovered: true }));
    expect(document.querySelector("[data-source]")!.hasAttribute("data-hovered")).toBe(true);
    renderNode(SourceNode, srcData({ selected: true }));
    expect(document.querySelectorAll("[data-source]")[1].hasAttribute("data-selected")).toBe(true);
  });
});

describe("StepNode", () => {
  it("data-node=step + 标签文本 + vuln 配色类", () => {
    renderNode(StepNode, stepData());
    const el = document.querySelector("[data-node='2']")!;
    expect(el.getAttribute("data-node")).toBe("2");
    expect(el.textContent).toContain("dao.find:88");
    expect(el.className).toContain("prune-node-vuln");
  });

  it("剪断点：✂ data-scissors + data-remnant 残端装饰", () => {
    renderNode(StepNode, stepData({ isVuln: false, isCut: true }));
    expect(document.querySelector("[data-scissors]")).toBeTruthy();
    expect(document.querySelector("[data-remnant]")).toBeTruthy();
    expect(document.querySelector("[data-node='2']")!.className).toContain("prune-node-safe");
  });

  it("盾：绕过=黄环 / 有效=绿环（环挂圆点）", () => {
    renderNode(StepNode, stepData({ shield: "yellow" }));
    expect(document.querySelector(".prune-dot")!.className).toContain("prune-shield-yellow");
    renderNode(StepNode, stepData({ shield: "green" }));
    expect(document.querySelectorAll(".prune-dot")[1].className).toContain("prune-shield-green");
  });

  it("公共函数下标：⟳ 文案 + tooltip 说明剪断了哪几条枝", () => {
    renderNode(StepNode, stepData({ pub: { count: 2, cutBranches: ["S-1", "S-2"] } }));
    const pub = document.querySelector("[data-pubfunc]")!;
    expect(pub.textContent).toContain("公共函数");
    expect(pub.textContent).toContain("2");
    const title = document.querySelector("[data-node='2']")!.getAttribute("title")!;
    expect(title).toContain("S-1");
    expect(title).toContain("S-2");
  });

  it("note 叙事原句进 tooltip（label 归一为短标识符后全文在此）", () => {
    renderNode(StepNode, stepData({ node: dataNode("dao.find", 88, "threshold 直接拼接进 $where") }));
    expect(document.querySelector("[data-node='2']")!.getAttribute("title")).toContain(
      "threshold 直接拼接进 $where",
    );
  });

  it("无 note 无 pub → 不设 title", () => {
    renderNode(StepNode, stepData());
    expect(document.querySelector("[data-node='2']")!.getAttribute("title")).toBeNull();
  });
});

describe("SinkNode", () => {
  it("有打通枝：data-sink-target=vuln + sink-pulse 脉动", () => {
    renderNode(SinkNode, sinkData(), false);
    const el = document.querySelector("[data-sink-target]")!;
    expect(el.getAttribute("data-sink-target")).toBe("vuln");
    expect(el.querySelector(".sink-pulse")).toBeTruthy();
    expect(screen.getByText("eval")).toBeTruthy();
  });

  it("safe-only：灰虚线靶心 + 「无输入到达」+ tooltip 带 note 优先", () => {
    renderNode(SinkNode, sinkData({ hasVuln: false, note: "所有枝被防护拦下" }), false);
    const el = document.querySelector("[data-sink-target]")!;
    expect(el.getAttribute("data-sink-target")).toBe("safe");
    expect(el.querySelector(".sink-idle")).toBeTruthy();
    expect(document.querySelector("[data-sink-noinput]")!.textContent).toContain("无输入到达");
    expect(el.getAttribute("title")).toContain("所有枝被防护拦下");
    expect(el.getAttribute("title")).toContain("无输入到达");
  });
});

describe("FoldNode", () => {
  const foldData = (p: Partial<FoldNodeData> = {}): FoldNodeData => ({
    kind: "fold",
    hiddenCount: 3,
    expanded: false,
    highlighted: false,
    ...p,
  });

  it("折叠态文案「+N 条枝被剪断」+ 点击/键盘 toggle", () => {
    renderNode(FoldNode, foldData());
    const el = document.querySelector("[data-collapsed-safe]")!;
    expect(el.textContent).toContain("+3");
    expect(el.textContent).toContain("剪断");
    expect(el.getAttribute("role")).toBe("button");
    fireEvent.click(el);
    expect(events.onFoldToggle).toHaveBeenCalledTimes(1);
    fireEvent.keyDown(el, { key: "Enter" });
    expect(events.onFoldToggle).toHaveBeenCalledTimes(2);
  });

  it("展开态文案「收起」+ hover 被折叠枝明细行联动高亮（data-hovered）", () => {
    renderNode(FoldNode, foldData({ expanded: true, highlighted: true }));
    const el = document.querySelector("[data-collapsed-safe]")!;
    expect(el.textContent).toContain("收起");
    expect(el.hasAttribute("data-hovered")).toBe(true);
  });
});
