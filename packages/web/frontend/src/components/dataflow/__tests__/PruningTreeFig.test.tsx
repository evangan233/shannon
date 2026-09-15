// PruningTreeFig 集成测试（2026-09-10 React Flow 迁移重组版）。
// 结构：语义断言平移自旧版（data-* 锚点 + 文案 + 交互联动）；几何断言（COL_W/xOf/tspan/
// viewBox/常量锁定）与 ZoomViewport 断言已删——几何回归锁移至 prune-layout.test.ts
// （「任意两节点矩形不相交」不变量，比旧像素断言更本质）；缩放交由 React Flow 内置。
// CSS 契约直读 tokens.css（选择器已更新为 React Flow DOM 形态）。
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeAll, describe, expect, it } from "vitest";
import i18next from "i18next";
import type { DataflowBranch, DataflowNode, DataflowSanitizer, DataflowTree } from "@/api/types";
import { PruningTreeFig } from "../PruningTreeFig";
import { BranchRow } from "../BranchRow";

beforeAll(() => {
  i18next.changeLanguage("zh");
});

// —— fixture helpers ——

function node(func: string, line: number, p: Partial<DataflowNode> = {}): DataflowNode {
  return { func, note: null, file: "app.js", line, intermediate_vars: [], has_code: true, code: `SELECT ${func}`, ...p };
}
function san(line: number, effective: boolean, file = "app.js"): DataflowSanitizer {
  return { name: "esc", effective, line, file };
}
function branch(
  id: string,
  verdict: DataflowBranch["verdict"],
  nodes: DataflowNode[],
  sanitizers: DataflowSanitizer[] = [],
  p: Partial<DataflowBranch> = {},
): DataflowBranch {
  return {
    branch_id: id,
    track: "gitnexus",
    verdict,
    source: { label: "req.body.q", type: "body", entry: "GET /x" },
    nodes,
    sanitizers,
    ...p,
  };
}
function tree(id: string, branches: DataflowBranch[], p: Partial<DataflowTree> = {}): DataflowTree {
  return {
    tree_id: id,
    vuln_class: "injection",
    sink: { label: "eval", file: "s.js", line: 9, rule_id: "JS-EVAL", category: "code-exec" },
    findings: [],
    branches,
    ...p,
  };
}

const TOKENS_CSS = readFileSync(
  path.join(path.dirname(fileURLToPath(import.meta.url)), "../../../styles/tokens.css"),
  "utf8",
);

describe("PruningTreeFig — 树卡外壳与树头（spec §5）", () => {
  it("每树一卡：data-tree-id（wrapper 锚点，2026-09-14 锚点挂载上移）+ sink 名 + file:line + rule_id + finding IDs", () => {
    render(<PruningTreeFig trees={[tree("T-1", [branch("B-1", "vulnerable", [node("a", 1)])], { findings: [{ id: "F-9" }] })]} />);
    // 锚点（data-tree-id）挂 wrapper；卡（testid）在其内——同一树容器
    const wrapper = document.querySelector('[data-tree-id="T-1"]')!;
    expect(wrapper).toBeTruthy();
    const card = wrapper.querySelector('[data-testid="pruning-tree-card"]')!;
    expect(card).toBeTruthy();
    expect(card.textContent).toContain("eval");
    expect(card.textContent).toContain("s.js:9");
    expect(card.textContent).toContain("JS-EVAL");
    expect(card.textContent).toContain("F-9");
  });

  it("trees 空 → 不渲染任何卡", () => {
    const { container } = render(<PruningTreeFig trees={[]} />);
    expect(container.querySelector("[data-tree-id]")).toBeNull();
  });

  it("迷你比例条：三段式（红/绿/琥珀）与文案口径", () => {
    render(
      <PruningTreeFig
        trees={[
          tree("T-1", [
            branch("B-1", "vulnerable", [node("a", 1)]),
            branch("B-2", "safe", [node("b", 2)], [san(2, true)]),
            branch("B-3", "unknown", [node("c", 3)]),
          ]),
        ]}
      />,
    );
    const bar = document.querySelector("[data-minibar]")!;
    expect(bar.querySelectorAll("[data-minibar-seg]").length).toBe(3);
    expect(document.querySelector('[data-minibar-seg="unknown"]')).toBeTruthy();
    expect(document.querySelector("[data-minibar-text]")!.textContent).toContain("未判定");
    // 纯 vuln/safe 树：两段
    render(<PruningTreeFig trees={[tree("T-2", [branch("B-1", "vulnerable", [node("a", 1)])])]} />);
    const bar2 = document.querySelectorAll("[data-minibar]")[1];
    expect(bar2.querySelectorAll("[data-minibar-seg]").length).toBe(2);
  });

  it("图容器 aria（pruningTreeAria 含 sink 名与判定计数）", () => {
    render(<PruningTreeFig trees={[tree("T-1", [branch("B-1", "vulnerable", [node("a", 1)])])]} />);
    const flow = document.querySelector(".prune-flow-wrap")!;
    expect(flow.getAttribute("role")).toBe("img");
    expect(flow.getAttribute("aria-label")).toContain("eval");
    expect(flow.getAttribute("aria-label")).toContain("打通");
  });
});

describe("枝条 verdict 视觉语言（spec §5 签名元素）", () => {
  it("打通枝：branch-vuln 红虚线 class，无常驻 flow（动效只在 hovered/selected）", () => {
    render(<PruningTreeFig trees={[tree("T-1", [branch("B-1", "vulnerable", [node("a", 1)])])]} />);
    const path = document.querySelector("path[data-branch='vulnerable']")!;
    expect(path.getAttribute("class")).toContain("branch-vuln");
    expect(path.getAttribute("class")).not.toContain("flow");
  });

  it("剪断枝：branch-safe + 剪断节点 ✂ + 残端（剪断点后节点不渲染）", () => {
    render(
      <PruningTreeFig
        trees={[tree("T-1", [branch("B-1", "safe", [node("a", 1), node("cutHere", 2), node("hidden", 3)], [san(2, true)])])]}
      />,
    );
    expect(document.querySelector("path[data-branch='safe']")!.getAttribute("class")).toContain(
      "branch-safe",
    );
    expect(document.querySelector("[data-scissors]")!.textContent).toContain("✂");
    expect(document.querySelector("[data-remnant]")).toBeTruthy();
    // 剪断点（step2）后的节点不渲染（明细行仍保留全部节点）
    expect(document.querySelector("[data-node='3']")).toBeNull();
    expect(document.querySelector("[data-node='2']")).toBeTruthy();
  });

  it("未判定枝：branch-unknown 琥珀虚线", () => {
    render(<PruningTreeFig trees={[tree("T-1", [branch("B-1", "unknown", [node("a", 1)])])]} />);
    expect(document.querySelector("path[data-branch='unknown']")!.getAttribute("class")).toContain(
      "branch-unknown",
    );
  });

  it("sink 靶心双态：有打通枝=红脉动 / safe-only=灰虚线+无输入到达", () => {
    render(
      <PruningTreeFig
        trees={[
          tree("T-1", [branch("B-1", "vulnerable", [node("a", 1)])]),
          tree("T-2", [branch("B-2", "safe", [node("b", 2)], [san(2, true)])]),
        ]}
      />,
    );
    const vulnSink = document.querySelector('[data-sink-target="vuln"]')!;
    expect(vulnSink.querySelector(".sink-pulse")).toBeTruthy();
    const safeSink = document.querySelector('[data-sink-target="safe"]')!;
    expect(safeSink.querySelector(".sink-idle")).toBeTruthy();
    expect(document.querySelector("[data-sink-noinput]")!.textContent).toContain("无输入到达");
  });
});

describe("source pill 与跨树提示", () => {
  it("data-source pill：label + type · METHOD /route 副行", () => {
    render(<PruningTreeFig trees={[tree("T-1", [branch("B-1", "vulnerable", [node("a", 1)])])]} />);
    const src = document.querySelector("[data-source]")!;
    expect(src.getAttribute("data-node")).toBe("0");
    expect(document.querySelector("[data-source-label]")!.textContent).toBe("req.body.q");
    expect(document.querySelector("[data-source-meta]")!.textContent).toBe("body · GET /x");
  });

  it("存储中转枝：琥珀 ⟳ 标记（图内 pill）+ tooltip 白话", () => {
    render(
      <PruningTreeFig
        trees={[tree("T-1", [branch("B-1", "vulnerable", [node("a", 1)], [], { source: { label: "db.row.x", type: "storage", entry: null } })])]}
      />,
    );
    const mark = document.querySelector("[data-source] [data-storage-relay]")!;
    expect(mark.textContent).toContain("存储中转");
    expect(document.querySelector("[data-source]")!.getAttribute("title")).toContain(
      "先存进数据库，读出来才发起请求",
    );
  });

  it("跨树 source 提示：同一入口出现在两树 → tooltip 注「同一入口还流向」", () => {
    render(
      <PruningTreeFig
        trees={[
          tree("T-1", [branch("B-1", "vulnerable", [node("a", 1)])]),
          tree("T-2", [branch("B-2", "vulnerable", [node("b", 2)])], { sink: { label: "mongo.$where", file: "m.js", line: 1 } }),
        ]}
      />,
    );
    const sources = document.querySelectorAll("[data-source]");
    expect(sources.length).toBeGreaterThanOrEqual(2);
    const t1 = document.querySelector('[data-tree-id="T-1"] [data-source]')!.getAttribute("title")!;
    expect(t1).toContain("同一入口还流向");
    expect(t1).toContain("mongo.$where");
  });

  it("LLM note 叙事原句进节点 tooltip（label 归一为短标识符后全文在此）", () => {
    render(
      <PruningTreeFig
        trees={[tree("T-1", [branch("B-1", "vulnerable", [node("dao.find", 88, { note: "threshold 直接模板字符串拼接进 $where" })])])]}
      />,
    );
    expect(document.querySelector("[data-node='1']")!.getAttribute("title")).toContain(
      "threshold 直接模板字符串拼接进 $where",
    );
  });

  it("公共函数下标：同名函数经两枝 → ⟳ N 枝经过 + tooltip 说明", () => {
    render(
      <PruningTreeFig
        trees={[
          tree("T-1", [
            branch("B-1", "vulnerable", [node("shared", 1)]),
            branch("B-2", "safe", [node("shared", 2)], [san(2, true)]),
          ]),
        ]}
      />,
    );
    const pub = document.querySelector("[data-pubfunc]")!;
    expect(pub.textContent).toContain("公共函数");
    expect(pub.textContent).toContain("2");
    expect(document.querySelector("[data-node='1']")!.getAttribute("title")).toContain("B-2");
  });

  it("同名函数弧：青色点线连接（不合并节点，spec 取舍）", () => {
    render(
      <PruningTreeFig
        trees={[
          tree("T-1", [
            branch("B-1", "vulnerable", [node("shared", 1)]),
            branch("B-2", "vulnerable", [node("shared", 2)]),
          ]),
        ]}
      />,
    );
    const arc = document.querySelector("g[data-sameline]")!;
    expect(arc.querySelector("path.sameline")).toBeTruthy();
    expect(arc.querySelector("text")).toBeNull(); // 无文字标注（语义在 LegendBar）
  });
});

describe("剪断枝折叠（>4 折叠为「+N 条枝被剪断」行）", () => {
  const sixSafe = Array.from({ length: 6 }, (_, i) =>
    branch(`S-${i}`, "safe", [node(`f${i}`, 10 + i)], [san(10 + i, true)]),
  );

  it("默认折叠：+N 文案 + 图上 safe 枝只显前 4", () => {
    render(<PruningTreeFig trees={[tree("T-1", [branch("V-1", "vulnerable", [node("a", 1)]), ...sixSafe])]} />);
    const fold = document.querySelector("[data-collapsed-safe]")!;
    expect(fold.textContent).toContain("+2");
    expect(fold.textContent).toContain("剪断");
    // 1 vuln + 4 safe = 5 个 source pill
    expect(document.querySelectorAll("[data-source]").length).toBe(5);
  });

  it("点击展开 → 全部枝在场、文案切「收起」；再点收起", () => {
    render(<PruningTreeFig trees={[tree("T-1", sixSafe)]} />);
    const fold = document.querySelector("[data-collapsed-safe]")!;
    fireEvent.click(fold);
    expect(document.querySelectorAll("[data-source]").length).toBe(6);
    expect(document.querySelector("[data-collapsed-safe]")!.textContent).toContain("收起");
    fireEvent.click(document.querySelector("[data-collapsed-safe]")!);
    expect(document.querySelectorAll("[data-source]").length).toBe(4);
  });

  it("hover 被折叠枝明细行 → 折叠节点联动高亮（data-hovered）", () => {
    render(<PruningTreeFig trees={[tree("T-1", sixSafe)]} />);
    const foldedRow = document.querySelector('[data-branch-row][data-branch-id="S-5"]')!;
    fireEvent.mouseEnter(foldedRow);
    expect(document.querySelector("[data-collapsed-safe]")!.hasAttribute("data-hovered")).toBe(true);
    fireEvent.mouseLeave(foldedRow);
    expect(document.querySelector("[data-collapsed-safe]")!.hasAttribute("data-hovered")).toBe(false);
  });
});

describe("图↔行双向联动 + 点枝条展开（spec §5「交互」段）", () => {
  const twoTrees = () =>
    render(
      <PruningTreeFig
        trees={[
          tree("T-1", [
            branch("B-1", "vulnerable", [node("a", 1)]),
            branch("B-2", "safe", [node("b", 2)], [san(2, true)]),
          ]),
        ]}
      />,
    );

  it("hover 图边 → 明细行 data-hovered + branch-row-hovered class（双向图→行）", () => {
    twoTrees();
    const edge = document.querySelector("g[data-branch-id='B-1']")!;
    fireEvent.mouseEnter(edge);
    const row = document.querySelector('[data-branch-row][data-branch-id="B-1"]')!;
    expect(row.hasAttribute("data-hovered")).toBe(true);
    expect(row.className).toContain("branch-row-hovered");
    fireEvent.mouseLeave(edge);
    expect(row.hasAttribute("data-hovered")).toBe(false);
  });

  it("hover 明细行 → 图边 hovered class（反向：行→图）", () => {
    twoTrees();
    const row = document.querySelector('[data-branch-row][data-branch-id="B-1"]')!;
    fireEvent.mouseEnter(row);
    const path = document.querySelector("path[data-branch='vulnerable']")!;
    expect(path.getAttribute("class")).toContain("hovered");
    fireEvent.mouseLeave(row);
    expect(path.getAttribute("class")).not.toContain("hovered");
  });

  it("联动互不干扰：hover B-1 时 B-2 两侧不动", () => {
    twoTrees();
    fireEvent.mouseEnter(document.querySelector("g[data-branch-id='B-1']")!);
    const row2 = document.querySelector('[data-branch-row][data-branch-id="B-2"]')!;
    expect(row2.hasAttribute("data-hovered")).toBe(false);
    const path2 = document.querySelector("path[data-branch='safe']")!;
    expect(path2.getAttribute("class")).not.toContain("hovered");
  });

  it("点枝条选中：明细行 data-selected + 展开首节点 code；再点取消", async () => {
    twoTrees();
    fireEvent.click(document.querySelector("g[data-branch-id='B-1']")!);
    const row = document.querySelector('[data-branch-row][data-branch-id="B-1"]')!;
    expect(row.hasAttribute("data-selected")).toBe(true);
    await waitFor(() => {
      expect(document.querySelector("[data-node-code]")!.textContent).toContain("SELECT");
    });
    fireEvent.click(document.querySelector("g[data-branch-id='B-1']")!);
    expect(
      document.querySelector('[data-branch-row][data-branch-id="B-1"]')!.hasAttribute("data-selected"),
    ).toBe(false);
  });

  it("键盘可达：source 节点 role=button + Enter toggle 选中", () => {
    twoTrees();
    const src = document.querySelector("[data-source]")!;
    expect(src.getAttribute("role")).toBe("button");
    expect(src.getAttribute("tabindex")).toBe("0");
    fireEvent.keyDown(src, { key: "Enter" });
    expect(
      document.querySelector('[data-branch-row][data-branch-id="B-1"]')!.hasAttribute("data-selected"),
    ).toBe(true);
    fireEvent.keyDown(src, { key: "Enter" });
    expect(
      document.querySelector('[data-branch-row][data-branch-id="B-1"]')!.hasAttribute("data-selected"),
    ).toBe(false);
  });

  it("自绘缩放条：aria/title 走 i18n（放大/缩小/重置缩放）", () => {
    twoTrees();
    expect(document.querySelector("[data-zoom-out]")!.getAttribute("aria-label")).toBe("缩小");
    expect(document.querySelector("[data-zoom-in]")!.getAttribute("aria-label")).toBe("放大");
    expect(document.querySelector("[data-zoom-reset]")!.getAttribute("title")).toBe("重置缩放");
  });
});

describe("tokens.css 动效与样式契约（React Flow DOM 形态）", () => {
  it("打通枝 flow 动画：仅 hovered/selected 或直接 hover 触发（无常驻）", () => {
    expect(TOKENS_CSS).toMatch(
      /\.branch-vuln\.hovered[\s\S]*?animation: flow 1\.1s linear infinite/,
    );
    expect(TOKENS_CSS).toMatch(/\.branch-vuln\.selected[\s\S]*?animation: flow/);
    // 直接 hover 触发器（React Flow 边层：g[data-branch-id] 嵌在 RF svg 内）
    expect(TOKENS_CSS).toMatch(
      /svg g\[data-branch-id\]:hover \.branch-vuln[\s\S]*?animation: flow/,
    );
  });

  it("sink 脉动 2.2s（页面唯一 ambient 动画——单焦点）", () => {
    expect(TOKENS_CSS).toMatch(/\.sink-pulse\s*{[^}]*animation: sink-pulse 2\.2s/);
  });

  it("prefers-reduced-motion 镜像：flow 触发器与 sink 脉动全关", () => {
    const reduced = TOKENS_CSS.split("@media (prefers-reduced-motion: reduce)")[1] ?? "";
    expect(reduced).toMatch(/\.branch-vuln\.hovered[\s\S]*?animation: none/);
    expect(reduced).toMatch(/svg g\[data-branch-id\]:hover \.branch-vuln[\s\S]*?animation: none/);
    expect(reduced).toMatch(/\.sink-pulse\s*{[^}]*animation: none/);
  });

  it("联动高亮 class 存在（边加粗提亮 + 行底色）", () => {
    expect(TOKENS_CSS).toMatch(/\.branch-vuln\.hovered[\s\S]*?stroke-width: 3\.6/);
    expect(TOKENS_CSS).toMatch(/\.branch-row-hovered\s*{/);
    expect(TOKENS_CSS).toMatch(/\.branch-row-selected\s*{/);
  });

  it("HTML 节点盒不透明底（线穿字修复的盒模型版：边在节点层之下被盖）", () => {
    expect(TOKENS_CSS).toMatch(/\.prune-node\s*{[^}]*background: hsl\(var\(--card\)\)/);
  });

  it("禁用 [data-tooltip] CSS 浮层（SVG 定位回退视口的旧坑，title 属性唯一 tooltip 通道）", () => {
    expect(TOKENS_CSS).not.toMatch(/\[data-tooltip\]:hover::after/);
  });
});

// —— BranchRow 明细行（组件与图实现解耦，迁移不改） ——

describe("BranchRow — 枝条明细 + 代码展开", () => {
  it("链级标签：打通 · 一路无有效防护", () => {
    render(<BranchRow branch={branch("B-1", "vulnerable", [node("a", 1)])} />);
    expect(screen.getByText("打通 · 一路无有效防护")).toBeTruthy();
  });

  it("链级标签：剪断 · 在 {cut} 被拦下（剪断点函数名进标签）", () => {
    render(<BranchRow branch={branch("B-1", "safe", [node("escHere", 5)], [san(5, true)])} />);
    expect(screen.getByText(/剪断 · 在 escHere 被拦下/)).toBeTruthy();
  });

  it("节点点击展开 code；has_code=false 降级白话", () => {
    render(<BranchRow branch={branch("B-1", "vulnerable", [node("a", 1)])} />);
    fireEvent.click(document.querySelector('[data-node-key="n0"]')!);
    expect(document.querySelector("[data-node-code]")!.textContent).toContain("SELECT");
    render(
      <BranchRow branch={branch("B-2", "vulnerable", [{ ...node("b", 2), has_code: false, code: null }])} />,
    );
    fireEvent.click(document.querySelectorAll('[data-node-key="n0"]')[1]);
    expect(document.querySelectorAll("[data-node-code]")[1].textContent).toContain("不带源码");
  });

  it("data-branch-id 锚点 + 轨道徽章（GN 轨/LLM 轨）", () => {
    render(
      <div>
        <BranchRow branch={branch("B-1", "vulnerable", [node("a", 1)], [], { track: "gitnexus" })} />
        <BranchRow branch={branch("B-2", "vulnerable", [node("b", 2)], [], { track: "llm" })} />
      </div>,
    );
    expect(document.querySelector('[data-branch-row][data-branch-id="B-1"]')).toBeTruthy();
    expect(screen.getByText("GN 轨")).toBeTruthy();
    expect(screen.getByText("LLM 轨")).toBeTruthy();
  });

  it("verdict_reason 限两行（line-clamp-2）且全文进 title", () => {
    render(
      <BranchRow
        branch={branch("B-1", "vulnerable", [node("a", 1)], [], {
          verdict_reason:
            "参数直接进入模板字符串拼接，未经任何转义处理即抵达数据库查询语句，" +
            "攻击者可注入 $where 服务端脚本；路径上未观察到防护点。",
        })}
      />,
    );
    const p = document.querySelector("[data-branch-verdict-reason]")!;
    expect(p.className).toContain("line-clamp-2");
    expect(p.getAttribute("title")).toContain("未经任何转义处理");
  });

  it("选中态自动展开首节点 code（点枝条联动）", async () => {
    const { rerender } = render(
      <BranchRow branch={branch("B-1", "vulnerable", [node("a", 1)])} selected={false} />,
    );
    expect(document.querySelector("[data-node-code]")).toBeNull();
    rerender(
      <BranchRow branch={branch("B-1", "vulnerable", [node("a", 1)])} selected={true} />,
    );
    await waitFor(() => {
      expect(document.querySelector("[data-node-code]")).toBeTruthy();
    });
  });
});
