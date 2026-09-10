// prune/layout.ts 纯函数测试（T3-T8，TDD 先行）。
// 核心：buildPruneLayout(tree, opts) → PruneLayout——dagre LR 出 y、x 列等距化（spec §5
// 「断在第几列横向可比」）、节点盒固定尺寸（渲染高度==布局高度，重叠物理消灭）。
// T4 的「任意两节点矩形不相交」不变量是本次迁移要根治问题的回归锁。
import { describe, expect, it } from "vitest";
import type { DataflowBranch, DataflowNode, DataflowSanitizer, DataflowTree } from "@/api/types";
import { buildPruneLayout } from "../prune/layout";
import { COL_X, FOLD_THRESHOLD, NODESEP, PAD_L, PAD_T } from "../prune/types";

// —— fixture helpers ——

function node(func: string, line: number, file = "app.js"): DataflowNode {
  return { func, note: null, file, line, intermediate_vars: [], has_code: false };
}
function san(line: number, effective: boolean, file = "app.js"): DataflowSanitizer {
  return { name: "esc", effective, line, file };
}
function branch(
  id: string,
  verdict: DataflowBranch["verdict"],
  nodes: DataflowNode[],
  sanitizers: DataflowSanitizer[] = [],
  sourceLabel = "req.body.q",
): DataflowBranch {
  return {
    branch_id: id,
    track: "gitnexus",
    verdict,
    source: { label: sourceLabel, type: "body", entry: "GET /x" },
    nodes,
    sanitizers,
  };
}
function tree(id: string, branches: DataflowBranch[], sinkLabel = "eval", findings: { id: string }[] = []): DataflowTree {
  return {
    tree_id: id,
    vuln_class: "injection",
    sink: { label: sinkLabel, file: "s.js", line: 1 },
    findings,
    branches,
  };
}

/** 矩形相交检测（0.5px 容差——浮点换算余量）。 */
function rectsOverlap(
  a: { x: number; y: number; w: number; h: number },
  b: { x: number; y: number; w: number; h: number },
): boolean {
  const eps = 0.5;
  return a.x < b.x + b.w - eps && b.x < a.x + a.w - eps && a.y < b.y + b.h - eps && b.y < a.y + a.h - eps;
}

/** 全节点两两不相交断言（重叠回归锁）。 */
function expectNoOverlap(treeIn: DataflowTree, opts?: Parameters<typeof buildPruneLayout>[1]) {
  const layout = buildPruneLayout(treeIn, opts);
  const nodes = layout.nodes;
  for (let i = 0; i < nodes.length; i++) {
    for (let j = i + 1; j < nodes.length; j++) {
      const a = nodes[i];
      const b = nodes[j];
      expect(
        rectsOverlap(a, b),
        `节点相交: ${a.id}(${a.kind}@${a.x},${a.y},${a.w}×${a.h}) × ${b.id}(${b.kind}@${b.x},${b.y},${b.w}×${b.h})`,
      ).toBe(false);
    }
  }
  return layout;
}

describe("T3 基础布局与列对齐", () => {
  const t = tree("T-1", [
    branch("B-1", "vulnerable", [node("handler", 10), node("dao.find", 20)]),
  ]);

  it("单枝链：source(step0)/step 节点/sink(maxStep+1) 齐全", () => {
    const layout = buildPruneLayout(t);
    const kinds = layout.nodes.map((n) => n.kind);
    expect(kinds).toContain("source");
    expect(kinds).toContain("step");
    expect(kinds).toContain("sink");
    const sink = layout.nodes.find((n) => n.kind === "sink")!;
    expect(sink.step).toBe(3); // maxNodes(2)+1
    // 链边：source→n1→n2→sink 共 3 条
    const chainEdges = layout.edges.filter((e) => e.kind === "branch");
    expect(chainEdges).toHaveLength(3);
    expect(chainEdges.every((e) => e.branchId === "B-1")).toBe(true);
  });

  it("列等距化：x = PAD_L + step×COL_X，同 step 同 x，随 step 严格递增", () => {
    const layout = buildPruneLayout(t);
    for (const n of layout.nodes) {
      expect(n.x).toBe(PAD_L + n.step * COL_X);
    }
    const xs = [...new Set(layout.nodes.map((n) => n.x))].sort((a, b) => a - b);
    for (let i = 1; i < xs.length; i++) expect(xs[i]).toBeGreaterThan(xs[i - 1]);
  });

  it("多枝同列严格对齐（跨枝 step=1 节点 x 全等）", () => {
    const t2 = tree("T-2", [
      branch("B-1", "vulnerable", [node("a", 1), node("b", 2)]),
      branch("B-2", "vulnerable", [node("c", 3), node("d", 4), node("e", 5)]),
    ]);
    const layout = buildPruneLayout(t2);
    const step1 = layout.nodes.filter((n) => n.kind === "step" && n.step === 1);
    expect(step1).toHaveLength(2);
    expect(step1[0].x).toBe(step1[1].x);
  });

  it("sink 纵向居中于枝行范围", () => {
    const t2 = tree("T-2", [
      branch("B-1", "vulnerable", [node("a", 1)]),
      branch("B-2", "vulnerable", [node("c", 3)]),
      branch("B-3", "vulnerable", [node("d", 5)]),
    ]);
    const layout = buildPruneLayout(t2);
    const sink = layout.nodes.find((n) => n.kind === "sink")!;
    const sources = layout.nodes.filter((n) => n.kind === "source");
    const minY = Math.min(...sources.map((n) => n.y));
    const maxY = Math.max(...sources.map((n) => n.y + n.h));
    expect(sink.y + sink.h / 2).toBeGreaterThanOrEqual(minY - 1);
    expect(sink.y + sink.h / 2).toBeLessThanOrEqual(maxY + 1);
  });

  it("节点/边 id 全局唯一（RF key 安全）", () => {
    const t2 = tree("T-2", [
      branch("B-1", "vulnerable", [node("a", 1)]),
      branch("B-2", "safe", [node("a", 2)], [san(2, true)]), // 同名函数 + 剪断
    ]);
    const layout = buildPruneLayout(t2);
    const nodeIds = layout.nodes.map((n) => n.id);
    expect(new Set(nodeIds).size).toBe(nodeIds.length);
    const edgeIds = layout.edges.map((e) => e.id);
    expect(new Set(edgeIds).size).toBe(edgeIds.length);
  });

  it("hovered/selected 注入：命中枝全链标 true，他枝 false", () => {
    const t2 = tree("T-2", [
      branch("B-1", "vulnerable", [node("a", 1)]),
      branch("B-2", "vulnerable", [node("c", 3)]),
    ]);
    const layout = buildPruneLayout(t2, { hoveredBranch: "B-1", selectedBranch: "B-2" });
    for (const n of layout.nodes) {
      if (n.kind !== "source" && n.kind !== "step") continue;
      const d = n.data as { hovered: boolean; selected: boolean };
      expect(d.hovered).toBe(n.data.kind === "source" ? (n.data as { branchId: string | null }).branchId === "B-1" : (n.data as { branchId: string | null }).branchId === "B-1");
      expect(d.selected).toBe((n.data as { branchId: string | null }).branchId === "B-2");
    }
    const e1 = layout.edges.find((e) => e.branchId === "B-1")!;
    expect(e1.hovered).toBe(true);
    expect(e1.selected).toBe(false);
    const e2 = layout.edges.find((e) => e.branchId === "B-2")!;
    expect(e2.hovered).toBe(false);
    expect(e2.selected).toBe(true);
  });
});

describe("T4 重叠不变量回归锁（本次迁移要根治的问题）", () => {
  // 真实数据形态：LLM 自然语言长 label（NodeGoat 实测 func 最长 63 字符、source 79、sink 53）
  const longFunc = "AllocationsDAO.getByUserIdAndThreshold 直接把 threshold 模板字符串拼接进 $where 查询";
  const longSource =
    "AllocationsHandler.displayAllocations 读取 req.body.threshold 参数（用户可控输入经路由直达 DAO 查询）";
  const longSink = "allocationsCol.find({ $where }) MongoDB 服务端 JavaScript 执行（NoSQL 注入危险点）";

  const bigTree = tree(
    "T-BIG",
    [
      branch("V-1", "vulnerable", [node(longFunc, 10), node("route.validate", 20), node("mongo.exec", 30)], [], longSource),
      branch("V-2", "vulnerable", [node("session.parse", 40), node(longFunc, 50)], [], longSource),
      branch("V-3", "unknown", [node("upload.handler", 60)], [], longSource),
      branch("S-1", "safe", [node("sanitize.escape", 70), node("dao.safe", 80)], [san(80, true)]),
      branch("S-2", "safe", [node("sanitize.escape", 71), node("dao.safe", 81)], [san(81, true)]),
      branch("S-3", "safe", [node(longFunc, 90)], [san(90, true)]),
      branch("S-4", "safe", [], []), // 0 节点枝（source 直连 sink 语义 → safe 全剪）
      branch("S-5", "safe", [node("x.y".repeat(20), 95)], [san(95, true)]), // 半角超长
    ],
    longSink,
  );

  it("长标签多枝树：任意两节点矩形不相交（折叠态）", () => {
    expectNoOverlap(bigTree);
  });

  it("长标签多枝树：任意两节点矩形不相交（展开态）", () => {
    expectNoOverlap(bigTree, { foldExpanded: true });
  });

  it("同列（step 列）垂直净距 ≥ NODESEP−1", () => {
    const layout = buildPruneLayout(bigTree, { foldExpanded: true });
    const byStep = new Map<number, typeof layout.nodes>();
    for (const n of layout.nodes) {
      if (n.step < 0) continue; // fold 后置不算
      const arr = byStep.get(n.step) ?? [];
      arr.push(n);
      byStep.set(n.step, arr);
    }
    for (const [step, nodes] of byStep) {
      const sorted = [...nodes].sort((a, b) => a.y - b.y);
      for (let i = 1; i < sorted.length; i++) {
        const gap = sorted[i].y - (sorted[i - 1].y + sorted[i - 1].h);
        expect(gap, `step=${step} 列内净距 ${gap} < ${NODESEP - 1}`).toBeGreaterThanOrEqual(NODESEP - 1);
      }
    }
  });

  it("布局包围盒包含所有节点（width/height 语义）", () => {
    const layout = buildPruneLayout(bigTree, { foldExpanded: true });
    for (const n of layout.nodes) {
      expect(n.x + n.w).toBeLessThanOrEqual(layout.width + 0.5);
      expect(n.y + n.h).toBeLessThanOrEqual(layout.height + 0.5);
      expect(n.x).toBeGreaterThanOrEqual(0);
      expect(n.y).toBeGreaterThanOrEqual(PAD_T - 0.5);
    }
  });

  it("首行不低于 PAD_T（上边距语义）", () => {
    const layout = buildPruneLayout(bigTree);
    const minY = Math.min(...layout.nodes.map((n) => n.y));
    expect(minY).toBeGreaterThanOrEqual(PAD_T - 0.5);
  });
});

describe("T5 剪断截断", () => {
  it("中途剪断：cutStep 后无节点/无边/无 sink 边，cut 节点 isCut", () => {
    const t = tree("T-1", [
      branch("B-1", "safe", [node("a", 10), node("b", 20), node("c", 30)], [san(20, true)]),
    ]);
    const layout = buildPruneLayout(t);
    // cutStep=2 → step3 节点不出现
    expect(layout.nodes.filter((n) => n.kind === "step" && n.step === 3)).toHaveLength(0);
    // cut 节点（step2）isCut=true
    const cutNode = layout.nodes.find((n) => n.kind === "step" && n.step === 2)!;
    expect((cutNode.data as { isCut: boolean }).isCut).toBe(true);
    // 非 cut 节点 isCut=false
    const step1 = layout.nodes.find((n) => n.kind === "step" && n.step === 1)!;
    expect((step1.data as { isCut: boolean }).isCut).toBe(false);
    // 链边止于 cut 节点（source→n1→n2），无 →sink 边
    const chainEdges = layout.edges.filter((e) => e.kind === "branch");
    expect(chainEdges).toHaveLength(2);
    expect(chainEdges.some((e) => e.target.includes("sink") || layout.nodes.find((n) => n.id === e.target)?.kind === "sink")).toBe(false);
  });

  it("sanitizer 无 line 匹配 → 全链画出但无 sink 边（画到枝尾剪断）", () => {
    const t = tree("T-1", [
      branch("B-1", "safe", [node("a", 10), node("b", 20)], [san(999, true)]),
    ]);
    const layout = buildPruneLayout(t);
    expect(layout.nodes.filter((n) => n.kind === "step")).toHaveLength(2);
    const toSink = layout.edges.filter(
      (e) => layout.nodes.find((n) => n.id === e.target)?.kind === "sink",
    );
    expect(toSink).toHaveLength(0);
  });

  it("打通枝（vulnerable/unknown）→sink 边存在", () => {
    const t = tree("T-1", [
      branch("B-1", "vulnerable", [node("a", 10)]),
      branch("B-2", "unknown", [node("b", 20)]),
    ]);
    const layout = buildPruneLayout(t);
    const toSink = layout.edges.filter(
      (e) => layout.nodes.find((n) => n.id === e.target)?.kind === "sink",
    );
    expect(toSink).toHaveLength(2);
  });

  it("0 节点打通枝：source 直连 sink", () => {
    const t = tree("T-1", [branch("B-1", "vulnerable", [])]);
    const layout = buildPruneLayout(t);
    const source = layout.nodes.find((n) => n.kind === "source")!;
    const direct = layout.edges.find(
      (e) => e.source === source.id && layout.nodes.find((n) => n.id === e.target)?.kind === "sink",
    );
    expect(direct).toBeTruthy();
  });
});

describe("T6 折叠", () => {
  const safeBranches = Array.from({ length: 6 }, (_, i) =>
    branch(`S-${i}`, "safe", [node(`f${i}`, 10 + i)], [san(10 + i, true)]),
  );

  it("safe 枝 > FOLD_THRESHOLD：默认折叠前 4 + FoldNode + foldedIds", () => {
    const t = tree("T-1", [branch("V-1", "vulnerable", [node("a", 1)]), ...safeBranches]);
    const layout = buildPruneLayout(t);
    // 图上 safe 枝 source 只有 4 个（另 1 个 vuln）
    expect(layout.nodes.filter((n) => n.kind === "source").length).toBe(5);
    const fold = layout.nodes.find((n) => n.kind === "fold");
    expect(fold).toBeTruthy();
    expect((fold!.data as { hiddenCount: number }).hiddenCount).toBe(2);
    expect(layout.foldedIds).toEqual(["S-4", "S-5"]);
    expect(layout.hasFold).toBe(true);
    // fold 节点位于图下方（y 大于所有 source）
    const maxY = Math.max(...layout.nodes.filter((n) => n.kind !== "fold").map((n) => n.y));
    expect(fold!.y).toBeGreaterThan(maxY);
  });

  it("foldExpanded=true：全部枝在场、折叠行仍在（「收起」入口）", () => {
    const t = tree("T-1", safeBranches);
    const layout = buildPruneLayout(t, { foldExpanded: true });
    expect(layout.nodes.filter((n) => n.kind === "source")).toHaveLength(6);
    const fold = layout.nodes.find((n) => n.kind === "fold");
    expect(fold).toBeTruthy(); // 展开态折叠行保留（可再点收起）
    expect((fold!.data as { expanded: boolean }).expanded).toBe(true);
    expect(layout.hasFold).toBe(true);
    expect(layout.foldedIds).toEqual([]); // 展开态无被折叠枝
  });

  it("恰好 FOLD_THRESHOLD 条 safe → 不折叠", () => {
    const t = tree("T-1", safeBranches.slice(0, FOLD_THRESHOLD));
    const layout = buildPruneLayout(t);
    expect(layout.hasFold).toBe(false);
    expect(layout.nodes.find((n) => n.kind === "fold")).toBeUndefined();
  });
});

describe("T7 同名函数弧", () => {
  it("跨枝同名 func 链式配对成 sameline 边", () => {
    const t = tree("T-1", [
      branch("B-1", "vulnerable", [node("shared", 1), node("x", 2)]),
      branch("B-2", "vulnerable", [node("shared", 3)]),
      branch("B-3", "vulnerable", [node("shared", 5)]),
    ]);
    const layout = buildPruneLayout(t);
    const arcs = layout.edges.filter((e) => e.kind === "sameline");
    expect(arcs).toHaveLength(2); // 链式：n1↔n2、n2↔n3
    // 弧端点是节点 id
    for (const a of arcs) {
      expect(layout.nodes.find((n) => n.id === a.source)).toBeTruthy();
      expect(layout.nodes.find((n) => n.id === a.target)).toBeTruthy();
    }
  });

  it("被剪断吞掉的节点（step > lastStep）不参与弧", () => {
    const t = tree("T-1", [
      // B-1 剪断在 step1：shared(节点1) 之后吞掉 → 但 shared 在 step1 可见
      branch("B-1", "safe", [node("shared", 1), node("hidden", 2)], [san(1, true)]),
      // B-2 剪断在 step1 之前？不：cut=1 → shared(step1) 恰是剪断点，可见
      branch("B-2", "safe", [node("shared", 3), node("hidden2", 4)], [san(3, true)]),
      // B-3 打通：hidden 在 B-1 被吞，但 B-3 自己可见 → hidden 与 hidden2 同名但 B-2 被吞 → 无弧
      branch("B-3", "vulnerable", [node("hidden", 5)]),
    ]);
    const layout = buildPruneLayout(t);
    const arcs = layout.edges.filter((e) => e.kind === "sameline");
    // shared 两处可见 → 1 弧；hidden 在 B-1 被吞（B-3 可见 1 处）+ hidden2 在 B-2 被吞 → 无弧
    expect(arcs).toHaveLength(1);
  });

  it("sameline 不参与布局（结构性断言：弧的 source/target 是可见 step 节点，不新增节点）", () => {
    const t = tree("T-1", [
      branch("B-1", "vulnerable", [node("shared", 1)]),
      branch("B-2", "vulnerable", [node("shared", 3)]),
    ]);
    const layout = buildPruneLayout(t);
    const arcs = layout.edges.filter((e) => e.kind === "sameline");
    expect(arcs).toHaveLength(1);
    // 弧端点都是 step 节点（不产生 ghost 节点、不动 source/sink）
    for (const a of arcs) {
      expect(layout.nodes.find((n) => n.id === a.source)?.kind).toBe("step");
      expect(layout.nodes.find((n) => n.id === a.target)?.kind).toBe("step");
    }
  });
});

describe("T8 sink/盾/公共函数语义", () => {
  it("hasVuln 口径：vulnCount>0 或 findings 非空", () => {
    const vulnTree = tree("T-1", [branch("B-1", "vulnerable", [node("a", 1)])]);
    expect((buildPruneLayout(vulnTree).nodes.find((n) => n.kind === "sink")!.data as { hasVuln: boolean }).hasVuln).toBe(true);

    const findingsTree = tree("T-2", [branch("B-1", "safe", [node("a", 1)], [san(1, true)])], "eval", [{ id: "F-1" }]);
    expect((buildPruneLayout(findingsTree).nodes.find((n) => n.kind === "sink")!.data as { hasVuln: boolean }).hasVuln).toBe(true);

    const safeTree = tree("T-3", [branch("B-1", "safe", [node("a", 1)], [san(1, true)])]);
    expect((buildPruneLayout(safeTree).nodes.find((n) => n.kind === "sink")!.data as { hasVuln: boolean }).hasVuln).toBe(false);
  });

  it("盾判定：effective=true → green；effective=false → yellow；无匹配 → none", () => {
    const t = tree("T-1", [
      branch("B-1", "vulnerable", [
        node("bypassed", 10),
        node("effective", 20),
        node("plain", 30),
      ], [san(10, false), san(20, true)]),
    ]);
    const layout = buildPruneLayout(t);
    const shieldOf = (step: number) =>
      (layout.nodes.find((n) => n.kind === "step" && n.step === step)!.data as { shield: string }).shield;
    expect(shieldOf(1)).toBe("yellow"); // 绕过（线继续红）
    expect(shieldOf(2)).toBe("green"); // 有效
    expect(shieldOf(3)).toBe("none");
  });

  it("公共函数：func 经 >1 可见枝 → pub 统计；折叠吞掉的枝不计数", () => {
    const branches = [
      branch("V-1", "vulnerable", [node("shared", 1)]),
      branch("S-1", "safe", [node("shared", 2)], [san(2, true)]),
      ...Array.from({ length: 5 }, (_, i) =>
        branch(`S-x${i}`, "safe", [node(`only${i}`, 3 + i)], [san(3 + i, true)]),
      ),
    ];
    const folded = buildPruneLayout(tree("T-1", branches)); // S-1 在前 4 safe 内 → 可见
    const pubFolded = (folded.nodes.find((n) => n.kind === "step" && (n.data as { fullLabel: string }).fullLabel.startsWith("shared"))!.data as { pub: { count: number } | null }).pub;
    expect(pubFolded).toEqual({ count: 2, cutBranches: ["S-1"] });

    // count=1 的 func 不标（⟳ 1 枝经过无语义，不占高度不渲染）
    const onlyOne = (folded.nodes.find((n) => n.kind === "step" && (n.data as { fullLabel: string }).fullLabel.startsWith("only0"))!.data as { pub: { count: number } | null }).pub;
    expect(onlyOne).toBeNull();
  });

  it("source data：meta 拼接 type · entry；storage 枝 isStorage", () => {
    const t = tree("T-1", [
      { ...branch("B-1", "vulnerable", [node("a", 1)]), source: { label: "db.row.x", type: "storage", entry: null } },
      branch("B-2", "vulnerable", [node("b", 2)]),
    ]);
    const layout = buildPruneLayout(t);
    const sources = layout.nodes.filter((n) => n.kind === "source");
    const storage = sources.find((n) => (n.data as { label: string }).label === "db.row.x")!.data as {
      isStorage: boolean;
      metaText: string | null;
    };
    expect(storage.isStorage).toBe(true);
    expect(storage.metaText).toBeNull(); // storage 枝 entry 通常为空，meta 不出
    const normal = sources.find((n) => (n.data as { label: string }).label === "req.body.q")!.data as {
      isStorage: boolean;
      metaText: string | null;
    };
    expect(normal.isStorage).toBe(false);
    expect(normal.metaText).toBe("body · GET /x");
  });
});
