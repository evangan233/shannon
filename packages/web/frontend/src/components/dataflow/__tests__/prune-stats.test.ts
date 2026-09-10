// prune/stats.ts 纯函数测试（T2，TDD 先行）——逻辑从旧 PruningTreeFig.tsx 原样搬，
// 测试锁定语义：剪断点定位（line+file 匹配）、公共函数统计、跨树 source 索引。
import { describe, expect, it } from "vitest";
import type { DataflowBranch, DataflowTree } from "@/api/types";
import { buildCrossTreeSourceTip, buildPubFuncStats, cutStepOf, sharedFuncNames } from "../prune/stats";

function branch(partial: Partial<DataflowBranch>): DataflowBranch {
  return {
    branch_id: "B-1",
    track: "gitnexus",
    verdict: "safe",
    source: { label: "req.body.q", type: "body", entry: "GET /x" },
    nodes: [],
    sanitizers: [],
    ...partial,
  };
}

describe("cutStepOf（剪断点定位）", () => {
  it("非 safe 枝 → Infinity（不截断，全链到 sink）", () => {
    expect(cutStepOf(branch({ verdict: "vulnerable" }))).toBe(Infinity);
    expect(cutStepOf(branch({ verdict: "unknown" }))).toBe(Infinity);
  });

  it("safe 枝 effective sanitizer 按 line 定位中途节点 → 1-based cutStep", () => {
    const b = branch({
      nodes: [
        { func: "a", note: null, file: "f.js", line: 10, intermediate_vars: [], has_code: false },
        { func: "b", note: null, file: "f.js", line: 20, intermediate_vars: [], has_code: false },
        { func: "c", note: null, file: "f.js", line: 30, intermediate_vars: [], has_code: false },
      ],
      sanitizers: [{ name: "esc", effective: true, line: 20, file: "f.js" }],
    });
    // line=20 命中第 2 个节点（idx 1）→ cutStep=2
    expect(cutStepOf(b)).toBe(2);
  });

  it("line 相同但 file 不同 → 不误定位（真实数据不同文件 line 巧合相同）", () => {
    const b = branch({
      nodes: [
        { func: "a", note: null, file: "other.js", line: 20, intermediate_vars: [], has_code: false },
        { func: "b", note: null, file: "f.js", line: 30, intermediate_vars: [], has_code: false },
      ],
      sanitizers: [{ name: "esc", effective: true, line: 20, file: "f.js" }],
    });
    expect(cutStepOf(b)).toBe(2); // 无匹配 → nodes.length
  });

  it("sanitizer 无 file 信息（file==null）→ 仅按 line 匹配（宽容）", () => {
    const b = branch({
      nodes: [
        { func: "a", note: null, file: "x.js", line: 10, intermediate_vars: [], has_code: false },
        { func: "b", note: null, file: "y.js", line: 20, intermediate_vars: [], has_code: false },
      ],
      sanitizers: [{ name: "esc", effective: true, line: 20, file: null }],
    });
    expect(cutStepOf(b)).toBe(2);
  });

  it("safe 枝无 effective sanitizer / sanitizer.line 为 null → nodes.length 兜底", () => {
    const nodes = [
      { func: "a", note: null, file: "f.js", line: 10, intermediate_vars: [], has_code: false },
    ];
    expect(cutStepOf(branch({ nodes, sanitizers: [] }))).toBe(1);
    expect(
      cutStepOf(branch({ nodes, sanitizers: [{ name: "esc", effective: true, line: null }] })),
    ).toBe(1);
    // ineffective sanitizer 不算剪断点
    expect(
      cutStepOf(branch({ nodes, sanitizers: [{ name: "x", effective: false, line: 10 }] })),
    ).toBe(1);
  });
});

describe("sharedFuncNames / buildPubFuncStats（公共函数统计）", () => {
  const b1 = branch({
    branch_id: "B-1",
    nodes: [
      { func: "shared", note: null, file: "f.js", line: 1, intermediate_vars: [], has_code: false },
      { func: "shared", note: null, file: "f.js", line: 2, intermediate_vars: [], has_code: false }, // 同枝重复只计一次
      { func: "only1", note: null, file: "f.js", line: 3, intermediate_vars: [], has_code: false },
    ],
  });
  const b2 = branch({
    branch_id: "B-2",
    verdict: "safe",
    nodes: [
      { func: "shared", note: null, file: "g.js", line: 9, intermediate_vars: [], has_code: false },
    ],
    sanitizers: [{ name: "esc", effective: true, line: 9, file: "g.js" }],
  });
  const b3 = branch({
    branch_id: "B-3",
    verdict: "vulnerable",
    nodes: [
      { func: "shared", note: null, file: "h.js", line: 5, intermediate_vars: [], has_code: false },
    ],
  });

  it("sharedFuncNames：跨枝重复的 func 才进集合", () => {
    expect(sharedFuncNames([b1, b2, b3])).toEqual(new Set(["shared"]));
  });

  it("buildPubFuncStats：同枝同 func 去重、safe 枝 branch_id 进 cutBranches", () => {
    const stats = buildPubFuncStats([b1, b2, b3]);
    // b1（safe，工厂默认）与 b2（safe）都剪断；b3 vulnerable 不进
    expect(stats.get("shared")).toEqual({ count: 3, cutBranches: ["B-1", "B-2"] });
    expect(stats.get("only1")).toEqual({ count: 1, cutBranches: ["B-1"] });
  });

  it("func 为 null 的节点不参与统计", () => {
    const b = branch({
      nodes: [
        { func: null, note: null, file: "f.js", line: 1, intermediate_vars: [], has_code: false },
      ],
    });
    expect(buildPubFuncStats([b]).size).toBe(0);
  });
});

describe("buildCrossTreeSourceTip（跨树 source 索引）", () => {
  const tree = (id: string, sinkLabel: string, srcLabel: string): DataflowTree => ({
    tree_id: id,
    vuln_class: "injection",
    sink: { label: sinkLabel, file: "s.js", line: 1 },
    findings: [],
    branches: [branch({ source: { label: srcLabel, type: "body", entry: "GET /x" } })],
  });

  it("同入口出现在两树 → 提示列出其它树的 sink 名（排除当前树）", () => {
    const tip = buildCrossTreeSourceTip([
      tree("T-1", "eval", "req.body.q"),
      tree("T-2", "mongo.$where", "req.body.q"),
    ]);
    expect(tip({ label: "req.body.q", type: "body", entry: "GET /x" }, "T-1")).toBe("mongo.$where");
    expect(tip({ label: "req.body.q", type: "body", entry: "GET /x" }, "T-2")).toBe("eval");
  });

  it("仅出现在一棵树 → null（不算跨树）", () => {
    const tip = buildCrossTreeSourceTip([tree("T-1", "eval", "req.body.a"), tree("T-2", "x", "req.body.b")]);
    expect(tip({ label: "req.body.a", type: "body", entry: null }, "T-1")).toBeNull();
  });

  it("label+entry 皆空 → 不索引，返回 null", () => {
    const tip = buildCrossTreeSourceTip([
      tree("T-1", "eval", ""),
      tree("T-2", "x", ""),
    ]);
    expect(tip({ label: "", type: null, entry: "" }, "T-1")).toBeNull();
  });

  it("entry 不同 → 不同入口（label 相同不合并）", () => {
    const t1: DataflowTree = {
      ...tree("T-1", "eval", "req.body.q"),
      branches: [branch({ source: { label: "req.body.q", type: "body", entry: "GET /a" } })],
    };
    const t2: DataflowTree = {
      ...tree("T-2", "mongo", "req.body.q"),
      branches: [branch({ source: { label: "req.body.q", type: "body", entry: "GET /b" } })],
    };
    const tip = buildCrossTreeSourceTip([t1, t2]);
    expect(tip({ label: "req.body.q", type: "body", entry: "GET /a" }, "T-1")).toBeNull();
  });
});
