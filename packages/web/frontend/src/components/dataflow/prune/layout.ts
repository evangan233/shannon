// 剪枝树布局纯函数（React Flow 迁移核心，plan 2026-09-10 D1/D2）：
// - dagre rankdir=LR 只出 y（同列避让 + crossing minimization），x 列等距化
//   x = PAD_L + step×COL_X——严格保 spec §5「断在第几列横向可比」；
// - 节点盒固定尺寸（宽 NODE_W，高由 wrapLabel 行数估算）→ 渲染高度==布局高度
//   （FlowCanvas 把 w/h 写进节点 style），「盒两两不相交」不变量即真实渲染回归锁；
// - sink/fold 不进 dagre（后置定位：sink=列等距+枝行纵向居中，fold=图下方）；
// - i18n 文案不进本层：data 携结构化字段（note/crossTreeSinks/pub…），组件内拼。
import dagre from "@dagrejs/dagre";
import type { DataflowBranch, DataflowTree } from "@/api/types";
import { buildPubFuncStats, buildCrossTreeSourceTip, cutStepOf, sharedFuncNames } from "./stats";
import { estimateTextWidthPx, wrapLabel } from "./text";
import {
  COL_X,
  FOLD_THRESHOLD,
  MAX_LINES,
  NODESEP,
  NODE_W,
  PAD_B,
  PAD_L,
  PAD_R,
  PAD_T,
} from "./types";
import type {
  PruneLayout,
  PruneLayoutEdge,
  PruneLayoutNode,
  PruneLayoutOpts,
  SourceNodeData,
  StepNodeData,
  SinkNodeData,
} from "./types";

// —— 尺寸估算常量（HTML 盒排版：fontSize 10px / 行高 13px，与 text.ts 估宽口径一致） ——

const LINE_H = 13;
const STEP_BASE_H = 44; // pad-top 8 + 圆点 22 + gap 6 + pad-bottom 8
const PUB_H = 15;
const SINK_BASE_H = 66; // pad 12 + 靶心 36 + gap 10 + pad 8
const FOLD_H = 28;
const SOURCE_PAD = 10;

function clamp(min: number, max: number, v: number): number {
  return Math.min(max, Math.max(min, v));
}

/** 节点 id（branch_id 空用枝序号兜底，全树唯一）。 */
function nodeId(treeId: string, branchKey: string, step: number): string {
  return `${treeId}:${branchKey}:${step}`;
}

export function buildPruneLayout(tree: DataflowTree, opts: PruneLayoutOpts = {}): PruneLayout {
  const treeId = tree.tree_id;
  const hovered = opts.hoveredBranch ?? null;
  const selected = opts.selectedBranch ?? null;
  const crossTreeTip = opts.crossTreeTip ?? buildCrossTreeSourceTip([tree]);

  // 1. 分枝与折叠（复刻旧 TreeCard 逻辑：vuln/unknown 在前，safe >阈值 折叠；折叠行在
  //    展开态仍渲染（文案切「收起」可再收），foldedIds 只在实际折叠时有值）
  const vulnBranches = tree.branches.filter(
    (b) => b.verdict === "vulnerable" || b.verdict === "unknown",
  );
  const safeBranches = tree.branches.filter((b) => b.verdict === "safe");
  const hasFold = safeBranches.length > FOLD_THRESHOLD; // 折叠行存在（含展开态）
  const folding = hasFold && !opts.foldExpanded; // 当前实际折叠中
  const shownSafe = folding ? safeBranches.slice(0, FOLD_THRESHOLD) : safeBranches;
  const visible = [...vulnBranches, ...shownSafe];
  const foldedIds = folding
    ? safeBranches.slice(FOLD_THRESHOLD).map((b) => b.branch_id).filter((x): x is string => !!x)
    : [];

  // 2. 每枝剪断点与可见步数
  const reachesSinkOf = (b: DataflowBranch) => b.verdict !== "safe";
  const lastStepOf = (b: DataflowBranch) => Math.min(cutStepOf(b), b.nodes.length);

  // 公共函数统计（可见枝，旧口径）
  const pubFuncStats = buildPubFuncStats(visible);
  const shared = sharedFuncNames(visible);

  // 3. 节点构造（source + step；data/尺寸/id）
  const nodes: PruneLayoutNode[] = [];
  const dagreEdges: { from: string; to: string }[] = [];
  // branchKey（branch_id 兜底序号）
  const branchKeyOf = new Map<DataflowBranch, string>();
  visible.forEach((b, i) => branchKeyOf.set(b, b.branch_id ?? `i${i}`));

  for (const b of visible) {
    const branchKey = branchKeyOf.get(b)!;
    const reachesSink = reachesSinkOf(b);
    const lastStep = lastStepOf(b);
    const isHl = b.branch_id != null;
    const hoveredThis = isHl && b.branch_id === hovered;
    const selectedThis = isHl && b.branch_id === selected;

    // —— source 节点（step 0）——
    const src = b.source;
    const label = src.label ?? "source";
    const isStorage = src.type === "storage";
    const metaText = [isStorage ? null : src.type, src.entry].filter(Boolean).join(" · ") || null;
    const hasSub = !!metaText || isStorage;
    const pillBudget = NODE_W - 16;
    const labelLines = wrapLabel(label, pillBudget, 2);
    const maxLabelW = Math.max(...labelLines.map((l) => estimateTextWidthPx(l, 10)));
    const subW = isStorage ? 80 : metaText ? estimateTextWidthPx(metaText, 10) : 0;
    const srcW = clamp(64, NODE_W, Math.max(56, maxLabelW + 14, hasSub ? subW + 14 : 0));
    const srcH = SOURCE_PAD * 2 + labelLines.length * LINE_H + (hasSub ? 12 : 0);
    const srcData: SourceNodeData = {
      kind: "source",
      branchId: b.branch_id,
      verdict: b.verdict,
      sinkLabel: tree.sink.label ?? "sink",
      label,
      metaText,
      isStorage,
      note: src.note ?? null,
      crossTreeSinks: crossTreeTip(src, treeId),
      hovered: hoveredThis,
      selected: selectedThis,
    };
    const srcId = nodeId(treeId, branchKey, 0);
    nodes.push({ id: srcId, kind: "source", step: 0, x: 0, y: 0, w: srcW, h: srcH, data: srcData });

    // —— step 节点（1..lastStep；剪断点之后不生成——剪断点后传播信息由 BranchRow 保留）——
    let prevId = srcId;
    for (let step = 1; step <= lastStep; step++) {
      const dn = b.nodes[step - 1];
      const fullLabel = dn.line != null ? `${dn.func ?? "?"}:${dn.line}` : (dn.func ?? "?");
      const lines = wrapLabel(fullLabel, NODE_W - 20, MAX_LINES);
      // 盾判定（旧 BranchPath 口径：按 line 匹配任意 sanitizer，effective true=green/false=yellow）
      const san = b.sanitizers.find((s) => s.line != null && dn.line === s.line);
      const shield: StepNodeData["shield"] = !san
        ? "none"
        : san.effective === true
          ? "green"
          : san.effective === false
            ? "yellow"
            : "none";
      // 公共函数下标仅 count>1（spec §5：⟳ N 枝经过，N≥2 才有语义；count=1 不占高度不渲染）
      const stat = dn.func ? pubFuncStats.get(dn.func) : undefined;
      const pub = stat && stat.count > 1 ? stat : null;
      const stepH = STEP_BASE_H + lines.length * LINE_H + (pub ? PUB_H : 0);
      const stepData: StepNodeData = {
        kind: "step",
        branchId: b.branch_id,
        step,
        fullLabel,
        lines,
        node: dn,
        isVuln: reachesSink,
        isCut: !reachesSink && step === lastStep && cutStepOf(b) === step,
        shield,
        pub,
        hovered: hoveredThis,
        selected: selectedThis,
      };
      const id = nodeId(treeId, branchKey, step);
      nodes.push({ id, kind: "step", step, x: 0, y: 0, w: NODE_W, h: stepH, data: stepData });
      dagreEdges.push({ from: prevId, to: id });
      prevId = id;
    }
  }

  // 4. dagre 布局（只放 source+step，出 y；x 等距化后处理）
  const g = new dagre.graphlib.Graph();
  g.setGraph({ rankdir: "LR", nodesep: NODESEP, edgesep: 8, ranksep: 1, marginx: 0, marginy: 0 });
  g.setDefaultEdgeLabel(() => ({}));
  for (const n of nodes) g.setNode(n.id, { width: n.w, height: n.h });
  for (const e of dagreEdges) g.setEdge(e.from, e.to);
  dagre.layout(g);
  for (const n of nodes) {
    const p = g.node(n.id);
    n.x = PAD_L + n.step * COL_X; // 列等距化（D2：同 step 严格同列）
    n.y = p.y - n.h / 2;
  }
  // 整体平移 minY → PAD_T
  const placed = nodes.filter((n) => n.kind === "source" || n.kind === "step");
  const minY = placed.length ? Math.min(...placed.map((n) => n.y)) : PAD_T;
  const dy = PAD_T - minY;
  for (const n of placed) n.y += dy;

  // 5. sink 后置（不进 dagre：safe-only 树 sink 成孤立分量会扰动行序；y=枝行纵向居中=旧 sinkY）
  const maxNodes = tree.branches.reduce((m, b) => Math.max(m, b.nodes.length), 0);
  const sinkStep = Math.max(1, maxNodes + 1); // 旧 sinkColIndex 口径
  const vulnCount = tree.branches.filter((b) => b.verdict === "vulnerable").length;
  const hasVuln = vulnCount > 0 || tree.findings.length > 0;
  const sinkLabel = tree.sink.label ?? "sink";
  const sinkLines = wrapLabel(sinkLabel, NODE_W - 24, 2);
  const sinkH = SINK_BASE_H + sinkLines.length * 12 + (hasVuln ? 0 : 14);
  const sinkId = `${treeId}:sink`;
  const sinkData: SinkNodeData = {
    kind: "sink",
    hasVuln,
    label: sinkLabel,
    lines: sinkLines,
    note: tree.sink.note ?? null,
  };
  const rangeMin = placed.length ? Math.min(...placed.map((n) => n.y)) : PAD_T;
  const rangeMax = placed.length ? Math.max(...placed.map((n) => n.y + n.h)) : PAD_T + sinkH;
  const sinkY = (rangeMin + rangeMax) / 2 - sinkH / 2;
  nodes.push({
    id: sinkId,
    kind: "sink",
    step: sinkStep,
    x: PAD_L + sinkStep * COL_X,
    y: sinkY,
    w: NODE_W,
    h: sinkH,
    data: sinkData,
  });

  // 6. fold 后置（图下方；展开态折叠行仍在——「收起」入口）
  if (hasFold) {
    const foldY = Math.max(...nodes.map((n) => n.y + n.h)) + 18;
    nodes.push({
      id: `${treeId}:fold`,
      kind: "fold",
      step: -1,
      x: PAD_L,
      y: foldY,
      w: COL_X,
      h: FOLD_H,
      data: {
        kind: "fold",
        hiddenCount: safeBranches.length - FOLD_THRESHOLD,
        expanded: !!opts.foldExpanded,
        highlighted: folding && hovered != null && foldedIds.includes(hovered),
      },
    });
  }

  // 7. 边：枝链边（+打通枝 →sink）+ 同名弧（可见节点链式配对，不进 dagre）
  const edges: PruneLayoutEdge[] = [];
  for (const b of visible) {
    const branchKey = branchKeyOf.get(b)!;
    const lastStep = lastStepOf(b);
    const ids = [nodeId(treeId, branchKey, 0)];
    for (let step = 1; step <= lastStep; step++) ids.push(nodeId(treeId, branchKey, step));
    for (let i = 1; i < ids.length; i++) {
      edges.push({
        id: `${treeId}:e:${branchKey}:${i}`,
        source: ids[i - 1],
        target: ids[i],
        kind: "branch",
        verdict: b.verdict,
        branchId: b.branch_id,
        hovered: b.branch_id === hovered,
        selected: b.branch_id === selected,
      });
    }
    if (reachesSinkOf(b)) {
      edges.push({
        id: `${treeId}:e:${branchKey}:sink`,
        source: ids[ids.length - 1],
        target: sinkId,
        kind: "branch",
        verdict: b.verdict,
        branchId: b.branch_id,
        hovered: b.branch_id === hovered,
        selected: b.branch_id === selected,
      });
    }
  }
  // 同名函数弧（跨枝同名节点对，spec §5「不合并节点」：弧=同一性提示；被剪断吞掉的节点不参与）
  const samePts = new Map<string, string[]>();
  for (const b of visible) {
    const branchKey = branchKeyOf.get(b)!;
    const lastStep = lastStepOf(b);
    for (let step = 1; step <= lastStep; step++) {
      const fn = b.nodes[step - 1].func;
      if (fn && shared.has(fn)) {
        const arr = samePts.get(fn) ?? [];
        arr.push(nodeId(treeId, branchKey, step));
        samePts.set(fn, arr);
      }
    }
  }
  let arcIdx = 0;
  for (const [fn, pts] of samePts) {
    for (let i = 1; i < pts.length; i++) {
      edges.push({
        id: `${treeId}:same:${arcIdx++}:${fn}`,
        source: pts[i - 1],
        target: pts[i],
        kind: "sameline",
        verdict: "unknown", // 弧无 verdict 语义（占位，渲染忽略）
        branchId: null,
        hovered: false,
        selected: false,
      });
    }
  }

  // 8. 包围盒
  const width = Math.max(...nodes.map((n) => n.x + n.w)) + PAD_R;
  const height = Math.max(...nodes.map((n) => n.y + n.h)) + PAD_B;

  return { nodes, edges, width, height, foldedIds, hasFold };
}
