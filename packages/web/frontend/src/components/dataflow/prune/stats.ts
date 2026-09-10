// 剪枝树统计纯函数（从旧 PruningTreeFig.tsx 原样搬，语义锁定见 prune-stats.test.ts）：
// - cutStepOf：剪断点定位（effective sanitizer 按 line+file 匹配节点，1-based；Infinity=不截断）；
// - sharedFuncNames / buildPubFuncStats：公共函数统计（spec §5「公共函数 ⟳ N 枝经过」）；
// - buildCrossTreeSourceTip：跨树 source 索引（同一入口流向多 sink 的提示）。
import type { DataflowBranch, DataflowSource, DataflowTree } from "@/api/types";
import type { PubFuncStat } from "./types";

/**
 * 剪断点 step（1-based）：verdict=safe 时 = effective sanitizer 所在节点序号；
 * 无匹配 → nodes.length（画到枝尾）；verdict≠safe → Infinity（不截断，全链到 sink）。
 * file 校验：真实数据不同文件 line 巧合相同会误定位剪断点（旧实现注释 2026-08-21）。
 */
export function cutStepOf(b: DataflowBranch): number {
  if (b.verdict !== "safe") return Infinity;
  const effSan = b.sanitizers.find((s) => s.effective === true);
  if (!effSan || effSan.line == null) return b.nodes.length;
  const idx = b.nodes.findIndex(
    (n) =>
      n.line != null &&
      n.line === effSan.line &&
      (effSan.file == null || n.file == null || n.file === effSan.file),
  );
  return idx >= 0 ? idx + 1 : b.nodes.length;
}

/** 同名函数检测：枝集合内 func 重名 → 该 func 出现于多枝。返回 Set<func 名>。 */
export function sharedFuncNames(branches: DataflowBranch[]): Set<string> {
  const counts = new Map<string, number>();
  for (const b of branches) {
    for (const n of b.nodes) {
      if (n.func) counts.set(n.func, (counts.get(n.func) ?? 0) + 1);
    }
  }
  const shared = new Set<string>();
  for (const [fn, c] of counts) if (c > 1) shared.add(fn);
  return shared;
}

/** 公共函数统计：func → { 经过枝数, 剪断枝 branch_id 列表 }（同枝同 func 只计一次）。 */
export function buildPubFuncStats(branches: DataflowBranch[]): Map<string, PubFuncStat> {
  const stats = new Map<string, PubFuncStat>();
  for (const b of branches) {
    const seen = new Set<string>();
    for (const n of b.nodes) {
      const fn = n.func;
      if (!fn || seen.has(fn)) continue;
      seen.add(fn);
      const cur = stats.get(fn) ?? { count: 0, cutBranches: [] };
      cur.count += 1;
      if (b.verdict === "safe" && b.branch_id) cur.cutBranches.push(b.branch_id);
      stats.set(fn, cur);
    }
  }
  return stats;
}

/** source 规范化 key（label + entry；二者皆空 → null，不索引）。 */
export function sourceKey(s: DataflowSource): string | null {
  const label = (s.label ?? "").trim();
  const entry = (s.entry ?? "").trim();
  if (!label && !entry) return null;
  return `${label}|${entry}`;
}

/**
 * 跨树 source 索引（spec §5「跨树 source 提示」）：返回函数 (source, currentTreeId) →
 * 其它树的 sink 名列表（"A / B"；无跨树 → null）。同一入口出现在多棵树时，source
 * tooltip 注「同一入口还流向」，避免误读为重复数据。
 */
export function buildCrossTreeSourceTip(
  trees: DataflowTree[],
): (source: DataflowSource, currentTreeId: string) => string | null {
  const index = new Map<string, { treeId: string; sink: string }[]>();
  for (const tree of trees) {
    for (const b of tree.branches) {
      const key = sourceKey(b.source);
      if (!key) continue;
      const entries = index.get(key) ?? [];
      const sink = tree.sink.label ?? tree.tree_id;
      if (!entries.some((e) => e.treeId === tree.tree_id)) {
        entries.push({ treeId: tree.tree_id, sink });
      }
      index.set(key, entries);
    }
  }
  return (source, currentTreeId) => {
    const key = sourceKey(source);
    if (!key) return null;
    const entries = index.get(key);
    if (!entries || entries.length < 2) return null; // 仅出现在一棵树 → 无跨树提示
    const otherSinks = entries.filter((e) => e.treeId !== currentTreeId).map((e) => e.sink);
    if (otherSinks.length === 0) return null;
    return otherSinks.join(" / ");
  };
}
