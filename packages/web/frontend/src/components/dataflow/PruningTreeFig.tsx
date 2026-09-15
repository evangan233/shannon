// 剪枝树组件（spec 2026-08-20 §5 视觉语言；2026-09-10 迁移 React Flow，spec §5 预留路径）。
// 每棵 sink 树一张卡：树头徽章 + React Flow 画布（prune/ 模块族）+ 枝条明细列表，
// 图↔行双向 hover/点选联动（state 提升在 TreeCard，契约与旧版一致）。
// 布局/节点/边/缩放在 prune/{layout,nodes,edges,FlowCanvas}；本文件只做组合与联动 state。
//
// 迁移动机：旧自研 SVG 固定网格（列宽 180/行高 88 + 手写估宽截断）在真实数据
// （LLM 自然语言 label 40-70 字符）下节点/文字互叠，三轮补丁（2026-08-21/26）后到极限；
// React Flow HTML 节点 + dagre 按真实尺寸避让，重叠物理消灭（prune-layout.test 不变量锁）。
import { useCallback, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import type { DataflowTree } from "@/api/types";
import { BranchRow } from "./BranchRow";
import { buildCrossTreeSourceTip } from "./prune/stats";
import { FlowCanvas } from "./prune/FlowCanvas";

export interface PruningTreeFigProps {
  trees: DataflowTree[];
}

export function PruningTreeFig({ trees }: PruningTreeFigProps) {
  // 跨树 source 索引（spec §5「跨树 source 提示」）：同一入口出现在多树 → tooltip 注明
  const crossTreeTip = useMemo(() => buildCrossTreeSourceTip(trees), [trees]);
  if (trees.length === 0) return null;
  return (
    <div className="space-y-4">
      {trees.map((tree) => (
        /* data-tree-id 挂 wrapper（TreeCard 自身不挂——TreeList 场景由树行挂载，避免展开态双锚点） */
        <div key={tree.tree_id} data-tree-id={tree.tree_id}>
          <TreeCard tree={tree} crossTreeTip={crossTreeTip} />
        </div>
      ))}
    </div>
  );
}

/** 单棵树卡：树头徽章 + RF 画布 + 枝条明细列表。
 *  图↔行交互（spec §5「交互」段）：TreeCard 是图与明细行的共同父级，联动 state 提升至
 *  此——hover 任一侧（边/节点或 BranchRow）→ 两侧同高亮（双向）；点枝条 → 选中对应
 *  明细行（高亮 + 展开首个节点 code，再点取消）；剪断枝折叠展开/收起。
 *  2026-09-14 信息架构重做：export 供 TreeList 展开态消费（收起行见 TreeList）。 */
export function TreeCard({
  tree,
  crossTreeTip,
}: {
  tree: DataflowTree;
  crossTreeTip: ReturnType<typeof buildCrossTreeSourceTip>;
}) {
  const { t } = useTranslation();
  const [hoveredBranch, setHoveredBranch] = useState<string | null>(null);
  const [selectedBranch, setSelectedBranch] = useState<string | null>(null);
  const [foldExpanded, setFoldExpanded] = useState(false);

  const handleBranchHover = useCallback((id: string | null) => setHoveredBranch(id), []);
  const handleBranchSelect = useCallback(
    (id: string) => setSelectedBranch((cur) => (cur === id ? null : id)),
    [],
  );
  const handleFoldToggle = useCallback(() => setFoldExpanded((cur) => !cur), []);

  const vulnCount = tree.branches.filter((b) => b.verdict === "vulnerable").length;
  const safeCount = tree.branches.filter((b) => b.verdict === "safe").length;
  const unknownCount = tree.branches.filter((b) => b.verdict === "unknown").length;
  const hasVuln = vulnCount > 0 || tree.findings.length > 0;

  const ariaLabel = t(
    unknownCount > 0
      ? "workspaceDetail.dataflow.pruningTreeAriaWithUnknown"
      : "workspaceDetail.dataflow.pruningTreeAria",
    {
      sink: tree.sink.label ?? "sink",
      vuln: vulnCount,
      safe: safeCount,
      unknown: unknownCount,
    },
  );

  return (
    <section
      className="rounded-lg border border-border bg-card p-4 shadow-card"
      data-testid="pruning-tree-card"
    >
      <TreeHeader
        tree={tree}
        t={t}
        vulnCount={vulnCount}
        safeCount={safeCount}
        unknownCount={unknownCount}
        hasVuln={hasVuln}
      />
      <FlowCanvas
        tree={tree}
        crossTreeTip={crossTreeTip}
        hoveredBranch={hoveredBranch}
        selectedBranch={selectedBranch}
        foldExpanded={foldExpanded}
        onHover={handleBranchHover}
        onSelect={handleBranchSelect}
        onFoldToggle={handleFoldToggle}
        ariaLabel={ariaLabel}
      />
      {/* 枝条明细列表（与图边/节点双向高亮联动；点枝条选中展开） */}
      <div className="mt-3">
        {tree.branches.map((b) => (
          <BranchRow
            key={b.branch_id ?? b.source.label}
            branch={b}
            highlighted={!!b.branch_id && hoveredBranch === b.branch_id}
            selected={!!b.branch_id && selectedBranch === b.branch_id}
            onHover={handleBranchHover}
          />
        ))}
      </div>
    </section>
  );
}

/** 树头徽章：sink 名 + file:line + rule_id/class + finding IDs + 迷你比例条。
 *  比例条三段式（红=打通 / 绿=剪断 / 琥珀=未判定——未判定不视觉等同「安全」）。 */
function TreeHeader({
  tree,
  t,
  vulnCount,
  safeCount,
  unknownCount,
  hasVuln,
}: {
  tree: DataflowTree;
  t: ReturnType<typeof useTranslation>["t"];
  vulnCount: number;
  safeCount: number;
  unknownCount: number;
  hasVuln: boolean;
}) {
  const findingIds = tree.findings.map((f) => f.id).filter(Boolean).join(", ");
  const total = Math.max(1, vulnCount + safeCount + unknownCount);
  const pct = (n: number) => `${(n / total) * 100}%`;
  const hasUnknown = unknownCount > 0;
  return (
    <div className="mb-3 flex flex-wrap items-center gap-2 text-sm">
      <span
        className={`inline-flex size-2.5 rounded-full ${hasVuln ? "bg-[hsl(var(--c-red))]" : "bg-[hsl(var(--c-green))]"}`}
        aria-hidden
      />
      <span className="font-medium">{tree.sink.label ?? t("workspaceDetail.dataflow.sink")}</span>
      {tree.sink.file && (
        <span className="font-mono text-xs text-muted-foreground">
          {tree.sink.file}
          {tree.sink.line != null ? `:${tree.sink.line}` : ""}
        </span>
      )}
      {tree.sink.rule_id && (
        <span className="rounded bg-secondary px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
          {tree.sink.rule_id}
        </span>
      )}
      {tree.sink.category && (
        <span className="rounded bg-secondary px-1.5 py-0.5 text-[10px] text-muted-foreground">
          {tree.sink.category}
        </span>
      )}
      {findingIds && <span className="font-mono text-xs text-muted-foreground">{findingIds}</span>}
      <span className="ml-auto flex items-center gap-1.5">
        <span className="text-xs text-muted-foreground" data-minibar-text="">
          {t(
            hasUnknown
              ? "workspaceDetail.dataflow.minibarWithUnknown"
              : "workspaceDetail.dataflow.minibar",
            { vuln: vulnCount, safe: safeCount, unknown: unknownCount },
          )}
        </span>
        <span
          className="inline-flex h-2 w-16 overflow-hidden rounded-full border border-border"
          role="img"
          data-minibar=""
          aria-label={t(
            hasUnknown
              ? "workspaceDetail.dataflow.minibarAriaWithUnknown"
              : "workspaceDetail.dataflow.minibarAria",
            { vuln: vulnCount, safe: safeCount, unknown: unknownCount },
          )}
        >
          <span data-minibar-seg="vuln" className="bg-[hsl(var(--c-red))]" style={{ width: pct(vulnCount) }} />
          <span data-minibar-seg="safe" className="bg-[hsl(var(--c-green))]" style={{ width: pct(safeCount) }} />
          {hasUnknown && (
            <span
              data-minibar-seg="unknown"
              className="bg-[hsl(var(--c-amber))] opacity-80"
              style={{ width: pct(unknownCount) }}
            />
          )}
        </span>
      </span>
    </div>
  );
}
