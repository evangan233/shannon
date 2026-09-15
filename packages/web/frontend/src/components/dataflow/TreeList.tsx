// 数据流树列表（2026-09-14 信息架构重做）：每树一行收起态 + 按需展开完整树卡。
// 动机：34 树全展开 = 12000px+ 长页 + 34 个 React Flow 实例——读者实际只关心少数树。
// 收起行 = 状态左边框（红=有打通/绿=全部剪断，与 BranchRow tone 语言同系）+ sink 名 +
// file:line mono + mini 比例条 + 枝计数 + chevron；整行可点（键盘可达）。
// 展开态：行头保持（chevron 旋转、作为收起开关），下方渲染 TreeCard（RF 画布 + 枝明细）。
// data-tree-id 只挂行（收起/展开恒在 DOM）——scrollspy/深链锚点稳定；TreeCard 自身不挂
// （PruningTreeFig 直渲染场景由其 wrapper 挂）。
import { useTranslation } from "react-i18next";
import { ChevronRight } from "lucide-react";
import type { DataflowTree } from "@/api/types";
import { TreeCard } from "./PruningTreeFig";
import { buildCrossTreeSourceTip } from "./prune/stats";

export interface TreeListProps {
  trees: DataflowTree[];
  /** 展开的 tree_id 集合（受控）。 */
  expandedIds: ReadonlySet<string>;
  /** 行点击切换（tree_id）。 */
  onToggle: (treeId: string) => void;
}

/** 树行（收起态摘要行 / 展开态行头）。 */
function TreeRowHeader({
  tree,
  expanded,
  onToggle,
  t,
}: {
  tree: DataflowTree;
  expanded: boolean;
  onToggle: (treeId: string) => void;
  t: ReturnType<typeof useTranslation>["t"];
}) {
  const vulnN = tree.branches.filter((b) => b.verdict === "vulnerable").length;
  const safeN = tree.branches.filter((b) => b.verdict === "safe").length;
  const unknownN = tree.branches.filter((b) => b.verdict === "unknown").length;
  const hasVuln = vulnN > 0 || tree.findings.length > 0;
  const total = Math.max(1, vulnN + safeN + unknownN);
  const pct = (n: number) => `${(n / total) * 100}%`;
  const countsKey =
    unknownN > 0 ? "workspaceDetail.dataflow.minibarWithUnknown" : "workspaceDetail.dataflow.minibar";
  return (
    <button
      type="button"
      data-tree-id={tree.tree_id}
      data-tree-row={expanded ? "expanded" : "collapsed"}
      aria-expanded={expanded}
      aria-label={t("workspaceDetail.dataflow.treeRowToggleAria", {
        sink: tree.sink.label ?? t("workspaceDetail.dataflow.sink"),
        state: expanded
          ? t("workspaceDetail.dataflow.treeRowCollapse")
          : t("workspaceDetail.dataflow.treeRowExpand"),
      })}
      onClick={() => onToggle(tree.tree_id)}
      className={`flex w-full items-center gap-2.5 rounded-lg border border-border bg-card px-3 py-2 text-left text-sm transition-colors hover:bg-accent/60 ${
        expanded ? "border-l-2" : ""
      } ${hasVuln ? "border-l-[hsl(var(--c-red))]" : "border-l-[hsl(var(--c-green))]"}`}
    >
      <ChevronRight
        aria-hidden
        className={`size-3.5 shrink-0 text-muted-foreground transition-transform ${expanded ? "rotate-90" : ""}`}
      />
      <span className="min-w-0 shrink font-medium">
        {tree.sink.label ?? t("workspaceDetail.dataflow.sink")}
      </span>
      {tree.sink.file && (
        <span className="hidden min-w-0 truncate font-mono text-xs text-muted-foreground sm:inline">
          {tree.sink.file}
          {tree.sink.line != null ? `:${tree.sink.line}` : ""}
        </span>
      )}
      <span className="ml-auto flex shrink-0 items-center gap-2">
        <span className="text-xs text-muted-foreground" data-rowbar-text="">
          {t(countsKey, { vuln: vulnN, safe: safeN, unknown: unknownN })}
        </span>
        <span
          className="inline-flex h-2 w-14 overflow-hidden rounded-full border border-border"
          aria-hidden
          data-rowbar=""
        >
          <span className="bg-[hsl(var(--c-red))]" style={{ width: pct(vulnN) }} />
          <span className="bg-[hsl(var(--c-green))]" style={{ width: pct(safeN) }} />
          {unknownN > 0 && (
            <span
              className="bg-[hsl(var(--c-amber))] opacity-80"
              style={{ width: pct(unknownN) }}
            />
          )}
        </span>
      </span>
    </button>
  );
}

export function TreeList({ trees, expandedIds, onToggle }: TreeListProps) {
  const { t } = useTranslation();
  // 跨树 source 索引（spec §5「跨树 source 提示」）：同一入口出现在多树 → tooltip 注明
  const crossTreeTip = buildCrossTreeSourceTip(trees);
  return (
    <div className="space-y-2" data-tree-list="">
      {trees.map((tree) => {
        const expanded = expandedIds.has(tree.tree_id);
        return (
          <div key={tree.tree_id} className="space-y-2">
            <TreeRowHeader tree={tree} expanded={expanded} onToggle={onToggle} t={t} />
            {expanded && <TreeCard tree={tree} crossTreeTip={crossTreeTip} />}
          </div>
        );
      })}
    </div>
  );
}
