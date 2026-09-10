// 剪枝树 React Flow 自定义边（spec §5 视觉语言）：
// - BranchEdge：枝链边（打通红虚线 / 剪断绿实线 / 未判定橙虚线），hover/selected 联动
//   class（tokens.css .branch-*.hovered/.selected 契约）+ 20px 透明命中层（SVG 细线可点）；
// - SamelineEdge：同名函数青色点线弧（二次贝塞尔上抬），无文字标注（语义在 LegendBar）。
// 边路径从 data 携带的节点 rect 自算（不依赖 RF handle/measured 测量——jsdom 确定性、
// 渲染真值即布局真值），RF 内部端点计算不消费。
import type { Edge, EdgeProps } from "@xyflow/react";
import { getBezierPath, Position } from "@xyflow/react";
import { useBranchEvents } from "./events";
import { branchClass } from "./nodes";
import type { PruneVerdict } from "./types";

export interface RectLike {
  x: number;
  y: number;
  w: number;
  h: number;
}

export type BranchEdgeData = {
  verdict: PruneVerdict;
  branchId: string | null;
  hovered: boolean;
  selected: boolean;
  sourceRect: RectLike;
  targetRect: RectLike;
};

export type SamelineEdgeData = {
  from: RectLike;
  to: RectLike;
};

/** 枝链边：源盒右缘中心 → 目标盒左缘中心（贝塞尔，复刻旧汇入 sink 观感）。 */
export function BranchEdge({ data }: EdgeProps<Edge<BranchEdgeData>>) {
  const d = data as BranchEdgeData;
  const { onHover, onSelect } = useBranchEvents();
  const [path] = getBezierPath({
    sourceX: d.sourceRect.x + d.sourceRect.w,
    sourceY: d.sourceRect.y + d.sourceRect.h / 2,
    sourcePosition: Position.Right,
    targetX: d.targetRect.x,
    targetY: d.targetRect.y + d.targetRect.h / 2,
    targetPosition: Position.Left,
  });
  const cls = `${branchClass(d.verdict)}${d.hovered ? " hovered" : ""}${d.selected ? " selected" : ""}`;
  return (
    <g
      data-branch={d.verdict}
      data-branch-id={d.branchId ?? undefined}
      data-hovered={d.hovered ? "" : undefined}
      data-selected={d.selected ? "" : undefined}
      onMouseEnter={() => onHover(d.branchId)}
      onMouseLeave={() => onHover(null)}
      onClick={() => d.branchId && onSelect(d.branchId)}
    >
      <path d={path} className={cls} data-branch={d.verdict} />
      {/* 命中层：20px 透明描边盖在可视线上方（后渲染），SVG 细线可点 */}
      <path
        d={path}
        className="prune-edge-hit"
        style={{ strokeWidth: "20px", stroke: "transparent", fill: "none" }}
        pointerEvents="stroke"
        fill="none"
      />
    </g>
  );
}

/** 同名函数弧：两节点中心连线，控制点上抬（旧 SameLineArcView 观感），不可交互。 */
export function SamelineEdge({ data }: EdgeProps<Edge<SamelineEdgeData>>) {
  const d = data as SamelineEdgeData;
  const x1 = d.from.x + d.from.w / 2;
  const y1 = d.from.y + d.from.h / 2;
  const x2 = d.to.x + d.to.w / 2;
  const y2 = d.to.y + d.to.h / 2;
  const mx = (x1 + x2) / 2;
  const my = Math.min(y1, y2) - 24;
  const path = `M ${x1} ${y1} Q ${mx} ${my}, ${x2} ${y2}`;
  return (
    <g data-sameline="">
      <path d={path} className="sameline" />
    </g>
  );
}

/** 模块级 edgeTypes（RF 反模式规避）。 */
export const EDGE_TYPES = {
  branch: BranchEdge,
  sameline: SamelineEdge,
} as const;
