// 剪枝树 React Flow 画布（组合层，plan 2026-09-10 D3/D6/D7）：
// - 适配：PruneLayout（纯函数产物）→ RF nodes/edges；节点 style 钉死 w/h（渲染高==布局高）；
//   边 data 携节点 rect（自算路径，不依赖 RF 测量）；
// - 配置收口（分析视图非编辑器）：禁拖拽/连线/选择/焦点，纯滚轮不劫持页面滚动
//   （Ctrl+wheel 缩放复刻旧契约），fitView maxZoom=1（深树不缩小到不可读，靠平移）；
// - 自绘 ZoomBar（−/fit/＋，消费 i18n zoomIn/zoomOut/zoomReset——i18n key 零改动）；
// - 折叠展开/收起后 fitView 复位。每树一实例（TreeCard 内），fitView 各卡独立。
import { useCallback, useEffect, useMemo } from "react";
import { useTranslation } from "react-i18next";
import "@xyflow/react/dist/style.css";
import {
  Position,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
  type Edge,
  type Node,
} from "@xyflow/react";
import type { DataflowTree } from "@/api/types";
import { buildPruneLayout } from "./layout";
import { NODE_TYPES } from "./nodes";
import { EDGE_TYPES } from "./edges";
import { BranchEventsContext, type BranchEvents } from "./events";
import type { PruneLayoutEdge, PruneLayoutNode } from "./types";

/** 容器高度钳制（旧 ZoomViewport maxHeight=520 语义：大图 fitView 缩小、小图不撑卡）。 */
const MAX_CANVAS_H = 520;
const MIN_CANVAS_H = 200;

export interface FlowCanvasProps {
  tree: DataflowTree;
  /** 跨树 source 提示（PruningTreeFig 顶层 buildCrossTreeSourceTip(trees) 产物）。 */
  crossTreeTip: (source: DataflowTree["branches"][number]["source"], treeId: string) => string | null;
  hoveredBranch: string | null;
  selectedBranch: string | null;
  foldExpanded: boolean;
  onHover: (branchId: string | null) => void;
  onSelect: (branchId: string) => void;
  onFoldToggle: () => void;
  /** 图容器 aria（pruningTreeAria i18n，TreeCard 拼）。 */
  ariaLabel: string;
}

/** PruneLayout → RF Node[]（width/height 声明初始尺寸：RF 视为已测量，边几何首帧即可算
 *  ——jsdom（ResizeObserver no-op）下边照常渲染；style 同步钉死盒模型，渲染高==布局高）。 */
function toFlowNodes(nodes: PruneLayoutNode[]): Node[] {
  return nodes.map((n) => ({
    id: n.id,
    type: n.kind,
    position: { x: n.x, y: n.y },
    width: n.w,
    height: n.h,
    style: { width: n.w, height: n.h },
    // 声明式 handles（RF12）：不渲染 Handle DOM、不经测量——边渲染的初始化条件
    // （isNodeInitialized 要求 handleBounds || handles），端点=右缘/左缘中点
    handles: [
      { type: "source", position: Position.Right, x: n.w, y: n.h / 2 },
      { type: "target", position: Position.Left, x: 0, y: n.h / 2 },
    ],
    data: n.data,
    draggable: false,
    selectable: false,
    connectable: false,
    zIndex: 2,
  }));
}

/** PruneLayout → RF Edge[]（rect 塞 data 供自算路径；弧 z 在枝边下）。 */
function toFlowEdges(edges: PruneLayoutEdge[], rectOf: Map<string, PruneLayoutNode>): Edge[] {
  return edges.map((e) => {
    const s = rectOf.get(e.source)!;
    const t = rectOf.get(e.target)!;
    return {
      id: e.id,
      source: e.source,
      target: e.target,
      type: e.kind,
      zIndex: e.kind === "sameline" ? 0 : 1,
      data:
        e.kind === "branch"
          ? {
              verdict: e.verdict,
              branchId: e.branchId,
              hovered: e.hovered,
              selected: e.selected,
              sourceRect: { x: s.x, y: s.y, w: s.w, h: s.h },
              targetRect: { x: t.x, y: t.y, w: t.w, h: t.h },
            }
          : { from: { x: s.x, y: s.y, w: s.w, h: s.h }, to: { x: t.x, y: t.y, w: t.w, h: t.h } },
    };
  });
}

export function FlowCanvas(props: FlowCanvasProps) {
  const { tree, crossTreeTip, hoveredBranch, selectedBranch, foldExpanded } = props;

  const layout = useMemo(
    () =>
      buildPruneLayout(tree, {
        foldExpanded,
        hoveredBranch,
        selectedBranch,
        crossTreeTip,
      }),
    [tree, foldExpanded, hoveredBranch, selectedBranch, crossTreeTip],
  );

  const nodes = useMemo(() => toFlowNodes(layout.nodes), [layout]);
  const edges = useMemo(() => {
    const rectOf = new Map(layout.nodes.map((n) => [n.id, n]));
    return toFlowEdges(layout.edges, rectOf);
  }, [layout]);

  // 稳定事件对象（context 不承载高亮态 → 零订阅者随 hover 重渲染）
  const events = useMemo<BranchEvents>(
    () => ({ onHover: props.onHover, onSelect: props.onSelect, onFoldToggle: props.onFoldToggle }),
    [props.onHover, props.onSelect, props.onFoldToggle],
  );

  const canvasH = Math.min(MAX_CANVAS_H, Math.max(MIN_CANVAS_H, layout.height + 24));

  return (
    <BranchEventsContext.Provider value={events}>
      <ReactFlowProvider>
        <div className="prune-flow-wrap" style={{ height: canvasH }} role="img" aria-label={props.ariaLabel}>
          <PruneFlow nodes={nodes} edges={edges} foldExpanded={foldExpanded} />
          <ZoomBar />
        </div>
      </ReactFlowProvider>
    </BranchEventsContext.Provider>
  );
}

/** <ReactFlow> 主体（须在 Provider 内才能用 useReactFlow 的 ZoomBar 与 fitView 复位）。 */
function PruneFlow({ nodes, edges, foldExpanded }: { nodes: Node[]; edges: Edge[]; foldExpanded: boolean }) {
  const { fitView } = useReactFlow();
  // 折叠展开/收起后节点集变化 → 复位视口（fitView prop 只在 init 生效）
  useEffect(() => {
    fitView({ padding: 0.12, maxZoom: 1, duration: 200 });
  }, [foldExpanded, fitView]);
  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      nodeTypes={NODE_TYPES}
      edgeTypes={EDGE_TYPES}
      nodesDraggable={false}
      nodesConnectable={false}
      elementsSelectable={false}
      nodesFocusable={false}
      edgesFocusable={false}
      zoomOnScroll={false}
      zoomActivationKeyCode="Control"
      panOnScroll={false}
      preventScrolling={false}
      panOnDrag
      zoomOnPinch
      zoomOnDoubleClick={false}
      selectionKeyCode={null}
      deleteKeyCode={null}
      multiSelectionKeyCode={null}
      minZoom={0.3}
      maxZoom={2.5}
      fitView
      fitViewOptions={{ padding: 0.12, maxZoom: 1 }}
      className="prune-flow"
    />
  );
}

/** 自绘缩放条（复刻旧 −/百分比/＋；aria/title 走 i18n zoomOut/zoomReset/zoomIn 三 key）。 */
function ZoomBar() {
  const { t } = useTranslation();
  const { zoomIn, zoomOut, fitView } = useReactFlow();
  const btnCls = "rounded border border-border bg-card px-1.5 text-xs text-muted-foreground hover:text-primary";
  const reset = useCallback(() => fitView({ padding: 0.12, maxZoom: 1, duration: 200 }), [fitView]);
  return (
    <span className="absolute right-2 top-2 z-10 flex items-center gap-1" data-zoom-bar="">
      <button
        type="button"
        data-zoom-out=""
        onClick={() => zoomOut({ duration: 200 })}
        className={btnCls}
        aria-label={t("workspaceDetail.dataflow.zoomOut")}
      >
        −
      </button>
      <button type="button" data-zoom-reset="" onClick={reset} className={btnCls} title={t("workspaceDetail.dataflow.zoomReset")}>
        ⤢
      </button>
      <button
        type="button"
        data-zoom-in=""
        onClick={() => zoomIn({ duration: 200 })}
        className={btnCls}
        aria-label={t("workspaceDetail.dataflow.zoomIn")}
      >
        ＋
      </button>
    </span>
  );
}
