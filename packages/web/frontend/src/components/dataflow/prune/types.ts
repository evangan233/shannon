// 剪枝树 React Flow 迁移的类型与布局常量（spec 2026-08-20 §5 视觉语言，plan 2026-09-10）。
// 分层：layout.ts 纯函数产出 PruneLayout（RF 无关、jsdom 可测）→ FlowCanvas 薄适配成
// ReactFlow 的 nodes/edges；i18n 文案在节点/边组件内用 useTranslation 拼（layout 不依赖 t）。
import type { DataflowBranch, DataflowNode } from "@/api/types";

export type PruneVerdict = DataflowBranch["verdict"];

/** 公共函数统计（spec §5「公共函数 ⟳ N 枝经过」）：func → 经过枝数 + 剪断枝 branch_id 列表。 */
export interface PubFuncStat {
  count: number;
  cutBranches: string[];
}

// —— 布局常量（导出供测试断言；改 NODE_W/COL_X 须同步评估列隙） ——

/** 节点盒宽（HTML 盒固定宽，文字 overflow-wrap 换行——重叠根治机制 D1）。 */
export const NODE_W = 160;
/** 列等距步长 = NODE_W + 44 列隙；「断在第几列横向可比」由 x = PAD_L + step×COL_X 保证（D2）。 */
export const COL_X = 204;
/** dagre 同列纵向净间隙。 */
export const NODESEP = 26;
/** 标签行数封顶（超出末行加「…」，全文进 <title>）。 */
export const MAX_LINES = 3;
/** 剪断枝 >4 折叠（沿用旧 FOLD_THRESHOLD）。 */
export const FOLD_THRESHOLD = 4;
export const PAD_L = 12;
export const PAD_T = 16;
export const PAD_R = 24;
export const PAD_B = 16;

// —— 节点 data（判别联合；hovered/selected 由 TreeCard 态经 layout 注入） ——

export type SourceNodeData = {
  kind: "source";
  branchId: string | null;
  verdict: PruneVerdict;
  /** sink 名（aria-label「从 source 流向 sink」用，branchAria i18n 参数）。 */
  sinkLabel: string;
  /** 完整 label（HTML 自动换行，不截断）。 */
  label: string;
  /** 副信息行文本（type · METHOD /route；storage 时不渲染 meta 行）。 */
  metaText: string | null;
  /** 2ND 存储中转枝（source.type === "storage"）琥珀标记。 */
  isStorage: boolean;
  /** LLM 叙事原句（tooltip 优先项；无则退全名）。 */
  note: string | null;
  /** 跨树提示：其它树的 sink 名列表（"A / B"），null=无跨树。 */
  crossTreeSinks: string | null;
  hovered: boolean;
  selected: boolean;
}

export type StepNodeData = {
  kind: "step";
  branchId: string | null;
  /** 1-based step（data-node 锚点；source 是 step 0）。 */
  step: number;
  fullLabel: string;
  /** wrapLabel 产物（高度估算依据；渲染交给 CSS 换行）。 */
  lines: string[];
  /** 原始 DataflowNode（note/code 等明细由组件消费）。 */
  node: DataflowNode;
  /** 所在枝是否打通（vuln/unknown）——节点盒配色。 */
  isVuln: boolean;
  /** 是否剪断点（✂ + 残端装饰）。 */
  isCut: boolean;
  shield: "none" | "green" | "yellow";
  pub: PubFuncStat | null;
  hovered: boolean;
  selected: boolean;
}

export type SinkNodeData = {
  kind: "sink";
  /** 有打通枝（vulnCount>0 或 findings 非空）→ 红脉动；否则灰虚线 +「无输入到达」。 */
  hasVuln: boolean;
  label: string;
  lines: string[];
  note: string | null;
}

export type FoldNodeData = {
  kind: "fold";
  /** 被折叠的剪断枝数。 */
  hiddenCount: number;
  expanded: boolean;
  /** hover 被折叠枝明细行 → 本节点高亮（反馈「该枝在折叠批次里」）。 */
  highlighted: boolean;
}

export type PruneNodeData = SourceNodeData | StepNodeData | SinkNodeData | FoldNodeData;

// —— 布局层结构（纯函数可测；x/y 为左上角，渲染高度==布局高度由 style 钉死） ——

export interface PruneLayoutNode {
  id: string;
  kind: PruneNodeData["kind"];
  /** 列号：source=0 / 步 i=i / sink=maxStep+1 / fold=-1（后置图下方）。 */
  step: number;
  x: number;
  y: number;
  w: number;
  h: number;
  data: PruneNodeData;
}

export interface PruneLayoutEdge {
  id: string;
  source: string;
  target: string;
  kind: "branch" | "sameline";
  verdict: PruneVerdict;
  branchId: string | null;
  hovered: boolean;
  selected: boolean;
}

export interface PruneLayout {
  nodes: PruneLayoutNode[];
  edges: PruneLayoutEdge[];
  /** 内容包围盒（容器高度与 fitView 参考）。 */
  width: number;
  height: number;
  foldedIds: string[];
  hasFold: boolean;
}

/** 布局输入态（TreeCard 的联动 state + 跨树提示函数）。 */
export interface PruneLayoutOpts {
  foldExpanded?: boolean;
  hoveredBranch?: string | null;
  selectedBranch?: string | null;
  /** 跨树 source 提示（PruningTreeFig 顶层 buildCrossTreeSourceTip(trees) 产物，纯函数入参）。 */
  crossTreeTip?: (source: DataflowBranch["source"], currentTreeId: string) => string | null;
}
