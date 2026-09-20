import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Info, Redo2, Undo2, LayoutGrid, Maximize, Minus, Plus } from "lucide-react";
import type { CorrelationTopologyEvidence } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  addTopologyEdge, deleteTopologyEdge, moveTopologyNode, redoTopology, undoTopology,
  resetTopologyLayout, restoreTopologyAiEdge, setTopologyEdgeEnabled, updateTopologyEdge,
  setTopologyNodeSource, toggleTopologyRole,
  validateTopologyDraft, type TopologyDraftState,
} from "@/lib/correlation-topology-draft";
import { anchorPair, type Box } from "@/lib/topology-anchors";

interface Props {
  state: TopologyDraftState;
  onState: (state: TopologyDraftState) => void;
  /** 复用候选数据源（属性面板节点模式「来源」下拉；原 TopologyTables 通道，2026-09-04 撤表并轨）。 */
  scans?: unknown[];
  onRemoveNode?: (repo: string) => void;
}

/** 节点盒尺寸（viewBox 坐标）——lib 侧 clamp 与此处共用同一口径。 */
const NODE_W = 105;
const NODE_H = 48;
/** 画布 viewBox（与 svg viewBox 硬编码一致）。 */
const CANVAS_W = 800;
const CANVAS_H = 600;
/** 拖动时节点离画布边缘的最小留白。 */
const EDGE_MARGIN = 6;
/** repo 名截断阈值：11px mono 下 105px 盒内可容 ~14 字符，超出截断 + title 悬停看全名。 */
const NAME_MAX = 14;

/* ===== 画布 pan/zoom（视口态，非内容态——不进 undo history）=====
 * 跨仓微服务动辄 6+ 服务，固定 800×600 视口装不下：滚轮缩放（指针锚定）+
 * 空白拖动平移 + 右下角缩放条（−/100%/＋/fit）。世界坐标 = 节点坐标（不变），
 * 视口坐标 = viewBox 原坐标，映射：world = (viewport - t) / k。 */
export interface ViewTransform { x: number; y: number; k: number }
/** 缩放范围：0.3（全景，服务 15+ 时仍可辨）～3（看文件级证据细节）。 */
const MIN_K = 0.3;
const MAX_K = 3;
const ZOOM_STEP = 1.2;

function clampK(k: number): number {
  return Math.min(MAX_K, Math.max(MIN_K, k));
}

/**
 * 客户端坐标 → viewBox 视口坐标。preserveAspectRatio 默认 meet 下容器宽高比
 * ≠ 4:3 时内容居中等比（宽容器左右留白）：rect.width 直接按比例换算有漂移，
 * 须按实际渲染 scale + 居中偏移换算（缩放后漂移被 k 放大，指针锚定会跑偏）。
 */
export function viewportPointOf(
  svg: SVGSVGElement | null, clientX: number, clientY: number,
): { x: number; y: number } {
  const rect = svg?.getBoundingClientRect();
  if (!rect) return { x: 0, y: 0 };
  const scale = Math.min(rect.width / CANVAS_W, rect.height / CANVAS_H) || 1;
  const offsetX = (rect.width - CANVAS_W * scale) / 2;
  const offsetY = (rect.height - CANVAS_H * scale) / 2;
  return { x: (clientX - rect.left - offsetX) / scale, y: (clientY - rect.top - offsetY) / scale };
}

/** 以视口坐标 vp 为锚缩放 factor 倍（指针下的世界点不动——内容朝指针收放）。 */
export function zoomAtPoint(
  v: ViewTransform, vp: { x: number; y: number }, factor: number,
): ViewTransform {
  const k = clampK(v.k * factor);
  const applied = k / v.k;
  return { k, x: vp.x - (vp.x - v.x) * applied, y: vp.y - (vp.y - v.y) * applied };
}

/** 节点包围盒是否溢出 800×600 画布（初始视口 {0,0,1} 下判定）。 */
function bboxOverflows(nodes: { position: { x: number; y: number } }[]): boolean {
  if (!nodes.length) return false;
  return nodes.some((n) => n.position.x < 0 || n.position.y < 0
    || n.position.x + NODE_W > CANVAS_W || n.position.y + NODE_H > CANVAS_H);
}

/** 节点包围盒适配视口：只缩小不放大（k ≤ 1——小图维持 100% 细节，不糊不迫近）。 */
export function fitTransform(
  nodes: { position: { x: number; y: number } }[], pad = 40,
): ViewTransform {
  if (!nodes.length) return { x: 0, y: 0, k: 1 };
  const minX = Math.min(...nodes.map((n) => n.position.x));
  const minY = Math.min(...nodes.map((n) => n.position.y));
  const maxX = Math.max(...nodes.map((n) => n.position.x + NODE_W));
  const maxY = Math.max(...nodes.map((n) => n.position.y + NODE_H));
  const k = Math.min(1, clampK(Math.min((CANVAS_W - pad * 2) / (maxX - minX), (CANVAS_H - pad * 2) / (maxY - minY))));
  return {
    k,
    x: (CANVAS_W - (maxX - minX) * k) / 2 - minX * k,
    y: (CANVAS_H - (maxY - minY) * k) / 2 - minY * k,
  };
}

/* ===== 证据面板解释性包装 =====
 * 证据是 agent 摘录的原样源码行（exact source line，后端校验 snippet 真实出现在
 * 该 file:line——防伪造），不是 agent 总结；「看得懂」由呈现层负责：叙述句 +
 * 调用方/接收方双端分组 + 空端显式化（handler 缺失本身是可信度信息）。 */

/** confidence → 语义色（StatusBadge 同款 border/text 语言）。 */
function confidenceClass(c: string): string {
  switch (c) {
    case "high":
      return "border-green/40 text-green";
    case "medium":
      return "border-amber/40 text-amber";
    default:
      return "border-border text-muted-foreground";
  }
}

/** 「重新扫描」哨兵值：radix SelectItem 不接受空串，重扫选项经哨兵映射回 null
 *  （原 TopologyTables 通道，撤表并轨进属性面板）。 */
const RESCAN = "__rescan__";

/** 属性面板紧凑下拉（ui/Select 全站同款；右栏窄列用小号）。 */
function CellSelect({ ariaLabel, value, placeholder, onChange, options }: {
  ariaLabel: string;
  value: string | undefined;
  placeholder?: string;
  onChange: (v: string) => void;
  options: { value: string; label: React.ReactNode }[];
}) {
  return (
    <Select value={value} onValueChange={onChange}>
      <SelectTrigger aria-label={ariaLabel} className="h-8 w-full text-xs">
        <SelectValue placeholder={placeholder} />
      </SelectTrigger>
      <SelectContent>
        {options.map((o) => <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>)}
      </SelectContent>
    </Select>
  );
}

/** 单条证据：file:line 头 + 原样 snippet 代码块（保留原文不转述）。valid=false
 *  （snippet 与源码不符，后端打假）标destructive 并透出校验错误。 */
function EvidenceItem({ ev }: { ev: CorrelationTopologyEvidence }) {
  const { t } = useTranslation();
  return (
    <div className="space-y-0.5">
      <div className="font-mono text-[11px] text-muted-foreground">
        {ev.repo}/{ev.file}:{ev.line ?? "?"}
        {ev.valid === false && (
          <span className="ml-1 font-sans text-destructive">
            {t("scan.correlation.topology.invalidEvidence")}
          </span>
        )}
      </div>
      {ev.snippet && (
        <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded bg-muted px-2 py-1 font-mono text-[11px] leading-relaxed text-foreground">
          {ev.snippet}
        </pre>
      )}
      {ev.valid === false && ev.validation_errors && ev.validation_errors.length > 0 && (
        <p className="text-[11px] text-destructive">{ev.validation_errors.join("; ")}</p>
      )}
    </div>
  );
}

/** 一端证据组：方向符号（⇢ 调用方发出 / ⇠ 接收方收到）+ 角色·仓标签；空端显式说明。 */
function EdgeEvidenceGroup({
  dir, label, repo, evidence, emptyText,
}: {
  dir: "client" | "handler";
  label: string;
  repo: string;
  evidence: CorrelationTopologyEvidence[];
  emptyText: string;
}) {
  return (
    <div className="space-y-1" data-testid={`topology-evidence-${dir}`}>
      <div className="font-medium">
        <span aria-hidden className="mr-1">{dir === "client" ? "⇢" : "⇠"}</span>
        {label} · <span className="font-mono">{repo}</span>
      </div>
      {evidence.length === 0 ? (
        <p className="text-[11px] text-muted-foreground">{emptyText}</p>
      ) : (
        evidence.map((ev, i) => <EvidenceItem key={`${ev.repo}-${ev.file}-${i}`} ev={ev} />)
      )}
    </div>
  );
}

/** 节点属性面板（右栏节点模式，2026-09-04 撤 TopologyTables 并轨）：角色 / 来源 /
 *  移除——原节点表的编辑能力全部收进这里，点击节点即达。 */
function NodePanel({ node, state, onState, scans, onRemove }: {
  node: NonNullable<TopologyDraftState["draft"]["nodes"][number]>;
  state: TopologyDraftState;
  onState: (s: TopologyDraftState) => void;
  scans: Array<{ scan_id?: string; id?: string; repo?: string; scan_type?: string; status?: string }>;
  onRemove?: (repo: string) => void;
}) {
  const { t } = useTranslation();
  const reusable = scans.filter((scan) => scan.scan_type === "whitebox"
    && scan.status === "completed" && scan.repo === node.repo && (scan.scan_id ?? scan.id));
  return (
    <div className="space-y-3 text-xs" data-testid="topology-node-panel">
      <div className="text-sm font-semibold font-mono">{node.repo}</div>
      <div className="space-y-1.5">
        <div className="text-muted-foreground">{t("scan.correlation.roleLabel")}</div>
        <div className="flex gap-3">
          {(["entrypoint", "backend"] as const).map((role) => (
            <label key={role} className="flex items-center gap-1.5">
              <Checkbox checked={node.roles.includes(role)}
                onCheckedChange={() => onState(toggleTopologyRole(state, node.repo, role))}
                aria-label={`${node.repo} ${role}`} />
              {t(`scan.correlation.role${role === "entrypoint" ? "Entrypoint" : "Backend"}`)}
            </label>
          ))}
        </div>
      </div>
      <label className="block space-y-1">
        <span className="text-muted-foreground">{t("scan.correlation.sourceLabel")}</span>
        <CellSelect ariaLabel={`${node.repo} source`} value={node.reuseScanId ?? RESCAN}
          onChange={(v) => onState(setTopologyNodeSource(state, node.repo, v === RESCAN ? null : v))}
          options={[
            { value: RESCAN, label: t("scan.correlation.sourceRescan") },
            ...reusable.map((scan) => ({
              value: scan.scan_id ?? scan.id ?? "",
              label: <span className="font-mono text-xs">
                {t("scan.correlation.sourceReuse")}: {scan.scan_id ?? scan.id}
              </span>,
            })),
          ]} />
      </label>
      {onRemove && (
        <Button type="button" variant="outline" size="sm" aria-label={`${t("scan.correlation.topology.removeNode")} ${node.repo}`}
          onClick={() => onRemove(node.repo)}>
          {t("scan.correlation.topology.removeNode")}
        </Button>
      )}
    </div>
  );
}

export function TopologyEditor({ state, onState, scans: scansUnknown = [], onRemoveNode }: Props) {
  const { t } = useTranslation();
  // 复用候选（属性面板「来源」下拉数据源）：原 TopologyTables 的窄化透传，撤表并轨后收进编辑器。
  const scans = scansUnknown as Array<{ scan_id?: string; id?: string; repo?: string; scan_type?: string; status?: string }>;
  const svgRef = useRef<SVGSVGElement>(null);
  const dragRepo = useRef<string | null>(null);
  /** 拖动位移标记：pointerdown→pointerup 位移 <5px 判点击（选中节点），否则是拖动布局。 */
  const dragMoved = useRef(false);
  // 连线态 state 化（原 ref 不触发渲染，拖线全程零视觉反馈）。connectPos = 预览线终点
  // （鼠标的世界坐标）。成边通道 = 在目标节点上松手；空白/画布外松手与 Esc = 取消。
  const [connectFrom, setConnectFrom] = useState<string | null>(null);
  const [connectPos, setConnectPos] = useState<{ x: number; y: number } | null>(null);
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null);
  /** 选中节点（右栏节点模式）：与选中边互斥——属性面板一次只服务一个对象。 */
  const [selectedNodeRepo, setSelectedNodeRepo] = useState<string | null>(null);
  // 画布视口（pan/zoom）：panning 态只驱动 grab→grabbing 光标；origin 快照让平移
  // 增量从落点起算（不受中间 setView 重渲染影响）。挂载时若节点包围盒溢出画布
  //（AI 分析恢复 5+ 服务时纵向 110px 步进会超出 600 viewBox）自动 fit 全图——
  // 无溢出保持 {0,0,1} 不惊动（小图 100% 细节）。后续节点增删不自动 fit（视口
  // 归用户，溢出提示点在 fit 按钮上）。
  const [view, setView] = useState<ViewTransform>(() =>
    bboxOverflows(state.draft.nodes) ? fitTransform(state.draft.nodes) : { x: 0, y: 0, k: 1 });
  const [panning, setPanning] = useState(false);
  const panRef = useRef<{ vx: number; vy: number; origin: ViewTransform } | null>(null);
  const selectedEdge = state.draft.edges.find((edge) => edge.id === selectedEdgeId) ?? null;
  const selectedNode = selectedNodeRepo
    ? state.draft.nodes.find((n) => n.repo === selectedNodeRepo) ?? null
    : null;
  const liveIdentities = new Set(state.draft.edges.map((edge) => `${edge.from}\n${edge.to}\n${edge.protocol}`));
  const removedAiEdges = (state.analysis?.result?.edges ?? []).filter(
    (edge) => !liveIdentities.has(`${edge.from}\n${edge.to}\n${edge.protocol}`));
  const nodeByRepo = new Map(state.draft.nodes.map((node) => [node.repo, node]));

  // Esc 取消连线（连线态才挂全局监听）
  useEffect(() => {
    if (!connectFrom) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { setConnectFrom(null); setConnectPos(null); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [connectFrom]);

  // 滚轮缩放须 native listener + passive:false：React onWheel 挂在 root 的
  // passive listener 上，preventDefault 无效（console 报警），页面会跟着滚。
  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return;
    const onWheel = (event: WheelEvent) => {
      event.preventDefault();
      // deltaMode 行/像素两种粒度归一；指数步进让触控板小增量平滑、滚轮格挡有感。
      const unit = event.deltaMode === WheelEvent.DOM_DELTA_LINE ? 33 : 1;
      const factor = Math.exp(-event.deltaY * unit * 0.0016);
      setView((v) => zoomAtPoint(v, viewportPointOf(svg, event.clientX, event.clientY), factor));
    };
    svg.addEventListener("wheel", onWheel, { passive: false });
    return () => svg.removeEventListener("wheel", onWheel);
  }, []);

  /** 指针事件的世界坐标（逆视口变换，预览线跟随鼠标用，不 clamp）。 */
  const rawPoint = (event: React.PointerEvent) => {
    const vp = viewportPointOf(svgRef.current, event.clientX, event.clientY);
    return { x: (vp.x - view.x) / view.k, y: (vp.y - view.y) / view.k };
  };
  /** 节点拖动坐标：clamp 进画布（节点不再能拖出边界「消失」）。 */
  const nodePoint = (event: React.PointerEvent) => {
    const p = rawPoint(event);
    return {
      x: Math.min(Math.max(p.x, EDGE_MARGIN), CANVAS_W - NODE_W - EDGE_MARGIN),
      y: Math.min(Math.max(p.y, EDGE_MARGIN), CANVAS_H - NODE_H - EDGE_MARGIN),
    };
  };

  const boxOf = (node: { position: { x: number; y: number } }): Box =>
    ({ x: node.position.x, y: node.position.y, w: NODE_W, h: NODE_H });
  const connectFromNode = connectFrom ? nodeByRepo.get(connectFrom) : undefined;

  const cancelConnect = () => { setConnectFrom(null); setConnectPos(null); };

  /** 节点包围盒（含盒体）是否溢出当前视口——溢出时 fit 按钮亮圆点作「找回全局」提示。 */
  const needsFit = (() => {
    if (!state.draft.nodes.length) return false;
    const xs = state.draft.nodes.flatMap((n) =>
      [n.position.x * view.k + view.x, (n.position.x + NODE_W) * view.k + view.x]);
    const ys = state.draft.nodes.flatMap((n) =>
      [n.position.y * view.k + view.y, (n.position.y + NODE_H) * view.k + view.y]);
    return Math.min(...xs) < -1 || Math.max(...xs) > CANVAS_W + 1
      || Math.min(...ys) < -1 || Math.max(...ys) > CANVAS_H + 1;
  })();

  return (
    <section className="space-y-3" aria-label={t("scan.correlation.topology.editor")}>
      <div className="flex flex-wrap items-center gap-2">
        <Button type="button" variant="outline" size="sm" disabled={!state.history.past.length}
          onClick={() => onState(undoTopology(state))}><Undo2 className="h-3.5 w-3.5" />{t("scan.correlation.topology.undo")}</Button>
        <Button type="button" variant="outline" size="sm" disabled={!state.history.future.length}
          onClick={() => onState(redoTopology(state))}><Redo2 className="h-3.5 w-3.5" />{t("scan.correlation.topology.redo")}</Button>
        <Button type="button" variant="outline" size="sm" onClick={() => onState(resetTopologyLayout(state))}>
          <LayoutGrid className="h-3.5 w-3.5" />{t("scan.correlation.topology.resetLayout")}
        </Button>
        <span className="ml-auto flex min-w-0 items-center gap-1 text-[11px] text-muted-foreground">
          <Info className="h-3.5 w-3.5 flex-shrink-0" aria-hidden />
          <span className="truncate" title={t("scan.correlation.topology.canvasHint")}>
            {t("scan.correlation.topology.canvasHint")}
          </span>
        </span>
      </div>
      <div className="grid gap-3 xl:grid-cols-[minmax(0,1fr)_300px]">
        <div className="relative">
        <svg ref={svgRef} viewBox={`0 0 ${CANVAS_W} ${CANVAS_H}`} data-testid="topology-canvas"
          className={`h-[420px] w-full touch-none rounded-lg border border-border bg-card xl:h-[540px] ${panning ? "cursor-grabbing" : "cursor-grab"}`}
          onPointerDown={(event) => {
            // 三种手势按落点分流：节点（data-node）拖节点、边（line）选边、手柄随节点——
            // 其余落点（背景/点阵）开画布平移。
            if ((event.target as Element).closest("[data-node], line")) return;
            const vp = viewportPointOf(svgRef.current, event.clientX, event.clientY);
            panRef.current = { vx: vp.x, vy: vp.y, origin: view };
            setPanning(true);
          }}
          onPointerMove={(event) => {
            if (connectFrom) { setConnectPos(rawPoint(event)); return; }
            if (dragRepo.current) {
              dragMoved.current = true;
              const p = nodePoint(event);
              onState(moveTopologyNode(state, dragRepo.current, p.x, p.y));
              return;
            }
            const pan = panRef.current;
            if (pan) {
              const vp = viewportPointOf(svgRef.current, event.clientX, event.clientY);
              setView({ ...pan.origin, x: pan.origin.x + (vp.x - pan.vx), y: pan.origin.y + (vp.y - pan.vy) });
            }
          }}
          onPointerUp={() => { dragRepo.current = null; cancelConnect(); panRef.current = null; setPanning(false); }}
          onPointerLeave={() => { dragRepo.current = null; cancelConnect(); panRef.current = null; setPanning(false); }}>
          <defs>
            <marker id="topology-arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
              <path d="M0,0 L8,4 L0,8 z" className="fill-muted-foreground" />
            </marker>
            {/* 画布点阵：自由拖放工作台语义（对齐设计工具画布语言），token 派生全主题适配。
                alpha 0.32 为五主题抽查定值：暗色/亮暗色底（charcoal/gruvbox）0.2x 档不可见。 */}
            <pattern id="topology-dots" width="26" height="26" patternUnits="userSpaceOnUse">
              <circle cx="1.2" cy="1.2" r="1.2" fill="hsl(var(--muted-foreground) / 0.32)" />
            </pattern>
          </defs>
          {/* 视口组：世界坐标内容（节点位置不变）整体 translate+scale。
              点阵铺到远超 800×600 的世界范围——平移/缩小后露出的画布区仍是点阵。 */}
          <g data-testid="topology-viewport" transform={`translate(${view.x} ${view.y}) scale(${view.k})`}>
          <rect x={-1600} y={-1200} width={CANVAS_W + 3200} height={CANVAS_H + 2400}
            fill="transparent" data-testid="topology-canvas-bg" />
          <rect x={-1600} y={-1200} width={CANVAS_W + 3200} height={CANVAS_H + 2400}
            fill="url(#topology-dots)" aria-hidden className="pointer-events-none" />
          {state.draft.edges.map((edge) => {
            const from = nodeByRepo.get(edge.from); const to = nodeByRepo.get(edge.to);
            if (!from || !to) return null;
            // 端点按节点相对位置选面向侧（anchorPair）：自由拖放后连线不再横穿节点本体
            const anchors = anchorPair(boxOf(from), boxOf(to));
            // 命中区：可见细线 1.5px × 缩放 k（0.3 时 ≈0.3 屏幕像素）真实浏览器点不中，
            // 垫一条 14px 透明实线兜住命中（TopologyGraph 同款手法；disabled 边的虚线
            // 间隙 visiblePainted 不响应指针，也由它兜住）。命中线在前 = 垫在可见线下层。
            const tid = edge.id.replace(/[^A-Za-z0-9_-]/g, "_");
            return (
              <g key={edge.id} className="cursor-pointer" tabIndex={0} role="button"
                aria-label={`${edge.from} ${edge.protocol} ${edge.to}`}
                onPointerDown={() => { setSelectedEdgeId(edge.id); setSelectedNodeRepo(null); }}
                onClick={() => { setSelectedEdgeId(edge.id); setSelectedNodeRepo(null); }}
                onKeyDown={(e) => { if (e.key === "Enter") { setSelectedEdgeId(edge.id); setSelectedNodeRepo(null); } }}>
                <title>{`${edge.from} → ${edge.to} · ${edge.protocol}`}</title>
                <line data-testid={`topology-edge-hit-${tid}`}
                  x1={anchors.from.x} y1={anchors.from.y} x2={anchors.to.x} y2={anchors.to.y}
                  stroke="transparent" strokeWidth={14} />
                <line data-testid={`topology-edge-${tid}`}
                  x1={anchors.from.x} y1={anchors.from.y} x2={anchors.to.x} y2={anchors.to.y}
                  className={edge.enabled ? (selectedEdgeId === edge.id ? "stroke-primary" : "stroke-muted-foreground") : "stroke-border"}
                  strokeWidth={selectedEdgeId === edge.id ? 2.5 : 1.5} strokeDasharray={edge.enabled ? undefined : "4 4"}
                  markerEnd="url(#topology-arrow)" pointerEvents="none" />
              </g>
            );
          })}
          {/* 连线预览：从起点手柄到当前鼠标的虚线，拖线全程可见 */}
          {connectFromNode && connectPos && (
            <line data-testid="topology-connect-preview"
              x1={connectFromNode.position.x + NODE_W} y1={connectFromNode.position.y + NODE_H / 2}
              x2={connectPos.x} y2={connectPos.y}
              className="stroke-primary/70" strokeWidth={1.5} strokeDasharray="5 4" pointerEvents="none" />
          )}
          {state.draft.nodes.map((node) => {
            const nodeSelected = selectedNodeRepo === node.repo;
            return (
            <g key={node.repo} data-testid={`topology-node-${node.repo}`} data-node={node.repo}
              className="cursor-move" tabIndex={0} role="group"
              aria-label={`${node.repo} ${node.roles.join(", ")}`}
              onPointerDown={() => { dragRepo.current = node.repo; dragMoved.current = false; }}
              onPointerUp={() => {
                // 拖线式成边：按住起点手柄拖到目标节点上松手（自身松手 = 取消选中态重置）
                if (connectFrom && connectFrom !== node.repo) {
                  onState(addTopologyEdge(state, { from: connectFrom, to: node.repo, protocol: "grpc" }));
                }
                // 点击（非拖动布局）→ 选中节点，右栏切节点属性模式（与选中边互斥）
                if (!dragMoved.current && !connectFrom) {
                  setSelectedNodeRepo(node.repo);
                  setSelectedEdgeId(null);
                }
                cancelConnect();
                dragRepo.current = null;
              }}
              onKeyDown={(e) => {
                if (e.key === "Enter") { setSelectedNodeRepo(node.repo); setSelectedEdgeId(null); }
              }}>
              <title>{node.repo}</title>
              <rect x={node.position.x} y={node.position.y} width={NODE_W} height={NODE_H} rx={8}
                className={nodeSelected
                  ? "fill-secondary stroke-primary"
                  : "fill-secondary stroke-border hover:stroke-primary/60"}
                strokeWidth={nodeSelected ? 2 : 1} />
              {/* 入口身份条：coral 左缘竖条（与 GroupLabel eyebrow 同语言——「入口」全站归 primary） */}
              {node.roles.includes("entrypoint") && (
                <rect x={node.position.x} y={node.position.y} width={3} height={NODE_H} rx={1.5} className="fill-primary" />
              )}
              <text x={node.position.x + 10} y={node.position.y + 20} className="fill-foreground font-mono text-[11px]">
                {node.repo.length > NAME_MAX ? `${node.repo.slice(0, NAME_MAX - 1)}…` : node.repo}
              </text>
              <text x={node.position.x + 10} y={node.position.y + 37} className="fill-muted-foreground text-[10px]">{node.roles.join(" · ") || "—"}</text>
              {/* 连接柄：环+点（可拉出连线的「手柄」形态，悬停原生 tooltip 补操作说明） */}
              <circle cx={node.position.x + NODE_W + 7} cy={node.position.y + NODE_H / 2} r={6.5}
                className={connectFrom === node.repo ? "fill-primary/20 stroke-primary" : "fill-none stroke-primary/45"}
                aria-label={`${t("scan.correlation.topology.connect")} ${node.repo}`} role="button" tabIndex={0}
                onPointerDown={(e) => {
                  e.stopPropagation();
                  if (connectFrom === node.repo) { cancelConnect(); return; }
                  setConnectFrom(node.repo);
                  setConnectPos({ x: node.position.x + NODE_W + 7, y: node.position.y + NODE_H / 2 });
                }}>
                <title>{t("scan.correlation.topology.connectHandle")}</title>
              </circle>
              <circle cx={node.position.x + NODE_W + 7} cy={node.position.y + NODE_H / 2} r={2.5} className="fill-primary pointer-events-none" />
            </g>
            );
          })}
          </g>
        </svg>
        {/* 缩放条（画布右下角，工具画布通用语言）：−/＋ 以画布中心步进；百分比即
            缩放读数、点击回 100%；fit 按节点包围盒适配。溢出当前视口时 fit 亮
            primary 圆点——「图已出界，一键找回全局」的导航信号，非装饰。 */}
        <div className="absolute bottom-2 right-2 flex items-center rounded-md border border-border bg-card/90 p-0.5 shadow-sm backdrop-blur-[2px]">
          <Button type="button" variant="ghost" size="icon-sm" aria-label={t("scan.correlation.topology.zoomOut")}
            title={t("scan.correlation.topology.zoomOut")}
            onClick={() => setView((v) => zoomAtPoint(v, { x: CANVAS_W / 2, y: CANVAS_H / 2 }, 1 / ZOOM_STEP))}>
            <Minus className="h-3.5 w-3.5" />
          </Button>
          <Button type="button" variant="ghost" size="icon-sm" className="w-10 font-mono text-[11px] tabular-nums"
            aria-label={t("scan.correlation.topology.zoomReset")}
            title={t("scan.correlation.topology.zoomReset")}
            onClick={() => setView({ x: 0, y: 0, k: 1 })}>
            {Math.round(view.k * 100)}%
          </Button>
          <Button type="button" variant="ghost" size="icon-sm" aria-label={t("scan.correlation.topology.zoomIn")}
            title={t("scan.correlation.topology.zoomIn")}
            onClick={() => setView((v) => zoomAtPoint(v, { x: CANVAS_W / 2, y: CANVAS_H / 2 }, ZOOM_STEP))}>
            <Plus className="h-3.5 w-3.5" />
          </Button>
          <div className="mx-0.5 h-4 w-px bg-border" aria-hidden />
          <Button type="button" variant="ghost" size="icon-sm" className="relative" aria-label={t("scan.correlation.topology.zoomFit")}
            title={t("scan.correlation.topology.zoomFit")}
            onClick={() => setView(fitTransform(state.draft.nodes))}>
            <Maximize className={`h-3.5 w-3.5 ${needsFit ? "text-primary" : ""}`} />
            {needsFit && <span data-testid="topology-fit-dot" className="absolute right-0.5 top-0.5 h-1.5 w-1.5 rounded-full bg-primary" aria-hidden />}
          </Button>
        </div>
        </div>
        {/* 右栏属性面板（双模式）：选中边=边属性+证据（现状）；选中节点=节点属性
            （2026-09-04 撤 TopologyTables 并轨——角色/来源/移除的唯一编辑入口）；
            与画布等高内部滚动。 */}
        <aside className="space-y-3 rounded-lg border border-border bg-card p-3 xl:max-h-[540px] xl:overflow-y-auto" aria-label={t("scan.correlation.topology.details")}>
          {selectedNode ? (
            <NodePanel node={selectedNode} state={state} onState={onState} scans={scans} onRemove={onRemoveNode} />
          ) : selectedEdge ? (
            <div className="space-y-3 text-xs">
              {/* 叙述句：数据里已有的语义字段拼成人话（谁通过什么调谁），代替裸 from→to + 散落小字 */}
              <div className="space-y-1">
                <div className="text-sm font-semibold leading-snug">
                  {t("scan.correlation.topology.edgeCall", {
                    from: selectedEdge.from, protocol: selectedEdge.protocol, to: selectedEdge.to,
                  })}
                </div>
                <div className="flex flex-wrap items-center gap-2 text-muted-foreground">
                  <span data-testid="topology-edge-confidence"
                    className={`rounded border px-1.5 py-0.5 text-[10px] font-medium ${confidenceClass(selectedEdge.confidence ?? "")}`}>
                    {selectedEdge.confidence ?? t("scan.correlation.topology.manualEdge")}
                  </span>
                  {(selectedEdge.service || selectedEdge.method) && (
                    <span className="font-mono text-[11px]">
                      {[selectedEdge.service, selectedEdge.method].filter(Boolean).join(".")}
                    </span>
                  )}
                </div>
              </div>
              <label className="block space-y-1">
                <span className="text-muted-foreground">{t("scan.correlation.protocolLabel")}</span>
                <Select value={selectedEdge.protocol}
                  onValueChange={(v) => onState(updateTopologyEdge(state, selectedEdge.id, { protocol: v as never }))}>
                  <SelectTrigger className="h-8 w-full text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {["grpc", "http", "graphql"].map((p) => <SelectItem key={p} value={p}>{p}</SelectItem>)}
                  </SelectContent>
                </Select>
              </label>
              <label className="flex items-center gap-2">
                <Checkbox checked={selectedEdge.enabled}
                  onCheckedChange={(v) => onState(setTopologyEdgeEnabled(state, selectedEdge.id, v === true))} />
                {t("scan.correlation.topology.enabled")}
              </label>
              <Button type="button" variant="outline" size="sm" onClick={() => onState(deleteTopologyEdge(state, selectedEdge.id))}>
                {t("scan.correlation.topology.deleteEdge")}
              </Button>
              {/* 证据双端分组：⇢ 调用方（from 仓发起）/ ⇠ 接收方（to 仓处理）——
                  双端对得上才可信，缺哪端一眼可见 */}
              <div className="space-y-2 border-t border-border pt-2">
                <EdgeEvidenceGroup dir="client" label={t("scan.correlation.topology.clientEvidence")}
                  repo={selectedEdge.from} evidence={selectedEdge.client_evidence ?? []}
                  emptyText={t("scan.correlation.topology.noClientEvidence")} />
                <EdgeEvidenceGroup dir="handler" label={t("scan.correlation.topology.handlerEvidence")}
                  repo={selectedEdge.to} evidence={selectedEdge.handler_evidence ?? []}
                  emptyText={t("scan.correlation.topology.noHandlerEvidence")} />
              </div>
            </div>
          ) : <p className="text-xs text-muted-foreground">{t("scan.correlation.topology.selectHint")}</p>}
          <div className="space-y-1 border-t border-border pt-2 text-[11px] text-muted-foreground">
            {state.draft.nodes.flatMap((node) => (node.capabilities ?? []).flatMap((capability) =>
              capability.evidence.map((ev, index) => (
                <div key={`${node.repo}-${capability.role}-${ev.file}-${index}`}>
                  {capability.role} ({capability.confidence}) {node.repo}/{ev.file}:{ev.line ?? "?"} — {ev.snippet}
                  {ev.valid === false ? ` · invalid: ${ev.validation_errors?.join(", ")}` : ""}
                </div>
              ))
            ))}
            {removedAiEdges.length > 0 && (
              <div className="space-y-2 border-t border-border pt-2">
                <div className="text-xs font-semibold">{t("scan.correlation.topology.removedAi")}</div>
                {removedAiEdges.map((edge) => (
                  <div key={`${edge.from}-${edge.to}-${edge.protocol}`} className="space-y-1">
                    <div className="font-mono">{edge.from} → {edge.to} ({edge.protocol})</div>
                    <div className="text-muted-foreground">
                      {edge.confidence ?? "unknown"}
                      {edge.service ? ` · ${edge.service}` : ""}
                      {edge.method ? ` · ${edge.method}` : ""}
                    </div>
                    {[...(edge.client_evidence ?? []), ...(edge.handler_evidence ?? [])].map((ev, i) => (
                      <div key={`${edge.from}-${edge.to}-${ev.file}-${i}`}>
                        {ev.repo}/{ev.file}:{ev.line ?? "?"} — {ev.snippet}
                        {ev.valid === false ? ` · invalid: ${ev.validation_errors?.join(", ")}` : ""}
                      </div>
                    ))}
                    <Button type="button" variant="outline" size="sm"
                      onClick={() => onState(restoreTopologyAiEdge(state, edge))}>
                      {t("scan.correlation.topology.restore")}
                    </Button>
                  </div>
                ))}
              </div>
            )}
            {state.draft.coverage.map((c) => <div key={c.repo}>{c.repo}: {c.complete ? "✓" : "○"} {c.reason}</div>)}
            {state.draft.uncertain.map((u, i) => <div key={`${u.repo}-${i}`}>? {u.repo}: {u.message}{u.protocol_hint ? ` (${u.protocol_hint})` : ""}</div>)}
          </div>
        </aside>
      </div>
      {/* isolated_node 是非阻塞警告（2026-09-20 降级）：amber 提示可保留扫描，其余仍为错误红。 */}
      {validateTopologyDraft(state.draft).map((issue) => (
        <p key={issue.code + issue.message} role="alert"
          className={`text-xs ${issue.code === "isolated_node" ? "text-amber" : "text-destructive"}`}>
          {t(`scan.correlation.issues.${issue.code}`, { defaultValue: issue.message })}
        </p>
      ))}
    </section>
  );
}
