// 剪枝树 React Flow 自定义节点（spec 2026-08-20 §5 视觉语言 1:1 迁移，HTML 盒版）。
// 锚点契约（测试与联动依赖，全部保留）：data-source/data-node(=step，source 为 0)/
// data-branch/data-branch-id/data-hovered/data-selected/data-scissors/data-remnant/
// data-pubfunc/data-storage-relay/data-sink-target/data-sink-label/data-sink-noinput/
// data-collapsed-safe。tooltip 用 HTML title 属性（等价旧 SVG <title>）。
// 盒尺寸由 layout 纯函数定死（style 写在 FlowCanvas 适配层）——本组件只管内容排版。
import { useTranslation } from "react-i18next";
import type { Node, NodeProps } from "@xyflow/react";
import { useBranchEvents } from "./events";
import type { FoldNodeData, SinkNodeData, SourceNodeData, StepNodeData } from "./types";

/** verdict → SVG/CSS path class（打通红 / 剪断绿 / 未判定橙）。 */
export function branchClass(verdict: SourceNodeData["verdict"]): string {
  if (verdict === "vulnerable") return "branch-vuln";
  if (verdict === "safe") return "branch-safe";
  return "branch-unknown";
}

function verdictShort(
  verdict: SourceNodeData["verdict"],
  t: ReturnType<typeof useTranslation>["t"],
): string {
  if (verdict === "vulnerable") return t("workspaceDetail.dataflow.branchShortVuln");
  if (verdict === "safe") return t("workspaceDetail.dataflow.branchShortSafe");
  return t("workspaceDetail.dataflow.branchShortUnknown");
}

/** 联动态属性（data-hovered/data-selected——存在性驱动 CSS）。 */
function hlAttrs(hovered: boolean, selected: boolean) {
  return {
    "data-hovered": hovered ? "" : undefined,
    "data-selected": selected ? "" : undefined,
  };
}

/** source 青色 pill（step 0，列对齐首列）。键盘可达宿主：role=button + Enter/Space 选中。 */
export function SourceNode({ data }: NodeProps<Node<SourceNodeData, "source">>) {
  const { t } = useTranslation();
  const { onHover, onSelect } = useBranchEvents();
  const d = data;
  // tooltip（旧 SourcePill 口径，labelCut 不复存在——HTML 自动换行）：
  // note 叙事原句 > 存储白话 > 跨树提示 拼接；全无 → label · type · entry 兜底
  const parts: string[] = [];
  if (d.note) parts.push(d.note);
  if (d.isStorage) parts.push(t("workspaceDetail.dataflow.storageRelayFull"));
  if (d.crossTreeSinks) {
    parts.push(t("workspaceDetail.dataflow.crossTreeTooltip", { sinks: d.crossTreeSinks }));
  }
  const tooltip = parts.length > 0 ? parts.join(" ｜ ") : `${d.label}${d.metaText ? ` · ${d.metaText}` : ""}`;
  return (
    <div
      className={`prune-node prune-source ${d.hovered ? "hovered" : ""} ${d.selected ? "selected" : ""}`}
      data-source=""
      data-node="0"
      data-branch={d.verdict}
      data-branch-id={d.branchId ?? undefined}
      {...hlAttrs(d.hovered, d.selected)}
      title={tooltip}
      role="button"
      tabIndex={d.branchId ? 0 : undefined}
      aria-label={
        d.branchId
          ? t("workspaceDetail.dataflow.branchAria", {
              source: d.label,
              sink: d.sinkLabel,
              verdict: verdictShort(d.verdict, t),
            })
          : undefined
      }
      onMouseEnter={() => onHover(d.branchId)}
      onMouseLeave={() => onHover(null)}
      onClick={() => d.branchId && onSelect(d.branchId)}
      onKeyDown={(e) => {
        if (!d.branchId) return;
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onSelect(d.branchId);
        }
      }}
    >
      <span className="prune-source-txt" data-source-label="">
        {d.label}
      </span>
      {d.metaText && !d.isStorage && (
        <span className="prune-source-meta" data-source-meta="">
          {d.metaText}
        </span>
      )}
      {d.isStorage && (
        <span className="prune-storage-relay" data-storage-relay="">
          {t("workspaceDetail.dataflow.storageRelayMark")}
        </span>
      )}
    </div>
  );
}

/** 中间传播节点：圆点（verdict 配色）+ 盾环（黄=绕过/绿=有效，绕圆点）+ 函数名（自动换行）
 *  + 公共函数下标 + 剪断点 ✂ + 渐隐残端装饰（盒右缘外挂，不参与布局）。 */
export function StepNode({ data }: NodeProps<Node<StepNodeData, "step">>) {
  const { t } = useTranslation();
  const d = data;
  const dotCls = `prune-dot ${d.isVuln ? "prune-dot-vuln" : d.isCut ? "prune-dot-safe" : ""} ${
    d.shield === "yellow"
      ? "prune-shield-yellow"
      : d.shield === "green"
        ? "prune-shield-green"
        : ""
  }`;
  // tooltip：note 叙事原句优先 + 公共函数剪断枝说明（旧 NodeView 口径）
  const pubTip =
    d.pub && d.pub.count > 1
      ? d.pub.cutBranches.length > 0
        ? t("workspaceDetail.dataflow.pubFuncTooltip", {
            count: d.pub.count,
            cut: d.pub.cutBranches.join(", "),
          })
        : t("workspaceDetail.dataflow.pubFuncTooltipNone", { count: d.pub.count })
      : null;
  const tooltip = [d.node.note, pubTip].filter(Boolean).join(" ｜ ") || undefined;
  return (
    <div
      className={`prune-node ${d.isVuln ? "prune-node-vuln" : d.isCut ? "prune-node-safe" : ""} ${d.hovered ? "hovered" : ""} ${d.selected ? "selected" : ""}`}
      data-node={d.step}
      data-branch-id={d.branchId ?? undefined}
      {...hlAttrs(d.hovered, d.selected)}
      title={tooltip}
    >
      <span className="prune-dot-wrap">
        <span className={dotCls} />
        {d.isCut && (
          <span className="prune-scissors" data-scissors="">
            ✂
          </span>
        )}
      </span>
      <span className="prune-label" data-node-label="">
        {d.fullLabel}
      </span>
      {d.pub && d.pub.count > 1 && (
        <span className="prune-pubfunc" data-pubfunc="">
          {t("workspaceDetail.dataflow.pubFuncSub", { count: d.pub.count })}
        </span>
      )}
      {/* 剪断残端：向 sink 方向渐隐虚线（不到 sink）；盒外右挂 40px 列隙内，不占布局 */}
      {d.isCut && (
        <svg className="prune-remnant" data-remnant="" width="40" height="12" aria-hidden>
          <path className="branch-remnant" d="M 0 6 H 40" />
        </svg>
      )}
    </div>
  );
}

/** sink 靶心：内嵌 SVG 直接复用旧类（sink-pulse 脉动 / sink-idle 灰虚线 + sink-label）。 */
export function SinkNode({ data }: NodeProps<Node<SinkNodeData, "sink">>) {
  const { t } = useTranslation();
  const d = data;
  const noInputTip = d.hasVuln ? null : t("workspaceDetail.dataflow.sinkNoInput");
  const tooltip = [d.note ?? d.label, noInputTip].filter(Boolean).join(" · ");
  const ringCls = d.hasVuln ? "sink-pulse" : "sink-idle";
  const labelY = 48;
  const svgH = labelY + (d.lines.length - 1) * 12 + (noInputTip ? 18 : 10);
  return (
    <div className="prune-node prune-sink" data-sink-target={d.hasVuln ? "vuln" : "safe"} title={tooltip}>
      <svg width="160" height={svgH} viewBox={`0 0 160 ${svgH}`} aria-hidden>
        <circle cx="80" cy="22" r="16" className={ringCls} />
        <circle
          cx="80"
          cy="22"
          r="6"
          fill={d.hasVuln ? "hsl(var(--c-red))" : "hsl(var(--muted-foreground))"}
          opacity={d.hasVuln ? 0.8 : 0.4}
        />
        <text x="80" y={labelY} className="sink-label" textAnchor="middle" data-sink-label="">
          {d.lines.map((l, i) => (
            <tspan key={i} x="80" dy={i === 0 ? 0 : 12}>
              {l}
            </tspan>
          ))}
        </text>
        {noInputTip && (
          <text x="80" y={labelY + d.lines.length * 12 + 2} className="sink-noinput-txt" textAnchor="middle" data-sink-noinput="">
            {noInputTip}
          </text>
        )}
      </svg>
    </div>
  );
}

/** 折叠行：「+N 条枝被剪断」⇄「收起」（点击/键盘切换）；hover 被折叠枝明细行 → 高亮。 */
export function FoldNode({ data }: NodeProps<Node<FoldNodeData, "fold">>) {
  const { t } = useTranslation();
  const { onFoldToggle } = useBranchEvents();
  const d = data;
  return (
    <div
      className="prune-node prune-fold"
      data-collapsed-safe=""
      data-hovered={d.highlighted ? "" : undefined}
      role="button"
      tabIndex={0}
      aria-label={t("workspaceDetail.dataflow.foldedSafeExpandHint")}
      title={t("workspaceDetail.dataflow.foldedSafeExpandHint")}
      onClick={onFoldToggle}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onFoldToggle();
        }
      }}
    >
      <svg className="prune-fold-line" width="204" height="28" viewBox="0 0 204 28" aria-hidden>
        <path className="folded-safe" d="M 0 14 H 204" />
      </svg>
      <span className={`prune-fold-txt ${d.highlighted ? "hovered" : ""}`}>
        {d.expanded
          ? t("workspaceDetail.dataflow.foldedSafeCollapse", { count: d.hiddenCount })
          : t("workspaceDetail.dataflow.foldedSafe", { count: d.hiddenCount })}
      </span>
    </div>
  );
}

/** 模块级 nodeTypes（React Flow 反模式规避：每次 render 新建对象触发警告）。 */
export const NODE_TYPES = {
  source: SourceNode,
  step: StepNode,
  sink: SinkNode,
  fold: FoldNode,
} as const;
