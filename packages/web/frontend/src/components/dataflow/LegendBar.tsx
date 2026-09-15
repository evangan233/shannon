// 图例条（spec 2026-08-20 §5「汇总条与图例」：教读图，位于树区上方）。
// 5 类图例项对齐 §5 视觉语言表：打通（红虚线）/ 剪断（绿实线+✂+残端）/ 黄盾=防护被绕过 /
// 绿盾=有效防护（剪断点）/ 靶心（红=有打通枝到达 · 灰虚线=无输入到达，一项双样例）。
// 样例复用 PruningTreeFig 的 tokens.css class（.branch-vuln/.branch-safe/.branch-remnant/
// .node-box-safe/.shield-yellow/.shield-green/.sink-idle）——静态不动画：不带 .flow /
// .sink-pulse 动画组合类，图例只教形状与颜色（红靶心用 Tailwind stroke 直染，避开动画类）。
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";

/** 单个图例项：小 SVG 样例 + 白话文案（i18n zh/en，禁词口径同 spec §5 白话表）。
 *  文案单行 ellipsis（title 全文）——瘦身版不折行。 */
function LegendItem({ kind, sample, text }: { kind: string; sample: ReactNode; text: string }) {
  return (
    <span className="flex shrink-0 items-center gap-1.5" data-legend={kind} title={text}>
      {sample}
      <span className="max-w-56 truncate whitespace-nowrap">{text}</span>
    </span>
  );
}

export function LegendBar() {
  const { t } = useTranslation();
  return (
    <div
      data-testid="dataflow-legend-bar"
      aria-label={t("workspaceDetail.dataflow.legendTitle")}
      /* 瘦身（2026-09-14 信息架构重做）：单行 + 横向滚动（34 树长页里教学条不再占两行屏）；
         项 shrink-0 保持样例+文案不折行，窄屏溢出侧滚。 */
      className="flex items-center gap-x-4 overflow-x-auto rounded-md border border-border bg-card px-3 py-1.5 text-xs text-muted-foreground"
    >
      <span className="font-medium text-foreground">
        {t("workspaceDetail.dataflow.legendTitle")}
      </span>
      {/* 打通枝：红虚线（静态，不带 .flow 流动动画）= 漏洞链路 */}
      <LegendItem
        kind="vuln"
        sample={
          <svg width="44" height="14" viewBox="0 0 44 14" aria-hidden className="shrink-0">
            <path d="M2 7 H42" className="branch-vuln" />
          </svg>
        }
        text={t("workspaceDetail.dataflow.legendVuln")}
      />
      {/* 剪断枝：绿实线至防护节点 + ✂ + 渐隐残端（不到 sink）= 防护拦下 */}
      <LegendItem
        kind="cut"
        sample={
          <svg width="46" height="16" viewBox="0 0 46 16" aria-hidden className="shrink-0">
            <path d="M2 8 H18" className="branch-safe" />
            <circle cx="18" cy="8" r="5" className="node-box-safe" />
            <text x="24" y="12" className="scissors-mark" data-scissors="">
              ✂
            </text>
            <path d="M32 8 H44" className="branch-remnant" />
          </svg>
        }
        text={t("workspaceDetail.dataflow.legendCut")}
      />
      {/* 黄盾：节点级防护存在但被绕过（线继续红） */}
      <LegendItem
        kind="shield-bypass"
        sample={
          <svg width="18" height="18" viewBox="0 0 18 18" aria-hidden className="shrink-0">
            <circle cx="9" cy="9" r="7" className="shield-yellow" />
            <circle cx="9" cy="9" r="3" className="node-box" />
          </svg>
        }
        text={t("workspaceDetail.dataflow.legendShieldBypass")}
      />
      {/* 绿盾：节点级防护有效 = 剪断点（+✂） */}
      <LegendItem
        kind="shield-effective"
        sample={
          <svg width="28" height="18" viewBox="0 0 28 18" aria-hidden className="shrink-0">
            <circle cx="9" cy="9" r="7" className="shield-green" />
            <circle cx="9" cy="9" r="3" className="node-box" />
            <text x="19" y="13" className="scissors-mark" data-scissors="">
              ✂
            </text>
          </svg>
        }
        text={t("workspaceDetail.dataflow.legendShieldEffective")}
      />
      {/* 靶心双态：红实线圆环=有打通枝到达（漏洞）· 灰虚线圆环=无输入到达（safe-only 树）。
          红靶心静态直染（不沿用 .sink-pulse 动画类）；灰沿用 .sink-idle（本就静态）。 */}
      <LegendItem
        kind="target"
        sample={
          <svg width="44" height="18" viewBox="0 0 44 18" aria-hidden className="shrink-0">
            <circle
              cx="10"
              cy="9"
              r="7"
              className="fill-none stroke-[hsl(var(--c-red))] stroke-2"
              data-sample="target-vuln"
            />
            <circle cx="10" cy="9" r="2.5" className="fill-[hsl(var(--c-red))] opacity-80" />
            <circle cx="32" cy="9" r="7" className="sink-idle" data-sample="target-safe" />
            <circle cx="32" cy="9" r="2.5" className="fill-[hsl(var(--muted-foreground))] opacity-40" />
          </svg>
        }
        text={t("workspaceDetail.dataflow.legendTarget")}
      />
      {/* 同一函数弧：青色点线连同名节点（跨枝同一性，不合并节点）——
          每弧文字标注已去（多共享函数时互叠，2026-08-21），语义收进本图例。 */}
      <LegendItem
        kind="sameline"
        sample={
          <svg width="40" height="16" viewBox="0 0 40 16" aria-hidden className="shrink-0">
            <path d="M3 13 Q 13 1, 23 7 T 37 13" className="sameline" fill="none" />
          </svg>
        }
        text={t("workspaceDetail.dataflow.samelineLabel")}
      />
    </div>
  );
}
