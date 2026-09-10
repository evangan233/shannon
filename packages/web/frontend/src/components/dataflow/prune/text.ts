// 文本估宽与换行纯函数（prune 布局的地基）。
// 估宽口径沿用旧 PruningTreeFig.textWidthPx（全角 1.0×fontSize / 半角 0.56×fontSize 的
// 手写近似）；区别在用途反转：旧代码用它「截断文字迁就固定网格」，新布局用它「数行数
// 撑高节点盒让网格迁就文字」——估宽偏差被固定尺寸盒 + overflow:hidden 吞掉，不再产生
// 重叠（D1，plan 2026-09-10）。

/** 估算文本显示宽（px）：全角 ch>0xFF 按 fontSize、半角按 0.56×fontSize。 */
export function estimateTextWidthPx(s: string, fontSize: number): number {
  let w = 0;
  for (const ch of s) w += ch.charCodeAt(0) > 0xff ? fontSize : fontSize * 0.56;
  return w;
}

/** wrapLabel 内定字号（节点标签 fontSize=10px，与旧实现一致）。 */
const LABEL_FONT = 10;
/** 省略号估宽（全角一字）。 */
const ELLIPSIS_PX = 10;
/** 恰好压线容差：半角 5.6×5=28.000000000000004 的浮点累进误差不得拒绝第 5 个字符。 */
const EPSILON = 0.01;

/** 贪心装行：返回装入本行的文本与剩余串。 */
function greedyFit(s: string, budgetPx: number): { text: string; rest: string } {
  let w = 0;
  let cut = 0;
  for (const ch of s) {
    const cw = ch.charCodeAt(0) > 0xff ? LABEL_FONT : LABEL_FONT * 0.56;
    if (w + cw > budgetPx + EPSILON) break;
    w += cw;
    cut++;
  }
  return { text: s.slice(0, cut), rest: s.slice(cut) };
}

/**
 * 按像素预算把标签拆成 ≤maxLines 行（纯函数、确定性）：
 * - 单行装得下 → [原文]；
 * - 逐字符贪心装行（行内不超预算）；
 * - 末行先按完整预算满装，装完仍有剩余才按「预算−省略号宽」重装并加「…」
 *   （恰好装满的最后一段内容不被冤枉截断，对齐旧 fitLabelTwoLines 语义）；
 * - 封顶内装完 → 无「…」（内容零丢失，全文另进 <title>）。
 */
export function wrapLabel(s: string, budgetPx: number, maxLines: number): string[] {
  if (estimateTextWidthPx(s, LABEL_FONT) <= budgetPx + EPSILON) return [s];
  const lines: string[] = [];
  let rest = s;
  for (let i = 0; i < maxLines; i++) {
    const isLast = i === maxLines - 1;
    const fit = greedyFit(rest, budgetPx);
    if (!isLast) {
      lines.push(fit.text);
      rest = fit.rest;
      if (!rest) return lines; // 封顶行数未用尽即装完：零丢失，无 …
      continue;
    }
    if (!fit.rest) {
      // 末行恰好装完：零丢失，无 …
      lines.push(fit.text);
      return lines;
    }
    // 末行仍溢出：预留省略号宽重装 + …
    const retry = greedyFit(rest, budgetPx - ELLIPSIS_PX);
    lines.push(retry.text + "…");
    return lines;
  }
  return lines;
}
