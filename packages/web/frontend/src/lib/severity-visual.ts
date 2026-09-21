/** severity 视觉语言单源（spec 2026-08-27 警报语义层 §2.2-§2.4）。
 *
 * 四通道分层（一个维度一个通道，近单色主题上色相弱、形状/线型等强）：
 * - hue 通道：SEV_PILL（红/橙/黄，回归锚——与既有 md/report 路径同值）；
 * - 形状通道：SEV_DOT（填充比例 ○/◑/◕/●，色经 currentColor 继承 pill 文本色）；
 * - 线型通道：SEV_EDGE（Medium 虚线 / Low 点线，Critical/High 实线）；
 * - 归一：SEV_CAP（小写 severity → 展示档位，供 report_data 键消费方）。
 *
 * 消费方：report/VulnerabilityCard、report/StatsRow、report/QuickReferenceTable、
 * MarkdownView（md 降级路径）。此前四处各持本地副本（两套键形），2026-08-27 收敛单源。 */

/** report_data.severity（小写）→ 展示档位。 */
export const SEV_CAP: Record<string, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};

/** severity → 药丸配色（tint 底=hue 通道原色；文本=sev-text-* 文本步，spec §4：
 *  同 hue 两步分离保证全主题 AA——原 text-red 直用在药丸/卡面实测 3.1-4.4:1）。 */
export const SEV_PILL: Record<string, string> = {
  Critical: "bg-red/15 sev-text-red",
  High: "bg-orange/15 sev-text-orange",
  Medium: "bg-yellow/15 sev-text-yellow",
  Low: "bg-muted text-muted-foreground",
};

/** severity → 填充比例 dot（形状通道；基类 .sev-dot 由 tokens.css 供尺寸/圆度）。
 *  Low ○ 空环 / Medium ◑ 半填充 / High ◕ 3/4 / Critical ● 满填充。 */
export const SEV_DOT: Record<string, string> = {
  Critical: "sev-dot-critical",
  High: "sev-dot-high",
  Medium: "sev-dot-medium",
  Low: "sev-dot-low",
};

/** severity → 卡左缘色规（hue+线型双通道）：Critical/High 实线、Medium 虚线、Low 点线。
 *  长列表滚动扫视时左缘即 triage（2026-08-26 标题升主标题配套语言的梯度推广）。 */
export const SEV_EDGE: Record<string, string> = {
  Critical: "border-l-2 border-l-red/70",
  High: "border-l-2 border-l-orange/70",
  Medium: "border-l-2 border-l-yellow/70 [border-left-style:dashed]",
  Low: "border-l-2 border-l-muted-foreground/40 [border-left-style:dotted]",
};

/** 展示档位序（小写键）：统计/排序消费方单源（此前 StatsRow/CorrStatsHeader 各持本地副本）。 */
export const SEV_ORDER = ["critical", "high", "medium", "low"] as const;
export type SevKey = (typeof SEV_ORDER)[number];
