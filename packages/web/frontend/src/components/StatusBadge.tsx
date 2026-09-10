import { useTranslation } from "react-i18next";
import {
  CircleCheck, CircleHelp, CirclePause, CircleX, Clock, LoaderCircle, TriangleAlert,
  type LucideIcon,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";

// 状态 → 语义色 tint + lucide 图标。2026-09-10 两轮演进：
// ① 图标语言统一：原 Unicode 字符（●⏸⏳✓✗⚠）+ 跨仓 🔗 emoji 在不同系统字体下
//   大小/基线漂移——跨仓行 🔗 还会撑爆 112px 状态列致文字换行（挤两行）；对齐
//   ReposTab StateBadge 的 lucide + 语义色 token 方案，跨仓类型归属由类型列
//   「跨仓关联」徽标承载（状态列单一职责）。
// ② soft-tint 状态灯（用户要更美观）：outline 平底 → 同色系柔和底（bg-<c>/10）
//   + 全主题胶囊（rounded-full——状态 chip 的形状恒定，主题差异交给 tint/字体），
//   字体去 mono 改 sans font-medium（状态=语义层；类型列 Badge 保持 mono 技术层，
//   形状+字体双重分层）。running 叠 status-breathe 底色呼吸（引擎感，reduce 停），
//   spinner 是全表唯一图标动效。
const TINT = "rounded-full px-2 font-medium";
const MAP: Record<string, { Icon: LucideIcon; cls: string }> = {
  running:      { Icon: LoaderCircle,  cls: "border-cyan/25 bg-cyan/10 text-cyan status-breathe" },
  "in-progress":{ Icon: LoaderCircle,  cls: "border-cyan/25 bg-cyan/10 text-cyan" },
  interrupted:  { Icon: CirclePause,   cls: "border-yellow/25 bg-yellow/10 text-yellow" },
  queued:       { Icon: Clock,         cls: "border-yellow/25 bg-yellow/10 text-yellow" },
  completed:    { Icon: CircleCheck,   cls: "border-green/25 bg-green/10 text-green" },
  done:         { Icon: CircleCheck,   cls: "border-green/25 bg-green/10 text-green" },
  failed:       { Icon: CircleX,       cls: "border-red/25 bg-red/10 text-red" },
  killed:       { Icon: CircleX,       cls: "border-red/25 bg-red/10 text-red" },
  crashed:      { Icon: TriangleAlert, cls: "border-yellow/25 bg-yellow/10 text-yellow" },
};

export function StatusBadge({ status }: { status: string }) {
  const { t, i18n: i18nInst } = useTranslation();
  const m = MAP[status] ?? { Icon: CircleHelp, cls: "border-yellow/25 bg-yellow/10 text-yellow" };
  // 未知状态 fallback 渲染原值(防后端新增枚举显示空白)
  const key = `workspaces.status.${status}`;
  const label = i18nInst.exists(key) ? t(key) : status;
  const running = status === "running";
  return (
    <Badge variant="outline" className={`gap-1.5 whitespace-nowrap ${TINT} ${m.cls}`} title={status}>
      <m.Icon
        aria-hidden
        className={`size-3.5 ${running ? "animate-spin motion-reduce:animate-none" : ""}`}
      />
      {label}
    </Badge>
  );
}
