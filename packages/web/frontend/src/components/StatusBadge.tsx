import { useTranslation } from "react-i18next";
import { Badge } from "@/components/ui/badge";

const MAP: Record<string, { icon: string; cls: string }> = {
  running:      { icon: "●", cls: "border-cyan/40 text-cyan" },
  "in-progress":{ icon: "●", cls: "border-cyan/40 text-cyan" },
  interrupted:  { icon: "⏸", cls: "border-yellow/40 text-yellow" },
  queued:       { icon: "⏳", cls: "border-yellow/40 text-yellow" },
  completed: { icon: "✓", cls: "border-green/40 text-green" },
  done:      { icon: "✓", cls: "border-green/40 text-green" },
  failed:    { icon: "✗", cls: "border-red/40 text-red" },
  killed:    { icon: "✗", cls: "border-red/40 text-red" },
  crashed:   { icon: "⚠", cls: "border-yellow/40 text-yellow" },
};

export function StatusBadge({ status, correlation = false }: { status: string; correlation?: boolean }) {
  const { t, i18n: i18nInst } = useTranslation();
  const m = MAP[status] ?? { icon: "?", cls: "border-yellow/40 text-yellow" };
  // 未知状态 fallback 渲染原值(防后端新增枚举显示空白)
  const key = `workspaces.status.${status}`;
  const label = i18nInst.exists(key) ? t(key) : status;
  return (
    <Badge variant="outline" className={`gap-1 font-mono ${m.cls}`} title={status}>
      <span aria-hidden>{m.icon}</span>
      {label}
      {correlation ? " 🔗" : ""}
    </Badge>
  );
}
