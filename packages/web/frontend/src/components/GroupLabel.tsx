/** 分组小标题：coral 竖条 eyebrow——卡内分组的全站统一视觉语言（Settings Section /
 *  扫描页三种类型共用）。适配中文卡内分组——无 uppercase/tracking-wider，仅 coral
 *  竖条 + 小号 semibold 标签拉层次。
 *  hint（2026-09-09 扫描页质感统一）：标题行右侧注解（MR「分支名或 commit sha 均可」/
 *  白盒「本地审计」「可选」/ 跨仓「可选」）——右贴 11px 常规体灰字，替代各分支各自的
 *  手写 span / 胶囊 tag / 数字徽章，三种扫描类型的分区标题行同构。折叠按钮行内使用时传
 *  className="flex-1" 让 ml-auto 有剩余空间可贴。 */
export function GroupLabel({ children, hint, className }: {
  children: React.ReactNode;
  hint?: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={`flex items-center gap-1.5 ${className ?? ""}`}>
      <span className="h-3 w-[3px] rounded-full bg-primary" aria-hidden />
      <span className="text-[11px] font-semibold text-muted-foreground">{children}</span>
      {hint && (
        <span className="ml-auto pl-2 text-[11px] font-normal text-muted-foreground">{hint}</span>
      )}
    </div>
  );
}
