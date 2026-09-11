import { Suspense, useEffect, useState } from "react";
import { Outlet } from "react-router-dom";
import { TopBar } from "./TopBar";
import { ChangePasswordDialog } from "@/components/ChangePasswordDialog";
import { LastVisitedTracker } from "@/components/LastVisitedTracker";
import { Skeleton } from "@/components/ui/skeleton";
import { useAuth } from "@/auth/AuthContext";

export function AppShell() {
  const { user, refreshUser } = useAuth();
  const [cpOpen, setCpOpen] = useState(false);
  const mustChange = user?.must_change_password === true;

  // 登录后若 must_change_password=true，自动弹一次改密提醒（用户可点「稍后」关闭，
  // 关闭后顶栏 ⚠ badge 仍持续可见，点击可再次打开）。
  useEffect(() => {
    if (mustChange) setCpOpen(true);
  }, [mustChange]);

  return (
    <div className="min-h-screen bg-background text-foreground">
      {/* 最近访问 ws 上报（置顶→最近访问替换 2026-09-11）：全 /p/:ws 子路径（含 scan 深页） */}
      <LastVisitedTracker />
      <TopBar onOpenChangePwd={() => setCpOpen(true)} />
      {/* 满宽控制台布局：max-w-[2400px] 在 ≤2K 屏基本铺满（旧 1400 在宽屏居中留半屏白），
          超宽屏（4K/带鱼）优雅居中。TopBar 内层用同一 max-w + px-7 保持左右边界对齐
          （视觉同一列）。py-5 + TopBar h-12 = 5.5rem 是 live/logs 的 h-[calc(100dvh-5.5rem)]
          依赖，勿改。 */}
      <main className="mx-auto w-full max-w-[2400px] px-7 py-5">
        {/* lazy 路由 chunk 加载期的页面级骨架（spec §B）：高度贴近典型页首屏，避免布局跳动 */}
        <Suspense fallback={<div className="space-y-4"><Skeleton className="h-28 w-full" /><Skeleton className="h-44 w-full" /></div>}>
          <Outlet />
        </Suspense>
      </main>
      {mustChange && (
        <ChangePasswordDialog
          open={cpOpen}
          onOpenChange={setCpOpen}
          onChanged={refreshUser}
        />
      )}
    </div>
  );
}
