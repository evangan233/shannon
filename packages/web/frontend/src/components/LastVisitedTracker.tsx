import { useEffect, useRef } from "react";
import { useLocation } from "react-router-dom";
import { setLastVisitedWorkspace } from "@/api/client";

/**
 * per-user 最近访问工作区上报（2026-09-11 置顶→最近访问替换）：路径命中 /p/:ws
 * 时 fire-and-forget PUT。挂 AppShell 而非 WorkspaceDetail——scan 深页
 * （/p/:ws/scans/:id）挂的是 ScanDetail、不经过 WorkspaceDetail，放后者会漏记。
 * 同 ws 去重（内存记住上次上报值，ws 内导航不重复 PUT）；失败静默
 * （记录是「工作区」入口跳转的优化，不是关键路径）。
 */
export function LastVisitedTracker() {
  const { pathname } = useLocation();
  const reportedRef = useRef<string | null>(null);

  useEffect(() => {
    const m = pathname.match(/^\/p\/([^/]+)/);
    const ws = m?.[1];
    if (!ws || ws === reportedRef.current) return;
    reportedRef.current = ws;
    setLastVisitedWorkspace(ws).catch(() => {
      /* 静默：上报失败不影响导航；下次进 ws 自然重试 */
    });
  }, [pathname]);

  return null;
}
