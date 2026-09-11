import { useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "@/auth/AuthContext";
import { useWorkspaces } from "@/api/useWorkspaces";

/**
 * 顶栏「工作区」入口的三段跳转（2026-09-11 置顶→最近访问替换）：
 * 1) last_visited 存在且 ∈ 归属列表 -> /p/:last_visited（ws 可能已被删/被移出，
 *    不校验会跳 404，故必须命中列表才跳）
 * 2) 未访问过（或已失效）但有归属 ws -> /p/:最近活跃 ws（latest_created_at 倒序首项）
 * 3) 无归属 ws -> / （Dashboard 自带空态）
 *
 * loading 期间不跳转（等 useWorkspaces 首次拉取完成避免误判空态）。
 */
export function WorkspacesEntry() {
  const { user } = useAuth();
  const { data, loading } = useWorkspaces();
  const nav = useNavigate();

  useEffect(() => {
    if (loading) return;
    const lastVisited = user?.last_visited_workspace;
    if (lastVisited && data.some((w) => w.name === lastVisited)) {
      nav(`/p/${lastVisited}`, { replace: true });
      return;
    }
    if (data.length > 0) {
      const recent = [...data].sort(
        (a, b) => (b.latest_created_at ?? b.created_at) - (a.latest_created_at ?? a.created_at),
      )[0];
      nav(`/p/${recent.name}`, { replace: true });
      return;
    }
    nav("/", { replace: true });
  }, [user?.last_visited_workspace, data, loading, nav]);

  return null;
}
