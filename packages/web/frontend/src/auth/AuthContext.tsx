import { createContext, useContext, useEffect, useState } from "react";
import type { ReactNode } from "react";
import { apiGet, apiPost } from "@/api/client";

export type AuthUser = {
  id: number;
  username: string;
  role: string;
  // 后端默认账号（users.yaml must_change_password: true）seed 时置 true；
  // 登录后前端据此弹改密提醒 + 顶栏 badge。change-password 成功后置 false。
  must_change_password: boolean;
  // per-user 最近访问工作区（2026-09-11 替换原置顶）。null=从未访问。经 /auth/me 返回。
  last_visited_workspace?: string | null;
  // SSO 用户头像（OA userInfo.avatarUrl；浏览器 <img> 直连加载，服务端不代理）
  avatar_url?: string | null;
  // per-user UI 主题（2026-08-28）：跟账号走、跨设备一致。null=从未自配
  //（前端回落 localStorage 首帧缓存 / OS 默认）。经 /auth/me 与 login 响应返回。
  theme?: string | null;
};
export type AuthState = {
  user: AuthUser | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
};

export const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    apiGet<{ user: AuthUser }>("/auth/me", { silent: true })
      .then((r) => setUser(r.user))
      .catch(() => setUser(null))
      .finally(() => setLoading(false));
  }, []);

  async function login(username: string, password: string) {
    // silent: 凭证错误（401）由 LoginPage 表单提示，不触发 onUnauthorized
    // 整页跳转 /login?expired=1--凭证错 ≠ session 过期，跳转会掩盖错误提示，
    // 用户反复输错即表现为「一直跳转 /login?expired=1」循环。
    await apiGet("/auth/csrf", { silent: true });  // 拿 sn-csrf cookie（写操作 csrf header 由 client 自动注入）
    const r = await apiPost<{ user: AuthUser }>("/auth/login", { username, password }, { silent: true });
    setUser(r.user);
  }

  async function logout() {
    // SSO 会话登出：后端返 OA 登出页地址（账密会话为 null）。本地态先清再跳——
    // 即使 OA 侧跳转失败，本地也已登出。
    const r = await apiPost<{ ok: boolean; sso_logout_url?: string | null }>("/auth/logout", {});
    setUser(null);
    if (r.sso_logout_url) window.location.assign(r.sso_logout_url);
  }

  async function refreshUser() {
    // 改密成功后刷新 user（must_change_password -> false，badge/弹窗自动消失）。
    // silent：未登录 401 不触发整页跳转。
    const r = await apiGet<{ user: AuthUser }>("/auth/me", { silent: true });
    setUser(r.user);
  }

  return <AuthContext.Provider value={{ user, loading, login, logout, refreshUser }}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const v = useContext(AuthContext);
  if (!v) throw new Error("useAuth 必须在 AuthProvider 内使用");
  return v;
}
