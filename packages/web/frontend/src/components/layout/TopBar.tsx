import { Link, NavLink, useLocation } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { cn } from "@/lib/utils";
import { ThemeToggle } from "./ThemeToggle";
import { LanguageSwitcher } from "@/components/LanguageSwitcher";
import { BrandMark } from "./BrandMark";
import { UserMenu } from "./UserMenu";
import { useBrand } from "@/brand/BrandContext";
import { useAuth } from "@/auth/AuthContext";

interface NavItem {
  labelKey: string;
  to: string;
  disabled?: boolean;
  end?: boolean;
  testId?: string;
  // to 之外的 active 判定前缀：用于 to 是中转路由、真实页面在别处前缀下的 nav 项。
  activePrefixes?: string[];
  // to 的运行时覆写标记：当前路径命中 /p/:ws 时直达本 ws 首页（跳回所在工作区，
  // 不经 /workspaces-entry 被 last_visited 拉走）。
  followCurrentWs?: boolean;
}

const NAV: NavItem[] = [
  { labelKey: "nav.dashboard", to: "/", end: true },
  // 「工作区」to 是三段跳转中转（/workspaces-entry 渲染 null 即跳走），真实工作区页
  // 在 /p/:ws 前缀下——NavLink 默认匹配只看 to 会永不命中，补 /p/ 前缀判定。
  { labelKey: "nav.workspaces", to: "/workspaces-entry", end: true, activePrefixes: ["/p/"], followCurrentWs: true },
  // P2: 仓库入口已迁入工作区详情页的「仓库」tab，顶级 nav 撤销
  { labelKey: "nav.scan", to: "/scan/new" },
  { labelKey: "nav.settings", to: "/settings" },
];

export function TopBar({ onOpenChangePwd }: { onOpenChangePwd?: () => void } = {}) {
  const { t } = useTranslation();
  const brand = useBrand();
  const { user } = useAuth();
  const { pathname } = useLocation();
  const mustChange = user?.must_change_password === true;
  // nav 统一 4 项（概览/工作区/扫描/设置），所有角色一致——WorkspaceListPage 已下线（spec 2026-07-27）。
  // 「工作区」入口跳回当前工作区（2026-09-10 用户反馈）：点击后 URL 已变 /workspaces-entry、
  // 来源丢失，故渲染时覆写——当前路径命中 /p/:ws 直达本 ws 首页；不在任何 ws 下
  // （Dashboard/设置等）才走三段跳转中转的 last_visited->最近活跃->空态兜底。
  const wsMatch = pathname.match(/^\/p\/([^/]+)/);
  const items: NavItem[] = wsMatch
    ? NAV.map((n) => (n.followCurrentWs ? { ...n, to: `/p/${wsMatch[1]}` } : n))
    : NAV;
  return (
    <header data-testid="topbar" className="sticky top-0 z-40 border-b-2 border-b-[hsl(var(--primary)/0.55)] bg-[hsl(var(--topbar-bg,var(--popover)))] [backdrop-filter:var(--backdrop-float,none)] print:border-transparent print:static">
      <div className="mx-auto flex h-12 w-full max-w-[2400px] items-center gap-6 px-7">
        <Link to="/" className="flex items-center gap-1.5 font-semibold tracking-tight text-base">
          <BrandMark className="h-[1.15em] w-[1.15em] text-foreground" />
          <span>{brand}</span>
        </Link>
        <nav className="flex items-center gap-1" aria-label={t("nav.mainAria")}>
          {items.map((n) =>
            n.disabled ? (
              <span
                key={n.labelKey}
                aria-disabled="true"
                className="topbar-nav-item cursor-not-allowed border-b-2 border-transparent px-3 py-1.5 text-sm text-muted-foreground/50"
              >
                {t(n.labelKey)}
              </span>
            ) : (
              <NavLink key={n.labelKey} to={n.to} end={n.end} className="inline-flex">
                {({ isActive }) => (
                  <span
                    data-testid={n.testId}
                    data-active={isActive || !!n.activePrefixes?.some((p) => pathname.startsWith(p))}
                    className={cn(
                      // topbar-nav-item：主题级导航材质挂钩（mac 分段控件 CSS 消费，
                      // 其他主题无规则、维持下划线范式）
                      "topbar-nav-item border-b-2 px-3 py-1.5 text-sm transition-colors",
                      isActive || !!n.activePrefixes?.some((p) => pathname.startsWith(p))
                        ? "border-primary text-primary"
                        : "border-transparent text-muted-foreground hover:text-foreground"
                    )}
                  >
                    {t(n.labelKey)}
                  </span>
                )}
              </NavLink>
            )
          )}
        </nav>
        <div className="ml-auto flex items-center gap-1">
          {/* 运行中扫描指示器 slot（子项目 5 接 SSE） */}
          {mustChange && (
            <button
              data-testid="must-change-badge"
              onClick={onOpenChangePwd}
              title={t("auth.mustChange.badge")}
              className="flex items-center gap-1 rounded-md border border-amber/50 px-2 py-1 text-xs text-amber hover:bg-amber/10"
            >
              <span aria-hidden>⚠</span>
              <span className="hidden sm:inline">{t("auth.mustChange.badgeShort")}</span>
            </button>
          )}
          <LanguageSwitcher />
          <ThemeToggle />
          <UserMenu />
        </div>
      </div>
    </header>
  );
}
