import { useMemo } from "react";
import { useTranslation } from "react-i18next";
import { Outlet, useParams, Link, NavLink } from "react-router-dom";
import { ArrowLeft, Settings, FolderGit2, KeyRound, Globe, ScanLine } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { buttonVariants } from "@/components/ui/button";
import { MemberManagerDialog } from "@/components/MemberManagerDialog";
import { WorkspaceSwitcher } from "@/components/WorkspaceSwitcher";
import type { ScanSummary } from "@/api/types";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { fmtCost, currencySymbol } from "@/utils/currency";
import { useScans } from "./useScans";

/** Outlet context：ScanList 操作（取消/删除/scan_end）后联动刷新工作台头聚合。 */
export interface WsOverviewCtx {
  refresh: () => void;
}

/** 指标条/命令栏同款的运行中判定（与 ScanList/Dashboard 口径一致）。 */
const isRunningScan = (s: ScanSummary) => s.is_running || s.status === "running";

/**
 * 区段导航项（命令栏 ‖ 右侧：扫描/仓库/认证/HOST/设置）。单 <a> 直接施加 button 样式
 * （避免 button 嵌套 a 的非法结构）；active 切 secondary 实底——与置顶按钮同一激活语言。
 * NavLink 自带 aria-current="page"；不设 end 时子路由（如 auth-profiles/:pid）下父区段保持高亮。
 */
function SectionLink({
  to,
  end,
  label,
  icon: Icon,
  iconOnly = false,
}: {
  to: string;
  end?: boolean;
  label: string;
  icon: LucideIcon;
  iconOnly?: boolean;
}) {
  return (
    <NavLink
      to={to}
      end={end}
      aria-label={label}
      title={label}
      className={({ isActive }) =>
        buttonVariants({ variant: isActive ? "secondary" : "toolbar", size: iconOnly ? "icon" : undefined })
      }
    >
      <Icon />
      {!iconOnly && label}
    </NavLink>
  );
}

/**
 * 工作区页 = 操作台（重设计 v2，overview-workspace-redesign-preview.html 2026-08-16）：
 * 两行紧凑工作台头（r1 = ws 名 + dot-live + 类型/扫描数徽标 + 命令栏；
 * r2 = 一行 mono 统计摘要：累计发现 + mini 谱带 + 运行中 + 需关注 + 花费 + 最新）
 * 替代原 Hero 大卡 + 四格指标条——态势震撼感让给概览大屏，这里数字只是干活要看的上下文。
 * 主体（过滤器 + 完整扫描表格）在 Outlet 的 ScanList。
 *
 * 头部不显 latest 状态徽标——成功/失败是单项扫描任务的概念（ScanList 逐行可见），
 * 工作区级别不设状态标志。
 * 空工作区（从未扫描）：中性虚线「尚未扫描」徽标 + 引导行（绝不绿色 all-clear）。
 * 聚合数据源 GET /workspaces/{ws}/scans；ScanList 操作经 Outlet context 联动刷新，
 * 运行中时 10s 静默轮询保持徽标/摘要新鲜。
 */
export default function WorkspaceDetail() {
  const { t } = useTranslation();
  const { workspace } = useParams<{ workspace: string }>();
  // SWR 数据层（spec §6.3）：与 ScanList 共享 key（["scans", workspace]）→ 单请求单轮询。
  const { scans, loading, notFound, refresh } = useScans(workspace);
  const hasRunning = scans.some(isRunningScan);

  // 聚合（工作台头 r2）：latest（created_at 倒序首）、运行中、需关注（失败+中断）、
  // 分币种花费（旧口径把 CNY/USD 数值直接相加是错值，分组渲染）、发现构成（mini 谱带）。
  const agg = useMemo(() => {
    const byCreated = [...scans].sort((a, b) => (b.created_at ?? 0) - (a.created_at ?? 0));
    const latest = byCreated[0];
    const running = scans.filter(isRunningScan);
    let failed = 0;
    let interrupted = 0;
    for (const s of scans) {
      if (isRunningScan(s) || s.status === "completed" || s.status === "done") continue;
      if (["failed", "killed", "crashed"].includes(s.status)) failed++;
      else interrupted++;
    }
    const by: Record<string, number> = {};
    for (const s of scans) {
      for (const [k, v] of Object.entries(s.vuln_counts ?? {})) by[k] = (by[k] ?? 0) + v;
    }
    const rows = Object.entries(by).filter(([, v]) => v > 0).sort((a, b) => b[1] - a[1]);
    const costByCurrency = new Map<string, number>();
    for (const s of scans) {
      if (s.total_cost_usd == null) continue;
      const cur = s.cost_currency ?? "USD";
      costByCurrency.set(cur, (costByCurrency.get(cur) ?? 0) + s.total_cost_usd);
    }
    return {
      latest,
      running,
      failed,
      interrupted,
      costEntries: [...costByCurrency.entries()].sort((a, b) => b[1] - a[1]),
      totalVulns: scans.reduce((a, s) => a + (s.vuln_count ?? 0), 0),
      composition: {
        top: rows.slice(0, 3),
        rest: rows.slice(3).reduce((a, [, v]) => a + v, 0),
        total: rows.reduce((a, [, v]) => a + v, 0),
      },
    };
  }, [scans]);

  // 空工作区（加载完且无扫描）：中性「尚未扫描」+ 引导行（不给状态暗示）。
  const never = !loading && scans.length === 0;
  const attention = agg.failed + agg.interrupted;

  // 分币种：单币种照常 fmtCost；多币种紧凑「¥76 + $29」（title 悬停全精度）。
  let costNum: string = "—";
  let costTitle: string | undefined;
  if (agg.costEntries.length === 1) {
    const [cur, v] = agg.costEntries[0];
    costNum = fmtCost(v, cur);
  } else if (agg.costEntries.length > 1) {
    costNum = agg.costEntries.map(([cur, v]) => `${currencySymbol(cur)}${Math.round(v)}`).join(" + ");
    costTitle = agg.costEntries.map(([cur, v]) => `${cur} ${v.toFixed(2)}`).join(" · ");
  }

  if (notFound) {
    return (
      <div className="space-y-4">
        <Link to="/workspaces-entry" className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-primary">
          <ArrowLeft className="size-3.5" /> {t("workspaceDetail.backToList")}
        </Link>
        <div className="rounded-md border border-yellow/40 bg-card p-6 text-sm">
          <h2 className="font-mono text-xl mb-2">{workspace}</h2>
          <p className="text-muted-foreground">
            {t("workspaceDetail.notFound.message")}
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <Link
        to="/workspaces-entry"
        className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-primary"
      >
        <ArrowLeft className="size-3.5" /> {t("workspaceDetail.backToList")}
      </Link>

      {/* ===== 工作台头：r1 = ws 名 + 徽标 + 命令栏；r2 = 一行 mono 统计摘要 ===== */}
      <Card className="px-[18px] pt-3.5 pb-3">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-2.5">
          <div className="flex min-w-0 flex-wrap items-center gap-2.5">
            {hasRunning && <span className="dash-live-dot" aria-hidden />}
            <span className="font-mono text-[22px] font-semibold leading-tight tracking-tight">{workspace}</span>
            {loading ? (
              <Skeleton className="h-5 w-36" />
            ) : never ? (
              // 空态：虚线中性「尚未扫描」——从未扫描 ≠ 安全，不给状态暗示
              <Badge variant="outline" className="border-dashed font-mono text-muted-foreground">
                {t("workspaceDetail.hero.notScanned")}
              </Badge>
            ) : (
              <span className="flex flex-wrap items-center gap-1.5">
                {agg.latest?.combined === true ? (
                  // 组合任务只显「组合」（scan_type 底层仍为 whitebox，双徽标冗余——与 ScanList 类型格同口径）
                  <Badge variant="outline" className="border-primary/35 font-mono text-primary">
                    {t("workspaceDetail.scans.typeCombined")}
                  </Badge>
                ) : (
                  agg.latest?.scan_type && (
                    <Badge variant="outline" className="font-mono">{agg.latest.scan_type}</Badge>
                  )
                )}
                <Badge variant="secondary" className="font-mono">
                  {t("workspaceDetail.scans.listTitle")} · {scans.length}
                </Badge>
              </span>
            )}
          </div>

          {/* 命令栏（toolbar 变体语言）：ws 级操作 ‖ 区段导航（active = secondary 实底） */}
          <div className="ml-auto flex flex-wrap items-center gap-2">
            <WorkspaceSwitcher currentWorkspace={workspace} />
            {workspace && <MemberManagerDialog ws={workspace} />}
            <span className="mx-0.5 h-5 w-px bg-border" aria-hidden />
            {/* 区段导航：扫描（index，end 精确匹配）+ 仓库/认证/HOST/设置；当前区段 secondary 高亮，
                子页可随时点「扫描」回任务列表（此前 index 无入口，点进子页只能靠浏览器后退）。 */}
            {workspace && (
              <SectionLink to={`/p/${workspace}`} end label={t("workspaceDetail.tabs.scans")} icon={ScanLine} />
            )}
            {workspace && <SectionLink to="repos" label={t("workspaceDetail.tabs.repos")} icon={FolderGit2} />}
            {workspace && <SectionLink to="auth-profiles" label={t("authProfiles.openLabel")} icon={KeyRound} />}
            {workspace && <SectionLink to="host-profiles" label={t("hostProfiles.openLabel")} icon={Globe} />}
            {workspace && <SectionLink to="settings" label={t("wsConfig.openSettings")} icon={Settings} iconOnly />}
          </div>
        </div>

        {/* 统计摘要行：累计发现 + mini 谱带 ‖ 运行中 ‖ 需关注 ‖ 花费 ‖ 最新（可点直达） */}
        <div className="mt-2.5 flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-border pt-2.5 font-mono text-xs text-muted-foreground">
          {never || loading ? (
            <span>{t("workspaceDetail.hero.emptyGuide")}</span>
          ) : (
            <>
              <span className="flex flex-wrap items-center gap-2.5">
                <span className="text-muted-foreground">
                  {t("workspaceDetail.hero.totalFindings")}{" "}
                  <b
                    data-testid="ws-hero-findings"
                    className={`text-[15px] font-semibold ${agg.totalVulns > 0 ? "text-red" : "text-green"}`}
                  >
                    {agg.totalVulns.toLocaleString()}
                  </b>
                </span>
                {agg.composition.total > 0 && (
                  <span className="flex items-center gap-2">
                    <span data-testid="ws-composition-bar" className="flex h-1 w-[120px] gap-px overflow-hidden rounded-full bg-border">
                      {agg.composition.top.map(([cls, n], i) => (
                        <span key={cls} className="bg-red" style={{ width: `${(n / agg.composition.total) * 100}%`, opacity: 1 - i * 0.22 }} />
                      ))}
                      {agg.composition.rest > 0 && (
                        <span className="bg-red/25" style={{ width: `${(agg.composition.rest / agg.composition.total) * 100}%` }} />
                      )}
                    </span>
                    <span className="flex gap-x-2">
                      {agg.composition.top.map(([cls, n]) => <span key={cls}>{cls} {n.toLocaleString()}</span>)}
                      {agg.composition.rest > 0 && <span>{t("dashboard.hero.other")} {agg.composition.rest.toLocaleString()}</span>}
                    </span>
                  </span>
                )}
              </span>
              <span className="opacity-35">|</span>
              <span>
                <b className="font-semibold text-foreground">{agg.running.length}</b>{" "}
                <span>{t("dashboard.stats.running")}</span>
              </span>
              <span className="opacity-35">|</span>
              <span>
                <span>{t("workspaceDetail.stats.needsAttention")}</span>{" "}
                <b className={`font-semibold ${attention > 0 ? "text-amber" : "text-foreground"}`}>{attention.toLocaleString()}</b>{" "}
                <span data-testid="ws-attn-ctx" className="opacity-80">
                  （{t("workspaceDetail.stats.needsAttentionCtx", { failed: agg.failed, interrupted: agg.interrupted })}）
                </span>
              </span>
              <span className="opacity-35">|</span>
              <span title={costTitle}>
                <span>{t("workspaceDetail.stats.cost")}</span>{" "}
                <b data-testid="ws-cost-num" className="font-semibold text-foreground">{costNum}</b>
              </span>
              <span className="opacity-35">|</span>
              {agg.latest && (
                <span className="min-w-0 truncate">
                  {t("workspaceDetail.hero.ctxLatest")}{" "}
                  <Link
                    to={`/p/${workspace}/scans/${agg.latest.scan_id}/${
                      agg.latest.status === "completed" || agg.latest.status === "done" ? "report" : "live"
                    }`}
                    className="text-foreground transition-colors hover:text-primary"
                  >
                    {agg.latest.workflow_id ?? agg.latest.scan_id}
                  </Link>
                  {isRunningScan(agg.latest) && agg.latest.progress_pct != null && (
                    <> · {Math.round(agg.latest.progress_pct)}%</>
                  )}
                </span>
              )}
            </>
          )}
        </div>
      </Card>

      <ErrorBoundary><Outlet context={{ refresh } satisfies WsOverviewCtx} /></ErrorBoundary>
    </div>
  );
}
