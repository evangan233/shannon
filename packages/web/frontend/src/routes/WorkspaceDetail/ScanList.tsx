import { useEffect, useMemo, useState } from "react";
// useEffect/useState 仍被行内组件（SSE 订阅等）使用；列表数据层已上移 useScans。
import { useTranslation } from "react-i18next";
import { useParams, useNavigate, useLocation, useOutletContext, Link } from "react-router-dom";
import { toast } from "sonner";
import { Ban, ChevronRight, Crosshair, Eye, Play, RefreshCw, Search, Trash2 } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { StatusBadge } from "@/components/StatusBadge";
import { ErrorState } from "@/components/ErrorState";
import { Empty } from "@/components/Empty";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import {
  cancelScan, deleteScan, deleteBlackboxRun, resumeScan, getScan, getResumePreview,
  scanEventsUrl, ApiError, type ResumePreview,
} from "@/api/client";
import useSWR from "swr";
import { useScans } from "./useScans";
import { getScanGate, type ScanGateSnapshot } from "@/api/client";
import { ScanGatePanel } from "@/components/ScanGatePanel";
import { useEventSource } from "@/api/useEventSource";
import { liveScanPct } from "@/state/liveScanPct";
import type { BlackboxRunSummary, BatchScanResponse, ScanSummary } from "@/api/types";
import { fmtCost } from "@/utils/currency";
import { fmtTime, fmtDur, compactUrl } from "@/utils/format";
import { isRunTerminal } from "./runStatus";
import { scanSegmentLabel } from "./ScanProgressBadge";
import type { WsOverviewCtx } from "./";

// 终态集（重跑/删除入口口径）。续跑显示另判（spec 2026-08-27-web-resume-breakpoint
// §4.6）：!running ∧ status ∉ {completed, done} ∧ 白盒行（含组合；correlation 无入口）——
// failed/cancelled/killed/crashed/interrupted 均可续跑，与后端 _RESUMABLE_STATUSES 对齐。
const TERMINAL = new Set(["completed", "done", "failed", "killed", "crashed", "cancelled"]);

// 运行中判定（分段过滤用）；轮询节奏由 useScans 的 SWR refreshInterval 管理。
const isRun = (s: ScanSummary) => s.is_running || s.status === "running";

/** 状态分段（filter 分段控件口径）：running/completed/failed + other（interrupted 等，仅「全部」可见）。 */
type Seg = "running" | "completed" | "failed";
function segOf(s: ScanSummary): Seg | "other" {
  if (isRun(s)) return "running";
  if (s.status === "completed" || s.status === "done") return "completed";
  if (["failed", "killed", "crashed"].includes(s.status)) return "failed";
  return "other";
}

/** 筛选态：分段（全部/运行中/已完成/失败）+ 类型 + 关键词。
 *  类型模型（重设计 2026-08-16 收窄 + 2026-08-24 关联回归 D4）：白盒 + 组合 + 跨仓关联。
 *  组合扫描 scan_type 仍为 whitebox、靠 combined 标记识别；黑盒一律是组合/关联任务的
 *  嵌套 run，无独立行/入口。注意 correlation 主行跑过段③黑盒验证后 session 亦被
 *  create_blackbox_run 置 combined=True——类型匹配须先判 correlation 再判 combined，
 *  否则关联行会漏进「组合」档。MR 增量（spec 2026-09-03）：scan_type="mr" 独立档，
 *  不入白盒/组合（纯白盒语义无黑盒段）。 */
type TypeFilter = "all" | "whitebox" | "combined" | "correlation" | "mr";
interface ListFilters { seg: "all" | Seg; type: TypeFilter; keyword: string }
const DEFAULT_LIST_FILTERS: ListFilters = { seg: "all", type: "all", keyword: "" };

function matchType(s: ScanSummary, type: TypeFilter): boolean {
  if (type === "all") return true;
  if (type === "correlation") return s.scan_type === "correlation";
  if (type === "mr") return s.scan_type === "mr";
  // 「白盒」「组合」档均不含关联/MR 行——只入自己的档。
  if (s.scan_type === "correlation" || s.scan_type === "mr") return false;
  if (type === "combined") return s.combined === true;
  return s.scan_type === "whitebox" && s.combined !== true;
}

function fmtTimeFull(unix?: number | null): string {
  if (!unix) return "";
  return new Date(unix * 1000).toLocaleString();
}

/** 在一次任务生命周期内保持进度不回退；续跑/状态切换通过 key 重置。 */
function useMonotonicPct(key: string, candidate: number): number {
  const [state, setState] = useState(() => ({ key, value: candidate }));
  useEffect(() => {
    setState((prev) => {
      if (prev.key !== key) return { key, value: candidate };
      return candidate > prev.value ? { key, value: candidate } : prev;
    });
  }, [key, candidate]);
  return state.key === key ? Math.max(state.value, candidate) : candidate;
}

/** 从 SSE events 推当前阶段（最后一条 PhaseEvent(start).phase）；无则 null。
 *  列表行粗粒度用：纯白盒/纯黑盒段标签后缀（如「白盒 · recon」）。 */
function useCurrentPhase(events: { type: string; event?: string; phase?: string }[]): string | null {
  return useMemo(() => {
    for (let i = events.length - 1; i >= 0; i--) {
      const e = events[i];
      if (e.type === "PhaseEvent" && e.event === "start") return e.phase ?? null;
    }
    return null;
  }, [events]);
}

export function ScanList() {
  const { t } = useTranslation();
  const { workspace } = useParams<{ workspace: string }>();
  // WorkspaceDetail（Outlet 父级）聚合联动：操作/scan_end 后同步刷新 Hero/指标条。
  // 独立渲染（单测直挂 Route）时无 context → null，退化为仅自身刷新。
  const wsCtx = useOutletContext<WsOverviewCtx | null>();
  // SWR 数据层（spec §6.3）：与父容器共享 key → 单请求单轮询（运行中才 10s，后台 tab 暂停）。
  const { scans, loading, error: err, refresh: refreshScans } = useScans(workspace);
  // 全局闸门快照（spec §8.2）：与 useScans 同款条件轮询——有占用/排队才 10s 刷
  const { data: gateSnap } = useSWR<ScanGateSnapshot>(["scan-gate"], getScanGate, {
    refreshInterval: (latest?: ScanGateSnapshot) =>
      latest && latest.held.length + latest.waiting.length > 0 ? 10_000 : 0,
  });
  const [filters, setFilters] = useState<ListFilters>(DEFAULT_LIST_FILTERS);

  // 批量提交结果横幅（2026-09-11 批量白盒）：ScanNewPage 批量提交后经 location.state
  // 传入 BatchScanResponse（202 与全失败 422 同形）。useState 初始化器捕获首帧 state
  // （闭包固定）——effect 里 navigate replace 清掉 history entry 的 state 后（防刷新/
  // 后退重复呈现），横幅仍显示（若直接读 location.state，replace 触发的重渲染会把
  // batchResult 变 undefined，横幅闪现即消失——已规避）。关闭用局部 bannerClosed。
  const location = useLocation();
  const bannerNav = useNavigate();
  const [batchResult] = useState(
    () => (location.state as { batchResult?: BatchScanResponse } | null)?.batchResult ?? null);
  const [bannerClosed, setBannerClosed] = useState(false);
  useEffect(() => {
    if (batchResult) bannerNav(location.pathname, { replace: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // 关键词 + 类型先行过滤（分段计数以此为准，计数不随当前分段变化）；
  // 分段口径见 segOf：other（interrupted 等）只在「全部」出现。
  // 列表量小（单 ws 扫描数）直算即可，避免在 err 早退后引入条件 hook。
  const kwTyped = scans.filter((s) => {
    if (!matchType(s, filters.type)) return false;
    const q = filters.keyword.trim().toLowerCase();
    if (q) {
      const hay = `${s.workflow_id ?? ""} ${s.scan_id} ${s.repo ?? ""} ${s.repo_url ?? ""}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  const segCounts = {
    all: kwTyped.length,
    running: kwTyped.filter((s) => segOf(s) === "running").length,
    completed: kwTyped.filter((s) => segOf(s) === "completed").length,
    failed: kwTyped.filter((s) => segOf(s) === "failed").length,
  };

  // correlation 子行富化源（D4）：corr_children 只带 {service, scan_id, reused}，状态/
  // 漏洞数/时间从同 ws 全量列表按 scan_id 补（现扫子仓由后端建在同 ws，天然在列）。
  // 必须用未过滤的 scans——关键词/分段过滤不应连带抽掉嵌套子行的富化数据。
  const scansById = new Map(scans.map((s) => [s.scan_id, s] as const));

  if (err) return <ErrorState message={t("workspaceDetail.scans.loadError", { error: err })} />;

  const filtered = filters.seg === "all" ? kwTyped : kwTyped.filter((s) => segOf(s) === filters.seg);

  // 行操作后：刷新自身列表 + 联动 Hero 聚合（同 key mutate 经 SWR 去重为一次请求）。 */
  const reload = () => { refreshScans(); wsCtx?.refresh?.(); };

  // 空工作区（v4）：过滤器隐藏（无对象可过滤）、列表头 CTA 移除（空态卡是唯一主操作）。
  // loading 期间保持显（避免加载闪隐），加载完确认为空才收起。
  const showListChrome = loading || scans.length > 0;

  // 耗时分布（标题行运营摘要）：平均/最长/最短（仅有 total_duration_ms 的扫描参与）。
  const durations = scans.map((s) => s.total_duration_ms ?? 0).filter((ms) => ms > 0);
  const avgInfo = durations.length
    ? {
        avg: fmtDur(durations.reduce((a, b) => a + b, 0) / durations.length),
        max: fmtDur(Math.max(...durations)),
        min: fmtDur(Math.min(...durations)),
      }
    : null;

  return (
    <div className="space-y-3">
      <ScanGatePanel snapshot={gateSnap ?? null} currentWs={workspace} />
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-baseline gap-x-2.5">
          <h3 className="text-base font-semibold tracking-tight">{t("workspaceDetail.scans.listTitle")}</h3>
          {showListChrome && (
            <>
              <span className="font-mono text-sm font-semibold tabular-nums">{scans.length}</span>
              {avgInfo && (
                <span className="font-mono text-[11.5px] text-muted-foreground">
                  {t("workspaceDetail.scans.avgCtx", avgInfo)}
                </span>
              )}
            </>
          )}
        </div>
        {workspace && showListChrome && (
          <Button variant="cta" asChild>
            <Link to={`/scan/new?workspace=${encodeURIComponent(workspace)}`}>
              {t("workspaceDetail.scans.newScan")}
            </Link>
          </Button>
        )}
      </div>

      {/* 过滤器（预览 2026-08-15）：搜索 + 状态分段（带计数）+ 类型 select；空工作区隐藏 */}
      {showListChrome && (
        <div className="flex flex-wrap items-center gap-2">
        <div className="relative min-w-[200px] flex-1 sm:max-w-xs">
          <Search className="pointer-events-none absolute left-3 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" aria-hidden />
          <Input
            value={filters.keyword}
            onChange={(e) => setFilters((f) => ({ ...f, keyword: e.target.value }))}
            placeholder={t("workspaceDetail.scans.searchPlaceholder")}
            aria-label={t("workspaceDetail.scans.searchPlaceholder")}
            className="pl-9"
          />
        </div>
        <div className="inline-flex rounded-[10px] bg-muted p-[3px]" role="group" aria-label={t("scanFilters.status")}>
          {([["all", "workspaceDetail.scans.seg.all", segCounts.all],
             ["running", "workspaces.status.running", segCounts.running],
             ["completed", "workspaces.status.completed", segCounts.completed],
             ["failed", "workspaces.status.failed", segCounts.failed]] as const).map(([seg, key, n]) => (
            <button
              key={seg}
              type="button"
              aria-pressed={filters.seg === seg}
              onClick={() => setFilters((f) => ({ ...f, seg }))}
              className={`rounded-md px-3 py-1 text-[12.5px] font-medium transition-colors ${
                filters.seg === seg
                  ? "bg-card text-foreground shadow-sm"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              {t(key)}<span className="ml-1 font-mono text-[11px] opacity-70">{n}</span>
            </button>
          ))}
        </div>
        {/* 类型模型（2026-08-16 收窄 + 2026-08-24 关联回归 D4）：白盒 + 组合 + 跨仓关联——
            黑盒是组合任务的嵌套 run 无独立类型可选；correlation 已接通（主行展开子仓
            白盒/黑盒验证/复用引用子行，见 ScanRow），过滤档见上 */}
        <Select value={filters.type} onValueChange={(v) => setFilters((f) => ({ ...f, type: v as TypeFilter }))}>
          <SelectTrigger aria-label={t("scanFilters.type")} className="w-40"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t("workspaces.filter.allType")}</SelectItem>
            <SelectItem value="whitebox">{t("workspaces.filter.whitebox")}</SelectItem>
            <SelectItem value="combined">{t("workspaceDetail.scans.typeFilterCombined")}</SelectItem>
            <SelectItem value="correlation">{t("workspaces.filter.correlation")}</SelectItem>
            <SelectItem value="mr">{t("workspaces.filter.mr")}</SelectItem>
          </SelectContent>
        </Select>
        </div>
      )}

      {/* 批量提交结果横幅（2026-09-11 批量白盒）：成功/失败计数 + 失败明细（repo：原因），
          可关闭。空工作区/加载中也显示——批量提交后跳转落地即见汇总，不依赖列表数据。 */}
      {batchResult && !bannerClosed && (
        <div data-testid="batch-result-banner"
          className="flex items-start justify-between gap-3 rounded-lg border border-border bg-card px-4 py-3">
          <div className="min-w-0 text-xs">
            <span className="font-medium">{t("scan.batch.bannerTitle",
              { ok: batchResult.submitted, fail: batchResult.failed })}</span>
            {batchResult.failed > 0 && (
              <ul className="mt-1.5 space-y-0.5">
                {batchResult.results.filter((r) => !r.ok).map((r) => (
                  <li key={r.repo} className="font-mono text-[11px] text-destructive">
                    {r.repo}：{r.error}
                  </li>
                ))}
              </ul>
            )}
          </div>
          <button type="button" data-testid="batch-banner-close" aria-label={t("scan.batch.bannerClose")}
            className="shrink-0 text-muted-foreground hover:text-foreground"
            onClick={() => setBannerClosed(true)}>✕</button>
        </div>
      )}

      {loading ? (
        <div className="space-y-2">
          {[0, 1, 2].map((i) => <Skeleton key={i} className="h-16 w-full" />)}
        </div>
      ) : scans.length === 0 ? (
        /* 空态卡（v4）：唯一 CTA + 次级入口（对应命令栏的仓库/认证，降低首次使用门槛） */
        <Empty title={t("workspaceDetail.scans.empty")} hint={t("workspaceDetail.scans.emptyHint")}>
          <div className="flex flex-col items-center gap-3">
            {workspace && (
              <Button variant="cta" asChild>
                <Link to={`/scan/new?workspace=${encodeURIComponent(workspace)}`}>
                  {t("workspaceDetail.scans.newScan")}
                </Link>
              </Button>
            )}
            <div className="flex gap-3.5 text-xs">
              <Link to="repos" className="text-primary hover:underline">
                {t("workspaceDetail.scans.setupRepos")}
              </Link>
              <Link to="auth-profiles" className="text-primary hover:underline">
                {t("workspaceDetail.scans.setupAuth")}
              </Link>
            </div>
          </div>
        </Empty>
      ) : filtered.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("workspaceDetail.scans.noMatch")}</p>
      ) : (
        <Card className="overflow-hidden p-0">
          <Table>
            <colgroup>
              <col style={{ width: 34 }} /><col style={{ width: 112 }} /><col />
              <col style={{ width: 190 }} /><col style={{ width: 104 }} /><col style={{ width: 172 }} />
              <col style={{ width: 72 }} /><col style={{ width: 92 }} /><col style={{ width: 132 }} />
              <col style={{ width: 196 }} />
            </colgroup>
            <TableHeader>
              <TableRow>
                <TableHead className="w-9 pl-4" />
                <TableHead className="whitespace-nowrap text-[11px] font-semibold uppercase tracking-wider">{t("workspaceDetail.scans.table.status")}</TableHead>
                <TableHead className="whitespace-nowrap text-[11px] font-semibold uppercase tracking-wider">{t("workspaceDetail.scans.table.scan")}</TableHead>
                <TableHead className="whitespace-nowrap text-[11px] font-semibold uppercase tracking-wider">{t("workspaceDetail.scans.table.repo")}</TableHead>
                <TableHead className="whitespace-nowrap text-[11px] font-semibold uppercase tracking-wider">{t("workspaceDetail.scans.table.type")}</TableHead>
                <TableHead className="whitespace-nowrap text-[11px] font-semibold uppercase tracking-wider">{t("workspaceDetail.scans.table.progress")}</TableHead>
                <TableHead className="whitespace-nowrap text-right text-[11px] font-semibold uppercase tracking-wider">{t("workspaceDetail.scans.table.vulns")}</TableHead>
                <TableHead className="whitespace-nowrap text-right text-[11px] font-semibold uppercase tracking-wider">{t("workspaceDetail.scans.table.cost")}</TableHead>
                <TableHead className="whitespace-nowrap text-[11px] font-semibold uppercase tracking-wider">{t("workspaceDetail.scans.table.created")}</TableHead>
                <TableHead className="whitespace-nowrap pr-4 text-right text-[11px] font-semibold uppercase tracking-wider">{t("workspaceDetail.scans.table.actions")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map((s) => (
                <ScanRow key={s.scan_id} ws={workspace!} scan={s} scansById={scansById} onChanged={reload} />
              ))}
            </TableBody>
          </Table>
        </Card>
      )}
    </div>
  );
}

/** 表格主行 + 嵌套子行（可展开，默认收起——列表扫读优先，明细按需展开）：
 *  组合任务 = 黑盒 run 子行（NestedBlackboxRuns）；correlation 主行 = 子仓白盒 +
 *  黑盒验证 run + 复用引用子行（NestedCorrChildren + NestedBlackboxRuns，D4）。 */
function ScanRow({ ws, scan, scansById, onChanged }: {
  ws: string; scan: ScanSummary; scansById: Map<string, ScanSummary>; onChanged: () => void;
}) {
  // 闸门快照（与主列表同 key，SWR 缓存共享）：queued 行显示排队位次
  const { data: gateSnap } = useSWR<ScanGateSnapshot>(["scan-gate"], getScanGate);
  const { t } = useTranslation();
  const nav = useNavigate();
  const [busy, setBusy] = useState(false);
  const [pending, setPending] = useState<"cancel" | "delete" | "resume" | null>(null);
  // 续跑确认流（§4.6）：点续跑先拉断点详情，弹窗摘要后确认才 POST resume。
  const [resumePreview, setResumePreview] = useState<ResumePreview | null>(null);
  const isCombined = scan.combined === true;
  const isCorr = scan.scan_type === "correlation";
  // MR 增量行（spec 2026-09-03 §6）：「MR」徽标 + base..head refs 标识（session 透传，
  // 无 refs 的存量/异常行只显徽标）。
  const isMr = scan.scan_type === "mr";
  // 黑盒 run 子行：组合任务 + correlation 主行（段③黑盒验证经 create_blackbox_run
  // 写 bb_runs；该调用同笔写 combined=True，isCorr 并入判式兜底半写状态）。
  const hasRuns = (isCombined || isCorr) && (scan.bb_runs?.length ?? 0) > 0;
  // correlation 子行（corr_children，C2 透传）：现扫子仓白盒（reused=false）+
  // 复用历史子仓引用（reused=true）；非 correlation 行恒空。
  const corrChildren = isCorr ? scan.corr_children ?? [] : [];
  const freshChildren = corrChildren.filter((c) => !c.reused);
  const reusedChildren = corrChildren.filter((c) => c.reused);
  const expandable = hasRuns || corrChildren.length > 0;
  const [open, setOpen] = useState(false);

  const isRunning = isRun(scan);
  const isTerminal = TERMINAL.has(scan.status);
  // 续跑入口（§4.6）：非 running ∧ 非 completed/done ∧ 白盒行（含组合；correlation
  // 走重新提交、无黑盒独立行）——failed/cancelled/killed/crashed/interrupted 全放行。
  const canResume = !isRunning
    && !["completed", "done"].includes(scan.status)
    && scan.scan_type === "whitebox";
  const scanPath = `/p/${ws}/scans/${scan.scan_id}`;
  // 任务名展示用 workflow_id（{ws}-{scan_id}[-resume-N]），路由/API 仍用 scan_id 定位目录。
  const label = scan.workflow_id ?? scan.scan_id;
  // 默认进 scan 详情的 tab：完成 -> report（看结果），其余 -> live（看实时）。
  // 与 router.tsx DefaultScanTab 一致；此处据 scan.status 直定，免走 DefaultScanTab 多一次 getScan + 空白闪烁。
  // correlation 主行例外（D6）：tab 组为 概览|跨仓关联|产物|日志（无 report/live），
  // 运行中/完成统一落「概览」（简版 CorrelationOverview）。
  const defaultTab = isCorr ? "overview"
    : scan.status === "completed" || scan.status === "done" ? "report" : "live";

  // 运行中行按需建 SSE 推实时阶段（粗粒度：段标签后缀）；终态/非运行中不建（url=""）。
  // 列表页粗粒度——精确步级/Agent 在扫描详情页顶部。scan_end → 刷新列表拿终态（漏洞数/状态）。
  const sseUrl = isRunning ? scanEventsUrl(ws, scan.scan_id) : "";
  const { events, hydrated } = useEventSource(sseUrl);
  // 子仓源（src=c-<scan_id>，2026-09-10 归并流扩子仓）不进列表行阶段——correlation
  // 主行流现含现扫子仓白盒日志，其 PhaseEvent 不得冒充主行阶段（主行三段网格无
  // PhaseEvent，过滤后维持无后缀现状）。子仓行自己的流无 c-* 源，不受影响。
  const mainEvents = useMemo(
    () => events.filter((e) => !String(e.src ?? "").startsWith("c-")),
    [events]);
  const currentPhase = useCurrentPhase(mainEvents);
  // 与进度百分比同样等待首轮回放边界，避免列表副标签也随历史 phase 逐帧闪动。
  const displayedPhase = hydrated ? currentPhase : null;
  // 实时进度（2026-08-27 修复列表进度不动；2026-08-28 组合口径修正）：progress_pct 的
  // 分子 completed_agents 只在 workflow 结束才落盘 session.json，运行中恒定 → 进度条
  // 钉死。改为 fold 已订阅的 SSE 归并流取实时进度——组合扫描按 src 源标记套三阶段
  // 加权（白盒满格=55% 而非 100%，黑盒段 55→100，对齐后端 _compute_progress_pct /
  // spec §9.2），纯白盒/correlation 保持当前 phase 直读（reducer 是当前 phase 口径，
  // 单段即全部/累积网格）。无 src（旧后端流）或 total=0 → null，展示层回退 progress_pct。
  // 首轮 SSE 历史回放未追平前，不拿中间 fold 值覆盖 API 快照；否则首次进入列表
  // 会把历史每个 phase 的临时比例逐个画出来。stream_ready 到达后再切到当前值。
  const livePct = useMemo(
    () => (hydrated ? liveScanPct(events, scan) : null),
    [events, scan, hydrated],
  );
  useEffect(() => {
    if (events.some((e) => e.type === "scan_end")) onChanged();
  }, [events, onChanged]);

  async function onResume() {
    // §4.6 确认流：先拉断点详情（只读）→ 弹窗展示可跳过摘要 / 不可续跑原因。
    setBusy(true);
    try {
      const preview = await getResumePreview(ws, scan.scan_id);
      setResumePreview(preview);
      setPending("resume");
    } catch (e) {
      toast.error(t("workspaceDetail.scans.resumePreviewFailed", { error: msg(e) }));
    } finally {
      setBusy(false);
    }
  }

  // 重跑 = 同 ws 新建扫描（spec §12.7），按原扫描类型跳对应 tab 并预填相关数据。
  // 调 getScan 拿原配置（白盒 source_repo）-> location state 传 ScanNewPage 预填。
  // 黑盒分支已删（D3 删 ScanNewPage 黑盒表单 + D4 删本列表黑盒行重跑入口）；
  // correlation 重跑只带类型（多仓配置不可从 detail 重建，落空关联表单手填）。
  // 组合扫描（bb_url 非空，2026-09-03）：黑盒段配置一并预填——目标 url + combined
  // 开关 + 认证（profile 档案优先，inline authentication 兜底）+ HOST 来源。
  // MR 增量（spec 2026-09-03 §6）：repo + base/head refs 预填（_scan_detail 透传）。
  async function onRerun() {
    setBusy(true);
    try {
      const detail = await getScan(ws, scan.scan_id);
      const state: Record<string, unknown> = { type: scan.scan_type, workspace: ws };
      if ((scan.scan_type === "whitebox" || scan.scan_type === "mr") && detail.source_repo) {
        state.repo = detail.source_repo;
      }
      if (scan.scan_type === "mr") {
        if (detail.mr_base_ref) state.mrBaseRef = detail.mr_base_ref;
        if (detail.mr_head_ref) state.mrHeadRef = detail.mr_head_ref;
        // merged 改道把手（2026-09-04）：改道扫描的重跑仍走 commit 对（不撞已删源分支）。
        if (detail.mr_head_commit) state.mrHeadCommit = detail.mr_head_commit;
        if (detail.mr_base_commit) state.mrBaseCommit = detail.mr_base_commit;
      }
      if (detail.bb_url) {
        state.url = detail.bb_url;
        state.combined = true;
        if (detail.auth_profile_id) {
          state.authProfileId = detail.auth_profile_id;
          state.authCredentialIds = detail.auth_credential_ids ?? [];
        } else if (detail.authentication) {
          state.auth = detail.authentication;
        }
        // HOST 多选（2026-09-11）：优先复数字段（旧任务只有单数 → detail 后端已包数组）。
        if (detail.host_profile_ids?.length) state.hostProfileIds = detail.host_profile_ids;
        else if (detail.host_profile_id) state.hostProfileId = detail.host_profile_id;
        if (detail.host_url) state.hostUrl = detail.host_url;
      }
      nav(`/scan/new?workspace=${encodeURIComponent(ws)}`, { state });
    } catch {
      // getScan 失败降级：只带 workspace 跳转（对齐旧现状），toast 提示用户手填。
      toast.error(t("workspaceDetail.scans.rerunLoadFailed"));
      nav(`/scan/new?workspace=${encodeURIComponent(ws)}`);
    } finally {
      setBusy(false);
    }
  }

  async function doAction() {
    if (!pending) return;
    setBusy(true);
    try {
      if (pending === "cancel") {
        await cancelScan(ws, scan.scan_id);
        toast.success(t("workspaceDetail.scans.canceled", { scanId: label }));
        setPending(null);
        onChanged();
      } else if (pending === "resume") {
        await resumeScan(ws, scan.scan_id);
        toast.success(t("workspaceDetail.scans.resumed"));
        setPending(null);
        // 续跑后落默认 tab（correlation 行无 live tab——落概览，D6）
        nav(`${scanPath}/${defaultTab}`);
      } else {
        await deleteScan(ws, scan.scan_id);
        toast.success(t("workspaceDetail.scans.deleted", { scanId: label }));
        setPending(null);
        onChanged();
      }
    } catch (e) {
      toast.error(t(
        pending === "cancel" ? "workspaceDetail.scans.cancelFailed"
          : pending === "resume" ? "workspaceDetail.scans.resumeFailed"
          : "workspaceDetail.scans.deleteFailed",
        { error: msg(e) },
      ));
    } finally {
      setBusy(false);
    }
  }

  const v = scan.vuln_count ?? 0;
  // SSE 实时进度优先（见上 livePct 注释）；无实时数据回退轮询快照 progress_pct。
  const fallbackPct = Math.max(0, Math.min(100, Math.round(scan.progress_pct ?? 0)));
  const candidatePct = livePct ?? fallbackPct;
  // 进度是单调展示量：PhaseEvent(start) 会让 dashboardReducer 切换到新 phase
  // 并暂时回到 0；列表不能把已走过的进度倒放。workflow_id 变化（续跑）时重置。
  const pctKey = `${scan.scan_id}:${scan.workflow_id ?? scan.created_at}:${isRunning ? "running" : scan.status}`;
  const pct = useMonotonicPct(pctKey, Math.max(0, Math.min(100, candidatePct)));
  const dur = fmtDur(scan.total_duration_ms);

  return (
    <>
      {/* 整行可点（v4）：与 ID/查看同目标（defaultTab）；行内交互元素 stopPropagation 防误触。
          展开时去底边线——父行与嵌套子行组无缝相接（树形从属，组内子行间仍保留细线）。 */}
      <TableRow
        onClick={() => nav(`${scanPath}/${defaultTab}`)}
        className={`cursor-pointer ${open && expandable ? "border-b-0" : ""}`}
      >
        {/* 展开柄：有子行可展开时显（组合任务带 bb_runs / correlation 主行带
            corr_children；纯白盒/黑盒无子行不占交互）。aria 按行类型选标签。 */}
        <TableCell className="w-9 pl-4">
          {expandable && (
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); setOpen((o) => !o); }}
              aria-expanded={open}
              aria-label={t(isCorr
                ? (open ? "workspaceDetail.scans.corr.toggleCollapse" : "workspaceDetail.scans.corr.toggleExpand")
                : (open ? "workspaceDetail.scans.runs.toggleCollapse" : "workspaceDetail.scans.runs.toggleExpand"))}
              className="flex size-5 items-center justify-center rounded text-muted-foreground transition-colors hover:text-foreground"
            >
              <ChevronRight className={`size-3.5 transition-transform ${open ? "rotate-90" : ""}`} />
            </button>
          )}
        </TableCell>
        {/* 状态徽标：所有行同构（类型归属在类型列徽标，2026-09-10 起状态列不再
            追加 🔗——emoji 基线漂移且撑爆 112px 列宽致换行） */}
        <TableCell>
          <div className="flex items-center gap-1">
            <StatusBadge status={scan.status} />
            {scan.status === "queued" && (() => {
              const pos = gateSnap?.waiting.findIndex((e) => e.scan_id === scan.scan_id) ?? -1;
              return pos >= 0
                ? <span className="text-xs text-muted-foreground">#{pos + 1}</span> : null;
            })()}
          </div>
        </TableCell>
        <TableCell className="max-w-0 truncate font-mono">
          <Link
            to={`${scanPath}/${defaultTab}`}
            onClick={(e) => e.stopPropagation()}
            className="text-[13px] font-medium hover:text-primary"
          >
            {label}
          </Link>
        </TableCell>
        {/* 仓库格：repo@branch（分支快照，spec 2026-08-21 §4）——切分支后同一仓扫不同
            分支靠此区分；commit 前 8 位进 title hover；无快照（存量/黑盒）只显 repo 名 */}
        <TableCell
          className="max-w-0"
          title={scan.repo_commit ? scan.repo_commit.slice(0, 8) : scan.repo_url ?? undefined}
        >
          <span className="block truncate text-[13px] font-medium">
            {scan.repo ?? "—"}
            {scan.repo_branch && (
              <span className="font-mono text-[11px] text-muted-foreground">@{scan.repo_branch}</span>
            )}
          </span>
          {scan.repo_url && (
            <span className="block truncate font-mono text-[10.5px] text-muted-foreground/80">{compactUrl(scan.repo_url)}</span>
          )}
        </TableCell>
        {/* 类型格：correlation 主行显「跨仓关联」徽标（先于 combined 判——关联行跑过
            段③黑盒验证后 session 亦置 combined=True）；组合任务只显「组合」徽标——
            scan_type 底层仍为 whitebox（spec 2026-08-12 §6.2），whitebox+组合双徽标
            冗余，2026-08-17 起组合单显；MR 行显「MR」徽标 + base..head refs（spec
            2026-09-03 §6） */}
        <TableCell>
          {isCorr ? (
            <Badge variant="outline" className="border-primary/35 font-mono text-primary">
              {t("workspaceDetail.scans.typeCorrelation")}
            </Badge>
          ) : isMr ? (
            <div className="flex flex-col items-start gap-0.5">
              <Badge variant="outline" className="border-primary/35 font-mono text-primary">MR</Badge>
              {scan.mr_base_ref && scan.mr_head_ref && (
                <span
                  className="max-w-[160px] truncate font-mono text-[10.5px] text-muted-foreground/80"
                  title={`${scan.mr_base_ref}..${scan.mr_head_ref}`}
                >
                  {scan.mr_base_ref}..{scan.mr_head_ref}
                </span>
              )}
            </div>
          ) : scan.combined === true ? (
            <Badge variant="outline" className="border-primary/35 font-mono text-primary">
              {t("workspaceDetail.scans.typeCombined")}
            </Badge>
          ) : (
            <Badge variant="outline" className="font-mono">{scan.scan_type}</Badge>
          )}
        </TableCell>
        <TableCell>
          {isRunning ? (
            <div className="flex min-w-[110px] flex-col gap-1">
              <div className="flex items-baseline gap-1.5">
                <span className="font-mono text-[13px] font-semibold leading-none">{pct}%</span>
                <span className="whitespace-nowrap text-[11px] text-muted-foreground">
                  {scanSegmentLabel(scan, displayedPhase, t)}
                </span>
              </div>
              <span
                role="progressbar"
                aria-valuenow={pct}
                aria-valuemin={0}
                aria-valuemax={100}
                className="block h-1 w-full overflow-hidden rounded-full bg-muted"
              >
                <span className="block h-full rounded-full bg-primary transition-all" style={{ width: `${pct}%` }} />
              </span>
            </div>
          ) : scan.status === "completed" || scan.status === "done" ? (
            <span className="whitespace-nowrap font-mono text-xs text-muted-foreground">
              100%{dur && ` · ${t("workspaceDetail.scans.duration", { dur })}`}
            </span>
          ) : isTerminal ? (
            <span className="text-xs text-muted-foreground">—</span>
          ) : scan.progress_pct != null ? (
            <span className="whitespace-nowrap font-mono text-xs text-muted-foreground">
              {t("workspaceDetail.scans.stoppedAt", { pct })}
            </span>
          ) : (
            <span className="text-xs text-muted-foreground">—</span>
          )}
        </TableCell>
        <TableCell className="text-right">
          <span
            data-testid={`row-vulns-${scan.scan_id}`}
            className={`font-mono text-base font-semibold leading-none ${v > 0 ? "text-red" : "text-muted-foreground/70"}`}
          >
            {v}
          </span>
        </TableCell>
        <TableCell className="whitespace-nowrap text-right font-mono text-[13px]">
          {fmtCost(scan.total_cost_usd ?? null, scan.cost_currency ?? null)}
        </TableCell>
        <TableCell className="whitespace-nowrap font-mono text-xs text-muted-foreground" title={fmtTimeFull(scan.created_at)}>
          {fmtTime(scan.created_at)}
        </TableCell>
        {/* 操作组（预览 2026-08-15）：running=取消/查看/删除；未完成=恢复/查看/删除；
            终态=查看/重跑/删除（黑盒历史行无重跑——D4 删入口，ScanNewPage 已无黑盒表单）。
            容器 stopPropagation——按钮动作不触发整行导航。 */}
        <TableCell className="whitespace-nowrap pr-4 text-right">
          <div className="flex justify-end gap-1" onClick={(e) => e.stopPropagation()}>
            {canResume && (
              <Button size="sm" variant="ghost" onClick={onResume} disabled={busy}>
                <Play className="size-3.5" /> {t("workspaceDetail.scans.resume")}
              </Button>
            )}
            {isRunning && (
              <Button size="sm" variant="ghost" onClick={() => setPending("cancel")} disabled={busy}>
                <Ban className="size-3.5" /> {t("common.cancel")}
              </Button>
            )}
            <Button size="sm" variant="ghost" asChild>
              <Link
                to={`${scanPath}/${defaultTab}`}
                onClick={(e) => e.stopPropagation()}
              >
                <Eye className="size-3.5" /> {t("workspaceDetail.scans.view")}
              </Link>
            </Button>
            {isTerminal && scan.scan_type !== "blackbox" && (
              <Button size="sm" variant="ghost" onClick={onRerun} disabled={busy}>
                <RefreshCw className="size-3.5" /> {t("workspaceDetail.scans.rerun")}
              </Button>
            )}
            {/* 黑盒验证入口（2026-09-10 D3 入口回归）：白盒终态行直达 ScanNewPage 黑盒
                验证表单（任务预选 + 目标/认证预填由 getScan 承担）——列表层级恢复显式
                触发位，替代「进详情页找 header 小按钮」。口径同 ScanDetail whiteboxAddable
                （白盒 + completed/done/cancelled——failed 不给，后端产物门 422 兜底）。 */}
            {isTerminal && scan.scan_type === "whitebox" && (
              <Button size="sm" variant="ghost" onClick={() =>
                nav(`/scan/new?workspace=${encodeURIComponent(ws)}`, {
                  state: { type: "blackbox", workspace: ws, reuseScanId: scan.scan_id },
                })} disabled={busy}>
                <Crosshair className="size-3.5" /> {t("workspaceDetail.scans.runs.verifyBlackbox")}
              </Button>
            )}
            <Button
              size="sm"
              variant="ghost"
              className="text-destructive hover:bg-destructive/10"
              aria-label={t("common.delete")}
              title={t("common.delete")}
              onClick={() => setPending("delete")}
              disabled={busy}
            >
              <Trash2 className="size-3.5" />
            </Button>
          </div>
        </TableCell>
      </TableRow>

      {/* 嵌套展开子行（默认收起，点柄展开）。子行直接产出 TableRow（与主表同网格，
          见各组件注释）。correlation 主行展开序（D4）：现扫子仓白盒 → 黑盒验证 run
          （读主行 bb_runs，既有渲染复用）→ 复用子仓引用。组合任务只有黑盒 run 子行；
          纯白盒（无 bb_runs/corr_children）不渲染。 */}
      {open && expandable && (
        <>
          {freshChildren.length > 0 && (
            <NestedCorrChildren ws={ws} entries={freshChildren} scansById={scansById} />
          )}
          {hasRuns && (
            <NestedBlackboxRuns
              ws={ws}
              scanId={scan.scan_id}
              runs={scan.bb_runs!}
              latestRunId={scan.latest_bb_run ?? null}
              onChanged={onChanged}
            />
          )}
          {reusedChildren.length > 0 && (
            <NestedCorrChildren ws={ws} entries={reusedChildren} scansById={scansById} />
          )}
        </>
      )}

      {/* 取消/删除/续跑确认 Dialog（续跑 = 断点摘要确认流，§4.6） */}
      <Dialog open={!!pending} onOpenChange={(o) => !o && setPending(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {pending === "cancel"
                ? t("workspaceDetail.scans.cancelConfirmTitle")
                : pending === "resume"
                  ? t("workspaceDetail.scans.resumeConfirmTitle")
                  : t("workspaceDetail.scans.deleteConfirmTitle")}
            </DialogTitle>
            <DialogDescription>
              {pending === "cancel"
                ? t("workspaceDetail.scans.cancelConfirmDesc", { scanId: label })
                : pending === "resume"
                  ? (resumePreview?.resumable
                      ? (resumePreview.completed_agents.length > 0
                          ? t("workspaceDetail.scans.resumeSummary", {
                              count: resumePreview.completed_agents.length,
                              agents: resumePreview.completed_agents.join(" / "),
                              next: resumePreview.interrupted_agent ?? "—",
                              steps: resumePreview.steps.filter((x) => x.state === "done").length,
                            })
                          : t("workspaceDetail.scans.resumeNoSkip"))
                      : (resumePreview?.reason ?? ""))
                  : t("workspaceDetail.scans.deleteConfirmDesc", { scanId: label })}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setPending(null)}>{t("common.cancel")}</Button>
            <Button
              variant={pending === "resume" ? "default" : "destructive"}
              disabled={busy || (pending === "resume" && resumePreview?.resumable === false)}
              onClick={doAction}
            >
              {t("common.confirm")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

/** 版本化黑盒 run 嵌套子行（spec 2026-08-14 §5.2）：每个 run 渲染为真实 TableRow，遵守
 *  主表同一 colgroup 列语义——状态徽标→状态列、run_id→扫描列、「黑盒」→类型列、
 *  completed_at→时间列、查看/删除→操作列，与主行垂直对齐；无数据的列（仓库/进度/
 *  漏洞/成本）以弱「—」占位保网格。
 *  （2026-08-24 改版：旧版是 colSpan 大格内自由 flex 列表，元素全挤左侧、右侧 6 列空洞，
 *  与主表网格零对齐——不平衡的根源。）从属表达：柄列贯通竖线（父行展开时 border-b-0
 *  无缝相接）+ 子行弱底色/小半号字/紧凑行高的整体降级。整行可点（与「查看」同目标
 *  ?run= 选中）；终态 run 可删（运行中禁删，对齐后端 409）。 */
function NestedBlackboxRuns({ ws, scanId, runs, latestRunId, onChanged }: {
  ws: string; scanId: string; runs: BlackboxRunSummary[]; latestRunId: string | null; onChanged: () => void;
}) {
  const { t } = useTranslation();
  const nav = useNavigate();
  const [pendingDelete, setPendingDelete] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const runPath = (runId: string) => `/p/${ws}/scans/${scanId}?run=${runId}`;

  async function doDelete() {
    if (!pendingDelete) return;
    setBusy(true);
    try {
      await deleteBlackboxRun(ws, scanId, pendingDelete);
      toast.success(t("workspaceDetail.scans.runs.deleted", { runId: pendingDelete }));
      setPendingDelete(null);
      onChanged();
    } catch (e) {
      toast.error(t("workspaceDetail.scans.runs.deleteFailed", { error: msg(e) }));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      {runs.map((r, i) => {
        // 时间列 started_at ?? completed_at：任务级 bb_runs[] 条目实际只在终态并
        // completed_at（started_at 只写 run 级 session，不进条目），运行中无时间戳 → 「—」。
        const tsMs = r.started_at ? Date.parse(r.started_at) : (r.completed_at ? Date.parse(r.completed_at) : NaN);
        const tsUnix = Number.isFinite(tsMs) ? tsMs / 1000 : null;
        return (
          <TableRow
            key={r.run_id}
            data-testid={i === 0 ? "nested-runs" : undefined}
            onClick={() => nav(runPath(r.run_id))}
            className="cursor-pointer bg-muted/25 text-xs hover:bg-muted/45"
          >
            {/* 柄列：贯通从属竖线（与父行展开柄同列，行高全高；px-0 让线正落列中轴） */}
            <TableCell className="relative w-9 px-0 py-1.5">
              <span aria-hidden className="absolute inset-y-0 left-1/2 w-px bg-border" />
            </TableCell>
            <TableCell className="py-1.5">
              <StatusBadge status={(r.status ?? r.bb_phase ?? "unknown") as never} />
            </TableCell>
            <TableCell className="max-w-0 py-1.5">
              <span className="flex items-center gap-1.5">
                <Link
                  to={runPath(r.run_id)}
                  onClick={(e) => e.stopPropagation()}
                  className="truncate font-mono text-[12px] font-medium hover:text-primary"
                >
                  {r.run_id}
                </Link>
                {r.run_id === latestRunId && (
                  <span className="shrink-0 rounded-full border border-primary/35 px-1.5 py-px text-[10px] leading-4 text-primary">
                    {t("workspaceDetail.scans.runs.latest")}
                  </span>
                )}
              </span>
            </TableCell>
            {/* 黑盒 run 打的是 web 目标非仓库；漏洞/成本无 run 级数据 → 「—」占位保网格 */}
            <TableCell className="py-1.5"><span className="text-muted-foreground/50">—</span></TableCell>
            <TableCell className="py-1.5">
              <Badge variant="outline" className="font-mono text-[10.5px] text-muted-foreground">
                {t("workspaceDetail.scans.typeBlackbox")}
              </Badge>
            </TableCell>
            <TableCell className="py-1.5"><span className="text-muted-foreground/50">—</span></TableCell>
            <TableCell className="py-1.5 text-right"><span className="text-muted-foreground/50">—</span></TableCell>
            <TableCell className="py-1.5 text-right"><span className="text-muted-foreground/50">—</span></TableCell>
            <TableCell
              className="whitespace-nowrap py-1.5 font-mono text-[11px] text-muted-foreground"
              title={fmtTimeFull(tsUnix) || undefined}
            >
              {tsUnix ? fmtTime(tsUnix) : <span className="text-muted-foreground/50">—</span>}
            </TableCell>
            <TableCell className="whitespace-nowrap py-1.5 pr-4 text-right">
              <div className="flex items-center justify-end gap-1" onClick={(e) => e.stopPropagation()}>
                <Link
                  to={runPath(r.run_id)}
                  onClick={(e) => e.stopPropagation()}
                  className="text-[11.5px] text-primary hover:underline"
                >
                  {t("workspaceDetail.scans.runs.view")}
                </Link>
                <Button
                  size="icon"
                  variant="ghost"
                  className="size-6 text-muted-foreground hover:text-destructive"
                  aria-label={t("workspaceDetail.scans.runs.delete")}
                  disabled={!isRunTerminal(r.status)}
                  title={isRunTerminal(r.status) ? undefined : t("workspaceDetail.scans.runs.deleteRunningHint")}
                  onClick={(e) => { e.preventDefault(); e.stopPropagation(); setPendingDelete(r.run_id); }}
                >
                  <Trash2 className="size-3.5" />
                </Button>
              </div>
            </TableCell>
          </TableRow>
        );
      })}
      {/* 删除 run 确认 Dialog */}
      <Dialog open={!!pendingDelete} onOpenChange={(o) => !o && setPendingDelete(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("workspaceDetail.scans.runs.deleteConfirmTitle")}</DialogTitle>
            <DialogDescription>
              {t("workspaceDetail.scans.runs.deleteConfirmDesc", { runId: pendingDelete })}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setPendingDelete(null)} disabled={busy}>
              {t("common.cancel")}
            </Button>
            <Button variant="destructive" onClick={doDelete} disabled={busy}>
              {busy && <RefreshCw className="mr-1 size-3.5 animate-spin" />}
              {t("common.confirm")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

function msg(e: unknown): string {
  if (e instanceof ApiError) return String(e.status);
  return e instanceof Error ? e.message : String(e);
}

/** correlation 主行嵌套子行（D4，spec 2026-08-24 §8.2）：corr_children[] 逐条渲染为
 *  真实 TableRow，结构与 NestedBlackboxRuns 同款——遵守主表同一 colgroup 列语义
 *  （状态→状态列、任务名→扫描列、service→仓库列、白盒→类型列、漏洞数→漏洞列、
 *  created_at→时间列、查看→操作列），从属表达用柄列贯通竖线 + 子行弱底色/小半号字。
 *  富化：corr_children 只带 {service, scan_id, reused}，状态/漏洞数/时间从同 ws 全量
 *  列表按 scan_id 补（现扫子仓由后端建在同 ws，天然在列）；查不到（历史行被删）时
 *  弱「—」占位保网格，链接仍指该 scan。调用方按 reused 分两组渲染（现扫在前、复用
 *  引用殿后），复用行加「复用」标注与现扫行区分。行链接走裸 scan 路径——DefaultScanTab
 *  按目标 scan 状态落 report/live。 */
function NestedCorrChildren({ ws, entries, scansById }: {
  ws: string;
  entries: { service: string; scan_id: string; reused: boolean }[];
  scansById: Map<string, ScanSummary>;
}) {
  const { t } = useTranslation();
  const nav = useNavigate();
  return (
    <>
      {entries.map((c) => {
        const s = scansById.get(c.scan_id);
        const childPath = `/p/${ws}/scans/${c.scan_id}`;
        const label = s?.workflow_id ?? c.scan_id;
        const v = s?.vuln_count ?? null;
        return (
          <TableRow
            key={`${c.service}:${c.scan_id}`}
            data-testid={`corr-child-${c.scan_id}`}
            onClick={() => nav(childPath)}
            className="cursor-pointer bg-muted/25 text-xs hover:bg-muted/45"
          >
            {/* 柄列：贯通从属竖线（与父行展开柄同列，行高全高；px-0 让线正落列中轴） */}
            <TableCell className="relative w-9 px-0 py-1.5">
              <span aria-hidden className="absolute inset-y-0 left-1/2 w-px bg-border" />
            </TableCell>
            <TableCell className="py-1.5">
              {s ? <StatusBadge status={s.status} /> : <span className="text-muted-foreground/50">—</span>}
            </TableCell>
            <TableCell className="max-w-0 py-1.5">
              <span className="flex items-center gap-1.5">
                <Link
                  to={childPath}
                  onClick={(e) => e.stopPropagation()}
                  className="truncate font-mono text-[12px] font-medium hover:text-primary"
                >
                  {label}
                </Link>
                {c.reused && (
                  <span className="shrink-0 rounded-full border border-primary/35 px-1.5 py-px text-[10px] leading-4 text-primary">
                    {t("workspaceDetail.scans.corr.reused")}
                  </span>
                )}
              </span>
            </TableCell>
            {/* 仓库格 = service 名（提交子仓即以 service 建扫描，仓库名同源） */}
            <TableCell className="max-w-0 py-1.5">
              <span className="block truncate text-[12px] font-medium">{c.service}</span>
            </TableCell>
            <TableCell className="py-1.5">
              <Badge variant="outline" className="font-mono text-[10.5px] text-muted-foreground">
                {t("workspaceDetail.scans.typeWhitebox")}
              </Badge>
            </TableCell>
            {/* 进度/成本无子行级数据 → 「—」占位保网格 */}
            <TableCell className="py-1.5"><span className="text-muted-foreground/50">—</span></TableCell>
            <TableCell className="py-1.5 text-right">
              {v != null ? (
                <span
                  data-testid={`corr-child-vulns-${c.scan_id}`}
                  className={`font-mono text-[13px] font-semibold leading-none ${v > 0 ? "text-red" : "text-muted-foreground/70"}`}
                >
                  {v}
                </span>
              ) : (
                <span data-testid={`corr-child-vulns-${c.scan_id}`} className="text-muted-foreground/50">—</span>
              )}
            </TableCell>
            <TableCell className="py-1.5 text-right"><span className="text-muted-foreground/50">—</span></TableCell>
            <TableCell
              className="whitespace-nowrap py-1.5 font-mono text-[11px] text-muted-foreground"
              title={s ? fmtTimeFull(s.created_at) || undefined : undefined}
            >
              {s ? fmtTime(s.created_at) : <span className="text-muted-foreground/50">—</span>}
            </TableCell>
            <TableCell className="whitespace-nowrap py-1.5 pr-4 text-right">
              <div className="flex items-center justify-end gap-1" onClick={(e) => e.stopPropagation()}>
                <Link
                  to={childPath}
                  onClick={(e) => e.stopPropagation()}
                  className="text-[11.5px] text-primary hover:underline"
                >
                  {t("workspaceDetail.scans.view")}
                </Link>
              </div>
            </TableCell>
          </TableRow>
        );
      })}
    </>
  );
}
