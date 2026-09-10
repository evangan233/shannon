import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Outlet, useParams, useLocation, useNavigate, Link, useSearchParams } from "react-router-dom";
import { ArrowLeft, RefreshCw, Plus, Trash2, CheckCircle2, PlayCircle, Circle } from "lucide-react";
import { toast } from "sonner";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import { StatusBadge } from "@/components/StatusBadge";
import { rerunBlackbox, addBlackboxToWhitebox, deleteBlackboxRun, resumeScan,
         getResumePreview, ApiError, type ResumePreview } from "@/api/client";
import type { BlackboxRunSummary } from "@/api/types";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { runStatusLabelKey, isRunFailureStatus, isRunTerminal, RunFailureBanner } from "./runStatus";
import { ScanProgressOverview } from "./ScanProgressOverview";
import { useScanDetail } from "./useScanDetail";

// per-scan 视图的 tab 集：只含 scan 级 tab（overview/report/deliverables/logs/live）。
// repos/settings 是 ws 级，留在 ws 概览页入口，不进 scan tabs。
const SCAN_TABS = [
  { value: "overview", labelKey: "workspaceDetail.tabs.overview" },
  { value: "report", labelKey: "workspaceDetail.tabs.report" },
  { value: "evidence", labelKey: "workspaceDetail.tabs.evidence" },
  { value: "deliverables", labelKey: "workspaceDetail.tabs.deliverables" },
  { value: "dataflow", labelKey: "workspaceDetail.tabs.dataflow" },
  { value: "logs", labelKey: "workspaceDetail.tabs.logs" },
  { value: "live", labelKey: "workspaceDetail.tabs.live" },
] as const;

// correlation 主行 tab 组（D6，spec 2026-08-24 §8；2026-09-10 增 live）：概览 | 跨仓
// 关联 | 产物 | 日志 | 实时——无 report/dataflow：关联结果在专属「跨仓关联」tab。live =
// 段②关联编排（correlation_progress 的 CORR 行）+ 段③黑盒验证 run 日志（归并流自动
// 纳入 run-K）；段①现扫子仓日志在子行自己的 live 看，不进主行流。顶部
// ScanProgressOverview（correlation_progress 经 dashboardReducer 渲染网格）照常全 tab 常驻。
const CORRELATION_SCAN_TABS = [
  { value: "overview", labelKey: "workspaceDetail.tabs.overview" },
  { value: "correlation", labelKey: "workspaceDetail.tabs.correlation" },
  { value: "deliverables", labelKey: "workspaceDetail.tabs.deliverables" },
  { value: "logs", labelKey: "workspaceDetail.tabs.logs" },
  { value: "live", labelKey: "workspaceDetail.tabs.live" },
] as const;

/** ApiError → 可读文案：优先 body.detail（后端 ValueError 的 str，如「白盒产物未就绪」），
 *  pydantic 校验数组取首条 msg；兜底 HTTP 状态码（ApiError.message 只是 "API 422"）。 */
function apiErrMsg(e: unknown): string {
  if (e instanceof ApiError) {
    const d = (e.body as { detail?: unknown } | null)?.detail;
    if (typeof d === "string") return d;
    if (Array.isArray(d) && d.length) {
      const first = d[0] as { msg?: unknown } | undefined;
      return String(first?.msg ?? e.status);
    }
    return String(e.status);
  }
  return e instanceof Error ? e.message : String(e);
}

// === 组合扫描段状态时间线（spec 2026-08-12 §9 / §11.3）===
// 详情页：白盒段 + 黑盒段两个时间段的状态（靠 bb_phase 切段），黑盒 failed 时附「续扫黑盒」。
// 步级 / Agent 实时进度在顶部 ScanProgressOverview（全 tab 常驻），此处不再重复渲染步级。
// 纯白盒/纯黑盒（combined!=true）不渲染此组件——零回归。

function segStatusKey(bbPhase: string | null | undefined, segment: "whitebox" | "blackbox"): string {
  // 白盒段：precheck/pending 进行中；之后（黑盒已起或跳过）= 已完成。
  // 黑盒段：直接映射 bb_phase；未到 running 为待接力。
  if (segment === "whitebox") {
    return bbPhase === "precheck" || bbPhase === "pending"
      ? "workspaceDetail.scans.combined.segStatusInProgress"
      : "workspaceDetail.scans.combined.segStatusDone";
  }
  switch (bbPhase) {
    case "running": return "workspaceDetail.scans.combined.segStatusInProgress";
    case "completed": return "workspaceDetail.scans.combined.segStatusDone";
    case "failed": return "workspaceDetail.scans.combined.segStatusFailed";
    case "skipped": return "workspaceDetail.scans.combined.segStatusSkipped";
    default: return "workspaceDetail.scans.combined.segStatusPending"; // precheck/pending/unknown
  }
}

function CombinedDetailTimeline({
  ws, scanId, bbPhase, runGaps, onRerunDone,
}: {
  ws: string; scanId: string; bbPhase?: string | null;
  // 选中 run 的验证缺口信号（scan_manager 落 run session、bb_runs[] 条目透传；
  // {vulnClass: gapCount}）。completed + 缺口 → 续跑放行（spec 2026-09-03 §7）。
  runGaps?: Record<string, number> | null;
  onRerunDone: () => void;
}) {
  const { t } = useTranslation();
  const [showRerun, setShowRerun] = useState(false);
  const [busy, setBusy] = useState(false);

  const blackboxFailed = bbPhase === "failed";
  const hasVerificationGaps = bbPhase === "completed"
    && !!runGaps && Object.keys(runGaps).length > 0;
  const canRerun = blackboxFailed || hasVerificationGaps;

  async function doRerun() {
    setBusy(true);
    try {
      await rerunBlackbox(ws, scanId);
      toast.success(t("workspaceDetail.scans.combined.rerunSuccess"));
      setShowRerun(false);
      onRerunDone(); // 刷新 summary：bb_phase failed → running
    } catch (e) {
      toast.error(t("workspaceDetail.scans.combined.rerunFailed", {
        error: e instanceof ApiError ? String(e.status) : e instanceof Error ? e.message : String(e),
      }));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="rounded-md border border-border bg-card p-3 space-y-2">
      <div className="text-xs font-medium text-muted-foreground">
        {t("workspaceDetail.scans.combined.detailTimelineTitle")}
      </div>
      {/* 白盒段 */}
      <div className="flex items-center gap-2 text-sm" data-testid="combined-segment-whitebox">
        <span className="font-medium">{t("workspaceDetail.scans.combined.segmentWhitebox")}</span>
        <span className="text-xs text-muted-foreground">{t(segStatusKey(bbPhase, "whitebox"))}</span>
      </div>
      {/* 黑盒段（+ 失败/验证缺口时续跑按钮）*/}
      <div className="flex items-center gap-2 text-sm" data-testid="combined-segment-blackbox">
        <span className="font-medium">{t("workspaceDetail.scans.combined.segmentBlackbox")}</span>
        <span className="text-xs text-muted-foreground">{t(segStatusKey(bbPhase, "blackbox"))}</span>
        {hasVerificationGaps && (
          <span data-testid="run-verification-gaps" className="text-xs text-amber">
            {t("workspaceDetail.scans.combined.rerunGapsHint", {
              count: Object.values(runGaps!).reduce((a, b) => a + b, 0),
            })}
          </span>
        )}
        {canRerun && (
          <Button size="sm" variant="outline" onClick={() => setShowRerun(true)} disabled={busy}>
            <RefreshCw className="size-3.5" /> {t("workspaceDetail.scans.combined.rerunBlackbox")}
          </Button>
        )}
      </div>
      {/* 续扫确认弹窗（simple confirm + POST，沿用原认证，spec §11.3 v1）*/}
      <Dialog open={showRerun} onOpenChange={(o) => !o && setShowRerun(false)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("workspaceDetail.scans.combined.rerunConfirmTitle")}</DialogTitle>
            <DialogDescription>{t("workspaceDetail.scans.combined.rerunConfirmDesc")}</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setShowRerun(false)}>{t("common.cancel")}</Button>
            <Button onClick={doRerun} disabled={busy}>{t("common.confirm")}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

// 白盒编排顺序（对齐后端 whitebox_resume._AGENT_ORDER）：续跑详情卡据此渲染
// 全量 agent 三态（✅ 已完成 / ▶ 将从此继续 / ⏳ 未跑到）——preview 响应只带
// completed/interrupted 两集合，全序由前端静态持有（agent 集稳定）。
const BREAKPOINT_AGENT_ORDER = [
  "pre-recon", "recon", "injection-vuln", "xss-vuln", "auth-vuln", "ssrf-vuln", "authz-vuln",
] as const;

const BREAKPOINT_STEP_LABEL: Record<string, string> = {
  done: "workspaceDetail.scans.breakpointStepDone",
  stale: "workspaceDetail.scans.breakpointStepStale",
  missing: "workspaceDetail.scans.breakpointStepMissing",
};

/** 续跑详情卡（spec 2026-08-27-web-resume-breakpoint §4.6；2026-09-09 由「断点详情」
 *  改名——全程阶段到哪了已由常驻 ScanPhaseRail 承担，本卡专注续跑细节）：非
 *  completed/running 的白盒行展示 agent 三态 + 步骤缓存简表 + warnings + 续跑按钮
 *  （确认流与列表页同款：摘要弹窗 → POST resume → 跳 live）。resumable:false 直示
 *  原因（引导重跑）。 */
function ResumeBreakpointCard({ ws, scanId, onResumed }: {
  ws: string; scanId: string; onResumed: () => void;
}) {
  const { t } = useTranslation();
  const nav = useNavigate();
  const [preview, setPreview] = useState<ResumePreview | null>(null);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let alive = true;
    let timer: ReturnType<typeof setInterval> | undefined;
    const stopPolling = () => { if (timer) { clearInterval(timer); timer = undefined; } };
    const fetchPreview = () => {
      getResumePreview(ws, scanId)
        .then((p) => {
          if (!alive) return;
          setPreview(p);
          // 取消收尾窗口的瞬态不可续（心跳判活未过期）：10s 轮询重拉，窗口一过
          // resumable:true → 按钮自动出现；非瞬态（race/abort/可续）停轮询——旧实现在
          // 此一次性拉取，把 ≤90s 的瞬态窗口固化成「永远不可续跑」。
          stopPolling();
          if (!p.resumable && p.transient) {
            timer = setInterval(fetchPreview, 10_000);
          }
        })
        .catch(() => { /* preview 拉取失败静默：列表页入口仍是主路径 */ });
    };
    fetchPreview();
    return () => { alive = false; stopPolling(); };
  }, [ws, scanId]);

  if (!preview) return null;

  async function doResume() {
    setBusy(true);
    try {
      await resumeScan(ws, scanId);
      toast.success(t("workspaceDetail.scans.resumed"));
      setConfirmOpen(false);
      onResumed();
      nav("live");
    } catch (e) {
      toast.error(t("workspaceDetail.scans.resumeFailed", { error: apiErrMsg(e) }));
    } finally {
      setBusy(false);
    }
  }

  const completed = new Set(preview.completed_agents);
  const doneSteps = preview.steps.filter((s) => s.state === "done").length;
  return (
    <div className="rounded-md border border-border bg-card p-3 space-y-2" data-testid="resume-breakpoint">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="text-xs font-medium text-muted-foreground">
          {t("workspaceDetail.scans.breakpointTitle")}
        </div>
        {preview.resumable && (
          <Button size="sm" variant="outline" onClick={() => setConfirmOpen(true)} disabled={busy}>
            <PlayCircle className="size-3.5" /> {t("workspaceDetail.scans.resume")}
          </Button>
        )}
      </div>
      {!preview.resumable ? (
        <div className="text-sm text-muted-foreground">
          {preview.reason ?? preview.abort_reason}
        </div>
      ) : (
        <>
          <div className="flex flex-wrap gap-x-4 gap-y-1 text-[13px]">
            {BREAKPOINT_AGENT_ORDER.map((a) => {
              if (completed.has(a)) {
                return (
                  <span key={a} className="inline-flex items-center gap-1 text-muted-foreground">
                    <CheckCircle2 className="size-3.5 text-emerald-500" aria-hidden /> {a}
                  </span>
                );
              }
              if (a === preview.interrupted_agent) {
                return (
                  <span key={a} className="inline-flex items-center gap-1 font-medium text-primary">
                    <PlayCircle className="size-3.5" aria-hidden /> {a}
                    <span className="text-[11px] font-normal opacity-80">
                      {t("workspaceDetail.scans.breakpointNextLabel")}
                    </span>
                  </span>
                );
              }
              return (
                <span key={a} className="inline-flex items-center gap-1 text-muted-foreground/60">
                  <Circle className="size-3.5" aria-hidden /> {a}
                  <span className="text-[11px] opacity-80">{t("workspaceDetail.scans.breakpointNotRun")}</span>
                </span>
              );
            })}
          </div>
          <div className="flex flex-wrap gap-x-3 gap-y-1 text-xs text-muted-foreground">
            {preview.steps.map((s) => (
              <span key={s.step} className="font-mono">
                {s.step}
                <span className="ml-1 opacity-70">
                  {t(BREAKPOINT_STEP_LABEL[s.state] ?? s.state)}
                </span>
              </span>
            ))}
          </div>
          {preview.warnings.length > 0 && (
            <ul className="space-y-0.5 text-xs text-muted-foreground">
              {preview.warnings.map((w, i) => <li key={i}>· {w}</li>)}
            </ul>
          )}
        </>
      )}
      {/* 续跑确认弹窗（摘要与列表页同款文案） */}
      <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("workspaceDetail.scans.resumeConfirmTitle")}</DialogTitle>
            <DialogDescription>
              {preview.completed_agents.length > 0
                ? t("workspaceDetail.scans.resumeSummary", {
                    count: preview.completed_agents.length,
                    agents: preview.completed_agents.join(" / "),
                    next: preview.interrupted_agent ?? "—",
                    steps: doneSteps,
                  })
                : t("workspaceDetail.scans.resumeNoSkip")}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setConfirmOpen(false)} disabled={busy}>
              {t("common.cancel")}
            </Button>
            <Button onClick={doResume} disabled={busy}>
              {busy && <RefreshCw className="mr-1 size-3.5 animate-spin" />}
              {t("common.confirm")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

/**
 * per-scan 布局：scan header（scan_id + status + scan_type + 返回 ws）+ scan tabs + Outlet。
 * 数据源全 scan-scoped（getScan / scanReportPath / scanEventsUrl ...），见各 Tab 组件。
 * scan 操作（取消/删除/恢复/重跑）在 ws 概览页扫描卡片，此处只展示。
 * 组合扫描（combined=true）：header 下渲染两段时间线 + 黑盒失败续跑入口。
 */
export default function ScanDetail() {
  const { t } = useTranslation();
  const { workspace, scanId } = useParams<{ workspace: string; scanId: string }>();
  const { pathname } = useLocation();
  const navigate = useNavigate();
  // 当前 tab = 路径末段（.../scans/:scanId/<tab>）。index 路由无 tab 段时由
  // DefaultScanTab 立即 replace 跳 live/report，此处 pop=scanId 为瞬时态（无高亮）。
  const current = pathname.split("/").pop() ?? "live";
  // SWR 数据层（2026-08-17 批次 Task 2）：key ["scan", ws, id] 与 OverviewTab /
  // ReportTab(combined 探测) 共享 → 详情页三处 getScan 合一。refresh 即 silent
  // revalidate（不翻 loading、不卸载 ScanProgressOverview——其 endedFor 的
  // scan_end 一次性通知 ref 随卸载销毁会致死循环刷新，见 ScanProgressOverview）。
  const { data: meta, loading, refresh: load } = useScanDetail(workspace, scanId);

  const status = meta?.status ?? meta?.session?.status ?? "running";
  const isCombined = meta?.combined === true;
  // correlation 主行（D6）：tab 组按 scan_type 分支（概览/跨仓关联/产物/日志）；
  // 两段式组合时间线不渲染——关联是三段接力（子仓白盒→关联→黑盒验证），两段
  // 「白盒段/黑盒段」标签会错述语义，专属三段横幅在概览 tab 的 CorrelationOverview。
  const isCorrelation = meta?.scan_type === "correlation";
  const scanTabs = isCorrelation ? CORRELATION_SCAN_TABS : SCAN_TABS;
  // 版本化黑盒 run（spec 2026-08-14 §5.2）：?run= 选中（默认 latest_bb_run），供 ReportTab/
  // DeliverablesTab 按 run 切黑盒/融合产物。终端态白盒任务提供「加黑盒」入口（建下一个 run）。
  const [searchParams, setSearchParams] = useSearchParams();
  const runs = meta?.bb_runs ?? [];
  const selectedRun = searchParams.get("run") ?? meta?.latest_bb_run ?? null;
  const selectedRunObj: BlackboxRunSummary | null =
    runs.find((r) => r.run_id === selectedRun) ?? null;
  const [addBbOpen, setAddBbOpen] = useState(false);
  const [addBbBusy, setAddBbBusy] = useState(false);
  const [deleteRunOpen, setDeleteRunOpen] = useState(false);
  const [deleteRunBusy, setDeleteRunBusy] = useState(false);
  // 加黑盒入口的可见条件：白盒产物已终态的任务（completed/done，或 cancelled——取消过
  // 手动黑盒 run 的任务白盒产物仍完好）。run 运行中任务级 status=running（后端
  // _add_blackbox_run 把任务级标 running），按钮随 status 自然隐藏；下方 runs 非终态门
  // 是 legacy 数据（任务级停终态但 run 未收口）的兜底。后端 _whitebox_deliverables_ready 422 兜底。
  const whiteboxAddable =
    meta?.scan_type === "whitebox" && ["completed", "done", "cancelled"].includes(status);
  // 加黑盒前置门（后端 422 兜底，前端先拦免空跑）：无目标 URL（纯白盒任务，黑盒无目标
  // 可打）不可加；任一 run 非终态不可叠加（legacy 状态兜底，正常路径按钮已隐藏）。
  const addBbBlockedBy = !meta?.web_url
    ? t("workspaceDetail.scans.runs.addNoUrlHint")
    : runs.some((r) => !isRunTerminal(r.status))
      ? t("workspaceDetail.scans.runs.addRunningHint")
      : null;

  const submitAddBlackbox = async () => {
    if (!workspace || !scanId) return;
    setAddBbBusy(true);
    try {
      const r = await addBlackboxToWhitebox(workspace, scanId, {});
      toast.success(t("workspaceDetail.scans.runs.addedSuccess"));
      setAddBbOpen(false);
      setSearchParams({ run: r.run_id });
      load();
    } catch (e) {
      toast.error(t("workspaceDetail.scans.runs.addedFailed", { error: apiErrMsg(e) }));
    } finally {
      setAddBbBusy(false);
    }
  };

  // 删除当前选中 run（spec §7.1 #4）：终态可删，运行中禁用（后端 409 兜底）。
  // 删的即当前选中 → 回退 run 选择（清 ?run=，load 后 selectedRun 回落到 latest_bb_run）。
  const submitDeleteRun = async () => {
    if (!workspace || !scanId || !selectedRun) return;
    setDeleteRunBusy(true);
    try {
      await deleteBlackboxRun(workspace, scanId, selectedRun);
      toast.success(t("workspaceDetail.scans.runs.deleted", { runId: selectedRun }));
      setDeleteRunOpen(false);
      setSearchParams((prev) => { prev.delete("run"); return prev; });
      load();
    } catch (e) {
      toast.error(t("workspaceDetail.scans.runs.deleteFailed", {
        error: e instanceof ApiError ? String(e.status) : e instanceof Error ? e.message : String(e),
      }));
    } finally {
      setDeleteRunBusy(false);
    }
  };

  // live/logs tab：根容器走 flex 链，高度 = 视口 - 固定的 TopBar(h-12=3rem) + main(py-5=2.5rem) = 5.5rem
  // （这俩不换行、精确可靠，非对 header 的估值）；header/时间线/sticky 进度块用 shrink-0 保持自然高
  // （窄屏 flex-wrap 换行也由 flex 自动吸收），Outlet 容器 flex-1 min-h-0 吃剩余空间 -> tab 内容动态
  // 填满、不溢出视口、无外层滚动条。其余 tab（overview/report/deliverables/dataflow）保持 space-y-4 流式
  // （依赖 window 滚，如 ReportTab TOC scroll-spy / DataFlowTab 两栏），进度概览+tabs 走 sticky 固定（见下）。
  const isFlexLayout = current === "live" || current === "logs";

  return (
    <div className={isFlexLayout ? "flex h-[calc(100dvh-5.5rem)] flex-col gap-4" : "space-y-4"}>
      <div className={`space-y-2${isFlexLayout ? " shrink-0" : ""}`}>
        <Link
          to={`/p/${workspace}`}
          className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-primary"
        >
          <ArrowLeft className="size-3.5" /> {t("workspaceDetail.backToWs", { ws: workspace })}
        </Link>
        <div className="flex flex-wrap items-center gap-3">
          <h2 className="font-mono text-xl">{meta?.workflow_id ?? scanId}</h2>
          {loading ? (
            <Skeleton className="h-5 w-40" />
          ) : (
            <>
              <StatusBadge status={status} />
              {meta?.scan_type && (
                <Badge variant="outline" className="font-mono">{meta.scan_type}</Badge>
              )}
              {meta?.repo_path && (
                <span className="font-mono text-sm text-muted-foreground">{meta.repo_path}</span>
              )}
            </>
          )}
          {/* 版本化黑盒 run 选择器（spec 2026-08-14 §5.2）：组合任务多 run 时切换查看。 */}
          {isCombined && runs.length > 0 && (
            <select
              aria-label={t("workspaceDetail.scans.runs.select")}
              className="h-8 rounded-md border border-input bg-background px-2 text-sm"
              value={selectedRun ?? ""}
              onChange={(e) => setSearchParams(e.target.value ? { run: e.target.value } : {})}
            >
              {runs.map((r) => {
                const labelKey = runStatusLabelKey(r.status);
                // status 后缀优先于「最新」：终态/运行中状态比 latest 标记更有信息量。
                const suffix = labelKey
                  ? ` · ${t(labelKey)}`
                  : r.run_id === meta?.latest_bb_run
                    ? ` · ${t("workspaceDetail.scans.runs.latest")}`
                    : "";
                return (
                  <option key={r.run_id} value={r.run_id}>
                    {r.run_id}{suffix}
                  </option>
                );
              })}
            </select>
          )}
          {/* 删除选中 run（spec §7.1 #4）：仅终态可删，运行中禁用（后端 409 兜底）。 */}
          {isCombined && runs.length > 0 && selectedRun && selectedRunObj && (
            <Button
              size="sm"
              variant="outline"
              onClick={() => setDeleteRunOpen(true)}
              disabled={deleteRunBusy || !isRunTerminal(selectedRunObj.status)}
              title={!isRunTerminal(selectedRunObj.status)
                ? t("workspaceDetail.scans.runs.deleteRunningHint") : undefined}
            >
              <Trash2 className="size-3.5" /> {t("workspaceDetail.scans.runs.delete")}
            </Button>
          )}
          {/* 加黑盒入口（spec §6）：白盒产物已终态的任务可新建黑盒 run（纯白盒→首个 run；
              已 combined→下一个 run）。无目标 URL / run 在跑时禁用（后端 422 兜底）。 */}
          {whiteboxAddable && (
            <Button size="sm" variant="outline" onClick={() => setAddBbOpen(true)}
              disabled={!!addBbBlockedBy} title={addBbBlockedBy ?? undefined}>
              <Plus className="size-3.5" /> {t("workspaceDetail.scans.runs.addBlackbox")}
            </Button>
          )}
        </div>
      </div>
      {/* 组合扫描两段时间线（spec §9/§11.3）+ 选中 run 失败横幅（spec 2026-08-14 可见性）：
          静态上下文，随页滚动；shrink-0 以兼容 live/logs flex 链。
          correlation 主行不渲染（见 isCorrelation 注释——三段语义在概览 tab）。 */}
      {isCombined && !isCorrelation && !loading && (
        <div className={isFlexLayout ? "shrink-0" : ""}>
          <CombinedDetailTimeline
            ws={workspace!} scanId={scanId!} bbPhase={meta?.bb_phase}
            runGaps={selectedRunObj?.verification_gaps} onRerunDone={load}
          />
        </div>
      )}
      {/* 续跑详情卡（spec 2026-08-27 §4.6）：非 completed/running 白盒行（含组合）
          展示 agent 三态 + 步骤缓存 + 续跑入口；correlation/blackbox 无此区块。 */}
      {!loading && meta && meta.scan_type === "whitebox"
        && !["completed", "done", "running"].includes(status) && (
        <div className={isFlexLayout ? "shrink-0" : ""}>
          <ResumeBreakpointCard ws={workspace!} scanId={scanId!} onResumed={load} />
        </div>
      )}
      {isCombined && selectedRunObj && isRunFailureStatus(selectedRunObj.status) &&
        selectedRunObj.reason && (
        <div className={isFlexLayout ? " shrink-0" : ""}>
          <RunFailureBanner
            reason={selectedRunObj.reason} ws={workspace ?? undefined}
            detail={selectedRunObj.bb_failure_detail} />
        </div>
      )}
      {/* 任务级失败横幅：precheck（t0 认证预验证）失败没有 bb_runs，run 级横幅不触发，
          用户只看到「失败」徽章 + "combined failed"。有 bb_reason 即展示（分类 + 原始
          detail），run 级横幅已在展示时跳过避免重复。 */}
      {!loading && ["failed", "crashed", "killed"].includes(status) && meta?.bb_reason &&
        !(isCombined && selectedRunObj && isRunFailureStatus(selectedRunObj.status) &&
          selectedRunObj.reason) && (
        <div className={isFlexLayout ? " shrink-0" : ""}>
          <RunFailureBanner
            reason={meta.bb_reason} ws={workspace ?? undefined}
            detail={meta.bb_failure_detail} />
        </div>
      )}
      {/* 假完成警告横幅（2026-08-27 NodeGoat 事故最后防线）：completed 但白盒从未
          启动（期望 agent>0 且 0 完成）——收口异常把「从未开始」标成「已完成」，
          报告全空且 completed 不可续跑。后端已有 reconcile 分流 + _ensure_scan_end
          保险丝两道防线，此处兜历史数据/未来漏网路径。 */}
      {!loading && status === "completed" && isCombined &&
        (meta?.expected_agents?.whitebox ?? 0) > 0 &&
        (meta?.completed_agents?.length ?? 0) === 0 && (
        <div
          role="alert"
          data-testid="fake-completed-banner"
          className={`rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-sm text-amber-700 dark:text-amber-400${isFlexLayout ? " shrink-0" : ""}`}
        >
          <div className="font-medium">{t("workspaceDetail.scans.fakeCompleted.title")}</div>
          <div className="mt-0.5 text-xs opacity-90">
            {t("workspaceDetail.scans.fakeCompleted.hint", {
              done: 0, total: meta?.expected_agents?.whitebox ?? 0 })}
          </div>
        </div>
      )}
      {/* 进度概览 + scan tabs 合成一个 sticky 块固定在 TopBar 下沿（top-12）：overview/report/
          deliverables 靠 window 滚动，固定后长内容滚动时当前阶段/步级/Agent 进度始终可见
          （spec 进度两层粒度 · 详情页细粒度；组合黑盒段自动读选中 run 的 events）。
          bg-background 遮住从块底滚过的内容。live/logs 走 flex 链、无页面滚动，sticky 不触发，
          shrink-0 保持自然高。 */}
      <div
        data-testid="scan-sticky-header"
        className={`sticky top-12 z-30 space-y-4 bg-background pb-2 print:static${isFlexLayout ? " shrink-0" : ""}`}
      >
        {!loading && meta && (
          <ScanProgressOverview
            ws={workspace!} scanId={scanId!} runsCount={runs.length}
            onScanEnd={() => load()}
            scanType={meta.scan_type}
          />
        )}
        <Tabs value={current} onValueChange={(v) => navigate(v)}>
          <div data-testid="scan-tabs-sticky">
            <TabsList>
              {scanTabs.map((tab) => (
                <TabsTrigger key={tab.value} value={tab.value}>{t(tab.labelKey)}</TabsTrigger>
              ))}
            </TabsList>
          </div>
        </Tabs>
      </div>
      <div className={isFlexLayout ? "min-h-0 flex-1 overflow-hidden" : undefined}><ErrorBoundary key={current}><Outlet context={{ selectedRun, runSummary: selectedRunObj, combined: meta?.combined ?? null, bbPhase: meta?.bb_phase ?? null, runsCount: runs.length, scanType: meta?.scan_type ?? null }} /></ErrorBoundary></div>

      {/* 加黑盒确认 Dialog（空 body = 无认证直连；后续可扩认证/HOST 选择） */}
      <Dialog open={addBbOpen} onOpenChange={setAddBbOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("workspaceDetail.scans.runs.addBlackbox")}</DialogTitle>
            <DialogDescription>{t("workspaceDetail.scans.runs.addBlackboxDesc")}</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setAddBbOpen(false)} disabled={addBbBusy}>
              {t("common.cancel")}
            </Button>
            <Button onClick={submitAddBlackbox} disabled={addBbBusy}>
              {addBbBusy && <RefreshCw className="mr-1 size-3.5 animate-spin" />}
              {t("common.confirm")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      {/* 删除 run 确认 Dialog */}
      <Dialog open={deleteRunOpen} onOpenChange={setDeleteRunOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("workspaceDetail.scans.runs.deleteConfirmTitle")}</DialogTitle>
            <DialogDescription>
              {t("workspaceDetail.scans.runs.deleteConfirmDesc", { runId: selectedRun })}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setDeleteRunOpen(false)} disabled={deleteRunBusy}>
              {t("common.cancel")}
            </Button>
            <Button variant="destructive" onClick={submitDeleteRun} disabled={deleteRunBusy}>
              {deleteRunBusy && <RefreshCw className="mr-1 size-3.5 animate-spin" />}
              {t("common.confirm")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
