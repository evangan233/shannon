import { useEffect, useState, useRef, useMemo } from "react";
import { useParams } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import { deleteRepo, deleteRepos, pullRepo, checkoutRepo, ApiError } from "@/api/client";
import { useRepos } from "@/api/useRepos";
import { useAuth } from "@/auth/AuthContext";
import type { Repo, RepoState } from "@/api/types";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Checkbox } from "@/components/ui/checkbox";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { StatRow, type StatItem } from "@/components/StatRow";
import { CheckCircle2, XCircle, AlertTriangle, RefreshCw, Trash2, Unlink, FolderX } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";
import { AddRepoDialog } from "@/components/AddRepoDialog";
import { BranchCombobox } from "@/components/BranchCombobox";
import { CloneProgress } from "@/components/CloneProgress";
import { CopyButton } from "@/components/CopyButton";

const PULL_REFRESH_DELAY_MS = 1500;

// 分组筛选值（2026-09-16）："all"=全部；GROUP_UNGROUPED=未分组档（group 为 null 的扁平仓）；
// 其余 = 组名本身。后端组名是单段目录名（不含 /），与哨兵值无碰撞。
const GROUP_ALL = "all";
const GROUP_UNGROUPED = "__ungrouped__";

function fmtSize(b?: number) {
  if (!b) return "-";
  if (b > 1_000_000) return `${(b / 1_000_000).toFixed(1)} MB`;
  if (b > 1000) return `${(b / 1000).toFixed(0)} KB`;
  return `${b} B`;
}

// 状态 -> 徽章 i18n key/色/图标（对齐 StatusBadge 的 DSF token 配色）。
// 状态符号用 lucide 图标（非 emoji），文本在 i18n repos.states.*（就绪/失败/未完成）；
// cloning/pulling 走 CloneProgress（含进度条 + "clone 中"），不经此 Badge。
// 2026-09-10 容器同步 StatusBadge soft-tint 状态灯（tint 底 + 全主题胶囊 + sans
// font-medium——状态=语义层，与类型列 mono 技术层分层），扫描列表/仓库页同一套语言。
const STATE_BADGE: Record<RepoState, { key: string; cls: string; Icon: LucideIcon }> = {
  ready:   { key: "repos.states.ready",   cls: "border-green/25 bg-green/10 text-green",   Icon: CheckCircle2 },
  failed:  { key: "repos.states.failed",  cls: "border-red/25 bg-red/10 text-red",         Icon: XCircle },
  stale:   { key: "repos.states.stale",   cls: "border-yellow/25 bg-yellow/10 text-yellow", Icon: AlertTriangle },
  cloning: { key: "repos.states.cloning", cls: "border-cyan/25 bg-cyan/10 text-cyan",      Icon: AlertTriangle },
  pulling: { key: "repos.states.pulling", cls: "border-cyan/25 bg-cyan/10 text-cyan",      Icon: AlertTriangle },
  extracting: { key: "repos.states.extracting", cls: "border-cyan/25 bg-cyan/10 text-cyan", Icon: AlertTriangle },
  // 空壳目录（占名挡 clone 的空目录残留）：安静的中性配色——非异常、非就绪，仅待清理
  empty:   { key: "repos.states.empty",   cls: "border-border bg-muted/40 text-muted-foreground", Icon: FolderX },
};

function StateBadge({ ws, repo }: { ws: string; repo: Repo }) {
  const { t } = useTranslation();
  // cloning/pulling/extracting 复用 CloneProgress（SSE 事件流；extracting 换文案"解压中"）
  if (repo.state === "cloning" || repo.state === "pulling" || repo.state === "extracting") {
    return (
      <CloneProgress
        ws={ws} name={repo.name}
        busyLabelKey={repo.state === "extracting" ? "repos.states.extracting" : undefined}
      />
    );
  }
  const m = STATE_BADGE[repo.state];
  return (
    <Badge variant="outline" className={cn("gap-1.5 whitespace-nowrap rounded-full px-2 font-medium", m.cls)}>
      <m.Icon className="size-3.5" aria-hidden />
      {t(m.key)}
    </Badge>
  );
}

// 异常态左侧色条（signature 扫读锚点）：就绪保持安静不显色，异常态显语义色。
function stateAccent(state: RepoState): string | null {
  if (state === "cloning" || state === "pulling" || state === "extracting") return "bg-cyan";
  if (state === "failed") return "bg-red";
  if (state === "stale") return "bg-yellow";
  return null;
}

interface Props {
  /**
   * workspace 名。两种来源：
   *  - 路由模式下：父组件不传，从 useParams() 取（router.tsx 里 `<ReposTab />` 不带 props）。
   *  - 测试 / 嵌入：直接传字面值（如 `<ReposTab workspace="ws1" />`）。
   */
  workspace?: string;
}

/**
 * 工作区内的"仓库"tab：克隆/列表/pull/checkout/删除。
 * 由原 pages/ReposPage.tsx + RepoDetailPage.tsx 合并迁入（P2：仓库迁到 ws 内）。
 *  - 不再独立 /repos 路由（TopBar 不再有其入口）。
 *  - 所有 API 调用带 ws 参数。
 *  - 仓库 → RepoDetail 的二级路由也一并撤销（无独立详情页；扫描入口在新建扫描页选 repo）。
 */
export function ReposTab({ workspace: wsProp }: Props) {
  const { t } = useTranslation();
  const { user } = useAuth();
  // linked 写操作 admin-only（spec 2026-09-04 §6）：非 admin 对 linked 仍只读
  const isAdmin = user?.role === "admin";
  const params = useParams<{ workspace: string }>();
  const workspace = wsProp ?? params.workspace ?? "";
  const [addOpen, setAddOpen] = useState(false);
  const [pendingDelete, setPendingDelete] = useState<string | null>(null);
  const [pendingBulkDelete, setPendingBulkDelete] = useState(false);
  const [busy, setBusy] = useState(false);
  const [query, setQuery] = useState("");
  const [groupFilter, setGroupFilter] = useState(GROUP_ALL);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const pullTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  // SWR 数据层（2026-08-17 批次 Task 3）：key ["repos", ws] 与 ScanFormFields 下拉共享，
  // 切回 tab 缓存即时显示。enabled=!!user 保留旧「等 auth user ready 再首拉」语义。
  const { repos, loading, error, refresh } = useRepos(workspace, !!user);

  // 加载失败 toast（旧 refresh catch 行为）：error 变化时提示一次。
  useEffect(() => { if (error) toast.error(t("repos.errors.loadFailed")); }, [error, t]);
  useEffect(() => () => { if (pullTimerRef.current) clearTimeout(pullTimerRef.current); }, []);
  // 后台任务（clone/pull/上传解压）进行中 → 轻量轮询刷新列表（结束后停）。
  // 状态列的实时进度走 SSE（CloneProgress），轮询只为收尾后刷新徽标/大小等列。
  const hasBusyRepo = repos.some((r) => r.state === "cloning" || r.state === "pulling" || r.state === "extracting");
  useEffect(() => {
    if (!hasBusyRepo) return;
    const id = setInterval(() => { void refresh(); }, 2000);
    return () => clearInterval(id);
  }, [hasBusyRepo, refresh]);

  async function doDelete() {
    if (!pendingDelete) return;
    try {
      setBusy(true);
      await deleteRepo(workspace, pendingDelete);
      await refresh();
    } catch (e) {
      if (e instanceof ApiError) {
        toast.error(
          e.status === 409
            ? t("repos.errors.inUse")
            : t("repos.errors.deleteFailed", { status: e.status }),
        );
      }
    } finally {
      setBusy(false);
      setPendingDelete(null);
    }
  }

  function toggleSelect(name: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  }

  async function doBulkDelete() {
    try {
      setBusy(true);
      const res = await deleteRepos(workspace, [...selected]);
      const done = res.deleted.length + res.unlinked.length;
      if (res.skipped.length > 0) {
        toast.warning(t("repos.bulk.successWithSkipped", { done, skipped: res.skipped.length }));
      } else {
        toast.success(t("repos.bulk.success", { done }));
      }
      setSelected(new Set());
      await refresh();
    } catch (e) {
      if (e instanceof ApiError) toast.error(t("repos.bulk.error"));
    } finally {
      setBusy(false);
      setPendingBulkDelete(false);
    }
  }

  async function doPull(name: string) {
    try {
      await pullRepo(workspace, name);
      toast.success(t("repos.updating", { name }));
      if (pullTimerRef.current) clearTimeout(pullTimerRef.current);
      pullTimerRef.current = setTimeout(() => void refresh(), PULL_REFRESH_DELAY_MS);
    } catch (e) {
      if (e instanceof ApiError) {
        // 后端 detail（linked pull 失败/超时带 git 原文，spec 2026-09-04 §5.3）优先透出
        const detail = (e.body as { detail?: string } | null)?.detail;
        toast.error(detail ?? t("repos.errors.updateFailed", { status: e.status }));
      }
    }
  }

  // 切换分支（spec 2026-08-21 §3；linked 放开见 spec 2026-09-04）：后端 checkout，
  // 私有仓 meta 回写 / linked 现读 .git，刷新取新 branch/commit。
  // 409=被扫描引用（与删除同文案）；422=分支不存在或 dirty 冲突（detail 优先）。
  async function doCheckout(name: string, branch: string) {
    try {
      await checkoutRepo(workspace, name, branch);
      toast.success(t("repoDetail.checkoutSuccess", { branch }));
      await refresh();
    } catch (e) {
      if (e instanceof ApiError) {
        toast.error(
          e.status === 409
            ? t("repos.errors.inUse")
            : e.status === 422
              // 后端 detail 优先（dirty 冲突带 git 原文；分支不存在带分支名，spec 2026-09-04 §4.2）
              ? ((e.body as { detail?: string } | null)?.detail
                  ?? t("repoDetail.errors.branchNotFound", { branch }))
              : t("repoDetail.errors.checkoutFailed", { status: e.status }),
        );
      }
    }
  }

  // 分组筛选（2026-09-16）：选项从当前仓库客户端派生（不动后端契约），与搜索词 AND。
  // 全部仓库都无分组时不渲染控件（只剩「全部/未分组」的噪音）；插入序对齐 groupRepos。
  const groups = useMemo(() => {
    const set = new Set<string>();
    repos.forEach((r) => { if (r.group) set.add(r.group); });
    return Array.from(set);
  }, [repos]);
  const hasUngrouped = useMemo(() => repos.some((r) => !r.group), [repos]);
  // 选中组在刷新后消失（组内仓库被删光）→ 派生回落「全部」，避免 Select 值无对应项显空
  const effectiveGroupFilter =
    groupFilter === GROUP_ALL
    || groups.includes(groupFilter)
    || (groupFilter === GROUP_UNGROUPED && hasUngrouped)
      ? groupFilter
      : GROUP_ALL;

  // 搜索：按仓库名过滤（跨分组）；分组筛选先行收窄（AND）
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return repos.filter((r) => {
      if (effectiveGroupFilter === GROUP_UNGROUPED) {
        if (r.group) return false;
      } else if (effectiveGroupFilter !== GROUP_ALL && r.group !== effectiveGroupFilter) {
        return false;
      }
      return !q || r.name.toLowerCase().includes(q);
    });
  }, [repos, query, effectiveGroupFilter]);

  // 概览条：客户端聚合 repos（不动后端契约）
  const stats: StatItem[] = useMemo(() => {
    const totalSize = repos.reduce((s, r) => s + (r.size_bytes ?? 0), 0);
    return [
      { label: t("repos.stats.total"), value: repos.length },
      { label: t("repos.stats.size"), value: fmtSize(totalSize) },
      { label: t("repos.stats.ready"), value: repos.filter((r) => r.state === "ready").length, tone: "green" },
      { label: t("repos.stats.cloning"), value: repos.filter((r) => r.state === "cloning" || r.state === "pulling").length, tone: "cyan" },
    ];
  }, [repos, t]);

  // 批量删除确认框文案：按选中仓库的 linked/私有 分类计数
  const selectedLinkedCount = useMemo(
    () => repos.filter((r) => selected.has(r.name) && r.linked).length,
    [repos, selected],
  );
  const selectedPrivateCount = selected.size - selectedLinkedCount;

  // 表头全选（扁平列表后，整表全选落在列头）：三态——全选 / 部分(indeterminate) / 无。
  const allFilteredSelected = filtered.length > 0 && filtered.every((r) => selected.has(r.name));
  const someFilteredSelected = filtered.some((r) => selected.has(r.name));
  const selectAllChecked = allFilteredSelected ? true : someFilteredSelected ? "indeterminate" : false;
  function toggleSelectAll() {
    setSelected((prev) => {
      const allSel = filtered.length > 0 && filtered.every((r) => prev.has(r.name));
      const next = new Set(prev);
      filtered.forEach((r) => (allSel ? next.delete(r.name) : next.add(r.name)));
      return next;
    });
  }

  return (
    <TooltipProvider>
      <div className="space-y-4">
        <StatRow stats={stats} />
        <div className="flex flex-wrap items-center gap-3">
          <Button variant="cta" onClick={() => setAddOpen(true)}>{t("repos.addRepo")}</Button>
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={t("repos.searchPlaceholder")}
            className="w-56"
            aria-label={t("repos.searchPlaceholder")}
          />
          {groups.length > 0 && (
            <Select value={effectiveGroupFilter} onValueChange={setGroupFilter}>
              <SelectTrigger aria-label={t("repos.groupFilter.label")} className="w-40">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={GROUP_ALL}>{t("repos.groupFilter.all")}</SelectItem>
                {groups.map((g) => (
                  <SelectItem key={g} value={g}>{g}</SelectItem>
                ))}
                {hasUngrouped && (
                  <SelectItem value={GROUP_UNGROUPED}>{t("repos.ungrouped")}</SelectItem>
                )}
              </SelectContent>
            </Select>
          )}
        </div>

        {selected.size > 0 && (
          <div className="flex flex-wrap items-center gap-3 rounded-md border border-border bg-muted/30 px-3 py-2">
            <span className="text-sm text-muted-foreground">{t("repos.bulk.selected", { count: selected.size })}</span>
            <Button size="sm" variant="destructive" onClick={() => setPendingBulkDelete(true)}>
              <Trash2 className="size-3.5" />
              {t("repos.bulk.deleteSelected")}
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setSelected(new Set())}>
              {t("repos.bulk.clear")}
            </Button>
          </div>
        )}

        {loading ? (
          <div className="text-sm text-muted-foreground">{t("repos.loading")}</div>
        ) : filtered.length === 0 ? (
          <div className="text-sm text-muted-foreground">
            {repos.length === 0 ? t("repos.empty") : t("repos.noMatch")}
          </div>
        ) : (
          <div className="overflow-auto rounded-md border border-border" style={{ maxHeight: "60vh" }}>
            <Table className="table-fixed">
              {/* 列头全表唯一 + sticky 粘顶：滚动时常驻。扁平列表（不再按分组折叠），
                  所在目录独立成列；整表全选 checkbox 落在名称列头（对齐全选入口）。 */}
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="sticky top-0 z-10 [backdrop-filter:var(--backdrop-card,none)] w-64 bg-card py-2.5 pl-4 pr-3 text-xs font-medium text-muted-foreground">
                    <div className="flex items-center gap-2">
                      <Checkbox
                        aria-label={t("repos.bulk.selectAll")}
                        checked={selectAllChecked}
                        onCheckedChange={() => toggleSelectAll()}
                      />
                      {t("repos.table.name")}
                    </div>
                  </TableHead>
                  <TableHead className="sticky top-0 z-10 [backdrop-filter:var(--backdrop-card,none)] w-40 bg-card py-2.5 px-3 text-xs font-medium text-muted-foreground">
                    {t("repos.table.directory")}
                  </TableHead>
                  <TableHead className="sticky top-0 z-10 [backdrop-filter:var(--backdrop-card,none)] bg-card py-2.5 px-3 text-xs font-medium text-muted-foreground">{t("repos.table.source")}</TableHead>
                  <TableHead className="sticky top-0 z-10 [backdrop-filter:var(--backdrop-card,none)] w-28 bg-card py-2.5 px-3 text-xs font-medium text-muted-foreground">{t("repos.table.branch")}</TableHead>
                  <TableHead className="sticky top-0 z-10 [backdrop-filter:var(--backdrop-card,none)] w-20 whitespace-nowrap bg-card py-2.5 px-3 text-right text-xs font-medium text-muted-foreground">{t("repos.table.size")}</TableHead>
                  <TableHead className="sticky top-0 z-10 [backdrop-filter:var(--backdrop-card,none)] w-36 whitespace-nowrap bg-card py-2.5 px-3 text-xs font-medium text-muted-foreground">{t("repos.table.state")}</TableHead>
                  <TableHead className="sticky top-0 z-10 [backdrop-filter:var(--backdrop-card,none)] w-28 whitespace-nowrap bg-card py-2.5 px-3 text-center text-xs font-medium text-muted-foreground">{t("repos.table.actions")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.map((r) => {
                  const url = r.source?.url;
                  const accent = stateAccent(r.state);
                  const slashIdx = r.name.lastIndexOf("/");
                  const dir = slashIdx > 0 ? r.name.slice(0, slashIdx) : null;
                  return (
                    <TableRow key={r.name} className="group border-b border-border/50 transition-colors hover:bg-muted/40">
                      {/* 名称：basename（目录前缀已移至独立「目录」列），hover 显完整路径 */}
                      <TableCell className="relative py-2.5 pl-4 pr-3">
                        {accent && <span className={cn("absolute inset-y-0 left-0 w-0.5", accent)} aria-hidden />}
                        <div className="flex items-center gap-2">
                          <Checkbox
                            aria-label={t("repos.bulk.selectRepo", { name: r.name })}
                            checked={selected.has(r.name)}
                            onCheckedChange={() => toggleSelect(r.name)}
                          />
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <span className="min-w-0 flex-1 truncate font-mono text-sm font-medium">
                                {r.name.split("/").pop() ?? r.name}
                              </span>
                            </TooltipTrigger>
                            <TooltipContent>{r.name}</TooltipContent>
                          </Tooltip>
                          {r.linked && (
                            <Badge variant="outline" className="shrink-0 border-cyan/40 text-cyan">
                              {t("repos.linkedBadge")}
                            </Badge>
                          )}
                        </div>
                      </TableCell>
                      {/* 所在目录：name 的路径前缀（group/repo 的 group 段）；扁平仓库为 — */}
                      <TableCell className="py-2.5 px-3">
                        {dir ? (
                          <span className="block truncate font-mono text-xs text-muted-foreground">{dir}</span>
                        ) : (
                          <span className="font-mono text-xs text-muted-foreground/50">—</span>
                        )}
                      </TableCell>
                      {/* 来源：URL 截断 + tooltip，复制按钮 hover 浮出（去渐变蒙层） */}
                      <TableCell className="py-2.5 px-3">
                        {url ? (
                          <div className="flex items-center gap-1">
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <span className="min-w-0 flex-1 truncate font-mono text-xs text-muted-foreground">{url}</span>
                              </TooltipTrigger>
                              <TooltipContent className="max-w-md break-all">{url}</TooltipContent>
                            </Tooltip>
                            <CopyButton
                              value={url}
                              ariaLabel={t("repos.copyUrlAria", { name: r.name })}
                              className="shrink-0 opacity-0 transition-opacity focus-within:opacity-100 group-hover:opacity-100"
                            />
                          </div>
                        ) : (
                          <span className="text-xs text-muted-foreground">
                            {/* 无 URL 的来源（linked 无 url 罕见 / upload / unknown）→ 本地化 kind 文案 */}
                            {r.source?.kind ? t(`repos.kinds.${r.source.kind}`, { defaultValue: r.source.kind }) : "-"}
                          </span>
                        )}
                      </TableCell>
                      {/* 分支列：ready+私有仓（git 克隆 / upload）或 linked+admin → 行内切换
                          下拉（点开 lazy 拉分支——clone 问远端、upload/linked 枚举本地 refs，
                          手输兜底）；linked 且非 admin / 非 ready 退化为只读文本（spec 2026-09-04） */}
                      <TableCell className="py-2.5 px-3">
                        {r.state === "ready" && (r.source?.kind === "git" || r.source?.kind === "upload" || (r.linked && isAdmin)) ? (
                          <BranchCombobox
                            ws={workspace}
                            repo={r.name}
                            value={r.source?.branch ?? null}
                            onSwitch={(b) => doCheckout(r.name, b)}
                          />
                        ) : (
                          <span className="block truncate font-mono text-xs text-muted-foreground">
                            {r.source?.branch ?? "-"}
                          </span>
                        )}
                      </TableCell>
                      <TableCell className="whitespace-nowrap py-2.5 px-3 text-right font-mono text-xs text-muted-foreground tabular-nums">
                        {fmtSize(r.size_bytes)}
                      </TableCell>
                      <TableCell className="whitespace-nowrap py-2.5 px-3">
                        <StateBadge ws={workspace} repo={r} />
                      </TableCell>
                      {/* 操作列统一 icon-only ghost 按钮：clone 行 更新+删除；linked 行 取消关联。 */}
                      <TableCell className="py-2.5 px-3 text-center">
                        <span className="inline-flex justify-center gap-1">
                          {/* 空壳目录（empty）无更新入口——pull 对其必报"仓库不存在"；
                              upload 仓是静态快照（后端 405），更新走重新上传；linked
                              共享路径可写但 admin-only（spec 2026-09-04 §6） */}
                          {(isAdmin || !r.linked) && r.state !== "empty" && r.source?.kind !== "upload" && (
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <Button
                                  size="icon"
                                  variant="ghost"
                                  aria-label={t("repos.updateAria", { name: r.name })}
                                  onClick={() => doPull(r.name)}
                                >
                                  <RefreshCw className="size-4" />
                                </Button>
                              </TooltipTrigger>
                              <TooltipContent>{t("common.update")}</TooltipContent>
                            </Tooltip>
                          )}
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Button
                                size="icon"
                                variant="ghost"
                                className="text-destructive hover:bg-destructive/10"
                                aria-label={t(r.linked ? "repos.unlinkAria" : "repos.deleteAria", { name: r.name })}
                                onClick={() => setPendingDelete(r.name)}
                              >
                                {/* 关联仓库：取消关联（仅移除引用，不删源文件） */}
                                {r.linked ? <Unlink className="size-4" /> : <Trash2 className="size-4" />}
                              </Button>
                            </TooltipTrigger>
                            <TooltipContent>{r.linked ? t("repos.unlink") : t("common.delete")}</TooltipContent>
                          </Tooltip>
                        </span>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        )}

        <AddRepoDialog ws={workspace} open={addOpen} onOpenChange={setAddOpen} onCreated={() => void refresh()} />

        <Dialog open={!!pendingDelete} onOpenChange={(o) => !o && setPendingDelete(null)}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>{t("repos.deleteDialog.title")}</DialogTitle>
              <DialogDescription>{t("repos.deleteDialog.desc", { name: pendingDelete })}</DialogDescription>
            </DialogHeader>
            <DialogFooter>
              <Button variant="ghost" onClick={() => setPendingDelete(null)}>{t("common.cancel")}</Button>
              <Button variant="destructive" disabled={busy} onClick={doDelete}>{t("common.confirm")}</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        <Dialog open={pendingBulkDelete} onOpenChange={(o) => !o && setPendingBulkDelete(false)}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>{t("repos.bulk.confirmTitle")}</DialogTitle>
              <DialogDescription>
                {selectedLinkedCount > 0 && selectedPrivateCount > 0
                  ? t("repos.bulk.confirmMixed", { linked: selectedLinkedCount, privateCount: selectedPrivateCount })
                  : selectedLinkedCount > 0
                    ? t("repos.bulk.confirmLinked", { count: selectedLinkedCount })
                    : t("repos.bulk.confirmDelete", { count: selectedPrivateCount })}
              </DialogDescription>
            </DialogHeader>
            <DialogFooter>
              <Button variant="ghost" onClick={() => setPendingBulkDelete(false)}>{t("common.cancel")}</Button>
              <Button variant="destructive" disabled={busy} onClick={doBulkDelete}>{t("common.confirm")}</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>
    </TooltipProvider>
  );
}
