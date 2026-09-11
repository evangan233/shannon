// HOST 档案库 页面（ws-child tab 内容）。范式镜像 AuthProfilesPage.tsx
// (refresh / loading / error / Card+Table / dialog 挂载) + useParams ws-scoped。
// 结构: 档案列表 + 新建/编辑/删除 + system 档案 fork + refresh。
// 列: 名称(+system 徽章) / 来源(手填=「手动」/GET 链接截断+Tooltip+复制) / 映射条数 / 更新时间 / 操作(编辑·刷新·删除；system 仅 fork)。
import { useState } from "react";
import { useParams } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import { Trash2, Pencil, Copy, RefreshCw } from "lucide-react";
import { deleteHostProfile, forkHostProfile, refreshHostProfile } from "@/api/hostProfiles";
import { useHostProfiles } from "@/api/useHostProfiles";
import { ApiError } from "@/api/client";
import type { HostProfile } from "@/api/types";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Tooltip, TooltipTrigger, TooltipContent, TooltipProvider } from "@/components/ui/tooltip";
import { CopyButton } from "@/components/CopyButton";
import { HostProfileDialog } from "@/components/HostProfileDialog";
import { fmtIsoTime } from "@/utils/format";

export function HostProfilesPage() {
  const { t } = useTranslation();
  const { workspace } = useParams<{ workspace: string }>();
  const [createOpen, setCreateOpen] = useState(false);
  const [editTarget, setEditTarget] = useState<HostProfile | null>(null);
  const [delTarget, setDelTarget] = useState<HostProfile | null>(null);
  const [refreshingId, setRefreshingId] = useState<string | null>(null);
  // SWR 数据层（2026-08-17 渐进迁移）：切回 tab 缓存即时显示 + 后台 revalidate；
  // key 与 ScanFormFields 下拉共享。
  const { profiles, loading, error, refresh } = useHostProfiles(workspace);

  async function onDelete() {
    if (!workspace || !delTarget) return;
    try {
      await deleteHostProfile(workspace, delTarget.id);
      toast.success(t("hostProfiles.deleted"));
      setDelTarget(null);
      void refresh();
    } catch {
      toast.error(t("hostProfiles.deleteFailed"));
    }
  }

  async function onFork(p: HostProfile) {
    if (!workspace) return;
    try {
      await forkHostProfile(workspace, p.id);
      toast.success(t("hostProfiles.forkSuccess"));
      void refresh();
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) {
        toast.info(t("hostProfiles.forkAlready"));
      } else {
        toast.error(t("hostProfiles.forkFailed"));
      }
    }
  }

  async function onRefresh(p: HostProfile) {
    if (!workspace) return;
    setRefreshingId(p.id);
    try {
      await refreshHostProfile(workspace, p.id);
      toast.success(t("hostProfiles.refreshed"));
      void refresh();
    } catch (e) {
      if (e instanceof ApiError && e.status === 403) {
        toast.info(t("hostProfiles.systemHint"));
      } else {
        toast.error(t("hostProfiles.refreshFailed"));
      }
    } finally {
      setRefreshingId(null);
    }
  }

  if (!workspace) return null;
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-medium">{t("hostProfiles.title")}</h3>
        <Button variant="cta" onClick={() => setCreateOpen(true)}>
          {t("hostProfiles.create")}
        </Button>
      </div>
      {loading ? <Skeleton className="h-20 w-full" />
       : error ? <div className="text-sm text-destructive">{error}</div>
       : profiles.length === 0 ? <Card className="p-6 text-sm text-muted-foreground">{t("hostProfiles.empty")}</Card>
       : <TooltipProvider><Card><Table className="table-fixed"><TableHeader><TableRow>
            <TableHead className="w-64">{t("hostProfiles.name")}</TableHead>
            <TableHead>{t("hostProfiles.source")}</TableHead>
            <TableHead className="w-24">{t("hostProfiles.mappingsCount")}</TableHead>
            <TableHead className="w-28">{t("hostProfiles.updated")}</TableHead>
            <TableHead className="w-32"></TableHead></TableRow></TableHeader>
            <TableBody>{profiles.map((p) => (
              <TableRow key={p.id} className="group transition-colors hover:bg-muted/40">
                <TableCell className="max-w-0">
                  <div className="flex items-start gap-2">
                    {/* 档案名=身份锚点，加重+前景色高亮（区别于 来源/映射/时间 等 muted 引用数据）。 */}
                    <span className="min-w-0 break-all font-mono text-sm font-semibold leading-snug text-foreground" title={p.name}>{p.name}</span>
                    {p.scope === "system" && (
                      <span
                        className="mt-px shrink-0 inline-flex items-center rounded-full border border-border bg-muted/40 px-2 py-0.5 text-[10.5px] font-semibold text-muted-foreground"
                        title={t("hostProfiles.systemHint")}
                      >
                        {t("hostProfiles.systemBadge")}
                      </span>
                    )}
                  </div>
                </TableCell>
                {/* 来源: 手填=「手动」/ source_url 截断 + Tooltip + hover 复制按钮（对齐 ReposTab 长URL范式）。 */}
                <TableCell className="max-w-0">
                  {!p.source_url ? (
                    <span className="text-xs text-muted-foreground">{t("hostProfiles.manualSource")}</span>
                  ) : (
                    <div className="flex items-center gap-1">
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <span className="min-w-0 flex-1 truncate font-mono text-xs text-muted-foreground">
                            {p.source_url}
                          </span>
                        </TooltipTrigger>
                        <TooltipContent className="max-w-md break-all">{p.source_url}</TooltipContent>
                      </Tooltip>
                      <CopyButton
                        value={p.source_url}
                        ariaLabel={t("hostProfiles.copyUrlAria", { name: p.name })}
                        className="shrink-0 opacity-0 transition-opacity focus-within:opacity-100 group-hover:opacity-100"
                      />
                    </div>
                  )}
                </TableCell>
                <TableCell className="font-mono text-xs text-muted-foreground">
                  {p.mappings?.length ?? 0}
                </TableCell>
                {/* 更新时间: 紧凑 MM-DD HH:mm（对齐 fmtTime 全站口径）；后端为 32 字符 ISO 机器串，
                    直渲染溢出固定列挤到操作按钮——完整串放 title hover。 */}
                <TableCell className="font-mono text-xs text-muted-foreground">
                  <span className="whitespace-nowrap" title={(p.updated_at || p.created_at) ?? undefined}>
                    {fmtIsoTime(p.updated_at || p.created_at)}
                  </span>
                </TableCell>
                {/* 操作列: flex + justify-end + gap-1 横排；system 仅 fork，ws 有 编辑/刷新/删除。 */}
                <TableCell>
                  <div className="flex items-center justify-end gap-1">
                    {p.scope === "system" && (
                      <Button variant="ghost" size="icon" aria-label={t("hostProfiles.forkLabel")} onClick={() => onFork(p)}>
                        <Copy className="size-4" />
                      </Button>
                    )}
                    {p.scope !== "system" && (
                      <>
                        <Button variant="ghost" size="icon" aria-label={t("hostProfiles.edit")} onClick={() => setEditTarget(p)}>
                          <Pencil className="size-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          aria-label={t("hostProfiles.refresh")}
                          onClick={() => onRefresh(p)}
                          disabled={!p.source_url || refreshingId === p.id}
                        >
                          <RefreshCw className={`size-4 ${refreshingId === p.id ? "animate-spin" : ""}`} />
                        </Button>
                        <Button variant="ghost" size="icon" aria-label={t("hostProfiles.delete")} onClick={() => setDelTarget(p)}>
                          <Trash2 className="size-4" />
                        </Button>
                      </>
                    )}
                  </div>
                </TableCell>
              </TableRow>))}</TableBody></Table></Card></TooltipProvider>}

      <HostProfileDialog ws={workspace} open={createOpen} onOpenChange={setCreateOpen} onSaved={refresh} />
      {editTarget && (
        <HostProfileDialog
          ws={workspace}
          open
          onOpenChange={(o) => !o && setEditTarget(null)}
          onSaved={() => { setEditTarget(null); void refresh(); }}
          editing={editTarget}
        />
      )}
      <Dialog open={!!delTarget} onOpenChange={(o) => !o && setDelTarget(null)}>
        <DialogContent>
          <DialogHeader><DialogTitle>{t("hostProfiles.delete")}</DialogTitle></DialogHeader>
          <p className="text-sm text-destructive">{delTarget?.name}</p>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setDelTarget(null)}>{t("common.cancel")}</Button>
            <Button variant="destructive" onClick={onDelete}>{t("hostProfiles.delete")}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
