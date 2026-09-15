import { useState, useMemo } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router-dom";
import {
  ArrowLeftRight,
  Trash2,
  Bug,
  CircleDollarSign,
  Layers,
  Clock,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useWorkspaces } from "@/api/useWorkspaces";
import { useAuth } from "@/auth/AuthContext";
import { CreateWorkspaceDialog } from "@/components/CreateWorkspaceDialog";
import { deleteWorkspace } from "@/api/client";
import { fmtCost, currencySymbol } from "@/utils/currency";
import type { Workspace } from "@/api/types";
import { toast } from "sonner";

const STATUS_COLOR: Record<string, string> = {
  running: "bg-cyan",
  completed: "bg-green",
  done: "bg-green",
  failed: "bg-red",
  killed: "bg-red",
  crashed: "bg-yellow",
};
const statusColor = (s: string) => STATUS_COLOR[s] ?? "bg-yellow";

// 与 DashboardPage / ScanList 同款绝对时间（unix 秒）。
function fmtTime(unix?: number | null): string {
  if (!unix) return "-";
  return new Date(unix * 1000).toLocaleString();
}

/** ws 的分币种花费条目：新后端读 cost_by_currency（跨全部 scans 聚合）；旧后端缺该
 * 字段时回落 total_cost_usd+cost_currency 单币种（无花费 → []）。 */
function wsCostEntries(w: Workspace): [string, number][] {
  const cbc = w.cost_by_currency;
  if (cbc && Object.keys(cbc).length > 0) return Object.entries(cbc);
  return w.total_cost_usd != null ? [[w.cost_currency ?? "USD", w.total_cost_usd]] : [];
}

/** 分币种紧凑渲染（对齐 Dashboard tileCost / WorkspaceDetail 头部）：单币种照常
 *  fmtCost；多币种「¥76 + $29」（跨币种直加是错值，分组才可加）。 */
function fmtCosts(entries: [string, number][]): string {
  if (entries.length === 0) return "—";
  if (entries.length === 1) return fmtCost(entries[0][1], entries[0][0]);
  return entries.map(([cur, v]) => `${currencySymbol(cur)}${Math.round(v)}`).join(" + ");
}

export function WorkspaceSwitcher({ currentWorkspace }: { currentWorkspace?: string }) {
  const { t } = useTranslation();
  const nav = useNavigate();
  const { data, refresh } = useWorkspaces();
  const { user } = useAuth();
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const isAdmin = user?.role === "admin";

  const list = useMemo(() => {
    if (!q.trim()) return data;
    const s = q.toLowerCase();
    return data.filter((w) => w.name.toLowerCase().includes(s));
  }, [data, q]);

  // 舰队汇总（对齐 Dashboard：跨 ws 聚合；花费按币种分组——跨币种直加是错值）。
  const fleet = useMemo(() => {
    const totalVulns = data.reduce((a, w) => a + (w.vuln_count ?? 0), 0);
    const byCurrency = new Map<string, number>();
    for (const w of data) {
      for (const [cur, v] of wsCostEntries(w)) {
        byCurrency.set(cur, (byCurrency.get(cur) ?? 0) + v);
      }
    }
    const costEntries = [...byCurrency.entries()].sort((a, b) => b[1] - a[1]);
    return { totalVulns, costEntries };
  }, [data]);

  function pick(name: string) {
    setOpen(false);
    setQ("");
    nav(`/p/${name}`);
  }

  // admin 行内删除（spec 2026-07-27：下线 WorkspaceListPage 后删除并入切换器）。
  const [pendingDelete, setPendingDelete] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function doDelete() {
    if (!pendingDelete) return;
    setBusy(true);
    try {
      const target = pendingDelete;
      await deleteWorkspace(target);
      toast.success(t("workspaces.deleteDialog.deleted", { ws: target }));
      setPendingDelete(null);
      await refresh();
      // 删的是 currentWorkspace → 跳 Dashboard，避免停在已删 ws 的 404 详情。
      if (target === currentWorkspace) nav("/");
    } catch (e) {
      toast.error(t("workspaces.actionFailed", { error: e instanceof Error ? e.message : String(e) }));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <Button variant="toolbar" onClick={() => setOpen(true)} aria-label={t("workspaceSwitcher.title")}>
        <ArrowLeftRight className="size-4" /> {t("workspaceSwitcher.title")}
      </Button>
      <Dialog open={open} onOpenChange={(o) => { setOpen(o); if (!o) setQ(""); }}>
        {/* 左侧全高抽屉；加宽到 520px 以容纳每行详情。close 复用 DialogContent 内置单个 X。 */}
        <DialogContent className="left-0 top-0 h-screen max-w-none translate-x-0 translate-y-0 flex flex-col rounded-l-none rounded-r-2xl sm:left-0 sm:max-w-[520px]">
          <DialogHeader className="shrink-0 pr-10">
            <DialogTitle>{t("workspaceSwitcher.title")}</DialogTitle>
            <p className="text-xs text-muted-foreground tabular-nums">
              {q.trim()
                ? t("workspaceSwitcher.filtered", { shown: list.length, total: data.length })
                : t("workspaceSwitcher.subtitle", { count: data.length })}
            </p>
          </DialogHeader>

          <div className="shrink-0 space-y-2">
            <Input placeholder={t("workspaceSwitcher.search")} value={q} onChange={(e) => setQ(e.target.value)} />
            {/* 舰队一览：累计漏洞 + 累计花费（决策时一眼看全舰队健康）。 */}
            <div className="flex items-center gap-3 text-xs text-muted-foreground tabular-nums">
              <span>
                <span className="font-semibold text-foreground">{fleet.totalVulns}</span>{" "}
                {t("workspaceSwitcher.stats.vulns")}
              </span>
              <span aria-hidden>·</span>
              <span>{t("workspaceSwitcher.summary.fleetCost", { cost: fmtCosts(fleet.costEntries) })}</span>
            </div>
          </div>

          <div className="flex-1 min-h-0 space-y-1.5 overflow-y-auto">
            {list.length === 0 && <p className="text-sm text-muted-foreground">{t("workspaceSwitcher.empty")}</p>}
            {list.map((w) => (
              <WorkspaceCard
                key={w.name}
                ws={w}
                current={w.name === currentWorkspace}
                isAdmin={isAdmin}
                t={t}
                onPick={() => pick(w.name)}
                onDelete={() => setPendingDelete(w.name)}
              />
            ))}
          </div>

          {isAdmin && (
            <div className="shrink-0 border-t pt-3">
              <CreateWorkspaceDialog onCreated={refresh} />
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* admin 删除工作区确认 Dialog（复用 workspaces.deleteDialog 文案） */}
      <Dialog open={!!pendingDelete} onOpenChange={(o) => !o && setPendingDelete(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("workspaces.deleteDialog.deleteTitle")}</DialogTitle>
            <DialogDescription>
              {t("workspaces.deleteDialog.deleteDesc", { ws: pendingDelete })}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setPendingDelete(null)}>{t("common.cancel")}</Button>
            <Button variant="destructive" disabled={busy} onClick={doDelete}>{t("common.confirm")}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

/** 单个工作区状态卡：上行身份，下行统计条（漏洞/花费/扫描/最近活动）。null-safe 对齐旧后端缺字段。 */
function WorkspaceCard({
  ws,
  current,
  isAdmin,
  t,
  onPick,
  onDelete,
}: {
  ws: Workspace;
  current: boolean;
  isAdmin: boolean;
  t: (k: string, o?: Record<string, unknown>) => string;
  onPick: () => void;
  onDelete: () => void;
}) {
  const vulns = ws.vuln_count ?? 0;
  const scans = ws.scan_count ?? 0;
  // 分币种（新后端 cost_by_currency 跨全部 scans 聚合；旧后端回落单币种）
  const cost = fmtCosts(wsCostEntries(ws));
  const when = fmtTime(ws.created_at);

  return (
    <div
      role="button"
      tabIndex={0}
      data-current={current}
      aria-label={t("workspaceSwitcher.rowAria", {
        ws: ws.name, status: ws.status, vulns, cost, scans, when,
      })}
      onClick={onPick}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onPick(); }
      }}
      className={`relative flex flex-col gap-1.5 rounded-lg border border-transparent px-3 py-2.5 text-left transition-colors hover:bg-accent ${
        current ? "bg-accent" : ""
      }`}
    >
      {/* 当前工作区左侧 accent 条：你在哪，一眼即知。 */}
      {current && <span className="absolute inset-y-0 left-0 w-0.5 rounded-l bg-primary" aria-hidden />}

      {/* 身份行（工作区是容器，scan_type 属于单条扫描而非工作区，故此处不展示类型 Badge） */}
      <div className="flex items-center gap-2.5">
        <span className={`inline-block size-2 shrink-0 rounded-full ${statusColor(ws.status)}`} />
        <span className="flex-1 truncate font-mono text-sm">{ws.name}</span>
        {isAdmin && (
          <Button
            size="icon"
            variant="ghost"
            className="size-6 shrink-0 text-muted-foreground hover:text-destructive"
            data-testid={`switcher-delete-${ws.name}`}
            aria-label={t("workspaceSwitcher.deleteAria", { ws: ws.name })}
            onClick={(e) => { e.stopPropagation(); onDelete(); }}
          >
            <Trash2 className="size-3.5" />
          </Button>
        )}
      </div>

      {/* 统计条：图标+数字，sr-only 文案保证可访问性；漏洞数是主角（>0 强调）。 */}
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 pl-[18px] text-xs text-muted-foreground tabular-nums">
        <span className="inline-flex items-center gap-1">
          <Bug className="size-3" />
          <span className={vulns > 0 ? "font-semibold text-foreground" : ""}>{vulns}</span>
          <span className="sr-only">{t("workspaceSwitcher.stats.vulns")}</span>
        </span>
        <span className="inline-flex items-center gap-1">
          <CircleDollarSign className="size-3" />
          {cost}
          <span className="sr-only">{t("workspaceSwitcher.stats.cost")}</span>
        </span>
        <span className="inline-flex items-center gap-1">
          <Layers className="size-3" />
          {scans}
          <span className="sr-only">{t("workspaceSwitcher.stats.scans")}</span>
        </span>
        <span className="ml-auto inline-flex items-center gap-1">
          <Clock className="size-3" />
          {when}
          <span className="sr-only">{t("workspaceSwitcher.stats.time")}</span>
        </span>
      </div>
    </div>
  );
}
