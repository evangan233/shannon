import { useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router-dom";
import { ChevronRight } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import type { ScanGateEntry, ScanGateSnapshot } from "@/api/client";

/** since（unix 秒）→「<1m / 41m / 3h05m」时长（面板跟随列表刷新节奏，无需实时跳秒）。 */
function fmtSince(since?: number): string {
  if (!since) return "";
  const mins = Math.max(0, Math.floor((Date.now() / 1000 - since) / 60));
  if (mins < 1) return "<1m";
  if (mins < 60) return `${mins}m`;
  const h = Math.floor(mins / 60);
  const m = mins % 60;
  return m ? `${h}h${String(m).padStart(2, "0")}m` : `${h}h`;
}

/** 芯片用短时长（更宽则换行）：≥1h 略分钟、≥24h 折天。明细行用 fmtSince 全格式。 */
function fmtSinceShort(since?: number): string {
  if (!since) return "";
  const mins = Math.max(0, Math.floor((Date.now() / 1000 - since) / 60));
  if (mins < 1) return "<1m";
  if (mins < 60) return `${mins}m`;
  const h = Math.floor(mins / 60);
  return h < 24 ? `${h}h` : `${Math.floor(h / 24)}d`;
}

/** since → 启动时刻：当日「HH:mm」，跨日「MM-DD HH:mm」（跨天看不到几点开跑就没意义）。 */
function fmtStart(since?: number): string {
  if (!since) return "";
  const d = new Date(since * 1000);
  const now = new Date();
  const hm = `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
  const sameDay = d.getFullYear() === now.getFullYear()
    && d.getMonth() === now.getMonth() && d.getDate() === now.getDate();
  return sameDay ? hm
    : `${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")} ${hm}`;
}

/** 摘要条排队芯片上限（芯片带文本较宽，比刻度收紧）；超出以 +N 文本收。 */
const WAITING_CHIPS = 3;
/** 摘要条容量刻度渲染上限（防异常 capacity 撑爆面板）。 */
const RAIL_CAPACITY_MAX = 32;

/** 槽位条芯片：ws + 短时长（占用=青点 / 排队=黄点 #N）；本工作区=ws 名 coral。
 *  ws+scan_id 齐全时可点进对应扫描详情。 */
function SlotChip({ e, rank, own }: { e: ScanGateEntry; rank?: number; own?: boolean }) {
  const href = e.ws && e.scan_id ? `/p/${e.ws}/scans/${e.scan_id}` : null;
  // 排队芯片黄 tint 边框（对齐 StatusBadge queued 的 border-yellow/40 处理）
  const cls = `inline-flex max-w-[9rem] items-center gap-1 rounded-md border px-1.5 py-0.5 text-[11px] leading-4 transition-colors ${rank ? "border-yellow/40" : "border-border"} ${href ? "hover:border-primary/50" : ""}`;
  const body = (
    <>
      <span aria-hidden className={`size-1.5 shrink-0 rounded-full ${rank ? "bg-yellow" : "bg-cyan"}`} />
      {rank != null && <span className="shrink-0 font-mono text-muted-foreground">#{rank}</span>}
      <span className={`truncate ${own ? "font-medium text-primary" : "text-foreground/85"}`} title={e.ws}>
        {e.ws || "—"}
      </span>
      <span className="shrink-0 font-mono text-muted-foreground">{fmtSinceShort(e.since)}</span>
    </>
  );
  return href
    ? <Link data-testid={rank ? "gate-waiting" : "gate-slot"} to={href} className={cls}>{body}</Link>
    : <span data-testid={rank ? "gate-waiting" : "gate-slot"} className={cls}>{body}</span>;
}

/** 闸门槽位条（本面板的签名）：容量=物理槽位，每格自描述——占用槽=带 ws+时长的
 *  芯片（青点）、空闲槽=虚线空格；阈值线之后=排队芯片（黄点 #N，与本工作区 ws
 *  coral 标记），超过上限以 +N 收。一条槽位条同时回答：谁占着哪个槽 / 占了多久 /
 *  空几格 / 队排多长。 */
function GateRail({ held, capacity, waiting, currentWs }: {
  held: ScanGateEntry[]; capacity: number; waiting: ScanGateEntry[]; currentWs?: string;
}) {
  const { t } = useTranslation();
  const cap = Math.max(0, Math.min(capacity, RAIL_CAPACITY_MAX));
  const free = Math.max(0, cap - held.length);
  const chips = waiting.slice(0, WAITING_CHIPS);
  return (
    <div
      data-testid="scan-gate-rail"
      title={t("scanGate.usage", { held: held.length, capacity })
        + (waiting.length > 0 ? ` · ${t("scanGate.waiting", { n: waiting.length })}` : "")}
      className="flex flex-wrap items-center gap-1"
    >
      {held.map((e) => (
        <SlotChip key={e.workflow_id ?? e.scan_id} e={e}
                  own={!!currentWs && e.ws === currentWs} />
      ))}
      {Array.from({ length: free }, (_, i) => (
        <span key={i} data-testid="gate-free" aria-hidden
              className="w-3 self-stretch rounded-[2px] border border-dashed border-border" />
      ))}
      {waiting.length > 0 && (
        <>
          {/* 阈值线：容量段与溢出段之间的「闸门」本体 */}
          <span aria-hidden className="mx-0.5 w-px self-stretch bg-border" />
          {chips.map((e, i) => (
            <SlotChip key={e.workflow_id ?? e.scan_id} e={e} rank={i + 1}
                      own={!!currentWs && e.ws === currentWs} />
          ))}
          {waiting.length > chips.length && (
            <span className="font-mono text-[10.5px] leading-none text-muted-foreground">
              +{waiting.length - chips.length}
            </span>
          )}
        </>
      )}
    </div>
  );
}

/** 段落标头：小标 + 通长发丝线（结构分隔，非装饰）；hint 右置微提示标注时刻列语义
 *  （占用段=启动时刻、排队段=入队时刻——since 在两段含义不同，见 scan_gate.snapshot）。 */
function SectionLabel({ children, hint }: { children: ReactNode; hint?: string }) {
  return (
    <div className="flex items-center gap-2 pt-1">
      <span className="whitespace-nowrap text-[11px] font-medium text-muted-foreground">{children}</span>
      <span aria-hidden className="h-px flex-1 bg-border" />
      {hint && <span className="whitespace-nowrap text-[10.5px] text-muted-foreground/80">{hint}</span>}
    </div>
  );
}

/** 单条目行：占用/排队两段共用同一列栅格（位次·工作区·类型·任务·时刻），跨段垂直
 *  对齐。running=青点（StatusBadge running 同语义）；本工作区条目=coral 左缘 gutter
 *  信号 + ws 名 primary 强调（gutter 结构信号纪律——彩色只出现在 gutter 与身份位，
 *  行文保持中性）。时刻列显式展示「启动/入队时刻 · 已历时」（14:02 · 3h05m），
 *  hover title 补完整日期时间；ws+scan_id 齐全的条目可点进扫描详情。 */
function EntryRow({ e, running, rank, own }: {
  e: ScanGateEntry; running?: boolean; rank?: number; own?: boolean;
}) {
  const { t } = useTranslation();
  const kind = e.kind && e.kind !== "unknown"
    ? t(`scanGate.kinds.${e.kind}`, e.kind) : "";
  const href = e.ws && e.scan_id ? `/p/${e.ws}/scans/${e.scan_id}` : null;
  const fullTs = e.since ? new Date(e.since * 1000).toLocaleString() : undefined;
  return (
    <div
      title={own ? t("scanGate.own") : undefined}
      className={`grid grid-cols-[3.5rem_4.5rem_auto_minmax(0,1fr)_auto] items-center gap-x-2 border-l-2 py-px ${own ? "border-l-primary" : "border-l-transparent"}`}
    >
      {running ? (
        <span aria-hidden className="size-1.5 justify-self-start rounded-full bg-cyan" />
      ) : (
        <span className="whitespace-nowrap text-[11px] text-muted-foreground">
          {t("scanGate.rank", { n: rank })}
        </span>
      )}
      <span
        className={`truncate text-[12px] ${own ? "font-medium text-primary" : "text-foreground/85"}`}
        title={e.ws}
      >
        {e.ws || "—"}
      </span>
      {kind ? (
        <Badge variant="outline" className="justify-self-start px-1.5 font-mono text-[10.5px] text-muted-foreground">
          {kind}
        </Badge>
      ) : (
        <span aria-hidden />
      )}
      {href ? (
        <Link to={href} className="truncate font-mono text-[12.5px] hover:text-primary">
          {e.label ?? e.workflow_id}
        </Link>
      ) : (
        <span className="truncate font-mono text-[12.5px]">{e.label ?? e.workflow_id}</span>
      )}
      <span
        data-testid="gate-time"
        className="justify-self-end whitespace-nowrap font-mono text-[11.5px] text-muted-foreground"
        title={fullTs}
      >
        {fmtStart(e.since)} · {fmtSince(e.since)}
      </span>
    </div>
  );
}

/** 并发概览面板（spec 2026-09-08-worker-scan-gate §8.2）：仅当 held/waiting 非空时
 *  显示——「为什么排队」的答案：5 槽被哪个工作区的什么任务占着、我排第几。
 *  空间纪律（2026-09-09 用户反馈）：默认收起一行（≈44px），但摘要行自描述——
 *  槽位条每格带 ws+时长、本区位次短标，不展开也答「谁/多久/我第几」；展开为
 *  任务名明细（drill-down，纯手动，无自动展开特例）。
 *  currentWs（所在工作区详情页）非空时，本工作区条目以 coral 标出。 */
export function ScanGatePanel({ snapshot, currentWs }: {
  snapshot: ScanGateSnapshot | null; currentWs?: string;
}) {
  const { t } = useTranslation();
  // useState 必须在早退前——空快照也保持 hook 序稳定。
  const [userOpen, setUserOpen] = useState(false);
  if (!snapshot || (!snapshot.held.length && !snapshot.waiting.length)) return null;
  const { held, waiting, capacity } = snapshot;
  // 本工作区首个排队条目的位次（=下一个放行的自家扫描），无则 -1
  const ownRank = currentWs
    ? waiting.findIndex((e) => e.ws === currentWs) : -1;
  return (
    <Card data-testid="scan-gate-panel" className="space-y-2 p-3">
      {/* 摘要行（常驻）：[开关+标题+本区位次] [槽位条（自描述）] [x/5]。
          槽位条与开关分离——芯片可点进扫描详情，不与展开按钮嵌套交互。 */}
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
        <button
          type="button"
          onClick={() => setUserOpen((o) => !o)}
          aria-expanded={userOpen}
          className="flex shrink-0 items-center gap-1.5"
        >
          <ChevronRight
            aria-hidden
            className={`size-3.5 text-muted-foreground transition-transform ${userOpen ? "rotate-90" : ""}`}
          />
          <span className="text-[13px] font-medium">{t("scanGate.title")}</span>
          {ownRank >= 0 && (
            <span className="text-[11.5px] text-yellow">
              {t("scanGate.ownRank", { n: ownRank + 1 })}
            </span>
          )}
        </button>
        <GateRail held={held} capacity={capacity} waiting={waiting} currentWs={currentWs} />
        <span className="ml-auto shrink-0 font-mono text-[12px] tabular-nums text-muted-foreground">
          {t("scanGate.usage", { held: held.length, capacity })}
        </span>
      </div>
      {userOpen && held.length > 0 && (
        <section className="space-y-1">
          <SectionLabel hint={t("scanGate.heldHint")}>
            {t("scanGate.heldCount", { n: held.length })}
          </SectionLabel>
          {held.map((e) => (
            <EntryRow key={e.workflow_id ?? e.scan_id} e={e} running
                      own={!!currentWs && e.ws === currentWs} />
          ))}
        </section>
      )}
      {userOpen && waiting.length > 0 && (
        <section className="space-y-1">
          <SectionLabel hint={t("scanGate.waitHint")}>
            {t("scanGate.waiting", { n: waiting.length })}
          </SectionLabel>
          {/* 长队列（max_waiting 封顶 50）：全量渲染 + 限高滚动——全局透明不截断，
              面板高度仍有界（max-h-56 ≈ 9 行，超出滚动；overscroll-contain 防滚动穿透）。 */}
          <div data-testid="gate-waiting-scroll"
               className="max-h-56 space-y-1 overflow-y-auto overscroll-contain pr-1">
            {waiting.map((e, i) => (
              <EntryRow key={e.workflow_id ?? e.scan_id} e={e} rank={i + 1}
                        own={!!currentWs && e.ws === currentWs} />
            ))}
          </div>
        </section>
      )}
    </Card>
  );
}
