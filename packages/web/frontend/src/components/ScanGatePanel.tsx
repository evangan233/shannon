import { type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router-dom";
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

/** 单条目行：占用/排队两段共用同一列栅格（状态·工作区·类型·任务·时刻），跨段垂直
 *  对齐；排队按快照顺序渲染，不逐项标位次。running=青点 / queued=黄点（StatusBadge
 *  同语义）。时刻列显式展示「启动/入队时刻 · 已历时」（14:02 · 3h05m），hover title
 *  补完整日期时间；ws+scan_id 齐全的条目可点进扫描详情。
 *  本工作区标记（2026-09-15 美化）：极淡主题色整行底 + 左缘竖线（「当前行」惯例
 *  范式），彩色只出现在背景与 gutter 结构层；内容文字恒中性——此前 ws 名也染
 *  primary，两层彩色叠加观感突兀（用户反馈「感觉好奇怪」），识别度由行底 + 字重
 *  承担。
 *  列宽（2026-09-15 修「ws 字段被挤到看不见」）：状态点列收窄（点仅 6px 无需宽列），
 *  ws 列从固定 4.5rem 改弹性（minmax 4.5rem 起步、与任务名列按约 1:1.4 分剩余宽）——
 *  长 ws 名可伸展可读，truncate 只在极限窄屏生效。 */
function EntryRow({ e, running, own }: {
  e: ScanGateEntry; running?: boolean; own?: boolean;
}) {
  const { t } = useTranslation();
  const kind = e.kind && e.kind !== "unknown"
    ? t(`scanGate.kinds.${e.kind}`, e.kind) : "";
  const href = e.ws && e.scan_id ? `/p/${e.ws}/scans/${e.scan_id}` : null;
  const fullTs = e.since ? new Date(e.since * 1000).toLocaleString() : undefined;
  return (
    <div
      title={own ? t("scanGate.own") : undefined}
      data-own={own || undefined}
      className={`grid grid-cols-[1.75rem_minmax(4.5rem,1fr)_auto_minmax(0,1.4fr)_auto] items-center gap-x-2 border-l-2 py-px ${own ? "border-l-primary bg-primary/[0.045]" : "border-l-transparent"}`}
    >
      <span aria-hidden className={`size-1.5 justify-self-start rounded-full ${running ? "bg-cyan" : "bg-yellow"}`} />
      <span
        className={`min-w-0 truncate text-[12px] ${own ? "font-medium text-foreground" : "text-foreground/85"}`}
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
 *  显示——「为什么排队」的答案：5 槽被哪个工作区的什么任务占着、队列还排着谁。
 *  无折叠（2026-09-15 用户裁定）：明细常驻直出，面板即全量信息——标题行右侧
 *  x/capacity 计数答「空几格」（原收起态槽位条 rail 与明细同屏重复，随折叠机制
 *  一并移除）。排队按快照顺序渲染，不逐项标位次（同日用户反馈：位次数字是噪音）。
 *  currentWs（所在工作区详情页）非空时，本工作区条目以淡底 + 左缘竖线标出。 */
export function ScanGatePanel({ snapshot, currentWs }: {
  snapshot: ScanGateSnapshot | null; currentWs?: string;
}) {
  const { t } = useTranslation();
  if (!snapshot || (!snapshot.held.length && !snapshot.waiting.length)) return null;
  const { held, waiting, capacity } = snapshot;
  return (
    <Card data-testid="scan-gate-panel" className="space-y-2 p-3">
      {/* 标题行：[标题] [x/capacity 计数右置]——「空几格」语义由此计数接管。 */}
      <div className="flex items-center justify-between gap-3">
        <span className="text-[13px] font-medium">{t("scanGate.title")}</span>
        <span className="font-mono text-[12px] tabular-nums text-muted-foreground">
          {t("scanGate.usage", { held: held.length, capacity })}
        </span>
      </div>
      {held.length > 0 && (
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
      {waiting.length > 0 && (
        <section className="space-y-1">
          <SectionLabel hint={t("scanGate.waitHint")}>
            {t("scanGate.waiting", { n: waiting.length })}
          </SectionLabel>
          {/* 长队列（max_waiting 封顶 50）：全量渲染 + 限高滚动——全局透明不截断，
              面板高度仍有界（max-h-56 ≈ 9 行，超出滚动；overscroll-contain 防滚动穿透）。 */}
          <div data-testid="gate-waiting-scroll"
               className="max-h-56 space-y-1 overflow-y-auto overscroll-contain pr-1">
            {waiting.map((e) => (
              <EntryRow key={e.workflow_id ?? e.scan_id} e={e}
                        own={!!currentWs && e.ws === currentWs} />
            ))}
          </div>
        </section>
      )}
    </Card>
  );
}
