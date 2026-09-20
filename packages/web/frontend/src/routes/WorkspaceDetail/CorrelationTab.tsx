import { useCallback, useMemo, useState } from "react";
import type { ReactNode } from "react";
import useSWR from "swr";
import { useTranslation } from "react-i18next";
import { ChevronDown, Download, ListCollapse, ListTree } from "lucide-react";
import { ApiError, getCorrelationDetail } from "@/api/client";
import type { AdjudicationCard, CorrelationDetail, CorrDismissed, CorrVuln } from "@/api/types";
import { focusAnchor } from "@/utils/focusAnchor";
import { downloadTextFile } from "@/lib/download";
import { Empty } from "@/components/Empty";
import { ErrorState } from "@/components/ErrorState";
import { MarkdownView } from "@/components/MarkdownView";
import { TopologyGraph } from "@/components/correlation/TopologyGraph";
import { AttackChainCard } from "@/components/correlation/AttackChainCard";
import { CorrStatsHeader, type SevKey } from "@/components/correlation/CorrStatsHeader";
import {
  CorrVulnCard, corrVulnAnchorId, toCorrVulnView,
} from "@/components/correlation/CorrVulnCard";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";

/**
 * 跨仓关联结果 tab（D5，spec 2026-08-24）：专属结果视图——
 * 总览头（数字卡 + severity 药丸，2026-09-20 可读性批次）→ 漂移警告横幅（首版
 * 后端恒空，渲染条件保留）→ 服务拓扑图 → 跨服务攻击链（漏洞引用可点定位）→
 * 多跳候选链（details 默认收起）→ 裁决区（方向聚合 + 卡片折叠，error 卡默认
 * 展开）→ 单仓已否决（跨仓重审）→ 按服务分组漏洞（集中折叠 + 全部收起/展开）
 * → 信任边界表 → 报告 md（details 默认收起 + 下载）。
 *
 * 定位体系对齐 ReportView 的 locateVuln（2026-08-26 报告目录模式）：攻击链
 * vuln_refs / 总览 severity 药丸点击 → 目标漏洞卡折叠时先展开再 focusAnchor
 * （coral 描边闪烁）；卡锚点 id 由 corrVulnAnchorId 单源。
 *
 * SWR 15s 轮询仅在「未完成」开（拓扑未出 = 关联跑着 / 裁决 running）；终态停
 * 轮询——completed 后继续打点无意义。topology === null → 阶段占位（「关联阶段
 * 进行中/未开始」+ corr_children 子仓状态）。props 收 ws/scanId（由挂载方 D6
 * 传入，对齐 brief；tab 内不经 useParams）。
 */
export function CorrelationTab({ ws, scanId }: { ws: string; scanId: string }) {
  const { t } = useTranslation();
  const { data, error, isLoading } = useSWR(
    ws && scanId ? ["corr-detail", ws, scanId] : null,
    () => getCorrelationDetail(ws, scanId),
    // 终态（拓扑已出且裁决非 running）停轮询：函数形式吃 latest（同形返回值
    // 0 = 不再排下一跳），避免在自身初始化器里引用 data（TDZ）；缺数据视为进行中。
    {
      refreshInterval: (latest?: CorrelationDetail) =>
        !latest || !latest.topology || latest.adjudication_status === "running" ? 15000 : 0,
    },
  );

  // 漏洞卡集中折叠 state（ReportView 模式）：空 set = 全展开（对齐单仓报告默认态）。
  const [collapsedVulns, setCollapsedVulns] = useState<Set<string>>(new Set());
  // 裁决卡折叠：null = 默认态（非 error 收起、error 卡故障信号必见）；用户首次
  // 交互后物化为显式 set（不然轮询重渲染会把默认态重算，用户展开被覆盖）。
  const [collapsedAdj, setCollapsedAdj] = useState<Set<string> | null>(null);

  /** 定位漏洞卡（折叠联动，对齐 ReportView.locateVuln）：折叠 → 先展开，等重渲染
   *  （卡身挂载）后再 focusAnchor，否则量到的 rect 是折叠卡头位置。 */
  const locateVuln = useCallback((id: string) => {
    let wasCollapsed = false;
    setCollapsedVulns((prev) => {
      if (!prev.has(id)) return prev;
      wasCollapsed = true;
      const next = new Set(prev);
      next.delete(id);
      return next;
    });
    if (wasCollapsed) setTimeout(() => focusAnchor(corrVulnAnchorId(id)), 0);
    else focusAnchor(corrVulnAnchorId(id));
  }, []);

  // severity → 该等级第一条漏洞 ID（扁平序）：总览 severity 药丸点击定位目标。
  const firstVulnIdBySev = useMemo(() => {
    const map = new Map<string, string>();
    for (const list of Object.values(data?.merged_vulns ?? {})) {
      for (const v of list) {
        const id = typeof v.ID === "string" ? v.ID : undefined;
        const sev = typeof v.severity === "string" ? v.severity.toLowerCase() : "";
        if (id && sev && !map.has(sev)) map.set(sev, id);
      }
    }
    return map;
  }, [data]);

  // 漏洞区全部收起/展开的目标集（宽松 dict：ID 非字符串跳过）。
  const vulnIds = useMemo(
    () =>
      Object.values(data?.merged_vulns ?? {})
        .flat()
        .map((v) => (typeof v.ID === "string" ? v.ID : ""))
        .filter(Boolean),
    [data],
  );

  if (error) {
    return (
      <ErrorState
        message={t("scan.correlation.loadError", {
          error: error instanceof ApiError ? `API ${error.status}` : String(error),
        })}
      />
    );
  }
  if (isLoading || !data) return <CorrLoading />;
  // 关联产物未生成（assemble_correlation_detail：topology 缺 → null）
  if (!data.topology) {
    return (
      <Empty
        title={t("scan.correlation.pending")}
        hint={t("scan.correlation.pendingHint")}
      >
        {data.corr_children.length > 0 && (
          <div
            data-testid="corr-children"
            className="flex flex-col items-center gap-1 text-xs"
          >
            <div className="font-medium text-foreground">
              {t("scan.correlation.childrenTitle")}
            </div>
            {data.corr_children.map((c) => (
              <div key={c.scan_id} className="font-mono">
                {c.service} · {c.scan_id} ·{" "}
                <span data-reused={c.reused ? "1" : "0"}>
                  {c.reused ? t("scan.correlation.childReused") : t("scan.correlation.childFresh")}
                </span>
              </div>
            ))}
          </div>
        )}
      </Empty>
    );
  }

  const serviceOrder = data.topology.services.map((s) => s.name);
  const groups = groupByService(data.merged_vulns, serviceOrder);
  // 裁决 direction 聚合（五向计数，徽标行扫视「成立/翻案/证伪」分布）——
  // 卡量数百级，直接算（hooks 不能放早退 return 之后）
  const adjCards = data.adjudication?.cards ?? [];
  const dirCountMap = new Map<string, number>();
  for (const card of adjCards) {
    dirCountMap.set(card.direction, (dirCountMap.get(card.direction) ?? 0) + 1);
  }
  const directionCounts = [...DIRECTION_ORDER]
    .map((dir) => ({ dir, count: dirCountMap.get(dir) ?? 0 }))
    .filter(({ count }) => count > 0);
  // dismissed ↔ 裁决卡匹配（service+vuln_id 复合键防跨服务同 ID 碰撞；只认 origin="dismissed"）
  const dismissedVerdicts = new Map<string, AdjudicationCard>();
  for (const card of adjCards) {
    if (card.finding_ref?.origin === "dismissed") {
      dismissedVerdicts.set(`${card.finding_ref.service}|${card.finding_ref.vuln_id}`, card);
    }
  }
  // 裁决卡折叠（见 collapsedAdj 注释）：默认非 error 收起；显式 set 后以 set 为准。
  const adjKey = (c: AdjudicationCard) => `${c.finding_ref.service}|${c.finding_ref.vuln_id}`;
  const isAdjCollapsed = (c: AdjudicationCard) =>
    collapsedAdj ? collapsedAdj.has(adjKey(c)) : c.direction !== "error";
  const toggleAdj = (c: AdjudicationCard) => {
    setCollapsedAdj((prev) => {
      const base =
        prev ?? new Set(adjCards.filter((x) => x.direction !== "error").map(adjKey));
      const next = new Set(base);
      const k = adjKey(c);
      if (next.has(k)) next.delete(k);
      else next.add(k);
      return next;
    });
  };

  return (
    <div className="space-y-6">
      {/* 总览头：数字卡 + severity 药丸（点击定位到该等级第一条漏洞卡） */}
      <CorrStatsHeader
        detail={data}
        onLocateSev={(sev: SevKey) => {
          const id = firstVulnIdBySev.get(sev);
          if (id) locateVuln(id);
        }}
      />
      {/* 漂移警告横幅：首版后端恒 []（不解析 report），条件保留待后续版本接线 */}
      {data.drift_warnings.length > 0 && (
        <section
          data-testid="corr-drift"
          className="rounded-md border border-amber/40 bg-amber/10 p-3 text-sm text-amber"
        >
          <div className="font-medium">{t("scan.correlation.driftTitle")}</div>
          <ul className="mt-1 list-disc pl-5">
            {data.drift_warnings.map((w, i) => (
              <li key={i}>{String(w)}</li>
            ))}
          </ul>
        </section>
      )}
      <section data-testid="corr-topology">
        <h3 className="font-medium">{t("scan.correlation.topologyTitle")}</h3>
        <TopologyGraph topology={data.topology} />
      </section>
      <section data-testid="corr-flows">
        <h3 className="font-medium">{t("scan.correlation.flowsTitle")}</h3>
        <p className="mt-0.5 text-xs text-muted-foreground">
          {t("scan.correlation.flowsIntro")}
        </p>
        <div className="mt-2 space-y-2">
          {data.flows.length ? (
            data.flows.map((f, i) => (
              <AttackChainCard key={i} flow={f} onLocateRef={locateVuln} />
            ))
          ) : (
            <p className="text-sm text-muted-foreground">
              {t("scan.correlation.flowsEmpty")}
            </p>
          )}
        </div>
      </section>
      <section data-testid="corr-multihop">
        <h3 className="font-medium">{t("scan.correlation.multihopTitle")}</h3>
        <p className="mt-0.5 text-xs text-muted-foreground">
          {t("scan.correlation.multihopIntro")}
        </p>
        <div className="mt-2 space-y-1">
          {data.multi_hop_chains.length ? (
            // 结构推断产物与拓扑图信息重叠、条数易多——默认收起，计数徽标示意量级。
            <details data-testid="corr-multihop-list">
              <summary className="cursor-pointer text-xs text-muted-foreground">
                {t("scan.correlation.multihopExpand", { count: data.multi_hop_chains.length })}
              </summary>
              <div className="mt-2 space-y-1">
                {data.multi_hop_chains.map((c, i) => (
                  <div key={i} className="font-mono text-sm" data-testid="corr-multihop-chain">
                    {c.path.join(" → ")}{" "}
                    <Badge variant="outline" className="ml-1 font-sans text-[10px]">
                      {c.basis} · {c.confidence}
                    </Badge>
                  </div>
                ))}
              </div>
            </details>
          ) : (
            <p className="text-sm text-muted-foreground">
              {t("scan.correlation.multihopEmpty")}
            </p>
          )}
        </div>
      </section>
      {(data.adjudication || data.adjudication_status === "running") && (
        <section data-testid="corr-adjudication">
          <SectionHead
            title={t("scan.correlation.adjudicationTitle")}
            intro={t("scan.correlation.adjudicationIntro")}
            actions={
              adjCards.length > 0 && (
                <CollapseToggleButtons
                  scope="adj"
                  onCollapse={() => setCollapsedAdj(new Set(adjCards.map(adjKey)))}
                  onExpand={() => setCollapsedAdj(new Set())}
                />
              )
            }
          />
          {/* 裁决进行中横幅（log 未落盘时的唯一进行中信号，amber 对齐 drift 横幅） */}
          {data.adjudication_status === "running" && (
            <div
              data-testid="corr-adj-running"
              className="mt-2 rounded-md border border-amber/40 bg-amber/10 p-3 text-sm text-amber"
            >
              {t("scan.correlation.adjRunning")}
            </div>
          )}
          {data.adjudication?.error ? (
            <p data-testid="corr-adjudication-error" className="mt-2 text-sm text-destructive">
              {data.adjudication.error}
            </p>
          ) : (data.adjudication?.cards ?? []).length === 0 ? (
            // 仅 running 横幅（log 未落盘）时不显示「无裁决卡」占位
            !data.adjudication ? null : (
              <p className="mt-2 text-sm text-muted-foreground">
                {t("scan.correlation.adjudicationEmpty")}
              </p>
            )
          ) : (
            <>
              {directionCounts.length > 0 && (
                <div data-testid="corr-adj-summary" className="mt-2 flex flex-wrap items-center gap-1.5">
                  {directionCounts.map(({ dir, count }) => (
                    <Badge key={dir} variant="outline" className="font-mono text-[10px]">
                      {t(ADJ_DIRECTION_KEY[dir] ?? dir)} × {count}
                    </Badge>
                  ))}
                </div>
              )}
              <div className="mt-2 space-y-2">
                {(data.adjudication?.cards ?? []).map((c, i) => (
                  <AdjudicationCardView
                    key={i}
                    card={c}
                    collapsed={isAdjCollapsed(c)}
                    onToggleCollapse={() => toggleAdj(c)}
                  />
                ))}
              </div>
            </>
          )}
        </section>
      )}
      {/* 单仓已否决（跨仓重审）：dismissed 明单 + 命中裁决的行内 direction 徽标 */}
      {data.dismissed.length > 0 && (
        <section data-testid="corr-dismissed">
          <h3 className="font-medium">{t("scan.correlation.dismissedTitle")}</h3>
          <p className="mt-0.5 text-xs text-muted-foreground">
            {t("scan.correlation.dismissedIntro")}
          </p>
          <Table className="mt-2">
            <TableHeader>
              <TableRow>
                <TableHead>{t("scan.correlation.colService")}</TableHead>
                <TableHead>{t("scan.correlation.colVulnClass")}</TableHead>
                <TableHead>ID</TableHead>
                <TableHead className="w-[28%]">{t("scan.correlation.colDismissReason")}</TableHead>
                <TableHead>{t("scan.correlation.colDismissStage")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.dismissed.map((d: CorrDismissed, i: number) => {
                const verdict = dismissedVerdicts.get(`${d.service}|${d.ID}`);
                return (
                  <TableRow key={`${d.service}:${d.ID}:${i}`} data-testid="corr-dismissed-row">
                    <TableCell className="font-mono text-xs">{d.service}</TableCell>
                    <TableCell className="font-mono text-xs">{d.vuln_class ?? "—"}</TableCell>
                    <TableCell className="font-mono text-xs">
                      {d.ID}
                      {verdict && (
                        <Badge
                          data-testid="corr-dismissed-verdict"
                          variant="outline"
                          className="ml-1.5 font-sans text-[10px]"
                        >
                          {t(ADJ_DIRECTION_KEY[verdict.direction] ?? verdict.direction)}
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      <span className="line-clamp-2">{d.title || d.dismiss_reason || "—"}</span>
                      {d.title && d.dismiss_reason && (
                        <span className="mt-0.5 block line-clamp-2">{d.dismiss_reason}</span>
                      )}
                    </TableCell>
                    <TableCell className="font-mono text-xs">{d.dismissed_at_stage ?? "—"}</TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </section>
      )}
      <section data-testid="corr-vulns">
        <SectionHead
          title={t("scan.correlation.vulnsTitle")}
          actions={
            groups.length > 0 && (
              <CollapseToggleButtons
                scope="vulns"
                onCollapse={() => setCollapsedVulns(new Set(vulnIds))}
                onExpand={() => setCollapsedVulns(new Set())}
              />
            )
          }
        />
        <div className="mt-2 space-y-3">
          {groups.length === 0 && (
            <p className="text-sm text-muted-foreground">
              {t("scan.correlation.vulnsEmpty")}
            </p>
          )}
          {groups.map((g) => (
            <div key={g.service} data-testid="corr-vuln-group" className="space-y-2">
              <Badge variant="outline" className="font-mono">
                {g.service || t("scan.correlation.serviceUnknown")}
              </Badge>
              {g.vulns.map((v, i) => {
                const view = toCorrVulnView(v);
                return (
                  <CorrVulnCard
                    key={`${g.service}-${i}`}
                    view={view}
                    anchorId={corrVulnAnchorId(view.id)}
                    collapsed={collapsedVulns.has(view.id)}
                    onToggleCollapse={() =>
                      setCollapsedVulns((prev) => {
                        const next = new Set(prev);
                        if (next.has(view.id)) next.delete(view.id);
                        else next.add(view.id);
                        return next;
                      })
                    }
                  />
                );
              })}
            </div>
          ))}
        </div>
      </section>
      <section data-testid="corr-boundaries">
        <h3 className="font-medium">{t("scan.correlation.boundariesTitle")}</h3>
        {data.boundaries.length === 0 ? (
          <p className="mt-2 text-sm text-muted-foreground">
            {t("scan.correlation.boundariesEmpty")}
          </p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t("scan.correlation.colService")}</TableHead>
                <TableHead>{t("scan.correlation.colMethod")}</TableHead>
                <TableHead>{t("scan.correlation.colExposure")}</TableHead>
                <TableHead>{t("scan.correlation.colReachableFrom")}</TableHead>
                <TableHead>{t("scan.correlation.colReason")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.boundaries.map((b, i) => (
                <TableRow key={i}>
                  <TableCell className="font-mono text-xs">{b.service}</TableCell>
                  <TableCell className="font-mono text-xs">
                    {b.method}{" "}
                    <span className="text-muted-foreground">({b.confidence})</span>
                  </TableCell>
                  <TableCell className="text-xs">{b.exposure}</TableCell>
                  <TableCell className="font-mono text-xs">
                    {b.reachable_from.join(", ") || "—"}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">{b.reason}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </section>
      {data.report_md && (
        // 导出物与上方结构化视图内容重叠——默认收起只留入口（标题 + 下载），
        // 需要通读 md 全文时展开（对齐 AttackChainCard evidence 的 <details> 语言）。
        <section data-testid="corr-report">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h3 className="font-medium">{t("scan.correlation.reportTitle")}</h3>
            <Button
              variant="ghost"
              size="sm"
              className="text-muted-foreground"
              onClick={() => downloadTextFile(`correlation-${scanId}.md`, data.report_md ?? "")}
            >
              <Download aria-hidden />
              {t("workspaceDetail.report.download")}
            </Button>
          </div>
          <details className="mt-2">
            <summary className="cursor-pointer text-xs text-muted-foreground">
              {t("scan.correlation.reportExpand")}
            </summary>
            <div className="mt-2">
              <MarkdownView markdown={data.report_md} />
            </div>
          </details>
        </section>
      )}
    </div>
  );
}

/** 区块头（标题 + intro + 右侧 actions）：漏洞/裁决区的「全部收起/展开」挂点。 */
function SectionHead({ title, intro, actions }: {
  title: string;
  intro?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-2">
      <div className="min-w-0">
        <h3 className="font-medium">{title}</h3>
        {intro && <p className="mt-0.5 text-xs text-muted-foreground">{intro}</p>}
      </div>
      {actions}
    </div>
  );
}

/** 全部收起/展开按钮对（视觉对齐 ReportView 的 collapse-all/expand-all）。
 *  scope 进 testid：裁决/漏洞两处同款按钮，测试 within 区块圈定。 */
function CollapseToggleButtons({ scope, onCollapse, onExpand }: {
  scope: "vulns" | "adj";
  onCollapse: () => void;
  onExpand: () => void;
}) {
  const { t } = useTranslation();
  const btnCls =
    "inline-flex items-center gap-1 rounded-sm border border-border px-2 py-1 font-mono text-[10.5px] text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary";
  return (
    <div className="flex items-center gap-1.5">
      <button type="button" data-testid={`corr-collapse-all-${scope}`} onClick={onCollapse}
        title={t("report.collapseAll")} className={btnCls}>
        <ListCollapse className="size-3.5" aria-hidden="true" />
        {t("report.collapseAll")}
      </button>
      <button type="button" data-testid={`corr-expand-all-${scope}`} onClick={onExpand}
        title={t("report.expandAll")} className={btnCls}>
        <ListTree className="size-3.5" aria-hidden="true" />
        {t("report.expandAll")}
      </button>
    </div>
  );
}

/** 加载占位（Skeleton 行，对齐 DataFlowTab/DeliverablesTab 习惯）。 */
function CorrLoading() {
  return (
    <div className="space-y-2">
      {[0, 1, 2].map((i) => (
        <Skeleton key={i} className="h-8 w-full" />
      ))}
    </div>
  );
}

/** CorrVuln（宽松 dict）→ CorrVulnCard 视图：归一逻辑收敛在
 *  components/correlation/CorrVulnCard.tsx 的 toCorrVulnView（防御拾取 + 位置
 *  兜底链 + report_endpoints/poc 结构化，导出便于单测）。 */

/** merged_vulns（键 = vuln class）拍平后按条目 service 字段分组。
 *  组序：serviceOrder（拓扑服务序，入口在前）优先，未列出的服务按字典序垫底；
 *  service 字段缺失 → ""（渲染层显示「未知服务」）。纯函数，导出便于测试。 */
export function groupByService(
  merged: Record<string, CorrVuln[]>,
  serviceOrder: string[] = [],
): { service: string; vulns: CorrVuln[] }[] {
  const byService = new Map<string, CorrVuln[]>();
  for (const vulns of Object.values(merged)) {
    for (const v of vulns) {
      const service = typeof v.service === "string" ? v.service : "";
      const bucket = byService.get(service);
      if (bucket) bucket.push(v);
      else byService.set(service, [v]);
    }
  }
  const rank = new Map(serviceOrder.map((s, i) => [s, i]));
  return [...byService.entries()]
    .sort((a, b) => {
      const ra = rank.get(a[0]) ?? serviceOrder.length;
      const rb = rank.get(b[0]) ?? serviceOrder.length;
      return ra - rb || a[0].localeCompare(b[0]);
    })
    .map(([service, vulns]) => ({ service, vulns }));
}

/** 裁决方向 → i18n key（spec 2026-08-27 §7.3 五向 + error 占位）。 */
const ADJ_DIRECTION_KEY: Record<string, string> = {
  upgrade: "scan.correlation.adjUpgrade",
  downgrade: "scan.correlation.adjDowngrade",
  confirm: "scan.correlation.adjConfirm",
  maintain: "scan.correlation.adjMaintain",
  error: "scan.correlation.adjError",
};
/** direction 聚合徽标行展示顺序（正反结论同构，error 垫底）。 */
const DIRECTION_ORDER = ["upgrade", "downgrade", "confirm", "maintain", "error"] as const;

/**
 * 单张裁决卡（spec 2026-08-27 §9）：正反结论同构——卡头（direction/conclusion
 * 徽标 + ID + service·origin + confidence）折叠，展开体（跨仓上下文 + 分析过程
 * （有序列表）+ 验证证据（file:line）+ 论证）。受控折叠：CorrelationTab 集中
 * state（默认非 error 收起、error 卡必见——卡量数百级全展开会淹没方向聚合行）。
 */
export function AdjudicationCardView({ card, collapsed, onToggleCollapse }: {
  card: AdjudicationCard;
  /** 受控折叠态（CorrelationTab 传入）；undefined = 展开（兜底直接渲染场景）。 */
  collapsed?: boolean;
  /** 折叠切换回调（卡头 button；缺省卡头退化为非交互行）。 */
  onToggleCollapse?: () => void;
}) {
  const { t } = useTranslation();
  const dirKey = ADJ_DIRECTION_KEY[card.direction] ?? card.direction;
  const isError = card.direction === "error";
  const isUpgrade = card.direction === "upgrade";
  const open = collapsed !== true;
  // 语义色走 --c-red/--c-amber token（逐主题校对比），不用 tailwind 原生色阶
  const frame = isError
    ? "border-red/40 bg-red/5"
    : isUpgrade
      ? "border-amber/40 bg-amber/5"
      : "border-border";
  return (
    <div data-testid="corr-adj-card" className={`rounded-md border p-3 text-sm ${frame}`}>
      {onToggleCollapse ? (
        <button
          type="button"
          data-testid="corr-adj-card-head"
          aria-expanded={open}
          onClick={onToggleCollapse}
          className="flex w-full flex-wrap items-center gap-2 rounded-sm text-left focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary focus-visible:outline-offset-2"
        >
          <HeadBadges card={card} dirKey={dirKey} isError={isError} t={t} />
          <ChevronDown
            className={`ml-auto size-4 shrink-0 text-muted-foreground transition-transform duration-150 ${open ? "" : "-rotate-90"}`}
            aria-hidden="true"
          />
        </button>
      ) : (
        <div className="flex flex-wrap items-center gap-2">
          <HeadBadges card={card} dirKey={dirKey} isError={isError} t={t} />
        </div>
      )}
      {open && (
        <div className="mt-2 space-y-1 text-xs">
          {card.cross_service_context && (
            <div>
              <span className="text-muted-foreground">
                {t("scan.correlation.adjContext")}:
              </span>{" "}
              {card.cross_service_context}
            </div>
          )}
          {card.analysis_process.length > 0 && (
            <div>
              <div className="text-muted-foreground">
                {t("scan.correlation.adjProcess")}
              </div>
              <ol className="list-decimal pl-5">
                {card.analysis_process.map((step, i) => (
                  <li key={i}>{step}</li>
                ))}
              </ol>
            </div>
          )}
          {card.verification_evidence.length > 0 && (
            <div>
              <div className="text-muted-foreground">
                {t("scan.correlation.adjEvidence")}
              </div>
              <ul className="list-disc pl-5">
                {card.verification_evidence.map((ev, i) => (
                  <li key={i}>
                    <span className="font-mono">{ev.location}</span>
                    {ev.note ? ` — ${ev.note}` : ""}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {card.reasoning && (
            <p>{card.reasoning}</p>
          )}
        </div>
      )}
    </div>
  );
}

/** 裁决卡卡头徽标行（direction/conclusion/ID/service·origin/confidence）——折叠
 *  button 与非受控 div 两种卡头共用。 */
function HeadBadges({ card, dirKey, isError, t }: {
  card: AdjudicationCard;
  dirKey: string;
  isError: boolean;
  t: (k: string, opts?: { defaultValue?: string }) => string;
}) {
  return (
    <>
      <Badge variant="outline" className={isError ? "text-red" : undefined}>
        {t(dirKey, { defaultValue: card.direction })}
      </Badge>
      <span className="font-mono font-medium">{card.finding_ref.vuln_id || "?"}</span>
      <span className="text-xs text-muted-foreground">
        {card.finding_ref.service} · {card.finding_ref.origin}
      </span>
      <Badge variant="secondary">{card.conclusion}</Badge>
      <span className="text-xs text-muted-foreground">
        confidence: {card.confidence}
      </span>
    </>
  );
}
