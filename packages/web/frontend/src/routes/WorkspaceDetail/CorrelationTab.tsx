import useSWR from "swr";
import { useTranslation } from "react-i18next";
import { ApiError, getCorrelationDetail } from "@/api/client";
import type { AdjudicationCard, CorrDismissed, CorrVuln } from "@/api/types";
import { Empty } from "@/components/Empty";
import { ErrorState } from "@/components/ErrorState";
import { MarkdownView } from "@/components/MarkdownView";
import { TopologyGraph } from "@/components/correlation/TopologyGraph";
import { AttackChainCard } from "@/components/correlation/AttackChainCard";
import { CorrVulnCard, toCorrVulnView } from "@/components/correlation/CorrVulnCard";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";

/**
 * 跨仓关联结果 tab（D5，spec 2026-08-24）：专属结果视图——
 * 漂移警告横幅（首版后端恒空，渲染条件保留）→ 服务拓扑图 → 跨服务攻击链 →
 * 裁决区（状态横幅 + direction 聚合 + 裁决卡）→ 单仓已否决（跨仓重审）→
 * 按服务分组漏洞（CorrVulnCard + service 徽标）→ 信任边界表 → 报告 md。
 *
 * SWR 15s 轮询（关联运行中持续刷新）；topology === null → 阶段占位
 * （「关联阶段进行中/未开始」+ corr_children 子仓状态）。props 收 ws/scanId
 * （由挂载方 D6 传入，对齐 brief；tab 内不经 useParams）。
 */
export function CorrelationTab({ ws, scanId }: { ws: string; scanId: string }) {
  const { t } = useTranslation();
  const { data, error, isLoading } = useSWR(
    ws && scanId ? ["corr-detail", ws, scanId] : null,
    () => getCorrelationDetail(ws, scanId),
    { refreshInterval: 15000 },
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

  return (
    <div className="space-y-6">
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
            data.flows.map((f, i) => <AttackChainCard key={i} flow={f} />)
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
            data.multi_hop_chains.map((c, i) => (
              <div key={i} className="font-mono text-sm" data-testid="corr-multihop-chain">
                {c.path.join(" → ")}{" "}
                <Badge variant="outline" className="ml-1 font-sans text-[10px]">
                  {c.basis} · {c.confidence}
                </Badge>
              </div>
            ))
          ) : (
            <p className="text-sm text-muted-foreground">
              {t("scan.correlation.multihopEmpty")}
            </p>
          )}
        </div>
      </section>
      {(data.adjudication || data.adjudication_status === "running") && (
        <section data-testid="corr-adjudication">
          <h3 className="font-medium">{t("scan.correlation.adjudicationTitle")}</h3>
          <p className="mt-0.5 text-xs text-muted-foreground">
            {t("scan.correlation.adjudicationIntro")}
          </p>
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
                  <AdjudicationCardView key={i} card={c} />
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
        <h3 className="font-medium">{t("scan.correlation.vulnsTitle")}</h3>
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
              {g.vulns.map((v, i) => (
                <CorrVulnCard key={`${g.service}-${i}`} view={toCorrVulnView(v)} />
              ))}
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
        <section data-testid="corr-report">
          <h3 className="font-medium">{t("scan.correlation.reportTitle")}</h3>
          <div className="mt-2">
            <MarkdownView markdown={data.report_md} />
          </div>
        </section>
      )}
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

/** 单张裁决卡（spec 2026-08-27 §9）：正反结论同构——direction/conclusion 徽标 +
 *  跨仓上下文 + 分析过程（有序列表）+ 验证证据（file:line）+ 论证。 */
export function AdjudicationCardView({ card }: { card: AdjudicationCard }) {
  const { t } = useTranslation();
  const dirKey = ADJ_DIRECTION_KEY[card.direction] ?? card.direction;
  const isError = card.direction === "error";
  const isUpgrade = card.direction === "upgrade";
  // 语义色走 --c-red/--c-amber token（逐主题校对比），不用 tailwind 原生色阶
  const frame = isError
    ? "border-red/40 bg-red/5"
    : isUpgrade
      ? "border-amber/40 bg-amber/5"
      : "border-border";
  return (
    <div data-testid="corr-adj-card" className={`rounded-md border p-3 text-sm ${frame}`}>
      <div className="flex flex-wrap items-center gap-2">
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
      </div>
      {card.cross_service_context && (
        <div className="mt-1 text-xs">
          <span className="text-muted-foreground">
            {t("scan.correlation.adjContext")}:
          </span>{" "}
          {card.cross_service_context}
        </div>
      )}
      {card.analysis_process.length > 0 && (
        <div className="mt-1 text-xs">
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
        <div className="mt-1 text-xs">
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
        <p className="mt-1 text-xs">{card.reasoning}</p>
      )}
    </div>
  );
}
