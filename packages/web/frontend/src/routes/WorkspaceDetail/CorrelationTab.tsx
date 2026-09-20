import { useCallback, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import useSWR from "swr";
import { useTranslation } from "react-i18next";
import { ChevronDown, Download, ListCollapse, ListTree } from "lucide-react";
import { ApiError, getCorrelationDetail } from "@/api/client";
import type { AdjudicationCard, CorrelationDetail, CorrDismissed, CorrVuln } from "@/api/types";
import { focusAnchor } from "@/utils/focusAnchor";
import { downloadTextFile } from "@/lib/download";
import {
  adjudicationCoverage, buildVerdictIndex, collectUpgraded, countVerdictGroups,
  findChainsForVuln, splitVulnsByVerdict, verdictGroupFromCard, verdictKey,
  type CorrVerdictGroup,
} from "@/lib/correlation-verdict";
import { Empty } from "@/components/Empty";
import { ErrorState } from "@/components/ErrorState";
import { MarkdownView } from "@/components/MarkdownView";
import { TopologyGraph } from "@/components/correlation/TopologyGraph";
import { AttackChainCard } from "@/components/correlation/AttackChainCard";
import { CorrStatsHeader, type SevKey } from "@/components/correlation/CorrStatsHeader";
import {
  CorrVulnCard, corrVulnAnchorId, toCorrVulnView,
  VERDICT_BADGE_CLS, type CorrVerdictView,
} from "@/components/correlation/CorrVulnCard";
import { CorrVerdictSummary, type VerdictEntry } from "@/components/correlation/CorrVerdictSummary";
import {
  CorrToc, CORR_SEC_BOUNDARIES, CORR_SEC_DISMISSED, CORR_SEC_FLOWS,
  CORR_SEC_MULTIHOP, CORR_SEC_REPORT, CORR_SEC_TOPOLOGY, CORR_SEC_VERDICT,
  CORR_SEC_VULNS, type CorrTocVuln,
} from "@/components/correlation/CorrToc";
import { AdjudicationCardView, ADJ_DIRECTION_KEY, DIRECTION_ORDER } from "@/components/correlation/AdjudicationCardView";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";

export { AdjudicationCardView };

/**
 * 跨仓关联结果 tab（D5，spec 2026-08-24；2026-09-20 结论优先批次重构）：
 * 左 sticky 目录（CorrToc，lg 起两栏）+ 右内容——总览头（数字卡 + severity 药丸）
 * → 跨仓结论摘要（五向结论卡 + 可展开清单，回答「哪些成立/消掉/为什么」）→
 * 漏洞（按裁决结论分组：成立展开、消掉/存疑/未重审折叠）→ 跨服务攻击链（漏洞
 * 引用可点定位）→ 多跳候选链 → 服务拓扑图 → 单仓已否决（跨仓重审）→ 信任边界
 * 表 → 报告 md（details 默认收起 + 下载）。漂移警告横幅接线 drift-warnings.json。
 *
 * 结论 join 纯函数在 lib/correlation-verdict.ts（verdictIndex/split/counts/
 * chains 反查），组件保持编排 + 渲染。定位体系对齐 ReportView 的 locateVuln：
 * 结论清单 / 攻击链 vuln_refs / 总览 severity 药丸 / 目录点击 → 目标漏洞卡折叠
 * 时先展开再 focusAnchor（coral 描边闪烁）；卡锚点 id 由 corrVulnAnchorId 单源。
 *
 * SWR 15s 轮询仅在「未完成」开（拓扑未出 = 关联跑着 / 裁决 running）；终态停
 * 轮询——completed 后继续打点无意义。topology === null → 阶段占位（「关联阶段
 * 进行中/未开始」+ corr_children 子仓状态）。props 收 ws/scanId（由挂载方 D6
 * 传入，对齐 brief；tab 内不经 useParams）。
 */

/** 漏洞结论组展示顺序（成立在前；默认仅第一组展开，见 openGroups 初始化）。 */
const VERDICT_GROUP_ORDER: CorrVerdictGroup[] = ["confirmed", "refuted", "uncertain", "unadjudicated"];
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
  // 结论组折叠（受控）：默认仅成立组展开（消掉/存疑/未重审折叠 + 计数徽标）；
  // locateVuln 定位时联动展开目标组。
  const [openGroups, setOpenGroups] = useState<Set<CorrVerdictGroup>>(
    () => new Set([VERDICT_GROUP_ORDER[0]]),
  );
  // 漏洞 ID → 结论组（locateVuln 联动用；每次渲染同步，回调解耦 data 时序）。
  const groupOfIdRef = useRef<Map<string, CorrVerdictGroup>>(new Map());
  const openGroupsRef = useRef(openGroups);
  openGroupsRef.current = openGroups;

  /** 定位漏洞卡（折叠联动，对齐 ReportView.locateVuln）：目标结论组先展开；
   *  组折叠或卡折叠 → 先展开，等重渲染（卡身挂载）后再 focusAnchor（异步），
   *  否则量到的 rect 是折叠卡头位置；全展开时同步定位（无重渲染等待）。 */
  const locateVuln = useCallback((id: string) => {
    const group = groupOfIdRef.current.get(id);
    const needExpandGroup = !!group && !openGroupsRef.current.has(group);
    if (group && needExpandGroup) {
      setOpenGroups((prev) => {
        if (prev.has(group)) return prev;
        const next = new Set(prev);
        next.add(group);
        return next;
      });
    }
    let wasCollapsed = false;
    setCollapsedVulns((prev) => {
      if (!prev.has(id)) return prev;
      wasCollapsed = true;
      const next = new Set(prev);
      next.delete(id);
      return next;
    });
    if (wasCollapsed || needExpandGroup) setTimeout(() => focusAnchor(corrVulnAnchorId(id)), 0);
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

  // ── 结论 join（lib/correlation-verdict 纯函数）：裁决卡 × merged_vulns × flows ──
  const adjCards = useMemo(() => data?.adjudication?.cards ?? [], [data]);
  const verdictCounts = useMemo(
    () => countVerdictGroups(data?.merged_vulns ?? {}, adjCards),
    [data, adjCards],
  );
  const verdictSplit = useMemo(
    () => splitVulnsByVerdict(data?.merged_vulns ?? {}, buildVerdictIndex(adjCards)),
    [data, adjCards],
  );
  // 漏洞 ID → 结论组（locateVuln 联动展开目标组）；渲染期同步到 ref。
  const groupOfId = useMemo(() => {
    const m = new Map<string, CorrVerdictGroup>();
    for (const [group, list] of Object.entries(verdictSplit)) {
      for (const { vuln } of list) {
        if (typeof vuln.ID === "string") m.set(vuln.ID, group as CorrVerdictGroup);
      }
    }
    return m;
  }, [verdictSplit]);
  groupOfIdRef.current = groupOfId;
  // 结论摘要清单条目（四组）：ID + 标题 + severity + reasoning 一句话。
  const verdictEntries = useMemo(() => {
    const index = buildVerdictIndex(adjCards);
    const out: Record<CorrVerdictGroup, VerdictEntry[]> = {
      confirmed: [], refuted: [], uncertain: [], unadjudicated: [],
    };
    for (const [group, list] of Object.entries(verdictSplit)) {
      out[group as CorrVerdictGroup] = list.map(({ vuln }) => {
        const id = typeof vuln.ID === "string" ? vuln.ID : "";
        const card = index.get(
          `${typeof vuln.service === "string" ? vuln.service : ""}|${id}`,
        );
        return {
          id,
          title: typeof vuln.title === "string" ? vuln.title : undefined,
          severity: typeof vuln.severity === "string" ? vuln.severity.toLowerCase() : undefined,
          service: typeof vuln.service === "string" ? vuln.service : undefined,
          reason: card?.reasoning,
          confidence: card?.confidence,
        };
      });
    }
    return out;
  }, [adjCards, verdictSplit]);
  const upgradedCards = useMemo(() => collectUpgraded(adjCards), [adjCards]);
  const coverage = useMemo(
    () => adjudicationCoverage(data?.merged_vulns ?? {}, adjCards),
    [data, adjCards],
  );
  // 子仓 service → scan_id（漏洞卡「查看单仓结果」链接）。
  const childScanByService = useMemo(() => {
    const m = new Map<string, string>();
    for (const c of data?.corr_children ?? []) m.set(c.service, c.scan_id);
    return m;
  }, [data]);
  const serviceOrder = useMemo(
    () => data?.topology?.services.map((s) => s.name) ?? [],
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

  // 漏洞卡 verdict 视图（origin=queue 卡归一 CorrVerdictView，key=service|id）；
  // group 归类经 verdictGroupFromCard 与漏洞分组单源。
  const verdictViewByServiceId = new Map<string, CorrVerdictView>();
  for (const card of adjCards) {
    if (card.finding_ref?.origin !== "queue") continue;
    verdictViewByServiceId.set(verdictKey(card.finding_ref.service, card.finding_ref.vuln_id), {
      group: verdictGroupFromCard(card),
      direction: card.direction,
      conclusion: card.conclusion,
      confidence: card.confidence,
      crossServiceContext: card.cross_service_context || undefined,
      reasoning: card.reasoning || undefined,
    });
  }
  // 漏洞结论分组（组内按服务分组排序，规则同 groupByService：serviceOrder 优先）。
  const vulnGroupsByVerdict = VERDICT_GROUP_ORDER.map((group) => ({
    group,
    services: groupSplitByService(verdictSplit[group], serviceOrder),
  })).filter((g) => g.services.some((s) => s.vulns.length > 0));
  // 目录数据：区块 presence + 漏洞条目（文档序 = 组序 → 服务序，scrollspy 才准）。
  const tocSections = {
    flows: data.flows.length > 0,
    multihop: data.multi_hop_chains.length > 0,
    topology: true,
    dismissed: data.dismissed.length > 0,
    boundaries: data.boundaries.length > 0,
    report: !!data.report_md,
  };
  const tocVulns: CorrTocVuln[] = vulnGroupsByVerdict.flatMap(({ group, services }) =>
    services.flatMap((svc) =>
      svc.vulns
        .map((v): CorrTocVuln | null => {
          const id = typeof v.ID === "string" ? v.ID : "";
          if (!id) return null;
          return {
            id,
            anchorId: corrVulnAnchorId(id),
            severity: typeof v.severity === "string" ? v.severity.toLowerCase() : undefined,
            service: svc.service || undefined,
            group,
          };
        })
        .filter((v): v is CorrTocVuln => v !== null),
    ),
  );
  const toggleGroup = (group: CorrVerdictGroup) => {
    setOpenGroups((prev) => {
      const next = new Set(prev);
      if (next.has(group)) next.delete(group);
      else next.add(group);
      return next;
    });
  };

  // 裁决 direction 聚合（五向计数，裁决明细区徽标行）
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

  // 左栏目录 + 右内容两栏（对齐 ReportView 布局：lg 起两栏，sticky top-44 ≈
  // TopBar + 进度 tabs 高度；跳转落点由 focusAnchor 运行时量取）。
  const body = (
    <div className="space-y-6">
      {/* 总览头：数字卡 + severity 药丸（点击定位到该等级第一条漏洞卡） */}
      <CorrStatsHeader
        detail={data}
        onLocateSev={(sev: SevKey) => {
          const id = firstVulnIdBySev.get(sev);
          if (id) locateVuln(id);
        }}
      />
      {/* 漂移警告横幅（后端 drift-warnings.json，2026-09-20 接线） */}
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
      {/* 跨仓结论摘要（第一屏回答「哪些成立/消掉/为什么」） */}
      <section id={CORR_SEC_VERDICT} data-testid="corr-verdict-section">
        <CorrVerdictSummary
          counts={verdictCounts}
          entries={verdictEntries}
          upgraded={upgradedCards}
          running={data.adjudication_status === "running"}
          failed={data.adjudication_status === "failed"}
          coverage={coverage}
          onLocateVuln={locateVuln}
        />
      </section>
      {/* 漏洞区（按裁决结论分组：成立展开，消掉/存疑/未重审折叠） */}
      <section id={CORR_SEC_VULNS} data-testid="corr-vulns">
        <SectionHead
          title={t("scan.correlation.vulnsTitle")}
          actions={
            vulnIds.length > 0 && (
              <CollapseToggleButtons
                scope="vulns"
                onCollapse={() => setCollapsedVulns(new Set(vulnIds))}
                onExpand={() => setCollapsedVulns(new Set())}
              />
            )
          }
        />
        <div className="mt-2 space-y-3">
          {vulnGroupsByVerdict.length === 0 && (
            <p className="text-sm text-muted-foreground">
              {t("scan.correlation.vulnsEmpty")}
            </p>
          )}
          {vulnGroupsByVerdict.map(({ group, services }) => {
            const total = services.reduce((a, s) => a + s.vulns.length, 0);
            const open = openGroups.has(group);
            return (
              <div
                key={group}
                data-testid="corr-vuln-verdict-group"
                data-group={group}
                className="rounded-md border border-border"
              >
                <button
                  type="button"
                  data-testid={`corr-verdict-group-head-${group}`}
                  aria-expanded={open}
                  onClick={() => toggleGroup(group)}
                  className="flex w-full items-center gap-2.5 rounded-t-md p-2.5 text-left transition-colors hover:bg-accent/50 focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary"
                >
                  <span
                    className={`inline-flex items-center rounded-full border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wide ${VERDICT_BADGE_CLS[group]}`}
                  >
                    {t(`scan.correlation.verdict.${group}`)}
                  </span>
                  <span className="text-[18px] font-bold leading-none">{total}</span>
                  <ChevronDown
                    className={`ml-auto size-4 shrink-0 text-muted-foreground transition-transform duration-150 ${open ? "" : "-rotate-90"}`}
                    aria-hidden="true"
                  />
                </button>
                {open && (
                  <div className="space-y-3 border-t border-border p-2.5">
                    {services.map((g) => (
                      <div key={g.service} data-testid="corr-vuln-group" className="space-y-2">
                        <Badge variant="outline" className="font-mono">
                          {g.service || t("scan.correlation.serviceUnknown")}
                        </Badge>
                        {g.vulns.map((v, i) => {
                          const view = toCorrVulnView(v);
                          const id = typeof v.ID === "string" ? v.ID : "";
                          const service = typeof v.service === "string" ? v.service : "";
                          const sid = childScanByService.get(service);
                          return (
                            <CorrVulnCard
                              key={`${group}-${g.service}-${i}`}
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
                              verdict={verdictViewByServiceId.get(verdictKey(service, id))}
                              chains={findChainsForVuln(service, id, data.flows)}
                              childScanHref={sid ? `/p/${ws}/scans/${sid}` : undefined}
                            />
                          );
                        })}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </section>
      <section id={CORR_SEC_FLOWS} data-testid="corr-flows">
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
      <section id={CORR_SEC_MULTIHOP} data-testid="corr-multihop">
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
      {/* 服务拓扑（背景信息，结论之后） */}
      <section id={CORR_SEC_TOPOLOGY} data-testid="corr-topology">
        <h3 className="font-medium">{t("scan.correlation.topologyTitle")}</h3>
        <TopologyGraph topology={data.topology} />
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
        <section id={CORR_SEC_DISMISSED} data-testid="corr-dismissed">
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
      <section id={CORR_SEC_BOUNDARIES} data-testid="corr-boundaries">
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
        <section id={CORR_SEC_REPORT} data-testid="corr-report">
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

  return (
    <div className="lg:grid lg:grid-cols-[210px_minmax(0,1fr)] lg:gap-6">
      {/* 目录左栏（CorrToc）：同 ReportView 布局——sticky 自滚，跳转落点由
          focusAnchor 运行时量取，不依赖此值。 */}
      <aside className="sticky top-44 hidden max-h-[calc(100vh-12rem)] self-start overflow-y-auto pr-1 lg:block">
        <CorrToc vulns={tocVulns} sections={tocSections} onLocateVuln={locateVuln} />
      </aside>
      {body}
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

/** merged_vulns（键 = vuln class）拍平后按条目 service 字段分组（委托
 *  groupSplitByService，排序规则单源）。纯函数，导出便于测试。 */
export function groupByService(
  merged: Record<string, CorrVuln[]>,
  serviceOrder: string[] = [],
): { service: string; vulns: CorrVuln[] }[] {
  return groupSplitByService(
    Object.entries(merged).flatMap(([vc, vulns]) =>
      vulns.map((vuln) => ({ vc, vuln })),
    ),
    serviceOrder,
  );
}

/** 结论组条目（{vc, vuln}[]）按 service 分组。组序：serviceOrder（拓扑服务序，
 *  入口在前）优先，未列出的服务按字典序垫底；service 字段缺失 → ""（渲染层
 *  显示「未知服务」）。纯函数，导出便于测试。 */
export function groupSplitByService(
  entries: { vc: string; vuln: CorrVuln }[],
  serviceOrder: string[] = [],
): { service: string; vulns: CorrVuln[] }[] {
  const byService = new Map<string, CorrVuln[]>();
  for (const { vuln } of entries) {
    const service = typeof vuln.service === "string" ? vuln.service : "";
    const bucket = byService.get(service);
    if (bucket) bucket.push(vuln);
    else byService.set(service, [vuln]);
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
