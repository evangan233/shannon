import { useCallback, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import useSWR from "swr";
import { useTranslation } from "react-i18next";
import { ChevronDown, Download, ListCollapse, ListTree } from "lucide-react";
import { ApiError, getCorrelationDetail } from "@/api/client";
import type { AdjudicationCard, CorrelationDetail, CorrVuln } from "@/api/types";
import { focusAnchor } from "@/utils/focusAnchor";
import { downloadTextFile } from "@/lib/download";
import {
  adjudicationCoverage, buildVerdictIndex, collectUpgraded, findChainsForVuln,
  findMultiHopsForVuln, splitVulnsByVerdict, verdictGroupFromCard, verdictKey,
  type CorrVerdictGroup,
} from "@/lib/correlation-verdict";
import { Empty } from "@/components/Empty";
import { ErrorState } from "@/components/ErrorState";
import { TopologyResultView } from "@/components/correlation/TopologyResultView";
import { AttackChainCard } from "@/components/correlation/AttackChainCard";
import { CorrStatsHeader } from "@/components/correlation/CorrStatsHeader";
import {
  CorrVulnCard, corrVulnAnchorId, toCorrVulnView,
  VERDICT_BADGE_CLS, type CorrVerdictView,
} from "@/components/correlation/CorrVulnCard";
import type { CorrStatGroup } from "@/components/correlation/CorrStatsHeader";
import {
  CorrToc, CORR_SEC_MULTIHOP, CORR_SEC_TOPOLOGY, CORR_SEC_VULNS,
  type CorrTocVuln,
} from "@/components/correlation/CorrToc";
import { AdjudicationCardView } from "@/components/correlation/AdjudicationCardView";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";

export { AdjudicationCardView };

/**
 * 跨仓关联结果 tab（D5，spec 2026-08-24；2026-09-20 去重 + 09-21 静默/设计批次）：
 * 左 sticky 目录（CorrToc，lg 起两栏）+ 右内容——总览头（结论四件套大数字 +
 * 成立口径 severity 药丸 + 过程量脚注 + 报告下载挂点，2026-09-21 由过程量数字卡
 * 改结论优先）→ 漏洞（唯一主区，按裁决结论分组：翻案置顶 → 成立展开完整卡 →
 * 消掉/存疑/未重审紧凑行【原因一句话直接铺出，点行展开完整卡】）→ 裁决状态横幅
 * （仅进行中/失败/error 占位卡时出现，正常完成零占位）→ 服务拓扑图 → 多跳候选链 →
 * 未关联漏洞的调用链（有才显示）。信任边界/单仓已否决/关联报告全文不再上页面——
 * 信息落位：边界进 md 报告附录，否决复核一行进 md，全文经下载按钮获取。
 *
 * 去重/静默两轮（2026-09-20 八问 + 09-21 四章复核）：①结论摘要独立章撤除（清单
 * 并入漏洞区紧凑行）；②攻击链独立章撤除（链只在漏洞卡「所在跨服链」，孤链降级
 * 附录）；③裁决卡平铺撤除；④单仓已否决静默（翻案置顶漏洞区，复核行留 md）；
 * ⑤多跳移到拓扑后；⑥信任边界/已否决/关联报告章节撤除（09-21）。
 *
 * 结论 join 纯函数在 lib/correlation-verdict.ts（verdictIndex/split/chains 反查），
 * 组件保持编排 + 渲染。定位体系对齐 ReportView 的 locateVuln：行/卡点击 / 总览
 * severity 药丸 / 目录点击 → 目标组与行先展开再 focusAnchor（coral 描边闪烁）；
 * 卡锚点 id 由 corrVulnAnchorId 单源。
 *
 * SWR 15s 轮询仅在「未完成」开（拓扑未出 = 关联跑着 / 裁决 running）；终态停
 * 轮询。topology === null → 阶段占位。props 收 ws/scanId（由挂载方 D6 传入）。
 */

/** 漏洞结论组展示顺序（成立在前；默认仅第一组展开，见 openGroups 初始化）。 */
const VERDICT_GROUP_ORDER: CorrVerdictGroup[] = ["confirmed", "refuted", "uncertain", "unadjudicated"];
/** 紧凑行结论组（成立组走完整卡，其余组折叠成行）。 */
const ROW_GROUPS: CorrVerdictGroup[] = ["refuted", "uncertain", "unadjudicated"];

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

  // 漏洞卡集中折叠 state（ReportView 模式）：空 set = 全展开（成立组默认态）。
  const [collapsedVulns, setCollapsedVulns] = useState<Set<string>>(new Set());
  // 结论组折叠（受控）：默认仅成立组展开（消掉/存疑/未重审折叠 + 计数徽标）；
  // locateVuln 定位时联动展开目标组。
  const [openGroups, setOpenGroups] = useState<Set<CorrVerdictGroup>>(
    () => new Set([VERDICT_GROUP_ORDER[0]]),
  );
  // 紧凑行展开 state（消掉/存疑/未重审组）：默认全收，点行展开完整卡。
  const [openRows, setOpenRows] = useState<Set<string>>(new Set());
  // 漏洞 ID → 结论组（locateVuln 联动用；每次渲染同步，回调解耦 data 时序）。
  const groupOfIdRef = useRef<Map<string, CorrVerdictGroup>>(new Map());
  const openGroupsRef = useRef(openGroups);
  openGroupsRef.current = openGroups;

  /** 定位漏洞卡（折叠联动，对齐 ReportView.locateVuln）：目标结论组先展开；
   *  紧凑行组的行先展开；组折叠或卡折叠 → 先展开，等重渲染（卡身挂载）后再
   *  focusAnchor（异步），否则量到的 rect 是折叠卡头位置；全展开时同步定位。 */
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
    // 紧凑行组：行默认收起——先开行（卡体才挂载），并保证卡身展开。
    const needOpenRow = !!group && (ROW_GROUPS as string[]).includes(group);
    if (needOpenRow) {
      setOpenRows((prev) => {
        if (prev.has(id)) return prev;
        const next = new Set(prev);
        next.add(id);
        return next;
      });
      setCollapsedVulns((prev) => {
        if (!prev.has(id)) return prev;
        const next = new Set(prev);
        next.delete(id);
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
    if (wasCollapsed || needExpandGroup || needOpenRow) {
      setTimeout(() => focusAnchor(corrVulnAnchorId(id)), 0);
    } else {
      focusAnchor(corrVulnAnchorId(id));
    }
  }, []);

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
  const verdictIndex = useMemo(() => buildVerdictIndex(adjCards), [adjCards]);
  const verdictSplit = useMemo(
    () => splitVulnsByVerdict(data?.merged_vulns ?? {}, verdictIndex),
    [data, verdictIndex],
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
  // 裁决覆盖进度（running 横幅：已出/总数）。
  const coverage = useMemo(
    () => adjudicationCoverage(data?.merged_vulns ?? {}, adjCards),
    [data, adjCards],
  );
  // 翻案卡（origin=dismissed 且 direction=upgrade）：置顶进漏洞区。
  const upgradedCards = useMemo(() => collectUpgraded(adjCards), [adjCards]);
  // 结论四件套计数（总览头第一行；与漏洞分组同一 verdictSplit，口径天然单源）。
  const verdictCounts = useMemo(
    () => ({
      confirmed: verdictSplit.confirmed.length,
      refuted: verdictSplit.refuted.length,
      uncertain: verdictSplit.uncertain.length,
      unadjudicated: verdictSplit.unadjudicated.length,
      upgraded: upgradedCards.length,
    }),
    [verdictSplit, upgradedCards],
  );
  /** 定位结论组（总览头结论数字点击）：组头常驻 DOM（组体才受折叠控制），直接
   *  focusAnchor；confirmed 有翻案时落翻案置顶块（本组最高优先级信号在前）。
   *  目标组若折叠 → 先展开再定位（组头不受影响，展开只为后续逐卡浏览）。 */
  const locateGroup = useCallback((group: CorrStatGroup) => {
    if (group !== "upgraded") {
      setOpenGroups((prev) => {
        if (prev.has(group as CorrVerdictGroup)) return prev;
        const next = new Set(prev);
        next.add(group as CorrVerdictGroup);
        return next;
      });
    }
    const anchor =
      group === "upgraded" || (group === "confirmed" && upgradedCards.length > 0)
        ? "corr-vuln-upgraded"
        : `corr-group-${group}`;
    focusAnchor(anchor);
  }, [upgradedCards.length]);

  // severity → 成立组内该等级第一条漏洞 ID（扁平序）：总览 severity 药丸点击
  // 定位目标。只数成立口径（2026-09-21 修正：此前数全量含消掉条目，点击会跳进
  // 消掉组——药丸文案「成立严重度」与定位目标必须同一口径）。
  const firstVulnIdBySev = useMemo(() => {
    const map = new Map<string, string>();
    for (const { vuln } of verdictSplit.confirmed) {
      const id = typeof vuln.ID === "string" ? vuln.ID : undefined;
      const sev = typeof vuln.severity === "string" ? vuln.severity.toLowerCase() : "";
      if (id && sev && !map.has(sev)) map.set(sev, id);
    }
    return map;
  }, [verdictSplit]);
  // 成立口径 severity 计数（总览头第二行药丸）。
  const confirmedSevCounts = useMemo(() => {
    const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const { vuln } of verdictSplit.confirmed) {
      const sev = typeof vuln.severity === "string" ? vuln.severity.toLowerCase() : "";
      if (sev in counts) counts[sev] += 1;
    }
    return counts;
  }, [verdictSplit]);
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
  // 未被任何漏洞引用的调用链（链章节已撤，孤链降级附录——有才显示）。
  const orphanFlows = useMemo(() => {
    const known = new Set(
      Object.values(data?.merged_vulns ?? {})
        .flat()
        .map((v) =>
          typeof v.service === "string" && typeof v.ID === "string"
            ? verdictKey(v.service, v.ID)
            : "",
        )
        .filter(Boolean),
    );
    return (data?.flows ?? []).filter(
      (f) => !(f.vuln_refs ?? []).some(
        (ref) => !!ref.vuln_id && known.has(verdictKey(ref.service, ref.vuln_id)),
      ),
    );
  }, [data]);

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
  // group 归类经 verdictGroupFromCard 与漏洞分组单源；exploit_path 透传（宽松防御，
  // 历史裁决卡无此字段 → 卡片走 flow 反查/入口自证/未建链降级）。
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
      exploitPath: card.exploit_path && typeof card.exploit_path === "object"
        ? card.exploit_path : undefined,
      refined: card.refined_finding && typeof card.refined_finding === "object"
        ? card.refined_finding : undefined,
    });
  }
  // 入口服务集合（漏洞所在服务是入口 → 单仓自证可达，卡片免跨服链）。
  // 渲染段普通构造（勿 useMemo——位于早退 return 之后，会成条件 hook）。
  const entryServices = new Set(
    (data.topology?.services ?? [])
      .filter((s) => s.role === "entrypoint")
      .map((s) => s.name),
  );
  // 漏洞结论分组（组内按服务分组排序，规则同 groupSplitByService：serviceOrder 优先）。
  const vulnGroupsByVerdict = VERDICT_GROUP_ORDER.map((group) => ({
    group,
    services: groupSplitByService(verdictSplit[group], serviceOrder),
  })).filter((g) => g.services.some((s) => s.vulns.length > 0));
  // 目录数据：区块 presence + 漏洞条目（文档序 = 组序 → 服务序，scrollspy 才准）。
  const tocSections = {
    multihop: data.multi_hop_chains.length > 0,
    topology: true,
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
  const toggleRow = (id: string) => {
    setOpenRows((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  // 裁决状态横幅（仅在「有话说」时出现，正常完成零占位）：running 进度 /
  // failed 透明提示 / error 占位卡（故障信号必见；全量卡留 md 附录与
  // adjudication-log.json）。
  const errorCards = (data.adjudication?.cards ?? []).filter((c) => c.direction === "error");
  const showAdjudication =
    data.adjudication_status === "running" || data.adjudication_status === "failed"
    || errorCards.length > 0;

  // 左栏目录 + 右内容两栏（对齐 ReportView 布局：lg 起两栏，sticky top-44 ≈
  // TopBar + 进度 tabs 高度；跳转落点由 focusAnchor 运行时量取）。
  const body = (
    <div className="space-y-6">
      {/* 总览头：结论四件套大数字（点击定位组）+ 成立口径 severity 药丸 +
          过程量 mono 脚注；报告下载挂在行 1 右端（全文含成立漏洞全文 + 消掉
          清单 + 信任边界 + 裁决留档附录，与结构化视图互补，不再上页面） */}
      <CorrStatsHeader
        detail={data}
        counts={verdictCounts}
        confirmedSevCounts={confirmedSevCounts}
        onLocateSev={(sev: string) => {
          const id = firstVulnIdBySev.get(sev);
          if (id) locateVuln(id);
        }}
        onLocateGroup={locateGroup}
        actions={
          data.report_md ? (
            <div data-testid="corr-report">
              <Button
                variant="ghost"
                size="sm"
                className="text-muted-foreground"
                onClick={() => downloadTextFile(`correlation-${scanId}.md`, data.report_md ?? "")}
              >
                <Download aria-hidden />
                {t("scan.correlation.reportDownload")}
              </Button>
            </div>
          ) : undefined
        }
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
      {/* 漏洞区（唯一主区）：翻案置顶 → 结论分组（成立完整卡，其余紧凑行） */}
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
          {upgradedCards.length > 0 && (
            <CorrUpgradedList cards={upgradedCards} />
          )}
          {vulnGroupsByVerdict.length === 0 && (
            <p className="text-sm text-muted-foreground">
              {t("scan.correlation.vulnsEmpty")}
            </p>
          )}
          {vulnGroupsByVerdict.map(({ group, services }) => {
            const total = services.reduce((a, s) => a + s.vulns.length, 0);
            const open = openGroups.has(group);
            const rowMode = (ROW_GROUPS as string[]).includes(group);
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
                  id={`corr-group-${group}`}
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
                        {rowMode ? (
                          // 紧凑行：原因一句话直接铺出（「为什么消掉」第一眼可见），
                          // 点行展开完整卡（跨仓上下文 + 单仓全文 + 所在链）。
                          g.vulns.map((v) => {
                            const id = typeof v.ID === "string" ? v.ID : "";
                            const service = typeof v.service === "string" ? v.service : "";
                            const card = verdictIndex.get(verdictKey(service, id));
                            const reason = card?.reasoning || card?.cross_service_context;
                            const title = typeof v.title === "string" ? v.title : "";
                            const sev = typeof v.severity === "string"
                              ? v.severity.toLowerCase() : "";
                            const sid = childScanByService.get(service);
                            const rowOpen = openRows.has(id);
                            return (
                              <div key={`${group}-${id}`} className="rounded-md border border-border">
                                <button
                                  type="button"
                                  data-testid="corr-verdict-row"
                                  data-vuln-id={id}
                                  aria-expanded={rowOpen}
                                  onClick={() => toggleRow(id)}
                                  className="flex w-full items-start gap-2 rounded-t-md p-2.5 text-left transition-colors hover:bg-accent/50 focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary"
                                >
                                  <span className="min-w-0 flex-1 space-y-0.5">
                                    <span className="flex min-w-0 items-center gap-2">
                                      <span className="shrink-0 font-mono text-[12.5px] font-semibold text-foreground">
                                        {id}
                                      </span>
                                      {sev && (
                                        <span className="shrink-0 font-mono text-[10px] uppercase text-muted-foreground">
                                          {sev}
                                        </span>
                                      )}
                                      {title && (
                                        <span className="min-w-0 truncate text-xs text-foreground/80">
                                          {title}
                                        </span>
                                      )}
                                    </span>
                                    {reason ? (
                                      <span className="line-clamp-1 block text-xs text-muted-foreground">
                                        {reason}
                                      </span>
                                    ) : (
                                      <span className="block text-xs text-muted-foreground">
                                        {t("scan.correlation.verdict.empty")}
                                      </span>
                                    )}
                                  </span>
                                  {card?.confidence && (
                                    <Badge variant="outline" className="mt-0.5 shrink-0 font-mono text-[10px]">
                                      {card.confidence}
                                    </Badge>
                                  )}
                                  <ChevronDown
                                    className={`mt-1 size-4 shrink-0 text-muted-foreground transition-transform duration-150 ${rowOpen ? "" : "-rotate-90"}`}
                                    aria-hidden="true"
                                  />
                                </button>
                                {rowOpen && (
                                  <div className="border-t border-border p-2.5">
                                    <CorrVulnCard
                                      view={toCorrVulnView(v)}
                                      anchorId={corrVulnAnchorId(id)}
                                      collapsed={collapsedVulns.has(id)}
                                      onToggleCollapse={() =>
                                        setCollapsedVulns((prev) => {
                                          const next = new Set(prev);
                                          if (next.has(id)) next.delete(id);
                                          else next.add(id);
                                          return next;
                                        })
                                      }
                                      verdict={verdictViewByServiceId.get(verdictKey(service, id))}
                                      chains={findChainsForVuln(service, id, data.flows)}
                                      multiHops={findMultiHopsForVuln(service, data.multi_hop_chains)}
                                      entrySelfServed={entryServices.has(service)}
                                      childScanHref={sid ? `/p/${ws}/scans/${sid}` : undefined}
                                    />
                                  </div>
                                )}
                              </div>
                            );
                          })
                        ) : (
                          g.vulns.map((v, i) => {
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
                                multiHops={findMultiHopsForVuln(service, data.multi_hop_chains)}
                                entrySelfServed={entryServices.has(service)}
                                childScanHref={sid ? `/p/${ws}/scans/${sid}` : undefined}
                              />
                            );
                          })
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </section>
      {/* 裁决状态横幅（仅进行中/失败/error 占位卡时出现——结论已并入漏洞区，
          全量裁决卡留 md 附录与 adjudication-log.json 下载；正常完成零占位） */}
      {showAdjudication && (
        <div data-testid="corr-adjudication" className="space-y-2">
          {data.adjudication_status === "running" && (
            <div
              data-testid="corr-adj-running"
              className="rounded-md border border-amber/40 bg-amber/10 p-3 text-sm text-amber"
            >
              {t("scan.correlation.verdict.running", {
                covered: coverage.covered,
                total: coverage.total,
              })}
            </div>
          )}
          {data.adjudication_status === "failed" && (
            <div
              data-testid="corr-adj-failed"
              className="rounded-md border border-red/40 bg-red/10 p-3 text-sm text-red"
            >
              {t("scan.correlation.verdict.failed")}
            </div>
          )}
          {data.adjudication?.error && (
            <p data-testid="corr-adjudication-error" className="text-sm text-destructive">
              {data.adjudication.error}
            </p>
          )}
          {errorCards.length > 0 && (
            <div className="space-y-2">
              {errorCards.map((c, i) => (
                <AdjudicationCardView key={i} card={c} collapsed={false}
                  onToggleCollapse={() => {}} />
              ))}
            </div>
          )}
        </div>
      )}
      {/* 服务拓扑（背景区开始；多跳是拓扑的衍生推断，紧跟其后）：复用配置页
          TopologyEditor 画布（只读）——2026-09-21 替换自绘小 SVG */}
      <section id={CORR_SEC_TOPOLOGY} data-testid="corr-topology">
        <h3 className="font-medium">{t("scan.correlation.topologyTitle")}</h3>
        <TopologyResultView topology={data.topology} />
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
              <summary className="cursor-pointer rounded-sm py-1 text-[13px] text-muted-foreground transition-colors hover:text-foreground focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary">
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
      {/* 未被漏洞引用的调用链（链章节已撤；孤链有保留价值才显示） */}
      {orphanFlows.length > 0 && (
        <section data-testid="corr-orphan-flows">
          <h3 className="font-medium">{t("scan.correlation.orphanFlowsTitle")}</h3>
          <div className="mt-2 space-y-2">
            {orphanFlows.map((f, i) => (
              <AttackChainCard key={i} flow={f} onLocateRef={locateVuln} />
            ))}
          </div>
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

/** 翻案置顶列表（origin=dismissed 且 direction=upgrade 的裁决卡全文）：单仓判非
 *  漏洞、跨仓重审认为可达成立——本页最高优先级信号，amber 强调块。本地折叠
 *  state（默认收起，点卡头展开论证），不影响漏洞卡集中折叠。 */
function CorrUpgradedList({ cards }: { cards: AdjudicationCard[] }) {
  const { t } = useTranslation();
  const [collapsed, setCollapsed] = useState<Set<number>>(() => new Set(cards.map((_, i) => i)));
  return (
    <div
      data-testid="corr-vuln-upgraded"
      id="corr-vuln-upgraded"
      className="space-y-2 rounded-md border border-amber/40 bg-amber/5 p-2.5"
    >
      <div className="flex items-center gap-2">
        <span className="inline-flex items-center rounded-full border border-amber/40 bg-amber/10 px-2 py-0.5 font-mono text-[10px] uppercase tracking-wide text-amber">
          {t("scan.correlation.verdict.upgraded")}
        </span>
        <span className="text-[18px] font-bold leading-none">{cards.length}</span>
        <span className="text-xs text-muted-foreground">
          {t("scan.correlation.upgradedIntro")}
        </span>
      </div>
      {cards.map((card, i) => (
        <AdjudicationCardView
          key={i}
          card={card}
          collapsed={collapsed.has(i)}
          onToggleCollapse={() =>
            setCollapsed((prev) => {
              const next = new Set(prev);
              if (next.has(i)) next.delete(i);
              else next.add(i);
              return next;
            })
          }
        />
      ))}
    </div>
  );
}

/** 区块头（标题 + intro + 右侧 actions）：漏洞区的「全部收起/展开」挂点。 */
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
 *  scope 进 testid：漏洞区按钮，测试 within 区块圈定。 */
function CollapseToggleButtons({ scope, onCollapse, onExpand }: {
  scope: "vulns";
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
