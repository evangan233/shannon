import type { AdjudicationCard, CorrFlow, CorrVuln } from "@/api/types";

/**
 * 跨仓结论 join 纯函数（2026-09-20 结论优先批次）：把阶段 B 裁决卡
 * （adjudication-log.json）与 merged_vulns / flows 关联起来——「哪些成立、
 * 哪些消掉、为什么」的数据层。全部纯函数，导出便于单测；组件保持纯渲染。
 *
 * 归类规则（plan 2026-09-20）：
 * - merged_vulns 条目只认 origin="queue" 的卡；dismissed 卡（upgrade 翻案 /
 *   maintain 维持）走 collectUpgraded / 已有 dismissed 表徽标，不进漏洞分组。
 * - confirm → 成立；downgrade → 消掉；conclusion=needs-review 或
 *   direction=error/upgrade/maintain（queue 卡异常方向）→ 存疑；无卡 → 未重审。
 */

export type CorrVerdictGroup =
  | "confirmed"
  | "refuted"
  | "uncertain"
  | "unadjudicated";

/** 索引键：service|vuln_id 复合防跨服务同 ID 碰撞（先例 dismissedVerdicts）。 */
export function verdictKey(service: string, vulnId: string): string {
  return `${service}|${vulnId}`;
}

/** 裁决卡索引：key = service|vuln_id，全量建（origin 过滤在各消费方做）。 */
export function buildVerdictIndex(
  cards: AdjudicationCard[],
): Map<string, AdjudicationCard> {
  const idx = new Map<string, AdjudicationCard>();
  for (const card of cards) {
    const { service, vuln_id: vulnId } = card.finding_ref ?? {};
    if (typeof service === "string" && typeof vulnId === "string" && vulnId) {
      idx.set(verdictKey(service, vulnId), card);
    }
  }
  return idx;
}

/** 单张裁决卡 → 结论组（归类逻辑单源：classifyVulnVerdict 与卡视图归一共用）。 */
export function verdictGroupFromCard(card: AdjudicationCard): CorrVerdictGroup {
  if (card.finding_ref?.origin !== "queue") return "unadjudicated";
  if (card.conclusion === "needs-review") return "uncertain";
  switch (card.direction) {
    case "confirm":
      return "confirmed";
    case "downgrade":
      return "refuted";
    default:
      // error（裁决失败占位）+ queue 批异常方向（upgrade/maintain 属 dismissed 批语义）
      return "uncertain";
  }
}

/** merged_vulns 条目 → 结论组（宽松 dict 防御，ID/service 缺失按未重审兜底）。 */
export function classifyVulnVerdict(
  vuln: CorrVuln,
  index: Map<string, AdjudicationCard>,
): CorrVerdictGroup {
  const id = typeof vuln.ID === "string" ? vuln.ID : "";
  const service = typeof vuln.service === "string" ? vuln.service : "";
  const card = id && service ? index.get(verdictKey(service, id)) : undefined;
  if (!card) return "unadjudicated";
  return verdictGroupFromCard(card);
}

/** merged_vulns 按结论组拆分：组内保持原序（服务/严重度排序交 groupByService）。 */
export function splitVulnsByVerdict(
  merged: Record<string, CorrVuln[]>,
  index: Map<string, AdjudicationCard>,
): Record<CorrVerdictGroup, { vc: string; vuln: CorrVuln }[]> {
  const out: Record<CorrVerdictGroup, { vc: string; vuln: CorrVuln }[]> = {
    confirmed: [], refuted: [], uncertain: [], unadjudicated: [],
  };
  for (const [vc, vulns] of Object.entries(merged)) {
    for (const vuln of vulns) {
      out[classifyVulnVerdict(vuln, index)].push({ vc, vuln });
    }
  }
  return out;
}

/** 翻案卡（origin=dismissed 且 direction=upgrade）：单仓判非漏洞、跨仓认为可达成立。 */
export function collectUpgraded(cards: AdjudicationCard[]): AdjudicationCard[] {
  return cards.filter(
    (c) => c.direction === "upgrade" && c.finding_ref?.origin === "dismissed",
  );
}

/** 结论组计数（漏洞四组 + 翻案），结论摘要卡数据源。 */
export interface CorrVerdictCounts {
  confirmed: number;
  refuted: number;
  uncertain: number;
  unadjudicated: number;
  upgraded: number;
}

export function countVerdictGroups(
  merged: Record<string, CorrVuln[]>,
  cards: AdjudicationCard[],
): CorrVerdictCounts {
  const index = buildVerdictIndex(cards);
  const split = splitVulnsByVerdict(merged, index);
  return {
    confirmed: split.confirmed.length,
    refuted: split.refuted.length,
    uncertain: split.uncertain.length,
    unadjudicated: split.unadjudicated.length,
    upgraded: collectUpgraded(cards).length,
  };
}

/** 漏洞所在跨服链反查：flows.vuln_refs 命中 vuln_id+service 的候选链（保序）。 */
export function findChainsForVuln(
  service: string,
  vulnId: string,
  flows: CorrFlow[],
): CorrFlow[] {
  if (!service || !vulnId) return [];
  return flows.filter((f) =>
    (f.vuln_refs ?? []).some(
      (ref) => ref.vuln_id === vulnId && ref.service === service,
    ),
  );
}

/** 裁决覆盖进度（running 态展示）：queue 总数与已覆盖数（含 error 占位卡）。 */
export function adjudicationCoverage(
  merged: Record<string, CorrVuln[]>,
  cards: AdjudicationCard[],
): { total: number; covered: number } {
  const total = Object.values(merged).reduce((a, l) => a + l.length, 0);
  const covered = cards.filter((c) => c.finding_ref?.origin === "queue").length;
  return { total, covered };
}
