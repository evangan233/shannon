// correlation-verdict 纯函数单测（2026-09-20 结论优先批次）：裁决卡索引 /
// 漏洞结论归类（confirm/downgrade/needs-review/error/无卡）/ 翻案收集 / 五向
// 计数 / 跨服链反查 / 裁决覆盖进度。
import { describe, it, expect } from "vitest";
import type { AdjudicationCard, CorrFlow } from "@/api/types";
import {
  adjudicationCoverage, buildVerdictIndex, classifyVulnVerdict,
  collectUpgraded, countVerdictGroups, findChainsForVuln, splitVulnsByVerdict,
  verdictGroupFromCard, verdictKey,
} from "./correlation-verdict";

const card = (over: Partial<AdjudicationCard>): AdjudicationCard => ({
  direction: "confirm",
  finding_ref: { service: "order-svc", vuln_id: "INJ-1", origin: "queue" },
  conclusion: "vulnerable",
  cross_service_context: "via gateway",
  analysis_process: [],
  verification_evidence: [],
  reasoning: "r",
  confidence: "high",
  ...over,
});

describe("verdictKey", () => {
  it("service|vuln_id 复合键防跨服务同 ID 碰撞", () => {
    expect(verdictKey("a", "INJ-1")).toBe("a|INJ-1");
    expect(verdictKey("a|INJ-1", "")).not.toBe(verdictKey("a", "INJ-1"));
  });
});

describe("verdictGroupFromCard / classifyVulnVerdict", () => {
  it("confirm(queue) → confirmed；downgrade → refuted", () => {
    expect(verdictGroupFromCard(card({}))).toBe("confirmed");
    expect(verdictGroupFromCard(card({ direction: "downgrade", conclusion: "downgraded" }))).toBe("refuted");
  });
  it("conclusion=needs-review 优先归存疑（含 error 卡）", () => {
    expect(verdictGroupFromCard(card({ direction: "error", conclusion: "needs-review", confidence: "low" }))).toBe("uncertain");
    expect(verdictGroupFromCard(card({ direction: "confirm", conclusion: "needs-review" }))).toBe("uncertain");
  });
  it("origin=dismissed 的卡不归漏洞组（翻案另路消费）", () => {
    expect(verdictGroupFromCard(card({ direction: "upgrade", finding_ref: { service: "s", vuln_id: "D-1", origin: "dismissed" } }))).toBe("unadjudicated");
  });
  it("无卡 → unadjudicated；ID/service 缺失兜底", () => {
    const index = buildVerdictIndex([card({})]);
    expect(classifyVulnVerdict({ ID: "INJ-9", title: "x" }, index)).toBe("unadjudicated");
    expect(classifyVulnVerdict({ ID: "", title: "x" }, index)).toBe("unadjudicated");
  });
  it("classifyVulnVerdict 按 service|ID 命中", () => {
    const index = buildVerdictIndex([card({}), card({ direction: "downgrade", finding_ref: { service: "web", vuln_id: "INJ-2", origin: "queue" } })]);
    expect(classifyVulnVerdict({ ID: "INJ-1", service: "order-svc", title: "t" }, index)).toBe("confirmed");
    expect(classifyVulnVerdict({ ID: "INJ-2", service: "web", title: "t" }, index)).toBe("refuted");
  });
});

describe("splitVulnsByVerdict / countVerdictGroups", () => {
  const vulns = {
    injection: [
      { ID: "INJ-1", service: "order-svc", title: "t" },
      { ID: "INJ-2", service: "web", title: "t" },
      { ID: "INJ-3", service: "web", title: "t" }, // 无卡
    ],
    xss: [{ ID: "X-1", service: "order-svc", title: "t" }], // 无卡
  };
  const cards = [
    card({}), // order-svc|INJ-1 confirm
    card({ direction: "downgrade", conclusion: "downgraded", finding_ref: { service: "web", vuln_id: "INJ-2", origin: "queue" } }),
    card({ direction: "upgrade", finding_ref: { service: "web", vuln_id: "D-9", origin: "dismissed" } }),
  ];
  it("四组拆分保留 vc 信息", () => {
    const split = splitVulnsByVerdict(vulns, buildVerdictIndex(cards));
    expect(split.confirmed.map((e) => e.vuln.ID)).toEqual(["INJ-1"]);
    expect(split.confirmed[0].vc).toBe("injection");
    expect(split.refuted.map((e) => e.vuln.ID)).toEqual(["INJ-2"]);
    expect(split.unadjudicated.map((e) => e.vuln.ID)).toEqual(["INJ-3", "X-1"]);
    expect(split.uncertain).toEqual([]);
  });
  it("五向计数（翻案独立于漏洞四组）", () => {
    expect(countVerdictGroups(vulns, cards)).toEqual({
      confirmed: 1, refuted: 1, uncertain: 0, unadjudicated: 2, upgraded: 1,
    });
  });
});

describe("collectUpgraded", () => {
  it("只收 origin=dismissed 且 direction=upgrade", () => {
    const cards = [
      card({ direction: "upgrade", finding_ref: { service: "s", vuln_id: "D-1", origin: "dismissed" } }),
      card({ direction: "upgrade", finding_ref: { service: "s", vuln_id: "Q-1", origin: "queue" } }),
      card({ direction: "maintain", finding_ref: { service: "s", vuln_id: "D-2", origin: "dismissed" } }),
    ];
    expect(collectUpgraded(cards).map((c) => c.finding_ref.vuln_id)).toEqual(["D-1"]);
  });
});

describe("findChainsForVuln", () => {
  const flows: CorrFlow[] = [
    {
      edge_from: "gw", edge_to: "order-svc", entry: "POST /orders", method: "o.Create",
      call_site: { file: "a.ts", line: 1, snippet: "s" },
      vuln_refs: [{ vuln_id: "INJ-1", service: "order-svc", title: "t", severity: "high", location: "l" }],
      confidence: "high", evidence: "e",
    },
    {
      edge_from: "gw", edge_to: "pay", entry: "POST /pay", method: "p.Pay",
      call_site: { file: "b.ts", line: 2, snippet: "s" },
      vuln_refs: [{ vuln_id: "INJ-1", service: "pay", title: "t", severity: "high", location: "l" }],
      confidence: "low", evidence: "e2",
    },
  ];
  it("按 vuln_id+service 双键命中，同 ID 不同服务不误报", () => {
    expect(findChainsForVuln("order-svc", "INJ-1", flows)).toHaveLength(1);
    expect(findChainsForVuln("pay", "INJ-1", flows)).toHaveLength(1);
    expect(findChainsForVuln("other", "INJ-1", flows)).toHaveLength(0);
  });
  it("空 ID/服务/无 refs 安全缺省", () => {
    expect(findChainsForVuln("", "INJ-1", flows)).toEqual([]);
    expect(findChainsForVuln("order-svc", "", flows)).toEqual([]);
  });
});

describe("adjudicationCoverage", () => {
  it("queue 总数与 origin=queue 卡数（error 占位也算已出位）", () => {
    const merged = { injection: [{ ID: "1", title: "t" }, { ID: "2", title: "t" }], xss: [{ ID: "3", title: "t" }] };
    const cards = [
      card({}),
      card({ direction: "error", conclusion: "needs-review", confidence: "low",
             finding_ref: { service: "s", vuln_id: "3", origin: "queue" } }),
      card({ direction: "upgrade", finding_ref: { service: "s", vuln_id: "D", origin: "dismissed" } }),
    ];
    expect(adjudicationCoverage(merged, cards)).toEqual({ total: 3, covered: 2 });
  });
});
