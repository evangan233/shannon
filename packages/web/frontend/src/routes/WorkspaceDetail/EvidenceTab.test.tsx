import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { screen, fireEvent, cleanup, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import i18n from "@/i18n";
import { renderWithSwr } from "@/test/swr-render";
import type { EvidenceMatrix } from "@/api/types";
import { EvidenceTab } from "./EvidenceTab";

// SWR 数据源打桩：EvidenceTab 经 fetchEvidenceMatrix 拉 matrix。
// ApiError 须可 instanceof（404 分支判别）+ 带 status（strict tsconfig 下给真实构造器）。
vi.mock("@/api/client", () => ({
  ApiError: class MockApiError extends Error {
    status: number;
    constructor(status: number) {
      super(`API ${status}`);
      this.status = status;
    }
  },
  fetchEvidenceMatrix: vi.fn(),
}));

import { fetchEvidenceMatrix } from "@/api/client";
const mockedFetch = vi.mocked(fetchEvidenceMatrix);

const matrix: EvidenceMatrix = {
  schema_version: 1, scan_id: "s1", generated_at: null, sources: {},
  endpoints: [
    {
      method: "GET", path: "/allocations/:userId", raw_route: "/allocations/:userId",
      func_block_id: null, entry_verdict: "confirmed", entry_evidence: null,
      whitebox: {
        findings: [{
          id: "INJ-VULN-01", vuln_class: "injection", severity: "high",
          confidence: "high", title: "NoSQL 注入", evidence_chain: "a.js -> dao.js",
          witness_payload: "1'; while(true){}; //", verdict: "vulnerable",
          mismatch_reason: null, params: ["userId (path)"],
          auth_required: "isLoggedIn", source_location: null, sink_location: null,
        }],
        safe: [], dismissed: [],
      },
      blackbox: {
        verdicts: [{
          vulnerability_id: "INJ-VULN-01", vuln_class: "injection",
          status: "exploited", severity: "critical", impact: "RCE",
          exploitation_steps: ["send payload"], proof_of_impact: "uid=1000",
          run_id: "run-1",
        }],
        rejected: [],
      },
      coverage: "findings",
    },
    {
      method: "GET", path: "/profile", raw_route: "/profile",
      func_block_id: null, entry_verdict: "confirmed", entry_evidence: null,
      whitebox: {
        findings: [],
        safe: [{ subject: "GET /profile", defense_mechanism: "session 绑定",
                 location: "profile.js:14", contains_live_probe: false }],
        dismissed: [],
      },
      blackbox: { verdicts: [], rejected: [] },
      coverage: "defended",
    },
  ],
  unmatched: { findings: [], safe_dismissed: [], verdicts: [] },
};

function renderTab() {
  // react-router useParams 需路由上下文——ws/scanId 缺省 "" 时 SWR key 为 null
  // 不发请求，故经真实路由形状（router.tsx：/p/:workspace/scans/:scanId/evidence）注入。
  // renderWithSwr：独立 SWR cache，防跨测试缓存污染（项目既有 wrapper）。
  return renderWithSwr(
    <MemoryRouter initialEntries={["/p/w/scans/s1/evidence"]}>
      <Routes>
        <Route path="/p/:workspace/scans/:scanId/evidence" element={<EvidenceTab />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("EvidenceTab", () => {
  beforeEach(() => {
    // jsdom navigator.language 默认 en，LanguageDetector 会切到 en；断言依赖中文渲染，钉回 zh。
    void i18n.changeLanguage("zh");
    mockedFetch.mockResolvedValue(matrix);
  });
  afterEach(cleanup);

  it("渲染接口清单与 coverage 徽标", async () => {
    renderTab();
    // 选中接口的 path 同时出现在左列与右侧标题——限定左列清单断言。
    const list = await screen.findByTestId("evidence-list");
    expect(within(list).getByText("/allocations/:userId")).toBeTruthy();
    expect(within(list).getByText("/profile")).toBeTruthy();
    expect(screen.getByText(i18n.t("workspaceDetail.evidence.coverageFindings"))).toBeTruthy();
  });

  it("选中接口展示白盒/黑盒两栏证据", async () => {
    renderTab();
    const list = await screen.findByTestId("evidence-list");
    fireEvent.click(within(list).getByText("/allocations/:userId"));
    // 白盒栏（id/witness 均为「{id} · {title}」复合文本 + 跨栏同 id，用 regex/栏内限定）
    const wb = within(screen.getByTestId("evidence-whitebox"));
    expect(wb.getByText(/INJ-VULN-01/)).toBeTruthy();
    expect(wb.getByText(/while\(true\)/)).toBeTruthy();
    // 黑盒栏
    const bb = within(screen.getByTestId("evidence-blackbox"));
    expect(bb.getByText(/exploited/)).toBeTruthy();
    expect(bb.getByText("uid=1000")).toBeTruthy();
  });

  it("defended 接口展示防御结论与黑盒未验证空态", async () => {
    renderTab();
    const list = await screen.findByTestId("evidence-list");
    fireEvent.click(within(list).getByText("/profile"));
    expect(within(screen.getByTestId("evidence-whitebox")).getByText(/session 绑定/)).toBeTruthy();
    expect(screen.getByText(i18n.t("workspaceDetail.evidence.blackboxEmpty"))).toBeTruthy();
  });
});
