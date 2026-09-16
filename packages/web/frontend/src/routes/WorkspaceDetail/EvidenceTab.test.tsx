import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { screen, fireEvent, cleanup, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes, Outlet } from "react-router-dom";
import i18n from "@/i18n";
import { renderWithSwr } from "@/test/swr-render";
import type { EvidenceMatrix } from "@/api/types";
import { EvidenceTab } from "./EvidenceTab";

// SWR 数据源打桩：EvidenceTab 经 fetchEvidenceMatrix 拉 matrix，另拉 dataflow
// 建跳转映射（404/undefined → 无映射 → 卡上「查看数据流」链接不渲染）。
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
  fetchDataflowView: vi.fn(),
}));

import { fetchEvidenceMatrix, fetchDataflowView } from "@/api/client";
const mockedFetch = vi.mocked(fetchEvidenceMatrix);
const mockedDataflow = vi.mocked(fetchDataflowView);

const matrix: EvidenceMatrix = {
  schema_version: 2, scan_id: "s1", generated_at: null,
  sources: { entry_points: true, report_data: true, blackbox_runs: 0 },
  endpoints: [
    {
      method: "GET", path: "/allocations/:userId", raw_route: "/allocations/:userId",
      func_block_id: null, entry_verdict: "confirmed",
      entry_evidence: "Express route: app.get('/allocations/:userId')",
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
  // 不发请求。路由形状对齐生产 router.tsx（嵌套：父 /p/:ws/scans/:scanId + 子段
  // evidence）——卡上「查看报告/数据流」链接用相对路径 ../report，平面 Route 下
  // 相对解析基准错误（jsdom 实测回落 /report）。
  // renderWithSwr：独立 SWR cache，防跨测试缓存污染（项目既有 wrapper）。
  return renderWithSwr(
    <MemoryRouter initialEntries={["/p/w/scans/s1/evidence"]}>
      <Routes>
        <Route path="/p/:workspace/scans/:scanId" element={<Outlet />}>
          <Route path="evidence" element={<EvidenceTab />} />
        </Route>
      </Routes>
    </MemoryRouter>,
  );
}

describe("EvidenceTab", () => {
  beforeEach(() => {
    // jsdom navigator.language 默认 en，LanguageDetector 会切到 en；断言依赖中文渲染，钉回 zh。
    void i18n.changeLanguage("zh");
    mockedFetch.mockResolvedValue(matrix);
    // dataflow 默认 404（SWR onError 数据 undefined）→ 无映射 → 数据流链接不渲染
    mockedDataflow.mockRejectedValue(new Error("404"));
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

  it("unmatched 面板：完整证据卡 + reason 徽标 + 三桶条目", async () => {
    const m = JSON.parse(JSON.stringify(matrix)) as EvidenceMatrix;
    m.unmatched = {
      findings: [{
        id: "AUTHZ-VULN-02", vuln_class: "authz", severity: "high",
        confidence: "high", title: "纵向越权：GET /benefits",
        evidence_chain: null, witness_payload: null, verdict: null,
        mismatch_reason: null, params: [], auth_required: null,
        source_location: null, sink_location: null,
        narrative: { cause: "资源属主校验缺失" },
        reason: "no-route-entries",
        declared_endpoints: [{ method: "GET", path: "/benefits" }],
      }],
      safe_dismissed: [{ kind: "safe", subject: "getByUserIdAndThreshold 无 threshold 分支" }],
      verdicts: [{
        vulnerability_id: "INJ-9", vuln_class: "injection",
        status: "blocked_by_security", severity: null, impact: null,
        exploitation_steps: [], proof_of_impact: null, run_id: "run-2",
        current_blocker: "WAF 拦截单引号", what_we_tried: "编码绕过",
        evidence_of_vulnerability: "报错回显", expected_impact: "RCE",
        reason: "finding-or-endpoint-not-matched",
      }],
    };
    mockedFetch.mockResolvedValue(m);
    renderTab();
    const banner = await screen.findByTestId("unmatched-banner");
    expect(banner.textContent).toContain("3");
    expect(screen.queryByTestId("unmatched-detail")).toBeNull(); // 初始收起
    fireEvent.click(banner);
    const detail = screen.getByTestId("unmatched-detail");
    // finding 完整证据卡（v2 一等公民化：narrative 直出，不再只剩标题）
    expect(within(detail).getByText(/AUTHZ-VULN-02/)).toBeTruthy();
    expect(within(detail).getByText("资源属主校验缺失")).toBeTruthy();
    // reason 徽标（i18n 文案，非原始键值）
    expect(within(detail).getByText(i18n.t("workspaceDetail.evidence.reason.no-route-entries")))
      .toBeTruthy();
    // declared_endpoints 可见（用户能对照 finding 声称的接口）
    expect(within(detail).getByText(/\/benefits/)).toBeTruthy();
    // safe 桶
    expect(within(detail).getByText(/getByUserIdAndThreshold/)).toBeTruthy();
    // verdicts 桶：blocked 态判定依据字段可见
    expect(within(detail).getByText(/INJ-9/)).toBeTruthy();
    expect(within(detail).getByText("WAF 拦截单引号")).toBeTruthy();
    expect(within(detail).getByText("报错回显")).toBeTruthy();
  });

  it("unmatched 面板 vuln_class 筛选生效", async () => {
    const m = JSON.parse(JSON.stringify(matrix)) as EvidenceMatrix;
    m.unmatched = {
      findings: [
        { id: "A-1", vuln_class: "authz", severity: null, confidence: null,
          title: "越权 A", evidence_chain: null, witness_payload: null,
          verdict: null, mismatch_reason: null, params: [], auth_required: null,
          source_location: null, sink_location: null, reason: "no-route-entries" },
        { id: "X-1", vuln_class: "xss", severity: null, confidence: null,
          title: "注入 X", evidence_chain: null, witness_payload: null,
          verdict: null, mismatch_reason: null, params: [], auth_required: null,
          source_location: null, sink_location: null, reason: "no-route-entries" },
      ],
      safe_dismissed: [],
      verdicts: [],
    };
    mockedFetch.mockResolvedValue(m);
    renderTab();
    fireEvent.click(await screen.findByTestId("unmatched-banner"));
    const detail = screen.getByTestId("unmatched-detail");
    expect(within(detail).getByText(/A-1/)).toBeTruthy();
    expect(within(detail).getByText(/X-1/)).toBeTruthy();
    fireEvent.change(screen.getByTestId("unmatched-class-filter"),
                      { target: { value: "xss" } });
    expect(within(detail).queryByText(/A-1/)).toBeNull();
    expect(within(detail).getByText(/X-1/)).toBeTruthy();
  });

  it("endpoints 空且有 note 时显示 note 而非选择空态", async () => {
    const m = JSON.parse(JSON.stringify(matrix)) as EvidenceMatrix;
    m.endpoints = [];
    m.note = "entry_points.json 缺失（纯黑盒扫描或旧版扫描），接口底册为空，证据无处挂载。";
    mockedFetch.mockResolvedValue(m);
    renderTab();
    const note = await screen.findByTestId("evidence-note");
    expect(note.textContent).toContain("entry_points.json 缺失");
    expect(screen.queryByText(i18n.t("workspaceDetail.evidence.selectEndpoint"))).toBeNull();
  });

  it("finding 卡渲染涉及参数与认证要求", async () => {
    renderTab();
    const list = await screen.findByTestId("evidence-list");
    fireEvent.click(within(list).getByText("/allocations/:userId"));
    const wb = within(screen.getByTestId("evidence-whitebox"));
    expect(wb.getByText(/userId \(path\)/)).toBeTruthy();
    expect(wb.getByText(/isLoggedIn/)).toBeTruthy();
  });

  it("v2 富 finding 卡：narrative/问题点片段/数据流步骤/per-class 字段直出", async () => {
    const m = JSON.parse(JSON.stringify(matrix)) as EvidenceMatrix;
    m.endpoints[0].whitebox.findings = [{
      id: "XSS-VULN-01", vuln_class: "xss", severity: "high",
      confidence: "needs_review", title: "CSV 公式注入",
      evidence_chain: null, witness_payload: null, verdict: "vulnerable",
      mismatch_reason: "无公式字符过滤", params: [], auth_required: null,
      source_location: null, sink_location: null,
      narrative: { cause: "无过滤", impact: "外泄", remediation: "过滤前缀" },
      problem_points: [{ location: "account.bus.go:132", description: "未过滤",
                         snippet: "func SetAlias() {" }],
      dataflow_steps: [{ label: "读取 req", file: "account.bus.go", line: 129,
                         protection: "TrimSpace only" }],
      evidence: { verification: "static", verdict: "vulnerable" },
      sink_call: "xlsx.NewCell", slot_type: "body",
    }];
    mockedFetch.mockResolvedValue(m);
    renderTab();
    const list = await screen.findByTestId("evidence-list");
    fireEvent.click(within(list).getByText("/allocations/:userId"));
    const wb = within(screen.getByTestId("evidence-whitebox"));
    const card = wb.getByTestId("evidence-finding-card");
    // 判定与理由（finding-verdict 徽章与 evidence 子块徽章同文本，用 testId 限定）
    expect(within(card).getByTestId("finding-verdict").textContent).toBe("vulnerable");
    expect(within(card).getByText("无公式字符过滤")).toBeTruthy();
    // narrative 三节
    expect(within(card).getByText("无过滤")).toBeTruthy();
    expect(within(card).getByText("外泄")).toBeTruthy();
    expect(within(card).getByText("过滤前缀")).toBeTruthy();
    // 问题点：位置 + snippet 面板
    expect(within(card).getByText("account.bus.go:132")).toBeTruthy();
    expect(within(card).getByTestId("ev-problem-snippet")).toBeTruthy();
    // 数据流步骤 + 防护标注
    expect(within(card).getByText(/读取 req/)).toBeTruthy();
    expect(within(card).getByText(/account.bus.go:129/)).toBeTruthy();
    // per-class 字段
    expect(within(card).getByText("xlsx.NewCell")).toBeTruthy();
    // 验证证据子块（静态分析徽章）
    expect(within(card).getByText(i18n.t("report.verificationStatic"))).toBeTruthy();
  });

  it("potential 黑盒卡渲染降级原因（不再只剩 status 一个词）", async () => {
    const m = JSON.parse(JSON.stringify(matrix)) as EvidenceMatrix;
    m.endpoints[0].blackbox.verdicts = [{
      vulnerability_id: "AUTHZ-7", vuln_class: "authz", status: "potential",
      severity: "medium", impact: null, exploitation_steps: [],
      proof_of_impact: null, run_id: "run-1", confidence: "low",
      downgrade_reason: "缺 victim baseline 证横向越权",
      evidence_of_vulnerability: "attacker 已达成访问",
    }];
    mockedFetch.mockResolvedValue(m);
    renderTab();
    const list = await screen.findByTestId("evidence-list");
    fireEvent.click(within(list).getByText("/allocations/:userId"));
    const bb = within(screen.getByTestId("evidence-blackbox"));
    const card = bb.getByTestId("evidence-verdict-card");
    expect(within(card).getByText("缺 victim baseline 证横向越权")).toBeTruthy();
    expect(within(card).getByText("attacker 已达成访问")).toBeTruthy();
    expect(within(card).getByText("low")).toBeTruthy();
  });

  it("黑盒 rejected 条目渲染（v1 类型有、零渲染）", async () => {
    const m = JSON.parse(JSON.stringify(matrix)) as EvidenceMatrix;
    m.endpoints[0].blackbox.rejected = [{ id: "XSS-7", reason: "L3 id 不在 queue" }];
    mockedFetch.mockResolvedValue(m);
    renderTab();
    const list = await screen.findByTestId("evidence-list");
    fireEvent.click(within(list).getByText("/allocations/:userId"));
    const bb = within(screen.getByTestId("evidence-blackbox"));
    expect(bb.getByTestId("blackbox-rejected")).toBeTruthy();
    expect(bb.getByText(/XSS-7/)).toBeTruthy();
    expect(bb.getByText(/L3 id 不在 queue/)).toBeTruthy();
  });

  it("接口头部渲染 entry_verdict 徽章与 entry_evidence；sources 缺失提示条", async () => {
    const m = JSON.parse(JSON.stringify(matrix)) as EvidenceMatrix;
    m.sources = { entry_points: true, report_data: false, blackbox_runs: 0 };
    mockedFetch.mockResolvedValue(m);
    renderTab();
    await screen.findByTestId("evidence-list");
    expect(screen.getByTestId("entry-verdict").textContent).toBe("confirmed");
    expect(screen.getByText(/Express route/)).toBeTruthy();
    expect(screen.getByTestId("evidence-sources-hint")).toBeTruthy();
  });

  it("finding 卡渲染查看报告链接；无 dataflow 映射时不渲染数据流链接", async () => {
    renderTab();
    fireEvent.click(await screen.findByTestId("evidence-list"));
    const list = screen.getByTestId("evidence-list");
    fireEvent.click(within(list).getByText("/allocations/:userId"));
    const wb = within(screen.getByTestId("evidence-whitebox"));
    const link = wb.getByTestId("evidence-report-link");
    expect(link.getAttribute("href")).toBe("/p/w/scans/s1/report#INJ-VULN-01");
    expect(wb.queryByTestId("evidence-dataflow-link")).toBeNull();
  });

  it("有 dataflow 映射时渲染查看数据流深链", async () => {
    mockedDataflow.mockResolvedValue({
      trees: [{ tree_id: "t-1", vuln_class: "injection",
                sink: { label: null }, findings: [{ id: "INJ-VULN-01" }], branches: [] }],
    } as unknown as Awaited<ReturnType<typeof fetchDataflowView>>);
    renderTab();
    const list = await screen.findByTestId("evidence-list");
    fireEvent.click(within(list).getByText("/allocations/:userId"));
    const link = within(screen.getByTestId("evidence-whitebox"))
      .getByTestId("evidence-dataflow-link");
    expect(link.getAttribute("href")).toBe(
      `/p/w/scans/s1/dataflow?tree=${encodeURIComponent("t-1")}`);
  });
});
