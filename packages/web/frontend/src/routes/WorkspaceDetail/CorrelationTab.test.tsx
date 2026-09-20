// D5：CorrelationTab 结果视图集成测试——区块顺序（总览头 → 拓扑 → 攻击链 →
// 裁决 → 单仓已否决 → 按服务分组漏洞 → 信任边界 → 报告 md）、pending 占位、
// 空 flows 降级、service 徽标、severity/PoC/成立-消掉视图（2026-09-18）、
// 总览头/定位/集中折叠（2026-09-20 可读性批次）。
// 风格对齐 DataFlowTab.test：msw + MemoryRouter + SWRConfig 独立 cache + i18n zh。
import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach, vi } from "vitest";
import { render, screen, within, waitFor, fireEvent, cleanup } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { setupServer } from "msw/node";
import { http, HttpResponse } from "msw";
import { SWRConfig } from "swr";
import i18n from "@/i18n";
import { CorrelationTab } from "./CorrelationTab";
import type { CorrelationDetail } from "@/api/types";

// fixture：2 服务（frontend 入口 / order-svc 后端）+ 1 条 ok 边（grpc）+ 1 条攻击链 +
// merged_vulns 两类（injection×2，分属 order-svc / frontend 服务）+ 1 条信任边界 + 报告 md。
const detail: CorrelationDetail = {
  topology: {
    services: [
      { name: "frontend", role: "entrypoint", repo: "frontend" },
      { name: "order-svc", role: "backend", repo: "order-svc" },
    ],
    edges: [
      {
        from: "frontend",
        to: "order-svc",
        protocol: "grpc",
        status: "ok",
        calls: [],
      },
    ],
  },
  flows: [
    {
      edge_from: "frontend",
      edge_to: "order-svc",
      entry: "POST /orders",
      method: "order.CreateOrder",
      call_site: { file: "checkout.ts", line: 42, snippet: "await stub.create(order)" },
      vuln_refs: [
        { vuln_id: "INJ-VULN-01", service: "order-svc", title: "SQL 注入", severity: "high", location: "db.py:10" },
      ],
      confidence: "high",
      evidence: "入口参数未过滤透传到后端拼接 SQL",
    },
  ],
  multi_hop_chains: [
    {
      path: ["frontend", "order-svc", "payment-svc"],
      basis: "edge-adjacency",
      confidence: "structural",
    },
  ],
  adjudication: {
    cards: [
      {
        direction: "upgrade",
        finding_ref: { service: "order-svc", vuln_id: "INJ-09", origin: "dismissed" },
        conclusion: "vulnerable",
        cross_service_context: "经 frontend POST /orders → order.CreateOrder 可达",
        analysis_process: ["① dismissed 理由=internal 不可达", "② topology 显示可达"],
        verification_evidence: [
          { repo: "order-svc", location: "db.py:10", snippet: "query(sql)", note: "拼接 SQL" },
        ],
        reasoning: "跨仓可达,翻案候选",
        confidence: "high",
      },
      {
        direction: "confirm",
        finding_ref: { service: "order-svc", vuln_id: "INJ-VULN-01", origin: "queue" },
        conclusion: "vulnerable",
        cross_service_context: "via frontend",
        analysis_process: ["s1"],
        verification_evidence: [],
        reasoning: "确认",
        confidence: "high",
      },
      {
        direction: "error",
        finding_ref: { service: "frontend", vuln_id: "INJ-VULN-02", origin: "queue" },
        conclusion: "needs-review",
        cross_service_context: "",
        analysis_process: [],
        verification_evidence: [],
        reasoning: "adjudication batch failed: llm down",
        confidence: "low",
      },
    ],
  },
  merged_vulns: {
    injection: [
      {
        ID: "INJ-VULN-01",
        vulnerability_type: "sql_injection",
        externally_exploitable: true,
        title: "订单查询 SQL 注入",
        severity: "critical",
        service: "order-svc",
        location: "order/db.py:10",
        endpoint: "POST /orders",
        report_endpoints: [
          { method: "POST", path: "/orders", params: ["q"], role: "write",
            auth: "public", route_registered_at: "api/orders.py:12" },
        ],
        report_problem_points: [
          { location: "order/db.py:10", description: "拼接 SQL", snippet: "query(sql)" },
        ],
        report_poc: {
          curl: "curl -X POST 'http://TARGET/orders' -d '{\"q\":\"1 OR 1=1\"}'",
          raw_http: "POST /orders HTTP/1.1\nHost: TARGET\n\n{\"q\":\"1 OR 1=1\"}",
          steps: ["1. 构造注入参数", "2. 观察返回行数异常"],
        },
      },
      {
        ID: "INJ-VULN-02",
        vulnerability_type: "sql_injection",
        externally_exploitable: false,
        title: "日志清洗 SQL 注入",
        service: "frontend",
        location: "front/log.py:3",
      },
    ],
  },
  boundaries: [
    {
      service: "order-svc",
      method: "order.CreateOrder",
      exposure: "internal",
      reachable_from: ["frontend"],
      reason: "仅集群内 grpc 可达，未挂网关",
      confidence: "high",
    },
  ],
  drift_warnings: [],
  corr_children: [
    { service: "frontend", scan_id: "20260824-000001", reused: false },
    { service: "order-svc", scan_id: "20260824-000002", reused: true },
  ],
  // 成立/消掉视图（2026-09-18）：子仓 dismissed 明单 + 裁决阶段状态
  dismissed: [
    {
      service: "order-svc",
      ID: "INJ-09",
      vuln_class: "injection",
      title: "内部同步任务 SQL 拼接",
      dismiss_reason: "internal 不可达",
      confidence: "high",
      source_track: "gitnexus",
      dismissed_at_stage: "chain-verdict",
    },
  ],
  adjudication_status: "completed",
  report_md: "# 跨仓关联报告\n\n总结：入口参数透传至后端未过滤。",
};

const server = setupServer();

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
// jsdom navigator.language 默认 en；现有断言依赖中文渲染，逐测试钉回 zh（DataFlowTab.test 同款）。
beforeEach(() => i18n.changeLanguage("zh"));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

function renderTab() {
  return render(
    <MemoryRouter>
      <SWRConfig value={{ provider: () => new Map() }}>
        <CorrelationTab ws="w1" scanId="s1" />
      </SWRConfig>
    </MemoryRouter>,
  );
}

/** 挂 mock 数据并等目标区块出现（各用例共同前置；until 可换占位等态 testid）。 */
async function renderWithDetail(d: CorrelationDetail = detail, until = "corr-topology") {
  server.use(
    http.get("/api/workspaces/:ws/scans/:scanId/correlation", () =>
      HttpResponse.json(d)),
  );
  renderTab();
  await waitFor(() =>
    expect(screen.getByTestId(until)).toBeInTheDocument());
}

describe("CorrelationTab", () => {
  it("渲染拓扑节点与边（frontend / order-svc / grpc）", async () => {
    await renderWithDetail();
    // frontend/order-svc 也出现在分组徽标/边界表——断言圈定拓扑区块
    const topo = within(screen.getByTestId("corr-topology"));
    expect(topo.getByText("frontend")).toBeInTheDocument();
    expect(topo.getByText("order-svc")).toBeInTheDocument();
    expect(topo.getByText("grpc")).toBeInTheDocument();
  });

  it("渲染攻击链三段（entry / method / vuln title）", async () => {
    await renderWithDetail();
    // entry 同时出现在攻击链与漏洞卡卡头接口小字——圈定攻击链区块
    expect(within(screen.getByTestId("corr-flows")).getByText("POST /orders")).toBeInTheDocument();
    // method 同时出现在攻击链与信任边界表——圈定攻击链区块
    expect(within(screen.getByTestId("corr-flows")).getByText("order.CreateOrder")).toBeInTheDocument();
    expect(screen.getByText("SQL 注入")).toBeInTheDocument();
  });

  it("flows 为空降级提示", async () => {
    await renderWithDetail({ ...detail, flows: [] });
    expect(screen.getByTestId("corr-flows")).toBeInTheDocument();
    expect(screen.getByText("暂无候选攻击链")).toBeInTheDocument();
  });

  it("漏洞按结论分组（成立默认展开，存疑默认折叠），组内 service 徽标 + severity/PoC 可见", async () => {
    await renderWithDetail();
    const vulns = screen.getByTestId("corr-vulns");
    // INJ-VULN-01 有 confirm 卡 → 成立组（默认展开）；INJ-VULN-02 是 error 卡 →
    // 存疑/未重审组（默认折叠，卡不挂载）；组容器恒渲染（折叠只收卡）
    const confirmedGroup = within(vulns)
      .getAllByTestId("corr-vuln-verdict-group")
      .find((g) => g.getAttribute("data-group") === "confirmed")!;
    expect(confirmedGroup).toBeInTheDocument();
    expect(within(confirmedGroup).getByText("INJ-VULN-01")).toBeInTheDocument();
    expect(within(vulns).queryByText("INJ-VULN-02")).not.toBeInTheDocument();
    // 展开存疑组 → INJ-VULN-02 卡挂载
    fireEvent.click(within(vulns).getByTestId("corr-verdict-group-head-uncertain"));
    const uncertainGroup = within(vulns)
      .getAllByTestId("corr-vuln-verdict-group")
      .find((g) => g.getAttribute("data-group") === "uncertain")!;
    expect(within(uncertainGroup).getByText("INJ-VULN-02")).toBeInTheDocument();
    // severity 药丸（critical → 严重）+ 组内 service 徽标（组序随拓扑服务序——入口在前）
    expect(within(confirmedGroup).getByTestId("corr-vuln-sev")).toHaveTextContent("严重");
    const groups = within(confirmedGroup).getAllByTestId("corr-vuln-group");
    expect(groups.length).toBe(1);
    expect(within(groups[0]).getByText("order-svc")).toBeInTheDocument();
    // 成立组默认展开：接口/PoC 直接可见
    const card = within(groups[0]).getByTestId("corr-vuln-card");
    expect(within(card).getByTestId("corr-vuln-endpoints")).toHaveTextContent("POST /orders");
    expect(within(card).getByTestId("corr-poc-curl")).toHaveTextContent("1 OR 1=1");
    expect(within(card).getAllByTestId("corr-poc-steps").length).toBeGreaterThan(0);
    expect(within(card).getByTestId("corr-problem-point-location")).toHaveTextContent("db.py:10");
    // 卡头点击收起 → 展开体消失（卡头 ID 仍在）；再点恢复
    fireEvent.click(within(card).getByTestId("corr-vuln-card-head"));
    expect(within(card).queryByTestId("corr-vuln-endpoints")).not.toBeInTheDocument();
    fireEvent.click(within(card).getByTestId("corr-vuln-card-head"));
    expect(within(card).getByTestId("corr-vuln-endpoints")).toBeInTheDocument();
  });

  it("漏洞卡跨仓富化：结论徽标 + 跨仓上下文（所在链 + 单仓结果链接）", async () => {
    await renderWithDetail();
    const card = within(screen.getByTestId("corr-vulns")).getByTestId("corr-vuln-card");
    // 卡头结论徽标（confirm → 成立 + confidence）
    expect(within(card).getByTestId("corr-vuln-verdict")).toHaveTextContent(/成立/);
    // 跨仓上下文节：reasoning + cross_service_context + 所在链（flows vuln_refs 反查命中）
    expect(within(card).getByTestId("corr-verdict-reasoning")).toHaveTextContent("确认");
    expect(within(card).getByTestId("corr-cross-context")).toHaveTextContent("via frontend");
    expect(within(card).getByTestId("corr-vuln-chain")).toHaveTextContent("POST /orders");
    expect(within(card).getByTestId("corr-vuln-chain")).toHaveTextContent("order.CreateOrder");
    // 单仓结果链接：corr_children service → /p/w1/scans/20260824-000002
    expect(within(card).getByTestId("corr-child-link")).toHaveAttribute(
      "href",
      "/p/w1/scans/20260824-000002",
    );
  });

  it("信任边界表（service / method / exposure / reachable_from / reason）", async () => {
    await renderWithDetail();
    const boundaries = screen.getByTestId("corr-boundaries");
    expect(within(boundaries).getByText("order.CreateOrder")).toBeInTheDocument();
    expect(within(boundaries).getByText("internal")).toBeInTheDocument();
    expect(within(boundaries).getByText("frontend")).toBeInTheDocument();
    expect(within(boundaries).getByText(/仅集群内 grpc 可达/)).toBeInTheDocument();
  });

  it("报告 md：默认收起只留标题+下载，展开后渲染全文（2026-09-20）", async () => {
    await renderWithDetail();
    const section = screen.getByTestId("corr-report");
    // 默认 details 收起：标题 + 下载入口可见，正文不渲染
    expect(
      within(section).getByRole("heading", { name: "关联报告" }),
    ).toBeInTheDocument();
    expect(within(section).getByRole("button", { name: /下载/ })).toBeInTheDocument();
    // jsdom 不隐藏 details 收起内容（DOM 常驻）——收起语义断言 open 属性
    const det = section.querySelector("details") as HTMLDetailsElement;
    expect(det.open).toBe(false);
    fireEvent.click(within(section).getByText("展开报告全文"));
    expect(det.open).toBe(true);
    expect(screen.getByText(/入口参数透传至后端未过滤/)).toBeInTheDocument();
  });

  it("区块顺序：总览头 → 结论摘要 → 漏洞 → 攻击链 → 多跳 → 拓扑 → 裁决 → 单仓已否决 → 信任边界 → 报告", async () => {
    await renderWithDetail();
    const order = ["corr-stats", "corr-verdict-section", "corr-vulns", "corr-flows", "corr-multihop",
      "corr-topology", "corr-adjudication", "corr-dismissed", "corr-boundaries", "corr-report"];
    const els = order.map((id) => screen.getByTestId(id));
    for (let i = 1; i < els.length; i++) {
      expect(
        els[i - 1].compareDocumentPosition(els[i]) & Node.DOCUMENT_POSITION_FOLLOWING,
      ).toBeTruthy();
    }
    // 漂移警告首版恒空：不渲染横幅
    expect(screen.queryByTestId("corr-drift")).not.toBeInTheDocument();
  });

  it("结论摘要区：五向结论卡计数 + 翻案组展开裁决卡论证 + 条目点击定位", async () => {
    const scrollTo = vi.fn();
    window.scrollTo = scrollTo as unknown as typeof window.scrollTo;
    await renderWithDetail(detail, "corr-verdict-section");
    // 五向计数：confirm→成立 1、error(needs-review)→存疑 1、未重审 0、dismissed upgrade→翻案 1
    expect(screen.getByTestId("corr-verdict-card-confirmed")).toHaveTextContent("1");
    expect(screen.getByTestId("corr-verdict-card-uncertain")).toHaveTextContent("1");
    expect(screen.getByTestId("corr-verdict-card-upgraded")).toHaveTextContent("1");
    expect(screen.getByTestId("corr-verdict-card-refuted")).toHaveTextContent("0");
    // 成立组清单：ID + reasoning 一句话；点击 → 同步定位（组默认展开、卡展开）
    fireEvent.click(within(screen.getByTestId("corr-verdict-list-confirmed")).getByTestId("corr-verdict-entry"));
    expect(scrollTo).toHaveBeenCalledWith({ top: expect.any(Number), behavior: "smooth" });
    // 翻案组展开（details）：裁决卡默认折叠（collapsed 传入）——点卡头展开后论证可见
    fireEvent.click(within(screen.getByTestId("corr-verdict-upgraded-list")).getByTestId("corr-adj-card-head"));
    expect(screen.getByTestId("corr-verdict-upgraded-list")).toHaveTextContent(/跨仓可达,翻案候选/);
  });

  it("topology null 显示进行中占位 + corr_children 子仓状态", async () => {
    await renderWithDetail({ ...detail, topology: null }, "corr-children");
    expect(screen.getByText("关联阶段进行中 / 未开始")).toBeInTheDocument();
    const children = screen.getByTestId("corr-children");
    expect(within(children).getByText(/frontend · 20260824-000001/)).toBeInTheDocument();
    expect(within(children).getByText(/order-svc · 20260824-000002/)).toBeInTheDocument();
    // 复用 / 新扫 标注
    expect(within(children).getByText("复用")).toBeInTheDocument();
    expect(within(children).getByText("新扫")).toBeInTheDocument();
    // 占位态不渲染结果区块
    expect(screen.queryByTestId("corr-topology")).not.toBeInTheDocument();
  });

  it("跨仓裁决区:三向分组卡片(error 卡默认展开,非 error 收起需展开后留证)", async () => {
    await renderWithDetail(detail, "corr-adjudication");
    const section = screen.getByTestId("corr-adjudication");
    // within 限定裁决区(分组漏洞区 VulnCard 也渲染 vuln_id,全文查询会撞多匹配)
    expect(within(section).getByText("INJ-09")).toBeInTheDocument();
    expect(within(section).getAllByText(/INJ-VULN-02/).length).toBeGreaterThan(0);
    // error 卡默认展开（故障信号必见）：reasoning 直接可见
    expect(within(section).getByText(/adjudication batch failed/)).toBeInTheDocument();
    // 非 error 卡默认收起：展开 upgrade 卡 → 翻案论证/分析过程/证据可见
    fireEvent.click(within(section).getAllByTestId("corr-adj-card-head")[0]);
    expect(within(section).getByText(/跨仓可达,翻案候选/)).toBeInTheDocument();
    expect(within(section).getByText(/dismissed 理由=internal 不可达/)).toBeInTheDocument();
    expect(within(section).getByText(/db\.py:10/)).toBeInTheDocument();
  });

  it("多跳链展示(默认收起,details 展开后 path 链可见)", async () => {
    await renderWithDetail(detail, "corr-adjudication");
    const det = screen.getByTestId("corr-multihop-list") as HTMLDetailsElement;
    // jsdom 不隐藏 details 收起内容（DOM 常驻）——收起语义断言 open 属性
    expect(det.open).toBe(false);
    fireEvent.click(within(det).getByText("展开 1 条候选链"));
    expect(det.open).toBe(true);
    expect(
      screen.getByText(/frontend → order-svc → payment-svc/),
    ).toBeInTheDocument();
  });

  it("adjudication 与状态均 null 时不渲染裁决区(multihop 空态提示保留)", async () => {
    await renderWithDetail(
      { ...detail, adjudication: null, adjudication_status: null, multi_hop_chains: [] },
      "corr-topology",
    );
    expect(screen.queryByTestId("corr-adjudication")).not.toBeInTheDocument();
    // multihop 区无条件渲染(同 flows 区),空时显示空态提示
    expect(screen.getByTestId("corr-multihop")).toBeInTheDocument();
  });

  it("裁决进行中:无 log 也渲染横幅(corr-adj-running),不显示无裁决卡占位", async () => {
    await renderWithDetail(
      { ...detail, adjudication: null, adjudication_status: "running" },
      "corr-adjudication",
    );
    expect(screen.getByTestId("corr-adj-running")).toHaveTextContent("跨仓裁决进行中");
    expect(screen.queryByText("无裁决卡")).not.toBeInTheDocument();
    // 无卡 → 无聚合徽标行
    expect(screen.queryByTestId("corr-adj-summary")).not.toBeInTheDocument();
  });

  it("裁决 direction 聚合徽标行(翻案候选 × 1 等)", async () => {
    await renderWithDetail(detail, "corr-adjudication");
    const summary = screen.getByTestId("corr-adj-summary");
    expect(summary).toHaveTextContent("翻案候选 × 1");
    expect(summary).toHaveTextContent("确认 × 1");
    expect(summary).toHaveTextContent("裁决失败 × 1");
  });

  it("单仓已否决表:dismissed 明单 + 命中裁决行内徽标(翻案候选)", async () => {
    await renderWithDetail(detail, "corr-dismissed");
    const section = screen.getByTestId("corr-dismissed");
    expect(within(section).getByText("INJ-09")).toBeInTheDocument();
    expect(within(section).getByText("internal 不可达")).toBeInTheDocument();
    expect(within(section).getByText("chain-verdict")).toBeInTheDocument();
    // service+vuln_id 命中 upgrade 卡 → 行内 direction 徽标
    expect(within(section).getByTestId("corr-dismissed-verdict")).toHaveTextContent("翻案候选");
  });

  it("dismissed 为空 → 整节不渲染", async () => {
    cleanup();
    await renderWithDetail({ ...detail, dismissed: [] }, "corr-topology");
    expect(screen.queryByTestId("corr-dismissed")).not.toBeInTheDocument();
  });

  it("总览头:数字卡(服务/攻击链/多跳/裁决/漏洞)+severity 药丸点击定位", async () => {
    const scrollTo = vi.fn();
    window.scrollTo = scrollTo as unknown as typeof window.scrollTo;
    await renderWithDetail(detail, "corr-stats");
    const stats = screen.getByTestId("corr-stats");
    expect(within(stats).getByTestId("corr-stat-services")).toHaveTextContent("2");
    expect(within(stats).getByTestId("corr-stat-flows")).toHaveTextContent("1");
    expect(within(stats).getByTestId("corr-stat-multihop")).toHaveTextContent("1");
    expect(within(stats).getByTestId("corr-stat-adjudication")).toHaveTextContent("3");
    expect(within(stats).getByTestId("corr-stat-vulns")).toHaveTextContent("2");
    // severity 药丸：critical 1（INJ-VULN-01）、high 0（flows 的 high 不计入漏洞）
    expect(within(stats).getByTestId("corr-stat-sev-critical")).toHaveTextContent("1");
    expect(within(stats).getByTestId("corr-stat-sev-high")).toHaveTextContent("0");
    // 点击定位：scrollTo smooth + 目标卡描边闪烁
    fireEvent.click(within(stats).getByTestId("corr-stat-sev-critical"));
    expect(scrollTo).toHaveBeenCalledWith({ top: expect.any(Number), behavior: "smooth" });
    expect(
      document.getElementById("corr-vuln-INJ-VULN-01")!.classList.contains("dataflow-flash"),
    ).toBe(true);
  });

  it("攻击链漏洞引用点击定位(目标卡折叠时先展开再定位)", async () => {
    const scrollTo = vi.fn();
    window.scrollTo = scrollTo as unknown as typeof window.scrollTo;
    await renderWithDetail(detail, "corr-flows");
    // 先全部收起 → 引用点击应联动展开（异步 setTimeout 后定位）
    fireEvent.click(screen.getByTestId("corr-collapse-all-vulns"));
    expect(
      document.getElementById("corr-vuln-INJ-VULN-01")!.classList.contains("dataflow-flash"),
    ).toBe(false);
    fireEvent.click(screen.getByTestId("chain-vuln-ref"));
    await waitFor(() =>
      expect(
        document.getElementById("corr-vuln-INJ-VULN-01")!.classList.contains("dataflow-flash"),
      ).toBe(true));
    expect(scrollTo).toHaveBeenCalledWith({ top: expect.any(Number), behavior: "smooth" });
  });

  it("漏洞区集中折叠:全部收起/展开(ReportView 模式),默认全展开", async () => {
    await renderWithDetail(detail, "corr-vulns");
    const vulns = screen.getByTestId("corr-vulns");
    // 默认全展开（对齐单仓报告默认态）：INJ-VULN-01 展开体可见
    expect(within(vulns).getByTestId("corr-vuln-endpoints")).toBeInTheDocument();
    // 全部收起 → 展开体不可见（卡头 ID 仍在）
    fireEvent.click(within(vulns).getByTestId("corr-collapse-all-vulns"));
    expect(within(vulns).queryByTestId("corr-vuln-endpoints")).not.toBeInTheDocument();
    expect(within(vulns).getByText("INJ-VULN-01")).toBeInTheDocument();
    // 全部展开 → 恢复
    fireEvent.click(within(vulns).getByTestId("corr-expand-all-vulns"));
    expect(within(vulns).getByTestId("corr-vuln-endpoints")).toBeInTheDocument();
  });

  it("裁决区集中折叠:默认非 error 收起,全部收起/展开可用", async () => {
    await renderWithDetail(detail, "corr-adjudication");
    const section = screen.getByTestId("corr-adjudication");
    const cards = within(section).getAllByTestId("corr-adj-card");
    expect(cards.length).toBe(3);
    // 默认态：非 error 卡收起（展开体 context 不可见），error 卡展开（reasoning 可见）
    expect(within(section).queryByText(/经 frontend POST/)).not.toBeInTheDocument();
    expect(within(section).getByText(/adjudication batch failed/)).toBeInTheDocument();
    // 全部展开 → 非 error 卡论证可见
    fireEvent.click(within(section).getByTestId("corr-expand-all-adj"));
    expect(within(section).getByText(/经 frontend POST/)).toBeInTheDocument();
    // 全部收起 → error 卡论证也收起
    fireEvent.click(within(section).getByTestId("corr-collapse-all-adj"));
    expect(within(section).queryByText(/adjudication batch failed/)).not.toBeInTheDocument();
  });

  it("加载中显示 Skeleton 占位", async () => {
    // 慢响应：先渲染出骨架（数据未到）
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId/correlation", async () => {
        await new Promise((r) => setTimeout(r, 500));
        return HttpResponse.json(detail);
      }),
    );
    renderTab();
    expect(document.querySelectorAll(".animate-pulse").length).toBeGreaterThan(0);
  });
});
