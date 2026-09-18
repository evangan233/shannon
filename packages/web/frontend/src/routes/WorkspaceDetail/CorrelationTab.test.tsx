// D5：CorrelationTab 结果视图集成测试——区块顺序（漂移警告 → 拓扑 → 攻击链 →
// 裁决 → 单仓已否决 → 按服务分组漏洞 → 信任边界 → 报告 md）、pending 占位、
// 空 flows 降级、service 徽标、severity/PoC/成立-消掉视图（2026-09-18）。
// 风格对齐 DataFlowTab.test：msw + MemoryRouter + SWRConfig 独立 cache + i18n zh。
import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach } from "vitest";
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
        { service: "order-svc", title: "SQL 注入", severity: "high", location: "db.py:10" },
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

  it("按服务分组漏洞 + service 徽标（CorrVulnCard 出现，severity/PoC 可见）", async () => {
    await renderWithDetail();
    const vulns = screen.getByTestId("corr-vulns");
    // CorrVulnCard 渲染两条（ID 在收起态卡头可见）
    expect(within(vulns).getByText("INJ-VULN-01")).toBeInTheDocument();
    expect(within(vulns).getByText("INJ-VULN-02")).toBeInTheDocument();
    // severity 药丸（critical → 严重）
    expect(within(vulns).getByTestId("corr-vuln-sev")).toHaveTextContent("严重");
    // 分组徽标：frontend / order-svc 各一组（组序随拓扑服务序——入口在前）
    const groups = within(vulns).getAllByTestId("corr-vuln-group");
    expect(groups.length).toBe(2);
    expect(within(groups[0]).getByText("frontend")).toBeInTheDocument();
    expect(within(groups[1]).getByText("order-svc")).toBeInTheDocument();
    // 展开卡头 → 接口/PoC 可见（默认收起，卡头是唯一 button）
    await fireEvent.click(within(groups[1]).getByRole("button"));
    const card = within(groups[1]).getByTestId("corr-vuln-card");
    expect(within(card).getByTestId("corr-vuln-endpoints")).toHaveTextContent("POST /orders");
    expect(within(card).getByTestId("corr-poc-curl")).toHaveTextContent("1 OR 1=1");
    expect(within(card).getAllByTestId("corr-poc-steps").length).toBeGreaterThan(0);
    expect(within(card).getByTestId("corr-problem-point-location")).toHaveTextContent("db.py:10");
  });

  it("信任边界表（service / method / exposure / reachable_from / reason）", async () => {
    await renderWithDetail();
    const boundaries = screen.getByTestId("corr-boundaries");
    expect(within(boundaries).getByText("order.CreateOrder")).toBeInTheDocument();
    expect(within(boundaries).getByText("internal")).toBeInTheDocument();
    expect(within(boundaries).getByText("frontend")).toBeInTheDocument();
    expect(within(boundaries).getByText(/仅集群内 grpc 可达/)).toBeInTheDocument();
  });

  it("报告 markdown 渲染（MarkdownView）", async () => {
    await renderWithDetail();
    expect(
      screen.getByRole("heading", { name: "跨仓关联报告" }),
    ).toBeInTheDocument();
    expect(screen.getByText(/入口参数透传至后端未过滤/)).toBeInTheDocument();
  });

  it("区块顺序：拓扑 → 攻击链 → 裁决 → 单仓已否决 → 分组漏洞 → 信任边界 → 报告", async () => {
    await renderWithDetail();
    const order = ["corr-topology", "corr-flows", "corr-adjudication", "corr-dismissed",
      "corr-vulns", "corr-boundaries", "corr-report"];
    const els = order.map((id) => screen.getByTestId(id));
    for (let i = 1; i < els.length; i++) {
      expect(
        els[i - 1].compareDocumentPosition(els[i]) & Node.DOCUMENT_POSITION_FOLLOWING,
      ).toBeTruthy();
    }
    // 漂移警告首版恒空：不渲染横幅
    expect(screen.queryByTestId("corr-drift")).not.toBeInTheDocument();
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

  it("跨仓裁决区:三向分组卡片(vuln_id/direction/error 卡留证)", async () => {
    await renderWithDetail(detail, "corr-adjudication");
    const section = screen.getByTestId("corr-adjudication");
    // within 限定裁决区(分组漏洞区 VulnCard 也渲染 vuln_id,全文查询会撞多匹配)
    expect(within(section).getByText("INJ-09")).toBeInTheDocument();
    expect(within(section).getAllByText(/INJ-VULN-02/).length).toBeGreaterThan(0);
    // 翻案论证留证
    expect(within(section).getByText(/跨仓可达,翻案候选/)).toBeInTheDocument();
    // 分析过程与证据可见
    expect(within(section).getByText(/dismissed 理由=internal 不可达/)).toBeInTheDocument();
    expect(within(section).getByText(/db.py:10/)).toBeInTheDocument();
  });

  it("多跳链展示(path 链)", async () => {
    await renderWithDetail(detail, "corr-adjudication");
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
