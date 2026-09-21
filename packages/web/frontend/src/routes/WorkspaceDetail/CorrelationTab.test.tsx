// D5：CorrelationTab 结果视图集成测试——区块顺序（总览头 → 漏洞（主区）→ 裁决 →
// 拓扑 → 多跳 → 信任边界 → 已否决一行 → 报告 md）、pending 占位、孤链附录、
// 结论分组（成立完整卡 / 消掉·存疑紧凑行【原因铺出，点行展开】）、翻案置顶、
// service 徽标、severity/PoC 视图、总览头/定位/集中折叠。
// 2026-09-20 去重批次：结论摘要独立章 / 攻击链独立章 / 裁决全量卡平铺 /
// 单仓已否决表均撤（内容并入漏洞区紧凑行 / 漏洞卡链 / md 附录 / 一行汇总）。
// 风格对齐 DataFlowTab.test：msw + MemoryRouter + SWRConfig 独立 cache + i18n zh。
import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach, vi } from "vitest";
import { render, screen, within, waitFor, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { setupServer } from "msw/node";
import { http, HttpResponse } from "msw";
import { SWRConfig } from "swr";
import i18n from "@/i18n";
import { CorrelationTab } from "./CorrelationTab";
import type { CorrelationDetail } from "@/api/types";

// fixture：2 服务（frontend 入口 / order-svc 后端）+ 1 条 ok 边（grpc）+ 1 条攻击链
// （引用 INJ-VULN-01 → 不成孤链）+ merged_vulns 两类（injection×2，分属 order-svc /
// frontend 服务）+ 1 条信任边界 + 报告 md + dismissed 明单（命中翻案卡）。
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
        exploit_path: {
          entry_service: "frontend",
          entry_endpoint: "POST /orders",
          hops: [
            { from: "frontend", to: "order-svc", rpc: "order.v1.OrderService/CreateOrder",
              call_site: "checkout.ts:42" },
          ],
          sink: "order/db.py:10",
          user_controlled: "q 参数原样拼接进 SQL",
          poc: {
            preconditions: "可公网达入口服务",
            steps: ["1. 构造注入参数", "2. 观察返回行数异常"],
            curl: "curl -X POST 'http://ENTRY/orders' -d '{\"q\":\"1 OR 1=1\"}'",
            notes: "err 与单仓 PoC 不同：入口为前端路由",
          },
        },
        refined_finding: {
          impact: "外部用户经入口接口可拖库（跨仓可达）",
          cause: "sink 信任上游透传的客户端可控 q 参数",
          severity: "high",
        },
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
        confidence: "medium",
        merge_source: "both",
        service: "order-svc",
        location: "order/db.py:10",
        endpoint: "POST /orders",
        impact: "拖库",
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
  // 子仓 dismissed 明单（INJ-09 命中翻案卡 → 复核行计翻案 1）
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
  it("服务拓扑复用只读编辑器画布：节点渲染，点边右栏 status 徽标 + 叙述句（protocol 入右栏）", async () => {
    await renderWithDetail();
    // frontend/order-svc 也出现在分组徽标——断言用编辑器画布 testid 圈定
    const topo = within(screen.getByTestId("corr-topology"));
    expect(topo.getByTestId("topology-node-frontend")).toBeInTheDocument();
    expect(topo.getByTestId("topology-node-order-svc")).toBeInTheDocument();
    // 点边 → 右栏：status 语义徽标 + 叙述句（protocol 信息在右栏，画布边无标签）
    fireEvent.click(topo.getByTestId("topology-edge-scan_frontend-_order-svc_grpc"));
    expect(topo.getByTestId("topology-edge-status")).toHaveTextContent("ok");
    expect(topo.getByText(/通过 grpc 调用 order-svc/)).toBeInTheDocument();
  });

  it("攻击链章已撤：被漏洞引用的链不成孤链；有 exploit_path 时路径块优先于链渲染", async () => {
    await renderWithDetail();
    expect(screen.queryByTestId("corr-orphan-flows")).not.toBeInTheDocument();
    const card = within(screen.getByTestId("corr-vulns")).getByTestId("corr-vuln-card");
    // 结构化触发路径存在 → 不再降级渲染 flow 链
    expect(within(card).getByTestId("corr-exploit-path")).toBeInTheDocument();
    expect(within(card).queryByTestId("corr-vuln-chain")).not.toBeInTheDocument();
  });

  it("未被漏洞引用的孤链 → 附录章渲染，引用可点定位", async () => {
    const scrollTo = vi.fn();
    window.scrollTo = scrollTo as unknown as typeof window.scrollTo;
    // 引用指向 ghost-svc（不在 merged_vulns）→ 孤链
    const orphan = {
      ...detail,
      flows: [{
        ...detail.flows[0],
        vuln_refs: [
          { vuln_id: "INJ-VULN-01", service: "ghost-svc", title: "SQL 注入", severity: "high", location: "db.py:10" },
        ],
      }],
    };
    await renderWithDetail(orphan, "corr-orphan-flows");
    const section = screen.getByTestId("corr-orphan-flows");
    expect(within(section).getByTestId("attack-chain")).toBeInTheDocument();
    // 孤链引用点击 → 定位到已挂载的成立卡（同步 focus，无重渲染等待）
    fireEvent.click(within(section).getByTestId("chain-vuln-ref"));
    expect(scrollTo).toHaveBeenCalledWith({ top: expect.any(Number), behavior: "smooth" });
  });

  it("漏洞按结论分组（成立默认展开完整卡；消掉/存疑/未重审默认折叠），组内 service 徽标", async () => {
    await renderWithDetail();
    const vulns = screen.getByTestId("corr-vulns");
    // INJ-VULN-01 有 confirm 卡 → 成立组（默认展开）；INJ-VULN-02 是 error 卡 →
    // 存疑组（默认折叠）；组容器恒渲染（折叠只收内容）
    const confirmedGroup = within(vulns)
      .getAllByTestId("corr-vuln-verdict-group")
      .find((g) => g.getAttribute("data-group") === "confirmed")!;
    expect(confirmedGroup).toBeInTheDocument();
    expect(within(confirmedGroup).getByText("INJ-VULN-01")).toBeInTheDocument();
    expect(within(vulns).queryByText("INJ-VULN-02")).not.toBeInTheDocument();
    // severity 药丸（critical → 严重）+ 组内 service 徽标（组序随拓扑服务序——入口在前）
    expect(within(confirmedGroup).getByTestId("corr-vuln-sev")).toHaveTextContent("严重");
    const groups = within(confirmedGroup).getAllByTestId("corr-vuln-group");
    expect(groups.length).toBe(1);
    expect(within(groups[0]).getByText("order-svc")).toBeInTheDocument();
  });

  it("存疑组紧凑行：原因一句话铺出，点行展开完整卡（PoC 等全文可见）", async () => {
    await renderWithDetail();
    const vulns = screen.getByTestId("corr-vulns");
    fireEvent.click(within(vulns).getByTestId("corr-verdict-group-head-uncertain"));
    const uncertainGroup = within(vulns)
      .getAllByTestId("corr-vuln-verdict-group")
      .find((g) => g.getAttribute("data-group") === "uncertain")!;
    // 紧凑行：ID + 标题 + reasoning 一句话直接可见（「为什么存疑」第一眼可读）
    const row = within(uncertainGroup).getByTestId("corr-verdict-row");
    expect(row).toHaveTextContent("INJ-VULN-02");
    expect(row).toHaveTextContent("日志清洗 SQL 注入");
    expect(row).toHaveTextContent("adjudication batch failed: llm down");
    // 行收起态不挂卡；点行 → 完整卡挂载
    expect(within(uncertainGroup).queryByTestId("corr-vuln-card")).not.toBeInTheDocument();
    fireEvent.click(row);
    const card = within(uncertainGroup).getByTestId("corr-vuln-card");
    expect(within(card).getByTestId("corr-vuln-verdict")).toHaveTextContent(/存疑/);
  });

  it("翻案置顶：dismissed upgrade 卡在漏洞区顶部 amber 块，点卡头展开论证", async () => {
    await renderWithDetail(detail, "corr-vulns");
    const upgraded = screen.getByTestId("corr-vuln-upgraded");
    expect(within(upgraded).getByText("INJ-09")).toBeInTheDocument();
    // 默认收起：点卡头展开 → 跨仓上下文/论证可见
    expect(within(upgraded).queryByText(/跨仓可达,翻案候选/)).not.toBeInTheDocument();
    fireEvent.click(within(upgraded).getByTestId("corr-adj-card-head"));
    expect(within(upgraded).getByText(/跨仓可达,翻案候选/)).toBeInTheDocument();
  });

  it("成立卡跨仓触发路径：结构化 exploit_path 渲染（入口接口 → RPC 逐跳 → 触达点 + 可控性）", async () => {
    await renderWithDetail();
    const card = within(screen.getByTestId("corr-vulns")).getByTestId("corr-vuln-card");
    const path = within(card).getByTestId("corr-exploit-path");
    // 入口段：入口服务 + HTTP 接口
    expect(within(path).getByTestId("corr-exploit-entry")).toHaveTextContent("frontend");
    expect(within(path).getByTestId("corr-exploit-entry")).toHaveTextContent("POST /orders");
    // RPC 逐跳：方法名 + 调用点
    expect(within(path).getByTestId("corr-exploit-hop")).toHaveTextContent("order.v1.OrderService/CreateOrder");
    expect(within(path).getByTestId("corr-exploit-hop")).toHaveTextContent("checkout.ts:42");
    // 触达点 + 用户可控性
    expect(within(path).getByTestId("corr-exploit-sink")).toHaveTextContent("order/db.py:10");
    expect(within(path).getByTestId("corr-exploit-ctrl")).toHaveTextContent("q 参数原样拼接进 SQL");
    // 跨仓 PoC（从入口接口触发）：curl 以入口为起点 + 前置/步骤/说明
    const xpoc = within(path).getByTestId("corr-exploit-poc");
    expect(within(xpoc).getByText(/跨仓 PoC/)).toBeInTheDocument();
    expect(within(xpoc).getByTestId("corr-exploit-poc-curl")).toHaveTextContent("http://ENTRY/orders");
    expect(within(xpoc).getByText(/可公网达入口服务/)).toBeInTheDocument();
    // 单仓 PoC 降级提示：直连后端内部接口
    expect(within(card).getByTestId("corr-poc-single-note")).toHaveTextContent(/单仓 PoC 直连后端内部接口/);
  });

  it("跨仓修订按需更新卡片：危害修订版优先（原文折叠）、成因补充、定级建议徽标、接口节标注", async () => {
    await renderWithDetail();
    const card = within(screen.getByTestId("corr-vulns")).getByTestId("corr-vuln-card");
    // 卡头定级建议：severity 同维度修订，以「→」紧贴药丸衔接（非并列徽标）；
    // 原 severity 药丸保持单仓值
    const refinedSev = within(card).getByTestId("corr-vuln-sev-refined");
    expect(refinedSev).toHaveTextContent(/定级建议: high/);
    expect(refinedSev).toHaveTextContent("→");
    // 卡头 meta 行：来源/单仓置信度（title 消歧）/CWE/入口接口降为小字——
    // 结论行不再堆来源徽标
    expect(within(card).getByText(/双轨确认/)).toBeInTheDocument();
    expect(within(card).getByTitle("单仓分析置信度")).toHaveTextContent("medium");
    // 危害：修订版为主展示 + 「跨仓修订」徽标 + 原文折叠
    const impact = within(card).getByTestId("corr-impact");
    expect(within(impact).getByText(/外部用户经入口接口可拖库/)).toBeInTheDocument();
    expect(within(impact).getByText("跨仓修订")).toBeInTheDocument();
    expect(within(impact).getByText(/拖库$/)).toBeInTheDocument(); // 单仓原文仍在（折叠）
    // 成因补充（跨仓）
    expect(within(card).getByTestId("corr-refined-cause")).toHaveTextContent(
      "sink 信任上游透传的客户端可控 q 参数",
    );
    // 相关接口节标注：单仓内部接口，入口见跨仓触发路径
    expect(within(card).getByTestId("corr-endpoints-note")).toHaveTextContent(
      /单仓注册的内部接口/,
    );
  });

  it("漏洞卡跨仓富化：结论徽标 + 跨仓上下文（所在链 + 单仓结果链接）", async () => {
    await renderWithDetail();
    const card = within(screen.getByTestId("corr-vulns")).getByTestId("corr-vuln-card");
    // 卡头结论徽标（confirm → 成立 + confidence）
    expect(within(card).getByTestId("corr-vuln-verdict")).toHaveTextContent(/成立/);
    // 跨仓上下文节：reasoning + cross_service_context + 所在链（flows vuln_refs 反查命中）
    expect(within(card).getByTestId("corr-verdict-reasoning")).toHaveTextContent("确认");
    expect(within(card).getByTestId("corr-cross-context")).toHaveTextContent("via frontend");
    // 单仓结果链接：corr_children service → /p/w1/scans/20260824-000002
    expect(within(card).getByTestId("corr-child-link")).toHaveAttribute(
      "href",
      "/p/w1/scans/20260824-000002",
    );
  });

  it("信任边界/已否决/关联报告章节静默撤除：不上页面（信息落 md 附录/下载）", async () => {
    await renderWithDetail();
    expect(screen.queryByTestId("corr-boundaries")).not.toBeInTheDocument();
    expect(screen.queryByTestId("corr-dismissed")).not.toBeInTheDocument();
    // 关联报告只剩总览头下的下载按钮条，全文不渲染
    const report = screen.getByTestId("corr-report");
    expect(within(report).getByRole("button", { name: /下载关联报告/ })).toBeInTheDocument();
    expect(screen.queryByText(/入口参数透传至后端未过滤/)).not.toBeInTheDocument();
    expect(screen.queryByTestId("corr-multihop")).toBeInTheDocument();
  });

  it("区块顺序：总览头 → 报告下载 → 漏洞 → 裁决 → 拓扑 → 多跳", async () => {
    await renderWithDetail();
    const order = ["corr-stats", "corr-report", "corr-vulns", "corr-adjudication",
      "corr-topology", "corr-multihop"];
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

  it("跨仓裁决横幅化：error 占位卡展开必见，无章节标题/徽标行/全量卡平铺", async () => {
    await renderWithDetail(detail, "corr-adjudication");
    const section = screen.getByTestId("corr-adjudication");
    // error 卡默认展开（故障信号必见）：reasoning 直接可见
    expect(within(section).getByText(/adjudication batch failed/)).toBeInTheDocument();
    // 全量卡平铺已撤：非 error 卡（翻案/确认）不在裁决区（翻案置顶漏洞区）
    expect(within(section).queryByText("INJ-09")).not.toBeInTheDocument();
    expect(within(section).getAllByTestId("corr-adj-card").length).toBe(1);
    // 无章节标题（横幅非章节）；direction 徽标行 + 折叠按钮随平铺撤除
    expect(within(section).queryByText("跨仓裁决")).not.toBeInTheDocument();
    expect(screen.queryByTestId("corr-adj-summary")).not.toBeInTheDocument();
    expect(screen.queryByTestId("corr-collapse-all-adj")).not.toBeInTheDocument();
  });

  it("裁决正常完成且无 error 卡 → 零占位（不渲染裁决区）", async () => {
    // 去掉 error 卡：completed + 无故障信号 = 无话说不出现
    const clean: CorrelationDetail = {
      ...detail,
      adjudication: {
        cards: (detail.adjudication!.cards ?? []).filter((c) => c.direction !== "error"),
      },
      adjudication_status: "completed",
    };
    await renderWithDetail(clean, "corr-topology");
    expect(screen.queryByTestId("corr-adjudication")).not.toBeInTheDocument();
  });

  it("多跳链展示(默认收起,details 展开后 path 链可见);卡内亦有经过该服务的多跳", async () => {
    await renderWithDetail(detail, "corr-multihop");
    const det = screen.getByTestId("corr-multihop-list") as HTMLDetailsElement;
    // jsdom 不隐藏 details 收起内容（DOM 常驻）——收起语义断言 open 属性
    expect(det.open).toBe(false);
    fireEvent.click(within(det).getByText("展开 1 条候选链"));
    expect(det.open).toBe(true);
    // 圈定多跳区块（同名链也在漏洞卡「所在多跳候选」内——2026-09-21 每卡附带）
    expect(
      within(det).getByText(/frontend → order-svc → payment-svc/),
    ).toBeInTheDocument();
    const card = within(screen.getByTestId("corr-vulns")).getByTestId("corr-vuln-card");
    expect(within(card).getByTestId("corr-vuln-multihop")).toHaveTextContent(
      "frontend → order-svc → payment-svc",
    );
  });

  it("adjudication 与状态均 null 时不渲染裁决区(multihop 空态提示保留)", async () => {
    await renderWithDetail(
      { ...detail, adjudication: null, adjudication_status: null, multi_hop_chains: [] },
      "corr-topology",
    );
    expect(screen.queryByTestId("corr-adjudication")).not.toBeInTheDocument();
    // multihop 区无条件渲染,空时显示空态提示
    expect(screen.getByTestId("corr-multihop")).toBeInTheDocument();
  });

  it("裁决进行中:无 log 也渲染横幅(corr-adj-running,含覆盖进度),无 error 卡不占位", async () => {
    await renderWithDetail(
      { ...detail, adjudication: null, adjudication_status: "running" },
      "corr-adjudication",
    );
    expect(screen.getByTestId("corr-adj-running")).toHaveTextContent(/跨仓裁决进行中/);
    expect(screen.getByTestId("corr-adj-running")).toHaveTextContent("0/2");
  });

  it("裁决失败:红色横幅透明提示(corr-adj-failed)", async () => {
    await renderWithDetail(
      { ...detail, adjudication: null, adjudication_status: "failed" },
      "corr-adjudication",
    );
    expect(screen.getByTestId("corr-adj-failed")).toHaveTextContent(/跨仓裁决阶段失败/);
  });

  it("单仓已否决：整节静默不上页面（翻案卡仍置顶漏洞区，复核行留 md 报告）", async () => {
    await renderWithDetail(detail, "corr-vulns");
    expect(screen.queryByTestId("corr-dismissed")).not.toBeInTheDocument();
    // 翻案信号保留在漏洞区置顶块
    expect(screen.getByTestId("corr-vuln-upgraded")).toBeInTheDocument();
  });

  it("总览头:结论四件套大数字+成立口径 severity 药丸+过程量脚注,均可点击定位", async () => {
    const scrollTo = vi.fn();
    window.scrollTo = scrollTo as unknown as typeof window.scrollTo;
    await renderWithDetail(detail, "corr-stats");
    const stats = screen.getByTestId("corr-stats");
    // 结论四件套（与漏洞分组同一 verdictSplit，口径单源）：成立 1 / 翻案 1 /
    // 消掉 0 / 存疑 1（error 卡归存疑）；全 0 组不渲染占位
    expect(within(stats).getByTestId("corr-stat-confirmed")).toHaveTextContent("1");
    expect(within(stats).getByTestId("corr-stat-upgraded")).toHaveTextContent("1");
    expect(within(stats).getByTestId("corr-stat-refuted")).toHaveTextContent("0");
    expect(within(stats).getByTestId("corr-stat-uncertain")).toHaveTextContent("1");
    expect(within(stats).queryByTestId("corr-stat-unadjudicated")).not.toBeInTheDocument();
    // 过程量降为 mono 脚注（原 34px 数字卡撤除，裁决卡数不上页面）
    expect(within(stats).getByTestId("corr-stat-process")).toHaveTextContent("2 服务");
    expect(within(stats).getByTestId("corr-stat-process")).toHaveTextContent("合并漏洞 2");
    // severity 药丸为成立口径：critical 1（INJ-VULN-01）；存疑/无 severity 不计入
    expect(within(stats).getByTestId("corr-stat-sev-critical")).toHaveTextContent("1");
    expect(within(stats).getByTestId("corr-stat-sev-high")).toHaveTextContent("0");
    // 点击 severity 药丸 → 定位成立组该等级第一条（scrollTo smooth + 描边闪烁）
    fireEvent.click(within(stats).getByTestId("corr-stat-sev-critical"));
    expect(scrollTo).toHaveBeenCalledWith({ top: expect.any(Number), behavior: "smooth" });
    expect(
      document.getElementById("corr-vuln-INJ-VULN-01")!.classList.contains("dataflow-flash"),
    ).toBe(true);
    // 结论数字点击 → 定位结论组（confirmed 有翻案时落翻案置顶块）
    fireEvent.click(within(stats).getByTestId("corr-stat-upgraded"));
    expect(
      document.getElementById("corr-vuln-upgraded")!.classList.contains("dataflow-flash"),
    ).toBe(true);
  });

  it("目录点存疑组条目：联动展开折叠组 + 紧凑行 + 卡体（异步 focus 定位）", async () => {
    const scrollTo = vi.fn();
    window.scrollTo = scrollTo as unknown as typeof window.scrollTo;
    await renderWithDetail(detail, "corr-vulns");
    // 存疑组默认折叠：INJ-VULN-02 行未挂载
    expect(screen.queryByTestId("corr-verdict-row")).not.toBeInTheDocument();
    // CorrToc 漏洞条目（存疑组）点击 → locateVuln 联动
    const tocBtn = document.querySelector('[data-toc-id="corr-vuln-INJ-VULN-02"]');
    expect(tocBtn).not.toBeNull();
    fireEvent.click(tocBtn!);
    await waitFor(() =>
      expect(
        document.getElementById("corr-vuln-INJ-VULN-02")!.classList.contains("dataflow-flash"),
      ).toBe(true));
    expect(scrollTo).toHaveBeenCalledWith({ top: expect.any(Number), behavior: "smooth" });
    // 行与卡体均已展开（卡圈定存疑组——成立组还有 INJ-VULN-01 的卡）
    expect(screen.getByTestId("corr-verdict-row")).toBeInTheDocument();
    const uncertainGroup = within(screen.getByTestId("corr-vulns"))
      .getAllByTestId("corr-vuln-verdict-group")
      .find((g) => g.getAttribute("data-group") === "uncertain")!;
    expect(within(uncertainGroup).getByTestId("corr-vuln-card")).toBeInTheDocument();
  });

  it("漏洞区集中折叠:全部收起/展开(ReportView 模式),默认全展开", async () => {
    await renderWithDetail(detail, "corr-vulns");
    const vulns = screen.getByTestId("corr-vulns");
    // 默认全展开（成立组）：INJ-VULN-01 展开体可见
    expect(within(vulns).getByTestId("corr-vuln-endpoints")).toBeInTheDocument();
    // 全部收起 → 展开体不可见（卡头 ID 仍在）
    fireEvent.click(within(vulns).getByTestId("corr-collapse-all-vulns"));
    expect(within(vulns).queryByTestId("corr-vuln-endpoints")).not.toBeInTheDocument();
    expect(within(vulns).getByText("INJ-VULN-01")).toBeInTheDocument();
    // 全部展开 → 恢复
    fireEvent.click(within(vulns).getByTestId("corr-expand-all-vulns"));
    expect(within(vulns).getByTestId("corr-vuln-endpoints")).toBeInTheDocument();
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
