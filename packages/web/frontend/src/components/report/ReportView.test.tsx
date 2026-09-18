import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";
import i18n from "@/i18n";
import { ReportView } from "./ReportView";
import { ExecutiveSummary } from "./ExecutiveSummary";
import { StatsRow } from "./StatsRow";
import { VulnerabilityCard, buildRawHttp } from "./VulnerabilityCard";
import type { ReportData, ReportStatsData, ReportVulnerability } from "@/api/types";

// ── fixture：对齐 core pydantic schema（models/report_data.py）snake_case 直传 ──

const vuln: ReportVulnerability = {
  id: "XSS-VULN-01",
  type: "xss",
  vulnerability_type: "Stored",
  title: "备忘录存储型 XSS",
  severity: "high",
  confidence: "high",
  cwe_id: "CWE-79",
  cvss: "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L 8.6",
  owasp_category: "A03:2021-Injection",
  externally_exploitable: true,
  merge_source: "both",
  merged_from: ["XSS-GN-13"],
  narrative: {
    cause: "渲染 memo 时未转义",
    impact: "会话窃取",
    remediation: "启用转义",
  },
  problem_points: [
    {
      location: "app/routes/memos.js:13",
      description: "memo 参数未校验直接落库",
      snippet: "const memo = req.body.memo;",
    },
    {
      location: "app/views/memos.html:31",
      description: "渲染时未转义输出",
      snippet: "<%= memo %>",
    },
  ],
  endpoints: [
    {
      method: "POST",
      path: "/memos",
      role: "write",
      auth: "isLoggedIn",
      params: ["memo"],
      route_registered_at: "app/routes/index.js:66",
      source_location: "app/routes/memos.js:13",
      sink_location: "app/views/memos.html:31",
    },
  ],
  affected_entries: [],
  dataflow_steps: [
    { label: "用户输入", file: "app/routes/memos.js", line: 13, protection: null },
    { label: "落库", file: "app/models/memo.js", line: 8, protection: "无" },
  ],
  poc: {
    // spec 2026-08-27-poc-agent-direct-design：poc-agent 直产文本 schema
    preconditions: "需登录（connect.sid）",
    expected_response: "响应含未转义 payload（onerror 触发）",
    steps: ["plant via POST /memos", "victim opens /memos"],
    self_check: "pass",
    curl: "curl -X POST 'http://t/memos' -d 'memo=<img src=x onerror=alert(1)>'",
    raw_http: null,
  },
  evidence: {
    verification: "static",
    dynamic_evidence: null,
    verdict: "vulnerable",
    code_snippet: "res.render('memos', { memo })",
    notes: null,
  },
  attack_chain_refs: [],
};

const dynamicVuln: ReportVulnerability = {
  ...vuln,
  id: "INJ-VULN-02",
  title: "NoSQL 注入（黑盒实测）",
  severity: "critical",
  merge_source: "llm-only",
  merged_from: [],
  evidence: {
    verification: "dynamic",
    dynamic_evidence: "HTTP/1.1 200 OK\n{\"uid\": 1000, \"role\": \"admin\"}",
    verdict: "exploited",
  },
};

const data: ReportData = {
  schema_version: 1,
  scan: { id: "scan-1", track: "whitebox", repo: "NodeGoat" },
  executive_summary: {
    narrative: "应用暴露面集中在备忘录模块",
    risk_level: "极高",
    top_risks: [
      { vuln_id: "XSS-VULN-01", reason: "公网可达且 pre-auth", priority: "P0" },
      { vuln_id: "INJ-VULN-02", reason: "实测已利用", priority: "P1" },
    ],
    remediation_order: "先修 XSS-VULN-01，再处理注入",
  },
  stats: {
    by_type: {
      xss: { count: 1, severity_range: "high", key_findings: "备忘录渲染缺转义" },
      injection: { count: 1, severity_range: "critical", key_findings: "NoSQL $where" },
      ssrf: { count: 0, severity_range: null, key_findings: null },
    },
    by_severity: { critical: 1, high: 1, medium: 0, low: 0 },
  },
  vulnerabilities: [vuln, dynamicVuln],
  attack_chains: [],
  qa: { passed: true, checks: [], reworked_ids: [] },
};

beforeEach(() => i18n.changeLanguage("zh"));
afterEach(() => i18n.changeLanguage("zh"));

describe("ReportView（JSON 纯渲染集成）", () => {
  it("渲染执行摘要叙事 + 统计行 + 全部漏洞卡", () => {
    render(<ReportView data={data} />);
    expect(screen.getByText(/应用暴露面集中在备忘录模块/)).toBeInTheDocument();
    expect(screen.getAllByTestId("report-vuln-card").length).toBe(2);
    // ID 同时出现在摘要锚点与卡片头（top-risk link → 卡片 id 锚点互通）
    expect(screen.getAllByText("XSS-VULN-01").length).toBeGreaterThanOrEqual(2);
    expect(screen.getAllByText("INJ-VULN-02").length).toBeGreaterThanOrEqual(2);
  });

  it("qa.passed=false 时显式呈现 QA 未通过横幅", () => {
    render(<ReportView data={{ ...data, qa: { passed: false, checks: [{ check: "endpoints≥1", failed_ids: ["X-1"] }], reworked_ids: [] } }} />);
    expect(screen.getByTestId("report-qa-banner")).toBeInTheDocument();
    expect(screen.getByText(/QA 校验未通过/)).toBeInTheDocument();
  });

  it("结构化报告所有可见代码块（Markdown 与原生面板）都带复制按钮", () => {
    const withCode: ReportData = {
      ...data,
      executive_summary: {
        ...data.executive_summary!,
        remediation_order: "优先执行：\n\n```bash\nnpm audit fix\n```",
      },
      vulnerabilities: [
        {
          ...vuln,
          narrative: {
            cause: "成因：\n\n```javascript\nrender(input)\n```",
            impact: "影响",
            remediation: "修复：\n\n```javascript\nescape(input)\n```",
          },
          evidence: {
            ...vuln.evidence!,
            dynamic_evidence: "HTTP/1.1 200 OK\nok",
            steps: [{ action: "Verify", command: "curl http://t/health", result: "200" }],
          },
        },
      ],
      attack_chains: [
        { id: "llm-chain-1", narrative: "链路：\n\n```http\nGET /x\n```", steps: [] },
      ],
    };
    const { container } = render(<ReportView data={withCode} />);
    const blocks = [...container.querySelectorAll("pre")];
    expect(blocks.length).toBeGreaterThan(5);
    blocks.forEach((block) => {
      expect(
        block.querySelector("button.copy-btn, button.code-chrome"),
        `code block without copy button: ${block.outerHTML}`,
      ).toBeTruthy();
    });
  });

  it("POC 步骤由有序列表统一编号，兼容旧报告中 agent 自带的步骤前缀", () => {
    render(
      <VulnerabilityCard
        v={{
          ...vuln,
          poc: {
            ...vuln.poc!,
            steps: ["1. 使用测试账号登录", "2) 提交 PoC payload", "3、观察响应", "1.2.3 版本说明不应被截断"],
          },
        }}
      />,
    );

    const items = within(screen.getByTestId("poc-steps"))
      .getAllByRole("listitem")
      .map((item) => item.textContent);
    expect(items).toEqual(["使用测试账号登录", "提交 PoC payload", "观察响应", "1.2.3 版本说明不应被截断"]);
  });

  it("目录（ReportToc）：条目镜像区块，点击精准定位（scrollTo smooth）+ 目标卡描边闪烁", () => {
    const scrollTo = vi.fn();
    window.scrollTo = scrollTo as unknown as typeof window.scrollTo;
    render(<ReportView data={data} />);
    const toc = screen.getByTestId("report-toc");
    expect(within(toc).getByText("漏洞 (2)")).toBeInTheDocument();
    expect(toc.querySelector('[data-toc-id="XSS-VULN-01"]')).toBeTruthy();
    expect(toc.querySelector('[data-toc-id="INJ-VULN-02"]')).toBeTruthy();
    fireEvent.click(toc.querySelector('[data-toc-id="XSS-VULN-01"]')!);
    expect(scrollTo).toHaveBeenCalledWith({ top: expect.any(Number), behavior: "smooth" });
    expect(document.getElementById("XSS-VULN-01")!.classList.contains("dataflow-flash")).toBe(true);
  });
});

describe("ExecutiveSummary", () => {
  it("渲染叙事 + 风险等级 + 修复优先级", () => {
    render(<ExecutiveSummary summary={data.executive_summary!} />);
    expect(screen.getByText(/应用暴露面集中在备忘录模块/)).toBeInTheDocument();
    expect(screen.getByText(/风险等级: 极高/)).toBeInTheDocument();
    expect(screen.getByText(/先修 XSS-VULN-01/)).toBeInTheDocument();
  });

  it("top_risks 锚点链接到对应漏洞卡（href=#vuln_id）", () => {
    render(<ExecutiveSummary summary={data.executive_summary!} />);
    const a = screen.getByRole("link", { name: /XSS-VULN-01/ }) as HTMLAnchorElement;
    expect(a.getAttribute("href")).toBe("#XSS-VULN-01");
    expect(screen.getByRole("link", { name: /INJ-VULN-02/ })).toBeInTheDocument();
    // priority 徽章呈现
    expect(screen.getByText("P0")).toBeInTheDocument();
  });
});

describe("StatsRow", () => {
  it("按类型呈现 count（零计数类型也显示——数据自带，前端不推断）", () => {
    render(<StatsRow stats={data.stats!} />);
    const xss = screen.getByTestId("stat-type-xss");
    expect(within(xss).getByText("1")).toBeInTheDocument();
    const ssrf = screen.getByTestId("stat-type-ssrf");
    expect(within(ssrf).getByText("0")).toBeInTheDocument();
    expect(within(ssrf).getByText(/N\/A|—|—/)).toBeInTheDocument(); // 零计数 range 降级
  });

  it("呈现 key_findings 与 by_severity 分布", () => {
    render(<StatsRow stats={data.stats!} />);
    expect(screen.getByText(/备忘录渲染缺转义/)).toBeInTheDocument();
    // by_severity：critical 1 / high 1
    const sev = screen.getByTestId("stat-severity");
    expect(within(sev).getByText(/Critical/i)).toBeInTheDocument();
    expect(within(sev).getAllByText("1").length).toBeGreaterThanOrEqual(2);
  });

  it("融合轨（分列数非 null）：count 下呈现「白盒 N · 黑盒 M」；单轨不渲染", () => {
    const fusionStats: ReportStatsData = {
      by_type: {
        xss: { count: 1, severity_range: "high",
               whitebox_count: 1, blackbox_count: 1 },
        ssrf: { count: 1, severity_range: "critical",
                whitebox_count: 1, blackbox_count: 0 },
      },
      by_severity: { critical: 1, high: 1 },
    };
    const { unmount } = render(<StatsRow stats={fusionStats} />);
    const xss = screen.getByTestId("stat-type-xss");
    expect(within(xss).getByText(/白盒 1 · 黑盒 1/)).toBeInTheDocument();
    const ssrf = screen.getByTestId("stat-type-ssrf");
    expect(within(ssrf).getByText(/白盒 1 · 黑盒 0/)).toBeInTheDocument();
    // 单轨（分列数缺省）：无分列小字
    unmount();
    render(<StatsRow stats={data.stats!} />);
    expect(screen.queryByText(/白盒 \d/)).toBeNull();
  });
});

describe("VulnerabilityCard", () => {
  it("头部：ID + 标题 + 严重度徽章 + 双轨徽章 + merged_from 徽章", () => {
    render(<VulnerabilityCard v={vuln} />);
    expect(screen.getByText("XSS-VULN-01")).toBeInTheDocument();
    // 标题升主标题（2026-08-26）：独立标题行（vuln-title），不再 truncate / 70% 透明
    const title = screen.getByTestId("vuln-title");
    expect(title.textContent).toBe("备忘录存储型 XSS");
    expect(title.className).not.toContain("truncate");
    const card = screen.getByTestId("report-vuln-card");
    // severity 左缘色规（high → orange 梯度，ExecutiveSummary 红左规语言推广）
    expect(card.className).toContain("border-l-orange");
    expect(card.getAttribute("data-severity")).toBe("high");
    expect(screen.getByText(/双轨确认/)).toBeInTheDocument();
    expect(screen.getByText(/XSS-GN-13/)).toBeInTheDocument();
    expect(screen.getByText(/高危/)).toBeInTheDocument(); // vuln.severity.High zh
  });

  it("可达徽章中性 ⌖ 字形（非红——可达性不与 severity 抢红色通道，spec 2026-08-27 §2.1）", () => {
    render(<VulnerabilityCard v={vuln} />);
    const badge = screen.getByText(/⌖/);
    expect(badge.textContent).toContain("可达");
    expect(badge.className).not.toContain("text-red");
    expect(badge.className).not.toContain("border-red");
  });

  it("sev dot 形状通道（填充比例）+ Medium 虚线左缘（spec 2026-08-27 §2.2/§2.3）", () => {
    const { rerender } = render(<VulnerabilityCard v={vuln} />);
    expect(screen.getByTestId("report-vuln-sev").querySelector("span")?.className).toContain("sev-dot-high");
    rerender(<VulnerabilityCard v={{ ...vuln, severity: "critical" }} />);
    expect(screen.getByTestId("report-vuln-sev").querySelector("span")?.className).toContain("sev-dot-critical");
    // Medium：左缘 hue=yellow + 线型=虚线（近单色主题兜底通道）
    rerender(<VulnerabilityCard v={{ ...vuln, severity: "medium" }} />);
    const cardCls = screen.getByTestId("report-vuln-card").className;
    expect(cardCls).toContain("border-l-yellow");
    expect(cardCls).toContain("[border-left-style:dashed]");
  });

  it("narrative 节独立纵排（弃 3 列 grid）：成因/危害/修复建议各成节，节头标签按七节基准", () => {
    render(<VulnerabilityCard v={vuln} />);
    expect(screen.getByTestId("sec-cause").textContent).toContain("渲染 memo 时未转义");
    expect(screen.getByTestId("sec-impact").textContent).toContain("会话窃取");
    expect(screen.getByTestId("sec-remediation").textContent).toContain("启用转义");
    expect(screen.getByText("漏洞成因（研判依据）")).toBeInTheDocument();
    expect(screen.getByText("漏洞危害")).toBeInTheDocument();
    expect(screen.getByText("修复建议")).toBeInTheDocument();
    // 弃 grid md:grid-cols-3：全卡纵向排布
    const card = screen.getByTestId("report-vuln-card");
    expect(card.className).not.toContain("md:grid-cols-3");
    expect(screen.queryByTestId("vuln-narrative")).not.toBeInTheDocument();
  });

  it("cause 空 → 成因节整体省略（GN-only 卡自然降级，不出空壳节）", () => {
    render(
      <VulnerabilityCard
        v={{ ...vuln, narrative: { cause: null, impact: "会话窃取", remediation: "启用转义" } }}
      />,
    );
    expect(screen.queryByTestId("sec-cause")).not.toBeInTheDocument();
    expect(screen.getByTestId("sec-impact")).toBeInTheDocument();
  });

  it("七节纵向顺序（spec §3 基准）：成因 → 危害 → 问题点 → 相关接口 → POC → 证据 → 漏洞细节 → 修复建议", () => {
    render(<VulnerabilityCard v={vuln} />);
    const card = screen.getByTestId("report-vuln-card");
    const ids = [
      "sec-cause",
      "sec-impact",
      "sec-problem-points",
      "sec-endpoints",
      "vuln-poc",
      "vuln-evidence",
      "sec-details",
      "sec-remediation",
    ];
    const els = ids.map((id) => card.querySelector(`[data-testid="${id}"]`));
    els.forEach((el, i) => expect(el, `section ${ids[i]} should render`).toBeTruthy());
    for (let i = 1; i < els.length; i++) {
      // els[i] 在 DOM 中跟随 els[i-1] 之后（纵向节序）
      expect(
        els[i - 1]!.compareDocumentPosition(els[i]!) & Node.DOCUMENT_POSITION_FOLLOWING,
      ).toBeTruthy();
    }
  });

  it("问题点节：problem_points 逐条渲染（位置 mono + 说明 + 代码片段 pre）", () => {
    render(<VulnerabilityCard v={vuln} />);
    const sec = screen.getByTestId("sec-problem-points");
    const items = within(sec).getAllByTestId("problem-point");
    expect(items.length).toBe(2);
    expect(items[0].textContent).toContain("app/routes/memos.js:13");
    expect(items[0].textContent).toContain("memo 参数未校验直接落库");
    const snippets = within(sec).getAllByTestId("problem-point-snippet");
    expect(snippets[0].textContent).toContain("const memo = req.body.memo;");
    expect(snippets[1].textContent).toContain("<%= memo %>");
  });

  it("problem_points 空时兜底链：位置 ← endpoints source→sink 逐行、片段 ← evidence.code_snippet", () => {
    render(<VulnerabilityCard v={{ ...vuln, problem_points: [] }} />);
    const sec = screen.getByTestId("sec-problem-points");
    const rows = within(sec).getAllByTestId("problem-point-location");
    expect(rows.length).toBe(1);
    expect(rows[0].textContent).toContain("app/routes/memos.js:13");
    expect(rows[0].textContent).toContain("app/views/memos.html:31");
    expect(within(sec).getAllByTestId("problem-point-snippet").length).toBe(1);
    expect(within(sec).getByTestId("problem-point-snippet").textContent).toContain(
      "res.render('memos', { memo })",
    );
  });

  it("问题点全空（无 problem_points、endpoints 无行号、无 code_snippet）→ 整节省略", () => {
    render(
      <VulnerabilityCard
        v={{
          ...vuln,
          problem_points: [],
          endpoints: [{ ...vuln.endpoints[0], source_location: null, sink_location: null }],
          evidence: { ...vuln.evidence!, code_snippet: null },
        }}
      />,
    );
    expect(screen.queryByTestId("sec-problem-points")).not.toBeInTheDocument();
  });

  it("相关接口：紧凑块（METHOD /path mono 加粗 + role 徽章 + 参数/认证/路由注册小字行），无表格", () => {
    render(<VulnerabilityCard v={vuln} />);
    const sec = screen.getByTestId("sec-endpoints");
    expect(sec.querySelector("table")).toBeNull();
    const blocks = within(sec).getAllByTestId("endpoint-block");
    expect(blocks.length).toBe(1);
    expect(within(blocks[0]).getByText("POST /memos")).toBeInTheDocument();
    expect(within(blocks[0]).getByTestId("endpoint-role").textContent).toBe("write");
    const meta = within(blocks[0]).getByTestId("endpoint-meta").textContent ?? "";
    expect(meta).toContain("memo");
    expect(meta).toContain("isLoggedIn");
    expect(meta).toContain("app/routes/index.js:66");
  });

  it("多接口逐块渲染（紧凑块非表格，块数 = endpoints 数）", () => {
    render(
      <VulnerabilityCard
        v={{
          ...vuln,
          endpoints: [
            ...vuln.endpoints,
            { method: "GET", path: "/memos/:id", role: "trigger", auth: null, params: ["id"], route_registered_at: null, source_location: null, sink_location: null },
          ],
        }}
      />,
    );
    const sec = screen.getByTestId("sec-endpoints");
    const blocks = within(sec).getAllByTestId("endpoint-block");
    expect(blocks.length).toBe(2);
    expect(within(blocks[1]).getByText("GET /memos/:id")).toBeInTheDocument();
    const meta = within(blocks[1]).getByTestId("endpoint-meta").textContent ?? "";
    expect(meta).toContain("id");
    expect(meta).not.toContain("isLoggedIn");
  });

  it("POC 节：curl ↔ Burp 双 tab，默认 curl；冗长 method/url/headers 逐行列表已删", () => {
    const writeText = vi.fn();
    Object.assign(navigator, { clipboard: { writeText } });
    render(<VulnerabilityCard v={vuln} />);
    const poc = screen.getByTestId("vuln-poc");
    // 默认 curl tab：curl 串原样展示（poc.curl 优先）+ 复制按钮
    expect(within(poc).getByTestId("poc-curl").textContent).toContain(
      "curl -X POST 'http://t/memos' -d 'memo=<img src=x onerror=alert(1)>'",
    );
    expect(within(poc).queryByTestId("poc-burp")).not.toBeInTheDocument();
    // 冗长的 poc-request 逐行列表已删除（双格式块是其超集）
    expect(within(poc).queryByTestId("poc-request")).not.toBeInTheDocument();
    expect(within(poc).queryByTestId("poc-body")).not.toBeInTheDocument();
    fireEvent.click(within(poc).getByTestId("copy-curl"));
    expect(writeText).toHaveBeenCalledWith("curl -X POST 'http://t/memos' -d 'memo=<img src=x onerror=alert(1)>'");
    // 前置条件 / 预期响应 / witness 保留
    expect(within(poc).getByTestId("poc-steps").textContent).toContain("plant via POST /memos");
    expect(within(poc).getByText(/需登录/)).toBeInTheDocument();
    expect(within(poc).getByText(/响应含未转义 payload/)).toBeInTheDocument();
    expect(within(poc).getByText(/onerror 触发/)).toBeInTheDocument();
  });

  // 黑盒形态 poc（request 对象、无 curl/raw_http 文本）——验证前端确定性拼兜底
  // （黑盒重放证据仍走此路径，spec 2026-08-27-poc-agent-direct-design 非目标不动）
  const blackboxPoc = {
    request: {
      method: "POST",
      url: "http://t/memos",
      headers: { Cookie: "connect.sid=abc" },
      body: "memo=<img src=x onerror=alert(1)>",
    },
    preconditions: "需登录",
    expected_response: { indicator: "响应含未转义 payload", success_criteria: null },
  };

  it("POC Burp tab：raw_http 缺 → 由 request 确定性拼 raw HTTP（方法行 + Host + headers + body）", () => {
    const writeText = vi.fn();
    Object.assign(navigator, { clipboard: { writeText } });
    render(<VulnerabilityCard v={{ ...vuln, poc: blackboxPoc }} />);
    const poc = screen.getByTestId("vuln-poc");
    fireEvent.click(within(poc).getByTestId("poc-tab-burp"));
    const burp = within(poc).getByTestId("poc-burp");
    expect(burp.textContent).toContain("POST /memos HTTP/1.1");
    expect(burp.textContent).toContain("Host: t");
    expect(burp.textContent).toContain("Cookie: connect.sid=abc");
    expect(burp.textContent).toContain("memo=<img src=x onerror=alert(1)>");
    // 切走后 curl 块隐藏；Burp 块自带复制按钮
    expect(within(poc).queryByTestId("poc-curl")).not.toBeInTheDocument();
    fireEvent.click(within(poc).getByTestId("copy-burp"));
    const copied = writeText.mock.calls[0][0] as string;
    expect(copied).toContain("POST /memos HTTP/1.1");
    expect(copied).toContain("Host: t");
    // 切回 curl
    fireEvent.click(within(poc).getByTestId("poc-tab-curl"));
    expect(within(poc).getByTestId("poc-curl")).toBeInTheDocument();
    expect(within(poc).queryByTestId("poc-burp")).not.toBeInTheDocument();
  });

  it("POC Burp tab：raw_http 有值时原样展示（不走 request 拼装）", () => {
    render(
      <VulnerabilityCard
        v={{ ...vuln, poc: { ...vuln.poc!, raw_http: "POST /memos HTTP/1.1\nHost: t\nX-Burp: 1\n\nmemo=x" } }}
      />,
    );
    fireEvent.click(screen.getByTestId("poc-tab-burp"));
    const burp = screen.getByTestId("poc-burp");
    expect(burp.textContent).toContain("X-Burp: 1");
    expect(burp.textContent).not.toContain("connect.sid");
  });

  it("漏洞细节节 meta：CVSS 尾分数提亮（font-semibold）+ 向量串 mono + OWASP badge", () => {
    render(<VulnerabilityCard v={vuln} />);
    const score = screen.getByTestId("cvss-score");
    expect(score.textContent).toBe("8.6");
    expect(score.className).toContain("font-semibold");
    expect(screen.getByTestId("cvss-vector").textContent).toContain("AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L");
    const owasp = screen.getByTestId("owasp-badge");
    expect(owasp.textContent).toContain("A03:2021-Injection");
  });

  it("CVSS 无尾分数结构 → 不切分，原样 mono（无 score 提亮元素）", () => {
    render(<VulnerabilityCard v={{ ...vuln, cvss: "AV:N/AC:L/PR:L" }} />);
    expect(screen.queryByTestId("cvss-score")).not.toBeInTheDocument();
    expect(screen.getByTestId("cvss-vector").textContent).toContain("AV:N/AC:L/PR:L");
  });

  it("dataflow_steps 折叠区：默认收起，点击展开显示步 + file:line", () => {
    render(<VulnerabilityCard v={vuln} />);
    expect(screen.queryByTestId("dataflow-step")).not.toBeInTheDocument();
    fireEvent.click(screen.getByTestId("dataflow-toggle"));
    const steps = screen.getAllByTestId("dataflow-step");
    expect(steps.length).toBe(2);
    expect(steps[0].textContent).toContain("用户输入");
    expect(steps[0].textContent).toContain("app/routes/memos.js:13");
  });

  it("evidence：dynamic 实测输出突出显示（data-testid）", () => {
    render(<VulnerabilityCard v={dynamicVuln} />);
    const dyn = screen.getByTestId("dynamic-evidence");
    expect(dyn.textContent).toContain("uid");
    expect(screen.getByText(/动态实测|实测验证/)).toBeInTheDocument();
  });

  it("验证步骤：steps 非空 → 分步骤时间线，每步 action + 命令代码块 + 复制按钮 + result 观察行", () => {
    const v: ReportVulnerability = {
      ...dynamicVuln,
      evidence: {
        verification: "dynamic",
        dynamic_evidence: "HTTP/1.1 200 OK\n{\"uid\": 1000}",
        verdict: "exploited",
        steps: [
          {
            action: "Login and capture session cookie",
            command: "curl -s -c jar http://t/login -d 'user=a'",
            result: "302 Set-Cookie connect.sid",
          },
          { action: "Post memo with witness payload", result: "reflected unencoded" },
        ],
      },
    };
    render(<VulnerabilityCard v={v} />);
    const sec = screen.getByTestId("vuln-evidence");
    const items = within(sec).getAllByTestId("verify-step");
    expect(items.length).toBe(2);
    expect(items[0].textContent).toContain("Login and capture session cookie");
    // 命令进独立代码块（可复制人工复验）
    const cmds = within(sec).getAllByTestId("verify-step-command");
    expect(cmds.length).toBe(1);
    expect(cmds[0].textContent).toContain("curl -s -c jar http://t/login");
    expect(within(sec).getByTestId("copy-step-command")).toBeInTheDocument();
    // result 观察行跟随
    expect(items[0].textContent).toContain("302 Set-Cookie connect.sid");
    expect(items[1].textContent).toContain("reflected unencoded");
    // 实测结论（dynamic_evidence）保留
    expect(screen.getByTestId("dynamic-evidence").textContent).toContain("uid");
  });

  it("验证步骤：steps 空（白盒卡/旧数据）→ 无步骤时间线，evidence 节原样（零变化）", () => {
    render(<VulnerabilityCard v={vuln} />);
    const sec = screen.getByTestId("vuln-evidence");
    expect(sec.querySelector('[data-testid="verify-step"]')).toBeNull();
  });

  it("curl 缺失时由 request 确定性拼出复制内容（渲染层格式化，非推断）", () => {
    const writeText = vi.fn();
    Object.assign(navigator, { clipboard: { writeText } });
    render(
      <VulnerabilityCard
        v={{ ...vuln, poc: blackboxPoc }}
      />,
    );
    fireEvent.click(screen.getByTestId("copy-curl"));
    const copied = writeText.mock.calls[0][0] as string;
    expect(copied).toContain("curl");
    expect(copied).toContain("http://t/memos");
    expect(copied).toContain("-H 'Cookie: connect.sid=abc'");
    expect(copied).toContain("memo=<img src=x onerror=alert(1)>");
  });

  // 非安全上下文（http://内网IP:7878 部署访问）下 navigator.clipboard === undefined：
  // 旧实现 `clipboard?.writeText` 静默无操作还切 Check 图标（假成功），用户报告
  // 「复制不生效」真根因。守护 fallback 到 execCommand 路径。
  it("非安全上下文：clipboard 不可用 → copy-curl 走 execCommand fallback 仍复制成功", async () => {
    Object.defineProperty(navigator, "clipboard", { value: undefined, configurable: true, writable: true });
    let captured = "";
    const exec = vi.fn(() => {
      captured = document.querySelector("textarea")?.value ?? "";
      return true;
    });
    document.execCommand = exec as unknown as typeof document.execCommand;
    try {
      render(<VulnerabilityCard v={vuln} />);
      fireEvent.click(screen.getByTestId("copy-curl"));
      expect(exec).toHaveBeenCalledWith("copy");
      expect(captured).toContain("curl -X POST 'http://t/memos'");
      // 复制成功 → aria-label 切「已复制」（真实成功，非旧实现的假成功）
      await waitFor(() =>
        expect(screen.getByTestId("copy-curl")).toHaveAttribute("aria-label", "已复制"),
      );
    } finally {
      delete (document as { execCommand?: unknown }).execCommand;
    }
  });
});

describe("buildRawHttp（Burp 格式确定性拼装，导出纯函数）", () => {
  it("方法行（path+query）+ Host（从 url 取）+ headers + 空行 + body", () => {
    expect(
      buildRawHttp({
        method: "POST",
        url: "http://t/memos?q=1",
        headers: { Cookie: "sid=1" },
        body: "memo=x",
      }),
    ).toBe("POST /memos?q=1 HTTP/1.1\nHost: t\nCookie: sid=1\n\nmemo=x");
  });

  it("headers 已含 Host 时不重复；无 body 不追加空行", () => {
    expect(
      buildRawHttp({ method: "GET", url: "http://t/x", headers: { Host: "t2.example" } }),
    ).toBe("GET /x HTTP/1.1\nHost: t2.example");
  });
});

// ── spec 2026-08-26-report-single-source-rendering §7：速查表 / 整卡折叠 / qa 逐卡缺口 ──

const qrData: ReportData = {
  ...data,
  quick_reference: [
    {
      id: "XSS-VULN-01",
      title: "备忘录存储型 XSS",
      params: ["memo (body)"],
      endpoints: ["POST /memos (write, isLoggedIn)"],
      severity: "high",
      verification: "静态分析",
      confidence: "待复核",
    },
    {
      id: "INJ-VULN-02",
      title: "NoSQL 注入（黑盒实测）",
      params: ["preTax (body)"],
      endpoints: ["POST /contributions"],
      severity: "critical",
      verification: "动态实测",
      confidence: "高",
    },
  ],
};

describe("速查表节（quick_reference）", () => {
  it("渲染速查表：行数 = 卡数；无 quick_reference（旧数据）整节省略", () => {
    const { unmount } = render(<ReportView data={qrData} />);
    expect(screen.getByTestId("quick-reference")).toBeInTheDocument();
    expect(screen.getAllByTestId("quick-ref-row").length).toBe(2);
    unmount();
    render(<ReportView data={data} />);
    expect(screen.queryByTestId("quick-reference")).not.toBeInTheDocument();
  });

  it("行点击 → 定位对应卡（focusAnchor smooth 滚动，同步路径——卡未折叠）", () => {
    const scrollTo = vi.fn();
    window.scrollTo = scrollTo as unknown as typeof window.scrollTo;
    render(<ReportView data={qrData} />);
    fireEvent.click(screen.getByTestId("quick-ref-jump-XSS-VULN-01"));
    expect(scrollTo).toHaveBeenCalledWith({ top: expect.any(Number), behavior: "smooth" });
  });

  it("卡折叠时点速查表行 → 先展开再定位（waitFor 异步路径）", async () => {
    const scrollTo = vi.fn();
    window.scrollTo = scrollTo as unknown as typeof window.scrollTo;
    render(<ReportView data={qrData} />);
    fireEvent.click(screen.getAllByTestId("vuln-collapse-toggle")[0]);
    expect(within(screen.getAllByTestId("report-vuln-card")[0]).queryByTestId("sec-cause")).not.toBeInTheDocument();
    fireEvent.click(screen.getByTestId("quick-ref-jump-XSS-VULN-01"));
    await waitFor(() => expect(scrollTo).toHaveBeenCalledWith({ top: expect.any(Number), behavior: "smooth" }));
    expect(within(screen.getAllByTestId("report-vuln-card")[0]).getByTestId("sec-cause")).toBeInTheDocument(); // 卡已展开
  });
});

describe("整卡折叠（spec §7：卡头 chevron + 键盘可达）", () => {
  it("默认全展开；点卡头折叠 → 只留卡头（aria-expanded=false），再点恢复", () => {
    render(<ReportView data={data} />);
    const toggles = screen.getAllByTestId("vuln-collapse-toggle");
    expect(toggles.length).toBe(2);
    expect(toggles[0].getAttribute("aria-expanded")).toBe("true");
    fireEvent.click(toggles[0]);
    expect(screen.getAllByTestId("vuln-collapse-toggle")[0].getAttribute("aria-expanded")).toBe("false");
    const card0 = screen.getAllByTestId("report-vuln-card")[0];
    expect(within(card0).queryByTestId("sec-cause")).not.toBeInTheDocument();
    // 卡头（ID+标题+severity）折叠态仍可见
    expect(within(card0).getByText("XSS-VULN-01")).toBeInTheDocument();
    expect(within(card0).getByTestId("vuln-title")).toBeInTheDocument();
    fireEvent.click(screen.getAllByTestId("vuln-collapse-toggle")[0]);
    expect(screen.getAllByTestId("vuln-collapse-toggle")[0].getAttribute("aria-expanded")).toBe("true");
    expect(within(screen.getAllByTestId("report-vuln-card")[0]).getByTestId("sec-cause")).toBeInTheDocument();
  });

  it("卡头是原生 button（键盘可达：Enter/Space 原生触发 click）", () => {
    render(<ReportView data={data} />);
    const btn = screen.getAllByRole("button", { name: /XSS-VULN-01/ }).find(
      (b) => b.getAttribute("data-testid") === "vuln-collapse-toggle",
    );
    expect(btn).toBeTruthy();
    expect(btn!.getAttribute("aria-expanded")).toBe("true");
  });

  it("批量收起/展开：collapse-all 后全部卡身隐藏，expand-all 恢复", () => {
    render(<ReportView data={data} />);
    fireEvent.click(screen.getByTestId("collapse-all"));
    for (const card of screen.getAllByTestId("report-vuln-card")) {
      expect(within(card).queryByTestId("sec-remediation")).not.toBeInTheDocument();
    }
    fireEvent.click(screen.getByTestId("expand-all"));
    for (const card of screen.getAllByTestId("report-vuln-card")) {
      expect(within(card).getByTestId("sec-remediation")).toBeInTheDocument();
    }
  });

  it("目录联动：全部收起后点 TOC 条目 → 目标卡展开（其余仍折叠）+ 定位", async () => {
    const scrollTo = vi.fn();
    window.scrollTo = scrollTo as unknown as typeof window.scrollTo;
    render(<ReportView data={data} />);
    fireEvent.click(screen.getByTestId("collapse-all"));
    const toc = screen.getByTestId("report-toc");
    fireEvent.click(toc.querySelector('[data-toc-id="XSS-VULN-01"]')!);
    await waitFor(() => expect(scrollTo).toHaveBeenCalledWith({ top: expect.any(Number), behavior: "smooth" }));
    expect(within(screen.getAllByTestId("report-vuln-card")[0]).getByTestId("sec-cause")).toBeInTheDocument();
    expect(within(screen.getAllByTestId("report-vuln-card")[1]).queryByTestId("sec-remediation")).not.toBeInTheDocument();
  });

  it("执行摘要 top_risks 联动：折叠卡后点 top-risk 链接 → 目标卡展开", async () => {
    const scrollTo = vi.fn();
    window.scrollTo = scrollTo as unknown as typeof window.scrollTo;
    render(<ReportView data={data} />);
    fireEvent.click(screen.getByTestId("collapse-all"));
    fireEvent.click(screen.getAllByTestId("top-risk-link")[0]);
    await waitFor(() => expect(scrollTo).toHaveBeenCalled());
    expect(within(screen.getAllByTestId("report-vuln-card")[0]).getByTestId("sec-cause")).toBeInTheDocument();
  });
});

describe("qa 横幅升级（逐卡缺口清单，spec §6）", () => {
  const qaData: ReportData = {
    ...data,
    qa: {
      passed: false,
      checks: [
        { check: "problem_points_present", failed_ids: ["XSS-VULN-01"] },
        { check: "poc_complete", failed_ids: ["INJ-VULN-02", "XSS-VULN-01"] },
        { check: "some_future_check", failed_ids: ["INJ-VULN-02"] },
      ],
      reworked_ids: [],
    },
  };

  it("每 check 一行（i18n 文案 + 未知 check 显示原 key）+ failed_ids 徽章", () => {
    render(<ReportView data={qaData} />);
    const banner = screen.getByTestId("report-qa-banner");
    expect(within(banner).getByText(/缺问题点/)).toBeInTheDocument();
    expect(within(banner).getByText(/缺 POC/)).toBeInTheDocument();
    expect(within(banner).getByText("some_future_check")).toBeInTheDocument(); // 未知 key 原样
    const badges = within(banner).getAllByTestId("qa-gap-vuln");
    expect(badges.length).toBe(4); // 1 + 2 + 1
    expect(badges.map((b) => b.textContent)).toContain("INJ-VULN-02");
  });

  it("failed_ids 徽章点击 → 定位对应卡（折叠时先展开）", async () => {
    const scrollTo = vi.fn();
    window.scrollTo = scrollTo as unknown as typeof window.scrollTo;
    render(<ReportView data={qaData} />);
    fireEvent.click(screen.getByTestId("collapse-all"));
    fireEvent.click(screen.getAllByTestId("qa-gap-vuln")[0]); // XSS-VULN-01
    await waitFor(() => expect(scrollTo).toHaveBeenCalled());
    expect(within(screen.getAllByTestId("report-vuln-card")[0]).getByTestId("sec-cause")).toBeInTheDocument();
  });

  it("qa.passed=false 无 failed checks → 横幅在但无缺口行", () => {
    render(<ReportView data={{ ...data, qa: { passed: false, checks: [], reworked_ids: [] } }} />);
    expect(screen.getByTestId("report-qa-banner")).toBeInTheDocument();
    expect(screen.queryAllByTestId("qa-gap-vuln").length).toBe(0);
  });
});

// === MR 增量段（spec 2026-09-03 §6）===
describe("MrIncrementalSummary（MR 增量摘要）", () => {
  const mrData: ReportData = {
    ...data,
    scan: {
      id: "nodegoat-mr-1", track: "whitebox",
      base_commit: "abc1234567890", head_commit: "def9876543210",
      diff_stat: { files: 3, insertions: 25, deletions: 8 },
    },
    incremental_summary: {
      degraded: false,
      new_entry_points: [
        { func_block_id: "app/routes.js:handler:10", function: "handler",
          route: "/memos", method: "POST", authentication: "isLoggedIn" },
      ],
      removed_protections: [
        { file: "app/utils.js", line: 42, kind: "sanitize",
          function: "sanitize_input", rationale: "escapes", followed_by_chains: true },
        { file: "app/gone.js", line: 3, kind: "authz_check",
          function: null, rationale: null, followed_by_chains: false },
      ],
      flow_counts: { new_code: 3, new_entry: 1, removed_protection: 2, affected_flows: 5 },
    },
  };

  it("非 MR 扫描（incremental_summary null）零渲染——全量报告零感知", () => {
    render(<ReportView data={data} />);
    expect(screen.queryByTestId("mr-incremental-summary")).toBeNull();
  });

  it("三统计卡 + base..head 头 + diff stat；明细折叠交互", async () => {
    render(<ReportView data={mrData} />);
    const section = screen.getByTestId("mr-incremental-summary");
    // 三统计卡（受影响链=affected_flows）
    expect(within(section).getByTestId("mr-stat-new-entry").textContent).toContain("1");
    expect(within(section).getByTestId("mr-stat-removed-protection").textContent).toContain("2");
    expect(within(section).getByTestId("mr-stat-affected-flows").textContent).toContain("5");
    // base..head 短显（>10 字符截断）+ diff stat
    expect(within(section).getByText("abc1234567..def9876543")).toBeInTheDocument();
    expect(within(section).getByText(/\+25 \/ −8 · 3/)).toBeInTheDocument();
    // 明细默认收起，点开见入口/防护明细（未追链行显人审提示）
    expect(screen.queryByTestId("mr-new-entry-details")).toBeNull();
    fireEvent.click(screen.getByTestId("mr-details-toggle"));
    const entries = await screen.findByTestId("mr-new-entry-details");
    expect(within(entries).getByText("POST /memos")).toBeInTheDocument();
    const removed = screen.getByTestId("mr-removed-protection-details");
    expect(within(removed).getByText("app/utils.js:42")).toBeInTheDocument();
    expect(within(removed).getByText(/未追链/)).toBeInTheDocument();
  });

  it("degraded=true 显式标注（来源 C 降级不阻塞，提示人工复核）", () => {
    render(<ReportView data={{
      ...mrData,
      incremental_summary: { ...mrData.incremental_summary!, degraded: true },
    }} />);
    expect(screen.getByText(/防护删除分析降级/)).toBeInTheDocument();
  });
});

describe("VulnerabilityCard trigger_source 徽章（MR 来源标注）", () => {
  it("trigger_source 非空 → ∆ 徽章（i18n 文案）；null 不渲染", () => {
    const { rerender } = render(
      <VulnerabilityCard v={{ ...vuln, trigger_source: "removed_protection" }}
        collapsed={false} onToggleCollapse={() => {}} />,
    );
    const badge = screen.getByTestId("trigger-source-badge");
    expect(badge.textContent).toContain("防护删除");
    rerender(
      <VulnerabilityCard v={{ ...vuln, trigger_source: null }}
        collapsed={false} onToggleCollapse={() => {}} />,
    );
    expect(screen.queryByTestId("trigger-source-badge")).toBeNull();
  });
});

describe("ReportView 验证缺口节（spec 2026-09-03 §8）", () => {
  it("verification_gaps 非空 → 渲染缺口节（卡片区后）；缺省 → 不渲染", () => {
    const withGaps: ReportData = {
      ...data,
      verification_gaps: [
        { vuln_id: "XSS-VULN-01", reason: "agent 未完成验证闭环（登记 0/15）；工具轨迹显示已对该端点发起过请求，未产出结论" },
      ],
    };
    const { rerender } = render(<ReportView data={withGaps} />);
    expect(screen.getByTestId("verification-gaps-section")).toBeInTheDocument();
    expect(screen.getByText(/登记 0\/15/)).toBeInTheDocument();
    // 缺省（纯白盒）：不渲染
    rerender(<ReportView data={data} />);
    expect(screen.queryByTestId("verification-gaps-section")).not.toBeInTheDocument();
  });
});
