// CorrVulnCard 单测（2026-09-18 跨仓卡片补全）：toCorrVulnView 纯函数归一
// （宽松 dict 防御拾取 / severity 归一 / 位置兜底链 / params 数组化）+ 组件渲染
// （默认收起卡头可见 ID+药丸，展开后七节按数据出省）。
import { describe, it, expect, beforeEach } from "vitest";
import { render, screen, within, fireEvent } from "@testing-library/react";
import i18n from "@/i18n";
import { CorrVulnCard, toCorrVulnView } from "./CorrVulnCard";
import type { CorrVuln } from "@/api/types";

beforeEach(() => i18n.changeLanguage("zh"));

const full: CorrVuln = {
  ID: "AUTHZ-VULN-01",
  vulnerability_type: "Vertical",
  severity: "critical",
  confidence: "high",
  service: "order-svc",
  merge_source: "both",
  externally_exploitable: true,
  title: "纵向越权写限制组合",
  endpoint: "POST /Restr/Add",
  cvss: "AV:A/AC:L/PR:N 8.1",
  cwe_id: "CWE-862",
  owasp_category: "A01:2021",
  impact: "可写入任意用户限制",
  remediation: "入口加服务身份校验",
  notes: "与 VULN-02 同根因",
  vulnerable_code_location: "svc/impl.go:43",
  report_endpoints: [
    { method: "POST", path: "/Restr/Add", params: ["user_restrict_info"], role: "write",
      auth: "public", route_registered_at: "proto/x.proto:203" },
    { method: "GET", path: "/Restr/Get" },
  ],
  report_problem_points: [
    { location: "svc/impl.go:43", description: "无鉴权", snippet: "def add(req): ..." },
  ],
  report_poc: {
    curl: "curl -X POST http://TARGET/Restr/Add",
    raw_http: "POST /Restr/Add HTTP/1.1\nHost: TARGET\n",
    steps: ["1. 构造请求", "2. 观察响应"],
  },
};

describe("toCorrVulnView", () => {
  it("完整条目：severity 小写归一 Critical + 结构化字段拾取", () => {
    const v = toCorrVulnView(full);
    expect(v.id).toBe("AUTHZ-VULN-01");
    expect(v.severity).toBe("Critical");
    expect(v.externallyExploitable).toBe(true);
    expect(v.endpoint).toBe("POST /Restr/Add");
    expect(v.location).toBe("svc/impl.go:43");
    expect(v.cvss).toBe("AV:A/AC:L/PR:N 8.1");
    expect(v.endpoints).toHaveLength(2);
    expect(v.endpoints[0].params).toEqual(["user_restrict_info"]);
    expect(v.endpoints[1].params).toEqual([]);
    expect(v.problemPoints[0]).toMatchObject({ location: "svc/impl.go:43", description: "无鉴权" });
    expect(v.poc).toMatchObject({ curl: "curl -X POST http://TARGET/Restr/Add" });
    expect(v.poc?.steps).toHaveLength(2);
  });

  it("空条目：安全缺省（ID 占位 / severity 未知不归一 / poc 缺 → undefined）", () => {
    const v = toCorrVulnView({ title: "t", service: "s" });
    expect(v.id).toBe("CORR-VULN-?");
    expect(v.severity).toBeUndefined();
    expect(v.endpoints).toEqual([]);
    expect(v.problemPoints).toEqual([]);
    expect(v.poc).toBeUndefined();
    expect(v.externallyExploitable).toBe(false);
  });

  it("report_poc 全空 → poc undefined（不渲染空 PoC 节）", () => {
    const v = toCorrVulnView({ ...full, report_poc: { steps: [] } });
    expect(v.poc).toBeUndefined();
  });

  it("位置兜底链：vulnerable_code_location 优先", () => {
    expect(toCorrVulnView(full).location).toBe("svc/impl.go:43");
  });

  it("位置兜底链：inj/xss 无 vulnerable_code_location → sink_call", () => {
    const v = toCorrVulnView({
      ...full,
      vulnerable_code_location: undefined,
      sink_call: "query(request)",
    });
    expect(v.location).toBe("query(request)");
  });

  it("位置兜底链：path + sink_function 拼接", () => {
    const v = toCorrVulnView({
      ...full,
      vulnerable_code_location: undefined,
      sink_call: undefined,
      path: "app/render.py",
      sink_function: "render_row",
    });
    expect(v.location).toBe("app/render.py · render_row");
  });

  it("位置兜底链：report_problem_points[0].location → location 垫底", () => {
    const strip = { ...full, vulnerable_code_location: undefined, sink_call: undefined,
      path: undefined, sink_function: undefined };
    expect(toCorrVulnView(strip).location).toBe("svc/impl.go:43");
    expect(toCorrVulnView({ ...strip, report_problem_points: [], location: "loc.py:1" })
      .location).toBe("loc.py:1");
  });
});

describe("CorrVulnCard", () => {
  it("默认收起：卡头可见 ID + severity 药丸 + 标题 + 入口接口；卡身不渲染", () => {
    render(<CorrVulnCard view={toCorrVulnView(full)} />);
    const card = screen.getByTestId("corr-vuln-card");
    expect(within(card).getByText("AUTHZ-VULN-01")).toBeInTheDocument();
    expect(within(card).getByTestId("corr-vuln-sev")).toHaveTextContent("严重");
    expect(within(card).getByText("纵向越权写限制组合")).toBeInTheDocument();
    expect(within(card).getByText("POST /Restr/Add")).toBeInTheDocument();
    expect(screen.queryByTestId("corr-poc")).not.toBeInTheDocument();
  });

  it("展开：危害/接口/问题点/PoC/修复/细节节齐全", () => {
    render(<CorrVulnCard view={toCorrVulnView(full)} />);
    fireEvent.click(screen.getByRole("button"));
    expect(screen.getByTestId("corr-impact")).toHaveTextContent("可写入任意用户限制");
    expect(screen.getByTestId("corr-vuln-endpoints")).toHaveTextContent("user_restrict_info");
    expect(screen.getByTestId("corr-problem-point-location")).toHaveTextContent("svc/impl.go:43");
    expect(screen.getByTestId("corr-poc-curl")).toHaveTextContent("curl -X POST");
    expect(screen.getByTestId("corr-poc-steps")).toHaveTextContent("构造请求");
    expect(screen.getByTestId("corr-remediation")).toHaveTextContent("入口加服务身份校验");
    expect(screen.getByTestId("corr-vuln-meta")).toHaveTextContent("8.1");
    // CWE 在卡头 eyebrow 行（对齐 report 卡习惯），不在 meta 节
    expect(screen.getByTestId("corr-vuln-card")).toHaveTextContent("CWE-862");
  });

  it("PoC curl ↔ Burp 双 tab 切换", () => {
    render(<CorrVulnCard view={toCorrVulnView(full)} />);
    fireEvent.click(screen.getByRole("button"));
    fireEvent.click(screen.getByTestId("corr-poc-tab-burp"));
    expect(screen.getByTestId("corr-poc-raw-http")).toBeInTheDocument();
    expect(screen.queryByTestId("corr-poc-curl")).not.toBeInTheDocument();
  });

  it("无 PoC/无问题点：对应节整节省略", () => {
    const v = toCorrVulnView({
      ...full,
      report_poc: null, report_problem_points: [], impact: undefined,
      remediation: undefined, cvss: undefined, owasp_category: undefined,
      vulnerable_code_location: undefined,
    });
    render(<CorrVulnCard view={v} />);
    fireEvent.click(screen.getByRole("button"));
    expect(screen.queryByTestId("corr-poc")).not.toBeInTheDocument();
    expect(screen.queryByTestId("corr-impact")).not.toBeInTheDocument();
    expect(screen.queryByTestId("corr-remediation")).not.toBeInTheDocument();
    expect(screen.queryByTestId("corr-vuln-endpoints")).toBeInTheDocument(); // 接口节仍在
  });

  it("未知 severity → 无药丸", () => {
    render(<CorrVulnCard view={toCorrVulnView({ ...full, severity: "info" })} />);
    expect(screen.queryByTestId("corr-vuln-sev")).not.toBeInTheDocument();
  });
});
