// D2: correlation / multi-configs API client 契约测试（mock 全局 fetch，不发真请求）。
// 对齐 backend：api/scans.py get_correlation_detail（Task C5）+ api/multi_configs.py
// （MultiRepoConfigStore.list_configs 返 list[str]；POST 返 201 {name}）。
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import {
  getCorrelationDetail, getMultiConfig, listMultiConfigs, saveMultiConfig,
} from "../api/client";

beforeEach(() => vi.stubGlobal("fetch", vi.fn()));
afterEach(() => vi.unstubAllGlobals());

describe("getCorrelationDetail", () => {
  it("GET /api/workspaces/{ws}/scans/{id}/correlation", async () => {
    const fetchMock = vi.mocked(fetch);
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ topology: null, flows: [] }), { status: 200 }));
    await getCorrelationDetail("ws1", "scan-1");
    expect(fetchMock.mock.calls[0][0]).toBe("/api/workspaces/ws1/scans/scan-1/correlation");
    // GET 无显式 method（request() 仅写方法才附 CSRF）
    expect(fetchMock.mock.calls[0][1]?.method).toBeUndefined();
  });

  it("透传 assemble_correlation_detail 全 11 键 payload", async () => {
    const payload = {
      topology: {
        services: [{ name: "frontend", role: "entrypoint", repo: "fe" }],
        edges: [{
          from: "frontend", to: "order", protocol: "grpc", status: "ok",
          calls: [{
            method: "CreateOrder",
            call_site: { file: "a.ts", line: 10, snippet: "client.create()" },
            confidence: "high", evidence: "grep hit",
          }],
          error: null,
        }],
      },
      boundaries: [{
        service: "order", method: "CreateOrder", exposure: "internal",
        reachable_from: ["frontend"], reason: "no auth check", confidence: "high",
      }],
      flows: [{
        edge_from: "frontend", edge_to: "order", entry: "POST /api/cart",
        method: "CreateOrder",
        call_site: { file: "a.ts", line: 10, snippet: "s" },
        vuln_refs: [{ service: "order", title: "SQLi", severity: "high", location: "b.ts:1" }],
        confidence: "low", evidence: "e",
      }],
      multi_hop_chains: [],
      adjudication: null,
      merged_vulns: { order: [{ title: "SQLi", severity: "high" }] },
      drift_warnings: [],
      corr_children: [{ service: "order", scan_id: "s-2", reused: false }],
      dismissed: [],
      adjudication_status: null,
      report_md: "# corr",
    };
    const fetchMock = vi.mocked(fetch);
    fetchMock.mockResolvedValue(new Response(JSON.stringify(payload), { status: 200 }));
    const r = await getCorrelationDetail("ws1", "scan-1");
    expect(r).toEqual(payload);
    expect(Object.keys(r).sort()).toEqual([
      "adjudication", "adjudication_status", "boundaries", "corr_children",
      "dismissed", "drift_warnings", "flows",
      "merged_vulns", "multi_hop_chains", "report_md", "topology",
    ]);
  });
});

describe("listMultiConfigs", () => {
  it("GET /api/multi-configs → 配置名数组（backend list_configs 返 list[str]）", async () => {
    const fetchMock = vi.mocked(fetch);
    fetchMock.mockResolvedValue(new Response(JSON.stringify(["cfg-a", "cfg-b"]), { status: 200 }));
    const r = await listMultiConfigs();
    expect(fetchMock.mock.calls[0][0]).toBe("/api/multi-configs");
    expect(r).toEqual(["cfg-a", "cfg-b"]);
  });
});

describe("saveMultiConfig", () => {
  it("POST /api/multi-configs body {name, content}，透传 201 {name}", async () => {
    const fetchMock = vi.mocked(fetch);
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ name: "cfg-a" }), { status: 201 }));
    const content = "repos:\n  a:\n    path: a\n    role: entrypoint\n";
    const r = await saveMultiConfig("cfg-a", content);
    expect(fetchMock.mock.calls[0][0]).toBe("/api/multi-configs");
    const init = fetchMock.mock.calls[0][1]!;
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({ name: "cfg-a", content });
    expect(r).toEqual({ name: "cfg-a" });
  });
});

describe("getMultiConfig", () => {
  it("GET /api/multi-configs/{name} → {name, content}", async () => {
    const fetchMock = vi.mocked(fetch);
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ name: "cfg-a", content: "repos: {}" }), { status: 200 }));
    const r = await getMultiConfig("cfg-a");
    expect(fetchMock.mock.calls[0][0]).toBe("/api/multi-configs/cfg-a");
    expect(r).toEqual({ name: "cfg-a", content: "repos: {}" });
  });
});
