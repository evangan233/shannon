import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  apiGet, apiPost, apiDelete, ApiError, setUnauthorizedHandler, resetUnauthorizedHandler,
  linkReposInDir, blackboxRunReportPath, blackboxRunDeliverablesPath,
  listBlackboxRuns, addBlackboxToWhitebox,
  startCorrelationTopologyAnalysis, getCorrelationTopologyAnalysis,
  cancelCorrelationTopologyAnalysis, deleteCorrelationTopologyAnalysis,
} from "./client";

// 构造符合 fetch Response 真实契约的 mock：text() 与 json() 都在。
function res({ ok, status, body }: { ok: boolean; status: number; body: unknown }) {
  const text = typeof body === "string" ? body : JSON.stringify(body);
  return {
    ok, status,
    text: async () => text,
    json: async () => (typeof body === "string" ? JSON.parse(body) : body),
  };
}

beforeEach(() => {
  globalThis.fetch = vi.fn() as unknown as typeof fetch;
});

describe("api client", () => {
  it("apiGet 解析 JSON 成功", async () => {
    (globalThis.fetch as any).mockResolvedValue(res({ ok: true, status: 200, body: { name: "ws" } }));
    const r = await apiGet<{ name: string }>("/workspaces/ws");
    expect(r.name).toBe("ws");
  });

  it("apiPost 成功返回 body", async () => {
    (globalThis.fetch as any).mockResolvedValue(res({ ok: true, status: 202, body: { workspace: "ws" } }));
    const r = await apiPost<{ workspace: string }>("/scan", { type: "whitebox" });
    expect(r.workspace).toBe("ws");
  });

  it("422 抛 ApiError 带 body", async () => {
    (globalThis.fetch as any).mockResolvedValue(
      res({ ok: false, status: 422, body: { detail: [{ loc: ["repos"], msg: "bad" }] } }),
    );
    await expect(apiPost("/scan", {})).rejects.toMatchObject({ status: 422 });
    try { await apiPost("/scan", {}); } catch (e) {
      expect(e).toBeInstanceOf(ApiError);
      expect((e as ApiError).body).toMatchObject({ detail: [{ loc: ["repos"] }] });
    }
  });

  it("非 JSON 错误体（500 纯文本/代理 502 HTML）抛 ApiError，而非 body stream already read", async () => {
    // 回归 2026-09-03：__legacy__ ws 触发后端 500 纯文本 "Internal Server Error"，
    // request() 旧错误分支 res.json()（失败、已消费 stream）→ fallback res.text()
    // 双读同一 stream → TypeError "Failed to execute 'text' on 'Response':
    // body stream already read"，掩盖真实状态码。须单次 text() 后 JSON.parse。
    (globalThis.fetch as any).mockResolvedValue(
      new Response("Internal Server Error", { status: 500 }));
    let err: unknown;
    try { await apiPost("/workspaces/__legacy__/correlation-topology/analyses", { repos: [] }); }
    catch (e) { err = e; }
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(500);
    expect((err as ApiError).body).toBe("Internal Server Error");
  });

  it("apiDelete 成功（204 无 body）", async () => {
    (globalThis.fetch as any).mockResolvedValue({ ok: true, status: 204, text: async () => "" });
    const r = await apiDelete<{ ok: true }>("/workspaces/ws");
    expect(r).toEqual({});
  });

  it("请求前缀 /api 且 POST 带 JSON body + Content-Type", async () => {
    let captured: { url?: string; init?: RequestInit } = {};
    (globalThis.fetch as any).mockImplementation((url: string, init: RequestInit) => {
      captured = { url, init };
      return Promise.resolve(res({ ok: true, status: 202, body: { workspace: "ws" } }));
    });
    await apiPost("/scan", { type: "blackbox" });
    expect(captured.url).toBe("/api/scan");
    expect(captured.init?.method).toBe("POST");
    expect((captured.init?.headers as Record<string, string>)["Content-Type"]).toBe("application/json");
    expect(captured.init?.body).toBe(JSON.stringify({ type: "blackbox" }));
  });

  it("linkReposInDir POST /workspaces/<ws>/repos/link-dir 带 path", async () => {
    let captured: { url?: string; init?: RequestInit } = {};
    (globalThis.fetch as any).mockImplementation((url: string, init: RequestInit) => {
      captured = { url, init };
      return Promise.resolve(res({ ok: true, status: 200, body: { imported: [], skipped: [] } }));
    });
    const r = await linkReposInDir("ws1", { path: "/app/repos/frontend" });
    expect(captured.url).toBe("/api/workspaces/ws1/repos/link-dir");
    expect(captured.init?.method).toBe("POST");
    expect(captured.init?.body).toBe(JSON.stringify({ path: "/app/repos/frontend" }));
    expect(r).toMatchObject({ imported: [], skipped: [] });
  });

  it("blackboxRunReportPath 编码各段", () => {
    expect(blackboxRunReportPath("WS", "s1", "run-1"))
      .toBe("/workspaces/WS/scans/s1/blackbox-runs/run-1/report");
    expect(blackboxRunReportPath("WS", "s1", "run-1", "combined"))
      .toBe("/workspaces/WS/scans/s1/blackbox-runs/run-1/report?track=combined");
  });

  it("blackboxRunDeliverablesPath 带/不带 file", () => {
    expect(blackboxRunDeliverablesPath("WS", "s1", "run-1"))
      .toBe("/workspaces/WS/scans/s1/blackbox-runs/run-1/deliverables");
    expect(blackboxRunDeliverablesPath("WS", "s1", "run-1", "foo.json"))
      .toBe("/workspaces/WS/scans/s1/blackbox-runs/run-1/deliverables?path=foo.json");
  });

  it("listBlackboxRuns GET run 列表", async () => {
    (globalThis.fetch as any).mockResolvedValue(
      res({ ok: true, status: 200, body: [{ run_id: "run-1" }, { run_id: "run-2" }] }));
    const runs = await listBlackboxRuns("WS", "s1");
    expect(runs.map((r: any) => r.run_id)).toEqual(["run-1", "run-2"]);
    expect((globalThis.fetch as any).mock.calls.at(-1)[0])
      .toBe("/api/workspaces/WS/scans/s1/blackbox-runs");
  });

  it("addBlackboxToWhitebox POST add-run 返 run_id", async () => {
    let captured: { url?: string; init?: RequestInit } = {};
    (globalThis.fetch as any).mockImplementation((url: string, init: RequestInit) => {
      captured = { url, init };
      return Promise.resolve(res({ ok: true, status: 202,
        body: { workspace: "WS", scan_id: "s1", run_id: "run-1" } }));
    });
    const r = await addBlackboxToWhitebox("WS", "s1", {});
    expect(r.run_id).toBe("run-1");
    expect(captured.url).toBe("/api/workspaces/WS/scans/s1/blackbox-runs");
    expect(captured.init?.method).toBe("POST");
  });
});

describe("client auth", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    document.cookie = "sn-csrf=token123; path=/";
  });

  it("sends credentials: include", async () => {
    const fm = vi.spyOn(window, "fetch").mockResolvedValue(new Response("{}", { status: 200 }));
    await apiGet("/foo");
    expect(fm.mock.calls[0][1]).toMatchObject({ credentials: "include" });
  });

  it("adds X-CSRF-Token on POST", async () => {
    const fm = vi.spyOn(window, "fetch").mockResolvedValue(new Response("{}", { status: 200 }));
    await apiPost("/foo", { a: 1 });
    const init = fm.mock.calls[0][1] as RequestInit;
    expect((init.headers as Record<string, string>)["X-CSRF-Token"]).toBe("token123");
  });

  it("401 silent does not fire handler", async () => {
    vi.spyOn(window, "fetch").mockResolvedValue(new Response("{}", { status: 401 }));
    const h = vi.fn();
    setUnauthorizedHandler(h);
    await expect(apiGet("/me", { silent: true })).rejects.toThrow();
    expect(h).not.toHaveBeenCalled();
  });

  it("401 non-silent fires handler", async () => {
    vi.spyOn(window, "fetch").mockResolvedValue(new Response("{}", { status: 401 }));
    const h = vi.fn();
    setUnauthorizedHandler(h);
    await expect(apiGet("/workspaces")).rejects.toThrow();
    expect(h).toHaveBeenCalled();
  });

  it("默认 handler 在 /login 页不重复跳转（防全局组件非 silent 401 致 login 页循环刷新）", async () => {
    // 根因：BrandProvider 在 App.tsx 最外层，未登录 /login 页也会发非 silent 401 请求
    // -> 默认 handler window.location.assign("/login?expired=1") -> 整页刷新 -> 重新
    // mount -> 又 401 -> 循环。默认 handler 在已在 /login 时不再 assign，根治循环。
    resetUnauthorizedHandler();
    const assignSpy = vi.fn();
    const origLoc = window.location;
    Object.defineProperty(window, "location", {
      value: { pathname: "/login", assign: assignSpy } as unknown as Location,
      writable: true,
      configurable: true,
    });
    vi.spyOn(window, "fetch").mockResolvedValue(new Response("{}", { status: 401 }));
    await expect(apiGet("/system-status")).rejects.toThrow();
    expect(assignSpy).not.toHaveBeenCalled();
    Object.defineProperty(window, "location", { value: origLoc, writable: true, configurable: true });
  });
});

describe("correlation topology analysis client", () => {
  it("start POST workspace path and body", async () => {
    let captured: { url?: string; init?: RequestInit } = {};
    (globalThis.fetch as any).mockImplementation((url: string, init: RequestInit) => {
      captured = { url, init };
      return Promise.resolve(res({ ok: true, status: 202, body: { analysis_id: "topology-1" } }));
    });
    const r = await startCorrelationTopologyAnalysis("WS one", {
      repos: ["gateway", "order-svc"], refresh: true,
    });
    expect(r.analysis_id).toBe("topology-1");
    expect(captured.url).toBe("/api/workspaces/WS%20one/correlation-topology/analyses");
    expect(captured.init?.body).toBe(JSON.stringify({ repos: ["gateway", "order-svc"], refresh: true }));
  });

  it("delete uses the action path while legacy DELETE remains cancel", async () => {
    (globalThis.fetch as any).mockResolvedValue(
      res({ ok: true, status: 200, body: { ok: true, analysis_id: "topology-1" } }));
    await cancelCorrelationTopologyAnalysis("WS", "topology-1");
    expect((globalThis.fetch as any).mock.calls.at(-1)).toEqual([
      "/api/workspaces/WS/correlation-topology/analyses/topology-1",
      expect.objectContaining({ method: "DELETE" }),
    ]);
    await deleteCorrelationTopologyAnalysis("WS", "topology-1");
    const last = (globalThis.fetch as any).mock.calls.at(-1);
    expect(last[0])
      .toBe("/api/workspaces/WS/correlation-topology/analyses/topology-1/delete");
    expect(last[1].method).toBe("POST");
    expect(last[1].body).toBe("{}");
  });

  it("get and cancel use the analysis path", async () => {
    (globalThis.fetch as any).mockResolvedValue(
      res({ ok: true, status: 200, body: { status: "running" } }));
    await getCorrelationTopologyAnalysis("WS", "topology-1");
    expect((globalThis.fetch as any).mock.calls.at(-1)[0])
      .toBe("/api/workspaces/WS/correlation-topology/analyses/topology-1");
    await cancelCorrelationTopologyAnalysis("WS", "topology-1");
    const last = (globalThis.fetch as any).mock.calls.at(-1);
    expect(last[0]).toBe("/api/workspaces/WS/correlation-topology/analyses/topology-1");
    expect(last[1].method).toBe("DELETE");
  });
});
