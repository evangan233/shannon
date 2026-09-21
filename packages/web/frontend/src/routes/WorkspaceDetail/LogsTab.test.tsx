import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import type { ReactNode } from "react";
import { MemoryRouter, Route, Routes, Outlet } from "react-router-dom";
import { setupServer } from "msw/node";
import { http, HttpResponse } from "msw";
import i18n from "@/i18n";
import { LogsTab } from "./LogsTab";

// LogsTab 用 apiGet<{content:string}> 取文件（JSON 解析），故 ?file= 响应须返 {content}。

const server = setupServer();

beforeAll(() => server.listen({ onUnhandledRequest: "bypass" }));
// jsdom navigator.language 默认 en，LanguageDetector 会把 i18n 切到 en；现有断言依赖中文渲染，逐测试钉回 zh。
beforeEach(() => i18n.changeLanguage("zh"));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/p/:workspace/scans/:scanId/logs" element={<LogsTab />} />
      </Routes>
    </MemoryRouter>,
  );
}

/** 生成 N 行极短文本（确保按行数而非字符数跨阈值）。
 * 每行约 8 字符（"line-NNN"），6000 行总字符数 ~52k，
 * 远低于旧 CHAR 阈值 100k → 旧实现不会虚拟化，新（行）实现会。 */
function makeShortLines(n: number): string {
  const lines: string[] = [];
  for (let i = 0; i < n; i++) lines.push(`line-${i}`);
  return lines.join("\n");
}

describe("LogsTab", () => {
  it("日志文件列表渲染 + 点击 .log 文件加载内容", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId/logs", ({ request }) => {
        const url = new URL(request.url);
        if (url.searchParams.has("file")) {
          return HttpResponse.json({ content: JSON.stringify({ ts: "t1", type: "AgentEvent", message: "hello" }) });
        }
        return HttpResponse.json({ files: ["workflow.log", "recon.log"] });
      }),
    );
    renderAt("/p/ws/scans/scan1/logs");
    await waitFor(() => expect(screen.getByText("recon.log")).toBeInTheDocument());
    fireEvent.click(screen.getByText("recon.log"));
    await waitFor(() => expect(screen.getByText(/hello/)).toBeInTheDocument());
  });

  it("日志行 ts 渲染为本地时区（真实 UTC ts 不显 Invalid Date）", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId/logs", ({ request }) => {
        const url = new URL(request.url);
        if (url.searchParams.has("file")) {
          return HttpResponse.json({ content: JSON.stringify({ ts: "2026-08-06T04:20:20Z", type: "AgentEvent", message: "scanning" }) });
        }
        return HttpResponse.json({ files: ["recon.log"] });
      }),
    );
    const { container } = renderAt("/p/ws/scans/scan1/logs");
    await waitFor(() => expect(screen.getByText("recon.log")).toBeInTheDocument());
    fireEvent.click(screen.getByText("recon.log"));
    await waitFor(() => expect(screen.getByText(/scanning/)).toBeInTheDocument());
    // 真实 UTC ts 经 fmtEvTs 本地化（parseEventTs->fmtLocalFull），不出现 Invalid Date
    expect(container.textContent ?? "").not.toContain("Invalid Date");
    // 含 HH:MM:SS 时分秒（值随浏览器时区，CST 环境 12:20:20，非裸 UTC 04:20:20）
    expect(container.textContent ?? "").toMatch(/\d{2}:\d{2}:\d{2}/);
  });

  it(".log 行数跨阈值 → 虚拟滚动（FixedSizeList 挂载 + 大文件提示）", async () => {
    // 6000 行短行：按行计数跨阈值（5000），按字符数远低于旧 100k 阈值。
    // 旧实现（按字符 100k）不会虚拟化 → 此测试在旧实现下 RED。
    const manyLines = makeShortLines(6000);
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId/logs", ({ request }) => {
        const url = new URL(request.url);
        if (url.searchParams.has("file")) {
          return HttpResponse.json({ content: manyLines });
        }
        return HttpResponse.json({ files: ["recon.log"] });
      }),
    );
    const { container } = renderAt("/p/ws/scans/scan1/logs");
    await waitFor(() => expect(screen.getByText("recon.log")).toBeInTheDocument());
    fireEvent.click(screen.getByText("recon.log"));
    // 虚拟滚动提示出现
    await waitFor(() => expect(screen.getByText(/虚拟滚动/)).toBeInTheDocument());
    // 结构断言：虚拟化只渲染可见窗口，远小于总行数 6000
    // 行类已 DSF 化：trace→text-sm text-muted-foreground，ev-info→border-l-2
    const renderedRows = container.querySelectorAll(".text-muted-foreground, .border-l-2");
    expect(renderedRows.length).toBeLessThan(100);
  });

  it(".log 行数未跨阈值 → 不虚拟滚动（全部行直接渲染）", async () => {
    // 100 行短行：远低于行阈值，应直接渲染全部。
    const fewLines = makeShortLines(100);
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId/logs", ({ request }) => {
        const url = new URL(request.url);
        if (url.searchParams.has("file")) {
          return HttpResponse.json({ content: fewLines });
        }
        return HttpResponse.json({ files: ["recon.log"] });
      }),
    );
    const { container } = renderAt("/p/ws/scans/scan1/logs");
    await waitFor(() => expect(screen.getByText("recon.log")).toBeInTheDocument());
    fireEvent.click(screen.getByText("recon.log"));
    await waitFor(() => expect(screen.getByText(/line-0/)).toBeInTheDocument());
    // 不虚拟滚动：无『虚拟滚动』提示
    expect(screen.queryByText(/虚拟滚动/)).not.toBeInTheDocument();
    // 全部 100 行渲染（断言非虚拟化）：非 JSON 行渲染为 text-sm text-muted-foreground（原 .trace）
    const rows = container.querySelectorAll(".text-muted-foreground, .border-l-2");
    expect(rows.length).toBe(100);
  });

  it("非 .log 文件（如 .txt）走 pre 原样渲染", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId/logs", ({ request }) => {
        const url = new URL(request.url);
        if (url.searchParams.has("file")) {
          return HttpResponse.json({ content: "plain text content" });
        }
        return HttpResponse.json({ files: ["notes.txt"] });
      }),
    );
    renderAt("/p/ws/scans/scan1/logs");
    await waitFor(() => expect(screen.getByText("notes.txt")).toBeInTheDocument());
    fireEvent.click(screen.getByText("notes.txt"));
    await waitFor(() => expect(screen.getByText(/plain text content/)).toBeInTheDocument());
  });

  it("文件列表项是 button（键盘可达）", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId/logs", ({ request }) => {
        const url = new URL(request.url);
        if (url.searchParams.has("file")) {
          return HttpResponse.json({ content: "log content" });
        }
        return HttpResponse.json({ files: ["workflow.log", "recon.log"] });
      }),
    );
    renderAt("/p/ws/scans/scan1/logs");
    await waitFor(() => expect(screen.getByText("recon.log")).toBeInTheDocument());
    // 文件名以 .log 结尾的 button 存在（键盘可达 + aria-current 可用）
    const fileButtons = screen.getAllByRole("button").filter((b) => /\.log$/.test(b.textContent ?? ""));
    expect(fileButtons.length).toBeGreaterThan(0);
    // 选中的文件 button 带 aria-current（选中态可达性）
    fireEvent.click(fileButtons[0]);
    await waitFor(() => expect(fileButtons[0]).toHaveAttribute("aria-current", "true"));
  });

  it("agent .log 格式（agent_logger {type,timestamp,data}）渲染 data 内容非空白", async () => {
    // 真实 agent .log（packages/core agent_logger.log_event）每行是
    // {type, timestamp, data}——内容在 data 里。旧实现只读 events.ndjson 风格的
    // message/tool_name → chain-verdict 等全部 agent 日志渲染成 "[] llm_response"
    // 空壳（2026-08-28 「chain-verdict 日志什么记录都没有」事故根因）。
    const lines = [
      JSON.stringify({ type: "agent_start", timestamp: "2026-08-28T05:55:21.559Z", data: { agentName: "chain-verdict-injection-01", attemptNumber: 1 } }),
      JSON.stringify({ type: "llm_response", timestamp: "2026-08-28T05:55:25.000Z", data: { turn: 3, content: "The sink is eval(req.body.preTax) at line 32" } }),
      JSON.stringify({ type: "tool_start", timestamp: "2026-08-28T05:55:22.000Z", data: { toolName: "grep", parameters: { pattern: "handleContributionsUpdate", path: "app" } } }),
      JSON.stringify({ type: "tool_end", timestamp: "2026-08-28T05:55:23.000Z", data: { result: "/app/repos/NodeGoat/app/routes/index.js:4:const ContributionsHandler" } }),
      JSON.stringify({ type: "agent_end", timestamp: "2026-08-28T05:55:36.607Z", data: { success: true, duration_ms: 15052 } }),
    ].join("\n");
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId/logs", ({ request }) => {
        const url = new URL(request.url);
        if (url.searchParams.has("file")) {
          return HttpResponse.json({ content: lines });
        }
        return HttpResponse.json({ files: ["agents/1787896521557_chain-verdict-injection-01_attempt-1.log"] });
      }),
    );
    renderAt("/p/ws/scans/scan1/logs");
    const btn = await screen.findByText(/chain-verdict-injection-01_attempt-1\.log/);
    fireEvent.click(btn);
    // 判定过程逐事件可见：llm_response 的推理文本 / tool 调用与结果 / agent 终态
    await waitFor(() => expect(screen.getByText(/The sink is eval\(req\.body\.preTax\)/)).toBeInTheDocument());
    expect(screen.getByText(/grep/)).toBeInTheDocument();
    expect(screen.getByText(/ContributionsHandler/)).toBeInTheDocument();
    // 2026-09-03 网格化：agent_end 终态对齐 live 语言（✓ Completed + metrics 时长），
    // 旧「success 15052ms」dump 串退役
    expect(screen.getByText(/Completed/)).toBeInTheDocument();
  });

  // ─── 2026-09-03 网格化渲染（对齐 live 页视觉语言）───
  // 旧版「[完整datetime] type + 原始JSON参数/2000字符result」三段拼接 + 满屏 cyan
  // 底块（.border-l-2 bg-cyan/10）= 用户实测「乱」。新版：log-row 网格（3px 色带|
  // HH:MM:SS|图标|TAG|body|metrics）+ ev-* 类型色 + humanize 参数 + title 全文披露。
  it("agent .log 渲染 log-row 网格行：TOOL 行 humanize 参数非原始 JSON，类型色/图标/tag 齐", async () => {
    const lines = [
      "========================================",
      "Agent: gn-discovery-sink-001",
      JSON.stringify({ type: "tool_start", timestamp: "2026-09-03T02:34:48.177Z", data: { toolName: "read_file", parameters: { path: "app/data/benefits-dao.js", offset: 0, limit: 50 } } }),
      JSON.stringify({ type: "llm_response", timestamp: "2026-09-03T02:35:11.334Z", data: { turn: 8, content: "Line1\nLine2 first-nonempty wins" } }),
    ].join("\n");
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId/logs", ({ request }) => {
        const url = new URL(request.url);
        if (url.searchParams.has("file")) return HttpResponse.json({ content: lines });
        return HttpResponse.json({ files: ["agents/x_gn-discovery-sink-001_attempt-1.log"] });
      }),
    );
    const { container } = renderAt("/p/ws/scans/scan1/logs");
    fireEvent.click(await screen.findByText(/gn-discovery-sink-001_attempt-1\.log/));
    await waitFor(() => expect(container.querySelectorAll(".log-row").length).toBe(2));
    // TOOL 行：humanize 后的参数（formatters 语义），非原始 JSON 串
    const toolRow = container.querySelector(".log-row.ev-tool");
    expect(toolRow?.textContent).toContain("read_file");
    // 人化 = key=value 形式（path=app/...），非原始 JSON 串
    expect(toolRow?.textContent).toContain("path=app/data/benefits-dao.js");
    expect(toolRow?.textContent).not.toContain("{\"path\":");
    // LLM 行：压平摘要（2026-09-21 修「Turn N: {」——首行非空行对 JSON/markdown
    // 回复是结构标记，信息量为零；换行折进单空格后整段可见）
    const llmRow = container.querySelector(".log-row.ev-llm");
    expect(llmRow?.textContent).toContain("Turn 8: Line1");
    expect(llmRow?.textContent).toContain("Line2");
    // banner 头（非 JSON 行）弱化为 muted 文本，不进网格
    expect(screen.getByText("Agent: gn-discovery-sink-001").className).toContain("text-muted-foreground");
    // 行 title 披露完整类型（渐进披露通道在）
    expect(toolRow?.getAttribute("title")).toContain("tool_start");
  });

  // 2026-09-21 修「Turn N: {」：llm_response 的 JSON 回复（vuln agent 终版输出常态）
  // 首行是 "{"，firstNonemptyLine 后行内只剩 "{"——压平整段后实际字段可见。
  it("llm_response content 为 JSON 时行内压平显示实际字段，非光秃首行 {", async () => {
    const lines = [
      JSON.stringify({
        type: "llm_response", timestamp: "2026-09-21T02:35:11.334Z",
        data: { turn: 4, content: '{\n  "title": "XSS in search",\n  "severity": "high"\n}' },
      }),
    ].join("\n");
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId/logs", ({ request }) => {
        const url = new URL(request.url);
        if (url.searchParams.has("file")) return HttpResponse.json({ content: lines });
        return HttpResponse.json({ files: ["agents/x_chain-verdict-injection-01_attempt-1.log"] });
      }),
    );
    const { container } = renderAt("/p/ws/scans/scan1/logs");
    fireEvent.click(await screen.findByText(/chain-verdict-injection-01_attempt-1\.log/));
    await waitFor(() => expect(container.querySelectorAll(".log-row").length).toBe(1));
    const llmRow = container.querySelector(".log-row.ev-llm");
    expect(llmRow?.textContent).toContain("Turn 4");
    expect(llmRow?.textContent).toContain('"title": "XSS in search"');
    expect(llmRow?.textContent).toContain('"severity": "high"');
  });

  it("events.ndjson 走 LogStream 渲染（与 live 页同组件同视觉，非 pre 原样文本）", async () => {
    // 后端 list_logs 已列顶层 *.ndjson（events.ndjson/authcheck-events.ndjson）。ndjson
    // 行结构与 live SSE 同构（{ts, category, type, ...}）——2026-09-03 起直接喂
    // LogStream：网格/类型色/agent 色带/AGENT 锚点/内置虚拟化与 live 页一致。
    // 数据仍是落盘静态文件（apiGet），不接 SSE——「同渲染器」≠「变实时流」。
    const line = JSON.stringify({ ts: "t1", category: "PHASE", type: "PhaseEvent", phase: "recon", event: "start", steps: [], step_intents: [] });
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId/logs", ({ request }) => {
        const url = new URL(request.url);
        if (url.searchParams.has("file")) return HttpResponse.json({ content: line });
        return HttpResponse.json({ files: ["events.ndjson"] });
      }),
    );
    const { container } = renderAt("/p/ws/scans/scan1/logs");
    fireEvent.click(await screen.findByText("events.ndjson"));
    // LogStream 渲染分支：log-row 网格行（PhaseEvent → ev-phase），非 pre 原样渲染
    await waitFor(() => expect(container.querySelectorAll(".log-row").length).toBe(1));
    expect(container.querySelector(".log-row")?.className).toContain("ev-phase");
    expect(container.querySelector("pre")).toBeNull();
  });

  it("fetch 文件列表失败渲染 ErrorState（role=alert）不永久 loading", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId/logs", () =>
        HttpResponse.json({ detail: "boom" }, { status: 500 }),
      ),
    );
    renderAt("/p/ws/scans/scan1/logs");
    await waitFor(() => expect(screen.getByRole("alert")).toBeInTheDocument());
  });
});

// ── 黑盒 run 日志（组合任务，模式对齐 DeliverablesTab 的 selectedRun）──────────
// ScanDetail 经 <Outlet context={{selectedRun, combined}}> 下发选中 run；
// LogsTab 黑盒侧走 /blackbox-runs/{run}/logs 端点（后端 scans.py run_logs 已有），
// 白盒侧维持 scan 级端点。纯白盒/无 context 任务不渲染切换器、行为零变化。
describe("LogsTab blackbox run", () => {
  // 模拟 ScanDetail 的 <Outlet context={...}>：LogsTab 经 useOutletContext 消费。
  function CtxOutlet({ ctx }: { ctx: Record<string, unknown> }) {
    return <Outlet context={ctx} />;
  }
  function renderAtCtx(ctx: Record<string, unknown>, path = "/p/ws/scans/scan1/logs") {
    return render(
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/p/:workspace/scans/:scanId" element={<CtxOutlet ctx={ctx} />}>
            <Route path="logs" element={<LogsTab />} />
          </Route>
        </Routes>
      </MemoryRouter>,
    );
  }
  function rerenderAtCtx(view: { rerender: (ui: ReactNode) => void }, ctx: Record<string, unknown>) {
    view.rerender(
      <MemoryRouter initialEntries={["/p/ws/scans/scan1/logs"]}>
        <Routes>
          <Route path="/p/:workspace/scans/:scanId" element={<CtxOutlet ctx={ctx} />}>
            <Route path="logs" element={<LogsTab />} />
          </Route>
        </Routes>
      </MemoryRouter>,
    );
  }
  const wbMock = http.get("/api/workspaces/:ws/scans/:scanId/logs", ({ request }) => {
    const url = new URL(request.url);
    if (url.searchParams.has("file")) return HttpResponse.json({ content: "wb content" });
    return HttpResponse.json({ files: ["workflow.log"] });
  });
  // run 级 mock：列表/内容按 runId 区分，供「切 run 自动重拉」断言。
  const bbMock = http.get("/api/workspaces/:ws/scans/:scanId/blackbox-runs/:runId/logs",
    ({ params, request }) => {
      const runId = params.runId as string;
      const url = new URL(request.url);
      if (url.searchParams.has("file")) return HttpResponse.json({ content: `bb ${runId} content` });
      return HttpResponse.json({ files: [`${runId}-xss-exploit.log`] });
    });

  it("组合任务渲染白盒/黑盒切换器，默认白盒仍调 scan 级端点", async () => {
    server.use(wbMock, bbMock);
    renderAtCtx({ selectedRun: "run-1", combined: true });
    expect(await screen.findByText("白盒")).toBeInTheDocument();
    expect(screen.getByText("黑盒 run-1")).toBeInTheDocument();
    // 默认白盒：列表来自 scan 级（workflow.log），黑盒 run 文件不出现
    await waitFor(() => expect(screen.getByText("workflow.log")).toBeInTheDocument());
    expect(screen.queryByText(/xss-exploit\.log/)).not.toBeInTheDocument();
  });

  it("切黑盒：列表与内容均走 blackbox-runs/{run} 端点，白盒侧选中被清空", async () => {
    server.use(wbMock, bbMock);
    renderAtCtx({ selectedRun: "run-1", combined: true });
    await screen.findByText("workflow.log");
    // 先看白盒内容（选中态）
    fireEvent.click(screen.getByText("workflow.log"));
    await waitFor(() => expect(screen.getByText(/wb content/)).toBeInTheDocument());
    // 切黑盒：列表换 run 级文件，内容区回选择提示（白盒选中不串轨）
    fireEvent.click(screen.getByText("黑盒 run-1"));
    await waitFor(() => expect(screen.getByText(/run-1-xss-exploit\.log/)).toBeInTheDocument());
    expect(screen.queryByText("workflow.log")).not.toBeInTheDocument();
    expect(screen.getByText(/选择左侧日志文件/)).toBeInTheDocument();
    // 点黑盒文件：内容走 run 级端点
    fireEvent.click(screen.getByText(/run-1-xss-exploit\.log/));
    await waitFor(() => expect(screen.getByText(/bb run-1 content/)).toBeInTheDocument());
  });

  it("黑盒侧 selectedRun 变化（run-1→run-2）自动重拉新 run 日志", async () => {
    server.use(wbMock, bbMock);
    const view = renderAtCtx({ selectedRun: "run-1", combined: true });
    fireEvent.click(await screen.findByText("黑盒 run-1"));
    await screen.findByText(/run-1-xss-exploit\.log/);
    // header run 选择器换 run（context 变化）→ 黑盒侧跟随
    rerenderAtCtx(view, { selectedRun: "run-2", combined: true });
    await waitFor(() => expect(screen.getByText(/run-2-xss-exploit\.log/)).toBeInTheDocument());
    expect(screen.queryByText(/run-1-xss-exploit\.log/)).not.toBeInTheDocument();
  });

  it("非组合任务（无 run context / combined=false）不渲染切换器，维持 scan 级", async () => {
    server.use(wbMock, bbMock);
    // 无 context（直接挂路由，同生产外仅测试可达的最小形态）
    renderAt("/p/ws/scans/scan1/logs");
    await waitFor(() => expect(screen.getByText("workflow.log")).toBeInTheDocument());
    expect(screen.queryByText("白盒")).not.toBeInTheDocument();
    // 有 context 但非组合任务（combined=false + 无 selectedRun）
    renderAtCtx({ selectedRun: null, combined: false }, "/p/ws/scans/scan2/logs");
    await waitFor(() => expect(screen.getAllByText("workflow.log").length).toBe(2));
    expect(screen.queryByText(/黑盒 run-1/)).not.toBeInTheDocument();
  });
});

describe("LogsTab i18n", () => {
  afterEach(() => i18n.changeLanguage("zh"));

  it("切英文后空态标题变英文", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId/logs", () => HttpResponse.json({ files: [] })),
    );
    renderAt("/p/ws/scans/scan1/logs");
    await screen.findByText(/暂无日志文件/);
    await i18n.changeLanguage("en");
    expect(await screen.findByText("No log files")).toBeInTheDocument();
    expect(screen.getByText(/will be generated once the scan starts/)).toBeInTheDocument();
  });

  it("切英文后『选择左侧日志文件』变英文", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId/logs", () => HttpResponse.json({ files: ["workflow.log"] })),
    );
    renderAt("/p/ws/scans/scan1/logs");
    await screen.findByText("workflow.log");
    await i18n.changeLanguage("en");
    expect(await screen.findByText("Select a log file on the left")).toBeInTheDocument();
  });

  it("日志行内容不随语言变化（数据不动）", async () => {
    const logLine = JSON.stringify({ ts: "t1", type: "AgentEvent", message: "hello" });
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId/logs", ({ request }) => {
        const url = new URL(request.url);
        if (url.searchParams.has("file")) return HttpResponse.json({ content: logLine });
        return HttpResponse.json({ files: ["recon.log"] });
      }),
    );
    renderAt("/p/ws/scans/scan1/logs");
    await waitFor(() => expect(screen.getByText("recon.log")).toBeInTheDocument());
    fireEvent.click(screen.getByText("recon.log"));
    await waitFor(() => expect(screen.getByText(/hello/)).toBeInTheDocument());
    await i18n.changeLanguage("en");
    // 日志内容仍是原始数据（不受语言切换影响）
    expect(screen.getByText(/hello/)).toBeInTheDocument();
  });
});
