import { describe, it, expect } from "vitest";
import { render, fireEvent } from "@testing-library/react";
import { LogStream } from "./LogStream";
import type { NdjsonEvent } from "../api/types";

const events: NdjsonEvent[] = [
  { ts: "2026-07-02T09:44:01.000Z", category: "PHASE", type: "PhaseEvent", phase: "recon", event: "start", steps: [], step_intents: [] },
  { ts: "2026-07-02T09:44:05.000Z", category: "AGENT", type: "AgentEvent", agent_name: "injection-vuln", event: "start", attempt: 1 },
  { ts: "2026-07-02T09:44:10.000Z", category: "ERROR", type: "ErrorEvent", error_type: "ValueError", message: "boom", context: "recon", classified: "non-retryable" },
];

// 行选择器：CAT_CLASS 的 `.ev-*`/`.trace` 是事件色不变量，作为行的稳定 hook
const ROW_SELECTOR = ".ev-phase, .ev-agent, .ev-tool, .ev-llm, .ev-error, .ev-info, .ev-warn, .trace, .ev-agent-ok, .ev-agent-fail";

describe("LogStream", () => {
  it("容器有 aria-live=polite", () => {
    render(<LogStream events={[]} />);
    expect(document.querySelector('[aria-live="polite"]')).toBeInTheDocument();
  });

  it("逐事件渲染行 + 按 category 上色 class", () => {
    const { container } = render(<LogStream events={events} />);
    const rows = container.querySelectorAll(ROW_SELECTOR);
    expect(rows.length).toBe(3);
    expect(rows[0].className).toContain("ev-phase");
    expect(rows[1].className).toContain("ev-agent");
    expect(rows[2].className).toContain("ev-error");
  });

  it("每行含时间戳 + data-type + 摘要", () => {
    const { container } = render(<LogStream events={events} />);
    // 时间戳经 parseEventTs->fmtClock 渲染为浏览器本地时区 HH:MM:SS（值随环境时区，
    // 在 CST 为 17:44:01；转换正确性由 eventTs.test.ts fmtClock 固定时区单测保证）。
    const tsCells = container.querySelectorAll(".log-ts");
    expect(tsCells.length).toBe(3);
    expect(tsCells[0].textContent ?? "").toMatch(/^\d{2}:\d{2}:\d{2}$/);
    const rows = container.querySelectorAll(".log-row");
    expect(rows.length).toBe(3);
    // type 身份经 data-type 属性承载（显示列已换成短语义标签）
    const types = Array.from(rows).map((r) => r.getAttribute("data-type"));
    expect(types).toEqual(["PhaseEvent", "AgentEvent", "ErrorEvent"]);
  });

  // ── tsClock 必须兼容生产 ndjson 的空格分隔 ts（非仅 ISO T 分隔）──
  // 真实 events.ndjson 的 ts = "2026-07-31 10:53:53"（空格分隔，非 ISO "T"）。
  // 若正则只认 T，fallback 返回完整串塞进窄 .log-ts 列被 ellipsis 截断 → 时间不可见
  // （crAPI live 页实测：每行日期时间全被挤没）。这里精确断言列文本 == HH:MM:SS。
  it("时间戳列提取 HH:MM:SS（兼容生产空格分隔格式，非仅 ISO）", () => {
    const ev: NdjsonEvent = {
      ts: "2026-07-31 10:53:53", category: "PHASE", type: "PhaseEvent",
      phase: "recon", event: "start", steps: [], step_intents: [],
    };
    const { container } = render(<LogStream events={[ev]} />);
    const tsEl = container.querySelector(".log-ts");
    // 本地化后值随浏览器时区（CST 环境 18:53:53，非裸 UTC 10:53:53）；锁 HH:MM:SS 格式，
    // 空格分隔 ts 的解析由 parseEventTs 保证（当 UTC），转换正确性由 fmtClock 单测保证。
    expect(tsEl?.textContent ?? "").toMatch(/^\d{2}:\d{2}:\d{2}$/);
  });

  it("events > 500 切 react-window 虚拟滚动（结构断言：行仍按 category 上色）", () => {
    const big: NdjsonEvent[] = Array.from({ length: 600 }, (_, i) => ({
      ts: "2026-07-02T09:44:01.000Z", category: i % 2 === 0 ? "PHASE" : "ERROR",
      type: i % 2 === 0 ? "PhaseEvent" : "ErrorEvent",
      phase: "recon", event: "start", steps: [], step_intents: [],
      error_type: "X", message: "boom",
    } as NdjsonEvent));
    const { container } = render(<LogStream events={big} />);
    const rows = container.querySelectorAll(ROW_SELECTOR);
    expect(rows.length).toBeGreaterThan(0);
    const colored = Array.from(rows).filter((r) =>
      r.className.includes("ev-phase") || r.className.includes("ev-error"));
    expect(colored.length).toBe(rows.length);
  });

  // helper：取单行 div 的 textContent（按 class 定位，避免 getByText 命中 type span 而非整行）
  function rowText(container: HTMLElement, cls: string): string {
    const el = container.querySelector(`.${cls}`);
    if (!el) throw new Error(`missing .${cls} row`);
    return el.textContent ?? "";
  }

  // ─── 增强测试：agent 行带 prefix + attempt ───
  it("AgentEvent start 行含 agent_prefix + agent_name + attempt", () => {
    const ev: NdjsonEvent = {
      ts: "2026-07-02T10:00:00.000Z", category: "AGENT", type: "AgentEvent",
      agent_name: "xss-vuln", event: "start", attempt: 2,
    };
    const { container } = render(<LogStream events={[ev]} />);
    const txt = rowText(container, "ev-agent");
    expect(txt).toMatch(/\[XSS\]/);
    expect(txt).toMatch(/xss-vuln/);
    expect(txt).toMatch(/attempt 2/);
  });

  // ─── 增强测试：AgentEvent end success 含 duration + cost + tokens ───
  it("AgentEvent end success 行含 duration + cost", () => {
    const ev: NdjsonEvent = {
      ts: "2026-07-02T10:00:05.000Z", category: "AGENT", type: "AgentEvent",
      agent_name: "injection-vuln", event: "end", attempt: 1,
      success: true, duration_ms: 45200, cost_usd: 0.1234, cost_currency: "USD",
      input_tokens: 1200, output_tokens: 345,
    };
    const { container } = render(<LogStream events={[ev]} />);
    const txt = rowText(container, "ev-agent-ok");
    expect(txt).toMatch(/\[Injection\]/);
    expect(txt).toMatch(/Completed/);
    expect(txt).toMatch(/45\.2s/);
    expect(txt).toMatch(/\$0\.12/);  // fmtCost 四舍五入到 2 位
  });

  // ─── 增强测试：AgentEvent end fail 含 error ───
  it("AgentEvent end fail 行含 duration + error", () => {
    const ev: NdjsonEvent = {
      ts: "2026-07-02T10:00:10.000Z", category: "AGENT", type: "AgentEvent",
      agent_name: "auth-vuln", event: "end", attempt: 1,
      success: false, duration_ms: 12300, error: "timeout",
    };
    const { container } = render(<LogStream events={[ev]} />);
    const txt = rowText(container, "ev-agent-fail");
    expect(txt).toMatch(/\[Auth\]/);
    expect(txt).toMatch(/failed/);
    expect(txt).toMatch(/12\.3s/);
    expect(txt).toMatch(/timeout/);
  });

  // ─── 增强测试：Agent end success/fail 颜色 class ───
  it("AgentEvent end success 用 ev-agent-ok，fail 用 ev-agent-fail", () => {
    const ok: NdjsonEvent = {
      ts: "2026-07-02T10:01:00.000Z", category: "AGENT", type: "AgentEvent",
      agent_name: "injection-vuln", event: "end", attempt: 1, success: true,
    };
    const fail: NdjsonEvent = {
      ts: "2026-07-02T10:01:01.000Z", category: "AGENT", type: "AgentEvent",
      agent_name: "xss-vuln", event: "end", attempt: 1, success: false,
    };
    const { container } = render(<LogStream events={[ok, fail]} />);
    const rows = container.querySelectorAll(ROW_SELECTOR);
    expect(rows[0].className).toContain("ev-agent-ok");
    expect(rows[1].className).toContain("ev-agent-fail");
  });

  // ── LlmTurnEvent：body 纯内容（归属不进正文），名在 title + gutter 指纹色带 ──
  it("LlmTurnEvent 行含 turn + content snippet，归属名在 title（2026-09-03 撤 chip 前缀）", () => {
    const ev: NdjsonEvent = {
      ts: "2026-07-02T10:02:00.000Z", category: "LLM", type: "LlmTurnEvent",
      agent_name: "ssrf-vuln", turn: 3, content: "Found sink at line 42\nsecond line",
    };
    const { container } = render(<LogStream events={[ev]} />);
    const txt = rowText(container, "ev-llm");
    expect(txt).toMatch(/Turn 3/);
    expect(txt).toContain("Found sink at line 42");
    expect(txt).not.toContain("[SSRF]");  // 名字不进 body——彩色长名每行重复是文字噪音
    const title = container.querySelector(".ev-llm")?.getAttribute("title") ?? "";
    expect(title).toContain("[SSRF] ssrf-vuln");  // 渐进披露：悬停才见归属
  });

  // ── 2026-09-21 修「Turn 14: {」：vuln agent 回复多为 JSON/markdown，首行是
  // 结构标记（{ / ```json），firstNonemptyLine 信息量为零。摘要改为压平整段
  // （空白→单空格）再截断，行内直接可见实际字段内容。──
  it("LlmTurnEvent content 为 JSON 时行内压平显示实际内容，不再只有首行 {", () => {
    const ev: NdjsonEvent = {
      ts: "2026-09-21T10:02:00.000Z", category: "LLM", type: "LlmTurnEvent",
      agent_name: "injection-vuln", turn: 14,
      content: '{\n  "vulns": [\n    { "title": "SQL injection in login" }\n  ]\n}',
    };
    const { container } = render(<LogStream events={[ev]} />);
    const txt = rowText(container, "ev-llm");
    expect(txt).toMatch(/Turn 14/);
    expect(txt).toContain('"vulns"');          // 压平后字段可见
    expect(txt).toContain("SQL injection in login");
  });

  it("LlmTurnEvent 长内容：行内截断省略，title 披露截断段之后的全文", () => {
    const tail = "TAIL-SECTION-ONLY-IN-TITLE";
    const ev: NdjsonEvent = {
      ts: "2026-09-21T10:02:01.000Z", category: "LLM", type: "LlmTurnEvent",
      agent_name: "xss-vuln", turn: 15,
      content: `${"x".repeat(300)}\n${tail}`,
    };
    const { container } = render(<LogStream events={[ev]} />);
    const txt = rowText(container, "ev-llm");
    expect(txt).not.toContain(tail);           // 行内 160 截断，后段不进 body
    const title = container.querySelector(".ev-llm")?.getAttribute("title") ?? "";
    expect(title).toContain(tail);             // hover 全文（2000 上限内）
  });

  // ── GitnexusLlmEvent progress ──
  it("GitnexusLlmEvent progress 行含 phase + done/total + hits", () => {
    const ev: NdjsonEvent = {
      ts: "2026-07-02T10:03:00.000Z", category: "GITNEXUS", type: "GitnexusLlmEvent",
      phase: "sink-discovery", kind: "progress", done: 5, total: 10, hits: 3,
    } as NdjsonEvent;
    const { container } = render(<LogStream events={[ev]} />);
    const txt = rowText(container, "ev-info");  // GITNEXUS → ev-info
    expect(txt).toContain("sink-discovery");
    expect(txt).toMatch(/5\/10/);
    expect(txt).toMatch(/3/);
  });

  // ── GitnexusLlmEvent hit ──
  it("GitnexusLlmEvent hit 行含 detail", () => {
    const ev: NdjsonEvent = {
      ts: "2026-07-02T10:03:01.000Z", category: "GITNEXUS", type: "GitnexusLlmEvent",
      phase: "chain-verdict", kind: "hit", done: 0, total: 0, hits: 0,
      detail: "SQL injection in /api/users",
    } as NdjsonEvent;
    const { container } = render(<LogStream events={[ev]} />);
    const txt = rowText(container, "ev-info");
    expect(txt).toContain("SQL injection in /api/users");
  });

  // ── WorkflowHeader 行含 repo_path + target_url ──
  it("WorkflowHeader 行含 repo_path + target_url", () => {
    const ev: NdjsonEvent = {
      ts: "2026-07-02T10:00:00.000Z", category: "HEADER", type: "WorkflowHeader",
      workflow_id: "wf-1", target_url: "https://example.com", repo_path: "/tmp/repo",
      mode: "offline", web_ui_url: "", logs_cmd: "", workspace: "ws1",
    } as NdjsonEvent;
    const { container } = render(<LogStream events={[ev]} />);
    const txt = rowText(container, "trace");  // HEADER → trace
    expect(txt).toContain("/tmp/repo");
    expect(txt).toContain("https://example.com");
  });

  // ── ToolCallEvent：body 纯内容，归属=title 披露 + gutter 指纹色带 ──
  it("ToolCallEvent 行含 tool_name + params，归属名在 title、gutter 带指纹色", () => {
    const ev: NdjsonEvent = {
      ts: "2026-07-02T10:04:00.000Z", category: "TOOL", type: "ToolCallEvent",
      agent_name: "injection-vuln", tool_name: "Bash",
      parameters: { command: "grep -r eval src/" },
    };
    const { container } = render(<LogStream events={[ev]} />);
    const txt = rowText(container, "ev-tool");
    expect(txt).toContain("Bash");
    expect(txt).not.toContain("[Injection]");
    const title = container.querySelector(".ev-tool")?.getAttribute("title") ?? "";
    expect(title).toContain("[Injection] injection-vuln");
    // gutter = 归属指纹色带（ag-N class），agent 行专属（系统行 gutter 无 ag class）
    const gutter = container.querySelector(".ev-tool .log-gutter");
    expect(gutter?.className).toMatch(/^log-gutter ag-\d{1,2}$/);
  });

  // ─── agent 归属 = 左缘指纹色带（2026-09-03 二次返工：撤 ●chip 文字前缀 + hover 聚焦）───
  // 归属呈现三层：①gutter 色带（同 agent 全行同色带，并发交错=色带交错）；
  // ②AGENT start/end 行 body 带全名作图例锚点；③TOOL/LLM 行 title 渐进披露。
  // 撤因：彩色长名（chain-verdict-xss-40 等）每行重复是文字噪音、一行三色打架；
  // hover kin/dim 划过全屏闪烁（用户实测「好奇怪、还没之前的好看、hover 不要高亮」）。
  it("ToolCallEvent 未知 agent：body 无 [Agent] 占位无名字，title 含全名，gutter 带指纹色", () => {
    const ev: NdjsonEvent = {
      ts: "2026-09-02T09:47:48.000Z", category: "TOOL", type: "ToolCallEvent",
      agent_name: "chain-verdict-xss-40", tool_name: "bash",
      parameters: { command: "cd /app/workspaces/evangan/repos/NodeGoat" },
    };
    const { container } = render(<LogStream events={[ev]} />);
    const txt = rowText(container, "ev-tool");
    expect(txt).toContain("bash");
    expect(txt).not.toMatch(/\[Agent\]/);
    expect(txt).not.toContain("chain-verdict-xss-40");  // 名字只在 title——零行内文字重复
    const title = container.querySelector(".ev-tool")?.getAttribute("title") ?? "";
    expect(title).toContain("chain-verdict-xss-40");
    const gutter = container.querySelector(".ev-tool .log-gutter");
    expect(gutter?.className).toMatch(/^log-gutter ag-\d{1,2}$/);
  });

  it("LlmTurnEvent 未知 agent：title 含全名，gutter 带指纹色", () => {
    const ev: NdjsonEvent = {
      ts: "2026-09-02T09:47:52.000Z", category: "LLM", type: "LlmTurnEvent",
      agent_name: "chain-verdict-xss-43", turn: 5,
      content: "The sink is at 214:27 per the chain.",
    };
    const { container } = render(<LogStream events={[ev]} />);
    const txt = rowText(container, "ev-llm");
    expect(txt).toMatch(/Turn 5/);
    expect(txt).not.toContain("chain-verdict-xss-43");
    const title = container.querySelector(".ev-llm")?.getAttribute("title") ?? "";
    expect(title).toContain("chain-verdict-xss-43");
    expect(container.querySelector(".ev-llm .log-gutter")?.className).toMatch(/ag-\d{1,2}/);
  });

  it("表内 agent 的 TOOL/LLM 行 title 含 [Prefix] 全名（对齐 CLI agent_title）", () => {
    const evs: NdjsonEvent[] = [
      { ts: "2026-09-02T09:48:00.000Z", category: "TOOL", type: "ToolCallEvent",
        agent_name: "injection-vuln", tool_name: "Bash", parameters: { command: "ls" } },
      { ts: "2026-09-02T09:48:01.000Z", category: "LLM", type: "LlmTurnEvent",
        agent_name: "ssrf-vuln", turn: 2, content: "Checking" },
    ];
    const { container } = render(<LogStream events={evs} />);
    const toolTitle = container.querySelector(".ev-tool")?.getAttribute("title") ?? "";
    expect(toolTitle).toContain("[Injection] injection-vuln");
    const llmTitle = container.querySelector(".ev-llm")?.getAttribute("title") ?? "";
    expect(llmTitle).toContain("[SSRF] ssrf-vuln");
  });

  // ─── 无 hover 交互（2026-09-03 撤 kin/dim 聚焦与行 hover 背景）───
  // 用户实测反馈：鼠标划过行不需要高亮，hover 聚焦划过全屏闪烁「好奇怪」。
  // 行正常显示；归属追踪靠 gutter 色带 + AGENT 锚点行，agent 名悬停 title 披露。
  it("hover 行无聚焦/高亮行为（无 kin/dim class 切换、无 chip 元素）", async () => {
    const evs: NdjsonEvent[] = [
      { ts: "2026-09-02T09:47:50.000Z", category: "AGENT", type: "AgentEvent",
        agent_name: "cv-xss-1", event: "start", attempt: 1 },
      { ts: "2026-09-02T09:47:52.000Z", category: "TOOL", type: "ToolCallEvent",
        agent_name: "cv-xss-1", tool_name: "bash", parameters: { command: "ls" } },
      { ts: "2026-09-02T09:47:53.000Z", category: "INFO", type: "LogEvent",
        logger_name: "mod", level: "INFO", message: "system ctx" } as NdjsonEvent,
    ];
    const { container } = render(<LogStream events={evs} />);
    const rows = container.querySelectorAll(".log-row");
    rows.forEach((r) => expect(r.className).not.toContain("log-row--"));
    await fireEvent.mouseEnter(rows[0]);   // 划过 AGENT 行——渲染不变
    rows.forEach((r) => expect(r.className).not.toContain("log-row--"));
    expect(container.querySelector(".log-chip")).toBeNull();  // chip 元素已裁撤
  });

  it("同 agent 的 AGENT/TOOL/LLM 行 gutter 色带同色，不同 agent 不同色，GITNX/LOG 行无指纹色", () => {
    const evs: NdjsonEvent[] = [
      { ts: "2026-09-02T09:47:50.000Z", category: "AGENT", type: "AgentEvent",
        agent_name: "chain-verdict-xss-43", event: "start", attempt: 1 },
      { ts: "2026-09-02T09:47:51.000Z", category: "TOOL", type: "ToolCallEvent",
        agent_name: "chain-verdict-xss-43", tool_name: "grep",
        parameters: { pattern: "eval" } },
      { ts: "2026-09-02T09:47:52.000Z", category: "LLM", type: "LlmTurnEvent",
        agent_name: "chain-verdict-xss-43", turn: 2, content: "Verifying chain." },
      { ts: "2026-09-02T09:47:50.500Z", category: "AGENT", type: "AgentEvent",
        agent_name: "chain-verdict-inj-07", event: "start", attempt: 1 },
      { ts: "2026-09-02T09:47:53.000Z", category: "TOOL", type: "ToolCallEvent",
        agent_name: "chain-verdict-inj-07", tool_name: "read",
        parameters: { path: "app.js" } },
      { ts: "2026-09-02T09:47:53.000Z", category: "GITNEXUS", type: "GitnexusLlmEvent",
        phase: "chain-verdict", kind: "hit", done: 0, total: 0, hits: 0,
        detail: "XSS-GN-40 vulnerable" } as NdjsonEvent,
      { ts: "2026-09-02T09:47:54.000Z", category: "INFO", type: "LogEvent",
        logger_name: "mod", level: "INFO", message: "hi" } as NdjsonEvent,
    ];
    const { container } = render(<LogStream events={evs} />);
    const gutters = container.querySelectorAll(".log-gutter");
    expect(gutters.length).toBe(7);  // 全部行都有 gutter；指纹色只在 agent 行
    const agGutters = Array.from(gutters).filter((g) => /ag-\d/.test(g.className));
    expect(agGutters.length).toBe(5);  // 两个 agent 的 AGENT/TOOL/LLM 行，GITNX/LOG 行走类型色
    const hueOf = (g: Element) => g.className.match(/ag-\d{1,2}/)?.[0] ?? "?";
    // 同 agent（首见 xss-43）三行色带同色
    expect(hueOf(agGutters[0])).toBe(hueOf(agGutters[1]));
    expect(hueOf(agGutters[1])).toBe(hueOf(agGutters[2]));
    // 不同 agent（inj-07 首见第二）不同色（首见顺序分配 ag-0/ag-1）
    expect(hueOf(agGutters[3])).not.toBe(hueOf(agGutters[0]));
    expect(hueOf(agGutters[3])).toBe(hueOf(agGutters[4]));
    // AGENT start 行 body 带全名（图例锚点——色带的「这是什么颜色」由它回答）
    const anchor = container.querySelector(".log-row[data-type='AgentEvent']");
    expect(anchor?.textContent).toContain("chain-verdict-xss-43");
  });

  // ── StepEvent done 含 duration ──
  it("StepEvent done 行含 duration", () => {
    const ev: NdjsonEvent = {
      ts: "2026-07-02T10:05:00.000Z", category: "STEP", type: "StepEvent",
      name: "code-index", phase: "pre-recon", event: "complete",
      duration_ms: 2500, intent: "Build code index",
    };
    const { container } = render(<LogStream events={[ev]} />);
    const txt = rowText(container, "ev-info");  // STEP → ev-info
    expect(txt).toContain("Build code index");
    expect(txt).toMatch(/2\.5s/);
  });

  // ── ErrorEvent 含 context + classified ──
  it("ErrorEvent 行含 context + classified", () => {
    const ev: NdjsonEvent = {
      ts: "2026-07-02T10:06:00.000Z", category: "ERROR", type: "ErrorEvent",
      error_type: "TimeoutError", message: "LLM timeout",
      context: "recon", classified: "retryable", display_retryable: true,
      attempt: 2, max_attempts: 5,
    };
    const { container } = render(<LogStream events={[ev]} />);
    const txt = rowText(container, "ev-error");
    expect(txt).toContain("TimeoutError");
    expect(txt).toContain("LLM timeout");
    expect(txt).toContain("recon");
    expect(txt).toContain("retryable");
  });

  // ── SummaryEvent 含 duration + cost + agent count ──
  it("SummaryEvent 行含 duration + cost + agent count", () => {
    const ev: NdjsonEvent = {
      ts: "2026-07-02T10:07:00.000Z", category: "SUMMARY", type: "SummaryEvent",
      status: "completed", total_duration_ms: 330000, total_cost_usd: 1.5,
      cost_currency: "USD",
      agents: [{ name: "a" }, { name: "b" }, { name: "c" }],
    } as NdjsonEvent;
    const { container } = render(<LogStream events={[ev]} />);
    const txt = rowText(container, "ev-phase");  // SUMMARY → ev-phase
    expect(txt).toContain("completed");
    expect(txt).toMatch(/5m 30s/);
    expect(txt).toMatch(/\$1\.50/);
    expect(txt).toContain("3");
  });

  // ── 自动滚底：非虚拟列表 ──
  it("新事件到达时非虚拟列表容器自动滚底（不崩溃 + ref 挂载）", () => {
    const { container, rerender } = render(<LogStream events={events} />);
    const scrollDiv = container.querySelector('[aria-live="polite"]');
    expect(scrollDiv).toBeTruthy();
    // re-render with more events → useEffect runs rAF scroll (jsdom: no-op, should not crash)
    expect(() => {
      rerender(<LogStream events={[...events, {
        ts: "2026-07-02T09:44:15.000Z", category: "INFO", type: "InfoEvent", message: "done", level: "info",
      }]} />);
    }).not.toThrow();
  });

  // ── 自动滚底：虚拟列表 scrollToItem ──
  it("events > 500 虚拟列表自动滚底", () => {
    const big: NdjsonEvent[] = Array.from({ length: 600 }, () => ({
      ts: "2026-07-02T09:44:01.000Z", category: "PHASE", type: "PhaseEvent",
      phase: "recon", event: "start", steps: [], step_intents: [],
    } as NdjsonEvent));
    // react-window FixedSizeList scrollToItem is a method on the instance.
    // jsdom renders the list DOM but we can't easily spy on the instance method.
    // Instead, verify the virtual list renders rows (existing test covers this)
    // and that no crash occurs when events grow beyond 500.
    const { container } = render(<LogStream events={big} />);
    const rows = container.querySelectorAll(ROW_SELECTOR);
    // Virtual window renders visible subset; verify it's non-empty
    expect(rows.length).toBeGreaterThan(0);
    // Re-render with +1 event — should not crash
    const bigger: NdjsonEvent[] = [...big, {
      ts: "2026-07-02T09:44:02.000Z", category: "INFO", type: "InfoEvent", message: "new", level: "info",
    } as NdjsonEvent];
    expect(() => render(<LogStream events={bigger} />)).not.toThrow();
  });

  // ── 真正未知 event type 走 default 不崩，显示 type 名 ──
  it("未知 event type 走 default 不崩，显示 type 名", () => {
    const ev = {
      ts: "2026-07-02T10:08:00.000Z", category: "INFO", type: "FutureEvent",
      foo: "bar",
    } as unknown as NdjsonEvent;
    const { container } = render(<LogStream events={[ev]} />);
    const txt = rowText(container, "ev-info");  // category=INFO → CAT_CLASS → ev-info
    expect(txt).toContain("FutureEvent");
  });

  it("LogEvent 渲染 [LEVEL] logger: msg 且按 level 着色", () => {
    const evs: NdjsonEvent[] = [
      { ts: "2026-07-16T02:00:00.000Z", category: "WARNING", type: "LogEvent", logger_name: "mod.a", level: "WARNING", message: "careful" } as NdjsonEvent,
      { ts: "2026-07-16T02:00:01.000Z", category: "ERROR", type: "LogEvent", logger_name: "mod.b", level: "ERROR", message: "boom" } as NdjsonEvent,
      { ts: "2026-07-16T02:00:02.000Z", category: "INFO", type: "LogEvent", logger_name: "mod.c", level: "INFO", message: "hi" } as NdjsonEvent,
    ];
    const { container } = render(<LogStream events={evs} />);
    // WARNING → ev-warn, ERROR → ev-error, INFO → 灰显(text-muted-foreground)
    expect(rowText(container, "ev-warn")).toMatch(/\[WARNING\]/);
    expect(rowText(container, "ev-warn")).toMatch(/mod\.a: careful/);
    expect(rowText(container, "ev-error")).toMatch(/\[ERROR\]/);
    expect(rowText(container, "ev-error")).toMatch(/mod\.b: boom/);
    // 注意：必须用 div.text-muted-foreground——LogStream.tsx 每行的时间戳/type <span>
    // 都带 text-muted-foreground class；裸 .text-muted-foreground 会命中首个 span 而非
    // INFO 行 div。INFO 行的 rowClass 返回 "text-muted-foreground"（div class），加 div
    // 限定只匹配该行 div。
    const infoRow = container.querySelector("div.text-muted-foreground");
    expect(infoRow?.textContent ?? "").toMatch(/\[INFO\]/);
    expect(infoRow?.textContent ?? "").toMatch(/mod\.c: hi/);
  });

  it("LogEvent 缺 logger_name（corr_writer.raw 编排日志）不再渲染 undefined:", () => {
    const ev: NdjsonEvent = {
      ts: "2026-09-20T07:47:14.000Z", category: "WARNING", type: "LogEvent",
      level: "WARNING",
      message: "boundary backend/asset_transfer SRPC:CashTransfer missing "
               + "reachable_from; defaulted to [] (source undetermined)",
    } as unknown as NdjsonEvent;
    const { container } = render(<LogStream events={[ev]} />);
    const txt = rowText(container, "ev-warn");
    expect(txt).toMatch(/\[WARNING\]/);
    expect(txt).toMatch(/boundary backend\/asset_transfer/);
    expect(txt).not.toContain("undefined");
  });

  // ─── correlation_progress（D6 跨仓关联主行编排事件，CONTROL → trace 色）───
  it("correlation_progress 渲染 node/name/status/detail，不再退化成裸 type 名", () => {
    const evs: NdjsonEvent[] = [
      { ts: "2026-08-24T10:00:00.000Z", category: "CONTROL", type: "correlation_progress",
        node: "repo", name: "frontend", status: "completed", detail: "reused" },
      { ts: "2026-08-24T10:00:01.000Z", category: "CONTROL", type: "correlation_progress",
        node: "edge", name: "frontend->order-svc", status: "failed", detail: "raw=low" },
    ];
    const { container } = render(<LogStream events={evs} />);
    // CONTROL → CAT_CLASS → trace（两行同色，按 data-type 区分身份后逐行断言）
    const rows = Array.from(container.querySelectorAll(".trace"));
    expect(rows).toHaveLength(2);
    expect(rows[0].textContent).toContain("repo frontend completed");
    expect(rows[0].textContent).toContain("reused");
    expect(rows[1].textContent).toContain("edge frontend->order-svc failed");
    expect(rows[1].textContent).toContain("raw=low");
  });

  // ─── gn-discovery-* agent 失败语义分层（2026-08-29 NodeGoat-20260828-162655）───
  // discovery 是 code_index activity 内部的补召回子调用：失败=跳过该 chunk 走纯规则
  // 降级（无 Temporal 重试、不阻塞主链路），与主 agent 的 activity 级 failed（整段
  // 重跑）语义差一个量级。同款红色 ✗ 呈现误导用户以为扫描出大问题——降级为
  // ⚠ + ev-warn + [GitNexus] prefix + (recall skipped)，主 agent ✗ 红保持不变。
  it("gn-discovery agent fail 降级 ⚠ warn + recall skipped；主 agent fail 保持 ✗ 红", () => {
    const evs: NdjsonEvent[] = [
      { ts: "2026-08-28T16:29:31.000Z", category: "AGENT", type: "AgentEvent",
        agent_name: "gn-discovery-source-001", event: "start", attempt: 1 },
      { ts: "2026-08-28T16:29:32.000Z", category: "AGENT", type: "AgentEvent",
        agent_name: "gn-discovery-source-001", event: "end", attempt: 1,
        success: false, duration_ms: 600, error: "Connection error." },
      { ts: "2026-08-28T16:29:29.000Z", category: "AGENT", type: "AgentEvent",
        agent_name: "pre-recon", event: "end", attempt: 1,
        success: false, duration_ms: 149474, error: "Connection error." },
    ];
    const { container } = render(<LogStream events={evs} />);
    const rows = container.querySelectorAll(".log-row");
    expect(rows.length).toBe(3);
    const [startRow, dRow, mRow] = rows;
    // start 行：gn-discovery-* 前缀 → [GitNexus]（对齐 CLI _AGENT_PREFIXES 同步约定）
    expect(startRow.textContent).toMatch(/\[GitNexus\]/);
    // discovery fail 行：⚠ + ev-warn（非 ev-agent-fail）+ (recall skipped)
    expect(dRow.className).toContain("ev-warn");
    expect(dRow.className).not.toContain("ev-agent-fail");
    expect(dRow.querySelector(".log-icon")?.textContent).toBe("⚠");
    expect(dRow.textContent).toMatch(/\[GitNexus\] gn-discovery-source-001/);
    expect(dRow.textContent).toContain("(recall skipped)");
    expect(dRow.textContent).toContain("Connection error.");
    // 主 agent fail 行保持现状：✗ + ev-agent-fail，不吃 discovery 分流。
    // chip 统一 agentTitle（2026-09-03）：未知名直接显示名字，[Agent] 占位不再出现
    // （对齐 127eb47a 对 TOOL/LLM 行的同款裁撤）。
    expect(mRow.className).toContain("ev-agent-fail");
    expect(mRow.querySelector(".log-icon")?.textContent).toBe("✗");
    expect(mRow.textContent).toContain("pre-recon");
    expect(mRow.textContent).not.toMatch(/\[Agent\]/);
    expect(mRow.textContent).not.toContain("recall skipped");
  });
});

  // ─── 子仓源归属前缀（2026-09-10 主行 live：归并流注入 service 字段）───
  it("带 service 字段的子仓事件 → 行 body 前缀 [svc]（多子仓同名 agent 可辨归属）", () => {
    const evs: NdjsonEvent[] = [
      { ts: "2026-09-10T10:00:00.000Z", category: "AGENT", type: "AgentEvent",
        agent_name: "vuln-injection", event: "start", attempt: 1,
        src: "c-gw-123", service: "gateway" },
      { ts: "2026-09-10T10:00:01.000Z", category: "AGENT", type: "AgentEvent",
        agent_name: "vuln-injection", event: "start", attempt: 1,
        src: "c-ord-456", service: "order-svc" },
      { ts: "2026-09-10T10:00:02.000Z", category: "AGENT", type: "AgentEvent",
        agent_name: "vuln-injection", event: "start", attempt: 1 },  // 主行/黑盒：无前缀
    ];
    const { container } = render(<LogStream events={evs} />);
    const rows = Array.from(container.querySelectorAll(".log-row"));
    expect(rows[0].textContent).toContain("[gateway]");
    expect(rows[1].textContent).toContain("[order-svc]");
    expect(rows[2].textContent).not.toContain("[");
  });
