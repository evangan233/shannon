// 1:1 移植 packages/core/src/supernova_core/display/formatters.py
// first_nonempty_line + humanize_tool_call + 依赖（default_tool_params / summarize_todo /
// maybe_browser_action）。reducer 对齐测试锁定行为，以 formatters.py 为准。

/** 返回第一个非空 stripped 行，无则 ""。对齐 formatters.py:167 first_nonempty_line。 */
export function firstNonemptyLine(text: string | null | undefined): string {
  for (const line of (text ?? "").split(/\r?\n/)) {
    const stripped = line.trim();
    if (stripped) return stripped;
  }
  return "";
}

/** LLM turn 单行摘要：压平整段（空白→单空格）再截断。web 专属增强（非 py 对齐，
 *  CLI 终端单行无需此道）。修「Turn 14: {」（2026-09-21）：vuln agent 回复多为
 *  JSON / markdown 代码块，firstNonemptyLine 取到的首行是结构标记（{ / ```json），
 *  信息量为零；压平整段后实际字段内容（"vulns": [ { "title": ...）直接可见。
 *  调用方配 title 渐进披露更长全文（建议 limit 2000，防原生 tooltip 过长卡顿）。 */
export function summarizeTurnContent(text: string | null | undefined, limit = 160): string {
  const flat = (text ?? "").replace(/\s+/g, " ").trim();
  return flat.length > limit ? flat.slice(0, limit) + " …" : flat;
}

// 对齐 formatters.py:103 default_tool_params —— tool_name -> 关键参数名映射 + 截断。
const TOOL_KEY_MAP: Record<string, string> = {
  Bash: "command",
  Read: "file_path",
  Write: "file_path",
  Edit: "file_path",
  Grep: "pattern",
  Glob: "pattern",
};

function defaultToolParams(toolName: string, params: Record<string, unknown>): string {
  const key = TOOL_KEY_MAP[toolName];
  if (key && key in params) {
    let val = String(params[key]);
    if (val.length > 80) val = val.slice(0, 77) + "...";
    return `${key}=${val}`;
  }
  const items = Object.entries(params).slice(0, 2);
  const parts = items.map(([k, v]) => `${k}=${String(v).slice(0, 40)}`);
  let result = parts.join(", ");
  if (Object.keys(params).length > 2) result += ", ...";
  return result;
}

// 对齐 formatters.py:70 summarize_todo —— 取最新 completed (✅) 或首条 in_progress (🔄)。
function summarizeTodo(params: Record<string, unknown>): string | null {
  const todos = params["todos"];
  if (!Array.isArray(todos)) return null;
  const completed = todos.filter((t) => t?.status === "completed");
  if (completed.length > 0) {
    return `✅ ${String(completed[completed.length - 1]?.content ?? "")}`;
  }
  const inProgress = todos.filter((t) => t?.status === "in_progress");
  if (inProgress.length > 0) {
    return `🔄 ${String(inProgress[0]?.content ?? "")}`;
  }
  return null;
}

// 对齐 formatters.py:127 maybe_browser_action —— 解析 playwright-cli / agent-browser 命令。
function parseDomain(url: string): string {
  try {
    const host = new URL(url).hostname;
    return host || url.slice(0, 30);
  } catch {
    return url.slice(0, 30);
  }
}

function maybeBrowserAction(params: Record<string, unknown>): string | null {
  const command = typeof params["command"] === "string" ? params["command"] : "";

  // agent-browser: `agent-browser --session <id> <sub> [args]`
  const ab = command.match(/^agent-browser\s+(?:--session\s+\S+\s+)?(\S+)(?:\s+(.*))?$/);
  // playwright-cli: `playwright-cli -s=<id> <sub> [args]`
  const pw = command.match(/^playwright-cli\s+(?:-s=\S+\s+)?(\S+)(?:\s+(.*))?$/);

  const match = ab || pw;
  if (!match) return null;
  const subcommand = match[1];
  const args = (match[2] ?? "").trim();

  if (subcommand === "open" || subcommand === "goto" || subcommand === "navigate") {
    return args ? `🌐 Navigating to ${parseDomain(args)}` : "🌐 Opening browser";
  }
  if (subcommand === "click" || subcommand === "dblclick") {
    return `🖱️ Clicking ${(args || "element").slice(0, 25)}`;
  }
  if (subcommand === "type" || subcommand === "fill") {
    return `⌨️ Typing ${(args || "text").slice(0, 20)}`;
  }
  if (subcommand === "snapshot") return "📸 Taking page snapshot";
  if (subcommand === "screenshot") return "📸 Taking screenshot";
  if (subcommand === "reload") return "🔄 Reloading page";
  return `🌐 Browser: ${subcommand}`;
}

/** 把原始 tool call 转成人读单行。对齐 formatters.py:180 humanize_tool_call。 */
export function humanizeToolCall(toolName: string, params: unknown): string {
  const p = params && typeof params === "object" ? (params as Record<string, unknown>) : {};
  switch (toolName) {
    case "Task":
      return `🚀 Launching ${String(p["description"] ?? "analysis agent")}`;
    case "TodoWrite":
      return summarizeTodo(p) ?? "TodoWrite";
    case "Bash":
      return maybeBrowserAction(p) ?? defaultToolParams(toolName, p);
    default:
      return defaultToolParams(toolName, p);
  }
}
