import { memo, useEffect, useMemo, useRef, useState } from "react";
import type { CSSProperties } from "react";
import { useParams, useOutletContext } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { FixedSizeList } from "react-window";
import { apiGet, scanLogsPath, blackboxRunLogsPath } from "../../api/client";
import { ErrorState } from "../../components/ErrorState";
import { Empty } from "../../components/Empty";
import { Skeleton } from "../../components/ui/skeleton";
import { LogStream } from "../../components/LogStream";
import type { NdjsonEvent } from "../../api/types";
import { humanizeToolCall, summarizeTurnContent } from "../../state/formatters";
import { parseEventTs, fmtClock, fmtLocalFull } from "../../utils/eventTs";

// 按行数（而非字符数）判阈值：spec/log-prose 谈论的是行计数，大日志=多行。
// 5000 行覆盖典型 workflow.log / activity_failures.log（数百~数千行），同时避免
// 给中量日志误开虚拟化（旧 100k 字符阈值会因长行提前触发）。
const VIRTUAL_LINE_THRESHOLD = 5000;
const ROW_HEIGHT = 20;

// 两种 JSON 行格式共用同一渲染分支：
// - events.ndjson 风格 {ts, type, message|tool_name}；
// - agent .log（agent_logger.log_event，agents/*.log 每行）{type, timestamp, data}——
//   内容在 data 里。旧实现只读前者字段，agent 日志全部渲染成 "[] llm_response"
//   空壳（2026-08-28 「chain-verdict 日志什么记录都没有」事故）。
type LogEv = {
  ts?: string;
  timestamp?: string;
  type?: string;
  message?: string;
  tool_name?: string;
  data?: unknown;
};

// 单行结构化描述（对齐 live 页 LogStream describe 的 icon/tag/类型色语言）：
// agent .log 五事件类型 + events 风格 message/tool_name 兜底 + 未知形态 JSON。
// 2026-09-03 重做：旧版「[完整datetime] type + 原始JSON参数/2000字符result」三段
// 拼接 + 满屏 cyan 底块 = 用户实测「乱」——改 log-row 网格（HH:MM:SS|图标|TAG|body），
// tool 参数走 humanizeToolCall 人化、snippet 收紧 160（完整内容行 title 披露）。
type AgentRow = { icon: string; tag: string; cls: string; body: string; metrics?: string; full?: string };

const SNIPPET_LIMIT = 160;

function snippet(s: unknown, limit: number = SNIPPET_LIMIT): string {
  if (typeof s !== "string") return "";
  const flat = s.replace(/\s+/g, " ").trim();
  return flat.length > limit ? flat.slice(0, limit) + " …" : flat;
}

function safeJson(v: unknown): string {
  try {
    return JSON.stringify(v) ?? "";
  } catch {
    return String(v);
  }
}

function fmtDur(ms: number): string {
  return ms < 1000 ? `${ms}ms` : `${(ms / 1000).toFixed(1)}s`;
}

function describeAgentEvent(ev: LogEv): AgentRow {
  const d = (ev.data && typeof ev.data === "object" ? ev.data : {}) as Record<string, unknown>;
  switch (ev.type) {
    case "agent_start":
      return { icon: "▶", tag: "AGENT", cls: "ev-agent",
        body: `${String(d.agentName ?? "")} — started (attempt ${String(d.attemptNumber ?? "?")})` };
    case "agent_end": {
      const failed = d.success === false;
      const ms = typeof d.duration_ms === "number" ? d.duration_ms : null;
      return { icon: failed ? "✗" : "✓", tag: "AGENT", cls: failed ? "ev-agent-fail" : "ev-agent-ok",
        body: failed ? "failed" : "Completed", metrics: ms != null ? fmtDur(ms) : undefined };
    }
    case "llm_response": {
      // 压平整段再截断（2026-09-21 修「Turn N: {」，对齐 live 页 LogStream）：
      // JSON/markdown 回复首行是结构标记（{ / ```json），firstNonemptyLine
      // 信息量为零；full 进行 title 披露 2000 字符全文。
      const raw = typeof d.content === "string" ? d.content : "";
      const turn = String(d.turn ?? "?");
      const full = raw ? summarizeTurnContent(raw, 2000) : "";
      return { icon: "›", tag: "LLM", cls: "ev-llm",
        body: `Turn ${turn}${raw ? `: ${summarizeTurnContent(raw)}` : ""}`,
        full: full ? `Turn ${turn}: ${full}` : undefined };
    }
    case "tool_start": {
      const toolName = String(d.toolName ?? "tool");
      const params = humanizeToolCall(toolName, d.parameters ?? {});
      return { icon: "↳", tag: "TOOL", cls: "ev-tool",
        body: `${toolName}${params ? `: ${params}` : ""}` };
    }
    case "tool_end":
      return { icon: "⇢", tag: "RESULT", cls: "text-muted-foreground", body: `→ ${snippet(d.result)}` };
    default:
      // events 风格行（recon.log 等：message/tool_name 直读）+ 未知形态兜底 JSON（不丢记录）
      if (ev.message) return { icon: "·", tag: "LOG", cls: "ev-info", body: snippet(ev.message) };
      if (ev.tool_name) return { icon: "↳", tag: "TOOL", cls: "ev-tool", body: ev.tool_name };
      return { icon: "·", tag: (ev.type ?? "LOG").toUpperCase(), cls: "text-muted-foreground",
        body: snippet(safeJson(ev.data ?? ev)) };
  }
}

// ev.ts -> browser-local full datetime. Raw ts is worker-UTC (or "t1" placeholder
// in tests); parseEventTs -> epoch -> fmtLocalFull. NaN (placeholder/non-date) falls
// back to the raw string so log rows never show "Invalid Date".
function fmtEvTs(ts?: string): string {
  if (!ts) return "";
  const ms = parseEventTs(ts);
  return Number.isNaN(ms) ? ts : fmtLocalFull(ms);
}

// JSON 行 → log-row 网格（与 live 页 LogStream 同 CSS class：3px 色带|HH:MM:SS|图标|
// TAG|body|metrics）；非 JSON（agent .log 头部 banner / 坏行）→ muted 原文本。
// 完整时间戳与完整 body 经行 title 渐进披露（窄列 ellipsis 不丢信息）。
function renderLine(l: string, key: number) {
  let ev: LogEv | null = null;
  try { ev = JSON.parse(l); } catch { /* 非 JSON，按原文本渲染 */ }
  if (!ev || typeof ev !== "object") {
    return <div key={key} className="text-sm text-muted-foreground">{l}</div>;
  }
  const row = describeAgentEvent(ev);
  const ts = ev.ts ?? ev.timestamp ?? "";
  const ms = parseEventTs(ts);
  // title 正文优先 full（llm_response 压平 2000 字符全文 > 截断 body），与 live 页同语义。
  const title = [fmtEvTs(ts), ev.type, row.full ?? row.body].filter(Boolean).join("  ");
  return (
    <div key={key} className={`log-row ${row.cls}`} data-type={ev.type} title={title}>
      <span className="log-gutter" aria-hidden />
      <span className="log-ts">{Number.isNaN(ms) ? ts : fmtClock(ms)}</span>
      <span className="log-icon" aria-hidden>{row.icon}</span>
      <span className="log-tag">{row.tag}</span>
      <span className="log-body">{row.body}</span>
      <span className="log-metrics">{row.metrics ?? ""}</span>
    </div>
  );
}

// Row 提到模块作用域 + memo：避免每次父组件渲染时重新定义 Row，导致 FixedSizeList
// 重新渲染所有可见行（react-window 用 children 引用相等性判断是否复用行）。
const Row = memo(function Row({ index, style, data }: {
  index: number;
  style: CSSProperties;
  data: string[];
}) {
  return <div style={style}>{renderLine(data[index], index)}</div>;
});

// react-window 包装：行高 20px，对齐 Task 8 LogStream 同模式（FixedSizeList + itemData）。
// 容器高度由外层 ResizeObserver 测量后传入（自适应替代旧固定 500）。
function VirtualLines({ lines, height }: { lines: string[]; height: number }) {
  return (
    <FixedSizeList height={height} width="100%" itemCount={lines.length} itemSize={ROW_HEIGHT} itemData={lines}>
      {Row}
    </FixedSizeList>
  );
}

export function LogsTab() {
  const { t } = useTranslation();
  const { workspace, scanId } = useParams<{ workspace: string; scanId: string }>();
  // 版本化黑盒 run（模式对齐 DeliverablesTab）：ScanDetail 经 Outlet context 下发
  // 选中 run；组合任务黑盒侧走 run 级端点，白盒侧维持 scan 级。无 context（非组合
  // 任务/单挂路由）→ selectedRun=null 不渲染切换器，行为与旧版一致。
  const outletCtx = useOutletContext<{ selectedRun?: string | null; combined?: boolean | null }>();
  const selectedRun = outletCtx?.selectedRun ?? null;
  const showToggle = outletCtx?.combined === true && !!selectedRun;
  const [track, setTrack] = useState<"whitebox" | "blackbox">("whitebox");
  // 黑盒侧当前生效 track（切换器隐藏时视为白盒，防 context 瞬时空导致请求打空 run）
  const effTrack = showToggle && track === "blackbox" ? "blackbox" : "whitebox";
  const [files, setFiles] = useState<string[]>([]);
  const [filesErr, setFilesErr] = useState<string | null>(null);
  const [filesLoading, setFilesLoading] = useState(true);
  const [sel, setSel] = useState<string | null>(null);
  const [content, setContent] = useState("");
  const [contentErr, setContentErr] = useState<string | null>(null);

  // 容器实测像素高度 → 喂给 FixedSizeList.height。jsdom 无 ResizeObserver，
  // typeof 守卫 + 初始值 400 兜底（fallback 保证虚拟滚动测试不崩）。
  const viewportRef = useRef<HTMLDivElement>(null);
  const [viewportH, setViewportH] = useState(400);
  useEffect(() => {
    if (typeof ResizeObserver === "undefined" || !viewportRef.current) return;
    const ro = new ResizeObserver((entries) => {
      for (const e of entries) setViewportH(Math.max(120, Math.floor(e.contentRect.height)));
    });
    ro.observe(viewportRef.current);
    return () => ro.disconnect();
  }, []);

  // 当前轨的日志端点（无 file=列表，带 file=内容），两个 effect 共用。
  const logsPath = (file?: string) =>
    effTrack === "blackbox" && selectedRun
      ? blackboxRunLogsPath(workspace!, scanId!, selectedRun, file)
      : scanLogsPath(workspace!, scanId!, file);

  useEffect(() => {
    if (!workspace || !scanId) return;
    setFilesLoading(true);
    setFilesErr(null);
    apiGet<{ files: string[] }>(logsPath())
      .then((r) => setFiles(r.files))
      .catch((e: unknown) => setFilesErr(e instanceof Error ? e.message : t("workspaceDetail.logs.listLoadError")))
      .finally(() => setFilesLoading(false));
  }, [workspace, scanId, effTrack, selectedRun]);

  useEffect(() => {
    if (!sel || !workspace || !scanId) return;
    setContent("");
    setContentErr(null);
    apiGet<{ content: string }>(logsPath(sel))
      .then((r) => setContent(r.content ?? ""))
      .catch((e: unknown) => setContentErr(e instanceof Error ? e.message : t("workspaceDetail.logs.contentLoadError")));
  }, [workspace, scanId, sel, effTrack, selectedRun]);

  // 换轨/换 run 时旧选中文件不在新列表（run 级文件名含 run 前缀），统一清空回选择提示。
  useEffect(() => { setSel(null); }, [effTrack, selectedRun]);

  // 渲染门三分支：.ndjson（events.ndjson/authcheck-events.ndjson 主事件流——行结构
  // 与 live SSE 同构，直接喂 LogStream，与 live 页同视觉：网格/类型色/agent 色带/
  // AGENT 锚点/自带虚拟化）；agents/*.log（{type,timestamp,data} JSON 行 + 头部
  // banner，走 renderLine 网格）；workflow.log 与 activity_failures.log 是人读文本，
  // 走 pre 原样。
  const isNdjson = !!sel?.endsWith(".ndjson");
  const isAgentLog = !!sel?.endsWith(".log")
    && !sel.endsWith("workflow.log") && !sel.endsWith("activity_failures.log");
  const lines = useMemo(
    () => (isNdjson || isAgentLog ? content.split(/\r?\n/).filter(Boolean) : []),
    [content, isNdjson, isAgentLog],
  );
  const ndjsonEvents = useMemo(() => {
    if (!isNdjson) return [] as NdjsonEvent[];
    // 坏行（非 JSON / 缺 ts+type 骨架）丢弃——LogStream 只吃结构化事件；文件级
    // 完整性由原始文件兜底。
    return lines.flatMap((l) => {
      try {
        const e = JSON.parse(l) as Record<string, unknown>;
        return typeof e?.type === "string" && typeof e?.ts === "string" ? [e as unknown as NdjsonEvent] : [];
      } catch { return []; }
    });
  }, [isNdjson, lines]);
  const big = lines.length > VIRTUAL_LINE_THRESHOLD;

  // 布局：grid h-full 吃 ScanDetail 的 flex-1 tab 容器（live/logs 走 flex 链），grid-rows-1 让单行撑满，
  // 两栏 h-full min-h-0 + overflow 各自内滚。不再用 max-h 固定算式（旧版窄屏 header 换行/矮视口下溢出）。
  return (
    <div className="grid h-full grid-cols-[240px_1fr] grid-rows-1 gap-4">
      <div className="h-full min-h-0 overflow-y-auto border-r border-border pr-2">
        {showToggle && (
          <div className="mb-2 flex gap-1" data-testid="log-track-toggle">
            {(["whitebox", "blackbox"] as const).map((tk) => (
              <button
                key={tk}
                type="button"
                aria-pressed={effTrack === tk}
                className={`flex-1 rounded-md px-2 py-1 text-xs font-medium hover:bg-accent ${effTrack === tk ? "bg-accent text-primary" : "text-muted-foreground"}`}
                onClick={() => setTrack(tk)}
              >
                {tk === "whitebox"
                  ? t("workspaceDetail.logs.trackWhitebox")
                  : t("workspaceDetail.logs.trackBlackbox", { runId: selectedRun })}
              </button>
            ))}
          </div>
        )}
        {filesLoading && <Skeleton className="h-4 w-full" />}
        {filesErr && <ErrorState message={filesErr} />}
        {!filesLoading && !filesErr && files.length === 0 && (
          <Empty icon="∅" title={t("workspaceDetail.logs.emptyTitle")} hint={t("workspaceDetail.logs.emptyHint")} />
        )}
        {files.map((f) => (
          <button
            key={f}
            type="button"
            aria-current={sel === f ? "true" : undefined}
            className={`block w-full text-left rounded-md px-2 py-0.5 font-mono text-xs hover:bg-accent ${sel === f ? "bg-accent text-primary" : "text-foreground"}`}
            onClick={() => setSel(f)}
          >
            {f}
          </button>
        ))}
      </div>
      {/* ndjson 分支右栏切 flex（LogStream fill 需要 flex 父级）；其余分支维持滚动容器 */}
      <div
        ref={viewportRef}
        className={`h-full min-h-0 ${isNdjson && sel && !contentErr ? "flex flex-col overflow-hidden" : "overflow-auto"}`}
      >
        {!sel && <div className="text-sm text-muted-foreground">{t("workspaceDetail.logs.selectHint")}</div>}
        {sel && contentErr && <ErrorState message={contentErr} />}
        {sel && !contentErr && isNdjson && <LogStream events={ndjsonEvents} fill />}
        {sel && !contentErr && !isNdjson && isAgentLog && big ? (
          <>
            <div className="text-sm text-muted-foreground">{t("workspaceDetail.logs.bigFileHint", { count: lines.length })}</div>
            <VirtualLines lines={lines} height={viewportH} />
          </>
        ) : sel && !contentErr && !isNdjson && isAgentLog ? (
          lines.map((l, i) => renderLine(l, i))
        ) : (
          sel && !contentErr && !isNdjson && !isAgentLog && <pre className="whitespace-pre-wrap break-words font-mono text-xs leading-relaxed">{content}</pre>
        )}
      </div>
    </div>
  );
}
