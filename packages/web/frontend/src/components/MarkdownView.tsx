import { useMemo, useState, useEffect, useRef, type ReactNode, type ReactElement, type MouseEvent, type ElementType } from "react";
import { useTranslation } from "react-i18next";
import ReactMarkdown from "react-markdown";
import { HIGHLIGHT_PLUGIN } from "@/lib/hljs-langs";
import GithubSlugger from "github-slugger";
import remarkGfm from "remark-gfm";
import { visit } from "unist-util-visit";
import { toString } from "hast-util-to-string";
import { Button } from "@/components/ui/button";
import { SEV_PILL, SEV_DOT, SEV_EDGE } from "@/lib/severity-visual";
import { copyableMarkdownCodeComponents } from "@/components/markdown/CopyableMarkdownCode";
import { ChevronDown, ChevronRight, ListCollapse, List, LayoutPanelTop, LayoutGrid } from "lucide-react";
import { AttackChainSection } from "./report/AttackChainSection";
import { ThreatOverview } from "./report/ThreatOverview";
import { TypeSummaryCards } from "./report/TypeSummaryCards";
import { splitByVulnBlocks, inferSeverity, type Segment } from "@/lib/vuln-block";
import { focusAnchor, stickyHeaderOffset } from "@/utils/focusAnchor";
import { splitAttackChainSection, splitPocSection, parsePocEntries, stripCardPocLines } from "@/lib/report-sections";
import {
  computeStats,
  type ParsedTypeSummary,
  type TopRiskItem,
} from "@/lib/report-stats";
import type { ParsedVulnBlock } from "../api/types";

// 语言子集 + 高亮插件（spec §4.3）：已提到 src/lib/hljs-langs.ts 与报告主路径
// （RichText/AttackChainSection/highlight-code）共享——单一事实源，扩语言只改一处。

// 【T6 状态（spec 2026-08-26 §7.2）】报告页主路径已迁 ReportView（report_data.json
// 纯渲染，见 components/report/）；本组件只剩两个消费方：
//   (a) ReportTab 的 md 降级分支（旧 scan 无 report_data.json -> 404 回退，功能不
//       破坏优先）；
//   (b) 交付物页 / 关联页的 md 文件预览（DeliverablesTab/CorrelationTab/FileStage）。
// 其内的解析/推断/归并逻辑（extractVulnIds/parseStructure/vulnPreview/groupSegments/
// pocById 归并等）均因 (a)(b) 保留。TODO(T6b)：(a) 下线时删报告页相关解析
// （vuln-block/report-sections/report-stats 同批），(b) 只需一个轻量 md 预览。

interface Heading {
  id: string;
  text: string;
  level: 1 | 2 | 3;
}

/** TOC 条目：id 直接取自渲染后 DOM（见 makeSharedSlugPlugin），保证 href 永远命中。 */
interface TocItem {
  id: string;
  text: string;
  level: 1 | 2 | 3;
}

/**
 * 段级 slug rehype plugin：每个 prose 段（独立 ReactMarkdown 实例）用本函数生成专属
 * plugin。slugger 在 attacher 内部新建——每次组件渲染 plugin 重新 attach 时纯函数式
 * 重建，同样输入 → 同样 id，无跨渲染累积。segmentIndex 前缀（= group 在 groups 里的
 * 稳定索引）跨段保证全局唯一，避开「共享 slugger 在 React 渲染中可变状态不稳定」的
 * 陷阱：共享 slugger 会在严格模式/重渲染（如切主题）下被重复消费 → 同一标题拿到 -1
 * 后缀 → DOM id 漂移、与 TOC 错位（用户报告的「点了没反应」真根因）。
 */
function makeSegmentSlugPlugin(segmentIndex: number) {
  return function segmentSlug() {
    const slugger = new GithubSlugger();
    return (tree: any) => {
      visit(tree, "element", (node: any) => {
        if (typeof node.tagName === "string" && /^h[1-6]$/.test(node.tagName)) {
          node.properties = node.properties || {};
          node.properties.id = `s${segmentIndex}-${slugger.slug(toString(node))}`;
        }
      });
    };
  };
}

/** 从「INJ-VULN-01/02/03」这类文本提取完整 vuln ID（展开 /02 /03，复用完整 stem）。
 *  ID 口径对齐 vuln-block 的 VULN_HEADING_RE/VULN_ID_RE（`<类前缀>(-<大写中段>)+-序号`）：
 *  兼容双轨——LLM 轨 -VULN- 与 GitNexus 轨 -GN-/-GN-EXPLORE-/-GN-LOGIC-（XSS-GN-01、
 *  AUTHZ-GN-EXPLORE-01 等）。旧正则只认 -VULN-，GN 卡进不了 topRiskIds 联动。 */
export function extractVulnIds(text: string): string[] {
  const ids: string[] = [];
  const re = /\b([A-Z]+(?:-[A-Z]+)+)-(\d+)((?:\/\d+)*)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const stem = m[1];
    ids.push(`${stem}-${m[2]}`);
    if (m[3]) {
      for (const slashNum of m[3].matchAll(/\/(\d+)/g)) {
        ids.push(`${stem}-${slashNum[1]}`);
      }
    }
  }
  return ids;
}

/** 从 md 提取 headings + 执行摘要「最高风险发现」+「按类型汇总」结构。
 *  注意：TOC 不再消费这里的 headings.id（改从 DOM 读真实 id），仅 topRisks /
 *  typeSummaries / execH2 检测依赖本函数。 */
function parseStructure(md: string): {
  headings: Heading[];
  topRisks: TopRiskItem[];
  typeSummaries: ParsedTypeSummary[];
} {
  const headings: Heading[] = [];
  const slugger = new GithubSlugger();
  const topRisks: TopRiskItem[] = [];
  const typeSummaries: ParsedTypeSummary[] = [];
  const lines = md.split(/\r?\n/);
  let inExecSummary = false;
  let inNumberedList = false;
  let inTypeSummarySection = false;
  let currentType: ParsedTypeSummary | null = null;

  const flushType = () => {
    if (currentType) {
      typeSummaries.push(currentType);
      currentType = null;
    }
  };

  for (const line of lines) {
    const hm = /^(#{1,3})\s+(.+)$/.exec(line);
    if (hm) {
      const level = hm[1].length as 1 | 2 | 3;
      const text = hm[2].trim();
      const id = slugger.slug(text);
      headings.push({ id, text, level });
      // 任何标题都关闭编号列表与当前类型小节
      inNumberedList = false;
      flushType();
      inExecSummary = text.includes("执行摘要");
      if (level <= 2) {
        inTypeSummarySection = text.includes("按漏洞类型汇总");
      } else if (inTypeSummarySection) {
        currentType = { prefix: "", displayName: text, count: 0, severityRangeRaw: "" };
      }
      continue;
    }

    if (inExecSummary) {
      const nm = /^\d+\.\s+(.+)$/.exec(line.trim());
      if (nm) {
        inNumberedList = true;
        const text = nm[1].replace(/\*\*/g, "");
        const vulnIds = extractVulnIds(text);
        topRisks.push({ text, vulnIds });
      } else if (inNumberedList && line.trim() && !/^\d+\./.test(line.trim())) {
        inNumberedList = false;
      }
      continue;
    }

    if (inTypeSummarySection && currentType) {
      const t = line.trim();
      const cm = /^(?:-\s*\*\*)?(?:Count|数量)[:：]\s*\*?\*?\s*(\d+)/i.exec(t);
      if (cm) {
        currentType.count = parseInt(cm[1], 10);
        const pm = /（([A-Z]+)-(?:VULN|GN)/.exec(t);
        if (pm) currentType.prefix = pm[1];
        continue;
      }
      const sm = /^(?:-\s*\*\*)?Severity range[:：]\s*\*\*\s*(.+)$/i.exec(t);
      if (sm) {
        currentType.severityRangeRaw = sm[1].trim();
        continue;
      }
      const fm = /^(?:-\s*\*\*)?Key findings[:：]\s*\*\*\s*(.+)$/i.exec(t);
      if (fm) {
        currentType.findingsText = fm[1].trim();
        continue;
      }
    }
  }
  flushType();
  return { headings, topRisks, typeSummaries };
}

/** 拍平 ReactNode 到纯文本（用于键值检测）。 */
function flatten(node: ReactNode): string {
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(flatten).join("");
  const el = node as ReactElement<{ children?: ReactNode }>;
  if (el?.props?.children) return flatten(el.props.children);
  return "";
}

/** 检测「Notes/备注 标签开头」的块：首元素为 <strong> 且文本 = 备注标签（zh「备注」/ en「Notes」）。
 *  命中返回 {eyebrow, val}；否则 null（交还默认渲染）。冒号可半/全角、可省。 */
function notesFromChildren(children: ReactNode): { eyebrow: string; val: ReactNode[] } | null {
  const kids = Array.isArray(children) ? children : [children];
  const firstStrongIdx = kids.findIndex(
    (k) => typeof k !== "string" && (k as ReactElement)?.type === "strong",
  );
  if (firstStrongIdx === -1) return null;
  // strong 必须在块首（其前只允许空白串），避免误伤「正文中段加粗 + 备注」之类。
  if (!kids.slice(0, firstStrongIdx).every((k) => typeof k === "string" && /^\s*$/.test(k)))
    return null;
  const strongEl = kids[firstStrongIdx] as ReactElement<{ children?: ReactNode }>;
  const rawLabel = flatten(strongEl.props.children);
  if (!/^(备注|Notes)[:：]?\s*$/i.test(rawLabel.trim())) return null;
  const restKids = kids.slice(firstStrongIdx + 1);
  const val: ReactNode[] = [];
  let trimming = true;
  for (const k of restKids) {
    if (trimming && typeof k === "string" && /^\s*$/.test(k)) continue;
    if (trimming && typeof k === "string") {
      val.push(k.replace(/^\s+/, ""));
      trimming = false;
    } else {
      val.push(k);
      trimming = false;
    }
  }
  // eyebrow 用源标签去冒号（en「Notes」经 uppercase class 显成 NOTES，zh「备注」原样）。
  return { eyebrow: rawLabel.replace(/[:：]\s*$/, "").trim(), val };
}

/** 把 Notes 块降级成「注释 aside」：coral 左规 + 暖纸底 + eyebrow + 更小更柔的正文，
 *  明示「补充参考」、不与主发现争视觉权重。被 Setext 解析成标题的 notes 也走这里。 */
function renderNotesAside(props: Record<string, unknown>, eyebrow: string, val: ReactNode[]) {
  return (
    <aside
      {...props}
      data-testid="vuln-notes"
      className="mt-3 rounded-md border-l-2 border-primary/30 bg-muted/40 px-3 py-2"
    >
      <div className="mb-1 font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
        {eyebrow}
      </div>
      <div className="text-[12.5px] leading-[1.65] break-words text-foreground/70">{val}</div>
    </aside>
  );
}

/** 块级元素工厂：若块是 Notes 标签开头 → 注释 aside；否则按原 Tag 渲染（保留 id 等 props）。
 *  覆盖 <p> 与 <h1>~<h6>：独立段落 `**备注:** 文本` 走 <p>；但综合报告用 `---` 分隔漏洞条目，
 *  每类「最后一条」漏洞的 notes 行紧跟 `---`（无空行），会被 markdown 按 Setext 解析成 <h2>
 *  标题（所以原本又大又粗）。两条路都接住 → 统一降级为 aside。 */
function notesBlockFor(tag: ElementType) {
  return function NotesBlock({ children, ...props }: { children?: ReactNode; [k: string]: unknown }) {
    const r = notesFromChildren(children);
    if (r) return renderNotesAside(props, r.eyebrow, r.val);
    const Tag = tag;
    return <Tag {...props}>{children}</Tag>;
  };
}

/** 冗余的每类「已确认漏洞」h2 子标题。report-executive prompt 指示 LLM 保留
 *  REPORT_VULN_SUBHEADING（代码从不解析该占位符，LLM 逐字填成「已确认漏洞」/
 *  「Confirmed Vulnerabilities」），它紧跟 `# <类> 漏洞利用报告` h1、漏洞卡片之前，
 *  与 h1 语义重复。降级为安静的小标签（非 heading）：不再每类冒出大标题，也自动
 *  从 TOC 移除（TOC 只收 h1/h2 DOM，<p> 不入选）。用户反馈：黑盒报告每类都有
 *  「已确认漏洞」大标题冗余——「不做成标题，加粗就行」（2026-08-12）。 */
const REDUNDANT_VULN_SUBHEADING_RE = /^已确认.*漏洞$|^confirmed\s+vulnerabilities$/i;

/** h2 专用：先降级冗余的「已确认漏洞」子标题 → 小标签；再走 Notes aside；否则原样 h2。 */
function h2Block({ children, ...props }: { children?: ReactNode; [k: string]: unknown }) {
  if (REDUNDANT_VULN_SUBHEADING_RE.test(flatten(children).trim())) {
    // 不沿用 h2 的 id（slug plugin 给 h2 加的锚点）——降级为 <p> 即脱离 TOC/锚跳，
    // 避免点 TOC 跳到一个无信息的小标签。
    return (
      <p
        data-testid="vuln-subheading"
        className="mb-3 mt-4 text-xs font-semibold tracking-wide text-muted-foreground"
      >
        {children}
      </p>
    );
  }
  const r = notesFromChildren(children);
  if (r) return renderNotesAside(props, r.eyebrow, r.val);
  return <h2 {...props}>{children}</h2>;
}

/** prose 段共享的 react-markdown 组件覆写（kv-row li / inline code / 可复制 pre）。
 *  代码块复制反馈在 CopyButton 内部随 i18n 重渲染；这里无需接收 t。 */
function makeProseComponents() {
  return {
  // KV 行（冒号守卫：`- **key:** value` → kv-row；编号列表 `1. **RCE**…` 不匹配）
  li: ({ children, ...props }: { children?: ReactNode; [k: string]: unknown }) => {
    const kids = Array.isArray(children) ? children : [children];
    const firstStrongIdx = kids.findIndex(
      (k) => typeof k !== "string" && (k as ReactElement)?.type === "strong",
    );
    if (firstStrongIdx !== -1) {
      const strongEl = kids[firstStrongIdx] as ReactElement<{ children?: ReactNode }>;
      const rawKey = flatten(strongEl.props.children);
      if (!/[：:]\s*$/.test(rawKey)) {
        return <li {...props}>{children}</li>;
      }
      const keyText = rawKey.replace(/[:：]\s*$/, "").trim();
      if (keyText) {
        const restKids = kids.slice(firstStrongIdx + 1);
        const valKids: ReactNode[] = [];
        let trimming = true;
        for (const k of restKids) {
          if (trimming && typeof k === "string" && /^\s*$/.test(k)) continue;
          if (trimming && typeof k === "string") {
            valKids.push(k.replace(/^\s+/, ""));
            trimming = false;
          } else {
            valKids.push(k);
            trimming = false;
          }
        }
        return (
          // 自然句式流（非 flex 两列）：标签紧贴值，长值换行占满整行宽度。
          // 旧 flex + key shrink-0 因各行 key 长短不一，把长标签那行的值推到右边、值列参差。
          // 冒号走 kv-key 伪元素（after:content）→ 继承标签 11px/muted 色，视觉一体不再跳眼；
          // 伪元素不计入 DOM textContent，故 .kv-key 仍断言为纯字段名（无冒号）。
          // {" "} 显式空格分隔（不依赖源码换行空白，免被格式化吞掉）。
          <li {...props} data-testid="kv-row" className="min-w-0 break-words">
            <span className="kv-key font-mono text-[11px] uppercase tracking-wide text-muted-foreground after:content-[':']">{keyText}</span>
            {" "}
            <span className="kv-val break-words">{valKids}</span>
          </li>
        );
      }
    }
    return <li {...props}>{children}</li>;
  },
  // Notes 段落 / Setect 标题 → 注释 aside（见模块级 notesBlockFor 注释）。
  p: notesBlockFor("p"),
  h1: notesBlockFor("h1"),
  h2: h2Block,
  h3: notesBlockFor("h3"),
  h4: notesBlockFor("h4"),
  h5: notesBlockFor("h5"),
  h6: notesBlockFor("h6"),
  // block code / pre：全报告 Markdown 共享“语言角标 + 可复制”协议（含结构化报告
  // RichText / AttackChainSection 与 md 降级路径），避免只出现在部分代码块上。
  ...copyableMarkdownCodeComponents,
  };
}

const REMARK_PLUGINS = [remarkGfm];

/** severity 视觉单源（spec 2026-08-27 §2.4）：hue 药丸 + 填充比例 dot + 线型左缘，
 *  与结构化路径（VulnerabilityCard/StatsRow/QuickReferenceTable）共用 lib/severity-visual
 *  （import 见顶部）。只在「药丸标签 + 圆点 + 左缘」着色；卡片本体保持 bg-card +
 *  hairline + shadow-card 的 Claude 卡面（对齐 AttackChainSection，不搞 alert 式色条/底色）。 */

/** 从漏洞块派生一行可扫的「是什么」小标题：优先 Sink/Location 的 basename:行号，其次 vulnType。
 *  GitNexus 轨漏洞标题只有 ID（无描述），靠这个给出有意义的扫描线索。 */
function vulnPreview(block: ParsedVulnBlock): string {
  const f =
    block.fields.find((x) => /sink call|sink/i.test(x.key)) ||
    block.fields.find((x) => /vulnerable location|location|source|endpoint/i.test(x.key));
  const raw = f?.val?.replace(/`/g, "") ?? "";
  const bm = /([^/()\s]+\.\w{1,5})/.exec(raw);
  const base = bm?.[1];
  if (base) {
    // basename 之后的第一个 :<数字> = 源/汇行号（路径形如 file.java:method:innercall:712:36）
    const after = raw.slice((bm?.index ?? 0) + base.length);
    const line = /:(\d+)/.exec(after)?.[1];
    return line ? `${base}:${line}` : base;
  }
  if (raw) return raw.split(/\s/)[0];
  return block.vulnType || "";
}

/** 连续 vuln 段合并成一个 grid 组，prose 段单独成组。 */
type VulnGroup = { type: "prose"; md: string } | { type: "grid"; blocks: ParsedVulnBlock[] };
function groupSegments(segments: Segment[]): VulnGroup[] {
  const groups: VulnGroup[] = [];
  let vulnAccum: ParsedVulnBlock[] = [];
  for (const seg of segments) {
    if (seg.type === "vuln") {
      vulnAccum.push(seg.block);
    } else {
      if (vulnAccum.length) {
        groups.push({ type: "grid", blocks: vulnAccum });
        vulnAccum = [];
      }
      groups.push({ type: "prose", md: seg.md });
    }
  }
  if (vulnAccum.length) groups.push({ type: "grid", blocks: vulnAccum });
  return groups;
}

export function MarkdownView({ markdown }: { markdown: string }) {
  const { t } = useTranslation();
  const [heroCollapsed, setHeroCollapsed] = useState(false);
  // 默认全部展开（完整展示，不丢信息）。每张卡片可单独折叠（chevron）；粘性按钮批量「全部收起/展开」。
  const [collapsedIds, setCollapsedIds] = useState<Set<string>>(() => new Set());
  const toggleCard = (id: string) =>
    setCollapsedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  const proseComponents = useMemo(() => makeProseComponents(), []);
  const { headings, topRisks, typeSummaries } = useMemo(() => parseStructure(markdown), [markdown]);
  const execH2 = headings.find((h) => h.text.includes("执行摘要"));
  const showHero = !!execH2 && topRisks.length > 0;
  const topRiskIds = useMemo(() => {
    const s = new Set<string>();
    for (const r of topRisks) for (const id of r.vulnIds) s.add(id);
    return s;
  }, [topRisks]);
  // PoC 独立章节最先切出（后端 report endpoint 把「主报告 + --- + PoC md」拼一份；PoC 在最末）。
  // 切出后按 ID 并入对应漏洞卡片 body，不再独立成章（spec 2026-07-24 §3.1）。
  const pocSplit = useMemo(() => splitPocSection(markdown), [markdown]);
  const withoutPoc = pocSplit ? pocSplit.before : markdown;
  // 攻击链章节独立切出（架构语义：攻击链 ≠ 单点漏洞，分开渲染/计数，见 spec §2/§5）。
  // splitByVulnBlocks 只对「去掉 PoC + 攻击链章节后的 md」切单点漏洞。
  const attackChainSplit = useMemo(() => splitAttackChainSection(withoutPoc), [withoutPoc]);
  const singleVulnMd = attackChainSplit
    ? attackChainSplit.before + attackChainSplit.after
    : withoutPoc;
  const segments = useMemo(() => splitByVulnBlocks(singleVulnMd), [singleVulnMd]);
  const stats = useMemo(
    () => ({
      ...computeStats(
        segments
          .filter((s): s is Extract<Segment, { type: "vuln" }> => s.type === "vuln")
          .map((s) => s.block),
        topRiskIds,
        topRisks,
        typeSummaries,
      ),
      attackChainCount: attackChainSplit?.count ?? 0,
    }),
    [segments, topRiskIds, topRisks, typeSummaries, attackChainSplit],
  );
  const groups = useMemo(() => groupSegments(segments), [segments]);
  const hasVulns = groups.some((g) => g.type === "grid");
  const allVulnIds = useMemo(
    () => groups.flatMap((g) => (g.type === "grid" ? g.blocks.map((b) => b.id) : [])),
    [groups],
  );
  const allCollapsed = allVulnIds.length > 0 && allVulnIds.every((id) => collapsedIds.has(id));

  // PoC → 漏洞卡片映射（spec 2026-07-24 §3.1）。重复 id 取首条。
  const pocEntries = useMemo(
    () => (pocSplit ? parsePocEntries(pocSplit.pocMd) : []),
    [pocSplit],
  );
  const pocById = useMemo(() => {
    const m = new Map<string, string>();
    for (const e of pocEntries) if (!m.has(e.id)) m.set(e.id, e.md);
    return m;
  }, [pocEntries]);
  // 已并入卡片的 PoC（有对应漏洞卡片）；无对应卡片的 PoC 末尾兜底列出，不丢信息。
  const matchedPocIds = useMemo(
    () => new Set(allVulnIds.filter((id) => pocById.has(id))),
    [allVulnIds, pocById],
  );
  const orphanPocEntries = useMemo(
    () => pocEntries.filter((e) => !matchedPocIds.has(e.id)),
    [pocEntries, matchedPocIds],
  );

  // 锚点跳转（2026-08-26 精准化）：委托 focusAnchor——运行时量 ScanDetail 双层 sticky
  // 遮蔽带（TopBar 48px + 进度概览/tabs sticky 块，合计远超旧 scroll-mt-20 的 80px
  // 预留），落点让目标卡头完整露出 + coral 描边闪烁确认；不 focus 目标（避免原生
  // 锚点 outline / 焦点跳动）。保留 href 供无障碍 / 键盘 / 右键复制（spec 2026-07-24 §3.2）。
  const scrollToId = (e: MouseEvent<HTMLAnchorElement>, id: string) => {
    e.preventDefault();
    focusAnchor(id);
  };

  // 漏洞卡片「全部收起/展开」按钮：图标态（与「收起目录」并排于 TOC 顶部行，风格统一；
  // 无 TOC 时降级放 vuln-grid 上方非 sticky）。图标 + aria-label + title：200px 侧栏不溢出，
  // hover 文字提示语义，无障碍可读。两态图标：展开态 LayoutPanelTop（面板朝上）/ 收起态 LayoutGrid。
  const collapseAllCardsBtn =
    hasVulns && allVulnIds.length > 0 ? (
      <button
        type="button"
        data-testid="vuln-expand-all"
        onClick={() => setCollapsedIds(allCollapsed ? new Set() : new Set(allVulnIds))}
        aria-label={allCollapsed ? t("markdown.expandCards") : t("markdown.collapseCards")}
        title={allCollapsed ? t("markdown.expandCards") : t("markdown.collapseCards")}
        className="flex size-6 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent/50 hover:text-foreground"
      >
        {allCollapsed ? (
          <LayoutGrid className="size-3.5" aria-hidden="true" />
        ) : (
          <LayoutPanelTop className="size-3.5" aria-hidden="true" />
        )}
      </button>
    ) : null;

  // TOC：从渲染后 DOM 读真实 heading id（h1 章节为骨架 + h2 子节；vuln h3 太碎不进 TOC）。
  // 这保证每个 TOC href 都命中 DOM 真实元素，与 id 生成方式解耦——根治「点了没反应」。
  const contentRef = useRef<HTMLDivElement>(null);
  const [tocItems, setTocItems] = useState<TocItem[]>([]);
  useEffect(() => {
    const root = contentRef.current;
    if (!root) {
      setTocItems([]);
      return;
    }
    const items: TocItem[] = [];
    // 收集：h1/h2 章节标题 + 攻击链章节 + 单漏洞卡 / 攻击链条目（按 DOM 顺序，href 命中真实 id）
    root.querySelectorAll<HTMLElement>(
      "h1[id], h2[id], [data-testid='attack-chain-section'], [data-testid='vuln-card'][id], [data-testid='chain-card'][id]",
    ).forEach((el) => {
      const testid = el.getAttribute("data-testid");
      let level: 1 | 2 | 3;
      let id = el.id;
      let text = "";
      const clean = (s: string | null | undefined) => (s ?? "").replace(/\s+/g, " ").trim();
      if (el.tagName === "H1") {
        level = 1;
        text = clean(el.textContent);
      } else if (el.tagName === "H2") {
        level = 2;
        text = clean(el.textContent);
      } else if (testid === "attack-chain-section") {
        level = 2;
        id = "attack-chain-section";
        text = clean(el.querySelector("h2")?.textContent) || t("report.attackChains");
      } else if (testid === "chain-card") {
        level = 3;
        text = clean(el.querySelector('[data-testid="chain-title"]')?.textContent) || id;
      } else {
        // vuln-card：用 ID 作可扫条目
        level = 3;
        text = id;
      }
      if (id && text) items.push({ id, text, level });
    });
    setTocItems(items);
  }, [markdown, groups, t]);

  // scroll-spy：高亮当前可视章节。jsdom 无 IntersectionObserver → 跳过（不影响 TOC 渲染）。
  const [activeId, setActiveId] = useState<string>("");
  useEffect(() => {
    if (typeof IntersectionObserver === "undefined" || tocItems.length === 0) return;
    const observer = new IntersectionObserver(
      (entries) => {
        // 精确判定（2026-09-15，与 ReportToc/TocSideBar 同款修「点击跳转后高亮落到
        // 前一个条目」）：旧 -80px 粗筛带上沿落在 sticky 遮蔽带（~199px）内，被遮住
        // 的前一章节尾被算「可见」且 top 更小，快速 smooth 跳转的合并通知批次里高亮
        // 被前一个抢走。对粗筛命中者按实时几何校验（上沿 = 遮蔽带下沿，与 focusAnchor
        // 落点同源、每次回调现量；下沿 = 视口 30%）再取最靠上者。
        const bandTop = stickyHeaderOffset();
        const bandBottom = window.innerHeight * 0.3;
        const visible = entries
          .filter((e) => {
            if (!e.isIntersecting) return false;
            const rect = e.target.getBoundingClientRect(); // 实时几何（IO 快照滞后于 sticky 长高）
            return rect.bottom > bandTop && rect.top < bandBottom;
          })
          .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
        if (visible[0]?.target.id) setActiveId(visible[0].target.id);
      },
      // 粗筛带上沿与遮蔽带同源（创建时固化；sticky 后续长高由回调内实时校验兜住）
      { rootMargin: `-${Math.ceil(stickyHeaderOffset())}px 0px -70% 0px`, threshold: 0 },
    );
    for (const { id } of tocItems) {
      const el = document.getElementById(id);
      if (el) observer.observe(el);
    }
    return () => observer.disconnect();
  }, [tocItems]);

  // TOC 树：把 level-3（漏洞/攻击链条目）挂到最近的 level<=2 父章节下，做成可折叠树。
  const tocTree = useMemo(() => {
    const tree: { item: TocItem; children: TocItem[] }[] = [];
    let cur: { item: TocItem; children: TocItem[] } | null = null;
    for (const it of tocItems) {
      if (it.level <= 2) {
        cur = { item: it, children: [] };
        tree.push(cur);
      } else if (cur) {
        cur.children.push(it);
      }
    }
    return tree;
  }, [tocItems]);
  const [collapsedSections, setCollapsedSections] = useState<Set<string>>(() => new Set());
  const toggleSection = (id: string) =>
    setCollapsedSections((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  const tocSectionIds = tocTree.filter((n) => n.children.length > 0).map((n) => n.item.id);
  const tocAllCollapsed = tocSectionIds.length > 0 && tocSectionIds.every((id) => collapsedSections.has(id));
  // 默认折叠：首次构建出目录树时，把所有带子条目的章节收起（用户后续手动操作不受影响）。
  const tocCollapseInited = useRef(false);
  useEffect(() => {
    if (tocCollapseInited.current || tocSectionIds.length === 0) return;
    tocCollapseInited.current = true;
    setCollapsedSections(new Set(tocSectionIds));
  }, [tocSectionIds]);
  // ★ 不再随 scroll-spy 自动展开章节。旧实现「命中折叠章节内条目时自动展开该章节」会
  //   累积：用户向下滚动浏览报告，每经过一个同级章节就展开一个且不再折叠，滚到下方时
  //   上方同级章节全被展开（用户报告「展开下方目录，上方折叠目录也跟着展开」）。
  //   现改为只高亮当前命中条目的父标题（见下方 `active` 计算），章节展开/折叠完全由
  //   用户手动控制--折叠的保持折叠，不被动跟着展开。

  const twoCol = tocItems.length >= 2;

  return (
    <div className="space-y-5">
      <ThreatOverview stats={stats} />

      {showHero && (
        <div
          data-testid="exec-summary-hero"
          className="rounded-md border border-border border-l-2 border-l-red/60 bg-card p-4 shadow-[var(--shadow-card)]"
        >
          <div className="mb-2 flex items-center justify-between font-semibold tracking-tight text-base">
            <span>{t("markdown.topRisksTitle")}</span>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => setHeroCollapsed((c) => !c)}
              aria-label={t("markdown.toggleHeroAria")}
            >
              {heroCollapsed ? <ChevronRight className="size-4" /> : <ChevronDown className="size-4" />}
              <span className="sr-only">{heroCollapsed ? t("markdown.expand") : t("markdown.collapse")}</span>
            </Button>
          </div>
          {!heroCollapsed && (
            <ol className="list-decimal space-y-1 pl-6 text-sm">
              {topRisks.map((r, i) => (
                <li key={i}>
                  {r.vulnIds.length > 0 && (
                    <a
                      href={`#${r.vulnIds[0]}`}
                      onClick={(e) => scrollToId(e, r.vulnIds[0])}
                      className="kv-vuln-id font-mono text-primary"
                    >
                      {r.vulnIds.join("/")}
                    </a>
                  )}{" "}
                  {r.text}
                </li>
              ))}
            </ol>
          )}
        </div>
      )}

      <TypeSummaryCards typeAggs={stats.typeAggs} />

      <div className={twoCol ? "grid grid-cols-[200px_1fr] gap-8" : "grid grid-cols-1"}>
        {twoCol && (
          <nav data-testid="toc" aria-label={t("markdown.tocAria")} className="sticky top-44 self-start">
            {/* 顶部工具行：「目录」label + 两个折叠图标按钮并排。
                ★ 两按钮都在 <ul> 目录树之上（ul 自身 max-h + overflow-y-auto），
                展开任意章节、目录条目增多时按钮恒在顶部可见，不被滚走。
                左：收起目录（toc-toggle-all，控 collapsedSections）
                右：收起卡片（vuln-expand-all，控 collapsedIds）--语义靠 aria-label/title 区分。 */}
            <div className="mb-2 flex items-center justify-between gap-1 px-2">
              <span className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                {t("markdown.toc")}
              </span>
              <div className="flex items-center gap-0.5">
                {tocSectionIds.length > 0 && (
                  <button
                    type="button"
                    data-testid="toc-toggle-all"
                    onClick={() => setCollapsedSections(tocAllCollapsed ? new Set() : new Set(tocSectionIds))}
                    aria-label={tocAllCollapsed ? t("markdown.expandAll") : t("markdown.collapseAll")}
                    title={tocAllCollapsed ? t("markdown.expandAll") : t("markdown.collapseAll")}
                    className="flex size-6 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent/50 hover:text-foreground"
                  >
                    {tocAllCollapsed ? (
                      <List className="size-3.5" aria-hidden="true" />
                    ) : (
                      <ListCollapse className="size-3.5" aria-hidden="true" />
                    )}
                  </button>
                )}
                {collapseAllCardsBtn}
              </div>
            </div>
            <ul className="max-h-[calc(100vh-12rem)] space-y-0.5 overflow-y-auto pr-1">
              {tocTree.map((node) => {
                const hasKids = node.children.length > 0;
                const collapsed = collapsedSections.has(node.item.id);
                // active：章节自身命中，或其任一子条目命中。折叠章节下子条目不可见时，
                // 父标题高亮仍能提示「当前所在章节」--替代旧自动展开（见上方说明）。
                const active =
                  node.item.id === activeId ||
                  node.children.some((c) => c.id === activeId);
                return (
                  <li key={node.item.id}>
                    <div className="flex items-center gap-0.5">
                      {hasKids ? (
                        <button
                          type="button"
                          data-testid="toc-toggle"
                          onClick={() => toggleSection(node.item.id)}
                          aria-expanded={!collapsed}
                          aria-label={collapsed ? t("markdown.expand") : t("markdown.collapse")}
                          className="flex size-4 shrink-0 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent/50 hover:text-foreground"
                        >
                          <ChevronDown
                            className={`size-3 transition-transform duration-150 ${collapsed ? "-rotate-90" : ""}`}
                            aria-hidden="true"
                          />
                        </button>
                      ) : (
                        <span className="size-4 shrink-0" aria-hidden="true" />
                      )}
                      <a
                        href={`#${node.item.id}`}
                        onClick={(e) => scrollToId(e, node.item.id)}
                        className={`flex flex-1 items-center rounded-md px-1.5 py-1.5 text-[13px] transition-colors ${
                          node.item.level === 1 ? "font-semibold" : ""
                        } ${
                          active
                            ? "bg-accent text-foreground"
                            : "text-muted-foreground hover:bg-accent/50 hover:text-foreground"
                        }`}
                      >
                        <span className="truncate">{node.item.text}</span>
                      </a>
                    </div>
                    {/* 树形缩进：竖线(ml-6=24px)对齐父标题「文本」起始列（箭头16+gap2+a-pad6=24px），
                        子条目文本落在 39px，明显缩进到父标题右侧——根治「小标题比大标题靠前」。
                        父标题前导圆点已去（active 靠 bg-accent 背景足矣）：它曾把父文本推到 36px、
                        且逼竖线落在父文本左侧，视觉上子条目反显靠前。改父前导（箭头/pad）时复核 ml-6。 */}
                    {hasKids && !collapsed && (
                      <ul
                        data-testid="toc-children"
                        className="ml-6 mt-0.5 space-y-0.5 border-l border-border/40 pl-2"
                      >
                        {node.children.map((child) => {
                          const cActive = child.id === activeId;
                          return (
                            <li key={child.id}>
                              <a
                                href={`#${child.id}`}
                                onClick={(e) => scrollToId(e, child.id)}
                                className={`group flex items-center rounded-md px-1.5 py-1 font-mono text-[11px] transition-colors ${
                                  cActive
                                    ? "bg-accent text-foreground"
                                    : "text-muted-foreground hover:bg-accent/50 hover:text-foreground"
                                }`}
                              >
                                <span className="truncate">{child.text}</span>
                              </a>
                            </li>
                          );
                        })}
                      </ul>
                    )}
                  </li>
                );
              })}
            </ul>
          </nav>
        )}
        <div ref={contentRef} className="min-w-0 space-y-5">
          {!twoCol && collapseAllCardsBtn && (
            <div className="mb-2 flex items-center justify-between gap-2 px-0.5 py-1">
              <span className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                {t("markdown.findings")}
              </span>
              {collapseAllCardsBtn}
            </div>
          )}
          {groups.map((g, i) =>
            g.type === "prose" ? (
              <div
                key={i}
                className="prose prose-sm max-w-none font-sans prose-headings:font-sans prose-headings:tracking-tight prose-h1:mt-0"
              >
                <ReactMarkdown
                  remarkPlugins={REMARK_PLUGINS}
                  rehypePlugins={[makeSegmentSlugPlugin(i), ...HIGHLIGHT_PLUGIN] as never}
                  components={proseComponents as never}
                >
                  {g.md}
                </ReactMarkdown>
              </div>
            ) : (
              <div key={i} data-testid="vuln-grid" className="space-y-4">
                {g.blocks.map((block) => {
                  const sev = inferSeverity(block, topRiskIds);
                  // body = 原始 markdown 去掉首行标题（ID 在 header 里显示），完整保留所有字段/代码/散文——不裁剪丢信息。
                  // PoC 单一呈现（spec 2026-08-26 §8）：有并入的详细 PoC（curl/Burp，
                  // payload 超集）时过滤卡内 PoC/最小见证行；无并入的卡保留 payload 行。
                  const pocMd = pocById.get(block.id);
                  const bodyMd = (pocMd
                    ? stripCardPocLines(block.raw)
                    : block.raw
                  )
                    .split(/\r?\n/)
                    .slice(1)
                    .join("\n")
                    .trim();
                  const subtitle = block.title || vulnPreview(block);
                  return (
                    <section
                      key={block.id}
                      id={block.id}
                      data-testid="vuln-card"
                      data-severity={sev}
                      className={`vuln-entry scroll-mt-20 rounded-md border border-border bg-card p-4 shadow-[var(--shadow-card)] ${SEV_EDGE[sev] ?? ""}`}
                    >
                      {/* 常驻 header：整块可点折叠（accordion），两级卡头（2026-08-26 标题
                          升主标题，与结构化路径 VulnerabilityCard 同构）——eyebrow 元信息行
                          （ID + severity 药丸 + chevron，扫视层）+ 标题行（14.5px semibold
                          前景全亮，line-clamp-2 替代旧单行 truncate）。flex-col 让两级各占
                          一行；折叠态也能扫。 */}
                      <button
                        type="button"
                        data-testid="vuln-toggle"
                        onClick={() => toggleCard(block.id)}
                        aria-expanded={!collapsedIds.has(block.id)}
                        aria-controls={`${block.id}-body`}
                        className="flex w-full min-w-0 flex-col gap-1 text-left"
                      >
                        <span className="flex min-w-0 flex-wrap items-center gap-x-2.5 gap-y-1.5">
                          <span className="shrink-0 font-mono text-[13px] font-semibold text-foreground">{block.id}</span>
                          <span
                            className={`inline-flex shrink-0 items-center gap-1 rounded-full px-2 py-0.5 font-mono text-[10px] uppercase tracking-wide ${SEV_PILL[sev]}`}
                            data-testid="vuln-sev"
                          >
                            <span className={`sev-dot ${SEV_DOT[sev]}`} aria-hidden="true" data-testid="vuln-dot" />
                            {t(`vuln.severity.${sev}`, { defaultValue: sev })}
                          </span>
                          <ChevronDown
                            className={`ml-auto size-4 shrink-0 text-muted-foreground transition-transform duration-150 ${collapsedIds.has(block.id) ? "-rotate-90" : ""}`}
                            aria-hidden="true"
                          />
                        </span>
                        {subtitle && (
                          <span
                            data-testid="vuln-subtitle"
                            className="line-clamp-2 break-words text-[14.5px] font-semibold leading-snug tracking-tight text-foreground"
                          >
                            {subtitle}
                          </span>
                        )}
                      </button>
                      {/* body：完整原始内容（命中时并入对应 PoC），默认展开（不丢信息）；
                          本卡折叠时隐藏（扫描视图）。break-words 让长路径自动折行，不溢出卡片。 */}
                      {!collapsedIds.has(block.id) && (bodyMd || pocMd) && (
                        <div className="mt-3 space-y-3">
                          {bodyMd && (
                            <div id={`${block.id}-body`} className="prose prose-sm max-w-none break-words prose-headings:font-sans">
                              <ReactMarkdown
                                remarkPlugins={REMARK_PLUGINS}
                                rehypePlugins={[...HIGHLIGHT_PLUGIN] as never}
                                components={proseComponents as never}
                              >
                                {bodyMd}
                              </ReactMarkdown>
                            </div>
                          )}
                          {pocMd && (
                            <div data-testid="vuln-poc" className="border-t border-border pt-3">
                              <div className="mb-1 font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                                {t("markdown.pocSection")}
                              </div>
                              <div className="prose prose-sm max-w-none break-words prose-headings:font-sans">
                                <ReactMarkdown
                                  remarkPlugins={REMARK_PLUGINS}
                                  rehypePlugins={[...HIGHLIGHT_PLUGIN] as never}
                                  components={proseComponents as never}
                                >
                                  {pocMd}
                                </ReactMarkdown>
                              </div>
                            </div>
                          )}
                        </div>
                      )}
                    </section>
                  );
                })}
              </div>
            ),
          )}
          {orphanPocEntries.length > 0 && (
            <div data-testid="poc-orphan-group" className="space-y-4">
              {orphanPocEntries.map((e) => (
                <section
                  key={e.id}
                  data-testid="poc-orphan"
                  className="vuln-entry scroll-mt-20 rounded-md border border-border bg-card p-4 shadow-[var(--shadow-card)]"
                >
                  <div className="mb-1 font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                    {t("markdown.pocSection")} · {e.id}
                  </div>
                  <div className="prose prose-sm max-w-none break-words prose-headings:font-sans">
                    <ReactMarkdown
                      remarkPlugins={REMARK_PLUGINS}
                      rehypePlugins={[...HIGHLIGHT_PLUGIN] as never}
                      components={proseComponents as never}
                    >
                      {e.md}
                    </ReactMarkdown>
                  </div>
                </section>
              ))}
            </div>
          )}
          {attackChainSplit && (
            <AttackChainSection md={attackChainSplit.sectionMd} count={attackChainSplit.count} />
          )}
        </div>
      </div>
    </div>
  );
}
