import { Fragment, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import type { CorrVerdictGroup } from "@/lib/correlation-verdict";
import { focusAnchor, stickyHeaderOffset } from "@/utils/focusAnchor";

/**
 * 跨仓结果页目录（2026-09-20 结论优先批次；09-20 去重 / 09-21 静默批次逐轮收窄）：
 * 区块级 sticky 目录镜像页面结构——漏洞（主区，按结论分组，条目 = severity 状态点 +
 * ID + 服务小字）/ 拓扑 / 多跳。结论摘要、攻击链、信任边界、单仓已否决、关联报告
 * 章节均已撤（内容分别并入漏洞区紧凑行 / 漏洞卡「所在跨服链」/ md 报告附录 /
 * 复核一行 / 总览头下载按钮），目录不再单列。点击 → focusAnchor 精准落点；
 * scrollspy 高亮当前区块（同族模式独立实现：ReportToc / dataflow TocSideBar 先例——
 * 仓内惯例「同族视觉、各自实现」，props 不绑 ReportData）。
 */

export const CORR_SEC_VULNS = "corr-sec-vulns";
export const CORR_SEC_MULTIHOP = "corr-sec-multihop";
export const CORR_SEC_TOPOLOGY = "corr-sec-topology";

/** severity（小写）→ 状态点色（--c-* 语义 channel，与 ReportToc 同源）。 */
const SEV_DOT_C: Record<string, string> = {
  critical: "hsl(var(--c-red))",
  high: "hsl(var(--c-orange))",
  medium: "hsl(var(--c-yellow))",
  low: "hsl(var(--muted-foreground))",
};

/** TOC 漏洞条目（父级归一：结论组 + severity + 服务）。 */
export interface CorrTocVuln {
  id: string;
  anchorId: string;
  severity?: string;
  service?: string;
  group: CorrVerdictGroup;
}

export interface CorrTocSections {
  multihop: boolean;
  topology: boolean;
}

/** 区块条目定义（anchor id + i18n label key），presence 由父级按数据有无决定；
 *  顺序镜像页面（漏洞主区在最前，恒在）。 */
const SECTIONS: { key: keyof CorrTocSections | "vulns"; id: string; labelKey: string }[] = [
  { key: "vulns", id: CORR_SEC_VULNS, labelKey: "scan.correlation.tocVulns" },
  { key: "topology", id: CORR_SEC_TOPOLOGY, labelKey: "scan.correlation.topologyTitle" },
  { key: "multihop", id: CORR_SEC_MULTIHOP, labelKey: "scan.correlation.multihopTitle" },
];

/** 结论组在 TOC 的分组顺序与标签 key（成立在前）。 */
const GROUP_ORDER: CorrVerdictGroup[] = ["confirmed", "refuted", "uncertain", "unadjudicated"];

export function CorrToc({ vulns, sections, onLocateSection, onLocateVuln }: {
  vulns: CorrTocVuln[];
  sections: CorrTocSections;
  /** 区块条目点击钩子；缺省直接 focusAnchor（区块无折叠联动）。 */
  onLocateSection?: (anchorId: string) => void;
  /** 漏洞条目点击钩子（收漏洞 ID，父级传「先展开目标组/卡再定位」的 locateVuln）；
   *  缺省直接 focusAnchor(v.anchorId)。 */
  onLocateVuln?: (vulnId: string) => void;
}) {
  const { t } = useTranslation();
  const [activeId, setActiveId] = useState<string | null>(null);
  const visibleRef = useRef<Set<string>>(new Set());

  // 目录条目序 = 页面文档序（漏洞区块 → 其漏洞条目 → 其余区块）——scrollspy 高亮
  // 与视觉顺序一致；漏洞条目穿插错位会让点击「往上跳」（2026-09-21 修复）。
  const anchorIds = useMemo(
    () => [
      ...(SECTIONS[0] ? [SECTIONS[0].id] : []),
      ...vulns.map((v) => v.anchorId),
      ...SECTIONS.slice(1).filter((s) => sections[s.key as keyof CorrTocSections]).map((s) => s.id),
    ],
    [sections, vulns],
  );

  // scrollspy：同 ReportToc 模式（IO 粗筛 + 遮蔽带实时几何校验）；jsdom 无 IO 跳过。
  useEffect(() => {
    if (typeof IntersectionObserver === "undefined") return;
    const els = anchorIds
      .map((id) => document.getElementById(id))
      .filter((el): el is HTMLElement => el !== null);
    if (els.length === 0) return;
    const io = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          if (e.isIntersecting) visibleRef.current.add(e.target.id);
          else visibleRef.current.delete(e.target.id);
        }
        const bandTop = stickyHeaderOffset();
        const bandBottom = window.innerHeight * 0.4;
        const first = anchorIds.find((id) => {
          if (!visibleRef.current.has(id)) return false;
          const rect = document.getElementById(id)?.getBoundingClientRect();
          return !!rect && rect.bottom > bandTop && rect.top < bandBottom;
        });
        if (first) setActiveId(first);
      },
      { rootMargin: `-${Math.ceil(stickyHeaderOffset())}px 0px -60% 0px` },
    );
    for (const el of els) io.observe(el);
    return () => io.disconnect();
  }, [anchorIds]);

  const locateSection = (anchorId: string) => {
    setActiveId(anchorId);
    if (onLocateSection) onLocateSection(anchorId);
    else focusAnchor(anchorId);
  };
  const locateVuln = (v: CorrTocVuln) => {
    setActiveId(v.anchorId);
    if (onLocateVuln) onLocateVuln(v.id);
    else focusAnchor(v.anchorId);
  };

  const itemCls = (id: string) =>
    `flex w-full items-start gap-1.5 rounded-sm p-1.5 text-left ${
      activeId === id ? "bg-accent text-accent-foreground" : "hover:bg-accent/60"
    }`;

  const present = (key: typeof SECTIONS[number]["key"]) =>
    key === "vulns" || sections[key as keyof CorrTocSections];

  /** 漏洞条目组块（按结论分组，成立在前）。 */
  const vulnGroupBlocks = GROUP_ORDER.map((group) => {
    const list = vulns.filter((v) => v.group === group);
    if (list.length === 0) return null;
    return (
      <div key={group} className="space-y-1">
        <p className="px-1.5 text-xs font-medium text-muted-foreground">
          {t(`scan.correlation.verdict.${group}`)} ({list.length})
        </p>
        {list.map((v) => (
          <button
            key={v.anchorId}
            type="button"
            data-toc-id={v.anchorId}
            data-severity={v.severity ?? ""}
            aria-current={activeId === v.anchorId ? "true" : undefined}
            onClick={() => locateVuln(v)}
            className={itemCls(v.anchorId)}
          >
            <span
              aria-hidden
              className="mt-1 size-1.5 shrink-0 rounded-full"
              style={{
                background: SEV_DOT_C[(v.severity ?? "").toLowerCase()] ?? "hsl(var(--muted-foreground))",
              }}
            />
            <span className="min-w-0 flex-1">
              <span className="block truncate font-mono text-[11.5px] font-medium text-foreground/90">{v.id}</span>
              {v.service && (
                <span className="block truncate text-[11px] text-muted-foreground">{v.service}</span>
              )}
            </span>
          </button>
        ))}
      </div>
    );
  });

  return (
    <nav aria-label={t("scan.correlation.tocAria")} data-testid="corr-toc" className="space-y-3 text-sm">
      {/* 漏洞区块条目 + 其漏洞条目紧随其后（文档序；其余区块垫后） */}
      {SECTIONS.filter((s) => present(s.key)).map((s, i) => (
        <Fragment key={s.id}>
          <button
            type="button"
            data-toc-id={s.id}
            aria-current={activeId === s.id ? "true" : undefined}
            onClick={() => locateSection(s.id)}
            className={`${itemCls(s.id)} truncate text-[13px] font-medium`}
          >
            {t(s.labelKey)}
          </button>
          {i === 0 && vulnGroupBlocks}
        </Fragment>
      ))}
    </nav>
  );
}
