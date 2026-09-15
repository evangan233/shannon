// 目录侧栏（spec 2026-08-20 §5「页面骨架：左目录 + 右内容两栏」）。
// 分组镜像页面三区：漏洞数据流树 (N) / 认证·授权风险 (N) / 排查过的入口 (N)。
// 每棵树一条：状态图标（●红=有打通枝 / ✂绿=全部剪断）+ sink 名 + 次行小字
// （finding IDs · N打通/M剪断）；认证·授权条目 ▲黄 + endpoint。
// IntersectionObserver scrollspy：滚动到哪棵树对应条目高亮；点击平滑滚动 +
// 目标卡 coral 描边闪烁（focusDataflowAnchor 与 DataFlowTab ?tree= 深链共用）。
// 吸顶 / 自身内滚 / 窄屏 <1000px 顶部块由 DataFlowTab 两栏布局承载（sticky 列）。
import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import type { ControlFinding, DataflowTree, SafeVector } from "@/api/types";
import { focusAnchor, stickyHeaderOffset } from "@/utils/focusAnchor";
import { controlAnchorId } from "./GuardChain";

export interface TocSideBarProps {
  trees: DataflowTree[];
  controls: ControlFinding[];
  safeVectors: SafeVector[];
  /** 目录点击定位回调（2026-09-14 信息架构重做）：宿主可先展开目标树（收起态行）
   *  再定位；缺省 = 直接 focusDataflowAnchor（向后兼容旧行为）。 */
  onLocate?: (id: string) => void;
}

/** 排查过的入口分组锚点 id（对应 SafeEntries 区的 data-safe-section）。 */
export const SAFE_SECTION_ID = "safe-entries";

function cssEscape(s: string): string {
  return typeof CSS !== "undefined" && CSS.escape ? CSS.escape(s) : s.replace(/["\\]/g, "\\$&");
}

/** 定位锚点：平滑滚动到目标卡（树卡 / 关卡卡 / 排查过的入口区）+ coral 描边闪烁。
 *  目录点击与 DataFlowTab ?tree= 深链（VulnCard「查看数据流」跳转落点）共用。
 *  定位核心（精准落点量 sticky 遮蔽带 + 闪烁 + 单一 active-target 语义）2026-08-26
 *  起委托共享 focusAnchor——与报告页目录/摘要锚点同一「落点露出目标 + coral 闪烁」
 *  语言；这里只保留 dataflow 的属性查找器（data-tree-id / data-control-id）。
 *  找不到目标（深链失效 / 数据未含该树）返回 false，静默不报错。 */
export function focusDataflowAnchor(id: string): boolean {
  const selector =
    id === SAFE_SECTION_ID
      ? "[data-safe-section]"
      : `[data-tree-id="${cssEscape(id)}"], [data-control-id="${cssEscape(id)}"]`;
  return focusAnchor(id, () => document.querySelector(selector));
}

/** 树是否有漏洞（打通口径，与 PruningTreeFig 靶心一致）：任一枝 verdict=vulnerable 或挂 findings。
 *  目录状态图标与 DataFlowTab「只看有漏洞的」筛选（Task 14）共用同一判定，避免口径漂移。 */
export function treeHasVuln(tree: DataflowTree): boolean {
  return tree.branches.some((b) => b.verdict === "vulnerable") || tree.findings.length > 0;
}

/** 树状态：●红=有打通枝（或挂 findings）/ ✂绿=全部剪断（与 PruningTreeFig 靶心口径一致）。 */
function treeStatus(tree: DataflowTree): "vuln" | "safe" {
  return treeHasVuln(tree) ? "vuln" : "safe";
}

/** 锚点元素 → TOC id（树卡 data-tree-id / 关卡卡 data-control-id / safe 区固定 id）。 */
function anchorIdOf(el: Element): string | null {
  const tid = el.getAttribute("data-tree-id");
  if (tid) return tid;
  const cid = el.getAttribute("data-control-id");
  if (cid) return cid;
  return el.hasAttribute("data-safe-section") ? SAFE_SECTION_ID : null;
}

export function TocSideBar({ trees, controls, safeVectors, onLocate }: TocSideBarProps) {
  const { t } = useTranslation();
  const [activeId, setActiveId] = useState<string | null>(null);
  const visibleRef = useRef<Set<string>>(new Set());

  // scrollspy：观察右内容区锚点，按文档序取第一个仍可见者高亮（多区同屏时顶部优先）。
  useEffect(() => {
    if (typeof IntersectionObserver === "undefined") return;
    const els = Array.from(
      document.querySelectorAll("[data-tree-id], [data-control-id], [data-safe-section]"),
    );
    if (els.length === 0) return;
    // id → 锚点元素（文档序，Map 保插入序）：精确判定时反查元素量实时几何
    const elById = new Map<string, Element>();
    for (const el of els) {
      const id = anchorIdOf(el);
      if (id) elById.set(id, el);
    }
    const order = [...elById.keys()];
    const io = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          const id = anchorIdOf(e.target);
          if (!id) continue;
          if (e.isIntersecting) visibleRef.current.add(id);
          else visibleRef.current.delete(id);
        }
        // 精确判定（2026-09-15 修「点击跳转后高亮落到前一个条目」，与 ReportToc
        // 同款）：IO 带只当粗筛，命中集合内再按实时几何校验——上沿 = sticky 遮蔽带
        // 下沿（与 focusAnchor 落点同源，每次回调现量），下沿 = 视口 40%。跳转后
        // 目标卡顶贴遮蔽带下沿，前一张卡尾只落在被遮蔽区 → 剔除，不再被文档序
        // 更靠前的前卡抢走高亮。
        const bandTop = stickyHeaderOffset();
        const bandBottom = window.innerHeight * 0.4;
        const first = order.find((id) => {
          if (!visibleRef.current.has(id)) return false;
          const rect = elById.get(id)?.getBoundingClientRect();
          return !!rect && rect.bottom > bandTop && rect.top < bandBottom;
        });
        if (first) setActiveId(first);
      },
      // 粗筛带上沿与遮蔽带同源（创建时固化；sticky 后续长高由回调内实时校验兜住），
      // 避免大视口（10% 视口 > 遮蔽带下沿）时目标卡落点落在粗筛带外被漏报。
      { rootMargin: `-${Math.ceil(stickyHeaderOffset())}px 0px -60% 0px` },
    );
    for (const el of els) io.observe(el);
    return () => io.disconnect();
  }, [trees, controls, safeVectors]);

  const locate = (id: string) => {
    setActiveId(id);
    if (onLocate) onLocate(id);
    else focusDataflowAnchor(id);
  };

  const entryCls = (id: string) =>
    `flex w-full items-start gap-1.5 rounded-sm p-1.5 text-left text-sm ${
      activeId === id ? "bg-accent text-accent-foreground" : "hover:bg-accent/60"
    }`;

  return (
    <nav aria-label={t("workspaceDetail.dataflow.tocAria")} data-testid="dataflow-toc" className="space-y-4 text-sm">
      {trees.length > 0 && (
        <div className="space-y-1">
          <p className="px-1.5 text-xs font-medium text-muted-foreground">
            {t("workspaceDetail.dataflow.tocGroupTrees", { count: trees.length })}
          </p>
          {trees.map((tree) => {
            const status = treeStatus(tree);
            const vulnN = tree.branches.filter((b) => b.verdict === "vulnerable").length;
            const safeN = tree.branches.filter((b) => b.verdict === "safe").length;
            // unknown 枝三段计数（2026-08-26 口径修复，与汇总条/迷你条同口径）
            const unknownN = tree.branches.filter((b) => b.verdict === "unknown").length;
            const ids = tree.findings.map((f) => f.id).filter(Boolean).join(", ");
            const counts =
              unknownN > 0
                ? t("workspaceDetail.dataflow.tocCountsWithUnknown", { vuln: vulnN, safe: safeN, unknown: unknownN })
                : t("workspaceDetail.dataflow.tocCounts", { vuln: vulnN, safe: safeN });
            return (
              <button
                key={tree.tree_id}
                type="button"
                data-toc-id={tree.tree_id}
                data-status={status}
                aria-current={activeId === tree.tree_id ? "true" : undefined}
                onClick={() => locate(tree.tree_id)}
                className={entryCls(tree.tree_id)}
              >
                <span
                  aria-hidden
                  className="mt-0.5 shrink-0 font-bold"
                  style={{ color: status === "vuln" ? "hsl(var(--c-red))" : "hsl(var(--c-green))" }}
                >
                  {status === "vuln" ? "●" : "✂"}
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block truncate font-medium">
                    {tree.sink.label ?? t("workspaceDetail.dataflow.sink")}
                  </span>
                  <span className="block truncate text-[11px] text-muted-foreground">
                    {ids ? `${ids} · ` : ""}
                    {counts}
                  </span>
                </span>
              </button>
            );
          })}
        </div>
      )}

      {controls.length > 0 && (
        <div className="space-y-1">
          <p className="px-1.5 text-xs font-medium text-muted-foreground">
            {t("workspaceDetail.dataflow.tocGroupControls", { count: controls.length })}
          </p>
          {controls.map((c, i) => {
            const id = controlAnchorId(c, i);
            return (
              <button
                key={id}
                type="button"
                data-toc-id={id}
                data-status="control"
                aria-current={activeId === id ? "true" : undefined}
                onClick={() => locate(id)}
                className={entryCls(id)}
              >
                <span
                  aria-hidden
                  className="mt-0.5 shrink-0 font-bold"
                  style={{ color: "hsl(var(--c-yellow))" }}
                >
                  ▲
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block truncate font-mono text-[13px]">
                    {c.endpoint ?? c.id ?? id}
                  </span>
                </span>
              </button>
            );
          })}
        </div>
      )}

      {safeVectors.length > 0 && (
        <div className="space-y-1">
          {/* 排查过的入口无逐条锚点（平铺一区）→ 分组头即定位入口 */}
          <button
            type="button"
            data-toc-id={SAFE_SECTION_ID}
            data-status="safe"
            aria-current={activeId === SAFE_SECTION_ID ? "true" : undefined}
            onClick={() => locate(SAFE_SECTION_ID)}
            className={`${entryCls(SAFE_SECTION_ID)} px-1.5 py-1 text-xs font-medium text-muted-foreground`}
          >
            <span aria-hidden className="shrink-0" style={{ color: "hsl(var(--c-green))" }}>
              ✔
            </span>
            {t("workspaceDetail.dataflow.tocGroupSafe", { count: safeVectors.length })}
          </button>
        </div>
      )}
    </nav>
  );
}
