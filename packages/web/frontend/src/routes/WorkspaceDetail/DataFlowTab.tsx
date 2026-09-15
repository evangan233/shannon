import { useEffect, useMemo, useRef, useState } from "react";
import useSWR from "swr";
import { useParams, useSearchParams } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { ApiError, fetchDataflowView } from "@/api/client";
import type { DataflowTree, DataflowView } from "@/api/types";
import { Empty } from "@/components/Empty";
import { Skeleton } from "@/components/ui/skeleton";
import {
  TocSideBar,
  focusDataflowAnchor,
  treeHasVuln,
  SAFE_SECTION_ID,
} from "@/components/dataflow/TocSideBar";
import { TreeList } from "@/components/dataflow/TreeList";
import { GuardChain } from "@/components/dataflow/GuardChain";
import { SafeEntries } from "@/components/dataflow/SafeEntries";
import { LegendBar } from "@/components/dataflow/LegendBar";

/**
 * 数据流视图 tab（spec 2026-08-20 §5）。
 *
 * 左目录侧栏（TocSideBar）+ 右内容区（战况带 → 图例条 → 树列表 → 关卡链 → 安全向量）。
 * SWR 拉 GET /workspaces/{ws}/scans/{id}/dataflow——后端写时组装 dataflow_view.json。
 *
 * 2026-09-14 信息架构重做：
 * - 汇总条 → 战况带（FlowStatBand）：三色连续比例条（红=打通/绿=剪断/琥珀=未判定，
 *   按枝数占比）+ 数字组 + 筛选器——「N 条数据流的战况」一图可读，与树头 mini 条、
 *   树行 rowbar 构成三级比例条语言；
 * - 34 树全展开长页（12000px+）→ TreeList 收起行 + 按需展开（默认展开第一棵有漏洞
 *   树；漏洞树置顶排序；React Flow 画布仅展开态挂载）；
 * - 筛选状态同时作用于树列表与目录（TocSideBar 收过滤后的 trees）；汇总计数保持
 *   全量口径（描述本次扫描整体，不随筛选缩水）。
 *
 * 后端全产物缺 → 404（不产文件），此处显「无数据流视图」空态（非错误）。
 * ws/scanId 取自路由 params（对齐 DeliverablesTab 习惯，router.tsx 作 <DataFlowTab /> 挂载）。
 */
export function DataFlowTab() {
  const { t } = useTranslation();
  const { workspace, scanId } = useParams<{ workspace: string; scanId: string }>();
  const ws = workspace ?? "";
  const id = scanId ?? "";
  const { data, error, isLoading } = useSWR(
    ws && id ? ["dataflow", ws, id] : null,
    () => fetchDataflowView(ws, id),
  );

  // 筛选器状态（spec §5 汇总条）：vuln_class 下拉（"all"=全部类型）+ 只看有漏洞的 toggle。
  const [vulnClass, setVulnClass] = useState("all");
  const [vulnOnly, setVulnOnly] = useState(false);

  // 可选 vuln_class（数据派生，taint 三类 injection/xss/ssrf 在前、其余按字典序——不硬编码死选项）。
  const vulnClasses = useMemo(() => {
    if (!data) return [];
    const order = ["injection", "xss", "ssrf"];
    return [...new Set(data.trees.map((tr) => tr.vuln_class))].sort((a, b) => {
      const ia = order.indexOf(a);
      const ib = order.indexOf(b);
      return (ia < 0 ? order.length : ia) - (ib < 0 ? order.length : ib) || a.localeCompare(b);
    });
  }, [data]);

  // 过滤后的树（树列表 + 目录共用），漏洞树置顶（读者第一屏先看到打通的）。「有漏洞」
  // 口径与目录状态图标一致（treeHasVuln）；组内保持数据序（稳定排序）。
  const filteredTrees = useMemo(() => {
    if (!data) return [];
    return data.trees
      .filter((tr) => {
        if (vulnClass !== "all" && tr.vuln_class !== vulnClass) return false;
        if (vulnOnly && !treeHasVuln(tr)) return false;
        return true;
      })
      .map((tr, i) => ({ tr, i }))
      .sort((a, b) => Number(treeHasVuln(b.tr)) - Number(treeHasVuln(a.tr)) || a.i - b.i)
      .map((x) => x.tr);
  }, [data, vulnClass, vulnOnly]);

  // 展开态（信息架构重做）：默认展开第一棵有漏洞的树（按全量数据，一次性初始化）。
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());
  const initExpandedRef = useRef(false);
  useEffect(() => {
    if (!data || initExpandedRef.current || data.trees.length === 0) return;
    initExpandedRef.current = true;
    const firstVuln = data.trees.find((tr) => treeHasVuln(tr)) ?? data.trees[0];
    setExpandedIds(new Set([firstVuln.tree_id]));
  }, [data]);

  const toggleTree = (treeId: string) =>
    setExpandedIds((cur) => {
      const next = new Set(cur);
      if (next.has(treeId)) next.delete(treeId);
      else next.add(treeId);
      return next;
    });

  // 展开目标树（TOC 点击 / ?tree= 深链共用）+ 等一帧渲染后再定位锚点。
  const expandAndFocus = (treeId: string) => {
    setExpandedIds((cur) => (cur.has(treeId) ? cur : new Set(cur).add(treeId)));
    requestAnimationFrame(() => focusDataflowAnchor(treeId));
  };

  // ?tree= 深链定位（spec §5 路由与入口：VulnCard「查看数据流」跳转落点）——
  // 数据到位后一次性展开目标树 + 锚点滚动 + 目标卡 coral 描边闪烁。
  // 注意须在早返回之前声明（rules of hooks）。
  const [searchParams] = useSearchParams();
  const deepLinkTree = searchParams.get("tree");
  const locatedRef = useRef(false);
  useEffect(() => {
    if (!data || !deepLinkTree || locatedRef.current) return;
    locatedRef.current = true;
    expandAndFocus(deepLinkTree);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data, deepLinkTree]);

  // 404 = 后端未产 dataflow_view.json（旧版扫描 / 白盒未产出）→ 空态，非错误。
  // spec §6：文案带「需新版扫描」引导（数据流视图仅新版扫描产出）。
  if (error instanceof ApiError && error.status === 404) {
    return (
      <Empty
        title={t("workspaceDetail.dataflow.emptyTitle")}
        hint={t("workspaceDetail.dataflow.emptyHint404")}
      />
    );
  }
  if (isLoading) return <DataflowLoading />;
  if (!data) {
    // 非 404 错误（5xx / 网络降级）兜底空态——错误横幅暂不接，保持最小。
    return (
      <Empty
        title={t("workspaceDetail.dataflow.emptyTitle")}
        hint={t("workspaceDetail.dataflow.emptyHint")}
      />
    );
  }

  return (
    /* 窄屏 <1000px：单列，目录退化为顶部块（spec §5）；≥1000px 两栏 232px 侧栏。 */
    <div className="grid grid-cols-1 items-start gap-5 min-[1000px]:grid-cols-[232px_minmax(0,1fr)]">
      {/* 左列：TOC 侧栏——sticky 吸顶 + 自身内滚；收过滤后的 trees（目录与树区同步）。 */}
      <div className="max-h-[calc(100vh-220px)] space-y-3 overflow-auto border-b border-border pb-3 min-[1000px]:sticky min-[1000px]:top-4 min-[1000px]:border-b-0 min-[1000px]:border-r min-[1000px]:pb-0 min-[1000px]:pr-4">
        <TocSideBar
          trees={filteredTrees}
          controls={data.control_findings}
          safeVectors={data.safe_vectors}
          onLocate={(target) => {
            if (target !== SAFE_SECTION_ID && !target.startsWith("ctl-")) expandAndFocus(target);
            else requestAnimationFrame(() => focusDataflowAnchor(target));
          }}
        />
      </div>
      {/* 右列：战况带（含筛选器）→ 图例条 → 树列表（收起行+按需展开）→ 关卡链 → 安全向量 */}
      <div className="min-w-0 space-y-4">
        <FlowStatBand
          trees={data.trees}
          controls={data.control_findings}
          safeVectors={data.safe_vectors}
          classes={vulnClasses}
          vulnClass={vulnClass}
          onVulnClassChange={setVulnClass}
          vulnOnly={vulnOnly}
          onVulnOnlyChange={setVulnOnly}
        />
        {/* 树区区头（spec §5 区 1）：标题精炼为「漏洞数据流树」+ 组织方式说明段；
            后接图例条（样例教读图）再接树列表——标题 → 说明段 → 图例条 → 树。 */}
        {data.trees.length > 0 && (
          <section>
            <h3 className="font-medium">{t("workspaceDetail.dataflow.treesTitle")}</h3>
            <p className="mt-0.5 text-xs text-muted-foreground">
              {t("workspaceDetail.dataflow.treesIntro")}
            </p>
          </section>
        )}
        {/* 图例条：树区上方教读图（spec §5）；有树才渲染。 */}
        {data.trees.length > 0 && <LegendBar />}
        {filteredTrees.length > 0 && (
          <TreeList trees={filteredTrees} expandedIds={expandedIds} onToggle={toggleTree} />
        )}
        {/* 筛选后无匹配：空提示（区别于「本来就没有树」——后者不渲染任何树区占位）。 */}
        {filteredTrees.length === 0 && data.trees.length > 0 && (
          <p
            data-testid="dataflow-filter-empty"
            className="rounded-md border border-dashed border-border px-3 py-6 text-center text-sm text-muted-foreground"
          >
            {t("workspaceDetail.dataflow.filterEmpty")}
          </p>
        )}
        <GuardChain controls={data.control_findings} />
        <SafeEntries vectors={data.safe_vectors} />
      </div>
    </div>
  );
}

/** 锚点跳转（平滑滚动 + coral 闪烁，与目录点击同一语言）；找不到目标静默。 */
function scrollToSelector(selector: string) {
  const el = document.querySelector(selector);
  if (el) {
    el.scrollIntoView({ behavior: "smooth", block: "start" });
    el.classList.add("dataflow-flash");
    window.setTimeout(() => el.classList.remove("dataflow-flash"), 1600);
  }
}

/**
 * 战况带（spec §5 汇总条的架构重做版）：三色连续比例条 + 数字组 + 筛选器。
 * 比例条按枝数占比分段（红=打通 / 绿=剪断 / 琥珀=未判定），与树头 mini 条、树行
 * rowbar 同语言（页面级「总战况」→ 树级 → 枝级行）；aria 汇总文案走 minibarAria 系。
 * 计数按枝条（branch）统计且保持全量（不随筛选缩水）——三项同一单位可加和。
 * 认证/授权风险、排查过的入口计数为可点锚点（>0 时滚到对应区）。
 */
function FlowStatBand({
  trees,
  controls,
  safeVectors,
  classes,
  vulnClass,
  onVulnClassChange,
  vulnOnly,
  onVulnOnlyChange,
}: {
  trees: DataflowTree[];
  controls: DataflowView["control_findings"];
  safeVectors: DataflowView["safe_vectors"];
  classes: string[];
  vulnClass: string;
  onVulnClassChange: (v: string) => void;
  vulnOnly: boolean;
  onVulnOnlyChange: (v: boolean) => void;
}) {
  const { t } = useTranslation();
  const flows = trees.reduce((n, tr) => n + tr.branches.length, 0);
  const breached = trees.reduce(
    (n, tr) => n + tr.branches.filter((b) => b.verdict === "vulnerable").length,
    0,
  );
  const cut = trees.reduce(
    (n, tr) => n + tr.branches.filter((b) => b.verdict === "safe").length,
    0,
  );
  // unknown 枝（LLM 轨「无法确认」）独立计数：总数含 unknown 而打通/剪断都不含 →
  // 「N 条未判定」补齐可加和口径（数字加得平）
  const unjudged = trees.reduce(
    (n, tr) => n + tr.branches.filter((b) => b.verdict === "unknown").length,
    0,
  );
  const total = Math.max(1, flows);
  const pct = (n: number) => `${(n / total) * 100}%`;
  // toggle 两态按钮共用样式：激活态 accent 底、非激活 muted 悬停提亮
  const segCls = (on: boolean) =>
    `rounded-md border border-border px-2 py-1 ${
      on ? "bg-accent font-medium text-accent-foreground" : "text-muted-foreground hover:text-foreground"
    }`;
  const anchorCls =
    "rounded px-1.5 py-0.5 text-muted-foreground underline-offset-2 hover:bg-accent/60 hover:text-foreground hover:underline";
  return (
    <div
      className="rounded-md border border-border bg-card p-3 text-sm"
      data-testid="dataflow-summary-bar"
    >
      {/* 比例带：三段连续（0 flows 不渲染空带） */}
      {flows > 0 && (
        <div
          data-flow-band=""
          role="img"
          aria-label={t(
            unjudged > 0
              ? "workspaceDetail.dataflow.minibarAriaWithUnknown"
              : "workspaceDetail.dataflow.minibarAria",
            { vuln: breached, safe: cut, unknown: unjudged },
          )}
          className="flex h-2.5 overflow-hidden rounded-full border border-border"
        >
          <span data-flow-band-seg="vuln" className="bg-[hsl(var(--c-red))]" style={{ width: pct(breached) }} />
          <span data-flow-band-seg="safe" className="bg-[hsl(var(--c-green))]" style={{ width: pct(cut) }} />
          {unjudged > 0 && (
            <span
              data-flow-band-seg="unknown"
              className="bg-[hsl(var(--c-amber))] opacity-80"
              style={{ width: pct(unjudged) }}
            />
          )}
        </div>
      )}
      <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1.5">
        <span className="font-medium">{t("workspaceDetail.dataflow.title")}</span>
        <span className="text-muted-foreground">
          {t("workspaceDetail.dataflow.totalFlows", { count: flows })}
        </span>
        <span className="text-[hsl(var(--c-red))]">
          {t("workspaceDetail.dataflow.breachedFlows", { count: breached })}
        </span>
        <span className="text-muted-foreground">
          {t("workspaceDetail.dataflow.cutFlows", { count: cut })}
        </span>
        {unjudged > 0 && (
          <span className="text-[hsl(var(--c-amber))]">
            {t("workspaceDetail.dataflow.unknownFlows", { count: unjudged })}
          </span>
        )}
        {/* 非枝条计数 → 区段锚点（>0 可点跳转；0 保持纯数字展示） */}
        {controls.length > 0 ? (
          <button
            type="button"
            data-anchor="controls"
            onClick={() => scrollToSelector("[data-guard-section]")}
            className={anchorCls}
          >
            {t("workspaceDetail.dataflow.controls", { count: controls.length })}
          </button>
        ) : (
          <span className="text-muted-foreground">
            {t("workspaceDetail.dataflow.controls", { count: controls.length })}
          </span>
        )}
        {safeVectors.length > 0 ? (
          <button
            type="button"
            data-anchor="safe"
            onClick={() => scrollToSelector("[data-safe-section]")}
            className={anchorCls}
          >
            {t("workspaceDetail.dataflow.safeVectors", { count: safeVectors.length })}
          </button>
        ) : (
          <span className="text-muted-foreground">
            {t("workspaceDetail.dataflow.safeVectors", { count: safeVectors.length })}
          </span>
        )}
        {classes.length > 0 && (
          /* 筛选器（spec §5）：vuln_class 下拉 + 「只看有漏洞的 ⇄ 全部」toggle */
          <span className="ml-auto flex flex-wrap items-center gap-2">
            <select
              value={vulnClass}
              onChange={(e) => onVulnClassChange(e.target.value)}
              aria-label={t("workspaceDetail.dataflow.filterClassLabel")}
              data-testid="dataflow-class-select"
              className="rounded-md border border-border bg-background px-2 py-1 text-xs"
            >
              <option value="all">{t("workspaceDetail.dataflow.filterAllClasses")}</option>
              {classes.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>
            <span
              role="group"
              aria-label={t("workspaceDetail.dataflow.filterGroupAria")}
              className="flex items-center gap-1"
            >
              <span aria-hidden className="text-muted-foreground">
                ⇄
              </span>
              <button
                type="button"
                data-testid="dataflow-toggle-all"
                aria-pressed={!vulnOnly}
                onClick={() => onVulnOnlyChange(false)}
                className={segCls(!vulnOnly)}
              >
                {t("workspaceDetail.dataflow.filterAll")}
              </button>
              <button
                type="button"
                data-testid="dataflow-toggle-vulnonly"
                aria-pressed={vulnOnly}
                onClick={() => onVulnOnlyChange(true)}
                className={segCls(vulnOnly)}
              >
                {t("workspaceDetail.dataflow.filterVulnOnly")}
              </button>
            </span>
          </span>
        )}
      </div>
    </div>
  );
}

/** 加载占位（Skeleton，对齐 DeliverablesTab 习惯）。 */
function DataflowLoading() {
  return (
    <div className="space-y-2">
      {[0, 1, 2, 3, 4].map((i) => (
        <Skeleton key={i} className="h-8 w-full" />
      ))}
    </div>
  );
}
