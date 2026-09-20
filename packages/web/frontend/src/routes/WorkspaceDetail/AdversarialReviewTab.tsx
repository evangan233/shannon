import { useMemo, useState } from "react";
import useSWR from "swr";
import { useParams } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { fetchAdversarialReview } from "@/api/client";
import type { ReviewRecord } from "@/api/types";

/**
 * 对抗性审查 tab（spec 2026-09-10 对抗审查阶段）。
 *
 * SWR 一次性拉 GET /workspaces/{ws}/scans/{id}/adversarial-review：summary 计数条
 * （总计/已驳回/无法反驳/未审成）+ verdict / failed_dimensions 双筛选（维度选项从
 * 记录数据派生，不硬编码死选项）+ 展开式记录卡（维度结果 / file:line 证据 / 反驳论证）。
 *
 * 后端未开启或未生成 → 404，此处显「无对抗审查记录」空态（非错误）。
 * ws/scanId 取自路由 params（对齐 DataFlowTab 习惯，router.tsx 作 <AdversarialReviewTab /> 挂载）。
 */

// 裁决筛选轴（"all" = 全部）；维度轴从数据派生（见 dims）。
const VERDICTS = ["all", "refuted", "survived", "unreviewed"] as const;

// 维度展示顺序（对齐 core 对抗审查 7 维）；记录里出现的未知维度尾随在后。
const DIMENSION_ORDER = [
  "defense_effective", "unreachable", "attacker_uncontrolled", "self_impact",
  "platform_protection", "authn_enforced", "authz_guard", "claim_mismatch",
];

/** 裁决 → 语义色 token（逐主题校对比，不用 tailwind 原生色阶）：驳回红 / 幸存绿 / 未审成弱化。 */
function verdictCls(verdict: ReviewRecord["review_verdict"]): string {
  if (verdict === "refuted") return "text-red";
  if (verdict === "survived") return "text-green";
  return "text-muted-foreground";
}

export function AdversarialReviewTab() {
  const { t } = useTranslation();
  const { workspace, scanId } = useParams<{ workspace: string; scanId: string }>();
  const ws = workspace ?? "";
  const id = scanId ?? "";
  const { data, error, isLoading } = useSWR(
    ws && id ? ["adversarial-review", ws, id] : null,
    () => fetchAdversarialReview(ws, id),
  );

  // 筛选器状态：verdict 下拉（"all"=全部）+ failed dimension 下拉（"all"=全部）。
  const [verdict, setVerdict] = useState<string>("all");
  const [dimension, setDimension] = useState<string>("all");

  // 可选维度（数据派生）：记录里出现过的 failed_dimensions，按 DIMENSION_ORDER 排、未知尾随。
  // ?? [] 兜底：产物缺字段（手改/旧版本文件）不炸整页（项目无全局 ErrorBoundary）。
  const dims = useMemo(() => {
    const seen = new Set(
      (data?.records ?? []).flatMap((r) => r.failed_dimensions ?? []),
    );
    const ordered = DIMENSION_ORDER.filter((d) => seen.has(d));
    for (const d of seen) if (!DIMENSION_ORDER.includes(d)) ordered.push(d);
    return ordered;
  }, [data]);

  const filtered = useMemo(
    () =>
      (data?.records ?? []).filter(
        (r) =>
          (verdict === "all" || r.review_verdict === verdict) &&
          (dimension === "all" || (r.failed_dimensions ?? []).includes(dimension)),
      ),
    [data, verdict, dimension],
  );

  if (error) {
    return (
      <div data-testid="adv-empty" className="p-6 text-sm text-muted-foreground">
        {t("workspaceDetail.adversarialReview.emptyHint")}
      </div>
    );
  }
  if (isLoading || !data) {
    return (
      <div className="p-6 text-sm text-muted-foreground">
        {t("workspaceDetail.adversarialReview.loading")}
      </div>
    );
  }
  // 畸形产物空值守卫：SSOT writer 恒写 summary，但手改/旧文件缺字段时
  // ?? 兜底渲染 0，不让整页卸载。
  const s = data.summary ?? { total: 0, refuted: 0, survived: 0, unreviewed: 0 };
  return (
    <div className="space-y-4">
      {/* summary 计数条：四项同一记录口径可加和（总计 = 驳回 + 幸存 + 未审成） */}
      <div
        data-testid="adv-summary"
        className="flex flex-wrap items-center gap-3 rounded-md border border-border bg-card p-3 text-sm"
      >
        <span className="font-medium">
          {t("workspaceDetail.adversarialReview.total")}: {s.total ?? 0}
        </span>
        <span className="text-red">
          {t("workspaceDetail.adversarialReview.refuted")}: {s.refuted ?? 0}
        </span>
        <span className="text-green">
          {t("workspaceDetail.adversarialReview.survived")}: {s.survived ?? 0}
        </span>
        <span className="text-muted-foreground">
          {t("workspaceDetail.adversarialReview.unreviewed")}: {s.unreviewed ?? 0}
        </span>
        {/* 双筛选轴（verdict 静态选项 / dimension 数据派生选项） */}
        <span className="ml-auto flex flex-wrap items-center gap-2">
          <select
            data-testid="adv-verdict-select"
            aria-label={t("workspaceDetail.adversarialReview.verdictLabel")}
            value={verdict}
            onChange={(e) => setVerdict(e.target.value)}
            className="rounded-md border border-border bg-background px-2 py-1 text-xs"
          >
            {VERDICTS.map((v) => (
              <option key={v} value={v}>
                {v === "all" ? t("workspaceDetail.adversarialReview.all") : v}
              </option>
            ))}
          </select>
          <select
            data-testid="adv-dimension-select"
            aria-label={t("workspaceDetail.adversarialReview.dimensionLabel")}
            value={dimension}
            onChange={(e) => setDimension(e.target.value)}
            className="rounded-md border border-border bg-background px-2 py-1 text-xs"
          >
            <option value="all">{t("workspaceDetail.adversarialReview.all")}</option>
            {dims.map((d) => (
              <option key={d} value={d}>
                {d}
              </option>
            ))}
          </select>
        </span>
      </div>
      {/* 记录卡区（展开式 details：维度结果 → file:line 证据 → 反驳/幸存论证） */}
      <div className="space-y-3">
        {filtered.map((r) => (
          <details
            key={`${r.vuln_class}-${r.finding_id}`}
            data-testid="adv-record"
            className="rounded-md border border-border p-3"
          >
            <summary className="cursor-pointer text-sm font-medium">
              <span className="mr-2 font-mono">{r.finding_id}</span>
              <span className="mr-2 text-muted-foreground">
                {String(r.before?.title ?? "")}
              </span>
              <span className={verdictCls(r.review_verdict)}>{r.review_verdict}</span>
            </summary>
            <div className="mt-2 space-y-2 text-xs">
              {(r.dimension_results ?? []).map((d, i) => (
                <div key={i}>
                  <span className={d.rebutted ? "text-red" : "text-muted-foreground"}>
                    {d.dimension}: {d.rebutted ? "rebutted" : "held"}
                  </span>{" "}
                  — {d.reason}
                  <ul className="ml-4 list-disc text-muted-foreground">
                    {(d.evidence ?? []).map((e, j) => (
                      <li key={j}>
                        <span className="font-mono">{e.location}</span> {e.snippet ?? ""}
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
              {r.rebuttal_reason && <p className="text-red">{r.rebuttal_reason}</p>}
              {r.survival_reason && (
                <p className="text-muted-foreground">{r.survival_reason}</p>
              )}
            </div>
          </details>
        ))}
        {filtered.length === 0 && (
          <p className="rounded-md border border-dashed border-border px-3 py-6 text-center text-sm text-muted-foreground">
            {t("workspaceDetail.adversarialReview.noMatch")}
          </p>
        )}
      </div>
    </div>
  );
}
