import { useCallback, useMemo } from "react";
import { useTranslation } from "react-i18next";
import { TopologyEditor } from "./TopologyEditor";
import { crossServiceTopologyToDraft } from "@/lib/correlation-topology-draft";
import type { CorrelationDetail } from "@/api/types";

export type CorrTopology = NonNullable<CorrelationDetail["topology"]>;

/**
 * 结果页服务拓扑（2026-09-21）：复用扫描配置页 TopologyEditor 的画布渲染
 * （readonly 模式）——点阵画布 + pan/zoom/fit + 节点/边视觉与配置页同一语言
 * （此前自绘小 SVG 分层图被用户点名「丑」）。分层布局由 lib/topology-layout 算
 * （入口第 0 层在左，被调方按深度右移）换算进编辑器世界坐标；扫描产物边带
 * status 语义色（ok 绿 / low 琥珀 / error 红 / declared-missing 虚线）；点边在
 * 右栏看该边跨服务调用证据（calls 表），点服务节点看名称与角色。
 */
export function TopologyResultView({ topology }: { topology: CorrTopology }) {
  const { t } = useTranslation();
  // 扫描产物不可变（本页无编辑入口）——draft 一次性转换即可；onState 恒 noop。
  const state = useMemo(() => crossServiceTopologyToDraft(topology), [topology]);
  const noop = useCallback(() => {}, []);
  return (
    <div>
      <TopologyEditor state={state} onState={noop} readonly />
      <p className="mt-1 text-xs text-muted-foreground">
        {t("scan.correlation.resultCanvasHint")}
      </p>
    </div>
  );
}
