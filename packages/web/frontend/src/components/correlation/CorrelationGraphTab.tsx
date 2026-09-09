import { useTranslation } from "react-i18next";
import { GroupLabel } from "@/components/GroupLabel";
import { Button } from "@/components/ui/button";
import type { CorrView } from "@/pages/ScanNewPage";
import type { TopologyDraftState } from "@/lib/correlation-topology-draft";
import { TopologyEditor } from "./TopologyEditor";

interface Props {
  topologyState: TopologyDraftState | null;
  onTopologyState: (state: TopologyDraftState) => void;
  /** 空态引导直达其他视图（表单/YAML 是同一拓扑的透镜）。 */
  onViewChange: (view: CorrView) => void;
  onRemoveNode: (repo: string) => void;
  scans: unknown[];
}

/** 图视图（2026-09-09 瘦身）：拓扑编辑器 = 拓扑本体；空态引导直达其他透镜。
 *  原「服务与分析」左轨道上提 ScanNewPage 常驻（CorrelationSourceRail，tabs 外——
 *  来源轨道三视图共享，切透镜不丢），本组件只剩右主区画布。 */
export function CorrelationGraphTab(props: Props) {
  const { t } = useTranslation();
  return props.topologyState ? (
    <section className="min-w-0 space-y-2.5">
      <GroupLabel>{t("scan.correlation.topology.editor")}</GroupLabel>
      <TopologyEditor state={props.topologyState} onState={props.onTopologyState} scans={props.scans}
        onRemoveNode={props.onRemoveNode} />
    </section>
  ) : (
    <div
      data-testid="corr-graph-empty"
      className="flex flex-col items-center gap-3 rounded-lg border border-dashed border-border px-4 py-8 text-center"
    >
      <p className="text-xs text-muted-foreground">{t("scan.correlation.graphEmptyTitle")}</p>
      <div className="flex flex-wrap items-center justify-center gap-2">
        <Button type="button" variant="outline" size="sm" onClick={() => props.onViewChange("form")}>
          {t("scan.correlation.graphEmptyForm")}
        </Button>
        <Button type="button" variant="outline" size="sm" onClick={() => props.onViewChange("yaml")}>
          {t("scan.correlation.graphEmptyYaml")}
        </Button>
      </div>
    </div>
  );
}
