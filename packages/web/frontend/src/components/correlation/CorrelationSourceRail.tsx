import { useTranslation } from "react-i18next";
import { AlertCircle, ChevronRight } from "lucide-react";
import { GroupLabel } from "@/components/GroupLabel";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import type { CorrelationTopologyAnalysis, Repo, TopologyAuditLine, Workspace } from "@/api/types";
import { RepositoryMultiSelector } from "./RepositoryMultiSelector";
import { CorrelationTopologyAnalysisPanel } from "./TopologyAnalysisPanel";

interface Props {
  /** 工作区段（常驻——提交有效性依赖 ws；收起分析区时仍可见可切）。 */
  workspace: string;
  wsList: Workspace[];
  wsLoading: boolean;
  onWorkspaceChange: (ws: string) => void;
  /** 服务与分析段（可折叠——收起即纯手工模式，分析轮询不受影响）。 */
  repos: Repo[];
  selectedRepos: string[];
  onSelectRepos: (repos: string[]) => void;
  analysis: CorrelationTopologyAnalysis | null;
  starting: boolean;
  analysisError: string | null;
  historyEntries?: CorrelationTopologyAnalysis[];
  historyActiveId?: string | null;
  onSelectHistoryEntry?: (entry: CorrelationTopologyAnalysis) => void;
  onDeleteHistoryEntry?: (entry: CorrelationTopologyAnalysis) => void;
  historyDeletingId?: string | null;
  logLines: TopologyAuditLine[];
  logDropped?: number;
  onStart: () => void;
  onRetry: () => void;
  onCancel: () => void;
  analysisOpen: boolean;
  onAnalysisOpen: (open: boolean) => void;
}

/** 跨仓关联「来源轨道」（2026-09-09 重排，tabs 外常驻）：拓扑的来源——工作区（环境，
 *  仓库列表按 ws 隔离）→ 服务清单（勾选=参与拓扑）→ AI 分析 + 历史档案。图|表单|YAML
 *  是同一拓扑的三个透镜，切透镜不丢来源（与黑盒验证同理放 tabs 外）。
 *
 *  ws 是轨道首字段而非页面右上角的选择框（2026-09-04 曾挂类型切换行右端）：控制紧贴
 *  其效果域——未选 ws 时「请先选择 workspace」提示就在 Select 正下方，不再视线跳跃。
 *  「服务与分析」段可折叠（corr-analysis-toggle）；收起时轨道收窄为 ws 段宽度
 *  （ScanNewPage 条件 grid 列），手工画布尽量占满。 */
export function CorrelationSourceRail(props: Props) {
  const { t } = useTranslation();
  const wsEmpty = !props.wsLoading && props.wsList.length === 0;
  return (
    <aside className="min-w-0 space-y-2.5" aria-label={t("scan.correlation.sourceRail")}>
      {/* 工作区段：常驻——收起分析区也保留（纯手工用户提交仍须 ws，且切 ws 清分析域） */}
      <section className="space-y-1.5">
        <GroupLabel>{t("scan.fields.wsSelectLabel")}</GroupLabel>
        <Select value={props.workspace} onValueChange={props.onWorkspaceChange}>
          <SelectTrigger className="w-full font-mono text-xs" aria-label={t("scan.steps.workspace")}>
            <SelectValue placeholder={t("scan.fields.wsSelectPlaceholder")} />
          </SelectTrigger>
          <SelectContent>
            {wsEmpty ? (
              <SelectItem value="__empty__" disabled>{t("scan.fields.wsEmptyOption")}</SelectItem>
            ) : props.wsList.map((w) => (
              <SelectItem key={w.name} value={w.name}>{w.name}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        {wsEmpty && (
          <div className="flex items-center gap-1.5 text-xs text-amber">
            <AlertCircle className="h-3.5 w-3.5" />{t("scan.fields.wsEmptyHintUser")}
          </div>
        )}
      </section>

      {/* 服务与分析段：可折叠 */}
      <section className="space-y-2.5 border-t border-border pt-2.5">
        <button
          type="button"
          data-testid="corr-analysis-toggle"
          onClick={() => props.onAnalysisOpen(!props.analysisOpen)}
          aria-expanded={props.analysisOpen}
          className="flex w-full items-center gap-2 text-left"
        >
          <GroupLabel>{t("scan.correlation.railTitle")}</GroupLabel>
          <ChevronRight
            className={`size-3.5 text-muted-foreground transition-transform ${props.analysisOpen ? "rotate-90" : ""}`}
            aria-hidden
          />
        </button>
        {props.analysisOpen && (
          <div className="space-y-2.5">
            {props.workspace ? (
              <RepositoryMultiSelector repos={props.repos} selected={props.selectedRepos}
                onChange={props.onSelectRepos}
                disabled={props.starting || props.analysis?.status === "running" || props.analysis?.status === "queued"} />
            ) : <p className="text-xs text-muted-foreground">{t("scan.fields.selectWsFirst")}</p>}
            <p className="text-[11px] text-muted-foreground">{t("scan.correlation.analysis.hint")}</p>
            <CorrelationTopologyAnalysisPanel analysis={props.analysis} starting={props.starting}
              error={props.analysisError} logLines={props.logLines} logDropped={props.logDropped}
              onStart={props.onStart} onRetry={props.onRetry}
              onCancel={props.onCancel}
              historyEntries={props.historyEntries} historyActiveId={props.historyActiveId}
              onSelectHistoryEntry={props.onSelectHistoryEntry}
              onDeleteHistoryEntry={props.onDeleteHistoryEntry}
              historyDeletingId={props.historyDeletingId} />
          </div>
        )}
      </section>
    </aside>
  );
}
