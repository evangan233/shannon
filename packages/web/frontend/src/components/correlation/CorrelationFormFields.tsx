import { useTranslation } from "react-i18next";
import { Trash2 } from "lucide-react";
import { GroupLabel } from "@/components/GroupLabel";
import { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { RepoCombobox } from "@/components/RepoCombobox";
import { useRepos } from "@/api/useRepos";
import { useScans } from "@/routes/WorkspaceDetail/useScans";
import { validateForm, type CorrFormState, type CorrRepoDraft, type CorrRole, type CorrProtocol } from "@/lib/correlation-yaml";
import { latestReusableScanId } from "@/lib/correlation-reuse";
import { formatCorrIssue } from "./corr-issues-i18n";

interface Props {
  state: CorrFormState;
  /** 表单交互路径：父层 updateCorr(s) 三方扇出（表单是源 → 图 + YAML 实时生成）。 */
  onState: (s: CorrFormState) => void;
  workspace: string;
}

/** 紧凑 segmented（角色/来源二选一）：aria-pressed 按钮，样式对齐 ScanFormFields 的来源 segmented。
 *  行式布局后字段不再带可见 Label——ariaLabel 补分组语义（role=group），供屏幕阅读器寻址。 */
function MiniSegmented({ value, options, onChange, ariaLabel }: {
  value: string;
  options: { value: string; label: string }[];
  onChange: (v: string) => void;
  ariaLabel?: string;
}) {
  return (
    <div role="group" aria-label={ariaLabel} className="inline-flex items-center gap-1 rounded-lg border border-border bg-muted/40 p-1 w-full">
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          onClick={() => onChange(o.value)}
          aria-pressed={value === o.value}
          className={`flex-1 px-2.5 py-1 rounded-md text-xs font-medium transition-colors ${
            value === o.value ? "bg-card text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground"
          }`}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

/** 已命名的 entrypoint 仓库名（星型边的 from 端）；无则 null。 */
function entryNameOf(s: CorrFormState): string | null {
  const e = s.repos.find((r) => r.role === "entrypoint" && r.repo.trim());
  return e ? e.repo : null;
}

/** 星型边自动补齐：backend 卡片命名后若无任何边触达且存在已命名 entrypoint → 补
 *  entrypoint→该仓库 一条边（协议取卡片 protocol）。幂等（已有边不重复补）。 */
function ensureStarEdge(s: CorrFormState, idx: number): CorrFormState {
  const card = s.repos[idx];
  if (!card || card.role !== "backend" || !card.repo.trim()) return s;
  const from = entryNameOf(s);
  if (!from || from === card.repo) return s;
  if (s.relations.some((e) => e.from === card.repo || e.to === card.repo)) return s;
  return { ...s, relations: [...s.relations, { from, to: card.repo, protocol: card.protocol }] };
}

function fmtTime(unix?: number): string {
  if (!unix) return "—";
  return new Date(unix * 1000).toLocaleString();
}

/** 表单 tab（2026-09-04 tabs 重组）：仓库行列表（仓库 | 角色 | 来源 | 协议 | 复用扫描）。
 *  原「表单模式整页容器」瘦身——ws 段/YAML 面板/relations chips/黑盒验证上提 tabs 外或
 *  并入其他视图：边的编辑主场在图 tab（边表/连线），chips 摘要与图内 TopologyTables 重复
 *  表达同一份边集合，撤除。 */
export function CorrelationFormFields({ state, onState, workspace }: Props) {
  const { t } = useTranslation();
  // repo 候选（卡片 RepoCombobox 数据源）：SWR 共享 key，与 ReposTab 同 ["repos", ws] 缓存。
  const { repos } = useRepos(workspace);
  // 复用候选：当前 ws 的 scans（useScans 共享 ["scans", ws] 缓存），按卡片仓库过滤 whitebox。
  const { scans } = useScans(workspace || undefined);

  // 复用候选（brief）：当前 ws 的 whitebox 扫描 + repo === 卡片仓库名
  const candidatesFor = (card: Pick<CorrRepoDraft, "repo">) =>
    card.repo.trim() ? scans.filter((s) => s.scan_type === "whitebox" && s.repo === card.repo) : [];

  // —— 卡片操作（全部经 onState 上抛，父层三方扇出：图 + YAML 实时重建） ——
  function addRepo() {
    const next: CorrRepoDraft = {
      repo: "",
      // role 逻辑（brief）：无 entrypoint 时默认 entrypoint，否则 backend（星型边在命名/角色
      // 变更时由 ensureStarEdge 补——边引用仓库名，须等卡片命名）。
      role: state.repos.some((r) => r.role === "entrypoint") ? "backend" : "entrypoint",
      protocol: "grpc",
      reuseScanId: null,
    };
    onState({ ...state, repos: [...state.repos, next] });
  }

  function removeRepo(i: number) {
    const name = state.repos[i]?.repo ?? "";
    onState({
      repos: state.repos.filter((_, j) => j !== i),
      // 删除卡片 → 清掉引用该仓库名的关联边
      relations: state.relations.filter((e) => e.from !== name && e.to !== name),
    });
  }

  function setCardName(i: number, name: string) {
    const old = state.repos[i]?.repo ?? "";
    const card = state.repos[i];
    // 来源跟随命名（2026-09-09 智能默认）：首次命名 → 默认复用最新成功白盒（无则现扫）；
    // 改名 → 携带的复用 id 不在新仓库候选（跨仓库携带提交会被后端拒）→ 重置为新仓库默认。
    const carried = card?.reuseScanId;
    const keepId = carried != null && name.trim()
      && candidatesFor({ repo: name }).some((s) => s.scan_id === carried);
    const reuseScanId = keepId ? carried : latestReusableScanId(scans, name);
    let s: CorrFormState = {
      ...state,
      repos: state.repos.map((r, j) => (j === i ? { ...r, repo: name, reuseScanId } : r)),
      // 仓改名 → 同步改写引用旧名的边（保住已建的拓扑）
      relations: state.relations.map((e) => ({
        ...e,
        from: e.from === old && name ? name : e.from,
        to: e.to === old && name ? name : e.to,
      })),
    };
    s = ensureStarEdge(s, i);
    onState(s);
  }

  function setCardRole(i: number, role: CorrRole) {
    let s: CorrFormState = { ...state, repos: state.repos.map((r, j) => (j === i ? { ...r, role } : r)) };
    s = ensureStarEdge(s, i);
    onState(s);
  }

  function setCardSource(i: number, mode: "rescan" | "reuse") {
    onState({
      ...state,
      repos: state.repos.map((r, j) =>
        j === i ? { ...r, reuseScanId: mode === "reuse" ? (r.reuseScanId ?? "") : null } : r),
    });
  }

  function setCardReuseScan(i: number, scanId: string) {
    onState({ ...state, repos: state.repos.map((r, j) => (j === i ? { ...r, reuseScanId: scanId } : r)) });
  }

  function setCardProtocol(i: number, protocol: CorrProtocol) {
    const target = state.repos[i]?.repo ?? "";
    const from = entryNameOf(state);
    onState({
      ...state,
      repos: state.repos.map((r, j) => (j === i ? { ...r, protocol } : r)),
      // 自动补的星型边（entrypoint→该仓库）跟随卡片协议，保持摘要与 YAML 一致
      relations: state.relations.map((e) =>
        e.to === target && e.from === from ? { ...e, protocol } : e),
    });
  }

  const issues = validateForm(state);

  return (
    <section className="space-y-2">
      <div className="flex items-center justify-between gap-2">
        <GroupLabel>{t("scan.correlation.reposSection")}</GroupLabel>
        {workspace && (
          <Button type="button" variant="outline" size="sm" onClick={addRepo}>
            {t("scan.correlation.addRepo")}
          </Button>
        )}
      </div>
      {!workspace ? (
        <div className="text-xs text-muted-foreground">{t("scan.fields.selectWsFirst")}</div>
      ) : state.repos.length === 0 ? (
        <div className="rounded-lg border border-dashed border-border px-3 py-4 text-xs text-muted-foreground">
          {t("scan.correlation.reposEmptyHint")}
        </div>
      ) : (
        <div className="overflow-hidden rounded-lg border border-border bg-card">
          {/* 列头（lg+ 单行铺开时才显示；字段可见 Label 已撤，列头即字段名） */}
          <div className="hidden gap-2 border-b border-border bg-muted/40 px-3 py-1.5 text-[11px] font-medium text-muted-foreground lg:grid lg:grid-cols-[minmax(0,1.2fr)_112px_104px_92px_minmax(0,1fr)]">
            <span>{t("scan.correlation.colRepo")}</span>
            <span>{t("scan.correlation.roleLabel")}</span>
            <span>{t("scan.correlation.sourceLabel")}</span>
            <span>{t("scan.correlation.protocolLabel")}</span>
            <span>{t("scan.correlation.colReuse")}</span>
          </div>
          {state.repos.map((card, i) => {
            const candidates = candidatesFor(card);
            const reuseOn = card.reuseScanId != null;
            return (
              <div
                key={i}
                data-testid="corr-repo-row"
                className="relative grid gap-x-2 gap-y-1.5 border-b border-border px-3 py-2.5 transition-colors last:border-b-0 hover:bg-muted/30 sm:grid-cols-2 lg:grid-cols-[minmax(0,1.2fr)_112px_104px_92px_minmax(0,1fr)] lg:items-center"
              >
                {card.role === "entrypoint" && (
                  <span className="absolute inset-y-0 left-0 w-[3px] bg-primary" aria-hidden />
                )}
                {/* 仓库 + 删除 */}
                <div className="flex items-center gap-1.5 sm:col-span-2 lg:col-span-1">
                  <div className="min-w-0 flex-1">
                    <RepoCombobox
                      repos={repos}
                      value={card.repo || null}
                      onChange={(v) => setCardName(i, v)}
                      placeholder={t("scan.repo.selectPlaceholder")}
                      searchPlaceholder={t("scan.repo.searchPlaceholder")}
                      emptyText={t("scan.repo.noMatch")}
                      ungroupedLabel={t("scan.repo.ungrouped")}
                      linkedLabel={t("repos.linkedBadge")}
                    />
                  </div>
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon-sm"
                    aria-label={t("scan.correlation.removeRepo")}
                    onClick={() => removeRepo(i)}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                </div>
                {/* 角色 */}
                <MiniSegmented
                  value={card.role}
                  ariaLabel={t("scan.correlation.roleLabel")}
                  options={[
                    { value: "entrypoint", label: t("scan.correlation.roleEntrypoint") },
                    { value: "backend", label: t("scan.correlation.roleBackend") },
                  ]}
                  onChange={(v) => setCardRole(i, v as CorrRole)}
                />
                {/* 来源 */}
                <MiniSegmented
                  value={reuseOn ? "reuse" : "rescan"}
                  ariaLabel={t("scan.correlation.sourceLabel")}
                  options={[
                    { value: "rescan", label: t("scan.correlation.sourceRescan") },
                    { value: "reuse", label: t("scan.correlation.sourceReuse") },
                  ]}
                  onChange={(v) => setCardSource(i, v as "rescan" | "reuse")}
                />
                {/* 协议 */}
                <Select value={card.protocol} onValueChange={(v) => setCardProtocol(i, v as CorrProtocol)}>
                  <SelectTrigger className="w-full text-xs" aria-label={t("scan.correlation.protocolLabel")}>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {(["grpc", "http", "graphql"] as const).map((p) => (
                      <SelectItem key={p} value={p}>{p}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {/* 复用扫描（固定占位列：rescan 显占位符保持网格稳定，不跳行高） */}
                <div className="flex min-h-8 items-center sm:col-span-2 lg:col-span-1">
                  {!reuseOn ? (
                    <span className="text-xs text-muted-foreground/50">—</span>
                  ) : !card.repo.trim() ? (
                    <span className="text-xs text-muted-foreground">{t("scan.correlation.selectRepoFirst")}</span>
                  ) : candidates.length === 0 ? (
                    <span className="text-xs text-muted-foreground">{t("scan.correlation.reuseEmpty")}</span>
                  ) : (
                    <Select value={card.reuseScanId || undefined} onValueChange={(v) => setCardReuseScan(i, v)}>
                      <SelectTrigger className="w-full text-xs" aria-label={t("scan.correlation.colReuse")}>
                        <SelectValue placeholder={t("scan.fields.reuseSelectPlaceholder")} />
                      </SelectTrigger>
                      <SelectContent>
                        {candidates.map((s) => (
                          <SelectItem key={s.scan_id} value={s.scan_id}>
                            <span className="font-mono text-xs">{s.workflow_id ?? s.scan_id}</span>
                            <span className="ml-1.5 text-[11px] text-muted-foreground">
                              （{fmtTime(s.created_at)} · {String(s.status)}）
                            </span>
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
      {/* 表单级校验（D1 validateForm；issue 文案经渲染层 i18n 映射——lib 产出中文硬编码，D7）。
          同步错误也会以红点亮在表单 tab 标签上（页面层 corr-tab-dot-form）。 */}
      {issues.length > 0 && (
        <div data-testid="corr-form-issues" className="space-y-0.5">
          {issues.map((m, i) => (
            <p key={i} className="text-destructive text-xs">{formatCorrIssue(m, t)}</p>
          ))}
        </div>
      )}
    </section>
  );
}
