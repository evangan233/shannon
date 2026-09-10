import { useEffect } from "react";
import { useTranslation } from "react-i18next";
import { AlertCircle } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { GroupLabel } from "@/components/GroupLabel";
import { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from "@/components/ui/select";
// 认证/HOST 块复用既有抽取组件（与白盒组合扫描/跨仓 gateway 同款）——黑盒验证的目标侧
// 配置与它们语义同构（登录态 + DNS 覆盖），不另起炉灶。
import { AuthFields, HostFields } from "@/components/ScanFormFields";
import { getScan } from "@/api/client";
import { useScans } from "@/routes/WorkspaceDetail/useScans";
import type { Workspace } from "@/api/types";
import {
  presetToAuthState, presetToHostState,
  type AuthFormState, type FormState, type HostFormState, type RerunPreset,
} from "@/pages/ScanNewPage";

interface Props {
  f: FormState;
  set: (patch: Partial<FormState>) => void;
  setAuth: (patch: Partial<AuthFormState>) => void;
  setHost: (patch: Partial<HostFormState>) => void;
  scanErr: string | null;
  urlErr: string | null;
  authErr: string | null;
  hostErr: string | null;
  workspace: string;
  wsList: Workspace[];
  onWorkspaceChange: (v: string) => void;
  wsLoading: boolean;
}

/** 可加黑盒的白盒任务口径（与 ScanDetail「加黑盒」按钮 whiteboxAddable 一致）：
 *  scan_type=whitebox ∧ status ∈ {completed, done, cancelled}——cancelled 也放行（取消过
 *  手动黑盒 run 的任务白盒产物仍完好），failed 不放（产物口径外，后端 422 兜底）。 */
const BLACKBOX_ADDABLE = new Set(["completed", "done", "cancelled"]);

/** 黑盒验证表单（D3 入口回归 2026-09-10，语义改为 add-run）：① 工作区 ② 已完成白盒任务
 *  选择器 ③ 目标 URL（必填，选中任务自动预填原黑盒目标）④ 认证（可选——无认证直连）
 *  ⑤ HOST 解析。提交由 ScanNewPage 黑盒分支走 addBlackboxToWhitebox（白盒任务下建 run-K），
 *  与详情页「加黑盒」按钮同后端路径。 */
export function BlackboxFormFields({
  f, set, setAuth, setHost, scanErr, urlErr, authErr, hostErr,
  workspace, wsList, onWorkspaceChange, wsLoading,
}: Props) {
  const { t } = useTranslation();
  const { scans, loading: scansLoading } = useScans(workspace || undefined);
  const candidates = scans.filter(
    (s) => s.scan_type === "whitebox" && BLACKBOX_ADDABLE.has(s.status),
  );
  const wsEmpty = !wsLoading && wsList.length === 0;

  // 选中任务 → 拉原任务黑盒配置预填（bb_url 优先兜底 web_url；认证/HOST 沿用原配置——
  // RerunPreset 形状 + presetToAuthState/presetToHostState，对齐组合扫描重跑预填语义）。
  // 仅在选择变化时拉（依赖 [workspace, f.reuseScanId]），用户手改 URL/认证不被覆盖。
  useEffect(() => {
    if (!workspace || !f.reuseScanId) return;
    let cancelled = false;
    getScan(workspace, f.reuseScanId)
      .then((detail) => {
        if (cancelled) return;
        const preset: RerunPreset = {
          url: detail.bb_url || detail.web_url || "",
          authProfileId: detail.auth_profile_id ?? undefined,
          authCredentialIds: detail.auth_credential_ids ?? undefined,
          auth: detail.authentication ?? undefined,
          hostProfileId: detail.host_profile_id ?? undefined,
          hostUrl: detail.host_url ?? undefined,
        };
        set({ url: preset.url ?? "" });
        setAuth(presetToAuthState(preset));
        setHost(presetToHostState(preset));
      })
      .catch(() => {
        /* 拉取失败留空让用户手填——不阻断表单（任务列表已确认任务存在）。 */
      });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [workspace, f.reuseScanId]);

  return (
    <div className="space-y-5" data-testid="blackbox-form">
      <div className="grid gap-4 sm:grid-cols-2">
        {/* ① 工作区（IA 不变量：任务按 ws 隔离，选任务前必须先选 ws） */}
        <section className="space-y-2">
          <GroupLabel>{t("scan.fields.wsSelectLabel")}</GroupLabel>
          <div className="space-y-1.5">
            <Select value={workspace} onValueChange={onWorkspaceChange}>
              <SelectTrigger className="w-full font-mono text-xs">
                <SelectValue placeholder={t("scan.fields.wsSelectPlaceholder")} />
              </SelectTrigger>
              <SelectContent>
                {wsEmpty ? (
                  <SelectItem value="__empty__" disabled>{t("scan.fields.wsEmptyOption")}</SelectItem>
                ) : wsList.map((w) => (
                  <SelectItem key={w.name} value={w.name}>{w.name}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            {wsEmpty && (
              <div className="flex items-center gap-1.5 text-xs text-amber">
                <AlertCircle className="h-3.5 w-3.5" />{t("scan.fields.wsEmptyHintUser")}
              </div>
            )}
          </div>
        </section>
        {/* ② 白盒任务选择器：只列可加黑盒的白盒终态任务。 */}
        <section className="space-y-2">
          <GroupLabel>{t("scan.blackbox.scanSelectLabel")}</GroupLabel>
          <div className="space-y-1.5">
            <Select value={f.reuseScanId || ""} onValueChange={(v) => set({ reuseScanId: v })}>
              <SelectTrigger className="w-full font-mono text-xs">
                <SelectValue placeholder={t("scan.blackbox.scanSelectPlaceholder")} />
              </SelectTrigger>
              <SelectContent>
                {!workspace || (scansLoading && !candidates.length) ? (
                  <SelectItem value="__empty__" disabled>
                    {workspace ? t("scan.blackbox.loadingScans") : t("scan.fields.selectWsFirst")}
                  </SelectItem>
                ) : candidates.length ? candidates.map((s) => (
                  <SelectItem key={s.scan_id} value={s.scan_id}>
                    {s.workflow_id ?? s.scan_id}{s.repo ? ` · ${s.repo}` : ""}
                  </SelectItem>
                )) : (
                  <SelectItem value="__empty__" disabled>{t("scan.blackbox.noScansOption")}</SelectItem>
                )}
              </SelectContent>
            </Select>
            {scanErr && <div className="text-destructive text-xs">{scanErr}</div>}
          </div>
        </section>
      </div>
      {/* ③ 目标 URL（必填——纯白盒任务无存量目标，此处补填；后端 422 兜底）。 */}
      <section className="space-y-2">
        <Label className="text-xs font-medium">{t("scan.blackbox.urlLabel")}</Label>
        <Input
          value={f.url}
          onChange={(e) => set({ url: e.target.value })}
          placeholder={t("scan.blackbox.urlPlaceholder")}
          size="sm"
          className="font-mono"
        />
        {urlErr && <div className="text-destructive text-xs">{urlErr}</div>}
        <div className="text-[11px] text-muted-foreground">{t("scan.blackbox.urlHint")}</div>
      </section>
      {/* ④ 认证（可选）+ ⑤ HOST 解析——复用组合扫描同款组件。 */}
      <AuthFields value={f.auth} onChange={setAuth} workspace={workspace} authErr={authErr ?? null} refreshSignal={0} />
      <HostFields value={f.host} onChange={setHost} workspace={workspace} error={hostErr} />
    </div>
  );
}
