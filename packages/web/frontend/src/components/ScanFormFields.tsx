import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { RepoCombobox } from "./RepoCombobox";
import { RepoQuickActions } from "./RepoQuickActions";
import { DeleteRepoOnFinishCheckbox } from "./DeleteRepoOnFinishCheckbox";
import { GroupLabel } from "./GroupLabel";
import { CredentialRows } from "./auth/CredentialRows";
import { AddRepoDialog } from "./AddRepoDialog";
import { CloneProgress } from "./CloneProgress";
import { listScans } from "@/api/client";
import { createAuthProfile } from "@/api/authProfiles";
import { useAuthProfiles } from "@/api/useAuthProfiles";
import { useHostProfiles } from "@/api/useHostProfiles";
import { useRepos } from "@/api/useRepos";
import type { ScanSummary, Workspace, AuthProfile, AuthProfileCredential, VerifyState } from "@/api/types";
import type { FormState, AuthFormState, HostFormState } from "../pages/ScanNewPage";
import { useAuth } from "@/auth/AuthContext";
import { apiErrorMessage } from "@/lib/apiError";
import { toast } from "sonner";
import { AlertCircle, Info } from "lucide-react";

/** AuthFormState（inline 临时填写）-> AuthProfile 创建 body（保存为档案）。
 *  保存全部角色（auth.accounts）为多角色 credential——档案本支持 credentials[]，完整存档多身份配置。
 *  credential id 占位（后端分配），verify_status=unverified（新建未经验证）。 */
function authToProfileBody(auth: AuthFormState, name: string): Partial<AuthProfile> {
  const credentials: AuthProfileCredential[] = auth.accounts.map((a) => ({
    id: "",
    role: a.role.trim() || "admin",
    username: a.username.trim(),
    verify_status: { state: "unverified" as VerifyState },
    ...(a.password ? { password: a.password } : {}),
  }));
  const flow = auth.loginFlow.split("\n").map((s) => s.trim()).filter(Boolean);
  return {
    name: name.trim(),
    login_url: auth.loginUrl.trim(),
    login_type: auth.loginType,
    ...(flow.length ? { login_flow: flow } : {}),
    credentials,
  };
}

/** 验证状态 → 徽章样式 + 图标（与 CredentialRow 同色系：success=绿✓ / failed=红✗ / unverified=黄●）。 */
function verifyBadge(st: VerifyState): { cls: string; icon: string } {
  return st === "success" ? { cls: "border-green/40 text-green", icon: "✓" }
    : st === "failed" ? { cls: "border-red/40 text-red", icon: "✗" }
    : st === "running" ? { cls: "border-blue/40 text-blue", icon: "●" }
    : { cls: "border-yellow/40 text-yellow", icon: "●" };
}
/** 档案整体状态：任一 success→可用；否则任一 running→验证中；否则任一 failed→不可用；否则未验证。 */
function overallState(creds: AuthProfileCredential[]): VerifyState {
  if (creds.some((c) => c.verify_status?.state === "success")) return "success";
  if (creds.some((c) => c.verify_status?.state === "running")) return "running";
  if (creds.some((c) => c.verify_status?.state === "failed")) return "failed";
  return "unverified";
}
/** login_url → host（档案卡显示用；解析失败回落原值）。 */
function hostOf(url: string): string {
  try { return new URL(url).host; } catch { return url; }
}

interface Props {
  type: "whitebox" | "blackbox";
  f: FormState;
  set: (patch: Partial<FormState>) => void;
  sourceErr: string | null;
  /** 黑盒 reuse 模式下未选白盒扫描的提示（仅 blackbox + reuse 模式传入）。 */
  reuseErr: string | null;
  urlErr: string | null;
  /** 黑盒登录配置校验错误（仅 blackbox 传入）。 */
  authErr: string | null;
  /** HOST source validation error (blackbox/combined only). */
  hostErr?: string | null;
  /** P2: 选定的目标 workspace——驱动 listRepos(ws) / listScans(ws) 与子组件 ws 参数 */
  workspace: string;
  /** P2: 用户可见的 ws 列表（P1 后端已过滤）——供下拉选项 */
  wsList: Workspace[];
  /** P2: ws 下拉变更回调 */
  onWorkspaceChange: (ws: string) => void;
  /** ws 列表加载中（防首帧 [] 误判为空态闪现提示） */
  wsLoading: boolean;
  /** 重跑预填的黑盒复用 scan_id（同 ws）；首帧保留预填值，不被 ws-change 清空 / 默认选最新覆盖。 */
  presetReuseScanId?: string;
}

/** 右栏认证核心（仅在 f.auth.enabled=展开 时挂载；#1 单一 disclosure：展开即启用）：
 *    coral 竖条标题 + 来源 segmented（使用档案 / 临时填写）+ 模式右栏内容。
 *  - inline 模式右栏：登录步骤（textarea）+ 存为档案（档案名+保存一行）。
 *  - profile 模式右栏：已选档案摘要卡 + 提示。
 *  顶格对齐左栏「目标服务」（grid items-start，折叠态占位与展开态核心互斥显隐）。 */
function RightAuthCore({ auth, setAuth, authErr, workspace, refreshSignal, onProfileSaved }: {
  auth: AuthFormState;
  setAuth: (patch: Partial<AuthFormState>) => void;
  authErr: string | null;
  workspace: string;
  refreshSignal: number;
  onProfileSaved: (profile: AuthProfile) => void;
}) {
  const { t } = useTranslation();
  return (
    <div className="space-y-3 fade-in">
      <div className="flex items-center gap-2">
        <span className="h-3 w-[3px] rounded-full bg-primary" aria-hidden />
        <h4 className="text-[13px] font-semibold">{t("scan.steps.auth")}</h4>
      </div>
      {/* 来源 segmented（使用档案 / 临时填写） */}
      <div className="inline-flex items-center gap-1 rounded-lg border border-border bg-muted/40 p-1 w-full">
        {(["profile", "inline"] as const).map((s) => (
          <button
            key={s}
            type="button"
            onClick={() => setAuth({ source: s })}
            aria-pressed={auth.source === s}
            className={`flex-1 px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
              auth.source === s ? "bg-card text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground"
            }`}
          >
            {t(`authProfiles.source${s === "inline" ? "Inline" : "Profile"}`)}
          </button>
        ))}
      </div>

      {/* 模式右栏内容 */}
      {auth.source === "inline" ? (
        <InlineRightEnhance auth={auth} setAuth={setAuth} ws={workspace} onProfileSaved={onProfileSaved} />
      ) : (
        <ProfileRightSummary auth={auth} workspace={workspace} refreshSignal={refreshSignal} />
      )}
      {/* profile 模式校验错误贴下方档案块显；inline 模式错误交下方 inline 块显。 */}
      {auth.source === "profile" && authErr && <div className="text-destructive text-xs">{authErr}</div>}

      <div className="flex items-start gap-1.5 text-[11px] text-muted-foreground leading-relaxed">
        <Info className="h-3.5 w-3.5 mt-0.5 flex-shrink-0" />
        <span>{t("scan.auth.infoNote")}</span>
      </div>
    </div>
  );
}

/** inline 模式右栏增强（对齐 preview #inlineRight）：登录步骤 + 存为档案（档案名+保存一行）。
 *  角色取凭据区 primary 填写值（accounts[0].role），保存入口与填写区在一起（非弹窗）。 */
function InlineRightEnhance({ auth, setAuth, ws, onProfileSaved }: {
  auth: AuthFormState;
  setAuth: (patch: Partial<AuthFormState>) => void;
  ws: string;
  onProfileSaved: (profile: AuthProfile) => void;
}) {
  const { t } = useTranslation();
  return (
    <div className="border-t border-border pt-3 space-y-3">
      <div className="space-y-1.5">
        <Label className="text-[11px] font-medium text-muted-foreground">
          {t("scan.auth.loginFlowLabel")} <span className="font-normal">({t("scan.auth.optional")})</span>
        </Label>
        <Textarea
          value={auth.loginFlow}
          onChange={(e) => setAuth({ loginFlow: e.target.value })}
          rows={3}
          placeholder={t("scan.auth.loginFlowHint")}
          size="sm"
          className="font-mono"
        />
      </div>
      {ws ? (
        <SaveAsProfileInline auth={auth} ws={ws} onSaved={onProfileSaved} />
      ) : (
        <div className="text-[11px] text-muted-foreground">{t("scan.fields.selectWsFirst")}</div>
      )}
    </div>
  );
}

/** profile 模式右栏摘要（对齐 preview #profileRight）：已选档案卡 + 提示。 */
function ProfileRightSummary({ auth, workspace, refreshSignal }: {
  auth: AuthFormState;
  workspace: string;
  refreshSignal: number;
}) {
  const { t } = useTranslation();
  // SWR 共享 key（同 BottomProfileBlock）；selected 查找本地派生。
  const { profiles, refresh } = useAuthProfiles(workspace);
  useEffect(() => { void refresh(); }, [refreshSignal, refresh]);
  const selected = profiles.find((p) => p.id === auth.profileId);
  if (!selected) {
    return (
      <div className="border-t border-border pt-3 space-y-3">
        <div className="text-[11px] text-muted-foreground">{t("scan.auth.multiRoleHint")}</div>
      </div>
    );
  }
  const ov = overallState(selected.credentials);
  const ob = verifyBadge(ov);
  return (
    <div className="border-t border-border pt-3 space-y-3">
      <div className="space-y-1.5">
        <Label className="text-[11px] font-medium text-muted-foreground">{t("scan.auth.selectedProfile")}</Label>
        <div className="rounded-lg border border-border bg-secondary p-3 space-y-1.5">
          <div className="flex items-center gap-2">
            <span className="text-[13px] font-semibold">{selected.name}</span>
            <span className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10.5px] font-semibold ${ob.cls}`}>
              <span aria-hidden>{ob.icon}</span>
              {t(`authProfiles.overall.${ov}`)}
            </span>
          </div>
          <div className="flex items-center gap-2 text-[11px] font-mono text-muted-foreground">
            <span>{hostOf(selected.login_url)}</span>
            <span>·</span>
            <span>{selected.credentials.length} {t("authProfiles.credentials")}</span>
          </div>
          <div className="flex items-center gap-2 text-[11px] pt-1">
            <span className="font-mono text-muted-foreground">{selected.login_url}</span>
            <span className="inline-flex items-center rounded-full bg-background px-2 py-0.5 text-[10px] font-semibold text-muted-foreground">
              {t(`scan.auth.loginType.${selected.login_type}`)}
            </span>
          </div>
        </div>
      </div>
      <div className="flex items-start gap-1.5 text-[10.5px] text-muted-foreground leading-relaxed">
        <Info className="h-3.5 w-3.5 mt-0.5 flex-shrink-0 text-primary" />
        <span>{t("scan.auth.multiRoleHint")}</span>
      </div>
    </div>
  );
}

/** inline 模式「保存为档案」--与临时填写右栏同处，展开后填档案名（角色取凭据区 accounts[0].role），
 *  提交调 createAuthProfile，成功后 onSaved(新档案) 回调让父级切 profile 模式并选中。
 *  保存前置校验：loginUrl + primary username 必填（profile 必备），缺则 toast 拦截不发请求。 */
function SaveAsProfileInline({ auth, ws, onSaved }: {
  auth: AuthFormState;
  ws: string;
  onSaved: (profile: AuthProfile) => void;
}) {
  const { t } = useTranslation();
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);

  async function onSave(e: React.FormEvent) {
    e.preventDefault();
    if (!auth.loginUrl.trim() || !auth.accounts[0]?.username.trim()) {
      toast.error(t("scan.auth.saveNeedFields"));
      return;
    }
    if (!name.trim()) return;
    setBusy(true);
    try {
      const profile = await createAuthProfile(ws, authToProfileBody(auth, name));
      toast.success(t("scan.auth.saveSuccess"));
      setName("");
      onSaved(profile);
    } catch (err) {
      toast.error(apiErrorMessage(err, t("authProfiles.createFailed")));
    } finally {
      setBusy(false);
    }
  }

  // 保存前置：loginUrl + primary username 必填（档案 credential 必备）。未填则按钮禁用 + 常驻提示。
  const canSave = !!auth.loginUrl.trim() && !!auth.accounts[0]?.username.trim();

  return (
    <form onSubmit={onSave} className="space-y-1.5">
      <Label className="text-[11px] font-medium text-muted-foreground">{t("scan.auth.saveAsProfile")}</Label>
      <div className="flex items-center gap-2">
        <Input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder={t("scan.auth.profileNamePlaceholder")}
          size="sm"
          className="flex-1 min-w-0"
          required
        />
        <Button type="submit" size="sm" variant="outline" disabled={!canSave || busy} className="shrink-0 text-xs">
          {busy ? "…" : t("scan.auth.saveAsProfile")}
        </Button>
      </div>
      {!canSave ? (
        <div className="text-[10.5px] text-muted-foreground leading-relaxed">{t("scan.auth.saveNeedFields")}</div>
      ) : (
        <div className="text-[10.5px] text-muted-foreground leading-relaxed">{t("scan.auth.saveAsProfileHint")}</div>
      )}
    </form>
  );
}

/** inline 模式下方核心块：登录入口（全宽）+ 凭据区（全宽 CredentialRows，含 primary accounts[0] 与附加角色）。
 *  字段经 setAuth 回写 FormState.auth.accounts；buildBody 转 ScanAuthentication 发后端。 */
function BottomInlineBlock({ auth, setAuth, authErr }: {
  auth: AuthFormState;
  setAuth: (patch: Partial<AuthFormState>) => void;
  authErr: string | null;
}) {
  const { t } = useTranslation();
  return (
    <div className="fade-in border-t border-border pt-4 space-y-3">
      {/* 登录入口（全宽） */}
      <div className="rounded-lg border border-border bg-secondary p-3 space-y-2">
        <GroupLabel>{t("scan.auth.entryGroup")}</GroupLabel>
        <div className="space-y-1.5">
          <Label className="text-xs font-medium">{t("scan.auth.loginTypeLabel")}</Label>
          <div className="inline-flex flex-wrap items-center gap-1 rounded-lg border border-border bg-muted/40 p-1">
            {(["form", "sso", "api", "basic"] as const).map((v) => (
              <button
                key={v}
                type="button"
                onClick={() => setAuth({ loginType: v })}
                aria-pressed={auth.loginType === v}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                  auth.loginType === v ? "bg-card text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground"
                }`}
              >
                {t(`scan.auth.loginType.${v}`)}
              </button>
            ))}
          </div>
        </div>
        <div className="space-y-1.5">
          <Label className="text-xs font-medium">{t("scan.auth.loginUrlLabel")}</Label>
          <Input
            value={auth.loginUrl}
            onChange={(e) => setAuth({ loginUrl: e.target.value })}
            placeholder="https://example.com/login"
            size="sm"
            className="font-mono"
          />
        </div>
      </div>

      {/* 凭据（全宽，所有角色同框同尺寸；accounts[0]=primary 不可删，附加角色可删） */}
      <div className="space-y-2">
        <GroupLabel>{t("scan.auth.credentialsGroup")}</GroupLabel>
        <CredentialRows
          value={auth.accounts}
          onChange={(next) => setAuth({ accounts: next })}
          allowMulti
          lockFirstRow
        />
      </div>
      {authErr && <div className="text-destructive text-xs mt-2">{authErr}</div>}
    </div>
  );
}

/** profile 模式下方块（对齐 preview #bottomProfile，角色单选→多选 2026-08-06）：
 *    左列档案卡列表（点选 → setAuth({profileId, credentialIds=全选})）
 *    右列选中档案详情 + 角色多选（复选框，默认全选，全选/取消全选切换 + 计数）。
 *  切档案 → 默认全选新档案所有角色（防残留旧角色 id 指向新档案里不存在的角色）。 */
function BottomProfileBlock({ auth, setAuth, workspace, refreshSignal }: {
  auth: AuthFormState;
  setAuth: (patch: Partial<AuthFormState>) => void;
  workspace: string;
  refreshSignal: number;
}) {
  const { t } = useTranslation();
  // SWR 共享 key（2026-08-17 批次 Task 5）：与档案管理页同 ["auth-profiles", ws] 缓存，
  // 浏览过档案 tab 后此下拉即时填充。refreshSignal（inline 保存新档案后递增）→ mutate。
  const { profiles, loading, error, refresh } = useAuthProfiles(workspace);
  const loadFailed = error !== null;
  useEffect(() => { void refresh(); }, [refreshSignal, refresh]);

  const selected = profiles.find((p) => p.id === auth.profileId);

  if (!workspace) {
    return <div className="text-xs text-muted-foreground">{t("scan.fields.selectWsFirst")}</div>;
  }
  if (loading) {
    return <div className="text-xs text-muted-foreground">{t("common.loading")}</div>;
  }

  const toggleRole = (id: string) => {
    const has = auth.credentialIds.includes(id);
    setAuth({ credentialIds: has ? auth.credentialIds.filter((x) => x !== id) : [...auth.credentialIds, id] });
  };
  const allSelected = !!selected && selected.credentials.every((c) => auth.credentialIds.includes(c.id));
  const toggleAll = () => {
    if (!selected) return;
    setAuth({ credentialIds: allSelected ? [] : selected.credentials.map((c) => c.id) });
  };

  return (
    <div className="fade-in border-t border-border pt-4">
      <div className="flex items-center gap-2 mb-3">
        <span className="h-3 w-[3px] rounded-full bg-primary" aria-hidden />
        <h4 className="text-[12px] font-semibold text-muted-foreground">{t("scan.auth.selectProfileLabel")}</h4>
        <span className="text-[10.5px] text-muted-foreground">{t("scan.auth.selectProfileCaption")}</span>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-[minmax(0,20rem)_minmax(0,1fr)] gap-4 items-start">
        {/* 左：档案卡列表 */}
        <div className="space-y-2">
          <GroupLabel>{t("scan.auth.profileListLabel")}</GroupLabel>
          {profiles.length === 0 ? (
            <div className="rounded-lg border border-dashed border-border bg-card p-3 text-xs text-muted-foreground">
              {loadFailed ? t("common.loadFailed") : t("authProfiles.empty")}
            </div>
          ) : (
            profiles.map((p) => {
              const ov = overallState(p.credentials);
              const ob = verifyBadge(ov);
              const sel = p.id === auth.profileId;
              return (
                <button
                  key={p.id}
                  type="button"
                  onClick={() => setAuth({ profileId: p.id, credentialIds: p.credentials.map((c) => c.id) })}
                  aria-pressed={sel}
                  className={`w-full text-left rounded-lg border p-3 transition-colors flex flex-col gap-1.5 ${
                    sel ? "border-primary bg-primary/5 shadow-sm" : "border-border bg-card hover:border-foreground/20"
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <span className="text-[13px] font-semibold">{p.name}</span>
                    {p.scope === "system" && (
                      <span
                        className="inline-flex items-center rounded-full border border-border bg-muted/40 px-1.5 py-0.5 text-[10px] font-semibold text-muted-foreground"
                        title={t("authProfiles.systemHint")}
                      >
                        {t("authProfiles.systemBadge")}
                      </span>
                    )}
                    <span className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10.5px] font-semibold ${ob.cls}`}>
                      <span aria-hidden>{ob.icon}</span>
                      {t(`authProfiles.overall.${ov}`)}
                    </span>
                  </div>
                  <div className="flex items-center gap-2 text-[11px] font-mono text-muted-foreground">
                    <span>{hostOf(p.login_url)}</span>
                    <span>·</span>
                    <span>{p.credentials.length} {t("authProfiles.credentials")}</span>
                  </div>
                </button>
              );
            })
          )}
        </div>

        {/* 右：选中档案详情 + 角色多选 */}
        {selected ? (
          <div className="space-y-3 rounded-lg border border-border bg-secondary p-3.5">
            <div>
              <div className="text-[14px] font-semibold">{selected.name}</div>
              <div className="flex items-center gap-2 text-xs mt-1.5">
                <span className="font-mono text-muted-foreground">{selected.login_url}</span>
                <span className="inline-flex items-center rounded-full bg-background px-2 py-0.5 text-[10.5px] font-semibold text-muted-foreground">
                  {t(`scan.auth.loginType.${selected.login_type}`)}
                </span>
              </div>
            </div>
            <div className="border-t border-border" />
            <div>
              <div className="flex items-center justify-between mb-2">
                <div className="text-[11px] font-semibold text-muted-foreground">
                  {t("scan.auth.selectRole")}
                  <span className="font-normal text-muted-foreground">（{t("scan.auth.multiRoleDefaultAll")}）</span>
                </div>
                <button
                  type="button"
                  onClick={toggleAll}
                  className="text-[10.5px] font-medium text-primary hover:underline"
                >
                  {allSelected ? t("scan.auth.deselectAllRoles") : t("scan.auth.selectAllRoles")}
                </button>
              </div>
              <div className="space-y-2">
                {selected.credentials.map((c) => {
                  const st = c.verify_status?.state ?? "unverified";
                  const b = verifyBadge(st);
                  const sel = auth.credentialIds.includes(c.id);
                  return (
                    <button
                      key={c.id}
                      type="button"
                      onClick={() => toggleRole(c.id)}
                      aria-pressed={sel}
                      className={`w-full flex items-center gap-2.5 rounded-lg border p-2.5 transition-colors text-left ${
                        sel ? "border-primary bg-primary/5 shadow-sm" : "border-border bg-card hover:border-foreground/20"
                      }`}
                    >
                      <span className={`w-4 h-4 rounded border-2 flex-none flex items-center justify-center ${sel ? "border-primary bg-primary" : "border-input"}`}>
                        {sel && (
                          <svg className="w-3 h-3 text-primary-foreground" viewBox="0 0 12 12" fill="none">
                            <path d="M2.5 6L5 8.5L9.5 3.5" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
                          </svg>
                        )}
                      </span>
                      <div className="flex-1 min-w-0">
                        <span className="text-[13px] font-medium font-mono">
                          {c.role} <span className="font-normal text-muted-foreground">· {c.username}</span>
                        </span>
                        {st === "failed" && c.verify_status?.failure_detail && (
                          <div className="text-[11px] text-red/80 mt-0.5">{c.verify_status.failure_detail}</div>
                        )}
                      </div>
                      <span className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10.5px] font-semibold flex-none ${b.cls}`}>
                        <span aria-hidden>{b.icon}</span>
                        {t(`authProfiles.verify.${st}`)}
                      </span>
                    </button>
                  );
                })}
              </div>
              <div className="mt-2 text-[10.5px] text-muted-foreground">
                {t("scan.auth.rolesSelected", { n: auth.credentialIds.length, m: selected.credentials.length })}
              </div>
            </div>
            <div className="border-t border-border" />
            <div className="flex items-start gap-1.5 text-[11px] text-muted-foreground leading-relaxed">
              <Info className="h-3.5 w-3.5 mt-0.5 flex-shrink-0" />
              <span>{t("scan.auth.profileRoleHint")}</span>
            </div>
          </div>
        ) : (
          <div className="rounded-lg border border-dashed border-border bg-card p-4 text-xs text-muted-foreground">
            {t("scan.auth.selectProfilePlaceholder")}
          </div>
        )}
      </div>
    </div>
  );
}

/** HOST 档案选择器（profile 模式内容）：拉取当前 ws 的 host-profiles，下拉单选。
 *  镜像 BottomProfileBlock 的 listAuthProfiles 消费范式，但 HOST 是单选（无角色多选）故用 Select 更轻。 */
function HostProfilePicker({ host, setHost, workspace }: {
  host: HostFormState;
  setHost: (patch: Partial<HostFormState>) => void;
  workspace: string;
}) {
  const { t } = useTranslation();
  // SWR 共享 key（2026-08-17 批次 Task 5）：与 HOST 档案管理页同缓存。
  const { profiles, loading, error } = useHostProfiles(workspace || undefined);
  const loadFailed = error !== null;

  if (!workspace) {
    return <div className="text-xs text-muted-foreground">{t("scan.fields.selectWsFirst")}</div>;
  }
  if (loading) {
    return <div className="text-xs text-muted-foreground">{t("common.loading")}</div>;
  }
  return (
    <Select value={host.profileId} onValueChange={(v) => setHost({ profileId: v })}>
      <SelectTrigger className="w-full text-xs">
        <SelectValue placeholder={t("scan.host.selectProfile")} />
      </SelectTrigger>
      <SelectContent>
        {profiles.length === 0 ? (
          <SelectItem value="__empty__" disabled>
            {loadFailed ? t("common.loadFailed") : t("hostProfiles.empty")}
          </SelectItem>
        ) : profiles.map((p) => (
          <SelectItem key={p.id} value={p.id}>
            <span className="font-mono text-xs">{p.name}</span>
            <span className="ml-1.5 text-[11px] text-muted-foreground">
              · {p.mappings.length} {t("hostProfiles.mappingsCount")}
            </span>
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

/** 共享认证字段块（Task 9）：白盒「同时发起黑盒扫描」组合展开区复用黑盒认证编辑能力。
 *  受控组件——value/onChange 读写 AuthFormState；自包含堆叠布局：
 *    1. 认证行（标题 + 状态 + 「配置登录」/「收起」按钮，单一 disclosure：展开即启用）。
 *    2. 展开后：来源 segmented（使用档案 / 临时填写）+ 对应字段块（复用 BottomInlineBlock / BottomProfileBlock）。
 *  黑盒分支保留其双栏布局（RightAuthCore + Bottom*），本组件服务白盒组合展开区（单栏堆叠）；
 *  字段映射共用 ScanNewPage.assignAuthToBody，保证两条分支 buildBody 一致。 */
export function AuthFields({ value, onChange, workspace, authErr, refreshSignal }: {
  value: AuthFormState;
  onChange: (patch: Partial<AuthFormState>) => void;
  workspace: string;
  authErr: string | null;
  refreshSignal: number;
}) {
  const { t } = useTranslation();
  // 草稿信号（折叠态按钮显「已配置」标记，折叠不丢配置）——与黑盒分支同款判定。
  const hasDraft = !!(value.loginUrl.trim() || value.loginFlow.trim() || value.profileId
    || value.accounts.some((a) => a.username.trim() || a.password.trim()));
  return (
    <div className="space-y-3">
      {/* 认证行：标题 + 状态 + 展开/收起按钮（#1 单一 disclosure：展开即启用） */}
      <div className="flex items-center gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <h4 className="text-[13px] font-semibold">{t("scan.steps.auth")}</h4>
            <span className="rounded-full bg-secondary px-2 py-0.5 text-[10.5px] font-semibold text-muted-foreground">
              {t("scan.tags.optional")}
            </span>
          </div>
          <div className="text-[11.5px] text-muted-foreground mt-0.5">
            {value.enabled ? t("scan.auth.statusEnabled") : t("scan.auth.statusUnauth")}
          </div>
        </div>
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="min-w-[5.5rem]"
          onClick={() => onChange({ enabled: !value.enabled })}
        >
          {value.enabled
            ? t("scan.auth.collapse")
            : hasDraft ? t("scan.auth.configureDraft") : t("scan.auth.configure")}
        </Button>
      </div>

      {/* 展开后：来源 segmented + 字段块（复用黑盒 Bottom*） */}
      {value.enabled && (
        <div className="space-y-3 fade-in">
          <div className="inline-flex items-center gap-1 rounded-lg border border-border bg-muted/40 p-1 w-full">
            {(["profile", "inline"] as const).map((s) => (
              <button
                key={s}
                type="button"
                onClick={() => onChange({ source: s })}
                aria-pressed={value.source === s}
                className={`flex-1 px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                  value.source === s ? "bg-card text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground"
                }`}
              >
                {t(`authProfiles.source${s === "inline" ? "Inline" : "Profile"}`)}
              </button>
            ))}
          </div>
          {value.source === "profile" ? (
            <BottomProfileBlock auth={value} setAuth={onChange} workspace={workspace} refreshSignal={refreshSignal} />
          ) : (
            <BottomInlineBlock auth={value} setAuth={onChange} authErr={authErr} />
          )}
          {/* profile 模式校验错误贴下方档案块显；inline 模式错误由 BottomInlineBlock 内部显。 */}
          {value.source === "profile" && authErr && (
            <div className="text-destructive text-xs">{authErr}</div>
          )}
        </div>
      )}
    </div>
  );
}

/** 共享 HOST 字段块（2026-08-13）：白盒「同时发起黑盒扫描」组合展开区与黑盒分支复用。
 *  受控组件--value/onChange 读写 HostFormState；自包含堆叠布局：
 *    1. HOST 行（标题 + 状态 + 「配置 HOST」/「收起」按钮，单一 disclosure：展开即启用）。
 *    2. 展开后：来源 segmented（使用档案 / 填写链接）+ 对应字段块（HostProfilePicker / URL 输入）。
 *  字段映射共用 ScanNewPage.assignHostToBody，保证两条分支 buildBody 一致。
 *  HOST 与认证独立、非互斥--二者各管各的：auth 管登录态，host 管 DNS 覆盖。 */
export function HostFields({ value, onChange, workspace, error }: {
  value: HostFormState;
  onChange: (patch: Partial<HostFormState>) => void;
  workspace: string;
  error?: string | null;
}) {
  const { t } = useTranslation();
  // 草稿信号（折叠态按钮显「已配置」标记，折叠不丢配置）--选了档案或填了 url 即视为已配置。
  const hasDraft = !!(value.profileId || value.hostUrl.trim());
  return (
    <section className="space-y-2">
      {/* HOST 行：标题 + 状态 + 展开/收起按钮（#1 单一 disclosure：展开即启用） */}
      <div className="flex items-center gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <h3 className="text-[13px] font-semibold">{t("scan.host.sectionLabel")}</h3>
            <span className="rounded-full bg-secondary px-2 py-0.5 text-[10.5px] font-semibold text-muted-foreground">
              {t("scan.tags.optional")}
            </span>
          </div>
          <div className="text-[11.5px] text-muted-foreground mt-0.5">
            {value.enabled ? t("scan.host.statusOn") : t("scan.host.statusOff")}
          </div>
        </div>
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="min-w-[5.5rem]"
          onClick={() => onChange({ enabled: !value.enabled })}
        >
          {value.enabled
            ? t("scan.host.collapse")
            : hasDraft ? t("scan.host.configureDraft") : t("scan.host.configure")}
        </Button>
      </div>
      {value.enabled && (
        <div className="space-y-2.5 fade-in">
          {/* 来源 segmented（使用档案 / 填写链接）--镜像 RightAuthCore 的 segmented toggle */}
          <div className="inline-flex items-center gap-1 rounded-lg border border-border bg-muted/40 p-1 w-full">
            {(["profile", "url"] as const).map((m) => (
              <button
                key={m}
                type="button"
                onClick={() => onChange({ mode: m })}
                aria-pressed={value.mode === m}
                className={`flex-1 px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                  value.mode === m ? "bg-card text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground"
                }`}
              >
                {m === "profile" ? t("scan.host.sourceProfile") : t("scan.host.sourceUrl")}
              </button>
            ))}
          </div>
          {value.mode === "profile" ? (
            <HostProfilePicker host={value} setHost={onChange} workspace={workspace} />
          ) : (
            <Input
              value={value.hostUrl}
              onChange={(e) => onChange({ hostUrl: e.target.value })}
              placeholder={t("scan.host.urlPlaceholder")}
              size="sm"
              className="font-mono"
            />
          )}
          <div className="flex items-start gap-1.5 text-[11px] text-muted-foreground leading-relaxed">
            <Info className="h-3.5 w-3.5 mt-0.5 flex-shrink-0" />
            <span>{t("scan.host.infoNote")}</span>
          </div>
          {error && <div className="text-destructive text-xs">{error}</div>}
        </div>
      )}
    </section>
  );
}

export function ScanFormFields({
  type,
  f,
  set,
  sourceErr,
  reuseErr,
  urlErr,
  authErr,
  hostErr,
  workspace,
  wsList,
  onWorkspaceChange,
  wsLoading,
  presetReuseScanId,
}: Props) {
  const { t } = useTranslation();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const [addOpen, setAddOpen] = useState(false);
  // 黑盒「复用白盒结果」候选：当前 ws 的 whitebox scans（按 created_at 倒序，listScans 契约）。
  const [wbScans, setWbScans] = useState<ScanSummary[]>([]);
  // 标记「候选已为哪个 ws 加载完成」——smart-default 据此判断，避免依赖 wbLoading（effect 同帧
  // 读到旧值导致提前翻转：ws 刚选定时 listScans 的 setWbLoading(true) 尚未提交）。
  const [wbLoadedFor, setWbLoadedFor] = useState<string | null>(null);
  // ProfilePicker 刷新信号：inline 保存为新档案后递增 -> 触发重拉（须在所有 early return 之前，
  // 守 hooks 规则--白盒提前 return 不跳过此 useState）。onProfileSaved 在黑盒区定义（用 setAuth）。
  const [profileRefresh, setProfileRefresh] = useState(0);

  // P2: repo 列表按选定 ws 拉取（SWR 共享 key，2026-08-17 批次 Task 5——与 ReposTab
  // 同 ["repos", ws] 缓存：浏览过仓库 tab 后表单下拉即时填充）。
  // ws 未选 → key null 挂起（路径无意义）。addOpen 关闭（clone 对话框完成）时 refresh。
  const { repos, refresh: refreshRepos } = useRepos(workspace);
  useEffect(() => { if (!addOpen) void refreshRepos(); }, [addOpen, refreshRepos]);

  // 黑盒复用候选：按选定 ws 拉取其 whitebox scans。ws 切换 -> 旧 scan_id 失效，清空待重选。
  // 重跑预填（presetReuseScanId）：首帧保留预填值（已在 f.reuseScanId），仅拉候选验证，
  // 跳过清空与「默认选最新」；ws 切换后走原逻辑（预填仅对原 ws 一次性生效）。
  const presetDoneRef = useRef(false);
  useEffect(() => {
    if (type !== "blackbox" || !workspace) {
      setWbScans([]);
      setWbLoadedFor(null);
      return;
    }
    if (!presetDoneRef.current && presetReuseScanId) {
      presetDoneRef.current = true;
      listScans(workspace)
        .then((all) => {
          setWbScans(all.filter((s) => s.scan_type === "whitebox"));
          setWbLoadedFor(workspace);
        })
        .catch(() => {
          setWbScans([]);
          setWbLoadedFor(workspace);
        });
      return;
    }
    presetDoneRef.current = true;
    set({ reuseScanId: "" });
    listScans(workspace)
      .then((all) => {
        setWbScans(all.filter((s) => s.scan_type === "whitebox"));
        setWbLoadedFor(workspace);
      })
      .catch(() => {
        setWbScans([]);
        setWbLoadedFor(workspace);
      });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [type, workspace]);

  // 默认选最新一条白盒（listScans 倒序，[0] = 最新）——复用「最新白盒」直觉，但显式可选。
  // wbLoadedFor===workspace 守卫：等候选确为当前 ws 加载完才选，避免 ws 切换瞬间旧候选误选。
  useEffect(() => {
    if (type === "blackbox" && !f.reuseScanId && wbLoadedFor === workspace && wbScans.length > 0) {
      set({ reuseScanId: wbScans[0].scan_id });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [type, f.reuseScanId, wbScans, wbLoadedFor, workspace]);

  const selectedRepoObj = repos.find((r) => r.name === f.selectedRepo);
  const selectedRepoState = selectedRepoObj?.state;

  // —— 共用：仓库选择器（入口已收窄——仅工作区已下载仓库，无本地路径分支） ——
  // ws 未选时不渲染仓库 picker / 添加按钮（listRepos 必须 ws）
  const repoPicker = workspace ? (
    <div className="space-y-2">
      <RepoCombobox
        repos={repos}
        value={f.selectedRepo || null}
        onChange={(v) => set({ selectedRepo: v })}
        placeholder={t("scan.repo.selectPlaceholder")}
        searchPlaceholder={t("scan.repo.searchPlaceholder")}
        emptyText={t("scan.repo.noMatch")}
        ungroupedLabel={t("scan.repo.ungrouped")}
        linkedLabel={t("repos.linkedBadge")}
      />
      <Button variant="outline" size="sm" onClick={() => setAddOpen(true)}>{t("scan.repo.addBtn")}</Button>
      {f.selectedRepo && selectedRepoState && selectedRepoState !== "ready" && (
        selectedRepoState === "cloning" || selectedRepoState === "pulling"
          ? <CloneProgress ws={workspace} name={f.selectedRepo} />
          : <div className="text-xs text-destructive">{t("scan.repo.notReady", { state: selectedRepoState })}</div>
      )}
      {/* C 段（2026-09-03）：ready 仓库的快捷操作条——切分支/更新，免跑去仓库页 */}
      {selectedRepoObj?.state === "ready" && (
        <RepoQuickActions workspace={workspace} repo={selectedRepoObj} />
      )}
      <AddRepoDialog ws={workspace} open={addOpen} onOpenChange={setAddOpen}
        onCreated={(name) => set({ selectedRepo: name })} />
    </div>
  ) : (
    <div className="text-xs text-muted-foreground">{t("scan.fields.selectWsFirst")}</div>
  );

  // —— 共用：workspace 选择器（P2: 替代原自由文本 wsName + 自动派生 + 冲突检测） ——
  const wsEmpty = !wsLoading && wsList.length === 0;
  const wsSelectInner = (
    <>
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
        <div className="flex items-start gap-1.5 text-xs text-amber">
          <AlertCircle className="h-3.5 w-3.5 mt-0.5 flex-shrink-0" />
          <span>{t(isAdmin ? "scan.fields.wsEmptyHintAdmin" : "scan.fields.wsEmptyHintUser")}</span>
        </div>
      )}
    </>
  );
  const workspaceField = (
    <div className="space-y-1.5">
      {wsSelectInner}
    </div>
  );

  // —— 共用：认证 patch 回写 + inline 存档回调（白盒组合展开区与黑盒分支都用） ——
  const setAuth = (patch: Partial<AuthFormState>) => set({ auth: { ...f.auth, ...patch } });
  // HOST patch 回写（与 auth 独立、非互斥）--提前到 early return 之前，白盒组合展开区与黑盒分支共用。
  const setHost = (patch: Partial<HostFormState>) => set({ host: { ...f.host, ...patch } });
  // inline 保存为新档案后：切 profile 模式 + 选中新建档案 + 默认全选其角色 + 递增 refreshSignal 触发重拉。
  const onProfileSaved = (profile: AuthProfile) => {
    setAuth({ source: "profile", profileId: profile.id, credentialIds: profile.credentials.map((c) => c.id) });
    setProfileRefresh((n) => n + 1);
  };

  // —— 白盒布局（2026-09-09 质感统一）：① 工作区 | ② 仓库 两列 → ③ 黑盒组合（可选）——
  // 分区语言对齐 MR/跨仓表单（coral 竖条 GroupLabel + 开放 section）：原 StepGroup
  // 数字徽章 / bg-secondary 卡中卡 / 胶囊 tag 退役——同一 segmented 切换三种扫描
  // 类型零质感跳变。数字步骤徽章不再需要：ws→repo 顺序依赖由空间（自上而下）+
  // 行为（未选 ws 时仓库区提示「请先选择工作区」）编码，与 MR 表单一致。
  // 白盒已去动态（recon 固定静态，见 f2c64c8b）——纯离线源码审计；web_url 仅留作后端兼容签名。
  // Task 9：③「同时发起黑盒扫描」组合开关——开 → 展开 URL 输入 + 共享 AuthFields。
  // IA 不变量：repo 列表按 ws 隔离（listRepos(workspace)），故「选工作区」必须在「选仓库」之上。
  if (type === "whitebox") {
    return (
      <div className="space-y-5">
        {/* ① 工作区 / ② 仓库 并排双列（sm 起并排、gap-4，与 MR 表单两列同构）；
            窄屏纵排回落。 */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <section className="space-y-2">
            <GroupLabel>{t("scan.fields.wsSelectLabel")}</GroupLabel>
            {workspaceField}
          </section>
          <section className="space-y-2">
            <GroupLabel hint={t("scan.tags.localAudit")}>{t("scan.steps.source")}</GroupLabel>
            {repoPicker}
            {sourceErr && <div className="text-destructive text-xs">{sourceErr}</div>}
            {/* 扫完即删（2026-09-10）：linked 仓禁用（后端 sweep 对 linked 完全不处理）。 */}
            <DeleteRepoOnFinishCheckbox
              checked={!!f.deleteRepoOnFinish}
              onChange={(v) => set({ deleteRepoOnFinish: v })}
              disabled={!!selectedRepoObj?.linked}
            />
          </section>
        </div>

        {/* Task 9：同时发起黑盒扫描（组合扫描，可选）——开关 + 展开区 */}
        <section className="space-y-2.5">
          <GroupLabel hint={t("scan.tags.optional")}>{t("scan.combined.sectionTitle")}</GroupLabel>
          <label className="flex items-start gap-2.5 cursor-pointer">
            <div className="pt-0.5">
              <Switch
                checked={!!f.combined}
                onCheckedChange={(v) => set({ combined: v })}
                aria-label={t("scan.combined.toggle")}
              />
            </div>
            <div className="flex flex-col gap-0.5">
              <span className="text-[13px] font-medium leading-tight">{t("scan.combined.toggle")}</span>
              <span className="text-[11px] text-muted-foreground leading-relaxed">{t("scan.combined.hint")}</span>
            </div>
          </label>

          {f.combined && (
            <div className="fade-in space-y-3 border-t border-border pt-3">
              <div className="space-y-1.5">
                <Label className="text-xs font-medium">{t("scan.combined.urlLabel")}</Label>
                <Input
                  value={f.url}
                  onChange={(e) => set({ url: e.target.value })}
                  placeholder={t("scan.combined.urlPlaceholder")}
                  size="sm"
                  className="font-mono border-orange/30"
                />
                {urlErr && <div className="text-destructive text-xs">{urlErr}</div>}
              </div>
              <AuthFields
                value={f.auth}
                onChange={setAuth}
                workspace={workspace}
                authErr={authErr}
                refreshSignal={profileRefresh}
              />
              <HostFields
                value={f.host}
                onChange={setHost}
                workspace={workspace}
                error={hostErr}
              />
            </div>
          )}
        </section>
      </div>
    );
  }

  // —— 黑盒布局（2026-08-06 重排，对齐 preview HTML）：左表单 + 右核心 + 下方横向，一屏装下不滚动。
  //   折叠态：右栏虚线占位 + 认证行一行；展开态：右栏核心顶格对齐目标服务 + 下方横向铺开。
  //   认证拆两块——核心（开关/来源/入口/凭据）+ 增强（步骤/存档 或 档案摘要）。
  // IA 不变量：repo 与白盒 scan 均按工作区隔离；URL 是黑盒主输入，保持在最上。
  // #1 单一 disclosure：收起态若有草稿（任意 inline 字段已填 / 已选档案），按钮显「已配置」标记——
  // 折叠不再清字段，标记告诉用户「配置还在、只是当前未启用」。primary 默认 role="admin" 不算草稿信号。
  const hasAuthDraft = !!(f.auth.loginUrl.trim() || f.auth.loginFlow.trim() || f.auth.profileId
    || f.auth.accounts.some((a) => a.username.trim() || a.password.trim()));
  return (
    <div className="space-y-5">
      {/* 上层：左表单 + 右核心(展开时) */}
      <div className="grid grid-cols-1 lg:grid-cols-[minmax(0,42rem)_minmax(0,1fr)] gap-8 items-start">
        {/* 左栏表单 */}
        <div className="flex flex-col gap-5">
          {/* 目标服务 */}
          <section className="space-y-2">
            <div className="flex items-baseline gap-2">
              <h3 className="text-[13px] font-semibold">{t("scan.steps.targetService")}</h3>
              <span className="text-[10.5px] font-medium text-destructive">{t("scan.tags.required")}</span>
              <span className="ml-auto text-[11.5px] text-muted-foreground">{t("scan.fields.targetHint")}</span>
            </div>
            <Input
              id="url"
              value={f.url}
              onChange={(e) => set({ url: e.target.value })}
              placeholder={t("scan.fields.urlPlaceholder")}
              size="sm"
              className="font-mono border-orange/30"
            />
            {urlErr && <div className="text-destructive text-xs">{urlErr}</div>}
            <div className="text-xs text-muted-foreground">{t("scan.fields.blackboxUrlHint")}</div>
          </section>

          <div className="border-t border-border" />

          {/* 扫描上下文：工作区 + 复用白盒（并排一条链） */}
          <section className="space-y-2.5">
            <div className="flex items-baseline gap-2">
              <h3 className="text-[13px] font-semibold">{t("scan.fields.contextLabel")}</h3>
              <span className="text-[10.5px] font-medium text-destructive">{t("scan.tags.required")}</span>
              <span className="ml-auto text-[11.5px] text-muted-foreground">{t("scan.fields.contextHint")}</span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-[minmax(0,15rem)_minmax(0,1fr)] gap-3">
              <div className="space-y-1.5">
                <Label className="text-xs font-medium">{t("scan.fields.wsSelectLabel")}</Label>
                {wsSelectInner}
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs font-medium">{t("scan.fields.reuseSelectLabel")}</Label>
                {wbScans.length === 0 ? (
                  <div className="rounded-lg border border-dashed border-border bg-card p-2.5 text-xs text-muted-foreground leading-relaxed">
                    {workspace ? t("scan.fields.reuseEmpty") : t("scan.fields.selectWsFirst")}
                  </div>
                ) : (
                  <Select value={f.reuseScanId} onValueChange={(v) => set({ reuseScanId: v })}>
                    <SelectTrigger className="w-full text-xs">
                      <SelectValue placeholder={t("scan.fields.reuseSelectPlaceholder")} />
                    </SelectTrigger>
                    <SelectContent>
                      {wbScans.map((s, i) => (
                        <SelectItem key={s.scan_id} value={s.scan_id}>
                          <span className="font-mono text-xs">{s.workflow_id ?? s.scan_id}</span>
                          {i === 0 && (
                            <span className="ml-1.5 inline-flex items-center rounded-full bg-primary/10 px-1.5 py-0.5 text-[9.5px] font-semibold text-primary">
                              {t("scan.fields.latestBadge")}
                            </span>
                          )}
                          <span className="ml-1.5 text-[11px] text-muted-foreground">
                            · {String(s.status)} · {s.vuln_count} {t("scan.fields.vulnsUnit")}
                          </span>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                )}
                {/* 有候选却没选才提示；无候选时上方空态盒已说明，不再重复「请选择」红字。 */}
                {wbScans.length > 0 && reuseErr && <div className="text-destructive text-xs">{reuseErr}</div>}
              </div>
            </div>
          </section>

          <div className="border-t border-border" />

          {/* 认证行（折叠态：标题+状态+「配置登录」按钮一行） */}
          <section>
            <div className="flex items-center gap-3">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <h3 className="text-[13px] font-semibold">{t("scan.steps.auth")}</h3>
                  <span className="rounded-full bg-secondary px-2 py-0.5 text-[10.5px] font-semibold text-muted-foreground">
                    {t("scan.tags.optional")}
                  </span>
                </div>
                <div className="text-[11.5px] text-muted-foreground mt-0.5">
                  {f.auth.enabled ? t("scan.auth.statusEnabled") : t("scan.auth.statusUnauth")}
                </div>
              </div>
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="min-w-[5.5rem]"
                onClick={() => setAuth({ enabled: !f.auth.enabled })}
              >
                {f.auth.enabled
                  ? t("scan.auth.collapse")
                  : hasAuthDraft ? t("scan.auth.configureDraft") : t("scan.auth.configure")}
              </Button>
            </div>
          </section>

          {/* HOST 解析（Task 13）：复用共享 HostFields 组件（与认证区并列、互不影响）。 */}
          <HostFields value={f.host} onChange={setHost} workspace={workspace} error={hostErr} />
        </div>

        {/* 右栏：折叠=虚线占位 / 展开=核心（顶格对齐目标服务） */}
        <div className="hidden lg:block">
          {f.auth.enabled ? (
            <RightAuthCore
              auth={f.auth}
              setAuth={setAuth}
              authErr={authErr}
              workspace={workspace}
              refreshSignal={profileRefresh}
              onProfileSaved={onProfileSaved}
            />
          ) : (
            <div className="h-full min-h-[14rem] rounded-lg border border-dashed border-border/50 flex items-center justify-center">
              <span className="text-[11px] text-muted-foreground/50">{t("scan.auth.expandHint")}</span>
            </div>
          )}
        </div>
      </div>

      {/* 下方横向（展开时显：inline=登录入口+凭据 / profile=档案卡列表+详情+角色多选） */}
      {f.auth.enabled && (
        f.auth.source === "profile" ? (
          <BottomProfileBlock auth={f.auth} setAuth={setAuth} workspace={workspace} refreshSignal={profileRefresh} />
        ) : (
          <BottomInlineBlock auth={f.auth} setAuth={setAuth} authErr={authErr} />
        )
      )}
    </div>
  );
}
