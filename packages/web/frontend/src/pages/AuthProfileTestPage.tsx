// 档案级认证测试页（路由 /p/:ws/auth-profiles/:pid）。
// 多选角色（对齐黑盒 BottomProfileBlock toggle 样式）→ POST test-batch → 串行逐个独立验证每个角色
// 能否登录（非越权对比，spec §2）。进度区：每选中角色一行；running 行挂 VerifyLivePanel 订阅其
// verify-events；完成行可跳单角色过程页。关页面恢复：轮询 profile 找 running cred 自动订阅其 events。
import { useEffect, useRef, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import { ArrowLeft, Loader2, ExternalLink, Square, Pencil } from "lucide-react";
import { getAuthProfile, testBatch, cancelTest } from "@/api/authProfiles";
import { apiErrorMessage, providerIncompleteMissing } from "@/lib/apiError";
import type { AuthProfile, AuthProfileCredential, VerifyState } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { VerifyLivePanel } from "./VerifyLivePanel";
import { HostFields } from "@/components/ScanFormFields";
import { VerifyFailureNote } from "@/components/auth/VerifyFailureNote";
import { AuthProfileDialog } from "@/components/AuthProfileDialog";
import { DEFAULT_HOST } from "./ScanNewPage";
import type { HostFormState } from "./ScanNewPage";

function credState(c: AuthProfileCredential): VerifyState {
  return c.verify_status?.state ?? "unverified";
}

// 批量进度 overall（区别于扫描 overallState 的 success 优先）：running 优先（批次进行中），
// 然后有失败→failed，然后任一 success→success，否则未验证。
function batchOverall(creds: AuthProfileCredential[]): VerifyState {
  const states = creds.map(credState);
  if (states.some((s) => s === "running")) return "running";
  if (states.some((s) => s === "failed")) return "failed";
  if (states.some((s) => s === "success")) return "success";
  return "unverified";
}

// 验证状态 → 徽章样式 + 图标（对齐 ScanFormFields.verifyBadge：success=绿✓ / failed=红✗ / running=蓝● / 未验证=黄●）
function verifyBadge(st: VerifyState): { cls: string; icon: string } {
  return st === "success" ? { cls: "border-green/40 text-green", icon: "✓" }
    : st === "failed" ? { cls: "border-red/40 text-red", icon: "✗" }
    : st === "running" ? { cls: "border-blue/40 text-blue", icon: "●" }
    : { cls: "border-yellow/40 text-yellow", icon: "●" };
}

/** HostFormState → 测试请求参数（profile 模式 → hostProfileIds 多选 / url 模式 → hostUrl）。
 *  对齐 ScanNewPage.assignHostToBody：未启用 → 空（直连）。供 AuthProfileTestPage 发起测试透传。 */
export function hostToParams(h: HostFormState): { hostProfileIds?: string[]; hostUrl?: string } {
  if (!h.enabled) return {};
  if (h.mode === "profile") {
    return h.profileIds.length ? { hostProfileIds: [...h.profileIds] } : {};
  }
  const url = h.hostUrl.trim();
  return url ? { hostUrl: url } : {};
}

interface LiveRun { cid: string; workflowId: string; probeDir: string; runKey: number; }

export function AuthProfileTestPage() {
  const { t } = useTranslation();
  const { workspace, pid } = useParams<{ workspace: string; pid: string }>();
  const [profile, setProfile] = useState<AuthProfile | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [batchWfId, setBatchWfId] = useState<string | null>(null);
  const [liveRun, setLiveRun] = useState<LiveRun | null>(null);
  const [testing, setTesting] = useState(false);
  const [polling, setPolling] = useState(false);
  const [refreshTick, setRefreshTick] = useState(0);
  const [host, setHost] = useState<HostFormState>(DEFAULT_HOST);
  const [editOpen, setEditOpen] = useState(false);

  // ref 同步：拉 profile effect 依赖 refreshTick（不含 polling/selectedIds），闭包经 ref 读最新值，
  // 避免 toggle role 触发多余 profile 请求。
  const pollingRef = useRef(false);
  const selectedIdsRef = useRef<string[]>([]);
  const initedRef = useRef(false);
  useEffect(() => { pollingRef.current = polling; }, [polling]);
  useEffect(() => { selectedIdsRef.current = selectedIds; }, [selectedIds]);

  // 拉 profile（refreshTick 驱动：初始 + 轮询 + 完成后重拉）
  useEffect(() => {
    if (!workspace || !pid) return;
    let cancelled = false;
    if (refreshTick === 0) { setLoading(true); setError(null); }
    getAuthProfile(workspace, pid)
      .then((p) => {
        if (cancelled) return;
        setProfile(p);
        // 首次加载：默认全选（initedRef 守卫防轮询重拉覆盖用户手动取消全选）
        if (!initedRef.current) {
          initedRef.current = true;
          setSelectedIds(p.credentials.map((c) => c.id));
        }
        setLoading(false);
        // 重载恢复：首次拉取发现 running cred（批次进行中）→ 恢复轮询 + testing
        if (refreshTick === 0 && !pollingRef.current) {
          const hasRunning = p.credentials.some((c) => credState(c) === "running");
          if (hasRunning) { setPolling(true); setTesting(true); }
        }
        // 轮询中：判全终态 → 停轮询 + 收尾
        if (pollingRef.current) {
          const sel = p.credentials.filter((c) => selectedIdsRef.current.includes(c.id));
          if (sel.length > 0 && sel.every((c) => ["success", "failed"].includes(credState(c)))) {
            setPolling(false); setTesting(false); setLiveRun(null);
            toast.success(t("authProfiles.testPage.allDone"));
          }
        }
      })
      .catch((e) => {
        if (!cancelled) { setError(apiErrorMessage(e, t("authProfiles.loadFailed"))); setLoading(false); }
      });
    return () => { cancelled = true; };
  }, [workspace, pid, refreshTick]);  // eslint-disable-line react-hooks/exhaustive-deps

  // 轮询：polling 时周期触发 refreshTick（→ 重拉 profile）。全终态由拉 profile effect 判定后停。
  useEffect(() => {
    if (!polling || !workspace || !pid) return;
    const id = setInterval(() => setRefreshTick((n) => n + 1), 2000);
    return () => clearInterval(id);
  }, [polling, workspace, pid]);

  // 定位 running cred → 订阅其 events（切到新 running 时更新 liveRun）。runKey 稳定常数 0 防轮询
  // 重拉致 EventSource flapping。liveRun.cid 条件内读，不作依赖（防循环）。
  useEffect(() => {
    if (!profile) return;
    const selected = profile.credentials.filter((c) => selectedIds.includes(c.id));
    const running = selected.find((c) => credState(c) === "running");
    if (running && running.verify_status?.workflow_id && running.verify_status?.probe_dir) {
      if (liveRun?.cid !== running.id) {
        setLiveRun({
          cid: running.id,
          workflowId: running.verify_status.workflow_id,
          probeDir: running.verify_status.probe_dir,
          runKey: 0,
        });
      }
    } else if (!running && liveRun) {
      setLiveRun(null);  // 无 running（全终态/未开始）→ 清 liveRun
    }
  }, [profile, selectedIds]);  // eslint-disable-line react-hooks/exhaustive-deps

  async function onStart() {
    if (!workspace || !pid || !profile) return;
    setTesting(true);
    try {
      const ids = profile.credentials.filter((c) => selectedIds.includes(c.id)).map((c) => c.id);
      const allIds = profile.credentials.map((c) => c.id);
      const hp = hostToParams(host);
      // 全选时省略 cred_ids（后端 None=全选语义）；HOST 选中（可多选，后端合并 mappings）→
      // 走代理，未选 → 直连
      const { workflow_id } = await testBatch(
        workspace, pid, ids.length === allIds.length ? undefined : ids,
        hp.hostProfileIds, hp.hostUrl);
      setBatchWfId(workflow_id);
      setPolling(true);
      setRefreshTick((n) => n + 1);  // 立即重拉（拿首 cred running）
    } catch (e) {
      // 工作区模型配置缺失/错误（测试登录不降级）→ 指引去工作区设置，而非通用失败文案。
      toast.error(providerIncompleteMissing(e)
        ? t("authProfiles.verify.providerMissing")
        : apiErrorMessage(e, t("authProfiles.verify.failed")));
      setTesting(false);
    }
  }

  // 停止批次（auth-test-cancel）：后端先回填 running→failed/cancelled 再 handle.cancel()。
  // 用户停止即批次终结（未开始的 cred 保持 unverified，轮询的"全终态"退出条件永不满足）→
  // 直接停轮询/测试态；重拉落 failed 态、running 消失 → liveRun 清空（SSE 卸载）。
  async function onStop() {
    if (!workspace || !pid || !stopWfId) return;
    try {
      await cancelTest(workspace, pid, stopWfId);
      toast.success(t("authProfiles.testPage.stopped"));
      setTesting(false);
      setPolling(false);
      setRefreshTick((n) => n + 1);
    } catch (e) {
      toast.error(apiErrorMessage(e, t("authProfiles.testPage.stopFailed")));
    }
  }

  function handleCredComplete() {
    // 某 cred scan_end → 重拉 profile（watcher 已回填该 cred 终态 + 下个 cred running，轮询自动订阅下一个）
    setRefreshTick((n) => n + 1);
  }

  function toggleRole(id: string) {
    setSelectedIds((prev) => prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]);
  }
  function toggleAll() {
    if (!profile) return;
    const allSelected = profile.credentials.length > 0 && profile.credentials.every((c) => selectedIds.includes(c.id));
    setSelectedIds(allSelected ? [] : profile.credentials.map((c) => c.id));
  }

  if (!workspace || !pid) return null;

  const selectedCreds = profile?.credentials.filter((c) => selectedIds.includes(c.id)) ?? [];
  const ov = batchOverall(selectedCreds);
  const allSelected = !!profile && profile.credentials.length > 0
    && profile.credentials.every((c) => selectedIds.includes(c.id));
  const showProgress = !!batchWfId || selectedCreds.some((c) => credState(c) !== "unverified");
  // 停止目标 workflow：发起态用 batchWfId；恢复态（重载页面靠轮询发现 running）用
  // running cred 的 verify_status.workflow_id。两者皆无 → 停止不可用（显示测试中占位）。
  const stopWfId = batchWfId
    ?? profile?.credentials.find((c) => credState(c) === "running")
      ?.verify_status?.workflow_id ?? null;

  return (
    <div className="space-y-4">
      <Link to={`/p/${workspace}/auth-profiles`}
        className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-primary">
        <ArrowLeft className="size-3.5" /> {t("authProfiles.testPage.back")}
      </Link>

      {loading ? <Skeleton className="h-40 w-full" />
       : error ? <Card className="p-6 text-sm text-destructive">{error}</Card>
       : !profile ? <Card className="p-6 text-sm text-muted-foreground">{t("authProfiles.testPage.notFound")}</Card>
       : profile.credentials.length === 0 ? <Card className="p-6 text-sm text-muted-foreground">{t("authProfiles.testPage.noRoles")}</Card>
       : (
        <>
          {/* header: 档案名 + login_url + overall 徽章 + 开始按钮 */}
          <Card className="p-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="min-w-0 space-y-1">
                <div className="flex items-center gap-2">
                  <h2 className="break-all font-mono text-lg font-medium">{profile.name}</h2>
                  {/* 档案级编辑：紧贴其编辑的对象（档案名）。对齐列表页图标范式；系统档案只读隐藏。 */}
                  {profile.scope !== "system" && (
                    <Button variant="ghost" size="icon" aria-label={t("authProfiles.edit")}
                      onClick={() => setEditOpen(true)} className="shrink-0 text-muted-foreground hover:text-primary">
                      <Pencil className="size-4" />
                    </Button>
                  )}
                </div>
                <p className="break-all font-mono text-xs text-muted-foreground">{profile.login_url}</p>
                <Badge variant="outline" className={`gap-1 font-mono ${verifyBadge(ov).cls}`}>
                  <span aria-hidden>{verifyBadge(ov).icon}</span>{t(`authProfiles.overall.${ov}`)}
                </Badge>
              </div>
              {/* 右侧操作区仅保留主线测试动作（开始/停止） */}
              {testing && stopWfId ? (
                <Button variant="destructive" onClick={onStop} className="shrink-0">
                  <Square className="size-3.5" /> {t("authProfiles.testPage.stop")}
                </Button>
              ) : testing ? (
                <Button variant="cta" disabled className="shrink-0">
                  <Loader2 className="size-4 animate-spin" /> {t("authProfiles.testPage.starting")}
                </Button>
              ) : (
                <Button variant="cta" onClick={onStart} disabled={selectedCreds.length === 0} className="shrink-0">
                  {t("authProfiles.testPage.start")}
                </Button>
              )}
            </div>
          </Card>

          {/* 角色多选区（对齐黑盒 BottomProfileBlock toggle 样式） */}
          <Card className="p-4 space-y-2">
            <div className="flex items-center justify-between mb-2">
              <div className="text-[11px] font-semibold text-muted-foreground">
                {t("scan.auth.selectRole")}
                <span className="font-normal text-muted-foreground">（{t("scan.auth.multiRoleDefaultAll")}）</span>
              </div>
              <button type="button" onClick={toggleAll}
                className="text-[10.5px] font-medium text-primary hover:underline">
                {allSelected ? t("scan.auth.deselectAllRoles") : t("scan.auth.selectAllRoles")}
              </button>
            </div>
            <div className="space-y-2">
              {profile.credentials.map((c) => {
                const st = credState(c);
                const b = verifyBadge(st);
                const sel = selectedIds.includes(c.id);
                return (
                  <button key={c.id} type="button" onClick={() => toggleRole(c.id)} aria-pressed={sel}
                    className={`w-full flex items-center gap-2.5 rounded-lg border p-2.5 transition-colors text-left ${sel ? "border-primary bg-primary/5 shadow-sm" : "border-border bg-card hover:border-foreground/20"}`}>
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
                    </div>
                    <span className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10.5px] font-semibold flex-none ${b.cls}`}>
                      <span aria-hidden>{b.icon}</span>{t(`authProfiles.verify.${st}`)}
                    </span>
                  </button>
                );
              })}
            </div>
            <div className="mt-2 text-[10.5px] text-muted-foreground">
              {t("authProfiles.testPage.selected", { n: selectedIds.length, m: profile.credentials.length })}
            </div>
          </Card>

          {/* HOST 解析（复用黑盒 HOST 能力）：选 HOST 走代理、不选直连。与扫描表单同款 HostFields。 */}
          <Card className="p-4">
            <HostFields
              value={host}
              onChange={(patch) => setHost({ ...host, ...patch })}
              workspace={workspace}
            />
          </Card>

          {/* 进度区：发起后 / 有已测角色时显示，每选中角色一行 */}
          {showProgress && (
            <Card className="p-4 space-y-3">
              {selectedCreds.map((c) => {
                const st = credState(c);
                const b = verifyBadge(st);
                return (
                  <div key={c.id} className="space-y-2">
                    <div className="flex flex-wrap items-center gap-2">
                      {st === "running"
                        ? <Loader2 className="size-4 animate-spin text-blue" />
                        : <span aria-hidden className={`text-sm ${b.cls.split(" ")[1]}`}>{b.icon}</span>}
                      <span className="font-mono text-sm">{c.role}·{c.username}</span>
                      <Badge variant="outline" className={`gap-1 font-mono ${b.cls}`}>
                        <span aria-hidden>{b.icon}</span>{t(`authProfiles.verify.${st}`)}
                      </Badge>
                      {["success", "failed"].includes(st) && c.verify_status?.workflow_id && (
                        <Link to={`/p/${workspace}/auth-profiles/${pid}/credentials/${c.id}`} target="_blank"
                          className="inline-flex items-center gap-1 text-xs text-primary hover:underline">
                          <ExternalLink className="size-3" /> {t("authProfiles.testPage.seeDetail")}
                        </Link>
                      )}
                    </div>
                    {liveRun?.cid === c.id && c.verify_status?.workflow_id && c.verify_status?.probe_dir && (
                      <VerifyLivePanel
                        key={liveRun.runKey}
                        ws={workspace} pid={pid} cid={c.id}
                        workflowId={liveRun.workflowId} probeDir={liveRun.probeDir}
                        onComplete={handleCredComplete}
                      />
                    )}
                    {st === "failed" && (c.verify_status?.failure_point || c.verify_status?.failure_detail) && (
                      <VerifyFailureNote
                        failurePoint={c.verify_status?.failure_point}
                        failureDetail={c.verify_status?.failure_detail}
                      />
                    )}
                  </div>
                );
              })}
            </Card>
          )}
        </>
      )}

      {/* 档案级编辑对话框（复用列表页）：保存后重拉 profile 同步角色/凭据。system 档案仅读（readOnly 兜底）。 */}
      {profile && (
        <AuthProfileDialog
          ws={workspace}
          open={editOpen}
          onOpenChange={setEditOpen}
          onSaved={() => { setEditOpen(false); setRefreshTick((n) => n + 1); }}
          editing={profile}
        />
      )}
    </div>
  );
}
