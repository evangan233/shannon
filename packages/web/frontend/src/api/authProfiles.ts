// 认证档案库 client（auth-profile-vault, Task 10 契约）。
// Pattern B：mirror members.ts —— 顶部 import helper + const enc = encodeURIComponent；
// 每个端点一个 arrow const，路径参数经 enc 单段 encode。
//
// 后端契约（plan auth-profile-vault）：
//   GET    /workspaces/{ws}/auth-profiles                          -> AuthProfile[]
//   GET    /workspaces/{ws}/auth-profiles/{pid}                    -> AuthProfile
//   POST   /workspaces/{ws}/auth-profiles                          -> AuthProfile            (body: Partial<AuthProfile>)
//   PUT    /workspaces/{ws}/auth-profiles/{pid}                    -> { ok: true }           (body: Partial<AuthProfile>)
//   DELETE /workspaces/{ws}/auth-profiles/{pid}                    -> { ok: true }
//   POST   /workspaces/{ws}/auth-profiles/{pid}/credentials/{cid}/test  -> { workflow_id, probe_dir }
//   GET    /workspaces/{ws}/auth-profiles/{pid}/credentials/{cid}/verify-status?workflow_id&probe_dir -> VerifyStatus
import { apiGet, apiPost, apiPut, apiDelete } from "./client";
import type { AuthProfile, VerifyStatus } from "./types";

const enc = encodeURIComponent;

export const listAuthProfiles = (ws: string) =>
  apiGet<AuthProfile[]>(`/workspaces/${enc(ws)}/auth-profiles`);
export const getAuthProfile = (ws: string, pid: string) =>
  apiGet<AuthProfile>(`/workspaces/${enc(ws)}/auth-profiles/${enc(pid)}`);
export const createAuthProfile = (ws: string, body: Partial<AuthProfile>) =>
  apiPost<AuthProfile>(`/workspaces/${enc(ws)}/auth-profiles`, body);
export const updateAuthProfile = (ws: string, pid: string, body: Partial<AuthProfile>) =>
  apiPut<{ ok: true }>(`/workspaces/${enc(ws)}/auth-profiles/${enc(pid)}`, body);
export const deleteAuthProfile = (ws: string, pid: string) =>
  apiDelete<{ ok: true }>(`/workspaces/${enc(ws)}/auth-profiles/${enc(pid)}`);
export const forkProfile = (ws: string, pid: string) =>
  apiPost<AuthProfile>(`/workspaces/${enc(ws)}/auth-profiles/${enc(pid)}/fork`, {});
export const testCredential = (ws: string, pid: string, cid: string,
                               hostProfileIds?: string[], hostUrl?: string) => {
  // HOST 多选（2026-09-11）：重复 query 参数 ?host_profile_ids=a&host_profile_ids=b；
  // 单档案也走复数（后端归一等价）。
  const qs = hostProfileIds?.length
    ? `?${hostProfileIds.map((id) => `host_profile_ids=${enc(id)}`).join("&")}`
    : hostUrl ? `?host_url=${enc(hostUrl)}` : "";
  return apiPost<{ workflow_id: string; probe_dir: string }>(
    `/workspaces/${enc(ws)}/auth-profiles/${enc(pid)}/credentials/${enc(cid)}/test${qs}`, {});
};
// 档案级批量测试登录（多选角色 → 串行逐个独立验证）。credIds 省略/空 = 全选。返 batch workflow_id。
// hostProfileIds 多选：多档案后端合并 mappings（同 host 不同 IP → 422 冲突报错）。
export const testBatch = (ws: string, pid: string, credIds?: string[],
                          hostProfileIds?: string[], hostUrl?: string) => {
  const body: Record<string, unknown> = {};
  if (credIds) body.cred_ids = credIds;
  if (hostProfileIds?.length) body.host_profile_ids = hostProfileIds;
  if (hostUrl) body.host_url = hostUrl;
  return apiPost<{ workflow_id: string }>(
    `/workspaces/${enc(ws)}/auth-profiles/${enc(pid)}/test-batch`, body);
};
// 停止认证测试（批量/单 cred 通用）：后端先回填状态（绑此 wf 且 running → failed/cancelled）
// 再 handle.cancel()。幂等：无 running 返 already_finished。
export const cancelTest = (ws: string, pid: string, workflowId: string) =>
  apiPost<{ cancelled: string; already_finished?: boolean }>(
    `/workspaces/${enc(ws)}/auth-profiles/${enc(pid)}/cancel-test`,
    { workflow_id: workflowId });
export const getVerifyStatus = (
  ws: string, pid: string, cid: string, workflowId: string, probeDir: string,
) =>
  apiGet<VerifyStatus>(
    `/workspaces/${enc(ws)}/auth-profiles/${enc(pid)}/credentials/${enc(cid)}/verify-status`
    + `?workflow_id=${enc(workflowId)}&probe_dir=${enc(probeDir)}`);

// 块3b：读验证过程 events.ndjson（agent 登录每步）。tail=N 实时观看末尾，省略=全量回看。
export const getVerifyLog = (
  ws: string, pid: string, cid: string, workflowId: string, probeDir: string, tail?: number,
) =>
  apiGet<{ events: Array<Record<string, unknown>> }>(
    `/workspaces/${enc(ws)}/auth-profiles/${enc(pid)}/credentials/${enc(cid)}/verify-log`
    + `?workflow_id=${enc(workflowId)}&probe_dir=${enc(probeDir)}`
    + (tail != null ? `&tail=${tail}` : ""));

// 块4：验证过程 SSE 实时流 URL（tail probe_dir/events.ndjson，遇 scan_end 关流）——喂 EventSource。
export const verifyEventsUrl = (
  ws: string, pid: string, cid: string, workflowId: string, probeDir: string,
) =>
  `/api/workspaces/${enc(ws)}/auth-profiles/${enc(pid)}/credentials/${enc(cid)}/verify-events`
  + `?workflow_id=${enc(workflowId)}&probe_dir=${enc(probeDir)}`;

