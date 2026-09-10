# 批量白盒扫描设计（batch-whitebox-scan）

> 日期：2026-09-11。状态：spec 待审。
> 需求：支持批量白盒扫描——输入批量 GitLab 链接（经现有批量克隆）与批量选择已注册仓库，一次提交对 N 个仓库各发起一条白盒扫描。
> 已确认的产品决策：两步分离（克隆与扫描不做自动串联）、无批次实体（N 个扫描即 N 条独立记录）、白盒 tab 内多选改造（不新增 tab）、后端批量端点一次 fan-out、提交后跳扫描列表页 + 汇总横幅。

## 1. 背景与现状

- **单发链路**：`ScanNewPage` 白盒 tab → `RepoCombobox` 单选仓库 → `buildBody` → `POST /api/scan`（`api/scan.py:36-83`）→ `sm.start()`（`scan_manager.py:403-671`）→ temporal `WhiteboxScanWorkflow`。
- **批量克隆已落地**（2026-09-09）：`POST /repos/batch-clone`（上限 `BATCH_CLONE_MAX_URLS=50`，撞 `_max_concurrent=3` 由后台排队补位）+ 前端 `AddRepoDialog` 多行 URL 输入。这是「批量 GitLab 链接」需求的现有承接点，本设计复用不改动。
- **fan-out 先例**：correlation 提交时对每个子仓循环 `create_scan` + `_submit_whitebox`（`scan_manager.py:607-630`），证明一次请求 N 个白盒 workflow 是被支持的模式。
- **并发控制天然存在**：worker 侧 ScanGate（容量 5 / 等待 50，`scan_gate.py`）把超量扫描自动排队；web 侧无并发限制（`scan_manager.py:411` 注释明示闸门已下沉 worker）。
- **缺口**：无任何批量创建 scan 的端点；`RepoCombobox` 仅单选；`sm.start` 要求仓库 `state==ready`（`_resolve_repo_path`，`scan_manager.py:2481-2508`）否则同步抛 ValueError。

## 2. 目标 / 非目标

**目标**

1. 白盒 tab 内勾选 N 个已就绪仓库，一次提交「批量扫描」，每个仓库各自产生一条独立白盒扫描（共享表单其余配置）。
2. 单仓失败（未就绪/不存在/排队满/Temporal 异常）只计入该仓结果，不阻断整批。
3. 批量 GitLab 链接 → 复用现有 AddRepoDialog 批量克隆；克隆完成后仓库出现在多选列表即可勾选（含小增强：克隆提交后自动预选新仓库）。

**非目标**

- 不做克隆→扫描自动串联（用户显式选择两步分离；全自动编排方案被否决）。
- 不做批次实体：无 batch_id、无列表分组折叠、无整体进度——N 个扫描就是 N 条独立记录。
- 不做 MR / 黑盒 / 关联扫描的批量。
- 不做 per-repo 差异化配置（分支/认证/host 对 N 个扫描统一生效——白盒扫描本身无 branch 字段，扫仓库当前状态）。
- 不新增并发控制（ScanGate 已覆盖；queue_full 单仓报「扫描排队已满」记入失败项）。

## 3. API 设计：`POST /api/scan/batch`

### 3.1 请求 `BatchScanRequest`（`models.py` 新增）

字段与白盒 `ScanRequest` 分支相同，`source` 换为仓库名列表：

```python
class BatchScanRequest(BaseModel):
    workspace: str
    repos: list[str]                    # 仓库名（RepoCombobox 的 value，含 group/ 两层名）
    # —— 以下与白盒 ScanRequest 同名同义，共享给每个仓库 ——
    url: str | None = None              # 组合模式目标 URL
    authentication: dict | None = None  # inline 认证（与 auth_profile 互斥，沿用现有校验）
    auth_accounts: list[dict] | None = None
    auth_profile_id: str | None = None
    auth_credential_ids: list[str] | None = None
    host_profile_id: str | None = None
    host_url: str | None = None
    delete_repo_on_finish: bool = False
```

**校验**（model_validator，复用/对齐单发白盒的既有规则）：
- `repos` 非空、去重、长度 ≤ 50（`BATCH_SCAN_MAX_REPOS=50`，对齐 `BATCH_CLONE_MAX_URLS`）。
- `type` 固定为白盒语义（无 type 字段），故 `_whitebox_combined_optional`（白盒带 url=组合、纯白盒禁认证）与 `_auth_profile_xor_inline`、`_host_profile_xor_url` 三条互斥校验**直接移植**到 BatchScanRequest。

### 3.2 端点处理（`api/scan.py` 新增 `create_scan_batch`）

```
前置（同 create_scan）：ws 存在/命名安全(422) → 成员权限(403)
                      → resolve_provider_config 缺失 → 结构化 422 provider_incomplete（不 fan-out）
fan-out：for repo in repos:
           构造单条白盒 ScanRequest(source={kind:"repo", value:repo}, 其余字段照抄)
           try: sm.start(单条) → results.append({repo, ok:true, scan_id})
           except (ValueError, PermissionError, TemporalUnavailable, …) as e:
                 results.append({repo, ok:false, error: 中文消息})
```

- **`scan_manager` 零改动**：端点层循环调现有 `sm.start()`。仓库相关校验（未就绪/不存在）在 `_resolve_repo_path` 同步抛 ValueError，可捕获。
- 每仓的 `sm.start` 是独立 try——Temporal 连接失败会让余下全部失败（属系统级故障，逐仓报同因错误，语义仍正确）。
- 异常消息映射复用单发的中文文案（ValueError→422 语义的消息、TemporalUnavailable→400 语义的消息），但批量下归入 `error` 字符串，不改变 HTTP 状态。

### 3.3 响应

有任何成功 → **202**：

```json
{"workspace": "ws", "submitted": 28, "failed": 2,
 "results": [{"repo": "backend-gateway", "ok": true, "scan_id": "scan-..."},
             {"repo": "data-pipeline", "ok": false, "error": "仓库未就绪：正在克隆中"}]}
```

全部失败 → **422** 附同样的 results 结构（前端据此展示全部失败明细）。

## 4. 前端设计

### 4.1 `RepoCombobox` 单选→多选

- 列表项前加 checkbox；勾选**不关闭**下拉，可连续勾选；再次点击取消。
- 已选项在触发器内显示为 chips（可点 × 移除）；`value: string` → `value: string[]`，`onChange(string[])`。
- 搜索过滤、分组、linked 徽标、键盘导航保留。
- **未就绪仓库（state != ready）禁选**：行置灰 + 原因提示（cloning→「克隆中」、failed→「克隆失败」），不可勾选。
- 兼容策略：MR tab 的仓库选择器也用 RepoCombobox——MR 保持单选语义。实现上给 RepoCombobox 加 `multiple?: boolean` prop，默认 false 走现有单选行为（MR/其他调用点零改动），true 时启用 checkbox/chips 多选形态。

### 4.2 `ScanNewPage` / `ScanFormFields` 状态改造

- `selectedRepo: string` → `selectedRepos: string[]`（白盒分支；MR 分支保持单选不变）。
- 选 1 个：**行为与现状完全一致**——提交 `POST /api/scan` 单发，成功跳 `/p/{ws}/scans/{scan_id}/live`。单扫体验零变化。
- 选 >1 个：提交按钮文案变「发起批量扫描 (N)」；提交 `POST /api/scan/batch`；成功后跳扫描列表页（`/p/{ws}/scans`），顶部横幅汇总：成功 N / 失败 M，M>0 时展开失败明细（仓库名 + 原因）；横幅可关闭。
- `buildBody` 拆出 `buildBatchBody(repos)`：批量分支的 body 构造（其余白盒字段与单发同源，组合/认证/host 字段沿用现有 `assignAuthToBody` 逻辑）。

### 4.3 AddRepoDialog 预选增强（小增强）

AddRepoDialog 批量克隆**提交成功后**（非 ready 后——ready 是异步的），把本批新仓库名预填进 `selectedRepos`：
- 已选中的 cloning 仓库在表单里显示「待就绪」态徽标；
- 提交批量扫描时后端仍会校验 ready——cloning 未完成的仓库将作为失败项返回「仓库未就绪」，用户可稍后仅对这些仓库重发；
- 纯前端预选，不自动发扫描，不违背两步分离。

### 4.4 类型与 client

- `types.ts`：`BatchScanRequest` / `BatchScanResponse`（含 `results: BatchScanResultItem[]`）。
- `client.ts`：`createBatchScan(body): Promise<BatchScanResponse>` 封装 `apiPost("/scan/batch", ...)`。

## 5. 错误处理汇总

| 场景 | 行为 |
|---|---|
| 单仓未就绪/不存在 | 该仓 `ok:false + error`，其余照常 |
| 排队满（queue_full） | 该仓 error「扫描排队已满」，其余照常 |
| provider 凭据缺失 | 整批 422 `provider_incomplete`，0 次 fan-out |
| 全部失败 | 422 + results 明细 |
| Temporal 不可用 | 逐仓同因失败（系统级），results 明细 |
| 提交时仓库被并发删除 | 该仓失败（`_resolve_repo_path` 抛错），整批不受影响 |
| 同仓重复发起（已有 running 再发起） | 与单发现状一致（允许），不额外限制 |

## 6. 测试计划（TDD）

**后端** `packages/web/tests/test_api_scan_batch.py`（参照 `test_batch_clone.py` 的 fake 手法）：
1. fan-out 成功：2 仓 → 202、2 条 scan 记录、results 各带 scan_id。
2. 部分失败：1 就绪 + 1 cloning → 202、submitted=1/failed=1、失败项含「未就绪」。
3. 全部失败 → 422 + results。
4. repos 空 / 超过 50 → 422。
5. provider 缺失 → 结构化 422，`sm.start` 0 次调用。
6. 权限：非成员 403。
7. 认证互斥等移植校验生效（profile 与 inline 同给 → 422）。

**前端**：
- `RepoCombobox.test.tsx`：多选勾选/取消/chips 移除、未就绪禁选、`multiple=false` 单选回归。
- `ScanNewPage.test.tsx`：选 1 个走单发回归不变；选 2 个 → 按钮文案「批量扫描 (2)」→ msw mock `/scan/batch` → 跳列表 + 横幅（含失败明细展示）；`buildBatchBody` 纯函数单测。
- `AddRepoDialog.test.tsx`：批量克隆提交成功后新仓库名进入已选（预选增强）。

## 7. 涉及文件

| 层 | 文件 | 改动 |
|---|---|---|
| 后端 | `packages/web/src/supernova_web/models.py` | +`BatchScanRequest`（移植 3 条互斥校验） |
| 后端 | `packages/web/src/supernova_web/api/scan.py` | +`create_scan_batch` 端点 |
| 后端 | `packages/web/tests/test_api_scan_batch.py` | 新建 |
| 前端 | `frontend/src/components/RepoCombobox.tsx` | +`multiple` prop 多选形态 |
| 前端 | `frontend/src/components/ScanFormFields.tsx` | 仓库区状态 string→string[]（白盒） |
| 前端 | `frontend/src/pages/ScanNewPage.tsx` | selectedRepos、buildBatchBody、批量提交/跳转/横幅 |
| 前端 | `frontend/src/components/AddRepoDialog.tsx` | 克隆提交后回调预选新仓库 |
| 前端 | `frontend/src/api/types.ts` / `client.ts` | +批量类型与封装 |
| 前端 | 对应 `*.test.tsx` | 见 §6 |

`scan_manager.py`、worker、temporal workflow：**零改动**。
