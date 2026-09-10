# 批量白盒扫描（batch-whitebox-scan）Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 白盒 tab 勾选 N 个已就绪仓库一次提交，后端 `POST /api/scan/batch` 逐仓 fan-out 独立白盒扫描；单仓失败不阻断整批。

**Architecture:** 后端新增 `BatchScanRequest`（字段同白盒 ScanRequest、`source`→`repos: list[str]`）+ 端点层循环调既有 `sm.start()`（`scan_manager` 零改动）。前端白盒 tab 仓库选择器换成现成的 `RepositoryMultiSelector`（correlation 已用的多选列表：搜索/全选/计数/未就绪禁选），选 ≥2 时提交走 batch 端点并跳扫描列表页 + 汇总横幅；选 1 个时单发行为与现状完全一致。MR tab 的 `RepoCombobox` 单选零改动。

**Tech Stack:** FastAPI + pydantic v2（后端）；React 19 + vitest + msw + testing-library（前端）；temporal worker 既有 ScanGate 排队（容量 5/等待 50），本功能不新增并发控制。

**Spec:** `docs/superpowers/specs/2026-09-11-batch-whitebox-scan-design.md`

## Global Constraints

- 上限：`BATCH_SCAN_MAX_REPOS = 50`（spec §3.1，对齐 `BATCH_CLONE_MAX_URLS`）。
- 有任何成功 → 202；全部失败 → 422（均附 `results` 明细）（spec §3.3）。
- provider 凭据缺失 → 结构化 422 `{code: "provider_incomplete", missing: [...]}`，0 次 fan-out（spec §3.2）。
- `scan_manager.py`、worker、temporal workflow **零改动**（spec §7）。
- MR 分支的 `f.selectedRepo`（string）与相关 preset/链接回填链路**零改动**（本计划采用「保留 selectedRepo（MR 专用）+ 新增 selectedRepos（白盒专用）」双状态，见 Task 3）。
- 前端 i18n：`src/locales/zh.json` 与 `en.json` 同步加 key（无 key 对齐锁定测试，但两语言必须同步）。
- 前端类型门禁：提交前 `cd packages/web/frontend && npx tsc -b` 必须零错误（vitest 不查类型）。
- 后端测试只跑本计划相关文件，勿广跑全套（CLAUDE.md §3 测试陷阱）。
- 每个任务结束 `git add <相关文件> && git commit`；commit message 风格参照 `git log --oneline -5`（中文、`feat(web-be)`/`feat(web-fe)`/`test` 前缀）。

---

### Task 1: 后端 `BatchScanRequest` 模型与校验

**Files:**
- Modify: `packages/web/src/supernova_web/models.py`（`ScanAccepted` 之后、`ErrorOut` 之前插入）
- Test: `packages/web/tests/test_api_scan_batch.py`（新建）

**Interfaces:**
- Consumes: 无（首任务）。
- Produces: `BatchScanRequest`（pydantic 模型，字段见 Step 3）、`BatchScanResultItem`、`BatchScanAccepted`（响应模型，Task 2 端点用）。

- [ ] **Step 1: 写失败的校验测试**

新建 `packages/web/tests/test_api_scan_batch.py`：

```python
"""POST /api/scan/batch 契约测试（spec 2026-09-11-batch-whitebox-scan）。

Task 1 先锁 pydantic 校验语义（不发 HTTP）；Task 2 加端点行为测试。
"""
import pytest
from pydantic import ValidationError

from supernova_web.models import BatchScanRequest


def _base(**kw):
    body = {"workspace": "WSX", "repos": ["backend-gateway", "auth-service"]}
    body.update(kw)
    return BatchScanRequest(**body)


class TestBatchScanRequestValidation:
    def test_minimal_ok(self):
        req = _base()
        assert req.repos == ["backend-gateway", "auth-service"]

    def test_repos_empty_rejected(self):
        with pytest.raises(ValidationError):
            _base(repos=[])

    def test_repos_dedup(self):
        req = _base(repos=["a", "a", "b"])
        assert sorted(req.repos) == ["a", "b"]

    def test_repos_over_50_rejected(self):
        with pytest.raises(ValidationError):
            _base(repos=[f"r{i}" for i in range(51)])

    def test_combined_url_with_auth_profile_ok(self):
        # 组合模式（带 url）：认证字段合法（profile 子集模式）
        req = _base(url="http://target.example",
                    auth_profile_id="p1", auth_credential_ids=["c1"])
        assert req.auth_profile_id == "p1"

    def test_pure_whitebox_rejects_auth(self):
        # 纯白盒（无 url）禁认证字段（移植 _whitebox_combined_optional）
        with pytest.raises(ValidationError):
            _base(auth_profile_id="p1")

    def test_auth_profile_xor_inline(self):
        with pytest.raises(ValidationError):
            _base(url="http://t", auth_profile_id="p1",
                  authentication={"login_type": "form"})

    def test_cred_without_profile_rejected(self):
        with pytest.raises(ValidationError):
            _base(url="http://t", auth_credential_ids=["c1"])

    def test_host_profile_xor_url(self):
        with pytest.raises(ValidationError):
            _base(url="http://t", host_profile_id="h1", host_url="http://hosts")

    def test_host_url_scheme_checked(self):
        with pytest.raises(ValidationError):
            _base(url="http://t", host_url="ftp://bad")

    def test_shared_fields_default(self):
        req = _base()
        assert req.url is None
        assert req.delete_repo_on_finish is False
```

- [ ] **Step 2: 跑测试确认失败**

```bash
cd /root/ft-codescan/packages/web && python -m pytest tests/test_api_scan_batch.py -v
```
预期：全部 ERROR/FAIL（`ImportError: cannot import name 'BatchScanRequest'`）。

- [ ] **Step 3: 实现 `BatchScanRequest`**

在 `models.py` 的 `ScanAccepted` 类之后（`ErrorOut` 之前）插入：

```python
# —— 批量白盒扫描（spec 2026-09-11-batch-whitebox-scan）——
# 一次请求对 N 个仓库各发起一条独立白盒扫描（无批次实体；并发由 worker ScanGate 排队）。
# 字段与白盒 ScanRequest 分支同义（url/认证/HOST/delete_repo_on_finish 共享给每个仓库），
# source 换为 repos: list[str]。校验移植自 ScanRequest 的三条互斥校验
# （_validate_auth_fields 家族 / _host_profile_xor_url），语义与单发白盒一致。


class BatchScanResultItem(BaseModel):
    repo: str
    ok: bool
    scan_id: str | None = None
    error: str | None = None


class BatchScanAccepted(BaseModel):
    workspace: str
    submitted: int
    failed: int
    results: list[BatchScanResultItem]


class BatchScanRequest(BaseModel):
    """POST /api/scan/batch 请求体（spec §3.1）。

    repos 上限 50（BATCH_SCAN_MAX_REPOS，对齐批量克隆的 BATCH_CLONE_MAX_URLS）。
    """

    workspace: str
    repos: list[str]
    url: str | None = None
    authentication: dict | None = None
    auth_accounts: list[dict] | None = None
    auth_profile_id: str | None = None
    auth_credential_ids: list[str] | None = None
    host_profile_id: str | None = None
    host_url: str | None = None
    delete_repo_on_finish: bool = False

    @field_validator("host_profile_id", "host_url", mode="before")
    @classmethod
    def _normalize_host_source(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise TypeError("HOST source must be a string")
        return value.strip()

    @field_validator("repos")
    @classmethod
    def _dedup_repos(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("repos 不能为空——请至少选择一个仓库")
        # 保序去重（用户重复提交同名的容错）；上限检查在去重之后——重复项不占额度
        seen: set[str] = set()
        out: list[str] = []
        for name in value:
            if name not in seen:
                seen.add(name)
                out.append(name)
        if len(out) > 50:
            raise ValueError("单次批量扫描最多 50 个仓库（BATCH_SCAN_MAX_REPOS）")
        return out

    def _validate_auth_fields(self) -> None:
        """与 ScanRequest._validate_auth_fields 同规则（复制而非继承——两条 body 契约独立演进）。"""
        has_profile = self.auth_profile_id is not None
        has_cred_ids = self.auth_credential_ids is not None
        has_inline = self.authentication is not None
        has_accounts = self.auth_accounts is not None
        if has_accounts and not has_inline:
            raise ValueError("auth_accounts 必须与 authentication 同时提供（内联多角色附加账号）")
        if (has_profile or has_cred_ids) and (has_inline or has_accounts):
            raise ValueError("登录配置不能同时指定认证档案与内联登录配置")
        if has_cred_ids and not has_profile:
            raise ValueError("选认证档案角色时必须同时指定 auth_profile_id")

    @model_validator(mode="after")
    def _combined_auth_rules(self) -> "BatchScanRequest":
        """移植 _whitebox_combined_optional：带 url=组合模式（认证可选，有时校验互斥）；
        无 url=纯白盒禁认证字段。"""
        if self.url:
            self._validate_auth_fields()
        else:
            has_any_auth = (self.authentication is not None or self.auth_accounts is not None
                            or self.auth_profile_id is not None or self.auth_credential_ids is not None)
            if has_any_auth:
                raise ValueError("纯白盒扫描不支持认证字段；如需登录扫描请填 url 走组合模式")
        return self

    @model_validator(mode="after")
    def _host_profile_xor_url(self) -> "BatchScanRequest":
        """移植 ScanRequest._host_profile_xor_url（组合模式段）。"""
        if self.url:
            if self.host_profile_id == "":
                raise ValueError("host_profile_id 不能为空；启用 HOST 后必须选择档案")
            if self.host_url == "":
                raise ValueError("host_url 不能为空；启用 HOST 后必须填写 URL")
            if self.host_profile_id is not None and self.host_url is not None:
                raise ValueError("host_profile_id 与 host_url 互斥，不能同时指定（HOST 档案二选一）")
            if self.host_url is not None:
                scheme = (urlparse(self.host_url).scheme or "").lower()
                if scheme not in ("http", "https"):
                    raise ValueError("host_url 仅允许 http/https URL")
        return self
```

**注意**：`repos` 去重在上限检查**之前**——重复项不算进 50。

- [ ] **Step 4: 跑测试确认通过**

```bash
cd /root/ft-codescan/packages/web && python -m pytest tests/test_api_scan_batch.py -v
```
预期：11 个校验测试全 PASS。

- [ ] **Step 5: Commit**

```bash
git add packages/web/src/supernova_web/models.py packages/web/tests/test_api_scan_batch.py
git commit -m "feat(web-be): 批量白盒扫描请求模型 BatchScanRequest——repos 上限 50 保序去重+白盒组合认证/HOST 互斥校验移植（TDD 11 测试）"
```

---

### Task 2: 后端 `POST /api/scan/batch` 端点（fan-out）

**Files:**
- Modify: `packages/web/src/supernova_web/api/scan.py`（`create_scan` 之后加 `create_scan_batch`）
- Test: `packages/web/tests/test_api_scan_batch.py`（追加端点测试）

**Interfaces:**
- Consumes: Task 1 的 `BatchScanRequest` / `BatchScanAccepted` / `BatchScanResultItem`；既有 `sm.start(req) -> (ws_name, scan_id)`；既有 `resolve_provider_config` / `ProviderConfigIncomplete`。
- Produces: `POST /api/scan/batch` → 202 `BatchScanAccepted{workspace, submitted, failed, results:[{repo, ok, scan_id?, error?}]}` 或 422（全失败 / provider 缺失 / 校验失败）。

- [ ] **Step 1: 追加失败的端点测试**

在 `test_api_scan_batch.py` 追加（复用 `test_api_scan.py` 的 FakeSM/登录 fixture 模式）：

```python
# —— 端点行为测试（Task 2）——
from fastapi.testclient import TestClient

from supernova_web.app import create_app
from supernova_web.components.scan_manager import TemporalUnavailable
from supernova_web.components.ws_config_store import default_ws_config


class FakeSM:
    """与 test_api_scan.FakeSM 同款，加 per-repo 失败注入（fail_repos）。"""

    def __init__(self):
        self.started = []
        self.fail_repos: set[str] = set()
        self.exc = None  # 全局异常（TemporalUnavailable 等）

    async def start(self, req):
        if self.exc:
            raise self.exc
        name = req.source.value if req.source else ""
        if name in self.fail_repos:
            raise ValueError(f"仓库未就绪（state=cloning），请先在 ws 内完成 clone")
        self.started.append(req)
        return "WSX", f"scan-{len(self.started):04d}"

    def active_pids(self):
        return {}


@pytest.fixture
def _authed_app(tmp_workspaces, monkeypatch):
    from supernova_core.utils.paths import resolve_workspaces_dir
    monkeypatch.setenv("SUPERNOVA_WORKER_ROOT", str(tmp_workspaces.parent))
    assert resolve_workspaces_dir() == tmp_workspaces
    monkeypatch.setenv("SUPERNOVA_WEB_COOKIE_SECURE", "0")
    from supernova_web.auth.passwords import hash_password
    app = create_app()
    app.state.auth_store.create_user("admin", hash_password("test-pw"), role="admin")
    app.state.config.workspaces_dir.joinpath("WSX").mkdir(parents=True, exist_ok=True)
    cfg = default_ws_config()
    cfg.provider.api_key = "test-key"
    app.state.ws_config_store.write("WSX", cfg)
    return app


def _client_of(_authed_app, fake):
    app = create_app(overrides={"scan_manager": fake})
    app.state.auth_store = _authed_app.state.auth_store
    app.state.session_manager = _authed_app.state.session_manager
    c = TestClient(app)
    tok = c.get("/api/auth/csrf").json()["csrf_token"]
    c.post("/api/auth/login", json={"username": "admin", "password": "test-pw"},
           headers={"X-CSRF-Token": tok})
    return c, c.get("/api/auth/csrf").json()["csrf_token"]


def _batch_body(repos, **kw):
    body = {"workspace": "WSX", "repos": repos}
    body.update(kw)
    return body


class TestCreateScanBatch:
    def test_fanout_all_ok_202(self, _authed_app):
        fake = FakeSM()
        c, tok = _client_of(_authed_app, fake)
        r = c.post("/api/scan/batch", json=_batch_body(["repo-a", "repo-b"]),
                   headers={"X-CSRF-Token": tok})
        assert r.status_code == 202
        body = r.json()
        assert body["workspace"] == "WSX"
        assert body["submitted"] == 2 and body["failed"] == 0
        assert all(item["ok"] and item["scan_id"] for item in body["results"])
        assert len(fake.started) == 2
        # 每条都是独立白盒 ScanRequest（source 指向对应 repo，公共字段共享）
        assert [s.source.value for s in fake.started] == ["repo-a", "repo-b"]
        assert all(s.type == "whitebox" for s in fake.started)

    def test_partial_failure_202(self, _authed_app):
        fake = FakeSM()
        fake.fail_repos = {"repo-b"}
        c, tok = _client_of(_authed_app, fake)
        r = c.post("/api/scan/batch", json=_batch_body(["repo-a", "repo-b"]),
                   headers={"X-CSRF-Token": tok})
        assert r.status_code == 202
        body = r.json()
        assert body["submitted"] == 1 and body["failed"] == 1
        by_repo = {item["repo"]: item for item in body["results"]}
        assert by_repo["repo-a"]["ok"] is True
        assert by_repo["repo-b"]["ok"] is False
        assert "未就绪" in by_repo["repo-b"]["error"]

    def test_all_failed_422_with_results(self, _authed_app):
        fake = FakeSM()
        fake.fail_repos = {"repo-a", "repo-b"}
        c, tok = _client_of(_authed_app, fake)
        r = c.post("/api/scan/batch", json=_batch_body(["repo-a", "repo-b"]),
                   headers={"X-CSRF-Token": tok})
        assert r.status_code == 422
        body = r.json()
        assert len(body["results"]) == 2
        assert all(not item["ok"] for item in body["results"])

    def test_provider_incomplete_422_zero_fanout(self, _authed_app):
        fake = FakeSM()
        c, tok = _client_of(_authed_app, fake)
        # 覆写 WSX 配置为缺 key 的默认值
        c.app.state.ws_config_store.write("WSX", default_ws_config())
        r = c.post("/api/scan/batch", json=_batch_body(["repo-a"]),
                   headers={"X-CSRF-Token": tok})
        assert r.status_code == 422
        detail = r.json()["detail"]
        assert detail["code"] == "provider_incomplete"
        assert fake.started == []

    def test_shared_fields_forwarded(self, _authed_app):
        fake = FakeSM()
        c, tok = _client_of(_authed_app, fake)
        r = c.post("/api/scan/batch",
                   json=_batch_body(["repo-a", "repo-b"], url="http://t.example",
                                    delete_repo_on_finish=True),
                   headers={"X-CSRF-Token": tok})
        assert r.status_code == 202
        for s in fake.started:
            assert s.url == "http://t.example"
            assert s.delete_repo_on_finish is True

    def test_workspace_not_exist_422(self, _authed_app):
        fake = FakeSM()
        c, tok = _client_of(_authed_app, fake)
        r = c.post("/api/scan/batch", json=_batch_body(["repo-a"], **{"workspace": "NOPE"}),
                   headers={"X-CSRF-Token": tok})
        assert r.status_code == 422
        assert fake.started == []

    def test_non_member_403(self, _authed_app):
        """权限：普通用户非该 ws 成员且非全局 admin → 403，0 次 fan-out（spec §6）。"""
        fake = FakeSM()
        app = create_app(overrides={"scan_manager": fake})
        app.state.auth_store = _authed_app.state.auth_store
        app.state.session_manager = _authed_app.state.session_manager
        from supernova_web.auth.passwords import hash_password
        app.state.auth_store.create_user("outsider", hash_password("test-pw"), role="user")
        c = TestClient(app)
        tok = c.get("/api/auth/csrf").json()["csrf_token"]
        c.post("/api/auth/login", json={"username": "outsider", "password": "test-pw"},
               headers={"X-CSRF-Token": tok})
        r = c.post("/api/scan/batch", json=_batch_body(["repo-a"]),
                   headers={"X-CSRF-Token": tok})
        assert r.status_code == 403
        assert fake.started == []
```

- [ ] **Step 2: 跑测试确认失败**

```bash
cd /root/ft-codescan/packages/web && python -m pytest tests/test_api_scan_batch.py -v -k TestCreateScanBatch
```
预期：404 Not Found（路由不存在，FastAPI 返回 404 而非 405）。共 7 个端点测试（含 `test_non_member_403`）。

- [ ] **Step 3: 实现端点**

在 `api/scan.py` 的 `create_scan` 函数之后、`get_scan_gate` 之前插入：

```python
@router.post("/batch", response_model=BatchScanAccepted, status_code=202)
async def create_scan_batch(req: BatchScanRequest, request: Request,
                            user: User = Depends(current_user)):
    """批量白盒扫描（spec 2026-09-11-batch-whitebox-scan §3）。

    端点层逐仓循环调既有 sm.start()——scan_manager 零改动；单仓失败（未就绪/
    不存在/排队满/Temporal 异常）只计入该仓 results，不阻断整批。有任何成功 →
    202；全部失败 → 422 附 results。并发由 worker ScanGate 排队（web 不限）。
    """
    ws = req.workspace
    if not ws or not is_safe_workspace_name(ws):
        raise HTTPException(422, "workspace 不存在，请先让 admin 创建")
    ws_dir = request.app.state.config.workspaces_dir / ws
    if not ws_dir.is_dir() or ws_dir.is_symlink():
        raise HTTPException(422, "workspace 不存在，请先让 admin 创建")
    if not is_global_admin(user) and request.app.state.auth_store.get_workspace_member_role(
            ws, user.id) is None:
        raise HTTPException(403, "非该 workspace 成员")
    try:
        request.app.state.ws_config_store.resolve_provider_config(ws)
    except ProviderConfigIncomplete as e:
        raise HTTPException(422, detail={"code": "provider_incomplete", "missing": e.missing})

    sm = request.app.state.scan_manager
    results: list[BatchScanResultItem] = []
    for repo in req.repos:
        single = ScanRequest(
            type="whitebox",
            source=RepoSource(kind="repo", value=repo),
            url=req.url,
            workspace=req.workspace,
            authentication=req.authentication,
            auth_accounts=req.auth_accounts,
            auth_profile_id=req.auth_profile_id,
            auth_credential_ids=req.auth_credential_ids,
            host_profile_id=req.host_profile_id,
            host_url=req.host_url,
            delete_repo_on_finish=req.delete_repo_on_finish,
        )
        try:
            _, scan_id = await sm.start(single)
            results.append(BatchScanResultItem(repo=repo, ok=True, scan_id=scan_id))
        except TemporalUnavailable:
            results.append(BatchScanResultItem(
                repo=repo, ok=False, error="Temporal 服务未运行，请先 docker-compose up -d"))
        except PermissionError as e:
            results.append(BatchScanResultItem(repo=repo, ok=False, error=str(e)))
        except ValueError as e:
            results.append(BatchScanResultItem(repo=repo, ok=False, error=str(e)))

    submitted = sum(1 for r in results if r.ok)
    failed = len(results) - submitted
    if submitted == 0:
        raise HTTPException(
            422, detail=BatchScanAccepted(
                workspace=ws, submitted=0, failed=failed, results=results).model_dump())
    return BatchScanAccepted(workspace=ws, submitted=submitted, failed=failed, results=results)
```

同时更新 `api/scan.py` 顶部 import：

```python
from supernova_web.models import (
    BatchScanAccepted, BatchScanRequest, BatchScanResultItem, RepoSource, ScanAccepted, ScanRequest,
)
```

（`RepoSource` 从 models.py import——`models.py` 已有该类定义。）

- [ ] **Step 4: 跑测试确认通过**

```bash
cd /root/ft-codescan/packages/web && python -m pytest tests/test_api_scan_batch.py -v
```
预期：Task 1 的 11 个校验测试 + Task 2 的 7 个端点测试全 PASS。

- [ ] **Step 5: 回归既有 scan 端点测试**

```bash
cd /root/ft-codescan/packages/web && python -m pytest tests/test_api_scan.py -v
```
预期：全 PASS（`/scan` 路由未被波及；router 前缀 `/api/scan` + `/batch` 不与 `""` 冲突）。

- [ ] **Step 6: Commit**

```bash
git add packages/web/src/supernova_web/api/scan.py packages/web/tests/test_api_scan_batch.py
git commit -m "feat(web-be): POST /api/scan/batch 批量白盒 fan-out——端点层循环 sm.start 单仓失败不阻断+全失败 422 附 results+provider 缺失零 fan-out（scan_manager 零改动，TDD 6 端点测试）"
```

---

### Task 3: 前端白盒 tab 多选改造（复用 RepositoryMultiSelector）

**Files:**
- Modify: `packages/web/frontend/src/pages/ScanNewPage.tsx`（FormState + 白盒校验 + buildBody 白盒分支 + MR 表单不动）
- Modify: `packages/web/frontend/src/components/ScanFormFields.tsx`（repoPicker 换多选列表）
- Test: `packages/web/frontend/src/pages/ScanNewPage.test.tsx`（修断言 + 新增多选用例）
- Test: `packages/web/frontend/src/components/ScanFormFields.test.tsx`（白盒仓库区断言更新）

**Interfaces:**
- Consumes: 既有 `RepositoryMultiSelector`（`packages/web/frontend/src/components/correlation/RepositoryMultiSelector.tsx`，props：`{repos: Repo[], selected: string[], onChange: (next: string[]) => void, disabled?: boolean}`——已具备搜索/全选/清空/已选计数/未就绪禁选+state 原文灰显）。
- Produces: `FormState.selectedRepos: string[]`（白盒专用，Task 4/5 依赖）；`validateSource` 签名不变（仍收 string，白盒侧传 `f.selectedRepos[0] ?? ""`）。

**设计要点（执行者必读）：**
- **双状态**：保留 `selectedRepo: string`（MR 专用，`ScanNewPage.tsx:275` 附近 + MR 表单 `:973-986` + `handleLinkResolved :745` + `presetRepo effect :571` 全部零改动）；新增 `selectedRepos: string[]`（白盒专用）。
- preset 初始化：`selectedRepos` 初值 = 白盒 preset 时 `[preset.repo ?? presetRepo ?? ""]` 过滤空串，否则 `[]`。具体：`selectedRepos: preset.type === "mr" || preset.type === "blackbox" || preset.type === "correlation" ? [] : [preset.repo ?? presetRepo ?? ""].filter(Boolean)`。`presetRepo` 的 effect（`ScanNewPage.tsx:570-573`）同时补 `selectedRepos`：`set({ selectedRepo: presetRepo, selectedRepos: presetRepo ? [presetRepo] : [] })`。
- 白盒 repoPicker 里**移除** `CloneProgress` 与 `RepoQuickActions`（多选列表自带 state 原文显示；快捷操作去仓库页）；**保留**「+ 添加新仓库」按钮 + `AddRepoDialog`（`onCreated` 回填改并入 `selectedRepos`）；**保留** `DeleteRepoOnFinishCheckbox`（disabled 改为「选中项含 linked 仓」）。
- 新增 `BusyReposWatch`：`repos` 存在 busy 态（cloning/pulling/extracting）时每 2s `refresh()`（复用 `ScanNewPage.tsx:254-255` 的 `CLONE_POLL_MS`/`CLONE_BUSY_STATES` 常量），让多选列表的 cloning→ready 实时翻转。放 `ScanFormFields.tsx` 内（用 `useRepos(workspace)` 的 refresh）。

- [ ] **Step 1: 写失败的白盒多选测试**

`ScanNewPage.test.tsx` 追加（该文件已有 msw server + `renderPage` + repo 注入模式——参照既有「repo 相关用例各自 server.use 注入」注释）：

```tsx
// —— 批量白盒扫描（spec 2026-09-11）：白盒 tab 仓库多选 ——
// 复用本文件既有 helper：selectWorkspace（Radix Select 已验证 click 姿势）。
// RepositoryMultiSelector 的 checkbox 无 label-for 可达名（label 文本含仓库名但
// htmlFor id 是 topology-repo-<name> 派生）——按序取 getAllByRole("checkbox") 断言。
describe("whitebox multi-repo select", () => {
  const MULTI_REPOS = [
    { name: "be/gateway", group: "be", source: { kind: "git", url: "https://gl/gw.git" }, state: "ready" },
    { name: "be/auth", group: "be", source: { kind: "git", url: "https://gl/auth.git" }, state: "ready" },
    { name: "be/cloning", group: "be", source: { kind: "git", url: "https://gl/c.git" }, state: "cloning" },
  ];

  it("白盒 tab 渲染多选列表（勾选两个 ready 仓，cloning 仓禁选）", async () => {
    server.use(
      http.get("/api/workspaces/:ws/repos", () => HttpResponse.json(MULTI_REPOS)),
    );
    renderPage();
    await selectWorkspace("ws1");
    const selector = await screen.findByTestId("topology-repo-selector");
    const boxes = within(selector).getAllByRole("checkbox");
    expect(boxes).toHaveLength(3);
    fireEvent.click(boxes[0]);  // be/gateway
    fireEvent.click(boxes[1]);  // be/auth
    expect(boxes[2]).toBeDisabled();  // be/cloning
    // 已选计数显示 2
    expect(within(selector).getByText("已选 2")).toBeInTheDocument();
  });

  it("buildBody 白盒分支单发取 selectedRepos[0]", () => {
    // baseF：本文件既有 FormState 字面量 helper（若名为其他——以文件内实际为准，
    // 执行者 grep "FormState = {" 找到基础字面量复制，补 selectedRepos 字段）。
    const f = { ...BASE_FORM_STATE, selectedRepos: ["be/gateway"] } as FormState;
    const body = buildBody("whitebox", f, "ws1");
    expect(body.source).toEqual({ kind: "repo", value: "be/gateway" });
  });
});
```

**执行者注意**：`BASE_FORM_STATE` 是占位名——`ScanNewPage.test.tsx` 里已有构造 `FormState` 的字面量模式（grep `FormState` 找到最近的完整字面量，本计划 Task 3 Step 3 加了 `selectedRepos` 必填字段后**所有既有 FormState 字面量都要补 `selectedRepos: [...]`**，白盒用例补选中的仓库名、MR 用例补 `[]`）。`已选 2` 是 `scan.correlation.analysis.selectedCount`（"已选 {{count}}"）的渲染结果——RepositoryMultiSelector 复用该 key。

- [ ] **Step 2: 跑测试确认失败**

```bash
cd /root/ft-codescan/packages/web/frontend && npx vitest run src/pages/ScanNewPage.test.tsx
```
预期：新用例 FAIL（无 `topology-repo-selector` 元素 / `selectedRepos` 类型不存在编译错）。

- [ ] **Step 3: 实现**

**3a. `ScanNewPage.tsx`：**
1. `FormState` 加字段（`selectedRepo` 注释改为「MR 专用」）：
```tsx
export interface FormState {
  /** MR 增量扫描专用仓库（单选；批量白盒不使用——白盒用 selectedRepos）。 */
  selectedRepo: string;
  /** 白盒批量/单发共用仓库多选（2026-09-11 批量白盒扫描）：长度 1 = 单发（行为同旧版），
   *  ≥2 = 批量（Task 4 走 /scan/batch）。MR 不使用。 */
  selectedRepos: string[];
  // …… 其余字段不动
}
```
2. 初始 state（`:472-488`）：`selectedRepo` 后加 `selectedRepos: preset.type && preset.type !== "whitebox" ? [] : [preset.repo ?? presetRepo ?? ""].filter(Boolean)`。
3. `presetRepo` effect（`:570-573`）：`set({ selectedRepo: presetRepo, selectedRepos: presetRepo ? [presetRepo] : [] })`。
4. 白盒 `sourceErr`（`:787`）：改 `type === "whitebox" ? validateSource(f.selectedRepos[0] ?? "", t) : type === "mr" ? validateSource(f.selectedRepo, t) : null`。
5. `buildBody` 白盒分支（`:389`）：`body.source = { kind: "repo", value: f.selectedRepos[0] ?? "" };`（MR 分支 `:357` 不动）。

**3b. `ScanFormFields.tsx` repoPicker 段（`:811-840`）重写：**

```tsx
  // —— 白盒仓库多选（2026-09-11 批量白盒扫描）：复用 correlation 的
  // RepositoryMultiSelector（搜索/全选/计数/未就绪禁选灰显 state 原文）。
  // CloneProgress/RepoQuickActions 随单选下拉退役——多选列表自带 state 显示，
  // busy 态由 BusyReposWatch 轮询驱动翻转；快捷操作去仓库页。
  const anySelectedLinked = repos.some((r) => r.linked && f.selectedRepos.includes(r.name));
  const repoPicker = workspace ? (
    <div className="space-y-2">
      <RepositoryMultiSelector
        repos={repos}
        selected={f.selectedRepos}
        onChange={(next) => set({ selectedRepos: next })}
      />
      <Button variant="outline" size="sm" onClick={() => setAddOpen(true)}>{t("scan.repo.addBtn")}</Button>
      <DeleteRepoOnFinishCheckbox
        checked={!!f.deleteRepoOnFinish}
        onChange={(v) => set({ deleteRepoOnFinish: v })}
        disabled={anySelectedLinked}
      />
      <AddRepoDialog ws={workspace} open={addOpen} onOpenChange={setAddOpen}
        onCreated={(name) => set({ selectedRepos: [...new Set([...f.selectedRepos, name])] })} />
      <BusyReposWatch workspace={workspace} repos={repos} />
    </div>
  ) : (
    <div className="text-xs text-muted-foreground">{t("scan.fields.selectWsFirst")}</div>
  );
```

同文件顶部 import：`import { RepositoryMultiSelector } from "./correlation/RepositoryMultiSelector";`，并删除不再使用的 `RepoCombobox`/`CloneProgress`/`RepoQuickActions` import（仅当文件内无其他引用时——先 grep 确认）。

**3c. `ScanFormFields.tsx` 新增 BusyReposWatch（组件文件底部或 ScanNewPage 导出后）：**

```tsx
/** busy 仓轮询（2026-09-11 批量白盒）：repos 有 cloning/pulling/extracting 时 2s 刷 SWR
 *  缓存，让多选列表的 state 原文（cloning→ready）实时翻转；全部脱离忙态即停。 */
function BusyReposWatch({ workspace, repos }: { workspace: string; repos: Repo[] }) {
  const { refresh } = useRepos(workspace || undefined);
  const busy = repos.some((r) => CLONE_BUSY_STATES.has(r.state));
  useEffect(() => {
    if (!busy) return;
    const timer = window.setInterval(() => void refresh(), CLONE_POLL_MS);
    return () => window.clearInterval(timer);
  }, [busy, refresh]);
  return null;
}
```

（`CLONE_POLL_MS`/`CLONE_BUSY_STATES`/`useRepos` 从 `ScanNewPage.tsx`/`@/api/useRepos` 引入；若 `CLONE_*` 常量未导出，把它们 export 或在本文件复制一份同值常量——优先 export。）

- [ ] **Step 4: 跑测试，修既有断言**

```bash
cd /root/ft-codescan/packages/web/frontend && npx vitest run src/pages/ScanNewPage.test.tsx src/components/ScanFormFields.test.tsx
```
既有用例失败属预期（白盒表单结构变了）——机械性修复：涉及白盒 repo 选择/断言 `RepoCombobox` 的用例改为多选交互（`topology-repo-selector` 内勾选）；`baseF` 类 FormState 字面量补 `selectedRepos: []` 或 `selectedRepos: ["<仓库名>"]`。**MR 用例不应需要改**（MR 表单零改动——若有 MR 用例挂了说明改错了地方）。

- [ ] **Step 5: 类型门禁**

```bash
cd /root/ft-codescan/packages/web/frontend && npx tsc -b
```
预期：零错误。

- [ ] **Step 6: Commit**

```bash
git add packages/web/frontend/src/pages/ScanNewPage.tsx packages/web/frontend/src/components/ScanFormFields.tsx packages/web/frontend/src/pages/ScanNewPage.test.tsx packages/web/frontend/src/components/ScanFormFields.test.tsx
git commit -m "feat(web-fe): 白盒 tab 仓库多选改造——复用 RepositoryMultiSelector（搜索/全选/未就绪禁选）+FormState.selectedRepos 双状态（MR 单选零改动）+BusyReposWatch 轮询；单发提交行为不变"
```

---

### Task 4: 前端批量提交链路（types/client + buildBatchBody + 跳列表 + 横幅）

**Files:**
- Modify: `packages/web/frontend/src/api/types.ts`（`ScanResponse` 之后加批量类型）
- Modify: `packages/web/frontend/src/api/client.ts`（`batchClone` 附近加 `createBatchScan`）
- Modify: `packages/web/frontend/src/pages/ScanNewPage.tsx`（`buildBatchBody` + `onSubmit` 分流 + 按钮文案）
- Modify: `packages/web/frontend/src/routes/WorkspaceDetail/ScanList.tsx`（顶部批量结果横幅）
- Modify: `packages/web/frontend/src/locales/zh.json` / `en.json`（新文案）
- Test: `packages/web/frontend/src/pages/ScanNewPage.test.tsx`（批量提交用例）
- Test: `packages/web/frontend/src/routes/WorkspaceDetail/ScanList.test.tsx`（横幅用例）

**Interfaces:**
- Consumes: Task 1/2 的后端契约（`POST /api/scan/batch` 请求/响应）；Task 3 的 `FormState.selectedRepos`。
- Produces: `createBatchScan(body: BatchScanRequest): Promise<BatchScanResponse>`（client.ts）；`buildBatchBody(repos: string[], f: FormState, workspace: string): BatchScanRequest`（ScanNewPage.tsx export，测试用）；ScanList 经 `location.state.batchResult` 显示横幅（Task 5 不依赖）。

- [ ] **Step 1: 写失败的测试**

`ScanNewPage.test.tsx` 追加：

```tsx
describe("whitebox batch submit", () => {
  const BATCH_REPOS = [
    { name: "be/gateway", group: "be", state: "ready", source: { kind: "git", url: "https://gl/gw.git" } },
    { name: "be/auth", group: "be", state: "ready", source: { kind: "git", url: "https://gl/a.git" } },
  ];

  it("buildBatchBody 组合公共字段（url/delete）", () => {
    const f = { ...BASE_FORM_STATE, selectedRepos: ["be/gateway", "be/auth"],
               combined: true, url: "http://t", deleteRepoOnFinish: true } as FormState;
    const body = buildBatchBody(["be/gateway", "be/auth"], f, "ws1");
    expect(body.repos).toEqual(["be/gateway", "be/auth"]);
    expect(body.workspace).toBe("ws1");
    expect(body.url).toBe("http://t");
    expect(body.delete_repo_on_finish).toBe(true);
  });

  it("buildBatchBody 纯白盒（无 combined）不发 url/auth 字段", () => {
    const f = { ...BASE_FORM_STATE, selectedRepos: ["be/gateway", "be/auth"] } as FormState;
    const body = buildBatchBody(["be/gateway", "be/auth"], f, "ws1");
    expect(body.url).toBeUndefined();
    expect(body.authentication).toBeUndefined();
  });

  it("选 2 仓 → 按钮文案「发起批量扫描 (2)」→ 提交走 /scan/batch → 跳列表页带 state", async () => {
    let captured: unknown;
    server.use(
      http.get("/api/workspaces/:ws/repos", () => HttpResponse.json(BATCH_REPOS)),
      http.post("/api/scan/batch", async ({ request }) => {
        captured = await request.json();
        return HttpResponse.json(
          { workspace: "ws1", submitted: 1, failed: 1,
            results: [
              { repo: "be/gateway", ok: true, scan_id: "scan-0001" },
              { repo: "be/auth", ok: false, error: "仓库未就绪（state=cloning）" },
            ] }, { status: 202 }));
      }),
    );
    renderPage();
    await selectWorkspace("ws1");
    const selector = await screen.findByTestId("topology-repo-selector");
    const boxes = within(selector).getAllByRole("checkbox");
    fireEvent.click(boxes[0]);
    fireEvent.click(boxes[1]);
    const btn = await screen.findByRole("button", { name: "发起批量扫描 (2)" });
    fireEvent.click(btn);
    await waitFor(() => expect(captured).toBeDefined());
    expect((captured as { repos: string[] }).repos).toEqual(["be/gateway", "be/auth"]);
    // 跳转：MemoryRouter 无真路由表——断言 nav 离开表单（按钮消失/表单元素消失）即可；
    // 精确路由断言由 ScanList 横幅用例（下方）覆盖 location.state 链路。
    await waitFor(() =>
      expect(screen.queryByTestId("topology-repo-selector")).not.toBeInTheDocument());
  });
});
```

（`BASE_FORM_STATE` 同 Task 3 注意事项——用文件内实际 FormState 字面量 helper 名。`buildBatchBody` 需加入文件顶部 import。）

`ScanList.test.tsx` 追加横幅用例（该文件已有 `renderWithSwr` + `MemoryRouter` + mock `useNavigate` 的套路，`renderList()` 在 `:126-132`）：

```tsx
it("批量提交结果横幅：location.state.batchResult 显示成功/失败明细，可关闭", async () => {
  renderWithSwr(
    <MemoryRouter initialEntries={[{
      pathname: "/p/ws",
      state: { batchResult: { workspace: "ws1", submitted: 1, failed: 1,
        results: [{ repo: "be/auth", ok: false, error: "仓库未就绪（state=cloning）" }] } },
    }]}>
      <Routes><Route path="/p/:workspace" element={<ScanList />} /></Routes>
    </MemoryRouter>,
  );
  expect(screen.getByTestId("batch-result-banner")).toBeInTheDocument();
  expect(screen.getByText(/成功 1/)).toBeInTheDocument();
  expect(screen.getByText(/be\/auth/)).toBeInTheDocument();
  fireEvent.click(screen.getByTestId("batch-banner-close"));
  await waitFor(() =>
    expect(screen.queryByTestId("batch-result-banner")).not.toBeInTheDocument());
});
```

（注意：该文件 mock 了 `react-router-dom` 的 `useNavigate` 为 `navMock`——横幅实现里的「读后 replace 清 state」走 mock 不影响渲染；`useState` 捕获式设计（见 3d）保证 nav 后横幅仍在。）

- [ ] **Step 2: 跑测试确认失败**

```bash
cd /root/ft-codescan/packages/web/frontend && npx vitest run src/pages/ScanNewPage.test.tsx src/routes/WorkspaceDetail/ScanList.test.tsx
```
预期：新用例 FAIL（`buildBatchBody` 未导出 / `createBatchScan` 不存在 / 无横幅）。

- [ ] **Step 3: 实现**

**3a. `types.ts`（`ScanResponse` 之后）：**

```ts
/** 批量白盒扫描（2026-09-11）：POST /api/scan/batch——N 个仓库共享其余白盒配置，
 *  各自产生独立扫描。字段名与 backend models.py BatchScanRequest 一致。 */
export interface BatchScanRequest {
  workspace: string;
  repos: string[];
  url?: string;
  authentication?: ScanAuthentication;
  auth_accounts?: { role: string; username: string; password: string; totp_secret?: string }[];
  auth_profile_id?: string;
  auth_credential_ids?: string[];
  host_profile_id?: string;
  host_url?: string;
  delete_repo_on_finish?: boolean;
}

export interface BatchScanResultItem {
  repo: string;
  ok: boolean;
  scan_id?: string;
  error?: string;
}

export interface BatchScanResponse {
  workspace: string;
  submitted: number;
  failed: number;
  results: BatchScanResultItem[];
}
```

**3b. `client.ts`（`batchClone` 定义附近）：**

```ts
export const createBatchScan = (body: import("./types").BatchScanRequest) =>
  apiPost<import("./types").BatchScanResponse>("/scan/batch", body);
```

**3c. `ScanNewPage.tsx`：**

1. import 加 `createBatchScan` 与 `BatchScanRequest`/`BatchScanResponse` 类型。
2. `assignAuthToBody`/`assignHostToBody` 的参数类型从 `ScanRequest` 放宽（批量 body 无 type/source 字段，structural typing 不兼容）：
```tsx
/** 认证/HOST 字段写入目标：单发 ScanRequest 与批量 BatchScanRequest 的公共字段面
 *  （2026-09-11 批量白盒：两条 body 共用同一映射函数，字段名恒一致）。 */
type AuthHostBody = Pick<ScanRequest, "authentication" | "auth_accounts" | "auth_profile_id"
  | "auth_credential_ids" | "host_profile_id" | "host_url">;
function assignAuthToBody(body: AuthHostBody, a: AuthFormState): void { /* 函数体不动 */ }
function assignHostToBody(body: AuthHostBody, h: HostFormState): void { /* 函数体不动 */ }
```
3. `buildBlackboxRunBody` 之前加：
```tsx
/** 批量白盒提交 body（2026-09-11 spec §4.2）：repos + 共享白盒配置。认证/HOST 映射
 *  与单发白盒组合模式共用 assignAuthToBody/assignHostToBody（hostIsActive 校验同款）。 */
export function buildBatchBody(repos: string[], f: FormState, workspace: string): BatchScanRequest {
  const combinedOn = !!f.combined && !!f.url;
  if (combinedOn) {
    const hostError = hostValidationKey(f.host);
    if (hostError) throw new Error(hostError);
  }
  const body: BatchScanRequest = { workspace: workspace || "", repos };
  if (combinedOn) {
    body.url = f.url;
    if (f.auth.enabled) assignAuthToBody(body, f.auth);
    assignHostToBody(body, f.host);
  }
  if (f.deleteRepoOnFinish) body.delete_repo_on_finish = true;
  return body;
}
```
4. `onSubmit` 白盒分流（`:832` 的 `apiPost` 之前）：
```tsx
      // 批量白盒（2026-09-11）：≥2 仓走 /scan/batch，跳扫描列表页 + location.state
      // 带汇总（ScanList 顶部横幅显示成功/失败明细）；1 仓维持单发直跳 live（零变化）。
      if (type === "whitebox" && f.selectedRepos.length > 1) {
        const r = await createBatchScan(buildBatchBody(f.selectedRepos, f, workspace));
        nav(`/p/${r.workspace}/scans`, { state: { batchResult: r } });
        return;
      }
```
5. 按钮文案（`:853` 附近）：
```tsx
  const submitLabel = type === "whitebox" && f.selectedRepos.length > 1
    ? t("scan.batch.submit", { count: f.selectedRepos.length })
    : t("scan.submit");
```

**3d. `ScanList.tsx` 顶部横幅（列表 Card 之前）：**

```tsx
// 批量提交结果横幅（2026-09-11 批量白盒）：ScanNewPage 批量提交后经 location.state
// 传入 BatchScanResponse。useState 初始化器捕获首帧 state（闭包固定）——effect 里
// navigate replace 清掉 history entry 的 state 后（防刷新/后退重复呈现），横幅仍显示
// （若直接读 location.state，replace 触发的重渲染会把 batchResult 变 undefined，
// 横幅闪现即消失——已规避）。关闭用局部 bannerClosed。
const location = useLocation();
const nav = useNavigate();
const [batchResult] = useState(
  () => (location.state as { batchResult?: BatchScanResponse } | null)?.batchResult ?? null);
const [bannerClosed, setBannerClosed] = useState(false);
useEffect(() => {
  if (batchResult) nav(location.pathname, { replace: true });
  // eslint-disable-next-line react-hooks/exhaustive-deps
}, []);
```

渲染（表格区上方）：

```tsx
{batchResult && !bannerClosed && (
  <div data-testid="batch-result-banner"
    className="flex items-start justify-between gap-3 rounded-lg border border-border bg-card px-4 py-3">
    <div className="min-w-0 text-xs">
      <span className="font-medium">{t("scan.batch.bannerTitle",
        { ok: batchResult.submitted, fail: batchResult.failed })}</span>
      {batchResult.failed > 0 && (
        <ul className="mt-1.5 space-y-0.5">
          {batchResult.results.filter((r) => !r.ok).map((r) => (
            <li key={r.repo} className="font-mono text-[11px] text-destructive">
              {r.repo}：{r.error}
            </li>
          ))}
        </ul>
      )}
    </div>
    <button type="button" data-testid="batch-banner-close" aria-label={t("scan.batch.bannerClose")}
      className="shrink-0 text-muted-foreground hover:text-foreground"
      onClick={() => setBannerClosed(true)}>✕</button>
  </div>
)}
```

（`useLocation` 已在该文件 import——`useNavigate` 亦然（`ScanList.tsx:5`）；`useState`/`useEffect` 同文件已有；`BatchScanResponse` 类型从 `@/api/types` import 追加。）

**3e. i18n（zh.json 的 `scan` 对象内加 `batch` 子对象；en.json 同步）：**

zh：
```json
"batch": {
  "submit": "发起批量扫描 ({{count}})",
  "bannerTitle": "批量提交完成：成功 {{ok}} / 失败 {{fail}}",
  "bannerClose": "关闭批量结果提示"
}
```
en：
```json
"batch": {
  "submit": "Start batch scan ({{count}})",
  "bannerTitle": "Batch submitted: {{ok}} succeeded / {{fail}} failed",
  "bannerClose": "Dismiss batch result"
}
```

- [ ] **Step 4: 跑测试确认通过 + 类型门禁**

```bash
cd /root/ft-codescan/packages/web/frontend && npx vitest run src/pages/ScanNewPage.test.tsx src/routes/WorkspaceDetail/ScanList.test.tsx && npx tsc -b
```
预期：全 PASS + 零类型错误。

- [ ] **Step 5: Commit**

```bash
git add packages/web/frontend/src/api/types.ts packages/web/frontend/src/api/client.ts packages/web/frontend/src/pages/ScanNewPage.tsx packages/web/frontend/src/routes/WorkspaceDetail/ScanList.tsx packages/web/frontend/src/locales/zh.json packages/web/frontend/src/locales/en.json packages/web/frontend/src/pages/ScanNewPage.test.tsx packages/web/frontend/src/routes/WorkspaceDetail/ScanList.test.tsx
git commit -m "feat(web-fe): 批量白盒提交链路——≥2 仓走 /scan/batch 跳列表页+location.state 汇总横幅（失败明细可关闭）+按钮文案计数+assignAuth/Host 放宽到 AuthHostBody 公共字段面（TDD）"
```

---

### Task 5: AddRepoDialog 批量克隆预选增强

**Files:**
- Modify: `packages/web/frontend/src/components/AddRepoDialog.tsx`（批量克隆分支 + 新 prop）
- Modify: `packages/web/frontend/src/components/ScanFormFields.tsx`（传 `onBatchCreated`）
- Test: `packages/web/frontend/src/components/AddRepoDialog.test.tsx`

**Interfaces:**
- Consumes: 既有 `batchClone(ws, {urls, group}) → BatchCloneResult{submitted: string[], queued: string[], skipped}`（`AddRepoDialog.tsx:74-80`）。
- Produces: `AddRepoDialog` 新可选 prop `onBatchCreated?: (names: string[]) => void`——批量克隆提交成功后以本批全部新仓库名（submitted + queued）调用。

- [ ] **Step 1: 写失败的测试**

`AddRepoDialog.test.tsx` 追加（该文件**不走 msw**——在模块层 `vi.mock("@/api/client", ...)` 把 `batchClone` 换成 `mockBatchClone`（见 `:16`），既有用例 `:111`「批量克隆：多行输入走 batchClone，onCreated 回调首个仓库名」就是完整范本，直接照抄其 mockReturn 设置）：

```tsx
it("批量克隆提交成功后 onBatchCreated 收到全部新仓库名（submitted+queued）", async () => {
  const onBatchCreated = vi.fn();
  mockBatchClone.mockResolvedValue(
    { submitted: ["be/new-a"], queued: ["be/new-b"], skipped: [] });
  render(<AddRepoDialog ws="ws1" open onOpenChange={() => {}} onCreated={() => {}}
    onBatchCreated={onBatchCreated} />);
  fireEvent.change(await screen.findByTestId("repo-urls"),
    { target: { value: "https://gl/a.git\nhttps://gl/b.git" } });
  fireEvent.click(screen.getByTestId("submit"));
  await waitFor(() =>
    expect(onBatchCreated).toHaveBeenCalledWith(["be/new-a", "be/new-b"]));
});

it("未传 onBatchCreated 时批量克隆仍走 onCreated(首个)（向后兼容）", async () => {
  const onCreated = vi.fn();
  mockBatchClone.mockResolvedValue(
    { submitted: ["be/new-a"], queued: ["be/new-b"], skipped: [] });
  render(<AddRepoDialog ws="ws1" open onOpenChange={() => {}} onCreated={onCreated} />);
  fireEvent.change(await screen.findByTestId("repo-urls"),
    { target: { value: "https://gl/a.git\nhttps://gl/b.git" } });
  fireEvent.click(screen.getByTestId("submit"));
  await waitFor(() => expect(onCreated).toHaveBeenCalledWith("be/new-a"));
});
```

- [ ] **Step 2: 跑测试确认失败**

```bash
cd /root/ft-codescan/packages/web/frontend && npx vitest run src/components/AddRepoDialog.test.tsx
```
预期：新用例 FAIL（`onBatchCreated` prop 不存在）。

- [ ] **Step 3: 实现**

`AddRepoDialog.tsx`：
1. `Props` 接口加：
```tsx
  /** 批量克隆提交成功回调（2026-09-11 批量白盒预选增强）：传本批全部新仓库名
   *  （submitted+queued，skipped 不含）——调用方（白盒表单）把它们预选进多选列表。
   *  可选：不传则维持旧行为 onCreated(首个)。 */
  onBatchCreated?: (names: string[]) => void;
```
组件参数解构同步加 `onBatchCreated`。
2. 批量克隆分支（`:71-80`）成功后：
```tsx
        const names = [...r.submitted, ...r.queued];
        if (onBatchCreated) onBatchCreated(names);
        else onCreated(r.submitted[0] ?? r.queued[0] ?? "");
```

`ScanFormFields.tsx` 的 `AddRepoDialog` 调用加：
```tsx
        onBatchCreated={(names) => set({ selectedRepos: [...new Set([...f.selectedRepos, ...names])] })}
```

- [ ] **Step 4: 跑测试确认通过**

```bash
cd /root/ft-codescan/packages/web/frontend && npx vitest run src/components/AddRepoDialog.test.tsx && npx tsc -b
```
预期：PASS + 零类型错误。

- [ ] **Step 5: Commit**

```bash
git add packages/web/frontend/src/components/AddRepoDialog.tsx packages/web/frontend/src/components/ScanFormFields.tsx packages/web/frontend/src/components/AddRepoDialog.test.tsx
git commit -m "feat(web-fe): AddRepoDialog 批量克隆预选增强——onBatchCreated 回调本批全部新仓库名并入白盒多选已选（cloning 中显示待就绪态，纯前端预选不自动扫，TDD）"
```

---

### Task 6: 端到端验证收尾

**Files:**
- Modify: `docs/superpowers/specs/2026-09-11-batch-whitebox-scan-design.md`（状态行更新）

**Interfaces:**
- Consumes: Task 1-5 全部产出。
- Produces: 验证过的完整功能。

- [ ] **Step 1: 后端相关测试全量**

```bash
cd /root/ft-codescan/packages/web && python -m pytest tests/test_api_scan_batch.py tests/test_api_scan.py -v
```
预期：全 PASS。

- [ ] **Step 2: 前端相关测试全量 + 类型门禁**

```bash
cd /root/ft-codescan/packages/web/frontend && npx vitest run src/pages/ScanNewPage.test.tsx src/components/ScanFormFields.test.tsx src/components/AddRepoDialog.test.tsx src/components/RepoCombobox.test.tsx src/components/correlation/RepositoryMultiSelector.test.tsx src/routes/WorkspaceDetail/ScanList.test.tsx && npx tsc -b
```
预期：全 PASS（`RepoCombobox.test.tsx`/`RepositoryMultiSelector.test.tsx` 未改动也应绿——验证零波及）。

- [ ] **Step 3: spec 状态更新并提交**

`docs/superpowers/specs/2026-09-11-batch-whitebox-scan-design.md` 首行 blockquote 改：
```
> 日期：2026-09-11。状态：已实现（见 plans/2026-09-11-batch-whitebox-scan.md）。
```
另在 §4.1 加一行实现注记：
```
> 实现注记：组件选型偏离 spec 原文（RepoCombobox 多选改造）——直接复用现成的
> RepositoryMultiSelector（correlation 多选列表：搜索/全选/计数/未就绪禁选），交互语义
> 全覆盖且 MR 单选零改动；白盒 repoPicker 的 CloneProgress/RepoQuickActions 随单选退役。
```

```bash
git add docs/superpowers/specs/2026-09-11-batch-whitebox-scan-design.md
git commit -m "docs(spec): 批量白盒扫描 spec 状态更新——已实现+组件选型注记（RepositoryMultiSelector 复用）"
```
