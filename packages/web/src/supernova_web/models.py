from __future__ import annotations

from typing import Literal, Union
from urllib.parse import urlparse

from pydantic import BaseModel, field_validator, model_validator


class PathSource(BaseModel):
    kind: Literal["path"]
    value: str


class RepoSource(BaseModel):
    kind: Literal["repo"]
    value: str  # 仓库名（可为 group/repo 或扁平 repo，对应 repos_dir 下相对路径）


# Web 入口已收窄为「工作区已下载仓库」——前端不再发 path source，但保留 PathSource 以兼容
# 可能的旧调用方 / CLI shim；scan_manager._resolve_inputs 仍按 kind 分流。
Source = Union[PathSource, RepoSource]


class ScanRequest(BaseModel):
    type: Literal["whitebox", "blackbox", "correlation", "mr"]
    source: Source | None = None
    url: str | None = None
    workspace: str | None = None
    # MR 增量扫描（spec 2026-09-03）：type="mr" 必填 base_ref / head_ref
    # （分支名或 commit sha），source.kind=="repo" 必填。
    base_ref: str | None = None
    head_ref: str | None = None
    # MR merged 改道（2026-09-04）：源分支已删的已合并 MR，实际扫描把手是 commit 对
    # ——head_commit=merge_commit_sha（true merge/squash）或 MR.sha（FF，配 base_commit=
    # diff_refs.base_sha；true merge 时 base_commit=None，worker 解 head^1）。可选：
    # 缺省 = 分支名模式（零变化）。head_ref 仍必填（表单展示/报告标识）。
    head_commit: str | None = None
    base_commit: str | None = None
    reuse_latest: bool = False
    # 黑盒「复用白盒结果」：要复用的白盒 scan_id（工作区内某 whitebox scan）。
    # 黑盒 = 白盒下游 exploitation-only（阶段 2）：恒复用白盒结果，model_validator
    # （_blackbox_requires_reuse）强制 reuse_whitebox_scan_id 必填 + 禁 source。
    reuse_whitebox_scan_id: str | None = None
    # 黑盒登录配置（结构化 dict，对齐 core Authentication schema：login_type/login_url/credentials
    # /login_flow）。scan_manager 内 Authentication.model_validate 校验 + 写 config YAML。
    authentication: dict | None = None
    # inline 多角色附加账号（2026-08-07）：与 authentication 同存，scan_manager 展开成 accounts[]。
    # 每条 {role, username, password, totp_secret?}；validator 保证仅 authentication 存在时合法。
    auth_accounts: list[dict] | None = None
    # 黑盒选已保存档案/角色(与 inline authentication 二选一):scan_manager 展开成 credentials。
    # 三模式（model_validator _auth_profile_xor_inline 保证互斥）：
    #   - profile_id 单独          = 全角色模式（展开档案所有 credentials → accounts[]，多身份验证）；
    #   - profile_id + cred_ids[]  = 子集模式（展开选中的 credentials → accounts[]，默认前端全选）；
    #   - profile_id + cred_id     = 单角色模式（旧契约，向后兼容；展开该 credential → 单 authentication）。
    auth_profile_id: str | None = None
    auth_credential_id: str | None = None
    # 多角色子集（2026-08-06）：profile 模式选多个角色，空=全选该档案所有角色。
    auth_credential_ids: list[str] | None = None
    # correlation 专用
    config_name: str | None = None
    config_content: str | None = None
    save_as: str | None = None
    # HOST 档案（Phase 2，2026-08-12）：与认证字段独立（HOST 可与任意 auth 模式组合）。
    # 两互斥来源（model_validator _host_profile_xor_url 保证互斥）：
    #   - host_profile_id = 选已保存 HOST 档案（scan_manager 取 store 解析 → mappings）；
    #   - host_url        = 填 /etc/hosts GET 链接（扫描启动时拉取 → mappings，结束可选 upsert）。
    # 都不填 = 不启用 HOST 代理（向后兼容，既有扫描字节不变）。
    host_profile_id: str | None = None   # 选 HOST 档案
    host_url: str | None = None          # 或填 GET 链接（扫描时拉取）
    # 扫完即删（2026-09-10）：勾选后扫描到任意终态（completed/failed/cancelled…）
    # 时由 web 仓库级 sweep 删除对应仓库（私有克隆 rmtree；linked 仓不处理）。
    # 标志随扫描行落 session；correlation 传播给本次新建的子仓扫描行。
    delete_repo_on_finish: bool = False

    @field_validator("host_profile_id", "host_url", mode="before")
    @classmethod
    def _normalize_host_source(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise TypeError("HOST source must be a string")
        return value.strip()

    @model_validator(mode="after")
    def _blackbox_requires_reuse(self) -> "ScanRequest":
        """黑盒 = 白盒下游 exploitation-only（阶段 2）：恒复用白盒结果，禁 standalone/repo。

        黑盒必须有 reuse_whitebox_scan_id，且禁 source（防 API 直传 repo/path 绕过前端）。
        whitebox/correlation 不约束。非法 → ValidationError → FastAPI 422。
        """
        if self.type == "blackbox":
            if not self.reuse_whitebox_scan_id:
                raise ValueError(
                    "blackbox 扫描必须复用白盒结果（reuse_whitebox_scan_id），请先跑白盒扫描"
                )
            if self.source is not None:
                raise ValueError(
                    "blackbox 扫描不支持 source（恒复用白盒结果），请改用 reuse_whitebox_scan_id"
                )
        return self

    @model_validator(mode="after")
    def _mr_requires_base_head_repo(self) -> "ScanRequest":
        """MR 增量扫描校验（spec 2026-09-03 §3.2）：type=mr 必填 repo + base_ref/head_ref。

        非法 → ValidationError → FastAPI 422。
        """
        if self.type == "mr":
            if self.source is None or self.source.kind != "repo":
                raise ValueError("MR 扫描必须选择工作区已下载仓库（source.kind=repo）")
            if not self.base_ref or not self.head_ref:
                raise ValueError("MR 扫描必须指定 base_ref 与 head_ref（分支名或 commit sha）")
        return self

    def _validate_auth_fields(self) -> None:
        """共享认证字段互斥校验体（blackbox 与 whitebox 组合模式复用）。

        三模式（profile 全角色 / 子集 / 单角色）与 inline authentication 互斥：
        - profile_id 单独          = 全角色模式（scan_manager 展开所有 credentials → accounts[]）；
        - profile_id + cred_ids[]  = 子集模式（展开选中的 credentials → accounts[]，默认前端全选）；
        - profile_id + cred_id     = 单角色模式（旧契约，向后兼容）；
        - inline authentication    = 内联登录（现状）；
        - profile_id + inline      = 非法（互斥）；
        - cred_id 或 cred_ids 无 profile_id = 非法（必须依附 profile）。
        抛 ValueError（pydantic model_validator 转 ValidationError → FastAPI 422）。
        """
        has_profile = self.auth_profile_id is not None
        has_cred = self.auth_credential_id is not None
        has_cred_ids = self.auth_credential_ids is not None
        has_inline = self.authentication is not None
        has_accounts = self.auth_accounts is not None
        # auth_accounts 属 inline 侧：仅与 authentication 同存（inline 多角色附加账号）。
        if has_accounts and not has_inline:
            raise ValueError("auth_accounts 必须与 authentication 同时提供（内联多角色附加账号）")
        if (has_profile or has_cred or has_cred_ids) and (has_inline or has_accounts):
            raise ValueError("登录配置不能同时指定认证档案与内联登录配置")
        if (has_cred or has_cred_ids) and not has_profile:
            raise ValueError("选认证档案角色时必须同时指定 auth_profile_id")

    @model_validator(mode="after")
    def _auth_profile_xor_inline(self) -> "ScanRequest":
        """blackbox 登录模式互斥校验（2026-08-06 多角色子集）。

        委托共享校验体 _validate_auth_fields（2026-08-13 抽出，供 whitebox 组合模式复用）。
        纯黑盒行为字节不变（仅提取方法，规则与错误语义一致）。
        """
        if self.type == "blackbox":
            self._validate_auth_fields()
        return self

    @model_validator(mode="after")
    def _whitebox_combined_optional(self) -> "ScanRequest":
        """whitebox 组合扫描认证校验（spec §6.1，2026-08-13）。

        - type=="whitebox" 且带 url → 组合模式：认证字段走与黑盒相同的互斥校验
          （_validate_auth_fields 复用，规则一致；认证字段可选，公开目标可不填）。
        - type=="whitebox" 无 url 但有任一认证字段 → 非法（纯白盒禁认证，防误传）。
        - type=="whitebox" 无 url 无认证 → 纯白盒（现状，零回归）。

        不改 _blackbox_requires_reuse（纯黑盒入口仍强制 reuse_whitebox_scan_id；
        组合扫描走白盒入口 + 接力）。
        """
        if self.type != "whitebox":
            return self
        has_any_auth = (self.authentication is not None or self.auth_accounts is not None
                        or self.auth_profile_id is not None or self.auth_credential_id is not None
                        or self.auth_credential_ids is not None)
        if self.url:
            # 组合模式：复用黑盒互斥校验（认证可选——公开目标可不填，故仅在有时校验互斥）。
            self._validate_auth_fields()
        else:
            # 纯白盒：禁任何认证字段（防误传）。
            if has_any_auth:
                raise ValueError("纯白盒扫描不支持认证字段；如需登录扫描请填 url 走组合模式")
        return self

    @model_validator(mode="after")
    def _host_profile_xor_url(self) -> "ScanRequest":
        """HOST 字段互斥校验（2026-08-12 Phase 2；2026-08-13 扩到组合模式）。

        - host_profile_id + host_url 同时填 = 非法（互斥，避免双源冲突）；
        - 单填一个 = 合法；都不填 = 合法（向后兼容，无 HOST 代理）。
        与认证字段完全独立（HOST 可与任意 auth 模式组合：profile/inline/无 auth）。
        对 blackbox 与组合模式（whitebox+url）生效--两条入口都暴露了 HOST 配置；
        correlation+url（C3 fix ②：gateway 段③黑盒验证）同组合模式校验；纯白盒
        （无 url）/correlation 无 url 即便误填也忽略（无黑盒阶段，HOST 代理无意义）。
        """
        is_combined_or_bb = (
            self.type == "blackbox"
            or (self.type == "whitebox" and self.url)
            or (self.type == "correlation" and self.url)
        )
        if is_combined_or_bb:
            if self.host_profile_id == "":
                raise ValueError("host_profile_id 不能为空；启用 HOST 后必须选择档案")
            if self.host_url == "":
                raise ValueError("host_url 不能为空；启用 HOST 后必须填写 URL")
            if self.host_profile_id is not None and self.host_url is not None:
                raise ValueError(
                    "host_profile_id 与 host_url 互斥，不能同时指定（HOST 档案二选一）"
                )
            if self.host_url is not None:
                scheme = (urlparse(self.host_url).scheme or "").lower()
                if scheme not in ("http", "https"):
                    raise ValueError("host_url 仅允许 http/https URL")
        return self


class ScanAccepted(BaseModel):
    workspace: str
    # T3: 1 ws : N scans 后 POST /api/scan 返回新 scan 的 scan_id（旧前端忽略仍可用）。
    scan_id: str | None = None
    # 组合扫描预验证态（spec §8.2 异步预验证）：start 立即返回后 precheck 在后台跑，
    # 此时 bb_phase="precheck"；前端据此显「预验证中」+ 跳 live 页跟踪。纯白盒/黑盒为 None。
    bb_phase: str | None = None


class ErrorOut(BaseModel):
    detail: str
