from __future__ import annotations

import html
import re
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse
from starlette.staticfiles import StaticFiles

from .api.system_status import resolve_brand_name
from .config import get_config
from supernova_core.config.env_loader import load_env


# 对账只在后台低频运行；单轮按 scan 串行 probe，避免工作区多时并发打满 Temporal。
# 这也是 reconnecting scan 的最短重试间隔，列表轮询本身不会触发 describe。
_ORPHAN_RECONCILE_INTERVAL_SECONDS = 60


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 启动时加载 profile 凭证（对齐 worker runner.main / CLI blackbox·combined main.py
    # 首行 load_env）。不加载则 scan_manager.build_provider_config() 读不到 profile 里的
    # SUPERNOVA_AI_PROVIDER（只在 .env.profiles/<profile>.env，docker env_file 不注入）→
    # 回落默认 anthropic_api → worker 跑 CLI 但无凭据 → 每轮 "Not logged in"（2026-07-30 根因）。
    load_env()
    # auth: 启动 seed 预置账号 + 周期清理过期 session
    from .auth.seed import seed_users, bootstrap_default_admin
    import asyncio
    seed_users(app.state.auth_store, app.state.config.users_seed_file)
    # 全新部署（无 users.yaml / 空库）兜底：库内无 admin 时建默认 admin/123456
    # （must_change=True 强制首登改密）。已有 admin（含 seed 出来的）→ no-op。
    if bootstrap_default_admin(
        app.state.auth_store,
        username=app.state.config.default_admin_username,
        password=app.state.config.default_admin_password,
        enabled=app.state.config.bootstrap_default_admin_enabled,
    ):
        import logging
        logging.getLogger("supernova_web").warning(
            "Bootstrapped default admin %r with default password — change it on first login.",
            app.state.config.default_admin_username,
        )
    async def _purge_loop():
        while True:
            try:
                app.state.session_manager.purge_expired()
                # SSO 防重放表周期清理：删 24h 前已用 ticket（now_iso 须 UTC isoformat）
                app.state.auth_store.purge_used_tickets(datetime.now(timezone.utc).isoformat())
            except Exception:
                pass
            await asyncio.sleep(3600)
    app.state._purge_task = asyncio.create_task(_purge_loop())

    # 启动对账序列（顺序敏感）：
    #   1) 给所有真实 ws 补全部 admin (manager)
    #   2) 为历史用户创建同名工作区（在成员补充后，避免用户名与残留目录同名时误判）
    #   3) per-ws 补写仓库 meta（读时自愈 _ensure_meta 的启动兜底）
    #   4) 重建孤儿 scan 状态（遍历 ScanStore scans）
    # purge_loop 与本序列无依赖、保持原位即可。
    # 注 1：旧全局 repos/<name> 的启动搬迁（_migrate_legacy_repos）已于 2026-08-27 退役——
    # 每次启动物理搬走在用仓库会令扫描当场 "Repository not found"
    # （NodeGoat-20260826-171403 实证）。全局 repos/ 视为废弃：启动不碰，手动放入的
    # 仓库经仓库页 link-dir 显式关联（linked_repos.json，谁关联谁可见）。守护测试
    # tests/test_legacy_repo_migration.py::test_startup_leaves_global_repos_untouched。
    # 注 2：ws 根平铺 scan/伪 ws 的启动收纳（_migrate_legacy_scans → __legacy__）已于
    # 2026-08-27 随 __legacy__ 概念一并退役（部署全走 web UI，CLI 直连实质废弃）。
    # 启动不移动任何存量目录。守护测试 tests/test_legacy_scan_migration.py。
    _migrate_legacy_workspace_members(app)
    # 先完成 legacy scan/repo 归并，再为历史用户创建同名工作区，避免用户名与旧 scan 同名时
    # 把旧 scan 临时当成正式 workspace。
    from .components.workspace_provisioner import ensure_all_user_workspaces
    ensure_all_user_workspaces(app.state.config.workspaces_dir, app.state.auth_store)
    _reconcile_repo_meta(app)
    await _reconcile_orphaned_scans(app)  # 重启后确认可收尾的孤儿 scan

    async def _orphan_reconcile_loop():
        """低频收敛 reconnecting scan；Temporal 不可用时由 probe fail-open 留待下轮。"""
        while True:
            await asyncio.sleep(_ORPHAN_RECONCILE_INTERVAL_SECONDS)
            try:
                await _reconcile_orphaned_scans(app)
            except Exception:
                import logging
                logging.getLogger("supernova_web").exception(
                    "background scan reconciliation failed; retrying next interval")

    app.state._scan_reconcile_task = asyncio.create_task(_orphan_reconcile_loop())
    # 扫完即删（2026-09-10）启动兜底 sweep：孤儿对账收口终态后，补删「带标志且
    # 已完毕」的仓库（_watch 随上次 web 进程退出丢失的窗口）。best-effort 不阻断启动。
    try:
        swept = await app.state.scan_manager.sweep_all_workspaces()
        if swept:
            import logging
            logging.getLogger("supernova_web").info(
                "Startup swept %d delete-on-finish repo(s).", swept)
    except Exception:
        import logging
        logging.getLogger("supernova_web").exception(
            "startup delete-on-finish sweep failed; continuing startup")
    # 启动把 configs/*.yaml 的 authentication 段 seed 成全局共享系统档案（.system 段，
    # 所有 ws 可见、只读，以 configs 文件为唯一真相源）。seed_from_config 内部对单个
    # 文件 parse 失败/无 authentication 段已容错；此处再兜一层防意外阻断启动。
    try:
        seeded = app.state.auth_profile_store.seed_from_config(app.state.config.configs_dir)
        if seeded:
            import logging
            logging.getLogger("supernova_web").info(
                "Seeded %d system auth profile(s) from configs/.", seeded)
    except Exception:
        import logging
        logging.getLogger("supernova_web").exception("auth-profile seed failed; continuing startup")
    # 认证验证启动对账(2026-08-17 卡"测试中"根因):watcher 随旧进程死亡后 running 凭据成
    # 永久孤儿(batch 前端不轮询 verify-status)。终态回填 / 在跑重挂跟踪,先于 probe 清理
    # (后者会保护 running cred 的 probe)。best-effort,失败不阻断启动。
    try:
        reconciled = await app.state.scan_manager.reconcile_auth_validation()
        if reconciled:
            import logging
            logging.getLogger("supernova_web").info(
                "Reconciled %d orphaned auth validation result(s).", reconciled)
    except Exception:
        import logging
        logging.getLogger("supernova_web").exception(
            "auth validation reconcile failed; continuing startup")
    # 清上次 worker 异常残留的认证 probe 明文凭据(收窄:只删 scan-config.yaml,保留过程记录)
    app.state.scan_manager.reap_stale_probes()
    yield
    app.state._purge_task.cancel()
    app.state._scan_reconcile_task.cancel()
    # shutdown（任务 9 接入 ScanManager 取消在途扫描后填充）


async def _reconcile_orphaned_scans(app: FastAPI) -> None:
    """启动时遍历每个 ws 的所有 scan（ScanStore 双源：新 scans/<id>/ + legacy 根），
    对无 heartbeat 的 scan 进行低频 Temporal 对账；只有明确关闭/不存在且无法归类业务结
    果的 execution 才补写 ``scan_end=interrupted``。Temporal 查询失败时 fail-open，保留
    reconnecting 到下一轮。

    T5: 改遍历 ScanStore._scan_entries（per-scan），而非 ws 根目录 -- 1:N 后 scan 在
    scans/<id>/（ScanStore 双源兼容历史 ws 根形态）。容器重启会杀掉 scan_manager._watch 协程，
    导致在途 scan 永不写 scan_end、session 卡 running、live SSE 空等。此处一次性兜底，
    使重开 live 页能正常显「已中断」+ 原因。单 scan 异常不阻塞启动。
    """
    from .components.orphan_reconciler import reconcile_orphaned
    from .components.scan_store import ScanStore
    cfg = app.state.config
    indexer = app.state.indexer
    # 启动时 scan_manager._procs 为空，active_pids()={}；reconcile_orphaned 会再以
    # heartbeat、gate 与 Temporal execution 交叉确认，不能仅凭没有本机 pid 收尾。
    indexer.sync_active(app.state.scan_manager.active_pids())
    if not cfg.workspaces_dir.is_dir():
        return
    store = ScanStore(cfg.workspaces_dir)
    for ws_dir in cfg.workspaces_dir.iterdir():
        if not ws_dir.is_dir():
            continue
        for _scan_id, scan_dir in store._scan_entries(ws_dir.name):
            try:
                await reconcile_orphaned(
                    scan_dir, False, scan_manager=app.state.scan_manager)
            except Exception:
                continue


def _migrate_legacy_workspace_members(app: FastAPI) -> None:
    """将 canonical ``admin`` 幂等加入所有 legacy/真实 workspace。

    普通成员和其他超管的既有成员关系保持不变；只有用户名正好为 ``admin`` 且角色仍为
    ``admin`` 的账号获得默认全局 workspace 成员关系。"""
    from .components.workspace_provisioner import ensure_global_admin_access

    ensure_global_admin_access(
        app.state.config.workspaces_dir,
        app.state.auth_store,
    )


def _reconcile_repo_meta(app: FastAPI) -> None:
    """对每个 workspace 跑 RepoManager.migrate_legacy(ws)——为已存在但缺 meta 的仓库
    补写 ``.supernova-repo.json``（读时自愈 _ensure_meta 的启动兜底）。

    旧名 ``_migrate_legacy_repos`` 与本函数语义不符（migrate_legacy 不搬仓库、只补 meta），
    2026-07-26 web repos isolation P2 Task 7 重命名为 ``_reconcile_repo_meta``。曾短暂存在的
    「搬旧全局 repos → __legacy__ ws」同名启动搬迁函数已于 2026-08-27 退役（见 lifespan
    注释），勿重建。单 ws 异常不阻塞启动（best-effort）。
    """
    cfg = app.state.config
    if not cfg.workspaces_dir.is_dir():
        return
    rm = app.state.repo_manager
    for d in cfg.workspaces_dir.iterdir():
        if not d.is_dir():
            continue
        try:
            rm.migrate_legacy(d.name)
        except Exception:
            # 单 ws 失败不影响其他 ws 与整体启动
            continue


_INDEX_CACHE: dict[str, tuple[float, str]] = {}
_TITLE_RE = re.compile(r"<title>.*?</title>", re.IGNORECASE | re.DOTALL)


def _render_index_html(index_html: Path, brand: str) -> str:
    """读 index.html，把首个 <title> 注入为当前生效品牌名(已 HTML 转义)。

    消除 SPA 刷新时标签页「先显 index.html 硬编码 Supernova、再被前端 JS 异步改写」的
    跳变:浏览器拿到 HTML 时 title 即为生效品牌名(运行时改名后即时反映)。文件内容按
    mtime 缓存——SPA fallback 是 catch-all,深度路由每次命中都要返 index.html,避免每请求
    读盘 + 正则;title 段每次现替换(brand 随运行时改名变)。brand 经 BrandingStore.validate
    只限长度/非空、不限字符,故必须 HTML 转义防破坏 <title> / 注入。
    """
    key = str(index_html.resolve())
    mtime = index_html.stat().st_mtime
    cached = _INDEX_CACHE.get(key)
    if cached is None or cached[0] != mtime:
        cached = (mtime, index_html.read_text("utf-8"))
        _INDEX_CACHE[key] = cached
    template = cached[1]
    if _TITLE_RE.search(template):
        return _TITLE_RE.sub(f"<title>{html.escape(brand)}</title>", template, count=1)
    return template


def _mount_frontend(app: FastAPI, cfg) -> None:
    """挂载前端 SPA 静态托管（生产/集成模式）。

    cfg.frontend_dir 为空或目录不存在时直接返回（dev 模式前端走 vite 5173）。
    必须在所有 /api/* 路由与 /health 注册**之后**调用——catch-all 靠 FastAPI
    注册顺序保证 API 优先命中。
    """
    if not cfg.frontend_dir:
        return
    dist = Path(cfg.frontend_dir)
    if not dist.is_dir():
        return
    index_html = dist / "index.html"
    dist_resolved = dist.resolve()
    assets_dir = dist / "assets"
    if assets_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=assets_dir), name="frontend-assets")

    # SPA 入口 index.html 每次必重新验证:注入的 title(品牌名)随运行时改名变,且杜绝浏览器
    # 启发式缓存陈旧 HTML(改名后 F5 仍显旧 title)。带 hash 的 /assets/* 仍可长缓存。
    no_cache = {"cache-control": "no-cache"}

    @app.get("/")
    async def _spa_root(request: Request):
        return HTMLResponse(
            _render_index_html(index_html, resolve_brand_name(request)), headers=no_cache
        )

    @app.get("/{full_path:path}")
    async def _spa_fallback(full_path: str, request: Request):
        candidate = (dist / full_path).resolve()
        try:
            candidate.relative_to(dist_resolved)
        except ValueError:
            raise HTTPException(status_code=404)
        if full_path and candidate.is_file():
            return FileResponse(candidate)
        return HTMLResponse(
            _render_index_html(index_html, resolve_brand_name(request)), headers=no_cache
        )


def create_app(overrides: dict | None = None) -> FastAPI:
    app = FastAPI(title="Supernova Web", version="0.1.0", lifespan=lifespan)
    cfg = get_config()
    app.state.config = cfg

    from .auth.store import AuthStore
    from .auth.session import SessionManager
    from .auth.middleware import AuthMiddleware
    auth_store = AuthStore(str(cfg.auth_db_path))
    auth_store.init_schema()
    # SSO 运行时配置一次性种子（spec 2026-08-26 §5）：env → auth.db sso_config 单行表，
    # 表空才种（此后 env 失效，设置页 PUT 是唯一写入方）。挂 create_app 同步段而非
    # lifespan——TestClient 不进 with 不跑 lifespan，env→DB 种子链路测试依赖同步性。
    from .auth.models import SsoConfig
    auth_store.ensure_sso_config_seeded(SsoConfig(
        enabled=cfg.sso_enabled, auth_domain=cfg.sso_auth_domain,
        public_base_url=cfg.sso_public_base_url, passport_base=cfg.sso_passport_base,
        session_ttl_hours=cfg.sso_session_ttl_hours))
    app.state.auth_store = auth_store
    app.state.session_manager = SessionManager(auth_store, ttl_hours=cfg.session_ttl_hours)
    app.add_middleware(AuthMiddleware)

    from .components.workspaces_indexer import WorkspacesIndexer
    from .components.git_fetcher import GitFetcher
    from .components.branding_store import BrandingStore
    from .components.multi_repo_config_store import MultiRepoConfigStore
    from .components.repo_manager import RepoManager
    from .components.scan_manager import ScanManager
    from .components.credential_vault import CredentialVault
    from .components.ws_config_store import WsConfigStore
    from .components.auth_profile_store import AuthProfileStore
    from .components.host_profile_store import HostProfileStore
    from .components.pricing_store import PricingStore
    from .api import correlation_topology, fs, members, multi_configs, repos, scan, scans, system_status, users, workspaces, ws_config, branding, auth_profiles, host_profiles, pricing

    app.state.indexer = WorkspacesIndexer(cfg.workspaces_dir)
    # P3c 阶段 2：per-ws 配置
    app.state.credential_vault = CredentialVault(cfg.master_key_file)
    app.state.ws_config_store = WsConfigStore(cfg.workspaces_dir, app.state.credential_vault)
    app.state.auth_profile_store = AuthProfileStore(cfg.workspaces_dir, app.state.credential_vault)
    app.state.host_profile_store = HostProfileStore(cfg.workspaces_dir)
    app.state.config_store = MultiRepoConfigStore(cfg.configs_dir)
    # 品牌名运行时覆盖存储(设置页改名):branding.json 落盘,system_status 解析优先读。
    app.state.branding_store = BrandingStore(cfg.workspaces_dir)
    # 定价两层存储(设置页全局价目表 + ws 覆盖,spec 2026-08-28):<workspaces_dir>/pricing.json
    # 与 <ws>/pricing.override.json。挂 create_app 同步段(setdefault 注入见下)。
    app.state.pricing_store = PricingStore(cfg.workspaces_dir)
    # 全局价目表 env 键:core pricing._pricing 的 global 层读此路径(worker 由 web spawn
    # 继承 env → 落盘即生效,无需重启)。setdefault 不覆盖显式配置(自定义部署)。
    import os as _os
    _os.environ.setdefault(
        "SUPERNOVA_GLOBAL_PRICING", str(cfg.workspaces_dir / "pricing.json"))
    git_fetcher = GitFetcher(
        cfg.repos_dir, cfg.gitlab_user, cfg.gitlab_token,
        ws_config_store=app.state.ws_config_store,
    )
    overrides = overrides or {}
    # RepoManager 先建：ScanManager 的扫完即删 sweep（2026-09-10）委托它删仓库。
    app.state.repo_manager = overrides.get("repo_manager") or RepoManager(
        cfg.workspaces_dir, git_fetcher, max_concurrent=cfg.repos_max_concurrent_clones,
        max_upload_zip_bytes=cfg.max_upload_zip_bytes)
    app.state.scan_manager = overrides.get("scan_manager") or ScanManager(
        cfg.workspaces_dir, cfg.repos_dir, app.state.config_store,
        scan_timeout=cfg.scan_timeout,
        ws_config_store=app.state.ws_config_store,
        auth_profile_store=app.state.auth_profile_store,
        host_profile_store=app.state.host_profile_store,
        repo_manager=app.state.repo_manager)

    from .components.topology_analysis import TopologyAnalysisManager
    app.state.topology_manager = overrides.get("topology_manager") or TopologyAnalysisManager(
        cfg.workspaces_dir, repo_manager=app.state.repo_manager,
        ws_config_store=app.state.ws_config_store)

    from .auth.dependencies import current_user
    _require_auth = [Depends(current_user)]
    app.include_router(workspaces.router, dependencies=_require_auth)
    app.include_router(scans.router, dependencies=_require_auth)
    app.include_router(scans.cross_ws_router, dependencies=_require_auth)
    app.include_router(scan.router, dependencies=_require_auth)
    app.include_router(multi_configs.router, dependencies=_require_auth)
    app.include_router(repos.router, dependencies=_require_auth)
    app.include_router(correlation_topology.router, dependencies=_require_auth)
    app.include_router(fs.router, dependencies=_require_auth)
    app.include_router(system_status.router, dependencies=_require_auth)
    app.include_router(members.router, dependencies=_require_auth)
    app.include_router(ws_config.router, dependencies=_require_auth)
    app.include_router(users.router, dependencies=_require_auth)
    app.include_router(auth_profiles.router, dependencies=_require_auth)
    app.include_router(host_profiles.router, dependencies=_require_auth)
    # branding:GET 需登录(任意角色可看当前名),PUT 需 admin(route 内 require_admin)。
    app.include_router(branding.router, dependencies=_require_auth)
    # pricing:全局表 GET 全员 / PUT·DELETE admin(route 内 require_admin);
    # ws 覆盖 member GET / manager PUT·DELETE(依赖内校验)。spec 2026-08-28。
    app.include_router(pricing.router, dependencies=_require_auth)
    app.include_router(pricing.ws_router, dependencies=_require_auth)

    from .auth import routes as auth_routes
    app.include_router(auth_routes.router)

    @app.get("/health")
    async def health() -> dict:
        return {
            "status": "ok",
            "git": {
                "binary_available": cfg.git_binary_available,
                "credentials_configured": bool(cfg.gitlab_user and cfg.gitlab_token),
            },
        }

    _mount_frontend(app, cfg)

    return app


app = create_app()


def main() -> None:
    import uvicorn

    cfg = get_config()
    uvicorn.run("supernova_web.app:app", host="0.0.0.0", port=cfg.port, reload=False)
