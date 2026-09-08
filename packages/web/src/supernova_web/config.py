from __future__ import annotations

import os
import shutil
from functools import lru_cache
from pathlib import Path


class WebConfig:
    def __init__(self) -> None:
        self.port = int(os.environ.get("SUPERNOVA_WEB_PORT", "7878"))
        # P3c 阶段 3：与 worker SUPERNOVA_WORKER_MAX_CONCURRENT_WF 建议同值（避免 pending 堆积）。
        self.scan_timeout = float(os.environ.get("SUPERNOVA_WEB_SCAN_TIMEOUT", "0"))
        self.gitlab_user = os.environ.get("GITLAB_USER")
        self.gitlab_token = os.environ.get("GITLAB_TOKEN")
        self.repos_dir = Path(os.environ.get("SUPERNOVA_REPOS_DIR", "repos"))
        self.repos_max_concurrent_clones = max(
            1, int(os.environ.get("SUPERNOVA_REPOS_MAX_CONCURRENT_CLONES", "3"))
        )
        # 上传 zip 文件本体大小上限（MB）——防超大包占满磁盘/内存（解压上限另在 RepoManager）。
        self.max_upload_zip_bytes = int(
            os.environ.get("SUPERNOVA_REPOS_MAX_UPLOAD_ZIP_MB", "1024")
        ) * 1024 * 1024
        self.configs_dir = Path(os.environ.get("SUPERNOVA_CONFIGS_DIR", "configs"))
        self.frontend_dir = os.environ.get("SUPERNOVA_WEB_FRONTEND_DIR")
        # Web 控制台品牌名(左上角字标 + 浏览器标签页 title);默认 Supernova,部署者可经
        # SUPERNOVA_WEB_BRAND_NAME 覆盖(white-label / 改名场景,无需改代码)。
        self.brand_name = os.environ.get("SUPERNOVA_WEB_BRAND_NAME", "Supernova")
        self.fs_roots: list[Path] = [
            Path(p).resolve() for p in os.environ.get("SUPERNOVA_FS_ROOTS", "").split(",") if p.strip()
        ]
        # auth（P0）
        self.session_ttl_hours = int(os.environ.get("SUPERNOVA_WEB_SESSION_TTL_HOURS", "12"))
        # cookie_secure 仅作「强制 secure」开关：True 时无条件打 Secure。
        # 默认 False——实际是否 secure 由 routes 按请求 scheme（含反代
        # X-Forwarded-Proto）决定。曾默认 True，但 main() 纯 HTTP 启动，
        # 致 http:// 下浏览器丢弃 session cookie → 登录循环（/login?expired=1）。
        # 生产 HTTPS 直接经 env=1 强制，或由 scheme 自动判断。
        self.cookie_secure = os.environ.get("SUPERNOVA_WEB_COOKIE_SECURE", "0") not in ("0", "false", "False")
        self.users_seed_file = os.environ.get("SUPERNOVA_WEB_USERS_SEED", "configs/users.yaml")
        # 默认 admin bootstrap：全新部署（users.yaml 缺失/空）启动时若库内无 admin，
        # 自动建 admin/<默认密码>（must_change=True 强制首登改密）。生产可经
        # SUPERNOVA_WEB_BOOTSTRAP_DEFAULT_ADMIN=0 关闭。默认密码 123456 绕过 API 的
        # 8 位长度限制（bootstrap 与 seed 同走 store.create_user 直插 DB）。
        self.bootstrap_default_admin_enabled = os.environ.get(
            "SUPERNOVA_WEB_BOOTSTRAP_DEFAULT_ADMIN", "1"
        ) not in ("0", "false", "False")
        self.default_admin_username = os.environ.get("SUPERNOVA_WEB_DEFAULT_ADMIN_USERNAME", "admin")
        self.default_admin_password = os.environ.get("SUPERNOVA_WEB_DEFAULT_ADMIN_PASSWORD", "123456")
        # ── SSO（富途 OA passport，spec 2026-08-25 §7）─────────────────────────
        # 总开关：关闭（默认）时 SSO 端点 404、前端不渲染 OA 登录按钮——零回归硬标准。
        self.sso_enabled = os.environ.get("SUPERNOVA_WEB_SSO_ENABLED", "0") not in ("0", "false", "False")
        # AUTH_DOMAIN = 本站裸域名（OA 侧登记的接入方标识），传 validateTicket 的 authDomain。
        self.sso_auth_domain = os.environ.get("SUPERNOVA_WEB_SSO_AUTH_DOMAIN", "")
        # returnUrl 拼接用完整 origin；默认 https://{auth_domain}，内网 http 部署可覆盖。
        self.sso_public_base_url = (
            os.environ.get("SUPERNOVA_WEB_SSO_PUBLIC_BASE_URL")
            or (f"https://{self.sso_auth_domain}" if self.sso_auth_domain else "")
        ).rstrip("/")
        self.sso_passport_base = os.environ.get(
            "SUPERNOVA_WEB_SSO_PASSPORT_BASE", "https://passport.futuoa.com"
        ).rstrip("/")
        # SSO 会话时长（cookie max_age 同步）；账密会话仍走 session_ttl_hours（12h）。
        self.sso_session_ttl_hours = int(os.environ.get("SUPERNOVA_WEB_SSO_SESSION_TTL_HOURS", "24"))
        # 2026-08-26 配置运行时化（spec 2026-08-26 §5/§6）：原两个启动 fail-fast
        # （enabled 缺 domain / passport 非 https）已删——env 降级为 auth.db sso_config
        # 单行表的首次种子来源，坏 env 由 store.ensure_sso_config_seeded 种子时降级
        # （enabled=0 / 默认 passport）不崩溃；运行时校验移到 PUT /sso/admin/config。

    @property
    def workspaces_dir(self) -> Path:
        from supernova_core.utils.paths import resolve_workspaces_dir
        return Path(resolve_workspaces_dir())

    @property
    def master_key_file(self) -> Path:
        """P3c 阶段 2：凭据 master key 落盘路径（env SUPERNOVA_MASTER_KEY 优先于该文件）。"""
        return self.workspaces_dir / ".master_key"

    @property
    def auth_db_path(self) -> Path:
        return self.workspaces_dir / "auth.db"

    @property
    def git_binary_available(self) -> bool:
        return shutil.which("git") is not None


@lru_cache
def get_config() -> WebConfig:
    return WebConfig()
