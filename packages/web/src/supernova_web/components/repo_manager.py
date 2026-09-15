from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from uuid import uuid4

import aiofiles

from .git_fetcher import GitFetcher, strip_credentials

_PROGRESS_RE = re.compile(r"(?:Receiving objects|Resolving deltas|Compressing objects|Counting objects):\s+(\d+)%")

# 仓库名：`repo` 或 `group/repo`（至多一层分组）。每段非空、不含 / \ NUL。
_REPO_NAME_RE = re.compile(r"^[^\x00/\\]+(/[^\x00/\\]+)?$")
# 单段目录名（不含 / \ NUL）——clone 时 name/group 各段独立校验
_REPO_SEGMENT_RE = re.compile(r"^[^\x00/\\]+$")


def _validate_repo_segment(seg: str, label: str = "名字段") -> None:
    """校验单段目录名（不含 / \\ NUL，非 . ..，非空）。供 clone 的 name/group 各段校验。"""
    if not seg or "\x00" in seg or not _REPO_SEGMENT_RE.match(seg) or seg in (".", ".."):
        raise ValueError(f"非法{label}：{seg!r}")


def _validate_ws_segment(ws: str) -> None:
    """校验 workspace 路径段（URL {ws} 来的，作 workspaces/<ws>/repos 前缀）。

    与单段 repo 名同档约束：非空、不含 ``/`` ``\\`` NUL、非 ``.`` ``..``。
    第二道防线在 _repos_root：resolve().is_relative_to(self._workspaces_dir)。
    """
    if not ws or "\x00" in ws or not _REPO_SEGMENT_RE.match(ws) or ws in (".", ".."):
        raise ValueError(f"非法 workspace：{ws!r}")


def _validate_repo_name(name: str) -> None:
    """校验仓库名合法且无遍历分量（path-traversal 第一道防线）。

    允许 `repo` 或 `group/repo`（至多一层分组，映射 repos_dir/<group>/<repo>）；
    禁止 `..`/`.` 分量、空分量（`a//b`）、首尾 `/`（`/a`、`a/`）、`\\`、NUL、
    多层嵌套（`a/b/c`）。第二道防线见 _resolve_repo_dir 的 resolve().is_relative_to()。

    raise ValueError if name 非法。
    """
    if not name or "\x00" in name or not _REPO_NAME_RE.match(name):
        raise ValueError(f"非法仓库名：{name!r}")
    # 正则已禁多层/空段/首尾斜杠，再防 `..` / `.` 作为整段（如 `..`、`a/..`）
    for part in name.split("/"):
        _validate_repo_segment(part, "仓库名")


def _resolve_repo_dir(repos_dir: Path, name: str) -> Path:
    """校验仓库名并解析为 repos_dir 内的绝对路径（path-traversal 双重防线）。

    即便 _validate_repo_name 正则有漏，resolve().is_relative_to() 兜底确保
    最终路径不越界 repos_dir。返回 resolve 后的绝对路径。
    """
    _validate_repo_name(name)
    base = Path(repos_dir).resolve()
    p = (base / name).resolve()
    if not p.is_relative_to(base):
        raise ValueError(f"非法仓库名：{name!r}")
    return p


def _norm_clone_url(u: str | None) -> str:
    """跨分组挡板的 URL 归一键：剥凭据 + 去尾斜杠 + 剥 ``.git`` 后缀。

    GitLab 同一仓库带不带 ``.git``、带不带尾斜杠是等价 URL（现场 risk_user_side
    两份恰好差一个 ``.git`` 后缀），不归一则写法差异穿透挡板。
    """
    u = (strip_credentials(u) or "").rstrip("/")
    return u[:-4] if u.endswith(".git") else u


def _is_repo(d: Path) -> bool:
    """目录是仓库 iff 有 `.git`（clone 产物）或 `.supernova-repo.json`（已纳入管理）。

    并集：既识别用户已 clone 的真仓库（有 .git），也识别已纳入管理但 .git 损坏的
    （有 meta）。分组目录两者皆无 → False，不被当仓库。
    """
    return (d / ".git").exists() or (d / ".supernova-repo.json").exists()


def _shell_kind(d: Path) -> str | None:
    """空壳目录分类：占住 clone 目标路径（``target.exists()`` 挡 re-clone 报
    "仓库已存在"）但顶层列表不可见（无 ``.git``）的目录。

    返回值：
      - ``"meta"``：无 ``.git`` 但有 meta——失败 clone 残留（``_mark_failed`` 落的
        state=failed meta + clone.ndjson，部分 git 版本还会留半成品工作区文件）。
        列表按 meta 状态显示（通常 failed），delete 走 ``_is_repo`` 的 rmtree 既有路径。
      - ``"empty"``：完全空目录（删分组仓库后残留的空分组目录 / 手建占位）。
        列表显示 state=empty，delete 走 rmdir（仅空目录可删，非空 OSError 天然防误删）。
      - ``None``：非空壳——``.git`` 真仓库 / 其下有子仓库的分组目录 / 无 meta 的
        非空普通目录（用户自放数据，不列出：rmtree 未知内容危险，可见化但删不掉更糟）。
    """
    if (d / ".git").exists():
        return None
    try:
        children = list(d.iterdir())
    except OSError:
        return None
    # 分组目录（其下有真仓库）不是空壳——二层扫描负责其子仓库（2026-07-08 回归守卫：
    # 分组目录即便被误写 meta 也不得当仓库列出，否则 continue 吞掉二层扫描）
    if any(c.is_dir() and (c / ".git").exists() for c in children):
        return None
    if (d / ".supernova-repo.json").exists():
        return "meta"
    return "empty" if not children else None


class TooManyClones(Exception):
    def __init__(self, limit: int) -> None:
        self.limit = limit
        super().__init__(f"并发 clone 上限 {limit}")


class RepoExists(Exception):
    """ws 内仓库名已存在（私有克隆或既有关联）—— link 时重名抛此异常（→ API 409）。"""
    def __init__(self, name: str) -> None:
        self.name = name
        super().__init__(f"仓库已存在：{name}")


def _no_prompt_env() -> dict:
    """linked git 子进程 env（spec 2026-09-04 §4.5）：GIT_TERMINAL_PROMPT=0。

    linked 的 .git/config 存原始远端 URL，凭据不在 supernova 体系——缺凭据时 git
    默认等终端输入，进程挂死；继承当前 env 再覆写（不动 PATH/HOME 等）。私有 clone
    管线不设（凭据在 URL 里不触发，行为不变）。
    """
    return {**os.environ, "GIT_TERMINAL_PROMPT": "0"}


class UploadTooLarge(Exception):
    """上传 zip 文件本体超过大小上限（→ API 413）。"""
    def __init__(self, size: int, limit: int) -> None:
        self.size = size
        self.limit = limit
        super().__init__(f"zip 超过大小上限：{size} > {limit} 字节")


# ---- 上传 ZIP：安全解压辅助（模块级纯函数，便于独立测试） ----

def _safe_unzip(zip_path: Path, dest: Path, max_bytes: int, max_entries: int) -> None:
    """安全解压 zip 到 dest：防 zip slip（逐条目 resolve 校验在 dest 内）+ zip bomb
    （解压总大小 / 条目数上限，超限中止）。条目名为绝对路径或含 ``..`` 分量直接拒绝。

    symlink 条目经 ``zf.open`` 读出目标路径文本、落为普通文件——不构成符号链接，
    无遍历风险（Linux 下 ``\\`` 是合法文件名字符，非路径分隔符，resolve 不展开）。
    """
    with zipfile.ZipFile(zip_path) as zf:
        infos = zf.infolist()
        if not infos:
            raise ValueError("zip 为空（无任何条目）")
        if len(infos) > max_entries:
            raise ValueError(f"zip 条目数超上限（{len(infos)} > {max_entries}）")
        dest_resolved = dest.resolve()
        total = 0
        for info in infos:
            parts = PurePosixPath(info.filename).parts
            if info.filename.startswith("/") or ".." in parts or not parts:
                raise ValueError(f"zip 条目路径非法：{info.filename!r}")
            target = (dest / info.filename).resolve()
            if not target.is_relative_to(dest_resolved):
                raise ValueError(f"zip 条目路径越界：{info.filename!r}")
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            total += info.file_size
            if total > max_bytes:
                raise ValueError(f"zip 解压总大小超上限（>{max_bytes} 字节）")
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst, length=1024 * 1024)


def _strip_single_root_wrapper(dest: Path) -> None:
    """zip 顶层是单一目录（repo-main/ 包裹，GitHub/GitLab 下载包常见）→ 内容上移一层。

    仅剥正常命名的单一顶层目录；顶层是单一隐藏目录（如只有 ``.git``）或多个条目则不动。
    """
    entries = list(dest.iterdir())
    if len(entries) != 1 or not entries[0].is_dir() or entries[0].name.startswith("."):
        return
    wrapper = entries[0]
    staging = dest.parent / (dest.name + ".unwrap-staging")
    staging.mkdir()
    for e in wrapper.iterdir():
        e.rename(staging / e.name)
    wrapper.rmdir()
    for e in staging.iterdir():
        e.rename(dest / e.name)
    staging.rmdir()


def _remove_git_hooks(repo: Path) -> None:
    """删除 zip 自带 .git 的 hooks 目录。

    git commit / 部分 porcelain 操作会执行 ``.git/hooks`` 下脚本——解压内容里的
    hooks 是任意代码执行面，对扫描无用，一律清除。``.git`` 为文件（worktree 指针）
    时 ``hooks`` 非 is_dir，安全跳过。
    """
    hooks = repo / ".git" / "hooks"
    if hooks.is_dir():
        shutil.rmtree(hooks, ignore_errors=True)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _dir_size(p: Path) -> int:
    total = 0
    for f in p.rglob("*"):
        if f.is_file():
            try:
                total += f.stat().st_size
            except OSError:
                pass
    return total


# ---- 关联仓库（linked repos）状态 IO ----
# 关联记录 = 把一个已存在的目录路径（绝对路径）「关联」进某 ws，多 ws 可关联同一路径
# （共享一份磁盘克隆）。状态独立存 workspaces/<ws>/linked_repos.json（不放进 workspace.json，
# 避开其全量重写被 legacy 迁移擦除）。RepoManager 与 ScanManager 共用这些模块函数。

LINKED_REPOS_FILENAME = "linked_repos.json"


def _linked_repos_path(ws_dir: Path) -> Path:
    return Path(ws_dir) / LINKED_REPOS_FILENAME


def read_linked_repos(ws_dir: Path) -> list[dict]:
    """读 ws 的关联记录列表。文件缺失/损坏/结构异常 → 降级为空列表（绝不抛）。"""
    f = _linked_repos_path(ws_dir)
    if not f.exists():
        return []
    try:
        data = json.loads(f.read_text("utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return []
    links = data.get("links") if isinstance(data, dict) else None
    if not isinstance(links, list):
        return []
    # 只留结构完整的记录（name + path 都在）
    return [l for l in links if isinstance(l, dict) and l.get("name") and l.get("path")]


def write_linked_repos(ws_dir: Path, links: list[dict]) -> None:
    ws_dir = Path(ws_dir)
    ws_dir.mkdir(parents=True, exist_ok=True)
    (_linked_repos_path(ws_dir)).write_text(
        json.dumps({"links": links}, ensure_ascii=False, indent=2), encoding="utf-8")


def resolve_linked_repo_path(workspaces_dir: Path, ws: str, name: str) -> str | None:
    """ws 内 name 是否为关联仓库 → 返回其存储路径，否则 None。供 ScanManager 解析扫描目标。"""
    _validate_ws_segment(ws)
    ws_dir = Path(workspaces_dir).resolve() / ws
    for link in read_linked_repos(ws_dir):
        if link.get("name") == name:
            return link.get("path")
    return None


class RepoManager:
    # 上传 zip 限制：文件本体大小（构造注入，来自 SUPERNOVA_REPOS_MAX_UPLOAD_ZIP_MB）、
    # 解压总大小与条目数（zip bomb 防护，类常量不做 env——磁盘/内存兜底值）。
    MAX_EXTRACT_BYTES = 4 * 1024 ** 3
    MAX_EXTRACT_ENTRIES = 100_000

    def __init__(self, workspaces_dir: Path, git_fetcher: GitFetcher,
                 max_concurrent: int = 3,
                 max_upload_zip_bytes: int = 1024 ** 3) -> None:
        self._workspaces_dir = Path(workspaces_dir)
        self._git = git_fetcher
        self._max_concurrent = max(1, max_concurrent)
        self.MAX_UPLOAD_ZIP_BYTES = max_upload_zip_bytes
        self._sem = asyncio.Semaphore(self._max_concurrent)
        self._jobs: dict[tuple[str, str], asyncio.Task] = {}
        # 内存登记正在跑的 job 阶段（"cloning"/"pulling"/"extracting"），供 _repo_view 在
        # target 尚无 ready meta 时显示准确状态。与 _jobs 同生命周期（task finally 一并 pop）。
        self._job_phase: dict[tuple[str, str], str] = {}

    # ---- ws 解析 + 校验 ----
    def _repos_root(self, ws: str) -> Path:
        """workspaces/<ws>/repos 的绝对路径（path-traversal 双重防线）。

        ws 段先经 _validate_ws_segment 正则挡掉空/`.``..`/`/`/`\\`/NUL；再用
        resolve().is_relative_to(self._workspaces_dir) 兜底，确保最终路径不越界
        workspaces_dir。
        """
        _validate_ws_segment(ws)
        base = self._workspaces_dir.resolve()
        p = (base / ws / "repos").resolve()
        if not p.is_relative_to(base):
            raise ValueError(f"非法 workspace：{ws!r}")
        return p

    def _ws_dir(self, ws: str) -> Path:
        """workspaces/<ws> 绝对路径（linked_repos.json 落此）。与 _repos_root 同档双重防线。"""
        _validate_ws_segment(ws)
        base = self._workspaces_dir.resolve()
        p = (base / ws).resolve()
        if not p.is_relative_to(base):
            raise ValueError(f"非法 workspace：{ws!r}")
        return p

    # ---- 查询 ----
    def is_busy(self, ws: str, name: str) -> bool:
        return (ws, name) in self._jobs

    def _repo_dir(self, ws: str, name: str) -> Path:
        """校验仓库名并解析为 ws 内 repos_dir 的绝对路径（path-traversal 双重防线）。"""
        return _resolve_repo_dir(self._repos_root(ws), name)

    def list_repos(self, ws: str) -> list[dict]:
        root = self._repos_root(ws)
        root.mkdir(parents=True, exist_ok=True)
        out: list[dict] = []
        for sub in sorted(root.iterdir()):
            if not sub.is_dir() or sub.name.startswith("."):
                continue
            # 顶层仓库: 必须有 .git（clone 产物）。仅 .supernova-repo.json 不算——
            # 旧版 migrate_legacy 会给分组目录误写 meta，若以 meta 判会把分组目录
            # 当仓库返回并 continue，跳过第二层子仓库扫描（2026-07-08 /repos 把
            # backend/frontend/20260615 当仓库、65 个真仓库全被吞的 bug）。
            if (sub / ".git").exists():
                try:
                    out.append(self._repo_view(ws, sub.name))
                except ValueError:
                    continue
                continue
            # 无 .git 的顶层目录：先判空壳（占名挡 re-clone 但不可见——失败 clone 残留 /
            # 空目录占位），可见化才能从 UI 删除（消灭"看不见也删不掉"死锁）。
            # busy（clone 进行中，target 已建但 .git 未落）不列——_repo_view 的 busy
            # 覆盖在 .git 出现后才生效，此处避免把 cloning 误显成 empty。
            shell = _shell_kind(sub)
            if shell == "meta":
                try:
                    out.append(self._repo_view(ws, sub.name))  # 按 meta 状态显示（failed）
                except ValueError:
                    continue
                continue
            if shell == "empty" and not self.is_busy(ws, sub.name):
                out.append(self._empty_shell_view(sub.name))
                continue
            # 非仓库目录 → 可能是分组目录，深入一层找 repos/<group>/<repo>
            for sub2 in sorted(sub.iterdir()):
                if not sub2.is_dir() or sub2.name.startswith("."):
                    continue
                if _is_repo(sub2):
                    try:
                        out.append(self._repo_view(ws, f"{sub.name}/{sub2.name}"))
                    except ValueError:
                        continue
                elif _shell_kind(sub2) == "empty" and not self.is_busy(ws, f"{sub.name}/{sub2.name}"):
                    out.append(self._empty_shell_view(f"{sub.name}/{sub2.name}"))
        # 关联仓库并入（私有克隆 ∪ 关联；关联项 linked=True）
        for link in read_linked_repos(self._ws_dir(ws)):
            try:
                out.append(self._linked_repo_view(
                    link["name"], link["path"], link.get("linked_at", "")))
            except Exception:
                continue  # 单条坏记录（如 path 已被外部删）不阻断整个列表
        return out

    def get_repo(self, ws: str, name: str) -> dict | None:
        try:
            d = self._repo_dir(ws, name)
        except ValueError:
            d = None
        if d is not None and d.is_dir() and _is_repo(d):
            view = self._repo_view(ws, name)
            view["recent_events"] = self._recent_events(ws, name, 20)
            return view
        # 关联仓库（私有克隆未中 → 查关联记录）
        for link in read_linked_repos(self._ws_dir(ws)):
            if link.get("name") == name:
                return self._linked_repo_view(name, link["path"], link.get("linked_at", ""))
        # 空壳目录（空目录占位）→ empty view（与列表同口径，列表可见详情不 404）
        if d is not None and d.is_dir() and _shell_kind(d) == "empty":
            return self._empty_shell_view(name)
        return None

    def _empty_shell_view(self, name: str) -> dict:
        """空壳目录（占名挡 clone 的空目录）的 view：state=empty、来源未知、无大小/
        时间戳（目录为空，无可统计）。恒非 busy——clone job 只挂在有 target 的
        clone 流程上，空壳是残留而非在跑。"""
        group = name.split("/", 1)[0] if "/" in name else None
        return {"name": name, "group": group, "source": {"kind": "unknown"}, "state": "empty"}

    def _repo_view(self, ws: str, name: str) -> dict:
        busy = self.is_busy(ws, name)
        # busy 时仓库正被 git 改（.git/config 可能半写、含注入凭据的 url）——不读不补 meta，
        # 避免与 _clone_task 竞态写 + 误把 cloning 判成 ready。
        if not busy:
            self._ensure_meta(ws, name)  # 读时自愈：运行期拷入的仓库补 meta
        meta = self._read_meta(ws, name)
        state = meta.get("state", "ready")
        if busy:
            # 内存有 job → 正在 clone/pull/extracting，覆盖磁盘 meta（期间 target 尚无 ready meta）
            state = self._job_phase.get((ws, name), "cloning")
        elif state in ("cloning", "pulling", "extracting"):
            state = "stale"  # 磁盘标进行中但内存无 job → 重启后未完成
        group = name.split("/", 1)[0] if "/" in name else None
        view = {"name": name, "group": group, **meta, "state": state}
        # 出站兜底：source.url 剥离 userinfo，防止历史/手动写入的带凭据 URL 泄露给前端
        # （get_repo + list_repos 的共同出口）。
        src = view.get("source")
        if isinstance(src, dict) and src.get("url"):
            view["source"] = {**src, "url": strip_credentials(src["url"])}
        if self.is_busy(ws, name):
            view["progress"] = self._last_progress(ws, name)
        return view

    def _read_meta(self, ws: str, name: str) -> dict:
        f = self._repo_dir(ws, name) / ".supernova-repo.json"
        if not f.exists():
            return {"name": name, "source": {"kind": "unknown"}, "state": "ready"}
        try:
            return json.loads(f.read_text("utf-8", errors="replace"))
        except json.JSONDecodeError:
            return {"name": name, "source": {"kind": "unknown"}, "state": "ready"}

    def _ensure_meta(self, ws: str, name: str) -> None:
        """读时自愈：仓库有 .git 但无 .supernova-repo.json（运行期文件系统拷入、未走 clone
        流程）→ 补写 meta（含 size_bytes）。幂等：meta 已存在或非 git 仓库则跳过；补写失败
        （_migrate_one 内部 try/except）不抛，仍由 _read_meta 兜底返回。

        刷新 /repos 即恢复来源/分支/大小三列数据，无需重启或手动扫描。
        """
        repo = self._repo_dir(ws, name)
        if (repo / ".supernova-repo.json").exists() or not (repo / ".git").exists():
            return
        self._migrate_one(ws, repo, name)

    def _write_meta(self, ws: str, name: str, **patch) -> None:
        f = self._repo_dir(ws, name) / ".supernova-repo.json"
        meta = self._read_meta(ws, name) if f.exists() else {"name": name}
        meta.update(patch)
        f.write_text(json.dumps(meta, ensure_ascii=False))

    def _last_progress(self, ws: str, name: str) -> int | None:
        f = self._repo_dir(ws, name) / "clone.ndjson"
        if not f.exists():
            return None
        last_pct = None
        for line in f.read_text("utf-8", errors="replace").splitlines()[-20:]:
            try:
                d = json.loads(line)
                if "progress" in d:
                    last_pct = d["progress"]
            except json.JSONDecodeError:
                continue
        return last_pct

    def _recent_events(self, ws: str, name: str, n: int) -> list[dict]:
        f = self._repo_dir(ws, name) / "clone.ndjson"
        if not f.exists():
            return []
        out: list[dict] = []
        for line in f.read_text("utf-8", errors="replace").splitlines()[-n:]:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out

    # ---- clone / pull ----
    async def clone(self, ws: str, url: str, branch: str | None, commit: str | None,
                    name: str | None, group: str | None = None) -> str:
        if not self._git.available(ws):
            raise PermissionError("未配置 git 凭证（GITLAB_USER/TOKEN）")
        name = name or self._git.repo_name(url)
        # name/group 各为单段目录名；组合成 group/repo 后整体由 _repo_dir 校验 + 兜底
        _validate_repo_segment(name, "仓库名")
        if group:
            _validate_repo_segment(group, "分组名")
            final_name = f"{group}/{name}"
        else:
            final_name = name
        target = self._repo_dir(ws, final_name)
        if target.exists():
            if _shell_kind(target) == "empty":
                raise ValueError(f"仓库已存在：{final_name}（空目录占位，请先在列表中删除）")
            raise ValueError(f"仓库已存在：{final_name}（可改用更新 pull）")
        if len(self._jobs) >= self._max_concurrent:
            raise TooManyClones(self._max_concurrent)
        # git clone 要求目标目录不存在或完全为空——只创建空 target，绝不预写 meta 进去。
        # 旧版在此预写 .supernova-repo.json 使 target 非空，git clone 必报 rc=128
        # 「destination path ... already exists and is not an empty directory」，clone 功能
        # 100% 不可用。cloning 期间：进度 ndjson 由 git 创建 target 后经 stderr drain 写入；
        # 列表可见性靠 .git（git init 后存在）+ is_busy（_repo_view 覆盖 state=cloning）。
        # source（url/branch/commit）在 clone 成功后由 _clone_task 落盘 ready meta。
        target.mkdir(parents=True, exist_ok=False)
        self._job_phase[(ws, final_name)] = "cloning"
        task = asyncio.create_task(self._clone_task(ws, final_name, url, branch, commit, target))
        self._jobs[(ws, final_name)] = task
        return final_name

    # ---- batch clone（批量克隆，2026-09-09）----
    # 单次批量上限（防超大请求体遍历过久，对齐 batch-delete 的 200 上限思路但
    # clone 是重操作，收紧到 50）；排队轮询间隔与单条等位上限防 jobs 卡死时无限转。
    BATCH_CLONE_MAX_URLS = 50
    BATCH_SLOT_POLL_S = 1.0
    BATCH_SLOT_MAX_WAIT_S = 600.0

    async def clone_batch(self, ws: str, urls: list[str], group: str | None = None) -> dict:
        """批量克隆：同步预检立即定局，撞并发上限的余量后台排队补位。

        返回 ``{"submitted": [name], "queued": [name], "skipped": [{"url","reason","existing"?}]}``：
        - 凭据缺失 → PermissionError（整批 fail-fast，端点 503）
        - 去重保序，重复条目 skipped(reason=duplicate)
        - 已存在（ValueError / 跨分组同 URL 或同名挡板）→ skipped(reason=exists,
          existing=已存在仓库名)，不中断整批
        - TooManyClones → 余量打包成一个后台任务逐条补位（queued），本方法立即
          返回——批量条数 > 并发上限时 HTTP 不悬挂（避免反代读超时掐断长请求），
          每条仍是独立 clone 任务，仓库列表逐个出现 cloning 态。

        跨分组挡板（2026-09-15）：clone() 的 exists 检查按 group/name 完整路径判，
        批量分多次提交时第二批漏填分组会让同 URL 落到另一路径重复克隆（现场
        __legacy__ 31/79 重复）。故批量预检按「归一 URL 已在任意分组/顶层」挡；
        名字挡板只收无 source.url 的仓（cloning 中/failed/linked）——ready 的
        同名不同 URL 放行（不同远端，非重复下载）。
        """
        if not self._git.available(ws):
            raise PermissionError("未配置 git 凭证（GITLAB_USER/TOKEN）")
        if not urls:
            raise ValueError("urls 不能为空")
        if len(urls) > self.BATCH_CLONE_MAX_URLS:
            raise ValueError(f"单次最多 {self.BATCH_CLONE_MAX_URLS} 条 URL")
        seen: set[str] = set()
        ordered: list[str] = []
        skipped: list[dict] = []
        for u in urls:
            if u in seen:
                skipped.append({"url": u, "reason": "duplicate"})
                continue
            seen.add(u)
            ordered.append(u)

        submitted: list[str] = []
        pending: list[str] = []
        for u in ordered:
            existing = self._batch_existing(ws, u)
            if existing:
                skipped.append({"url": u, "reason": "exists", "existing": existing})
                continue
            try:
                submitted.append(await self.clone(ws, u, None, None, None, group))
            except ValueError:        # 已存在（含空目录占位）→ 跳过收集
                skipped.append({"url": u, "reason": "exists",
                                "existing": self._batch_name(u, group)})
            except TooManyClones:
                pending.append(u)
        queued: list[str] = [self._batch_name(u, group) for u in pending]
        if pending:
            asyncio.create_task(self._batch_submit_task(ws, pending, group))
        return {"submitted": submitted, "queued": queued, "skipped": skipped}

    def _ws_repo_index(self, ws: str) -> tuple[dict[str, str], dict[str, str]]:
        """跨分组挡板索引：``(归一 URL -> 已有仓库名, repo_name -> 已有仓库名)``。

        扫私有克隆两层目录（顶层仓库 = _is_repo；否则视为分组目录深入一层）+
        关联清单。names 只收 meta 无 source.url 的仓——cloning 中（.git 无 meta）、
        failed（meta 无 source）、linked（本就无 URL）——这些 URL 未知，按名字挡
        （宁挡勿重：同 name 大概率就是同一仓在下）。ready 的只进 urls，避免误伤
        「同名不同远端」的有意两份。
        """
        urls: dict[str, str] = {}
        names: dict[str, str] = {}
        root = self._repos_root(ws)
        if root.is_dir():
            for sub in root.iterdir():
                if not sub.is_dir() or sub.name.startswith("."):
                    continue
                if _is_repo(sub):
                    self._index_repo(ws, sub.name, urls, names)
                    continue
                for sub2 in sub.iterdir():
                    if sub2.is_dir() and not sub2.name.startswith(".") and _is_repo(sub2):
                        self._index_repo(ws, f"{sub.name}/{sub2.name}", urls, names)
        for link in read_linked_repos(self._ws_dir(ws)):
            n = link.get("name")
            if n:
                names.setdefault(n.rsplit("/", 1)[-1], n)
        return urls, names

    def _index_repo(self, ws: str, name: str,
                    urls: dict[str, str], names: dict[str, str]) -> None:
        meta = self._read_meta(ws, name)
        u = (meta.get("source") or {}).get("url")
        if u:
            urls[_norm_clone_url(u)] = name
        else:
            names[name.rsplit("/", 1)[-1]] = name

    def _batch_existing(self, ws: str, u: str) -> str | None:
        """u 的克隆目标已被占（任意分组/顶层同 URL，或 cloning/failed/linked 同名）。

        返回已存在仓库名，未占用返回 None。每次现扫——排队补位期间新 ready 的
        仓也要被后续条目看见，不缓存。
        """
        url_idx, name_idx = self._ws_repo_index(ws)
        hit = url_idx.get(_norm_clone_url(u))
        if hit:
            return hit
        return name_idx.get(self._git.repo_name(u))

    def _batch_name(self, url: str, group: str | None) -> str:
        name = self._git.repo_name(url)
        return f"{group}/{name}" if group else name

    async def _batch_submit_task(self, ws: str, urls: list[str], group: str | None) -> None:
        """排队补位：逐条等空位提交（clone_batch 的后台半段）。

        等位条件看「未完成 job 数」——done-but-not-popped 的 entry 不计数
        （_clone_task finally pop 前的窗口不构成真实占位）。排队期间重名（用户
        手动加了同名仓 / 另一批已在其他分组克隆同 URL——2026-09-15 跨批排队
        竞态：批 A 目录未建时批 B 的同 URL 也进了排队，补位前复查 _batch_existing
        才能挡住顶层+分组双份）→ 放弃该条；凭据中途失效 → 放弃剩余（均后台
        静默：仓库列表里不会出现该仓，用户重贴即可）。
        """
        for u in urls:
            waited = 0.0
            while True:
                if self._batch_existing(ws, u):
                    break               # 排队期间已被其他批次/分组克隆 → 放弃
                if sum(1 for t in self._jobs.values() if not t.done()) < self._max_concurrent:
                    try:
                        await self.clone(ws, u, None, None, None, group)
                        break
                    except ValueError:
                        break            # 排队期间重名 → 放弃该条
                    except PermissionError:
                        return           # 凭据失效 → 放弃剩余
                    except TooManyClones:
                        pass             # 竞态丢槽（检查与提交间被抢先）→ 重试
                if waited >= self.BATCH_SLOT_MAX_WAIT_S:
                    break                # 单条等位超上限 → 放弃该条
                await asyncio.sleep(self.BATCH_SLOT_POLL_S)
                waited += self.BATCH_SLOT_POLL_S

    async def _clone_task(self, ws: str, name: str, url: str, branch: str | None,
                          commit: str | None, target: Path) -> None:
        try:
            async with self._sem:
                ok = await self._run_git_with_progress(
                    ws, name, phase="cloning",
                    argv=self._build_clone_argv(self._git._inject_auth(url, ws), target, branch))
                # _mark_failed 已写 state=failed；跳过 ready 收尾，保持 failed 状态
                if ok:
                    # commit checkout（可选）
                    if commit:
                        await self._run_git_with_progress(
                            ws, name, phase="cloning",
                            argv=["git", "-C", str(target), "fetch", "--all"])
                        proc = await asyncio.create_subprocess_exec(
                            "git", "-C", str(target), "checkout", commit,
                            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                        await proc.wait()
                        if proc.returncode != 0:
                            self._mark_failed(ws, name, f"commit {commit} checkout 失败")
                            return
                    head = await self._head_commit(target)
                    self._write_meta(ws, name, state="ready", last_pull_at=_now_iso(),
                                     cloned_at=_now_iso(),
                                     size_bytes=_dir_size(target),
                                     source={"kind": "git", "url": strip_credentials(url),
                                             "branch": branch, "commit": head})
                    await self._append_event(ws, name, {"ts": _now_iso(), "type": "clone_end", "status": "ready"})
        finally:
            self._jobs.pop((ws, name), None)
            self._job_phase.pop((ws, name), None)

    async def pull(self, ws: str, name: str) -> None:
        if self._is_linked(ws, name):
            await self._pull_linked(ws, name)
            return
        target = self._repo_dir(ws, name)
        if not target.is_dir() or not _is_repo(target):
            raise ValueError(f"仓库不存在：{name}")
        if (ws, name) in self._jobs:
            raise ValueError(f"仓库正忙：{name}")
        self._write_meta(ws, name, state="pulling")
        self._job_phase[(ws, name)] = "pulling"
        task = asyncio.create_task(self._pull_task(ws, name, target))
        self._jobs[(ws, name)] = task

    async def _pull_task(self, ws: str, name: str, target: Path) -> None:
        try:
            async with self._sem:
                ok = await self._run_git_with_progress(
                    ws, name, phase="pulling", argv=["git", "-C", str(target), "pull", "--ff-only"])
                if ok:
                    head = await self._head_commit(target)
                    self._write_meta(ws, name, state="ready", last_pull_at=_now_iso(),
                                     size_bytes=_dir_size(target),
                                     source={**self._read_meta(ws, name).get("source", {}), "commit": head})
                    await self._append_event(ws, name, {"ts": _now_iso(), "type": "clone_end", "status": "ready"})
                else:
                    self._mark_failed(ws, name, "pull 失败")
        finally:
            self._jobs.pop((ws, name), None)
            self._job_phase.pop((ws, name), None)

    # linked pull 超时上限（spec 2026-09-04 §4.3）：同步等待防悬挂；远端凭据不在
    # supernova 体系，慢网/大仓可能久等，超时如实报（端点 502）。
    LINKED_PULL_TIMEOUT_S = 120

    async def _pull_linked(self, ws: str, name: str) -> None:
        """linked pull（spec 2026-09-04 §4.3）：请求内同步 --ff-only。

        不复用私有仓的 202 + _run_git_with_progress 后台管线——那套的 clone.ndjson /
        meta / size 全写私有 clone 目录，对共享路径 = 污染用户目录（spec §7 零写入）。
        失败 / 超时 → RuntimeError（端点映射 502 带 stderr 摘要）。并发保护靠 git 自身
        index.lock 串行化（与 _checkout_linked 同约定，不引入锁）。
        """
        raw = resolve_linked_repo_path(self._workspaces_dir, ws, name)
        if raw is None:
            raise ValueError(f"仓库不存在：{name}")
        target = Path(raw)
        if not target.is_dir() or not _is_repo(target):
            raise ValueError(f"仓库不存在：{name}")
        if (ws, name) in self._jobs:
            raise ValueError(f"仓库正忙：{name}")
        proc = await asyncio.create_subprocess_exec(
            "git", "-C", str(target), "pull", "--ff-only",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            env=_no_prompt_env())
        try:
            _, err = await asyncio.wait_for(proc.communicate(), self.LINKED_PULL_TIMEOUT_S)
        except asyncio.TimeoutError:
            proc.kill()
            raise RuntimeError(f"pull 超时（> {self.LINKED_PULL_TIMEOUT_S}s），请在本地执行")
        if proc.returncode != 0:
            raise RuntimeError(f"pull 失败：{err.decode(errors='replace').strip()[:200]}")

    # ---- 上传 ZIP（upload repos）----
    async def upload_zip(self, ws: str, zip_path: Path, filename: str,
                         name: str | None, group: str | None = None) -> str:
        """上传 zip 添加仓库（异步，与 clone 同款 202 + 后台 task 模式）。

        流程：校验（扩展/大小/重名/并发）→ 后台解压到 repos 根下隐藏临时目录
        （防 zip slip / zip bomb）→ 剥单一顶层包裹目录 → 清 .git/hooks → 无 .git 则
        git init 单 commit 快照化（扫描链路 preflight/GitNexus 全兼容）→ meta
        kind=upload state=ready。失败落 failed meta（可见可删可重传）。

        zip_path 所有权：task 启动成功即移交组件——_upload_task 结束（成功/失败/
        异常）时删除该文件；本方法抛异常（校验失败，task 未启动）则由调用方自理。
        """
        if not filename.lower().endswith(".zip"):
            raise ValueError(f"仅支持 .zip 文件：{filename!r}")
        # multipart filename 可带路径分量——取 basename 再剥后缀，segment 校验二道防线
        base_name = Path(filename).name[: -len(".zip")]
        name = name or base_name
        _validate_repo_segment(name, "仓库名")
        if group:
            _validate_repo_segment(group, "分组名")
            final_name = f"{group}/{name}"
        else:
            final_name = name
        size = zip_path.stat().st_size
        if size > self.MAX_UPLOAD_ZIP_BYTES:
            raise UploadTooLarge(size, self.MAX_UPLOAD_ZIP_BYTES)
        target = self._repo_dir(ws, final_name)
        if target.exists():
            raise ValueError(f"仓库已存在：{final_name}（请先删除或改名）")
        if len(self._jobs) >= self._max_concurrent:
            raise TooManyClones(self._max_concurrent)
        # 先落可见骨架（空 target + extracting meta）：解压期间列表可见 state=extracting
        # （_shell_kind 的 meta 分支 + _repo_view busy 覆盖）。内容解压在隐藏临时目录
        # （.upload-* 前缀，list_repos 跳过），成功后同文件系统 rename 原子挪入。
        target.mkdir(parents=True, exist_ok=False)
        self._write_meta(ws, final_name, state="extracting",
                         source={"kind": "upload"}, cloned_at=_now_iso())
        self._job_phase[(ws, final_name)] = "extracting"
        task = asyncio.create_task(self._upload_task(ws, final_name, zip_path, target))
        self._jobs[(ws, final_name)] = task
        return final_name

    async def _upload_task(self, ws: str, name: str, zip_path: Path, target: Path) -> None:
        tmp_dir = self._repos_root(ws) / f".upload-{uuid4().hex[:12]}"
        try:
            await self._append_event(ws, name, {
                "ts": _now_iso(), "phase": "extracting", "status": "progress",
                "message": "解压上传包"})
            try:
                await asyncio.to_thread(
                    _safe_unzip, zip_path, tmp_dir,
                    self.MAX_EXTRACT_BYTES, self.MAX_EXTRACT_ENTRIES)
                _strip_single_root_wrapper(tmp_dir)
                _remove_git_hooks(tmp_dir)
                # 剔除 zip 内夹带的同名管理文件：meta/事件只能出自上传流程本身
                # （防伪造 state/source、污染事件流；最终 meta 稍后也会覆盖，双保险）
                for junk in (".supernova-repo.json", "clone.ndjson"):
                    (tmp_dir / junk).unlink(missing_ok=True)
            except (ValueError, RuntimeError, zipfile.BadZipFile, OSError) as e:
                self._mark_failed(ws, name, f"上传解压失败：{e}")
                return
            for e in sorted(tmp_dir.iterdir()):
                e.rename(target / e.name)
            tmp_dir.rmdir()
            if (target / ".git").exists():
                # zip 自带 .git：保留真实历史，url/branch/commit 从工作树现状读——
                # 信息呈现与 clone/linked 一致（来源列显远端地址、分支列显真实分支）；
                # url 可能带上传者本地凭据，落盘前剥净（与 clone/迁移路径同一铁律）
                url, branch = self._infer_from_git(target)
                head = await self._head_commit(target)
            else:
                await self._append_event(ws, name, {
                    "ts": _now_iso(), "phase": "extracting", "status": "progress",
                    "message": "创建快照（git init + commit）"})
                url = None  # 无 .git 快照无远端可言；分支列显快照分支
                try:
                    branch, head = await self._git_snapshot(target)
                except RuntimeError as e:
                    self._mark_failed(ws, name, str(e))
                    return
            self._write_meta(ws, name, state="ready", last_error=None,
                             cloned_at=_now_iso(), last_pull_at=_now_iso(),
                             size_bytes=_dir_size(target),
                             source={"kind": "upload", "url": strip_credentials(url),
                                     "branch": branch, "commit": head})
            await self._append_event(ws, name, {"ts": _now_iso(), "type": "clone_end", "status": "ready"})
        except Exception as e:  # 兜底：磁盘满等意外也落 failed（可见可删可重传）
            self._mark_failed(ws, name, f"上传失败：{e}")
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            zip_path.unlink(missing_ok=True)  # 临时 zip 用完即删（API 层移交的所有权）
            self._jobs.pop((ws, name), None)
            self._job_phase.pop((ws, name), None)

    async def _git_snapshot(self, repo: Path) -> tuple[str | None, str | None]:
        """无 .git 的上传目录 → git init + add -A + 单 commit 快照（--allow-empty 兜空仓）。

        git 身份用 -c 临时注入（不污染全局/仓库 config）。返回 (branch, commit)。
        抛 RuntimeError（含 stderr 摘要）由调用方落 failed。
        """
        argvs = [
            ["git", "-C", str(repo), "init", "-q"],
            ["git", "-C", str(repo), "add", "-A"],
            ["git", "-C", str(repo), "-c", "user.name=supernova-upload",
             "-c", "user.email=upload@supernova.local",
             "commit", "-q", "--allow-empty", "-m", "supernova upload snapshot"],
        ]
        for argv in argvs:
            proc = await asyncio.create_subprocess_exec(
                *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            _, err = await proc.communicate()
            if proc.returncode != 0:
                raise RuntimeError(f"git 快照化失败：{err.decode(errors='replace').strip()[:200]}")
        return await self._current_branch(repo), await self._head_commit(repo)

    async def _current_branch(self, target: Path) -> str | None:
        try:
            proc = await asyncio.create_subprocess_exec(
                "git", "-C", str(target), "branch", "--show-current",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            out, _ = await proc.communicate()
            return out.decode("utf-8", "replace").strip() or None
        except Exception:
            return None

    def _is_upload(self, ws: str, name: str) -> bool:
        """私有仓库是否为上传来源（kind=upload）。上传仓凭据未进 ws auth：
        pull（fetch 远端）端点据此挡 405，更新走重新上传；checkout / 列分支
        不受影响——本地 refs 完整（zip 打包自完整 clone），纯本地操作。"""
        return self._read_meta(ws, name).get("source", {}).get("kind") == "upload"

    # ---- checkout / delete ----
    async def checkout(self, ws: str, name: str, branch: str) -> None:
        if self._is_linked(ws, name):
            await self._checkout_linked(ws, name, branch)
            return
        target = self._repo_dir(ws, name)
        if not target.is_dir() or not _is_repo(target):
            raise ValueError(f"仓库不存在：{name}")
        if (ws, name) in self._jobs:
            raise ValueError(f"仓库正忙：{name}")
        if not self._is_upload(ws, name):
            # clone 仓：先 fetch origin 同步远端分支（凭据已在 .git/config）
            proc = await asyncio.create_subprocess_exec(
                "git", "-C", str(target), "fetch", "origin", branch,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            _, err = await proc.communicate()
            if proc.returncode != 0:
                raise ValueError(f"分支不存在：{branch}")
        # 上传仓跳过 fetch（无凭据问不了远端）直接本地 checkout——zip 自带 .git 的
        # 本地 refs 完整；无 .git 快照仓单分支，切他支同样在这里报「分支不存在」
        proc = await asyncio.create_subprocess_exec(
            "git", "-C", str(target), "checkout", branch,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        await proc.communicate()
        if proc.returncode != 0:
            raise ValueError(f"分支不存在：{branch}")
        head = await self._head_commit(target)
        src = self._read_meta(ws, name).get("source", {})
        src["branch"] = branch; src["commit"] = head
        self._write_meta(ws, name, source=src)

    async def _checkout_linked(self, ws: str, name: str, branch: str) -> None:
        """linked checkout（spec 2026-09-04 §4.2）：直接切目标目录分支。

        跳过 fetch——linked 远端凭据不在 supernova 凭据体系（非本系统 clone，
        .git/config 存原始 URL），fetch 会交互式挂起；仅 refs/remotes 有该分支时
        git checkout 的 DWIM 自动建本地跟踪分支。共享目录零写入：不回写 meta
        （_linked_repo_view 每次现读 .git 推断 branch，切完刷新即见）。
        """
        raw = resolve_linked_repo_path(self._workspaces_dir, ws, name)
        if raw is None:
            raise ValueError(f"仓库不存在：{name}")
        target = Path(raw)
        if not target.is_dir() or not _is_repo(target):
            raise ValueError(f"仓库不存在：{name}")
        if (ws, name) in self._jobs:
            raise ValueError(f"仓库正忙：{name}")
        proc = await asyncio.create_subprocess_exec(
            "git", "-C", str(target), "checkout", branch,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            env=_no_prompt_env())
        _, err = await proc.communicate()
        if proc.returncode != 0:
            text = err.decode(errors="replace").strip()
            if "would be overwritten" in text or "Please commit" in text:
                raise ValueError(f"本地有未提交改动与目标分支冲突：{text[:200]}")
            raise ValueError(f"分支不存在：{branch}")

    # ls-remote 是网络调用（问远端，不依赖本地 ref），大仓/慢网需上限防悬挂
    LS_REMOTE_TIMEOUT_S = 15

    async def list_branches(self, ws: str, name: str) -> list[str]:
        """列分支名（分支列 combobox 数据源）。

        clone 仓问远端（git ls-remote --heads origin，不依赖本地 ref）——凭据零新
        工作：clone 时 _inject_auth 注入的带凭据 URL 已被 git 写进 .git/config
        remote origin。上传仓走本地枚举（git for-each-ref refs/heads）：凭据未进
        ws auth 问不了远端，但 zip 打包自完整 clone、本地 refs 全在（无 .git 快照
        仓退化为单元素列表）。
        错误约定（branches 端点映射）：仓库不存在/忙 → ValueError；ls-remote /
        本地枚举失败、超时 → RuntimeError（前端降级手输）。
        """
        if self._is_linked(ws, name):
            raw = resolve_linked_repo_path(self._workspaces_dir, ws, name)
            if raw is None:
                raise ValueError(f"仓库不存在：{name}")
            linked_target = Path(raw)
            if not linked_target.is_dir() or not _is_repo(linked_target):
                raise ValueError(f"仓库不存在：{name}")
            if (ws, name) in self._jobs:
                raise ValueError(f"仓库正忙：{name}")
            return await self._list_branches_linked(linked_target)
        target = self._repo_dir(ws, name)
        if not target.is_dir() or not _is_repo(target):
            raise ValueError(f"仓库不存在：{name}")
        if (ws, name) in self._jobs:
            raise ValueError(f"仓库正忙：{name}")
        if self._is_upload(ws, name):
            proc = await asyncio.create_subprocess_exec(
                "git", "-C", str(target), "for-each-ref", "refs/heads",
                "--format=%(refname:short)",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            out, err = await proc.communicate()
            if proc.returncode != 0:
                raise RuntimeError(
                    f"本地分支枚举失败：{err.decode(errors='replace').strip()[:200]}")
            return [ln for ln in out.decode(errors="replace").splitlines() if ln]
        try:
            proc = await asyncio.wait_for(asyncio.create_subprocess_exec(
                "git", "-C", str(target), "ls-remote", "--heads", "origin",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE),
                timeout=self.LS_REMOTE_TIMEOUT_S)
            out, err = await proc.communicate()
        except asyncio.TimeoutError:
            raise RuntimeError(f"ls-remote 超时（>{self.LS_REMOTE_TIMEOUT_S}s）")
        if proc.returncode != 0:
            raise RuntimeError(f"ls-remote 失败：{err.decode(errors='replace').strip()[:200]}")
        # 输出行 `<sha>\trefs/heads/<branch>`；取尾段去重排序
        return sorted({ln.split("\t")[1][len("refs/heads/"):]
                       for ln in out.decode(errors="replace").splitlines()
                       if "\trefs/heads/" in ln})

    async def _list_branches_linked(self, target: Path) -> list[str]:
        """linked 分支枚举（spec 2026-09-04 §4.4）：refs/heads ∪ refs/remotes/origin。

        纯本地 for-each-ref（同 upload 路径），不问远端——linked 凭据不在体系；
        remotes 条目 strip ``origin/`` 前缀去重（for-each-ref 字典序 heads 先出，
        本地名优先天然成立）。origin/HEAD 符号引用跳过。失败 → RuntimeError
        （端点 502，前端降级手输）。
        """
        proc = await asyncio.create_subprocess_exec(
            "git", "-C", str(target), "for-each-ref",
            "refs/heads", "refs/remotes/origin", "--format=%(refname:short)",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            env=_no_prompt_env())
        out, err = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(
                f"本地分支枚举失败：{err.decode(errors='replace').strip()[:200]}")
        names: list[str] = []
        seen: set[str] = set()
        for ln in out.decode(errors="replace").splitlines():
            short = ln.strip().removeprefix("origin/")
            if not short or short == "HEAD":
                continue
            if short not in seen:
                seen.add(short)
                names.append(short)
        return names

    async def delete(self, ws: str, name: str) -> None:
        if (ws, name) in self._jobs:
            raise ValueError(f"仓库正忙：{name}")
        # 关联仓库 → 仅取消引用（unlink），绝不删源文件（共享路径，可能他 ws 仍用）
        if self._is_linked(ws, name):
            self.unlink_repo(ws, name)
            return
        target = self._repo_dir(ws, name)
        # 仅删除真仓库目录（有 .git 或 meta），绝不 rmtree 分组目录（含多个子仓库）
        if target.is_dir() and _is_repo(target):
            shutil.rmtree(target, ignore_errors=False)
            self._rmdir_group_if_empty(ws, target)
            return
        # 空壳目录（空目录占位）→ rmdir 清理。rmdir 仅空目录可删（非空 OSError），
        # 天然防误删——非空无 meta 的普通目录仍走不删（内容归属未知）
        if target.is_dir() and _shell_kind(target) == "empty":
            target.rmdir()

    def _rmdir_group_if_empty(self, ws: str, repo_dir: Path) -> None:
        """删分组仓库后清理空分组目录：repos/<g>/<repo> 删掉后 <g> 若空 → rmdir。
        避免留下占名空壳（下次 clone 同名顶层仓库会被 target.exists() 挡住报
        "仓库已存在"）。<g> 非空（还有兄弟仓库）→ rmdir 抛 OSError → 忽略保留。
        顶层仓库父目录即 repos 根——绝不动根。
        """
        parent = repo_dir.parent
        if parent == self._repos_root(ws):
            return
        try:
            parent.rmdir()
        except OSError:
            pass

    async def delete_one(self, ws: str, name: str) -> str:
        """批量删除的逐项归类器：复用 ``delete`` 的分叉（linked→unlink 不删源、私有→rmtree），
        返回 ``'deleted' | 'unlinked' | 'busy' | 'not_found'`` 供批量端点收集 skipped。

        与单条 ``delete`` 的区别仅在归类：``delete`` 对不存在目录静默无操作、对忙碌抛
        ``ValueError``；``delete_one`` 把这两种显式归为 ``'not_found'`` / ``'busy'``，不抛，
        使批量场景能逐项继续、收集跳过原因。
        """
        _validate_repo_name(name)
        if (ws, name) in self._jobs:
            return "busy"
        linked = self._is_linked(ws, name)
        target_exists = False
        try:
            target = self._repo_dir(ws, name)
            # 空壳（空目录占位）视同存在 → 'deleted'（delete 走 rmdir），
            # 批量删除可清理占位目录
            target_exists = target.is_dir() and (_is_repo(target) or _shell_kind(target) == "empty")
        except ValueError:
            target_exists = False
        if not linked and not target_exists:
            return "not_found"
        await self.delete(ws, name)
        return "unlinked" if linked else "deleted"

    # ---- 关联仓库（linked repos）----
    def link_repo(self, ws: str, name: str, path: str) -> dict:
        """把一个已存在的目录路径（绝对路径）关联进 ws。

        校验：ws/name 合法、path 存在且是目录、name 与 ws 内现有 repo（私有克隆 ∪
        既有关联）不重名。多 ws 可关联同一路径（共享）。写 linked_repos.json，返回 view。
        """
        _validate_ws_segment(ws)
        _validate_repo_name(name)
        target = Path(path).expanduser().resolve()
        if not target.is_dir():
            raise ValueError(f"路径不存在或非目录：{path}")
        ws_dir = self._ws_dir(ws)
        clone_names = {r["name"] for r in self.list_repos(ws)}
        linked_names = {l["name"] for l in read_linked_repos(ws_dir)}
        if name in (clone_names | linked_names):
            raise RepoExists(name)
        linked_at = _now_iso()
        links = read_linked_repos(ws_dir)
        links.append({"name": name, "path": str(target), "linked_at": linked_at})
        write_linked_repos(ws_dir, links)
        return self._linked_repo_view(name, str(target), linked_at)

    def _linked_repo_view(self, name: str, path: str, linked_at: str) -> dict:
        """关联仓库的 view：source.kind=linked；若 path 含 .git 则推断 url/branch 展示。
        无 state（关联仓库无 clone 状态，恒视为 ready）、无 size_bytes（避免对共享/大仓
        目录每次列表都 walk）。"""
        group = name.split("/", 1)[0] if "/" in name else None
        url, branch = self._infer_from_git(Path(path))
        source: dict = {"kind": "linked"}
        if url or branch:
            source = {"kind": "linked",
                      "url": strip_credentials(url) if url else None,
                      "branch": branch}
        return {
            "name": name,
            "group": group,
            "linked": True,
            "source": source,
            "state": "ready",
            "cloned_at": linked_at,
        }

    def unlink_repo(self, ws: str, name: str) -> None:
        """取消关联：仅从 linked_repos.json 移除记录，绝不触碰源目录文件。不存在 → ValueError。"""
        _validate_ws_segment(ws)
        ws_dir = self._ws_dir(ws)
        links = read_linked_repos(ws_dir)
        new_links = [l for l in links if l.get("name") != name]
        if len(new_links) == len(links):
            raise ValueError(f"关联仓库不存在：{name}")
        write_linked_repos(ws_dir, new_links)

    # 批量扫描时跳过的噪声目录名（依赖产物 / 构建缓存，绝非用户要关联的仓库）
    _NOISE_DIR_NAMES = frozenset({
        ".git", "node_modules", ".venv", "venv", "__pycache__",
        ".idea", ".vscode", ".next", "dist", "build", "target", ".cache",
    })
    _LINK_DIR_MAX_DEPTH = 4  # name 至多一层分组（2 段）；扫描深度上限防全盘

    def link_repos_in_dir(self, ws: str, path: str) -> dict:
        """扫描父目录下所有 git 仓库（含 .git），批量关联进 ws。

        name = 相对父目录的路径（至多一层分组 ``group/repo``；超出 2 段的跳过并报告）。
        ws 内已存在的 name 跳过（不中断批量）。找到仓库后不再深入其内部（submodule 边界）。
        返回 ``{"imported": [{name, path}], "skipped": [{name?, path, reason}]}``。
        """
        _validate_ws_segment(ws)
        base = Path(path).expanduser().resolve()
        if not base.is_dir():
            raise ValueError(f"路径不存在或非目录：{path}")
        ws_dir = self._ws_dir(ws)
        existing = {r["name"] for r in self.list_repos(ws)}  # 私有克隆 ∪ 已关联
        links = read_linked_repos(ws_dir)
        imported: list[dict] = []
        skipped: list[dict] = []
        for dirpath, dirnames, _ in os.walk(base, topdown=True):
            cur = Path(dirpath)
            depth = len(cur.relative_to(base).parts)
            if depth >= self._LINK_DIR_MAX_DEPTH:
                dirnames[:] = []
                continue
            dirnames[:] = [d for d in dirnames if d not in self._NOISE_DIR_NAMES]
            if not _is_repo(cur):
                continue  # 非仓库目录 -> 继续递归其（已过滤噪声的）子目录
            # 仓库根：生成 name（相对父目录的路径）
            name = base.name if cur == base else "/".join(cur.relative_to(base).parts)
            try:
                _validate_repo_name(name)
            except ValueError:
                skipped.append({"path": str(cur), "reason": "路径层级过深（仅支持至多一层分组）"})
                dirnames[:] = []
                continue
            if name in existing:
                skipped.append({"name": name, "path": str(cur), "reason": "已存在"})
            else:
                links.append({"name": name, "path": str(cur), "linked_at": _now_iso()})
                existing.add(name)
                imported.append({"name": name, "path": str(cur)})
            dirnames[:] = []  # 仓库内部不再深入（避免把仓库内 .git 当子仓库）
        write_linked_repos(ws_dir, links)
        return {"imported": imported, "skipped": skipped}

    def _is_linked(self, ws: str, name: str) -> bool:
        return any(l.get("name") == name for l in read_linked_repos(self._ws_dir(ws)))

    # ---- git 子进程 + stderr 进度解析 ----
    def _build_clone_argv(self, authed_url: str, target: Path, branch: str | None) -> list[str]:
        cmd = ["git", "clone", "--progress"]
        if branch:
            cmd += ["--branch", branch]
        cmd += [authed_url, str(target)]
        return cmd

    async def _run_git_with_progress(self, ws: str, name: str, phase: str, argv: list[str]) -> bool:
        """跑 git，异步读 stderr 解析进度写 ndjson。返回 returncode==0。"""
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        assert proc.stderr is not None

        async def drain_stderr():
            while True:
                line = await proc.stderr.readline()
                if not line:
                    break
                text = line.decode("utf-8", "replace")
                m = _PROGRESS_RE.search(text)
                if m:
                    await self._append_event(ws, name, {
                        "ts": _now_iso(), "phase": phase, "progress": int(m.group(1)),
                        "status": "progress"})
                else:
                    await self._append_event(ws, name, {
                        "ts": _now_iso(), "phase": phase,
                        "message": self._git.redact(text.rstrip()), "status": "progress"})

        async def drain_stdout():
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break

        await asyncio.gather(drain_stderr(), drain_stdout())
        rc = await proc.wait()
        if rc != 0:
            self._mark_failed(ws, name, f"{phase} 失败（rc={rc}）")
        return rc == 0

    def _mark_failed(self, ws: str, name: str, msg: str) -> None:
        # 容错：git clone 失败（认证/网络/源不存在）在某些 git 版本下会删除它创建的 target，
        # 此时需重建目录以落 failed meta + clone_end 事件，让失败项可见、可删、可重试。
        repo = self._repo_dir(ws, name)
        repo.mkdir(parents=True, exist_ok=True)
        self._write_meta(ws, name, state="failed", last_error=msg, last_pull_at=_now_iso())
        # clone_end 失败事件（同步写，task 内调用）
        f = self._repo_dir(ws, name) / "clone.ndjson"
        with open(f, "a") as fh:
            fh.write(json.dumps({"ts": _now_iso(), "type": "clone_end",
                                 "status": "failed", "error": msg}, ensure_ascii=False) + "\n")

    async def _append_event(self, ws: str, name: str, payload: dict) -> None:
        f = self._repo_dir(ws, name) / "clone.ndjson"
        async with aiofiles.open(f, "a") as fh:
            await fh.write(json.dumps(payload, ensure_ascii=False) + "\n")

    async def _head_commit(self, target: Path) -> str | None:
        try:
            proc = await asyncio.create_subprocess_exec(
                "git", "-C", str(target), "rev-parse", "HEAD",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            out, _ = await proc.communicate()
            return out.decode("utf-8", "replace").strip() or None
        except Exception:
            return None

    # ---- 旧目录迁移 ----
    def _cleanup_miswritten_group_meta(self, ws: str) -> int:
        """清理被旧版误写到分组目录的 .supernova-repo.json。

        旧版 migrate_legacy 会给顶层每个目录补 meta，导致分组目录（下面有真仓库）也被
        写入 meta，使 _is_repo 误判其为仓库（list_repos 把分组目录当仓库返回、pull 对
        其执行 git pull 失败）。新版不再误写，但已存在的脏 meta 须清理：顶层目录有 meta、
        无 .git、且下面有子仓库（含 .git）-> 判定为分组目录，删 meta。

        单个删除失败（PermissionError 等）不影响整体--lifespan 启动期调用。
        """
        root = self._repos_root(ws)
        if not root.is_dir():
            return 0
        n = 0
        for sub in root.iterdir():
            if not sub.is_dir() or sub.name.startswith("."):
                continue
            meta = sub / ".supernova-repo.json"
            if not meta.exists() or (sub / ".git").exists():
                continue
            has_child_repo = any(
                c.is_dir() and not c.name.startswith(".") and (c / ".git").exists()
                for c in sub.iterdir()
            )
            if has_child_repo:
                try:
                    meta.unlink()
                    n += 1
                except OSError:
                    pass
        return n

    def migrate_legacy(self, ws: str) -> int:
        """把已 clone 但未纳入管理的旧仓库（有 .git 无 .supernova-repo.json）补写 meta。

        扫两层（扁平 repos/<name> + 分组 repos/<group>/<name>），只处理有 .git 的目录，
        跳过无 .git 的分组目录（避免把 frontend/backend 这类分组目录误当仓库纳入）。

        单个仓库迁移失败（PermissionError / 损坏符号链接 / .git/config 不可读 / 非法名等）
        不影响其他仓库与整体启动——lifespan 启动期调用，绝不可因一个坏目录 abort。
        """
        root = self._repos_root(ws)
        if not root.is_dir():
            return 0
        self._cleanup_miswritten_group_meta(ws)
        n = 0
        for sub in root.iterdir():
            if not sub.is_dir() or sub.name.startswith("."):
                continue
            if (sub / ".git").exists():
                n += self._migrate_one(ws, sub, sub.name)
                continue
            # 非仓库目录 → 可能分组目录，深入一层找真仓库
            for sub2 in sub.iterdir():
                if not sub2.is_dir() or sub2.name.startswith("."):
                    continue
                if (sub2 / ".git").exists():
                    n += self._migrate_one(ws, sub2, f"{sub.name}/{sub2.name}")
        return n

    def _migrate_one(self, ws: str, repo: Path, name: str) -> int:
        """单个仓库补写 meta（已纳入管理或失败则返回 0，成功返回 1）。"""
        if (repo / ".supernova-repo.json").exists():
            return 0
        try:
            url, branch = self._infer_from_git(repo)
            url = strip_credentials(url)
            self._write_meta(ws, name,
                source={"kind": "git" if url else "unknown", "url": url, "branch": branch},
                cloned_at=datetime.fromtimestamp(repo.stat().st_mtime, timezone.utc).isoformat(),
                size_bytes=_dir_size(repo),
                state="ready", last_error=None)
        except Exception:
            # 单个坏仓库不应阻断迁移或启动；跳过即可（目录仍在，下次启动可重试）
            return 0
        return 1

    @staticmethod
    def _infer_from_git(repo: Path) -> tuple[str | None, str | None]:
        url, branch = None, None
        cfg = repo / ".git" / "config"
        if cfg.exists():
            for line in cfg.read_text("utf-8", errors="replace").splitlines():
                s = line.strip()
                if s.startswith("url = "):
                    url = s[6:]
        head = repo / ".git" / "HEAD"
        if head.exists():
            t = head.read_text("utf-8", errors="replace").strip()
            if t.startswith("ref: refs/heads/"):
                branch = t[len("ref: refs/heads/"):]
        return url, branch
