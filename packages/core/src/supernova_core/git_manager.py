from __future__ import annotations

import asyncio
import logging
import subprocess
from pathlib import Path
from typing import ClassVar

from supernova_core.models.agents import AgentName
from supernova_core.models.errors import ErrorCode, PentestError
from supernova_core.models.result import GitResult

logger = logging.getLogger(__name__)

_GIT_LOCK_PATTERNS: list[str] = [
    "index.lock",
    "unable to lock",
    "Another git process",
    "fatal: Unable to create",
    "fatal: index file",
    # 并发对同一 unborn ref 走 create 语义,输家到 ref 阶段撞上赢家已建的 ref
    # (2026-09-10 cross-repo 首扫:ensure 的 initial commit 与并发 edge 的
    # checkpoint commit 竞态)。重试即自愈——第二次 ref 已存在,走 update 语义。
    "cannot lock ref",
]


def _is_git_lock_error(stderr: str) -> bool:
    return any(p in stderr for p in _GIT_LOCK_PATTERNS)


def _log_change_summary(
    changed_files: list[str],
    action: str,
    max_show: int = 5,
) -> None:
    if not changed_files:
        logger.info("%s: no file changes", action)
        return
    if len(changed_files) <= max_show:
        logger.info("%s: %s", action, ", ".join(changed_files))
    else:
        shown = ", ".join(changed_files[:max_show])
        logger.info(
            "%s: %s ... and %d more files",
            action,
            shown,
            len(changed_files) - max_show,
        )


class GitManager:
    """Async git operations with concurrency control and retry."""

    _git_lock: ClassVar[asyncio.Lock] = asyncio.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @staticmethod
    async def is_git_repository(repo_path: Path) -> bool:
        """Check if *repo_path* is inside a git repository."""
        try:
            result = await GitManager._run_git(repo_path, "rev-parse", "--git-dir")
            return result.returncode == 0
        except Exception:
            return False

    @staticmethod
    async def ensure_repository(repo_path: Path) -> GitResult:
        """幂等确保 repo_path 是独立 git 仓库(对齐 TS activities.ts:535-552)。

        用 stat(repo_path/.git) 判断 .git 是否"直接存在于 repo_path 内"——
        刻意不用 is_git_repository(后者用 rev-parse,会匹配父仓库的 .git,
        正是迁移后 deliverables 污染主仓库的 bug 根源)。不存在则 git init +
        设 local 身份(避免无全局 git config 的环境 commit 失败)+ 首次空 commit。

        init+initial commit 全程持 _git_lock(对齐 commit_index 的锁内自查
        init):多个 agent 并发 execute 时,首个协程的 initial commit 若不持锁,
        会与后续协程持锁的 create_checkpoint 在 git 层并发——unborn HEAD 上
        双方同走 create 语义,输家报 "cannot lock ref 'HEAD': reference
        already exists"(2026-09-10 cross-repo 首扫生产事故)。快检在锁外,
        拿锁后双检(等锁期间可能已被并发协程 init)。
        """
        dot_git = repo_path / ".git"
        if dot_git.exists():
            return GitResult(success=True)

        async with GitManager._git_lock:
            if dot_git.exists():
                return GitResult(success=True)
            await GitManager._run_git(repo_path, "init")
            # local 身份:TS 依赖全局 config,这里设 local 以在 CI/容器等无全局环境稳健
            await GitManager._run_git(repo_path, "config", "user.email", "shannon-deliverables@local")
            await GitManager._run_git(repo_path, "config", "user.name", "shannon-deliverables")
            await GitManager._run_git_with_retry(
                repo_path, "commit", "--allow-empty", "-m", "Initial deliverables checkpoint",
            )
        return GitResult(success=True)

    @staticmethod
    async def create_checkpoint(
        repo_path: Path,
        agent_name: str | AgentName,
        attempt: int = 1,
    ) -> GitResult:
        """Create a git checkpoint before agent execution.

        attempt == 1  → preserve existing changes, then add + commit
        attempt >  1  → reset + clean first, then add + commit
        """
        if not await GitManager.is_git_repository(repo_path):
            logger.warning("Checkpoint skipped: not a git repository (%s)", repo_path)
            return GitResult(success=True)

        name = agent_name.value if isinstance(agent_name, AgentName) else agent_name

        # On retries, clean workspace first
        if attempt > 1:
            await GitManager._run_git(repo_path, "reset", "--hard", "HEAD")
            await GitManager._run_git(repo_path, "clean", "-fd")

        async with GitManager._git_lock:
            await GitManager._run_git(repo_path, "add", "-A")
            changed = await GitManager._get_changed_files(repo_path)
            msg = f"checkpoint: before {name} (attempt {attempt})"
            result = await GitManager._run_git_with_retry(
                repo_path, "commit", "--allow-empty", "-m", msg,
            )

        if result.returncode != 0:
            raise PentestError(
                f"Git checkpoint failed for {name}: {result.stderr}",
                "infrastructure",
                error_code=ErrorCode.GIT_CHECKPOINT_FAILED,
                context={"agent": name, "attempt": attempt},
            )

        _log_change_summary(changed, f"Checkpoint ({name})")
        return GitResult(success=True, changed_files=changed)

    @staticmethod
    async def commit(
        repo_path: Path,
        agent_name: str | AgentName,
    ) -> GitResult:
        """Commit agent deliverables."""
        if not await GitManager.is_git_repository(repo_path):
            logger.warning("Commit skipped: not a git repository (%s)", repo_path)
            return GitResult(success=True)

        name = agent_name.value if isinstance(agent_name, AgentName) else agent_name

        async with GitManager._git_lock:
            await GitManager._run_git(repo_path, "add", "-A")
            changed = await GitManager._get_changed_files(repo_path)
            msg = f"deliverable: {name}"
            result = await GitManager._run_git_with_retry(
                repo_path, "commit", "--allow-empty", "-m", msg,
            )

        if result.returncode != 0:
            raise PentestError(
                f"Git commit failed for {name}: {result.stderr}",
                "infrastructure",
                error_code=ErrorCode.GIT_CHECKPOINT_FAILED,
                context={"agent": name},
            )

        _log_change_summary(changed, f"Committed ({name})")
        return GitResult(success=True, changed_files=changed)

    @staticmethod
    async def commit_index(repo_path: Path) -> GitResult:
        """把索引/图/缺口报告等**中间产物**提交为跟踪 deliverable。

        背景:run_code_index 与 pre-recon agent 在 asyncio.gather 里并发。pre-recon
        失败时 rollback 的 ``git clean -fd`` 会删掉**未跟踪**的中间产物(intermediate/
        整个目录),而 run_code_index 已成功、不在重试循环里 → 文件永不重生,下游
        run_entry_point_fusion 硬报 FileNotFoundError。提交为跟踪文件后,clean -fd
        不动它、reset --hard HEAD 会还原它,与 agent 自己的 deliverable 享受同等保护。

        tiering(spec 2026-08-18)后中间产物落桶内 intermediate/,整个目录提交保护;
        老平铺结构(code_index.json/code_index_summary.md 在桶根)兜底。

        用 ``index:`` 前缀(非 ``deliverable:``),避免 get_completed_agents 把它误当
        已完成 agent 而污染 resume 的跳过守卫。全程持 ``_git_lock``,避免与并发 agent
        的 checkpoint/commit 抢 git index。
        """
        async with GitManager._git_lock:
            # 仓可能尚未 init(run_code_index 与 pre-recon 的 ensure_repository 并发)
            if not (repo_path / ".git").exists():
                await GitManager._run_git(repo_path, "init")
                await GitManager._run_git(
                    repo_path, "config", "user.email", "shannon-deliverables@local",
                )
                await GitManager._run_git(
                    repo_path, "config", "user.name", "shannon-deliverables",
                )
                await GitManager._run_git_with_retry(
                    repo_path, "commit", "--allow-empty", "-m", "Initial deliverables checkpoint",
                )
            # 中间产物目录存在 → add 整个 intermediate/(含 code_index.json /
            # parameter_graph.json / gap reports);老平铺结构 → 只 add 实际存在的
            # index 文件,避免 pathspec 缺失报错。
            intermediate_dir = repo_path / "intermediate"
            if intermediate_dir.exists():
                await GitManager._run_git(repo_path, "add", "--", "intermediate/")
            else:
                index_files = [
                    p for p in ("code_index.json", "code_index_summary.md")
                    if (repo_path / p).exists()
                ]
                if index_files:
                    await GitManager._run_git(repo_path, "add", "--", *index_files)
            result = await GitManager._run_git_with_retry(
                repo_path, "commit", "--allow-empty", "-m", "index: code-index",
            )

        if result.returncode != 0:
            raise PentestError(
                f"Git commit_index failed: {result.stderr}",
                "infrastructure",
                error_code=ErrorCode.GIT_CHECKPOINT_FAILED,
                context={"step": "code-index"},
            )
        return GitResult(success=True)

    @staticmethod
    async def rollback(repo_path: Path, reason: str) -> GitResult:
        """Hard-reset to HEAD and remove untracked files."""
        if not await GitManager.is_git_repository(repo_path):
            logger.warning("Rollback skipped: not a git repository (%s)", repo_path)
            return GitResult(success=True)

        async with GitManager._git_lock:
            changed = await GitManager._get_changed_files(repo_path)
            await GitManager._run_git(repo_path, "reset", "--hard", "HEAD")
            await GitManager._run_git(repo_path, "clean", "-fd")

        _log_change_summary(changed, f"Rollback ({reason})")
        logger.info("Rollback completed: %s", reason)
        return GitResult(success=True, changed_files=changed)

    @staticmethod
    async def get_commit_hash(repo_path: Path) -> str | None:
        """Return the current HEAD commit hash, or *None* on failure."""
        try:
            result = await GitManager._run_git(repo_path, "rev-parse", "HEAD")
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return None

    @staticmethod
    async def get_completed_agents(repo_path: Path) -> set[str]:
        """Return agent names that have a `deliverable: {name}` commit in git log.

        Non-git repos return an empty set. Used by resume to derive the
        authoritative 'completed' signal (G).
        """
        if not await GitManager.is_git_repository(repo_path):
            return set()
        result = await GitManager._run_git(
            repo_path, "log", "--pretty=format:%s", "--grep=^deliverable:",
        )
        if result.returncode != 0:
            return set()
        completed: set[str] = set()
        prefix = "deliverable:"
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith(prefix):
                completed.add(line[len(prefix):].strip())
        return completed

    @staticmethod
    async def execute_with_retry(
        repo_path: Path,
        *args: str,
        description: str = "",
        max_retries: int = 5,
    ) -> subprocess.CompletedProcess:
        """Execute an arbitrary git command with lock-conflict retry."""
        return await GitManager._run_git_with_retry(
            repo_path,
            *args,
            max_retries=max_retries,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    async def _run_git(repo_path: Path, *args: str) -> subprocess.CompletedProcess:
        """Execute a single git command via asyncio subprocess."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "git", *args,
                cwd=str(repo_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_bytes, stderr_bytes = await proc.communicate()
            return subprocess.CompletedProcess(
                args=["git", *args],
                returncode=proc.returncode or 0,
                stdout=stdout_bytes.decode().strip(),
                stderr=stderr_bytes.decode().strip(),
            )
        except FileNotFoundError:
            raise PentestError(
                "git not found in PATH",
                "infrastructure",
                error_code=ErrorCode.GIT_CHECKPOINT_FAILED,
            )

    @staticmethod
    async def _run_git_with_retry(
        repo_path: Path,
        *args: str,
        max_retries: int = 5,
    ) -> subprocess.CompletedProcess:
        """Run git with exponential backoff on lock errors."""
        result = await GitManager._run_git(repo_path, *args)
        for attempt in range(max_retries):
            if result.returncode == 0:
                return result
            if not _is_git_lock_error(result.stderr):
                return result
            delay = 2 ** attempt * 0.5
            logger.warning(
                "Git lock conflict on '%s', retrying in %.1fs (attempt %d/%d)",
                " ".join(args), delay, attempt + 1, max_retries,
            )
            await asyncio.sleep(delay)
            result = await GitManager._run_git(repo_path, *args)
        return result

    @staticmethod
    async def _get_changed_files(repo_path: Path) -> list[str]:
        """Return a list of changed file entries from ``git status --porcelain``."""
        result = await GitManager._run_git(repo_path, "status", "--porcelain")
        if result.returncode != 0:
            return []
        lines = result.stdout.strip().split("\n")
        return [line.strip() for line in lines if line.strip()]
