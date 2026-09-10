import asyncio
import subprocess

import pytest
from pathlib import Path

from supernova_core.git_manager import GitManager
from supernova_core.models.errors import PentestError
from supernova_core.models.result import GitResult


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    """Create a minimal git repository with one initial commit."""
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, capture_output=True, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@test.com"],
        cwd=repo, capture_output=True, check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test"],
        cwd=repo, capture_output=True, check=True,
    )
    (repo / "initial.txt").write_text("initial")
    subprocess.run(["git", "add", "."], cwd=repo, capture_output=True, check=True)
    subprocess.run(
        ["git", "commit", "-m", "initial"],
        cwd=repo, capture_output=True, check=True,
    )
    return repo


# ---- is_git_repository ----


async def test_is_git_repository_true(git_repo: Path):
    assert await GitManager.is_git_repository(git_repo) is True


async def test_is_git_repository_false(tmp_path: Path):
    non_repo = tmp_path / "not-a-repo"
    non_repo.mkdir()
    assert await GitManager.is_git_repository(non_repo) is False


# ---- get_commit_hash ----


async def test_get_commit_hash(git_repo: Path):
    h = await GitManager.get_commit_hash(git_repo)
    assert h is not None
    assert len(h) == 40


async def test_get_commit_hash_non_repo(tmp_path: Path):
    h = await GitManager.get_commit_hash(tmp_path / "nonexistent")
    assert h is None


# ---- create_checkpoint ----


async def test_create_checkpoint_attempt1(git_repo: Path):
    result = await GitManager.create_checkpoint(git_repo, "pre-recon", attempt=1)
    assert result.success is True


async def test_create_checkpoint_attempt1_preserves_files(git_repo: Path):
    """On first attempt, existing uncommitted files should be preserved in the checkpoint."""
    (git_repo / "existing.txt").write_text("kept")
    await GitManager.create_checkpoint(git_repo, "pre-recon", attempt=1)
    assert (git_repo / "existing.txt").exists()
    # The file should be committed in the checkpoint
    log = subprocess.run(
        ["git", "log", "--oneline", "-1"],
        cwd=git_repo, capture_output=True, text=True, check=True,
    )
    assert "checkpoint" in log.stdout


async def test_create_checkpoint_retry_cleans_first(git_repo: Path):
    """On attempt > 1, workspace should be cleaned before checkpoint."""
    (git_repo / "stale.txt").write_text("stale")
    subprocess.run(["git", "add", "."], cwd=git_repo, capture_output=True, check=True)

    result = await GitManager.create_checkpoint(git_repo, "pre-recon", attempt=2)
    assert result.success is True
    assert not (git_repo / "stale.txt").exists()


async def test_create_checkpoint_non_git_dir(tmp_path: Path):
    non_repo = tmp_path / "not-git"
    non_repo.mkdir()
    result = await GitManager.create_checkpoint(non_repo, "agent")
    assert result.success is True
    assert result.changed_files == []


# ---- commit ----


async def test_commit_success(git_repo: Path):
    (git_repo / "deliverable.md").write_text("# Report")
    result = await GitManager.commit(git_repo, "pre-recon")
    assert result.success is True
    assert len(result.changed_files) > 0
    log = subprocess.run(
        ["git", "log", "--oneline", "-1"],
        cwd=git_repo, capture_output=True, text=True, check=True,
    )
    assert "deliverable: pre-recon" in log.stdout


async def test_commit_non_git_dir(tmp_path: Path):
    non_repo = tmp_path / "not-git"
    non_repo.mkdir()
    result = await GitManager.commit(non_repo, "agent")
    assert result.success is True


# ---- rollback ----


async def test_rollback_removes_files(git_repo: Path):
    (git_repo / "bad_file.txt").write_text("bad content")
    subprocess.run(["git", "add", "."], cwd=git_repo, capture_output=True, check=True)
    result = await GitManager.rollback(git_repo, "test failure")
    assert result.success is True
    assert not (git_repo / "bad_file.txt").exists()


async def test_rollback_removes_untracked(git_repo: Path):
    (git_repo / "untracked.txt").write_text("not tracked")
    result = await GitManager.rollback(git_repo, "cleanup")
    assert result.success is True
    assert not (git_repo / "untracked.txt").exists()


async def test_rollback_non_git_dir(tmp_path: Path):
    non_repo = tmp_path / "not-git"
    non_repo.mkdir()
    result = await GitManager.rollback(non_repo, "nothing to do")
    assert result.success is True


async def test_rollback_returns_changed_files(git_repo: Path):
    (git_repo / "file1.txt").write_text("a")
    (git_repo / "file2.txt").write_text("b")
    subprocess.run(["git", "add", "."], cwd=git_repo, capture_output=True, check=True)
    result = await GitManager.rollback(git_repo, "multi-file")
    assert result.success is True
    assert len(result.changed_files) >= 2


# ---- Concurrency ----


async def test_concurrent_checkpoints_serialized(git_repo: Path):
    """Multiple concurrent create_checkpoint calls should not raise lock errors."""
    (git_repo / "concurrent.txt").write_text("data")

    results = await asyncio.gather(
        GitManager.create_checkpoint(git_repo, "agent-a", attempt=1),
        GitManager.create_checkpoint(git_repo, "agent-b", attempt=1),
        GitManager.create_checkpoint(git_repo, "agent-c", attempt=1),
    )
    assert all(r.success for r in results)


# ---- Retry mechanism ----


async def test_retry_on_lock_error(git_repo: Path, monkeypatch):
    """Verify retry is attempted when a lock error occurs."""
    call_count = 0
    original_run_git = GitManager._run_git

    async def mock_run_git(repo_path: Path, *args: str):
        nonlocal call_count
        result = await original_run_git(repo_path, *args)
        # Inject a lock error on the first commit call
        if args and args[0] == "commit":
            call_count += 1
            if call_count == 1:
                result = subprocess.CompletedProcess(
                    args=["git", *args],
                    returncode=1,
                    stdout="",
                    stderr="fatal: Unable to create 'index.lock': File exists.",
                )
        return result

    monkeypatch.setattr(GitManager, "_run_git", staticmethod(mock_run_git))
    # Reset lock for clean state
    GitManager._git_lock = asyncio.Lock()

    result = await GitManager.create_checkpoint(git_repo, "retry-agent")
    assert result.success is True
    assert call_count >= 2  # Initial call + at least 1 retry


# ---- Error handling ----


async def test_create_checkpoint_raises_on_persistent_failure(git_repo: Path, monkeypatch):
    """When git commit keeps failing with non-lock errors, PentestError is raised."""
    async def mock_run_git_with_retry(repo_path: Path, *args: str, max_retries: int = 5):
        return subprocess.CompletedProcess(
            args=["git", *args],
            returncode=1,
            stdout="",
            stderr="some non-lock error",
        )

    monkeypatch.setattr(GitManager, "_run_git_with_retry", staticmethod(mock_run_git_with_retry))

    with pytest.raises(PentestError) as exc_info:
        await GitManager.create_checkpoint(git_repo, "failing-agent")

    assert exc_info.value.error_code is not None
    assert "GIT_CHECKPOINT_FAILED" in str(exc_info.value.error_code)


async def test_commit_raises_on_failure(git_repo: Path, monkeypatch):
    async def mock_run_git_with_retry(repo_path: Path, *args: str, max_retries: int = 5):
        return subprocess.CompletedProcess(
            args=["git", *args],
            returncode=1,
            stdout="",
            stderr="commit error",
        )

    monkeypatch.setattr(GitManager, "_run_git_with_retry", staticmethod(mock_run_git_with_retry))

    with pytest.raises(PentestError) as exc_info:
        await GitManager.commit(git_repo, "failing-agent")

    assert "GIT_CHECKPOINT_FAILED" in str(exc_info.value.error_code)


# ---- execute_with_retry ----


async def test_execute_with_retry_success(git_repo: Path):
    result = await GitManager.execute_with_retry(git_repo, "status", "--porcelain")
    assert result.returncode == 0


# ---- Change tracking ----


async def test_changed_files_tracked_on_commit(git_repo: Path):
    (git_repo / "new_file.py").write_text("print('hello')")
    result = await GitManager.commit(git_repo, "tracker-agent")
    assert result.success
    assert any("new_file.py" in f for f in result.changed_files)


async def test_no_changes_returns_empty_list(git_repo: Path):
    result = await GitManager.commit(git_repo, "no-change-agent")
    assert result.success
    assert result.changed_files == []


# ---- commit_index (protect code_index.json from concurrent agent rollback) ----


@pytest.mark.asyncio
async def test_commit_index_protects_files_from_rollback(tmp_path: Path):
    """run_code_index 的产物必须能挺过并发 agent 失败时的 rollback(clean -fd)。

    固化生产 bug: code_index.json 作为未跟踪文件,被并发 pre-recon agent 的
    rollback(clean -fd)清掉;而 run_code_index 已成功、不在重试循环里,文件永不
    重生 → run_entry_point_fusion 硬报 FileNotFoundError。
    """
    deliverables = tmp_path / "deliverables"
    deliverables.mkdir()
    (deliverables / "code_index.json").write_text('{"blocks": []}')
    (deliverables / "code_index_summary.md").write_text("# code index")

    await GitManager.ensure_repository(deliverables)
    await GitManager.commit_index(deliverables)  # 提交为跟踪文件

    # 模拟并发 pre-recon agent 失败 → rollback(reset --hard + clean -fd)
    await GitManager.rollback(deliverables, "simulated pre-recon failure")

    assert (deliverables / "code_index.json").exists()
    assert (deliverables / "code_index_summary.md").exists()


@pytest.mark.asyncio
async def test_commit_index_uses_index_prefix_not_deliverable(tmp_path: Path):
    """commit_index 用 'index:' 前缀,避免 get_completed_agents 把 code-index
    误当已完成 agent(污染 resume 的跳过守卫)。"""
    deliverables = tmp_path / "deliverables"
    deliverables.mkdir()
    (deliverables / "code_index.json").write_text('{}')

    await GitManager.ensure_repository(deliverables)
    await GitManager.commit_index(deliverables)

    completed = await GitManager.get_completed_agents(deliverables)
    assert "code-index" not in completed
    assert "code_index" not in completed


@pytest.mark.asyncio
async def test_commit_index_protects_intermediate_dir_from_rollback(tmp_path: Path):
    """tiering 后中间产物落 intermediate/（整个目录未跟踪）→ commit_index 必须把
    整个目录提交为跟踪，挺过并发 agent 失败时的 rollback(clean -fd)。固化根因 2：
    曾只 add 平铺 code_index.json，intermediate/ 未跟踪 → rollback 清光（含
    parameter_graph.json 等）→ run_code_index 不在重试循环、永不重生。"""
    deliverables = tmp_path / "deliverables"
    deliverables.mkdir()
    (deliverables / "intermediate").mkdir()
    (deliverables / "intermediate" / "code_index.json").write_text('{"blocks": []}')
    (deliverables / "intermediate" / "parameter_graph.json").write_text('{"nodes": []}')

    await GitManager.ensure_repository(deliverables)
    await GitManager.commit_index(deliverables)  # add 整个 intermediate/ 并提交

    # 模拟并发 pre-recon agent 失败 → rollback(reset --hard + clean -fd)
    await GitManager.rollback(deliverables, "simulated pre-recon failure")

    assert (deliverables / "intermediate" / "code_index.json").exists()
    assert (deliverables / "intermediate" / "parameter_graph.json").exists()


# ---- ensure_repository ----


@pytest.mark.asyncio
async def test_ensure_repository_inits_new_repo(tmp_path: Path):
    """deliverables 无 .git 时,ensure_repository 建 .git + 首次 commit。"""
    deliverables = tmp_path / "deliverables"
    deliverables.mkdir()

    result = await GitManager.ensure_repository(deliverables)

    assert result.success is True
    assert (deliverables / ".git").exists()  # .git 直接在 deliverables 内
    # 首次 commit 存在
    log = subprocess.run(
        ["git", "log", "--oneline"], cwd=deliverables, capture_output=True, text=True,
    )
    assert "Initial deliverables checkpoint" in log.stdout


@pytest.mark.asyncio
async def test_ensure_repository_idempotent(tmp_path: Path):
    """deliverables 已有 .git 时,ensure_repository 幂等跳过(不重复 init/commit)。"""
    deliverables = tmp_path / "deliverables"
    deliverables.mkdir()
    await GitManager.ensure_repository(deliverables)
    head_before = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=deliverables, capture_output=True, text=True,
    ).stdout.strip()

    result = await GitManager.ensure_repository(deliverables)  # 二次调用

    assert result.success is True
    head_after = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=deliverables, capture_output=True, text=True,
    ).stdout.strip()
    assert head_before == head_after  # HEAD 不变(未新增 commit)


@pytest.mark.asyncio
async def test_ensure_repository_holds_git_lock(tmp_path: Path, monkeypatch):
    """ensure_repository 的 init+initial commit 必须全程持 _git_lock。

    固化生产 bug(2026-09-10 cross-repo-20260910-054739):多个 edge agent 并发
    execute 时,首个协程的 ensure_repository initial commit(曾不持锁)与第二个
    协程的 create_checkpoint commit(持锁)在 git 层并发——输家读到 unborn HEAD
    走 create 语义,ref 阶段撞上赢家已建的 refs/heads/master →
    "fatal: cannot lock ref 'HEAD': reference already exists" → 该 edge fail。
    """
    deliverables = tmp_path / "deliverables"
    deliverables.mkdir()
    original = GitManager._run_git
    lock_states: list[bool] = []

    async def spy_run_git(repo_path: Path, *args: str):
        lock_states.append(GitManager._git_lock.locked())
        return await original(repo_path, *args)

    monkeypatch.setattr(GitManager, "_run_git", staticmethod(spy_run_git))

    await GitManager.ensure_repository(deliverables)

    assert lock_states, "ensure_repository should run git commands on init path"
    assert all(lock_states), (
        f"git commands ran without holding _git_lock: {lock_states}"
    )


@pytest.mark.asyncio
async def test_cannot_lock_ref_text_recognized_as_lock_error():
    """'cannot lock ref' 文本本质是锁冲突(并发 create 同一 ref),必须进重试名单。

    固化生产 bug:该文本曾不在 _GIT_LOCK_PATTERNS → 不重试直接 PentestError。
    重试即可自愈——第二次跑时 ref 已存在,走 update 语义成功。
    """
    from supernova_core.git_manager import _is_git_lock_error

    assert _is_git_lock_error(
        "fatal: cannot lock ref 'HEAD': reference already exists"
    )


@pytest.mark.asyncio
async def test_retry_on_cannot_lock_ref_error(git_repo: Path, monkeypatch):
    """cannot lock ref 错误须触发重试(对齐 test_retry_on_lock_error 的注入模式)。"""
    call_count = 0
    original_run_git = GitManager._run_git

    async def mock_run_git(repo_path: Path, *args: str):
        nonlocal call_count
        result = await original_run_git(repo_path, *args)
        if args and args[0] == "commit":
            call_count += 1
            if call_count == 1:
                result = subprocess.CompletedProcess(
                    args=["git", *args],
                    returncode=1,
                    stdout="",
                    stderr="fatal: cannot lock ref 'HEAD': reference already exists",
                )
        return result

    monkeypatch.setattr(GitManager, "_run_git", staticmethod(mock_run_git))

    result = await GitManager.create_checkpoint(git_repo, "retry-agent")
    assert result.success is True
    assert call_count >= 2  # Initial call + at least 1 retry


@pytest.mark.asyncio
async def test_ensure_and_checkpoint_concurrent_no_conflict(tmp_path: Path):
    """复刻跨仓首扫时序:ensure_repository 与多个 create_checkpoint 同时 gather。

    修复后 ensure 持锁,三个操作与 checkpoint 串行,不出现 unborn-HEAD 并发
    create ref 竞态(修复前为概率性 git 竞态,非确定性红灯,靠上面的锁观察
    测试锁定根因;此测试做整合护栏)。"""
    deliverables = tmp_path / "deliverables"
    deliverables.mkdir()

    results = await asyncio.gather(
        GitManager.ensure_repository(deliverables),
        GitManager.create_checkpoint(deliverables, "edge-a", attempt=1),
        GitManager.create_checkpoint(deliverables, "edge-b", attempt=1),
    )

    assert all(r.success for r in results)
    # 仓库结构健康:HEAD 可解析、master 存在
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=deliverables, capture_output=True, text=True,
    )
    assert head.returncode == 0


@pytest.mark.asyncio
async def test_ensure_repository_dotgit_is_inside_not_parent(tmp_path: Path):
    """关键:.git 必须直接在 deliverables 内,而非沿用父仓库的 .git(这是原 bug 根源)。"""
    parent = tmp_path / "parent"
    parent.mkdir()
    subprocess.run(["git", "init"], cwd=parent, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "p@p.com"], cwd=parent, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.name", "P"], cwd=parent, capture_output=True, check=True)
    subprocess.run(["git", "commit", "--allow-empty", "-m", "parent-initial"], cwd=parent, capture_output=True, check=True)
    deliverables = parent / "deliverables"  # 嵌套在父仓库内(模拟 workspaces/<session>/deliverables)
    deliverables.mkdir()

    await GitManager.ensure_repository(deliverables)

    assert (deliverables / ".git").exists()  # deliverables 自己的 .git
    # deliverables 的 HEAD 与父仓库不同(独立仓库)
    deliv_head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=deliverables, capture_output=True, text=True,
    ).stdout.strip()
    parent_head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=parent, capture_output=True, text=True,
    ).stdout.strip()
    assert deliv_head != parent_head
