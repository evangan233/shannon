"""clone_batch（批量克隆）组件层测试。

API 契约：``clone_batch(ws, urls, group) -> {"submitted": [name], "queued": [name],
"skipped": [{"url", "reason"}]}``——同步预检（凭据/重名/去重/上限）立即定局，
撞并发上限的剩余条目由后台排队任务逐条补位提交（端点立即返回，不悬挂 HTTP）。
"""

import asyncio
import json
import sys
import textwrap
import pytest
from pathlib import Path
from supernova_web.components.repo_manager import RepoManager


WS = "ws1"


def _rm(tmp_path, monkeypatch) -> RepoManager:
    monkeypatch.setenv("SUPERNOVA_WORKER_ROOT", str(tmp_path))
    monkeypatch.setenv("SUPERNOVA_REPOS_DIR", str(tmp_path / "repos"))
    from supernova_web.config import get_config; get_config.cache_clear()
    from supernova_web.components.git_fetcher import GitFetcher
    cfg = get_config()
    (cfg.workspaces_dir / WS).mkdir(parents=True, exist_ok=True)
    return RepoManager(cfg.workspaces_dir, GitFetcher(cfg.repos_dir, "u", "t"), max_concurrent=3)


def _rm_no_creds(tmp_path, monkeypatch) -> RepoManager:
    monkeypatch.setenv("SUPERNOVA_WORKER_ROOT", str(tmp_path))
    monkeypatch.setenv("SUPERNOVA_REPOS_DIR", str(tmp_path / "repos"))
    from supernova_web.config import get_config; get_config.cache_clear()
    from supernova_web.components.git_fetcher import GitFetcher
    cfg = get_config()
    (cfg.workspaces_dir / WS).mkdir(parents=True, exist_ok=True)
    return RepoManager(cfg.workspaces_dir, GitFetcher(cfg.repos_dir, None, None), max_concurrent=3)


def _repos_base(tmp_path) -> Path:
    return tmp_path / "workspaces" / WS / "repos"


@pytest.fixture
def fake_clone_ok(tmp_path):
    s = tmp_path / "ok.py"
    s.write_text(textwrap.dedent('''
        import sys
        sys.stderr.write("Receiving objects: 40%\\n")
        sys.exit(0)
    '''))
    return s


def _patch_fast_poll(monkeypatch, rm):
    """排队轮询间隔缩到测试可用量级（生产 1s）。"""
    monkeypatch.setattr(rm, "BATCH_SLOT_POLL_S", 0.05)


@pytest.mark.asyncio
async def test_batch_clone_submits_and_skips_existing(tmp_path, monkeypatch, fake_clone_ok):
    """3 条 URL（1 条目录已存在）→ submitted 2 / skipped 1(reason=exists)；group 生效。"""
    rm = _rm(tmp_path, monkeypatch)
    monkeypatch.setattr(rm, "_build_clone_argv",
                        lambda url, target, branch: [sys.executable, str(fake_clone_ok)])
    (_repos_base(tmp_path) / "frontend" / "taken").mkdir(parents=True)

    r = await rm.clone_batch(WS, [
        "https://gitlab.example/foo.git",
        "https://gitlab.example/taken.git",
        "https://gitlab.example/bar.git",
    ], group="frontend")

    assert r["submitted"] == ["frontend/foo", "frontend/bar"]
    assert r["queued"] == []
    assert [s["url"] for s in r["skipped"]] == ["https://gitlab.example/taken.git"]
    assert r["skipped"][0]["reason"] == "exists"

    await asyncio.sleep(0.3)
    for n in ("frontend/foo", "frontend/bar"):
        meta = json.loads((_repos_base(tmp_path) / n / ".supernova-repo.json").read_text())
        assert meta["state"] == "ready"
    assert not (_repos_base(tmp_path) / "frontend" / "taken" / ".supernova-repo.json").exists()


@pytest.mark.asyncio
async def test_batch_clone_no_creds_fail_fast(tmp_path, monkeypatch):
    """凭据缺失 → PermissionError 整批拒绝（端点转 503），不产生任何目录。"""
    rm = _rm_no_creds(tmp_path, monkeypatch)
    with pytest.raises(PermissionError):
        await rm.clone_batch(WS, ["https://gitlab.example/foo.git"])
    assert not (_repos_base(tmp_path) / "foo").exists()


@pytest.mark.asyncio
async def test_batch_clone_queues_when_full(tmp_path, monkeypatch, fake_clone_ok):
    """并发槽满 → 剩余进 queued 立即返回；占位释放后后台任务补位提交成功。"""
    rm = _rm(tmp_path, monkeypatch)
    rm._max_concurrent = 1
    _patch_fast_poll(monkeypatch, rm)
    monkeypatch.setattr(rm, "_build_clone_argv",
                        lambda url, target, branch: [sys.executable, str(fake_clone_ok)])

    # 占位 job：0.3s 后完成并按 _clone_task 同款语义 pop 掉自己的槽位
    async def _placeholder():
        try:
            await asyncio.sleep(0.3)
        finally:
            rm._jobs.pop((WS, "busy"), None)
    rm._jobs[(WS, "busy")] = asyncio.create_task(_placeholder())

    r = await rm.clone_batch(WS, ["https://gitlab.example/foo.git",
                                  "https://gitlab.example/bar.git"])
    assert r["submitted"] == []
    assert set(r["queued"]) == {"foo", "bar"}
    assert r["skipped"] == []

    # 轮询等待两条排队仓库先后提交并 clone 完成（max=1 → 链式等槽）
    for _ in range(60):  # 上限 3s
        await asyncio.sleep(0.05)
        if (_repos_base(tmp_path) / "bar" / ".supernova-repo.json").exists():
            break
    for n in ("foo", "bar"):
        meta = json.loads((_repos_base(tmp_path) / n / ".supernova-repo.json").read_text())
        assert meta["state"] == "ready", n


@pytest.mark.asyncio
async def test_batch_clone_dedup(tmp_path, monkeypatch, fake_clone_ok):
    """重复 URL 去重（保序首条生效），重复条目进 skipped(reason=duplicate)。"""
    rm = _rm(tmp_path, monkeypatch)
    monkeypatch.setattr(rm, "_build_clone_argv",
                        lambda url, target, branch: [sys.executable, str(fake_clone_ok)])
    r = await rm.clone_batch(WS, ["https://gitlab.example/foo.git",
                                  "https://gitlab.example/foo.git"])
    assert r["submitted"] == ["foo"]
    assert r["skipped"] == [{"url": "https://gitlab.example/foo.git", "reason": "duplicate"}]


@pytest.mark.asyncio
async def test_batch_clone_limit_and_empty(tmp_path, monkeypatch):
    """超 50 条 / 空列表 → ValueError（端点转 422）。"""
    rm = _rm(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="不能为空"):
        await rm.clone_batch(WS, [])
    with pytest.raises(ValueError, match="50"):
        await rm.clone_batch(WS, [f"https://gitlab.example/r{i}.git" for i in range(51)])


# ---- 跨分组重复挡板（2026-09-15）----
# 现场：__legacy__ ws 里 2026H2/statement 与顶层 statement 同 URL 各一份（31/79 重复），
# 根因是 clone() 的 exists 挡板按 group/name 完整路径判存在——批量分多次提交时
# 对话框每次重置、第二批漏填分组，同 URL 落到另一路径畅通无阻。批量预检须按
# 「归一 URL 已存在于任意分组/顶层」挡，并报出已存在路径。


def _seed_repo(base: Path, name: str, url: str | None, with_git: bool = True) -> None:
    """预置一个已纳管仓库目录（.git + meta；url=None 模拟 cloning/failed 无 source）。"""
    d = base / name
    d.mkdir(parents=True)
    if with_git:
        (d / ".git").mkdir()
    meta = {"state": "ready"}
    if url:
        meta["source"] = {"kind": "git", "url": url}
    (d / ".supernova-repo.json").write_text(json.dumps(meta))


@pytest.mark.asyncio
async def test_batch_clone_skips_same_url_in_other_group(tmp_path, monkeypatch, fake_clone_ok):
    """同 URL 已在其他分组 ready → skip(exists, existing=分组路径)，不重复克隆。"""
    rm = _rm(tmp_path, monkeypatch)
    monkeypatch.setattr(rm, "_build_clone_argv",
                        lambda url, target, branch: [sys.executable, str(fake_clone_ok)])
    _seed_repo(_repos_base(tmp_path), "g1/foo", "https://gitlab.example/foo.git")

    r = await rm.clone_batch(WS, ["https://gitlab.example/foo.git"])  # 无 group

    assert r["submitted"] == [] and r["queued"] == []
    assert r["skipped"] == [{"url": "https://gitlab.example/foo.git",
                             "reason": "exists", "existing": "g1/foo"}]
    assert not (_repos_base(tmp_path) / "foo").exists()


@pytest.mark.asyncio
async def test_batch_clone_skips_same_name_cloning_in_other_group(tmp_path, monkeypatch, fake_clone_ok):
    """cloning 中（.git 无 meta）同名仓 → 挡（URL 未知，宁挡勿重）。"""
    rm = _rm(tmp_path, monkeypatch)
    monkeypatch.setattr(rm, "_build_clone_argv",
                        lambda url, target, branch: [sys.executable, str(fake_clone_ok)])
    _seed_repo(_repos_base(tmp_path), "g1/bar", None)

    r = await rm.clone_batch(WS, ["https://gitlab.example/bar.git"])

    assert r["submitted"] == []
    assert r["skipped"][0]["reason"] == "exists"
    assert r["skipped"][0]["existing"] == "g1/bar"


@pytest.mark.asyncio
async def test_batch_clone_url_normalization_git_suffix(tmp_path, monkeypatch, fake_clone_ok):
    """同仓两种写法（带/不带 .git 后缀、尾斜杠）→ 归一后挡住（现场 risk_user_side）。"""
    rm = _rm(tmp_path, monkeypatch)
    monkeypatch.setattr(rm, "_build_clone_argv",
                        lambda url, target, branch: [sys.executable, str(fake_clone_ok)])
    # 已存在：meta 里存的是无 .git 后缀写法
    _seed_repo(_repos_base(tmp_path), "g1/qux", "https://gitlab.example/team1/qux")
    # 提交：带 .git 后缀 + 尾斜杠的同一仓库
    r = await rm.clone_batch(WS, ["https://gitlab.example/team1/qux.git/"])

    assert r["submitted"] == []
    assert r["skipped"][0]["reason"] == "exists"
    assert r["skipped"][0]["existing"] == "g1/qux"


@pytest.mark.asyncio
async def test_batch_clone_allows_same_name_different_url(tmp_path, monkeypatch, fake_clone_ok):
    """同名不同 URL（不同远端的两个仓）→ 放行：不是重复下载，两份各有其源。"""
    rm = _rm(tmp_path, monkeypatch)
    monkeypatch.setattr(rm, "_build_clone_argv",
                        lambda url, target, branch: [sys.executable, str(fake_clone_ok)])
    _seed_repo(_repos_base(tmp_path), "g1/baz", "https://gitlab.example/team1/baz.git")

    r = await rm.clone_batch(WS, ["https://gitlab.example/team2/baz.git"])

    assert r["submitted"] == ["baz"] and r["skipped"] == []
    await asyncio.sleep(0.2)
    meta = json.loads((_repos_base(tmp_path) / "baz" / ".supernova-repo.json").read_text())
    assert meta["state"] == "ready"


@pytest.mark.asyncio
async def test_batch_submit_task_rechecks_before_submit(tmp_path, monkeypatch, fake_clone_ok):
    """跨批排队竞态：批 A（group=g1）排队中目录未建、批 B（无 group）同 URL 也排队；
    补位提交前复查挡板 → 磁盘上该 repo_name 只落一份（而非顶层+分组各一份）。"""
    rm = _rm(tmp_path, monkeypatch)
    rm._max_concurrent = 1
    _patch_fast_poll(monkeypatch, rm)
    monkeypatch.setattr(rm, "_build_clone_argv",
                        lambda url, target, branch: [sys.executable, str(fake_clone_ok)])

    # 长占位 job：持有唯一并发槽 0.5s
    async def _placeholder():
        try:
            await asyncio.sleep(0.5)
        finally:
            rm._jobs.pop((WS, "busy"), None)
    rm._jobs[(WS, "busy")] = asyncio.create_task(_placeholder())

    await rm.clone_batch(WS, ["https://gitlab.example/foo.git"], group="g1")
    await rm.clone_batch(WS, ["https://gitlab.example/foo.git"])  # 批 B：无 group

    # 等两个后台补位任务跑完（占位释放后逐条提交）
    for _ in range(100):
        await asyncio.sleep(0.05)
        g1_meta = _repos_base(tmp_path) / "g1" / "foo" / ".supernova-repo.json"
        if g1_meta.exists():
            await asyncio.sleep(0.3)  # 给另一个排队任务留出复查+放弃的时间
            break
    assert g1_meta.exists()
    # 顶层不得出现第二份（批 B 的补位任务复查后放弃该条）
    assert not (_repos_base(tmp_path) / "foo").exists()
