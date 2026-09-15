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
    """超 500 条 / 空列表 → ValueError（端点转 422）；51 条（旧上限+1）不再被拒。"""
    rm = _rm(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="不能为空"):
        await rm.clone_batch(WS, [])
    with pytest.raises(ValueError, match="500"):
        await rm.clone_batch(WS, [f"https://gitlab.example/r{i}.git" for i in range(501)])
    # 2026-09-15 上限 50→500：51 条（旧上限+1）应正常受理——mock clone 免真克隆
    async def _fake_clone(ws, url, branch, commit, name, group):
        return f"r{url}"
    monkeypatch.setattr(rm, "clone", _fake_clone)
    r = await rm.clone_batch(WS, [f"https://gitlab.example/r{i}.git" for i in range(51)])
    assert len(r["submitted"]) == 51
