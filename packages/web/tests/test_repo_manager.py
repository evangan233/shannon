import asyncio
import json
import sys
import textwrap
import pytest
from pathlib import Path
from supernova_web.components.repo_manager import RepoManager, TooManyClones


WS = "ws1"  # all tests in this file operate in a single workspace


def _rm(tmp_path, monkeypatch) -> RepoManager:
    # T1 (web repos isolation P2): RepoManager 现按 workspaces/<ws>/repos 分桶。
    # 把 workspaces_dir 设到 tmp_path/workspaces，并预建 ws1，repo 落到其下 repos/。
    monkeypatch.setenv("SUPERNOVA_WORKER_ROOT", str(tmp_path))
    monkeypatch.setenv("SUPERNOVA_REPOS_DIR", str(tmp_path / "repos"))
    from supernova_web.config import get_config; get_config.cache_clear()
    from supernova_web.components.git_fetcher import GitFetcher
    cfg = get_config()
    ws_dir = cfg.workspaces_dir
    (ws_dir / WS).mkdir(parents=True, exist_ok=True)
    return RepoManager(ws_dir, GitFetcher(cfg.repos_dir, "u", "t"), max_concurrent=3)


def _repos_base(tmp_path) -> Path:
    """该 ws 的 repos 根目录：tmp_path/workspaces/ws1/repos。"""
    return tmp_path / "workspaces" / WS / "repos"


@pytest.fixture
def fake_clone_ok(tmp_path):
    """假 git 子进程：写一行 progress 到 stderr 后退出 0。"""
    s = tmp_path / "ok.py"
    s.write_text(textwrap.dedent('''
        import sys
        sys.stderr.write("Receiving objects: 40%\\n")
        sys.exit(0)
    '''))
    return s


@pytest.mark.asyncio
async def test_clone_writes_ndjson_and_meta(tmp_path, monkeypatch, fake_clone_ok):
    rm = _rm(tmp_path, monkeypatch)
    monkeypatch.setattr(rm, "_build_clone_argv",
                        lambda url, target, branch: [sys.executable, str(fake_clone_ok)])
    name = await rm.clone(WS, "https://gitlab.example/foo.git", None, None, None)
    assert name == "foo"
    # 等 task 结束
    await asyncio.sleep(0.3)
    meta = json.loads((_repos_base(tmp_path) / "foo" / ".supernova-repo.json").read_text())
    assert meta["state"] == "ready"
    lines = (_repos_base(tmp_path) / "foo" / "clone.ndjson").read_text().splitlines()
    assert any("40" in l and '"progress"' in l for l in lines)
    assert any('"clone_end"' in l and '"ready"' in l for l in lines)


@pytest.mark.asyncio
async def test_clone_failed_writes_failed_state(tmp_path, monkeypatch):
    crash = tmp_path / "crash.py"
    crash.write_text('import sys; sys.stderr.write("boom https://u:t@host\\n"); sys.exit(1)')
    rm = _rm(tmp_path, monkeypatch)
    monkeypatch.setattr(rm, "_build_clone_argv",
                        lambda url, target, branch: [sys.executable, str(crash)])
    await rm.clone(WS, "https://gitlab.example/foo.git", None, None, None)
    await asyncio.sleep(0.3)
    meta = json.loads((_repos_base(tmp_path) / "foo" / ".supernova-repo.json").read_text())
    assert meta["state"] == "failed"
    assert "t@" not in meta["last_error"]  # token 脱敏（last_error 是固定串，本就行）
    # 真正的安全属性：stderr 的 `https://u:t@host` 经 _git.redact 写进 clone.ndjson 的
    # message 字段，必须脱敏为 `https://***:***@host`，绝不含 `u:t@` token 模式。
    ndjson = (_repos_base(tmp_path) / "foo" / "clone.ndjson").read_text("utf-8", errors="replace")
    assert "u:t@" not in ndjson
    assert "***:***@" in ndjson


@pytest.mark.asyncio
async def test_clone_failure_keeps_request_context_and_stderr(tmp_path, monkeypatch):
    """失败 clone 即使 git 清理 target，也要保留 URL、请求分支、命令和错误尾窗。"""
    crash = tmp_path / "crash-with-detail.py"
    crash.write_text(
        'import sys; sys.stderr.write("fatal: repository not found\\n"); sys.exit(128)'
    )
    rm = _rm(tmp_path, monkeypatch)
    monkeypatch.setattr(rm, "_build_clone_argv",
                        lambda url, target, branch: [sys.executable, str(crash)])
    await rm.clone(WS, "https://gitlab.example/team/foo.git", "develop", None, None)
    await asyncio.sleep(0.3)

    target = _repos_base(tmp_path) / "foo"
    meta = json.loads((target / ".supernova-repo.json").read_text())
    assert meta["state"] == "failed"
    assert meta["source"] == {
        "kind": "git", "url": "https://gitlab.example/team/foo.git",
        "branch": "develop", "commit": None,
    }
    assert meta["clone_request"]["branch"] == "develop"
    assert "https://gitlab.example/team/foo.git" in meta["clone_request"]["command"]
    assert "fatal: repository not found" in meta["last_error"]
    assert "fatal: repository not found" in meta["stderr_tail"]

    events = [json.loads(line) for line in (target / "clone.ndjson").read_text().splitlines()]
    failed = events[-1]
    assert failed["type"] == "clone_end"
    assert failed["source"]["branch"] == "develop"
    assert "fatal: repository not found" in failed["stderr_tail"]


@pytest.mark.asyncio
async def test_clone_rejects_path_traversal_name(tmp_path, monkeypatch):
    """name 含路径分隔符/遍历分量必须 ValueError，防止越界 repos_dir mkdir/clone/rmtree
    （final-review I-6）。

    注：name=None 走 repo_name(url) 派生路径（合法，不进 _validate_repo_name），
    故只测显式传非法名的情形。
    """
    rm = _rm(tmp_path, monkeypatch)
    # 防御：若校验被绕过，绝不能真起 git clone 子进程（会挂）
    def _no_real_clone(*a, **kw):
        raise AssertionError("validation should block before _build_clone_argv")
    monkeypatch.setattr(rm, "_build_clone_argv", _no_real_clone)
    for evil in ("../evil", "a/b", ".", "..", "x\\y", "x/y"):
        with pytest.raises(ValueError, match="非法仓库名"):
            await rm.clone(WS, "https://gitlab.example/foo.git", None, None, evil)


@pytest.mark.asyncio
async def test_name_conflict_raises(tmp_path, monkeypatch):
    rm = _rm(tmp_path, monkeypatch)
    (_repos_base(tmp_path) / "foo").mkdir(parents=True)
    with pytest.raises(ValueError, match="已存在"):
        await rm.clone(WS, "https://gitlab.example/foo.git", None, None, None)


@pytest.mark.asyncio
async def test_concurrent_limit(tmp_path, monkeypatch):
    rm = _rm(tmp_path, monkeypatch)
    # Plan-internal deviation: brief's clone() guard is `len(self._jobs) >= self._max_concurrent`.
    # _rm hardcodes max_concurrent=3, so override to 1 to make len(_jobs)=1 trigger the raise.
    rm._max_concurrent = 1
    rm._sem = asyncio.Semaphore(1)  # secondary backstop (harmless)
    rm._jobs[(WS, "busy")] = asyncio.create_task(asyncio.sleep(10))
    with pytest.raises(TooManyClones):
        await rm.clone(WS, "https://gitlab.example/bar.git", None, None, None)


@pytest.mark.asyncio
async def test_clone_with_group(tmp_path, monkeypatch, fake_clone_ok):
    """clone(group=...) 落到 repos/<group>/<name>，返回 group/repo 名。"""
    rm = _rm(tmp_path, monkeypatch)
    monkeypatch.setattr(rm, "_build_clone_argv",
                        lambda url, target, branch: [sys.executable, str(fake_clone_ok)])
    name = await rm.clone(WS, "https://gitlab.example/foo.git", None, None, None, group="frontend")
    assert name == "frontend/foo"
    await asyncio.sleep(0.3)
    meta_path = _repos_base(tmp_path) / "frontend" / "foo" / ".supernova-repo.json"
    assert meta_path.exists()
    assert json.loads(meta_path.read_text())["state"] == "ready"


@pytest.mark.asyncio
async def test_clone_real_git_succeeds(tmp_path, monkeypatch):
    """真 git clone（非 mock _build_clone_argv）：clone 本地 bare 仓库到 target 必须成功。

    回归：旧版 clone() 在 git clone 之前先 ``target.mkdir`` 并在 target 内预写
    ``.supernova-repo.json``，使 target 非空，git clone 报
    ``destination path ... already exists and is not an empty directory``（rc=128）→ state=failed。
    现有测试全部 mock 掉 _build_clone_argv（假脚本不检查目录是否非空），漏掉了 git
    「目标目录必须不存在或完全为空」的硬约束——此测试用真 git 覆盖该约束。
    """
    import subprocess
    # 造一个本地 bare 源仓库并塞一个 commit（file:// 无需凭据，绕开 _inject_auth）
    origin = tmp_path / "origin.git"
    subprocess.run(["git", "init", "--bare", "-b", "main", str(origin)],
                   check=True, capture_output=True)
    work = tmp_path / "work"
    subprocess.run(["git", "clone", "-q", str(origin), str(work)],
                   check=True, capture_output=True)
    subprocess.run(["git", "-C", str(work), "config", "user.email", "t@t.t"], check=True)
    subprocess.run(["git", "-C", str(work), "config", "user.name", "t"], check=True)
    (work / "README.md").write_text("hello")
    subprocess.run(["git", "-C", str(work), "add", "."], check=True)
    subprocess.run(["git", "-C", str(work), "commit", "-qm", "init"], check=True)
    subprocess.run(["git", "-C", str(work), "push", "-q", "origin", "main"],
                   check=True, capture_output=True)

    rm = _rm(tmp_path, monkeypatch)
    name = await rm.clone(WS, f"file://{origin}", None, None, None)
    assert name == "origin"  # repo_name 取末段 origin.git → origin
    task = rm._jobs.get((WS, name))
    if task is not None:
        await task

    target = _repos_base(tmp_path) / "origin"
    assert (target / ".git").exists(), "git clone 未真正执行（target 缺 .git）"
    assert (target / "README.md").read_text() == "hello"
    meta = json.loads((target / ".supernova-repo.json").read_text())
    assert meta["state"] == "ready", f"clone 失败：last_error={meta.get('last_error')!r}"


def test_list_repos_groups(tmp_path, monkeypatch):
    """分组目录下的真仓库识别为 group/repo；分组目录本身不当仓库；同名跨组不冲突。"""
    rm = _rm(tmp_path, monkeypatch)
    base = _repos_base(tmp_path)
    for rel in ["frontend/foo", "backend/honor", "frontend/honor"]:
        d = base / rel; d.mkdir(parents=True)
        (d / ".git").mkdir()  # 真仓库标志
    (base / "baz").mkdir()
    (base / "baz" / ".git").mkdir()  # 扁平仓库
    views = {r["name"]: r for r in rm.list_repos(WS)}
    assert set(views) == {"frontend/foo", "backend/honor", "frontend/honor", "baz"}
    assert "frontend" not in views and "backend" not in views  # 分组目录不入列
    assert views["frontend/foo"]["group"] == "frontend"
    assert views["baz"]["group"] is None
    # frontend/honor 与 backend/honor 同名跨组共存
    assert "frontend/honor" in views and "backend/honor" in views


def test_get_repo_rejects_group_dir(tmp_path, monkeypatch):
    """get_repo 对分组目录（无 .git 无 meta）返回 None，不当作仓库。"""
    rm = _rm(tmp_path, monkeypatch)
    base = _repos_base(tmp_path)
    (base / "frontend" / "foo").mkdir(parents=True)
    (base / "frontend" / "foo" / ".git").mkdir()
    assert rm.get_repo(WS, "frontend/foo") is not None
    assert rm.get_repo(WS, "frontend") is None  # 分组目录


@pytest.mark.asyncio
async def test_delete_does_not_rmtree_group_dir(tmp_path, monkeypatch):
    """delete 分组目录绝不能 rmtree 子仓库（误删/越界防护）。"""
    rm = _rm(tmp_path, monkeypatch)
    base = _repos_base(tmp_path)
    for rel in ["frontend/foo", "frontend/bar"]:
        d = base / rel; d.mkdir(parents=True)
        (d / ".git").mkdir()
    await rm.delete(WS, "frontend")  # 分组目录：不应删任何子仓库
    assert (base / "frontend" / "foo" / ".git").exists()
    assert (base / "frontend" / "bar" / ".git").exists()


def test_validate_repo_name_allows_group():
    """_validate_repo_name 允许 group/repo，拒多层/遍历/空段/首尾斜杠。"""
    from supernova_web.components.repo_manager import _validate_repo_name
    _validate_repo_name("foo")
    _validate_repo_name("frontend/foo")
    for evil in ("a/b/c", "../evil", "a//b", "/a", "a/", "a/../b", ".", "..", "a\\b"):
        with pytest.raises(ValueError, match="非法"):
            _validate_repo_name(evil)


def test_list_repos_treats_group_dir_with_stale_meta_as_group(tmp_path, monkeypatch):
    """分组目录有残留 .supernova-repo.json（旧版误写）时，list_repos 仍当分组深入一层，
    不把分组目录本身当仓库（回归 2026-07-08 /repos 把分组目录当仓库、真仓库全被吞的 bug）。"""
    rm = _rm(tmp_path, monkeypatch)
    base = _repos_base(tmp_path)
    (base / "frontend" / "foo").mkdir(parents=True)
    (base / "frontend" / "foo" / ".git").mkdir()  # 子仓库
    # 旧版误写到分组目录的脏 meta（kind=unknown，非 clone 产物）
    (base / "frontend" / ".supernova-repo.json").write_text(
        json.dumps({"name": "frontend", "source": {"kind": "unknown"}, "state": "ready"}))
    views = {r["name"]: r for r in rm.list_repos(WS)}
    assert set(views) == {"frontend/foo"}
    assert "frontend" not in views  # 分组目录（即使有脏 meta）不入列
    assert views["frontend/foo"]["group"] == "frontend"


def test_migrate_legacy_cleans_miswritten_group_meta(tmp_path, monkeypatch):
    """migrate_legacy 清理被旧版误写到分组目录的脏 meta（有 meta、无 .git、且含子仓库）。"""
    rm = _rm(tmp_path, monkeypatch)
    base = _repos_base(tmp_path)
    (base / "backend" / "honor").mkdir(parents=True)
    (base / "backend" / "honor" / ".git").mkdir()  # 子仓库
    stale = base / "backend" / ".supernova-repo.json"
    stale.write_text(json.dumps({"name": "backend", "source": {"kind": "unknown"}, "state": "ready"}))
    rm.migrate_legacy(WS)
    assert not stale.exists()  # 脏 meta 被清
    # 子仓库被正常 migrate（补 meta）
    assert (base / "backend" / "honor" / ".supernova-repo.json").exists()


def _make_bare_git(repo: Path, url: str, branch: str) -> None:
    """构造一个"已 clone"仓库目录：含 .git/config(url) + .git/HEAD(ref) 但无 .supernova-repo.json。

    模拟用户在服务运行期间把已 clone 的仓库直接拷进 repos_dir（未走 clone 流程）——
    list_repos 凭 .git 能扫到，但 _read_meta 找不到 meta 返回兜底（无 url/branch/size）。
    """
    g = repo / ".git"
    g.mkdir(parents=True)
    (g / "config").write_text(f'[remote "origin"]\n\turl = {url}\n')
    (g / "HEAD").write_text(f"ref: refs/heads/{branch}\n")


def test_list_repos_self_heals_runtime_copied_repo(tmp_path, monkeypatch):
    """运行期拷入的仓库（有 .git 无 .supernova-repo.json）经 list_repos 自愈补 meta：
    来源/分支从 .git 推断、size_bytes 落盘，刷新页面即恢复三列数据（回归 2026-07-13
    /repos 的 vuln-range 下拷入仓库三列全空的 bug）。"""
    rm = _rm(tmp_path, monkeypatch)
    base = _repos_base(tmp_path)
    _make_bare_git(base / "vuln-range" / "NodeGoat", "https://x/NodeGoat.git", "main")
    views = {r["name"]: r for r in rm.list_repos(WS)}
    v = views["vuln-range/NodeGoat"]
    assert v["source"]["url"] == "https://x/NodeGoat.git"
    assert v["source"]["branch"] == "main"
    assert isinstance(v["size_bytes"], int)
    # 自愈落盘 meta（后续刷新不再重算）
    assert (base / "vuln-range" / "NodeGoat" / ".supernova-repo.json").exists()


def test_migrate_legacy_writes_size_bytes(tmp_path, monkeypatch):
    """migrate_legacy 补 meta 时计算 size_bytes（迁移入库的旧仓库大小列不再恒空）。"""
    rm = _rm(tmp_path, monkeypatch)
    base = _repos_base(tmp_path)
    repo = base / "solo"
    _make_bare_git(repo, "https://x/solo.git", "dev")
    (repo / "README.md").write_text("hello")  # 占位文件让 size > 0
    rm.migrate_legacy(WS)
    meta = json.loads((repo / ".supernova-repo.json").read_text())
    assert meta["source"]["url"] == "https://x/solo.git"
    assert meta["source"]["branch"] == "dev"
    assert isinstance(meta["size_bytes"], int) and meta["size_bytes"] > 0


# ---- source.url 凭据脱敏（GitLab token 泄露安全修复）----
# 泄露路径：带凭据的 clone URL（https://oauth2:TOKEN@host 或 _inject_auth 注入的
# USER:TOKEN@）会原样落盘 .supernova-repo.json 的 source.url，并经 _repo_view 透传给
# /api/repos 返回前端。这些测试锁定：落盘前 + 出站前都必须剥离 userinfo。

def test_strip_credentials():
    """strip_credentials 剥离 URL userinfo（username/password），保留 host/port/path/query。"""
    from supernova_web.components.git_fetcher import strip_credentials
    # 标准带凭据 https
    assert strip_credentials("https://oauth2:glpat-xyz@gitlab.example/foo.git") == \
        "https://gitlab.example/foo.git"
    # 带 port + query + fragment
    assert strip_credentials("https://u:p@host:8080/a/b?x=1#frag") == "https://host:8080/a/b?x=1#frag"
    # 仅 username 无 password
    assert strip_credentials("https://u@host/p") == "https://host/p"
    # 无凭据原样返回（不重建、不改动）
    assert strip_credentials("https://gitlab.example/foo.git") == "https://gitlab.example/foo.git"
    # 非 http(s) 不动（SSH git@host:path 等）
    assert strip_credentials("git@gitlab.example:foo.git") == "git@gitlab.example:foo.git"
    # 空值
    assert strip_credentials(None) is None
    assert strip_credentials("") == ""


@pytest.mark.asyncio
async def test_clone_strips_credentials_from_source_url(tmp_path, monkeypatch, fake_clone_ok):
    """clone 带凭据的 URL：落盘 meta 与 get_repo 出站的 source.url 都须剥离 token。"""
    rm = _rm(tmp_path, monkeypatch)
    monkeypatch.setattr(rm, "_build_clone_argv",
                        lambda url, target, branch: [sys.executable, str(fake_clone_ok)])
    secret = "https://oauth2:glpat-LEAK-TOKEN@gitlab.example/foo.git"
    await rm.clone(WS, secret, None, None, None)
    await asyncio.sleep(0.3)
    # 落盘 meta 不含 token
    meta = json.loads((_repos_base(tmp_path) / "foo" / ".supernova-repo.json").read_text())
    assert "glpat-LEAK-TOKEN" not in json.dumps(meta)
    assert meta["source"]["url"] == "https://gitlab.example/foo.git"
    # 出站（get_repo）也不含 token
    view = rm.get_repo(WS, "foo")
    assert "glpat-LEAK-TOKEN" not in json.dumps(view)
    assert view["source"]["url"] == "https://gitlab.example/foo.git"


def test_get_repo_redacts_credentials_in_legacy_meta(tmp_path, monkeypatch):
    """旧 meta 已含带凭据的 source.url（历史/手动写入）：get_repo 出站兜底仍须剥离。"""
    rm = _rm(tmp_path, monkeypatch)
    base = _repos_base(tmp_path)
    d = base / "foo"
    d.mkdir(parents=True)
    (d / ".git").mkdir()
    (d / ".supernova-repo.json").write_text(json.dumps({
        "name": "foo",
        "source": {"kind": "git", "url": "https://oauth2:glpat-LEGACY-LEAK@gitlab.example/foo.git"},
        "state": "ready",
    }))
    view = rm.get_repo(WS, "foo")
    assert "glpat-LEGACY-LEAK" not in json.dumps(view)
    assert view["source"]["url"] == "https://gitlab.example/foo.git"


def test_list_repos_redacts_credentials(tmp_path, monkeypatch):
    """list_repos 出站清洗带凭据的 source.url（_repo_view 是共同出口）。"""
    rm = _rm(tmp_path, monkeypatch)
    base = _repos_base(tmp_path)
    d = base / "foo"
    d.mkdir(parents=True)
    (d / ".git").mkdir()
    (d / ".supernova-repo.json").write_text(json.dumps({
        "name": "foo",
        "source": {"kind": "git", "url": "https://oauth2:glpat-LIST-LEAK@gitlab.example/foo.git"},
        "state": "ready",
    }))
    blob = json.dumps(rm.list_repos(WS))
    assert "glpat-LIST-LEAK" not in blob


def test_migrate_strips_credentials_from_git_config(tmp_path, monkeypatch):
    """migrate_legacy 从 .git/config 读回带凭据 url（_inject_auth 注入污染）：落盘须剥离。"""
    rm = _rm(tmp_path, monkeypatch)
    base = _repos_base(tmp_path)
    d = base / "foo"
    d.mkdir(parents=True)
    gitcfg = d / ".git"
    gitcfg.mkdir()
    # _inject_auth 注入后 git 写入 config 的带凭据 url
    (gitcfg / "config").write_text(
        '[remote "origin"]\n\turl = https://u:glpat-MIGRATE-LEAK@gitlab.example/foo.git\n')
    (gitcfg / "HEAD").write_text("ref: refs/heads/main\n")
    rm.migrate_legacy(WS)
    meta = json.loads((d / ".supernova-repo.json").read_text())
    assert "glpat-MIGRATE-LEAK" not in json.dumps(meta)
    assert meta["source"]["url"] == "https://gitlab.example/foo.git"


# ---- 关联仓库（linked repos）：admin 按绝对路径关联已存在目录，多 ws 可共享 ----

def _make_real_repo(tmp_path, name="real-repo") -> Path:
    """构造一个真实可被关联的目录（含 .git 以测分支推断；非必须）。"""
    d = tmp_path / "external" / name
    d.mkdir(parents=True)
    (d / ".git").mkdir()
    (d / ".git" / "config").write_text('[remote "origin"]\n\turl = https://x/foo.git\n')
    (d / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (d / "README.md").write_text("hi")
    return d


def _ws_dir(tmp_path) -> Path:
    return tmp_path / "workspaces" / WS


def test_link_repo_writes_linked_repos_json(tmp_path, monkeypatch):
    rm = _rm(tmp_path, monkeypatch)
    target = _make_real_repo(tmp_path)
    view = rm.link_repo(WS, "ftoa", str(target))
    assert view["name"] == "ftoa"
    assert view["linked"] is True
    assert view["source"]["kind"] == "linked"
    # git 目录推断出 branch
    assert view["source"]["branch"] == "main"
    data = json.loads((_ws_dir(tmp_path) / "linked_repos.json").read_text())
    assert data["links"] == [
        {"name": "ftoa", "path": str(target), "linked_at": view["cloned_at"]}]


def test_link_repo_rejects_missing_path(tmp_path, monkeypatch):
    rm = _rm(tmp_path, monkeypatch)
    with pytest.raises(ValueError):
        rm.link_repo(WS, "ftoa", str(tmp_path / "nope"))


def test_link_repo_rejects_file_path(tmp_path, monkeypatch):
    rm = _rm(tmp_path, monkeypatch)
    f = tmp_path / "afile"
    f.write_text("x")
    with pytest.raises(ValueError):
        rm.link_repo(WS, "ftoa", str(f))


def test_link_repo_rejects_bad_name(tmp_path, monkeypatch):
    rm = _rm(tmp_path, monkeypatch)
    target = _make_real_repo(tmp_path)
    for evil in ("../x", "a/b/c", "..", "."):
        with pytest.raises(ValueError, match="非法"):
            rm.link_repo(WS, evil, str(target))


def test_link_repo_collision_with_clone_raises_repoexists(tmp_path, monkeypatch):
    from supernova_web.components.repo_manager import RepoExists
    rm = _rm(tmp_path, monkeypatch)
    d = _repos_base(tmp_path) / "foo"
    d.mkdir(parents=True)
    (d / ".git").mkdir()
    target = _make_real_repo(tmp_path)
    with pytest.raises(RepoExists):
        rm.link_repo(WS, "foo", str(target))


def test_link_repo_duplicate_name_raises_repoexists(tmp_path, monkeypatch):
    from supernova_web.components.repo_manager import RepoExists
    rm = _rm(tmp_path, monkeypatch)
    target = _make_real_repo(tmp_path)
    rm.link_repo(WS, "ftoa", str(target))
    with pytest.raises(RepoExists):
        rm.link_repo(WS, "ftoa", str(target))


def test_resolve_linked_repo_path_hits_and_misses(tmp_path, monkeypatch):
    from supernova_web.components.repo_manager import resolve_linked_repo_path
    rm = _rm(tmp_path, monkeypatch)
    target = _make_real_repo(tmp_path)
    rm.link_repo(WS, "ftoa", str(target))
    workspaces_dir = tmp_path / "workspaces"
    assert resolve_linked_repo_path(workspaces_dir, WS, "ftoa") == str(target)
    assert resolve_linked_repo_path(workspaces_dir, WS, "nope") is None


def test_read_linked_repos_corrupt_degrades_to_empty(tmp_path, monkeypatch):
    from supernova_web.components.repo_manager import read_linked_repos
    _rm(tmp_path, monkeypatch)
    (_ws_dir(tmp_path) / "linked_repos.json").write_text("{ broken json")
    assert read_linked_repos(_ws_dir(tmp_path)) == []


# ---- 关联仓库 checkout / pull / branches（spec 2026-09-04：admin-only 可写）----

def _real_work_repo(p: Path) -> Path:
    """真 git 工作仓（非假 .git 标志）：main/dev 两分支内容不同，bare origin 作 remote。"""
    import subprocess
    origin = p.parent / (p.name + ".origin.git")
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(origin)], check=True)
    subprocess.run(["git", "clone", "-q", str(origin), str(p)], check=True)
    subprocess.run(["git", "-C", str(p), "config", "user.email", "t@t.t"], check=True)
    subprocess.run(["git", "-C", str(p), "config", "user.name", "t"], check=True)
    (p / "README.md").write_text("main content")
    subprocess.run(["git", "-C", str(p), "add", "."], check=True)
    subprocess.run(["git", "-C", str(p), "commit", "-qm", "init"], check=True)
    subprocess.run(["git", "-C", str(p), "push", "-q", "origin", "main"], check=True)
    subprocess.run(["git", "-C", str(p), "checkout", "-qb", "dev"], check=True)
    (p / "README.md").write_text("dev content")
    subprocess.run(["git", "-C", str(p), "add", "."], check=True)
    subprocess.run(["git", "-C", str(p), "commit", "-qm", "dev"], check=True)
    subprocess.run(["git", "-C", str(p), "push", "-q", "origin", "dev"], check=True)
    subprocess.run(["git", "-C", str(p), "checkout", "-q", "main"], check=True)
    return p


def _link_real_repo(tmp_path, monkeypatch, name="shared"):
    rm = _rm(tmp_path, monkeypatch)
    target = _real_work_repo(tmp_path / "external" / name)
    rm.link_repo(WS, name, str(target))
    return rm, target


@pytest.mark.asyncio
async def test_checkout_linked_switches_branch_without_writing_meta(tmp_path, monkeypatch):
    """spec §4.2：linked checkout 直接切目标目录分支（跳过 fetch），共享目录零写入。"""
    rm, target = _link_real_repo(tmp_path, monkeypatch)
    await rm.checkout(WS, "shared", "dev")
    assert "dev content" in (target / "README.md").read_text()
    # 共享目录零写入：不落 meta / events（spec §7 不变量）
    assert not (target / ".supernova-repo.json").exists()
    assert not (target / "clone.ndjson").exists()
    # linked view 每次现读 .git → branch=dev
    view = rm.get_repo(WS, "shared")
    assert view["source"]["branch"] == "dev"


@pytest.mark.asyncio
async def test_checkout_linked_dirty_reports_git_message(tmp_path, monkeypatch):
    """spec §4.2：dirty 工作树 checkout 被拒时如实带 git 原文（不再误报「分支不存在」）。"""
    rm, target = _link_real_repo(tmp_path, monkeypatch)
    (target / "README.md").write_text("uncommitted local work")  # 与 dev 冲突的未提交改动
    with pytest.raises(ValueError, match="本地有未提交改动") as excinfo:
        await rm.checkout(WS, "shared", "dev")
    assert "README.md" in str(excinfo.value)  # git 原文摘要在消息里


@pytest.mark.asyncio
async def test_checkout_linked_missing_branch_raises(tmp_path, monkeypatch):
    """spec §4.2：分支（本地与 remotes 皆无）不存在 → ValueError（端点映射 422）。"""
    rm, target = _link_real_repo(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="分支不存在"):
        await rm.checkout(WS, "shared", "no-such-branch")


@pytest.mark.asyncio
async def test_pull_linked_updates_worktree_synchronously(tmp_path, monkeypatch):
    """spec §4.3：linked pull 同步 --ff-only——await 返回即完成（非私有仓的 202 后台
    模式），共享目录零写入（不落 meta / events）。"""
    import subprocess
    rm, target = _link_real_repo(tmp_path, monkeypatch)
    # origin 侧追加一个 commit（helper 克隆 → commit → push）
    origin = tmp_path / "external" / "shared.origin.git"
    helper = tmp_path / "external" / "helper"
    subprocess.run(["git", "clone", "-q", str(origin), str(helper)], check=True)
    subprocess.run(["git", "-C", str(helper), "config", "user.email", "t@t.t"], check=True)
    subprocess.run(["git", "-C", str(helper), "config", "user.name", "t"], check=True)
    (helper / "README.md").write_text("main content v2")
    subprocess.run(["git", "-C", str(helper), "add", "."], check=True)
    subprocess.run(["git", "-C", str(helper), "commit", "-qm", "v2"], check=True)
    subprocess.run(["git", "-C", str(helper), "push", "-q", "origin", "main"], check=True)
    await rm.pull(WS, "shared")
    # 同步语义：await 返回时工作树已更新
    assert "main content v2" in (target / "README.md").read_text()
    # 共享目录零写入（spec §7 不变量）
    assert not (target / ".supernova-repo.json").exists()
    assert not (target / "clone.ndjson").exists()


@pytest.mark.asyncio
async def test_list_branches_linked_merges_heads_and_remotes(tmp_path, monkeypatch):
    """spec §4.4：linked 分支列表 = refs/heads ∪ refs/remotes/origin（strip 前缀去重、
    本地名优先）——pull 后新分支只在 remotes，不合并则下拉看不到。"""
    import subprocess
    rm, target = _link_real_repo(tmp_path, monkeypatch)
    # 造仅存在于远端的分支：helper 建并 push，shared 不 fetch
    origin = tmp_path / "external" / "shared.origin.git"
    helper = tmp_path / "external" / "helper"
    subprocess.run(["git", "clone", "-q", str(origin), str(helper)], check=True)
    subprocess.run(["git", "-C", str(helper), "config", "user.email", "t@t.t"], check=True)
    subprocess.run(["git", "-C", str(helper), "config", "user.name", "t"], check=True)
    subprocess.run(["git", "-C", str(helper), "checkout", "-qb", "feature"], check=True)
    subprocess.run(["git", "-C", str(helper), "push", "-q", "origin", "feature"], check=True)
    # spec §5.4 闭环：pull（隐含 fetch）后 origin/feature 才落 refs/remotes
    await rm.pull(WS, "shared")
    branches = await rm.list_branches(WS, "shared")
    assert "main" in branches and "dev" in branches   # 本地 heads
    assert "feature" in branches                       # pull 后仅存于 remotes 的新分支
    assert "origin/feature" not in branches            # 去前缀、无重复
    # spec §4.2 DWIM：仅 remotes 有的分支可直接 checkout（git 自动建本地跟踪分支）
    await rm.checkout(WS, "shared", "feature")
    assert (target / ".git" / "refs" / "heads" / "feature").exists()


@pytest.mark.asyncio
async def test_linked_git_subprocess_disables_terminal_prompt(tmp_path, monkeypatch):
    """spec §4.5 安全护栏：linked 的 git 子进程必须带 GIT_TERMINAL_PROMPT=0——
    .git/config 里的原始远端缺凭据时 git 默认等终端输入，进程挂死。"""
    import supernova_web.components.repo_manager as rm_mod
    calls: list[dict] = []
    real_exec = asyncio.create_subprocess_exec

    async def spy_exec(*argv, **kw):
        calls.append({"argv": [str(a) for a in argv], "env": kw.get("env")})
        return await real_exec(*argv, **kw)

    monkeypatch.setattr(rm_mod.asyncio, "create_subprocess_exec", spy_exec)
    rm, target = _link_real_repo(tmp_path, monkeypatch)
    await rm.checkout(WS, "shared", "dev")
    await rm.list_branches(WS, "shared")
    linked_calls = [c for c in calls
                    if c["argv"][:1] == ["git"] and str(target) in c["argv"]]
    assert linked_calls, "应捕获到作用于 linked 目录的 git 子进程"
    for c in linked_calls:
        assert c["env"] is not None
        assert c["env"].get("GIT_TERMINAL_PROMPT") == "0"


# ---- 批量关联目录（link_repos_in_dir）----

def _git_dir(p: Path) -> Path:
    """构造一个 git 仓库目录（含 .git 标志）。"""
    p.mkdir(parents=True, exist_ok=True)
    (p / ".git").mkdir(exist_ok=True)
    return p


def test_link_repos_in_dir_imports_flat_and_grouped(tmp_path, monkeypatch):
    rm = _rm(tmp_path, monkeypatch)
    proj = tmp_path / "proj"
    _git_dir(proj / "frontend")
    _git_dir(proj / "services" / "auth")
    res = rm.link_repos_in_dir(WS, str(proj))
    names = {x["name"] for x in res["imported"]}
    assert names == {"frontend", "services/auth"}
    from supernova_web.components.repo_manager import read_linked_repos
    links = {l["name"]: l for l in read_linked_repos(_ws_dir(tmp_path))}
    assert set(links) == {"frontend", "services/auth"}
    assert links["services/auth"]["path"].endswith("services/auth")


def test_link_repos_in_dir_skips_non_git(tmp_path, monkeypatch):
    rm = _rm(tmp_path, monkeypatch)
    proj = tmp_path / "proj"
    (proj / "plain").mkdir(parents=True)  # 非 git 目录
    _git_dir(proj / "repo")
    res = rm.link_repos_in_dir(WS, str(proj))
    assert {x["name"] for x in res["imported"]} == {"repo"}


def test_link_repos_in_dir_skips_existing(tmp_path, monkeypatch):
    rm = _rm(tmp_path, monkeypatch)
    proj = tmp_path / "proj"
    _git_dir(proj / "frontend")
    other = _git_dir(tmp_path / "other")  # 先单条关联一个同名 frontend
    rm.link_repo(WS, "frontend", str(other))
    res = rm.link_repos_in_dir(WS, str(proj))
    assert {x["name"] for x in res["imported"]} == set()
    assert "frontend" in {x.get("name") for x in res["skipped"]}


def test_link_repos_in_dir_skips_too_deep(tmp_path, monkeypatch):
    rm = _rm(tmp_path, monkeypatch)
    proj = tmp_path / "proj"
    _git_dir(proj / "a" / "b" / "c")  # 相对 a/b/c -> 3 段（超过一层分组）
    res = rm.link_repos_in_dir(WS, str(proj))
    assert res["imported"] == []
    assert any("深" in x["reason"] for x in res["skipped"])


def test_link_repos_in_dir_prunes_inside_repo(tmp_path, monkeypatch):
    """仓库内部不再深入：proj/repo/.git + proj/repo/inner/.git 只导入 repo。"""
    rm = _rm(tmp_path, monkeypatch)
    proj = tmp_path / "proj"
    _git_dir(proj / "repo")
    _git_dir(proj / "repo" / "inner")
    res = rm.link_repos_in_dir(WS, str(proj))
    names = {x["name"] for x in res["imported"]}
    assert names == {"repo"}
    assert "repo/inner" not in names


def test_link_repos_in_dir_skips_noise_dirs(tmp_path, monkeypatch):
    rm = _rm(tmp_path, monkeypatch)
    proj = tmp_path / "proj"
    _git_dir(proj / "node_modules" / "pkg")  # 噪声目录内的 git 不导入
    _git_dir(proj / "repo")
    res = rm.link_repos_in_dir(WS, str(proj))
    assert {x["name"] for x in res["imported"]} == {"repo"}


def test_link_repos_in_dir_missing_path(tmp_path, monkeypatch):
    rm = _rm(tmp_path, monkeypatch)
    with pytest.raises(ValueError):
        rm.link_repos_in_dir(WS, str(tmp_path / "nope"))


def test_unlink_repo_removes_record_not_files(tmp_path, monkeypatch):
    from supernova_web.components.repo_manager import read_linked_repos
    rm = _rm(tmp_path, monkeypatch)
    target = _make_real_repo(tmp_path)
    rm.link_repo(WS, "ftoa", str(target))
    rm.unlink_repo(WS, "ftoa")
    assert read_linked_repos(_ws_dir(tmp_path)) == []  # 记录移除
    assert target.exists() and (target / "README.md").exists()  # 源文件绝不删


def test_unlink_repo_unknown_raises(tmp_path, monkeypatch):
    rm = _rm(tmp_path, monkeypatch)
    with pytest.raises(ValueError):
        rm.unlink_repo(WS, "nope")


def test_list_repos_includes_linked(tmp_path, monkeypatch):
    rm = _rm(tmp_path, monkeypatch)
    d = _repos_base(tmp_path) / "clone1"
    d.mkdir(parents=True)
    (d / ".git").mkdir()  # 私有克隆
    target = _make_real_repo(tmp_path)
    rm.link_repo(WS, "ftoa", str(target))  # 关联
    views = {r["name"]: r for r in rm.list_repos(WS)}
    assert set(views) == {"clone1", "ftoa"}
    assert views["clone1"].get("linked") is not True  # 私有克隆非关联
    assert views["ftoa"]["linked"] is True


def test_list_repos_linked_plain_dir_no_git(tmp_path, monkeypatch):
    rm = _rm(tmp_path, monkeypatch)
    plain = tmp_path / "plain"
    plain.mkdir()
    rm.link_repo(WS, "data", str(plain))
    views = {r["name"]: r for r in rm.list_repos(WS)}
    assert views["data"]["source"]["kind"] == "linked"
    assert "branch" not in views["data"]["source"]  # 无 .git 不推断分支


def test_get_repo_finds_linked(tmp_path, monkeypatch):
    rm = _rm(tmp_path, monkeypatch)
    target = _make_real_repo(tmp_path)
    rm.link_repo(WS, "ftoa", str(target))
    view = rm.get_repo(WS, "ftoa")
    assert view is not None and view["linked"] is True
    assert rm.get_repo(WS, "unknown") is None


@pytest.mark.asyncio
async def test_delete_unlinks_linked_without_rmtree(tmp_path, monkeypatch):
    from supernova_web.components.repo_manager import read_linked_repos
    rm = _rm(tmp_path, monkeypatch)
    target = _make_real_repo(tmp_path)
    rm.link_repo(WS, "ftoa", str(target))
    await rm.delete(WS, "ftoa")
    assert read_linked_repos(_ws_dir(tmp_path)) == []  # 关联记录移除
    assert target.exists()  # 源目录仍在（关联=仅取消引用，绝不删文件）


# ---- 批量删除归类（delete_one）----
# delete_one 是批量删除端点的逐项归类器：复用 delete 的分叉（linked→unlink 不删源、
# 私有→rmtree），返回结构化结果（deleted/unlinked/busy/not_found）供端点收集 skipped。


@pytest.mark.asyncio
async def test_delete_one_private_clone_deleted(tmp_path, monkeypatch):
    """delete_one 私有克隆 → 'deleted'，目录被 rmtree。"""
    rm = _rm(tmp_path, monkeypatch)
    d = _repos_base(tmp_path) / "foo"
    d.mkdir(parents=True)
    (d / ".git").mkdir()
    assert await rm.delete_one(WS, "foo") == "deleted"
    assert not d.exists()


@pytest.mark.asyncio
async def test_delete_one_grouped_private_clone_deleted(tmp_path, monkeypatch):
    """delete_one 分组私有克隆 group/repo → 'deleted'。"""
    rm = _rm(tmp_path, monkeypatch)
    d = _repos_base(tmp_path) / "frontend" / "foo"
    d.mkdir(parents=True)
    (d / ".git").mkdir()
    assert await rm.delete_one(WS, "frontend/foo") == "deleted"
    assert not d.exists()


@pytest.mark.asyncio
async def test_delete_one_linked_unlinked_keeps_files(tmp_path, monkeypatch):
    """delete_one 关联仓 → 'unlinked'：源文件保留、linked 记录移除。"""
    from supernova_web.components.repo_manager import read_linked_repos
    rm = _rm(tmp_path, monkeypatch)
    target = _make_real_repo(tmp_path)
    rm.link_repo(WS, "ftoa", str(target))
    assert await rm.delete_one(WS, "ftoa") == "unlinked"
    assert read_linked_repos(_ws_dir(tmp_path)) == []
    assert target.exists() and (target / "README.md").exists()


@pytest.mark.asyncio
async def test_delete_one_not_found(tmp_path, monkeypatch):
    """delete_one 既非关联、文件系统也无仓库目录 → 'not_found'，无副作用。"""
    rm = _rm(tmp_path, monkeypatch)
    assert await rm.delete_one(WS, "ghost") == "not_found"


@pytest.mark.asyncio
async def test_delete_one_busy(tmp_path, monkeypatch):
    """delete_one 仓库在 _jobs（clone/pull 中）→ 'busy'，目录不动。"""
    rm = _rm(tmp_path, monkeypatch)
    d = _repos_base(tmp_path) / "foo"
    d.mkdir(parents=True)
    (d / ".git").mkdir()
    rm._jobs[(WS, "foo")] = asyncio.create_task(asyncio.sleep(10))
    try:
        assert await rm.delete_one(WS, "foo") == "busy"
        assert d.exists()  # 未删
    finally:
        t = rm._jobs.pop((WS, "foo"), None)
        if t:
            t.cancel()


# ---- 空壳目录（shell dirs）可见化 + 可删除 ----
# 空壳 = 占住 clone 目标路径（target.exists() 挡 re-clone 报"仓库已存在"）但列表不可见
# （顶层无 .git 不显示）的目录。两种形态：
#   1) 失败 clone 残留：_mark_failed 落的 state=failed meta + clone.ndjson，无 .git
#      （git clone 失败不留完整 .git）——QC-GZ 机器 2026-08-17 实报：clone rc=128 失败后
#      列表看不到 backend，re-clone 报已存在。
#   2) 空目录占位：删分组仓库后残留的空分组目录 / 手建目录。
# 目标：列表显示（残留→failed 态、空目录→empty 态）、delete 可删（rmtree / rmdir），
# 消灭"看不见也删不掉"的死锁。


@pytest.mark.asyncio
async def test_clone_failed_residue_visible_in_list(tmp_path, monkeypatch):
    """失败 clone 残留（meta+ndjson、无 .git）必须在列表可见且 state=failed。"""
    crash = tmp_path / "crash.py"
    crash.write_text("import sys; sys.exit(128)")
    rm = _rm(tmp_path, monkeypatch)
    monkeypatch.setattr(rm, "_build_clone_argv",
                        lambda url, target, branch: [sys.executable, str(crash)])
    await rm.clone(WS, "https://gitlab.example/backend.git", None, None, None)
    await asyncio.sleep(0.3)
    views = {r["name"]: r for r in rm.list_repos(WS)}
    assert "backend" in views
    assert views["backend"]["state"] == "failed"


def test_list_repos_shows_empty_shell_dirs(tmp_path, monkeypatch):
    """空目录占位（顶层 + 二层）→ state=empty 显示；get_repo 同口径（列表可见详情不 404）。"""
    rm = _rm(tmp_path, monkeypatch)
    base = _repos_base(tmp_path)
    (base / "frontend").mkdir(parents=True)          # 顶层空壳
    (base / "grp" / "leftover").mkdir(parents=True)  # 二层空壳
    views = {r["name"]: r for r in rm.list_repos(WS)}
    assert views["frontend"]["state"] == "empty"
    assert views["grp/leftover"]["state"] == "empty"
    assert views["grp/leftover"]["group"] == "grp"
    assert rm.get_repo(WS, "frontend") is not None
    assert rm.get_repo(WS, "frontend")["state"] == "empty"


def test_group_dir_with_miswritten_meta_not_listed_as_repo(tmp_path, monkeypatch):
    """2026-07-08 回归守卫：分组目录（其下有真仓库）即便被误写 meta 也不得当仓库列出，
    否则 continue 会吞掉二层子仓库扫描。空壳可见化不得重新引入此 bug。"""
    rm = _rm(tmp_path, monkeypatch)
    base = _repos_base(tmp_path)
    child = base / "grp" / "real"
    child.mkdir(parents=True)
    (child / ".git").mkdir()
    (base / "grp" / ".supernova-repo.json").write_text('{"name": "grp", "state": "ready"}')
    names = [r["name"] for r in rm.list_repos(WS)]
    assert "grp" not in names
    assert "grp/real" in names


def test_nonempty_plain_dir_stays_hidden(tmp_path, monkeypatch):
    """非空且无 .git/meta 的目录（用户自放数据）不列出——rmtree 删未知内容危险，
    可见化但删不掉比不可见更糟。"""
    rm = _rm(tmp_path, monkeypatch)
    base = _repos_base(tmp_path)
    (base / "data").mkdir(parents=True)
    (base / "data" / "file.txt").write_text("x")
    assert all(r["name"] != "data" for r in rm.list_repos(WS))


@pytest.mark.asyncio
async def test_delete_empty_shell_dir(tmp_path, monkeypatch):
    """delete 空壳目录 → rmdir 删除；delete_one 归类 'deleted'（批量删除可清理）。"""
    rm = _rm(tmp_path, monkeypatch)
    base = _repos_base(tmp_path)
    (base / "frontend").mkdir(parents=True)
    await rm.delete(WS, "frontend")
    assert not (base / "frontend").exists()
    (base / "test").mkdir()
    assert await rm.delete_one(WS, "test") == "deleted"
    assert not (base / "test").exists()


@pytest.mark.asyncio
async def test_delete_grouped_repo_cleans_empty_group_dir(tmp_path, monkeypatch):
    """删分组仓库后：分组目录仍有兄弟仓库 → 保留；空了 → 一并清理（不留占名空壳）。"""
    rm = _rm(tmp_path, monkeypatch)
    base = _repos_base(tmp_path)
    for n in ("g/a", "g/b"):
        d = base / n
        d.mkdir(parents=True)
        (d / ".git").mkdir()
    await rm.delete(WS, "g/a")
    assert (base / "g" / "b").exists()
    assert (base / "g").is_dir()  # 仍有 b → 分组目录保留
    await rm.delete(WS, "g/b")
    assert not (base / "g").exists()  # 空了 → 分组目录一并清理


@pytest.mark.asyncio
async def test_delete_top_level_repo_keeps_repos_root(tmp_path, monkeypatch):
    """删顶层仓库绝不波及 repos 根目录本身（父目录即根，必须跳过清理）。"""
    rm = _rm(tmp_path, monkeypatch)
    base = _repos_base(tmp_path)
    d = base / "solo"
    d.mkdir(parents=True)
    (d / ".git").mkdir()
    await rm.delete(WS, "solo")
    assert base.is_dir()  # 根目录仍在


@pytest.mark.asyncio
async def test_clone_into_empty_shell_hints_delete(tmp_path, monkeypatch):
    """对空壳占位 clone：409 信息指向"先删除"而非误导性的"改用更新 pull"
    （pull 对空壳会报"仓库不存在"）。"""
    rm = _rm(tmp_path, monkeypatch)
    (_repos_base(tmp_path) / "frontend").mkdir(parents=True)
    with pytest.raises(ValueError, match="空目录占位"):
        await rm.clone(WS, "https://gitlab.example/frontend.git", None, None, None)
