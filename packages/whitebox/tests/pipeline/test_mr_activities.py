"""MR 前置 activities（spec 2026-09-03 §3.1 步骤 2/3）：repo prepare + git diff。

不经 Temporal 直接调 async activity 函数（对齐 test_activities_* 惯例）；
产物落 deliverables/whitebox/intermediate/mr/。
"""

import json
import subprocess
from pathlib import Path

import pytest

from supernova_core.models.errors import PentestError
from supernova_whitebox.pipeline.shared import ActivityInput
from supernova_whitebox.pipeline.mr_activities import (
    MR_DIR_NAME, run_git_diff, run_mr_repo_prepare,
)


def _git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


@pytest.fixture()
def mr_repo(tmp_path):
    """两 commit 的 git 仓：base（sanitize 版）→ head（删 sanitize + 加路由）。"""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@t")
    _git(repo, "config", "user.name", "t")
    f = repo / "app.py"
    f.write_text("def h(req):\n    q = req['q']\n    q = sanitize(q)\n    return db(q)\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "base")
    f.write_text("def h(req):\n    q = req['q']\n    return db(q)\n"
                 "\n\ndef new_route(req):\n    return db(req['id'])\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "head")
    return repo


def _act(repo: Path, tmp_path: Path, **kw) -> ActivityInput:
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir(exist_ok=True)
    defaults = dict(mr_base_ref="main~1", mr_head_ref="main")
    defaults.update(kw)
    return ActivityInput(
        repo_path=str(repo),
        workspace_path=str(scan_dir),
        **defaults,
    )


@pytest.fixture()
def merged_repo(tmp_path):
    """GitLab「合并后删源分支」形态：main 上 true merge commit（--no-ff），
    feature/safe 已删。返回 (repo, merge_sha)——merge_sha 即 resolve-link 改道
    穿下来的 head_commit（MR API merge_commit_sha）。"""
    repo = tmp_path / "merged"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@t")
    _git(repo, "config", "user.name", "t")
    f = repo / "app.py"
    f.write_text("def h(req):\n    q = req['q']\n    q = sanitize(q)\n    return db(q)\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "base")
    _git(repo, "checkout", "-qb", "feature/safe")
    f.write_text("def h(req):\n    q = req['q']\n    return db(q)\n"
                 "\n\ndef new_route(req):\n    return db(req['id'])\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "head")
    _git(repo, "checkout", "-q", "main")
    _git(repo, "merge", "--no-ff", "-qm", "merge MR !99", "feature/safe")
    _git(repo, "branch", "-qD", "feature/safe")  # 模拟合并后删源分支
    merge_sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo,
                               capture_output=True, text=True,
                               check=True).stdout.strip()
    return repo, merge_sha


async def test_repo_prepare_resolves_merge_base_and_checks_out_head(mr_repo, tmp_path):
    result = await run_mr_repo_prepare(_act(mr_repo, tmp_path))

    # merge-base 解析出 base commit sha；head 已 checkout（HEAD == head_ref 解析值）
    assert result["base_commit"]
    assert result["head_commit"]
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=mr_repo,
                          capture_output=True, text=True, check=True).stdout.strip()
    assert head == result["head_commit"]


@pytest.fixture()
def remote_mr_repo(tmp_path):
    """事故形态（2026-09-08 risk_user_side!153）：repo 注册按 MR head 分支
    clone（-b head），base 分支只存在于 refs/remotes/origin/ 下、无同名本地
    分支——裸名 rev-parse 解析不到 remote-tracking ref（gitrevisions 路径
    不含 refs/remotes/origin/<name>）。"""
    origin = tmp_path / "origin.git"
    _git(tmp_path, "init", "-q", "--bare", str(origin))
    work = tmp_path / "work"
    work.mkdir()
    _git(work, "init", "-q", "-b", "feature/v20260618_th")
    _git(work, "config", "user.email", "t@t")
    _git(work, "config", "user.name", "t")
    f = work / "app.py"
    f.write_text("def h(req):\n    q = req['q']\n    q = sanitize(q)\n    return db(q)\n")
    _git(work, "add", "-A")
    _git(work, "commit", "-qm", "base")
    _git(work, "push", "-q", str(origin), "feature/v20260618_th")
    _git(work, "checkout", "-qb", "feature/th-credit-limit-v2")
    f.write_text("def h(req):\n    q = req['q']\n    return db(q)\n"
                 "\n\ndef new_route(req):\n    return db(req['id'])\n")
    _git(work, "add", "-A")
    _git(work, "commit", "-qm", "head")
    _git(work, "push", "-q", str(origin), "feature/th-credit-limit-v2")
    repo = tmp_path / "repo"
    _git(tmp_path, "clone", "-q", "-b", "feature/th-credit-limit-v2", str(origin), str(repo))
    return repo


async def test_repo_prepare_resolves_base_from_remote_tracking_only(
        remote_mr_repo, tmp_path):
    """base 分支无本地分支、仅 origin/<base> remote-tracking（fetch/clone 产物）
    → prepare 应经 origin/<ref> 兜底解析成功，而非 fail-fast。"""
    repo = remote_mr_repo
    act = _act(repo, tmp_path,
               mr_base_ref="feature/v20260618_th",
               mr_head_ref="feature/th-credit-limit-v2")

    result = await run_mr_repo_prepare(act)

    base_sha = subprocess.run(
        ["git", "rev-parse", "refs/remotes/origin/feature/v20260618_th"],
        cwd=repo, capture_output=True, text=True, check=True).stdout.strip()
    assert result["base_commit"] == base_sha
    assert result["merge_base"] == base_sha  # head 从 base 分出，merge-base 即 base tip
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo,
                          capture_output=True, text=True, check=True).stdout.strip()
    assert head == result["head_commit"]


async def test_repo_prepare_fails_fast_on_unresolvable_ref(mr_repo, tmp_path):
    act = _act(mr_repo, tmp_path)
    act.mr_base_ref = "no-such-ref"

    with pytest.raises(PentestError):
        await run_mr_repo_prepare(act)


# ---- merged 改道模式（2026-09-04：源分支已删的已合并 MR，按 commit 对定位）----

def _merged_act(repo: Path, tmp_path: Path, merge_sha: str, **kw) -> ActivityInput:
    """改道入参：head_ref 仍是已删分支名（仅展示），实际把手 mr_head_commit。"""
    defaults = dict(mr_base_ref="main", mr_head_ref="feature/safe",
                    mr_head_commit=merge_sha)
    defaults.update(kw)
    return _act(repo, tmp_path, **defaults)


async def test_repo_prepare_merged_fallback_resolves_first_parent(merged_repo, tmp_path):
    repo, merge_sha = merged_repo

    result = await run_mr_repo_prepare(_merged_act(repo, tmp_path, merge_sha))

    # base = merge commit 的第一父（true merge 的目标分支侧）→ diff 区间恰好是
    # MR 合入的全部变更；head checkout 到 merge commit（无需已删的源分支）。
    first_parent = subprocess.run(
        ["git", "rev-parse", f"{merge_sha}^1"], cwd=repo,
        capture_output=True, text=True, check=True).stdout.strip()
    assert result["head_commit"] == merge_sha
    assert result["base_commit"] == first_parent
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo,
                          capture_output=True, text=True, check=True).stdout.strip()
    assert head == merge_sha


async def test_repo_prepare_merged_fallback_explicit_base_commit(merged_repo, tmp_path):
    """FF 形态：resolve-link 显式穿 base_commit（diff_refs.base_sha），worker 不猜 ^1。"""
    repo, merge_sha = merged_repo
    base_sha = subprocess.run(
        ["git", "rev-parse", f"{merge_sha}^1"], cwd=repo,
        capture_output=True, text=True, check=True).stdout.strip()

    result = await run_mr_repo_prepare(
        _merged_act(repo, tmp_path, merge_sha, mr_base_commit=base_sha))

    assert result["base_commit"] == base_sha
    assert result["head_commit"] == merge_sha


async def test_repo_prepare_merged_fallback_unresolvable_commit_fails_fast(
        merged_repo, tmp_path):
    """merge commit 在目标分支上解析不到（被 force-push 等）→ fail-fast 带原因。"""
    repo, merge_sha = merged_repo
    with pytest.raises(PentestError, match="61da230a"):
        await run_mr_repo_prepare(
            _merged_act(repo, tmp_path, merge_sha,
                        mr_head_commit="61da230a"))


async def test_git_diff_merged_fallback_covers_mr_changes_only(merged_repo, tmp_path):
    """改道 diff = first-parent 区间：只含 MR 变更（app.py 的删防护+新路由），
    不含 base 之前的历史；manifest/patch 照常落盘（增量三方向管道输入不变）。"""
    repo, merge_sha = merged_repo

    result = await run_git_diff(_merged_act(repo, tmp_path, merge_sha))

    mr_dir = tmp_path / "scan" / "deliverables" / "whitebox" / "intermediate" / MR_DIR_NAME
    manifest = json.loads((mr_dir / "diff_manifest.json").read_text())
    assert "diff --git" in (mr_dir / "diff.patch").read_text()
    assert {h["file_path"] for h in manifest["hunks"]} == {"app.py"}
    assert manifest["stats"]["insertions"] >= 1
    assert "injection" in result["selected_vuln_classes"]
    first_parent = subprocess.run(
        ["git", "rev-parse", f"{merge_sha}^1"], cwd=repo,
        capture_output=True, text=True, check=True).stdout.strip()
    assert result["base_commit"] == first_parent
    assert result["head_commit"] == merge_sha


async def test_git_diff_writes_manifest_and_patch(mr_repo, tmp_path):
    result = await run_git_diff(_act(mr_repo, tmp_path))

    mr_dir = tmp_path / "scan" / "deliverables" / "whitebox" / "intermediate" / MR_DIR_NAME
    manifest = json.loads((mr_dir / "diff_manifest.json").read_text())
    patch = (mr_dir / "diff.patch").read_text()

    assert manifest["stats"]["insertions"] >= 1
    assert manifest["stats"]["deletions"] >= 1
    assert "diff --git" in patch
    # 解析出的新增行覆盖 new_route（来源 B 的对齐基础）
    added_files = {h["file_path"] for h in manifest["hunks"]}
    assert "app.py" in added_files
    assert result["stats"]["insertions"] == manifest["stats"]["insertions"]
    # vuln 类启发式一并返回（child workflow 类选择用）
    assert "injection" in result["selected_vuln_classes"]


_VALID_PROTECTION_JSON = json.dumps({"removed_protections": [{
    "file_path": "app.py", "base_line_no": 3, "removed_text": "    q = sanitize(q)",
    "function_name": "h", "protection_kind": "sanitize",
    "rationale": "输入清洗被删", "confidence": 0.9,
}]})


async def test_protection_removal_analysis_writes_protections(mr_repo, tmp_path, monkeypatch):
    await run_git_diff(_act(mr_repo, tmp_path))   # 先产 diff.patch

    from supernova_whitebox.pipeline import mr_activities

    async def stub_client(prompt, **kwargs):
        return _VALID_PROTECTION_JSON

    monkeypatch.setattr(mr_activities, "_make_protection_llm_client",
                        lambda *a, **k: stub_client)

    result = await mr_activities.run_protection_removal_analysis(_act(mr_repo, tmp_path))

    mr_dir = tmp_path / "scan" / "deliverables" / "whitebox" / "intermediate" / MR_DIR_NAME
    data = json.loads((mr_dir / "removed_protections.json").read_text())
    assert result["degraded"] is False
    assert data["degraded"] is False
    assert data["protections"][0]["function_name"] == "h"


async def test_protection_removal_analysis_degrades_without_llm(mr_repo, tmp_path, monkeypatch):
    await run_git_diff(_act(mr_repo, tmp_path))

    from supernova_whitebox.pipeline import mr_activities
    monkeypatch.setattr(mr_activities, "_make_protection_llm_client", lambda *a, **k: None)

    result = await mr_activities.run_protection_removal_analysis(_act(mr_repo, tmp_path))

    assert result["degraded"] is True
    assert result["protections"] == []


async def test_incremental_scope_activity_writes_scope(mr_repo, tmp_path):
    act = _act(mr_repo, tmp_path)
    await run_git_diff(act)
    mr_dir = tmp_path / "scan" / "deliverables" / "whitebox" / "intermediate" / MR_DIR_NAME
    # 布置 head 索引产物（code_index.json 含 parameter_graph）
    from supernova_whitebox.pipeline import mr_activities

    index = _index_fixture()
    (mr_dir.parent / "code_index.json").write_text(index.model_dump_json())

    result = await mr_activities.run_incremental_scope(act)

    data = json.loads((mr_dir / "incremental_scope.json").read_text())
    # fixture 的新入口链（app.py:new_route added）被来源 B 收进 verdict 候选
    assert data["verdict_flow_ids"]
    assert result["verdict_flow_count"] == len(data["verdict_flow_ids"])


def _index_fixture():
    """与 mr_repo head 版本对齐的最小 CodeIndex：new_route 为新入口（added 行 5-6）。"""
    from supernova_core.code_index.models import CodeIndex, EntryPoint, FuncBlock
    from supernova_core.code_index.parameter_models import (
        ParameterPropagationGraph, SinkCallSite, SinkCategory, TaintFlow,
    )

    def blk(fid, start, end):
        fp, fn, _ = fid.split(":")
        return FuncBlock(id=fid, file_path=fp, function_name=fn, start_line=start,
                         end_line=end, source_code="", parameters=[], language="python")

    blocks = [blk("app.py:h:1", 1, 4), blk("app.py:new_route:6", 6, 7)]
    entries = [EntryPoint(func_block_id="app.py:new_route:6", entry_type="http_route",
                          route="/new", http_method="GET", confidence=1.0, evidence="e",
                          needs_llm_review=False)]
    sink = SinkCallSite(id="app.py:new_route:7:db:7", caller_id="app.py:new_route:6",
                        callee_name="db", callee_receiver=None,
                        category=SinkCategory.SQL, sink_subtype="sql_value",
                        file_path="app.py", line=7, column=1, dangerous_slots=[],
                        rule_id="r")
    flows = [TaintFlow(flow_id="app.py:new_route:6->app.py:new_route:7:db:7",
                       entry_point_id="app.py:new_route:6", source_param="req",
                       source_type="query",
                       sink_call_site_id="app.py:new_route:7:db:7")]
    return CodeIndex(repository="r", language="python", total_blocks=2,
                     total_entry_points=1, total_chains=0, blocks=blocks, edges=[],
                     entry_points=entries, chains=[], sink_call_sites=[sink],
                     source_points=[],
                     parameter_graph=ParameterPropagationGraph(taint_flows=flows))
