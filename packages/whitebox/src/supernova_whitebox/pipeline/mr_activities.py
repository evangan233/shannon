"""MR 增量扫描前置 activities（spec 2026-09-03 §3.1 步骤 2/3）。

run_mr_repo_prepare：fetch → checkout head → merge-base 解析（fail-fast）。
run_git_diff：git diff -U3 merge-base..head → DiffManifest + patch 落盘。
run_protection_removal_analysis / run_incremental_scope：后续接入。

产物集中 deliverables/whitebox/intermediate/mr/：
  diff_manifest.json / diff.patch / removed_protections.json / incremental_scope.json
"""

import json
import logging
import subprocess
from pathlib import Path

from temporalio import activity

from supernova_core.models.errors import ErrorCode, PentestError
from supernova_core.utils.paths import intermediate_dir
from supernova_whitebox.pipeline.shared import ActivityInput

logger = logging.getLogger(__name__)

MR_DIR_NAME = "mr"


def _mr_deliverables(input: ActivityInput) -> Path:
    """deliverables/whitebox/（与 _get_paths 同源的桶内路径）。"""
    from supernova_core.utils.paths import WHITEBOX_SUBDIR
    if input.workspace_path:
        deliverables = Path(input.workspace_path) / input.deliverables_subdir
    else:  # activity 直调（无 workspace_path）回落 repo 同级 workspaces —— 与测试/调试兼容
        deliverables = Path(input.repo_path).parent / "workspaces"
    track_dir = deliverables / WHITEBOX_SUBDIR
    track_dir.mkdir(parents=True, exist_ok=True)
    return track_dir


def _mr_dir(input: ActivityInput) -> Path:
    """deliverables/whitebox/intermediate/mr/（与 _get_paths 同源的桶内路径）。"""
    mr_dir = intermediate_dir(_mr_deliverables(input)) / MR_DIR_NAME
    mr_dir.mkdir(parents=True, exist_ok=True)
    return mr_dir


def _git(repo: Path, *args: str, check: bool = True) -> str:
    proc = subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise PentestError(
            f"git {' '.join(args)} failed: {proc.stderr.strip()}",
            category="mr_prepare", error_code=ErrorCode.REPO_NOT_FOUND,
        )
    return proc.stdout.strip()


def _fetch_branch(repo: Path, ref: str) -> None:
    """best-effort fetch（check=False 的可观测版）：失败不挡流程——本地仓无
    remote（测试/本地调试）或远端瞬时故障时本地 ref 已可用；但 stderr 落
    warning——2026-09-08 事故排障时 fetch 真实成败不可见，只能靠 rev-parse
    报错倒推。"""
    proc = subprocess.run(["git", "fetch", "origin", ref], cwd=repo,
                          capture_output=True, text=True)
    if proc.returncode != 0:
        logger.warning("git fetch origin %s failed (rc=%d): %s",
                       ref, proc.returncode, proc.stderr.strip())


def _rev_parse(repo: Path, ref: str) -> str:
    """裸名 → origin/<ref> 兜底（2026-09-08 risk_user_side!153 事故）。

    fetch/clone 只建 refs/remotes/origin/<ref>（remote-tracking），而 git 裸名
    解析路径（gitrevisions）不含它——repo 按 head 分支 clone 时 head 有本地
    分支碰巧成功、base 无本地分支必失败。逐候选试解析，全败才 fail-fast。
    """
    for candidate in (ref, f"origin/{ref}"):
        out = _git(repo, "rev-parse", "--verify", candidate + "^{commit}", check=False)
        if out:
            return out
    raise PentestError(
        f"MR ref 解析失败: {ref}（本地分支与 origin/{ref} 均无）",
        category="mr_prepare", error_code=ErrorCode.REPO_NOT_FOUND,
    )


@activity.defn
async def run_mr_repo_prepare(input: ActivityInput) -> dict:
    """fetch（best-effort）→ 解析 base/head → merge-base → checkout head。

    merged 改道（2026-09-04）：mr_head_commit 非空时不碰分支名——源分支已删的
    已合并 MR 按 commit 对定位（head=merge_commit_sha；base 显式给或解析 head^1
    first-parent），fetch 目标分支把 merge commit 带下来即可。

    fail-fast 语义（spec §7）：ref 解析不到 / 无共同祖先 → PentestError。
    """
    repo = Path(input.repo_path)
    base_ref = input.mr_base_ref or ""
    head_ref = input.mr_head_ref or ""
    if input.mr_head_commit:
        return await _prepare_by_commits(repo, input)
    if not base_ref or not head_ref:
        raise PentestError(
            "MR 模式需要 base_ref 与 head_ref", category="mr_prepare",
            error_code=ErrorCode.REPO_NOT_FOUND,
        )

    # fetch best-effort：本地仓无 remote（测试/本地调试）时忽略失败，本地 ref 已可用
    _fetch_branch(repo, head_ref)
    _fetch_branch(repo, base_ref)

    head_commit = _rev_parse(repo, head_ref)
    base_commit = _rev_parse(repo, base_ref)

    merge_base = _git(repo, "merge-base", base_commit, head_commit)
    if not merge_base:
        raise PentestError(
            f"无共同祖先（merge-base 为空）: {base_ref}..{head_ref}",
            category="mr_prepare", error_code=ErrorCode.REPO_NOT_FOUND,
        )

    _git(repo, "checkout", "-q", head_commit)
    logger.info("MR repo prepared: base=%s head=%s (merge-base=%s)",
                base_commit[:8], head_commit[:8], merge_base[:8])
    return {
        "base_commit": base_commit,
        "head_commit": head_commit,
        "merge_base": merge_base,
    }


async def _prepare_by_commits(repo: Path, input: ActivityInput) -> dict:
    """merged 改道：commit 对解析 → checkout head（无需源分支）。

    base 缺省解析 head^1（true merge 的目标分支侧 / squash 的前驱）；FF 形态由
    resolve-link 显式穿 mr_base_commit（diff_refs.base_sha）。
    """
    # merge commit 在目标分支历史上——fetch 目标分支即带下（best-effort 同上）。
    if input.mr_base_ref:
        _fetch_branch(repo, input.mr_base_ref)

    try:
        head_commit = _rev_parse(repo, input.mr_head_commit or "")
    except PentestError as e:
        raise PentestError(
            f"MR 已合并但合入 commit {input.mr_head_commit} 在仓库中解析不到"
            f"（可能目标分支被改写），无法增量扫描: {e}",
            category="mr_prepare", error_code=ErrorCode.REPO_NOT_FOUND,
        ) from e
    base_commit = (_rev_parse(repo, input.mr_base_commit)
                   if input.mr_base_commit
                   else _rev_parse(repo, (input.mr_head_commit or "") + "^1"))

    _git(repo, "checkout", "-q", head_commit)
    logger.info("MR repo prepared (merged fallback): base=%s head=%s",
                base_commit[:8], head_commit[:8])
    return {
        "base_commit": base_commit,
        "head_commit": head_commit,
        "merge_base": base_commit,  # 改道区间直接给定（base..head），无 merge-base 步
    }


@activity.defn
async def run_git_diff(input: ActivityInput) -> dict:
    """merge-base..head 的 unified diff → DiffManifest + patch 落盘。

    merged 改道（mr_head_commit 非空）：diff 区间直接由 commit 对给定（base 缺省
    head^1 first-parent），不经 merge-base。

    返回 stats + select_vuln_classes（child workflow 的 vuln 类选择输入）。
    自包含重解析 ref（activity 重试幂等，不依赖 repo_prepare 的内存返回）。
    """
    from supernova_core.mr_scan.diff_manifest import parse_unified_diff
    from supernova_core.mr_scan.incremental_scope import select_vuln_classes

    repo = Path(input.repo_path)
    if input.mr_head_commit:
        head_commit = _rev_parse(repo, input.mr_head_commit)
        base_commit = (_rev_parse(repo, input.mr_base_commit)
                       if input.mr_base_commit
                       else _rev_parse(repo, input.mr_head_commit + "^1"))
    else:
        head_commit = _rev_parse(repo, input.mr_head_ref or "")
        base_commit = _rev_parse(repo, input.mr_base_ref or "")
        base_commit = _git(repo, "merge-base", base_commit, head_commit)

    diff_text = _git(repo, "diff", "-U3", "--no-color", f"{base_commit}..{head_commit}")
    manifest = parse_unified_diff(diff_text, base_commit=base_commit, head_commit=head_commit)

    mr_dir = _mr_dir(input)
    (mr_dir / "diff_manifest.json").write_text(manifest.model_dump_json(indent=2))
    (mr_dir / "diff.patch").write_text(diff_text)

    return {
        "stats": manifest.stats.model_dump(),
        "selected_vuln_classes": select_vuln_classes(manifest),
        "base_commit": base_commit,
        "head_commit": head_commit,
    }


def _make_protection_llm_client(provider_config: dict | None = None):
    """run_claude_prompt 封装成 detect_removed_protections 的 LLMClient 契约。

    对齐 activities._make_gitnexus_llm_client：structured_output 优先还原 str 契约；
    env 关（is_gitnexus_llm_enabled False）返回 None → detect 内部静默降级。
    """
    from supernova_core.agents.runner import run_claude_prompt

    if not _gitnexus_llm_enabled():
        return None

    async def _client(prompt: str, **kwargs) -> str:
        result = await run_claude_prompt(
            prompt=prompt, repo_path="", model_tier="medium",
            structured_output_schema=kwargs.get("output_format"),
            provider_config=provider_config,
        )
        so = result.structured_output
        if so is not None:
            return json.dumps(so)
        return result.text
    return _client


def _gitnexus_llm_enabled() -> bool:
    from supernova_core.config.concurrency import is_gitnexus_llm_enabled
    return is_gitnexus_llm_enabled()


@activity.defn
async def run_protection_removal_analysis(input: ActivityInput) -> dict:
    """diff.patch → 删防护 LLM 判定 → removed_protections.json（spec §5.1）。

    降级（degraded=True）也落盘——来源 C 缺席但 A/B 不受影响，报告标注降级。
    """
    mr_dir = _mr_dir(input)
    patch_path = mr_dir / "diff.patch"
    if not patch_path.exists():
        raise PentestError(
            f"MR diff 产物缺失: {patch_path}", category="mr_prepare",
            error_code=ErrorCode.DELIVERABLE_NOT_FOUND,
        )

    from supernova_core.mr_scan.protection_removal import detect_removed_protections

    diff_text = patch_path.read_text()
    outcome = await detect_removed_protections(
        diff_text, llm_client=_make_protection_llm_client(input.provider_config),
    )
    payload = {
        "degraded": outcome.degraded,
        "protections": [p.model_dump() for p in outcome.protections],
    }
    (mr_dir / "removed_protections.json").write_text(json.dumps(payload, indent=2))
    return payload


@activity.defn
async def run_incremental_scope(input: ActivityInput) -> dict:
    """diff_manifest + removed_protections + code_index → IncrementalScope 落盘。

    在 child workflow 的 pre-recon 之后跑（head 索引已产）。
    """
    mr_dir = _mr_dir(input)
    from supernova_core.code_index.models import CodeIndex
    from supernova_core.mr_scan.diff_manifest import DiffManifest
    from supernova_core.mr_scan.incremental_scope import (
        RemovedProtection, build_incremental_scope,
    )

    manifest = DiffManifest.model_validate_json(
        (mr_dir / "diff_manifest.json").read_text())
    index_path = mr_dir.parent / "code_index.json"
    index = CodeIndex.model_validate_json(index_path.read_text())
    pgraph = index.parameter_graph or type(index.parameter_graph)()

    protections: list[RemovedProtection] = []
    rp_path = mr_dir / "removed_protections.json"
    if rp_path.exists():
        rp_data = json.loads(rp_path.read_text())
        protections = [RemovedProtection(**p) for p in rp_data.get("protections", [])]

    scope = build_incremental_scope(
        diff=manifest, index=index, pgraph=pgraph, removed_protections=protections,
    )
    (mr_dir / "incremental_scope.json").write_text(scope.model_dump_json(indent=2))
    # 容量铁律（spec §5.1，CLAUDE.md §1）：GN verdict 窗口 = 链数 ÷ 并发 ×
    # 单链上界（60s/轮），下限 5min。activity 层算好穿 workflow（workflow 沙箱
    # 禁 env 读非确定性源），child 调 run_gitnexus_chain_verdict 时用。
    import math
    from supernova_core.config.concurrency import get_chain_verdict_concurrency
    conc = max(get_chain_verdict_concurrency(), 1)
    verdict_timeout_minutes = max(5, math.ceil(len(scope.verdict_flow_ids) / conc))
    return {
        "verdict_flow_count": len(scope.verdict_flow_ids),
        "verdict_timeout_minutes": verdict_timeout_minutes,
        "selected_vuln_classes": scope.selected_vuln_classes,
        "new_entry_point_count": len(scope.new_entry_point_ids),
        "removed_protection_count": len(scope.removed_protection_flows),
    }


@activity.defn
async def run_mr_empty_diff_finalize(input: ActivityInput) -> dict:
    """空 diff 快速终态（spec §7）：base==head（stats.files==0）→ 不跑双轨，
    复用全量报告组装器产「无变更」报告（queue 缺席 → 空 vulns；scan 带增量
    refs——builder 读 intermediate/mr/diff_manifest.json 自动补）。
    """
    from supernova_whitebox.pipeline.activities import _build_report_data_initial

    deliverables = _mr_deliverables(input)
    rd = await _build_report_data_initial(input, deliverables)
    return {"vuln_count": len(rd.vulnerabilities),
            "report_data": str(deliverables / "report_data.json")}
