import asyncio
import hashlib
import json
import logging
import time
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from temporalio import activity
from temporalio.exceptions import ApplicationError as ApplicationFailure

from pydantic import ValidationError

from supernova_core.models.agents import AgentName, AGENTS, ALL_VULN_CLASSES, VulnType
from supernova_core.models.audit import AgentEndResult, WorkflowSummary
from supernova_core.models.errors import (
    ErrorCode,
    PentestError,
    classify_error_for_temporal,
    classify_for_temporal_with_retry_cap,
)
from supernova_core.models.metrics import AgentMetrics
from supernova_core.models.retry import agent_retry_category, retry_for
from supernova_core.runtime.heartbeat import stop_heartbeat
from supernova_core.utils.atomic_write import atomic_write_json
from supernova_core.utils.paths import intermediate_path, resolve_deliverables_path, resolve_intermediate
from supernova_core.utils.credential_validator import validate_credentials
from supernova_core.logging import create_activity_logger
from supernova_core.logging.log_bus import LogBus
from supernova_core.agents.executor import AgentExecutor
from supernova_core.agents.runner import run_claude_prompt
from supernova_core.agents.recon_context_summarizer import (
    DIGEST_SECTION_ORDER,
    RECON_CONTEXT_SUMMARIZER_PROMPT_VERSION,
    UNPARSED_SECTION,
    build_deterministic_sections,
    build_summarizer_input,
    extract_recon_context_sections,
    parse_sections,
    summarize_recon_context,
)
from supernova_core.config.concurrency import (
    get_chain_verdict_concurrency, get_chain_verdict_max_turns,
    get_gitnexus_verdict_max_turns, get_poc_agent_concurrency,
    get_poc_shard_max_cards, is_gitnexus_llm_enabled,
)
from supernova_core.prompts.manager import PromptManager
from supernova_core.session import SessionManager
from supernova_whitebox.audit.session import AuditSession
from supernova_whitebox.audit.session_registry import get_audit_session
from supernova_core.audit.session_recovery import (
    build_headless_audit_session,
    ensure_audit_session,
)

from .shared import ActivityInput
from .mr_wiring import (
    build_mr_incremental_guidance, filter_flows_by_mr_scope, load_mr_scope_flow_ids,
)
from .step_intents import intent_for
from .step_cache import (
    STEP_AUTHZ_GITNEXUS_JUDGE,
    STEP_GITNEXUS_CHAIN_VERDICT,
    mark_done,
    should_skip,
)

logger = logging.getLogger(__name__)


def _get_paths(input: ActivityInput) -> tuple[Path, Path, Path]:
    from supernova_core.utils.paths import WHITEBOX_SUBDIR

    # workspace_path（web=event_file.parent=scan_dir；CLI=repo.parent/workspaces/<ws>）由
    # WhiteboxScanWorkflow 算好传入（workflows.py C1 Phase B）。优先用它作 deliverables 根，
    # 使产物落 scan_dir，与 web DeliverablesReader / get_workspace_vuln_counts 读取口径对齐——
    # 修 2026-07-30 分裂：_get_paths 旧用 resolve_deliverables_path(workspace_name=scan_id) 落
    # workspaces/<scan_id>/ 平铺目录，web 在 scan_dir/deliverables 读不到 → 前端 0 漏洞。
    # 无 workspace_path（activity 被直接调用、不经 workflow）回落 resolve_deliverables_path。
    if input.workspace_path:
        deliverables = Path(input.workspace_path) / input.deliverables_subdir
    else:
        deliverables = resolve_deliverables_path(
            repo_path=input.repo_path,
            deliverables_subdir=input.deliverables_subdir,
            workspace_name=input.workspace_name,
        )
    # 白盒产物隔离到 deliverables/whitebox/（与黑盒 blackbox/ 对称）。
    # 写侧永远落新结构；黑盒读白盒 queue 走 resolve_track_deliverable fallback。
    deliverables = deliverables / WHITEBOX_SUBDIR
    repo = Path(input.repo_path)
    workspaces = repo.parent / "workspaces"
    return repo, deliverables, workspaces


def _to_endpoint(d: dict):
    """Reconstruct framework analyzer endpoint dataclasses from JSON."""
    from supernova_core.services.framework_analyzer import InferredEndpoint

    return InferredEndpoint(
        method=d["method"],
        path=d["path"],
        source=d["source"],
        model=d.get("model"),
        middleware=tuple(d.get("middleware", [])),
        vulnerability_indicators=tuple(d.get("vulnerability_indicators", [])),
    )


@activity.defn
async def run_preflight(input: ActivityInput) -> None:
    from supernova_whitebox.audit.session_registry import get_audit_session
    await ensure_audit_session(input)  # worker 重启后可观测恢复(幂等;见 session_recovery.py)
    try:
        async with get_audit_session().track_step("setup", "preflight", intent=intent_for("preflight")):
            # Config parsing validation
            if input.config_path:
                from supernova_core.config.parser import parse_config
                try:
                    parse_config(input.config_path)
                except PentestError:
                    raise
                except Exception as exc:
                    raise PentestError(
                        f"Config parsing failed: {exc}",
                        category="config",
                        error_code=ErrorCode.CONFIG_PARSE_ERROR,
                    ) from exc

            repo, _, _ = _get_paths(input)
            if not repo.exists():
                raise PentestError(
                    f"Repository not found: {input.repo_path}",
                    "config",
                    error_code=ErrorCode.REPO_NOT_FOUND,
                )
            if not (repo / ".git").exists():
                raise PentestError(
                    f"Not a git repository: {input.repo_path}",
                    "config",
                    error_code=ErrorCode.REPO_NOT_FOUND,
                )
    except PentestError as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e
    except Exception as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e


def _vuln_max_turns(agent_name: str) -> int | None:
    """vuln agent 用专用 max_turns(SUPERNOVA_VULN_MAX_TURNS,默认 500);其他返回 None。

    返回 None 时,executor → run_claude_prompt → provider 沿用各引擎全局 env 默认
    (CLAUDE_MAX_TURNS / SUPERNOVA_OPENAI_MAX_TURNS = 200),行为零变更。
    B2: 仅 vuln 单独配,不污染 pre-recon/recon/report。
    """
    if agent_retry_category(agent_name) == "vuln":
        return int(os.getenv("SUPERNOVA_VULN_MAX_TURNS", "500"))
    return None


def _vuln_output_schema(agent_name: AgentName) -> dict | None:
    """Phase 2 B 拓扑(spec 2026-08-19 §3.5):恒返 None,vuln agent 停传结构化输出。

    queue 数据通道已切换到 collector(submit_finding 单条上交 + finding_roster 对账,
    executor 写盘);末条大 JSON 通道停用——CLI --json-schema 与 collected_text 兜底
    对 vuln 不再激活,网关断流的原始故障形态(session 正常结束带半截 JSON)在 vuln
    通道不复存在。历史:本函数曾补「schema 未传 → queue 永不落盘」的断线(见原
    docstring,对齐原始 TS getOutputFormat 的 *-vuln 宽松基线 schema),Phase 2 起
    该断线由 collector 通道接管。

    恒返 None(原 *-vuln / *-exploit 之分随之失效;exploit 仍为 None)。
    """
    return None


@activity.defn
async def run_agent(input: ActivityInput) -> dict:
    from supernova_whitebox.audit.session_registry import get_audit_session
    await ensure_audit_session(input)  # worker 重启后可观测恢复(幂等;见 session_recovery.py)
    from supernova_whitebox.audit.session_tool_audit_logger import SessionToolAuditLogger
    from supernova_core.models.audit import AgentEndResult, end_result_from_pentest_error

    agent_name = AgentName(input.agent_name or input.workspace_name)
    attempt = activity.info().attempt
    # Resolve once; reused by both except branches so the display can render
    # 将重试 N/M (attempt/max) without recomputing.
    max_attempts = retry_for(
        agent_retry_category(agent_name.value)).maximum_attempts
    session = get_audit_session()
    tool_audit_logger = SessionToolAuditLogger(session, agent_name.value, attempt)
    agent_start = time.monotonic()
    try:
        repo, deliverables, _ = _get_paths(input)
        prompts_dir = Path(__file__).resolve().parents[5] / "prompts"
        prompt_manager = PromptManager(prompts_dir)
        executor = AgentExecutor(prompt_manager)

        prompt_variables = None
        if agent_name == AgentName.RECON:
            prompt_variables = {}

        if agent_name == AgentName.PRE_RECON:
            prompt_variables = prompt_variables or {}

        if _is_vuln_agent(agent_name):
            prompt_variables = await _build_vuln_prompt_variables(
                input, prompt_variables or {}
            )

        await session.start_agent(agent_name.value, f"agent={agent_name.value}", attempt=attempt)
        await tool_audit_logger.initialize()
        metrics = await executor.execute(
            agent_name=agent_name,
            repo_path=str(repo),
            web_url=input.web_url,
            deliverables_path=str(deliverables),
            config_path=input.config_path,
            api_key=input.api_key,
            pipeline_testing=input.pipeline_testing_mode,
            prompt_override=input.prompt_override,
            prompt_variables=prompt_variables,
            tool_audit_logger=tool_audit_logger,
            max_turns=_vuln_max_turns(agent_name.value),
            structured_output_schema=_vuln_output_schema(agent_name),
            provider_config=input.provider_config,   # P3c 阶段 1
            prompt_suffix=build_mr_incremental_guidance(input.mr_meta),  # MR 增量引导段（§5.2）
        )
        await tool_audit_logger.close(success=True, duration_ms=metrics.duration_ms)
        await session.end_agent(agent_name.value, AgentEndResult(
            success=True,
            duration_ms=metrics.duration_ms,
            cost_usd=metrics.cost_usd or 0.0,
            cost_currency=metrics.cost_currency,
            attempt_number=attempt,
            model=metrics.model,
            num_turns=metrics.num_turns,
            input_tokens=metrics.input_tokens,
            output_tokens=metrics.output_tokens,
            cache_read_tokens=metrics.cache_read_tokens,
            cache_creation_tokens=metrics.cache_creation_tokens,
        ))
        return metrics.model_dump()
    except PentestError as e:
        dur_ms = int((time.monotonic() - agent_start) * 1000)
        await tool_audit_logger.close(success=False, duration_ms=dur_ms)
        # 失败 agent 也记 cost：从 PentestError.context 取 executor 携带的真实消耗
        # （修 error path cost 归 0），取不到回落 0（非 executor raise）。
        await session.end_agent(
            agent_name.value,
            end_result_from_pentest_error(e, duration_ms=dur_ms, attempt_number=attempt))
        await session.log_error(
            e, context=agent_name.value, attempt=attempt, max_attempts=max_attempts)
        # classify + OUTPUT_VALIDATION 独立 cap(对齐 TS MAX_OUTPUT_VALIDATION_RETRIES=3):
        # vuln agent 反复不吐 exploitation_queue 时,attempt >= cap 则停止重试(non_retryable),
        # 而非吃满通用 VULN_RETRY(8) 白烧 ~5×20min。
        error_type, retryable = classify_for_temporal_with_retry_cap(e, attempt)
        # log_error surfaces to the live display; ApplicationFailure surfaces to
        # Temporal for retry decisions — both are intended, not double-logging.
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e
    except Exception as e:
        await tool_audit_logger.close(
            success=False, duration_ms=int((time.monotonic() - agent_start) * 1000))
        await session.end_agent(agent_name.value, AgentEndResult(
            success=False, duration_ms=int((time.monotonic() - agent_start) * 1000), cost_usd=0.0,
            attempt_number=attempt, error=str(e)))
        await session.log_error(
            e, context=agent_name.value, attempt=attempt, max_attempts=max_attempts)
        error_type, retryable = classify_for_temporal_with_retry_cap(e, attempt)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e

@activity.defn
async def run_vuln_agent(input: ActivityInput) -> dict:
    return await run_agent(input)


# ── vuln prompt_variables 注入（Task 7 / SharedKnowledge 接通） ──────────
# 5 个 vuln agent（INJECTION_VULN/XSS_VULN/SSRF_VULN/AUTHZ_VULN/AUTH_VULN）专用：在 vuln prompt
# 渲染前注入 {{RECON_CONTEXT}}（LLM 摘要 recon_deliverable.md，六节视图）+
# {{FRAMEWORK_ANALYSIS}}（条件：framework_analysis.json inferred_endpoints 非空）。
# 守铁律（CLAUDE.md §1）：注入源仅限 LLM 轨产物（recon md + pre-recon 代码层推断），
# 绝不引 GitNexus 确定性层产物。
_VULN_AGENT_NAMES = frozenset({
    AgentName.INJECTION_VULN,
    AgentName.XSS_VULN,
    AgentName.SSRF_VULN,
    AgentName.AUTHZ_VULN,
    AgentName.AUTH_VULN,
})


def _is_vuln_agent(agent_name: AgentName) -> bool:
    return agent_name in _VULN_AGENT_NAMES


def _make_recon_summary_llm_client(repo_path: str, provider_config: dict | None = None,
                                   audit_session=None):   # P3c 阶段 1 + spec 2026-08-27 §8
    """LLM client for summarize_recon_context（记账版）。

    Always attempts an LLM call (not gated by GitNexus-LLM toggle, since the
    summarizer belongs to the LLM track, not GitNexus). When the LLM provider
    itself is unavailable, run_claude_prompt raises and the summarizer degrades
    gracefully to the deterministic six-section extraction (non-fatal).

    spec 2026-08-27 §8：AccountedLlmClient 包装——cost/tokens 此前被闭包剥 str
    时整笔丢弃；调用方用完须 ``await client.finalize()``（agent_name=
    recon-summary）。audit_session=None → 纯透传（兼容旧行为）。
    """
    from supernova_core.agents.llm_accounting import AccountedLlmClient

    async def _runner(prompt: str, **kwargs):
        return await run_claude_prompt(
            prompt=prompt, repo_path=repo_path, model_tier="medium",
            provider_config=provider_config,
        )
    return AccountedLlmClient(_runner, audit_session, "recon-summary")


def _recon_narration_language(input: ActivityInput) -> str:
    """Resolve the digest cache's language dimension without mutating process env."""
    return (input.env_overrides or {}).get(
        "SUPERNOVA_AGENT_NARRATION_LANG",
        os.getenv("SUPERNOVA_AGENT_NARRATION_LANG", "zh"),
    )


# 端点对账降级阈值（spec 2026-09-01 §4.3）：digest endpoints 行数 / §4 表行数
# 低于此值 → degraded(coverage_low)，resume 自动重试升级。模块级常量，不进 env。
_COVERAGE_LOW_THRESHOLD = 0.8


def _load_recon_context_digest(
    deliverables: Path,
    *,
    source_hash: str,
    language: str,
    require_llm: bool = False,
) -> dict | None:
    """Load a compatible shared recon-context digest, or return None as a miss.

    ``require_llm=True``（resume 升级路径）只拒绝 degraded digest——
    ``coverage_low`` / ``unsectioned`` 的 llm-summary 不认（重新生成升级）；
    deterministic-extract 是非 degraded 有效终态（spec 2026-09-01 §4.4/§4.6）。
    """
    path = resolve_intermediate(deliverables, "recon_context_digest.json")
    if path is None:
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("text"), str):
        return None
    if not isinstance(data.get("sections"), dict):
        return None
    if data.get("schema_version") != 2:
        return None
    if data.get("source_hash") != source_hash:
        return None
    if data.get("summarizer_prompt_version") != RECON_CONTEXT_SUMMARIZER_PROMPT_VERSION:
        return None
    if data.get("language") != language:
        return None
    if require_llm and data.get("degraded"):
        return None
    return data


def _write_recon_context_digest(
    deliverables: Path,
    *,
    source_hash: str,
    language: str,
    text: str,
    source: str,
    sections: dict[str, str],
    degraded: bool,
    degraded_reason: str | None,
    coverage: dict,
    missing_sections: list[str],
    input_meta: dict,
) -> None:
    atomic_write_json(
        intermediate_path(deliverables, "recon_context_digest.json"),
        {
            "schema_version": 2,
            "source": source,
            "degraded": degraded,
            "degraded_reason": degraded_reason,
            "source_hash": source_hash,
            "summarizer_prompt_version": RECON_CONTEXT_SUMMARIZER_PROMPT_VERSION,
            "language": language,
            "input_meta": input_meta,
            "coverage": coverage,
            "missing_sections": missing_sections,
            "text": text,
            "sections": sections,
        },
    )


@activity.defn
async def run_recon_context_digest(input: ActivityInput) -> dict:
    """Generate the LLM-track recon context once for all vuln agents.

    Previously every vuln activity independently summarized the same
    ``recon_deliverable.md``.  This activity moves that call ahead of the vuln
    fan-out and persists an atomically-written digest (schema v2: six-section
    views + endpoint-coverage reconciliation + degraded/resume-upgrade,
    spec 2026-09-01).  The input remains an LLM-track product only; no GitNexus
    deterministic artifacts are consumed.
    """
    from supernova_whitebox.audit.session_registry import get_audit_session

    await ensure_audit_session(input)
    repo, deliverables, _ = _get_paths(input)
    recon_md_path = deliverables / "recon_deliverable.md"
    try:
        recon_md = recon_md_path.read_text(encoding="utf-8") if recon_md_path.exists() else ""
    except OSError as exc:
        logger.warning("recon-context-digest: read recon failed, using empty context: %s", exc)
        recon_md = ""

    source_hash = hashlib.sha256(recon_md.encode("utf-8")).hexdigest()
    language = _recon_narration_language(input)

    async with get_audit_session().track_step(
            "recon", "recon-context-digest",
            intent=intent_for("recon-context-digest")):
        cached = _load_recon_context_digest(
            deliverables, source_hash=source_hash, language=language,
            require_llm=bool(recon_md.strip()))
        if cached is not None:
            return {
                "source": cached["source"],
                "cache_hit": True,
                "recon_context_chars": len(cached["text"]),
                "degraded": cached.get("degraded", False),
                "degraded_reason": cached.get("degraded_reason"),
            }

        digest_text = ""
        digest_source = "deterministic-extract"
        degraded = False
        degraded_reason: str | None = None
        sections: dict[str, str] = {}
        coverage: dict = {"digest_endpoint_rows": None, "coverage_ratio": None}
        # 对账仅对 llm-summary 生效（spec §4.4）；deterministic 模式 coverage 不适用。
        _, input_meta = build_summarizer_input(recon_md)
        llm_client = None
        if recon_md.strip():
            try:
                llm_client = _make_recon_summary_llm_client(
                    str(repo), provider_config=input.provider_config,
                    audit_session=get_audit_session())
                digest_text = await summarize_recon_context(
                    recon_md, llm_client, fallback_on_error=False)
                if not digest_text.strip():
                    # Empty/blank output is not a clean LLM digest — deterministic
                    # fallback so all five agents get a usable shared context.
                    raise ValueError("empty llm summary output")
                digest_source = "llm-summary"
                sections = parse_sections(digest_text)
                if not sections:
                    degraded, degraded_reason = True, "unsectioned"
                digest_rows = sum(
                    1 for ln in sections.get("endpoints", "").splitlines()
                    if ln.strip())
                ratio = digest_rows / max(input_meta["source_endpoint_rows"], 1)
                coverage = {
                    "digest_endpoint_rows": digest_rows,
                    "coverage_ratio": ratio,
                }
                if not degraded and ratio < _COVERAGE_LOW_THRESHOLD:
                    degraded, degraded_reason = True, "coverage_low"
                    logger.warning(
                        "recon-context-digest: endpoint coverage %.2f below %.2f, "
                        "marked degraded (resume will retry)", ratio,
                        _COVERAGE_LOW_THRESHOLD)
            except Exception as exc:  # noqa: BLE001 — summary is non-fatal
                logger.warning(
                    "recon-context-digest: LLM summary failed, deterministic fallback: %s", exc)
                digest_source = "deterministic-extract"
                degraded, degraded_reason = False, None
                sections = build_deterministic_sections(recon_md)
                digest_text = extract_recon_context_sections(recon_md)
                coverage = {"digest_endpoint_rows": None, "coverage_ratio": None}
            finally:
                if llm_client is not None:
                    try:
                        await llm_client.finalize()
                    except Exception:  # noqa: BLE001 — accounting must not block context
                        pass
        else:
            digest_text = "(no recon deliverable available)"
            digest_source = "empty-recon"

        missing_sections = [n for n in DIGEST_SECTION_ORDER if n not in sections]
        _write_recon_context_digest(
            deliverables,
            source_hash=source_hash,
            language=language,
            text=digest_text,
            source=digest_source,
            sections=sections,
            degraded=degraded,
            degraded_reason=degraded_reason,
            coverage=coverage,
            missing_sections=missing_sections,
            input_meta=input_meta,
        )
        return {
            "source": digest_source,
            "cache_hit": False,
            "recon_context_chars": len(digest_text),
            "degraded": degraded,
            "degraded_reason": degraded_reason,
        }


def _render_digest_context(digest: dict) -> str:
    """digest → {{RECON_CONTEXT}}：sections 非空按固定节序重组，否则退 text 全文。

    第一期不按 agent_name 路由——五个 vuln agent 拿同一份完整分节摘要
    （spec 2026-09-01 §4.4；分发差异化是二期期权）。
    """
    sections = digest.get("sections") or {}
    if not sections:
        return digest["text"]
    parts = [
        f"## {name}\n{sections[name].strip()}"
        for name in DIGEST_SECTION_ORDER if name in sections
    ]
    if UNPARSED_SECTION in sections:
        parts.append(f"## additional\n{sections[UNPARSED_SECTION].strip()}")
    return "\n\n".join(parts)


async def _build_vuln_prompt_variables(
    input: ActivityInput, base: dict
) -> dict:
    """Inject shared recon prior knowledge into vuln prompt_variables.

    - RECON_CONTEXT: read from the once-per-scan digest generated by
      ``run_recon_context_digest``. Missing digest retains the deterministic
      six-section deterministic extraction compatibility path (no per-agent LLM call).
    - FRAMEWORK_ANALYSIS: from framework_analysis.json — injected ONLY when
      inferred_endpoints is non-empty (whitebox samples are often empty).
    Both sources are LLM-track / code-layer pre-recon output — NEVER GitNexus
    deterministic-layer (CLAUDE.md §1 ironclad rule).
    """
    _, deliverables, _ = _get_paths(input)

    recon_md_path = deliverables / "recon_deliverable.md"
    try:
        recon_md = recon_md_path.read_text("utf-8") if recon_md_path.exists() else ""
    except OSError:
        recon_md = ""

    digest = _load_recon_context_digest(
        deliverables,
        source_hash=hashlib.sha256(recon_md.encode("utf-8")).hexdigest(),
        language=_recon_narration_language(input),
    )
    if digest is not None:
        base["RECON_CONTEXT"] = _render_digest_context(digest)
    else:
        # Compatibility path for direct activity invocation / deployment drift.
        # This is deterministic and never triggers a per-agent LLM summary.
        base["RECON_CONTEXT"] = (
            extract_recon_context_sections(recon_md)
            if recon_md.strip()
            else "(no recon deliverable available)"
        )

    # FRAMEWORK_ANALYSIS: conditional — only when inferred_endpoints non-empty
    fw_path = resolve_intermediate(deliverables, "framework_analysis.json")  # tiering 双路径
    fw_lines: list[str] = []
    if fw_path is not None:
        try:
            fw = json.loads(fw_path.read_text("utf-8"))
            endpoints = fw.get("inferred_endpoints", []) or []
            if endpoints:
                fw_lines.append(
                    "Framework-inferred endpoints (auto-generated, verify each):"
                )
                for ep in endpoints:
                    fw_lines.append(
                        f"- {ep.get('method', '?')} {ep.get('path', '?')} "
                        f"[source={ep.get('source', '?')}, "
                        f"middleware={ep.get('middleware', [])}]"
                    )
        except (json.JSONDecodeError, OSError):
            pass  # non-fatal
    base["FRAMEWORK_ANALYSIS"] = "\n".join(fw_lines) if fw_lines else ""

    return base


@activity.defn
async def log_phase_start_activity(input: ActivityInput, steps: list[str] | None = None,
                                   intents: list[str] | None = None) -> None:
    from supernova_whitebox.audit.session_registry import get_audit_session
    await ensure_audit_session(input)  # worker 重启后可观测恢复(幂等;见 session_recovery.py)
    phase = input.phase or input.workspace_name or "unknown"
    await get_audit_session().log_phase_start(
        phase, steps=tuple(steps or ()), step_intents=tuple(intents or ()))


@activity.defn
async def log_phase_complete_activity(input: ActivityInput) -> None:
    """Emit a phase-complete event.

    Scheduled by ``WhiteboxScanWorkflow.run()`` at the end of each phase
    (setup / pre-recon / recon / risk-scoring / vulnerability-analysis /
    attack-chain / reporting) to surface phase completion, mirroring the
    phase-start event emitted by ``log_phase_start_activity``.
    """
    from supernova_whitebox.audit.session_registry import get_audit_session
    await ensure_audit_session(input)  # worker 重启后可观测恢复(幂等;见 session_recovery.py)
    phase = input.phase or input.workspace_name or "unknown"
    await get_audit_session().log_phase_complete(phase)


def _entry_points_brief(
    http_route_count: int, entry_point_total: int,
    route_table: str | None = None, max_routes: int = 120,
) -> str:
    """spec-1a T4: 格式化 entry_points_summary 给 explore prompt。

    除计数外携带已识别路由表（METHOD route @ file:line），防止探索 agent 因缺少
    起点而扫描 sibling repos/全局 registry（2026-09-09 identity 实证：30/33 routes
    已识别，但 prompt 只有 count，agent 从 /root/.gitnexus/registry.json 开始跨仓）。
    超大仓按输入序截断，同时保留计数说明。
    """
    header = (
        f"{http_route_count} http_route / {entry_point_total} total entry points"
        if (http_route_count or entry_point_total)
        else "0 http_route / 0 total (deterministic layer identified no entry points; grep routes yourself)"
    )
    if not route_table or route_table.startswith("("):
        return header
    lines = [line for line in route_table.splitlines() if line.strip()]
    if len(lines) <= max_routes:
        return f"{header}\n" + "\n".join(lines)
    omitted = len(lines) - max_routes
    return (
        f"{header}\n" + "\n".join(lines[:max_routes]) + "\n"
        f"- ... {omitted} more identified routes omitted; grep within the target repo for the rest"
    )


@activity.defn
async def log_info_activity(input: ActivityInput) -> None:
    from supernova_whitebox.audit.session_registry import get_audit_session
    await ensure_audit_session(input)  # worker 重启后可观测恢复(幂等;见 session_recovery.py)
    try:
        await get_audit_session().log_info(input.info_message, input.info_level)
    except Exception:
        pass  # best-effort: 显示侧通道失败绝不影响扫描（尤其 except 块里调，避免替换原异常）


@activity.defn
async def persist_completed_agents(input: ActivityInput, completed_agents: list[str]) -> None:
    """completed_agents 增量落盘 session.json（2026-08-27 列表进度不动修复 · 写侧）。

    原只在 workflow 结束（finalize_summary）落盘 → 运行中 session.json 恒 []，
    progress_pct 分子不动（列表/详情/仪表盘阶段内钉死）。workflow 在每个 agent
    完成点调本 activity 落盘（Temporal workflow 禁 IO）。异常上抛由 workflow 侧
    _persist_progress 吞（best-effort：进度失败不阻塞扫描）。

    session.json 缺失（异常路径）时 no-op——update_session 对缺失文件会写出只含
    completed_agents 的残缺 session，破坏后续读取。
    """
    from supernova_core.session import SessionManager
    scan_dir = Path(input.workspace_path)
    if not (scan_dir / "session.json").exists():
        return
    SessionManager(scan_dir.parent).update_session(
        scan_dir, {"completed_agents": list(completed_agents)})


@activity.defn
async def write_track_status_activity(input: ActivityInput) -> dict:
    """Task 4 fail-fast: 写 gitnexus_track_status.json(workflow->activity->helper).

    Task 1 helper 的薄 activity 包装: workflow 在两 GitNexus activity(authz_judge /
    chain_verdict)执行后, 汇总 per-class 状态(inj/xss/ssrf + authz), 经本 activity
    落盘 gitnexus_track_status.json. merger/report 读它做开轨标红; workflow 读
    返回值决定关轨终止(关轨 + DEGRADABLE fail).

    铁律 (CLAUDE.md §1): 状态产物只给 workflow/merger/report 编排用, 绝不喂 LLM 轨 prompt.
    activity 不直接写文件 -- 调 Task 1 的 write_track_status helper (守「不假估算」).
    """
    from supernova_core.code_index.gitnexus_track_status import write_track_status
    _, deliverables, _ = _get_paths(input)
    write_track_status(deliverables, getattr(input, "track_statuses", {}))
    return {"written": True}


def _verdict_agent_failure_reason(result) -> str | None:
    """失败 verdict result 的统一可读原因。

    max-turns 不抛异常，而是返回 success=False + error_code=ExecutionLimitError
    （error 可能为 None）。caller 必须显式检查 success，否则空 text 会被当
    parse warning 降级，且 step cache 误标成功。
    """
    if result.success:
        return None
    if result.error:
        return str(result.error)
    if result.error_code:
        return str(result.error_code)
    stop_reason = getattr(result, "stop_reason", None)
    return f"verdict agent unsuccessful (stop_reason={stop_reason or 'unknown'})"


def _parse_gitnexus_verdict_output(raw, id_prefix):
    """补缺 ID 的 GitNexus 轨 verdict/explore 输出 → parse_lenient → (vulns, warnings)。

    探索/判定 agent 产出的候选可能缺 ID(authz_gitnexus_explore prompt schema 无 ID
    字段),而 BaseVulnerability.ID 必填 → parse_lenient 校验丢弃 → 静默落地 0
    (回归 hr_20260713:agent 找到 4 个候选,authz_gitnexus_queue.json 落地 0)。
    这里在 parse 前给缺 ID 的条目补序列化 ID(如 AUTHZ-GN-EXPLORE-01),防静默丢数据。

    warnings 由 parse_lenient 产出(dropped 计数等);callers MUST 打日志
    (守 queue_schemas.parse_lenient docstring 的 "callers MUST surface, never silent")。
    """
    from supernova_core.models.queue_schemas import VulnerabilityQueue
    raw_str = raw if isinstance(raw, str) else (json.dumps(raw) if raw is not None else "{}")
    try:
        data = json.loads(raw_str)
        vulns = data.get("vulnerabilities") if isinstance(data, dict) else None
        if isinstance(vulns, list):
            for idx, v in enumerate(vulns):
                if isinstance(v, dict) and not v.get("ID"):
                    v["ID"] = f"{id_prefix}{idx + 1:02d}"
            raw_str = json.dumps(data)
    except (json.JSONDecodeError, ValueError, TypeError):
        pass  # raw 非 JSON → parse_lenient 以 invalid_json 形式兜底
    parsed = VulnerabilityQueue.parse_lenient(raw_str)
    return list(parsed.queue.vulnerabilities), parsed.warnings


@activity.defn
async def run_authz_gitnexus_judge(input: ActivityInput) -> dict:
    """GitNexus track LLM chain-judgement pass for authz (spec §5.7).

    1. Build IDOR candidates from code_index.json + framework_analysis.json
       (dominance heuristic + framework auto-generated).
    2. If candidates exist, render them into the authz_gitnexus_judge prompt
       and call run_claude_prompt (single call, structured JSON output).
    3. Parse the LLM verdicts leniently, tag each with source_track="gitnexus"
       + evidence_chain (the candidate path), write authz_gitnexus_queue.json.

    No candidates → write empty queue, skip the LLM call (save cost).
    Lenient on LLM output: invalid JSON → empty queue, no crash.

    This writes ONLY authz_gitnexus_queue.json (never authz_exploitation_queue.json
    — that's the LLM track's; Plan 3 merges them). It does NOT go through
    executor.execute (no git checkpoint, no validator, no auto queue write).
    """
    from supernova_whitebox.audit.session_registry import get_audit_session
    await ensure_audit_session(input)  # worker 重启后可观测恢复(幂等;见 session_recovery.py)
    from supernova_core.code_index.authz_gitnexus_track import build_authz_gitnexus_track
    from supernova_core.models.queue_schemas import VulnerabilityQueue

    try:
        failed = False
        fail_reason: str | None = None
        async with get_audit_session().track_step(
            "vulnerability-analysis", "authz-gitnexus-judge",
            intent=intent_for("authz-gitnexus-judge"),
        ):
            repo, deliverables, _ = _get_paths(input)
            # step cache（spec 2026-08-27-web-resume-breakpoint §4.3）：输入指纹
            # （code_index/framework_analysis，均产自 pre-recon 守卫块、块后无人
            # 覆写）全匹配 → 跳过候选轨重建与判定 agent，还原缓存返回值。
            _cache_inputs = [
                intermediate_path(deliverables, "code_index.json"),
                intermediate_path(deliverables, "framework_analysis.json"),
            ]
            _skip, _cached = should_skip(
                STEP_AUTHZ_GITNEXUS_JUDGE, deliverables, inputs=_cache_inputs)
            if _skip:
                logger.info("authz-gitnexus-judge: step cache 命中，跳过判定（输入指纹一致）")
                return _cached
            try:
                md, dom_cands, fw_cands, http_route_count, entry_point_total = build_authz_gitnexus_track(str(deliverables))
            except Exception as exc:
                failed = True
                fail_reason = f"build_authz_gitnexus_track failed: {exc}"
                logger.warning("authz gitnexus build track failed: %s", exc)
                # tiering：*_gitnexus_queue.json 属中间产物 → 桶内 intermediate/
                atomic_write_json(
                    intermediate_path(deliverables, "authz_gitnexus_queue.json"),
                    {"vulnerabilities": []})
                return {"candidate_count": 0, "verdict_count": 0, "dominance_candidates": 0,
                        "framework_candidates": 0, "failed": True, "fail_reason": fail_reason}
            candidate_count = len(dom_cands) + len(fw_cands)

            # 可观测性（spec §3.2）：GitNexus 轨候选状态经 InfoEvent 通道，避免静默空转。
            # best-effort：显示通道失败绝不影响扫描（对齐 log_info_activity 防御）。
            try:
                _session = get_audit_session()
                if candidate_count == 0:
                    await _session.log_info(
                        f"authz GitNexus 轨：0 候选（dominance={len(dom_cands)}, "
                        f"framework={len(fw_cands)}；http_route 入口点="
                        f"{http_route_count}/{entry_point_total}）→ 进入自主探索分支"
                        f"（GitNexus 轨内部补召回）。",
                        "warning",
                    )
                else:
                    await _session.log_info(
                        f"authz GitNexus 轨：{candidate_count} 候选（dominance="
                        f"{len(dom_cands)}, framework={len(fw_cands)}）→ 调 LLM 判定。",
                        "info",
                    )
            except Exception:
                pass

            vulnerabilities: list[dict] = []
            # prompt_manager 两分支共用（T4：0 候选探索分支也要加载 explore prompt）。
            prompts_dir = Path(__file__).resolve().parents[5] / "prompts"
            prompt_manager = PromptManager(prompts_dir)
            if candidate_count > 0:
                prompt = prompt_manager.load_sync(
                    "authz_gitnexus_judge",
                    variables={
                        "authz_gitnexus_candidates": md,
                        "repo_root": str(repo),
                    },
                )
                try:
                    result = await run_gitnexus_verdict_agent(
                        prompt=prompt,
                        repo_path=str(repo),
                        structured_output_schema=_authz_output_schema(),
                        audit_session=get_audit_session(),
                        provider_config=input.provider_config,   # P3c 阶段 1
                    )
                except Exception as exc:
                    failed = True
                    fail_reason = f"verdict agent failed: {exc}"
                    logger.warning("authz gitnexus verdict agent failed: %s", exc)
                    vulnerabilities = []
                else:
                    fail_reason = _verdict_agent_failure_reason(result)
                    if fail_reason:
                        failed = True
                        logger.warning(
                            "authz gitnexus verdict agent failed: %s", fail_reason)
                        vulnerabilities = []
                    else:
                        raw = result.structured_output
                        if raw is None and result.text:
                            raw = result.text
                        gn_vulns, gn_warnings = _parse_gitnexus_verdict_output(
                            raw, "AUTHZ-GN-")
                        for v in gn_vulns:
                            data = v.model_dump()
                            data["source_track"] = "gitnexus"
                            if not data.get("evidence_chain"):
                                data["evidence_chain"] = (
                                    "gitnexus track candidate (dominance/framework)")
                            vulnerabilities.append(data)
                        if gn_warnings:
                            try:
                                await get_audit_session().log_info(
                                    f"authz GitNexus 轨：parse warnings (candidate>0): {gn_warnings}",
                                    "warning",
                                )
                            except Exception:
                                pass

                        try:
                            await get_audit_session().log_info(
                                f"authz GitNexus 轨：产出 {len(vulnerabilities)} 条 verdict。",
                                "info",
                            )
                        except Exception:
                            pass
            else:
                # spec-1a G2：0 候选不静默写空 queue——多轮 agent 自主探索仓库找 IDOR。
                # 确定性层常因入口点未识别（语言误判/调用图未就绪/纯静态页）漏召回，
                # agent 自主 grep route + read handler 补候选（软候选，needs_review=True）。
                explore_prompt = prompt_manager.load_sync(
                    "authz_gitnexus_explore",
                    variables={
                        "repo_root": str(repo),
                        "entry_points_summary": _entry_points_brief(
                            http_route_count, entry_point_total,
                            route_table=_load_route_table(deliverables),
                        ),
                    },
                )
                try:
                    result = await run_gitnexus_verdict_agent(
                        prompt=explore_prompt,
                        repo_path=str(repo),
                        structured_output_schema=_authz_output_schema(),
                        audit_session=get_audit_session(),
                        provider_config=input.provider_config,   # P3c 阶段 1
                    )
                except Exception as exc:
                    failed = True
                    fail_reason = f"explore agent failed: {exc}"
                    logger.warning("authz gitnexus explore agent failed: %s", exc)
                    vulnerabilities = []
                else:
                    fail_reason = _verdict_agent_failure_reason(result)
                    if fail_reason:
                        failed = True
                        logger.warning(
                            "authz gitnexus explore agent failed: %s", fail_reason)
                        vulnerabilities = []
                    else:
                        raw = result.structured_output
                        if raw is None and result.text:
                            raw = result.text
                        gn_vulns, gn_warnings = _parse_gitnexus_verdict_output(
                            raw, "AUTHZ-GN-EXPLORE-")
                        for v in gn_vulns:
                            data = v.model_dump()
                            data["source_track"] = "gitnexus"
                            # 探索发现，软候选（未经确定性 dominance 验证）。
                            data["needs_review"] = True
                            if not data.get("evidence_chain"):
                                data["evidence_chain"] = (
                                    "gitnexus explore-discovered "
                                    "(0 deterministic candidates)")
                            vulnerabilities.append(data)
                        if gn_warnings:
                            try:
                                await get_audit_session().log_info(
                                    f"authz GitNexus 轨（探索）：parse warnings: {gn_warnings}",
                                    "warning",
                                )
                            except Exception:
                                pass

                        try:
                            await get_audit_session().log_info(
                                f"authz GitNexus 轨（探索）：0 确定性候选 → 自主探索产出 "
                                f"{len(vulnerabilities)} 条软候选（needs_review=True）。",
                                "info",
                            )
                        except Exception:
                            pass

            atomic_write_json(
                intermediate_path(deliverables, "authz_gitnexus_queue.json"),
                {"vulnerabilities": vulnerabilities},
            )
            _ret = {
                "candidate_count": candidate_count,
                "verdict_count": len(vulnerabilities),
                "dominance_candidates": len(dom_cands),
                "framework_candidates": len(fw_cands),
                "failed": failed,
                "fail_reason": fail_reason,
            }
            # step cache：干净完成（failed=False）才打点（§4.3——agent 失败降级
            # failed=True 不打，resume=再试一次）。
            if not failed:
                mark_done(
                    STEP_AUTHZ_GITNEXUS_JUDGE, deliverables,
                    inputs=_cache_inputs,
                    outputs=[intermediate_path(
                        deliverables, "authz_gitnexus_queue.json")],
                    ret=_ret)
            return _ret
    except PentestError as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e
    except Exception as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e


@activity.defn
async def run_credential_check(input: ActivityInput) -> None:

    from supernova_whitebox.audit.session_registry import get_audit_session
    await ensure_audit_session(input)  # worker 重启后可观测恢复(幂等;见 session_recovery.py)
    try:
        async with get_audit_session().track_step("setup", "credential-check", intent=intent_for("credential-check")):
            # P3c 阶段 1：web 穿线优先（input.provider_config），CLI 兜底 build from env。
            from supernova_core.agents.providers import build_provider_config
            from supernova_core.agents.runner import ProviderConfig

            if input.provider_config:
                config = ProviderConfig(**input.provider_config)
            else:
                config = build_provider_config(api_key=input.api_key or None)
            # 不再对「anthropic_api + 无 api_key」特殊跳过：glm-anthropic 走 auth_token
            # （validate_credentials 新增 Bearer 预检分支），凭据全空（web 不 load_env 错配）
            # 由 validate_credentials fail-fast。避免静默放行后 worker 满屏 "Not logged in"。
            await validate_credentials(
                config.type,
                api_key=config.api_key,
                base_url=config.base_url,
                auth_token=config.auth_token,
                model=config.large_model or config.medium_model or config.model,
            )
    except PentestError as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e
    except Exception as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e


@activity.defn
async def run_code_index(input: ActivityInput) -> dict:
    from supernova_whitebox.audit.session_registry import get_audit_session
    await ensure_audit_session(input)  # worker 重启后可观测恢复(幂等;见 session_recovery.py)
    try:
        import logging
        from supernova_core.code_index import build_code_index_with_gitnexus, write_index_files
        from supernova_core.code_index.gitnexus_mcp import GitNexusMCPClient

        logger = logging.getLogger(__name__)

        repo, deliverables, _ = _get_paths(input)

        async with get_audit_session().track_step("pre-recon", "code-index", intent=intent_for("code-index")):
            # Create LLM client for taint analysis (+ LLM sink discovery)
            def _make_gitnexus_llm_client(repo_path: str, provider_config: dict | None = None):   # P3c 阶段 1：透传 run_claude_prompt
                """封装 run_claude_prompt 成 analyze_taint_llm/discover 期望的
                async (prompt, output_format=None)->str 契约。

                output_format（JSON Schema）透传给 run_claude_prompt -> CLI --json-schema
                强制模型吐合法 JSON + SDK structured_output 预解析（对齐 TS outputFormat 通道，
                根因治本：GLM 不再返回 Markdown 文本致 json.loads 崩）。优先返回
                structured_output（json.dumps 成 str 保持契约）；空则回退 result.text，由下游
                _extract_json_payload + 各自 fallback 兜底（三重防线）。

                env 关时返回 None → consumer 入口各自静默降级(discover_sinks/sources 早退返回空,
                analyze_taint_llm 走 deterministic fallback), 不再跑 N 个无用的 raise-task 刷屏。"""
                if not is_gitnexus_llm_enabled():
                    return None

                async def _client(prompt: str, **kwargs) -> str:
                    result = await run_claude_prompt(
                        prompt=prompt, repo_path=repo_path, model_tier="medium",
                        structured_output_schema=kwargs.get("output_format"),
                        provider_config=provider_config,
                    )
                    # structured_output 由 provider 填充（SDK 原生优先，缺失时 _extract_json_payload
                    # 从 collected_text 兜底）。非空时它是已解析的 dict/list，json.dumps 还原成 str
                    # 契约供下游 parse。空 → 回退 .text（下游 _extract_json_payload + fallback）。
                    so = result.structured_output
                    if so is not None:
                        import json as _json
                        return _json.dumps(so)
                    return result.text
                return _client

            _llm_taint_client = _make_gitnexus_llm_client(str(repo), provider_config=input.provider_config)   # P3c 阶段 1
            # discovery 多轮 agent（spec 2026-08-27 §5）：sink/source/storage 补召回
            # 走逐 chunk 多轮 agent（自主 Read 源码 / Grep 追 callee）；taint 分析
            # 仍走单次 llm_client（per-function 批量分类器，多轮成本不可行）。
            # agent_name 由 discovery 层传 gn-discovery-{kind}-NNN 前缀（记账唯一）。
            _discovery_agent = None
            if is_gitnexus_llm_enabled():
                _discovery_agent = _make_verdict_agent_runner(
                    str(repo), provider_config=input.provider_config,
                    audit_session=get_audit_session())

            # --- GitNexus integration ---
            # GitNexus MCP serves ALL indexed repos from its global registry
            # (~/.gitnexus/registry.json).  The correct order is:
            #   1. `gitnexus analyze <repo>`  — index & register the repo
            #   2. `gitnexus mcp`             — start MCP server (no --repo flag)
            # If GitNexus is unavailable, indexing fails, or MCP fails, we raise PentestError — no degradation.
            from supernova_core.code_index.gitnexus_engine import GitNexusEngine

            engine = GitNexusEngine(Path(repo))
            if not engine.is_available():
                raise PentestError(
                    "GitNexus CLI not available, cannot build code index. "
                    "Install with: npm install -g gitnexus",
                    category="code_index", error_code=ErrorCode.CODE_INDEX_FAILED,
                )
            result = await engine.ensure_indexed_async()
            if not result.success:
                raise PentestError(
                    f"GitNexus indexing failed: {result.error_message}. "
                    "Code index requires a working GitNexus index.",
                    category="code_index", error_code=ErrorCode.CODE_INDEX_FAILED,
                )

            try:
                # resolve medium-tier model 名(spec 2026-07-10): 传给 discovery 做 chunk
                # threshold 派生(按模型 context 自适应)。不裸读 SUPERNOVA_MODEL(=large tier,
                # 与 gitnexus 轨实际用的 medium tier 错配会估大 context 致爆)。resolve 失败
                # -> None -> discovery 走默认 context, 不阻断。
                from supernova_core.agents.providers import build_provider_config, resolve_tier_model
                from supernova_core.agents.runner import ProviderConfig
                try:
                    # P3c 阶段 1：web 穿线优先（input.provider_config），CLI 兜底 build from env。
                    if input.provider_config:
                        _pcfg = ProviderConfig(**input.provider_config)
                    else:
                        _pcfg = build_provider_config(api_key=input.api_key or None)
                    _medium_model = resolve_tier_model(_pcfg, "medium")
                except Exception:
                    _medium_model = None

                async with GitNexusMCPClient(Path(repo)) as mcp:
                    index, rule_gaps, source_gaps, storage_gaps = await build_code_index_with_gitnexus(
                        str(repo),
                        mcp_client=mcp,
                        llm_client=_llm_taint_client,
                        discovery_agent=_discovery_agent,
                        auto_index=False,
                        progress_cb=_make_gitnexus_progress_cb(get_audit_session()),
                        model=_medium_model,
                    )
            except PentestError:
                raise
            except ConnectionError as exc:
                # MCP 子进程冷启动/握手超时是并发负载下的瞬时环境错误（真机
                # NodeGoat-20260821-044404：LLM subagent 抢 CPU，node 冷启动 >30s，
                # initialize 读超时）。retryable=True 让 CODE_INDEX_RETRY 重试——
                # 重试时 node 二进制已进 page cache，二次启动快；仍失败才真死。
                # engine 不可用/索引失败等配置类错误不在此列，保持 non-retryable。
                raise PentestError(
                    f"GitNexus MCP query failed: {exc}. "
                    "Code index requires a working GitNexus MCP connection.",
                    category="code_index", error_code=ErrorCode.CODE_INDEX_FAILED,
                    retryable=True,
                ) from exc
            except Exception as exc:
                raise PentestError(
                    f"GitNexus MCP query failed: {exc}. "
                    "Code index requires a working GitNexus MCP connection.",
                    category="code_index", error_code=ErrorCode.CODE_INDEX_FAILED,
                ) from exc

            json_path, summary_path = write_index_files(
                index, str(deliverables),
                rule_gaps=rule_gaps, source_gaps=source_gaps,
                storage_gaps=storage_gaps,
            )

            # tiering 保护（git_manager.commit_index，spec 2026-08-18）：中间产物
            # 提交为跟踪文件，防并发 pre-recon agent 失败时 rollback(clean -fd)清掉
            # 未跟踪的 intermediate/（run_code_index 已成功、不在重试循环 → 永不重生，
            # 下游 fusion/merge 硬报 FileNotFoundError）。commit 失败不阻断：产物仍在
            # 盘上，读侧 resolve_intermediate 兜底。
            try:
                from supernova_core.git_manager import GitManager
                await GitManager.commit_index(deliverables)
            except Exception as exc:
                logger.warning("commit_index failed (non-fatal): %s", exc)

            # 可观测性：调用图统计。chains=0 是 GitNexus 轨空壳的核心信号
            #（→ taint_flows=0 → 3 类 builder 全空 → GitNexus 轨无结果）。
            # 对齐 06-29 authz/injection-gitnexus-track-observability 的 InfoEvent 风格。
            try:
                empty_call_graph = index.total_chains == 0
                await get_audit_session().log_info(
                    f"GitNexus code-index：blocks={index.total_blocks}, "
                    f"entry_points={index.total_entry_points}, chains={index.total_chains}, "
                    f"degradation={index.degradation_level}"
                    + (" → ⚠️ 调用图空壳（chains=0 → taint_flows=0 → GitNexus 轨将无结果）"
                       if empty_call_graph else ""),
                    "warning" if empty_call_graph else "info",
                )
            except Exception:
                pass

        return {
            "total_blocks": index.total_blocks,
            "total_entry_points": index.total_entry_points,
            "total_chains": index.total_chains,
            "json_path": str(json_path),
            "summary_path": str(summary_path),
        }
    except PentestError as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e
    except Exception as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e


@activity.defn
async def run_entry_point_fusion(input: ActivityInput) -> dict:
    """Merge deterministic entry points with LLM-discovered entry points."""
    from supernova_whitebox.audit.session_registry import get_audit_session
    await ensure_audit_session(input)  # worker 重启后可观测恢复(幂等;见 session_recovery.py)
    try:
        from supernova_core.code_index import run_entry_point_fusion as _fusion

        repo, deliverables, _ = _get_paths(input)
        async with get_audit_session().track_step("pre-recon", "entry-point-fusion", intent=intent_for("entry-point-fusion")):
            index = _fusion(str(deliverables), repo_path=str(repo))

        return {
            "total_entry_points": index.total_entry_points,
            "status": "ok",
        }
    except PentestError as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e
    except Exception as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e


@activity.defn
async def run_save_adjudication(input: ActivityInput) -> dict:
    from supernova_whitebox.audit.session_registry import get_audit_session
    await ensure_audit_session(input)  # worker 重启后可观测恢复(幂等;见 session_recovery.py)
    try:
        from supernova_core.code_index import save_adjudication

        repo, deliverables, _ = _get_paths(input)
        async with get_audit_session().track_step("pre-recon", "adjudication", intent=intent_for("adjudication")):
            save_adjudication(str(deliverables))

        return {"status": "ok"}
    except PentestError as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e
    except Exception as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e


@activity.defn
async def run_merge_sink_reports(input: ActivityInput) -> dict:
    """Merge deterministic sinks with LLM-discovered sinks from pre-recon."""
    from supernova_whitebox.audit.session_registry import get_audit_session
    await ensure_audit_session(input)  # worker 重启后可观测恢复(幂等;见 session_recovery.py)
    try:
        from supernova_core.code_index.sink_merger import merge_sink_reports
        from supernova_core.code_index.parameter_models import SinkCallSite
        from supernova_core.code_index.models import CodeIndex

        repo, deliverables, _ = _get_paths(input)

        async with get_audit_session().track_step("pre-recon", "merge-sinks", intent=intent_for("merge-sinks")):
            # Load deterministic sinks from code_index.json
            code_index_path = resolve_intermediate(deliverables, "code_index.json")  # tiering 双路径
            det_sinks: list[SinkCallSite] = []
            index = None
            if code_index_path is not None:
                index = CodeIndex.model_validate_json(code_index_path.read_text())
                det_sinks = index.sink_call_sites

            # Read LLM pre-recon deliverable
            llm_report = ""
            pre_recon_path = deliverables / "pre_recon_deliverable.md"
            if pre_recon_path.exists():
                llm_report = pre_recon_path.read_text()

            # Merge
            merged = merge_sink_reports(det_sinks, llm_report)

            # Write merged sinks back to code_index.json (reuse existing index)
            if index is not None:
                index.sink_call_sites = merged
                atomic_write_json(code_index_path, json.loads(index.model_dump_json()))

        return {
            "deterministic_count": len(det_sinks),
            "llm_only_count": len(merged) - len(det_sinks),
            "total_count": len(merged),
        }
    except PentestError as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e
    except Exception as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e


@activity.defn
async def run_merge_dual_track_queues(input: ActivityInput) -> dict:
    """Merge LLM-track and GitNexus-track vulnerability queues."""
    from supernova_whitebox.audit.session_registry import get_audit_session
    await ensure_audit_session(input)  # worker 重启后可观测恢复(幂等;见 session_recovery.py)
    try:
        from supernova_core.code_index.dual_track_merger import merge_dual_track_queues
        from supernova_core.code_index.gitnexus_track_status import read_track_status
        from supernova_core.models.queue_schemas import VulnerabilityQueue

        repo, deliverables, _ = _get_paths(input)
        # track-parity 记账 client（spec 2026-08-27 §8）：轻量调用 cost 此前被
        # client 闭包剥 str 时整笔丢弃——AccountedLlmClient 累计，循环外一次
        # finalize 记总账（agent_name=track-parity 进 phase 汇总）。包
        # _make_track_parity_client 工厂（唯一 client 定义，兼测试注入点——
        # 2026-08-31 修复：曾内联 _parity_runner 绕过工厂，测试 fake 注入失效
        # 走真 LLM）。
        from supernova_core.agents.llm_accounting import AccountedLlmClient
        _accounted_parity = AccountedLlmClient(
            _make_track_parity_client(
                str(repo) if repo else "",
                getattr(input, "provider_config", None)),
            get_audit_session(), "track-parity")
        # GitNexus 轨 per-class 状态(Task 4 写,文件缺/损坏返 {} 容错)。
        # 仅供 merger 标记 gitnexus_status + 报告标红;合并逻辑不读它(failed 类
        # 自然 gitnexus_findings=[] -> llm-only 或 continue 跳过)。
        track_status = read_track_status(deliverables)

        merged_classes: list[str] = []
        per_class_counts: dict[str, dict] = {}

        async with get_audit_session().track_step(
            "vulnerability-analysis",
            "merge-dual-track",
            intent=intent_for("merge-dual-track"),
        ):
            for vuln_class in ("injection", "xss", "ssrf", "authz", "auth"):
                # tiering 双路径读：LLM 轨 queue 由 executor auto-write 落 intermediate/，
                # GitNexus 轨写侧同迁（老 session 平铺兜底）。平铺直拼曾致 LLM 轨
                # findings 恒空 → verdict OR 丢边。
                exploitation_path = resolve_intermediate(
                    deliverables, f"{vuln_class}_exploitation_queue.json")
                gitnexus_path = resolve_intermediate(
                    deliverables, f"{vuln_class}_gitnexus_queue.json")

                # GitNexus-track findings (may exist independently of LLM track)
                gitnexus_findings = []
                if gitnexus_path is not None:
                    gitnexus_parsed = VulnerabilityQueue.parse_lenient(
                        gitnexus_path.read_text(encoding="utf-8")
                    )
                    gitnexus_findings = gitnexus_parsed.queue.vulnerabilities

                # LLM-track findings. A4: LLM queue absent -> empty list, still merge
                # (GitNexus-only must reach the report, not be dropped). Skip only
                # when BOTH tracks are empty.
                llm_findings = []
                llm_warnings = []
                if exploitation_path is not None:
                    # merge 幂等（spec 2026-08-27-web-resume-breakpoint §4.4）：
                    # agent 级 resume 跳过 vuln agent 后，exploitation 可能是
                    # merge 自己写回的合并版（卡带 merge_source 标——merger 独有，
                    # LLM agent 产的卡没有）→ LLM 输入改读首跑备份的原始件，
                    # 不二次合并、不覆盖备份（无条件备份会销毁唯一 LLM 原始件）。
                    # 无标（首跑 / ¬G agent 重跑产新件）走原件并首写备份。
                    # 备份缺失的合并版（用户手删/修复前老 session）回落原件路径，
                    # 行为等同修复前，不再恶化。
                    llm_path = intermediate_path(
                        deliverables, f"{vuln_class}_llm_queue.json")
                    _raw = exploitation_path.read_text(encoding="utf-8")
                    _parsed = VulnerabilityQueue.parse_lenient(_raw)
                    _already_merged = any(
                        getattr(f, "merge_source", None)
                        for f in _parsed.queue.vulnerabilities)
                    if _already_merged and llm_path.exists():
                        llm_parsed = VulnerabilityQueue.parse_lenient(
                            llm_path.read_text(encoding="utf-8"))
                    else:
                        # 保 LLM 轨原始副本（tier：*_llm_queue.json → intermediate/）
                        llm_path.parent.mkdir(parents=True, exist_ok=True)
                        llm_path.write_text(_raw, encoding="utf-8")
                        llm_parsed = _parsed
                    llm_findings = llm_parsed.queue.vulnerabilities
                    llm_warnings = llm_parsed.warnings
                elif not gitnexus_findings:
                    continue  # both tracks empty

                # LLM 轨同接口多参数归并（数据层，2026-08-26 用户口径：多参数
                # 不拆卡、多接口才拆卡）：SSOT 落盘前归并——黑盒 add_exploit per
                # queue ID → evidence 1 卡，白盒渲染/速查表读同一 SSOT 自动跟随。
                # 仅 taint 三类（auth/authz missing-control 每条独立漏洞不归并）。
                from supernova_core.code_index.llm_collapse import collapse_llm_entries
                llm_findings = collapse_llm_entries(llm_findings, vuln_class)

                merged = merge_dual_track_queues(
                    llm_findings,
                    gitnexus_findings,
                    mode="verdict",
                )
                # 双轨呈现一致性（spec 2026-08-26 §6）：确定性 key 配不上的同洞卡
                # 由轻量 LLM 配对归并（仅 high 应用）——两轨卡片呈现同构。配对后
                # 仍 GN-only 的卡不做 merge 内补全：叙事/评级全字段由 merge 后
                # 独立深度富化 step（run_gn_finding_enrichment，多轮读码）承担，
                # 避免同卡双重 LLM 花费。本层常开、独立于
                # SUPERNOVA_GITNEXUS_LLM_ENABLED（2026-08-26 用户口径「判定关省
                # token、双轨一致性层开」；档位开关 SUPERNOVA_GN_ENRICH_MODE 已于
                # 2026-08-31 整键移除）。LLM 不可用优雅退化（enhance 内部捕获，
                # 维持确定性 merge 结果），报告管线不因增强层阻塞。
                both_before = sum(
                    1 for f in merged if f.merge_source == "both")
                try:
                    from supernova_core.services.track_parity import (
                        enhance_track_parity,
                    )
                    merged = await enhance_track_parity(
                        merged, _accounted_parity)
                except Exception as exc:  # noqa: BLE001 — 增强层不阻塞
                    logger.warning(
                        "track-parity skipped for %s (client setup failed): %s",
                        vuln_class, exc)
                parity_paired = sum(
                    1 for f in merged if f.merge_source == "both") - both_before
                # 合并版写回 intermediate/（SSOT；下游 resolve_intermediate 优先读到合并版）
                atomic_write_json(
                    intermediate_path(deliverables, f"{vuln_class}_exploitation_queue.json"),
                    {"vulnerabilities": [finding.model_dump() for finding in merged]},
                )

                merged_classes.append(vuln_class)
                _ts = track_status.get(vuln_class, {})
                _gn_status = _ts.get("status", "absent")
                per_class_counts[vuln_class] = {
                    "llm": len(llm_findings),
                    "gitnexus": len(gitnexus_findings),
                    "merged": len(merged),
                    "both": sum(1 for finding in merged if finding.merge_source == "both"),
                    "llm_only": sum(1 for finding in merged if finding.merge_source == "llm-only"),
                    "gitnexus_only": sum(
                        1 for finding in merged if finding.merge_source == "gitnexus-only"
                    ),
                    "warnings": llm_warnings,
                    # GitNexus 轨状态(ok/failed/absent)。failed 类合并退 llm-only
                    # 或被跳过(双轨空);此处仅标红供报告,不影响合并产物。
                    "gitnexus_status": _gn_status,
                }
                if _gn_status == "failed":
                    per_class_counts[vuln_class]["gitnexus_fail_reason"] = _ts.get("reason")
                    logger.info(
                        "merge: vuln=%s GitNexus track failed (%s) - 标红供报告,合并退 llm-only",
                        vuln_class, _ts.get("reason"))
                gn_only = sum(1 for f in merged if f.merge_source == "gitnexus-only")
                if gn_only:
                    logger.info(
                        "merge: vuln=%s merged %d gitnexus-only findings (LLM track did not cover)",
                        vuln_class, gn_only)

        await _accounted_parity.finalize()  # spec 2026-08-27 §8：出口一次记账
        return {"merged_classes": merged_classes, "per_class_counts": per_class_counts}
    except PentestError as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e
    except Exception as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e


# GN-only 深度富化可回填字段（spec 2026-08-26 §6.2 deep 档）：原值为空/占位时写。
# 保护字段（externally_exploitable/verdict/flow_id/merge_source/source_track/
# affected_entries/sanitizer_annotations/ID）归确定性层与合并器，绝不覆写。
_ENRICHABLE_FIELDS = (
    "title", "notes", "severity", "impact", "remediation", "cwe_id", "cvss",
    "owasp_category", "witness_payload", "mismatch_reason", "path",
    "source_detail", "sink_function", "encoding_observed", "accessible_routes",
    "authentication_required", "dataflow_steps", "endpoints",
    "affected_parameters",
)
# chain-verdict 降级占位前缀（LLM 关/失败时的 fallback 文案）——富化输出可替换。
_DEGRADED_PREFIXES = ("llm chain-verdict pass",)

# _ENRICHABLE_FIELDS 里的 list 型字段（模型 list[str]/list[dict]）：回填守卫
# 非 list 丢弃（dataflow_steps 既有守卫 2026-09-02 扩到 endpoints/
# affected_parameters 同治——三字段同是 array 契约，守卫只护一个是漏的）。
_LIST_ENRICHABLE_FIELDS = frozenset(
    {"dataflow_steps", "endpoints", "affected_parameters"})


def _coerce_str_field(new: object) -> str | None:
    """str 字段回填类型收敛（2026-09-02 NodeGoat-045436 实翻车根因修复）。

    gn-enrich 的 structured_output_schema 是空壳（vulnerabilities: array 无
    items 约束），LLM 布尔直觉会把 authentication_required 落笔成原生 JSON
    bool（同扫描内 ssrf 类输出字符串、xss 类输出 bool 的概率性翻车），而
    模型契约是 str|None（"true"|"false" 字符串枚举，TS 移植——vuln.py
    _str_field 声明同源）。bool 保语义小写化成 "true"/"false"；其余非 str
    标量（int/float，如 cvss 给 7.6）str() 收敛；空串/复杂类型（list/dict）
    返回 None 丢弃该值——单字段畸形不值得炸整个 activity。
    """
    if isinstance(new, bool):
        return "true" if new else "false"
    if isinstance(new, str):
        return new if new.strip() else None
    if isinstance(new, (int, float)):
        return str(new)
    return None
# chain_verdict._fallback_title 的确定性形态（"{vuln_class}：{src} → {sink}"）——
# 非叙事标题，富化输出可替换（叙事 title 永不以裸类名+冒号/via 开头）。
import re as _re
_FALLBACK_TITLE_RE = _re.compile(r"^(xss|injection|ssrf)(：|: | via )", _re.IGNORECASE)


def _render_gn_only_candidates(findings: list) -> str:
    """GN-only 条目渲染成富化 prompt 的候选 markdown（确定性事实，无叙事）。"""
    lines: list[str] = []
    for f in findings:
        entries = getattr(f, "affected_entries", None) or []
        entry_rows = "\n".join(
            f"  - param={e.get('parameter')} sink_location={e.get('sink_location')}"
            for e in entries if isinstance(e, dict)) or "  (none)"
        lines.append(
            f"- ID: {f.ID}\n"
            f"  class: {getattr(f, 'vulnerability_type', None)}\n"
            f"  source: {getattr(f, 'source', None)}\n"
            f"  sink_call: {getattr(f, 'sink_call', None) or getattr(f, 'sink_function', None)}\n"
            f"  flow_id: {getattr(f, 'flow_id', None)}\n"
            f"  path: {getattr(f, 'path', None)}\n"
            f"  render_context: {getattr(f, 'render_context', None)}\n"
            f"  evidence_chain: {getattr(f, 'evidence_chain', None)}\n"
            f"  affected_entries:\n{entry_rows}"
        )
    return "\n".join(lines) or "(none)"


def _apply_gn_enrichment(findings: list, raw: object) -> tuple[int, list[str]]:
    """富化 agent 输出按 ID 回填进 findings（原地）。

    宽松解析：structured_output dict / JSON 文本皆可；逐条按 ID 匹配，白名单
    字段仅原值为 None/空/降级占位时写入。返回 (回填条数, warnings)。
    """
    warnings: list[str] = []

    def _shape(x: object) -> str:
        # 翻车时带 raw 实际形态（type + 前 200 字符）——agents log 不记最终输出
        # 文本，warning 不带内容则只能靠推断翻车原因（NodeGoat 2026-08-26 教训）。
        return f"type={type(x).__name__}, head={str(x)[:200]!r}"

    data: object = raw
    if isinstance(data, str):
        try:
            import json as _json
            data = _json.loads(data)
        except (ValueError, TypeError):
            return 0, [f"gn-enrichment: unparseable output ({_shape(raw)})"]
    if isinstance(data, list):
        # 裸数组根（NodeGoat 2026-08-26 实形态：structured_output=[{...}]，schema
        # 契约是 {"vulnerabilities":[...]}，agent 差一层包装）——适配而非整轮报废。
        data = {"vulnerabilities": data}
    if not isinstance(data, dict):
        return 0, [f"gn-enrichment: output not a JSON object ({_shape(data)})"]
    entries = data.get("vulnerabilities")
    if not isinstance(entries, list):
        return 0, [f"gn-enrichment: no vulnerabilities array ({_shape(data)})"]
    by_id = {f.ID: f for f in findings}
    enriched = 0
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        eid = str(entry.get("ID") or "")
        target = by_id.get(eid)
        if target is None:
            warnings.append(f"gn-enrichment: unknown ID {eid!r} skipped")
            continue
        data_f = target.model_dump()
        touched = False
        for field in _ENRICHABLE_FIELDS:
            new = entry.get(field)
            if field in _LIST_ENRICHABLE_FIELDS:
                if not isinstance(new, list):
                    continue
            else:
                # str 字段类型收敛（bool/数字标量 → str；畸形 → None 丢弃）。
                new = _coerce_str_field(new)
                if new is None:
                    continue
            old = data_f.get(field)
            is_degraded = (isinstance(old, str)
                           and any(old.strip().lower().startswith(p)
                                   for p in _DEGRADED_PREFIXES))
            replaceable = old in (None, "", []) or is_degraded
            if field == "title" and isinstance(old, str) and old.strip():
                replaceable = replaceable or bool(_FALLBACK_TITLE_RE.match(old.strip()))
            if replaceable:
                data_f[field] = new
                touched = True
        if touched:
            # per-entry 容错（2026-09-02 前科：单字段类型错炸整个 activity，
            # temporal 全量重跑再炸，enrichment 与 report_polish rework 两处
            # 同雷）：深层结构校验炸（如 dataflow_steps 元素非 dict）跳过该条
            # 保确定性原值，其余条目照常——对齐本 activity docstring 承诺的
            # 「失败降级为不富化」。
            try:
                findings[findings.index(target)] = type(target).model_validate(data_f)
                enriched += 1
            except ValidationError as exc:
                warnings.append(
                    f"gn-enrichment: entry {eid!r} validation failed "
                    f"(kept deterministic fields): {str(exc)[:200]}")
    if not enriched and entries:
        warnings.append("gn-enrichment: 0 findings enriched (all IDs unknown or no new fields)")
    return enriched, warnings


@activity.defn
async def run_gn_finding_enrichment(input: ActivityInput) -> dict:
    """GN-only 深度富化（spec 2026-08-26 §6.2；2026-08-26 用户口径：轻量单次
    升级为深度多轮——agent 自己 grep/read 追链，产 dataflow_steps/
    witness_payload 全字段，卡片与 LLM 轨同构）。

    位置：merge（run_merge_dual_track_queues，含 track-parity 配对）之后、
    render_findings 之前；读合并后 SSOT {vc}_exploitation_queue.json，过滤
    merge_source=="gitnexus-only" 的 taint 三类条目（authz 深判已有叙事；
    auth 无 GN 轨），逐 class 一次 run_gitnexus_verdict_agent 多轮富化，
    按 ID 回填写回同一 SSOT。

    常开（档位开关 SUPERNOVA_GN_ENRICH_MODE off/light/deep 已于 2026-08-31
    整键移除——off/light 从未被真实使用，deep 行为常开）；省 token 出口在
    SUPERNOVA_LLM_TRACK_ENABLED / SUPERNOVA_GITNEXUS_LLM_ENABLED 层面。失败
    降级为不富化（保留确定性字段），由 workflow 层 non-fatal 包裹。
    """
    from supernova_whitebox.audit.session_registry import get_audit_session
    await ensure_audit_session(input)  # worker 重启后可观测恢复(幂等)
    repo, deliverables, _ = _get_paths(input)
    from supernova_core.models.queue_schemas import VulnerabilityQueue

    prompts_dir = Path(__file__).resolve().parents[5] / "prompts"
    prompt_manager = PromptManager(prompts_dir)
    max_turns = _gn_enrich_max_turns()
    enriched_classes: dict[str, dict] = {}
    total_enriched = 0
    async with get_audit_session().track_step(
            "vulnerability-analysis", "gn-finding-enrichment",
            intent=intent_for("gn-finding-enrichment")):
        for vuln_class in ("injection", "xss", "ssrf"):
            queue_path = resolve_intermediate(
                deliverables, f"{vuln_class}_exploitation_queue.json")
            if queue_path is None or not queue_path.exists():
                continue
            parsed = VulnerabilityQueue.parse_lenient(
                queue_path.read_text(encoding="utf-8"))
            findings = list(parsed.queue.vulnerabilities)
            gn_only = [f for f in findings
                       if getattr(f, "merge_source", None) == "gitnexus-only"
                       and getattr(f, "source_track", None) == "gitnexus"]
            if not gn_only:
                continue
            prompt = prompt_manager.load_sync(
                "gn_finding_enrichment",
                variables={
                    "gn_only_candidates": _render_gn_only_candidates(gn_only),
                },
            )
            try:
                result = await run_gitnexus_verdict_agent(
                    prompt=prompt,
                    repo_path=str(repo),
                    agent_name=f"gn-enrich-{vuln_class}",
                    structured_output_schema=_gn_enrich_output_schema(),
                    audit_session=get_audit_session(),
                    provider_config=input.provider_config,   # P3c 阶段 1
                    max_turns=max_turns,
                )
            except Exception as exc:  # noqa: BLE001 — 富化失败不阻塞报告
                logger.warning(
                    "gn-finding-enrichment: %s agent failed (keep deterministic "
                    "fields): %s", vuln_class, exc)
                enriched_classes[vuln_class] = {
                    "candidates": len(gn_only), "enriched": 0,
                    "failed": str(exc)[:200]}
                continue
            raw = result.structured_output
            if raw is None and result.text:
                raw = result.text
            enriched, warnings = _apply_gn_enrichment(findings, raw)
            for w in warnings:
                logger.warning("%s (%s)", w, vuln_class)
            atomic_write_json(
                queue_path,
                {"vulnerabilities": [f.model_dump() for f in findings]},
            )
            enriched_classes[vuln_class] = {
                "candidates": len(gn_only), "enriched": enriched}
            total_enriched += enriched
            logger.info(
                "gn-finding-enrichment: %s %d/%d GN-only cards enriched",
                vuln_class, enriched, len(gn_only))
    return {"skipped": None, "enriched_classes": enriched_classes,
            "total_enriched": total_enriched}


def _gn_enrich_output_schema() -> dict:
    """gn-enrich structured_output_schema 的 items 字段级类型引导（源头治理，
    2026-09-02 NodeGoat-045436 翻车：空壳 schema——vulnerabilities: array 无
    items 约束——LLM 布尔直觉把 authentication_required 落笔成原生 bool）。

    宽松声明：只引导类型，不设 required / additionalProperties——anthropic
    引擎 --json-schema 走 AJV 协议级校验 + SDK 自纠重试，过严声明会触发
    重试循环；openai 引擎 non-strict 本就宽松。回填层类型收敛
    （_coerce_str_field）仍是两引擎统一的权威防线，此处仅减少 bool 产出。
    enrichment 与 rework 两处共用（enrichment 与 _rework_missing_narratives
    都喂 _apply_gn_enrichment）。"""
    props = {f: {"type": "string"}
             for f in _ENRICHABLE_FIELDS if f not in _LIST_ENRICHABLE_FIELDS}
    props.update({
        "ID": {"type": "string"},  # 回填主键（不在 _ENRICHABLE_FIELDS，同样引导）
        "dataflow_steps": {"type": "array", "items": {"type": "object"}},
        "endpoints": {"type": "array", "items": {"type": "string"}},
        "affected_parameters": {"type": "array", "items": {"type": "string"}},
    })
    return {
        "type": "object",
        "properties": {
            "vulnerabilities": {
                "type": "array",
                "items": {"type": "object", "properties": props},
            },
        },
    }


def _authz_output_schema() -> dict:
    """authz judge/explore structured_output_schema 的 items 字段级类型引导。

    两处原为空壳（vulnerabilities: array 无 items 约束，与 gn-enrich 2026-09-02
    翻车同款形态）：authz 输出走 _parse_gitnexus_verdict_output →
    VulnerabilityQueue.parse_lenient——单条类型错不炸 activity，但该条被丢弃
    （静默漏报），schema 引导从源头减少类型错。字段 = authz_gitnexus_judge.txt
    <output_format> 契约（explore 是其子集，无 ID——宽松声明对子集无副作用，
    缺 ID 由 _parse_gitnexus_verdict_output 回填）。注意 externally_exploitable
    契约是 bool（可达性标签，与 gn-enrich 的 str 字段相反）。宽松声明（无
    required / additionalProperties，防 anthropic AJV 过严自纠循环），对齐
    _gn_enrich_output_schema 的设计。"""
    props = {
        "ID": {"type": "string"},
        "title": {"type": "string"},
        "vulnerability_type": {"type": "string"},
        "externally_exploitable": {"type": "boolean"},
        "endpoint": {"type": "string"},
        "vulnerable_code_location": {"type": "string"},
        "role_context": {"type": "string"},
        "guard_evidence": {"type": "string"},
        "side_effect": {"type": "string"},
        "reason": {"type": "string"},
        "minimal_witness": {"type": "string"},
        "confidence": {"type": "string"},
        "notes": {"type": "string"},
    }
    return {
        "type": "object",
        "properties": {
            "vulnerabilities": {
                "type": "array",
                "items": {"type": "object", "properties": props},
            },
        },
    }


def _gn_enrich_max_turns() -> int:
    """SUPERNOVA_GN_ENRICH_MAX_TURNS（默认 100，2026-08-28 30→100：与
    endpoint enrich 同任务形态——逐卡富化 + task 委派往返，30 耗尽 →
    ExecutionLimitError 整类 0 富化）。enrichment 与 rework 两处共用。"""
    return int(os.getenv("SUPERNOVA_GN_ENRICH_MAX_TURNS", "100"))


def _endpoint_enrich_max_turns() -> int:
    """SUPERNOVA_ENDPOINT_ENRICH_MAX_TURNS（默认 100，2026-08-28 30→100：
    卡多的类 11 张逐卡钉行号链 + task 委派往返，30 turns 耗尽 →
    ExecutionLimitError 整类 0 富化）。enrichment 与 rework 两处共用。"""
    return int(os.getenv("SUPERNOVA_ENDPOINT_ENRICH_MAX_TURNS", "100"))


@activity.defn
async def run_endpoint_enrichment(input: ActivityInput) -> dict:
    """全卡接口表富化（spec 2026-08-26-report-generation-agent §5.2）。

    素材包 = 合并后 SSOT 全部卡（两轨）+ entry_points.json 路由表；per-class
    并行 run_gitnexus_verdict_agent（多轮可 grep/read），产接口一体表
    （method/path/params/auth + route_registered_at/source_location/
    sink_location 行号链），按 ID 写回 queue 的 report_endpoints 字段
    （builder 组装 report_data.json 优先采用；确定性 endpoint 兜底不受影响）。
    §4.1（spec 2026-08-26-vuln-card-seven-sections）：同 agent 扩产 per 卡
    problem_points（location/description/snippet——snippet 必须是真实读到的
    源码原文），独立校验后写回 report_problem_points。

    位置：merge 与 run_gn_finding_enrichment 之后、render_findings 之前。
    开关 SUPERNOVA_ENDPOINT_ENRICH_ENABLED（默认开——接口富化对两轨全部卡
    生效）。失败降级为不富化（non-fatal）。
    """
    from supernova_whitebox.audit.session_registry import get_audit_session
    await ensure_audit_session(input)  # worker 重启后可观测恢复(幂等)
    from supernova_core.config.concurrency import endpoint_enrich_enabled
    if not endpoint_enrich_enabled():
        return {"skipped": "disabled", "enriched_classes": {},
                "total_enriched": 0}
    repo, deliverables, _ = _get_paths(input)
    from supernova_core.models.queue_schemas import VulnerabilityQueue

    prompts_dir = Path(__file__).resolve().parents[5] / "prompts"
    prompt_manager = PromptManager(prompts_dir)
    route_table = _load_route_table(deliverables)
    max_turns = _endpoint_enrich_max_turns()

    async def _enrich_class(vuln_class: str) -> dict:
        queue_path = resolve_intermediate(
            deliverables, f"{vuln_class}_exploitation_queue.json")
        if queue_path is None or not queue_path.exists():
            return {"candidates": 0, "enriched": 0, "noop": True}
        parsed = VulnerabilityQueue.parse_lenient(
            queue_path.read_text(encoding="utf-8"))
        findings = list(parsed.queue.vulnerabilities)
        if not findings:
            return {"candidates": 0, "enriched": 0, "noop": True}
        prompt = prompt_manager.load_sync(
            "endpoint_enrichment",
            variables={
                "route_table": route_table,
                "vuln_candidates": _render_endpoint_candidates(findings),
            },
        )
        try:
            result = await run_gitnexus_verdict_agent(
                prompt=prompt,
                repo_path=str(repo),
                agent_name=f"endpoint-enrich-{vuln_class}",
                structured_output_schema={
                    "type": "object",
                    "properties": {"vulnerabilities": {"type": "array"}},
                },
                audit_session=get_audit_session(),
                provider_config=input.provider_config,
                max_turns=max_turns,
            )
        except Exception as exc:  # noqa: BLE001 — 富化失败不阻塞报告
            logger.warning(
                "endpoint-enrichment: %s agent failed (keep deterministic "
                "endpoints): %s", vuln_class, exc)
            return {"candidates": len(findings), "enriched": 0,
                    "failed": str(exc)[:200]}
        raw = result.structured_output
        if raw is None and result.text:
            raw = result.text
        enriched, warnings = _apply_endpoint_enrichment(findings, raw)
        for w in warnings:
            logger.warning("%s (%s)", w, vuln_class)
        atomic_write_json(
            queue_path,
            {"vulnerabilities": [f.model_dump() for f in findings]},
        )
        logger.info("endpoint-enrichment: %s %d/%d cards enriched",
                    vuln_class, enriched, len(findings))
        return {"candidates": len(findings), "enriched": enriched}

    enriched_classes: dict[str, dict] = {}
    total_enriched = 0
    async with get_audit_session().track_step(
            "vulnerability-analysis", "endpoint-enrichment",
            intent=intent_for("endpoint-enrichment")):
        results = await asyncio.gather(
            *(_enrich_class(vc) for vc in ALL_VULN_CLASSES),
            return_exceptions=True,
        )
        for vuln_class, res in zip(ALL_VULN_CLASSES, results):
            if isinstance(res, BaseException):
                logger.warning(
                    "endpoint-enrichment: %s crashed (non-fatal): %s",
                    vuln_class, res)
                res = {"failed": str(res)[:200]}
            enriched_classes[vuln_class] = res
            total_enriched += int(res.get("enriched", 0)) if isinstance(res, dict) else 0
    return {"skipped": None, "enriched_classes": enriched_classes,
            "total_enriched": total_enriched}


def _load_route_table(deliverables: Path) -> str:
    """entry_points.json → 路由表文本素材（METHOD route @ file:line）。"""
    import json as _json
    ep_path = resolve_intermediate(deliverables, "entry_points.json")
    if ep_path is None or not ep_path.exists():
        return "(no entry_points.json)"
    try:
        data = _json.loads(ep_path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return "(entry_points.json unreadable)"
    lines: list[str] = []
    for ep in data.get("adjudicated_entry_points") or []:
        if not isinstance(ep, dict):
            continue
        route = ep.get("route")
        method = ep.get("http_method") or "-"
        # func_block_id "app/routes/index.js:index:66" → 注册位置 file:line
        fb = str(ep.get("func_block_id") or "")
        parts = fb.rsplit(":", 1)
        registered = f"{parts[0]}:{parts[1]}" if len(parts) == 2 and parts[1].isdigit() else fb
        evidence = ep.get("evidence") or ""
        lines.append(f"- {method} {route} @ {registered} ({evidence})")
    return "\n".join(lines) or "(no adjudicated entry points)"


def _render_endpoint_candidates(findings: list) -> str:
    """全部卡渲染成接口富化 prompt 的候选 markdown（确定性事实）。"""
    lines: list[str] = []
    for f in findings:
        eps = getattr(f, "endpoints", None) or []
        lines.append(
            f"- ID: {f.ID}\n"
            f"  type: {getattr(f, 'vulnerability_type', None)}\n"
            f"  title: {getattr(f, 'title', None)}\n"
            f"  endpoints: {eps}\n"
            f"  endpoint: {getattr(f, 'endpoint', None) or getattr(f, 'source_endpoint', None)}\n"
            f"  path: {getattr(f, 'path', None)}\n"
            f"  source: {getattr(f, 'source', None)}\n"
            f"  sink_call: {getattr(f, 'sink_call', None)}\n"
            f"  affected_parameters: {getattr(f, 'affected_parameters', None)}"
        )
    return "\n".join(lines) or "(none)"


def _apply_endpoint_enrichment(findings: list, raw: object) -> tuple[int, list[str]]:
    """接口富化 agent 输出按 ID 回填 report_endpoints / report_problem_points（原地）。

    宽松解析：structured_output dict / JSON 文本皆可；id/ID 均认；条目 path
    不以 / 开头丢弃（防幻觉）；ID 未知整条丢弃。§4.1（spec
    2026-08-26-vuln-card-seven-sections）：problem_points 逐项校验（非 dict /
    location 空白 / snippet 空白丢弃），与 report_endpoints 独立判断、独立
    写回；enriched 计数按卡去重（任一字段写回即算 1）。
    返回 (回填条数, warnings)。
    """
    import json as _json
    warnings: list[str] = []
    data: object = raw
    if isinstance(data, str):
        try:
            data = _json.loads(data)
        except (ValueError, TypeError):
            return 0, ["endpoint-enrichment: unparseable output"]
    if not isinstance(data, dict):
        return 0, ["endpoint-enrichment: output not a JSON object"]
    entries = data.get("vulnerabilities")
    if not isinstance(entries, list):
        return 0, ["endpoint-enrichment: no vulnerabilities array"]
    by_id = {f.ID: f for f in findings}
    enriched = 0
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        eid = str(entry.get("id") or entry.get("ID") or "")
        target = by_id.get(eid)
        if target is None:
            warnings.append(f"endpoint-enrichment: unknown ID {eid!r} skipped")
            continue
        card_touched = False
        raw_eps = entry.get("endpoints")
        if isinstance(raw_eps, list):
            valid: list[dict] = []
            for ep in raw_eps:
                if not isinstance(ep, dict):
                    continue
                path = str(ep.get("path") or "")
                if not path.startswith("/"):
                    warnings.append(
                        f"endpoint-enrichment: {eid} malformed path {path!r} dropped")
                    continue
                valid.append(ep)
            if valid:
                target.report_endpoints = valid
                card_touched = True
        # §4.1 problem_points：防幻觉立场同 path/行号——location/snippet 均非空
        # 才收（snippet 必须是 agent 真实读到的原文）；空条目丢弃 + warning。
        raw_pps = entry.get("problem_points")
        if isinstance(raw_pps, list):
            valid_pps: list[dict] = []
            for idx, pp in enumerate(raw_pps):
                if not isinstance(pp, dict):
                    warnings.append(
                        f"endpoint-enrichment: {eid} problem_points[{idx}] "
                        f"not a dict, dropped")
                    continue
                if not str(pp.get("location") or "").strip():
                    warnings.append(
                        f"endpoint-enrichment: {eid} problem_points[{idx}] "
                        f"missing location, dropped")
                    continue
                if not str(pp.get("snippet") or "").strip():
                    warnings.append(
                        f"endpoint-enrichment: {eid} problem_points[{idx}] "
                        f"missing snippet, dropped")
                    continue
                valid_pps.append(pp)
            if valid_pps:
                target.report_problem_points = valid_pps
                card_touched = True
        if card_touched:
            enriched += 1
    return enriched, warnings


@activity.defn
async def run_assemble_dataflow_view(input: ActivityInput) -> dict:
    """P4: 组装 dataflow_view.json（spec 2026-08-20 §3；失败不阻塞扫描）。

    读 merge 后 SSOT queue + chain_verdicts 等 intermediate 产物，调 Task 7
    纯函数 assemble_dataflow_view 组装数据流视图，落
    intermediate/dataflow_view.json（报告页数据流视图用）。non-fatal 报告增强：
    全产物缺 → skipped 不落盘；任何异常 → logger.warning + skipped 返回值，
    **不抛 ApplicationFailure**（区别于本文件 fatal 活动惯例）。
    """
    try:
        from supernova_core.services.dataflow_view import assemble_dataflow_view

        _repo, deliverables, _ws = _get_paths(input)
        view = assemble_dataflow_view(deliverables)
        if view is None:
            return {"status": "skipped", "reason": "no products"}
        atomic_write_json(intermediate_path(deliverables, "dataflow_view.json"), view)
        return {"status": "ok", "trees": len(view.get("trees", []))}
    except Exception as exc:  # noqa: BLE001 — non-blocking（报告增强，绝不阻塞扫描）
        logger.warning("run_assemble_dataflow_view failed (non-blocking): %s", exc)
        return {"status": "skipped", "reason": str(exc)}


@activity.defn
async def run_assemble_api_evidence(input: ActivityInput) -> dict:
    """接口证据矩阵组装（spec 2026-09-10 §6；non-fatal 报告增强）。

    聚合 entry_points/report_data/safe_vectors/dismissed/blackbox verdicts 为
    deliverables 根 api_evidence_matrix.json（跨 track 视角——白盒 workflow 时点
    黑盒 runs 多半未跑，黑盒栏为空；黑盒完成后的刷新靠 web lazy mtime 重建，
    spec §7）。任何异常 → logger.warning + skipped，绝不阻塞扫描收尾。
    """
    try:
        from supernova_core.services.api_evidence_matrix import (
            EVIDENCE_MATRIX_FILENAME, build_api_evidence_matrix)

        _repo, wb_deliverables, _ws = _get_paths(input)
        scan_dir = wb_deliverables.parent.parent
        matrix = build_api_evidence_matrix(scan_dir)
        atomic_write_json(wb_deliverables.parent / EVIDENCE_MATRIX_FILENAME, matrix)
        return {"status": "ok", "endpoints": len(matrix.get("endpoints", []))}
    except Exception as exc:  # noqa: BLE001 — non-blocking（报告增强，绝不阻塞扫描）
        logger.warning("run_assemble_api_evidence failed (non-blocking): %s", exc)
        return {"status": "skipped", "reason": str(exc)}


@activity.defn
async def run_risk_scoring(input: ActivityInput) -> dict:
    """Score call chains and produce tiered audit plan."""
    from supernova_whitebox.audit.session_registry import get_audit_session
    await ensure_audit_session(input)  # worker 重启后可观测恢复(幂等;见 session_recovery.py)
    try:
        from supernova_core.code_index.models import CodeIndex
        from supernova_core.code_index.parameter_models import ParameterPropagationGraph
        from supernova_core.code_index.risk_scorer import AuditBudget
        from supernova_core.code_index.tiered_audit import TieredAuditPlanner

        repo, deliverables, _ = _get_paths(input)

        async with get_audit_session().track_step("risk-scoring", "risk-scoring", intent=intent_for("risk-scoring")):
            # Load code index
            code_index_path = resolve_intermediate(deliverables, "code_index.json")  # tiering 双路径
            if code_index_path is None:
                return {"total_chains": 0, "tier3_count": 0, "tier2_count": 0, "tier1_count": 0}

            index = CodeIndex.model_validate_json(code_index_path.read_text())

            # Load parameter graph
            param_graph_path = resolve_intermediate(deliverables, "parameter_graph.json")  # tiering 双路径
            taint_flows_by_chain: dict[str, list] = {}
            if param_graph_path is not None:
                pgraph = ParameterPropagationGraph.model_validate_json(
                    param_graph_path.read_text()
                )
                for flow in pgraph.taint_flows:
                    taint_flows_by_chain.setdefault(flow.entry_point_id, []).append(flow)

            # Build block lookup
            blocks_by_id = {b.id: b for b in index.blocks}

            # Auth middleware detection: simple heuristic — functions with
            # auth/login/token/verify in name or decorators
            auth_ids: set[str] = set()
            for block in index.blocks:
                combined = f"{block.function_name} {' '.join(block.decorators)}".lower()
                if any(kw in combined for kw in ("auth", "login", "token", "verify", "session")):
                    auth_ids.add(block.id)

            # Plan
            planner = TieredAuditPlanner(
                chains=index.chains,
                blocks_by_id=blocks_by_id,
                taint_flows_by_chain=taint_flows_by_chain,
                auth_middleware_ids=auth_ids,
                budget=AuditBudget(),
                sink_call_sites=index.sink_call_sites,
            )
            plan = planner.plan()

            # Write audit plan
            plan_path = intermediate_path(deliverables, "audit_plan.json")  # tiering
            plan_data = json.loads(plan.to_json())
            atomic_write_json(plan_path, plan_data)

        return {
            "total_chains": plan.total_chains,
            "tier3_count": plan.tier3_count,
            "tier2_count": plan.tier2_count,
            "tier1_count": plan.tier1_count,
            "estimated_llm_calls": plan.estimated_llm_calls,
        }
    except Exception as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e


@activity.defn
async def render_findings(input: ActivityInput) -> None:
    """【退役 2026-08-26（spec 2026-08-26-report-single-source-rendering §3.1）】
    逻辑并入 assemble_report（findings.md 从 report_data 单点渲染）；workflow
    不再调度。函数保留防注册表断链，验收阶段统一清理。"""
    from supernova_whitebox.audit.session_registry import get_audit_session
    await ensure_audit_session(input)  # worker 重启后可观测恢复(幂等;见 session_recovery.py)
    try:
        from supernova_core.services.findings_renderer import FindingsRenderer
        from supernova_core.config.parser import parse_config

        repo, deliverables, _ = _get_paths(input)
        async with get_audit_session().track_step("reporting", "render-findings", intent=intent_for("render-findings")):
            report_config = None
            if input.config_path:
                cfg = parse_config(input.config_path)
                report_config = cfg.report
            # repo_root：卡片「问题点」snippet 确定性提取（spec 2026-08-25 §10.4）
            await FindingsRenderer.render_findings_from_queues(
                deliverables, report_config, repo_root=repo)
    except PentestError as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e
    except Exception as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e


@activity.defn
async def assemble_report(input: ActivityInput) -> None:
    """组装 report_data.json 初版（单源 SSOT）+ 分项 findings 单点渲染。

    spec 2026-08-26-report-single-source-rendering §3：comprehensive md 不再
    在此产（移至 run_report_polish 之后的 export_report_markdown_files）；
    render_findings 逻辑并入（findings.md 从 report_data 渲染——与 md 导出
    同一渲染函数，单点）。rd 组装失败 fatal：rd.json 是单源链路的根交付物
    （md / web 前端都吃它），失败 = 部署问题显式暴露（不再是「md 主链路
    non-fatal」的旧语义）。
    """
    from supernova_whitebox.audit.session_registry import get_audit_session
    await ensure_audit_session(input)  # worker 重启后可观测恢复(幂等;见 session_recovery.py)
    try:
        _, deliverables, _ = _get_paths(input)
        async with get_audit_session().track_step(
            "reporting", "assemble-report", intent=intent_for("assemble-report")
        ):
            rd = await _build_report_data_initial(input, deliverables)
            await _render_findings_deliverables_from_rd(rd, deliverables)
    except PentestError as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e
    except Exception as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e


async def _build_report_data_initial(input: ActivityInput, deliverables: Path):
    """rd.json 初版组装落盘（spec §3；fatal——根交付物）。

    scan id 推断：workspace_path（web=scan_dir）目录名 → session.json 祖先 →
    "unknown"。模块属性调用（report_data_builder.build_report_data）以支持
    测试 monkeypatch。选中类过滤：input.vuln_classes 非空时 rd 只含选中类
    （resume/减类重跑防旧 queue 泄漏进报告——旧 md 路径 assemble 的同款契约）。
    """
    from supernova_core.models.report_data import ScanMeta
    from supernova_core.services import report_data_builder

    scan_id = "unknown"
    if input.workspace_path:
        scan_id = Path(input.workspace_path).name
    else:
        for ancestor in deliverables.resolve().parents:
            if (ancestor / "session.json").exists():
                scan_id = ancestor.name
                break
    report_data = await report_data_builder.build_report_data(
        deliverables, ScanMeta(id=scan_id, track="whitebox"))
    selected = {str(vc) for vc in (input.vuln_classes or [])}
    if selected:
        report_data.vulnerabilities = [
            v for v in report_data.vulnerabilities if v.type in selected]
        report_data.stats = _filter_stats_for_classes(
            report_data.stats, report_data.vulnerabilities)
    await report_data_builder.write_report_data(
        report_data, deliverables / "report_data.json")
    return report_data


def _filter_stats_for_classes(stats, vulns):
    """按过滤后卡片重算 stats（by_type 只留选中类；by_severity 重数；
    severity_range 语义对齐 builder._severity_range）。"""
    from supernova_core.models.report_data import ReportStats, TypeStats
    from supernova_core.services.severity_rules import SEVERITY_ORDER

    if stats is None:
        return None
    by_class: dict[str, list] = {}
    by_severity: dict[str, int] = {}
    for v in vulns:
        by_class.setdefault(v.type, []).append(v)
        if v.severity:
            by_severity[v.severity] = by_severity.get(v.severity, 0) + 1
    by_type: dict[str, TypeStats] = {}
    for vuln_class, items in by_class.items():
        ranked = sorted([v.severity for v in items if v.severity],
                        key=lambda s: SEVERITY_ORDER.get(s, 0))
        severity_range = (ranked[0] if ranked[0] == ranked[-1]
                          else f"{ranked[0]}-{ranked[-1]}") if ranked else None
        by_type[vuln_class] = TypeStats(count=len(items),
                                        severity_range=severity_range)
    return ReportStats(by_type=by_type, by_severity=by_severity)


async def _render_findings_deliverables_from_rd(rd, deliverables: Path) -> None:
    """分项 findings.md 从 report_data 单点渲染（spec §3：render_findings 并入）。

    文件名对齐 FindingsRenderer（CLASS_CONFIG.findings_file）；卡片复用
    render_vuln_card（经 ``_VulnView`` 合并视图——与 md 导出同一渲染路径，
    单点）。rd 中无卡的类不产文件（对齐「无 queue 不产」现状）；幂等重写
    （rd 是唯一事实源，重跑跟随最新 rd）。
    """
    from supernova_core.services.findings_renderer import (
        CLASS_CONFIG, render_vuln_card, _M as _FINDINGS_MESSAGES,
    )
    from supernova_core.services.report_markdown_exporter import _VulnView
    from supernova_core.utils.file_io import async_write_file

    by_class: dict[str, list[tuple[str, object]]] = {}
    for rv in rd.vulnerabilities:
        by_class.setdefault(rv.type, []).append((rv.id, _VulnView(rv)))
    for vuln_class, cfg in CLASS_CONFIG.items():
        entries = by_class.get(vuln_class) or []
        if not entries:
            continue
        sections: list[str] = [f"## {_FINDINGS_MESSAGES.get(cfg.heading)}", ""]
        for card_id, view in entries:
            try:
                sections.append(render_vuln_card(view, vuln_class))
            except Exception as exc:  # noqa: BLE001 — 单卡渲染失败不拖垮整文件
                logger.warning("findings 渲染 %s 失败（跳过该卡）: %s",
                               card_id, exc)
        sections.extend(["", _FINDINGS_MESSAGES.get("disclaimer"), ""])
        await async_write_file(deliverables / cfg.findings_file,
                               "\n".join(sections))


@activity.defn
async def verify_report_vuln_blocks(input: ActivityInput) -> None:
    """【退役 2026-08-26（spec §3.1）】md 改由 report_data 确定性导出后无需
    自愈（同构校验移入 export_report_markdown_files）；workflow 不再调度。

    原职责：report-executive 后校验 + 自愈:最终报告 ### ID 节数 vs 底稿期望数。

    回归(2026-08-19 另一环境):report agent 自写 cleanup 脚本把正文压成
    「模式汇总+行内 ID 引用」,丢掉全部结构化漏洞节——前端 splitByVulnBlocks
    解析 0 节 → 报告页统计全 0、PoC 无卡片可并。prompt 三处锁定节格式仍被
    绕过(SCRATCHPAD 允许 scripts 是口子),故加确定性防线:节数不足 → 重新
    assemble 覆盖 agent 版(丢执行摘要、保漏洞数据——数据完整性 > 摘要美化),
    后续 inject_* 照常追加。必须在 run-report-agent 之后、inject_attack_chains
    之前运行。校验/自愈失败不阻塞主报告(吞异常 + warning)。
    """
    log = logging.getLogger(__name__)
    try:
        from supernova_core.services.report_assembler import ReportAssembler
        from supernova_core.utils.file_io import async_path_exists

        _, deliverables, _ = _get_paths(input)
        report_path = deliverables / "comprehensive_security_assessment_report.md"
        if not await async_path_exists(report_path):
            return  # 主报告不存在(agent 失败),无处校验
        vuln_classes = input.vuln_classes or list(ALL_VULN_CLASSES)
        actual, expected = await ReportAssembler.verify_vuln_block_coverage(
            deliverables, vuln_classes, report_path)
        if actual >= expected:
            return  # 覆盖完好(含无漏洞扫描:0 >= 0)
        log.warning(
            "报告漏洞节覆盖不足(actual=%d < expected=%d):report-executive 丢失结构化"
            "漏洞节,重新 assemble 覆盖 agent 版(执行摘要丢弃,漏洞数据恢复)",
            actual, expected,
        )
        await ReportAssembler.assemble(deliverables, vuln_classes, report_path)
    except Exception as exc:  # noqa: BLE001 — 校验/自愈失败不阻塞主报告
        log.warning("verify_report_vuln_blocks failed (non-blocking): %s", exc)


@activity.defn
async def inject_attack_chains(input: ActivityInput) -> None:
    """【退役 2026-08-26（spec §3.1）】攻击链由导出器从 rd.attack_chains 渲染；
    workflow 不再调度。

    原职责：报告阶段最后注入：attack_chains.json → ## 攻击链 章节追加到最终报告。

    必须在 run-report-agent 之后运行——report-executive agent 重写
    comprehensive_security_assessment_report.md（同 deliverable_filename）,
    若在此之前追加攻击链章节会被覆盖丢失（回归 hr_20260713-104726）。
    放最后注入,确保攻击链章节留存。幂等（标题已存在则跳过）。失败不阻塞。
    """
    log = logging.getLogger(__name__)
    try:
        from supernova_core.services.report_assembler import ReportAssembler
        from supernova_core.utils.file_io import (
            async_path_exists, async_read_file, async_write_file,
        )

        _, deliverables, _ = _get_paths(input)
        report_path = deliverables / "comprehensive_security_assessment_report.md"
        if not await async_path_exists(report_path):
            return  # 主报告不存在,无处追加
        chains_md = await ReportAssembler.render_attack_chains(deliverables)
        if not chains_md:
            return  # 无攻击链 / 渲染为空
        content = await async_read_file(report_path)
        if "## 攻击链（多步利用路径）" in content:
            return  # 幂等：已注入（resume/重跑）
        await async_write_file(report_path, content + chains_md)
    except Exception as exc:  # noqa: BLE001 — 攻击链注入失败不阻塞主报告
        log.warning("inject_attack_chains failed (non-blocking): %s", exc)


@activity.defn
async def inject_gitnexus_track_status(input: ActivityInput) -> None:
    """【退役 2026-08-26（spec §3.1）】GN 判定状态由导出器从卡级
    confidence/merge_source 渲染；workflow 不再调度。

    原职责：GitNexus 轨 fail-fast 状态注记(report-executive 之后注入,防覆盖)。

    必须在 run-report-agent 之后运行——report-executive agent 重写整个
    comprehensive_security_assessment_report.md,若在此之前注入会被覆盖丢失
    (对齐 inject_attack_chains 的模式,fail-fast plan Task 6 fix 2026-07-19)。
    读 Task 1 的 gitnexus_track_status.json,若有 failed 类,在报告顶部(原 H1
    之后)插入 ## GitNexus 轨判定状态 章节,逐条列出 failed 类 + reason +
    「结果由 LLM 轨提供」。

    幂等(标题已存在则跳过)。失败不阻塞主报告(吞异常 + warning)。
    无 failed 类 / 主报告缺 → 直接 return。
    """
    log = logging.getLogger(__name__)
    try:
        from supernova_core.code_index.gitnexus_track_status import read_track_status
        from supernova_core.utils.file_io import (
            async_path_exists, async_read_file, async_write_file,
        )

        _, deliverables, _ = _get_paths(input)
        report_path = deliverables / "comprehensive_security_assessment_report.md"
        if not await async_path_exists(report_path):
            return  # 主报告不存在,无处注入

        track_status = read_track_status(deliverables)
        failed_notes = [
            f"- {vc}: GitNexus 轨判定失败({s.get('reason', 'unknown')}),结果由 LLM 轨提供"
            for vc, s in track_status.items()
            if isinstance(s, dict) and s.get("status") == "failed"
        ]
        if not failed_notes:
            return  # 无 failed 类,不改报告

        content = await async_read_file(report_path)
        if "## GitNexus 轨判定状态" in content:
            return  # 幂等:已注入(resume/重跑)

        banner = (
            "## GitNexus 轨判定状态\n\n"
            + "\n".join(failed_notes)
            + "\n\n---\n\n"
        )
        # 插在报告顶部;若首个非空行是 H1,插在 H1 之后更自然(避免 H2 先于 H1)
        lines = content.split("\n")
        i = 0
        while i < len(lines) and not lines[i].strip():
            i += 1
        if i < len(lines) and lines[i].lstrip().startswith("# "):
            head = "\n".join(lines[: i + 1])
            tail = "\n".join(lines[i + 1 :]).lstrip("\n")
            new_content = head + "\n\n" + banner + tail
        else:
            new_content = banner + content
        await async_write_file(report_path, new_content)
    except Exception as exc:  # noqa: BLE001 — 注记注入失败不阻塞主报告
        log.warning("inject_gitnexus_track_status failed (non-blocking): %s", exc)


@activity.defn
async def write_agent_poc(input: ActivityInput) -> None:
    """poc-agent 产出写回 queue（spec 2026-08-27-poc-agent-direct-design）。

    每 vuln_class 一次多轮 agent（回读源码验证端点形态）→ validate_pocs 校验 →
    report_poc 文本 schema 写回（curl/raw_http/steps 透传）。agent 失败诚实缺失
    （不写回、不降级到确定性拼装——已退役）。写回失败 non-fatal（md 卡 POC 节
    缺省），语义与拆出前一致。
    """
    import logging
    log = logging.getLogger(__name__)
    try:
        await ensure_audit_session(input)  # worker 重启后可观测恢复(幂等)
        _, deliverables, _ = _get_paths(input)
        await _write_agent_pocs(input, deliverables)
    except Exception as exc:  # noqa: BLE001 — 写回失败绝不阻塞主流程
        log.warning("poc: whitebox write_agent_poc failed (non-blocking): %s", exc)


_SINK_FILE_RE = re.compile(r"([\w./\\-]+\.[A-Za-z]\w*):\d+")


def _sink_file_key(card: object) -> str:
    """聚类 key：卡片 sink 所在文件（空串 = unknown 桶）。

    提取优先级（2026-09-02 NodeGoat-20260902-045436 真实卡形态校准）：
    1. sink_call / sink_function 字符串里的「file:line」——LLM 轨卡
       （xss: 'login.html:110 value=…'、inj: 'eval() — contributions.js:32-34'）；
       对 LLM 轨 XSS 卡它指向模板 sink 终点，比 dataflow 末步（渲染入口
       server.js）更准。
    2. dataflow_steps 末步 file——GN 轨卡（sink_function 常为裸 'render'）。
    3. 都提不出 → ""（authz 等非 taint 卡无 sink 概念，同类卡共享
       handler/middleware 读码，按序聚片恰好合理）。

    输入两种形态都吃：queue pydantic 模型（poc-agent 路径）与原始 dict
    （adversarial review 从 JSON 直读的 queue entries，2026-09-10）。
    """
    for attr in ("sink_call", "sink_function"):
        v = card.get(attr) if isinstance(card, dict) else getattr(card, attr, None)
        if isinstance(v, str):
            m = _SINK_FILE_RE.search(v)
            if m:
                return m.group(1)
    steps = (card.get("dataflow_steps") if isinstance(card, dict)
             else getattr(card, "dataflow_steps", None))
    if isinstance(steps, list) and steps:
        last = steps[-1]
        if isinstance(last, dict):
            f = last.get("file")
            if isinstance(f, str) and f.strip():
                return f.strip()
    return ""


def _group_poc_targets(targets: list, max_per_shard: int) -> list[list]:
    """按 sink 文件聚类 → 切片：同 key 相邻按序装片，超限同 key 裂多片。

    一锅端 14 卡 = 90KB prompt + 10万 token 级请求（GLM ServerOverloaded 时段
    最先被丢）+ 超限截断输出（2026-09-02 4 次启动 0 交付的根因）；同文件卡
    共享读码（路由注册/handler/middleware 文件级复用）故按文件聚、不按序号
    平切。输入序在片内与片间均保持（稳定输出，回炉 only_ids 可复算）。
    """
    by_key: dict[str, list] = {}
    order: list[str] = []
    for t in targets:
        k = _sink_file_key(t)
        if k not in by_key:
            by_key[k] = []
            order.append(k)
        by_key[k].append(t)
    shards: list[list] = []
    for k in order:
        group = by_key[k]
        for i in range(0, len(group), max_per_shard):
            shards.append(group[i:i + max_per_shard])
    return shards


async def _write_agent_pocs(
    input: ActivityInput, deliverables: Path,
    only_ids: set[str] | None = None,
) -> list[str]:
    """poc-agent 接线（spec 2026-08-27-poc-agent-direct-design §3，2026-09-02
    聚类分片）：每类 queue 的目标卡按 sink 文件聚类成 ≤N 卡的片，每片一次
    run_gitnexus_verdict_agent（多轮可 grep/read 回读源码验证端点形态）→
    validate_pocs L0-L3 校验 → report_poc 类级统一写回（agent 直产
    curl/raw_http/steps 文本，透传不改写）。取代确定性拼装（build_structured_poc
    退役）。

    - 诚实缺失：片 agent 失败/空产出 → 该片卡不写回（queue 原样），warning
      记账；一片失败不炸类、类失败不炸 activity；
    - 写回即 checkpoint：已有 report_poc 的卡默认跳过（不重打、不覆写）；
    - ``only_ids``（回炉）：额外过滤，只处理指定且尚无 report_poc 的卡——
      分片在过滤之后，回炉只重跑缺失卡命中的片。
    """
    from supernova_core.collectors.poc import (
        POC_AGENT_OUTPUT_SCHEMA, extract_pocs_payload, validate_pocs,
    )
    from supernova_core.models.queue_schemas import VulnerabilityQueue
    from supernova_whitebox.audit.session_registry import get_audit_session

    prompts_dir = Path(__file__).resolve().parents[5] / "prompts"
    prompt_manager = PromptManager(prompts_dir)
    # turn 预算默认 40（2026-09-02 聚类分片后换算：2026-09-01 一锅端实证 xss
    # 单 agent 129 turns / 14 卡 ≈ 9 turns/卡 + 固定探索，≤3 卡/片 ≈ 3×9 + 余量
    # → 40；一锅端 180 的 6s/turn×180≈18min 长尾随之消失）。容量铁律对齐
    # chain_verdict：改片大小/预算时同步评估 write_agent_poc 窗口（片多时
    # 总量 ≈ 片数 ÷ 并发 × 单片耗时）。
    max_turns = int(os.getenv("SUPERNOVA_POC_AGENT_MAX_TURNS", "40"))
    shard_max = get_poc_shard_max_cards()
    # 类间+片间共享限流：write_agent_poc 是 5 类 gather 并行、每类再裂 N 片，
    # 各持信号量会 5×N 叠加放大 429 暴露面——一个 scan 级 Semaphore 统一管。
    sem = asyncio.Semaphore(get_poc_agent_concurrency())
    classes = [vc for vc in (input.vuln_classes or list(ALL_VULN_CLASSES))
               if vc in _QUEUE_FILES]

    async def _one_class(vuln_class: str) -> list[str]:
        """单类：分片 → 片 agent（共享限流）→ 校验 → 统一写回 queue 一次。"""
        queue_path = resolve_intermediate(deliverables, _QUEUE_FILES[vuln_class])
        if queue_path is None or not queue_path.exists():
            return []
        parsed = VulnerabilityQueue.parse_lenient(
            queue_path.read_text(encoding="utf-8"), vuln_class=vuln_class)
        findings = list(parsed.queue.vulnerabilities)
        # 目标卡：尚无 report_poc（写回即 checkpoint，不覆写）且回炉过滤命中
        targets = [f for f in findings
                   if not getattr(f, "report_poc", None)
                   and (only_ids is None or f.ID in only_ids)]
        if not targets:
            return []
        shards = _group_poc_targets(targets, shard_max)

        async def _one_shard(idx: int, shard: list) -> list[dict]:
            """单片：prompt 只塞该片卡；失败诚实缺失（return []，不炸类）。"""
            agent_name = f"poc-agent-{vuln_class}-{idx + 1:02d}"
            try:
                async with sem:
                    prompt = prompt_manager.load_sync(
                        "poc-agent",
                        variables={
                            "web_url": input.web_url or "http://TARGET",
                            "vuln_class": vuln_class,
                            "repo_root": input.repo_path,
                            "vuln_queue": json.dumps(
                                [f.model_dump() for f in shard],
                                ensure_ascii=False, indent=2),
                        })
                    result = await run_gitnexus_verdict_agent(
                        prompt=prompt,
                        repo_path=input.repo_path,
                        structured_output_schema=POC_AGENT_OUTPUT_SCHEMA,
                        audit_session=get_audit_session(),
                        provider_config=input.provider_config,
                        max_turns=max_turns,
                        agent_name=agent_name,
                    )
            except Exception as exc:  # noqa: BLE001 — 诚实缺失：不写回，不阻塞
                logger.warning("poc-agent: %s failed (cards left without "
                               "PoC): %s", agent_name, exc)
                return []
            raw = result.structured_output
            if raw is None and getattr(result, "text", None):
                # 打捞兜底（2026-08-28 auth 实证：agent 烧满 turn 预算被 SDK
                # 掐断，structured_output=None 但 text 里常有成型/围栏 pocs
                # JSON）——裸 JSON → 花括号平衡段纯解析，不改写内容；救不回
                # 走诚实缺失。
                raw = extract_pocs_payload(result.text)
            items = raw.get("pocs") if isinstance(raw, dict) else None
            if not items:
                logger.warning("poc-agent: %s returned no pocs (cards left "
                               "without PoC)", agent_name)
                return []
            # valid_ids 限片内（不是全类）：片 A agent 幻觉返回片 B 的 ID
            # 不越片写回。
            res = validate_pocs(items, valid_ids={f.ID for f in shard})
            for _rej, reason in res.rejected:
                logger.warning("poc-agent: %s verdict rejected: %s",
                               agent_name, reason)
            return res.accepted

        # 片间并行（共享 sem 限流）；gather 后类级统一写回一次（单点写盘，
        # 片间无「读-改-写」竞争——多片各写各的会互相覆盖）。
        shard_results = await asyncio.gather(
            *(_one_shard(i, s) for i, s in enumerate(shards)))
        accepted = [p for r in shard_results for p in r]
        if not accepted:
            return []
        by_id = {v["vulnerability_id"]: v for v in accepted}
        entries = [f.model_dump() for f in findings]
        wrote: list[str] = []
        for entry in entries:
            poc = by_id.get(entry.get("ID"))
            if poc is not None:
                entry["report_poc"] = poc
                wrote.append(entry["ID"])
        atomic_write_json(queue_path, {"vulnerabilities": entries})
        return wrote

    # 类间并行（对齐 endpoint_enrichment per-class 并行模式）：各类写各自的
    # queue 文件无共享状态，agent_name 带 vc+片序号记账不互相覆盖；片级/类级
    # 失败均不阻塞其余。结果按类序拼接（稳定输出序）。
    results = await asyncio.gather(*(_one_class(vc) for vc in classes))
    return [vid for r in results for vid in r]


@activity.defn
async def run_adversarial_review(input: ActivityInput) -> None:
    """对抗性审查（spec 2026-09-10）：merge 后逐卡反驳，refuted 剔卡+归档。

    POC 同款组织：sink 文件聚类分片 + scan 级 Semaphore 并发；片失败/
    打捞失败/预算超限 → unreviewed 保守放行（通道失败 ≠ 判了误报）。
    non-fatal（审查挂了保守放行，不阻塞主流程），开关关时直接 return。
    """
    import logging
    log = logging.getLogger(__name__)
    try:
        await ensure_audit_session(input)  # worker 重启后可观测恢复(幂等)
        _, deliverables, _ = _get_paths(input)
        # spec §4.3 activity 骨架：ensure_audit_session → _get_paths →
        # track_step（phase/step slug 均 "adversarial-review"，对齐
        # gn-finding-enrichment :1624 的 async with 形态）。
        async with get_audit_session().track_step(
                "adversarial-review", "adversarial-review",
                intent=intent_for("adversarial-review")):
            await _run_adversarial_review_for_classes(
                deliverables=deliverables, repo_path=str(input.repo_path),
                provider_config=input.provider_config)
    except Exception as exc:  # noqa: BLE001 — non-fatal：审查挂了保守放行
        log.warning("adversarial review failed (non-blocking): %s", exc)


async def _run_adversarial_review_for_classes(
    *, deliverables: Path, repo_path: str, provider_config: dict | None,
) -> None:
    """对抗性审查内核（壳 run_adversarial_review 的可测主体，对齐
    write_agent_poc → _write_agent_pocs 拆法）。deliverables 是 whitebox 桶根
    （_get_paths 中位，同 _write_agent_pocs 口径）。

    五类各读 <vc>_exploitation_queue.json，目标卡按 sink 文件聚类分片，每片
    一次 run_gitnexus_verdict_agent（多轮可 grep/read 回读源码找反证）→
    validate_review_cards L0-L4 校验（refuted 高门槛 + 证据存在性）→ 类级
    gather 后统一写回 queue + dismissed 归档一次。产物
    intermediate/adversarial_review.json 即 checkpoint：已有终态
    （survived/refuted）记录的卡不重审；refuted 剔卡 +
    dismissed_findings.json 归档（dismissed_at_stage=adversarial-review）。
    """
    from supernova_core.collectors.adversarial_review import (
        ADVERSARIAL_REVIEW_AGENT_SCHEMA, extract_review_payload,
        validate_review_cards,
    )
    from supernova_core.config.concurrency import (
        get_adversarial_review_concurrency, get_adversarial_review_max_agents,
        get_adversarial_review_max_turns, get_adversarial_review_shard_max_cards,
        is_adversarial_review_enabled,
    )
    from supernova_core.services.dismissed_archive import append_dismissed

    if not is_adversarial_review_enabled():
        return
    prompts_dir = Path(__file__).resolve().parents[5] / "prompts"
    prompt_manager = PromptManager(prompts_dir)
    max_turns = get_adversarial_review_max_turns()
    shard_max = get_adversarial_review_shard_max_cards()
    budget = get_adversarial_review_max_agents()
    classes = ("injection", "xss", "ssrf", "authz", "auth")
    # 类间并行（对齐 _write_agent_pocs 的 5 类 gather 先例——spec §4.3）+
    # 类内片间并行：一个 scan 级 Semaphore 统一限流（防类×片并发叠加放大
    # 429 暴露面）。
    sem = asyncio.Semaphore(get_adversarial_review_concurrency())
    review_path = intermediate_path(deliverables, "adversarial_review.json")
    dismissed_path = intermediate_path(deliverables, "dismissed_findings.json")

    # 产物即 checkpoint：已有终态（survived/refuted）记录的卡不重审。
    # 键 = (vuln_class, finding_id)：卡 ID 命名空间跨类不保证唯一（不同类都
    # 可能有 F-001），单 ID 键会跨类误跳审——保守不误删但 unreviewed 卡永远
    # 补不了审，语义错。
    prior_records: dict[tuple[str, str], dict] = {}
    if review_path.exists():
        try:
            prior = json.loads(review_path.read_text(encoding="utf-8"))
            for r in prior.get("records", []):
                if isinstance(r, dict) and r.get("review_verdict") in (
                        "survived", "refuted"):
                    prior_records[(str(r.get("vuln_class")),
                                   str(r.get("finding_id")))] = r
        except (json.JSONDecodeError, OSError):
            pass  # 损坏 → 当作无 checkpoint 全量重审

    launched = 0  # 预算护栏计数

    async def _one_class(vuln_class: str) -> tuple[list[dict], list[dict], list[dict]]:
        """返回 (kept_entries, new_records, dismissed_entries)，由调用方统一落盘。"""
        queue_path = resolve_intermediate(deliverables,
                                          f"{vuln_class}_exploitation_queue.json")
        if queue_path is None or not queue_path.exists():
            return [], [], []
        # queue 读兜底（fix 2026-09-11 review I2）：坏文件该类按空处理
        # （records 空 → 收口处不覆写 queue），不让单类坏文件炸整轮审查。
        try:
            data = json.loads(queue_path.read_text(encoding="utf-8"))
        except (ValueError, OSError) as exc:  # JSONDecodeError/UnicodeDecodeError/IO
            logger.warning("adversarial review: %s queue unreadable, "
                           "class skipped: %s", vuln_class, exc)
            return [], [], []
        entries = data.get("vulnerabilities") if isinstance(data, dict) else None
        if not isinstance(entries, list):
            return [], [], []
        targets = [e for e in entries
                   if isinstance(e, dict)
                   and e.get("verdict") != "not_vulnerable"
                   and (vuln_class, str(e.get("ID", ""))) not in prior_records]
        shards = _group_poc_targets(targets, shard_max)

        def _all_unreviewed(shard: list[dict]) -> list[tuple[dict, dict]]:
            return [(e, _record(vuln_class, e, "unreviewed", None,
                                {"action": "kept"})) for e in shard]

        async def _one_shard(idx: int, shard: list[dict]) -> list[tuple[dict, dict]]:
            """单片 → 该片 (entry, record) 对；失败 → 全部 unreviewed。"""
            nonlocal launched
            agent_name = f"adv-review-{vuln_class}-{idx + 1:02d}"
            by_id = {str(e.get("ID")): e for e in shard}
            try:
                async with sem:
                    if launched >= budget:
                        return _all_unreviewed(shard)
                    launched += 1
                    prompt = prompt_manager.load_sync(
                        "adversarial-review", variables={
                            "VULN_CLASS": vuln_class,
                            "REPO_ROOT": repo_path,
                            "FINDING_CARDS": json.dumps(
                                shard, ensure_ascii=False, indent=2),
                        })
                    result = await run_gitnexus_verdict_agent(
                        prompt=prompt, repo_path=repo_path,
                        structured_output_schema=ADVERSARIAL_REVIEW_AGENT_SCHEMA,
                        audit_session=get_audit_session(),
                        provider_config=provider_config,
                        max_turns=max_turns, agent_name=agent_name)
                # validate 及其后处理留在兜内（fix 2026-09-11 review I2）：
                # validate 层任何未预见的畸形（实证一例：null-byte location 曾
                # 使 fpath.resolve() 抛 ValueError）按全片 unreviewed 保守放行，
                # 不逃逸炸掉剩余类 → 已剔卡失去审查记录且重试不重建。
                raw = result.structured_output
                if raw is None and getattr(result, "text", None):
                    # 打捞兜底（对齐 _write_agent_pocs）：structured_output=None 但
                    # text 里常有成型/围栏 JSON——救不回走 unreviewed。
                    raw = extract_review_payload(result.text)
                cards = raw.get("cards") if isinstance(raw, dict) else None
                if not cards:
                    logger.warning("adversarial review: %s returned no cards "
                                   "(findings left unreviewed)", agent_name)
                    return _all_unreviewed(shard)
                # valid_ids 限片内（不是全类）：片 A agent 幻觉返回片 B 的 ID
                # 不越片生效（对齐 validate_pocs 用法）。
                res = validate_review_cards(
                    cards, valid_ids=set(by_id), vuln_class=vuln_class,
                    repo_root=Path(repo_path))
                for _rej, reason in res.rejected:
                    logger.warning("adversarial review: %s card rejected: %s",
                                   agent_name, reason)
                out: list[tuple[dict, dict]] = []
                seen: set[str] = set()
                for card in res.accepted:
                    fid = card["vulnerability_id"]
                    if fid in seen or fid not in by_id:
                        continue
                    seen.add(fid)
                    entry = by_id[fid]
                    verdict = card["review_verdict"]
                    after = ({"action": "dismissed"} if verdict == "refuted"
                             else {"action": "kept"})
                    out.append((entry, _record(vuln_class, entry, verdict, card, after)))
                for e in shard:  # agent 漏答的卡 → unreviewed
                    if str(e.get("ID")) not in seen:
                        out.append((e, _record(vuln_class, e, "unreviewed", None,
                                               {"action": "kept"})))
                return out
            except Exception as exc:  # noqa: BLE001 — 诚实缺失/后处理兜底
                logger.warning("adversarial review: %s failed: %s",
                               agent_name, exc)
                return _all_unreviewed(shard)

        # return_exceptions 兜底（fix 2026-09-11 review I2）：任何单点异常只
        # 降级该片（全 unreviewed），不逃逸中断其余片/类。
        shard_results = await asyncio.gather(
            *(_one_shard(i, s) for i, s in enumerate(shards)),
            return_exceptions=True)
        pairs: list[tuple[dict, dict]] = []
        for i, r in enumerate(shard_results):
            if isinstance(r, BaseException):
                logger.warning("adversarial review: adv-review-%s-%02d "
                               "crashed: %s", vuln_class, i + 1, r)
                pairs.extend(_all_unreviewed(shards[i]))
            else:
                pairs.extend(r)
        # refuted 剔卡用 ID 集合差集（不依赖对象恒等——queue entries 反序列化
        # 后与片内引用同源，但 ID 差集对任何引用形态都稳）。
        refuted_ids = {p[1]["finding_id"] for p in pairs
                       if p[1]["review_verdict"] == "refuted"}
        kept = [e for e in entries
                if not (isinstance(e, dict) and str(e.get("ID")) in refuted_ids)]
        dismissed = [_dismissed_entry(vuln_class, e, rec)
                     for e, rec in pairs if rec["review_verdict"] == "refuted"]
        return kept, [p[1] for p in pairs], dismissed

    def _record(vc: str, entry: dict, verdict: str, card: dict | None,
                after: dict) -> dict:
        card = card or {}
        return {
            "vuln_class": vc,
            "finding_id": str(entry.get("ID", "")),
            "reviewed_at": datetime.now(timezone.utc).isoformat(),
            "before": {k: entry.get(k) for k in
                       ("ID", "title", "verdict", "merge_source",
                        "confidence", "source_track")},
            "review_verdict": verdict,
            "dimension_results": card.get("dimension_results", []),
            "failed_dimensions": card.get("failed_dimensions", []),
            "rebuttal_reason": card.get("rebuttal_reason"),
            "survival_reason": card.get("survival_reason"),
            "evidence": [e for d in card.get("dimension_results", [])
                         for e in d.get("evidence", [])],
            "confidence": card.get("confidence"),
            "after": after,
        }

    def _dismissed_entry(vc: str, entry: dict, record: dict) -> dict:
        dims = ",".join(record.get("failed_dimensions") or [])
        reason = str(record.get("rebuttal_reason") or "")[:500]
        return {
            "ID": entry.get("ID", ""),
            "source_track": entry.get("source_track"),
            "vuln_class": vc,
            "title": entry.get("title"),
            "dismiss_reason": f"adversarial-review[{dims}]: {reason}",
            "evidence": record.get("evidence"),
            "confidence": record.get("confidence") or entry.get("confidence"),
            "source": entry.get("source"),
            "sink_call": entry.get("sink_call"),
            "dismissed_at_stage": "adversarial-review",
        }

    # 类间并行（fix 2026-09-11 review I5：对齐 _write_agent_pocs :2591 的 5 类
    # gather 先例与 spec §4.3 步骤 3；原串行 barrier 会让每类最慢片空转吃窗）。
    # 各类读/写各自的 queue 文件无共享状态，共享 sem 统一限流；return_exceptions
    # + 收口处按类序逐类落盘（写盘语义与串行版一致：单类异常按空处理不覆写
    # queue，adversarial_review.json 恒落盘）。
    results = await asyncio.gather(*(_one_class(vc) for vc in classes),
                                   return_exceptions=True)
    all_records: list[dict] = list(prior_records.values())
    for vc, outcome in zip(classes, results):
        if isinstance(outcome, BaseException):
            # 单类异常不逃逸（fix 2026-09-11 review I2）：该类按空处理、其余类
            # 照常落盘——否则异常中断循环时已剔卡+归档的类失去整轮审查记录
            # （adversarial_review.json 只在尾部写，重试也不会重建）。
            logger.warning("adversarial review: class %s crashed: %s",
                           vc, outcome)
            continue
        kept, records, dismissed = outcome
        queue_path = resolve_intermediate(deliverables,
                                          f"{vc}_exploitation_queue.json")
        if queue_path is not None and queue_path.exists() and records:
            atomic_write_json(queue_path, {"vulnerabilities": kept})
            append_dismissed(dismissed_path, dismissed)
        all_records.extend(records)

    # summary 全量口径（含 prior 终态），产物即下次运行的 checkpoint
    by_v: dict[str, int] = {}
    by_class: dict[str, dict[str, int]] = {}
    for r in all_records:
        v = r["review_verdict"]
        by_v[v] = by_v.get(v, 0) + 1
        c = by_class.setdefault(r["vuln_class"],
                                {"total": 0, "refuted": 0, "survived": 0,
                                 "unreviewed": 0})
        c["total"] += 1
        c[v] += 1
    atomic_write_json(review_path, {
        "summary": {
            "total": len(all_records),
            "refuted": by_v.get("refuted", 0),
            "survived": by_v.get("survived", 0),
            "unreviewed": by_v.get("unreviewed", 0),
            "by_class": by_class,
        },
        "records": all_records,
    })


@activity.defn
async def export_report_markdown_files(input: ActivityInput) -> None:
    """report_data.json → 两 md 交付物 + 同构校验（spec §3/§6，polish 之后）。

    comprehensive_security_assessment_report.md = export_report_markdown(rd)；
    exploitable_poc_collection.md = export_poc_collection(rd)（PoC 单源）。
    同构校验（§6）：md ``### ID`` 卡数 = rd 卡数；quick_reference 非空时行数 =
    卡数。mismatch → 写回 rd.qa.checks（md_json_isomorphic /
    quick_reference_isomorphic）显式呈现，不静默、不抛。IO/解析异常 →
    fatal（对齐 assemble 语义：确定性导出失败 = 部署问题显式暴露）。
    """
    from supernova_whitebox.audit.session_registry import get_audit_session
    await ensure_audit_session(input)
    try:
        _, deliverables, _ = _get_paths(input)
        async with get_audit_session().track_step(
                "reporting", "export-report-markdown",
                intent=intent_for("export-report-markdown")):
            from supernova_core.models.report_data import ReportData, ReportQA, QACheck
            from supernova_core.services import report_data_builder
            from supernova_core.services.report_assembler import count_vuln_headings
            from supernova_core.services.report_markdown_exporter import (
                export_poc_collection, export_report_markdown,
            )
            from supernova_core.utils.file_io import async_write_file

            rd_path = deliverables / "report_data.json"
            rd = ReportData.model_validate_json(
                rd_path.read_text(encoding="utf-8"))
            md = export_report_markdown(rd)
            await async_write_file(
                deliverables / "comprehensive_security_assessment_report.md", md)
            await async_write_file(
                deliverables / "exploitable_poc_collection.md",
                export_poc_collection(rd))

            # --- 同构校验（确定性，§6）---
            rd_ids = [v.id for v in rd.vulnerabilities]
            missing_in_md = [vid for vid in rd_ids if f"### {vid}" not in md]
            extra_checks: list[QACheck] = []
            if missing_in_md or count_vuln_headings(md) != len(rd_ids):
                extra_checks.append(QACheck(check="md_json_isomorphic",
                                            failed_ids=missing_in_md))
            if rd.quick_reference:
                card_ids = set(rd_ids)
                qr_failed = [r.id for r in rd.quick_reference
                             if r.id not in card_ids]
                if len(rd.quick_reference) != len(rd_ids) or qr_failed:
                    extra_checks.append(QACheck(
                        check="quick_reference_isomorphic", failed_ids=qr_failed))
            if extra_checks:
                if rd.qa is None:
                    rd.qa = ReportQA()
                rd.qa.checks.extend(extra_checks)
                rd.qa.passed = not any(c.failed_ids for c in rd.qa.checks)
                await report_data_builder.write_report_data(rd, rd_path)
                logger.warning(
                    "export: 同构校验失败（显式呈现，不静默）: %s",
                    [c.model_dump() for c in extra_checks])
    except PentestError as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e
    except Exception as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e


# taint 三类 + authz/auth 的 queue 文件名（结构化 POC / polish 重建遍历用）
_QUEUE_FILES = {
    "injection": "injection_exploitation_queue.json",
    "xss": "xss_exploitation_queue.json",
    "ssrf": "ssrf_exploitation_queue.json",
    "auth": "auth_exploitation_queue.json",
    "authz": "authz_exploitation_queue.json",
}

_TAINT_CLASSES = ("injection", "xss", "ssrf")


@activity.defn
async def run_report_polish(input: ActivityInput) -> dict:
    """T5（spec 2026-08-26-report-generation-agent §5.4/§5.5）：report_data 终版组装。

    位置：generate_poc_report 之后（全部富化——merge/接口表/POC——已写回 queue），
    reporting 收尾。三步：
    1. 重建 report_data（确定性组装，吃全部富化字段）——rd.json 的权威组装点；
    2. ⑤QA：确定性必填校验（taint 卡 endpoints≥1 / title / severity），缺
       endpoints 的卡回炉一次（复用 endpoint 富化 agent + prompt）→ 重建；
       仍失败 → qa.passed=false 显式呈现（不静默）；
    3. ④执行摘要：LLM 产 executive_summary（攻击面叙事/top_risks/P0-P1）；
       失败回退确定性摘要（severity 排序）。
    任何 LLM 失败不阻塞 rd 产出（non-fatal 全程）。
    """
    from supernova_whitebox.audit.session_registry import get_audit_session
    await ensure_audit_session(input)
    repo, deliverables, _ = _get_paths(input)
    from supernova_core.models.report_data import (
        ExecutiveSummary, ReportQA, QACheck, ScanMeta, TopRisk,
    )
    from supernova_core.services import report_data_builder
    from supernova_core.services.severity_rules import SEVERITY_ORDER

    def _scan_meta() -> ScanMeta:
        scan_id = "unknown"
        if input.workspace_path:
            scan_id = Path(input.workspace_path).name
        else:
            for ancestor in deliverables.resolve().parents:
                if (ancestor / "session.json").exists():
                    scan_id = ancestor.name
                    break
        return ScanMeta(id=scan_id, track="whitebox")

    prompts_dir = Path(__file__).resolve().parents[5] / "prompts"
    prompt_manager = PromptManager(prompts_dir)

    async with get_audit_session().track_step(
            "reporting", "report-polish", intent=intent_for("report-polish")):
        rd = await report_data_builder.build_report_data(deliverables, _scan_meta())

        # --- ⑤QA（§6 扩展）：七节覆盖率缺口分组 → 回炉一次（多路）→ 复检 ---
        # 分组口径：taint 专属（endpoints/params/problem_points/行号链走接口
        # 富化 agent——产出三兄弟同源）；全卡（POC 走结构化写回路径；title 或
        # narrative 缺段走 GN 深富化路径，白名单仅补空缺）。单轮回炉，失败保
        # 产物 + qa.passed=false 显式呈现。severity/isomorphic 属工程 invariant，
        # 不交给 LLM 回炉。
        def _poc_incomplete(v) -> bool:
            p = v.poc
            return p is None or not (p.curl or p.raw_http or p.steps)

        def _params_missing(v) -> bool:
            return (v.type in _TAINT_CLASSES and v.endpoints
                    and not any(e.params for e in v.endpoints))

        def _locs_missing(v) -> bool:
            return (v.type in _TAINT_CLASSES and v.endpoints
                    and not any(e.sink_location for e in v.endpoints))

        def _title_missing(v) -> bool:
            return not (v.title or "").strip()

        def _narrative_missing(v) -> bool:
            return (v.narrative is None
                    or not (v.narrative.cause and v.narrative.impact
                            and v.narrative.remediation))

        def _narrative_rework_missing(v) -> bool:
            # title 与 narrative 三段同属 reader-facing 深富化产物；title 单独
            # 缺失也必须回炉（2026-08-26 QA 契约：必填缺口回炉一次）。
            return _title_missing(v) or _narrative_missing(v)

        missing_endpoints = [v for v in rd.vulnerabilities
                             if v.type in _TAINT_CLASSES and not v.endpoints]
        missing_pp = [v for v in rd.vulnerabilities
                      if v.type in _TAINT_CLASSES and not v.problem_points]
        enrich_targets = _dedupe_by_id(
            missing_endpoints + missing_pp
            + [v for v in rd.vulnerabilities if _params_missing(v)]
            + [v for v in rd.vulnerabilities if _locs_missing(v)])
        missing_poc = [v for v in rd.vulnerabilities if _poc_incomplete(v)]
        # 变量名保留 missing_narr：这里表示 narrative 深富化 route 的目标集，
        # 该 route 负责 title + cause/impact/remediation。
        missing_narr = [v for v in rd.vulnerabilities
                        if _narrative_rework_missing(v)]

        reworked: set[str] = set()
        if enrich_targets:
            reworked.update(await _rework_missing_endpoints(
                input, deliverables, repo, enrich_targets, prompt_manager))
        if missing_poc:
            reworked.update(await _rework_missing_pocs(
                input, deliverables, [v.id for v in missing_poc]))
        if missing_narr:
            reworked.update(await _rework_missing_narratives(
                input, deliverables, repo, missing_narr, prompt_manager))
        reworked_ids = sorted(reworked)
        if reworked_ids:
            rd = await report_data_builder.build_report_data(
                deliverables, _scan_meta())

        checks: list[QACheck] = []
        taint_missing = [v.id for v in rd.vulnerabilities
                         if v.type in _TAINT_CLASSES and not v.endpoints]
        checks.append(QACheck(check="taint_endpoints_present",
                              failed_ids=taint_missing))
        no_title = [v.id for v in rd.vulnerabilities if _title_missing(v)]
        checks.append(QACheck(check="title_present", failed_ids=no_title))
        bad_sev = [v.id for v in rd.vulnerabilities
                   if v.severity not in SEVERITY_ORDER]
        checks.append(QACheck(check="severity_valid", failed_ids=bad_sev))
        # §6 七节覆盖率（逐卡缺口，显式呈现）
        checks.append(QACheck(
            check="problem_points_present",
            failed_ids=[v.id for v in rd.vulnerabilities
                        if v.type in _TAINT_CLASSES and not v.problem_points]))
        checks.append(QACheck(
            check="poc_complete",
            failed_ids=[v.id for v in rd.vulnerabilities if _poc_incomplete(v)]))
        checks.append(QACheck(
            check="params_present",
            failed_ids=[v.id for v in rd.vulnerabilities if _params_missing(v)]))
        checks.append(QACheck(
            check="narrative_complete",
            failed_ids=[v.id for v in rd.vulnerabilities if _narrative_missing(v)]))
        checks.append(QACheck(
            check="endpoint_rows_have_locations",
            failed_ids=[v.id for v in rd.vulnerabilities if _locs_missing(v)]))
        qa = ReportQA(passed=not any(c.failed_ids for c in checks),
                      checks=checks, reworked_ids=reworked_ids)

        # --- ④执行摘要 ---
        # spec 2026-08-27 §8：AccountedLlmClient 包装（report-summary 记账——
        # 此前单次调用 cost 整笔丢弃）；finalize 在 try 出口。
        from supernova_core.agents.llm_accounting import AccountedLlmClient
        summary_source = "deterministic"
        es = None

        async def _summary_runner(prompt, **kw):
            return await run_claude_prompt(
                prompt=prompt, repo_path=str(repo), model_tier="medium",
                structured_output_schema={
                    "type": "object",
                    "properties": {
                        "narrative": {"type": "string"},
                        "risk_level": {"type": "string"},
                        "top_risks": {"type": "array"},
                        "remediation_order": {"type": "string"},
                    },
                },
                provider_config=input.provider_config)

        _summary_client = AccountedLlmClient(
            _summary_runner, get_audit_session(), "report-summary")
        try:
            digest_lines = [
                f"- {v.id} | {v.type} | {v.severity} | {v.title} | "
                f"endpoints={','.join(e.path for e in v.endpoints) or '-'}"
                for v in rd.vulnerabilities
            ]
            prompt = prompt_manager.load_sync(
                "report_summary",
                variables={"vuln_digest": "\n".join(digest_lines) or "(none)"},
            )
            raw_summary = await _summary_client(prompt)
            result = type("_R", (), {})()  # 兼容下游 payload 读取
            result.structured_output = None
            if raw_summary:
                import json as _json
                try:
                    result.structured_output = _json.loads(raw_summary)
                except (ValueError, TypeError):
                    result.structured_output = None
            payload = result.structured_output
            if isinstance(payload, dict) and payload.get("narrative"):
                es = ExecutiveSummary.model_validate(payload)
                summary_source = "llm"
        except Exception as exc:  # noqa: BLE001 — 摘要失败回退确定性
            logger.warning("report-polish: summary agent failed "
                           "(deterministic fallback): %s", exc)
        finally:
            try:
                await _summary_client.finalize()  # spec 2026-08-27 §8 记账出口
            except Exception:
                pass  # best-effort
        if es is None:
            es = _deterministic_summary(rd)

        rd.executive_summary = es
        rd.qa = qa
        await report_data_builder.write_report_data(
            rd, deliverables / "report_data.json")
        return {"summary": summary_source, "qa_passed": qa.passed,
                "reworked": reworked_ids}


def _deterministic_summary(rd):
    """④降级：确定性摘要（severity 排序 top 卡；无 LLM）。"""
    from supernova_core.models.report_data import ExecutiveSummary, TopRisk

    ranked = sorted(
        [v for v in rd.vulnerabilities],
        key=lambda v: -({"critical": 3, "high": 2, "medium": 1, "low": 0}
                        .get(v.severity or "medium", 0)))
    if not ranked:
        return ExecutiveSummary(narrative="未发现漏洞。", risk_level="低")
    by_sev: dict[str, int] = {}
    for v in ranked:
        by_sev[v.severity or "medium"] = by_sev.get(v.severity or "medium", 0) + 1
    sev_text = "、".join(f"{k} {v} 个" for k, v in by_sev.items())
    top = ranked[0]
    risk_level = {"critical": "极高", "high": "高",
                  "medium": "中", "low": "低"}.get(top.severity or "medium", "中")
    top_risks = [
        TopRisk(vuln_id=v.id, reason=v.title,
                priority="P0" if (v.severity == "critical") else "P1")
        for v in ranked[:5]
    ]
    return ExecutiveSummary(
        narrative=(f"共发现 {len(ranked)} 个漏洞（{sev_text}）。"
                   f"最高风险：{top.id} {top.title}。"),
        risk_level=risk_level, top_risks=top_risks)


def _dedupe_by_id(cards) -> list:
    """按 id 去重保序（§6 回炉分组：同一卡多缺口只喂 agent 一次）。"""
    seen: set[str] = set()
    out = []
    for v in cards:
        if v.id not in seen:
            seen.add(v.id)
            out.append(v)
    return out


async def _rework_missing_pocs(
    input: ActivityInput, deliverables: Path, missing_ids: list[str],
) -> list[str]:
    """§6 回炉：缺 POC 的卡走结构化 POC 写回（复用 write_agent_poc 路径，
    only_ids 只补缺失卡——不重打全量 LLM、不覆写已有 report_poc）。"""
    try:
        return await _write_agent_pocs(input, deliverables,
                                            only_ids=set(missing_ids))
    except Exception as exc:  # noqa: BLE001 — 回炉失败保 qa.passed=false
        logger.warning("report-polish: poc rework failed: %s", exc)
        return []


async def _rework_missing_narratives(
    input: ActivityInput, deliverables: Path, repo: Path,
    missing, prompt_manager,
) -> list[str]:
    """§6 回炉：title/narrative 缺段 → GN 深富化路径（gn_finding_enrichment
    agent，白名单字段仅补空缺——已有段不覆写）。"""
    from supernova_core.models.queue_schemas import VulnerabilityQueue
    from supernova_whitebox.audit.session_registry import get_audit_session

    by_class: dict[str, list] = {}
    for v in missing:
        by_class.setdefault(v.type, []).append(v)
    reworked: list[str] = []
    for vuln_class, cards in by_class.items():
        cfg = _QUEUE_FILES.get(vuln_class)
        if cfg is None:
            continue
        queue_path = resolve_intermediate(deliverables, cfg)
        if queue_path is None or not queue_path.exists():
            continue
        parsed = VulnerabilityQueue.parse_lenient(
            queue_path.read_text(encoding="utf-8"), vuln_class=vuln_class)
        findings = list(parsed.queue.vulnerabilities)
        card_ids = {v.id for v in cards}
        targets = [f for f in findings if f.ID in card_ids]
        if not targets:
            continue
        prompt = prompt_manager.load_sync(
            "gn_finding_enrichment",
            variables={
                "gn_only_candidates": _render_gn_only_candidates(targets),
            },
        )
        try:
            result = await run_gitnexus_verdict_agent(
                prompt=prompt,
                repo_path=str(repo),
                agent_name=f"gn-enrich-rework-{vuln_class}",
                structured_output_schema=_gn_enrich_output_schema(),
                audit_session=get_audit_session(),
                provider_config=input.provider_config,
                max_turns=_gn_enrich_max_turns(),
            )
        except Exception as exc:  # noqa: BLE001 — 回炉失败保 qa.passed=false
            logger.warning("report-polish: narrative rework %s failed: %s",
                           vuln_class, exc)
            continue
        raw = result.structured_output
        if raw is None and result.text:
            raw = result.text
        enriched, warnings = _apply_gn_enrichment(findings, raw)
        for w in warnings:
            logger.warning("%s (narrative rework %s)", w, vuln_class)
        if enriched:
            atomic_write_json(
                queue_path,
                {"vulnerabilities": [f.model_dump() for f in findings]},
            )
            # _apply_gn_enrichment 是整对象替换（非原地）——从 findings 重查。
            # title 与 narrative 三段同属本 route 的修复契约；只写回 notes 但
            # title 仍缺时不能记为 reworked。
            by_id_after = {f.ID: f for f in findings}
            fixed = [
                i for i in card_ids
                if by_id_after.get(i) is not None
                and (getattr(by_id_after[i], "title", None) or "").strip()
                and getattr(by_id_after[i], "notes", None)
                and getattr(by_id_after[i], "impact", None)
                and getattr(by_id_after[i], "remediation", None)
            ]
            reworked.extend(sorted(fixed))
    return reworked


async def _rework_missing_endpoints(
    input: ActivityInput, deliverables: Path, repo: Path,
    missing, prompt_manager,
) -> list[str]:
    """⑤回炉（§6 扩展）：缺 endpoints/params/problem_points/行号链的卡喂回
    接口富化 agent 一次（同一 agent 产出 report_endpoints + report_problem_points）；
    写回 queue。"""
    from supernova_core.models.queue_schemas import VulnerabilityQueue
    from supernova_whitebox.audit.session_registry import get_audit_session

    by_class: dict[str, list] = {}
    for v in missing:
        by_class.setdefault(v.type, []).append(v)
    reworked: list[str] = []
    route_table = _load_route_table(deliverables)
    for vuln_class, cards in by_class.items():
        cfg = _QUEUE_FILES.get(vuln_class)
        if cfg is None:
            continue
        queue_path = resolve_intermediate(deliverables, cfg)
        if queue_path is None or not queue_path.exists():
            continue
        parsed = VulnerabilityQueue.parse_lenient(
            queue_path.read_text(encoding="utf-8"), vuln_class=vuln_class)
        findings = list(parsed.queue.vulnerabilities)
        card_ids = {v.id for v in cards}
        targets = [f for f in findings if f.ID in card_ids]
        if not targets:
            continue
        prompt = prompt_manager.load_sync(
            "endpoint_enrichment",
            variables={
                "route_table": route_table,
                "vuln_candidates": _render_endpoint_candidates(targets),
            },
        )
        try:
            result = await run_gitnexus_verdict_agent(
                prompt=prompt,
                repo_path=str(repo),
                agent_name=f"endpoint-enrich-rework-{vuln_class}",
                structured_output_schema={
                    "type": "object",
                    "properties": {"vulnerabilities": {"type": "array"}},
                },
                audit_session=get_audit_session(),
                provider_config=input.provider_config,
                max_turns=_endpoint_enrich_max_turns(),
            )
        except Exception as exc:  # noqa: BLE001 — 回炉失败保 qa.passed=false
            logger.warning("report-polish: rework %s failed: %s", vuln_class, exc)
            continue
        raw = result.structured_output
        if raw is None and result.text:
            raw = result.text
        enriched, warnings = _apply_endpoint_enrichment(findings, raw)
        for w in warnings:
            logger.warning("%s (rework %s)", w, vuln_class)
        if enriched:
            atomic_write_json(
                queue_path,
                {"vulnerabilities": [f.model_dump() for f in findings]},
            )
            reworked_ids = {f.ID for f in targets
                            if (getattr(f, "report_endpoints", None)
                                or getattr(f, "report_problem_points", None))}
            reworked.extend(sorted(reworked_ids))
    return reworked


def _make_verdict_agent_runner(repo_path: str, provider_config: dict | None = None,
                               audit_session=None):
    """多轮 verdict agent runner 工厂（spec 2026-08-27 §3，生产主线）。

    闭包契约对齐 core 层 judge_chain_verdict 的 verdict_agent 形态：
    ``async (prompt, *, output_format, agent_name) -> ClaudeRunResult``——
    经 run_gitnexus_verdict_agent 多轮跑（grep/read 自主验证链），继承记账
    （audit_session → end_agent）、工具审计、max_turns
    （SUPERNOVA_CHAIN_VERDICT_MAX_TURNS 默认 30，ws_getenv per-workspace）。
    agent_name 由 builder 逐链
    传唯一名（chain-verdict-{vc}-{i:02d}，防 metrics.agents 同名覆盖）。"""
    async def runner(prompt: str, *, output_format=None, agent_name=None):
        return await run_gitnexus_verdict_agent(
            prompt=prompt,
            repo_path=repo_path,
            structured_output_schema=output_format,
            audit_session=audit_session,
            provider_config=provider_config,
            max_turns=get_chain_verdict_max_turns(),
            agent_name=agent_name or "chain-verdict",
        )
    return runner


def _make_track_parity_client(repo_path: str, provider_config: dict | None = None):
    """track-parity（配对归并，spec 2026-08-26 §6）专用单次 runner 工厂。

    返回 ClaudeRunResult-like runner（AccountedLlmClient 契约——包装层记
    cost/tokens/model 并转 str；剥 str 的闭包正是 §8 轻量调用 cost 漏记的
    根因，2026-08-31 修复回归该契约）。开关语义：**不受
    SUPERNOVA_GITNEXUS_LLM_ENABLED 门控**——用户关 chain-verdict 判定省
    token 时（2026-08-26 用户口径：判定关、双轨一致性层开），配对归并仍
    工作（chain verdict 的判定路径 2026-09-01 起只有多轮 agent 一种形态，
    本工厂做的是配对归并非漏洞判定）。output_format 透传
    run_claude_prompt（模块级名——测试经 patch
    activities.run_claude_prompt / patch 本工厂注入 fake）单次结构化输出。"""

    async def _runner(prompt: str, **kwargs):
        return await run_claude_prompt(
            prompt=prompt, repo_path=repo_path, model_tier="medium",
            structured_output_schema=kwargs.get("output_format"),
            provider_config=provider_config,
        )
    return _runner


# 交付纪律统一注入（2026-08-28 收口）：全部 JSON 契约多轮 agent 的唯一入口
# （endpoint/gn enrich、authz judge/explore、chain verdict、discovery 四模板）在此
# 统一注入，prompt 文件不再各自抄写（单点补丁模式 = 无穷无尽；现场实证见
# tests/test_verdict_agent_delivery_rules.py 模块 docstring）。注入条件 =
# structured_output_schema 非 None：有工具的多轮（能写文件）∧ 要收 JSON 的交集；
# 单次 llm_client（无工具）与无 schema 路径天然不注入。
_DELIVERY_RULES = """<delivery_rules>
CRITICAL — violating these voids the entire run (your work is collected from
your final message, nothing else):
- Your final message must BE the JSON object itself.
  Do NOT write the JSON to a file (no write_file, no bash redirection) — the
  harness never reads files you create.
- Budget your turns: finish greping/reading early and reserve enough turns to
  emit the complete JSON object in one single final message. If you run out of
  turns before emitting it, everything is discarded.
</delivery_rules>"""


async def run_gitnexus_verdict_agent(
    *,
    prompt: str,
    repo_path: str,
    structured_output_schema: dict | None = None,
    audit_session: "AuditSession | None" = None,
    provider_config: dict | None = None,   # P3c 阶段 1：穿线下传 run_claude_prompt
    max_turns: int | None = None,
    agent_name: str = "gitnexus-verdict",
) -> "ClaudeRunResult":
    """GitNexus 多轮 verdict agent：带 grep/read 自主追链，吃确定性候选做深度判定。

    max_turns 显式参数优先；None 走 SUPERNOVA_GITNEXUS_VERDICT_MAX_TURNS
    （默认 30，ws_getenv per-workspace）。
    返回完整 ClaudeRunResult（含 turns/cost/structured_output），不截断为 str——
    chain verdict 判定的唯一通道（单次 llm_client 路径已拆，2026-09-01）。
    GN-only 深度富化（run_gn_finding_enrichment）
    传 SUPERNOVA_GN_ENRICH_MAX_TURNS 走此参数，不污染 authz 深判的 env。

    audit_session 非 None 时构造 SessionToolAuditLogger（对齐 run_agent :167/183/198），多轮
    grep/read 工具调用经逐轮审计；为 None 时 tool_audit_logger=None（行为同前，向后兼容）。

    记账（2026-08-27 修成本漏记）：audit_session 非 None 时，result 的 cost/tokens/model
    经 end_agent(AgentEndResult) 记入 session.json metrics——此前调用方只消费
    structured_output，深判 LLM 消耗在总账不可见（2026-08-25 NodeGoat 扫描实证
    authz 深判 7 轮成本整笔漏记）。入口配对发 start_agent（2026-08-28 补——实时
    dashboard 此前看不到深判 agent 的 running 态）。run_claude_prompt 全捕获异常恒
    返回 result，成功/失败两路都记账。一次扫描内多次调用（富化逐 class/回炉）须传
    唯一 agent_name，防 metrics.agents 同名条目互相覆盖（totals 累加、agents 覆盖）。

    供 spec-1 的 run_authz_gitnexus_judge 多轮判定用。单测 mock run_claude_prompt 验证
    max_turns 透传 / audit_session 注入 tool_audit_logger。
    """
    from supernova_core.agents.runner import run_claude_prompt  # 延迟 import，对齐 :859
    tool_audit_logger = None
    if audit_session is not None:
        from supernova_whitebox.audit.session_tool_audit_logger import (
            SessionToolAuditLogger,
        )
        tool_audit_logger = SessionToolAuditLogger(
            audit_session, agent_name, attempt=1
        )
    agent_start = time.monotonic()
    # start_agent 补发（2026-08-28 实时页 Agent 盲区修复）：此前只发 end_agent →
    # 前端 dashboardReducer 里深判 agent（chain-verdict-*/gn-*）无 running 态。与
    # 出口 end_agent 成对（对齐 run_agent :195 先例）；prompt 传占位符不落大文件。
    if audit_session is not None:
        await audit_session.start_agent(
            agent_name, f"gitnexus-verdict:{agent_name}", attempt=1)
    try:
        if tool_audit_logger is not None:
            await tool_audit_logger.initialize()
        # 交付纪律注入（见 _DELIVERY_RULES docstring）：JSON 契约路径统一收口。
        if structured_output_schema is not None:
            prompt = f"{prompt}\n\n{_DELIVERY_RULES}"
        result = await run_claude_prompt(
            prompt=prompt,
            repo_path=repo_path,
            model_tier="medium",
            max_turns=(max_turns if max_turns is not None else
                       get_gitnexus_verdict_max_turns()),
            structured_output_schema=structured_output_schema,
            tool_audit_logger=tool_audit_logger,
            provider_config=provider_config,   # P3c 阶段 1
        )
    finally:
        if tool_audit_logger is not None:
            # 异常向上抛由 caller 处理；finally 内保守传 success（best-effort，对齐 run_agent）。
            await tool_audit_logger.close(
                success=True,
                duration_ms=int((time.monotonic() - agent_start) * 1000),
            )
    # 记账（见 docstring）：成功/失败都记；run_claude_prompt 抛异常（理论上不抛）
    # 时无 result 可记，异常继续上抛由 caller 降级处理。
    if audit_session is not None:
        tokens = result.tokens
        await audit_session.end_agent(agent_name, AgentEndResult(
            success=result.success,
            duration_ms=int((time.monotonic() - agent_start) * 1000),
            cost_usd=result.cost or 0.0,
            cost_currency=result.cost_currency,
            model=result.model,
            error=result.error or result.error_code,
            num_turns=result.turns,
            input_tokens=tokens.input_tokens if tokens else None,
            output_tokens=tokens.output_tokens if tokens else None,
            cache_read_tokens=tokens.cache_read_input_tokens if tokens else None,
            cache_creation_tokens=(
                tokens.cache_creation_input_tokens if tokens else None),
        ))
    return result


def _make_gitnexus_progress_cb(session):
    """采样 + 包装 session.log_gitnexus_progress。best-effort（吞 session 异常）。

    触发规则：final→summary；note 非空→note；detail 非空→hit；done==1 或 done%10==0→progress；其余静默。
    phase 透传自 sample.phase（core 的 ProgressEmitter 已带 sink-discovery /
    source-discovery / taint-analysis / chain-verdict）。cb=None 路径（LLM 关）由
    core emitter 兜底（emitter 自身 cb=None no-op），非本层职责。
    """
    async def cb(sample) -> None:
        if sample.final:
            kind, detail = "summary", sample.detail
        elif sample.note:
            kind, detail = "note", sample.note
        elif sample.detail:
            kind, detail = "hit", sample.detail
        elif sample.done == 1 or sample.done % 10 == 0:
            kind, detail = "progress", None
        else:
            return
        try:
            await session.log_gitnexus_progress(
                sample.phase, kind, sample.done, sample.total, sample.hits, detail)
        except Exception:
            pass
    return cb


def _ann_to_dict(item):
    """sanitizer_annotations 元素归一为可 JSON 序列化的 dict。

    真实数据流：CandidateChain.sanitizer_annotations 的元素是
    SanitizerAnnotation（sanitizer_library.py:33，frozen dataclass，字段
    rule_id/defense_type/applies_to/code_location/matched_text），finding 的
    原始属性存的是这些实例——原样塞 json.dumps 抛 TypeError（Fix round 2：
    safe 链才带 sanitizer → 恰好 safe 链炸掉整个 chain_verdicts.json 产物）。
    注意 gitnexus_queue 路径不受影响（f.model_dump() 会自动转 dict），只有
    本 dump 的 raw getattr 路径需要归一。

    防御顺序：dict 原样保留 → pydantic model_dump() → stdlib dataclass
    asdict() → str() 最终兜底（不崩，保留可读 repr）。
    """
    if isinstance(item, dict):
        return item
    if hasattr(item, "model_dump"):
        return item.model_dump()
    import dataclasses
    if dataclasses.is_dataclass(item) and not isinstance(item, type):
        return dataclasses.asdict(item)
    return str(item)


def _dump_chain_verdicts(
    deliverables: Path,
    vc: str,
    findings: list,
) -> None:
    """落 intermediate/{vc}_chain_verdicts.json；safe 链也进。零 finding 不落盘。

    findings 已含 safe 链（builder 对所有 candidate 都产 finding，safe 的
    externally_exploitable=False/verdict='safe'）。shape 对齐 spec 2026-08-20 §4
    P1 + Task 7 组装器读 ``verdicts.get("verdicts", [])``。

    finding→dump 字段映射（防御 getattr 兜底，适配三类 taint finding 不同字段名）：
    - flow_id: 三类均补（Task 2）；缺失降级空串。
    - sink_call_site_id: injection/xss 取 sink_call；ssrf 无 sink_call →
      降级 vulnerable_code_location（builder 写的即 chain.sink_call_site_id）→ 空。
    - verdict/mismatch_reason/confidence: 三类 builder 均从 ChainVerdict 复制。
    - reason: inj/xss 走 mismatch_reason；ssrf 无 mismatch_reason → 兜底取
      missing_defense（ssrf_builder 把 verdict.mismatch_reason 写进 missing_defense）。
    - sanitizer_annotations: 三类 builder 均从 CandidateChain.sanitizer_annotations
      复制进 finding（Task 2 Fix F2）；元素经 _ann_to_dict 归一（SanitizerAnnotation
      dataclass 实例 → dict，Fix round 2）；降级空 list（spec §6 容忍旧 finding）。
    """
    if not findings:
        return
    rows = []
    for f in findings:
        rows.append({
            "flow_id": getattr(f, "flow_id", "") or "",
            "sink_call_site_id": (
                getattr(f, "sink_call", "") or getattr(f, "vulnerable_code_location", "") or ""
            ),
            "vuln_class": vc,
            "verdict": getattr(f, "verdict", "") or "",
            "reason": (
                getattr(f, "mismatch_reason", "") or getattr(f, "missing_defense", "") or ""
            ),
            "sanitizer_annotations": [
                _ann_to_dict(a) for a in (getattr(f, "sanitizer_annotations", []) or [])
            ],
            "confidence": getattr(f, "confidence", "") or "",
        })
    atomic_write_json(
        intermediate_path(deliverables, f"{vc}_chain_verdicts.json"),
        {"verdicts": rows},
    )


@activity.defn
async def run_gitnexus_chain_verdict(input: ActivityInput) -> dict:
    """GitNexus-track chain verdict for injection/xss/ssrf (spec §5.4-5.6).

    Reads parameter_graph.json (Plan 1) + code_index.json (sink_call_sites for
    XSS routing), runs the light chain-verdict pass for the three trace-class
    vuln types, and writes <vuln>_gitnexus_queue.json for each. Plan 3's
    run_merge_dual_track_queues then does verdict OR against the LLM track.

    Graceful degradation: no parameter_graph.json (Plan 1 not landed) ->
    per_class empty, no gitnexus queues written, merger falls back to llm-only.
    """
    from supernova_whitebox.audit.session_registry import get_audit_session
    await ensure_audit_session(input)  # worker 重启后可观测恢复(幂等;见 session_recovery.py)
    try:
        from supernova_core.code_index.models import CodeIndex, EntryPoint
        from supernova_core.code_index.parameter_models import (
            ParameterPropagationGraph,
            SinkCallSite,
        )
        from supernova_core.code_index.vuln_chain_builders.injection_builder import (
            build_injection_findings,
        )
        from supernova_core.code_index.vuln_chain_builders.xss_builder import (
            build_xss_findings,
        )
        from supernova_core.code_index.vuln_chain_builders.ssrf_builder import (
            build_ssrf_findings,
        )
        from supernova_core.utils.atomic_write import atomic_write_json

        repo, deliverables, _ = _get_paths(input)
        # step cache（spec 2026-08-27-web-resume-breakpoint §4.3）：输入指纹
        # （parameter_graph/code_index，均产自 pre-recon 守卫块、块后无人覆写）
        # + salt（gn-llm env 开关——off 跑出的 unadjudicated 结果不得在 on 的
        # 续跑里被复用）全匹配 → 跳过整段判定，还原缓存返回值。
        _cache_inputs = [
            intermediate_path(deliverables, "parameter_graph.json"),
            intermediate_path(deliverables, "code_index.json"),
        ]
        _cache_salt = f"gn-llm={is_gitnexus_llm_enabled()}"
        _skip, _cached = should_skip(
            STEP_GITNEXUS_CHAIN_VERDICT, deliverables,
            inputs=_cache_inputs, salt=_cache_salt)
        if _skip:
            logger.info("gitnexus chain-verdict: step cache 命中，跳过判定（输入指纹一致）")
            return _cached
        per_class: dict[str, int] = {}
        failed_classes: list[str] = []
        fail_reasons: dict[str, str] = {}

        pgraph_path = resolve_intermediate(deliverables, "parameter_graph.json")  # tiering 双路径
        if pgraph_path is None:
            try:
                await get_audit_session().log_info(
                    "GitNexus 注入轨：parameter_graph.json 缺失 → 3 类判定失败（fail-fast，不降级）。",
                    "warning",
                )
            except Exception:
                pass
            _reason = "parameter_graph.json missing"
            for _vc in ("injection", "xss", "ssrf"):
                failed_classes.append(_vc)
                fail_reasons[_vc] = _reason
            return {
                "per_class": {},
                "failed_classes": failed_classes,
                "fail_reasons": fail_reasons,
            }
        try:
            pgraph = ParameterPropagationGraph.model_validate_json(pgraph_path.read_text())
        except Exception:
            try:
                await get_audit_session().log_info(
                    "GitNexus 注入轨：parameter_graph.json 无效 → 3 类判定失败（fail-fast，不降级）。",
                    "warning",
                )
            except Exception:
                pass
            _reason = "parameter_graph.json invalid"
            for _vc in ("injection", "xss", "ssrf"):
                failed_classes.append(_vc)
                fail_reasons[_vc] = _reason
            return {
                "per_class": {},
                "failed_classes": failed_classes,
                "fail_reasons": fail_reasons,
            }

        # MR 增量模式（spec 2026-09-03 §5.1）：候选按 IncrementalScope 预过滤——
        # verdict 只判增量链（新 sink 链/新入口链/删防护反向链），容量窗口自然收窄。
        # 非 MR 扫描（incremental_scope.json 不存在）→ load 返回 None → 原图直通零开销。
        _mr_scope_ids = load_mr_scope_flow_ids(deliverables)
        if _mr_scope_ids is not None:
            pgraph = filter_flows_by_mr_scope(pgraph, _mr_scope_ids)
            logger.info("MR 增量模式：chain verdict 候选 %d/%d 条",
                        len(pgraph.taint_flows), len(_mr_scope_ids) or 0)

        # XSS routes by SinkCallSite.category == XSS (SlotContext has no render
        # context), so read code_index.json for the sink call sites.
        sink_call_sites: dict[str, SinkCallSite] = {}
        # O2 前半：已解析的 HTTP 路由（entry_points.py 产物，code_index.json 落盘）
        # 按 func_block_id join 给 builder，让 GN 轨漏洞带 "METHOD /path"（PoC
        # 模板层直接命中，免 gap-fill LLM）。join miss → builder 保持原样兜底。
        entry_point_map: dict[str, EntryPoint] = {}
        # F6-B 白名单（spec 2026-09-03 §2 R2）：全量路由集合，绕开
        # entry_point_map 同 func_block_id 多路由被 dict 折叠的 bug。
        all_routes: set[str] = set()
        code_index_path = resolve_intermediate(deliverables, "code_index.json")  # tiering 双路径
        if code_index_path is not None:
            try:
                index = CodeIndex.model_validate_json(code_index_path.read_text())
                sink_call_sites = {s.id: s for s in index.sink_call_sites}
                entry_point_map = {
                    ep.func_block_id: ep for ep in index.entry_points if ep.route
                }
                all_routes = {
                    f"{ep.http_method.strip().upper()} {ep.route}"
                    for ep in index.entry_points
                    if ep.route and ep.http_method
                }
            except Exception as exc:
                logger.warning("gitnexus chain-verdict: code_index.json parse failed (%s)", exc)

        async with get_audit_session().track_step(
            "vulnerability-analysis", "gitnexus-chain-verdict",
            intent=None,
        ):
            # 判定通道（spec 2026-08-27 §3）：env 开 → 逐条多轮 verdict agent
            # （grep/read 自主验证，agent_name 唯一化记账）；env 关 → 通道不配置
            # （verdict_agent=None → judge 落 unadjudicated 保守。单次判定路径
            # 已拆，2026-09-01——不存在「无 agent 时退单次」的形态）。
            _verdict_agent = None
            if is_gitnexus_llm_enabled():
                _verdict_agent = _make_verdict_agent_runner(
                    str(repo), provider_config=input.provider_config,
                    audit_session=get_audit_session())
            _chain_cb = _make_gitnexus_progress_cb(get_audit_session())
            # 类间并发共享预算：三类单跳 builder + second_order 并发跑、共用
            # 同一信号量——总并发恒为 SUPERNOVA_CHAIN_VERDICT_CONCURRENCY
            # （而非 并发数×builder 数 乘法爆炸）；类间无依赖（各自独立提取
            # 候选/判定/落盘），并发只消除段间空转（前类尾部单链在飞时后类
            # 立即填补并发槽）。
            _verdict_sem = asyncio.Semaphore(get_chain_verdict_concurrency())

            def _verdict_ckpt(label: str):
                """逐链判定 checkpoint（2026-08-28 事故修）：activity 超时重试 /
                resume 只补未判链（此前全量重跑——2026-08-27 NodeGoat 27+31 链
                每条累计判 ~5 遍）。每类一文件防跨 gather 并发写竞争；损坏按空
                处理（load 语义），缓存命中零 LLM 调用。
                """
                from supernova_core.code_index.verdict_checkpoint import (
                    VerdictCheckpoint,
                )
                return VerdictCheckpoint.load(
                    intermediate_path(
                        deliverables, f"chain_verdict_checkpoint_{label}.json"))

            # Second-order storage-taint findings (子项⑤): compute once, group
            # by vuln class, then merge into the per-class queue inside the
            # builder loop. Guarded on ``index`` being defined (only set when
            # code_index.json parsed successfully above) — absent/invalid
            # code_index.json ⇒ no second-order findings, no crash.
            # 与三类单跳 builder 并发跑（共享 _verdict_sem）；失败不挡三类（原语义）。
            second_order_by_vc: dict[str, list] = {}

            async def _run_second_order():
                try:
                    storage_writes = list(index.storage_write_points)
                    reads_by_id = {s.param_name: s for s in index.source_points
                                   if s.source_type.value == "storage"}
                    if not (storage_writes and reads_by_id):
                        return []
                    from supernova_core.code_index.vuln_chain_builders.second_order_builder import (
                        build_second_order_findings,
                    )

                    def _second_order_source_provider(w):
                        # Lazy-load a write point's file source for table-name
                        # resolution (@Table / naming convention, Tasks 2-4).
                        # Missing/unreadable file → None → join degrades
                        # conservatively (under-recall, never a crash).
                        try:
                            return (repo / w.file_path).read_bytes()
                        except (FileNotFoundError, OSError, IsADirectoryError):
                            return None

                    return await build_second_order_findings(
                        storage_writes, pgraph,
                        verdict_agent=_verdict_agent,
                        sink_call_sites=sink_call_sites, reads_by_id=reads_by_id,
                        source_provider=_second_order_source_provider,
                        progress_cb=_chain_cb,
                        semaphore=_verdict_sem,
                        verdict_checkpoint=_verdict_ckpt("2nd"),
                    )
                except NameError:
                    # index undefined — code_index.json absent/failed to parse.
                    return []
                except Exception as exc:
                    logger.warning(
                        "gitnexus chain-verdict: second-order builder failed (%s)", exc)
                    return []

            # P3 (spec 2026-08-21 safe-branch-recall): presumed-safe 来源候选
            # (chain_propagator 对 intra 否定 sink 的表达式兜底,notes='presumed-safe')
            # 判 vulnerable → 只进 chain_verdicts.json(数据流视图可见该枝终审),
            # 不进 exploitation queue —— 防确定性兜底假阳污染报告。intra 报的
            # 候选(无此 notes)判 vulnerable 是真阳,照常进 queue(现状不变)。
            presumed_safe_flow_ids = {
                f.flow_id for f in pgraph.taint_flows
                if getattr(f, "notes", "") == "presumed-safe"
            }

            # 三类单跳 builder 并发跑（共享 _verdict_sem；类间无依赖）；
            # one vuln class failing must not block the others（原语义，异常
            # 收进结果元组，gather 后逐类分流）。
            async def _run_builder(vc, builder):
                try:
                    findings = await builder(pgraph,
                                             verdict_agent=_verdict_agent,
                                             sink_call_sites=sink_call_sites,
                                             entry_points=entry_point_map,
                                             progress_cb=_chain_cb,
                                             semaphore=_verdict_sem,
                                             verdict_checkpoint=_verdict_ckpt(vc))
                    return vc, findings, None
                except Exception as exc:
                    return vc, None, exc

            _second_order_task = asyncio.create_task(_run_second_order())
            _builder_results = await asyncio.gather(*[
                _run_builder(vc, builder)
                for vc, builder in (
                    ("injection", build_injection_findings),
                    ("xss", build_xss_findings),
                    ("ssrf", build_ssrf_findings),
                )])
            for f in await _second_order_task or []:
                vc2 = f.vulnerability_type.replace("second_order_", "")
                second_order_by_vc.setdefault(vc2, []).append(f)

            for vc, findings, _exc in _builder_results:
                if _exc is not None:
                    failed_classes.append(vc)
                    fail_reasons[vc] = f"builder raised: {_exc}"
                    logger.warning("gitnexus chain-verdict %s failed: %s", vc, _exc)
                    continue
                # Merge second-order findings into this vc's queue so they
                # get written + counted alongside the single-hop ones.
                findings = list(findings or []) + second_order_by_vc.get(vc, [])
                # 判非漏洞分流（spec 2026-08-27 §4）：verdict="safe" 卡不进
                # gitnexus_queue（不进报告 / SSOT / 黑盒输入），转
                # dismissed_findings.json 留档（人工分析）；needs_review /
                # unadjudicated 保守保留（「没判成 ≠ 非漏洞」）。
                # findings 保持全量（chain_verdicts 数据流视图用，见下方
                # _dump_chain_verdicts 与 P3 同模式）。
                from supernova_core.services.dismissed_archive import (
                    append_dismissed,
                    split_dismissed,
                )
                kept_findings, _dismissed = split_dismissed(findings, vuln_class=vc)
                if _dismissed:
                    append_dismissed(
                        intermediate_path(deliverables, "dismissed_findings.json"),
                        _dismissed)
                    logger.info(
                        "gitnexus chain-verdict %s: %d safe finding(s) archived "
                        "to dismissed_findings.json (not in queue/report)",
                        vc, len(_dismissed))
                # P3 分流：presumed-safe 来源判 vulnerable 的条目出 queue
                # (chain_verdicts 落盘仍用全量 findings,见下方 _dump_chain_verdicts)。
                queue_findings = [
                    f for f in kept_findings
                    if not (getattr(f, "flow_id", "") in presumed_safe_flow_ids
                            and getattr(f, "verdict", "") == "vulnerable")
                ]
                if len(queue_findings) < len(kept_findings):
                    logger.info(
                        "gitnexus chain-verdict %s: %d presumed-safe vulnerable "
                        "finding(s) routed to chain_verdicts only (not queue)",
                        vc, len(findings) - len(queue_findings),
                    )
                if queue_findings:
                    # F6-B：endpoint 缺失回填（LLM 提名 + 全量路由白名单验证 +
                    # 唯一命中采信，spec 2026-09-03 §3）。
                    from supernova_core.code_index.endpoint_backfill import (
                        backfill_endpoints,
                    )
                    queue_findings = backfill_endpoints(queue_findings, all_routes)
                    # tiering：*_gitnexus_queue.json 属中间产物 → 桶内 intermediate/
                    atomic_write_json(
                        intermediate_path(deliverables, f"{vc}_gitnexus_queue.json"),
                        {"vulnerabilities": [f.model_dump() for f in queue_findings]},
                    )
                    per_class[vc] = len(queue_findings)
                # 数据流视图（spec 2026-08-20 §4 P1）：落 chain_verdicts
                # 产物（safe 链也进），供 P4 组装器按 flow_id 拼 GitNexus 枝。
                # 与 gitnexus_queue 同条件（有 findings 才落盘），零 finding
                # 不产空文件。
                _dump_chain_verdicts(deliverables, vc, findings or [])

            taint_flows_count = len(pgraph.taint_flows)
            sink_call_sites_count = len(sink_call_sites)
            try:
                _sess = get_audit_session()
                if not per_class:  # 3 类全 0 findings
                    await _sess.log_info(
                        f"GitNexus 注入轨：3 类 0 findings（taint_flows={taint_flows_count}，"
                        f"sink_call_sites={sink_call_sites_count}）— 合法结论"
                        f"（流程跑通，本类无 taint）。下游按 fail-fast 策略编排。",
                        "info",
                    )
                else:
                    await _sess.log_info(
                        f"GitNexus 注入轨：inj={per_class.get('injection', 0)}, "
                        f"xss={per_class.get('xss', 0)}, ssrf={per_class.get('ssrf', 0)} "
                        f"findings（taint_flows={taint_flows_count}）。",
                        "info",
                    )
            except Exception:
                pass

        _ret = {
            "per_class": per_class,
            "failed_classes": failed_classes,
            "fail_reasons": fail_reasons,
        }
        # step cache：干净完成才打点（§4.3——failed_classes 非空不打，resume=
        # 再试一次；关轨 fail-fast 下打点会让续跑用缓存返回值原地下场）。
        # outputs 只记实际落盘的 queue 文件（零 finding 类不产空文件）。
        if not failed_classes:
            mark_done(
                STEP_GITNEXUS_CHAIN_VERDICT, deliverables,
                inputs=_cache_inputs,
                outputs=[p for p in (
                    intermediate_path(deliverables, f"{vc}_gitnexus_queue.json")
                    for vc in ("injection", "xss", "ssrf")) if p.exists()],
                ret=_ret, salt=_cache_salt)
        return _ret
    except PentestError as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e
    except Exception as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e


@activity.defn
async def run_framework_analysis(input: ActivityInput) -> dict:
    """Detect auto-REST frameworks, infer endpoints, write deliverable."""
    from supernova_whitebox.audit.session_registry import get_audit_session
    await ensure_audit_session(input)  # worker 重启后可观测恢复(幂等;见 session_recovery.py)
    try:
        from supernova_core.services.framework_analyzer import analyze_frameworks

        repo, deliverables, _ = _get_paths(input)
        async with get_audit_session().track_step("pre-recon", "framework-analysis", intent=intent_for("framework-analysis")):
            result = await analyze_frameworks(str(repo))

            # Write result as JSON deliverable
            import dataclasses
            result_data = dataclasses.asdict(result)
            result_path = intermediate_path(deliverables, "framework_analysis.json")  # tiering
            atomic_write_json(result_path, result_data)

        return {
            "detected_framework": result.detected_framework.name if result.detected_framework else None,
            "inferred_endpoint_count": len(result.inferred_endpoints),
            "recommendation_count": len(result.recommendations),
        }
    except PentestError as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e
    except Exception as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e


@activity.defn
async def run_frontend_mapping(input: ActivityInput) -> dict:
    """Map frontend routes to API calls, identify XSS chains, write deliverable."""
    from supernova_whitebox.audit.session_registry import get_audit_session
    await ensure_audit_session(input)  # worker 重启后可观测恢复(幂等;见 session_recovery.py)
    try:
        from supernova_core.services.frontend_mapper import map_frontend_routes

        repo, deliverables, _ = _get_paths(input)
        async with get_audit_session().track_step("pre-recon", "frontend-mapping", intent=intent_for("frontend-mapping")):
            result = await map_frontend_routes(str(repo))

            # Write result as JSON deliverable
            import dataclasses
            result_data = dataclasses.asdict(result)
            result_path = intermediate_path(deliverables, "frontend_mapping.json")  # tiering
            atomic_write_json(result_path, result_data)

        return {
            "route_count": len(result.routes),
            "xss_chain_count": len(result.xss_chains),
        }
    except PentestError as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e
    except Exception as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e


@activity.defn
async def run_route_chain_building(input: ActivityInput) -> dict:
    """Build route chain map from framework + frontend analysis results."""
    from supernova_whitebox.audit.session_registry import get_audit_session
    await ensure_audit_session(input)  # worker 重启后可观测恢复(幂等;见 session_recovery.py)
    try:
        from supernova_core.services.framework_analyzer import FrameworkAnalysisResult
        from supernova_core.services.frontend_mapper import FrontendAnalysisResult, XssAttackChain, FrontendRoute
        from supernova_core.services.route_chain_builder import build_attack_chains_from_analysis
        import dataclasses
        import logging

        repo, deliverables, _ = _get_paths(input)
        log = logging.getLogger(__name__)

        async with get_audit_session().track_step("pre-recon", "route-chain-building", intent=intent_for("route-chain-building")):
            # Load framework analysis result
            framework_result = FrameworkAnalysisResult()
            framework_path = resolve_intermediate(deliverables, "framework_analysis.json")  # tiering 双路径
            if framework_path is not None:
                data = json.loads(framework_path.read_text())
                endpoints = [_to_endpoint(ep) for ep in data.get("inferred_endpoints", []) if isinstance(ep, dict)]
                framework_result = FrameworkAnalysisResult(
                    inferred_endpoints=endpoints,
                    recommendations=data.get("recommendations", []),
                )

            # Load frontend mapping result
            frontend_result = FrontendAnalysisResult()
            frontend_path = resolve_intermediate(deliverables, "frontend_mapping.json")  # tiering 双路径
            if frontend_path is not None:
                data = json.loads(frontend_path.read_text())
                def _to_route(d: dict) -> FrontendRoute:
                    return FrontendRoute(
                        path=d["path"], component=d["component"], authenticated=d["authenticated"],
                    )
                def _to_xss(d: dict) -> XssAttackChain:
                    return XssAttackChain(
                        entry_point=d["entry_point"], storage_endpoint=d["storage_endpoint"],
                        render_endpoint=d["render_endpoint"], sink=d["sink"], confidence=d["confidence"],
                    )
                routes = [_to_route(r) for r in data.get("routes", []) if isinstance(r, dict)]
                xss_chains = [_to_xss(c) for c in data.get("xss_chains", []) if isinstance(c, dict)]
                frontend_result = FrontendAnalysisResult(routes=routes, xss_chains=xss_chains)

            chains = build_attack_chains_from_analysis(
                framework_result.inferred_endpoints, frontend_result.routes, frontend_result.xss_chains, log,
            )

            # Write chains
            chains_data = [dataclasses.asdict(c) for c in chains]
            chains_path = intermediate_path(deliverables, "route_chains.json")  # tiering
            atomic_write_json(chains_path, chains_data)

        return {"chain_count": len(chains)}
    except PentestError as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e
    except Exception as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e


@activity.defn
async def run_attack_chain_llm_agent(input: ActivityInput) -> dict:
    """LLM-track attack chain agent (creative-driven, multi-step inference).

    Runs the ATTACK_CHAIN agent (attack-chain.txt prompt) via the shared executor.
    Reads recon + exploitation_queue (LLM-track self-produced) — NEVER GitNexus
    deterministic artifacts (CLAUDE.md §1). The prompt instructs the agent to
    Write attack_chains_llm_queue.json itself; we do NOT pass structured_output
    schema (consistent with report agent — see _vuln_output_schema returning None).
    """
    try:
        act_input = ActivityInput(
            **{**input.__dict__, "agent_name": AgentName.ATTACK_CHAIN.value}
        )
        result = await run_agent(act_input)
        # run_agent 返回 metrics.model_dump() (dict)，字段名 num_turns。
        # chain_count 这里仅是 activity-level metadata（真实 chain 数由
        # assembly_v2 读 attack_chains_llm_queue.json 计数返回）。
        return {"chain_count": result.get("num_turns", 0), "track": "llm"}
    except (PentestError, Exception) as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(
            str(e), type=error_type, non_retryable=not retryable
        ) from e


@activity.defn
async def run_attack_chain_assembly_v2(input: ActivityInput) -> dict:
    """GitNexus-track assembly + dual-track merge → attack_chains.json.

    1. Read {vt}_gitnexus_queue.json findings (GitNexus own output).
    2. assemble_attack_chains (deterministic cross-endpoint correlation).
    3. Read attack_chains_llm_queue.json (from run_attack_chain_llm_agent).
    4. merge_attack_chains → attack_chains.json.

    GitNexus unavailable → gitnexus_chains=[] (graceful), LLM track covers.
    CLAUDE.md §1: 不反向喂 LLM 轨 prompt — assembly 只读两轨各自产物做合并。
    """
    try:
        repo, deliverables, _ = _get_paths(input)
        log = logging.getLogger(__name__)

        # 1. GitNexus findings per class
        gn_by_class: dict[str, list] = {}
        for vt in ("injection", "xss", "ssrf", "authz"):
            qpath = resolve_intermediate(deliverables, f"{vt}_gitnexus_queue.json")
            if qpath is not None:
                try:
                    data = json.loads(qpath.read_text("utf-8"))
                    gn_by_class[vt] = data.get("vulnerabilities", []) or []
                except (json.JSONDecodeError, OSError):
                    gn_by_class[vt] = []

        # 2. Assemble GitNexus chains
        from supernova_core.code_index.attack_chain_assembler import assemble_attack_chains
        gn_chains = assemble_attack_chains(gn_by_class, log)
        gn_path = intermediate_path(deliverables, "attack_chains_gitnexus_queue.json")  # tiering
        atomic_write_json(gn_path, {"chains": gn_chains})

        # 3. LLM chains（attack-chain agent Write 落盘）
        llm_chains: list = []
        llm_path = resolve_intermediate(deliverables, "attack_chains_llm_queue.json")  # tiering 双路径(agent self-Write 落顶层)
        if llm_path is not None:
            try:
                llm_chains = (
                    json.loads(llm_path.read_text("utf-8")).get("chains", []) or []
                )
            except (json.JSONDecodeError, OSError):
                llm_chains = []

        # 4. Merge → attack_chains.json
        from supernova_core.code_index.dual_track_merger import merge_attack_chains
        merged = merge_attack_chains(llm_chains, gn_chains)
        atomic_write_json(intermediate_path(deliverables, "attack_chains.json"), {"chains": merged})

        return {
            "chain_count": len(merged),
            "llm_count": len(llm_chains),
            "gitnexus_count": len(gn_chains),
        }
    except Exception as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(
            str(e), type=error_type, non_retryable=not retryable
        ) from e


# ── C1 worker-container-path 迁移 activity ──────────────────────────────
# 这 3 个 activity 仅 worker 容器路径调用（Task 4 workflow 接入）；CLI run_scan 不调用
# （CLI 自行 inline AuditSession/HeartbeatManager，零改动）。setup_display 注入进程全局
# AuditSession 使后续 activity 的 get_audit_session() 可用；run_heartbeat 长驻写 heartbeat
# 供 web 判活；finalize_summary 写 scan_end 事件 + 清理全局 session。

@activity.defn
async def setup_display(input: ActivityInput) -> None:
    """C1 前导 activity: 构造 headless AuditSession(event_file 来自 input) + set_audit_session。

    worker 容器无 TTY，用 use_rich=False + Console()（自动检测非 TTY → 纯文本）。
    AuditSession 构造逻辑复用 run_with_display(display_lifecycle.py) 的 headless 分支：
    构造 AuditSession + initialize(workflow_id, event_file=input.event_file)。
    event_file 透传到 WorkflowLogger.initialize → 挂 StructuredEventRenderer 写 events.ndjson。

    SessionMetadata.output_path 取 workspace_path 的父目录（workspaces dir），id 取
    workspace_name，使 generate_audit_path = workspaces/<session> = workspace_path（与 CLI
    run_scan 的 meta 语义一致：audit 产物落 session 目录下）。

    构造逻辑抽到 core ``build_headless_audit_session``，与 ``ensure_audit_session``（worker
    重启后可观测恢复）共用--见 session_recovery.py。
    """
    await build_headless_audit_session(input)
    from supernova_core.config.scan_env import set_scan_env
    set_scan_env(input.env_overrides)


@activity.defn
async def finalize_summary(input: ActivityInput, summary: dict) -> None:
    """C1 后置 activity: log_workflow_complete(触发 StructuredEventRenderer 写 scan_end) + 清 AuditSession。

    summary 由 workflow 从 self._state 构建（等价 run_scan worker.py:312-328 的逻辑，
    移进 workflow）。log_workflow_complete 内部调 workflow_logger.close()（关 LogStream +
    StructuredEventRenderer 句柄），故无需额外 close。clear_audit_session 清进程全局。
    """
    from supernova_whitebox.audit.session_registry import (
        NullAuditSession, clear_audit_session, get_audit_session,
    )

    await ensure_audit_session(input)  # worker 重启后可观测恢复(幂等;见 session_recovery.py)
    session = get_audit_session()
    if not isinstance(session, NullAuditSession):
        # cost / cost_currency 取 session.get_metrics()(MetricsTracker 累积所有 agent,完整),
        # 非 summary dict(其 total_cost 来自 workflow self._state.agent_metrics,LLM 轨关时
        # 残缺→0)。对齐 CLI 路径 worker._build_final_summary 同源修复:两条路径 cost 数据源
        # 一致 = MetricsTracker(回归 NodeGoat ``Total Cost: $0.0000``)。
        final_metrics = await session.get_metrics() or {}
        ws = WorkflowSummary(
            status=summary.get("status", "failed"),
            total_duration_ms=summary.get("total_duration_ms", 0),
            total_cost_usd=final_metrics.get("total_cost_usd") or 0.0,
            cost_currency=final_metrics.get("cost_currency") or "USD",
            completed_agents=summary.get("completed_agents", []),
            agent_metrics=summary.get("agent_metrics", {}),
            error=summary.get("error"),
        )
        # 统一日志总线：final flush（dispatch 余下 LogEvent 到 workflow.log/events.ndjson）
        # 在 log_workflow_complete 关闭 workflow_logger 之前，对齐 display_lifecycle
        # finally 顺序（drain_and_detach → session.close）。
        await LogBus.drain_and_detach()
        if input.combined:
            # D1：组合扫描白盒阶段——调现有 log_phase_complete（写 PhaseEvent，非 scan_end），
            # 不写终态 status，留 scan 非终态供编排器在同目录追加黑盒阶段。
            await session.log_phase_complete("whitebox")
            # drain-task 收尾（2026-08-18 NodeGoat 真机回归）：黑盒阶段走自己的
            # setup_display 自建 session，白盒 session 在 combined finalize 后无人复用。
            # 不 close 的话 clear_audit_session() 紧接着摘走 _SESSIONS 最后引用 →
            # dispatcher drain task 成孤儿（纯 PENDING 挂 queue.get()）→ 下个 scan
            # 期间被 GC 销毁，"Task was destroyed but it is pending!" 经 LogBus 误路由
            # 进当时活跃 scan 的 live 页。close 会先 join 队列（phase 事件不丢）再
            # cancel+await drain task。
            await session.close()
        else:
            await session.log_workflow_complete(ws)
    await stop_heartbeat()  # 停 heartbeat daemon(启动于 setup_display); 终态自停兜底
    clear_audit_session()
    from supernova_core.config.scan_env import clear_scan_env
    clear_scan_env()


@activity.defn
async def cleanup_auth_state_activity(workspace_path: str) -> None:
    """finally 收尾: 清理 auth-state*.json（glob 文件 I/O，sandbox 禁 workflow 直调）。

    workflow finally 原裸调 cleanup_auth_state_sync（glob.glob）→ 抛
    RestrictedWorkflowAccessError → WorkflowTask 反复 TimedOut → scan failed（与
    blackbox 同根因：带 auth config 的扫描登录后生成 auth-state.json，finally 走 cleanup 触发）。
    挪进 activity（worker 进程，不受 workflow sandbox 限制）。best-effort，失败由 workflow
    侧 try/except 吞掉不阻断收尾。对齐 blackbox cleanup_auth_state_activity。
    """
    from supernova_core.services.validate_authentication import cleanup_auth_state

    if not workspace_path:
        return
    try:
        await cleanup_auth_state(workspace_path)
    except Exception:  # noqa: BLE001 - best-effort cleanup
        pass
