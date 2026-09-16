import asyncio
import logging
import time
from pathlib import Path
from urllib.parse import urlparse

from temporalio import activity
from temporalio.exceptions import ApplicationError as ApplicationFailure

from supernova_core.models.agents import AgentName
from supernova_core.models.errors import ErrorCode, PentestError, classify_error_for_temporal
from supernova_core.models.metrics import end_reason_from_stop_reason
from supernova_core.models.retry import agent_retry_category, retry_for
from supernova_core.utils.security import validate_target_url, check_url_reachable
from supernova_core.utils.credential_validator import validate_credentials
from supernova_core.agents.executor import AgentExecutor
from supernova_core.prompts.manager import PromptManager
from supernova_core.utils.paths import (
    BLACKBOX_SUBDIR,
    WHITEBOX_SUBDIR,
    blackbox_dir,
    resolve_deliverables_path,
)

from supernova_core.services.validate_authentication import (
    validate_authentication,
    AuthValidationResult,
)
from supernova_core.audit.session_recovery import (
    build_headless_audit_session,
    ensure_audit_session,
)
from supernova_core.services.host_proxy import (
    start_host_proxy,
    stop_host_proxy as stop_host_proxy_func,
    ProxyHandle,
)
from supernova_core.runtime.temporal_heartbeat import with_activity_heartbeat

from .shared import BlackboxActivityInput, is_engine_failure
from supernova_blackbox.services.exploitation_checker import QueueValidationResult

logger = logging.getLogger(__name__)


# Phase 2（HOST 档案）：per-scan 本地代理句柄注册表。
# ``run_host_proxy_setup`` 写入（key=proxy_url），``stop_host_proxy`` pop 清理。
# 模块级——同 worker 进程内 setup/stop activity 共享（Temporal activity 同 worker 进程内执行）。
_PROXY_HANDLES: dict[str, ProxyHandle] = {}


def _get_deliverables_path(input: BlackboxActivityInput) -> Path:
    # C1 Phase B（黑盒 web 化）：workspace_path（web=event_file.parent=scan_dir）由
    # BlackboxScanWorkflow 算好传入（workflows.py C1 Phase B）。优先用它作 deliverables 根，
    # 使产物落 scan_dir，与 web DeliverablesReader 读取口径对齐——对齐 whitebox _get_paths
    # （activities.py:42-61，2026-07-30 修过同类分裂：旧 resolve_deliverables_path(workspace_name=
    # scan_id) 落 workspaces/<scan_id>/ 平铺目录，web 在 scan_dir/deliverables 读不到 → 0 漏洞）。
    # 无 workspace_path（activity 被直接调用、不经 workflow）回落 resolve_deliverables_path。
    if input.workspace_path:
        return Path(input.workspace_path) / input.deliverables_subdir
    return resolve_deliverables_path(
        repo_path=input.repo_path,
        deliverables_subdir=input.deliverables_subdir,
        workspace_name=input.workspace_name,
    )


# C1 Phase B（黑盒 web 化）：这两个 activity 仅 worker 容器路径调用（BlackboxScanWorkflow 接入）；
# CLI run_scan 不调用（CLI 自行 inline AuditSession/heartbeat，零改动）。setup_display 注入进程
# 全局 AuditSession 使后续 activity 的 get_audit_session() 可用；finalize_summary 写 scan_end 事件
# + 清理全局 session。直采 core audit 体系（whitebox 的 supernova_whitebox.audit.* 是 core shim）。


@activity.defn
async def setup_display(input: BlackboxActivityInput) -> None:
    """C1 前导 activity（黑盒 web 化）：构造 headless core AuditSession + 注入 event_file。

    worker 容器无 TTY，用 use_rich=False + Console()（自动检测非 TTY → 纯文本）。
    AuditSession.initialize(workflow_id, event_file=input.event_file) → WorkflowLogger 挂
    StructuredEventRenderer 写 events.ndjson（web live 页可见）。参照 whitebox setup_display
   （activities.py:1760-1807），但全用 core import（whitebox audit.* 仅 core 的 compat shim）。

    构造逻辑抽到 core ``build_headless_audit_session``，与 ``ensure_audit_session``（worker
    重启后可观测恢复）共用--见 session_recovery.py。
    """
    await build_headless_audit_session(input)
    from supernova_core.config.scan_env import set_scan_env
    set_scan_env(input.env_overrides)


@activity.defn
async def finalize_summary(input: BlackboxActivityInput, summary: dict) -> None:
    """C1 后置 activity（黑盒 web 化）：log_workflow_complete（→ StructuredEventRenderer 写 scan_end
    事件）+ 清 AuditSession/heartbeat。summary 由 workflow 从 self._state 构建（等价 whitebox
    finalize_summary activities.py:1810-1844）。CLI 路径不调用。
    """
    from supernova_core.logging.log_bus import LogBus
    from supernova_core.models.audit import WorkflowSummary
    from supernova_core.audit.session_registry import (
        NullAuditSession, clear_audit_session, get_audit_session,
    )
    from supernova_core.runtime.heartbeat import stop_heartbeat

    await ensure_audit_session(input)  # worker 重启后可观测恢复(幂等;见 session_recovery.py)
    session = get_audit_session()
    if not isinstance(session, NullAuditSession):
        # cost/cost_currency 取 session.get_metrics()（MetricsTracker 累积所有 agent，完整），
        # 非 summary dict（其 total_cost 来自 workflow state.agent_metrics，可能残缺）。对齐 whitebox。
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
        # final flush（dispatch 余下 LogEvent）在 log_workflow_complete 关闭 workflow_logger 之前。
        await LogBus.drain_and_detach()
        await session.log_workflow_complete(ws)
    await stop_heartbeat()  # 停 heartbeat daemon（启动于 setup_display）；终态自停兜底
    clear_audit_session()
    from supernova_core.config.scan_env import clear_scan_env
    clear_scan_env()


@activity.defn
async def run_host_proxy_setup(input: BlackboxActivityInput) -> str:
    """起 per-scan 本地代理（若 host_mappings 非空）。

    Phase 2（HOST 档案）：把 HOST→IP 映射塞进 proxy.py 子进程的 DNS 插件，让黑盒所有
    HTTP 出口统一走该代理。无映射（默认）返回 ``""``——扫描行为不变（backward compat）。
    失败 raise ``ApplicationFailure``（fail-fast； mappings 非空却起不来代理 = 配置/环境
    错，不应静默继续，否则扫描会落到错误的 IP 上）。
    """
    if not input.host_mappings:
        return ""
    try:
        handle = await start_host_proxy(input.host_mappings)
        _PROXY_HANDLES[handle.proxy_url] = handle
        return handle.proxy_url
    except PentestError as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e
    except Exception as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e


@activity.defn
async def stop_host_proxy(proxy_url: str) -> None:
    """best-effort 停代理（**绝不 raise**）。

    cleanup activity——失败只 swallow，不阻断 finally 收尾（Temporal cleanup 失败会
    让 workflow 卡在完成态）。空 url（未起代理）直接 return。
    """
    if not proxy_url:
        return
    handle = _PROXY_HANDLES.pop(proxy_url, None)
    if handle:
        try:
            await stop_host_proxy_func(handle)
        except Exception:  # noqa: BLE001 - cleanup best-effort，绝不 raise
            pass


@activity.defn
async def run_blackbox_preflight(input: BlackboxActivityInput) -> None:
    try:
        # URL safety and reachability checks (mandatory for blackbox)
        if input.web_url:
            # Phase 2（HOST 档案）：host_mappings 优先（bypass DNS for 内部 hostname）。
            pinned_ip = validate_target_url(input.web_url, host_mappings=input.host_mappings)
            reachable = await check_url_reachable(
                input.web_url,
                pinned_ip=pinned_ip,
                original_host=urlparse(input.web_url).hostname,
                proxy_url=input.proxy_url,
            )
            if not reachable:
                raise PentestError(
                    f"Target URL is not reachable: {input.web_url}",
                    category="preflight",
                    error_code=ErrorCode.TARGET_UNREACHABLE,
                )

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

        # Repo is optional for blackbox — skip git checks entirely
    except PentestError as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e
    except Exception as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e


@activity.defn
@with_activity_heartbeat
async def run_blackbox_auth_validation(input: BlackboxActivityInput) -> None:
    from supernova_core.audit.session_registry import get_audit_session
    await ensure_audit_session(input)  # worker 重启后可观测恢复(幂等;见 session_recovery.py)
    from supernova_core.audit.session_tool_audit_logger import SessionToolAuditLogger
    from supernova_core.models.audit import AgentEndResult, end_result_from_pentest_error
    from supernova_core.models.agents import AgentName

    agent_name = AgentName.VALIDATE_AUTH
    attempt = activity.info().attempt
    max_attempts = retry_for(agent_retry_category(agent_name.value)).maximum_attempts
    session = get_audit_session()
    tool_audit_logger = SessionToolAuditLogger(session, agent_name.value, attempt)
    agent_start = time.monotonic()
    try:
        from supernova_core.services.validate_authentication import validate_authentication

        prompts_dir = Path(__file__).resolve().parents[5] / "prompts"
        prompt_manager = PromptManager(prompts_dir)
        executor = AgentExecutor(prompt_manager)

        await session.start_agent(agent_name.value, f"agent={agent_name.value}", attempt=attempt)
        await tool_audit_logger.initialize()
        deliverables = _get_deliverables_path(input)
        result = await validate_authentication(
            web_url=input.web_url,
            config_path=input.config_path,
            workspace_path=input.workspace_path or "",
            prompt_manager=prompt_manager,
            executor=executor,
            repo_path=input.repo_path or "",
            deliverables_path=str(deliverables),
            api_key=input.api_key,
            provider_config=input.provider_config,
            tool_audit_logger=tool_audit_logger,
            proxy_url=input.proxy_url,
        )
    except PentestError as e:
        dur_ms = int((time.monotonic() - agent_start) * 1000)
        await tool_audit_logger.close(
            success=False, duration_ms=dur_ms,
            # 失败类别留痕（对齐 whitebox run_agent）
            end_reason=e.error_code.value if e.error_code else "error")
        # 失败 agent 也记 cost：从 PentestError.context 取 executor 携带的真实消耗
        # （修 error path cost 归 0），取不到回落 0（非 executor raise / probe 无 cost）。
        await session.end_agent(
            agent_name.value,
            end_result_from_pentest_error(e, duration_ms=dur_ms, attempt_number=attempt))
        await session.log_error(e, context=agent_name.value, attempt=attempt, max_attempts=max_attempts)
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e
    except Exception as e:
        await tool_audit_logger.close(
            success=False, duration_ms=int((time.monotonic() - agent_start) * 1000),
            end_reason="unexpected_error")
        await session.end_agent(agent_name.value, AgentEndResult(
            success=False, duration_ms=int((time.monotonic() - agent_start) * 1000), cost_usd=0.0,
            attempt_number=attempt, error=str(e)))
        await session.log_error(e, context=agent_name.value, attempt=attempt, max_attempts=max_attempts)
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e
    finally:
        # B 层机械收尾：validate-auth 的浏览器 session 是 manager._interpolate 的
        # BROWSER_SESSION_MAPPING 回落（VALIDATE_AUTH → agent1，models/agents.py），
        # 结束即回收，不等扫描级 finally（其 session_ids 只取 AGENT_SESSION_MAPPING
        # 的 5 个 exploit base id，agent1 本就不在扫描级清理集里）。
        from supernova_core.models.agents import BROWSER_SESSION_MAPPING
        await _cleanup_browser_session(
            input.repo_path, input.engine_name,
            [BROWSER_SESSION_MAPPING.get(AgentName.VALIDATE_AUTH.value, "agent1")])

    # validate_authentication 正常返回（未 raise）：可观测收尾按真实 verdict 记录，
    # 恰一次（旧版先记 success=True 再 raise PentestError 进 except 双记，黑盒 auth
    # 失败时 events 里 agent 显示成功——2026-08-14 修正）。fail-fast 直接 raise
    # ApplicationFailure（不再经 PentestError→except，避免双记）。
    dur_ms = int((time.monotonic() - agent_start) * 1000)
    await tool_audit_logger.close(
        success=result.success, duration_ms=dur_ms,
        # verdict=False 紧随 raise PentestError(AUTH_LOGIN_FAILED)，end_reason 同语义
        end_reason=None if result.success else "auth_login_failed")
    await session.end_agent(agent_name.value, AgentEndResult(
        success=result.success, duration_ms=dur_ms, cost_usd=0.0, attempt_number=attempt))
    if not result.success:
        err = PentestError(
            f"Authentication validation failed: {result.failure_detail or 'unknown'}",
            category="preflight",
            retryable=False,
            error_code=ErrorCode.AUTH_LOGIN_FAILED,
        )
        await session.log_error(err, context=agent_name.value, attempt=attempt,
                                max_attempts=max_attempts)
        error_type, retryable = classify_error_for_temporal(err)
        raise ApplicationFailure(str(err), type=error_type,
                                 non_retryable=not retryable) from err


async def _cleanup_browser_session(
    repo_path: str | None, engine_name: str | None, session_ids: list[str],
) -> None:
    """agent 结束即回收自己的浏览器 session（2026-09-03 xss 40min 事故 B 层机械收尾）。

    死占泄漏根因：exploit / auth-validation / endpoint-verify agent 各绑一个浏览器
    profile，agent 结束后 session 死占到扫描级 finally 的 cleanup_engine_configs——
    并行 agent 越晚结束，白背的已死 agent 浏览器越多（真机 274 chromium 压穿 4G
    worker，xss agent 空转烧满 40min 超时）。归属唯一（每 agent 独立 session id），
    per-session 清理不误杀并行 agent（pkill pattern 带 [- ] 分隔后缀，core 测试锁定）。
    engine_name 缺省（CLI 直跑 / 独立 AuthValidationWorkflow 未透传）→ 不清理，行为
    与现状一致。best-effort：清理失败绝不影响 agent 结果（吞掉）；扫描级 finally
    cleanup_engine_configs 保留兜底。activity 重试兼容：失败清理后 write_config
    幂等重写、agent 重开同 id session。
    """
    if not (repo_path and engine_name and session_ids):
        return
    try:
        from supernova_core.services.browser_engine import BrowserEngineFactory
        import supernova_core.services.engines  # noqa: F401 – registers engines

        engine = BrowserEngineFactory.get_engine(engine_name)
        engine.cleanup_processes(repo_path, session_ids=session_ids)
        for sid in session_ids:
            engine.cleanup_config(repo_path, session_id=sid)
    except Exception:  # noqa: BLE001 - best-effort，绝不影响 agent 结果
        pass


@activity.defn
@with_activity_heartbeat
async def run_exploit_agent(input: BlackboxActivityInput) -> dict:
    from supernova_core.audit.session_registry import get_audit_session
    await ensure_audit_session(input)  # worker 重启后可观测恢复(幂等;见 session_recovery.py)
    from supernova_core.audit.session_tool_audit_logger import SessionToolAuditLogger
    from supernova_core.models.audit import AgentEndResult, end_result_from_pentest_error

    vuln_type: str = input.vuln_type
    agent_name = AgentName(f"{vuln_type}-exploit")
    attempt = activity.info().attempt
    max_attempts = retry_for(agent_retry_category(agent_name.value)).maximum_attempts
    session = get_audit_session()
    tool_audit_logger = SessionToolAuditLogger(session, agent_name.value, attempt)
    agent_start = time.monotonic()
    try:
        from supernova_blackbox.agents.exploit_executor import ExploitExecutor

        deliverables = _get_deliverables_path(input)
        # spec 2026-08-08 根因修复：exploit 读 queue 用白盒根（repo_path/deliverables_subdir，
        # queue 在其 whitebox/ 子目录），而非黑盒自己 deliverables（空目录）。与 gating
        # validate_exploitation_queue 读根对齐。standalone（无 repo_path）回落 None →
        # exploit_executor 回落 deliverables_path（保持原行为）。
        queue_root = Path(input.repo_path) / input.deliverables_subdir if input.repo_path else None
        prompts_dir = Path(__file__).resolve().parents[5] / "prompts"
        prompt_manager = PromptManager(prompts_dir)
        executor = AgentExecutor(prompt_manager)
        exploit = ExploitExecutor(executor)

        await session.start_agent(agent_name.value, f"agent={agent_name.value}", attempt=attempt)
        await tool_audit_logger.initialize()
        metrics = await exploit.execute(
            agent_name=agent_name,
            vuln_type=vuln_type,
            workspace_path=deliverables.parent,
            deliverables_path=deliverables,
            web_url=input.web_url,
            config_path=input.config_path,
            api_key=input.api_key,
            provider_config=input.provider_config,
            pipeline_testing=input.pipeline_testing_mode,
            tool_audit_logger=tool_audit_logger,
            correlation_context=input.correlation_context,
            queue_root=queue_root,
            proxy_url=input.proxy_url,
        )
        await tool_audit_logger.close(
            success=True, duration_ms=metrics.duration_ms,
            # 截断/max_turns 假成功检测（对齐 whitebox run_agent）
            end_reason=end_reason_from_stop_reason(metrics.stop_reason))
        await session.end_agent(agent_name.value, AgentEndResult(
            success=True,
            duration_ms=metrics.duration_ms,
            cost_usd=metrics.cost_usd or 0.0,
            cost_currency=metrics.cost_currency,
            attempt_number=attempt,
            model=metrics.model,
            input_tokens=metrics.input_tokens,
            output_tokens=metrics.output_tokens,
            cache_read_tokens=metrics.cache_read_tokens,
            cache_creation_tokens=metrics.cache_creation_tokens,
        ))
        return metrics.model_dump()
    except PentestError as e:
        dur_ms = int((time.monotonic() - agent_start) * 1000)
        await tool_audit_logger.close(
            success=False, duration_ms=dur_ms,
            # 失败类别留痕（对齐 whitebox run_agent）
            end_reason=e.error_code.value if e.error_code else "error")
        # 失败 agent 也记 cost：从 PentestError.context 取 executor 携带的真实消耗
        # （修 error path cost 归 0），取不到回落 0（非 executor raise / probe 无 cost）。
        await session.end_agent(
            agent_name.value,
            end_result_from_pentest_error(e, duration_ms=dur_ms, attempt_number=attempt))
        await session.log_error(e, context=agent_name.value, attempt=attempt, max_attempts=max_attempts)
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e
    except Exception as e:
        await tool_audit_logger.close(
            success=False, duration_ms=int((time.monotonic() - agent_start) * 1000),
            end_reason="unexpected_error")
        await session.end_agent(agent_name.value, AgentEndResult(
            success=False, duration_ms=int((time.monotonic() - agent_start) * 1000), cost_usd=0.0,
            attempt_number=attempt, error=str(e)))
        await session.log_error(e, context=agent_name.value, attempt=attempt, max_attempts=max_attempts)
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e
    finally:
        # B 层机械收尾：agent 结束（成功/失败/异常）立即回收自己的浏览器 session，
        # 不等扫描级 finally（治死占——见 _cleanup_browser_session docstring）。
        from supernova_core.services.playwright_config_writer import get_session_id
        await _cleanup_browser_session(
            input.repo_path, input.engine_name, [get_session_id(agent_name.value)])


@activity.defn
@with_activity_heartbeat
async def run_endpoint_verify(input: BlackboxActivityInput) -> dict:
    """spec 2026-08-03: 端点 live 验证 agent。读白盒端点清单 + auth-state(AgentExecutor
    基层注入),对每端点做 live 验证 + 路由转发前缀探测,产 endpoint_verify.json 到 blackbox/。

    功能性失败(agent 崩/超时/LLM 不可用/无产出) → 返回 degraded(endpoint_verify=None),
    workflow 据此降级 exploit 全打(不 raise / 不重试 / 不中断)。endpoint_verify 是增强
    功能,失败=现状行为(零回归),故不浪费 budget 重试。"""
    from supernova_core.audit.session_registry import get_audit_session
    await ensure_audit_session(input)  # worker 重启后可观测恢复(幂等;见 session_recovery.py)
    from supernova_core.audit.session_tool_audit_logger import SessionToolAuditLogger
    from supernova_core.models.audit import AgentEndResult, end_result_from_pentest_error
    from supernova_core.models.agents import ALL_VULN_CLASSES

    agent_name = AgentName.ENDPOINT_VERIFY
    attempt = activity.info().attempt
    session = get_audit_session()
    tool_audit_logger = SessionToolAuditLogger(session, agent_name.value, attempt)
    agent_start = time.monotonic()
    try:
        from supernova_blackbox.agents.endpoint_verify_executor import EndpointVerifyExecutor

        deliverables = _get_deliverables_path(input)
        prompts_dir = Path(__file__).resolve().parents[5] / "prompts"
        prompt_manager = PromptManager(prompts_dir)
        executor = AgentExecutor(prompt_manager)
        verifier = EndpointVerifyExecutor(executor)

        await session.start_agent(agent_name.value, f"agent={agent_name.value}", attempt=attempt)
        await tool_audit_logger.initialize()
        result = await verifier.execute(
            deliverables_path=deliverables,
            workspace_path=deliverables.parent,
            web_url=input.web_url,
            vuln_classes=list(ALL_VULN_CLASSES),
            config_path=input.config_path,
            api_key=input.api_key,
            provider_config=input.provider_config,
            pipeline_testing=input.pipeline_testing_mode,
            tool_audit_logger=tool_audit_logger,
            proxy_url=input.proxy_url,
        )
        dur_ms = int((time.monotonic() - agent_start) * 1000)
        await tool_audit_logger.close(success=True, duration_ms=dur_ms,
                                      end_reason=None)
        await session.end_agent(agent_name.value, AgentEndResult(
            success=True,
            duration_ms=result.get("duration_ms", dur_ms) if isinstance(result, dict) else dur_ms,
            cost_usd=(result.get("cost_usd") or 0.0) if isinstance(result, dict) else 0.0,
            cost_currency=(result.get("cost_currency") if isinstance(result, dict) else None) or "USD",
            attempt_number=attempt,
        ))
        return result
    except Exception as e:
        dur_ms = int((time.monotonic() - agent_start) * 1000)
        await tool_audit_logger.close(success=False, duration_ms=dur_ms,
                                      end_reason="unexpected_error")
        await session.end_agent(agent_name.value, AgentEndResult(
            success=False, duration_ms=dur_ms, cost_usd=0.0,
            attempt_number=attempt, error=str(e)))
        # 降级:不 raise,返回 degraded。exploit 据此全打(零回归)。
        return {"endpoint_verify": None, "reason": f"{type(e).__name__}: {e}"}
    finally:
        # B 层机械收尾：endpoint-verify 用 get_session_id 回落 "default" session
        # （endpoint_verify_executor 同口径取 id），结束即回收，不等扫描级 finally。
        from supernova_core.services.playwright_config_writer import get_session_id
        await _cleanup_browser_session(
            input.repo_path, input.engine_name,
            [get_session_id(AgentName.ENDPOINT_VERIFY.value)])


@activity.defn
async def assemble_report(input: BlackboxActivityInput) -> None:
    try:
        from supernova_core.services.report_assembler import ReportAssembler
        from supernova_core.models.agents import ALL_VULN_CLASSES
        from supernova_core.services.findings_renderer import FindingsRenderer

        deliverables = _get_deliverables_path(input)
        vuln_classes: list[str] = list(ALL_VULN_CLASSES)
        bb = blackbox_dir(deliverables)
        bb.mkdir(parents=True, exist_ok=True)
        report_path = bb / "comprehensive_security_assessment_report.md"

        # T7（spec 2026-08-26 §6.1）：verdicts → blackbox/report_data.json（确定性
        # 结构化 SSOT，md 链路不变）。先于 md 链跑——report_data 只依赖 verdicts
        # （已在盘），md 侧失败/重试不影响其产出与幂等重写。non-fatal：失败
        # warning 不阻塞 md 报告（旧链路行为不变）。
        try:
            from supernova_core.services.report_data_blackbox import (
                write_blackbox_report_data,
            )
            session_path = (
                Path(input.workspace_path) / "session.json"
                if input.workspace_path else None)
            fallback_id = (
                input.workspace_name
                or (Path(input.workspace_path).name if input.workspace_path else "")
                or "blackbox")
            out = await write_blackbox_report_data(
                deliverables, session_path, fallback_id)
            logger.info("blackbox report_data.json written: %s", out)
        except Exception as exc:  # noqa: BLE001 — 结构化报告失败不阻塞 md 链路
            logger.warning(
                "blackbox report_data.json assembly failed (non-fatal): %s", exc)

        report_config = None
        if input.config_path:
            from supernova_core.config.parser import parse_config
            cfg = parse_config(input.config_path)
            report_config = cfg.report
        await FindingsRenderer.render_findings_from_queues(
            deliverables, report_config,
            queue_subdir=WHITEBOX_SUBDIR, findings_subdir=BLACKBOX_SUBDIR)

        # AU-6: exploit queue→evidence 闭环——未覆盖条目写入 evidence 未覆盖节，
        # ReportAssembler 读 evidence 全文时自动带入最终报告。
        from supernova_blackbox.services.coverage_renderer import close_coverage_gaps
        await close_coverage_gaps(deliverables, vuln_classes)

        # Order invariant: close_coverage_gaps mutates evidence above; ReportAssembler
        # reads evidence here — do not reorder (uncovered section would be missed).
        # ReportAssembler 收 bb（blackbox/）：黑盒 evidence/findings 在 blackbox/ 自洽。
        await ReportAssembler.assemble(bb, vuln_classes, report_path)
    except PentestError as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e
    except Exception as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e


@activity.defn
async def validate_exploitation_queue(input: BlackboxActivityInput) -> QueueValidationResult:
    """在 activity 内执行 exploitation queue 校验（文件 I/O 须在 sandbox 外）。

    ExploitationChecker.validate_queue 内部走 aiofiles（async_path_exists/async_read_file
    → run_in_executor），workflow sandbox 内直调会抛 NotImplementedError。本 activity 包装它，
    文件 I/O 全在 activity 内完成，workflow 侧只 execute_activity 拿回 QueueValidationResult。

    返回类型注解必须保留：temporalio 默认 converter 序列化 dataclass→json/plain，反序列化时
    只有拿到 ret_type 作 type_hint 才能还原 dataclass（worker/_workflow_instance.py:
    ``ret_types = [ret_type] if ret_type else None``）。缺注解→ret_type=None→workflow 侧拿到
    dict→validation.valid 抛 AttributeError（真机 exploitation gating 崩，单测不经 converter
    往返而漏）。见 test_validate_exploitation_queue_roundtrips_as_dataclass。
    """
    from supernova_blackbox.services.exploitation_checker import ExploitationChecker
    try:
        # 根因 1 修复：查白盒 queue 的根 = repo_path/deliverables_subdir（白盒产物所在），
        # 而非黑盒自己 _get_deliverables_path（workspace_path/deliverables_subdir，空）。
        # standalone（无 repo_path）回落 _get_deliverables_path。
        deliverables = (
            Path(input.repo_path) / input.deliverables_subdir
            if input.repo_path else _get_deliverables_path(input)
        )
        return await ExploitationChecker.validate_queue(
            vuln_type=input.vuln_type,
            deliverables_path=deliverables,
        )
    except PentestError as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e
    except Exception as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e


@activity.defn
@with_activity_heartbeat
async def run_report_agent(input: BlackboxActivityInput) -> dict:
    from supernova_core.audit.session_registry import get_audit_session
    await ensure_audit_session(input)  # worker 重启后可观测恢复(幂等;见 session_recovery.py)
    from supernova_core.audit.session_tool_audit_logger import SessionToolAuditLogger
    from supernova_core.models.audit import AgentEndResult, end_result_from_pentest_error

    agent_name = AgentName.REPORT
    attempt = activity.info().attempt
    max_attempts = retry_for(agent_retry_category(agent_name.value)).maximum_attempts
    session = get_audit_session()
    tool_audit_logger = SessionToolAuditLogger(session, agent_name.value, attempt)
    agent_start = time.monotonic()
    try:
        deliverables = _get_deliverables_path(input)
        # 对齐 assemble_report / finalize_report：黑盒报告落 deliverables/blackbox/。
        # report-executive prompt 假设 assemble 已在 {{DELIVERABLES_PATH}} 下拼好报告等它
        # Edit、validator 也校验同一路径。若传顶层 deliverables，agent 在顶层找不到
        # blackbox/ 里的拼接报告 → 发散自建、写错位置 → Missing deliverable（重试到死）。
        bb = blackbox_dir(deliverables)
        bb.mkdir(parents=True, exist_ok=True)
        prompts_dir = Path(__file__).resolve().parents[5] / "prompts"
        prompt_manager = PromptManager(prompts_dir)
        executor = AgentExecutor(prompt_manager)

        await session.start_agent(agent_name.value, f"agent={agent_name.value}", attempt=attempt)
        await tool_audit_logger.initialize()
        metrics = await executor.execute(
            agent_name=agent_name,
            repo_path=str(bb),
            web_url=input.web_url,
            deliverables_path=str(bb),
            config_path=input.config_path,
            api_key=input.api_key,
            provider_config=input.provider_config,
            pipeline_testing=input.pipeline_testing_mode,
            tool_audit_logger=tool_audit_logger,
            proxy_url=input.proxy_url,
        )
        await tool_audit_logger.close(
            success=True, duration_ms=metrics.duration_ms,
            # 截断/max_turns 假成功检测（对齐 whitebox run_agent）
            end_reason=end_reason_from_stop_reason(metrics.stop_reason))
        await session.end_agent(agent_name.value, AgentEndResult(
            success=True,
            duration_ms=metrics.duration_ms,
            cost_usd=metrics.cost_usd or 0.0,
            cost_currency=metrics.cost_currency,
            attempt_number=attempt,
            model=metrics.model,
            input_tokens=metrics.input_tokens,
            output_tokens=metrics.output_tokens,
            cache_read_tokens=metrics.cache_read_tokens,
            cache_creation_tokens=metrics.cache_creation_tokens,
        ))
        return metrics.model_dump()
    except PentestError as e:
        dur_ms = int((time.monotonic() - agent_start) * 1000)
        await tool_audit_logger.close(
            success=False, duration_ms=dur_ms,
            # 失败类别留痕（对齐 whitebox run_agent）
            end_reason=e.error_code.value if e.error_code else "error")
        # 失败 agent 也记 cost：从 PentestError.context 取 executor 携带的真实消耗
        # （修 error path cost 归 0），取不到回落 0（非 executor raise / probe 无 cost）。
        await session.end_agent(
            agent_name.value,
            end_result_from_pentest_error(e, duration_ms=dur_ms, attempt_number=attempt))
        await session.log_error(e, context=agent_name.value, attempt=attempt, max_attempts=max_attempts)
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e
    except Exception as e:
        await tool_audit_logger.close(
            success=False, duration_ms=int((time.monotonic() - agent_start) * 1000),
            end_reason="unexpected_error")
        await session.end_agent(agent_name.value, AgentEndResult(
            success=False, duration_ms=int((time.monotonic() - agent_start) * 1000), cost_usd=0.0,
            attempt_number=attempt, error=str(e)))
        await session.log_error(e, context=agent_name.value, attempt=attempt, max_attempts=max_attempts)
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e


@activity.defn
async def verify_report_vuln_blocks(input: BlackboxActivityInput) -> None:
    """report-executive 后校验 + 自愈(镜像 whitebox 同名防线,blackbox/ 口径)。

    黑盒链路同构暴露:assemble_report 拼 blackbox/ 报告 → run_report_agent 用
    同一份 report-executive prompt 重写——自写脚本压缩正文丢 ### ID 结构节
    会让前端报告页统计全 0(2026-08-19 回归,combined scan 白盒侧爆发)。
    节数不足 → 重新 assemble 覆盖 agent 版(丢执行摘要、保漏洞数据);须在
    run_report_agent 之后、finalize_report 之前。失败不阻塞(吞异常+warning)。
    """
    log = logging.getLogger(__name__)
    try:
        from supernova_core.models.agents import ALL_VULN_CLASSES
        from supernova_core.services.report_assembler import ReportAssembler
        from supernova_core.utils.file_io import async_path_exists

        bb = blackbox_dir(_get_deliverables_path(input))
        report_path = bb / "comprehensive_security_assessment_report.md"
        if not await async_path_exists(report_path):
            return  # 主报告不存在(agent 失败),无处校验
        vuln_classes = list(ALL_VULN_CLASSES)  # 对齐 assemble_report 口径
        actual, expected = await ReportAssembler.verify_vuln_block_coverage(
            bb, vuln_classes, report_path)
        if actual >= expected:
            return  # 覆盖完好(含无漏洞:0 >= 0)
        log.warning(
            "报告漏洞节覆盖不足(actual=%d < expected=%d):report-executive 丢失结构化"
            "漏洞节,重新 assemble 覆盖 agent 版(执行摘要丢弃,漏洞数据恢复)",
            actual, expected,
        )
        await ReportAssembler.assemble(bb, vuln_classes, report_path)
    except Exception as exc:  # noqa: BLE001 — 校验/自愈失败不阻塞主报告
        log.warning("verify_report_vuln_blocks failed (non-blocking): %s", exc)


@activity.defn
async def finalize_report(input: BlackboxActivityInput) -> None:
    try:
        from supernova_core.services.report_assembler import ReportAssembler
        from supernova_core.interfaces.report_output_provider import NoOpReportOutputProvider

        deliverables = _get_deliverables_path(input)
        bb = blackbox_dir(deliverables)
        bb.mkdir(parents=True, exist_ok=True)
        report_path = bb / "comprehensive_security_assessment_report.md"

        session_path = Path(input.workspace_path) / "session.json" if input.workspace_path else None
        if session_path:
            await ReportAssembler.inject_model_info(report_path, session_path)

        provider = NoOpReportOutputProvider()
        await provider.generate(report_path, deliverables)
    except PentestError as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e
    except Exception as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e


@activity.defn
async def log_phase_start_activity(input: BlackboxActivityInput,
                                   steps: list[str] | None = None,
                                   intents: list[str] | None = None) -> None:
    from supernova_core.audit.session_registry import get_audit_session
    await ensure_audit_session(input)  # worker 重启后可观测恢复(幂等;见 session_recovery.py)
    phase = input.phase or input.workspace_name or "unknown"
    await get_audit_session().log_phase_start(
        phase, steps=tuple(steps or ()), step_intents=tuple(intents or ()))


@activity.defn
async def log_phase_complete_activity(input: BlackboxActivityInput) -> None:
    from supernova_core.audit.session_registry import get_audit_session
    await ensure_audit_session(input)  # worker 重启后可观测恢复(幂等;见 session_recovery.py)
    phase = input.phase or input.workspace_name or "unknown"
    await get_audit_session().log_phase_complete(phase)


@activity.defn
async def log_info_activity(input: BlackboxActivityInput) -> None:
    from supernova_core.audit.session_registry import get_audit_session
    await ensure_audit_session(input)  # worker 重启后可观测恢复(幂等;见 session_recovery.py)
    try:
        await get_audit_session().log_info(input.info_message, input.info_level)
    except Exception:
        pass  # best-effort: 显示侧通道失败绝不影响扫描（尤其 except 块里调，避免替换原异常）


@activity.defn
async def persist_completed_agents(input: BlackboxActivityInput,
                                   completed_agents: list[str]) -> None:
    """completed_agents 增量落盘 run 级 session.json（2026-08-27 列表进度不动修复 · 写侧）。

    与 whitebox 侧同构：原只在 workflow 结束落盘 → 运行中恒 []，组合扫描黑盒段
    progress_pct 分子不动（钉死 55%）。workflow 在每个 agent 完成点调本 activity
    落盘（Temporal workflow 禁 IO）；异常由 workflow 侧 _persist_progress 吞。
    session.json 缺失（异常路径）no-op，防 update_session 写出残缺 session。
    """
    from supernova_core.session import SessionManager
    run_dir = Path(input.workspace_path)
    if not (run_dir / "session.json").exists():
        return
    SessionManager(run_dir.parent).update_session(
        run_dir, {"completed_agents": list(completed_agents)})


@activity.defn
async def load_correlation_context(corr_workspace_path: str) -> dict | None:
    """读关联 workspace 的 topology/boundaries 作为 exploitation 上下文（B2）。

    在 activity 内做文件 I/O（workflow sandbox 禁 Path.exists/read_text）。
    文件缺失返回 None（workflow 退回原逻辑）。corr_workspace_path 由 workflow 在
    sandbox 外用 ws_root 拼好后以 str 传入（Path 不便跨 Temporal payload 序列化）。
    """
    import json
    corr_workspace_path = Path(corr_workspace_path)
    dlv = corr_workspace_path / "deliverables"
    topo_f, bound_f = dlv / "cross-service-topology.json", dlv / "trust-boundaries.json"
    if not (topo_f.exists() and bound_f.exists()):
        return None
    return {
        "topology": json.loads(topo_f.read_text(encoding="utf-8")),
        "boundaries": json.loads(bound_f.read_text(encoding="utf-8")),
    }


@activity.defn
async def resolve_blackbox_engine(input: BlackboxActivityInput) -> str:
    """preflight: 解析 config + 解析/校验 engine + 写 deny rules + 写 stealth config。

    把原 workflow run() 体内 config/engine 初始化块的文件 I/O 与副作用（parse_config 读
    yaml、check_available 走 shutil.which、sync_code_path_deny_rules 写 settings.json、
    write_config 写 stealth config）整体挪进 activity——workflow sandbox 禁这些操作。
    返回 engine_name 供后续 exploit 循环复用（workflow 侧不再持有不可序列化的 engine 对象）。
    错误语义与原 workflow 块一致（BROWSER_ENGINE_UNAVAILABLE）。
    """
    try:
        from supernova_core.config.parser import parse_config
        from supernova_core.services.settings_writer import sync_code_path_deny_rules
        from supernova_core.services.browser_engine import BrowserEngineFactory
        import supernova_core.services.engines  # noqa: F401 – registers engines

        cfg = parse_config(input.config_path) if input.config_path else None
        # 无 config 时 fallback 经 ws_getenv 读 env（对齐 parser 的 env 优先级），
        # SUPERNOVA_BROWSER_ENGINE 显式配置不再被硬编码默认忽略。
        if cfg:
            engine_name = cfg.browser_engine
        else:
            from supernova_core.config.scan_env import ws_getenv
            env_engine = ws_getenv("SUPERNOVA_BROWSER_ENGINE")
            engine_name = env_engine.strip() if env_engine else "agent-browser"
        if engine_name == "agent-browser":
            # 2026-09-03 xss 40min 事故治本主力：agent-browser daemon 官方 idle 自愈
            # （README Architecture——"an integration that dies without calling close
            # cannot leak the daemon and its browser indefinitely"）。默认 1h 对扫描
            # 场景太长（死占窗口 35min << 1h，idle 门永远等不到），收紧到 5min——对齐
            # 云浏览器厂 session TTL 行业默认（Browserless TTL / Kernel TIMEOUT 均
            # 300s）。每条命令重置计时（活跃 agent 不受影响）；daemon 被 idle 回收后
            # 下一条命令自动重拉 + --profile 持久目录保住认证态。同时治两个泄漏源：
            # 死占（agent 结束后 5min 内 daemon 自杀）+ 野开 session（无人再发命令，
            # 同样 5min 自杀）。setdefault：部署者显式配置完全尊重。
            import os
            os.environ.setdefault("AGENT_BROWSER_IDLE_TIMEOUT_MS", "300000")
        try:
            engine = BrowserEngineFactory.get_engine(engine_name)
        except KeyError as e:
            raise PentestError(
                f"No browser engine registered as '{engine_name}'.",
                "browser",
                error_code=ErrorCode.BROWSER_ENGINE_UNAVAILABLE,
            ) from e
        if not engine.check_available():
            raise PentestError(
                f"Browser engine '{engine.name}' is not available. "
                f"Install it with: npm install -g {engine.name} && {engine.name} install",
                "browser",
                error_code=ErrorCode.BROWSER_ENGINE_UNAVAILABLE,
            )
        if cfg and cfg.rules and cfg.rules.avoid:
            sync_code_path_deny_rules(cfg.rules.avoid)
        if input.repo_path:
            # 修复 D（2026-09-03）：repo 级 config 带 per-scan proxy——playwright 代理
            # 唯一注入通道是 launchOptions（config 文件）；此 activity 运行时代理已起
            # （workflow 起 proxy → preflight → resolve），不传则 playwright 主扫描在
            # per-session config 写入前存在代理盲区。agent-browser write_config 忽略
            # proxy（走 session_flag --proxy），零影响。
            engine.write_config(input.repo_path, proxy_url=input.proxy_url or None)
        return engine_name
    except PentestError as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e
    except Exception as e:
        error_type, retryable = classify_error_for_temporal(e)
        raise ApplicationFailure(str(e), type=error_type, non_retryable=not retryable) from e


@activity.defn
async def detect_whitebox_results(
    deliverables_path: str,
    vuln_classes: list[str],
    correlation_deliverables_path: str | None,
) -> dict:
    """preflight: 检测单仓/关联 workspace 的有效白盒 queue（文件 I/O，sandbox 禁）。

    复刻原 workflow run() 的 has_valid_whitebox_results + §6.2 correlation 检测逻辑：
    单仓无结果才查关联（ADD 语义，任一有效即 skip recon）。state 更新与 log 留在
    workflow 侧（用返回值驱动）。corr 路径由 workflow 在 sandbox 外拼好后以 str 传入。
    返回 {has_whitebox_results, found_classes, corr_classes, has_recon_deliverable}。

    对齐 TS validateDeliverablesExist（activities.ts:1330）：recon_deliverable.md 是全局攻击面
    情报（exploit agent 读它拿 API inventory / input vectors / 技术栈），缺失则 exploit 失明。
    TS 在 queue 校验前先校验 recon 存在，缺即 nonRetryable fail。此处只报告 has_recon_deliverable
    （单仓；corr 不补 recon——exploit agent 从单仓 wb_queue_root 读 recon，corr 只补 queue 候选），
    fail-fast 决策留 workflow（与 has_whitebox_results 同构）。
    """
    from supernova_core.utils.paths import (
        has_valid_whitebox_results,
        resolve_track_deliverable,
        WHITEBOX_SUBDIR,
    )

    dlv = Path(deliverables_path)
    found_classes = [
        vt for vt in vuln_classes
        if has_valid_whitebox_results(
            resolve_track_deliverable(dlv, WHITEBOX_SUBDIR, f"{vt}_exploitation_queue.json"))
    ]
    corr_classes: list[str] = []
    if correlation_deliverables_path and not found_classes:
        corr_dlv = Path(correlation_deliverables_path)
        corr_classes = [
            vt for vt in vuln_classes
            if has_valid_whitebox_results(
                resolve_track_deliverable(corr_dlv, WHITEBOX_SUBDIR, f"{vt}_exploitation_queue.json"))
        ]
    has_recon_deliverable = resolve_track_deliverable(
        dlv, WHITEBOX_SUBDIR, "recon_deliverable.md").exists()
    return {
        "has_whitebox_results": bool(found_classes or corr_classes),
        "found_classes": found_classes,
        "corr_classes": corr_classes,
        "has_recon_deliverable": has_recon_deliverable,
    }


@activity.defn
async def write_engine_config_for_session(
    repo_path: str, session_id: str, engine_name: str,
    proxy_url: str | None = None,
) -> None:
    """exploit 循环: 为每个 agent session 写浏览器 stealth config（文件 I/O，sandbox 禁）。

    engine_name 由 resolve_blackbox_engine 在 preflight 解析后经 workflow 透传——engine
    对象不可跨 workflow/activity 边界，故每次按 engine_name 重新 get_engine。
    write_config 幂等（wrote/skipped-existing），即便 exploit executor 内部也写无害。
    proxy_url（Phase 2 HOST 档案）透传给 write_config，让 playwright launchOptions /
    agent-browser --proxy 走 per-scan 代理；None=不启用代理（backward compat）。
    """
    from supernova_core.services.browser_engine import BrowserEngineFactory
    import supernova_core.services.engines  # noqa: F401 – registers engines

    engine = BrowserEngineFactory.get_engine(engine_name)
    engine.write_config(repo_path, session_id=session_id, proxy_url=proxy_url)


@activity.defn
async def cleanup_engine_configs(repo_path: str, engine_name: str) -> None:
    """finally 收尾: 清理各 session 的浏览器 stealth config（文件 I/O，sandbox 禁）。

    与 write_engine_config_for_session 对称——engine_name 由 resolve_blackbox_engine 在
    preflight 解析后经 workflow 透传，engine 对象不可跨 workflow/activity 边界故按 engine_name
    重新 get_engine。best-effort cleanup（write_config 幂等，残留 config 下次覆盖），失败由
    workflow 侧 try/except 吞掉不阻断收尾。session_id 集合取自 AGENT_SESSION_MAPPING（同 worker
    进程，get_session_id 在 workflow 侧填充）。
    """
    from supernova_core.services.browser_engine import BrowserEngineFactory
    from supernova_core.services.playwright_config_writer import AGENT_SESSION_MAPPING
    import supernova_core.services.engines  # noqa: F401 – registers engines

    engine = BrowserEngineFactory.get_engine(engine_name)
    session_ids = list(set(AGENT_SESSION_MAPPING.values()))
    # 进程清理先于 config 清理(config 删 profile 目录不影响杀进程匹配)
    try:
        engine.cleanup_processes(repo_path, session_ids=session_ids)
    except Exception:  # noqa: BLE001 - best-effort
        pass
    for session_id in session_ids:
        engine.cleanup_config(repo_path, session_id=session_id)
    engine.cleanup_config(repo_path)


@activity.defn
async def cleanup_auth_state_activity(workspace_path: str) -> None:
    """finally 收尾: 清理 auth-state*.json（glob 文件 I/O，sandbox 禁 workflow 直调）。

    workflow finally 原裸调 cleanup_auth_state_sync（glob.glob）→ 抛
    RestrictedWorkflowAccessError → WorkflowTask 反复 TimedOut → 整个 scan failed（真机
    NodeGoat 黑盒扫描直接死因：带 auth config 的扫描登录后生成 auth-state.json，finally
    走 cleanup 触发）。挪进 activity（worker 进程，不受 workflow sandbox 限制）。best-effort，
    失败由 workflow 侧 try/except 吞掉不阻断收尾（auth-state 残留下次覆盖，无副作用）。
    """
    from supernova_core.services.validate_authentication import cleanup_auth_state

    if not workspace_path:
        return
    try:
        await cleanup_auth_state(workspace_path)
    except Exception:  # noqa: BLE001 - best-effort cleanup
        pass


@activity.defn
@with_activity_heartbeat
async def run_auth_validation_probe(input: BlackboxActivityInput) -> AuthValidationResult:
    """独立认证验证探针:驱动 validate_authentication 真实登录,失败不抛异常(降级返回)。

    与 run_blackbox_auth_validation 区别:后者在扫描流程内,失败抛 ApplicationFailure
    触发 fail-fast;本探针供"认证管理页 测试登录"独立入口,失败只回失败点不触发扫描。

    可观测性(对齐 run_blackbox_auth_validation):setup_display 已由 workflow 在本探针前
    调用并注册 AuditSession,故此处理 get_audit_session() 拿到真实 session → 接
    SessionToolAuditLogger(透传给 validate_authentication,使 agent 的 tool call / LLM
    turn 落 events.ndjson)+ start_agent/end_agent(发 AgentEvent)。这是"测试登录过程
    实时可见"的前提——否则 events.ndjson 只有 PhaseEvent/SummaryEvent,前端看不到过程。
    session 未注册(setup_display 失败)时 get_audit_session 返 NullAuditSession,no-op 安全。
    """
    from supernova_core.audit.session_registry import get_audit_session
    from supernova_core.audit.session_tool_audit_logger import SessionToolAuditLogger
    from supernova_core.models.audit import AgentEndResult, end_result_from_pentest_error

    await ensure_audit_session(input)  # worker 重启后可观测恢复(幂等;见 session_recovery.py)
    agent_name = AgentName.VALIDATE_AUTH
    try:
        attempt = activity.info().attempt
    except RuntimeError:
        # Direct unit/CLI invocation has no Temporal activity context.
        attempt = 1
    session = get_audit_session()
    tool_audit_logger = SessionToolAuditLogger(session, agent_name.value, attempt)
    agent_start = time.monotonic()
    await session.start_agent(agent_name.value, f"agent={agent_name.value}", attempt=attempt)
    await tool_audit_logger.initialize()

    prompts_dir = Path(__file__).resolve().parents[5] / "prompts"
    prompt_manager = PromptManager(prompts_dir)
    executor = AgentExecutor(prompt_manager)
    try:
        result = await validate_authentication(
            web_url=input.web_url,
            config_path=input.config_path,
            workspace_path=input.workspace_path or "",
            # 必传 deliverables_path:executor 已删 repo fallback(f1abf69d),
            # 不传则 raise ValueError。对齐 run_blackbox_auth_validation(:191)。
            # input.workspace_path=probe_dir 非空 → 落 probe_dir/<subdir>。
            deliverables_path=str(_get_deliverables_path(input)),
            prompt_manager=prompt_manager,
            executor=executor,
            api_key=input.api_key,
            provider_config=input.provider_config,
            tool_audit_logger=tool_audit_logger,
            proxy_url=input.proxy_url,
        )
    except Exception as e:
        # 降级:不 raise(仿 run_endpoint_verify activities.py:349-356),但照常收尾可观测性
        dur_ms = int((time.monotonic() - agent_start) * 1000)
        await tool_audit_logger.close(
            success=False, duration_ms=dur_ms,
            end_reason=(e.error_code.value
                        if isinstance(e, PentestError) and e.error_code
                        else "unexpected_error"))
        if isinstance(e, PentestError):
            # 失败 agent 也记 cost:PentestError.context 携带 executor 真实消耗(对齐 :195-205)
            await session.end_agent(
                agent_name.value,
                end_result_from_pentest_error(e, duration_ms=dur_ms, attempt_number=attempt))
        else:
            await session.end_agent(agent_name.value, AgentEndResult(
                success=False, duration_ms=dur_ms, cost_usd=0.0,
                attempt_number=attempt, error=str(e)))
        return AuthValidationResult(
            success=False,
            # LLM 引擎失败（provider 401/限额等）≠ 登录失败：分类成 engine 让前端
            # 指向 LLM 配置排查；其余维持 out_of_band（2026-08-17 NodeGoat 401 误读根因）。
            failure_point="engine" if is_engine_failure(e) else "out_of_band",
            failure_detail=f"{type(e).__name__}: {e}",
        )
    except BaseException as e:
        # cancel 兜底记账（2026-08-28 authcheck 超时丢账，NodeGoat-20260827-152204 现场）：
        # Temporal start_to_close_timeout 到期以 CancelledError cancel 掉 activity，
        # 穿透上方 except Exception（BaseException 分支）→ end_agent 永不执行 →
        # AgentEvent end 缺失、已花 usage 丢账。此处从 executor.usage_sink（provider
        # cancel 分支已写入的部分消耗）取值落 end_agent 后原样 re-raise——cancel/
        # 重试语义不变。sink 无值（引擎拿不到中途消耗）照记 0 的 end（有 end 行、
        # error 注明 cancelled，好过凭空消失）。记账 best-effort：失败不拦 cancel。
        dur_ms = int((time.monotonic() - agent_start) * 1000)
        sink = getattr(executor, "usage_sink", None)
        try:
            await asyncio.shield(session.end_agent(agent_name.value, AgentEndResult(
                success=False, duration_ms=dur_ms,
                cost_usd=sink.cost_usd if sink is not None else 0.0,
                cost_currency=(sink.cost_currency if sink is not None and sink.cost_currency
                               else "USD"),
                attempt_number=attempt,
                error=f"{type(e).__name__}: activity cancelled/timeout after {dur_ms}ms",
                model=sink.model if sink is not None else None,
                input_tokens=sink.input_tokens if sink is not None else None,
                output_tokens=sink.output_tokens if sink is not None else None,
                cache_read_tokens=sink.cache_read_tokens if sink is not None else None,
                cache_creation_tokens=(sink.cache_creation_tokens
                                       if sink is not None else None),
            )))
        except BaseException:
            pass  # shield 后再被 cancel / 记账失败：不拦原 cancel
        raise
    dur_ms = int((time.monotonic() - agent_start) * 1000)
    await tool_audit_logger.close(
        success=result.success, duration_ms=dur_ms,
        # verdict=False 紧随 raise PentestError(AUTH_LOGIN_FAILED)，end_reason 同语义
        end_reason=None if result.success else "auth_login_failed")
    await session.end_agent(agent_name.value, AgentEndResult(
        success=result.success, duration_ms=dur_ms, cost_usd=0.0, attempt_number=attempt))
    return result

