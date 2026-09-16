import asyncio
import time
from datetime import timedelta

from temporalio.client import Client
from temporalio.worker import Worker

from .pipeline.activities import (
    run_blackbox_preflight,
    run_blackbox_auth_validation,
    run_auth_validation_probe,
    run_exploit_agent,
    run_endpoint_verify,
    validate_exploitation_queue,
    assemble_report,
    run_report_agent,
    verify_report_vuln_blocks,
    finalize_report,
    log_phase_start_activity,
    log_phase_complete_activity,
    log_info_activity,
    persist_completed_agents,
    load_correlation_context,
    resolve_blackbox_engine,
    detect_whitebox_results,
    write_engine_config_for_session,
    cleanup_engine_configs,
    cleanup_auth_state_activity,
    setup_display,
    finalize_summary,
    run_host_proxy_setup,
    stop_host_proxy,
)
from .pipeline.workflows import BlackboxScanWorkflow
from .pipeline.shared import BlackboxPipelineInput, BlackboxPipelineState
from supernova_core.utils.paths import resolve_workspaces_dir
from supernova_core.runtime.workflow_timeout import scan_budget
from supernova_core.services.temporal_infra import generate_task_queue
from supernova_core.models.metrics import SessionMetadata
from supernova_core.models.audit import AgentMetricsSummary, WorkflowSummary
from supernova_core.audit.display_lifecycle import run_with_display
from supernova_core.display.structured_event_renderer import wire_web_event_file
from supernova_core.audit.session_registry import set_audit_session, clear_audit_session
from supernova_core.services.scan_gate import scan_gate_try_acquire, scan_gate_release
from supernova_core.runtime.heartbeat import HeartbeatManager, mark_owner_if_unset
from supernova_core.runtime.scan_runner import (
    ScanCancelled,
    ShutdownController,
    await_workflow_with_shutdown,
)

TASK_QUEUE_PREFIX = "supernova-bb"


def _resolve_engine_name(config_path: str | None) -> str | None:
    """从 config 解析 engine_name(无 config / 解析失败返回 None)。"""
    if not config_path:
        return None
    try:
        from supernova_core.config.parser import parse_config

        cfg = parse_config(config_path)
        return cfg.browser_engine
    except Exception:  # noqa: BLE001
        return None


def build_browser_cleanup_callback(repo_path: str, engine_name: str | None):
    """构造同步 cleanup 函数,供 ShutdownController 在 os._exit 前调用(强退路径)。

    engine_name 为 None(无 config)时返回 no-op;否则 get_engine + cleanup_processes。
    全程不抛(强退路径绝不崩)。
    """
    if not engine_name:
        return lambda session_ids=None: None

    def _cleanup(session_ids=None) -> None:
        try:
            import supernova_core.services.engines  # noqa: F401 – registers engines
            from supernova_core.services.browser_engine import BrowserEngineFactory

            engine = BrowserEngineFactory.get_engine(engine_name)
            engine.cleanup_processes(repo_path, session_ids=session_ids)
        except Exception:  # noqa: BLE001 - best-effort
            pass

    return _cleanup


def _to_workflow_summary(result: BlackboxPipelineState, total_duration_ms: int) -> WorkflowSummary:
    status = result.status if result.status in ("completed", "failed", "cancelled") else "failed"
    return WorkflowSummary(
        status=status,  # type: ignore[arg-type]
        total_duration_ms=total_duration_ms,
        total_cost_usd=sum((m.get("cost_usd") or 0.0) for m in result.agent_metrics.values()),
        completed_agents=list(result.completed_agents),
        agent_metrics={
            name: AgentMetricsSummary(
                duration_ms=int(m.get("duration_ms") or 0),
                cost_usd=m.get("cost_usd"),
            )
            for name, m in result.agent_metrics.items()
        },
        error=result.errors[-1] if result.errors else None,
    )


async def run_scan(input: BlackboxPipelineInput, temporal_address: str = "localhost:7233",
                   use_rich: bool = False) -> BlackboxPipelineState:
    """跑黑盒扫描；Ctrl+C 时优雅取消并返回 BlackboxPipelineState(status="cancelled")。"""
    # 防御：确保 workspaces_root 在 sandbox 外解析好（CLI 通常已填；兜底其它入口/测试）。
    # workflow sandbox 内禁 os.getenv/Path.cwd，run() 会因 workspaces_root 为 None 而 fail-fast。
    if not input.workspaces_root:
        input.workspaces_root = str(resolve_workspaces_dir(input.repo_path))

    # 纯黑盒场景（无白盒 session 可接）：worker 自建一个 blackbox session，
    # deliverables 落 workspaces/<自建session>/deliverables（spec 决策 6）。
    if not input.workspace_name:
        from supernova_core.session import SessionManager
        workspaces_dir = resolve_workspaces_dir(input.repo_path)
        mgr = SessionManager(workspaces_dir)
        ws_path = mgr.create_workspace(
            web_url=input.web_url or "",
            repo_path=input.repo_path or "",
            name=None,
            scan_type="blackbox",
        )
        input.workspace_name = ws_path.name

    # CLI(uv run)启动的扫描默认把 events.ndjson 落到本 workspace,使 supernova-web 实时页
    # (SSE tail events.ndjson)可见。setdefault:WEB 启动时 scan_manager 已注入该 env → 不覆盖。
    wire_web_event_file(resolve_workspaces_dir(input.repo_path), input.workspace_name)
    ws_dir = resolve_workspaces_dir(input.repo_path) / input.workspace_name
    # CLI 起 owner=host(web 起时 scan_manager 已写 owner=web,mark_owner_if_unset 不覆盖)。
    mark_owner_if_unset(ws_dir, "host")

    client = await Client.connect(temporal_address)
    task_queue = generate_task_queue(TASK_QUEUE_PREFIX)

    worker = Worker(
        client=client,
        task_queue=task_queue,
        workflows=[BlackboxScanWorkflow],
        activities=[
            run_blackbox_preflight, run_blackbox_auth_validation,
            run_auth_validation_probe,
            run_exploit_agent, run_endpoint_verify,
            validate_exploitation_queue, assemble_report, run_report_agent,
            verify_report_vuln_blocks,
            finalize_report,
            log_phase_start_activity, log_phase_complete_activity,
            log_info_activity,
            persist_completed_agents,
            load_correlation_context,
            resolve_blackbox_engine, detect_whitebox_results, write_engine_config_for_session,
            cleanup_engine_configs,
            cleanup_auth_state_activity,
            setup_display, finalize_summary,
            run_host_proxy_setup, stop_host_proxy,
            # 全局扫描闸门（spec 2026-09-08-worker-scan-gate §5）：CLI 进程独立
            # gate 实例（空闸直接 granted），但 activity 必须注册——漏注册 =
            # workflow 卡闸门段（unregistered activity 无限重试）。
            scan_gate_try_acquire, scan_gate_release,
        ],
        graceful_shutdown_timeout=timedelta(seconds=10),
    )

    meta = SessionMetadata(
        id=input.workspace_name or "blackbox-scan",
        web_url=input.web_url,
        repo_path=input.repo_path,
        output_path=str(resolve_workspaces_dir(input.repo_path)),
    )

    # rerun：归档旧 evidence + workflow id 加时间戳规避 AlreadyStarted
    workflow_id_base = input.workspace_name or f"blackbox-{int(asyncio.get_running_loop().time())}"
    if input.rerun:
        from datetime import datetime
        from supernova_core.utils.paths import resolve_deliverables_path
        from supernova_blackbox.pipeline.blackbox_rerun import archive_blackbox_deliverables
        deliverables = resolve_deliverables_path(
            repo_path=input.repo_path,
            deliverables_subdir=input.deliverables_subdir,
            workspace_name=input.workspace_name,
            workspaces_root=resolve_workspaces_dir(input.repo_path),
        )
        run_ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        archive_blackbox_deliverables(deliverables, run_ts)
        workflow_id = f"{workflow_id_base}-rerun-{run_ts}"
    else:
        workflow_id = workflow_id_base

    ctrl = ShutdownController()
    engine_name = _resolve_engine_name(input.config_path)
    ctrl.install(
        asyncio.get_running_loop(),
        cleanup_callback=build_browser_cleanup_callback(input.repo_path, engine_name),
    )
    # 进程级心跳:周期写 heartbeat(web 据其 mtime 判活)+ 监听 cancel.requested(web Cancel
    # 宿主 scan 时协作式自退 → ctrl._trigger_graceful)。独立于 Temporal 调度:worker 活就跳、死就停。
    heartbeat = HeartbeatManager(ws_dir, on_cancel=ctrl._trigger_graceful)
    try:
        await heartbeat.__aenter__()
        async with worker:
            async with run_with_display(meta, use_rich=use_rich) as session:
                # P3c 阶段 3：显式传 workflow_id(= start_workflow 的 id)对齐 activity 内
                # get_audit_session() 的 activity.info().workflow_id(CLI 非 activity context
                # 默认落 '_cli' 会失配)。详见 whitebox worker.py 同段注释。
                set_audit_session(session, workflow_id=workflow_id)
                scan_start = time.monotonic()
                handle = await client.start_workflow(
                    BlackboxScanWorkflow.run,
                    input,
                    id=workflow_id,
                    task_queue=task_queue,
                    run_timeout=scan_budget(),
                )
                try:
                    result = await await_workflow_with_shutdown(
                        handle, ctrl, cancel_grace_seconds=15.0,
                    )
                except ScanCancelled:
                    return BlackboxPipelineState(status="cancelled")
                except Exception as e:
                    # Workflow-level failure: finalize the dashboard with a failed
                    # summary so the Live context closes cleanly, then re-raise so
                    # the CLI surfaces the error. (In-activity failures are already
                    # surfaced via log_error during the run; this covers workflow-
                    # level raises like browser-engine-unavailable / config-parse.)
                    await session.log_workflow_complete(_to_workflow_summary(
                        BlackboxPipelineState(status="failed", errors=[str(e)]),
                        int((time.monotonic() - scan_start) * 1000),
                    ))
                    raise
                finally:
                    clear_audit_session(workflow_id=workflow_id)

                total_duration_ms = int((time.monotonic() - scan_start) * 1000)
                await session.log_workflow_complete(_to_workflow_summary(result, total_duration_ms))
                return result
    finally:
        await heartbeat.__aexit__(None, None, None)
        ctrl.uninstall()


def main():
    import sys
    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"
    asyncio.run(run_scan(BlackboxPipelineInput(web_url=url)))
