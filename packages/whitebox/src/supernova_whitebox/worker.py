import asyncio
import json
import time
from dataclasses import asdict
from datetime import datetime, timedelta
from pathlib import Path

from temporalio.client import Client
from temporalio.worker import Worker

from supernova_core.display.structured_event_renderer import wire_web_event_file
from supernova_core.models.audit import WorkflowSummary, AgentMetricsSummary
from supernova_core.runtime.workflow_timeout import workflow_run_timeout

from .pipeline.activities import (
    render_findings,
    assemble_report,
    run_agent,
    run_recon_context_digest,
    run_authz_gitnexus_judge,
    run_code_index,
    run_credential_check,
    run_merge_dual_track_queues,
    run_adversarial_review,
    run_gn_finding_enrichment,
    run_endpoint_enrichment,
    run_report_polish,
    run_assemble_dataflow_view,
    run_assemble_api_evidence,
    run_merge_sink_reports,
    run_entry_point_fusion,
    run_preflight,
    run_risk_scoring,
    run_save_adjudication,
    run_vuln_agent,
    run_attack_chain_llm_agent,
    run_attack_chain_assembly_v2,
    run_framework_analysis,
    run_frontend_mapping,
    run_gitnexus_chain_verdict,
    run_route_chain_building,
    write_agent_poc,
    export_report_markdown_files,
    verify_report_vuln_blocks,
    inject_attack_chains,
    inject_gitnexus_track_status,
    write_track_status_activity,
    log_phase_start_activity,
    log_phase_complete_activity,
    log_info_activity,
    persist_completed_agents,
    setup_display,
    finalize_summary,
    cleanup_auth_state_activity,
)
from .pipeline.workflows import WhiteboxScanWorkflow
from .pipeline.shared import PipelineInput, PipelineState
from supernova_core.services.scan_gate import scan_gate_try_acquire, scan_gate_release
from supernova_core.utils.paths import resolve_workspaces_dir
from supernova_core.services.temporal_infra import generate_task_queue
from supernova_core.runtime.heartbeat import HeartbeatManager, mark_owner_if_unset
from supernova_core.runtime.scan_runner import (
    ScanCancelled,
    ShutdownController,
    await_workflow_with_shutdown,
)

TASK_QUEUE_PREFIX = "supernova-wb"


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


def resolve_workflow_id(
    workspace_name: str | None, epoch: float, resume_attempt: int = 0
) -> str:
    """Single source of truth for the Temporal workflow id.

    Used for both the WorkflowHeader banner (meta.id → web_ui_url / logs_cmd)
    and client.start_workflow(id=...) so the Web UI link points at the real run.

    resume_attempt > 0 且有 workspace_name 时追加 ``-resume-{n}``，规避与旧
    workflow 的 Temporal ``AlreadyStarted`` 冲突。默认 0 保证向后兼容。
    """
    if resume_attempt > 0 and workspace_name:
        return f"{workspace_name}-resume-{resume_attempt}"
    return workspace_name or f"whitebox-{int(epoch)}"


async def _build_final_summary(result, session, scan_start: float) -> WorkflowSummary:
    """构建最终 WorkflowSummary(cost 取 session metrics,非 PipelineState.agent_metrics)。

    cost / cost_currency 取 ``session.get_metrics()`` —— MetricsTracker 是 single source
    of truth,累积了**所有**经 run_agent 的 agent(含 attack-chain/report/auth-gitnexus 等)+
    所有 attempt。**不**从 ``PipelineState.agent_metrics`` 算:后者只在 workflows.py 三处
    (pre-recon/recon/vuln)赋值,LLM 轨关闭时为空 → 旧 ``sum(agent_metrics.cost_usd)`` 在
    LLM 轨关时 = 0(回归 NodeGoat CLI 最终 ``Total Cost: $0.0000``,而真实 cost 躺在
    session.json)。

    duration 取 wall-clock(``scan_start`` 到 now,扫描总耗时,含 agent 间隙/并行),非
    MetricsTracker 的 agent 累计时长(那是另一语义,前端 OverviewTab 单独读 session.json)。
    """
    status = (
        result.status
        if isinstance(result.status, str) and result.status in ("completed", "failed", "cancelled")
        else "failed"
    )
    final_metrics = await session.get_metrics() or {}
    cost_currency = final_metrics.get("cost_currency") or "USD"
    raw_agents = final_metrics.get("agents") or {}
    agent_metrics_summary = {
        name: AgentMetricsSummary(
            duration_ms=int(a.get("duration_ms", 0) or 0),
            cost_usd=a.get("cost_usd"),
            cost_currency=a.get("cost_currency") or cost_currency,
            input_tokens=a.get("input_tokens"),
            output_tokens=a.get("output_tokens"),
            cache_read_tokens=a.get("cache_read_tokens"),
            cache_creation_tokens=a.get("cache_creation_tokens"),
        )
        for name, a in raw_agents.items()
        if isinstance(a, dict)
    }
    return WorkflowSummary(
        status=status,
        total_duration_ms=int((time.monotonic() - scan_start) * 1000),
        total_cost_usd=final_metrics.get("total_cost_usd") or 0.0,
        cost_currency=cost_currency,
        completed_agents=list(result.completed_agents or []),
        agent_metrics=agent_metrics_summary,
        error=(result.errors[0] if result.errors else None),
    )


async def run_scan(input: PipelineInput, temporal_address: str = "localhost:7233",
                   use_rich: bool = False) -> dict:
    from supernova_core.session import SessionManager
    from supernova_core.models.metrics import SessionMetadata
    from supernova_whitebox.audit.display_lifecycle import run_with_display

    # 用户是否显式传 -w：仅显式 -w 才视为 resume 已有 session 的意图。
    # 无 -w 时自动生成的 session 是全新扫描，不该触发 resume 对账——否则一个历史
    # repo 的 git deliverable commit 会与新建空 session 的 deliverables 对账（G∧¬F
    # 误判"文件被误删"而中止）。
    explicit_workspace = bool(input.workspace_name)

    # 持久化 session（无 -w 时自动生成 name 并回填，使 deliverables/session_id 解析一致）
    workspaces_dir = resolve_workspaces_dir(input.repo_path)
    mgr = SessionManager(workspaces_dir)
    ws_path = mgr.create_workspace(
        web_url=input.web_url or "",
        repo_path=input.repo_path,
        name=input.workspace_name,
    )
    input.workspace_name = ws_path.name

    # CLI(uv run)启动的扫描默认把 events.ndjson 落到本 workspace,使 supernova-web 实时页
    # (SSE tail events.ndjson)可见。setdefault:WEB 启动时 scan_manager 已注入该 env → 不覆盖。
    wire_web_event_file(workspaces_dir, input.workspace_name)
    # CLI 起 owner=host(web 起时 scan_manager 已写 owner=web,mark_owner_if_unset 不覆盖)。
    mark_owner_if_unset(ws_path, "host")

    client = await Client.connect(temporal_address)
    task_queue = generate_task_queue(TASK_QUEUE_PREFIX)

    worker = Worker(
        client=client,
        task_queue=task_queue,
        workflows=[WhiteboxScanWorkflow],
        activities=[
            render_findings, assemble_report, run_agent,
            run_recon_context_digest,
            run_authz_gitnexus_judge, run_code_index,
            run_credential_check, run_merge_dual_track_queues,
            run_adversarial_review,
            run_gn_finding_enrichment,
            run_endpoint_enrichment,
            run_report_polish,
            run_assemble_dataflow_view,
            run_assemble_api_evidence,
            run_merge_sink_reports, run_entry_point_fusion,
            run_preflight, run_risk_scoring,
            run_save_adjudication, run_vuln_agent,
            run_attack_chain_llm_agent, run_attack_chain_assembly_v2,
            run_framework_analysis, run_frontend_mapping,
            run_gitnexus_chain_verdict,
            run_route_chain_building,
                    write_agent_poc,
            export_report_markdown_files,
            verify_report_vuln_blocks,
            inject_attack_chains,
            inject_gitnexus_track_status,
            write_track_status_activity,
            log_phase_start_activity, log_phase_complete_activity,
            log_info_activity,
            persist_completed_agents,
            setup_display, finalize_summary,
            cleanup_auth_state_activity,
            # 全局扫描闸门（spec 2026-09-08-worker-scan-gate §5）：CLI 进程独立
            # gate 实例（空闸直接 granted），但 activity 必须注册——漏注册 =
            # workflow 卡闸门段（unregistered activity 无限重试）。
            scan_gate_try_acquire, scan_gate_release,
        ],
        graceful_shutdown_timeout=timedelta(seconds=10),
    )

    loop = asyncio.get_running_loop()

    # resume 探测：从磁盘重建 completed_agents，激活 workflow 的空壳守卫。
    # fresh 模式（input._fresh=True）或无 workspace_name 跳过整个探测块。
    # None = 尚未计算（fresh/首次/无 completed_agents）；>=1 = resume 第 N 次。
    # 用哨兵而非 0，避免下方 "if not resume_attempt" 把 0 当 falsy 与"未设置"混淆。
    resume_attempt = 0
    workflow_id: str | None = None
    is_fresh = bool(getattr(input, "_fresh", False))
    if explicit_workspace and not is_fresh:
        from supernova_whitebox.pipeline.whitebox_resume import (
            WhiteboxResumeStateBuilder,
        )
        from supernova_core.utils.paths import resolve_deliverables_path

        workspaces_dir = resolve_workspaces_dir(input.repo_path)
        ws_dir = workspaces_dir / input.workspace_name
        deliverables = resolve_deliverables_path(
            input.repo_path, input.deliverables_subdir, input.workspace_name,
        )
        rewind_target = getattr(input, "_rewind_target", None)
        mode = "rewind" if rewind_target else "auto"

        builder = WhiteboxResumeStateBuilder()
        rstate = await builder.build(
            mode=mode,
            workspace=ws_dir,
            deliverables=deliverables,
            repo_path=Path(input.repo_path),
            rewind_target=rewind_target,
        )
        if rstate.aborted:
            raise RuntimeError(rstate.abort_reason)

        if rstate.completed_agents:
            input.resume_completed_agents = rstate.completed_agents

            # === top-level `resumeAttempts` schema 说明 ===
            # worker 把 resume 计数记录在 session.json 的 **top-level** `resumeAttempts`
            #（与 repo_path / web_url / created_at 同层）。这是 worker resume 逻辑的
            # canonical 位置：resume_attempt = len(top-level resumeAttempts) + 1，
            # resume 成功后向它 append 一条。它与 MetricsTracker 拥有的嵌套
            # `session.resumeAttempts`（audit/UI 显示用，被 initialize 重置、目前由
            # add_resume_attempt 写入）刻意分离 —— 不同所有者、不同生命周期。
            # 跨 MetricsTracker.initialize 的存活依赖 initialize 用 `dict(existing)`
            # 浅拷贝保留所有 top-level key（MetricsTracker 只 owns `session`/`metrics`
            # 两个子树）。见 test_resume_attempts_survive_metrics_tracker_initialize。

            # 决策 2：resume_attempt 从 session.json 的 top-level resumeAttempts 读 len+1
            session_file = ws_dir / "session.json"
            n = 1
            if session_file.exists():
                try:
                    existing = json.loads(
                        session_file.read_text(encoding="utf-8"))
                    attempts = existing.get("resumeAttempts") or []
                    if isinstance(attempts, list):
                        n = len(attempts) + 1
                except (json.JSONDecodeError, OSError):
                    n = 1
            resume_attempt = n

            # 决策 5：rewind cleanup 需要 run_ts 做归档目录名
            cleanup_kwargs = dict(
                mode=mode,
                deliverables=deliverables,
                completed_agents=rstate.completed_agents,
                rewind_target=rewind_target,
            )
            if mode == "rewind":
                cleanup_kwargs["run_ts"] = datetime.now().strftime(
                    "%Y%m%d-%H%M%S")
            await builder.cleanup(**cleanup_kwargs)

            # 决策 4：resume 成功后追加一条到 top-level resumeAttempts。
            # workflow_id 只算一次（含 resume_attempt），preview 与下方实际
            # start_workflow(id=...) 复用同一个值。
            workflow_id = resolve_workflow_id(
                input.workspace_name, loop.time(), resume_attempt)
            terminated = (
                [rstate.interrupted_agent] if rstate.interrupted_agent else []
            )
            self_mgr = SessionManager(workspaces_dir)
            ws_path = self_mgr.get_workspace(input.workspace_name)
            if ws_path is not None:
                data = self_mgr.get_session_data(ws_path)
                attempts = data.get("resumeAttempts") or []
                attempts.append({
                    "workflowId": workflow_id,
                    "terminatedAgents": terminated,
                    "checkpoint": None,
                })
                data["resumeAttempts"] = attempts
                self_mgr.update_session(ws_path, data)

    # 非恢复路径（fresh/首次/无 completed_agents）：resume_attempt 仍为 0，
    # workflow_id 尚未在恢复分支内计算，这里补算。恢复路径已在上方算过，直接复用。
    if workflow_id is None:
        workflow_id = resolve_workflow_id(
            input.workspace_name, loop.time(), resume_attempt)

    # 决策 1：meta.id 固定 = workspace_name（若有），保证 MetricsTracker 写
    # session.json 的目录 = workspace_name/，与 builder 下次 resume 读取路径一致。
    # resume 时 workflow_id 会变 workspace_name-resume-N，但 session.json 必须仍
    # 累积在 workspace_name/ 下。fresh/首次扫描（有 workspace_name）行为不变。
    session_id = input.workspace_name or workflow_id

    meta = SessionMetadata(
        id=session_id,
        web_url=input.web_url,
        repo_path=input.repo_path,
        output_path=str(resolve_workspaces_dir(input.repo_path)),
    )

    ctrl = ShutdownController()
    engine_name = _resolve_engine_name(input.config_path)
    ctrl.install(
        asyncio.get_running_loop(),
        cleanup_callback=build_browser_cleanup_callback(input.repo_path, engine_name),
    )
    # 进程级心跳:周期写 heartbeat(web 据其 mtime 判活)+ 监听 cancel.requested(web Cancel
    # 宿主 scan 时协作式自退 → ctrl._trigger_graceful 复用 SIGINT 的 graceful 取消)。独立于
    # Temporal workflow/activity 调度——worker 活就跳、死就停(spec §4.1/§4.5)。
    heartbeat = HeartbeatManager(ws_path, on_cancel=ctrl._trigger_graceful)
    try:
        await heartbeat.__aenter__()
        async with worker:
            async with run_with_display(meta, use_rich=use_rich) as session:
                from supernova_whitebox.audit.session_registry import (
                    set_audit_session, clear_audit_session,
                )
                # P3c 阶段 3：显式传 workflow_id(= start_workflow 的 id)——CLI 在 workflow
                # 启动前(非 activity context)调,set 默认会落 '_cli';而 activity 内
                # get_audit_session() 经 activity.info().workflow_id 查真实 wf id。传真实
                # workflow_id 让两者匹配(activity 拿到 session 而非 NullAuditSession)。
                set_audit_session(session, workflow_id=workflow_id)
                scan_start = time.monotonic()
                try:
                    handle = await client.start_workflow(
                        WhiteboxScanWorkflow.run,
                        input,
                        id=workflow_id,
                        task_queue=task_queue,
                        run_timeout=workflow_run_timeout(),
                    )
                    try:
                        # progress_type=None: Rich 仪表盘已负责进度展示，不重复 poll 打印。
                        result = await await_workflow_with_shutdown(
                            handle, ctrl, cancel_grace_seconds=15.0,
                        )
                    except ScanCancelled:
                        # session-status 同步:cancelled 落盘(原版只 return → session 永远 running)。
                        await session.log_workflow_complete(
                            await _build_final_summary(
                                PipelineState(status="cancelled"),
                                session, scan_start))
                        return {"status": "cancelled"}
                    except Exception as e:
                        # session-status 同步:workflow FAILED 兜底(workflow except 没跑到的场景,
                        # 如被 terminate / sandbox 崩)。抄 blackbox worker.py:201-211。
                        await session.log_workflow_complete(
                            await _build_final_summary(
                                PipelineState(status="failed", errors=[str(e)]),
                                session, scan_start))
                        raise
                finally:
                    clear_audit_session(workflow_id=workflow_id)

                # Emit the final summary so the Rich summary table / dashboard
                # finalization fires. cost/currency 取 session metrics(MetricsTracker 累积
                # 所有 agent,完整),非 PipelineState.agent_metrics(LLM 轨关时残缺→0)。
                summary = await _build_final_summary(result, session, scan_start)
                await session.log_workflow_complete(summary)

                result_dict = asdict(result) if not isinstance(result, dict) else dict(result)
                result_dict["workspace_name"] = input.workspace_name
                result_dict["web_url"] = input.web_url

                # deliverables 落 session 下（workspaces/<session>/deliverables）
                from supernova_core.utils.paths import resolve_deliverables_path
                result_dict["deliverables_path"] = str(
                    resolve_deliverables_path(
                        repo_path=input.repo_path,
                        deliverables_subdir=input.deliverables_subdir,
                        workspace_name=input.workspace_name,
                    )
                )
                return result_dict
    finally:
        await heartbeat.__aexit__(None, None, None)
        ctrl.uninstall()


def main():
    import sys
    asyncio.run(run_scan(PipelineInput(repo_path=sys.argv[1] if len(sys.argv) > 1 else ".")))
