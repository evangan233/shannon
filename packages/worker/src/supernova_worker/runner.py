"""常驻 worker 容器入口：连接 temporal，起三个 Worker 消费 WEB 固定 task queue。

与 CLI 的 self-contained run_scan 不同——这里 worker 只消费、不提交：
- 白盒 Worker 消费 supernova-wb-web（web scan_manager 提交，Plan 2 接入）
- 黑盒 Worker 消费 supernova-bb-web
- 跨仓关联 Worker 消费 supernova-corr-web（B2：依赖 supernova-multi pipeline）

CLI 路径（supernova-whitebox/-blackbox start）零改动，仍用 generate_task_queue
唯一随机 queue 自己提交自己消费，与本 worker 容器互不干扰（queue 精确匹配）。
"""
import asyncio
import logging
import os
from datetime import timedelta

from temporalio.client import Client
from temporalio.worker import Worker

from supernova_core.config.env_loader import load_env
from supernova_core.services.temporal_infra import (
    WEB_TASK_QUEUE_WHITEBOX,
    WEB_TASK_QUEUE_BLACKBOX,
    WEB_TASK_QUEUE_CORRELATION,
)
from supernova_whitebox.pipeline.workflows import WhiteboxScanWorkflow, MrScanWorkflow
from supernova_whitebox.pipeline.activities import (
    render_findings, assemble_report, run_agent,
    run_recon_context_digest,
    run_authz_gitnexus_judge,
    run_code_index, run_credential_check, run_merge_dual_track_queues,
    run_adversarial_review,
    run_gn_finding_enrichment, run_endpoint_enrichment, run_report_polish,
    run_assemble_api_evidence,
    run_merge_sink_reports, run_entry_point_fusion, run_preflight, run_risk_scoring,
    run_save_adjudication, run_vuln_agent, run_attack_chain_llm_agent,
    run_attack_chain_assembly_v2, run_framework_analysis, run_frontend_mapping,
    run_gitnexus_chain_verdict, run_route_chain_building, inject_attack_chains,
    inject_gitnexus_track_status, write_agent_poc,
    run_assemble_dataflow_view,
    verify_report_vuln_blocks,
    export_report_markdown_files,
    write_track_status_activity,
    log_phase_start_activity, log_phase_complete_activity, log_info_activity,
    setup_display, finalize_summary, cleanup_auth_state_activity,
    persist_completed_agents,
)
# MR 增量扫描（spec 2026-09-03）：前置 activities 在独立模块 mr_activities
# （b40a1a5a 曾漏 import——activities 列表引用未导入名，run_worker() 调用即
# NameError，本 import 补齐并加注册冒烟测试锁定）。
from supernova_whitebox.pipeline.mr_activities import (
    run_mr_repo_prepare, run_git_diff,
    run_protection_removal_analysis, run_incremental_scope,
    run_mr_empty_diff_finalize,
)
from supernova_blackbox.pipeline.workflows import BlackboxScanWorkflow, AuthValidationWorkflow, BatchAuthValidationWorkflow
from supernova_blackbox.pipeline.activities import (
    run_blackbox_preflight, run_blackbox_auth_validation,
    run_auth_validation_probe,
    run_exploit_agent, run_endpoint_verify, validate_exploitation_queue, assemble_report as bb_assemble_report,
    run_report_agent, finalize_report,
    log_phase_start_activity as bb_log_phase_start, log_phase_complete_activity as bb_log_phase_complete,
    log_info_activity as bb_log_info, load_correlation_context, resolve_blackbox_engine,
    detect_whitebox_results, write_engine_config_for_session, cleanup_engine_configs,
    verify_report_vuln_blocks as bb_verify_report_vuln_blocks,
    setup_display as bb_setup_display, finalize_summary as bb_finalize_summary,
    run_host_proxy_setup as bb_run_host_proxy_setup, stop_host_proxy as bb_stop_host_proxy,
    cleanup_auth_state_activity as bb_cleanup_auth_state_activity,
    persist_completed_agents as bb_persist_completed_agents,
)
from supernova_multi.pipeline.workflows import (
    CorrelationScanWorkflow,
    TopologyAnalysisWorkflow,
    run_correlation_activity,
    run_topology_analysis_activity,
)
from supernova_core.runtime.heartbeat import snapshot_heartbeat_workflows
from supernova_core.services.scan_gate import (
    scan_gate_try_acquire, scan_gate_release,
    preload_gate, reap_ids, gate_candidate_ids, restore_gate_held_from_file,
)

_GRACEFUL_SHUTDOWN = timedelta(seconds=10)
# 心跳节流收紧（spec 2026-08-28-temporal-native-cancel-design 修 F）：temporalio 默认
# default_heartbeat_throttle_interval=30s——activity 不设 heartbeat_timeout 时每 30s 才真发
# 一次心跳 RPC，取消传播上限被拖到 30s+。收紧到 10s → web Cancel 后 ~10s 级送达 activity。
_HEARTBEAT_THROTTLE = timedelta(seconds=10)

# 协作取消桥轮询周期（2026-08-28 取消失效治本方案 B）。exists() 检查极廉，
# 取短周期换「点取消 → worker 真停」的低延迟。
_CANCEL_BRIDGE_INTERVAL_SECONDS = 5.0

# 闸门 janitor 轮询周期（spec 2026-09-08-worker-scan-gate §6）：槽泄漏兜底，
# 最坏多占一个周期。
_GATE_JANITOR_INTERVAL_SECONDS = 10.0
# bootstrap 预占重试间隔（2026-09-16 复盘）：visibility 查询失败期间不消费，
# 对齐 janitor 周期——恢复后一个周期内补上预占并放行。
_GATE_BOOTSTRAP_RETRY_SECONDS = 10.0
# bootstrap 预占的扫描类 workflow 类型（退化查询用；TaskQueue 查询优先）
_SCAN_WORKFLOW_TYPES = (
    "BlackboxScanWorkflow", "CorrelationScanWorkflow",
    "MrScanWorkflow", "WhiteboxScanWorkflow",
)


async def _process_cancel_signals(client: Client) -> None:
    """单轮协作取消桥：扫活跃 heartbeat 注册表各 ws_dir 的 cancel.requested。

    web cancel ② 轨写 cancel.requested，但 worker 容器路径的 activity
    start_heartbeat(on_cancel=None) 不消费协作信号（只有 CLI 路径 HeartbeatManager
    挂 ctrl._trigger_graceful）——owner=web 扫描的协作通道整个不存在（死信）。
    本桥把文件信号转回 temporal cancel，复用 temporalio 对 async activity 的
    task.cancel 传导（_activity.py:762-764，无需 heartbeat）。

    信号文件先删再 cancel（防下一轮对已终态 workflow 重复触发）；cancel 抛错
    （workflow 不存在/已终态/temporal 抖动）best-effort 吞掉。CLI 路径不受影响
    （随机 task queue 隔离，其 HeartbeatManager 自消费信号）。
    """
    for wf_id, ws_dir in snapshot_heartbeat_workflows().items():
        sig = ws_dir / "cancel.requested"
        if not sig.exists():
            continue
        try:
            sig.unlink()
        except OSError:
            continue  # 删失败（权限/竞态）跳过本轮，下轮重试
        try:
            await client.get_workflow_handle(wf_id).cancel()
        except Exception:  # noqa: BLE001 - best-effort；信号已删，不重复触发
            pass


async def _cancel_signal_bridge(client: Client) -> None:
    """协作取消桥主循环（worker 容器常驻后台 task，进程退出即止）。"""
    while True:
        await asyncio.sleep(_CANCEL_BRIDGE_INTERVAL_SECONDS)
        try:
            await _process_cancel_signals(client)
        except Exception:  # noqa: BLE001 - 桥绝不因单轮异常退出
            pass


async def _gate_bootstrap(client: Client) -> bool:
    """worker 启动闸门恢复 + 预占：spec §6 防重启超卖；2026-09-16 事故修复。

    第一步 restore：从 gate_state.json 恢复 held 的**真实 descriptor（带 ws）**
    ——ws cap 的归属计数靠它；只靠 visibility 预占（ws="")会让重启窗口 ws cap
    彻底失效，且预占集含闸门排队者（排队 workflow 也是 RUNNING），旧实现
    try_acquire 幂等分支会把他们无条件放行（现场：ws cap 3 下排队 2 个突然
    自动开跑）。waiting 不恢复：排队者 5s 轮询自愈重新入列。

    第二步 visibility 兜底预占：RUNNING 扫描类 workflow 一律计槽（快照丢失/
    未落盘的过闸者）。已过闸的 workflow 重放不会重新 acquire（event-sourced
    history 恢复 granted 结果直接跳过闸门段）——不预占则新排队者立即拿空闸门
    超卖。主查询 TaskQueue+WorkflowType 双过滤（排除 CLI 随机 queue 的同类型
    workflow、也排除 bb 队列上 AuthValidation/Topology 等非闸门 workflow——
    预占它们会白白吃闸门容量且永不 release）；不支持该 search attribute 时
    退化为 WorkflowType 过滤（接受 CLI 干扰：保守少槽，无害，spec §11）。

    返回两级 visibility 预占是否成功。**两级都失败返回 False 而非 fail-open**
    （2026-09-16 复盘：预占不全还启动消费 = 排队者放行窗口，闸门硬保证优先
    于可用性；调用方 _gate_bootstrap_until_ready 重试等待，恢复前不消费）。
    temporal 整体不可用时 Client.connect 已 fail-fast，落到这里的失败只剩
    visibility 专属故障（如 ES 后端抖动）。
    """
    restore_gate_held_from_file()
    queues = "','".join(
        (WEB_TASK_QUEUE_WHITEBOX, WEB_TASK_QUEUE_BLACKBOX, WEB_TASK_QUEUE_CORRELATION))
    types = "','".join(_SCAN_WORKFLOW_TYPES)
    ids: list[str] = []
    try:
        ids = [w.id async for w in client.list_workflows(
            query=f"TaskQueue IN ('{queues}') AND WorkflowType IN ('{types}')")]
    except Exception:
        try:
            ids = [w.id async for w in client.list_workflows(
                query=f"WorkflowType IN ('{types}')")]
        except Exception:  # noqa: BLE001 - 预占失败（调用方重试），见 docstring
            logging.getLogger(__name__).warning(
                "gate bootstrap 两级 visibility 查询均失败，预占不完整——"
                "暂缓启动 worker 消费直到恢复")
            return False
    preload_gate(ids)
    return True


async def _gate_bootstrap_until_ready(
        client: Client, *, interval: float = _GATE_BOOTSTRAP_RETRY_SECONDS) -> None:
    """bootstrap 重试循环：visibility 查询成功前不返回（= 不启动 worker 消费，
    扫描天然暂停——没有 consumer，排队 workflow 的 activity 在 task queue 排队，
    恢复后立即处理）。「任务没被确认结束前不能释放名额，名额没确认前不补位」
    的启动侧：确认不了谁占着槽，就不放新任务进来。"""
    attempt = 0
    while not await _gate_bootstrap(client):
        attempt += 1
        logging.getLogger(__name__).warning(
            "gate bootstrap 未就绪（第 %d 次重试），暂停 worker 消费 %gs",
            attempt, interval)
        await asyncio.sleep(interval)


async def _gate_janitor_once(client: Client) -> None:
    """单轮闸门回收：校验持有/等待者存活性，死 key 摘除（spec §6）。

    覆盖一切异常释放路径：cancel 保险丝 terminate（不给清理机会）、cancel 时
    cleanup 没跑成、workflow 崩溃。waiting 死 key 同摘——幽灵排队者会挡 FIFO。

    2026-09-16 收紧「查询失败 ≠ 死亡」：旧逻辑 describe 抛任何异常都判死回收，
    temporal 抖动一轮就把全部 held/waiting 误摘（槽放空 → 排队者超卖获槽，
    与 bootstrap 抢跑事故同后果的第二口子）。现仅 RPC NOT_FOUND（workflow 已
    终结被回收，确凿死亡）摘除；其余异常跳过本轮下轮再校验。describe 返回
    非 RUNNING（终态可见）照旧摘。
    """
    from temporalio.client import WorkflowExecutionStatus
    from temporalio.service import RPCError, RPCStatusCode
    for wf_id in gate_candidate_ids():
        try:
            desc = await client.get_workflow_handle(wf_id).describe()
        except RPCError as err:
            if err.status is not RPCStatusCode.NOT_FOUND:
                continue  # 网络抖动/服务端错误 ≠ 死亡，本轮跳过
            reap_ids([wf_id])  # workflow 不存在 = 确凿死 key
            continue
        except Exception:  # noqa: BLE001 - 查询失败本轮跳过（下轮再校验）
            continue
        if desc.status != WorkflowExecutionStatus.RUNNING:
            reap_ids([wf_id])


async def _gate_janitor(client: Client) -> None:
    """闸门 janitor 主循环（worker 常驻后台 task，进程退出即止；对齐取消桥模式）。"""
    while True:
        await asyncio.sleep(_GATE_JANITOR_INTERVAL_SECONDS)
        try:
            await _gate_janitor_once(client)
        except Exception:  # noqa: BLE001 - janitor 绝不因单轮异常退出
            pass


async def run_worker(temporal_address: str = "localhost:7233") -> None:
    """连接 temporal，起白盒+黑盒+跨仓关联三个常驻 Worker 并行消费 WEB 固定 queue。

    永不主动返回（常驻）；temporal 连接失败 fail-fast 抛错。
    """
    client = await Client.connect(temporal_address)

    wb_worker = Worker(
        client=client,
        task_queue=WEB_TASK_QUEUE_WHITEBOX,
        workflows=[WhiteboxScanWorkflow, MrScanWorkflow],
        activities=[
            render_findings, assemble_report, run_agent,
            run_recon_context_digest,
            run_authz_gitnexus_judge,
            run_code_index, run_credential_check, run_merge_dual_track_queues,
            run_adversarial_review,
            run_gn_finding_enrichment, run_endpoint_enrichment, run_report_polish,
            run_assemble_api_evidence,
            run_merge_sink_reports, run_entry_point_fusion, run_preflight, run_risk_scoring,
            run_save_adjudication, run_vuln_agent, run_attack_chain_llm_agent,
            run_attack_chain_assembly_v2, run_framework_analysis, run_frontend_mapping,
            run_gitnexus_chain_verdict, run_route_chain_building, inject_attack_chains,
            inject_gitnexus_track_status, write_agent_poc,
            run_assemble_dataflow_view,
            verify_report_vuln_blocks,
            export_report_markdown_files,
            write_track_status_activity,
            log_phase_start_activity, log_phase_complete_activity, log_info_activity,
            setup_display, finalize_summary, cleanup_auth_state_activity,
            persist_completed_agents,
            # MR 增量扫描（spec 2026-09-03）：前置 activities + 空 diff 快速终态
            run_mr_repo_prepare, run_git_diff,
            run_protection_removal_analysis, run_incremental_scope,
            run_mr_empty_diff_finalize,
            # 全局扫描闸门（spec 2026-09-08-worker-scan-gate §4.1）：三 queue 都要注册
            scan_gate_try_acquire, scan_gate_release,
        ],
        # P3c 阶段 3：AuditSession/LogBus/heartbeat 已 contextvar 化（按 workflow_id 隔离），
        # 多 scan 并发不再串台 → max_concurrent 放开（默认 4，env 可配）。
        max_concurrent_workflow_tasks=int(
            os.environ.get("SUPERNOVA_WORKER_MAX_CONCURRENT_WF", "4")
        ),
        graceful_shutdown_timeout=_GRACEFUL_SHUTDOWN,
        default_heartbeat_throttle_interval=_HEARTBEAT_THROTTLE,
    )
    bb_worker = Worker(
        client=client,
        task_queue=WEB_TASK_QUEUE_BLACKBOX,
        workflows=[BlackboxScanWorkflow, AuthValidationWorkflow, BatchAuthValidationWorkflow,
                   TopologyAnalysisWorkflow],
        activities=[
            run_topology_analysis_activity,
            run_blackbox_preflight, run_blackbox_auth_validation,
            run_auth_validation_probe,
            run_exploit_agent, run_endpoint_verify, validate_exploitation_queue, bb_assemble_report,
            run_report_agent, finalize_report,
            bb_log_phase_start, bb_log_phase_complete, bb_log_info,
            load_correlation_context, resolve_blackbox_engine, detect_whitebox_results,
            write_engine_config_for_session, cleanup_engine_configs,
            bb_setup_display, bb_finalize_summary,
            bb_run_host_proxy_setup, bb_stop_host_proxy,
            bb_cleanup_auth_state_activity,
            bb_persist_completed_agents,
            bb_verify_report_vuln_blocks,
            scan_gate_try_acquire, scan_gate_release,
        ],
        # P3c 阶段 3：对齐 wb_worker，contextvar 化后并发放开（默认 4，env 可配）。
        max_concurrent_workflow_tasks=int(
            os.environ.get("SUPERNOVA_WORKER_MAX_CONCURRENT_WF", "4")
        ),
        graceful_shutdown_timeout=_GRACEFUL_SHUTDOWN,
        default_heartbeat_throttle_interval=_HEARTBEAT_THROTTLE,
    )
    corr_worker = Worker(
        client=client,
        task_queue=WEB_TASK_QUEUE_CORRELATION,
        workflows=[CorrelationScanWorkflow],
        activities=[run_correlation_activity,
                    scan_gate_try_acquire, scan_gate_release],
        # 对齐 wb/bb worker，contextvar 化后并发放开（默认 4，env 可配）。
        max_concurrent_workflow_tasks=int(
            os.environ.get("SUPERNOVA_WORKER_MAX_CONCURRENT_WF", "4")
        ),
        graceful_shutdown_timeout=_GRACEFUL_SHUTDOWN,
        default_heartbeat_throttle_interval=_HEARTBEAT_THROTTLE,
    )

    # 闸门 bootstrap 预占必须在 worker 消费前（spec §6：防重启超卖）；
    # visibility 查询失败 → 重试等待（暂停消费），预占不全不放新任务进来
    # （2026-09-16 复盘：fail-open 的放行窗口 = 抢跑事故第三口子）。
    await _gate_bootstrap_until_ready(client)

    # 协作取消桥（方案 B）：把 web cancel ② 轨的 cancel.requested 文件信号转发为
    # temporal cancel（worker 容器路径协作通道的唯一消费者）。worker 全退时一并取消。
    bridge = asyncio.create_task(_cancel_signal_bridge(client))
    gate_janitor_task = asyncio.create_task(_gate_janitor(client))
    try:
        await asyncio.gather(wb_worker.run(), bb_worker.run(), corr_worker.run())
    finally:
        bridge.cancel()
        gate_janitor_task.cancel()


def main() -> None:
    # 加载共享 .env + 当前 profile 凭证(SUPERNOVA_AI_PROVIDER / SUPERNOVA_OPENAI_* 等)。
    # worker 容器化时漏了这一步:不调 load_env,profile 凭证不进进程环境 → 引擎回落
    # 默认 anthropic_api(claude CLI)→ deepseek-openai 等 openai profile 无 ANTHROPIC
    # 凭证 → claude CLI 子进程 "Not logged in · Please run /login" → pre-recon 失败、
    # 扫描卡死、WEB 各页全空(真机 trip_1784107863)。对齐 CLI 入口(whitebox/
    # blackbox/combined main.py 均首行 load_env)。
    load_env()
    import os
    host = os.environ.get("SUPERNOVA_TEMPORAL_HOST", "localhost")
    port = os.environ.get("SUPERNOVA_TEMPORAL_PORT", "7233")
    asyncio.run(run_worker(f"{host}:{port}"))
