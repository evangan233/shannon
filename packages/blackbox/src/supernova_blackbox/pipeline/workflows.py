import asyncio
import logging
from datetime import timedelta
from pathlib import Path

from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ApplicationError, CancelledError

from supernova_core.models.agents import AgentName, ALL_VULN_CLASSES
from supernova_core.runtime.temporal_heartbeat import is_cancellation
from supernova_core.agents.progress_tool import AUTH_VALIDATION_PROGRESS
from supernova_core.utils.paths import (
    resolve_deliverables_path,
    has_valid_whitebox_results,
    resolve_track_deliverable,
    WHITEBOX_SUBDIR,
)

from .shared import BlackboxActivityInput, BlackboxAuthValidationBatchInput, BlackboxAuthValidationInput, BlackboxPipelineInput, BlackboxPipelineState, PipelineProgress, is_engine_failure

logger = logging.getLogger(__name__)


def has_correlation_results(corr_ws_deliverables: Path, vuln_classes: list[str]) -> bool:
    """§6.2 闭环检测端:关联 workspace 的 merged queue 是否构成黑盒 recon-skip 复用源。

    纯函数(不依赖 Temporal,可单测)。当 `--correlated-workspace` 指定的关联
    workspace deliverables 里存在 `vuln_classes` 中至少一个漏洞类的有效
    `{vt}_exploitation_queue.json` 时返回 True。有效性复用
    `has_valid_whitebox_results`(每条 entry 必须含 title/description/severity/location
    四字段,spec §7 B1 硬约束;跨服务额外字段如 service/cross_service_source 因 subset
    检查不破坏判定)。

    与单仓 deliverables 检查的关系:ADD 源(任一有效即 skip recon),非 replace。
    调用方(workflow `run`)仅在 `input.correlated_workspace` 设置时调用本函数——
    `correlated_workspace` 为 None(所有单仓 / 现有 `--repo`·`--latest` 调用)时
    根本不进入此路径,行为与改动前字节一致(单仓零回归)。
    """
    if not vuln_classes:
        return False
    for vt in vuln_classes:
        queue_file = resolve_track_deliverable(
            corr_ws_deliverables, WHITEBOX_SUBDIR, f"{vt}_exploitation_queue.json")
        if has_valid_whitebox_results(queue_file):
            return True
    return False


with workflow.unsafe.imports_passed_through():
    from . import activities
    from supernova_core.services.scan_gate import (
        acquire_gate_slot, release_gate_slot,
        gate_scan_id_from_event_file, gate_ws_for_descriptor,
        gate_ws_cap_from_overrides)
    from supernova_core.utils.progress import (
        AgentOutcome,
        exploit_result_to_outcome,
        format_exploit_summary,
    )
    from supernova_core.services.settings_writer import cleanup_settings
    from supernova_core.services.playwright_config_writer import (
        get_session_id,
    )
    from supernova_core.services.validate_authentication import AuthValidationResult
    from supernova_core.models.retry import retry_for
    from supernova_core.models.errors import PentestError, ErrorCode, classify_error_for_temporal


@workflow.defn
class BlackboxScanWorkflow:
    def __init__(self):
        self._state = BlackboxPipelineState()

    @workflow.run
    async def run(self, input: BlackboxPipelineInput) -> BlackboxPipelineState:
        # 全局扫描闸门（spec 2026-09-08-worker-scan-gate §5）：排队轮询直到获得全局槽。
        # 放最前：排队期间不推进任何 pipeline 逻辑，start_time 在放行后才记（duration 不含排队）。
        await acquire_gate_slot({
            "kind": "blackbox",
            "ws": gate_ws_for_descriptor(input.workspace_name, input.event_file),
            "scan_id": gate_scan_id_from_event_file(input.event_file),
            "label": input.web_url,
            # ws 并发上限（2026-09-15）：闸门段先于 setup_display（set_scan_env 注入
            # 点），从 input.env_overrides 提交时快照解析携带；未配置不带键。
            # add-run / rerun 走同 workflow，同吃本 ws 的 cap。
            **({} if (ws_cap := gate_ws_cap_from_overrides(input.env_overrides))
               is None else {"ws_cap": ws_cap}),
        }, input)
        try:
            self._state.start_time = workflow.time_ns() / 1e9

            # workspaces 根由 sandbox 外（CLI/worker）解析后经 input 传入；sandbox 内禁
            # os.getenv/Path.cwd（否则 RestrictedWorkflowAccessError）。run 体内只用此值，零 I/O。
            if not input.workspaces_root:
                raise ValueError(
                    "BlackboxPipelineInput.workspaces_root must be set before starting the "
                    "workflow (sandbox cannot resolve it)."
                )
            ws_root = Path(input.workspaces_root)

            selected_classes: list[str] = input.vuln_classes or list(ALL_VULN_CLASSES)

            # C1 Phase B（黑盒 web 化）：event_file 非 None = web 提交（worker 路径），调迁移
            # activity（setup_display/finalize_summary）；None = CLI 路径，run_scan 外层已
            # set_audit_session/heartbeat/log_workflow_complete，workflow 内不重复（守 CLI 零改动）。
            # 对齐 whitebox workflows.py:97-101 is_worker_path 门控。
            is_worker_path = input.event_file is not None

            # Compute workspace_path so activities know where to write 产物（heartbeat/deliverables/
            # workflow.log/session）。WEB 路径（event_file 非 None）：用 event_file 同目录（= scan_dir，
            # web scan_manager 创建的 workspaces/<ws>/scans/<scan_id>/），与 web 判活（heartbeat）/
            # DeliverablesReader 读取对齐——修历史分裂（产物原落 ws_root/workspace_name 平铺，web 读不到）。
            # CLI 路径（无 event_file）：走 ws_root/workspace_name（与旧 resolve_deliverables_path 同路径）。
            if input.event_file:
                workspace_path = str(Path(input.event_file).parent)
            elif input.workspace_name:
                workspace_path = str(ws_root / input.workspace_name)
            else:
                workspace_path = input.repo_path

            act_input = BlackboxActivityInput(
                web_url=input.web_url,
                repo_path=input.repo_path,
                config_path=input.config_path,
                workspace_name=input.workspace_name,
                deliverables_subdir=input.deliverables_subdir,
                pipeline_testing_mode=input.pipeline_testing_mode,
                api_key=input.api_key,
                workspace_path=workspace_path,
                correlated_workspace=input.correlated_workspace,
                event_file=input.event_file,
                host_mappings=input.host_mappings or {},
                env_overrides=input.env_overrides,
                provider_config=input.provider_config,   # P3c 阶段 1 补齐：此前字段已定义但未灌入，全链 **act_input.__dict__ 继承
            )

            retry_policy = retry_for(
                "standard",
                "testing" if input.pipeline_testing_mode else (input.retry_profile or "production"),
            )

            # C1 Phase B：worker 路径前导 setup_display（注入 AuditSession + event_file + heartbeat），
            # 必须在首个 activity 前挂 StructuredEventRenderer，否则 preflight/auth 阶段事件不落盘。
            # CLI 路径跳过（外层 run_scan 已 set_audit_session/heartbeat）。对齐 whitebox:144-149。
            if is_worker_path:
                await workflow.execute_activity(
                    activities.setup_display, act_input,
                    start_to_close_timeout=timedelta(seconds=30),
                    retry_policy=retry_for("standard"),
                )

            await workflow.execute_activity(
                activities.log_phase_start_activity,
                args=[
                    BlackboxActivityInput(**{**act_input.__dict__, "phase": "preflight"}),
                    [],
                    [],
                ],
                start_to_close_timeout=timedelta(seconds=10),
                retry_policy=retry_for("log"),
            )
            # per-scan host proxy（preflight 前起；空 host_mappings 返 "" 不影响现状）。
            # proxy_url 注入 act_input，后续所有派生子 input 经 **act_input.__dict__ 继承，
            # 供 exploit / endpoint_verify / report activity 的浏览器出口走 per-scan 代理。
            proxy_url = await workflow.execute_activity(
                activities.run_host_proxy_setup,
                args=[act_input],
                start_to_close_timeout=timedelta(seconds=60),
                retry_policy=RetryPolicy(maximum_attempts=1),
            )
            if proxy_url:
                act_input.proxy_url = proxy_url
            await workflow.execute_activity(
                activities.run_blackbox_preflight, act_input,
                start_to_close_timeout=timedelta(minutes=2),
                retry_policy=retry_for("preflight"),
            )

            # Resolve config and browser engine — 文件 I/O 与副作用(parse_config 读 yaml /
            # check_available 走 shutil.which / sync_code_path_deny_rules 写 settings.json /
            # write_config 写 stealth config)经 resolve_blackbox_engine activity 完成,
            # sandbox 禁这些操作。返回 engine_name 供 exploit 循环复用。
            engine_name = await workflow.execute_activity(
                activities.resolve_blackbox_engine, act_input,
                start_to_close_timeout=timedelta(seconds=30),
                retry_policy=retry_for("log"),
            )

            # Auth validation when config is present
            if input.config_path:
                # 步骤条声明(2026-08-21):与独立 AuthValidationWorkflow 同源(SSOT)——
                # log_milestone 工具发的 StepEvent(navigate/…/verify_session × 每凭据)与
                # validate-authentication 的 AgentEvent 都在发,声明即推进,零新增发射器。
                await workflow.execute_activity(
                    activities.log_phase_start_activity,
                    args=[
                        BlackboxActivityInput(**{**act_input.__dict__,
                                                 "phase": AUTH_VALIDATION_PROGRESS.phase}),
                        list(AUTH_VALIDATION_PROGRESS.step_keys),
                        [s.intent for s in AUTH_VALIDATION_PROGRESS.steps],
                    ],
                    start_to_close_timeout=timedelta(seconds=10),
                    retry_policy=retry_for("log"),
                )
                await workflow.execute_activity(
                    activities.run_blackbox_auth_validation,
                    # B 层（2026-09-03 xss 40min 事故）：透传 engine_name，activity 结束
                    # 即回收 validate-auth 的浏览器 session（agent1），不等扫描级 finally。
                    BlackboxActivityInput(**{**act_input.__dict__, "engine_name": engine_name}),
                    start_to_close_timeout=timedelta(minutes=10),
                    heartbeat_timeout=timedelta(minutes=2),
                    retry_policy=retry_for("auth-validation"),
                )

            try:
                # C1 Phase B：deliverables 落点优先 workspace_path（web=scan_dir/deliverables_subdir），
                # 与 _get_deliverables_path（activities.py）+ web DeliverablesReader 读取口径对齐。
                # CLI 路径 workspace_path 上方已算（ws_root/workspace_name，与旧 resolve_deliverables_path
                # 同路径，零回归）；兜底分支防 standalone（无 repo 无 ws）workspace_path 为空。
                if workspace_path:
                    deliverables = Path(workspace_path) / input.deliverables_subdir
                else:
                    deliverables = resolve_deliverables_path(
                        repo_path=input.repo_path,
                        deliverables_subdir=input.deliverables_subdir,
                        workspace_name=input.workspace_name,
                        workspaces_root=ws_root,
                    )

                # B2: 当指定关联 workspace 时，加载其 topology/boundaries 作为 exploitation 上下文。
                # ws_root 由 sandbox 外（CLI/worker）解析后经 input 传入（honors SUPERNOVA_WORKER_ROOT +
                # find_project_root() 口径）；文件读取经 activity 完成（sandbox 禁 Path.exists/read_text）。
                corr_ctx = None
                corr_ws_path = None
                if input.correlated_workspace:
                    corr_ws_path = ws_root / input.correlated_workspace
                    corr_ctx = await workflow.execute_activity(
                        activities.load_correlation_context,
                        str(corr_ws_path),
                        start_to_close_timeout=timedelta(seconds=30),
                        retry_policy=retry_for("log"),
                    )
                self._state.correlation_context = corr_ctx  # 供 exploitation 读取（B3）

                # 白盒结果检测（单仓 + §6.2 关联 workspace ADD 源）——文件 I/O（读 queue）经
                # detect_whitebox_results activity 完成（sandbox 禁 has_valid_whitebox_results/
                # has_correlation_results）。corr 路径由 sandbox 外拼好以 str 传入；ADD 语义
                # （单仓无结果才查关联）在 activity 内。state 更新与 log 留 workflow（用返回值驱动）。
                corr_dlv_path = (
                    str(corr_ws_path / "deliverables")
                    if (input.correlated_workspace and corr_ws_path is not None)
                    else None
                )
                # 根因 1 修复：读白盒 queue 的根 = repo_path/deliverables_subdir（白盒 scan_dir/
                # deliverables，白盒产物所在），而非黑盒自己 deliverables（workspace_path/
                # deliverables_subdir，空）——否则 exploitation 5 类全 queue_file_not_found skip。
                # standalone（无 repo_path）回落黑盒自己 deliverables（detect 必返 False → 1.2 fail-fast）。
                wb_queue_root = (
                    str(Path(input.repo_path) / input.deliverables_subdir)
                    if input.repo_path else str(deliverables)
                )
                wb = await workflow.execute_activity(
                    activities.detect_whitebox_results,
                    args=[wb_queue_root, selected_classes, corr_dlv_path],
                    start_to_close_timeout=timedelta(seconds=30),
                    retry_policy=retry_for("log"),
                )
                has_whitebox_results: bool = wb["has_whitebox_results"]
                found_classes: list[str] = wb["found_classes"]
                # 对齐 TS validateDeliverablesExist：recon_deliverable.md 存在性（攻击面情报完整性）。
                # .get(..., True) 向后兼容旧 activity（不返回此字段时不阻塞）。
                has_recon_deliverable: bool = wb.get("has_recon_deliverable", True)
                self._state.has_whitebox_results = has_whitebox_results
                self._state.found_whitebox_classes = found_classes

                # §6.2 闭环：关联 workspace 贡献了结果时（单仓无结果、关联命中），合并 found_classes
                # 并记录日志（ADD 源可观测性）。corr_classes 非空 ⟺ activity 内单仓无结果且关联命中。
                corr_classes: list[str] = wb["corr_classes"]
                if corr_classes:
                    found_classes = found_classes + [
                        vt for vt in corr_classes if vt not in found_classes
                    ]
                    self._state.has_whitebox_results = True
                    self._state.found_whitebox_classes = found_classes
                    await workflow.execute_activity(
                        activities.log_info_activity,
                        BlackboxActivityInput(**{**act_input.__dict__,
                           "info_message": f"Correlation workspace results detected at {corr_ws_path}/deliverables for classes: {corr_classes} — skipping RECON_BLACKBOX (§6.2 closed loop)",
                           "info_level": "info"}),
                        start_to_close_timeout=timedelta(seconds=10),
                        retry_policy=retry_for("log"),
                    )

                # 对齐 TS validateDeliverablesExist（activities.ts:1330）：recon_deliverable.md 缺失即
                # nonRetryable fail（即使 queue 非空）。recon 是全局攻击面情报（API inventory / input
                # vectors / 技术栈），缺失则 exploit agent 失明。此前错误消息写了 recon 但未真校验。
                if not has_recon_deliverable:
                    raise PentestError(
                        "Blackbox scan requires whitebox recon_deliverable.md (attack-surface "
                        f"intelligence) under {wb_queue_root}/{WHITEBOX_SUBDIR}/. It is missing — "
                        "exploit agents would run blind without API inventory / input vectors. "
                        "Re-run the whitebox scan (its recon phase produces recon_deliverable.md) "
                        "before reusing its results.",
                        "whitebox",
                        error_code=ErrorCode.DELIVERABLE_NOT_FOUND,
                    )

                if has_whitebox_results:
                    await workflow.execute_activity(
                        activities.log_info_activity,
                        BlackboxActivityInput(**{**act_input.__dict__,
                           "info_message": f"Whitebox results detected at {wb_queue_root} for classes: {found_classes} — skipping RECON_BLACKBOX",
                           "info_level": "info"}),
                        start_to_close_timeout=timedelta(seconds=10),
                        retry_policy=retry_for("log"),
                    )
                else:
                    # 对齐 TS validateDeliverablesExist：黑盒 = 白盒下游 exploitation-only，不独立发现漏洞
                    # （TS 黑盒本身无 recon/analysis 阶段，强制要求白盒产物，standalone hard fail）。
                    # 无白盒产物 → fail-fast（recon 阶段已于阶段 2 删除，黑盒恒复用白盒）。PentestError
                    # 被 workflow except 捕获 → state.status=failed + return；is_worker_path 时 _finalize_web 写 scan_end + failed。
                    raise PentestError(
                        "Blackbox scan requires existing whitebox scan deliverables "
                        f"(recon_deliverable.md + non-empty *_exploitation_queue.json) under "
                        f"{wb_queue_root}/{WHITEBOX_SUBDIR}/. Run a whitebox scan first or reuse its "
                        "results. Blackbox is exploitation-only and does not run recon.",
                        "whitebox",
                        error_code=ErrorCode.DELIVERABLE_NOT_FOUND,
                    )

                if input.exploit:
                    # 步骤条声明(2026-08-21,白盒 vulnerability-analysis 的 vuln_phase_steps
                    # 同模式):endpoint-verify 仅 web_url 有值时才调度(下方 if input.web_url),
                    # {vt}-exploit 与实际调度的 exploit agent(AgentName(f"{vt}-exploit"))同名
                    # → 既有 AgentEvent(start/end) 自动推进,零新增事件发射。队列验证跳过的类
                    # 无 agent 事件 → 运行中灰显,终态由 scan_end(completed) 收敛标绿(reducer 既有)。
                    exploit_steps = (
                        (["endpoint-verify"] if input.web_url else [])
                        + [f"{vt}-exploit" for vt in selected_classes]
                    )
                    exploit_intents = (
                        (["端点 live 验证与路由前缀探测"] if input.web_url else [])
                        + [f"利用 {vt} 漏洞" for vt in selected_classes]
                    )
                    await workflow.execute_activity(
                        activities.log_phase_start_activity,
                        args=[
                            BlackboxActivityInput(**{**act_input.__dict__, "phase": "exploitation"}),
                            exploit_steps,
                            exploit_intents,
                        ],
                        start_to_close_timeout=timedelta(seconds=10),
                        retry_policy=retry_for("log"),
                    )
                    self._state.current_phase = "exploitation"
                    self._state.current_agent = "pipelines"
                    # spec 2026-08-03: 端点 live 验证(exploitation 前)。读白盒端点 + auth-state,
                    # 验证 live + 路由转发前缀探测,产 blackbox/endpoint_verify.json。功能性失败 →
                    # 降级(activity 内部吞异常返 endpoint_verify=None,不 raise),exploit 全打(零回归)。
                    # 无 web_url(黑盒无 live target)→ 跳过(exploit 照打)。maximum_attempts=1:增强
                    # 功能不重试(失败=现状)。exploit 衔接(读 endpoint_verify.json)见 ExploitExecutor。
                    if input.web_url:
                        await workflow.execute_activity(
                            activities.run_endpoint_verify,
                            # B 层（2026-09-03 xss 40min 事故）：透传 engine_name，activity
                            # 结束即回收 endpoint-verify 的浏览器 session（default）。
                            BlackboxActivityInput(**{**act_input.__dict__,
                                                     "engine_name": engine_name}),
                            start_to_close_timeout=timedelta(minutes=15),
                            heartbeat_timeout=timedelta(minutes=2),
                            retry_policy=RetryPolicy(maximum_attempts=1),
                        )
                    # Queue gating: validate queue files before scheduling exploit agents
                    validation_results = []
                    exploit_tasks = []
                    for vt in selected_classes:
                        exploit_check_input = BlackboxActivityInput(
                            **{**act_input.__dict__, "vuln_type": vt}
                        )
                        validation = await workflow.execute_activity(
                            activities.validate_exploitation_queue,
                            exploit_check_input,
                            start_to_close_timeout=timedelta(seconds=30),
                            retry_policy=retry_for("log"),
                        )
                        validation_results.append((vt, validation))
                        if not validation.valid:
                            if validation.is_expected:
                                logger.debug(
                                    "Skipping exploit for %s (expected): %s",
                                    vt, validation.message,
                                )
                            else:
                                await workflow.execute_activity(
                                    activities.log_info_activity,
                                    BlackboxActivityInput(**{**act_input.__dict__,
                                       "info_message": f"Skipping exploit for {vt} (anomalous): {validation.message} | queue_path={validation.context.get('queue_path', 'N/A')}",
                                       "info_level": "warning"}),
                                    start_to_close_timeout=timedelta(seconds=10),
                                    retry_policy=retry_for("log"),
                                )
                            continue
                        agent_name = AgentName(f"{vt}-exploit")
                        if agent_name.value not in self._state.completed_agents:
                            self._state.current_agent = agent_name.value
                            session_id = get_session_id(agent_name.value)
                            await workflow.execute_activity(
                                activities.write_engine_config_for_session,
                                args=[input.repo_path, session_id, engine_name, act_input.proxy_url],
                                start_to_close_timeout=timedelta(seconds=30),
                                retry_policy=retry_for("log"),
                            )
                            exploit_input = BlackboxActivityInput(
                                **{**act_input.__dict__,
                                   "agent_name": agent_name.value,
                                   "vuln_type": vt,
                                   "correlation_context": self._state.correlation_context,
                                   # B 层（2026-09-03 xss 40min 事故）：透传 engine_name，
                                   # exploit agent 结束即回收自己的浏览器 session——
                                   # 治死占（先结束 agent 的浏览器不再被独跑的 xss 白背）。
                                   "engine_name": engine_name}
                            )
                            exploit_tasks.append((vt, agent_name, workflow.execute_activity(
                                activities.run_exploit_agent, exploit_input,
                                start_to_close_timeout=timedelta(hours=2),
                                heartbeat_timeout=timedelta(minutes=2),
                                retry_policy=retry_policy,
                            )))

                    # Validation summary log
                    _VALIDATION_ICONS = {"valid": "✅", "expected": "⏭️", "anomalous": "⚠️"}
                    summary_lines = ["Validation summary:"]
                    for vt, v in validation_results:
                        if v.valid:
                            icon = _VALIDATION_ICONS["valid"]
                        elif v.is_expected:
                            icon = _VALIDATION_ICONS["expected"]
                        else:
                            icon = _VALIDATION_ICONS["anomalous"]
                        summary_lines.append(f"  {icon} {vt}: {v.message}")
                    await workflow.execute_activity(
                        activities.log_info_activity,
                        BlackboxActivityInput(**{**act_input.__dict__,
                           "info_message": "\n".join(summary_lines),
                           "info_level": "info"}),
                        start_to_close_timeout=timedelta(seconds=10),
                        retry_policy=retry_for("log"),
                    )

                    # Track scheduled vuln types for skipped outcomes
                    scheduled_vuln_types = {vt for vt, _, _ in exploit_tasks}

                    if exploit_tasks:
                        semaphore = asyncio.Semaphore(input.max_concurrent)

                        async def bounded_exploit(
                            coro, vt: str, agent_name: AgentName
                        ):
                            async with semaphore:
                                return await coro

                        results = await asyncio.gather(
                            *[bounded_exploit(task, vt, agent_name) for vt, agent_name, task in exploit_tasks],
                            return_exceptions=True,
                        )
                        # 取消放行（spec 2026-08-28-temporal-native-cancel-design 修 0）：
                        # return_exceptions=True 会把 activity 取消的 ActivityError 收进结果
                        # 列表——不放行则 workflow 继续跑 reporting（幽灵扫描机制，T1 探针钉死）。
                        for _r in results:
                            if isinstance(_r, BaseException) and is_cancellation(_r):
                                raise _r

                        # Build AgentOutcome list from results
                        outcomes: list[AgentOutcome] = []
                        for i, result in enumerate(results):
                            vt, agent_name, _ = exploit_tasks[i]
                            if isinstance(result, Exception):
                                self._state.errors.append(f"{agent_name.value}: {result}")
                                self._state.failed_agents.append(agent_name.value)
                                outcomes.append(AgentOutcome(
                                    agent_name=agent_name.value,
                                    vuln_type=vt,
                                    status="failed",
                                    error=str(result),
                                ))
                            else:
                                self._state.completed_agents.append(agent_name.value)
                                self._state.agent_metrics[agent_name.value] = result
                                await self._persist_progress(act_input)
                                outcomes.append(
                                    exploit_result_to_outcome(result, agent_name.value, vt)
                                )

                        # Add skipped outcomes for vuln types that were not scheduled
                        for vt, validation in validation_results:
                            if vt not in scheduled_vuln_types:
                                outcomes.append(AgentOutcome(
                                    agent_name=f"{vt}-exploit",
                                    vuln_type=vt,
                                    status="skipped",
                                ))

                        await workflow.execute_activity(
                            activities.log_info_activity,
                            BlackboxActivityInput(**{**act_input.__dict__,
                               "info_message": format_exploit_summary(outcomes),
                               "info_level": "info"}),
                            start_to_close_timeout=timedelta(seconds=10),
                            retry_policy=retry_for("log"),
                        )

                # 步骤条声明(2026-08-21):report 与 run_report_agent 的
                # AgentEvent(agent_name="report") 同名 → start/end 自动推进;resume 跳过
                # agent 时由 scan_end(completed) 收敛兜底。
                await workflow.execute_activity(
                    activities.log_phase_start_activity,
                    args=[
                        BlackboxActivityInput(**{**act_input.__dict__, "phase": "reporting"}),
                        ["report"],
                        ["撰写黑盒报告"],
                    ],
                    start_to_close_timeout=timedelta(seconds=10),
                    retry_policy=retry_for("log"),
                )
                self._state.current_phase = "reporting"
                self._state.current_agent = "assemble-report"
                await workflow.execute_activity(
                    activities.assemble_report, act_input,
                    start_to_close_timeout=timedelta(minutes=5),
                    retry_policy=retry_policy,
                )
                self._state.current_agent = None

                if AgentName.REPORT.value not in self._state.completed_agents:
                    self._state.current_agent = AgentName.REPORT.value
                    metrics = await workflow.execute_activity(
                        activities.run_report_agent, act_input,
                        start_to_close_timeout=timedelta(hours=1),
                        heartbeat_timeout=timedelta(minutes=2),
                        retry_policy=retry_policy,
                    )
                    self._state.completed_agents.append(AgentName.REPORT.value)
                    self._state.agent_metrics[AgentName.REPORT.value] = metrics
                    await self._persist_progress(act_input)
                    self._state.current_agent = None

                # 漏洞节覆盖校验+自愈（report-executive 之后）：agent 自写脚本压缩正文丢
                # ### ID 结构节会让报告页统计全 0（2026-08-19 回归，白盒侧爆发），节数不足
                # 则重建底稿版。无条件执行（resume 跳过 agent 时校验仍幂等有意义）。
                await workflow.execute_activity(
                    activities.verify_report_vuln_blocks, act_input,
                    start_to_close_timeout=timedelta(minutes=2),
                    retry_policy=retry_policy,
                )
                await workflow.execute_activity(
                    activities.finalize_report, act_input,
                    start_to_close_timeout=timedelta(minutes=5),
                    retry_policy=retry_policy,
                )

                # Set final status based on failure tracking
                if self._state.failed_agents:
                    self._state.status = "failed"
                    first_error_msg = self._state.errors[0].split(": ", 1)[-1] if self._state.errors else ""
                    error_type, _ = classify_error_for_temporal(Exception(first_error_msg))
                    self._state.error_code = error_type
                else:
                    self._state.status = "completed"
                self._state.current_phase = None
                if is_worker_path:
                    try:
                        await self._finalize_web(act_input)
                    except Exception:
                        # 根因 2 加固：落 traceback（不再销毁现场）；仍 best-effort 不阻塞 return
                        # （web _watch finally 兜底补 scan_end）。
                        logger.exception("blackbox _finalize_web failed (best-effort)")
                return self._state
            except CancelledError:
                self._state.status = "cancelled"
                self._state.current_phase = None
                return self._state
            except Exception as e:
                # 取消类异常按 cancelled 语义收尾（spec 2026-08-28 修 0）：cancel 注入丢失时
                # 取消以 ActivityError(cause=CancelledError) 形态上抛到这——不放行会被标
                # failed（语义失真）。对齐上方 except CancelledError 分支。
                if is_cancellation(e):
                    self._state.status = "cancelled"
                    self._state.current_phase = None
                    return self._state
                # session-status 同步(对齐 whitebox):workflow-level 失败 → state.status=failed +
                # return(不 raise,Temporal 标 COMPLETED)。不调 finalize_activity(规避
                # finalize_report 签名依赖);session 落盘靠 blackbox CLI worker.py 正常路径
                # (_to_workflow_summary 读 state.status=failed)或其 except Exception 兜底。
                self._state.status = "failed"
                if not self._state.errors:
                    self._state.errors.append(f"{type(e).__name__}: {e}")
                self._state.current_phase = None
                if is_worker_path:
                    try:
                        await self._finalize_web(act_input)
                    except Exception:
                        # 根因 2 加固：落 traceback（不再销毁现场）；仍 best-effort 不阻塞 return
                        # （web _watch finally 兜底补 scan_end）。
                        logger.exception("blackbox _finalize_web failed (best-effort)")
                return self._state
            finally:
                cleanup_settings()
                # engine 对象由 resolve_blackbox_engine activity 持有（workflow 侧不持有不可序列化
                # 对象）；stealth config 清理经 cleanup_engine_configs activity 完成。engine_name 在
                # 上方 try 外由 resolve_blackbox_engine 解析（line 117，先于本 try），此处必已定义。
                if engine_name and input.repo_path:
                    try:
                        await workflow.execute_activity(
                            activities.cleanup_engine_configs,
                            args=[input.repo_path, engine_name],
                            # 根因 3：cleanup 对 N session 串行 cleanup_processes（单 session 最坏 ~24s），
                            # 15s 不够；retry 会把同一次超时放大 3×。120s 覆盖串行 + maximum_attempts=1
                            # （cleanup 幂等，残留 config 下次覆盖，失败由 except 吞不阻断收尾）。
                            start_to_close_timeout=timedelta(seconds=120),
                            retry_policy=RetryPolicy(maximum_attempts=1),
                        )
                    except Exception:
                        pass  # best-effort cleanup，失败不阻断 workflow 收尾
                try:
                    await workflow.execute_activity(
                        activities.cleanup_auth_state_activity,
                        args=[act_input.workspace_path or input.repo_path],
                        start_to_close_timeout=timedelta(seconds=30),
                        retry_policy=RetryPolicy(maximum_attempts=1),
                    )
                except Exception:
                    pass  # best-effort cleanup，失败不阻断 workflow 收尾
                # per-scan host proxy 收尾（与 cleanup_auth_state 同模式：best-effort，
                # 失败只 swallow）。仅在 act_input.proxy_url 已设（起过代理）时调；
                # 空 host_mappings 路径 proxy_url 为 None → 跳过（零回归）。
                if act_input.proxy_url:
                    try:
                        await workflow.execute_activity(
                            activities.stop_host_proxy,
                            args=[act_input.proxy_url],
                            start_to_close_timeout=timedelta(seconds=30),
                            retry_policy=RetryPolicy(maximum_attempts=1),
                        )
                    except Exception:
                        pass  # best-effort，绝不阻断 workflow shutdown

        finally:
            # 尽力释放：cancel/cleanup 异常时由 runner 的闸门 janitor 兜底回收（spec §6）
            await release_gate_slot()

    async def _persist_progress(self, act_input: BlackboxActivityInput) -> None:
        """completed_agents 增量落盘 run 级 session.json（2026-08-27 列表进度不动修复 · 写侧）。

        与 whitebox 侧同构：每个 agent 完成点调用，progress_pct 分子原只在结束落盘。
        best-effort：activity 失败吞异常（进度显示降级回 SSE 读侧，不影响扫描本体）；
        单次尝试不重试（下一个 agent 完成点会再写）。
        """
        try:
            await workflow.execute_activity(
                activities.persist_completed_agents,
                args=[act_input, list(self._state.completed_agents)],
                start_to_close_timeout=timedelta(seconds=10),
                retry_policy=RetryPolicy(maximum_attempts=1),
            )
        except Exception:
            pass

    def _build_finalize_summary(self, error_fallback: str | None = None) -> dict:
        """构造 finalize_summary 用的 summary dict（success/failed 路径共用，DRY）。

        对齐 whitebox _build_finalize_summary（whitebox/workflows.py:67-88）：agent_metrics 消毒成
        AgentMetricsSummary（只 duration_ms + cost_usd 等 JSON-safe 字段），丢弃 structured_output
        富字段。根因 2（ghost-scan）：裸 dict(self._state.agent_metrics) 含 model_dump 残留的非 JSON
        原生对象 → temporal activity 参数编码失败 → 异常被吞 → finalize_summary 不执行 → scan_end
        不写 / heartbeat 不停 / session 永远 running。status 取 self._state.status（调用方已设）；
        error 取已记录首个 error，无则回落 error_fallback。
        """
        from supernova_core.models.audit import AgentMetricsSummary
        return {
            "status": self._state.status,
            "total_duration_ms": int((workflow.time_ns() / 1e9 - self._state.start_time) * 1000),
            "total_cost_usd": sum((m.get("cost_usd") or 0.0) for m in self._state.agent_metrics.values()),
            "completed_agents": list(self._state.completed_agents),
            "agent_metrics": {
                name: AgentMetricsSummary(
                    duration_ms=int(m.get("duration_ms", 0) or 0),
                    cost_usd=m.get("cost_usd"),
                )
                for name, m in self._state.agent_metrics.items()
            },
            "error": (self._state.errors[0] if self._state.errors else error_fallback),
        }

    async def _finalize_web(self, act_input: BlackboxActivityInput) -> None:
        """C1 Phase B（黑盒 web 化）：worker 路径收尾——调 finalize_summary 写 scan_end 事件 +
        清 AuditSession/heartbeat。仅 is_worker_path 调用（CLI 路径不调，run_scan 外层收尾）。
        summary 经 _build_finalize_summary 消毒（根因 2）。调用处包 best-effort try/except，
        防 finalize 失败阻塞 return（web _watch finally 兜底补 scan_end）。"""
        # 构造与 execute_activity 分离：构造失败时降级最小 summary 继续调度 activity，
        # 保证 scan_end/heartbeat 一定收尾（ghost-scan 兜底）。
        try:
            summary = self._build_finalize_summary()
        except Exception:
            logger.exception("blackbox _build_finalize_summary failed; using minimal summary")
            summary = {
                "status": self._state.status,
                "completed_agents": list(self._state.completed_agents),
            }
        await workflow.execute_activity(
            activities.finalize_summary, args=[act_input, summary],
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=retry_for("log"),
        )

    @workflow.query(name="PipelineProgress")
    def pipeline_progress(self) -> PipelineProgress:
        """返回当前工作流进度供 CLI 轮询。"""
        elapsed_ns = workflow.time_ns() - int(self._state.start_time * 1e9)
        return PipelineProgress(
            workflow_id=workflow.info().workflow_id,
            elapsed_ms=elapsed_ns // 1_000_000,
            current_phase=self._state.current_phase,
            current_agent=self._state.current_agent,
            completed_agents=self._state.completed_agents,
            status=self._state.status,
        )


@workflow.defn
class AuthValidationWorkflow:
    """独立认证验证 workflow(认证管理页"测试登录"):只跑 auth 段,不跑扫描。

    不能复用 BlackboxScanWorkflow:后者强依赖白盒产物(workflows.py:248-280 无白盒 queue
    抛 DELIVERABLE_NOT_FOUND fail-fast)。本 workflow 仅 log_phase + probe + 返回 result。
    """

    @workflow.run
    async def run(self, input: BlackboxAuthValidationInput) -> AuthValidationResult:
        if not input.web_url:
            # non_retryable: 输入校验错误重试无意义(输入不变),对齐 whitebox/workflows.py:475
            # fail-fast 模式;plain ValueError 默认 retryable → workflow task 无限重试,
            # execute_workflow 永久挂起(真机 web "测试登录"漏传 web_url 会卡死)。
            raise ApplicationError("BlackboxAuthValidationInput.web_url is required", non_retryable=True)
        act_input = BlackboxActivityInput(
            web_url=input.web_url,
            config_path=input.config_path,
            workspace_path=input.workspace_path,
            api_key=input.api_key,
            event_file=input.event_file,
            host_mappings=input.host_mappings or {},
            env_overrides=input.env_overrides,
            provider_config=input.provider_config,   # 完整穿线，防 key/端点错配
        )
        # 块1（认证验证可观测性）：setup_display 挂 AuditSession + StructuredEventRenderer 写
        # events.ndjson（agent 登录每步落盘）。event_file=None（CLI 直调）则不挂 renderer，setup_display
        # 照跑挂 NullAuditSession 兜底。setup_display 自身失败不阻塞验证（降级无 events，spec 风险），
        # 故 try/except 吞掉；但成功后 finalize 必跑（停 heartbeat，否则 daemon 线程泄漏）。
        display_ok = False
        proxy_url = ""
        try:
            await workflow.execute_activity(
                activities.setup_display, act_input,
                start_to_close_timeout=timedelta(seconds=30),
                retry_policy=retry_for("log"),
            )
            display_ok = True
        except Exception as exc:
            if is_cancellation(exc):  # 取消放行（spec 2026-08-28 修 0）
                raise
            pass  # 验证照跑（无 events），NullAuditSession 兜底后续 log_phase
        try:
            if act_input.host_mappings:
                proxy_url = await workflow.execute_activity(
                    activities.run_host_proxy_setup, act_input,
                    start_to_close_timeout=timedelta(seconds=60),
                    retry_policy=RetryPolicy(maximum_attempts=1),
                )
                if proxy_url:
                    act_input.proxy_url = proxy_url
            # 声明 auth-validation 阶段的 4 步（步骤条）：step key 与 log_milestone 工具同源
            # （AUTH_VALIDATION_PROGRESS），reducer 按 name 匹配推进。steps/intents 经
            # log_phase_start_activity 透传到 PhaseEvent(steps=...)。
            await workflow.execute_activity(
                activities.log_phase_start_activity,
                args=[
                    BlackboxActivityInput(**{**act_input.__dict__,
                                             "phase": AUTH_VALIDATION_PROGRESS.phase}),
                    list(AUTH_VALIDATION_PROGRESS.step_keys),
                    [s.intent for s in AUTH_VALIDATION_PROGRESS.steps],
                ],
                start_to_close_timeout=timedelta(seconds=10),
                retry_policy=retry_for("log"),
            )
            # 真实 status（2026-08-28 authcheck 超时丢账修复 · 状态失真半）：probe 抛异常
            # （超时耗尽 / 引擎错）→ finally 里 finalize 传 failed + error 后 re-raise——
            # 修复前硬编码 completed，3×10min 全超时也显示"成功完成"。probe 正常返回
            # （含业务性 success=False 结论）→ 生命周期完整 → completed。usage 聚合在
            # finalize_summary 内从 session.get_metrics()（MetricsTracker）取，cancel 落账
            # （activities probe 的 BaseException 分支）后自动累积，无需此处传。
            probe_error: str | None = None
            try:
                return await workflow.execute_activity(
                    activities.run_auth_validation_probe, act_input,
                    # 窗口经 input 传入（env 在 sandbox 外解析，默认 600s=原 10min）
                    start_to_close_timeout=timedelta(
                        seconds=input.probe_timeout_seconds or 600),
                    heartbeat_timeout=timedelta(minutes=2),
                    retry_policy=retry_for("auth-validation"),
                )
            except Exception as e:
                probe_error = f"{type(e).__name__}: {e}"
                raise  # workflow failed 语义保持（web 侧照常读到失败）
        finally:
            if proxy_url:
                try:
                    await workflow.execute_activity(
                        activities.stop_host_proxy, proxy_url,
                        start_to_close_timeout=timedelta(seconds=30),
                        retry_policy=RetryPolicy(maximum_attempts=1),
                    )
                except Exception:
                    pass
            if display_ok:
                # finalize_summary：drain LogBus + log_workflow_complete + 停 heartbeat + 清 session。
                # summary 最小集（auth-validation 无 agent_metrics 聚合，finalize_summary 容错 .get 读）。
                summary: dict = {"status": "completed" if probe_error is None else "failed"}
                if probe_error is not None:
                    summary["error"] = probe_error
                await workflow.execute_activity(
                    activities.finalize_summary,
                    args=[act_input, summary],
                    start_to_close_timeout=timedelta(seconds=30),
                    retry_policy=retry_for("log"),
                )


@workflow.defn
class BatchAuthValidationWorkflow:
    """档案级批量认证验证（认证管理页"测试登录"多选角色）：串行 N 次 Branch A 单次登录。

    语义（spec §2）：逐个独立验证每个选中角色能否登录（非越权对比）。与单 cred
    AuthValidationWorkflow 区别：后者跑一个 cred 即返；本 workflow 串行跑 items 全部，失败 cred
    仅标 failed 不阻断后续（对齐 validate_authentication Branch B 非 primary 失败不阻断语义）。
    batch_progress query 返回 per-cred 进度供 web watcher 实时回填 verify_status（分层：web 层
    query + 回填，blackbox activity 不调 web store）。

    每个 cred 复用单 cred 同款编排：setup_display（挂 AuditSession 写该 cred events.ndjson）→
    log_phase_start_activity（4 步 PhaseEvent）→ run_auth_validation_probe（Branch A 单次登录）
    → finalize_summary（drain+收尾）。串行 = 同时只一个 cred running，与 per-cred running 恢复契合。
    """

    def __init__(self):
        # cred_id -> {cred_id, state, failure_point?, failure_detail?}。query 返回此快照。
        self._progress: dict[str, dict] = {}

    @workflow.run
    async def run(self, input: BlackboxAuthValidationBatchInput) -> list[dict]:
        if not input.items:
            raise ApplicationError(
                "BlackboxAuthValidationBatchInput.items 必须非空", non_retryable=True)
        results: list[dict] = []
        for item in input.items:
            if not item.web_url:
                raise ApplicationError(
                    f"item {item.cred_id} 缺 web_url", non_retryable=True)
            self._progress[item.cred_id] = {"cred_id": item.cred_id, "state": "running"}
            act_input = BlackboxActivityInput(
                web_url=item.web_url,
                config_path=item.config_path,
                workspace_path=item.workspace_path,
                api_key=input.api_key,
                event_file=item.event_file,
                env_overrides=input.env_overrides,
                host_mappings=item.host_mappings or {},
                provider_config=input.provider_config,   # 完整穿线，防 key/端点错配
            )
            # setup_display best-effort（失败不阻塞，降级无 events，NullAuditSession 兜底）；成功后
            # finalize 必跑（停 heartbeat，否则 daemon 线程泄漏）。
            display_ok = False
            try:
                await workflow.execute_activity(
                    activities.setup_display, act_input,
                    start_to_close_timeout=timedelta(seconds=30),
                    retry_policy=retry_for("log"),
                )
                display_ok = True
            except Exception as exc:
                if is_cancellation(exc):  # 取消放行（spec 2026-08-28 修 0）
                    raise
                pass
            result = None
            proxy_url = ""
            try:
                # HOST 档案：item 带 mappings → 起 per-cred host proxy，proxy_url 注入 act_input
                # （probe 经代理落点）；不带 → 空 → 直连（零回归）。镜像单 cred AuthValidationWorkflow。
                if act_input.host_mappings:
                    proxy_url = await workflow.execute_activity(
                        activities.run_host_proxy_setup, act_input,
                        start_to_close_timeout=timedelta(seconds=60),
                        retry_policy=RetryPolicy(maximum_attempts=1),
                    )
                    if proxy_url:
                        act_input.proxy_url = proxy_url
                # 声明 4 步 PhaseEvent（步骤条）：step key 与 log_milestone 工具同源。
                await workflow.execute_activity(
                    activities.log_phase_start_activity,
                    args=[
                        BlackboxActivityInput(**{**act_input.__dict__,
                                                 "phase": AUTH_VALIDATION_PROGRESS.phase}),
                        list(AUTH_VALIDATION_PROGRESS.step_keys),
                        [s.intent for s in AUTH_VALIDATION_PROGRESS.steps],
                    ],
                    start_to_close_timeout=timedelta(seconds=10),
                    retry_policy=retry_for("log"),
                )
                result = await workflow.execute_activity(
                    activities.run_auth_validation_probe, act_input,
                    start_to_close_timeout=timedelta(minutes=10),
                    heartbeat_timeout=timedelta(minutes=2),
                    retry_policy=retry_for("auth-validation"),
                )
            except Exception as e:
                if is_cancellation(e):  # 取消放行（spec 2026-08-28 修 0）：不转 per-cred 失败
                    raise
                # per-cred 异常隔离：某 cred activity 重试耗尽/抛错 → 标 failed，不阻断后续 cred
                # （对齐 Branch B 非 primary 失败不阻断）。run_auth_validation_probe 自身降级返回不抛，
                # 此 except 兜底 activity 框架级异常（non_retryable / 重试耗尽）。LLM 引擎失败
                # （provider 401/限额）分类成 engine，与目标站登录失败区分（2026-08-17）。
                result = AuthValidationResult(
                    success=False,
                    failure_point="engine" if is_engine_failure(e) else "out_of_band",
                    failure_detail=f"{type(e).__name__}: {e}")
            finally:
                if proxy_url:
                    try:
                        await workflow.execute_activity(
                            activities.stop_host_proxy, proxy_url,
                            start_to_close_timeout=timedelta(seconds=30),
                            retry_policy=RetryPolicy(maximum_attempts=1),
                        )
                    except Exception:
                        pass  # proxy 收尾 best-effort，失败不阻断下一 cred
                if display_ok:
                    try:
                        await workflow.execute_activity(
                            activities.finalize_summary,
                            args=[act_input, {"status": "completed"}],
                            start_to_close_timeout=timedelta(seconds=30),
                            retry_policy=retry_for("log"),
                        )
                    except Exception:
                        pass  # finalize 失败不阻断下一个 cred（best-effort 收尾）
            entry = {"cred_id": item.cred_id,
                     "state": "success" if result and result.success else "failed"}
            if not result or not result.success:
                entry["failure_point"] = result.failure_point if result else "out_of_band"
                entry["failure_detail"] = result.failure_detail if result else None
            self._progress[item.cred_id] = entry
            results.append(entry)
        return results

    @workflow.query(name="batch_progress")
    def batch_progress(self) -> dict:
        """返回各 cred 进度供 web watcher 回填 verify_status。

        items 顺序与 input.items 一致（watcher 按 cred_id 取，顺序仅供诊断）；all_done=全部终态。
        running/pending 的 cred 也在列表里（watcher 据此定位当前 running 那个）。
        """
        items = list(self._progress.values())
        return {
            "items": items,
            "all_done": bool(items) and all(
                it.get("state") in ("success", "failed") for it in items),
        }
