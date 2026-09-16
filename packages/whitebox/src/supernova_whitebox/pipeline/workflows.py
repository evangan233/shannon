import asyncio
from datetime import timedelta
from pathlib import Path

from temporalio import workflow
from temporalio.exceptions import ApplicationError as ApplicationFailure, CancelledError
from temporalio.common import RetryPolicy

from supernova_core.models.agents import (
    ALL_VULN_CLASSES,
    DEGRADABLE_VULN_CLASSES,
    AgentName,
    VulnType,
)
from supernova_core.models.errors import ErrorCode, PentestError
from supernova_core.runtime.temporal_heartbeat import is_cancellation
from supernova_core.config.vuln_selection import select_vuln_classes
# is_llm_track_enabled() 在 CLI 入口(main.py:77)读 env 一次注入 input.enable_llm_track,
# workflow 用 input.enable_llm_track 判定(守 Temporal 确定性: workflow code 不直接读 env).

from .shared import ActivityInput, PipelineInput, PipelineState, PipelineProgress
from .step_intents import step_names, step_intents


# run_code_index activity timeout: 文件级聚合后 sink+source+taint 三阶段累加仍偏紧,
# 10min 容不下大仓(真机 kol_mapping_service 撞 timeout)-> 曾提至 45min(spec 2026-07-10 §3.2)。
# 2026-08-04 降回 20min: GitNexusMCPClient 已给 create_subprocess_exec / stdin.drain 加
# 超时(P0+P1), MCP 子进程启动偶发卡死 30s 内自拔 -> activity 重试, 不再裸等 45min。
# 正常查询实测 ~6min(delivery 仓), 20min 留足余量; 最坏 3 次重试都卡启动也 ~90s fail-fast。
CODE_INDEX_ACTIVITY_TIMEOUT = timedelta(minutes=20)


def vuln_phase_steps(vuln_classes: list[str]) -> tuple[str, ...]:
    return tuple(f"{vt}-vuln" for vt in vuln_classes)


def _activity_not_registered_hint(exc: Exception) -> str:
    """§5.7（spec 2026-08-26-report-generation-agent）：activity 未注册 = 部署
    不一致（代码已提交、worker 进程未重启——NodeGoat-20260826-041323 实证：
    GN 富化 activity 曾 3 次 NotFoundError 静默降级）。显式提示重启，不再
    无痕跳过。"""
    msg = str(exc).lower().replace(" ", "")
    if "notregistered" in msg or "notfounderror" in msg:
        return (" — ACTIVITY NOT REGISTERED: worker 部署不一致（新代码未随 worker"
                " 重启加载），重启 worker 后新扫描生效")
    return ""


def _needs_recon_context_digest(
    selected_classes: list[VulnType],
    completed_agents: list[str],
    llm_track_enabled: bool,
) -> bool:
    """Whether any pending vuln agent will consume the shared recon digest.

    Pure workflow-safe helper. Resume skips digest generation when every selected
    vuln agent already completed; a degraded digest remains retriable whenever a
    pending agent exists.
    """
    for vuln_class in selected_classes:
        if not llm_track_enabled and vuln_class in DEGRADABLE_VULN_CLASSES:
            continue
        if AgentName(f"{vuln_class}-vuln").value not in completed_agents:
            return True
    return False


def _decide_gitnexus_failfast(statuses: dict, llm_track_enabled: bool) -> list[str]:
    """Task 4 fail-fast 决策(纯函数, 单测可达, 无 Temporal 依赖).

    返回需终止的 DEGRADABLE(inj/xss/ssrf)类列表(-> workflow raise ApplicationFailure).
    空 list = 继续. 三场景:
      - 关轨 + DEGRADABLE 任一 failed -> 返回该类(无 LLM 兜底, 终止).
      - 关轨 + 仅 authz failed -> [] 不终止(authz-vuln LLM 关轨仍跑, 做 GitNexus
        做不了的 Vertical/Context; authz 不在 DEGRADABLE_VULN_CLASSES).
      - 开轨 + 任何 fail -> [] 继续(LLM 轨兜底, merger/report 读状态产物标红).

    抽成纯函数: workflow 内联逻辑难以 Temporal 真机测(需 mock 整条链),
    抽出来后单测覆盖三场景 + 边界(状态缺失/多 fail), workflow 只调它 + raise.
    """
    if llm_track_enabled:
        return []
    return [
        vc for vc in DEGRADABLE_VULN_CLASSES
        if statuses.get(vc, {}).get("status") == "failed"
    ]


with workflow.unsafe.imports_passed_through():
    from . import activities
    from supernova_core.services.settings_writer import sync_code_path_deny_rules, cleanup_settings
    from supernova_core.services.scan_gate import (
        acquire_gate_slot, release_gate_slot,
        gate_scan_id_from_event_file, gate_ws_for_descriptor,
        gate_ws_cap_from_overrides)
    from supernova_core.models.retry import retry_for
    from supernova_core.models.errors import classify_error_for_temporal

def _derive_workspace_path(input: PipelineInput) -> str:
    """web（event_file 同目录）/ CLI（repo 同级 workspaces/<ws>）/ 兜底 三级派生
    （2026-07-14 路径分歧修复的口径）。WhiteboxScanWorkflow 主线与 MrScanWorkflow
    前置 activities 共用（曾各自内联，MrScanWorkflow 抄错成不存在的
    input.workspace_path——workflow 级测试抓出）。"""
    if input.event_file:
        return str(Path(input.event_file).parent)
    if input.workspace_name:
        return str(Path(input.repo_path).parent / "workspaces" / input.workspace_name)
    return input.repo_path


def _gate_label(input: PipelineInput) -> str:
    """闸门快照展示标签：仓库名（MR 追加 !MR号，兜底 web_url）。"""
    repo = Path(input.repo_path).name if input.repo_path else ""
    if input.mr_meta:
        mr_id = (input.mr_meta.get("mr_iid") or input.mr_meta.get("mr_id") or "")
        return f"{repo}!{mr_id}" if mr_id else repo
    return repo or input.web_url


@workflow.defn
class WhiteboxScanWorkflow:
    def __init__(self):
        self._state = PipelineState()
        # MR 增量（spec 2026-09-03 §5.1 容量铁律）：run_incremental_scope 算好的
        # GN verdict 窗口分钟数；None = 非 MR / 未跑 scope（回落全量 15min）。
        self._mr_verdict_timeout_minutes: int | None = None

    @staticmethod
    def _derive_workspace_path(input: PipelineInput) -> str:
        """child 主线兼容入口（历史内联点）——委托模块级实现。"""
        return _derive_workspace_path(input)

    def _build_finalize_summary(self, error_fallback: str | None = None) -> dict:
        """构造 finalize_summary 用的 summary dict(success/failed 路径共用,DRY).

        status 取 self._state.status(调用前调用方已设:success 路径=completed/failed,
        except Exception 路径=failed);error 取已记录的首个 error,无则回落 error_fallback
        (success=None, failed=str(e))。
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

    async def _persist_progress(self, act_input: ActivityInput) -> None:
        """completed_agents 增量落盘 session.json（2026-08-27 列表进度不动修复 · 写侧）。

        每个 agent 完成点调用——progress_pct 分子原只在 workflow 结束落盘，运行中
        恒 []（列表/仪表盘 progress_pct 阶段内钉死）。best-effort：activity 失败吞
        异常继续扫描（进度显示降级回 SSE 读侧，不影响扫描本体）；单次尝试不重试
        （下一个 agent 完成点会再写，无需为此占用重试预算）。
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

    @workflow.run
    async def run(self, input: PipelineInput) -> PipelineState:
        # 全局扫描闸门（spec 2026-09-08-worker-scan-gate §5）：排队轮询直到获得全局槽。
        # 放最前：排队期间不推进任何 pipeline 逻辑，start_time 亦在放行后才记
        # （duration 不含排队）。MR 的白盒子 workflow 也走这里（mr_meta 非空 → kind=mr）。
        await acquire_gate_slot({
            "kind": "mr" if input.mr_meta else "whitebox",
            "ws": gate_ws_for_descriptor(input.workspace_name, input.event_file),
            "scan_id": gate_scan_id_from_event_file(input.event_file),
            "label": _gate_label(input),
            # ws 并发上限（2026-09-15）：闸门段先于 setup_display（set_scan_env 注入
            # 点），ws_getenv 层不可用，从 input.env_overrides 提交时快照解析携带；
            # 未配置不带键（闸门侧 None=仅全局容量）。clamp 在闸门侧（sandbox 不
            # import worker 进程常量）。
            **({} if (ws_cap := gate_ws_cap_from_overrides(input.env_overrides))
               is None else {"ws_cap": ws_cap}),
        }, input)
        try:
            # resume: 预填已完成 agent，激活下方 `if X not in completed_agents` 守卫
            if input.resume_completed_agents:
                self._state.completed_agents = list(input.resume_completed_agents)
            self._state.start_time = workflow.time_ns() / 1e9

            # C1 Phase B: worker 容器路径门控. event_file 非 None = web 提交(worker 路径),
            # 调迁移 activity(setup_display/heartbeat/finalize); None = CLI 路径, run_scan 外层
            # 已 set_audit_session/heartbeat/log_workflow_complete, workflow 内不重复(守 "CLI
            # 零改动" + 消除 R1 双重 scan_end/heartbeat/set_audit_session).
            is_worker_path = input.event_file is not None

            # Resolve config (YAML) early so vuln-class selection can consult cfg.vuln_classes.
            cfg = None
            if input.config_path:
                from supernova_core.config.parser import parse_config
                cfg = parse_config(input.config_path)

            # vuln 类优先级链: CLI/env override(经 input.vuln_classes) > MR 启发式(mr_meta,
            # spec 2026-09-03 §4.5) > YAML(cfg.vuln_classes) > 默认全跑。
            # 修通 pre-existing 断链（旧: input.vuln_classes or ALL_VULN_CLASSES，丢弃 cfg.vuln_classes）。
            from .mr_wiring import resolve_mr_vuln_classes
            _mr_classes = resolve_mr_vuln_classes(
                input.vuln_classes, input.mr_meta,
                cfg.vuln_classes if cfg else None,
            )
            if _mr_classes is not None:
                # VulnType 是 Literal 别名（非 enum）——字符串直传即可（曾误
                # VulnType(c) 实例化 typing.Literal 炸 workflow task，测试抓出）。
                selected_classes: list[VulnType] = [c for c in _mr_classes]
            else:
                selected_classes = select_vuln_classes(
                    input.vuln_classes,
                    cfg.vuln_classes if cfg else None,
                )

            # Compute workspace_path so activities know where to write 产物(heartbeat/deliverables/
            # activity_failures/agents/workflow.log/session). WEB 路径(event_file 非 None): 用 event_file
            # 同目录(web scan_manager 创建的 /app/workspaces/<ws>), 与 web 判活(is_scan_alive 看
            # <ws>/heartbeat)/报告读取(get_workspace_vuln_counts)对齐。CLI 路径(无 event_file): 走
            # repo_path.parent/workspaces(CLI 习惯, run_scan 外层建)。修路径分歧(2026-07-14 端到端暴露:
            # worker 产物原落 /app/repos/.../workspaces/<ws>, web 找不到 heartbeat → 判活失效 + 报告空).
            workspace_path = self._derive_workspace_path(input)

            act_input = ActivityInput(
                repo_path=input.repo_path,
                web_url=input.web_url,
                config_path=input.config_path,
                workspace_name=input.workspace_name,
                deliverables_subdir=input.deliverables_subdir,
                pipeline_testing_mode=input.pipeline_testing_mode,
                api_key=input.api_key,
                prompt_override=input.prompt_override,
                workspace_path=workspace_path,
                event_file=input.event_file,
                provider_config=input.provider_config,   # P3c 阶段 1：一处灌入，全链 **act_input.__dict__ 继承
                combined=input.combined,   # D1 组合扫描：透传到 finalize_summary 做阶段分支
                env_overrides=input.env_overrides,
                mr_base_ref=input.mr_base_ref,   # MR 增量（spec 2026-09-03）：前置 activity 消费
                mr_head_ref=input.mr_head_ref,
                mr_meta=input.mr_meta,           # 消费点：prompt 引导段 / verdict 过滤 / 报告
            )
            # C1 Phase B: worker 路径前导 setup_display(注入 AuditSession + event_file) + 并行
            # run_heartbeat(长驻写 heartbeat). CLI 路径跳过(外层 run_scan 已做).
            if is_worker_path:
                await workflow.execute_activity(
                    activities.setup_display, act_input,
                    start_to_close_timeout=timedelta(seconds=30),
                    retry_policy=retry_for("standard"),
                )
                # heartbeat 由 setup_display(上面 await)启动的 daemon 线程写, 非 workflow background
                # activity. 曾用 start_activity/create_task 包 run_heartbeat, 但 max_concurrent_workflow_tasks=1
                # (runner.py wb_worker, AuditSession 全局单例所致)下 worker 不 dispatch background activity
                # handler → heartbeat 永不写(2026-07-23 hr_1784788700 回归, test_workflow_heartbeat_execution
                # 钉死). finalize_summary 停止 daemon(终态自停兜底).
            await workflow.execute_activity(
                activities.log_phase_start_activity,
                args=[
                    ActivityInput(**{**act_input.__dict__, "phase": "setup"}),
                    list(step_names("setup")),
                    list(step_intents("setup")),
                ],
                start_to_close_timeout=timedelta(seconds=10),
                retry_policy=retry_for("log"),
            )
            self._state.current_phase = "setup"
            await workflow.execute_activity(
                activities.run_preflight, act_input,
                start_to_close_timeout=timedelta(minutes=2),
                retry_policy=retry_for("preflight"),
            )

            # Credential check
            await workflow.execute_activity(
                activities.run_credential_check, act_input,
                start_to_close_timeout=timedelta(minutes=1),
                retry_policy=retry_for("preflight"),
            )

            await workflow.execute_activity(
                activities.log_phase_complete_activity,
                ActivityInput(**{**act_input.__dict__, "phase": "setup"}),
                start_to_close_timeout=timedelta(seconds=10),
                retry_policy=retry_for("log"),
            )

            # Write code path deny rules (S6)
            if cfg and cfg.rules and cfg.rules.avoid:
                sync_code_path_deny_rules(cfg.rules.avoid)

            try:
                # === Parallel: Code Index (deterministic) ∥ PRE_RECON (LLM) ===
                # These two have no data dependency. The original Shannon had no
                # deterministic layer, so PRE_RECON's Sink Hunter runs fine
                # on its own.

                if AgentName.PRE_RECON.value not in self._state.completed_agents:
                    await workflow.execute_activity(
                        activities.log_phase_start_activity,
                        args=[
                            ActivityInput(**{**act_input.__dict__, "phase": "pre-recon"}),
                            list(step_names("pre-recon")),
                            list(step_intents("pre-recon")),
                        ],
                        start_to_close_timeout=timedelta(seconds=10),
                        retry_policy=retry_for("log"),
                    )
                    self._state.current_phase = "pre-recon"
                    self._state.current_agent = AgentName.PRE_RECON.value

                    # pre-recon LLM 始终跑(不再受 enable_llm_track 门控): recon 链是 authz
                    # Vertical/Context 的输入(角色模型 §7 / 工作流 §8.3), GitNexus 完全不产 ——
                    # 关 LLM 轨也必须跑, 否则 authz 巧妇难为无米之炊(plan smooth-wandering-dolphin)。
                    # Fail-fast: if either fails, cancel the other and propagate.
                    code_index_result, pre_recon_metrics = await asyncio.gather(
                        workflow.execute_activity(
                            activities.run_code_index, act_input,
                            start_to_close_timeout=CODE_INDEX_ACTIVITY_TIMEOUT,
                            retry_policy=retry_for("code-index"),
                        ),
                        workflow.execute_activity(
                            activities.run_agent,
                            ActivityInput(**{**act_input.__dict__, "agent_name": AgentName.PRE_RECON.value}),
                            start_to_close_timeout=timedelta(hours=2),
                            retry_policy=retry_for("standard"),
                        ),
                    )
                    self._state.completed_agents.append(AgentName.PRE_RECON.value)
                    self._state.agent_metrics[AgentName.PRE_RECON.value] = pre_recon_metrics
                    await self._persist_progress(act_input)

                    self._state.code_index_stats = code_index_result

                    # merge_sink_reports 始终跑(不再门控): 依赖 pre-recon deliverable,
                    # 保 pre-recon(上)则保它。合并确定性 sinks + LLM-discovered sinks。
                    await workflow.execute_activity(
                        activities.run_merge_sink_reports, act_input,
                        start_to_close_timeout=timedelta(minutes=2),
                        retry_policy=retry_for("standard"),
                    )

                    # Entry point fusion: schema/convention 无条件跑（纯确定性 + LLM 源靠
                    # deliverable 存在性内部 skip）；G6 解耦——不再被 enable_llm_track 门控，
                    # 让关 LLM 轨时 GitNexus 轨仍融合 OpenAPI schema 源（兜底不丢入口）。
                    await workflow.execute_activity(
                        activities.run_entry_point_fusion, act_input,
                        start_to_close_timeout=timedelta(minutes=2),
                        retry_policy=retry_for("standard"),
                    )

                    # Adjudicate merged entry points by confidence
                    await workflow.execute_activity(
                        activities.run_save_adjudication, act_input,
                        start_to_close_timeout=timedelta(minutes=2),
                        retry_policy=retry_for("standard"),
                    )
                    self._state.current_agent = None

                    # === Route Analysis Phase (parallel) ===
                    framework_result, frontend_result = await asyncio.gather(
                        workflow.execute_activity(
                            activities.run_framework_analysis, act_input,
                            start_to_close_timeout=timedelta(minutes=5),
                            retry_policy=retry_for("standard"),
                        ),
                        workflow.execute_activity(
                            activities.run_frontend_mapping, act_input,
                            start_to_close_timeout=timedelta(minutes=5),
                            retry_policy=retry_for("standard"),
                        ),
                    )

                    # Route chain building (depends on framework + frontend)
                    await workflow.execute_activity(
                        activities.run_route_chain_building, act_input,
                        start_to_close_timeout=timedelta(minutes=2),
                        retry_policy=retry_for("standard"),
                    )
                    # MR 增量模式（spec 2026-09-03 §3.1 步骤 6）：head 索引已产，
                    # 合成 IncrementalScope（三来源 verdict 候选过滤集）供 GitNexus 轨
                    # 预过滤 + 报告增量段消费。非 MR（mr_meta=None）跳过，零行为变化。
                    if input.mr_meta:
                        from . import mr_activities
                        _mr_scope = await workflow.execute_activity(
                            mr_activities.run_incremental_scope, act_input,
                            start_to_close_timeout=timedelta(minutes=2),
                            retry_policy=retry_for("standard"),
                        )
                        # 容量铁律（spec §5.1）：GN verdict 窗口按增量链数重估
                        # （activity 层算好的分钟数，workflow 只透传——沙箱禁 env 读）
                        self._mr_verdict_timeout_minutes = (
                            _mr_scope or {}).get("verdict_timeout_minutes")
                    await workflow.execute_activity(
                        activities.log_phase_complete_activity,
                        ActivityInput(**{**act_input.__dict__, "phase": "pre-recon"}),
                        start_to_close_timeout=timedelta(seconds=10),
                        retry_policy=retry_for("log"),
                    )

                if AgentName.RECON.value not in self._state.completed_agents:
                    # recon LLM 始终跑(不再门控): authz Vertical/Context 的输入
                    # (角色模型 §7 / 工作流 §8.3 / 端点安全上下文 §4.2), GitNexus 完全不产。
                    await workflow.execute_activity(
                        activities.log_phase_start_activity,
                        args=[
                            ActivityInput(**{**act_input.__dict__, "phase": "recon"}),
                            list(step_names("recon")),
                            list(step_intents("recon")),
                        ],
                        start_to_close_timeout=timedelta(seconds=10),
                        retry_policy=retry_for("log"),
                    )
                    self._state.current_phase = "recon"
                    self._state.current_agent = AgentName.RECON.value
                    metrics = await workflow.execute_activity(
                        activities.run_agent,
                        ActivityInput(**{**act_input.__dict__, "agent_name": AgentName.RECON.value}),
                        start_to_close_timeout=timedelta(hours=2),
                        retry_policy=retry_for("standard"),
                    )
                    self._state.completed_agents.append(AgentName.RECON.value)
                    self._state.agent_metrics[AgentName.RECON.value] = metrics
                    await self._persist_progress(act_input)
                    self._state.current_agent = None
                    await workflow.execute_activity(
                        activities.log_phase_complete_activity,
                        ActivityInput(**{**act_input.__dict__, "phase": "recon"}),
                        start_to_close_timeout=timedelta(seconds=10),
                        retry_policy=retry_for("log"),
                    )

                # Shared recon digest: generate once before the vuln-agent fan-out.
                # This removes the former N-times-per-scan recon-summary LLM calls and
                # guarantees every pending vuln agent receives the same LLM-track context.
                if _needs_recon_context_digest(
                        selected_classes, self._state.completed_agents,
                        input.enable_llm_track):
                    await workflow.execute_activity(
                        activities.run_recon_context_digest, act_input,
                        start_to_close_timeout=timedelta(minutes=10),
                        retry_policy=retry_for("standard"),
                    )

                # Risk scoring — produce tiered audit plan
                await workflow.execute_activity(
                    activities.log_phase_start_activity,
                    args=[
                        ActivityInput(**{**act_input.__dict__, "phase": "risk-scoring"}),
                        list(step_names("risk-scoring")),
                        list(step_intents("risk-scoring")),
                    ],
                    start_to_close_timeout=timedelta(seconds=10),
                    retry_policy=retry_for("log"),
                )
                self._state.current_phase = "risk-scoring"
                risk_result = await workflow.execute_activity(
                    activities.run_risk_scoring, act_input,
                    start_to_close_timeout=timedelta(minutes=5),
                    retry_policy=retry_for("risk-scoring"),
                )
                self._state.audit_plan_stats = risk_result

                await workflow.execute_activity(
                    activities.log_phase_complete_activity,
                    ActivityInput(**{**act_input.__dict__, "phase": "risk-scoring"}),
                    start_to_close_timeout=timedelta(seconds=10),
                    retry_policy=retry_for("log"),
                )

                # phase start 的 step/intent 列表对齐实际调度的 vuln agent: 关 LLM 轨时只
                # authz/auth-vuln 跑(inj/xss/ssrf 靠 GitNexus chain_verdict, 在本 phase 后段,
                # 非 vuln agent, 不在此 step 列表), 避免显示 inj-vuln 等不跑的 agent 误导。
                if input.enable_llm_track:
                    vuln_display = list(selected_classes)
                else:
                    vuln_display = [vt for vt in selected_classes
                                    if vt not in DEGRADABLE_VULN_CLASSES]
                await workflow.execute_activity(
                    activities.log_phase_start_activity,
                    args=[
                        ActivityInput(**{**act_input.__dict__, "phase": "vulnerability-analysis"}),
                        list(vuln_phase_steps([str(vt) for vt in vuln_display])),
                        # 必须补齐第 3 参数(intents)，使 args 数量(3)== log_phase_start_activity
                        # 参数数(3)。否则 temporalio worker 检测到数量不匹配会把整个 arg_types
                        # 置 None，input 被反序列化成 dict 而非 ActivityInput → input.phase 崩。
                        # vuln steps 是动态 agent(vuln_classes 决定)，无静态 step_intents，故按
                        # 每个 vuln class 现造平行 intent 文案。
                        [f"分析 {vt} 漏洞" for vt in vuln_display],
                    ],
                    start_to_close_timeout=timedelta(seconds=10),
                    retry_policy=retry_for("log"),
                )
                self._state.current_phase = "vulnerability-analysis"
                vuln_tasks: list[tuple[VulnType, AgentName, object]] = []
                if input.enable_llm_track:
                    # 开轨: 全部 selected_classes 跑(双轨: LLM vuln agent + GitNexus 轨 OR)
                    for vt in selected_classes:
                        agent_name = AgentName(f"{vt}-vuln")
                        if agent_name.value not in self._state.completed_agents:
                            self._state.current_agent = agent_name.value
                            coro = workflow.execute_activity(
                                activities.run_vuln_agent,
                                ActivityInput(**{**act_input.__dict__, "agent_name": agent_name.value}),
                                start_to_close_timeout=timedelta(hours=2),
                                retry_policy=retry_for("vuln"),
                            )
                            vuln_tasks.append((vt, agent_name, coro))
                else:
                    # 关 LLM 轨: 只关 inj/xss/ssrf(taint, GitNexus chain_verdict 主干兜底);
                    # authz/auth 必须保留(GitNexus 只做 IDOR 不覆盖 Vertical/Context, auth 无确定性轨)。
                    # recon/pre-recon LLM 已在上游始终跑(本 gate 之外), 保证 authz 有输入不降级。
                    for vt in selected_classes:
                        if vt in DEGRADABLE_VULN_CLASSES:
                            continue
                        agent_name = AgentName(f"{vt}-vuln")
                        if agent_name.value not in self._state.completed_agents:
                            self._state.current_agent = agent_name.value
                            coro = workflow.execute_activity(
                                activities.run_vuln_agent,
                                ActivityInput(**{**act_input.__dict__, "agent_name": agent_name.value}),
                                start_to_close_timeout=timedelta(hours=2),
                                retry_policy=retry_for("vuln"),
                            )
                            vuln_tasks.append((vt, agent_name, coro))
                    await workflow.execute_activity(
                        activities.log_info_activity,
                        ActivityInput(**{**act_input.__dict__,
                           "info_message": "llm_track=disabled (SUPERNOVA_LLM_TRACK_ENABLED=0): inj/xss/ssrf vuln agents skipped (GitNexus chain_verdict fallback); authz/auth vuln agents + recon/pre-recon LLM retained",
                           "info_level": "info"}),
                        start_to_close_timeout=timedelta(seconds=10),
                        retry_policy=retry_for("log"),
                    )

                if vuln_tasks:
                    semaphore = asyncio.Semaphore(input.max_concurrent)

                    async def bounded(coro):
                        async with semaphore:
                            return await coro

                    results = await asyncio.gather(
                        *[bounded(coro) for _, _, coro in vuln_tasks],
                        return_exceptions=True,
                    )
                    # 取消放行（spec 2026-08-28-temporal-native-cancel-design 修 0）：
                    # return_exceptions=True 会把 activity 取消的 ActivityError 收进结果
                    # 列表——不放行则 workflow 继续下一 phase（幽灵扫描机制，T1 探针钉死）。
                    for _r in results:
                        if isinstance(_r, BaseException) and is_cancellation(_r):
                            raise _r
                    for (vt, agent_name, _), result in zip(vuln_tasks, results):
                        if isinstance(result, Exception):
                            self._state.errors.append(f"{agent_name.value}: {result}")
                            self._state.failed_agents.append(agent_name.value)
                        else:
                            self._state.completed_agents.append(agent_name.value)
                            self._state.agent_metrics[agent_name.value] = result
                            await self._persist_progress(act_input)
                # === Authz GitNexus track: judge IDOR candidates (spec §5.7) ===
                # Runs after vuln agents (LLM track queues ready) and before the
                # dual-track merge (Plan 3) so authz_gitnexus_queue.json exists
                # when merge reads it. Graceful: empty candidates -> empty queue.
                # Task 4 fail-fast: 删 try/except 吞异常; activity 返 failed=True 经
                # 状态产物标红, 不再走"LLM 兜底"降级(authz-vuln LLM 轨在关轨时仍跑,
                # 由 _decide_gitnexus_failfast 判定, authz fail 永不终止).
                _authz_gn = await workflow.execute_activity(
                    activities.run_authz_gitnexus_judge, act_input,
                    start_to_close_timeout=timedelta(minutes=30),  # 原 10；多轮 agent 窗口（spec-0）
                    retry_policy=retry_for("gitnexus-verdict"),  # 原 standard；spec-1a 切（多轮 agent，max 3）
                )
                # === GitNexus-track chain verdict: inj/xss/ssrf (spec §5.4-5.6) ===
                # Produces <vuln>_gitnexus_queue.json for the dual-track merger.
                # Task 4 fail-fast: 删 try/except; activity 返 failed_classes/fail_reasons,
                # workflow 据返回值判 fail-fast(关轨 + DEGRADABLE fail -> 终止).
                # MR 增量（spec §5.1 容量铁律）：窗口按增量链数重估（链数 ÷ 并发 ×
                # 60s/轮，下限 5min——run_incremental_scope 算好穿来）；全量扫描保持
                # 15min（多轮 agent 窗口，spec-0）。未跑 scope（resume 跳过 pre-recon
                # 段）回落全量窗口——宁可宽不可爆。
                _gn_timeout = timedelta(minutes=15)
                if input.mr_meta is not None and self._mr_verdict_timeout_minutes:
                    _gn_timeout = timedelta(minutes=int(self._mr_verdict_timeout_minutes))
                _gn_verdict = await workflow.execute_activity(
                    activities.run_gitnexus_chain_verdict, act_input,
                    start_to_close_timeout=_gn_timeout,
                    retry_policy=retry_for("standard"),
                )

                # === fail-fast 编排:汇总两轨状态,写 gitnexus_track_status.json ===
                # 状态产物供 merger/report 读(开轨标红); 关轨 + DEGRADABLE fail 由
                # _decide_gitnexus_failfast 判定后 raise 终止(无 LLM 兜底).
                _statuses: dict = {}
                for _vc, _n in (_gn_verdict or {}).get("per_class", {}).items():
                    _statuses[_vc] = {"status": "ok", "findings": _n}
                for _vc in (_gn_verdict or {}).get("failed_classes", []):
                    _statuses[_vc] = {"status": "failed",
                                      "reason": (_gn_verdict or {}).get("fail_reasons", {}).get(_vc, "unknown")}
                if _authz_gn is not None:
                    if _authz_gn.get("failed"):
                        _statuses["authz"] = {"status": "failed", "reason": _authz_gn.get("fail_reason", "unknown")}
                    else:
                        _statuses["authz"] = {"status": "ok", "findings": _authz_gn.get("verdict_count", 0)}
                await workflow.execute_activity(
                    activities.write_track_status_activity,
                    ActivityInput(**{**act_input.__dict__, "track_statuses": _statuses}),
                    start_to_close_timeout=timedelta(seconds=10),
                    retry_policy=retry_for("log"),
                )

                # 关轨终止:仅 DEGRADABLE(inj/xss/ssrf)的 GitNexus fail 是真·无 LLM 兜底 -> 终止。
                # authz GitNexus fail(任何模式)+ 开轨的 inj/xss/ssrf fail -> 标红继续(merger/report 读状态产物)
                # 关轨判定用 input.enable_llm_track(已在 workflow 入口由 CLI 从 is_llm_track_enabled()
                # 读 env 一次注入), 守 Temporal 确定性(workflow code 不应直接读 env).
                if _no_fallback_failed := _decide_gitnexus_failfast(
                    _statuses, llm_track_enabled=input.enable_llm_track
                ):
                    raise ApplicationFailure(
                        f"GitNexus 轨 fail-fast(关轨模式):{_no_fallback_failed} 判定失败,"
                        f"且这些类关轨后无 LLM 轨兜底 -> 终止扫描。",
                        type="GitNexusTrackFailure", non_retryable=True,
                    )
                await workflow.execute_activity(
                    activities.run_merge_dual_track_queues,
                    act_input,
                    start_to_close_timeout=timedelta(minutes=2),
                    retry_policy=retry_for("standard"),
                )
                # === 对抗性审查（merge 后、富化前；non-fatal，spec
                # 2026-09-10）：固定 7 维度逐卡反驳，refuted 剔卡+归档，
                # 反驳掉的卡不再消耗富化/POC/polish 的逐卡 LLM 成本。 ===
                try:
                    await workflow.execute_activity(
                        activities.run_adversarial_review, act_input,
                        start_to_close_timeout=timedelta(minutes=20),
                        retry_policy=retry_for("standard"),
                    )
                except Exception as exc:
                    if is_cancellation(exc):  # 取消放行（吞掉=幽灵扫描）
                        raise
                    if _activity_not_registered_hint(exc):
                        raise ApplicationFailure(
                            f"Adversarial review activity is not registered: {exc}",
                            type="ActivityNotRegistered",
                            non_retryable=True,
                        ) from exc
                    await workflow.execute_activity(
                        activities.log_info_activity,
                        ActivityInput(**{**act_input.__dict__,
                           "info_message": f"adversarial review failed (non-fatal): {exc}",
                           "info_level": "warning"}),
                        start_to_close_timeout=timedelta(seconds=10),
                        retry_policy=retry_for("log"),
                    )
                # === GN-only 深度富化（merge 后；non-fatal，spec 2026-08-26 §6.2） ===
                # 对配对后仍 gitnexus-only 的 taint 条目跑多轮 agent 读码富化
                # （title/impact/remediation/dataflow_steps/witness_payload 等
                # 全字段），写回同一 SSOT。常开（档位开关 SUPERNOVA_GN_ENRICH_MODE
                # 已于 2026-08-31 整键移除，deep 行为常开）。
                # 外层 try/except non-fatal（对齐 dataflow view 套路：timeout 等 runtime
                # cancel 是 activity 内 try 抓不到的，须 workflow 兜）。
                try:
                    await workflow.execute_activity(
                        activities.run_gn_finding_enrichment, act_input,
                        start_to_close_timeout=timedelta(minutes=30),
                        retry_policy=retry_for("gitnexus-verdict"),
                    )
                except Exception as exc:
                    if is_cancellation(exc):  # 取消放行（spec 2026-08-28 修 0）：吞掉=幽灵扫描
                        raise
                    # Activity registration drift is an infrastructure/deployment error, not
                    # a degradable enrichment failure.  Do not report a falsely completed
                    # scan when the worker cannot execute a required pipeline step.
                    if _activity_not_registered_hint(exc):
                        raise ApplicationFailure(
                            f"GN finding enrichment activity is not registered: {exc}",
                            type="ActivityNotRegistered",
                            non_retryable=True,
                        ) from exc
                    await workflow.execute_activity(
                        activities.log_info_activity,
                        ActivityInput(**{**act_input.__dict__,
                           "info_message": f"gn finding enrichment failed (non-fatal): {exc}",
                           "info_level": "warning"}),
                        start_to_close_timeout=timedelta(seconds=10),
                        retry_policy=retry_for("log"),
                    )
                # === 全卡接口表富化（GN 富化后；non-fatal，spec 2026-08-26-report-
                # generation-agent §5.2）——两轨全部卡产接口一体表（method/path/params/
                # auth + 路由注册/源/汇行号链），写回 queue 的 report_endpoints；
                # SUPERNOVA_ENDPOINT_ENRICH_ENABLED 关闭时 activity 内部跳过。 ===
                try:
                    await workflow.execute_activity(
                        activities.run_endpoint_enrichment, act_input,
                        start_to_close_timeout=timedelta(minutes=30),
                        retry_policy=retry_for("gitnexus-verdict"),
                    )
                except Exception as exc:
                    if is_cancellation(exc):  # 取消放行（spec 2026-08-28 修 0）
                        raise
                    if _activity_not_registered_hint(exc):
                        raise ApplicationFailure(
                            f"Endpoint enrichment activity is not registered: {exc}",
                            type="ActivityNotRegistered",
                            non_retryable=True,
                        ) from exc
                    await workflow.execute_activity(
                        activities.log_info_activity,
                        ActivityInput(**{**act_input.__dict__,
                           "info_message": f"endpoint enrichment failed (non-fatal): {exc}",
                           "info_level": "warning"}),
                        start_to_close_timeout=timedelta(seconds=10),
                        retry_policy=retry_for("log"),
                    )
                # === P4 数据流视图组装（merge 后；non-fatal 报告增强，失败不阻塞） ===
                # 读 merge 后 SSOT 产物组装 intermediate/dataflow_view.json。activity
                # 内部已吞异常返 skipped，外层 try/except 双保险（对齐 attack-chain 套路；
                # timeout 等 runtime cancel 是 activity 内 try 抓不到的，须 workflow 兜）。
                try:
                    await workflow.execute_activity(
                        activities.run_assemble_dataflow_view, act_input,
                        start_to_close_timeout=timedelta(minutes=2),
                        retry_policy=retry_for("standard"),
                    )
                except Exception as exc:
                    if is_cancellation(exc):  # 取消放行（spec 2026-08-28 修 0）
                        raise
                    await workflow.execute_activity(
                        activities.log_info_activity,
                        ActivityInput(**{**act_input.__dict__,
                           "info_message": f"dataflow view assembly failed (non-fatal): {exc}",
                           "info_level": "warning"}),
                        start_to_close_timeout=timedelta(seconds=10),
                        retry_policy=retry_for("log"),
                    )
                await workflow.execute_activity(
                    activities.log_phase_complete_activity,
                    ActivityInput(**{**act_input.__dict__, "phase": "vulnerability-analysis"}),
                    start_to_close_timeout=timedelta(seconds=10),
                    retry_policy=retry_for("log"),
                )

                # === Attack Chain (dual-track, post-vuln) ===
                # LLM track (run_attack_chain_llm_agent) 跑 attack-chain agent
                # (Write attack_chains_llm_queue.json)；GitNexus track
                # (run_attack_chain_assembly_v2) 组装 GitNexus chains + 合并两轨
                # → attack_chains.json。两步均非 fatal（attack chains 增强报告不阻塞）。
                await workflow.execute_activity(
                    activities.log_phase_start_activity,
                    args=[
                        ActivityInput(**{**act_input.__dict__, "phase": "attack-chain"}),
                        list(step_names("attack-chain")),
                        list(step_intents("attack-chain")),
                    ],
                    start_to_close_timeout=timedelta(seconds=10),
                    retry_policy=retry_for("log"),
                )
                self._state.current_phase = "attack-chain"
                try:
                    await workflow.execute_activity(
                        activities.run_attack_chain_llm_agent, act_input,
                        start_to_close_timeout=timedelta(minutes=30),
                        retry_policy=retry_for("standard"),
                    )
                except Exception as exc:
                    if is_cancellation(exc):  # 取消放行（spec 2026-08-28 修 0）
                        raise
                    # Non-fatal — LLM track 失败时 GitNexus 轨仍可独立产 chains
                    await workflow.execute_activity(
                        activities.log_info_activity,
                        ActivityInput(**{**act_input.__dict__,
                           "info_message": f"Attack chain LLM agent failed (non-fatal, GitNexus-only track continues): {exc}",
                           "info_level": "warning"}),
                        start_to_close_timeout=timedelta(seconds=10),
                        retry_policy=retry_for("log"),
                    )
                try:
                    await workflow.execute_activity(
                        activities.run_attack_chain_assembly_v2, act_input,
                        start_to_close_timeout=timedelta(minutes=5),
                        retry_policy=retry_for("standard"),
                    )
                except Exception as exc:
                    if is_cancellation(exc):  # 取消放行（spec 2026-08-28 修 0）
                        raise
                    # Non-fatal — attack chains 增强报告但不阻塞主流程
                    await workflow.execute_activity(
                        activities.log_info_activity,
                        ActivityInput(**{**act_input.__dict__,
                           "info_message": f"Attack chain assembly v2 failed (non-fatal): {exc}",
                           "info_level": "warning"}),
                        start_to_close_timeout=timedelta(seconds=10),
                        retry_policy=retry_for("log"),
                    )
                await workflow.execute_activity(
                    activities.log_phase_complete_activity,
                    ActivityInput(**{**act_input.__dict__, "phase": "attack-chain"}),
                    start_to_close_timeout=timedelta(seconds=10),
                    retry_policy=retry_for("log"),
                )

                await workflow.execute_activity(
                    activities.log_phase_start_activity,
                    args=[
                        ActivityInput(**{**act_input.__dict__, "phase": "reporting"}),
                        list(step_names("reporting")),
                        list(step_intents("reporting")),
                    ],
                    start_to_close_timeout=timedelta(seconds=10),
                    retry_policy=retry_for("log"),
                )
                self._state.current_phase = "reporting"
                # === §4.2（spec 2026-08-26-vuln-card-seven-sections）POC 写回时序前移 ===
                # 结构化 POC 写回 queue 必须在 render_findings 之前——md 卡要原生渲染
                # POC 节（curl + Burp 双格式），render 时 report_poc 已在 queue 里。
                # 写回失败 non-fatal（md 卡 POC 节缺省），workflow 层兜底对齐
                # generate_poc_report：activity 内 try/except 抓不到 Temporal
                # start_to_close_timeout(runtime cancel 非 Python 异常)，须在此包裹。
                self._state.current_agent = "write-structured-poc"
                try:
                    await workflow.execute_activity(
                        activities.write_agent_poc, act_input,
                        start_to_close_timeout=timedelta(minutes=20),
                        retry_policy=retry_for("poc"),
                    )
                except Exception as exc:  # noqa: BLE001 — POC 写回任何失败只降级（取消除外）
                    if is_cancellation(exc):  # 取消放行（spec 2026-08-28 修 0）——2026-08-28
                        raise  # 幽灵扫描事故点：吞掉 ActivityError(cancelled) 多烧 9 分钟
                    if _activity_not_registered_hint(exc):
                        # 部署不一致（worker 未注册新 activity）非可降级富化失败，
                        # fail-fast 显式暴露（b51eb9a4 教训：静默不跑=md 卡全丢 POC 节）。
                        raise ApplicationFailure(
                            f"Write structured poc activity is not registered: {exc}",
                            type="ActivityNotRegistered",
                            non_retryable=True,
                        ) from exc
                    await workflow.execute_activity(
                        activities.log_info_activity,
                        ActivityInput(**{**act_input.__dict__,
                           "info_message": f"write structured poc failed (non-fatal): {exc}",
                           "info_level": "warning"}),
                        start_to_close_timeout=timedelta(seconds=10),
                        retry_policy=retry_for("log"),
                    )
                finally:
                    self._state.current_agent = None
                # === §3（spec 2026-08-26-report-single-source-rendering）报告段新时序 ===
                # 单源链路：assemble 组装 report_data.json 初版（根交付物）+ 分项
                # findings 单点渲染（render_findings 逻辑并入，不产 md）→ polish
                # 终版（摘要 + QA 七节覆盖率 + 回炉）→ export 从 rd 确定性导出
                # comprehensive md + poc_collection.md。md 链路旧步骤（render_findings /
                # run_agent(report) / verify_report_vuln_blocks / inject_attack_chains /
                # inject_gitnexus_track_status / generate_poc_report）退役（§3.1 清单：
                # md 不再有独立渲染/agent 改写/注入链路——前端与 md 永远同构）。
                self._state.current_agent = "assemble-report"
                await workflow.execute_activity(
                    activities.assemble_report,
                    ActivityInput(**{**act_input.__dict__,
                                     "vuln_classes": [str(vt) for vt in selected_classes]}),
                    start_to_close_timeout=timedelta(minutes=2),
                    retry_policy=retry_for("standard"),
                )
                # === T5：report_data 终版组装（§5.4/§5.5 摘要+QA 七节覆盖率；non-fatal） ===
                # 全部富化（merge/接口表/POC）已写回 queue 后重建 report_data.json，
                # LLM 摘要 + QA 校验 + 回炉。任何失败不阻塞扫描收尾（rd.json 已有
                # assemble 时的初版兜底；export 吃得到初版，md 仍可产出）。
                self._state.current_agent = "report-polish"
                try:
                    await workflow.execute_activity(
                        activities.run_report_polish, act_input,
                        start_to_close_timeout=timedelta(minutes=20),
                        retry_policy=retry_for("standard"),
                    )
                except Exception as exc:  # noqa: BLE001 — rd 初版兜底已落盘（取消除外）
                    if is_cancellation(exc):  # 取消放行（spec 2026-08-28 修 0）
                        raise
                    if _activity_not_registered_hint(exc):
                        raise ApplicationFailure(
                            f"Report polish activity is not registered: {exc}",
                            type="ActivityNotRegistered",
                            non_retryable=True,
                        ) from exc
                    await workflow.execute_activity(
                        activities.log_info_activity,
                        ActivityInput(**{**act_input.__dict__,
                           "info_message": f"report polish failed (non-fatal): {exc}",
                           "info_level": "warning"}),
                        start_to_close_timeout=timedelta(seconds=10),
                        retry_policy=retry_for("log"),
                    )
                finally:
                    self._state.current_agent = None
                # === 接口证据矩阵（spec 2026-09-10 §6；non-fatal 报告增强） ===
                # report_data 终版后聚合：接口级白盒/黑盒两栏证据，落 deliverables
                # 根 api_evidence_matrix.json。黑盒 runs 此时多半未跑（黑盒栏空，
                # 黑盒完成后 web lazy mtime 重建刷新——spec §7）。失败不阻塞收尾。
                self._state.current_agent = "assemble-api-evidence"
                try:
                    await workflow.execute_activity(
                        activities.run_assemble_api_evidence, act_input,
                        start_to_close_timeout=timedelta(minutes=2),
                        retry_policy=retry_for("standard"),
                    )
                except Exception as exc:
                    if is_cancellation(exc):  # 取消放行
                        raise
                    await workflow.execute_activity(
                        activities.log_info_activity,
                        ActivityInput(**{**act_input.__dict__,
                           "info_message": f"api evidence matrix assembly failed (non-fatal): {exc}",
                           "info_level": "warning"}),
                        start_to_close_timeout=timedelta(seconds=10),
                        retry_policy=retry_for("log"),
                    )
                # === §3 export：rd → comprehensive md + poc_collection（含同构校验） ===
                # 确定性纯函数（分钟内）：失败 = 部署问题显式暴露 → fatal（对齐
                # assemble 语义）；同构 mismatch 在 activity 内写 qa.checks 不抛。
                # ActivityNotRegistered fail-fast（b51eb9a4 教训：静默不跑 = 交付物缺）。
                self._state.current_agent = "export-report-markdown"
                try:
                    await workflow.execute_activity(
                        activities.export_report_markdown_files, act_input,
                        start_to_close_timeout=timedelta(minutes=2),
                        retry_policy=retry_for("standard"),
                    )
                except Exception as exc:  # noqa: BLE001 — 重抛（fatal），仅加注册失职的显式面
                    if is_cancellation(exc):  # 取消放行（spec 2026-08-28 修 0）
                        raise
                    if _activity_not_registered_hint(exc):
                        raise ApplicationFailure(
                            f"Export report markdown activity is not registered: {exc}",
                            type="ActivityNotRegistered",
                            non_retryable=True,
                        ) from exc
                    raise
                finally:
                    self._state.current_agent = None
                await workflow.execute_activity(
                    activities.log_phase_complete_activity,
                    ActivityInput(**{**act_input.__dict__, "phase": "reporting"}),
                    start_to_close_timeout=timedelta(seconds=10),
                    retry_policy=retry_for("log"),
                )

                # Set final status based on whether any agents failed
                if self._state.failed_agents:
                    self._state.status = "failed"
                    first_error_msg = self._state.errors[0].split(": ", 1)[-1] if self._state.errors else ""
                    error_type, _ = classify_error_for_temporal(Exception(first_error_msg))
                    self._state.error_code = error_type
                else:
                    self._state.status = "completed"
                # C1 Phase B: worker 路径后置 finalize_summary(写 scan_end + 清 AuditSession) +
                # 停 heartbeat. CLI 路径跳过(外层 run_scan 已 log_workflow_complete).
                if is_worker_path:
                    summary = self._build_finalize_summary(error_fallback=None)
                    await workflow.execute_activity(
                        activities.finalize_summary, args=[act_input, summary],
                        start_to_close_timeout=timedelta(seconds=30),
                        retry_policy=retry_for("standard"),
                    )
                self._state.current_phase = None
                return self._state
            except CancelledError:
                # 不调 finalize_summary/stop_heartbeat 是有意的: cancel 终态写入由 web 侧
                # 负责(scan_manager._mark_cancelled 在 handle.cancel() 后立即写 session.json
                # status=cancelled + scan_end), workflow 此处再调 finalize_summary 会重复写
                # scan_end 致报告混乱 + workflow determinism 风险(except 内 await activity).
                # 心跳 daemon 靠 _session_is_terminal 终态自停(≤1 周期, test_heartbeat.py 覆盖)
                # 兜底, 无需显式 stop. AuditSession 残留由下个 scan 的 setup_display 覆盖.
                self._state.status = "cancelled"
                self._state.current_phase = None
                return self._state
            except Exception as e:
                # 取消类异常按 cancelled 语义收尾（spec 2026-08-28 修 0）：cancel 注入丢失时
                # 取消以 ActivityError(cause=CancelledError) 形态上抛到这——不放行会被标
                # failed（语义失真）。对齐上方 except CancelledError 分支（设 cancelled return）。
                if is_cancellation(e):
                    self._state.status = "cancelled"
                    self._state.current_phase = None
                    return self._state
                # session-status 同步:workflow-level 失败(GitNexus fail-fast ApplicationFailure /
                # activity retry 耗尽 / 任何未捕获异常)→ finalize_summary 写 session.status=failed +
                # scan_end,再 raise 让 Temporal 标 FAILED(web _watch describe 兜底依赖此信号)。
                self._state.status = "failed"
                if not self._state.errors:
                    self._state.errors.append(f"{type(e).__name__}: {e}")
                if is_worker_path:
                    summary = self._build_finalize_summary(error_fallback=str(e))
                    try:
                        await workflow.execute_activity(
                            activities.finalize_summary, args=[act_input, summary],
                            start_to_close_timeout=timedelta(seconds=30),
                            retry_policy=retry_for("standard"),
                        )
                    except Exception:
                        pass  # finalize 自身失败不掩盖原异常;workflow 仍 FAILED,web _watch describe 兜底
                self._state.current_phase = None
                raise
            finally:
                cleanup_settings()
                try:
                    await workflow.execute_activity(
                        activities.cleanup_auth_state_activity,
                        args=[workspace_path],
                        start_to_close_timeout=timedelta(seconds=30),
                        retry_policy=RetryPolicy(maximum_attempts=1),
                    )
                except Exception:
                    pass  # best-effort cleanup，失败不阻断 workflow 收尾

        finally:
            # 尽力释放：cancel/cleanup 异常时由 runner 的闸门 janitor 兜底回收（spec §6）
            await release_gate_slot()

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


# === MR 增量扫描（spec 2026-09-03）===========================================
# 独立 workflow：前置 diff/repo-prepare/删防护判定 activities → 填 mr_meta →
# 调 WhiteboxScanWorkflow.run（child）跑全量主体（消费点消费 mr_meta 做增量收窄）。
# 全量 WhiteboxScanWorkflow 仅加 5 个可选消费点，零回归。

_MR_CHILD_TIMEOUT = timedelta(hours=6)


def _mr_child_input(input: PipelineInput, prepared: dict, diff_result: dict) -> PipelineInput:
    """MrScanWorkflow → child 的 PipelineInput 构造（纯函数，单测锁定穿线语义）。

    mr_meta 摘要：base/head commit（diff_result 优先、repo_prepare 兜底）+
    MR 启发式 vuln 类 + verdict_flow_count=0（child 侧 run_incremental_scope
    后回填实际计数经实例变量供 verdict 窗口重估）。
    """
    child_meta = {
        "base_commit": diff_result.get("base_commit") or prepared.get("base_commit", ""),
        "head_commit": diff_result.get("head_commit") or prepared.get("head_commit", ""),
        "selected_vuln_classes": diff_result.get("selected_vuln_classes", []),
        "verdict_flow_count": 0,
    }
    return PipelineInput(
        repo_path=input.repo_path,
        web_url=input.web_url,
        config_path=input.config_path,
        workspace_name=input.workspace_name,
        deliverables_subdir=input.deliverables_subdir,
        pipeline_testing_mode=input.pipeline_testing_mode,
        api_key=input.api_key,
        prompt_override=input.prompt_override,
        max_concurrent=input.max_concurrent,
        enable_llm_track=input.enable_llm_track,
        event_file=input.event_file,
        provider_config=input.provider_config,
        combined=input.combined,
        env_overrides=input.env_overrides,
        mr_meta=child_meta,
    )


@workflow.defn
class MrScanWorkflow:
    def __init__(self):
        self._state = PipelineState()

    @workflow.run
    async def run(self, input: PipelineInput) -> PipelineState:
        from . import mr_activities

        self._state.start_time = workflow.time_ns() / 1e9
        self._state.current_phase = "mr-setup"
        # worker 路径门控（对齐 WhiteboxScanWorkflow）：event_file 非 None = web 提交，
        # 失败时经 finalize_summary 写 scan_end + session failed；CLI 路径外层收尾。
        is_worker_path = input.event_file is not None
        act_input = ActivityInput(
            repo_path=input.repo_path,
            web_url=input.web_url,
            config_path=input.config_path,
            workspace_name=input.workspace_name,
            deliverables_subdir=input.deliverables_subdir,
            pipeline_testing_mode=input.pipeline_testing_mode,
            api_key=input.api_key,
            prompt_override=input.prompt_override,
            workspace_path=_derive_workspace_path(input),
            event_file=input.event_file,
            provider_config=input.provider_config,
            combined=input.combined,
            env_overrides=input.env_overrides,
            mr_base_ref=input.mr_base_ref,
            mr_head_ref=input.mr_head_ref,
            mr_head_commit=input.mr_head_commit,   # merged 改道（2026-09-04）
            mr_base_commit=input.mr_base_commit,
        )

        # child 启动标志：child 自带 try/except 收尾（其 finalize_summary 已写
        # scan_end），child 阶段的失败不再由 Mr 侧 finalize（防双 scan_end）。
        child_launched = False
        try:
            # 1. repo prepare（fetch→checkout head→merge-base）
            prepared = await workflow.execute_activity(
                mr_activities.run_mr_repo_prepare, act_input,
                start_to_close_timeout=timedelta(minutes=2),
                retry_policy=RetryPolicy(maximum_attempts=1),
            )
            # 2. diff 解析落盘（vuln 类启发式随返）
            diff_result = await workflow.execute_activity(
                mr_activities.run_git_diff, act_input,
                start_to_close_timeout=timedelta(minutes=2),
                retry_policy=retry_for("standard"),
            )
            # 空 diff 快速终态（spec §7）：base==head（stats.files==0）→ 不跑双轨
            # （删防护判定/child 全跳过），finalize 产「无变更」报告即 completed。
            if not (diff_result.get("stats") or {}).get("files"):
                await workflow.execute_activity(
                    mr_activities.run_mr_empty_diff_finalize, act_input,
                    start_to_close_timeout=timedelta(minutes=2),
                    retry_policy=RetryPolicy(maximum_attempts=1),
                )
                # 快速终态也须 finalize 收尾（2026-09-04 研究缺口）：报告产了但
                # 旧版零收尾——web _watch 只认 FAILED 三态，COMPLETED + 无 scan_end
                # = 无限空转（生产 SCAN_TIMEOUT=0 无 deadline）→ 永久占并发槽 +
                # session 幽灵 running。对齐 WhiteboxScanWorkflow 正常路径；finalize
                # 失败自然落入下方 except Exception 收尾链（不吞）。
                if is_worker_path:
                    await workflow.execute_activity(
                        activities.finalize_summary,
                        args=[act_input, {
                            "status": "completed",
                            "total_duration_ms": int(
                                (workflow.time_ns() / 1e9 - self._state.start_time) * 1000),
                            "total_cost_usd": 0.0,
                            "completed_agents": [],
                            "agent_metrics": {},
                            "error": None,
                        }],
                        start_to_close_timeout=timedelta(seconds=30),
                        retry_policy=retry_for("standard"),
                    )
                self._state.status = "completed"
                self._state.current_phase = "mr-empty-diff"
                return self._state
            # 3. diff.patch → 删防护 LLM 判定（降级不阻塞）
            await workflow.execute_activity(
                mr_activities.run_protection_removal_analysis, act_input,
                start_to_close_timeout=timedelta(minutes=10),
                retry_policy=retry_for("standard"),
            )

            # mr_meta 摘要穿给 child：base/head/verdict 候选计数 + MR 启发式 vuln 类
            # （构造收口 _mr_child_input 纯函数——穿线语义单测锁定，workflow 级端到端
            # 由独立脚本验证：pytest WorkflowEnvironment + child workflow 在本机有
            # 预存挂起（CLAUDE.md 测试陷阱，heartbeat 基准同挂），不引入挂起测试。）
            child_input = _mr_child_input(input, prepared, diff_result)

            # 4. child workflow 跑全量主体（MR 消费点在其内生效）
            # 预算对齐（2026-09-16 scan_budget 获槽起算重构）：child 是父预算内
            # 最大的一块——6h 上限 > 父预算（默认 5h）会父先 TIMED_OUT 白跑 child。
            # clamp 到父 run 剩余预算（下限 30min 防负/零）；child 自身过闸门，
            # 获槽后有 CAN 重启给满额预算（排队不限时）。注意父不过闸门，child
            # 的闸门排队时间仍计入父预算（MR 既有语义，批量白盒不走此路径）。
            _parent_rt = workflow.info().run_timeout or _MR_CHILD_TIMEOUT
            _elapsed = timedelta(seconds=workflow.time_ns() / 1e9 - self._state.start_time)
            child_run_timeout = max(min(_MR_CHILD_TIMEOUT, _parent_rt - _elapsed),
                                    timedelta(minutes=30))
            child_launched = True
            child_state = await workflow.execute_child_workflow(
                WhiteboxScanWorkflow.run,
                args=[child_input],
                id=f"{workflow.info().workflow_id}-wb",
                retry_policy=RetryPolicy(maximum_attempts=1),
                run_timeout=child_run_timeout,
            )
            # 泡沫：child 完成了 MR 主流程，返回其 PipelineState（状态/错误沿用）
            self._state.status = child_state.status
            self._state.errors = list(child_state.errors)
            self._state.completed_agents = list(child_state.completed_agents)
            self._state.agent_metrics = dict(child_state.agent_metrics)
            self._state.error_code = child_state.error_code
            self._state.current_phase = None
            return self._state
        except CancelledError:
            # 对齐 WhiteboxScanWorkflow：cancel 终态写入由 web 侧负责
            # （scan_manager._mark_cancelled），此处不调 finalize_summary（防双 scan_end）。
            self._state.status = "cancelled"
            self._state.current_phase = None
            return self._state
        except Exception as e:
            # 取消类异常按 cancelled 语义收尾（cancel 注入丢失时以 ChildWorkflowError
            # 形态上抛——对齐 WhiteboxScanWorkflow 同款分支）。
            if is_cancellation(e):
                self._state.status = "cancelled"
                self._state.current_phase = None
                return self._state
            # session-status 同步（2026-09-04 shorturl MR !99 事故）：前置 activity
            # PentestError（源分支已删除 → git rev-parse 失败等）旧版直接上抛零落盘，
            # 用户等 15s 才见 web _watch 兜底的零信息 "workflow FAILED"。对齐
            # WhiteboxScanWorkflow：finalize_summary 写 scan_end 带真实错误 + session
            # failed，再 raise 让 Temporal 标 FAILED（web describe 兜底依赖此信号）。
            self._state.status = "failed"
            if not self._state.errors:
                self._state.errors.append(f"{type(e).__name__}: {e}")
            if is_worker_path and not child_launched:
                summary = {
                    "status": "failed",
                    "total_duration_ms": int(
                        (workflow.time_ns() / 1e9 - self._state.start_time) * 1000),
                    "total_cost_usd": 0.0,
                    "completed_agents": [],
                    "agent_metrics": {},
                    "error": self._state.errors[0],
                }
                try:
                    await workflow.execute_activity(
                        activities.finalize_summary, args=[act_input, summary],
                        start_to_close_timeout=timedelta(seconds=30),
                        retry_policy=retry_for("standard"),
                    )
                except Exception:
                    pass  # finalize 自身失败不掩盖原异常；workflow 仍 FAILED，web 兜底
            raise
