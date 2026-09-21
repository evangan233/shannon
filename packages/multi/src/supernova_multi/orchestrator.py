from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from supernova_core.models.multi_repo_config import MultiRepoConfig


@dataclass
class RepoScanPlan:
    service: str
    repo_path: str | None
    workspace: str | None
    reuse: bool
    scan_config: str | None


def plan_repo_scans(config: MultiRepoConfig) -> list[RepoScanPlan]:
    """纯函数:决定每个 repo 复用已有 workspace 还是现扫。
    复用条件:声明了 workspace(交付物完整性由编排器后续检查)。
    否则需要 path → 现扫。
    """
    plans: list[RepoScanPlan] = []
    for service, spec in config.repos.items():
        if spec.workspace:
            plans.append(RepoScanPlan(service=service, repo_path=spec.path,
                                      workspace=spec.workspace, reuse=True,
                                      scan_config=spec.scan_config))
        else:
            plans.append(RepoScanPlan(service=service, repo_path=spec.path,
                                      workspace=None, reuse=False,
                                      scan_config=spec.scan_config))
    return plans


# ---------------------------------------------------------------------------
# Task A6: per-edge asyncio + 单边隔离 + merge
# ---------------------------------------------------------------------------
import asyncio  # noqa: E402
import json  # noqa: E402
import logging  # noqa: E402
import os  # noqa: E402
from supernova_core.correlation.schemas import (  # noqa: E402
    CrossServiceTopology, ServiceNode, TopologyEdge, Call, CallSite, TrustBoundary,
)
from supernova_core.correlation.queue_merge import merge_exploitation_queues  # noqa: E402
from supernova_core.correlation.drift import detect_drift  # noqa: E402
from supernova_core.correlation.artifacts_guide import (  # noqa: E402
    ServiceArtifacts, build_artifacts_guide,
)
from supernova_core.correlation.merge_validation import (  # noqa: E402
    assemble_multi_hop_chains, validate_vuln_refs,
)
from supernova_core.correlation.adjudication import (  # noqa: E402
    build_adjudication_batches, split_dismissed_by_service,
)
from supernova_core.utils.paths import (  # noqa: E402
    INTERMEDIATE_SUBDIR, WHITEBOX_SUBDIR, resolve_track_deliverable,
)
from supernova_core.runtime.heartbeat import HeartbeatManager, mark_owner_if_unset  # noqa: E402

logger = logging.getLogger(__name__)


def _prompts_dir() -> Path:
    """Absolute prompts dir, independent of process CWD.

    orchestrator.py is at <repo>/packages/multi/src/supernova_multi/orchestrator.py,
    so parents[4] is the repo root that holds prompts/.
    (final-review IMPORTANT 1: 避免非 repo-root CWD 调用时 Prompt file not found 崩溃)
    """
    return Path(__file__).resolve().parents[4] / "prompts"


async def _run_edge(from_svc: str, to_svc: str, *, runner) -> dict:
    """单条 edge 推断。runner 是 async(f,t)->dict(真实=AgentExecutor 调用)。
    失败 → 标 status=error,不抛(spec §8 单边隔离)。"""
    try:
        return await runner(from_svc, to_svc)
    except Exception as e:  # noqa: BLE001
        return {"from": from_svc, "to": to_svc, "protocol": "grpc",
                "calls": [], "status": "error", "error": str(e), "boundaries": []}


def _merge_edge_results(edge_results: list[dict]) -> dict:
    edges, boundaries = [], []
    for r in edge_results:
        # A2 flows 透传:per-edge 候选攻击链原样并进 edges(旧 prompt 无 flows 也合法)
        edges.append({"from": r["from"], "to": r["to"], "protocol": r.get("protocol", "grpc"),
                      "calls": r.get("calls", []), "status": r.get("status", "ok"),
                      "error": r.get("error"), "flows": r.get("flows", [])})
        boundaries.extend(r.get("boundaries", []))
    return {"edges": edges, "boundaries": boundaries}


async def run_correlation_phase(
    config: MultiRepoConfig,
    repo_workspace_paths: dict[str, Path],
    out_ws_dir: Path,
    event_file: Path,
    *,
    pipeline_testing: bool = False,
    provider_config: dict | None = None,
    write_scan_end: bool = True,
) -> dict:
    """关联段(原 run_cross_repo 第 2 步起,A3 拆出):收集各仓 queue → 关联 workspace
    → per-edge Agent → 合并落盘。

    repo_workspace_paths / out_ws_dir / event_file 全显式注入,web 编排可直接复用
    (run_cross_repo 传 CLI 等价值,行为不变);write_scan_end=False 时不写 scan_end
    事件(web 编排收尾用),heartbeat 两分支都照常进/出。provider_config 为 per-scan
    provider 穿线(CLI 不传 = None,与拆分前一致)。

    返回 ``{"edge_statuses": [...], "deliverables_path": str}``。
    """
    from supernova_core.session import SessionManager
    from supernova_core.utils.paths import deliverables_dir_for_workspace
    from supernova_core.agents.executor import AgentExecutor
    from supernova_core.prompts.manager import PromptManager
    from supernova_core.models.agents import AgentName
    from supernova_core.correlation.schemas import CrossServiceFlow
    from supernova_core.correlation.report import write_correlation_deliverables
    from supernova_multi.correlation_event_writer import CorrelationEventWriter, EdgeAgentEventLogger

    corr_writer = CorrelationEventWriter(event_file)

    # 1. 收集各仓 exploitation queue(spec §7 合并, B1)—— 由 repo_workspace_paths 驱动。
    #    spec 2026-08-27:顺手探测 entry_points/dismissed 产物建 ServiceArtifacts
    #    (artifacts-guide 素材) + 阶段 B 批组织输入 + vuln_id 校验集。
    per_repo_queue: dict[str, list[dict]] = {}
    findings_by_service: dict[str, dict[str, list[dict]]] = {}
    dismissed_by_service: dict[str, list[dict]] = {}
    artifacts_by_service: dict[str, ServiceArtifacts] = {}
    per_service_id_sets: dict[str, set[str]] = {}
    drift_warnings: list[str] = []
    for service, ws_path in repo_workspace_paths.items():
        dlv = deliverables_dir_for_workspace(ws_path)
        spec = config.repos.get(service)
        # A2 版本漂移检测(时间戳粗判,仅复用 —— spec.workspace 声明,等价 plan_repo_scans
        # 的 reuse 判定 —— 且 repo path 已知且盘上存在时)。
        # final-review MINOR 5: 复用 workspace 的 path 可能已失配/移动,
        # getmtime 会 FileNotFoundError 并中止整个编排 —— 加 Path.exists() 守卫优雅降级(跳过漂移检测)。
        if (spec and spec.workspace and spec.path
                and (ws_path / "session.json").exists() and Path(spec.path).exists()):
            sess = json.loads((ws_path / "session.json").read_text(encoding="utf-8"))
            rpt = detect_drift(sess.get("created_at", 0.0), os.path.getmtime(spec.path))
            if rpt.drifted:
                drift_warnings.append(f"{service}: {rpt.note}")
        # 白盒 queue 新结构在 whitebox/intermediate/(tiering spec 2026-08-18),
        # 老结构在 whitebox/ 顶层或 deliverables 根;glob 不递归,三处合并去重
        # (intermediate 优先,同名仅补白)。
        queue_files: dict[str, Path] = {}
        for q in (dlv / WHITEBOX_SUBDIR / INTERMEDIATE_SUBDIR).glob("*_exploitation_queue.json"):
            queue_files[q.name] = q
        for q in (dlv / WHITEBOX_SUBDIR).glob("*_exploitation_queue.json"):
            queue_files.setdefault(q.name, q)
        for q in dlv.glob("*_exploitation_queue.json"):
            queue_files.setdefault(q.name, q)
        for q in queue_files.values():
            vc = q.stem.replace("_exploitation_queue", "")
            try:
                entries = json.loads(q.read_text(encoding="utf-8")).get("vulnerabilities", [])
            except (json.JSONDecodeError, OSError) as e:
                # final-review MINOR 6: 仅捕解析/IO 错并留痕,不再静默吞所有异常。
                logger.warning("跳过损坏的 exploitation queue %s: %s", q, e)
                entries = []
            per_repo_queue.setdefault(vc, []).extend(
                [{"__service": service, **e} for e in entries])
            findings_by_service.setdefault(service, {}).setdefault(vc, []).extend(entries)
            per_service_id_sets.setdefault(service, set()).update(
                e.get("ID") for e in entries
                if isinstance(e, dict) and e.get("ID"))
        # entry_points / dismissed 探测(读侧三级回落链,与 queue 同源)
        ep_path = resolve_track_deliverable(dlv, WHITEBOX_SUBDIR, "entry_points.json")
        dm_path = resolve_track_deliverable(dlv, WHITEBOX_SUBDIR, "dismissed_findings.json")
        dm_entries: list[dict] = []
        if dm_path.exists():
            try:
                data = json.loads(dm_path.read_text(encoding="utf-8"))
                dm_entries = data.get("dismissed", []) if isinstance(data, dict) else []
            except (json.JSONDecodeError, OSError) as e:
                logger.warning("跳过损坏的 dismissed 档案 %s: %s", dm_path, e)
        dismissed_by_service[service] = dm_entries
        artifacts_by_service[service] = ServiceArtifacts(
            service=service, role=spec.role if spec else "backend",
            roles=sorted(spec.effective_roles) if spec else ["backend"],
            repo_path=spec.path if spec else None, deliverables=dlv,
            queue_files=list(queue_files.values()),
            entry_points=ep_path if ep_path.exists() else None,
            dismissed=dm_path if (dm_path.exists() and dm_entries) else None,
            proto_roots=list(spec.proto_roots) if spec else [])

    # 2. 关联 workspace —— 无归属 repo,SessionManager(out_ws_dir.parent) 幂等
    # (目录已存在不报错;web 已建主行不覆盖 session.json;CLI 传入
    # resolve_workspaces_dir()/out_workspace 与原 resolve_workspaces_dir() 根等价)。
    mgr = SessionManager(out_ws_dir.parent)
    out_ws = mgr.create_workspace(web_url="", repo_path="",
                                  name=out_ws_dir.name,
                                  scan_type="correlation")
    out_dlv = deliverables_dir_for_workspace(out_ws)
    mark_owner_if_unset(out_ws, "host")  # CLI 起 owner=host(web 起 scan_manager 已写 web)
    # 进程级心跳 + 协作式取消(multi 无 ShutdownController:on_cancel 取消本协程主 task,
    # 让 gather/await 抛 CancelledError 退出;异常/取消路径靠进程退出 + heartbeat stale 兜底,
    # 正常路径 return 前 __aexit__ 清理)。spec §4.5/§8。
    main_task = asyncio.current_task()
    heartbeat = HeartbeatManager(out_ws, on_cancel=main_task.cancel)
    await heartbeat.__aenter__()

    # temporalio failure traceback 重定向到本会话目录（2026-09-11 日志串台修复）：
    # 常驻 worker 单进程跑 wb/bb/corr 多 queue，corr activity 的崩溃 traceback 此前
    # 被 wb 会话的最后安装重定向抢走（NodeGoat-20260910-193720 目录躺 corr 崩溃
    # 实证）。共享 routing handler 按 record 内 workflow_id 路由；activity 上下文
    # 外（测试/CLI 直跑）workflow_id=None → 注册为 fallback。best-effort 不炸扫描。
    try:
        from supernova_core.logging.temporalio_redirect import (
            current_temporal_workflow_id, install_temporalio_log_redirect,
        )
        install_temporalio_log_redirect(
            out_ws / "activity_failures.log",
            workflow_id=current_temporal_workflow_id())
    except Exception:  # noqa: BLE001 - logging 故障不上行成扫描故障
        logger.warning("corr temporalio redirect install failed", exc_info=True)

    # 3. per-edge 关联 Agent(asyncio.Semaphore 限并发, B5)
    role_map = {
        service: sorted(spec.effective_roles, key=("entrypoint", "backend").index)
        for service, spec in config.repos.items()
    }
    primary_role = {service: spec.role for service, spec in config.repos.items()}

    repo_paths = {s: spec.path for s, spec in config.repos.items()}
    # final-review MINOR 8: 并发上限改接 SUPERNOVA_MAX_CONCURRENT(whitebox/blackbox 同源 env 驱动,
    # 默认 3),闭合 spec B5 风险登记 TODO。
    from supernova_core.config.concurrency import get_max_concurrent
    sem = asyncio.Semaphore(get_max_concurrent())
    # final-review IMPORTANT 1+2: PromptManager 用绝对路径(_prompts_dir() 不受 CWD 影响),
    # 且单实例提升到本函数作用域 —— N 条 edge 不再重复构造 executor / 重编译 prompt。
    executor = AgentExecutor(PromptManager(_prompts_dir()))
    edge_output_schema = {
        "type": "object",
        "properties": {
            "from": {"type": "string"}, "to": {"type": "string"},
            "protocol": {"type": "string"}, "status": {"type": "string"},
            "calls": {"type": "array"},
            # boundaries item 收紧（2026-09-11 cross-repo attempt1 崩溃回归，双防线的
            # 生产端）：6 字段 required——openai 引擎 structured outputs 对嵌套 required
            # 有强制力（漏字段在引擎侧被拒），claude 引擎无害；契约对齐
            # cross-repo-correlation.txt:57-59。消费端容错见 :310 附近 from_dict。
            "boundaries": {"type": "array", "items": {
                "type": "object",
                "properties": {
                    "service": {"type": "string"},
                    "method": {"type": "string"},
                    "exposure": {"type": "string"},
                    "reachable_from": {"type": "array",
                                       "items": {"type": "string"}},
                    "reason": {"type": "string"},
                    "confidence": {"type": "string"},
                },
                "required": ["service", "method", "exposure",
                             "reachable_from", "reason", "confidence"],
                "additionalProperties": True,   # LLM 多吐键容忍（消费端白名单过滤）
            }},
            "flows": {"type": "array"},  # A2 per-edge 候选攻击链(不入 required:旧 prompt 无 flows 也合法)
        },
        "required": ["from", "to", "status"],
    }

    async def edge_runner(f: str, t: str) -> dict:
        async with sem:
            prompt_vars = {
                "relations_json": json.dumps({"from": f, "to": t,
                    "protocol": next((r.protocol for r in config.relations
                                      if r.from_ == f and r.to == t), "grpc")}),
                "role_map": json.dumps(role_map),
                "repo_paths": json.dumps({f: repo_paths.get(f), t: repo_paths.get(t)}),
                "deliverables_path": str(out_dlv),
                # spec 2026-08-27 §5.1:产物目录导读(修 P1——不再让 Agent 读空的
                # 关联 out_dlv,引导读两仓真实扫描产物)
                "artifacts_guide": build_artifacts_guide(
                    artifacts_by_service.get(f) or ServiceArtifacts(
                        service=f, role=primary_role.get(f, "backend"), roles=role_map.get(f, ["backend"]),
                        repo_path=repo_paths.get(f), deliverables=None),
                    artifacts_by_service.get(t) or ServiceArtifacts(
                        service=t, role=primary_role.get(t, "backend"), roles=role_map.get(t, ["backend"]),
                        repo_path=repo_paths.get(t), deliverables=None)),
            }
            # edge agent 细粒度事件落盘（2026-09-10 live tab）：tool_audit_logger 钩子
            # 转 AgentEvent/ToolCallEvent/LlmTurnEvent（标准形状,前端零改动渲染），
            # start/end 手动包裹（end 拆 AgentMetrics 计量字段）。
            edge_logger = EdgeAgentEventLogger(corr_writer, f"edge:{f}→{t}")
            await edge_logger.agent_start()
            try:
                metrics = await executor.execute(
                    agent_name=AgentName.CROSS_REPO_CORRELATION,
                    repo_path=str(out_ws),  # 注:非 git repo,但 git ops 全在 deliverables(见 Task A6 风险 #1)
                    deliverables_path=str(out_dlv),
                    pipeline_testing=pipeline_testing,
                    prompt_variables=prompt_vars,
                    structured_output_schema=edge_output_schema,  # 强制单 edge JSON 输出
                    provider_config=provider_config,  # A3: per-scan provider 穿线(web 编排;CLI 恒 None)
                    tool_audit_logger=edge_logger,
                )
            except Exception as e:
                await edge_logger.agent_end(success=False, error=str(e))
                raise  # 交回 _run_edge 既有单边隔离（status=error）
            await edge_logger.agent_end(
                duration_ms=getattr(metrics, "duration_ms", None),
                cost_usd=getattr(metrics, "cost_usd", None),
                cost_currency=getattr(metrics, "cost_currency", None),
                input_tokens=getattr(metrics, "input_tokens", None),
                output_tokens=getattr(metrics, "output_tokens", None))
            # A6 风险 #3:AgentMetrics 真实属性是 structured_output(非 brief 的 output)。
            # 取不到合法 payload 则降级 unverified(spec §8 per-edge 隔离)。
            payload = getattr(metrics, "structured_output", None)
            if isinstance(payload, dict) and "from" in payload:
                return payload
            return {"from": f, "to": t, "protocol": "grpc", "calls": [],
                    "status": "unverified", "boundaries": []}

    edge_pairs = [(r.from_, r.to) for r in config.relations]
    await corr_writer.phase("correlation", "started")
    edge_results = await asyncio.gather(
        *[_run_edge(f, t, runner=edge_runner) for f, t in edge_pairs])
    # per-edge 进度（_run_edge 已把异常映射为 status=error,spec §8 单边隔离,不致 scan 失败）
    for er in edge_results:
        await corr_writer.edge(f"{er['from']}->{er['to']}", er.get("status", "ok"))
    merged = _merge_edge_results(edge_results)
    # spec 2026-08-27 §6:确定性校验(幻觉 vuln_id 标 invalid_ref) + 多跳边邻接
    # 拼装 —— 零推断,纯防幻觉与结构性拼装。
    validated_edges = validate_vuln_refs(merged["edges"], per_service_id_sets)
    multi_hop_chains = assemble_multi_hop_chains(validated_edges)

    # 4. 组装 topology + boundaries
    topology = CrossServiceTopology(
        services=[ServiceNode(
                      name=s, role=spec.role,
                      roles=sorted(spec.effective_roles, key=("entrypoint", "backend").index),
                      repo=spec.path or spec.workspace or "")
                  for s, spec in config.repos.items()],
        edges=[TopologyEdge(from_=e["from"], to=e["to"], protocol=e["protocol"],
                            calls=[Call(method=c["method"],
                                        call_site=CallSite(**c["call_site"]),
                                        confidence=c["confidence"], evidence=c["evidence"])
                                   for c in e.get("calls", [])],
                            status=e["status"], error=e.get("error"))
               for e in validated_edges])
    # 容错反序列化（2026-09-11 cross-repo attempt1 崩溃回归）：LLM 偶发漏字段不再
    # TypeError 炸整单（曾致 5 edge agent 整段无检查点重烧）。缺可选字段补默认保留
    # 条目；核心字段缺丢弃；两路均落 events.ndjson warning（可观测，不留到构造点炸）。
    boundaries: list[TrustBoundary] = []
    for b in merged["boundaries"]:
        tb = TrustBoundary.from_dict(b)
        if tb is None:
            await corr_writer.raw({
                "category": "WARNING", "type": "LogEvent", "level": "WARNING",
                "message": "boundary dropped (missing core field "
                           "service/method/exposure): "
                           + json.dumps(b, ensure_ascii=False, default=str)[:200],
            })
            continue
        if not b.get("reachable_from"):
            await corr_writer.raw({
                "category": "WARNING", "type": "LogEvent", "level": "WARNING",
                "message": f"boundary {tb.service} {tb.method} missing "
                           "reachable_from; defaulted to [] (source undetermined)",
            })
        boundaries.append(tb)

    # 5. 合并 queue(B1 四字段)+ 组装 flows(A2 透传)+ 落盘
    merged_queues = {vc: merge_exploitation_queues(
        _group_by_service(entries)) for vc, entries in per_repo_queue.items()}
    flows = [CrossServiceFlow(edge_from=e["from"], edge_to=e["to"],
                              entry=f["entry"], method=f["method"],
                              call_site=CallSite(**f["call_site"]),
                              vuln_refs=f.get("vuln_refs", []),
                              confidence=f.get("confidence", "low"),
                              evidence=f.get("evidence", ""))
             for e in validated_edges for f in e.get("flows", [])]
    report_md = _render_report(topology, boundaries, merged_queues, drift_warnings)
    write_correlation_deliverables(out_dlv, topology, boundaries, merged_queues,
                                   report_md, flows=flows,
                                   multi_hop_chains=multi_hop_chains,
                                   drift_warnings=drift_warnings)

    # 6. 阶段 B 跨仓裁决(spec §7)——发现驱动,跑在阶段 A 产物落盘之后。
    #    批级容错在 run_adjudication_phase 内(error 占位卡);此处整体异常
    #    隔离:阶段 A 产物照常交付,scan 终态不受影响(spec §10)。
    adjudication_cards: list[dict] = []
    skipped_dismissed: list[dict] = []
    try:
        # 批大小可调（SUPERNOVA_ADJUDICATION_BATCH_LIMIT，默认 15）：更小的批 ×
        # 批间并发（run_adjudication_phase 内部，独立 env 上限）→ 单批 prompt 更小、
        # 总时长成倍缩短（2026-09-20 cross-repo 串行大批排队的结构性优化）。
        try:
            batch_limit = max(1, int(os.getenv("SUPERNOVA_ADJUDICATION_BATCH_LIMIT", "15")))
        except ValueError:
            batch_limit = 15
        # 防护类否决分桶（spec 2026-09-21 §3.3）：dismiss_reason 为 sink 处防护
        # （参数化/脱敏/转义…）的条目与调用方无关，跨仓视角翻不了——不进批不占
        # 预算，留痕落 adjudication-log.json（可人工复核分类错杀）。env 可关。
        if os.getenv("SUPERNOVA_ADJUDICATION_SKIP_DEFENSIVE", "1") != "0":
            dismissed_by_service, skipped_dismissed = split_dismissed_by_service(
                dismissed_by_service)
        batches = build_adjudication_batches(findings_by_service,
                                             dismissed_by_service,
                                             batch_limit=batch_limit)
        if batches:
            await corr_writer.phase("adjudication", "started")
            from supernova_multi.adjudication_phase import run_adjudication_phase
            adjudication_cards = await run_adjudication_phase(
                batches=batches,
                artifacts_by_service=artifacts_by_service,
                correlation_context={
                    # edges 带 calls 明细（2026-09-21：此前只给 from/to/protocol/status，
                    # 裁决 agent 看不到 RPC 调用点，重构 exploit_path 只能重查源码；
                    # 精简版不带 snippet/evidence 大字段，细节按 artifacts_guide 自查）
                    "edges": [{"from": e["from"], "to": e["to"],
                               "protocol": e.get("protocol", "grpc"),
                               "status": e.get("status", "ok"),
                               "calls": [{"method": c.get("method", ""),
                                          "call_site": f"{c.get('call_site', {}).get('file', '')}:"
                                                       f"{c.get('call_site', {}).get('line', '')}",
                                          "confidence": c.get("confidence", "")}
                                         for c in (e.get("calls") or [])]}
                              for e in validated_edges],
                    "flows": [f for e in validated_edges
                              for f in e.get("flows", [])],
                    "multi_hop_chains": multi_hop_chains,
                    # 入站调用面（spec 2026-09-21 §3.1）：按 to 服务聚合"谁调用本
                    # 服务哪些 RPC 方法 + 哪些入口路由可达"。dismissed 批的翻案原料
                    # ——此前 agent 只能查只覆盖已报漏洞链的 flows 判可达性
                    # （循环论证，0/143 翻案的结构性根因）。
                    "inbound_surface": _build_inbound_surface(
                        validated_edges, boundaries, artifacts_by_service)},
                executor=executor,
                # sem 不传：adjudication 批是大 prompt，独立并发上限
                # （SUPERNOVA_ADJUDICATION_MAX_CONCURRENT，默认 3），不随
                # edge agents 的 SUPERNOVA_MAX_CONCURRENT 池放大限流风险。
                repo_path=str(out_ws), deliverables_path=str(out_dlv),
                pipeline_testing=pipeline_testing,
                provider_config=provider_config,
                corr_writer=corr_writer)
            await corr_writer.phase("adjudication", "completed")
    except Exception as e:  # noqa: BLE001 —— 阶段 B 整体异常:留痕不阻断
        logger.warning("adjudication phase failed (phase A deliverables kept): %s", e)
        await corr_writer.phase("adjudication", "failed")
        (out_dlv / "adjudication-log.json").write_text(
            json.dumps({"error": str(e),
                        "skipped_dismissed": skipped_dismissed},
                       ensure_ascii=False), encoding="utf-8")
    if adjudication_cards or skipped_dismissed:
        from supernova_core.correlation.report import write_adjudication_deliverables
        report_md = _render_report(topology, boundaries, merged_queues,
                                   drift_warnings, cards=adjudication_cards,
                                   skipped_dismissed=skipped_dismissed)
        write_adjudication_deliverables(out_dlv, adjudication_cards, report_md,
                                        skipped_dismissed=skipped_dismissed)

    # 扫描失败不上探到本函数(现扫异常在 run_cross_repo 已 raise),scan_end 恒 completed;
    # write_scan_end=False 时收尾事件交由调用方写(web 编排收尾)。heartbeat 两分支都清理。
    if write_scan_end:
        await corr_writer.scan_end("completed")
    await heartbeat.__aexit__(None, None, None)

    return {"edge_statuses": [e["status"] for e in merged["edges"]],
            "deliverables_path": str(out_dlv)}


async def run_cross_repo(config_path: Path, temporal_address: str, *, pipeline_testing: bool = False) -> dict:
    from supernova_core.config.parser import parse_multi_repo_config
    from supernova_whitebox.worker import run_scan as run_whitebox
    from supernova_whitebox.pipeline.shared import PipelineInput

    config = parse_multi_repo_config(config_path)
    plans = plan_repo_scans(config)
    # workspace 根必须与 run_whitebox 写入根一致(run_whitebox 用 resolve_workspaces_dir(repo_path)),
    # 否则 SUPERNOVA_WORKER_ROOT 或 cwd≠project-root 时读取会落空(A6 review Important #1)。
    from supernova_core.utils.paths import resolve_workspaces_dir
    from supernova_multi.correlation_event_writer import CorrelationEventWriter

    # 联动进度 writer：在 repo 扫描开始前就绪，events.ndjson 路径与下方
    # run_correlation_phase 的 out_ws_dir 同根同目录（同一文件,两 writer 追加写）。
    corr_writer = CorrelationEventWriter(
        resolve_workspaces_dir() / config.correlation.out_workspace / "events.ndjson")

    # 1. N repo 白盒:复用 or 现扫(queue 收集已移入 run_correlation_phase,
    #    由 repo_workspace_paths 驱动;此处只产出各仓 workspace 目录)
    repo_workspace_paths: dict[str, Path] = {}
    for p in plans:
        # 每个 repo 的 workspace 都从其写入根(resolve_workspaces_dir(repo_path))读取,
        # 与 run_whitebox 的 resolve_workspaces_dir(input.repo_path) 对齐。
        repo_ws_root = resolve_workspaces_dir(p.repo_path)
        if p.reuse:
            await corr_writer.repo(p.service, "started")
            ws_path = repo_ws_root / p.workspace
            await corr_writer.repo(p.service, "completed", detail="reused")
        else:
            await corr_writer.repo(p.service, "started")
            wb_input = PipelineInput(repo_path=p.repo_path, workspace_name=p.workspace,
                                     config_path=p.scan_config,
                                     pipeline_testing_mode=pipeline_testing)
            try:
                result = await run_whitebox(wb_input, temporal_address)
            except Exception:
                # 现扫失败:repo failed 事件留痕后原样上抛(scan_end 不写,靠进程退出 +
                # heartbeat stale 兜底 —— 与拆分前一致,overall_failed 从不可达至此)。
                await corr_writer.repo(p.service, "failed", detail="scan error")
                raise
            ws_path = repo_ws_root / result["workspace_name"]
            await corr_writer.repo(p.service, "completed")
        repo_workspace_paths[p.service] = ws_path

    # 2. 关联段:CLI 等价原行为(write_scan_end=True 收尾事件仍由 phase 写)。
    out_ws_dir = resolve_workspaces_dir() / config.correlation.out_workspace
    phase_result = await run_correlation_phase(
        config,
        repo_workspace_paths,
        out_ws_dir,
        out_ws_dir / "events.ndjson",
        pipeline_testing=pipeline_testing,
        write_scan_end=True,
    )
    return {**phase_result, "out_workspace": config.correlation.out_workspace}


def _group_by_service(entries: list[dict]) -> dict[str, list[dict]]:
    g: dict[str, list[dict]] = {}
    for e in entries:
        svc = e.pop("__service", "unknown")
        g.setdefault(svc, []).append(e)
    return g


def _build_inbound_surface(validated_edges: list[dict], boundaries: list,
                           artifacts_by_service: dict) -> dict:
    """按 to 服务聚合"入站调用面"（spec 2026-09-21 §3.1）——dismissed 批的翻案原料。

    - inbound_calls：谁调用本服务的哪些 RPC 方法、调用点在哪（边 calls）；
    - reachable_entries：这些方法哪些从入口路由可达（边界 reachable_from，
      阶段 A edge agent 已打通"入口 HTTP 路由 → RPC 方法"映射）；
    - entry_points_ref：本仓 entry_points.json 路径（agent 自查暴露面的指路）。

    纯数据搬运、零推断：数据全部来自阶段 A 既有产物。此前这些数据不进裁决
    context，agent 判 dismissed 可达性只能查只覆盖已报漏洞链的 flows——
    循环论证、0/143 翻案的结构性根因（2026-09-20 cross-repo-20260920-092147 实测）。
    """
    surface: dict[str, dict] = {}

    def _slot(svc: str) -> dict:
        return surface.setdefault(svc, {"inbound_calls": [],
                                        "reachable_entries": []})

    for e in validated_edges:
        for c in (e.get("calls") or []):
            method = c.get("method") or ""
            if not method:
                continue
            cs = c.get("call_site") or {}
            _slot(e["to"])["inbound_calls"].append({
                "from_service": e["from"],
                "rpc_method": method,
                "call_site": f"{cs.get('file', '')}:{cs.get('line', '')}"})
    for b in boundaries:
        if not b.method:
            continue
        _slot(b.service)["reachable_entries"].append({
            "rpc_method": b.method,
            "exposure": b.exposure,
            "via": list(b.reachable_from or [])})
    for svc, art in artifacts_by_service.items():
        if art.entry_points:
            _slot(svc)["entry_points_ref"] = str(art.entry_points)
    return surface


def _render_report(topology, boundaries, merged_queues, drift_warnings,
                   cards: list[dict] | None = None,
                   skipped_dismissed: list[dict] | None = None) -> str:
    # 章节序（2026-09-21 目录优化）：结论区（统计→成立→消掉→失败占位）在前，
    # 背景区（拓扑→边界）垫底——读者从结论读起不必滚过背景。
    lines = ["# 跨仓关联扫描报告", ""]
    if cards:
        lines += _render_verdict_stats(merged_queues, cards)
    if drift_warnings:
        # 漂移警告 = 结论数字可信度的注脚（复用产物可能过时），紧跟统计
        lines += ["## 版本漂移警告", ""]
        lines += [f"- {w}" for w in drift_warnings] + [""]
    if cards:
        # 结论优先章节（2026-09-20 口径对齐结果页；09-21 加速览表）：per-vuln
        # 结论统计 + 成立漏洞全文 + 消掉/存疑清单——人工复核直接从结论读起。
        classified = _classify_merged_verdicts(merged_queues, cards)
        lines += _render_confirmed_vulns(classified, _dismissed_upgrade_cards(cards))
        lines += _render_refuted_list(classified)
        # 裁决失败占位（故障信号必见）单独留档；其余全量裁决卡不再进报告——
        # 确认卡已融入成立全文、消掉论证已在清单 reasoning、维持是纯噪音
        # （2026-09-21 精简），机器留档由 adjudication-log.json 承担。
        error_cards = [c for c in cards if c.get("direction") == "error"]
        if error_cards:
            lines += ["", "## 裁决失败(占位留档)", ""]
            for c in error_cards:
                ref = c.get("finding_ref", {})
                lines.append(f"- [{ref.get('vuln_id', '?')}] {ref.get('service', '?')}"
                             f"({ref.get('origin', '?')}) — {c.get('reasoning', '')}")
            lines.append("")
    else:
        # cards=[] 且 skipped 非空（全部防护类跳过）≠ 进行中——只有 None（阶段 B
        # 未跑/未回）才是"进行中"。
        if cards is None:
            lines += ["## 跨仓裁决", "",
                      "- 裁决阶段进行中，完成后本报告将补充跨仓结论章节。", ""]
    if skipped_dismissed:
        # 防护类否决留痕说明（spec 2026-09-21 §3.3）：跳过必须可审计。
        lines += ["", "## 防护类否决(未进跨仓审查)", "",
                  f"- 共 {len(skipped_dismissed)} 条防护类否决未占用跨仓审查预算"
                  "（sink 处防护与调用方无关，跨仓视角不可翻案）；"
                  "明细见 adjudication-log.json 的 skipped_dismissed 段。", ""]
    # ── 背景区（垫底）──
    lines += ["## 服务拓扑", ""]
    for e in topology.edges:
        lines.append(f"- {e.from_} → {e.to} ({e.protocol}) [{e.status}]")
    # 未验证/低置信边（透明单列）——空则不输出标题
    bad_edges = [e for e in topology.edges
                 if e.status in ("low", "unverified", "error", "declared-missing")]
    if bad_edges:
        lines += ["", "### 未验证/低置信/失败项", ""]
        for e in bad_edges:
            lines.append(f"- {e.from_}→{e.to}: {e.status} {e.error or ''}")
    # 信任边界附录（2026-09-21 页面撤章后信息落位：结果页不再渲染，导出物保留）
    if boundaries:
        lines += ["", "## 信任边界", ""]
        for b in boundaries:
            reach = ", ".join(b.reachable_from) or "—"
            lines.append(f"- {b.service} · {b.method}（{b.confidence}）— "
                         f"{b.exposure}，可达来源: {reach} · {b.reason}")
    return "\n".join(lines)


def _classify_merged_verdicts(
    merged_queues: dict[str, list[dict]], cards: list[dict],
) -> dict[str, list[tuple[dict, dict | None]]]:
    """合并漏洞 × 裁决卡 per-vuln 四分类——与前端 correlation-verdict.ts 同口径
    （2026-09-20 报告口径对齐：报告数字必须等于结果页数字）。

    卡索引按 (service, vuln_id) last-wins（同前端 Map 行为，重复卡后写覆盖）；
    归类只认 origin=queue 的卡：confirm→成立、downgrade→消掉、
    conclusion=needs-review 或 queue 卡异常方向（upgrade/maintain/error）→存疑、
    无卡（或键命中 dismissed 卡）→未重审。
    返回 {组: [(漏洞条目, 裁决卡|None)]}，组内保持合并序。
    """
    idx: dict[tuple[str, str], dict] = {}
    for c in cards:
        ref = c.get("finding_ref", {})
        svc, vid = ref.get("service"), ref.get("vuln_id")
        if isinstance(svc, str) and isinstance(vid, str) and vid:
            idx[(svc, vid)] = c

    def group_of(entry: dict) -> tuple[str, dict | None]:
        card = idx.get((entry.get("service"), entry.get("ID")))
        if card is None or card.get("finding_ref", {}).get("origin") != "queue":
            return "unadjudicated", None
        if card.get("conclusion") == "needs-review":
            return "uncertain", card
        direction = card.get("direction")
        if direction == "confirm":
            return "confirmed", card
        if direction == "downgrade":
            return "refuted", card
        return "uncertain", card  # upgrade/maintain/error 等 queue 批异常方向

    out: dict[str, list[tuple[dict, dict | None]]] = {
        "confirmed": [], "refuted": [], "uncertain": [], "unadjudicated": []}
    for entries in merged_queues.values():
        for e in entries:
            if not (isinstance(e, dict) and e.get("ID")):
                continue
            group, card = group_of(e)
            out[group].append((e, card))
    return out


def _dismissed_upgrade_cards(cards: list[dict]) -> list[dict]:
    """翻案卡：origin=dismissed 且 direction=upgrade（单仓判非漏洞、跨仓认为可达成立）。"""
    return [c for c in cards
            if c.get("direction") == "upgrade"
            and c.get("finding_ref", {}).get("origin") == "dismissed"]


def _render_verdict_stats(merged_queues: dict[str, list[dict]], cards: list[dict]) -> list[str]:
    """结论统计头：per-vuln 口径（与结果页一致）+ 单仓已否决复核一行。"""
    classified = _classify_merged_verdicts(merged_queues, cards)
    upgraded = _dismissed_upgrade_cards(cards)
    total = sum(len(v) for v in merged_queues.values())
    lines = ["## 结论统计", "",
             f"成立 {len(classified['confirmed'])} ｜ 翻案 {len(upgraded)} ｜ "
             f"消掉 {len(classified['refuted'])} ｜ 存疑 {len(classified['uncertain'])}"
             f" ｜ 未重审 {len(classified['unadjudicated'])}（合并漏洞共 {total} 条）"]
    reviewed = [c for c in cards if c.get("finding_ref", {}).get("origin") == "dismissed"]
    if reviewed:
        # 单仓否决的跨仓复核结论一行带过：无翻案时对读者是纯噪音，不展开成清单；
        # 有翻案时指回成立区。needs-review 的维持卡（maintain 举证门槛拦截 /
        # 占位失败，spec 2026-09-21 §3.2）不算"维持"，单列存疑。
        review_needs = [c for c in reviewed if c.get("conclusion") == "needs-review"]
        maintained = len(reviewed) - len(upgraded) - len(review_needs)
        lines += [""]
        if upgraded:
            extra = (f" · 存疑 {len(review_needs)}（举证不足/裁决失败，待人工）"
                     if review_needs else "")
            lines.append(f"单仓已否决复核：维持 {maintained}"
                         f" · 翻案 {len(upgraded)}（翻案候选见「成立的漏洞」区，待人工确认）"
                         + extra)
        elif review_needs:
            lines.append(f"单仓已否决复核：维持 {maintained}"
                         f" · 存疑 {len(review_needs)}（举证不足/裁决失败，待人工）")
        else:
            lines.append(f"单仓已否决复核：{len(reviewed)} 条全部维持原判，无翻案。")
    # 留档指引并入统计节尾（2026-09-21：报告只收结论，全量卡由 json 承担）
    lines += ["", f"> 全量裁决留档：{len(cards)} 张卡见 adjudication-log.json。", ""]
    return lines


def _render_vuln_detail(entry: dict, card: dict) -> list[str]:
    """成立的单条漏洞全文（接口/问题点/POC/危害/修复），供报告直接交付复核。

    2026-09-21：confirm 卡带 exploit_path 时，前置渲染「跨仓触发路径」（入口接口
    → 逐跳 RPC → 触达点 + 用户可控性）与「跨仓 PoC」（以入口接口为起点重写）；
    单仓接口/POC 同步降级标注——单仓接口是后端内部面（内网端口/直连），跨仓场景
    下不可达，避免复核者拿错 PoC 打错接口。"""
    ref = card.get("finding_ref", {})
    # 跨仓修订（2026-09-21，按需）：危害重述/成因补充/定级建议——跨仓分析
    # 改变了表述时才由裁决卡给出；展示层修订版优先、单仓原文保留可审计
    refined = card.get("refined_finding")
    refined = refined if isinstance(refined, dict) and refined else {}
    sev_line = entry.get("severity", "?")
    if refined.get("severity"):
        sev_line = f"{sev_line}，跨仓定级建议: {refined['severity']}"
    lines = [f"### [{entry.get('ID', '?')}] {entry.get('service', '?')} — "
             f"{entry.get('title', '')}（{sev_line}）"]
    ep = card.get("exploit_path")
    has_path = isinstance(ep, dict) and bool(ep)
    if has_path:
        lines.append("- 跨仓触发路径:")
        if ep.get("entry_endpoint"):
            lines.append(f"  - 入口: {ep.get('entry_service', '')}"
                         f" `{ep['entry_endpoint']}`".rstrip())
        for h in ep.get("hops") or []:
            lines.append(f"  - RPC: {h.get('from', '?')} → {h.get('to', '?')}"
                         f" · {h.get('rpc', '?')}（{h.get('call_site', '?')}）")
        if ep.get("sink"):
            lines.append(f"  - 触达点: {ep['sink']}")
        if ep.get("user_controlled"):
            lines.append(f"  - 用户可控性: {ep['user_controlled']}")
        xpoc = ep.get("poc")
        if isinstance(xpoc, dict) and xpoc:
            lines.append("- 跨仓 PoC（从入口接口触发）:")
            if xpoc.get("preconditions"):
                lines.append(f"  - 前置: {xpoc['preconditions']}")
            for s in xpoc.get("steps") or []:
                lines.append(f"  - 步骤: {s}")
            if xpoc.get("curl"):
                lines.append(f"  ```bash\n  {xpoc['curl']}\n  ```")
            if xpoc.get("raw_http"):
                lines.append(f"  ```http\n  {xpoc['raw_http']}\n  ```")
            if xpoc.get("notes"):
                lines.append(f"  - 说明: {xpoc['notes']}")
    eps = entry.get("report_endpoints") or []
    # 入口自证（exploit_path 无 hops）：单仓接口即对外入口，不降级标注
    entry_self = has_path and not (ep.get("hops") or [])
    iface_label = ("- 单仓接口（后端内部面，非公网入口）:"
                   if has_path and not entry_self and eps else "- 接口:")
    for ep_row in eps[:5]:
        head = f"{iface_label} {ep_row.get('method', '')} {ep_row.get('path', '')}".strip()
        meta = " · ".join(x for x in (
            f"auth: {ep_row['auth']}" if ep_row.get("auth") else "",
            f"route: {ep_row['route_registered_at']}" if ep_row.get("route_registered_at") else "",
            f"source: {ep_row['source_location']}" if ep_row.get("source_location") else "",
        ) if x)
        lines.append(f"{head}（{meta}）" if meta else head)
        if ep_row.get("params"):
            lines.append(f"  - 参数: {'; '.join(ep_row['params'])}")
    if entry.get("location") or entry.get("vulnerable_code_location"):
        lines.append(f"- 位置: {entry.get('vulnerable_code_location') or entry.get('location')}")
    if refined.get("cause"):
        lines.append(f"- 成因补充（跨仓）: {refined['cause']}")
    if entry.get("impact"):
        if refined.get("impact"):
            lines.append(f"- 危害: {refined['impact']}（跨仓修订；单仓原表述: {entry['impact']}）")
        else:
            lines.append(f"- 危害: {entry['impact']}")
    for p in (entry.get("report_problem_points") or [])[:5]:
        lines.append(f"- 问题点: {p.get('location', '?')} — {p.get('description', '')}")
        if p.get("snippet"):
            lines.append(f"  ```\n  {p['snippet']}\n  ```")
    poc = entry.get("report_poc") or {}
    if isinstance(poc, dict) and poc:
        poc_label = ("- 单仓 PoC（直连后端内部接口；跨仓场景请用上方跨仓 PoC）:"
                     if has_path and not entry_self else "- POC:")
        lines.append(poc_label)
        if poc.get("preconditions"):
            lines.append(f"  - 前置: {poc['preconditions']}")
        if poc.get("expected_response"):
            lines.append(f"  - 预期: {poc['expected_response']}")
        for s in poc.get("steps") or []:
            lines.append(f"  - 步骤: {s}")
        if poc.get("curl"):
            lines.append(f"  ```bash\n  {poc['curl']}\n  ```")
        if poc.get("raw_http"):
            lines.append(f"  ```http\n  {poc['raw_http']}\n  ```")
    if entry.get("remediation"):
        lines.append(f"- 修复建议: {entry['remediation']}")
    # 跨仓上下文散文行：无结构化路径（旧卡）时保留；有 exploit_path 时同信息已
    # 由「跨仓触发路径」结构化表达，不再重复（2026-09-21 精简）
    if card.get("cross_service_context") and not has_path:
        lines.append(f"- 跨仓上下文: {card['cross_service_context']}")
    lines.append("")
    return lines


def _render_confirmed_vulns(classified: dict[str, list[tuple[dict, dict | None]]],
                            upgraded: list[dict]) -> list[str]:
    """成立漏洞全文：per-vuln confirmed（queue 条目全文 + 裁决卡跨仓上下文）
    + dismissed upgrade 翻案卡全文。章首附速览表（2026-09-21 目录优化）——
    ID/服务/严重度/定级建议/标题 一览，当目录兼摘要，免滚全文找条目。"""
    confirmed = classified["confirmed"]
    if not confirmed and not upgraded:
        return []
    lines = ["", "## 成立的漏洞（跨仓确认 + 翻案）", ""]

    def _sev_rank(s: str) -> int:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        return order.get((s or "").lower(), 4)

    rows = [(e.get("severity", ""), e.get("ID", "?"), e.get("service", "?"),
             ((c or {}).get("refined_finding") or {}).get("severity", ""),
             e.get("title", "")) for e, c in confirmed]
    rows.sort(key=lambda r: (_sev_rank(r[0]), r[1], r[2]))
    if upgraded:
        for c in upgraded:
            ref = c.get("finding_ref", {})
            rows.append(("—", ref.get("vuln_id", "?"), ref.get("service", "?"),
                         "", f"翻案：{(c.get('cross_service_context') or '')[:40]}"))
    lines += ["| ID | 服务 | 严重度 | 定级建议 | 标题 |", "|---|---|---|---|---|"]
    for sev, vid, svc, refined_sev, title in rows:
        lines.append(f"| {vid} | {svc} | {sev} | {refined_sev or '—'} | {title} |")
    lines.append("")
    for entry, card in confirmed:
        lines += _render_vuln_detail(entry, card or {})
    if upgraded:
        lines += ["### 翻案候选（单仓已否决 → 跨仓可达，待人工复核）", ""]
        for c in upgraded:
            ref = c.get("finding_ref", {})
            lines.append(f"### [{ref.get('vuln_id', '?')}] {ref.get('service', '?')}"
                         f"（confidence: {c.get('confidence', '?')}）")
            if c.get("cross_service_context"):
                lines.append(f"- 跨仓上下文: {c['cross_service_context']}")
            for step in c.get("analysis_process") or []:
                lines.append(f"- 过程: {step}")
            for ev in c.get("verification_evidence") or []:
                lines.append(f"- 证据: {ev.get('location', '?')} — {ev.get('note', '')}")
            if c.get("reasoning"):
                lines.append(f"- 论证: {c['reasoning']}")
            lines.append("")
    return lines


def _render_refuted_list(
    classified: dict[str, list[tuple[dict, dict | None]]],
) -> list[str]:
    """消掉/存疑清单：per-vuln 一行一条（ID + service + 结论 + reasoning），与结果页
    紧凑行同口径。dismissed 维持卡不进本清单（结论文案见结论统计的复核行；
    留档全文在「跨仓裁决(阶段 B)」章节）。"""
    rows = [("消掉", classified["refuted"]), ("存疑", classified["uncertain"])]
    if not any(items for _, items in rows):
        return []
    lines = ["", "## 消掉/存疑清单", ""]
    for label, items in rows:
        for entry, card in items:
            c = card or {}
            lines.append(f"- [{entry.get('ID', '?')}] {entry.get('service', '?')}（{label}, "
                         f"confidence: {c.get('confidence', '-') if c else '-'}）"
                         f"— {c.get('reasoning', '') if c else '无裁决卡'}")
    lines.append("")
    return lines
