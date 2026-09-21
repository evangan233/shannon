"""Code index and call graph construction for Supernova's whitebox pipeline."""
import asyncio
import logging
from pathlib import Path

from supernova_core.code_index.models import (
    CodeIndex, TypedParameter, EntryPoint,
    AdjudicatedEntryPoint, AdjudicationResult, Verdict, EntryPointSource,
)
from supernova_core.code_index.parser import detect_language, discover_source_files
from supernova_core.code_index.entry_points import detect_entry_points
from supernova_core.code_index.summary import generate_summary
from supernova_core.code_index.parsers import get_parser
from supernova_core.code_index.sink_detector import detect_sinks
from supernova_core.code_index.degradation import build_degradation_report
from supernova_core.code_index.file_discovery import discover_security_files
from supernova_core.code_index.models import DegradationLevel, FileManifest
from supernova_core.code_index.gitnexus_call_graph import build_call_graph_from_gitnexus
from supernova_core.code_index.llm_taint_analyzer import (
    _deterministic_intra_fallback,
    analyze_taint_llm,
)
from supernova_core.code_index.chain_propagator import (
    merge_taint_flows,
    produce_intra_first_taint_flows,
    propagate_across_chains,
    propagate_backward_across_chains,
)
from supernova_core.code_index.parameter_models import ParameterPropagationGraph
from supernova_core.code_index.progress import ProgressEmitter
from supernova_core.code_index.sink_discovery_llm import (
    RuleGap,
    collect_entry_handler_blocks,
    collect_suspicious_calls,
    discover_sinks_by_entry,
    discover_sinks_llm,
)
from supernova_core.code_index.source_detector import detect_sources
from supernova_core.code_index.source_detector import _dedup as _dedup_source_points
from supernova_core.code_index.source_discovery_llm import (
    SourceGap,
    collect_source_candidates,
    discover_sources_by_rules,
    discover_sources_llm,
)
from supernova_core.code_index.storage_detector import (
    detect_storage_reads,
    detect_storage_writes,
)
from supernova_core.code_index.storage_discovery_llm import (
    StorageGap,
    StorageReadCandidate,
    StorageWriteCandidate,
    discover_storage_reads_llm,
    discover_storage_writes_llm,
)

logger = logging.getLogger(__name__)


def warn_all_empty_intra(intra_results: dict, taint_items) -> bool:
    """spec 2026-08-21 修复点 F: intra 全空观测性告警(纯观测不改行为)。

    全部含 sink 函数的 intra tainted_params 均空 **且** 存在任一 sink 的
    dangerous_slot is_entry_hint=True(直达污点,如 eval(req.body.preTax))→
    "有直达污点却判全空"是矛盾信号(参数提取错位/模型集体失灵),发 warning
    留第一现场。NodeGoat 2026-08-20 事件中 5/5 全 0 仅在进度条显示 0,无告警。

    Returns: 是否触发了告警(供测试断言)。
    """
    if not intra_results:
        return False  # 零函数被分析,无从判异常
    if any(r.tainted_params for r in intra_results.values()):
        return False  # 有任一非空判定 → 正常
    n_hint = sum(
        1 for _, func_sinks in taint_items for s in func_sinks
        if any(slot.is_entry_hint for slot in (s.dangerous_slots or [])))
    if n_hint == 0:
        return False  # 无直达污点 sink,全空不足以判异常
    logger.warning(
        "GitNexus intra taint 全空但存在 %d 个直达污点 sink(is_entry_hint)——"
        "疑似参数提取/模型异常,GitNexus 轨召回可能受损(修复点 A 表达式回退已兜底 flow, "
        "但 sanitizer 标注缺失,建议复查)。", n_hint)
    return True


def backfill_skipped_taint_fallback(taint_items, taint_pairs, blocks_by_id):
    """LLM 超时/异常跳过的 sink 函数走确定性兜底(CLAUDE.md §1 "LLM 不可用档不浪费")。

    map_llm_with_bounds 的 _Skip(超时/error)函数不进 ``taint_pairs`` -> 原本不进
    intra_results -> backward ``_tainted_params_reaching_sink`` 拿到 ``intra=None``
    -> 回退 ``dangerous_slots.expression``(常为局部变量,如 ``httpClient.execute(request)``
    的 "request")-> 无法映射到 caller 参数 -> source 锚定失败 -> 跨函数 taint flow
    全丢(sentinel_dashboard SSRF=0 真根因:proxyPprofRequest 等核心 sink 函数 >60s
    超时被跳过)。

    兜底 ``_deterministic_intra_fallback`` 标 ``tainted_params=全部参数`` + ``hits=0.5``
    (间接命中, is_entry_hint=False),保 backward chain seed 与跨函数传播,不损失召回
    (双轨铁律:GitNexus 轨确定性补召回)。误报由下游 chain_verdict 轻量 LLM 复核过滤。
    """
    intra_results = {func_id: result for func_id, result in taint_pairs}
    analyzed_ids = set(intra_results)
    for func_id, func_sinks in taint_items:
        if func_id in analyzed_ids:
            continue
        block = blocks_by_id.get(func_id)
        if block is None:
            continue
        intra_results[func_id] = _deterministic_intra_fallback(block, func_sinks)
    return intra_results


def _build_typed_params_by_block(index: CodeIndex) -> dict[str, list[TypedParameter]]:
    """对每个 entry block 提取 typed parameters。

    block.file_path 是相对 repo 的路径，需拼接 index.repository 根才能读到源文件。
    extract_typed_parameters 在 Go/Java/PHP 上返回 [] 是预期行为（spec §4.3）。
    单个 entry 提取失败不应影响整体，吞掉异常并 warning。
    """
    from supernova_core.code_index.enhanced_parameters import extract_typed_parameters
    repo_root = Path(index.repository)
    result: dict[str, list[TypedParameter]] = {}
    for ep in index.entry_points:
        block = next((b for b in index.blocks if b.id == ep.func_block_id), None)
        if block is None:
            continue
        try:
            tps = extract_typed_parameters(
                repo_root / block.file_path, block.function_name,
                block.start_line, index.language,
            )
        except Exception as exc:
            logger.warning("typed param extraction failed for %s: %s", block.id, exc)
            tps = []
        result[block.id] = tps
    return result


def _parse_and_detect_sync(repo, language, parser):
    """同步 tree-sitter 解析 + sink/source 候选检测（CPU/FS bound 重活）。

    从 build_code_index_with_gitnexus 抽出，供 asyncio.to_thread 移出 event loop：给
    cancel 一个 await 注入点，避免大仓全量解析阻塞 worker loop 导致 Ctrl+C 不可取消
    （与 run_code_index 的 ensure_indexed_async 同一治本方向）。返回下游 await 段所需
    的 (file_sources, all_blocks, sink_call_sites, suspicious)。
    """
    from supernova_core.models.errors import ErrorCode, PentestError

    source_files = discover_source_files(repo, language)
    if not source_files:
        raise PentestError(
            f"No source files found for language '{language}' in {repo}",
            category="code_index", error_code=ErrorCode.CODE_INDEX_FAILED,
        )

    file_sources: dict[str, bytes] = {}
    all_blocks = []
    for file_path in source_files:
        try:
            source = file_path.read_bytes()
            rel = str(file_path.relative_to(repo))
            file_sources[rel] = source
            blocks = parser.parse_file(file_path, repo)
            all_blocks.extend(blocks)
        except Exception as exc:
            logger.warning("Failed to index %s: %s", file_path, exc)
            continue

    def _provide_source(block):
        return file_sources.get(block.file_path)

    sink_call_sites = detect_sinks(all_blocks, parser, source_provider=_provide_source)
    logger.info("Detected %d rule-based sink call sites", len(sink_call_sites))
    suspicious = collect_suspicious_calls(all_blocks, parser, source_provider=_provide_source)
    return file_sources, all_blocks, sink_call_sites, suspicious


async def build_code_index_with_gitnexus(
    repo_path: str,
    *,
    mcp_client,
    llm_client,
    discovery_agent=None,
    auto_index: bool = False,
    progress_cb=None,
    model: str | None = None,
) -> tuple[CodeIndex, list[RuleGap], list[SourceGap], list[StorageGap]]:
    """Build code index with GitNexus call graph + LLM taint analysis.

    Pipeline:
    1. Tree-sitter parse → FuncBlock[]
    2. GitNexus MCP → precise call graph (edges, chains, entry_points)
    3. sink_detector → SinkCallSite[]
    4. LLM taint analysis (per-function, only for functions with sinks)
    5. Deterministic chain propagation (cross-function parameter mapping)

    Args:
        repo_path: Absolute path to the repository root.
        mcp_client: GitNexus MCP client for call graph queries.
        llm_client: LLM client for taint analysis.
        auto_index: If True, attempt to ensure GitNexus has indexed the repo
            via the CLI engine before proceeding. Raises PentestError if
            GitNexus CLI is unavailable or indexing fails (no fallback).

    Raises:
        PentestError: if GitNexus CLI is unavailable, indexing fails, or (later) MCP query fails.
        GitNexusNotIndexedError: if GitNexus hasn't indexed the repo
        GitNexusConnectionError: if MCP connection fails
    """
    from supernova_core.models.errors import ErrorCode, PentestError

    repo = Path(repo_path).resolve()
    file_manifest = discover_security_files(repo)

    # ⓪ Auto-indexing: ensure GitNexus has indexed the repo
    if auto_index:
        from supernova_core.code_index.gitnexus_engine import GitNexusEngine
        engine = GitNexusEngine(repo)
        if not engine.is_available():
            raise PentestError(
                "GitNexus CLI not installed but is required for code indexing. "
                "Install with: npm install -g gitnexus",
                category="code_index", error_code=ErrorCode.CODE_INDEX_FAILED,
            )
        index_result = await engine.ensure_indexed_async()
        if not index_result.success:
            raise PentestError(
                f"GitNexus indexing failed: {index_result.error_message}. "
                "Code index requires a working GitNexus index.",
                category="code_index", error_code=ErrorCode.CODE_INDEX_FAILED,
            )

    # ① Tree-sitter parse → FuncBlock[]
    # detect_language / get_parser 留 loop 上（快、早期 PentestError 更清晰）；重 CPU 的
    # 全量解析+检测移进 _parse_and_detect_sync 经 asyncio.to_thread 跑，不阻塞 event loop
    # （给 cancel 一个 await 注入点，治本 Ctrl+C 不可取消）。parser 留作用域供后续 detect_sources 用。
    try:
        language = detect_language(repo)
    except ValueError as exc:
        raise PentestError(
            str(exc), category="code_index", error_code=ErrorCode.CODE_INDEX_FAILED,
        ) from exc
    logger.info("Detected language: %s", language)

    parser = get_parser(language)
    if parser is None:
        raise PentestError(
            f"No parser available for language '{language}'",
            category="code_index", error_code=ErrorCode.CODE_INDEX_FAILED,
        )

    file_sources, all_blocks, sink_call_sites, suspicious = await asyncio.to_thread(
        _parse_and_detect_sync, repo, language, parser,
    )

    # 重建 _provide_source 闭包（引用 to_thread 返回的 file_sources，供后续 source 检测用）
    def _provide_source(block):
        return file_sources.get(block.file_path)

    # ② GitNexus MCP → precise call graph
    call_graph = await build_call_graph_from_gitnexus(
        repo_path=str(repo),
        mcp_client=mcp_client,
        blocks=all_blocks,
    )

    # ③b LLM sink 补召回 (spec §3.1): 规则未命中的可疑 call → 软 SinkCallSite
    soft_sinks, rule_gaps = await discover_sinks_llm(
        suspicious, llm_client, discovery_agent=discovery_agent,
        progress_cb=progress_cb, model=model)
    if soft_sinks:
        sink_call_sites = sink_call_sites + soft_sinks
        logger.info("LLM sink discovery added %d soft sinks (%d rule gaps)",
                    len(soft_sinks), len(rule_gaps))

    # ⑦ entry 组装(spec 子项① 前置): detect_entry_points ∪ process entry（G2）。
    #    **提前到 taint 之前**(原在 ⑤ 之后)—— sink 探测器(③c)消费 entry_point_ids,
    #    故 entry_point_ids 必须在 ③c 之前算出; taint 仍自由引用 entry_point_ids。
    #    process entry = call_graph.entry_points(path[0] FuncBlock) 中 detect 未识别的，
    #    entry_type="gitnexus_process"(SRPC/RPC 业务入口,非 HTTP);同 id 时 detect 优先
    #    (保留其 route/http_method)。替代旧的 detect ∩ gitnexus(intersect)。
    all_entry_points = detect_entry_points(all_blocks, language, repo_path=str(repo))
    detected_ids = {ep.func_block_id for ep in all_entry_points}
    process_entries: list[EntryPoint] = []
    for ep_block in call_graph.entry_points:
        if ep_block.id not in detected_ids:
            process_entries.append(EntryPoint(
                func_block_id=ep_block.id,
                entry_type="gitnexus_process",
                route=None,
                http_method=None,
                confidence=0.9,
                evidence=f"GitNexus process entry: {ep_block.function_name}",
                needs_llm_review=False,
                source="gitnexus",
            ))
    gitnexus_entry_points = list(all_entry_points) + process_entries
    logger.info(
        "entry assembly: %d detect + %d gitnexus_process = %d total",
        len(all_entry_points), len(process_entries), len(gitnexus_entry_points),
    )
    entry_point_ids = {ep.func_block_id for ep in gitnexus_entry_points}

    # ④ Group sinks by function (含软 sink)
    from collections import defaultdict
    sinks_by_func: dict[str, list] = defaultdict(list)
    for s in sink_call_sites:
        sinks_by_func[s.caller_id].append(s)

    # ③c LLM sink 探测器(spec 子项③): entry handler 内 LLM 自由找 sink,
    #     补判定器(候选表筛选)漏的框架特有 sink(fastjson.parseObject 等)。
    #     必须在 ⑤ taint analysis 之前: taint 消费 sinks_by_func。
    sink_func_ids_prelim = set(sinks_by_func.keys())  # 规则+判定器软 sink 的函数
    entry_handler_cands = collect_entry_handler_blocks(
        all_blocks, entry_point_ids=entry_point_ids,
        sink_func_ids=sink_func_ids_prelim)
    hunter_sinks, _hunter_gaps = await discover_sinks_by_entry(
        entry_handler_cands, llm_client, progress_cb=progress_cb, model=model)
    if hunter_sinks:
        sink_call_sites = sink_call_sites + hunter_sinks
        for s in hunter_sinks:
            sinks_by_func[s.caller_id].append(s)
        logger.info("LLM sink hunter (entry-driven) added %d soft sinks", len(hunter_sinks))

    # ⑤ LLM taint analysis (only for functions with sinks)
    blocks_by_id = {b.id: b for b in all_blocks}

    # ⑤ LLM taint analysis (only for functions with sinks) — 并发(治本 2):
    # 串行 per-function LLM 会被 ③b 产的 soft sinks 放大,拖垮 activity 超时。

    def _count_taint_flows(result) -> int:
        """per-function taint-flow 计数。

        analyze_taint_llm 返回 IntraResult(tainted_params: set, hits: dict,
        local_steps: list)。tainted_params 非空 = 该函数存在 source→sink
        taint，计为 1 个 taint flow（per-function 粒度，与 map 的 item 粒度一致）。
        """
        if result is None:
            return 0
        return 1 if result.tainted_params else 0

    taint_emitter = ProgressEmitter("taint-analysis", len(sinks_by_func), progress_cb)

    async def _taint_one(item):
        func_id, func_sinks = item
        block = blocks_by_id.get(func_id)
        if block is None:
            await taint_emitter.tick(detail=None, hits_delta=0)  # 仍计数保持准确
            return None
        result = await analyze_taint_llm(
            block=block,
            sinks_in_func=func_sinks,
            llm_client=llm_client,
        )
        flows_count = _count_taint_flows(result)
        detail = f"taint flow in {block.function_name}" if flows_count else None
        await taint_emitter.tick(detail=detail, hits_delta=flows_count)
        return (func_id, result)

    from supernova_core.code_index.llm_concurrency import map_llm_with_bounds
    from supernova_core.config.concurrency import get_max_concurrent
    taint_items = list(sinks_by_func.items())

    async def _on_skip(idx, message):
        # idx → 函数名(同 sink/source discovery): per-function taint 超时/错误诊断走
        # dispatcher 通道, 取代撞 footer 的裸 logger.warning。
        func_id = taint_items[idx][0]
        block = blocks_by_id.get(func_id)
        who = block.function_name if block else func_id
        await taint_emitter.note(f"{who}: {message}")

    taint_pairs = await map_llm_with_bounds(
        taint_items, _taint_one,
        concurrency=get_max_concurrent(),
        label="analyze_taint_llm",
        on_skip=_on_skip,
    )
    await taint_emitter.finalize(
        f"{sum(_count_taint_flows(r) for _, r in taint_pairs)} taint_flows")
    # 超时/异常跳过的 sink 函数走确定性兜底(CLAUDE.md §1 "不浪费"),否则 backward
    # 拿不到 seed -> 跨函数 taint flow 全丢(如 SSRF controller->service)。
    intra_results = backfill_skipped_taint_fallback(taint_items, taint_pairs, blocks_by_id)
    # spec 2026-08-21 修复点 F: intra 全空 + 直达污点 sink → 观测性告警(不改行为)。
    warn_all_empty_intra(intra_results, taint_items)

    # ⑧b source detection（平行 ③ sink detect，独立不依赖 sink；主路径扫 entry_point）
    #    entry_point_ids 已在 ⑦(③b 后)提前算出, 此处直接引用(原 :295 行删除, 解耦子项①)。
    source_points = detect_sources(
        all_blocks, parser, entry_point_ids, source_provider=_provide_source,
    )
    n_entry_sources = len(source_points)
    logger.info("Detected %d rule-based source points (entry_point scan)",
                n_entry_sources)

    # ⑩ storage hard rules (spec 子项⑤ §3.2/§3.3, SYNC, 平行 detect_sources/detect_sinks):
    #    - writes → StorageWritePoint(独立类型,不进 sink_call_sites;DB 写本身非漏洞)
    #    - reads  → SourcePoint(source_type=STORAGE) 并入 source_points(双轨铁律 A:
    #               复用单跳 chain_verdict,零新类型)
    #    两路都扫 entry handler,token 须字面量(group "tok" / group(1));动态 token 留 LLM。
    storage_writes = detect_storage_writes(
        all_blocks, parser, entry_point_ids, source_provider=_provide_source,
    )
    storage_reads = detect_storage_reads(
        all_blocks, parser, entry_point_ids, source_provider=_provide_source,
    )
    logger.info("Detected %d storage writes + %d storage reads (rule-based)",
                len(storage_writes), len(storage_reads))

    # ⑧b' source 补召回(spec 2026-07-10 §3.1):对**含 sink 函数**补 source ——
    #    NodeGoat handler 不在 entry_point(detect_entry_points 把路由归 index.js),
    #    source_detector 主路径漏扫 → 这里对含 sink 函数补回 req.body.preTax 等。
    #    规则路径(扩范围到含 sink 函数)+ LLM 补解构;主路径不变(守"source 不被 sink 驱动")。
    sink_func_ids = set(sinks_by_func.keys())
    rule_extra_sources = discover_sources_by_rules(
        all_blocks, sink_func_ids, source_provider=_provide_source,
        entry_point_ids=entry_point_ids,
    )
    source_candidates = collect_source_candidates(
        all_blocks, sink_func_ids, source_provider=_provide_source,
        entry_point_ids=entry_point_ids,
    )
    soft_sources, source_gaps = await discover_sources_llm(
        source_candidates, llm_client, discovery_agent=discovery_agent,
        progress_cb=progress_cb, model=model)

    # ⑩' storage LLM hunters (spec 子项⑤ §3.3, ASYNC, 平行 discover_sources_llm):
    #    候选 = entry handler blocks(对称 collect_entry_handler_blocks 的口径),用
    #    StorageReadCandidate / StorageWriteCandidate 包装(都带 .block,chunk_items_by_file
    #    按 block_of 提取)。LLM 不可用 → ([], []) 降级(守"GitNexus 轨确定性兜底")。
    #    - read hunter  → 软 SourcePoint(STORAGE),并入 source_points 喂 chain_propagator
    #    - write hunter → 软 StorageWritePoint,并入 storage_writes
    storage_write_candidates = [
        StorageWriteCandidate(block=b)
        for b in all_blocks if b.id in entry_point_ids
    ]
    storage_read_candidates = [
        StorageReadCandidate(block=b)
        for b in all_blocks if b.id in entry_point_ids
    ]
    soft_storage_reads, storage_read_gaps = await discover_storage_reads_llm(
        storage_read_candidates, llm_client, discovery_agent=discovery_agent,
        progress_cb=progress_cb, model=model,
    )
    soft_storage_writes, storage_write_gaps = await discover_storage_writes_llm(
        storage_write_candidates, llm_client, discovery_agent=discovery_agent,
        progress_cb=progress_cb, model=model,
    )
    storage_writes = storage_writes + soft_storage_writes
    storage_gaps = storage_read_gaps + storage_write_gaps

    # 合并去重(按 entry_point_id + param_name + source_type);entry 主路径优先。
    # storage_reads(STORAGE-flavored SourcePoint)与 soft_storage_reads 一并并入
    # source_points → chain_propagator 经 _source_points_matching substring 匹配
    # 产 STORAGE taint_flows(spec 子项⑤ Task 2 锁定的零改动复用契约)。
    source_points = _dedup_source_points(
        source_points + rule_extra_sources + soft_sources
        + storage_reads + soft_storage_reads
    )
    logger.info(
        "source recall: %d entry + %d sink-func rule + %d soft + %d storage-read "
        "+ %d soft-storage-read → %d unique (%d source gaps)",
        n_entry_sources, len(rule_extra_sources), len(soft_sources),
        len(storage_reads), len(soft_storage_reads),
        len(source_points), len(source_gaps),
    )

    # ⑥' propagation:
    #   - intra-first(spec 2026-07-10 §3.2):不依赖 chain,对每个含 sink 函数直接产 flow
    #     (覆盖 handler 不在 chain → backward 丢弃 intra 结果的根因,§2)。
    #   - backward(Sink→Source):沿 chain 反向,终点 SourcePoint 锚定(跨函数)。
    #   合并去重(intra-first 同函数优先,backward 补跨函数)。
    #   注:必须在 ⑧b source detect 之后(消费 source_points 锚定终点)。
    backward_flows = propagate_backward_across_chains(
        chains=call_graph.chains,
        blocks=all_blocks,
        intra_results=intra_results,
        sink_call_sites=sink_call_sites,
        source_points=source_points,
    )
    intra_first_flows = produce_intra_first_taint_flows(
        sink_call_sites=sink_call_sites,
        intra_results=intra_results,
        source_points=source_points,
        blocks=all_blocks,
    )
    taint_flows = merge_taint_flows(intra_first_flows, backward_flows)
    pgraph = ParameterPropagationGraph(
        taint_flows=taint_flows,
        language_coverage=[language],
    )
    logger.info(
        "propagation: %d intra-first + %d backward → %d taint_flows "
        "(source_points=%d, sinks=%d)",
        len(intra_first_flows), len(backward_flows), len(pgraph.taint_flows),
        len(source_points), len(sink_call_sites),
    )

    # ⑨ Assemble CodeIndex
    return (
        CodeIndex(
            repository=str(repo),
            language=language,
            total_blocks=len(all_blocks),
            total_entry_points=len(gitnexus_entry_points),
            total_chains=len(call_graph.chains),
            blocks=all_blocks,
            edges=call_graph.edges,
            entry_points=gitnexus_entry_points,
            chains=call_graph.chains,
            sink_call_sites=sink_call_sites,
            source_points=source_points,
            storage_write_points=storage_writes,
            file_manifest=file_manifest,
            degradation_level=DegradationLevel.FULL,
            parameter_graph=pgraph,
        ),
        rule_gaps,
        source_gaps,
        storage_gaps,
    )


def write_index_files(
    index: CodeIndex,
    output_dir: str,
    *,
    rule_gaps: list | None = None,
    source_gaps: list | None = None,
    storage_gaps: list | None = None,
) -> tuple[Path, Path]:
    """Write code_index.json, code_index_summary.md, parameter_graph.json,
    and (if any) rule_gap_report.json / source_gap_report.json /
    storage_gap_report.json."""
    out = Path(output_dir)
    # tiering（spec 2026-08-18）：索引/图/缺口报告是管线中间产物 → 桶内 intermediate/。
    from supernova_core.utils.paths import intermediate_path
    out.mkdir(parents=True, exist_ok=True)

    json_path = intermediate_path(out, "code_index.json")
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(index.model_dump_json(indent=2))

    summary_path = intermediate_path(out, "code_index_summary.md")
    summary_path.write_text(generate_summary(index))

    pgraph_path = intermediate_path(out, "parameter_graph.json")
    if index.parameter_graph is not None:
        pgraph_path.write_text(index.parameter_graph.model_dump_json(indent=2))
    elif pgraph_path.exists():
        pgraph_path.unlink()

    # 旁路: 规则缺口报告(spec §3.1 层 2, 驱动规则库迭代, 不参与 taint/verdict)
    gap_path = intermediate_path(out, "rule_gap_report.json")
    if rule_gaps:
        import json as _json
        gap_path.write_text(_json.dumps(
            [g if isinstance(g, dict) else g.__dict__ for g in rule_gaps],
            indent=2, ensure_ascii=False,
        ))
    elif gap_path.exists():
        gap_path.unlink()

    # 旁路: source 规则缺口报告(spec 2026-07-10 §3.1, 反哺 source_rules.yml)
    src_gap_path = intermediate_path(out, "source_gap_report.json")
    if source_gaps:
        import json as _json
        src_gap_path.write_text(_json.dumps(
            [g if isinstance(g, dict) else g.__dict__ for g in source_gaps],
            indent=2, ensure_ascii=False,
        ))
    elif src_gap_path.exists():
        src_gap_path.unlink()

    # 旁路: storage 规则缺口报告(spec 子项⑤ §3.3, 反哺 storage_rules.yml)
    # 内容 = LLM soft anchor(reads + writes)按 pattern/medium/kind 聚合的 StorageGap 列表
    storage_gap_path = intermediate_path(out, "storage_gap_report.json")
    if storage_gaps:
        import json as _json
        storage_gap_path.write_text(_json.dumps(
            [g if isinstance(g, dict) else g.__dict__ for g in storage_gaps],
            indent=2, ensure_ascii=False,
        ))
    elif storage_gap_path.exists():
        storage_gap_path.unlink()

    return json_path, summary_path


def run_entry_point_fusion(
    deliverables_dir: str, repo_path: str | None = None,
) -> CodeIndex:
    """Merge deterministic entry points with LLM- and schema-discovered entry points.

    Sources merged (all dedup by func_block_id, deterministic code_index as base):
    - deterministic (code_index.json entry_points) — base
    - LLM (pre_recon_deliverable.md, parsed) — only if deliverable exists
    - OpenAPI/Swagger schema files (repo_path) — only if repo_path given (G5)

    Args:
        deliverables_dir: Path to the deliverables directory containing
            code_index.json and pre_recon_deliverable.md.
        repo_path: Optional repo root to scan for OpenAPI/Swagger schema
            files. When None (default), no schema scan is performed
            (back-compat with pre-G5 callers).

    Returns:
        Updated CodeIndex with merged entry points.
    """
    from supernova_core.code_index.entry_point_fusion import parse_llm_entry_points
    from supernova_core.code_index.schema_entry_parser import parse_openapi_schema_files
    from supernova_core.utils.paths import intermediate_path, resolve_intermediate

    out = Path(deliverables_dir)
    # tiering（spec 2026-08-18）：code_index.json 是中间产物 → intermediate/ 优先，
    # 平铺老结构兜底；None = 两种结构都不存在。
    code_index_path = resolve_intermediate(out, "code_index.json")
    deliverable_path = out / "pre_recon_deliverable.md"

    if code_index_path is None:
        logger.warning("code_index.json not found; skipping entry point fusion")
        raise FileNotFoundError(
            f"code_index.json not found in {deliverables_dir} "
            "(checked intermediate/ and track root)"
        )

    index = CodeIndex.model_validate_json(code_index_path.read_text())

    # Source: LLM pre-recon (only if deliverable exists)
    llm_eps: list[EntryPoint] = []
    if deliverable_path.exists():
        deliverable_text = deliverable_path.read_text()
        llm_eps = parse_llm_entry_points(deliverable_text)
        logger.info("Parsed %d LLM entry points from deliverable", len(llm_eps))
    else:
        logger.info("No pre_recon_deliverable.md found; LLM fusion skipped")

    # Source: OpenAPI/Swagger schema files (G5; only if repo_path given)
    schema_eps: list[EntryPoint] = []
    if repo_path:
        schema_eps = parse_openapi_schema_files(repo_path)
        logger.info("Parsed %d schema entry points from OpenAPI files", len(schema_eps))

    # Merge: deterministic as base, append LLM- and schema-only discoveries
    deterministic_ids = {ep.func_block_id for ep in index.entry_points}
    merged_entries = list(index.entry_points)
    added_llm = 0
    added_schema = 0
    for ep in llm_eps:
        if ep.func_block_id not in deterministic_ids:
            merged_entries.append(ep)
            added_llm += 1
        else:
            logger.debug("LLM entry point %s already in deterministic results, skipping", ep.func_block_id)
    for ep in schema_eps:
        if ep.func_block_id not in deterministic_ids:
            merged_entries.append(ep)
            added_schema += 1
        else:
            logger.debug("Schema entry point %s already in deterministic results, skipping", ep.func_block_id)

    logger.info(
        "Entry point fusion: %d deterministic + %d LLM-only + %d schema-only = %d total",
        len(index.entry_points), added_llm, added_schema, len(merged_entries),
    )

    # Update index
    updated = index.model_copy(update={
        "entry_points": merged_entries,
        "total_entry_points": len(merged_entries),
    })

    # RPC 接口关联（spec 2026-09-21 §3.1 单元 2）：repo_path 给定时解析 proto
    # service/rpc 表，对 grpc_service 入口做同名 join 填 route（proto-only 不进
    # 底册）。join 结果随融合版本一并写回 code_index.json。
    if repo_path:
        from supernova_core.code_index.proto_entry_parser import (
            join_proto_routes,
            parse_proto_services,
        )
        proto_table = parse_proto_services(repo_path)
        if proto_table:
            updated = join_proto_routes(updated, proto_table)

    # Write updated code_index.json（写回 intermediate/，与写侧一致；下游
    # resolve_intermediate 优先读它，保证读到的始终是融合后版本）
    _write_back = intermediate_path(out, "code_index.json")
    _write_back.parent.mkdir(parents=True, exist_ok=True)
    _write_back.write_text(updated.model_dump_json(indent=2))

    return updated


def save_adjudication(deliverables_dir: str) -> None:
    """Adjudicate entry points by confidence and write adjudication result.

    Reads code_index.json, assigns verdict based on confidence thresholds:
    - confidence >= 0.85: CONFIRMED
    - confidence < 0.50: REJECTED
    - otherwise: NEEDS_REVIEW
    """
    out = Path(deliverables_dir)
    out.mkdir(parents=True, exist_ok=True)
    # tiering（spec 2026-08-18）：code_index.json 在 intermediate/ 优先，平铺老结构兜底。
    from supernova_core.utils.paths import intermediate_path, resolve_intermediate
    code_index_path = resolve_intermediate(out, "code_index.json")

    if code_index_path is None:
        logger.warning("code_index.json not found; skipping adjudication")
        return

    index = CodeIndex.model_validate_json(code_index_path.read_text())

    adjudicated = []
    for ep in index.entry_points:
        if ep.confidence >= 0.85:
            verdict = Verdict.CONFIRMED
        elif ep.confidence < 0.50:
            verdict = Verdict.REJECTED
        else:
            verdict = Verdict.NEEDS_REVIEW

        adjudicated.append(AdjudicatedEntryPoint(
            func_block_id=ep.func_block_id,
            verdict=verdict,
            entry_type=ep.entry_type,
            route=ep.route,
            http_method=ep.http_method,
            evidence=ep.evidence,
            source=EntryPointSource.CODE_INDEX if ep.source in ("code_index", "gitnexus")
                    else EntryPointSource.LLM_DISCOVERY,
        ))

    result = AdjudicationResult(
        repository=index.repository,
        language=index.language,
        adjudicated_entry_points=adjudicated,
    )

    # tiering（spec 2026-08-18）：entry_points.json 是机器交接的中间产物 → intermediate/。
    entry_points_path = intermediate_path(out, "entry_points.json")
    entry_points_path.parent.mkdir(parents=True, exist_ok=True)
    entry_points_path.write_text(result.model_dump_json(indent=2))

    confirmed = sum(1 for a in adjudicated if a.verdict == Verdict.CONFIRMED)
    needs_review = sum(1 for a in adjudicated if a.verdict == Verdict.NEEDS_REVIEW)
    rejected = sum(1 for a in adjudicated if a.verdict == Verdict.REJECTED)
    logger.info(
        "Adjudicated %d entry points: %d confirmed, %d needs_review, %d rejected",
        len(adjudicated), confirmed, needs_review, rejected,
    )
