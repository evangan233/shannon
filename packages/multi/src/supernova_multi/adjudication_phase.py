"""阶段 B 裁决编排（spec 2026-08-27 §7）——发现驱动，跑在阶段 A 产物之上。

批粒度容错：单批 Agent 失败/无效 payload/漏判 finding → error 占位卡补位
（direction="error"、conclusion="needs-review"），不静默丢失、不拖垮其它批。
矛盾卡（direction vs conclusion）经 sanitize_adjudication_cards 拦截。
"""
from __future__ import annotations

import asyncio
import json
import logging
import os

from supernova_core.correlation.adjudication import AdjudicationBatch
from supernova_core.correlation.artifacts_guide import build_full_artifacts_guide
from supernova_core.correlation.merge_validation import sanitize_adjudication_cards
from supernova_core.models.agents import AgentName

logger = logging.getLogger(__name__)

_CARD_SCHEMA = {
    "type": "object",
    "properties": {
        "cards": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "direction": {"type": "string"},
                    "finding_ref": {"type": "object"},
                    "conclusion": {"type": "string"},
                    "cross_service_context": {"type": "string"},
                    "analysis_process": {"type": "array"},
                    "verification_evidence": {"type": "array"},
                    "reasoning": {"type": "string"},
                    "confidence": {"type": "string"},
                },
                "required": ["direction", "finding_ref", "conclusion"],
            },
        }
    },
    "required": ["cards"],
}


def _error_card(batch: AdjudicationBatch, finding: dict, reason: str) -> dict:
    return {
        "direction": "error",
        "finding_ref": {"service": batch.service,
                        "vuln_id": finding.get("ID", ""),
                        "origin": batch.origin},
        "conclusion": "needs-review",
        "cross_service_context": "",
        "analysis_process": [],
        "verification_evidence": [],
        "reasoning": f"adjudication batch failed: {reason}",
        "confidence": "low",
    }


def _error_cards(batch: AdjudicationBatch, reason: str) -> list[dict]:
    return [_error_card(batch, f, reason) for f in batch.findings]


def _exec_timeout() -> float:
    """单批 executor.execute 的 run 级 wall-clock 超时（秒）。

    2026-09-20 cross-repo-20260920-073614：adjudication 单批 50min+ 零产出零日志
    （挂点在 call() 的 wait_for(call_timeout) 覆盖面之外的环节），整单僵死在
    "adjudication started"。本兜底在批粒度封顶——超时 → TimeoutError → 既有批级
    except → error 占位卡，后续批照常。默认 2700s（> openai 引擎 call_timeout
    2400s，正常批不被误杀；只截兜底外的卡死）。env 可配。
    """
    return float(os.getenv("SUPERNOVA_OPENAI_ADJUDICATION_EXEC_TIMEOUT", "2700"))


def _batch_concurrency() -> int:
    """批并发上限。adjudication 批是大 prompt（15 findings × 全仓 artifacts_guide），
    对 LLM 端 429/慢响应敏感，不与 edge agents 共用 SUPERNOVA_MAX_CONCURRENT 池
    （生产可能调大；批间并发跑满会放大限流）。独立 env、默认 3，垃圾值回落默认
    （对齐 get_max_concurrent 的防御语义，env 配错不炸 scan）。
    """
    raw = os.getenv("SUPERNOVA_ADJUDICATION_MAX_CONCURRENT")
    if raw is None:
        return 3
    try:
        v = int(raw)
    except ValueError:
        return 3
    return v if v >= 1 else 3


async def run_adjudication_phase(
    *,
    batches: list[AdjudicationBatch],
    artifacts_by_service: dict,
    correlation_context: dict,
    executor,
    sem=None,
    repo_path: str,
    deliverables_path: str,
    pipeline_testing: bool = False,
    provider_config: dict | None = None,
    corr_writer=None,
) -> list[dict]:
    """跑全部裁决批，返回 sanitized 裁决卡列表（含 error 占位卡）。

    批并发跑（asyncio.gather + 信号量限流）——此前是串行 for 循环，8-10 批排队
    等单批 5-15min 的深判，总时长 40-150min（2026-09-20 cross-repo-20260920-073614
    用户体感「每次都在 adjudication 卡很久」的结构性根因之一）。sem=None 时用
    _batch_concurrency()（独立 env，默认 3）；显式传 sem 则用传入的（测试/老调用）。

    corr_writer（可选，CorrelationEventWriter）：批级进度事件（started/completed/
    failed，node=adjudication-batch）落 events.ndjson——此前批循环零观测（上），
    live 页只见 "adjudication started" 后长期静默。None 时静默跳过（既有测试/老调用
    形态兼容）。
    """
    cards: list[dict] = []
    total = len(batches)
    if sem is None:
        sem = asyncio.Semaphore(_batch_concurrency())

    async def run_batch(batch: AdjudicationBatch) -> list[dict]:
        async with sem:
            try:
                metrics = await asyncio.wait_for(
                    executor.execute(
                        agent_name=AgentName.CROSS_REPO_ADJUDICATION,
                        repo_path=repo_path,
                        deliverables_path=deliverables_path,
                        pipeline_testing=pipeline_testing,
                        prompt_variables={
                            "artifacts_guide": build_full_artifacts_guide(
                                artifacts_by_service),
                            "correlation_context": json.dumps(
                                correlation_context, ensure_ascii=False),
                            "batch_json": json.dumps(
                                batch.findings, ensure_ascii=False),
                        },
                        structured_output_schema=_CARD_SCHEMA,
                        provider_config=provider_config,
                    ),
                    timeout=_exec_timeout(),
                )
            except asyncio.TimeoutError as e:
                raise RuntimeError(
                    f"adjudication exec exceeded {_exec_timeout():.0f}s wall-clock "
                    "(run-level guard, 兜底 call_timeout 覆盖面之外)") from e
            payload = getattr(metrics, "structured_output", None)
            if not (isinstance(payload, dict) and isinstance(payload.get("cards"), list)):
                return _error_cards(batch, "invalid structured output")
            return payload["cards"]

    async def process(batch: AdjudicationBatch, idx: int) -> list[dict]:
        """单批全程（执行 + 漏判补位 + 终态事件），异常自兜不外抛（批粒度容错）。"""
        label = f"{batch.service}/{batch.vuln_class}"
        progress = f"{idx + 1}/{total} · {len(batch.findings)} findings"
        if corr_writer is not None:
            await corr_writer.adjudication_batch(label, "started", detail=progress)
        failed_reason: str | None = None
        try:
            batch_cards = await run_batch(batch)
        except Exception as e:  # noqa: BLE001 —— 单批失败 → 占位卡,不拖垮其它批
            logger.warning("adjudication batch %s/%s/%s failed: %s",
                           batch.service, batch.vuln_class, batch.origin, e)
            batch_cards = _error_cards(batch, str(e))
            failed_reason = str(e)
        # 漏判补位：批内每个 finding 必须有卡（ID 对齐 finding_ref.vuln_id）
        covered = {c.get("finding_ref", {}).get("vuln_id") for c in batch_cards
                   if isinstance(c, dict)}
        for f in batch.findings:
            if f.get("ID") not in covered:
                batch_cards.append(
                    _error_card(batch, f, "not covered by agent output"))
        # 终态事件统一在补位后发（cards 数含补位卡，与落盘一致）
        if corr_writer is not None:
            if failed_reason is not None:
                await corr_writer.adjudication_batch(
                    label, "failed", detail=f"{progress} · {failed_reason}")
            else:
                await corr_writer.adjudication_batch(
                    label, "completed",
                    detail=f"{progress} · cards={len(batch_cards)}")
        return batch_cards

    # 并发跑全部批；process 内部自兜异常，gather 不会上抛
    if batches:
        results = await asyncio.gather(
            *(process(b, i) for i, b in enumerate(batches)))
        for batch_cards in results:
            cards.extend(c for c in batch_cards if isinstance(c, dict))

    return sanitize_adjudication_cards(cards)
