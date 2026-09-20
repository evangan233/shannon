"""阶段 B 裁决编排（spec 2026-08-27 §7）——发现驱动，批粒度容错。

- 正常批 → CROSS_REPO_ADJUDICATION agent 调用（prompt_vars 三注入）→ sanitized cards
- 单批失败/无效 payload → 全批 error 占位卡（每 finding 一张，不静默丢失）
- 批内漏判 finding → 补 error 占位卡
"""
import asyncio

import pytest

from supernova_core.correlation.adjudication import AdjudicationBatch
from supernova_multi.adjudication_phase import run_adjudication_phase


def _artifacts(services):
    from supernova_core.correlation.artifacts_guide import ServiceArtifacts
    return {s: ServiceArtifacts(service=s, role="backend", repo_path=f"/r/{s}",
                                deliverables=None) for s in services}


def _batch(service="order-svc", vc="injection", origin="queue", ids=("INJ-1",)):
    return AdjudicationBatch(
        service=service, vuln_class=vc, origin=origin,
        findings=[{"ID": i, "title": "t"} for i in ids])


class _M:
    def __init__(self, payload):
        self.structured_output = payload


class FakeExecutor:
    def __init__(self, behavior):
        self.behavior = behavior      # list of payload | Exception（按调用序）
        self.calls = []

    async def execute(self, **kw):
        self.calls.append(kw)
        item = self.behavior[len(self.calls) - 1]
        if isinstance(item, Exception):
            raise item
        return _M(item)


async def _run(executor, batches):
    return await run_adjudication_phase(
        batches=batches,
        artifacts_by_service=_artifacts(["gateway", "order-svc"]),
        correlation_context={"edges": [], "flows": [], "multi_hop_chains": []},
        executor=executor, sem=asyncio.Semaphore(3),
        repo_path="/ws", deliverables_path="/ws/deliverables")


@pytest.mark.asyncio
async def test_normal_batch_calls_adjudication_agent_with_prompt_vars():
    ex = FakeExecutor([{"cards": [{
        "direction": "confirm", "finding_ref": {"service": "order-svc",
                                                 "vuln_id": "INJ-1", "origin": "queue"},
        "conclusion": "vulnerable"}]}])
    cards = await _run(ex, [_batch()])
    assert ex.calls[0]["agent_name"].value == "cross-repo-adjudication"
    pv = ex.calls[0]["prompt_variables"]
    assert "order-svc" in pv["artifacts_guide"]
    assert "multi_hop_chains" in pv["correlation_context"]
    assert "INJ-1" in pv["batch_json"]
    assert cards[0]["conclusion"] == "vulnerable"


@pytest.mark.asyncio
async def test_failed_batch_yields_error_cards_per_finding():
    ex = FakeExecutor([RuntimeError("llm down")])
    cards = await _run(ex, [_batch(ids=("INJ-1", "INJ-2"))])
    assert len(cards) == 2                      # 不静默丢失
    assert all(c["direction"] == "error" and c["conclusion"] == "needs-review"
               for c in cards)
    assert all("llm down" in c["reasoning"] for c in cards)


@pytest.mark.asyncio
async def test_invalid_payload_treated_as_batch_failure():
    ex = FakeExecutor([{"no_cards_here": True}])      # 无 cards 键
    cards = await _run(ex, [_batch(ids=("INJ-1",))])
    assert cards[0]["direction"] == "error"


@pytest.mark.asyncio
async def test_missing_finding_gets_error_placeholder():
    """Agent 漏判批内 finding → 编排补 error 占位卡。"""
    ex = FakeExecutor([{"cards": [{
        "direction": "confirm", "finding_ref": {"service": "order-svc",
                                                 "vuln_id": "INJ-1", "origin": "queue"},
        "conclusion": "vulnerable"}]}])
    cards = await _run(ex, [_batch(ids=("INJ-1", "INJ-2"))])
    by_id = {c["finding_ref"].get("vuln_id"): c for c in cards}
    assert by_id["INJ-1"]["direction"] == "confirm"
    assert by_id["INJ-2"]["direction"] == "error"


@pytest.mark.asyncio
async def test_contradictory_card_sanitized():
    ex = FakeExecutor([{"cards": [{
        "direction": "upgrade", "finding_ref": {"service": "order-svc",
                                                 "vuln_id": "INJ-1", "origin": "dismissed"},
        "conclusion": "not-vulnerable"}]}])
    cards = await _run(ex, [_batch(origin="dismissed")])
    assert cards[0]["conclusion"] == "needs-review"


class FakeWriter:
    """记录 adjudication_batch 进度事件（对齐 CorrelationEventWriter 形态）。"""

    def __init__(self):
        self.events = []

    async def adjudication_batch(self, name, status, detail=None):
        self.events.append((name, status, detail))


async def _run_with_writer(executor, batches, writer):
    return await run_adjudication_phase(
        batches=batches,
        artifacts_by_service=_artifacts(["gateway", "order-svc"]),
        correlation_context={"edges": [], "flows": [], "multi_hop_chains": []},
        executor=executor, sem=asyncio.Semaphore(3),
        repo_path="/ws", deliverables_path="/ws/deliverables",
        corr_writer=writer)


@pytest.mark.asyncio
async def test_batch_progress_events_written():
    """批 started/completed 事件按序落 writer（2026-09-20 cross-repo 零观测遗留项）。"""
    ok = {"cards": [{
        "direction": "confirm", "finding_ref": {"service": "order-svc",
                                                "vuln_id": "INJ-1", "origin": "queue"},
        "conclusion": "vulnerable"}]}
    ex = FakeExecutor([ok, ok])
    writer = FakeWriter()
    await _run_with_writer(ex, [_batch(ids=("INJ-1",)), _batch(vc="authz")], writer)
    assert [e[1] for e in writer.events] == ["started", "completed",
                                             "started", "completed"]
    assert all(e[0] == "order-svc/injection" or e[0] == "order-svc/authz"
               for e in writer.events)
    # detail 带批序与 cards 数
    assert "1/2" in writer.events[0][2] and "completed" == writer.events[1][1]
    assert "cards=1" in writer.events[1][2]


@pytest.mark.asyncio
async def test_batch_failure_emits_failed_event():
    ex = FakeExecutor([RuntimeError("llm down")])
    writer = FakeWriter()
    cards = await _run_with_writer(ex, [_batch(ids=("INJ-1",))], writer)
    assert cards[0]["direction"] == "error"
    assert writer.events[0][1] == "started"
    assert writer.events[1][1] == "failed" and "llm down" in writer.events[1][2]


@pytest.mark.asyncio
async def test_exec_timeout_yields_error_cards(monkeypatch):
    """run 级 wall-clock 兜底：execute 卡死超时 → TimeoutError → 批级 error 占位卡，
    不再整单僵死（2026-09-20 cross-repo-20260920-073614 50min 零产出）。"""
    monkeypatch.setenv("SUPERNOVA_OPENAI_ADJUDICATION_EXEC_TIMEOUT", "0.05")

    class SlowExecutor:
        async def execute(self, **kw):
            await asyncio.sleep(5)      # 远超 0.05s 兜底
            return _M({"cards": []})

    writer = FakeWriter()
    cards = await _run_with_writer(SlowExecutor(), [_batch(ids=("INJ-1",))], writer)
    assert cards[0]["direction"] == "error"
    assert "wall-clock" in cards[0]["reasoning"]
    assert writer.events[1][1] == "failed"
