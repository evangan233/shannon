# packages/whitebox/tests/test_adversarial_review_activity.py
"""run_adversarial_review activity 单测——mock run_gitnexus_verdict_agent，
真文件系统（tmp_path 建五类 queue + repo 源文件），验证：
分片复用 / checkpoint 幂等 / refuted 剔卡+归档 / 降级矩阵 / 产物 schema。
"""
import json
from pathlib import Path

import pytest

from supernova_whitebox.pipeline import activities


@pytest.fixture
def env(tmp_path: Path, monkeypatch):
    """最小扫描目录：deliverables/whitebox/intermediate + injection queue 一卡。"""
    dlv = tmp_path / "deliverables" / "whitebox"
    inter = dlv / "intermediate"
    inter.mkdir(parents=True)
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)  # L4 证据存在性校验要求 repo 源文件真实存在
    (repo / "app.js").write_text("const x = escape(userInput);\n", encoding="utf-8")
    (inter / "injection_exploitation_queue.json").write_text(json.dumps({
        "vulnerabilities": [{
            "ID": "INJ-01", "title": "t", "verdict": "vulnerable",
            "source_track": "llm", "confidence": "high",
            "sink_call": "eval() — app.js:32",
        }]}), encoding="utf-8")
    for vc in ("xss", "ssrf", "authz", "auth"):
        (inter / f"{vc}_exploitation_queue.json").write_text(
            json.dumps({"vulnerabilities": []}), encoding="utf-8")
    monkeypatch.setattr(activities, "get_audit_session", lambda: None)
    # 直接调内部函数 _run_adversarial_review_for_classes 以绕过 activity 运行时
    return {"deliverables": dlv, "repo": repo, "intermediate": inter}


def _agent_result(payload: dict | None, text: str = ""):
    from types import SimpleNamespace
    return SimpleNamespace(structured_output=payload, text=text)


REFUTED = {"cards": [{
    "vulnerability_id": "INJ-01", "review_verdict": "refuted",
    "dimension_results": [
        {"dimension": "defense_effective", "rebutted": True, "reason": "r",
         "evidence": [{"location": "app.js:1",
                       "snippet": "const x = escape(userInput);"}]}],
    "failed_dimensions": ["defense_effective"],
    "rebuttal_reason": "escape covers the slot",
    "survival_reason": None, "confidence": "high"}]}


async def test_refuted_card_removed_and_archived(env, monkeypatch):
    async def fake_agent(**kw):
        return _agent_result(REFUTED)
    monkeypatch.setattr(activities, "run_gitnexus_verdict_agent", fake_agent)
    await activities._run_adversarial_review_for_classes(
        deliverables=env["deliverables"], repo_path=str(env["repo"]),
        provider_config=None)
    q = json.loads((env["intermediate"] /
                    "injection_exploitation_queue.json").read_text())
    assert q["vulnerabilities"] == []  # 剔除
    dismissed = json.loads((env["intermediate"] /
                            "dismissed_findings.json").read_text())
    assert dismissed["dismissed"][0]["ID"] == "INJ-01"
    assert dismissed["dismissed"][0]["dismissed_at_stage"] == "adversarial-review"
    review = json.loads((env["intermediate"] /
                         "adversarial_review.json").read_text())
    rec = review["records"][0]
    assert rec["before"]["ID"] == "INJ-01"
    assert rec["review_verdict"] == "refuted"
    assert rec["failed_dimensions"] == ["defense_effective"]
    assert rec["after"] == {"action": "dismissed"}
    assert review["summary"]["refuted"] == 1


async def test_checkpoint_skips_finalized(env, monkeypatch):
    calls = []
    async def fake_agent(**kw):
        calls.append(kw)
        return _agent_result(REFUTED)
    monkeypatch.setattr(activities, "run_gitnexus_verdict_agent", fake_agent)
    await activities._run_adversarial_review_for_classes(
        deliverables=env["deliverables"], repo_path=str(env["repo"]),
        provider_config=None)
    await activities._run_adversarial_review_for_classes(  # 重跑：终态不重审
        deliverables=env["deliverables"], repo_path=str(env["repo"]),
        provider_config=None)
    assert len(calls) == 1


async def test_agent_failure_leaves_unreviewed(env, monkeypatch):
    async def fake_agent(**kw):
        raise RuntimeError("boom")
    monkeypatch.setattr(activities, "run_gitnexus_verdict_agent", fake_agent)
    await activities._run_adversarial_review_for_classes(
        deliverables=env["deliverables"], repo_path=str(env["repo"]),
        provider_config=None)
    q = json.loads((env["intermediate"] /
                    "injection_exploitation_queue.json").read_text())
    assert len(q["vulnerabilities"]) == 1  # 保守放行
    review = json.loads((env["intermediate"] /
                         "adversarial_review.json").read_text())
    assert review["records"][0]["review_verdict"] == "unreviewed"
    assert review["records"][0]["after"] == {"action": "kept"}


async def test_validate_crash_degrades_shard_not_round(env, monkeypatch):
    """reviewer fix I2：validate 层任何未预见的异常（实证一例：null-byte
    location → fpath.resolve() 抛 ValueError）只降级该片 unreviewed，不逃逸
    炸类——queue 不剔卡、adversarial_review.json 恒落盘（否则已剔卡+归档
    却无审查记录，重试也不重建）。"""
    import supernova_core.collectors.adversarial_review as ar_mod

    async def fake_agent(**kw):
        return _agent_result(REFUTED)
    monkeypatch.setattr(activities, "run_gitnexus_verdict_agent", fake_agent)

    def boom(*a, **kw):
        raise ValueError("lstat: embedded null character in path")
    monkeypatch.setattr(ar_mod, "validate_review_cards", boom)
    await activities._run_adversarial_review_for_classes(
        deliverables=env["deliverables"], repo_path=str(env["repo"]),
        provider_config=None)
    q = json.loads((env["intermediate"] /
                    "injection_exploitation_queue.json").read_text())
    assert len(q["vulnerabilities"]) == 1  # 该片 unreviewed 保守放行，未剔卡
    review = json.loads((env["intermediate"] /
                         "adversarial_review.json").read_text())
    assert review["records"][0]["review_verdict"] == "unreviewed"
    assert review["summary"]["total"] == 1  # 产物落盘未被异常截断


async def test_corrupt_queue_file_skips_class_not_round(env, monkeypatch):
    """reviewer fix I2：单类 queue 文件坏（非 JSON）该类按空处理 + warning，
    其余类照常审、adversarial_review.json 恒落盘；坏 queue 不被覆写。"""
    (env["intermediate"] / "injection_exploitation_queue.json").write_text(
        "{not json", encoding="utf-8")
    (env["intermediate"] / "xss_exploitation_queue.json").write_text(
        json.dumps({"vulnerabilities": [{
            "ID": "XSS-01", "title": "t", "verdict": "vulnerable",
            "source_track": "llm", "confidence": "high"}]}), encoding="utf-8")

    async def fake_agent(**kw):
        return _agent_result({"cards": [{
            "vulnerability_id": "XSS-01", "review_verdict": "survived",
            "dimension_results": [], "failed_dimensions": [],
            "rebuttal_reason": None, "survival_reason": "held",
            "confidence": "high"}]})
    monkeypatch.setattr(activities, "run_gitnexus_verdict_agent", fake_agent)
    await activities._run_adversarial_review_for_classes(
        deliverables=env["deliverables"], repo_path=str(env["repo"]),
        provider_config=None)
    review = json.loads((env["intermediate"] /
                         "adversarial_review.json").read_text())
    recs = {(r["vuln_class"], r["finding_id"]) for r in review["records"]}
    assert ("injection", "INJ-01") not in recs  # 坏类按空处理
    assert ("xss", "XSS-01") in recs            # 其余类照常审
    assert review["summary"]["total"] == 1
    # records 空 → 收口处不覆写坏 queue（不销毁读不了的文件）
    assert (env["intermediate"] /
            "injection_exploitation_queue.json").read_text() == "{not json"


def _dup_refuted() -> dict:
    """REFUTED 的 DUP-01 版（L2 要求 vulnerability_id ∈ 片内）。"""
    card = json.loads(json.dumps(REFUTED["cards"][0]))
    card["vulnerability_id"] = "DUP-01"
    return {"cards": [card]}


def _dup_survived() -> dict:
    return {"cards": [{
        "vulnerability_id": "DUP-01", "review_verdict": "survived",
        "dimension_results": [], "failed_dimensions": [],
        "rebuttal_reason": None, "survival_reason": "defense upstream",
        "confidence": "high"}]}


async def test_checkpoint_scoped_per_class(env, monkeypatch):
    """prior_records 键 = (vuln_class, finding_id)：同 ID 卡跨类不串——
    injection DUP-01 已 refuted 终态后，xss 的同名 DUP-01 unreviewed 仍补审
    （单 ID 键会跨类误跳审，unreviewed 卡永远补不了审）。"""
    (env["intermediate"] / "injection_exploitation_queue.json").write_text(
        json.dumps({"vulnerabilities": [{
            "ID": "DUP-01", "title": "t-inj", "verdict": "vulnerable",
            "source_track": "llm", "confidence": "high",
            "sink_call": "eval() — app.js:32"}]}), encoding="utf-8")
    (env["intermediate"] / "xss_exploitation_queue.json").write_text(
        json.dumps({"vulnerabilities": [{
            "ID": "DUP-01", "title": "t-xss", "verdict": "vulnerable",
            "source_track": "llm", "confidence": "high"}]}), encoding="utf-8")

    async def fake_agent(**kw):
        return _agent_result(_dup_refuted() if "injection" in kw["agent_name"]
                             else None)  # xss 片空 cards → unreviewed
    monkeypatch.setattr(activities, "run_gitnexus_verdict_agent", fake_agent)
    await activities._run_adversarial_review_for_classes(
        deliverables=env["deliverables"], repo_path=str(env["repo"]),
        provider_config=None)

    async def xss_survived(**kw):
        return _agent_result(_dup_survived()
                             if "xss" in kw["agent_name"] else None)
    monkeypatch.setattr(activities, "run_gitnexus_verdict_agent", xss_survived)
    await activities._run_adversarial_review_for_classes(  # 重跑：只补审 xss
        deliverables=env["deliverables"], repo_path=str(env["repo"]),
        provider_config=None)

    review = json.loads((env["intermediate"] /
                         "adversarial_review.json").read_text())
    recs = {(r["vuln_class"], r["finding_id"]): r for r in review["records"]}
    assert recs[("injection", "DUP-01")]["review_verdict"] == "refuted"
    assert recs[("xss", "DUP-01")]["review_verdict"] == "survived"  # 补审成功
    assert review["summary"]["total"] == 2
    inj_q = json.loads((env["intermediate"] / "injection_exploitation_queue.json")
                       .read_text())["vulnerabilities"]
    xss_q = json.loads((env["intermediate"] / "xss_exploitation_queue.json")
                       .read_text())["vulnerabilities"]
    assert inj_q == [] and len(xss_q) == 1

