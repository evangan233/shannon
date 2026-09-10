# packages/whitebox/tests/test_adversarial_review_end_to_end.py
"""端到端（无 LLM）：多类混合裁定 queue fixture → _run_adversarial_review_for_classes
(mock agent 按 agent_name=adv-review-{vuln_class}-{片序} 路由返回每类裁定：
injection refuted / xss survived / auth 片 agent 抛错 → unreviewed)，
断言：三类 queue 各自正确（剔空/保留）、dismissed 归档、
adversarial_review.json summary.by_class 计数、checkpoint 幂等（终态不重审）、
unreviewed 补审且 prior_records 跨类不串。
fixture 模式 = Task 4 test_adversarial_review_activity.py 的多类扩展。
"""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from supernova_whitebox.pipeline import activities


def _agent_result(payload: dict):
    return SimpleNamespace(structured_output=payload, text="")


def _card(id_: str, **extra) -> dict:
    card = {"ID": id_, "title": f"t-{id_}", "verdict": "vulnerable",
            "source_track": "llm", "confidence": "high"}
    card.update(extra)
    return card


INJ_CARD = _card("INJ-01", sink_call="eval() — app.js:32")
XSS_CARD = _card("XSS-01", sink_call="innerHTML — views/profile.ejs:12")
AUTH_CARD = _card("AUTH-01", sink_call="requireAuth() — middleware/auth.js:8")

# injection refuted：过 L3（failed 维度 rebutted=true + file:line + rebuttal_reason）
# 与 L4（app.js 真实存在 + snippet 子串匹配）——降级矩阵不触发，保持 refuted。
REFUTED_INJ = {"cards": [{
    "vulnerability_id": "INJ-01", "review_verdict": "refuted",
    "dimension_results": [
        {"dimension": "defense_effective", "rebutted": True, "reason": "r",
         "evidence": [{"location": "app.js:1",
                       "snippet": "const x = escape(userInput);"}]}],
    "failed_dimensions": ["defense_effective"],
    "rebuttal_reason": "escape covers the slot",
    "survival_reason": None, "confidence": "high"}]}

SURVIVED_XSS = {"cards": [{
    "vulnerability_id": "XSS-01", "review_verdict": "survived",
    "dimension_results": [], "failed_dimensions": [],
    "rebuttal_reason": None,
    "survival_reason": "sink writes to textContent, no HTML sink reachable",
    "confidence": "high"}]}

SURVIVED_AUTH = {"cards": [{
    "vulnerability_id": "AUTH-01", "review_verdict": "survived",
    "dimension_results": [], "failed_dimensions": [],
    "rebuttal_reason": None,
    "survival_reason": "authn check enforced upstream of the flagged handler",
    "confidence": "medium"}]}


def _make_mock(results_by_class: dict, calls: list[str]):
    """按 agent_name 的类段路由裁定：payload dict → 返回，Exception → 抛
    （片 agent 失败 → 该片全 unreviewed）。未配置的类默认抛（保守）。"""

    async def fake_agent(**kw):
        name = str(kw.get("agent_name", ""))
        calls.append(name)
        vc = name.removeprefix("adv-review-").rsplit("-", 1)[0]
        result = results_by_class.get(vc)
        if isinstance(result, Exception):
            raise result
        return _agent_result(result)

    return fake_agent


def _run(env):
    return activities._run_adversarial_review_for_classes(
        deliverables=env["deliverables"], repo_path=str(env["repo"]),
        provider_config=None)


def _read_queue(inter: Path, vc: str) -> list:
    return json.loads(
        (inter / f"{vc}_exploitation_queue.json").read_text())["vulnerabilities"]


@pytest.fixture
def env(tmp_path: Path, monkeypatch):
    """最小扫描目录：deliverables/whitebox/intermediate + 三类各一卡
    （injection/xss/auth）+ 两类空 queue（ssrf/authz，审查零调用零产物）。"""
    dlv = tmp_path / "deliverables" / "whitebox"
    inter = dlv / "intermediate"
    inter.mkdir(parents=True)
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)  # L4 证据存在性校验要求 repo 源文件真实存在
    (repo / "app.js").write_text("const x = escape(userInput);\n", encoding="utf-8")
    (repo / "views").mkdir()
    (repo / "views" / "profile.ejs").write_text(
        "<div><%= user.bio %></div>\n", encoding="utf-8")
    (inter / "injection_exploitation_queue.json").write_text(
        json.dumps({"vulnerabilities": [INJ_CARD]}), encoding="utf-8")
    (inter / "xss_exploitation_queue.json").write_text(
        json.dumps({"vulnerabilities": [XSS_CARD]}), encoding="utf-8")
    (inter / "auth_exploitation_queue.json").write_text(
        json.dumps({"vulnerabilities": [AUTH_CARD]}), encoding="utf-8")
    for vc in ("ssrf", "authz"):
        (inter / f"{vc}_exploitation_queue.json").write_text(
            json.dumps({"vulnerabilities": []}), encoding="utf-8")
    monkeypatch.setattr(activities, "get_audit_session", lambda: None)
    # 直接调内部函数 _run_adversarial_review_for_classes 以绕过 activity 运行时
    return {"deliverables": dlv, "repo": repo, "intermediate": inter}


async def test_mixed_verdicts_across_classes(env, monkeypatch):
    """三类混合裁定：queue 剔空/保留、dismissed 归档、summary.by_class 计数。"""
    calls: list[str] = []
    monkeypatch.setattr(activities, "run_gitnexus_verdict_agent", _make_mock(
        {"injection": REFUTED_INJ, "xss": SURVIVED_XSS,
         "auth": RuntimeError("boom")}, calls))
    await _run(env)
    inter = env["intermediate"]

    # 三类 queue 各自正确：injection 剔空、xss/auth 保守保留
    assert _read_queue(inter, "injection") == []
    assert _read_queue(inter, "xss") == [XSS_CARD]
    assert _read_queue(inter, "auth") == [AUTH_CARD]

    # dismissed 只有 injection 的卡，且标注 adversarial-review 阶段
    dismissed = json.loads(
        (inter / "dismissed_findings.json").read_text())["dismissed"]
    assert len(dismissed) == 1
    assert dismissed[0]["ID"] == "INJ-01"
    assert dismissed[0]["vuln_class"] == "injection"
    assert dismissed[0]["dismissed_at_stage"] == "adversarial-review"
    assert "adversarial-review[defense_effective]" in dismissed[0]["dismiss_reason"]

    # summary（全量口径）+ by_class 三类计数
    review = json.loads((inter / "adversarial_review.json").read_text())
    s = review["summary"]
    assert (s["total"], s["refuted"], s["survived"], s["unreviewed"]) == (3, 1, 1, 1)
    assert s["by_class"]["injection"] == {
        "total": 1, "refuted": 1, "survived": 0, "unreviewed": 0}
    assert s["by_class"]["xss"] == {
        "total": 1, "refuted": 0, "survived": 1, "unreviewed": 0}
    assert s["by_class"]["auth"] == {
        "total": 1, "refuted": 0, "survived": 0, "unreviewed": 1}
    assert "ssrf" not in s["by_class"] and "authz" not in s["by_class"]

    # records 跨类归属正确（vuln_class 逐条标注，after 动作正确）
    recs = {r["finding_id"]: r for r in review["records"]}
    assert recs["INJ-01"]["vuln_class"] == "injection"
    assert recs["INJ-01"]["review_verdict"] == "refuted"
    assert recs["INJ-01"]["failed_dimensions"] == ["defense_effective"]
    assert recs["INJ-01"]["after"] == {"action": "dismissed"}
    assert recs["XSS-01"]["vuln_class"] == "xss"
    assert recs["XSS-01"]["review_verdict"] == "survived"
    assert recs["XSS-01"]["after"] == {"action": "kept"}
    assert recs["AUTH-01"]["vuln_class"] == "auth"
    assert recs["AUTH-01"]["review_verdict"] == "unreviewed"
    assert recs["AUTH-01"]["after"] == {"action": "kept"}

    # 每类一片 → 恰好 3 次片 agent 调用（空 queue 类零调用）
    assert sorted(calls) == ["adv-review-auth-01", "adv-review-injection-01",
                             "adv-review-xss-01"]


async def test_checkpoint_idempotent_and_unreviewed_rereview(env, monkeypatch):
    """checkpoint：终态（refuted/survived）不重审；unreviewed 的 auth 卡重跑补审
    （prior_records 跨类不串——补审只动 auth，injection/xss 不重跑）。"""
    calls: list[str] = []
    monkeypatch.setattr(activities, "run_gitnexus_verdict_agent", _make_mock(
        {"injection": REFUTED_INJ, "xss": SURVIVED_XSS,
         "auth": RuntimeError("boom")}, calls))
    await _run(env)
    assert len(calls) == 3
    inter = env["intermediate"]

    # 第二跑：injection/xss 已是终态不重审，只有 unreviewed 的 auth 卡补审
    # （auth 仍抛错 → 仍 unreviewed，queue 不剔卡）
    await _run(env)
    assert calls[3:] == ["adv-review-auth-01"]
    assert not any(c.startswith("adv-review-injection") for c in calls[3:])
    assert not any(c.startswith("adv-review-xss") for c in calls[3:])
    assert _read_queue(inter, "auth") == [AUTH_CARD]

    # 第三跑：mock 换成 auth 返回 survived——unreviewed 卡补审成功转终态；
    # injection/xss 的终态 prior_records 不受影响（跨类不串、不重跑）。
    calls2: list[str] = []
    monkeypatch.setattr(activities, "run_gitnexus_verdict_agent", _make_mock(
        {"auth": SURVIVED_AUTH}, calls2))
    await _run(env)
    assert calls2 == ["adv-review-auth-01"]
    assert _read_queue(inter, "auth") == [AUTH_CARD]  # survived 保留
    review = json.loads((inter / "adversarial_review.json").read_text())
    s = review["summary"]
    assert (s["total"], s["refuted"], s["survived"], s["unreviewed"]) == (3, 1, 2, 0)
    assert s["by_class"]["auth"] == {
        "total": 1, "refuted": 0, "survived": 1, "unreviewed": 0}
    assert s["by_class"]["injection"] == {
        "total": 1, "refuted": 1, "survived": 0, "unreviewed": 0}
    assert s["by_class"]["xss"] == {
        "total": 1, "refuted": 0, "survived": 1, "unreviewed": 0}
    recs = {r["finding_id"]: r for r in review["records"]}
    assert recs["AUTH-01"]["review_verdict"] == "survived"
    assert recs["INJ-01"]["review_verdict"] == "refuted"  # prior 原样保留
    assert recs["XSS-01"]["review_verdict"] == "survived"

    # 第四跑：全部终态 → checkpoint 完全幂等，agent 调用数零增加
    calls3: list[str] = []
    monkeypatch.setattr(activities, "run_gitnexus_verdict_agent", _make_mock(
        {"auth": SURVIVED_AUTH}, calls3))
    await _run(env)
    assert calls3 == []
    assert (json.loads((inter / "adversarial_review.json").read_text())
            ["summary"]["total"]) == 3
