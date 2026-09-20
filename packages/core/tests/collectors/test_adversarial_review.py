# packages/core/tests/collectors/test_adversarial_review.py
"""对抗审查裁定校验（L0-L4）单测——spec 2026-09-10 §4.2/§6。

L3/L4 降级语义：refuted 证据不过门槛 → 降级 survived 进 accepted（不是拒收，
agent 确实审了）；L2 幻觉 ID → 整卡拒收（该卡视作未审成）。
"""
import json
from pathlib import Path

import pytest

from supernova_core.collectors.adversarial_review import (
    ADVERSARIAL_REVIEW_AGENT_SCHEMA, REVIEW_DIMENSIONS,
    extract_review_payload, validate_review_cards,
)

TAINT = "injection"


def _ok_refuted(fid="INJ-01"):
    return {
        "vulnerability_id": fid,
        "review_verdict": "refuted",
        "dimension_results": [
            {"dimension": "defense_effective", "rebutted": True,
             "reason": "escape() 覆盖该 slot 且无再拼接",
             "evidence": [{"location": "app.js:88", "snippet": "escape(userInput)"}]},
            {"dimension": "unreachable", "rebutted": False,
             "reason": "路由已注册", "evidence": []},
        ],
        "failed_dimensions": ["defense_effective"],
        "rebuttal_reason": "defense_effective 成立：编码匹配且生效",
        "survival_reason": None,
        "confidence": "high",
    }


def _ok_survived(fid="INJ-02"):
    return {
        "vulnerability_id": fid,
        "review_verdict": "survived",
        "dimension_results": [
            {"dimension": "defense_effective", "rebutted": False,
             "reason": "无防御", "evidence": []},
        ],
        "failed_dimensions": [],
        "rebuttal_reason": None,
        "survival_reason": "各维度均无法反驳",
        "confidence": "medium",
    }


def test_schema_is_loose_top_level():
    # 宽松顶层（对齐 POC_AGENT_OUTPUT_SCHEMA 模式：GLM 深层嵌套不可靠）
    assert ADVERSARIAL_REVIEW_AGENT_SCHEMA["required"] == ["cards"]


def test_dimensions_by_class():
    # claim_mismatch（2026-09-20 加强）：全 5 类适用——扫描器声称的数据流
    # 本身不存在（source 与 sink 无连接/幻觉链）是独立于 attacker_uncontrolled
    # 的误报根因（实证 SSRF-GN-02/AUTH-VULN-11 借维度表达）
    assert REVIEW_DIMENSIONS["injection"] == frozenset({
        "defense_effective", "unreachable", "attacker_uncontrolled",
        "self_impact", "platform_protection", "claim_mismatch"})
    assert REVIEW_DIMENSIONS["auth"] == frozenset({
        "unreachable", "self_impact", "platform_protection", "authn_enforced",
        "claim_mismatch"})
    assert REVIEW_DIMENSIONS["authz"] == frozenset({
        "unreachable", "self_impact", "platform_protection", "authz_guard",
        "claim_mismatch"})


def test_valid_refuted_passes(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()  # brief 原稿漏建目录：write_text 不会创建父目录
    (repo / "app.js").write_text("const x = escape(userInput);\n", encoding="utf-8")
    res = validate_review_cards([_ok_refuted()], valid_ids={"INJ-01"},
                                vuln_class=TAINT, repo_root=repo)
    assert len(res.accepted) == 1 and res.accepted[0]["review_verdict"] == "refuted"
    assert res.rejected == []


def test_hallucinated_id_rejected():
    res = validate_review_cards([_ok_refuted("GHOST-99")], valid_ids={"INJ-01"},
                                vuln_class=TAINT)
    assert res.accepted == []
    assert len(res.rejected) == 1
    assert "GHOST-99" in res.rejected[0][1]


def test_refuted_without_evidence_degrades_to_survived():
    card = _ok_refuted()
    card["dimension_results"][0]["evidence"] = []  # 无证据
    res = validate_review_cards([card], valid_ids={"INJ-01"}, vuln_class=TAINT)
    assert res.accepted[0]["review_verdict"] == "survived"
    assert res.accepted[0]["failed_dimensions"] == []
    assert "[auto-degraded]" in res.accepted[0]["survival_reason"]
    assert len(res.rejected) == 1  # 拒因留 warning


def test_refuted_empty_failed_dimensions_degrades():
    card = _ok_refuted()
    card["failed_dimensions"] = []
    res = validate_review_cards([card], valid_ids={"INJ-01"}, vuln_class=TAINT)
    assert res.accepted[0]["review_verdict"] == "survived"


def test_l4_missing_file_degrades(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    res = validate_review_cards([_ok_refuted()], valid_ids={"INJ-01"},
                                vuln_class=TAINT, repo_root=repo)  # app.js 不存在
    assert res.accepted[0]["review_verdict"] == "survived"


def test_l4_snippet_not_in_file_degrades(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()  # brief 原稿漏建目录：write_text 不会创建父目录
    (repo / "app.js").write_text("console.log(1);\n", encoding="utf-8")
    res = validate_review_cards([_ok_refuted()], valid_ids={"INJ-01"},
                                vuln_class=TAINT, repo_root=repo)
    assert res.accepted[0]["review_verdict"] == "survived"


@pytest.mark.parametrize("seg", ["node_modules", "site-packages", "vendor"])
def test_l4_missing_dependency_file_pardoned(tmp_path: Path, seg: str):
    # G3 豁免（2026-09-20）：依赖库文件在扫描环境未安装是常态（实证
    # INJ-VULN-05 引用 node_modules/marked 的真驳回被 L4 误降级 survived），
    # 缺失不判幻觉；与 test_l4_missing_file_degrades（仓库自身文件缺失照降）
    # 形成对照
    repo = tmp_path / "repo"
    repo.mkdir()
    card = _ok_refuted()
    card["dimension_results"][0]["evidence"] = [
        {"location": f"{seg}/marked/lib/marked.js:120",
         "snippet": "output = output.replace(...)"}]
    res = validate_review_cards([card], valid_ids={"INJ-01"},
                                vuln_class=TAINT, repo_root=repo)
    assert res.accepted[0]["review_verdict"] == "refuted"
    assert res.accepted[0]["failed_dimensions"] == ["defense_effective"]


def test_l4_dependency_file_present_snippet_still_checked(tmp_path: Path):
    # 豁免只针对「文件不存在」：依赖文件真实存在时 snippet 照常校验，
    # 防豁免被当造假后门
    repo = tmp_path / "repo"
    dep = repo / "node_modules" / "marked" / "lib"
    dep.mkdir(parents=True)
    (dep / "marked.js").write_text("module.exports = {};\n", encoding="utf-8")
    card = _ok_refuted()
    card["dimension_results"][0]["evidence"] = [
        {"location": "node_modules/marked/lib/marked.js:1",
         "snippet": "escape(userInput)"}]
    res = validate_review_cards([card], valid_ids={"INJ-01"},
                                vuln_class=TAINT, repo_root=repo)
    assert res.accepted[0]["review_verdict"] == "survived"


def test_l4_skipped_when_repo_root_none():
    # repo_root=None 跳过存在性校验（测试/离线友好）
    res = validate_review_cards([_ok_refuted()], valid_ids={"INJ-01"}, vuln_class=TAINT)
    assert res.accepted[0]["review_verdict"] == "refuted"


def test_l4_absolute_path_location_degrades(tmp_path: Path):
    # L4 包含性：绝对路径 location 被拒——Path 拼接会被整体替换到仓库外，
    # 即使该文件真实存在且 snippet 匹配也不能为反驳背书
    repo = tmp_path / "repo"
    (tmp_path / "outside.js").write_text("escape(userInput);\n", encoding="utf-8")
    repo.mkdir()
    card = _ok_refuted()
    card["dimension_results"][0]["evidence"] = [
        {"location": f"{tmp_path / 'outside.js'}:1", "snippet": "escape(userInput)"}]
    res = validate_review_cards([card], valid_ids={"INJ-01"},
                                vuln_class=TAINT, repo_root=repo)
    assert res.accepted[0]["review_verdict"] == "survived"


def test_l4_parent_escape_location_degrades(tmp_path: Path):
    # L4 包含性：`..` 逃逸被拒——repo 外真实存在的文件同样不能为反驳背书
    repo = tmp_path / "repo"
    (tmp_path / "escape.js").write_text("escape(userInput);\n", encoding="utf-8")
    repo.mkdir()
    card = _ok_refuted()
    card["dimension_results"][0]["evidence"] = [
        {"location": "../escape.js:1", "snippet": "escape(userInput)"}]
    res = validate_review_cards([card], valid_ids={"INJ-01"},
                                vuln_class=TAINT, repo_root=repo)
    assert res.accepted[0]["review_verdict"] == "survived"


def test_l4_null_byte_location_degrades_not_raises(tmp_path: Path):
    # reviewer fix I2：null 字节 location 曾使 fpath.resolve() 抛未捕获
    # ValueError（"lstat: embedded null character in path"）→ 穿透片级
    # try 丢整轮审查记录；现按 L4 降级语义记 problem 走 survived 不抛
    repo = tmp_path / "repo"
    repo.mkdir()
    card = _ok_refuted()
    card["dimension_results"][0]["evidence"] = [
        {"location": "app.js\x00:1", "snippet": "escape(userInput)"}]
    res = validate_review_cards([card], valid_ids={"INJ-01"},
                                vuln_class=TAINT, repo_root=repo)
    assert res.accepted[0]["review_verdict"] == "survived"
    assert res.accepted[0]["failed_dimensions"] == []
    assert "unreadable/invalid path" in res.rejected[0][1]


def test_l4_survived_evidence_not_checked(tmp_path: Path):
    # survived 卡的证据不做存在性要求
    repo = tmp_path / "repo"
    repo.mkdir()
    card = _ok_survived()
    card["dimension_results"][0]["evidence"] = [
        {"location": "ghost.js:1", "snippet": "不存在"}]
    res = validate_review_cards([card], valid_ids={"INJ-02"},
                                vuln_class=TAINT, repo_root=repo)
    assert res.accepted[0]["review_verdict"] == "survived"


def test_inapplicable_dimension_stripped():
    # auth 卡混入 taint 专属维度 → 剥离不拒收
    card = _ok_survived()
    card["dimension_results"].append(
        {"dimension": "defense_effective", "rebutted": True, "reason": "x",
         "evidence": [{"location": "a.js:1", "snippet": "a"}]})
    res = validate_review_cards([card], valid_ids={"INJ-02"}, vuln_class="auth")
    dims = [d["dimension"] for d in res.accepted[0]["dimension_results"]]
    assert "defense_effective" not in dims


def test_verdict_alias_normalized():
    card = _ok_survived()
    card["review_verdict"] = "CONFIRMED"  # 别名归一
    res = validate_review_cards([card], valid_ids={"INJ-02"}, vuln_class=TAINT)
    assert res.accepted[0]["review_verdict"] == "survived"


def test_survived_missing_reason_gets_default_not_rejected():
    card = _ok_survived()
    card["survival_reason"] = None
    res = validate_review_cards([card], valid_ids={"INJ-02"}, vuln_class=TAINT)
    assert len(res.accepted) == 1
    assert res.accepted[0]["survival_reason"].startswith("[no survival reason")


def test_survived_failed_dimensions_cleared():
    # reviewer fix I3：survived + 非空 failed_dimensions = agent 自相矛盾输出，
    # validate 强制清零（spec §4.2「failed 非空 ⟺ refuted」完整不变量；
    # 不清洗会污染 web Tab 的失败维度筛选口径）
    card = _ok_survived()
    card["failed_dimensions"] = ["defense_effective"]
    res = validate_review_cards([card], valid_ids={"INJ-02"}, vuln_class=TAINT)
    assert len(res.accepted) == 1
    assert res.accepted[0]["review_verdict"] == "survived"
    assert res.accepted[0]["failed_dimensions"] == []


def test_extract_review_payload_swallows_fenced_json():
    text = "analysis...\n```json\n{\"cards\": [{\"vulnerability_id\": \"X\"}]}\n```"
    assert extract_review_payload(text)["cards"][0]["vulnerability_id"] == "X"
    assert extract_review_payload("no json here") is None
