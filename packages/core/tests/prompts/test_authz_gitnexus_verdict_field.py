"""authz GitNexus 判词契约必须带显式 verdict 字段（vulnerable|safe）。

回归 risk_margin-20260910-041235：authz_gitnexus_judge/explore 输出契约无
verdict 字段，agent 复核出「已防护/无危害」时无结构化出口，只能把结论写进
标题文本（「水平越权（复核为已防护）：…」），卡仍以 high 进报告。旧 judge
规则更教「rejected candidates → set externally_exploitable=false」——直接
违反 CLAUDE.md §1 铁律（externally_exploitable 是可达性标签，不能被 verdict
覆写），且 authz both/ee-OR 链路会拿这个被污染的标签做 OR。

锁定三点：
1. judge/explore output 契约定义 verdict 字段，值域 vulnerable|safe；
2. judge 的 rejected 规则 = verdict="safe"，不再覆写 externally_exploitable
   （ee=false 旧信号被禁——可达性铁律）；
3. explore 的 safe 出口语义在（复核确认有防护 → verdict=safe 留档，不静默丢）。

写入侧分流由 activities._split_authz_safe 承担
（test_run_authz_gitnexus_judge.py）；merge 侧 GN-only safe drop 由
test_dual_track_merger.py::test_gitnexus_only_safe_excluded_from_union 锁定。
"""
from pathlib import Path

PROMPTS_DIR = Path(__file__).resolve().parents[4] / "prompts"


def test_authz_gitnexus_judge_defines_verdict_field():
    text = (PROMPTS_DIR / "authz_gitnexus_judge.txt").read_text()
    # output_format JSON 契约含 verdict 字段
    assert '"verdict"' in text, (
        "authz_gitnexus_judge.txt output_format 缺 verdict 字段——判 safe 无"
        "结构化出口，已防护卡会混进报告（risk_margin 回归）")
    # 值域双态在
    assert "vulnerable" in text and '"safe"' in text


def test_authz_gitnexus_judge_rejected_rule_uses_verdict_not_ee():
    """rejected 规则必须 verdict="safe"；严禁再用 externally_exploitable=false
    表达 rejected（可达性标签，CLAUDE.md §1 铁律：不能被 verdict 覆写）。"""
    text = (PROMPTS_DIR / "authz_gitnexus_judge.txt").read_text()
    assert 'verdict="safe"' in text or "verdict\": \"safe" in text, (
        "authz_gitnexus_judge.txt 缺 rejected → verdict=safe 规则")
    assert "externally_exploitable=false" not in text, (
        "authz_gitnexus_judge.txt 仍在教 rejected → externally_exploitable=false"
        "（污染可达性标签，违反 CLAUDE.md §1 铁律）")
    # ee 与 verdict 相互独立的语义声明在
    assert "reachability" in text.lower()


def test_authz_gitnexus_explore_defines_verdict_semantics():
    text = (PROMPTS_DIR / "authz_gitnexus_explore.txt").read_text()
    assert '"verdict"' in text, (
        "authz_gitnexus_explore.txt output 契约缺 verdict 字段")
    # safe 出口语义：复核确认有防护 → 留档而非静默丢/混进漏洞
    assert '"safe"' in text
    assert "archived" in text.lower()
