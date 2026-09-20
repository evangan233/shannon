"""对抗审查 prompt：变量可渲染 + 姿态校准关键句在位（spec §4.1）。"""
from pathlib import Path

from supernova_core.prompts.manager import PromptManager  # 对照现有 import 路径，若不同以仓内为准

# 仓内实况：prompts/ 在仓库根（packages/core/tests/prompts/ → parents[4]），
# 对照 packages/core/tests/prompts/test_report_executive_i18n.py 的 PROMPTS_DIR。
PROMPTS_DIR = Path(__file__).resolve().parents[4] / "prompts"


def test_prompt_renders_variables():
    pm = PromptManager(PROMPTS_DIR)
    text = pm.load_sync("adversarial-review", variables={
        "VULN_CLASS": "injection", "REPO_ROOT": "/repo",
        "FINDING_CARDS": '[{"ID": "INJ-01"}]'})
    assert "injection" in text and "/repo" in text and "INJ-01" in text
    assert "{{" not in text  # 无未替换占位


def test_review_narration_lang_partial_included():
    """语言约定走 lang-aware @include（fix：审查理由英文根因），不写死单一
    语言——SUPERNOVA_AGENT_NARRATION_LANG=en 时须能切英文，对齐
    _output-language.txt 双语对模式（manager.py lang-aware fallback）。"""
    text = (PROMPTS_DIR / "adversarial-review.txt").read_text(encoding="utf-8")
    assert "@include(shared/_review-narration.txt)" in text


def test_review_narration_renders_zh(monkeypatch):
    monkeypatch.setenv("SUPERNOVA_AGENT_NARRATION_LANG", "zh")
    text = PromptManager(PROMPTS_DIR).load_sync("adversarial-review", variables={
        "VULN_CLASS": "injection", "REPO_ROOT": "/repo",
        "FINDING_CARDS": '[{"ID": "INJ-01"}]'})
    # zh 档注入中文叙述指令（reason/rebuttal_reason/survival_reason）
    assert "简体中文" in text


def test_review_narration_renders_en(monkeypatch):
    monkeypatch.setenv("SUPERNOVA_AGENT_NARRATION_LANG", "en")
    text = PromptManager(PROMPTS_DIR).load_sync("adversarial-review", variables={
        "VULN_CLASS": "injection", "REPO_ROOT": "/repo",
        "FINDING_CARDS": '[{"ID": "INJ-01"}]'})
    # en 档换英文指令且不残留中文——语言随 env 切换（设计不变量）
    assert "English" in text
    assert "简体中文" not in text


def test_repo_boundary_rules_present():
    """仓库边界铁律（2026-09-15 单仓跨服务宽容，实证 INJ-VULN-01）：边界外
    假设禁当反驳依据（无法验证 ≠ 驳倒）+ 出站转发污点调用本身是 sink +
    defense_effective/attacker_uncontrolled/platform_protection 三维度跨服务
    陷阱反例。"""
    text = (PROMPTS_DIR / "adversarial-review.txt").read_text(encoding="utf-8")
    # 总铁律：起决定作用的防御在仓库外 → 该维度不可驳
    assert "Repo boundary" in text
    assert "OUTSIDE this repository" in text
    assert "Unverifiable" in text
    # 跨服务 sink 语义：本仓不执行 ≠ 不是 sink（下游消费在可见性之外）
    assert "cross-service sink" in text.lower()
    assert "NOT a refutation" in text
    # 三维度陷阱反例锚点
    assert "EXPECT the downstream service" in text
    assert "NOT automatically attacker-uncontrolled" in text
    assert "deployment assumption" in text


def test_calibration_sentences_present():
    text = (PROMPTS_DIR / "adversarial-review.txt").read_text(encoding="utf-8")
    # 姿态校准硬规则（spec §4.1）与维度清单锚点
    assert "honest skeptic" in text
    assert "NOT a failure" in text
    # 只读工具约束（spec §4.1：只读 grep/read，禁 Task 子代理/写文件——
    # claude 引擎 bypassPermissions 下审查 agent 实际可写被扫仓库）
    assert "read-only" in text
    assert "Task" in text
    assert "Edit/Write" in text
    assert "dangerouslySetInnerHTML" in text  # platform_protection 陷阱反例
    for dim in ("defense_effective", "unreachable", "attacker_uncontrolled",
                "self_impact", "platform_protection", "authn_enforced",
                "authz_guard", "claim_mismatch"):
        assert dim in text, dim


def test_attack_path_first_methodology_present():
    """G2 攻击路径先行（2026-09-20）：逐卡先构造具体攻击路径再沿路径检验——
    defense_effective 从「防御存在」升级为「拦得住这条路径」；路径构造不出
    = claim_mismatch。对齐 OpenAnt 阶段 5 攻击者模拟（纸面推演，非黑盒）。"""
    text = (PROMPTS_DIR / "adversarial-review.txt").read_text(encoding="utf-8")
    assert "attack path" in text.lower()
    assert "claim_mismatch" in text  # 构造不出路径 → claim_mismatch 归因


def test_unreachable_nonproduction_clause_present():
    """G4 unreachable 环境性子句（2026-09-20）：非产品攻击面（测试专用/
    dev-only/功能开关关闭）算不可达成立。"""
    text = (PROMPTS_DIR / "adversarial-review.txt").read_text(encoding="utf-8")
    assert "test-only" in text
    assert "feature flag" in text
