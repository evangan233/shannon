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
                "authz_guard"):
        assert dim in text, dim
