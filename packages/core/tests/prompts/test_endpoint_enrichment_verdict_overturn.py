"""endpoint_enrichment prompt 复核翻案契约（2026-09-16 残面修复）。

endpoint-enrichment agent 深读代码富化接口表时可能确认卡实际有防护/无危害
（risk_margin-20260910-041235 实证：复核结论无结构化出口，只能写进标题文本，
卡仍以 high 进报告）。翻案出口契约锁定：
- output_format 含可选 verdict 字段 + verdict_reason；
- 单向语义：只允许翻 safe（说 vulnerable 无增量信息），不确定必须省略
  （保守宁过报，不许猜 safe）。

回填/分流行为由 whitebox test_run_endpoint_enrichment.py 锁定（单向闸门 +
SSOT 分流）；authz GN 判词契约由 test_authz_gitnexus_verdict_field.py 锁定。
"""
from pathlib import Path

PROMPTS_DIR = Path(__file__).resolve().parents[4] / "prompts"


def test_endpoint_enrichment_defines_verdict_overturn_contract():
    text = (PROMPTS_DIR / "endpoint_enrichment.txt").read_text()
    assert '"verdict"' in text, (
        "endpoint_enrichment.txt 缺 verdict 翻案字段——复核出防护的卡无结构化"
        "出口，只能把结论写进标题文本（risk_margin 回归）")
    assert '"safe"' in text
    assert "verdict_reason" in text
    # 单向 + 保守门槛语义在
    low = text.lower()
    assert "one-way" in low or "one way" in low, (
        "翻案必须声明单向（verdict 只用于翻 safe，无权翻回 vulnerable）")
    assert "uncertain" in low and "omit" in low, (
        "不确定必须省略 verdict（保守宁过报，防富化 agent 滥翻 safe 漏报）")
