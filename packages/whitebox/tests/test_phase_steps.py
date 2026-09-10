import pytest

from supernova_whitebox.pipeline.step_intents import (
    PHASE_STEPS, StepSpec, step_names, step_intents, intent_for,
)


def test_every_declared_step_has_an_intent():
    for phase, specs in PHASE_STEPS.items():
        for spec in specs:
            assert isinstance(spec, StepSpec)
            assert spec.intent, f"step {phase}/{spec.name} 缺少 intent"


def test_intent_for_resolves_all_declared_names():
    names = {s.name for specs in PHASE_STEPS.values() for s in specs}
    for n in names:
        assert intent_for(n) is not None, f"intent_for({n!r}) 未命中"


def test_step_names_matches_phase_steps_order():
    assert step_names("setup") == ("preflight", "credential-check", "auth-validation")
    assert step_names("pre-recon") == (
        "code-index", "pre-recon", "merge-sinks", "entry-point-fusion",
        "adjudication", "framework-analysis", "frontend-mapping", "route-chain-building",
    )
    assert step_names("recon") == ("recon", "recon-context-digest")
    assert step_names("risk-scoring") == ("risk-scoring", "dataflow-hints")
    assert step_names("attack-chain") == ("attack-chain-assembly",)
    assert step_names("reporting") == (
        # 单源化时序（spec 2026-08-26-report-single-source-rendering §3）：
        # render-findings 并入 assemble；run-report-agent/verify/inject×2 退役；
        # md 由 export-report-markdown 从 report_data 确定性导出。
        "write-structured-poc",
        "assemble-report",
        "report-polish",
        "export-report-markdown",
    )


def test_vulnerability_analysis_phase_contains_adversarial_review():
    from supernova_whitebox.pipeline.step_intents import PHASE_STEPS
    names = [s.name for s in PHASE_STEPS["vulnerability-analysis"]]
    assert "adversarial-review" in names
    assert names.index("merge-dual-track") < names.index("adversarial-review") \
        < names.index("gn-finding-enrichment")


def test_step_names_unknown_phase_raises_keyerror():
    with pytest.raises(KeyError):
        step_names("does-not-exist")


def test_step_intents_parallel_to_step_names():
    for phase in PHASE_STEPS:
        names = step_names(phase)
        intents = step_intents(phase)
        assert len(names) == len(intents)


def test_intent_for_unknown_returns_none():
    assert intent_for("does-not-exist") is None
