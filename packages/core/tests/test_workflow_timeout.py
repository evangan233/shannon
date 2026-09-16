"""scan_budget: 单次扫描预算（获槽起算），默认 5h，env SUPERNOVA_SCAN_BUDGET_HOURS 可配。

2026-09-16 语义重构（原 workflow_run_timeout 从提交起算 3h、排队计入——批量排队
被整点收割）：排队不限时由 acquire_gate_slot 的 continue-as-new 支撑，预算只约束
获槽后的扫描段。"""
from datetime import timedelta

from supernova_core.runtime.workflow_timeout import scan_budget


def test_default_5h(monkeypatch):
    monkeypatch.delenv("SUPERNOVA_SCAN_BUDGET_HOURS", raising=False)
    assert scan_budget() == timedelta(hours=5)


def test_env_override(monkeypatch):
    monkeypatch.setenv("SUPERNOVA_SCAN_BUDGET_HOURS", "8")
    assert scan_budget() == timedelta(hours=8)


def test_malformed_falls_back(monkeypatch):
    monkeypatch.setenv("SUPERNOVA_SCAN_BUDGET_HOURS", "abc")
    assert scan_budget() == timedelta(hours=5)


def test_below_one_falls_back(monkeypatch):
    monkeypatch.setenv("SUPERNOVA_SCAN_BUDGET_HOURS", "0")
    assert scan_budget() == timedelta(hours=5)
