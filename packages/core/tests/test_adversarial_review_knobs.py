# packages/core/tests/test_adversarial_review_knobs.py
"""对抗审查旋钮：默认值 / 畸形回退 / 开关语义（spec §4.6）。"""
from supernova_core.config.concurrency import (
    get_adversarial_review_concurrency, get_adversarial_review_max_agents,
    get_adversarial_review_max_turns, get_adversarial_review_shard_max_cards,
    is_adversarial_review_enabled,
)


def test_defaults(monkeypatch):
    for k in ("SUPERNOVA_ADVERSARIAL_REVIEW_ENABLED",
              "SUPERNOVA_ADVERSARIAL_REVIEW_CONCURRENCY",
              "SUPERNOVA_ADVERSARIAL_REVIEW_MAX_TURNS",
              "SUPERNOVA_ADVERSARIAL_REVIEW_SHARD_MAX_CARDS",
              "SUPERNOVA_ADVERSARIAL_REVIEW_MAX_AGENTS"):
        monkeypatch.delenv(k, raising=False)
    assert is_adversarial_review_enabled() is True
    assert get_adversarial_review_concurrency() == 4
    assert get_adversarial_review_max_turns() == 40
    assert get_adversarial_review_shard_max_cards() == 3
    assert get_adversarial_review_max_agents() == 50


def test_enabled_off_variants(monkeypatch):
    for v in ("0", "false", "no", "off", "FALSE"):
        monkeypatch.setenv("SUPERNOVA_ADVERSARIAL_REVIEW_ENABLED", v)
        assert is_adversarial_review_enabled() is False, v
    monkeypatch.setenv("SUPERNOVA_ADVERSARIAL_REVIEW_ENABLED", "1")
    assert is_adversarial_review_enabled() is True


def test_malformed_falls_back(monkeypatch):
    monkeypatch.setenv("SUPERNOVA_ADVERSARIAL_REVIEW_CONCURRENCY", "abc")
    monkeypatch.setenv("SUPERNOVA_ADVERSARIAL_REVIEW_MAX_AGENTS", "0")
    assert get_adversarial_review_concurrency() == 4
    assert get_adversarial_review_max_agents() == 50
