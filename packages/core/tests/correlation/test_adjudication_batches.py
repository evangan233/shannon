"""裁决批组织（spec 2026-08-27 §7.1）——(service, vc) × 两类输入源，确定性纯函数。

- queue 批：service 该 vc 的 queue 条目 → confirm/downgrade
- dismissed 批：单文件条目按 vuln_class 过滤 → upgrade/maintain；全量进批，
  dismiss_reason 含可达性/暴露面的排批内前部（排序只影响优先级不影响覆盖）
- 批上限（默认 15）分片
- 防护类否决分桶（spec 2026-09-21 §3.3）：defensive 不进批（留痕），reviewable 进批
"""
from supernova_core.correlation.adjudication import (
    AdjudicationBatch, build_adjudication_batches, split_dismissed_by_service,
)


def test_queue_batches_per_service_and_vc():
    batches = build_adjudication_batches(
        {"gateway": {"injection": [{"ID": "XSS-1", "title": "t"}]},
         "order-svc": {"xss": [{"ID": "XSS-2", "title": "t"}]}},
        {})
    assert {(b.service, b.vuln_class, b.origin) for b in batches} == {
        ("gateway", "injection", "queue"),
        ("order-svc", "xss", "queue")}


def test_dismissed_batched_by_vuln_class_field():
    dismissed = {"order-svc": [
        {"ID": "D1", "vuln_class": "injection", "dismiss_reason": "judged safe"},
        {"ID": "D2", "vuln_class": "xss", "dismiss_reason": "judged safe"},
    ]}
    batches = build_adjudication_batches({}, dismissed)
    assert {(b.vuln_class, b.origin) for b in batches} == {
        ("injection", "dismissed"), ("xss", "dismissed")}


def test_dismissed_reachability_reason_sorted_first():
    """否决理由含可达性/暴露面的排批内前部——全量保留，只调顺序。"""
    dismissed = {"b": [
        {"ID": "D-safe", "vuln_class": "injection", "dismiss_reason": "sanitizer present"},
        {"ID": "D-reach", "vuln_class": "injection",
         "dismiss_reason": "internal service not reachable from entrypoint"},
        {"ID": "D-expo", "vuln_class": "injection", "dismiss_reason": "exposure internal"},
    ]}
    batches = build_adjudication_batches({}, dismissed)
    assert len(batches) == 1
    assert [f["ID"] for f in batches[0].findings] == ["D-reach", "D-expo", "D-safe"]


def test_batch_limit_splits_shards():
    entries = [{"ID": f"Q{i:02d}", "title": "t"} for i in range(17)]
    batches = build_adjudication_batches({"b": {"injection": entries}}, {},
                                         batch_limit=15)
    assert len(batches) == 2
    assert len(batches[0].findings) == 15
    assert len(batches[1].findings) == 2
    # 分片保序：第 2 片接第 1 片尾部
    assert batches[1].findings[0]["ID"] == "Q15"


def test_empty_inputs_yield_no_batches():
    assert build_adjudication_batches({}, {}) == []


def test_service_without_dismissed_gets_no_dismissed_batch():
    batches = build_adjudication_batches(
        {"gateway": {"injection": [{"ID": "A"}]}}, {"order-svc": [
            {"ID": "D1", "vuln_class": "xss", "dismiss_reason": "r"}]})
    assert all(not (b.service == "gateway" and b.origin == "dismissed")
               for b in batches)
    assert any(b.service == "order-svc" and b.origin == "dismissed" for b in batches)


# ---------------------------------------------------------------------------
# 防护类否决分桶（spec 2026-09-21 §3.3）——defensive 不进批（留痕）
# ---------------------------------------------------------------------------

def test_defensive_skipped_and_reviewable_kept():
    dismissed = {"b": [
        # 防护类：sink 处防护与调用方无关，跨仓视角翻不了 → 跳过
        {"ID": "D-param", "vuln_class": "injection",
         "dismiss_reason": "SQL 参数化查询，无拼接"},
        {"ID": "D-mask", "vuln_class": "auth",
         "dismiss_reason": "返回值已脱敏（前4+****+后4）"},
        # 可达性类：跨仓审查的目标客户 → 保留
        {"ID": "D-reach", "vuln_class": "injection",
         "dismiss_reason": "内部接口，外部不可达"},
        # 两类都不沾：宁可多审 → 保留
        {"ID": "D-other", "vuln_class": "xss", "dismiss_reason": "低置信度误报"},
        # 两类都沾：保守保留
        {"ID": "D-both", "vuln_class": "xss",
         "dismiss_reason": "内部接口且框架统一转义"},
    ]}
    kept, skipped = split_dismissed_by_service(dismissed)
    assert [f["ID"] for f in kept["b"]] == ["D-reach", "D-other", "D-both"]
    assert [s["ID"] for s in skipped] == ["D-param", "D-mask"]


def test_skipped_record_carries_audit_fields():
    dismissed = {"b": [{"ID": "D1", "vuln_class": "injection",
                        "dismiss_reason": "prepared statement 全覆盖",
                        "evidence": "a.go:10"}]}
    _, skipped = split_dismissed_by_service(dismissed)
    rec = skipped[0]
    assert rec["service"] == "b"
    assert rec["ID"] == "D1"
    assert rec["vuln_class"] == "injection"
    assert rec["dismiss_reason"] == "prepared statement 全覆盖"
    assert rec["evidence"] == "a.go:10"
    assert rec["matched_defense_hint"]      # 留痕：命中的防护关键词


def test_split_keeps_original_entries_unmodified():
    entry = {"ID": "D1", "vuln_class": "xss", "dismiss_reason": "低置信度"}
    kept, skipped = split_dismissed_by_service({"b": [entry]})
    assert kept == {"b": [entry]}
    assert skipped == []


def test_split_empty_inputs():
    kept, skipped = split_dismissed_by_service({})
    assert kept == {}
    assert skipped == []
