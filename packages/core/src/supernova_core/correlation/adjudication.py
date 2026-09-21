"""裁决批组织（spec 2026-08-27 §7.1）——发现驱动的阶段 B 输入编排，确定性纯函数。

批 = (service, vc) × 输入源（queue | dismissed）。dismissed_findings.json 是
单文件（每条含 vuln_class 字段），按字段过滤组织批；条目全量进批，
dismiss_reason 含可达性/暴露面的排批内前部（排序只影响优先级，不影响覆盖）。
批内 finding 数上限分片（防爆上下文）。

防护类否决分桶（spec 2026-09-21 §3.3）：dismiss_reason 为"参数化/脱敏/转义"
等 sink 处防护（与调用方无关，跨仓视角翻不了）的条目不进批，由调用方留痕。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# dismiss_reason 中提示"可达性/暴露面类否决"的关键词——这类是跨仓重审的
# 高优先翻案候选（spec §1 需求 3）。宽松匹配只影响批内顺序。
_REACHABILITY_HINTS = ("reach", "exposure", "可达", "暴露", "internal", "不可达")

# 防护类否决特征（spec 2026-09-21 §1.5/§3.3）：sink 处的防护独立于输入来源成立，
# 跨服务上下文翻不了案。有意不放"校验/验证"这类泛词——泛词误跳的代价是漏翻案。
_DEFENSIVE_RE = re.compile(
    r"参数化|prepared|脱敏|转义|escap|sanitiz|过滤|白名单|allowlist"
    r"|强类型|序列化|无\S{0,4}渲染|无\S{0,4}拼接|autoescape|template",
    re.I)

# 可达性特征（_REACHABILITY_HINTS 的正则形，支持"调用点/调用方"等更宽覆盖；
# 命中即保留进批——可达性类是跨仓审查的目标客户）
_REACHABILITY_RE = re.compile(
    r"reach|exposure|可达|暴露|internal|内部|不可达|未对外|无外部|仅限内网|公网|非对外"
    r"|调用点|调用方", re.I)


@dataclass
class AdjudicationBatch:
    service: str
    vuln_class: str
    origin: str                     # "queue" | "dismissed"
    findings: list[dict] = field(default_factory=list)


def _reachability_rank(reason: str | None) -> int:
    r = (reason or "").lower()
    return 0 if any(h in r for h in _REACHABILITY_HINTS) else 1


def classify_dismissed(entry: dict) -> str:
    """单条 dismissed 分类（spec 2026-09-21 §3.3）："defensive" | "reviewable"。

    防护类（sink 处防护、与调用方无关）且无任何可达性表述 → defensive；
    可达性类、两类都不沾、两类都沾 → reviewable（宁可多审，不激进漏筛）。
    """
    reason = entry.get("dismiss_reason") or ""
    if _DEFENSIVE_RE.search(reason) and not _REACHABILITY_RE.search(reason):
        return "defensive"
    return "reviewable"


def split_dismissed_by_service(
        dismissed_by_service: dict[str, list[dict]],
) -> tuple[dict[str, list[dict]], list[dict]]:
    """dismissed 条目分桶（spec 2026-09-21 §3.3）：reviewable 进批，defensive 跳过。

    返回 (kept_by_service, skipped_records)。skipped 记录带 service/ID/vuln_class/
    dismiss_reason/evidence/matched_defense_hint，供调用方落盘留痕（审计可回溯）。
    纯函数：不改写输入条目。
    """
    kept: dict[str, list[dict]] = {}
    skipped: list[dict] = []
    for service, entries in dismissed_by_service.items():
        kept_entries = []
        for e in entries:
            if classify_dismissed(e) == "defensive":
                skipped.append({
                    "service": service,
                    "ID": e.get("ID", ""),
                    "vuln_class": e.get("vuln_class", ""),
                    "dismiss_reason": e.get("dismiss_reason", ""),
                    "evidence": e.get("evidence", ""),
                    "matched_defense_hint": ", ".join(
                        dict.fromkeys(_DEFENSIVE_RE.findall(
                            e.get("dismiss_reason") or ""))),
                })
            else:
                kept_entries.append(e)
        if kept_entries:
            kept[service] = kept_entries
    return kept, skipped


def build_adjudication_batches(
    findings_by_service: dict[str, dict[str, list[dict]]],
    dismissed_by_service: dict[str, list[dict]],
    *,
    batch_limit: int = 15,
) -> list[AdjudicationBatch]:
    batches: list[AdjudicationBatch] = []
    for service, by_vc in findings_by_service.items():
        for vc, entries in by_vc.items():
            if entries:
                batches.extend(_shard(service, vc, "queue", list(entries),
                                      batch_limit))
    for service, entries in dismissed_by_service.items():
        by_vc: dict[str, list[dict]] = {}
        for e in entries:
            by_vc.setdefault(e.get("vuln_class", "unknown"), []).append(e)
        for vc, vc_entries in by_vc.items():
            vc_entries.sort(key=lambda e: _reachability_rank(e.get("dismiss_reason")))
            batches.extend(_shard(service, vc, "dismissed", vc_entries,
                                  batch_limit))
    return batches


def _shard(service: str, vc: str, origin: str,
           findings: list[dict], limit: int) -> list[AdjudicationBatch]:
    return [AdjudicationBatch(service=service, vuln_class=vc, origin=origin,
                              findings=findings[i:i + limit])
            for i in range(0, len(findings), limit)]
