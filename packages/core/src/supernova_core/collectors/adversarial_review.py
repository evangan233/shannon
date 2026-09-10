# packages/core/src/supernova_core/collectors/adversarial_review.py
"""对抗性审查裁定的输出 schema + 校验（L0-L4）——spec 2026-09-10 §4.2/§6。

哲学（对齐 validate_pocs 分层 + spec 防过驳双防线）：
- L0 lenient：verdict 别名归一、不适配维度剥离；
- L1 必填：vulnerability_id / verdict 枚举 / dimension_results 结构；
- L2 id ∈ 片内 valid_ids（防幻觉，对齐 validate_pocs）；
- L3 反驳高门槛：refuted ⟺ failed_dimensions 非空且每个 failed 维度有
  rebutted=true + file:line 证据 + rebuttal_reason 非空——不过门槛**降级
  survived**（不是拒收：agent 审了但证据不铁，保守保留漏洞，spec §6 L3）；
- L4 证据存在性校验（防幻觉证据，纯确定性零 LLM）：refuted 证据的 location
  须是 repo_root 内的相对路径（绝对路径/`..` 逃逸拒绝）+ 文件须在 repo 存在
  + snippet 归一化空白后须能在文件中子串匹配——不过同样降级。
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

# 固定 7 维度（spec §3）——代码侧单一事实源，prompt/schema 与此对齐。
_DIMENSIONS_TAINT = frozenset({
    "defense_effective", "unreachable", "attacker_uncontrolled",
    "self_impact", "platform_protection"})
REVIEW_DIMENSIONS: dict[str, frozenset[str]] = {
    "injection": _DIMENSIONS_TAINT,
    "xss": _DIMENSIONS_TAINT,
    "ssrf": _DIMENSIONS_TAINT,
    "auth": frozenset({"unreachable", "self_impact", "platform_protection",
                       "authn_enforced"}),
    "authz": frozenset({"unreachable", "self_impact", "platform_protection",
                        "authz_guard"}),
}

# run_gitnexus_verdict_agent 顶层 output schema（宽松 items——GLM 深层嵌套
# 不可靠，具体字段由 validate L0-L4 兜底，对齐 POC_AGENT_OUTPUT_SCHEMA 模式）。
ADVERSARIAL_REVIEW_AGENT_SCHEMA: dict = {
    "type": "object",
    "properties": {"cards": {"type": "array"}},
    "required": ["cards"],
}

_VERDICT_ALIASES = {
    "refuted": "refuted", "refute": "refuted", "false_positive": "refuted",
    "survived": "survived", "survive": "survived", "confirmed": "survived",
    "vulnerable": "survived", "not_refuted": "survived",
}

_CARD_FIELDS = ("vulnerability_id", "review_verdict", "dimension_results",
                "failed_dimensions", "rebuttal_reason", "survival_reason",
                "confidence")


@dataclass
class ReviewValidation:
    accepted: list[dict] = field(default_factory=list)
    rejected: list[tuple[dict, str]] = field(default_factory=list)


def _normalize_card(card: dict, applicable: frozenset[str]) -> dict | None:
    """L0/L1：字段剥离 + verdict 归一 + 不适用维度剥离。结构坏 → None（拒收）。"""
    if not isinstance(card, dict):
        return None
    out = {k: card.get(k) for k in _CARD_FIELDS}
    vid = out.get("vulnerability_id")
    if not isinstance(vid, str) or not vid.strip():
        return None
    raw_v = str(out.get("review_verdict") or "").strip().lower()
    verdict = _VERDICT_ALIASES.get(raw_v)
    if verdict is None:
        return None
    out["review_verdict"] = verdict
    dims = out.get("dimension_results")
    if not isinstance(dims, list):
        dims = []
    kept = []
    for d in dims:
        if not isinstance(d, dict):
            continue
        name = str(d.get("dimension") or "").strip()
        if name in applicable:
            kept.append({
                "dimension": name,
                "rebutted": bool(d.get("rebutted")),
                "reason": d.get("reason"),
                "evidence": d.get("evidence") if isinstance(d.get("evidence"), list) else [],
            })
    out["dimension_results"] = kept
    failed = out.get("failed_dimensions")
    if not isinstance(failed, list):
        failed = []
    out["failed_dimensions"] = [str(x) for x in failed if str(x) in applicable]
    return out


def _has_location(evidence: list) -> bool:
    return bool(evidence) and all(
        isinstance(e, dict) and isinstance(e.get("location"), str) and e["location"].strip()
        for e in evidence)


def _norm_ws(s: str) -> str:
    return " ".join(s.split())


def _evidence_exists(evidence: list, repo_root: Path) -> list[str]:
    """L4：逐条校验证据真实性，返回失败原因列表（空 = 全过）。

    含包含性校验：location 必须落在 repo_root 内——绝对路径（Path 拼接
    会被整体替换）或 `..` 逃逸一律记 problem（fix 2026-09-11 wave-1
    review），否则仓库外真实存在的文件会为幻觉证据「验证通过」。
    """
    problems: list[str] = []
    root = repo_root.resolve()
    for e in evidence:
        loc = str(e.get("location") or "")
        fname = loc.split(":")[0].strip()
        snippet = str(e.get("snippet") or "")
        fpath = repo_root / fname
        # resolve()/is_file() 对畸形路径会抛 ValueError（实证一例：null 字节
        # location → "lstat: embedded null character in path"）——按 L4 降级
        # 语义记 problem（fix 2026-09-11 review I2），不让单卡畸形炸整片。
        try:
            if fname and not fpath.resolve().is_relative_to(root):
                problems.append(f"path escapes repo root: {fname}")
                continue
            if not fname or not fpath.is_file():
                problems.append(f"file not found: {fname}")
                continue
            if not snippet:
                continue  # snippet 缺失只记 L3 层面的弱证据，L4 不重复拦
            content = _norm_ws(fpath.read_text(encoding="utf-8", errors="replace"))
        except ValueError as exc:
            problems.append(f"unreadable/invalid path {fname}: {exc}")
            continue
        except OSError as exc:
            problems.append(f"unreadable {fname}: {exc}")
            continue
        if _norm_ws(snippet) not in content:
            problems.append(f"snippet not found in {fname}")
    return problems


def validate_review_cards(
    items: list, *, valid_ids: set[str], vuln_class: str,
    repo_root: Path | None = None,
) -> ReviewValidation:
    applicable = REVIEW_DIMENSIONS.get(vuln_class, _DIMENSIONS_TAINT)
    res = ReviewValidation()
    for raw in items if isinstance(items, list) else []:
        card = _normalize_card(raw, applicable)
        if card is None:
            res.rejected.append((raw if isinstance(raw, dict) else {},
                                 "malformed card / unknown verdict"))
            continue
        vid = card["vulnerability_id"]
        if vid not in valid_ids:  # L2 幻觉 ID：整卡拒收（该卡未审成）
            res.rejected.append((card, f"id {vid} not in shard"))
            continue
        if card["review_verdict"] == "survived":
            if not (isinstance(card.get("survival_reason"), str)
                    and card["survival_reason"].strip()):
                card["survival_reason"] = "[no survival reason provided]"
            # 清洗自相矛盾输出（fix 2026-09-11 review I3）：agent 说 survived
            # 却列 failed 维度——保留会破坏「failed 非空 ⟺ refuted」不变量，
            # 且污染 web Tab 的失败维度筛选口径。
            card["failed_dimensions"] = []
            res.accepted.append(card)
            continue
        # L3：refuted 高门槛
        problems: list[str] = []
        failed = card["failed_dimensions"]
        if not failed:
            problems.append("refuted with empty failed_dimensions")
        if not (isinstance(card.get("rebuttal_reason"), str)
                and card["rebuttal_reason"].strip()):
            problems.append("refuted without rebuttal_reason")
        by_dim = {d["dimension"]: d for d in card["dimension_results"]}
        for dim in failed:
            d = by_dim.get(dim)
            if d is None or not d["rebutted"]:
                problems.append(f"{dim}: no rebutted=true dimension_result")
            elif not _has_location(d["evidence"]):
                problems.append(f"{dim}: evidence lacks file:line location")
        # L4：证据存在性（repo_root=None 跳过）
        if repo_root is not None and not problems:
            for dim in failed:
                problems.extend(
                    _evidence_exists(by_dim[dim]["evidence"], repo_root))
        if problems:
            # 降级而非拒收（spec §6 L3/L4：宁可漏反驳不误杀）
            card["review_verdict"] = "survived"
            card["failed_dimensions"] = []
            card["survival_reason"] = (
                f"[auto-degraded] refutation rejected by validation: "
                f"{'; '.join(problems)}")
            res.rejected.append((card, "; ".join(problems)))
        res.accepted.append(card)
    return res


_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)


def extract_review_payload(text: str) -> dict | None:
    """打捞兜底（对齐 extract_pocs_payload）：围栏 JSON → 裸 JSON → None。"""
    if not text:
        return None
    m = _FENCE_RE.search(text)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            return None
    return None
