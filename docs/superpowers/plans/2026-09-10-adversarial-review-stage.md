# 对抗性审查阶段（adversarial-review）实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在白盒双轨合并后新增对抗性审查阶段——固定 7 维度逐卡反驳、反驳成功剔卡归档、全量审查记录落盘、web 详情页可按维度筛选查看。

**Architecture:** POC 生成同款组织形态（sink 文件聚类分片 + scan 级 Semaphore 片间并发，每片一次 `run_gitnexus_verdict_agent` 多轮 agent），插在 `run_merge_dual_track_queues` 之后、`run_gn_finding_enrichment` 之前，non-fatal。core 层放 schema/validate（L0-L4，L4 为证据存在性机器校验），whitebox 层放 activity，web 层加只读端点 + 前端 Tab。

**Tech Stack:** Python（temporal activity / pydantic 校验）/ React + SWR + Radix Tabs / pytest + vitest。

**Spec:** `docs/superpowers/specs/2026-09-10-adversarial-review-stage-design.md`（执行前必读——维度定义、口径表、降级矩阵、防过驳双防线全在 spec）。

## Global Constraints

- 双轨独立性铁律：LLM 轨 vuln agent prompt 不引确定性 hints——本阶段在合并后消费 SSOT，属第三阶段，不碰此铁律，但**不得**把本阶段任何产物喂进 LLM 轨 prompt。
- 审查降级哲学：通道失败 ≠ 判了误报——一切校验不过/agent 失败/预算超限一律保守放行（survived 降级或 unreviewed）。
- 防过驳双防线（spec §1/§4.1/§6）：L4 证据存在性校验（纯确定性）+ prompt 姿态校准（survived 是正常结论，refuted 是需 file:line 铁证的例外）。
- `BaseVulnerability`（`packages/core/src/supernova_core/models/queue_schemas.py`）**零侵入**——审查标记只挂 adversarial_review.json 与 dismissed 归档。
- 测试只跑改动相关文件（CLAUDE.md §3：全套 pytest 有预存挂起，勿广跑）。
- 前端提交前本地 `npx tsc -b`（vitest 不查类型）；本地 LogsTab 的 @types/react 双版本报错是伪影勿修。
- 仓库有并行会话在途（接口证据页 / dataflow prune）：`ScanDetail.test.tsx` 的 tab 总数断言按落地时实际数改，locales 文件可能有未合并冲突标记，编辑前先看文件现状。
- commit 消息中文、模块前缀（feat(core)/feat(web-fe)/docs…），对齐 git log 现有风格。

---

### Task 1: core 层校验模块（维度常量 + schema + validate L0-L4 + 打捞）

**Files:**
- Create: `packages/core/src/supernova_core/collectors/adversarial_review.py`
- Test: `packages/core/tests/collectors/test_adversarial_review.py`（样板：同目录 `test_poc_collector.py`）

**Interfaces:**
- Consumes: 无（首个任务）。
- Produces（Task 4 消费，签名必须一字不差）:
  - `ADVERSARIAL_REVIEW_AGENT_SCHEMA: dict`
  - `validate_review_cards(items: list, *, valid_ids: set[str], vuln_class: str, repo_root: Path | None = None) -> ReviewValidation`，其中 `ReviewValidation` 是 dataclass：`accepted: list[dict]`（裁定生效的卡，含降级改写后的）、`rejected: list[tuple[dict, str]]`（整卡拒收 + 拒因）
  - `extract_review_payload(text: str) -> dict | None`（structured_output=None 时从 agent text 打捞）
  - `REVIEW_DIMENSIONS: dict[str, frozenset[str]]`（vuln_class → 适用维度集，activity 侧不直接用但测试锁定）

- [ ] **Step 1: 写失败测试**

```python
# packages/core/tests/collectors/test_adversarial_review.py
"""对抗审查裁定校验（L0-L4）单测——spec 2026-09-10 §4.2/§6。

L3/L4 降级语义：refuted 证据不过门槛 → 降级 survived 进 accepted（不是拒收，
agent 确实审了）；L2 幻觉 ID → 整卡拒收（该卡视作未审成）。
"""
import json
from pathlib import Path

import pytest

from supernova_core.collectors.adversarial_review import (
    ADVERSARIAL_REVIEW_AGENT_SCHEMA, REVIEW_DIMENSIONS,
    extract_review_payload, validate_review_cards,
)

TAINT = "injection"


def _ok_refuted(fid="INJ-01"):
    return {
        "vulnerability_id": fid,
        "review_verdict": "refuted",
        "dimension_results": [
            {"dimension": "defense_effective", "rebutted": True,
             "reason": "escape() 覆盖该 slot 且无再拼接",
             "evidence": [{"location": "app.js:88", "snippet": "escape(userInput)"}]},
            {"dimension": "unreachable", "rebutted": False,
             "reason": "路由已注册", "evidence": []},
        ],
        "failed_dimensions": ["defense_effective"],
        "rebuttal_reason": "defense_effective 成立：编码匹配且生效",
        "survival_reason": None,
        "confidence": "high",
    }


def _ok_survived(fid="INJ-02"):
    return {
        "vulnerability_id": fid,
        "review_verdict": "survived",
        "dimension_results": [
            {"dimension": "defense_effective", "rebutted": False,
             "reason": "无防御", "evidence": []},
        ],
        "failed_dimensions": [],
        "rebuttal_reason": None,
        "survival_reason": "各维度均无法反驳",
        "confidence": "medium",
    }


def test_schema_is_loose_top_level():
    # 宽松顶层（对齐 POC_AGENT_OUTPUT_SCHEMA 模式：GLM 深层嵌套不可靠）
    assert ADVERSARIAL_REVIEW_AGENT_SCHEMA["required"] == ["cards"]


def test_dimensions_by_class():
    assert REVIEW_DIMENSIONS["injection"] == frozenset({
        "defense_effective", "unreachable", "attacker_uncontrolled",
        "self_impact", "platform_protection"})
    assert REVIEW_DIMENSIONS["auth"] == frozenset({
        "unreachable", "self_impact", "platform_protection", "authn_enforced"})
    assert REVIEW_DIMENSIONS["authz"] == frozenset({
        "unreachable", "self_impact", "platform_protection", "authz_guard"})


def test_valid_refuted_passes(tmp_path: Path):
    repo = tmp_path / "repo"
    (repo / "app.js").write_text("const x = escape(userInput);\n", encoding="utf-8")
    res = validate_review_cards([_ok_refuted()], valid_ids={"INJ-01"},
                                vuln_class=TAINT, repo_root=repo)
    assert len(res.accepted) == 1 and res.accepted[0]["review_verdict"] == "refuted"
    assert res.rejected == []


def test_hallucinated_id_rejected():
    res = validate_review_cards([_ok_refuted("GHOST-99")], valid_ids={"INJ-01"},
                                vuln_class=TAINT)
    assert res.accepted == []
    assert len(res.rejected) == 1
    assert "GHOST-99" in res.rejected[0][1]


def test_refuted_without_evidence_degrades_to_survived():
    card = _ok_refuted()
    card["dimension_results"][0]["evidence"] = []  # 无证据
    res = validate_review_cards([card], valid_ids={"INJ-01"}, vuln_class=TAINT)
    assert res.accepted[0]["review_verdict"] == "survived"
    assert res.accepted[0]["failed_dimensions"] == []
    assert "[auto-degraded]" in res.accepted[0]["survival_reason"]
    assert len(res.rejected) == 1  # 拒因留 warning


def test_refuted_empty_failed_dimensions_degrades():
    card = _ok_refuted()
    card["failed_dimensions"] = []
    res = validate_review_cards([card], valid_ids={"INJ-01"}, vuln_class=TAINT)
    assert res.accepted[0]["review_verdict"] == "survived"


def test_l4_missing_file_degrades(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    res = validate_review_cards([_ok_refuted()], valid_ids={"INJ-01"},
                                vuln_class=TAINT, repo_root=repo)  # app.js 不存在
    assert res.accepted[0]["review_verdict"] == "survived"


def test_l4_snippet_not_in_file_degrades(tmp_path: Path):
    repo = tmp_path / "repo"
    (repo / "app.js").write_text("console.log(1);\n", encoding="utf-8")
    res = validate_review_cards([_ok_refuted()], valid_ids={"INJ-01"},
                                vuln_class=TAINT, repo_root=repo)
    assert res.accepted[0]["review_verdict"] == "survived"


def test_l4_skipped_when_repo_root_none():
    # repo_root=None 跳过存在性校验（测试/离线友好）
    res = validate_review_cards([_ok_refuted()], valid_ids={"INJ-01"}, vuln_class=TAINT)
    assert res.accepted[0]["review_verdict"] == "refuted"


def test_l4_survived_evidence_not_checked(tmp_path: Path):
    # survived 卡的证据不做存在性要求
    repo = tmp_path / "repo"
    repo.mkdir()
    card = _ok_survived()
    card["dimension_results"][0]["evidence"] = [
        {"location": "ghost.js:1", "snippet": "不存在"}]
    res = validate_review_cards([card], valid_ids={"INJ-02"},
                                vuln_class=TAINT, repo_root=repo)
    assert res.accepted[0]["review_verdict"] == "survived"


def test_inapplicable_dimension_stripped():
    # auth 卡混入 taint 专属维度 → 剥离不拒收
    card = _ok_survived()
    card["dimension_results"].append(
        {"dimension": "defense_effective", "rebutted": True, "reason": "x",
         "evidence": [{"location": "a.js:1", "snippet": "a"}]})
    res = validate_review_cards([card], valid_ids={"INJ-02"}, vuln_class="auth")
    dims = [d["dimension"] for d in res.accepted[0]["dimension_results"]]
    assert "defense_effective" not in dims


def test_verdict_alias_normalized():
    card = _ok_survived()
    card["review_verdict"] = "CONFIRMED"  # 别名归一
    res = validate_review_cards([card], valid_ids={"INJ-02"}, vuln_class=TAINT)
    assert res.accepted[0]["review_verdict"] == "survived"


def test_survived_missing_reason_gets_default_not_rejected():
    card = _ok_survived()
    card["survival_reason"] = None
    res = validate_review_cards([card], valid_ids={"INJ-02"}, vuln_class=TAINT)
    assert len(res.accepted) == 1
    assert res.accepted[0]["survival_reason"].startswith("[no survival reason")


def test_extract_review_payload_swallows_fenced_json():
    text = "analysis...\n```json\n{\"cards\": [{\"vulnerability_id\": \"X\"}]}\n```"
    assert extract_review_payload(text)["cards"][0]["vulnerability_id"] == "X"
    assert extract_review_payload("no json here") is None
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cd /root/ft-codescan/packages/core && python -m pytest tests/collectors/test_adversarial_review.py -v`
Expected: FAIL（ModuleNotFoundError: adversarial_review）

- [ ] **Step 3: 实现模块**

```python
# packages/core/src/supernova_core/collectors/adversarial_review.py
"""对抗性审查裁定的输出 schema + 校验（L0-L4）——spec 2026-09-10 §4.2/§6。

哲学（对齐 validate_pocs 分层 + spec 防过驳双防线）：
- L0 lenient：verdict 别名归一、不适配维度剥离；
- L1 必填：vulnerability_id / verdict 枚举 / dimension_results 结构；
- L2 id ∈ 片内 valid_ids（防幻觉，对齐 validate_pocs）；
- L3 反驳高门槛：refuted ⟺ failed_dimensions 非空且每个 failed 维度有
  rebutted=true + file:line 证据 + rebuttal_reason 非空——不过门槛**降级
  survived**（不是拒收：agent 审了但证据不铁，保守保留漏洞，spec §6 L3）；
- L4 证据存在性校验（防幻觉证据，纯确定性零 LLM）：refuted 证据的文件须在
  repo 存在 + snippet 归一化空白后须能在文件中子串匹配——不过同样降级。
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
    """L4：逐条校验证据真实性，返回失败原因列表（空 = 全过）。"""
    problems: list[str] = []
    for e in evidence:
        loc = str(e.get("location") or "")
        fname = loc.split(":")[0].strip()
        snippet = str(e.get("snippet") or "")
        fpath = repo_root / fname
        if not fname or not fpath.is_file():
            problems.append(f"file not found: {fname}")
            continue
        if not snippet:
            continue  # snippet 缺失只记 L3 层面的弱证据，L4 不重复拦
        try:
            content = _norm_ws(fpath.read_text(encoding="utf-8", errors="replace"))
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
```

注意：降级分支里 `res.rejected.append((card, ...))` 与 `res.accepted.append(card)` 是**同一对象**——accepted 里是降级改写后的卡，rejected 条目仅供 warning 记账（对齐 POC `res.rejected` 的用法）。测试 `test_refuted_without_evidence_degrades_to_survived` 依赖此语义。

- [ ] **Step 4: 跑测试确认全绿**

Run: `cd /root/ft-codescan/packages/core && python -m pytest tests/collectors/test_adversarial_review.py -v`
Expected: 13 passed

- [ ] **Step 5: Commit**

```bash
git add packages/core/src/supernova_core/collectors/adversarial_review.py packages/core/tests/collectors/test_adversarial_review.py
git commit -m "feat(core): 对抗审查裁定校验模块——固定7维度适用表+宽松agent schema+validate L0-L4(幻觉ID拒收/refuted证据门槛降级survived/L4文件存在+snippet归一化匹配打幻觉)+text打捞"
```

---

### Task 2: concurrency 旋钮（5 个）

**Files:**
- Modify: `packages/core/src/supernova_core/config/concurrency.py`（追加在文件尾部）
- Test: Create `packages/core/tests/test_adversarial_review_knobs.py`

**Interfaces:**
- Consumes: 同文件既有 `_get_max_turns(key, default)` 私有 helper 与 `ws_getenv`。
- Produces（Task 4 消费）:
  - `is_adversarial_review_enabled() -> bool`
  - `get_adversarial_review_concurrency() -> int`（默认 4）
  - `get_adversarial_review_max_turns() -> int`（默认 40）
  - `get_adversarial_review_shard_max_cards() -> int`（默认 3）
  - `get_adversarial_review_max_agents() -> int`（默认 50）

- [ ] **Step 1: 写失败测试**

```python
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
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cd /root/ft-codescan/packages/core && python -m pytest tests/test_adversarial_review_knobs.py -v`
Expected: FAIL（ImportError）

- [ ] **Step 3: 实现（追加到 concurrency.py 尾部）**

```python
# ── 对抗性审查阶段旋钮（spec 2026-09-10 §4.6）──

_ADVERSARIAL_REVIEW_CONCURRENCY_DEFAULT = 4
_ADVERSARIAL_REVIEW_MAX_TURNS_DEFAULT = 40
_ADVERSARIAL_REVIEW_SHARD_MAX_DEFAULT = 3
_ADVERSARIAL_REVIEW_MAX_AGENTS_DEFAULT = 50


def is_adversarial_review_enabled() -> bool:
    """SUPERNOVA_ADVERSARIAL_REVIEW_ENABLED（默认开）：白盒合并后对抗审查总开关。
    经 ws_getenv 支持 per-workspace 覆盖。"""
    raw = ws_getenv("SUPERNOVA_ADVERSARIAL_REVIEW_ENABLED")
    if raw is None:
        return True
    return raw.strip().lower() not in ("0", "false", "no", "off")


def get_adversarial_review_concurrency() -> int:
    """片 agent 并发上限（scan 级共享 Semaphore，类间+片间统一限流防 429 放大）。"""
    return _int_env_or("SUPERNOVA_ADVERSARIAL_REVIEW_CONCURRENCY",
                       _ADVERSARIAL_REVIEW_CONCURRENCY_DEFAULT)


def get_adversarial_review_max_turns() -> int:
    """片 agent turn 预算（默认 40，对齐 POC 片换算：≤3 卡/片 × ~9 turns/卡 + 余量）。"""
    return _get_max_turns("SUPERNOVA_ADVERSARIAL_REVIEW_MAX_TURNS",
                          _ADVERSARIAL_REVIEW_MAX_TURNS_DEFAULT)


def get_adversarial_review_shard_max_cards() -> int:
    """片大小上限（同 sink 文件超限裂片，对齐 get_poc_shard_max_cards 模式）。"""
    return _int_env_or("SUPERNOVA_ADVERSARIAL_REVIEW_SHARD_MAX_CARDS",
                       _ADVERSARIAL_REVIEW_SHARD_MAX_DEFAULT)


def get_adversarial_review_max_agents() -> int:
    """预算护栏：超出片数的卡 unreviewed 保守放行（对齐 CHAIN_VERDICT_MAX_AGENTS）。"""
    return _int_env_or("SUPERNOVA_ADVERSARIAL_REVIEW_MAX_AGENTS",
                       _ADVERSARIAL_REVIEW_MAX_AGENTS_DEFAULT)


def _int_env_or(key: str, default: int) -> int:
    raw = ws_getenv(key)
    if raw is None:
        return default
    try:
        val = int(raw)
    except ValueError:
        _log.warning("%s=%r not an int; falling back to %d", key, raw, default)
        return default
    if val < 1:
        _log.warning("%s=%d must be >=1; falling back to %d", key, val, default)
        return default
    return val
```

注：若同文件已有等价 `_int_env_or` 类 helper（先 grep），复用之而不是重复定义。

- [ ] **Step 4: 跑测试确认全绿**

Run: `cd /root/ft-codescan/packages/core && python -m pytest tests/test_adversarial_review_knobs.py -v`
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add packages/core/src/supernova_core/config/concurrency.py packages/core/tests/test_adversarial_review_knobs.py
git commit -m "feat(core): 对抗审查 5 旋钮——ENABLED 默认开/CONCURRENCY 4/MAX_TURNS 40/SHARD_MAX 3/MAX_AGENTS 50,ws_getenv per-workspace,畸形回退不 crash"
```

---

### Task 3: prompt 文件

**Files:**
- Create: `prompts/adversarial-review.txt`
- Test: Create `packages/core/tests/prompts/test_adversarial_review_prompt.py`

**Interfaces:**
- Consumes: 无。
- Produces: prompt 模板名 `adversarial-review`（Task 4 经 `PromptManager.load_sync("adversarial-review", variables={...})` 加载），变量 `{{VULN_CLASS}}` / `{{REPO_ROOT}}` / `{{FINDING_CARDS}}`。

- [ ] **Step 1: 写失败测试**

```python
# packages/core/tests/prompts/test_adversarial_review_prompt.py
"""对抗审查 prompt：变量可渲染 + 姿态校准关键句在位（spec §4.1）。"""
from pathlib import Path

from supernova_core.prompts.manager import PromptManager  # 对照现有 import 路径，若不同以仓内为准

PROMPTS_DIR = Path(__file__).resolve().parents[3] / "prompts"


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
    assert "dangerouslySetInnerHTML" in text  # platform_protection 陷阱反例
    for dim in ("defense_effective", "unreachable", "attacker_uncontrolled",
                "self_impact", "platform_protection", "authn_enforced",
                "authz_guard"):
        assert dim in text, dim
```

注：`PromptManager` 的 import 路径以仓内既有用法为准（`packages/whitebox/src/supernova_whitebox/pipeline/activities.py:827` 一带有 `from ... import PromptManager` 的现成 import，照抄其模块路径；若 core tests 无法 import whitebox 侧类，则测试放 `packages/whitebox/tests/` 并把断言留在同一文件）。

- [ ] **Step 2: 跑测试确认失败**

Run: `cd /root/ft-codescan/packages/core && python -m pytest tests/prompts/test_adversarial_review_prompt.py -v`
Expected: FAIL（FileNotFoundError: adversarial-review.txt）

- [ ] **Step 3: 写 prompt 全文**

```
You are an Adversarial Reviewer — an honest skeptic performing adversarial
review of vulnerability findings in REPO_ROOT. Your job is to TRY HARD to
refute each finding (prove it is a false positive), and report HONESTLY what
you find. You are NOT a defense attorney that must win: a finding that
survives your honest refutation attempts is the NORMAL outcome.

<calibration_rules>
- "survived" is a normal and common conclusion (NOT a failure). "refuted" is
  the EXCEPTION that requires hard evidence.
- Do not refute for the sake of refuting. If you cannot find concrete code
  evidence, honestly return survived.
- Evidence MUST come from code you actually read in THIS session (grep/read).
  Never fabricate file:line or snippets from memory or from the finding card's
  own claims.
- Not-vulnerable conclusions need the SAME rigor as vulnerable ones: cite
  file:line evidence for every defense you claim to exist.
</calibration_rules>

<task>
Vulnerability class: {{VULN_CLASS}}
Repository root: {{REPO_ROOT}}

Below are finding cards from the merged dual-track queue. For EACH card,
attempt refutation along EVERY applicable dimension (see below), then judge.
Every card gets exactly one verdict card in your output — do not skip or merge.

FINDING CARDS:
{{FINDING_CARDS}}
</task>

<dimensions>
Attempt each dimension applicable to {{VULN_CLASS}}. A dimension "rebutted":
true means you found hard evidence the finding fails ON THAT dimension.

For injection/xss/ssrf:
- defense_effective: a sanitizer/encoding actually exists on the tainted path,
  matches THIS slot/render_context, and no concatenation reintroduces taint
  after it. TRAP: do NOT count "framework default escaping" if the sink uses
  an escape bypass (dangerouslySetInnerHTML / v-html / |safe filter / direct
  innerHTML assignment / eval / template string into command).
- unreachable: the route is not registered / the param is not bound / the
  code path is dead / preconditions cannot be satisfied.
- attacker_uncontrolled: the sink argument is a constant or server-generated
  — the attacker cannot control it.
- self_impact: the "victim" is only the attacker themselves (no third-party
  victim; attacker editing their own data is not a vulnerability).

For all classes:
- platform_protection: a platform-level control genuinely contains the
  impact (same-origin policy, CSP that blocks exfiltration for THIS sink,
  cloud bucket ACLs). TRAP: "the framework escapes by default" is NOT valid
  here for bypass sinks (see above).

For auth:
- authn_enforced: authentication actually exists on this path and cannot be
  bypassed (middleware order, route guard coverage).

For authz:
- authz_guard: a role/owner check actually covers this operation (middleware,
  ownership scoping in the query, policy layer).

Dimensions NOT listed for {{VULN_CLASS}} do not apply — omit them.
</dimensions>

<methodology>
For each card:
1. Read the card's claimed sink/endpoint/dataflow.
2. For EVERY applicable dimension, actually read the code (grep/read) and
   try to refute. Record per-dimension: rebutted true/false + reason +
   evidence (file:line + snippet you read).
3. Only after trying all applicable dimensions, judge:
   - "refuted": at least one dimension rebutted with hard evidence. Fill
     failed_dimensions (the rebutted dimension keys) and rebuttal_reason
     (the full argument). Every failed dimension MUST cite file:line.
   - "survived": no dimension rebutted. Fill survival_reason (why each
     refutation attempt failed).
4. witness quality: prefer reading the exact sink line and any middleware
   between entry and sink before concluding.
</methodology>

<output-format>
Return a single JSON object:
{"cards": [{
  "vulnerability_id": "<ID from the finding card>",
  "review_verdict": "refuted" | "survived",
  "dimension_results": [
    {"dimension": "<key>", "rebutted": true|false, "reason": "...",
     "evidence": [{"location": "file.ext:123", "snippet": "exact code"}]}
  ],
  "failed_dimensions": ["<key>", ...],
  "rebuttal_reason": "<required when refuted: full argument>",
  "survival_reason": "<required when survived: why every dimension failed to refute>",
  "confidence": "high" | "medium" | "low"
}]}
Rules:
- EVERY finding card in the input gets exactly one output card.
- refuted requires failed_dimensions non-empty AND per-dimension
  rebutted=true AND evidence with file:line — otherwise return survived.
- Location format: relative path from repo root with line, e.g. "app.js:88".
</output-format>
```

- [ ] **Step 4: 跑测试确认全绿**

Run: `cd /root/ft-codescan/packages/core && python -m pytest tests/prompts/test_adversarial_review_prompt.py -v`
Expected: 2 passed

- [ ] **Step 5: Commit**

```bash
git add prompts/adversarial-review.txt packages/core/tests/prompts/test_adversarial_review_prompt.py
git commit -m "feat(prompts): 对抗审查 agent prompt——诚实怀疑者姿态校准(survived 非失败/反驳需铁证/禁造证据)+7维度判据含陷阱反例+逐卡一裁定输出契约"
```

---

### Task 4: whitebox activity `run_adversarial_review`

**Files:**
- Modify: `packages/whitebox/src/supernova_whitebox/pipeline/activities.py`（追加；复用同文件 `_sink_file_key` :2388 / `_group_poc_targets` :2416 / `_QUEUE_FILES` / `resolve_intermediate` / `atomic_write_json` 等）
- Test: Create `packages/whitebox/tests/test_adversarial_review_activity.py`（样板：`test_poc_agent_sharding.py` + `test_findings_activity.py` 的 tmp_path 模式）

**Interfaces:**
- Consumes:
  - Task 1: `ADVERSARIAL_REVIEW_AGENT_SCHEMA` / `validate_review_cards` / `extract_review_payload`（from `supernova_core.collectors.adversarial_review`）
  - Task 2: `is_adversarial_review_enabled` / `get_adversarial_review_concurrency` / `get_adversarial_review_max_turns` / `get_adversarial_review_shard_max_cards` / `get_adversarial_review_max_agents`
  - Task 3: `PromptManager(...).load_sync("adversarial-review", variables=...)`
  - 既有：`run_gitnexus_verdict_agent(prompt=, repo_path=, structured_output_schema=, audit_session=, provider_config=, max_turns=, agent_name=) -> ClaudeRunResult`（`.structured_output` / `.text`）；`dismissed_archive.append_dismissed(path, entries)`
- Produces（Task 5 workflow 消费）: activity 函数 `run_adversarial_review(input: ActivityInput) -> None`；产物 `intermediate/adversarial_review.json`（Task 6 web 端点消费）。

- [ ] **Step 1: 写失败测试**

```python
# packages/whitebox/tests/test_adversarial_review_activity.py
"""run_adversarial_review activity 单测——mock run_gitnexus_verdict_agent，
真文件系统（tmp_path 建五类 queue + repo 源文件），验证：
分片复用 / checkpoint 幂等 / refuted 剔卡+归档 / 降级矩阵 / 产物 schema。
"""
import json
from pathlib import Path

import pytest

from supernova_whitebox.pipeline import activities


@pytest.fixture
def env(tmp_path: Path, monkeypatch):
    """最小扫描目录：deliverables/whitebox/intermediate + injection queue 一卡。"""
    dlv = tmp_path / "deliverables" / "whitebox"
    inter = dlv / "intermediate"
    inter.mkdir(parents=True)
    repo = tmp_path / "repo"
    (repo / "app.js").write_text("const x = escape(userInput);\n", encoding="utf-8")
    (inter / "injection_exploitation_queue.json").write_text(json.dumps({
        "vulnerabilities": [{
            "ID": "INJ-01", "title": "t", "verdict": "vulnerable",
            "source_track": "llm", "confidence": "high",
            "sink_call": "eval() — app.js:32",
        }]}), encoding="utf-8")
    for vc in ("xss", "ssrf", "authz", "auth"):
        (inter / f"{vc}_exploitation_queue.json").write_text(
            json.dumps({"vulnerabilities": []}), encoding="utf-8")
    monkeypatch.setattr(activities, "get_audit_session", lambda: None)
    # 直接调内部函数 _run_adversarial_review_for_classes 以绕过 activity 运行时
    return {"deliverables": dlv, "repo": repo, "intermediate": inter}


def _agent_result(payload: dict | None, text: str = ""):
    from types import SimpleNamespace
    return SimpleNamespace(structured_output=payload, text=text)


REFUTED = {"cards": [{
    "vulnerability_id": "INJ-01", "review_verdict": "refuted",
    "dimension_results": [
        {"dimension": "defense_effective", "rebutted": True, "reason": "r",
         "evidence": [{"location": "app.js:1",
                       "snippet": "const x = escape(userInput);"}]}],
    "failed_dimensions": ["defense_effective"],
    "rebuttal_reason": "escape covers the slot",
    "survival_reason": None, "confidence": "high"}]}


async def test_refuted_card_removed_and_archived(env, monkeypatch):
    async def fake_agent(**kw):
        return _agent_result(REFUTED)
    monkeypatch.setattr(activities, "run_gitnexus_verdict_agent", fake_agent)
    await activities._run_adversarial_review_for_classes(
        deliverables=env["deliverables"], repo_path=str(env["repo"]),
        provider_config=None)
    q = json.loads((env["intermediate"] /
                    "injection_exploitation_queue.json").read_text())
    assert q["vulnerabilities"] == []  # 剔除
    dismissed = json.loads((env["intermediate"] /
                            "dismissed_findings.json").read_text())
    assert dismissed["dismissed"][0]["ID"] == "INJ-01"
    assert dismissed["dismissed"][0]["dismissed_at_stage"] == "adversarial-review"
    review = json.loads((env["intermediate"] /
                         "adversarial_review.json").read_text())
    rec = review["records"][0]
    assert rec["before"]["ID"] == "INJ-01"
    assert rec["review_verdict"] == "refuted"
    assert rec["failed_dimensions"] == ["defense_effective"]
    assert rec["after"] == {"action": "dismissed"}
    assert review["summary"]["refuted"] == 1


async def test_checkpoint_skips_finalized(env, monkeypatch):
    calls = []
    async def fake_agent(**kw):
        calls.append(kw)
        return _agent_result(REFUTED)
    monkeypatch.setattr(activities, "run_gitnexus_verdict_agent", fake_agent)
    await activities._run_adversarial_review_for_classes(
        deliverables=env["deliverables"], repo_path=str(env["repo"]),
        provider_config=None)
    await activities._run_adversarial_review_for_classes(  # 重跑：终态不重审
        deliverables=env["deliverables"], repo_path=str(env["repo"]),
        provider_config=None)
    assert len(calls) == 1


async def test_agent_failure_leaves_unreviewed(env, monkeypatch):
    async def fake_agent(**kw):
        raise RuntimeError("boom")
    monkeypatch.setattr(activities, "run_gitnexus_verdict_agent", fake_agent)
    await activities._run_adversarial_review_for_classes(
        deliverables=env["deliverables"], repo_path=str(env["repo"]),
        provider_config=None)
    q = json.loads((env["intermediate"] /
                    "injection_exploitation_queue.json").read_text())
    assert len(q["vulnerabilities"]) == 1  # 保守放行
    review = json.loads((env["intermediate"] /
                         "adversarial_review.json").read_text())
    assert review["records"][0]["review_verdict"] == "unreviewed"
    assert review["records"][0]["after"] == {"action": "kept"}
```

注：asyncio 测试模式照抄 `test_poc_agent_sharding.py`（若其用 `@pytest.mark.asyncio` 或 anyio，照抄同款 marker；conftest 已有 event_loop fixture 的可能性大，先看样板）。`_run_adversarial_review_for_classes` 是 activity 的可测内核（activity 壳 `run_adversarial_review` 只做 ensure_audit_session/_get_paths/classify_error 包裹，对齐 `write_agent_poc` → `_write_agent_pocs` 的拆法）。

- [ ] **Step 2: 跑测试确认失败**

Run: `cd /root/ft-codescan/packages/whitebox && python -m pytest tests/test_adversarial_review_activity.py -v`
Expected: FAIL（AttributeError: _run_adversarial_review_for_classes）

- [ ] **Step 3: 实现 activity（追加到 activities.py，`write_agent_poc` 附近）**

```python
@activity.defn
async def run_adversarial_review(input: ActivityInput) -> None:
    """对抗性审查（spec 2026-09-10）：merge 后逐卡反驳，refuted 剔卡+归档。

    POC 同款组织：sink 文件聚类分片 + scan 级 Semaphore 并发；片失败/
    打捞失败/预算超限 → unreviewed 保守放行（通道失败 ≠ 判了误报）。
    non-fatal（workflow 层包裹），开关关时直读 return。
    """
    import logging
    log = logging.getLogger(__name__)
    try:
        await ensure_audit_session(input)
        _, deliverables, _ = _get_paths(input)
        await _run_adversarial_review_for_classes(
            deliverables=deliverables, repo_path=str(input.repo_path),
            provider_config=input.provider_config)
    except Exception as exc:  # noqa: BLE001 — non-fatal：审查挂了保守放行
        log.warning("adversarial review failed (non-blocking): %s", exc)


async def _run_adversarial_review_for_classes(
    *, deliverables: Path, repo_path: str, provider_config: dict | None,
) -> None:
    from supernova_core.collectors.adversarial_review import (
        ADVERSARIAL_REVIEW_AGENT_SCHEMA, extract_review_payload,
        validate_review_cards,
    )
    from supernova_core.config.concurrency import (
        get_adversarial_review_concurrency, get_adversarial_review_max_agents,
        get_adversarial_review_max_turns, get_adversarial_review_shard_max_cards,
        is_adversarial_review_enabled,
    )
    from supernova_core.services.dismissed_archive import append_dismissed
    from supernova_core.utils.atomic_write import atomic_write_json

    if not is_adversarial_review_enabled():
        return
    prompts_dir = Path(__file__).resolve().parents[5] / "prompts"
    prompt_manager = PromptManager(prompts_dir)
    max_turns = get_adversarial_review_max_turns()
    shard_max = get_adversarial_review_shard_max_cards()
    budget = get_adversarial_review_max_agents()
    sem = asyncio.Semaphore(get_adversarial_review_concurrency())
    review_path = deliverables / "whitebox" / "intermediate" / "adversarial_review.json"
    dismissed_path = deliverables / "whitebox" / "intermediate" / "dismissed_findings.json"

    # 产物即 checkpoint：已有终态（survived/refuted）记录的卡不重审
    prior_records: dict[str, dict] = {}
    if review_path.exists():
        try:
            prior = json.loads(review_path.read_text(encoding="utf-8"))
            for r in prior.get("records", []):
                if isinstance(r, dict) and r.get("review_verdict") in ("survived", "refuted"):
                    prior_records[str(r.get("finding_id"))] = r
        except (json.JSONDecodeError, OSError):
            pass  # 损坏 → 当作无 checkpoint 全量重审

    launched = 0  # 预算护栏计数

    async def _one_class(vuln_class: str) -> tuple[list[dict], list[dict], list[dict]]:
        """返回 (kept_entries, new_records, dismissed_entries)，由调用方统一落盘。"""
        queue_path = resolve_intermediate(deliverables / "whitebox",
                                          f"{vuln_class}_exploitation_queue.json")
        if queue_path is None or not queue_path.exists():
            return [], [], []
        data = json.loads(queue_path.read_text(encoding="utf-8"))
        entries = data.get("vulnerabilities") if isinstance(data, dict) else None
        if not isinstance(entries, list):
            return [], [], []
        targets = [e for e in entries
                   if isinstance(e, dict)
                   and e.get("verdict") != "not_vulnerable"
                   and str(e.get("ID", "")) not in prior_records]
        shards = _group_poc_targets(targets, shard_max)

        async def _one_shard(idx: int, shard: list[dict]) -> list[tuple[dict, dict]]:
            """单片 → 该片 (entry, record) 对；失败 → 全部 unreviewed。"""
            nonlocal launched
            agent_name = f"adv-review-{vuln_class}-{idx + 1:02d}"
            by_id = {str(e.get("ID")): e for e in shard}
            try:
                async with sem:
                    if launched >= budget:
                        return [(e, _record(vuln_class, e, "unreviewed", None,
                                            {"action": "kept"}))
                                for e in shard]
                    launched += 1
                    prompt = prompt_manager.load_sync(
                        "adversarial-review", variables={
                            "VULN_CLASS": vuln_class,
                            "REPO_ROOT": repo_path,
                            "FINDING_CARDS": json.dumps(
                                shard, ensure_ascii=False, indent=2),
                        })
                    result = await run_gitnexus_verdict_agent(
                        prompt=prompt, repo_path=repo_path,
                        structured_output_schema=ADVERSARIAL_REVIEW_AGENT_SCHEMA,
                        audit_session=get_audit_session(),
                        provider_config=provider_config,
                        max_turns=max_turns, agent_name=agent_name)
            except Exception as exc:  # noqa: BLE001 — 诚实缺失
                logger.warning("adversarial review: %s failed: %s", agent_name, exc)
                return [(e, _record(vuln_class, e, "unreviewed", None,
                                    {"action": "kept"})) for e in shard]
            raw = result.structured_output
            if raw is None and getattr(result, "text", None):
                raw = extract_review_payload(result.text)
            cards = raw.get("cards") if isinstance(raw, dict) else None
            if not cards:
                return [(e, _record(vuln_class, e, "unreviewed", None,
                                    {"action": "kept"})) for e in shard]
            res = validate_review_cards(
                cards, valid_ids=set(by_id), vuln_class=vuln_class,
                repo_root=Path(repo_path))
            for _rej, reason in res.rejected:
                logger.warning("adversarial review: %s card rejected: %s",
                               agent_name, reason)
            out: list[tuple[dict, dict]] = []
            seen = set()
            for card in res.accepted:
                fid = card["vulnerability_id"]
                if fid in seen or fid not in by_id:
                    continue
                seen.add(fid)
                entry = by_id[fid]
                verdict = card["review_verdict"]
                after = ({"action": "dismissed"} if verdict == "refuted"
                         else {"action": "kept"})
                out.append((entry, _record(vuln_class, entry, verdict, card, after)))
            for e in shard:  # agent 漏答的卡 → unreviewed
                if str(e.get("ID")) not in seen:
                    out.append((e, _record(vuln_class, e, "unreviewed", None,
                                           {"action": "kept"})))
            return out

        pairs = [p for r in await asyncio.gather(
            *(_one_shard(i, s) for i, s in enumerate(shards))) for p in r]
        kept = [e for e in entries if e not in [p[0] for p in pairs
                                                if p[1]["review_verdict"] == "refuted"]]
        dismissed = [_dismissed_entry(vuln_class, e, p[1])
                     for e, p in ((p[0], p[1]) for p in pairs)
                     if p[1]["review_verdict"] == "refuted"]
        return kept, [p[1] for p in pairs], dismissed

    def _record(vc: str, entry: dict, verdict: str, card: dict | None,
                after: dict) -> dict:
        card = card or {}
        return {
            "vuln_class": vc,
            "finding_id": str(entry.get("ID", "")),
            "reviewed_at": datetime.now(timezone.utc).isoformat(),
            "before": {k: entry.get(k) for k in
                       ("ID", "title", "verdict", "merge_source",
                        "confidence", "source_track")},
            "review_verdict": verdict,
            "dimension_results": card.get("dimension_results", []),
            "failed_dimensions": card.get("failed_dimensions", []),
            "rebuttal_reason": card.get("rebuttal_reason"),
            "survival_reason": card.get("survival_reason"),
            "evidence": [e for d in card.get("dimension_results", [])
                         for e in d.get("evidence", [])],
            "confidence": card.get("confidence"),
            "after": after,
        }

    def _dismissed_entry(vc: str, entry: dict, record: dict) -> dict:
        dims = ",".join(record.get("failed_dimensions") or [])
        reason = str(record.get("rebuttal_reason") or "")[:500]
        return {
            "ID": entry.get("ID", ""),
            "source_track": entry.get("source_track"),
            "vuln_class": vc,
            "title": entry.get("title"),
            "dismiss_reason": f"adversarial-review[{dims}]: {reason}",
            "evidence": record.get("evidence"),
            "confidence": record.get("confidence") or entry.get("confidence"),
            "source": entry.get("source"),
            "sink_call": entry.get("sink_call"),
            "dismissed_at_stage": "adversarial-review",
        }

    from datetime import datetime, timezone
    all_records: list[dict] = list(prior_records.values())
    for vc in ("injection", "xss", "ssrf", "authz", "auth"):
        kept, records, dismissed = await _one_class(vc)
        queue_path = resolve_intermediate(deliverables / "whitebox",
                                          f"{vc}_exploitation_queue.json")
        if queue_path is not None and queue_path.exists() and records:
            atomic_write_json(queue_path, {"vulnerabilities": kept})
            append_dismissed(dismissed_path, dismissed)
        all_records.extend(records)

    # summary 全量口径（含 prior 终态）
    by_v = {}
    by_class: dict[str, dict[str, int]] = {}
    for r in all_records:
        v = r["review_verdict"]
        by_v[v] = by_v.get(v, 0) + 1
        c = by_class.setdefault(r["vuln_class"],
                                {"total": 0, "refuted": 0, "survived": 0,
                                 "unreviewed": 0})
        c["total"] += 1
        c[v] += 1
    atomic_write_json(review_path, {
        "summary": {
            "total": len(all_records),
            "refuted": by_v.get("refuted", 0),
            "survived": by_v.get("survived", 0),
            "unreviewed": by_v.get("unreviewed", 0),
            "by_class": by_class,
        },
        "records": all_records,
    })
```

实现注意（对照同文件既有 import 与 helper 微调，勿照抄漏 import）：
- `datetime/timezone` 置文件顶部或函数内 import 均可（对齐文件现状）；
- `kept` 的剔除判断用了对象恒等（entries 里的 dict 与 targets 里的同一对象），分片不复制对象，成立；若实现中发现 `_group_poc_targets` 做了拷贝，改用 ID 集合差集：`refuted_ids = {p[1]["finding_id"] for p in pairs if p[1]["review_verdict"]=="refuted"}; kept = [e for e in entries if str(e.get("ID")) not in refuted_ids]`（**推荐直接用 ID 集合版**，更稳）；
- `logger` 用文件模块级既有 logger。

- [ ] **Step 4: 跑测试确认全绿**

Run: `cd /root/ft-codescan/packages/whitebox && python -m pytest tests/test_adversarial_review_activity.py -v`
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add packages/whitebox/src/supernova_whitebox/pipeline/activities.py packages/whitebox/tests/test_adversarial_review_activity.py
git commit -m "feat(whitebox): run_adversarial_review activity——POC同款sink聚类分片+Semaphore并发+预算护栏,refuted剔卡+dismissed归档(新档adversarial-review)+adversarial_review.json全量记录(before/after/维度/原因),产物即checkpoint终态不重审"
```

---

### Task 5: workflow / worker / step_intents 接线

**Files:**
- Modify: `packages/whitebox/src/supernova_whitebox/pipeline/workflows.py`（merge 之后、GN 富化之前插入，:629 `run_merge_dual_track_queues` 的 execute_activity 之后）
- Modify: `packages/whitebox/src/supernova_whitebox/worker.py`（import 区 + activities 列表两处）
- Modify: `packages/whitebox/src/supernova_whitebox/pipeline/step_intents.py:44`（`PHASE_STEPS["vulnerability-analysis"]` 加 StepSpec）
- Test: Create `packages/whitebox/tests/test_worker_registers_adversarial_review.py`；Modify `packages/whitebox/tests/test_phase_steps.py`（加断言）

**Interfaces:**
- Consumes: Task 4 的 `activities.run_adversarial_review`。
- Produces: workflow 步骤接线完成（Task 8 端到端消费）。

- [ ] **Step 1: 写失败测试**

```python
# packages/whitebox/tests/test_worker_registers_adversarial_review.py
"""worker 注册契约（对齐 test_worker_registers_authz_judge 钉死模式）：
漏注册 = workflow 侧 ActivityNotRegistered fail-fast 或静默降级。"""
from supernova_whitebox import worker


def test_adversarial_review_registered():
    names = {getattr(a, "__name__", str(a)) for a in worker.ACTIVITIES}
    assert "run_adversarial_review" in names
```

`test_phase_steps.py` 追加断言（放该文件既有同款断言旁）：

```python
def test_vulnerability_analysis_phase_contains_adversarial_review():
    from supernova_whitebox.pipeline.step_intents import PHASE_STEPS
    names = [s.name for s in PHASE_STEPS["vulnerability-analysis"]]
    assert "adversarial-review" in names
    assert names.index("merge-dual-track") < names.index("adversarial-review") \
        < names.index("gn-finding-enrichment")
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cd /root/ft-codescan/packages/whitebox && python -m pytest tests/test_worker_registers_adversarial_review.py tests/test_phase_steps.py -v`
Expected: FAIL

- [ ] **Step 3: 实现三处接线**

workflows.py（插在 merge 的 execute_activity 之后、"GN-only 深度富化"注释块之前）：

```python
                # === 对抗性审查（merge 后、富化前；non-fatal，spec
                # 2026-09-10）：固定 7 维度逐卡反驳，refuted 剔卡+归档，
                # 反驳掉的卡不再消耗富化/POC/polish 的逐卡 LLM 成本。 ===
                try:
                    await workflow.execute_activity(
                        activities.run_adversarial_review, act_input,
                        start_to_close_timeout=timedelta(minutes=20),
                        retry_policy=retry_for("standard"),
                    )
                except Exception as exc:
                    if is_cancellation(exc):  # 取消放行（吞掉=幽灵扫描）
                        raise
                    if _activity_not_registered_hint(exc):
                        raise ApplicationFailure(
                            f"Adversarial review activity is not registered: {exc}",
                            type="ActivityNotRegistered",
                            non_retryable=True,
                        ) from exc
                    await workflow.execute_activity(
                        activities.log_info_activity,
                        ActivityInput(**{**act_input.__dict__,
                           "info_message": f"adversarial review failed (non-fatal): {exc}",
                           "info_level": "warning"}),
                        start_to_close_timeout=timedelta(seconds=10),
                        retry_policy=retry_for("log"),
                    )
```

worker.py：import 区加 `run_adversarial_review`（与其它 activities import 同处），activities 列表加同名条目（两处的确切位置对照 `run_merge_dual_track_queues` 现有条目，紧随其后）。

step_intents.py（:44 `merge-dual-track` 之后）：

```python
        StepSpec("adversarial-review",  "双轨合并后对抗性审查(7维度逐卡反驳,refuted剔卡归档)"),
```

- [ ] **Step 4: 跑测试确认全绿**

Run: `cd /root/ft-codescan/packages/whitebox && python -m pytest tests/test_worker_registers_adversarial_review.py tests/test_phase_steps.py -v`
Expected: PASS（含既有用例不回归）

- [ ] **Step 5: Commit**

```bash
git add packages/whitebox/src/supernova_whitebox/pipeline/workflows.py packages/whitebox/src/supernova_whitebox/worker.py packages/whitebox/src/supernova_whitebox/pipeline/step_intents.py packages/whitebox/tests/test_worker_registers_adversarial_review.py packages/whitebox/tests/test_phase_steps.py
git commit -m "feat(whitebox): 对抗审查接线——workflow merge后non-fatal包裹(取消放行+ActivityNotRegistered fail-fast+log_info降级,20min窗口)+worker两处注册+step_intents新StepSpec"
```

---

### Task 6: web 后端端点

**Files:**
- Modify: `packages/web/src/supernova_web/api/scans.py`（`scan_dataflow` 端点 :516-522 之后追加）
- Test: Create `packages/web/tests/test_scans_adversarial_review.py`（样板：`test_scans_dataflow.py` 全文）

**Interfaces:**
- Consumes: Task 4 的产物 `deliverables/whitebox/intermediate/adversarial_review.json`；既有 `resolve_intermediate` / `WHITEBOX_SUBDIR`（`supernova_core.utils.paths`）。
- Produces: `GET /api/workspaces/{ws}/scans/{scan_id}/adversarial-review` → dict JSON（Task 7 前端消费）。

- [ ] **Step 1: 写失败测试**

```python
# packages/web/tests/test_scans_adversarial_review.py
"""GET adversarial-review 端点（照抄 test_scans_dataflow 四用例骨架）。"""
import json
from pathlib import Path

REVIEW = {"summary": {"total": 1, "refuted": 1, "survived": 0, "unreviewed": 0},
          "records": [{"vuln_class": "injection", "finding_id": "INJ-01",
                       "review_verdict": "refuted",
                       "failed_dimensions": ["defense_effective"],
                       "after": {"action": "dismissed"}}]}


def _make_scan(tmp_workspaces, ws="ws1", scan_id="S1"):
    scan_dir = tmp_workspaces / ws / "scans" / scan_id
    (scan_dir / "deliverables").mkdir(parents=True, exist_ok=True)
    (scan_dir / "session.json").write_text(json.dumps({"scan_id": scan_id}),
                                           encoding="utf-8")
    return scan_dir


def test_returns_review_json(authed_client, tmp_workspaces):
    d = _make_scan(tmp_workspaces)
    inter = d / "deliverables" / "whitebox" / "intermediate"
    inter.mkdir(parents=True)
    (inter / "adversarial_review.json").write_text(json.dumps(REVIEW),
                                                   encoding="utf-8")
    r = authed_client.get("/api/workspaces/ws1/scans/S1/adversarial-review")
    assert r.status_code == 200
    assert r.json()["summary"]["refuted"] == 1


def test_404_when_missing(authed_client, tmp_workspaces):
    _make_scan(tmp_workspaces)
    r = authed_client.get("/api/workspaces/ws1/scans/S1/adversarial-review")
    assert r.status_code == 404


def test_404_unknown_scan(authed_client, tmp_workspaces):
    r = authed_client.get("/api/workspaces/ws1/scans/NOPE/adversarial-review")
    assert r.status_code == 404
```

（fixture `authed_client` / `tmp_workspaces` 来自 `tests/conftest.py`，用法照抄 `test_scans_dataflow.py` 的 import 与签名。）

- [ ] **Step 2: 跑测试确认失败**

Run: `cd /root/ft-codescan/packages/web && python -m pytest tests/test_scans_adversarial_review.py -v`
Expected: FAIL（404 路由不存在 → FastAPI 返回 404 但语义不同，用例1 应失败）

- [ ] **Step 3: 实现端点（scans.py 追加）**

```python
def _adversarial_review_for(scan_dir: Path) -> dict:
    """直读 intermediate/adversarial_review.json（spec 2026-09-10 §4.8）。

    不经 DeliverablesReader——端点返 JSON 非 text/plain 截断（对齐
    _dataflow_view_for 模式）。缺失/坏 JSON 一律 404，不让 500 冒出。
    """
    from supernova_core.utils.paths import WHITEBOX_SUBDIR, resolve_intermediate
    path = resolve_intermediate(scan_dir / "deliverables" / WHITEBOX_SUBDIR,
                                "adversarial_review.json")
    if path is None or not path.is_file():
        raise HTTPException(status_code=404, detail="adversarial review not generated")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise HTTPException(status_code=404,
                            detail=f"adversarial review unreadable: {exc}") from exc
    if not isinstance(data, dict):
        raise HTTPException(status_code=404, detail="adversarial review malformed")
    return data


@router.get("/{ws}/scans/{scan_id}/adversarial-review")
async def scan_adversarial_review(
    ws: str, scan_id: str, request: Request,
    _: User = Depends(workspace_member),
) -> dict:
    scan_dir = _scan_dir_or_404(request, ws, scan_id)
    return _adversarial_review_for(scan_dir)
```

（import 与 helper 名对照 `_dataflow_view_for`/`scan_dataflow` 现状微调：若 `json`/`HTTPException` 已在文件头 import 则复用。）

- [ ] **Step 4: 跑测试确认全绿**

Run: `cd /root/ft-codescan/packages/web && python -m pytest tests/test_scans_adversarial_review.py -v`
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add packages/web/src/supernova_web/api/scans.py packages/web/tests/test_scans_adversarial_review.py
git commit -m "feat(web): GET adversarial-review 端点——scan_dataflow 同款直读(白盒桶 resolve_intermediate+坏 JSON 404),workspace_member 权限,纯文件读零 agent"
```

---

### Task 7: 前端 adversarial Tab

**Files:**
- Modify: `packages/web/frontend/src/api/types.ts`（`DataflowView` :692 附近加类型）
- Modify: `packages/web/frontend/src/api/client.ts`（`fetchDataflowView` :367 之后加 fetch）
- Modify: `packages/web/frontend/src/router.tsx`（lazy import :19-27 区 + per-scan children :130-140 区）
- Modify: `packages/web/frontend/src/routes/WorkspaceDetail/ScanDetail.tsx`（`SCAN_TABS` :24-31 加行）
- Create: `packages/web/frontend/src/routes/WorkspaceDetail/AdversarialReviewTab.tsx`
- Modify: `packages/web/frontend/src/locales/zh.json` + `en.json`（`workspaceDetail.tabs.adversarialReview` + `workspaceDetail.adversarialReview.*`）
- Test: Create `packages/web/frontend/src/routes/WorkspaceDetail/__tests__/AdversarialReviewTab.test.tsx`；Modify `ScanDetail.test.tsx`（tab 总数断言 +1）

**Interfaces:**
- Consumes: Task 6 的 `GET .../adversarial-review` 响应结构（`{summary: {total, refuted, survived, unreviewed}, records: [...]}`）。
- Produces: 前端 Tab（无后续消费者）。

- [ ] **Step 1: 写失败测试**

```tsx
// packages/web/frontend/src/routes/WorkspaceDetail/__tests__/AdversarialReviewTab.test.tsx
// 照抄 DataFlowTab.test.tsx 骨架（msw + MemoryRouter + SWRConfig 独立 cache + i18n zh）
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { http, HttpResponse, setupServer } from "msw";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { SWRConfig } from "swr";

import { AdversarialReviewTab } from "../AdversarialReviewTab";
import { renderWithSwr } from "../../../../test/swr-render";

const fixture = {
  summary: { total: 3, refuted: 1, survived: 1, unreviewed: 1 },
  records: [
    { vuln_class: "injection", finding_id: "INJ-01", review_verdict: "refuted",
      failed_dimensions: ["defense_effective"],
      before: { title: "SQLi", verdict: "vulnerable" },
      dimension_results: [
        { dimension: "defense_effective", rebutted: true, reason: "r",
          evidence: [{ location: "app.js:88", snippet: "escape(x)" }] }],
      rebuttal_reason: "defense covers slot",
      survival_reason: null, after: { action: "dismissed" } },
    { vuln_class: "xss", finding_id: "XSS-01", review_verdict: "survived",
      failed_dimensions: [], before: { title: "t2", verdict: "vulnerable" },
      dimension_results: [], rebuttal_reason: null,
      survival_reason: "no refutation", after: { action: "kept" } },
    { vuln_class: "auth", finding_id: "AUTH-01", review_verdict: "unreviewed",
      failed_dimensions: [], before: { title: "t3", verdict: "vulnerable" },
      dimension_results: [], rebuttal_reason: null, survival_reason: null,
      after: { action: "kept" } },
  ],
};

const server = setupServer(
  http.get("/api/workspaces/:ws/scans/:scanId/adversarial-review",
    () => HttpResponse.json(fixture)));
beforeAll(() => server.listen());
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

function render() {
  return renderWithSwr(
    <SWRConfig value={{ provider: () => new Map() }}>
      <MemoryRouter initialEntries={["/p/ws1/scans/S1/adversarial"]}>
        <Routes>
          <Route path="/p/:workspace/scans/:scanId/adversarial"
            element={<AdversarialReviewTab />} />
        </Routes>
      </MemoryRouter>
    </SWRConfig>);
}

// Tab 组件从 useScanDetail/useParams 取 ws/scanId——若 DataFlowTab 用 props
// 注入则照抄其测试的挂载方式（对照 __tests__/DataFlowTab.test.tsx 实际写法调整 render）。

it("renders summary counts", async () => {
  render();
  await waitFor(() => expect(screen.getByTestId("adv-summary")).toHaveTextContent("3"));
});

it("filters by verdict", async () => {
  render();
  await waitFor(() => screen.getByText("INJ-01"));
  fireEvent.change(screen.getByTestId("adv-verdict-select"),
                   { target: { value: "survived" } });
  expect(screen.queryByText("INJ-01")).not.toBeInTheDocument();
  expect(screen.getByText("XSS-01")).toBeInTheDocument();
});

it("filters by failed dimension", async () => {
  render();
  await waitFor(() => screen.getByText("INJ-01"));
  fireEvent.change(screen.getByTestId("adv-dimension-select"),
                   { target: { value: "defense_effective" } });
  expect(screen.getByText("INJ-01")).toBeInTheDocument();
  expect(screen.queryByText("XSS-01")).not.toBeInTheDocument();
});

it("shows empty state on 404", async () => {
  server.use(
    http.get("/api/workspaces/:ws/scans/:scanId/adversarial-review",
      () => HttpResponse.json({ detail: "not generated" }, { status: 404 })));
  render();
  await waitFor(() =>
    expect(screen.getByTestId("adv-empty")).toBeInTheDocument());
});
```

`ScanDetail.test.tsx`：找到 tab 总数断言（`toHaveLength(6)`，约 :44），改为 `toHaveLength(7)`，并在 tab 名单断言里补 `adversarial`（对照该文件现有写法）。

- [ ] **Step 2: 跑测试确认失败**

Run: `cd /root/ft-codescan/packages/web/frontend && npx vitest run src/routes/WorkspaceDetail/__tests__/AdversarialReviewTab.test.tsx`
Expected: FAIL（Cannot find module '../AdversarialReviewTab'）

- [ ] **Step 3: 实现**

types.ts（`DataflowView` 接口后追加）：

```typescript
export interface ReviewEvidence { location: string; snippet?: string; note?: string }
export interface DimensionResult {
  dimension: string; rebutted: boolean; reason?: string | null;
  evidence?: ReviewEvidence[];
}
export interface ReviewRecord {
  vuln_class: string; finding_id: string; reviewed_at?: string;
  before?: Record<string, unknown>;
  review_verdict: "refuted" | "survived" | "unreviewed";
  dimension_results: DimensionResult[];
  failed_dimensions: string[];
  rebuttal_reason?: string | null;
  survival_reason?: string | null;
  evidence?: ReviewEvidence[];
  confidence?: string | null;
  after?: { action?: string } | null;
}
export interface AdversarialReview {
  summary: { total: number; refuted: number; survived: number; unreviewed: number };
  records: ReviewRecord[];
}
```

client.ts（`fetchDataflowView` 后追加，`apiGet` 用法对照该函数）：

```typescript
export const fetchAdversarialReview = (ws: string, scanId: string) =>
  apiGet<AdversarialReview>(
    `/workspaces/${encWs(ws)}/scans/${encWs(scanId)}/adversarial-review`);
```

router.tsx：lazy 区加 `const AdversarialReviewTab = lazyWithRetry(() => import("./routes/WorkspaceDetail/AdversarialReviewTab"));`，children 加 `{ path: "adversarial", element: <AdversarialReviewTab /> }`（dataflow 行之后）。

ScanDetail.tsx `SCAN_TABS` 加行（merge/correlation 兄弟样式）：

```tsx
  { value: "adversarial", labelKey: "workspaceDetail.tabs.adversarialReview" },
```

AdversarialReviewTab.tsx（骨架照 DataFlowTab + 卡片样式照 CorrelationTab 的 AdjudicationCardView）：

```tsx
import { useMemo, useState } from "react";
import { useParams } from "react-router-dom";
import useSWR from "swr";

import { fetchAdversarialReview } from "../../../api/client";
import { useTranslation } from "../../../i18n/useTranslation"; // 对照 DataFlowTab 实际 import

const VERDICTS = ["all", "refuted", "survived", "unreviewed"] as const;
const DIMENSION_ORDER = ["defense_effective", "unreachable",
  "attacker_uncontrolled", "self_impact", "platform_protection",
  "authn_enforced", "authz_guard"];

export function AdversarialReviewTab() {
  const { t } = useTranslation();
  const { workspace, scanId } = useParams();
  const { data, error } = useSWR(
    ["adversarial-review", workspace, scanId],
    () => fetchAdversarialReview(workspace!, scanId!));
  const [verdict, setVerdict] = useState<string>("all");
  const [dimension, setDimension] = useState<string>("all");

  const dims = useMemo(() => {
    const s = new Set<string>(
      (data?.records ?? []).flatMap(r => r.failed_dimensions));
    return DIMENSION_ORDER.filter(d => s.has(d));
  }, [data]);
  const filtered = useMemo(() =>
    (data?.records ?? []).filter(r =>
      (verdict === "all" || r.review_verdict === verdict) &&
      (dimension === "all" || r.failed_dimensions.includes(dimension))),
    [data, verdict, dimension]);

  if (error) {
    return <div data-testid="adv-empty" className="p-6 text-sm opacity-70">
      {t("workspaceDetail.adversarialReview.emptyHint")}
    </div>;
  }
  if (!data) {
    return <div className="p-6 text-sm opacity-70">
      {t("workspaceDetail.adversarialReview.loading")}
    </div>;
  }
  const s = data.summary;
  return (
    <div className="space-y-4 p-6">
      <div data-testid="adv-summary" className="flex gap-4 text-sm">
        <span>{t("workspaceDetail.adversarialReview.total")}: {s.total}</span>
        <span className="text-red-500">{t("workspaceDetail.adversarialReview.refuted")}: {s.refuted}</span>
        <span className="text-emerald-500">{t("workspaceDetail.adversarialReview.survived")}: {s.survived}</span>
        <span className="opacity-60">{t("workspaceDetail.adversarialReview.unreviewed")}: {s.unreviewed}</span>
      </div>
      <div className="flex gap-3">
        <select data-testid="adv-verdict-select" aria-label="verdict"
          value={verdict} onChange={e => setVerdict(e.target.value)}>
          {VERDICTS.map(v => <option key={v} value={v}>
            {v === "all" ? t("workspaceDetail.adversarialReview.all") : v}
          </option>)}
        </select>
        <select data-testid="adv-dimension-select" aria-label="dimension"
          value={dimension} onChange={e => setDimension(e.target.value)}>
          <option value="all">{t("workspaceDetail.adversarialReview.all")}</option>
          {dims.map(d => <option key={d} value={d}>{d}</option>)}
        </select>
      </div>
      <div className="space-y-3">
        {filtered.map(r => (
          <details key={`${r.vuln_class}-${r.finding_id}`}
            data-testid="adv-record" className="rounded border p-3">
            <summary className="cursor-pointer text-sm font-medium">
              <span className="mr-2">{r.finding_id}</span>
              <span className="mr-2 opacity-70">{String(r.before?.title ?? "")}</span>
              <span className={
                r.review_verdict === "refuted" ? "text-red-500"
                : r.review_verdict === "survived" ? "text-emerald-500" : "opacity-60"}>
                {r.review_verdict}
              </span>
            </summary>
            <div className="mt-2 space-y-2 text-xs">
              {r.dimension_results.map((d, i) => (
                <div key={i}>
                  <span className={d.rebutted ? "text-red-500" : "opacity-70"}>
                    {d.dimension}: {d.rebutted ? "rebutted" : "held"}
                  </span>{" "}
                  — {d.reason}
                  <ul className="ml-4 opacity-70">
                    {(d.evidence ?? []).map((e, j) => (
                      <li key={j} className="font-mono">
                        {e.location} {e.snippet ?? ""}
                      </li>))}
                  </ul>
                </div>))}
              {r.rebuttal_reason && (
                <p className="text-red-400">{r.rebuttal_reason}</p>)}
              {r.survival_reason && (
                <p className="opacity-70">{r.survival_reason}</p>)}
            </div>
          </details>))}
        {filtered.length === 0 && (
          <div className="text-sm opacity-60">
            {t("workspaceDetail.adversarialReview.noMatch")}
          </div>)}
      </div>
    </div>
  );
}
```

（import 路径 / `useTranslation` / className 体系对照 DataFlowTab 实际写法微调——仓库是 mode×palette 双 class 主题，勿引硬编码色之外的新色，若 DataFlowTab 用 token class 则照抄。）

zh.json（`workspaceDetail` 段内，`tabs` 加 `"adversarialReview": "对抗审查"`；另加 `adversarialReview` 子对象）：

```json
"adversarialReview": {
  "emptyHint": "该扫描无对抗审查记录（未开启或未生成）",
  "loading": "加载中…",
  "total": "总计", "refuted": "已驳回", "survived": "无法反驳",
  "unreviewed": "未审成", "all": "全部", "noMatch": "无匹配记录"
}
```

en.json 同结构（key 集合必须一致，`locales.test.ts` 锁定）：

```json
"adversarialReview": {
  "emptyHint": "No adversarial review records for this scan",
  "loading": "Loading…",
  "total": "Total", "refuted": "Refuted", "survived": "Survived",
  "unreviewed": "Unreviewed", "all": "All", "noMatch": "No matching records"
}
```

注意：locales 文件当前可能带另一会话的未合并冲突标记——编辑前先 `git status` 看 `UU` 状态，若仍有冲突先与用户确认，不要盲目覆盖。

- [ ] **Step 4: 跑测试 + tsc**

Run: `cd /root/ft-codescan/packages/web/frontend && npx vitest run src/routes/WorkspaceDetail/__tests__/AdversarialReviewTab.test.tsx src/routes/WorkspaceDetail/__tests__/ScanDetail.test.tsx src/i18n/locales.test.ts && npx tsc -b`
Expected: 全部 PASS，tsc exit 0

- [ ] **Step 5: Commit**

```bash
git add packages/web/frontend/src/api/types.ts packages/web/frontend/src/api/client.ts packages/web/frontend/src/router.tsx packages/web/frontend/src/routes/WorkspaceDetail/ScanDetail.tsx packages/web/frontend/src/routes/WorkspaceDetail/AdversarialReviewTab.tsx packages/web/frontend/src/locales/zh.json packages/web/frontend/src/locales/en.json packages/web/frontend/src/routes/WorkspaceDetail/__tests__/AdversarialReviewTab.test.tsx packages/web/frontend/src/routes/WorkspaceDetail/__tests__/ScanDetail.test.tsx
git commit -m "feat(web-fe): 对抗审查 Tab——summary 计数条+verdict/failed_dimensions 双筛选(选项数据派生)+展开卡片(维度结果/file:line证据/反驳论证),SWR 一次性拉取,404 空态"
```

---

### Task 8: 端到端验证（fixture 驱动 + 真实扫描 smoke）

**Files:**
- Create: `packages/whitebox/tests/test_adversarial_review_end_to_end.py`
- 无产品代码改动——本任务只验证全链。

**Interfaces:**
- Consumes: Task 1-7 全部。
- Produces: 端到端信心。

- [ ] **Step 1: 写端到端测试（worker 注册 + workflow 顺序 + 全链产物）**

```python
# packages/whitebox/tests/test_adversarial_review_end_to_end.py
"""端到端（无 LLM）：五类 queue fixture → _run_adversarial_review_for_classes
(mock agent 返回混合裁定) → 断言 queue 剔除/归档/产物/checkpoint 幂等/重开补审。"""
# 内容 = Task 4 三个用例的多类扩展版：再加 xss survived 卡 + auth unreviewed 卡，
# 断言 summary.by_class 计数、多类 queue 各自正确、prior_records 跨类不串。
# 具体写法照 Task 4 的 env fixture 扩展（fixture 里多写两个 queue 文件与卡）。
```

（此测试与 Task 4 的差别仅在覆盖面——按 Task 4 的 fixture 模式扩展即可，此处不重复贴全码。）

- [ ] **Step 2: 跑全套相关测试（改动文件全集回归）**

Run:
```bash
cd /root/ft-codescan/packages/core && python -m pytest tests/collectors/test_adversarial_review.py tests/test_adversarial_review_knobs.py tests/prompts/test_adversarial_review_prompt.py -v
cd /root/ft-codescan/packages/whitebox && python -m pytest tests/test_adversarial_review_activity.py tests/test_adversarial_review_end_to_end.py tests/test_worker_registers_adversarial_review.py tests/test_phase_steps.py tests/test_poc_agent_sharding.py -v
cd /root/ft-codescan/packages/web && python -m pytest tests/test_scans_adversarial_review.py tests/test_web_never_runs_agents.py -v
```
Expected: 全绿（`test_poc_agent_sharding.py` 与 `test_web_never_runs_agents.py` 是回归哨兵，必须仍绿）

- [ ] **Step 3: 真实扫描 smoke（可选，需 LLM 环境）**

对一个已知有误报的小仓（如 NodeGoat）发起白盒扫描，验证：
1. 日志出现 `adv-review-*` agent 记账；
2. `intermediate/adversarial_review.json` 生成且 summary 计数与 queue 变化一致；
3. `dismissed_findings.json` 出现 `dismissed_at_stage="adversarial-review"` 条目；
4. web 详情页 adversarial Tab 可见、可筛选；
5. 总扫描时长未超 20min 窗口（片数 ÷ 并发 × 单片耗时，CLAUDE.md 容量铁律——若超，调 `SUPERNOVA_ADVERSARIAL_REVIEW_MAX_AGENTS` 或窗口）。

- [ ] **Step 4: Commit**

```bash
git add packages/whitebox/tests/test_adversarial_review_end_to_end.py
git commit -m "test(whitebox): 对抗审查端到端——多类混合裁定剔卡/归档/产物/幂等回归+哨兵(poc sharding/web 零 agent)全绿"
```

---

## Self-Review 记录

- **Spec 覆盖**：§3 维度（Task 1/3）、§4.1 prompt（Task 3）、§4.2 schema（Task 1）、§4.3 activity（Task 4）、§4.4 产物含 by_class（Task 4）、§4.5 归档（Task 4）、§4.6 旋钮（Task 2）、§4.7 接线六动点（Task 4/5——AGENT_PHASE_MAP 经对照 gn-enrich 先例裁为不注册，spec §4.7 第 6 点的「若要 phase 聚合」条件不满足）、§4.8 web（Task 6/7）、§6 校验/降级（Task 1/4）、§7 checkpoint（Task 4）、§8 测试（各 Task + Task 8）。
- **占位符扫描**：Task 8 Step 1 的端到端测试标注「照 Task 4 fixture 模式扩展」并说明差异——已给出差异定义与fixture来源，非 TBD。其余无占位符。
- **类型一致性**：`validate_review_cards(items, *, valid_ids, vuln_class, repo_root)` / `ReviewValidation(accepted, rejected)` / `ADVERSARIAL_REVIEW_AGENT_SCHEMA` / `extract_review_payload(text)` 在 Task 1 定义、Task 4 消费一致；`_run_adversarial_review_for_classes(*, deliverables, repo_path, provider_config)` 在 Task 4 定义、测试消费一致；web 端点路径与前端 fetch 路径一致。
