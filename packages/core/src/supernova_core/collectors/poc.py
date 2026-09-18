# packages/core/src/supernova_core/collectors/poc.py
"""poc-agent 的 add_poc append collector + verdict 校验（L0-L3）。

spec 2026-08-27-poc-agent-direct-design：白盒 PoC 去 templated 化——curl/raw_http
文本由报告阶段 poc-agent 直产，本 collector 收集 + 校验，渲染层原文透传
（零格式改写逻辑）。模式对齐 collectors/exploit.py（CollectorBase mode="append"，
复用 generic mode-aware 桥）。

校验哲学与 exploit collector 同构但有 PoC 特有取舍：
- L0 lenient：steps 归一（str → [str]、dict → 提取说明字段）；self_check 归一
  （非显式 "pass" 一律保守 "fail"——正确性自检没做就不能声称通过，spec §4.3
  正确性主位）；
- L1 必填：vulnerability_id 非空 str + 产出物至少一项（curl/raw_http/steps/
  notes）——空 verdict 防护（GLM 95 次传空 {} 死循环教训）；声明为 str 的字段
  传非 str → 拒（json.dumps 一个 dict 会产出假 curl 进报告，宁拒不造）；
- L2 id ∈ queue（防幻觉）；L3 去重（首份生效）；
- 校验层不触碰 curl/raw_http 文本内容（不改写、不 reformat——透传不变量）。
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from supernova_core.collectors.base import CollectorBase, SectionSchema

# add_poc 工具 input schema（扁平 type:object，非 oneOf——两引擎 function calling
# 硬约束，同 add_exploit 的教训：顶层 oneOf 在 openai 侧致 GLM 空参死循环、
# claude 侧走 param-dict 误解析，见 collectors/exploit.py 模块注释）。
_POC_SCHEMA = {
    "type": "object",
    "properties": {
        "vulnerability_id": {
            "type": "string",
            "description": "ID from your input exploitation queue (e.g. XSS-VULN-01).",
        },
        "curl": {
            "type": "string",
            "description": (
                "Full copy-paste reproducible curl for the HTTP delivery of this "
                "vuln, with auth placeholders (<AUTH_TOKEN> / <SESSION_COOKIE>). "
                "For SPA/browser-rendered sinks this may be omitted — put the "
                "delivery in `steps` instead."
            ),
        },
        "raw_http": {
            "type": "string",
            "description": (
                "Burp Repeater raw request for the SAME request as `curl` "
                "(request line + Host + headers + body). Omit if no curl."
            ),
        },
        "steps": {
            "type": "array",
            "items": {"type": "string"},
            "description": (
                "Ordered multi-step delivery (stored XSS: plant then trigger; "
                "DOM XSS: browser navigation with login state). One string per step."
            ),
        },
        "preconditions": {
            "type": "string",
            "description": (
                "Auth/role/plant prerequisites (e.g. 'reviewer login required; "
                "plant point lives in an external service — controllability "
                "unverified')."
            ),
        },
        "expected_response": {
            "type": "string",
            "description": "What response/observation proves the PoC worked.",
        },
        "self_check": {
            "type": "string",
            "enum": ["pass", "fail"],
            "description": (
                "Correctness-first self check (PRIMARY): target endpoint really "
                "exists and consumes the param (file:line evidence); delivery "
                "model matches how the vuln actually triggers; sink is on that "
                "request's trigger path. Format checks (shell quoting, "
                "placeholders) are SECONDARY. 'fail' when you cannot prove "
                "correctness — never fake a pass."
            ),
        },
        "notes": {
            "type": "string",
            "description": (
                "Honest annotations: why self_check failed, degraded cards "
                "(cannot produce a correct PoC + reason), external plant points, "
                "SPA navigation caveats."
            ),
        },
    },
    "required": ["vulnerability_id"],
}

POC_SECTION = SectionSchema(
    tool_name="add_poc",
    section_key="pocs",
    description=(
        "Record the PoC (proof of concept) for a single vulnerability (call ONCE "
        "per queue ID). Provide `curl`+`raw_http` for HTTP delivery, or `steps` "
        "for multi-step/browser delivery; `self_check` is your correctness-first "
        "self check. The host renders these verbatim into the report."
    ),
    json_schema=_POC_SCHEMA,
    mode="append",
)


def make_poc_collector() -> CollectorBase:
    """poc-agent 共用的 append collector（单 add_poc append section）。"""
    return CollectorBase([POC_SECTION])


# run_gitnexus_verdict_agent 的顶层 output schema（宽松 items——GLM 对深层嵌套
# schema 的结构化输出不可靠，具体字段由 validate_pocs L0-L3 兜底，对齐
# endpoint_enrichment 的 {"vulnerabilities": {"type": "array"}} 模式）。
POC_AGENT_OUTPUT_SCHEMA: dict = {
    "type": "object",
    "properties": {"pocs": {"type": "array"}},
    "required": ["pocs"],
}


# ── verdict 校验（L0-L3，对齐 validate_exploit_verdicts 分层哲学）──

# 输出契约字段（未知键剥离——防 agent 幻觉垃圾字段进报告卡）
_POC_FIELDS = ("vulnerability_id", "curl", "raw_http", "steps", "preconditions",
               "expected_response", "self_check", "notes")
_STR_FIELDS = ("curl", "raw_http", "preconditions", "expected_response", "notes")

# steps dict 元素的说明字段同义表（agent 不严格守 schema 的字段名，同
# collectors/exploit._STEP_ACTION_KEYS 的宽容哲学）
_STEP_TEXT_KEYS = ("step", "description", "action", "text", "title", "summary")
_ORDERED_STEP_PREFIX_RE = re.compile(r"^\s*\d+(?:[.)]\s+|、\s*)")


def _strip_ordered_step_prefix(text: str) -> str:
    """Keep the ordinal in the collection, not in each ``steps`` value.

    ``steps`` is rendered by both the web card and Markdown exporter as an
    ordered list. Agents sometimes return Markdown-formatted items (``1. do
    this``), which otherwise renders as ``1. 1. do this``. Only a leading
    decimal list marker (including Chinese ``、`` notation) is presentation
    syntax; values such as ``1.2.3`` are intentionally unchanged.
    """
    return _ORDERED_STEP_PREFIX_RE.sub("", text)


@dataclass
class PocValidation:
    accepted: list[dict] = field(default_factory=list)
    rejected: list[tuple[dict, str]] = field(default_factory=list)


def _normalize_steps(raw: object) -> list[str] | None:
    """L0 steps 归一：str → [str]；list 内 str 保留、dict 提取说明字段、其余丢弃。

    dict 提不出可读字段 → json.dumps 兜底（保信息，不静默丢步骤）。
    归一后空 list → None（视同未提供，L1 产出物判定不含它）。
    """
    items: list[object]
    if isinstance(raw, str):
        items = [raw]
    elif isinstance(raw, list):
        items = raw
    else:
        return None
    out: list[str] = []
    for it in items:
        if isinstance(it, str):
            if it.strip():
                out.append(_strip_ordered_step_prefix(it))
        elif isinstance(it, dict):
            text = next((it[k] for k in _STEP_TEXT_KEYS
                         if isinstance(it.get(k), str) and it[k].strip()), None)
            if text is not None:
                out.append(_strip_ordered_step_prefix(text))
            else:
                out.append(json.dumps(it, ensure_ascii=False))
    return out or None


def _normalize_verdict(item: dict) -> dict:
    """L0：steps 归一 + self_check 保守归一（非显式 "pass" → "fail"）。"""
    v: dict = {k: item.get(k) for k in _POC_FIELDS if item.get(k) is not None}
    steps = _normalize_steps(v.get("steps"))
    if steps is None:
        v.pop("steps", None)
    else:
        v["steps"] = steps
    sc = v.get("self_check")
    v["self_check"] = "pass" if isinstance(sc, str) and sc.strip().lower() == "pass" \
        else "fail"
    return v


def validate_pocs(raw: list[dict], valid_ids: set[str]) -> PocValidation:
    """L0 lenient 归一 → L1 必填/类型 → L2 id ∈ valid_ids → L3 去重。

    accepted 顺序保留；rejected 记 (归一后 dict, 原因)。curl/raw_http 文本
    原样透传（校验层绝不改写内容）。
    """
    seen: set[str] = set()
    accepted: list[dict] = []
    rejected: list[tuple[dict, str]] = []
    for item in raw:
        if not isinstance(item, dict):
            rejected.append((item, "L1 非法 verdict（非 dict）"))
            continue
        v = _normalize_verdict(item)
        vid = v.get("vulnerability_id")
        if not isinstance(vid, str) or not vid.strip():
            rejected.append((v, "L1 缺/空/非 str vulnerability_id"))
            continue
        v["vulnerability_id"] = vid.strip()
        bad = [k for k in _STR_FIELDS if k in v and not isinstance(v[k], str)]
        if bad:
            rejected.append((v, f"L1 字段非 str：{','.join(bad)}"))
            continue
        if not any(v.get(k) for k in ("curl", "raw_http", "steps", "notes")):
            rejected.append((v, "L1 无产出物（curl/raw_http/steps/notes 全空）"))
            continue
        if v["vulnerability_id"] not in valid_ids:
            rejected.append((v, f"L2 id 不在 queue: {v['vulnerability_id']}"))
            continue
        if v["vulnerability_id"] in seen:
            rejected.append((v, f"L3 重复id: {v['vulnerability_id']}"))
            continue
        seen.add(v["vulnerability_id"])
        accepted.append(v)
    return PocValidation(accepted=accepted, rejected=rejected)


def extract_pocs_payload(text: object) -> dict | None:
    """result.text 打捞 → {"pocs": [...]} dict；打捞不出返回 None。

    2026-08-28 NodeGoat auth 实证：agent 烧满 turn 预算被 SDK 掐断，
    structured_output=None 但 result.text 里往往已有成型的 pocs JSON（或
    围栏块）。此函数把 text 变回可校验的 payload，救回被预算掐断的产出。

    顺序：text 裸 JSON → 花括号平衡段（含围栏块，状态机跳过字符串内的
    {}/引号）。**纯解析不改写**——对齐 validate_pocs「校验层绝不改写内容」
    的口径：弯引号/未转义引号的内容级修复不做（改写风险大于收益，宁可
    诚实缺失）。解析成功但非 {"pocs": list} 形态 → None（不猜结构）。
    """
    if not isinstance(text, str) or not text.strip():
        return None

    def _ok(data: object) -> dict | None:
        if isinstance(data, dict) and isinstance(data.get("pocs"), list):
            return data
        return None

    try:
        hit = _ok(json.loads(text))
        if hit is not None:
            return hit
    except (json.JSONDecodeError, ValueError):
        pass

    for segment in _balanced_brace_segments(text):
        try:
            hit = _ok(json.loads(segment))
            if hit is not None:
                return hit
        except (json.JSONDecodeError, ValueError):
            continue
    return None


def _balanced_brace_segments(text: str):
    """从左到右产出顶层花括号平衡段（字符串内的 {} 与引号不计数）。

    生成器：每段是一个潜在的 JSON object 候选；不平衡到 EOF 则止（残文
    无完整段，返回空——调用方拿 None 走诚实缺失）。
    """
    i, n = 0, len(text)
    while i < n:
        if text[i] != "{":
            i += 1
            continue
        depth, j, in_str, esc = 0, i, False, False
        end = None
        while j < n:
            c = text[j]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
            else:
                if c == '"':
                    in_str = True
                elif c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        end = j
                        break
            j += 1
        if end is None:
            return  # 不平衡残文：无完整段
        yield text[i:end + 1]
        i = end + 1
