import logging
import re
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Callable

from supernova_core.code_index.gn_collapse import (
    extract_endpoint,
    extract_param,
    parse_sink_call_site_id,
)
from supernova_core.i18n import Messages, current_lang
from supernova_core.models.config import ReportConfig
from supernova_core.models.queue_schemas import (
    Vulnerability,
    VulnerabilityQueue,
)
from supernova_core.services.code_snippet import annotate_direct, extract_snippet
from supernova_core.services.severity_rules import SEVERITY_ZH, effective_severity
from supernova_core.services.vulnerability_cause import vulnerability_cause
from supernova_core.utils.file_io import async_path_exists, async_read_file, async_write_file
from supernova_core.utils.paths import resolve_intermediate, resolve_track_deliverable

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}
CONFIDENCE_ZH = {"high": "高", "medium": "中", "low": "低",
                 # spec 2026-08-26 §5.7：判定通道失败（非 LLM 判了且低置信）——
                 # 与 needs_review 的「待复核」显式区分，不静默混入。
                 "unadjudicated": "未判定（判定通道失败）"}
CONFIDENCE_EN = {"high": "High", "medium": "Medium", "low": "Low",
                 "unadjudicated": "Unadjudicated (verdict pass failed)"}

# 内部标签零泄漏（spec §9）：pipeline 内部判定状态串不得出现在报告正文。
# 先吃掉「纯标签括号组」（如 "(llm-pass-failed, needs_review)" 整体删除），
# 再把残留的独立标签替换为「待复核」。
_INTERNAL_LABEL_RE = re.compile(
    r"\(\s*(?:llm-pass-failed|needs_review|unparseable-llm)"
    r"(?:\s*,\s*(?:llm-pass-failed|needs_review|unparseable-llm))*\s*\)"
    r"|llm-pass-failed|needs_review|unparseable-llm"
)
_FILE_LINE_RE = re.compile(r"[\w./-]+\.[A-Za-z]{1,5}:\d+")

# 接口块描述符串解析（对齐 report_data_builder.parse_endpoint_string 契约；
# 不直接 import——builder 反向依赖本模块，会循环导入）。串形态：
# "POST /memos (write, isLoggedIn)" / "GET /memos (trigger)" / "/allocations/:id"。
_EP_STRING_RE = re.compile(
    r"^\s*(?:(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+)?([^\s(]+)\s*(?:\((.*?)\))?\s*$",
    re.IGNORECASE,
)
_EP_KNOWN_ROLES = {"write", "trigger", "read", "update", "delete"}

# 漏洞卡 / 报告文案双语（zh/en 可配，跟随 SUPERNOVA_AGENT_NARRATION_LANG）。
_M = Messages({
    # 通用 entry 标签（技术细节折叠区沿用 _label 行式）
    "verdict": {"zh": "判定", "en": "Verdict"},
    "concat_occurrences": {"zh": "拼接出现", "en": "Concat Occurrences"},
    "sanitization_observed": {"zh": "防护情况", "en": "Protection Observed"},
    "encoding_observed": {"zh": "编码情况", "en": "Encoding Observed"},
    "missing_defense": {"zh": "缺失防护", "en": "Missing Defense"},
    "exploitation_hypothesis": {"zh": "利用假设", "en": "Exploitation Hypothesis"},
    "suggested_exploit_technique": {"zh": "建议利用技术", "en": "Suggested Exploit Technique"},
    "role_context": {"zh": "角色上下文", "en": "Role Context"},
    "guard_evidence": {"zh": "防护证据", "en": "Guard Evidence"},
    "side_effect": {"zh": "副作用", "en": "Side Effect"},
    "reason": {"zh": "原因", "en": "Reason"},
    "minimal_witness": {"zh": "最小见证", "en": "Minimal Witness"},
    "vulnerable_parameter": {"zh": "脆弱参数", "en": "Vulnerable Parameter"},
    "cvss": {"zh": "CVSS", "en": "CVSS"},
    "owasp_category": {"zh": "OWASP 分类", "en": "OWASP Category"},
    "dataflow": {"zh": "数据流", "en": "Dataflow"},
    "evidence_chain": {"zh": "证据链", "en": "Evidence Chain"},
    # 问题点三要素（spec 2026-08-26 §4.2）
    "issue_location": {"zh": "位置", "en": "Location"},
    "issue_desc_label": {"zh": "说明", "en": "Issue"},
    "issue_render_ctx": {"zh": "（{ctx} 上下文）", "en": " ({ctx} context)"},
    # CLASS_CONFIG heading（value = message key）
    "heading_injection": {"zh": "注入漏洞", "en": "Injection Vulnerabilities"},
    "heading_xss": {"zh": "跨站脚本 (XSS)", "en": "Cross-Site Scripting (XSS)"},
    "heading_auth": {"zh": "认证漏洞", "en": "Authentication Vulnerabilities"},
    "heading_authz": {"zh": "授权漏洞", "en": "Authorization Vulnerabilities"},
    "heading_ssrf": {"zh": "服务端请求伪造 (SSRF)", "en": "Server-Side Request Forgery (SSRF)"},
    # none_found_label（value = message key）
    "none_injection": {"zh": "未发现注入漏洞。", "en": "No injection vulnerabilities found."},
    "none_xss": {"zh": "未发现 XSS 漏洞。", "en": "No XSS vulnerabilities found."},
    "none_auth": {"zh": "未发现认证漏洞。", "en": "No authentication vulnerabilities found."},
    "none_authz": {"zh": "未发现授权漏洞。", "en": "No authorization vulnerabilities found."},
    "none_ssrf": {"zh": "未发现 SSRF 漏洞。", "en": "No SSRF vulnerabilities found."},
    # 四要素统一卡片（spec 2026-08-25 §5/§6）
    "cardname_injection": {"zh": "注入漏洞", "en": "Injection"},
    "cardname_xss": {"zh": "跨站脚本 (XSS)", "en": "XSS"},
    "cardname_auth": {"zh": "认证漏洞", "en": "Authentication"},
    "cardname_authz": {"zh": "授权漏洞", "en": "Authorization"},
    "cardname_ssrf": {"zh": "服务端请求伪造 (SSRF)", "en": "SSRF"},
    "meta_severity": {"zh": "严重程度：", "en": "Severity: "},
    "meta_verification": {"zh": "验证：", "en": "Verification: "},
    "meta_confidence": {"zh": "置信度：", "en": "Confidence: "},
    "meta_sep": {"zh": " ｜ ", "en": " | "},
    "meta_dual_track": {"zh": "（双轨确认）", "en": " (dual-track confirmed)"},
    "verif_static": {"zh": "静态分析", "en": "static analysis"},
    "verif_dynamic": {"zh": "已动态验证", "en": "dynamically verified"},
    "gn_pending_review": {"zh": "待复核", "en": "pending review"},
    "gn_static_hint": {
        "zh": "静态链路发现，建议人工确认后修复。",
        "en": "Static-chain finding; confirm manually before remediation.",
    },
    "gn_rem_hint": {
        "zh": "静态链路发现，建议人工确认。",
        "en": "Static-chain finding; confirm manually.",
    },
    "entry_sep": {"zh": "、", "en": ", "},
    "suspected_indirect": {"zh": "（疑似间接）", "en": " (suspected indirect)"},
    # 相关接口紧凑块小字行标签（spec 2026-08-26-vuln-card-seven-sections §3
    # 节 4，弃表后原表列并入；冒号含在文案内）
    "ep_params": {"zh": "参数：", "en": "Params: "},
    "ep_auth": {"zh": "认证：", "en": "Auth: "},
    "ep_route": {"zh": "路由注册：", "en": "Route: "},
    "ep_sink": {"zh": "Sink：", "en": "Sink: "},
    "ep_chain": {"zh": "链：", "en": "Chain: "},
    "sec_description": {"zh": "**漏洞成因（研判依据）**", "en": "**Root Cause (Basis)**"},
    "sec_impact": {"zh": "**漏洞危害**", "en": "**Impact**"},
    "sec_code": {"zh": "**问题点**", "en": "**Problem Points**"},
    "sec_endpoints": {"zh": "**相关接口**", "en": "**Related Endpoints**"},
    "sec_poc": {"zh": "**POC**", "en": "**POC**"},
    # 验证步骤节（2026-08-27 验证证据展示优化）：黑盒/融合卡的实测过程分步骤
    # 展示（白盒卡 steps 空 → 整节省略）。生成层结构化（VerifyStep），命令直进
    # ```bash 围栏可复制人工复验，无需启发式从散文拆。
    "sec_verify_steps": {"zh": "**验证步骤（黑盒实测）**",
                         "en": "**Verification Steps (live-tested)**"},
    "sec_remediation": {"zh": "**修复建议**", "en": "**Remediation**"},
    "sec_tech_detail": {"zh": "#### 漏洞细节", "en": "#### Vulnerability Details"},
    # POC 独立节（§3 节 5，从漏洞细节区拆出）
    "poc_preconditions": {"zh": "前置条件", "en": "Preconditions"},
    "poc_expected": {"zh": "预期响应", "en": "Expected Response"},
    "poc_expected_full": {"zh": "{indicator}（{criteria}）", "en": "{indicator} ({criteria})"},
    "poc_witness": {"zh": "Witness", "en": "Witness"},
    "poc_self_check_fail": {
        "zh": "PoC 正确性自检未通过（agent 自报，复现前请人工核对）",
        "en": "PoC correctness self-check FAILED (agent-reported; verify manually before replaying)",
    },
    "det_into": {"zh": "传入", "en": "flows into"},
    "det_unfiltered_into": {
        "zh": "{param} 未经过滤传入 {sink}",
        "en": "{param} reaches {sink} without filtering",
    },
    "det_unfiltered_sink": {
        "zh": "{sink} 收到未经过滤的输入",
        "en": "{sink} receives unfiltered input",
    },
    "det_missing_protection": {"zh": "缺少必要的防护", "en": "missing required protection"},
    "code_input_generic": {"zh": "用户输入", "en": "user input"},
    "code_issue_line": {
        "zh": "问题所在：{param} 在此处未经校验即进入 {sink}。",
        "en": "Issue: {param} reaches {sink} here without validation.",
    },
    # 五类确定性危害兜底（_IMPACT_FALLBACK 引用）
    "impact_injection": {
        "zh": "攻击者可注入恶意代码或查询，可能导致数据泄露、篡改或服务器接管。",
        "en": "An attacker can inject malicious code or queries, potentially causing data disclosure, tampering, or full server takeover.",
    },
    "impact_xss": {
        "zh": "攻击者可在受害者浏览器中执行任意脚本，窃取会话或凭据、伪造页面操作，最坏情况可接管账户。",
        "en": "An attacker can run arbitrary scripts in victims' browsers to steal sessions or credentials and forge page actions; at worst, account takeover.",
    },
    "impact_ssrf": {
        "zh": "攻击者可让服务器向任意目标发起请求，访问内部服务或云元数据端点，进而以服务器为跳板渗透内网。",
        "en": "An attacker can make the server issue requests to arbitrary targets, reaching internal services or cloud metadata endpoints to pivot into the internal network.",
    },
    "impact_auth": {
        "zh": "攻击者可绕过或攻破认证机制，冒充任意用户访问系统，最坏情况可获得管理员权限。",
        "en": "An attacker can bypass or break authentication and impersonate any user; at worst, gain administrative access.",
    },
    "impact_authz": {
        "zh": "攻击者可越权访问或篡改其他用户的数据与功能，造成横向越权的数据泄露或破坏。",
        "en": "An attacker can access or modify other users' data and functions, causing unauthorized data disclosure or tampering.",
    },
    # 五类确定性修复兜底（_REM_FALLBACK 引用；LLM 未携带 remediation 的过渡文案）
    "rem_injection": {
        "zh": "将用户输入与命令/查询结构分离：SQL 用参数化查询，命令用数组传参调用，禁止 eval/exec 直接执行用户输入。",
        "en": "Separate user input from command/query structure: parameterized queries for SQL, array-argument calls for commands; never feed user input to eval/exec.",
    },
    "rem_xss": {
        "zh": "输出点按上下文转义（HTML 用实体编码、JS 用 \\uXXXX 转义），或改用 textContent / 框架自动转义，禁止把用户输入直接拼入 innerHTML。",
        "en": "Escape output by context (HTML entity encoding, \\uXXXX for JS) or switch to textContent / framework auto-escaping; never concatenate user input into innerHTML.",
    },
    "rem_ssrf": {
        "zh": "对外发 URL 做协议与目标校验（仅允许 http/https，解析后 IP 不落在内网/环回段），不允许直接请求用户提供的 URL。",
        "en": "Validate outbound URLs by protocol and target (http/https only, resolved IP outside internal/loopback ranges); never fetch user-supplied URLs directly.",
    },
    "rem_auth": {
        "zh": "补齐缺失的认证控制（登录失败限流与锁定、安全的会话与凭据存储），并删除可绕过的认证路径。",
        "en": "Add the missing authentication controls (login throttling/lockout, secure session and credential storage) and remove bypassable auth paths.",
    },
    "rem_authz": {
        "zh": "在服务端对每次对象访问做属主/权限校验（优先行级过滤，如按 user_id 条件查询），不信任客户端传入的 ID。",
        "en": "Enforce server-side ownership/permission checks on every object access (prefer row-level filtering, e.g. filtering by user_id); never trust client-supplied IDs.",
    },
    # disclaimer + 降级文案
    "disclaimer": {
        "zh": "> **免责声明：** 本报告由自动化安全评估工具生成。所有发现须经合格安全专业人员核实后再采取行动。",
        "en": "> **Disclaimer:** This report was generated by an automated security assessment tool. All findings should be verified by a qualified security professional before taking action.",
    },
    "queue_unreadable": {
        "zh": "> ⚠️ {heading} 队列不可读；该类发现不可用。见日志。",
        "en": "> ⚠️ {heading} queue unreadable; findings unavailable for this class. See logs.",
    },
    "queue_auto_recovered": {
        "zh": "> ⚠️ 队列已自动恢复（{warnings}）。原始队列保留在 `{queue_file}`；请核实数据完整性。",
        "en": "> ⚠️ Queue auto-recovered ({warnings}). Raw queue preserved at `{queue_file}`; verify data integrity.",
    },
    "no_renderable_entries": {
        "zh": "> ⚠️ `{queue_file}` 无可渲染条目（{reason}）。",
        "en": "> ⚠️ No renderable entries in `{queue_file}` ({reason}).",
    },
    "no_parseable_entries": {"zh": "无可解析条目", "en": "no parseable entries"},
    "render_error": {"zh": "### {id} — 渲染错误\n", "en": "### {id} — render error\n"},
})

# 五类确定性危害一句话（spec §5「危害」要素兜底；value = message key）
_IMPACT_FALLBACK = {
    "injection": "impact_injection",
    "xss": "impact_xss",
    "ssrf": "impact_ssrf",
    "auth": "impact_auth",
    "authz": "impact_authz",
}

# 五类确定性修复一句话（remediation 字段缺省的过渡兜底；value = message key）
_REM_FALLBACK = {
    "injection": "rem_injection",
    "xss": "rem_xss",
    "ssrf": "rem_ssrf",
    "auth": "rem_auth",
    "authz": "rem_authz",
}


def _label(key: str) -> str:
    """渲染 `- **<label>:**` 前缀。"""
    return f"- **{_M.get(key)}:**"


def _strip_internal(text: str) -> str:
    """内部标签零泄漏（spec §9）：纯标签括号组整体删除，孤立标签→「待复核」。"""
    def _repl(m: re.Match) -> str:
        return "" if m.group(0).startswith("(") else _M.get("gn_pending_review")
    return _INTERNAL_LABEL_RE.sub(_repl, text)


def _snippet_lang_tag(loc: str) -> str:
    """从 `file.ext:line` 位置串提 fence 语言标注（无则空）。"""
    m = _FILE_LINE_RE.search(loc or "")
    if not m:
        return ""
    name = m.group(0).split(":", 1)[0]
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return ext if ext.isalnum() else ""


def _card_param(vuln) -> str | None:
    """参数名：extract_param(source) → affected_parameters[0] → vulnerable_parameter。"""
    p = extract_param(getattr(vuln, "source", None))
    if not p:
        ap = getattr(vuln, "affected_parameters", None) or []
        p = ap[0] if ap else None
    return p or getattr(vuln, "vulnerable_parameter", None)


def _card_sink(vuln) -> tuple[str | None, str | None]:
    """(sink 显示名, file:line 位置)：优先 LLM sink_function，回退 GN sink_call 解析。"""
    sink_call = getattr(vuln, "sink_call", None)
    func = loc = None
    if isinstance(sink_call, str) and sink_call:
        func, loc = parse_sink_call_site_id(sink_call)
    name = getattr(vuln, "sink_function", None) or func
    if not name and isinstance(sink_call, str) and sink_call:
        name = sink_call.split(":", 1)[0]
    return name, loc


def _card_loc(vuln, sink_loc: str | None) -> str | None:
    """file:line 位置：GN sink_call 解析 → affected_entries[0] → 代码位置字段 → 正则
    （含 sink_function 文本——XSS 是 sink_function 族，LLM 自然语言 sink 常内嵌
    "at file:line"，NodeGoat XSS-VULN-02~08 问题点节消失正因缺此回退）。"""
    if sink_loc:
        return sink_loc
    entries = getattr(vuln, "affected_entries", None) or []
    if entries and isinstance(entries[0], dict):
        sl = entries[0].get("sink_location")
        if isinstance(sl, str) and sl:
            return sl
    vcl = getattr(vuln, "vulnerable_code_location", None)
    if isinstance(vcl, str) and vcl:
        return vcl
    for attr in ("path", "sink_call", "sink_function"):
        val = getattr(vuln, attr, None)
        if isinstance(val, str):
            m = _FILE_LINE_RE.search(val)
            if m:
                return m.group(0)
    return None


def _deterministic_core(vuln) -> str | None:
    """title 缺省时的确定性一句话主干：`{param} 传入 {sink}`（退化容忍单边）。"""
    param = _card_param(vuln)
    sink, _ = _card_sink(vuln)
    if param and sink:
        return f"{param} {_M.get('det_into')} {sink}"
    if sink:
        return sink
    if param:
        return param
    return None


def _gn_description(cls_name: str, colon: str, param, sink, loc_part: str) -> str:
    """GN-only 确定性漏洞说明（spec §6）：`{类名}：{param} 未经过滤传入 {sink}（{loc}）`。"""
    if param and sink:
        body = _M.get("det_unfiltered_into", param=param, sink=sink)
    elif sink:
        body = _M.get("det_unfiltered_sink", sink=sink)
    else:
        body = _M.get("det_missing_protection")
    return f"{cls_name}{colon}{body}{loc_part}"


def _description_lines(vuln, gn_only: bool, cls_name: str, colon: str,
                       param, sink, loc_part: str,
                       vuln_class: str | None = None) -> list[str]:
    """漏洞成因（研判依据）：成立依据优先，notes 只作末级回退。
    title 已在卡片标题行（F9a）。链 dump（source→path）与接口行不混排本节——
    链在漏洞细节区 vulnerable_location，接口在受影响入口节。"""
    cause = vulnerability_cause(vuln, vuln_class)
    if not gn_only and cause:
        return [cause]
    return [_gn_description(cls_name, colon, param, sink, loc_part)]


def _parse_endpoint_string(raw: str) -> dict | None:
    """接口串 → 块描述符（method/path/role/auth；对齐 builder 的解析语义：
    无方法前缀且不以 / 开头的串不是端点）。"""
    m = _EP_STRING_RE.match(raw.strip())
    if not m:
        return None
    method, path, paren = m.group(1), m.group(2), m.group(3)
    if method is None and not path.startswith("/"):
        return None
    d = {"method": method.upper() if method else None, "path": path,
         "role": None, "auth": None, "route": None, "params": [], "sink": None}
    if paren:
        for part in [p.strip() for p in paren.split(",") if p.strip()]:
            if part.lower() in _EP_KNOWN_ROLES and d["role"] is None:
                d["role"] = part.lower()
            elif d["auth"] is None:
                d["auth"] = part
    return d


def _endpoint_descriptors(vuln) -> tuple[list[dict], bool]:
    """接口块描述符（§3 节 4）：report_endpoints（富化写回，EndpointEntry
    形态）优先 → endpoints 串解析（多接口，写入+触发分开）→ endpoint /
    path 提取 / source_endpoint 单接口兜底。返回 (descriptors, structured)：
    structured=True 表示富化块自带 params/sink/auth/route（不并入卡级 rows）。"""
    descriptors: list[dict] = []
    for item in (getattr(vuln, "report_endpoints", None) or []):
        if not isinstance(item, dict):
            continue
        path = str(item.get("path") or "").strip()
        if not path:
            continue
        method = str(item.get("method") or "").strip().upper() or None
        descriptors.append({
            "method": method, "path": path,
            "role": str(item.get("role") or "").strip() or None,
            "auth": str(item.get("auth") or "").strip() or None,
            "route": str(item.get("route_registered_at") or "").strip() or None,
            "params": [str(p) for p in (item.get("params") or [])
                       if str(p).strip()],
            "sink": str(item.get("sink_location") or "").strip() or None,
        })
    if descriptors:
        return descriptors, True
    for raw in (getattr(vuln, "endpoints", None) or []):
        d = _parse_endpoint_string(str(raw))
        if d is not None:
            descriptors.append(d)
    if descriptors:
        return descriptors, False
    # 单接口兜底（对齐原 _card_endpoints 回退链：path 提取 → endpoint →
    # source_endpoint）
    fallback = (extract_endpoint(getattr(vuln, "path", None))
                or getattr(vuln, "endpoint", None)
                or getattr(vuln, "source_endpoint", None))
    if fallback:
        d = _parse_endpoint_string(str(fallback))
        if d is not None:
            return [d], False
    return [], False


def _entry_rows(vuln, loc: str | None) -> list[tuple[str, str, str]]:
    """(参数, sink 位置, 链 ID) 行：affected_entries 优先；LLM-only 无 entries
    时由 affected_parameters / vulnerable_parameter × loc 合成（链 ID 留空）。
    三列全空不渲染（F8）。"""
    entries = getattr(vuln, "affected_entries", None) or []
    rows: list[tuple[str, str, str]] = []
    if entries:
        vcl = getattr(vuln, "vulnerable_code_location", None)
        for e in entries:
            if not isinstance(e, dict):
                continue
            p = str(e.get("parameter") or "")
            if e.get("direct") is False:
                p += _M.get("suspected_indirect")
            sl = e.get("sink_location") or vcl or ""
            if not (p or sl or e.get("chain_id")):
                continue  # F8：三列全空不渲染
            rows.append((p, str(sl), str(e.get("chain_id") or "")))
    else:
        params = [str(p) for p in (getattr(vuln, "affected_parameters", None) or [])]
        vp = getattr(vuln, "vulnerable_parameter", None)
        if vp and vp not in params:
            params.append(str(vp))
        rows = [(p, loc or "", "") for p in params]
    return rows


def _join_unique(items: list[str]) -> str:
    """按序去重拼接（空值跳过）——多值并入小字行单段的展示形态。"""
    out: list[str] = []
    for it in items:
        it = str(it).strip()
        if it and it not in out:
            out.append(it)
    return _M.get("entry_sep").join(out)


def _ep_small_line(params: list[str], auth: str | None, route: str | None,
                   sinks: list[str], chains: list[str]) -> str | None:
    """接口块缩进小字行：`参数 ｜ 认证 ｜ 路由注册 ｜ Sink ｜ 链`（空段省，
    全空返回 None 不渲染空行）。"""
    segments: list[str] = []
    joined = _join_unique(params)
    if joined:
        segments.append(f"{_M.get('ep_params')}{joined}")
    if auth:
        segments.append(f"{_M.get('ep_auth')}{auth}")
    if route:
        segments.append(f"{_M.get('ep_route')}{route}")
    joined = _join_unique(sinks)
    if joined:
        segments.append(f"{_M.get('ep_sink')}{joined}")
    joined = _join_unique(chains)
    if joined:
        segments.append(f"{_M.get('ep_chain')}{joined}")
    if not segments:
        return None
    return f"  - {_M.get('meta_sep').join(segments)}"


def _entry_section_lines(vuln, loc: str | None) -> list[str]:
    """相关接口节（spec 2026-08-26-vuln-card-seven-sections §3 节 4）：每接口
    一块（`- METHOD /path（role）` + 缩进小字行「参数 ｜ 认证 ｜ 路由注册 ｜
    Sink ｜ 链」），弃 markdown 表——原表列（参数/Sink 位置/链 ID）信息无损
    并入小字行（多值按序去重拼接）。

    数据源分层：report_endpoints（富化写回）优先且块自带 params/sink/auth/
    route（链 ID 不在 EndpointEntry 契约内，仍并入卡级 affected_entries 聚合）；
    派生块（endpoints 串解析 / 单接口兜底）把卡级 rows 聚合并入每块——多接口
    卡无 per-endpoint 归属数据，各块同聚合（信息无损、不虚构归属）。接口与
    参数全无 → 返回空（整节省略）。"""
    descriptors, structured = _endpoint_descriptors(vuln)
    rows = _entry_rows(vuln, loc)
    if not descriptors and not rows:
        return []
    row_params = [p for p, _, _ in rows]
    row_sinks = [s for _, s, _ in rows]
    row_chains = [c for _, _, c in rows]
    card_auth = getattr(vuln, "authentication_required", None)
    card_auth = card_auth.strip() if isinstance(card_auth, str) and card_auth.strip() else None
    zh = current_lang() == "zh"
    lines: list[str] = [_M.get("sec_endpoints")]
    if descriptors:
        for d in descriptors:
            head = "- " + (f"{d['method']} " if d["method"] else "") + d["path"]
            if d["role"]:
                head += f"（{d['role']}）" if zh else f" ({d['role']})"
            lines.append(head)
            params = list(d["params"])
            sinks = [d["sink"]] if d["sink"] else []
            if not structured:
                # 派生块并入卡级 rows 聚合（富化块自带，不重复并入）
                params += row_params
                sinks += row_sinks
            small = _ep_small_line(params, d["auth"] or card_auth, d["route"],
                                   sinks, row_chains)
            if small:
                lines.append(small)
    else:
        # 无接口锚点但卡级 rows 有料（如纯位置条目）：小字行独立成行
        small = _ep_small_line(row_params, card_auth, None, row_sinks, row_chains)
        if small is None:
            return []
        lines.append(small)
    return lines


def _problem_points(vuln) -> list[tuple[str, str | None, str | None]]:
    """report_problem_points（富化写回）→ (location, description, snippet) 列表。
    宽松校验同 report_data_builder._problem_points：非 dict / 缺 location 丢弃。"""
    points: list[tuple[str, str | None, str | None]] = []
    for item in (getattr(vuln, "report_problem_points", None) or []):
        if not isinstance(item, dict):
            continue
        location = str(item.get("location") or "").strip()
        if not location:
            continue
        points.append((location, item.get("description"), item.get("snippet")))
    return points


def _issue_section_lines(vuln, vuln_class: str, param, sink_name,
                         loc: str | None, snippet: str | None) -> list[str]:
    """问题点三要素（spec 2026-08-26-vuln-card-seven-sections §3 节 3）：
    report_problem_points（富化写回，逐条 位置/说明/snippet fence——语言标签按
    文件后缀）优先；无则回落合成路径——位置（file:line，回退链见 _card_loc）、
    说明（{param} 未经校验进入 {sink}；XSS 附渲染上下文）、传入 snippet fence
    （提取失败缺省 fence，位置+说明照常——不再整节省略）。位置与说明全无 →
    返回空。"""
    points = _problem_points(vuln)
    if points:
        out = [_M.get("sec_code")]
        for location, desc, pt_snippet in points:
            out.append(f"- **{_M.get('issue_location')}:** {location}")
            if desc:
                out.append(f"- **{_M.get('issue_desc_label')}:** {desc}")
            if pt_snippet:
                out.append(f"```{_snippet_lang_tag(location)}")
                out.append(str(pt_snippet))
                out.append("```")
        return out
    desc = None
    if sink_name:
        p_disp = param or _M.get("code_input_generic")
        desc = _M.get("code_issue_line", param=p_disp, sink=sink_name)
        rc = getattr(vuln, "render_context", None)
        if rc and vuln_class == "xss":
            desc = (desc.rstrip("。.")
                    + _M.get("issue_render_ctx", ctx=rc)
                    + ("。" if current_lang() == "zh" else "."))
    if not loc and not desc:
        return []
    out = [_M.get("sec_code")]
    if loc:
        out.append(f"- **{_M.get('issue_location')}:** {loc}")
    if desc:
        out.append(f"- **{_M.get('issue_desc_label')}:** {desc}")
    if snippet:
        out.append(f"```{_snippet_lang_tag(loc or '')}")
        out.append(snippet)
        out.append("```")
    return out


def _dataflow_item_lines(vuln) -> list[str]:
    """数据流分点（用户口径 2026-08-25：不要混成一团）：dataflow_steps 优先
    （结构化，每步 label + file:line）；无 steps 按 evidence_chain 的 →/-> 拆。
    `- **数据流:**` 标签行 + 2 空格缩进编号子列表；无素材返回空。"""
    steps = getattr(vuln, "dataflow_steps", None)
    items: list[str] = []
    if steps:
        for s in steps:
            if not isinstance(s, dict):
                continue
            label = str(s.get("label") or "?")
            f = s.get("file")
            if f:
                label += f" ({f}:{s.get('line')})" if s.get("line") else f" ({f})"
            items.append(label)
    else:
        chain = getattr(vuln, "evidence_chain", None)
        if isinstance(chain, str) and chain:
            items = [p.strip() for p in re.split(r"\s*(?:→|->)\s*", chain)
                     if p.strip()]
    if not items:
        return []
    return [_label("dataflow")] + [f"  {i}. {t}" for i, t in enumerate(items, 1)]


def _poc_section_lines(vuln) -> list[str]:
    """POC 独立节（§3 节 5；spec 2026-08-27-poc-agent-direct-design：agent 直产
    文本透传）——前置条件/预期响应/自检标注行 + steps 有序步骤 + curl（```bash）
    与 raw_http（```http）双 fenced block，缺则对应行/块省。self_check=fail 带 ⚠
    （agent 自报不通过好过静默错）。无 report_poc 或无可渲染内容 → 整节省略。"""
    poc = getattr(vuln, "report_poc", None)
    if not isinstance(poc, dict):
        return []
    lines: list[str] = []
    preconditions = str(poc.get("preconditions") or "").strip()
    if preconditions:
        lines.append(f"{_label('poc_preconditions')} {preconditions}")
    expected = str(poc.get("expected_response") or "").strip()
    if expected:
        lines.append(f"{_label('poc_expected')} {expected}")
    self_check = str(poc.get("self_check") or "").strip().lower()
    if self_check == "fail":
        lines.append(f"> ⚠ {_M.get('poc_self_check_fail')}")
    notes = str(poc.get("notes") or "").strip()
    if notes:
        lines.append(f"> {notes}")
    steps = [s for s in (poc.get("steps") or []) if str(s).strip()]
    for i, s in enumerate(steps, 1):
        lines.append(f"{i}. {str(s).strip()}")
    curl = str(poc.get("curl") or "").strip()
    if curl:
        lines.extend(("```bash", curl, "```"))
    raw_http = str(poc.get("raw_http") or "").strip()
    if raw_http:
        lines.extend(("```http", raw_http, "```"))
    if not lines:
        return []
    return [_M.get("sec_poc"), *lines]


def _tech_detail_lines(vuln) -> list[str]:
    """漏洞细节折叠区（用户口径 2026-08-25 + 2026-08-26 §4.1 收敛）：数据流
    （分点）→ 防护情况置顶，判定/CVSS/OWASP 随后，其余判定字段全量收纳，
    沿用 _label 行式。信息归并（§4.1）：脆弱位置/来源详情并入数据流分点，
    Sink 函数/渲染上下文/脆弱代码位置并入问题点三要素，端点/来源端点并入
    相关接口紧凑块——均不再在本区独立成行；witness 升 POC 独立节
    （vuln-card-seven-sections §4.3），本区不再渲染 PoC 行。"""
    lines: list[str] = []

    def add(key: str, value) -> None:
        if value:
            lines.append(f"{_label(key)} {value}")

    # 1. 数据流（分点编号，不混排）
    lines.extend(_dataflow_item_lines(vuln))
    # 2. 防护情况：taint 净化（encoding/sanitization）+ authz 防护证据 +
    #    auth/ssrf 缺失防护（同属防护语义，收拢置顶）
    if getattr(vuln, "encoding_observed", None):
        add("encoding_observed", vuln.encoding_observed)
    else:
        add("sanitization_observed", getattr(vuln, "sanitization_observed", None))
    add("guard_evidence", getattr(vuln, "guard_evidence", None))
    add("missing_defense", getattr(vuln, "missing_defense", None))
    # 3. 判定三件套
    add("verdict", getattr(vuln, "verdict", None))
    add("cvss", getattr(vuln, "cvss", None))
    add("owasp_category", getattr(vuln, "owasp_category", None))
    # 4. 其余判定字段照旧全量（归并行不再渲染，见 docstring）
    add("concat_occurrences", getattr(vuln, "concat_occurrences", None))
    add("vulnerable_parameter", getattr(vuln, "vulnerable_parameter", None))
    add("exploitation_hypothesis", getattr(vuln, "exploitation_hypothesis", None))
    add("suggested_exploit_technique", getattr(vuln, "suggested_exploit_technique", None))
    add("role_context", getattr(vuln, "role_context", None))
    add("side_effect", getattr(vuln, "side_effect", None))
    add("reason", getattr(vuln, "reason", None))
    add("minimal_witness", getattr(vuln, "minimal_witness", None))
    return lines


def _verify_steps_section_lines(vuln) -> list[str]:
    """验证步骤节（黑盒实测过程）：``verification_steps``（_VulnView 从
    ``evidence.steps`` 暴露）→ 有序列表，command 嵌套 ```bash 围栏、result 以
    ``→ `` 观察行跟随（对齐 renderers/exploit 的结构化步骤渲染形态）。缺字段
    整节省略。"""
    steps = getattr(vuln, "verification_steps", None)
    if not steps:
        return []
    lines = [_M.get("sec_verify_steps")]
    for i, s in enumerate(steps, start=1):
        action = str(s.get("action") or "").strip()
        command = s.get("command")
        result = s.get("result")
        if not action and not command:
            continue
        marker = f"{i}. "
        indent = " " * len(marker)
        if command:
            lines.append(f"{marker}{action}" if action
                         else f"{marker}```bash")
            if action:
                lines.append(f"{indent}```bash")
            lines.append(str(command))
            lines.append(f"{indent}```")
            if result:
                lines.append(f"{indent}→ {result}")
        else:
            tail = f" → {result}" if result else ""
            lines.append(f"{marker}{action}{tail}")
    return lines


def render_vuln_card(vuln, vuln_class: str, snippet: str | None = None) -> str:
    """统一漏洞卡（spec 2026-08-26-vuln-card-seven-sections §3 七节基准）。

    结构：`### {ID} {类名}：{title}` → 元信息行（严重程度/CWE/验证/置信度，
    双轨确认、GN-only 追加待复核）→ **漏洞成因（研判依据）** → **漏洞危害** →
    **问题点**（report_problem_points 优先，回落位置+说明+snippet fence）→
    **相关接口**（紧凑块，弃表）→ **POC**（report_poc；前置条件/预期响应/
    Witness + curl/raw_http 双 fenced，无则整节省略）→ #### 漏洞细节（数据流
    分点/防护情况 + 判定字段全量收纳）→ **修复建议**（收尾）。
    内部标签（llm-pass-failed/needs_review/unparseable-llm）零泄漏。
    """
    zh = current_lang() == "zh"
    colon = "：" if zh else ": "
    cls_name = _M.get(f"cardname_{vuln_class}")
    gn_only = (getattr(vuln, "source_track", None) == "gitnexus"
               and getattr(vuln, "merge_source", None) != "both")
    param = _card_param(vuln)
    sink_name, sink_loc = _card_sink(vuln)
    loc = _card_loc(vuln, sink_loc)
    loc_part = f"（{loc}）" if zh and loc else (f" ({loc})" if loc else "")

    lines: list[str] = []

    # 标题：有 title 用 title；缺省走确定性描述 `{param} 传入 {sink}（{loc}）`
    core = _deterministic_core(vuln)
    title = vuln.title or (core + loc_part if core else None)
    lines.append(f"### {vuln.ID} {cls_name}{colon}{title}" if title
                 else f"### {vuln.ID} {cls_name}")
    lines.append("")

    # 元信息行：严重程度 ｜ CWE ｜ 验证 ｜ 置信度（双轨确认）[｜ 待复核]
    sev = effective_severity(vuln)
    sev_disp = SEVERITY_ZH.get(sev, sev) if zh else sev.capitalize()
    meta_parts = [f"{_M.get('meta_severity')}{sev_disp}"]
    if vuln.cwe_id:
        meta_parts.append(vuln.cwe_id)
    verif = (_M.get("verif_dynamic")
             if getattr(vuln, "verification", None) == "dynamically_verified"
             else _M.get("verif_static"))
    meta_parts.append(f"{_M.get('meta_verification')}{verif}")
    conf = vuln.confidence or ""
    conf_disp = (CONFIDENCE_ZH if zh else CONFIDENCE_EN).get(conf, _strip_internal(conf))
    conf_line = f"{_M.get('meta_confidence')}{conf_disp}"
    if getattr(vuln, "merge_source", None) == "both":
        conf_line += _M.get("meta_dual_track")
    meta_parts.append(conf_line)
    if gn_only and conf != "unadjudicated":
        pending = _M.get("gn_pending_review")
        # §4.4：confidence 已显示「待复核」（needs_review 内部标签替换）时不再追加；
        # §5.7：unadjudicated 已显示「未判定（判定通道失败）」——语义不同，同样不追加
        if pending not in conf_line:
            meta_parts.append(pending)
    lines.append(_M.get("meta_sep").join(meta_parts))
    lines.append("")

    # 漏洞成因（研判依据）：语义化成立依据 / 确定性描述；链 dump 与接口行不混排
    lines.append(_M.get("sec_description"))
    lines.extend(_description_lines(
        vuln, gn_only, cls_name, colon, param, sink_name, loc_part, vuln_class))
    lines.append("")

    # 危害（§3 节 2）：impact（并行任务加的字段，此刻可能不存在）→ notes →
    # 类级兜底；GN-only 统一明示「静态链路发现，建议人工确认后修复」
    impact = getattr(vuln, "impact", None)
    if gn_only:
        impact = impact or vuln.notes or _M.get("gn_static_hint")
    else:
        impact = impact or vuln.notes or _M.get(_IMPACT_FALLBACK[vuln_class])
    lines.append(_M.get("sec_impact"))
    lines.append(impact)
    lines.append("")

    # 问题点三要素（§3 节 3）：report_problem_points 优先 → 位置 + 说明
    # （XSS 附渲染上下文）+ snippet fence 回落；snippet 提取失败仅缺 fence，
    # 位置+说明照常（不再整节省略）
    issue_lines = _issue_section_lines(vuln, vuln_class, param, sink_name, loc, snippet)
    if issue_lines:
        lines.extend(issue_lines)
        lines.append("")

    # 相关接口（§3 节 4）：每接口一块（紧凑小字行，弃表）
    entry_lines = _entry_section_lines(vuln, loc)
    if entry_lines:
        lines.extend(entry_lines)
        lines.append("")

    # POC（§3 节 5，独立节）：report_poc 缺则整节省略
    poc_lines = _poc_section_lines(vuln)
    if poc_lines:
        lines.extend(poc_lines)
        lines.append("")

    # 验证步骤（黑盒实测过程，2026-08-27）：steps 非空才出（黑盒/融合卡），
    # 紧随 POC——复现请求之上的实测过程分步骤记录，命令可复制人工复验。
    vsteps_lines = _verify_steps_section_lines(vuln)
    if vsteps_lines:
        lines.extend(vsteps_lines)
        lines.append("")

    # 漏洞细节（§3 节 6，折叠附录区；PoC 行已升独立节）
    lines.append(_M.get("sec_tech_detail"))
    lines.extend(_tech_detail_lines(vuln))
    lines.append("")

    # 修复建议（§3 节 7，收尾）：remediation（并行任务加的字段）→ GN-only
    # 人工确认提示 → 类级兜底
    remediation = getattr(vuln, "remediation", None)
    if not remediation:
        remediation = _M.get("gn_rem_hint" if gn_only else _REM_FALLBACK[vuln_class])
    lines.append(_M.get("sec_remediation"))
    lines.append(remediation)

    # 行级 rstrip：吃掉内部标签剥离留下的行尾空白
    return "\n".join(
        l.rstrip() for l in _strip_internal("\n".join(lines)).splitlines())


@dataclass
class VulnClassConfig:
    heading: str        # message key（运行时 _M.get 解析）
    none_found_label: str  # message key
    queue_file: str
    findings_file: str
    render_entry: Callable


CLASS_CONFIG: dict[str, VulnClassConfig] = {
    "injection": VulnClassConfig(
        heading="heading_injection",
        none_found_label="none_injection",
        queue_file="injection_exploitation_queue.json",
        findings_file="injection_findings.md",
        render_entry=partial(render_vuln_card, vuln_class="injection"),
    ),
    "xss": VulnClassConfig(
        heading="heading_xss",
        none_found_label="none_xss",
        queue_file="xss_exploitation_queue.json",
        findings_file="xss_findings.md",
        render_entry=partial(render_vuln_card, vuln_class="xss"),
    ),
    "auth": VulnClassConfig(
        heading="heading_auth",
        none_found_label="none_auth",
        queue_file="auth_exploitation_queue.json",
        findings_file="auth_findings.md",
        render_entry=partial(render_vuln_card, vuln_class="auth"),
    ),
    "authz": VulnClassConfig(
        heading="heading_authz",
        none_found_label="none_authz",
        queue_file="authz_exploitation_queue.json",
        findings_file="authz_findings.md",
        render_entry=partial(render_vuln_card, vuln_class="authz"),
    ),
    "ssrf": VulnClassConfig(
        heading="heading_ssrf",
        none_found_label="none_ssrf",
        queue_file="ssrf_exploitation_queue.json",
        findings_file="ssrf_findings.md",
        render_entry=partial(render_vuln_card, vuln_class="ssrf"),
    ),
}


def _passes_filter(vuln: Vulnerability, config: ReportConfig) -> bool:
    if config.min_confidence:
        vuln_level = CONFIDENCE_ORDER.get(vuln.confidence, 0)
        min_level = CONFIDENCE_ORDER.get(config.min_confidence, 0)
        if vuln_level < min_level:
            return False
    if config.min_severity:
        severity = getattr(vuln, "severity", None)
        if severity is not None:
            vuln_level = SEVERITY_ORDER.get(severity, 0)
            min_level = SEVERITY_ORDER.get(config.min_severity, 0)
            if vuln_level < min_level:
                return False
    return True


def filter_vulnerabilities(queue: VulnerabilityQueue, config: ReportConfig) -> list[Vulnerability]:
    return [v for v in queue.vulnerabilities if _passes_filter(v, config)]


class FindingsRenderer:
    @staticmethod
    async def render_findings_from_queues(
        deliverables_path: Path,
        report_config: ReportConfig | None = None,
        *,
        queue_subdir: str | None = None,
        findings_subdir: str | None = None,
        repo_root: Path | None = None,
    ) -> None:
        """Render findings MD from queue JSON.

        Shared by both whitebox and blackbox callers. The keyword-only params
        route queue READS and findings WRITES to track subdirectories without
        coupling this shared service to either caller's layout:

        - ``findings_subdir``: when set, findings MD is written to
          ``deliverables_path / findings_subdir /`` (created if missing). When
          ``None`` (the whitebox default), findings are written directly under
          ``deliverables_path`` — preserving the pre-2026-07 behaviour so the
          whitebox caller's reads/writes stay inside ``whitebox/``.
        - ``queue_subdir``: when set, queue JSON is read via
          :func:`resolve_track_deliverable` (``deliverables_path / queue_subdir /
          filename`` with legacy root fallback). When ``None``, queues are read
          via :func:`resolve_intermediate` — tiering 后 queue 落桶内
          ``intermediate/``，读侧 intermediate/ 优先 + 平铺老结构兜底。
        - ``repo_root``: when set, each vuln gets a deterministic code snippet
          (sink line ±3, spec §10.4) extracted from the repo and injected into
          the card's 问题代码 section; ``affected_entries`` get ``direct``
          annotations. ``None`` skips extraction (blackbox / tests).

        Defaults preserve the old behaviour — existing callers are unaffected.
        """
        config = report_config or ReportConfig()
        if findings_subdir:
            findings_base = deliverables_path / findings_subdir
            findings_base.mkdir(parents=True, exist_ok=True)
        else:
            findings_base = deliverables_path
        for _vuln_class, class_cfg in CLASS_CONFIG.items():
            findings_path = findings_base / class_cfg.findings_file
            if await async_path_exists(findings_path):
                continue
            if queue_subdir:
                queue_path = resolve_track_deliverable(
                    deliverables_path, queue_subdir, class_cfg.queue_file)
            else:
                # tiering（spec 2026-08-18）：queue 是中间产物 → 写侧落桶内
                # intermediate/（executor.py intermediate_path），读侧须
                # intermediate/ 优先 + 平铺老结构兜底（f4b98d38 扫尾模式同口径；
                # 平铺直读会让 findings.md 静默缺失 → assemble 回落
                # analysis_deliverable → 报告页出现分分析报告）。
                queue_path = resolve_intermediate(
                    deliverables_path, class_cfg.queue_file)
            if queue_path is None or not await async_path_exists(queue_path):
                continue

            heading = _M.get(class_cfg.heading)
            try:
                content = await async_read_file(queue_path)
                parsed = VulnerabilityQueue.parse_lenient(
                    content, vuln_class=_vuln_class)
            except Exception as exc:  # noqa: BLE001 — isolate this class
                logger.warning("queue %s unreadable: %s", class_cfg.queue_file, exc)
                await async_write_file(findings_path, "\n".join([
                    f"## {heading}", "",
                    _M.get("queue_unreadable", heading=heading),
                    "", _M.get("disclaimer"), "",
                ]))
                continue

            if parsed.warnings:
                logger.warning(
                    "queue %s parsed leniently: %s", class_cfg.queue_file, parsed.warnings
                )
            queue = parsed.queue
            filtered = filter_vulnerabilities(queue, config)

            sections: list[str] = [f"## {heading}", ""]
            if parsed.warnings:
                sections.append(
                    _M.get("queue_auto_recovered",
                           warnings="; ".join(parsed.warnings),
                           queue_file=class_cfg.queue_file)
                )
                sections.append("")

            if not filtered:
                if parsed.original_form == "object" and not parsed.warnings:
                    sections.append(_M.get(class_cfg.none_found_label))
                else:
                    reason = "; ".join(parsed.warnings) or _M.get("no_parseable_entries")
                    sections.append(
                        _M.get("no_renderable_entries",
                               queue_file=class_cfg.queue_file, reason=reason)
                    )
            else:
                for vuln in filtered:
                    try:
                        snippet: str | None = None
                        if repo_root is not None:
                            # 位置 SSOT = _card_loc（§4.4 与问题点节同一回退链）
                            loc = _card_loc(vuln, _card_sink(vuln)[1])
                            if loc:
                                snippet = await extract_snippet(repo_root, loc)
                            annotate_direct(
                                getattr(vuln, "affected_entries", None), snippet)
                            vuln.code_snippet = snippet
                        sections.append(class_cfg.render_entry(vuln, snippet=snippet))
                    except Exception as exc:  # noqa: BLE001 — isolate single entry
                        logger.warning(
                            "render entry %s failed: %s",
                            getattr(vuln, "ID", "?"), exc,
                        )
                        sections.append(
                            _M.get("render_error", id=getattr(vuln, "ID", "UNKNOWN"))
                        )

            sections.append("")
            sections.append(_M.get("disclaimer"))
            sections.append("")
            await async_write_file(findings_path, "\n".join(sections))
