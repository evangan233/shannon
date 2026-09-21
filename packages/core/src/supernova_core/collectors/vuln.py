"""vuln 5 class 共用 collector:submit_finding(append) + 3 shared set_* + 1 per-class strategic_intelligence。

移植 TS apps/worker/src/collectors/vuln-collector.ts(整个文件权威；字段对照原 schema)。
- submit_finding             (数据主通道, append) per-class 单条 finding, spec 2026-08-19 §3.3
- set_findings_summary       (§1 + §2 + finding_roster) shared
- set_strategic_intelligence (§3)      per-class, 按 vuln_class 选 5 个 schema 之一
- set_safe_vectors           (§4)      shared
- set_blind_spots            (§5)      shared

声明式 schema(纯 JSON Schema dict,无 pydantic),经 bridge.py 双引擎桥生成 set_* 工具。
本模块不 import 任何 GitNexus / 确定性层 / code_index 符号——vuln source 是 LLM 自身分析,
collector 仅作结构化通道(守 §1 双轨独立性)。
"""
from __future__ import annotations

from supernova_core.collectors.base import CollectorBase, SectionSchema

VULN_CLASSES: list[str] = ["injection", "xss", "auth", "ssrf", "authz"]


# ── 本地 schema 构造 helper(不 import pre_recon.py 的私有 helper) ───────
def _str_field(desc: str, min_length: int = 1) -> dict:
    return {"type": "string", "minLength": min_length, "description": desc}


def _obj(props: dict, required: list[str], desc: str = "") -> dict:
    schema: dict = {"type": "object", "properties": props, "required": required}
    if desc:
        schema["description"] = desc
    return schema


# ============================================================================
# SHARED SCHEMAS — set_findings_summary / set_safe_vectors / set_blind_spots
# ============================================================================

# Pattern(对齐 TS PatternSchema)
_PATTERN: dict = _obj(
    {
        "name": _str_field(
            'Concise pattern name, e.g. "Weak Session Management", '
            '"Reflected XSS in Search Parameter", "Insufficient URL Validation".'
        ),
        "description": _str_field(
            "One- to two-sentence description of the pattern observed in the codebase."
        ),
        "implication": _str_field(
            "One- to two-sentence implication for exploitation — what does this pattern "
            "enable an attacker to do."
        ),
        "representative_finding_ids": {
            "type": "array",
            "items": {"type": "string", "minLength": 1},
            "minItems": 1,
            "description": (
                "IDs of findings that exhibit this pattern (e.g. "
                '["AUTH-VULN-01", "AUTH-VULN-02"]). Must match IDs the agent has assigned '
                "in the structured-output exploitation queue."
            ),
        },
    },
    ["name", "description", "implication", "representative_finding_ids"],
)

# set_findings_summary (§1 + §2 + roster 对账声明, spec 2026-08-19 §3.3)
FINDINGS_SUMMARY: dict = _obj(
    {
        "key_outcome": _str_field(
            "One to two sentences capturing the headline result of your analysis — what was "
            "found and its severity profile (e.g. \"Several high-confidence SQL injection "
            'vulnerabilities were identified; all findings have been passed to the exploitation '
            'phase"). Becomes Section 1 of the rendered deliverable.'
        ),
        "patterns": {
            "type": "array",
            "items": _PATTERN,
            "description": (
                "Complete list of dominant patterns observed across findings. Pass all patterns "
                "in one call. Empty array is acceptable if no recurring patterns were observed — "
                'the deliverable will render "No dominant patterns identified" for Section 2 in '
                "that case."
            ),
        },
        "finding_roster": {
            "type": "array",
            "items": _obj(
                {
                    "id": _str_field(
                        'Finding ID exactly as submitted via submit_finding (e.g. "AUTH-VULN-01").'
                    ),
                    "title": _str_field("Finding title exactly as submitted via submit_finding."),
                },
                ["id", "title"],
            ),
            "description": (
                "Reconciliation roster: the COMPLETE list of {id, title} for EVERY finding you "
                "submitted via submit_finding this session — one entry per submission, IDs "
                "matching exactly. Empty array if and only if you found no vulnerabilities. "
                "The host reconciles this roster against your submissions to catch lost ones."
            ),
        },
    },
    ["key_outcome", "patterns", "finding_roster"],
)

# SafeVector item(对齐 TS SafeVectorInputSchema)
_SAFE_VECTOR: dict = _obj(
    {
        "subject": _str_field(
            "The specific subject of analysis. For injection/xss runs, the input parameter name "
            '(e.g. "username", "redirect_url"). For auth/ssrf runs, the component or flow name '
            '(e.g. "Password Hashing", "Webhook Configuration"). For authz runs, the endpoint '
            '(e.g. "POST /api/auth/logout"). The renderer maps this to the class-appropriate '
            "column header."
        ),
        "location": _str_field(
            'File path with line number (e.g. "controllers/authController.js:45") or endpoint '
            'URL (e.g. "/profile"). For authz runs, this is the guard location specifically '
            '(e.g. "middleware/auth.js:45"). The renderer maps this to the class-appropriate '
            "column header."
        ),
        "defense_mechanism": _str_field(
            "The robust defense observed (e.g. \"Prepared Statement (Parameter Binding)\", "
            '"HTML Entity Encoding", "Strict URL Whitelist Validation", '
            '"bcrypt.compare for constant-time check").'
        ),
        "render_context": {
            "anyOf": [{"type": "string"}, {"type": "null"}],
            "description": (
                "XSS-only: the DOM render context for the validated vector — one of HTML_BODY, "
                "HTML_ATTRIBUTE, JAVASCRIPT_STRING, URL_PARAM, CSS_VALUE. Omit (or pass null) for "
                "non-XSS classes; the renderer only emits this column for the XSS deliverable."
            ),
        },
    },
    ["subject", "location", "defense_mechanism"],  # render_context 不在 required
)

# set_safe_vectors (§4)
SAFE_VECTORS: dict = _obj(
    {
        "vectors": {
            "type": "array",
            "items": _SAFE_VECTOR,
            "description": (
                "All input vectors / components / endpoints that were analyzed and confirmed to "
                'have robust, context-appropriate defenses. Empty array is acceptable but unusual — '
                'the deliverable will render "No vectors confirmed secure during analysis" for '
                "Section 4 in that case. Becomes Section 4 of the rendered deliverable. The "
                "renderer sorts by (subject, location) before rendering, so emission order does "
                "not affect output."
            ),
        },
    },
    ["vectors"],
)

# BlindSpot item(对齐 TS BlindSpotItemSchema)
_BLIND_SPOT_ITEM: dict = _obj(
    {
        "heading": _str_field(
            'Short heading for the blind spot (e.g. "Untraced Asynchronous Flows", '
            '"Limited Visibility into Stored Procedures", "Minified JavaScript Bundle").'
        ),
        "description": _str_field(
            "One to three sentences describing the analysis gap — what could not be traced, "
            "why, and what the residual risk is."
        ),
    },
    ["heading", "description"],
)

# set_blind_spots (§5)
BLIND_SPOTS: dict = _obj(
    {
        "items": {
            "type": "array",
            "items": _BLIND_SPOT_ITEM,
            "description": (
                "Analysis constraints, untraced code paths, or other coverage gaps that should be "
                'noted. Empty array is acceptable on high-coverage runs — the deliverable will '
                'render "No analysis constraints or blind spots identified" for Section 5 in that '
                "case. Becomes Section 5 of the rendered deliverable."
            ),
        },
    },
    ["items"],
)


# ============================================================================
# PER-CLASS set_strategic_intelligence SCHEMAS(字段对照 TS line 155-285)
# ============================================================================

INJECTION_STRATEGIC_INTEL: dict = _obj(
    {
        "defensive_evasion_waf": _str_field(
            "WAF behavior observed during analysis: active rules, common payloads blocked, "
            'identified bypasses (e.g. "WAF blocks UNION SELECT but not time-based blind '
            'injection"). Write "Not applicable — no WAF observed" if none was detected.'
        ),
        "error_based_potential": _str_field(
            "Whether endpoints leak verbose database errors that enable error-based injection "
            '(/api/products returns verbose PostgreSQL error messages, prime target for error-based '
            'exploitation"). Write "Not applicable" if no injection findings exist.'
        ),
        "confirmed_database_technology": _str_field(
            "Database engine(s) confirmed via error syntax or function calls (e.g. "
            '"PostgreSQL, confirmed via pg_sleep() and verbose error syntax"). Drives payload '
            'selection downstream. Write "Not applicable" if no DB sinks in scope.'
        ),
    },
    ["defensive_evasion_waf", "error_based_potential", "confirmed_database_technology"],
)

XSS_STRATEGIC_INTEL: dict = _obj(
    {
        "csp_analysis": _str_field(
            "Content Security Policy observed and its bypassability: current policy text, "
            "critical bypasses (e.g. \"script-src 'self' https://trusted-cdn.com — the trusted "
            'CDN hosts vulnerable AngularJS, enabling client-side template injection bypass"). '
            'Write "Not applicable — no CSP header served" if none.'
        ),
        "cookie_security": _str_field(
            "Session cookie security observations: HttpOnly, Secure, SameSite flags, and storage "
            "mechanism (e.g. \"Primary session cookie `sessionid` is missing HttpOnly; tokens are "
            'also stored in localStorage, both accessible to JavaScript"). Drives exfiltration '
            "strategy."
        ),
    },
    ["csp_analysis", "cookie_security"],
)

AUTH_STRATEGIC_INTEL: dict = _obj(
    {
        "authentication_method": _str_field(
            "How users authenticate: JWT, session cookie, OAuth, SAML, etc. Include any algorithm "
            'or library details (e.g. "JWT (RS256) with hardcoded private key in lib/insecurity.ts:23").'
        ),
        "session_token_details": _str_field(
            "Where tokens live and how they are protected: cookie name, storage mechanism (cookie "
            "vs localStorage), cookie flags, expiration (e.g. \"JWT stored in localStorage under "
            'key `token`; cookie copy lacks HttpOnly/Secure/SameSite; 6-hour TTL with no revocation").'
        ),
        "password_policy": _str_field(
            "Observed server-side password policy and storage: complexity rules, hashing algorithm, "
            "salt, (e.g. \"MD5 without salt via crypto.createHash; no server-side complexity policy; "
            'client-side 5-char minimum trivially bypassed").'
        ),
    },
    ["authentication_method", "session_token_details", "password_policy"],
)

SSRF_STRATEGIC_INTEL: dict = _obj(
    {
        "http_client_library": _str_field(
            "HTTP client library/libraries used for outbound requests (e.g. \"axios 1.6\", "
            '"node-fetch", "requests", "HttpClient (Spring)"). Include version where it informs '
            "known bypass techniques."
        ),
        "request_architecture": _str_field(
            "How outbound requests are constructed and routed: proxy/middleware patterns, internal "
            "routing rules (e.g. \"Webhook URLs are POSTed directly without an outbound proxy; "
            'redirects are followed by default with no maxRedirects limit").'
        ),
        "internal_services": _str_field(
            "Internal endpoints, services, or cloud-metadata addresses discovered during analysis "
            "that an SSRF could reach (e.g. \"169.254.169.254 (AWS IMDS), internal admin API at "
            'admin.internal:8443, PostgreSQL on localhost:5432").'
        ),
    },
    ["http_client_library", "request_architecture", "internal_services"],
)

AUTHZ_STRATEGIC_INTEL: dict = _obj(
    {
        "session_management_architecture": _str_field(
            "Session and authentication architecture relevant to authorization decisions: where "
            "user identity comes from, whether the user ID is trusted by downstream guards (e.g. "
            "\"JWT tokens in cookies; user ID extracted from `req.user.id` and used directly in DB "
            'queries without ownership re-validation").'
        ),
        "role_permission_model": _str_field(
            "Roles, capabilities, and where they live: identified roles, their privilege levels, "
            "and where role/permission data is stored (e.g. \"Three roles: user, moderator, admin. "
            "Role embedded in JWT and database; checks inconsistent — many admin routes only check "
            '`req.user` presence").'
        ),
        "resource_access_patterns": _str_field(
            "How resource IDs flow through the system and ownership patterns: e.g. \"Most endpoints "
            "use path parameters for resource IDs (/api/users/{id}); IDs are passed to DB queries "
            'without ownership validation". Critical for IDOR exploitation.'
        ),
        "workflow_implementation": _str_field(
            "Multi-step processes and state transitions: how workflow stages are tracked, whether "
            "prior-state checks are enforced (e.g. \"Multi-step processes use status fields in "
            'database; status transitions do not verify prior state completion"). Drives '
            "context-based authz exploitation."
        ),
    },
    [
        "session_management_architecture",
        "role_permission_model",
        "resource_access_patterns",
        "workflow_implementation",
    ],
)

_STRATEGIC_INTEL_SCHEMAS: dict[str, dict] = {
    "injection": INJECTION_STRATEGIC_INTEL,
    "xss": XSS_STRATEGIC_INTEL,
    "auth": AUTH_STRATEGIC_INTEL,
    "ssrf": SSRF_STRATEGIC_INTEL,
    "authz": AUTHZ_STRATEGIC_INTEL,
}


# ============================================================================
# submit_finding per-class finding schemas（spec 2026-08-19 §3.3）
# 单条 finding object（append item），基线 required + class 特有 optional（无 enum，
# 宽松优先——下游 parse_lenient 容错解析，enum 反而拒收合法变体）。
# ============================================================================

def _finding_props(class_props: dict) -> dict:
    props = {
        "ID": _str_field('Unique ID for this finding (e.g. "AUTH-VULN-01"); '
                         "reuse the same ID in finding_roster."),
        "vulnerability_type": _str_field(
            "Vulnerability subtype label for this class (free-form from the methodology, "
            'e.g. "Authentication_Bypass", "Session_Management_Flaw").'),
        "externally_exploitable": {
            "type": "boolean",
            "description": ("true if reachable from the public internet without prior "
                            "authentication state; false for internal/cross-service only."),
        },
        "confidence": _str_field('"High" | "Medium" | "Low".'),
        "title": _str_field(
            "一句话描述性标题，编码缺陷 + 位置，用简体中文撰写（漏洞类型/参数/路径/端点保留英文），"
            "如 'POST /login 缺少速率限制，可被暴力破解'。不要只写裸标签。"),
        "notes": _str_field(
            "Relevant details: required session state, applicable roles, observed headers, "
            "links to related findings."),
        # 报告可读性改造（spec 2026-08-25 Task 7）：报告四要素卡片字段进 collector
        # 共通 props（全 optional，不动 _FINDING_BASE_REQUIRED——旧 collector 消息
        # 向后兼容）。prompt 字段表同步所教（<report-style> 风格指南约束写法），
        # 一致性由 test_vuln_prompt_schema_contract.py 锁定。落盘走
        # BaseVulnerability（impact/remediation 已入 schema，不静默丢弃）。
        "severity": {
            "type": "string",
            "enum": ["critical", "high", "medium", "low"],
            "description": (
                "critical/high/medium/low 之一，按实际影响定档（见 <report-style> "
                "风格指南），不要一律 critical。"),
        },
        "impact": _str_field(
            "危害一句话（结论先行，不超过 3 句）——报告卡片'危害'段的权威来源。"),
        "remediation": _str_field(
            "修复建议一句话：代码级具体（改哪个函数、换成什么写法），不写空话。"),
        "cwe_id": _str_field('CWE 编号，如 "CWE-95"、"CWE-79"。'),
        # 终审遗留 F5（2026-08-25）：cvss/owasp_category 是死字段——schema 有、
        # 渲染层也渲染，但工具契约从不教 ⇒ 无人填。此处复活：进 collector 共通
        # props + prompt 字段表同步所教（同样全 optional，不确定就省略，不编造）。
        "cvss": {
            "type": "string",
            "description": (
                "可选：CVSS 向量串与估分，如 'AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H 9.8'。"
                "按向量估分；不确定时省略，不要编造。"),
        },
        "owasp_category": _str_field(
            "可选：OWASP Top 10 分类，如 'A03:2021-Injection'；不确定时省略。"),
    }
    props.update(class_props)
    return props


_FINDING_BASE_REQUIRED = ["ID", "vulnerability_type", "externally_exploitable",
                          "confidence", "title"]

# P2 dataflow_steps（spec 2026-08-20 dataflow-view §2 L39 / §4 P2①）：扁平数组
# （压缩 GLM 结构化输出失败面）。仅三个 taint class（inj/xss/ssrf）携带——
# auth/authz 无 taint 流不加；三处引用同一 dict 对象（单一声明，非复制三份，
# 保持 bridge 双引擎「同一份 dict」语义）。元素全 optional：items 无 required 键，
# 与 description 自洽；下游 _normalize_dataflow_steps（Task 4）对 label 缺失/类型
# 错宽容（留元素不丢）。
_DATAFLOW_STEPS_FIELD: dict = {
    "type": "array",
    "description": "按传播顺序列 source→sink 经过的节点；防护节点标 protection。元素全 optional。",
    "items": {
        "type": "object",
        "properties": {
            "label": {"type": "string", "minLength": 1, "description": "函数名或调用点描述"},
            "file": {"type": "string", "description": "文件路径"},
            "line": {"anyOf": [{"type": "integer"}, {"type": "null"}], "description": "行号，未知填 null"},
            "protection": {"anyOf": [{"type": "string"}, {"type": "null"}], "description": "该节点防护（sanitizer 名）；无防护填 null"},
        },
    },
}

# injection / xss 是两套字段契约（对齐 TS 原版 queue-schemas.ts 的
# injectionFields / xssFields，2026-08-20 follow-up 拆分）：injection=sink_call 族，
# xss=sink_function 族；两轨各含 prompt 移植增强字段 authentication_required /
# accessible_routes（此前不在 schema，模型按 prompt 交出后 pydantic 静默丢弃）。
# prompt 字段表（vuln-*.txt <finding_submission>）是契约权威——schema 与其一致性
# 由 tests/prompts/test_vuln_prompt_schema_contract.py 锁定，漂移即红。
# RPC 接口关联（spec 2026-09-21 §3.4）：RPC/gRPC 服务的接口标识方法论指引，
# injection/xss/auth（ssrf 继承 auth）三处 endpoints description 共享。
# 方法论指引——源由 agent 自行 grep 派生，不注入确定性产物（双轨铁律不涉及）。
_RPC_ENDPOINT_GUIDANCE = (
    " 对 RPC/gRPC 服务（无 HTTP 路由），产出 RPC 接口标识 /Service/Method"
    "（可带 proto 包名，如 /pkg.Service/Method）——自行 grep .proto 的 "
    "service/rpc 定义或 Go 方法实现（receiver 类型=service 名、方法名=rpc 名）得出。"
)

_INJECTION_FINDING_PROPS: dict = {
    "source": _str_field(
        "Tainted input param name & file:line — a SINGLE source per finding."),
    "authentication_required": _str_field(
        '"true" | "false" — whether login is required to reach this sink via this '
        "route (check the router file for auth middleware)."),
    "accessible_routes": _str_field(
        "All routes reaching this sink with middleware chains, one per line: "
        "'METHOD /path [middleware1, middleware2, ...]'."),
    "path": _str_field(
        "Source→sink hop list; MUST start with 'METHOD /route' when HTTP-reachable."),
    "sink_call": _str_field("Sink file:line and function/method."),
    "slot_type": _str_field(
        "Sink slot label (SQL-val | SQL-like | SQL-num | SQL-enum | SQL-ident | "
        "CMD-argument | CMD-part-of-string | FILE-path | FILE-include | "
        "TEMPLATE-expression | DESERIALIZE-object | PATH-component)."),
    "sanitization_observed": _str_field(
        "Sanitizers on this path: name & file:line, all of them, in order."),
    "concat_occurrences": _str_field(
        "Each concat/format/join with file:line; flag those after sanitization."),
    "verdict": _str_field('"vulnerable" — only vulnerable findings are submitted.'),
    "mismatch_reason": _str_field("Why the defense fails / mismatches (1–2 lines)."),
    "witness_payload": _str_field(
        "Minimal concrete payload value proving the flaw (payload 值本身，无前缀无说明)."),
    # spec 2026-08-26 §5：受影响入口节结构化数据源（接口列表 + 外部参数）。
    "endpoints": {
        "type": "array",
        "items": {"type": "string"},
        "description": (
            "该漏洞涉及的全部接口（METHOD /path）；写入与触发分开列（如存储型 XSS "
            "的写入口与渲染触发口），可带角色注记，如 'POST /memos (write)'、"
            "'GET /memos (trigger)'。" + _RPC_ENDPOINT_GUIDANCE),
    },
    "affected_parameters": {
        "type": "array",
        "items": {"type": "string"},
        "description": (
            "外部可控参数名，每个必须带位置注记：(body) 或 (query)，按路由"
            "读取方式判定（req.body.x → body，req.query.x / ?x= → query）——"
            "PoC 参数位的权威信号。"),
    },
    "dataflow_steps": _DATAFLOW_STEPS_FIELD,
}

_XSS_FINDING_PROPS: dict = {
    "source": _str_field("The tainted input vector (parameter/field/body path)."),
    "source_detail": _str_field("Where the input enters (route + handler)."),
    "authentication_required": _str_field(
        '"true" | "false" — whether login is required to reach this sink via this '
        "route (check the router file for auth middleware)."),
    "accessible_routes": _str_field(
        "All routes reaching this sink with middleware chains, one per line: "
        "'METHOD /path [middleware1, middleware2, ...]'."),
    "path": _str_field(
        "Source→sink dataflow path summary; HTTP-reachable时以 METHOD /route 开头."),
    "sink_function": _str_field("The dangerous sink call (function + file:line)."),
    "render_context": _str_field("Render context (HTML_BODY/HTML_ATTRIBUTE/JAVASCRIPT_STRING/URL_PARAM/CSS_VALUE)."),
    "encoding_observed": _str_field("Encoding/sanitization observed on the path (or none)."),
    "verdict": _str_field('"vulnerable" | "safe" — only vulnerable findings are submitted.'),
    "mismatch_reason": _str_field("Why the defense fails / mismatches."),
    "witness_payload": _str_field("Minimal concrete payload value proving the flaw (payload 值本身，无前缀无说明)."),
    # spec 2026-08-26 §5：受影响入口节结构化数据源（接口列表 + 外部参数）。
    "endpoints": {
        "type": "array",
        "items": {"type": "string"},
        "description": (
            "该漏洞涉及的全部接口（METHOD /path）；写入与触发分开列（如存储型 XSS "
            "的写入口与渲染触发口），可带角色注记，如 'POST /memos (write)'、"
            "'GET /memos (trigger)'。" + _RPC_ENDPOINT_GUIDANCE),
    },
    "affected_parameters": {
        "type": "array",
        "items": {"type": "string"},
        "description": (
            "外部可控参数名，每个必须带位置注记：(body) 或 (query)，按路由"
            "读取方式判定（req.body.x → body，req.query.x / ?x= → query）——"
            "PoC 参数位的权威信号。"),
    },
    "dataflow_steps": _DATAFLOW_STEPS_FIELD,
}

_AUTH_FINDING_PROPS: dict = {
    "source_endpoint": _str_field('"{HTTP_METHOD} {endpoint_path}".'),
    "authentication_required": _str_field(
        '"true" | "false" — whether login is required to reach this flaw via '
        "this route (check the router file for auth middleware)."),
    "vulnerable_code_location": _str_field("Exact file:line of the flawed logic or missing check."),
    "missing_defense": _str_field("Concise core problem (e.g. 'No rate limit on POST /login')."),
    "exploitation_hypothesis": _str_field("Active attack outcome on success (not just confirmation)."),
    "suggested_exploit_technique": _str_field("Attack pattern to attempt (e.g. 'brute_force_login')."),
}

_SSRF_FINDING_PROPS: dict = {
    **_AUTH_FINDING_PROPS,
    "vulnerable_parameter": _str_field("The outbound-request parameter carrying attacker-controlled input."),
    "witness_payload": _str_field("Minimal concrete payload value proving the flaw (payload 值本身，无前缀无说明)."),
    # spec 2026-08-26 §5：受影响入口节结构化数据源（接口列表 + 外部参数）。
    "endpoints": {
        "type": "array",
        "items": {"type": "string"},
        "description": (
            "该漏洞涉及的全部接口（METHOD /path）；写入与触发分开列（如存储型 XSS "
            "的写入口与渲染触发口），可带角色注记，如 'POST /memos (write)'、"
            "'GET /memos (trigger)'。" + _RPC_ENDPOINT_GUIDANCE),
    },
    "affected_parameters": {
        "type": "array",
        "items": {"type": "string"},
        "description": (
            "外部可控参数名，每个必须带位置注记：(body) 或 (query)，按路由"
            "读取方式判定（req.body.x → body，req.query.x / ?x= → query）——"
            "PoC 参数位的权威信号。"),
    },
    "dataflow_steps": _DATAFLOW_STEPS_FIELD,
}

_AUTHZ_FINDING_PROPS: dict = {
    "endpoint": _str_field("Affected endpoint (e.g. 'POST /api/auth/logout')."),
    "authentication_required": _str_field(
        '"true" | "false" — whether the attacker must be authenticated to '
        "trigger this flaw (broken object-level auth is usually \"true\")."),
    "vulnerable_code_location": _str_field("Guard location (file:line)."),
    "role_context": _str_field("Roles involved (owner/victim or role pair)."),
    "guard_evidence": _str_field("What the guard checks vs. omits (ownership re-validation gap)."),
    "side_effect": _str_field("State-changing effect reachable without authorization."),
    "reason": _str_field("Why this is exploitable (missing check / broken object-level auth)."),
    "minimal_witness": _str_field("Minimal request pair or ID substitution demonstrating the flaw."),
}

_FINDING_SCHEMAS: dict[str, dict] = {
    "injection": _obj(_finding_props(_INJECTION_FINDING_PROPS), _FINDING_BASE_REQUIRED),
    "xss": _obj(_finding_props(_XSS_FINDING_PROPS), _FINDING_BASE_REQUIRED),
    "auth": _obj(_finding_props(_AUTH_FINDING_PROPS), _FINDING_BASE_REQUIRED),
    "ssrf": _obj(_finding_props(_SSRF_FINDING_PROPS), _FINDING_BASE_REQUIRED),
    "authz": _obj(_finding_props(_AUTHZ_FINDING_PROPS), _FINDING_BASE_REQUIRED),
}


def _section(tool_name: str, key: str, desc: str, schema: dict,
             mode: str = "set") -> SectionSchema:
    return SectionSchema(
        tool_name=tool_name, section_key=key, description=desc,
        json_schema=schema, mode=mode
    )


def make_vuln_sections(vuln_class: str) -> list[SectionSchema]:
    """5 个 section（spec 2026-08-19 §3.3 后）：submit_finding（append，数据主通道）居首
    + 4 个 set_*（write-once，md 渲染通道，顺序对齐 TS VULN_TOOLS）。
    strategic_intelligence 按 class 选 schema。"""
    if vuln_class not in _STRATEGIC_INTEL_SCHEMAS:
        raise ValueError(f"unknown vuln class: {vuln_class!r}")
    intel_schema = _STRATEGIC_INTEL_SCHEMAS[vuln_class]
    finding_schema = _FINDING_SCHEMAS[vuln_class]
    return [
        _section(
            "submit_finding",
            "submitted_findings",
            "Submit ONE confirmed vulnerable finding IMMEDIATELY when its verdict is "
            "vulnerable — one finding per call, never batched. The host assembles the "
            "exploitation queue from these submissions.",
            finding_schema,
            mode="append",
        ),
        _section(
            "set_findings_summary",
            "findings_summary",
            "Headline result (Section 1) + dominant patterns (Section 2) + finding_roster "
            '(reconciliation roster). Empty patterns array renders "No dominant patterns '
            'identified".',
            FINDINGS_SUMMARY,
        ),
        _section(
            "set_strategic_intelligence",
            "strategic_intelligence",
            f"{vuln_class} strategic intelligence (Section 3). Per-class schema.",
            intel_schema,
        ),
        _section(
            "set_safe_vectors",
            "safe_vectors",
            'Vectors/components confirmed secure (Section 4). Empty renders "No vectors confirmed '
            'secure during analysis".',
            SAFE_VECTORS,
        ),
        _section(
            "set_blind_spots",
            "blind_spots",
            'Analysis constraints or blind spots (Section 5). Empty renders "No analysis '
            'constraints or blind spots identified".',
            BLIND_SPOTS,
        ),
    ]


def make_vuln_collector(vuln_class: str) -> CollectorBase:
    """per-vuln-class CollectorBase(5 section: submit_finding + 4 set_*)。"""
    return CollectorBase(section_schemas=make_vuln_sections(vuln_class))
