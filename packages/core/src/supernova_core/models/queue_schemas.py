import json
from dataclasses import dataclass, field
from typing import Union

from pydantic import BaseModel, TypeAdapter

class BaseVulnerability(BaseModel):
    ID: str
    vulnerability_type: str
    externally_exploitable: bool
    confidence: str
    # 一句话概括标题（spec 2026-08-06）：报告 ### ID: title 的 title SSOT。
    # 可选以兼容旧 queue；新数据的 title 由 collector submit_finding schema
    # （collectors/vuln.py 的 _FINDING_BASE_REQUIRED）强制必给（Phase 2 B 拓扑：
    # vuln queue 走 collector 主通道，不再有 _vuln_output_schema）。
    title: str | None = None
    notes: str | None = None
    # Spec §4.1 dual-track merge fields. All are optional for backward compatibility.
    source_track: str | None = None
    evidence_chain: str | None = None
    merge_source: str | None = None
    # 数据流视图（spec 2026-08-20 §4 P1）：GitNexus 轨 taint finding 关联
    # 候选链 sanitizer_annotations（CandidateChain.sanitizer_annotations），
    # 精确标注随之落盘（spec §4 P1 原文「不再用完即丢」）。放基类对所有子类
    # 生效（append-only，roster 对账按 ID 不按字段，与 Phase 2 无冲突）。
    sanitizer_annotations: list | None = None
    # 报告可读性改造（spec 2026-08-25 §4）：全部 append-only，旧 queue 兼容。
    severity: str | None = None            # critical/high/medium/low；缺省渲染层兜底
    cvss: str | None = None                # 如 "AV:N/AC:L/PR:L/UI:N 8.8"
    cwe_id: str | None = None              # "CWE-95"
    owasp_category: str | None = None      # "A03:2021-Injection"
    endpoint: str | None = None            # 归一化 "POST /contributions"
    # spec 2026-08-26 §5：该漏洞涉及的全部接口（写入+触发分开），元素可带角色
    # 注记如 "POST /memos (write)"；collector/prompt 侧 T2 教 LLM 输出，旧 queue 缺省。
    endpoints: list[str] | None = None
    affected_parameters: list[str] | None = None
    affected_entries: list[dict] | None = None  # {parameter, sink_location, chain_id, track, direct}
    verification: str | None = None        # static_analysis | dynamically_verified
    code_snippet: str | None = None        # 渲染层注入，不落 queue
    # "true"|"false" 契约（到达该缺陷是否需登录；PoC preconditions/Authorization
    # 头的信号源）。全类收编进基类（2026-08-27：auth/authz/ssrf 曾只教 prompt
    # 不落模型被静默丢弃——同 2026-08-20 injection/xss 教训，双侧契约见
    # tests/prompts/test_vuln_prompt_schema_contract.py）。
    authentication_required: str | None = None
    # spec 2026-08-25（Task 7）：LLM 轨 collector（submit_finding）新输出字段，
    # append-only 兼容旧 queue——不落 schema 的话 pydantic 会静默丢弃 collector
    # 产出的这两个字段（同 2026-08-20 authentication_required 静默丢弃教训）。
    impact: str | None = None          # 危害一句话（LLM 轨 collector 输出，报告卡片"危害"段权威来源）
    remediation: str | None = None     # 修复建议一句话（LLM 轨 collector 输出）
    # ---- 报告生成 agent 化（spec 2026-08-26-report-generation-agent-design §3/§5）----
    # agent 富化产物写回 SSOT queue 的 append-only 结构化字段（旧 queue 兼容全 None）：
    # ①归并终审（T2）：跨轨同洞合并——本卡为主体时挂靠的 GN 卡 ID 列表
    merged_from: list[str] | None = None
    # ②卡片富化（T3）：接口一体表行（models/report_data.EndpointEntry 形态 dict，
    # 含 route_registered_at/source_location/sink_location 行号链）
    report_endpoints: list[dict] | None = None
    # ②′问题点富化（spec 2026-08-26-vuln-card-seven-sections §4.1，同 T3 写回）：
    # 问题点三要素行（models/report_data.ProblemPoint 形态 dict：
    # location/description/snippet，snippet 为 repo 真实源码）
    report_problem_points: list[dict] | None = None
    # ③POC 增强（T4）：结构化 POC（models/report_data.PocBlock 形态 dict：
    # request/preconditions/expected_response/witness_payload）
    report_poc: dict | None = None

class InjectionVulnerability(BaseVulnerability):
    # injection 输出契约 = TS 原版 injectionFields（sink_call 族，vuln-injection.txt
    # 字段表所教，2026-08-20 follow-up 起与 collector schema 一致——见
    # collectors/vuln.py 与 tests/prompts/test_vuln_prompt_schema_contract.py）。
    source: str | None = None
    accessible_routes: str | None = None
    path: str | None = None
    sink_call: str | None = None
    slot_type: str | None = None
    sanitization_observed: str | None = None
    concat_occurrences: str | None = None
    verdict: str | None = None
    mismatch_reason: str | None = None
    witness_payload: str | None = None
    # XSS 风格字段保留兼容(_vuln_output_schema 时代的历史产出;
    # GitNexus 轨未来可能输出)。
    combined_sources: str | None = None
    source_detail: str | None = None
    sink_function: str | None = None
    render_context: str | None = None
    encoding_observed: str | None = None
    # 数据流视图（spec 2026-08-20 §4 P1）：GitNexus 轨 taint finding 关联
    # 候选链 flow_id，供 P4 组装器按 flow_id 拼接 GitNexus 枝。仅 GitNexus
    # 轨 inj/xss/ssrf 有意义（append-only，不破坏现有契约）。
    flow_id: str | None = None
    # P2 dataflow_steps：LLM 轨 taint 专属（spec §2 仅 inj/xss/ssrf）。
    # LLM 枝节点扁平数组（元素 {label:str, file:str, line:int|None,
    # protection:str|None}，全 optional），P4 组装器经 finding.dataflow_steps
    # 读 LLM 枝。Task 3 review 裁决不放基类（spec §2 L39：auth/authz 无
    # taint 流不加；collector schema 已同步收窄）。
    dataflow_steps: list[dict] | None = None

class XssVulnerability(BaseVulnerability):
    source: str | None = None
    source_detail: str | None = None
    accessible_routes: str | None = None
    path: str | None = None
    # GN 轨 sink 全标识（file:cls:fn:line:col，xss_builder 回填）——gn_collapse
    # _unit_key 凭它折叠 GN 单元 + 解析 affected_entries[].sink_location（对齐
    # InjectionVulnerability.sink_call 先例；spec 2026-08-26 §7 根因：缺此字段时
    # 15 条参数×行笛卡尔积链一条不折）。LLM 轨不产此字段（collector schema
    # 契约不合并，维持 sink_function 族）。
    sink_call: str | None = None
    sink_function: str | None = None
    render_context: str | None = None
    encoding_observed: str | None = None
    verdict: str | None = None
    mismatch_reason: str | None = None
    witness_payload: str | None = None
    # 数据流视图（spec 2026-08-20 §4 P1）：见 InjectionVulnerability 同名字段注释。
    flow_id: str | None = None
    # P2 dataflow_steps：LLM 轨 taint 专属（spec §2 仅 inj/xss/ssrf）——
    # 见 InjectionVulnerability 同名字段注释。
    dataflow_steps: list[dict] | None = None

class AuthVulnerability(BaseVulnerability):
    source_endpoint: str | None = None
    vulnerable_code_location: str | None = None
    missing_defense: str | None = None
    exploitation_hypothesis: str | None = None
    suggested_exploit_technique: str | None = None
    # 判词值域对齐其余子模型（inj/xss/ssrf/authz 均有）；auth 无 GN 轨，此字段
    # 由 endpoint-enrichment 复核翻案写（"safe"，单向），报告终末防线 skip。
    verdict: str | None = None

class SsrfVulnerability(BaseVulnerability):
    source_endpoint: str | None = None
    vulnerable_parameter: str | None = None
    vulnerable_code_location: str | None = None
    # GN 轨 sink 全标识（ssrf_builder 回填）——同 XssVulnerability.sink_call 注释：
    # gn_collapse 折叠与 sink_location 解析凭它（spec 2026-08-26 §7 根因修复）。
    sink_call: str | None = None
    missing_defense: str | None = None
    exploitation_hypothesis: str | None = None
    suggested_exploit_technique: str | None = None
    # Spec §5.6: align with injection/xss so the Plan 3 merger can do verdict OR
    # via the verdict field (not just externally_exploitable).
    path: str | None = None
    verdict: str | None = None
    witness_payload: str | None = None
    # 数据流视图（spec 2026-08-20 §4 P1）：见 InjectionVulnerability 同名字段注释。
    flow_id: str | None = None
    # P2 dataflow_steps：LLM 轨 taint 专属（spec §2 仅 inj/xss/ssrf）——
    # 见 InjectionVulnerability 同名字段注释。
    dataflow_steps: list[dict] | None = None

class AuthzVulnerability(BaseVulnerability):
    endpoint: str | None = None
    vulnerable_code_location: str | None = None
    role_context: str | None = None
    guard_evidence: str | None = None
    side_effect: str | None = None
    reason: str | None = None
    minimal_witness: str | None = None
    # 判词值域 "vulnerable"|"safe"（authz_gitnexus_judge/explore prompt 契约，
    # 对齐 inj/xss/ssrf 子模型的 verdict 字段）。不落模型的话 pydantic 会静默
    # 丢弃 agent 输出的 verdict → 判 safe 无出口、_split_authz_safe 分流失效
    # （同 2026-08-27 authentication_required 静默丢弃教训）。safe 卡由
    # activities._split_authz_safe 分流 dismissed_findings.json（不进报告）。
    verdict: str | None = None

Vulnerability = Union[InjectionVulnerability, XssVulnerability, AuthVulnerability, SsrfVulnerability, AuthzVulnerability, BaseVulnerability]

# pydantic 2: bare typing.Union has no .model_validate — use a TypeAdapter.
_VulnerabilityAdapter = TypeAdapter(Vulnerability)

# 按 vuln_class 强制解析的子类 adapter——规避 smart-union 在字段重叠时误判类型
# (injection 与 xss 共用 LLM 输出 schema,injection entry 会被误判为 XssVulnerability →
# render_vuln_card 访问 sink_call 崩 → 整章"渲染错误"占位)。
# 调用方已知 queue 的 class 时(如 findings_renderer 按 CLASS_CONFIG key 遍历)应传
# vuln_class 用对应子类解析,而非让通用 Union 猜类型。
_CLASS_ADAPTERS: dict[str, TypeAdapter] = {
    "injection": TypeAdapter(InjectionVulnerability),
    "xss": TypeAdapter(XssVulnerability),
    "auth": TypeAdapter(AuthVulnerability),
    "ssrf": TypeAdapter(SsrfVulnerability),
    "authz": TypeAdapter(AuthzVulnerability),
}


def parse_vuln_entry(entry: dict, vuln_class: str | None = None):
    """单条 queue entry → 对应子类实例（report_data.raw 重建用，公共入口）。

    与 parse_lenient 同一套 adapter 语义：已知 vuln_class 强制子类解析，
    未知/None 走 Union 猜测。畸形 entry 直接抛（调用方自行决定兜底）。
    """
    adapter = _CLASS_ADAPTERS.get(vuln_class, _VulnerabilityAdapter) \
        if vuln_class else _VulnerabilityAdapter
    return adapter.validate_python(entry)


@dataclass
class LenientParseResult:
    """Result of lenient queue parsing.

    ``queue`` is always a valid (possibly empty) VulnerabilityQueue.
    ``warnings`` is non-empty whenever lenient recovery was applied —
    callers MUST surface these (never silent).
    """
    queue: "VulnerabilityQueue"
    warnings: list[str] = field(default_factory=list)
    original_form: str = "object"  # object | bare_list | object_no_key | invalid_json


def _normalize_dataflow_steps(entry: dict) -> None:
    """P2: dataflow_steps 宽容归一——畸形不拒收 finding（spec §4 P2③）。

    在 parse_lenient 的 adapter.validate_python(entry) 之前原地清理 entry：
    - 键不存在 / None → 不动（pydantic 默认 None）；
    - 非 list → 删键（当作未提供）；
    - 元素非 dict → 丢弃**该元素**（spec 显式点名元素宾语）；
    - 字段类型错 → 忽略**该字段**（元素保留；spec 不点名元素宾语——
      按字段独立校验，字段间不联动。fix round 1 controller 裁决：label
      畸形但 file/line 合法时保留 file/line，P4 组装器按末节点 file:line
      定位 sink（spec §3 规则 2）依赖此信息）；
    - 各字段独立校验：label 非空 str 才留；file str 才留；line int 非
      bool（bool 是 int 子类，line=True 忽略）或 None 才留；protection
      str 或 None 才留；未提供的键不物化（缺席时不补 None）；
    - 全部元素清空后 → None（kept or None）。
    """
    if "dataflow_steps" not in entry:
        return
    raw = entry["dataflow_steps"]
    if raw is None:
        return
    if not isinstance(raw, list):
        del entry["dataflow_steps"]  # 非 list → 当作未提供
        return
    kept: list[dict] = []
    for item in raw:
        if not isinstance(item, dict):
            continue  # 非 dict 元素丢弃
        clean: dict = {}
        label = item.get("label")
        if isinstance(label, str) and label:
            clean["label"] = label
        file_ = item.get("file")
        if isinstance(file_, str):
            clean["file"] = file_
        if "line" in item:
            line = item["line"]
            if line is None or (isinstance(line, int) and not isinstance(line, bool)):
                clean["line"] = line
        if "protection" in item:
            prot = item["protection"]
            if prot is None or isinstance(prot, str):
                clean["protection"] = prot
        kept.append(clean)
    entry["dataflow_steps"] = kept or None


class VulnerabilityQueue(BaseModel):
    vulnerabilities: list[Vulnerability] = []

    @classmethod
    def parse_lenient(
        cls, content: str, vuln_class: str | None = None
    ) -> LenientParseResult:
        """Tolerantly parse a queue file, absorbing legacy/hand-written forms.

        Never raises. Supported forms:
        - {"vulnerabilities": [...]}            -> object (normal)
        - [...]                                  -> bare_list (wrapped)
        - {...} without "vulnerabilities"        -> object_no_key (empty)
        - invalid JSON                           -> invalid_json (empty)
        Per-entry schema failures are dropped (recorded in warnings).

        ``vuln_class``: when the caller knows which class a queue belongs to
        (e.g. ``injection_exploitation_queue.json`` → ``"injection"``), pass it to
        force each entry into the matching subtype via ``_CLASS_ADAPTERS`` instead of
        letting the bare ``Vulnerability`` Union smart-guess. This is required because
        injection and xss share the same LLM output schema, so smart-union misclassifies
        injection entries as ``XssVulnerability``. ``None`` (default) preserves the
        legacy union-guess behaviour for the many callers that parse mixed/unknown queues.
        Unknown class names fall back to union parsing with a warning.
        """
        warnings: list[str] = []

        # --- JSON decode ---
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, ValueError, TypeError) as exc:
            return LenientParseResult(
                queue=cls(vulnerabilities=[]),
                warnings=[f"invalid json: {exc}"],
                original_form="invalid_json",
            )

        # --- Normalize top-level form into an entries list ---
        if isinstance(data, list):
            warnings.append(f"wrapped bare-list form ({len(data)} {'entry' if len(data) == 1 else 'entries'})")
            original_form = "bare_list"
            entries = data
        elif isinstance(data, dict):
            entries = data.get("vulnerabilities")
            if not isinstance(entries, list):
                actual = type(entries).__name__ if entries is not None else "None"
                warnings.append(f"'vulnerabilities' is {actual}, expected list")
                return LenientParseResult(
                    queue=cls(vulnerabilities=[]),
                    warnings=warnings,
                    original_form="object_no_key",
                )
            original_form = "object"
        else:
            warnings.append(f"top-level JSON is {type(data).__name__}, expected object or array")
            return LenientParseResult(
                queue=cls(vulnerabilities=[]),
                warnings=warnings,
                original_form="invalid_json",
            )

        # --- Validate entries individually, drop malformed ---
        # 已知 vuln_class → 用对应子类 adapter(规避 smart-union 误判);否则通用 Union。
        if vuln_class and vuln_class in _CLASS_ADAPTERS:
            adapter = _CLASS_ADAPTERS[vuln_class]
        else:
            adapter = _VulnerabilityAdapter
            if vuln_class:
                warnings.append(
                    f"unknown vuln_class {vuln_class!r}; fell back to union parsing"
                )
        vulns: list[Vulnerability] = []
        dropped = 0
        for entry in entries:
            if not isinstance(entry, dict):
                dropped += 1
                continue
            _normalize_dataflow_steps(entry)  # P2 宽容归一：畸形 dataflow_steps 不拒收 finding
            try:
                vulns.append(adapter.validate_python(entry))
            except Exception:
                dropped += 1
        if dropped:
            warnings.append(f"dropped {dropped} malformed entr{'y' if dropped == 1 else 'ies'}")

        return LenientParseResult(
            queue=cls(vulnerabilities=vulns),
            warnings=warnings,
            original_form=original_form,
        )
