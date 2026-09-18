"""白盒 report_data 组装器（spec 2026-08-26-report-generation-agent-design §3/§4）。

确定性步骤：读合并后 SSOT（``{vc}_exploitation_queue.json``）+ attack_chains，
映射为 ``models/report_data.ReportData``。agent 富化（①归并终审 merged_from /
②接口表 report_endpoints / ③POC report_poc）已写回 queue 的结构化字段在此
优先采用；agent 步骤未跑/失败时现有确定性字段照常组装——报告永远完整。

纯数据搬运无渲染：md 导出（report_markdown_exporter）与前端渲染都吃本产物。

GN 卡 dataflow_steps 确定性派生（2026-08-31，零成本兜底层）：queue 的
dataflow_steps 是 LLM 轨 taint 专属字段，GN builder 不产、GN-only 深度富化
agent 又不保证回填 → 报告卡数据流整段缺失。组装时对空 steps 的 GN taint 卡
从 parameter_graph.json 派生 ``source(param) → hops(vars/transformation@file:line)
→ sink(callee@file:line)``——GN 自有精确形态（真实行号/变量名），不模仿 LLM
叙事；queue 已有 steps（富化深链）不覆盖，queue SSOT 不写派生值（字段契约
不破），只落 report_data 供 web / comprehensive md / 分项 findings.md 单源渲染。
"""
import json
import logging
import re

from supernova_core.models.report_data import (
    AttackChainEntry,
    EndpointEntry,
    PocBlock,
    QuickReferenceRow,
    ReportData,
    ReportStats,
    ReportVulnerability,
    ScanMeta,
    TypeStats,
    VulnEvidence,
    VulnNarrative,
    ProblemPoint,
)
from supernova_core.models.queue_schemas import VulnerabilityQueue
from supernova_core.services.findings_renderer import CLASS_CONFIG
from supernova_core.services.vulnerability_cause import vulnerability_cause
# 速查表行口径复用 report_assembler 单元格函数（勿抄逻辑——与 md 现速查表
# 同源，spec 2026-08-26-report-single-source-rendering §5「渲染层纯渲染」）
from supernova_core.services.report_assembler import (
    _confidence_cell,
    _endpoint_cell,
    _report_endpoint_params,
    _report_endpoint_routes,
    _severity_cell,
    _type_title,
    _verification_cell,
)
from supernova_core.services.severity_rules import (
    SEVERITY_ORDER,
    effective_severity,
)
from supernova_core.utils.file_io import async_path_exists, async_read_file, async_write_file
from supernova_core.utils.paths import resolve_intermediate

logger = logging.getLogger(__name__)

# queue entry verification 字段值 → report_data evidence.verification 枚举
_VERIFICATION_MAP = {"static_analysis": "static", "dynamically_verified": "dynamic"}

# endpoints 串元素契约 "METHOD /path (role, auth)?"——role 已知集合外的单段
# 括号内容视为 auth（"GET /memos (trigger)" vs "POST /x (isLoggedIn)"）。
_ENDPOINT_RE = re.compile(
    r"^\s*(?:(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+)?([^\s(]+)\s*(?:\((.*?)\))?\s*$",
    re.IGNORECASE,
)
_KNOWN_ROLES = {"write", "trigger", "read", "update", "delete"}


def parse_endpoint_string(raw: str) -> EndpointEntry | None:
    """端点串 → EndpointEntry（确定性；解析不出 path 返回 None）。

    支持形态：``POST /memos (write, isLoggedIn)``、``GET /memos (trigger)``、
    ``POST /login``、``/allocations/:userId``（无 method）。
    """
    if not raw or not isinstance(raw, str):
        return None
    m = _ENDPOINT_RE.match(raw.strip())
    if not m:
        return None
    method, path, paren = m.group(1), m.group(2), m.group(3)
    if not path.startswith("/"):
        # 无方法前缀且不以 / 开头（如纯参数名）——不是端点
        if method is None:
            return None
    entry = EndpointEntry(
        method=method.upper() if method else None, path=path)
    if paren:
        parts = [p.strip() for p in paren.split(",") if p.strip()]
        for i, part in enumerate(parts):
            if part.lower() in _KNOWN_ROLES and entry.role is None:
                entry.role = part.lower()
            elif entry.auth is None:
                entry.auth = part
    return entry


def _backfill_deterministic_entries(vuln, entries: list[EndpointEntry]) -> None:
    """确定性路径数据补齐（spec 单源化 §5）：params ← affected_parameters
    （去重保序，卡级集合对串解析/单端兜底产出的每个 entry 共享——多接口卡
    无 per-endpoint 归属数据，不虚构归属）；行号链（sink/source/route）←
    affected_entries 首个非空值兜底。富化路径（report_endpoints）不进此函数。"""
    params: list[str] = []
    for p in (getattr(vuln, "affected_parameters", None) or []):
        p = str(p).strip()
        if p and p not in params:
            params.append(p)
    entries_meta = [e for e in (getattr(vuln, "affected_entries", None) or [])
                    if isinstance(e, dict)]

    def first_non_empty(key: str) -> str | None:
        for e in entries_meta:
            v = e.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
        return None

    sink_loc = first_non_empty("sink_location")
    src_loc = first_non_empty("source_location")
    route_at = first_non_empty("route_registered_at")
    for entry in entries:
        if params:
            entry.params = list(params)
        if sink_loc:
            entry.sink_location = sink_loc
        if src_loc:
            entry.source_location = src_loc
        if route_at:
            entry.route_registered_at = route_at


def _endpoint_entries(vuln) -> list[EndpointEntry]:
    """接口一体表（确定性派生）：report_endpoints（②富化写回）优先 →
    endpoints 串解析 → endpoint/path 单端兜底（后两者走 §5 回填）。"""
    structured = getattr(vuln, "report_endpoints", None)
    if structured:
        entries = []
        for item in structured:
            try:
                entries.append(EndpointEntry.model_validate(item))
            except Exception:  # noqa: BLE001 — 富化产物畸形逐条丢弃
                logger.warning("report_endpoints 畸形条目丢弃: %r", item)
        if entries:
            return entries
    entries: list[EndpointEntry] = []
    for raw in (getattr(vuln, "endpoints", None) or []):
        parsed = parse_endpoint_string(str(raw))
        if parsed is not None:
            entries.append(parsed)
    if not entries:
        # 兜底：endpoint（归一化串）或 path 提取
        fallback_src = getattr(vuln, "endpoint", None) or getattr(vuln, "path", None)
        if fallback_src:
            from supernova_core.code_index.gn_collapse import extract_endpoint
            extracted = extract_endpoint(fallback_src)
            if extracted:
                parsed = parse_endpoint_string(extracted)
                if parsed is not None:
                    entries = [parsed]
    if entries:
        _backfill_deterministic_entries(vuln, entries)
    return entries


def _poc_block(vuln) -> PocBlock | None:
    """POC：report_poc（poc-agent 写回）透传；畸形/缺失 → None（诚实缺失，
    spec 2026-08-27-poc-agent-direct-design——witness_payload 降级路径已退役）。"""
    structured = getattr(vuln, "report_poc", None)
    if isinstance(structured, dict):
        try:
            return PocBlock.model_validate(structured)
        except Exception:  # noqa: BLE001
            logger.warning("report_poc 畸形，POC 节缺省")
    return None


def _narrative(vuln, vuln_class: str | None = None) -> VulnNarrative | None:
    """Use the recorded security argument; notes are only a final fallback."""
    cause = vulnerability_cause(vuln, vuln_class)
    impact = getattr(vuln, "impact", None)
    remediation = getattr(vuln, "remediation", None)
    if cause or impact or remediation:
        return VulnNarrative(
            cause=cause, impact=impact, remediation=remediation)


def _problem_points(vuln, vuln_class: str) -> list[ProblemPoint]:
    """report_problem_points（富化写回）→ ProblemPoint 透传（不合成不推断）。

    宽松校验与 endpoint 写回同立场：非 dict / 缺 location 的畸形条目丢弃。
    auth/authz 卡不走 endpoint_enrichment（spec 单源化 §5）——写回空时确定性
    兜底：location ← findings_renderer 位置回退链（_card_loc/_card_sink，与
    md 卡问题点节同源），snippet ← queue code_snippet 透传，description 无。
    taint 卡不兜底（富化 agent 职责）。
    """
    points: list[ProblemPoint] = []
    for item in (getattr(vuln, "report_problem_points", None) or []):
        if not isinstance(item, dict):
            continue
        location = str(item.get("location") or "").strip()
        if not location:
            continue
        points.append(ProblemPoint(
            location=location,
            description=item.get("description"),
            snippet=item.get("snippet"),
        ))
    if points or vuln_class not in ("auth", "authz"):
        return points
    # auth/authz 确定性兜底：位置链复用 findings_renderer 私有 helper
    from supernova_core.services.findings_renderer import _card_loc, _card_sink
    _, sink_loc = _card_sink(vuln)
    loc = _card_loc(vuln, sink_loc)
    if not loc:
        return []
    snippet = getattr(vuln, "code_snippet", None)
    return [ProblemPoint(
        location=loc,
        snippet=snippet if isinstance(snippet, str) and snippet.strip() else None,
    )]


def _evidence(vuln) -> VulnEvidence:
    raw_verif = (getattr(vuln, "verification", None) or "").strip().lower()
    return VulnEvidence(
        verification=_VERIFICATION_MAP.get(raw_verif, "static"),
        verdict=getattr(vuln, "verdict", None),
        code_snippet=getattr(vuln, "code_snippet", None),
    )


# ---------------------------------------------------------------------------
# GN 卡 dataflow_steps 确定性派生（零成本兜底层，见模块 docstring）
# ---------------------------------------------------------------------------

_TAINT_DERIVE_CLASSES = ("injection", "xss", "ssrf")
# transformation 的净化提示前缀（chain_propagator 产，如 "sanitize_hint:swig
# (via consolidate) template engine autoescapes HTML..."）
_SANITIZE_HINT_PREFIX = "sanitize_hint:"
# SinkCallSite.id "{file}:{caller}:{callee}:{line}:{col}"（对齐 dataflow_view._parse_sink_id）
_SINK_ID_RE = re.compile(r"^(.*?):([^:]*):([^:]*):(\d+):\d+$")
# 2ND finding combined_sources 形如 "write:w.py:7 (users.bio) + read:r.js:3"
_WRITE_LOC_RE = re.compile(r"write:(\S+?):(\d+)")
_HOP_LABEL_MAX = 80


class _GnDeriveCtx:
    """parameter_graph + code_index 的派生索引（组装期读一次，全卡复用）。"""

    def __init__(self, pgraph: dict, code_index: dict):
        self.flows = {f["flow_id"]: f for f in pgraph.get("taint_flows") or []
                      if isinstance(f, dict) and f.get("flow_id")}
        self.source_points = [sp for sp in code_index.get("source_points") or []
                              if isinstance(sp, dict)]
        self.sinks = {s["id"]: s for s in code_index.get("sink_call_sites") or []
                      if isinstance(s, dict) and s.get("id")}


async def _load_derive_ctx(deliverables_path) -> _GnDeriveCtx | None:
    """parameter_graph 缺/坏 → None（确定性层失败档：诚实不派生）；code_index
    仅富化（source file:line / sink 标签），缺则退化不影响主链。"""
    pg_path = resolve_intermediate(deliverables_path, "parameter_graph.json")
    if pg_path is None or not await async_path_exists(pg_path):
        return None
    try:
        pgraph = json.loads(await async_read_file(pg_path))
    except (json.JSONDecodeError, OSError, ValueError) as exc:
        logger.warning("report_data: parameter_graph 不可读，跳过 GN 派生（%s）", exc)
        return None
    code_index: dict = {}
    ci_path = resolve_intermediate(deliverables_path, "code_index.json")
    if ci_path is not None and await async_path_exists(ci_path):
        try:
            loaded = json.loads(await async_read_file(ci_path))
            if isinstance(loaded, dict):
                code_index = loaded
        except (json.JSONDecodeError, OSError, ValueError):
            pass  # 富化产物坏 → 退化派生（source/sink 无 meta 加持）
    return _GnDeriveCtx(pgraph if isinstance(pgraph, dict) else {}, code_index)


def _dataflow_steps(vuln, vuln_class: str, ctx: _GnDeriveCtx | None) -> list[dict]:
    """queue dataflow_steps 优先（LLM 轨产 / GN 富化深链回填）；GN taint 卡
    空值时确定性派生；非 taint 类（auth/authz 无 flow 语义）不派生。"""
    steps = list(getattr(vuln, "dataflow_steps", None) or [])
    if steps or vuln_class not in _TAINT_DERIVE_CLASSES:
        return steps
    return _derive_gn_dataflow_steps(vuln, ctx)


def _derive_gn_dataflow_steps(vuln, ctx: _GnDeriveCtx | None) -> list[dict]:
    """GN 卡派生链：source → hops → sink。产不出 source→sink 两端 → []
    （诚实交还渲染层 evidence_chain 兜底，不产单点假链）。"""
    if ctx is None:
        return []
    if not (getattr(vuln, "source_track", None) == "gitnexus"
            or str(getattr(vuln, "ID", "")).startswith("2ND-GN-")):
        return []
    flow = ctx.flows.get(getattr(vuln, "flow_id", None) or "")
    source = _derive_source_step(vuln, flow, ctx)
    sink = _derive_sink_step(vuln, flow, ctx)
    if source is None or sink is None:
        return []
    steps = [source]
    for raw in (flow or {}).get("propagation_steps") or []:
        if not isinstance(raw, dict):
            continue
        hop = _derive_hop_step(raw)
        if hop is not None:
            steps.append(hop)
    steps.append(sink)
    _attach_sanitizer_protections(
        steps, getattr(vuln, "sanitizer_annotations", None) or [])
    return steps


def _attach_sanitizer_protections(steps: list[dict], annotations: list) -> None:
    """finding.sanitizer_annotations（CandidateChain 随卡落盘的净化标注）按
    code_location 的 file:line 匹配挂 step.protection（matched_text 优先，
    已有 protection 不覆写——sanitize_hint 提示优先）；匹配不到任何步的标注
    丢弃（兜底层不虚构挂点）。"""
    for ann in annotations:
        if not isinstance(ann, dict):
            continue
        name = ann.get("matched_text") or ann.get("rule_id")
        if not name:
            continue
        f_, l_ = _derive_parse_loc(ann.get("code_location"))
        if f_ is None:
            continue
        for st in steps:
            if (st.get("file") == f_ and st.get("line") == l_
                    and not st.get("protection")):
                st["protection"] = name
                break


def _derive_source_step(vuln, flow: dict | None, ctx: _GnDeriveCtx):
    """链首步：2ND=storage 写侧（combined_sources 的 write:file:line 并入
    label，对齐 dataflow_view 二阶枝口径）；1st=source_point 锚定 param；
    flow 缺=finding 自述（GN builder source 形如 "param (entry_id)"，剥括号尾巴）。"""
    if str(getattr(vuln, "ID", "")).startswith("2ND-GN-"):
        label = getattr(vuln, "source", None) or "stored data"
        m = _WRITE_LOC_RE.search(getattr(vuln, "combined_sources", None) or "")
        if m:
            wfile, wline = m.group(1), int(m.group(2))
            return {"label": f"{label} (write {wfile}:{wline})",
                    "file": wfile, "line": wline}
        return {"label": label}
    if flow:
        label = flow.get("source_param")
        if label:
            # 入口通道后缀（body/path/query）——对齐 affected_parameters
            # "email (body)" 惯例，让读者从数据流首步即知污点入口形态
            stype = flow.get("source_type")
            if stype:
                label = f"{label} ({stype})"
        else:
            label = (str(vuln.source).rsplit(" (", 1)[0].strip()
                     if getattr(vuln, "source", None) else None)
            if not label:
                return None
        sp = next((sp for sp in ctx.source_points
                   if sp.get("entry_point_id") == flow.get("entry_point_id")
                   and sp.get("param_name") == flow.get("source_param")), None)
        step = {"label": label}
        if sp is not None:
            if sp.get("file_path"):
                step["file"] = sp.get("file_path")
            if isinstance(sp.get("line"), int):
                step["line"] = sp.get("line")
        return step
    raw = getattr(vuln, "source", None) or getattr(vuln, "vulnerable_parameter", None)
    label = str(raw).rsplit(" (", 1)[0].strip() if raw else None
    return {"label": label} if label else None


def _derive_hop_step(raw: dict) -> dict | None:
    """传播步 → 中间节点：transformation 优先，其次 intermediate_vars 拼接
    （→ 连接、截长），两者皆无退 basename:line / to_func_id；再无素材 → None
    （纯透传步不虚构标签——但 code_location 仍在 file/line 保留）。

    transformation 带 ``sanitize_hint:`` 前缀（GN 净化提示——真实数据里非空
    transformation 主要是它）→ 剥前缀挂 step.protection（web 卡每步「防护」
    渲染位，LLM 轨 steps[].protection 同位），label 保留全文。"""
    file_, line = _derive_parse_loc(raw.get("code_location"))
    trans = raw.get("transformation")
    vars_ = [str(v) for v in (raw.get("intermediate_vars") or []) if str(v).strip()]
    label = (str(trans) if trans
             else (" → ".join(vars_) if vars_ else None))
    protection = None
    if trans and str(trans).startswith(_SANITIZE_HINT_PREFIX):
        protection = str(trans)[len(_SANITIZE_HINT_PREFIX):].strip() or None
    if label is None:
        base = (file_ or "").rsplit("/", 1)[-1]
        label = (f"{base}:{line}" if base and line is not None
                 else (base or raw.get("to_func_id") or None))
        if label is None:
            return None
    if len(label) > _HOP_LABEL_MAX:
        label = label[:_HOP_LABEL_MAX - 1] + "…"
    step = {"label": label}
    if file_:
        step["file"] = file_
    if line is not None:
        step["line"] = line
    if protection:
        step["protection"] = protection
    return step


def _derive_sink_step(vuln, flow: dict | None, ctx: _GnDeriveCtx):
    """链尾步：sink meta（receiver.callee 如 res.render）优先，缺则从
    SinkCallSite.id 解 callee，再退 finding.sink_function。"""
    sink_id = ((flow or {}).get("sink_call_site_id")
               or getattr(vuln, "sink_call", None) or "")
    meta = ctx.sinks.get(sink_id) if sink_id else None
    if meta is not None:
        callee = meta.get("callee_name")
        receiver = meta.get("callee_receiver")
        label = (f"{receiver}.{callee}" if receiver and callee
                 else (callee or sink_id))
        step = {"label": label}
        if meta.get("file_path"):
            step["file"] = meta.get("file_path")
        if isinstance(meta.get("line"), int):
            step["line"] = meta.get("line")
        return step
    if sink_id:
        f_, l_, callee = _derive_sink_parts(sink_id)
        step = {"label": callee or sink_id}
        if f_:
            step["file"] = f_
        if l_ is not None:
            step["line"] = l_
        return step
    fn = getattr(vuln, "sink_function", None)
    return {"label": fn} if fn else None


def _derive_parse_loc(s: object) -> tuple[str | None, int | None]:
    """"file:line" → (file, line)（自实现简化版，对齐 dataflow_view 惯例）。"""
    if not isinstance(s, str) or not s.strip():
        return (None, None)
    s = s.strip()
    file_part, _, line_part = s.rpartition(":")
    if file_part and line_part.isdigit():
        return (file_part, int(line_part))
    return (s, None)


def _derive_sink_parts(sink_id: str) -> tuple[str | None, int | None, str | None]:
    m = _SINK_ID_RE.match(sink_id or "")
    if m:
        return (m.group(1), int(m.group(4)), m.group(3))
    return (None, None, None)


def _report_vulnerability(vuln, vuln_class: str, raw_entry: dict,
                          derive_ctx: "_GnDeriveCtx | None" = None,
                          trigger_source: str | None = None) -> ReportVulnerability:
    auth = getattr(vuln, "authentication_required", None)
    if auth is not None:
        auth = str(auth)
    return ReportVulnerability(
        id=str(vuln.ID),
        type=vuln_class,
        vulnerability_type=getattr(vuln, "vulnerability_type", None),
        title=getattr(vuln, "title", None) or _type_title(vuln),
        severity=effective_severity(vuln),
        confidence=getattr(vuln, "confidence", None),
        cvss=getattr(vuln, "cvss", None),
        cwe_id=getattr(vuln, "cwe_id", None),
        owasp_category=getattr(vuln, "owasp_category", None),
        externally_exploitable=getattr(vuln, "externally_exploitable", None),
        authentication_required=auth,
        merge_source=getattr(vuln, "merge_source", None),
        merged_from=list(getattr(vuln, "merged_from", None) or []),
        trigger_source=trigger_source,
        narrative=_narrative(vuln, vuln_class),
        problem_points=_problem_points(vuln, vuln_class),
        endpoints=_endpoint_entries(vuln),
        affected_entries=list(getattr(vuln, "affected_entries", None) or []),
        dataflow_steps=_dataflow_steps(vuln, vuln_class, derive_ctx),
        poc=_poc_block(vuln),
        evidence=_evidence(vuln),
        raw=raw_entry,
    )


def _severity_range(severities: list[str]) -> str | None:
    if not severities:
        return None
    ranked = sorted(severities, key=lambda s: SEVERITY_ORDER.get(s, 0))
    return ranked[0] if ranked[0] == ranked[-1] else f"{ranked[0]}-{ranked[-1]}"


def _quick_reference_row(vuln) -> QuickReferenceRow:
    """速查表行（spec 单源化 §5）：单元格口径复用 report_assembler（同 md 表）。

    params 存全量原样（>3 截断是渲染层的事）；endpoints 串原样，空时
    report_endpoints（②富化写回，GN 轨卡的路由锚点主信号——不落数据流文本）
    → endpoint/path 兜底归一化（对齐 _endpoint_cell，但不落 '-' placeholder——
    行是数据不是展示，渲染层管空态）。
    """
    endpoints = [str(e).strip() for e in (getattr(vuln, "endpoints", None) or [])
                 if str(e).strip()]
    if not endpoints:
        endpoints = _report_endpoint_routes(vuln)
    if not endpoints:
        fallback = (getattr(vuln, "endpoint", None)
                    or getattr(vuln, "path", None))
        if fallback:
            from supernova_core.code_index.gn_collapse import extract_endpoint
            normalized = extract_endpoint(fallback) or str(fallback).strip()
            if normalized:
                endpoints = [normalized]
    params: list[str] = []
    for p in (getattr(vuln, "affected_parameters", None) or []):
        p = str(p).strip()
        if p and p not in params:
            params.append(p)
    if not params:
        params = _report_endpoint_params(vuln)
    title = getattr(vuln, "title", None) or _type_title(vuln)
    return QuickReferenceRow(
        id=str(vuln.ID),
        title=title,
        params=params,
        endpoints=endpoints,
        severity=_severity_cell(vuln),
        verification=_verification_cell(vuln),
        confidence=_confidence_cell(vuln),
    )


def _quick_reference(queues_by_class: dict[str, list]) -> list[QuickReferenceRow]:
    """速查表行集：类序对齐 CLASS_CONFIG + 类内 severity 降序（同档稳定保序），
    与 render_summary_table 行序完全一致。"""
    rows: list[QuickReferenceRow] = []
    ordered = [c for c in CLASS_CONFIG if c in queues_by_class]
    ordered += [c for c in queues_by_class if c not in CLASS_CONFIG]
    for vuln_class in ordered:
        ranked = sorted(
            queues_by_class[vuln_class],
            key=lambda v: -SEVERITY_ORDER.get(effective_severity(v), 0))
        rows.extend(_quick_reference_row(v) for v in ranked)
    return rows


def _key_findings(vulns: list[ReportVulnerability]) -> str | None:
    """类型汇总关键发现（spec 单源化 §5）：每类 top severity 卡（≤3 张）
    「ID 标题」串、「；」拼接——确定性产，摘要 agent 可覆写。"""
    ranked = sorted(
        vulns, key=lambda v: -SEVERITY_ORDER.get(v.severity or "", 0))
    items = []
    for v in ranked[:3]:
        title = v.title or _type_title(v)
        items.append(f"{v.id} {title}".strip())
    return "；".join(items) if items else None


def _build_stats(vulns_by_class: dict[str, list[ReportVulnerability]]) -> ReportStats:
    by_type: dict[str, TypeStats] = {}
    by_severity: dict[str, int] = {}
    for vuln_class, vulns in vulns_by_class.items():
        severities = [v.severity for v in vulns if v.severity]
        by_type[vuln_class] = TypeStats(
            count=len(vulns), severity_range=_severity_range(severities),
            key_findings=_key_findings(vulns))
        for sev in severities:
            by_severity[sev] = by_severity.get(sev, 0) + 1
    return ReportStats(by_type=by_type, by_severity=by_severity)


async def _read_attack_chains(deliverables_path) -> list[AttackChainEntry]:
    chains_path = resolve_intermediate(deliverables_path, "attack_chains.json")
    if chains_path is None or not await async_path_exists(chains_path):
        return []
    try:
        data = json.loads(await async_read_file(chains_path))
    except (json.JSONDecodeError, OSError, ValueError):
        return []
    entries = []
    for chain in (data.get("chains") or []):
        if not isinstance(chain, dict):
            continue
        entries.append(AttackChainEntry(
            id=str(chain.get("id", "")),
            steps=list(chain.get("steps") or []),
            narrative=chain.get("description"),
        ))
    return entries


async def _load_mr_summary(deliverables_path):
    """读 intermediate/mr/ 产物 → (summary | None, scope | None, scan_update | None)。

    非 MR 扫描（incremental_scope.json 不存在）→ (None, None, None) 零感知；
    scope 损坏同上（报告组装不因 MR 中间产物坏而失败）；diff_manifest 单独
    容错——缺失只丢 scan 元信息（base/head/diff_stat），摘要段照常。
    来源 B 的路由 join 直接读 code_index.json（MR join 只需 entry_points，
    不随 _load_derive_ctx 的 parameter_graph 前置条件走）。
    """
    from supernova_core.models.report_data import (
        IncrementalSummary, MrNewEntryPoint, MrRemovedProtection,
    )
    from supernova_core.mr_scan.incremental_scope import IncrementalScope

    mr_dir = deliverables_path / "intermediate" / "mr"
    scope_path = mr_dir / "incremental_scope.json"
    if not await async_path_exists(scope_path):
        return None, None, None
    try:
        scope = IncrementalScope.model_validate_json(
            await async_read_file(scope_path))
    except Exception as exc:  # noqa: BLE001 — scope 坏按非 MR 处理
        logger.warning("report_data: incremental_scope unreadable: %s", exc)
        return None, None, None

    manifest: dict = {}
    manifest_path = mr_dir / "diff_manifest.json"
    if await async_path_exists(manifest_path):
        try:
            loaded = json.loads(await async_read_file(manifest_path))
            if isinstance(loaded, dict):
                manifest = loaded
        except (json.JSONDecodeError, OSError, ValueError):
            pass

    # 来源 B join code_index.entry_points（路由明细；join miss 只留 func id）
    code_index: dict = {}
    ci_path = resolve_intermediate(deliverables_path, "code_index.json")
    if ci_path is not None and await async_path_exists(ci_path):
        try:
            loaded = json.loads(await async_read_file(ci_path))
            if isinstance(loaded, dict):
                code_index = loaded
        except (json.JSONDecodeError, OSError, ValueError):
            pass
    entry_map: dict[str, dict] = {}
    for ep in code_index.get("entry_points") or []:
        if isinstance(ep, dict) and ep.get("func_block_id"):
            entry_map[ep["func_block_id"]] = ep
    block_func: dict[str, str] = {}
    for b in code_index.get("blocks") or []:
        if isinstance(b, dict) and b.get("id"):
            block_func[b["id"]] = str(b.get("function_name") or "")

    new_entries = [
        MrNewEntryPoint(
            func_block_id=fid,
            function=block_func.get(fid),
            route=entry_map.get(fid, {}).get("route"),
            method=entry_map.get(fid, {}).get("http_method"),
            authentication=entry_map.get(fid, {}).get("authentication"),
        )
        for fid in scope.new_entry_point_ids
    ]
    removed = [
        MrRemovedProtection(
            file=rp.protection.file_path,
            line=rp.protection.base_line_no,
            kind=rp.protection.protection_kind,
            function=rp.protection.function_name,
            rationale=rp.protection.rationale or None,
            followed_by_chains=bool(rp.flow_ids),
        )
        for rp in scope.removed_protection_flows
    ]
    degraded = False
    rp_path = mr_dir / "removed_protections.json"
    if await async_path_exists(rp_path):
        try:
            degraded = bool(json.loads(
                await async_read_file(rp_path)).get("degraded"))
        except Exception:  # noqa: BLE001 — 降级标志缺失按 False
            pass
    summary = IncrementalSummary(
        degraded=degraded,
        new_entry_points=new_entries,
        removed_protections=removed,
        flow_counts={
            "new_code": len(scope.source_a_flow_ids),
            "new_entry": len(scope.source_b_flow_ids),
            "removed_protection": len(scope.source_c_flow_ids),
            "affected_flows": len(scope.verdict_flow_ids),
        },
    )
    scan_update = {
        "base_commit": manifest.get("base_commit"),
        "head_commit": manifest.get("head_commit"),
        "diff_stat": manifest.get("stats"),
    }
    return summary, scope, scan_update


async def build_report_data(
    deliverables_path, scan_meta: ScanMeta,
) -> ReportData:
    """读 SSOT queue 组装 ReportData（确定性；无 LLM）。"""
    from supernova_core.mr_scan.incremental_scope import trigger_source_of

    vulns_by_class: dict[str, list[ReportVulnerability]] = {}
    queue_vulns_by_class: dict[str, list] = {}
    derive_ctx = await _load_derive_ctx(deliverables_path)
    # MR 增量（spec 2026-09-03 §6）：增量摘要 + scope（trigger_source 反查用）
    mr_summary, mr_scope, mr_scan_update = await _load_mr_summary(
        deliverables_path)
    for vuln_class, cfg in CLASS_CONFIG.items():
        queue_path = resolve_intermediate(deliverables_path, cfg.queue_file)
        if queue_path is None or not await async_path_exists(queue_path):
            continue
        try:
            content = await async_read_file(queue_path)
            parsed = VulnerabilityQueue.parse_lenient(
                content, vuln_class=vuln_class)
        except Exception as exc:  # noqa: BLE001 — 缺一类不致命
            logger.warning("report_data: queue %s unreadable: %s",
                           cfg.queue_file, exc)
            continue
        report_vulns = []
        kept_vulns = []
        for vuln in parsed.queue.vulnerabilities:
            # 防线（spec 2026-08-27 §4）：verdict=not_vulnerable / safe 卡不进
            # 报告。主修复在 GN queue 写入侧分流（activity 层 split_dismissed；
            # authz GN judge/explore 走 _split_authz_safe 同款）；此处终末防线兜
            # 旧 session 产物 / schema 回归——非漏洞卡已留档
            # dismissed_findings.json，报告只承载漏洞与待复核（needs_review /
            # unadjudicated 保守保留：「没判成 ≠ 非漏洞」）。值域双态：
            # not_vulnerable（旧枚举）/ safe（chain_verdict 与 authz 判词现行契约）。
            if getattr(vuln, "verdict", None) in ("not_vulnerable", "safe"):
                logger.info(
                    "report_data: skip non-vulnerable card %s (%s, "
                    "dismissed archive has it)", vuln.ID, vuln_class)
                continue
            raw = vuln.model_dump(exclude_none=True)
            # trigger_source 只标 GN 轨可归因发现（both / gitnexus-only 且
            # flow_id 命中 scope 来源集，C > B > A 归并）；LLM-only 一律不标。
            _trigger = None
            if mr_scope is not None and getattr(vuln, "merge_source", None) in (
                    "both", "gitnexus-only"):
                _trigger = trigger_source_of(
                    getattr(vuln, "flow_id", None), mr_scope)
            report_vulns.append(
                _report_vulnerability(vuln, vuln_class, raw, derive_ctx,
                                      trigger_source=_trigger))
            kept_vulns.append(vuln)
        vulns_by_class[vuln_class] = report_vulns
        queue_vulns_by_class[vuln_class] = kept_vulns

    all_vulns = [v for vs in vulns_by_class.values() for v in vs]
    if mr_scan_update:
        scan_meta = scan_meta.model_copy(update=mr_scan_update)
    return ReportData(
        scan=scan_meta,
        stats=_build_stats(vulns_by_class),
        vulnerabilities=all_vulns,
        attack_chains=await _read_attack_chains(deliverables_path),
        quick_reference=_quick_reference(queue_vulns_by_class),
        incremental_summary=mr_summary,
    )


async def write_report_data(report_data: ReportData, path) -> None:
    """JSON 落盘（ensure_ascii=False，中文原样）。"""
    payload = json.dumps(
        report_data.model_dump(mode="json"), ensure_ascii=False, indent=2)
    await async_write_file(path, payload)
