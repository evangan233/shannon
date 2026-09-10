"""接口证据矩阵聚合器（spec 2026-09-10-api-evidence-matrix §4/§5/§6）。

纯确定性聚合：读现有白盒/黑盒产物，倒排为「接口 → 白盒证据 + 黑盒证据」
矩阵，落 deliverables/api_evidence_matrix.json。零 LLM 成本；对齐
dataflow_view.py 先例——同步纯函数、缺产物降级、不抛扫描级异常。

数据源（scan_dir 相对）：
- deliverables/whitebox/intermediate/entry_points.json      接口底册
- deliverables/whitebox/report_data.json                     finding SSOT（endpoints 富化后）
- deliverables/whitebox/intermediate/{vc}_safe_vectors.json  白盒安全结论
- deliverables/whitebox/intermediate/dismissed_findings.json 白盒驳回
- blackbox-runs/run-*/deliverables/blackbox/intermediate/{vc}_exploit_verdicts.json
                                                             黑盒验证证据（blackbox-runs/ 与
                                                             deliverables/ 平级，scan_dir 直下）
"""
from __future__ import annotations

import datetime as _dt
import json
import logging
import re
from pathlib import Path
from typing import Any

from supernova_core.utils.paths import resolve_intermediate

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1
EVIDENCE_MATRIX_FILENAME = "api_evidence_matrix.json"
VULN_CLASSES = ("injection", "xss", "ssrf", "authz", "auth")
LIVE_PROBE_MARKERS = ("黑盒实测", "probe-transcript", "实测")

_BRACE_RE = re.compile(r"\{([^}/]+)\}")
_ANGLE_RE = re.compile(r"<([^>/]+)>")
_STAR_RE = re.compile(r"\*([^/]+)")
# 注：`_` 显式紧跟 0-9（旧写法 `0-9:_\-` 中 `_` 实已存在，但紧邻 `:` 极易误读为缺失）
_METHOD_PATH_RE = re.compile(
    r"\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(/[A-Za-z0-9_:\-./{}<>]+)")
_BARE_PATH_RE = re.compile(r"(?<![\w/:])(/[A-Za-z0-9_\-./:{}<>]+)")


def normalize_route(route: str) -> str:
    route = str(route).split("?", 1)[0].strip()
    if not route.startswith("/"):
        route = "/" + route
    route = _BRACE_RE.sub(r":\1", route)
    route = _ANGLE_RE.sub(r":\1", route)
    route = _STAR_RE.sub(r":\1", route)
    if len(route) > 1:
        route = route.rstrip("/") or "/"
    return route


def route_shape(route: str) -> tuple[str, ...]:
    segs = normalize_route(route).split("/")[1:]
    return tuple(":" if s.startswith(":") else s for s in segs)


def _shape_key(route: str) -> str:
    return "/".join(route_shape(route))


def index_entries(entries: list[dict]) -> dict[tuple[str, str], list[dict]]:
    index: dict[tuple[str, str], list[dict]] = {}
    for e in entries:
        method = str(e.get("method") or "").upper()
        index.setdefault((method, _shape_key(e.get("path", ""))), []).append(e)
    return index


def match_entry(index: dict[tuple[str, str], list[dict]],
                method: str | None, route: str) -> dict | None:
    """唯一命中才返回（spec §5.3 歧义→None 不硬凑）。method=None 跨桶唯一才挂。"""
    shape = _shape_key(route)
    if method is not None:
        bucket = index.get((str(method).upper(), shape), [])
        return bucket[0] if len(bucket) == 1 else None
    hits = [e for (m, s), bucket in index.items() if s == shape for e in bucket]
    return hits[0] if len(hits) == 1 else None


def extract_endpoint_texts(text: str) -> list[tuple[str | None, str]]:
    """自由文本提 (METHOD, /path)；先带方法匹配，再裸路径（不重叠）。"""
    if not text:
        return []
    out: list[tuple[str | None, str]] = []
    consumed: list[tuple[int, int]] = []
    for m in _METHOD_PATH_RE.finditer(text):
        out.append((m.group(1), normalize_route(m.group(2))))
        consumed.append(m.span(2))
    for m in _BARE_PATH_RE.finditer(text):
        if any(s <= m.start() < e for s, e in consumed):
            continue
        out.append((None, normalize_route(m.group(1))))
    return out


def _load_json(path: Path | None) -> dict | None:
    if path is None or not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        logger.warning("api_evidence_matrix: %s 解析失败按缺失降级（%s）", path, exc)
        return None
    return data if isinstance(data, dict) else None


def _load_intermediate(wb_dir: Path, name: str) -> dict | None:
    return _load_json(resolve_intermediate(wb_dir, name))


def _live_probe(text: object) -> bool:
    s = str(text or "")
    return any(marker in s for marker in LIVE_PROBE_MARKERS)


def _endpoint_rows(vuln: dict) -> list[dict]:
    rows = vuln.get("endpoints")
    if not isinstance(rows, list):
        return []
    # 结构化 endpoints[]：dict 行直接用；字符串行（"POST /login (trigger)"）解析
    out = []
    for r in rows:
        if isinstance(r, dict) and r.get("path"):
            out.append({"method": r.get("method"), "path": str(r["path"]),
                        "role": r.get("role"), "params": r.get("params") or [],
                        "auth": r.get("auth"),
                        "source_location": r.get("source_location"),
                        "sink_location": r.get("sink_location")})
        elif isinstance(r, str):
            for method, path in extract_endpoint_texts(r):
                out.append({"method": method, "path": path, "role": None,
                            "params": [], "auth": None,
                            "source_location": None, "sink_location": None})
    return out


def _finding_view(vuln: dict) -> dict:
    raw = vuln.get("raw") if isinstance(vuln.get("raw"), dict) else {}

    def _pick(key, default=None):
        return vuln.get(key) if vuln.get(key) is not None else raw.get(key, default)

    return {
        "id": vuln.get("id"),
        "vuln_class": vuln.get("type"),
        "severity": vuln.get("severity"),
        "confidence": vuln.get("confidence"),
        "title": vuln.get("title"),
        "evidence_chain": _pick("evidence_chain") or _pick("source_detail"),
        "witness_payload": raw.get("witness_payload"),
        "verdict": raw.get("verdict"),
        "mismatch_reason": raw.get("mismatch_reason"),
        "params": _pick("affected_parameters") or [],
        "auth_required": _pick("authentication_required"),
    }


def _safe_view(vec: dict) -> dict:
    return {
        "subject": vec.get("subject") or vec.get("source"),
        "defense_mechanism": vec.get("defense_mechanism"),
        "location": vec.get("location"),
        "contains_live_probe": _live_probe(
            str(vec.get("subject", "")) + str(vec.get("defense_mechanism", ""))),
    }


def _dismissed_view(d: dict) -> dict:
    return {
        "ID": d.get("ID"), "vuln_class": d.get("vuln_class"),
        "title": d.get("title"), "dismiss_reason": d.get("dismiss_reason"),
        "dismissed_at_stage": d.get("dismissed_at_stage"),
    }


def _verdict_view(v: dict, run_id: str, vuln_class: str) -> dict:
    return {
        "vulnerability_id": v.get("vulnerability_id"),
        "vuln_class": vuln_class, "status": v.get("status"),
        "severity": v.get("severity"), "impact": v.get("impact"),
        "exploitation_steps": v.get("exploitation_steps") or [],
        "proof_of_impact": v.get("proof_of_impact"), "run_id": run_id,
    }


def build_api_evidence_matrix(scan_dir: Path) -> dict:
    """spec §4/§6：scan_dir 下聚合接口证据矩阵。产物缺失降级，不抛错。"""
    scan_dir = Path(scan_dir)
    deliverables = scan_dir / "deliverables"
    wb = deliverables / "whitebox"

    entry_payload = _load_intermediate(wb, "entry_points.json")
    report = _load_json(wb / "report_data.json")

    entries = []
    if entry_payload and isinstance(entry_payload.get("adjudicated_entry_points"), list):
        for ep in entry_payload["adjudicated_entry_points"]:
            if isinstance(ep, dict) and ep.get("route"):
                entries.append({
                    "method": str(ep.get("http_method") or "").upper(),
                    "path": normalize_route(str(ep["route"])),
                    "raw_route": ep.get("route"),
                    "func_block_id": ep.get("func_block_id"),
                    "entry_verdict": ep.get("verdict"),
                    "entry_evidence": ep.get("evidence"),
                    "whitebox": {"findings": [], "safe": [], "dismissed": []},
                    "blackbox": {"verdicts": [], "rejected": []},
                })
    index = index_entries(entries)

    unmatched_findings: list[dict] = []
    unmatched_safe: list[dict] = []
    unmatched_verdicts: list[dict] = []
    finding_to_entries: dict[str, list[dict]] = {}

    # ── 白盒 finding（report_data SSOT）→ 接口 ──
    if report and isinstance(report.get("vulnerabilities"), list):
        for vuln in report["vulnerabilities"]:
            if not isinstance(vuln, dict) or not vuln.get("id"):
                continue
            view = _finding_view(vuln)
            mounted = False
            for row in _endpoint_rows(vuln):
                hit = match_entry(index, row["method"], row["path"])
                if hit is None:
                    continue
                f = dict(view)
                f.update({k: row[k] for k in
                          ("params", "source_location", "sink_location")
                          if row.get(k)})
                f["auth_required"] = f.get("auth_required") or row.get("auth")
                f["role"] = row.get("role")
                hit["whitebox"]["findings"].append(f)
                finding_to_entries.setdefault(vuln["id"], []).append(hit)
                mounted = True
            if not mounted:
                unmatched_findings.append({
                    "id": vuln.get("id"), "vuln_class": vuln.get("type"),
                    "title": vuln.get("title"),
                    "reason": "ambiguous-or-no-endpoint-match",
                })

    # ── 白盒安全结论 / 驳回（自由文本）──
    for vc in VULN_CLASSES:
        sv = _load_intermediate(wb, f"{vc}_safe_vectors.json")
        for vec in (sv or {}).get("vectors") or []:
            if not isinstance(vec, dict):
                continue
            texts = extract_endpoint_texts(str(vec.get("subject", "")))
            hit = None
            for method, path in texts:
                hit = match_entry(index, method, path)
                if hit is not None:
                    break
            if hit is not None:
                hit["whitebox"]["safe"].append(_safe_view(vec))
            else:
                unmatched_safe.append({"kind": "safe", "vuln_class": vc,
                                       **_safe_view(vec)})

    dismissed = _load_intermediate(wb, "dismissed_findings.json")
    for d in (dismissed or {}).get("dismissed") or []:
        if not isinstance(d, dict):
            continue
        texts = extract_endpoint_texts(str(d.get("title", "")))
        hit = None
        for method, path in texts:
            hit = match_entry(index, method, path)
            if hit is not None:
                break
        if hit is not None:
            hit["whitebox"]["dismissed"].append(_dismissed_view(d))
        else:
            unmatched_safe.append({"kind": "dismissed",
                                   **_dismissed_view(d)})

    # ── 黑盒 verdicts → 白盒 finding → 接口 ──
    # 真实布局：blackbox-runs/ 与 deliverables/ 平级（utils/paths.blackbox_runs_dir），
    # 故 glob 从 scan_dir 起——deliverables/ 前缀永远 glob 不中（fix round 2）。
    blackbox_run_ids: set[str] = set()
    for verdicts_path in sorted(
            scan_dir.glob("blackbox-runs/run-*/deliverables/blackbox/"
                          "intermediate/*_exploit_verdicts.json")):
        run_id = verdicts_path.parts[-5]  # run-N
        blackbox_run_ids.add(run_id)   # sources.blackbox_runs 按 run 去重计数
        payload = _load_json(verdicts_path) or {}
        vc = str(payload.get("vuln_class") or
                 verdicts_path.name.split("_", 1)[0])
        for v in payload.get("verdicts") or []:
            if not isinstance(v, dict):
                continue
            mounted = False
            for hit in finding_to_entries.get(v.get("vulnerability_id"), []):
                hit["blackbox"]["verdicts"].append(_verdict_view(v, run_id, vc))
                mounted = True
            if not mounted:
                # finding 缺失/未挂：从 verdict 自身文本提接口再试（spec §5.5）
                for method, path in extract_endpoint_texts(
                        str(v.get("impact", "")) + " " +
                        " ".join(str(s) for s in v.get("exploitation_steps") or [])):
                    hit = match_entry(index, method, path)
                    if hit is not None:
                        hit["blackbox"]["verdicts"].append(
                            _verdict_view(v, run_id, vc))
                        mounted = True
                        break
            if not mounted:
                unmatched_verdicts.append({
                    "vulnerability_id": v.get("vulnerability_id"),
                    "status": v.get("status"), "run_id": run_id,
                    "reason": "finding-or-endpoint-not-matched"})
        for r in payload.get("rejected") or []:
            if not isinstance(r, dict):
                continue
            anchored = False
            for hit in finding_to_entries.get(r.get("vulnerability_id"), []):
                hit["blackbox"]["rejected"].append(r)
                anchored = True
            if not anchored:
                # 无 finding 锚的 rejected 不静默丢弃 → unmatched 可见
                unmatched_verdicts.append({
                    "kind": "rejected",
                    "vulnerability_id": r.get("vulnerability_id"),
                    "vuln_class": vc,
                    "status": r.get("status"),
                    "run_id": run_id,
                    "reason": "finding-or-endpoint-not-matched"})

    # ── coverage（spec §4：clean = 白盒/黑盒证据均未命中——黑盒-only 不得标 clean）──
    for e in entries:
        wb_ = e["whitebox"]
        bb_ = e["blackbox"]
        if wb_["findings"] or bb_["verdicts"] or bb_["rejected"]:
            e["coverage"] = "findings"
        elif wb_["safe"] or wb_["dismissed"]:
            e["coverage"] = "defended"
        else:
            e["coverage"] = "clean"

    matrix: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "scan_id": scan_dir.name,
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "sources": {
            "entry_points": entry_payload is not None,
            "report_data": report is not None,
            "blackbox_runs": len(blackbox_run_ids),
        },
        "endpoints": entries,
        "unmatched": {
            "findings": unmatched_findings,
            "safe_dismissed": unmatched_safe,
            "verdicts": unmatched_verdicts,
        },
    }
    if entry_payload is None:
        matrix["note"] = ("entry_points.json 缺失或解析失败（纯黑盒扫描或旧版扫描），"
                          "接口底册为空，证据无处挂载。")
    return matrix
