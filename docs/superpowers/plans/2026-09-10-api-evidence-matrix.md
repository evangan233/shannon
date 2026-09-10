# 接口证据页（api evidence matrix）Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 扫描完成后以 WEB 接口为维度落一份证据矩阵产物（白盒分析证据 / 黑盒验证证据两栏独立），web 独立「证据」tab 渲染，旧扫描 lazy 回填。

**Architecture:** 纯确定性聚合器（core `api_evidence_matrix.py`，对齐 `dataflow_view.py` 先例：同步纯函数读 intermediate 产物、缺产物降级不抛错）→ 产物落 `deliverables/api_evidence_matrix.json`（deliverables 根，跨 track）。whitebox workflow report 段后独立 non-fatal activity 落盘；web API 直读、产物缺失/陈旧时 lazy 重建（纯 JSON 处理，不起 agent）。前端对齐 `DataFlowTab` 先例（SWR + 独立路由 tab）。

**Tech Stack:** Python（supernova_core / supernova_whitebox temporal activity / FastAPI）、React + TypeScript + SWR + react-i18n、pytest / vitest + @testing-library/react。

**Spec:** `docs/superpowers/specs/2026-09-10-api-evidence-matrix-design.md`（§5 匹配规则、§4 schema、§7 lazy 语义为本计划的契约）。

## Global Constraints

- 纯确定性聚合，**零新增 LLM 成本**；聚合器任何异常不得阻塞扫描（non-fatal）。
- **web 进程零 agent 执行点**（CLAUDE.md §2）：web 侧只 import `supernova_core.services.api_evidence_matrix`（纯 JSON 处理），不得 import `PromptManager` / `supernova_core.agents.runner`。
- 匹配保守：歧义进 `unmatched`，**不硬凑**（spec §5）。
- 前端提交前本地 `npx tsc -b` 必须过（vitest 不查类型，docker build 才爆——memory `frontend-tsc-build-gates`）。
- 测试只跑改动相关文件（CLAUDE.md §3：全套 pytest 有预存挂起）。
- i18n 键 camelCase 进 `src/locales/zh.json` / `en.json` 的 `workspaceDetail` 段（kebab→camel 陷阱——memory `web-theme-system-architecture`）。
- 提交信息中文、对齐仓库现有风格（`feat(core): …` / `feat(web): …`）。

---

### Task 1: core 聚合器——path 归一化 + 形状匹配器

**Files:**
- Create: `packages/core/src/supernova_core/services/api_evidence_matrix.py`
- Test: `packages/core/tests/services/test_api_evidence_matrix.py`

**Interfaces:**
- Consumes: 无（纯函数，无 IO）。
- Produces（Task 2/4 依赖，签名精确到行为）:
  - `normalize_route(route: str) -> str`——剥 query、`{p}`/`<p>`/`*p` → `:p`、尾 `/` 归一（根保持 `/`）、补前导 `/`。
  - `route_shape(route: str) -> tuple[str, ...]`——逐段：参数段归一为 `"":"`、静态段原样；`/allocations/:userId` → `("allocations", ":")`。
  - `index_entries(entries: list[dict]) -> dict[tuple[str, str], list[dict]]`——键 `(METHOD, "/".join(shape))`，值为底册 entry 列表（entry 需含 `method`/`path`/`raw_route` 键，由 Task 2 构造）。
  - `match_entry(index, method: str | None, route: str) -> dict | None`——method+shape 查桶；`method=None` 时在所有 method 桶中按 shape 查，**仅全桶合计唯一命中才返回**；0 或 >1 命中返回 None。
  - `extract_endpoint_texts(text: str) -> list[tuple[str | None, str]]`——从自由文本提 `(METHOD, /path)` 对，方法缺失为 None。

- [ ] **Step 1: Write the failing test**

```python
"""api_evidence_matrix 聚合器单测（spec 2026-09-10 §5 匹配规则）。

Task 1 覆盖纯函数：normalize_route / route_shape / index_entries /
match_entry / extract_endpoint_texts。
"""
from supernova_core.services.api_evidence_matrix import (
    extract_endpoint_texts,
    index_entries,
    match_entry,
    normalize_route,
    route_shape,
)


class TestNormalizeRoute:
    def test_strips_query_and_keeps_param_colon(self):
        assert normalize_route("/allocations/:userId?x=1") == "/allocations/:userId"

    def test_brace_angle_star_params_to_colon(self):
        assert normalize_route("/users/{id}") == "/users/:id"
        assert normalize_route("/users/<id>") == "/users/:id"
        assert normalize_route("/files/*rest") == "/files/:rest"

    def test_trailing_slash_normalized_root_kept(self):
        assert normalize_route("/profile/") == "/profile"
        assert normalize_route("/") == "/"

    def test_leading_slash_added(self):
        assert normalize_route("profile") == "/profile"


class TestRouteShape:
    def test_param_name_agnostic(self):
        assert route_shape("/allocations/:userId") == route_shape("/allocations/:id")
        assert route_shape("/allocations/:userId") == ("allocations", ":")

    def test_static_segments_kept_verbatim(self):
        assert route_shape("/api/v2/items") == ("api", "v2", "items")


class _Entry(dict):
    """测试用底册 entry（index_entries 的输入形态，Task 2 同款）。"""


def _idx(*pairs):
    return index_entries([
        _Entry(method=m, path=normalize_route(p), raw_route=p) for m, p in pairs
    ])


class TestMatchEntry:
    def test_unique_hit_with_method(self):
        idx = _idx(("GET", "/allocations/:userId"), ("POST", "/allocations/:userId"))
        hit = match_entry(idx, "GET", "/allocations/:id")  # 参数名无关
        assert hit is not None and hit["raw_route"] == "/allocations/:userId"

    def test_no_method_unique_across_buckets(self):
        idx = _idx(("GET", "/profile"), ("POST", "/login"))
        hit = match_entry(idx, None, "/profile")
        assert hit is not None and hit["method"] == "GET"

    def test_no_method_ambiguous_returns_none(self):
        idx = _idx(("GET", "/data"), ("POST", "/data"))
        assert match_entry(idx, None, "/data") is None

    def test_shape_collision_two_static_same_route_returns_none(self):
        # 同 method 同 shape 两条底册行（重复注册）→ 歧义不硬凑
        idx = index_entries([
            _Entry(method="GET", path="/d", raw_route="/d"),
            _Entry(method="GET", path="/d", raw_route="/d2"),
        ])
        assert match_entry(idx, "GET", "/d") is None

    def test_miss_returns_none(self):
        idx = _idx(("GET", "/profile"))
        assert match_entry(idx, "POST", "/profile") is None
        assert match_entry(idx, "GET", "/nope") is None


class TestExtractEndpointTexts:
    def test_method_and_path(self):
        assert extract_endpoint_texts("GET /profile（本人 PII 读取）") == [("GET", "/profile")]

    def test_bare_path_no_method(self):
        assert extract_endpoint_texts("问题位于 /dashboard 页面") == [(None, "/dashboard")]

    def test_param_path_kept_whole(self):
        assert extract_endpoint_texts("POST /allocations/:userId 提交") == [("POST", "/allocations/:userId")]

    def test_no_path_returns_empty(self):
        assert extract_endpoint_texts("查询构造精确匹配") == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /root/ft-codescan/packages/core && python -m pytest tests/services/test_api_evidence_matrix.py -v`
Expected: FAIL（`ModuleNotFoundError: supernova_core.services.api_evidence_matrix`）

- [ ] **Step 3: Write minimal implementation**

`packages/core/src/supernova_core/services/api_evidence_matrix.py` 起步（模块 docstring 写明 spec 引用）：

```python
"""接口证据矩阵聚合器（spec 2026-09-10-api-evidence-matrix §4/§5/§6）。

纯确定性聚合：读现有白盒/黑盒产物，倒排为「接口 → 白盒证据 + 黑盒证据」
矩阵，落 deliverables/api_evidence_matrix.json。零 LLM 成本；对齐
dataflow_view.py 先例——同步纯函数、缺产物降级、不抛扫描级异常。

数据源（scan_dir 相对）：
- deliverables/whitebox/intermediate/entry_points.json      接口底册
- deliverables/whitebox/report_data.json                     finding SSOT（endpoints 富化后）
- deliverables/whitebox/intermediate/{vc}_safe_vectors.json  白盒安全结论
- deliverables/whitebox/intermediate/dismissed_findings.json 白盒驳回
- deliverables/blackbox-runs/run-*/deliverables/blackbox/intermediate/{vc}_exploit_verdicts.json
                                                             黑盒验证证据
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
VULN_CLASSES = ("injection", "xss", "ssrf", "authz", "auth")
LIVE_PROBE_MARKERS = ("黑盒实测", "probe-transcript", "实测")

_BRACE_RE = re.compile(r"\{([^}/]+)\}")
_ANGLE_RE = re.compile(r"<([^>/]+)>")
_STAR_RE = re.compile(r"\*([^/]+)")
_METHOD_PATH_RE = re.compile(
    r"\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(/[A-Za-z0-9:_\-./{}<>]+)")
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /root/ft-codescan/packages/core && python -m pytest tests/services/test_api_evidence_matrix.py -v`
Expected: PASS（全部）

- [ ] **Step 5: Commit**

```bash
cd /root/ft-codescan && git add packages/core/src/supernova_core/services/api_evidence_matrix.py packages/core/tests/services/test_api_evidence_matrix.py
git commit -m "feat(core): api_evidence_matrix 聚合器起步——path 归一化/形状匹配/自由文本接口提取（参数名无关+歧义不硬凑）"
```

---

### Task 2: core 聚合器——build_api_evidence_matrix 主流程

**Files:**
- Modify: `packages/core/src/supernova_core/services/api_evidence_matrix.py`（追加主流程）
- Test: `packages/core/tests/services/test_api_evidence_matrix.py`（追加 fixture 树测试）

**Interfaces:**
- Consumes: Task 1 的 `normalize_route / index_entries / match_entry / extract_endpoint_texts`；`supernova_core.utils.paths.resolve_intermediate`（`resolve_intermediate(track_dir, filename) -> Path | None`，intermediate/ 优先、桶平铺 fallback）。
- Produces:
  - `build_api_evidence_matrix(scan_dir: Path) -> dict`——产物缺失不抛错；返回 spec §4 schema dict（`schema_version/scan_id/generated_at/sources/endpoints[]/unmatched/note?`）。Task 3 activity 与 Task 4 web API 都调它。
  - `EVIDENCE_MATRIX_FILENAME = "api_evidence_matrix.json"`（Task 4 import 复用，避免魔法字符串）。

- [ ] **Step 1: Write the failing test**

追加到 `test_api_evidence_matrix.py`（新 section，含 fixture 产物树 builder）：

```python
# ---------------------------------------------------------------------------
# Task 2: build_api_evidence_matrix 主流程（fixture 产物树）
# ---------------------------------------------------------------------------
import json
from pathlib import Path

from supernova_core.services.api_evidence_matrix import build_api_evidence_matrix


def _wb_scan(tmp_path: Path) -> Path:
    """最小白盒 scan 目录树：deliverables/whitebox/{intermediate,report_data.json}。"""
    scan = tmp_path / "NodeGoat-X"
    wb = scan / "deliverables" / "whitebox"
    (wb / "intermediate").mkdir(parents=True)
    (wb / "report_data.json").write_text(json.dumps({
        "schema_version": 1,
        "vulnerabilities": [],
    }))
    return scan


def _write_entry_points(scan: Path, rows):
    wb = scan / "deliverables" / "whitebox"
    (wb / "intermediate" / "entry_points.json").write_text(json.dumps({
        "repository": "/r", "language": "js",
        "adjudicated_entry_points": rows,
    }))


def _write_report_data(scan: Path, vulns):
    wb = scan / "deliverables" / "whitebox"
    (wb / "report_data.json").write_text(json.dumps({
        "schema_version": 1, "vulnerabilities": vulns,
    }))


def _ep(method, route, block="f:1"):
    return {"func_block_id": block, "verdict": "confirmed",
            "entry_type": "http_route", "route": route,
            "http_method": method, "evidence": f"Express route: {method} {route}",
            "source": "code_index"}


def _vuln(vid, vtype, endpoints, raw=None, severity="high"):
    return {"id": vid, "type": vtype, "vulnerability_type": "Reflected",
            "title": f"{vid} title", "severity": severity,
            "confidence": "high", "endpoints": endpoints, "raw": raw or {}}


def _find_matrix(matrix, method, path):
    for e in matrix["endpoints"]:
        if e["method"] == method and e["path"] == normalize_route(path):
            return e
    return None


class TestBuildMatrix:
    def test_structured_hit_with_blackbox_verdict(self, tmp_path):
        scan = _wb_scan(tmp_path)
        _write_entry_points(scan, [_ep("GET", "/allocations/:userId")])
        _write_report_data(scan, [
            _vuln("INJ-VULN-01", "injection",
                  [{"method": "GET", "path": "/allocations/:id", "role": "trigger",
                    "auth": "isLoggedIn", "params": ["userId (path)"],
                    "source_location": "a.js:21", "sink_location": "dao.js:78"}],
                  raw={"witness_payload": "1'; while(true){}; //"}),
        ])
        # 黑盒 verdict：vulnerability_id 锚白盒 finding → 同接口
        bb = scan / "deliverables" / "blackbox-runs" / "run-1" / \
            "deliverables" / "blackbox" / "intermediate"
        bb.mkdir(parents=True)
        (bb / "injection_exploit_verdicts.json").write_text(json.dumps({
            "vuln_class": "injection", "accepted_ids": ["INJ-VULN-01"],
            "verdicts": [{"vulnerability_id": "INJ-VULN-01", "status": "exploited",
                          "severity": "critical", "impact": "RCE",
                          "exploitation_steps": ["send payload"],
                          "proof_of_impact": "uid=1000"}],
            "rejected": [],
        }))
        m = build_api_evidence_matrix(scan)
        row = _find_matrix(m, "GET", "/allocations/:userId")
        assert row is not None
        assert row["coverage"] == "findings"
        assert row["whitebox"]["findings"][0]["id"] == "INJ-VULN-01"
        assert row["whitebox"]["findings"][0]["witness_payload"] == "1'; while(true){}; //"
        assert row["blackbox"]["verdicts"][0]["status"] == "exploited"
        assert row["blackbox"]["verdicts"][0]["run_id"] == "run-1"
        assert m["sources"]["blackbox_runs"] == 1
        assert not m["unmatched"]["findings"]

    def test_safe_vector_free_text_mounts_and_coverage_defended(self, tmp_path):
        scan = _wb_scan(tmp_path)
        _write_entry_points(scan, [_ep("GET", "/profile"), _ep("POST", "/login")])
        _write_report_data(scan, [])  # 无 finding
        wb = scan / "deliverables" / "whitebox" / "intermediate"
        (wb / "authz_safe_vectors.json").write_text(json.dumps({
            "vectors": [{"subject": "GET /profile（本人 PII 读取的身份绑定）",
                         "defense_mechanism": "userId 仅从 session 解构",
                         "location": "profile.js:14"}],
        }))
        (wb / "dismissed_findings.json").write_text(json.dumps({
            "dismissed": [{"ID": "AUTH-LLM-SAFE-01", "source_track": "llm",
                          "vuln_class": "auth", "title": "无接口描述的驳回",
                          "dismiss_reason": "等值查询", "evidence": None,
                          "confidence": None, "source": None, "sink_call": None,
                          "dismissed_at_stage": "llm-exploration"}],
        }))
        m = build_api_evidence_matrix(scan)
        prof = _find_matrix(m, "GET", "/profile")
        login = _find_matrix(m, "POST", "/login")
        assert prof["coverage"] == "defended"
        assert prof["whitebox"]["safe"][0]["location"] == "profile.js:14"
        assert prof["whitebox"]["safe"][0]["contains_live_probe"] is False
        assert login["coverage"] == "clean"          # 底册在、无证据命中
        # 提不出接口的 dismissed → unmatched.safe_dismissed（不丢）
        assert m["unmatched"]["safe_dismissed"][0]["kind"] == "dismissed"

    def test_ambiguous_endpoint_goes_unmatched(self, tmp_path):
        scan = _wb_scan(tmp_path)
        # 同 method 同 shape 两条底册行 → finding 归属歧义
        _write_entry_points(scan, [_ep("GET", "/data"), _ep("GET", "/data2", block="f:2")])
        _write_report_data(scan, [
            _vuln("X-1", "xss", [{"method": "GET", "path": "/data"}]),
        ])
        m = build_api_evidence_matrix(scan)
        assert not [e for e in m["endpoints"] if e["whitebox"]["findings"]]
        assert m["unmatched"]["findings"][0]["id"] == "X-1"
        assert "ambiguous" in m["unmatched"]["findings"][0]["reason"]

    def test_live_probe_marker(self, tmp_path):
        scan = _wb_scan(tmp_path)
        _write_entry_points(scan, [_ep("GET", "/dashboard")])
        _write_report_data(scan, [])
        wb = scan / "deliverables" / "whitebox" / "intermediate"
        (wb / "auth_safe_vectors.json").write_text(json.dumps({
            "vectors": [{"subject": "GET /dashboard 黑盒实测被拒",
                         "defense_mechanism": "302 -> /login", "location": "s.js:36"}],
        }))
        m = build_api_evidence_matrix(scan)
        assert _find_matrix(m, "GET", "/dashboard")["whitebox"]["safe"][0][
            "contains_live_probe"] is True

    def test_missing_everything_returns_empty_matrix_not_raise(self, tmp_path):
        scan = tmp_path / "pure-blackbox-scan"
        (scan / "deliverables" / "blackbox").mkdir(parents=True)
        m = build_api_evidence_matrix(scan)
        assert m["schema_version"] == 1
        assert m["endpoints"] == []
        assert m["sources"]["entry_points"] is False
        assert "note" in m
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /root/ft-codescan/packages/core && python -m pytest tests/services/test_api_evidence_matrix.py -v -k BuildMatrix`
Expected: FAIL（`ImportError: build_api_evidence_matrix`）

- [ ] **Step 3: Write minimal implementation**

追加到 `api_evidence_matrix.py`：

```python
import datetime as _dt
import json
import logging

from supernova_core.utils.paths import resolve_intermediate

logger = logging.getLogger(__name__)

EVIDENCE_MATRIX_FILENAME = "api_evidence_matrix.json"


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
                          ("params", "auth_required", "source_location",
                           "sink_location") if row.get(k)})
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
    blackbox_runs = 0
    for verdicts_path in sorted(
            deliverables.glob("blackbox-runs/run-*/deliverables/blackbox/"
                              "intermediate/*_exploit_verdicts.json")):
        blackbox_runs += 1
        run_id = verdicts_path.parts[-5]  # run-N
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
            for hit in finding_to_entries.get(r.get("vulnerability_id"), []):
                hit["blackbox"]["rejected"].append(r)

    # ── coverage ──
    for e in entries:
        wb_ = e["whitebox"]
        if wb_["findings"]:
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
            "blackbox_runs": blackbox_runs,
        },
        "endpoints": entries,
        "unmatched": {
            "findings": unmatched_findings,
            "safe_dismissed": unmatched_safe,
            "verdicts": unmatched_verdicts,
        },
    }
    if entry_payload is None:
        matrix["note"] = ("entry_points.json 缺失（纯黑盒扫描或旧版扫描），"
                          "接口底册为空，证据无处挂载。")
    return matrix
```

**实现注意（易错点）：**
- `_endpoint_rows` 里字符串行 `"POST /login (trigger)"` 用 `extract_endpoint_texts` 解析——`quick_reference` 式 endpoints 串的兜底（report_data_builder §「endpoints 串元素契约」）。
- 测试 `test_ambiguous_endpoint_goes_unmatched` 里 `match_entry` 对同 method 同 shape 两行返回 None——与 Task 1 语义一致。
- `run_id` 用 `verdicts_path.parts[-5]` 提取：路径 `…/blackbox-runs/run-1/deliverables/blackbox/intermediate/x.json` 的倒数第 5 段是 `run-1`。若测试失败先打印 parts 核对。

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /root/ft-codescan/packages/core && python -m pytest tests/services/test_api_evidence_matrix.py -v`
Expected: PASS（Task 1 + Task 2 全部）

- [ ] **Step 5: Commit**

```bash
cd /root/ft-codescan && git add packages/core/src/supernova_core/services/api_evidence_matrix.py packages/core/tests/services/test_api_evidence_matrix.py
git commit -m "feat(core): build_api_evidence_matrix 主流程——白盒/黑盒两栏挂载+coverage 三档+unmatched 兜底，产物缺失降级不抛错"
```

---

### Task 3: whitebox 管线挂载（activity + workflow + worker 注册）

**Files:**
- Modify: `packages/whitebox/src/supernova_whitebox/pipeline/activities.py`（`run_assemble_dataflow_view` 之后追加 activity）
- Modify: `packages/whitebox/src/supernova_whitebox/pipeline/workflows.py`（`run_report_polish` except 块之后追加调度）
- Modify: `packages/whitebox/src/supernova_whitebox/worker.py`（activities 列表注册）
- Test: `packages/whitebox/tests/pipeline/test_assemble_api_evidence_activity.py`

**Interfaces:**
- Consumes: Task 2 的 `build_api_evidence_matrix(scan_dir: Path) -> dict`；本文件 `activities.py` 已有 `_get_paths(input) -> (repo, deliverables_whitebox, workspaces)`、`atomic_write_json`（`supernova_core.utils.atomic_write`）。
- Produces: activity `run_assemble_api_evidence(input: ActivityInput) -> dict`，返回 `{"status": "ok", "endpoints": N}` 或 `{"status": "skipped", "reason": str}`；产物落 `deliverables 根/api_evidence_matrix.json`（= `deliverables_whitebox.parent / EVIDENCE_MATRIX_FILENAME`）。

- [ ] **Step 1: Write the failing test**

`packages/whitebox/tests/pipeline/test_assemble_api_evidence_activity.py`（打桩模式对齐 `test_assemble_dataflow_view_activity.py`）：

```python
"""api_evidence_matrix 组装活动——non-fatal，成功落 deliverables 根产物。

打桩方式对齐 test_assemble_dataflow_view_activity：patch build 函数 +
patch activities._get_paths（返回 (repo, wb_deliverables, workspaces)，
wb_deliverables = scan_dir/deliverables/whitebox）。asyncio_mode=auto 直接 await。
"""
import json
from pathlib import Path
from unittest.mock import patch

import pytest


@pytest.fixture
def wb_deliverables(tmp_path: Path) -> Path:
    """scan 树：tmp/deliverables/whitebox（_get_paths 返回的已是白盒桶）。"""
    wb = tmp_path / "deliverables" / "whitebox"
    wb.mkdir(parents=True)
    return wb


async def test_activity_writes_matrix_at_deliverables_root(wb_deliverables: Path):
    from supernova_whitebox.pipeline import activities

    matrix = {"schema_version": 1, "scan_id": "NodeGoat-X",
              "endpoints": [{"method": "GET", "path": "/p"}]}
    with patch("supernova_core.services.api_evidence_matrix"
               ".build_api_evidence_matrix", return_value=matrix) as build:
        with patch.object(activities, "_get_paths",
                          return_value=(Path("/r"), wb_deliverables, Path("/w"))):
            result = await activities.run_assemble_api_evidence(input=object())
    assert result == {"status": "ok", "endpoints": 1}
    # scan_dir = wb_deliverables.parent.parent；build 收到 scan_dir
    assert build.call_args[0][0] == wb_deliverables.parent.parent
    out = wb_deliverables.parent / "api_evidence_matrix.json"
    assert json.loads(out.read_text(encoding="utf-8")) == matrix


async def test_activity_non_fatal_on_exception(wb_deliverables: Path):
    """组装器抛 → warning + skipped 返回值，不抛 ApplicationFailure。"""
    from supernova_whitebox.pipeline import activities

    with patch("supernova_core.services.api_evidence_matrix"
               ".build_api_evidence_matrix", side_effect=RuntimeError("boom")):
        with patch.object(activities, "_get_paths",
                          return_value=(Path("/r"), wb_deliverables, Path("/w"))):
            result = await activities.run_assemble_api_evidence(input=object())
    assert result["status"] == "skipped"
    assert not (wb_deliverables.parent / "api_evidence_matrix.json").exists()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /root/ft-codescan/packages/whitebox && python -m pytest tests/pipeline/test_assemble_api_evidence_activity.py -v`
Expected: FAIL（`AttributeError: run_assemble_api_evidence`）

- [ ] **Step 3: Write minimal implementation**

`activities.py`：在 `run_assemble_dataflow_view` 函数之后追加：

```python
@activity.defn
async def run_assemble_api_evidence(input: ActivityInput) -> dict:
    """接口证据矩阵组装（spec 2026-09-10 §6；non-fatal 报告增强）。

    聚合 entry_points/report_data/safe_vectors/dismissed/blackbox verdicts 为
    deliverables 根 api_evidence_matrix.json（跨 track 视角——白盒 workflow 时点
    黑盒 runs 多半未跑，黑盒栏为空；黑盒完成后的刷新靠 web lazy mtime 重建，
    spec §7）。任何异常 → logger.warning + skipped，绝不阻塞扫描收尾。
    """
    try:
        from supernova_core.services.api_evidence_matrix import (
            EVIDENCE_MATRIX_FILENAME, build_api_evidence_matrix)

        _repo, wb_deliverables, _ws = _get_paths(input)
        scan_dir = wb_deliverables.parent.parent
        matrix = build_api_evidence_matrix(scan_dir)
        atomic_write_json(wb_deliverables.parent / EVIDENCE_MATRIX_FILENAME, matrix)
        return {"status": "ok", "endpoints": len(matrix.get("endpoints", []))}
    except Exception as exc:  # noqa: BLE001 — non-blocking（报告增强，绝不阻塞扫描）
        logger.warning("run_assemble_api_evidence failed (non-blocking): %s", exc)
        return {"status": "skipped", "reason": str(exc)}
```

`workflows.py`：在 `run_report_polish` 的 `except` 块结束后（`start_to_close_timeout=timedelta(minutes=20)` 那个 try/except 的收尾花括号后）追加：

```python
                # === 接口证据矩阵（spec 2026-09-10 §6；non-fatal 报告增强） ===
                # report_data 终版后聚合：接口级白盒/黑盒两栏证据，落 deliverables
                # 根 api_evidence_matrix.json。黑盒 runs 此时多半未跑（黑盒栏空，
                # 黑盒完成后 web lazy mtime 重建刷新——spec §7）。失败不阻塞收尾。
                self._state.current_agent = "assemble-api-evidence"
                try:
                    await workflow.execute_activity(
                        activities.run_assemble_api_evidence, act_input,
                        start_to_close_timeout=timedelta(minutes=2),
                        retry_policy=retry_for("standard"),
                    )
                except Exception as exc:
                    if is_cancellation(exc):  # 取消放行
                        raise
                    await workflow.execute_activity(
                        activities.log_info_activity,
                        ActivityInput(**{**act_input.__dict__,
                           "info_message": f"api evidence matrix assembly failed (non-fatal): {exc}",
                           "info_level": "warning"}),
                        start_to_close_timeout=timedelta(seconds=10),
                        retry_policy=retry_for("log"),
                    )
```

`worker.py`：activities 列表 `run_assemble_dataflow_view,` 行后加一行 `run_assemble_api_evidence,`；同文件顶部 import 块（`from …pipeline.activities import` 处，约 27 行 `run_assemble_dataflow_view,` 旁）加 `run_assemble_api_evidence,`。

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /root/ft-codescan/packages/whitebox && python -m pytest tests/pipeline/test_assemble_api_evidence_activity.py tests/pipeline/test_assemble_dataflow_view_activity.py -v`
Expected: PASS（新测试 + dataflow 回归不破）

- [ ] **Step 5: Commit**

```bash
cd /root/ft-codescan && git add packages/whitebox/src/supernova_whitebox/pipeline/activities.py packages/whitebox/src/supernova_whitebox/pipeline/workflows.py packages/whitebox/src/supernova_whitebox/worker.py packages/whitebox/tests/pipeline/test_assemble_api_evidence_activity.py
git commit -m "feat(whitebox): run_assemble_api_evidence non-fatal 活动——report_polish 后落 deliverables 根 api_evidence_matrix.json（黑盒栏 web lazy 刷新）"
```

---

### Task 4: web API——GET evidence-matrix + lazy 重建

**Files:**
- Modify: `packages/web/src/supernova_web/api/scans.py`（`scan_dataflow` endpoint 之后追加）
- Test: `packages/web/tests/test_scans_evidence_matrix.py`（fixture 惯例对齐 `test_scans_dataflow.py`：`authed_client` + `tmp_workspaces` + `_make_scan`）

**Interfaces:**
- Consumes: Task 2 的 `build_api_evidence_matrix` / `EVIDENCE_MATRIX_FILENAME`；本文件已有 `_scan_dir_or_404(request, ws, scan_id)`、`REPORT_DATA_FILENAME`、`Depends(workspace_member)`、`HTTPException`。
- Produces: `GET /api/workspaces/{ws}/scans/{scan_id}/evidence-matrix` → 200 matrix dict / 404 `{"detail": "evidence matrix not available"}`。Task 5/6 前端 `fetchEvidenceMatrix` 消费。

- [ ] **Step 1: Write the failing test**

`packages/web/tests/test_scans_evidence_matrix.py`：

```python
"""evidence-matrix 端点：直读 / lazy 重建 / mtime 陈旧重建 / 404。

fixture 惯例对齐 test_scans_dataflow.py（authed_client + tmp_workspaces +
直接建 scan 目录写 session.json）。lazy 生成在 web 进程内跑 core 纯聚合函数
（零 agent，不违 test_web_never_runs_agents 守护）。
"""
import json
import os
import time


def _make_scan(tmp_workspaces, ws, scan_id="s1"):
    scan_dir = tmp_workspaces / ws / "scans" / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)
    sess = {"status": "completed", "scan_type": "whitebox", "created_at": 1780000000.0,
            "web_url": "http://e", "repo_path": "/code", "owner": "web"}
    (scan_dir / "session.json").write_text(json.dumps(sess))
    return scan_dir


def _wb_products(scan_dir, vulns=None, entries=None):
    wb = scan_dir / "deliverables" / "whitebox"
    (wb / "intermediate").mkdir(parents=True, exist_ok=True)
    (wb / "report_data.json").write_text(json.dumps(
        {"schema_version": 1, "vulnerabilities": vulns or []}))
    (wb / "intermediate" / "entry_points.json").write_text(json.dumps({
        "repository": "/r", "language": "js",
        "adjudicated_entry_points": entries or [],
    }))


def _ep(method, route):
    return {"func_block_id": "f:1", "verdict": "confirmed", "entry_type": "http_route",
            "route": route, "http_method": method, "evidence": "e", "source": "code_index"}


def test_evidence_matrix_200_when_cached(authed_client, tmp_workspaces):
    scan_dir = _make_scan(tmp_workspaces, "w1")
    _wb_products(scan_dir)
    cached = {"schema_version": 1, "scan_id": "s1", "cached": True, "sources": {},
              "endpoints": [], "unmatched": {}}
    (scan_dir / "deliverables" / "api_evidence_matrix.json").write_text(
        json.dumps(cached))
    # 缓存比所有源新 → 直读不重建
    r = authed_client.get("/api/workspaces/w1/scans/s1/evidence-matrix")
    assert r.status_code == 200
    assert r.json()["cached"] is True


def test_evidence_matrix_lazy_generates_and_persists(authed_client, tmp_workspaces):
    scan_dir = _make_scan(tmp_workspaces, "w1")
    _wb_products(scan_dir, entries=[_ep("GET", "/profile")])
    r = authed_client.get("/api/workspaces/w1/scans/s1/evidence-matrix")
    assert r.status_code == 200
    body = r.json()
    assert body["schema_version"] == 1
    assert body["endpoints"][0]["path"] == "/profile"
    # 落盘缓存（下次直读）
    assert (scan_dir / "deliverables" / "api_evidence_matrix.json").exists()


def test_evidence_matrix_stale_cache_rebuilds(authed_client, tmp_workspaces):
    """缓存比源旧（黑盒 verdicts 更新后）→ 重建。"""
    scan_dir = _make_scan(tmp_workspaces, "w1")
    _wb_products(scan_dir, entries=[_ep("GET", "/profile")])
    stale = {"schema_version": 1, "scan_id": "s1", "stale": True, "sources": {},
             "endpoints": [], "unmatched": {}}
    out = scan_dir / "deliverables" / "api_evidence_matrix.json"
    out.write_text(json.dumps(stale))
    past = time.time() - 3600
    os.utime(out, (past, past))  # 缓存 1 小时前
    r = authed_client.get("/api/workspaces/w1/scans/s1/evidence-matrix")
    assert r.status_code == 200
    assert "stale" not in r.json()
    assert r.json()["endpoints"][0]["path"] == "/profile"


def test_evidence_matrix_404_when_nothing(authed_client, tmp_workspaces):
    _make_scan(tmp_workspaces, "w1")  # 无 matrix 无 report_data
    r = authed_client.get("/api/workspaces/w1/scans/s1/evidence-matrix")
    assert r.status_code == 404
    assert "not available" in r.json()["detail"]


def test_evidence_matrix_404_when_scan_missing(authed_client, tmp_workspaces):
    r = authed_client.get("/api/workspaces/w1/scans/nope/evidence-matrix")
    assert r.status_code == 404
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /root/ft-codescan/packages/web && python -m pytest tests/test_scans_evidence_matrix.py -v`
Expected: FAIL（404 路由不存在——FastAPI 返回 404 但 detail 是 "Not Found"，断言 `not available` 失败）

- [ ] **Step 3: Write minimal implementation**

`scans.py`：`scan_dataflow` endpoint 之后追加（import 放函数内，对齐本文件 lazy import 风格）：

```python
@router.get("/{ws}/scans/{scan_id}/evidence-matrix")
async def scan_evidence_matrix(ws: str, scan_id: str, request: Request,
                               _: User = Depends(workspace_member)) -> dict:
    """api_evidence_matrix.json（spec 2026-09-10 §7）——接口级证据矩阵。

    产物新鲜直读；缺失/陈旧（源产物 mtime 更新，典型 = 黑盒 run 完成后）且
    whitebox report_data.json 在 → web 进程内跑 core 纯聚合函数重建（零 agent，
    不违 web 零 agent 执行点铁律）+ 落盘缓存（写失败只返不缓存）。重建条件
    不满足但有旧产物 → 返旧文件；两者皆无 → 404。
    """
    import json as _json

    from supernova_core.services.api_evidence_matrix import (
        EVIDENCE_MATRIX_FILENAME, build_api_evidence_matrix)
    from supernova_core.utils.atomic_write import atomic_write_json

    scan_dir = _scan_dir_or_404(request, ws, scan_id)
    matrix_path = scan_dir / "deliverables" / EVIDENCE_MATRIX_FILENAME
    wb_rd = scan_dir / "deliverables" / "whitebox" / REPORT_DATA_FILENAME

    def _read_matrix() -> dict:
        return _json.loads(matrix_path.read_text(encoding="utf-8"))

    def _stale() -> bool:
        """缓存 mtime < 任一源产物 mtime → 陈旧。"""
        try:
            cached_mtime = matrix_path.stat().st_mtime
        except OSError:
            return True
        sources = [scan_dir / "deliverables" / "whitebox" /
                   "intermediate" / "entry_points.json", wb_rd, *scan_dir.glob(
            "deliverables/blackbox-runs/run-*/deliverables/blackbox/"
            "intermediate/*_exploit_verdicts.json")]
        return any(p.exists() and p.stat().st_mtime > cached_mtime
                   for p in sources)

    if matrix_path.exists() and not _stale():
        return _read_matrix()
    if not wb_rd.exists():
        if matrix_path.exists():
            return _read_matrix()  # 无法重建（report_data 缺）→ 旧文件兜底
        raise HTTPException(404, "evidence matrix not available")
    matrix = build_api_evidence_matrix(scan_dir)
    try:
        atomic_write_json(matrix_path, matrix)
    except OSError:
        pass  # 只读挂载等：不缓存，仅返回
    return matrix
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /root/ft-codescan/packages/web && python -m pytest tests/test_scans_evidence_matrix.py tests/test_web_never_runs_agents.py -v`
Expected: PASS（守护测试不受影响——聚合器是纯 JSON 处理，不 import agents.runner）

- [ ] **Step 5: Commit**

```bash
cd /root/ft-codescan && git add packages/web/src/supernova_web/api/scans.py packages/web/tests/test_scans_evidence_matrix.py
git commit -m "feat(web): GET evidence-matrix 端点——新鲜直读/lazy 重建/mtime 陈旧刷新（黑盒 run 后自动更新），零 agent 守护不破"
```

---

### Task 5: 前端——类型 + API client + 路由 + tab + i18n

**Files:**
- Modify: `packages/web/frontend/src/api/types.ts`（`DataflowView` 附近追加类型）
- Modify: `packages/web/frontend/src/api/client.ts`（`fetchDataflowView` 之后追加）
- Modify: `packages/web/frontend/src/router.tsx`（lazy import + 路由行）
- Modify: `packages/web/frontend/src/routes/WorkspaceDetail/ScanDetail.tsx:24-31`（`SCAN_TABS`）
- Modify: `packages/web/frontend/src/locales/zh.json` / `en.json`（`workspaceDetail.tabs.evidence` + `workspaceDetail.evidence.*`）

**Interfaces:**
- Consumes: Task 4 的 `GET /evidence-matrix`。
- Produces: `fetchEvidenceMatrix(ws: string, scanId: string) => Promise<EvidenceMatrix>`、类型 `EvidenceMatrix` 等（Task 6 EvidenceTab 消费）；路由 `evidence`（Tab value）。

- [ ] **Step 1: Add types（types.ts，`DataflowView` interface 之后）**

```ts
// ── 接口证据矩阵（spec 2026-09-10 §4；core api_evidence_matrix.py 产物）──

export interface EvidenceFinding {
  id: string | null;
  vuln_class: string | null;
  severity: string | null;
  confidence: string | null;
  title: string | null;
  evidence_chain: string | null;
  witness_payload: string | null;
  verdict: string | null;
  mismatch_reason: string | null;
  params: string[];
  auth_required: string | null;
  source_location: string | null;
  sink_location: string | null;
  role?: string | null;
}

export interface EvidenceSafeVector {
  subject: string | null;
  defense_mechanism: string | null;
  location: string | null;
  contains_live_probe: boolean;
}

export interface EvidenceDismissed {
  ID: string | null;
  vuln_class: string | null;
  title: string | null;
  dismiss_reason: string | null;
  dismissed_at_stage: string | null;
}

export interface EvidenceVerdict {
  vulnerability_id: string | null;
  vuln_class: string | null;
  status: string | null;
  severity: string | null;
  impact: string | null;
  exploitation_steps: string[];
  proof_of_impact: string | null;
  run_id: string | null;
}

export interface EvidenceEndpoint {
  method: string;
  path: string;
  raw_route: string | null;
  func_block_id: string | null;
  entry_verdict: string | null;
  entry_evidence: string | null;
  whitebox: {
    findings: EvidenceFinding[];
    safe: EvidenceSafeVector[];
    dismissed: EvidenceDismissed[];
  };
  blackbox: {
    verdicts: EvidenceVerdict[];
    rejected: Record<string, unknown>[];
  };
  coverage: "findings" | "defended" | "clean";
}

export interface EvidenceMatrix {
  schema_version: number;
  scan_id: string | null;
  generated_at: string | null;
  sources: Record<string, unknown>;
  endpoints: EvidenceEndpoint[];
  unmatched: {
    findings: Record<string, unknown>[];
    safe_dismissed: Record<string, unknown>[];
    verdicts: Record<string, unknown>[];
  };
  note?: string | null;
}
```

- [ ] **Step 2: Add client（client.ts，`fetchDataflowView` 之后）**

```ts
// GET /workspaces/{ws}/scans/{id}/evidence-matrix → api_evidence_matrix.json
//（写时组装 + web lazy 重建；404 = 该扫描无证据产物）。
export const fetchEvidenceMatrix = (ws: string, scanId: string) =>
  apiGet<EvidenceMatrix>(`/workspaces/${encWs(ws)}/scans/${encWs(scanId)}/evidence-matrix`);
```

（同文件顶部 import 块的 `DataflowView` 类型 import 处补 `EvidenceMatrix`。）

- [ ] **Step 3: Wire route + tab**

`router.tsx`：lazy import 区（`DataFlowTab` 行旁）加：

```ts
const EvidenceTab = lazyWithRetry(() => import("./routes/WorkspaceDetail/EvidenceTab").then(m => ({ default: m.EvidenceTab })));
```

per-scan 子路由（`{ path: "report", element: <ReportTab /> }` 行后）加：

```ts
          { path: "evidence", element: <EvidenceTab /> },
```

`ScanDetail.tsx` `SCAN_TABS`（report 行后插入，spec §8：report 之后 deliverables 之前）：

```ts
const SCAN_TABS = [
  { value: "overview", labelKey: "workspaceDetail.tabs.overview" },
  { value: "report", labelKey: "workspaceDetail.tabs.report" },
  { value: "evidence", labelKey: "workspaceDetail.tabs.evidence" },
  { value: "deliverables", labelKey: "workspaceDetail.tabs.deliverables" },
  { value: "dataflow", labelKey: "workspaceDetail.tabs.dataflow" },
  { value: "logs", labelKey: "workspaceDetail.tabs.logs" },
  { value: "live", labelKey: "workspaceDetail.tabs.live" },
] as const;
```

**注意**：本 task 结束时 `EvidenceTab.tsx` 尚不存在（Task 6 创建），router lazy import 会编译失败——**本 task 先创建最小占位组件** `packages/web/frontend/src/routes/WorkspaceDetail/EvidenceTab.tsx`：

```tsx
/** 接口证据 tab（spec 2026-09-10 §8）——Task 6 实现完整 UI，本占位先通路由。 */
export function EvidenceTab() {
  return null;
}
```

- [ ] **Step 4: Add i18n keys**

`src/locales/zh.json` 的 `"workspaceDetail"` → `"tabs"` 段加（dataflow 行旁）：

```json
      "evidence": "证据",
```

`"workspaceDetail"` 段下加 `"evidence"` 子对象（放在 `"dataflow"` 兄弟位置；键名 camelCase）：

```json
    "evidence": {
      "emptyTitle": "无接口证据产物",
      "emptyHint": "该扫描未产出接口证据矩阵（旧版扫描或纯黑盒扫描）。需新版白盒扫描。",
      "filterAll": "全部",
      "coverageFindings": "有发现",
      "coverageDefended": "有防御结论",
      "coverageClean": "无发现",
      "whiteboxTrack": "白盒分析证据",
      "blackboxTrack": "黑盒验证证据",
      "whiteboxEmpty": "白盒无发现",
      "blackboxEmpty": "黑盒未验证",
      "findingsGroup": "问题证据",
      "safeGroup": "安全结论",
      "dismissedGroup": "已驳回候选",
      "liveProbe": "含实测",
      "unmatchedBanner": "{{n}} 条证据未能关联到具体接口",
      "steps": "实测步骤",
      "proof": "实测证据",
      "witness": "Witness Payload",
      "evidenceChain": "证据链",
      "dismissReason": "驳回理由",
      "selectEndpoint": "选择左侧接口查看证据"
    },
```

`src/locales/en.json` 同结构英文翻译：

```json
    "evidence": {
      "emptyTitle": "No API evidence matrix",
      "emptyHint": "This scan has no evidence matrix (legacy or blackbox-only scan). Requires a recent whitebox scan.",
      "filterAll": "All",
      "coverageFindings": "Findings",
      "coverageDefended": "Defended",
      "coverageClean": "Clean",
      "whiteboxTrack": "Whitebox analysis evidence",
      "blackboxTrack": "Blackbox verification evidence",
      "whiteboxEmpty": "No whitebox findings",
      "blackboxEmpty": "Not verified by blackbox",
      "findingsGroup": "Findings",
      "safeGroup": "Safety conclusions",
      "dismissedGroup": "Dismissed candidates",
      "liveProbe": "live probe",
      "unmatchedBanner": "{{n}} evidence items could not be mapped to an endpoint",
      "steps": "Exploitation steps",
      "proof": "Proof of impact",
      "witness": "Witness payload",
      "evidenceChain": "Evidence chain",
      "dismissReason": "Dismiss reason",
      "selectEndpoint": "Select an endpoint to view evidence"
    },
```

- [ ] **Step 5: Verify build + i18n test**

Run: `cd /root/ft-codescan/packages/web/frontend && npx tsc -b && npx vitest run src/i18n/locales.test.ts`
Expected: tsc 零错误；locales 测试 PASS（zh/en 键集一致性）

- [ ] **Step 6: Commit**

```bash
cd /root/ft-codescan && git add packages/web/frontend/src/api/types.ts packages/web/frontend/src/api/client.ts packages/web/frontend/src/router.tsx packages/web/frontend/src/routes/WorkspaceDetail/ScanDetail.tsx packages/web/frontend/src/routes/WorkspaceDetail/EvidenceTab.tsx packages/web/frontend/src/locales/zh.json packages/web/frontend/src/locales/en.json
git commit -m "feat(web-fe): 证据 tab 挂载——types/client/路由/SCAN_TABS/i18n（EvidenceTab 占位，Task 6 填 UI）"
```

---

### Task 6: EvidenceTab 组件（接口清单 + 白盒/黑盒两栏证据）

**Files:**
- Modify: `packages/web/frontend/src/routes/WorkspaceDetail/EvidenceTab.tsx`（替换占位实现）
- Test: `packages/web/frontend/src/routes/WorkspaceDetail/EvidenceTab.test.tsx`

**Interfaces:**
- Consumes: Task 5 的 `fetchEvidenceMatrix` / `EvidenceMatrix` 类型；`@/api/client` 的 `ApiError`；`@/components/Empty`；`@/components/ui/skeleton`；`renderWithSwr`（`@/test/swr-render`）。
- Produces: 完整证据页 UI（本 plan 的最终用户可见交付物）。

**布局**（spec §8）：
- 顶部：unmatched 提示条（`unmatched` 三桶合计 > 0 时显示）+ coverage/method 筛选下拉。
- 左列（`w-72 shrink-0`，可滚动）：接口行 = method 徽标 + path + coverage 色点 + 计数徽标（findings/verdicts）。
- 右侧：选中接口标题行（method+path+raw_route）→ **白盒栏（蓝系边框）/ 黑盒栏（橙系边框）左右两栏**（`grid gap-4 lg:grid-cols-2`）：
  - 白盒栏：findings 卡（title/severity/confidence/evidence_chain/witness_payload/params/auth）→ safe 卡（subject/defense_mechanism/location + `contains_live_probe` 徽标）→ dismissed 卡（title/dismiss_reason）。
  - 黑盒栏：verdicts 卡（status/severity/impact/exploitation_steps 编号列表/proof_of_impact 等宽块）。
  - 空态文案：白盒 `whiteboxEmpty` / 黑盒 `blackboxEmpty`。
- 404 → `Empty`（`emptyTitle`/`emptyHint`）；加载中 → Skeleton。
- 筛选逻辑：`coverageFilter: "all"|"findings"|"defended"|"clean"`；`methodFilter: "all"|METHOD`（数据派生自 endpoints）。排序：coverage 权重 findings(0) < defended(1) < clean(2)，同档按 method+path 字典序。

- [ ] **Step 1: Write the failing test**

`EvidenceTab.test.tsx`：

```tsx
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import i18n from "@/i18n";
import type { EvidenceMatrix } from "@/api/types";
import { EvidenceTab } from "./EvidenceTab";

// SWR 数据源打桩：EvidenceTab 经 fetchEvidenceMatrix 拉 matrix
vi.mock("@/api/client", () => ({
  ApiError: class extends Error { status: number; },
  fetchEvidenceMatrix: vi.fn(),
}));

import { fetchEvidenceMatrix } from "@/api/client";
const mockedFetch = vi.mocked(fetchEvidenceMatrix);

const matrix: EvidenceMatrix = {
  schema_version: 1, scan_id: "s1", generated_at: null, sources: {},
  endpoints: [
    {
      method: "GET", path: "/allocations/:userId", raw_route: "/allocations/:userId",
      func_block_id: null, entry_verdict: "confirmed", entry_evidence: null,
      whitebox: {
        findings: [{
          id: "INJ-VULN-01", vuln_class: "injection", severity: "high",
          confidence: "high", title: "NoSQL 注入", evidence_chain: "a.js -> dao.js",
          witness_payload: "1'; while(true){}; //", verdict: "vulnerable",
          mismatch_reason: null, params: ["userId (path)"],
          auth_required: "isLoggedIn", source_location: null, sink_location: null,
        }],
        safe: [], dismissed: [],
      },
      blackbox: {
        verdicts: [{
          vulnerability_id: "INJ-VULN-01", vuln_class: "injection",
          status: "exploited", severity: "critical", impact: "RCE",
          exploitation_steps: ["send payload"], proof_of_impact: "uid=1000",
          run_id: "run-1",
        }],
        rejected: [],
      },
      coverage: "findings",
    },
    {
      method: "GET", path: "/profile", raw_route: "/profile",
      func_block_id: null, entry_verdict: "confirmed", entry_evidence: null,
      whitebox: {
        findings: [],
        safe: [{ subject: "GET /profile", defense_mechanism: "session 绑定",
                 location: "profile.js:14", contains_live_probe: false }],
        dismissed: [],
      },
      blackbox: { verdicts: [], rejected: [] },
      coverage: "defended",
    },
  ],
  unmatched: { findings: [], safe_dismissed: [], verdicts: [] },
};

function renderTab() {
  // react-router useParams 需路由上下文——组件内 ws/scanId 缺省 "" 时 SWR key
  // 为 null 不发请求，故测试直接传经 mock 的数据渲染需要路由包装：
  return render(
    <MemoryRouter initialEntries={["/w/scans/s1/evidence"]}>
      <Routes>
        <Route path="/:workspace/:_scans/:scanId/:_tab" element={<EvidenceTab />} />
      </Routes>
    </MemoryRouter>,
  );
}

import { MemoryRouter, Route, Routes } from "react-router-dom";

describe("EvidenceTab", () => {
  beforeEach(() => { mockedFetch.mockResolvedValue(matrix); });

  it("渲染接口清单与 coverage 徽标", async () => {
    renderTab();
    expect(await screen.findByText("/allocations/:userId")).toBeTruthy();
    expect(screen.getByText("/profile")).toBeTruthy();
    expect(screen.getByText(i18n.t("workspaceDetail.evidence.coverageFindings"))).toBeTruthy();
  });

  it("选中接口展示白盒/黑盒两栏证据", async () => {
    renderTab();
    fireEvent.click(await screen.findByText("/allocations/:userId"));
    // 白盒栏
    expect(screen.getByText("INJ-VULN-01")).toBeTruthy();
    expect(screen.getByText(/while\(true\)/)).toBeTruthy();
    // 黑盒栏
    expect(screen.getByText("exploited")).toBeTruthy();
    expect(screen.getByText("uid=1000")).toBeTruthy();
  });

  it("defended 接口展示防御结论与黑盒未验证空态", async () => {
    renderTab();
    fireEvent.click(await screen.findByText("/profile"));
    expect(screen.getByText(/session 绑定/)).toBeTruthy();
    expect(screen.getByText(i18n.t("workspaceDetail.evidence.blackboxEmpty"))).toBeTruthy();
  });
});
```

（若组件内 `useSWR` 的 key 写法在 `ws/id` 为空时不发请求导致测试挂起，检查 mock 路由参数注入是否生效；`DataFlowTab` 同款 params 模式。）

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /root/ft-codescan/packages/web/frontend && npx vitest run src/routes/WorkspaceDetail/EvidenceTab.test.tsx`
Expected: FAIL（占位组件 render null，findByText 超时）

- [ ] **Step 3: Write minimal implementation**

`EvidenceTab.tsx`（替换占位）：

```tsx
import { useMemo, useState } from "react";
import useSWR from "swr";
import { useParams } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { ApiError, fetchEvidenceMatrix } from "@/api/client";
import type { EvidenceEndpoint, EvidenceMatrix } from "@/api/types";
import { Empty } from "@/components/Empty";
import { Skeleton } from "@/components/ui/skeleton";

/**
 * 接口证据 tab（spec 2026-09-10 §8）。
 *
 * 左列接口清单（coverage/method 筛选）+ 右侧选中接口的白盒（蓝）/黑盒（橙）
 * 两栏证据。404 = 无证据产物（旧版/纯黑盒扫描）→ Empty 空态。
 * SWR 拉 GET /workspaces/{ws}/scans/{id}/evidence-matrix（web lazy 重建，
 * 黑盒 run 完成后自动刷新——mtime 失效语义见后端）。
 */
const COVERAGE_ORDER = { findings: 0, defended: 1, clean: 2 } as const;
const COVERAGE_KEY = {
  findings: "workspaceDetail.evidence.coverageFindings",
  defended: "workspaceDetail.evidence.coverageDefended",
  clean: "workspaceDetail.evidence.coverageClean",
};

export function EvidenceTab() {
  const { t } = useTranslation();
  const { workspace, scanId } = useParams<{ workspace: string; scanId: string }>();
  const ws = workspace ?? "";
  const id = scanId ?? "";
  const { data, error, isLoading } = useSWR(
    ws && id ? ["evidence-matrix", ws, id] : null,
    () => fetchEvidenceMatrix(ws, id),
  );

  const [coverageFilter, setCoverageFilter] = useState<string>("all");
  const [methodFilter, setMethodFilter] = useState<string>("all");
  const [selectedPath, setSelectedPath] = useState<string | null>(null);

  const methods = useMemo(
    () => [...new Set((data?.endpoints ?? []).map((e) => e.method))].sort(),
    [data],
  );
  const endpoints = useMemo(() => {
    const list = (data?.endpoints ?? []).filter((e) =>
      (coverageFilter === "all" || e.coverage === coverageFilter) &&
      (methodFilter === "all" || e.method === methodFilter));
    return [...list].sort((a, b) =>
      COVERAGE_ORDER[a.coverage] - COVERAGE_ORDER[b.coverage] ||
      `${a.method} ${a.path}`.localeCompare(`${b.method} ${b.path}`));
  }, [data, coverageFilter, methodFilter]);

  const selected = useMemo(
    () => endpoints.find((e) => `${e.method} ${e.path}` === selectedPath)
      ?? endpoints[0] ?? null,
    [endpoints, selectedPath],
  );

  const unmatchedTotal = data
    ? data.unmatched.findings.length + data.unmatched.safe_dismissed.length
      + data.unmatched.verdicts.length
    : 0;

  if (error instanceof ApiError && error.status === 404) {
    return (
      <Empty title={t("workspaceDetail.evidence.emptyTitle")}
             hint={t("workspaceDetail.evidence.emptyHint")} />
    );
  }
  if (isLoading || !data) return <Skeleton className="h-96 w-full" />;

  return (
    <div className="flex h-full min-h-0 gap-4">
      {/* 左列：接口清单 */}
      <aside className="w-72 shrink-0 overflow-y-auto" data-testid="evidence-list">
        <div className="mb-2 flex gap-2">
          <select aria-label="coverage" value={coverageFilter}
                  onChange={(e) => setCoverageFilter(e.target.value)}
                  className="rounded border bg-background px-2 py-1 text-xs">
            <option value="all">{t("workspaceDetail.evidence.filterAll")}</option>
            <option value="findings">{t(COVERAGE_KEY.findings)}</option>
            <option value="defended">{t(COVERAGE_KEY.defended)}</option>
            <option value="clean">{t(COVERAGE_KEY.clean)}</option>
          </select>
          <select aria-label="method" value={methodFilter}
                  onChange={(e) => setMethodFilter(e.target.value)}
                  className="rounded border bg-background px-2 py-1 text-xs">
            <option value="all">{t("workspaceDetail.evidence.filterAll")}</option>
            {methods.map((m) => <option key={m} value={m}>{m}</option>)}
          </select>
        </div>
        {unmatchedTotal > 0 && (
          <div className="mb-2 rounded border border-amber-500/40 bg-amber-500/10 px-2 py-1 text-xs">
            {t("workspaceDetail.evidence.unmatchedBanner", { n: unmatchedTotal })}
          </div>
        )}
        <ul>
          {endpoints.map((e) => {
            const key = `${e.method} ${e.path}`;
            const active = selected && `${selected.method} ${selected.path}` === key;
            return (
              <li key={key}>
                <button
                  onClick={() => setSelectedPath(key)}
                  className={`flex w-full items-center gap-2 rounded px-2 py-1.5 text-left text-sm hover:bg-accent ${active ? "bg-accent" : ""}`}
                >
                  <span className="font-mono text-xs font-semibold">{e.method}</span>
                  <span className="flex-1 truncate font-mono text-xs">{e.path}</span>
                  <CoverageDot coverage={e.coverage} />
                  {(e.whitebox.findings.length > 0 || e.blackbox.verdicts.length > 0) && (
                    <span className="rounded-full bg-muted px-1.5 text-[10px]">
                      {e.whitebox.findings.length}/{e.blackbox.verdicts.length}
                    </span>
                  )}
                </button>
              </li>
            );
          })}
        </ul>
      </aside>

      {/* 右侧：选中接口两栏证据 */}
      <div className="min-w-0 flex-1 overflow-y-auto">
        {selected ? (
          <>
            <header className="mb-4">
              <h2 className="font-mono text-base font-semibold">
                <span className="mr-2 rounded bg-muted px-1.5 py-0.5 text-xs">
                  {selected.method}
                </span>
                {selected.path}
              </h2>
            </header>
            <div className="grid gap-4 lg:grid-cols-2">
              <WhiteboxColumn endpoint={selected} />
              <BlackboxColumn endpoint={selected} />
            </div>
          </>
        ) : (
          <Empty title={t("workspaceDetail.evidence.selectEndpoint")} />
        )}
      </div>
    </div>
  );
}

function CoverageDot({ coverage }: { coverage: EvidenceEndpoint["coverage"] }) {
  const color = coverage === "findings" ? "bg-red-500"
    : coverage === "defended" ? "bg-emerald-500" : "bg-muted-foreground/30";
  return <span className={`h-2 w-2 shrink-0 rounded-full ${color}`} aria-label={coverage} />;
}

function WhiteboxColumn({ endpoint }: { endpoint: EvidenceEndpoint }) {
  const { t } = useTranslation();
  const { findings, safe, dismissed } = endpoint.whitebox;
  return (
    <section className="space-y-3 rounded-lg border border-blue-500/30 p-3"
             data-testid="evidence-whitebox">
      <h3 className="text-sm font-semibold text-blue-600 dark:text-blue-400">
        {t("workspaceDetail.evidence.whiteboxTrack")}
      </h3>
      {findings.length === 0 && safe.length === 0 && dismissed.length === 0 ? (
        <p className="text-xs text-muted-foreground">
          {t("workspaceDetail.evidence.whiteboxEmpty")}</p>
      ) : (
        <>
          {findings.map((f) => (
            <article key={f.id} className="rounded border p-2 text-xs">
              <div className="font-medium">
                {f.id} · {f.title}
                {f.severity && <SeverityTag severity={f.severity} />}
              </div>
              {f.evidence_chain && (
                <p className="mt-1 whitespace-pre-wrap break-words">
                  {t("workspaceDetail.evidence.evidenceChain")}：{f.evidence_chain}
                </p>
              )}
              {f.witness_payload && (
                <pre className="mt-1 overflow-x-auto rounded bg-muted p-1.5 font-mono">
                  {f.witness_payload}
                </pre>
              )}
            </article>
          ))}
          {safe.map((s, i) => (
            <article key={i} className="rounded border border-emerald-500/30 p-2 text-xs">
              <div className="font-medium">
                {s.subject}
                {s.contains_live_probe && (
                  <span className="ml-1 rounded bg-amber-500/15 px-1 text-[10px] text-amber-600">
                    {t("workspaceDetail.evidence.liveProbe")}
                  </span>
                )}
              </div>
              <p className="mt-1">{s.defense_mechanism}</p>
              {s.location && <p className="mt-1 font-mono opacity-70">{s.location}</p>}
            </article>
          ))}
          {dismissed.map((d) => (
            <article key={d.ID} className="rounded border border-dashed p-2 text-xs opacity-80">
              <div className="font-medium">{d.title}</div>
              <p className="mt-1">
                {t("workspaceDetail.evidence.dismissReason")}：{d.dismiss_reason}
              </p>
            </article>
          ))}
        </>
      )}
    </section>
  );
}

function BlackboxColumn({ endpoint }: { endpoint: EvidenceEndpoint }) {
  const { t } = useTranslation();
  const { verdicts } = endpoint.blackbox;
  return (
    <section className="space-y-3 rounded-lg border border-orange-500/30 p-3"
             data-testid="evidence-blackbox">
      <h3 className="text-sm font-semibold text-orange-600 dark:text-orange-400">
        {t("workspaceDetail.evidence.blackboxTrack")}
      </h3>
      {verdicts.length === 0 ? (
        <p className="text-xs text-muted-foreground">
          {t("workspaceDetail.evidence.blackboxEmpty")}</p>
      ) : verdicts.map((v, i) => (
        <article key={i} className="rounded border p-2 text-xs">
          <div className="font-medium">
            {v.vulnerability_id} · {v.status}
            {v.severity && <SeverityTag severity={v.severity} />}
          </div>
          {v.impact && <p className="mt-1">{v.impact}</p>}
          {v.exploitation_steps.length > 0 && (
            <ol className="mt-1 list-decimal space-y-1 pl-4">
              {v.exploitation_steps.map((s, j) => <li key={j}>{s}</li>)}
            </ol>
          )}
          {v.proof_of_impact && (
            <pre className="mt-1 overflow-x-auto rounded bg-muted p-1.5 font-mono">
              {v.proof_of_impact}
            </pre>
          )}
        </article>
      ))}
    </section>
  );
}

function SeverityTag({ severity }: { severity: string }) {
  return (
    <span className="ml-1 rounded bg-red-500/10 px-1 text-[10px] text-red-600">
      {severity}
    </span>
  );
}
```

**实现注意：**
- `Empty` 组件的 props 名以实际 `@/components/Empty` 为准（`DataFlowTab` 用法是 `title` + 第二个 prop——**写码前先看该组件签名**，若第二 prop 名不是 `hint` 则对齐）。
- 视觉基调贴合项目主题系统（mode×palette 双 class、soft-tint 状态灯——memory `web-theme-system-architecture` / `scan-page-button-family-iterations`）：蓝/橙两栏用 `<color>-500/30` 半透明边 + `dark:` 变体文字色，不引入新配色体系。
- 组件不拆多文件（~280 行，内聚一个交付物；后续长再拆）。

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /root/ft-codescan/packages/web/frontend && npx vitest run src/routes/WorkspaceDetail/EvidenceTab.test.tsx && npx tsc -b`
Expected: 3 测试 PASS + tsc 零错误

- [ ] **Step 5: Commit**

```bash
cd /root/ft-codescan && git add packages/web/frontend/src/routes/WorkspaceDetail/EvidenceTab.tsx packages/web/frontend/src/routes/WorkspaceDetail/EvidenceTab.test.tsx
git commit -m "feat(web-fe): EvidenceTab 接口证据页——左列接口清单(coverage/method 筛选)+右侧白盒(蓝)/黑盒(橙)两栏证据卡+unmatched 提示条"
```

---

### Task 7: 端到端验证 + 真实扫描回填抽查

**Files:**
- 无新文件（验证任务）

**Interfaces:**
- Consumes: Task 1-6 全部交付物。
- Produces: 验证结论（产物在真实历史扫描上可聚合、前端可渲染）。

- [ ] **Step 1: 全部相关测试串跑**

Run:
```bash
cd /root/ft-codescan/packages/core && python -m pytest tests/services/test_api_evidence_matrix.py -v
cd /root/ft-codescan/packages/whitebox && python -m pytest tests/pipeline/test_assemble_api_evidence_activity.py -v
cd /root/ft-codescan/packages/web && python -m pytest tests/test_scans_evidence_matrix.py tests/test_web_never_runs_agents.py -v
cd /root/ft-codescan/packages/web/frontend && npx tsc -b && npx vitest run src/routes/WorkspaceDetail/EvidenceTab.test.tsx src/i18n/locales.test.ts
```
Expected: 全绿（不跑全套 pytest——CLAUDE.md §3 预存挂起约定）。

- [ ] **Step 2: 真实历史扫描离线聚合抽查**

对既有产物齐全的扫描跑聚合器（验证真实产物字段兼容——fixture 之外的最后防线）：

```bash
cd /root/ft-codescan/packages/core && python -c "
import json
from pathlib import Path
from supernova_core.services.api_evidence_matrix import build_api_evidence_matrix
m = build_api_evidence_matrix(Path('/root/ft-codescan/workspaces/__legacy__/scans/NodeGoat-20260827-040049'))
print('endpoints:', len(m['endpoints']))
print('coverage:', {c: sum(1 for e in m['endpoints'] if e['coverage']==c) for c in ('findings','defended','clean')})
print('unmatched:', {k: len(v) for k, v in m['unmatched'].items()})
print('blackbox_runs:', m['sources']['blackbox_runs'])
mounted = sum(len(e['whitebox']['findings']) for e in m['endpoints'])
print('mounted findings:', mounted)
"
```

Expected: endpoints ≈ 22（entry_points 数量级）、findings 挂载数与 report_data vulnerabilities 数量级吻合（23 条 → 多 endpoint 的重复挂载可略多）、unmatched 各桶非爆炸（findings 桶 0-3 条属正常）。若 findings 桶大量堆积 → 打印 unmatched reason 分类排查 `_endpoint_rows` 字符串行解析。

再验证一个带黑盒 verdicts 的扫描（NodeGoat-20260820-135941 有 run-1，但该扫描 deliverables 结构若无 whitebox 桶则 matrix 为空——属预期，注明即可；主验证对象是 20260827 白盒 + 手工把 20260820 的 blackbox-runs 目录 symlink 进来可选）。

- [ ] **Step 3: spec 状态更新**

`docs/superpowers/specs/2026-09-10-api-evidence-matrix-design.md` 头部状态行改为：

```markdown
- 状态：已实现（2026-09-10）
```

- [ ] **Step 4: Commit**

```bash
cd /root/ft-codescan && git add docs/superpowers/specs/2026-09-10-api-evidence-matrix-design.md
git commit -m "docs(specs): 接口证据页 spec 状态→已实现"
```

---

## Self-Review 记录

- **Spec 覆盖**：§4 schema（Task 2）、§5 匹配规则五条（Task 1/2：结构化优先=Task 2 `_endpoint_rows`+`match_entry`、归一化=Task 1 `normalize_route`、参数名无关+歧义=Task 1 `route_shape`/`match_entry`、自由文本=Task 1 `extract_endpoint_texts`+Task 2 挂载、黑盒锚链=Task 2 verdicts 段）、§6 聚合器+挂载（Task 2/3）、§7 web lazy（Task 4，mtime 失效为 spec「不存在才生成」的强化——黑盒 run 后产物会陈旧，spec §3 亦明示此动机）、§8 前端（Task 5/6）、§9 live probe 标记（Task 2 `_live_probe`）、§10 测试（各 task + Task 7）。§11 开放问题无需任务。
- **占位符扫描**：Task 5 的 EvidenceTab 占位是显式的临时桩（同 task 内声明、Task 6 替换），非「TBD」式占位。无其他占位。
- **类型一致性**：`build_api_evidence_matrix(scan_dir: Path) -> dict`（Task 2 定义、Task 3 activity / Task 4 API 消费）；`EVIDENCE_MATRIX_FILENAME`（Task 2 产、Task 3/4 用）；`fetchEvidenceMatrix`（Task 5 产、Task 6 用）；`EvidenceMatrix` 类型（Task 5 产、Task 6 用）；activity 名 `run_assemble_api_evidence`（Task 3 三处一致：activities/workflows/worker）。
