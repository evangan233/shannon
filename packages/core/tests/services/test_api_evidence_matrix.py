"""api_evidence_matrix 聚合器单测（spec 2026-09-10 §5 匹配规则）。

Task 1 覆盖纯函数：normalize_route / route_shape / index_entries /
match_entry / extract_endpoint_texts。
Task 2 覆盖 build_api_evidence_matrix 主流程（fixture 产物树）。
"""
import json
from pathlib import Path

from supernova_core.services.api_evidence_matrix import (
    build_api_evidence_matrix,
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

    def test_method_path_regex_includes_underscore(self):
        # 修复 round 1：字符类补 `_`——`GET /user_profile` 不得截断成 /user（证据错挂他接口）
        assert extract_endpoint_texts("GET /user_profile（本人 PII 读取）") == [
            ("GET", "/user_profile")]


# ---------------------------------------------------------------------------
# Task 2: build_api_evidence_matrix 主流程（fixture 产物树）
# ---------------------------------------------------------------------------
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
        # （真实布局：blackbox-runs/ 与 deliverables/ 平级，见 utils/paths.blackbox_runs_dir）
        bb = scan / "blackbox-runs" / "run-1" / \
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
        # 同 method 同 shape 两条底册行（尾斜杠归一后均为 /data）→ finding 归属歧义
        _write_entry_points(scan, [_ep("GET", "/data"), _ep("GET", "/data/", block="f:2")])
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

    def test_blackbox_only_verdict_fallback_yields_findings_coverage(self, tmp_path):
        # 修复 round 1：§5.5 verdict 自身文本挂载的黑盒-only 接口不得误标 clean
        # （spec §4：clean = 白盒/黑盒证据均未命中）
        scan = _wb_scan(tmp_path)
        _write_entry_points(scan, [_ep("GET", "/export")])
        _write_report_data(scan, [])  # 无白盒 finding
        bb = scan / "blackbox-runs" / "run-2" / \
            "deliverables" / "blackbox" / "intermediate"
        bb.mkdir(parents=True)
        (bb / "injection_exploit_verdicts.json").write_text(json.dumps({
            "vuln_class": "injection",
            "verdicts": [{"vulnerability_id": "BB-9", "status": "exploited",
                          "impact": "GET /export 导出全部用户 PII",
                          "exploitation_steps": []}],
        }))
        m = build_api_evidence_matrix(scan)
        row = _find_matrix(m, "GET", "/export")
        assert row["whitebox"] == {"findings": [], "safe": [], "dismissed": []}
        assert row["blackbox"]["verdicts"][0]["vulnerability_id"] == "BB-9"
        assert row["coverage"] == "findings"
