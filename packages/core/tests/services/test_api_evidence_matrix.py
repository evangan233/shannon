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
        assert m["schema_version"] == 2
        assert m["endpoints"] == []
        assert m["sources"]["entry_points"] is False
        assert "note" in m

    def test_identical_duplicate_entries_deduped_finding_mounts(self, tmp_path):
        """旧扫描自愈（2026-09-11 NodeGoat 事故）：注释代码曾产出逐字段完全
        相同的重复 entry（/benefits ×2）→ match_entry 把纯重复当真歧义拒挂，
        finding 全落 unmatched。矩阵层对完全相同条目去重；真歧义（不同
        block/evidence）仍拒挂（由 test_ambiguous_endpoint_goes_unmatched 锁定）。"""
        scan = _wb_scan(tmp_path)
        _write_entry_points(scan, [_ep("GET", "/benefits"), _ep("GET", "/benefits")])
        _write_report_data(scan, [
            _vuln("AUTHZ-1", "authz", [{"method": "GET", "path": "/benefits"}]),
        ])
        m = build_api_evidence_matrix(scan)
        row = _find_matrix(m, "GET", "/benefits")
        assert row is not None
        assert row["whitebox"]["findings"][0]["id"] == "AUTHZ-1"
        assert not m["unmatched"]["findings"]
        # 底册行本身也只展示一条（重复行不再进矩阵）
        assert len([e for e in m["endpoints"]
                    if e["method"] == "GET" and e["path"] == "/benefits"]) == 1

    def test_verdict_exploitation_steps_dict_items_coerced_to_string(self, tmp_path):
        """组合扫描后证据页报错根因（2026-09-11）：黑盒 verdict 步骤是
        {action,command,result} dict 列表，原样透传 → 前端 <li>{s}</li> 渲染
        object 崩（Objects are not valid as a React child）→ ErrorBoundary。
        矩阵 SSOT 侧收敛为可读字符串（前端零改动）。"""
        scan = _wb_scan(tmp_path)
        _write_entry_points(scan, [_ep("GET", "/export")])
        _write_report_data(scan, [])
        bb = scan / "blackbox-runs" / "run-1" / \
            "deliverables" / "blackbox" / "intermediate"
        bb.mkdir(parents=True)
        (bb / "auth_exploit_verdicts.json").write_text(json.dumps({
            "vuln_class": "auth",
            "verdicts": [{"vulnerability_id": "AUTH-1", "status": "exploited",
                          "impact": "GET /export 伪造会话导出 PII",
                          "exploitation_steps": [
                              {"action": "构造伪造 cookie",
                               "command": "node -e 'sign...'",
                               "result": "Set-Cookie 下发"},
                              "携带 cookie 访问 /export",   # string 步骤原样保留
                              {"unexpected": "形状外键"},    # 形状外 dict 不丢信息
                          ]}],
        }))
        m = build_api_evidence_matrix(scan)
        steps = _find_matrix(m, "GET", "/export")["blackbox"]["verdicts"][0][
            "exploitation_steps"]
        assert all(isinstance(s, str) for s in steps)
        assert "构造伪造 cookie" in steps[0]
        assert "node -e 'sign...'" in steps[0]
        assert "Set-Cookie 下发" in steps[0]
        assert steps[1] == "携带 cookie 访问 /export"
        assert isinstance(steps[2], str) and "unexpected" in steps[2]

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


class TestVerdictViewRichFields:
    """证据页 v2（2026-09-16）：5 态 verdict 富透传。

    `_verdict_view` 此前只有 exploited 形态字段——blocked/potential 卡
    impact=None 时前端整卡只剩 status 一个词，「为什么没问题/没打通」的
    current_blocker/what_we_tried/downgrade_reason 全被丢掉。
    """

    def _bb(self, scan, vc, verdicts):
        bb = scan / "blackbox-runs" / "run-1" / \
            "deliverables" / "blackbox" / "intermediate"
        bb.mkdir(parents=True)
        (bb / f"{vc}_exploit_verdicts.json").write_text(json.dumps({
            "vuln_class": vc, "verdicts": verdicts}))

    def _scan_with_finding(self, tmp_path):
        scan = _wb_scan(tmp_path)
        _write_entry_points(scan, [_ep("GET", "/allocations/:userId")])
        _write_report_data(scan, [
            _vuln("INJ-VULN-01", "injection",
                  [{"method": "GET", "path": "/allocations/:id"}]),
        ])
        return scan

    def _mounted_verdict(self, matrix):
        row = _find_matrix(matrix, "GET", "/allocations/:userId")
        assert row is not None
        assert row["blackbox"]["verdicts"], "verdict 应经 finding 锚挂载"
        return row["blackbox"]["verdicts"][0]

    def test_blocked_verdict_carries_blocker_evidence(self, tmp_path):
        scan = self._scan_with_finding(tmp_path)
        self._bb(scan, "injection", [{
            "vulnerability_id": "INJ-VULN-01", "status": "blocked_by_security",
            "confidence": "high", "current_blocker": "WAF 拦截单引号",
            "what_we_tried": "编码绕过/注释混淆等 10 种",
            "evidence_of_vulnerability": "报错回显确认注入点存在",
            "expected_impact": "若无 WAF 可 RCE", "cwe_id": "CWE-89",
        }])
        m = build_api_evidence_matrix(scan)
        v = self._mounted_verdict(m)
        assert v["current_blocker"] == "WAF 拦截单引号"
        assert v["what_we_tried"] == "编码绕过/注释混淆等 10 种"
        assert v["evidence_of_vulnerability"] == "报错回显确认注入点存在"
        assert v["expected_impact"] == "若无 WAF 可 RCE"
        assert v["confidence"] == "high"
        assert v["cwe_id"] == "CWE-89"

    def test_potential_verdict_carries_downgrade_reason(self, tmp_path):
        scan = self._scan_with_finding(tmp_path)
        self._bb(scan, "injection", [{
            "vulnerability_id": "INJ-VULN-01", "status": "potential",
            "severity": "medium", "confidence": "low",
            "downgrade_reason": "缺 victim baseline 证横向越权",
            "evidence_of_vulnerability": "attacker 已达成越权访问",
        }])
        m = build_api_evidence_matrix(scan)
        v = self._mounted_verdict(m)
        assert v["severity"] == "medium"
        assert v["confidence"] == "low"
        assert v["downgrade_reason"] == "缺 victim baseline 证横向越权"
        assert v["evidence_of_vulnerability"] == "attacker 已达成越权访问"

    def test_false_positive_verdict_carries_reason_evidence_steps(self, tmp_path):
        scan = self._scan_with_finding(tmp_path)
        self._bb(scan, "injection", [{
            "vulnerability_id": "INJ-VULN-01", "status": "false_positive",
            "reason": "参数化查询无拼接", "evidence": "repos.go:42 占位符绑定",
            "exploitation_steps": [{"action": "注入单引号",
                                    "command": "curl '?q=1%27",
                                    "result": "被参数化吞掉"}],
        }])
        m = build_api_evidence_matrix(scan)
        v = self._mounted_verdict(m)
        assert v["reason"] == "参数化查询无拼接"
        assert v["evidence"] == "repos.go:42 占位符绑定"
        assert all(isinstance(s, str) for s in v["exploitation_steps"])
        assert "注入单引号" in v["exploitation_steps"][0]
        assert "被参数化吞掉" in v["exploitation_steps"][0]

    def test_out_of_scope_verdict_carries_reason_evidence(self, tmp_path):
        scan = self._scan_with_finding(tmp_path)
        self._bb(scan, "injection", [{
            "vulnerability_id": "INJ-VULN-01", "status": "out_of_scope_internal",
            "reason": "内网服务公网不可达", "evidence": "bind 10.254.x",
        }])
        m = build_api_evidence_matrix(scan)
        v = self._mounted_verdict(m)
        assert v["reason"] == "内网服务公网不可达"
        assert v["evidence"] == "bind 10.254.x"

    def test_exploited_still_has_steps_key_for_frontend(self, tmp_path):
        # exploited 回归 + blocked 态恒带 exploitation_steps（前端 .map 容错）
        scan = self._scan_with_finding(tmp_path)
        self._bb(scan, "injection", [
            {"vulnerability_id": "INJ-VULN-01", "status": "blocked_by_security",
             "confidence": "high", "current_blocker": "WAF",
             "what_we_tried": "x", "evidence_of_vulnerability": "y",
             "expected_impact": "z"},
        ])
        m = build_api_evidence_matrix(scan)
        v = self._mounted_verdict(m)
        assert v["exploitation_steps"] == []


class TestFindingViewRichFields:
    """证据页 v2（2026-09-16）：finding 卡富透传（非空才带）。

    `_finding_view` 此前只透传 11 字段——report_data 卡里的
    narrative/poc/problem_points/dataflow_steps/evidence 与 raw 里的
    per-class 证据字段（auth/authz 判定依据、taint 细节）全被丢掉，
    证据页「为什么有问题」只剩标题和一行链。
    """

    def test_rich_taint_finding_passes_through_evidence_blocks(self, tmp_path):
        scan = _wb_scan(tmp_path)
        _write_entry_points(scan, [_ep("POST", "/account/set-alias")])
        _write_report_data(scan, [{
            "id": "XSS-VULN-01", "type": "xss", "title": "CSV 公式注入",
            "severity": "high", "confidence": "needs_review",
            "cwe_id": "CWE-1236", "externally_exploitable": True,
            "narrative": {"cause": "无公式字符过滤", "impact": "数据外泄",
                          "remediation": "过滤 =+-@ 前缀"},
            "poc": {"curl": "curl -X POST ...", "preconditions": "登录态"},
            "problem_points": [{"location": "account.bus.go:132",
                                "description": "未过滤", "snippet": "func SetAlias()"}],
            "dataflow_steps": [{"label": "读取 req", "file": "account.bus.go",
                                "line": 129, "protection": "TrimSpace only"}],
            "evidence": {"verification": "static", "steps": [],
                         "verdict": "vulnerable"},
            "endpoints": [{"method": "POST", "path": "/account/set-alias"}],
            "raw": {"sink_call": "xlsx.NewCell", "slot_type": "body",
                    "sanitization_observed": "TrimSpace only",
                    "source_track": "llm"},
        }])
        m = build_api_evidence_matrix(scan)
        f = _find_matrix(m, "POST", "/account/set-alias")["whitebox"]["findings"][0]
        assert f["narrative"]["cause"] == "无公式字符过滤"
        assert f["poc"]["curl"] == "curl -X POST ..."
        assert f["problem_points"][0]["snippet"] == "func SetAlias()"
        assert f["dataflow_steps"][0]["line"] == 129
        assert f["evidence"]["verdict"] == "vulnerable"
        assert "cross_verification" not in f  # fixture 未提供 → 非空才带不写键
        assert f["cwe_id"] == "CWE-1236"
        assert f["externally_exploitable"] is True
        assert f["sink_call"] == "xlsx.NewCell"
        assert f["slot_type"] == "body"
        assert f["sanitization_observed"] == "TrimSpace only"
        assert f["source_track"] == "llm"

    def test_authz_finding_passes_guard_evidence(self, tmp_path):
        scan = _wb_scan(tmp_path)
        _write_entry_points(scan, [_ep("GET", "/benefits")])
        _write_report_data(scan, [{
            "id": "AUTHZ-1", "type": "authz", "title": "水平越权",
            "severity": "high", "confidence": "high",
            "endpoints": [{"method": "GET", "path": "/benefits"}],
            "raw": {"reason": "资源属主校验缺失", "guard_evidence": "无 owner 检查",
                    "role_context": "普通用户 A 访问 B 的 benefits",
                    "side_effect": "读 B 的 PII",
                    "minimal_witness": "替换 id 参数即命中",
                    "vulnerable_code_location": "benefits.js:88",
                    "source_track": "gitnexus"},
        }])
        m = build_api_evidence_matrix(scan)
        f = _find_matrix(m, "GET", "/benefits")["whitebox"]["findings"][0]
        assert f["reason"] == "资源属主校验缺失"
        assert f["guard_evidence"] == "无 owner 检查"
        assert f["role_context"] == "普通用户 A 访问 B 的 benefits"
        assert f["side_effect"] == "读 B 的 PII"
        assert f["minimal_witness"] == "替换 id 参数即命中"
        assert f["vulnerable_code_location"] == "benefits.js:88"
        assert f["source_track"] == "gitnexus"

    def test_auth_finding_passes_missing_defense(self, tmp_path):
        scan = _wb_scan(tmp_path)
        _write_entry_points(scan, [_ep("POST", "/login")])
        _write_report_data(scan, [{
            "id": "AUTH-1", "type": "auth", "title": "弱口令",
            "severity": "medium", "confidence": "medium",
            "endpoints": [{"method": "POST", "path": "/login"}],
            "raw": {"missing_defense": "无失败锁定",
                    "exploitation_hypothesis": "爆破常见口令",
                    "suggested_exploit_technique": "hydra",
                    "vulnerable_code_location": "auth.js:12",
                    "source_endpoint": "POST /login"},
        }])
        m = build_api_evidence_matrix(scan)
        f = _find_matrix(m, "POST", "/login")["whitebox"]["findings"][0]
        assert f["missing_defense"] == "无失败锁定"
        assert f["exploitation_hypothesis"] == "爆破常见口令"
        assert f["suggested_exploit_technique"] == "hydra"
        assert f["vulnerable_code_location"] == "auth.js:12"
        assert f["source_endpoint"] == "POST /login"

    def test_minimal_finding_omits_new_keys(self, tmp_path):
        """体积护栏：字段缺失/为空时新键一律不写（v2 非空才带）。"""
        scan = _wb_scan(tmp_path)
        _write_entry_points(scan, [_ep("GET", "/data")])
        _write_report_data(scan, [
            _vuln("X-1", "xss", [{"method": "GET", "path": "/data"}]),
        ])
        m = build_api_evidence_matrix(scan)
        f = _find_matrix(m, "GET", "/data")["whitebox"]["findings"][0]
        for key in ("narrative", "poc", "problem_points", "dataflow_steps",
                    "evidence", "cross_verification", "cwe_id",
                    "externally_exploitable", "sink_call", "slot_type",
                    "reason", "guard_evidence", "missing_defense",
                    "source_track"):
            assert key not in f, f"空字段 {key} 不应写入矩阵"
        assert f["params"] == []  # 前端 f.params.length 依赖，恒有


class TestUnmatchedFirstClass:
    """证据页 v2（2026-09-16）：unmatched 一等公民化。

    此前 unmatched findings 只留 {id, vuln_class, title, reason}——Go/RPC
    项目底册无 route 行（实测金融平台 104 条全 null）时全部 finding 落
    unmatched，证据页只剩标题黑洞；note 也只在底册整体缺失时产出，
    RPC 项目右侧落到「选择左侧接口查看证据」误导空态。
    """

    def _go_scan(self, tmp_path):
        """Go/RPC 型扫描：底册 entry 全无 route（grpc_service）。"""
        scan = _wb_scan(tmp_path)
        _write_entry_points(scan, [
            {"func_block_id": "account.bus.go:List:31", "verdict": "needs_review",
             "entry_type": "grpc_service", "route": None, "http_method": None,
             "evidence": "Signature includes context.Context",
             "source": "code_index"},
        ])
        return scan

    def test_go_rpc_findings_unmatched_with_full_view_and_note(self, tmp_path):
        scan = self._go_scan(tmp_path)
        _write_report_data(scan, [{
            "id": "XSS-VULN-01", "type": "xss", "title": "CSV 公式注入",
            "severity": "high", "confidence": "needs_review",
            "narrative": {"cause": "无过滤"},
            "poc": {"curl": "curl ..."},
            "problem_points": [{"location": "a.go:132", "description": "x"}],
            "endpoints": [{"method": "POST", "path": "/account/set-alias"}],
        }])
        m = build_api_evidence_matrix(scan)
        assert m["endpoints"] == []
        assert "无 HTTP route" in m["note"]
        um = m["unmatched"]["findings"][0]
        assert um["id"] == "XSS-VULN-01"
        assert um["reason"] == "no-route-entries"
        assert um["narrative"]["cause"] == "无过滤"
        assert um["poc"]["curl"] == "curl ..."
        assert um["problem_points"][0]["location"] == "a.go:132"
        assert um["declared_endpoints"] == [
            {"method": "POST", "path": "/account/set-alias"}]

    def test_unmatched_finding_without_rows_is_no_endpoint_rows(self, tmp_path):
        scan = _wb_scan(tmp_path)
        _write_entry_points(scan, [_ep("GET", "/other")])
        _write_report_data(scan, [_vuln("X-1", "xss", [])])
        m = build_api_evidence_matrix(scan)
        assert m["unmatched"]["findings"][0]["reason"] == "no-endpoint-rows"

    def test_unmatched_finding_all_miss_is_no_endpoint_match(self, tmp_path):
        scan = _wb_scan(tmp_path)
        _write_entry_points(scan, [_ep("GET", "/other")])
        _write_report_data(scan, [
            _vuln("X-1", "xss", [{"method": "GET", "path": "/nowhere"}]),
        ])
        m = build_api_evidence_matrix(scan)
        assert m["unmatched"]["findings"][0]["reason"] == "no-endpoint-match"
        assert "declared_endpoints" not in m["unmatched"]["findings"][0] or \
            m["unmatched"]["findings"][0]["declared_endpoints"] == [
                {"method": "GET", "path": "/nowhere"}]

    def test_unmatched_ambiguous_precise_reason(self, tmp_path):
        scan = _wb_scan(tmp_path)
        _write_entry_points(scan, [_ep("GET", "/data"), _ep("GET", "/data/", block="f:2")])
        _write_report_data(scan, [
            _vuln("X-1", "xss", [{"method": "GET", "path": "/data"}]),
        ])
        m = build_api_evidence_matrix(scan)
        assert m["unmatched"]["findings"][0]["reason"] == "ambiguous"

    def test_blocked_verdict_unmatched_carries_blocker(self, tmp_path):
        scan = self._go_scan(tmp_path)
        _write_report_data(scan, [])  # 无 finding → verdict 无锚落 unmatched
        bb = scan / "blackbox-runs" / "run-1" / \
            "deliverables" / "blackbox" / "intermediate"
        bb.mkdir(parents=True)
        (bb / "injection_exploit_verdicts.json").write_text(json.dumps({
            "vuln_class": "injection",
            "verdicts": [{"vulnerability_id": "INJ-9",
                          "status": "blocked_by_security", "confidence": "high",
                          "current_blocker": "WAF 拦截", "what_we_tried": "编码绕过",
                          "evidence_of_vulnerability": "报错回显",
                          "expected_impact": "RCE"}],
        }))
        m = build_api_evidence_matrix(scan)
        uv = m["unmatched"]["verdicts"][0]
        assert uv["status"] == "blocked_by_security"
        assert uv["current_blocker"] == "WAF 拦截"
        assert uv["evidence_of_vulnerability"] == "报错回显"

    def test_unmatched_rejected_keeps_id_and_reason(self, tmp_path):
        scan = self._go_scan(tmp_path)
        _write_report_data(scan, [])
        bb = scan / "blackbox-runs" / "run-1" / \
            "deliverables" / "blackbox" / "intermediate"
        bb.mkdir(parents=True)
        (bb / "xss_exploit_verdicts.json").write_text(json.dumps({
            "vuln_class": "xss",
            "rejected": [{"id": "XSS-7", "reason": "L3 id 不在 queue"}],
        }))
        m = build_api_evidence_matrix(scan)
        ur = [v for v in m["unmatched"]["verdicts"]
              if v.get("kind") == "rejected"][0]
        assert ur["vulnerability_id"] == "XSS-7"  # 旧代码取 vulnerability_id 恒 None
        assert ur["reason"] == "L3 id 不在 queue"

    def test_dismissed_unmatched_carries_evidence_and_track(self, tmp_path):
        scan = _wb_scan(tmp_path)
        _write_entry_points(scan, [_ep("GET", "/profile")])
        _write_report_data(scan, [])
        wb = scan / "deliverables" / "whitebox" / "intermediate"
        (wb / "dismissed_findings.json").write_text(json.dumps({
            "dismissed": [{"ID": "INJ-LLM-SAFE-1", "source_track": "llm",
                           "vuln_class": "injection", "title": "无接口的驳回",
                           "dismiss_reason": "参数化查询",
                           "evidence": "repos.go:42,164", "confidence": "high",
                           "source": "AddQuery map", "sink_call": "db.Query",
                           "dismissed_at_stage": "llm-exploration"}],
        }))
        m = build_api_evidence_matrix(scan)
        um = [d for d in m["unmatched"]["safe_dismissed"]
              if d.get("kind") == "dismissed"][0]
        assert um["evidence"] == "repos.go:42,164"
        assert um["confidence"] == "high"
        assert um["source_track"] == "llm"
        assert um["sink_call"] == "db.Query"
        assert um["source"] == "AddQuery map"
