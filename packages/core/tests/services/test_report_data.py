"""T1（spec 2026-08-26-report-generation-agent-design §4）：report_data schema。

ReportData 是三轨统一的报告 SSOT——组装（build_report_data）产 JSON，
md 导出与前端渲染都吃它。schema 骨架测试先行。
"""
import pytest


def test_report_vulnerability_minimal_fields():
    from supernova_core.models.report_data import (
        ReportVulnerability,
    )
    vuln = ReportVulnerability(
        id="XSS-VULN-01", type="xss", vulnerability_type="Stored",
        title="t", severity="high", merge_source="llm-only",
        externally_exploitable=True,
    )
    assert vuln.id == "XSS-VULN-01"
    assert vuln.merge_source == "llm-only"
    # 未提供的结构化字段缺省为 None / 空列表，不炸
    assert vuln.merged_from == []
    assert vuln.endpoints == []
    assert vuln.poc is None
    assert vuln.problem_points == []


def test_report_vulnerability_requires_id_and_type():
    from supernova_core.models.report_data import (
        ReportVulnerability,
    )
    with pytest.raises(Exception):
        ReportVulnerability(
            vulnerability_type="Stored", title="t", severity="high",
        )
    with pytest.raises(Exception):
        ReportVulnerability(id="XSS-VULN-01", title="t", severity="high")


def test_report_data_top_level_shape():
    from supernova_core.models.report_data import ReportData, ScanMeta
    rd = ReportData(
        scan=ScanMeta(id="NodeGoat-1", track="whitebox"),
        vulnerabilities=[],
    )
    assert rd.schema_version == 1
    assert rd.executive_summary is None  # ④ agent 产物，组装时可缺省
    assert rd.qa is None  # ⑤ agent 产物
    assert rd.vulnerabilities == []
    assert rd.quick_reference == []  # 速查表行（spec 单源化 §5）缺省空


def test_quick_reference_row_model():
    """QuickReferenceRow（spec 2026-08-26-report-single-source-rendering §5）：
    速查表 schema——builder 确定性产，前端与 md 只渲染不派生。"""
    from supernova_core.models.report_data import QuickReferenceRow
    row = QuickReferenceRow(
        id="XSS-VULN-01", title="存储型 XSS：POST /memos",
        params=["memo (body)"],
        endpoints=["POST /memos (write, isLoggedIn)"],
        severity="high", verification="静态分析", confidence="待复核")
    assert row.id == "XSS-VULN-01"
    assert row.params == ["memo (body)"]
    # 最小行：仅 id 必填（title 等缺省容忍——渲染层跳空段）
    minimal = QuickReferenceRow(id="AUTH-VULN-01")
    assert minimal.title is None
    assert minimal.params == []


# ---------- T1 组装器（report_data_builder）----------

async def _write_queue(deliverables, name, vulnerabilities):
    import json
    deliverables.mkdir(parents=True, exist_ok=True)
    (deliverables / name).write_text(
        json.dumps({"vulnerabilities": vulnerabilities}, ensure_ascii=False),
        encoding="utf-8")


async def test_build_report_data_maps_queue_fields(tmp_path):
    from supernova_core.services.report_data_builder import build_report_data
    from supernova_core.models.report_data import ScanMeta

    d = tmp_path / "deliverables"
    await _write_queue(d, "xss_exploitation_queue.json", [{
        "ID": "XSS-VULN-01", "vulnerability_type": "Stored",
        "externally_exploitable": True, "confidence": "needs_review",
        "merge_source": "llm-only",
        "title": "存储型 XSS：POST /memos",
        "severity": "high", "cwe_id": "CWE-79",
        "notes": "路由为 isLoggedIn", "impact": "窃取会话", "remediation": "DOMPurify",
        "endpoints": ["POST /memos (write, isLoggedIn)", "GET /memos (trigger)"],
        "affected_parameters": ["memo (body)"],
        "affected_entries": [{"parameter": "memo", "sink_location": "memos.js:11",
                              "chain_id": "", "track": "llm"}],
        "dataflow_steps": [{"label": "接收", "file": "app/routes/memos.js", "line": 11}],
        "witness_payload": "<img src=x onerror=alert(1)>",
        "verdict": "vulnerable", "verification": "static_analysis",
        "authentication_required": "true",
    }])

    rd = await build_report_data(d, ScanMeta(id="s1", track="whitebox"))

    assert len(rd.vulnerabilities) == 1
    v = rd.vulnerabilities[0]
    assert v.id == "XSS-VULN-01"
    assert v.type == "xss"
    assert v.severity == "high"
    assert v.narrative is not None
    assert v.narrative.cause == "路由为 isLoggedIn"
    assert v.narrative.impact == "窃取会话"
    assert v.narrative.remediation == "DOMPurify"
    # endpoints 串 → 结构化
    assert [e.path for e in v.endpoints] == ["/memos", "/memos"]
    assert v.endpoints[0].method == "POST"
    assert v.endpoints[0].role == "write"
    assert v.endpoints[0].auth == "isLoggedIn"
    assert v.endpoints[1].method == "GET"
    assert v.endpoints[1].role == "trigger"
    # poc/evidence
    assert v.poc is not None and v.poc.witness_payload == "<img src=x onerror=alert(1)>"
    assert v.evidence is not None
    assert v.evidence.verification == "static"
    assert v.evidence.verdict == "vulnerable"
    # raw 保留原始 entry（md 导出复用 render_vuln_card）
    assert v.raw is not None and v.raw["ID"] == "XSS-VULN-01"


async def test_build_report_data_uses_security_argument_not_notes(tmp_path):
    """Scope/uncertainty notes must not replace the argument for a finding."""
    from supernova_core.services.report_data_builder import build_report_data
    from supernova_core.models.report_data import ScanMeta

    d = tmp_path / "deliverables"
    await _write_queue(d, "authz_exploitation_queue.json", [{
        "ID": "AUTHZ-VULN-01", "vulnerability_type": "Horizontal",
        "externally_exploitable": True, "confidence": "medium",
        "title": "申请记录 IDOR", "severity": "high",
        "notes": "下游服务是否还有兜底校验尚不可见。",
        "reason": "applicationId 由客户端控制，查询路径没有将其与当前用户归属绑定。",
        "guard_evidence": "仅校验请求中的 accountId，没有校验申请记录归属。",
    }])

    rd = await build_report_data(d, ScanMeta(id="s1", track="whitebox"))
    assert rd.vulnerabilities[0].narrative.cause == (
        "applicationId 由客户端控制，查询路径没有将其与当前用户归属绑定。")


async def test_build_report_data_problem_points_passthrough(tmp_path):
    """report_problem_points（问题点富化写回）→ problem_points 透传；畸形条目丢弃。"""
    from supernova_core.services.report_data_builder import build_report_data
    from supernova_core.models.report_data import ScanMeta

    d = tmp_path / "deliverables"
    await _write_queue(d, "xss_exploitation_queue.json", [
        {
            "ID": "XSS-VULN-01", "vulnerability_type": "Stored",
            "severity": "high", "confidence": "high",
            "externally_exploitable": True,
            "report_problem_points": [
                {"location": "app/views/memos.html:31",
                 "description": "memo 未经消毒进入模板渲染",
                 "snippet": "<div><%- memo %></div>"},
                {"description": "缺 location 的畸形条目"},
                {"location": "   "},
            ],
        },
        {
            "ID": "XSS-VULN-02", "vulnerability_type": "Reflected",
            "severity": "high", "confidence": "high",
            "externally_exploitable": True,
        },
    ])
    rd = await build_report_data(d, ScanMeta(id="s1", track="whitebox"))
    by_id = {v.id: v for v in rd.vulnerabilities}
    pp = by_id["XSS-VULN-01"].problem_points
    assert len(pp) == 1
    assert pp[0].location == "app/views/memos.html:31"
    assert pp[0].description == "memo 未经消毒进入模板渲染"
    assert pp[0].snippet == "<div><%- memo %></div>"
    # 无写回字段的卡缺省空列表（GN/黑盒卡降级路径）
    assert by_id["XSS-VULN-02"].problem_points == []


async def test_build_report_data_endpoint_fallback(tmp_path):
    """无 endpoints 列表时从 endpoint/path 兜底（GN 卡路径）。"""
    from supernova_core.services.report_data_builder import build_report_data
    from supernova_core.models.report_data import ScanMeta

    d = tmp_path / "deliverables"
    await _write_queue(d, "injection_exploitation_queue.json", [{
        "ID": "INJ-GN-01", "vulnerability_type": "Code Injection",
        "externally_exploitable": True, "confidence": "low",
        "merge_source": "gitnexus-only",
        "endpoint": None,
        "path": "preTax -> app/routes/contributions.js:ContributionsHandler:eval:32:23 (llm-pass-failed, needs_review)",
        "sink_call": "app/routes/contributions.js:ContributionsHandler:eval:32:23",
    }])
    rd = await build_report_data(d, ScanMeta(id="s1", track="whitebox"))
    v = rd.vulnerabilities[0]
    # path 提取不出 METHOD /route 时 endpoints 允许为空（T3 富化补）
    assert v.type == "injection"
    # affected_entries 无 → 空；sink 信息在 raw 里保留
    assert v.raw is not None and v.raw["sink_call"].startswith("app/routes/contributions.js")


async def test_build_report_data_stats_aggregation(tmp_path):
    from supernova_core.services.report_data_builder import build_report_data
    from supernova_core.models.report_data import ScanMeta

    d = tmp_path / "deliverables"
    await _write_queue(d, "xss_exploitation_queue.json", [
        {"ID": "XSS-VULN-01", "vulnerability_type": "Stored",
         "externally_exploitable": True, "confidence": "high", "severity": "high"},
        {"ID": "XSS-GN-01", "vulnerability_type": "Reflected",
         "externally_exploitable": True, "confidence": "low"},
    ])
    await _write_queue(d, "ssrf_exploitation_queue.json", [
        {"ID": "SSRF-VULN-01", "vulnerability_type": "SSRF",
         "externally_exploitable": False, "confidence": "high", "severity": "critical"},
    ])
    rd = await build_report_data(d, ScanMeta(id="s1", track="whitebox"))
    assert rd.stats is not None
    assert rd.stats.by_type["xss"].count == 2
    assert rd.stats.by_type["ssrf"].count == 1
    assert rd.stats.by_type["xss"].severity_range == "high"
    # severity 缺省走 effective_severity 兜底
    assert rd.stats.by_severity["critical"] == 1
    assert "high" in rd.stats.by_severity


async def test_build_report_data_skips_safe_verdict_cards(tmp_path):
    """终末防线（spec 2026-08-27 §4）：verdict=safe（authz GN judge/explore 判
    非漏洞现行契约值）/ not_vulnerable（旧枚举）卡不进报告；needs_review /
    verdict 缺失保守保留。写入侧分流（split_dismissed / _split_authz_safe）
    是主修复，此处兜 SSOT 已带的 safe 卡（如旧 session 重跑报告）。"""
    from supernova_core.services.report_data_builder import build_report_data
    from supernova_core.models.report_data import ScanMeta

    d = tmp_path / "deliverables"
    await _write_queue(d, "authz_exploitation_queue.json", [
        {"ID": "AUTHZ-GN-EXPLORE-01", "vulnerability_type": "Horizontal",
         "externally_exploitable": True, "confidence": "needs_review",
         "merge_source": "gitnexus-only", "severity": "high",
         "verdict": "safe"},
        {"ID": "AUTHZ-GN-EXPLORE-02", "vulnerability_type": "Horizontal",
         "externally_exploitable": True, "confidence": "needs_review",
         "merge_source": "gitnexus-only", "severity": "high",
         "verdict": "not_vulnerable"},
        {"ID": "AUTHZ-VULN-01", "vulnerability_type": "Horizontal",
         "externally_exploitable": True, "confidence": "needs_review",
         "merge_source": "llm-only", "severity": "medium"},
    ])
    rd = await build_report_data(d, ScanMeta(id="s1", track="whitebox"))
    ids = [v.id for v in rd.vulnerabilities]
    assert ids == ["AUTHZ-VULN-01"]


async def test_build_report_data_quick_reference(tmp_path):
    """quick_reference（spec 单源化 §5）：builder 确定性产行——口径复用
    report_assembler 速查表单元格函数；行序=类序（CLASS_CONFIG）+类内
    severity 降序（对齐 render_summary_table）。"""
    from supernova_core.services.report_data_builder import build_report_data
    from supernova_core.models.report_data import ScanMeta

    d = tmp_path / "deliverables"
    await _write_queue(d, "xss_exploitation_queue.json", [
        {  # 类内 severity 高的排前（低卡在后）
            "ID": "XSS-VULN-01", "vulnerability_type": "Stored",
            "externally_exploitable": True, "confidence": "needs_review",
            "title": "存储型 XSS：POST /memos", "severity": "high",
            "endpoints": ["POST /memos (write, isLoggedIn)"],
            "affected_parameters": ["memo (body)"],
            "verification": "static_analysis",
        },
        {  # title 缺省回退 _type_title；endpoints 空时 endpoint/path 兜底归一化
            "ID": "XSS-GN-01", "vulnerability_type": "Reflected",
            "externally_exploitable": True, "confidence": "high",
            "severity": "low",
            "endpoint": "POST /profile → app/routes/profile.js:31",
        },
    ])
    await _write_queue(d, "ssrf_exploitation_queue.json", [
        {"ID": "SSRF-VULN-01", "vulnerability_type": "SSRF",
         "externally_exploitable": True, "confidence": "high",
         "severity": "critical", "endpoints": ["/fetch"],
         "verification": "dynamically_verified"},
    ])
    rd = await build_report_data(d, ScanMeta(id="s1", track="whitebox"))

    assert len(rd.quick_reference) == 3  # 行数 = 卡数
    # 行序：xss 类（CLASS_CONFIG 序）先于 ssrf；类内 severity 降序
    assert [r.id for r in rd.quick_reference] == [
        "XSS-VULN-01", "XSS-GN-01", "SSRF-VULN-01"]
    r1 = rd.quick_reference[0]
    assert r1.title == "存储型 XSS：POST /memos"
    assert r1.params == ["memo (body)"]
    assert r1.endpoints == ["POST /memos (write, isLoggedIn)"]
    assert r1.severity == "高危"         # _severity_cell zh 映射（SEVERITY_ZH）
    assert r1.verification == "静态分析"
    assert r1.confidence == "待复核"     # needs_review → 待复核
    r2 = rd.quick_reference[1]
    assert r2.title == "reflected"       # title 缺省回退 _type_title
    assert r2.endpoints == ["POST /profile"]  # endpoint 归一化（剥 GN 尾巴）
    assert r2.confidence == "高"
    r3 = rd.quick_reference[2]
    assert r3.verification == "已动态验证"


async def test_build_report_data_quick_reference_report_endpoints(tmp_path):
    """GN-only 卡速查表行（双轨对齐）：endpoints/affected_parameters 全空、path 是
    数据流摘要时，endpoints/params 从 report_endpoints（②富化写回）派生——
    渗透者速查表要的是 HTTP 路由（GET /research）而非内部数据流文本。"""
    from supernova_core.services.report_data_builder import build_report_data
    from supernova_core.models.report_data import ScanMeta

    d = tmp_path / "deliverables"
    await _write_queue(d, "ssrf_exploitation_queue.json", [
        {"ID": "SSRF-GN-01", "vulnerability_type": "SSRF",
         "externally_exploitable": True, "confidence": "unadjudicated",
         "merge_source": "gitnexus-only", "title": "SSRF /research", "severity": "high",
         "path": "symbol -> app/routes/research.js:ResearchHandler:get:16:19 (needs_review)",
         "report_endpoints": [
             {"method": "GET", "path": "/research", "role": "trigger",
              "auth": "isLoggedIn", "params": ["url (query)", "symbol (query)"]}],
         },
    ])
    rd = await build_report_data(d, ScanMeta(id="s1", track="whitebox"))

    row = rd.quick_reference[0]
    assert row.endpoints == ["GET /research (isLoggedIn)"]
    assert row.params == ["url (query)", "symbol (query)"]


async def test_build_report_data_endpoint_params_backfill(tmp_path):
    """确定性路径 params/行号链回填（spec 单源化 §5）：无 report_endpoints
    富化时 params ← affected_parameters（去重保序）、行号链 ← affected_entries
    兜底；富化路径不被覆写。"""
    from supernova_core.services.report_data_builder import build_report_data
    from supernova_core.models.report_data import ScanMeta

    d = tmp_path / "deliverables"
    await _write_queue(d, "xss_exploitation_queue.json", [
        {  # 确定性路径：串解析 + affected_* 回填
            "ID": "XSS-VULN-01", "vulnerability_type": "Stored",
            "externally_exploitable": True, "confidence": "high",
            "severity": "high",
            "endpoints": ["POST /memos (write, isLoggedIn)", "GET /memos (trigger)"],
            "affected_parameters": ["memo (body)", "memo (body)", "userId (query)"],
            "affected_entries": [{
                "parameter": "memo", "sink_location": "memos.js:11",
                "source_location": "app.js:5", "route_registered_at": "routes.js:20",
                "chain_id": "c1", "track": "llm"}],
        },
        {  # 富化路径：report_endpoints 自带字段，不被 affected_* 覆写
            "ID": "XSS-VULN-02", "vulnerability_type": "Reflected",
            "externally_exploitable": True, "confidence": "high",
            "severity": "high",
            "endpoints": ["GET /q"],
            "affected_parameters": ["q"],
            "affected_entries": [{"parameter": "q", "sink_location": "q.js:1"}],
            "report_endpoints": [
                {"path": "/search", "method": "GET", "params": ["keyword"]}],
        },
    ])
    rd = await build_report_data(d, ScanMeta(id="s1", track="whitebox"))
    by_id = {v.id: v for v in rd.vulnerabilities}

    e1 = by_id["XSS-VULN-01"].endpoints
    assert len(e1) == 2
    # params ← affected_parameters 去重保序（两个接口串共享卡级参数集）
    assert e1[0].params == ["memo (body)", "userId (query)"]
    assert e1[1].params == ["memo (body)", "userId (query)"]
    # 行号链 ← affected_entries 兜底
    assert e1[0].sink_location == "memos.js:11"
    assert e1[0].source_location == "app.js:5"
    assert e1[0].route_registered_at == "routes.js:20"

    # 富化路径不动：report_endpoints 的 params 保持富化值
    e2 = by_id["XSS-VULN-02"].endpoints
    assert [e.path for e in e2] == ["/search"]
    assert e2[0].params == ["keyword"]
    assert e2[0].sink_location is None  # 富化条目没写的行号不被覆写


async def test_build_report_data_auth_problem_points_fallback(tmp_path):
    """auth/authz 卡 problem_points 确定性兜底（spec 单源化 §5）：这类不走
    endpoint_enrichment 富化——location ← findings_renderer 位置回退链
    （_card_loc/_card_sink），snippet ← queue code_snippet 透传；taint 卡
    无写回时仍为空（兜底只限 auth/authz）。"""
    from supernova_core.services.report_data_builder import build_report_data
    from supernova_core.models.report_data import ScanMeta

    d = tmp_path / "deliverables"
    await _write_queue(d, "auth_exploitation_queue.json", [
        {  # vulnerable_code_location 命中回退链
            "ID": "AUTH-VULN-01", "vulnerability_type": "Session",
            "externally_exploitable": True, "confidence": "high",
            "severity": "high",
            "vulnerable_code_location": "app/routes/sessions.js:42",
            "code_snippet": "res.cookie('sessionId', token, { httpOnly: false })",
        },
        {  # 无任何位置字段 → 不产兜底条目（location 必填）
            "ID": "AUTH-VULN-02", "vulnerability_type": "JWT",
            "externally_exploitable": True, "confidence": "high",
            "severity": "medium",
        },
    ])
    await _write_queue(d, "xss_exploitation_queue.json", [
        {  # taint 卡有 code_snippet 但无写回 → 不兜底（走 endpoint_enrichment）
            "ID": "XSS-VULN-01", "vulnerability_type": "Stored",
            "externally_exploitable": True, "confidence": "high",
            "severity": "high",
            "vulnerable_code_location": "app/views/memos.html:31",
            "code_snippet": "<div><%- memo %></div>",
        },
    ])
    rd = await build_report_data(d, ScanMeta(id="s1", track="whitebox"))
    by_id = {v.id: v for v in rd.vulnerabilities}

    pp = by_id["AUTH-VULN-01"].problem_points
    assert len(pp) == 1
    assert pp[0].location == "app/routes/sessions.js:42"
    assert pp[0].snippet == "res.cookie('sessionId', token, { httpOnly: false })"
    assert pp[0].description is None  # 确定性路径无说明——渲染层只渲染位置+片段

    assert by_id["AUTH-VULN-02"].problem_points == []  # 无位置不产
    assert by_id["XSS-VULN-01"].problem_points == []   # taint 卡不兜底


async def test_build_report_data_key_findings(tmp_path):
    """by_type.key_findings（spec 单源化 §5）：每类 top severity 卡（≤3 张）
    「ID 标题」串、「；」拼接，确定性产（摘要 agent 可覆写）。"""
    from supernova_core.services.report_data_builder import build_report_data
    from supernova_core.models.report_data import ScanMeta

    d = tmp_path / "deliverables"
    await _write_queue(d, "xss_exploitation_queue.json", [
        {"ID": "XSS-VULN-01", "title": "存储型 XSS", "severity": "high",
         "vulnerability_type": "Stored", "externally_exploitable": True,
         "confidence": "high"},
        {"ID": "XSS-VULN-02", "title": "反射型 XSS", "severity": "medium",
         "vulnerability_type": "Reflected", "externally_exploitable": True,
         "confidence": "high"},
        {"ID": "XSS-VULN-03", "title": "DOM XSS", "severity": "low",
         "vulnerability_type": "DOM", "externally_exploitable": True,
         "confidence": "high"},
        {"ID": "XSS-GN-04", "title": "eval 注入 XSS", "severity": "critical",
         "vulnerability_type": "Stored", "externally_exploitable": True,
         "confidence": "low"},
    ])
    rd = await build_report_data(d, ScanMeta(id="s1", track="whitebox"))
    kf = rd.stats.by_type["xss"].key_findings
    assert kf is not None
    # top3 = critical/high/medium（severity 降序，同档稳定保序），low 不入
    assert kf.startswith("XSS-GN-04 eval 注入 XSS；")
    assert "XSS-VULN-01 存储型 XSS" in kf
    assert "XSS-VULN-02 反射型 XSS" in kf
    assert "XSS-VULN-03" not in kf
    assert kf.count("；") == 2  # 3 条 → 2 个分隔


async def test_write_report_data_json(tmp_path):
    from supernova_core.services.report_data_builder import (
        build_report_data, write_report_data,
    )
    from supernova_core.models.report_data import ScanMeta

    d = tmp_path / "deliverables"
    await _write_queue(d, "xss_exploitation_queue.json", [{
        "ID": "XSS-VULN-01", "vulnerability_type": "Stored",
        "externally_exploitable": True, "confidence": "high", "title": "中文标题",
    }])
    rd = await build_report_data(d, ScanMeta(id="s1", track="whitebox"))
    out = d / "report_data.json"
    await write_report_data(rd, out)
    import json
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["schema_version"] == 1
    assert data["scan"]["id"] == "s1"
    assert data["vulnerabilities"][0]["title"] == "中文标题"  # ensure_ascii=False


async def test_build_report_data_skips_not_vulnerable(tmp_path):
    """防线（spec 2026-08-27 §4）：verdict=not_vulnerable 卡不进报告。

    主修复在 GN queue 写入侧分流（activity 层 split_dismissed）；此处是终末
    防线——旧 session 产物 / schema 回归兜底，防非漏洞卡混入报告。"""
    from supernova_core.services.report_data_builder import build_report_data
    from supernova_core.models.report_data import ScanMeta

    d = tmp_path / "deliverables"
    await _write_queue(d, "xss_exploitation_queue.json", [
        {"ID": "XSS-VULN-01", "vulnerability_type": "Stored",
         "externally_exploitable": True, "confidence": "high", "severity": "high",
         "verdict": "vulnerable"},
        {"ID": "XSS-GN-02", "vulnerability_type": "Reflected",
         "externally_exploitable": False, "confidence": "high",
         "verdict": "not_vulnerable"},
        # 拿不准/没判成保守保留（「没判成 ≠ 非漏洞」）
        {"ID": "XSS-GN-03", "vulnerability_type": "Reflected",
         "externally_exploitable": False, "confidence": "needs_review",
         "verdict": "needs_review"},
    ])
    rd = await build_report_data(d, ScanMeta(id="s1", track="whitebox"))
    ids = [v.id for v in rd.vulnerabilities]
    assert ids == ["XSS-VULN-01", "XSS-GN-03"]
    # 速查表 / 统计同步干净（同源过滤）
    assert [r.id for r in rd.quick_reference] == ids


# ---------- T1 md 导出（report_markdown_exporter）----------
# 已迁出至 test_report_markdown_exporter.py（spec 2026-08-26 单源化，
# builder 与 exporter 测试文件分离）。


async def test_build_report_data_vuln_title_fallback(tmp_path):
    """主卡片 title 缺省回退 _type_title（2026-09-03 NodeGoat 空标题回归）。

    XSS-VULN-02~07 title=None 裸落 report_data.json → 前端空标题；速查表
    （_quick_reference_row）本就有 `or _type_title(vuln)` 兜底，主卡片对齐。
    """
    from supernova_core.services.report_data_builder import build_report_data
    from supernova_core.models.report_data import ScanMeta

    d = tmp_path / "deliverables"
    await _write_queue(d, "xss_exploitation_queue.json", [
        {   # title 完全缺失 → 回退 vulnerability_type 原值
            "ID": "XSS-VULN-01", "vulnerability_type": "Reflected",
            "severity": "high", "confidence": "high",
            "externally_exploitable": True,
        },
        {   # title=None 同罪；title 有实质值的下一条不受影响
            "ID": "XSS-VULN-02", "vulnerability_type": "Stored",
            "title": None,
            "severity": "high", "confidence": "high",
            "externally_exploitable": True,
        },
        {
            "ID": "XSS-VULN-03", "vulnerability_type": "Stored",
            "title": "存储型 XSS：POST /memos",
            "severity": "high", "confidence": "high",
            "externally_exploitable": True,
        },
    ])

    rd = await build_report_data(d, ScanMeta(id="s1", track="whitebox"))
    titles = {v.id: v.title for v in rd.vulnerabilities}
    assert titles["XSS-VULN-01"] == "reflected"      # 回退 _type_title
    assert titles["XSS-VULN-02"] == "stored"         # None 同罪
    assert titles["XSS-VULN-03"] == "存储型 XSS：POST /memos"  # 实质值不动


# ---------- MR 增量段（spec 2026-09-03 §6）----------

def _write_mr_products(d, manifest_dict=None, protections=None, scope=None):
    """写 intermediate/mr/ 产物（incremental_scope.json 缺省不写 = 非 MR 扫描）。"""
    import json
    mr_dir = d / "intermediate" / "mr"
    mr_dir.mkdir(parents=True, exist_ok=True)
    if manifest_dict is not None:
        (mr_dir / "diff_manifest.json").write_text(
            json.dumps(manifest_dict, ensure_ascii=False), encoding="utf-8")
    if protections is not None:
        (mr_dir / "removed_protections.json").write_text(
            json.dumps(protections, ensure_ascii=False), encoding="utf-8")
    if scope is not None:
        (mr_dir / "incremental_scope.json").write_text(
            json.dumps(scope, ensure_ascii=False), encoding="utf-8")


async def test_build_report_data_mr_incremental_summary_and_trigger_source(tmp_path):
    """MR 扫描：scan 补 base/head/diff_stat + 顶层 incremental_summary +
    GN 轨卡（both/gitnexus-only）按 flow_id 反查标 trigger_source；LLM-only 不标。"""
    from supernova_core.services.report_data_builder import build_report_data
    from supernova_core.models.report_data import ScanMeta
    import json

    d = tmp_path / "deliverables"
    await _write_queue(d, "xss_exploitation_queue.json", [
        {   # 双轨合并卡（GN flow fa 命中来源 A）→ 标 new_code
            "ID": "XSS-VULN-01", "vulnerability_type": "Reflected",
            "externally_exploitable": True, "confidence": "high",
            "merge_source": "both", "flow_id": "fa",
            "verdict": "vulnerable", "severity": "high",
        },
        {   # LLM-only 卡（即使带 flow_id 也不标——只标 GN 轨可归因发现）
            "ID": "XSS-VULN-02", "vulnerability_type": "Stored",
            "externally_exploitable": True, "confidence": "high",
            "merge_source": "llm-only", "flow_id": "fz",
            "verdict": "vulnerable", "severity": "high",
        },
    ])
    _write_mr_products(
        d,
        manifest_dict={
            "base_commit": "b1", "head_commit": "h1", "hunks": [],
            "stats": {"files": 2, "insertions": 10, "deletions": 3},
        },
        protections={
            "degraded": False,
            "protections": [{
                "file_path": "app/utils.js", "base_line_no": 42,
                "removed_text": "q = sanitize(q)", "function_name": "sanitize_input",
                "protection_kind": "sanitize", "rationale": "escapes",
                "confidence": 0.9,
            }],
        },
        scope={
            "selected_vuln_classes": ["xss"],
            "new_entry_point_ids": ["app/routes.js:handler:10"],
            "verdict_flow_ids": ["fa", "fb", "fc1"],
            "removed_protection_flows": [{
                "protection": {
                    "file_path": "app/utils.js", "base_line_no": 42,
                    "removed_text": "q = sanitize(q)",
                    "function_name": "sanitize_input",
                    "protection_kind": "sanitize", "rationale": "escapes",
                    "confidence": 0.9,
                },
                "func_block_id": "app/utils.js:sanitize_input:40",
                "flow_ids": ["fc1"],
            }],
            "source_a_flow_ids": ["fa"],
            "source_b_flow_ids": ["fb"],
            "source_c_flow_ids": ["fc1"],
        },
    )
    # code_index.json：new_entry_point join 路由明细用
    (d / "intermediate").mkdir(exist_ok=True)
    (d / "intermediate" / "code_index.json").write_text(
        json.dumps({
            "repository": "r", "language": "javascript",
            "total_blocks": 1, "total_entry_points": 1, "total_chains": 0,
            "blocks": [], "edges": [], "chains": [],
            "sink_call_sites": [], "source_points": [],
            "entry_points": [{
                "func_block_id": "app/routes.js:handler:10",
                "entry_type": "http_route", "route": "/memos",
                "http_method": "POST", "confidence": 1.0, "evidence": "e",
                "needs_llm_review": False,
            }],
        }, ensure_ascii=False), encoding="utf-8")

    rd = await build_report_data(d, ScanMeta(id="s1", track="whitebox"))

    # scan MR 元信息（builder 内部从 intermediate/mr/ 补，调用方零改动）
    assert rd.scan.base_commit == "b1"
    assert rd.scan.head_commit == "h1"
    assert rd.scan.diff_stat == {"files": 2, "insertions": 10, "deletions": 3}
    # 顶层增量摘要
    assert rd.incremental_summary is not None
    inc = rd.incremental_summary
    assert inc.degraded is False
    assert inc.new_entry_points[0].route == "/memos"
    assert inc.new_entry_points[0].method == "POST"
    assert inc.removed_protections[0].function == "sanitize_input"
    assert inc.removed_protections[0].followed_by_chains is True
    assert inc.flow_counts == {"new_code": 1, "new_entry": 1,
                               "removed_protection": 1, "affected_flows": 3}
    # trigger_source：GN 合并卡标 / LLM-only 卡不标
    by_id = {v.id: v for v in rd.vulnerabilities}
    assert by_id["XSS-VULN-01"].trigger_source == "new_code"
    assert by_id["XSS-VULN-02"].trigger_source is None


async def test_build_report_data_mr_degraded_and_unfollowed_protection(tmp_path):
    """删防护判定降级标注；函数被删（无 flow）→ followed_by_chains=False 供人审。"""
    from supernova_core.services.report_data_builder import build_report_data
    from supernova_core.models.report_data import ScanMeta

    d = tmp_path / "deliverables"
    _write_mr_products(
        d,
        protections={"degraded": True, "protections": []},
        scope={
            "selected_vuln_classes": [], "new_entry_point_ids": [],
            "verdict_flow_ids": [], "removed_protection_flows": [{
                "protection": {
                    "file_path": "app/gone.js", "base_line_no": 3,
                    "removed_text": "@login_required", "function_name": None,
                    "protection_kind": "authz_check",
                },
                "func_block_id": None, "flow_ids": [],
            }],
            "source_a_flow_ids": [], "source_b_flow_ids": [],
            "source_c_flow_ids": [],
        },
    )

    rd = await build_report_data(d, ScanMeta(id="s1", track="whitebox"))

    assert rd.incremental_summary is not None
    assert rd.incremental_summary.degraded is True
    assert rd.incremental_summary.removed_protections[0].followed_by_chains is False


async def test_build_report_data_non_mr_zero_regression(tmp_path):
    """非 MR 扫描（无 intermediate/mr/）：incremental_summary=None、scan 无 MR 字段。"""
    from supernova_core.services.report_data_builder import build_report_data
    from supernova_core.models.report_data import ScanMeta

    d = tmp_path / "deliverables"
    await _write_queue(d, "xss_exploitation_queue.json", [
        {"ID": "XSS-VULN-01", "vulnerability_type": "Stored",
         "externally_exploitable": True, "confidence": "high",
         "merge_source": "llm-only", "flow_id": "fa",
         "verdict": "vulnerable", "severity": "high"},
    ])

    rd = await build_report_data(d, ScanMeta(id="s1", track="whitebox"))

    assert rd.incremental_summary is None
    assert rd.scan.base_commit is None
    assert rd.scan.head_commit is None
    assert rd.scan.diff_stat is None
    assert rd.vulnerabilities[0].trigger_source is None
