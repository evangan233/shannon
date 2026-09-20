"""C5: correlation 详情 API（GET /api/workspaces/{ws}/scans/{scan_id}/correlation）。

组装 deliverables 四产物（topology/boundaries/flows/{vc}_exploitation_queue.json）+
correlation-report.md + session corr_children；404（scan 不存在）/422（非
correlation scan）/200+空产物（关联未跑完，前端显示进行中）语义。
产物 shape 对齐 run_correlation_phase 落盘（deliverables/ 根，无 track 桶）。
"""
import json


def _make_scan(tmp_workspaces, ws, scan_id, scan_type="correlation", status="completed",
               **extra):
    """直接在 tmp_workspaces 建 scan（不经 scan_manager.start，免 temporal）。"""
    scan_dir = tmp_workspaces / ws / "scans" / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)
    sess = {"status": status, "scan_type": scan_type, "created_at": 1780000000.0,
            "web_url": "", "repo_path": "/code", "owner": "web"}
    sess.update(extra)
    (scan_dir / "session.json").write_text(json.dumps(sess))
    return scan_dir


def _make_child_scan(tmp_workspaces, ws, scan_id, dismissed=None, bad_json=False):
    """建子仓 scan 目录（c1 的兄弟），可选落 dismissed_findings.json。"""
    child_dlv = tmp_workspaces / ws / "scans" / scan_id / "deliverables"
    (child_dlv / "whitebox" / "intermediate").mkdir(parents=True, exist_ok=True)
    if dismissed is not None or bad_json:
        text = "{not-json" if bad_json else json.dumps({"dismissed": dismissed})
        (child_dlv / "whitebox" / "intermediate" / "dismissed_findings.json").write_text(text)


def test_correlation_endpoint_assembles(authed_client, tmp_workspaces):
    """完整组装：四产物原文 + corr_children 透传 + drift_warnings 保守 []。"""
    _make_scan(tmp_workspaces, "WS", scan_id="c1", corr_children=[
        {"service": "gateway", "scan_id": "gw-1", "reused": False},
        {"service": "orders", "scan_id": "ord-1", "reused": True},
    ])
    dlv = tmp_workspaces / "WS" / "scans" / "c1" / "deliverables"
    dlv.mkdir(parents=True)
    _make_child_scan(tmp_workspaces, "WS", "gw-1", dismissed=[
        {"ID": "INJ-LLM-SAFE-01", "vuln_class": "injection", "title": "误报链",
         "dismiss_reason": "sink 不可达", "evidence": {"chain": ["a", "b"]},
         "confidence": "high", "source_track": "llm",
         "dismissed_at_stage": "llm-exploration", "source": "s", "sink_call": "k()"}])
    (dlv / "cross-service-topology.json").write_text(json.dumps({
        "services": [{"name": "gateway", "role": "frontend", "repo": "/code/gateway"}],
        "edges": [{"from": "gateway", "to": "orders", "protocol": "grpc",
                   "calls": [], "status": "ok", "error": None}]}))
    (dlv / "trust-boundaries.json").write_text(json.dumps([
        {"service": "orders", "method": "CreateOrder", "exposure": "internal",
         "reachable_from": ["gateway"], "reason": "svc 无 authz", "confidence": "high"}]))
    (dlv / "cross-service-flows.json").write_text(json.dumps({
        "flows": [
            {"edge_from": "gateway", "edge_to": "orders", "entry": "POST /api/orders",
             "method": "CreateOrder",
             "call_site": {"file": "handler.go", "line": 42, "snippet": "c.CreateOrder"},
             "vuln_refs": [{"vuln_id": "INJ-01", "service": "orders", "title": "SQLi",
                            "severity": "high", "location": "db.go:10",
                            "source": "queue"}],
             "confidence": "high", "evidence": "e"}],
        "multi_hop_chains": [
            {"path": ["gateway", "orders", "payment"], "basis": "edge-adjacency",
             "confidence": "structural"}]}))
    (dlv / "adjudication-log.json").write_text(json.dumps({"cards": [
        {"direction": "upgrade",
         "finding_ref": {"service": "orders", "vuln_id": "INJ-09", "origin": "dismissed"},
         "conclusion": "vulnerable", "cross_service_context": "via gateway",
         "analysis_process": ["s1"], "verification_evidence": [],
         "reasoning": "reachable now", "confidence": "high"},
        {"direction": "error",
         "finding_ref": {"service": "orders", "vuln_id": "INJ-10", "origin": "queue"},
         "conclusion": "needs-review", "cross_service_context": "",
         "analysis_process": [], "verification_evidence": [],
         "reasoning": "adjudication batch failed: llm down", "confidence": "low"}]}))
    (dlv / "injection_exploitation_queue.json").write_text(json.dumps(
        {"vulnerabilities": [{"ID": "INJ-01", "title": "SQLi", "service": "orders"}]}))
    (dlv / "correlation-report.md").write_text(
        "# Cross-Repo Correlation Report\n\n## 服务拓扑\n")
    r = authed_client.get("/api/workspaces/WS/scans/c1/correlation")
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["topology"]["services"][0]["name"] == "gateway"
    assert d["topology"]["edges"][0]["from"] == "gateway"
    assert d["boundaries"][0]["service"] == "orders"
    assert d["flows"][0]["method"] == "CreateOrder"
    assert d["flows"][0]["vuln_refs"][0]["service"] == "orders"
    assert d["multi_hop_chains"][0]["path"] == ["gateway", "orders", "payment"]
    # spec 2026-08-27 §9:adjudication 透传(裁决卡,error 占位卡同样透传)
    assert d["adjudication"]["cards"][0]["direction"] == "upgrade"
    assert d["adjudication"]["cards"][1]["direction"] == "error"
    assert d["merged_vulns"]["injection"][0]["service"] == "orders"
    assert "# Cross-Repo" in d["report_md"]
    assert d["corr_children"] == [
        {"service": "gateway", "scan_id": "gw-1", "reused": False},
        {"service": "orders", "scan_id": "ord-1", "reused": True}]
    assert d["drift_warnings"] == []
    # 成立/消掉视图（2026-09-18）：子仓 dismissed 投影透传（evidence 不出网）+
    # log 存在 → 裁决终态 completed
    assert len(d["dismissed"]) == 1
    item = d["dismissed"][0]
    assert item["service"] == "gateway"
    assert item["ID"] == "INJ-LLM-SAFE-01"
    assert item["dismissed_at_stage"] == "llm-exploration"
    assert "evidence" not in item
    assert d["adjudication_status"] == "completed"


def test_correlation_endpoint_legacy_list_flows_compat(authed_client, tmp_workspaces):
    """旧产物兼容：历史 scan 的 flows json 是 list 形态(2026-08-27 前)——
    flows 透传、multi_hop_chains=[]、adjudication None。"""
    _make_scan(tmp_workspaces, "WS", scan_id="c1")
    dlv = tmp_workspaces / "WS" / "scans" / "c1" / "deliverables"
    dlv.mkdir(parents=True)
    (dlv / "cross-service-flows.json").write_text(json.dumps([
        {"edge_from": "g", "edge_to": "o", "entry": "POST /x", "method": "M",
         "call_site": {"file": "f", "line": 1, "snippet": "s"},
         "vuln_refs": [], "confidence": "low", "evidence": "e"}]))
    r = authed_client.get("/api/workspaces/WS/scans/c1/correlation")
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["flows"][0]["method"] == "M"
    assert d["multi_hop_chains"] == []
    assert d["adjudication"] is None


def test_correlation_endpoint_adjudication_error_form(authed_client, tmp_workspaces):
    """阶段 B 整体异常留档形态 {"error": ...} 原样透传(spec §10)；状态推导 failed。"""
    _make_scan(tmp_workspaces, "WS", scan_id="c1")
    dlv = tmp_workspaces / "WS" / "scans" / "c1" / "deliverables"
    dlv.mkdir(parents=True)
    (dlv / "adjudication-log.json").write_text(json.dumps(
        {"error": "adjudication infra down"}))
    r = authed_client.get("/api/workspaces/WS/scans/c1/correlation")
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["adjudication"] == {"error": "adjudication infra down"}
    assert d["adjudication_status"] == "failed"


def _append_events(scan_dir, events):
    with (scan_dir / "events.ndjson").open("a", encoding="utf-8") as fh:
        for e in events:
            fh.write(json.dumps(e) + "\n")


def _adj_phase(status):
    return {"type": "correlation_progress", "node": "phase",
            "name": "adjudication", "status": status}


def test_correlation_adjudication_status_from_events(authed_client, tmp_workspaces):
    """无 log 时从 events.ndjson 尾读推导：running / failed / 最后一条优先。"""
    _make_scan(tmp_workspaces, "WS", scan_id="c1", status="running")
    scan_dir = tmp_workspaces / "WS" / "scans" / "c1"
    dlv = scan_dir / "deliverables"
    dlv.mkdir(parents=True)
    # started → running
    _append_events(scan_dir, [_adj_phase("started")])
    d = authed_client.get("/api/workspaces/WS/scans/c1/correlation").json()
    assert d["adjudication_status"] == "running"
    # completed 追加在后 → completed（取最后一条）
    _append_events(scan_dir, [_adj_phase("completed")])
    d = authed_client.get("/api/workspaces/WS/scans/c1/correlation").json()
    assert d["adjudication_status"] == "completed"
    # 再 started（重跑语义）→ running；中间隔无关事件不影响
    _append_events(scan_dir, [{"type": "scan_end", "status": "completed"},
                              _adj_phase("started")])
    d = authed_client.get("/api/workspaces/WS/scans/c1/correlation").json()
    assert d["adjudication_status"] == "running"


def test_correlation_adjudication_status_terminal_session_guard(authed_client, tmp_workspaces):
    """加固：events 说 running 但 session 已终态（被取消/中断旧扫描）→ failed，
    防前端「裁决进行中」横幅永挂。"""
    _make_scan(tmp_workspaces, "WS", scan_id="c1", status="cancelled")
    scan_dir = tmp_workspaces / "WS" / "scans" / "c1"
    (scan_dir / "deliverables").mkdir(parents=True)
    _append_events(scan_dir, [_adj_phase("started")])
    d = authed_client.get("/api/workspaces/WS/scans/c1/correlation").json()
    assert d["adjudication_status"] == "failed"


def test_correlation_dismissed_children_tolerant(authed_client, tmp_workspaces):
    """子仓 dismissed 读取容错：坏 JSON/缺文件/scan_id 含路径分隔符 → 跳过不 500，
    其余子仓照读；无任何数据 → dismissed==[]。"""
    _make_scan(tmp_workspaces, "WS", scan_id="c1", corr_children=[
        {"service": "bad", "scan_id": "bad-1", "reused": True},
        {"service": "gone", "scan_id": "gone-1", "reused": True},
        {"service": "evil", "scan_id": "../evil-1", "reused": True},
        {"service": "good", "scan_id": "good-1", "reused": True},
    ])
    _make_child_scan(tmp_workspaces, "WS", "bad-1", dismissed=[], bad_json=True)
    _make_child_scan(tmp_workspaces, "WS", "good-1", dismissed=[
        {"ID": "XSS-9", "vuln_class": "xss", "title": "t", "dismiss_reason": "r"}])
    dlv = tmp_workspaces / "WS" / "scans" / "c1" / "deliverables"
    dlv.mkdir(parents=True)
    d = authed_client.get("/api/workspaces/WS/scans/c1/correlation").json()
    assert [x["service"] for x in d["dismissed"]] == ["good"]
    assert d["dismissed"][0]["ID"] == "XSS-9"
    # 无 corr_children 的 scan：dismissed 恒 []
    _make_scan(tmp_workspaces, "WS", scan_id="c9")
    (tmp_workspaces / "WS" / "scans" / "c9" / "deliverables").mkdir(parents=True)
    d9 = authed_client.get("/api/workspaces/WS/scans/c9/correlation").json()
    assert d9["dismissed"] == []
    assert d9["adjudication_status"] is None


def test_correlation_endpoint_missing_queue_key_absent(authed_client, tmp_workspaces):
    """缺 {vc}_exploitation_queue.json -> merged_vulns 键缺席（非空数组冒充）。"""
    _make_scan(tmp_workspaces, "WS", scan_id="c2")
    dlv = tmp_workspaces / "WS" / "scans" / "c2" / "deliverables"
    dlv.mkdir(parents=True)
    (dlv / "xss_exploitation_queue.json").write_text(json.dumps(
        {"vulnerabilities": [{"ID": "XSS-01", "service": "gateway"}]}))
    d = authed_client.get("/api/workspaces/WS/scans/c2/correlation").json()
    assert set(d["merged_vulns"]) == {"xss"}


def test_correlation_endpoint_pending(authed_client, tmp_workspaces):
    """主行存在但 deliverables 空 -> 200，flows==[]、topology None（关联进行中/未开始）。"""
    _make_scan(tmp_workspaces, "WS", scan_id="c3", status="running")
    r = authed_client.get("/api/workspaces/WS/scans/c3/correlation")
    assert r.status_code == 200
    d = r.json()
    assert d["flows"] == [] and d["topology"] is None
    assert d["boundaries"] == [] and d["report_md"] is None
    assert d["merged_vulns"] == {}
    assert d["corr_children"] == []
    assert d["dismissed"] == [] and d["adjudication_status"] is None


def test_correlation_endpoint_wrong_type(authed_client, tmp_workspaces):
    """白盒 scan -> 422 {"detail": "not a correlation scan"}。"""
    _make_scan(tmp_workspaces, "WS", scan_id="w1", scan_type="whitebox")
    r = authed_client.get("/api/workspaces/WS/scans/w1/correlation")
    assert r.status_code == 422
    assert r.json()["detail"] == "not a correlation scan"


def test_correlation_endpoint_unknown_scan_404(authed_client, tmp_workspaces):
    _make_scan(tmp_workspaces, "WS", scan_id="c1")
    assert authed_client.get("/api/workspaces/WS/scans/nope/correlation").status_code == 404


def test_correlation_endpoint_drift_warnings_read(authed_client, tmp_workspaces):
    """2026-09-20 接线：drift-warnings.json 存在 → 透传；坏 JSON → 回落 []。"""
    _make_scan(tmp_workspaces, "WS", scan_id="c1")
    dlv = tmp_workspaces / "WS" / "scans" / "c1" / "deliverables"
    dlv.mkdir(parents=True)
    (dlv / "cross-service-topology.json").write_text(json.dumps({
        "services": [{"name": "gateway", "role": "frontend", "repo": "/code/gateway"}],
        "edges": []}))
    (dlv / "drift-warnings.json").write_text(json.dumps(
        ["backend/x: 复用产物,源码版本可能漂移"]))
    r = authed_client.get("/api/workspaces/WS/scans/c1/correlation")
    assert r.status_code == 200, r.text
    assert r.json()["drift_warnings"] == ["backend/x: 复用产物,源码版本可能漂移"]
    # 坏 JSON：静默回落 []（对齐本文件容错立场）
    (dlv / "drift-warnings.json").write_text("not-json")
    r2 = authed_client.get("/api/workspaces/WS/scans/c1/correlation")
    assert r2.status_code == 200
    assert r2.json()["drift_warnings"] == []
