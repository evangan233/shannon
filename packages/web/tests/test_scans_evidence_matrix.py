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


def test_evidence_matrix_stale_rebuilds_on_blackbox_verdict(authed_client, tmp_workspaces):
    """黑盒 verdicts 更新 → 缓存陈旧重建（真实布局回归）。

    blackbox-runs/ 与 deliverables/ 平级（utils/paths.blackbox_runs_dir，spec §4）：
    真实 verdicts 路径是 <scan>/blackbox-runs/run-N/deliverables/blackbox/
    intermediate/*_exploit_verdicts.json——曾误 glob 成 deliverables/blackbox-runs/
    子路径致黑盒更新永不触发重建（本测试锁死）。

    白盒源显式回拨、缓存居中、verdicts 最新：只有黑盒 verdicts 能触发陈旧。
    """
    scan_dir = _make_scan(tmp_workspaces, "w1")
    _wb_products(scan_dir, entries=[_ep("GET", "/profile")])
    past = time.time() - 7200
    os.utime(scan_dir / "deliverables" / "whitebox" / "report_data.json", (past, past))
    os.utime(scan_dir / "deliverables" / "whitebox" / "intermediate" /
             "entry_points.json", (past, past))
    cached = {"schema_version": 1, "scan_id": "s1", "cached": True, "sources": {},
              "endpoints": [], "unmatched": {}}
    out = scan_dir / "deliverables" / "api_evidence_matrix.json"
    out.write_text(json.dumps(cached))  # 比白盒源新 → 白盒源不触发
    os.utime(out, (time.time() - 3600,) * 2)
    vd = scan_dir / "blackbox-runs" / "run-1" / "deliverables" / "blackbox" / "intermediate"
    vd.mkdir(parents=True)
    (vd / "injection_exploit_verdicts.json").write_text(json.dumps(
        {"vuln_class": "injection", "verdicts": []}))  # 最新 mtime
    r = authed_client.get("/api/workspaces/w1/scans/s1/evidence-matrix")
    assert r.status_code == 200
    assert "cached" not in r.json()  # 重建，非直读旧缓存
    assert r.json()["sources"]["blackbox_runs"] == 1


def test_evidence_matrix_corrupt_cache_self_heals(authed_client, tmp_workspaces):
    """缓存坏 JSON（mtime 新鲜）→ 不 500：按不可用缓存处理，重建自愈并落盘。"""
    scan_dir = _make_scan(tmp_workspaces, "w1")
    _wb_products(scan_dir, entries=[_ep("GET", "/profile")])
    out = scan_dir / "deliverables" / "api_evidence_matrix.json"
    out.write_text("{not valid json")
    r = authed_client.get("/api/workspaces/w1/scans/s1/evidence-matrix")
    assert r.status_code == 200
    assert r.json()["schema_version"] == 1
    assert json.loads(out.read_text(encoding="utf-8"))["schema_version"] == 1  # 已重建落盘


def test_evidence_matrix_stale_cache_served_when_report_data_missing(authed_client,
                                                                     tmp_workspaces):
    """旧产物兜底：缓存陈旧但 report_data 缺（无法重建）→ 返旧文件，不 404。"""
    scan_dir = _make_scan(tmp_workspaces, "w1")
    inter = scan_dir / "deliverables" / "whitebox" / "intermediate"
    inter.mkdir(parents=True)
    (inter / "entry_points.json").write_text(json.dumps(
        {"adjudicated_entry_points": []}))  # 陈旧触发源（report_data 不写）
    old = {"schema_version": 1, "scan_id": "s1", "old": True, "sources": {},
           "endpoints": [], "unmatched": {}}
    out = scan_dir / "deliverables" / "api_evidence_matrix.json"
    out.write_text(json.dumps(old))
    past = time.time() - 3600
    os.utime(out, (past, past))  # 缓存比 entry_points 旧 → 陈旧
    r = authed_client.get("/api/workspaces/w1/scans/s1/evidence-matrix")
    assert r.status_code == 200
    assert r.json()["old"] is True
