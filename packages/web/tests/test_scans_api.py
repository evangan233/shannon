"""T4: scan-scoped API 路由 + shim 测试。

GET /{ws}/scans、/{ws}/scans/{scan_id}(detail/report/deliverables/logs) 按 scan_id；
scan_id 路径校验拒越界 -> 404；resume interrupted/crashed -> 202、completed/failed/running ->
422；shim GET /{ws} 含 scans[]；shim DELETE /api/scan/{ws} cancel latest。
"""
import json

import pytest


def _make_scan(tmp_workspaces, ws, scan_id="20260727-120000", status="completed",
               owner="web", **extra):
    """直接在 tmp_workspaces 建 scan（不经 scan_manager.start，免 temporal）。"""
    scan_dir = tmp_workspaces / ws / "scans" / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)
    sess = {"status": status, "scan_type": "whitebox", "created_at": 1780000000.0,
            "web_url": "http://e", "repo_path": "/code", "owner": owner}
    sess.update(extra)
    (scan_dir / "session.json").write_text(json.dumps(sess))
    return scan_dir


def _csrf(c):
    return c.get("/api/auth/csrf").json()["csrf_token"]


class FakeSM:
    """隔离 scan_manager（免 temporal），记录 resume/cancel/delete/rerun 调用。"""
    def __init__(self):
        self.resumed = []
        self.cancelled = []
        self.deleted = []
        self.rerun_bb = []  # [(ws, scan_id, new_auth), ...]（rerun_blackbox 记录；
        # 不叫 rerun——批量重跑加了 sm.rerun 方法，实例属性会遮蔽同名方法）
        self.add_run = []  # [(ws, scan_id, req), ...]
        self.deleted_runs = []  # [(ws, scan_id, run_id), ...]
        self.resume_exc = None
        self.resume_for_exc: dict[str, Exception] = {}
        # 批量端点（2026-09-15）：scan_status 状态门（scan_id -> 对外状态；缺省查不到
        # 视为不存在）+ cancel_exc（scan_id -> 异常，单项失败隔离测试）。
        self.status_map: dict[str, str] = {}
        self.cancel_exc: dict[str, Exception] = {}
        self.preview_result = {
            "status": "failed", "resumable": True, "reason": None,
            "scan_type": "whitebox",
            "completed_agents": ["pre-recon"], "interrupted_agent": "recon",
            "steps": [{"step": "gitnexus-chain-verdict", "state": "done",
                       "ts": 1756272000.0}],
            "warnings": [], "abort_reason": None, "resume_attempts": 1}
        self.preview_exc = None
        self.delete_exc = None
        self.delete_for_exc: dict[str, Exception] = {}
        self.delete_run_exc = None
        # 批量重跑（2026-09-20）：sm.rerun 逐项记录 + rerun_for_exc 单项异常隔离。
        self.rerunned = []  # [(ws, scan_id), ...]
        self.rerun_for_exc: dict[str, Exception] = {}

    async def resume(self, ws, scan_id):
        if scan_id in self.resume_for_exc:
            raise self.resume_for_exc[scan_id]
        if self.resume_exc:
            raise self.resume_exc
        self.resumed.append((ws, scan_id))
        return ws, scan_id

    async def resume_preview(self, ws, scan_id):
        if self.preview_exc:
            raise self.preview_exc
        return self.preview_result

    def scan_status(self, ws, scan_id):
        return self.status_map.get(scan_id)

    async def cancel(self, ws, scan_id=None):
        if scan_id in self.cancel_exc:
            raise self.cancel_exc[scan_id]
        self.cancelled.append((ws, scan_id))
        return {"cancelled": scan_id if scan_id else ws}

    async def delete(self, ws, scan_id):
        if scan_id in self.delete_for_exc:
            raise self.delete_for_exc[scan_id]
        if self.delete_exc:
            raise self.delete_exc
        self.deleted.append((ws, scan_id))
        return None if scan_id == "nope" else {"deleted": scan_id}

    async def rerun_blackbox(self, ws, scan_id, new_auth=None):
        self.rerun_bb.append((ws, scan_id, new_auth))
        return "run-2"  # 新模型：续跑返下一个 run_id（run-K+1）

    async def rerun(self, ws, scan_id):
        if scan_id in self.rerun_for_exc:
            raise self.rerun_for_exc[scan_id]
        self.rerunned.append((ws, scan_id))
        return (ws, f"new-{scan_id}")

    async def _add_blackbox_run(self, ws, scan_id, req=None):
        self.add_run.append((ws, scan_id, req))
        return "run-1"

    async def delete_blackbox_run(self, ws, scan_id, run_id):
        if self.delete_run_exc:
            raise self.delete_run_exc
        self.deleted_runs.append((ws, scan_id, run_id))
        return None if run_id == "run-nope" else {"deleted": run_id}

    def active_pids(self):
        return {}


# ── scan-scoped 读路由 ─────────────────────────────────────────────────────

def test_list_scans(authed_client, tmp_workspaces):
    _make_scan(tmp_workspaces, "WS", scan_id="20260727-120000")
    _make_scan(tmp_workspaces, "WS", scan_id="20260727-130000")
    r = authed_client.get("/api/workspaces/WS/scans")
    assert r.status_code == 200
    ids = {s["scan_id"] for s in r.json()}
    assert ids == {"20260727-120000", "20260727-130000"}


def test_get_scan_detail(authed_client, tmp_workspaces):
    _make_scan(tmp_workspaces, "WS", scan_id="s1", status="completed",
               repo_path="/code/x", source_repo="group/repo-a")
    r = authed_client.get("/api/workspaces/WS/scans/s1")
    assert r.status_code == 200
    d = r.json()
    assert d["repo_path"] == "/code/x"
    assert d["scan_type"] == "whitebox"
    assert d["status"] == "completed"
    # 重跑预填字段：白盒 source_repo；无 scan-config.yaml -> authentication None
    assert d["source_repo"] == "group/repo-a"
    assert d["reuse_whitebox_scan_id"] is None
    assert d["authentication"] is None


# ── 版本化黑盒 run 透传 + run 级路由（T12，spec §7.1 #9）──────────────────────

def test_scan_detail_includes_bb_runs(authed_client, tmp_workspaces):
    from supernova_web.components.scan_store import ScanStore
    _make_scan(tmp_workspaces, "WS", scan_id="s1", status="completed")
    store = ScanStore(tmp_workspaces)
    store.create_blackbox_run("WS", "s1")
    detail = authed_client.get("/api/workspaces/WS/scans/s1").json()
    assert detail["combined"] is True
    assert detail["latest_bb_run"] == "run-1"
    assert detail["bb_runs"][0]["run_id"] == "run-1"


def test_list_blackbox_runs_route(authed_client, tmp_workspaces):
    from supernova_web.components.scan_store import ScanStore
    _make_scan(tmp_workspaces, "WS", scan_id="s1")
    store = ScanStore(tmp_workspaces)
    store.create_blackbox_run("WS", "s1")
    store.create_blackbox_run("WS", "s1")
    runs = authed_client.get("/api/workspaces/WS/scans/s1/blackbox-runs").json()
    assert [r["run_id"] for r in runs] == ["run-1", "run-2"]


def test_blackbox_run_detail_route(authed_client, tmp_workspaces):
    from supernova_web.components.scan_store import ScanStore
    _make_scan(tmp_workspaces, "WS", scan_id="s1")
    store = ScanStore(tmp_workspaces)
    store.create_blackbox_run("WS", "s1")
    store.update_blackbox_run("WS", "s1", "run-1", phase="running", status="running")
    rd = authed_client.get("/api/workspaces/WS/scans/s1/blackbox-runs/run-1").json()
    assert rd["run_id"] == "run-1"
    assert rd["bb_phase"] == "running"


def test_blackbox_run_detail_404(authed_client, tmp_workspaces):
    _make_scan(tmp_workspaces, "WS", scan_id="s1")
    r = authed_client.get("/api/workspaces/WS/scans/s1/blackbox-runs/run-9")
    assert r.status_code == 404


# ── run 级报告/产物 + POST add-run（T13，spec §7.1 #10/#8）────────────────────

def test_blackbox_run_report_route(authed_client, tmp_workspaces):
    from supernova_web.components.scan_store import ScanStore
    _make_scan(tmp_workspaces, "WS", scan_id="s1")
    store = ScanStore(tmp_workspaces)
    store.create_blackbox_run("WS", "s1")
    run_dir = tmp_workspaces / "WS" / "scans" / "s1" / "blackbox-runs" / "run-1"
    (run_dir / "deliverables" / "blackbox").mkdir(parents=True)
    (run_dir / "deliverables" / "blackbox" / "comprehensive_security_assessment_report.md").write_text(
        "# 黑盒报告")
    txt = authed_client.get(
        "/api/workspaces/WS/scans/s1/blackbox-runs/run-1/report").text
    assert txt == "# 黑盒报告"


def test_blackbox_run_combined_report_route(authed_client, tmp_workspaces):
    """run report ?track=combined 读 combined/run-K/combined_report.md。"""
    from supernova_core.utils.paths import combined_run_dir
    from supernova_web.components.scan_store import ScanStore
    _make_scan(tmp_workspaces, "WS", scan_id="s1")
    store = ScanStore(tmp_workspaces)
    store.create_blackbox_run("WS", "s1")
    scan_dir = tmp_workspaces / "WS" / "scans" / "s1"
    out = combined_run_dir(scan_dir, "run-1")
    out.mkdir(parents=True)
    (out / "combined_report.md").write_text("# 融合报告")
    txt = authed_client.get(
        "/api/workspaces/WS/scans/s1/blackbox-runs/run-1/report?track=combined").text
    assert txt == "# 融合报告"


def test_blackbox_run_deliverables_route(authed_client, tmp_workspaces):
    from supernova_web.components.scan_store import ScanStore
    _make_scan(tmp_workspaces, "WS", scan_id="s1")
    store = ScanStore(tmp_workspaces)
    store.create_blackbox_run("WS", "s1")
    run_dir = tmp_workspaces / "WS" / "scans" / "s1" / "blackbox-runs" / "run-1"
    (run_dir / "deliverables" / "blackbox").mkdir(parents=True)
    (run_dir / "deliverables" / "blackbox" / "injection_exploit_verdicts.json").write_text(
        '{"verdicts":[]}')
    r = authed_client.get(
        "/api/workspaces/WS/scans/s1/blackbox-runs/run-1/deliverables")
    assert r.status_code == 200


def test_post_add_blackbox_run(authed_client, app_with_ws, tmp_workspaces):
    """POST /blackbox-runs（空 body=无认证）→ 202 + run_id（调 _add_blackbox_run）。"""
    _make_scan(tmp_workspaces, "WS", scan_id="s1", status="completed")
    fake = FakeSM()
    app_with_ws.state.scan_manager = fake
    tok = _csrf(authed_client)
    r = authed_client.post("/api/workspaces/WS/scans/s1/blackbox-runs",
                           json={}, headers={"X-CSRF-Token": tok})
    assert r.status_code == 202, r.text
    assert r.json()["run_id"] == "run-1"
    assert fake.add_run == [("WS", "s1", None)]


def test_rerun_blackbox_returns_run_id(authed_client, app_with_ws, tmp_workspaces):
    """rerun-blackbox 响应含 run_id（新模型返下一个 run）。"""
    _make_scan(tmp_workspaces, "WS", scan_id="s1", status="failed",
               combined=True, bb_phase="failed")
    fake = FakeSM()
    app_with_ws.state.scan_manager = fake
    tok = _csrf(authed_client)
    r = authed_client.post("/api/workspaces/WS/scans/s1/combined/rerun-blackbox",
                           json={}, headers={"X-CSRF-Token": tok})
    assert r.status_code == 202
    assert r.json()["run_id"] == "run-2"


def test_get_scan_detail_rerun_preset_blackbox(authed_client, tmp_workspaces):
    """黑盒 _scan_detail 返 reuse_whitebox_scan_id + authentication（读 scan-config.yaml）。"""
    bb_dir = _make_scan(tmp_workspaces, "WS", scan_id="bb1", scan_type="blackbox",
                        reuse_whitebox_scan_id="wb1")
    (bb_dir / "scan-config.yaml").write_text("""authentication:
  login_type: form
  login_url: http://t/login
  credentials:
    username: admin
    password: pw
  success_condition:
    type: url_contains
    value: welcome
""", encoding="utf-8")
    r = authed_client.get("/api/workspaces/WS/scans/bb1")
    assert r.status_code == 200
    d = r.json()
    assert d["reuse_whitebox_scan_id"] == "wb1"
    auth = d["authentication"]
    assert auth["login_type"] == "form"
    assert auth["login_url"] == "http://t/login"
    assert auth["credentials"]["username"] == "admin"


def test_get_scan_detail_no_auth_config(authed_client, tmp_workspaces):
    """黑盒无 scan-config.yaml（未启用登录）-> authentication None，不阻塞详情。"""
    _make_scan(tmp_workspaces, "WS", scan_id="bb2", scan_type="blackbox")
    r = authed_client.get("/api/workspaces/WS/scans/bb2")
    assert r.status_code == 200
    assert r.json()["authentication"] is None


def test_get_scan_404_unknown(authed_client, tmp_workspaces):
    _make_scan(tmp_workspaces, "WS", scan_id="s1")
    assert authed_client.get("/api/workspaces/WS/scans/nope").status_code == 404


# 注：scan_id 路径遍历防护（拒 ..///）在单测 test_scan_store.py::test_get_scan_dir_rejects_traversal
# 覆盖（HTTP 层 Starlette 会规范化 /scans/.. -> /WS/，不作为 scan_id 到达路由）。


def test_scan_deliverables(authed_client, tmp_workspaces):
    scan_dir = _make_scan(tmp_workspaces, "WS", scan_id="s1")
    dl = scan_dir / "deliverables" / "whitebox"
    dl.mkdir(parents=True)
    (dl / "report.md").write_text("# R")
    s = authed_client.get("/api/workspaces/WS/scans/s1/deliverables").json()
    assert any(f["path"] == "whitebox/report.md" for f in s["files"])


# ── 产物下载（?download=1 → FileResponse 附件：磁盘原文，无 preview_limit 截断）──

# 大于默认 preview_limit（2MB）→ 预览截断 / 下载全文的分界
_BIG = "x" * (3 * 1024 * 1024)


def test_scan_deliverables_download(authed_client, tmp_workspaces):
    """scan 级下载：attachment 头 + basename 文件名 + 全文无截断（3MB > preview_limit）。"""
    scan_dir = _make_scan(tmp_workspaces, "WS", scan_id="s1")
    dl = scan_dir / "deliverables" / "whitebox"
    dl.mkdir(parents=True)
    (dl / "big_report.md").write_text(_BIG, encoding="utf-8")
    r = authed_client.get(
        "/api/workspaces/WS/scans/s1/deliverables"
        "?path=whitebox%2Fbig_report.md&download=1")
    assert r.status_code == 200
    assert r.headers["content-disposition"].startswith('attachment; filename="big_report.md"')
    assert len(r.text) == len(_BIG)  # 磁盘原文，无 [truncated: 标注
    assert "[truncated:" not in r.text


def test_scan_deliverables_download_404(authed_client, tmp_workspaces):
    _make_scan(tmp_workspaces, "WS", scan_id="s1")
    r = authed_client.get(
        "/api/workspaces/WS/scans/s1/deliverables?path=whitebox%2Fnope.md&download=1")
    assert r.status_code == 404


def test_scan_deliverables_preview_still_truncated(authed_client, tmp_workspaces):
    """回归：无 download 参数仍走预览语义（超 preview_limit 截断 + 标注）。"""
    scan_dir = _make_scan(tmp_workspaces, "WS", scan_id="s1")
    dl = scan_dir / "deliverables" / "whitebox"
    dl.mkdir(parents=True)
    (dl / "big_report.md").write_text(_BIG, encoding="utf-8")
    r = authed_client.get(
        "/api/workspaces/WS/scans/s1/deliverables?path=whitebox%2Fbig_report.md")
    assert r.status_code == 200
    assert "[truncated:" in r.text
    assert len(r.text) < len(_BIG)


def test_blackbox_run_deliverables_download(authed_client, tmp_workspaces):
    """run 级下载（strip 模式）：无前缀 path 按 blackbox 桶解析，附件返回原文。"""
    from supernova_web.components.scan_store import ScanStore
    _make_scan(tmp_workspaces, "WS", scan_id="s1")
    store = ScanStore(tmp_workspaces)
    store.create_blackbox_run("WS", "s1")
    run_dir = tmp_workspaces / "WS" / "scans" / "s1" / "blackbox-runs" / "run-1"
    bbd = run_dir / "deliverables" / "blackbox"
    bbd.mkdir(parents=True)
    (bbd / "comprehensive_security_assessment_report.md").write_text("# 黑盒报告全文")
    r = authed_client.get(
        "/api/workspaces/WS/scans/s1/blackbox-runs/run-1/deliverables"
        "?path=comprehensive_security_assessment_report.md&download=1")
    assert r.status_code == 200
    assert r.headers["content-disposition"].startswith(
        'attachment; filename="comprehensive_security_assessment_report.md"')
    assert r.text == "# 黑盒报告全文"


def test_scan_report(authed_client, tmp_workspaces):
    scan_dir = _make_scan(tmp_workspaces, "WS", scan_id="s1")
    dl = scan_dir / "deliverables" / "whitebox"
    dl.mkdir(parents=True)
    (dl / "comprehensive_security_assessment_report.md").write_text("# 综合报告")
    assert authed_client.get("/api/workspaces/WS/scans/s1/report").text == "# 综合报告"


def test_scan_report_blackbox_track(authed_client, tmp_workspaces):
    """黑盒扫描报告落在 deliverables/blackbox/。read() 默认 track 必须自动推断到
    blackbox(对齐 summary/read_poc),否则 report_for 按默认 whitebox track 找不到
    -> FileNotFoundError -> 500（regression: repo-20260802-154427 报告页加载失败）。"""
    scan_dir = _make_scan(tmp_workspaces, "WS", scan_id="s1", scan_type="blackbox")
    dl = scan_dir / "deliverables" / "blackbox"
    dl.mkdir(parents=True)
    (dl / "comprehensive_security_assessment_report.md").write_text("# 黑盒综合报告")
    assert authed_client.get("/api/workspaces/WS/scans/s1/report").text == "# 黑盒综合报告"


def test_scan_report_track_param_three_view(authed_client, tmp_workspaces):
    """组合扫描三视图（spec §10.1）：?track=whitebox/blackbox/combined 各取该桶报告。
    track=None auto-infer 到 combined（_infer_track 优先 combined_report.md）。
    无 track 参数时跨桶 list_reports + auto-infer 对组合扫描会错桶 -> 故三视图必须显式 track。"""
    scan_dir = _make_scan(tmp_workspaces, "WS", scan_id="c1", scan_type="whitebox")
    d = scan_dir / "deliverables"
    for t, body in [("whitebox", "# 白盒报告"), ("blackbox", "# 黑盒报告"),
                    ("combined", "# 融合报告")]:
        sd = d / t
        sd.mkdir(parents=True)
        (sd / "comprehensive_security_assessment_report.md" if t != "combined"
         else sd / "combined_report.md").write_text(body)
    # 显式 track：各桶各取各的报告。
    assert authed_client.get("/api/workspaces/WS/scans/c1/report?track=whitebox").text == "# 白盒报告"
    assert authed_client.get("/api/workspaces/WS/scans/c1/report?track=blackbox").text == "# 黑盒报告"
    assert authed_client.get("/api/workspaces/WS/scans/c1/report?track=combined").text == "# 融合报告"
    # 无 track 仍 auto-infer（零回归）：combined_report.md 存在 -> combined 桶。
    assert authed_client.get("/api/workspaces/WS/scans/c1/report").text == "# 融合报告"
    # 不存在的桶 -> 200 空文本（不 500）。
    assert authed_client.get("/api/workspaces/WS/scans/c1/report?track=nonexistent").text == ""


def test_scan_logs(authed_client, tmp_workspaces):
    scan_dir = _make_scan(tmp_workspaces, "WS", scan_id="s1")
    (scan_dir / "workflow.log").write_text("wf")
    files = authed_client.get("/api/workspaces/WS/scans/s1/logs").json()["files"]
    assert "workflow.log" in files


# ── resume（用户决策：仅 interrupted/crashed 可 resume）──────────────────────

def test_resume_interrupted_202(authed_client, app_with_ws, tmp_workspaces):
    _make_scan(tmp_workspaces, "WS", scan_id="s1", status="interrupted")
    fake = FakeSM()
    app_with_ws.state.scan_manager = fake
    tok = _csrf(authed_client)
    r = authed_client.post("/api/workspaces/WS/scans/s1/resume",
                           headers={"X-CSRF-Token": tok})
    assert r.status_code == 202
    assert fake.resumed == [("WS", "s1")]


def test_resume_crashed_202(authed_client, app_with_ws, tmp_workspaces):
    _make_scan(tmp_workspaces, "WS", scan_id="s1", status="crashed")
    fake = FakeSM()
    app_with_ws.state.scan_manager = fake
    tok = _csrf(authed_client)
    assert authed_client.post("/api/workspaces/WS/scans/s1/resume",
                              headers={"X-CSRF-Token": tok}).status_code == 202


def test_resume_completed_422(authed_client, app_with_ws, tmp_workspaces):
    """completed scan 不可 resume -> 422（用重扫 POST /api/scan 起 scan）。"""
    _make_scan(tmp_workspaces, "WS", scan_id="s1", status="completed")
    fake = FakeSM()
    fake.resume_exc = ValueError("该扫描状态为 completed，不可恢复，请重新扫描")
    app_with_ws.state.scan_manager = fake
    tok = _csrf(authed_client)
    assert authed_client.post("/api/workspaces/WS/scans/s1/resume",
                              headers={"X-CSRF-Token": tok}).status_code == 422


def test_resume_failed_422(authed_client, app_with_ws, tmp_workspaces):
    """resume 被 ValueError 拒 -> 422。failed 现已可续跑（spec 2026-08-27 §4.1），
    典型拒绝场景换为 builder abort（G∧¬F 产物丢失带 abort_reason）。"""
    _make_scan(tmp_workspaces, "WS", scan_id="s1", status="failed")
    fake = FakeSM()
    fake.resume_exc = ValueError(
        "resume 中止：recon 有 deliverable commit 但产出物文件缺失")
    app_with_ws.state.scan_manager = fake
    tok = _csrf(authed_client)
    assert authed_client.post("/api/workspaces/WS/scans/s1/resume",
                              headers={"X-CSRF-Token": tok}).status_code == 422


# ── rerun-blackbox（HTTP body 边界，review Important #1）───────────────────────

def test_rerun_blackbox_empty_json_body_202(authed_client, app_with_ws, tmp_workspaces):
    """v1 续跑无新认证：前端 apiPost 恒发 Content-Type: application/json + body "{}"。
    路由必须容忍 "{}" 为「沿用原认证」——旧 ``body: ScanRequest | None = Body(default=None)``
    会把 "{}" 当 ScanRequest 校验（type 必填）→ 422，破坏 v1 路径。new_auth=None 透传 scan_manager。
    """
    _make_scan(tmp_workspaces, "WS", scan_id="s1", status="failed",
               combined=True, bb_phase="failed")
    fake = FakeSM()
    app_with_ws.state.scan_manager = fake
    tok = _csrf(authed_client)
    r = authed_client.post("/api/workspaces/WS/scans/s1/combined/rerun-blackbox",
                           json={}, headers={"X-CSRF-Token": tok})
    assert r.status_code == 202, r.text
    assert fake.rerun_bb == [("WS", "s1", None)]  # new_auth=None（沿用原认证）


def test_rerun_blackbox_truly_empty_body_202(authed_client, app_with_ws, tmp_workspaces):
    """无 body（Content-Length 0）同样视为沿用原认证。"""
    _make_scan(tmp_workspaces, "WS", scan_id="s1", status="failed",
               combined=True, bb_phase="failed")
    fake = FakeSM()
    app_with_ws.state.scan_manager = fake
    tok = _csrf(authed_client)
    r = authed_client.post("/api/workspaces/WS/scans/s1/combined/rerun-blackbox",
                           headers={"X-CSRF-Token": tok})
    assert r.status_code == 202, r.text
    assert fake.rerun_bb[-1] == ("WS", "s1", None)


def test_rerun_blackbox_invalid_scanrequest_422(authed_client, app_with_ws, tmp_workspaces):
    """非空 body 但缺 type（非法 ScanRequest）→ 422（换认证路径保留校验）。"""
    _make_scan(tmp_workspaces, "WS", scan_id="s1", status="failed",
               combined=True, bb_phase="failed")
    fake = FakeSM()
    app_with_ws.state.scan_manager = fake
    tok = _csrf(authed_client)
    r = authed_client.post("/api/workspaces/WS/scans/s1/combined/rerun-blackbox",
                           json={"url": "http://t"}, headers={"X-CSRF-Token": tok})
    assert r.status_code == 422
    assert fake.rerun_bb == []  # 未触 scan_manager（校验在前）


def test_resume_unknown_scan_404(authed_client, app_with_ws, tmp_workspaces):
    fake = FakeSM()
    fake.resume_exc = ValueError("scan 不存在")
    app_with_ws.state.scan_manager = fake
    tok = _csrf(authed_client)
    assert authed_client.post("/api/workspaces/WS/scans/nope/resume",
                              headers={"X-CSRF-Token": tok}).status_code == 404


def test_cancel_scan_by_id(authed_client, app_with_ws, tmp_workspaces):
    """POST /scans/{id}/cancel 取消（DELETE 端点已让位给真删）。"""
    _make_scan(tmp_workspaces, "WS", scan_id="s1", status="running")
    fake = FakeSM()
    app_with_ws.state.scan_manager = fake
    tok = _csrf(authed_client)
    r = authed_client.post("/api/workspaces/WS/scans/s1/cancel",
                           headers={"X-CSRF-Token": tok})
    assert r.status_code == 200
    assert fake.cancelled == [("WS", "s1")]


def test_cancel_scan_passes_through_via_signal(authed_client, app_with_ws, tmp_workspaces):
    """scan-scoped cancel 返 via:signal 时 api 透传给前端（ws 列表 cancelActiveScan 依赖）。"""
    _make_scan(tmp_workspaces, "WS", scan_id="s1", status="running")

    class HostSM:
        def __init__(self):
            self.cancelled = []

        async def cancel(self, ws, scan_id):
            self.cancelled.append((ws, scan_id))
            return {"cancelled": scan_id, "via": "signal"}

        def active_pids(self):
            return {}

    fake = HostSM()
    app_with_ws.state.scan_manager = fake
    tok = _csrf(authed_client)
    r = authed_client.post("/api/workspaces/WS/scans/s1/cancel", headers={"X-CSRF-Token": tok})
    assert r.status_code == 200
    assert r.json() == {"cancelled": "s1", "via": "signal"}
    assert fake.cancelled == [("WS", "s1")]


# ── batch-cancel / batch-resume（2026-09-15 批量取消/续跑）───────────────────

def test_batch_cancel_mixed(authed_client, app_with_ws, tmp_workspaces):
    """running/queued 逐项调 sm.cancel；终态 skipped；不存在 error；有成功 → 202。"""
    _make_scan(tmp_workspaces, "WS", scan_id="s1", status="running")
    fake = FakeSM()
    fake.status_map = {"s1": "running", "s2": "queued", "s3": "completed", "s4": "interrupted"}
    app_with_ws.state.scan_manager = fake
    tok = _csrf(authed_client)
    r = authed_client.post("/api/workspaces/WS/scans/batch-cancel",
                           json={"scan_ids": ["s1", "s2", "s3", "s4", "nope"]},
                           headers={"X-CSRF-Token": tok})
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["submitted"] == 2
    assert body["skipped"] == 2
    assert body["failed"] == 3 - 2  # 不存在一项
    by_id = {x["scan_id"]: x for x in body["results"]}
    assert fake.cancelled == [("WS", "s1"), ("WS", "s2")]  # 只有 running/queued 进 cancel
    assert by_id["s3"]["skipped"] is True
    assert by_id["nope"]["ok"] is False and by_id["nope"]["skipped"] is False


def test_batch_cancel_state_gate_protects_terminal(authed_client, app_with_ws, tmp_workspaces):
    """状态门核心：completed 不裸调 sm.cancel——裸调会 _mark_cancelled 把终态覆写成
    cancelled（单行按钮靠 UI 条件挡，批量必须服务端挡「勾选到确认间跑完」的漂移）。"""
    _make_scan(tmp_workspaces, "WS", scan_id="s1", status="completed")
    fake = FakeSM()
    fake.status_map = {"s1": "completed"}
    app_with_ws.state.scan_manager = fake
    tok = _csrf(authed_client)
    r = authed_client.post("/api/workspaces/WS/scans/batch-cancel",
                           json={"scan_ids": ["s1"]}, headers={"X-CSRF-Token": tok})
    assert r.status_code == 422  # 全跳过（零成功）→ 422
    assert fake.cancelled == []  # 从未触 cancel


def test_batch_cancel_empty_ids_422(authed_client, app_with_ws):
    """空 scan_ids → 422（validator：请至少选择一个扫描任务）。"""
    fake = FakeSM()
    app_with_ws.state.scan_manager = fake
    tok = _csrf(authed_client)
    r = authed_client.post("/api/workspaces/WS/scans/batch-cancel",
                           json={"scan_ids": []}, headers={"X-CSRF-Token": tok})
    assert r.status_code == 422
    assert fake.cancelled == []


def test_batch_cancel_dedup(authed_client, app_with_ws, tmp_workspaces):
    """重复 scan_id 保序去重——同一任务只取消一次。"""
    _make_scan(tmp_workspaces, "WS", scan_id="s1", status="running")
    fake = FakeSM()
    fake.status_map = {"s1": "running"}
    app_with_ws.state.scan_manager = fake
    tok = _csrf(authed_client)
    r = authed_client.post("/api/workspaces/WS/scans/batch-cancel",
                           json={"scan_ids": ["s1", "s1", "s1"]}, headers={"X-CSRF-Token": tok})
    assert r.status_code == 202
    assert fake.cancelled == [("WS", "s1")]
    assert len(r.json()["results"]) == 1


def test_batch_cancel_single_failure_isolated(authed_client, app_with_ws, tmp_workspaces):
    """单项 cancel 异常只计入该行 results，不阻断整批。"""
    _make_scan(tmp_workspaces, "WS", scan_id="s1", status="running")
    fake = FakeSM()
    fake.status_map = {"s1": "running", "s2": "running"}
    fake.cancel_exc["s2"] = RuntimeError("boom")
    app_with_ws.state.scan_manager = fake
    tok = _csrf(authed_client)
    r = authed_client.post("/api/workspaces/WS/scans/batch-cancel",
                           json={"scan_ids": ["s1", "s2"]}, headers={"X-CSRF-Token": tok})
    assert r.status_code == 202
    body = r.json()
    assert body["submitted"] == 1
    by_id = {x["scan_id"]: x for x in body["results"]}
    assert by_id["s2"]["ok"] is False and "boom" in by_id["s2"]["error"]


def test_batch_resume_mixed(authed_client, app_with_ws, tmp_workspaces):
    """批量续跑：resume 自带状态门（ValueError 逐项转 error），有成功 → 202。"""
    _make_scan(tmp_workspaces, "WS", scan_id="s1", status="interrupted")
    fake = FakeSM()
    fake.resume_for_exc = {"s2": ValueError("该扫描状态为 running，不可恢复，请重新扫描")}
    app_with_ws.state.scan_manager = fake
    tok = _csrf(authed_client)
    r = authed_client.post("/api/workspaces/WS/scans/batch-resume",
                           json={"scan_ids": ["s1", "s2"]}, headers={"X-CSRF-Token": tok})
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["submitted"] == 1
    assert fake.resumed == [("WS", "s1")]
    by_id = {x["scan_id"]: x for x in body["results"]}
    assert by_id["s2"]["ok"] is False and "不可恢复" in by_id["s2"]["error"]


def test_batch_resume_all_failed_422(authed_client, app_with_ws, tmp_workspaces):
    """全失败 → 422（body 顶层同形，对齐 batch-scan 先例）。"""
    _make_scan(tmp_workspaces, "WS", scan_id="s1", status="completed")
    fake = FakeSM()
    fake.resume_exc = ValueError("该扫描状态为 completed，不可恢复，请重新扫描")
    app_with_ws.state.scan_manager = fake
    tok = _csrf(authed_client)
    r = authed_client.post("/api/workspaces/WS/scans/batch-resume",
                           json={"scan_ids": ["s1"]}, headers={"X-CSRF-Token": tok})
    assert r.status_code == 422
    assert r.json()["results"][0]["ok"] is False


# ── batch-rerun（2026-09-20 批量重跑）────────────────────────────────────────

def test_batch_rerun_mixed(authed_client, app_with_ws, tmp_workspaces):
    """批量重跑：可重建项逐项调 sm.rerun；rerun 自带状态门（ValueError 逐项转
    error），有成功 → 202。"""
    _make_scan(tmp_workspaces, "WS", scan_id="s1", status="cancelled")
    fake = FakeSM()
    fake.rerun_for_exc = {
        "s2": ValueError("跨仓关联扫描的多仓配置不可自动重建，请用单行「重跑」手动配置"),
        "s3": ValueError("该扫描状态为 running，不可重跑（仅终态可重跑）"),
    }
    app_with_ws.state.scan_manager = fake
    tok = _csrf(authed_client)
    r = authed_client.post("/api/workspaces/WS/scans/batch-rerun",
                           json={"scan_ids": ["s1", "s2", "s3"]},
                           headers={"X-CSRF-Token": tok})
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["submitted"] == 1
    assert body["failed"] == 2
    assert fake.rerunned == [("WS", "s1")]
    by_id = {x["scan_id"]: x for x in body["results"]}
    assert by_id["s1"]["ok"] is True
    assert by_id["s2"]["ok"] is False and "跨仓" in by_id["s2"]["error"]
    assert by_id["s3"]["ok"] is False and "状态" in by_id["s3"]["error"]


def test_batch_rerun_all_failed_422(authed_client, app_with_ws, tmp_workspaces):
    """全失败 → 422（body 顶层同形，对齐 batch-resume 先例）。"""
    _make_scan(tmp_workspaces, "WS", scan_id="s1", status="cancelled")
    fake = FakeSM()
    fake.rerun_for_exc = {"s1": ValueError("该扫描状态为 cancelled，不可重跑（仅终态可重跑）")}
    app_with_ws.state.scan_manager = fake
    tok = _csrf(authed_client)
    r = authed_client.post("/api/workspaces/WS/scans/batch-rerun",
                           json={"scan_ids": ["s1"]}, headers={"X-CSRF-Token": tok})
    assert r.status_code == 422
    assert r.json()["results"][0]["ok"] is False


def test_batch_rerun_single_failure_isolated(authed_client, app_with_ws, tmp_workspaces):
    """单项异常（如 TemporalUnavailable）只计入该行 results，不阻断整批。"""
    _make_scan(tmp_workspaces, "WS", scan_id="s1", status="failed")
    fake = FakeSM()
    fake.rerun_for_exc = {"s1": RuntimeError("boom")}
    _make_scan(tmp_workspaces, "WS", scan_id="s2", status="failed")
    app_with_ws.state.scan_manager = fake
    tok = _csrf(authed_client)
    r = authed_client.post("/api/workspaces/WS/scans/batch-rerun",
                           json={"scan_ids": ["s1", "s2"]}, headers={"X-CSRF-Token": tok})
    assert r.status_code == 202
    body = r.json()
    assert body["submitted"] == 1
    by_id = {x["scan_id"]: x for x in body["results"]}
    assert by_id["s1"]["ok"] is False and "boom" in by_id["s1"]["error"]
    assert by_id["s2"]["ok"] is True


def test_batch_rerun_empty_ids_422(authed_client, app_with_ws):
    """空 scan_ids → 422（ScanIdsBatchRequest validator，对齐批量取消）。"""
    fake = FakeSM()
    app_with_ws.state.scan_manager = fake
    tok = _csrf(authed_client)
    r = authed_client.post("/api/workspaces/WS/scans/batch-rerun",
                           json={"scan_ids": []}, headers={"X-CSRF-Token": tok})
    assert r.status_code == 422
    assert fake.rerunned == []


def test_scan_status_real_disk(tmp_path):
    """scan_status 真盘口径（非 mock）：终态直读 session.json；不存在 -> None。
    批量取消状态门依赖它读真实状态（防勾选到确认间的状态漂移毁终态）。"""
    from supernova_web.components.scan_manager import ScanManager
    scan_dir = tmp_path / "workspaces" / "WS" / "scans" / "s1"
    scan_dir.mkdir(parents=True)
    (scan_dir / "session.json").write_text(json.dumps({
        "status": "completed", "scan_type": "whitebox", "created_at": 1780000000.0}))
    sm = ScanManager(workspaces_dir=tmp_path / "workspaces", repos_dir=tmp_path / "repos",
                     config_store=object())
    assert sm.scan_status("WS", "s1") == "completed"
    assert sm.scan_status("WS", "nope") is None


# ── batch-delete（2026-09-15 批量删除：终态门 + 逐项真删）─────────────────────

def test_batch_delete_terminal_only(authed_client, app_with_ws, tmp_workspaces):
    """终态逐项调 sm.delete；running/queued 被 effective 状态门拦为 skipped（不裸调
    ——queued 的单点 delete 只拦 raw=running，排队中真删会留孤儿 workflow）。"""
    _make_scan(tmp_workspaces, "WS", scan_id="s1", status="completed")
    fake = FakeSM()
    fake.status_map = {"s1": "completed", "s2": "interrupted", "s3": "running", "s4": "queued"}
    app_with_ws.state.scan_manager = fake
    tok = _csrf(authed_client)
    r = authed_client.post("/api/workspaces/WS/scans/batch-delete",
                           json={"scan_ids": ["s1", "s2", "s3", "s4"]},
                           headers={"X-CSRF-Token": tok})
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["submitted"] == 2
    assert body["skipped"] == 2
    assert fake.deleted == [("WS", "s1"), ("WS", "s2")]  # 只有终态进 delete
    by_id = {x["scan_id"]: x for x in body["results"]}
    assert by_id["s3"]["skipped"] is True
    assert by_id["s4"]["skipped"] is True


def test_batch_delete_running_race_isolated(authed_client, app_with_ws, tmp_workspaces):
    """状态门过后才翻 running 的竞态：sm.delete 抛 ScanRunning 逐项转 error 不阻断。"""
    from supernova_web.components.scan_manager import ScanRunning
    _make_scan(tmp_workspaces, "WS", scan_id="s1", status="completed")
    fake = FakeSM()
    fake.status_map = {"s1": "completed", "s2": "completed"}
    fake.delete_for_exc["s2"] = ScanRunning("s2")
    app_with_ws.state.scan_manager = fake
    tok = _csrf(authed_client)
    r = authed_client.post("/api/workspaces/WS/scans/batch-delete",
                           json={"scan_ids": ["s1", "s2"]}, headers={"X-CSRF-Token": tok})
    assert r.status_code == 202
    body = r.json()
    assert body["submitted"] == 1
    by_id = {x["scan_id"]: x for x in body["results"]}
    assert by_id["s2"]["ok"] is False and "取消" in by_id["s2"]["error"]


def test_batch_delete_all_skipped_422(authed_client, app_with_ws, tmp_workspaces):
    """全被门拦（零成功）→ 422。"""
    _make_scan(tmp_workspaces, "WS", scan_id="s1", status="running")
    fake = FakeSM()
    fake.status_map = {"s1": "running"}
    app_with_ws.state.scan_manager = fake
    tok = _csrf(authed_client)
    r = authed_client.post("/api/workspaces/WS/scans/batch-delete",
                           json={"scan_ids": ["s1"]}, headers={"X-CSRF-Token": tok})
    assert r.status_code == 422
    assert fake.deleted == []


# ── delete（真删，spec §5.1 DELETE）─────────────────────────────────────────

def test_delete_scan_by_id(authed_client, app_with_ws, tmp_workspaces):
    """DELETE /scans/{id} 真删（调 sm.delete），返 {deleted:id}。"""
    _make_scan(tmp_workspaces, "WS", scan_id="s1", status="completed")
    fake = FakeSM()
    app_with_ws.state.scan_manager = fake
    tok = _csrf(authed_client)
    r = authed_client.delete("/api/workspaces/WS/scans/s1", headers={"X-CSRF-Token": tok})
    assert r.status_code == 200
    assert r.json() == {"deleted": "s1"}
    assert fake.deleted == [("WS", "s1")]


def test_delete_running_scan_409(authed_client, app_with_ws, tmp_workspaces):
    """running scan 删除 -> 409（先取消再删，对齐 delete_workspace 删 ws 前 running 检查）。"""
    from supernova_web.components.scan_manager import ScanRunning
    _make_scan(tmp_workspaces, "WS", scan_id="s1", status="running")
    fake = FakeSM()
    fake.delete_exc = ScanRunning("s1")
    app_with_ws.state.scan_manager = fake
    tok = _csrf(authed_client)
    r = authed_client.delete("/api/workspaces/WS/scans/s1", headers={"X-CSRF-Token": tok})
    assert r.status_code == 409


def test_delete_unknown_scan_404(authed_client, app_with_ws, tmp_workspaces):
    """scan 不存在 -> sm.delete 返 None -> 404。"""
    fake = FakeSM()
    app_with_ws.state.scan_manager = fake
    tok = _csrf(authed_client)
    r = authed_client.delete("/api/workspaces/WS/scans/nope", headers={"X-CSRF-Token": tok})
    assert r.status_code == 404


# ── 删单个黑盒 run（spec §7.1 #4，DELETE /blackbox-runs/{run_id}）──────────────

def test_delete_blackbox_run_route(authed_client, app_with_ws, tmp_workspaces):
    """DELETE /blackbox-runs/{run_id} 调 sm.delete_blackbox_run，返 {deleted:run_id}。"""
    _make_scan(tmp_workspaces, "WS", scan_id="s1", status="completed")
    fake = FakeSM()
    app_with_ws.state.scan_manager = fake
    tok = _csrf(authed_client)
    r = authed_client.delete("/api/workspaces/WS/scans/s1/blackbox-runs/run-1",
                             headers={"X-CSRF-Token": tok})
    assert r.status_code == 200
    assert r.json() == {"deleted": "run-1"}
    assert fake.deleted_runs == [("WS", "s1", "run-1")]


def test_delete_blackbox_run_running_409(authed_client, app_with_ws, tmp_workspaces):
    """运行中 run 删除 -> ScanRunning -> 409（先取消再删）。"""
    from supernova_web.components.scan_manager import ScanRunning
    _make_scan(tmp_workspaces, "WS", scan_id="s1")
    fake = FakeSM()
    fake.delete_run_exc = ScanRunning("run-1")
    app_with_ws.state.scan_manager = fake
    tok = _csrf(authed_client)
    r = authed_client.delete("/api/workspaces/WS/scans/s1/blackbox-runs/run-1",
                             headers={"X-CSRF-Token": tok})
    assert r.status_code == 409


def test_delete_blackbox_run_missing_404(authed_client, app_with_ws, tmp_workspaces):
    """run 不存在 -> sm.delete_blackbox_run 返 None -> 404。"""
    _make_scan(tmp_workspaces, "WS", scan_id="s1")
    fake = FakeSM()
    app_with_ws.state.scan_manager = fake
    tok = _csrf(authed_client)
    r = authed_client.delete("/api/workspaces/WS/scans/s1/blackbox-runs/run-nope",
                             headers={"X-CSRF-Token": tok})
    assert r.status_code == 404


# ── shim 已彻底移除（scan-scoped 是唯一取消路径）──────────────────────────────


def test_legacy_ws_scoped_delete_now_404(authed_client, tmp_workspaces):
    """旧 DELETE /api/scan/{ws} shim 已移除 -> 404（路由不存在；scan-scoped DELETE 才是唯一取消路径）。"""
    _make_scan(tmp_workspaces, "WS", scan_id="s1", status="running")
    tok = _csrf(authed_client)
    assert authed_client.delete("/api/scan/WS", headers={"X-CSRF-Token": tok}).status_code == 404


def _scan_with(tmp_workspaces, ws, scan_id="s1", status="completed", **extra):
    """建 scan + 写 session.json 任意字段（metrics/session/repo_path 等）。"""
    import json as _json
    scan_dir = tmp_workspaces / ws / "scans" / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)
    sess = {"status": status, "scan_type": "whitebox", "created_at": 1780000000.0,
            "web_url": "http://e", "repo_path": "/code", "owner": "web"}
    sess.update(extra)
    (scan_dir / "session.json").write_text(_json.dumps(sess))
    return scan_dir


def test_scan_deliverables_summary_shape(authed_client, tmp_workspaces):
    """deliverables 摘要：track/files(kind)/aggregated_vulns/notes；.git 排除。"""
    scan_dir = _scan_with(tmp_workspaces, "D", scan_id="s1")
    dl = scan_dir / "deliverables" / "whitebox"
    dl.mkdir(parents=True)
    (dl / "xss_exploitation_queue.json").write_text(json.dumps({"vulnerabilities": [
        {"ID": "XSS-01", "vulnerability_type": "xss", "externally_exploitable": True}]}))
    (dl / "report.md").write_text("# R")
    (dl / "empty_authz_exploitation_queue.json").write_text(json.dumps({"vulnerabilities": []}))
    (dl / ".git").mkdir()
    (dl / ".git" / "config").write_text("x")
    s = authed_client.get("/api/workspaces/D/scans/s1/deliverables").json()
    assert s["track"] == "whitebox"
    paths = [f["path"] for f in s["files"]]
    assert not any(".git" in p for p in paths)
    assert "whitebox/xss_exploitation_queue.json" in paths
    assert any(f["kind"] == "md" for f in s["files"])
    assert any(f["kind"] == "empty_json" for f in s["files"])
    assert any(v["ID"] == "XSS-01" for v in s["aggregated_vulnerabilities"])
    assert s["notes"]["injection_has_no_queue"] is True


def test_scan_deliverables_file_dual_mode(authed_client, tmp_workspaces):
    """?path= md -> text/plain 原样；json -> text/plain 序列化；不存在 -> 404。"""
    scan_dir = _scan_with(tmp_workspaces, "F", scan_id="s1")
    dl = scan_dir / "deliverables" / "whitebox"
    dl.mkdir(parents=True)
    (dl / "xss_exploitation_queue.json").write_text(json.dumps({"vulnerabilities": [{"ID": "X"}]}))
    (dl / "report.md").write_text("# R")
    client = authed_client
    r = client.get("/api/workspaces/F/scans/s1/deliverables?path=whitebox/report.md")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain") and r.text == "# R"
    rj = client.get("/api/workspaces/F/scans/s1/deliverables?path=whitebox/xss_exploitation_queue.json")
    assert rj.status_code == 200 and "X" in rj.text
    assert client.get("/api/workspaces/F/scans/s1/deliverables?path=whitebox/nope.json").status_code == 404


def test_scan_logs_dual_mode(authed_client, tmp_workspaces):
    """logs 无 file -> {files}；有 file -> {content}；agents/ 相对路径解析。"""
    scan_dir = _scan_with(tmp_workspaces, "L", scan_id="s1")
    (scan_dir / "workflow.log").write_text("wf content")
    agents = scan_dir / "agents"; agents.mkdir()
    (agents / "recon.log").write_text("agent content")
    client = authed_client
    files = client.get("/api/workspaces/L/scans/s1/logs").json()["files"]
    assert "workflow.log" in files and "agents/recon.log" in files
    assert client.get("/api/workspaces/L/scans/s1/logs?file=workflow.log").json()["content"] == "wf content"
    assert client.get("/api/workspaces/L/scans/s1/logs?file=agents/recon.log").json()["content"] == "agent content"
    assert client.get("/api/workspaces/L/scans/s1/logs?file=nope.log").status_code == 404


def test_scan_report_no_poc_concat(authed_client, tmp_workspaces):
    """report 端点不拼接 PoC md（spec 2026-08-26-report-single-source-rendering
    §3.1）：新管线下 comprehensive md 卡自带 POC 节，尾部再拼 poc_collection
    会重复；PoC 集合是独立交付物（DeliverablesTab 可见），md 端点返回纯报告。"""
    scan_dir = _scan_with(tmp_workspaces, "P", scan_id="s1")
    dl = scan_dir / "deliverables" / "whitebox"; dl.mkdir(parents=True)
    (dl / "comprehensive_security_assessment_report.md").write_text("# 综合报告\n\n正文")
    (dl / "exploitable_poc_collection.md").write_text(
        "# 可利用漏洞 PoC 集合（白盒）\n\n```bash\ncurl -i -X GET 'https://t/x'\n```")
    body = authed_client.get("/api/workspaces/P/scans/s1/report").text
    assert body == "# 综合报告\n\n正文"  # 纯 md，无 --- 拼接、无 PoC 内容


def test_scan_report_no_report_empty_200(authed_client, tmp_workspaces):
    """scan 存在但无报告产物 -> 200 空文本（非 404）。"""
    _scan_with(tmp_workspaces, "NoReport", scan_id="s1")  # 有 session.json 无 deliverables
    r = authed_client.get("/api/workspaces/NoReport/scans/s1/report")
    assert r.status_code == 200 and r.text == ""


def test_scan_detail_session_data_shape(authed_client, tmp_workspaces):
    """scan 详情 SessionData：metrics.phases/agents + session 嵌套；无 vuln_count/is_correlation。"""
    _scan_with(tmp_workspaces, "A", scan_id="s1", status="completed",
        repo_path="/repo",
        metrics={
            "total_duration_ms": 1000, "total_cost_usd": 1.5,
            "phases": {"recon": {"duration_ms": 1000, "duration_percentage": 100, "cost_usd": 1.5, "agent_count": 1}},
            "agents": {"recon": {"duration_ms": 1000, "cost_usd": 1.5, "success": True, "attempt_number": 1, "model": "x"}},
        },
        session={"id": "A", "status": "completed", "createdAt": "2026-05-29T10:00:00Z"})
    d = authed_client.get("/api/workspaces/A/scans/s1").json()
    assert d["repo_path"] == "/repo"
    assert d["status"] == "completed"
    assert isinstance(d["created_at"], (int, float))
    # server_now：服务端墙钟基准（秒），供前端做跨时钟 offset 校正，消除「总耗时负数」根因。
    assert isinstance(d["server_now"], (int, float))
    assert "recon" in d["metrics"]["phases"]
    assert "recon" in d["metrics"]["agents"]
    assert d["metrics"]["total_cost_usd"] == 1.5
    assert d["session"]["id"] == "A"
    assert "vuln_count" not in d and "is_correlation" not in d


def test_scan_detail_combined_duration_wallclock(authed_client, tmp_workspaces):
    """组合扫描详情 metrics.total_duration_ms 走墙钟口径（含黑盒段），与列表一致——
    OverviewTab 读该字段，只读任务级 metrics（白盒和）会偏小（2026-08-21）。纯扫描
    detail 的 metrics 仍原样（下一测试覆盖）。"""
    _scan_with(tmp_workspaces, "CW", scan_id="s1", status="completed",
        metrics={"total_duration_ms": 600_000},        # 白盒 agents 和 10min
        combined=True,
        bb_runs=[{"run_id": "run-1", "status": "completed",
                  "completed_at": "2026-08-20T18:36:03+00:00"}],
        created_at=1787247948.0,                        # 17:45:48Z
        completed_at=1787250963.0)                      # 18:36:03Z（run 同刻收尾）
    d = authed_client.get("/api/workspaces/CW/scans/s1").json()
    assert d["metrics"]["total_duration_ms"] == 3015000, \
        "created(1787247948)→end(1787250963) 墙钟 3015s，非 metrics 的 600000"


def test_scan_detail_recently_active_running(authed_client, tmp_workspaces):
    """scan heartbeat fresh -> status=running，不 500。"""
    import time as _time
    scan_dir = _scan_with(tmp_workspaces, "HostAlive", scan_id="s1", status=None,
                          created_at=_time.time(), completed_at=None)
    (scan_dir / "heartbeat").write_text(f"{_time.time()}\n")
    r = authed_client.get("/api/workspaces/HostAlive/scans/s1")
    assert r.status_code == 200 and r.json()["status"] == "running"


def test_scan_detail_normalizes_legacy_agents(authed_client, tmp_workspaces):
    """scan 详情归一化旧格式 metrics.agents（final_duration_ms/total_cost_usd -> 新 schema）。"""
    _scan_with(tmp_workspaces, "Legacy", scan_id="s1", status="completed",
        metrics={
            "total_duration_ms": 1000, "total_cost_usd": 8.79,
            "phases": {"recon": {"duration_ms": 1000, "duration_percentage": 100.0,
                                 "cost_usd": 8.79, "agent_count": 1}},
            "agents": {"recon": {
                "status": "success",
                "attempts": [{"attempt_number": 1, "duration_ms": 1000, "cost_usd": 8.79,
                              "success": True, "model": "claude-opus-4-7"}],
                "final_duration_ms": 1000, "total_cost_usd": 8.79,
                "model": "claude-opus-4-7", "checkpoint": "abc"}},
        })
    d = authed_client.get("/api/workspaces/Legacy/scans/s1").json()
    a = d["metrics"]["agents"]["recon"]
    assert a["cost_usd"] == 8.79 and a["duration_ms"] == 1000
    assert a["success"] is True and a["attempt_number"] == 1
    assert "final_duration_ms" not in a and "total_cost_usd" not in a and "attempts" not in a


def test_get_scan_detail_exposes_host_source_for_rerun(authed_client, tmp_workspaces):
    """详情返回非敏感 HOST 来源，供新建扫描重跑预填，不泄露实时引用语义。"""
    _make_scan(
        tmp_workspaces,
        "WS",
        scan_id="bb-host",
        scan_type="blackbox",
        host_config={
            "enabled": True,
            "source": "profile",
            "profile_id": "host_profile_1",
            "source_url": "https://hosts.example/hosts",
            "mappings": {"api.internal.example": "10.0.0.2", "admin.internal.example": "10.0.0.3"},
        },
    )
    d = authed_client.get("/api/workspaces/WS/scans/bb-host").json()
    assert d["host_profile_id"] == "host_profile_1"
    assert d["host_url"] is None
    assert d["host_source"] == "profile"
    assert d["host_mapping_count"] == 2


def test_scan_detail_exposes_combined_rerun_fields(authed_client, tmp_workspaces):
    """组合扫描 detail 返 bb_url + 认证档案引用（bb_auth_ref），供重跑预填黑盒段。

    D3 黑盒并入组合扫描后，列表行「重跑」是重建黑盒段的唯一路径——目标 url 与
    profile 模式认证档案（非敏感 profile_id/cred_ids 引用）须随 detail 暴露。
    前端 RerunPreset（authProfileId/authCredentialIds/url）早已就位等这组字段。
    """
    _make_scan(
        tmp_workspaces,
        "WS",
        scan_id="s-comb",
        combined=True,
        bb_url="https://target.example.com",
        bb_auth_ref={"profile_id": "auth_profile_1", "cred_id": None,
                     "cred_ids": ["cred-a", "cred-b"]},
    )
    d = authed_client.get("/api/workspaces/WS/scans/s-comb").json()
    assert d["bb_url"] == "https://target.example.com"
    assert d["auth_profile_id"] == "auth_profile_1"
    assert d["auth_credential_ids"] == ["cred-a", "cred-b"]


def test_scan_detail_combined_rerun_fields_inline_and_absent(authed_client, tmp_workspaces):
    """inline 认证（bb_auth_ref.profile_id=None）-> 档案字段 None + cred_ids 归一 []；
    纯白盒（无 bb_url/bb_auth_ref）-> 全空——不阻塞详情、不误导预填。"""
    _make_scan(
        tmp_workspaces, "WS", scan_id="s-inline",
        combined=True, bb_url="https://target.example.com",
        bb_auth_ref={"profile_id": None},
    )
    d = authed_client.get("/api/workspaces/WS/scans/s-inline").json()
    assert d["bb_url"] == "https://target.example.com"
    assert d["auth_profile_id"] is None
    assert d["auth_credential_ids"] == []
    # inline 登录配置仍在 scan-config.yaml 读路径（authentication 字段）
    assert d["authentication"] is None  # 无 scan-config.yaml -> None（既有语义）

    _make_scan(tmp_workspaces, "WS", scan_id="s-pure-wb")
    d2 = authed_client.get("/api/workspaces/WS/scans/s-pure-wb").json()
    assert d2["bb_url"] is None
    assert d2["auth_profile_id"] is None
    assert d2["auth_credential_ids"] == []


def test_scan_detail_bb_phase_merged_from_latest_run(authed_client, tmp_workspaces):
    """detail 的 bb_phase/bb_reason/progress 合并 latest run（与 list 同视图）。

    run 版本化（spec 2026-08-14 §5.2）后 bb_phase 下沉到 run 级 session，任务级停在
    precheck/pending；详情消费方（两段时间线 / ScanProgressOverview 的 eventsUrl 切换）
    按 run phase 消费——不合并则黑盒段永显「待接力」、run 级实时进度在详情页不可见。
    """
    from supernova_core.session import SessionManager
    from supernova_web.components.scan_store import ScanStore
    store = ScanStore(tmp_workspaces)
    wb_id, scan_dir = store.create_scan("WS", "http://e", "/code/x")
    SessionManager(scan_dir.parent).update_session(scan_dir, {
        "expected_agents": {"whitebox": 4, "blackbox": 2},
        "completed_agents": ["a", "b", "c", "d"]})  # 白盒 4 完成
    _, run_dir = store.create_blackbox_run("WS", wb_id)  # 任务 combined=True + run-1 pending
    SessionManager(run_dir.parent).update_session(run_dir, {
        "bb_phase": "running", "completed_agents": ["e"]})  # run-1 黑盒 1/2
    # 白盒 workflow 的根 session 可能已经先落 completed；组合 detail 仍应以后续黑盒阶段为准。
    SessionManager(scan_dir.parent).update_session(scan_dir, {"status": "completed"})
    d = authed_client.get(f"/api/workspaces/WS/scans/{wb_id}").json()
    assert d["combined"] is True
    assert d["status"] == "running"
    assert d["bb_phase"] == "running"  # 取自 latest run（任务级停在 pending）
    assert d["progress_pct"] == 77.5  # 与 list 同口径：55 + 45 × (5-4)/2
    # list/detail 一致（同 merge_latest_run_view 视图）
    lst = authed_client.get("/api/workspaces/WS/scans").json()
    row = next(s for s in lst if s["scan_id"] == wb_id)
    assert row["status"] == "running"
    assert row["bb_phase"] == "running" and row["progress_pct"] == 77.5


# ── resume-preview（spec 2026-08-27-web-resume-breakpoint §4.5）──────────────

def test_resume_preview_200(authed_client, app_with_ws):
    fake = FakeSM()
    app_with_ws.state.scan_manager = fake
    r = authed_client.get("/api/workspaces/WS/scans/s1/resume-preview")
    assert r.status_code == 200
    body = r.json()
    assert body["resumable"] is True
    assert body["completed_agents"] == ["pre-recon"]
    assert body["steps"][0]["state"] == "done"


def test_resume_preview_unknown_404(authed_client, app_with_ws):
    fake = FakeSM()
    fake.preview_exc = ValueError("scan 不存在")
    app_with_ws.state.scan_manager = fake
    assert authed_client.get(
        "/api/workspaces/WS/scans/nope/resume-preview").status_code == 404
