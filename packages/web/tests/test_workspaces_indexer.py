import json
import os

import pytest

from supernova_web.components.workspaces_indexer import WorkspacesIndexer


def _make_ws(root, name, status="completed", scan_type="whitebox", queues=None, nested=False):
    ws = root / name
    ws.mkdir(parents=True)
    data = {"status": status, "scan_type": scan_type,
            "created_at": "2026-07-02T10:00:00Z", "completed_at": "2026-07-02T10:05:00Z"}
    payload = {"session": data} if nested else data
    (ws / "session.json").write_text(json.dumps(payload))
    if queues:
        dl = ws / "deliverables" / "whitebox"
        dl.mkdir(parents=True)
        for cls, n in queues.items():
            (dl / f"{cls}_exploitation_queue.json").write_text(
                json.dumps({"vulnerabilities": [{}] * n}))


def test_completed_with_vuln_counts(tmp_workspaces):
    _make_ws(tmp_workspaces, "NodeGoat_x", status="completed", queues={"xss": 3, "ssrf": 1})
    rows = WorkspacesIndexer(tmp_workspaces).list_workspaces()
    assert len(rows) == 1
    assert rows[0]["name"] == "NodeGoat_x"
    assert rows[0]["status"] == "completed"
    assert rows[0]["vuln_counts"] == {"xss": 3, "ssrf": 1}


def test_nested_legacy_session_format(tmp_workspaces):
    _make_ws(tmp_workspaces, "Old_y", status="failed", scan_type="whitebox", nested=True)
    rows = WorkspacesIndexer(tmp_workspaces).list_workspaces()
    assert rows[0]["status"] == "failed"
    assert rows[0]["scan_type"] == "whitebox"


def test_interrupted_when_pid_alive_but_no_heartbeat(tmp_workspaces):
    """pid 表不再参与判活(spec §4.3):注入 alive pid 但无 heartbeat → interrupted。
    pid 表只服务 cancel(web 自起 SIGINT),不服务判活——避免「容器非 host PID namespace
    看不到 host pid 就判死」的误判(回归铁律:判活统一靠 heartbeat)。"""
    _make_ws(tmp_workspaces, "Run_z", status=None)
    idx = WorkspacesIndexer(tmp_workspaces)
    idx.set_active_pid("Run_z", os.getpid())  # alive pid,但不参与判活
    assert idx.list_workspaces()[0]["status"] == "interrupted"


def test_interrupted_when_no_pid_no_status(tmp_workspaces):
    _make_ws(tmp_workspaces, "Dead_w", status=None)
    # 无 heartbeat(死掉的孤儿,scan 早已停写)→ interrupted
    idx = WorkspacesIndexer(tmp_workspaces)
    assert idx.list_workspaces()[0]["status"] == "interrupted"


def test_running_when_heartbeat_fresh(tmp_workspaces):
    """回归:host CLI 起的活 scan,web 看不到其 pid(容器非 host PID namespace),但
    HeartbeatManager 持续写 heartbeat → _status_of 显 running 而非 interrupted
    (kol_mapping_service_20260708-193139 列表/详情被误标 interrupted 即此 bug)。
    判活信号源已从 workflow.log 换成 heartbeat(进程级、不受 LLM 卡顿影响)。"""
    import time
    _make_ws(tmp_workspaces, "HostAlive", status=None)
    ws = tmp_workspaces / "HostAlive"
    (ws / "heartbeat").write_text(f"{time.time()}\n")  # fresh heartbeat → scan 仍存活
    idx = WorkspacesIndexer(tmp_workspaces)
    assert idx.list_workspaces()[0]["status"] == "running"


def test_status_running_within_submit_grace(tmp_workspaces):
    """_status_of 在提交宽限内(无 heartbeat)→ running 而非 interrupted(防冷启动误杀).

    回归 hr_1784014329:提交后 1s 内 worker 还没写首个 heartbeat, _status_of 仅看 heartbeat 会
    判 interrupted, 且终态优先致后续 worker 写 heartbeat 也翻不回。宽限门据 submitted_at 判 running.
    """
    import time
    _make_ws(tmp_workspaces, "Cold", status=None)
    ws = tmp_workspaces / "Cold"
    (ws / "session.json").write_text(json.dumps({
        "status": "running", "scan_type": "whitebox", "submitted_at": time.time(),
    }))
    idx = WorkspacesIndexer(tmp_workspaces)
    assert idx.list_workspaces()[0]["status"] == "running"


def test_terminal_status_passed_through(tmp_workspaces):
    """显式终态集合(completed/failed/interrupted/cancelled/killed/crashed)→ 该终态
    (强信号,立即定;spec §4.3)。取代旧「只认 completed/failed + 兜底推断 interrupted」。"""
    for st in ("completed", "failed", "interrupted", "cancelled", "killed", "crashed"):
        _make_ws(tmp_workspaces, f"S_{st}", status=st)
    rows = {r["name"]: r["status"] for r in WorkspacesIndexer(tmp_workspaces).list_workspaces()}
    for st in ("completed", "failed", "interrupted", "cancelled", "killed", "crashed"):
        assert rows[f"S_{st}"] == st


def test_correlation_marked(tmp_workspaces):
    _make_ws(tmp_workspaces, "Cor_c", status="completed", scan_type="correlation")
    rows = WorkspacesIndexer(tmp_workspaces).list_workspaces()
    assert rows[0]["is_correlation"] is True


def test_sorts_by_created_at_desc(tmp_workspaces):
    _make_ws(tmp_workspaces, "A", )
    _make_ws(tmp_workspaces, "B")
    # B 的新 session 已写；用覆盖法给 A 更早
    (tmp_workspaces / "A" / "session.json").write_text(json.dumps(
        {"status": "completed", "scan_type": "whitebox",
         "created_at": "2026-01-01T00:00:00Z", "completed_at": "2026-01-01T00:05:00Z"}))
    names = [r["name"] for r in WorkspacesIndexer(tmp_workspaces).list_workspaces()]
    assert names[0] == "B"


def test_list_supplements_cost_duration_links_vuln_count(tmp_workspaces):
    """list_workspaces 补返 total_cost_usd/total_duration_ms/vuln_count(number)/links。"""
    import json
    ws = tmp_workspaces / "full-ws"
    ws.mkdir()
    (ws / "session.json").write_text(json.dumps({
        "status": "completed", "scan_type": "whitebox",
        "created_at": 1780000000.0,
        "metrics": {"total_cost_usd": 1.23, "total_duration_ms": 45000},
        "links": {"child_workspaces": ["child-a", "child-b"]},
    }))
    from supernova_web.components.workspaces_indexer import WorkspacesIndexer
    rows = WorkspacesIndexer(tmp_workspaces).list_workspaces()
    row = next(r for r in rows if r["name"] == "full-ws")
    assert row["total_cost_usd"] == 1.23
    assert row["total_duration_ms"] == 45000
    assert row["links"] == {"child_workspaces": ["child-a", "child-b"]}
    # vuln_count 是聚合后的 number（无漏洞数据 → 0）
    assert row["vuln_count"] == 0
    assert isinstance(row["vuln_count"], int)


def test_list_vuln_count_aggregates_dict(tmp_workspaces):
    """vuln_counts dict → vuln_count number（sum values）。"""
    import json
    ws = tmp_workspaces / "agg-ws"
    ws.mkdir()
    (ws / "session.json").write_text(json.dumps({
        "status": "completed", "scan_type": "whitebox", "created_at": 1,
    }))
    from supernova_web.components.workspaces_indexer import WorkspacesIndexer
    idx = WorkspacesIndexer(tmp_workspaces)
    # mock get_workspace_vuln_counts 返多类型 dict
    # T2: vuln_counts 由 ScanStore._summarize 算（get_workspace_vuln_counts 在 scan_store 模块）。
    # monkeypatch scan_store 模块的引用（非 workspaces_indexer，后者已不再直接调用）。
    import supernova_web.components.scan_store as store_mod
    orig = store_mod.get_workspace_vuln_counts
    store_mod.get_workspace_vuln_counts = lambda _p: {"injection": 3, "xss": 2}
    try:
        rows = idx.list_workspaces()
    finally:
        store_mod.get_workspace_vuln_counts = orig
    row = next(r for r in rows if r["name"] == "agg-ws")
    assert row["vuln_count"] == 5
    assert row["vuln_counts"] == {"injection": 3, "xss": 2}


def test_list_missing_metrics_returns_none(tmp_workspaces):
    """session.json 无 metrics → total_cost_usd/duration 为 None，不崩。"""
    import json
    ws = tmp_workspaces / "bare-ws"
    ws.mkdir()
    (ws / "session.json").write_text(json.dumps({
        "status": "completed", "scan_type": "whitebox", "created_at": 1,
    }))
    from supernova_web.components.workspaces_indexer import WorkspacesIndexer
    row = next(r for r in WorkspacesIndexer(tmp_workspaces).list_workspaces() if r["name"] == "bare-ws")
    assert row["total_cost_usd"] is None
    assert row["total_duration_ms"] is None
    assert row["cost_currency"] is None
    assert row["cost_by_currency"] is None
    assert row["links"] == {}


def test_list_exposes_cost_currency(tmp_workspaces):
    """row 补 cost_currency(前端 fmtCost 据此选 ¥/$,修首页 $ vs 详情页 ¥ 不一致)。

    前端 Workspace.cost_currency 字段早已声明、DashboardPage/WorkspaceListPage 早已读
    w.cost_currency;此前纯后端 workspaces_indexer 漏传 → undefined → 默认 $。"""
    import json
    ws = tmp_workspaces / "cur-ws"
    ws.mkdir()
    (ws / "session.json").write_text(json.dumps({
        "status": "completed", "scan_type": "whitebox", "created_at": 1,
        "metrics": {"total_cost_usd": 6.49, "cost_currency": "CNY"},
    }))
    from supernova_web.components.workspaces_indexer import WorkspacesIndexer
    row = next(r for r in WorkspacesIndexer(tmp_workspaces).list_workspaces() if r["name"] == "cur-ws")
    assert row["cost_currency"] == "CNY"
    assert row["total_cost_usd"] == 6.49


def test_sort_mixed_created_at_types(tmp_workspaces):
    """回归:created_at 类型混合(float | ISO-str | 缺失)时 sort 不能 TypeError。
    真实 workspaces 目录 24 项 = 14 float + 10 缺失,曾致 /api/workspaces 500
    (sort key `x.get("created_at") or ""` 让 None→str 与 float 不可比)。"""
    def _mk(name, body):
        ws = tmp_workspaces / name
        ws.mkdir()
        (ws / "session.json").write_text(json.dumps(body))
    _mk("ws-float", {"status": "completed", "scan_type": "whitebox", "created_at": 1780000000.0})
    _mk("ws-iso",   {"status": "completed", "scan_type": "whitebox", "created_at": "2026-01-01T00:00:00Z"})
    _mk("ws-none",  {"status": "completed", "scan_type": "whitebox"})
    rows = WorkspacesIndexer(tmp_workspaces).list_workspaces()
    assert len(rows) == 3                    # 不抛 TypeError
    assert rows[0]["name"] == "ws-float"     # float(≈2026)最新,排最前


def test__to_unix_normalizes_mixed_created_at_types():
    """_to_unix 归一 created_at 为 unix float|None:float/int 直用、ISO str 解析、None/异常→None。
    修后端透传 ISO str 致前端 Workspace.created_at(number) Invalid Date 的契约断裂。"""
    from supernova_web.components.workspaces_indexer import _to_unix
    assert _to_unix(1780000000.0) == 1780000000.0
    assert _to_unix(1780000000) == 1780000000.0
    iso_ts = _to_unix("2026-05-29T10:00:00Z")
    assert isinstance(iso_ts, float) and iso_ts > 1_700_000_000  # 合理 unix epoch
    from datetime import datetime, timezone
    assert datetime.fromtimestamp(iso_ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M") == "2026-05-29T10:00"
    assert _to_unix(None) is None
    assert _to_unix("not-a-date") is None


def test_list_created_at_is_unix_number(tmp_workspaces):
    """row.created_at/completed_at 是 unix number(前端 Workspace.created_at: number),非 ISO str。"""
    ws = tmp_workspaces / "Float"
    ws.mkdir()
    (ws / "session.json").write_text(json.dumps({
        "status": "completed", "scan_type": "whitebox",
        "created_at": 1780000000.0, "completed_at": 1780000005.0,
    }))
    rows = WorkspacesIndexer(tmp_workspaces).list_workspaces()
    row = next(r for r in rows if r["name"] == "Float")
    assert isinstance(row["created_at"], float)
    assert row["created_at"] == 1780000000.0
    assert isinstance(row["completed_at"], float)
    assert row["completed_at"] == 1780000005.0


# ── T2: 1 ws : N scans 聚合 ─────────────────────────────────────────────────

def test_list_empty_ws_with_workspace_json(tmp_workspaces):
    """空 ws（workspace.json + 无 scan）-> scan_count=0、status=completed（idle）。"""
    from supernova_web.components.scan_store import write_workspace_meta
    ws = tmp_workspaces / "empty-ws"
    ws.mkdir()
    write_workspace_meta(ws, name="empty-ws", owner="admin")
    rows = WorkspacesIndexer(tmp_workspaces).list_workspaces()
    row = next(r for r in rows if r["name"] == "empty-ws")
    assert row["scan_count"] == 0
    assert row["status"] == "completed"
    assert row["latest_status"] == "completed"
    assert row["vuln_count"] == 0
    assert row["latest_created_at"] is not None  # ws 元数据 created_at


def test_list_ws_multiple_scans_aggregated(tmp_workspaces):
    """ws（workspace.json + 2 scan）-> scan_count=2、latest_* 取最新 scan。"""
    from supernova_web.components.scan_store import ScanStore, write_workspace_meta
    ws = tmp_workspaces / "multi-ws"
    ws.mkdir()
    write_workspace_meta(ws, name="multi-ws", owner="admin")
    store = ScanStore(tmp_workspaces)
    _, d1 = store.create_scan("multi-ws", "http://e", "/x")
    # 第一个 scan 标 completed（旧）
    import json as _json
    s1 = _json.loads((d1 / "session.json").read_text())
    s1["status"] = "completed"; s1["created_at"] = 1780000000.0
    (d1 / "session.json").write_text(_json.dumps(s1))
    _, d2 = store.create_scan("multi-ws", "http://e", "/x")
    s2 = _json.loads((d2 / "session.json").read_text())
    s2["status"] = "failed"; s2["created_at"] = 1780003600.0  # 更新
    (d2 / "session.json").write_text(_json.dumps(s2))
    rows = WorkspacesIndexer(tmp_workspaces).list_workspaces()
    row = next(r for r in rows if r["name"] == "multi-ws")
    assert row["scan_count"] == 2
    assert row["status"] == "failed"          # 最新 scan 的 status
    assert row["latest_status"] == "failed"
    assert row["latest_created_at"] == 1780003600.0


def test_list_ws_stats_aggregate_all_scans(tmp_workspaces):
    """统计字段（vuln/cost/duration）跨全部 scans 聚合，状态/时间仍取最新。

    对齐工作区页头部「累计发现/累计花费」口径（WorkspaceDetail agg = scans.reduce）。
    回归 1（25731b62）：Brightli 43 漏洞被新起 running scan 清零——sum 语义下无产出
    scan 贡献 0，不清零。回归 2（本修复）：「取最近 completed 单条」致切换器只显
    第一条任务的数字，与工作区页总数不一致。"""
    from supernova_web.components.scan_store import ScanStore, write_workspace_meta
    ws = tmp_workspaces / "stats-ws"
    ws.mkdir()
    write_workspace_meta(ws, name="stats-ws", owner="admin")
    store = ScanStore(tmp_workspaces)
    # 旧 scan：completed + injection queue 3 条 + cost/duration
    _, d1 = store.create_scan("stats-ws", "http://e", "/x")
    s1 = json.loads((d1 / "session.json").read_text())
    s1["status"] = "completed"; s1["created_at"] = 1780000000.0
    s1["metrics"] = {"total_cost_usd": 1.5, "cost_currency": "CNY",
                     "total_duration_ms": 45000}
    (d1 / "session.json").write_text(json.dumps(s1))
    dl = d1 / "deliverables" / "whitebox"
    dl.mkdir(parents=True)
    (dl / "injection_exploitation_queue.json").write_text(
        json.dumps({"vulnerabilities": [{}] * 3}))
    # 第二条 completed：xss 2 条 + cost/duration（同币种）
    _, d2 = store.create_scan("stats-ws", "http://e", "/x")
    s2 = json.loads((d2 / "session.json").read_text())
    s2["status"] = "completed"; s2["created_at"] = 1780001800.0
    s2["metrics"] = {"total_cost_usd": 3.25, "cost_currency": "CNY",
                     "total_duration_ms": 15000}
    (d2 / "session.json").write_text(json.dumps(s2))
    dl2 = d2 / "deliverables" / "whitebox"
    dl2.mkdir(parents=True)
    (dl2 / "xss_exploitation_queue.json").write_text(
        json.dumps({"vulnerabilities": [{}] * 2}))
    # 最新 scan：interrupted（终态、无产物——不依赖 heartbeat 判活）
    _, d3 = store.create_scan("stats-ws", "http://e", "/x")
    s3 = json.loads((d3 / "session.json").read_text())
    s3["status"] = "interrupted"; s3["created_at"] = 1780003600.0
    (d3 / "session.json").write_text(json.dumps(s3))
    rows = WorkspacesIndexer(tmp_workspaces).list_workspaces()
    row = next(r for r in rows if r["name"] == "stats-ws")
    # 状态/时间取最新（动态）
    assert row["status"] == "interrupted"
    assert row["latest_status"] == "interrupted"
    assert row["latest_created_at"] == 1780003600.0
    # 统计跨全部 scans 聚合（无产出的 interrupted 贡献 0，不清零）
    assert row["vuln_count"] == 5
    assert row["vuln_counts"] == {"injection": 3, "xss": 2}
    assert row["total_cost_usd"] == 4.75
    assert row["cost_currency"] == "CNY"
    assert row["cost_by_currency"] == {"CNY": 4.75}
    assert row["total_duration_ms"] == 60000


def test_list_ws_cost_by_currency_splits_mixed_currencies(tmp_workspaces):
    """混合币种：cost_by_currency 分币种分组（跨币种直加是错值——对齐 WorkspaceDetail
    头部 / Dashboard tileCost 口径）；total_cost_usd/cost_currency 保留 last-wins+直加
    兼容口径（CLAUDE.md §4 metrics_tracker），正确展示走 cost_by_currency。"""
    from supernova_web.components.scan_store import ScanStore, write_workspace_meta
    ws = tmp_workspaces / "mixed-ws"
    ws.mkdir()
    write_workspace_meta(ws, name="mixed-ws", owner="admin")
    store = ScanStore(tmp_workspaces)
    _, d1 = store.create_scan("mixed-ws", "http://e", "/x")
    s1 = json.loads((d1 / "session.json").read_text())
    s1["status"] = "completed"; s1["created_at"] = 1780000000.0
    s1["metrics"] = {"total_cost_usd": 1.5, "cost_currency": "CNY"}
    (d1 / "session.json").write_text(json.dumps(s1))
    _, d2 = store.create_scan("mixed-ws", "http://e", "/x")
    s2 = json.loads((d2 / "session.json").read_text())
    s2["status"] = "completed"; s2["created_at"] = 1780001800.0
    s2["metrics"] = {"total_cost_usd": 2.0, "cost_currency": "USD"}
    (d2 / "session.json").write_text(json.dumps(s2))
    rows = WorkspacesIndexer(tmp_workspaces).list_workspaces()
    row = next(r for r in rows if r["name"] == "mixed-ws")
    assert row["cost_by_currency"] == {"CNY": 1.5, "USD": 2.0}
    # 兼容字段：直加 + 最新优先币种（metrics_tracker 口径）
    assert row["total_cost_usd"] == 3.5
    assert row["cost_currency"] == "USD"


def test_list_ws_stats_sum_failed_partial_output(tmp_workspaces):
    """failed-only ws：failed scan 失败前的部分产出计入累计（sum 语义天然保留，
    不因「无 completed」清零——对齐 WorkspaceDetail 全量聚合口径）。"""
    from supernova_web.components.scan_store import ScanStore, write_workspace_meta
    ws = tmp_workspaces / "fallback-ws"
    ws.mkdir()
    write_workspace_meta(ws, name="fallback-ws", owner="admin")
    store = ScanStore(tmp_workspaces)
    _, d1 = store.create_scan("fallback-ws", "http://e", "/x")
    s1 = json.loads((d1 / "session.json").read_text())
    s1["status"] = "failed"; s1["created_at"] = 1780000000.0
    (d1 / "session.json").write_text(json.dumps(s1))
    dl = d1 / "deliverables" / "whitebox"
    dl.mkdir(parents=True)
    (dl / "ssrf_exploitation_queue.json").write_text(
        json.dumps({"vulnerabilities": [{}] * 2}))
    rows = WorkspacesIndexer(tmp_workspaces).list_workspaces()
    row = next(r for r in rows if r["name"] == "fallback-ws")
    assert row["status"] == "failed"
    assert row["vuln_count"] == 2  # 部分产出计入累计，不清零


def test_list_legacy_ws_root_session_count_1(tmp_workspaces):
    """legacy ws（ws 根 session.json，未迁移）-> scan_count=1（双源兼容）。"""
    _make_ws(tmp_workspaces, "legacy-ws", status="completed")
    rows = WorkspacesIndexer(tmp_workspaces).list_workspaces()
    row = next(r for r in rows if r["name"] == "legacy-ws")
    assert row["scan_count"] == 1
    assert row["status"] == "completed"


def test_list_row_has_aggregation_fields(tmp_workspaces):
    """row 含 scan_count/latest_status/latest_created_at 三个新字段（spec §5.3）。"""
    _make_ws(tmp_workspaces, "fields-ws", status="completed")
    row = WorkspacesIndexer(tmp_workspaces).list_workspaces()[0]
    assert "scan_count" in row
    assert "latest_status" in row
    assert "latest_created_at" in row


def test_list_workspaces_skips_dot_dir(tmp_workspaces):
    # .system 段即便被 out-of-band 放了 workspace.json，也不得出现在 ws 列表
    from supernova_web.components.scan_store import write_workspace_meta
    sys_dir = tmp_workspaces / ".system"
    sys_dir.mkdir(parents=True)
    write_workspace_meta(sys_dir, name=".system", owner="sys")
    _make_ws(tmp_workspaces, "realws")
    rows = WorkspacesIndexer(tmp_workspaces).list_workspaces()
    names = {r["name"] for r in rows}
    assert ".system" not in names
    assert "realws" in names
