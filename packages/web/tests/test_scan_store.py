"""T1: ScanStore — 1 ws : N scans 存储层。

create_scan 落 workspaces/<ws>/scans/<scan_id>/session.json（复用 core
SessionManager(scans_dir) 的 create_workspace）；list_scans 双源合并（scans/<id>/
新 scan + ws 根 legacy session.json），按 created_at 倒序；get_scan_dir 路径校验
拒越界（..///）；latest_scan 取最新。

core SessionManager 的读写方法只收 workspace_path，故 SessionManager(ws_dir/"scans")
把 scans 目录当 workspaces 根即可复用全部 scan 读写——core 零改动（CLAUDE.md §1
铁律不碰，core session.py 不改）。
"""
import json
from datetime import datetime

import pytest

from supernova_core.session import SessionManager

from supernova_web.components.scan_store import ScanStore, ScanSummary


def _make_legacy_root_scan(ws_dir, created_at=1780000000.0, status="completed",
                           scan_type="whitebox"):
    """在 ws 根写 legacy session.json（模拟 CLI/worker.py 旧路径产出的 scan）。"""
    ws_dir.mkdir(parents=True, exist_ok=True)
    (ws_dir / "session.json").write_text(json.dumps({
        "status": status, "scan_type": scan_type, "created_at": created_at,
        "web_url": "", "repo_path": "",
    }))


# ── create_scan ────────────────────────────────────────────────────────────

def test_create_scan_lands_in_scans_subdir(tmp_path):
    store = ScanStore(tmp_path)
    scan_id, scan_dir = store.create_scan("WS1", "http://e", "/code/x")
    assert scan_dir == tmp_path / "WS1" / "scans" / scan_id
    assert (scan_dir / "session.json").exists()
    sess = json.loads((scan_dir / "session.json").read_text())
    assert sess["web_url"] == "http://e"
    assert sess["repo_path"] == "/code/x"
    assert sess["status"] == "running"
    assert sess["scan_type"] == "whitebox"


def test_create_scan_id_format(tmp_path):
    """scan_id = <repo>-YYYYMMDD-HHMMSS（仓库名前缀 + 本地时区紧凑秒级）。"""
    store = ScanStore(tmp_path)
    scan_id, _ = store.create_scan("WS", "u", "/code/NodeGoat")
    # 形如 NodeGoat-20260729-171759
    assert scan_id.startswith("NodeGoat-")
    ts = scan_id[len("NodeGoat-"):]
    assert len(ts) == 15 and ts[8] == "-"  # YYYYMMDD-HHMMSS


def test_create_scan_same_second_collision(monkeypatch, tmp_path):
    """同秒同名碰撞 -> 第二个追加 -2（_gen_scan_id 序号）。"""
    import supernova_web.components.scan_store as mod
    fixed = datetime(2026, 7, 27, 14, 30, 0)
    monkeypatch.setattr(mod, "_now_local", lambda: fixed)
    store = ScanStore(tmp_path)
    id1, _ = store.create_scan("WS", "u", "/x")
    id2, _ = store.create_scan("WS", "u", "/x")
    assert id1 == "x-20260727-143000"
    assert id2 == "x-20260727-143000-2"
    # 第三个 -3
    id3, _ = store.create_scan("WS", "u", "/x")
    assert id3 == "x-20260727-143000-3"


def test_create_scan_repo_name_prefix(tmp_path):
    """scan_id 以仓库名（repo_path basename）为前缀；空 repo_path fallback 'repo'。"""
    store = ScanStore(tmp_path)
    sid_repo, _ = store.create_scan("WS", "u", "/code/NodeGoat")
    assert sid_repo.startswith("NodeGoat-")
    sid_empty, _ = store.create_scan("WS", "u", "")
    assert sid_empty.startswith("repo-")


# ── list_scans（双源）────────────────────────────────────────────────────────

def test_list_scans_new_scan_only(tmp_path):
    store = ScanStore(tmp_path)
    store.create_scan("WS1", "http://e", "/x")
    scans = store.list_scans("WS1")
    assert len(scans) == 1
    assert isinstance(scans[0], ScanSummary)
    assert scans[0].scan_type == "whitebox"


def test_list_scans_empty_ws(tmp_path):
    """无 scan 的 ws（仅 workspace.json/repos，或新建空 ws）-> 空列表。"""
    store = ScanStore(tmp_path)
    (tmp_path / "WS").mkdir()
    assert store.list_scans("WS") == []
    assert store.list_scans("NOPE") == []


def test_list_scans_dual_source_new_plus_legacy(tmp_path):
    """双源：scans/<id>/ 新 scan + ws 根 legacy session.json，合并按 created_at 倒序。"""
    store = ScanStore(tmp_path)
    # legacy 根 scan（旧 created_at）
    _make_legacy_root_scan(tmp_path / "WS1", created_at=1780000000.0)
    # 新 scan（更新 created_at）
    new_id, _ = store.create_scan("WS1", "http://e", "/x")
    scans = store.list_scans("WS1")
    assert len(scans) == 2
    # 新 scan created_at > legacy -> 排第一
    assert scans[0].scan_id == new_id
    # legacy 排第二
    assert scans[1].scan_id != new_id
    assert scans[1].created_at == 1780000000.0


def test_list_scans_multiple_new_scans_sorted_desc(tmp_path):
    """同 ws 多个新 scan，按 created_at 倒序。"""
    store = ScanStore(tmp_path)
    # 建三个 scan（同秒 scan_id 碰撞 -2/-3），再各自覆盖 created_at 拉开时间。
    createds = [1780000000.0, 1780003600.0, 1780001800.0]  # 10:00 / 11:00 / 11:30 派生
    dirs = []
    for _ in range(3):
        _, d = store.create_scan("WS", "u", "/x")
        dirs.append(d)
    for d, c in zip(dirs, createds):
        sess = json.loads((d / "session.json").read_text())
        sess["created_at"] = c
        (d / "session.json").write_text(json.dumps(sess))
    scans = store.list_scans("WS")
    assert len(scans) == 3
    # createds[1](11:00 派生) > createds[2] > createds[0]
    assert scans[0].created_at == createds[1]
    assert scans[1].created_at == createds[2]
    assert scans[2].created_at == createds[0]


# ── get_scan_dir（路径校验 + 双源定位）────────────────────────────────────────

def test_get_scan_dir_new_scan(tmp_path):
    store = ScanStore(tmp_path)
    new_id, new_dir = store.create_scan("WS", "u", "/x")
    assert store.get_scan_dir("WS", new_id) == new_dir


def test_get_scan_dir_legacy_root(tmp_path):
    """legacy ws 根 scan：get_scan_dir 据派生 legacy_id 定位回 ws 根。"""
    store = ScanStore(tmp_path)
    _make_legacy_root_scan(tmp_path / "WS2", created_at=1780000000.0)
    legacy_id = store._legacy_scan_id(tmp_path / "WS2")
    assert store.get_scan_dir("WS2", legacy_id) == tmp_path / "WS2"


def test_get_scan_dir_unknown_returns_none(tmp_path):
    store = ScanStore(tmp_path)
    store.create_scan("WS", "u", "/x")
    assert store.get_scan_dir("WS", "nonexistent") is None


def test_get_scan_dir_rejects_traversal(tmp_path):
    r"""路径校验：scan_id 含 .. / 正斜杠 / 反斜杠 -> None（防越界读其他目录）。"""
    store = ScanStore(tmp_path)
    store.create_scan("WS", "u", "/x")
    assert store.get_scan_dir("WS", "..") is None
    assert store.get_scan_dir("WS", "../..") is None
    assert store.get_scan_dir("WS", "foo/bar") is None
    assert store.get_scan_dir("WS", "foo\\bar") is None
    assert store.get_scan_dir("WS", "") is None


# ── latest_scan ────────────────────────────────────────────────────────────

def test_latest_scan_returns_newest(tmp_path):
    store = ScanStore(tmp_path)
    _make_legacy_root_scan(tmp_path / "WS", created_at=1780000000.0)
    new_id, new_dir = store.create_scan("WS", "u", "/x")
    assert store.latest_scan("WS") == new_dir


def test_latest_scan_prefers_running_over_newer_completed(tmp_path):
    """active 优先：更新的已完成 scan + 较旧的在跑 scan -> 返回在跑的那个。

    shim DELETE /api/scan/{ws} cancel latest/active 依赖此：同 ws 多 scan 时 cancel
    正在跑的，而非更新的已完成 scan（spec §5.2 latest_scan active 优先）。
    """
    import time
    store = ScanStore(tmp_path)
    # 较旧的 scan，标 running + fresh heartbeat（在跑）
    _, running_dir = store.create_scan("WS", "u", "/x")
    sess = json.loads((running_dir / "session.json").read_text())
    sess["created_at"] = 1780000000.0  # 较旧
    sess["status"] = "running"
    (running_dir / "session.json").write_text(json.dumps(sess))
    (running_dir / "heartbeat").write_text(f"{time.time()}\n")  # fresh -> running
    # 更新的 scan，标 completed（不在跑）
    _, done_dir = store.create_scan("WS", "u", "/x")
    sess2 = json.loads((done_dir / "session.json").read_text())
    sess2["created_at"] = 1780003600.0  # 更新
    sess2["status"] = "completed"
    (done_dir / "session.json").write_text(json.dumps(sess2))
    # active 优先 -> 返回 running_dir（虽更旧），而非 done_dir（更新但已完成）
    assert store.latest_scan("WS") == running_dir


def test_latest_scan_legacy_only(tmp_path):
    """只有 legacy 根 scan -> latest_scan 返回 ws 根。"""
    store = ScanStore(tmp_path)
    _make_legacy_root_scan(tmp_path / "WS", created_at=1780000000.0)
    assert store.latest_scan("WS") == tmp_path / "WS"


def test_latest_scan_empty_returns_none(tmp_path):
    store = ScanStore(tmp_path)
    assert store.latest_scan("NOPE") is None


# ── ScanSummary 字段 ─────────────────────────────────────────────────────────

def test_scan_summary_fields_cost_vuln_running(tmp_path):
    """ScanSummary 聚合 vuln_count/total_cost_usd/cost_currency/is_running。"""
    store = ScanStore(tmp_path)
    new_id, scan_dir = store.create_scan("WS", "u", "/x")
    # 写 metrics + 漏洞 queue + 标 completed
    (scan_dir / "deliverables" / "whitebox").mkdir(parents=True)
    (scan_dir / "deliverables" / "whitebox" / "xss_exploitation_queue.json").write_text(
        json.dumps({"vulnerabilities": [{}, {}]}))
    sess = json.loads((scan_dir / "session.json").read_text())
    sess["metrics"] = {"total_cost_usd": 1.5, "cost_currency": "CNY"}
    sess["status"] = "completed"
    (scan_dir / "session.json").write_text(json.dumps(sess))
    s = store.list_scans("WS")[0]
    assert s.vuln_count == 2
    assert s.total_cost_usd == 1.5
    assert s.cost_currency == "CNY"
    assert s.status == "completed"
    assert s.is_running is False
    assert isinstance(s.created_at, float)


def test_scan_summary_running_when_heartbeat_fresh(tmp_path):
    """新 scan 无终态 + heartbeat fresh -> status=running, is_running=True。"""
    import time
    store = ScanStore(tmp_path)
    _, scan_dir = store.create_scan("WS", "u", "/x")
    (scan_dir / "heartbeat").write_text(f"{time.time()}\n")
    s = store.list_scans("WS")[0]
    assert s.status == "running"
    assert s.is_running is True


# ── workflow_id（前端任务名展示）──────────────────────────────────────────────

def test_scan_summary_workflow_id(tmp_path):
    """展示名 workflow_id = {scan_id}[-resume-N]（剥 {ws}- 前缀，任务名不带工作区名）。"""
    store = ScanStore(tmp_path)
    new_id, scan_dir = store.create_scan("WS1", "u", "/x")
    s = store.list_scans("WS1")[0]
    # 首次（无 resumeAttempts）：展示名剥 {ws}- 前缀 -> {scan_id}
    assert s.workflow_id == new_id
    assert s.as_dict()["workflow_id"] == new_id
    # 写 resumeAttempts（模拟已 resume 1 次）-> 加 -resume-1（ws 前缀仍剥）
    sess = json.loads((scan_dir / "session.json").read_text())
    sess["resumeAttempts"] = [{"at": 1}]
    (scan_dir / "session.json").write_text(json.dumps(sess))
    s2 = store.list_scans("WS1")[0]
    assert s2.workflow_id == f"{new_id}-resume-1"


def test_scan_summary_workflow_id_legacy(tmp_path):
    """legacy ws 根 scan 展示名 = {legacy_id}（剥 {ws}- 前缀）。"""
    store = ScanStore(tmp_path)
    _make_legacy_root_scan(tmp_path / "WS2", created_at=1780000000.0)
    s = store.list_scans("WS2")[0]
    legacy_id = store._legacy_scan_id(tmp_path / "WS2")
    assert s.workflow_id == legacy_id


def test_scan_summary_workflow_id_prefers_ndjson_header(tmp_path):
    """events.ndjson 首行 WorkflowHeader.workflow_id 是真实 temporal id（single source of
    truth）——CLI/legacy scan 的 workflow_id = workspace_name（CLI scheme），与 web scan 的
    {ws}-{scan_id}（web scheme）不同，算不出来只能读。有 ndjson 时优先读，覆盖算的值。

    真机 sentinel_dashboard scan 即此结构：scan_id=20260721-121435（migration 派生），
    但 ndjson WorkflowHeader.workflow_id=sentinel_dashboard_20260721-201435（CLI workspace_name）。
    """
    store = ScanStore(tmp_path)
    new_id, scan_dir = store.create_scan("WS1", "u", "/x")
    (scan_dir / "events.ndjson").write_text(
        json.dumps({"ts": "2026-07-21 20:14:35", "category": "HEADER",
                    "type": "WorkflowHeader",
                    "workflow_id": "sentinel_dashboard_20260721-201435"}) + "\n"
    )
    s = store.list_scans("WS1")[0]
    assert s.workflow_id == "sentinel_dashboard_20260721-201435"
    assert s.workflow_id != f"WS1-{new_id}"  # 不是算的 web scheme


def test_resolve_workflow_id_strips_ws_prefix(tmp_path):
    """展示层 resolve_workflow_id 剥 {ws}- 前缀：web scheme 真实 id {ws}-{scan_id} -> 展示名
    {scan_id}（前端任务名不再带工作区名——ws 上下文前端已知 / 跨 ws 表格另有独立 ws 列）；
    CLI scheme workspace_name 不以 {ws}- 开头 -> 不误剥，原样返回。真实 temporal id 不变。"""
    from supernova_web.components.scan_store import resolve_workflow_id
    store = ScanStore(tmp_path)
    new_id, scan_dir = store.create_scan("WS1", "u", "/code/NodeGoat")
    # fallback（无 ndjson）：真实 id {ws}-{scan_id} -> 展示名 {scan_id}
    assert resolve_workflow_id("WS1", scan_dir, new_id) == new_id
    # ndjson web scheme：真实 id {ws}-{scan_id} -> 展示名 {scan_id}
    (scan_dir / "events.ndjson").write_text(
        json.dumps({"type": "WorkflowHeader", "workflow_id": f"WS1-{new_id}"}) + "\n")
    assert resolve_workflow_id("WS1", scan_dir, new_id) == new_id
    # CLI scheme workspace_name：不以 {ws}- 开头 -> 不误剥，原样
    (scan_dir / "events.ndjson").write_text(
        json.dumps({"type": "WorkflowHeader",
                    "workflow_id": "sentinel_dashboard_20260721-201435"}) + "\n")
    assert resolve_workflow_id("WS1", scan_dir, new_id) == "sentinel_dashboard_20260721-201435"


# ── delete_scan（双源删除）────────────────────────────────────────────────────

def test_delete_scan_new_scan_removes_dir(tmp_path):
    """源① scans/<id>/：delete_scan 后整个 scan 目录消失，list_scans 不再返回。"""
    store = ScanStore(tmp_path)
    new_id, scan_dir = store.create_scan("WS", "u", "/x")
    # 写点产物，确认整目录删干净
    (scan_dir / "deliverables").mkdir()
    (scan_dir / "events.ndjson").write_text('{"type":"scan_end"}\n')
    assert store.delete_scan("WS", new_id) is True
    assert not scan_dir.exists()
    assert store.get_scan_dir("WS", new_id) is None
    assert store.list_scans("WS") == []


def test_delete_scan_unknown_returns_false(tmp_path):
    """scan 不存在 -> 返回 False（不抛，端点据此 404）。"""
    store = ScanStore(tmp_path)
    store.create_scan("WS", "u", "/x")
    assert store.delete_scan("WS", "nonexistent") is False


def test_delete_scan_rejects_traversal(tmp_path):
    """路径校验同 get_scan_dir：scan_id 含 ../// -> False（防越界删其他目录）。"""
    store = ScanStore(tmp_path)
    store.create_scan("WS", "u", "/x")
    assert store.delete_scan("WS", "..") is False
    assert store.delete_scan("WS", "foo/bar") is False
    assert store.delete_scan("WS", "") is False


def test_delete_scan_legacy_root_removes_products_keeps_ws_shell(tmp_path):
    """源② legacy ws 根 scan：删 scan 产物（session.json/events.ndjson/deliverables），
    保留 ws 壳 + ws 级元数据（workspace.json/config.yaml）+ 其他新 scan（scans/）+ repo。

    legacy scan 产物散落 ws 根，但 ws 根同时是 workspace 容器——删 scan 不能 rmtree 整个 ws
    （会连带删 workspace.json / 其他 scan / repo）。迁移机制通常已把根 scan 搬进 __legacy__/scans/
    （变源①），源②仅残留于迁移跳过（损坏 session / 带 config.yaml 的 ws）的边缘情况。
    """
    from supernova_web.components.scan_store import write_workspace_meta
    store = ScanStore(tmp_path)
    ws_dir = tmp_path / "WS"
    ws_dir.mkdir()
    # ws 级元数据 + 其他新 scan 子目录 + ws 级配置（必须保留）
    write_workspace_meta(ws_dir, name="WS", owner="admin")
    other = ws_dir / "scans" / "other-20260730-120000"
    other.mkdir(parents=True)
    (other / "session.json").write_text(
        json.dumps({"status": "completed", "created_at": 1780003600.0}))
    (ws_dir / "config.yaml").write_text("ai: x")
    (ws_dir / "repos").mkdir()
    # legacy scan 产物（必须删）
    _make_legacy_root_scan(ws_dir, created_at=1780000000.0)
    (ws_dir / "events.ndjson").write_text('{"type":"scan_end"}\n')
    (ws_dir / "deliverables").mkdir()
    legacy_id = store._legacy_scan_id(ws_dir)

    assert store.delete_scan("WS", legacy_id) is True
    # scan 产物已删
    assert not (ws_dir / "session.json").exists()
    assert not (ws_dir / "events.ndjson").exists()
    assert not (ws_dir / "deliverables").exists()
    # ws 壳 + ws 级元数据 + 其他 scan + repo 保留
    assert ws_dir.exists()
    assert (ws_dir / "workspace.json").exists()
    assert (ws_dir / "config.yaml").exists()
    assert (ws_dir / "repos").exists()
    assert (other / "session.json").exists()
    # legacy scan 不再列出（其他新 scan 仍在）
    ids = [s.scan_id for s in store.list_scans("WS")]
    assert legacy_id not in ids
    assert "other-20260730-120000" in ids


# ── blackbox scan_id（白盒血缘前缀 <wb>~<N>）──────────────────────────────────

def test_create_scan_blackbox_uses_lineage_prefix_with_seq(tmp_path):
    """黑盒 scan_id = <wb_scan_id>~<N>:整段白盒 scan_id 作血缘前缀,序号从 1 起。"""
    store = ScanStore(tmp_path)
    wb = "NodeGoat-20260803-1200"
    sid1, _ = store.create_scan("WS", "u", "", scan_type="blackbox", lineage=wb)
    assert sid1 == "NodeGoat-20260803-1200~1"
    sid2, _ = store.create_scan("WS", "u", "", scan_type="blackbox", lineage=wb)
    assert sid2 == "NodeGoat-20260803-1200~2"
    # 不同白盒独立序号空间
    sid_other, _ = store.create_scan("WS", "u", "", scan_type="blackbox",
                                     lineage="NodeGoat-20260804-0900")
    assert sid_other == "NodeGoat-20260804-0900~1"


def test_create_scan_whitebox_format_unchanged(tmp_path):
    """回归保护:白盒 scan_id 格式不变(<repo>-YYYYMMDD-HHMMSS),不含 ~。"""
    store = ScanStore(tmp_path)
    sid, _ = store.create_scan("WS", "u", "/code/NodeGoat")  # 默认 whitebox,不传 lineage
    assert sid.startswith("NodeGoat-")
    assert "~" not in sid


def test_create_scan_id_label_avoids_repo_task_namespace(monkeypatch, tmp_path):
    """id_label 只改 scan_id 前缀，不改 session.repo_path。

    回归场景：跨仓主行先创建，同秒 frontend 子仓不应被迫变成 frontend-...-2。
    """
    import supernova_web.components.scan_store as mod
    fixed = datetime(2026, 9, 9, 18, 0, 0)
    monkeypatch.setattr(mod, "_now_local", lambda: fixed)
    store = ScanStore(tmp_path)
    main_id, main_dir = store.create_scan(
        "WS", "u", "/code/frontend", "correlation", id_label="cross-repo")
    child_id, _ = store.create_scan("WS", "u", "/code/frontend")
    assert main_id == "cross-repo-20260909-180000"
    assert child_id == "frontend-20260909-180000"
    data = json.loads((main_dir / "session.json").read_text())
    assert data["repo_path"] == "/code/frontend"


def test_create_scan_blackbox_requires_lineage(tmp_path):
    """黑盒无 lineage → ValueError(黑盒恒复用白盒,lineage 必填,防御性校验)。"""
    store = ScanStore(tmp_path)
    with pytest.raises(ValueError):
        store.create_scan("WS", "u", "", scan_type="blackbox", lineage=None)


# ── create_blackbox_run（嵌套 run-K 子目录，spec §4/§5.1）──────────────────────

def test_create_blackbox_run_allocates_run1_under_task(tmp_path):
    store = ScanStore(tmp_path)
    wb_id, wb_dir = store.create_scan("WS", "http://e", "/code/x")  # 白盒任务根
    run_id, run_dir = store.create_blackbox_run("WS", wb_id)
    assert run_id == "run-1"
    assert run_dir == wb_dir / "blackbox-runs" / "run-1"
    assert (run_dir / "session.json").exists()
    run_sess = json.loads((run_dir / "session.json").read_text())
    assert run_sess["status"] == "pending"
    assert run_sess["bb_phase"] == "pending"
    # 任务级 session 索引 bb_runs[] + latest_bb_run + combined
    task_sess = json.loads((wb_dir / "session.json").read_text())
    assert task_sess["combined"] is True
    assert task_sess["latest_bb_run"] == "run-1"
    assert task_sess["bb_runs"] == [{"run_id": "run-1", "status": "pending"}]


def test_create_blackbox_run_monotonic_per_task(tmp_path):
    store = ScanStore(tmp_path)
    wb_id, wb_dir = store.create_scan("WS", "http://e", "/code/x")
    r1, _ = store.create_blackbox_run("WS", wb_id)
    r2, _ = store.create_blackbox_run("WS", wb_id)
    assert (r1, r2) == ("run-1", "run-2")
    task_sess = json.loads((wb_dir / "session.json").read_text())
    assert [r["run_id"] for r in task_sess["bb_runs"]] == ["run-1", "run-2"]
    assert task_sess["latest_bb_run"] == "run-2"


def test_get_blackbox_run_dir_validates_run_id(tmp_path):
    store = ScanStore(tmp_path)
    wb_id, _ = store.create_scan("WS", "http://e", "/code/x")
    store.create_blackbox_run("WS", wb_id)
    assert store.get_blackbox_run_dir("WS", wb_id, "run-1").name == "run-1"
    assert store.get_blackbox_run_dir("WS", wb_id, "run-9") is None  # 不存在
    assert store.get_blackbox_run_dir("WS", wb_id, "../etc") is None  # 越界
    assert store.get_blackbox_run_dir("WS", wb_id, "run-x") is None  # 非法格式


# ── list/update/delete run + ScanSummary 透传 + 隐藏 legacy ~N ──────────────

def test_list_update_delete_blackbox_run(tmp_path):
    store = ScanStore(tmp_path)
    wb_id, wb_dir = store.create_scan("WS", "http://e", "/code/x")
    r1, _ = store.create_blackbox_run("WS", wb_id)
    r2, _ = store.create_blackbox_run("WS", wb_id)
    # list 从 session bb_runs[] 取
    runs = store.list_blackbox_runs("WS", wb_id)
    assert [r["run_id"] for r in runs] == ["run-1", "run-2"]
    # update：写 run session + 任务索引条目 + latest_bb_run
    store.update_blackbox_run("WS", wb_id, r1, status="completed", phase="completed")
    runs = store.list_blackbox_runs("WS", wb_id)
    assert next(r for r in runs if r["run_id"] == "run-1")["status"] == "completed"
    run_sess = json.loads((wb_dir / "blackbox-runs" / "run-1" / "session.json").read_text())
    assert run_sess["bb_phase"] == "completed"
    # delete：rmtree run + combined/run-K + 移除 bb_runs[] 条目
    assert store.delete_blackbox_run("WS", wb_id, r2) is True
    assert not (wb_dir / "blackbox-runs" / "run-2").exists()
    assert store.list_blackbox_runs("WS", wb_id) == [
        {"run_id": "run-1", "status": "completed"}]


def test_summarize_combined_progress_uses_latest_run_phase(tmp_path):
    store = ScanStore(tmp_path)
    wb_id, wb_dir = store.create_scan("WS", "http://e", "/code/x")
    SessionManager(wb_dir.parent).update_session(wb_dir, {
        "expected_agents": {"whitebox": 4, "blackbox": 2},
        "completed_agents": ["a", "b", "c", "d"]})  # 白盒 4 完成
    r1, run_dir = store.create_blackbox_run("WS", wb_id)
    # run-1 跑到 running，黑盒完成 1/2
    SessionManager(run_dir.parent).update_session(run_dir, {
        "bb_phase": "running", "completed_agents": ["e"]})
    summ = store.list_scans("WS")[0]
    # combined + running 分段：55 + 45*(1/2) = 77.5
    assert summ.combined is True
    assert summ.bb_phase == "running"  # 取自 latest run
    assert summ.progress_pct == 77.5
    assert summ.latest_bb_run == "run-1"
    assert summ.bb_runs[-1]["run_id"] == "run-1"
    # as_dict 透传
    d = summ.as_dict()
    assert d["latest_bb_run"] == "run-1"
    assert d["bb_runs"][-1]["run_id"] == "run-1"


# ── 组合扫描用时口径（墙钟，2026-08-21）──────────────────────────────────────

def test_scan_summary_combined_duration_wallclock_completed(tmp_path):
    """组合扫描 total_duration_ms 用墙钟口径（含黑盒段），非任务级 metrics 的白盒和。

    任务级 metrics.total_duration_ms 只由白盒 run 的 MetricsTracker 累积（黑盒 run 的
    metrics 落 run-K/session.json，从不合并进任务级）——只读 metrics 会显示偏小
    （真机 NodeGoat-20260820-174548 实测：白盒 32.3min vs 墙钟 50.3min）。
    口径：end = max(任务级 completed_at, 各 bb_run completed_at) - created_at。
    """
    store = ScanStore(tmp_path)
    wb_id, wb_dir = store.create_scan("WS", "http://e", "/code/x")
    r1, _ = store.create_blackbox_run("WS", wb_id)
    store.update_blackbox_run("WS", wb_id, r1, status="completed", phase="completed",
                              completed_at="2026-08-20T18:36:03+00:00")
    # 手写任务级 session：metrics 只有白盒和（10min）；终态时间戳早于 run 收尾。
    sess = json.loads((wb_dir / "session.json").read_text())
    sess["metrics"] = {"total_duration_ms": 600_000}
    sess["created_at"] = 1_787_247_948.0
    sess["completed_at"] = 1_787_247_948.0 + 1_800  # 任务级 30min
    (wb_dir / "session.json").write_text(json.dumps(sess))
    s = store.list_scans("WS")[0]
    # run-1 completed_at(2026-08-20T18:36:03Z=1_787_250_963) > 任务级 → end 取 run：
    assert s.total_duration_ms == pytest.approx((1_787_250_963 - 1_787_247_948) * 1000), \
        "组合扫描用时 = 墙钟(created→最晚收尾)，非 metrics 白盒和 600000"


def test_scan_summary_combined_duration_wallclock_running(tmp_path):
    """组合扫描在跑（无任何终态）：end=now → 用时随时间增长（列表 10s 轮询可见推进）。"""
    import time as _time
    store = ScanStore(tmp_path)
    wb_id, wb_dir = store.create_scan("WS", "http://e", "/code/x")
    store.create_blackbox_run("WS", wb_id)
    sess = json.loads((wb_dir / "session.json").read_text())
    sess["metrics"] = {"total_duration_ms": 60_000}
    sess["created_at"] = _time.time() - 120  # 2 分钟前起跑
    (wb_dir / "session.json").write_text(json.dumps(sess))
    s = store.list_scans("WS")[0]
    assert s.total_duration_ms is not None
    assert 110_000 <= s.total_duration_ms <= 130_000, \
        "在跑组合扫描用时应 ≈ now-created（120s），非 metrics 的 60000"


def test_scan_summary_pure_scan_duration_still_reads_metrics(tmp_path):
    """纯白盒/纯黑盒（无 bb_runs、combined 非 True）：用时仍读 metrics（零回归）。"""
    store = ScanStore(tmp_path)
    _, scan_dir = store.create_scan("WS", "http://e", "/code/x")
    sess = json.loads((scan_dir / "session.json").read_text())
    sess["metrics"] = {"total_duration_ms": 123_456}
    sess["created_at"] = 1_000_000.0
    sess["completed_at"] = 1_000_900.0  # 墙钟 900s ≠ metrics 值，确保走的是 metrics
    sess["status"] = "completed"
    (scan_dir / "session.json").write_text(json.dumps(sess))
    s = store.list_scans("WS")[0]
    assert s.total_duration_ms == 123_456


def test_list_scans_hides_legacy_tilde_n(tmp_path):
    store = ScanStore(tmp_path)
    wb_id, _ = store.create_scan("WS", "http://e", "/code/x")
    # 手造一个 legacy 平级 ~N 目录
    legacy = tmp_path / "WS" / "scans" / f"{wb_id}~1"
    legacy.mkdir(parents=True)
    (legacy / "session.json").write_text(
        '{"scan_type":"blackbox","created_at":"2026-01-01T00:00:00"}')
    ids = [s.scan_id for s in store.list_scans("WS")]
    assert wb_id in ids
    assert f"{wb_id}~1" not in ids  # legacy 隐藏
