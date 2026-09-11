"""组合扫描 session 字段 + 后端透传 + expected_agents + progress_pct（Task 1）。

覆盖：
- _snapshot_auth_ref（D2 认证明文不进 session.json；inline → {profile_id: None}，
  profile → {profile_id, cred_id, cred_ids}）。
- _compute_expected_agents（返回 {"whitebox": N}，N 受 vuln 类 × LLM 轨系数影响）。
- ScanSummary 字段 + as_dict 透传 combined/bb_phase/bb_reason/progress_pct。
- _scan_detail payload 含 combined/bb_phase/bb_reason/progress_pct/expected_agents/completed_agents。
- progress_pct 三阶段加权（spec §9.2）。
"""
import json
from pathlib import Path

import pytest

from supernova_web.components.scan_manager import ScanManager
from supernova_web.models import ScanRequest


# ── _snapshot_auth_ref（D2 认证明文不进 session.json）───────────────────────

def test_snapshot_auth_ref_inline_mode_returns_profile_none(tmp_path):
    """inline 模式（无 profile_id）→ {"profile_id": None}（认证明文在 scan-config.yaml，
    不进 session.json）。"""
    sm = ScanManager(workspaces_dir=tmp_path, repos_dir=tmp_path, config_store=object())
    req = ScanRequest(type="whitebox", url="http://t/",
                      source={"kind": "repo", "value": "r"}, workspace="ws",
                      authentication={"login_type": "form", "login_url": "http://t/",
                                      "credentials": {"username": "a", "password": "secret"}})
    ref = sm._snapshot_auth_ref(req)
    assert ref == {"profile_id": None}
    # 铁律：不含任何明文 / username / password。
    dumped = json.dumps(ref)
    assert "secret" not in dumped
    assert "username" not in dumped


def test_snapshot_auth_ref_profile_mode_returns_ids(tmp_path):
    """profile 模式 → {"profile_id", "cred_id", "cred_ids"}（非敏感引用）。"""
    sm = ScanManager(workspaces_dir=tmp_path, repos_dir=tmp_path, config_store=object())
    req = ScanRequest(type="whitebox", url="http://t/",
                      source={"kind": "repo", "value": "r"}, workspace="ws",
                      auth_profile_id="prof_1", auth_credential_id="cred_a",
                      auth_credential_ids=["cred_a", "cred_b"])
    ref = sm._snapshot_auth_ref(req)
    assert ref == {"profile_id": "prof_1", "cred_id": "cred_a",
                   "cred_ids": ["cred_a", "cred_b"]}


def test_snapshot_auth_ref_profile_subset_mode(tmp_path):
    """profile 子集模式（profile_id + cred_ids，无 cred_id）→ cred_id 为 None。"""
    sm = ScanManager(workspaces_dir=tmp_path, repos_dir=tmp_path, config_store=object())
    req = ScanRequest(type="whitebox", url="http://t/",
                      source={"kind": "repo", "value": "r"}, workspace="ws",
                      auth_profile_id="prof_1", auth_credential_ids=["cred_a"])
    ref = sm._snapshot_auth_ref(req)
    assert ref["profile_id"] == "prof_1"
    assert ref["cred_ids"] == ["cred_a"]
    assert ref["cred_id"] is None


# ── _compute_expected_agents（进度分母，spec §9.5）──────────────────────────

def test_compute_expected_agents_returns_whitebox_only(tmp_path):
    """白盒部分只返 {"whitebox": N}（blackbox 在 submit 时补，见 Task 4）。"""
    sm = ScanManager(workspaces_dir=tmp_path, repos_dir=tmp_path, config_store=object())
    req = ScanRequest(type="whitebox",
                      source={"kind": "repo", "value": "r"}, workspace="ws")
    result = sm._compute_expected_agents(req)
    assert isinstance(result, dict)
    assert "whitebox" in result
    assert "blackbox" not in result  # blackbox 部分在 Task 4 补


def test_compute_expected_agents_llm_track_doubles_taint_count(tmp_path, monkeypatch):
    """开 LLM 轨时，taint 类（inj/xss/ssrf）双轨，expected 含全部 vuln agent。"""
    monkeypatch.setenv("SUPERNOVA_LLM_TRACK_ENABLED", "1")
    sm = ScanManager(workspaces_dir=tmp_path, repos_dir=tmp_path, config_store=object())
    req = ScanRequest(type="whitebox",
                      source={"kind": "repo", "value": "r"}, workspace="ws")
    result_on = sm._compute_expected_agents(req)
    # 关 LLM 轨：taint vuln agent 被关（DEGRADABLE_VULN_CLASSES），expected 减少。
    monkeypatch.setenv("SUPERNOVA_LLM_TRACK_ENABLED", "0")
    result_off = sm._compute_expected_agents(req)
    assert result_on["whitebox"] > result_off["whitebox"], (
        "关 LLM 轨 expected 应小于开轨（taint vuln agent 被关）")


def test_compute_expected_agents_positive_int(tmp_path):
    """expected_agents['whitebox'] 是正整数（至少 pre-recon + recon + 报告）。"""
    sm = ScanManager(workspaces_dir=tmp_path, repos_dir=tmp_path, config_store=object())
    req = ScanRequest(type="whitebox",
                      source={"kind": "repo", "value": "r"}, workspace="ws")
    n = sm._compute_expected_agents(req)["whitebox"]
    assert isinstance(n, int) and n >= 3


# ── ScanSummary + as_dict + _scan_detail 透传 ───────────────────────────────

def _make_combined_session(scan_dir: Path, *,
                           combined: bool = True,
                           bb_phase: str = "pending",
                           bb_reason: str | None = None,
                           completed_agents: list[str] | None = None,
                           expected_agents: dict | None = None) -> None:
    """写一个组合扫描 session.json（带组合字段）。"""
    data = {
        "web_url": "http://t/",
        "repo_path": str(scan_dir),
        "created_at": 1700000000.0,
        "scan_type": "whitebox",
        "status": "running",
        "completed_at": None,
        "combined": combined,
        "bb_phase": bb_phase,
        "bb_url": "http://target.example/",
        "bb_auth_ref": {"profile_id": None},
        "expected_agents": expected_agents or {"whitebox": 9},
        "completed_agents": completed_agents or [],
    }
    if bb_reason is not None:
        data["bb_reason"] = bb_reason
    (scan_dir / "session.json").write_text(json.dumps(data), encoding="utf-8")


def test_scan_summary_as_dict_includes_combined_fields(tmp_path):
    """ScanSummary.as_dict 含 combined/bb_phase/bb_reason/progress_pct。"""
    from supernova_core.session import SessionManager
    from supernova_web.components.scan_store import ScanStore
    ws = "ws1"
    scan_id = "repo-20260813-120000"
    ws_dir = tmp_path / ws
    scans_dir = ws_dir / "scans" / scan_id
    scans_dir.mkdir(parents=True)
    _make_combined_session(scans_dir, bb_phase="pending", bb_reason=None,
                           expected_agents={"whitebox": 9},
                           completed_agents=["pre-recon", "recon"])
    store = ScanStore(tmp_path)
    summaries = store.list_scans(ws)
    assert len(summaries) == 1
    d = summaries[0].as_dict()
    assert d["combined"] is True
    assert d["bb_phase"] == "pending"
    assert d["bb_reason"] is None
    assert "progress_pct" in d
    assert isinstance(d["progress_pct"], (int, float))
    assert 0 <= d["progress_pct"] <= 100


def test_progress_pct_pure_whitebox_completed_over_expected(tmp_path):
    """纯白盒（无 combined）：progress_pct = completed / expected × 100（spec §9.2）。"""
    from supernova_web.components.scan_store import ScanStore
    ws = "ws1"
    scan_id = "repo-20260813-120001"
    scans_dir = tmp_path / ws / "scans" / scan_id
    scans_dir.mkdir(parents=True)
    data = {
        "web_url": "http://t/", "repo_path": str(scans_dir),
        "created_at": 1700000000.0, "scan_type": "whitebox", "status": "running",
        "completed_at": None, "completed_agents": ["pre-recon", "recon"],
        "expected_agents": {"whitebox": 8},
    }
    (scans_dir / "session.json").write_text(json.dumps(data), encoding="utf-8")
    store = ScanStore(tmp_path)
    d = store.list_scans(ws)[0].as_dict()
    # 2/8 = 25%
    assert d["progress_pct"] == 25


def test_progress_pct_combined_three_stage_weighting(tmp_path):
    """组合扫描三阶段加权（spec §9.2）：precheck 0-5% / 白盒 5+50×ratio / 黑盒 55+45×ratio / completed 100%。"""
    from supernova_web.components.scan_store import ScanStore
    ws = "ws1"

    # pending 阶段（白盒中）：2/8 白盒完成 → 5 + 50×(2/8) = 5 + 12.5 = 17.5
    scan_id = "repo-20260813-120002"
    scans_dir = tmp_path / ws / "scans" / scan_id
    scans_dir.mkdir(parents=True)
    _make_combined_session(
        scans_dir, combined=True, bb_phase="pending",
        expected_agents={"whitebox": 8}, completed_agents=["pre-recon", "recon"])
    store = ScanStore(tmp_path)
    d = store.list_scans(ws)[0].as_dict()
    assert d["progress_pct"] == pytest.approx(17.5, abs=0.5)


def test_progress_pct_combined_precheck_stage(tmp_path):
    """组合扫描 precheck 阶段：0%（spec §9.2 precheck → 0–5%；precheck 期无 completed）。"""
    from supernova_web.components.scan_store import ScanStore
    ws = "ws1"
    scan_id = "repo-20260813-120003"
    scans_dir = tmp_path / ws / "scans" / scan_id
    scans_dir.mkdir(parents=True)
    _make_combined_session(
        scans_dir, combined=True, bb_phase="precheck",
        expected_agents={"whitebox": 8}, completed_agents=[])
    store = ScanStore(tmp_path)
    d = store.list_scans(ws)[0].as_dict()
    assert d["progress_pct"] == 0


def test_progress_pct_combined_completed_is_100(tmp_path):
    """组合扫描 completed：100%。"""
    from supernova_web.components.scan_store import ScanStore
    ws = "ws1"
    scan_id = "repo-20260813-120004"
    scans_dir = tmp_path / ws / "scans" / scan_id
    scans_dir.mkdir(parents=True)
    _make_combined_session(
        scans_dir, combined=True, bb_phase="completed",
        expected_agents={"whitebox": 8, "blackbox": 4},
        completed_agents=["pre-recon", "recon", "injection-vuln"])
    # 把 status 改成 completed（终态）
    sf = scans_dir / "session.json"
    data = json.loads(sf.read_text())
    data["status"] = "completed"
    sf.write_text(json.dumps(data), encoding="utf-8")
    store = ScanStore(tmp_path)
    d = store.list_scans(ws)[0].as_dict()
    assert d["progress_pct"] == 100


def test_combined_whitebox_completed_but_blackbox_pending_is_not_terminal(tmp_path):
    """白盒 workflow 已写 completed 但黑盒 run 仍 pending 时，组合任务不能显示已完成。

    白盒和黑盒共用任务根目录；白盒 workflow 的 scan_end/session.status 会先落
    completed，黑盒阶段则落在 latest run。对外状态必须以后者为准，避免列表/详情把
    「白盒完成、黑盒待接力」误报为组合扫描完成。
    """
    from supernova_web.components.scan_store import ScanStore

    ws = "ws1"
    scan_id = "repo-20260813-120006"
    scans_dir = tmp_path / ws / "scans" / scan_id
    scans_dir.mkdir(parents=True)
    _make_combined_session(
        scans_dir,
        combined=True,
        bb_phase="pending",
        expected_agents={"whitebox": 8, "blackbox": 2},
        completed_agents=[f"wb-{i}" for i in range(8)],
    )
    store = ScanStore(tmp_path)
    run_id, _ = store.create_blackbox_run(ws, scan_id)
    assert run_id == "run-1"

    # 模拟白盒 workflow 已结束；黑盒 run 仍保持 create_blackbox_run 的 pending。
    session_file = scans_dir / "session.json"
    data = json.loads(session_file.read_text(encoding="utf-8"))
    data["status"] = "completed"
    data["completed_at"] = 1700000001.0
    session_file.write_text(json.dumps(data), encoding="utf-8")

    row = store.list_scans(ws)[0].as_dict()

    assert row["bb_phase"] == "pending"
    assert row["status"] == "running"
    assert row["is_running"] is True
    assert row["progress_pct"] == 55.0


@pytest.mark.asyncio
async def test_scan_detail_payload_includes_combined_fields(tmp_path):
    """_scan_detail payload 含 combined/bb_phase/bb_reason/progress_pct/expected_agents/completed_agents。"""
    from supernova_web.components.scan_store import ScanStore
    from supernova_web.api.scans import _scan_detail
    ws = "ws1"
    scan_id = "repo-20260813-120005"
    scans_dir = tmp_path / ws / "scans" / scan_id
    scans_dir.mkdir(parents=True)
    _make_combined_session(
        scans_dir, combined=True, bb_phase="running", bb_reason=None,
        expected_agents={"whitebox": 8}, completed_agents=["pre-recon"])

    class _FakeIndexer:
        def _status_of(self, scan_dir, raw):
            return "running"

    class _FakeState:
        indexer = _FakeIndexer()

    class _FakeApp:
        state = _FakeState()

    class _FakeRequest:
        app = _FakeApp()

    payload = await _scan_detail(_FakeRequest(), ws, scan_id, scans_dir)
    for key in ("combined", "bb_phase", "bb_reason", "progress_pct",
                "expected_agents", "completed_agents"):
        assert key in payload, f"_scan_detail 缺组合字段: {key}"
    assert payload["combined"] is True
    assert payload["bb_phase"] == "running"
    assert payload["expected_agents"] == {"whitebox": 8}
    assert payload["completed_agents"] == ["pre-recon"]
