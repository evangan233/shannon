# packages/web/tests/test_scans_adversarial_review.py
"""GET adversarial-review 端点（照抄 test_scans_dataflow 四用例骨架）。"""
import json
from pathlib import Path

REVIEW = {"summary": {"total": 1, "refuted": 1, "survived": 0, "unreviewed": 0},
          "records": [{"vuln_class": "injection", "finding_id": "INJ-01",
                       "review_verdict": "refuted",
                       "failed_dimensions": ["defense_effective"],
                       "after": {"action": "dismissed"}}]}


def _make_scan(tmp_workspaces, ws="ws1", scan_id="S1"):
    scan_dir = tmp_workspaces / ws / "scans" / scan_id
    (scan_dir / "deliverables").mkdir(parents=True, exist_ok=True)
    (scan_dir / "session.json").write_text(json.dumps({"scan_id": scan_id}),
                                           encoding="utf-8")
    return scan_dir


def test_returns_review_json(authed_client, tmp_workspaces):
    d = _make_scan(tmp_workspaces)
    inter = d / "deliverables" / "whitebox" / "intermediate"
    inter.mkdir(parents=True)
    (inter / "adversarial_review.json").write_text(json.dumps(REVIEW),
                                                   encoding="utf-8")
    r = authed_client.get("/api/workspaces/ws1/scans/S1/adversarial-review")
    assert r.status_code == 200
    assert r.json()["summary"]["refuted"] == 1


def test_404_when_missing(authed_client, tmp_workspaces):
    _make_scan(tmp_workspaces)
    r = authed_client.get("/api/workspaces/ws1/scans/S1/adversarial-review")
    assert r.status_code == 404


def test_404_unknown_scan(authed_client, tmp_workspaces):
    r = authed_client.get("/api/workspaces/ws1/scans/NOPE/adversarial-review")
    assert r.status_code == 404
