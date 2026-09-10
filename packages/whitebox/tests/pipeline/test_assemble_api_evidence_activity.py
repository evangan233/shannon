"""api_evidence_matrix 组装活动——non-fatal，成功落 deliverables 根产物。

打桩方式对齐 test_assemble_dataflow_view_activity：patch build 函数 +
patch activities._get_paths（返回 (repo, wb_deliverables, workspaces)，
wb_deliverables = scan_dir/deliverables/whitebox）。asyncio_mode=auto 直接 await。
"""
import json
from pathlib import Path
from unittest.mock import patch

import pytest


@pytest.fixture
def wb_deliverables(tmp_path: Path) -> Path:
    """scan 树：tmp/deliverables/whitebox（_get_paths 返回的已是白盒桶）。"""
    wb = tmp_path / "deliverables" / "whitebox"
    wb.mkdir(parents=True)
    return wb


async def test_activity_writes_matrix_at_deliverables_root(wb_deliverables: Path):
    from supernova_whitebox.pipeline import activities

    matrix = {"schema_version": 1, "scan_id": "NodeGoat-X",
              "endpoints": [{"method": "GET", "path": "/p"}]}
    with patch("supernova_core.services.api_evidence_matrix"
               ".build_api_evidence_matrix", return_value=matrix) as build:
        with patch.object(activities, "_get_paths",
                          return_value=(Path("/r"), wb_deliverables, Path("/w"))):
            result = await activities.run_assemble_api_evidence(input=object())
    assert result == {"status": "ok", "endpoints": 1}
    # scan_dir = wb_deliverables.parent.parent；build 收到 scan_dir
    assert build.call_args[0][0] == wb_deliverables.parent.parent
    out = wb_deliverables.parent / "api_evidence_matrix.json"
    assert json.loads(out.read_text(encoding="utf-8")) == matrix


async def test_activity_non_fatal_on_exception(wb_deliverables: Path):
    """组装器抛 → warning + skipped 返回值，不抛 ApplicationFailure。"""
    from supernova_whitebox.pipeline import activities

    with patch("supernova_core.services.api_evidence_matrix"
               ".build_api_evidence_matrix", side_effect=RuntimeError("boom")):
        with patch.object(activities, "_get_paths",
                          return_value=(Path("/r"), wb_deliverables, Path("/w"))):
            result = await activities.run_assemble_api_evidence(input=object())
    assert result["status"] == "skipped"
    assert not (wb_deliverables.parent / "api_evidence_matrix.json").exists()
