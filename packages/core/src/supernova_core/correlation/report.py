from __future__ import annotations
import json
from pathlib import Path
from supernova_core.correlation.schemas import (
    CrossServiceTopology, TrustBoundary, CrossServiceFlow,
)


def write_correlation_deliverables(
    out_deliverables: Path,
    topology: CrossServiceTopology,
    boundaries: list[TrustBoundary],
    merged_queues: dict[str, list[dict]],
    report_md: str,
    flows: list[CrossServiceFlow] | None = None,
    multi_hop_chains: list[dict] | None = None,
    drift_warnings: list[str] | None = None,
) -> None:
    out_deliverables.mkdir(parents=True, exist_ok=True)
    (out_deliverables / "cross-service-topology.json").write_text(
        topology.to_json(), encoding="utf-8")
    (out_deliverables / "trust-boundaries.json").write_text(
        json.dumps([json.loads(b.to_json()) for b in boundaries], ensure_ascii=False, indent=2),
        encoding="utf-8")
    (out_deliverables / "correlation-report.md").write_text(report_md, encoding="utf-8")
    # 版本漂移警告结构化落盘（2026-09-20）：此前只渲染进 report md，web API 侧
    # 读不到（硬编码 []）致前端漂移横幅恒死的断链。
    if drift_warnings is not None:
        (out_deliverables / "drift-warnings.json").write_text(
            json.dumps(drift_warnings, ensure_ascii=False, indent=2),
            encoding="utf-8")
    for vc, entries in merged_queues.items():
        (out_deliverables / f"{vc}_exploitation_queue.json").write_text(
            json.dumps({"vulnerabilities": entries}, ensure_ascii=False, indent=2),
            encoding="utf-8")
    if flows is not None:
        # spec 2026-08-27 §8:对象形态 {"flows": [...], "multi_hop_chains": [...]}
        (out_deliverables / "cross-service-flows.json").write_text(
            json.dumps({"flows": [json.loads(f.to_json()) for f in flows],
                        "multi_hop_chains": multi_hop_chains or []},
                       ensure_ascii=False, indent=2),
            encoding="utf-8")


def write_adjudication_deliverables(
    out_deliverables: Path,
    cards: list[dict],
    report_md: str,
) -> None:
    """阶段 B 落盘：adjudication-log.json + 重渲染 correlation-report.md（裁决章节）。"""
    out_deliverables.mkdir(parents=True, exist_ok=True)
    (out_deliverables / "adjudication-log.json").write_text(
        json.dumps({"cards": cards}, ensure_ascii=False, indent=2),
        encoding="utf-8")
    (out_deliverables / "correlation-report.md").write_text(report_md, encoding="utf-8")
