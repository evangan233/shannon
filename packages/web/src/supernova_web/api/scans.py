"""T4: scan-scoped API 路由（1 ws : N scans）。

挂在 /api/workspaces（路径 /{ws}/scans/...）。所有路由 Depends(workspace_member)--
能访问 ws 就能访问该 ws 所有 scan（与 P2 repo 同模型，scan 不引入独立 ACL）。
scan_id 路径校验：ScanStore.get_scan_dir 拒 ..//（防路径遍历）。

shim（api/workspaces.py 的 GET /{ws}、/{ws}/report|deliverables|logs、api/events.py 的
GET /{ws}/events、api/scan.py 的 DELETE /api/scan/{ws}）转发到 latest scan，供旧前端不破。
"""
from __future__ import annotations

import time

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from pathlib import Path, PurePosixPath

from supernova_web.auth.dependencies import current_user, workspace_member
from supernova_web.components.workspace_provisioner import is_global_admin
from supernova_web.auth.models import User
from supernova_web.components.deliverables_reader import DeliverablesReader
from supernova_web.models import ScanBatchAccepted, ScanBatchResultItem, ScanIdsBatchRequest

router = APIRouter(prefix="/api/workspaces", tags=["scans"])

# 跨 ws 扫描聚合（IA 重设计 §3.1/§7.1）：独立 prefix /api/scans，不属于 /{ws}/scans 命名空间。
# 不能挂 router（prefix=/api/workspaces）--@router.get("") 会撞 workspaces.py 的列表路由。
cross_ws_router = APIRouter(prefix="/api/scans", tags=["scans"])


def _store(request: Request):
    from supernova_web.components.scan_store import ScanStore
    return ScanStore(request.app.state.config.workspaces_dir)


@cross_ws_router.get("")
async def list_all_scans(request: Request, user: User = Depends(current_user)):
    """跨 ws 扫描聚合（IA 重设计 §3.1/§7.1）。admin 见全部 ws 扫描，
    普通用户只见归属 ws（list_user_workspaces）的扫描。每条注入 workspace 字段，
    按 created_at 倒序。ws 量通常个位数到几十，每 ws list_scans 是目录扫描，可接受。"""
    from supernova_web.components.scan_store import ScanStore
    cfg = request.app.state.config
    indexer = request.app.state.indexer
    store = ScanStore(cfg.workspaces_dir)
    if is_global_admin(user):
        ws_names = [w["name"] for w in indexer.list_workspaces()]
    else:
        ws_names = request.app.state.auth_store.list_user_workspaces(user.id)
    out = []
    for ws in ws_names:
        for s in store.list_scans(ws):
            d = s.as_dict()
            d["workspace"] = ws
            out.append(d)
    out.sort(key=lambda x: x.get("created_at") or 0, reverse=True)
    return out


def _scan_dir_or_404(request: Request, ws: str, scan_id: str):
    """按 (ws, scan_id) 定位 scan 目录，路径校验拒越界；None -> 404。"""
    scan_dir = _store(request).get_scan_dir(ws, scan_id)
    if scan_dir is None:
        raise HTTPException(404, "scan not found")
    return scan_dir


async def _scan_detail(request: Request, ws: str, scan_id: str, scan_dir) -> dict:
    """scan 详情 payload（同旧 GET /{ws} SessionData shape，读 scan_dir session.json）。"""
    from supernova_core.session import SessionManager
    from supernova_web.components.metrics_normalizer import normalize_metrics
    from supernova_web.components.workspaces_indexer import _to_unix
    from supernova_web.components.scan_store import (
        resolve_workflow_id, _compute_progress_pct, effective_scan_status,
        merge_latest_run_view, combined_wallclock_ms, _is_combined_scan,
        is_post_hoc_runs_task)
    mgr = SessionManager(scan_dir.parent)
    data = mgr.get_session_data(scan_dir)
    idx = request.app.state.indexer
    raw_status = idx._status_of(scan_dir, mgr.get_status(scan_dir))
    # 判活盲区二次确认（2026-09-11 NodeGoat-20260910-193720 事故）：activity 在
    # Temporal 重试等待期（backoff ~5min ×3）不执行 → 心跳停更 → interrupted 误判，
    # 但 workflow 仍 RUNNING。detail 是用户决策入口（「已中断」+ 续跑按钮据此出现，
    # 引导用户 terminate 掉实际在推进的扫描）——describe 确认 RUNNING 则维持
    # running。仅 interrupted 才查（正常/终态短路），误判窗口短暂罕见，不设缓存。
    if raw_status == "interrupted":
        from supernova_web.components.orphan_reconciler import _workflow_still_running
        if await _workflow_still_running(scan_dir):
            raw_status = "running"
    combined = data.get("combined")
    # 版本化 run（spec §5.2/§5.3）：bb_phase/bb_reason 合并 latest run（与 list 同视图）——
    # 任务级 phase 停在 precheck/pending，前端时间线/进度概览的 eventsUrl 切换都按 run
    # phase 消费（ScanProgressOverview.resolveActiveEventsUrl），不合并则黑盒段永显「待
    # 接力」、run 级实时进度不可见（list/detail 口径一致，修 run 版本化重构遗留）。
    bb_phase, bb_reason, progress_data = merge_latest_run_view(scan_dir, data)
    status = effective_scan_status(
        raw_status, combined, bb_phase, post_hoc_runs=is_post_hoc_runs_task(data))
    # 组合扫描重跑预填（2026-09-03）：bb_url=黑盒目标；bb_auth_ref=profile 模式认证
    # 档案引用（非敏感 profile_id/cred_ids，inline 模式 profile_id=None——明文在
    # scan-config.yaml，走下方 authentication）。前端 RerunPreset 早已就位等这组字段。
    bb_auth_ref = data.get("bb_auth_ref") or {}
    host_config = data.get("host_config") or {}
    host_enabled = bool(host_config.get("enabled")) if isinstance(host_config, dict) else False
    host_source = host_config.get("source") if host_enabled else None
    host_mappings = host_config.get("mappings") if isinstance(host_config, dict) else {}
    # 组合扫描用时走墙钟口径（含黑盒段），与列表 _summarize 一致；OverviewTab 读
    # metrics.total_duration_ms，纯扫描两口径同为 metrics 值，零变化。
    metrics = normalize_metrics(data.get("metrics", {}))
    if _is_combined_scan(data, combined):
        wallclock = combined_wallclock_ms(
            data, _to_unix(mgr.get_created_at(scan_dir)),
            _to_unix(mgr.get_completed_at(scan_dir)))
        if wallclock is not None:
            metrics["total_duration_ms"] = wallclock
    return {
        "web_url": mgr.get_web_url(scan_dir),
        "repo_path": data.get("repo_path"),
        "scan_type": mgr.get_scan_type(scan_dir),
        "status": status,
        "created_at": _to_unix(mgr.get_created_at(scan_dir)),
        "completed_at": _to_unix(mgr.get_completed_at(scan_dir)),
        # 服务端墙钟基准（unix 秒）：前端 offset 校正用，消除跨时钟「总耗时负数」根因。
        "server_now": time.time(),
        "links": data.get("links", {}),
        "metrics": metrics,
        "session": data.get("session", {}),
        "workflow_id": resolve_workflow_id(ws, scan_dir, scan_id),
        # 重跑预填用：白盒 repo 名 / 黑盒复用白盒 scan_id / 黑盒登录配置。
        # source_repo 缺失时从 repo_path basename 兜底（2026-09-04）：存量组合扫描
        # precheck 失败路径未落 source_repo（写盘时序 bug，scan_manager 已修），兜底让
        # 这些 failed 任务重跑仍能预填仓库；web 入口仓库名默认 flat 命名 = basename。
        "source_repo": data.get("source_repo") or (
            PurePosixPath(data["repo_path"]).name if data.get("repo_path") else None),
        "reuse_whitebox_scan_id": data.get("reuse_whitebox_scan_id"),
        "authentication": _read_auth_config(scan_dir),
        # MR 增量扫描 refs（spec 2026-09-03 §6）：重跑预填 base/head（非 MR 未写 → None）。
        "mr_base_ref": data.get("mr_base_ref"),
        "mr_head_ref": data.get("mr_head_ref"),
        # merged 改道把手（2026-09-04）：重跑预填实际扫描 commit 对（无则分支名模式）。
        "mr_head_commit": data.get("mr_head_commit"),
        "mr_base_commit": data.get("mr_base_commit"),
        # 组合扫描黑盒段重跑预填：目标 url + 认证档案引用（与 authentication 互斥——
        # profile 模式时后者的 scan-config.yaml 不 dump 认证明文，profile 引用是唯一来源）。
        "bb_url": data.get("bb_url"),
        "auth_profile_id": bb_auth_ref.get("profile_id"),
        "auth_credential_ids": bb_auth_ref.get("cred_ids") or [],
        # HOST 来源仅用于新建扫描重跑预填；mapping 内容不随详情暴露。
        # host_profile_ids（2026-09-11 多选）：新快照完整列表；旧快照只有单数
        # profile_id → 包成 [profile_id] 兜底（前端统一吃数组）；url 源 → []。
        "host_profile_id": host_config.get("profile_id") if host_source == "profile" else None,
        "host_profile_ids": (
            host_config.get("profile_ids")
            or ([host_config["profile_id"]] if host_config.get("profile_id") else [])
        ) if host_source == "profile" else [],
        "host_url": host_config.get("source_url") if host_source == "url" else None,
        "host_source": host_source,
        "host_mapping_count": len(host_mappings) if isinstance(host_mappings, dict) else 0,
        # 组合扫描字段 + 进度（spec §6.2/§9.2，2026-08-13 Task 1）：
        # combined 透传 session.json；bb_phase/bb_reason/completed_agents 经
        # merge_latest_run_view 合并 latest run（见上）；progress_pct 三阶段加权预算；
        # expected_agents/completed_agents 是进度分母/分子（list_scans 已透传，详情一并给）。
        "combined": bool(combined) if combined is not None else None,
        "bb_phase": bb_phase,
        "bb_reason": bb_reason,
        # precheck/编排失败详情（bb_failure_detail 如 "Target unreachable: ..."）：
        # 供前端失败横幅展示，历史扫描无此键 → null 自然降级为只显示 reason。
        "bb_failure_point": data.get("bb_failure_point"),
        "bb_failure_detail": data.get("bb_failure_detail"),
        "progress_pct": _compute_progress_pct(status, combined, bb_phase, progress_data),
        "expected_agents": data.get("expected_agents") or {},
        "completed_agents": data.get("completed_agents") or [],
        # 版本化黑盒 run（spec §5.2）：任务级索引 bb_runs[] + latest_bb_run（纯白盒为 None/[]）。
        "bb_runs": data.get("bb_runs"),
        "latest_bb_run": data.get("latest_bb_run"),
    }


def _read_auth_config(scan_dir: Path) -> dict | None:
    """读 scan_dir/scan-config.yaml 的 authentication（黑盒登录配置，供重跑预填）。

    黑盒 _resolve_blackbox_inputs 在 req.authentication 非空时 dump 写入；无 auth 配置
    （黑盒未启用登录）/ 白盒（无该文件）-> None。损坏 YAML -> None（best-effort，不阻塞详情）。
    """
    cfg = scan_dir / "scan-config.yaml"
    if not cfg.exists():
        return None
    try:
        import yaml
        data = yaml.safe_load(cfg.read_text("utf-8"))
        if isinstance(data, dict) and isinstance(data.get("authentication"), dict):
            return data["authentication"]
    except (OSError, ValueError):
        return None
    return None


# ── 共享视图（scans.py 路由 + workspaces.py shim 转发共用）─────────────────────

_PREVIEW_MAX_BYTES_DEFAULT = 2 * 1024 * 1024  # spec 2026-08-18：大文件预览截断阈值


def _preview_max_bytes() -> int:
    import os
    raw = os.getenv("SUPERNOVA_DELIVERABLES_PREVIEW_MAX_BYTES")
    try:
        return int(raw) if raw else _PREVIEW_MAX_BYTES_DEFAULT
    except ValueError:
        return _PREVIEW_MAX_BYTES_DEFAULT


def deliverables_summary_for(scan_dir, path: str | None, *, strip_track: bool = False,
                             download: bool = False):
    reader = DeliverablesReader(scan_dir, strip_track_prefix="blackbox" if strip_track else None)
    if path is None:
        return reader.summary()
    parts = path.split("/", 1)
    if len(parts) == 2 and parts[0] in ("whitebox", "blackbox"):
        track, filename = parts[0], parts[1]
    elif strip_track:
        # run 级（展示层已剥桶前缀）：无前缀文件名按黑盒 track 读
        track, filename = "blackbox", path
    else:
        track, filename = "whitebox", path  # legacy 兜底（无 track 前缀）
    if download:
        # 下载（产物 tab FileStage 下载按钮）：FileResponse 附件返磁盘原文——无
        # preview_limit 截断、无 json.loads（big_json/empty_json/other 也可下）。
        # 附件文件名由前端 <a download> 属性定（track 前缀区分三桶同名），此处
        # Content-Disposition basename 兜底。
        from fastapi.responses import FileResponse
        try:
            return FileResponse(reader.resolve_path(filename, track), filename=Path(filename).name)
        except FileNotFoundError:
            raise HTTPException(404, "file not found")
    try:
        content = reader.read(filename, track, preview_limit=_preview_max_bytes())
    except FileNotFoundError:
        raise HTTPException(404, "file not found")
    if isinstance(content, str):
        return PlainTextResponse(content)
    import json
    return PlainTextResponse(json.dumps(content, ensure_ascii=False, indent=2))


def deliverables_file_for(scan_dir, filename: str, track: str = "whitebox"):
    try:
        return DeliverablesReader(scan_dir).read(filename, track, preview_limit=_preview_max_bytes())
    except FileNotFoundError:
        raise HTTPException(404, "file not found")


def _dataflow_view_for(scan_dir: Path):
    """读 deliverables/whitebox/intermediate/dataflow_view.json（tier fallback
    桶平铺）-> dict。缺产物 / 解析失败 -> 404 "dataflow view not generated"。

    用 resolve_intermediate（spec 2026-08-18 tiering 读侧 fallback）：先
    intermediate/ 再桶平铺，都不存在返 None。不经 DeliverablesReader——端点返
    JSON（非 text/plain 截断），且 dataflow_view.json 是结构化视图产物，
    透传原始 JSON 由 FastAPI 序列化，避免 preview_limit 截断成 str。
    """
    import json
    from supernova_core.utils.paths import resolve_intermediate, WHITEBOX_SUBDIR
    wb_dir = scan_dir / "deliverables" / WHITEBOX_SUBDIR
    path = resolve_intermediate(wb_dir, "dataflow_view.json")
    if path is None or not path.exists():
        raise HTTPException(404, "dataflow view not generated")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise HTTPException(404, "dataflow view not generated")


def report_for(scan_dir, track: str | None = None) -> str:
    """读 scan_dir 的综合报告 md。

    track 解析：显式传入 > auto-infer（``DeliverablesReader._infer_track``，combined_report.md
    存在时优先 combined）。统一在 ``deliverables/{resolved}/`` 桶内挑报告（comprehensive 优先，
    否则首个 md）——不跨桶，跨桶 list_reports 会按错桶 read -> FileNotFoundError（regression）。

    不再拼接 PoC md（spec 2026-08-26-report-single-source-rendering §3.1）：新管线下
    comprehensive md 卡自带 POC 节，尾部再拼 poc_collection 会重复；PoC 集合是独立
    交付物（DeliverablesTab 可见）。

    零回归：显式 track=None 时等价 auto-infer 单桶读——纯白盒/纯黑盒行为与旧 list_reports 一致
    （单桶时 comprehensive 挑选结果相同）。
    """
    from pathlib import Path
    reader = DeliverablesReader(scan_dir)
    resolved = reader._infer_track() if track is None else track
    track_dir = Path(scan_dir) / "deliverables" / resolved
    mds = sorted(f.name for f in track_dir.glob("*.md")) if track_dir.is_dir() else []
    chosen = next((x for x in mds if "comprehensive" in x.lower()), mds[0] if mds else None)
    if not chosen:
        return ""  # 该桶无报告产物 -> 200 空文本
    return reader.read(chosen, resolved)


def logs_for(scan_dir, file: str | None):
    reader = DeliverablesReader(scan_dir)
    if file is None:
        return {"files": reader.list_logs()}
    try:
        return {"content": reader.read_log(file)}
    except FileNotFoundError:
        raise HTTPException(404, "log not found")


# ── scan-scoped 路由 ────────────────────────────────────────────────────────

@router.get("/{ws}/scans")
async def list_scans(ws: str, request: Request, _: User = Depends(workspace_member)):
    return [s.as_dict() for s in _store(request).list_scans(ws)]


@router.get("/{ws}/scans/{scan_id}")
async def get_scan(ws: str, scan_id: str, request: Request, _: User = Depends(workspace_member)):
    return await _scan_detail(request, ws, scan_id, _scan_dir_or_404(request, ws, scan_id))


@router.get("/{ws}/scans/{scan_id}/blackbox-runs")
async def list_blackbox_runs(ws: str, scan_id: str, request: Request,
                             _: User = Depends(workspace_member)) -> list:
    """列该白盒任务的版本化黑盒 run（从任务 session bb_runs[]，非扫盘）。"""
    _scan_dir_or_404(request, ws, scan_id)  # scan 存在性 + 路径校验
    return _store(request).list_blackbox_runs(ws, scan_id)


@router.get("/{ws}/scans/{scan_id}/blackbox-runs/{run_id}")
async def blackbox_run_detail(ws: str, scan_id: str, run_id: str, request: Request,
                              _: User = Depends(workspace_member)) -> dict:
    """单个 run 详情（读 run 级 session.json：bb_phase/bb_reason/status/...）。"""
    run_dir = _store(request).get_blackbox_run_dir(ws, scan_id, run_id)
    if run_dir is None:
        raise HTTPException(404, "run 不存在")
    from supernova_core.session import SessionManager
    data = SessionManager(run_dir.parent).get_session_data(run_dir)
    return {"run_id": run_id, **data}


def _run_dir_or_404(request: Request, ws: str, scan_id: str, run_id: str) -> Path:
    run_dir = _store(request).get_blackbox_run_dir(ws, scan_id, run_id)
    if run_dir is None:
        raise HTTPException(404, "run 不存在")
    return run_dir


@router.get("/{ws}/scans/{scan_id}/blackbox-runs/{run_id}/deliverables")
async def run_deliverables_summary(ws: str, scan_id: str, run_id: str, request: Request,
                                   _: User = Depends(workspace_member),
                                   path: str | None = Query(None),
                                   download: bool = Query(False)):
    return deliverables_summary_for(_run_dir_or_404(request, ws, scan_id, run_id), path,
                                    strip_track=True, download=download)


@router.get("/{ws}/scans/{scan_id}/blackbox-runs/{run_id}/deliverables/{filename}")
async def run_deliverables_file(ws: str, scan_id: str, run_id: str, filename: str,
                                request: Request, _: User = Depends(workspace_member)):
    return deliverables_file_for(
        _run_dir_or_404(request, ws, scan_id, run_id), filename, track="blackbox")


@router.get("/{ws}/scans/{scan_id}/blackbox-runs/{run_id}/report",
            response_class=PlainTextResponse)
async def run_report(ws: str, scan_id: str, run_id: str, request: Request,
                     _: User = Depends(workspace_member),
                     track: str | None = Query(None)) -> str:
    """run 级报告：track=combined 读 combined/run-K/combined_report.md；否则读 run 黑盒报告。"""
    store = _store(request)
    wb_dir = store.get_scan_dir(ws, scan_id)
    if wb_dir is None:
        raise HTTPException(404, "scan not found")
    if track == "combined":
        from supernova_core.utils.paths import combined_run_dir
        p = combined_run_dir(wb_dir, run_id) / "combined_report.md"
        if not p.is_file():
            raise HTTPException(404, "融合报告未生成")
        return p.read_text("utf-8")
    return report_for(_run_dir_or_404(request, ws, scan_id, run_id), track="blackbox")


# report_data.json 文件名（spec 2026-08-26-report-generation-agent-design §4：
# deliverables/{track}/report_data.json；融合在 combined/run-K/）。
REPORT_DATA_FILENAME = "report_data.json"


def _read_report_data(path: Path) -> dict:
    """读 report_data.json 原文 JSON。缺文件 / 坏 JSON → 404（旧 scan / 写一半中断：
    前端按 404 回退 md 渲染路径，不让 500 冒出）。"""
    import json
    p = Path(path)
    if not p.is_file():
        raise HTTPException(404, "report data not generated")
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise HTTPException(404, "report data not generated")


@router.get("/{ws}/scans/{scan_id}/blackbox-runs/{run_id}/report-data")
async def run_report_data(ws: str, scan_id: str, run_id: str, request: Request,
                          _: User = Depends(workspace_member),
                          track: str = Query("blackbox")) -> dict:
    """run 级 report_data.json（spec §7.1）：track=combined 读 combined/run-K/report_data.json
    （融合报告 SSOT）；默认 track=blackbox 读 run 黑盒桶。缺产物 404（前端回退 md）。
    先经 _run_dir_or_404 验 run 存在性（run_id 路径校验拒越界）。"""
    if track == "combined":
        from supernova_core.utils.paths import combined_run_dir
        wb_dir = _store(request).get_scan_dir(ws, scan_id)
        if wb_dir is None:
            raise HTTPException(404, "scan not found")
        _run_dir_or_404(request, ws, scan_id, run_id)  # run 存在性 + ^run-\\d+$ 校验
        return _read_report_data(combined_run_dir(wb_dir, run_id) / REPORT_DATA_FILENAME)
    if track != "blackbox":
        raise HTTPException(422, "track 须为 blackbox|combined")
    run_dir = _run_dir_or_404(request, ws, scan_id, run_id)
    return _read_report_data(run_dir / "deliverables" / "blackbox" / REPORT_DATA_FILENAME)


@router.get("/{ws}/scans/{scan_id}/blackbox-runs/{run_id}/logs")
async def run_logs(ws: str, scan_id: str, run_id: str, request: Request,
                   _: User = Depends(workspace_member),
                   file: str | None = Query(None)):
    return logs_for(_run_dir_or_404(request, ws, scan_id, run_id), file)


@router.get("/{ws}/scans/{scan_id}/blackbox-runs/{run_id}/events")
async def run_events(ws: str, scan_id: str, run_id: str, request: Request,
                     _: User = Depends(workspace_member)):
    run_dir = _run_dir_or_404(request, ws, scan_id, run_id)
    from .events import build_single_events_response
    return await build_single_events_response(request, run_dir)


@router.post("/{ws}/scans/{scan_id}/blackbox-runs", status_code=202)
async def add_blackbox_run(ws: str, scan_id: str, request: Request,
                           _: User = Depends(workspace_member)) -> dict:
    """给已有白盒任务加一个黑盒 run（spec §6/§7.1 #8 手动入口）。

    body：空 / null / {} = 无新认证（沿用现盘 scan-config.yaml，公开目标则直连）；
    非空 JSON = 合法组合模式 ScanRequest（type=whitebox + url + 认证）。返新 run_id。
    """
    import json as _json
    from pydantic import ValidationError
    from supernova_web.models import ScanRequest

    new_req = None
    raw = (await request.body()).strip()
    if raw and raw not in (b"null", b"{}", b"[]"):
        try:
            payload = _json.loads(raw)
        except _json.JSONDecodeError as e:
            raise HTTPException(422, f"invalid JSON body: {e}")
        if isinstance(payload, dict) and payload:
            try:
                new_req = ScanRequest.model_validate(payload)
            except ValidationError as e:
                raise HTTPException(422, e.errors())

    sm = request.app.state.scan_manager
    try:
        run_id = await sm._add_blackbox_run(ws, scan_id, new_req)
    except ValueError as e:
        msg = str(e)
        if "不存在" in msg:
            raise HTTPException(404, msg)
        raise HTTPException(422, msg)
    return {"workspace": ws, "scan_id": scan_id, "run_id": run_id}


@router.delete("/{ws}/scans/{scan_id}/blackbox-runs/{run_id}")
async def delete_blackbox_run(ws: str, scan_id: str, run_id: str, request: Request,
                              _: User = Depends(workspace_member)):
    """删单个黑盒 run（spec §7.1 #4）。

    DELETE 语义=删资源（同 delete_scan）；运行中 run -> 409（先 cancel 再删）；run 不存在 -> 404。
    范围由 store.delete_blackbox_run 决定（rmtree run + combined + 移除 bb_runs[] + latest 回退）。
    run_id 路径校验由 manager→store.get_blackbox_run_dir（^run-\\d+$）兜底，越界/非法 -> 404。
    """
    from supernova_web.components.scan_manager import ScanRunning
    sm = request.app.state.scan_manager
    try:
        result = await sm.delete_blackbox_run(ws, scan_id, run_id)
    except ScanRunning as e:
        raise HTTPException(409, str(e))
    if result is None:
        raise HTTPException(404, "run 不存在")
    return result


@router.get("/{ws}/scans/{scan_id}/deliverables")
async def scan_deliverables_summary(ws: str, scan_id: str, request: Request,
                                    _: User = Depends(workspace_member),
                                    path: str | None = Query(None),
                                    download: bool = Query(False)):
    return deliverables_summary_for(_scan_dir_or_404(request, ws, scan_id), path,
                                    download=download)


@router.get("/{ws}/scans/{scan_id}/deliverables/{filename}")
async def scan_deliverables_file(ws: str, scan_id: str, filename: str, request: Request,
                                 _: User = Depends(workspace_member),
                                 track: str = "whitebox"):
    return deliverables_file_for(_scan_dir_or_404(request, ws, scan_id), filename, track)


@router.get("/{ws}/scans/{scan_id}/report", response_class=PlainTextResponse)
async def scan_report(ws: str, scan_id: str, request: Request, _: User = Depends(workspace_member),
                      track: str | None = Query(None)):
    """综合报告（text/plain）。track 可选（spec §10.1 三视图）：whitebox/blackbox/combined
    取该桶报告；不传则 auto-infer（纯白盒/纯黑盒零回归）。"""
    return report_for(_scan_dir_or_404(request, ws, scan_id), track)


@router.get("/{ws}/scans/{scan_id}/report-data")
async def scan_report_data(ws: str, scan_id: str, request: Request,
                           _: User = Depends(workspace_member),
                           track: str | None = Query(None)) -> dict:
    """report_data.json（spec 2026-08-26 §4/§7.1）——三轨报告结构化 SSOT，前端
    ReportView 纯渲染的数据源（md 渲染降级路径之外的优先路径）。

    track=whitebox|blackbox 读对应 deliverables 桶；缺省 auto-infer（对齐 scan_report
    零回归语义；组合扫描 infer 到 combined 时回落白盒桶——融合产物是 per-run 的，
    由 blackbox-runs/{run_id}/report-data?track=combined 服务）。缺产物 404：前端据此
    回退旧 md 渲染路径（旧 scan 兼容）。
    """
    scan_dir = _scan_dir_or_404(request, ws, scan_id)
    if track in (None, ""):
        resolved = DeliverablesReader(scan_dir)._infer_track()
        track = "whitebox" if resolved == "combined" else resolved
    if track not in ("whitebox", "blackbox"):
        raise HTTPException(422, "track 须为 whitebox|blackbox（combined 走 blackbox-runs 端点）")
    return _read_report_data(scan_dir / "deliverables" / track / REPORT_DATA_FILENAME)


@router.get("/{ws}/scans/{scan_id}/dataflow")
async def scan_dataflow(ws: str, scan_id: str, request: Request,
                        _: User = Depends(workspace_member)):
    """P5: 数据流视图（dataflow_view.json）。读 whitebox intermediate 产物，
    缺 -> 404 "dataflow view not generated"。对齐 scan_report 鉴权（workspace_member）。
    """
    return _dataflow_view_for(_scan_dir_or_404(request, ws, scan_id))


def _adversarial_review_for(scan_dir: Path) -> dict:
    """直读 intermediate/adversarial_review.json（spec 2026-09-10 §4.8）。

    不经 DeliverablesReader——端点返 JSON 非 text/plain 截断（对齐
    _dataflow_view_for 模式）。缺失/坏 JSON 一律 404，不 500 冒泡。
    """
    import json
    from supernova_core.utils.paths import resolve_intermediate, WHITEBOX_SUBDIR
    wb_dir = scan_dir / "deliverables" / WHITEBOX_SUBDIR
    path = resolve_intermediate(wb_dir, "adversarial_review.json")
    if path is None or not path.is_file():
        raise HTTPException(404, "adversarial review not generated")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise HTTPException(404,
                            f"adversarial review unreadable: {exc}") from exc
    if not isinstance(data, dict):
        raise HTTPException(404, "adversarial review malformed")
    return data


@router.get("/{ws}/scans/{scan_id}/adversarial-review")
async def scan_adversarial_review(
    ws: str, scan_id: str, request: Request,
    _: User = Depends(workspace_member),
) -> dict:
    """对抗性审查结果（spec 2026-09-10 §4.8）。读 whitebox intermediate
    产物 adversarial_review.json，缺 -> 404。对齐 scan_dataflow 鉴权与直读模式。
    """
    return _adversarial_review_for(_scan_dir_or_404(request, ws, scan_id))


@router.get("/{ws}/scans/{scan_id}/evidence-matrix")
async def scan_evidence_matrix(ws: str, scan_id: str, request: Request,
                               _: User = Depends(workspace_member)) -> dict:
    """api_evidence_matrix.json（spec 2026-09-10 §7）——接口级证据矩阵。

    产物新鲜直读；缺失/陈旧（源产物 mtime 更新，典型 = 黑盒 run 完成后）且
    whitebox report_data.json 在 → web 进程内跑 core 纯聚合函数重建（零 agent，
    不违 web 零 agent 执行点铁律）+ 落盘缓存（写失败只返不缓存）。缓存坏 JSON
    按不可用缓存处理（落回重建自愈，不 500）。重建条件不满足但有旧产物 →
    返旧文件；两者皆无（或旧产物也坏）→ 404。
    """
    import json as _json

    from supernova_core.services.api_evidence_matrix import (
        EVIDENCE_MATRIX_FILENAME, build_api_evidence_matrix)
    from supernova_core.utils.atomic_write import atomic_write_json

    scan_dir = _scan_dir_or_404(request, ws, scan_id)
    matrix_path = scan_dir / "deliverables" / EVIDENCE_MATRIX_FILENAME
    wb_rd = scan_dir / "deliverables" / "whitebox" / REPORT_DATA_FILENAME

    def _read_matrix() -> dict | None:
        """读缓存；坏 JSON / 读失败 → None（不可用缓存，调用方走重建/兜底）。"""
        try:
            return _json.loads(matrix_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def _stale() -> bool:
        """缓存 mtime < 任一源产物 mtime → 陈旧。

        blackbox-runs/ 与 deliverables/ 平级（utils/paths.blackbox_runs_dir），
        glob 从 scan_dir 起——曾误挂 deliverables/ 前缀致黑盒 verdicts 更新
        永不触发重建。
        """
        try:
            cached_mtime = matrix_path.stat().st_mtime
        except OSError:
            return True
        sources = [scan_dir / "deliverables" / "whitebox" /
                   "intermediate" / "entry_points.json", wb_rd, *scan_dir.glob(
            "blackbox-runs/run-*/deliverables/blackbox/"
            "intermediate/*_exploit_verdicts.json")]
        for p in sources:
            try:
                if p.exists() and p.stat().st_mtime > cached_mtime:
                    return True
            except OSError:
                continue  # 源被并发删（sweep）→ 不作陈旧依据，也不 500
        return False

    if matrix_path.exists() and not _stale():
        cached = _read_matrix()
        if cached is not None:
            return cached  # 坏 JSON（此处 None）→ 落回下方重建自愈
    if not wb_rd.exists():
        cached = _read_matrix() if matrix_path.exists() else None
        if cached is not None:
            return cached  # 无法重建（report_data 缺）→ 旧文件兜底
        raise HTTPException(404, "evidence matrix not available")
    matrix = build_api_evidence_matrix(scan_dir)
    try:
        atomic_write_json(matrix_path, matrix)
    except OSError:
        pass  # 只读挂载等：不缓存，仅返回
    return matrix


def assemble_correlation_detail(scan_dir: Path) -> dict:
    """C5: 组装 correlation scan 详情（纯函数，只读 scan_dir 便于单测）。

    关联产物由 run_correlation_phase 写在 deliverables/ 根（无 track 桶——非白盒/
    黑盒产物，不经 DeliverablesReader），此处原文透传 JSON（不 preview 截断）。
    缺文件语义（关联未跑完，前端显示进行中/未开始）：topology/report_md → None、
    boundaries/flows → []、{vc}_exploitation_queue.json 缺 → merged_vulns 键缺席
    （不用空数组冒充「该类无漏洞」）。drift_warnings 首版保守返回 []（不解析
    correlation-report.md；事件/report 提取留给后续版本）。
    """
    import json
    from supernova_core.session import SessionManager

    dlv = scan_dir / "deliverables"

    def _read_json(name: str):
        try:
            return json.loads((dlv / name).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def _read_text(name: str) -> str | None:
        try:
            return (dlv / name).read_text(encoding="utf-8")
        except OSError:
            return None

    merged_vulns: dict[str, list] = {}
    for q in sorted(dlv.glob("*_exploitation_queue.json")):
        data = _read_json(q.name)
        if isinstance(data, dict) and isinstance(data.get("vulnerabilities"), list):
            merged_vulns[q.name[: -len("_exploitation_queue.json")]] = data["vulnerabilities"]

    boundaries = _read_json("trust-boundaries.json")
    flows_raw = _read_json("cross-service-flows.json")
    # spec 2026-08-27 §8/§9:flows json 对象形态 {"flows": [...], "multi_hop_chains": [...]}
    # 旧产物(2026-08-27 前)是 list 形态 —— flows 透传、multi_hop_chains 兜空。
    if isinstance(flows_raw, dict):
        flows = flows_raw.get("flows")
        multi_hop_chains = flows_raw.get("multi_hop_chains")
    else:
        flows, multi_hop_chains = flows_raw, None
    adjudication = _read_json("adjudication-log.json")
    session = SessionManager(scan_dir.parent).get_session_data(scan_dir)
    return {
        "topology": _read_json("cross-service-topology.json"),
        "boundaries": boundaries if isinstance(boundaries, list) else [],
        "flows": flows if isinstance(flows, list) else [],
        "multi_hop_chains": multi_hop_chains if isinstance(multi_hop_chains, list) else [],
        "adjudication": adjudication if isinstance(adjudication, dict) else None,
        "merged_vulns": merged_vulns,
        "drift_warnings": [],
        "corr_children": session.get("corr_children") or [],
        "report_md": _read_text("correlation-report.md"),
    }


@router.get("/{ws}/scans/{scan_id}/correlation")
async def get_correlation_detail(ws: str, scan_id: str, request: Request,
                                 _: User = Depends(workspace_member)) -> dict:
    """C5: correlation scan 详情（跨仓关联结果视图数据源，spec 2026-08-24）。

    404=scan 不存在；422=非 correlation scan；200=详情（产物未生成时各字段
    null/[]，前端据此显示「关联阶段进行中/未开始」）。鉴权对齐 scan_report
    （workspace_member：能访问 ws 就能访问该 ws 所有 scan）。
    """
    from supernova_core.session import SessionManager
    scan_dir = _scan_dir_or_404(request, ws, scan_id)
    if SessionManager(scan_dir.parent).get_scan_type(scan_dir) != "correlation":
        raise HTTPException(422, "not a correlation scan")
    return assemble_correlation_detail(scan_dir)


@router.get("/{ws}/scans/{scan_id}/logs")
async def scan_logs(ws: str, scan_id: str, request: Request, _: User = Depends(workspace_member),
                    file: str | None = Query(None)):
    return logs_for(_scan_dir_or_404(request, ws, scan_id), file)


@router.get("/{ws}/scans/{scan_id}/events")
async def scan_events(ws: str, scan_id: str, request: Request, _: User = Depends(workspace_member)):
    scan_dir = _scan_dir_or_404(request, ws, scan_id)
    from .events import build_scan_events_response
    return await build_scan_events_response(request, scan_dir)


@router.delete("/{ws}/scans/{scan_id}")
async def delete_scan(ws: str, scan_id: str, request: Request, _: User = Depends(workspace_member)):
    """删除单个 scan（真删目录，spec §5.1 DELETE）。

    DELETE 语义=删资源（同 delete_workspace）；取消走 POST /{ws}/scans/{scan_id}/cancel。
    running scan -> 409（先取消再删，避免删在跑 workflow 的目录致状态不一致）；不存在 -> 404。
    """
    from supernova_web.components.scan_manager import ScanRunning
    sm = request.app.state.scan_manager
    try:
        result = await sm.delete(ws, scan_id)
    except ScanRunning as e:
        raise HTTPException(409, str(e))
    if result is None:
        raise HTTPException(404, "scan not found")
    return result


@router.post("/{ws}/scans/{scan_id}/cancel")
async def cancel_scan(ws: str, scan_id: str, request: Request, _: User = Depends(workspace_member)):
    """取消 scan（动作型 POST，对齐 resume POST 子路径风格）。

    web 自起 -> handle.cancel；host 在跑 -> cancel.requested；已死 -> 标 cancelled。
    不存在 -> 404。
    """
    sm = request.app.state.scan_manager
    result = await sm.cancel(ws, scan_id)
    if result is None:
        raise HTTPException(404, "scan not found")
    return result


@router.post("/{ws}/scans/batch-cancel", response_model=ScanBatchAccepted, status_code=202)
async def batch_cancel_scans(ws: str, req: ScanIdsBatchRequest, request: Request,
                             _: User = Depends(workspace_member)):
    """批量取消扫描任务（2026-09-15 批量取消/续跑）。

    端点层状态门（running/queued 才调 sm.cancel）+ 逐项循环调既有单点——scan_manager
    其余零改动。状态门是硬要求：cancel 自身无状态门，对 completed 等终态裸调也会
    _mark_cancelled 覆写成 cancelled（单行按钮靠 UI 条件挡，批量必须服务端挡
    「勾选到确认之间任务自己跑完」的漂移）；被拦项记 skipped 未触副作用。
    单项异常只计入该行 results 不阻断整批。有任何成功 → 202；零成功（含全跳过）→ 422
    （body 顶层即 ScanBatchAccepted，对齐 batch-scan 先例）。
    """
    sm = request.app.state.scan_manager
    results: list[ScanBatchResultItem] = []
    for scan_id in req.scan_ids:
        status = sm.scan_status(ws, scan_id)
        if status is None:
            results.append(ScanBatchResultItem(scan_id=scan_id, ok=False, error="scan 不存在"))
            continue
        if status not in ("running", "queued"):
            results.append(ScanBatchResultItem(
                scan_id=scan_id, ok=False, skipped=True,
                error=f"状态为 {status}，已结束，无需取消"))
            continue
        try:
            await sm.cancel(ws, scan_id)
            results.append(ScanBatchResultItem(scan_id=scan_id, ok=True))
        except Exception as e:  # noqa: BLE001 - 单项失败不阻断整批（对齐 batch-scan）
            results.append(ScanBatchResultItem(scan_id=scan_id, ok=False, error=str(e)))
    submitted = sum(1 for r in results if r.ok)
    skipped = sum(1 for r in results if r.skipped)
    if submitted == 0:
        return JSONResponse(status_code=422, content=ScanBatchAccepted(
            workspace=ws, submitted=0, skipped=skipped,
            failed=len(results) - skipped, results=results).model_dump())
    return ScanBatchAccepted(workspace=ws, submitted=submitted, skipped=skipped,
                             failed=len(results) - submitted - skipped, results=results)


@router.post("/{ws}/scans/batch-resume", response_model=ScanBatchAccepted, status_code=202)
async def batch_resume_scans(ws: str, req: ScanIdsBatchRequest, request: Request,
                             _: User = Depends(workspace_member)):
    """批量续跑扫描任务（2026-09-15 批量取消/续跑）。

    逐项循环调既有单点 sm.resume——resume 自带状态门（_RESUMABLE_STATUSES + 心跳
    判活），ValueError/TemporalUnavailable 逐项转 error 不阻断整批（cancelled 收尾
    transient 窗口的 422 同路回显）。有任何成功 → 202；全失败 → 422。
    """
    from supernova_web.components.scan_manager import TemporalUnavailable
    sm = request.app.state.scan_manager
    results: list[ScanBatchResultItem] = []
    for scan_id in req.scan_ids:
        try:
            await sm.resume(ws, scan_id)
            results.append(ScanBatchResultItem(scan_id=scan_id, ok=True))
        except ValueError as e:
            results.append(ScanBatchResultItem(scan_id=scan_id, ok=False, error=str(e)))
        except TemporalUnavailable:
            results.append(ScanBatchResultItem(
                scan_id=scan_id, ok=False, error="Temporal 服务未运行，请先 docker-compose up -d"))
        except Exception as e:  # noqa: BLE001 - 单项失败不阻断整批
            results.append(ScanBatchResultItem(scan_id=scan_id, ok=False, error=str(e)))
    submitted = sum(1 for r in results if r.ok)
    if submitted == 0:
        return JSONResponse(status_code=422, content=ScanBatchAccepted(
            workspace=ws, submitted=0, skipped=0,
            failed=len(results), results=results).model_dump())
    return ScanBatchAccepted(workspace=ws, submitted=submitted, skipped=0,
                             failed=len(results) - submitted, results=results)


# 批量删除终态门：可删状态集（对齐 workspaces_indexer._TERMINAL_STATUSES + done）。
# running/queued 拦（queued 单点 delete 只拦 raw=running——排队 workflow 获槽后写
# 文件会变孤儿；批量门用 effective 口径一并拦）。
_BATCH_DELETABLE = frozenset({
    "completed", "done", "failed", "killed", "crashed", "cancelled", "interrupted"})


@router.post("/{ws}/scans/batch-delete", response_model=ScanBatchAccepted, status_code=202)
async def batch_delete_scans(ws: str, req: ScanIdsBatchRequest, request: Request,
                             _: User = Depends(workspace_member)):
    """批量删除扫描任务（2026-09-15 批量删除）：effective 状态门只放行终态，
    其余记 skipped；门过后才翻 running 的竞态由 sm.delete 的 ScanRunning 逐项兜底。
    单项异常不阻断整批；零成功（含全跳过）→ 422（body 顶层同形）。
    """
    from supernova_web.components.scan_manager import ScanRunning
    sm = request.app.state.scan_manager
    results: list[ScanBatchResultItem] = []
    for scan_id in req.scan_ids:
        status = sm.scan_status(ws, scan_id)
        if status is None:
            results.append(ScanBatchResultItem(scan_id=scan_id, ok=False, error="scan 不存在"))
            continue
        if status not in _BATCH_DELETABLE:
            results.append(ScanBatchResultItem(
                scan_id=scan_id, ok=False, skipped=True,
                error=f"状态为 {status}，请先取消再删除"))
            continue
        try:
            deleted = await sm.delete(ws, scan_id)
            if deleted is None:
                results.append(ScanBatchResultItem(scan_id=scan_id, ok=False, error="scan 不存在"))
            else:
                results.append(ScanBatchResultItem(scan_id=scan_id, ok=True))
        except ScanRunning as e:
            results.append(ScanBatchResultItem(scan_id=scan_id, ok=False, error=str(e)))
        except Exception as e:  # noqa: BLE001 - 单项失败不阻断整批
            results.append(ScanBatchResultItem(scan_id=scan_id, ok=False, error=str(e)))
    submitted = sum(1 for r in results if r.ok)
    skipped = sum(1 for r in results if r.skipped)
    if submitted == 0:
        return JSONResponse(status_code=422, content=ScanBatchAccepted(
            workspace=ws, submitted=0, skipped=skipped,
            failed=len(results) - skipped, results=results).model_dump())
    return ScanBatchAccepted(workspace=ws, submitted=submitted, skipped=skipped,
                             failed=len(results) - submitted - skipped, results=results)


@router.get("/{ws}/scans/{scan_id}/resume-preview")
async def get_resume_preview(ws: str, scan_id: str, request: Request,
                             _: User = Depends(workspace_member)):
    """断点详情（spec 2026-08-27-web-resume-breakpoint §4.5，只读不动状态）。

    白盒行：agent 对账（completed_agents / interrupted_agent / warnings）+ step
    缓存简表（done/stale/missing）+ resumable 判定（abort/心跳/状态不可续跑 →
    false 带 reason/abort_reason）。correlation / blackbox → resumable:false。
    scan 不存在 -> 404。
    """
    sm = request.app.state.scan_manager
    try:
        return await sm.resume_preview(ws, scan_id)
    except ValueError as e:
        msg = str(e)
        if "不存在" in msg:
            raise HTTPException(404, msg)
        raise HTTPException(422, msg)


@router.post("/{ws}/scans/{scan_id}/resume", status_code=202)
async def resume_scan(ws: str, scan_id: str, request: Request, _: User = Depends(workspace_member)):
    """续跑已停未完成的 scan（interrupted/crashed/failed/cancelled/killed，
    spec 2026-08-27-web-resume-breakpoint §4.1）——白盒行先 agent 级对账再提交，
    completed/running -> 422（completed 用重扫 POST /api/scan 起新 scan，旧记录保留）。
    scan 不存在 -> 404。
    """
    from supernova_web.components.scan_manager import TemporalUnavailable
    sm = request.app.state.scan_manager
    try:
        ws_name, scan_id_out = await sm.resume(ws, scan_id)
    except ValueError as e:
        msg = str(e)
        if "不存在" in msg:
            raise HTTPException(404, msg)
        raise HTTPException(422, msg)
    except TemporalUnavailable:
        raise HTTPException(400, "Temporal 服务未运行，请先 docker-compose up -d")
    return {"workspace": ws_name, "scan_id": scan_id_out}


@router.post("/{ws}/scans/{scan_id}/combined/rerun-blackbox", status_code=202)
async def rerun_blackbox(ws: str, scan_id: str, request: Request,
                         _: User = Depends(workspace_member)):
    """组合扫描黑盒续跑（spec §11.3 / D5）：黑盒 failed 后换认证续跑，复用白盒产物，
    起新黑盒 workflow ``{ws}-{scan_id}-bb-rerun-{N}``。

    body 语义：空 / null / ``{}`` = 沿用原认证（v1 无新认证，前端 ``apiPost`` 恒发 JSON ``"{}"``）；
    非空 JSON 对象 = 换认证（须合法组合模式 ScanRequest：type=whitebox + url +
    authentication/auth_profile，复用既有 model 校验，非法 → 422）。

    手动读 raw body 而非 ``body: ScanRequest | None = Body(default=None)``——后者对
    ``Content-Type: application/json`` + ``{}`` 非空 body 强制按 ScanRequest 校验，type 必填 → 422，
    破坏 v1 无新认证路径（review-cea7ac6b..b4ece1b1 Important #1）。

    前置：scan 存在（404）+ combined 且 bb_phase=failed（422）+ 白盒产物完好（422）。
    换认证时先 _run_precheck 预验证——fail → 仍 202 但 bb_phase=auth_failed（异步标）。
    """
    import json as _json
    from pydantic import ValidationError
    from supernova_web.components.scan_manager import TemporalUnavailable
    from supernova_web.models import ScanRequest

    # 空 / null / {} = 沿用原认证；其余按 ScanRequest 校验（换认证）。
    new_auth = None
    raw = (await request.body()).strip()
    if raw and raw not in (b"null", b"{}", b"[]"):
        try:
            payload = _json.loads(raw)
        except _json.JSONDecodeError as e:
            raise HTTPException(422, f"invalid JSON body: {e}")
        if isinstance(payload, dict) and payload:
            try:
                new_auth = ScanRequest.model_validate(payload)
            except ValidationError as e:
                raise HTTPException(422, e.errors())

    sm = request.app.state.scan_manager
    try:
        run_id = await sm.rerun_blackbox(ws, scan_id, new_auth=new_auth)
    except ValueError as e:
        msg = str(e)
        if "不存在" in msg:
            raise HTTPException(404, msg)
        raise HTTPException(422, msg)
    except TemporalUnavailable:
        raise HTTPException(400, "Temporal 服务未运行，请先 docker-compose up -d")
    return {"workspace": ws, "scan_id": scan_id, "run_id": run_id}
