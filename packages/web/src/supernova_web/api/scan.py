from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import ValidationError

from supernova_web.auth.dependencies import current_user, workspace_member
from supernova_web.components.workspace_provisioner import is_global_admin, is_safe_workspace_name
from supernova_web.auth.models import User
from supernova_web.components.scan_manager import TemporalUnavailable
from supernova_web.components.ws_config_store import ProviderConfigIncomplete
from supernova_web.models import ScanAccepted, ScanRequest

router = APIRouter(prefix="/api/scan", tags=["scan"])


@router.post("", response_model=ScanAccepted, status_code=202)
async def create_scan(req: ScanRequest, request: Request,
                      user: User = Depends(current_user)):
    # P1: scan 必须在 admin 预建好的 ws 内跑 (替代原 scan 创建 manager 模型)。
    # ws 先于 scan 存在, 为 P2 repo 隔离铺路; 这里只校验, 不创建。
    ws = req.workspace
    if not ws or not is_safe_workspace_name(ws):
        raise HTTPException(422, "workspace 不存在，请先让 admin 创建")
    ws_dir = request.app.state.config.workspaces_dir / ws
    if not ws_dir.is_dir() or ws_dir.is_symlink():
        raise HTTPException(422, "workspace 不存在，请先让 admin 创建")
    if not is_global_admin(user) and request.app.state.auth_store.get_workspace_member_role(
            ws, user.id) is None:
        raise HTTPException(403, "非该 workspace 成员")
    sm = request.app.state.scan_manager
    try:
        # Web workspace scan 必须使用完整的 workspace-owned Provider 配置，不能把全局
        # env/model 当作缺省值。API 层先检一遍，避免 fake/替代 scan manager 绕过约束。
        try:
            request.app.state.ws_config_store.resolve_provider_config(ws)
        except ProviderConfigIncomplete as e:
            # 工作区缺 LLM 凭据等必填字段 → 结构化错误，让前端区分于真正的 yaml 校验失败，
            # 显示「请前往工作区设置补全凭据」而非「yaml 校验失败」（HTTPException 穿透下方
            # 通用 except ValueError）。
            raise HTTPException(422, detail={"code": "provider_incomplete", "missing": e.missing})
        ws_name, scan_id = await sm.start(req)
    except TemporalUnavailable:
        raise HTTPException(400, "Temporal 服务未运行，请先 docker-compose up -d")
    except PermissionError as e:
        # OS-level EACCES/EPERM from ws_dir.mkdir()（git-creds 来源已于 Task 3 移除）
        raise HTTPException(400, str(e))
    except ValueError as e:
        raise HTTPException(422, str(e))
    except ValidationError as e:  # correlation yaml 校验失败
        raise HTTPException(422, detail=e.errors())
    # 组合扫描：start 已写 bb_phase=precheck 到 session（precheck 在后台 kickoff 跑）。
    # 读回透传给前端显「预验证中」+ 跳 live 页跟踪进度（spec §8.2）。best-effort：scan_dir
    # 不存在 / session 无 bb_phase → None（纯白盒/黑盒）。
    bb_phase = None
    if scan_id:
        from supernova_core.session import SessionManager
        scan_dir = request.app.state.config.workspaces_dir / ws_name / "scans" / scan_id
        if scan_dir.is_dir():
            try:
                bb_phase = SessionManager(scan_dir.parent).get_session_data(scan_dir).get("bb_phase")
            except Exception:  # noqa: BLE001 - 读 session best-effort，不阻塞提交响应
                bb_phase = None
    return ScanAccepted(workspace=ws_name, scan_id=scan_id, bb_phase=bb_phase)


@router.get("/gate")
async def get_scan_gate(request: Request, user: User = Depends(current_user)):
    """全局扫描闸门快照（排队可视化，spec 2026-09-08-worker-scan-gate §8.1）。

    快照由 worker 闸门原子写（<workspaces_root>/gate_state.json）；文件缺失/损坏
    = worker 未起或未配置落盘 → 空快照。**全员可见完整快照，不按 ws 成员过滤**
    （2026-09-09 用户裁定）：闸门是共享调度器，其存在意义就是让所有用户看到全局
    占用与自己的排队位次——成员过滤会让「为什么排队」的答案本身缺失。条目只含
    ws/类型/标签/时刻，不含报告或漏洞数据。
    """
    from supernova_core.services.scan_gate import read_gate_snapshot_file
    sf = request.app.state.config.workspaces_dir / "gate_state.json"
    return read_gate_snapshot_file(sf) or {
        "capacity": 5, "max_waiting": 50, "held": [], "waiting": []}
