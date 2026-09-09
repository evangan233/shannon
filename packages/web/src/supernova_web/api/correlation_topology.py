from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, field_validator

from supernova_web.auth.dependencies import workspace_member
from supernova_web.auth.models import User
from supernova_web.components.topology_analysis import (
    AnalysisNotFound, TopologyAnalysisActive, TopologyProviderConfigError,
    TooManyTopologyAnalyses,
    TopologyValidationError,
)
from supernova_web.components.ws_config_store import ProviderConfigIncomplete

router = APIRouter(prefix="/api/workspaces", tags=["correlation-topology"])


class StartTopologyBody(BaseModel):
    repos: list[str]
    refresh: bool = False

    @field_validator("repos")
    @classmethod
    def _unique(cls, value: list[str]) -> list[str]:
        return list(dict.fromkeys(value))


@router.post("/{ws}/correlation-topology/analyses", status_code=202)
async def start_analysis(ws: str, body: StartTopologyBody, request: Request,
                         _: User = Depends(workspace_member)):
    try:
        analysis_id = await request.app.state.topology_manager.start(
            ws, body.repos, refresh=body.refresh)
    except TopologyValidationError as exc:
        raise HTTPException(422, detail={
            "code": "invalid_repositories", "message": str(exc), "repos": exc.repos,
        })
    except TooManyTopologyAnalyses as exc:
        raise HTTPException(429, detail={"code": "too_many_analyses", "message": str(exc)})
    except ProviderConfigIncomplete as exc:
        raise HTTPException(422, detail={
            "code": "provider_incomplete", "message": str(exc), "missing": exc.missing,
        })
    except TopologyProviderConfigError as exc:
        raise HTTPException(422, detail={
            "code": "provider_invalid", "message": str(exc),
        })
    except ValueError as exc:
        # 兜底：store 层 ws 名/路径校验（__legacy__ 时代 500 回归）。注意须排在
        # TopologyValidationError/TopologyProviderConfigError（均为 ValueError 子类）
        # 之后，勿抢子类语义。转 422 JSON，勿让 500 纯文本把前端 json() 解析炸成
        # "body stream already read"。
        raise HTTPException(422, detail={
            "code": "invalid_workspace", "message": str(exc),
        })
    return {"analysis_id": analysis_id}


@router.get("/{ws}/correlation-topology/analyses")
async def list_analyses(ws: str, request: Request, _: User = Depends(workspace_member)):
    """分析历史列表（摘要，created_at 降序）：前端「历史分析」选择器数据源；
    选中条目后经 /{analysis_id} 拉全量（result）。路径无尾段，与 /{analysis_id}
    动态路由天然不冲突。"""
    return request.app.state.topology_manager.list_analyses(ws)


@router.get("/{ws}/correlation-topology/analyses/latest")
async def latest_analysis(ws: str, request: Request, _: User = Depends(workspace_member)):
    """刷新恢复入口：页面 mount 时取最近一条 analysis 恢复状态/日志轮询。

    必须注册在 /{analysis_id} 动态路由之前，否则 "latest" 会被当 analysis_id 吞掉。
    """
    try:
        return request.app.state.topology_manager.latest(ws)
    except AnalysisNotFound:
        raise HTTPException(404, detail={"code": "analysis_not_found", "message": "no analyses"})


@router.get("/{ws}/correlation-topology/analyses/{analysis_id}/log")
async def analysis_log(ws: str, analysis_id: str, request: Request,
                       after: int = -1, limit: int = 200,
                       _: User = Depends(workspace_member)):
    """过程日志尾读：tool-audit.ndjson 按 after 行号游标增量，服务端裁剪摘要。"""
    try:
        return request.app.state.topology_manager.tail_log(
            ws, analysis_id, after=after, limit=max(1, min(limit, 1000)))
    except AnalysisNotFound:
        raise HTTPException(404, detail={"code": "analysis_not_found", "message": "analysis not found"})


@router.get("/{ws}/correlation-topology/analyses/{analysis_id}")
async def get_analysis(ws: str, analysis_id: str, request: Request,
                       _: User = Depends(workspace_member)):
    try:
        return request.app.state.topology_manager.api_view(ws, analysis_id)
    except AnalysisNotFound:
        raise HTTPException(404, detail={"code": "analysis_not_found", "message": "analysis not found"})


@router.post("/{ws}/correlation-topology/analyses/{analysis_id}/delete")
async def delete_analysis(ws: str, analysis_id: str, request: Request,
                          _: User = Depends(workspace_member)):
    """删除单条历史分析（真删 state/log 目录）。旧 DELETE 保留为取消语义。

    queued/running -> 409（先取消再删，防止 worker 晚到写回）；不存在 -> 404。
    """
    try:
        return await request.app.state.topology_manager.delete(ws, analysis_id)
    except TopologyAnalysisActive:
        raise HTTPException(409, detail={
            "code": "analysis_active",
            "message": "cancel the analysis before deleting it",
        })
    except AnalysisNotFound:
        raise HTTPException(404, detail={"code": "analysis_not_found", "message": "analysis not found"})


@router.delete("/{ws}/correlation-topology/analyses/{analysis_id}")
async def cancel_analysis(ws: str, analysis_id: str, request: Request,
                          _: User = Depends(workspace_member)):
    try:
        await request.app.state.topology_manager.cancel(ws, analysis_id)
        return request.app.state.topology_manager.api_view(ws, analysis_id)
    except AnalysisNotFound:
        raise HTTPException(404, detail={"code": "analysis_not_found", "message": "analysis not found"})
