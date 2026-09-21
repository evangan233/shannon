"""proto service/rpc parser → RPC route lookup table.

spec 2026-09-21-rpc-endpoint-correlation §3.1 单元 1：扫描仓内 .proto，
解析 service/rpc 块产 (service, method) → ProtoRouteInfo 查找表。只产查找表
不产 EntryPoint——proto-only 不进底册（proto 里约半数是「调下游」的客户端
定义，直接当本仓入口会产假接口卡，spec §2 D3）；同名 join 在
merge_entry_points_from_deliverable（§3.1 单元 2）。

解析失败（花括号失衡等）→ 该文件跳过（warning），非致命，对齐
schema_entry_parser 降级风格。srpc 命令字等 option 附带记录进 options，
不参与 join 键（spec §2 D5）。
"""

import logging
import os
import re
from pathlib import Path

from pydantic import BaseModel

from supernova_core.code_index.models import CodeIndex, EntryPoint
from supernova_core.code_index.path_exclusions import is_excluded_dir

logger = logging.getLogger(__name__)


class ProtoRouteInfo(BaseModel):
    """单个 rpc 方法的 proto 侧信息（route 为 /Service/Method 短形态，D1）。"""

    route: str
    proto_file: str
    package: str | None = None
    options: dict[str, str] = {}


_COMMENT_BLOCK_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_COMMENT_LINE_RE = re.compile(r"//[^\n]*")
_SERVICE_RE = re.compile(r"\bservice\s+(\w+)\s*\{")
_RPC_RE = re.compile(r"\brpc\s+(\w+)\s*\(")
_PACKAGE_RE = re.compile(r"\bpackage\s+([\w.]+)\s*;")
# 只抓简单赋值形态；嵌套 message 值（如 HttpRouteOptions { get: "/x" }）含
# `{` 天然不匹配，安全跳过（spec §2 D5：option 不参与 join 键）
_OPTION_RE = re.compile(r"option\s*\(\s*srpc\.(\w+)\s*\)\s*=\s*([^;{]+);")


def _strip_comments(text: str) -> str:
    """注释替换为等长空白（保偏移/行结构），防注释伪 service 块误配。"""
    text = _COMMENT_BLOCK_RE.sub(lambda m: " " * len(m.group(0)), text)
    return _COMMENT_LINE_RE.sub(lambda m: " " * len(m.group(0)), text)


def _match_braces(text: str, open_idx: int) -> int | None:
    """text[open_idx] 必须是 `{`；返回配对 `}` 偏移，失衡返回 None。"""
    depth = 0
    for i in range(open_idx, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return None


def _parse_srpc_options(segment: str) -> dict[str, str]:
    return {m.group(1): m.group(2).strip() for m in _OPTION_RE.finditer(segment)}


def _parse_services(clean: str, rel: str, package: str | None) -> dict[tuple[str, str], ProtoRouteInfo]:
    table: dict[tuple[str, str], ProtoRouteInfo] = {}
    for svc in _SERVICE_RE.finditer(clean):
        name = svc.group(1)
        close = _match_braces(clean, svc.end() - 1)
        if close is None:
            logger.warning("proto parse: %s service %s 花括号失衡，跳过", rel, name)
            return table
        body = clean[svc.end():close]
        # 按 rpc 切段：头段 option 归 service 级，各 rpc 段 option 归该方法
        rpcs = list(_RPC_RE.finditer(body))
        service_opts = _parse_srpc_options(body[:rpcs[0].start()] if rpcs else body)
        for i, rpc in enumerate(rpcs):
            seg_end = rpcs[i + 1].start() if i + 1 < len(rpcs) else len(body)
            method = rpc.group(1)
            opts = {**service_opts,
                    **_parse_srpc_options(body[rpc.start():seg_end])}
            table[(name, method)] = ProtoRouteInfo(
                route=f"/{name}/{method}",
                proto_file=rel,
                package=package,
                options=opts,
            )
    return table


def parse_proto_services(repo_path: str) -> dict[tuple[str, str], ProtoRouteInfo]:
    """Parse all .proto files under repo_path → (service, method) lookup table.

    CMD 命令号风格纯 message proto（无 service 块）天然产空表；排除目录
    （path_exclusions 共享名单）不扫；花括号失衡的文件整文件跳过。
    """
    table: dict[tuple[str, str], ProtoRouteInfo] = {}
    repo = Path(repo_path)
    if not repo.exists():
        return table

    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if not is_excluded_dir(d) and not d.startswith(".")]
        for f in files:
            if not f.endswith(".proto"):
                continue
            path = Path(root) / f
            try:
                raw = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                logger.warning("proto parse: %s 读取失败，跳过（%s）", path, exc)
                continue
            clean = _strip_comments(raw)
            pkg = _PACKAGE_RE.search(clean)
            rel = path.relative_to(repo).as_posix()
            table.update(_parse_services(
                clean, rel, pkg.group(1) if pkg else None))

    logger.info("proto schema parse: %d rpc methods from %s", len(table), repo)
    return table


# join 命中后的 confidence：签名启发式（0.70）+ proto 双重印证，恰过
# save_adjudication 的 CONFIRMED 线（>=0.85）
_JOINED_CONFIDENCE = 0.85


def join_proto_routes(index: CodeIndex,
                      proto_table: dict[tuple[str, str], ProtoRouteInfo]) -> CodeIndex:
    """grpc_service 入口的 proto 同名 join（spec §3.1 单元 2）。

    join 策略（D2）：FuncBlock.class_name（Go receiver type，go_parser 已填）
    非空时优先 (class_name, method) 双键精确命中；双键 miss 退化单键。单键
    （method 名）须全表唯一命中才采信——多 service 同名 method 歧义不 join
    （宁缺勿错）。命中填 route=/Service/Method、evidence 注 proto 出处、
    confidence 提至 0.85。非 grpc_service / 已有 route 的入口不动。
    """
    if not proto_table:
        return index
    block_class = {b.id: b.class_name for b in index.blocks}
    by_method: dict[str, list[tuple[str, str]]] = {}
    for key in proto_table:
        by_method.setdefault(key[1], []).append(key)

    updated: list[EntryPoint] = []
    joined = 0
    for ep in index.entry_points:
        if ep.entry_type != "grpc_service" or ep.route:
            updated.append(ep)
            continue
        func_name = ep.func_block_id.rsplit(":", 2)[-2]
        info = None
        cls = block_class.get(ep.func_block_id)
        if cls is not None:
            info = proto_table.get((cls, func_name))
        if info is None:
            cands = by_method.get(func_name, [])
            if len(cands) == 1:
                info = proto_table[cands[0]]
        if info is None:
            updated.append(ep)
            continue
        pkg_suffix = f" (package={info.package})" if info.package else ""
        updated.append(ep.model_copy(update={
            "route": info.route,
            "confidence": _JOINED_CONFIDENCE,
            "evidence": (f"{ep.evidence}; "
                         f"joined from proto: {info.proto_file}{pkg_suffix}"),
        }))
        joined += 1

    if joined:
        logger.info("proto route join: %d/%d grpc_service entries joined",
                    joined, len(index.entry_points))
    return index.model_copy(update={"entry_points": updated})
