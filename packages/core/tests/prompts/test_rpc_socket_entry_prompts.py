"""RPC/Socket 入口识别（2026-09-15 补齐）prompt 锚点。

单仓扫描下游 gRPC / socket 服务仓（入口非 HTTP，上游网关才有 HTTP）曾
是 LLM 轨全链路盲区：pre-recon Entry Point Mapper 与 recon 五角度全
HTTP 向，vuln-injection 的 coverage_requirements 也不含 RPC/Socket
输入向量。本测试锁定三处 prompt 的补齐锚点（配套 GitNexus 轨
source_rules.yml rpc/socket 规则 + entry_points grpc_service /
socket_handler 检测）。
"""
from pathlib import Path

PROMPTS_DIR = Path(__file__).resolve().parents[4] / "prompts"


def test_pre_recon_entry_point_mapper_covers_rpc_socket():
    text = (PROMPTS_DIR / "pre-recon-code.txt").read_text(encoding="utf-8")
    # Entry Point Mapper 指令补非 HTTP 服务入口枚举目标
    assert "gRPC" in text
    assert "Thrift" in text or "Dubbo" in text
    assert "socket" in text.lower()
    assert "WebSocket" in text
    # 上游网关转发语义（服务间入口的公网可达性判断依据）
    assert "upstream" in text.lower()


def test_recon_static_has_sixth_angle_rpc_socket():
    text = (PROMPTS_DIR / "recon-static.txt").read_text(encoding="utf-8")
    # Angle 6 — RPC & socket service handlers
    assert "Angle 6" in text
    assert "gRPC" in text
    # 纯后端服务仓提示：前五角度全空手时第六角度是唯一入口来源
    assert "sole source" in text


def test_enumeration_completeness_has_rpc_socket_layer():
    text = (PROMPTS_DIR / "shared" / "_enumeration-completeness.txt").read_text(
        encoding="utf-8")
    assert "RPC" in text
    assert "socket" in text.lower()


def test_vuln_injection_coverage_includes_rpc_socket_vectors():
    text = (PROMPTS_DIR / "vuln-injection.txt").read_text(encoding="utf-8")
    # coverage_requirements 补 RPC 消息字段 + Socket 帧向量
    assert "RPC" in text
    assert "socket" in text.lower()
    # taint 默认：经 RPC/Socket 到达的输入同样 tainted（treated as attacker-controlled）
    assert "arrival" in text or "arriving" in text or "到达" in text


def test_vuln_injection_path_field_non_http_syntax():
    text = (PROMPTS_DIR / "vuln-injection.txt").read_text(encoding="utf-8")
    # 非 HTTP 入口的 path/accessible_routes 写法（RPC 方法 / socket handler）
    assert "RPC <service>/<Method>" in text
    assert "SOCK" in text
