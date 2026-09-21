"""vuln prompt endpoints schema 的 RPC 接口指引锁定（spec 2026-09-21 §3.4）。

对 RPC/gRPC 服务（无 HTTP 路由），agent 产出 /Service/Method（可带 proto
包名）形态接口标识。这是方法论指引——源由 agent 自行 grep proto/实现派生，
非确定性产物注入，不违反双轨铁律（test_static_dataflow_hints_decoupling
锁定项不涉及）。

覆盖 3 个含 endpoints 字段的 finding schema：injection / xss / ssrf
（authz 无 endpoints 字段，走 IDOR 语义）。
"""
from supernova_core.collectors.vuln import (
    _INJECTION_FINDING_PROPS,
    _SSRF_FINDING_PROPS,
    _XSS_FINDING_PROPS,
)

_SCHEMA_SNIPPET = "对 RPC/gRPC 服务"


def _endpoints_desc(props: dict) -> str:
    return props["endpoints"]["description"]


def test_injection_endpoints_has_rpc_guidance():
    desc = _endpoints_desc(_INJECTION_FINDING_PROPS)
    assert _SCHEMA_SNIPPET in desc
    assert "/Service/Method" in desc
    assert "proto" in desc


def test_xss_endpoints_has_rpc_guidance():
    desc = _endpoints_desc(_XSS_FINDING_PROPS)
    assert _SCHEMA_SNIPPET in desc
    assert "/Service/Method" in desc
    assert "proto" in desc


def test_ssrf_endpoints_has_rpc_guidance():
    desc = _endpoints_desc(_SSRF_FINDING_PROPS)
    assert _SCHEMA_SNIPPET in desc
    assert "/Service/Method" in desc
    assert "proto" in desc


def test_rpc_guidance_is_methodology_not_deterministic_injection():
    """指引只能要求 agent 自行 grep 派生，不得引用任何确定性产物文件
    （entry_points.json / 白盒 intermediate 等）——双轨铁律防线。"""
    descs = [
        _endpoints_desc(p) for p in
        (_INJECTION_FINDING_PROPS, _XSS_FINDING_PROPS, _SSRF_FINDING_PROPS)
    ]
    for d in descs:
        assert "entry_points" not in d
        assert "intermediate" not in d
        assert "@include" not in d
        assert "自行 grep" in d or "grep" in d
