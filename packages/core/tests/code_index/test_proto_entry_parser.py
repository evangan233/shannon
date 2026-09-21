"""Tests for proto service/rpc parser → RPC route lookup table.

spec 2026-09-21-rpc-endpoint-correlation §3.1：解析 .proto 的 service/rpc
块产 (service, method) → ProtoRouteInfo 查找表（单元 1），及 grpc_service
入口的同名 join（单元 2，join_proto_routes）。
"""

import textwrap

from supernova_core.code_index.models import CodeIndex, EntryPoint, FuncBlock
from supernova_core.code_index.proto_entry_parser import (
    ProtoRouteInfo,
    join_proto_routes,
    parse_proto_services,
)


def _write_proto(repo, rel, content):
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(content))
    return p


def test_parse_service_rpc_basic(tmp_path):
    """service/rpc 块 → (service, method) → route=/Service/Method + package/proto_file。"""
    _write_proto(tmp_path, "setup_order.proto", """\
        syntax = "proto2";
        package customer.web;

        service SetupOrder {
            rpc SetupOrderCreate(SetupOrderCreateReq) returns (SetupOrderCreateRsp) {}
            rpc SetupOrderUpdate(SetupOrderUpdateReq) returns (SetupOrderUpdateRsp) {}
        }
    """)
    table = parse_proto_services(str(tmp_path))
    assert ("SetupOrder", "SetupOrderCreate") in table
    info = table[("SetupOrder", "SetupOrderCreate")]
    assert info.route == "/SetupOrder/SetupOrderCreate"
    assert info.proto_file == "setup_order.proto"
    assert info.package == "customer.web"
    assert ("SetupOrder", "SetupOrderUpdate") in table


def test_srpc_options_recorded(tmp_path):
    """srpc 命令字 option 附带记录进 options（不参与 join 键）。"""
    _write_proto(tmp_path, "svc.proto", """\
        service Foo {
            option (srpc.service_option_id) = 0x5002;
            rpc Bar(X) returns (Y) {
                option (srpc.method_option_id) = 0x1;
            }
        }
    """)
    table = parse_proto_services(str(tmp_path))
    info = table[("Foo", "Bar")]
    assert info.options.get("service_option_id") == "0x5002"
    assert info.options.get("method_option_id") == "0x1"


def test_commented_out_service_ignored(tmp_path):
    """注释里的伪 service 块不误配（// 与 /* */ 两种）。"""
    _write_proto(tmp_path, "commented.proto", """\
        // service Ghost {
        //     rpc Phantom(X) returns (Y) {}
        // }
        /* service BlockGhost {
           rpc BlockPhantom(X) returns (Y) {}
           } */
        service Real {
            rpc RealMethod(X) returns (Y) {}
        }
    """)
    table = parse_proto_services(str(tmp_path))
    assert ("Ghost", "Phantom") not in table
    assert ("BlockGhost", "BlockPhantom") not in table
    assert ("Real", "RealMethod") in table


def test_unbalanced_braces_file_skipped(tmp_path):
    """花括号失衡 → 该文件跳过（不崩、不误产），其余文件照常。"""
    _write_proto(tmp_path, "bad.proto", """\
        service Broken {
            rpc NoClose(X) returns (Y) {}
        """)
    _write_proto(tmp_path, "good.proto", """\
        service Ok {
            rpc Fine(X) returns (Y) {}
        }
    """)
    table = parse_proto_services(str(tmp_path))
    assert ("Broken", "NoClose") not in table
    assert ("Ok", "Fine") in table


def test_cmd_style_proto_yields_empty(tmp_path):
    """CMD 纯 message proto（无 service 块）→ 不产条目。"""
    _write_proto(tmp_path, "cmd.proto", """\
        package FTCmd2008;
        message Request { required fixed64 be_uid64 = 1; }
        message Response { required int32 result = 1; }
    """)
    assert parse_proto_services(str(tmp_path)) == {}


def test_path_exclusions_respected(tmp_path):
    """排除目录（node_modules 等）下的 proto 不扫。"""
    _write_proto(tmp_path, "node_modules/dep/x.proto", """\
        service Excluded { rpc M(X) returns (Y) {} }
    """)
    assert parse_proto_services(str(tmp_path)) == {}


# ── §3.1 单元 2：同名 join（join_proto_routes）──

def _grpc_ep(method_name, file="internal/app/user.bus.go", line=31):
    return EntryPoint(
        func_block_id=f"{file}:{method_name}:{line}",
        entry_type="grpc_service",
        confidence=0.70,
        evidence="Signature includes context.Context with request-message pointer param",
        needs_llm_review=True,
    )


def _block(fb_id, class_name):
    file, func, line = fb_id.rsplit(":", 2)
    return FuncBlock(
        id=fb_id, file_path=file, function_name=func, start_line=int(line),
        end_line=int(line) + 5, source_code="", parameters=[],
        language="go", class_name=class_name,
    )


def _index(eps, blocks=()):
    return CodeIndex(
        repository="r", language="go", total_blocks=len(blocks),
        total_entry_points=len(eps), total_chains=0,
        blocks=list(blocks), edges=[], entry_points=list(eps), chains=[],
    )


def _info(service, method):
    return ProtoRouteInfo(route=f"/{service}/{method}", proto_file="x.proto")


class TestJoinProtoRoutes:
    def test_unique_method_name_joins(self):
        """方法名唯一命中 → 填 route + evidence 注 proto 出处 + confidence 0.85。"""
        idx = _index([_grpc_ep("SetupOrderCreate")])
        table = {("SetupOrder", "SetupOrderCreate"):
                 _info("SetupOrder", "SetupOrderCreate")}
        out = join_proto_routes(idx, table)
        ep = out.entry_points[0]
        assert ep.route == "/SetupOrder/SetupOrderCreate"
        assert ep.confidence == 0.85
        assert "joined from proto" in ep.evidence

    def test_ambiguous_method_name_not_joined(self):
        """多 service 同名 method → 歧义不 join（宁缺勿错）。"""
        idx = _index([_grpc_ep("Get")])
        table = {("A", "Get"): _info("A", "Get"), ("B", "Get"): _info("B", "Get")}
        out = join_proto_routes(idx, table)
        assert out.entry_points[0].route is None

    def test_class_name_double_key_wins_over_single_ambiguity(self):
        """单键歧义但 (class_name, method) 双键唯一 → 双键 join。"""
        idx = _index([_grpc_ep("Create", file="f.go", line=1)],
                     [_block("f.go:Create:1", "SetupOrder")])
        table = {("SetupOrder", "Create"): _info("SetupOrder", "Create"),
                 ("Other", "Create"): _info("Other", "Create")}
        out = join_proto_routes(idx, table)
        assert out.entry_points[0].route == "/SetupOrder/Create"

    def test_class_name_mismatch_falls_back_to_unique_single(self):
        """class_name 与 service 不符 → 退化单键，唯一仍 join（spec §3.1）。"""
        idx = _index([_grpc_ep("Create", file="f.go", line=1)],
                     [_block("f.go:Create:1", "NoMatch")])
        table = {("SetupOrder", "Create"): _info("SetupOrder", "Create")}
        out = join_proto_routes(idx, table)
        assert out.entry_points[0].route == "/SetupOrder/Create"

    def test_http_entry_untouched(self):
        """http_route 入口不受 join 影响。"""
        idx = _index([EntryPoint(func_block_id="a.py:h:1", entry_type="http_route",
                                 route="/x", http_method="GET", confidence=0.95,
                                 evidence="flask", needs_llm_review=False)])
        out = join_proto_routes(idx, {("X", "h"): _info("X", "h")})
        assert out.entry_points[0].route == "/x"

    def test_already_routed_grpc_untouched(self):
        """已有 route 的 grpc_service 不重复处理。"""
        ep = _grpc_ep("SetupOrderCreate").model_copy(
            update={"route": "/Already/Routed"})
        out = join_proto_routes(
            _index([ep]),
            {("SetupOrder", "SetupOrderCreate"):
             _info("SetupOrder", "SetupOrderCreate")})
        assert out.entry_points[0].route == "/Already/Routed"


class TestMergeDeliverableProtoJoin:
    def test_merge_joins_proto_routes_and_persists(self, tmp_path):
        """merge_entry_points_from_deliverable：repo 有 proto → grpc entry
        带 route，且融合+join 结果落盘 code_index.json。"""
        import json

        from supernova_core.code_index import run_entry_point_fusion

        d = tmp_path / "deliverables"
        (d / "intermediate").mkdir(parents=True)
        idx = _index([_grpc_ep("SetupOrderCreate")])
        (d / "intermediate" / "code_index.json").write_text(idx.model_dump_json())
        repo = tmp_path / "repo"
        (repo / "proto").mkdir(parents=True)
        (repo / "proto" / "x.proto").write_text(
            'service SetupOrder { rpc SetupOrderCreate(A) returns (B) {} }\n')

        out = run_entry_point_fusion(str(d), str(repo))
        ep = out.entry_points[0]
        assert ep.route == "/SetupOrder/SetupOrderCreate"
        assert ep.confidence == 0.85

        # 写回版本同样带 route（下游 save_adjudication 读落盘产物）
        persisted = json.loads(
            (d / "intermediate" / "code_index.json").read_text())
        assert persisted["entry_points"][0]["route"] == "/SetupOrder/SetupOrderCreate"
