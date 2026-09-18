# packages/core/tests/collectors/test_poc_collector.py
# spec 2026-08-27-poc-agent-direct-design §4.4：add_poc append collector + 校验层。
from supernova_core.collectors.base import CollectorBase
from supernova_core.collectors.poc import (
    POC_SECTION, make_poc_collector, validate_pocs, PocValidation,
)


def test_poc_collector_is_append_mode_collectorbase():
    c = make_poc_collector()
    assert isinstance(c, CollectorBase)  # 复用 CollectorBase，非独立类
    assert POC_SECTION.mode == "append"
    assert POC_SECTION.tool_name == "add_poc"
    assert POC_SECTION.section_key == "pocs"
    assert c.tool_names() == ["add_poc"]


def test_append_section_accumulates_into_pocs_list():
    c = make_poc_collector()
    c.append_section("add_poc", {"vulnerability_id": "XSS-VULN-01",
        "curl": "curl -i 'http://TARGET/x'", "self_check": "pass"})
    c.append_section("add_poc", {"vulnerability_id": "INJ-1",
        "steps": ["plant", "trigger"], "self_check": "pass"})
    data = c.get_all()
    assert list(data.keys()) == ["pocs"]
    assert len(data["pocs"]) == 2
    assert data["pocs"][0]["vulnerability_id"] == "XSS-VULN-01"


def test_get_all_empty_when_no_append():
    assert make_poc_collector().get_all() == {}  # append section 空则不含键


def test_add_poc_schema_is_flat_object_for_llm():
    # 顶层 type:object（非 oneOf）——两引擎 function calling 硬约束，同
    # add_exploit 的 GLM 空参死循环教训（collectors/exploit.py 模块注释）。
    s = POC_SECTION.json_schema
    assert s.get("type") == "object", "顶层须 type:object（function calling 要求）"
    assert "vulnerability_id" in s.get("properties", {})
    assert set(s.get("required", [])) == {"vulnerability_id"}


def test_validate_accepts_full_and_minimal_verdicts():
    full = {"vulnerability_id": "XSS-VULN-01",
            "curl": "curl -i 'http://TARGET/x'",
            "raw_http": "GET /x HTTP/1.1\nHost: TARGET",
            "steps": ["plant", "trigger"],
            "preconditions": "需登录（审核员）",
            "expected_response": "payload 反射",
            "self_check": "pass", "notes": "n"}
    minimal = {"vulnerability_id": "INJ-1", "curl": "curl -i 'http://TARGET/y'",
               "self_check": "pass"}
    res = validate_pocs([full, minimal], valid_ids={"XSS-VULN-01", "INJ-1"})
    assert isinstance(res, PocValidation)
    assert [v["vulnerability_id"] for v in res.accepted] == ["XSS-VULN-01", "INJ-1"]
    assert res.rejected == []


def test_validate_accepts_degraded_card_without_curl():
    # 宁缺毋错降级卡：无 curl/raw_http/steps，只有 notes 说明产不出 + self_check=fail
    res = validate_pocs([{"vulnerability_id": "XSS-VULN-02",
                          "self_check": "fail",
                          "notes": "plant 点在仓库外，无法产出正确 PoC"}],
                        valid_ids={"XSS-VULN-02"})
    assert [v["vulnerability_id"] for v in res.accepted] == ["XSS-VULN-02"]
    assert res.rejected == []


def test_validate_rejects_verdict_with_no_artifact():
    # 空 verdict 防护（GLM 传空 {} 死循环教训）：只有 id 无任何产出物 → 拒
    res = validate_pocs([{"vulnerability_id": "INJ-1", "self_check": "pass"}],
                        valid_ids={"INJ-1"})
    assert res.accepted == []
    assert len(res.rejected) == 1
    assert "产出物" in res.rejected[0][1]


def test_validate_rejects_missing_or_nonstring_id():
    res = validate_pocs([
        {"curl": "curl -i 'http://TARGET/x'", "self_check": "pass"},   # 无 id
        {"vulnerability_id": "", "curl": "c", "self_check": "pass"},   # 空 id
        {"vulnerability_id": 42, "curl": "c", "self_check": "pass"},   # 非 str id
    ], valid_ids={"INJ-1"})
    assert res.accepted == []
    assert len(res.rejected) == 3


def test_validate_rejects_phantom_id_and_dedupes():
    # L2 防幻觉 + L3 去重（首份生效）
    raw = [
        {"vulnerability_id": "INJ-1", "curl": "curl -i 'http://TARGET/a'", "self_check": "pass"},
        {"vulnerability_id": "PHANTOM", "curl": "curl -i 'http://TARGET/b'", "self_check": "pass"},
        {"vulnerability_id": "INJ-1", "curl": "curl -i 'http://TARGET/c'", "self_check": "fail"},
    ]
    res = validate_pocs(raw, valid_ids={"INJ-1"})
    assert len(res.accepted) == 1
    assert res.accepted[0]["curl"].endswith("/a'")
    assert len(res.rejected) == 2
    assert any("不在 queue" in r[1] for r in res.rejected)
    assert any("重复" in r[1] for r in res.rejected)


def test_validate_normalizes_steps_and_self_check():
    # L0：steps str → [str]、dict → 提取说明字段；self_check 大小写归一后过、
    # 乱填/缺省一律保守 fail——正确性自检没做就不能声称通过）
    v = {"vulnerability_id": "INJ-1",
         "steps": "plant then trigger",
         "self_check": "PASS"}
    res = validate_pocs([v], valid_ids={"INJ-1"})
    assert res.accepted[0]["steps"] == ["plant then trigger"]
    assert res.accepted[0]["self_check"] == "pass"   # 大小写归一后放行

    v_garbage = {"vulnerability_id": "INJ-9", "curl": "curl -i 'http://TARGET/g'",
                 "self_check": "true"}               # 乱填非契约值
    res_g = validate_pocs([v_garbage], valid_ids={"INJ-9"})
    assert res_g.accepted[0]["self_check"] == "fail"  # → 保守 fail

    v2 = {"vulnerability_id": "INJ-2",
          "steps": [{"description": "step one"}, {"step": "step two"}],
          "self_check": "pass"}
    res2 = validate_pocs([v2], valid_ids={"INJ-2"})
    assert res2.accepted[0]["steps"] == ["step one", "step two"]

    v3 = {"vulnerability_id": "INJ-3", "curl": "curl -i 'http://TARGET/z'"}  # 无 self_check
    res3 = validate_pocs([v3], valid_ids={"INJ-3"})
    assert res3.accepted[0]["self_check"] == "fail"  # 缺省保守 fail


def test_validate_rejects_nonstring_curl():
    # curl 非 str（dict 等）→ 拒（json.dumps 会产出非法 curl 文本进报告，宁拒不造）
    res = validate_pocs([{"vulnerability_id": "INJ-1", "curl": {"method": "GET"},
                          "self_check": "pass"}], valid_ids={"INJ-1"})
    assert res.accepted == []
    assert "curl" in res.rejected[0][1]


def test_validate_strips_unknown_fields():
    # 未知键剥离（防 agent 幻觉垃圾字段进报告卡）
    v = {"vulnerability_id": "INJ-1", "curl": "curl -i 'http://TARGET/x'",
         "self_check": "pass", "hallucinated_field": "x", "another": 1}
    res = validate_pocs([v], valid_ids={"INJ-1"})
    assert res.accepted[0] == {"vulnerability_id": "INJ-1",
                               "curl": "curl -i 'http://TARGET/x'",
                               "self_check": "pass"}


def test_validate_normalizes_mixed_steps_list():
    # list 混合形态：str/dict 共存各自归一；非 str 非 dict（int）丢弃
    v = {"vulnerability_id": "INJ-1",
         "steps": ["plain", {"text": "from text key"}, 42],
         "self_check": "pass"}
    res = validate_pocs([v], valid_ids={"INJ-1"})
    assert res.accepted[0]["steps"] == ["plain", "from text key"]


def test_validate_removes_list_markers_from_poc_step_text():
    """列表编号由报告渲染器生成，agent 文本不能再内嵌一份。"""
    res = validate_pocs([{
        "vulnerability_id": "INJ-1",
        "steps": ["1. 登录测试账号", "2) 提交 payload", "3、观察响应", "1.2.3 版本号保留"],
        "self_check": "pass",
    }], valid_ids={"INJ-1"})
    assert res.accepted[0]["steps"] == [
        "登录测试账号", "提交 payload", "观察响应", "1.2.3 版本号保留",
    ]


# ---------- extract_pocs_payload（2026-08-28 打捞兜底） ----------

from supernova_core.collectors.poc import extract_pocs_payload


def _poc_dict(vid: str = "AUTH-VULN-01") -> dict:
    return {"pocs": [{"vulnerability_id": vid, "curl": "curl -i 'http://T/x'",
                      "self_check": "pass"}]}


def test_extract_bare_json_text():
    import json
    assert extract_pocs_payload(json.dumps(_poc_dict())) == _poc_dict()


def test_extract_fenced_json_block_amid_prose():
    import json
    text = ("Here are the PoCs:\n```json\n" + json.dumps(_poc_dict("XSS-VULN-02"))
            + "\n```\nDone.")
    assert extract_pocs_payload(text) == _poc_dict("XSS-VULN-02")


def test_extract_brace_balanced_segment_without_fence():
    # 无围栏、前后都是 prose：花括号平衡段提取（含字符串内 {}/引号 状态机）
    import json
    payload = _poc_dict("INJ-VULN-03")
    payload["pocs"][0]["curl"] = "curl 'http://T/x?q={a}&w=\"b\"'"
    text = " preamble " + json.dumps(payload) + " trailing notes"
    assert extract_pocs_payload(text) == payload


def test_extract_returns_none_when_no_json():
    assert extract_pocs_payload("no json here at all") is None
    assert extract_pocs_payload("") is None
    assert extract_pocs_payload(None) is None


def test_extract_returns_none_when_parsed_but_not_pocs_shape():
    import json
    # 解析成功但非 {"pocs": list} 形态 → None（宁缺毋错，不猜结构）
    assert extract_pocs_payload(json.dumps({"items": []})) is None
    assert extract_pocs_payload(json.dumps([1, 2])) is None


def test_extract_unbalanced_brace_returns_none():
    # 花括号不平衡（agent 被掐断的残文）→ None，不抛
    assert extract_pocs_payload('{"pocs": [{"vulnerability_id": "X"') is None
