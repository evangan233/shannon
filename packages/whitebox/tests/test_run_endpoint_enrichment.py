# packages/whitebox/tests/test_run_endpoint_enrichment.py
"""T3（spec 2026-08-26-report-generation-agent §5.2）：全卡接口表富化。

覆盖：agent 产物写回 report_endpoints（含行号链）/ 幻觉 ID 丢弃 / 畸形
endpoint 条目丢弃 / agent 失败 non-fatal（queue 不变）/ 素材包含
entry_points 路由表 / 开关门控（SUPERNOVA_ENDPOINT_ENRICH_ENABLED）；
§4.1（2026-08-26-vuln-card-seven-sections）problem_points 富化（有效回填 /
畸形条目丢弃 / 幻觉 ID 跳过 / 无输出不动原值 / enriched 去重计数）。
"""
import json
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import patch

from supernova_whitebox.pipeline import activities


class _FakeInput:
    def __init__(self, tmp_path):
        self.agent_name = None
        self.web_url = None
        self.repo_path = str(tmp_path)
        self.deliverables_subdir = None
        self.workspace_name = None
        self.workspace_path = None
        self.config_path = None
        self.api_key = None
        self.pipeline_testing_mode = False
        self.prompt_override = None
        self.provider_config = None


class _RecordingSession:
    @asynccontextmanager
    async def track_step(self, phase, name, intent=None):
        yield


def _wb(tmp_path):
    d = tmp_path / "deliverables" / "whitebox"
    (d / "intermediate").mkdir(parents=True, exist_ok=True)
    return d


def _write_queue(d, vulns, name="xss_exploitation_queue.json"):
    d.joinpath("intermediate", name).write_text(
        json.dumps({"vulnerabilities": vulns}))


def _write_entry_points(d, entries):
    d.joinpath("intermediate", "entry_points.json").write_text(json.dumps({
        "repository": "/repo", "language": "javascript",
        "adjudicated_entry_points": entries,
    }))


_EP = {"route": "/memos", "http_method": "POST",
       "func_block_id": "app/routes/index.js:index:66",
       "evidence": "Express route: app.post('/memos')",
       "verdict": "confirmed", "entry_type": "http_route", "source": "code_index"}

_XSS_VULN = {
    "ID": "XSS-VULN-01", "vulnerability_type": "Stored",
    "externally_exploitable": True, "confidence": "high",
    "merge_source": "llm-only", "title": "存储型 XSS：POST /memos",
    "severity": "high",
    "endpoints": ["POST /memos (write, isLoggedIn)", "GET /memos (trigger)"],
}


def _agent_result(payload):
    return SimpleNamespace(structured_output=payload, text=None)


async def test_endpoint_enrichment_writes_report_endpoints(tmp_path, monkeypatch):
    """agent 产物（接口一体表含行号链）按 ID 写回 report_endpoints。"""
    d = _wb(tmp_path)
    _write_queue(d, [_XSS_VULN])
    _write_entry_points(d, [_EP])
    monkeypatch.setattr(activities, "_get_paths",
                        lambda inp: (tmp_path, d, tmp_path))
    payload = {"vulnerabilities": [{
        "id": "XSS-VULN-01",
        "endpoints": [{
            "method": "POST", "path": "/memos", "role": "write",
            "auth": "isLoggedIn", "params": ["memo"],
            "route_registered_at": "app/routes/index.js:66",
            "source_location": "app/routes/memos.js:13",
            "sink_location": "app/views/memos.html:31",
        }],
    }]}
    with patch.object(activities, "run_gitnexus_verdict_agent",
                      return_value=_agent_result(payload)) as mock_agent, \
         patch("supernova_core.config.concurrency.ws_getenv",
               lambda k, d=None: {"SUPERNOVA_ENDPOINT_ENRICH_ENABLED": "1"}.get(k, d)):
        result = await activities.run_endpoint_enrichment(_FakeInput(tmp_path))

    assert result["total_enriched"] == 1
    queue = json.loads(d.joinpath("intermediate", "xss_exploitation_queue.json")
                       .read_text(encoding="utf-8"))
    entry = queue["vulnerabilities"][0]
    assert entry["report_endpoints"][0]["route_registered_at"] == \
        "app/routes/index.js:66"
    assert entry["report_endpoints"][0]["sink_location"] == \
        "app/views/memos.html:31"
    # prompt 素材含路由表行
    prompt = mock_agent.call_args.kwargs["prompt"]
    assert "POST /memos" in prompt
    assert "app/routes/index.js" in prompt
    # 记账唯一名（防 metrics.agents 同名覆盖，逐 class 唯一）
    assert mock_agent.call_args.kwargs["agent_name"] == "endpoint-enrich-xss"


async def test_endpoint_enrichment_drops_hallucinated_and_malformed(tmp_path, monkeypatch):
    """幻觉 ID 整条丢弃；path 不以 / 开头的条目丢弃，合法条目照常写。"""
    d = _wb(tmp_path)
    _write_queue(d, [_XSS_VULN])
    _write_entry_points(d, [_EP])
    monkeypatch.setattr(activities, "_get_paths",
                        lambda inp: (tmp_path, d, tmp_path))
    payload = {"vulnerabilities": [
        {"id": "XSS-GHOST-99", "endpoints": [{"method": "GET", "path": "/x"}]},
        {"id": "XSS-VULN-01", "endpoints": [
            {"method": "GET", "path": "not-a-path"},       # 畸形 path
            {"method": "GET", "path": "/memos"},           # 合法
        ]},
    ]}
    with patch.object(activities, "run_gitnexus_verdict_agent",
                      return_value=_agent_result(payload)), \
         patch("supernova_core.config.concurrency.ws_getenv",
               lambda k, d=None: {"SUPERNOVA_ENDPOINT_ENRICH_ENABLED": "1"}.get(k, d)):
        result = await activities.run_endpoint_enrichment(_FakeInput(tmp_path))

    queue = json.loads(d.joinpath("intermediate", "xss_exploitation_queue.json")
                       .read_text(encoding="utf-8"))
    eps = queue["vulnerabilities"][0]["report_endpoints"]
    assert [e["path"] for e in eps] == ["/memos"]
    assert result["total_enriched"] == 1


async def test_endpoint_enrichment_agent_failure_nonfatal(tmp_path, monkeypatch):
    """agent 失败 → queue 原样保留（确定性字段兜底），返回 failed 状态。"""
    d = _wb(tmp_path)
    _write_queue(d, [_XSS_VULN])
    _write_entry_points(d, [_EP])
    monkeypatch.setattr(activities, "_get_paths",
                        lambda inp: (tmp_path, d, tmp_path))

    async def _boom(**kw):
        raise RuntimeError("llm unavailable")
    with patch.object(activities, "run_gitnexus_verdict_agent", side_effect=_boom), \
         patch("supernova_core.config.concurrency.ws_getenv",
               lambda k, d=None: {"SUPERNOVA_ENDPOINT_ENRICH_ENABLED": "1"}.get(k, d)):
        result = await activities.run_endpoint_enrichment(_FakeInput(tmp_path))

    queue = json.loads(d.joinpath("intermediate", "xss_exploitation_queue.json")
                       .read_text(encoding="utf-8"))
    assert "report_endpoints" not in queue["vulnerabilities"][0]
    assert result["enriched_classes"]["xss"]["failed"]


# ---------- §4.1（spec 2026-08-26-vuln-card-seven-sections）problem_points 富化 ----------

_PP = [{"location": "app/routes/memos.js:13", "description": "未净化用户输入直拼模板",
        "snippet": "const memo = req.body.memo;\nres.render('memos', {memo});"}]


async def test_endpoint_enrichment_writes_report_problem_points(tmp_path, monkeypatch):
    """§4.1：problem_points 有效条目按 ID 写回；同卡 endpoints+problem_points
    enriched 只算 1（去重）；prompt 契约含 problem_points 字段。"""
    d = _wb(tmp_path)
    _write_queue(d, [_XSS_VULN])
    _write_entry_points(d, [_EP])
    monkeypatch.setattr(activities, "_get_paths",
                        lambda inp: (tmp_path, d, tmp_path))
    payload = {"vulnerabilities": [{
        "id": "XSS-VULN-01",
        "endpoints": [{"method": "POST", "path": "/memos"}],
        "problem_points": _PP,
    }]}
    with patch.object(activities, "run_gitnexus_verdict_agent",
                      return_value=_agent_result(payload)) as mock_agent, \
         patch("supernova_core.config.concurrency.ws_getenv",
               lambda k, d=None: {"SUPERNOVA_ENDPOINT_ENRICH_ENABLED": "1"}.get(k, d)):
        result = await activities.run_endpoint_enrichment(_FakeInput(tmp_path))

    # 同卡写回 endpoints + problem_points 两字段，enriched 去重只算 1
    assert result["total_enriched"] == 1
    queue = json.loads(d.joinpath("intermediate", "xss_exploitation_queue.json")
                       .read_text(encoding="utf-8"))
    entry = queue["vulnerabilities"][0]
    assert entry["report_problem_points"] == _PP
    # prompt 产出契约已扩 problem_points（防杜撰措辞与行号约束同款）
    prompt = mock_agent.call_args.kwargs["prompt"]
    assert "problem_points" in prompt


async def test_endpoint_enrichment_problem_points_only_counts(tmp_path, monkeypatch):
    """§4.1：只写回 problem_points（无 endpoints 输出）该卡也算 enriched=1。"""
    d = _wb(tmp_path)
    _write_queue(d, [_XSS_VULN])
    _write_entry_points(d, [_EP])
    monkeypatch.setattr(activities, "_get_paths",
                        lambda inp: (tmp_path, d, tmp_path))
    payload = {"vulnerabilities": [{
        "id": "XSS-VULN-01", "problem_points": _PP,
    }]}
    with patch.object(activities, "run_gitnexus_verdict_agent",
                      return_value=_agent_result(payload)), \
         patch("supernova_core.config.concurrency.ws_getenv",
               lambda k, d=None: {"SUPERNOVA_ENDPOINT_ENRICH_ENABLED": "1"}.get(k, d)):
        result = await activities.run_endpoint_enrichment(_FakeInput(tmp_path))

    assert result["total_enriched"] == 1
    queue = json.loads(d.joinpath("intermediate", "xss_exploitation_queue.json")
                       .read_text(encoding="utf-8"))
    entry = queue["vulnerabilities"][0]
    assert entry["report_problem_points"] == _PP
    # 两字段独立判断：未输出 endpoints 则 report_endpoints 保持 None
    # （写回走 model_dump，未设置字段序列化为 None）
    assert entry["report_endpoints"] is None


async def test_endpoint_enrichment_drops_invalid_problem_points(tmp_path, monkeypatch, caplog):
    """§4.1：非 dict / location 空 / snippet 空的条目丢弃 + warning；合法条目照常写。"""
    d = _wb(tmp_path)
    _write_queue(d, [_XSS_VULN])
    _write_entry_points(d, [_EP])
    monkeypatch.setattr(activities, "_get_paths",
                        lambda inp: (tmp_path, d, tmp_path))
    payload = {"vulnerabilities": [{
        "id": "XSS-VULN-01",
        "problem_points": [
            "not-a-dict",                                        # 非 dict
            {"location": "   ", "description": "d", "snippet": "s"},   # location 空白
            {"location": "app/a.js:1", "description": "d", "snippet": ""},  # snippet 空
            _PP[0],                                              # 合法
        ],
    }]}
    with patch.object(activities, "run_gitnexus_verdict_agent",
                      return_value=_agent_result(payload)), \
         patch("supernova_core.config.concurrency.ws_getenv",
               lambda k, d=None: {"SUPERNOVA_ENDPOINT_ENRICH_ENABLED": "1"}.get(k, d)):
        with caplog.at_level("WARNING"):
            result = await activities.run_endpoint_enrichment(_FakeInput(tmp_path))

    queue = json.loads(d.joinpath("intermediate", "xss_exploitation_queue.json")
                       .read_text(encoding="utf-8"))
    assert queue["vulnerabilities"][0]["report_problem_points"] == _PP
    assert result["total_enriched"] == 1
    # 丢弃有 warning 可观测（非静默）
    assert sum(1 for r in caplog.records
               if "problem_points" in r.getMessage()
               and r.levelname == "WARNING") >= 3


async def test_endpoint_enrichment_problem_points_unknown_id_skipped(tmp_path, monkeypatch):
    """§4.1：幻觉 ID 的 problem_points 整条跳过，queue 不动该字段。"""
    d = _wb(tmp_path)
    _write_queue(d, [_XSS_VULN])
    _write_entry_points(d, [_EP])
    monkeypatch.setattr(activities, "_get_paths",
                        lambda inp: (tmp_path, d, tmp_path))
    payload = {"vulnerabilities": [
        {"id": "XSS-GHOST-99", "problem_points": _PP},
    ]}
    with patch.object(activities, "run_gitnexus_verdict_agent",
                      return_value=_agent_result(payload)), \
         patch("supernova_core.config.concurrency.ws_getenv",
               lambda k, d=None: {"SUPERNOVA_ENDPOINT_ENRICH_ENABLED": "1"}.get(k, d)):
        result = await activities.run_endpoint_enrichment(_FakeInput(tmp_path))

    assert result["total_enriched"] == 0
    queue = json.loads(d.joinpath("intermediate", "xss_exploitation_queue.json")
                       .read_text(encoding="utf-8"))
    # 幻觉 ID 跳过：该卡 report_problem_points 保持 None（model_dump 序列化）
    assert queue["vulnerabilities"][0]["report_problem_points"] is None


async def test_endpoint_enrichment_keeps_existing_problem_points(tmp_path, monkeypatch):
    """§4.1：agent 无 problem_points 输出 → 原 report_problem_points 不动。"""
    d = _wb(tmp_path)
    preset = [_PP[0]]
    _write_queue(d, [{**_XSS_VULN, "report_problem_points": preset}])
    _write_entry_points(d, [_EP])
    monkeypatch.setattr(activities, "_get_paths",
                        lambda inp: (tmp_path, d, tmp_path))
    payload = {"vulnerabilities": [{
        "id": "XSS-VULN-01",
        "endpoints": [{"method": "POST", "path": "/memos"}],
    }]}
    with patch.object(activities, "run_gitnexus_verdict_agent",
                      return_value=_agent_result(payload)), \
         patch("supernova_core.config.concurrency.ws_getenv",
               lambda k, d=None: {"SUPERNOVA_ENDPOINT_ENRICH_ENABLED": "1"}.get(k, d)):
        await activities.run_endpoint_enrichment(_FakeInput(tmp_path))

    queue = json.loads(d.joinpath("intermediate", "xss_exploitation_queue.json")
                       .read_text(encoding="utf-8"))
    entry = queue["vulnerabilities"][0]
    assert entry["report_problem_points"] == preset   # 原值保留
    assert entry["report_endpoints"][0]["path"] == "/memos"  # endpoints 照常写


async def test_endpoint_enrichment_default_max_turns_100(tmp_path, monkeypatch):
    """SUPERNOVA_ENDPOINT_ENRICH_MAX_TURNS 未设时默认 100（2026-08-28 现场：
    默认 30 对卡多的类不够——auth 11 卡逐卡钉行号链 + task 委派往返，30 turns
    耗尽 → ExecutionLimitError → 整类 0/11 全灭）。"""
    d = _wb(tmp_path)
    _write_queue(d, [_XSS_VULN])
    _write_entry_points(d, [_EP])
    monkeypatch.setattr(activities, "_get_paths",
                        lambda inp: (tmp_path, d, tmp_path))
    monkeypatch.delenv("SUPERNOVA_ENDPOINT_ENRICH_MAX_TURNS", raising=False)
    payload = {"vulnerabilities": [
        {"id": "XSS-VULN-01",
         "endpoints": [{"method": "POST", "path": "/memos"}]},
    ]}
    with patch.object(activities, "run_gitnexus_verdict_agent",
                      return_value=_agent_result(payload)) as mock_agent, \
         patch("supernova_core.config.concurrency.ws_getenv",
               lambda k, d=None: {"SUPERNOVA_ENDPOINT_ENRICH_ENABLED": "1"}.get(k, d)):
        await activities.run_endpoint_enrichment(_FakeInput(tmp_path))

    assert mock_agent.call_args.kwargs["max_turns"] == 100


async def test_endpoint_enrichment_passes_schema_for_delivery_rules(tmp_path, monkeypatch):
    """write_file 通道错配的治本收口（2026-08-28）：交付纪律由
    run_gitnexus_verdict_agent 按 structured_output_schema 有无统一注入
    （见 test_verdict_agent_delivery_rules.py），prompt 文件不再自带。
    本测试锁定注入前提：endpoint enrich 必须传 schema。"""
    d = _wb(tmp_path)
    _write_queue(d, [_XSS_VULN])
    _write_entry_points(d, [_EP])
    monkeypatch.setattr(activities, "_get_paths",
                        lambda inp: (tmp_path, d, tmp_path))
    payload = {"vulnerabilities": [
        {"id": "XSS-VULN-01",
         "endpoints": [{"method": "POST", "path": "/memos"}]},
    ]}
    with patch.object(activities, "run_gitnexus_verdict_agent",
                      return_value=_agent_result(payload)) as mock_agent, \
         patch("supernova_core.config.concurrency.ws_getenv",
               lambda k, d=None: {"SUPERNOVA_ENDPOINT_ENRICH_ENABLED": "1"}.get(k, d)):
        await activities.run_endpoint_enrichment(_FakeInput(tmp_path))

    assert mock_agent.call_args.kwargs["structured_output_schema"] is not None


async def test_endpoint_enrichment_disabled_by_env(tmp_path, monkeypatch):
    """SUPERNOVA_ENDPOINT_ENRICH_ENABLED=0 → 跳过（agent 不调用）。"""
    d = _wb(tmp_path)
    _write_queue(d, [_XSS_VULN])
    monkeypatch.setattr(activities, "_get_paths",
                        lambda inp: (tmp_path, d, tmp_path))
    with patch.object(activities, "run_gitnexus_verdict_agent") as mock_agent, \
         patch("supernova_core.config.concurrency.ws_getenv",
               lambda k, d=None: {"SUPERNOVA_ENDPOINT_ENRICH_ENABLED": "0"}.get(k, d)):
        result = await activities.run_endpoint_enrichment(_FakeInput(tmp_path))
    assert result["skipped"] == "disabled"
    mock_agent.assert_not_called()


# ── 复核翻案（2026-09-16 残面修复）─────────────────────────────────────────────
#
# endpoint-enrichment agent 深读代码富化接口表时，可能确认卡实际有防护/无危害
# （risk_margin-20260910-041235 实证：复核结论只能写进标题文本，卡仍以 high
# 进报告）。翻案出口：verdict="safe"（单向闸门）→ 卡出 SSOT、dismissed 留档。


async def test_endpoint_enrichment_flips_safe_card_out_of_queue(tmp_path, monkeypatch):
    """agent 输出 verdict=safe + verdict_reason → 卡出 SSOT、dismissed 留档、
    计数进 safe_flipped；正常富化卡照旧写回。"""
    d = _wb(tmp_path)
    _write_queue(d, [
        _XSS_VULN,
        {"ID": "XSS-GN-01", "vulnerability_type": "Reflected",
         "externally_exploitable": True, "confidence": "needs_review",
         "merge_source": "gitnexus-only", "title": "可疑卡", "severity": "high",
         "source_track": "gitnexus"},
    ])
    _write_entry_points(d, [_EP])
    monkeypatch.setattr(activities, "_get_paths",
                        lambda inp: (tmp_path, d, tmp_path))
    payload = {"vulnerabilities": [
        {"id": "XSS-VULN-01",
         "endpoints": [{"method": "POST", "path": "/memos"}]},
        {"id": "XSS-GN-01", "verdict": "safe",
         "verdict_reason": "输出经 DOMPurify 净化 (views/memos.html:31)"},
    ]}
    with patch.object(activities, "run_gitnexus_verdict_agent",
                      return_value=_agent_result(payload)), \
         patch("supernova_core.config.concurrency.ws_getenv",
               lambda k, d=None: {"SUPERNOVA_ENDPOINT_ENRICH_ENABLED": "1"}.get(k, d)):
        result = await activities.run_endpoint_enrichment(_FakeInput(tmp_path))

    queue = json.loads(d.joinpath("intermediate", "xss_exploitation_queue.json")
                       .read_text(encoding="utf-8"))
    assert [v["ID"] for v in queue["vulnerabilities"]] == ["XSS-VULN-01"]
    assert queue["vulnerabilities"][0]["report_endpoints"]  # 正常富化不受影响

    dismissed = json.loads(d.joinpath("intermediate", "dismissed_findings.json")
                           .read_text(encoding="utf-8"))
    entry = [e for e in dismissed["dismissed"] if e["ID"] == "XSS-GN-01"]
    assert len(entry) == 1
    assert entry[0]["vuln_class"] == "xss"
    assert entry[0]["dismissed_at_stage"] == "endpoint-enrichment"
    assert "DOMPurify" in entry[0]["dismiss_reason"]

    assert result["enriched_classes"]["xss"]["safe_flipped"] == 1


async def test_endpoint_enrichment_verdict_is_one_way_gate(tmp_path, monkeypatch):
    """单向闸门：agent 输出 verdict="vulnerable" / 垃圾值 → 忽略，卡保持原状
    留在 SSOT（富化 agent 无权把卡翻成漏洞，也无权用垃圾值扰动判定）。"""
    d = _wb(tmp_path)
    _write_queue(d, [_XSS_VULN])
    _write_entry_points(d, [_EP])
    monkeypatch.setattr(activities, "_get_paths",
                        lambda inp: (tmp_path, d, tmp_path))
    payload = {"vulnerabilities": [
        {"id": "XSS-VULN-01", "verdict": "VULNERABLE",
         "endpoints": [{"method": "POST", "path": "/memos"}]},
    ]}
    with patch.object(activities, "run_gitnexus_verdict_agent",
                      return_value=_agent_result(payload)), \
         patch("supernova_core.config.concurrency.ws_getenv",
               lambda k, d=None: {"SUPERNOVA_ENDPOINT_ENRICH_ENABLED": "1"}.get(k, d)):
        result = await activities.run_endpoint_enrichment(_FakeInput(tmp_path))

    queue = json.loads(d.joinpath("intermediate", "xss_exploitation_queue.json")
                       .read_text(encoding="utf-8"))
    assert len(queue["vulnerabilities"]) == 1
    assert queue["vulnerabilities"][0]["verdict"] is None  # 未被写
    assert result["enriched_classes"]["xss"]["safe_flipped"] == 0
    assert not d.joinpath("intermediate", "dismissed_findings.json").exists()
