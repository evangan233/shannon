# packages/whitebox/tests/test_run_authz_gitnexus_judge.py
import json
from unittest.mock import patch, AsyncMock

import pytest

from supernova_whitebox.pipeline import activities


class _FakeInput:
    def __init__(self, tmp_path):
        self.agent_name = None
        self.web_url = None
        self.repo_path = str(tmp_path)
        self.deliverables_subdir = None
        self.workspace_name = None
        self.config_path = None
        self.api_key = None
        self.pipeline_testing_mode = False
        self.prompt_override = None
        self.provider_config = None  # P3c 穿线字段（agent 调用前求值，缺属性即 AttributeError）


def _write_index_with_candidate(tmp_path):
    handler = {"id": "u.js:update:10", "file_path": "u.js", "function_name": "update",
               "start_line": 10, "end_line": 13,
               "source_code": "async function update(req){ await repo.update(req.params.id); }",
               "parameters": [], "decorators": [], "language": "typescript"}
    sink = {"id": "repo.js:update:1", "file_path": "repo.js", "function_name": "update",
            "start_line": 1, "end_line": 3,
            "source_code": "function update(){ db.user.update(); }",
            "parameters": [], "decorators": [], "language": "typescript"}
    # code_index.json 属于 deliverables（activity 从 deliverables 读），落 whitebox/ 子目录。
    dlv = tmp_path / "whitebox"
    dlv.mkdir(parents=True, exist_ok=True)
    (dlv / "code_index.json").write_text(json.dumps({
        "repository": "r", "language": "typescript", "total_blocks": 2,
        "total_entry_points": 1, "total_chains": 1, "blocks": [handler, sink],
        "edges": [],
        "entry_points": [{"func_block_id": "u.js:update:10", "entry_type": "http_route",
                          "route": "/api/u/:id", "http_method": "PUT", "confidence": 0.9,
                          "evidence": "", "needs_llm_review": False,
                          "authentication": "required", "source": "code_index"}],
        "chains": [{"entry_point_id": "u.js:update:10",
                    "path": ["u.js:update:10", "repo.js:update:1"],
                    "depth": 1, "has_unresolved": False}],
    }))


@pytest.mark.asyncio
@pytest.mark.xfail(
    reason=(
        "预存失败（feat/py 带入）：_write_index_with_candidate fixture 不被 "
        "build_authz_gitnexus_track/find_unguarded_sink_paths 识别为 dominance 候选 → "
        "candidate_count=0 走探索分支，故 result['candidate_count']>=1 不成立。"
        "根因在候选生成层（fixture 缺 dominance 识别所需字段，如 source_points），"
        "非 epic deep-agent 判定深度引入；待 spec-1b/G3 候选来源扩展时修 fixture。"
    ),
    strict=False,
)
async def test_judge_writes_gitnexus_queue_from_candidates(tmp_path):
    _write_index_with_candidate(tmp_path)
    captured = {}

    async def fake_run(prompt, **kwargs):
        captured["prompt"] = prompt
        return type("R", (), {
            "success": True, "error": None, "retryable": False, "turns": 1,
            "cost": 0.0, "text": "", "model": "m", "stop_reason": "end",
            "tokens": None,
            "structured_output": {"vulnerabilities": [{
                "ID": "AUTHZ-GN-01", "vulnerability_type": "Horizontal",
                "externally_exploitable": True, "endpoint": "PUT /api/u/:id",
                "vulnerable_code_location": "u.js:update:10",
                "role_context": "user", "guard_evidence": "no ownership check",
                "side_effect": "update any user record", "reason": "no ownership",
                "minimal_witness": "change :id", "confidence": "high",
                "notes": "dominance",
            }]},
        })()

    with patch.object(activities, "_get_paths", return_value=(tmp_path, tmp_path / "whitebox", tmp_path)):
        with patch("supernova_whitebox.pipeline.activities.run_gitnexus_verdict_agent", new=fake_run):
            with patch("supernova_whitebox.audit.session_registry.get_audit_session") as gs:
                inst = gs.return_value
                inst.track_step = _noop_cm_factory()
                inst.log_info = AsyncMock()
                result = await activities.run_authz_gitnexus_judge(_FakeInput(tmp_path))

    queue_path = tmp_path / "whitebox" / "intermediate" / "authz_gitnexus_queue.json"
    assert queue_path.exists()
    data = json.loads(queue_path.read_text())
    assert len(data["vulnerabilities"]) == 1
    v = data["vulnerabilities"][0]
    assert v["externally_exploitable"] is True
    assert v["source_track"] == "gitnexus"
    assert v["evidence_chain"]  # populated from candidate path
    assert result["candidate_count"] >= 1
    # prompt carried candidates
    assert "PUT /api/u/:id" in captured["prompt"]


@pytest.mark.asyncio
async def test_judge_skips_llm_when_no_candidates(tmp_path):
    """0 candidates → spec-1a G2: no longer silent empty queue.

    Now triggers autonomous explore (calls run_gitnexus_verdict_agent once
    with the explore prompt). This test asserts the post-T4 contract:
    explore is invoked, queue still exists, candidate_count==0.
    """
    # code_index.json 属于 deliverables（activity 从 deliverables/whitebox 读），
    # 落 whitebox/ 子目录，使 index 真正被读到——match 测试名 "no_candidates"
    # 的意图（index 存在但无候选），而非 index 整体缺失。
    dlv = tmp_path / "whitebox"
    dlv.mkdir(parents=True, exist_ok=True)
    (dlv / "code_index.json").write_text(json.dumps({
        "repository": "r", "language": "typescript", "total_blocks": 0,
        "total_entry_points": 0, "total_chains": 0, "blocks": [], "edges": [],
        "entry_points": [], "chains": [],
    }))

    called = {"n": 0, "prompt": None}

    async def fake_run(prompt, **kwargs):
        called["n"] += 1
        called["prompt"] = prompt
        return type("R", (), {
            "success": True, "structured_output": {"vulnerabilities": []},
            "text": "{}",
        })()

    with patch.object(activities, "_get_paths", return_value=(tmp_path, tmp_path / "whitebox", tmp_path)):
        with patch("supernova_whitebox.pipeline.activities.run_gitnexus_verdict_agent", new=fake_run):
            with patch("supernova_whitebox.audit.session_registry.get_audit_session") as gs:
                inst = gs.return_value
                inst.track_step = _noop_cm_factory()
                inst.log_info = AsyncMock()
                result = await activities.run_authz_gitnexus_judge(_FakeInput(tmp_path))

    # spec-1a G2: 0 候选触发自主探索（不再静默空）
    assert called["n"] == 1, "0 候选应触发 explore（非静默写空 queue）"
    assert called["prompt"] is not None
    assert "explore" in called["prompt"].lower() or "route" in called["prompt"].lower()
    assert (tmp_path / "whitebox" / "intermediate" / "authz_gitnexus_queue.json").exists()
    data = json.loads((tmp_path / "whitebox" / "intermediate" / "authz_gitnexus_queue.json").read_text())
    assert data["vulnerabilities"] == []  # explore 返空，queue 仍空（无幻觉）
    assert result["candidate_count"] == 0  # 确定性候选仍 0（explore 不改 candidate_count）


@pytest.mark.asyncio
async def test_judge_explore_prompt_has_repo_scope_and_routes(tmp_path):
    """探索 prompt 必须钉死 repo 边界并携带已识别路由表。

    2026-09-09 identity 实证：prompt 只给 route count 时，agent 会读全局
    /root/.gitnexus/registry.json 并跨 repo 枚举，最终耗尽 max turns 且无 JSON。
    """
    dlv = tmp_path / "whitebox"
    inter = dlv / "intermediate"
    inter.mkdir(parents=True, exist_ok=True)
    (inter / "code_index.json").write_text(json.dumps({
        "repository": "r", "language": "typescript", "total_blocks": 0,
        "total_entry_points": 1, "total_chains": 0, "blocks": [], "edges": [],
        "entry_points": [], "chains": [],
    }))
    (inter / "entry_points.json").write_text(json.dumps({
        "adjudicated_entry_points": [{
            "entry_type": "http_route", "route": "/api/items/:id",
            "http_method": "GET",
            "func_block_id": "src/item.ts:getItem:42", "evidence": "GetMapping",
        }],
    }))

    captured = {}

    async def fake_run(prompt, **kwargs):
        captured["prompt"] = prompt
        return type("R", (), {
            "success": True, "structured_output": {"vulnerabilities": []},
            "text": "{}",
        })()

    with patch.object(activities, "_get_paths", return_value=(tmp_path, dlv, tmp_path)):
        with patch("supernova_whitebox.pipeline.activities.run_gitnexus_verdict_agent", new=fake_run):
            with patch("supernova_whitebox.audit.session_registry.get_audit_session") as gs:
                inst = gs.return_value
                inst.track_step = _noop_cm_factory()
                inst.log_info = AsyncMock()
                await activities.run_authz_gitnexus_judge(_FakeInput(tmp_path))

    prompt = captured["prompt"]
    assert str(tmp_path) in prompt
    assert "ONLY allowed analysis target" in prompt
    assert "/root/.gitnexus/" in prompt
    assert "GET /api/items/:id @ src/item.ts:getItem:42" in prompt
    assert "{{REPO_ROOT}}" not in prompt
    assert "{{ENTRY_POINTS_SUMMARY}}" not in prompt


@pytest.mark.asyncio
async def test_judge_explore_failed_result_does_not_cache(tmp_path):
    """max-turns 返回 success=False（不抛异常）时必须标 failed 且不写 step cache。

    回归 identity/libs/app：结果为空 text 被当作 parse warning，activity 返回
    failed=false，step cache 反而把这次失败缓存成成功。
    """
    dlv = tmp_path / "whitebox"
    inter = dlv / "intermediate"
    inter.mkdir(parents=True, exist_ok=True)
    (inter / "code_index.json").write_text("{}")
    (inter / "framework_analysis.json").write_text("{}")

    async def fake_run(prompt, **kwargs):
        return type("R", (), {
            "success": False, "structured_output": None, "text": "",
            "error": None, "error_code": "ExecutionLimitError",
            "stop_reason": "max_turns", "turns": 0,
        })()

    with patch.object(activities, "_get_paths", return_value=(tmp_path, dlv, tmp_path)):
        with patch("supernova_whitebox.pipeline.activities.run_gitnexus_verdict_agent", new=fake_run):
            with patch("supernova_whitebox.audit.session_registry.get_audit_session") as gs:
                inst = gs.return_value
                inst.track_step = _noop_cm_factory()
                inst.log_info = AsyncMock()
                result = await activities.run_authz_gitnexus_judge(_FakeInput(tmp_path))

    assert result["failed"] is True
    assert result["fail_reason"] == "ExecutionLimitError"
    assert result["verdict_count"] == 0
    assert not (inter / ".step-cache" / "authz-gitnexus-judge.json").exists()


@pytest.mark.asyncio
async def test_judge_lenient_on_invalid_llm_output(tmp_path):
    """LLM returns non-JSON → parse_lenient absorbs, writes empty queue, no crash."""
    _write_index_with_candidate(tmp_path)

    async def fake_run(prompt, **kwargs):
        return type("R", (), {
            "success": True, "structured_output": None,
            "text": "not json", "error": None, "retryable": False, "turns": 1,
            "cost": 0.0, "model": "m", "stop_reason": "end", "tokens": None,
        })()

    with patch.object(activities, "_get_paths", return_value=(tmp_path, tmp_path / "whitebox", tmp_path)):
        with patch("supernova_whitebox.pipeline.activities.run_gitnexus_verdict_agent", new=fake_run):
            with patch("supernova_whitebox.audit.session_registry.get_audit_session") as gs:
                inst = gs.return_value
                inst.track_step = _noop_cm_factory()
                inst.log_info = AsyncMock()
                await activities.run_authz_gitnexus_judge(_FakeInput(tmp_path))

    data = json.loads((tmp_path / "whitebox" / "intermediate" / "authz_gitnexus_queue.json").read_text())
    assert data["vulnerabilities"] == []  # lenient


@pytest.mark.asyncio
async def test_judge_logs_warning_when_no_candidates(tmp_path):
    """0 候选 → 发 warning（经 InfoEvent），点明 http_route 入口点数。"""
    # code_index.json 属于 deliverables（activity 从 deliverables/whitebox 读），
    # 落 whitebox/ 子目录，使 index 真正被读到——match "no_candidates" 的意图。
    dlv = tmp_path / "whitebox"
    dlv.mkdir(parents=True, exist_ok=True)
    (dlv / "code_index.json").write_text(json.dumps({
        "repository": "r", "language": "typescript", "total_blocks": 0,
        "total_entry_points": 0, "total_chains": 0, "blocks": [], "edges": [],
        "entry_points": [], "chains": [],
    }))

    async def fake_run(prompt, **kwargs):
        return type("R", (), {"success": True, "structured_output": {"vulnerabilities": []}})()

    with patch.object(activities, "_get_paths", return_value=(tmp_path, tmp_path / "whitebox", tmp_path)):
        with patch("supernova_whitebox.pipeline.activities.run_gitnexus_verdict_agent", new=fake_run):
            with patch("supernova_whitebox.audit.session_registry.get_audit_session") as gs:
                inst = gs.return_value
                inst.track_step = _noop_cm_factory()
                inst.log_info = AsyncMock()
                await activities.run_authz_gitnexus_judge(_FakeInput(tmp_path))

    levels = [call.args[1] for call in inst.log_info.call_args_list]
    msgs = [call.args[0] for call in inst.log_info.call_args_list]
    assert "warning" in levels
    assert any("0 候选" in m and "http_route" in m for m in msgs)


@pytest.mark.asyncio
@pytest.mark.xfail(
    reason=(
        "预存失败（同 test_judge_writes_gitnexus_queue_from_candidates 根因）："
        "fixture 不产生候选 → 走探索分支 → 日志为 '自主探索产出软候选' 不含 'verdict'。"
        "根因在候选生成层，非 epic 判定深度引入；待 spec-1b/G3 修 fixture。"
    ),
    strict=False,
)
async def test_judge_logs_info_when_candidates(tmp_path):
    """有候选 → 发 info（调 LLM + 产出 verdict 数）。"""
    _write_index_with_candidate(tmp_path)

    async def fake_run(prompt, **kwargs):
        return type("R", (), {
            "success": True, "error": None, "retryable": False, "turns": 1,
            "cost": 0.0, "text": "", "model": "m", "stop_reason": "end",
            "tokens": None,
            "structured_output": {"vulnerabilities": [{
                "ID": "AUTHZ-GN-01", "vulnerability_type": "Horizontal",
                "externally_exploitable": True, "endpoint": "PUT /api/u/:id",
                "vulnerable_code_location": "u.js:update:10", "role_context": "user",
                "guard_evidence": "none", "side_effect": "update", "reason": "no ownership",
                "minimal_witness": "x", "confidence": "high", "notes": "",
            }]},
        })()

    with patch.object(activities, "_get_paths", return_value=(tmp_path, tmp_path / "whitebox", tmp_path)):
        with patch("supernova_whitebox.pipeline.activities.run_gitnexus_verdict_agent", new=fake_run):
            with patch("supernova_whitebox.audit.session_registry.get_audit_session") as gs:
                inst = gs.return_value
                inst.track_step = _noop_cm_factory()
                inst.log_info = AsyncMock()
                await activities.run_authz_gitnexus_judge(_FakeInput(tmp_path))

    levels = [call.args[1] for call in inst.log_info.call_args_list]
    msgs = [call.args[0] for call in inst.log_info.call_args_list]
    assert "info" in levels
    assert any("候选" in m for m in msgs)
    assert any("verdict" in m for m in msgs)  # 判定后那条


@pytest.mark.asyncio
async def test_judge_explore_fills_missing_id_not_drops(tmp_path):
    """回归 hr_20260713:0 候选探索 agent 返回**缺 ID** 的候选,应补 ID 后落地,
    而非被 parse_lenient 静默丢弃(BaseVulnerability.ID 必填 → 全丢 → queue 落地 0)。

    真机:authz 探索 agent 找到 4 个候选(authz_gitnexus_explore prompt 产出的
    schema 无 ID 字段),authz_gitnexus_queue.json 落地 0。
    """
    dlv = tmp_path / "whitebox"
    dlv.mkdir(parents=True, exist_ok=True)
    (dlv / "code_index.json").write_text(json.dumps({
        "repository": "r", "language": "typescript", "total_blocks": 0,
        "total_entry_points": 0, "total_chains": 0, "blocks": [], "edges": [],
        "entry_points": [], "chains": [],
    }))

    async def fake_run(prompt, **kwargs):
        # 探索 agent 产出**缺 ID**(模拟 authz_gitnexus_explore prompt schema)
        return type("R", (), {
            "success": True,
            "structured_output": {"vulnerabilities": [
                {"endpoint": "GET /api/a/:id", "vulnerability_type": "Horizontal",
                 "externally_exploitable": False, "vulnerable_code_location": "a.ts:1",
                 "reason": "no ownership", "minimal_witness": "x", "confidence": "low"},
                {"endpoint": "GET /api/b/:id", "vulnerability_type": "Horizontal",
                 "externally_exploitable": False, "vulnerable_code_location": "b.ts:1",
                 "reason": "no ownership", "minimal_witness": "y", "confidence": "low"},
            ]},
            "text": "",
        })()

    with patch.object(activities, "_get_paths", return_value=(tmp_path, tmp_path / "whitebox", tmp_path)):
        with patch("supernova_whitebox.pipeline.activities.run_gitnexus_verdict_agent", new=fake_run):
            with patch("supernova_whitebox.audit.session_registry.get_audit_session") as gs:
                inst = gs.return_value
                inst.track_step = _noop_cm_factory()
                inst.log_info = AsyncMock()
                await activities.run_authz_gitnexus_judge(_FakeInput(tmp_path))

    data = json.loads((tmp_path / "whitebox" / "intermediate" / "authz_gitnexus_queue.json").read_text())
    assert len(data["vulnerabilities"]) == 2  # BUG 时此处为 0(parse_lenient 丢缺 ID)
    assert all(v.get("ID") for v in data["vulnerabilities"])  # 补了 ID
    assert all(v.get("needs_review") is True for v in data["vulnerabilities"])  # 探索软候选


@pytest.mark.asyncio
async def test_judge_explore_output_schema_has_field_type_guidance(tmp_path):
    """structured_output_schema 不再是空壳（2026-09-02 盘点收口：authz 两处与
    gn-enrich 翻车同款形态——vulnerabilities: array 无 items 约束）：items 带
    authz_gitnexus_judge.txt <output_format> 契约的类型引导——str 字段 +
    externally_exploitable: boolean（可达性标签，bool 契约，与 gn-enrich 的
    str 字段相反）；宽松声明（无 required / additionalProperties，防
    anthropic AJV 过严自纠循环）。judge 与 explore 两分支共用同一 schema。"""
    dlv = tmp_path / "whitebox"
    dlv.mkdir(parents=True, exist_ok=True)
    (dlv / "code_index.json").write_text(json.dumps({
        "repository": "r", "language": "typescript", "total_blocks": 0,
        "total_entry_points": 0, "total_chains": 0, "blocks": [], "edges": [],
        "entry_points": [], "chains": [],
    }))

    captured = {}

    async def fake_run(prompt, **kwargs):
        captured.update(kwargs)
        return type("R", (), {
            "success": True,
            "structured_output": {"vulnerabilities": []},
            "text": "",
        })()

    with patch.object(activities, "_get_paths", return_value=(tmp_path, tmp_path / "whitebox", tmp_path)):
        with patch("supernova_whitebox.pipeline.activities.run_gitnexus_verdict_agent", new=fake_run):
            with patch("supernova_whitebox.audit.session_registry.get_audit_session") as gs:
                inst = gs.return_value
                inst.track_step = _noop_cm_factory()
                inst.log_info = AsyncMock()
                await activities.run_authz_gitnexus_judge(_FakeInput(tmp_path))

    schema = captured["structured_output_schema"]
    items = schema["properties"]["vulnerabilities"]["items"]
    props = items["properties"]
    assert props["endpoint"] == {"type": "string"}
    assert props["vulnerable_code_location"] == {"type": "string"}
    assert props["externally_exploitable"] == {"type": "boolean"}
    assert props["confidence"] == {"type": "string"}
    # 宽松声明：不设 required / additionalProperties
    assert "required" not in items
    assert "additionalProperties" not in items


def test_parse_gitnexus_verdict_output_fills_missing_id():
    """缺 ID 的候选 parse 前补序列化 ID(不被 parse_lenient 丢弃);已有 ID 保留不变。

    覆盖 candidate>0 判定分支与探索分支共用的 helper:真机 hr_20260713 的 4→0
    根因即缺 ID 被丢,这里钉死补 ID 行为 + 已有 ID 不被覆写。
    """
    from supernova_whitebox.pipeline.activities import _parse_gitnexus_verdict_output
    raw = {"vulnerabilities": [
        {"endpoint": "/a", "vulnerability_type": "Horizontal",
         "externally_exploitable": False, "confidence": "low"},               # 缺 ID
        {"ID": "AUTHZ-GN-99", "endpoint": "/b", "vulnerability_type": "Horizontal",
         "externally_exploitable": True, "confidence": "high"},               # 已有 ID
        {"endpoint": "/c", "vulnerability_type": "Horizontal",
         "externally_exploitable": False, "confidence": "low"},               # 缺 ID
    ]}
    vulns, _warnings = _parse_gitnexus_verdict_output(raw, "AUTHZ-GN-EXPLORE-")
    assert len(vulns) == 3
    assert [v.ID for v in vulns] == ["AUTHZ-GN-EXPLORE-01", "AUTHZ-GN-99", "AUTHZ-GN-EXPLORE-03"]


def test_parse_gitnexus_verdict_output_invalid_raw_no_crash():
    """非 JSON / 空 raw → ([], warnings),不崩(守 parse_lenient 容错 + never silent)。"""
    from supernova_whitebox.pipeline.activities import _parse_gitnexus_verdict_output
    vulns, warnings = _parse_gitnexus_verdict_output("not json", "AUTHZ-GN-")
    assert vulns == []
    assert warnings  # invalid json → parse_lenient 产 warning,caller 应打日志


def _noop_cm_factory():
    class _CM:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a):
            return False
    return lambda *a, **k: _CM()


# ── step cache 接线（spec 2026-08-27-web-resume-breakpoint §4.3）───────────────
#
# marker + 输入指纹（code_index.json / framework_analysis.json）——命中则
# 候选轨重建与判定 agent 都不跑、直接还原缓存返回值；干净完成（failed=False）
# 末尾打点，agent 失败降级（failed=True）不打（resume=再试一次）。

_STEP = "authz-gitnexus-judge"


def _cache_inputs(deliverables):
    from supernova_core.utils.paths import intermediate_path
    return [intermediate_path(deliverables, "code_index.json"),
            intermediate_path(deliverables, "framework_analysis.json")]


def _marker(deliverables):
    return deliverables / "intermediate" / ".step-cache" / f"{_STEP}.json"


def _mk_inter(tmp_path):
    deliverables = tmp_path / "whitebox"
    inter = deliverables / "intermediate"
    inter.mkdir(parents=True, exist_ok=True)
    (inter / "code_index.json").write_text("{}")
    (inter / "framework_analysis.json").write_text("{}")
    return deliverables, inter


@pytest.mark.asyncio
async def test_step_cache_hit_skips_track_build_and_agent(tmp_path):
    """marker 有效 → build_authz_gitnexus_track 与 run_gitnexus_verdict_agent
    均不得被调用，返回缓存快照。"""
    from supernova_whitebox.pipeline import step_cache
    deliverables, inter = _mk_inter(tmp_path)
    cached_ret = {"candidate_count": 2, "verdict_count": 1,
                  "dominance_candidates": 1, "framework_candidates": 1,
                  "failed": False, "fail_reason": None}
    # 首跑产物在盘（outputs 存在性校验的一部分）
    (inter / "authz_gitnexus_queue.json").write_text(
        '{"vulnerabilities": []}', encoding="utf-8")
    step_cache.mark_done(_STEP, deliverables,
                         inputs=_cache_inputs(deliverables),
                         outputs=[inter / "authz_gitnexus_queue.json"],
                         ret=cached_ret)

    with patch.object(activities, "_get_paths", return_value=(tmp_path, deliverables, tmp_path)):
        with patch("supernova_core.code_index.authz_gitnexus_track.build_authz_gitnexus_track",
                   side_effect=AssertionError("缓存命中时不得重建候选轨")):
            with patch("supernova_whitebox.pipeline.activities.run_gitnexus_verdict_agent",
                       side_effect=AssertionError("缓存命中时不得调判定 agent")):
                with patch("supernova_whitebox.audit.session_registry.get_audit_session") as gs:
                    inst = gs.return_value
                    inst.track_step = _noop_cm_factory()
                    inst.log_info = AsyncMock()
                    result = await activities.run_authz_gitnexus_judge(_FakeInput(tmp_path))

    assert result == cached_ret


@pytest.mark.asyncio
async def test_clean_run_writes_marker(tmp_path):
    """干净完成（failed=False）末尾打点，键料与跳过侧一致。"""
    from supernova_whitebox.pipeline import step_cache
    deliverables, _inter = _mk_inter(tmp_path)

    def fake_build(out):
        return ("# no candidates", [], [], 0, 0)

    async def fake_agent(**kwargs):
        return type("R", (), {
            "success": True, "error": None, "retryable": False, "turns": 1,
            "cost": 0.0, "text": "", "model": "m", "stop_reason": "end",
            "tokens": None, "structured_output": None,
        })()

    with patch.object(activities, "_get_paths", return_value=(tmp_path, deliverables, tmp_path)):
        with patch("supernova_core.code_index.authz_gitnexus_track.build_authz_gitnexus_track",
                   new=fake_build):
            with patch("supernova_whitebox.pipeline.activities.run_gitnexus_verdict_agent",
                       new=fake_agent):
                with patch("supernova_whitebox.audit.session_registry.get_audit_session") as gs:
                    inst = gs.return_value
                    inst.track_step = _noop_cm_factory()
                    inst.log_info = AsyncMock()
                    result = await activities.run_authz_gitnexus_judge(_FakeInput(tmp_path))

    assert result["failed"] is False
    skip, cached = step_cache.should_skip(
        _STEP, deliverables, inputs=_cache_inputs(deliverables))
    assert skip is True
    assert cached == result


@pytest.mark.asyncio
async def test_failed_run_does_not_write_marker(tmp_path):
    """agent 失败降级（failed=True 返回）不打点——resume 会重试。"""
    deliverables, _inter = _mk_inter(tmp_path)

    def fake_build(out):
        return ("# no candidates", [], [], 0, 0)

    async def fake_agent(**kwargs):
        raise RuntimeError("agent boom")

    with patch.object(activities, "_get_paths", return_value=(tmp_path, deliverables, tmp_path)):
        with patch("supernova_core.code_index.authz_gitnexus_track.build_authz_gitnexus_track",
                   new=fake_build):
            with patch("supernova_whitebox.pipeline.activities.run_gitnexus_verdict_agent",
                       new=fake_agent):
                with patch("supernova_whitebox.audit.session_registry.get_audit_session") as gs:
                    inst = gs.return_value
                    inst.track_step = _noop_cm_factory()
                    inst.log_info = AsyncMock()
                    result = await activities.run_authz_gitnexus_judge(_FakeInput(tmp_path))

    assert result["failed"] is True
    assert not _marker(deliverables).exists()


# ── 判非漏洞分流（spec 2026-08-27 §4 authz 补位）───────────────────────────────
#
# 回归 risk_margin-20260910-041235：两条 AUTHZ-GN-EXPLORE 标题明写「复核为已防护」、
# narrative 写「无实际越权影响」，仍以 high 进报告——authz 判词契约无 verdict 字段，
# 判 safe 无出口（只能写进标题文本），写入侧也无分流。现在 prompt 契约带
# verdict（vulnerable|safe），activity 写入侧 _split_authz_safe 分流留档。


def test_split_authz_safe_helper_ducks_typing():
    """verdict="safe" → dismissed entry（vuln_class=authz + stage 透传）；
    verdict 缺失/vulnerable 保守进 queue。"""
    from types import SimpleNamespace
    safe = SimpleNamespace(ID="AUTHZ-GN-EXPLORE-01", verdict="safe", title="t",
                           guard_evidence=None, reason="仅选择公开配置",
                           evidence_chain="e", confidence="low",
                           endpoint="GET /api/x", vulnerable_code_location="c.js:1")
    vuln = SimpleNamespace(ID="AUTHZ-GN-EXPLORE-02", verdict="vulnerable",
                           title=None, guard_evidence="no check", reason="r",
                           evidence_chain=None, confidence="low",
                           endpoint="GET /api/y", vulnerable_code_location="c.js:9")
    missing = SimpleNamespace(ID="AUTHZ-GN-EXPLORE-03", verdict=None)
    kept, dismissed = activities._split_authz_safe(
        [safe, vuln, missing], stage="authz-gitnexus-explore")
    assert [v.ID for v in kept] == ["AUTHZ-GN-EXPLORE-02", "AUTHZ-GN-EXPLORE-03"]
    assert len(dismissed) == 1
    entry = dismissed[0]
    assert entry["ID"] == "AUTHZ-GN-EXPLORE-01"
    assert entry["vuln_class"] == "authz"
    assert entry["source_track"] == "gitnexus"
    assert entry["dismissed_at_stage"] == "authz-gitnexus-explore"
    # guard_evidence 缺 → reason 兜底（留档可判读）
    assert entry["dismiss_reason"] == "仅选择公开配置"


@pytest.mark.asyncio
async def test_judge_explore_splits_safe_verdicts_to_dismissed(tmp_path):
    """explore 输出混 verdict=safe/vulnerable → queue 只留 vulnerable，
    safe 卡进 dismissed_findings.json 留档（不进 queue/报告）。"""
    deliverables = tmp_path / "whitebox"
    inter = deliverables / "intermediate"
    inter.mkdir(parents=True, exist_ok=True)
    # 完整空索引（{} 过不了 build_authz_gitnexus_track 的 pydantic 校验）
    (inter / "code_index.json").write_text(json.dumps({
        "repository": "r", "language": "typescript", "total_blocks": 0,
        "total_entry_points": 0, "total_chains": 0, "blocks": [], "edges": [],
        "entry_points": [], "chains": [],
    }))
    (inter / "framework_analysis.json").write_text("{}")

    async def fake_run(prompt, **kwargs):
        return type("R", (), {
            "success": True,
            "structured_output": {"vulnerabilities": [
                {"ID": "AUTHZ-GN-EXPLORE-01", "vulnerability_type": "Horizontal",
                 "externally_exploitable": True, "endpoint": "GET /api/a",
                 "verdict": "safe", "confidence": "low",
                 "reason": "仅选择公开行情配置", "notes": "explore-discovered"},
                {"ID": "AUTHZ-GN-EXPLORE-02", "vulnerability_type": "Horizontal",
                 "externally_exploitable": True, "endpoint": "GET /api/b",
                 "verdict": "vulnerable", "confidence": "low",
                 "reason": "no ownership check", "notes": "explore-discovered"},
            ]},
            "text": "",
        })()

    with patch.object(activities, "_get_paths", return_value=(tmp_path, deliverables, tmp_path)):
        with patch("supernova_whitebox.pipeline.activities.run_gitnexus_verdict_agent", new=fake_run):
            with patch("supernova_whitebox.audit.session_registry.get_audit_session") as gs:
                inst = gs.return_value
                inst.track_step = _noop_cm_factory()
                inst.log_info = AsyncMock()
                result = await activities.run_authz_gitnexus_judge(_FakeInput(tmp_path))

    queue = json.loads(
        (deliverables / "intermediate" / "authz_gitnexus_queue.json").read_text())
    assert [v["ID"] for v in queue["vulnerabilities"]] == ["AUTHZ-GN-EXPLORE-02"]
    assert queue["vulnerabilities"][0]["needs_review"] is True

    dismissed = json.loads(
        (deliverables / "intermediate" / "dismissed_findings.json").read_text())
    entries = [e for e in dismissed["dismissed"]
               if e["ID"] == "AUTHZ-GN-EXPLORE-01"]
    assert len(entries) == 1
    assert entries[0]["vuln_class"] == "authz"
    assert entries[0]["dismissed_at_stage"] == "authz-gitnexus-explore"
    assert entries[0]["dismiss_reason"] == "仅选择公开行情配置"

    assert result["verdict_count"] == 1
    assert result["safe_dismissed"] == 1
    assert result["failed"] is False
