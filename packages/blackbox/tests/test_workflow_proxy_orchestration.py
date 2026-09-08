"""Task 8 workflow orchestration: host proxy setup runs BEFORE preflight;
stop_host_proxy runs in finally (best-effort cleanup).

Uses Temporal's WorkflowEnvironment + mocked activities (same pattern as
test_endpoint_verify.py). Asserts activity call ORDER, not real proxy behavior.

⚠️ LOCAL-RUN NOTE: This test depends on `WorkflowEnvironment.start_local()`,
which auto-downloads a Temporal dev-server binary on first use. In some sandboxed
CI / dev environments that download TIMES OUT (Task 7's test_endpoint_verify.py
hit the same environmental block). If the dev-server download times out here,
this test is INCOMPLETE-LOCALLY by design — it is REPORTED as
"dev-server-blocked; verified in CI / Task 14 real-machine smoke" — NOT deleted,
NOT faked GREEN. The orchestration EDITS are additionally guarded by code
inspection (reviewer) + the registration test (test_host_proxy_registration.py,
which IS locally verifiable).

Mock coverage (re-walked for test input: web_url+event_file+exploit set,
no config_path, no correlated_workspace):
  REACHED & MOCKED — setup_display, log_phase_start_activity (preflight/
    exploitation/reporting), run_host_proxy_setup, run_blackbox_preflight,
    resolve_blackbox_engine, detect_whitebox_results, log_info_activity
    (multiple sites), run_endpoint_verify, validate_exploitation_queue,
    write_engine_config_for_session, run_exploit_agent, assemble_report,
    run_report_agent, finalize_report, finalize_summary, cleanup_engine_configs,
    cleanup_auth_state_activity, stop_host_proxy
  SKIPPED (no need to mock) — run_blackbox_auth_validation + auth-validation
    log_phase (config_path=None), load_correlation_context
    (correlated_workspace=None), corr-classes log_info_activity (mock returns
    corr_classes=[]), invalid-queue log_info_activity (mock returns valid=True)
"""
import pytest
from temporalio import activity
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from supernova_blackbox.pipeline.workflows import BlackboxScanWorkflow
from supernova_core.services import scan_gate as gate_mod
from supernova_blackbox.pipeline.shared import BlackboxPipelineInput
from supernova_blackbox.services.exploitation_checker import QueueValidationResult



@pytest.fixture(autouse=True)
def _reset_gate():
    """闸门接线后 run() 首个 activity 是 scan_gate_try_acquire（真实现）——
    进程级 gate 单例跨测试清态，防槽残留互扰。"""
    gate_mod.reset_gate_for_tests()
    yield
    gate_mod.reset_gate_for_tests()

def _build_proxy_chain_mocks(call_order: list, proxy_url_return: str) -> list:
    """Build the full mock activity chain for BlackboxScanWorkflow with host
    proxy instrumentation. ``proxy_url_return`` controls what
    ``run_host_proxy_setup`` returns ('' = no proxy / non-empty = proxy active).
    """
    @activity.defn
    async def setup_display(i): pass
    @activity.defn
    async def log_phase_start_activity(i, steps=None, intents=None): pass
    @activity.defn
    async def run_host_proxy_setup(i):
        call_order.append("host_proxy_setup")
        return proxy_url_return
    @activity.defn
    async def run_blackbox_preflight(i):
        call_order.append("preflight")
    @activity.defn
    async def resolve_blackbox_engine(i): return "agent-browser"
    @activity.defn
    async def detect_whitebox_results(dp, vc, corr):
        return {"has_whitebox_results": True, "found_classes": ["injection"],
                "corr_classes": [], "has_recon_deliverable": True}
    @activity.defn
    async def log_info_activity(i): pass
    @activity.defn
    async def run_endpoint_verify(i):
        # web_url=set → workflow reaches L323 run_endpoint_verify. Return shape
        # mimics the degradation path (the workflow does not consume the return
        # value — it's just awaited; activity writes endpoint_verify.json itself).
        call_order.append("endpoint_verify")
        return {"endpoint_verify": None, "cost_currency": "USD"}
    @activity.defn
    async def validate_exploitation_queue(i) -> QueueValidationResult:
        call_order.append("validate")
        return QueueValidationResult(valid=True, reason="ok", vuln_count=1)
    @activity.defn
    async def write_engine_config_for_session(repo, sess, eng, proxy_url=None):
        call_order.append(f"write_engine_config:{proxy_url}")
    @activity.defn
    async def run_exploit_agent(i):
        call_order.append("exploit")
        return {"duration_ms": 1, "cost_usd": 0.0, "cost_currency": "USD"}
    @activity.defn
    async def assemble_report(i): pass
    @activity.defn
    async def run_report_agent(i): return {"duration_ms": 1, "cost_usd": 0.0}
    @activity.defn
    async def finalize_report(i): pass
    @activity.defn
    async def cleanup_engine_configs(rp, eng): pass
    @activity.defn
    async def cleanup_auth_state_activity(ws): pass
    @activity.defn
    async def stop_host_proxy(proxy_url):
        call_order.append(f"stop_host_proxy:{proxy_url}")
    @activity.defn
    async def finalize_summary(i, summary): pass
    @activity.defn
    async def persist_completed_agents(i, completed_agents): pass
    return [setup_display, log_phase_start_activity, run_host_proxy_setup,
            run_blackbox_preflight, resolve_blackbox_engine,
            detect_whitebox_results, log_info_activity,
            run_endpoint_verify,
            validate_exploitation_queue, write_engine_config_for_session,
            run_exploit_agent, assemble_report, run_report_agent,
            finalize_report, cleanup_engine_configs,
            cleanup_auth_state_activity, stop_host_proxy, finalize_summary,
            persist_completed_agents]


async def _run_workflow(acts, inp, wid, tq):
    async with await WorkflowEnvironment.start_local() as env:
        async with Worker(env.client, task_queue=tq, workflows=[BlackboxScanWorkflow],
                          # gate activity 用真实现：闸门接线后 run() 首个 activity 即过闸
                          activities=[*acts, gate_mod.scan_gate_try_acquire,
                                      gate_mod.scan_gate_release]):
            return await env.client.execute_workflow(
                BlackboxScanWorkflow.run, inp, id=wid, task_queue=tq)


def _pipeline_input(tmp_path, host_mappings: dict) -> BlackboxPipelineInput:
    return BlackboxPipelineInput(
        web_url="https://example.com", repo_path=str(tmp_path / "repo"),
        workspace_name="bb-proxy", workspaces_root=str(tmp_path / "workspaces"),
        deliverables_subdir="deliverables", exploit=True,
        event_file=str(tmp_path / "events.ndjson"),
        host_mappings=host_mappings,
    )


@pytest.mark.asyncio
async def test_workflow_runs_setup_before_preflight_and_cleanup_in_finally(tmp_path):
    """host_mappings 非空 → setup 返回 proxy_url → 注入 act_input → preflight 后;
    finally 调 stop_host_proxy。setup 必须在 preflight 前(供 preflight 映射 host)。

    RED (before T8 workflow edits): call_order 不含 host_proxy_setup,或其在
    preflight 之后;finally 无 stop_host_proxy。
    GREEN (after T8): host_proxy_setup 在 preflight 前,stop 在末尾。
    """
    call_order: list = []
    acts = _build_proxy_chain_mocks(call_order, "http://127.0.0.1:9090")
    await _run_workflow(
        acts, _pipeline_input(tmp_path, {"x.test": "10.0.0.1"}),
        "w-proxy1", "tq-proxy1")

    # setup ran at all
    assert "host_proxy_setup" in call_order, "workflow must call run_host_proxy_setup"
    # ORDER: setup strictly before preflight
    assert call_order.index("host_proxy_setup") < call_order.index("preflight"), (
        "run_host_proxy_setup must run BEFORE run_blackbox_preflight "
        "(proxy_url must be available so preflight can pin host→IP)"
    )
    # proxy_url propagated to write_engine_config_for_session (proves injection
    # into act_input + derivative inputs)
    assert any(str(c).startswith("write_engine_config:http://127.0.0.1:9090")
               for c in call_order), (
        "proxy_url must propagate to write_engine_config_for_session "
        "(proves act_input.proxy_url injection + derivative-input inheritance)"
    )
    # stop_host_proxy called in finally (best-effort cleanup)
    assert any(str(c).startswith("stop_host_proxy:http://127.0.0.1:9090")
               for c in call_order), (
        "stop_host_proxy must run in finally when proxy_url was set"
    )
    # stop must come AFTER preflight (sanity — finally is last)
    assert call_order.index(
        next(c for c in call_order if str(c).startswith("stop_host_proxy:"))
    ) > call_order.index("preflight")


@pytest.mark.asyncio
async def test_workflow_no_mappings_skips_proxy_start_and_cleanup(tmp_path):
    """host_mappings={} → run_host_proxy_setup returns '' → act_input.proxy_url
    stays None → stop_host_proxy NOT called in finally (backward compat;
    existing scans with no HOST profile are unaffected).

    Note: the setup activity IS still invoked (it returns '' as a no-op), but
    no proxy is started and no cleanup is scheduled. This preserves zero-regression
    for existing scans.
    """
    call_order: list = []
    acts = _build_proxy_chain_mocks(call_order, "")  # setup returns '' (no mappings)
    await _run_workflow(
        acts, _pipeline_input(tmp_path, {}),  # empty host_mappings
        "w-proxy2", "tq-proxy2")

    # setup activity IS invoked (workflow always calls it; it decides no-op internally)
    assert "host_proxy_setup" in call_order
    # but proxy_url is '' → not injected into act_input → write_engine_config sees None
    assert any(str(c) == "write_engine_config:None" for c in call_order), (
        "with empty host_mappings, proxy_url must be '' → not set on act_input → "
        "write_engine_config_for_session receives None (backward compat)"
    )
    # CRITICAL: stop_host_proxy NOT called (proxy_url is None → finally guard skips it)
    assert not any(str(c).startswith("stop_host_proxy:") for c in call_order), (
        "stop_host_proxy must NOT be invoked when proxy_url was never set "
        "(zero-regression for scans without a HOST profile)"
    )
