"""Task 5: WorkflowLogger wires the temporalio.activity redirect into initialize.

We test the extracted ``_install_failure_redirect`` helper directly rather than
the heavier ``initialize`` (which spins up a LogStream + dispatcher + Rich
renderers). The helper is the unit of behavior: it computes the same-source
sibling path, installs the redirect, and records the path for ``log_error``'s
``detail_path`` hint.
"""
import logging
from pathlib import Path
from unittest.mock import patch

import pytest

from supernova_core.audit.workflow_logger import WorkflowLogger

_LOGGER_NAME = "temporalio.activity"


@pytest.fixture(autouse=True)
def _restore_temporalio_activity_logger():
    """Snapshot and restore the temporalio.activity logger state.

    ``logging.getLogger(name)`` returns the same global logger across tests, so
    handlers attached by ``install_temporalio_log_redirect`` and the
    ``propagate=False`` toggle would leak into subsequent tests (both within
    this module and across the wider suite). We snapshot before and restore
    after so each test starts from a clean, propagation-on, handler-less state.
    Mirrors the T4 fixture in ``test_temporalio_log_redirect.py``.
    """
    logger = logging.getLogger(_LOGGER_NAME)
    saved_handlers = list(logger.handlers)
    saved_propagate = logger.propagate
    saved_level = logger.level
    try:
        yield
    finally:
        for h in list(logger.handlers):
            if h not in saved_handlers:
                logger.removeHandler(h)
                h.close()
        for h in saved_handlers:
            if h not in logger.handlers:
                logger.addHandler(h)
        logger.propagate = saved_propagate
        logger.setLevel(saved_level)


def test_install_failure_redirect_sets_path_and_propagate(tmp_path):
    """_install_failure_redirect sets detail_path (sibling) and disables propagate."""
    wf_log = tmp_path / "workflow.log"
    wl = WorkflowLogger.__new__(WorkflowLogger)  # bypass __init__ (no dispatcher)
    wl._meta = None  # generate_workflow_log_path is patched, so meta is unused
    wl._activity_failure_log_path = None

    with patch(
        "supernova_core.audit.workflow_logger.generate_workflow_log_path",
        return_value=wf_log,
    ):
        wl._install_failure_redirect()

    # detail_path is the sibling of workflow.log: <audit_dir>/activity_failures.log
    assert wl._activity_failure_log_path == str(
        wf_log.with_name("activity_failures.log"))
    # propagate=False is the defense-in-depth against a root stderr handler.
    assert logging.getLogger(_LOGGER_NAME).propagate is False
    # 路由架构（2026-09-11）：logger 挂共享 routing handler，其 fallback 目标
    # （workflow_logger 不带 workflow_id 安装 → fallback）指向该路径。
    routing = [h for h in logging.getLogger(_LOGGER_NAME).handlers
               if not isinstance(h, logging.FileHandler)]
    assert routing, "expected the shared routing handler on temporalio.activity"
    fh = routing[0]._targets.get("_fallback")
    assert fh is not None, "expected a fallback FileHandler registered"
    assert Path(fh.baseFilename).resolve() \
        == (tmp_path / "activity_failures.log").resolve()


def test_install_failure_redirect_degrades_silently_on_error(tmp_path):
    """If the redirect install raises, log_error still works (detail_path=None)."""
    wl = WorkflowLogger.__new__(WorkflowLogger)
    wl._meta = None
    wl._activity_failure_log_path = "stale"

    with patch(
        "supernova_core.audit.workflow_logger.generate_workflow_log_path",
        side_effect=RuntimeError("disk full"),
    ):
        wl._install_failure_redirect()  # must NOT raise

    assert wl._activity_failure_log_path is None
