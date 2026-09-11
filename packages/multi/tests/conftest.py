"""multi 测试的 logging 单例清理（对齐 core/tests/conftest.py 基线）。

run_correlation_phase（2026-09-11 起装 temporalio redirect 到本会话目录）会把
共享 routing handler 挂到进程级 temporalio.* logger 上；logger 是全局单例，
不清理则泄漏到后续测试（handler 指向已删 tmp_path / propagate=False 残留）。
"""
from __future__ import annotations

import logging

import pytest

_TEMPORALIO_LOGGERS = ("temporalio.activity", "temporalio.worker")


@pytest.fixture(autouse=True)
def _clean_temporalio_loggers():
    yield
    for name in _TEMPORALIO_LOGGERS:
        lg = logging.getLogger(name)
        for h in list(lg.handlers):
            lg.removeHandler(h)
            h.close()
        lg.propagate = True
    import supernova_core.logging.temporalio_redirect as _tr
    if _tr._routing_handler is not None:
        for fh in list(_tr._routing_handler._targets.values()):
            fh.close()
        _tr._routing_handler = None
