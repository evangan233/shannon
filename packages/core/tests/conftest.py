"""全局 autouse fixture：防 logging 单例跨测试泄漏。

某些测试用真实 run_with_display（如 test_live_ghost_frames），其 workflow_logger
会安装 temporalio.activity handler；LogBus.attach 也会留状态。若无 teardown 清理，
这些会泄漏到后续测试——例如 test_temporalio_log_redirect 的幂等断言会检测到上一个
测试残留的 handler（曾表现为 ``/tmp/ghost-probe/.../activity_failures.log`` handler
堆叠），误判安装不幂等。

模块级 snapshot/restore fixture（test_logging_setup / test_temporalio_log_redirect /
test_log_bus*）优先处理各自单例；本 conftest 做基线强制清理兜底，保证每个测试结束后
logging 单例回到干净状态。
"""
from __future__ import annotations

import logging
import queue as _queue

import pytest

# redirect(temporalio_redirect.py)管理的 logger: temporalio.activity(failure trace)
# + temporalio.worker 子树(_activity :315/:521 执行边界 DEBUG)。两者都可能被测试
# 安装 handler + propagate=False,必须都清,否则跨测试泄漏(propagate=False 残留尤甚)。
_TEMPORALIO_LOGGERS = ("temporalio.activity", "temporalio.worker")


@pytest.fixture(autouse=True)
def _clean_logging_singletons():
    yield
    # 强制重置到干净基线（非 snapshot restore），清掉任何测试安装的 handler/状态。
    for _tio_name in _TEMPORALIO_LOGGERS:
        tio = logging.getLogger(_tio_name)
        for h in list(tio.handlers):
            tio.removeHandler(h)
            h.close()
        tio.propagate = True
    # routing handler 模块单例重置（2026-09-11 路由架构）：不重置则带旧 registry
    # （指向已删 tmp_path 的 FileHandler）跨测试存活。
    import supernova_core.logging.temporalio_redirect as _tr
    for fh in list(_tr._routing_handler._targets.values()) \
            if _tr._routing_handler else []:
        fh.close()
    _tr._routing_handler = None
    # LogBus：P3c 阶段 3 已 dict 化（_BUSES 按 workflow_id 索引），清注册表所有 bus。
    # （旧版写 LogBus._xxx 落在 _LogBusProxy 代理 instance __dict__、不触达真实 bus，
    # 且污染代理后续 __getattr__ → 跨测试串读。）
    try:
        from supernova_core.logging.log_bus import _BUSES, reset_diagnostic
        for bus in list(_BUSES.values()):
            bus._attached = False
            bus._dispatcher = None
            if bus._drain_task is not None and not bus._drain_task.done():
                bus._drain_task.cancel()
            bus._drain_task = None
            while True:
                try:
                    bus.queue.get_nowait()
                except _queue.Empty:
                    break
        _BUSES.clear()
        # diagnostic 已是进程级单例（2026-08-18 起不在 bus 上），单独重置。
        reset_diagnostic()
    except Exception:  # pragma: no cover - LogBus 未导入的极端情况
        pass
