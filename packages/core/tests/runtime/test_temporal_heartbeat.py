"""T2：activity_heartbeat helper 与 is_cancellation 单测（monkeypatch temporalio.activity）。

机制验证（真 server）在 test_temporal_cancel_propagation.py（T1）；本文件只测
helper 自身行为：非 activity 上下文 no-op / 周期心跳 / 取消回收 / 心跳异常不外溢，
以及 is_cancellation 的 cause 链判定。
"""
import asyncio

import pytest
from temporalio.exceptions import ActivityError, CancelledError as TemporalCancelledError

from supernova_core.runtime.temporal_heartbeat import (
    activity_heartbeat, is_cancellation,
)


def _in_activity(monkeypatch, heartbeat=None):
    """把 temporalio.activity 探测为「activity 上下文内」，heartbeat 可替换。"""
    import temporalio.activity as tio_activity

    def _info():
        return object()  # 不抛 RuntimeError 即视为在上下文内

    monkeypatch.setattr(tio_activity, "info", _info)
    if heartbeat is not None:
        monkeypatch.setattr(tio_activity, "heartbeat", heartbeat)


async def test_noop_outside_activity_context(monkeypatch):
    """非 activity 上下文（info 抛 RuntimeError）：不起心跳 task，零调用。"""
    import temporalio.activity as tio_activity

    def _raise():
        raise RuntimeError("Not in activity context")

    monkeypatch.setattr(tio_activity, "info", _raise)
    calls = []
    monkeypatch.setattr(tio_activity, "heartbeat", lambda *a: calls.append(a))
    async with activity_heartbeat(interval=0.01):
        await asyncio.sleep(0.05)
    assert calls == []


async def test_periodic_heartbeat_while_body_runs(monkeypatch):
    """activity 上下文：body 执行期间周期心跳（无参调用），退出即停。"""
    calls = []
    _in_activity(monkeypatch, heartbeat=lambda *a: calls.append(a))
    async with activity_heartbeat(interval=0.02):
        await asyncio.sleep(0.1)  # ~5 个周期
    n_at_exit = len(calls)
    assert n_at_exit >= 3, f"心跳次数不足: {n_at_exit}"
    await asyncio.sleep(0.06)  # 3 个周期，验证已停
    assert len(calls) == n_at_exit, "退出后心跳应已停止"


async def test_helper_collected_on_body_cancel(monkeypatch):
    """body 被 cancel（模拟 SDK cancel activity task）：CancelledError 照穿。"""
    calls = []
    _in_activity(monkeypatch, heartbeat=lambda *a: calls.append(a))
    with pytest.raises(asyncio.CancelledError):
        async with activity_heartbeat(interval=0.01):
            # 模拟 SDK cancel activity task：当前 await 点被打断
            asyncio.current_task().cancel()
            await asyncio.sleep(10)
    await asyncio.sleep(0.05)
    n = len(calls)
    await asyncio.sleep(0.05)
    assert len(calls) == n, "body 取消后 helper task 应被回收不再心跳"


async def test_heartbeat_exception_does_not_leak(monkeypatch):
    """heartbeat 抛异常：循环继续，不打断 body。"""
    calls = []
    def _flaky():
        calls.append(1)
        raise ValueError("rpc glitch")
    _in_activity(monkeypatch, heartbeat=_flaky)
    async with activity_heartbeat(interval=0.02):
        await asyncio.sleep(0.08)  # ≥3 次抛错
    assert len(calls) >= 3, "心跳失败后循环应继续"


async def test_decorator_pumps_heartbeat_across_whole_body(monkeypatch):
    """with_activity_heartbeat：activity 上下文内全函数体周期心跳，结果透传。"""
    from supernova_core.runtime import temporal_heartbeat as th

    calls = []
    _in_activity(monkeypatch, heartbeat=lambda *a: calls.append(a))
    monkeypatch.setattr(th, "_DEFAULT_HEARTBEAT_INTERVAL", 0.02)  # 装饰器用默认间隔

    @th.with_activity_heartbeat
    async def body(x, *, y=None):
        await asyncio.sleep(0.1)  # 覆盖 ~5 个泵周期
        return (x, y)

    assert await body(1, y=2) == (1, 2)
    assert len(calls) >= 3, f"函数体期间心跳次数不足: {len(calls)}"


async def test_decorator_noop_outside_activity_context(monkeypatch):
    """CLI 直调/单测（非 activity 上下文）：装饰器零行为变化（不起泵不心跳）。"""
    import temporalio.activity as tio_activity
    from supernova_core.runtime.temporal_heartbeat import with_activity_heartbeat

    def _raise():
        raise RuntimeError("Not in activity context")

    monkeypatch.setattr(tio_activity, "info", _raise)
    calls = []
    monkeypatch.setattr(tio_activity, "heartbeat", lambda *a: calls.append(a))

    @with_activity_heartbeat
    async def body():
        return "done"

    assert await body() == "done"
    assert calls == []


def test_decorator_preserves_name_and_signature():
    """functools.wraps：__name__/签名保留——@activity.defn 命名与 keyword-only
    校验（inspect.signature 跟随 __wrapped__）不受包装影响。"""
    import functools
    import inspect

    from supernova_core.runtime.temporal_heartbeat import with_activity_heartbeat

    @with_activity_heartbeat
    async def probe(a, b=1, *, c):
        return a

    assert probe.__name__ == "probe"
    params = inspect.signature(probe).parameters
    assert list(params) == ["a", "b", "c"]
    assert params["c"].kind is inspect.Parameter.KEYWORD_ONLY


def test_decorator_stacks_with_activity_defn():
    """装饰顺序契约：@activity.defn 在上、@with_activity_heartbeat 在下——
    defn 拿到 wrapper 且 activity 命名/定义照常（runner 注册靠它）。"""
    from temporalio import activity as tio_activity

    from supernova_core.runtime.temporal_heartbeat import with_activity_heartbeat

    @tio_activity.defn
    @with_activity_heartbeat
    async def wrapped_probe():
        return 42

    definition = getattr(wrapped_probe, "__temporal_activity_definition")
    assert definition.name == "wrapped_probe"
    assert asyncio.iscoroutinefunction(wrapped_probe)


def test_is_cancellation_direct_and_chain():
    """is_cancellation：直接 CancelledError / ActivityError(cause=CancelledError) 判真。"""
    assert is_cancellation(TemporalCancelledError())
    act = ActivityError(
        "a cancelled", scheduled_event_id=0, started_event_id=0,
        identity="test", activity_type="probe", activity_id="1",
        retry_state=None,
    )
    act.__cause__ = TemporalCancelledError()
    assert is_cancellation(act)
    assert not is_cancellation(ValueError("plain"))
    plain_chain = ValueError("outer")
    plain_chain.__cause__ = RuntimeError("inner")
    assert not is_cancellation(plain_chain)
