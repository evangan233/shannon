"""Temporal activity 心跳保活 + 取消判定（spec 2026-08-28-temporal-native-cancel-design）。

机制链路（temporalio 1.27.2 源码核实 + T1 真 server 实测）：

- workflow ``handle.cancel()`` → server 发 cancel → worker cancel 整个 activity
  asyncio task → ``asyncio.CancelledError`` 抛在业务 await 点（LLM 调用处）。
- ``activity.heartbeat()`` 是取消传递的确定性通道（同步函数、永不抛）；不心跳的
  activity 靠 worker poll 通道收 cancel，时序不稳定（T1 实测竞态）。
- 上下文探测：``activity.info()`` 在非 activity 上下文抛裸 ``RuntimeError``——
  ``except RuntimeError`` 探测（项目惯例，参考 logging/activity_logger.py）。

非 LLM 长 activity（code_index / auth probe / playwright 类）不经
``run_claude_prompt`` → 「跑完当前 activity」窗口仍在，由 web 侧 terminate
保险丝兜底（spec「残留窗口取舍」）。
"""
import asyncio
import contextlib
from collections.abc import AsyncIterator

_DEFAULT_HEARTBEAT_INTERVAL = 10.0


def _in_activity_context() -> bool:
    try:
        from temporalio import activity
        activity.info()
        return True
    except RuntimeError:
        return False


async def _heartbeat_loop(interval: float) -> None:
    from temporalio import activity
    while True:
        await asyncio.sleep(interval)
        try:
            activity.heartbeat()
        except RuntimeError:  # 已退出 activity 上下文（防御）
            return
        except Exception:  # noqa: BLE001 — 心跳失败绝不打断业务
            continue


@contextlib.asynccontextmanager
async def activity_heartbeat(
    interval: float | None = None,
) -> AsyncIterator[None]:
    """temporal activity 心跳保活（取消传递通道）。非 activity 上下文 no-op。

    interval 运行时读 ``_DEFAULT_HEARTBEAT_INTERVAL``（测试可 monkeypatch）。
    exit 只 ``task.cancel()`` 不 await：取消路径上不再挂一个可被二次 cancel
    打断的 await；循环自身吞尽 ``Exception``，CancelledError 自然结束。
    """
    if not _in_activity_context():
        yield
        return
    effective = _DEFAULT_HEARTBEAT_INTERVAL if interval is None else interval
    task = asyncio.create_task(_heartbeat_loop(effective))
    try:
        yield
    finally:
        task.cancel()


def with_activity_heartbeat(fn):
    """activity 实现装饰器：全函数体套心跳泵（含 LLM 前后的非 LLM 段）。

    背景（2026-09-16 worker 重启事故）：长 activity 配了 ``heartbeat_timeout``
    后，server 靠心跳判活——worker 重启后 ~2min 即判死重投、activity 入口的
    ``ensure_audit_session`` 及时恢复心跳文件，web 不再长时间误显「已中断」。
    但 ``run_claude_prompt`` 内置的泵只盖 LLM 调用段，前置/后置（GitNexus
    查询、解析、落盘）无心跳，heartbeat_timeout 会误杀——本装饰器把泵扩到
    全函数体。非 activity 上下文（CLI 直调/单测）泵 no-op，零行为变化。

    须放在 ``@activity.defn`` **之下**（defn 拿到的是 wrapper；functools.wraps
    保留 ``__name__``/签名，defn 的 keyword-only 校验与 activity 命名不受影响）。
    与 ``run_claude_prompt`` 内置泵叠加无害（同为 10s 一拍，RPC 由 throttle 合并）。
    """
    import functools

    @functools.wraps(fn)
    async def wrapper(*args, **kwargs):
        async with activity_heartbeat():
            return await fn(*args, **kwargs)

    return wrapper


def is_cancellation(exc: BaseException) -> bool:
    """异常（含 ``__cause__`` 链）是否为 Temporal 取消——workflow 吞点放行用。

    实测（T1）：cancel 到达时若 await 点是（shielded）activity future，
    CancelledError 注入丢失、future 以 ``ActivityError(cause=CancelledError)``
    结束——业务 ``except Exception`` 会把取消当普通失败吞掉，workflow 继续跑
    （2026-08-28 幽灵扫描事故）。所有 non-fatal 降级吞点必须先
    ``if is_cancellation(exc): raise`` 放行，workflow 才能翻终态 Canceled。
    """
    from temporalio.exceptions import CancelledError as TemporalCancelledError
    seen: set[int] = set()
    cur: BaseException | None = exc
    while cur is not None and id(cur) not in seen:
        if isinstance(cur, TemporalCancelledError):
            return True
        seen.add(id(cur))
        cur = cur.__cause__
    return False
