"""统一 429 重试（全系统单点）：provider.call 失败为 RateLimitError 时按预算退避重跑。

背景（2026-09-02 NodeGoat-20260902-045436 深挖）：GLM 网关 ServerOverloaded 过载
窗口内 poc-agent-xss 两次 429 直接整类丢弃（XSS 类 0/14 卡 PoC）。全系统对 429 的
处理此前散装三层且互不衔接：SDK 内部 max_retries=1（单请求级、短退避）、chunk 路径
TRANSIENT_RETRIES（map_llm_with_bounds，error 类含 429）、Temporal RetryPolicy
（仅当异常穿透 activity 才生效——poc 的 except Exception 吃掉 429 后一处都不生效）。

本模块把 429 重试收敛到 runner 层单点：``run_claude_prompt`` 是全仓唯一 LLM 漏斗
（executor / GitNexus chunk / verdict agent / poc / enrich / web topology / scripts
全部穿过它），在此重试即全系统统一，无阶段散装。两引擎失败统一表现为
``ClaudeRunResult(success=False, error_code="RateLimitError")``（openai：
``_classify_error`` 的 ratelimiterror 类名匹配；anthropic：ResultMessage
api_error_status=429），故以 result 字段判定、非 try/except。

边界（血泪史约束，docs/scan-time-gates.md §四）：
- **只重 429**：timeout 刻意不重（幂等超时重试只是再超时一遍，曾 stall 4×300s）；
  其余 error_code 一律原样返回。anthropic 异常路径 "rate limit" 文本判 BillingError
  的既有分歧不纳入（余额不足重试无用）。
- **CancelledError 穿透**：本循环不经过 except Exception，cancel 语义优先。
- **SDK 层不动**：``SUPERNOVA_OPENAI_MAX_RETRIES=1`` 保持（曾 3→1 收敛：SDK 对
  timeout 也重试会放大 stall）；SDK 快速短退避先兜一层，失败的到本层慢退避。
- **叠加关系**：chunk 路径 TRANSIENT_RETRIES 与 Temporal RetryPolicy 均不动——
  各层退避充分（10s/20s/40s），总量有界；Temporal 退化为真正持续过载的最后手段。
- **预算计入扫描预算**（SUPERNOVA_SCAN_BUDGET_HOURS，默认 5h，获槽起算）：默认
  2 次 × 指数退避 20s/40s（上限 120s），单 agent 最多 +60s 量级，对扫描预算可
  忽略，又能盖过实测分钟级网关过载窗口（2026-09-02 两次 429 间隔 25min、单窗
  ~2min）。

不覆盖（有意）：credential_validator 裸 httpx 预检（fail-fast 语义）；providers_openai
_lightweight_reparse（call 内部降级路径，异常全吞不抛）。
"""
from __future__ import annotations

import asyncio
import logging
import os
import random
from typing import Awaitable, Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from supernova_core.agents.runner import ClaudeRunResult

logger = logging.getLogger(__name__)

_RETRIES_DEFAULT = 2
_BACKOFF_BASE_DEFAULT = 20.0
_BACKOFF_CAP = 120.0
# jitter 上界比例：防并发 agent 同步退避风暴（多 agent 同刻重试再撞 429）。
_JITTER_MAX_RATIO = 0.25


def get_rate_limit_retries() -> int:
    """SUPERNOVA_RATE_LIMIT_RETRIES（默认 2，0 = 显式关闭）：429 重试次数。

    返回 env 值(int>=0)；未设 / 畸形 / 负数回退默认并 warning（不 crash 扫描，
    对齐 config/concurrency.py 的容错契约）。
    """
    raw = os.environ.get("SUPERNOVA_RATE_LIMIT_RETRIES")
    if raw is None:
        return _RETRIES_DEFAULT
    try:
        val = int(raw)
    except ValueError:
        logger.warning("SUPERNOVA_RATE_LIMIT_RETRIES=%r not an int; "
                       "falling back to %d", raw, _RETRIES_DEFAULT)
        return _RETRIES_DEFAULT
    if val < 0:
        logger.warning("SUPERNOVA_RATE_LIMIT_RETRIES=%d must be >=0; "
                       "falling back to %d", val, _RETRIES_DEFAULT)
        return _RETRIES_DEFAULT
    return val


def get_rate_limit_backoff_base() -> float:
    """SUPERNOVA_RATE_LIMIT_BACKOFF_SECONDS（默认 20s）：429 重试退避基数。

    实际退避 = min(base × 2^attempt, 120s) × (1 + jitter∈[0, 25%])。
    返回 env 值(float>0)；未设 / 畸形 / <=0 回退默认并 warning（不 crash 扫描）。
    """
    raw = os.environ.get("SUPERNOVA_RATE_LIMIT_BACKOFF_SECONDS")
    if raw is None:
        return _BACKOFF_BASE_DEFAULT
    try:
        val = float(raw)
    except ValueError:
        logger.warning("SUPERNOVA_RATE_LIMIT_BACKOFF_SECONDS=%r not a float; "
                       "falling back to %s", raw, _BACKOFF_BASE_DEFAULT)
        return _BACKOFF_BASE_DEFAULT
    if val <= 0:
        logger.warning("SUPERNOVA_RATE_LIMIT_BACKOFF_SECONDS=%s must be >0; "
                       "falling back to %s", val, _BACKOFF_BASE_DEFAULT)
        return _BACKOFF_BASE_DEFAULT
    return val


async def call_with_rate_limit_retry(
    call_fn: Callable[[], Awaitable["ClaudeRunResult"]],
    *,
    retries: int | None = None,
    backoff_base: float | None = None,
) -> "ClaudeRunResult":
    """执行 call_fn，失败为 RateLimitError 时按预算指数退避重跑。

    Args:
        call_fn: 无参协程工厂（每次调用 = 一次完整 provider.call；重试即重跑
            整个 agent run，两引擎行为统一）。CancelledError 由其自然穿透。
        retries: 重试次数上限；None 读 env（默认 2）。测试可传 0 关闭。
        backoff_base: 退避基数秒；None 读 env（默认 20s）。

    Returns:
        ClaudeRunResult: 成功 result，或耗尽重试后的原始失败 result
        （error_code=="RateLimitError" 保留，上层 Temporal/调用方语义不变）。
    """
    if retries is None:
        retries = get_rate_limit_retries()
    if backoff_base is None:
        backoff_base = get_rate_limit_backoff_base()

    attempt = 0
    while True:
        result = await call_fn()
        if result.success or result.error_code != "RateLimitError":
            return result
        if attempt >= retries:
            logger.warning(
                "rate-limit retry exhausted after %d retries (error=%.200s)",
                retries, result.error or "")
            return result
        delay = min(backoff_base * (2 ** attempt), _BACKOFF_CAP)
        delay *= 1.0 + random.uniform(0.0, _JITTER_MAX_RATIO)
        logger.warning(
            "429 rate-limit: retry %d/%d in %.1fs (model=%s, error=%.200s)",
            attempt + 1, retries, delay, result.model or "?",
            result.error or "")
        await asyncio.sleep(delay)
        attempt += 1
