"""Env-driven concurrency limit shared by whitebox/blackbox scans."""

import logging
import os

from .scan_env import ws_getenv

_DEFAULT = 3
_PER_CALL_TIMEOUT_DEFAULT = 60.0
_CHUNK_MAX_CALLS_DEFAULT = 100
_log = logging.getLogger(__name__)


def get_max_concurrent() -> int:
    """Read SUPERNOVA_MAX_CONCURRENT.

    Returns the env value when it is an int >= 1; otherwise falls back to the
    default (3) and logs a warning. A malformed value must NOT crash a scan.
    """
    raw = os.environ.get("SUPERNOVA_MAX_CONCURRENT")
    if raw is None:
        return _DEFAULT
    try:
        val = int(raw)
    except ValueError:
        _log.warning("SUPERNOVA_MAX_CONCURRENT=%r not an int; falling back to %d", raw, _DEFAULT)
        return _DEFAULT
    if val < 1:
        _log.warning("SUPERNOVA_MAX_CONCURRENT=%d must be >=1; falling back to %d", val, _DEFAULT)
        return _DEFAULT
    return val


def _is_truthy_env(name: str, default: bool) -> bool:
    """读布尔 env: '0'/'false'/'no' → False, 其余非空 → True, 未设 → default。

    经 ws_getenv 支持 per-workspace 覆盖（is_llm_track_enabled / is_gitnexus_llm_enabled）。
    """
    raw = ws_getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() not in {"0", "false", "no", "off"}


def is_llm_track_enabled() -> bool:
    """SUPERNOVA_LLM_TRACK_ENABLED: 关 LLM 轨开关(默认开 True)。

    =0 时只关 inj/xss/ssrf vuln agent(DEGRADABLE_VULN_CLASSES, taint GitNexus
    chain_verdict 主干兜底); pre-recon/recon/authz/auth 的 LLM 全保留(GitNexus
    做不了 authz Vertical/Context + recon 角色模型/工作流, 关了会降安全效果).
    详见 plan smooth-wandering-dolphin + CLAUDE.md §1.
    """
    return _is_truthy_env("SUPERNOVA_LLM_TRACK_ENABLED", default=True)


def is_gitnexus_llm_enabled() -> bool:
    """SUPERNOVA_GITNEXUS_LLM_ENABLED: 是否接通 GitNexus 轨 LLM
    (discover_sinks_llm / analyze_taint_llm / chain_verdict). 默认开.
    关闭 → llm_client 走 raise → 各处降级到纯规则 + is_entry_hint(spec §3.3 边界)."""
    return _is_truthy_env("SUPERNOVA_GITNEXUS_LLM_ENABLED", default=True)


# GN 富化档位开关 SUPERNOVA_GN_ENRICH_MODE（off/light/deep）已于 2026-08-31
# 整键移除：deep 行为常开（light 是升级前旧实现残留、off 从未被真实使用），
# 省 token 出口在 SUPERNOVA_LLM_TRACK_ENABLED / SUPERNOVA_GITNEXUS_LLM_ENABLED。


def endpoint_enrich_enabled() -> bool:
    """SUPERNOVA_ENDPOINT_ENRICH_ENABLED（默认 "1"，经 ws_getenv 支持 per-workspace）：

    全卡接口表富化（spec 2026-08-26-report-generation-agent §5.2）——接口富化
    对两轨全部卡生效（LLM 卡补行号链、GN 卡补接口），关闭时 builder 走确定性
    endpoint 兜底（无行号）。"""
    raw = ws_getenv("SUPERNOVA_ENDPOINT_ENRICH_ENABLED")
    if raw is None:
        return True
    return raw.strip().lower() not in ("0", "false", "no", "off")


def get_chunk_max_calls() -> int:
    """Read SUPERNOVA_CHUNK_MAX_CALLS (chunk 内 suspicious/source call 数上限, spec 2026-07-10).

    跨文件贪心合并后, 一个 chunk 可含多文件多 call; 此值是 call 数软上限 —— 任一 chunk
    超 token_threshold 或 call 数 > 此值即开新 chunk(双上限: token 防 context 爆, call 数
    防 LLM 疲劳漏判 + 失败粒度)。默认 100(kol 631 calls → ~7 chunk 的量级)。

    返回 env 值(int>=1); 未设 / 畸形 / <=0 回退默认(100)并 warning。
    畸形值绝不崩 scan(对齐 get_max_concurrent / get_per_call_timeout 的容错契约)。
    """
    raw = ws_getenv("SUPERNOVA_CHUNK_MAX_CALLS")
    if raw is None:
        return _CHUNK_MAX_CALLS_DEFAULT
    try:
        val = int(raw)
    except ValueError:
        _log.warning("SUPERNOVA_CHUNK_MAX_CALLS=%r not an int; falling back to %d",
                     raw, _CHUNK_MAX_CALLS_DEFAULT)
        return _CHUNK_MAX_CALLS_DEFAULT
    if val < 1:
        _log.warning("SUPERNOVA_CHUNK_MAX_CALLS=%d must be >=1; falling back to %d",
                     val, _CHUNK_MAX_CALLS_DEFAULT)
        return _CHUNK_MAX_CALLS_DEFAULT
    return val


def get_per_call_timeout() -> float:
    """Read SUPERNOVA_LLM_PER_CALL_TIMEOUT (单次 GitNexus 轨 LLM 调用上限秒数).

    discover_sinks_llm / discover_sources_llm / analyze_taint_llm 共用
    map_llm_with_bounds, 每个函数一次 LLM 调用; 超过此值即降级跳过该函数(治本 2,
    防大仓 N 个函数串行累加拖垮 activity 的 start_to_close_timeout)。

    返回 env 值(float>0); 未设 / 畸形 / <=0 回退默认(60s)并 warning。
    畸形值绝不崩 scan(对齐 get_max_concurrent 的容错契约)。

    提高此值(如 180)给单次调用更多时间(含 provider 内部 retry), 代价是大仓
    N 个函数的总耗时上升——需与 activity 的 start_to_close_timeout 平衡。
    """
    raw = ws_getenv("SUPERNOVA_LLM_PER_CALL_TIMEOUT")
    if raw is None:
        return _PER_CALL_TIMEOUT_DEFAULT
    try:
        val = float(raw)
    except ValueError:
        _log.warning(
            "SUPERNOVA_LLM_PER_CALL_TIMEOUT=%r not a float; falling back to %s",
            raw, _PER_CALL_TIMEOUT_DEFAULT)
        return _PER_CALL_TIMEOUT_DEFAULT
    if val <= 0:
        _log.warning(
            "SUPERNOVA_LLM_PER_CALL_TIMEOUT=%s must be >0; falling back to %s",
            val, _PER_CALL_TIMEOUT_DEFAULT)
        return _PER_CALL_TIMEOUT_DEFAULT
    return val


_CHAIN_VERDICT_MAX_AGENTS_DEFAULT = 200


def get_chain_verdict_max_agents() -> int:
    """SUPERNOVA_CHAIN_VERDICT_MAX_AGENTS（spec 2026-08-27 §3 护栏，默认 200）：
    逐条多轮深判的候选链数上限。多轮化后每链一个 agent（max_turns 默认 30），
    大仓候选链 runaway 会 token 爆——超限链不再跑 agent，直接 unadjudicated
    保守进 queue（「没判成 ≠ 非漏洞」，不烧 token、不静默丢）+ warning。
    经 ws_getenv 支持 per-workspace 覆盖。

    返回 env 值(int>=1)；未设 / 畸形 / <=0 回退默认并 warning（不 crash 扫描）。
    """
    raw = ws_getenv("SUPERNOVA_CHAIN_VERDICT_MAX_AGENTS")
    if raw is None:
        return _CHAIN_VERDICT_MAX_AGENTS_DEFAULT
    try:
        val = int(raw)
    except ValueError:
        _log.warning("SUPERNOVA_CHAIN_VERDICT_MAX_AGENTS=%r not an int; "
                     "falling back to %d", raw, _CHAIN_VERDICT_MAX_AGENTS_DEFAULT)
        return _CHAIN_VERDICT_MAX_AGENTS_DEFAULT
    if val < 1:
        _log.warning("SUPERNOVA_CHAIN_VERDICT_MAX_AGENTS=%d must be >=1; "
                     "falling back to %d", val, _CHAIN_VERDICT_MAX_AGENTS_DEFAULT)
        return _CHAIN_VERDICT_MAX_AGENTS_DEFAULT
    return val


_CHAIN_VERDICT_CONCURRENCY_DEFAULT = 4


def get_chain_verdict_concurrency() -> int:
    """SUPERNOVA_CHAIN_VERDICT_CONCURRENCY（默认 4，经 ws_getenv 支持 per-workspace）：

    chain-verdict 逐链并行研判的并发上限——builder 内候选链经
    Semaphore+gather 并行判定（原本逐链串行，链多时拖慢 activity 且顶
    15 分钟窗口）。每链一个多轮 verdict agent（CLI 子进程），默认 4 与
    vuln agents 并行量级相当；链间无共享可变状态（agent_name 唯一 /
    end_agent 锁内记账 / gather 保序），并发安全。

    返回 env 值(int>=1)；未设 / 畸形 / <=0 回退默认并 warning（不 crash 扫描）。
    """
    raw = ws_getenv("SUPERNOVA_CHAIN_VERDICT_CONCURRENCY")
    if raw is None:
        return _CHAIN_VERDICT_CONCURRENCY_DEFAULT
    try:
        val = int(raw)
    except ValueError:
        _log.warning("SUPERNOVA_CHAIN_VERDICT_CONCURRENCY=%r not an int; "
                     "falling back to %d", raw, _CHAIN_VERDICT_CONCURRENCY_DEFAULT)
        return _CHAIN_VERDICT_CONCURRENCY_DEFAULT
    if val < 1:
        _log.warning("SUPERNOVA_CHAIN_VERDICT_CONCURRENCY=%d must be >=1; "
                     "falling back to %d", val, _CHAIN_VERDICT_CONCURRENCY_DEFAULT)
        return _CHAIN_VERDICT_CONCURRENCY_DEFAULT
    return val


_CHAIN_VERDICT_MAX_TURNS_DEFAULT = 30
_GITNEXUS_VERDICT_MAX_TURNS_DEFAULT = 30


def _get_max_turns(key: str, default: int) -> int:
    """verdict 多轮 agent 深度上限的共享读取（ws_getenv per-workspace）。

    两键同族：SUPERNOVA_CHAIN_VERDICT_MAX_TURNS 管 inj/xss/ssrf 判定主链
    （_make_verdict_agent_runner 显式传参），SUPERNOVA_GITNEXUS_VERDICT_MAX_TURNS
    是 run_gitnexus_verdict_agent 不显式传参调用方（authz 深判等）的回落默认。
    2026-09-01 准入工作区覆盖：max_turns 与 CHAIN_VERDICT_CONCURRENCY 同为
    「工作区预算×质量」旋钮——容量铁律「链数÷并发×单链耗时≤窗口」里单链
    耗时由 max_turns 决定，只许并发 per-ws 调、深度全局调则配平只能调一半。

    返回 env 值(int>=1)；未设 / 畸形 / <=0 回退默认并 warning（不 crash 扫描，
    对齐 get_chain_verdict_concurrency 的容错契约——ws 文本框手输容错）。
    """
    raw = ws_getenv(key)
    if raw is None:
        return default
    try:
        val = int(raw)
    except ValueError:
        _log.warning("%s=%r not an int; falling back to %d", key, raw, default)
        return default
    if val < 1:
        _log.warning("%s=%d must be >=1; falling back to %d", key, val, default)
        return default
    return val


def get_chain_verdict_max_turns() -> int:
    """SUPERNOVA_CHAIN_VERDICT_MAX_TURNS（默认 30，经 ws_getenv 支持 per-workspace）：
    chain-verdict 单链多轮深判的轮数上限。"""
    return _get_max_turns("SUPERNOVA_CHAIN_VERDICT_MAX_TURNS",
                          _CHAIN_VERDICT_MAX_TURNS_DEFAULT)


def get_gitnexus_verdict_max_turns() -> int:
    """SUPERNOVA_GITNEXUS_VERDICT_MAX_TURNS（默认 30，经 ws_getenv 支持 per-workspace）：
    run_gitnexus_verdict_agent 的回落默认（authz 深判 / gn-enrich 首轮等不显式
    传 max_turns 的调用方；chain verdict 主链被显式参数遮蔽不读此键）。"""
    return _get_max_turns("SUPERNOVA_GITNEXUS_VERDICT_MAX_TURNS",
                          _GITNEXUS_VERDICT_MAX_TURNS_DEFAULT)


_GN_DISCOVERY_AGENT_TIMEOUT_DEFAULT = 300.0


def get_gn_discovery_agent_timeout() -> float:
    """SUPERNOVA_GN_DISCOVERY_AGENT_TIMEOUT（spec 2026-08-27 §5，默认 300s）：
    discovery 多轮 agent 的单 chunk 超时地板。原 SUPERNOVA_LLM_PER_CALL_TIMEOUT
    （60s）与文件级默认（120s）都是单次档——多轮 agent（自主 Read/Grep）需更高；
    agent 路径取 max(现值, 本值)。经 ws_getenv 支持 per-workspace 覆盖。

    返回 env 值(float>0)；未设 / 畸形 / <=0 回退默认并 warning（不 crash 扫描）。
    """
    raw = ws_getenv("SUPERNOVA_GN_DISCOVERY_AGENT_TIMEOUT")
    if raw is None:
        return _GN_DISCOVERY_AGENT_TIMEOUT_DEFAULT
    try:
        val = float(raw)
    except ValueError:
        _log.warning("SUPERNOVA_GN_DISCOVERY_AGENT_TIMEOUT=%r not a float; "
                     "falling back to %s", raw, _GN_DISCOVERY_AGENT_TIMEOUT_DEFAULT)
        return _GN_DISCOVERY_AGENT_TIMEOUT_DEFAULT
    if val <= 0:
        _log.warning("SUPERNOVA_GN_DISCOVERY_AGENT_TIMEOUT=%s must be >0; "
                     "falling back to %s", val, _GN_DISCOVERY_AGENT_TIMEOUT_DEFAULT)
        return _GN_DISCOVERY_AGENT_TIMEOUT_DEFAULT
    return val


_TRANSIENT_RETRIES_DEFAULT = 1
_TRANSIENT_RETRY_DELAY_DEFAULT = 10.0


def get_transient_retries() -> int:
    """SUPERNOVA_LLM_TRANSIENT_RETRIES（默认 1）：map_llm_with_bounds 对 error 类
    失败（连接错误等瞬时故障）的每 chunk 重试次数。2026-08-29 网关 5s 抖动致
    discovery 补召回整层丢失（NodeGoat-20260828-162655）后引入——timeout 类
    不重试（幂等超时重试只是再超时一遍）。0 = 显式关闭；未设 / 畸形 / <0
    回退默认并 warning（不 crash 扫描）。
    """
    raw = ws_getenv("SUPERNOVA_LLM_TRANSIENT_RETRIES")
    if raw is None:
        return _TRANSIENT_RETRIES_DEFAULT
    try:
        val = int(raw)
    except ValueError:
        _log.warning("SUPERNOVA_LLM_TRANSIENT_RETRIES=%r not an int; "
                     "falling back to %s", raw, _TRANSIENT_RETRIES_DEFAULT)
        return _TRANSIENT_RETRIES_DEFAULT
    if val < 0:
        _log.warning("SUPERNOVA_LLM_TRANSIENT_RETRIES=%s must be >=0; "
                     "falling back to %s", val, _TRANSIENT_RETRIES_DEFAULT)
        return _TRANSIENT_RETRIES_DEFAULT
    return val


def get_transient_retry_delay() -> float:
    """SUPERNOVA_LLM_TRANSIENT_RETRY_DELAY（默认 10s）：瞬时错误重试前的 backoff
    秒数。取 10s 量级盖过典型网关抖动窗口（2026-08-28 实测 5s）；0 = 立即重试
    （测试提速）。未设 / 畸形 / <0 回退默认并 warning（不 crash 扫描）。
    """
    raw = ws_getenv("SUPERNOVA_LLM_TRANSIENT_RETRY_DELAY")
    if raw is None:
        return _TRANSIENT_RETRY_DELAY_DEFAULT
    try:
        val = float(raw)
    except ValueError:
        _log.warning("SUPERNOVA_LLM_TRANSIENT_RETRY_DELAY=%r not a float; "
                     "falling back to %s", raw, _TRANSIENT_RETRY_DELAY_DEFAULT)
        return _TRANSIENT_RETRY_DELAY_DEFAULT
    if val < 0:
        _log.warning("SUPERNOVA_LLM_TRANSIENT_RETRY_DELAY=%s must be >=0; "
                     "falling back to %s", val, _TRANSIENT_RETRY_DELAY_DEFAULT)
        return _TRANSIENT_RETRY_DELAY_DEFAULT
    return val


# ── poc-agent 聚类分片旋钮（2026-09-02 NodeGoat-20260902-045436 根因修复）──
# 一锅端 14 卡 = 90KB prompt + 10万 token 级请求（429 最先被丢）+ 超限截断
# 输出，4 次启动 0 交付；分片对齐 chain-verdict 逐条模式。两键同为工作区
# 「预算×质量」取舍（与 CHAIN_VERDICT_CONCURRENCY 同族），进 SCAN_ENV_KEYS。

_POC_SHARD_MAX_CARDS_DEFAULT = 3
_POC_AGENT_CONCURRENCY_DEFAULT = 3


def get_poc_shard_max_cards() -> int:
    """SUPERNOVA_POC_SHARD_MAX_CARDS（默认 3，经 ws_getenv 支持 per-workspace）：
    poc-agent 按 sink 文件聚类后每片卡数上限——同文件卡共享读码（路由注册/
    handler/middleware 文件级复用），超限同文件裂多片（防「文件级一锅端」回潮，
    NodeGoat XSS session.js 一家 18 卡的现实量级）。大仓单卡验证重可降到 1-2。

    返回 env 值(int>=1)；未设 / 畸形 / <=0 回退默认并 warning（不 crash 扫描，
    对齐 get_chain_verdict_concurrency 的容错契约——ws 文本框手输容错）。
    """
    raw = ws_getenv("SUPERNOVA_POC_SHARD_MAX_CARDS")
    if raw is None:
        return _POC_SHARD_MAX_CARDS_DEFAULT
    try:
        val = int(raw)
    except ValueError:
        _log.warning("SUPERNOVA_POC_SHARD_MAX_CARDS=%r not an int; "
                     "falling back to %d", raw, _POC_SHARD_MAX_CARDS_DEFAULT)
        return _POC_SHARD_MAX_CARDS_DEFAULT
    if val < 1:
        _log.warning("SUPERNOVA_POC_SHARD_MAX_CARDS=%d must be >=1; "
                     "falling back to %d", val, _POC_SHARD_MAX_CARDS_DEFAULT)
        return _POC_SHARD_MAX_CARDS_DEFAULT
    return val


def get_poc_agent_concurrency() -> int:
    """SUPERNOVA_POC_AGENT_CONCURRENCY（默认 3，经 ws_getenv 支持 per-workspace）：
    poc-agent 片间并发上限——**类间+片间共享**（write_agent_poc 是 5 类 gather
    并行，每类再裂 N 片，若各类各持信号量瞬时并发 = 5×N 反而放大 429 暴露面；
    共享一个 scan 级 Semaphore 统一限流，对齐容量直觉）。

    返回 env 值(int>=1)；未设 / 畸形 / <=0 回退默认并 warning（不 crash 扫描）。
    """
    raw = ws_getenv("SUPERNOVA_POC_AGENT_CONCURRENCY")
    if raw is None:
        return _POC_AGENT_CONCURRENCY_DEFAULT
    try:
        val = int(raw)
    except ValueError:
        _log.warning("SUPERNOVA_POC_AGENT_CONCURRENCY=%r not an int; "
                     "falling back to %d", raw, _POC_AGENT_CONCURRENCY_DEFAULT)
        return _POC_AGENT_CONCURRENCY_DEFAULT
    if val < 1:
        _log.warning("SUPERNOVA_POC_AGENT_CONCURRENCY=%d must be >=1; "
                     "falling back to %d", val, _POC_AGENT_CONCURRENCY_DEFAULT)
        return _POC_AGENT_CONCURRENCY_DEFAULT
    return val


# ── 对抗性审查阶段旋钮（spec 2026-09-10 §4.6）──
# 整型解析复用 _get_max_turns（通用 int>=1 env 读取，等价 brief 的 _int_env_or，
# 勿重复定义）；布尔开关复用 _is_truthy_env。

_ADVERSARIAL_REVIEW_CONCURRENCY_DEFAULT = 4
_ADVERSARIAL_REVIEW_MAX_TURNS_DEFAULT = 40
_ADVERSARIAL_REVIEW_SHARD_MAX_DEFAULT = 3
_ADVERSARIAL_REVIEW_MAX_AGENTS_DEFAULT = 50


def is_adversarial_review_enabled() -> bool:
    """SUPERNOVA_ADVERSARIAL_REVIEW_ENABLED（默认开）：白盒合并后对抗审查总开关。
    经 ws_getenv 支持 per-workspace 覆盖。"""
    return _is_truthy_env("SUPERNOVA_ADVERSARIAL_REVIEW_ENABLED", default=True)


def get_adversarial_review_concurrency() -> int:
    """片 agent 并发上限（scan 级共享 Semaphore，类间+片间统一限流防 429 放大）。"""
    return _get_max_turns("SUPERNOVA_ADVERSARIAL_REVIEW_CONCURRENCY",
                          _ADVERSARIAL_REVIEW_CONCURRENCY_DEFAULT)


def get_adversarial_review_max_turns() -> int:
    """片 agent turn 预算（默认 40，对齐 POC 片换算：≤3 卡/片 × ~9 turns/卡 + 余量）。"""
    return _get_max_turns("SUPERNOVA_ADVERSARIAL_REVIEW_MAX_TURNS",
                          _ADVERSARIAL_REVIEW_MAX_TURNS_DEFAULT)


def get_adversarial_review_shard_max_cards() -> int:
    """片大小上限（同 sink 文件超限裂片，对齐 get_poc_shard_max_cards 模式）。"""
    return _get_max_turns("SUPERNOVA_ADVERSARIAL_REVIEW_SHARD_MAX_CARDS",
                          _ADVERSARIAL_REVIEW_SHARD_MAX_DEFAULT)


def get_adversarial_review_max_agents() -> int:
    """预算护栏：超出片数的卡 unreviewed 保守放行（对齐 CHAIN_VERDICT_MAX_AGENTS）。"""
    return _get_max_turns("SUPERNOVA_ADVERSARIAL_REVIEW_MAX_AGENTS",
                          _ADVERSARIAL_REVIEW_MAX_AGENTS_DEFAULT)
