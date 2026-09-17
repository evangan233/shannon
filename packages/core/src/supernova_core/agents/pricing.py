"""LLM 成本换算——纯函数，无副作用。

双引擎统一自算（spec §4.5）：claude / openai 引擎都经本模块按 token 用量 × 价目表算 cost，
消除「claude 读 SDK total_cost_usd、openai 自算」的不对称。价目表分层合并（低 → 高）：
内置 ``BUILTIN_PRICING_CNY``（GLM + DeepSeek，默认 CNY）< ``SUPERNOVA_PRICING_OVERRIDE``
指向的 JSON 文件（process 层，per-profile，经 env_loader override=True 天然 per-profile）
< ``SUPERNOVA_GLOBAL_PRICING`` 指向的 JSON 文件（全局层，web 控制台管理，压过 process 层）
< 工作区覆盖层（ws 的 ``SUPERNOVA_PRICING_OVERRIDE``，经 ``scan_env.ws_override_get``，
最高）。各层 override 支持新 schema (``{"currency","models"}``) 与旧 flat schema
（``{model:{...}}``，币种回落 CNY）；币种 = 最高优先非空层的 currency。
**模型级币种（2026-08-28）**：价格对象内可选 ``currency`` 键（仅 CNY/USD）覆盖表级
——混合币种表（GLM CNY + 海外模型 USD）可表达；缺省/非法回落表级；整对象替换时
随价格一起被高层覆盖（高层缺键 → 低层模型级币种丢失，回落表级）。
session 级聚合（metrics_tracker 等）暂按 last-wins 币种,混合币种 session 仅告警。

返回 ``CostAmount{cost, currency}``：cost 是 ``currency`` 币种的金额（单 session 本币直达，
不再 ÷ 汇率）；未知模型回落 ``CostAmount(0.0, currency)``（守「不假估算」）。

usage 参数 duck-typed：只读 .input_tokens / .output_tokens / .cache_read_input_tokens /
.cache_creation_input_tokens（通常是 supernova_core.agents.runner.TokenUsage）。
**input_tokens 须已归一为「不含 cache 命中」**（openai mapper 负责，spec §4.3）——
本模块不再做 input-cached 扣减。
"""
from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass

from supernova_core.config.scan_env import ws_override_get

_log = logging.getLogger(__name__)

# 单位：本币（CNY）/ 百万 token。GLM 2026-07-09 已按智谱官网核对（bigmodel.cn/pricing）；
# DeepSeek 2026-08-20 已按官方定价页核对（api-docs.deepseek.com），2026-08-31 用户核对
# 更新（flash 1/2/0.2、flash-coder 2/4/0.4 单列、pro 24/48/2）。
# glm-4.5-air 取代表档（输入<32K / 输出≥0.2K / 缓存命中 0.16）——pricing 单一档位近似，
# 阶梯精确计费需扩展 pricing.py。
# cache_creation 对 GLM/DeepSeek/openai 协议恒 0（无此概念）。
# -coder 变体默认与基础模型同价（未单列时 lookup 剥 "-coder" 回落基础价）；
# 2026-08-31 起 glm-5.2-coder 单列独立价（16/56/4/0，2× 基础），全名键优先命中。
BUILTIN_PRICING_CNY: dict[str, dict[str, float]] = {
    "glm-5.2": {"input": 8.0, "output": 28.0, "cache_read": 2.0, "cache_creation": 0.0},
    # glm-5.2-coder 单列独立价（2026-08-31 用户核对，2× 基础 8/28/2）
    "glm-5.2-coder": {"input": 16.0, "output": 56.0, "cache_read": 4.0, "cache_creation": 0.0},
    # glm-5.3 与 glm-5.2 同价（2026-08-19 上线未调价；JPMorgan 研报 + 上线报道双源核对）
    "glm-5.3": {"input": 8.0, "output": 28.0, "cache_read": 2.0, "cache_creation": 0.0},
    # glm-5.3-flash（2026-08-28 官网核对；normalize_model 不剥 -flash，键即查询形态）
    "glm-5.3-flash": {"input": 0.8, "output": 2.8, "cache_read": 0.23, "cache_creation": 0.0},
    "glm-4.5-air": {"input": 0.8, "output": 6.0, "cache_read": 0.16, "cache_creation": 0.0},
    # deepseek-v4.1-flash 2/8/0.04/0（2026-09-17 用户核对；推理输出与普通输出同价 8）
    "deepseek-v4.1-flash": {"input": 2.0, "output": 8.0, "cache_read": 0.04, "cache_creation": 0.0},
    # deepseek-v4-pro 24/48/2/0（2026-08-31 用户核对更新，原 profile JSON 旧价 3/6/0.025；
    # 与 .env.profiles.example/deepseek.pricing.json 一致）
    "deepseek-v4-pro": {"input": 24.0, "output": 48.0, "cache_read": 2.0, "cache_creation": 0.0},
    # deepseek-v4-flash 1/2/0.2/0（2026-08-31 用户核对更新，原平时档 1/2/0.02）
    "deepseek-v4-flash": {"input": 1.0, "output": 2.0, "cache_read": 0.2, "cache_creation": 0.0},
    # deepseek-v4-flash-0731 与 flash 同价（默认表显式支持带日期别名）
    "deepseek-v4-flash-0731": {"input": 1.0, "output": 2.0, "cache_read": 0.2, "cache_creation": 0.0},
    # deepseek-v4-flash-coder 单列独立价 2/4/0.4/0（2026-08-31 用户核对，2× 基础）；
    # flash / flash-0731 / flash-coder 均与 profile 示例价表一致
    "deepseek-v4-flash-coder": {"input": 2.0, "output": 4.0, "cache_read": 0.4, "cache_creation": 0.0},
}

# 默认 ¥→$ 汇率；单 session 不再使用（本币直达），仅保留供未来跨 session/跨币种聚合。
USD_CNY_RATE: float = 7.2

_CURRENCY_SYMBOLS = {"CNY": "¥", "USD": "$"}

# 合法币种（表级 / 模型级共用）
_CURRENCIES = ("CNY", "USD")


def _model_currency(prices: dict, table_currency: str) -> str:
    """模型级币种：价格对象内可选 ``currency`` 键，仅认 CNY/USD 字符串；
    缺省 / 非法值回落表级币种。整对象替换时随价格一起被高层覆盖（缺键即丢失）。"""
    c = prices.get("currency")
    return c if isinstance(c, str) and c in _CURRENCIES else table_currency

# 去后缀：[1m] / -YYYYMMDD / --xxx；并折叠 claude 日期快照后缀。
_MODEL_SUFFIX_RE = re.compile(r"\[.*?\]|-\d{8}.*$|--.*$", re.IGNORECASE)

# -coder 变体默认与基础模型同价（2026-08-20 约定；2026-08-31 起可单列覆盖）：
# lookup 先查全名键（含 -coder 独立价），未命中再剥 "-coder" 尾缀回落基础模型，
# deepseek-v4-flash-coder → deepseek-v4-flash。
_CODER_SUFFIX_RE = re.compile(r"-coder$", re.IGNORECASE)

# 别名 → 归一化 key（按需补充）。
_MODEL_ALIASES: dict[str, str] = {}


@dataclass(frozen=True)
class CostAmount:
    """成本 + 币种（cost 是 currency 币种的金额）。"""

    cost: float
    currency: str


def currency_symbol(currency: str) -> str:
    """币种 → 显示符号（CNY→¥，USD→$，未知→$）。"""
    return _CURRENCY_SYMBOLS.get(currency, "$")


def normalize_model(name: str) -> str:
    """模型名归一化：小写 + 去后缀 + 别名映射 + 剥 ``-coder``。

    GLM-5.2[1m] → glm-5.2；claude-sonnet-4-5-20251022 → claude-sonnet-4-5；
    glm-5.2-coder → glm-5.2（容量等「变体≈基础」场景用；价目表查键见
    normalize_pricing_key / _lookup_key——coder 可独立定价，不在此折叠）。
    """
    if not name:
        return ""
    key = name.strip().lower()
    key = _MODEL_SUFFIX_RE.sub("", key).strip()
    key = _CODER_SUFFIX_RE.sub("", key).strip()
    return _MODEL_ALIASES.get(key, key)


def normalize_pricing_key(model: str) -> str:
    """价目表键归一化：小写 + 去快照后缀 + 别名映射，**保留 ``-coder`` 尾缀**。

    与 normalize_model（剥 -coder）相对：价目表支持 -coder 独立定价
    （2026-08-31 起 glm-5.2-coder 单列），查表与 web 层落盘 key 都不折叠
    coder；未单列的 coder 变体由 _lookup_key 回落基础价。
    """
    if not model:
        return ""
    key = model.strip().lower()
    key = _MODEL_SUFFIX_RE.sub("", key).strip()
    return _MODEL_ALIASES.get(key, key)


def _rate() -> float:
    """汇率（单 session 不再使用；保留供未来跨币种聚合）。"""
    raw = os.environ.get("SUPERNOVA_USD_CNY_RATE")
    if raw:
        try:
            v = float(raw)
            if v > 0:
                return v
        except ValueError:
            _log.warning("SUPERNOVA_USD_CNY_RATE=%r 非法，落回默认 %s", raw, USD_CNY_RATE)
    return USD_CNY_RATE


def _load_pricing_file(path: str | None) -> dict:
    """读一份价目表文件；路径空 / 读失败 / 顶层非 dict → {}（容错，该层视为空）。"""
    if not path:
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
        _log.warning("价目表 %r 顶层非 object，忽略该层", path)
    except (OSError, json.JSONDecodeError) as e:
        _log.warning("价目表 %r 解析失败（%s），忽略该层", path, e)
    return {}


def _pricing(pricing_override: str | None = None) -> tuple[dict, str]:
    """分层合并内置表 + 三层 override，返回 (价目表, 币种)。

    优先级（低 → 高，逐层 update，高层同模型压过低层、未覆盖模型继承低层）：
    内置 < process 层（``SUPERNOVA_PRICING_OVERRIDE``，per-profile）< 全局层
    （``SUPERNOVA_GLOBAL_PRICING``，web 控制台）< 工作区层（ws 覆盖的
    ``SUPERNOVA_PRICING_OVERRIDE``）。各层兼容新 schema
    ``{"currency": "CNY"|"USD", "models": {model: {4 档}}}`` 与旧 flat
    ``{model: {input,output,cache_read}}``（币种按 CNY）。

    币种 = 最高优先非空层的 currency（缺省/空串回落 CNY，全部层空 → CNY）。
    兼容不变量：未设 GLOBAL 键且无 ws 覆盖时，输出与拆层前
    （BUILTIN ∪ ws_getenv 单层混合）逐项等价。
    """
    layers = [
        _load_pricing_file(pricing_override or os.environ.get("SUPERNOVA_PRICING_OVERRIDE")),  # process 层
        _load_pricing_file(os.environ.get("SUPERNOVA_GLOBAL_PRICING")),  # 全局层（web 注入）
        _load_pricing_file(ws_override_get("SUPERNOVA_PRICING_OVERRIDE")),  # 工作区层（最高）
    ]
    table = dict(BUILTIN_PRICING_CNY)
    currency = "CNY"
    for layer in layers:  # 低 → 高逐层 update
        if isinstance(layer.get("models"), dict):
            currency = layer.get("currency", "CNY") or "CNY"
            table.update(layer["models"])
        elif layer:  # 旧 flat schema
            currency = "CNY"
            table.update(layer)
    return table, currency


def _price_table() -> dict:
    """向后兼容：仅返回价目表（is_model_priced 用）。"""
    return _pricing()[0]


def _lookup_key(model: str, table: dict) -> str:
    """查表键（两级）：先全名（normalize_pricing_key，保留 ``-coder`` 独立键），
    未命中再剥 ``-coder`` 回落基础模型——未单列的 coder 变体与基础同价。"""
    key = normalize_pricing_key(model)
    if key in table:
        return key
    return _CODER_SUFFIX_RE.sub("", key).strip()


def is_model_priced(model: str) -> bool:
    table = _price_table()
    return _lookup_key(model, table) in table


def compute_cost(model: str, usage, *, pricing_override: str | None = None) -> CostAmount:
    """按价目表 + token 用量算成本。未知模型 → CostAmount(0.0, currency)。

    计费公式（spec §4.4，input_tokens 已归一为不含 cache 命中）::

        cost = ( input*P_in + cache_creation*P_cc + cache_read*P_cr + output*P_out ) / 1e6
    """
    table, currency = _pricing(pricing_override)
    key = _lookup_key(model, table)
    if key not in table:
        _log.warning(
            "模型 %r 不在价目表，cost 记 0（守「不假估算」）；可经 SUPERNOVA_PRICING_OVERRIDE 补充定价",
            key,
        )
        return CostAmount(0.0, currency)
    p = table[key]
    inp = getattr(usage, "input_tokens", 0) or 0
    out = getattr(usage, "output_tokens", 0) or 0
    cache_read = getattr(usage, "cache_read_input_tokens", 0) or 0
    cache_creation = getattr(usage, "cache_creation_input_tokens", 0) or 0
    cost = (
        inp * p["input"]
        + cache_creation * p.get("cache_creation", 0.0)
        + cache_read * p["cache_read"]
        + out * p["output"]
    ) / 1_000_000
    return CostAmount(cost, _model_currency(p, currency))


def compute_cost_usd(model: str, usage, *, pricing_override: str | None = None) -> float:
    """过渡兼容 wrapper：返回 compute_cost().cost（本币值，不再 ÷ 汇率）。

    新代码请用 ``compute_cost`` 拿 (cost, currency)。mapper / provider 切换后本函数可移除。
    """
    return compute_cost(model, usage, pricing_override=pricing_override).cost
