"""env 文本 ↔ WsConfig 字段转换（parse / render）。

env 文本是工作区设置的表现层；config.yaml 仍是存储 SSOT（ws_config_store）。
本模块只做纯转换，不碰 IO / 加密。

spec: docs/superpowers/specs/2026-08-10-ws-config-env-textarea-design.md
"""
from __future__ import annotations

from dataclasses import dataclass, field as dc_field

from supernova_core.config.provider_settings import get_provider_fields


_STR = "str"
_INT = "int"
_BOOL = "bool"

# env key → (config field, 类型)。反向映射，parse 用；key 名唯一，不依赖 provider。
# 同一字段多 env 变体（base_url / api_key / tier model）是因为 env key 是 per-provider 的。
ENV_TO_FIELD: dict[str, tuple[str, str]] = {
    "SUPERNOVA_AI_PROVIDER": ("ai_provider", _STR),
    # base_url（per-provider 变体）
    "ANTHROPIC_BASE_URL": ("base_url", _STR),
    "SUPERNOVA_OPENAI_BASE_URL": ("base_url", _STR),
    "SUPERNOVA_BASE_URL": ("base_url", _STR),
    # api_key（per-provider 凭据变体）
    "ANTHROPIC_AUTH_TOKEN": ("api_key", _STR),
    "ANTHROPIC_API_KEY": ("api_key", _STR),
    "SUPERNOVA_OPENAI_API_KEY": ("api_key", _STR),
    "SUPERNOVA_AUTH_TOKEN": ("api_key", _STR),
    # model
    "SUPERNOVA_MODEL": ("model", _STR),
    # tier models（anthropic / openai 变体）
    "SUPERNOVA_SMALL_MODEL": ("small_model", _STR),
    "SUPERNOVA_MEDIUM_MODEL": ("medium_model", _STR),
    "SUPERNOVA_LARGE_MODEL": ("large_model", _STR),
    "SUPERNOVA_OPENAI_SMALL_MODEL": ("small_model", _STR),
    "SUPERNOVA_OPENAI_MEDIUM_MODEL": ("medium_model", _STR),
    "SUPERNOVA_OPENAI_LARGE_MODEL": ("large_model", _STR),
    # 调参（config.yaml 独有，约定 env key）
    "SUPERNOVA_MAX_TURNS": ("max_turns", _INT),
    "SUPERNOVA_ADAPTIVE_THINKING": ("adaptive_thinking", _BOOL),
    # git
    "GITLAB_USER": ("gitlab_user", _STR),
    "GITLAB_TOKEN": ("gitlab_token", _STR),
}

# 扫描期开关（worker activity 执行期间读、语义 per-workspace 有意义）→ 进 env 段，
# 经 scan_env.ws_getenv 支持 per-workspace 覆盖。新增扫描期配置并把其读取点改用
# ws_getenv 后，把键加进此集合即自动支持 ws 覆盖。
SCAN_ENV_KEYS: frozenset[str] = frozenset({
    "SUPERNOVA_LLM_TRACK_ENABLED",
    "SUPERNOVA_GITNEXUS_LLM_ENABLED",
    "SUPERNOVA_PRICING_OVERRIDE",
    "SUPERNOVA_BROWSER_ENGINE",
    "SUPERNOVA_AGENT_NARRATION_LANG",
    "SUPERNOVA_LLM_PER_CALL_TIMEOUT",
    "SUPERNOVA_CHUNK_MAX_CALLS",
    "SUPERNOVA_MODEL_CONTEXT_OVERRIDE",
    "SUPERNOVA_CHUNK_TOKEN_THRESHOLD",
    "SUPERNOVA_CHAIN_VERDICT_CONCURRENCY",
    "SUPERNOVA_AUTH_VALIDATION_TIMEOUT_SECONDS",
    # 2026-08-31 准入（per-workspace 语义裁定）：接口富化开关是工作区预算×质量
    # 取舍。GN 富化档位键 SUPERNOVA_GN_ENRICH_MODE 同日整键移除（off/light/deep
    # 精简为 deep 常开），工作区写了归 unknown 警告丢弃。同期 ws_getenv 化的
    # 运维参数（LLM_TRANSIENT_RETRIES/RETRY_DELAY、GN_DISCOVERY_AGENT_TIMEOUT、
    # CHAIN_VERDICT_MAX_AGENTS）有意不进——全局配置走全局通道（.env；ws_getenv
    # 回落 os.environ），工作区写了归 unknown 警告丢弃。
    "SUPERNOVA_ENDPOINT_ENRICH_ENABLED",
    # 2026-09-01 准入（per-workspace 预算×质量取舍）：verdict 多轮判定深度
    # 两键，与 CHAIN_VERDICT_CONCURRENCY 同族旋钮——容量铁律「链数÷并发×
    # 单链耗时≤窗口」里单链耗时由 max_turns 决定，只许并发 per-ws 调、深度
    # 全局调则配平只能调一半。CHAIN 管 inj/xss/ssrf 判定主链；GITNEXUS 是
    # authz 深判等不传参调用方的回落默认。护栏键 CHAIN_VERDICT_MAX_AGENTS
    # 仍有意不进（见上条注释）。
    "SUPERNOVA_CHAIN_VERDICT_MAX_TURNS",
    "SUPERNOVA_GITNEXUS_VERDICT_MAX_TURNS",
    # 2026-09-02 准入（per-workspace 预算×质量取舍）：poc-agent 聚类分片
    # 两旋钮，与 CHAIN_VERDICT_CONCURRENCY 同族——NodeGoat-20260902-045436
    # 一锅端 14 卡 4 次启动 0 交付（429 大请求 + 输出截断）的根因修复。
    "SUPERNOVA_POC_SHARD_MAX_CARDS",
    "SUPERNOVA_POC_AGENT_CONCURRENCY",
    # 2026-09-11 准入（对抗性审查阶段，per-workspace 预算×质量取舍）：
    # ENABLED 是工作区主人省 token 关掉整段审查的唯一出口（同
    # ENDPOINT_ENRICH_ENABLED 先例）；CONCURRENCY / MAX_TURNS / SHARD_MAX_CARDS
    # 逐一对照同族先例准入（CHAIN_VERDICT_CONCURRENCY / *_VERDICT_MAX_TURNS /
    # POC_SHARD_MAX_CARDS）——审查片与 POC 片同为「聚类分片 + 片 agent」形态，
    # 容量铁律「片数÷并发×单链耗时≤窗口」三旋钮只许全局调则工作区配不平。
    # 预算护栏键 SUPERNOVA_ADVERSARIAL_REVIEW_MAX_AGENTS 对齐
    # CHAIN_VERDICT_MAX_AGENTS 有意不进（护栏留全局，工作区写了归 unknown
    # 警告丢弃，见上条注释）。
    "SUPERNOVA_ADVERSARIAL_REVIEW_ENABLED",
    "SUPERNOVA_ADVERSARIAL_REVIEW_CONCURRENCY",
    "SUPERNOVA_ADVERSARIAL_REVIEW_MAX_TURNS",
    "SUPERNOVA_ADVERSARIAL_REVIEW_SHARD_MAX_CARDS",
})

# 启动期配置（worker main() 启动时读一次，ws 覆盖不生效）→ 警告不阻塞，不进 fields/env。
INEFFECTIVE_KEYS: frozenset[str] = frozenset({
    "SUPERNOVA_MAX_CONCURRENT",
    "CLAUDE_CODE_MAX_OUTPUT_TOKENS",
})

# 凭据字段（render 时掩码、PUT 时智能保留）
CREDENTIAL_FIELDS: frozenset[str] = frozenset({"api_key", "gitlab_token"})

# 凭据字段对应的全部 env key 变体（mask_credentials 用，含 per-provider 名）。
CREDENTIAL_ENV_KEYS: frozenset[str] = frozenset(
    key for key, (fld, _) in ENV_TO_FIELD.items() if fld in CREDENTIAL_FIELDS
)


def mask_credentials(text: str) -> str:
    """把凭据 key 行的值替换为掩码，其余内容原样保留（含注释 / 空行 / 顺序）。

    display 文本 = 用户提交的 env 文本经此函数处理后的版本：GET/PUT 直接回显它，
    保证「保存什么就看到什么」；唯一改动是凭据值打码，确保 config.yaml 不落明文。
    注释行同样打码（用户可能把真实凭据注释掉留底，不能让明文残留在盘上）。
    """
    out: list[str] = []
    for line in text.split("\n"):
        body = line.lstrip()
        if body.startswith("#"):
            body = body[1:].lstrip()
        key, eq, value = body.partition("=")
        if eq and key.strip() in CREDENTIAL_ENV_KEYS and value.strip():
            out.append(f"{line[: line.index(body)]}{key}={MASKED}")
        else:
            out.append(line)
    return "\n".join(out)


@dataclass
class ParsedEnv:
    """parse_env_text 的结果。

    fields: config 字段 → 强类型值（仅含文本里出现的生效字段）。
    env: 扫描期 env 覆盖 → 原始 str（KEY→value，存 config.yaml 的 env 段）。
    ineffective: 启动期 key（警告，ws 覆盖不生效，不存 config）。
    unknown: 未知 key（警告，可能拼写错误）。
    """
    fields: dict[str, str | int | bool] = dc_field(default_factory=dict)
    env: dict[str, str] = dc_field(default_factory=dict)
    ineffective: list[str] = dc_field(default_factory=list)
    unknown: list[str] = dc_field(default_factory=list)


def _convert(value: str, kind: str, key: str) -> str | int | bool:
    if kind == _INT:
        try:
            return int(value)
        except ValueError:
            raise ValueError(f"invalid int for {key}: {value!r}")
    if kind == _BOOL:
        low = value.lower()
        if low in ("true", "1"):
            return True
        if low in ("false", "0"):
            return False
        raise ValueError(f"invalid bool for {key}: {value!r}")
    return value


def parse_env_text(text: str) -> ParsedEnv:
    """把 env 文本（KEY=value）解析成 config 字段 + warnings。

    Raises:
        ValueError: 某行无 '='，或 int/bool 字段值非法（API 层转 422）。
    """
    fields: dict[str, str | int | bool] = {}
    env: dict[str, str] = {}
    ineffective: list[str] = []
    unknown: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"invalid env line (no '='): {raw_line!r}")
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if key in ENV_TO_FIELD:
            fld, kind = ENV_TO_FIELD[key]
            fields[fld] = _convert(value, kind, key)
        elif key in SCAN_ENV_KEYS:
            env[key] = value
        elif key in INEFFECTIVE_KEYS:
            ineffective.append(key)
        else:
            unknown.append(key)
    return ParsedEnv(fields=fields, env=env, ineffective=ineffective, unknown=unknown)


# ---- render: WsConfig → env 文本 ----

MASKED = "••••"

# provider 段渲染顺序（git 段单独处理，置末）
_RENDER_ORDER_PROVIDER = [
    "ai_provider", "base_url", "api_key", "model",
    "small_model", "medium_model", "large_model",
    "max_turns", "adaptive_thinking",
]

# 约定 env key（无对应 ProviderFields 属性，单独列）
_CONST_ENV_NAME = {
    "ai_provider": "SUPERNOVA_AI_PROVIDER",
    "max_turns": "SUPERNOVA_MAX_TURNS",
    "adaptive_thinking": "SUPERNOVA_ADAPTIVE_THINKING",
    "gitlab_user": "GITLAB_USER",
    "gitlab_token": "GITLAB_TOKEN",
}


def _env_name_for(field_name: str, pf) -> str | None:
    """config field → 该 provider 的 env key 名；None 表示 provider 不读此字段。"""
    if field_name in _CONST_ENV_NAME:
        return _CONST_ENV_NAME[field_name]
    if field_name == "api_key":  # 凭据：优先 auth_token（anthropic），回落 api_key
        return pf.auth_token or pf.api_key
    # base_url / model / small_model / medium_model / large_model：取 ProviderFields 同名属性
    return getattr(pf, field_name, None)


def render_env_text(cfg, ai_provider: str = "anthropic_api") -> str:
    """把 WsConfig 渲染成 env 文本（凭据掩码 ••••；仅渲染非 None 字段）。

    ai_provider 决定 env key 名模板（anthropic→ANTHROPIC_*，openai→SUPERNOVA_OPENAI_*）。
    调用方负责传 ws ?? 全局 ?? 默认 的 ai_provider。
    """
    pf = get_provider_fields(ai_provider) or get_provider_fields("anthropic_api")
    lines: list[str] = []
    for fld in _RENDER_ORDER_PROVIDER:
        val = getattr(cfg.provider, fld, None)
        if val is None:
            continue
        env_name = _env_name_for(fld, pf)
        if env_name is None:
            continue
        if fld in CREDENTIAL_FIELDS:
            lines.append(f"{env_name}={MASKED}")
        elif isinstance(val, bool):  # bool 先于 int（bool 是 int 子类）
            lines.append(f"{env_name}={'true' if val else 'false'}")
        else:
            lines.append(f"{env_name}={val}")
    g = cfg.git
    if g.gitlab_user is not None:
        lines.append(f"GITLAB_USER={g.gitlab_user}")
    if g.gitlab_token is not None:
        lines.append(f"GITLAB_TOKEN={MASKED}")
    # env 段（扫描期 per-workspace 覆盖，原样 KEY=value，按 key 排序稳定输出）。
    for key in sorted(cfg.env):
        lines.append(f"{key}={cfg.env[key]}")
    return "\n".join(lines) + ("\n" if lines else "")
