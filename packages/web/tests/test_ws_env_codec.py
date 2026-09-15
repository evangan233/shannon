"""env 文本 ↔ WsConfig 字段转换（parse / render）单元测试。

spec: docs/superpowers/specs/2026-08-10-ws-config-env-textarea-design.md
"""
import pytest

from supernova_web.components.ws_env_codec import parse_env_text, render_env_text, mask_credentials
from supernova_web.components.ws_config_store import (
    WsConfig, WsProviderFields, WsGitFields,
)


# ---- parse: 生效字段（存 config.yaml，真 ws 覆盖）----

def test_parse_extracts_ai_provider():
    parsed = parse_env_text("SUPERNOVA_AI_PROVIDER=openai_compatible\n")
    assert parsed.fields["ai_provider"] == "openai_compatible"


def test_parse_extracts_anthropic_credential_to_api_key():
    parsed = parse_env_text("ANTHROPIC_AUTH_TOKEN=sk-secret\n")
    assert parsed.fields["api_key"] == "sk-secret"


def test_parse_extracts_openai_credential_to_api_key():
    parsed = parse_env_text("SUPERNOVA_OPENAI_API_KEY=sk-oai\n")
    assert parsed.fields["api_key"] == "sk-oai"


def test_parse_extracts_base_url_variants():
    assert parse_env_text("ANTHROPIC_BASE_URL=http://a\n").fields["base_url"] == "http://a"
    assert parse_env_text("SUPERNOVA_OPENAI_BASE_URL=http://b\n").fields["base_url"] == "http://b"


def test_parse_extracts_tier_models():
    text = "SUPERNOVA_LARGE_MODEL=GLM-5.2\nSUPERNOVA_SMALL_MODEL=GLM-4.5-Air\n"
    parsed = parse_env_text(text)
    assert parsed.fields["large_model"] == "GLM-5.2"
    assert parsed.fields["small_model"] == "GLM-4.5-Air"


def test_parse_max_turns_as_int():
    assert parse_env_text("SUPERNOVA_MAX_TURNS=42\n").fields["max_turns"] == 42


def test_parse_adaptive_thinking_as_bool():
    assert parse_env_text("SUPERNOVA_ADAPTIVE_THINKING=true\n").fields["adaptive_thinking"] is True
    assert parse_env_text("SUPERNOVA_ADAPTIVE_THINKING=false\n").fields["adaptive_thinking"] is False


def test_parse_git_fields():
    parsed = parse_env_text("GITLAB_USER=bot\nGITLAB_TOKEN=glpat-x\n")
    assert parsed.fields["gitlab_user"] == "bot"
    assert parsed.fields["gitlab_token"] == "glpat-x"


# ---- parse: 注释 / 空行 / 空白 ----

def test_parse_skips_comments_and_blank_lines():
    text = "# a comment\n\nSUPERNOVA_AI_PROVIDER=openai_compatible\n  \n"
    parsed = parse_env_text(text)
    assert parsed.fields == {"ai_provider": "openai_compatible"}


def test_parse_strips_whitespace_around_kv():
    parsed = parse_env_text("  SUPERNOVA_AI_PROVIDER  =  openai_compatible  \n")
    assert parsed.fields["ai_provider"] == "openai_compatible"


# ---- parse: warnings（进程级 ineffective / 未知 unknown）----

def test_parse_collects_ineffective_keys():
    """启动期键（MAX_CONCURRENT）仍 ineffective；扫描期键（LLM_TRACK）进 env 段。"""
    parsed = parse_env_text("SUPERNOVA_MAX_CONCURRENT=8\nSUPERNOVA_LLM_TRACK_ENABLED=0\n")
    assert parsed.ineffective == ["SUPERNOVA_MAX_CONCURRENT"]
    assert parsed.env == {"SUPERNOVA_LLM_TRACK_ENABLED": "0"}
    assert "max_turns" not in parsed.fields  # 不进 fields


def test_parse_scan_env_keys_to_env_section():
    """扫描期开关进 env 段（不再 ineffective）。"""
    text = ("SUPERNOVA_LLM_TRACK_ENABLED=0\n"
            "SUPERNOVA_GITNEXUS_LLM_ENABLED=1\n"
            "SUPERNOVA_BROWSER_ENGINE=agent-browser\n"
            "SUPERNOVA_PRICING_OVERRIDE=p.json\n")
    parsed = parse_env_text(text)
    assert parsed.env == {
        "SUPERNOVA_LLM_TRACK_ENABLED": "0",
        "SUPERNOVA_GITNEXUS_LLM_ENABLED": "1",
        "SUPERNOVA_BROWSER_ENGINE": "agent-browser",
        "SUPERNOVA_PRICING_OVERRIDE": "p.json",
    }
    assert parsed.ineffective == []


def test_parse_collects_unknown_keys_and_pricing_to_env():
    """未知键 → unknown；PRICING_OVERRIDE 扫描期键 → env 段（不再 ineffective）。"""
    parsed = parse_env_text("TOTALLY_UNKNOWN_KEY=x\nSUPERNOVA_PRICING_OVERRIDE=p.json\n")
    assert parsed.unknown == ["TOTALLY_UNKNOWN_KEY"]
    assert parsed.env == {"SUPERNOVA_PRICING_OVERRIDE": "p.json"}
    assert parsed.ineffective == []


def test_parse_empty_text_returns_empty():
    parsed = parse_env_text("")
    assert parsed.fields == {}
    assert parsed.env == {}
    assert parsed.ineffective == []
    assert parsed.unknown == []


def test_render_env_section_sorted():
    """env 段按 key 排序稳定输出（原样 KEY=value）。"""
    cfg = WsConfig(env={"SUPERNOVA_BROWSER_ENGINE": "agent-browser",
                        "SUPERNOVA_LLM_TRACK_ENABLED": "0"})
    text = render_env_text(cfg, ai_provider="openai_compatible")
    assert "SUPERNOVA_BROWSER_ENGINE=agent-browser" in text
    assert "SUPERNOVA_LLM_TRACK_ENABLED=0" in text
    # 按 key 排序：BROWSER_ENGINE 在 LLM_TRACK 之前
    assert text.index("SUPERNOVA_BROWSER_ENGINE=") < text.index("SUPERNOVA_LLM_TRACK_ENABLED=")


def test_render_empty_env_section_omitted():
    cfg = WsConfig()
    text = render_env_text(cfg, ai_provider="openai_compatible")
    assert "LLM_TRACK" not in text
    assert "BROWSER_ENGINE" not in text


# ---- parse: 格式错误 → ValueError（API 层转 422）----

def test_parse_missing_equals_raises():
    with pytest.raises(ValueError):
        parse_env_text("THIS_LINE_HAS_NO_EQUALS\n")


def test_parse_invalid_max_turns_raises():
    with pytest.raises(ValueError):
        parse_env_text("SUPERNOVA_MAX_TURNS=not-a-number\n")


def test_parse_invalid_adaptive_thinking_raises():
    with pytest.raises(ValueError):
        parse_env_text("SUPERNOVA_ADAPTIVE_THINKING=maybe\n")


# ---- render: config → env 文本（按 provider 选 key 名 / 凭据掩码 / 只渲染非 None）----

def test_render_anthropic_basic_fields():
    cfg = WsConfig(provider=WsProviderFields(
        ai_provider="anthropic_api", base_url="http://a", large_model="GLM-5.2",
    ))
    text = render_env_text(cfg, ai_provider="anthropic_api")
    assert "SUPERNOVA_AI_PROVIDER=anthropic_api" in text
    assert "ANTHROPIC_BASE_URL=http://a" in text
    assert "SUPERNOVA_LARGE_MODEL=GLM-5.2" in text


def test_render_openai_uses_openai_key_names():
    cfg = WsConfig(provider=WsProviderFields(
        ai_provider="openai_compatible", base_url="http://b", api_key="sk-oai",
        large_model="gpt-x",
    ))
    text = render_env_text(cfg, ai_provider="openai_compatible")
    assert "SUPERNOVA_OPENAI_BASE_URL=http://b" in text
    assert "SUPERNOVA_OPENAI_API_KEY=••••" in text  # 凭据掩码
    assert "SUPERNOVA_OPENAI_LARGE_MODEL=gpt-x" in text
    assert "sk-oai" not in text


def test_render_anthropic_credential_uses_auth_token_masked():
    cfg = WsConfig(provider=WsProviderFields(ai_provider="anthropic_api", api_key="sk-secret"))
    text = render_env_text(cfg, ai_provider="anthropic_api")
    assert "ANTHROPIC_AUTH_TOKEN=••••" in text
    assert "sk-secret" not in text


def test_render_credential_omitted_when_unset():
    cfg = WsConfig(provider=WsProviderFields(ai_provider="openai_compatible"))
    text = render_env_text(cfg, ai_provider="openai_compatible")
    assert "API_KEY" not in text  # 无凭据 → 不渲染该行


def test_render_only_non_none_fields():
    cfg = WsConfig(provider=WsProviderFields(
        ai_provider="openai_compatible", base_url="http://b",
    ))
    text = render_env_text(cfg, ai_provider="openai_compatible")
    assert "SUPERNOVA_OPENAI_BASE_URL=http://b" in text
    assert "SUPERNOVA_MODEL" not in text     # 未设 → 不渲染
    assert "SMALL_MODEL" not in text


def test_render_max_turns_and_adaptive_thinking():
    cfg = WsConfig(provider=WsProviderFields(
        ai_provider="openai_compatible", max_turns=42, adaptive_thinking=True,
    ))
    text = render_env_text(cfg, ai_provider="openai_compatible")
    assert "SUPERNOVA_MAX_TURNS=42" in text
    assert "SUPERNOVA_ADAPTIVE_THINKING=true" in text


def test_render_git_section_token_masked():
    cfg = WsConfig(
        provider=WsProviderFields(ai_provider="openai_compatible"),
        git=WsGitFields(gitlab_user="bot", gitlab_token="glpat-x"),
    )
    text = render_env_text(cfg, ai_provider="openai_compatible")
    assert "GITLAB_USER=bot" in text
    assert "GITLAB_TOKEN=••••" in text
    assert "glpat-x" not in text


def test_render_empty_config_returns_empty():
    assert render_env_text(WsConfig(), ai_provider="anthropic_api") == ""


# ---- mask_credentials：display 文本打码（其余原样保留）----

def test_mask_credentials_masks_credential_values_only():
    text = ("# --- 引擎 ---\n"
            "SUPERNOVA_AI_PROVIDER=openai_compatible\n"
            "SUPERNOVA_OPENAI_API_KEY=sk-secret\n"
            "SUPERNOVA_OPENAI_BASE_URL=http://x\n"
            "GITLAB_TOKEN=glpat-x\n")
    masked = mask_credentials(text)
    assert "SUPERNOVA_OPENAI_API_KEY=••••" in masked
    assert "GITLAB_TOKEN=••••" in masked
    # 非凭据行与注释行原样保留
    assert "# --- 引擎 ---" in masked
    assert "SUPERNOVA_AI_PROVIDER=openai_compatible" in masked
    assert "SUPERNOVA_OPENAI_BASE_URL=http://x" in masked
    assert "sk-secret" not in masked
    assert "glpat-x" not in masked


def test_mask_credentials_masks_commented_credential_lines():
    """注释掉的凭据行同样打码（用户可能注释留底，明文不能落盘）。"""
    masked = mask_credentials("#SUPERNOVA_OPENAI_API_KEY=sk-real\n")
    assert masked == "#SUPERNOVA_OPENAI_API_KEY=••••\n"


def test_mask_credentials_covers_all_provider_variants():
    masked = mask_credentials(
        "ANTHROPIC_AUTH_TOKEN=sk-a\nANTHROPIC_API_KEY=sk-b\nSUPERNOVA_AUTH_TOKEN=sk-c\n")
    assert masked == ("ANTHROPIC_AUTH_TOKEN=••••\n"
                      "ANTHROPIC_API_KEY=••••\n"
                      "SUPERNOVA_AUTH_TOKEN=••••\n")


def test_mask_credentials_preserves_layout_verbatim():
    """空行、顺序、行尾换行、非凭据内容逐字保留——回显即所存。"""
    text = "A=1\n\n# note\nB=2\n"
    assert mask_credentials(text) == text


def test_mask_credentials_ignores_empty_credential_values():
    assert mask_credentials("SUPERNOVA_OPENAI_API_KEY=\n") == "SUPERNOVA_OPENAI_API_KEY=\n"


def test_parse_chain_verdict_concurrency_to_env_section():
    """chain-verdict 并发数是扫描期键 → 进 env 段（工作区独立配置的准入）。"""
    parsed = parse_env_text("SUPERNOVA_CHAIN_VERDICT_CONCURRENCY=6\n")
    assert parsed.env == {"SUPERNOVA_CHAIN_VERDICT_CONCURRENCY": "6"}
    assert parsed.unknown == []
    assert parsed.ineffective == []


def test_parse_verdict_max_turns_keys_to_env_section():
    """verdict max_turns 两键（2026-09-01 准入，工作区预算×质量取舍）→ env 段。

    CHAIN_VERDICT_MAX_TURNS 管 inj/xss/ssrf 判定主链深度；
    GITNEXUS_VERDICT_MAX_TURNS 是 authz 深判等不传参调用方的回落默认。
    同日裁定注意：CHAIN_VERDICT_MAX_AGENTS（护栏）仍是有意不进白名单的
    运维参数（见下个测试），勿无差别补齐。"""
    parsed = parse_env_text(
        "SUPERNOVA_CHAIN_VERDICT_MAX_TURNS=40\n"
        "SUPERNOVA_GITNEXUS_VERDICT_MAX_TURNS=25\n")
    assert parsed.env == {
        "SUPERNOVA_CHAIN_VERDICT_MAX_TURNS": "40",
        "SUPERNOVA_GITNEXUS_VERDICT_MAX_TURNS": "25",
    }
    assert parsed.unknown == []
    assert parsed.ineffective == []


def test_parse_endpoint_enrich_key_and_removed_gn_enrich_mode():
    """接口富化开关是 per-workspace 语义的扫描期键 → 进 env 段（2026-08-31 裁定）。

    GN 富化档位键 SUPERNOVA_GN_ENRICH_MODE 同日**整键移除**（off/light/deep
    精简为 deep 常开，读取点 concurrency.gn_enrich_mode 已删）→ 工作区 env
    文本写了归 unknown 警告丢弃。运维参数（LLM_TRANSIENT_RETRIES/RETRY_DELAY、
    GN_DISCOVERY_AGENT_TIMEOUT、CHAIN_VERDICT_MAX_AGENTS）按「全局配置走全局
    通道（.env / .env.profiles，ws_getenv 回落 os.environ）」原则**有意**留在
    白名单外——工作区写了归 unknown 警告丢弃，不静默半生效。勿无差别补齐。
    """
    parsed = parse_env_text(
        "SUPERNOVA_GN_ENRICH_MODE=deep\n"
        "SUPERNOVA_ENDPOINT_ENRICH_ENABLED=0\n"
        "SUPERNOVA_LLM_TRANSIENT_RETRIES=3\n"
        "SUPERNOVA_LLM_TRANSIENT_RETRY_DELAY=5\n"
        "SUPERNOVA_GN_DISCOVERY_AGENT_TIMEOUT=600\n"
        "SUPERNOVA_CHAIN_VERDICT_MAX_AGENTS=400\n"
    )
    assert parsed.env == {"SUPERNOVA_ENDPOINT_ENRICH_ENABLED": "0"}
    assert sorted(parsed.unknown) == [
        "SUPERNOVA_CHAIN_VERDICT_MAX_AGENTS",
        "SUPERNOVA_GN_DISCOVERY_AGENT_TIMEOUT",
        "SUPERNOVA_GN_ENRICH_MODE",
        "SUPERNOVA_LLM_TRANSIENT_RETRIES",
        "SUPERNOVA_LLM_TRANSIENT_RETRY_DELAY",
    ]
    assert parsed.ineffective == []


def test_parse_poc_shard_keys_to_env_section():
    """poc-agent 聚类分片两键（2026-09-02 准入，工作区预算×质量取舍）→ env 段。

    SHARD_MAX_CARDS 控每片卡数（大仓单卡验证重可降 1-2）；
    AGENT_CONCURRENCY 是类间+片间共享的片级并发。根因：NodeGoat-20260902-
    045436 一锅端 14 卡 4 次启动 0 交付（429 大请求 + 输出截断）。"""
    parsed = parse_env_text(
        "SUPERNOVA_POC_SHARD_MAX_CARDS=2\n"
        "SUPERNOVA_POC_AGENT_CONCURRENCY=2\n")
    assert parsed.env == {
        "SUPERNOVA_POC_SHARD_MAX_CARDS": "2",
        "SUPERNOVA_POC_AGENT_CONCURRENCY": "2",
    }
    assert parsed.unknown == []
    assert parsed.ineffective == []


def test_parse_adversarial_review_keys_to_env_section():
    """对抗审查四旋钮（2026-09-11 准入，工作区预算×质量取舍）→ env 段。

    ENABLED 是工作区省 token 关整段审查的唯一出口（同 ENDPOINT_ENRICH_ENABLED
    先例）；CONCURRENCY / MAX_TURNS / SHARD_MAX_CARDS 对照同族先例准入
    （CHAIN_VERDICT_CONCURRENCY / *_VERDICT_MAX_TURNS / POC_SHARD_MAX_CARDS）。
    预算护栏 ADVERSARIAL_REVIEW_MAX_AGENTS 对齐 CHAIN_VERDICT_MAX_AGENTS
    有意不进（见下个测试），勿无差别补齐。"""
    parsed = parse_env_text(
        "SUPERNOVA_ADVERSARIAL_REVIEW_ENABLED=0\n"
        "SUPERNOVA_ADVERSARIAL_REVIEW_CONCURRENCY=2\n"
        "SUPERNOVA_ADVERSARIAL_REVIEW_MAX_TURNS=30\n"
        "SUPERNOVA_ADVERSARIAL_REVIEW_SHARD_MAX_CARDS=1\n")
    assert parsed.env == {
        "SUPERNOVA_ADVERSARIAL_REVIEW_ENABLED": "0",
        "SUPERNOVA_ADVERSARIAL_REVIEW_CONCURRENCY": "2",
        "SUPERNOVA_ADVERSARIAL_REVIEW_MAX_TURNS": "30",
        "SUPERNOVA_ADVERSARIAL_REVIEW_SHARD_MAX_CARDS": "1",
    }
    assert parsed.unknown == []
    assert parsed.ineffective == []


def test_parse_adversarial_review_max_agents_stays_global():
    """预算护栏对齐 CHAIN_VERDICT_MAX_AGENTS：有意留全局通道，ws 写了归
    unknown 警告丢弃（不静默半生效）。"""
    parsed = parse_env_text("SUPERNOVA_ADVERSARIAL_REVIEW_MAX_AGENTS=100\n")
    assert parsed.env == {}


def test_parse_ws_scan_concurrency_to_env_section():
    """ws 扫描并发上限（2026-09-15 准入，天生 per-workspace 语义）→ env 段。

    通道不走 ws_getenv 覆盖层（闸门段先于 set_scan_env 注入），而是提交时
    随 PipelineInput.env_overrides 进闸门 descriptor——但准入仍走本白名单
    （ws 写的键必须 known，否则归 unknown 警告丢弃，闸门永远拿不到）。
    值的正负/畸形由 gate_ws_cap_from_overrides 容错（畸形→不限+warning），
    parse 层不做类型校验（对齐其他 SCAN_ENV_KEYS 的 str 原样存储）。"""
    parsed = parse_env_text("SUPERNOVA_WS_SCAN_CONCURRENCY=2\n")
    assert parsed.env == {"SUPERNOVA_WS_SCAN_CONCURRENCY": "2"}
    assert parsed.unknown == []
    assert parsed.ineffective == []
