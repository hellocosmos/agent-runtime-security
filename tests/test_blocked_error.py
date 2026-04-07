"""Tests for enhanced BlockedToolError."""
import pytest
from asr.guard import BlockedToolError
from asr.types import BeforeToolDecision


def _make_decision(**overrides) -> BeforeToolDecision:
    defaults = {
        "action": "block",
        "reason": "domain_not_allowed",
        "policy_id": "egress_control",
        "severity": "high",
        "tool_name": "send_email",
        "redacted_args": {},
        "capabilities": ["network_send"],
        "original_action": "block",
        "mode": "enforce",
    }
    defaults.update(overrides)
    return BeforeToolDecision(**defaults)


class TestShortMessage:
    def test_basic_message(self):
        err = BlockedToolError(_make_decision())
        msg = str(err)
        assert "send_email" in msg
        assert "domain_not_allowed" in msg
        assert "egress_control" in msg
        assert "enforce" in msg

    def test_message_includes_target(self):
        err = BlockedToolError(
            _make_decision(),
            context={"target": "evil.com"},
        )
        msg = str(err)
        assert "evil.com" in msg

    def test_message_without_target(self):
        err = BlockedToolError(_make_decision())
        msg = str(err)
        assert "''" not in msg  # no empty target


class TestToDict:
    def test_core_fields_present(self):
        err = BlockedToolError(_make_decision())
        d = err.to_dict()
        assert d["tool_name"] == "send_email"
        assert d["action"] == "block"
        assert d["reason"] == "domain_not_allowed"
        assert d["policy_id"] == "egress_control"
        assert d["mode"] == "enforce"
        assert d["severity"] == "high"
        assert d["capabilities"] == ["network_send"]

    def test_context_in_details(self):
        err = BlockedToolError(
            _make_decision(),
            context={
                "target": "evil.com",
                "allowed_domains": ["mail.internal"],
                "trace_id": "abc-123",
            },
        )
        d = err.to_dict()
        assert "details" in d
        assert d["details"]["target"] == "evil.com"
        assert d["details"]["allowed_domains"] == ["mail.internal"]
        assert d["details"]["trace_id"] == "abc-123"

    def test_context_cannot_overwrite_core(self):
        """details에 tool_name 키가 있어도 core를 덮지 않음."""
        err = BlockedToolError(
            _make_decision(),
            context={"tool_name": "hacked"},
        )
        d = err.to_dict()
        assert d["tool_name"] == "send_email"
        assert d["details"]["tool_name"] == "hacked"


class TestDebugMessage:
    def test_includes_fix_hint(self):
        err = BlockedToolError(
            _make_decision(),
            context={
                "target": "evil.com",
                "allowed_domains": ["mail.internal"],
                "trace_id": "abc-123",
                "fix_hint": "add 'evil.com' to domain_allowlist",
            },
        )
        msg = err.debug_message()
        assert "evil.com" in msg
        assert "mail.internal" in msg
        assert "abc-123" in msg
        assert "add 'evil.com' to domain_allowlist" in msg
        assert "egress_control" in msg

    def test_minimal_context(self):
        err = BlockedToolError(_make_decision())
        msg = err.debug_message()
        assert "send_email" in msg
        assert "domain_not_allowed" in msg
