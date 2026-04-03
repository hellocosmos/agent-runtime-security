"""Tests for the shared dataclasses."""

from asr.types import (
    Finding,
    ScanResult,
    BeforeToolDecision,
    AfterToolDecision,
    PolicyMatch,
)


class TestPolicyMatch:
    def test_attribute_access(self):
        match = PolicyMatch(
            action="block",
            reason="domain_not_allowed",
            policy_id="domain_allowlist",
            severity="high",
        )
        assert match.action == "block"
        assert match.policy_id == "domain_allowlist"

    def test_mapping_compatibility(self):
        match = PolicyMatch(
            action="warn",
            reason="email_destination_not_in_allowlist",
            policy_id="egress_control",
            severity="medium",
        )
        assert match["action"] == "warn"
        assert dict(match) == {
            "action": "warn",
            "reason": "email_destination_not_in_allowlist",
            "policy_id": "egress_control",
            "severity": "medium",
        }


class TestFinding:
    def test_create_finding(self):
        f = Finding(
            pattern_id="css_hidden_text",
            severity="high",
            description="Detected hidden CSS text",
            location="line 42",
        )
        assert f.pattern_id == "css_hidden_text"
        assert f.severity == "high"
        assert f.location == "line 42"

    def test_finding_location_optional(self):
        f = Finding(
            pattern_id="prompt_injection_keywords",
            severity="medium",
            description="Detected prompt injection keywords",
        )
        assert f.location is None


class TestScanResult:
    def test_create_scan_result(self):
        finding = Finding(pattern_id="test", severity="low", description="test")
        result = ScanResult(
            score=0.5, severity="medium", findings=[finding],
            redacted_excerpt="...", source_type="html",
            source_ref="https://example.com", scanned_at="2026-04-01T12:00:00Z",
        )
        assert result.score == 0.5
        assert len(result.findings) == 1
        assert result.source_ref == "https://example.com"

    def test_scan_result_source_ref_optional(self):
        result = ScanResult(
            score=0.0, severity="low", findings=[], redacted_excerpt="",
            source_type="text", scanned_at="2026-04-01T12:00:00Z",
        )
        assert result.source_ref is None


class TestBeforeToolDecision:
    def test_create_before_tool_decision(self):
        d = BeforeToolDecision(
            action="block", reason="domain_not_allowed", policy_id="domain_allowlist",
            severity="high", tool_name="http_post",
            redacted_args={"url": "https://evil.com", "body": "[REDACTED]"},
        )
        assert d.action == "block"
        assert d.policy_id == "domain_allowlist"

    def test_capabilities_default_empty(self):
        d = BeforeToolDecision(
            action="allow", reason="ok", policy_id="none",
            severity="low", tool_name="test",
        )
        assert d.capabilities == []

    def test_original_action_and_mode_fields(self):
        d = BeforeToolDecision(
            action="warn", reason="domain_not_allowed", policy_id="domain_allowlist",
            severity="high", tool_name="http_post",
            original_action="block", mode="warn",
        )
        assert d.action == "warn"
        assert d.original_action == "block"
        assert d.mode == "warn"

    def test_original_action_defaults_empty(self):
        d = BeforeToolDecision(
            action="block", reason="test", policy_id="test",
            severity="high", tool_name="test",
        )
        assert d.original_action == ""
        assert d.mode == "enforce"


class TestAfterToolDecision:
    def test_create_allow(self):
        d = AfterToolDecision(
            action="allow", reason="no_issues", policy_id="none",
            severity="low", tool_name="search",
        )
        assert d.action == "allow"
        assert d.redacted_result is None

    def test_create_redact_result(self):
        d = AfterToolDecision(
            action="redact_result", reason="pii_in_result", policy_id="pii_detection",
            severity="medium", tool_name="search",
            redacted_result="[CONTAINS PII - REDACTED]",
        )
        assert d.action == "redact_result"
        assert d.redacted_result == "[CONTAINS PII - REDACTED]"

    def test_original_action_and_mode_fields(self):
        d = AfterToolDecision(
            action="redact_result", reason="pii_in_result", policy_id="pii_detection",
            severity="high", tool_name="search",
            redacted_result="[REDACTED]",
            original_action="redact_result", mode="shadow",
        )
        assert d.original_action == "redact_result"
        assert d.mode == "shadow"

    def test_original_action_defaults_empty(self):
        d = AfterToolDecision(
            action="allow", reason="test", policy_id="test",
            severity="low", tool_name="test",
        )
        assert d.original_action == ""
        assert d.mode == "enforce"
