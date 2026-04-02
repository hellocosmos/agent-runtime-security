"""AuditLogger 테스트"""

import json
from asr.audit import AuditLogger
from asr.types import ScanResult, Finding, BeforeToolDecision, AfterToolDecision


class TestAuditLoggerStdout:
    def test_log_scan_event_to_stdout(self, capsys):
        audit = AuditLogger(output="stdout")
        result = ScanResult(
            score=0.82, severity="high",
            findings=[Finding(pattern_id="css_hidden_text", severity="high", description="CSS 숨김 텍스트")],
            redacted_excerpt="Ignore previous ...", source_type="html",
            source_ref="https://example.com", scanned_at="2026-04-01T12:00:00Z",
        )
        audit.log_scan(result, trace_id="t-001")
        output = capsys.readouterr().out.strip()
        event = json.loads(output)
        assert event["event_type"] == "scan"
        assert event["module"] == "scanner"
        assert event["trace_id"] == "t-001"
        assert event["score"] == 0.82
        assert event["severity"] == "high"
        assert event["findings"] == ["css_hidden_text"]
        assert "event_id" in event
        assert "timestamp" in event

    def test_log_guard_before_event(self, capsys):
        audit = AuditLogger(output="stdout")
        decision = BeforeToolDecision(
            action="block", reason="domain_not_allowed", policy_id="domain_allowlist",
            severity="high", tool_name="http_post",
            redacted_args={"url": "https://evil.com", "body": "[REDACTED]"},
        )
        audit.log_guard(decision, trace_id="t-002")
        output = capsys.readouterr().out.strip()
        event = json.loads(output)
        assert event["event_type"] == "guard_before"
        assert event["module"] == "guard"
        assert event["tool_name"] == "http_post"
        assert event["decision"] == "block"
        assert event["capabilities"] == []
        assert event["redacted_args"]["body"] == "[REDACTED]"

    def test_log_guard_after_event(self, capsys):
        audit = AuditLogger(output="stdout")
        decision = AfterToolDecision(
            action="redact_result", reason="pii_in_result", policy_id="pii_detection",
            severity="medium", tool_name="search", redacted_result="[REDACTED]",
        )
        audit.log_guard(decision, trace_id="t-003")
        output = capsys.readouterr().out.strip()
        event = json.loads(output)
        assert event["event_type"] == "guard_after"
        assert event["redacted_result"] == "[REDACTED]"

    def test_log_error_event(self, capsys):
        audit = AuditLogger(output="stdout")
        audit.log_error(
            error_type="policy_evaluation_error", error_message="Invalid domain format",
            trace_id="t-004", tool_name="http_post", severity="high",
        )
        output = capsys.readouterr().out.strip()
        event = json.loads(output)
        assert event["event_type"] == "error"
        assert event["module"] == "system"
        assert event["error_type"] == "policy_evaluation_error"
        assert event["stack_trace"] is None


class TestAuditLoggerFile:
    def test_log_to_file(self, tmp_path):
        log_file = tmp_path / "audit.jsonl"
        audit = AuditLogger(output=str(log_file))
        result = ScanResult(score=0.1, severity="low", findings=[], redacted_excerpt="",
                           source_type="text", scanned_at="2026-04-01T12:00:00Z")
        audit.log_scan(result, trace_id="t-010")
        lines = log_file.read_text().strip().split("\n")
        assert len(lines) == 1
        assert json.loads(lines[0])["trace_id"] == "t-010"

    def test_multiple_events_append(self, tmp_path):
        log_file = tmp_path / "audit.jsonl"
        audit = AuditLogger(output=str(log_file))
        for i in range(3):
            result = ScanResult(score=0.0, severity="low", findings=[], redacted_excerpt="",
                               source_type="text", scanned_at="2026-04-01T12:00:00Z")
            audit.log_scan(result, trace_id=f"t-{i}")
        lines = log_file.read_text().strip().split("\n")
        assert len(lines) == 3


class TestAuditLoggerCallback:
    def test_log_to_callback(self):
        events = []
        audit = AuditLogger(output=events.append)
        result = ScanResult(score=0.5, severity="medium", findings=[], redacted_excerpt="",
                           source_type="text", scanned_at="2026-04-01T12:00:00Z")
        audit.log_scan(result, trace_id="t-020")
        assert len(events) == 1
        assert events[0]["trace_id"] == "t-020"


class TestAuditLoggerStoreRaw:
    def test_store_raw_false_no_stack_trace(self, capsys):
        audit = AuditLogger(output="stdout", store_raw=False)
        audit.log_error(error_type="test_error", error_message="test", trace_id="t-030",
                       severity="low", stack_trace="Traceback (most recent call last):\n  ...")
        output = capsys.readouterr().out.strip()
        assert json.loads(output)["stack_trace"] is None

    def test_store_raw_true_includes_stack_trace(self, capsys):
        audit = AuditLogger(output="stdout", store_raw=True)
        audit.log_error(error_type="test_error", error_message="test", trace_id="t-031",
                       severity="low", stack_trace="Traceback ...")
        output = capsys.readouterr().out.strip()
        assert json.loads(output)["stack_trace"] == "Traceback ..."


class TestAuditModeFields:
    def test_guard_before_includes_mode_fields(self, capsys):
        audit = AuditLogger(output="stdout")
        decision = BeforeToolDecision(
            action="warn", reason="domain_not_allowed", policy_id="domain_allowlist",
            severity="high", tool_name="http_post",
            original_action="block", mode="warn",
        )
        audit.log_guard(decision, trace_id="t-mode-1")
        event = json.loads(capsys.readouterr().out.strip())
        assert event["decision"] == "warn"  # 기존 필드 유지
        assert event["effective_action"] == "warn"
        assert event["original_action"] == "block"
        assert event["mode"] == "warn"

    def test_guard_after_includes_mode_and_protection_type(self, capsys):
        audit = AuditLogger(output="stdout")
        decision = AfterToolDecision(
            action="redact_result", reason="pii_detected_in_result",
            policy_id="pii_detection", severity="high", tool_name="search",
            redacted_result="[REDACTED]",
            original_action="redact_result", mode="shadow",
        )
        audit.log_guard(decision, trace_id="t-mode-2")
        event = json.loads(capsys.readouterr().out.strip())
        assert event["decision"] == "redact_result"  # 기존 필드 유지
        assert event["effective_action"] == "redact_result"
        assert event["original_action"] == "redact_result"
        assert event["mode"] == "shadow"
        assert event["protection_type"] == "data_protection"

    def test_guard_before_enforce_original_equals_effective(self, capsys):
        audit = AuditLogger(output="stdout")
        decision = BeforeToolDecision(
            action="block", reason="tool_in_blocklist", policy_id="tool_blocklist",
            severity="high", tool_name="rm_rf",
            original_action="block", mode="enforce",
        )
        audit.log_guard(decision, trace_id="t-mode-3")
        event = json.loads(capsys.readouterr().out.strip())
        assert event["effective_action"] == event["original_action"] == "block"
        assert event["mode"] == "enforce"
