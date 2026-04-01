"""PII 탐지 패턴 테스트"""
from asr.pii import detect_pii, redact_pii, has_pii


class TestDetectPii:
    def test_detect_email(self):
        hits = detect_pii("Contact us at admin@example.com for help")
        assert any(h["type"] == "email" for h in hits)

    def test_detect_phone_kr(self):
        hits = detect_pii("전화번호: 010-1234-5678")
        assert any(h["type"] == "phone" for h in hits)

    def test_detect_phone_intl(self):
        hits = detect_pii("Call +1-555-123-4567")
        assert any(h["type"] == "phone" for h in hits)

    def test_detect_api_key(self):
        hits = detect_pii("api_key=sk-abc123def456ghi789jkl012mno345pqr678")
        assert any(h["type"] == "api_key" for h in hits)

    def test_detect_bearer_token(self):
        hits = detect_pii("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
        assert any(h["type"] == "bearer_token" for h in hits)

    def test_detect_generic_secret(self):
        hits = detect_pii('password = "SuperSecret123!"')
        assert any(h["type"] == "secret" for h in hits)

    def test_no_pii_in_clean_text(self):
        hits = detect_pii("This is a normal sentence about programming.")
        assert len(hits) == 0

    def test_multiple_pii(self):
        text = "Email: test@example.com, Key: sk-abc123def456ghi789jkl012mno345pqr678"
        hits = detect_pii(text)
        types = {h["type"] for h in hits}
        assert "email" in types
        assert "api_key" in types


class TestRedactPii:
    def test_redact_email(self):
        result = redact_pii("Send to admin@example.com please")
        assert "admin@example.com" not in result
        assert "[EMAIL]" in result

    def test_redact_preserves_structure(self):
        result = redact_pii("Name: John, No PII here")
        assert result == "Name: John, No PII here"

    def test_redact_multiple(self):
        text = "Email: a@b.com, Phone: 010-1234-5678"
        result = redact_pii(text)
        assert "a@b.com" not in result
        assert "010-1234-5678" not in result


class TestHasPii:
    def test_has_pii_true(self):
        assert has_pii("email: test@example.com") is True

    def test_has_pii_false(self):
        assert has_pii("no sensitive data here") is False
