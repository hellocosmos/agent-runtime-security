"""PII profile system tests."""
from asr.pii import detect_pii, redact_pii, has_pii, PII_PROFILES, AVAILABLE_PROFILES
import pytest


def test_all_profiles_when_none():
    """When profiles=None, all patterns should be executed."""
    text = "email: a@b.com, ssn: 123-45-6789, iban: DE89 3704 0044 0532 0130 00"
    hits = detect_pii(text)
    types = {h["type"] for h in hits}
    assert "email" in types
    assert "ssn" in types


def test_global_core_only():
    """When global-core profile is selected, email should be detected but SSN should not."""
    text = "email: a@b.com, ssn: 123-45-6789"
    hits = detect_pii(text, profiles=["global-core"])
    types = {h["type"] for h in hits}
    assert "email" in types
    assert "ssn" not in types


def test_us_profile():
    """US profile should only detect SSN."""
    text = "ssn: 123-45-6789, email: a@b.com"
    hits = detect_pii(text, profiles=["us"])
    types = {h["type"] for h in hits}
    assert "ssn" in types
    assert "email" not in types


def test_kr_profile():
    """KR profile should detect Korean resident registration number but not SSN."""
    text = "주민: 901215-1234567, ssn: 123-45-6789"
    hits = detect_pii(text, profiles=["kr"])
    types = {h["type"] for h in hits}
    assert "krn" in types
    assert "ssn" not in types


def test_eu_iban_profile():
    """EU-IBAN profile should detect IBAN."""
    text = "IBAN: DE89 3704 0044 0532 0130 00"
    hits = detect_pii(text, profiles=["eu-iban"])
    types = {h["type"] for h in hits}
    assert "iban" in types


def test_multiple_profiles():
    """Multiple profiles can be selected."""
    text = "email: a@b.com, 주민: 901215-1234567, ssn: 123-45-6789"
    hits = detect_pii(text, profiles=["global-core", "kr"])
    types = {h["type"] for h in hits}
    assert "email" in types
    assert "krn" in types
    assert "ssn" not in types


def test_invalid_profile_raises():
    """Invalid profile name should raise ValueError."""
    with pytest.raises(ValueError, match="Unknown PII profile"):
        detect_pii("test", profiles=["invalid-profile"])


def test_redact_with_profiles():
    """redact_pii should support profiles."""
    text = "email: a@b.com, ssn: 123-45-6789"
    result = redact_pii(text, profiles=["global-core"])
    assert "[EMAIL]" in result
    assert "123-45-6789" in result  # SSN should not be redacted


def test_has_pii_with_profiles():
    """has_pii should support profiles."""
    text = "ssn: 123-45-6789"
    assert has_pii(text, profiles=["us"]) is True
    assert has_pii(text, profiles=["kr"]) is False


def test_ssn_redaction():
    """Verify SSN redaction."""
    text = "My SSN is 123-45-6789"
    result = redact_pii(text, profiles=["us"])
    assert "[SSN]" in result
    assert "123-45-6789" not in result


def test_iban_redaction():
    """Verify IBAN redaction."""
    text = "Account: DE89 3704 0044 0532 0130 00"
    result = redact_pii(text, profiles=["eu-iban"])
    assert "[IBAN]" in result


def test_available_profiles():
    """Verify available profiles list."""
    assert "global-core" in AVAILABLE_PROFILES
    assert "kr" in AVAILABLE_PROFILES
    assert "us" in AVAILABLE_PROFILES
    assert "eu-iban" in AVAILABLE_PROFILES
