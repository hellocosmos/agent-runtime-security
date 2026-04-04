"""Korean PII pattern tests."""
from asr.pii import detect_pii, redact_pii


def test_detect_krn():
    """Detect Korean resident registration number."""
    text = "주민등록번호: 901215-1234567"
    hits = detect_pii(text)
    krn_hits = [h for h in hits if h["type"] == "krn"]
    assert len(krn_hits) == 1
    assert "901215-1234567" in krn_hits[0]["value"]


def test_detect_brn():
    """Detect business registration number."""
    text = "사업자번호: 123-45-67890"
    hits = detect_pii(text)
    brn_hits = [h for h in hits if h["type"] == "brn"]
    assert len(brn_hits) == 1


def test_detect_account():
    """Detect account number (14-digit format that doesn't overlap with phone)."""
    text = "계좌: 12345-12-3456789"
    hits = detect_pii(text)
    account_hits = [h for h in hits if h["type"] == "account"]
    assert len(account_hits) == 1


def test_redact_korean_pii():
    """Test Korean PII redaction."""
    text = "주민번호 901215-1234567, 사업자 123-45-67890"
    result = redact_pii(text)
    assert "[KRN]" in result
    assert "[BRN]" in result
    assert "901215" not in result
    assert "67890" not in result


def test_krn_invalid_month_not_detected():
    """Invalid month (13th month) should not be detected."""
    text = "901315-1234567"
    hits = detect_pii(text)
    krn_hits = [h for h in hits if h["type"] == "krn"]
    assert len(krn_hits) == 0


def test_short_number_not_account():
    """Numbers with 9 or fewer digits should not be detected as account numbers."""
    text = "123-45-6789"
    hits = detect_pii(text)
    account_hits = [h for h in hits if h["type"] == "account"]
    assert len(account_hits) == 0
