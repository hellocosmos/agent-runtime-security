"""PII detection and redaction."""
from __future__ import annotations
import re

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

_PHONE_RE = re.compile(
    r"(?:\+\d{1,3}[\s\-]?)?"
    r"(?:\(?\d{2,4}\)?[\s\-]?)"
    r"\d{3,4}[\s\-]?\d{4}"
)

_API_KEY_RE = re.compile(
    r"(?:sk|pk|api[_\-]?key|apikey|api_secret|secret_key)"
    r"[\s=:\"']*"
    r"([a-zA-Z0-9\-_]{20,})",
    re.IGNORECASE,
)

_BEARER_RE = re.compile(r"[Bb]earer\s+([a-zA-Z0-9\-_\.]{20,})")

_SECRET_RE = re.compile(
    r"(?:password|passwd|secret|token|credential)"
    r"\s*[=:]\s*[\"']?"
    r"([^\s\"']{6,})",
    re.IGNORECASE,
)

# Korean National ID (Resident Registration Number): YYMMDD-NNNNNNN (6-digit birth date + hyphen + 7-digit gender/century indicator)
_KRN_RE = re.compile(
    r"\b(\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01]))\s*[-\u2013]\s*([1-4]\d{6})\b"
)

# Korean Business Registration Number: NNN-NN-NNNNN
_BRN_RE = re.compile(
    r"\b(\d{3})\s*[-\u2013]\s*(\d{2})\s*[-\u2013]\s*(\d{5})\b"
)

# Korean Bank Account Number: 10-16 digit numbers (hyphens optional)
_ACCOUNT_RE = re.compile(
    r"\b\d{3,6}[-\u2013]?\d{2,6}[-\u2013]?\d{2,6}[-\u2013]?\d{1,6}\b"
)

# US Social Security Number (SSN): XXX-XX-XXXX
# First 3 digits cannot be 000/666/9xx, middle 2 digits cannot be 00, last 4 digits cannot be 0000
_SSN_RE = re.compile(
    r"\b(?!000|666|9\d\d)(\d{3})\s*[-\u2013]\s*(?!00)(\d{2})\s*[-\u2013]\s*(?!0000)(\d{4})\b"
)

# EU IBAN: 2-digit country code + 2-digit checksum + up to 30-digit alphanumeric
_IBAN_RE = re.compile(r"\b([A-Z]{2}\d{2})\s*(\d{4}\s*){2,7}\d{1,4}\b")


# PII profile definitions
PII_PROFILES: dict[str, list[str]] = {
    "global-core": ["email", "phone", "api_key", "bearer_token", "secret"],
    "kr": ["krn", "brn", "account"],
    "us": ["ssn"],
    "eu-iban": ["iban"],
}

# All available profile names
AVAILABLE_PROFILES = frozenset(PII_PROFILES.keys())


def _get_active_types(profiles: list[str] | None) -> frozenset[str] | None:
    """Return the set of active PII types for the given profiles. None means all types are active."""
    if profiles is None:
        return None  # None means all types
    active = set()
    for profile in profiles:
        if profile not in PII_PROFILES:
            raise ValueError(
                f"Unknown PII profile: {profile!r}. Available: {sorted(AVAILABLE_PROFILES)}"
            )
        active.update(PII_PROFILES[profile])
    return frozenset(active)


def detect_pii(text: str, profiles: list[str] | None = None) -> list[dict]:
    """Detect PII in text.

    Args:
        text: Text to scan
        profiles: List of profiles to enable. None means run all patterns.

    Returns:
        List of detected PII items (includes type, value, start, end)
    """
    active_types = _get_active_types(profiles)
    hits: list[dict] = []

    if active_types is None or "email" in active_types:
        for match in _EMAIL_RE.finditer(text):
            hits.append({"type": "email", "value": match.group(), "start": match.start(), "end": match.end()})

    if active_types is None or "phone" in active_types:
        for match in _PHONE_RE.finditer(text):
            raw = match.group()
            digits = re.sub(r"\D", "", match.group())
            has_separator = any(ch in raw for ch in (" ", "-", "(", ")", "+"))
            # Contiguous long digit strings (for example order numbers) should
            # not be treated as phone numbers unless the length looks like a
            # real domestic/mobile pattern.
            if has_separator and len(digits) >= 10:
                hits.append({"type": "phone", "value": match.group(), "start": match.start(), "end": match.end()})
            elif not has_separator and 10 <= len(digits) <= 11:
                hits.append({"type": "phone", "value": match.group(), "start": match.start(), "end": match.end()})

    if active_types is None or "api_key" in active_types:
        for match in _API_KEY_RE.finditer(text):
            hits.append({"type": "api_key", "value": match.group(), "start": match.start(), "end": match.end()})

    if active_types is None or "bearer_token" in active_types:
        for match in _BEARER_RE.finditer(text):
            hits.append({"type": "bearer_token", "value": match.group(), "start": match.start(), "end": match.end()})

    if active_types is None or "secret" in active_types:
        for match in _SECRET_RE.finditer(text):
            hits.append({"type": "secret", "value": match.group(), "start": match.start(), "end": match.end()})

    # Korean-specific PII detection
    if active_types is None or "krn" in active_types:
        for match in _KRN_RE.finditer(text):
            hits.append({"type": "krn", "value": match.group(), "start": match.start(), "end": match.end()})

    if active_types is None or "brn" in active_types:
        for match in _BRN_RE.finditer(text):
            hits.append({"type": "brn", "value": match.group(), "start": match.start(), "end": match.end()})

    if active_types is None or "account" in active_types:
        for match in _ACCOUNT_RE.finditer(text):
            # Only consider as account number if total digits are 10-16
            digits = re.sub(r"\D", "", match.group())
            if 10 <= len(digits) <= 16:
                hits.append({"type": "account", "value": match.group(), "start": match.start(), "end": match.end()})

    # US SSN detection
    if active_types is None or "ssn" in active_types:
        for match in _SSN_RE.finditer(text):
            hits.append({"type": "ssn", "value": match.group(), "start": match.start(), "end": match.end()})

    # EU IBAN detection
    if active_types is None or "iban" in active_types:
        for match in _IBAN_RE.finditer(text):
            hits.append({"type": "iban", "value": match.group(), "start": match.start(), "end": match.end()})

    return _remove_overlapping_hits(hits) if hits else hits


_REDACTION_MAP = {
    "email": "[EMAIL]", "phone": "[PHONE]", "api_key": "[API_KEY]",
    "bearer_token": "[BEARER_TOKEN]", "secret": "[SECRET]",
    "krn": "[KRN]", "brn": "[BRN]", "account": "[ACCOUNT]",
    "ssn": "[SSN]", "iban": "[IBAN]",
}


def _remove_overlapping_hits(hits: list[dict]) -> list[dict]:
    """Remove overlapping hits: prioritize more specific types (higher priority first)."""
    # Priority: lower numbers mean more specific
    _PRIORITY = {"krn": 0, "brn": 1, "email": 2, "bearer_token": 3,
                 "api_key": 4, "secret": 5, "ssn": 6, "phone": 7,
                 "iban": 8, "account": 9}
    # Sort by priority, then by length (longer first)
    sorted_hits = sorted(
        hits,
        key=lambda h: (_PRIORITY.get(h["type"], 99), -(h["end"] - h["start"]))
    )
    result: list[dict] = []
    for hit in sorted_hits:
        # Skip if overlaps with already accepted hits
        overlapping = any(
            not (hit["end"] <= kept["start"] or hit["start"] >= kept["end"])
            for kept in result
        )
        if not overlapping:
            result.append(hit)
    return result


def redact_pii(text: str, profiles: list[str] | None = None) -> str:
    """Detect and mask PII in text.

    Args:
        text: Text to mask
        profiles: List of profiles to enable. None means apply all patterns.

    Returns:
        Text with PII masked
    """
    hits = detect_pii(text, profiles=profiles)
    if not hits:
        return text
    # Remove overlapping hits, then sort in reverse to preserve indices
    hits_deduped = _remove_overlapping_hits(hits)
    hits_sorted = sorted(hits_deduped, key=lambda h: h["start"], reverse=True)
    result = text
    for hit in hits_sorted:
        label = _REDACTION_MAP.get(hit["type"], "[REDACTED]")
        result = result[:hit["start"]] + label + result[hit["end"]:]
    return result


def has_pii(text: str, profiles: list[str] | None = None) -> bool:
    """Check if text contains PII.

    Args:
        text: Text to scan
        profiles: List of profiles to enable. None means apply all patterns.

    Returns:
        Whether PII is present
    """
    return len(detect_pii(text, profiles=profiles)) > 0
