"""Additional PII profiles used by the optional HTTP API."""

from __future__ import annotations

import re


_MY_NUMBER_RE = re.compile(r"\b(\d{4})\s?(\d{4})\s?(\d{4})\b")
_MY_NUMBER_CONTEXT_RE = re.compile(
    r"(?:my[\s_-]?number|individual[\s_-]?number|マイナンバー|個人番号)",
    re.IGNORECASE,
)
_JP_PHONE_RE = re.compile(
    r"(?:\+81[-\s]?\d{1,2}[-\s]?\d{4}[-\s]?\d{4})"
    r"|(?:0[1-9]0[-\s]?\d{4}[-\s]?\d{4})"
)
_CN_CITIZEN_ID_RE = re.compile(
    r"\b[1-6]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b"
)
_CN_PHONE_RE = re.compile(r"\b1[3-9]\d{9}\b")
_CREDIT_CARD_RE = re.compile(
    r"\b(?:"
    r"4\d{3}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}"
    r"|5[1-5]\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}"
    r"|3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}"
    r"|6(?:011|5\d{2})[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}"
    r")\b"
)


EXTENDED_PROFILES: dict[str, list[str]] = {
    "jp": ["my_number", "jp_phone"],
    "cn": ["cn_citizen_id", "cn_phone"],
    "payment": ["credit_card"],
}

EXTENDED_REDACTION_MAP: dict[str, str] = {
    "my_number": "[MY_NUMBER]",
    "jp_phone": "[JP_PHONE]",
    "cn_citizen_id": "[CN_ID]",
    "cn_phone": "[CN_PHONE]",
    "credit_card": "[CREDIT_CARD]",
}

_BASE_PRIORITY = {
    "krn": 0,
    "brn": 1,
    "email": 2,
    "bearer_token": 3,
    "api_key": 4,
    "secret": 5,
    "ssn": 6,
    "phone": 7,
    "iban": 8,
    "account": 9,
}
_EXTENDED_PRIORITY = {
    "credit_card": 5,
    "my_number": 6,
    "cn_citizen_id": 7,
    "jp_phone": 10,
    "cn_phone": 11,
}

_installed = False


def _luhn_check(number_str: str, *, min_len: int = 13, max_len: int = 19) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", number_str)]
    if len(digits) < min_len or len(digits) > max_len:
        return False
    checksum = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _has_context(
    text: str,
    start: int,
    end: int,
    pattern: re.Pattern[str],
    *,
    window: int = 60,
) -> bool:
    window_start = max(0, start - window)
    window_end = min(len(text), end + window)
    return bool(pattern.search(text[window_start:window_end]))


def _remove_overlapping_hits(hits: list[dict]) -> list[dict]:
    priority = {**_BASE_PRIORITY, **_EXTENDED_PRIORITY}
    sorted_hits = sorted(
        hits,
        key=lambda hit: (priority.get(hit["type"], 99), -(hit["end"] - hit["start"])),
    )
    kept: list[dict] = []
    for hit in sorted_hits:
        overlaps = any(
            not (hit["end"] <= existing["start"] or hit["start"] >= existing["end"])
            for existing in kept
        )
        if not overlaps:
            kept.append(hit)
    return kept


def _detect_extended(text: str, active_types: frozenset[str] | None) -> list[dict]:
    hits: list[dict] = []

    if active_types is None or "my_number" in active_types:
        for match in _MY_NUMBER_RE.finditer(text):
            digits = re.sub(r"\D", "", match.group())
            if len(digits) == 12 and _has_context(text, match.start(), match.end(), _MY_NUMBER_CONTEXT_RE):
                hits.append(
                    {"type": "my_number", "value": match.group(), "start": match.start(), "end": match.end()}
                )

    if active_types is None or "jp_phone" in active_types:
        for match in _JP_PHONE_RE.finditer(text):
            hits.append(
                {"type": "jp_phone", "value": match.group(), "start": match.start(), "end": match.end()}
            )

    if active_types is None or "cn_citizen_id" in active_types:
        for match in _CN_CITIZEN_ID_RE.finditer(text):
            hits.append(
                {
                    "type": "cn_citizen_id",
                    "value": match.group(),
                    "start": match.start(),
                    "end": match.end(),
                }
            )

    if active_types is None or "cn_phone" in active_types:
        for match in _CN_PHONE_RE.finditer(text):
            hits.append(
                {"type": "cn_phone", "value": match.group(), "start": match.start(), "end": match.end()}
            )

    if active_types is None or "credit_card" in active_types:
        for match in _CREDIT_CARD_RE.finditer(text):
            if _luhn_check(match.group()):
                hits.append(
                    {"type": "credit_card", "value": match.group(), "start": match.start(), "end": match.end()}
                )

    return hits


def install_extended_pii() -> None:
    """Patch the core PII helpers with extra API-oriented profiles."""
    global _installed
    if _installed:
        return
    _installed = True

    import asr.guard
    import asr.pii
    import asr.policies
    import asr.redaction

    asr.pii.PII_PROFILES.update(EXTENDED_PROFILES)
    asr.pii.AVAILABLE_PROFILES = frozenset(asr.pii.PII_PROFILES.keys())
    asr.pii._REDACTION_MAP.update(EXTENDED_REDACTION_MAP)

    original_detect = asr.pii.detect_pii

    def enhanced_detect_pii(text: str, profiles: list[str] | None = None) -> list[dict]:
        hits = original_detect(text, profiles=profiles)
        active_types = asr.pii._get_active_types(profiles)
        extended_hits = _detect_extended(text, active_types)
        if extended_hits:
            hits.extend(extended_hits)
        return _remove_overlapping_hits(hits) if hits else hits

    def enhanced_redact_pii(text: str, profiles: list[str] | None = None) -> str:
        hits = enhanced_detect_pii(text, profiles=profiles)
        if not hits:
            return text
        result = text
        for hit in sorted(hits, key=lambda item: item["start"], reverse=True):
            label = asr.pii._REDACTION_MAP.get(hit["type"], "[REDACTED]")
            result = result[: hit["start"]] + label + result[hit["end"] :]
        return result

    def enhanced_has_pii(text: str, profiles: list[str] | None = None) -> bool:
        return len(enhanced_detect_pii(text, profiles=profiles)) > 0

    asr.pii.detect_pii = enhanced_detect_pii
    asr.pii.redact_pii = enhanced_redact_pii
    asr.pii.has_pii = enhanced_has_pii
    asr.guard.has_pii = enhanced_has_pii
    asr.policies.has_pii = enhanced_has_pii
    asr.redaction.redact_pii = enhanced_redact_pii
