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


def detect_pii(text: str) -> list[dict]:
    hits: list[dict] = []
    for match in _EMAIL_RE.finditer(text):
        hits.append({"type": "email", "value": match.group(), "start": match.start(), "end": match.end()})
    for match in _PHONE_RE.finditer(text):
        digits = re.sub(r"\D", "", match.group())
        if len(digits) >= 10:
            hits.append({"type": "phone", "value": match.group(), "start": match.start(), "end": match.end()})
    for match in _API_KEY_RE.finditer(text):
        hits.append({"type": "api_key", "value": match.group(), "start": match.start(), "end": match.end()})
    for match in _BEARER_RE.finditer(text):
        hits.append({"type": "bearer_token", "value": match.group(), "start": match.start(), "end": match.end()})
    for match in _SECRET_RE.finditer(text):
        hits.append({"type": "secret", "value": match.group(), "start": match.start(), "end": match.end()})
    return hits


_REDACTION_MAP = {
    "email": "[EMAIL]", "phone": "[PHONE]", "api_key": "[API_KEY]",
    "bearer_token": "[BEARER_TOKEN]", "secret": "[SECRET]",
}


def redact_pii(text: str) -> str:
    hits = detect_pii(text)
    if not hits:
        return text
    hits_sorted = sorted(hits, key=lambda h: h["start"], reverse=True)
    result = text
    for hit in hits_sorted:
        label = _REDACTION_MAP.get(hit["type"], "[REDACTED]")
        result = result[:hit["start"]] + label + result[hit["end"]:]
    return result


def has_pii(text: str) -> bool:
    return len(detect_pii(text)) > 0
