"""Helpers for recursive text extraction and PII redaction."""

from __future__ import annotations

from typing import Any

from asr.pii import redact_pii


def redact_args(args: dict) -> dict:
    """Redact PII from string values inside an args dictionary."""
    redacted = {}
    for key, value in args.items():
        if isinstance(value, str):
            redacted[key] = redact_pii(value)
        elif isinstance(value, dict):
            redacted[key] = redact_args(value)
        else:
            redacted[key] = value
    return redacted


def extract_text(value: Any) -> str:
    """Recursively flatten structured values into text for PII inspection."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return " ".join(extract_text(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return " ".join(extract_text(item) for item in value)
    return str(value) if value is not None else ""


def redact_result(value: Any) -> Any:
    """Redact PII while preserving the original result type."""
    if isinstance(value, str):
        return redact_pii(value)
    if isinstance(value, dict):
        return {key: redact_result(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(redact_result(item) for item in value)
    return value
