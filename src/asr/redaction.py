"""Helpers for recursive text extraction and PII redaction."""

from __future__ import annotations

from typing import Any

from asr.pii import redact_pii


def redact_args(args: dict, profiles: list[str] | None = None) -> dict:
    """Redact PII from string values inside an args dictionary.

    Args:
        args: Argument dictionary to inspect.
        profiles: Active PII profiles. ``None`` applies all patterns.
    """
    redacted = {}
    for key, value in args.items():
        if isinstance(value, str):
            redacted[key] = redact_pii(value, profiles=profiles)
        elif isinstance(value, dict):
            redacted[key] = redact_args(value, profiles=profiles)
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


def redact_result(value: Any, profiles: list[str] | None = None) -> Any:
    """Redact PII while preserving the original result type.

    Args:
        value: Value to redact, such as ``str``, ``dict``, ``list``, or ``tuple``.
        profiles: Active PII profiles. ``None`` applies all patterns.
    """
    if isinstance(value, str):
        return redact_pii(value, profiles=profiles)
    if isinstance(value, dict):
        return {key: redact_result(item, profiles=profiles) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(redact_result(item, profiles=profiles) for item in value)
    return value
