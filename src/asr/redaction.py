"""Helpers for recursive text extraction and PII redaction."""

from __future__ import annotations

from typing import Any

from asr.pii import redact_pii


def redact_args(args: dict, profiles: list[str] | None = None) -> dict:
    """args 딕셔너리 내 문자열 값에서 PII를 마스킹한다.

    Args:
        args: 검사할 인수 딕셔너리
        profiles: 활성화할 PII 프로필 목록. None이면 모든 패턴 적용.
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
    """구조화된 값을 재귀적으로 평탄화하여 PII 검사용 텍스트로 반환한다."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return " ".join(extract_text(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return " ".join(extract_text(item) for item in value)
    return str(value) if value is not None else ""


def redact_result(value: Any, profiles: list[str] | None = None) -> Any:
    """원래 결과 타입을 보존하면서 PII를 마스킹한다.

    Args:
        value: 마스킹할 값 (str, dict, list, tuple 또는 기타)
        profiles: 활성화할 PII 프로필 목록. None이면 모든 패턴 적용.
    """
    if isinstance(value, str):
        return redact_pii(value, profiles=profiles)
    if isinstance(value, dict):
        return {key: redact_result(item, profiles=profiles) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(redact_result(item, profiles=profiles) for item in value)
    return value
