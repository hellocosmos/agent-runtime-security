"""Shared dataclass definitions."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field


@dataclass(frozen=True)
class PolicyMatch(Mapping[str, str]):
    """Typed policy evaluation result with dict-like compatibility."""

    action: str
    reason: str
    policy_id: str
    severity: str

    _FIELDS = ("action", "reason", "policy_id", "severity")

    def __getitem__(self, key: str) -> str:
        if key not in self._FIELDS:
            raise KeyError(key)
        return getattr(self, key)

    def __iter__(self) -> Iterator[str]:
        return iter(self._FIELDS)

    def __len__(self) -> int:
        return len(self._FIELDS)

    def as_dict(self) -> dict[str, str]:
        """Return the policy match as a plain dictionary."""
        return {field: getattr(self, field) for field in self._FIELDS}


@dataclass(frozen=True)
class Finding:
    """Single scanner finding."""
    pattern_id: str
    severity: str  # "low" | "medium" | "high"
    description: str
    location: str | None = None


@dataclass(frozen=True)
class ScanResult:
    """Result returned by Scanner.scan."""
    score: float  # 0.0 ~ 1.0
    severity: str  # "low" | "medium" | "high"
    findings: list[Finding]
    redacted_excerpt: str
    source_type: str
    scanned_at: str
    source_ref: str | None = None


@dataclass(frozen=True)
class BeforeToolDecision:
    """Decision returned by Guard.before_tool."""
    action: str  # "allow" | "warn" | "block" - effective action after mode handling
    reason: str
    policy_id: str
    severity: str  # "low" | "medium" | "high"
    tool_name: str
    redacted_args: dict = field(default_factory=dict)
    capabilities: list[str] = field(default_factory=list)
    original_action: str = ""  # original policy action before mode handling
    mode: str = "enforce"  # "enforce" | "warn" | "shadow"


@dataclass(frozen=True)
class AfterToolDecision:
    """Decision returned by Guard.after_tool."""
    action: str  # "allow" | "warn" | "redact_result"
    reason: str
    policy_id: str
    severity: str  # "low" | "medium" | "high"
    tool_name: str
    redacted_result: object | None = None
    original_action: str = ""  # original policy action; after_tool is not mode-shifted
    mode: str = "enforce"  # "enforce" | "warn" | "shadow"
