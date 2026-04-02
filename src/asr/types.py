"""Shared dataclass definitions."""

from __future__ import annotations

from dataclasses import dataclass, field


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
