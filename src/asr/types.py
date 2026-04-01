"""공유 dataclass 정의"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Finding:
    """스캐너 탐지 항목"""
    pattern_id: str
    severity: str  # "low" | "medium" | "high"
    description: str
    location: str | None = None


@dataclass(frozen=True)
class ScanResult:
    """스캐너 스캔 결과"""
    score: float  # 0.0 ~ 1.0
    severity: str  # "low" | "medium" | "high"
    findings: list[Finding]
    redacted_excerpt: str
    source_type: str
    scanned_at: str
    source_ref: str | None = None


@dataclass(frozen=True)
class BeforeToolDecision:
    """Guard before_tool 판정 결과"""
    action: str  # "allow" | "warn" | "block"
    reason: str
    policy_id: str
    severity: str  # "low" | "medium" | "high"
    tool_name: str
    redacted_args: dict = field(default_factory=dict)
    capabilities: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class AfterToolDecision:
    """Guard after_tool 판정 결과"""
    action: str  # "allow" | "warn" | "redact_result"
    reason: str
    policy_id: str
    severity: str  # "low" | "medium" | "high"
    tool_name: str
    redacted_result: object | None = None
