"""HTTP-oriented scanner extensions built on top of the core Scanner."""

from __future__ import annotations

import re
from datetime import datetime, timezone

from asr.scanner import Scanner, _SEVERITY_SCORES
from asr.types import Finding, ScanResult


_SQL_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bDROP\s+TABLE\b", re.IGNORECASE),
    re.compile(r"\bUNION\s+(?:ALL\s+)?SELECT\b", re.IGNORECASE),
    re.compile(r"'\s*OR\s+1\s*=\s*1", re.IGNORECASE),
    re.compile(r"(?:WAITFOR\s+DELAY|BENCHMARK\s*\(|SLEEP\s*\()", re.IGNORECASE),
]

_COMMAND_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?:^|[;&|`])\s*(?:rm\s+-rf|curl\s+|wget\s+|bash\s+-[ic]|sh\s+-[ic]|python\s+-c)", re.IGNORECASE),
    re.compile(r"`[^`\n]{0,80}\b(?:cat|curl|wget|bash|sh|python|rm)\b[^`\n]{0,120}`|\$\([^)]{3,}\)", re.IGNORECASE),
]

_PATH_TRAVERSAL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?:\.\./){2,}"),
    re.compile(r"(?:%2e%2e[/\\%]){2,}", re.IGNORECASE),
    re.compile(r"\.\./.*(?:etc/passwd|etc/shadow|\.ssh|\.env)", re.IGNORECASE),
]

_SSRF_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"https?://(?:169\.254\.169\.254|metadata\.google\.internal|169\.254\.170\.2)", re.IGNORECASE),
    re.compile(r"https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1):\d+", re.IGNORECASE),
    re.compile(r"/(?:latest/meta-data|computeMetadata|metadata/instance)", re.IGNORECASE),
]

_CREDENTIAL_HARVEST_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?:dump|show|print|get|read|extract|export)\s+(?:all\s+)?(?:passwords?|credentials?|secrets?|api[_\s]?keys?|tokens?)", re.IGNORECASE),
    re.compile(r"(?:access|read|cat|open)\s+.*(?:\.env|\.ssh/|credentials|secrets\.(?:json|yaml|yml|toml|ini))", re.IGNORECASE),
    re.compile(r"(?:비밀번호|인증\s*정보|시크릿|API\s*키|토큰).{0,10}(?:전부|모두|출력|추출|덤프)", re.IGNORECASE),
]

_WEBHOOK_EXFIL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"https?://(?:[\w-]+\.)?webhook\.site", re.IGNORECASE),
    re.compile(r"https?://(?:[\w-]+\.)?requestbin\.(?:com|net)", re.IGNORECASE),
    re.compile(r"https?://(?:[\w-]+\.)?pipedream\.net", re.IGNORECASE),
    re.compile(r"https?://(?:[\w-]+\.)?ngrok\.io", re.IGNORECASE),
]

_CONSENT_BYPASS_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?:pretend|assume)\s+(?:the\s+user|they)\s+(?:already\s+)?(?:consented|approved|authorized)", re.IGNORECASE),
    re.compile(r"(?:skip|bypass|ignore)\s+(?:the\s+)?(?:consent|confirmation|approval)\s+(?:step|check|prompt)", re.IGNORECASE),
    re.compile(r"(?:동의|승인|확인)\s*(?:절차|단계).{0,10}(?:건너뛰|생략|무시|스킵)", re.IGNORECASE),
]

_BULK_ARCHIVE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?:zip|tar|compress|archive)\s+(?:all|every|entire)\s+(?:data|files?|records?|database|folder)", re.IGNORECASE),
    re.compile(r"(?:export|dump|upload|share)\s+(?:everything|all\s+data|full\s+archive|complete\s+backup)", re.IGNORECASE),
    re.compile(r"(?:전체|모든)\s*(?:데이터|파일|레코드).{0,10}(?:압축|아카이브|백업|내보내기)", re.IGNORECASE),
]


class RuntimeScanner(Scanner):
    """Scanner with extra patterns that are handy for HTTP gateway deployments."""

    def scan(
        self,
        content: str,
        *,
        source_type: str,
        source_ref: str | None = None,
    ) -> ScanResult:
        base_result = super().scan(content, source_type=source_type, source_ref=source_ref)
        findings = list(base_result.findings)
        findings.extend(self._check_sql_injection(content))
        findings.extend(self._check_command_injection(content))
        findings.extend(self._check_path_traversal(content))
        findings.extend(self._check_ssrf_attempt(content))
        findings.extend(self._check_credential_harvest(content))
        findings.extend(self._check_webhook_exfil(content))
        findings.extend(self._check_consent_bypass(content))
        findings.extend(self._check_bulk_archive(content))

        score = min(sum(_SEVERITY_SCORES.get(finding.severity, 0.1) for finding in findings), 1.0)
        if score >= 0.6:
            severity = "high"
        elif score >= 0.3:
            severity = "medium"
        else:
            severity = "low"

        return ScanResult(
            score=round(score, 4),
            severity=severity,
            findings=findings,
            redacted_excerpt=self._build_excerpt(content, findings),
            source_type=source_type,
            scanned_at=datetime.now(timezone.utc).isoformat(),
            source_ref=source_ref,
        )

    @staticmethod
    def _check_sql_injection(content: str) -> list[Finding]:
        for pattern in _SQL_INJECTION_PATTERNS:
            if pattern.search(content):
                return [
                    Finding(
                        pattern_id="sql_injection",
                        severity="high",
                        description="Detected SQL injection pattern",
                        location="content_body",
                    )
                ]
        return []

    @staticmethod
    def _check_command_injection(content: str) -> list[Finding]:
        for pattern in _COMMAND_INJECTION_PATTERNS:
            if pattern.search(content):
                return [
                    Finding(
                        pattern_id="command_injection",
                        severity="high",
                        description="Detected shell command injection pattern",
                        location="content_body",
                    )
                ]
        return []

    @staticmethod
    def _check_path_traversal(content: str) -> list[Finding]:
        for pattern in _PATH_TRAVERSAL_PATTERNS:
            if pattern.search(content):
                return [
                    Finding(
                        pattern_id="path_traversal",
                        severity="high",
                        description="Detected path traversal attempt",
                        location="content_body",
                    )
                ]
        return []

    @staticmethod
    def _check_ssrf_attempt(content: str) -> list[Finding]:
        for pattern in _SSRF_PATTERNS:
            if pattern.search(content):
                return [
                    Finding(
                        pattern_id="ssrf_attempt",
                        severity="high",
                        description="Detected SSRF attempt targeting an internal or metadata endpoint",
                        location="content_body",
                    )
                ]
        return []

    @staticmethod
    def _check_credential_harvest(content: str) -> list[Finding]:
        for pattern in _CREDENTIAL_HARVEST_PATTERNS:
            if pattern.search(content):
                return [
                    Finding(
                        pattern_id="credential_harvest",
                        severity="high",
                        description="Detected credential harvesting request",
                        location="content_body",
                    )
                ]
        return []

    @staticmethod
    def _check_webhook_exfil(content: str) -> list[Finding]:
        for pattern in _WEBHOOK_EXFIL_PATTERNS:
            if pattern.search(content):
                return [
                    Finding(
                        pattern_id="webhook_exfil",
                        severity="high",
                        description="Detected webhook-style exfiltration URL",
                        location="content_body",
                    )
                ]
        return []

    @staticmethod
    def _check_consent_bypass(content: str) -> list[Finding]:
        for pattern in _CONSENT_BYPASS_PATTERNS:
            if pattern.search(content):
                return [
                    Finding(
                        pattern_id="consent_bypass_phrase",
                        severity="medium",
                        description="Detected consent bypass or approval-skipping language",
                        location="content_body",
                    )
                ]
        return []

    @staticmethod
    def _check_bulk_archive(content: str) -> list[Finding]:
        for pattern in _BULK_ARCHIVE_PATTERNS:
            if pattern.search(content):
                return [
                    Finding(
                        pattern_id="bulk_archive_export",
                        severity="medium",
                        description="Detected bulk archive or full data export request",
                        location="content_body",
                    )
                ]
        return []
