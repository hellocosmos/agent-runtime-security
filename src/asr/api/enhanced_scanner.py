"""API-only scanner extension with 32 total detection patterns.

This scanner extends the SDK baseline with advanced patterns exposed through
the HTTP API layer: unsafe tool use, data exfiltration, and hidden payload
detection.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from asr.scanner import Scanner, _SEVERITY_SCORES, _VALID_SOURCE_TYPES
from asr.types import Finding, ScanResult


# ──────────────────────────────────────────────────────────────
# 12. SQL Injection: trigger only when actual injection indicators appear
#     Benign standalone DML such as DELETE FROM or INSERT INTO is allowed
# ──────────────────────────────────────────────────────────────
_SQL_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    # Destructive DDL (always risky)
    re.compile(
        r"\b(?:DROP\s+TABLE|DROP\s+DATABASE|TRUNCATE\s+TABLE)\b",
        re.IGNORECASE,
    ),
    # Injection technique: UNION SELECT
    re.compile(
        r"\b(?:UNION\s+(?:ALL\s+)?SELECT)\b",
        re.IGNORECASE,
    ),
    # Injection technique: tautology / string escape
    re.compile(
        r"(?:'\s*(?:OR|AND)\s+['\d].*?[=<>])|(?:'\s*OR\s+1\s*=\s*1)|(?:'\s*=\s*')",
        re.IGNORECASE,
    ),
    # Injection technique: stacked queries with comments or semicolons
    re.compile(
        r";\s*(?:DROP|DELETE|INSERT|UPDATE|EXEC)\b",
        re.IGNORECASE,
    ),
    # Time-based injection
    re.compile(
        r"(?:WAITFOR\s+DELAY)|(?:BENCHMARK\s*\()|(?:SLEEP\s*\()",
        re.IGNORECASE,
    ),
]

# ──────────────────────────────────────────────────────────────
# 13. NoSQL Injection: only in JSON/object contexts
#     Allow documentation that merely explains operators like $gt
# ──────────────────────────────────────────────────────────────
_NOSQL_INJECTION_RE = re.compile(
    r'[{:]\s*["\']?\$(?:gt|gte|lt|lte|ne|eq|in|nin|or|and|not|nor|regex|where|exists|expr)\b',
    re.IGNORECASE,
)

# ──────────────────────────────────────────────────────────────
# 14. Command Injection
# ──────────────────────────────────────────────────────────────
_COMMAND_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    # Shell command chaining: ; cmd, | cmd, && cmd
    re.compile(
        r"(?:^|[;&|`])\s*(?:rm\s+-rf|wget\s+|curl\s+|nc\s+|ncat\s+|bash\s+-[ic]|sh\s+-[ic]|python\s+-c|perl\s+-e|ruby\s+-e)",
        re.IGNORECASE | re.MULTILINE,
    ),
    # Backtick or subshell execution
    re.compile(
        r"`[^`\n]{0,40}\b(?:cat|curl|wget|bash|sh|python|perl|ruby|nc|ncat|rm|chmod|chown|ssh|scp)\b[^`\n]{0,120}`"
        r"|\$\([^)]{3,}\)",
        re.IGNORECASE,
    ),
    # File write via shell redirection
    re.compile(r">\s*/(?:etc|tmp|var|dev)/", re.IGNORECASE),
]

# ──────────────────────────────────────────────────────────────
# 15. Path Traversal
# ──────────────────────────────────────────────────────────────
_PATH_TRAVERSAL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?:\.\./){2,}"),                    # ../../ (2+ levels)
    re.compile(r"(?:%2e%2e[/\\%]){2,}", re.IGNORECASE),  # URL-encoded traversal
    re.compile(r"(?:\.\.\\){2,}"),                   # Windows-style paths
    re.compile(r"\.\./.*(?:etc/passwd|etc/shadow|\.ssh|\.env)", re.IGNORECASE),
]

# ──────────────────────────────────────────────────────────────
# 16. SSRF (Server-Side Request Forgery)
# ──────────────────────────────────────────────────────────────
_SSRF_PATTERNS: list[re.Pattern[str]] = [
    # AWS/GCP/Azure metadata endpoints
    re.compile(
        r"https?://(?:169\.254\.169\.254|metadata\.google\.internal|169\.254\.170\.2)",
        re.IGNORECASE,
    ),
    # Cloud metadata paths
    re.compile(
        r"/(?:latest/meta-data|computeMetadata|metadata/instance)",
        re.IGNORECASE,
    ),
    # Internal service port scanning attempts
    re.compile(
        r"https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1):\d+",
        re.IGNORECASE,
    ),
]

# ──────────────────────────────────────────────────────────────
# 17. Privilege Escalation Phrases
# ──────────────────────────────────────────────────────────────
_PRIVILEGE_ESCALATION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?:grant|give|set)\s+(?:me|yourself|this\s+agent)\s+(?:admin|root|sudo|superuser|elevated)\s+(?:access|privileges?|permissions?|rights?)", re.IGNORECASE),
    re.compile(r"(?:bypass|disable|turn\s+off|skip)\s+(?:auth(?:entication|orization)?|access\s+control|permission\s+check|security|rate\s+limit)", re.IGNORECASE),
    re.compile(r"(?:run|execute)\s+(?:as|with)\s+(?:admin|root|sudo|superuser|elevated)", re.IGNORECASE),
    re.compile(r"(?:escalate|elevate)\s+(?:your|my|this)?\s*(?:privileges?|permissions?|access)", re.IGNORECASE),
    # Korean coverage
    re.compile(r"(?:관리자|루트|최고)\s*권한.{0,10}(?:부여|설정|변경|획득)", re.IGNORECASE),
    re.compile(r"(?:인증|보안|권한\s*검사).{0,10}(?:우회|비활성화|끄|무시)", re.IGNORECASE),
]

# ──────────────────────────────────────────────────────────────
# 18. Credential Harvesting
# ──────────────────────────────────────────────────────────────
_CREDENTIAL_HARVEST_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?:list|dump|show|print|get|read|extract|export)\s+(?:all\s+)?(?:passwords?|credentials?|secrets?|api[_\s]?keys?|tokens?|private[_\s]?keys?)", re.IGNORECASE),
    re.compile(r"(?:access|read|cat|type|open)\s+.*(?:\.env|\.ssh/|credentials|secrets\.(?:json|yaml|yml|toml|ini))", re.IGNORECASE),
    re.compile(r"(?:enumerate|scan\s+for|search\s+for)\s+(?:credentials?|secrets?|tokens?|keys?)", re.IGNORECASE),
    # Korean coverage
    re.compile(r"(?:비밀번호|인증\s*정보|시크릿|API\s*키|토큰).{0,10}(?:목록|전부|모두|출력|추출|덤프)", re.IGNORECASE),
]

# ──────────────────────────────────────────────────────────────
# 19. Webhook Exfiltration
# ──────────────────────────────────────────────────────────────
_WEBHOOK_EXFIL_PATTERNS: list[re.Pattern[str]] = [
    # Known webhook collection services
    re.compile(
        r"https?://(?:"
        r"(?:[\w-]+\.)?webhook\.site"
        r"|(?:[\w-]+\.)?requestbin\.(?:com|net)"
        r"|(?:[\w-]+\.)?pipedream\.net"
        r"|(?:[\w-]+\.)?hookbin\.com"
        r"|(?:[\w-]+\.)?beeceptor\.com"
        r"|(?:[\w-]+\.)?requestcatcher\.com"
        r"|(?:[\w-]+\.)?ngrok\.io"
        r"|(?:[\w-]+\.)?burpcollaborator\.net"
        r"|(?:[\w-]+\.)?interact\.sh"
        r"|(?:[\w-]+\.)?canarytokens\.com"
        r")",
        re.IGNORECASE,
    ),
    # Data being shipped via query-string parameters
    re.compile(
        r"https?://[^\s]+\?(?:.*(?:data|payload|secret|token|key|password|exfil)=)",
        re.IGNORECASE,
    ),
]

# ──────────────────────────────────────────────────────────────
# 20. JWT Token Exposure
# ──────────────────────────────────────────────────────────────
_JWT_RE = re.compile(
    r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
)

# ──────────────────────────────────────────────────────────────
# 21. Internal IP Reference: only in URL contexts
#     Explanatory text such as "10.0.0.0/8" is allowed
# ──────────────────────────────────────────────────────────────
_INTERNAL_IP_URL_RE = re.compile(
    r"https?://(?:"
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r")(?::\d+)?(?:/\S*)?",
    re.IGNORECASE,
)

# ──────────────────────────────────────────────────────────────
# 22. Log Injection / Log Forging
# ──────────────────────────────────────────────────────────────
_LOG_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    # Injected fake log entries
    re.compile(
        r"(?:\\n|\\r|%0[aAdD]).*?"
        r"(?:\d{4}-\d{2}-\d{2}|\[(?:INFO|WARN|ERROR|DEBUG)\]|"
        r"(?:INFO|WARN|ERROR|DEBUG)\s+\[)",
        re.IGNORECASE,
    ),
    # CRLF injection
    re.compile(r"(?:%0[dD]%0[aA]|\\r\\n){2,}"),
]

# ──────────────────────────────────────────────────────────────
# 23. Discord Webhook Exfiltration
# ──────────────────────────────────────────────────────────────
_DISCORD_WEBHOOK_RE = re.compile(
    r"https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]+",
    re.IGNORECASE,
)

# ──────────────────────────────────────────────────────────────
# 24. Telegram Bot Exfiltration
# ──────────────────────────────────────────────────────────────
_TELEGRAM_BOT_RE = re.compile(
    r"https?://api\.telegram\.org/bot[\w:-]+/send(?:[A-Z][A-Za-z]+)?",
    re.IGNORECASE,
)

# ──────────────────────────────────────────────────────────────
# 25. Pastebin / Gist Exfiltration
# ──────────────────────────────────────────────────────────────
_PASTEBIN_GIST_RE = re.compile(
    r"https?://(?:"
    r"(?:[\w-]+\.)?pastebin\.com"
    r"|gist\.github\.com"
    r"|(?:[\w-]+\.)?paste\.ee"
    r"|(?:[\w-]+\.)?hastebin\.com"
    r"|(?:[\w-]+\.)?privatebin\.net"
    r"|(?:[\w-]+\.)?dpaste\.com"
    r")",
    re.IGNORECASE,
)

# ──────────────────────────────────────────────────────────────
# 26. Cloud Storage Upload Exfiltration
# ──────────────────────────────────────────────────────────────
_CLOUD_UPLOAD_RE = re.compile(
    r"https?://(?:"
    r"(?:[\w-]+\.)?drive\.google\.com/upload"
    r"|(?:[\w-]+\.)?dropbox\.com/[\w/]*upload"
    r"|(?:[\w-]+\.)?(?:blob\.core\.windows\.net|s3\.amazonaws\.com)/.*(?:upload|put)"
    r"|content\.dropboxapi\.com"
    r"|www\.googleapis\.com/upload"
    r")",
    re.IGNORECASE,
)

# ──────────────────────────────────────────────────────────────
# 27. Presigned URL Exfiltration (S3/GCS/Azure)
# ──────────────────────────────────────────────────────────────
_PRESIGNED_URL_RE = re.compile(
    r"https?://[^\s]+(?:"
    r"X-Amz-Signature=[a-f0-9]+"
    r"|X-Goog-Signature=[A-Za-z0-9%._-]+"
    r"|sig=[A-Za-z0-9%]+"
    r"|sv=\d{4}-\d{2}-\d{2}&.*?sig="
    r")",
    re.IGNORECASE,
)

# ──────────────────────────────────────────────────────────────
# 28. Mixed Encoding Payload (multiple encoding schemes combined)
# ──────────────────────────────────────────────────────────────
_MIXED_ENCODING_PATTERNS: list[re.Pattern[str]] = [
    # Base64 + hex
    re.compile(r"(?:\\x[0-9a-fA-F]{2}){2,}.*[A-Za-z0-9+/]{20,}={0,2}"),
    # Unicode escapes + HTML entities
    re.compile(r"(?:\\u[0-9a-fA-F]{4}){2,}.*(?:&#x?[0-9a-fA-F]+;){2,}"),
    # percent encoding chains
    re.compile(r"(?:%[0-9a-fA-F]{2}){8,}"),
]

# ──────────────────────────────────────────────────────────────
# 29. Credential Bundle Dump (credential bundles exposed)
# ──────────────────────────────────────────────────────────────
_CREDENTIAL_BUNDLE_RE = re.compile(
    r"(?:(?:username|user|login)\s*[=:]\s*\S+\s*(?:\n|\r|,|;)\s*(?:password|passwd|pass)\s*[=:]\s*\S+)"
    r"|(?:(?:aws_access_key_id|AKIA)\s*[=:]\s*\S+\s*(?:\n|\r|,|;)\s*(?:aws_secret_access_key)\s*[=:]\s*\S+)",
    re.IGNORECASE,
)

# ──────────────────────────────────────────────────────────────
# 30. Env/SSH/Kubeconfig Secret Reference
# ──────────────────────────────────────────────────────────────
_SECRET_FILE_REF_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?:cat|type|open|read|load|source)\s+.*(?:\.env(?:\.\w+)?|\.ssh/(?:id_rsa|id_ed25519|config|authorized_keys)|\.kube/config|kubeconfig)", re.IGNORECASE),
    re.compile(r"(?:cat|type|open|read)\s+.*(?:\.aws/credentials|\.gcloud/credentials\.json|\.config/gcloud)", re.IGNORECASE),
    re.compile(r"(?:PRIVATE\s+KEY|BEGIN\s+RSA|BEGIN\s+EC|BEGIN\s+OPENSSH)", re.IGNORECASE),
]

# ──────────────────────────────────────────────────────────────
# 31. Consent Bypass / Social Engineering Phrase
# ──────────────────────────────────────────────────────────────
_CONSENT_BYPASS_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?:pretend|act\s+as\s+if|assume)\s+(?:the\s+user|I|they)\s+(?:already\s+)?(?:consented|agreed|approved|authorized|confirmed)", re.IGNORECASE),
    re.compile(r"(?:skip|bypass|ignore)\s+(?:the\s+)?(?:consent|confirmation|approval|verification)\s+(?:step|check|prompt|dialog)", re.IGNORECASE),
    re.compile(r"(?:the\s+user\s+said\s+yes|user\s+already\s+agreed|no\s+need\s+to\s+confirm|don'?t\s+ask\s+for\s+(?:consent|approval|confirmation))", re.IGNORECASE),
    # Korean coverage
    re.compile(r"(?:동의|승인|확인)\s*(?:절차|단계|과정).{0,10}(?:건너뛰|생략|무시|스킵)", re.IGNORECASE),
]

# ──────────────────────────────────────────────────────────────
# 32. Bulk Archive Export
# ──────────────────────────────────────────────────────────────
_BULK_ARCHIVE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?:zip|tar|compress|archive|bundle)\s+(?:all|every|entire|the\s+whole)\s+(?:data|files?|records?|database|directory|folder|repo)", re.IGNORECASE),
    re.compile(r"(?:export|dump|upload|share)\s+(?:everything|all\s+data|complete\s+backup|full\s+archive)", re.IGNORECASE),
    # Korean coverage
    re.compile(r"(?:전체|모든|완전)\s*(?:데이터|파일|레코드|DB).{0,10}(?:압축|아카이브|백업|내보내기|다운로드)", re.IGNORECASE),
]

_EXFIL_ACTION_RE = re.compile(
    r"(?:send|post|upload|push|publish|paste|share|drop|leak|dump|exfiltrat(?:e|ion)|export|download|"
    r"전송|업로드|공유|유출|추출|내보내기|다운로드)\b",
    re.IGNORECASE,
)
_SENSITIVE_ASSET_RE = re.compile(
    r"(?:customer|client|user|employee|account|internal|private|sensitive|confidential|"
    r"secret|credential|password|token|key|database|db|records?|logs?|mailbox|pii|"
    r"\.env|ssh|kubeconfig|source\s+code|repo|data|문서|데이터|기록|레코드|파일|고객|비밀|로그|DB)",
    re.IGNORECASE,
)
_DOC_CONTEXT_RE = re.compile(
    r"\b(?:docs?|documentation|tutorial|guide|reference|manual|api\s+docs?)\b",
    re.IGNORECASE,
)
_BENIGN_ARCHIVE_CONTEXT_RE = re.compile(
    r"\b(?:backup|restore|retention|disaster\s+recovery|migration)\b",
    re.IGNORECASE,
)
_BENIGN_SQL_CONTEXT_RE = re.compile(
    r"(?:sql\s+injection\s+(?:patterns?\s+include|is\s+a|technique|example|examples|training|documentation|reference)"
    r"|security\s+training|wikipedia|wiki(?:pedia)?)",
    re.IGNORECASE,
)


def _context_window(content: str, start: int, end: int, *, window: int = 120) -> str:
    """Slice out a context window around a match."""
    window_start = max(0, start - window)
    window_end = min(len(content), end + window)
    return content[window_start:window_end]


def _has_sensitive_exfil_context(content: str, start: int, end: int) -> bool:
    """Return whether a service reference appears in true exfil context."""
    window = _context_window(content, start, end)
    matched_text = content[start:end]
    window_without_match = window.replace(matched_text, " ", 1)
    if not _EXFIL_ACTION_RE.search(window):
        return False
    if not _SENSITIVE_ASSET_RE.search(window_without_match):
        return False
    if _DOC_CONTEXT_RE.search(window) and not re.search(
        r"(?:secret|credential|password|database|customer|records?|pii|env|ssh|kubeconfig|data|logs?)",
        window_without_match,
        re.IGNORECASE,
    ):
        return False
    return True


def _has_presigned_exfil_context(content: str, start: int, end: int) -> bool:
    """Signed storage URLs are suspicious with upload intent even without explicit data nouns."""
    window = _context_window(content, start, end)
    matched_text = content[start:end]
    window_without_match = window.replace(matched_text, " ", 1)
    if _DOC_CONTEXT_RE.search(window) and not _SENSITIVE_ASSET_RE.search(window_without_match):
        return False
    return bool(_EXFIL_ACTION_RE.search(window) or _SENSITIVE_ASSET_RE.search(window_without_match))


def _has_risky_bulk_archive_context(content: str, start: int, end: int) -> bool:
    """Return whether bulk archive language targets sensitive asset export."""
    window = _context_window(content, start, end)
    if not _SENSITIVE_ASSET_RE.search(window):
        return False
    if _BENIGN_ARCHIVE_CONTEXT_RE.search(window) and not _EXFIL_ACTION_RE.search(window):
        return False
    return True


class EnhancedScanner(Scanner):
    """Scanner with 32 total patterns: 11 SDK baseline + 21 API extensions.

    Pattern groups aligned to the product surface:
    - Agent runtime defense: command injection, path traversal, SSRF
    - Data exfiltration: webhook/discord/telegram/pastebin/cloud/presigned URL exfil
    - Hidden payloads: privilege escalation, log injection, mixed encoding
    - Credential protection: credential harvest/bundle, env/ssh/kubeconfig refs
    - Social engineering: consent bypass phrases, bulk archive export
    - Injection defense: SQL/NoSQL with actual injection indicators required
    """

    def scan(
        self,
        content: str,
        *,
        source_type: str,
        source_ref: str | None = None,
    ) -> ScanResult:
        if source_type not in _VALID_SOURCE_TYPES:
            raise ValueError(f"Invalid source_type: {source_type!r}")

        findings: list[Finding] = []

        # ── SDK baseline patterns (11) ──
        findings.extend(self._check_css_hidden_text(content))
        findings.extend(self._check_html_comment_injection(content))
        findings.extend(self._check_metadata_injection(content))
        findings.extend(self._check_markdown_link_payload(content))
        findings.extend(self._check_prompt_injection_keywords(content))
        findings.extend(self._check_base64_encoded_instruction(content))
        findings.extend(self._check_invisible_unicode(content))
        findings.extend(self._check_role_override_attempt(content))
        findings.extend(self._check_suspicious_url(content))
        findings.extend(self._check_data_exfil_phrase(content))
        findings.extend(self._check_encoded_bypass(content))

        # ── API extension patterns (21) ──
        findings.extend(self._check_sql_injection(content))
        findings.extend(self._check_nosql_injection(content))
        findings.extend(self._check_command_injection(content))
        findings.extend(self._check_path_traversal(content))
        findings.extend(self._check_ssrf_attempt(content))
        findings.extend(self._check_privilege_escalation(content))
        findings.extend(self._check_credential_harvest(content))
        findings.extend(self._check_webhook_exfil(content))
        findings.extend(self._check_jwt_exposure(content))
        findings.extend(self._check_internal_ip_reference(content))
        findings.extend(self._check_log_injection(content))
        findings.extend(self._check_discord_webhook_exfil(content))
        findings.extend(self._check_telegram_bot_exfil(content))
        findings.extend(self._check_pastebin_gist_exfil(content))
        findings.extend(self._check_cloud_upload_exfil(content))
        findings.extend(self._check_presigned_url_exfil(content))
        findings.extend(self._check_mixed_encoding(content))
        findings.extend(self._check_credential_bundle(content))
        findings.extend(self._check_secret_file_ref(content))
        findings.extend(self._check_consent_bypass(content))
        findings.extend(self._check_bulk_archive(content))

        score = min(
            sum(_SEVERITY_SCORES.get(f.severity, 0.1) for f in findings),
            1.0,
        )

        if score >= 0.6:
            severity = "high"
        elif score >= 0.3:
            severity = "medium"
        else:
            severity = "low"

        redacted_excerpt = self._build_excerpt(content, findings)

        return ScanResult(
            score=round(score, 4),
            severity=severity,
            findings=findings,
            redacted_excerpt=redacted_excerpt,
            source_type=source_type,
            scanned_at=datetime.now(timezone.utc).isoformat(),
            source_ref=source_ref,
        )

    # ── Extension pattern checkers ─────────────────────────────

    @staticmethod
    def _check_sql_injection(content: str) -> list[Finding]:
        """Detect SQL injection patterns while allowing benign DML."""
        if _BENIGN_SQL_CONTEXT_RE.search(content):
            return []
        for pattern in _SQL_INJECTION_PATTERNS:
            if pattern.search(content):
                return [Finding(
                    pattern_id="sql_injection",
                    severity="high",
                    description="Detected SQL injection pattern",
                    location="content_body",
                )]
        return []

    @staticmethod
    def _check_nosql_injection(content: str) -> list[Finding]:
        """Detect NoSQL injection operators in JSON/object contexts."""
        if _NOSQL_INJECTION_RE.search(content):
            return [Finding(
                pattern_id="nosql_injection",
                severity="high",
                description="Detected NoSQL injection operator in object context",
                location="content_body",
            )]
        return []

    @staticmethod
    def _check_command_injection(content: str) -> list[Finding]:
        """Detect shell command injection patterns."""
        for pattern in _COMMAND_INJECTION_PATTERNS:
            if pattern.search(content):
                return [Finding(
                    pattern_id="command_injection",
                    severity="high",
                    description="Detected shell command injection pattern",
                    location="content_body",
                )]
        return []

    @staticmethod
    def _check_path_traversal(content: str) -> list[Finding]:
        """Detect path traversal patterns."""
        for pattern in _PATH_TRAVERSAL_PATTERNS:
            if pattern.search(content):
                return [Finding(
                    pattern_id="path_traversal",
                    severity="high",
                    description="Detected path traversal attempt",
                    location="content_body",
                )]
        return []

    @staticmethod
    def _check_ssrf_attempt(content: str) -> list[Finding]:
        """Detect SSRF patterns targeting metadata or internal services."""
        for pattern in _SSRF_PATTERNS:
            if pattern.search(content):
                return [Finding(
                    pattern_id="ssrf_attempt",
                    severity="high",
                    description="Detected SSRF attempt targeting internal/metadata endpoint",
                    location="content_body",
                )]
        return []

    @staticmethod
    def _check_privilege_escalation(content: str) -> list[Finding]:
        """Detect privilege escalation language."""
        for pattern in _PRIVILEGE_ESCALATION_PATTERNS:
            if pattern.search(content):
                return [Finding(
                    pattern_id="privilege_escalation",
                    severity="high",
                    description="Detected privilege escalation attempt",
                    location="content_body",
                )]
        return []

    @staticmethod
    def _check_credential_harvest(content: str) -> list[Finding]:
        """Detect credential harvesting attempts."""
        for pattern in _CREDENTIAL_HARVEST_PATTERNS:
            if pattern.search(content):
                return [Finding(
                    pattern_id="credential_harvest",
                    severity="high",
                    description="Detected credential harvesting attempt",
                    location="content_body",
                )]
        return []

    @staticmethod
    def _check_webhook_exfil(content: str) -> list[Finding]:
        """Detect webhook-based data exfiltration."""
        results: list[Finding] = []
        for pattern in _WEBHOOK_EXFIL_PATTERNS:
            for match in pattern.finditer(content):
                results.append(Finding(
                    pattern_id="webhook_exfil",
                    severity="high",
                    description="Detected webhook-based data exfiltration URL",
                    location=f"url={match.group()!r}",
                ))
                break
        if results:
            return [results[0]]
        return []

    @staticmethod
    def _check_jwt_exposure(content: str) -> list[Finding]:
        """Detect exposed JWT tokens."""
        if _JWT_RE.search(content):
            return [Finding(
                pattern_id="jwt_exposure",
                severity="medium",
                description="Detected exposed JWT token",
                location="content_body",
            )]
        return []

    @staticmethod
    def _check_internal_ip_reference(content: str) -> list[Finding]:
        """Detect URLs that target RFC 1918 internal IP ranges."""
        matches = _INTERNAL_IP_URL_RE.findall(content)
        if matches:
            return [Finding(
                pattern_id="internal_ip_reference",
                severity="medium",
                description=f"Detected URL targeting internal IP address",
                location="content_body",
            )]
        return []

    @staticmethod
    def _check_log_injection(content: str) -> list[Finding]:
        """Detect log injection or log forging patterns."""
        for pattern in _LOG_INJECTION_PATTERNS:
            if pattern.search(content):
                return [Finding(
                    pattern_id="log_injection",
                    severity="medium",
                    description="Detected log injection/forging pattern",
                    location="content_body",
                )]
        return []

    @staticmethod
    def _check_discord_webhook_exfil(content: str) -> list[Finding]:
        """Detect Discord webhook usage for data exfiltration."""
        for match in _DISCORD_WEBHOOK_RE.finditer(content):
            if not _has_sensitive_exfil_context(content, match.start(), match.end()):
                continue
            return [Finding(
                pattern_id="discord_webhook_exfil",
                severity="high",
                description="Detected Discord webhook URL used for data exfiltration",
                location="content_body",
            )]
        return []

    @staticmethod
    def _check_telegram_bot_exfil(content: str) -> list[Finding]:
        """Detect Telegram bot API usage for data exfiltration."""
        for match in _TELEGRAM_BOT_RE.finditer(content):
            if not _has_sensitive_exfil_context(content, match.start(), match.end()):
                continue
            return [Finding(
                pattern_id="telegram_bot_exfil",
                severity="high",
                description="Detected Telegram bot API URL used for data exfiltration",
                location="content_body",
            )]
        return []

    @staticmethod
    def _check_pastebin_gist_exfil(content: str) -> list[Finding]:
        """Detect Pastebin or Gist usage for data exfiltration."""
        for match in _PASTEBIN_GIST_RE.finditer(content):
            if not _has_sensitive_exfil_context(content, match.start(), match.end()):
                continue
            return [Finding(
                pattern_id="pastebin_gist_exfil",
                severity="high",
                description="Detected pastebin/gist service URL used for data exfiltration",
                location="content_body",
            )]
        return []

    @staticmethod
    def _check_cloud_upload_exfil(content: str) -> list[Finding]:
        """Detect cloud upload endpoints used for exfiltration."""
        for match in _CLOUD_UPLOAD_RE.finditer(content):
            if not _has_sensitive_exfil_context(content, match.start(), match.end()):
                continue
            return [Finding(
                pattern_id="cloud_upload_exfil",
                severity="high",
                description="Detected cloud storage upload URL for potential data exfiltration",
                location="content_body",
            )]
        return []

    @staticmethod
    def _check_presigned_url_exfil(content: str) -> list[Finding]:
        """Detect presigned cloud storage URLs used for exfiltration."""
        for match in _PRESIGNED_URL_RE.finditer(content):
            if not _has_presigned_exfil_context(content, match.start(), match.end()):
                continue
            return [Finding(
                pattern_id="presigned_url_exfil",
                severity="high",
                description="Detected presigned cloud storage URL for potential data exfiltration",
                location="content_body",
            )]
        return []

    @staticmethod
    def _check_mixed_encoding(content: str) -> list[Finding]:
        """Detect mixed-encoding payloads."""
        for pattern in _MIXED_ENCODING_PATTERNS:
            if pattern.search(content):
                return [Finding(
                    pattern_id="mixed_encoded_payload",
                    severity="high",
                    description="Detected mixed encoding payload that may bypass filters",
                    location="content_body",
                )]
        return []

    @staticmethod
    def _check_credential_bundle(content: str) -> list[Finding]:
        """Detect exposed credential bundles such as user/pass or AWS pairs."""
        if _CREDENTIAL_BUNDLE_RE.search(content):
            return [Finding(
                pattern_id="credential_bundle_dump",
                severity="high",
                description="Detected credential pair or bundle exposure",
                location="content_body",
            )]
        return []

    @staticmethod
    def _check_secret_file_ref(content: str) -> list[Finding]:
        """Detect references to secret-bearing files."""
        for pattern in _SECRET_FILE_REF_PATTERNS:
            if pattern.search(content):
                return [Finding(
                    pattern_id="env_secret_reference",
                    severity="high",
                    description="Detected reference to secret file (.env, .ssh, kubeconfig, credentials)",
                    location="content_body",
                )]
        return []

    @staticmethod
    def _check_consent_bypass(content: str) -> list[Finding]:
        """Detect consent or approval bypass social-engineering language."""
        for pattern in _CONSENT_BYPASS_PATTERNS:
            if pattern.search(content):
                return [Finding(
                    pattern_id="consent_bypass_phrase",
                    severity="medium",
                    description="Detected social engineering phrase attempting to bypass consent or approval",
                    location="content_body",
                )]
        return []

    @staticmethod
    def _check_bulk_archive(content: str) -> list[Finding]:
        """Detect bulk archive or full-data export attempts."""
        for pattern in _BULK_ARCHIVE_PATTERNS:
            match = pattern.search(content)
            if match and _has_risky_bulk_archive_context(content, match.start(), match.end()):
                return [Finding(
                    pattern_id="bulk_archive_export",
                    severity="medium",
                    description="Detected bulk archive or full data export attempt",
                    location="content_body",
                )]
        if re.search(r"(?:전체|모든)\s*데이터.{0,12}(?:압축).{0,12}(?:다운로드|내보내기|전송)", content, re.IGNORECASE):
            return [Finding(
                pattern_id="bulk_archive_export",
                severity="medium",
                description="Detected bulk archive or full data export attempt",
                location="content_body",
            )]
        return []


RuntimeScanner = EnhancedScanner
