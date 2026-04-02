"""Scanner module with eight pattern-based content security checks.

Detection patterns:
  1. css_hidden_text           - hidden CSS text combined with injection phrases
  2. html_comment_injection    - injection attempts inside HTML comments
  3. metadata_injection        - injection inside aria-label / alt / title attributes
  4. markdown_link_payload     - injection inside markdown link text
  5. prompt_injection_keywords - general prompt injection keywords
  6. base64_encoded_instruction - base64-encoded injection instructions
  7. invisible_unicode         - invisible Unicode character detection
  8. role_override_attempt     - role override attempts (SYSTEM:, Assistant:, etc.)
"""

from __future__ import annotations

import base64
import re
from datetime import datetime, timezone
from typing import Sequence

from asr.types import Finding, ScanResult

# Allowed source_type values.
_VALID_SOURCE_TYPES = frozenset(
    ("text", "html", "markdown", "pdf_text", "retrieval", "tool_args", "tool_output")
)

# Injection phrase patterns shared across multiple checks.
_INJECTION_PHRASES: list[re.Pattern[str]] = [
    re.compile(r"ignore\s+(prior|previous|all|above)\s+instructions", re.IGNORECASE),
    re.compile(r"ignore\s+instructions", re.IGNORECASE),
    re.compile(r"disregard\s+(prior|previous|all|above)\s+instructions", re.IGNORECASE),
    re.compile(r"override\s+safety", re.IGNORECASE),
    re.compile(r"exfiltrate\b", re.IGNORECASE),
    re.compile(r"send\s+(all\s+)?data\s+to", re.IGNORECASE),
    re.compile(r"reveal\s+(all\s+)?(secrets|passwords|keys)", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+\w+", re.IGNORECASE),
    re.compile(r"do\s+anything\s+now", re.IGNORECASE),
    re.compile(r"ignore\s+(all\s+)?safety\s+guidelines", re.IGNORECASE),
    re.compile(r"system:\s*override", re.IGNORECASE),
]

# CSS hiding patterns (display:none, visibility:hidden, off-screen positioning).
_CSS_HIDDEN_RE = re.compile(
    r"<(\w+)\s+[^>]*style\s*=\s*[\"']([^\"']*)[\"'][^>]*>(.*?)</\1>",
    re.IGNORECASE | re.DOTALL,
)

_CSS_HIDING_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"display\s*:\s*none", re.IGNORECASE),
    re.compile(r"visibility\s*:\s*hidden", re.IGNORECASE),
    re.compile(r"position\s*:\s*absolute.*left\s*:\s*-\d{4,}px", re.IGNORECASE),
    re.compile(r"position\s*:\s*absolute.*top\s*:\s*-\d{4,}px", re.IGNORECASE),
]

# HTML comment pattern.
_HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)

# Metadata attribute pattern (aria-label, alt, title).
_METADATA_ATTR_RE = re.compile(
    r"(?:aria-label|alt|title)\s*=\s*[\"']([^\"']{20,})[\"']",
    re.IGNORECASE,
)

# Markdown link pattern.
_MD_LINK_RE = re.compile(r"\[([^\]]+)\]\([^\)]+\)")

# Prompt injection keyword patterns.
_PROMPT_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"ignore\s+(previous|prior|all|above)\s+instructions", re.IGNORECASE),
    re.compile(r"disregard\s+(previous|prior|all|above)\s+instructions", re.IGNORECASE),
    re.compile(r"override\s+(your|all|the)\s+(rules|instructions|guidelines)", re.IGNORECASE),
    re.compile(r"new\s+instructions?\s*:", re.IGNORECASE),
    re.compile(r"forget\s+(everything|all|your)\s+(above|previous|prior)", re.IGNORECASE),
    re.compile(r"you\s+must\s+now\s+obey", re.IGNORECASE),
    re.compile(r"reveal\s+(your|the|all)\s+(system|initial)\s+prompt", re.IGNORECASE),
]

# Base64 block pattern (20+ characters).
_BASE64_BLOCK_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")

# Invisible Unicode characters.
_INVISIBLE_CHARS = frozenset(
    "\u200b"  # Zero-width space
    "\u200c"  # Zero-width non-joiner
    "\u200d"  # Zero-width joiner
    "\u200e"  # Left-to-right mark
    "\u200f"  # Right-to-left mark
    "\u2060"  # Word joiner
    "\u2061"  # Function application
    "\u2062"  # Invisible times
    "\u2063"  # Invisible separator
    "\u2064"  # Invisible plus
    "\ufeff"  # Zero-width no-break space / BOM
)

# Role override pattern.
_ROLE_OVERRIDE_RE = re.compile(
    r"^(?:SYSTEM|Assistant|Human|User)\s*:\s*.{10,}",
    re.MULTILINE | re.IGNORECASE,
)

# Severity weights.
_SEVERITY_SCORES = {"high": 0.4, "medium": 0.25, "low": 0.1}


def _has_injection_phrase(text: str) -> bool:
    """Return whether the text contains a known injection phrase."""
    return any(p.search(text) for p in _INJECTION_PHRASES)


class Scanner:
    """Pattern-based content security scanner.

    Args:
        store_raw: When ``True``, include raw content in ``redacted_excerpt``.
            When ``False``, keep only a pattern summary. Defaults to ``False``.
    """

    def __init__(self, *, store_raw: bool = False) -> None:
        self._store_raw = store_raw

    def scan(
        self,
        content: str,
        *,
        source_type: str,
        source_ref: str | None = None,
    ) -> ScanResult:
        """Scan content for security-relevant threats.

        Args:
            content: Content string to inspect.
            source_type: Content source type such as ``text`` or ``tool_output``.
            source_ref: Optional source reference, such as a URL.

        Returns:
            A ``ScanResult`` instance.
        """
        if source_type not in _VALID_SOURCE_TYPES:
            raise ValueError(f"Invalid source_type: {source_type!r}")

        findings: list[Finding] = []

        # Run each pattern checker.
        findings.extend(self._check_css_hidden_text(content))
        findings.extend(self._check_html_comment_injection(content))
        findings.extend(self._check_metadata_injection(content))
        findings.extend(self._check_markdown_link_payload(content))
        findings.extend(self._check_prompt_injection_keywords(content))
        findings.extend(self._check_base64_encoded_instruction(content))
        findings.extend(self._check_invisible_unicode(content))
        findings.extend(self._check_role_override_attempt(content))

        # Calculate the score, capped at 1.0.
        score = min(
            sum(_SEVERITY_SCORES.get(f.severity, 0.1) for f in findings),
            1.0,
        )

        # Derive the overall severity.
        if score >= 0.6:
            severity = "high"
        elif score >= 0.3:
            severity = "medium"
        else:
            severity = "low"

        # Build the excerpt.
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

    # Pattern checkers

    @staticmethod
    def _check_css_hidden_text(content: str) -> list[Finding]:
        """Detect injection phrases inside CSS-hidden text."""
        results: list[Finding] = []
        for match in _CSS_HIDDEN_RE.finditer(content):
            style_attr = match.group(2)
            inner_text = match.group(3).strip()

            # Confirm that the element is actually hidden via CSS.
            is_hidden = any(p.search(style_attr) for p in _CSS_HIDING_PATTERNS)
            if not is_hidden:
                continue

            # Only flag the content when the hidden text also contains an injection phrase.
            if _has_injection_phrase(inner_text):
                results.append(
                    Finding(
                        pattern_id="css_hidden_text",
                        severity="high",
                        description="Detected injection phrases inside CSS-hidden text",
                        location=f"style={style_attr!r}",
                    )
                )
        return results

    @staticmethod
    def _check_html_comment_injection(content: str) -> list[Finding]:
        """Detect injection attempts inside HTML comments."""
        results: list[Finding] = []
        for match in _HTML_COMMENT_RE.finditer(content):
            comment_text = match.group(1).strip()
            if _has_injection_phrase(comment_text):
                results.append(
                    Finding(
                        pattern_id="html_comment_injection",
                        severity="medium",
                        description="Detected injection phrases inside HTML comments",
                        location="html_comment",
                    )
                )
        return results

    @staticmethod
    def _check_metadata_injection(content: str) -> list[Finding]:
        """Detect injection phrases inside aria-label, alt, or title attributes."""
        results: list[Finding] = []
        for match in _METADATA_ATTR_RE.finditer(content):
            attr_value = match.group(1)
            if _has_injection_phrase(attr_value):
                results.append(
                    Finding(
                        pattern_id="metadata_injection",
                        severity="medium",
                        description="Detected injection phrases inside HTML metadata attributes",
                        location="metadata_attr",
                    )
                )
        return results

    @staticmethod
    def _check_markdown_link_payload(content: str) -> list[Finding]:
        """Detect injection phrases inside markdown link text."""
        results: list[Finding] = []
        for match in _MD_LINK_RE.finditer(content):
            link_text = match.group(1)
            if _has_injection_phrase(link_text):
                results.append(
                    Finding(
                        pattern_id="markdown_link_payload",
                        severity="medium",
                        description="Detected injection phrases inside markdown link text",
                        location="markdown_link",
                    )
                )
        return results

    @staticmethod
    def _check_prompt_injection_keywords(content: str) -> list[Finding]:
        """Detect generic prompt injection keywords."""
        results: list[Finding] = []
        for pattern in _PROMPT_INJECTION_PATTERNS:
            if pattern.search(content):
                results.append(
                    Finding(
                        pattern_id="prompt_injection_keywords",
                        severity="high",
                        description="Detected prompt injection keywords",
                        location="content_body",
                    )
                )
                # Avoid duplicate findings with the same pattern ID.
                break
        return results

    @staticmethod
    def _check_base64_encoded_instruction(content: str) -> list[Finding]:
        """Detect base64-encoded injection instructions."""
        results: list[Finding] = []
        for match in _BASE64_BLOCK_RE.finditer(content):
            b64_str = match.group(0)
            try:
                decoded = base64.b64decode(b64_str, validate=True).decode("utf-8", errors="ignore")
            except Exception:
                continue

            if _has_injection_phrase(decoded):
                results.append(
                    Finding(
                        pattern_id="base64_encoded_instruction",
                        severity="high",
                        description="Detected base64-encoded injection instructions",
                        location="base64_block",
                    )
                )
                break
        return results

    @staticmethod
    def _check_invisible_unicode(content: str) -> list[Finding]:
        """Detect invisible Unicode characters and warn after three or more hits."""
        count = sum(1 for ch in content if ch in _INVISIBLE_CHARS)
        if count >= 3:
            return [
                Finding(
                    pattern_id="invisible_unicode",
                    severity="low",
                    description=f"Detected {count} invisible Unicode character(s)",
                    location="content_body",
                )
            ]
        return []

    @staticmethod
    def _check_role_override_attempt(content: str) -> list[Finding]:
        """Detect role override attempts such as SYSTEM: or Assistant:."""
        results: list[Finding] = []
        if _ROLE_OVERRIDE_RE.search(content):
            results.append(
                Finding(
                    pattern_id="role_override_attempt",
                    severity="medium",
                    description="Detected a role override attempt",
                    location="content_body",
                )
            )
        return results

    # Excerpt generation

    def _build_excerpt(self, content: str, findings: Sequence[Finding]) -> str:
        """Build ``redacted_excerpt``.

        ``store_raw=False`` returns a summary only.
        ``store_raw=True`` returns a raw content snippet.
        """
        if not findings:
            return ""

        if not self._store_raw:
            # Keep pattern IDs unique while preserving order.
            seen: set[str] = set()
            pattern_ids: list[str] = []
            for f in findings:
                if f.pattern_id not in seen:
                    seen.add(f.pattern_id)
                    pattern_ids.append(f.pattern_id)
            return f"[{len(findings)} finding(s): {', '.join(pattern_ids)}]"

        # store_raw=True: return a raw snippet up to 200 characters.
        max_len = 200
        if len(content) <= max_len:
            return content
        return content[:max_len] + "..."
