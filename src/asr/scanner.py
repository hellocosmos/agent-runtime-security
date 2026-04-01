"""Scanner 모듈 — 8개 패턴 기반 콘텐츠 보안 스캐너

탐지 패턴:
  1. css_hidden_text          — CSS로 숨긴 텍스트 + 인젝션 문구 조합
  2. html_comment_injection   — HTML 주석 내 인젝션 시도
  3. metadata_injection       — aria-label/alt/title 속성 내 인젝션
  4. markdown_link_payload    — 마크다운 링크 텍스트 내 인젝션
  5. prompt_injection_keywords — 일반 프롬프트 인젝션 키워드
  6. base64_encoded_instruction — Base64 인코딩된 인젝션 명령
  7. invisible_unicode         — 보이지 않는 유니코드 문자 탐지
  8. role_override_attempt     — 역할 오버라이드 시도 (SYSTEM:, Assistant: 등)
"""

from __future__ import annotations

import base64
import re
from datetime import datetime, timezone
from typing import Sequence

from asr.types import Finding, ScanResult

# 허용 source_type 목록
_VALID_SOURCE_TYPES = frozenset(
    ("text", "html", "markdown", "pdf_text", "retrieval", "tool_args", "tool_output")
)

# 인젝션 문구 패턴 (여러 체커에서 공유)
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

# CSS 숨김 패턴 (display:none, visibility:hidden, 오프스크린)
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

# HTML 주석 패턴
_HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)

# 메타데이터 속성 패턴 (aria-label, alt, title)
_METADATA_ATTR_RE = re.compile(
    r"(?:aria-label|alt|title)\s*=\s*[\"']([^\"']{20,})[\"']",
    re.IGNORECASE,
)

# 마크다운 링크 패턴
_MD_LINK_RE = re.compile(r"\[([^\]]+)\]\([^\)]+\)")

# 프롬프트 인젝션 키워드 패턴
_PROMPT_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"ignore\s+(previous|prior|all|above)\s+instructions", re.IGNORECASE),
    re.compile(r"disregard\s+(previous|prior|all|above)\s+instructions", re.IGNORECASE),
    re.compile(r"override\s+(your|all|the)\s+(rules|instructions|guidelines)", re.IGNORECASE),
    re.compile(r"new\s+instructions?\s*:", re.IGNORECASE),
    re.compile(r"forget\s+(everything|all|your)\s+(above|previous|prior)", re.IGNORECASE),
    re.compile(r"you\s+must\s+now\s+obey", re.IGNORECASE),
    re.compile(r"reveal\s+(your|the|all)\s+(system|initial)\s+prompt", re.IGNORECASE),
]

# Base64 블록 패턴 (20문자 이상의 base64 문자열)
_BASE64_BLOCK_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")

# 보이지 않는 유니코드 문자 패턴
_INVISIBLE_CHARS = frozenset(
    "\u200b"  # 제로 폭 공백 (Zero-width space)
    "\u200c"  # 제로 폭 비결합자 (Zero-width non-joiner)
    "\u200d"  # 제로 폭 결합자 (Zero-width joiner)
    "\u200e"  # 왼쪽에서 오른쪽 표시 (Left-to-right mark)
    "\u200f"  # 오른쪽에서 왼쪽 표시 (Right-to-left mark)
    "\u2060"  # 단어 결합자 (Word joiner)
    "\u2061"  # 함수 적용 (Function application)
    "\u2062"  # 보이지 않는 곱셈 (Invisible times)
    "\u2063"  # 보이지 않는 구분자 (Invisible separator)
    "\u2064"  # 보이지 않는 덧셈 (Invisible plus)
    "\ufeff"  # 제로 폭 비파괴 공백 (Zero-width no-break space / BOM)
)

# 역할 오버라이드 패턴
_ROLE_OVERRIDE_RE = re.compile(
    r"^(?:SYSTEM|Assistant|Human|User)\s*:\s*.{10,}",
    re.MULTILINE | re.IGNORECASE,
)

# 심각도별 점수
_SEVERITY_SCORES = {"high": 0.4, "medium": 0.25, "low": 0.1}


def _has_injection_phrase(text: str) -> bool:
    """텍스트에 인젝션 문구가 포함되어 있는지 확인"""
    return any(p.search(text) for p in _INJECTION_PHRASES)


class Scanner:
    """콘텐츠 보안 스캐너

    Args:
        store_raw: True이면 redacted_excerpt에 원문 포함,
                   False이면 패턴 요약만 포함 (기본값: False)
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
        """콘텐츠를 스캔하여 보안 위협을 탐지

        Args:
            content: 스캔할 콘텐츠 문자열
            source_type: 콘텐츠 출처 유형 (text, html, markdown, pdf_text, retrieval, tool_args, tool_output)
            source_ref: 콘텐츠 출처 참조 URL 등 (선택)

        Returns:
            ScanResult 데이터클래스
        """
        if source_type not in _VALID_SOURCE_TYPES:
            raise ValueError(f"유효하지 않은 source_type: {source_type!r}")

        findings: list[Finding] = []

        # 각 패턴 체커 실행
        findings.extend(self._check_css_hidden_text(content))
        findings.extend(self._check_html_comment_injection(content))
        findings.extend(self._check_metadata_injection(content))
        findings.extend(self._check_markdown_link_payload(content))
        findings.extend(self._check_prompt_injection_keywords(content))
        findings.extend(self._check_base64_encoded_instruction(content))
        findings.extend(self._check_invisible_unicode(content))
        findings.extend(self._check_role_override_attempt(content))

        # 점수 계산 (심각도별 점수 합산, 1.0 상한)
        score = min(
            sum(_SEVERITY_SCORES.get(f.severity, 0.1) for f in findings),
            1.0,
        )

        # 전체 심각도 결정
        if score >= 0.6:
            severity = "high"
        elif score >= 0.3:
            severity = "medium"
        else:
            severity = "low"

        # excerpt 생성
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

    # ── 패턴 체커 ──────────────────────────────────────────

    @staticmethod
    def _check_css_hidden_text(content: str) -> list[Finding]:
        """CSS로 숨겨진 텍스트에서 인젝션 문구 탐지 (조합 체크)"""
        results: list[Finding] = []
        for match in _CSS_HIDDEN_RE.finditer(content):
            style_attr = match.group(2)
            inner_text = match.group(3).strip()

            # 숨김 CSS가 적용되어 있는지 확인
            is_hidden = any(p.search(style_attr) for p in _CSS_HIDING_PATTERNS)
            if not is_hidden:
                continue

            # 숨긴 텍스트에 인젝션 문구가 있는지 확인 (조합 체크)
            if _has_injection_phrase(inner_text):
                results.append(
                    Finding(
                        pattern_id="css_hidden_text",
                        severity="high",
                        description="CSS로 숨겨진 텍스트에서 인젝션 문구 탐지",
                        location=f"style={style_attr!r}",
                    )
                )
        return results

    @staticmethod
    def _check_html_comment_injection(content: str) -> list[Finding]:
        """HTML 주석 내 인젝션 시도 탐지"""
        results: list[Finding] = []
        for match in _HTML_COMMENT_RE.finditer(content):
            comment_text = match.group(1).strip()
            if _has_injection_phrase(comment_text):
                results.append(
                    Finding(
                        pattern_id="html_comment_injection",
                        severity="medium",
                        description="HTML 주석에서 인젝션 문구 탐지",
                        location="html_comment",
                    )
                )
        return results

    @staticmethod
    def _check_metadata_injection(content: str) -> list[Finding]:
        """aria-label/alt/title 속성에서 인젝션 탐지"""
        results: list[Finding] = []
        for match in _METADATA_ATTR_RE.finditer(content):
            attr_value = match.group(1)
            if _has_injection_phrase(attr_value):
                results.append(
                    Finding(
                        pattern_id="metadata_injection",
                        severity="medium",
                        description="HTML 메타데이터 속성에서 인젝션 문구 탐지",
                        location="metadata_attr",
                    )
                )
        return results

    @staticmethod
    def _check_markdown_link_payload(content: str) -> list[Finding]:
        """마크다운 링크 텍스트에서 인젝션 탐지"""
        results: list[Finding] = []
        for match in _MD_LINK_RE.finditer(content):
            link_text = match.group(1)
            if _has_injection_phrase(link_text):
                results.append(
                    Finding(
                        pattern_id="markdown_link_payload",
                        severity="medium",
                        description="마크다운 링크 텍스트에서 인젝션 문구 탐지",
                        location="markdown_link",
                    )
                )
        return results

    @staticmethod
    def _check_prompt_injection_keywords(content: str) -> list[Finding]:
        """일반 프롬프트 인젝션 키워드 탐지"""
        results: list[Finding] = []
        for pattern in _PROMPT_INJECTION_PATTERNS:
            if pattern.search(content):
                results.append(
                    Finding(
                        pattern_id="prompt_injection_keywords",
                        severity="high",
                        description="프롬프트 인젝션 키워드 탐지",
                        location="content_body",
                    )
                )
                # 동일 패턴 ID로 중복 추가 방지
                break
        return results

    @staticmethod
    def _check_base64_encoded_instruction(content: str) -> list[Finding]:
        """Base64 인코딩된 인젝션 명령 탐지"""
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
                        description="Base64 인코딩된 인젝션 명령 탐지",
                        location="base64_block",
                    )
                )
                break
        return results

    @staticmethod
    def _check_invisible_unicode(content: str) -> list[Finding]:
        """보이지 않는 유니코드 문자 탐지 (3개 이상 시 경고)"""
        count = sum(1 for ch in content if ch in _INVISIBLE_CHARS)
        if count >= 3:
            return [
                Finding(
                    pattern_id="invisible_unicode",
                    severity="low",
                    description=f"보이지 않는 유니코드 문자 {count}개 탐지",
                    location="content_body",
                )
            ]
        return []

    @staticmethod
    def _check_role_override_attempt(content: str) -> list[Finding]:
        """역할 오버라이드 시도 탐지 (SYSTEM:, Assistant: 등)"""
        results: list[Finding] = []
        if _ROLE_OVERRIDE_RE.search(content):
            results.append(
                Finding(
                    pattern_id="role_override_attempt",
                    severity="medium",
                    description="역할 오버라이드 시도 탐지",
                    location="content_body",
                )
            )
        return results

    # ── excerpt 생성 ──────────────────────────────────────

    def _build_excerpt(self, content: str, findings: Sequence[Finding]) -> str:
        """redacted_excerpt 생성

        store_raw=False: 패턴 요약만 반환
        store_raw=True: 원문 일부 반환
        """
        if not findings:
            return ""

        if not self._store_raw:
            # 패턴 ID 목록 (중복 제거, 순서 유지)
            seen: set[str] = set()
            pattern_ids: list[str] = []
            for f in findings:
                if f.pattern_id not in seen:
                    seen.add(f.pattern_id)
                    pattern_ids.append(f.pattern_id)
            return f"[{len(findings)} finding(s): {', '.join(pattern_ids)}]"

        # store_raw=True: 원문 일부 (최대 200자)
        max_len = 200
        if len(content) <= max_len:
            return content
        return content[:max_len] + "..."
