"""Extended PII profiles used by the HTTP API extension.

This module patches the SDK's runtime PII registry with additional regional
profiles and payment-card detection.
"""

from __future__ import annotations

import re

# ──────────────────────────────────────────────────────────────
# 일본 (jp)
# ──────────────────────────────────────────────────────────────
# 마이넘버 (個人番号): 12자리 숫자 + 근처에 문맥 키워드 필수
_MY_NUMBER_RE = re.compile(r"\b(\d{4})\s?(\d{4})\s?(\d{4})\b")
_MY_NUMBER_CONTEXT_RE = re.compile(
    r"(?:マイナンバー|個人番号|my[\s_-]?number|individual[\s_-]?number)",
    re.IGNORECASE,
)

# 일본 전화번호: 0X0-XXXX-XXXX 또는 +81-X0-XXXX-XXXX
_JP_PHONE_RE = re.compile(
    r"(?:\+81[-\s]?\d{1,2}[-\s]?\d{4}[-\s]?\d{4})"
    r"|(?:0[1-9]0[-\s]?\d{4}[-\s]?\d{4})"
)

# ──────────────────────────────────────────────────────────────
# 중국 (cn)
# ──────────────────────────────────────────────────────────────
# 신분증 (身份证号): 18자리 (마지막은 숫자 또는 X)
_CN_CITIZEN_ID_RE = re.compile(
    r"\b[1-6]\d{5}"                   # 지역코드 6자리
    r"(?:19|20)\d{2}"                 # 생년 4자리
    r"(?:0[1-9]|1[0-2])"             # 월
    r"(?:0[1-9]|[12]\d|3[01])"       # 일
    r"\d{3}[\dXx]\b"                  # 순번 3자리 + 체크 1자리
)

# 중국 휴대폰: 1[3-9]로 시작하는 11자리
_CN_PHONE_RE = re.compile(r"\b1[3-9]\d{9}\b")

# ──────────────────────────────────────────────────────────────
# 인도 (in)
# ──────────────────────────────────────────────────────────────
# Aadhaar: 12자리 (2-9로 시작, 스페이스 구분 가능)
_AADHAAR_RE = re.compile(r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b")

# PAN (Permanent Account Number): AAAAA9999A (5글자+4숫자+1글자)
_PAN_RE = re.compile(r"\b[A-Z]{3}[ABCFGHLJPTK][A-Z]\d{4}[A-Z]\b")

# ──────────────────────────────────────────────────────────────
# 브라질 (br)
# ──────────────────────────────────────────────────────────────
# CPF: XXX.XXX.XXX-XX (11자리)
_CPF_RE = re.compile(r"\b(\d{3})\.(\d{3})\.(\d{3})-(\d{2})\b")

# CNPJ: XX.XXX.XXX/XXXX-XX (14자리)
_CNPJ_RE = re.compile(r"\b(\d{2})\.(\d{3})\.(\d{3})/(\d{4})-(\d{2})\b")

# ──────────────────────────────────────────────────────────────
# 캐나다 (ca)
# ──────────────────────────────────────────────────────────────
# SIN (Social Insurance Number): XXX-XXX-XXX (9자리, Luhn 검증)
_SIN_RE = re.compile(r"\b(\d{3})[-\s](\d{3})[-\s](\d{3})\b")

# ──────────────────────────────────────────────────────────────
# 호주 (au)
# ──────────────────────────────────────────────────────────────
# TFN (Tax File Number): XXX XXX XXX (9자리, 가중 체크섬)
_TFN_RE = re.compile(r"\b(\d{3})\s(\d{3})\s(\d{3})\b")
_TFN_WEIGHTS = (1, 4, 3, 7, 5, 8, 6, 9, 10)


def _tfn_check(number_str: str) -> bool:
    """호주 TFN 가중 체크섬 검증."""
    digits = [int(d) for d in re.sub(r"\D", "", number_str)]
    if len(digits) != 9:
        return False
    return sum(d * w for d, w in zip(digits, _TFN_WEIGHTS)) % 11 == 0

# ──────────────────────────────────────────────────────────────
# 영국 (uk)
# ──────────────────────────────────────────────────────────────
# NINO (National Insurance Number): AB 12 34 56 C
_NINO_RE = re.compile(
    r"\b(?!BG|GB|NK|KN|TN|NT|ZZ)[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]"
    r"\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b",
    re.IGNORECASE,
)

# ──────────────────────────────────────────────────────────────
# 싱가포르 (sg)
# ──────────────────────────────────────────────────────────────
# NRIC/FIN: [STFGM]NNNNNNN[A-Z] (1글자 + 7숫자 + 1글자)
_SG_NRIC_RE = re.compile(r"\b[STFGM]\d{7}[A-Z]\b")

# 싱가포르 전화번호: +65 XXXX XXXX 또는 6/8/9로 시작 8자리
_SG_PHONE_RE = re.compile(r"(?:\+65[-\s]?)?[689]\d{3}[-\s]?\d{4}\b")

# ──────────────────────────────────────────────────────────────
# EU VAT (eu-vat)
# ──────────────────────────────────────────────────────────────
# VAT ID: 2글자 국가코드 + 숫자/문자 조합 (8~12자리)
_EU_VAT_RE = re.compile(
    r"\b(?:AT|BE|BG|CY|CZ|DE|DK|EE|EL|ES|FI|FR|HR|HU|IE|IT|LT|LU|LV|MT|NL|PL|PT|RO|SE|SI|SK)"
    r"[A-Z0-9]{8,12}\b"
)

# ──────────────────────────────────────────────────────────────
# 멕시코 (mx)
# ──────────────────────────────────────────────────────────────
# CURP: 18자리 (4글자 + 6숫자 + 6글자 + 2영숫자)
_CURP_RE = re.compile(r"\b[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]{2}\b")

# RFC: 12~13자리 (법인 12, 개인 13) - 4글자 + 6숫자 + 2~3영숫자
_RFC_RE = re.compile(r"\b[A-ZÑ&]{3,4}\d{6}[A-Z0-9]{2,3}\b")

# ──────────────────────────────────────────────────────────────
# 필리핀 (ph)
# ──────────────────────────────────────────────────────────────
# TIN: XXX-XXX-XXX-XXX (12자리, 하이픈 구분)
_PH_TIN_RE = re.compile(r"\b(\d{3})-(\d{3})-(\d{3})-(\d{3})\b")

# SSS: XX-XXXXXXX-X (10자리, 하이픈 구분)
_PH_SSS_RE = re.compile(r"\b(\d{2})-(\d{7})-(\d{1})\b")

# ──────────────────────────────────────────────────────────────
# 말레이시아 (my)
# ──────────────────────────────────────────────────────────────
# MyKad NRIC: YYMMDD-SS-NNNN (6숫자-2숫자-4숫자)
_MY_NRIC_RE = re.compile(
    r"\b(\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01]))-(\d{2})-(\d{4})\b"
)

_SG_PHONE_CONTEXT_RE = re.compile(
    r"(?:phone|mobile|tel|contact|call|whatsapp|singapore|sg\b|전화|연락처)",
    re.IGNORECASE,
)
_EU_VAT_CONTEXT_RE = re.compile(
    r"(?:vat|tax\s*id|tax\s*number|ust[\s-]?id|iva|tva|mwst)",
    re.IGNORECASE,
)
_PH_ID_CONTEXT_RE = re.compile(
    r"(?:tin|tax\s*id|bir|sss|social\s*security|philippines|philippine)",
    re.IGNORECASE,
)
_MY_NRIC_CONTEXT_RE = re.compile(
    r"(?:mykad|nric|identity\s*card|malaysia|malaysian|kad\s*pengenalan)",
    re.IGNORECASE,
)

# ──────────────────────────────────────────────────────────────
# 결제 정보 (payment)
# ──────────────────────────────────────────────────────────────
# 신용카드: 주요 브랜드 패턴 (Luhn 검증 포함)
_CREDIT_CARD_RE = re.compile(
    r"\b(?:"
    r"4\d{3}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}"      # Visa 16자리
    r"|5[1-5]\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}" # Mastercard
    r"|3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}"              # Amex
    r"|6(?:011|5\d{2})[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}"  # Discover
    r"|35(?:2[89]|[3-8]\d)[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}"  # JCB
    r"|(?:62|81)\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}"  # UnionPay
    r")\b"
)


def _luhn_check(number_str: str, *, min_len: int = 13, max_len: int = 19) -> bool:
    """Luhn 알고리즘으로 번호 유효성 검증."""
    digits = [int(d) for d in re.sub(r"\D", "", number_str)]
    if len(digits) < min_len or len(digits) > max_len:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _has_nearby_context(
    text: str,
    start: int,
    end: int,
    context_re: re.Pattern[str],
    *,
    window: int = 24,
) -> bool:
    """매치 주변 윈도우 안에 식별 문맥이 있는지 확인."""
    window_start = max(0, start - window)
    window_end = min(len(text), end + window)
    return bool(context_re.search(text[window_start:window_end]))


# ── 프로필 정의 ──────────────────────────────────────────────

EXTENDED_PROFILES: dict[str, list[str]] = {
    "jp": ["my_number", "jp_phone"],
    "cn": ["cn_citizen_id", "cn_phone"],
    "in": ["aadhaar", "pan"],
    "br": ["cpf", "cnpj"],
    "ca": ["sin"],
    "au": ["tfn"],
    "uk": ["nino"],
    "payment": ["credit_card"],
    "sg": ["sg_nric", "sg_phone"],
    "eu-vat": ["eu_vat"],
    "mx": ["curp", "rfc"],
    "ph": ["ph_tin", "ph_sss"],
    "my": ["my_nric"],
}

EXTENDED_REDACTION_MAP: dict[str, str] = {
    "my_number": "[MY_NUMBER]",
    "jp_phone": "[JP_PHONE]",
    "cn_citizen_id": "[CN_ID]",
    "cn_phone": "[CN_PHONE]",
    "aadhaar": "[AADHAAR]",
    "pan": "[PAN]",
    "cpf": "[CPF]",
    "cnpj": "[CNPJ]",
    "sin": "[SIN]",
    "tfn": "[TFN]",
    "nino": "[NINO]",
    "credit_card": "[CREDIT_CARD]",
    "sg_nric": "[SG_NRIC]",
    "sg_phone": "[SG_PHONE]",
    "eu_vat": "[VAT_ID]",
    "curp": "[CURP]",
    "rfc": "[RFC]",
    "ph_tin": "[PH_TIN]",
    "ph_sss": "[PH_SSS]",
    "my_nric": "[MY_NRIC]",
}

# 확장 타입의 우선순위 (낮을수록 우선)
EXTENDED_PRIORITY: dict[str, int] = {
    "cn_citizen_id": 10,
    "aadhaar": 11,
    "my_number": 12,
    "pan": 13,
    "cpf": 14,
    "cnpj": 15,
    "credit_card": 16,
    "nino": 17,
    "sin": 18,
    "tfn": 19,
    "jp_phone": 20,
    "cn_phone": 21,
    "sg_nric": 22,
    "eu_vat": 23,
    "curp": 24,
    "rfc": 25,
    "my_nric": 26,
    "ph_tin": 27,
    "ph_sss": 28,
    "sg_phone": 29,
}


def _detect_extended(text: str, active_types: frozenset[str] | None) -> list[dict]:
    """확장 PII 타입 탐지."""
    hits: list[dict] = []

    # 일본 — match 기준 앞뒤 60자 윈도우 안에 문맥 키워드가 있어야 탐지
    if active_types is None or "my_number" in active_types:
        for m in _MY_NUMBER_RE.finditer(text):
            digits = re.sub(r"\D", "", m.group())
            if len(digits) != 12:
                continue
            window_start = max(0, m.start() - 60)
            window_end = min(len(text), m.end() + 60)
            window = text[window_start:window_end]
            if _MY_NUMBER_CONTEXT_RE.search(window):
                hits.append({"type": "my_number", "value": m.group(), "start": m.start(), "end": m.end()})

    if active_types is None or "jp_phone" in active_types:
        for m in _JP_PHONE_RE.finditer(text):
            hits.append({"type": "jp_phone", "value": m.group(), "start": m.start(), "end": m.end()})

    # 중국
    if active_types is None or "cn_citizen_id" in active_types:
        for m in _CN_CITIZEN_ID_RE.finditer(text):
            hits.append({"type": "cn_citizen_id", "value": m.group(), "start": m.start(), "end": m.end()})

    if active_types is None or "cn_phone" in active_types:
        for m in _CN_PHONE_RE.finditer(text):
            hits.append({"type": "cn_phone", "value": m.group(), "start": m.start(), "end": m.end()})

    # 인도
    if active_types is None or "aadhaar" in active_types:
        for m in _AADHAAR_RE.finditer(text):
            digits = re.sub(r"\D", "", m.group())
            if len(digits) == 12:
                hits.append({"type": "aadhaar", "value": m.group(), "start": m.start(), "end": m.end()})

    if active_types is None or "pan" in active_types:
        for m in _PAN_RE.finditer(text):
            hits.append({"type": "pan", "value": m.group(), "start": m.start(), "end": m.end()})

    # 브라질
    if active_types is None or "cpf" in active_types:
        for m in _CPF_RE.finditer(text):
            hits.append({"type": "cpf", "value": m.group(), "start": m.start(), "end": m.end()})

    if active_types is None or "cnpj" in active_types:
        for m in _CNPJ_RE.finditer(text):
            hits.append({"type": "cnpj", "value": m.group(), "start": m.start(), "end": m.end()})

    # 캐나다 — Luhn 검증 필수 (9자리)
    if active_types is None or "sin" in active_types:
        for m in _SIN_RE.finditer(text):
            digits = re.sub(r"\D", "", m.group())
            if len(digits) == 9 and _luhn_check(digits, min_len=9, max_len=9):
                hits.append({"type": "sin", "value": m.group(), "start": m.start(), "end": m.end()})

    # 호주 — 가중 체크섬 검증 필수
    if active_types is None or "tfn" in active_types:
        for m in _TFN_RE.finditer(text):
            if _tfn_check(m.group()):
                hits.append({"type": "tfn", "value": m.group(), "start": m.start(), "end": m.end()})

    # 영국
    if active_types is None or "nino" in active_types:
        for m in _NINO_RE.finditer(text):
            hits.append({"type": "nino", "value": m.group(), "start": m.start(), "end": m.end()})

    # 결제
    if active_types is None or "credit_card" in active_types:
        for m in _CREDIT_CARD_RE.finditer(text):
            if _luhn_check(m.group()):
                hits.append({"type": "credit_card", "value": m.group(), "start": m.start(), "end": m.end()})

    # 싱가포르
    if active_types is None or "sg_nric" in active_types:
        for m in _SG_NRIC_RE.finditer(text):
            hits.append({"type": "sg_nric", "value": m.group(), "start": m.start(), "end": m.end()})

    if active_types is None or "sg_phone" in active_types:
        for m in _SG_PHONE_RE.finditer(text):
            digits = re.sub(r"\D", "", m.group())
            has_country_prefix = digits.startswith("65") and len(digits) >= 10
            if len(digits) < 8:
                continue
            if not has_country_prefix and not _has_nearby_context(
                text,
                m.start(),
                m.end(),
                _SG_PHONE_CONTEXT_RE,
            ):
                continue
            hits.append({"type": "sg_phone", "value": m.group(), "start": m.start(), "end": m.end()})

    # EU VAT
    if active_types is None or "eu_vat" in active_types:
        for m in _EU_VAT_RE.finditer(text):
            if not _has_nearby_context(text, m.start(), m.end(), _EU_VAT_CONTEXT_RE):
                continue
            hits.append({"type": "eu_vat", "value": m.group(), "start": m.start(), "end": m.end()})

    # 멕시코
    if active_types is None or "curp" in active_types:
        for m in _CURP_RE.finditer(text):
            hits.append({"type": "curp", "value": m.group(), "start": m.start(), "end": m.end()})

    if active_types is None or "rfc" in active_types:
        for m in _RFC_RE.finditer(text):
            hits.append({"type": "rfc", "value": m.group(), "start": m.start(), "end": m.end()})

    # 필리핀
    if active_types is None or "ph_tin" in active_types:
        for m in _PH_TIN_RE.finditer(text):
            if not _has_nearby_context(text, m.start(), m.end(), _PH_ID_CONTEXT_RE):
                continue
            hits.append({"type": "ph_tin", "value": m.group(), "start": m.start(), "end": m.end()})

    if active_types is None or "ph_sss" in active_types:
        for m in _PH_SSS_RE.finditer(text):
            if not _has_nearby_context(text, m.start(), m.end(), _PH_ID_CONTEXT_RE):
                continue
            hits.append({"type": "ph_sss", "value": m.group(), "start": m.start(), "end": m.end()})

    # 말레이시아
    if active_types is None or "my_nric" in active_types:
        for m in _MY_NRIC_RE.finditer(text):
            if not _has_nearby_context(text, m.start(), m.end(), _MY_NRIC_CONTEXT_RE):
                continue
            hits.append({"type": "my_nric", "value": m.group(), "start": m.start(), "end": m.end()})

    return hits


# ── 설치 함수 ────────────────────────────────────────────────

_installed = False


def install_enhanced_pii() -> None:
    """SDK의 PII 모듈을 확장 프로필로 패치한다.

    API 서버 시작 시 한 번만 호출해야 한다.
    Guard, policies, redaction 모듈이 확장된 PII 함수를 사용하게 된다.
    """
    global _installed
    if _installed:
        return
    _installed = True

    import asr.guard
    import asr.pii
    import asr.policies
    import asr.redaction

    # 1. 프로필 레지스트리 확장
    asr.pii.PII_PROFILES.update(EXTENDED_PROFILES)
    asr.pii.AVAILABLE_PROFILES = frozenset(asr.pii.PII_PROFILES.keys())

    # 2. 마스킹 라벨 확장
    asr.pii._REDACTION_MAP.update(EXTENDED_REDACTION_MAP)

    # 3. 원본 함수 저장
    _original_detect = asr.pii.detect_pii

    # 4. 확장 detect_pii
    def enhanced_detect_pii(text: str, profiles: list[str] | None = None) -> list[dict]:
        # SDK 기본 탐지
        hits = _original_detect(text, profiles=profiles)
        # 확장 타입 탐지
        active_types = asr.pii._get_active_types(profiles)
        extended_hits = _detect_extended(text, active_types)
        if extended_hits:
            hits.extend(extended_hits)
        return asr.pii._remove_overlapping_hits(hits) if hits else hits

    # 5. 확장 redact_pii
    def enhanced_redact_pii(text: str, profiles: list[str] | None = None) -> str:
        hits = enhanced_detect_pii(text, profiles=profiles)
        if not hits:
            return text
        hits_deduped = asr.pii._remove_overlapping_hits(hits)
        hits_sorted = sorted(hits_deduped, key=lambda h: h["start"], reverse=True)
        result = text
        for hit in hits_sorted:
            label = asr.pii._REDACTION_MAP.get(hit["type"], "[REDACTED]")
            result = result[:hit["start"]] + label + result[hit["end"]:]
        return result

    # 6. 확장 has_pii
    def enhanced_has_pii(text: str, profiles: list[str] | None = None) -> bool:
        return len(enhanced_detect_pii(text, profiles=profiles)) > 0

    # 7. 모든 참조 지점에 패치 적용
    asr.pii.detect_pii = enhanced_detect_pii
    asr.pii.redact_pii = enhanced_redact_pii
    asr.pii.has_pii = enhanced_has_pii

    # guard.py, policies.py, redaction.py에서 from import한 참조도 패치
    asr.guard.has_pii = enhanced_has_pii
    asr.policies.has_pii = enhanced_has_pii
    asr.redaction.redact_pii = enhanced_redact_pii


install_extended_pii = install_enhanced_pii
