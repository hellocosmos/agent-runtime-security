"""Extended PII profiles used by the HTTP API extension.

This module patches the SDK's runtime PII registry with additional regional
profiles and payment-card detection.
"""

from __future__ import annotations

import re

# ──────────────────────────────────────────────────────────────
# Japan (jp)
# ──────────────────────────────────────────────────────────────
# My Number (個人番号): 12 digits with nearby context keywords required
_MY_NUMBER_RE = re.compile(r"\b(\d{4})\s?(\d{4})\s?(\d{4})\b")
_MY_NUMBER_CONTEXT_RE = re.compile(
    r"(?:マイナンバー|個人番号|my[\s_-]?number|individual[\s_-]?number)",
    re.IGNORECASE,
)

# Japanese phone number: 0X0-XXXX-XXXX or +81-X0-XXXX-XXXX
_JP_PHONE_RE = re.compile(
    r"(?:\+81[-\s]?\d{1,2}[-\s]?\d{4}[-\s]?\d{4})"
    r"|(?:0[1-9]0[-\s]?\d{4}[-\s]?\d{4})"
)

# ──────────────────────────────────────────────────────────────
# China (cn)
# ──────────────────────────────────────────────────────────────
# Citizen ID (身份证号): 18 digits, last character can be a digit or X
_CN_CITIZEN_ID_RE = re.compile(
    r"\b[1-6]\d{5}"                   # 6-digit region code
    r"(?:19|20)\d{2}"                 # 4-digit birth year
    r"(?:0[1-9]|1[0-2])"             # month
    r"(?:0[1-9]|[12]\d|3[01])"       # day
    r"\d{3}[\dXx]\b"                  # 3-digit sequence + 1 check digit
)

# Chinese mobile number: 11 digits starting with 1[3-9]
_CN_PHONE_RE = re.compile(r"\b1[3-9]\d{9}\b")

# ──────────────────────────────────────────────────────────────
# India (in)
# ──────────────────────────────────────────────────────────────
# Aadhaar: 12 digits starting with 2-9, spaces allowed
_AADHAAR_RE = re.compile(r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b")

# PAN (Permanent Account Number): AAAAA9999A (5 letters + 4 digits + 1 letter)
_PAN_RE = re.compile(r"\b[A-Z]{3}[ABCFGHLJPTK][A-Z]\d{4}[A-Z]\b")

# ──────────────────────────────────────────────────────────────
# Brazil (br)
# ──────────────────────────────────────────────────────────────
# CPF: XXX.XXX.XXX-XX (11 digits)
_CPF_RE = re.compile(r"\b(\d{3})\.(\d{3})\.(\d{3})-(\d{2})\b")

# CNPJ: XX.XXX.XXX/XXXX-XX (14 digits)
_CNPJ_RE = re.compile(r"\b(\d{2})\.(\d{3})\.(\d{3})/(\d{4})-(\d{2})\b")

# ──────────────────────────────────────────────────────────────
# Canada (ca)
# ──────────────────────────────────────────────────────────────
# SIN (Social Insurance Number): XXX-XXX-XXX (9 digits, Luhn-validated)
_SIN_RE = re.compile(r"\b(\d{3})[-\s](\d{3})[-\s](\d{3})\b")

# ──────────────────────────────────────────────────────────────
# Australia (au)
# ──────────────────────────────────────────────────────────────
# TFN (Tax File Number): XXX XXX XXX (9 digits, weighted checksum)
_TFN_RE = re.compile(r"\b(\d{3})\s(\d{3})\s(\d{3})\b")
_TFN_WEIGHTS = (1, 4, 3, 7, 5, 8, 6, 9, 10)


def _tfn_check(number_str: str) -> bool:
    """Validate an Australian TFN using its weighted checksum."""
    digits = [int(d) for d in re.sub(r"\D", "", number_str)]
    if len(digits) != 9:
        return False
    return sum(d * w for d, w in zip(digits, _TFN_WEIGHTS)) % 11 == 0

# ──────────────────────────────────────────────────────────────
# United Kingdom (uk)
# ──────────────────────────────────────────────────────────────
# NINO (National Insurance Number): AB 12 34 56 C
_NINO_RE = re.compile(
    r"\b(?!BG|GB|NK|KN|TN|NT|ZZ)[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]"
    r"\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b",
    re.IGNORECASE,
)

# ──────────────────────────────────────────────────────────────
# Singapore (sg)
# ──────────────────────────────────────────────────────────────
# NRIC/FIN: [STFGM]NNNNNNN[A-Z] (1 letter + 7 digits + 1 letter)
_SG_NRIC_RE = re.compile(r"\b[STFGM]\d{7}[A-Z]\b")

# Singapore phone number: +65 XXXX XXXX or 8 digits starting with 6/8/9
_SG_PHONE_RE = re.compile(r"(?:\+65[-\s]?)?[689]\d{3}[-\s]?\d{4}\b")

# ──────────────────────────────────────────────────────────────
# EU VAT (eu-vat)
# ──────────────────────────────────────────────────────────────
# VAT ID: 2-letter country code plus alphanumeric suffix (8-12 chars)
_EU_VAT_RE = re.compile(
    r"\b(?:AT|BE|BG|CY|CZ|DE|DK|EE|EL|ES|FI|FR|HR|HU|IE|IT|LT|LU|LV|MT|NL|PL|PT|RO|SE|SI|SK)"
    r"[A-Z0-9]{8,12}\b"
)

# ──────────────────────────────────────────────────────────────
# Mexico (mx)
# ──────────────────────────────────────────────────────────────
# CURP: 18 chars (4 letters + 6 digits + 6 letters + 2 alphanumerics)
_CURP_RE = re.compile(r"\b[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]{2}\b")

# RFC: 12-13 chars (12 for orgs, 13 for individuals)
_RFC_RE = re.compile(r"\b[A-ZÑ&]{3,4}\d{6}[A-Z0-9]{2,3}\b")

# ──────────────────────────────────────────────────────────────
# Philippines (ph)
# ──────────────────────────────────────────────────────────────
# TIN: XXX-XXX-XXX-XXX (12 digits, hyphen-separated)
_PH_TIN_RE = re.compile(r"\b(\d{3})-(\d{3})-(\d{3})-(\d{3})\b")

# SSS: XX-XXXXXXX-X (10 digits, hyphen-separated)
_PH_SSS_RE = re.compile(r"\b(\d{2})-(\d{7})-(\d{1})\b")

# ──────────────────────────────────────────────────────────────
# Malaysia (my)
# ──────────────────────────────────────────────────────────────
# MyKad NRIC: YYMMDD-SS-NNNN (6 digits - 2 digits - 4 digits)
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
# Payment data (payment)
# ──────────────────────────────────────────────────────────────
# Credit cards: major brand patterns with Luhn validation
_CREDIT_CARD_RE = re.compile(
    r"\b(?:"
    r"4\d{3}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}"      # Visa 16 digits
    r"|5[1-5]\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}" # Mastercard
    r"|3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}"              # Amex
    r"|6(?:011|5\d{2})[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}"  # Discover
    r"|35(?:2[89]|[3-8]\d)[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}"  # JCB
    r"|(?:62|81)\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}"  # UnionPay
    r")\b"
)


def _luhn_check(number_str: str, *, min_len: int = 13, max_len: int = 19) -> bool:
    """Validate a number string using the Luhn algorithm."""
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
    """Return whether identifying context appears near the match."""
    window_start = max(0, start - window)
    window_end = min(len(text), end + window)
    return bool(context_re.search(text[window_start:window_end]))


# ── Profile definitions ──────────────────────────────────────

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

# Priority for extended types (lower wins)
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
    """Detect extended PII types."""
    hits: list[dict] = []

    # Japan: require context keywords within a 60-character window
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

    # China
    if active_types is None or "cn_citizen_id" in active_types:
        for m in _CN_CITIZEN_ID_RE.finditer(text):
            hits.append({"type": "cn_citizen_id", "value": m.group(), "start": m.start(), "end": m.end()})

    if active_types is None or "cn_phone" in active_types:
        for m in _CN_PHONE_RE.finditer(text):
            hits.append({"type": "cn_phone", "value": m.group(), "start": m.start(), "end": m.end()})

    # India
    if active_types is None or "aadhaar" in active_types:
        for m in _AADHAAR_RE.finditer(text):
            digits = re.sub(r"\D", "", m.group())
            if len(digits) == 12:
                hits.append({"type": "aadhaar", "value": m.group(), "start": m.start(), "end": m.end()})

    if active_types is None or "pan" in active_types:
        for m in _PAN_RE.finditer(text):
            hits.append({"type": "pan", "value": m.group(), "start": m.start(), "end": m.end()})

    # Brazil
    if active_types is None or "cpf" in active_types:
        for m in _CPF_RE.finditer(text):
            hits.append({"type": "cpf", "value": m.group(), "start": m.start(), "end": m.end()})

    if active_types is None or "cnpj" in active_types:
        for m in _CNPJ_RE.finditer(text):
            hits.append({"type": "cnpj", "value": m.group(), "start": m.start(), "end": m.end()})

    # Canada: require 9 digits and a valid Luhn checksum
    if active_types is None or "sin" in active_types:
        for m in _SIN_RE.finditer(text):
            digits = re.sub(r"\D", "", m.group())
            if len(digits) == 9 and _luhn_check(digits, min_len=9, max_len=9):
                hits.append({"type": "sin", "value": m.group(), "start": m.start(), "end": m.end()})

    # Australia: require the TFN weighted checksum
    if active_types is None or "tfn" in active_types:
        for m in _TFN_RE.finditer(text):
            if _tfn_check(m.group()):
                hits.append({"type": "tfn", "value": m.group(), "start": m.start(), "end": m.end()})

    # United Kingdom
    if active_types is None or "nino" in active_types:
        for m in _NINO_RE.finditer(text):
            hits.append({"type": "nino", "value": m.group(), "start": m.start(), "end": m.end()})

    # Payment
    if active_types is None or "credit_card" in active_types:
        for m in _CREDIT_CARD_RE.finditer(text):
            if _luhn_check(m.group()):
                hits.append({"type": "credit_card", "value": m.group(), "start": m.start(), "end": m.end()})

    # Singapore
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

    # Mexico
    if active_types is None or "curp" in active_types:
        for m in _CURP_RE.finditer(text):
            hits.append({"type": "curp", "value": m.group(), "start": m.start(), "end": m.end()})

    if active_types is None or "rfc" in active_types:
        for m in _RFC_RE.finditer(text):
            hits.append({"type": "rfc", "value": m.group(), "start": m.start(), "end": m.end()})

    # Philippines
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

    # Malaysia
    if active_types is None or "my_nric" in active_types:
        for m in _MY_NRIC_RE.finditer(text):
            if not _has_nearby_context(text, m.start(), m.end(), _MY_NRIC_CONTEXT_RE):
                continue
            hits.append({"type": "my_nric", "value": m.group(), "start": m.start(), "end": m.end()})

    return hits


# ── Installation hook ────────────────────────────────────────

_installed = False


def install_enhanced_pii() -> None:
    """Patch the SDK PII module with the extended profiles.

    This should be called once at API startup so the guard, policy, and
    redaction modules all use the enhanced PII helpers.
    """
    global _installed
    if _installed:
        return
    _installed = True

    import asr.guard
    import asr.pii
    import asr.policies
    import asr.redaction

    # 1. Extend the profile registry
    asr.pii.PII_PROFILES.update(EXTENDED_PROFILES)
    asr.pii.AVAILABLE_PROFILES = frozenset(asr.pii.PII_PROFILES.keys())

    # 2. Extend redaction labels
    asr.pii._REDACTION_MAP.update(EXTENDED_REDACTION_MAP)

    # 3. Capture the original detector
    _original_detect = asr.pii.detect_pii

    # 4. Patch detect_pii
    def enhanced_detect_pii(text: str, profiles: list[str] | None = None) -> list[dict]:
        # Base SDK detection
        hits = _original_detect(text, profiles=profiles)
        # Extended type detection
        active_types = asr.pii._get_active_types(profiles)
        extended_hits = _detect_extended(text, active_types)
        if extended_hits:
            hits.extend(extended_hits)
        return asr.pii._remove_overlapping_hits(hits) if hits else hits

    # 5. Patch redact_pii
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

    # 6. Patch has_pii
    def enhanced_has_pii(text: str, profiles: list[str] | None = None) -> bool:
        return len(enhanced_detect_pii(text, profiles=profiles)) > 0

    # 7. Apply patches to every reference point
    asr.pii.detect_pii = enhanced_detect_pii
    asr.pii.redact_pii = enhanced_redact_pii
    asr.pii.has_pii = enhanced_has_pii

    # Also patch imported references held by guard/policies/redaction modules
    asr.guard.has_pii = enhanced_has_pii
    asr.policies.has_pii = enhanced_has_pii
    asr.redaction.redact_pii = enhanced_redact_pii


install_extended_pii = install_enhanced_pii
