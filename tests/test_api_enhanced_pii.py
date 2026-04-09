"""확장 PII 프로필 테스트."""

from __future__ import annotations

import pytest

from asr.api.enhanced_pii import (
    EXTENDED_PROFILES,
    EXTENDED_REDACTION_MAP,
    _detect_extended,
    _luhn_check,
    _tfn_check,
    install_enhanced_pii,
)


@pytest.fixture(autouse=True)
def _install():
    install_enhanced_pii()


# ── Luhn 알고리즘 ────────────────────────────────────────────


class TestLuhn:
    def test_valid_visa(self):
        assert _luhn_check("4111111111111111") is True

    def test_valid_mastercard(self):
        assert _luhn_check("5500000000000004") is True

    def test_invalid_number(self):
        assert _luhn_check("1234567890123456") is False

    def test_too_short(self):
        assert _luhn_check("123456") is False


# ── 일본 (jp) ────────────────────────────────────────────────


class TestJapanPII:
    def test_my_number_with_context(self):
        """문맥 키워드(マイナンバー)가 있으면 탐지."""
        hits = _detect_extended("マイナンバー: 1234 5678 9012", frozenset(["my_number"]))
        types = [h["type"] for h in hits]
        assert "my_number" in types

    def test_my_number_with_english_context(self):
        """영어 문맥 키워드(my number)도 동작."""
        hits = _detect_extended("My Number is 123456789012", frozenset(["my_number"]))
        types = [h["type"] for h in hits]
        assert "my_number" in types

    def test_my_number_no_context_no_match(self):
        """문맥 키워드 없는 12자리 숫자는 탐지하지 않음."""
        hits = _detect_extended("order_id=123456789012", frozenset(["my_number"]))
        types = [h["type"] for h in hits]
        assert "my_number" not in types

    def test_my_number_distant_context_no_match(self):
        """문맥 키워드가 60자 넘게 떨어져 있으면 탐지하지 않음."""
        text = "My Number policy note " + "x" * 200 + " order_id=123456789012"
        hits = _detect_extended(text, frozenset(["my_number"]))
        types = [h["type"] for h in hits]
        assert "my_number" not in types

    def test_jp_phone(self):
        hits = _detect_extended("電話: 090-1234-5678", frozenset(["jp_phone"]))
        types = [h["type"] for h in hits]
        assert "jp_phone" in types

    def test_jp_phone_intl(self):
        hits = _detect_extended("Phone: +81-90-1234-5678", frozenset(["jp_phone"]))
        types = [h["type"] for h in hits]
        assert "jp_phone" in types


# ── 중국 (cn) ────────────────────────────────────────────────


class TestChinaPII:
    def test_citizen_id(self):
        hits = _detect_extended("身份证号: 110101199001011234", frozenset(["cn_citizen_id"]))
        types = [h["type"] for h in hits]
        assert "cn_citizen_id" in types

    def test_citizen_id_with_x(self):
        hits = _detect_extended("ID: 11010119900101123X", frozenset(["cn_citizen_id"]))
        types = [h["type"] for h in hits]
        assert "cn_citizen_id" in types

    def test_cn_phone(self):
        hits = _detect_extended("手机: 13912345678", frozenset(["cn_phone"]))
        types = [h["type"] for h in hits]
        assert "cn_phone" in types


# ── 인도 (in) ────────────────────────────────────────────────


class TestIndiaPII:
    def test_aadhaar(self):
        hits = _detect_extended("Aadhaar: 2345 6789 0123", frozenset(["aadhaar"]))
        types = [h["type"] for h in hits]
        assert "aadhaar" in types

    def test_pan(self):
        hits = _detect_extended("PAN: ABCPD1234E", frozenset(["pan"]))
        types = [h["type"] for h in hits]
        assert "pan" in types

    def test_invalid_pan_no_match(self):
        """4번째 문자가 유효 코드(ABCFGHLJPTK)가 아니면 탐지 안 됨."""
        hits = _detect_extended("PAN: XYZXB1234C", frozenset(["pan"]))
        types = [h["type"] for h in hits]
        assert "pan" not in types


# ── 브라질 (br) ──────────────────────────────────────────────


class TestBrazilPII:
    def test_cpf(self):
        hits = _detect_extended("CPF: 123.456.789-09", frozenset(["cpf"]))
        types = [h["type"] for h in hits]
        assert "cpf" in types

    def test_cnpj(self):
        hits = _detect_extended("CNPJ: 12.345.678/0001-95", frozenset(["cnpj"]))
        types = [h["type"] for h in hits]
        assert "cnpj" in types


# ── 캐나다 (ca) ──────────────────────────────────────────────


class TestCanadaPII:
    def test_sin_valid_luhn(self):
        """Luhn 통과하는 SIN만 탐지."""
        hits = _detect_extended("SIN: 046-454-286", frozenset(["sin"]))
        types = [h["type"] for h in hits]
        assert "sin" in types

    def test_sin_invalid_luhn_no_match(self):
        """Luhn 실패하는 숫자는 탐지하지 않음 (오탐 방지)."""
        hits = _detect_extended("invoice 123-456-789 due", frozenset(["sin"]))
        types = [h["type"] for h in hits]
        assert "sin" not in types


# ── 호주 (au) ────────────────────────────────────────────────


class TestAustraliaPII:
    def test_tfn_valid_checksum(self):
        """가중 체크섬 통과하는 TFN만 탐지."""
        # 가중합 = 8*1+6*4+5*3+5*7+7*5+8*8+9*6+6*9+3*10 = 336 → 336%11=0 ✓
        hits = _detect_extended("TFN: 865 578 963", frozenset(["tfn"]))
        assert _tfn_check("865 578 963") is True
        types = [h["type"] for h in hits]
        assert "tfn" in types

    def test_tfn_invalid_checksum_no_match(self):
        """체크섬 실패하는 숫자는 탐지하지 않음 (오탐 방지)."""
        hits = _detect_extended("ref 123 456 789 ok", frozenset(["tfn"]))
        assert _tfn_check("123 456 789") is False
        types = [h["type"] for h in hits]
        assert "tfn" not in types


# ── 영국 (uk) ────────────────────────────────────────────────


class TestUKPII:
    def test_nino(self):
        hits = _detect_extended("NINO: AB 12 34 56 C", frozenset(["nino"]))
        types = [h["type"] for h in hits]
        assert "nino" in types

    def test_nino_compact(self):
        hits = _detect_extended("NI: AB123456C", frozenset(["nino"]))
        types = [h["type"] for h in hits]
        assert "nino" in types

    def test_invalid_prefix_no_match(self):
        """BG, GB, NK 등은 NINO에 사용 불가."""
        hits = _detect_extended("NI: BG123456C", frozenset(["nino"]))
        types = [h["type"] for h in hits]
        assert "nino" not in types


# ── 싱가포르 / EU VAT / 필리핀 / 말레이시아 ──────────────────


class TestSingaporePII:
    def test_sg_phone_with_context(self):
        hits = _detect_extended("Phone: 8123 4567", frozenset(["sg_phone"]))
        types = [h["type"] for h in hits]
        assert "sg_phone" in types

    def test_sg_phone_with_country_code(self):
        hits = _detect_extended("Reach me at +65 8123 4567", frozenset(["sg_phone"]))
        types = [h["type"] for h in hits]
        assert "sg_phone" in types

    def test_sg_phone_no_context_no_match(self):
        hits = _detect_extended("ref 8123 4567 is your seat number", frozenset(["sg_phone"]))
        types = [h["type"] for h in hits]
        assert "sg_phone" not in types


class TestEUVATPII:
    def test_eu_vat_with_context(self):
        hits = _detect_extended("VAT ID: DE123456789", frozenset(["eu_vat"]))
        types = [h["type"] for h in hits]
        assert "eu_vat" in types

    def test_eu_vat_no_context_no_match(self):
        hits = _detect_extended("order DE123456789 shipped today", frozenset(["eu_vat"]))
        types = [h["type"] for h in hits]
        assert "eu_vat" not in types


class TestPhilippinesPII:
    def test_ph_tin_with_context(self):
        hits = _detect_extended("TIN: 123-456-789-012", frozenset(["ph_tin"]))
        types = [h["type"] for h in hits]
        assert "ph_tin" in types

    def test_ph_sss_with_context(self):
        hits = _detect_extended("SSS: 12-3456789-0", frozenset(["ph_sss"]))
        types = [h["type"] for h in hits]
        assert "ph_sss" in types

    def test_ph_tin_no_context_no_match(self):
        hits = _detect_extended("invoice 123-456-789-012 ready", frozenset(["ph_tin"]))
        types = [h["type"] for h in hits]
        assert "ph_tin" not in types


class TestMalaysiaPII:
    def test_my_nric_with_context(self):
        hits = _detect_extended("MyKad: 900101-12-1234", frozenset(["my_nric"]))
        types = [h["type"] for h in hits]
        assert "my_nric" in types

    def test_my_nric_no_context_no_match(self):
        hits = _detect_extended("dob-like token 900101-12-1234 appeared in log", frozenset(["my_nric"]))
        types = [h["type"] for h in hits]
        assert "my_nric" not in types


# ── 결제 (payment) ──────────────────────────────────────────


class TestPaymentPII:
    def test_visa(self):
        hits = _detect_extended("Card: 4111-1111-1111-1111", frozenset(["credit_card"]))
        types = [h["type"] for h in hits]
        assert "credit_card" in types

    def test_mastercard(self):
        hits = _detect_extended("Card: 5500 0000 0000 0004", frozenset(["credit_card"]))
        types = [h["type"] for h in hits]
        assert "credit_card" in types

    def test_invalid_luhn_no_match(self):
        """Luhn 검증 실패하면 탐지 안 됨."""
        hits = _detect_extended("Card: 4111-1111-1111-1112", frozenset(["credit_card"]))
        types = [h["type"] for h in hits]
        assert "credit_card" not in types


# ── 통합 (SDK PII 패치 동작 확인) ──────────────────────────


class TestIntegrationWithSDK:
    def test_sdk_pii_profiles_extended(self):
        import asr.pii
        for profile in EXTENDED_PROFILES:
            assert profile in asr.pii.PII_PROFILES

    def test_sdk_redaction_map_extended(self):
        import asr.pii
        for label_key in EXTENDED_REDACTION_MAP:
            assert label_key in asr.pii._REDACTION_MAP

    def test_sdk_detect_pii_finds_extended_types(self):
        import asr.pii
        hits = asr.pii.detect_pii("CPF: 123.456.789-09", profiles=["br"])
        types = [h["type"] for h in hits]
        assert "cpf" in types

    def test_sdk_redact_pii_masks_extended_types(self):
        import asr.pii
        result = asr.pii.redact_pii("Card: 4111-1111-1111-1111", profiles=["payment"])
        assert "[CREDIT_CARD]" in result

    def test_sdk_has_pii_with_extended_profile(self):
        import asr.pii
        assert asr.pii.has_pii("NINO: AB123456C", profiles=["uk"]) is True

    def test_sdk_original_profiles_still_work(self):
        """SDK 기본 프로필도 여전히 동작."""
        import asr.pii
        assert asr.pii.has_pii("email: test@example.com", profiles=["global-core"]) is True
        result = asr.pii.redact_pii("SSN: 123-45-6789", profiles=["us"])
        assert "[SSN]" in result


# ── 프로필 메타데이터 ────────────────────────────────────────


class TestProfileMetadata:
    def test_extended_profiles_count(self):
        assert len(EXTENDED_PROFILES) == 13

    def test_all_types_have_redaction_label(self):
        for profile_types in EXTENDED_PROFILES.values():
            for pii_type in profile_types:
                assert pii_type in EXTENDED_REDACTION_MAP, f"{pii_type} has no redaction label"
