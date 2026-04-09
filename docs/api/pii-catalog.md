# PII Profile Catalog

Detailed reference for the 17 PII profiles. Select them with the `pii_profiles` parameter.

> If `pii_profiles` is omitted (`null`), all available profiles run.

---

## SDK Default Profiles (4)

### `global-core`

| PII type | Redaction label | Pattern | Notes |
|----------|-----------------|---------|-------|
| Email | `[EMAIL]` | `user@domain.com` |
| Phone | `[PHONE]` | International or domestic formats, 10+ digits |
| API key | `[API_KEY]` | `sk_`, `pk_`, `api_key=` and similar prefixes with 20+ character values |
| Bearer token | `[BEARER_TOKEN]` | `Bearer ` followed by a 20+ character token |
| Secret | `[SECRET]` | `password=`, `secret=`, `token=` and similar labels with 6+ character values |

**False-positive notes**
- `phone`: any 10+ digit pattern can match, so order numbers or reference codes may need a narrower profile selection
- `secret`: values like `password=test123` are intentionally detected even in development-style text

**Recommended baseline:** include this in almost every deployment.

---

### `kr`

| PII type | Redaction label | Pattern | Notes |
|----------|-----------------|---------|-------|
| Korean resident number | `[KRN]` | `YYMMDD-NNNNNNN` | Month and day validity checks included |
| Business registration number | `[BRN]` | `NNN-NN-NNNNN` |
| Bank account number | `[ACCOUNT]` | 10 to 16 digits, optional hyphens | Total-length validation |

**False-positive notes**
- `account`: 10 to 16 digit sequences are broad enough that generic references can match

**Recommended combination:** `["global-core", "kr"]`

---

### `us`

| PII type | Redaction label | Pattern | Notes |
|----------|-----------------|---------|-------|
| SSN | `[SSN]` | `XXX-XX-XXXX` | Invalid `000`, `666`, `9xx`, `00`, and `0000` ranges are excluded |

**False-positive notes**
- SSN matching is relatively strict, so false positives are lower than many number-only patterns

**Recommended combination:** `["global-core", "us"]`

---

### `eu-iban`

| PII type | Redaction label | Pattern | Notes |
|----------|-----------------|---------|-------|
| IBAN | `[IBAN]` | 2-letter country code + 2 check digits + up to 30 characters |

**Recommended combination:** `["global-core", "eu-iban"]`

---

## API-Extended Profiles (13)

### `jp`

| PII type | Redaction label | Pattern | Validation |
|----------|-----------------|---------|------------|
| My Number | `[MY_NUMBER]` | 12 digits | Nearby context keyword required within 60 characters (`マイナンバー`, `個人番号`, `my number`) |
| Japanese phone | `[JP_PHONE]` | `0X0-XXXX-XXXX` or `+81-X0-XXXX-XXXX` |

**False-positive control**
- My Number is only detected when the keyword context is near the number, which reduces collisions with order IDs and generic references

**Recommended combination:** `["global-core", "jp"]`

---

### `cn`

| PII type | Redaction label | Pattern | Validation |
|----------|-----------------|---------|------------|
| Chinese national ID | `[CN_ID]` | 18 digits | Region prefix, birth year, month, and day validation |
| Chinese mobile phone | `[CN_PHONE]` | `1[3-9]` plus 9 digits |

**Recommended combination:** `["global-core", "cn"]`

---

### `in`

| PII type | Redaction label | Pattern | Validation |
|----------|-----------------|---------|------------|
| Aadhaar | `[AADHAAR]` | 12 digits starting with `2-9` | Total length validation |
| PAN | `[PAN]` | `AAAAA9999A` | Fourth letter must be one of the supported codes |

**False-positive notes**
- PAN is highly structured and tends to be precise
- Aadhaar is broader, but the start digit and grouping rules reduce noise

**Recommended combination:** `["global-core", "in"]` or `["global-core", "in", "payment"]` for payment-heavy flows

---

### `br`

| PII type | Redaction label | Pattern | Validation |
|----------|-----------------|---------|------------|
| CPF | `[CPF]` | `XXX.XXX.XXX-XX` | Punctuation required |
| CNPJ | `[CNPJ]` | `XX.XXX.XXX/XXXX-XX` | Punctuation required |

**False-positive notes**
- Required punctuation keeps false positives low

**Recommended combination:** `["global-core", "br"]`

---

### `ca`

| PII type | Redaction label | Pattern | Validation |
|----------|-----------------|---------|------------|
| SIN | `[SIN]` | `XXX-XXX-XXX` or spaced 9-digit format | Luhn checksum required |

**False-positive control**
- Generic values such as `123-456-789` do not match because they fail checksum validation

**Recommended combination:** `["global-core", "ca"]`

---

### `au`

| PII type | Redaction label | Pattern | Validation |
|----------|-----------------|---------|------------|
| TFN | `[TFN]` | `XXX XXX XXX` | Weighted checksum required |

**False-positive control**
- Generic references are filtered out unless they pass the TFN checksum

**Recommended combination:** `["global-core", "au"]`

---

### `uk`

| PII type | Redaction label | Pattern | Validation |
|----------|-----------------|---------|------------|
| NINO | `[NINO]` | `AB 12 34 56 C` | Restricted prefix list |

**False-positive notes**
- The mixed letter-number format makes false positives relatively low

**Recommended combination:** `["global-core", "uk"]`

---

### `payment`

| PII type | Redaction label | Pattern | Validation |
|----------|-----------------|---------|------------|
| Credit card | `[CREDIT_CARD]` | Visa, Mastercard, Amex, Discover, JCB, UnionPay | Luhn checksum required |

**Supported brands**

| Brand | Prefix | Length |
|-------|--------|--------|
| Visa | `4xxx` | 16 |
| Mastercard | `51xx-55xx` | 16 |
| Amex | `34xx`, `37xx` | 15 |
| Discover | `6011`, `65xx` | 16 |
| JCB | `352x-358x` | 16 |
| UnionPay | `62xx`, `81xx` | 16 |

**False-positive control**
- Only numbers that pass Luhn are detected

**Recommended combination:** `["global-core", "payment"]`, or add a regional profile such as `["global-core", "kr", "payment"]`

---

### `sg`

| PII type | Redaction label | Pattern | Validation |
|----------|-----------------|---------|------------|
| Singapore NRIC / FIN | `[SG_NRIC]` | `S1234567A`-style identifiers | Structural format check |
| Singapore phone | `[SG_PHONE]` | `+65 8123 4567` or local 8-digit mobile/landline format | Country code or nearby phone/contact context required |

**False-positive control**
- Local 8-digit phone matches require nearby context such as `phone`, `mobile`, `contact`, or `+65`

**Recommended combination:** `["global-core", "sg"]`

---

### `eu-vat`

| PII type | Redaction label | Pattern | Validation |
|----------|-----------------|---------|------------|
| EU VAT ID | `[VAT_ID]` | Country prefix plus 8-12 alphanumeric characters | Nearby VAT / tax-ID context required |

**False-positive control**
- Values such as order references with country prefixes are ignored unless VAT or tax-ID context is nearby

**Recommended combination:** `["global-core", "eu-vat"]`

---

### `mx`

| PII type | Redaction label | Pattern | Validation |
|----------|-----------------|---------|------------|
| CURP | `[CURP]` | 18-character personal identifier | Structural format check |
| RFC | `[RFC]` | 12-13 character tax identifier | Structural format check |

**Recommended combination:** `["global-core", "mx"]`

---

### `ph`

| PII type | Redaction label | Pattern | Validation |
|----------|-----------------|---------|------------|
| Philippine TIN | `[PH_TIN]` | `123-456-789-012` | Nearby `TIN` or tax-ID context required |
| Philippine SSS | `[PH_SSS]` | `12-3456789-0` | Nearby `SSS` or social-security context required |

**False-positive control**
- Hyphenated numeric strings are not matched unless TIN or SSS context is nearby

**Recommended combination:** `["global-core", "ph"]`

---

### `my`

| PII type | Redaction label | Pattern | Validation |
|----------|-----------------|---------|------------|
| MyKad / Malaysian NRIC | `[MY_NRIC]` | `900101-12-1234` | Nearby `MyKad`, `NRIC`, or Malaysian identity-card context required |

**False-positive control**
- Date-like numeric strings are ignored unless MyKad / NRIC context is nearby

**Recommended combination:** `["global-core", "my"]`

---

## Profile Combination Guide

| Scenario | Recommended profiles |
|----------|----------------------|
| Korean finance | `["global-core", "kr", "payment"]` |
| US healthcare | `["global-core", "us"]` |
| Japanese enterprise | `["global-core", "jp", "payment"]` |
| Global ecommerce | `["global-core", "payment"]` |
| European compliance | `["global-core", "eu-iban", "uk"]` |
| China service workflow | `["global-core", "cn"]` |
| Brazil fintech | `["global-core", "br", "payment"]` |
| Singapore B2B workflow | `["global-core", "sg"]` |
| EU tax operations | `["global-core", "eu-vat"]` |
| Mexico back office | `["global-core", "mx"]` |
| Minimal baseline | `["global-core"]` |
| All profiles | `null` (omit `pii_profiles`) |
