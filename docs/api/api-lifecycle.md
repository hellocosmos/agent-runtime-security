# API Lifecycle

Current versioning and known limits for the API as it exists today.

---

## Current Version

| Item | Value |
|------|-------|
| API version | `v1` |
| Service version | `0.3.0` |
| Base URL | `http://127.0.0.1:8000/v1` |

---

## Versioning Policy

- The API version is part of the URL path: `/v1/scan`, `/v1/decide`, `/v1/redact`
- Breaking changes ship in a new version such as `/v2/`
- Non-breaking additions such as new fields, new patterns, new presets, or new PII profiles may land within the current version

### Non-breaking examples

- New detection patterns
- New policy presets
- New PII profiles
- Additional response fields

### Breaking examples

- Removing an existing field
- Changing a field type
- Renaming pattern IDs
- Changing the response structure
- Replacing the authentication scheme

---

## Changelog

### v1 / 0.3.0 (2026-04-09)

Unified public repository release:

- 3 endpoints: `/v1/scan`, `/v1/decide`, `/v1/redact`
- 32 detection patterns
- 17 policy presets
- 17 PII profiles
- Bearer token authentication
- `shadow`, `warn`, and `enforce` modes
- API docs, eval fixtures, and deploy examples now live in the main repository

---

## Current Limits

| Item | Value |
|------|-------|
| Request size | 256 KB (nginx limit) |

### Known Limitations

| Area | Notes |
|------|-------|
| Pattern detection | Regex-based and strongest on known, explicit patterns |
| PII detection | Format-based; broad numeric formats can still collide with non-PII values |
| Policy evaluation | Stateless; each request is evaluated independently |
| File and binary content | Text-only |
| Language coverage | Strongest for English and Korean patterns today |
| Overlapping PII formats | Some numeric formats can overlap; explicit `pii_profiles` reduce noise |

### Health Check

```bash
curl http://127.0.0.1:8000/health
```

A healthy service returns `{"ok": true}`.

---

## Support

- **Email:** hellocosmos@gmail.com
- **GitHub:** [agent-runtime-security](https://github.com/hellocosmos/agent-runtime-security/issues)
- **Swagger UI:** `http://127.0.0.1:8000/docs`
