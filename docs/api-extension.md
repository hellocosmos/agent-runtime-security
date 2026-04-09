# API Extension

Agent Runtime Security includes an optional FastAPI wrapper inside the main repository. The goal is to expose the same scanner, guard, and redaction primitives over HTTP without splitting them into a separate codebase.

Install the extra:

```bash
pip install "agent-runtime-security[api]"
```

Run the local server:

```bash
asr-api
```

Or run it explicitly with Uvicorn:

```bash
uvicorn asr.api.main:app --host 0.0.0.0 --port 8000
```

Default endpoints:

- `GET /health`
- `POST /v1/scan`
- `POST /v1/decide`
- `POST /v1/redact`

Minimal API key store:

```json
{
  "keys": [
    {
      "name": "local-dev",
      "hash": "sha256_of_your_api_key"
    }
  ]
}
```

Set `ASR_API_KEYS_FILE` to that JSON file. When `ASR_AUTH_ENABLED=false`, the auth dependency is bypassed for local development.

The repository now includes the full public API kit:

- FastAPI app under `src/asr/api`
- 17 packaged policy presets
- full API docs under `docs/api`
- eval fixtures and runner under `eval/api`
- Docker and nginx deployment examples under `deploy/api`

Preset lookup order:

1. `ASR_POLICIES_DIR` override directory, if configured
2. Packaged presets under `asr.api.presets`

Useful environment variables:

- `ASR_AUTH_ENABLED`
- `ASR_API_KEYS_FILE`
- `ASR_API_PREFIX`
- `ASR_ROOT_PATH`
- `ASR_POLICIES_DIR`
- `ASR_DEFAULT_POLICY_PRESET`

The API helpers also accept the legacy `TRAPDEFENSE_*` variable names for compatibility with older local deployments.

Related files:

- App entrypoint: [`../src/asr/api/main.py`](../src/asr/api/main.py)
- Service adapter: [`../src/asr/api/service.py`](../src/asr/api/service.py)
- Packaged presets: [`../src/asr/api/presets`](../src/asr/api/presets)
- API tests: [`../tests/test_api.py`](../tests/test_api.py)
- Extended docs: [`./api/overview.md`](./api/overview.md)
- Deploy docs: [`../deploy/api/DEPLOYMENT.md`](../deploy/api/DEPLOYMENT.md)
