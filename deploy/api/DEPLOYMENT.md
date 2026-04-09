# Agent Runtime Security API Deployment Guide

This repository includes the full public HTTP API extension. Use this guide when you want to
run the API from the same checkout as the core SDK.

## Recommended Layout

```text
/srv/agent-runtime-security/
  deploy/api/
  docs/api/
  eval/api/
  secrets/
    api_keys.json
  src/asr/api/
    presets/
```

`secrets/` should stay local only. The repository `.gitignore` already excludes it.

## Build Locally

```bash
cd /srv/agent-runtime-security
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[api,dev]"
pytest -q
```

## Create an API Key File

```bash
mkdir -p secrets
python3 - <<'PY'
import hashlib
import json
import secrets
from pathlib import Path

api_key = "td_" + secrets.token_urlsafe(32)
api_hash = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
Path("secrets/api_keys.json").write_text(
    json.dumps({"keys": [{"name": "prod-admin", "hash": api_hash}]}, indent=2),
    encoding="utf-8",
)
print(f"API key: {api_key}")
PY
```

Store the printed key somewhere safe. Only the SHA-256 hash is kept on disk.

## Docker Build

```bash
cd /srv/agent-runtime-security
docker build -f deploy/api/Dockerfile -t agent-runtime-security-api .
```

## Run The Container

```bash
docker run -d \
  --name agent-runtime-security-api \
  --restart unless-stopped \
  -p 127.0.0.1:8000:8000 \
  -v /srv/agent-runtime-security/secrets:/workspace/secrets:ro \
  -e ASR_AUTH_ENABLED=true \
  -e ASR_API_KEYS_FILE=/workspace/secrets/api_keys.json \
  -e ASR_LOG_LEVEL=INFO \
  agent-runtime-security-api
```

Optional:

- Set `ASR_ROOT_PATH=/api` when serving behind a reverse proxy on `/api`
- Set `ASR_POLICIES_DIR=/workspace/policies` if you want custom preset overrides
- Use legacy `TRAPDEFENSE_*` env vars only if you need backward compatibility with older scripts

## Health Check

```bash
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/docs
```

## nginx Example

When serving the API on `https://your-domain.example/api`, start the container with
`ASR_ROOT_PATH=/api` and use a path-based nginx proxy:

```nginx
limit_req_zone $binary_remote_addr zone=asr_api:10m rate=10r/s;

location /api/ {
    limit_req zone=asr_api burst=20 nodelay;

    proxy_pass http://127.0.0.1:8000/;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Request-ID $request_id;
    proxy_read_timeout 30s;
    proxy_connect_timeout 10s;
    client_max_body_size 256k;
}
```

Then verify:

```bash
curl https://your-domain.example/api/health
curl https://your-domain.example/api/docs
```

## Updating A Deployment

```bash
cd /srv/agent-runtime-security
git pull
docker build -f deploy/api/Dockerfile -t agent-runtime-security-api .
docker stop agent-runtime-security-api || true
docker rm agent-runtime-security-api || true
docker run -d \
  --name agent-runtime-security-api \
  --restart unless-stopped \
  -p 127.0.0.1:8000:8000 \
  -v /srv/agent-runtime-security/secrets:/workspace/secrets:ro \
  -e ASR_AUTH_ENABLED=true \
  -e ASR_API_KEYS_FILE=/workspace/secrets/api_keys.json \
  agent-runtime-security-api
```

## Troubleshooting

```bash
docker logs agent-runtime-security-api --tail 50
docker ps -a | grep agent-runtime-security-api
docker exec agent-runtime-security-api cat /workspace/secrets/api_keys.json
```

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `ASR_AUTH_ENABLED` | `true` | Enable Bearer token authentication |
| `ASR_API_KEYS_FILE` | `secrets/api_keys.json` | JSON file with API key hashes |
| `ASR_API_PREFIX` | `/v1` | Prefix for API routes |
| `ASR_ROOT_PATH` | `""` | Reverse-proxy mount path such as `/api` |
| `ASR_LOG_LEVEL` | `INFO` | Log level |
| `ASR_POLICIES_DIR` | unset | External preset override directory |
| `ASR_DEFAULT_POLICY_PRESET` | `default` | Default preset name |
