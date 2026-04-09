"""Bearer API key authentication for the ASR HTTP extension."""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from asr.api.config import get_settings


security = HTTPBearer(auto_error=False)


def hash_api_key(api_key: str) -> str:
    """Return the stable SHA256 digest for an API key."""
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def _load_hashed_keys(path: Path) -> list[str]:
    with path.open(encoding="utf-8") as file_obj:
        payload = json.load(file_obj)

    raw_keys = payload.get("keys", [])
    if not isinstance(raw_keys, list):
        raise ValueError("API key store must contain a 'keys' list")

    hashes: list[str] = []
    for entry in raw_keys:
        if not isinstance(entry, dict) or "hash" not in entry:
            raise ValueError("Each API key entry must be an object with a 'hash' field")
        hashes.append(str(entry["hash"]))
    return hashes


def verify_api_key(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
) -> str:
    """Validate bearer tokens against the local hashed key store."""
    settings = get_settings()
    if not settings.auth_enabled:
        return "auth-disabled"

    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "auth_required", "message": "Missing Bearer API key"},
        )

    try:
        known_hashes = _load_hashed_keys(settings.api_keys_file)
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "service_unavailable", "message": "API key store is not available"},
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"code": "server_error", "message": str(exc)},
        ) from exc

    supplied_hash = hash_api_key(credentials.credentials)
    if any(hmac.compare_digest(supplied_hash, stored_hash) for stored_hash in known_hashes):
        return supplied_hash

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"code": "auth_invalid", "message": "Invalid API key"},
    )
