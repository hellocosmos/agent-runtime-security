"""Application settings for the ASR HTTP extension."""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]


def _env(*names: str, default: str | None = None) -> str | None:
    for name in names:
        value = os.getenv(name)
        if value is not None:
            return value
    return default


def _env_bool(*names: str, default: bool) -> bool:
    value = _env(*names)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class APISettings:
    app_name: str
    environment: str
    api_prefix: str
    root_path: str
    log_level: str
    auth_enabled: bool
    api_keys_file: Path
    policies_dir: Path | None
    default_policy_preset: str


@lru_cache(maxsize=1)
def get_settings() -> APISettings:
    policies_dir_raw = _env(
        "ASR_POLICIES_DIR",
        "TRAPDEFENSE_POLICIES_DIR",
    )
    return APISettings(
        app_name="Agent Runtime Security API",
        environment=_env(
            "ASR_ENV",
            "ASR_ENVIRONMENT",
            "TRAPDEFENSE_ENV",
            "TRAPDEFENSE_ENVIRONMENT",
            default="development",
        )
        or "development",
        api_prefix=_env("ASR_API_PREFIX", "TRAPDEFENSE_API_PREFIX", default="/v1") or "/v1",
        root_path=_env("ASR_ROOT_PATH", "TRAPDEFENSE_ROOT_PATH", default="") or "",
        log_level=_env("ASR_LOG_LEVEL", "TRAPDEFENSE_LOG_LEVEL", default="INFO") or "INFO",
        auth_enabled=_env_bool("ASR_AUTH_ENABLED", "TRAPDEFENSE_AUTH_ENABLED", default=True),
        api_keys_file=Path(
            _env(
                "ASR_API_KEYS_FILE",
                "TRAPDEFENSE_API_KEYS_FILE",
                default=str(PROJECT_ROOT / "secrets" / "api_keys.json"),
            )
            or (PROJECT_ROOT / "secrets" / "api_keys.json")
        ),
        policies_dir=Path(policies_dir_raw) if policies_dir_raw else None,
        default_policy_preset=_env(
            "ASR_DEFAULT_POLICY_PRESET",
            "TRAPDEFENSE_DEFAULT_POLICY_PRESET",
            default="default",
        )
        or "default",
    )


def clear_settings_cache() -> None:
    """Clear memoized settings for tests or process reloads."""
    get_settings.cache_clear()
