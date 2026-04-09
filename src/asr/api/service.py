"""Adapters between the HTTP layer and the core SDK."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
import json
from importlib import resources
from pathlib import Path
import re
from typing import Any

from asr import Guard, load_policy_file
from asr.api.config import get_settings
from asr.api.enhanced_pii import install_enhanced_pii
from asr.api.enhanced_scanner import EnhancedScanner


_PRESET_RE = re.compile(r"^[A-Za-z0-9_-]+$")

install_enhanced_pii()


def _serialize_dataclass(value: Any) -> Any:
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, list):
        return [_serialize_dataclass(item) for item in value]
    if isinstance(value, dict):
        return {key: _serialize_dataclass(item) for key, item in value.items()}
    return value


def _load_policy_text(text: str, *, suffix: str) -> dict[str, Any]:
    if suffix == ".json":
        data = json.loads(text)
    elif suffix in {".yaml", ".yml"}:
        try:
            import yaml
        except ImportError as exc:
            raise ImportError(
                "pyyaml is required to load packaged presets: pip install agent-runtime-security[api]"
            ) from exc
        data = yaml.safe_load(text)
    else:
        raise ValueError(f"Unsupported preset format: {suffix}")

    if not isinstance(data, dict):
        raise ValueError("Policy preset must use a mapping at the top level")
    return data


def _find_external_preset_path(preset: str) -> Path | None:
    settings = get_settings()
    if settings.policies_dir is None:
        return None
    for suffix in (".yaml", ".yml", ".json"):
        candidate = settings.policies_dir / f"{preset}{suffix}"
        if candidate.exists():
            return candidate
    return None


def load_policy_preset(preset: str) -> dict[str, Any]:
    """Load a named preset from an override directory or packaged defaults."""
    if not _PRESET_RE.fullmatch(preset):
        raise ValueError("policy_preset may contain only letters, numbers, hyphens, and underscores")

    external_path = _find_external_preset_path(preset)
    if external_path is not None:
        return load_policy_file(str(external_path))

    package_root = resources.files("asr.api.presets")
    for suffix in (".yaml", ".yml", ".json"):
        resource = package_root.joinpath(f"{preset}{suffix}")
        if resource.is_file():
            return _load_policy_text(resource.read_text(encoding="utf-8"), suffix=suffix)

    raise ValueError(f"Unknown policy preset: {preset}")


def available_policy_presets() -> list[str]:
    """Return the names of shipped or overridden presets."""
    names: set[str] = set()

    package_root = resources.files("asr.api.presets")
    for resource in package_root.iterdir():
        if resource.name.endswith((".yaml", ".yml", ".json")):
            names.add(resource.name.rsplit(".", 1)[0])

    settings = get_settings()
    if settings.policies_dir and settings.policies_dir.exists():
        for path in settings.policies_dir.iterdir():
            if path.suffix.lower() in {".yaml", ".yml", ".json"}:
                names.add(path.stem)

    return sorted(names)


def _load_policy_config(
    *,
    policy: dict[str, Any] | None,
    policy_preset: str | None,
    mode: str | None,
) -> dict[str, Any]:
    if policy is not None:
        config = dict(policy)
    else:
        preset = policy_preset or get_settings().default_policy_preset
        config = load_policy_preset(preset)

    if mode is not None:
        config["mode"] = mode
    return config


def scan_content(*, content: str, source_type: str, source_ref: str | None = None) -> dict[str, Any]:
    scanner = EnhancedScanner()
    result = scanner.scan(content, source_type=source_type, source_ref=source_ref)
    return _serialize_dataclass(result)


def decide_tool_use(
    *,
    tool_name: str,
    args: dict[str, Any],
    capabilities: list[str],
    policy: dict[str, Any] | None = None,
    policy_preset: str | None = None,
    mode: str | None = None,
    pii_profiles: list[str] | None = None,
) -> dict[str, Any]:
    config = _load_policy_config(policy=policy, policy_preset=policy_preset, mode=mode)
    if pii_profiles is not None:
        config["pii_profiles"] = pii_profiles
    decision = Guard.from_config(config).before_tool(tool_name, args, capabilities=capabilities)
    return _serialize_dataclass(decision)


def redact_tool_result(
    *,
    tool_name: str,
    result: Any,
    policy: dict[str, Any] | None = None,
    policy_preset: str | None = None,
    mode: str | None = None,
    pii_profiles: list[str] | None = None,
) -> dict[str, Any]:
    config = _load_policy_config(policy=policy, policy_preset=policy_preset, mode=mode)
    if pii_profiles is not None:
        config["pii_profiles"] = pii_profiles
    decision = Guard.from_config(config).after_tool(tool_name, result)
    return _serialize_dataclass(decision)
