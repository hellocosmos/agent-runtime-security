"""Validation helpers for Guard policy configuration."""

from __future__ import annotations


KNOWN_CONFIG_KEYS = {
    "version",
    "mode",
    "domain_allowlist",
    "file_path_allowlist",
    "pii_action",
    "pii_profiles",
    "block_egress",
    "tool_blocklist",
    "capability_policy",
    "default_action",
}

_VALID_VALUES = {
    "mode": ("enforce", "warn", "shadow"),
    "pii_action": ("off", "warn", "block"),
    "default_action": ("allow", "warn", "block"),
}


def validate_guard_config(config: dict) -> None:
    """Validate a policy config dictionary."""
    if "version" not in config:
        raise ValueError("Policy files must include a 'version' field")
    if config["version"] != 1:
        raise ValueError(
            f"Unsupported version: {config['version']}. Only version 1 is supported"
        )

    unknown = set(config.keys()) - KNOWN_CONFIG_KEYS
    if unknown:
        raise ValueError(f"Unknown policy field(s): {', '.join(sorted(unknown))}")

    for field, valid in _VALID_VALUES.items():
        if field in config and config[field] not in valid:
            raise ValueError(
                f"Invalid value for '{field}': {config[field]!r}. "
                f"Allowed: {', '.join(valid)}"
            )

    for field in ("domain_allowlist", "file_path_allowlist", "tool_blocklist"):
        if field in config:
            value = config[field]
            if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                raise ValueError(f"'{field}' must be a list of strings")

    if "block_egress" in config and not isinstance(config["block_egress"], bool):
        raise ValueError("'block_egress' must be a bool")

    if "capability_policy" not in config:
        return

    capability_policy = config["capability_policy"]
    if not isinstance(capability_policy, dict):
        raise ValueError("'capability_policy' must be a dict")

    valid_actions = ("allow", "warn", "block")
    for capability, action in capability_policy.items():
        if action not in valid_actions:
            raise ValueError(
                f"Invalid 'capability_policy' value: "
                f"{capability}={action!r}. Allowed: {', '.join(valid_actions)}"
            )
