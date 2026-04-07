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
    # v2
    "tools",
}

KNOWN_TOOL_KEYS = {
    "capabilities",
    "mode",
    "domain_allowlist",
    "file_path_allowlist",
    "pii_action",
    "pii_profiles",
    "block_egress",
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
    version = config.get("version", 1)
    if version not in (1, 2):
        raise ValueError(
            f"Unsupported version: {version}. Only version 1 and 2 are supported"
        )

    unknown = set(config.keys()) - KNOWN_CONFIG_KEYS
    if unknown:
        raise ValueError(f"Unknown policy field(s): {', '.join(sorted(unknown))}")

    # tools: requires version 2
    if "tools" in config and version < 2:
        raise ValueError(
            "'tools' section requires version: 2. "
            "Set 'version: 2' in your policy file to use per-tool configuration"
        )

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

    if "capability_policy" in config:
        _validate_capability_policy(config["capability_policy"])

    if "tools" in config:
        _validate_tools_section(config["tools"])


def _validate_capability_policy(policy: object, prefix: str = "") -> None:
    """Validate a capability_policy dict."""
    if not isinstance(policy, dict):
        label = f"'{prefix}capability_policy'" if prefix else "'capability_policy'"
        raise ValueError(f"{label} must be a dict")

    valid_actions = ("allow", "warn", "block")
    for capability, action in policy.items():
        if action not in valid_actions:
            label = f"{prefix}capability_policy" if prefix else "capability_policy"
            raise ValueError(
                f"Invalid '{label}' value: "
                f"{capability}={action!r}. Allowed: {', '.join(valid_actions)}"
            )


def _validate_tools_section(tools: object) -> None:
    """Validate the tools: section of a v2 policy file."""
    if not isinstance(tools, dict):
        raise ValueError("'tools' must be a mapping of tool_name -> config")

    for tool_name, tool_config in tools.items():
        if not isinstance(tool_config, dict):
            raise ValueError(f"tools.{tool_name} must be a mapping")

        unknown = set(tool_config.keys()) - KNOWN_TOOL_KEYS
        if unknown:
            raise ValueError(
                f"Unknown key(s) in tools.{tool_name}: "
                f"{', '.join(sorted(unknown))}"
            )

        # capabilities: list of non-empty strings
        if "capabilities" in tool_config:
            caps = tool_config["capabilities"]
            if not isinstance(caps, list) or not all(isinstance(c, str) for c in caps):
                raise ValueError(
                    f"tools.{tool_name}.capabilities must be a list of strings"
                )
            if any(c == "" for c in caps):
                raise ValueError(
                    f"tools.{tool_name}.capabilities items must be non-empty strings"
                )

        # Reuse same validation rules for scalar/list fields
        prefix = f"tools.{tool_name}."
        for field, valid in _VALID_VALUES.items():
            if field in tool_config and tool_config[field] not in valid:
                raise ValueError(
                    f"Invalid value for '{prefix}{field}': "
                    f"{tool_config[field]!r}. Allowed: {', '.join(valid)}"
                )

        for field in ("domain_allowlist", "file_path_allowlist"):
            if field in tool_config:
                value = tool_config[field]
                if not isinstance(value, list) or not all(
                    isinstance(item, str) for item in value
                ):
                    raise ValueError(
                        f"'{prefix}{field}' must be a list of strings"
                    )

        if "block_egress" in tool_config:
            if not isinstance(tool_config["block_egress"], bool):
                raise ValueError(f"'{prefix}block_egress' must be a bool")

        if "capability_policy" in tool_config:
            _validate_capability_policy(tool_config["capability_policy"], prefix=prefix)
