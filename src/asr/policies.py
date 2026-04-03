"""Policy evaluators.

Each evaluator returns a typed policy match or ``None`` when it does not apply.
"""
from __future__ import annotations
import fnmatch
import ipaddress
import pathlib
from urllib.parse import urlparse
from asr.pii import has_pii
from asr.types import PolicyMatch


def evaluate_tool_blocklist(tool_name: str, args: dict, *, blocklist: list[str]) -> PolicyMatch | None:
    if tool_name in blocklist:
        return _match("block", "tool_in_blocklist", "tool_blocklist", "high")
    return None


def evaluate_egress(
    tool_name: str,
    args: dict,
    *,
    domain_allowlist: list[str],
    block_egress: bool,
) -> PolicyMatch | None:
    if not block_egress:
        return None
    url_str = _extract_url(args)
    if url_str is not None:
        parsed = urlparse(url_str)
        hostname = parsed.hostname
        if hostname is None:
            return None
        if _is_private_or_local(hostname):
            return _match("block", "private_or_local_address", "egress_control", "high")
        if not _domain_matches(hostname, domain_allowlist):
            return _match("block", "domain_not_allowed", "domain_allowlist", "high")
        return None
    # If there is no URL, inspect email-recipient fields instead.
    email_dest = _extract_email_destination(args)
    if email_dest is not None:
        email_domain = email_dest.split("@")[1] if "@" in email_dest else None
        if email_domain and not _domain_matches(email_domain, domain_allowlist):
            return _match("warn", "email_destination_not_in_allowlist", "egress_control", "medium")
    return None


def evaluate_file_path(tool_name: str, args: dict, *, allowlist: list[str]) -> PolicyMatch | None:
    path_str = _extract_path(args)
    if path_str is None:
        return None
    # Sensitive path patterns take priority.
    sensitive_patterns = ["**/.ssh/*", "**/.env", "**/.env.*", "**/credentials*", "**/secrets*"]
    for pattern in sensitive_patterns:
        if fnmatch.fnmatch(path_str, pattern):
            return _match("block", "sensitive_path", "file_path_allowlist", "high")
    # Normalize the path, then verify it is inside an allowed directory.
    resolved = pathlib.Path(path_str).resolve()
    for allowed in allowlist:
        allowed_resolved = pathlib.Path(allowed).resolve()
        try:
            resolved.relative_to(allowed_resolved)
            return None
        except ValueError:
            continue
    return _match("block", "path_not_allowed", "file_path_allowlist", "medium")


def evaluate_pii(tool_name: str, args: dict, *, pii_action: str) -> PolicyMatch | None:
    if pii_action == "off":
        return None
    args_text = _args_to_text(args)
    if not has_pii(args_text):
        return None
    severity = "high" if pii_action == "block" else "medium"
    return _match(pii_action, "pii_detected_in_args", "pii_detection", severity)


def evaluate_capability(*, capabilities: list[str] | None, policy: dict[str, str]) -> PolicyMatch | None:
    if not capabilities:
        return None
    _priority = {"block": 3, "warn": 2, "allow": 1}
    worst_action = "allow"
    worst_cap = capabilities[0]
    for cap in capabilities:
        action = policy.get(cap, "warn")
        if _priority.get(action, 0) > _priority.get(worst_action, 0):
            worst_action = action
            worst_cap = cap
    severity = "high" if worst_action == "block" else "medium" if worst_action == "warn" else "low"
    return _match(worst_action, f"capability_{worst_cap}", "capability_policy", severity)


def evaluate_unknown_tool(*, default: str) -> PolicyMatch:
    severity = "medium" if default == "warn" else "high"
    return _match(default, "unknown_tool", "default_action", severity)


def has_url(args: dict) -> bool:
    """Return whether ``args`` contains a URL field used by Guard."""
    return _extract_url(args) is not None


def has_email_destination(args: dict) -> bool:
    """Return whether ``args`` contains an email destination used by Guard."""
    return _extract_email_destination(args) is not None


# --- Internal helpers ---

def _match(action: str, reason: str, policy_id: str, severity: str) -> PolicyMatch:
    return PolicyMatch(
        action=action,
        reason=reason,
        policy_id=policy_id,
        severity=severity,
    )


def _extract_url(args: dict) -> str | None:
    for key in ("url", "endpoint", "uri", "href", "target"):
        if key in args and isinstance(args[key], str):
            if args[key].startswith(("http://", "https://")):
                return args[key]
    return None

def _extract_path(args: dict) -> str | None:
    for key in ("path", "file_path", "filepath", "file", "filename"):
        if key in args and isinstance(args[key], str):
            return args[key]
    return None

def _is_private_or_local(hostname: str) -> bool:
    if hostname in ("localhost",):
        return True
    try:
        addr = ipaddress.ip_address(hostname)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False

def _domain_matches(hostname: str, allowlist: list[str]) -> bool:
    for pattern in allowlist:
        if pattern.startswith("*."):
            suffix = pattern[1:]
            if hostname.endswith(suffix) or hostname == pattern[2:]:
                return True
        else:
            if hostname == pattern:
                return True
    return False

def _extract_email_destination(args: dict) -> str | None:
    """Extract an email address from recipient-related fields."""
    for key in ("to", "recipient", "recipients"):
        if key in args:
            val = args[key]
            if isinstance(val, str) and "@" in val:
                return val
            if isinstance(val, list) and val and isinstance(val[0], str) and "@" in val[0]:
                return val[0]
    return None

def _args_to_text(args: dict) -> str:
    # Skip recipient fields so normal email destinations do not trigger PII blocking.
    _RECIPIENT_KEYS = {"to", "from", "recipient", "recipients", "cc", "bcc"}
    parts = []
    for key, value in args.items():
        if key in _RECIPIENT_KEYS:
            continue
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, dict):
            parts.append(_args_to_text(value))
    return " ".join(parts)
