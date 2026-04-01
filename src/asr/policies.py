"""정책 평가 함수 — 각 정책은 dict | None을 반환. None이면 비해당."""
from __future__ import annotations
import fnmatch
import ipaddress
import pathlib
from urllib.parse import urlparse
from asr.pii import has_pii


def evaluate_tool_blocklist(tool_name: str, args: dict, *, blocklist: list[str]) -> dict | None:
    if tool_name in blocklist:
        return {"action": "block", "reason": "tool_in_blocklist", "policy_id": "tool_blocklist", "severity": "high"}
    return None


def evaluate_egress(tool_name: str, args: dict, *, domain_allowlist: list[str], block_egress: bool) -> dict | None:
    if not block_egress:
        return None
    url_str = _extract_url(args)
    if url_str is None:
        return None
    parsed = urlparse(url_str)
    hostname = parsed.hostname
    if hostname is None:
        return None
    if _is_private_or_local(hostname):
        return {"action": "block", "reason": "private_or_local_address", "policy_id": "egress_control", "severity": "high"}
    if not _domain_matches(hostname, domain_allowlist):
        return {"action": "block", "reason": "domain_not_allowed", "policy_id": "domain_allowlist", "severity": "high"}
    return None


def evaluate_file_path(tool_name: str, args: dict, *, allowlist: list[str]) -> dict | None:
    path_str = _extract_path(args)
    if path_str is None:
        return None
    # 민감 경로 우선 검사
    sensitive_patterns = ["**/.ssh/*", "**/.env", "**/.env.*", "**/credentials*", "**/secrets*"]
    for pattern in sensitive_patterns:
        if fnmatch.fnmatch(path_str, pattern):
            return {"action": "block", "reason": "sensitive_path", "policy_id": "file_path_allowlist", "severity": "high"}
    # 경로 정규화 후 자식 디렉토리인지 확인
    resolved = pathlib.Path(path_str).resolve()
    for allowed in allowlist:
        allowed_resolved = pathlib.Path(allowed).resolve()
        try:
            resolved.relative_to(allowed_resolved)
            return None
        except ValueError:
            continue
    return {"action": "block", "reason": "path_not_allowed", "policy_id": "file_path_allowlist", "severity": "medium"}


def evaluate_pii(tool_name: str, args: dict, *, pii_action: str) -> dict | None:
    if pii_action == "off":
        return None
    args_text = _args_to_text(args)
    if not has_pii(args_text):
        return None
    return {"action": pii_action, "reason": "pii_detected_in_args", "policy_id": "pii_detection",
            "severity": "high" if pii_action == "block" else "medium"}


def evaluate_capability(*, capabilities: list[str] | None, policy: dict[str, str]) -> dict | None:
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
    return {"action": worst_action, "reason": f"capability_{worst_cap}", "policy_id": "capability_policy",
            "severity": "high" if worst_action == "block" else "medium" if worst_action == "warn" else "low"}


def evaluate_unknown_tool(*, default: str) -> dict:
    return {"action": default, "reason": "unknown_tool", "policy_id": "default_action",
            "severity": "medium" if default == "warn" else "high"}


def has_url(args: dict) -> bool:
    """args에 URL이 있는지 확인 (Guard에서 사용)"""
    return _extract_url(args) is not None


# --- 내부 유틸리티 ---

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

def _args_to_text(args: dict) -> str:
    parts = []
    for value in args.values():
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, dict):
            parts.append(_args_to_text(value))
    return " ".join(parts)
