"""Guard module with before_tool/after_tool policy checks and decorators."""
from __future__ import annotations

import functools
import inspect
import logging
import uuid
from typing import Any, Callable

logger = logging.getLogger("asr.guard")

from asr.guard_config import KNOWN_CONFIG_KEYS, validate_guard_config
from asr.pii import has_pii
from asr.policies import (
    evaluate_capability,
    evaluate_egress,
    evaluate_file_path,
    evaluate_pii,
    evaluate_tool_blocklist,
    evaluate_unknown_tool,
    has_email_destination,
    has_url,
)
from asr.redaction import extract_text, redact_args, redact_result
from asr.types import AfterToolDecision, BeforeToolDecision, PolicyMatch


# --- Internal helper: detect file path keys in args ---
_PATH_KEYS = ("path", "file_path", "filepath", "file", "filename")


def _has_path(args: dict) -> bool:
    """Return whether ``args`` contains a file path key."""
    return any(k in args and isinstance(args[k], str) for k in _PATH_KEYS)


class BlockedToolError(Exception):
    """Raised when Guard blocks a tool invocation."""

    def __init__(self, decision: BeforeToolDecision, *, context: dict | None = None):
        self.decision = decision
        self.context = context or {}
        super().__init__(self._short_message())

    def _short_message(self) -> str:
        d = self.decision
        target = self.context.get("target", "")
        target_part = f" to '{target}'" if target else ""
        return (
            f"Blocked: tool '{d.tool_name}'{target_part} "
            f"({d.reason}, policy={d.policy_id}, mode={d.mode})"
        )

    def to_dict(self) -> dict:
        """Return structured error info for logging/API responses."""
        d = self.decision
        return {
            "tool_name": d.tool_name,
            "action": d.action,
            "reason": d.reason,
            "policy_id": d.policy_id,
            "mode": d.mode,
            "severity": d.severity,
            "capabilities": list(d.capabilities),
            "original_action": d.original_action,
            "details": dict(self.context),
        }

    def debug_message(self) -> str:
        """Return human-readable debug output."""
        info = self.to_dict()
        details = info.get("details", {})
        lines = [f"Blocked: tool '{info['tool_name']}'"]
        if "target" in details:
            lines.append(f"  Target: {details['target']}")
        lines.append(f"  Reason: {info['reason']}")
        if "allowed_domains" in details:
            lines.append(f"  Allowed: {', '.join(details['allowed_domains'])}")
        lines.append(f"  Policy: {info['policy_id']} | Mode: {info['mode']}")
        if "trace_id" in details:
            lines.append(f"  Trace: {details['trace_id']}")
        if "fix_hint" in details:
            lines.append(f"  Fix: {details['fix_hint']}")
        return "\n".join(lines)


class Guard:
    """Guard for AI agent tool invocations.

    Policy evaluation order:
    1. tool_blocklist - highest priority
    2. egress (domain_allowlist) - specific policy
    3. file_path_allowlist - specific policy
    4. pii_detection - specific policy
    5. capability_policy - true fallback, only when no specific policy matched
    6. default_action - final fallback
    """

    def __init__(
        self,
        *,
        mode: str = "enforce",
        domain_allowlist: list[str] | None = None,
        file_path_allowlist: list[str] | None = None,
        pii_action: str = "off",
        pii_profiles: list[str] | None = None,
        block_egress: bool = False,
        tool_blocklist: list[str] | None = None,
        capability_policy: dict[str, str] | None = None,
        default_action: str = "warn",
        on_block: Callable | None = None,
        on_warn: Callable | None = None,
        audit: "AuditLogger | None" = None,
        tools: dict[str, dict] | None = None,
    ):
        if mode not in ("enforce", "warn", "shadow"):
            raise ValueError(f"Invalid mode: {mode!r}. Must be 'enforce', 'warn', or 'shadow'")
        self._mode = mode
        self._domain_allowlist = domain_allowlist or []
        self._file_path_allowlist = file_path_allowlist or []
        self._pii_action = pii_action
        self._pii_profiles = pii_profiles
        self._block_egress = block_egress
        self._tool_blocklist = tool_blocklist or []
        self._capability_policy = capability_policy or {}
        self._default_action = default_action
        self._on_block = on_block
        self._on_warn = on_warn
        self._audit = audit
        self._tools = tools or {}
        logger.info("Guard initialized (mode=%s)", self._mode)

    # ------------------------------------------------------------------
    # before_tool
    # ------------------------------------------------------------------
    def before_tool(
        self,
        name: str,
        args: dict,
        context: dict | None = None,
        capabilities: list[str] | None = None,
    ) -> BeforeToolDecision:
        """Evaluate policies before a tool call."""
        config = self._resolve_tool_config(name, capabilities)
        return self._before_tool_with_config(name, args, config, context)

    # ------------------------------------------------------------------
    # after_tool
    # ------------------------------------------------------------------
    def after_tool(
        self,
        name: str,
        result: Any,
        context: dict | None = None,
    ) -> AfterToolDecision:
        """Inspect and redact PII in the tool result."""
        config = self._resolve_tool_config(name, None)
        return self._after_tool_with_config(name, result, config, context)

    def _after_tool_with_config(
        self,
        name: str,
        result: Any,
        config: dict,
        context: dict | None = None,
    ) -> AfterToolDecision:
        """Inspect and redact PII using resolved config."""
        pii_action = config.get("pii_action", self._pii_action)
        pii_profiles = config.get("pii_profiles", self._pii_profiles)
        mode = config.get("mode", self._mode)

        if pii_action == "off":
            return AfterToolDecision(
                action="allow",
                reason="pii_off",
                policy_id="pii_detection",
                severity="low",
                tool_name=name,
                redacted_result=result,
                original_action="allow",
                mode=mode,
            )

        text = self._extract_text(result)
        if not has_pii(text, profiles=pii_profiles):
            return AfterToolDecision(
                action="allow",
                reason="no_pii_in_result",
                policy_id="pii_detection",
                severity="low",
                tool_name=name,
                redacted_result=result,
                original_action="allow",
                mode=mode,
            )

        # PII found.
        redacted = redact_result(result, profiles=pii_profiles)

        if pii_action == "block":
            return AfterToolDecision(
                action="redact_result",
                reason="pii_detected_in_result",
                policy_id="pii_detection",
                severity="high",
                tool_name=name,
                redacted_result=redacted,
                original_action="redact_result",
                mode=mode,
            )

        # pii_action == "warn"
        return AfterToolDecision(
            action="warn",
            reason="pii_detected_in_result",
            policy_id="pii_detection",
            severity="medium",
            tool_name=name,
            redacted_result=redacted,
            original_action="warn",
            mode=mode,
        )

    # ------------------------------------------------------------------
    # Classmethods for policy-file construction.
    # ------------------------------------------------------------------
    _KNOWN_CONFIG_KEYS = KNOWN_CONFIG_KEYS

    @classmethod
    def from_config(cls, config: dict, **overrides) -> "Guard":
        """Create a Guard from a validated config dictionary.

        Args:
            config: Policy configuration dictionary. ``version`` is required.
            **overrides: Guard constructor overrides such as ``on_block`` or ``mode``.
        """
        cls._validate_config(config)
        # Pass through every config key except version, including pii_profiles.
        guard_params = {k: v for k, v in config.items() if k != "version"}
        guard_params.update(overrides)
        return cls(**guard_params)

    @classmethod
    def from_policy_file(cls, path: str, **overrides) -> "Guard":
        """Create a Guard from a policy file.

        Args:
            path: Policy file path (``.json``, ``.yaml``, ``.yml``).
            **overrides: Guard constructor overrides.
        """
        from asr.config import load_policy_file
        config = load_policy_file(path)
        return cls.from_config(config, **overrides)

    @classmethod
    def _validate_config(cls, config: dict) -> None:
        """Validate a policy config dictionary."""
        validate_guard_config(config)

    # ------------------------------------------------------------------
    # protect decorator
    # ------------------------------------------------------------------
    def protect(
        self,
        func: Callable | None = None,
        *,
        capabilities: list[str] | None = None,
    ):
        """Deprecated: use guard.tool() instead."""
        import warnings
        warnings.warn(
            "guard.protect() is deprecated, use guard.tool() instead. "
            "Tool-specific capabilities now come from policy.yaml tools: section.",
            FutureWarning,
            stacklevel=2,
        )
        return self.tool(func, capabilities=capabilities)

    # ------------------------------------------------------------------
    # tool decorator (unified)
    # ------------------------------------------------------------------
    def tool(
        self,
        func: Callable | None = None,
        *,
        name: str | None = None,
        capabilities: list[str] | None = None,
        audit: "AuditLogger | None" = None,
    ):
        """Unified decorator for protecting tool functions.

        Supports both sync and async functions. Looks up per-tool policy
        from the YAML tools: section by function name (or name= override).
        """
        if func is None:
            return functools.partial(self.tool, name=name, capabilities=capabilities, audit=audit)

        tool_name = name or func.__name__
        resolved = self._resolve_tool_config(tool_name, capabilities)
        effective_audit = audit or self._audit

        if inspect.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                sig = inspect.signature(func)
                try:
                    bound = sig.bind_partial(*args, **kwargs)
                    bound.apply_defaults()
                    named_args = dict(bound.arguments)
                except TypeError:
                    named_args = kwargs.copy()

                trace_id = str(uuid.uuid4())
                decision = self._before_tool_with_config(tool_name, named_args, resolved)

                if effective_audit is not None:
                    effective_audit.log_guard(decision, trace_id=trace_id)

                if decision.action == "block":
                    ctx = self._build_error_context(decision, named_args, resolved, trace_id)
                    raise BlockedToolError(decision, context=ctx)

                result = await func(*args, **kwargs)

                after_decision = self._after_tool_with_config(tool_name, result, resolved)
                if effective_audit is not None:
                    effective_audit.log_guard(after_decision, trace_id=trace_id)

                if after_decision.action == "redact_result" and after_decision.redacted_result is not None:
                    return after_decision.redacted_result

                return result

            return async_wrapper
        else:
            @functools.wraps(func)
            def sync_wrapper(*args, **kwargs):
                sig = inspect.signature(func)
                try:
                    bound = sig.bind_partial(*args, **kwargs)
                    bound.apply_defaults()
                    named_args = dict(bound.arguments)
                except TypeError:
                    named_args = kwargs.copy()

                trace_id = str(uuid.uuid4())
                decision = self._before_tool_with_config(tool_name, named_args, resolved)

                if effective_audit is not None:
                    effective_audit.log_guard(decision, trace_id=trace_id)

                if decision.action == "block":
                    ctx = self._build_error_context(decision, named_args, resolved, trace_id)
                    raise BlockedToolError(decision, context=ctx)

                result = func(*args, **kwargs)

                after_decision = self._after_tool_with_config(tool_name, result, resolved)
                if effective_audit is not None:
                    effective_audit.log_guard(after_decision, trace_id=trace_id)

                if after_decision.action == "redact_result" and after_decision.redacted_result is not None:
                    return after_decision.redacted_result

                return result

            return sync_wrapper

    # ------------------------------------------------------------------
    # Internal utilities
    # ------------------------------------------------------------------
    def _resolve_tool_config(
        self, tool_name: str, code_capabilities: list[str] | None
    ) -> dict:
        """Merge global + per-tool policy into an effective config."""
        effective = {
            "mode": self._mode,
            "domain_allowlist": list(self._domain_allowlist) if self._domain_allowlist else [],
            "file_path_allowlist": list(self._file_path_allowlist) if self._file_path_allowlist else [],
            "pii_action": self._pii_action,
            "pii_profiles": list(self._pii_profiles) if self._pii_profiles else None,
            "block_egress": self._block_egress,
            "capability_policy": dict(self._capability_policy) if self._capability_policy else {},
            "default_action": self._default_action,
        }

        tool_config = self._tools.get(tool_name, {})
        for key, value in tool_config.items():
            if key == "capabilities":
                continue
            elif key == "capability_policy":
                effective["capability_policy"].update(value)
            elif isinstance(value, list):
                effective[key] = list(value)
            else:
                effective[key] = value

        if code_capabilities is not None:
            effective["capabilities"] = code_capabilities
        else:
            effective["capabilities"] = tool_config.get("capabilities")

        return effective

    def _apply_mode(self, original_action: str) -> str:
        """Return the effective action after applying the current mode."""
        if self._mode == "enforce":
            return original_action
        if self._mode == "warn":
            return "warn" if original_action == "block" else original_action
        # shadow
        return "allow"

    def _redact_args(self, args: dict) -> dict:
        """Redact PII from string values inside an args dictionary."""
        return redact_args(args)

    def _fire_callbacks(self, decision: BeforeToolDecision) -> None:
        """Invoke block or warn callbacks when configured."""
        if decision.action == "block" and self._on_block:
            self._on_block(decision)
        elif decision.action == "warn" and self._on_warn:
            self._on_warn(decision)

    @staticmethod
    def _extract_text(result: Any) -> str:
        """Recursively extract text from a result for PII inspection."""
        return extract_text(result)

    def _redact_result(self, result: Any) -> Any:
        """Redact PII while preserving the original result type."""
        return redact_result(result, profiles=self._pii_profiles)

    def _before_tool_with_config(
        self,
        name: str,
        args: dict,
        config: dict,
        context: dict | None = None,
    ) -> BeforeToolDecision:
        """Evaluate policies using a resolved config."""
        caps = config.get("capabilities") or []
        redacted = self._redact_args(args)

        mode = config.get("mode", self._mode)
        domain_allowlist = config.get("domain_allowlist", self._domain_allowlist)
        file_path_allowlist = config.get("file_path_allowlist", self._file_path_allowlist)
        pii_action = config.get("pii_action", self._pii_action)
        pii_profiles = config.get("pii_profiles", self._pii_profiles)
        block_egress = config.get("block_egress", self._block_egress)
        capability_policy = config.get("capability_policy", self._capability_policy)
        default_action = config.get("default_action", self._default_action)

        def _apply_mode_local(original: str) -> str:
            if mode == "enforce":
                return original
            if mode == "warn":
                return "warn" if original == "block" else original
            return "allow"

        def _decision(result: PolicyMatch) -> BeforeToolDecision:
            original = result.action
            effective = _apply_mode_local(original)
            d = BeforeToolDecision(
                action=effective,
                reason=result.reason,
                policy_id=result.policy_id,
                severity=result.severity,
                tool_name=name,
                redacted_args=redacted,
                capabilities=caps,
                original_action=original,
                mode=mode,
            )
            self._fire_callbacks(d)
            return d

        # 1. Blocklist (global only)
        r = evaluate_tool_blocklist(name, args, blocklist=self._tool_blocklist)
        if r is not None:
            return _decision(r)

        # Email capability pre-check
        if has_email_destination(args) and "email_send" in caps:
            email_action = capability_policy.get("email_send")
            if email_action == "block":
                r = evaluate_capability(capabilities=["email_send"], policy=capability_policy)
                if r is not None:
                    return _decision(r)

        # 2-4. Specific policies
        matched_any_specific = False
        worst_result = None

        if block_egress and (has_url(args) or has_email_destination(args)):
            matched_any_specific = True
            r = evaluate_egress(name, args, domain_allowlist=domain_allowlist, block_egress=block_egress)
            if r is not None:
                if r.action == "block":
                    return _decision(r)
                worst_result = r

        if file_path_allowlist and _has_path(args):
            matched_any_specific = True
            r = evaluate_file_path(name, args, allowlist=file_path_allowlist)
            if r is not None:
                if r.action == "block":
                    return _decision(r)
                if worst_result is None:
                    worst_result = r

        if pii_action != "off":
            r = evaluate_pii(name, args, pii_action=pii_action, pii_profiles=pii_profiles)
            if r is not None:
                matched_any_specific = True
                if r.action == "block":
                    return _decision(r)
                if worst_result is None:
                    worst_result = r

        if matched_any_specific:
            if worst_result is not None:
                return _decision(worst_result)
            d = BeforeToolDecision(
                action=_apply_mode_local("allow"),
                reason="specific_policy_passed",
                policy_id="specific_policy",
                severity="low",
                tool_name=name,
                redacted_args=redacted,
                capabilities=caps,
                original_action="allow",
                mode=mode,
            )
            self._fire_callbacks(d)
            return d

        # 5. Capability fallback
        if caps and capability_policy:
            r = evaluate_capability(capabilities=caps, policy=capability_policy)
            if r is not None:
                return _decision(r)

        # 6. Default
        r = evaluate_unknown_tool(default=default_action)
        return _decision(r)

    @staticmethod
    def _build_error_context(
        decision: BeforeToolDecision,
        args: dict,
        config: dict,
        trace_id: str,
    ) -> dict:
        """Build structured error context for BlockedToolError."""
        from urllib.parse import urlparse

        ctx: dict[str, object] = {"trace_id": trace_id}

        for key in ("url", "endpoint", "uri", "href", "target"):
            val = args.get(key)
            if isinstance(val, str) and val.startswith(("http://", "https://")):
                try:
                    ctx["target"] = urlparse(val).hostname or val
                    ctx["target_kind"] = "domain"
                except Exception:
                    ctx["target"] = val
                    ctx["target_kind"] = "url"
                break

        if "target" not in ctx:
            for key in ("to", "recipient", "recipients"):
                val = args.get(key)
                if val:
                    if isinstance(val, list):
                        ctx["target"] = ", ".join(str(v) for v in val)
                    else:
                        ctx["target"] = str(val)
                    ctx["target_kind"] = "email"
                    break

        if "target" not in ctx:
            for key in ("path", "file_path", "filepath", "file", "filename"):
                val = args.get(key)
                if isinstance(val, str):
                    ctx["target"] = val
                    ctx["target_kind"] = "file_path"
                    break

        if config.get("domain_allowlist"):
            ctx["allowed_domains"] = config["domain_allowlist"]

        policy_id = decision.policy_id
        if policy_id == "domain_allowlist":
            target = ctx.get("target", "the domain")
            ctx["fix_hint"] = f"add '{target}' to domain_allowlist or set mode to 'shadow'"
        elif policy_id == "file_path_allowlist":
            ctx["fix_hint"] = "add the path to file_path_allowlist or set mode to 'shadow'"
        elif policy_id == "tool_blocklist":
            ctx["fix_hint"] = f"remove '{decision.tool_name}' from tool_blocklist"
        elif policy_id == "pii_detection":
            ctx["fix_hint"] = "set pii_action to 'warn' or 'off' for this tool"
        elif policy_id == "capability_policy":
            ctx["fix_hint"] = "change the capability action to 'warn' or 'allow'"

        return ctx
