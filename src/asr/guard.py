"""Guard module with before_tool/after_tool policy checks and decorators."""
from __future__ import annotations

import functools
import inspect
import logging
from typing import Any, Callable

logger = logging.getLogger("asr.guard")

from asr.pii import has_pii, redact_pii
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
from asr.types import AfterToolDecision, BeforeToolDecision


# --- Internal helper: detect file path keys in args ---
_PATH_KEYS = ("path", "file_path", "filepath", "file", "filename")


def _has_path(args: dict) -> bool:
    """Return whether ``args`` contains a file path key."""
    return any(k in args and isinstance(args[k], str) for k in _PATH_KEYS)


class BlockedToolError(Exception):
    """Raised when Guard blocks a tool invocation."""

    def __init__(self, decision: BeforeToolDecision):
        self.decision = decision
        super().__init__(f"Blocked: {decision.reason} (policy={decision.policy_id})")


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
        block_egress: bool = False,
        tool_blocklist: list[str] | None = None,
        capability_policy: dict[str, str] | None = None,
        default_action: str = "warn",
        on_block: Callable | None = None,
        on_warn: Callable | None = None,
    ):
        if mode not in ("enforce", "warn", "shadow"):
            raise ValueError(f"Invalid mode: {mode!r}. Must be 'enforce', 'warn', or 'shadow'")
        self._mode = mode
        self._domain_allowlist = domain_allowlist or []
        self._file_path_allowlist = file_path_allowlist or []
        self._pii_action = pii_action
        self._block_egress = block_egress
        self._tool_blocklist = tool_blocklist or []
        self._capability_policy = capability_policy or {}
        self._default_action = default_action
        self._on_block = on_block
        self._on_warn = on_warn
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
        caps = capabilities or []
        redacted = self._redact_args(args)

        def _decision(result: dict) -> BeforeToolDecision:
            original = result["action"]
            effective = self._apply_mode(original)
            d = BeforeToolDecision(
                action=effective,
                reason=result["reason"],
                policy_id=result["policy_id"],
                severity=result["severity"],
                tool_name=name,
                redacted_args=redacted,
                capabilities=caps,
                original_action=original,
                mode=self._mode,
            )
            self._fire_callbacks(d)
            return d

        # 1. Blocklist - highest priority.
        r = evaluate_tool_blocklist(name, args, blocklist=self._tool_blocklist)
        if r is not None:
            return _decision(r)

        # 2-4. Specific policies (egress / file_path / pii)
        # matched_any_specific tracks whether any specific policy applied.
        # worst_result keeps the strictest non-block result; blocks return immediately.
        matched_any_specific = False
        worst_result = None

        # 2. Egress policy
        if self._block_egress and (has_url(args) or has_email_destination(args)):
            matched_any_specific = True
            r = evaluate_egress(
                name, args,
                domain_allowlist=self._domain_allowlist,
                block_egress=self._block_egress,
            )
            if r is not None:
                if r["action"] == "block":
                    return _decision(r)
                worst_result = r

        # 3. File path policy
        if self._file_path_allowlist and _has_path(args):
            matched_any_specific = True
            r = evaluate_file_path(name, args, allowlist=self._file_path_allowlist)
            if r is not None:
                if r["action"] == "block":
                    return _decision(r)
                if worst_result is None:
                    worst_result = r

        # 4. PII policy
        if self._pii_action != "off":
            r = evaluate_pii(name, args, pii_action=self._pii_action)
            if r is not None:
                matched_any_specific = True
                if r["action"] == "block":
                    return _decision(r)
                if worst_result is None:
                    worst_result = r

        # If any specific policy matched, skip capability fallback and return now.
        if matched_any_specific:
            if worst_result is not None:
                return _decision(worst_result)
            d = BeforeToolDecision(
                action=self._apply_mode("allow"),
                reason="specific_policy_passed",
                policy_id="specific_policy",
                severity="low",
                tool_name=name,
                redacted_args=redacted,
                capabilities=caps,
                original_action="allow",
                mode=self._mode,
            )
            self._fire_callbacks(d)
            return d

        # 5. Capability policy - true fallback.
        if caps and self._capability_policy:
            r = evaluate_capability(capabilities=caps, policy=self._capability_policy)
            if r is not None:
                return _decision(r)

        # 6. Final fallback - default_action.
        r = evaluate_unknown_tool(default=self._default_action)
        return _decision(r)

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
        if self._pii_action == "off":
            return AfterToolDecision(
                action="allow",
                reason="pii_off",
                policy_id="pii_detection",
                severity="low",
                tool_name=name,
                redacted_result=result,
                original_action="allow",
                mode=self._mode,
            )

        text = self._extract_text(result)
        if not has_pii(text):
            return AfterToolDecision(
                action="allow",
                reason="no_pii_in_result",
                policy_id="pii_detection",
                severity="low",
                tool_name=name,
                redacted_result=result,
                original_action="allow",
                mode=self._mode,
            )

        # PII found.
        redacted = self._redact_result(result)

        if self._pii_action == "block":
            return AfterToolDecision(
                action="redact_result",
                reason="pii_detected_in_result",
                policy_id="pii_detection",
                severity="high",
                tool_name=name,
                redacted_result=redacted,
                original_action="redact_result",
                mode=self._mode,
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
            mode=self._mode,
        )

    # ------------------------------------------------------------------
    # Classmethods for policy-file construction.
    # ------------------------------------------------------------------
    _KNOWN_CONFIG_KEYS = {
        "version", "mode", "domain_allowlist", "file_path_allowlist",
        "pii_action", "block_egress", "tool_blocklist",
        "capability_policy", "default_action",
    }

    @classmethod
    def from_config(cls, config: dict, **overrides) -> "Guard":
        """Create a Guard from a validated config dictionary.

        Args:
            config: Policy configuration dictionary. ``version`` is required.
            **overrides: Guard constructor overrides such as ``on_block`` or ``mode``.
        """
        cls._validate_config(config)
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
        if "version" not in config:
            raise ValueError("정책 파일에 'version' 필드가 필요합니다")
        if config["version"] != 1:
            raise ValueError(
                f"지원하지 않는 version: {config['version']}. 현재 version: 1만 지원합니다"
            )

        unknown = set(config.keys()) - cls._KNOWN_CONFIG_KEYS
        if unknown:
            raise ValueError(f"알 수 없는 정책 필드: {', '.join(sorted(unknown))}")

        _VALID_VALUES = {
            "mode": ("enforce", "warn", "shadow"),
            "pii_action": ("off", "warn", "block"),
            "default_action": ("allow", "warn", "block"),
        }
        for field, valid in _VALID_VALUES.items():
            if field in config and config[field] not in valid:
                raise ValueError(
                    f"'{field}' 값이 올바르지 않습니다: {config[field]!r}. "
                    f"허용: {', '.join(valid)}"
                )

        for field in ("domain_allowlist", "file_path_allowlist", "tool_blocklist"):
            if field in config:
                val = config[field]
                if not isinstance(val, list) or not all(isinstance(x, str) for x in val):
                    raise ValueError(f"'{field}'는 문자열 리스트여야 합니다")

        if "block_egress" in config and not isinstance(config["block_egress"], bool):
            raise ValueError("'block_egress'는 bool이어야 합니다")

        if "capability_policy" in config:
            cp = config["capability_policy"]
            if not isinstance(cp, dict):
                raise ValueError("'capability_policy'는 dict여야 합니다")
            valid_actions = ("allow", "warn", "block")
            for k, v in cp.items():
                if v not in valid_actions:
                    raise ValueError(
                        f"'capability_policy' 값이 올바르지 않습니다: "
                        f"{k}={v!r}. 허용: {', '.join(valid_actions)}"
                    )

    # ------------------------------------------------------------------
    # protect decorator
    # ------------------------------------------------------------------
    def protect(
        self,
        func: Callable | None = None,
        *,
        capabilities: list[str] | None = None,
    ):
        """Decorator that protects a tool function with Guard.

        Examples:
            @guard.protect
            def my_tool(...): ...

            @guard.protect(capabilities=["shell_exec"])
            def run_cmd(...): ...
        """
        if func is None:
            # Support @guard.protect(capabilities=["shell_exec"]).
            return functools.partial(self.protect, capabilities=capabilities)

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Map positional arguments to parameter names.
            sig = inspect.signature(func)
            try:
                bound = sig.bind_partial(*args, **kwargs)
                bound.apply_defaults()
                named_args = dict(bound.arguments)
            except TypeError:
                named_args = kwargs.copy()

            # Evaluate before_tool.
            tool_name = func.__name__
            decision = self.before_tool(tool_name, named_args, capabilities=capabilities)

            if decision.action == "block":
                raise BlockedToolError(decision)

            # Execute the wrapped function.
            result = func(*args, **kwargs)

            # Evaluate after_tool.
            after_decision = self.after_tool(tool_name, result)
            if after_decision.action == "redact_result":
                return after_decision.redacted_result

            return result

        return wrapper

    # ------------------------------------------------------------------
    # Internal utilities
    # ------------------------------------------------------------------
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
        redacted = {}
        for key, value in args.items():
            if isinstance(value, str):
                redacted[key] = redact_pii(value)
            elif isinstance(value, dict):
                redacted[key] = self._redact_args(value)
            else:
                redacted[key] = value
        return redacted

    def _fire_callbacks(self, decision: BeforeToolDecision) -> None:
        """Invoke block or warn callbacks when configured."""
        if decision.action == "block" and self._on_block:
            self._on_block(decision)
        elif decision.action == "warn" and self._on_warn:
            self._on_warn(decision)

    @staticmethod
    def _extract_text(result: Any) -> str:
        """Recursively extract text from a result for PII inspection."""
        if isinstance(result, str):
            return result
        if isinstance(result, dict):
            parts = []
            for v in result.values():
                parts.append(Guard._extract_text(v))
            return " ".join(parts)
        if isinstance(result, (list, tuple)):
            return " ".join(Guard._extract_text(item) for item in result)
        return str(result) if result is not None else ""

    def _redact_result(self, result: Any) -> Any:
        """Redact PII while preserving the original result type."""
        if isinstance(result, str):
            return redact_pii(result)
        if isinstance(result, dict):
            return {k: self._redact_result(v) for k, v in result.items()}
        if isinstance(result, (list, tuple)):
            return type(result)(self._redact_result(item) for item in result)
        return result
