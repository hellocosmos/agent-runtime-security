"""MCP adapter that protects tool handlers with Guard policies."""
from __future__ import annotations

import functools
import inspect
import uuid
from typing import Any, Callable

from asr.audit import AuditLogger
from asr.guard import Guard


def mcp_guard(
    guard: Guard,
    *,
    audit: AuditLogger | None = None,
    tool_name: str | None = None,
    capabilities: list[str] | None = None,
    trace_id_getter: Callable[..., str | None] | None = None,
):
    """Async decorator that protects an MCP tool handler with Guard.

    Args:
        guard: Guard instance.
        audit: Optional audit logger. When set, before/after events are recorded.
        tool_name: Tool name passed to Guard. Defaults to ``fn.__name__``.
        capabilities: Capability tags for the tool.
        trace_id_getter: Optional function that extracts ``trace_id`` from ``**kwargs``.
    """
    def decorator(fn: Callable) -> Callable:
        # Reject sync handlers at decoration time.
        if not inspect.iscoroutinefunction(fn):
            raise TypeError(
                f"mcp_guard requires async def tool handlers, "
                f"but '{fn.__name__}' is sync"
            )

        name = tool_name or fn.__name__

        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Map positional arguments to parameter names, matching guard.protect.
            sig = inspect.signature(fn)
            try:
                bound = sig.bind_partial(*args, **kwargs)
                bound.apply_defaults()
                named_args = dict(bound.arguments)
            except TypeError:
                named_args = kwargs.copy()

            # Generate a trace_id.
            trace_id = None
            if trace_id_getter is not None:
                trace_id = trace_id_getter(**named_args)
            if trace_id is None:
                trace_id = str(uuid.uuid4())

            # Evaluate before_tool.
            decision = guard.before_tool(name, named_args, capabilities=capabilities)

            if audit is not None:
                audit.log_guard(decision, trace_id=trace_id)

            if decision.action == "block":
                _raise_tool_error(
                    f"Tool '{name}' blocked by policy "
                    f"'{decision.policy_id}': {decision.reason}"
                )

            # Execute the tool handler.
            result = await fn(*args, **kwargs)

            # Inspect the result for PII after execution.
            after_decision = guard.after_tool(name, result)

            if audit is not None:
                audit.log_guard(after_decision, trace_id=trace_id)

            # Return the redacted payload when data protection triggered.
            # This is stricter than guard.protect and still redacts on warn.
            if after_decision.redacted_result is not None and after_decision.action in (
                "redact_result", "warn"
            ):
                return after_decision.redacted_result

            return result

        return wrapper
    return decorator


def _raise_tool_error(message: str) -> None:
    """Raise MCP ToolError when available, otherwise fall back to RuntimeError."""
    try:
        from mcp.server.fastmcp.exceptions import ToolError
        raise ToolError(message)
    except ImportError:
        raise RuntimeError(message)
