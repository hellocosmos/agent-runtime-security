"""MCP adapter that protects tool handlers with Guard policies."""
from __future__ import annotations

import warnings
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
    """Deprecated: use guard.tool() instead."""
    warnings.warn(
        "mcp_guard() is deprecated, use guard.tool() instead. "
        "Tool-specific capabilities now come from policy.yaml tools: section.",
        FutureWarning,
        stacklevel=2,
    )
    if trace_id_getter is not None:
        warnings.warn(
            "trace_id_getter is no longer supported in guard.tool(). "
            "trace_id should now be supplied by the integration layer via context/details.",
            FutureWarning,
            stacklevel=2,
        )
    return guard.tool(name=tool_name, capabilities=capabilities, audit=audit)


def _raise_tool_error(message: str) -> None:
    """Raise MCP ToolError when available, otherwise fall back to RuntimeError."""
    try:
        from mcp.server.fastmcp.exceptions import ToolError
        raise ToolError(message)
    except ImportError:
        raise RuntimeError(message)
