"""LangGraph adapter — wraps ToolNode tools with Guard policy protection."""
from __future__ import annotations

from typing import Any

from asr.audit import AuditLogger
from asr.guard import Guard

from asr.adapters.langchain import guard_tool

try:
  from langchain_core.tools import BaseTool
  from langgraph.prebuilt import ToolNode
except ImportError as e:
  raise ImportError(
    "langgraph is required: pip install agent-runtime-security[langgraph]"
  ) from e


def create_guarded_tool_node(
  tools: list[BaseTool],
  guard: Guard,
  *,
  audit: AuditLogger | None = None,
  capabilities_map: dict[str, list[str]] | None = None,
  **tool_node_kwargs: Any,
) -> ToolNode:
  """Create a LangGraph ToolNode with Guard policy protection.

  Wraps each tool with guard_tool() before passing to ToolNode.

  Args:
      tools: LangChain BaseTool instances to protect.
      guard: Guard instance.
      audit: Optional audit logger.
      capabilities_map: Per-tool capability tags, e.g. ``{"send_email": ["network_send"]}``.
      **tool_node_kwargs: Additional kwargs passed to ToolNode (name, tags, etc.).

  Returns:
      A ToolNode with Guard policy enforcement on all tools.
  """
  caps_map = capabilities_map or {}

  guarded_tools = [
    guard_tool(
      t,
      guard=guard,
      audit=audit,
      capabilities=caps_map.get(t.name),
    )
    for t in tools
  ]

  return ToolNode(guarded_tools, **tool_node_kwargs)
