"""LangChain adapter — wraps BaseTool with Guard policy protection."""
from __future__ import annotations

import uuid
from typing import Any, Optional, Type

from asr.audit import AuditLogger
from asr.guard import Guard

try:
  from langchain_core.tools import BaseTool, ToolException
  from langchain_core.callbacks import (
    CallbackManagerForToolRun,
    AsyncCallbackManagerForToolRun,
  )
  from pydantic import BaseModel
except ImportError as e:
  raise ImportError(
    "langchain-core is required: pip install agent-runtime-security[langchain]"
  ) from e


class GuardedTool(BaseTool):
  """LangChain Tool wrapper protected by Guard policies."""

  name: str = ""
  description: str = ""
  args_schema: Optional[Type[BaseModel]] = None
  handle_tool_error: bool = True

  _inner: BaseTool
  _guard: Guard
  _audit: Optional[AuditLogger]
  _capabilities: Optional[list[str]]

  def __init__(
    self,
    inner: BaseTool,
    guard: Guard,
    audit: AuditLogger | None = None,
    capabilities: list[str] | None = None,
  ):
    super().__init__(
      name=inner.name,
      description=inner.description,
      args_schema=inner.args_schema,
      handle_tool_error=True,
    )
    self._inner = inner
    self._guard = guard
    self._audit = audit
    self._capabilities = capabilities

  # LangChain internal kwargs to exclude from Guard evaluation
  _LC_INTERNAL_KEYS = frozenset({"run_manager", "config"})

  def _extract_tool_args(self, kwargs: dict) -> dict:
    """Extract tool arguments, excluding LangChain internal kwargs."""
    return {k: v for k, v in kwargs.items() if k not in self._LC_INTERNAL_KEYS}

  def _run(self, *args: Any, **kwargs: Any) -> Any:
    trace_id = str(uuid.uuid4())
    tool_kwargs = self._extract_tool_args(kwargs)

    decision = self._guard.before_tool(
      self.name, tool_kwargs, capabilities=self._capabilities
    )
    if self._audit is not None:
      self._audit.log_guard(decision, trace_id=trace_id)

    if decision.action == "block":
      raise ToolException(
        f"Tool '{self.name}' blocked: {decision.reason} "
        f"(policy={decision.policy_id})"
      )

    # Use invoke for StructuredTool compatibility
    result = self._inner.invoke(tool_kwargs)

    after_decision = self._guard.after_tool(self.name, result)
    if self._audit is not None:
      self._audit.log_guard(after_decision, trace_id=trace_id)

    if after_decision.redacted_result is not None and after_decision.action in (
      "redact_result", "warn"
    ):
      return after_decision.redacted_result

    return result

  async def _arun(self, *args: Any, **kwargs: Any) -> Any:
    trace_id = str(uuid.uuid4())
    tool_kwargs = self._extract_tool_args(kwargs)

    decision = self._guard.before_tool(
      self.name, tool_kwargs, capabilities=self._capabilities
    )
    if self._audit is not None:
      self._audit.log_guard(decision, trace_id=trace_id)

    if decision.action == "block":
      raise ToolException(
        f"Tool '{self.name}' blocked: {decision.reason} "
        f"(policy={decision.policy_id})"
      )

    result = await self._inner.ainvoke(tool_kwargs)

    after_decision = self._guard.after_tool(self.name, result)
    if self._audit is not None:
      self._audit.log_guard(after_decision, trace_id=trace_id)

    if after_decision.redacted_result is not None and after_decision.action in (
      "redact_result", "warn"
    ):
      return after_decision.redacted_result

    return result


def guard_tool(
  tool: BaseTool,
  guard: Guard,
  *,
  audit: AuditLogger | None = None,
  capabilities: list[str] | None = None,
) -> GuardedTool:
  """Wrap a LangChain Tool with Guard policy protection.

  Args:
      tool: LangChain BaseTool instance to protect.
      guard: Guard instance.
      audit: Optional audit logger.
      capabilities: Capability tags for the tool.

  Returns:
      A GuardedTool with policy enforcement applied.
  """
  return GuardedTool(
    inner=tool,
    guard=guard,
    audit=audit,
    capabilities=capabilities,
  )
