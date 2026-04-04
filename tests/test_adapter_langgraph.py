"""LangGraph create_guarded_tool_node adapter tests."""
import pytest
from langchain_core.tools import tool
from langchain_core.messages import AIMessage, ToolMessage
from langgraph.graph import StateGraph, MessagesState

from asr import Guard, AuditLogger
from asr.adapters.langchain import GuardedTool
from asr.adapters.langgraph import create_guarded_tool_node


# --- Test tools ---

@tool
def post_webhook(url: str, body: str) -> str:
  """Post a webhook."""
  return f"Sent to {url}"


@tool
def search(query: str) -> str:
  """Search — returns results containing PII."""
  return "Contact: admin@secret.com"


@tool
def safe_tool(message: str) -> str:
  """A safe tool."""
  return f"OK: {message}"


# --- Helper: run ToolNode inside a graph ---

def _run_tool_node(node, tool_name: str, args: dict, call_id: str = "call_1"):
  graph = StateGraph(MessagesState)
  graph.add_node("tools", node)
  graph.set_entry_point("tools")
  graph.set_finish_point("tools")
  app = graph.compile()

  msg = AIMessage(
    content="",
    tool_calls=[{
      "name": tool_name,
      "args": args,
      "id": call_id,
      "type": "tool_call",
    }],
  )
  result = app.invoke({"messages": [msg]})
  return result["messages"][-1]


# --- ToolNode creation ---

class TestCreateGuardedToolNode:
  def test_returns_tool_node(self):
    from langgraph.prebuilt import ToolNode
    guard = Guard()
    node = create_guarded_tool_node([safe_tool], guard=guard)
    assert isinstance(node, ToolNode)

  def test_wraps_all_tools(self):
    guard = Guard()
    node = create_guarded_tool_node(
      [post_webhook, search, safe_tool], guard=guard
    )
    for t in node.tools_by_name.values():
      assert isinstance(t, GuardedTool)

  def test_preserves_tool_names(self):
    guard = Guard()
    node = create_guarded_tool_node(
      [post_webhook, search, safe_tool], guard=guard
    )
    assert set(node.tools_by_name.keys()) == {"post_webhook", "search", "safe_tool"}

  def test_capabilities_map_applied(self):
    guard = Guard(capability_policy={"network_send": "block"})
    node = create_guarded_tool_node(
      [post_webhook, safe_tool],
      guard=guard,
      capabilities_map={"post_webhook": ["network_send"]},
    )
    assert node.tools_by_name["post_webhook"]._capabilities == ["network_send"]
    assert node.tools_by_name["safe_tool"]._capabilities is None


# --- ToolNode execution ---

class TestToolNodeExecution:
  def test_allow_through_tool_node(self):
    guard = Guard(
      domain_allowlist=["api.internal.com"],
      block_egress=True,
    )
    node = create_guarded_tool_node([post_webhook], guard=guard)
    msg = _run_tool_node(
      node, "post_webhook",
      {"url": "https://api.internal.com/hook", "body": "hi"},
    )
    assert isinstance(msg, ToolMessage)
    assert "api.internal.com" in msg.content

  def test_block_through_tool_node(self):
    guard = Guard(
      domain_allowlist=["api.internal.com"],
      block_egress=True,
    )
    node = create_guarded_tool_node(
      [post_webhook], guard=guard, handle_tool_errors=True
    )
    msg = _run_tool_node(
      node, "post_webhook",
      {"url": "https://evil.com/hook", "body": "hi"},
    )
    assert isinstance(msg, ToolMessage)
    assert "blocked" in msg.content

  def test_redact_through_tool_node(self):
    guard = Guard(pii_action="redact")
    node = create_guarded_tool_node([search], guard=guard)
    msg = _run_tool_node(node, "search", {"query": "admin"})
    assert isinstance(msg, ToolMessage)
    assert "admin@secret.com" not in msg.content
    assert "[EMAIL]" in msg.content

  def test_audit_with_tool_node(self, tmp_path):
    log_path = tmp_path / "audit.jsonl"
    audit = AuditLogger(output=str(log_path))
    guard = Guard(pii_action="redact")
    node = create_guarded_tool_node([search], guard=guard, audit=audit)

    _run_tool_node(node, "search", {"query": "admin"})

    lines = log_path.read_text().strip().split("\n")
    assert len(lines) >= 2
