"""LangChain guard_tool adapter tests."""
import pytest
from langchain_core.tools import tool, ToolException

from asr import Guard, AuditLogger
from asr.adapters.langchain import guard_tool, GuardedTool


# --- Test tools ---

@tool
def post_webhook(url: str, body: str) -> str:
  """Post a webhook."""
  return f"Sent to {url}"


@tool
def read_file(path: str) -> str:
  """Read a file."""
  return f"Contents of {path}"


@tool
def search(query: str) -> str:
  """Search — returns results containing PII."""
  return "Contact: admin@secret.com, key: sk-1234567890abcdef"


@tool
def safe_tool(message: str) -> str:
  """A safe tool."""
  return f"OK: {message}"


# --- Basic wrapping ---

class TestGuardTool:
  def test_returns_guarded_tool_instance(self):
    guard = Guard()
    protected = guard_tool(post_webhook, guard=guard)
    assert isinstance(protected, GuardedTool)

  def test_preserves_name_and_description(self):
    guard = Guard()
    protected = guard_tool(post_webhook, guard=guard)
    assert protected.name == "post_webhook"
    assert protected.description == "Post a webhook."

  def test_preserves_args_schema(self):
    guard = Guard()
    protected = guard_tool(post_webhook, guard=guard)
    assert protected.args_schema is post_webhook.args_schema

  def test_handle_tool_error_enabled(self):
    guard = Guard()
    protected = guard_tool(post_webhook, guard=guard)
    assert protected.handle_tool_error is True


# --- Allow scenarios ---

class TestAllow:
  def test_allowed_url_returns_result(self):
    guard = Guard(
      domain_allowlist=["api.internal.com"],
      block_egress=True,
    )
    protected = guard_tool(post_webhook, guard=guard)
    result = protected.invoke({"url": "https://api.internal.com/hook", "body": "hi"})
    assert result == "Sent to https://api.internal.com/hook"

  def test_allowed_file_path_returns_result(self):
    guard = Guard(file_path_allowlist=["/tmp/safe"])
    protected = guard_tool(read_file, guard=guard)
    result = protected.invoke({"path": "/tmp/safe/data.txt"})
    assert result == "Contents of /tmp/safe/data.txt"

  def test_no_policy_allows_by_default(self):
    guard = Guard()
    protected = guard_tool(safe_tool, guard=guard)
    result = protected.invoke({"message": "hello"})
    assert result == "OK: hello"


# --- Block scenarios ---

class TestBlock:
  def test_blocked_url_returns_error_message(self):
    guard = Guard(
      domain_allowlist=["api.internal.com"],
      block_egress=True,
    )
    protected = guard_tool(post_webhook, guard=guard)
    result = protected.invoke({"url": "https://evil.com/hook", "body": "hi"})
    assert "blocked" in result
    assert "domain_not_allowed" in result

  def test_blocked_file_path_returns_error_message(self):
    guard = Guard(file_path_allowlist=["/tmp/safe"])
    protected = guard_tool(read_file, guard=guard)
    result = protected.invoke({"path": "/etc/passwd"})
    assert "blocked" in result

  def test_blocklisted_tool_returns_error_message(self):
    guard = Guard(tool_blocklist=["dangerous_tool"])

    @tool
    def dangerous_tool(cmd: str) -> str:
      """A dangerous tool."""
      return f"Executed: {cmd}"

    protected = guard_tool(dangerous_tool, guard=guard)
    result = protected.invoke({"cmd": "rm -rf /"})
    assert "blocked" in result
    assert "tool_blocklist" in result

  def test_block_raises_tool_exception_directly(self):
    guard = Guard(
      domain_allowlist=["api.internal.com"],
      block_egress=True,
    )
    protected = GuardedTool(inner=post_webhook, guard=guard)
    protected.handle_tool_error = False
    with pytest.raises(ToolException, match="blocked"):
      protected.invoke({"url": "https://evil.com/hook", "body": "hi"})


# --- PII redaction ---

class TestRedact:
  def test_pii_redacted_in_result(self):
    guard = Guard(pii_action="redact")
    protected = guard_tool(search, guard=guard)
    result = protected.invoke({"query": "admin"})
    assert "admin@secret.com" not in result
    assert "[EMAIL]" in result

  def test_no_redaction_when_no_pii(self):
    guard = Guard(pii_action="redact")
    protected = guard_tool(safe_tool, guard=guard)
    result = protected.invoke({"message": "hello world"})
    assert result == "OK: hello world"


# --- Audit logging ---

class TestAudit:
  def test_audit_logs_before_and_after(self, tmp_path):
    log_path = tmp_path / "audit.jsonl"
    audit = AuditLogger(output=str(log_path))
    guard = Guard(pii_action="redact")

    protected = guard_tool(search, guard=guard, audit=audit)
    protected.invoke({"query": "admin"})

    lines = log_path.read_text().strip().split("\n")
    assert len(lines) >= 2

  def test_audit_logs_on_block(self, tmp_path):
    log_path = tmp_path / "audit.jsonl"
    audit = AuditLogger(output=str(log_path))
    guard = Guard(
      domain_allowlist=["api.internal.com"],
      block_egress=True,
    )

    protected = guard_tool(post_webhook, guard=guard, audit=audit)
    protected.invoke({"url": "https://evil.com/hook", "body": "hi"})

    lines = log_path.read_text().strip().split("\n")
    assert len(lines) >= 1


# --- Capabilities ---

class TestCapabilities:
  def test_capability_policy_blocks(self):
    guard = Guard(capability_policy={"network_send": "block"})
    protected = guard_tool(safe_tool, guard=guard, capabilities=["network_send"])
    result = protected.invoke({"message": "hello"})
    assert "blocked" in result

  def test_capability_policy_allows(self):
    guard = Guard(capability_policy={"network_send": "allow"})
    protected = guard_tool(safe_tool, guard=guard, capabilities=["network_send"])
    result = protected.invoke({"message": "hello"})
    assert result == "OK: hello"
