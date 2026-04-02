# ARS MCP Example Server

[English](./README.md) | [한국어](./README.ko.md)

This is a demo MCP server protected by Guard policies. It uses three tools to show the core behavior of the SDK.

## Tools

| Tool | Demo point |
|------|------------|
| `send_email` | Block egress to external domains |
| `read_file` | Restrict file paths |
| `search` | Automatically redact PII in results |

## Run

```bash
# Run with MCP Inspector
mcp dev examples/mcp_server.py

# Or run directly
python examples/mcp_server.py
```

## Demo Scenarios

### 1. Shadow mode (default)

Run the server with `mode: shadow` in `policy.yaml`.

```text
send_email(to="attacker@evil.com", subject="test", body="hello")
-> Allowed to execute, but audit records original_action=block

read_file(path="/etc/passwd")
-> Allowed to execute, but audit records original_action=block

search(query="admin")
-> PII is redacted from the result (data protection still applies in shadow mode)
```

### 2. Enforce mode

Change `policy.yaml` to `mode: enforce` and restart.

```text
send_email(to="attacker@evil.com", subject="test", body="hello")
-> Blocked: "Tool 'send_email' blocked by policy 'egress_control'"

send_email(to="user@internal.com", subject="test", body="hello")
-> Allowed (domain is on the allowlist)

read_file(path="/etc/passwd")
-> Blocked: "Tool 'read_file' blocked by policy 'file_path_allowlist'"

read_file(path="/tmp/safe/data.txt")
-> Allowed (path is on the allowlist)

search(query="admin")
-> PII is redacted from the result
```

## Policy File

Update `policy.yaml` to change policy behavior without modifying code.
