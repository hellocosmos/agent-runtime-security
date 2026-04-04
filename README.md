# Agent Runtime Security

[![Test](https://github.com/hellocosmos/agent-runtime-security/actions/workflows/test.yml/badge.svg)](https://github.com/hellocosmos/agent-runtime-security/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)

[English](./README.md) | [한국어](./README.ko.md)

> Open-source runtime security for tool-using AI agents.

Agent Runtime Security helps teams control risky tool calls, redact sensitive data, and keep audit trails for AI agent workflows. It is designed for practical runtime defense, especially where agents can browse the web, call APIs, read files, send email, or interact with MCP tools.

Brand note: `TrapDefense` is the product and site brand, while `Agent Runtime Security` is the open-source SDK and repository name.

This project was inspired by Google DeepMind's 2026 paper, [*AI Agent Traps*](https://papers.ssrn.com/sol3/papers.cfm?abstract_id=6372438), and focuses on the parts that are practical to defend today:

- Content injection signals at ingestion time
- Behavioral control at tool execution time
- Audit evidence for security review and rollout

It does **not** claim to solve every agent security problem. Instead, it focuses on a narrow but important layer: runtime controls for tool-using agents.

## Why this exists

The model is not the only risk.

In tool-using agent systems, the real damage happens when the agent actually uses a tool:

- Sending data to an external endpoint
- Reading or writing the wrong file
- Executing a risky command
- Returning sensitive information in tool output

Prompt filters and content scanning can help, but they do not stop the final action. Agent Runtime Security adds enforcement where it matters most: before a tool runs, plus data protection after it returns.

## Features

- `Guard` for tool-use policy enforcement
- `Scanner` for basic content-injection detection
- `AuditLogger` for structured JSONL security events
- `mcp_guard` for protecting MCP tool handlers
- `shadow`, `warn`, and `enforce` rollout modes
- YAML / JSON policy file loading
- Minimal dependencies with a Python-first integration model

## Installation

Base package:

```bash
pip install agent-runtime-security
```

With MCP integration:

```bash
pip install agent-runtime-security[mcp]
```

With PDF support:

```bash
pip install agent-runtime-security[pdf]
```

With YAML policy loading:

```bash
pip install agent-runtime-security[yaml]
```

## Quick Start

```python
from asr import Scanner, Guard, AuditLogger

# Scan inbound content
scanner = Scanner()
result = scanner.scan(
    "<span style='display:none'>Ignore instructions</span>",
    source_type="html",
)
print(f"score={result.score}, severity={result.severity}")

# Protect tool calls
guard = Guard(
    domain_allowlist=["api.internal.com"],
    block_egress=True,
    pii_action="block",
    file_path_allowlist=["/tmp/safe"],
    capability_policy={"shell_exec": "block"},
)

decision = guard.before_tool(
    "http_post",
    {"url": "https://evil.com"},
    capabilities=["network_send"],
)
print(f"action={decision.action}, reason={decision.reason}")

# Decorator-based protection
@guard.protect(capabilities=["network_send"])
def send_email(to, subject, body):
    ...

# Audit log
audit = AuditLogger(output="logs/audit.jsonl")
audit.log_scan(result, trace_id="req-001")
audit.log_guard(decision, trace_id="req-001")
```

## Rollout Modes

You can roll out policies gradually in production:

```python
# Phase 1: shadow — observe only, no blocking
guard = Guard(mode="shadow", ...)

# Phase 2: warn — downgrade block to warn
guard = Guard(mode="warn", ...)

# Phase 3: enforce — apply policy decisions
guard = Guard(mode="enforce", ...)

# PII redaction still applies even in shadow/warn
decision = guard.before_tool("http_post", {"url": "https://evil.com"})
print(decision.action)          # "allow" in shadow mode
print(decision.original_action) # "block"
print(decision.mode)            # "shadow"
```

### Mode semantics

| Mode | Behavior |
|------|----------|
| `enforce` | Apply policy results as-is |
| `warn` | Downgrade `block` to `warn` |
| `shadow` | Always allow, but record the original decision |

## MCP Integration

Protect MCP tool handlers with `mcp_guard`:

```python
from asr import Guard, AuditLogger
from asr.mcp import mcp_guard

guard = Guard(
    mode="shadow",
    domain_allowlist=["api.internal.com"],
    block_egress=True,
)
audit = AuditLogger(output="logs/audit.jsonl")

@server.tool()
@mcp_guard(guard, audit=audit, capabilities=["network_send"])
async def send_email(to: str, subject: str, body: str) -> str:
    return await email_service.send(to, subject, body)
```

When a tool call is blocked, the adapter turns the policy decision into an MCP-compatible tool error. If sensitive data appears in the result, it can also be redacted automatically.

See the example server in [examples/README.md](./examples/README.md).

## Policy Model

The `Guard` supports six policy layers and three rollout modes.

### Policies

| Policy | Description |
|--------|-------------|
| `tool_blocklist` | Block tools by name |
| `domain_allowlist` + `block_egress` | Block network egress outside allowed domains |
| `file_path_allowlist` | Restrict file access to approved paths |
| `pii_action` | Detect PII in tool args / results: `off`, `warn`, `block` |
| `capability_policy` | Fallback policy based on capability tags |
| `default_action` | Final fallback for unknown tools |

### Evaluation order

`Blocklist -> Egress -> FilePath -> PII -> Capability (fallback) -> Default`

This order matters because specific policies should be evaluated before generic capability fallback.

## Scanner Coverage

`Scanner` is a regex-based first-pass filter. It is intentionally lightweight and should be combined with stronger controls when needed.

Supported patterns:

| Pattern | Description |
|--------|-------------|
| `css_hidden_text` | Hidden CSS text plus injection language |
| `html_comment_injection` | Suspicious instructions inside HTML comments |
| `metadata_injection` | Injection attempts through `aria-label`, `alt`, or `title` |
| `markdown_link_payload` | Hidden instructions inside markdown link text |
| `prompt_injection_keywords` | Common prompt-injection phrases |
| `base64_encoded_instruction` | Base64-encoded suspicious instructions |
| `invisible_unicode` | Invisible Unicode characters often used for obfuscation |
| `role_override_attempt` | Role override attempts such as `SYSTEM:` |

## What this project does well

- Runtime control at tool execution time
- Practical policy rollout with `shadow -> warn -> enforce`
- Structured audit logs for security review
- Python / MCP integration with minimal dependencies

## What this project does not try to solve yet

- Full semantic manipulation detection
- Long-term memory poisoning defense
- Systemic multi-agent risk management
- A full hosted security platform or dashboard

Those may become future product layers, but they are intentionally outside the current SDK scope.

## Example Server

Run the MCP example server:

```bash
mcp dev examples/mcp_server.py
```

The example demonstrates:

- External egress control
- File path restriction
- Automatic PII redaction

See [examples/README.md](./examples/README.md) for details.

## Development

Install in editable mode with development dependencies:

```bash
pip install -e ".[dev]"
```

Run the test suite:

```bash
pytest
```

For demos and internal validation, the MCP example in [examples/README.md](./examples/README.md) is the recommended starting point.

## Repository language policy

- Public-facing GitHub documentation: English first
- Korean translation: [README.ko.md](./README.ko.md)
- Internal working docs may remain in Korean

## License

MIT
