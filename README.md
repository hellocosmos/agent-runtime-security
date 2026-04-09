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
- `guard.tool()` as the unified decorator for sync and async tools
- `Scanner` for basic content-injection detection
- `AuditLogger` for structured JSONL security events
- `mcp_guard` as a compatibility wrapper for MCP handlers during the v0.3 transition
- `guard_tool` for protecting LangChain tools
- `create_guarded_tool_node` for protecting LangGraph ToolNodes
- `shadow`, `warn`, and `enforce` rollout modes
- YAML / JSON policy file loading
- YAML v2 `tools:` overrides for per-tool policy
- Optional FastAPI extension for local `/scan`, `/decide`, and `/redact` endpoints
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

With LangChain integration:

```bash
pip install agent-runtime-security[langchain]
```

With LangGraph integration:

```bash
pip install agent-runtime-security[langgraph]
```

With the optional HTTP API:

```bash
pip install agent-runtime-security[api]
```

## HTTP API Extension

This repository now ships with a first-party FastAPI wrapper under `asr.api`.

Documentation map:

- Core SDK overview: this README
- API setup details: [`docs/api-extension.md`](./docs/api-extension.md)
- MCP / LangChain / LangGraph demos: [`examples/README.md`](./examples/README.md)

Start the local server:

```bash
asr-api
```

Or create the app in Python:

```python
from asr.api.main import create_app

app = create_app()
```

The API ships with the full preset library:

- General: `default`, `internal-agent`, `mcp-server`, `customer-support`
- Industry: `finance`, `healthcare`, `devops`, `data-pipeline`, `hr-agent`, `legal`, `ecommerce`, `research`
- Role: `developer-agent`, `browser-agent`, `sales-ops-agent`, `security-ops-agent`, `executive-assistant`

You can inspect them programmatically:

```python
from asr.api import available_policy_presets, load_policy_preset

print(available_policy_presets())
print(load_policy_preset("mcp-server"))
```

Environment variables:

- `ASR_AUTH_ENABLED`
- `ASR_API_KEYS_FILE`
- `ASR_API_PREFIX`
- `ASR_ROOT_PATH`
- `ASR_POLICIES_DIR`
- `ASR_DEFAULT_POLICY_PRESET`

Legacy `TRAPDEFENSE_*` env vars are still accepted for compatibility.

Additional API docs:

- Overview: [`docs/api/overview.md`](./docs/api/overview.md)
- Reference: [`docs/api/api-reference.md`](./docs/api/api-reference.md)
- Deployment: [`deploy/api/DEPLOYMENT.md`](./deploy/api/DEPLOYMENT.md)

Minimal local auth file:

```json
{
  "keys": [
    {
      "name": "local-dev",
      "hash": "sha256_of_your_api_key"
    }
  ]
}
```

Point `ASR_API_KEYS_FILE` to that JSON file, then send requests with:

```bash
curl -X POST http://127.0.0.1:8000/v1/scan \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"content": "ignore previous instructions", "source_type": "text"}'
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

# Protect tool calls with a policy file
guard = Guard.from_policy_file(
    "policy.yaml",
    audit=AuditLogger(output="logs/audit.jsonl"),
)

@guard.tool()
def send_email(to, subject, body):
    return f"queued message to {to}"

decision = guard.before_tool("send_email", {"to": "user@mail.internal"})
print(f"action={decision.action}, reason={decision.reason}")
print(send_email("user@mail.internal", "hello", "world"))
```

```yaml
# policy.yaml
version: 2
mode: shadow
pii_action: block
block_egress: true
domain_allowlist:
  - internal.com
capability_policy:
  network_send: warn
  shell_exec: block
default_action: warn

tools:
  send_email:
    capabilities: [network_send]
    domain_allowlist: [mail.internal]
    pii_action: redact
    mode: enforce
```

`guard.tool()` uses the function name as the default tool identifier. If the YAML key differs from the function name, use `@guard.tool(name="...")`.

## Migration Note for v0.3.0

- `guard.tool()` is now the primary decorator for sync and async Python tools.
- `guard.protect()` is deprecated and will be removed in v0.4.0.
- `mcp_guard()` is deprecated and now acts as a compatibility wrapper around `guard.tool()` for MCP-native `ToolError` behavior during the v0.3.x transition.
- Tool-specific capabilities should move from decorator arguments into `policy.yaml` under `tools:`.

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

Use `guard.tool()` as the core API, and keep `mcp_guard()` only where you need MCP-native `ToolError` conversion during the v0.3.x transition:

```python
from asr import Guard, AuditLogger
from asr.mcp import mcp_guard

guard = Guard.from_policy_file(
    "policy.yaml",
    audit=AuditLogger(output="logs/audit.jsonl"),
)

@server.tool()
@mcp_guard(guard)
async def send_email(to: str, subject: str, body: str) -> str:
    return await email_service.send(to, subject, body)
```

`mcp_guard()` now delegates to `guard.tool()` internally, then converts blocked decisions into MCP-compatible tool errors. If sensitive data appears in the result, it can also be redacted automatically.

See the example server in [examples/README.md](./examples/README.md).

## LangChain Integration

Protect LangChain tools with `guard_tool`:

```python
from langchain_core.tools import tool
from asr import Guard
from asr.adapters.langchain import guard_tool

guard = Guard(
    domain_allowlist=["api.internal.com"],
    block_egress=True,
    pii_action="redact",
)

@tool
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email."""
    return f"Sent to {to}"

protected = guard_tool(send_email, guard=guard, capabilities=["network_send"])
result = protected.invoke({"to": "user@api.internal.com", "subject": "hi", "body": "hello"})
```

When a tool is blocked, `ToolException` is raised and returned as an error message (via `handle_tool_error=True`). PII in tool results is automatically redacted.

## LangGraph Integration

Protect all tools in a LangGraph `ToolNode`:

```python
from asr import Guard
from asr.adapters.langgraph import create_guarded_tool_node

guard = Guard.from_policy_file("policy.yaml")

tool_node = create_guarded_tool_node(
    tools=[search_tool, file_reader_tool],
    guard=guard,
    capabilities_map={"search_tool": ["network_send"]},
)
# graph.add_node("tools", tool_node)
```

See `examples/langchain_agent.py` and `examples/langgraph_agent.py` for full working examples.

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

### YAML v2 tool overrides

Version 2 policy files can override global defaults per tool:

```yaml
version: 2
mode: shadow
pii_action: block
default_action: warn

tools:
  send_email:
    capabilities: [network_send]
    domain_allowlist: [mail.internal]
    pii_action: redact
    mode: enforce
```

Merge behavior is intentionally predictable:

- Scalar values such as `mode`, `pii_action`, and `default_action` are replaced by the tool-level value.
- Lists such as `domain_allowlist`, `file_path_allowlist`, and `capabilities` are replaced, not merged.
- `capability_policy` is shallow-merged so a tool can override one capability without redefining the entire map.
- Unregistered tools fall back to the global policy.

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
- A full multi-tenant control plane or dashboard

Those may become future architecture layers, but they are intentionally outside the current SDK scope.

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
