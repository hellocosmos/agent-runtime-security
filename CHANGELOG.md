# Changelog

Follows [Keep a Changelog](https://keepachangelog.com/) format.

## [Unreleased]

### Added

- **First-party HTTP API extension** — `asr.api` now ships inside the main repository
  - FastAPI app factory and `asr-api` CLI entrypoint
  - Packaged starter presets for `default`, `internal-agent`, `mcp-server`, and `customer-support`
  - API-focused scanner extensions for SQL injection, command injection, path traversal, SSRF, and exfiltration signals
  - Additional PII profiles for `payment`, `jp`, and `cn`

### Changed

- **Documentation refresh** — README, Korean README, example docs, and API extension docs now describe the repository as a unified SDK plus optional HTTP extension

## [0.3.0] - 2026-04-07

### Added

- **Unified decorator API** — `guard.tool()` now protects both sync and async tools with one decorator
  - Function name or `name=` is used to resolve the tool identifier
  - Per-tool audit logger override support
- **YAML v2 tool overrides** — `tools:` section adds per-tool policy configuration on top of global defaults
  - Scalar values replace global defaults
  - List values replace global defaults
  - `capability_policy` uses shallow merge semantics
- **Richer blocked errors** — `BlockedToolError` now provides:
  - Short `str()` output for logs and user-facing messages
  - `to_dict()` for structured responses and telemetry
  - `debug_message()` for operator-friendly diagnostics

### Changed

- **Guard resolution path** — `before_tool()`, `after_tool()`, decorator calls, and adapters now share the same resolved-config path for YAML v2 behavior
- **Examples and docs** — README, MCP example docs, and demo scripts now document the `guard.tool()`-first model and YAML v2 policy layout
- **Package version** — bumped to `0.3.0`

### Deprecated

- **`guard.protect()`** — deprecated in favor of `guard.tool()`, scheduled for removal in `v0.4.0`
- **`mcp_guard()`** — deprecated in favor of `guard.tool()`, while remaining available as an MCP compatibility wrapper during the `v0.3.x` transition

### Notes

- Tool-specific capabilities should now be defined in `policy.yaml` under `tools:`
- Existing `version: 1` policy files remain supported without `tools:`

## [0.2.0] - 2026-04-04

### Added

- **LangChain adapter** — `guard_tool()` wraps any LangChain `BaseTool` with Guard policy enforcement
  - Block → `ToolException` (compatible with `handle_tool_error`)
  - Automatic PII redaction on tool results
  - Audit logging support
- **LangGraph adapter** — `create_guarded_tool_node()` wraps all tools in a `ToolNode` with Guard
  - Per-tool capability mapping via `capabilities_map`
  - Works inside LangGraph state graphs
- **New optional dependencies** — `langchain` and `langgraph` extras
  - `pip install agent-runtime-security[langchain]`
  - `pip install agent-runtime-security[langgraph]`
- **New examples** — `langchain_agent.py` and `langgraph_agent.py`

## [0.1.0] - 2026-04-03

Initial public release.

### Added

- **Guard** — before_tool/after_tool policy evaluation engine
  - 6-step policy evaluation order: Tool Blocklist → Egress Control → File Path → PII Detection → Capability Fallback → Default Action
  - shadow / warn / enforce rollout modes
  - `protect` decorator, `from_config`, `from_policy_file` factories
- **Scanner** — 8 regex-based input scanner patterns (with CSS false-positive prevention)
- **AuditLogger** — structured JSONL audit logger (ScanEvent, GuardBefore, GuardAfter, ErrorEvent)
- **PII detection/redaction** — email, phone number, API key, bearer token, and secret patterns
- **MCP adapter** — `mcp_guard` async decorator for MCP tool handler protection
- **Policy file loading** — JSON/YAML policy file support
- **Egress policy** — URL + email recipient domain control
- **File path policy** — path allowlist-based file access control
- **Capability fallback** — default action for tools not matched by any specific policy
- **Examples** — MCP server example, demo runner, YAML policy sample
- **Docs** — English/Korean README, examples documentation

### Notes

- Python 3.11+ support
- Zero required dependencies (mcp, pyyaml, pymupdf are optional)
- Inspired by Google DeepMind's "AI Agent Traps" paper (2026)
