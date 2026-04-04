# Changelog

Follows [Keep a Changelog](https://keepachangelog.com/) format.

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
