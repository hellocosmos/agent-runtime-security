# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Agent Runtime Security (ARS) — a Python SDK that controls and audits tool calls made by privileged AI agents. Inspired by Google DeepMind's "AI Agent Traps" paper (2026). Guard (action control) and Audit (evidence) are the core value; Scanner (input detection) is a regex-based first-pass filter.

## Development Commands

```bash
# Install (dev mode)
pip install -e ".[dev]"

# Run all tests
pytest

# Single test file
pytest tests/test_guard.py -v

# Specific test
pytest tests/test_guard.py::TestGuardBeforeTool::test_blocklist_highest_priority -v

# Filter by keyword
pytest -k "pii" -v
```

## Architecture

```
asr/
├── guard.py        ← Core. before_tool/after_tool policy evaluation, protect decorator, shadow/warn/enforce modes
├── audit.py        ← Core. JSONL structured logger (ScanEvent/GuardBefore/GuardAfter/ErrorEvent)
├── scanner.py      ← 11 regex-based input scanner patterns (first-pass filter)
├── policies.py     ← 6 policy evaluation functions (called in order by guard.py)
├── pii.py          ← PII detection/redaction with regional profile system (global-core/kr/us/eu-iban)
├── redaction.py    ← Recursive text extraction and PII redaction helpers (profile-aware)
├── types.py        ← Shared dataclasses (Finding, ScanResult, BeforeToolDecision, AfterToolDecision)
├── mcp.py          ← MCP tool handler async decorator (mcp optional dependency)
└── utils.py        ← PDF text extraction utility (pymupdf optional dependency)
```

### Guard Policy Evaluation Order (must maintain this order)

1. Tool Blocklist → 2. Egress Control → 3. File Path → 4. PII Detection → 5. Capability (fallback) → 6. Default Action

**`matched_any_specific` pattern:** If any of Egress/FilePath/PII matched a tool, Capability is skipped. Capability is a true fallback that only applies when no specific policy matched.

**Most restrictive judgment wins among specific policies:** Only `block` returns immediately; `warn` is collected, and if a more restrictive result appears later, that result is returned.

### Guard Operating Modes (shadow/warn/enforce)

- `enforce` (default) — apply policy results as-is
- `warn` — downgrade block→warn, allow execution but record warning
- `shadow` — allow everything, record original judgment in `original_action`

**Only before_tool is affected by mode; after_tool PII redaction is always enforced regardless of mode.** Shadow means "defer action blocking," not "defer data protection."

Decision objects contain `original_action` (raw policy result) and `mode` fields. Callbacks (`on_block`, `on_warn`) fire based on `effective_action`.

### Guard Egress Policy — URLs + Email Recipients

Egress policy inspects not just URLs but also email recipient fields (`to`, `recipient`, `recipients`). Entry condition: `has_url(args) or has_email_destination(args)`.

### Guard after_tool Type Preservation

`after_tool()` redaction preserves the original result type (str→str, dict→dict recursive, list→list recursive). Never convert with `str(result)`.

### Scanner Patterns (11)

1. `css_hidden_text` — injection phrases inside CSS-hidden text
2. `html_comment_injection` — injection inside HTML comments
3. `metadata_injection` — injection inside aria-label/alt/title attributes
4. `markdown_link_payload` — injection inside markdown link text
5. `prompt_injection_keywords` — general prompt injection keywords
6. `base64_encoded_instruction` — base64-encoded injection instructions
7. `invisible_unicode` — invisible Unicode character detection (3+ chars)
8. `role_override_attempt` — role override attempts (SYSTEM:, Assistant:, etc.)
9. `suspicious_url` — shortened URL services (10) + direct IP access
10. `data_exfil_phrase` — data exfiltration intent phrases (English 7 + Korean 2)
11. `encoded_bypass` — hex/unicode/HTML entity encoding bypass attempts

CSS hidden text false-positive prevention: only flags when hidden region contains an injection phrase (avoids flagging accessibility skip links).

### PII Profile System

PII detection supports regional profiles via the `profiles` parameter:

```python
detect_pii(text, profiles=["global-core", "kr"])
redact_pii(text, profiles=["global-core", "us"])
has_pii(text, profiles=["eu-iban"])
```

Available profiles:
- `global-core` — email, phone, API key, bearer token, secret
- `kr` — Korean resident number (KRN), business registration number (BRN), bank account
- `us` — Social Security Number (SSN)
- `eu-iban` — IBAN

`profiles=None` runs all patterns (backward compatible). Guard accepts `pii_profiles` in `__init__` and `from_config()`, propagating through policies and redaction.

### PII Exempt Fields

`_PII_EXEMPT_KEYS` (`to`, `from`, `recipient`, `recipients`, `cc`, `bcc`) are excluded from PII scanning. Recipient emails are normal business data.

### MCP Guard Adapter

`mcp_guard` decorator protects MCP tool handlers (async def) with Guard policies. Import: `from asr.mcp import mcp_guard`. `mcp` package is an optional dependency.

- Guard stays sync; only `mcp_guard` is an async wrapper
- `BlockedToolError` → MCP `ToolError` (`isError=True`)
- Stricter PII protection than `guard.protect`: returns masked result even with `pii_action="warn"`
- Raises `TypeError` at decoration time if applied to a sync function

### Audit Schema — mode Field

Audit logs include `decision` (backward compatible) + `effective_action`, `original_action`, `mode`. after_tool events include `protection_type: "data_protection"`.

## Language and Coding Rules

- **Code comments, docstrings, commit messages, documentation: English** (this is a global OSS project)
- Variable/function names: English
- Indentation: 2 spaces
- Python 3.11+, minimize external dependencies (prefer standard library)
