# MCP Protection Pack

Security guidance for teams that connect internal tools such as Notion, Jira, Slack,
databases, and email systems through MCP servers.

## Risks This Pack Targets

MCP servers give AI agents access to real tools. That unlocks useful workflows, but it also
creates real operational risk:

| Risk | Example | Impact |
|------|---------|--------|
| Data exfiltration | An agent sends database results to an external URL | Customer or business data exposure |
| Unauthorized actions | An agent calls `drop_table` or `delete_database` | Data loss or service damage |
| PII exposure | Search results contain resident IDs, email addresses, or phone numbers | Privacy and compliance incidents |
| Prompt injection | Hidden instructions in external content steer the agent | Unintended tool behavior |

## Recommended Baseline

### Policy preset: `mcp-server`

```bash
curl -X POST http://127.0.0.1:8000/v1/decide \
  -H "Authorization: Bearer YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "send_email",
    "args": {"to": "external@gmail.com", "body": "quarterly revenue report"},
    "capabilities": ["email_send"],
    "policy_preset": "mcp-server"
  }'
```

What `mcp-server` does:

| Policy area | Behavior |
|-------------|----------|
| Outbound transfer control | Blocks HTTP and email destinations outside the allowlist |
| High-risk tools | Blocks tools such as `shell_exec`, `eval`, and `delete_database` |
| PII handling | Redacts PII from tool results in warn mode |
| File access | Blocks access outside approved directories |
| Capability fallback | Enforces `network_send`, `credential_access`, `bulk_export`, and similar capabilities |

### PII profile selection

```bash
# Korea-focused deployment
"pii_profiles": ["global-core", "kr"]

# Global deployment with payment handling
"pii_profiles": ["global-core", "payment"]

# Japan-focused deployment
"pii_profiles": ["global-core", "jp"]
```

| Profile | Coverage |
|---------|----------|
| `global-core` | Email, phone, API keys, bearer tokens, generic secrets |
| `kr` | Korean resident numbers, business registration numbers, bank accounts |
| `payment` | Visa, Mastercard, Amex, Discover, JCB, UnionPay card numbers |

Full profile list: [coverage.md](./coverage.md)

## Recommended Rollout

Do not start with strict enforcement on day one. A three-phase rollout is safer.

### Phase 1: Shadow

```json
{
  "tool_name": "send_email",
  "args": {"to": "external@unknown.com"},
  "policy_preset": "mcp-server",
  "mode": "shadow"
}
```

- All tool calls are allowed
- `original_action` records what the policy would have done
- No traffic is blocked yet
- This phase is for allowlist tuning and false-positive review

Review items:

- Legitimate tools being marked as block: expand `domain_allowlist`
- Too many warnings: tune `capability_policy`

### Phase 2: Warn

```json
{
  "mode": "warn"
}
```

- Blocks are downgraded to warnings
- Workflows continue to run
- Teams can review operational pressure before enforcing hard stops
- PII redaction still applies

### Phase 3: Enforce

```json
{
  "mode": "enforce"
}
```

- Policy violations are actually blocked
- This should happen only after the allowlist, blocklist, and capability rules are stable

## MCP Tool Handler Example

```python
import httpx
from mcp.server import Server

ASR_API_KEY = "YOUR_API_KEY"
ASR_API_URL = "http://127.0.0.1:8000/v1"

server = Server("my-mcp-server")


async def check_tool(tool_name: str, args: dict, capabilities: list[str]) -> dict:
    """Request a pre-execution policy decision."""
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{ASR_API_URL}/decide",
            headers={"Authorization": f"Bearer {ASR_API_KEY}"},
            json={
                "tool_name": tool_name,
                "args": args,
                "capabilities": capabilities,
                "policy_preset": "mcp-server",
            },
        )
        return resp.json()


async def redact_result(tool_name: str, result: str) -> str:
    """Redact PII from the tool result before returning it to the agent."""
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{ASR_API_URL}/redact",
            headers={"Authorization": f"Bearer {ASR_API_KEY}"},
            json={
                "tool_name": tool_name,
                "result": result,
                "pii_profiles": ["global-core", "kr"],
            },
        )
        data = resp.json()
        return data["data"]["redacted_result"]


@server.tool()
async def send_email(to: str, subject: str, body: str) -> str:
    decision = await check_tool(
        "send_email",
        {"to": to, "subject": subject, "body": body},
        ["email_send", "network_send"],
    )
    if decision["data"]["action"] == "block":
        return f"Blocked: {decision['data']['reason']}"

    result = actually_send_email(to, subject, body)
    return await redact_result("send_email", result)
```

## False Positive Guide

### A legitimate tool call is blocked

| Cause | Fix |
|------|-----|
| Missing approved domain | Add it to `domain_allowlist` or pass a custom `policy` |
| Required capability is blocked | Change that capability to `warn` in `capability_policy` |
| The tool is on the blocklist | Remove it from `tool_blocklist` |

### Non-sensitive data gets redacted

| Cause | Fix |
|------|-----|
| A phone-like number matched a broad profile | Specify a narrower `pii_profiles` list |
| A regional profile is unnecessary | Use only the profiles your workflow really needs |

### Passing a custom policy directly

If the preset is close but not quite right, send `policy` inline:

```json
{
  "tool_name": "send_email",
  "args": {"to": "partner@allowed.com"},
  "policy": {
    "version": 1,
    "mode": "enforce",
    "block_egress": true,
    "domain_allowlist": ["allowed.com", "*.mycompany.com"],
    "tool_blocklist": ["shell_exec", "eval"],
    "pii_action": "warn",
    "default_action": "warn"
  }
}
```

## What This Pack Includes

| Item | Included |
|------|----------|
| Policy preset | `mcp-server` |
| PII profiles | `global-core` plus regional extensions |
| Detection patterns | Full HTTP API scan coverage |
| Rollout guide | `shadow -> warn -> enforce` |
| Integration example | Python MCP server example |
| False-positive guidance | Common tuning advice |

Questions or feedback: **hellocosmos@gmail.com**
