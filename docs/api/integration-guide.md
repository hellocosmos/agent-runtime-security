# Integration Guide

A minimal Python and MCP integration guide for the Agent Runtime Security API.

## Where the API Fits

```text
[agent request]
      ↓
  /decide   ← check before the tool runs
      ↓
  [tool execution]
      ↓
  /redact   ← remove PII from the result
      ↓
[result returned to the agent]
```

The smallest practical integration uses `/decide` before tool execution and `/redact` after tool
execution. Add `/scan` when untrusted content enters the workflow before the agent sees it.

## MCP Server Example

```python
import httpx
from mcp.server import Server

ASR_API_URL = "http://127.0.0.1:8000/v1"
ASR_API_KEY = "YOUR_API_KEY"
HEADERS = {
    "Authorization": f"Bearer {ASR_API_KEY}",
    "Content-Type": "application/json",
}

server = Server("protected-server")


async def check_before(tool_name: str, args: dict, capabilities: list[str]) -> dict:
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{ASR_API_URL}/decide",
            headers=HEADERS,
            json={
                "tool_name": tool_name,
                "args": args,
                "capabilities": capabilities,
                "policy_preset": "mcp-server",
            },
        )
        return resp.json()["data"]


async def redact_after(tool_name: str, result):
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{ASR_API_URL}/redact",
            headers=HEADERS,
            json={
                "tool_name": tool_name,
                "result": result,
                "pii_profiles": ["global-core", "kr"],
            },
        )
        return resp.json()["data"]["redacted_result"]


@server.tool()
async def send_email(to: str, subject: str, body: str) -> str:
    decision = await check_before(
        "send_email",
        {"to": to, "subject": subject, "body": body},
        ["email_send"],
    )
    if decision["action"] == "block":
        return f"Blocked: {decision['reason']}"

    result = actually_send_email(to, subject, body)
    return await redact_after("send_email", result)
```

## Rollout: Shadow -> Warn -> Enforce

Use the `mode` field to control rollout behavior.

1. `shadow`
   Record what would have happened without blocking or warning the workflow.
2. `warn`
   Downgrade blocks into warnings so the team can see real policy pressure without immediately stopping traffic.
3. `enforce`
   Apply the actual policy outcome.

## Error Handling

```python
async def safe_decide(tool_name, args, capabilities):
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{ASR_API_URL}/decide",
                headers=HEADERS,
                json={
                    "tool_name": tool_name,
                    "args": args,
                    "capabilities": capabilities,
                    "policy_preset": "mcp-server",
                },
            )
            resp.raise_for_status()
            return resp.json()["data"]
    except (httpx.HTTPStatusError, httpx.ConnectError):
        return {"action": "allow", "reason": "api_unavailable"}  # fail open
```

For early rollout, fail-open behavior is usually safer than taking a production workflow down because the API is unreachable.
