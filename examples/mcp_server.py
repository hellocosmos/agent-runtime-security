"""ARS MCP example server for Guard policy demos.

Run with: python examples/mcp_server.py
Or:       mcp dev examples/mcp_server.py

Demo flow:
  1. mode: shadow (default) - allow all calls and record original_action in audit
  2. change policy.yaml to mode: enforce and rerun - apply policies for real
"""
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from asr import Guard, AuditLogger
from asr.mcp import mcp_guard

# Build Guard from the policy file.
POLICY_PATH = Path(__file__).parent / "policy.yaml"
guard = Guard.from_policy_file(str(POLICY_PATH))
audit = AuditLogger(output="stdout")

mcp = FastMCP("ARS Demo Server")


@mcp.tool()
@mcp_guard(guard, audit=audit, capabilities=["network_send"])
async def post_webhook(url: str, body: str) -> str:
    """Send a webhook (simulated).

    URL-based egress policy blocks destinations outside the domain allowlist.
    This is the clearest blocking demo for external network calls.
    """
    return f"Webhook sent: url={url}, body_length={len(body)}"


@mcp.tool()
@mcp_guard(guard, audit=audit, capabilities=["network_send"])
async def send_email(to: str, subject: str, body: str) -> str:
    """Send an email (simulated).

    Recipient domains are inspected by egress policy.
    In this demo, external email destinations produce a warning and remain auditable.
    """
    return f"Email sent: to={to}, subject={subject}"


@mcp.tool()
@mcp_guard(guard, audit=audit, capabilities=["file_read"])
async def read_file(path: str) -> str:
    """Read a file (simulated).

    Only paths inside file_path_allowlist are allowed.
    Sensitive paths such as /etc/passwd are blocked.
    """
    return f"File contents (simulated): path={path}, data=sample content"


@mcp.tool()
@mcp_guard(guard, audit=audit)
async def search(query: str) -> str:
    """Search data (simulated).

    Search results are automatically redacted when they contain PII such as
    emails or API keys. With pii_action=block they are replaced with labels
    such as [EMAIL] and [API_KEY].
    """
    # Intentionally include PII in the simulated result.
    return (
        f"Search results ({query}):\n"
        f"  - Contact: admin@secret.com\n"
        f"  - API key: sk-proj-abc123def456ghi789jkl012mno345pqr678stu\n"
        f"  - Phone: 010-1234-5678"
    )


if __name__ == "__main__":
    mcp.run()
