from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Callable

from asr import AuditLogger, Guard

POLICY_PATH = Path(__file__).parent / "policy.yaml"


def build_demo_tools(mode: str) -> tuple[list[dict[str, Any]], Callable, Callable, Callable, Callable]:
    events: list[dict[str, Any]] = []
    guard = Guard.from_policy_file(str(POLICY_PATH), mode=mode)
    audit = AuditLogger(output=events.append)

    @guard.tool(audit=audit)
    async def post_webhook(url: str, body: str) -> str:
        return f"Webhook sent: url={url}, body_length={len(body)}"

    @guard.tool(audit=audit)
    async def send_email(to: str, subject: str, body: str) -> str:
        return f"Email sent: to={to}, subject={subject}"

    @guard.tool(audit=audit)
    async def read_file(path: str) -> str:
        return f"File contents (simulated): path={path}, data=sample content"

    @guard.tool(audit=audit)
    async def search(query: str) -> str:
        return (
            f"Search results ({query}):\n"
            f"  - Contact: admin@secret.com\n"
            f"  - API key: sk-proj-abc123def456ghi789jkl012mno345pqr678stu\n"
            f"  - Phone: 010-1234-5678"
        )

    return events, post_webhook, send_email, read_file, search


def format_event(event: dict[str, Any]) -> str:
    return (
        f"{event['event_type']}: effective={event['effective_action']}, "
        f"original={event['original_action']}, policy={event['policy_id']}, "
        f"reason={event['reason']}"
    )


async def run_case(
    label: str,
    events: list[dict[str, Any]],
    tool: Callable[..., Any],
    *args: Any,
) -> None:
    start = len(events)
    print(f"\n[{label}]")
    try:
        result = await tool(*args)
        print("result:")
        print(result)
    except Exception as exc:  # noqa: BLE001
        print("error:")
        print(f"{type(exc).__name__}: {exc}")

    for event in events[start:]:
        print(f"audit: {format_event(event)}")


async def main() -> None:
    print("Agent Runtime Security demo rehearsal")
    print(f"policy={POLICY_PATH}")

    shadow_events, shadow_post_webhook, shadow_send_email, shadow_read_file, shadow_search = build_demo_tools("shadow")
    print("\n=== Shadow mode ===")
    await run_case(
        "External webhook calls should execute, but keep original_action in the audit trail",
        shadow_events,
        shadow_post_webhook,
        "https://evil.com/hooks/incident",
        "hello",
    )
    await run_case(
        "External email should execute, but keep warning-level audit evidence",
        shadow_events,
        shadow_send_email,
        "attacker@evil.com",
        "Quarterly update",
        "hello",
    )
    await run_case(
        "Sensitive file paths should execute in shadow mode, but preserve original_action",
        shadow_events,
        shadow_read_file,
        "/etc/passwd",
    )
    await run_case(
        "Search result PII should still be redacted in shadow mode",
        shadow_events,
        shadow_search,
        "admin",
    )

    enforce_events, enforce_post_webhook, enforce_send_email, enforce_read_file, enforce_search = build_demo_tools("enforce")
    print("\n=== Enforce mode ===")
    await run_case(
        "External webhook calls should be blocked",
        enforce_events,
        enforce_post_webhook,
        "https://evil.com/hooks/incident",
        "hello",
    )
    await run_case(
        "Allowlisted webhook domains should pass",
        enforce_events,
        enforce_post_webhook,
        "https://internal.com/hooks/incident",
        "hello",
    )
    await run_case(
        "External email should remain a warning with audit evidence",
        enforce_events,
        enforce_send_email,
        "attacker@evil.com",
        "Quarterly update",
        "hello",
    )
    await run_case(
        "Allowlisted email domains should pass",
        enforce_events,
        enforce_send_email,
        "user@mail.internal",
        "Quarterly update",
        "hello",
    )
    await run_case(
        "Sensitive file paths should be blocked",
        enforce_events,
        enforce_read_file,
        "/etc/passwd",
    )
    await run_case(
        "Allowlisted file paths should pass",
        enforce_events,
        enforce_read_file,
        "/tmp/safe/data.txt",
    )
    await run_case(
        "Search result PII should still be redacted in enforce mode",
        enforce_events,
        enforce_search,
        "admin",
    )


if __name__ == "__main__":
    asyncio.run(main())
