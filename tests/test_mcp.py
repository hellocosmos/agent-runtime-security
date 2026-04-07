"""Tests for the mcp_guard decorator."""
import warnings

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from asr.audit import AuditLogger
from asr.guard import Guard, BlockedToolError
from asr.mcp import mcp_guard


class TestMcpGuardDeprecated:
    async def test_mcp_guard_warns_future(self):
        guard = Guard(default_action="allow")
        with pytest.warns(FutureWarning, match="guard.tool"):
            @mcp_guard(guard)
            async def my_tool(x: str) -> str:
                return x

    async def test_mcp_guard_still_works(self):
        guard = Guard(default_action="allow")
        with pytest.warns(FutureWarning):
            @mcp_guard(guard)
            async def my_tool(x: str) -> str:
                return f"result: {x}"
        assert await my_tool(x="hello") == "result: hello"

    async def test_trace_id_getter_warns(self):
        guard = Guard(default_action="allow")
        with pytest.warns(FutureWarning, match="trace_id_getter"):
            @mcp_guard(guard, trace_id_getter=lambda **kw: "abc")
            async def my_tool(x: str) -> str:
                return x


@pytest.mark.filterwarnings("ignore::FutureWarning")
class TestMcpGuardBlocking:
    """mcp_guard converts BlockedToolError to ToolError for MCP compat."""

    async def test_blocked_tool_raises_tool_error(self):
        guard = Guard(tool_blocklist=["dangerous_tool"])

        @mcp_guard(guard)
        async def dangerous_tool(cmd: str) -> str:
            return "should not reach"

        with pytest.raises(ToolError):
            await dangerous_tool(cmd="rm -rf /")

    async def test_allowed_tool_executes(self):
        guard = Guard(default_action="allow")

        @mcp_guard(guard)
        async def safe_tool(query: str) -> str:
            return f"result: {query}"

        result = await safe_tool(query="hello")
        assert result == "result: hello"

    async def test_block_message_includes_policy_info(self):
        guard = Guard(tool_blocklist=["blocked_tool"])

        @mcp_guard(guard)
        async def blocked_tool() -> str:
            return "nope"

        with pytest.raises(ToolError) as exc_info:
            await blocked_tool()
        msg = str(exc_info.value)
        assert "blocked_tool" in msg
        assert "tool_blocklist" in msg

    async def test_shadow_mode_allows_blocked_tool(self):
        guard = Guard(mode="shadow", tool_blocklist=["dangerous_tool"])

        @mcp_guard(guard)
        async def dangerous_tool(cmd: str) -> str:
            return "executed"

        result = await dangerous_tool(cmd="rm -rf /")
        assert result == "executed"

    async def test_warn_mode_allows_blocked_tool(self):
        guard = Guard(mode="warn", tool_blocklist=["dangerous_tool"])

        @mcp_guard(guard)
        async def dangerous_tool(cmd: str) -> str:
            return "executed"

        result = await dangerous_tool(cmd="rm -rf /")
        assert result == "executed"


@pytest.mark.filterwarnings("ignore::FutureWarning")
class TestMcpGuardSyncCheck:
    """mcp_guard now delegates to guard.tool() which supports sync functions."""

    def test_sync_handler_accepted(self):
        guard = Guard(default_action="allow")

        @mcp_guard(guard)
        def sync_handler(x: str) -> str:
            return x

        assert sync_handler(x="hello") == "hello"


@pytest.mark.filterwarnings("ignore::FutureWarning")
class TestMcpGuardRedaction:
    """PII redaction after tool execution."""

    async def test_result_pii_redacted_on_block_action(self):
        guard = Guard(pii_action="block")

        @mcp_guard(guard)
        async def search(query: str) -> str:
            return "Found: admin@secret.com in records"

        result = await search(query="admin")
        assert "admin@secret.com" not in result
        assert "[EMAIL]" in result

    async def test_result_pii_not_redacted_on_warn_action(self):
        """guard.tool() does not force redaction on warn (unlike old mcp_guard)."""
        guard = Guard(pii_action="warn")

        @mcp_guard(guard)
        async def search(query: str) -> str:
            return "Found: admin@secret.com in records"

        result = await search(query="admin")
        # guard.tool() passes through the original result on warn
        assert result == "Found: admin@secret.com in records"

    async def test_clean_result_passes_through(self):
        guard = Guard(pii_action="block")

        @mcp_guard(guard)
        async def search(query: str) -> str:
            return "No sensitive data here"

        result = await search(query="test")
        assert result == "No sensitive data here"


@pytest.mark.filterwarnings("ignore::FutureWarning")
class TestMcpGuardAudit:
    """Automatic audit logging."""

    async def test_audit_logs_before_and_after(self):
        events = []
        guard = Guard(default_action="allow", pii_action="off")
        audit = AuditLogger(output=events.append)

        @mcp_guard(guard, audit=audit)
        async def safe_tool(query: str) -> str:
            return "result"

        await safe_tool(query="hello")
        assert len(events) == 2
        assert events[0]["event_type"] == "guard_before"
        assert events[1]["event_type"] == "guard_after"

    async def test_audit_logs_block_only_before(self):
        events = []
        guard = Guard(tool_blocklist=["blocked"])
        audit = AuditLogger(output=events.append)

        @mcp_guard(guard, audit=audit)
        async def blocked() -> str:
            return "nope"

        with pytest.raises(Exception):
            await blocked()
        assert len(events) == 1
        assert events[0]["event_type"] == "guard_before"

    async def test_audit_shares_trace_id(self):
        events = []
        guard = Guard(default_action="allow", pii_action="off")
        audit = AuditLogger(output=events.append)

        @mcp_guard(guard, audit=audit)
        async def my_tool(x: str) -> str:
            return "ok"

        await my_tool(x="test")
        assert events[0]["trace_id"] == events[1]["trace_id"]
        assert len(events[0]["trace_id"]) > 0


@pytest.mark.filterwarnings("ignore::FutureWarning")
class TestMcpGuardOptions:
    """Options for tool_name, capabilities, and trace_id_getter."""

    async def test_custom_tool_name(self):
        events = []
        guard = Guard(default_action="allow")
        audit = AuditLogger(output=events.append)

        @mcp_guard(guard, audit=audit, tool_name="custom_name")
        async def original_name(x: str) -> str:
            return "ok"

        await original_name(x="test")
        assert events[0]["tool_name"] == "custom_name"

    async def test_capabilities_passed_to_guard(self):
        guard = Guard(capability_policy={"shell_exec": "block"})

        @mcp_guard(guard, capabilities=["shell_exec"])
        async def run_cmd(cmd: str) -> str:
            return "output"

        with pytest.raises(ToolError):
            await run_cmd(cmd="ls")

    async def test_trace_id_getter_ignored(self):
        """trace_id_getter is deprecated and ignored; UUID is always generated."""
        events = []
        guard = Guard(default_action="allow")
        audit = AuditLogger(output=events.append)

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FutureWarning)
            @mcp_guard(
                guard, audit=audit,
                trace_id_getter=lambda **kw: kw.get("request_id"),
            )
            async def my_tool(request_id: str, data: str) -> str:
                return "ok"

        await my_tool(request_id="req-123", data="test")
        # trace_id_getter is ignored, so trace_id is a UUID (36 chars)
        assert len(events[0]["trace_id"]) == 36

    async def test_trace_id_is_uuid_format(self):
        events = []
        guard = Guard(default_action="allow")
        audit = AuditLogger(output=events.append)

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FutureWarning)
            @mcp_guard(
                guard, audit=audit,
                trace_id_getter=lambda **kw: None,
            )
            async def my_tool(data: str) -> str:
                return "ok"

        await my_tool(data="test")
        assert len(events[0]["trace_id"]) == 36  # UUID format


@pytest.mark.filterwarnings("ignore::FutureWarning")
class TestMcpGuardErrorPropagation:
    """Handler exceptions should propagate unchanged."""

    async def test_handler_exception_propagates(self):
        guard = Guard(default_action="allow")

        @mcp_guard(guard)
        async def buggy_tool(x: str) -> str:
            raise ValueError("handler bug")

        with pytest.raises(ValueError, match="handler bug"):
            await buggy_tool(x="test")

    async def test_handler_exception_not_caught_as_block(self):
        """Handler ValueError should remain distinct from ToolError."""
        guard = Guard(default_action="allow")

        @mcp_guard(guard)
        async def buggy_tool(x: str) -> str:
            raise ValueError("not a policy block")

        with pytest.raises(ValueError):
            await buggy_tool(x="test")


@pytest.mark.filterwarnings("ignore::FutureWarning")
class TestMcpGuardToolErrorPreserved:
    """mcp_guard must still raise ToolError during deprecation window."""

    async def test_blocked_raises_tool_error_not_blocked_tool_error(self):
        guard = Guard(tool_blocklist=["blocked_tool"])

        @mcp_guard(guard)
        async def blocked_tool() -> str:
            return "nope"

        with pytest.raises(ToolError):
            await blocked_tool()

        # Should NOT be BlockedToolError
        try:
            await blocked_tool()
        except ToolError:
            pass  # correct
        except BlockedToolError:
            pytest.fail("Should raise ToolError, not BlockedToolError")
