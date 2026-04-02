"""mcp_guard 데코레이터 테스트"""
import pytest
from mcp.server.fastmcp.exceptions import ToolError

from asr.audit import AuditLogger
from asr.guard import Guard
from asr.mcp import mcp_guard


class TestMcpGuardBlocking:
    """before_tool에서 block 판정 시 ToolError 발생"""

    async def test_blocked_tool_raises_tool_error(self):
        guard = Guard(tool_blocklist=["dangerous_tool"])

        @mcp_guard(guard)
        async def dangerous_tool(cmd: str) -> str:
            return "should not reach"

        with pytest.raises(ToolError, match="blocked by policy"):
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


class TestMcpGuardSyncCheck:
    """sync 함수에 mcp_guard를 적용하면 TypeError"""

    def test_sync_handler_raises_type_error(self):
        guard = Guard(default_action="allow")

        with pytest.raises(TypeError, match="async"):
            @mcp_guard(guard)
            def sync_handler(x: str) -> str:
                return x


class TestMcpGuardRedaction:
    """after_tool에서 PII redaction"""

    async def test_result_pii_redacted_on_block_action(self):
        guard = Guard(pii_action="block")

        @mcp_guard(guard)
        async def search(query: str) -> str:
            return "Found: admin@secret.com in records"

        result = await search(query="admin")
        assert "admin@secret.com" not in result
        assert "[EMAIL]" in result

    async def test_result_pii_redacted_on_warn_action(self):
        """pii_action=warn에서도 MCP 응답은 마스킹"""
        guard = Guard(pii_action="warn")

        @mcp_guard(guard)
        async def search(query: str) -> str:
            return "Found: admin@secret.com in records"

        result = await search(query="admin")
        assert "admin@secret.com" not in result

    async def test_clean_result_passes_through(self):
        guard = Guard(pii_action="block")

        @mcp_guard(guard)
        async def search(query: str) -> str:
            return "No sensitive data here"

        result = await search(query="test")
        assert result == "No sensitive data here"


class TestMcpGuardAudit:
    """audit 자동 기록"""

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


class TestMcpGuardOptions:
    """tool_name, capabilities, trace_id_getter 옵션"""

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

        from mcp.server.fastmcp.exceptions import ToolError
        with pytest.raises(ToolError, match="blocked by policy"):
            await run_cmd(cmd="ls")

    async def test_trace_id_getter(self):
        events = []
        guard = Guard(default_action="allow")
        audit = AuditLogger(output=events.append)

        @mcp_guard(
            guard, audit=audit,
            trace_id_getter=lambda **kw: kw.get("request_id"),
        )
        async def my_tool(request_id: str, data: str) -> str:
            return "ok"

        await my_tool(request_id="req-123", data="test")
        assert events[0]["trace_id"] == "req-123"

    async def test_trace_id_getter_returns_none_falls_back_to_uuid(self):
        events = []
        guard = Guard(default_action="allow")
        audit = AuditLogger(output=events.append)

        @mcp_guard(
            guard, audit=audit,
            trace_id_getter=lambda **kw: None,
        )
        async def my_tool(data: str) -> str:
            return "ok"

        await my_tool(data="test")
        assert len(events[0]["trace_id"]) == 36  # UUID format


class TestMcpGuardErrorPropagation:
    """handler 내부 예외는 그대로 propagate"""

    async def test_handler_exception_propagates(self):
        guard = Guard(default_action="allow")

        @mcp_guard(guard)
        async def buggy_tool(x: str) -> str:
            raise ValueError("handler bug")

        with pytest.raises(ValueError, match="handler bug"):
            await buggy_tool(x="test")

    async def test_handler_exception_not_caught_as_block(self):
        """handler ValueError는 ToolError와 구분됨"""
        guard = Guard(default_action="allow")

        @mcp_guard(guard)
        async def buggy_tool(x: str) -> str:
            raise ValueError("not a policy block")

        with pytest.raises(ValueError):
            await buggy_tool(x="test")
