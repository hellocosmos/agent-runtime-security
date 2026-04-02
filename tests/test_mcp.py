"""mcp_guard 데코레이터 테스트"""
import pytest
from mcp.server.fastmcp.exceptions import ToolError

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
