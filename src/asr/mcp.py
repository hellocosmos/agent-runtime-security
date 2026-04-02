"""MCP Guard 어댑터 — MCP tool handler를 Guard 정책으로 보호하는 데코레이터"""
from __future__ import annotations

import functools
import inspect
import uuid
from typing import Any, Callable

from asr.audit import AuditLogger
from asr.guard import Guard


def mcp_guard(
    guard: Guard,
    *,
    audit: AuditLogger | None = None,
    tool_name: str | None = None,
    capabilities: list[str] | None = None,
    trace_id_getter: Callable[..., str | None] | None = None,
):
    """MCP tool handler를 Guard 정책으로 보호하는 async 데코레이터

    Args:
        guard: Guard 인스턴스
        audit: 감사 로거. 설정 시 before/after 자동 기록
        tool_name: Guard에 전달할 도구 이름. None이면 fn.__name__
        capabilities: 도구의 capability 태그
        trace_id_getter: trace_id 추출 함수(**kwargs를 받음). None이면 UUID 자동 생성
    """
    def decorator(fn: Callable) -> Callable:
        # 데코레이션 시점에 sync 함수 검사
        if not inspect.iscoroutinefunction(fn):
            raise TypeError(
                f"mcp_guard requires async def tool handlers, "
                f"but '{fn.__name__}' is sync"
            )

        name = tool_name or fn.__name__

        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            # positional args를 파라미터 이름에 매핑 (guard.protect 패턴과 동일)
            sig = inspect.signature(fn)
            try:
                bound = sig.bind_partial(*args, **kwargs)
                bound.apply_defaults()
                named_args = dict(bound.arguments)
            except TypeError:
                named_args = kwargs.copy()

            # trace_id 생성
            trace_id = None
            if trace_id_getter is not None:
                trace_id = trace_id_getter(**named_args)
            if trace_id is None:
                trace_id = str(uuid.uuid4())

            # before_tool 정책 평가
            decision = guard.before_tool(name, named_args, capabilities=capabilities)

            if audit is not None:
                audit.log_guard(decision, trace_id=trace_id)

            if decision.action == "block":
                _raise_tool_error(
                    f"Tool '{name}' blocked by policy "
                    f"'{decision.policy_id}': {decision.reason}"
                )

            # tool handler 실행
            result = await fn(*args, **kwargs)

            # after_tool 결과 PII 검사
            after_decision = guard.after_tool(name, result)

            if audit is not None:
                audit.log_guard(after_decision, trace_id=trace_id)

            # PII 보호: redact_result 또는 warn이면서 마스킹 결과가 있으면 반환
            # guard.protect보다 엄격 — warn에서도 PII가 누출되지 않도록 redacted 반환
            if after_decision.redacted_result is not None and after_decision.action in (
                "redact_result", "warn"
            ):
                return after_decision.redacted_result

            return result

        return wrapper
    return decorator


def _raise_tool_error(message: str) -> None:
    """MCP ToolError가 있으면 사용, 없으면 RuntimeError로 fallback"""
    try:
        from mcp.server.fastmcp.exceptions import ToolError
        raise ToolError(message)
    except ImportError:
        raise RuntimeError(message)
