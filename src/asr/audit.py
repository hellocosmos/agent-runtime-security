"""감사 로그 모듈 — 전 구간 구조화 JSONL 기록"""

from __future__ import annotations

import json
import uuid
import warnings
from datetime import datetime, timezone
from typing import Any, Callable

from asr.types import BeforeToolDecision, AfterToolDecision, ScanResult


class AuditLogger:
    """JSONL 구조화 감사 로거"""

    def __init__(self, output: str | Callable[[dict], Any] = "stdout", store_raw: bool = False):
        self._output = output
        self._store_raw = store_raw
        if store_raw:
            warnings.warn("store_raw=True: 원문이 로그에 포함됩니다. 민감정보 노출 위험이 있습니다.",
                         UserWarning, stacklevel=2)

    def log_scan(self, result: ScanResult, trace_id: str) -> None:
        event = self._base_event(trace_id, "scan", "scanner")
        event.update({
            "source_type": result.source_type, "source_ref": result.source_ref,
            "score": result.score, "severity": result.severity,
            "findings": [f.pattern_id for f in result.findings],
            "redacted_excerpt": result.redacted_excerpt,
        })
        self._emit(event)

    def log_guard(self, decision: BeforeToolDecision | AfterToolDecision, trace_id: str) -> None:
        if isinstance(decision, BeforeToolDecision):
            event = self._base_event(trace_id, "guard_before", "guard")
            event.update({
                "tool_name": decision.tool_name, "capabilities": decision.capabilities,
                "decision": decision.action, "reason": decision.reason,
                "policy_id": decision.policy_id, "severity": decision.severity,
                "redacted_args": decision.redacted_args,
            })
        else:
            event = self._base_event(trace_id, "guard_after", "guard")
            event.update({
                "tool_name": decision.tool_name, "decision": decision.action,
                "reason": decision.reason, "policy_id": decision.policy_id,
                "severity": decision.severity, "redacted_result": decision.redacted_result,
            })
        self._emit(event)

    def log_error(self, error_type: str, error_message: str, trace_id: str,
                  severity: str = "high", tool_name: str | None = None,
                  stack_trace: str | None = None) -> None:
        event = self._base_event(trace_id, "error", "system")
        event.update({
            "error_type": error_type, "error_message": error_message,
            "tool_name": tool_name, "severity": severity,
            "stack_trace": stack_trace if self._store_raw else None,
        })
        self._emit(event)

    def _base_event(self, trace_id: str, event_type: str, module: str) -> dict:
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "trace_id": trace_id, "event_id": str(uuid.uuid4()),
            "event_type": event_type, "module": module,
        }

    def _emit(self, event: dict) -> None:
        line = json.dumps(event, ensure_ascii=False, default=str)
        if callable(self._output):
            self._output(event)
        elif self._output == "stdout":
            print(line, flush=True)
        else:
            with open(self._output, "a", encoding="utf-8") as f:
                f.write(line + "\n")
