"""Guard 모듈 — before_tool/after_tool 정책 평가 및 protect 데코레이터"""
from __future__ import annotations

import functools
import inspect
import logging
from typing import Any, Callable

logger = logging.getLogger("asr.guard")

from asr.pii import has_pii, redact_pii
from asr.policies import (
    evaluate_capability,
    evaluate_egress,
    evaluate_file_path,
    evaluate_pii,
    evaluate_tool_blocklist,
    evaluate_unknown_tool,
    has_email_destination,
    has_url,
)
from asr.types import AfterToolDecision, BeforeToolDecision


# --- 내부 유틸: args에 파일 경로 키가 있는지 확인 ---
_PATH_KEYS = ("path", "file_path", "filepath", "file", "filename")


def _has_path(args: dict) -> bool:
    """args에 파일 경로 키가 있는지 확인"""
    return any(k in args and isinstance(args[k], str) for k in _PATH_KEYS)


class BlockedToolError(Exception):
    """Guard가 도구 호출을 차단했을 때 발생하는 예외"""

    def __init__(self, decision: BeforeToolDecision):
        self.decision = decision
        super().__init__(f"Blocked: {decision.reason} (policy={decision.policy_id})")


class Guard:
    """AI 에이전트 도구 호출 가드

    정책 평가 순서:
    1. tool_blocklist — 최우선
    2. egress (domain_allowlist) — 세부 정책
    3. file_path_allowlist — 세부 정책
    4. pii_detection — 세부 정책
    5. capability_policy — 진짜 fallback (세부 정책이 하나도 해당 안 될 때만)
    6. default_action — 최종 fallback
    """

    def __init__(
        self,
        *,
        mode: str = "enforce",
        domain_allowlist: list[str] | None = None,
        file_path_allowlist: list[str] | None = None,
        pii_action: str = "off",
        block_egress: bool = False,
        tool_blocklist: list[str] | None = None,
        capability_policy: dict[str, str] | None = None,
        default_action: str = "warn",
        on_block: Callable | None = None,
        on_warn: Callable | None = None,
    ):
        if mode not in ("enforce", "warn", "shadow"):
            raise ValueError(f"Invalid mode: {mode!r}. Must be 'enforce', 'warn', or 'shadow'")
        self._mode = mode
        self._domain_allowlist = domain_allowlist or []
        self._file_path_allowlist = file_path_allowlist or []
        self._pii_action = pii_action
        self._block_egress = block_egress
        self._tool_blocklist = tool_blocklist or []
        self._capability_policy = capability_policy or {}
        self._default_action = default_action
        self._on_block = on_block
        self._on_warn = on_warn
        logger.info("Guard initialized (mode=%s)", self._mode)

    # ------------------------------------------------------------------
    # before_tool
    # ------------------------------------------------------------------
    def before_tool(
        self,
        name: str,
        args: dict,
        context: dict | None = None,
        capabilities: list[str] | None = None,
    ) -> BeforeToolDecision:
        """도구 호출 전 정책 평가"""
        caps = capabilities or []
        redacted = self._redact_args(args)

        def _decision(result: dict) -> BeforeToolDecision:
            original = result["action"]
            effective = self._apply_mode(original)
            d = BeforeToolDecision(
                action=effective,
                reason=result["reason"],
                policy_id=result["policy_id"],
                severity=result["severity"],
                tool_name=name,
                redacted_args=redacted,
                capabilities=caps,
                original_action=original,
                mode=self._mode,
            )
            self._fire_callbacks(d)
            return d

        # 1. 블록리스트 — 최우선
        r = evaluate_tool_blocklist(name, args, blocklist=self._tool_blocklist)
        if r is not None:
            return _decision(r)

        # 2~4. 세부 정책 (egress / file_path / pii)
        # matched_any_specific: 세부 정책 중 하나라도 "해당"되었는지 추적
        # worst_result: block이 아닌 결과 중 가장 제한적인 것 (block은 즉시 반환)
        matched_any_specific = False
        worst_result = None

        # 2. Egress 정책
        if self._block_egress and (has_url(args) or has_email_destination(args)):
            matched_any_specific = True
            r = evaluate_egress(
                name, args,
                domain_allowlist=self._domain_allowlist,
                block_egress=self._block_egress,
            )
            if r is not None:
                if r["action"] == "block":
                    return _decision(r)
                worst_result = r

        # 3. 파일 경로 정책
        if self._file_path_allowlist and _has_path(args):
            matched_any_specific = True
            r = evaluate_file_path(name, args, allowlist=self._file_path_allowlist)
            if r is not None:
                if r["action"] == "block":
                    return _decision(r)
                if worst_result is None:
                    worst_result = r

        # 4. PII 정책
        if self._pii_action != "off":
            r = evaluate_pii(name, args, pii_action=self._pii_action)
            if r is not None:
                matched_any_specific = True
                if r["action"] == "block":
                    return _decision(r)
                if worst_result is None:
                    worst_result = r

        # 세부 정책이 하나라도 해당되었으면 → capability 건너뛰고 결과 반환
        if matched_any_specific:
            if worst_result is not None:
                return _decision(worst_result)
            d = BeforeToolDecision(
                action=self._apply_mode("allow"),
                reason="specific_policy_passed",
                policy_id="specific_policy",
                severity="low",
                tool_name=name,
                redacted_args=redacted,
                capabilities=caps,
                original_action="allow",
                mode=self._mode,
            )
            self._fire_callbacks(d)
            return d

        # 5. Capability 정책 — 진짜 fallback
        if caps and self._capability_policy:
            r = evaluate_capability(capabilities=caps, policy=self._capability_policy)
            if r is not None:
                return _decision(r)

        # 6. 최종 fallback — default_action
        r = evaluate_unknown_tool(default=self._default_action)
        return _decision(r)

    # ------------------------------------------------------------------
    # after_tool
    # ------------------------------------------------------------------
    def after_tool(
        self,
        name: str,
        result: Any,
        context: dict | None = None,
    ) -> AfterToolDecision:
        """도구 호출 후 결과 PII 검사 및 마스킹"""
        if self._pii_action == "off":
            return AfterToolDecision(
                action="allow",
                reason="pii_off",
                policy_id="pii_detection",
                severity="low",
                tool_name=name,
                redacted_result=result,
                original_action="allow",
                mode=self._mode,
            )

        text = self._extract_text(result)
        if not has_pii(text):
            return AfterToolDecision(
                action="allow",
                reason="no_pii_in_result",
                policy_id="pii_detection",
                severity="low",
                tool_name=name,
                redacted_result=result,
                original_action="allow",
                mode=self._mode,
            )

        # PII 발견
        redacted = self._redact_result(result)

        if self._pii_action == "block":
            return AfterToolDecision(
                action="redact_result",
                reason="pii_detected_in_result",
                policy_id="pii_detection",
                severity="high",
                tool_name=name,
                redacted_result=redacted,
                original_action="redact_result",
                mode=self._mode,
            )

        # pii_action == "warn"
        return AfterToolDecision(
            action="warn",
            reason="pii_detected_in_result",
            policy_id="pii_detection",
            severity="medium",
            tool_name=name,
            redacted_result=redacted,
            original_action="warn",
            mode=self._mode,
        )

    # ------------------------------------------------------------------
    # protect 데코레이터
    # ------------------------------------------------------------------
    def protect(
        self,
        func: Callable | None = None,
        *,
        capabilities: list[str] | None = None,
    ):
        """도구 함수를 Guard로 보호하는 데코레이터

        사용법:
            @guard.protect
            def my_tool(...): ...

            @guard.protect(capabilities=["shell_exec"])
            def run_cmd(...): ...
        """
        if func is None:
            # @guard.protect(capabilities=["shell_exec"]) 형태
            return functools.partial(self.protect, capabilities=capabilities)

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # positional args를 파라미터 이름에 매핑
            sig = inspect.signature(func)
            try:
                bound = sig.bind_partial(*args, **kwargs)
                bound.apply_defaults()
                named_args = dict(bound.arguments)
            except TypeError:
                named_args = kwargs.copy()

            # before_tool 평가
            tool_name = func.__name__
            decision = self.before_tool(tool_name, named_args, capabilities=capabilities)

            if decision.action == "block":
                raise BlockedToolError(decision)

            # 함수 실행
            result = func(*args, **kwargs)

            # after_tool 평가
            after_decision = self.after_tool(tool_name, result)
            if after_decision.action == "redact_result":
                return after_decision.redacted_result

            return result

        return wrapper

    # ------------------------------------------------------------------
    # 내부 유틸리티
    # ------------------------------------------------------------------
    def _apply_mode(self, original_action: str) -> str:
        """모드에 따라 effective_action 반환"""
        if self._mode == "enforce":
            return original_action
        if self._mode == "warn":
            return "warn" if original_action == "block" else original_action
        # shadow
        return "allow"

    def _redact_args(self, args: dict) -> dict:
        """args dict의 문자열 값에서 PII를 마스킹"""
        redacted = {}
        for key, value in args.items():
            if isinstance(value, str):
                redacted[key] = redact_pii(value)
            elif isinstance(value, dict):
                redacted[key] = self._redact_args(value)
            else:
                redacted[key] = value
        return redacted

    def _fire_callbacks(self, decision: BeforeToolDecision) -> None:
        """block/warn 콜백 호출"""
        if decision.action == "block" and self._on_block:
            self._on_block(decision)
        elif decision.action == "warn" and self._on_warn:
            self._on_warn(decision)

    @staticmethod
    def _extract_text(result: Any) -> str:
        """결과에서 텍스트를 재귀적으로 추출 (PII 검사용, 중첩 dict/list 포함)"""
        if isinstance(result, str):
            return result
        if isinstance(result, dict):
            parts = []
            for v in result.values():
                parts.append(Guard._extract_text(v))
            return " ".join(parts)
        if isinstance(result, (list, tuple)):
            return " ".join(Guard._extract_text(item) for item in result)
        return str(result) if result is not None else ""

    def _redact_result(self, result: Any) -> Any:
        """결과 타입을 보존하면서 PII 마스킹 — 중첩 dict/list도 재귀적으로 처리"""
        if isinstance(result, str):
            return redact_pii(result)
        if isinstance(result, dict):
            return {k: self._redact_result(v) for k, v in result.items()}
        if isinstance(result, (list, tuple)):
            return type(result)(self._redact_result(item) for item in result)
        return result
