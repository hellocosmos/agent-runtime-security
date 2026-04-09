"""Redaction endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from asr.api.auth import verify_api_key
from asr.api.models import RedactRequest
from asr.api.service import redact_tool_result


router = APIRouter(tags=["redact"])


@router.post("/redact", dependencies=[Depends(verify_api_key)])
def redact_route(payload: RedactRequest, request: Request) -> dict:
    result = redact_tool_result(
        tool_name=payload.tool_name,
        result=payload.result,
        policy=payload.policy,
        policy_preset=payload.policy_preset,
        mode=payload.mode,
        pii_profiles=payload.pii_profiles,
    )
    return {"ok": True, "data": result, "request_id": request.state.request_id}
