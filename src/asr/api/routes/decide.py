"""Decision endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from asr.api.auth import verify_api_key
from asr.api.models import DecideRequest
from asr.api.service import decide_tool_use


router = APIRouter(tags=["decide"])


@router.post("/decide", dependencies=[Depends(verify_api_key)])
def decide_route(payload: DecideRequest, request: Request) -> dict:
    result = decide_tool_use(
        tool_name=payload.tool_name,
        args=payload.args,
        capabilities=payload.capabilities,
        policy=payload.policy,
        policy_preset=payload.policy_preset,
        mode=payload.mode,
        pii_profiles=payload.pii_profiles,
    )
    return {"ok": True, "data": result, "request_id": request.state.request_id}
