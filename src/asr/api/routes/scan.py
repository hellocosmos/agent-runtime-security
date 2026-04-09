"""Scan endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from asr.api.auth import verify_api_key
from asr.api.models import ScanRequest
from asr.api.service import scan_content


router = APIRouter(tags=["scan"])


@router.post("/scan", dependencies=[Depends(verify_api_key)])
def scan_route(payload: ScanRequest, request: Request) -> dict:
    result = scan_content(
        content=payload.content,
        source_type=payload.source_type,
        source_ref=payload.source_ref,
    )
    return {"ok": True, "data": result, "request_id": request.state.request_id}
