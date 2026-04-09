"""Health endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Request

from asr import __version__


router = APIRouter(tags=["health"])


@router.get("/health")
def health_check(request: Request) -> dict:
    return {
        "ok": True,
        "data": {
            "status": "healthy",
            "service": "agent-runtime-security-api",
            "version": __version__,
        },
        "request_id": request.state.request_id,
    }
