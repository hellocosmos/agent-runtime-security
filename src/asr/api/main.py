"""FastAPI entrypoint for the first-party ASR HTTP extension."""

from __future__ import annotations

from uuid import uuid4

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from asr import __version__
from asr.api.config import get_settings
from asr.api.routes import decide, health, redact, scan


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        description=(
            "Optional HTTP wrapper for Agent Runtime Security.\n\n"
            "Endpoints:\n"
            "- POST /v1/scan\n"
            "- POST /v1/decide\n"
            "- POST /v1/redact\n"
            "- GET /health\n"
        ),
        root_path=settings.root_path,
    )

    def _request_id(request: Request) -> str:
        return getattr(request.state, "request_id", f"req_{uuid4().hex[:12]}")

    def _error_response(request: Request, *, status_code: int, code: str, message: str) -> JSONResponse:
        return JSONResponse(
            status_code=status_code,
            content={
                "ok": False,
                "error": {"code": code, "message": message},
                "request_id": _request_id(request),
            },
        )

    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next):
        request.state.request_id = f"req_{uuid4().hex[:12]}"
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        return response

    @app.exception_handler(ValueError)
    async def value_error_handler(request: Request, exc: ValueError) -> JSONResponse:
        return _error_response(
            request,
            status_code=400,
            code="invalid_request",
            message=str(exc),
        )

    @app.exception_handler(RuntimeError)
    async def runtime_error_handler(request: Request, exc: RuntimeError) -> JSONResponse:
        return _error_response(
            request,
            status_code=503,
            code="service_unavailable",
            message=str(exc),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "ok": False,
                "error": {
                    "code": "invalid_request",
                    "message": "Request validation failed",
                    "details": exc.errors(),
                },
                "request_id": _request_id(request),
            },
        )

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        detail = exc.detail
        if isinstance(detail, dict):
            code = str(detail.get("code", "http_error"))
            message = str(detail.get("message", "Request failed"))
        else:
            code = "http_error"
            message = str(detail)
        return _error_response(request, status_code=exc.status_code, code=code, message=message)

    app.include_router(health.router)
    app.include_router(scan.router, prefix=settings.api_prefix)
    app.include_router(decide.router, prefix=settings.api_prefix)
    app.include_router(redact.router, prefix=settings.api_prefix)
    return app


app = create_app()


def run() -> None:
    """Local CLI entrypoint."""
    uvicorn.run("asr.api.main:app", host="0.0.0.0", port=8000, reload=False)
