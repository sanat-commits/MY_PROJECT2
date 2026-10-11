"""Centralized error handling and privacy preservation for the FastAPI application."""

import logging
from typing import Union
from fastapi import Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError, HTTPException
from pydantic import ValidationError

from src.api.schemas import ErrorDetail, ErrorResponse
from src.llm.output_validation import OutputValidationError
from src.llm.provider import LlmError, ProviderUnavailableError, ModelNotFoundError

logger = logging.getLogger(__name__)


def _get_correlation_id(request: Request) -> str:
    return getattr(request.state, "correlation_id", "unknown")


async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Handle standard FastAPI/Starlette HTTP exceptions."""
    corr_id = _get_correlation_id(request)
    code = "HTTP_ERROR"
    if exc.status_code == 404:
        code = "NOT_FOUND"
    elif exc.status_code == 400:
        code = "BAD_REQUEST"
    elif exc.status_code == 429:
        code = "RATE_LIMITED"
    elif exc.status_code == 503:
        code = "SERVICE_UNAVAILABLE"

    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            error=ErrorDetail(
                code=code,
                message=str(exc.detail),
                correlation_id=corr_id,
            )
        ).model_dump(),
    )


async def validation_exception_handler(request: Request, exc: Union[RequestValidationError, ValidationError]) -> JSONResponse:
    """Handle Pydantic request validation failures."""
    corr_id = _get_correlation_id(request)
    raw_errors = exc.errors() if hasattr(exc, "errors") else str(exc)

    def _sanitize(obj):
        if isinstance(obj, bytes):
            return obj.decode("utf-8", errors="replace")
        elif isinstance(obj, dict):
            return {k: _sanitize(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [_sanitize(v) for v in obj]
        return obj

    sanitized_errors = _sanitize(raw_errors)

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=ErrorResponse(
            error=ErrorDetail(
                code="VALIDATION_ERROR",
                message="Request body or query parameter validation failed.",
                correlation_id=corr_id,
                details=sanitized_errors,
            )
        ).model_dump(),
    )


async def output_validation_exception_handler(request: Request, exc: OutputValidationError) -> JSONResponse:
    """Handle LLM output validation failures."""
    corr_id = _get_correlation_id(request)
    logger.error("Output validation error [correlation_id=%s]: %s", corr_id, exc)
    return JSONResponse(
        status_code=status.HTTP_502_BAD_GATEWAY,
        content=ErrorResponse(
            error=ErrorDetail(
                code="INVALID_MODEL_OUTPUT",
                message="Model generated response that failed schema or citation validation.",
                correlation_id=corr_id,
            )
        ).model_dump(),
    )


async def provider_unavailable_exception_handler(request: Request, exc: ProviderUnavailableError) -> JSONResponse:
    """Handle local LLM provider connectivity errors."""
    corr_id = _get_correlation_id(request)
    logger.error("LLM Provider unavailable [correlation_id=%s]: %s", corr_id, exc)
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content=ErrorResponse(
            error=ErrorDetail(
                code="PROVIDER_UNAVAILABLE",
                message="Local LLM inference provider (Ollama) is unavailable or unresponsive.",
                correlation_id=corr_id,
            )
        ).model_dump(),
    )


async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all error handler sanitizing internal stack traces."""
    corr_id = _get_correlation_id(request)
    logger.exception("Unhandled server exception [correlation_id=%s]: %s", corr_id, exc)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=ErrorResponse(
            error=ErrorDetail(
                code="INTERNAL_SERVER_ERROR",
                message="An unexpected internal error occurred. Diagnostic reference logged.",
                correlation_id=corr_id,
            )
        ).model_dump(),
    )
