"""FastAPI application factory, middleware, and router registration."""

import logging
import time
import uuid
from typing import Optional
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError, HTTPException

from src.api.config import ApiConfig
from src.api.dependencies import get_api_config
from src.api.error_handlers import (
    http_exception_handler,
    validation_exception_handler,
    output_validation_exception_handler,
    provider_unavailable_exception_handler,
    generic_exception_handler,
)
from src.api.routes import (
    health_router,
    status_router,
    alerts_router,
    investigations_router,
)
from src.llm.output_validation import OutputValidationError
from src.llm.provider import ProviderUnavailableError

logger = logging.getLogger(__name__)


def create_app(config: Optional[ApiConfig] = None) -> FastAPI:
    """Factory creating and configuring the FastAPI backend application."""
    cfg = config or get_api_config()

    app = FastAPI(
        title="AI Security Log Anomaly & Investigation API",
        description="Local-first cybersecurity detection, risk scoring, MITRE ATT&CK mapping, RAG, and LangGraph Qwen investigation API.",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # 1. CORS Middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
    )

    # 2. Correlation ID & Request Tracing Middleware
    @app.middleware("http")
    async def request_tracing_middleware(request: Request, call_next):
        corr_id = request.headers.get("X-Correlation-ID")
        if not corr_id:
            corr_id = f"req_{uuid.uuid4().hex[:12]}"
        request.state.correlation_id = corr_id

        start_time = time.time()
        logger.info(
            "Incoming request [correlation_id=%s]: %s %s",
            corr_id,
            request.method,
            request.url.path,
        )

        try:
            response = await call_next(request)
            duration = time.time() - start_time
            response.headers["X-Correlation-ID"] = corr_id
            logger.info(
                "Completed request [correlation_id=%s]: %s %s -> %d in %.3fs",
                corr_id,
                request.method,
                request.url.path,
                response.status_code,
                duration,
            )
            return response
        except Exception as exc:
            duration = time.time() - start_time
            logger.error(
                "Unhandled error in request [correlation_id=%s]: %s %s after %.3fs: %s",
                corr_id,
                request.method,
                request.url.path,
                duration,
                exc,
            )
            raise exc

    # 3. Register Custom Exception Handlers
    app.add_exception_handler(HTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(OutputValidationError, output_validation_exception_handler)
    app.add_exception_handler(ProviderUnavailableError, provider_unavailable_exception_handler)
    app.add_exception_handler(Exception, generic_exception_handler)

    # 4. Mount Application Routers
    app.include_router(health_router)
    app.include_router(status_router)
    app.include_router(alerts_router)
    app.include_router(investigations_router)

    return app


# Default singleton instance for ASGI servers
app = create_app()
