"""Pydantic schemas for the backend API contracts."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from src.agent.schemas import AgentStatus


class HealthResponse(BaseModel):
    """Liveness probe response model."""
    status: str = "ok"


class DependencyStatus(BaseModel):
    """Detailed health check for an individual upstream dependency."""
    status: str
    message: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class ReadinessResponse(BaseModel):
    """Readiness probe response detailing component operational statuses."""
    status: str  # "ready" or "degraded" or "not_ready"
    dependencies: Dict[str, DependencyStatus]


class ModelStatusResponse(BaseModel):
    """Status information regarding the local LLM runtime."""
    provider: str
    configured_model: str
    detected_model: Optional[str] = None
    availability: str  # "available", "unavailable", "model_not_found"
    last_check: str
    error_code: Optional[str] = None


class PaginatedAlertsResponse(BaseModel):
    """Paginated collection of security alerts."""
    items: List[Dict[str, Any]]
    limit: int
    offset: int
    total: int


class InvestigationRequest(BaseModel):
    """Optional parameters supplied by an analyst for triggering an investigation."""
    correlation_id: Optional[str] = Field(
        default=None,
        max_length=64,
        description="External correlation / tracing identifier",
    )
    thread_id: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Optional checkpoint resume thread identifier",
    )


class InvestigationResponse(BaseModel):
    """Structured response container for an investigation result."""
    investigation_id: str
    alert_id: str
    status: str
    final_report: Optional[Dict[str, Any]] = None
    execution_trace_summary: List[Dict[str, Any]] = Field(default_factory=list)
    tool_call_count: int = 0
    llm_call_count: int = 0
    iteration_count: int = 0
    elapsed_time: float = 0.0
    warnings: List[str] = Field(default_factory=list)
    failure_reason: Optional[str] = None


class ErrorDetail(BaseModel):
    """Standardized API error detail container."""
    code: str
    message: str
    correlation_id: Optional[str] = None
    details: Optional[Any] = None


class ErrorResponse(BaseModel):
    """Standardized top-level API error response."""
    error: ErrorDetail
