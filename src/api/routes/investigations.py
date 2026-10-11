"""Historical investigation retrieval routes."""

from typing import Any, Dict, List
from fastapi import APIRouter, Depends, HTTPException, Query, status

from src.api.schemas import InvestigationResponse
from src.api.dependencies import get_investigation_repository
from src.api.repository import InvestigationRepository
from src.agent.schemas import InvestigationResult

router = APIRouter(prefix="/investigations", tags=["Investigations"])


def _format_investigation(result: InvestigationResult) -> InvestigationResponse:
    final_report_dict = (
        result.final_report.model_dump()
        if result.final_report and hasattr(result.final_report, "model_dump")
        else None
    )

    trace_summary = [
        t.model_dump() if hasattr(t, "model_dump") else t
        for t in result.execution_trace
    ]

    a_id = (
        getattr(result, "alert_id", None)
        or (result.final_report.alert_id if result.final_report else "unknown")
    )
    return InvestigationResponse(
        investigation_id=result.investigation_id,
        alert_id=a_id,
        status=result.status.value if hasattr(result.status, "value") else str(result.status),
        final_report=final_report_dict,
        execution_trace_summary=trace_summary,
        tool_call_count=result.tool_call_count,
        llm_call_count=result.llm_call_count,
        iteration_count=result.iteration_count,
        elapsed_time=result.elapsed_time,
        warnings=result.warnings,
        failure_reason=result.failure_reason,
    )


@router.get("/{investigation_id}", response_model=InvestigationResponse)
def get_investigation(
    investigation_id: str,
    repo: InvestigationRepository = Depends(get_investigation_repository),
) -> InvestigationResponse:
    """Retrieve historical investigation run by its unique investigation ID."""
    inv = repo.get(investigation_id)
    if inv is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation run '{investigation_id}' was not found in records.",
        )
    return _format_investigation(inv)


@router.get("", response_model=List[InvestigationResponse])
def list_investigations(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    repo: InvestigationRepository = Depends(get_investigation_repository),
) -> List[InvestigationResponse]:
    """List historical investigations recorded in this environment."""
    items, _ = repo.list(offset=offset, limit=limit)
    return [_format_investigation(item) for item in items]
