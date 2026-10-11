"""Alert retrieval and LangGraph investigation trigger routes."""

import asyncio
from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status

from src.api.schemas import (
    PaginatedAlertsResponse,
    InvestigationRequest,
    InvestigationResponse,
)
from src.api.dependencies import (
    get_alert_repository,
    get_investigation_repository,
    get_investigation_workflow,
    get_investigation_semaphore,
    get_api_config,
)
from src.api.repository import AlertRepository, InvestigationRepository
from src.api.config import ApiConfig
from src.agent.workflow import InvestigationWorkflow
from src.agent.schemas import InvestigationResult

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.get("", response_model=PaginatedAlertsResponse)
def list_alerts(
    limit: int = Query(20, ge=1, le=100, description="Page size limit"),
    offset: int = Query(0, ge=0, description="Item offset index"),
    severity: Optional[str] = Query(None, description="Optional severity filter (e.g. HIGH, MEDIUM)"),
    is_anomaly: Optional[int] = Query(None, ge=0, le=1, description="Optional anomaly binary filter (0 or 1)"),
    repo: AlertRepository = Depends(get_alert_repository),
) -> PaginatedAlertsResponse:
    """Retrieve a paginated collection of security alerts with optional severity filtering."""
    alerts, total = repo.list(
        offset=offset,
        limit=limit,
        severity=severity,
        is_anomaly=is_anomaly,
    )
    items = [
        a.model_dump() if hasattr(a, "model_dump") else a
        for a in alerts
    ]
    return PaginatedAlertsResponse(
        items=items,
        limit=limit,
        offset=offset,
        total=total,
    )


@router.get("/{alert_id}")
def get_alert(
    alert_id: str,
    repo: AlertRepository = Depends(get_alert_repository),
) -> Dict[str, Any]:
    """Retrieve full structured alert details by alert ID."""
    alert = repo.get(alert_id)
    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert '{alert_id}' was not found in the repository.",
        )
    return alert.model_dump() if hasattr(alert, "model_dump") else alert


@router.post("/{alert_id}/investigate", response_model=InvestigationResponse)
async def investigate_alert(
    alert_id: str,
    request_body: Optional[InvestigationRequest] = None,
    repo: AlertRepository = Depends(get_alert_repository),
    inv_repo: InvestigationRepository = Depends(get_investigation_repository),
    workflow: InvestigationWorkflow = Depends(get_investigation_workflow),
    semaphore: asyncio.Semaphore = Depends(get_investigation_semaphore),
) -> InvestigationResponse:
    """Trigger a multi-step LangGraph investigation for a verified security alert."""
    alert = repo.get(alert_id)
    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Cannot investigate: Security alert '{alert_id}' was not found.",
        )

    thread_id = request_body.thread_id if request_body else None

    # Enforce concurrency boundary to prevent local VRAM/GPU saturation
    async with semaphore:
        # Run synchronous LangGraph workflow in thread pool
        result: InvestigationResult = await asyncio.to_thread(
            workflow.run_investigation,
            alert=alert,
            thread_id=thread_id,
        )

    # Persist completed investigation for historical audit
    inv_repo.save(result)

    final_report_dict = (
        result.final_report.model_dump()
        if result.final_report and hasattr(result.final_report, "model_dump")
        else None
    )

    trace_summary = [
        t.model_dump() if hasattr(t, "model_dump") else t
        for t in result.execution_trace
    ]

    return InvestigationResponse(
        investigation_id=result.investigation_id,
        alert_id=alert.alert_id,
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
