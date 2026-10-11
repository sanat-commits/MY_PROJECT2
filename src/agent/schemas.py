"""Typed schemas for Phase 7 LangGraph Investigation Agent."""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from src.llm.schemas import InvestigationReport, FindingType
from src.risk_scoring.schema import SecurityAlert, SeverityLevel


class AgentStatus(str, Enum):
    """Investigation execution outcomes matching project contracts."""
    SUCCESS = "SUCCESS"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    LIMIT_REACHED = "LIMIT_REACHED"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    TOOL_ERROR = "TOOL_ERROR"
    INVALID_INPUT = "INVALID_INPUT"
    INVALID_MODEL_OUTPUT = "INVALID_MODEL_OUTPUT"
    TIMEOUT = "TIMEOUT"
    INVESTIGATION_ERROR = "INVESTIGATION_ERROR"


class ApprovedAction(str, Enum):
    """Permitted action types in the agent's action selection registry."""
    SEARCH_LOGS = "search_logs"
    GET_RELATED_EVENTS = "get_related_events"
    SEARCH_KNOWLEDGE_BASE = "search_knowledge_base"
    LOOKUP_ATTACK_TECHNIQUE = "lookup_attack_technique"
    FINALIZE = "finalize"


class ActionDecision(BaseModel):
    """Validated next-step action proposal chosen by the agent."""
    action: ApprovedAction = Field(..., description="Approved action to dispatch")
    reason: str = Field(..., description="Auditable justification for why this action is requested")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Validated parameters for the action")
    expected_information: Optional[str] = Field(None, description="What information the agent expects to resolve")


class ToolExecutionRecord(BaseModel):
    """Audit record capturing an individual tool call, arguments, and outcome."""
    tool_name: str
    parameters: Dict[str, Any]
    status: str  # 'SUCCESS', 'NO_RESULTS', 'SOURCE_UNAVAILABLE', 'INVALID_INPUT', 'ERROR'
    data: Any = None
    error: Optional[str] = None
    started_at: float
    duration_seconds: float
    is_repeated: bool = False


class TraceStep(BaseModel):
    """Observability trace event for an individual LangGraph node execution."""
    node_name: str
    timestamp: float
    duration_seconds: float
    status: str
    action_requested: Optional[str] = None
    action_approved: Optional[str] = None
    summary: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)


class InvestigationState(BaseModel):
    """Typed state dictionary managed by LangGraph throughout the investigation lifecycle."""
    investigation_id: str
    alert_id: str
    original_alert: SecurityAlert
    observed_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    attack_context: Dict[str, Any] = Field(default_factory=dict)
    retrieval_context: List[Dict[str, Any]] = Field(default_factory=list)
    tool_results: List[ToolExecutionRecord] = Field(default_factory=list)
    tool_errors: List[str] = Field(default_factory=list)
    action_history: List[str] = Field(default_factory=list)
    decision_history: List[ActionDecision] = Field(default_factory=list)
    iteration_count: int = 0
    tool_call_count: int = 0
    llm_call_count: int = 0
    started_at: float = 0.0
    deadline: float = 0.0
    current_status: AgentStatus = AgentStatus.INVALID_INPUT
    final_report: Optional[InvestigationReport] = None
    warnings: List[str] = Field(default_factory=list)
    failure_reason: Optional[str] = None
    execution_trace: List[TraceStep] = Field(default_factory=list)


class InvestigationResult(BaseModel):
    """Public return contract conforming to Section 14 agent interface."""
    investigation_id: str
    status: AgentStatus
    alert_id: Optional[str] = None
    final_report: Optional[InvestigationReport] = None
    execution_trace: List[TraceStep] = Field(default_factory=list)
    tool_results_summary: List[Dict[str, Any]] = Field(default_factory=list)
    llm_call_count: int
    tool_call_count: int
    iteration_count: int
    elapsed_time: float
    warnings: List[str] = Field(default_factory=list)
    failure_reason: Optional[str] = None
