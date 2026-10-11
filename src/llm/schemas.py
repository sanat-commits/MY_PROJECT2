"""Data schemas and types for the local LLM investigation engine."""

from enum import Enum
from typing import Any
from pydantic import BaseModel, Field

from src.risk_scoring.schema import EvidenceItem, SeverityLevel


class FindingType(str, Enum):
    """Categorization of investigation finding adhering to cybersecurity truthfulness."""
    ANOMALOUS_ACTIVITY = "ANOMALOUS_ACTIVITY"
    SUSPICIOUS_ACTIVITY = "SUSPICIOUS_ACTIVITY"
    POSSIBLE_ATTACK = "POSSIBLE_ATTACK"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class InvestigationStatus(str, Enum):
    """Execution status codes for investigation operations."""
    SUCCESS = "SUCCESS"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    MODEL_NOT_FOUND = "MODEL_NOT_FOUND"
    REQUEST_TIMEOUT = "REQUEST_TIMEOUT"
    INVALID_INPUT = "INVALID_INPUT"
    INVALID_MODEL_OUTPUT = "INVALID_MODEL_OUTPUT"
    RETRIEVAL_UNAVAILABLE = "RETRIEVAL_UNAVAILABLE"
    INVESTIGATION_ERROR = "INVESTIGATION_ERROR"


class ReportCitation(BaseModel):
    """Attributable citation referencing a verified chunk returned from Phase 5 RAG."""
    chunk_id: str
    source_id: str
    source_title: str
    source_uri_or_path: str
    document_title: str | None = None
    relevant_text: str | None = None
    content: str | None = None


class ObservedEvidenceRef(BaseModel):
    """Verified telemetry evidence reference grounding model claims."""
    field_name: str
    observed_value: Any
    description: str


class InvestigationInput(BaseModel):
    """Validated input packet assembled by the application for the local LLM."""
    investigation_id: str
    alert_id: str
    window_id: str
    anomaly_score: float
    is_anomaly: bool
    risk_score: float
    severity: SeverityLevel
    evidence_items: list[EvidenceItem] = Field(default_factory=list)
    score_breakdown: dict[str, Any] = Field(default_factory=dict)
    mitre_status: str | None = None
    mitre_candidate_techniques: list[dict[str, Any]] = Field(default_factory=list)
    rag_chunks: list[dict[str, Any]] = Field(default_factory=list)
    rag_status: str = "no_results"
    created_at: str | None = None


class InvestigationReport(BaseModel):
    """Structured, verified investigation report produced by local Qwen 3 8B."""
    investigation_id: str
    alert_id: str
    summary: str
    supplied_severity: SeverityLevel
    supplied_risk_score: float
    finding: FindingType
    observed_evidence: list[ObservedEvidenceRef] = Field(default_factory=list)
    interpretation: str
    possible_attack_techniques: list[str] = Field(default_factory=list)
    uncertainty: str
    recommended_next_steps: list[str] = Field(default_factory=list)
    citations: list[ReportCitation] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    model_metadata: dict[str, Any] = Field(default_factory=dict)


class InvestigationResult(BaseModel):
    """High-level container returned by InvestigationEngine adhering to agent tool expectations."""
    status: InvestigationStatus
    report: InvestigationReport | None = None
    error_message: str | None = None
    diagnostics: dict[str, Any] = Field(default_factory=dict)
