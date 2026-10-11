"""Authoritative alert schema and types for Phase 3 Explainable Risk Scoring.

Defines typed Pydantic models for:
- Severity levels (LOW, MEDIUM, HIGH, CRITICAL)
- Verifiable evidence items
- Component-level score breakdowns
- Final structured security alert contracts
"""

from enum import Enum
import hashlib
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field, field_validator, model_validator

from src.risk_scoring.characterization import AnomalyCharacterization


class SeverityLevel(str, Enum):
    """Configured operational severity prioritization bands."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EvidenceItem(BaseModel):
    """An observed telemetry signal that contributed to alert risk scoring.
    
    Contains exact source field references, observed values, and rule explanations.
    Never contains fabricated or unobserved attributes.
    """

    signal_name: str = Field(..., description="Identifier of the risk signal rule")
    source_field: str = Field(..., description="Actual telemetry column name in source window")
    observed_value: Union[int, float, str, bool] = Field(
        ..., description="Actual observed value in the input telemetry"
    )
    comparison_or_rule: str = Field(
        ..., description="Documented rule or baseline comparison used for evaluation"
    )
    contribution: float = Field(
        ..., ge=0.0, le=100.0, description="Score contribution points attributed to this observation"
    )
    explanation: str = Field(
        ..., description="Plain-text explanation of the observation and its contribution"
    )

    # Backward compatibility and frontend alignment fields
    score_contribution: Optional[float] = Field(
        None, ge=0.0, le=100.0, description="Alias matching frontend expectation for score contribution"
    )
    threshold_or_baseline: Optional[Union[int, float, str]] = Field(
        None, description="Alias matching frontend expectation for baseline threshold or rule"
    )

    @model_validator(mode="after")
    def populate_evidence_aliases(self) -> "EvidenceItem":
        if self.score_contribution is None:
            self.score_contribution = self.contribution
        if self.threshold_or_baseline is None:
            self.threshold_or_baseline = self.comparison_or_rule
        return self


class ScoreComponentBreakdown(BaseModel):
    """Detailed audit entry for a single score contributor (ML or behavioral)."""

    component: str = Field(..., description="Name of the scoring component")
    source_field: Optional[str] = Field(
        None, description="Source telemetry field name, or None for composite/model signals"
    )
    observed_value: Optional[Union[int, float, str, bool]] = Field(
        None, description="Observed input value, or None if unavailable/composite"
    )
    configured_weight: float = Field(
        ..., ge=0.0, le=100.0, description="Maximum potential score contribution"
    )
    rule: str = Field(..., description="Evaluation rule or formula applied")
    contribution: float = Field(
        ..., ge=0.0, le=100.0, description="Actual score contribution awarded"
    )
    calculation_method: str = Field(
        ..., description="Mathematical calculation method (e.g., linear_interpolation, step, threshold_excess)"
    )
    status: str = Field(
        ..., description="Evaluation status: 'contributed', 'baseline_normal', 'missing_evidence', or 'error'"
    )

    # Frontend alignment aliases
    component_name: Optional[str] = Field(
        None, description="Display name for frontend component rendering"
    )
    formula_reference: Optional[str] = Field(
        None, description="Formula or rule description for frontend audit"
    )

    @model_validator(mode="after")
    def populate_component_aliases(self) -> "ScoreComponentBreakdown":
        if self.component_name is None:
            self.component_name = self.component
        if self.formula_reference is None:
            self.formula_reference = self.rule
        return self


class ScoreBreakdown(BaseModel):
    """Complete audit breakdown reconciling individual contributions to total risk score."""

    ml_anomaly: ScoreComponentBreakdown = Field(
        ..., description="Contribution breakdown of the Phase 2 ML anomaly signal"
    )
    behavioral_components: List[ScoreComponentBreakdown] = Field(
        default_factory=list, description="Contribution breakdowns of behavioral indicators"
    )
    total_ml_contribution: float = Field(
        ..., ge=0.0, le=100.0, description="Total points awarded from ML anomaly signal"
    )
    total_behavioral_contribution: float = Field(
        ..., ge=0.0, le=100.0, description="Total points awarded from behavioral signals"
    )
    calculated_risk_score: float = Field(
        ..., ge=0.0, le=100.0, description="Final sum of all contributions"
    )
    reconciled: bool = Field(
        ..., description="True if sum of contributions matches calculated_risk_score within rounding tolerance"
    )
    rounding_difference: float = Field(
        ..., description="Absolute difference between sum of contributions and reported risk score"
    )

    # Unified list for frontend rendering and serialization
    components: List[ScoreComponentBreakdown] = Field(
        default_factory=list, description="Unified ordered list of all component breakdowns"
    )
    calculation_explanation: Optional[str] = Field(
        None, description="Human-readable formula explanation reconciling components"
    )
    config_version: Optional[str] = Field(
        None, description="Scoring configuration version identifier"
    )

    @model_validator(mode="after")
    def populate_breakdown_components(self) -> "ScoreBreakdown":
        if not self.components:
            self.components = [self.ml_anomaly] + list(self.behavioral_components)
        if self.calculation_explanation is None:
            self.calculation_explanation = (
                f"Composite risk score: ML anomaly contributed {self.total_ml_contribution:.2f} pts and "
                f"behavioral indicators contributed {self.total_behavioral_contribution:.2f} pts "
                f"(total = {self.calculated_risk_score:.2f} pts)."
            )
        return self


class SecurityAlert(BaseModel):
    """Typed, validated structured alert contract for Phase 3.
    
    Encapsulates Phase 2 ML predictions, verifiable evidence, transparent score breakdown,
    assigned operational severity, and explainable anomaly characterization.
    """

    alert_id: str = Field(
        ..., description="Deterministic, unique identifier for the alert"
    )
    window_id: str = Field(
        ..., description="Identifier of the source behavioral telemetry window"
    )
    anomaly_score: float = Field(
        ..., description="Phase 2 derived anomaly score (-decision_function)"
    )
    is_anomaly: int = Field(
        ..., ge=0, le=1, description="Phase 2 binary anomaly flag (1=anomalous, 0=normal)"
    )
    risk_score: float = Field(
        ..., ge=0.0, le=100.0, description="Bounded priority score (0.0 to 100.0), not a probability"
    )
    severity: SeverityLevel = Field(
        ..., description="Assigned operational prioritization severity"
    )
    evidence: List[EvidenceItem] = Field(
        default_factory=list,
        description="Observations that directly contributed positive points to risk scoring",
    )
    score_breakdown: ScoreBreakdown = Field(
        ..., description="Full audit trail of all score components and reconciliation"
    )
    scoring_config_version: str = Field(
        ..., description="Version of the risk scoring configuration applied"
    )
    created_at: str = Field(
        ..., description="ISO 8601 UTC timestamp of alert generation"
    )

    # Verifiable metadata from actual inputs
    raw_model_score: Optional[float] = Field(
        None, description="Raw Phase 2 decision_function score (higher is more normal)"
    )
    anomaly_threshold: Optional[float] = Field(
        None, description="Phase 2 decision threshold used for is_anomaly"
    )
    critical_safeguard_applied: bool = Field(
        default=False,
        description="True if severity was capped/downgraded due to critical safeguard",
    )
    safeguard_note: Optional[str] = Field(
        None, description="Explanation if critical safeguard was triggered"
    )

    # Phase 3 / Bug Fix Explainable Anomaly Characterization
    anomaly_characterization: Optional[AnomalyCharacterization] = Field(
        default=None,
        description="Structured behavioral characterization explaining the nature of detected anomalous activity",
    )

    @field_validator("risk_score")
    @classmethod
    def validate_risk_score_bounds(cls, v: float) -> float:
        if not (0.0 <= v <= 100.0):
            raise ValueError(f"Risk score must be between 0.0 and 100.0, got {v}")
        return round(v, 2)


def generate_deterministic_alert_id(window_id: str, config_version: str) -> str:
    """Generate a stable, deterministic alert ID from window ID and config version."""
    content = f"{window_id}:{config_version}".encode("utf-8")
    digest = hashlib.sha256(content).hexdigest()[:12]
    return f"alt_{window_id}_{digest}"
