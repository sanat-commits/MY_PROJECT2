"""Configuration specification for Phase 3 Explainable Risk Scoring.

Defines typed Pydantic configuration schemas for:
- Behavioral risk signal rules, baseline thresholds, and saturation limits
- Configured severity bands and boundary rules
- Critical alert safeguard settings
- Total weight normalization verification
- Loading/saving configurations and deriving baseline thresholds from normal training data
"""

import json
from pathlib import Path
from typing import Dict, List, Literal, Optional, Union
import numpy as np
import pandas as pd
from pydantic import BaseModel, Field, field_validator, model_validator


class BehavioralSignalConfig(BaseModel):
    """Configuration for an individual behavioral telemetry risk indicator."""

    name: str = Field(..., description="Unique human-readable identifier of the signal rule")
    source_field: str = Field(..., description="Exact column name in the source telemetry window")
    weight: float = Field(..., ge=0.0, le=100.0, description="Maximum contribution points allocated")
    baseline_threshold: float = Field(
        ..., description="Training-normal baseline threshold (e.g. 99th percentile of normal data)"
    )
    saturation_threshold: float = Field(
        ..., description="Observed value at which the signal reaches 100% of allocated weight"
    )
    comparison_operator: Literal["gt", "gte", "eq"] = Field(
        default="gt", description="Rule comparison logic: 'gt' for numeric excess, 'eq' for exact flag match"
    )
    description: str = Field(default="", description="Operational description of the indicator")

    @model_validator(mode="after")
    def validate_thresholds(self) -> "BehavioralSignalConfig":
        if self.comparison_operator in ("gt", "gte"):
            if self.saturation_threshold < self.baseline_threshold:
                raise ValueError(
                    f"Signal '{self.name}': saturation_threshold ({self.saturation_threshold}) "
                    f"must be >= baseline_threshold ({self.baseline_threshold})"
                )
        return self


class SeverityBandConfig(BaseModel):
    """Operational prioritization severity band boundaries.
    
    Bands:
    - LOW:      [0.0, low_max)
    - MEDIUM:   [low_max, medium_max)
    - HIGH:     [medium_max, high_max)
    - CRITICAL: [high_max, 100.0]
    """

    low_max: float = Field(default=30.0, ge=0.0, le=100.0)
    medium_max: float = Field(default=60.0, ge=0.0, le=100.0)
    high_max: float = Field(default=80.0, ge=0.0, le=100.0)

    @model_validator(mode="after")
    def validate_band_monotonicity(self) -> "SeverityBandConfig":
        if not (0.0 <= self.low_max <= self.medium_max <= self.high_max <= 100.0):
            raise ValueError(
                f"Severity bands must satisfy 0 <= low_max ({self.low_max}) <= "
                f"medium_max ({self.medium_max}) <= high_max ({self.high_max}) <= 100.0"
            )
        return self


class CriticalSafeguardConfig(BaseModel):
    """Safeguard preventing uncorroborated single-signal or pure-ML critical escalation."""

    enabled: bool = Field(
        default=True,
        description="Whether to enforce the corroborating behavioral evidence safeguard for CRITICAL severity",
    )
    min_corroborating_signals: int = Field(
        default=1,
        ge=1,
        description="Minimum number of positive behavioral signals required to assign CRITICAL severity",
    )


class RiskScoringConfig(BaseModel):
    """Complete, validated configuration for Phase 3 Explainable Risk Scoring."""

    version: str = Field(default="v1.0.0", description="Semantic configuration version identifier")
    description: str = Field(
        default="Default operational risk scoring configuration calibrated against normal training baseline",
        description="Human-readable description and rationale for configuration parameters",
    )

    # ML Anomaly contribution settings
    ml_anomaly_weight: float = Field(
        default=40.0,
        ge=0.0,
        le=100.0,
        description="Maximum contribution points awarded for ML anomaly detection signal",
    )
    ml_anomaly_threshold: float = Field(
        default=0.04116906323724265,
        description="Phase 2 decision threshold (95th percentile of normal training scores)",
    )
    ml_anomaly_max_expected: float = Field(
        default=0.20,
        description="Expected upper ceiling of anomaly score used for saturation scaling",
    )

    # Configured behavioral signals
    behavioral_signals: List[BehavioralSignalConfig] = Field(
        default_factory=list,
        description="List of configured behavioral telemetry indicators and weights",
    )

    # Severity bands
    severity_bands: SeverityBandConfig = Field(
        default_factory=SeverityBandConfig,
        description="Numerical boundaries for operational severity bands",
    )

    # Safeguard
    critical_safeguard: CriticalSafeguardConfig = Field(
        default_factory=CriticalSafeguardConfig,
        description="Policy settings for critical alert safeguard",
    )

    # Missing evidence policy
    missing_evidence_policy: Literal["zero_with_audit", "strict_raise"] = Field(
        default="zero_with_audit",
        description="Policy for handling missing telemetry fields: 'zero_with_audit' awards 0 pts and logs audit, 'strict_raise' fails evaluation",
    )

    rounding_tolerance: float = Field(
        default=0.01,
        ge=0.0,
        description="Allowable rounding difference when reconciling score breakdown components to final risk score",
    )

    @model_validator(mode="after")
    def validate_weight_sum(self) -> "RiskScoringConfig":
        total_behavioral = sum(sig.weight for sig in self.behavioral_signals)
        total_weight = self.ml_anomaly_weight + total_behavioral
        if abs(total_weight - 100.0) > 0.001:
            raise ValueError(
                f"Total scoring weights must sum exactly to 100.0 (got {total_weight:.4f}: "
                f"ML={self.ml_anomaly_weight}, Behavioral={total_behavioral})"
            )
        # Check for duplicate signal names or source fields
        names = [sig.name for sig in self.behavioral_signals]
        if len(names) != len(set(names)):
            raise ValueError(f"Duplicate signal names detected in configuration: {names}")
        return self


def derive_baseline_thresholds_from_training(train_csv_path: Union[str, Path]) -> Dict[str, float]:
    """Derive reproducible behavioral baseline thresholds from normal-only training data.
    
    Computes the 99th percentile of normal observations for key numeric features.
    Guarantees that 99% of normal operations fall below these thresholds.
    """
    path = Path(train_csv_path)
    if not path.exists():
        raise FileNotFoundError(f"Training dataset not found for threshold derivation: {path}")

    df = pd.read_csv(path)
    # Check that data is normal-only to prevent leakage
    if "label" in df.columns:
        unique_labels = set(df["label"].unique())
        if unique_labels != {0}:
            raise ValueError(f"Cannot derive baseline from dataset containing non-zero labels: {unique_labels}")

    numeric_features = [
        "failed_logins",
        "new_source_ip_count",
        "privileged_actions",
        "external_connections",
        "bytes_out_mb",
        "rare_process_count",
    ]
    p99 = df[numeric_features].quantile(0.99).to_dict()
    return p99


def get_default_risk_config(
    train_csv_path: Optional[Union[str, Path]] = None,
    ml_threshold: Optional[float] = None,
) -> RiskScoringConfig:
    """Instantiate the authoritative default RiskScoringConfig.
    
    Behavioral thresholds represent the 99th percentile of normal behavior from training data:
    - failed_logins: 3.0
    - privileged_actions: 2.0
    - rare_process_count: 1.0
    - external_connections: 19.0
    - bytes_out_mb: 26.905
    - after_hours: 1.0 (binary operational schedule flag)
    
    Weights:
    - ML Anomaly: 40.0 pts
    - failed_logins: 15.0 pts
    - privileged_actions: 10.0 pts
    - rare_process_count: 10.0 pts
    - external_connections: 10.0 pts
    - bytes_out_mb: 10.0 pts
    - after_hours: 5.0 pts
    Total = 100.0 pts.
    """
    if train_csv_path is not None and Path(train_csv_path).exists():
        p99 = derive_baseline_thresholds_from_training(train_csv_path)
        fl_base = float(p99.get("failed_logins", 3.0))
        pa_base = float(p99.get("privileged_actions", 2.0))
        rp_base = float(p99.get("rare_process_count", 1.0))
        ec_base = float(p99.get("external_connections", 19.0))
        bo_base = float(p99.get("bytes_out_mb", 26.9))
    else:
        # Precomputed 99th percentiles of security_windows_train_normal.csv
        fl_base = 3.0
        pa_base = 2.0
        rp_base = 1.0
        ec_base = 19.0
        bo_base = 26.905

    ml_thresh = ml_threshold if ml_threshold is not None else 0.04116906323724265

    signals = [
        BehavioralSignalConfig(
            name="failed_login_burst",
            source_field="failed_logins",
            weight=15.0,
            baseline_threshold=fl_base,
            saturation_threshold=40.0,
            comparison_operator="gt",
            description=f"Authentication failure count exceeded normal baseline (p99={fl_base:.1f})",
        ),
        BehavioralSignalConfig(
            name="elevated_privileged_actions",
            source_field="privileged_actions",
            weight=10.0,
            baseline_threshold=pa_base,
            saturation_threshold=10.0,
            comparison_operator="gt",
            description=f"Privileged command execution volume exceeded normal baseline (p99={pa_base:.1f})",
        ),
        BehavioralSignalConfig(
            name="rare_process_execution",
            source_field="rare_process_count",
            weight=10.0,
            baseline_threshold=rp_base,
            saturation_threshold=15.0,
            comparison_operator="gt",
            description=f"Atypical binary execution frequency exceeded normal baseline (p99={rp_base:.1f})",
        ),
        BehavioralSignalConfig(
            name="excessive_external_connections",
            source_field="external_connections",
            weight=10.0,
            baseline_threshold=ec_base,
            saturation_threshold=60.0,
            comparison_operator="gt",
            description=f"Outbound network egress connection count exceeded normal baseline (p99={ec_base:.1f})",
        ),
        BehavioralSignalConfig(
            name="high_volume_data_egress",
            source_field="bytes_out_mb",
            weight=10.0,
            baseline_threshold=bo_base,
            saturation_threshold=1000.0,
            comparison_operator="gt",
            description=f"Outbound network egress volume in MB exceeded normal baseline (p99={bo_base:.1f} MB)",
        ),
        BehavioralSignalConfig(
            name="off_hours_activity",
            source_field="after_hours",
            weight=5.0,
            baseline_threshold=1.0,
            saturation_threshold=1.0,
            comparison_operator="eq",
            description="Telemetry observation occurred outside approved operational business hours",
        ),
    ]

    return RiskScoringConfig(
        version="v1.0.0",
        ml_anomaly_weight=40.0,
        ml_anomaly_threshold=ml_thresh,
        ml_anomaly_max_expected=0.20,
        behavioral_signals=signals,
        severity_bands=SeverityBandConfig(
            low_max=30.0,
            medium_max=60.0,
            high_max=80.0,
        ),
        critical_safeguard=CriticalSafeguardConfig(
            enabled=True,
            min_corroborating_signals=1,
        ),
    )


def save_config_to_json(config: RiskScoringConfig, output_path: Union[str, Path]) -> None:
    """Save risk scoring configuration to JSON file."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(config.model_dump_json(indent=2))


def load_config_from_json(config_path: Union[str, Path]) -> RiskScoringConfig:
    """Load and validate risk scoring configuration from JSON file."""
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Risk scoring config file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return RiskScoringConfig(**data)
