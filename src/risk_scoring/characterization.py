"""Authoritative Explainable Anomaly Characterization Service.

Provides verifiable, evidence-based behavioral characterization of detected anomalies
without mutating ML anomaly scores, risk scores, or operational severities.
Guarantees strict leakage prevention: never uses synthetic labels (label, anomaly_type)
to determine characterization.
"""

from enum import Enum
import logging
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
import numpy as np
import pandas as pd
from pydantic import BaseModel, Field

from src.risk_scoring.config import RiskScoringConfig, get_default_risk_config

logger = logging.getLogger(__name__)


class ClassificationStatus(str, Enum):
    """Operational status of behavioral characterization evaluation."""

    CHARACTERIZED = "CHARACTERIZED"
    UNCLASSIFIED = "UNCLASSIFIED"
    NOT_ANOMALOUS = "NOT_ANOMALOUS"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    SERVICE_ERROR = "SERVICE_ERROR"


class AnomalyCategory(str, Enum):
    """Supported behavioral anomaly categories based on verified telemetry features."""

    OFF_HOURS_ACTIVITY = "OFF_HOURS_ACTIVITY"
    REPEATED_FAILED_AUTHENTICATION = "REPEATED_FAILED_AUTHENTICATION"
    UNUSUAL_PROCESS_ACTIVITY = "UNUSUAL_PROCESS_ACTIVITY"
    UNUSUAL_NETWORK_ACTIVITY = "UNUSUAL_NETWORK_ACTIVITY"
    UNUSUAL_OUTBOUND_DATA_ACTIVITY = "UNUSUAL_OUTBOUND_DATA_ACTIVITY"
    MULTIPLE_BEHAVIORAL_ANOMALIES = "MULTIPLE_BEHAVIORAL_ANOMALIES"
    UNCLASSIFIED_ANOMALY = "UNCLASSIFIED_ANOMALY"


class SupportingSignal(BaseModel):
    """An observed telemetry signal supporting a behavioral characterization."""

    signal_name: str = Field(..., description="Name of the supporting behavioral signal")
    source_field: str = Field(..., description="Telemetry source field")
    observed_value: Union[int, float, str, bool] = Field(..., description="Observed numeric or boolean value")
    threshold_or_baseline: Union[int, float, str] = Field(
        ..., description="Baseline threshold or rule condition evaluated against"
    )
    rule_id: str = Field(..., description="ID of the characterization rule that matched this signal")
    comparison: str = Field(..., description="Comparison operator used in rule (e.g. '>', '==')")
    explanation: str = Field(..., description="Factual description of the observed signal breach")
    contribution_points: Optional[float] = Field(
        default=None, description="Risk score points contributed, if known"
    )


class AnomalyCharacterization(BaseModel):
    """Structured, explainable behavioral characterization contract."""

    classification_status: ClassificationStatus = Field(
        ..., description="Operational status of the characterization"
    )
    primary_category: AnomalyCategory = Field(
        ..., description="Primary behavioral anomaly category"
    )
    additional_categories: List[AnomalyCategory] = Field(
        default_factory=list, description="Additional matching categories if multiple anomalies observed"
    )
    summary: str = Field(
        ..., description="Concise human-readable summary of the characterization"
    )
    supporting_signals: List[SupportingSignal] = Field(
        default_factory=list, description="Verifiable supporting signals and thresholds"
    )
    explanation: str = Field(
        ..., description="Detailed factual explanation of the observed behavior"
    )
    uncertainty: str = Field(
        ..., description="Explicit documentation of limitations, uncertainty, and non-proof notice"
    )
    rule_ids: List[str] = Field(
        default_factory=list, description="Identifiers of characterization rules matched"
    )
    characterization_version: str = Field(
        default="v1.0.0", description="Semantic version of characterization rules"
    )


class CharacterizationRule:
    """Deterministic rule evaluating telemetry for a specific behavioral anomaly category."""

    def __init__(
        self,
        rule_id: str,
        category: AnomalyCategory,
        name: str,
        description: str,
        source_fields: List[str],
        eval_fn: Callable[[Dict[str, Any], RiskScoringConfig], Optional[Tuple[SupportingSignal, str]]],
    ):
        self.rule_id = rule_id
        self.category = category
        self.name = name
        self.description = description
        self.source_fields = source_fields
        self.eval_fn = eval_fn

    def evaluate(
        self, window: Dict[str, Any], config: RiskScoringConfig
    ) -> Optional[Tuple[SupportingSignal, str]]:
        return self.eval_fn(window, config)


def _get_signal_baseline(config: RiskScoringConfig, source_field: str, fallback: float) -> float:
    """Retrieve calibrated baseline threshold from RiskScoringConfig for a source field."""
    for sig in config.behavioral_signals:
        if sig.source_field == source_field:
            return float(sig.baseline_threshold)
    return fallback


def _eval_off_hours(
    window: Dict[str, Any], config: RiskScoringConfig
) -> Optional[Tuple[SupportingSignal, str]]:
    """Evaluate off-hours activity flag."""
    if "after_hours" not in window:
        return None
    val = window["after_hours"]
    if val is None or pd.isna(val):
        return None
    try:
        num = float(val)
    except (ValueError, TypeError):
        return None

    if num == 1.0:
        sig = SupportingSignal(
            signal_name="off_hours_activity",
            source_field="after_hours",
            observed_value=1.0,
            threshold_or_baseline=1.0,
            rule_id="RULE_CHAR_OFF_HOURS",
            comparison="==",
            explanation="Activity was observed outside normal operational business hours (after_hours=1).",
            contribution_points=5.0,
        )
        return sig, "Activity outside standard operational business hours"
    return None


def _eval_failed_auth(
    window: Dict[str, Any], config: RiskScoringConfig
) -> Optional[Tuple[SupportingSignal, str]]:
    """Evaluate repeated failed authentication attempts."""
    if "failed_logins" not in window:
        return None
    val = window["failed_logins"]
    if val is None or pd.isna(val):
        return None
    try:
        num = float(val)
    except (ValueError, TypeError):
        return None

    baseline = _get_signal_baseline(config, "failed_logins", 3.0)
    if num > baseline:
        sig = SupportingSignal(
            signal_name="failed_login_burst",
            source_field="failed_logins",
            observed_value=num,
            threshold_or_baseline=baseline,
            rule_id="RULE_CHAR_FAILED_AUTH",
            comparison=">",
            explanation=f"Authentication failure count of {num:.0f} exceeded the normal baseline threshold of {baseline:.1f}.",
        )
        return sig, f"Repeated failed logins ({num:.0f} failures > baseline {baseline:.1f})"
    return None


def _eval_process_activity(
    window: Dict[str, Any], config: RiskScoringConfig
) -> Optional[Tuple[SupportingSignal, str]]:
    """Evaluate unusual or rare process activity."""
    if "rare_process_count" not in window:
        return None
    val = window["rare_process_count"]
    if val is None or pd.isna(val):
        return None
    try:
        num = float(val)
    except (ValueError, TypeError):
        return None

    baseline = _get_signal_baseline(config, "rare_process_count", 1.0)
    if num > baseline:
        sig = SupportingSignal(
            signal_name="rare_process_execution",
            source_field="rare_process_count",
            observed_value=num,
            threshold_or_baseline=baseline,
            rule_id="RULE_CHAR_PROCESS_ACTIVITY",
            comparison=">",
            explanation=f"Rare process execution frequency of {num:.0f} exceeded the normal baseline threshold of {baseline:.1f}.",
        )
        return sig, f"Unusual binary/process execution count ({num:.0f} rare processes > baseline {baseline:.1f})"
    return None


def _eval_network_activity(
    window: Dict[str, Any], config: RiskScoringConfig
) -> Optional[Tuple[SupportingSignal, str]]:
    """Evaluate unusual external network connections."""
    if "external_connections" not in window:
        return None
    val = window["external_connections"]
    if val is None or pd.isna(val):
        return None
    try:
        num = float(val)
    except (ValueError, TypeError):
        return None

    baseline = _get_signal_baseline(config, "external_connections", 19.0)
    if num > baseline:
        sig = SupportingSignal(
            signal_name="excessive_external_connections",
            source_field="external_connections",
            observed_value=num,
            threshold_or_baseline=baseline,
            rule_id="RULE_CHAR_NETWORK_ACTIVITY",
            comparison=">",
            explanation=f"External connection count of {num:.0f} exceeded the normal baseline threshold of {baseline:.1f}.",
        )
        return sig, f"Elevated external network connections ({num:.0f} connections > baseline {baseline:.1f})"
    return None


def _eval_outbound_data(
    window: Dict[str, Any], config: RiskScoringConfig
) -> Optional[Tuple[SupportingSignal, str]]:
    """Evaluate unusual outbound data volume."""
    if "bytes_out_mb" not in window:
        return None
    val = window["bytes_out_mb"]
    if val is None or pd.isna(val):
        return None
    try:
        num = float(val)
    except (ValueError, TypeError):
        return None

    baseline = _get_signal_baseline(config, "bytes_out_mb", 26.905)
    if num > baseline:
        sig = SupportingSignal(
            signal_name="excessive_outbound_data",
            source_field="bytes_out_mb",
            observed_value=num,
            threshold_or_baseline=baseline,
            rule_id="RULE_CHAR_OUTBOUND_DATA",
            comparison=">",
            explanation=f"Outbound data volume of {num:.2f} MB exceeded the normal baseline threshold of {baseline:.2f} MB.",
        )
        return sig, f"Unusual outbound data transfer volume ({num:.2f} MB > baseline {baseline:.2f} MB)"
    return None


def build_default_rules() -> List[CharacterizationRule]:
    """Construct canonical versioned characterization rules."""
    return [
        CharacterizationRule(
            rule_id="RULE_CHAR_OFF_HOURS",
            category=AnomalyCategory.OFF_HOURS_ACTIVITY,
            name="Off-Hours Operational Activity",
            description="Identifies activity occurring outside scheduled organizational business hours.",
            source_fields=["after_hours"],
            eval_fn=_eval_off_hours,
        ),
        CharacterizationRule(
            rule_id="RULE_CHAR_FAILED_AUTH",
            category=AnomalyCategory.REPEATED_FAILED_AUTHENTICATION,
            name="Repeated Failed Authentication",
            description="Identifies elevated login failure volume exceeding normal 99th percentile baseline.",
            source_fields=["failed_logins"],
            eval_fn=_eval_failed_auth,
        ),
        CharacterizationRule(
            rule_id="RULE_CHAR_PROCESS_ACTIVITY",
            category=AnomalyCategory.UNUSUAL_PROCESS_ACTIVITY,
            name="Unusual Process Execution",
            description="Identifies execution frequency of rare or atypical process binaries above normal baseline.",
            source_fields=["rare_process_count"],
            eval_fn=_eval_process_activity,
        ),
        CharacterizationRule(
            rule_id="RULE_CHAR_NETWORK_ACTIVITY",
            category=AnomalyCategory.UNUSUAL_NETWORK_ACTIVITY,
            name="Unusual External Network Activity",
            description="Identifies external network connection count breaching normal baseline threshold.",
            source_fields=["external_connections"],
            eval_fn=_eval_network_activity,
        ),
        CharacterizationRule(
            rule_id="RULE_CHAR_OUTBOUND_DATA",
            category=AnomalyCategory.UNUSUAL_OUTBOUND_DATA_ACTIVITY,
            name="Unusual Outbound Data Activity",
            description="Identifies anomalous volume of egress data transfer exceeding normal baseline.",
            source_fields=["bytes_out_mb"],
            eval_fn=_eval_outbound_data,
        ),
    ]


class AnomalyCharacterizationService:
    """Reusable service for explainable behavioral anomaly characterization."""

    VERSION = "v1.0.0"

    # Monitored telemetry fields required for comprehensive evaluation
    KEY_TELEMETRY_FIELDS = [
        "failed_logins",
        "after_hours",
        "rare_process_count",
        "external_connections",
        "bytes_out_mb",
    ]

    def __init__(
        self,
        config: Optional[RiskScoringConfig] = None,
        rules: Optional[List[CharacterizationRule]] = None,
    ):
        self.config = config or get_default_risk_config()
        self.rules = rules or build_default_rules()

    def characterize(
        self,
        prediction: Union[Dict[str, Any], pd.Series],
        source_window: Union[Dict[str, Any], pd.Series],
        config: Optional[RiskScoringConfig] = None,
    ) -> AnomalyCharacterization:
        """Evaluate an anomaly prediction and source window against evidence-based characterization rules.
        
        Guarantees:
        - Strict leakage prevention: does NOT use 'label' or 'anomaly_type' from input.
        - Returns UNCLASSIFIED_ANOMALY when an anomaly is detected without specific rule breaches.
        - Returns NOT_ANOMALOUS when is_anomaly == 0.
        - Returns INSUFFICIENT_EVIDENCE when required telemetry is unavailable.
        - Returns SERVICE_ERROR on unexpected processing exceptions.
        """
        active_config = config or self.config

        try:
            # 1. Parse prediction fields
            if not isinstance(prediction, (dict, pd.Series)):
                return AnomalyCharacterization(
                    classification_status=ClassificationStatus.SERVICE_ERROR,
                    primary_category=AnomalyCategory.UNCLASSIFIED_ANOMALY,
                    summary="Service error: Invalid prediction object type.",
                    explanation=f"Expected prediction as dict or pd.Series, got {type(prediction)}.",
                    uncertainty="Characterization could not be performed due to invalid input types.",
                    characterization_version=self.VERSION,
                )

            pred_dict = dict(prediction)
            is_anomaly = int(pred_dict.get("is_anomaly", 0))

            # 2. Check if detection indicated nominal normal
            if is_anomaly == 0:
                return AnomalyCharacterization(
                    classification_status=ClassificationStatus.NOT_ANOMALOUS,
                    primary_category=AnomalyCategory.UNCLASSIFIED_ANOMALY,
                    summary="Nominal activity: Telemetry conforms to learned normal baseline distribution.",
                    explanation="Isolation Forest decision function indicates nominal baseline behavior (is_anomaly=0). No behavioral characterization is required.",
                    uncertainty="Telemetry does not show statistical deviation from normal operational baselines.",
                    characterization_version=self.VERSION,
                )

            # 3. Validate source window structure
            if not isinstance(source_window, (dict, pd.Series)):
                return AnomalyCharacterization(
                    classification_status=ClassificationStatus.SERVICE_ERROR,
                    primary_category=AnomalyCategory.UNCLASSIFIED_ANOMALY,
                    summary="Service error: Invalid source window object type.",
                    explanation=f"Expected source_window as dict or pd.Series, got {type(source_window)}.",
                    uncertainty="Characterization could not be performed due to invalid input types.",
                    characterization_version=self.VERSION,
                )

            win_dict = dict(source_window)

            # Strict leakage prevention: purge any synthetic labels or ground truth metadata
            sanitized_window = {
                k: v for k, v in win_dict.items()
                if k not in ("label", "anomaly_type", "ground_truth", "synthetic_type")
            }

            # 4. Check for presence of key telemetry fields (insufficient evidence check)
            present_key_fields = [
                f for f in self.KEY_TELEMETRY_FIELDS
                if f in sanitized_window and sanitized_window[f] is not None and not pd.isna(sanitized_window[f])
            ]
            if len(present_key_fields) == 0:
                return AnomalyCharacterization(
                    classification_status=ClassificationStatus.INSUFFICIENT_EVIDENCE,
                    primary_category=AnomalyCategory.UNCLASSIFIED_ANOMALY,
                    summary="Insufficient telemetry evidence: Monitored behavioral features are missing from observation window.",
                    explanation=f"None of the required behavioral telemetry features ({', '.join(self.KEY_TELEMETRY_FIELDS)}) were available in the observation window.",
                    uncertainty="Cannot distinguish behavioral pattern due to absence of observable telemetry signals.",
                    characterization_version=self.VERSION,
                )

            # Check numeric validity of present key fields
            for f in present_key_fields:
                try:
                    num_val = float(sanitized_window[f])
                    if not np.isfinite(num_val):
                        return AnomalyCharacterization(
                            classification_status=ClassificationStatus.SERVICE_ERROR,
                            primary_category=AnomalyCategory.UNCLASSIFIED_ANOMALY,
                            summary=f"Invalid telemetry value: Field '{f}' contains non-finite value.",
                            explanation=f"Feature '{f}' contains non-finite value {sanitized_window[f]}.",
                            uncertainty="Characterization halted due to invalid non-finite data.",
                            characterization_version=self.VERSION,
                        )
                except (ValueError, TypeError):
                    return AnomalyCharacterization(
                        classification_status=ClassificationStatus.SERVICE_ERROR,
                        primary_category=AnomalyCategory.UNCLASSIFIED_ANOMALY,
                        summary=f"Invalid telemetry value: Field '{f}' contains non-numeric data.",
                        explanation=f"Feature '{f}' contains non-numeric value '{sanitized_window[f]}'.",
                        uncertainty="Characterization halted due to non-numeric telemetry.",
                        characterization_version=self.VERSION,
                    )

            # 5. Evaluate all characterization rules
            matched_rules: List[CharacterizationRule] = []
            supporting_signals: List[SupportingSignal] = []
            matched_summaries: List[str] = []

            for rule in self.rules:
                res = rule.evaluate(sanitized_window, active_config)
                if res is not None:
                    sig, summary_str = res
                    matched_rules.append(rule)
                    supporting_signals.append(sig)
                    matched_summaries.append(summary_str)

            # 6. Synthesize classification outcome
            standard_uncertainty = (
                "Observed behavioral deviations represent statistical telemetry anomalies and do not constitute "
                "conclusive proof of compromise or malicious intent. Corroboration with host logs and analyst triage is required."
            )

            # Case: No matching behavioral rules breached
            if len(matched_rules) == 0:
                return AnomalyCharacterization(
                    classification_status=ClassificationStatus.UNCLASSIFIED,
                    primary_category=AnomalyCategory.UNCLASSIFIED_ANOMALY,
                    additional_categories=[],
                    summary="Statistical anomaly detected without distinct individual behavioral threshold breaches.",
                    supporting_signals=[],
                    explanation=(
                        "Isolation Forest identified a statistical outlier based on multidimensional feature distribution, "
                        "but none of the individual monitored behavioral features (failed logins, egress volume, rare processes, "
                        "external connections, or after-hours schedule) exceeded their univariate 99th percentile baseline thresholds."
                    ),
                    uncertainty=(
                        "The specific operational pattern cannot be characterized reliably from individual univariate indicators alone; "
                        "the deviation is multidimensional. Manual analyst review is required."
                    ),
                    rule_ids=[],
                    characterization_version=self.VERSION,
                )

            # Case: Exactly one matching behavioral category
            if len(matched_rules) == 1:
                single_rule = matched_rules[0]
                return AnomalyCharacterization(
                    classification_status=ClassificationStatus.CHARACTERIZED,
                    primary_category=single_rule.category,
                    additional_categories=[],
                    summary=matched_summaries[0],
                    supporting_signals=supporting_signals,
                    explanation=(
                        f"Observation window exhibited {single_rule.name.lower()}: "
                        f"{supporting_signals[0].explanation}"
                    ),
                    uncertainty=standard_uncertainty,
                    rule_ids=[single_rule.rule_id],
                    characterization_version=self.VERSION,
                )

            # Case: Multiple matching behavioral categories
            distinct_categories = list(dict.fromkeys(r.category for r in matched_rules))
            return AnomalyCharacterization(
                classification_status=ClassificationStatus.CHARACTERIZED,
                primary_category=AnomalyCategory.MULTIPLE_BEHAVIORAL_ANOMALIES,
                additional_categories=distinct_categories,
                summary=f"Multiple behavioral deviations observed: {'; '.join(matched_summaries)}.",
                supporting_signals=supporting_signals,
                explanation=(
                    f"Observation window exhibited multiple concurrent behavioral deviations across "
                    f"{len(matched_rules)} indicators: "
                    + "; ".join(s.explanation for s in supporting_signals)
                ),
                uncertainty=standard_uncertainty,
                rule_ids=[r.rule_id for r in matched_rules],
                characterization_version=self.VERSION,
            )

        except Exception as exc:
            logger.error("Unexpected error during anomaly characterization: %s", exc, exc_info=True)
            return AnomalyCharacterization(
                classification_status=ClassificationStatus.SERVICE_ERROR,
                primary_category=AnomalyCategory.UNCLASSIFIED_ANOMALY,
                summary="Service error occurred during anomaly characterization.",
                explanation=f"Error evaluating characterization: {str(exc)}",
                uncertainty="Classification could not be performed due to service error.",
                characterization_version=self.VERSION,
            )


_GLOBAL_SERVICE: Optional[AnomalyCharacterizationService] = None


def get_characterization_service() -> AnomalyCharacterizationService:
    """Retrieve singleton AnomalyCharacterizationService instance."""
    global _GLOBAL_SERVICE
    if _GLOBAL_SERVICE is None:
        _GLOBAL_SERVICE = AnomalyCharacterizationService()
    return _GLOBAL_SERVICE
