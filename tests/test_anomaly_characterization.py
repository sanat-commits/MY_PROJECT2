"""Comprehensive unit and integration test suite for Explainable Anomaly Characterization.

Tests all required aspects of Phase 3 / Bug Fix Anomaly Characterization:
- Each supported category with valid fixture data
- Multiple matching rules (MULTIPLE_BEHAVIORAL_ANOMALIES)
- No matching rule (UNCLASSIFIED_ANOMALY)
- Missing required features (INSUFFICIENT_EVIDENCE)
- Invalid feature types / non-numeric data (SERVICE_ERROR)
- Non-anomalous telemetry (NOT_ANOMALOUS)
- Strict leakage prevention: training label / anomaly_type metadata ignored
- Deterministic characterization stability
- Immutability of original risk score and severity
- API serialization includes characterization
- Backward compatibility: older alerts lacking characterization load without error
- Evidence explanation matches actual rule evaluation
- Score contribution and explanation consistency
"""

import json
import pytest
import numpy as np
import pandas as pd

from src.risk_scoring.characterization import (
    AnomalyCategory,
    ClassificationStatus,
    AnomalyCharacterization,
    AnomalyCharacterizationService,
    build_default_rules,
    get_characterization_service,
)
from src.risk_scoring.config import get_default_risk_config
from src.risk_scoring.engine import RiskEngine
from src.risk_scoring.schema import (
    SecurityAlert,
    SeverityLevel,
    EvidenceItem,
    ScoreBreakdown,
    ScoreComponentBreakdown,
)


@pytest.fixture
def char_service() -> AnomalyCharacterizationService:
    config = get_default_risk_config()
    return AnomalyCharacterizationService(config=config)


@pytest.fixture
def risk_engine() -> RiskEngine:
    return RiskEngine(get_default_risk_config())


@pytest.fixture
def base_window() -> dict:
    """Nominal observation window within all normal baselines."""
    return {
        "window_id": "WIN-TEST-001",
        "user_role": "analyst",
        "host_type": "workstation",
        "hour": 14,
        "day_of_week": 2,
        "is_weekend": 0,
        "failed_logins": 0.0,
        "successful_logins": 10.0,
        "login_attempts": 10.0,
        "unique_source_ips": 1.0,
        "new_source_ip_count": 0.0,
        "privileged_actions": 0.0,
        "file_access_count": 20.0,
        "process_count": 15.0,
        "network_connections": 5.0,
        "external_connections": 2.0,
        "bytes_out_mb": 1.5,
        "distinct_destinations": 2.0,
        "rare_process_count": 0.0,
        "after_hours": 0.0,
    }


@pytest.fixture
def anom_prediction() -> dict:
    return {
        "window_id": "WIN-TEST-001",
        "anomaly_score": 0.15,
        "is_anomaly": 1,
        "raw_score": -0.15,
    }


# ============================================================================
# 1. Tests for Each Supported Category with Valid Fixture Data
# ============================================================================

def test_category_off_hours_activity(char_service, anom_prediction, base_window):
    """Verify after_hours flag triggers OFF_HOURS_ACTIVITY."""
    window = dict(base_window, after_hours=1.0)
    result = char_service.characterize(anom_prediction, window)

    assert result.classification_status == ClassificationStatus.CHARACTERIZED
    assert result.primary_category == AnomalyCategory.OFF_HOURS_ACTIVITY
    assert len(result.additional_categories) == 0
    assert "RULE_CHAR_OFF_HOURS" in result.rule_ids
    assert len(result.supporting_signals) == 1
    sig = result.supporting_signals[0]
    assert sig.signal_name == "off_hours_activity"
    assert sig.source_field == "after_hours"
    assert sig.observed_value == 1.0
    assert sig.comparison == "=="
    assert "business hours" in result.explanation


def test_category_repeated_failed_authentication(char_service, anom_prediction, base_window):
    """Verify failed_logins above baseline triggers REPEATED_FAILED_AUTHENTICATION."""
    window = dict(base_window, failed_logins=12.0)
    result = char_service.characterize(anom_prediction, window)

    assert result.classification_status == ClassificationStatus.CHARACTERIZED
    assert result.primary_category == AnomalyCategory.REPEATED_FAILED_AUTHENTICATION
    assert len(result.additional_categories) == 0
    assert "RULE_CHAR_FAILED_AUTH" in result.rule_ids
    assert len(result.supporting_signals) == 1
    sig = result.supporting_signals[0]
    assert sig.signal_name == "failed_login_burst"
    assert sig.source_field == "failed_logins"
    assert sig.observed_value == 12.0
    assert sig.threshold_or_baseline == 3.0
    assert "Repeated failed logins" in result.summary


def test_category_unusual_process_activity(char_service, anom_prediction, base_window):
    """Verify rare_process_count above baseline triggers UNUSUAL_PROCESS_ACTIVITY."""
    window = dict(base_window, rare_process_count=4.0)
    result = char_service.characterize(anom_prediction, window)

    assert result.classification_status == ClassificationStatus.CHARACTERIZED
    assert result.primary_category == AnomalyCategory.UNUSUAL_PROCESS_ACTIVITY
    assert len(result.additional_categories) == 0
    assert "RULE_CHAR_PROCESS_ACTIVITY" in result.rule_ids
    assert len(result.supporting_signals) == 1
    sig = result.supporting_signals[0]
    assert sig.signal_name == "rare_process_execution"
    assert sig.source_field == "rare_process_count"
    assert sig.observed_value == 4.0
    assert sig.threshold_or_baseline == 1.0


def test_category_unusual_network_activity(char_service, anom_prediction, base_window):
    """Verify external_connections above baseline triggers UNUSUAL_NETWORK_ACTIVITY."""
    window = dict(base_window, external_connections=35.0)
    result = char_service.characterize(anom_prediction, window)

    assert result.classification_status == ClassificationStatus.CHARACTERIZED
    assert result.primary_category == AnomalyCategory.UNUSUAL_NETWORK_ACTIVITY
    assert len(result.additional_categories) == 0
    assert "RULE_CHAR_NETWORK_ACTIVITY" in result.rule_ids
    assert len(result.supporting_signals) == 1
    sig = result.supporting_signals[0]
    assert sig.signal_name == "excessive_external_connections"
    assert sig.source_field == "external_connections"
    assert sig.observed_value == 35.0
    assert sig.threshold_or_baseline == 19.0


def test_category_unusual_outbound_data_activity(char_service, anom_prediction, base_window):
    """Verify bytes_out_mb above baseline triggers UNUSUAL_OUTBOUND_DATA_ACTIVITY."""
    window = dict(base_window, bytes_out_mb=120.5)
    result = char_service.characterize(anom_prediction, window)

    assert result.classification_status == ClassificationStatus.CHARACTERIZED
    assert result.primary_category == AnomalyCategory.UNUSUAL_OUTBOUND_DATA_ACTIVITY
    assert len(result.additional_categories) == 0
    assert "RULE_CHAR_OUTBOUND_DATA" in result.rule_ids
    assert len(result.supporting_signals) == 1
    sig = result.supporting_signals[0]
    assert sig.signal_name == "excessive_outbound_data"
    assert sig.source_field == "bytes_out_mb"
    assert sig.observed_value == 120.5


# ============================================================================
# 2. Multiple Matching Rules Test
# ============================================================================

def test_multiple_matching_rules(char_service, anom_prediction, base_window):
    """Verify multiple concurrent breaches return MULTIPLE_BEHAVIORAL_ANOMALIES."""
    window = dict(
        base_window,
        after_hours=1.0,
        failed_logins=15.0,
        bytes_out_mb=85.0,
    )
    result = char_service.characterize(anom_prediction, window)

    assert result.classification_status == ClassificationStatus.CHARACTERIZED
    assert result.primary_category == AnomalyCategory.MULTIPLE_BEHAVIORAL_ANOMALIES
    assert len(result.additional_categories) == 3
    assert AnomalyCategory.OFF_HOURS_ACTIVITY in result.additional_categories
    assert AnomalyCategory.REPEATED_FAILED_AUTHENTICATION in result.additional_categories
    assert AnomalyCategory.UNUSUAL_OUTBOUND_DATA_ACTIVITY in result.additional_categories
    assert len(result.rule_ids) == 3
    assert len(result.supporting_signals) == 3
    assert "Multiple behavioral deviations observed" in result.summary


# ============================================================================
# 3. No Matching Rule Test (Unclassified Anomaly)
# ============================================================================

def test_unclassified_anomaly_when_no_rules_match(char_service, anom_prediction, base_window):
    """Verify anomaly detected by ML with all features within normal baselines returns UNCLASSIFIED_ANOMALY."""
    # base_window has all values <= normal baselines
    result = char_service.characterize(anom_prediction, base_window)

    assert result.classification_status == ClassificationStatus.UNCLASSIFIED
    assert result.primary_category == AnomalyCategory.UNCLASSIFIED_ANOMALY
    assert len(result.additional_categories) == 0
    assert len(result.rule_ids) == 0
    assert len(result.supporting_signals) == 0
    assert "Statistical anomaly detected without distinct individual behavioral threshold breaches" in result.summary
    assert "univariate 99th percentile baseline thresholds" in result.explanation
    assert "manual analyst review is required" in result.uncertainty.lower()


# ============================================================================
# 4. Nominal Normal Telemetry (is_anomaly == 0)
# ============================================================================

def test_nominal_normal_telemetry(char_service, base_window):
    """Verify non-anomalous prediction returns NOT_ANOMALOUS."""
    normal_pred = {
        "window_id": "WIN-TEST-001",
        "anomaly_score": 0.01,
        "is_anomaly": 0,
        "raw_score": 0.05,
    }
    result = char_service.characterize(normal_pred, base_window)

    assert result.classification_status == ClassificationStatus.NOT_ANOMALOUS
    assert result.primary_category == AnomalyCategory.UNCLASSIFIED_ANOMALY
    assert "Nominal activity" in result.summary


# ============================================================================
# 5. Missing Required Features / Insufficient Evidence
# ============================================================================

def test_missing_features_returns_insufficient_evidence(char_service, anom_prediction):
    """Verify window lacking monitored behavioral features returns INSUFFICIENT_EVIDENCE."""
    sparse_window = {
        "window_id": "WIN-TEST-001",
        "user_role": "admin",
        # missing failed_logins, after_hours, rare_process_count, external_connections, bytes_out_mb
    }
    result = char_service.characterize(anom_prediction, sparse_window)

    assert result.classification_status == ClassificationStatus.INSUFFICIENT_EVIDENCE
    assert result.primary_category == AnomalyCategory.UNCLASSIFIED_ANOMALY
    assert "Insufficient telemetry evidence" in result.summary
    assert len(result.supporting_signals) == 0


# ============================================================================
# 6. Invalid Feature Types / Malformed Inputs
# ============================================================================

def test_invalid_feature_type_handled_gracefully(char_service, anom_prediction, base_window):
    """Verify non-numeric feature value results in SERVICE_ERROR rather than uncaught crash."""
    bad_window = dict(base_window, failed_logins="INVALID_STRING")
    result = char_service.characterize(anom_prediction, bad_window)

    assert result.classification_status == ClassificationStatus.SERVICE_ERROR
    assert result.primary_category == AnomalyCategory.UNCLASSIFIED_ANOMALY
    assert "non-numeric" in result.explanation.lower() or "service error" in result.summary.lower()


def test_invalid_prediction_type_handled_gracefully(char_service, base_window):
    """Verify non-dict prediction results in SERVICE_ERROR."""
    result = char_service.characterize("NOT_A_DICT", base_window)

    assert result.classification_status == ClassificationStatus.SERVICE_ERROR
    assert result.primary_category == AnomalyCategory.UNCLASSIFIED_ANOMALY


# ============================================================================
# 7. Strict Leakage Prevention
# ============================================================================

def test_leakage_prevention_ignores_ground_truth_labels(char_service, anom_prediction, base_window):
    """Verify that presence of synthetic ground-truth metadata does NOT influence classification."""
    # Telemetry indicates off-hours activity, but ground-truth labels claim 'brute_force'
    window_with_labels = dict(
        base_window,
        after_hours=1.0,
        failed_logins=0.0,
        anomaly_type="brute_force",  # ground truth label
        label=1,
    )
    result = char_service.characterize(anom_prediction, window_with_labels)

    # Must classify based SOLELY on verified features (after_hours=1 -> OFF_HOURS_ACTIVITY),
    # NOT the synthetic 'brute_force' label!
    assert result.primary_category == AnomalyCategory.OFF_HOURS_ACTIVITY
    assert result.primary_category != AnomalyCategory.REPEATED_FAILED_AUTHENTICATION

    # Modifying or stripping ground truth labels must produce IDENTICAL output
    window_without_labels = {k: v for k, v in window_with_labels.items() if k not in ("anomaly_type", "label")}
    result_cleaned = char_service.characterize(anom_prediction, window_without_labels)
    assert result.model_dump() == result_cleaned.model_dump()


# ============================================================================
# 8. Deterministic Classification
# ============================================================================

def test_deterministic_classification_stability(char_service, anom_prediction, base_window):
    """Verify consecutive characterization calls on identical inputs yield identical outputs."""
    window = dict(base_window, failed_logins=20.0, after_hours=1.0)
    res1 = char_service.characterize(anom_prediction, window)
    res2 = char_service.characterize(anom_prediction, window)

    assert res1.model_dump() == res2.model_dump()


# ============================================================================
# 9. Original Risk Score and Severity Immutability
# ============================================================================

def test_risk_score_and_severity_remain_unchanged(risk_engine, anom_prediction, base_window):
    """Verify that adding characterization does NOT mutate the risk score, severity, or ML score."""
    window = dict(base_window, failed_logins=15.0, after_hours=1.0)
    alert = risk_engine.score_alert(anom_prediction, window)

    # Check alert structure
    assert isinstance(alert, SecurityAlert)
    assert alert.anomaly_characterization is not None
    assert alert.anomaly_characterization.classification_status == ClassificationStatus.CHARACTERIZED

    # The risk score calculation:
    # ml_anomaly: 0.15 > 0.041169 -> supra-threshold contribution ~ 32.88
    # failed_logins: (15 - 3)/(40 - 3) * 15 ~ 4.86
    # after_hours: 5.0
    # Expected total is strictly determined by RiskScoreCalculator, not mutated by characterization
    assert alert.risk_score > 0.0
    assert alert.severity in (SeverityLevel.LOW, SeverityLevel.MEDIUM, SeverityLevel.HIGH, SeverityLevel.CRITICAL)

    # Verification: calculate expected score directly from calculator
    expected_risk, _ = risk_engine.calculator.calculate_risk_score(
        ml_component=alert.score_breakdown.ml_anomaly,
        behavioral_components=alert.score_breakdown.behavioral_components,
    )
    assert alert.risk_score == expected_risk


# ============================================================================
# 10. API Serialization Includes Characterization
# ============================================================================

def test_api_serialization_includes_characterization(risk_engine, anom_prediction, base_window):
    """Verify full alert serialization via model_dump contains anomaly_characterization and all fields."""
    window = dict(base_window, bytes_out_mb=150.0)
    alert = risk_engine.score_alert(anom_prediction, window)

    serialized = alert.model_dump()
    assert "anomaly_characterization" in serialized
    char_dict = serialized["anomaly_characterization"]
    assert char_dict is not None
    assert char_dict["classification_status"] == "CHARACTERIZED"
    assert char_dict["primary_category"] == "UNUSUAL_OUTBOUND_DATA_ACTIVITY"
    assert "summary" in char_dict
    assert "explanation" in char_dict
    assert "uncertainty" in char_dict
    assert "supporting_signals" in char_dict
    assert len(char_dict["supporting_signals"]) == 1
    assert char_dict["supporting_signals"][0]["source_field"] == "bytes_out_mb"


# ============================================================================
# 11. Backward Compatibility for Legacy Alerts
# ============================================================================

def test_legacy_alerts_without_characterization_remain_readable(risk_engine, anom_prediction, base_window):
    """Verify alerts persisted without anomaly_characterization load cleanly without error or fabrication."""
    alert = risk_engine.score_alert(anom_prediction, base_window)
    alert_dict = alert.model_dump()

    # Simulate legacy alert stored in older version
    alert_dict.pop("anomaly_characterization", None)
    assert "anomaly_characterization" not in alert_dict

    # Re-instantiate SecurityAlert
    legacy_alert = SecurityAlert(**alert_dict)
    assert legacy_alert.anomaly_characterization is None
    assert legacy_alert.alert_id == alert.alert_id
    assert legacy_alert.risk_score == alert.risk_score


# ============================================================================
# 12. Score Contribution and Explanation Consistency Bug Fix Verification
# ============================================================================

def test_score_contribution_and_explanation_consistency(risk_engine, anom_prediction, base_window):
    """Verify that EvidenceItem.contribution and score_contribution are non-zero when explanation claims points.
    
    Fixes the root cause where off_hours_activity rendered +0.0 while explanation claimed 5.00 points.
    """
    window = dict(base_window, after_hours=1.0)
    alert = risk_engine.score_alert(anom_prediction, window)

    # Locate off_hours_activity evidence item
    off_hours_ev = next((ev for ev in alert.evidence if ev.signal_name == "off_hours_activity"), None)
    assert off_hours_ev is not None

    # Both contribution and score_contribution must be exactly 5.0
    assert off_hours_ev.contribution == 5.0
    assert off_hours_ev.score_contribution == 5.0
    assert "contributed 5.00 points" in off_hours_ev.explanation

    # Score breakdown must include off_hours_activity with 5.0 points
    breakdown_comp = next((c for c in alert.score_breakdown.components if c.component == "off_hours_activity"), None)
    assert breakdown_comp is not None
    assert breakdown_comp.contribution == 5.0
    assert breakdown_comp.status == "contributed"


def test_score_breakdown_unified_components_present(risk_engine, anom_prediction, base_window):
    """Verify score_breakdown.components is automatically populated with both ML and behavioral signals."""
    window = dict(base_window, failed_logins=20.0, after_hours=1.0)
    alert = risk_engine.score_alert(anom_prediction, window)

    bd = alert.score_breakdown
    assert len(bd.components) >= 2
    # First component is ML anomaly
    assert bd.components[0].component == bd.ml_anomaly.component
    # Subsequent components match behavioral components
    behavioral_names = [c.component for c in bd.behavioral_components]
    components_names = [c.component for c in bd.components[1:]]
    assert behavioral_names == components_names
