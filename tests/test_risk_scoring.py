"""Phase 3 Explainable Risk Scoring Tests.

Tests:
- Alert schema completeness, validation, and field preservation (Section 10.A)
- Transparent risk calculation, bounded output [0, 100], determinism, and reconciliation (Section 10.B)
- Severity band classification, boundary values, and critical safeguard (Section 10.C)
- Evidence extraction fidelity, factual explanations, and absence of unsupported claims (Section 10.D)
- Negative failure modes and input validation (Section 10.E)
- End-to-end integration with real Phase 2 model inference (Section 10.F)
"""

from pathlib import Path
import json
import pytest
import numpy as np
import pandas as pd
from pydantic import ValidationError

from src.risk_scoring.config import (
    BehavioralSignalConfig,
    SeverityBandConfig,
    CriticalSafeguardConfig,
    RiskScoringConfig,
    get_default_risk_config,
    derive_baseline_thresholds_from_training,
    save_config_to_json,
    load_config_from_json,
)
from src.risk_scoring.schema import (
    SecurityAlert,
    SeverityLevel,
    EvidenceItem,
    ScoreComponentBreakdown,
    ScoreBreakdown,
    generate_deterministic_alert_id,
)
from src.risk_scoring.evidence import EvidenceExtractor
from src.risk_scoring.calculator import RiskScoreCalculator
from src.risk_scoring.severity import SeverityClassifier
from src.risk_scoring.engine import (
    RiskEngine,
    score_alert,
    score_alerts,
)
from src.ml.inference import AnomalyDetector

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
TRAIN_FILE = DATA_DIR / "security_windows_train_normal.csv"
EVAL_FILE = DATA_DIR / "security_windows_eval_labeled.csv"
ARTIFACT_DIR = ROOT / "artifacts" / "ml"


@pytest.fixture
def default_config() -> RiskScoringConfig:
    return get_default_risk_config(train_csv_path=TRAIN_FILE)


@pytest.fixture
def sample_window() -> dict:
    return {
        "window_id": "win_test_001",
        "user_role": "analyst",
        "host_type": "workstation",
        "hour": 14,
        "day_of_week": 2,
        "is_weekend": 0,
        "failed_logins": 45,
        "successful_logins": 5,
        "login_attempts": 50,
        "unique_source_ips": 2,
        "new_source_ip_count": 1,
        "privileged_actions": 6,
        "file_access_count": 10,
        "process_count": 25,
        "network_connections": 20,
        "external_connections": 35,
        "bytes_out_mb": 500.0,
        "distinct_destinations": 15,
        "rare_process_count": 8,
        "after_hours": 1,
        "anomaly_type": "test_burst",
        "label": 1,
    }


@pytest.fixture
def sample_prediction() -> dict:
    return {
        "window_id": "win_test_001",
        "raw_score": -0.12,
        "anomaly_score": 0.12,
        "is_anomaly": 1,
    }


# =====================================================================
# 1. Alert Schema Tests (Section 10.A)
# =====================================================================

def test_alert_schema_all_required_fields(default_config, sample_prediction, sample_window):
    """Generated alert must contain all required fields from project contract."""
    engine = RiskEngine(default_config)
    alert = engine.score_alert(sample_prediction, sample_window)

    required_fields = [
        "alert_id",
        "window_id",
        "anomaly_score",
        "is_anomaly",
        "risk_score",
        "severity",
        "evidence",
        "score_breakdown",
        "scoring_config_version",
        "created_at",
    ]
    dumped = alert.model_dump()
    for f in required_fields:
        assert f in dumped, f"Missing required field {f}"

    assert alert.window_id == "win_test_001"
    assert alert.scoring_config_version == default_config.version
    assert alert.anomaly_score == pytest.approx(0.12)
    assert alert.is_anomaly == 1


def test_alert_schema_rejects_out_of_bounds_risk_score():
    """SecurityAlert must reject risk scores outside [0, 100]."""
    with pytest.raises(ValidationError):
        SecurityAlert(
            alert_id="alt_test_1",
            window_id="win_1",
            anomaly_score=0.1,
            is_anomaly=1,
            risk_score=-5.0,  # Invalid: negative
            severity=SeverityLevel.LOW,
            evidence=[],
            score_breakdown=ScoreBreakdown(
                ml_anomaly=ScoreComponentBreakdown(
                    component="ml",
                    configured_weight=40.0,
                    rule="rule",
                    contribution=0.0,
                    calculation_method="method",
                    status="baseline_normal",
                ),
                total_ml_contribution=0.0,
                total_behavioral_contribution=0.0,
                calculated_risk_score=0.0,
                reconciled=True,
                rounding_difference=0.0,
            ),
            scoring_config_version="v1.0.0",
            created_at="2026-10-09T00:00:00Z",
        )

    with pytest.raises(ValidationError):
        SecurityAlert(
            alert_id="alt_test_2",
            window_id="win_2",
            anomaly_score=0.1,
            is_anomaly=1,
            risk_score=105.0,  # Invalid: > 100
            severity=SeverityLevel.CRITICAL,
            evidence=[],
            score_breakdown=ScoreBreakdown(
                ml_anomaly=ScoreComponentBreakdown(
                    component="ml",
                    configured_weight=40.0,
                    rule="rule",
                    contribution=0.0,
                    calculation_method="method",
                    status="baseline_normal",
                ),
                total_ml_contribution=0.0,
                total_behavioral_contribution=0.0,
                calculated_risk_score=0.0,
                reconciled=True,
                rounding_difference=0.0,
            ),
            scoring_config_version="v1.0.0",
            created_at="2026-10-09T00:00:00Z",
        )


def test_alert_id_is_deterministic(sample_prediction, sample_window, default_config):
    """The same input and config must generate identical alert IDs."""
    id1 = generate_deterministic_alert_id("win_001", "v1.0.0")
    id2 = generate_deterministic_alert_id("win_001", "v1.0.0")
    id3 = generate_deterministic_alert_id("win_001", "v2.0.0")
    id4 = generate_deterministic_alert_id("win_002", "v1.0.0")

    assert id1 == id2
    assert id1 != id3
    assert id1 != id4


# =====================================================================
# 2. Risk Calculation Tests (Section 10.B)
# =====================================================================

def test_risk_score_bounds_and_reconciliation(default_config, sample_prediction, sample_window):
    """Risk scores must stay within 0..100 and breakdown must reconcile within tolerance."""
    engine = RiskEngine(default_config)
    alert = engine.score_alert(sample_prediction, sample_window)

    assert 0.0 <= alert.risk_score <= 100.0
    bd = alert.score_breakdown
    assert bd.reconciled is True
    assert bd.rounding_difference <= default_config.rounding_tolerance

    # Direct summation check
    reconstructed_sum = bd.total_ml_contribution + bd.total_behavioral_contribution
    assert abs(reconstructed_sum - alert.risk_score) <= default_config.rounding_tolerance


def test_risk_score_determinism(default_config, sample_prediction, sample_window):
    """Scoring the same input repeatedly must produce identical scores and breakdowns."""
    engine = RiskEngine(default_config)
    a1 = engine.score_alert(sample_prediction, sample_window, created_at="2026-10-09T00:00:00Z")
    a2 = engine.score_alert(sample_prediction, sample_window, created_at="2026-10-09T00:00:00Z")

    assert a1.alert_id == a2.alert_id
    assert a1.risk_score == a2.risk_score
    assert a1.severity == a2.severity
    assert len(a1.evidence) == len(a2.evidence)
    assert a1.model_dump() == a2.model_dump()


def test_changing_applicable_signal_changes_score(default_config, sample_prediction, sample_window):
    """Increasing an observed risk feature must increase the risk score as expected."""
    engine = RiskEngine(default_config)

    win_low = dict(sample_window)
    win_low["failed_logins"] = 1  # Below baseline (3.0) -> 0 pts

    win_high = dict(sample_window)
    win_high["failed_logins"] = 40  # Saturation ceiling -> full 15.0 pts

    alert_low = engine.score_alert(sample_prediction, win_low)
    alert_high = engine.score_alert(sample_prediction, win_high)

    diff = alert_high.risk_score - alert_low.risk_score
    assert diff == pytest.approx(15.0, abs=0.1)


def test_changing_scoring_weight_changes_output(sample_prediction, sample_window):
    """Modifying configuration weights must change component contribution proportionally."""
    cfg1 = get_default_risk_config(train_csv_path=TRAIN_FILE)
    # Rebalance weights: ML from 40 to 30, failed_logins from 15 to 25
    signals = []
    for s in cfg1.behavioral_signals:
        s_dict = s.model_dump()
        if s.name == "failed_login_burst":
            s_dict["weight"] = 25.0
        signals.append(BehavioralSignalConfig(**s_dict))

    cfg2 = RiskScoringConfig(
        version="v1.1.0",
        ml_anomaly_weight=30.0,
        ml_anomaly_threshold=cfg1.ml_anomaly_threshold,
        ml_anomaly_max_expected=cfg1.ml_anomaly_max_expected,
        behavioral_signals=signals,
        severity_bands=cfg1.severity_bands,
        critical_safeguard=cfg1.critical_safeguard,
    )

    engine1 = RiskEngine(cfg1)
    engine2 = RiskEngine(cfg2)

    a1 = engine1.score_alert(sample_prediction, sample_window)
    a2 = engine2.score_alert(sample_prediction, sample_window)

    # In win_test_001, failed_logins is 45 >= 40 (saturated)
    # Under cfg1, contrib was 15.0; under cfg2, contrib must be 25.0
    bd1 = next(c for c in a1.score_breakdown.behavioral_components if c.component == "failed_login_burst")
    bd2 = next(c for c in a2.score_breakdown.behavioral_components if c.component == "failed_login_burst")

    assert bd1.contribution == pytest.approx(15.0)
    assert bd2.contribution == pytest.approx(25.0)


# =====================================================================
# 3. Severity Classification & Safeguard Tests (Section 10.C)
# =====================================================================

def test_severity_band_boundaries():
    """Verify exact boundary handling across LOW, MEDIUM, HIGH, CRITICAL."""
    bands = SeverityBandConfig(low_max=30.0, medium_max=60.0, high_max=80.0)
    # Safeguard disabled for pure boundary test
    classifier = SeverityClassifier(bands=bands, safeguard=CriticalSafeguardConfig(enabled=False))

    sev, _, _ = classifier.classify(0.0)
    assert sev == SeverityLevel.LOW

    sev, _, _ = classifier.classify(29.99)
    assert sev == SeverityLevel.LOW

    sev, _, _ = classifier.classify(30.0)
    assert sev == SeverityLevel.MEDIUM

    sev, _, _ = classifier.classify(59.99)
    assert sev == SeverityLevel.MEDIUM

    sev, _, _ = classifier.classify(60.0)
    assert sev == SeverityLevel.HIGH

    sev, _, _ = classifier.classify(79.99)
    assert sev == SeverityLevel.HIGH

    sev, _, _ = classifier.classify(80.0)
    assert sev == SeverityLevel.CRITICAL

    sev, _, _ = classifier.classify(100.0)
    assert sev == SeverityLevel.CRITICAL


def test_severity_rejects_out_of_range():
    """SeverityClassifier must reject scores < 0 or > 100."""
    classifier = SeverityClassifier(SeverityBandConfig())
    with pytest.raises(ValueError):
        classifier.classify(-0.01)
    with pytest.raises(ValueError):
        classifier.classify(100.01)


def test_critical_alert_safeguard_enforcement():
    """High score without corroborating behavioral evidence must be capped at HIGH."""
    bands = SeverityBandConfig(low_max=30.0, medium_max=60.0, high_max=80.0)
    safeguard = CriticalSafeguardConfig(enabled=True, min_corroborating_signals=1)
    classifier = SeverityClassifier(bands=bands, safeguard=safeguard)

    # Score in critical band (85.0), but 0 corroborating behavioral signals
    sev, applied, note = classifier.classify(85.0, evidence=[])
    assert sev == SeverityLevel.HIGH
    assert applied is True
    assert note is not None
    assert "capped at HIGH" in note

    # Score in critical band (85.0) WITH 1 corroborating signal
    ev_item = EvidenceItem(
        signal_name="sig",
        source_field="field",
        observed_value=50,
        comparison_or_rule="rule",
        contribution=10.0,
        explanation="expl",
    )
    sev_ok, applied_ok, note_ok = classifier.classify(85.0, evidence=[ev_item])
    assert sev_ok == SeverityLevel.CRITICAL
    assert applied_ok is False
    assert note_ok is None


def test_critical_alert_safeguard_disabled():
    """When safeguard is disabled, uncorroborated score >= 80 receives CRITICAL."""
    bands = SeverityBandConfig(low_max=30.0, medium_max=60.0, high_max=80.0)
    safeguard = CriticalSafeguardConfig(enabled=False)
    classifier = SeverityClassifier(bands=bands, safeguard=safeguard)

    sev, applied, note = classifier.classify(85.0, evidence=[])
    assert sev == SeverityLevel.CRITICAL
    assert applied is False


# =====================================================================
# 4. Evidence Extraction Tests (Section 10.D)
# =====================================================================

def test_evidence_refers_to_real_inputs(default_config, sample_prediction, sample_window):
    """Evidence items must reflect real fields and observed values."""
    engine = RiskEngine(default_config)
    alert = engine.score_alert(sample_prediction, sample_window)

    assert len(alert.evidence) > 0
    for ev in alert.evidence:
        assert ev.source_field in sample_window
        assert ev.observed_value == sample_window[ev.source_field]
        assert ev.contribution > 0.0
        assert len(ev.explanation) > 0


def test_unobserved_field_handled_safely(default_config, sample_prediction, sample_window):
    """Missing fields in source window must be marked missing_evidence, not fabricated as 0."""
    win = dict(sample_window)
    del win["failed_logins"]  # Remove source field

    engine = RiskEngine(default_config)
    alert = engine.score_alert(sample_prediction, win)

    # failed_login_burst must NOT appear in positive evidence
    ev_names = [e.signal_name for e in alert.evidence]
    assert "failed_login_burst" not in ev_names

    # Breakdown must explicitly record missing_evidence status
    fl_bd = next(c for c in alert.score_breakdown.behavioral_components if c.component == "failed_login_burst")
    assert fl_bd.status == "missing_evidence"
    assert fl_bd.contribution == 0.0
    assert fl_bd.observed_value is None


def test_no_unsupported_attack_labels_generated(default_config, sample_prediction, sample_window):
    """Alerts, explanations, and evidence must avoid unsupported ATT&CK claims."""
    engine = RiskEngine(default_config)
    alert = engine.score_alert(sample_prediction, sample_window)

    full_text = json.dumps(alert.model_dump()).lower()
    prohibited_terms = ["apt29", "apt28", "ransomware", "confirmed attack", "proven compromise"]
    for term in prohibited_terms:
        assert term not in full_text, f"Prohibited unverified term '{term}' found in alert output."


# =====================================================================
# 5. Negative Failure Tests (Section 10.E)
# =====================================================================

def test_rejects_malformed_prediction(default_config, sample_window):
    """Engine must reject prediction missing required fields or non-numeric scores."""
    engine = RiskEngine(default_config)

    # Missing anomaly_score
    bad_pred = {"window_id": "win_1", "is_anomaly": 1}
    with pytest.raises(ValueError, match="missing required field"):
        engine.score_alert(bad_pred, sample_window)

    # Non-numeric anomaly_score
    bad_pred_score = {"window_id": "win_1", "anomaly_score": "not_numeric", "is_anomaly": 1}
    with pytest.raises(ValueError, match="must be numeric"):
        engine.score_alert(bad_pred_score, sample_window)

    # Non-finite anomaly_score
    bad_pred_inf = {"window_id": "win_1", "anomaly_score": float("inf"), "is_anomaly": 1}
    with pytest.raises(ValueError, match="must be finite"):
        engine.score_alert(bad_pred_inf, sample_window)


def test_rejects_mismatched_window_ids(default_config, sample_prediction, sample_window):
    """Engine must reject when prediction window_id does not match source window window_id."""
    engine = RiskEngine(default_config)
    pred = dict(sample_prediction)
    pred["window_id"] = "win_different_999"

    with pytest.raises(ValueError, match="Window ID mismatch"):
        engine.score_alert(pred, sample_window)


def test_rejects_missing_window_id(default_config, sample_prediction, sample_window):
    """Engine must reject source window missing window_id."""
    engine = RiskEngine(default_config)
    win = dict(sample_window)
    del win["window_id"]

    with pytest.raises(ValueError, match="missing required 'window_id'"):
        engine.score_alert(sample_prediction, win)


def test_rejects_non_numeric_telemetry_in_numeric_signal(default_config, sample_prediction, sample_window):
    """Engine must reject non-numeric values in numeric source fields."""
    engine = RiskEngine(default_config)
    win = dict(sample_window)
    win["failed_logins"] = "invalid_string"

    with pytest.raises(ValueError, match="contains non-numeric value"):
        engine.score_alert(sample_prediction, win)


def test_rejects_invalid_config_weights():
    """RiskScoringConfig must reject configurations where weights do not sum to 100.0."""
    with pytest.raises(ValueError, match="Total scoring weights must sum exactly to 100.0"):
        RiskScoringConfig(
            version="v_bad",
            ml_anomaly_weight=50.0,
            behavioral_signals=[
                BehavioralSignalConfig(
                    name="sig1",
                    source_field="f1",
                    weight=30.0,  # 50 + 30 = 80 != 100
                    baseline_threshold=1.0,
                    saturation_threshold=5.0,
                )
            ],
        )


def test_rejects_inverted_saturation_threshold():
    """BehavioralSignalConfig must reject saturation_threshold < baseline_threshold."""
    with pytest.raises(ValueError, match="saturation_threshold"):
        BehavioralSignalConfig(
            name="sig_inv",
            source_field="f1",
            weight=10.0,
            baseline_threshold=10.0,
            saturation_threshold=5.0,  # Invalid: saturation < baseline
        )


# =====================================================================
# 6. Integration Tests (Section 10.F)
# =====================================================================

def test_end_to_end_integration_with_phase2(default_config):
    """Full integration: Phase 2 detector scores evaluation rows -> enters RiskEngine -> produces valid alerts."""
    detector = AnomalyDetector.load(ARTIFACT_DIR)
    eval_df = pd.read_csv(EVAL_FILE, nrows=50)

    # 1. Phase 2 inference
    preds = detector.predict(eval_df)
    assert len(preds) == 50

    # 2. Score alerts through RiskEngine
    engine = RiskEngine(default_config)
    alerts = engine.score_alerts(preds, eval_df)

    assert len(alerts) == 50

    # 3. Verify alerts
    for alert, (_, row) in zip(alerts, eval_df.iterrows()):
        assert alert.window_id == row["window_id"]
        assert 0.0 <= alert.risk_score <= 100.0
        assert alert.score_breakdown.reconciled is True
        assert alert.severity in (SeverityLevel.LOW, SeverityLevel.MEDIUM, SeverityLevel.HIGH, SeverityLevel.CRITICAL)

        # Check evidence correspondence
        for ev in alert.evidence:
            assert ev.source_field in row
            assert ev.observed_value == pytest.approx(float(row[ev.source_field]))
