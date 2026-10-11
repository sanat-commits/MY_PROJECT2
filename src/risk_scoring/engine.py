"""End-to-end Risk Scoring Engine for Phase 3.

Orchestrates prediction validation, source window verification, verifiable evidence extraction,
transparent score calculation, severity classification, and structured alert creation.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import numpy as np
import pandas as pd

from src.risk_scoring.config import RiskScoringConfig, get_default_risk_config
from src.risk_scoring.evidence import EvidenceExtractor
from src.risk_scoring.calculator import RiskScoreCalculator
from src.risk_scoring.characterization import (
    AnomalyCharacterizationService,
    get_characterization_service,
)
from src.risk_scoring.severity import SeverityClassifier
from src.risk_scoring.schema import (
    SecurityAlert,
    generate_deterministic_alert_id,
)


class RiskEngine:
    """Unified engine for transforming Phase 2 ML predictions and behavioral windows into explainable alerts."""

    def __init__(self, config: Optional[RiskScoringConfig] = None):
        self.config = config or get_default_risk_config()
        self.evidence_extractor = EvidenceExtractor(
            missing_evidence_policy=self.config.missing_evidence_policy
        )
        self.calculator = RiskScoreCalculator(self.config)
        self.severity_classifier = SeverityClassifier(
            bands=self.config.severity_bands,
            safeguard=self.config.critical_safeguard,
        )
        self.characterization_service = AnomalyCharacterizationService(config=self.config)

    def validate_prediction(self, prediction: Union[Dict[str, Any], pd.Series]) -> Dict[str, Any]:
        """Validate that ML prediction conforms to Phase 2 inference contract."""
        if not isinstance(prediction, (dict, pd.Series)):
            raise TypeError(f"Expected prediction as dict or pd.Series, got {type(prediction)}")

        p_dict = dict(prediction)

        # Check required fields
        required = ["window_id", "anomaly_score", "is_anomaly"]
        missing = [f for f in required if f not in p_dict]
        if missing:
            raise ValueError(f"Malformed Phase 2 prediction: missing required field(s) {missing}")

        # Check types
        win_id = str(p_dict["window_id"]).strip()
        if not win_id:
            raise ValueError("Prediction window_id cannot be empty.")

        try:
            anom_score = float(p_dict["anomaly_score"])
        except (ValueError, TypeError):
            raise ValueError(
                f"Prediction anomaly_score must be numeric, got {p_dict['anomaly_score']}"
            )

        if not np.isfinite(anom_score):
            raise ValueError(f"Prediction anomaly_score must be finite, got {anom_score}")

        try:
            is_anom = int(p_dict["is_anomaly"])
        except (ValueError, TypeError):
            raise ValueError(f"Prediction is_anomaly must be integer, got {p_dict['is_anomaly']}")

        if is_anom not in (0, 1):
            raise ValueError(f"Prediction is_anomaly must be 0 or 1, got {is_anom}")

        raw_score = None
        if "raw_score" in p_dict and p_dict["raw_score"] is not None:
            try:
                raw_score = float(p_dict["raw_score"])
            except (ValueError, TypeError):
                raise ValueError(f"Prediction raw_score must be numeric, got {p_dict['raw_score']}")

        return {
            "window_id": win_id,
            "anomaly_score": anom_score,
            "is_anomaly": is_anom,
            "raw_score": raw_score,
        }

    def validate_source_window(self, window: Union[Dict[str, Any], pd.Series]) -> Dict[str, Any]:
        """Validate source telemetry window structure and types."""
        if not isinstance(window, (dict, pd.Series)):
            raise TypeError(f"Expected source_window as dict or pd.Series, got {type(window)}")

        w_dict = dict(window)

        if "window_id" not in w_dict:
            raise ValueError("Source telemetry window is missing required 'window_id' field.")

        win_id = str(w_dict["window_id"]).strip()
        if not win_id:
            raise ValueError("Source telemetry window window_id cannot be empty.")

        # Validate numeric parseability of any configured signal fields present
        for sig in self.config.behavioral_signals:
            f = sig.source_field
            if f in w_dict and w_dict[f] is not None and not pd.isna(w_dict[f]):
                try:
                    float(w_dict[f])
                except (ValueError, TypeError):
                    raise ValueError(
                        f"Source window field '{f}' contains non-numeric value: {w_dict[f]}"
                    )

        return w_dict

    def score_alert(
        self,
        prediction: Union[Dict[str, Any], pd.Series],
        source_window: Union[Dict[str, Any], pd.Series],
        created_at: Optional[str] = None,
    ) -> SecurityAlert:
        """Score a single observation window and return a validated SecurityAlert."""
        # 1. Validate prediction
        pred = self.validate_prediction(prediction)

        # 2. Validate source window
        win = self.validate_source_window(source_window)

        # 3. Verify window ID consistency
        if pred["window_id"] != str(win["window_id"]).strip():
            raise ValueError(
                f"Window ID mismatch between prediction ('{pred['window_id']}') and "
                f"source window ('{win['window_id']}')"
            )

        window_id = pred["window_id"]

        # 4. Extract verifiable evidence & component breakdowns
        evidence_items, behavioral_breakdowns = self.evidence_extractor.extract_all_evidence(
            self.config.behavioral_signals, win
        )

        # 5. Calculate ML contribution
        ml_component = self.calculator.calculate_ml_component(
            anomaly_score=pred["anomaly_score"],
            is_anomaly=pred["is_anomaly"],
            raw_score=pred["raw_score"],
        )

        # 6. Calculate total risk score and reconciled breakdown
        risk_score, score_breakdown = self.calculator.calculate_risk_score(
            ml_component=ml_component,
            behavioral_components=behavioral_breakdowns,
        )

        # 7. Classify operational severity with critical safeguard
        severity, safeguard_applied, safeguard_note = self.severity_classifier.classify(
            risk_score=risk_score,
            evidence=evidence_items,
        )

        # 8. Characterize behavioral anomaly pattern
        characterization = self.characterization_service.characterize(
            prediction=pred,
            source_window=win,
            config=self.config,
        )

        # 9. Deterministic alert ID and timestamp
        alert_id = generate_deterministic_alert_id(window_id, self.config.version)
        timestamp = created_at or datetime.now(timezone.utc).isoformat()

        # 10. Assemble and return validated SecurityAlert
        alert = SecurityAlert(
            alert_id=alert_id,
            window_id=window_id,
            anomaly_score=pred["anomaly_score"],
            is_anomaly=pred["is_anomaly"],
            risk_score=risk_score,
            severity=severity,
            evidence=evidence_items,
            score_breakdown=score_breakdown,
            scoring_config_version=self.config.version,
            created_at=timestamp,
            raw_model_score=pred["raw_score"],
            anomaly_threshold=self.config.ml_anomaly_threshold,
            critical_safeguard_applied=safeguard_applied,
            safeguard_note=safeguard_note,
            anomaly_characterization=characterization,
        )

        return alert

    def score_alerts(
        self,
        predictions_df: pd.DataFrame,
        source_windows_df: pd.DataFrame,
    ) -> List[SecurityAlert]:
        """Score a batch of predictions and source windows."""
        if not isinstance(predictions_df, pd.DataFrame) or not isinstance(source_windows_df, pd.DataFrame):
            raise TypeError("Expected both predictions_df and source_windows_df as pandas DataFrames")

        if len(predictions_df) != len(source_windows_df):
            raise ValueError(
                f"Length mismatch between predictions ({len(predictions_df)}) and "
                f"source windows ({len(source_windows_df)})"
            )

        alerts = []
        # Index windows by window_id if present for fast lookup
        windows_by_id = {}
        for _, row in source_windows_df.iterrows():
            w_id = str(row["window_id"]).strip()
            windows_by_id[w_id] = row

        for _, pred_row in predictions_df.iterrows():
            pred_id = str(pred_row["window_id"]).strip()
            if pred_id not in windows_by_id:
                raise ValueError(f"Prediction window_id '{pred_id}' not found in source windows")
            win_row = windows_by_id[pred_id]
            alert = self.score_alert(pred_row, win_row)
            alerts.append(alert)

        return alerts


def score_alert(
    prediction: Union[Dict[str, Any], pd.Series],
    source_window: Union[Dict[str, Any], pd.Series],
    scoring_config: Optional[RiskScoringConfig] = None,
) -> SecurityAlert:
    """Convenience functional interface for scoring a single alert."""
    engine = RiskEngine(scoring_config)
    return engine.score_alert(prediction, source_window)


def score_alerts(
    predictions_df: pd.DataFrame,
    source_windows_df: pd.DataFrame,
    scoring_config: Optional[RiskScoringConfig] = None,
) -> List[SecurityAlert]:
    """Convenience functional interface for batch scoring alerts."""
    engine = RiskEngine(scoring_config)
    return engine.score_alerts(predictions_df, source_windows_df)


def run_evaluation_scoring() -> Dict[str, Any]:
    """Score the evaluation dataset using Phase 2 inference and report statistics."""
    from src.ml.config import get_default_config
    from src.ml.inference import AnomalyDetector

    ml_cfg = get_default_config()
    detector = AnomalyDetector.load(ml_cfg.artifact_dir)

    eval_df = pd.read_csv(ml_cfg.eval_path)
    preds = detector.predict(eval_df)

    risk_cfg = get_default_risk_config(
        train_csv_path=ml_cfg.train_path,
        ml_threshold=detector.threshold,
    )
    engine = RiskEngine(risk_cfg)

    print("==================================================")
    print("Executing Phase 3 Risk Scoring on Evaluation Data")
    print("==================================================")
    alerts = engine.score_alerts(preds, eval_df)

    severity_counts = {
        "LOW": sum(1 for a in alerts if a.severity.value == "LOW"),
        "MEDIUM": sum(1 for a in alerts if a.severity.value == "MEDIUM"),
        "HIGH": sum(1 for a in alerts if a.severity.value == "HIGH"),
        "CRITICAL": sum(1 for a in alerts if a.severity.value == "CRITICAL"),
    }

    scores = [a.risk_score for a in alerts]
    evidence_counts = [len(a.evidence) for a in alerts]
    safeguard_triggers = sum(1 for a in alerts if a.critical_safeguard_applied)

    print(f"Total Alerts Generated:   {len(alerts)}")
    print(f"Severity Breakdown:       {severity_counts}")
    print(f"Mean Risk Score:          {np.mean(scores):.2f}")
    print(f"Min / Median / Max Score: {np.min(scores):.2f} / {np.median(scores):.2f} / {np.max(scores):.2f}")
    print(f"Mean Evidence Count:      {np.mean(evidence_counts):.2f}")
    print(f"Critical Safeguard Note:  {safeguard_triggers} alerts affected by safeguard")

    return {
        "total_alerts": len(alerts),
        "severity_counts": severity_counts,
        "mean_risk_score": float(np.mean(scores)),
        "safeguard_triggers": safeguard_triggers,
    }


if __name__ == "__main__":
    run_evaluation_scoring()
