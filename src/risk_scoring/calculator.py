"""Transparent risk score calculation engine for Phase 3.

Combines the ML anomaly signal with verifiable behavioral contributions into an explainable,
bounded priority score from 0.0 to 100.0 with full audit breakdown reconciliation.
"""

from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np

from src.risk_scoring.config import RiskScoringConfig
from src.risk_scoring.schema import ScoreBreakdown, ScoreComponentBreakdown


class RiskScoreCalculator:
    """Calculates bounded priority risk scores with full breakdown reconciliation."""

    def __init__(self, config: RiskScoringConfig):
        self.config = config

    def calculate_ml_component(
        self,
        anomaly_score: float,
        is_anomaly: int,
        raw_score: Optional[float] = None,
    ) -> ScoreComponentBreakdown:
        """Compute the ML anomaly score contribution using Phase 2 score semantics.
        
        Score Semantics:
        - raw_score: decision_function(X) (higher is normal, lower anomalous)
        - anomaly_score: -raw_score (higher is anomalous, lower normal)
        - is_anomaly: anomaly_score > threshold (95th percentile of normal baseline)
        
        Formula:
        - If anomaly_score <= 0.0:
            nominal baseline traffic, 0.0 contribution.
        - If 0.0 < anomaly_score <= threshold:
            sub-threshold deviation scaling up to 25% of ML weight:
            scale = 0.25 * (anomaly_score / threshold)
        - If anomaly_score > threshold:
            confirmed statistical anomaly above 95th percentile:
            excess = min(1.0, (anomaly_score - threshold) / (max_expected - threshold))
            scale = 0.25 + 0.75 * excess
            contribution = round(weight * scale, 2)
        """
        weight = self.config.ml_anomaly_weight
        thresh = self.config.ml_anomaly_threshold
        ceiling = self.config.ml_anomaly_max_expected

        if not np.isfinite(anomaly_score):
            raise ValueError(f"Non-finite anomaly_score provided: {anomaly_score}")

        if anomaly_score <= 0.0:
            scale = 0.0
            contrib = 0.0
            status = "baseline_normal"
            calc_method = "non_positive_nominal_baseline"
            rule_str = f"anomaly_score <= 0.0 (baseline normal)"
        elif anomaly_score <= thresh:
            scale = 0.25 * (anomaly_score / thresh)
            contrib = round(weight * scale, 2)
            status = "baseline_normal"
            calc_method = "sub_threshold_linear_scaling"
            rule_str = f"0.0 < anomaly_score <= threshold ({thresh:.4f})"
        else:
            denom = ceiling - thresh
            if denom <= 0:
                excess = 1.0
            else:
                excess = min(1.0, max(0.0, (anomaly_score - thresh) / denom))
            scale = 0.25 + 0.75 * excess
            contrib = round(weight * scale, 2)
            status = "contributed"
            calc_method = "supra_threshold_saturation_scaling"
            rule_str = f"anomaly_score > threshold ({thresh:.4f})"

        return ScoreComponentBreakdown(
            component="ml_isolation_forest_anomaly",
            source_field="anomaly_score",
            observed_value=float(round(anomaly_score, 6)),
            configured_weight=weight,
            rule=rule_str,
            contribution=contrib,
            calculation_method=calc_method,
            status=status,
        )

    def calculate_risk_score(
        self,
        ml_component: ScoreComponentBreakdown,
        behavioral_components: List[ScoreComponentBreakdown],
    ) -> Tuple[float, ScoreBreakdown]:
        """Combine ML and behavioral components into final bounded risk score and breakdown."""
        total_ml = ml_component.contribution
        total_behavioral = sum(b.contribution for b in behavioral_components)
        raw_total = total_ml + total_behavioral

        # Bounded priority score strictly in [0.0, 100.0]
        final_score = round(min(100.0, max(0.0, raw_total)), 2)

        rounding_diff = round(abs(raw_total - final_score), 4)
        reconciled = rounding_diff <= self.config.rounding_tolerance

        breakdown = ScoreBreakdown(
            ml_anomaly=ml_component,
            behavioral_components=behavioral_components,
            total_ml_contribution=round(total_ml, 2),
            total_behavioral_contribution=round(total_behavioral, 2),
            calculated_risk_score=final_score,
            reconciled=reconciled,
            rounding_difference=rounding_diff,
        )

        return final_score, breakdown
