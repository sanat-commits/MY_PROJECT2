"""Evidence extraction component for Phase 3 Explainable Risk Scoring.

Evaluates behavioral signals against source telemetry windows, extracting verifiable
evidence items and detailed score breakdowns. Guarantees that:
- Evidence strictly reflects actual observed input values without fabrication.
- Unobserved/missing fields are explicitly identified and never claimed to be negative.
- Explanations are factual, mathematical, and free from unsupported attack labels.
"""

from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np
import pandas as pd

from src.risk_scoring.config import BehavioralSignalConfig
from src.risk_scoring.schema import EvidenceItem, ScoreComponentBreakdown


class EvidenceExtractor:
    """Reusable extractor of verifiable behavioral evidence from telemetry windows."""

    def __init__(self, missing_evidence_policy: str = "zero_with_audit"):
        self.missing_evidence_policy = missing_evidence_policy

    def evaluate_signal(
        self,
        signal: BehavioralSignalConfig,
        window: Union[Dict[str, Any], pd.Series],
    ) -> Tuple[Optional[EvidenceItem], ScoreComponentBreakdown]:
        """Evaluate a single behavioral signal against a telemetry observation window.
        
        Returns:
            (EvidenceItem or None, ScoreComponentBreakdown)
            EvidenceItem is generated only when the signal contributes positive risk score (> 0).
        """
        field = signal.source_field

        # 1. Check if source field exists and is not null/empty
        if field not in window:
            if self.missing_evidence_policy == "strict_raise":
                raise ValueError(f"Required telemetry feature '{field}' missing from source window.")
            breakdown = ScoreComponentBreakdown(
                component=signal.name,
                source_field=field,
                observed_value=None,
                configured_weight=signal.weight,
                rule=f"{signal.comparison_operator} {signal.baseline_threshold}",
                contribution=0.0,
                calculation_method="missing_evidence_fallback",
                status="missing_evidence",
            )
            return None, breakdown

        val = window[field]
        if val is None or pd.isna(val):
            if self.missing_evidence_policy == "strict_raise":
                raise ValueError(f"Feature '{field}' contains null/NaN value in source window.")
            breakdown = ScoreComponentBreakdown(
                component=signal.name,
                source_field=field,
                observed_value=None,
                configured_weight=signal.weight,
                rule=f"{signal.comparison_operator} {signal.baseline_threshold}",
                contribution=0.0,
                calculation_method="null_evidence_fallback",
                status="missing_evidence",
            )
            return None, breakdown

        # 2. Check numeric parseability
        try:
            numeric_val = float(val)
        except (ValueError, TypeError):
            raise ValueError(
                f"Feature '{field}' observed non-numeric value '{val}' that cannot be evaluated."
            )

        if not np.isfinite(numeric_val):
            raise ValueError(f"Feature '{field}' observed non-finite value '{val}'.")

        # 3. Evaluate based on operator
        contribution = 0.0
        status = "baseline_normal"
        calc_method = "no_excess"
        rule_str = ""
        explanation_str = ""

        if signal.comparison_operator == "gt":
            rule_str = f"observed > baseline_threshold ({signal.baseline_threshold})"
            if numeric_val <= signal.baseline_threshold:
                contribution = 0.0
                status = "baseline_normal"
                calc_method = "at_or_below_baseline"
                explanation_str = (
                    f"Observed {field}={numeric_val:.1f} was within normal baseline "
                    f"(<= {signal.baseline_threshold:.1f}); no risk contribution."
                )
            else:
                status = "contributed"
                calc_method = "linear_saturation_interpolation"
                denom = signal.saturation_threshold - signal.baseline_threshold
                if denom <= 0:
                    scale = 1.0
                else:
                    scale = min(1.0, max(0.0, (numeric_val - signal.baseline_threshold) / denom))
                raw_contrib = signal.weight * scale
                contribution = round(raw_contrib, 2)
                explanation_str = (
                    f"Observed {field}={numeric_val:.1f} exceeded baseline threshold "
                    f"({signal.baseline_threshold:.1f}); saturation ceiling is {signal.saturation_threshold:.1f}; "
                    f"contributed {contribution:.2f} points."
                )

        elif signal.comparison_operator == "gte":
            rule_str = f"observed >= baseline_threshold ({signal.baseline_threshold})"
            if numeric_val < signal.baseline_threshold:
                contribution = 0.0
                status = "baseline_normal"
                calc_method = "below_baseline"
                explanation_str = (
                    f"Observed {field}={numeric_val:.1f} was below baseline threshold "
                    f"({signal.baseline_threshold:.1f}); no risk contribution."
                )
            else:
                status = "contributed"
                calc_method = "linear_saturation_interpolation"
                denom = signal.saturation_threshold - signal.baseline_threshold
                if denom <= 0:
                    scale = 1.0
                else:
                    scale = min(1.0, max(0.0, (numeric_val - signal.baseline_threshold) / denom))
                contribution = round(signal.weight * scale, 2)
                explanation_str = (
                    f"Observed {field}={numeric_val:.1f} reached or exceeded baseline "
                    f"({signal.baseline_threshold:.1f}); contributed {contribution:.2f} points."
                )

        elif signal.comparison_operator == "eq":
            rule_str = f"observed == {signal.baseline_threshold}"
            if numeric_val == signal.baseline_threshold:
                status = "contributed"
                calc_method = "exact_match_step"
                contribution = round(signal.weight, 2)
                explanation_str = (
                    f"Observed {field}={numeric_val:.0f} matched positive risk condition "
                    f"(== {signal.baseline_threshold:.0f}); contributed {contribution:.2f} points."
                )
            else:
                status = "baseline_normal"
                calc_method = "exact_match_step"
                contribution = 0.0
                explanation_str = (
                    f"Observed {field}={numeric_val:.0f} did not match indicator condition; no risk contribution."
                )

        breakdown = ScoreComponentBreakdown(
            component=signal.name,
            source_field=field,
            observed_value=numeric_val,
            configured_weight=signal.weight,
            rule=rule_str,
            contribution=contribution,
            calculation_method=calc_method,
            status=status,
        )

        evidence_item = None
        if contribution > 0.0:
            evidence_item = EvidenceItem(
                signal_name=signal.name,
                source_field=field,
                observed_value=numeric_val,
                comparison_or_rule=rule_str,
                contribution=contribution,
                explanation=explanation_str,
            )

        return evidence_item, breakdown

    def extract_all_evidence(
        self,
        signals: List[BehavioralSignalConfig],
        window: Union[Dict[str, Any], pd.Series],
    ) -> Tuple[List[EvidenceItem], List[ScoreComponentBreakdown]]:
        """Evaluate all configured behavioral signals and return evidence list and breakdown components."""
        evidence_items: List[EvidenceItem] = []
        breakdowns: List[ScoreComponentBreakdown] = []

        for sig in signals:
            item, bd = self.evaluate_signal(sig, window)
            if item is not None:
                evidence_items.append(item)
            breakdowns.append(bd)

        return evidence_items, breakdowns
