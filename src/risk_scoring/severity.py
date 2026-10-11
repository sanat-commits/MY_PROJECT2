"""Severity classification module for Phase 3 Explainable Risk Scoring.

Provides centralized operational severity band assignment, boundary enforcement,
and the critical-alert corroborating evidence safeguard.
"""

from typing import List, Optional, Tuple
from src.risk_scoring.config import SeverityBandConfig, CriticalSafeguardConfig
from src.risk_scoring.schema import EvidenceItem, SeverityLevel


class SeverityClassifier:
    """Centralized mapper of continuous risk scores to operational severity bands."""

    def __init__(
        self,
        bands: SeverityBandConfig,
        safeguard: Optional[CriticalSafeguardConfig] = None,
    ):
        self.bands = bands
        self.safeguard = safeguard or CriticalSafeguardConfig()

    def classify(
        self,
        risk_score: float,
        evidence: Optional[List[EvidenceItem]] = None,
    ) -> Tuple[SeverityLevel, bool, Optional[str]]:
        """Assign operational severity level based on risk score and evidence.
        
        Returns:
            (SeverityLevel, safeguard_applied: bool, safeguard_note: Optional[str])
        
        Boundary Rules:
        - [0.0, low_max) -> LOW
        - [low_max, medium_max) -> MEDIUM
        - [medium_max, high_max) -> HIGH
        - [high_max, 100.0] -> CRITICAL
        
        Critical-Alert Safeguard:
        If raw severity is CRITICAL and safeguard is enabled, requires at least
        min_corroborating_signals behavioral evidence observations (> 0 contribution).
        If uncorroborated, downgrades to HIGH.
        """
        if not (0.0 <= risk_score <= 100.0):
            raise ValueError(f"Risk score must be in range [0.0, 100.0], got {risk_score}")

        evidence_items = evidence or []
        corroborating_count = len(evidence_items)

        # 1. Determine raw severity band
        if risk_score < self.bands.low_max:
            raw_severity = SeverityLevel.LOW
        elif risk_score < self.bands.medium_max:
            raw_severity = SeverityLevel.MEDIUM
        elif risk_score < self.bands.high_max:
            raw_severity = SeverityLevel.HIGH
        else:
            raw_severity = SeverityLevel.CRITICAL

        # 2. Evaluate critical-alert safeguard
        safeguard_applied = False
        safeguard_note = None

        if raw_severity == SeverityLevel.CRITICAL:
            if self.safeguard.enabled:
                min_req = self.safeguard.min_corroborating_signals
                if corroborating_count < min_req:
                    raw_severity = SeverityLevel.HIGH
                    safeguard_applied = True
                    safeguard_note = (
                        f"Critical severity capped at HIGH: Risk score ({risk_score:.2f}) "
                        f"reached CRITICAL band, but observed only {corroborating_count} "
                        f"corroborating behavioral evidence signal(s) (minimum required: {min_req})."
                    )

        return raw_severity, safeguard_applied, safeguard_note
