"""Phase 3 — Explainable Risk Scoring Package.

Provides:
- SecurityAlert, EvidenceItem, ScoreBreakdown, SeverityLevel schemas
- RiskScoringConfig, BehavioralSignalConfig, SeverityBandConfig
- EvidenceExtractor, RiskScoreCalculator, SeverityClassifier
- RiskEngine, score_alert, score_alerts
"""

from src.risk_scoring.schema import (
    SeverityLevel,
    EvidenceItem,
    ScoreComponentBreakdown,
    ScoreBreakdown,
    SecurityAlert,
    generate_deterministic_alert_id,
)
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
from src.risk_scoring.evidence import EvidenceExtractor
from src.risk_scoring.calculator import RiskScoreCalculator
from src.risk_scoring.severity import SeverityClassifier
from src.risk_scoring.engine import (
    RiskEngine,
    score_alert,
    score_alerts,
)

__all__ = [
    "SeverityLevel",
    "EvidenceItem",
    "ScoreComponentBreakdown",
    "ScoreBreakdown",
    "SecurityAlert",
    "generate_deterministic_alert_id",
    "BehavioralSignalConfig",
    "SeverityBandConfig",
    "CriticalSafeguardConfig",
    "RiskScoringConfig",
    "get_default_risk_config",
    "derive_baseline_thresholds_from_training",
    "save_config_to_json",
    "load_config_from_json",
    "EvidenceExtractor",
    "RiskScoreCalculator",
    "SeverityClassifier",
    "RiskEngine",
    "score_alert",
    "score_alerts",
]
