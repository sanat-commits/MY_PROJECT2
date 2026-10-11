"""Machine learning baseline package for security log anomaly detection."""

from src.ml.config import MLConfig, get_default_config
from src.ml.features import (
    EXCLUDED_COLUMNS,
    FEATURE_RATIONALE,
    NUMERIC_BEHAVIORAL_FEATURES,
    validate_feature_schema,
)
from src.ml.preprocessing import FeaturePreprocessor


def __getattr__(name: str):
    if name == "train_baseline":
        from src.ml.train import train_baseline
        return train_baseline
    if name in ("AnomalyDetector", "run_inference"):
        from src.ml.inference import AnomalyDetector, run_inference
        return AnomalyDetector if name == "AnomalyDetector" else run_inference
    if name == "evaluate_baseline":
        from src.ml.evaluation import evaluate_baseline
        return evaluate_baseline
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


__all__ = [
    "MLConfig",
    "get_default_config",
    "NUMERIC_BEHAVIORAL_FEATURES",
    "EXCLUDED_COLUMNS",
    "FEATURE_RATIONALE",
    "validate_feature_schema",
    "FeaturePreprocessor",
    "AnomalyDetector",
    "train_baseline",
    "run_inference",
    "evaluate_baseline",
]
