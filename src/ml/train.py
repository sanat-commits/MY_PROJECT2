"""Training pipeline for Baseline Isolation Forest Anomaly Detection.

Trains Isolation Forest strictly on normal training data, derives a reproducible
threshold from the training score distribution, and saves all artifacts.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from src.ml.config import MLConfig, get_default_config
from src.ml.features import NUMERIC_BEHAVIORAL_FEATURES, validate_feature_schema
from src.ml.preprocessing import FeaturePreprocessor


def train_baseline(config: Optional[MLConfig] = None) -> Dict[str, Any]:
    """Execute complete baseline training pipeline and save artifacts."""
    if config is None:
        config = get_default_config()

    print("==================================================")
    print("Executing Phase 2 Training: Baseline Isolation Forest")
    print("==================================================")
    print(f"Training dataset: {config.train_path}")
    print(f"Artifact directory: {config.artifact_dir}")

    # 1. Validate training input path
    if not config.train_path.exists():
        raise FileNotFoundError(f"Training dataset missing at {config.train_path}")

    # 2. Load training data
    train_df = pd.read_csv(config.train_path)
    if train_df.empty:
        raise ValueError(f"Training dataset is empty: {config.train_path}")

    # Ensure training data is strictly normal-only (no target leakage)
    if "label" in train_df.columns:
        labels = set(train_df["label"].unique())
        if labels != {0}:
            raise ValueError(
                f"Training dataset contains non-normal labels: {labels}. Expected normal-only (0)."
            )

    train_rows = len(train_df)
    print(f"Loaded {train_rows} training rows (verified normal-only).")

    # 3. Validate feature schema
    validate_feature_schema(train_df, NUMERIC_BEHAVIORAL_FEATURES)

    # 4. Fit preprocessing on training data
    preprocessor = FeaturePreprocessor(feature_names=NUMERIC_BEHAVIORAL_FEATURES)
    X_train = preprocessor.fit_transform(train_df)
    print(f"Features extracted: {len(NUMERIC_BEHAVIORAL_FEATURES)} numeric behavioral features.")

    # 5. Fit Isolation Forest
    print(
        f"Fitting IsolationForest(n_estimators={config.n_estimators}, "
        f"random_state={config.random_state}, contamination={config.contamination})..."
    )
    model = IsolationForest(
        n_estimators=config.n_estimators,
        max_samples=config.max_samples,
        contamination=config.contamination,
        random_state=config.random_state,
    )
    model.fit(X_train)

    # 6. Determine threshold from training-normal distribution
    # raw_score: decision_function (higher = more normal, lower = anomalous)
    # anomaly_score: -decision_function (higher = more anomalous)
    train_raw_scores = model.decision_function(X_train)
    train_anomaly_scores = -train_raw_scores

    threshold_val = float(np.percentile(train_anomaly_scores, config.threshold_percentile))
    print(
        f"Derived threshold ({config.threshold_percentile}th percentile of training anomaly scores): "
        f"{threshold_val:.6f}"
    )

    # 7. Prepare and save artifacts
    config.artifact_dir.mkdir(parents=True, exist_ok=True)

    # Preprocessor
    preprocessor.save(config.preprocessor_artifact_path)

    # Model
    joblib.dump(model, config.model_artifact_path)

    # Threshold artifact
    threshold_data = {
        "threshold": threshold_val,
        "threshold_percentile": config.threshold_percentile,
        "threshold_method": config.threshold_method,
        "score_semantics": {
            "raw_score": "decision_function (lower is more anomalous)",
            "anomaly_score": "-decision_function (higher is more anomalous)",
            "decision_rule": "anomaly_score > threshold",
        },
        "training_data_ref": str(config.train_path.name),
        "training_rows": train_rows,
        "training_score_stats": {
            "min": float(np.min(train_anomaly_scores)),
            "mean": float(np.mean(train_anomaly_scores)),
            "median": float(np.median(train_anomaly_scores)),
            "max": float(np.max(train_anomaly_scores)),
            "std": float(np.std(train_anomaly_scores)),
        },
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    with open(config.threshold_artifact_path, "w", encoding="utf-8") as f:
        json.dump(threshold_data, f, indent=2)

    # Feature schema artifact
    feature_schema_data = {
        "model_version": "0.1.0-baseline-iforest",
        "feature_names": NUMERIC_BEHAVIORAL_FEATURES,
        "feature_count": len(NUMERIC_BEHAVIORAL_FEATURES),
        "expected_order": NUMERIC_BEHAVIORAL_FEATURES,
        "feature_data_types": {f: "float64" for f in NUMERIC_BEHAVIORAL_FEATURES},
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    with open(config.feature_schema_artifact_path, "w", encoding="utf-8") as f:
        json.dump(feature_schema_data, f, indent=2)

    print(f"Artifacts successfully saved to {config.artifact_dir}")

    return {
        "model": model,
        "preprocessor": preprocessor,
        "threshold": threshold_val,
        "train_rows": train_rows,
        "artifacts": {
            "preprocessor": str(config.preprocessor_artifact_path),
            "model": str(config.model_artifact_path),
            "threshold": str(config.threshold_artifact_path),
            "feature_schema": str(config.feature_schema_artifact_path),
        },
    }


def main():
    config = get_default_config()
    train_baseline(config)


if __name__ == "__main__":
    main()
