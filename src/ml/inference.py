"""Inference module for loading trained Isolation Forest artifacts and scoring windows.

Loads preprocessor, model, feature schema, and threshold to score behavioral windows
without retraining.
"""

from pathlib import Path
from typing import Dict, List, Optional, Union
import json
import joblib
import numpy as np
import pandas as pd

from src.ml.config import MLConfig, get_default_config
from src.ml.preprocessing import FeaturePreprocessor


class AnomalyDetector:
    """Production inference wrapper for the trained baseline anomaly detector."""

    def __init__(
        self,
        model: object,
        preprocessor: FeaturePreprocessor,
        threshold: float,
        feature_schema: Dict[str, object],
        metadata: Optional[Dict[str, object]] = None,
    ):
        self.model = model
        self.preprocessor = preprocessor
        self.threshold = threshold
        self.feature_schema = feature_schema
        self.metadata = metadata or {}
        self.expected_features: List[str] = feature_schema.get("expected_order", [])

    @classmethod
    def load(cls, artifact_dir: Union[str, Path]) -> "AnomalyDetector":
        """Load detector artifacts from disk without retraining."""
        dir_path = Path(artifact_dir)

        model_path = dir_path / "isolation_forest.joblib"
        prep_path = dir_path / "preprocessor.joblib"
        thresh_path = dir_path / "threshold.json"
        schema_path = dir_path / "feature_schema.json"

        # Check required files
        for p in [model_path, prep_path, thresh_path, schema_path]:
            if not p.exists():
                raise FileNotFoundError(f"Missing required ML artifact: {p}")

        try:
            model = joblib.load(model_path)
        except Exception as e:
            raise RuntimeError(f"Corrupted or invalid model artifact at {model_path}: {e}")

        try:
            preprocessor = FeaturePreprocessor.load(prep_path)
        except Exception as e:
            raise RuntimeError(f"Corrupted or invalid preprocessor artifact at {prep_path}: {e}")

        try:
            with open(thresh_path, "r", encoding="utf-8") as f:
                thresh_data = json.load(f)
            threshold = float(thresh_data["threshold"])
        except Exception as e:
            raise RuntimeError(f"Corrupted or invalid threshold artifact at {thresh_path}: {e}")

        try:
            with open(schema_path, "r", encoding="utf-8") as f:
                schema_data = json.load(f)
        except Exception as e:
            raise RuntimeError(f"Corrupted or invalid feature schema artifact at {schema_path}: {e}")

        return cls(
            model=model,
            preprocessor=preprocessor,
            threshold=threshold,
            feature_schema=schema_data,
            metadata=thresh_data,
        )

    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        """Score input DataFrame and return structured predictions."""
        if not isinstance(df, pd.DataFrame):
            raise TypeError(f"Expected pandas DataFrame, got {type(df)}")

        if df.empty:
            raise ValueError("Input DataFrame is empty.")

        # Preprocessor handles schema validation & canonical feature extraction
        X = self.preprocessor.transform(df)

        raw_scores = self.model.decision_function(X)
        anomaly_scores = -raw_scores
        is_anomaly = (anomaly_scores > self.threshold).astype(int)

        results = {
            "raw_score": raw_scores,
            "anomaly_score": anomaly_scores,
            "is_anomaly": is_anomaly,
        }

        # Include window_id if present in input
        if "window_id" in df.columns:
            results["window_id"] = df["window_id"].values
        else:
            results["window_id"] = [f"row_{i}" for i in range(len(df))]

        pred_df = pd.DataFrame(results)
        # Put window_id first
        cols = ["window_id", "raw_score", "anomaly_score", "is_anomaly"]
        return pred_df[cols]


def run_inference(
    data_path: Optional[Union[str, Path]] = None,
    config: Optional[MLConfig] = None,
) -> pd.DataFrame:
    """Run inference against a specified dataset or the default evaluation set."""
    if config is None:
        config = get_default_config()

    target_path = Path(data_path) if data_path else config.eval_path
    if not target_path.exists():
        raise FileNotFoundError(f"Inference target data not found at {target_path}")

    df = pd.read_csv(target_path)
    detector = AnomalyDetector.load(config.artifact_dir)
    predictions = detector.predict(df)

    print("==================================================")
    print("Inference Completed")
    print("==================================================")
    print(f"Scored rows: {len(predictions)}")
    print(f"Detected anomalies: {int((predictions['is_anomaly'] == 1).sum())}")
    print(f"Normal windows: {int((predictions['is_anomaly'] == 0).sum())}")
    print("\nSample predictions:")
    print(predictions.head())

    return predictions


def main():
    config = get_default_config()
    run_inference(config=config)


if __name__ == "__main__":
    main()
