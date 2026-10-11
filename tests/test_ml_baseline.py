"""Phase 2 Machine Learning Baseline Tests.

Tests:
- Behavioral feature schema and ordering
- Data leakage prevention (trains only on label 0)
- Preprocessing and inference without retraining
- Deterministic reproducibility (two trainings yield identical thresholds and predictions)
- Fresh process / fresh object artifact loading
- Schema mismatch handling (missing feature, non-numeric values, reordered columns)
- Negative failure modes (empty dataset, missing file, missing artifact, corrupted artifact)
- Threshold computation based strictly on training normal data
- Measured performance on evaluation dataset
"""

from pathlib import Path
import json
import pytest
import numpy as np
import pandas as pd

from src.ml.config import MLConfig
from src.ml.features import (
    NUMERIC_BEHAVIORAL_FEATURES,
    EXCLUDED_COLUMNS,
    validate_feature_schema,
)
from src.ml.preprocessing import FeaturePreprocessor
from src.ml.inference import AnomalyDetector, run_inference
from src.ml.train import train_baseline
from src.ml.evaluation import evaluate_baseline

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
TRAIN_FILE = DATA_DIR / "security_windows_train_normal.csv"
EVAL_FILE = DATA_DIR / "security_windows_eval_labeled.csv"
DEFAULT_ARTIFACT_DIR = ROOT / "artifacts" / "ml"


# =====================================================================
# 1. Feature schema & exclusions
# =====================================================================

def test_feature_list_and_exclusions():
    """Verify that feature list contains exactly 17 numeric features and excludes metadata."""
    assert len(NUMERIC_BEHAVIORAL_FEATURES) == 17
    for col in ["window_id", "label", "anomaly_type", "user_role", "host_type"]:
        assert col not in NUMERIC_BEHAVIORAL_FEATURES
        assert col in EXCLUDED_COLUMNS


def test_validate_feature_schema_success():
    """Valid training rows must pass schema validation without error."""
    df = pd.read_csv(TRAIN_FILE, nrows=50)
    validate_feature_schema(df, NUMERIC_BEHAVIORAL_FEATURES)


# =====================================================================
# 2. Preprocessor functionality
# =====================================================================

def test_preprocessor_column_reordering_preservation():
    """FeaturePreprocessor must extract features in canonical order even if columns are shuffled."""
    df = pd.read_csv(TRAIN_FILE, nrows=20)
    prep = FeaturePreprocessor(NUMERIC_BEHAVIORAL_FEATURES)
    prep.fit(df)
    arr_normal = prep.transform(df)

    # Reverse columns
    reversed_cols = list(reversed(df.columns))
    df_reversed = df[reversed_cols].copy()
    arr_reversed = prep.transform(df_reversed)

    np.testing.assert_array_almost_equal(arr_normal, arr_reversed)


def test_preprocessor_rejects_missing_column():
    """FeaturePreprocessor must reject DataFrames missing a required feature."""
    df = pd.read_csv(TRAIN_FILE, nrows=10)
    prep = FeaturePreprocessor(NUMERIC_BEHAVIORAL_FEATURES)
    prep.fit(df)

    broken_df = df.drop(columns=["failed_logins"])
    with pytest.raises(ValueError, match="Missing required ML features"):
        prep.transform(broken_df)


def test_preprocessor_rejects_non_numeric():
    """FeaturePreprocessor must reject DataFrames with non-numeric values in numeric columns."""
    df = pd.read_csv(TRAIN_FILE, nrows=10).copy()
    prep = FeaturePreprocessor(NUMERIC_BEHAVIORAL_FEATURES)
    prep.fit(df)

    df["hour"] = df["hour"].astype(object)
    df.loc[0, "hour"] = "not_a_number"
    with pytest.raises(ValueError, match="non-numeric"):
        prep.transform(df)


# =====================================================================
# 3. Model training & artifact generation
# =====================================================================

def test_train_baseline_in_temp_dir(tmp_path):
    """Training in a clean directory must generate all 4 training artifacts."""
    art_dir = tmp_path / "artifacts"
    config = MLConfig(data_dir=DATA_DIR, artifact_dir=art_dir)
    result = train_baseline(config)

    assert (art_dir / "preprocessor.joblib").exists()
    assert (art_dir / "isolation_forest.joblib").exists()
    assert (art_dir / "threshold.json").exists()
    assert (art_dir / "feature_schema.json").exists()

    with open(art_dir / "threshold.json", "r") as f:
        t_data = json.load(f)
    assert "threshold" in t_data
    assert t_data["training_rows"] == 12000
    assert t_data["threshold_method"] == "training_normal_percentile"


def test_training_rejects_labeled_anomalies(tmp_path):
    """Training must refuse to fit on datasets containing anomaly labels (label != 0)."""
    art_dir = tmp_path / "artifacts"
    bad_train_file = tmp_path / "bad_train.csv"

    # Create synthetic dataset with anomaly label
    df = pd.read_csv(TRAIN_FILE, nrows=100).copy()
    df.loc[0, "label"] = 1
    df.to_csv(bad_train_file, index=False)

    config = MLConfig(
        data_dir=tmp_path,
        artifact_dir=art_dir,
        train_filename="bad_train.csv",
    )
    with pytest.raises(ValueError, match="non-normal labels"):
        train_baseline(config)


# =====================================================================
# 4. Reproducibility test
# =====================================================================

def test_training_reproducibility(tmp_path):
    """Two training runs with identical seeds must yield identical thresholds and predictions."""
    dir1 = tmp_path / "run1"
    dir2 = tmp_path / "run2"

    cfg1 = MLConfig(data_dir=DATA_DIR, artifact_dir=dir1, random_state=42)
    cfg2 = MLConfig(data_dir=DATA_DIR, artifact_dir=dir2, random_state=42)

    train_baseline(cfg1)
    train_baseline(cfg2)

    with open(dir1 / "threshold.json") as f:
        t1 = json.load(f)["threshold"]
    with open(dir2 / "threshold.json") as f:
        t2 = json.load(f)["threshold"]

    assert t1 == pytest.approx(t2, rel=1e-6)

    # Compare predictions on evaluation set
    eval_df = pd.read_csv(EVAL_FILE, nrows=200)
    det1 = AnomalyDetector.load(dir1)
    det2 = AnomalyDetector.load(dir2)

    pred1 = det1.predict(eval_df)
    pred2 = det2.predict(eval_df)

    np.testing.assert_array_almost_equal(pred1["raw_score"], pred2["raw_score"])
    np.testing.assert_array_almost_equal(pred1["anomaly_score"], pred2["anomaly_score"])
    np.testing.assert_array_equal(pred1["is_anomaly"], pred2["is_anomaly"])


# =====================================================================
# 5. Inference & artifact loading without retraining
# =====================================================================

def test_inference_loading_without_retraining(tmp_path):
    """AnomalyDetector.load must load pre-trained artifacts and perform inference without training."""
    art_dir = tmp_path / "artifacts"
    config = MLConfig(data_dir=DATA_DIR, artifact_dir=art_dir)
    train_baseline(config)

    # Load into independent detector instance
    detector = AnomalyDetector.load(art_dir)
    eval_sample = pd.read_csv(EVAL_FILE, nrows=100)

    preds = detector.predict(eval_sample)
    assert len(preds) == 100
    assert list(preds.columns) == ["window_id", "raw_score", "anomaly_score", "is_anomaly"]
    assert np.all(np.isfinite(preds["raw_score"]))
    assert np.all(np.isfinite(preds["anomaly_score"]))
    assert set(preds["is_anomaly"].unique()).issubset({0, 1})


# =====================================================================
# 6. Evaluation metrics test
# =====================================================================

def test_evaluation_baseline_produces_metrics(tmp_path):
    """Evaluation must calculate precision, recall, F1, and save metrics.json."""
    art_dir = tmp_path / "artifacts"
    config = MLConfig(data_dir=DATA_DIR, artifact_dir=art_dir)
    train_baseline(config)

    metrics = evaluate_baseline(config)
    assert (art_dir / "metrics.json").exists()
    assert "classification_metrics" in metrics
    cm = metrics["classification_metrics"]
    assert cm["precision"] > 0.8
    assert cm["recall"] > 0.8
    assert cm["f1"] > 0.8
    assert metrics["confusion_matrix"]["true_positives"] > 0


# =====================================================================
# 7. Negative failure modes
# =====================================================================

def test_negative_missing_training_file(tmp_path):
    """train_baseline must fail clearly when training file does not exist."""
    config = MLConfig(data_dir=tmp_path / "empty_dir", artifact_dir=tmp_path / "art")
    with pytest.raises(FileNotFoundError):
        train_baseline(config)


def test_negative_empty_training_file(tmp_path):
    """train_baseline must fail safely on an empty file."""
    empty_file = tmp_path / "security_windows_train_normal.csv"
    empty_file.write_text("")
    config = MLConfig(data_dir=tmp_path, artifact_dir=tmp_path / "art")
    with pytest.raises((ValueError, pd.errors.EmptyDataError)):
        train_baseline(config)


def test_negative_missing_model_artifact(tmp_path):
    """AnomalyDetector.load must raise FileNotFoundError if an artifact is missing."""
    empty_art_dir = tmp_path / "empty_art"
    empty_art_dir.mkdir()
    with pytest.raises(FileNotFoundError, match="Missing required ML artifact"):
        AnomalyDetector.load(empty_art_dir)


def test_negative_corrupt_model_artifact(tmp_path):
    """AnomalyDetector.load must raise RuntimeError if an artifact is corrupted."""
    art_dir = tmp_path / "art"
    config = MLConfig(data_dir=DATA_DIR, artifact_dir=art_dir)
    train_baseline(config)

    # Corrupt model file
    (art_dir / "isolation_forest.joblib").write_bytes(b"corrupted binary data")
    with pytest.raises(RuntimeError, match="Corrupted or invalid"):
        AnomalyDetector.load(art_dir)
