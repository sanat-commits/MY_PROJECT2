"""Phase 1 Dataset Validation Tests.

Covers:
- File existence (train, eval, manifest)
- Exact schema & single source of truth
- Training-set rules (normal-only, labels == 0)
- Evaluation-set rules (both classes, valid anomaly types)
- Required values (no nulls or empty strings)
- Semantic types (ints, floats, strings)
- Value ranges (hours, days, counts, bytes, labels)
- Internal consistency (login_attempts == failed + successful; weekends)
- Manifest consistency & synthetic flag
- Full validation pipeline execution on seeded dataset
- Negative tests for missing/extra columns, range errors, consistency violations,
  invalid labels, missing values, and corrupted manifests.
- Reproducibility testing.
"""

from pathlib import Path
import json
import pytest
import pandas as pd

from src.data_validation.schema import (
    REQUIRED_COLUMNS,
    METADATA_COLUMNS,
    FEATURE_COLUMNS,
    ALLOWED_USER_ROLES,
    ALLOWED_HOST_TYPES,
    ALLOWED_ANOMALY_TYPES,
)
from src.data_validation.validators import (
    CheckStatus,
    validate_manifest,
    validate_dataframe,
    validate_dataset_file,
)
from src.data_validation.report import run_full_validation

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
TRAIN_FILE = DATA_DIR / "security_windows_train_normal.csv"
EVAL_FILE = DATA_DIR / "security_windows_eval_labeled.csv"
MANIFEST_FILE = DATA_DIR / "dataset_manifest.json"


# =====================================================================
# 1. File existence
# =====================================================================

def test_seeded_files_exist():
    """Verify that all required dataset files exist in the data directory."""
    assert TRAIN_FILE.exists(), f"Missing training file: {TRAIN_FILE}"
    assert EVAL_FILE.exists(), f"Missing evaluation file: {EVAL_FILE}"
    assert MANIFEST_FILE.exists(), f"Missing manifest file: {MANIFEST_FILE}"


# =====================================================================
# 2. Exact schema & single source of truth
# =====================================================================

def test_schema_single_source_of_truth():
    """Ensure schema defines exactly 22 columns matching DATASET_SPEC.md."""
    assert len(REQUIRED_COLUMNS) == 22
    assert set(METADATA_COLUMNS).issubset(set(REQUIRED_COLUMNS))
    assert len(FEATURE_COLUMNS) == len(REQUIRED_COLUMNS) - len(METADATA_COLUMNS)
    assert "window_id" in METADATA_COLUMNS
    assert "label" in METADATA_COLUMNS
    assert "anomaly_type" in METADATA_COLUMNS


def test_train_csv_exact_schema():
    """Training CSV columns must match REQUIRED_COLUMNS in exact set and count."""
    df = pd.read_csv(TRAIN_FILE)
    assert list(df.columns) == REQUIRED_COLUMNS


def test_eval_csv_exact_schema():
    """Evaluation CSV columns must match REQUIRED_COLUMNS in exact set and count."""
    df = pd.read_csv(EVAL_FILE)
    assert list(df.columns) == REQUIRED_COLUMNS


# =====================================================================
# 3. Training-set rules
# =====================================================================

def test_training_set_rules():
    """Training set must be non-empty, label 0 only, and anomaly_type == 'normal'."""
    df = pd.read_csv(TRAIN_FILE)
    assert len(df) == 12000
    assert set(df["label"].unique()) == {0}
    assert set(df["anomaly_type"].unique()) == {"normal"}


# =====================================================================
# 4. Evaluation-set rules
# =====================================================================

def test_eval_set_rules():
    """Evaluation set must contain both classes (0 and 1) and valid anomaly types."""
    df = pd.read_csv(EVAL_FILE)
    assert len(df) == 4000
    assert set(df["label"].unique()) == {0, 1}
    eval_types = set(df["anomaly_type"].unique())
    assert eval_types.issubset(ALLOWED_ANOMALY_TYPES)
    # Check that normal and synthetic anomalies are both represented
    assert "normal" in eval_types
    assert len(eval_types) > 1


# =====================================================================
# 5. Required values & semantic types
# =====================================================================

def test_no_null_or_empty_values():
    """Ensure no columns contain nulls, NaN, or whitespace-only strings."""
    for file_path in [TRAIN_FILE, EVAL_FILE]:
        df = pd.read_csv(file_path)
        assert df.isnull().sum().sum() == 0, f"Found nulls in {file_path}"
        for str_col in ["window_id", "user_role", "host_type", "anomaly_type"]:
            empty_count = (df[str_col].astype(str).str.strip() == "").sum()
            assert empty_count == 0, f"Found empty strings in {file_path} col {str_col}"


def test_categorical_allowed_values():
    """Categorical values must strictly belong to approved sets."""
    for file_path in [TRAIN_FILE, EVAL_FILE]:
        df = pd.read_csv(file_path)
        assert set(df["user_role"].unique()).issubset(ALLOWED_USER_ROLES)
        assert set(df["host_type"].unique()).issubset(ALLOWED_HOST_TYPES)


# =====================================================================
# 6. Range checks
# =====================================================================

def test_value_ranges():
    """Validate documented numeric ranges and non-negativity."""
    for file_path in [TRAIN_FILE, EVAL_FILE]:
        df = pd.read_csv(file_path)
        assert df["hour"].between(0, 23).all()
        assert df["day_of_week"].between(0, 6).all()
        assert set(df["is_weekend"].unique()).issubset({0, 1})
        assert set(df["after_hours"].unique()).issubset({0, 1})
        assert set(df["label"].unique()).issubset({0, 1})

        # Non-negative counts
        count_cols = [
            "failed_logins", "successful_logins", "login_attempts",
            "new_source_ip_count", "privileged_actions", "file_access_count",
            "process_count", "network_connections", "external_connections",
            "distinct_destinations", "rare_process_count"
        ]
        for col in count_cols:
            assert (df[col] >= 0).all(), f"Negative count in {col} of {file_path}"

        assert (df["unique_source_ips"] >= 1).all()
        assert (df["bytes_out_mb"] >= 0.0).all()


# =====================================================================
# 7. Internal consistency checks
# =====================================================================

def test_login_attempts_consistency():
    """login_attempts must equal failed_logins + successful_logins for 100% of rows."""
    for file_path in [TRAIN_FILE, EVAL_FILE]:
        df = pd.read_csv(file_path)
        mismatches = df[df["login_attempts"] != (df["failed_logins"] + df["successful_logins"])]
        assert len(mismatches) == 0, f"Login count mismatch in {file_path}"


def test_weekend_day_consistency():
    """is_weekend must be 1 iff day_of_week is 5 (Saturday) or 6 (Sunday)."""
    for file_path in [TRAIN_FILE, EVAL_FILE]:
        df = pd.read_csv(file_path)
        expected_weekend = df["day_of_week"].isin([5, 6]).astype(int)
        mismatches = df[df["is_weekend"] != expected_weekend]
        assert len(mismatches) == 0, f"Weekend flag mismatch in {file_path}"


# =====================================================================
# 8. Manifest validation
# =====================================================================

def test_manifest_validation():
    """Manifest must exist, have synthetic=True, and match row counts."""
    results = validate_manifest(MANIFEST_FILE, train_path=TRAIN_FILE, eval_path=EVAL_FILE)
    for r in results:
        assert r.status == CheckStatus.PASS, f"Manifest check failed: {r.message}"


# =====================================================================
# 9. Full validation pipeline integration
# =====================================================================

def test_full_validation_seeded_dataset():
    """Running full validation on data directory must yield overall PASS."""
    report = run_full_validation(DATA_DIR)
    assert report.overall_status == CheckStatus.PASS
    assert report.train_rows == 12000
    assert report.eval_rows == 4000
    assert report.train_status == CheckStatus.PASS
    assert report.eval_status == CheckStatus.PASS
    assert report.manifest_status == CheckStatus.PASS


# =====================================================================
# 10. Negative tests (temporary fixtures, never corrupting canonical data)
# =====================================================================

@pytest.fixture
def sample_train_df():
    """Return a fresh 100-row valid training DataFrame for mutation testing."""
    df = pd.read_csv(TRAIN_FILE, nrows=100)
    return df.copy()


def test_negative_missing_column(sample_train_df):
    """Removing a required column must result in FAIL."""
    sample_train_df.drop(columns=["failed_logins"], inplace=True)
    results = validate_dataframe(sample_train_df, "sample_train", is_training=True)
    failed = [r for r in results if r.status == CheckStatus.FAIL and "missing_columns" in r.check_name]
    assert len(failed) > 0


def test_negative_extra_column(sample_train_df):
    """Adding an unexpected column must result in FAIL."""
    sample_train_df["unexpected_field"] = "bad"
    results = validate_dataframe(sample_train_df, "sample_train", is_training=True)
    failed = [r for r in results if r.status == CheckStatus.FAIL and "unexpected_columns" in r.check_name]
    assert len(failed) > 0


def test_negative_invalid_range(sample_train_df):
    """Setting hour=27 must result in FAIL."""
    sample_train_df.loc[0, "hour"] = 27
    results = validate_dataframe(sample_train_df, "sample_train", is_training=True)
    failed = [r for r in results if r.status == CheckStatus.FAIL and "range" in r.check_name]
    assert len(failed) > 0
    assert any(r.affected_rows >= 1 for r in failed)


def test_negative_broken_consistency(sample_train_df):
    """Breaking login_attempts == failed + successful must result in FAIL."""
    sample_train_df.loc[0, "failed_logins"] = 4
    sample_train_df.loc[0, "successful_logins"] = 2
    sample_train_df.loc[0, "login_attempts"] = 99
    results = validate_dataframe(sample_train_df, "sample_train", is_training=True)
    failed = [r for r in results if r.status == CheckStatus.FAIL and "login_consistency" in r.check_name]
    assert len(failed) > 0
    assert failed[0].affected_rows >= 1


def test_negative_invalid_training_label(sample_train_df):
    """Having label=1 in training set must result in FAIL."""
    sample_train_df.loc[0, "label"] = 1
    results = validate_dataframe(sample_train_df, "sample_train", is_training=True)
    failed = [r for r in results if r.status == CheckStatus.FAIL and "training_labels" in r.check_name]
    assert len(failed) > 0


def test_negative_missing_value(sample_train_df):
    """Inserting NaN / missing value must result in FAIL."""
    sample_train_df.loc[0, "user_role"] = None
    results = validate_dataframe(sample_train_df, "sample_train", is_training=True)
    failed = [r for r in results if r.status == CheckStatus.FAIL and "null" in r.check_name]
    assert len(failed) > 0


def test_negative_invalid_manifest(tmp_path):
    """Manifest with synthetic=False must result in FAIL."""
    manifest_data = {
        "seed": 20261008,
        "train_rows": 12000,
        "eval_rows": 4000,
        "training_policy": "normal_only",
        "evaluation_policy": "50_percent_normal_50_percent_synthetic_anomaly",
        "synthetic": False,
        "anomaly_types": ["brute_force"]
    }
    tmp_manifest = tmp_path / "dataset_manifest.json"
    with open(tmp_manifest, "w", encoding="utf-8") as f:
        json.dump(manifest_data, f)

    results = validate_manifest(tmp_manifest)
    failed = [r for r in results if r.status == CheckStatus.FAIL and "synthetic_flag" in r.check_name]
    assert len(failed) > 0


def test_negative_manifest_row_count_mismatch(tmp_path):
    """Manifest claiming wrong row count must result in FAIL."""
    manifest_data = {
        "seed": 20261008,
        "train_rows": 99999,
        "eval_rows": 4000,
        "training_policy": "normal_only",
        "evaluation_policy": "50_percent_normal_50_percent_synthetic_anomaly",
        "synthetic": True,
        "anomaly_types": ["brute_force"]
    }
    tmp_manifest = tmp_path / "dataset_manifest.json"
    with open(tmp_manifest, "w", encoding="utf-8") as f:
        json.dump(manifest_data, f)

    results = validate_manifest(tmp_manifest, train_path=TRAIN_FILE, eval_path=EVAL_FILE)
    failed = [r for r in results if r.status == CheckStatus.FAIL and "train_row_count" in r.check_name]
    assert len(failed) > 0


# =====================================================================
# 11. Generator reproducibility
# =====================================================================

def test_generator_reproducibility_in_temp_dir(tmp_path):
    """Verify that seed_dataset generator produces valid data matching the contract."""
    from scripts.seed_dataset import generate_dataset
    gen_dir = tmp_path / "generated_data"
    generate_dataset(output_dir=gen_dir, seed=42, train_rows=100, eval_rows=50, force=True)

    report = run_full_validation(gen_dir)
    assert report.overall_status == CheckStatus.PASS
    assert report.train_rows == 100
    assert report.eval_rows == 50
