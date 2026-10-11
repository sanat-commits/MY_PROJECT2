"""Validation logic and typed check results.

Implements structural, semantic, range, consistency, and manifest validation.
Returns structured ValidationCheckResult instances distinguishing PASS and FAIL.
"""

from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import json
import pandas as pd
from pydantic import BaseModel, Field

from src.data_validation.schema import (
    REQUIRED_COLUMNS,
    ALLOWED_USER_ROLES,
    ALLOWED_HOST_TYPES,
    ALLOWED_ANOMALY_TYPES,
    NUMERIC_RANGES,
    COLUMN_SEMANTIC_TYPES,
    MANIFEST_REQUIRED_FIELDS,
)


class CheckStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"


class ValidationCheckResult(BaseModel):
    check_name: str
    status: CheckStatus
    message: str
    affected_rows: int = 0
    details: Optional[Dict[str, Any]] = None


def validate_manifest(
    manifest_path: Union[str, Path],
    train_path: Optional[Union[str, Path]] = None,
    eval_path: Optional[Union[str, Path]] = None,
) -> List[ValidationCheckResult]:
    """Validate dataset manifest existence, structure, synthetic status, and row counts."""
    results: List[ValidationCheckResult] = []
    path = Path(manifest_path)

    if not path.exists():
        results.append(
            ValidationCheckResult(
                check_name="manifest_existence",
                status=CheckStatus.FAIL,
                message=f"Manifest file not found: {path}",
            )
        )
        return results

    results.append(
        ValidationCheckResult(
            check_name="manifest_existence",
            status=CheckStatus.PASS,
            message="Manifest file exists.",
        )
    )

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        results.append(
            ValidationCheckResult(
                check_name="manifest_json_syntax",
                status=CheckStatus.FAIL,
                message=f"Failed to parse manifest JSON: {e}",
            )
        )
        return results

    # Required fields
    missing_fields = [k for k in MANIFEST_REQUIRED_FIELDS if k not in data]
    if missing_fields:
        results.append(
            ValidationCheckResult(
                check_name="manifest_required_fields",
                status=CheckStatus.FAIL,
                message=f"Manifest missing required fields: {missing_fields}",
            )
        )
    else:
        results.append(
            ValidationCheckResult(
                check_name="manifest_required_fields",
                status=CheckStatus.PASS,
                message="All required manifest fields present.",
            )
        )

    # Synthetic flag check
    if data.get("synthetic") is True:
        results.append(
            ValidationCheckResult(
                check_name="manifest_synthetic_flag",
                status=CheckStatus.PASS,
                message="Synthetic flag is explicitly True.",
            )
        )
    else:
        results.append(
            ValidationCheckResult(
                check_name="manifest_synthetic_flag",
                status=CheckStatus.FAIL,
                message=f"Synthetic flag must be True, got {data.get('synthetic')}.",
            )
        )

    # Training policy check
    if data.get("training_policy") == "normal_only":
        results.append(
            ValidationCheckResult(
                check_name="manifest_training_policy",
                status=CheckStatus.PASS,
                message="Training policy confirmed as normal_only.",
            )
        )
    else:
        results.append(
            ValidationCheckResult(
                check_name="manifest_training_policy",
                status=CheckStatus.FAIL,
                message=f"Expected training_policy 'normal_only', got {data.get('training_policy')}",
            )
        )

    # Validate against actual CSV counts if paths provided
    if train_path and Path(train_path).exists():
        try:
            train_df = pd.read_csv(train_path)
            actual_train_rows = len(train_df)
            expected_train = data.get("train_rows")
            if actual_train_rows == expected_train:
                results.append(
                    ValidationCheckResult(
                        check_name="manifest_train_row_count",
                        status=CheckStatus.PASS,
                        message=f"Train rows match manifest ({actual_train_rows}).",
                    )
                )
            else:
                results.append(
                    ValidationCheckResult(
                        check_name="manifest_train_row_count",
                        status=CheckStatus.FAIL,
                        message=f"Train row count mismatch: manifest={expected_train}, actual={actual_train_rows}.",
                    )
                )
        except Exception as e:
            results.append(
                ValidationCheckResult(
                    check_name="manifest_train_row_count",
                    status=CheckStatus.FAIL,
                    message=f"Could not read train CSV for manifest check: {e}",
                )
            )

    if eval_path and Path(eval_path).exists():
        try:
            eval_df = pd.read_csv(eval_path)
            actual_eval_rows = len(eval_df)
            expected_eval = data.get("eval_rows")
            if actual_eval_rows == expected_eval:
                results.append(
                    ValidationCheckResult(
                        check_name="manifest_eval_row_count",
                        status=CheckStatus.PASS,
                        message=f"Eval rows match manifest ({actual_eval_rows}).",
                    )
                )
            else:
                results.append(
                    ValidationCheckResult(
                        check_name="manifest_eval_row_count",
                        status=CheckStatus.FAIL,
                        message=f"Eval row count mismatch: manifest={expected_eval}, actual={actual_eval_rows}.",
                    )
                )
        except Exception as e:
            results.append(
                ValidationCheckResult(
                    check_name="manifest_eval_row_count",
                    status=CheckStatus.FAIL,
                    message=f"Could not read eval CSV for manifest check: {e}",
                )
            )

    return results


def validate_dataframe(
    df: pd.DataFrame,
    dataset_name: str,
    is_training: bool,
) -> List[ValidationCheckResult]:
    """Validate a loaded DataFrame for schema, types, bounds, and business rules."""
    results: List[ValidationCheckResult] = []

    # 1. Non-empty check
    if len(df) == 0:
        results.append(
            ValidationCheckResult(
                check_name=f"{dataset_name}_non_empty",
                status=CheckStatus.FAIL,
                message=f"{dataset_name} is empty.",
            )
        )
        return results
    results.append(
        ValidationCheckResult(
            check_name=f"{dataset_name}_non_empty",
            status=CheckStatus.PASS,
            message=f"{dataset_name} contains {len(df)} rows.",
        )
    )

    # 2. Schema: missing & unexpected columns
    actual_cols = list(df.columns)
    missing_cols = [c for c in REQUIRED_COLUMNS if c not in actual_cols]
    extra_cols = [c for c in actual_cols if c not in REQUIRED_COLUMNS]

    if missing_cols:
        results.append(
            ValidationCheckResult(
                check_name=f"{dataset_name}_missing_columns",
                status=CheckStatus.FAIL,
                message=f"Missing required columns in {dataset_name}: {missing_cols}",
            )
        )
    else:
        results.append(
            ValidationCheckResult(
                check_name=f"{dataset_name}_missing_columns",
                status=CheckStatus.PASS,
                message=f"All required columns present in {dataset_name}.",
            )
        )

    if extra_cols:
        results.append(
            ValidationCheckResult(
                check_name=f"{dataset_name}_unexpected_columns",
                status=CheckStatus.FAIL,
                message=f"Unexpected columns found in {dataset_name}: {extra_cols}",
            )
        )
    else:
        results.append(
            ValidationCheckResult(
                check_name=f"{dataset_name}_unexpected_columns",
                status=CheckStatus.PASS,
                message=f"No unexpected columns in {dataset_name}.",
            )
        )

    # If columns are missing, we cannot reliably continue column-level validation
    if missing_cols:
        return results

    # 3. Missing / Null / Empty checks
    null_counts = df.isnull().sum()
    cols_with_nulls = null_counts[null_counts > 0].to_dict()
    if cols_with_nulls:
        total_null_rows = int(df.isnull().any(axis=1).sum())
        results.append(
            ValidationCheckResult(
                check_name=f"{dataset_name}_null_values",
                status=CheckStatus.FAIL,
                message=f"Null values detected in {dataset_name}: {cols_with_nulls}",
                affected_rows=total_null_rows,
                details=cols_with_nulls,
            )
        )
    else:
        results.append(
            ValidationCheckResult(
                check_name=f"{dataset_name}_null_values",
                status=CheckStatus.PASS,
                message=f"No null values in {dataset_name}.",
            )
        )

    # Empty string checks for string columns
    str_cols = [c for c, t in COLUMN_SEMANTIC_TYPES.items() if t == "string"]
    empty_str_issues = {}
    for col in str_cols:
        if col in df.columns:
            empty_mask = df[col].astype(str).str.strip() == ""
            cnt = int(empty_mask.sum())
            if cnt > 0:
                empty_str_issues[col] = cnt
    if empty_str_issues:
        results.append(
            ValidationCheckResult(
                check_name=f"{dataset_name}_empty_strings",
                status=CheckStatus.FAIL,
                message=f"Empty or whitespace string values in {dataset_name}: {empty_str_issues}",
                affected_rows=sum(empty_str_issues.values()),
                details=empty_str_issues,
            )
        )
    else:
        results.append(
            ValidationCheckResult(
                check_name=f"{dataset_name}_empty_strings",
                status=CheckStatus.PASS,
                message=f"No empty string values in {dataset_name}.",
            )
        )

    # 4. Semantic types verification
    type_errors = {}
    for col, expected_type in COLUMN_SEMANTIC_TYPES.items():
        if col not in df.columns:
            continue
        if expected_type == "integer":
            # Must be convertible to numeric without NaNs and have whole integer values
            numeric_s = pd.to_numeric(df[col], errors="coerce")
            invalid_mask = numeric_s.isna() | (numeric_s % 1 != 0)
            bad_cnt = int(invalid_mask.sum())
            if bad_cnt > 0:
                type_errors[col] = f"{bad_cnt} non-integer values"
        elif expected_type == "float":
            numeric_s = pd.to_numeric(df[col], errors="coerce")
            bad_cnt = int(numeric_s.isna().sum())
            if bad_cnt > 0:
                type_errors[col] = f"{bad_cnt} non-float values"

    if type_errors:
        results.append(
            ValidationCheckResult(
                check_name=f"{dataset_name}_semantic_types",
                status=CheckStatus.FAIL,
                message=f"Type parsing errors in {dataset_name}: {type_errors}",
                details=type_errors,
            )
        )
    else:
        results.append(
            ValidationCheckResult(
                check_name=f"{dataset_name}_semantic_types",
                status=CheckStatus.PASS,
                message=f"All columns in {dataset_name} match expected semantic types.",
            )
        )

    # 5. Range and bounds verification
    range_failures = {}
    for col, bounds in NUMERIC_RANGES.items():
        if col not in df.columns:
            continue
        col_s = pd.to_numeric(df[col], errors="coerce")
        min_val = bounds["min"]
        max_val = bounds["max"]
        cond = pd.Series(True, index=df.index)
        if min_val is not None:
            cond = cond & (col_s >= min_val)
        if max_val is not None:
            cond = cond & (col_s <= max_val)

        violations = int((~cond).sum())
        if violations > 0:
            range_failures[col] = {
                "violations": violations,
                "min_expected": min_val,
                "max_expected": max_val,
                "actual_min": float(col_s.min()) if not col_s.empty else None,
                "actual_max": float(col_s.max()) if not col_s.empty else None,
            }

    if range_failures:
        total_violating_rows = sum(v["violations"] for v in range_failures.values())
        results.append(
            ValidationCheckResult(
                check_name=f"{dataset_name}_numeric_ranges",
                status=CheckStatus.FAIL,
                message=f"Range violations detected in {dataset_name}: {list(range_failures.keys())}",
                affected_rows=total_violating_rows,
                details=range_failures,
            )
        )
    else:
        results.append(
            ValidationCheckResult(
                check_name=f"{dataset_name}_numeric_ranges",
                status=CheckStatus.PASS,
                message=f"All numeric columns in {dataset_name} are within documented ranges.",
            )
        )

    # 6. Categorical allowed sets
    invalid_roles = set(df["user_role"].dropna().unique()) - ALLOWED_USER_ROLES
    if invalid_roles:
        results.append(
            ValidationCheckResult(
                check_name=f"{dataset_name}_user_roles",
                status=CheckStatus.FAIL,
                message=f"Disallowed user roles in {dataset_name}: {invalid_roles}",
                affected_rows=int(df["user_role"].isin(invalid_roles).sum()),
            )
        )
    else:
        results.append(
            ValidationCheckResult(
                check_name=f"{dataset_name}_user_roles",
                status=CheckStatus.PASS,
                message=f"User roles in {dataset_name} belong to approved categories.",
            )
        )

    invalid_hosts = set(df["host_type"].dropna().unique()) - ALLOWED_HOST_TYPES
    if invalid_hosts:
        results.append(
            ValidationCheckResult(
                check_name=f"{dataset_name}_host_types",
                status=CheckStatus.FAIL,
                message=f"Disallowed host types in {dataset_name}: {invalid_hosts}",
                affected_rows=int(df["host_type"].isin(invalid_hosts).sum()),
            )
        )
    else:
        results.append(
            ValidationCheckResult(
                check_name=f"{dataset_name}_host_types",
                status=CheckStatus.PASS,
                message=f"Host types in {dataset_name} belong to approved categories.",
            )
        )

    # 7. Internal consistency
    # login_attempts == failed_logins + successful_logins
    expected_attempts = df["failed_logins"] + df["successful_logins"]
    mismatched_logins = df["login_attempts"] != expected_attempts
    login_mismatch_cnt = int(mismatched_logins.sum())
    if login_mismatch_cnt > 0:
        results.append(
            ValidationCheckResult(
                check_name=f"{dataset_name}_login_consistency",
                status=CheckStatus.FAIL,
                message=f"Login attempts mismatch (failed + successful != attempts) in {login_mismatch_cnt} rows.",
                affected_rows=login_mismatch_cnt,
            )
        )
    else:
        results.append(
            ValidationCheckResult(
                check_name=f"{dataset_name}_login_consistency",
                status=CheckStatus.PASS,
                message=f"Login attempts consistency verified for all rows in {dataset_name}.",
            )
        )

    # is_weekend consistency: day_of_week in (5, 6)
    expected_weekend = df["day_of_week"].isin([5, 6]).astype(int)
    weekend_mismatches = df["is_weekend"] != expected_weekend
    weekend_mismatch_cnt = int(weekend_mismatches.sum())
    if weekend_mismatch_cnt > 0:
        results.append(
            ValidationCheckResult(
                check_name=f"{dataset_name}_weekend_consistency",
                status=CheckStatus.FAIL,
                message=f"is_weekend inconsistency with day_of_week in {weekend_mismatch_cnt} rows.",
                affected_rows=weekend_mismatch_cnt,
            )
        )
    else:
        results.append(
            ValidationCheckResult(
                check_name=f"{dataset_name}_weekend_consistency",
                status=CheckStatus.PASS,
                message=f"Weekend indicator consistency verified for all rows in {dataset_name}.",
            )
        )

    # window_id uniqueness
    dup_windows = int(df["window_id"].duplicated().sum())
    if dup_windows > 0:
        results.append(
            ValidationCheckResult(
                check_name=f"{dataset_name}_window_id_uniqueness",
                status=CheckStatus.FAIL,
                message=f"Duplicate window_id values found in {dataset_name}: {dup_windows}",
                affected_rows=dup_windows,
            )
        )
    else:
        results.append(
            ValidationCheckResult(
                check_name=f"{dataset_name}_window_id_uniqueness",
                status=CheckStatus.PASS,
                message=f"All window_id values are unique in {dataset_name}.",
            )
        )

    # 8. Training vs Evaluation specific rules
    if is_training:
        # Training set rules: label must be only 0, anomaly_type must be only "normal"
        labels = set(df["label"].unique())
        if labels != {0}:
            bad_label_cnt = int((df["label"] != 0).sum())
            results.append(
                ValidationCheckResult(
                    check_name=f"{dataset_name}_training_labels",
                    status=CheckStatus.FAIL,
                    message=f"Training set must contain only normal label 0; found labels: {labels}",
                    affected_rows=bad_label_cnt,
                )
            )
        else:
            results.append(
                ValidationCheckResult(
                    check_name=f"{dataset_name}_training_labels",
                    status=CheckStatus.PASS,
                    message="Training set contains exclusively normal label 0.",
                )
            )

        anomaly_types = set(df["anomaly_type"].unique())
        if anomaly_types != {"normal"}:
            bad_anom_cnt = int((df["anomaly_type"] != "normal").sum())
            results.append(
                ValidationCheckResult(
                    check_name=f"{dataset_name}_training_anomaly_types",
                    status=CheckStatus.FAIL,
                    message=f"Training set anomaly_type must be only 'normal'; found: {anomaly_types}",
                    affected_rows=bad_anom_cnt,
                )
            )
        else:
            results.append(
                ValidationCheckResult(
                    check_name=f"{dataset_name}_training_anomaly_types",
                    status=CheckStatus.PASS,
                    message="Training set anomaly_type is exclusively 'normal'.",
                )
            )
    else:
        # Evaluation set rules: must contain both 0 and 1; valid anomaly types
        labels = set(df["label"].unique())
        if labels != {0, 1}:
            results.append(
                ValidationCheckResult(
                    check_name=f"{dataset_name}_eval_labels",
                    status=CheckStatus.FAIL,
                    message=f"Evaluation set must contain both labels 0 and 1; found: {labels}",
                )
            )
        else:
            results.append(
                ValidationCheckResult(
                    check_name=f"{dataset_name}_eval_labels",
                    status=CheckStatus.PASS,
                    message="Evaluation set contains both normal (0) and anomaly (1) labels.",
                )
            )

        eval_anomaly_types = set(df["anomaly_type"].unique())
        invalid_anoms = eval_anomaly_types - ALLOWED_ANOMALY_TYPES
        if invalid_anoms:
            bad_cnt = int(df["anomaly_type"].isin(invalid_anoms).sum())
            results.append(
                ValidationCheckResult(
                    check_name=f"{dataset_name}_eval_anomaly_types",
                    status=CheckStatus.FAIL,
                    message=f"Disallowed anomaly types in evaluation set: {invalid_anoms}",
                    affected_rows=bad_cnt,
                )
            )
        else:
            results.append(
                ValidationCheckResult(
                    check_name=f"{dataset_name}_eval_anomaly_types",
                    status=CheckStatus.PASS,
                    message=f"Evaluation set contains valid anomaly types: {eval_anomaly_types}",
                )
            )

    return results


def validate_dataset_file(
    file_path: Union[str, Path],
    is_training: bool,
) -> List[ValidationCheckResult]:
    """Validate a CSV dataset file directly from path."""
    path = Path(file_path)
    dataset_name = path.stem

    if not path.exists():
        return [
            ValidationCheckResult(
                check_name=f"{dataset_name}_existence",
                status=CheckStatus.FAIL,
                message=f"File not found: {path}",
            )
        ]

    try:
        df = pd.read_csv(path)
    except Exception as e:
        return [
            ValidationCheckResult(
                check_name=f"{dataset_name}_csv_parse",
                status=CheckStatus.FAIL,
                message=f"Failed to read CSV from {path}: {e}",
            )
        ]

    results = [
        ValidationCheckResult(
            check_name=f"{dataset_name}_existence",
            status=CheckStatus.PASS,
            message=f"Dataset file exists: {path.name}",
        )
    ]
    results.extend(validate_dataframe(df, dataset_name, is_training=is_training))
    return results
