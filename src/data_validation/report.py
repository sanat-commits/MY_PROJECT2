"""Validation report compilation and formatting.

Produces human-readable summary reports and structured report models
containing metrics, checks, distributions, and pass/fail diagnostics.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import json
import pandas as pd
from pydantic import BaseModel, Field

from src.data_validation.validators import (
    CheckStatus,
    ValidationCheckResult,
    validate_dataframe,
    validate_manifest,
)


class DatasetMetrics(BaseModel):
    name: str
    rows: int
    columns: int
    status: CheckStatus
    label_distribution: Dict[str, int] = Field(default_factory=dict)
    anomaly_distribution: Dict[str, int] = Field(default_factory=dict)
    missing_value_count: int = 0


class ValidationReport(BaseModel):
    overall_status: CheckStatus
    train_status: CheckStatus
    eval_status: CheckStatus
    manifest_status: CheckStatus
    synthetic_status: CheckStatus

    train_rows: int
    eval_rows: int
    train_metrics: Optional[DatasetMetrics] = None
    eval_metrics: Optional[DatasetMetrics] = None

    categories: Dict[str, CheckStatus] = Field(default_factory=dict)
    checks: List[ValidationCheckResult] = Field(default_factory=list)
    failures: List[ValidationCheckResult] = Field(default_factory=list)

    def format_text(self) -> str:
        """Render a formatted, user-facing validation report."""
        lines = [
            "Dataset Validation Report",
            "----------------------------------------",
            "",
            "Training dataset",
            f"Rows: {self.train_rows}",
            f"Status: {self.train_status.value}",
        ]
        if self.train_metrics:
            lines.append(f"Label distribution: {self.train_metrics.label_distribution}")

        lines.extend([
            "",
            "Evaluation dataset",
            f"Rows: {self.eval_rows}",
            f"Status: {self.eval_status.value}",
        ])
        if self.eval_metrics:
            lines.append(f"Label distribution: {self.eval_metrics.label_distribution}")
            lines.append(f"Anomaly types: {self.eval_metrics.anomaly_distribution}")

        lines.extend([
            "",
            "Detailed Checks",
            "----------------------------------------",
        ])
        for cat, stat in self.categories.items():
            lines.append(f"{cat}: {stat.value}")

        lines.extend([
            "",
            f"Overall: {self.overall_status.value}",
            "----------------------------------------",
        ])

        if self.failures:
            lines.extend([
                "",
                "FAILURES DETECTED:",
            ])
            for f in self.failures:
                aff = f" (affected rows: {f.affected_rows})" if f.affected_rows > 0 else ""
                lines.append(f" - [{f.check_name}]: {f.message}{aff}")

        return "\n".join(lines)


def run_full_validation(data_dir: Union[str, Path] = "./data") -> ValidationReport:
    """Run full Phase 1 validation suite on dataset directory and return report."""
    data_path = Path(data_dir)
    train_path = data_path / "security_windows_train_normal.csv"
    eval_path = data_path / "security_windows_eval_labeled.csv"
    manifest_path = data_path / "dataset_manifest.json"

    all_checks: List[ValidationCheckResult] = []

    # 1. Manifest
    manifest_checks = validate_manifest(manifest_path, train_path=train_path, eval_path=eval_path)
    all_checks.extend(manifest_checks)

    # 2. Train dataset
    train_metrics = None
    train_rows = 0
    if train_path.exists():
        try:
            train_df = pd.read_csv(train_path)
            train_rows = len(train_df)
            train_checks = validate_dataframe(train_df, "training_dataset", is_training=True)
            all_checks.extend(train_checks)
            train_has_fail = any(c.status == CheckStatus.FAIL for c in train_checks)
            train_metrics = DatasetMetrics(
                name="training_dataset",
                rows=train_rows,
                columns=len(train_df.columns),
                status=CheckStatus.FAIL if train_has_fail else CheckStatus.PASS,
                label_distribution={str(k): int(v) for k, v in train_df["label"].value_counts().items()} if "label" in train_df.columns else {},
                anomaly_distribution={str(k): int(v) for k, v in train_df["anomaly_type"].value_counts().items()} if "anomaly_type" in train_df.columns else {},
                missing_value_count=int(train_df.isnull().sum().sum()),
            )
        except Exception as e:
            all_checks.append(
                ValidationCheckResult(
                    check_name="training_csv_load",
                    status=CheckStatus.FAIL,
                    message=f"Failed to read training CSV: {e}",
                )
            )
    else:
        all_checks.append(
            ValidationCheckResult(
                check_name="training_file_existence",
                status=CheckStatus.FAIL,
                message=f"Training CSV missing: {train_path}",
            )
        )

    # 3. Eval dataset
    eval_metrics = None
    eval_rows = 0
    if eval_path.exists():
        try:
            eval_df = pd.read_csv(eval_path)
            eval_rows = len(eval_df)
            eval_checks = validate_dataframe(eval_df, "evaluation_dataset", is_training=False)
            all_checks.extend(eval_checks)
            eval_has_fail = any(c.status == CheckStatus.FAIL for c in eval_checks)
            eval_metrics = DatasetMetrics(
                name="evaluation_dataset",
                rows=eval_rows,
                columns=len(eval_df.columns),
                status=CheckStatus.FAIL if eval_has_fail else CheckStatus.PASS,
                label_distribution={str(k): int(v) for k, v in eval_df["label"].value_counts().items()} if "label" in eval_df.columns else {},
                anomaly_distribution={str(k): int(v) for k, v in eval_df["anomaly_type"].value_counts().items()} if "anomaly_type" in eval_df.columns else {},
                missing_value_count=int(eval_df.isnull().sum().sum()),
            )
        except Exception as e:
            all_checks.append(
                ValidationCheckResult(
                    check_name="eval_csv_load",
                    status=CheckStatus.FAIL,
                    message=f"Failed to read evaluation CSV: {e}",
                )
            )
    else:
        all_checks.append(
            ValidationCheckResult(
                check_name="eval_file_existence",
                status=CheckStatus.FAIL,
                message=f"Evaluation CSV missing: {eval_path}",
            )
        )

    # Categories breakdown
    def cat_status(filter_fn) -> CheckStatus:
        relevant = [c for c in all_checks if filter_fn(c.check_name)]
        if not relevant:
            return CheckStatus.PASS
        return CheckStatus.FAIL if any(c.status == CheckStatus.FAIL for c in relevant) else CheckStatus.PASS

    categories = {
        "Schema": cat_status(lambda n: "columns" in n),
        "Missing values": cat_status(lambda n: "null" in n or "empty" in n),
        "Ranges": cat_status(lambda n: "range" in n),
        "Consistency": cat_status(lambda n: "consistency" in n or "uniqueness" in n),
        "Labels": cat_status(lambda n: "label" in n or "anomaly_type" in n),
        "Manifest": cat_status(lambda n: "manifest" in n and "synthetic" not in n),
        "Synthetic flag": cat_status(lambda n: "synthetic" in n),
    }

    manifest_status = cat_status(lambda n: "manifest" in n)
    synthetic_status = cat_status(lambda n: "synthetic" in n)
    train_status = CheckStatus.FAIL if (train_metrics is None or train_metrics.status == CheckStatus.FAIL) else CheckStatus.PASS
    eval_status = CheckStatus.FAIL if (eval_metrics is None or eval_metrics.status == CheckStatus.FAIL) else CheckStatus.PASS

    failures = [c for c in all_checks if c.status == CheckStatus.FAIL]
    overall_status = CheckStatus.FAIL if failures else CheckStatus.PASS

    return ValidationReport(
        overall_status=overall_status,
        train_status=train_status,
        eval_status=eval_status,
        manifest_status=manifest_status,
        synthetic_status=synthetic_status,
        train_rows=train_rows,
        eval_rows=eval_rows,
        train_metrics=train_metrics,
        eval_metrics=eval_metrics,
        categories=categories,
        checks=all_checks,
        failures=failures,
    )
