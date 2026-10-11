"""Authoritative feature definition and schema validation for ML baseline.

Specifies behavioral numeric features, exclusion rationale, and schema verification.
"""

from typing import Dict, List, Optional
import numpy as np
import pandas as pd

# The 17 numeric behavioral features selected for the baseline Isolation Forest
NUMERIC_BEHAVIORAL_FEATURES: List[str] = [
    "hour",
    "day_of_week",
    "is_weekend",
    "failed_logins",
    "successful_logins",
    "login_attempts",
    "unique_source_ips",
    "new_source_ip_count",
    "privileged_actions",
    "file_access_count",
    "process_count",
    "network_connections",
    "external_connections",
    "bytes_out_mb",
    "distinct_destinations",
    "rare_process_count",
    "after_hours",
]

# Excluded columns and justification
EXCLUDED_COLUMNS: Dict[str, str] = {
    "window_id": "Identifier/metadata only; contains no behavioral signal.",
    "label": "Supervised ground truth; using it during unsupervised training causes target leakage.",
    "anomaly_type": "Synthetic label metadata; using it causes direct target leakage.",
    "user_role": "Categorical string; arbitrary integer encoding introduces artificial numerical ordering.",
    "host_type": "Categorical string; arbitrary integer encoding introduces artificial numerical ordering.",
}

# Feature rationale
FEATURE_RATIONALE: Dict[str, str] = {
    "hour": "Captures temporal activity cycles and off-peak operating patterns.",
    "day_of_week": "Captures weekly recurring workload rhythms.",
    "is_weekend": "Distinguishes standard working days from weekend activity.",
    "failed_logins": "Key indicator of authentication stress or credential attacks.",
    "successful_logins": "Baseline authentication volume.",
    "login_attempts": "Total authentication intensity in the window.",
    "unique_source_ips": "Detects distributed or multi-source connection origins.",
    "new_source_ip_count": "Flags access originating from previously unseen source IPs.",
    "privileged_actions": "Monitors elevated/administrative executions.",
    "file_access_count": "Tracks bulk or anomalous data access behavior.",
    "process_count": "Monitors local execution intensity.",
    "network_connections": "Overall outbound/inbound network traffic intensity.",
    "external_connections": "Outbound perimeter network connections.",
    "bytes_out_mb": "Data volume egress for identifying exfiltration-like behavior.",
    "distinct_destinations": "Network diversity of connection targets.",
    "rare_process_count": "Frequency of uncommon/anomalous binary executions.",
    "after_hours": "Flags activity outside approved operational business hours.",
}


def validate_feature_schema(
    df: pd.DataFrame,
    expected_features: Optional[List[str]] = None,
) -> None:
    """Validate that input DataFrame contains expected numeric features with proper types.

    Raises:
        ValueError: If features are missing, extra unexpected features are present,
                    types cannot be parsed as numeric, or null values exist.
    """
    if expected_features is None:
        expected_features = NUMERIC_BEHAVIORAL_FEATURES

    if df.empty:
        raise ValueError("Input DataFrame is empty.")

    missing = [f for f in expected_features if f not in df.columns]
    if missing:
        raise ValueError(f"Missing required ML features: {missing}")

    # Check for null / NaN in required features
    null_counts = df[expected_features].isnull().sum()
    cols_with_nulls = null_counts[null_counts > 0].to_dict()
    if cols_with_nulls:
        raise ValueError(f"Features contain null/NaN values: {cols_with_nulls}")

    # Verify numeric parseability
    for col in expected_features:
        if not np.issubdtype(df[col].dtype, np.number):
            # Attempt numeric conversion check
            converted = pd.to_numeric(df[col], errors="coerce")
            if converted.isna().any():
                raise ValueError(
                    f"Feature '{col}' contains non-numeric values that cannot be parsed."
                )
