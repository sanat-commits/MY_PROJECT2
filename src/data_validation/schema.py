"""Authoritative dataset schema and constraints specification.

Single source of truth for:
- Required column names and ordering
- Feature vs. metadata column separation
- Semantic data types
- Value ranges and allowed categories
- Manifest fields and policies
"""

from typing import Dict, List, Set, Union

# Exact required column list in order, matching docs/DATASET_SPEC.md
REQUIRED_COLUMNS: List[str] = [
    "window_id",
    "user_role",
    "host_type",
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
    "anomaly_type",
    "label",
]

# Non-feature metadata columns to exclude from ML model fitting
METADATA_COLUMNS: List[str] = [
    "window_id",
    "anomaly_type",
    "label",
]

# Numeric/behavioral feature columns for model training
FEATURE_COLUMNS: List[str] = [
    col for col in REQUIRED_COLUMNS if col not in METADATA_COLUMNS
]

# Allowed categorical values
ALLOWED_USER_ROLES: Set[str] = {
    "analyst",
    "employee",
    "developer",
    "admin",
    "service",
}

ALLOWED_HOST_TYPES: Set[str] = {
    "workstation",
    "laptop",
    "server",
}

ALLOWED_ANOMALY_TYPES: Set[str] = {
    "normal",
    "brute_force",
    "off_hours_admin_access",
    "unusual_external_activity",
    "data_exfiltration_like",
    "rare_process_burst",
}

# Semantic types expected for each column
COLUMN_SEMANTIC_TYPES: Dict[str, str] = {
    "window_id": "string",
    "user_role": "string",
    "host_type": "string",
    "hour": "integer",
    "day_of_week": "integer",
    "is_weekend": "integer",
    "failed_logins": "integer",
    "successful_logins": "integer",
    "login_attempts": "integer",
    "unique_source_ips": "integer",
    "new_source_ip_count": "integer",
    "privileged_actions": "integer",
    "file_access_count": "integer",
    "process_count": "integer",
    "network_connections": "integer",
    "external_connections": "integer",
    "bytes_out_mb": "float",
    "distinct_destinations": "integer",
    "rare_process_count": "integer",
    "after_hours": "integer",
    "anomaly_type": "string",
    "label": "integer",
}

# Range constraints: (min_inclusive, max_inclusive or None)
NUMERIC_RANGES: Dict[str, Dict[str, Union[int, float, None]]] = {
    "hour": {"min": 0, "max": 23},
    "day_of_week": {"min": 0, "max": 6},
    "is_weekend": {"min": 0, "max": 1},
    "failed_logins": {"min": 0, "max": None},
    "successful_logins": {"min": 0, "max": None},
    "login_attempts": {"min": 0, "max": None},
    "unique_source_ips": {"min": 1, "max": None},
    "new_source_ip_count": {"min": 0, "max": None},
    "privileged_actions": {"min": 0, "max": None},
    "file_access_count": {"min": 0, "max": None},
    "process_count": {"min": 0, "max": None},
    "network_connections": {"min": 0, "max": None},
    "external_connections": {"min": 0, "max": None},
    "bytes_out_mb": {"min": 0.0, "max": None},
    "distinct_destinations": {"min": 0, "max": None},
    "rare_process_count": {"min": 0, "max": None},
    "after_hours": {"min": 0, "max": 1},
    "label": {"min": 0, "max": 1},
}

# Manifest requirements
MANIFEST_REQUIRED_FIELDS: List[str] = [
    "seed",
    "train_rows",
    "eval_rows",
    "training_policy",
    "evaluation_policy",
    "synthetic",
    "anomaly_types",
]
