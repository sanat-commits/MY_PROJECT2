"""Deterministic generator for synthetic security-log anomaly datasets.

Generates:
- security_windows_train_normal.csv (12,000 normal-only rows)
- security_windows_eval_labeled.csv (4,000 rows: 2,000 normal, 2,000 anomalies)
- dataset_manifest.json

Safeguard:
Does NOT overwrite existing seeded datasets unless explicitly passed --force.
Supports --output-dir for temporary generation / reproducibility testing.
"""

import argparse
import json
from pathlib import Path
import random
import sys
from typing import Dict, List

# Ensure project root is in sys.path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.data_validation.schema import REQUIRED_COLUMNS

DEFAULT_SEED = 20261008
ROLES = ["analyst", "employee", "developer", "admin", "service"]
HOSTS = ["workstation", "laptop", "server"]
ANOMALY_TYPES = [
    "brute_force",
    "off_hours_admin_access",
    "unusual_external_activity",
    "data_exfiltration_like",
    "rare_process_burst",
]


def generate_window(
    window_id: str,
    rng: random.Random,
    anomaly_type: str = "normal",
) -> Dict[str, object]:
    user_role = rng.choice(ROLES)
    host_type = rng.choice(HOSTS)
    day_of_week = rng.randint(0, 6)
    is_weekend = 1 if day_of_week in (5, 6) else 0

    if anomaly_type == "off_hours_admin_access":
        hour = rng.choice([0, 1, 2, 3, 4, 22, 23])
        user_role = "admin"
        after_hours = 1
    else:
        hour = rng.randint(0, 23)
        after_hours = 1 if (is_weekend == 1 or hour < 7 or hour >= 20) else 0

    # Normal baselines
    failed_logins = rng.randint(0, 2)
    successful_logins = rng.randint(1, 5)
    unique_source_ips = rng.randint(1, 2)
    new_source_ip_count = rng.randint(0, 1) if rng.random() < 0.1 else 0
    privileged_actions = rng.randint(0, 2) if user_role == "admin" else 0
    file_access_count = rng.randint(5, 50)
    process_count = rng.randint(20, 80)
    network_connections = rng.randint(10, 50)
    external_connections = rng.randint(0, 15)
    bytes_out_mb = round(rng.uniform(1.0, 50.0), 3)
    distinct_destinations = rng.randint(1, 20)
    rare_process_count = 1 if rng.random() < 0.05 else 0
    label = 0

    # Inject anomaly signatures
    if anomaly_type == "brute_force":
        label = 1
        failed_logins = rng.randint(25, 80)
        successful_logins = rng.randint(0, 2)
        unique_source_ips = rng.randint(2, 5)
    elif anomaly_type == "off_hours_admin_access":
        label = 1
        privileged_actions = rng.randint(4, 12)
        file_access_count = rng.randint(40, 120)
    elif anomaly_type == "unusual_external_activity":
        label = 1
        external_connections = rng.randint(40, 90)
        distinct_destinations = rng.randint(30, 60)
        new_source_ip_count = 1
    elif anomaly_type == "data_exfiltration_like":
        label = 1
        file_access_count = rng.randint(500, 1500)
        bytes_out_mb = round(rng.uniform(1000.0, 9999.0), 3)
        external_connections = rng.randint(30, 80)
    elif anomaly_type == "rare_process_burst":
        label = 1
        rare_process_count = rng.randint(10, 30)
        process_count = rng.randint(200, 500)

    login_attempts = failed_logins + successful_logins

    row = {
        "window_id": window_id,
        "user_role": user_role,
        "host_type": host_type,
        "hour": hour,
        "day_of_week": day_of_week,
        "is_weekend": is_weekend,
        "failed_logins": failed_logins,
        "successful_logins": successful_logins,
        "login_attempts": login_attempts,
        "unique_source_ips": unique_source_ips,
        "new_source_ip_count": new_source_ip_count,
        "privileged_actions": privileged_actions,
        "file_access_count": file_access_count,
        "process_count": process_count,
        "network_connections": network_connections,
        "external_connections": external_connections,
        "bytes_out_mb": bytes_out_mb,
        "distinct_destinations": distinct_destinations,
        "rare_process_count": rare_process_count,
        "after_hours": after_hours,
        "anomaly_type": anomaly_type,
        "label": label,
    }
    return row


def write_csv(path: Path, rows: List[Dict[str, object]]) -> None:
    import csv
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=REQUIRED_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def generate_dataset(
    output_dir: Path,
    seed: int = DEFAULT_SEED,
    train_rows: int = 12000,
    eval_rows: int = 4000,
    force: bool = False,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    train_path = output_dir / "security_windows_train_normal.csv"
    eval_path = output_dir / "security_windows_eval_labeled.csv"
    manifest_path = output_dir / "dataset_manifest.json"

    if (train_path.exists() or eval_path.exists()) and not force:
        print(f"Dataset already exists in {output_dir}. Pass --force to regenerate.")
        return

    rng = random.Random(seed)

    # 1. Training set: normal only
    train_data = [
        generate_window(f"win_train_{i:06d}", rng, anomaly_type="normal")
        for i in range(train_rows)
    ]
    write_csv(train_path, train_data)

    # 2. Evaluation set: 50% normal, 50% anomaly
    eval_normal_count = eval_rows // 2
    eval_anomaly_count = eval_rows - eval_normal_count
    eval_data = [
        generate_window(f"win_eval_norm_{i:06d}", rng, anomaly_type="normal")
        for i in range(eval_normal_count)
    ]

    per_anomaly = eval_anomaly_count // len(ANOMALY_TYPES)
    for idx, atype in enumerate(ANOMALY_TYPES):
        count = per_anomaly if idx < len(ANOMALY_TYPES) - 1 else eval_anomaly_count - per_anomaly * (len(ANOMALY_TYPES) - 1)
        for i in range(count):
            eval_data.append(generate_window(f"win_eval_{atype}_{i:06d}", rng, anomaly_type=atype))

    rng.shuffle(eval_data)
    write_csv(eval_path, eval_data)

    # 3. Manifest
    manifest = {
        "seed": seed,
        "train_rows": train_rows,
        "eval_rows": eval_rows,
        "training_policy": "normal_only",
        "evaluation_policy": "50_percent_normal_50_percent_synthetic_anomaly",
        "synthetic": True,
        "anomaly_types": ANOMALY_TYPES,
    }
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"Generated {train_rows} train rows and {eval_rows} eval rows in {output_dir}.")


def main():
    parser = argparse.ArgumentParser(description="Deterministic generator for synthetic security log data.")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "data", help="Target output directory")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED, help="Random seed for reproducibility")
    parser.add_argument("--train-rows", type=int, default=12000, help="Number of training rows")
    parser.add_argument("--eval-rows", type=int, default=4000, help="Number of evaluation rows")
    parser.add_argument("--force", action="store_true", help="Overwrite existing dataset")

    args = parser.parse_args()
    generate_dataset(
        output_dir=args.output_dir,
        seed=args.seed,
        train_rows=args.train_rows,
        eval_rows=args.eval_rows,
        force=args.force,
    )


if __name__ == "__main__":
    main()
