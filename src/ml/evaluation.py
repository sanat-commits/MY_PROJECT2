"""Evaluation module for Baseline Isolation Forest Anomaly Detection.

Measures precision, recall, F1, confusion matrix, ROC-AUC, PR-AUC, and per-anomaly
breakdown on synthetic evaluation data. Saves results to metrics.json.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
import json
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from src.ml.config import MLConfig, get_default_config
from src.ml.inference import AnomalyDetector


def evaluate_baseline(config: Optional[MLConfig] = None) -> Dict[str, Any]:
    """Execute evaluation against labeled evaluation dataset and generate metrics.json."""
    if config is None:
        config = get_default_config()

    print("==================================================")
    print("Executing Phase 2 Evaluation")
    print("==================================================")
    print(f"Evaluation dataset: {config.eval_path}")
    print(f"Artifact directory: {config.artifact_dir}")

    if not config.eval_path.exists():
        raise FileNotFoundError(f"Evaluation dataset missing at {config.eval_path}")

    # 1. Load evaluation dataset
    eval_df = pd.read_csv(config.eval_path)
    if eval_df.empty:
        raise ValueError(f"Evaluation dataset is empty: {config.eval_path}")

    if "label" not in eval_df.columns:
        raise ValueError(f"Evaluation dataset missing required 'label' column: {config.eval_path}")

    y_true = eval_df["label"].to_numpy(dtype=int)

    # 2. Run inference using saved artifacts
    detector = AnomalyDetector.load(config.artifact_dir)
    pred_df = detector.predict(eval_df)

    y_pred = pred_df["is_anomaly"].to_numpy(dtype=int)
    anomaly_scores = pred_df["anomaly_score"].to_numpy(dtype=float)

    # 3. Calculate metrics
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    acc = float(accuracy_score(y_true, y_pred))

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()

    # Ranking metrics using continuous anomaly scores
    try:
        roc_auc = float(roc_auc_score(y_true, anomaly_scores))
    except Exception:
        roc_auc = None

    try:
        pr_auc = float(average_precision_score(y_true, anomaly_scores))
    except Exception:
        pr_auc = None

    # False positive rate on normal evaluation rows
    normal_count = int(tn + fp)
    fpr = float(fp / normal_count) if normal_count > 0 else 0.0

    # 4. Breakdown by anomaly type if available
    per_type_metrics = {}
    if "anomaly_type" in eval_df.columns:
        for atype in eval_df["anomaly_type"].unique():
            subset_mask = eval_df["anomaly_type"] == atype
            sub_true = y_true[subset_mask]
            sub_pred = y_pred[subset_mask]
            sub_total = int(len(sub_true))
            sub_flagged = int(np.sum(sub_pred))
            if atype == "normal":
                per_type_metrics[atype] = {
                    "total_rows": sub_total,
                    "false_positives": sub_flagged,
                    "false_positive_rate": round(float(sub_flagged / sub_total), 4) if sub_total > 0 else 0.0,
                }
            else:
                per_type_metrics[atype] = {
                    "total_rows": sub_total,
                    "detected_anomalies": sub_flagged,
                    "recall": round(float(sub_flagged / sub_total), 4) if sub_total > 0 else 0.0,
                }

    metrics_payload = {
        "model": "IsolationForest",
        "threshold": float(detector.threshold),
        "evaluation_dataset": str(config.eval_path.name),
        "total_eval_rows": len(eval_df),
        "synthetic": True,
        "classification_metrics": {
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
            "accuracy": round(acc, 4),
            "false_positive_rate": round(fpr, 4),
            "roc_auc": round(roc_auc, 4) if roc_auc is not None else None,
            "pr_auc": round(pr_auc, 4) if pr_auc is not None else None,
        },
        "confusion_matrix": {
            "true_positives": int(tp),
            "false_positives": int(fp),
            "true_negatives": int(tn),
            "false_negatives": int(fn),
        },
        "per_anomaly_type_breakdown": per_type_metrics,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    # 5. Save metrics.json
    config.artifact_dir.mkdir(parents=True, exist_ok=True)
    with open(config.metrics_artifact_path, "w", encoding="utf-8") as f:
        json.dump(metrics_payload, f, indent=2)

    # 6. Print formatted report
    print("\nEvaluation Results:")
    print("--------------------------------------------------")
    print(f"Total Rows:      {len(eval_df)}")
    print(f"Threshold:       {detector.threshold:.6f}")
    print(f"Precision:       {prec:.4f}")
    print(f"Recall:          {rec:.4f}")
    print(f"F1-Score:        {f1:.4f}")
    print(f"Accuracy:        {acc:.4f}")
    print(f"False Pos. Rate: {fpr:.4f}")
    if roc_auc is not None:
        print(f"ROC-AUC:         {roc_auc:.4f}")
    if pr_auc is not None:
        print(f"PR-AUC:          {pr_auc:.4f}")
    print(f"Confusion Matrix: TP={tp}, FP={fp}, FN={fn}, TN={tn}")
    print("--------------------------------------------------")
    print(f"Metrics saved to {config.metrics_artifact_path}")

    return metrics_payload


def main():
    config = get_default_config()
    evaluate_baseline(config)


if __name__ == "__main__":
    main()
