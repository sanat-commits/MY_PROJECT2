"""Phase 10 — ML Evaluation Script.

Executes the existing Phase 2 evaluation module against the labeled synthetic
evaluation dataset and records real precision/recall/F1/FPR metrics.

Usage:
    python scripts/evaluate_ml.py

Outputs:
    artifacts/evaluation/ml_metrics.json
"""

from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Ensure project root is on sys.path when run as a top-level script
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.ml.config import get_default_config
from src.ml.evaluation import evaluate_baseline


EVAL_OUTPUT_DIR = ROOT / "artifacts" / "evaluation"


def run_ml_evaluation() -> dict:
    """Run ML evaluation and return the evaluation result dict."""
    config = get_default_config()

    # Verify prerequisites
    errors: list[str] = []
    if not config.eval_path.exists():
        errors.append(f"Evaluation dataset missing: {config.eval_path}")
    if not config.model_artifact_path.exists():
        errors.append(f"Model artifact missing: {config.model_artifact_path}")
    if not config.preprocessor_artifact_path.exists():
        errors.append(f"Preprocessor artifact missing: {config.preprocessor_artifact_path}")

    if errors:
        result = {
            "status": "BLOCKED",
            "errors": errors,
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
        }
        _save_result(result)
        print("[BLOCKED] ML evaluation prerequisites not met:")
        for e in errors:
            print(f"  - {e}")
        return result

    # Run evaluation and time it
    t0 = time.perf_counter()
    try:
        metrics = evaluate_baseline(config)
        elapsed = round(time.perf_counter() - t0, 3)
    except Exception as exc:  # pragma: no cover
        elapsed = round(time.perf_counter() - t0, 3)
        result = {
            "status": "ERROR",
            "error": str(exc),
            "elapsed_seconds": elapsed,
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
        }
        _save_result(result)
        print(f"[ERROR] ML evaluation failed: {exc}")
        return result

    cm = metrics.get("classification_metrics", {})
    result = {
        "status": "PASS",
        "model": metrics.get("model"),
        "threshold_method": config.threshold_method,
        "threshold_percentile": config.threshold_percentile,
        "evaluation_dataset": metrics.get("evaluation_dataset"),
        "total_eval_rows": metrics.get("total_eval_rows"),
        "synthetic": True,
        "classification_metrics": cm,
        "confusion_matrix": metrics.get("confusion_matrix", {}),
        "per_anomaly_type_breakdown": metrics.get("per_anomaly_type_breakdown", {}),
        "elapsed_seconds": elapsed,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "notes": (
            "All data is synthetic. Metrics measure behaviour on a generated "
            "benchmark dataset, not on live network telemetry. "
            "An anomaly flag does not prove compromise."
        ),
    }

    _save_result(result)
    _print_summary(result)
    return result


def _save_result(result: dict) -> None:
    EVAL_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = EVAL_OUTPUT_DIR / "ml_metrics.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    print(f"[ML] Results saved to {out_path}")


def _print_summary(result: dict) -> None:
    cm = result.get("classification_metrics", {})
    print("\n=== ML Evaluation Summary ===")
    print(f"Status          : {result['status']}")
    print(f"Model           : {result.get('model')}")
    print(f"Precision       : {cm.get('precision')}")
    print(f"Recall          : {cm.get('recall')}")
    print(f"F1-Score        : {cm.get('f1')}")
    print(f"False Pos. Rate : {cm.get('false_positive_rate')}")
    print(f"ROC-AUC         : {cm.get('roc_auc')}")
    print(f"PR-AUC          : {cm.get('pr_auc')}")
    print(f"Elapsed         : {result.get('elapsed_seconds')}s")


if __name__ == "__main__":
    run_ml_evaluation()
