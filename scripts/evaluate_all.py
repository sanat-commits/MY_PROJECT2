"""Phase 10 — Consolidated Evaluation Runner.

Runs all sub-evaluations (ML, RAG, Structured Output, Agent, API) in sequence
and produces a consolidated JSON summary and a human-readable Markdown report.

Usage:
    # Run all evaluations (API probe skipped if backend not running)
    python scripts/evaluate_all.py

    # Include API evaluation (requires live backend)
    python scripts/evaluate_all.py --api --api-base-url http://127.0.0.1:8000

    # Run a specific subset
    python scripts/evaluate_all.py --only ml rag

Outputs:
    artifacts/evaluation/evaluation_summary.json
    artifacts/evaluation/EVALUATION_REPORT.md
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

EVAL_OUTPUT_DIR = ROOT / "artifacts" / "evaluation"


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Phase 10 consolidated evaluation.")
    parser.add_argument(
        "--only",
        nargs="+",
        choices=["ml", "rag", "structured_output", "agent", "api"],
        default=None,
        help="Only run the specified sub-evaluations.",
    )
    parser.add_argument(
        "--api",
        action="store_true",
        default=False,
        help="Include API evaluation (requires live backend).",
    )
    parser.add_argument(
        "--api-base-url",
        default="http://127.0.0.1:8000",
        help="Backend base URL for API evaluation.",
    )
    args = parser.parse_args()

    run_subset = set(args.only) if args.only else {"ml", "rag", "structured_output", "agent"}
    if args.api:
        run_subset.add("api")

    EVAL_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print("Phase 10 — Consolidated Evaluation")
    print(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
    print(f"Running:   {', '.join(sorted(run_subset))}")
    print("=" * 60)

    results: dict[str, Any] = {}
    t_global = time.perf_counter()

    # --- ML Evaluation ---
    if "ml" in run_subset:
        print("\n[1/5] Running ML evaluation...")
        from scripts.evaluate_ml import run_ml_evaluation
        results["ml"] = run_ml_evaluation()

    # --- RAG Evaluation ---
    if "rag" in run_subset:
        print("\n[2/5] Running RAG evaluation...")
        from scripts.evaluate_rag import run_rag_evaluation
        results["rag"] = run_rag_evaluation()

    # --- Structured Output Evaluation ---
    if "structured_output" in run_subset:
        print("\n[3/5] Running structured output validation evaluation...")
        from scripts.evaluate_structured_output import run_structured_output_evaluation
        results["structured_output"] = run_structured_output_evaluation()

    # --- Agent Evaluation ---
    if "agent" in run_subset:
        print("\n[4/5] Running agent reliability evaluation...")
        from scripts.evaluate_agent import run_agent_evaluation
        results["agent"] = run_agent_evaluation()

    # --- API Evaluation ---
    if "api" in run_subset:
        print("\n[5/5] Running API/endpoint evaluation...")
        from scripts.evaluate_api import run_api_evaluation
        results["api"] = run_api_evaluation(base_url=args.api_base_url)

    global_elapsed = round(time.perf_counter() - t_global, 2)

    # Build summary
    summary = {
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": global_elapsed,
        "sub_evaluations": {k: v.get("status", "UNKNOWN") for k, v in results.items()},
        "results": results,
        "data_disclaimer": (
            "All data used in this evaluation is synthetic. "
            "Metrics reflect behaviour on generated benchmark datasets, not live network telemetry. "
            "An anomaly flag does not prove compromise."
        ),
    }

    # Determine overall status
    statuses = [v.get("status", "UNKNOWN") for v in results.values()]
    if all(s == "PASS" for s in statuses):
        summary["overall_status"] = "PASS"
    elif any(s in ("FAIL", "ERROR") for s in statuses):
        summary["overall_status"] = "FAIL"
    elif any(s == "BLOCKED" for s in statuses):
        summary["overall_status"] = "PARTIAL_BLOCKED"
    else:
        summary["overall_status"] = "PARTIAL"

    # Save JSON summary
    json_path = EVAL_OUTPUT_DIR / "evaluation_summary.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    # Generate Markdown report
    md_path = EVAL_OUTPUT_DIR / "EVALUATION_REPORT.md"
    _write_markdown_report(summary, md_path)

    print("\n" + "=" * 60)
    print(f"Overall status  : {summary['overall_status']}")
    print(f"Total elapsed   : {global_elapsed}s")
    print(f"JSON summary    : {json_path}")
    print(f"Markdown report : {md_path}")
    print("=" * 60)


def _write_markdown_report(summary: dict, out_path: Path) -> None:
    """Write a structured Markdown evaluation report."""
    ts = summary.get("evaluated_at", "unknown")
    overall = summary.get("overall_status", "UNKNOWN")
    elapsed = summary.get("elapsed_seconds", "?")
    results = summary.get("results", {})

    lines: list[str] = [
        "# Phase 10 Evaluation Report",
        "",
        f"> **Generated**: {ts}  ",
        f"> **Overall status**: `{overall}`  ",
        f"> **Total evaluation time**: {elapsed}s",
        "",
        "> [!IMPORTANT]",
        "> All data used in this evaluation is synthetic. Metrics reflect behaviour on a generated benchmark dataset, not on live organisational telemetry. An anomaly flag **does not prove compromise**.",
        "",
        "---",
        "",
        "## Summary",
        "",
        "| Sub-evaluation | Status |",
        "|---|---|",
    ]

    status_emoji = {"PASS": "✅", "FAIL": "❌", "PARTIAL": "⚠️", "BLOCKED": "🚫", "ERROR": "❌", "PARTIAL_BLOCKED": "⚠️"}
    for key, status in summary.get("sub_evaluations", {}).items():
        emoji = status_emoji.get(status, "❓")
        lines.append(f"| {key.replace('_', ' ').title()} | {emoji} {status} |")

    lines += ["", "---", ""]

    # --- ML Section ---
    if "ml" in results:
        ml = results["ml"]
        lines += ["## 1. ML Anomaly Detection (Phase 2)", ""]
        if ml.get("status") == "BLOCKED":
            lines += [f"> [!WARNING]", f"> BLOCKED — {', '.join(ml.get('errors', []))}", ""]
        elif ml.get("status") == "ERROR":
            lines += [f"> [!CAUTION]", f"> ERROR — {ml.get('error', 'unknown')}", ""]
        else:
            cm_data = ml.get("classification_metrics", {})
            conf = ml.get("confusion_matrix", {})
            lines += [
                f"**Model**: {ml.get('model')}  ",
                f"**Threshold method**: {ml.get('threshold_method')} @ {ml.get('threshold_percentile')}th percentile  ",
                f"**Evaluation dataset**: {ml.get('evaluation_dataset')} ({ml.get('total_eval_rows')} rows)  ",
                "",
                "| Metric | Value |",
                "|---|---|",
                f"| Precision | {cm_data.get('precision')} |",
                f"| Recall | {cm_data.get('recall')} |",
                f"| F1-Score | {cm_data.get('f1')} |",
                f"| Accuracy | {cm_data.get('accuracy')} |",
                f"| False Positive Rate | {cm_data.get('false_positive_rate')} |",
                f"| ROC-AUC | {cm_data.get('roc_auc')} |",
                f"| PR-AUC | {cm_data.get('pr_auc')} |",
                "",
                "**Confusion matrix**:",
                "",
                "| | Predicted Anomaly | Predicted Normal |",
                "|---|---|---|",
                f"| **Actual Anomaly** | TP={conf.get('true_positives')} | FN={conf.get('false_negatives')} |",
                f"| **Actual Normal** | FP={conf.get('false_positives')} | TN={conf.get('true_negatives')} |",
                "",
            ]
            breakdown = ml.get("per_anomaly_type_breakdown", {})
            if breakdown:
                lines += ["**Per-anomaly-type recall**:", "", "| Anomaly Type | Rows | Detected | Recall |", "|---|---|---|---|"]
                for atype, aval in breakdown.items():
                    if atype == "normal":
                        lines.append(f"| {atype} | {aval.get('total_rows')} | FP={aval.get('false_positives')} | FPR={aval.get('false_positive_rate')} |")
                    else:
                        lines.append(f"| {atype} | {aval.get('total_rows')} | {aval.get('detected_anomalies')} | {aval.get('recall')} |")
                lines.append("")

    # --- RAG Section ---
    if "rag" in results:
        rag = results["rag"]
        lines += ["## 2. RAG Retrieval Quality (Phase 5)", ""]
        if rag.get("status") == "BLOCKED":
            lines += ["> [!WARNING]", f"> BLOCKED — {', '.join(rag.get('errors', []))}", ""]
        elif rag.get("status") == "ERROR":
            lines += ["> [!CAUTION]", f"> ERROR — {rag.get('error', 'unknown')}", ""]
        else:
            m = rag.get("metrics", {})
            lines += [
                "| Metric | Value |",
                "|---|---|",
                f"| Total queries | {m.get('total_queries')} |",
                f"| Answerable queries | {m.get('answerable_queries')} |",
                f"| Unanswerable queries | {m.get('unanswerable_queries')} |",
                f"| Recall@5 | {m.get('recall_at_5')} |",
                f"| Precision@5 | {m.get('precision_at_5')} |",
                f"| MRR | {m.get('mrr')} |",
                f"| Exact ID success rate | {m.get('exact_id_success_rate')} |",
                f"| No-answer rejection rate | {m.get('no_answer_rejection_rate')} |",
                f"| Attribution validity rate | {m.get('attribution_validity_rate')} |",
                f"| Embedding model | {m.get('embedding_model')} |",
                "",
                "> [!NOTE]",
                "> The no-answer rejection rate measures the RAG system's ability to return `NO_RESULTS` for out-of-scope queries rather than returning hallucinated or irrelevant chunks.",
                "",
            ]

    # --- Structured Output Section ---
    if "structured_output" in results:
        so = results["structured_output"]
        lines += ["## 3. LLM Structured Output Validation (Phase 6)", ""]
        if so.get("status") == "BLOCKED":
            lines += ["> [!WARNING]", f"> BLOCKED — {', '.join(so.get('errors', []))}", ""]
        else:
            lines += [
                f"**Status**: {so.get('status')}  ",
                f"**Cases**: {so.get('total_cases')} total, {so.get('pass_count')} passed, {so.get('fail_count')} failed  ",
                "",
                "| Case | Result |",
                "|---|---|",
            ]
            for cr in so.get("case_results", []):
                icon = "✅" if cr.get("passed") else "❌"
                lines.append(f"| {cr.get('case')} | {icon} |")
            lines += [
                "",
                "> [!NOTE]",
                "> This evaluation tests the deterministic `ReportValidator` layer only. The Ollama model is NOT invoked.",
                "",
            ]

    # --- Agent Section ---
    if "agent" in results:
        ag = results["agent"]
        lines += ["## 4. Agent Reliability (Phase 7)", ""]
        if ag.get("status") == "BLOCKED":
            lines += ["> [!WARNING]", f"> BLOCKED — {', '.join(ag.get('errors', []))}", ""]
        else:
            lines += [
                f"**Status**: {ag.get('status')}  ",
                f"**Cases**: {ag.get('total_cases')} total, {ag.get('pass_count')} passed, {ag.get('fail_count')} failed  ",
                "",
                "| Case | Result |",
                "|---|---|",
            ]
            for cr in ag.get("case_results", []):
                icon = "✅" if cr.get("passed") else "❌"
                lines.append(f"| {cr.get('case')} | {icon} |")
            lines += [
                "",
                "> [!NOTE]",
                "> Agent evaluation exercises tool contracts and config correctness. Full end-to-end evaluation requires a live Ollama+qwen3:8b instance (~180s/investigation).",
                "",
            ]

    # --- API Section ---
    if "api" in results:
        api = results["api"]
        lines += ["## 5. API Endpoint Quality (Phase 8)", ""]
        if api.get("status") == "BLOCKED":
            lines += ["> [!WARNING]", f"> BLOCKED — {', '.join(api.get('errors', []))}", ""]
        else:
            lines += [
                f"**Status**: {api.get('status')}  ",
                f"**Base URL**: `{api.get('base_url')}`  ",
                f"**Latency budget**: {api.get('latency_budget_seconds')}s  ",
                f"**Avg latency**: {api.get('avg_latency_seconds')}s  ",
                f"**P95 latency**: {api.get('p95_latency_seconds')}s  ",
                "",
                "| Endpoint | HTTP Status | Latency | Result |",
                "|---|---|---|---|",
            ]
            for ep in api.get("endpoint_results", []):
                icon = "✅" if ep["passed"] else "❌"
                lat = ep.get("latency_seconds", "?")
                code = ep.get("http_status", ep.get("error", "?"))
                lines.append(f"| {ep['name']} | {code} | {lat}s | {icon} |")
            lines.append("")

    # --- Limitations Reference ---
    lines += [
        "---",
        "",
        "## Known Limitations",
        "",
        "See [LIMITATIONS_AND_FUTURE_WORK.md](../docs/LIMITATIONS_AND_FUTURE_WORK.md) for full details.",
        "",
        "Key constraints recorded during this evaluation:",
        "",
        "- **Inference latency**: Local Qwen 3 8B inference on CPU/swap takes ~180s per investigation; excluded from API latency budget.",
        "- **Synthetic data only**: All training, evaluation, and benchmark data is generated. Real-world coverage is unknown.",
        "- **No live threat-intel**: ATT&CK mappings use static fixture data; no real-time IOC feeds.",
        "- **Single-user, loopback only**: Backend binds to 127.0.0.1 by default; external access requires a reverse proxy.",
        "",
        "---",
        "",
        f"*Report generated by `scripts/evaluate_all.py` at {ts}*",
    ]

    out_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"[REPORT] Markdown report saved to {out_path}")


if __name__ == "__main__":
    main()
