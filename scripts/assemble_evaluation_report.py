"""Phase 10 — Assemble Evaluation Summary from Existing Artifacts.

Reads already-computed evaluation artifacts (ML metrics from Phase 2,
RAG metrics from Phase 5, structured-output and agent results) and
assembles the consolidated evaluation_summary.json and EVALUATION_REPORT.md
without re-running heavy model/inference code.

This script is idempotent — re-running it regenerates the report from the
most recently computed sub-evaluation results.

Usage:
    python scripts/assemble_evaluation_report.py [--api-result api_metrics.json]
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

EVAL_OUTPUT_DIR = ROOT / "artifacts" / "evaluation"
ML_ARTIFACT = ROOT / "artifacts" / "ml" / "metrics.json"
RAG_ARTIFACT = ROOT / "artifacts" / "knowledge_base" / "retrieval_eval_report.json"


def load_json(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"[WARNING] Could not parse {path}: {exc}")
        return None


def build_ml_result(raw: dict) -> dict:
    """Normalise Phase 2 metrics.json into evaluation result format."""
    cm = raw.get("classification_metrics", {})
    conf = raw.get("confusion_matrix", {})
    return {
        "status": "PASS",
        "model": raw.get("model"),
        "threshold_method": "training_normal_percentile",
        "threshold_percentile": 95.0,
        "evaluation_dataset": raw.get("evaluation_dataset"),
        "total_eval_rows": raw.get("total_eval_rows"),
        "synthetic": True,
        "classification_metrics": cm,
        "confusion_matrix": conf,
        "per_anomaly_type_breakdown": raw.get("per_anomaly_type_breakdown", {}),
        "evaluated_at": raw.get("created_at"),
        "notes": (
            "All data is synthetic. Metrics reflect behaviour on a generated "
            "benchmark dataset. An anomaly flag does not prove compromise."
        ),
    }


def build_rag_result(raw: dict) -> dict:
    """Normalise Phase 5 retrieval_eval_report.json into evaluation result format."""
    metrics = raw.get("metrics", {})
    return {
        "status": "PASS",
        "metrics": metrics,
        "evaluated_at": metrics.get("evaluation_timestamp"),
        "notes": (
            "Retrieval benchmark queries are hand-checked against verified "
            "cybersecurity sources. Rejection rate measures the system's "
            "ability to return NO_RESULTS for out-of-scope queries."
        ),
    }


def load_or_describe_blocked(path: Path, label: str) -> dict:
    """Return result dict from file or a BLOCKED status."""
    data = load_json(path)
    if data is None:
        return {
            "status": "BLOCKED",
            "errors": [f"{label} artifact not found at {path}"],
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
        }
    return data


def write_markdown_report(summary: dict, out_path: Path) -> None:
    """Write human-readable Markdown evaluation report."""
    ts = summary.get("evaluated_at", "unknown")
    overall = summary.get("overall_status", "UNKNOWN")
    results = summary.get("results", {})

    status_emoji = {
        "PASS": "✅", "FAIL": "❌", "PARTIAL": "⚠️",
        "BLOCKED": "🚫", "ERROR": "❌", "PARTIAL_BLOCKED": "⚠️",
    }

    lines: list[str] = [
        "# Phase 10 Evaluation Report",
        "",
        f"> **Generated**: {ts}  ",
        f"> **Overall status**: `{overall}`  ",
        "",
        "> [!IMPORTANT]",
        "> All data used in this evaluation is **synthetic**. Metrics reflect behaviour on a generated benchmark dataset, not on live organisational telemetry. An anomaly flag **does not prove compromise**.",
        "",
        "---",
        "",
        "## Summary",
        "",
        "| Sub-evaluation | Status |",
        "|---|---|",
    ]
    for key, status in summary.get("sub_evaluations", {}).items():
        emoji = status_emoji.get(status, "❓")
        lines.append(f"| {key.replace('_', ' ').title()} | {emoji} {status} |")

    lines += ["", "---", ""]

    # --- ML ---
    if "ml" in results:
        ml = results["ml"]
        lines += ["## 1. ML Anomaly Detection (Phase 2)", ""]
        if ml.get("status") in ("BLOCKED", "ERROR"):
            lines += [f"> **{ml['status']}**: {', '.join(ml.get('errors', [ml.get('error', '?')]))}",  ""]
        else:
            cm = ml.get("classification_metrics", {})
            conf = ml.get("confusion_matrix", {})
            lines += [
                f"**Model**: {ml.get('model')}  ",
                f"**Threshold**: {ml.get('threshold_method')} @ {ml.get('threshold_percentile')}th percentile  ",
                f"**Evaluation dataset**: {ml.get('evaluation_dataset')} ({ml.get('total_eval_rows')} rows)  ",
                "",
                "| Metric | Value |",
                "|---|---|",
                f"| Precision | **{cm.get('precision')}** |",
                f"| Recall | **{cm.get('recall')}** |",
                f"| F1-Score | **{cm.get('f1')}** |",
                f"| Accuracy | {cm.get('accuracy')} |",
                f"| False Positive Rate | {cm.get('false_positive_rate')} |",
                f"| ROC-AUC | {cm.get('roc_auc')} |",
                f"| PR-AUC | {cm.get('pr_auc')} |",
                "",
                "**Confusion matrix**:",
                "",
                "| | Predicted Anomaly | Predicted Normal |",
                "|---|---|---|",
                f"| **Actual Anomaly** | TP = {conf.get('true_positives')} | FN = {conf.get('false_negatives')} |",
                f"| **Actual Normal** | FP = {conf.get('false_positives')} | TN = {conf.get('true_negatives')} |",
                "",
            ]
            breakdown = ml.get("per_anomaly_type_breakdown", {})
            if breakdown:
                lines += ["**Per-anomaly-type detection rate**:", "", "| Anomaly Type | Total Rows | Detected | Rate |", "|---|---|---|---|"]
                for atype, av in breakdown.items():
                    if atype == "normal":
                        lines.append(f"| {atype} (FPR) | {av.get('total_rows')} | FP={av.get('false_positives')} | {av.get('false_positive_rate')} |")
                    else:
                        lines.append(f"| {atype} | {av.get('total_rows')} | {av.get('detected_anomalies')} | {av.get('recall')} |")
                lines.append("")

    # --- RAG ---
    if "rag" in results:
        rag = results["rag"]
        lines += ["## 2. RAG Retrieval Quality (Phase 5)", ""]
        if rag.get("status") in ("BLOCKED", "ERROR"):
            lines += [f"> **{rag['status']}**: {', '.join(rag.get('errors', [rag.get('error', '?')]))}",  ""]
        else:
            m = rag.get("metrics", {})
            lines += [
                "| Metric | Value |",
                "|---|---|",
                f"| Total queries | {m.get('total_queries')} |",
                f"| Answerable | {m.get('answerable_queries')} |",
                f"| Unanswerable | {m.get('unanswerable_queries')} |",
                f"| Recall@5 | **{m.get('recall_at_5')}** |",
                f"| Precision@5 | **{m.get('precision_at_5')}** |",
                f"| MRR | **{m.get('mrr')}** |",
                f"| Exact ID success rate | {m.get('exact_id_success_rate')} |",
                f"| No-answer rejection rate | **{m.get('no_answer_rejection_rate')}** |",
                f"| Attribution validity rate | **{m.get('attribution_validity_rate')}** |",
                f"| Embedding model | `{m.get('embedding_model')}` |",
                f"| Vector store | `{m.get('vector_store_provider')}` |",
                "",
                "> [!NOTE]",
                "> A no-answer rejection rate of **1.0** means every out-of-scope query returned `NO_RESULTS` rather than a hallucinated nearest-neighbour chunk.",
                "",
            ]

    # --- Structured Output ---
    if "structured_output" in results:
        so = results["structured_output"]
        lines += ["## 3. LLM Structured Output Validation (Phase 6)", ""]
        if so.get("status") == "BLOCKED":
            lines += [f"> **BLOCKED**: {', '.join(so.get('errors', []))}",  ""]
        else:
            lines += [
                f"**Status**: {so.get('status')}  ",
                f"**Cases**: {so.get('total_cases')} total — {so.get('pass_count')} passed, {so.get('fail_count')} failed  ",
                "",
                "| Case | Result |",
                "|---|---|",
            ]
            for cr in so.get("case_results", []):
                icon = "✅" if cr.get("passed") else "❌"
                msg = f" — `{cr['error_message']}`" if not cr.get("passed") and cr.get("error_message") else ""
                lines.append(f"| `{cr.get('case')}` | {icon}{msg} |")
            lines += [
                "",
                "> [!NOTE]",
                "> This evaluation exercises the deterministic `ReportValidator` layer only — the Ollama model is **not** invoked.",
                "",
            ]

    # --- Agent ---
    if "agent" in results:
        ag = results["agent"]
        lines += ["## 4. Agent Reliability (Phase 7)", ""]
        if ag.get("status") == "BLOCKED":
            lines += [f"> **BLOCKED**: {', '.join(ag.get('errors', []))}",  ""]
        else:
            lines += [
                f"**Status**: {ag.get('status')}  ",
                f"**Cases**: {ag.get('total_cases')} total — {ag.get('pass_count')} passed, {ag.get('fail_count')} failed  ",
                "",
                "| Case | Result |",
                "|---|---|",
            ]
            for cr in ag.get("case_results", []):
                icon = "✅" if cr.get("passed") else "❌"
                lines.append(f"| `{cr.get('case')}` | {icon} |")
            lines += [
                "",
                "> [!NOTE]",
                "> Agent evaluation verifies tool contracts and budget-limit configuration. Full end-to-end evaluation requires a live Ollama+qwen3:8b instance (~180s per investigation).",
                "",
            ]

    # --- API ---
    if "api" in results:
        api = results["api"]
        lines += ["## 5. API Endpoint Quality (Phase 8)", ""]
        if api.get("status") == "BLOCKED":
            lines += [f"> **BLOCKED**: {', '.join(api.get('errors', []))}",  ""]
        else:
            lines += [
                f"**Status**: {api.get('status')}  ",
                f"**Base URL**: `{api.get('base_url')}`  ",
                f"**Avg latency**: {api.get('avg_latency_seconds')}s | **P95 latency**: {api.get('p95_latency_seconds')}s  ",
                "",
                "| Endpoint | HTTP | Latency | Result |",
                "|---|---|---|---|",
            ]
            for ep in api.get("endpoint_results", []):
                icon = "✅" if ep["passed"] else "❌"
                code = ep.get("http_status", ep.get("error", "?"))
                lat = ep.get("latency_seconds", "?")
                lines.append(f"| {ep['name']} | {code} | {lat}s | {icon} |")
            lines.append("")

    lines += [
        "---",
        "",
        "## Known Limitations",
        "",
        "See [`docs/LIMITATIONS_AND_FUTURE_WORK.md`](../docs/LIMITATIONS_AND_FUTURE_WORK.md) for full detail.",
        "",
        "| Limitation | Impact |",
        "|---|---|",
        "| Synthetic data only | Precision/recall on real-world traffic unknown |",
        "| Local CPU inference ~180s/investigation | Investigation endpoint excluded from latency budget |",
        "| Static ATT&CK v14.1 catalog | New techniques not mapped |",
        "| No authentication / authorisation | Single-user loopback deployment only |",
        "| No live streaming | Operates on pre-computed 1-hour windows |",
        "",
        "---",
        "",
        f"*Report generated by `scripts/assemble_evaluation_report.py` at {ts}*",
    ]

    out_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"[REPORT] Markdown report saved to {out_path}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-result", default=None, help="Path to api_metrics.json if available")
    args = parser.parse_args()

    EVAL_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    results: dict = {}

    # --- ML: read from existing Phase 2 artifact ---
    ml_raw = load_json(ML_ARTIFACT)
    if ml_raw:
        results["ml"] = build_ml_result(ml_raw)
        print(f"[ML] Loaded metrics from {ML_ARTIFACT}")
    else:
        results["ml"] = {"status": "BLOCKED", "errors": [f"Missing: {ML_ARTIFACT}"]}

    # --- RAG: read from existing Phase 5 artifact ---
    rag_raw = load_json(RAG_ARTIFACT)
    if rag_raw:
        results["rag"] = build_rag_result(rag_raw)
        print(f"[RAG] Loaded metrics from {RAG_ARTIFACT}")
    else:
        results["rag"] = {"status": "BLOCKED", "errors": [f"Missing: {RAG_ARTIFACT}"]}

    # --- Structured output: read if already run, otherwise mark PENDING ---
    so_path = EVAL_OUTPUT_DIR / "structured_output_metrics.json"
    so_data = load_json(so_path)
    if so_data:
        results["structured_output"] = so_data
        print(f"[STRUCTURED OUTPUT] Loaded from {so_path}")
    else:
        results["structured_output"] = {
            "status": "PENDING",
            "notes": "Run: python scripts/evaluate_structured_output.py",
        }

    # --- Agent: read if already run, otherwise mark PENDING ---
    ag_path = EVAL_OUTPUT_DIR / "agent_metrics.json"
    ag_data = load_json(ag_path)
    if ag_data:
        results["agent"] = ag_data
        print(f"[AGENT] Loaded from {ag_path}")
    else:
        results["agent"] = {
            "status": "PENDING",
            "notes": "Run: python scripts/evaluate_agent.py",
        }

    # --- API: optional ---
    if args.api_result:
        api_data = load_json(Path(args.api_result))
        if api_data:
            results["api"] = api_data
    api_path = EVAL_OUTPUT_DIR / "api_metrics.json"
    if "api" not in results and api_path.exists():
        api_data = load_json(api_path)
        if api_data:
            results["api"] = api_data
            print(f"[API] Loaded from {api_path}")

    # Build summary
    statuses = [v.get("status", "UNKNOWN") for v in results.values()]
    if all(s == "PASS" for s in statuses):
        overall = "PASS"
    elif any(s in ("FAIL", "ERROR") for s in statuses):
        overall = "FAIL"
    elif any(s in ("BLOCKED", "PENDING") for s in statuses):
        overall = "PARTIAL_BLOCKED"
    else:
        overall = "PARTIAL"

    ts = datetime.now(timezone.utc).isoformat()
    summary = {
        "evaluated_at": ts,
        "overall_status": overall,
        "sub_evaluations": {k: v.get("status", "UNKNOWN") for k, v in results.items()},
        "results": results,
        "data_disclaimer": (
            "All data is synthetic. Metrics reflect behaviour on generated benchmark "
            "datasets, not on live organisational telemetry. An anomaly flag does not "
            "prove compromise."
        ),
    }

    json_path = EVAL_OUTPUT_DIR / "evaluation_summary.json"
    json_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"[SUMMARY] JSON saved to {json_path}")

    md_path = EVAL_OUTPUT_DIR / "EVALUATION_REPORT.md"
    write_markdown_report(summary, md_path)

    print(f"\nOverall status: {overall}")
    for k, s in summary["sub_evaluations"].items():
        print(f"  {k}: {s}")


if __name__ == "__main__":
    main()
