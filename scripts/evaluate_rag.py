"""Phase 10 — RAG Retrieval Evaluation Script.

Executes the existing Phase 5 retrieval evaluator against the benchmark query
set (data/knowledge_base/retrieval_eval.jsonl) and records real retrieval
quality metrics.

Usage:
    python scripts/evaluate_rag.py

Outputs:
    artifacts/evaluation/rag_metrics.json
"""

from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

EVAL_OUTPUT_DIR = ROOT / "artifacts" / "evaluation"
EVAL_QUERY_FILE = ROOT / "data" / "knowledge_base" / "retrieval_eval.jsonl"
VECTOR_STORE_DIR = ROOT / "artifacts" / "vector_store"


def run_rag_evaluation() -> dict:
    """Run RAG retrieval evaluation and return the evaluation result dict."""
    errors: list[str] = []

    if not EVAL_QUERY_FILE.exists():
        errors.append(f"RAG benchmark query file missing: {EVAL_QUERY_FILE}")
    if not VECTOR_STORE_DIR.exists():
        errors.append(f"Vector store artifact missing: {VECTOR_STORE_DIR}")

    if errors:
        result = {
            "status": "BLOCKED",
            "errors": errors,
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
        }
        _save_result(result)
        for e in errors:
            print(f"[BLOCKED] {e}")
        return result

    # Import after path validation to give a cleaner error if deps missing
    try:
        from src.rag.config import get_default_config as get_rag_config
        from src.rag.service import KnowledgeBaseService
        from src.rag.evaluation import RetrievalEvaluator
    except ImportError as exc:
        result = {
            "status": "BLOCKED",
            "errors": [f"Import error: {exc}"],
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
        }
        _save_result(result)
        print(f"[BLOCKED] Import error: {exc}")
        return result

    t0 = time.perf_counter()
    try:
        rag_config = get_rag_config()
        service = KnowledgeBaseService(rag_config)
        evaluator = RetrievalEvaluator(service, eval_path=EVAL_QUERY_FILE)
        metrics = evaluator.evaluate(top_k=5)
        elapsed = round(time.perf_counter() - t0, 3)
    except Exception as exc:
        elapsed = round(time.perf_counter() - t0, 3)
        result = {
            "status": "ERROR",
            "error": str(exc),
            "elapsed_seconds": elapsed,
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
        }
        _save_result(result)
        print(f"[ERROR] RAG evaluation failed: {exc}")
        return result

    m = metrics.model_dump()
    result = {
        "status": "PASS",
        "metrics": m,
        "elapsed_seconds": elapsed,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "notes": (
            "Retrieval benchmark queries are hand-checked against verified "
            "cybersecurity sources. Rejection rate measures the RAG system's "
            "ability to return NO_RESULTS for out-of-scope queries rather than "
            "returning hallucinated or irrelevant chunks."
        ),
    }

    _save_result(result)
    _print_summary(result)
    return result


def _save_result(result: dict) -> None:
    EVAL_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = EVAL_OUTPUT_DIR / "rag_metrics.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    print(f"[RAG] Results saved to {out_path}")


def _print_summary(result: dict) -> None:
    m = result.get("metrics", {})
    print("\n=== RAG Retrieval Evaluation Summary ===")
    print(f"Status                  : {result['status']}")
    print(f"Total queries           : {m.get('total_queries')}")
    print(f"Answerable queries      : {m.get('answerable_queries')}")
    print(f"Unanswerable queries    : {m.get('unanswerable_queries')}")
    print(f"Recall@5                : {m.get('recall_at_5')}")
    print(f"Precision@5             : {m.get('precision_at_5')}")
    print(f"MRR                     : {m.get('mrr')}")
    print(f"Exact ID success rate   : {m.get('exact_id_success_rate')}")
    print(f"No-answer rejection rate: {m.get('no_answer_rejection_rate')}")
    print(f"Attribution validity    : {m.get('attribution_validity_rate')}")
    print(f"Elapsed                 : {result.get('elapsed_seconds')}s")


if __name__ == "__main__":
    run_rag_evaluation()
