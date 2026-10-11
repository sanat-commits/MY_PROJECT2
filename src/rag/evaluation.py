"""Retrieval evaluation benchmark measuring Recall, MRR, exact ID accuracy, and rejection rates."""

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from src.rag.schemas import EvalMetrics, EvalQuery, RetrievalStatus
from src.rag.service import KnowledgeBaseService


class RetrievalEvaluator:
    """Evaluates retrieval quality against ground-truth cybersecurity queries."""

    def __init__(self, service: KnowledgeBaseService, eval_path: Path | None = None):
        self.service = service
        self.eval_path = eval_path or Path("data/knowledge_base/retrieval_eval.jsonl")

    def load_eval_queries(self) -> list[EvalQuery]:
        """Load benchmark evaluation queries."""
        if not self.eval_path.exists():
            raise FileNotFoundError(f"Evaluation benchmark file not found: {self.eval_path}")

        queries = []
        with open(self.eval_path, "r", encoding="utf-8") as f:
            for line in f:
                line_str = line.strip()
                if line_str:
                    queries.append(EvalQuery.model_validate_json(line_str))
        return queries

    def evaluate(self, top_k: int = 5) -> EvalMetrics:
        """Run full evaluation suite and calculate standard retrieval metrics."""
        eval_queries = self.load_eval_queries()
        if not eval_queries:
            raise ValueError("No queries loaded from benchmark set")

        answerable_count = 0
        unanswerable_count = 0
        hits_at_k = 0
        sum_reciprocal_rank = 0.0
        sum_precision = 0.0
        exact_id_queries = 0
        exact_id_hits = 0
        unanswerable_rejected = 0
        total_returned_chunks = 0
        valid_attributions = 0

        detailed_results: list[dict[str, Any]] = []

        for q in eval_queries:
            result = self.service.search_knowledge_base(q.query, top_k=top_k)
            retrieved_chunks = result.results
            total_returned_chunks += len(retrieved_chunks)

            # Attribution validity check on every returned chunk
            for c in retrieved_chunks:
                if c.chunk_id and c.source_id and c.source_title and c.source_uri_or_path and c.content:
                    valid_attributions += 1

            if q.is_answerable:
                answerable_count += 1
                first_relevant_rank = None
                query_hits = 0

                for rank, chunk in enumerate(retrieved_chunks, start=1):
                    # Check if chunk matches expected source or target ID
                    is_match = False
                    if chunk.source_id in q.expected_source_ids:
                        is_match = True
                    if q.target_technique_id and chunk.technique_id == q.target_technique_id:
                        is_match = True

                    if is_match:
                        query_hits += 1
                        if first_relevant_rank is None:
                            first_relevant_rank = rank

                if first_relevant_rank is not None:
                    hits_at_k += 1
                    sum_reciprocal_rank += 1.0 / first_relevant_rank

                if retrieved_chunks:
                    sum_precision += query_hits / len(retrieved_chunks)

                # Check exact identifier query success (at rank 1)
                if q.target_technique_id or q.target_event_id:
                    exact_id_queries += 1
                    if retrieved_chunks:
                        top_chunk = retrieved_chunks[0]
                        if q.target_technique_id and top_chunk.technique_id == q.target_technique_id:
                            exact_id_hits += 1
                        elif q.target_event_id and q.target_event_id in top_chunk.content:
                            exact_id_hits += 1

                detailed_results.append({
                    "query_id": q.query_id,
                    "query": q.query,
                    "status": result.status.value,
                    "retrieved_count": len(retrieved_chunks),
                    "first_rank": first_relevant_rank,
                    "is_hit": first_relevant_rank is not None,
                })

            else:
                unanswerable_count += 1
                # Unanswerable query is successfully handled if status is NO_RESULTS or 0 results
                if result.status == RetrievalStatus.NO_RESULTS or len(retrieved_chunks) == 0:
                    unanswerable_rejected += 1

                detailed_results.append({
                    "query_id": q.query_id,
                    "query": q.query,
                    "status": result.status.value,
                    "correctly_rejected": (result.status == RetrievalStatus.NO_RESULTS or len(retrieved_chunks) == 0),
                })

        recall = hits_at_k / answerable_count if answerable_count > 0 else 0.0
        precision = sum_precision / answerable_count if answerable_count > 0 else 0.0
        mrr = sum_reciprocal_rank / answerable_count if answerable_count > 0 else 0.0
        exact_id_rate = exact_id_hits / exact_id_queries if exact_id_queries > 0 else 1.0
        rejection_rate = unanswerable_rejected / unanswerable_count if unanswerable_count > 0 else 1.0
        attribution_rate = valid_attributions / total_returned_chunks if total_returned_chunks > 0 else 1.0

        metrics = EvalMetrics(
            total_queries=len(eval_queries),
            answerable_queries=answerable_count,
            unanswerable_queries=unanswerable_count,
            recall_at_5=round(recall, 4),
            precision_at_5=round(precision, 4),
            mrr=round(mrr, 4),
            exact_id_success_rate=round(exact_id_rate, 4),
            no_answer_rejection_rate=round(rejection_rate, 4),
            attribution_validity_rate=round(attribution_rate, 4),
            evaluation_timestamp=datetime.now(timezone.utc).isoformat(),
            embedding_model=self.service.embedding_provider.model_name,
            vector_store_provider=self.service.config.vector_store_provider,
        )

        # Save report
        report_dir = Path("artifacts/knowledge_base")
        report_dir.mkdir(parents=True, exist_ok=True)
        report_file = report_dir / "retrieval_eval_report.json"
        with open(report_file, "w", encoding="utf-8") as f:
            json.dump({
                "metrics": metrics.model_dump(),
                "query_results": detailed_results,
            }, f, indent=2)

        return metrics
