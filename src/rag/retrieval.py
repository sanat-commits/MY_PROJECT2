"""Hybrid retrieval engine combining dense vector search, lexical BM25, and rank fusion."""

import re
from typing import Any

from src.rag.config import RagConfig
from src.rag.embeddings import EmbeddingError, EmbeddingProvider
from src.rag.lexical_search import BM25Index
from src.rag.schemas import KnowledgeChunk, RetrievalResult, RetrievalStatus, RetrievedChunk
from src.rag.vector_store import VectorStore


TECHNIQUE_PATTERN = re.compile(r"\b(t\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)
EVENT_ID_PATTERN = re.compile(r"\b(?:event\s*id\s*|eventid:?\s*)?(\d{4})\b", re.IGNORECASE)


class HybridRetriever:
    """Executes hybrid dense + lexical search with Reciprocal Rank Fusion and exact identifier awareness."""

    def __init__(
        self,
        vector_store: VectorStore,
        bm25_index: BM25Index,
        embedding_provider: EmbeddingProvider,
        config: RagConfig | None = None,
    ):
        self.vector_store = vector_store
        self.bm25_index = bm25_index
        self.embedding_provider = embedding_provider
        self.config = config or RagConfig()

    def retrieve(
        self,
        query: str,
        top_k: int | None = None,
        filters: dict[str, Any] | None = None,
    ) -> RetrievalResult:
        """Execute hybrid search returning verified, attributable chunks."""
        effective_top_k = top_k if top_k is not None else self.config.final_top_k

        # 1. Query validation
        if not query or not query.strip():
            return RetrievalResult(
                query=query or "",
                status=RetrievalStatus.INVALID_QUERY,
                results=[],
                count=0,
                metadata={"error": "Query string is empty or contains whitespace only"},
            )

        if effective_top_k <= 0:
            return RetrievalResult(
                query=query,
                status=RetrievalStatus.INVALID_QUERY,
                results=[],
                count=0,
                metadata={"error": f"top_k must be a positive integer, got {effective_top_k}"},
            )

        # 2. Check if indexes are empty
        if self.vector_store.count() == 0 or self.bm25_index.doc_count == 0:
            return RetrievalResult(
                query=query,
                status=RetrievalStatus.SOURCE_UNAVAILABLE,
                results=[],
                count=0,
                metadata={"error": "Vector store or lexical index is empty. Ingestion required."},
            )

        # 3. Dense Retrieval
        dense_results: list[tuple[KnowledgeChunk, float]] = []
        try:
            q_vector = self.embedding_provider.embed_query(query)
            dense_results = self.vector_store.search(
                query_vector=q_vector,
                top_k=self.config.dense_top_k,
                filters=filters,
            )
        except EmbeddingError as e:
            return RetrievalResult(
                query=query,
                status=RetrievalStatus.SOURCE_UNAVAILABLE,
                results=[],
                count=0,
                metadata={"error": f"Dense embedding lookup failed: {e}"},
            )

        # 4. Lexical BM25 Retrieval
        lexical_results = self.bm25_index.search(
            query=query,
            top_k=self.config.lexical_top_k,
            filters=filters,
        )

        # 5. Extract exact identifiers from query
        query_lower = query.lower()
        extracted_tids = [t.upper() for t in TECHNIQUE_PATTERN.findall(query_lower)]
        extracted_eids = [e for e in EVENT_ID_PATTERN.findall(query_lower) if e in ("4624", "4625", "4688", "4672", "4728", "4732")]

        # 6. Rank Fusion (Reciprocal Rank Fusion with Exact ID Boosting)
        fused_scores: dict[str, dict[str, Any]] = {}
        rrf_k = self.config.rrf_k

        for rank, (chunk, d_score) in enumerate(dense_results, start=1):
            cid = chunk.chunk_id
            if cid not in fused_scores:
                fused_scores[cid] = {
                    "chunk": chunk,
                    "dense_score": d_score,
                    "dense_rank": rank,
                    "lexical_score": None,
                    "lexical_rank": None,
                    "fused_score": 0.0,
                    "is_exact_match": False,
                }
            fused_scores[cid]["fused_score"] += 1.0 / (rrf_k + rank)

        for rank, (chunk, l_score) in enumerate(lexical_results, start=1):
            cid = chunk.chunk_id
            if cid not in fused_scores:
                fused_scores[cid] = {
                    "chunk": chunk,
                    "dense_score": None,
                    "dense_rank": None,
                    "lexical_score": l_score,
                    "lexical_rank": rank,
                    "fused_score": 0.0,
                    "is_exact_match": False,
                }
            else:
                fused_scores[cid]["lexical_score"] = l_score
                fused_scores[cid]["lexical_rank"] = rank
            fused_scores[cid]["fused_score"] += 1.0 / (rrf_k + rank)

        # 7. Exact Identifier Match Boosting
        for cid, item in fused_scores.items():
            chunk: KnowledgeChunk = item["chunk"]
            is_match = False
            if chunk.technique_id and chunk.technique_id in extracted_tids:
                is_match = True
            if any(eid in chunk.event_ids for eid in extracted_eids):
                is_match = True
            if is_match:
                item["is_exact_match"] = True
                item["fused_score"] += self.config.exact_id_boost

        # Sort candidate pool by fused score descending
        ranked_candidates = sorted(
            fused_scores.values(),
            key=lambda x: x["fused_score"],
            reverse=True,
        )

        # 8. Relevance Filtering & Deduplication
        filtered_results: list[RetrievedChunk] = []
        seen_documents: dict[str, int] = {}

        for rank, item in enumerate(ranked_candidates, start=1):
            chunk: KnowledgeChunk = item["chunk"]
            f_score = item["fused_score"]
            is_exact = item["is_exact_match"]
            dense_s = item["dense_score"]
            lex_s = item["lexical_score"]

            # Multi-stage relevance verification:
            # 1. Exact identifier match automatically verified
            # 2. Both dense and lexical agree above moderate thresholds
            # 3. High dense semantic confidence
            # 4. High lexical keyword confidence
            strong_agree = (
                dense_s is not None
                and dense_s >= self.config.agreement_dense_min
                and lex_s is not None
                and lex_s >= self.config.agreement_lexical_min
            )
            high_dense = (dense_s is not None and dense_s >= self.config.min_dense_confidence)
            high_lex = (lex_s is not None and lex_s >= self.config.min_lexical_confidence)

            if not (is_exact or strong_agree or high_dense or high_lex):
                continue

            # Diversity deduplication: max 2 chunks per parent document
            doc_count = seen_documents.get(chunk.parent_document_id, 0)
            if doc_count >= 2:
                continue
            seen_documents[chunk.parent_document_id] = doc_count + 1

            retrieved_chunk = RetrievedChunk(
                chunk_id=chunk.chunk_id,
                source_id=chunk.source_id,
                source_title=chunk.source_title,
                document_title=chunk.document_title,
                source_uri_or_path=chunk.source_uri_or_path,
                source_type=chunk.source_type,
                source_version_or_date=chunk.source_version_or_date,
                heading_path=chunk.heading_path,
                content=chunk.content,
                dense_score=item["dense_score"],
                dense_rank=item["dense_rank"],
                lexical_score=item["lexical_score"],
                lexical_rank=item["lexical_rank"],
                fused_score=round(f_score, 5),
                fused_rank=rank,
                is_exact_match=item["is_exact_match"],
                technique_id=chunk.technique_id,
                rule_id=chunk.rule_id,
            )
            filtered_results.append(retrieved_chunk)
            if len(filtered_results) >= effective_top_k:
                break

        # 9. Handle No Results State
        if not filtered_results:
            return RetrievalResult(
                query=query,
                status=RetrievalStatus.NO_RESULTS,
                results=[],
                count=0,
                metadata={
                    "candidates_evaluated": len(ranked_candidates),
                    "relevance_threshold": self.config.relevance_score_threshold,
                    "reason": "No retrieved candidates met relevance filtering criteria",
                },
            )

        return RetrievalResult(
            query=query,
            status=RetrievalStatus.SUCCESS,
            results=filtered_results,
            count=len(filtered_results),
            metadata={
                "dense_candidates": len(dense_results),
                "lexical_candidates": len(lexical_results),
                "fused_candidates": len(ranked_candidates),
                "top_fused_score": filtered_results[0].fused_score if filtered_results else 0.0,
            },
        )
