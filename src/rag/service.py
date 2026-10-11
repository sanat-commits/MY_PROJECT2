"""Public Knowledge Base retrieval service conforming to docs/TOOL_CONTRACTS.md."""

from pathlib import Path
from typing import Any

from src.rag.config import RagConfig
from src.rag.embeddings import EmbeddingProvider, get_embedding_provider
from src.rag.lexical_search import BM25Index
from src.rag.retrieval import HybridRetriever
from src.rag.schemas import RetrievalResult, RetrievalStatus
from src.rag.vector_store import VectorStore, get_vector_store


class KnowledgeBaseService:
    """Production service for querying cybersecurity knowledge base with hybrid retrieval."""

    def __init__(
        self,
        config: RagConfig | None = None,
        vector_store: VectorStore | None = None,
        embedding_provider: EmbeddingProvider | None = None,
        bm25_index: BM25Index | None = None,
        base_dir: Path | None = None,
    ):
        self.config = config or RagConfig()
        self.base_dir = base_dir or Path.cwd()
        self.vector_store = vector_store or get_vector_store(self.config)
        self.embedding_provider = embedding_provider or get_embedding_provider(self.config)

        # Load or initialize BM25 index
        if bm25_index:
            self.bm25_index = bm25_index
        else:
            lex_file = self.base_dir / self.config.lexical_index_path
            if lex_file.exists():
                self.bm25_index = BM25Index.load(lex_file)
            else:
                self.bm25_index = BM25Index()

        self.retriever = HybridRetriever(
            vector_store=self.vector_store,
            bm25_index=self.bm25_index,
            embedding_provider=self.embedding_provider,
            config=self.config,
        )

    def search_knowledge_base(
        self,
        query: str,
        top_k: int = 5,
        filters: dict[str, Any] | None = None,
    ) -> RetrievalResult:
        """Search knowledge base and return ranked, attributable chunks.

        Conforms strictly to docs/TOOL_CONTRACTS.md:
        Input: query, top_k, optional source filters.
        Output: chunks with chunk_id, title, source URI/path, type, version/date, relevance metadata.
        No-result is an explicit, valid state.
        """
        try:
            return self.retriever.retrieve(query=query, top_k=top_k, filters=filters)
        except Exception as e:
            return RetrievalResult(
                query=query,
                status=RetrievalStatus.RETRIEVAL_ERROR,
                results=[],
                count=0,
                metadata={"error": str(e)},
            )
