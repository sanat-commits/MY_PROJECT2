"""Knowledge base ingestion orchestrator for extracting, chunking, embedding, and indexing."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any

from src.rag.chunk_validation import ChunkValidator
from src.rag.chunking import StructureAwareChunker
from src.rag.config import RagConfig
from src.rag.embeddings import EmbeddingProvider, get_embedding_provider
from src.rag.extractors import get_extractor_for_type
from src.rag.lexical_search import BM25Index
from src.rag.schemas import KnowledgeChunk, SourceEntry
from src.rag.vector_store import VectorStore, get_vector_store


class IngestionError(Exception):
    """Raised when knowledge base ingestion fails."""
    pass


class KnowledgeBaseIngestor:
    """Orchestrates end-to-end ingestion of verified cybersecurity knowledge sources."""

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
        self.bm25_index = bm25_index or BM25Index()
        self.chunker = StructureAwareChunker(self.config)
        self.validator = ChunkValidator(self.config)

    def load_sources_manifest(self) -> list[SourceEntry]:
        """Load and parse the verified sources manifest."""
        manifest_file = self.base_dir / self.config.sources_manifest_path
        if not manifest_file.exists():
            raise IngestionError(f"Sources manifest not found at: {manifest_file}")

        with open(manifest_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        sources = []
        for raw_src in data.get("sources", []):
            sources.append(SourceEntry.model_validate(raw_src))
        return sources

    def ingest_all(self, force_rebuild: bool = False) -> dict[str, Any]:
        """Ingest all configured knowledge sources into persistent vector and lexical stores."""
        sources = self.load_sources_manifest()
        if not sources:
            raise IngestionError("Sources manifest contains no sources to ingest")

        if force_rebuild:
            self.vector_store.clear()
            self.bm25_index.clear()

        all_valid_chunks: list[KnowledgeChunk] = []
        source_summaries: list[dict[str, Any]] = []

        for src in sources:
            src_path = self.base_dir / src.canonical_path
            if not src_path.exists():
                raise IngestionError(f"Source file does not exist: {src_path}")

            # Verify cryptographic integrity against manifest
            actual_hash = hashlib.sha256(src_path.read_bytes()).hexdigest()
            if actual_hash != src.content_hash:
                raise IngestionError(
                    f"Integrity check failed for source '{src.source_id}'. "
                    f"Expected hash {src.content_hash}, got {actual_hash}"
                )

            # Extract documents
            extractor = get_extractor_for_type(src.document_type)
            docs = extractor.extract(src, self.base_dir)

            src_valid_chunks: list[KnowledgeChunk] = []
            for doc in docs:
                chunks = self.chunker.chunk_document(doc, src.title)
                for chunk in chunks:
                    val_res = self.validator.validate(chunk)
                    if val_res.is_valid:
                        src_valid_chunks.append(chunk)

            all_valid_chunks.extend(src_valid_chunks)
            source_summaries.append({
                "source_id": src.source_id,
                "title": src.title,
                "document_type": src.document_type.value,
                "chunks_count": len(src_valid_chunks),
                "content_hash": actual_hash,
            })

        if not all_valid_chunks:
            raise IngestionError("No valid chunks were produced after extraction and validation")

        # 1. Generate Embeddings and Index into Vector Store
        chunk_texts = [c.content for c in all_valid_chunks]
        embeddings = self.embedding_provider.embed_documents(chunk_texts)
        self.vector_store.add_chunks(all_valid_chunks, embeddings)

        # 2. Build and Persist BM25 Lexical Index
        self.bm25_index.build(all_valid_chunks)
        lex_path = self.base_dir / self.config.lexical_index_path
        self.bm25_index.save(lex_path)

        # 3. Write Index Manifest for Provenance and Reproducibility
        manifest_path = self.base_dir / self.config.index_manifest_path
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_record = {
            "ingested_at": datetime.now(timezone.utc).isoformat(),
            "sources_count": len(sources),
            "total_chunks": len(all_valid_chunks),
            "rejected_chunks_count": len(self.validator.rejected_chunks),
            "embedding_provider": self.config.embedding_provider,
            "embedding_model": self.embedding_provider.model_name,
            "embedding_dimension": self.embedding_provider.dimension,
            "vector_store_provider": self.config.vector_store_provider,
            "sources": source_summaries,
            "rejected_samples": self.validator.rejected_chunks[:5],
        }
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest_record, f, indent=2)

        return manifest_record
