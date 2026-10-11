"""Configuration for the RAG Knowledge Base subsystem."""

from pathlib import Path
from pydantic import BaseModel, Field


class RagConfig(BaseModel):
    """Validated configuration for RAG knowledge base ingestion and retrieval."""

    # Paths and manifests
    sources_manifest_path: Path = Field(
        default=Path("data/knowledge_base/sources_manifest.json"),
        description="Path to JSON manifest of verified knowledge sources",
    )
    vector_store_path: Path = Field(
        default=Path("artifacts/vector_store"),
        description="Directory for persistent vector store storage",
    )
    lexical_index_path: Path = Field(
        default=Path("artifacts/vector_store/lexical_index.json"),
        description="Path for serialized lexical BM25 index",
    )
    index_manifest_path: Path = Field(
        default=Path("artifacts/vector_store/index_manifest.json"),
        description="Path for index manifest recording source provenance and versions",
    )
    collection_name: str = Field(
        default="security_knowledge",
        description="Vector store collection name",
    )

    # Provider selections
    vector_store_provider: str = Field(
        default="chroma",
        description="Vector store backend ('chroma' or 'sqlite')",
    )
    embedding_provider: str = Field(
        default="ollama",
        description="Embedding provider ('ollama' or 'mock')",
    )
    embedding_model: str = Field(
        default="embeddinggemma:latest",
        description="Exact model tag for local embedding generation",
    )
    embedding_dimension: int = Field(
        default=768,
        description="Expected vector dimensionality of the embedding model",
    )
    ollama_base_url: str = Field(
        default="http://localhost:11434",
        description="Base URL for local Ollama daemon",
    )
    ollama_timeout_seconds: float = Field(
        default=30.0,
        description="HTTP request timeout for Ollama embeddings API",
    )

    # Chunking limits
    max_chunk_tokens: int = Field(
        default=512,
        description="Target maximum token length per chunk",
    )
    chunk_overlap_tokens: int = Field(
        default=64,
        description="Token overlap between adjacent chunks in the same section",
    )
    min_chunk_chars: int = Field(
        default=25,
        description="Minimum character length for valid meaningful chunks",
    )

    # Retrieval parameters
    dense_top_k: int = Field(
        default=15,
        description="Number of candidates to retrieve from vector store",
    )
    lexical_top_k: int = Field(
        default=15,
        description="Number of candidates to retrieve from lexical BM25 index",
    )
    final_top_k: int = Field(
        default=5,
        description="Maximum number of relevant chunks to return to caller",
    )
    rrf_k: int = Field(
        default=60,
        description="Smoothing constant for Reciprocal Rank Fusion",
    )
    exact_id_boost: float = Field(
        default=0.05,
        description="Additive score boost for exact identifier matches (ATT&CK ID, Event ID, rule ID)",
    )
    relevance_score_threshold: float = Field(
        default=0.015,
        description="Minimum fused RRF score required for a chunk to be considered relevant",
    )
    min_dense_confidence: float = Field(
        default=0.60,
        description="Dense cosine similarity threshold for standalone semantic relevance",
    )
    min_lexical_confidence: float = Field(
        default=9.0,
        description="BM25 score threshold for standalone lexical relevance",
    )
    agreement_dense_min: float = Field(
        default=0.52,
        description="Minimum dense score required when both dense and lexical agree",
    )
    agreement_lexical_min: float = Field(
        default=6.0,
        description="Minimum BM25 score required when both dense and lexical agree",
    )

    @classmethod
    def from_env(cls, **overrides) -> "RagConfig":
        """Load configuration respecting environment variables and explicit overrides."""
        import os

        env_dict = {}
        if "VECTOR_STORE_PROVIDER" in os.environ:
            env_dict["vector_store_provider"] = os.environ["VECTOR_STORE_PROVIDER"]
        if "VECTOR_STORE_PATH" in os.environ:
            env_dict["vector_store_path"] = Path(os.environ["VECTOR_STORE_PATH"])
        if "OLLAMA_BASE_URL" in os.environ:
            env_dict["ollama_base_url"] = os.environ["OLLAMA_BASE_URL"]
        if "EMBEDDING_MODEL" in os.environ:
            env_dict["embedding_model"] = os.environ["EMBEDDING_MODEL"]
        if "EMBEDDING_PROVIDER" in os.environ:
            env_dict["embedding_provider"] = os.environ["EMBEDDING_PROVIDER"]

        env_dict.update(overrides)
        return cls(**env_dict)


def get_default_config() -> RagConfig:
    """Return default RagConfig initialized from environment."""
    return RagConfig.from_env()
