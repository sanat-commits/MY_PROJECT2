"""Data schemas and types for the RAG Knowledge Base subsystem."""

from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


class DocumentType(str, Enum):
    """Categorization of supported knowledge document formats."""
    MITRE_ATTACK_STIX = "mitre_attack_stix"
    SIGMA_RULE = "sigma_rule"
    MARKDOWN_GUIDE = "markdown_guide"
    PLAIN_TEXT = "plain_text"


class RetrievalStatus(str, Enum):
    """Standardized retrieval outcome statuses adhering to tool contract."""
    SUCCESS = "success"
    NO_RESULTS = "no_results"
    SOURCE_UNAVAILABLE = "source_unavailable"
    INVALID_QUERY = "invalid_query"
    RETRIEVAL_ERROR = "retrieval_error"


class SourceEntry(BaseModel):
    """Manifest record representing an approved knowledge source."""
    source_id: str
    title: str
    canonical_path: str
    canonical_url: str
    document_type: DocumentType
    version: str | None = None
    license: str | None = None
    retrieved_at: str | None = None
    content_hash: str
    status: str = "verified"


class RawDocument(BaseModel):
    """Extracted raw document representation before chunking."""
    document_id: str
    source_id: str
    title: str
    content: str
    document_type: DocumentType
    source_uri_or_path: str
    version_or_date: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class KnowledgeChunk(BaseModel):
    """Validated, attributable atomic chunk stored in vector and lexical indexes."""
    chunk_id: str
    source_id: str
    source_title: str
    source_uri_or_path: str
    source_type: DocumentType
    source_version_or_date: str | None = None
    document_title: str
    heading_path: list[str] = Field(default_factory=list)
    chunk_index: int = 0
    content: str
    content_hash: str
    token_count: int = 0
    parent_document_id: str
    technique_id: str | None = None
    rule_id: str | None = None
    event_ids: list[str] = Field(default_factory=list)


class ChunkValidationResult(BaseModel):
    """Report detailing whether a chunk passed quality checks."""
    is_valid: bool
    rejection_reason: str | None = None


class RetrievedChunk(BaseModel):
    """Search result chunk enriched with dense, lexical, and fused ranking metrics."""
    chunk_id: str
    source_id: str
    source_title: str
    document_title: str | None = None
    source_uri_or_path: str
    source_type: DocumentType
    source_version_or_date: str | None = None
    heading_path: list[str] = Field(default_factory=list)
    content: str
    dense_score: float | None = None
    dense_rank: int | None = None
    lexical_score: float | None = None
    lexical_rank: int | None = None
    fused_score: float
    fused_rank: int
    is_exact_match: bool = False
    technique_id: str | None = None
    rule_id: str | None = None


class RetrievalResult(BaseModel):
    """Standardized retrieval output conforming to docs/TOOL_CONTRACTS.md."""
    query: str
    status: RetrievalStatus
    results: list[RetrievedChunk] = Field(default_factory=list)
    count: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)


class EvalQuery(BaseModel):
    """Benchmark query record for evaluating retrieval quality."""
    query_id: str
    query: str
    category: str
    is_answerable: bool = True
    expected_source_ids: list[str] = Field(default_factory=list)
    expected_chunk_patterns: list[str] = Field(default_factory=list)
    target_technique_id: str | None = None
    target_event_id: str | None = None


class EvalMetrics(BaseModel):
    """Measured performance metrics computed across the evaluation benchmark."""
    total_queries: int
    answerable_queries: int
    unanswerable_queries: int
    recall_at_5: float
    precision_at_5: float
    mrr: float
    exact_id_success_rate: float
    no_answer_rejection_rate: float
    attribution_validity_rate: float
    evaluation_timestamp: str
    embedding_model: str
    vector_store_provider: str
