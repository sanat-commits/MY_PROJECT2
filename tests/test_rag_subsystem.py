"""Unit and integration tests for Phase 5 RAG Knowledge Base and Retrieval subsystem."""

import hashlib
from pathlib import Path
import pytest

from src.rag.chunk_validation import ChunkValidator
from src.rag.chunking import StructureAwareChunker, generate_stable_chunk_id
from src.rag.config import RagConfig
from src.rag.embeddings import (
    DeterministicMockEmbeddingProvider,
    EmbeddingUnavailableError,
    OllamaEmbeddingProvider,
    get_embedding_provider,
)
from src.rag.evaluation import RetrievalEvaluator
from src.rag.extractors import AttackExtractor, MarkdownExtractor, SigmaExtractor
from src.rag.ingestion import KnowledgeBaseIngestor
from src.rag.lexical_search import BM25Index
from src.rag.retrieval import HybridRetriever
from src.rag.schemas import DocumentType, KnowledgeChunk, RawDocument, RetrievalStatus, SourceEntry
from src.rag.service import KnowledgeBaseService
from src.rag.vector_store import SQLiteVectorStore, get_vector_store


@pytest.fixture
def test_config():
    """Isolated test configuration using deterministic mock embeddings and SQLite store."""
    return RagConfig(
        vector_store_provider="sqlite",
        vector_store_path=Path("artifacts/test_vector_store"),
        lexical_index_path=Path("artifacts/test_vector_store/lexical_index.json"),
        index_manifest_path=Path("artifacts/test_vector_store/index_manifest.json"),
        embedding_provider="mock",
        embedding_dimension=768,
        embedding_model="mock-embedding-v1",
        collection_name="test_knowledge",
    )


@pytest.fixture
def sample_chunk():
    """Sample valid KnowledgeChunk fixture."""
    content = "Adversaries may use brute force attacks (T1110) to gain access to valid user accounts by attempting multiple passwords."
    return KnowledgeChunk(
        chunk_id="chk_test_01_abcdef123456",
        source_id="src_mitre_attack_enterprise",
        source_title="MITRE ATT&CK Enterprise",
        source_uri_or_path="https://attack.mitre.org/techniques/T1110",
        source_type=DocumentType.MITRE_ATTACK_STIX,
        source_version_or_date="v14.1",
        document_title="Brute Force (T1110)",
        heading_path=["Brute Force (T1110)"],
        chunk_index=0,
        content=content,
        content_hash=hashlib.sha256(content.encode("utf-8")).hexdigest(),
        token_count=25,
        parent_document_id="doc_test_t1110",
        technique_id="T1110",
        event_ids=["4625"],
    )


def test_sources_manifest_exists_and_valid():
    """Verify sources manifest exists, parses correctly, and references real files with valid hashes."""
    ingestor = KnowledgeBaseIngestor()
    sources = ingestor.load_sources_manifest()
    assert len(sources) >= 5, "Expected at least 5 approved knowledge sources in manifest"

    for src in sources:
        assert src.source_id.startswith("src_")
        assert src.title
        assert src.canonical_path
        p = Path(src.canonical_path)
        assert p.exists(), f"Source file does not exist: {p}"
        actual_hash = hashlib.sha256(p.read_bytes()).hexdigest()
        assert actual_hash == src.content_hash, f"Hash mismatch for {src.source_id}"


def test_attack_extractor_parses_techniques():
    """Verify AttackExtractor parses STIX bundle into individual RawDocuments."""
    extractor = AttackExtractor()
    src_entry = SourceEntry(
        source_id="src_test_attack",
        title="ATT&CK Fixture",
        canonical_path="data/mitre/enterprise_attack_fixture.json",
        canonical_url="https://attack.mitre.org",
        document_type=DocumentType.MITRE_ATTACK_STIX,
        version="v14.1",
        content_hash="7a0fe2a1c7d81f734b3b27397f6c3ddba854fd8871ffa685157579f9507d6fcf",
    )
    docs = extractor.extract(src_entry, Path.cwd())
    assert len(docs) >= 5
    tids = [d.metadata.get("technique_id") for d in docs]
    assert "T1110" in tids
    assert "T1078" in tids


def test_sigma_extractor_parses_yaml_rule():
    """Verify SigmaExtractor preserves rule structure, tags, and detection logic."""
    extractor = SigmaExtractor()
    src_entry = SourceEntry(
        source_id="src_test_sigma",
        title="Sigma Failed Logon",
        canonical_path="data/knowledge_base/sigma/sigma_win_failed_logon_burst.yml",
        canonical_url="https://github.com/SigmaHQ",
        document_type=DocumentType.SIGMA_RULE,
        version="2024-10-01",
        content_hash="test",
    )
    docs = extractor.extract(src_entry, Path.cwd())
    assert len(docs) == 1
    doc = docs[0]
    assert doc.document_type == DocumentType.SIGMA_RULE
    assert "4625" in doc.content
    assert "T1110" in doc.metadata.get("attack_technique_ids", [])


def test_markdown_extractor_parses_guide():
    """Verify MarkdownExtractor extracts content and title."""
    extractor = MarkdownExtractor()
    src_entry = SourceEntry(
        source_id="src_test_md",
        title="Windows Security Log Guide",
        canonical_path="data/knowledge_base/guides/windows_security_log_investigation.md",
        canonical_url="https://learn.microsoft.com",
        document_type=DocumentType.MARKDOWN_GUIDE,
        version="2024-08-01",
        content_hash="test",
    )
    docs = extractor.extract(src_entry, Path.cwd())
    assert len(docs) == 1
    assert "Event ID 4624" in docs[0].content


def test_structure_aware_chunking_deterministic_ids():
    """Verify chunk IDs are content-hash-backed and completely deterministic."""
    c1 = generate_stable_chunk_id("src_test", "doc_01", "This is a test content string", 0)
    c2 = generate_stable_chunk_id("src_test", "doc_01", "This is a test content string", 0)
    c3 = generate_stable_chunk_id("src_test", "doc_01", "Different content", 0)
    assert c1 == c2
    assert c1 != c3


def test_chunk_validation_accepts_valid(sample_chunk):
    """Verify valid chunk passes validation."""
    validator = ChunkValidator()
    res = validator.validate(sample_chunk)
    assert res.is_valid is True
    assert res.rejection_reason is None


def test_chunk_validation_rejects_empty_content(sample_chunk):
    """Verify validator rejects empty or whitespace-only content."""
    validator = ChunkValidator()
    invalid_chunk = sample_chunk.model_copy(update={"content": "   \n\t  "})
    res = validator.validate(invalid_chunk)
    assert res.is_valid is False
    assert "empty" in res.rejection_reason.lower()


def test_chunk_validation_rejects_missing_provenance(sample_chunk):
    """Verify validator rejects chunks missing source identity or content hash."""
    validator = ChunkValidator()
    invalid_chunk = sample_chunk.model_copy(update={"source_id": ""})
    res = validator.validate(invalid_chunk)
    assert res.is_valid is False
    assert "source_id" in res.rejection_reason.lower()


def test_deterministic_mock_embedding_provider():
    """Verify mock embedding provider generates unit-normalized vectors deterministically."""
    provider = DeterministicMockEmbeddingProvider(dimension=768)
    v1 = provider.embed_query("Security alert logon burst")
    v2 = provider.embed_query("Security alert logon burst")
    v3 = provider.embed_query("Unrelated quantum network")
    assert len(v1) == 768
    assert v1 == v2
    assert v1 != v3


def test_vector_store_persistence_and_idempotence(test_config, sample_chunk):
    """Verify vector store idempotent upsert prevents duplicate chunk accumulation."""
    vstore = SQLiteVectorStore(test_config)
    vstore.clear()
    assert vstore.count() == 0

    embed_provider = DeterministicMockEmbeddingProvider(dimension=768)
    vec = embed_provider.embed_documents([sample_chunk.content])

    # First insertion
    vstore.add_chunks([sample_chunk], vec)
    assert vstore.count() == 1

    # Re-inserting identical chunk ID must not increment count
    vstore.add_chunks([sample_chunk], vec)
    assert vstore.count() == 1

    # Search retrieves chunk
    results = vstore.search(vec[0], top_k=5)
    assert len(results) == 1
    assert results[0][0].chunk_id == sample_chunk.chunk_id
    assert results[0][1] > 0.99


def test_bm25_lexical_search(sample_chunk):
    """Verify BM25 index scores exact identifier tokens accurately."""
    bm25 = BM25Index()
    bm25.build([sample_chunk])
    assert bm25.doc_count == 1

    hits = bm25.search("T1110", top_k=5)
    assert len(hits) == 1
    assert hits[0][0].chunk_id == sample_chunk.chunk_id
    assert hits[0][1] > 0.0

    unrelated_hits = bm25.search("quantum cryptography", top_k=5)
    assert len(unrelated_hits) == 0


def test_hybrid_retrieval_success_and_tool_contract():
    """Verify search_knowledge_base returns compliant structure matching tool contract."""
    svc = KnowledgeBaseService()
    res = svc.search_knowledge_base("T1110", top_k=3)
    assert res.status == RetrievalStatus.SUCCESS
    assert res.count > 0
    top = res.results[0]
    assert top.chunk_id
    assert top.source_id
    assert top.source_title
    assert top.source_uri_or_path
    assert top.content
    assert top.fused_score > 0.0


def test_hybrid_retrieval_rejects_empty_query():
    """Verify empty query returns controlled INVALID_QUERY status."""
    svc = KnowledgeBaseService()
    res = svc.search_knowledge_base("   ")
    assert res.status == RetrievalStatus.INVALID_QUERY
    assert res.count == 0


def test_hybrid_retrieval_rejects_invalid_top_k():
    """Verify negative top_k returns INVALID_QUERY."""
    svc = KnowledgeBaseService()
    res = svc.search_knowledge_base("T1110", top_k=-1)
    assert res.status == RetrievalStatus.INVALID_QUERY
    assert res.count == 0


def test_hybrid_retrieval_rejects_out_of_scope_query():
    """Verify completely out-of-scope query returns NO_RESULTS without hallucinated chunks."""
    svc = KnowledgeBaseService()
    res = svc.search_knowledge_base("quantum cryptography satellite downlink communication protocols")
    assert res.status == RetrievalStatus.NO_RESULTS
    assert res.count == 0
    assert len(res.results) == 0


def test_retrieval_evaluation_benchmark_metrics():
    """Run full benchmark evaluation and verify quality metrics satisfy thresholds."""
    svc = KnowledgeBaseService()
    evaluator = RetrievalEvaluator(svc)
    metrics = evaluator.evaluate(top_k=5)

    assert metrics.total_queries >= 20
    assert metrics.answerable_queries >= 15
    assert metrics.unanswerable_queries >= 4
    assert metrics.recall_at_5 >= 0.90, f"Recall@5 ({metrics.recall_at_5}) below threshold 0.90"
    assert metrics.mrr >= 0.85, f"MRR ({metrics.mrr}) below threshold 0.85"
    assert metrics.exact_id_success_rate >= 0.85, f"Exact ID rate ({metrics.exact_id_success_rate}) below 0.85"
    assert metrics.no_answer_rejection_rate >= 0.90, f"Rejection rate ({metrics.no_answer_rejection_rate}) below 0.90"
    assert metrics.attribution_validity_rate == 1.0, "All returned chunks must have verified attribution"
