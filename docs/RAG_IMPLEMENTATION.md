# RAG Implementation and Accurate Retrieval Specification

## 1. Overview and Architecture

The Phase 5 subsystem implements an enterprise-grade, measurable, and attributable **Retrieval-Augmented Generation (RAG)** knowledge retrieval pipeline for the AI-Powered Security Log Anomaly Detection project.

This subsystem provides ground-truth, source-backed context for security alerts, preparing structured domain intelligence for the local Qwen 3 8B LLM in Phase 6 without hallucination.

```text
Approved Knowledge Sources (ATT&CK STIX, Sigma YAML, Markdown Guides)
                               |
                               v
               Cryptographic Checksum Validation
                               |
                               v
                   Type-Specific Extractors
                               |
                               v
                   Structure-Aware Chunking
                               |
                               v
              Chunk Quality & Provenance Validation
                               |
                               v
                     Stable Content-Hash IDs
                               |
            +------------------+------------------+
            |                                     |
            v                                     v
Dense Embeddings (Ollama 768-d)          Lexical Inverted Index (BM25)
            |                                     |
            v                                     v
Persistent Vector Store (Chroma/SQLite)   Persistent Lexical Store (JSON)
            |                                     |
            +------------------+------------------+
                               |
                               v
               Reciprocal Rank Fusion (RRF k=60)
                               |
                               v
              Exact Identifier Boosting (T####, EventID)
                               |
                               v
             Multi-Stage Relevance Verification Filter
                               |
                               v
             Attributable, Deduplicated Chunks
                               |
                               v
              Standardized Retrieval Result (Tool Contract)
```

---

## 2. Knowledge Sources and Provenance

All knowledge sources are explicitly registered in [`data/knowledge_base/sources_manifest.json`](file:///c:/Users/upadh/OneDrive/Desktop/Proj2/ai_security_log_anomaly_project_starter/data/knowledge_base/sources_manifest.json) with cryptographic SHA-256 digests:

| Source ID | Title | Document Type | Version | Canonical Reference | Verified SHA-256 Digest |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `src_mitre_attack_enterprise` | MITRE ATT&CK Enterprise Catalog | `mitre_attack_stix` | v14.1 | [`data/mitre/enterprise_attack_fixture.json`](file:///c:/Users/upadh/OneDrive/Desktop/Proj2/ai_security_log_anomaly_project_starter/data/mitre/enterprise_attack_fixture.json) | `7a0fe2a1c7d81f734b3b27397f6c3ddba854fd8871ffa685157579f9507d6fcf` |
| `src_sigma_failed_logon_burst` | Potential Windows Failed Logon Burst | `sigma_rule` | 2024-10-01 | [`data/knowledge_base/sigma/sigma_win_failed_logon_burst.yml`](file:///c:/Users/upadh/OneDrive/Desktop/Proj2/ai_security_log_anomaly_project_starter/data/knowledge_base/sigma/sigma_win_failed_logon_burst.yml) | `85a5c0e0a196ffc3a18aaee2d4d4303094e51e40d121c6e6c27afe91fafe2e8b` |
| `src_sigma_privileged_user_creation` | Suspicious Privileged Group Member Addition | `sigma_rule` | 2024-02-10 | [`data/knowledge_base/sigma/sigma_win_privileged_user_creation.yml`](file:///c:/Users/upadh/OneDrive/Desktop/Proj2/ai_security_log_anomaly_project_starter/data/knowledge_base/sigma/sigma_win_privileged_user_creation.yml) | `c1939a74cd8e93957f2ec98158f939c4ccba418f524cd35ae426c02886b173d3` |
| `src_sigma_rare_process_cmdline` | Execution of Suspicious Shell or Scripting Interpreter | `sigma_rule` | 2024-03-01 | [`data/knowledge_base/sigma/sigma_proc_rare_process_cmdline.yml`](file:///c:/Users/upadh/OneDrive/Desktop/Proj2/ai_security_log_anomaly_project_starter/data/knowledge_base/sigma/sigma_proc_rare_process_cmdline.yml) | `69375a7e0058c9b8f378161e1875a63e90bf9be84307c768cf76bec972b6b275` |
| `src_sigma_high_volume_data_exfil` | High Volume Network Egress Connection Burst | `sigma_rule` | 2024-03-15 | [`data/knowledge_base/sigma/sigma_net_high_volume_data_exfil.yml`](file:///c:/Users/upadh/OneDrive/Desktop/Proj2/ai_security_log_anomaly_project_starter/data/knowledge_base/sigma/sigma_net_high_volume_data_exfil.yml) | `bebd937f0ead826ca077335fdfdd7bd292f313c810741374f2ded32f514b867e` |
| `src_guide_windows_security_log` | Windows Security Event Log Investigation Guide | `markdown_guide` | 2024-08-01 | [`data/knowledge_base/guides/windows_security_log_investigation.md`](file:///c:/Users/upadh/OneDrive/Desktop/Proj2/ai_security_log_anomaly_project_starter/data/knowledge_base/guides/windows_security_log_investigation.md) | `a1946a6228f2600972b72632ac60145e90bbb9cad3684147329b8386afcb6951` |
| `src_guide_auth_anomalies` | Threat Hunting Guide: Authentication Anomalies | `markdown_guide` | 2024-09-01 | [`data/knowledge_base/guides/threat_hunting_authentication_anomalies.md`](file:///c:/Users/upadh/OneDrive/Desktop/Proj2/ai_security_log_anomaly_project_starter/data/knowledge_base/guides/threat_hunting_authentication_anomalies.md) | `bcfdd72f6a6eac96e0fb18cd702d4e5158b5191acb5ba40652d2d3b998b7c1ce` |
| `src_guide_data_exfil` | Incident Response Playbook: Data Exfiltration | `markdown_guide` | 2024-09-15 | [`data/knowledge_base/guides/incident_response_data_exfiltration.md`](file:///c:/Users/upadh/OneDrive/Desktop/Proj2/ai_security_log_anomaly_project_starter/data/knowledge_base/guides/incident_response_data_exfiltration.md) | `253015f3cc2e505350d4de79522535915eee3d1b433798dae1e1203a22f5a92c` |

---

## 3. Extraction and Structure-Aware Chunking

Naive fixed-character window chunking destroys cybersecurity context. The chunking pipeline in [`src/rag/chunking.py`](file:///c:/Users/upadh/OneDrive/Desktop/Proj2/ai_security_log_anomaly_project_starter/src/rag/chunking.py) implements three distinct structure-aware strategies:

### A. MITRE ATT&CK Objects
- Preserves individual technique entities (`attack-pattern`).
- Injects canonical ID, name, tactic relationships, platforms, and data sources into every child chunk.
- If a technique description exceeds the 512-token ceiling, paragraphs are split into parts while retaining the parent technique metadata header in every slice.

### B. Sigma Rules
- Rules are treated as atomic retrieval units.
- Detection logic, conditions, false positives, tags, and severity levels are kept in a single chunk to prevent decoupling detection logic from field names.

### C. Markdown Guides
- Recursive splitting follows heading hierarchy (`H1 -> H2 -> H3`).
- Maintains `heading_path` in metadata and prepends breadcrumb context (e.g. `# Title > Section > SubSection`) to each chunk.

### Stable Chunk Identifier Specification
Chunk IDs are deterministically derived from source and content hashes:
$$\text{chunk\_id} = \text{chk\_}\{\text{source\_slug}\}\_\{\text{index:02d}\}\_\{\text{sha256}(\text{source\_id} + \text{doc\_id} + \text{normalized\_content})[:12]\}$$
Repeated ingestion of identical content yields identical chunk IDs, preventing duplicate accumulation.

---

## 4. Chunk Quality Validation Gates

Before embedding and indexing, all chunks must pass the [`ChunkValidator`](file:///c:/Users/upadh/OneDrive/Desktop/Proj2/ai_security_log_anomaly_project_starter/src/rag/chunk_validation.py):
1. **Content Completeness**: Rejects empty or whitespace-only content, or content shorter than 25 characters.
2. **Token Ceiling**: Rejects chunks exceeding hard ceiling ($512 \times 2.5 = 1280$ tokens).
3. **Mandatory Provenance**: Requires `chunk_id`, `source_id`, `source_title`, `source_uri_or_path`, `parent_document_id`, and `content_hash`.
4. **Boilerplate / Artifact Check**: Rejects chunks where $>60\%$ of lines consist of markup delimiters (`---`, ```` ````) or generic boilerplate.

---

## 5. Embedding Provider and Vector Storage

### Embedding Model
- **Provider**: Local Ollama runtime (`http://localhost:11434`) via [`OllamaEmbeddingProvider`](file:///c:/Users/upadh/OneDrive/Desktop/Proj2/ai_security_log_anomaly_project_starter/src/rag/embeddings.py).
- **Model Tag**: `embeddinggemma:latest` (307.58M parameters, GGUF BF16).
- **Dimensionality**: 768 float values.
- **Fail-Safe**: If Ollama daemon is unreachable or the model tag is missing, raises `EmbeddingUnavailableError` (reported as `BLOCKED` in exit tests). No silent cloud fallback or mock substitution in production mode.
- **Unit Testing**: Offline test harness uses [`DeterministicMockEmbeddingProvider`](file:///c:/Users/upadh/OneDrive/Desktop/Proj2/ai_security_log_anomaly_project_starter/src/rag/embeddings.py) generating unit-normalized pseudo-vectors seeded deterministically from text hashes.

### Vector Store
- **Primary Backend**: `chromadb.PersistentClient` storing vectors and metadata to [`artifacts/vector_store/`](file:///c:/Users/upadh/OneDrive/Desktop/Proj2/ai_security_log_anomaly_project_starter/artifacts/vector_store) with HNSW cosine metric space.
- **Alternative Backend**: Embedded zero-dependency [`SQLiteVectorStore`](file:///c:/Users/upadh/OneDrive/Desktop/Proj2/ai_security_log_anomaly_project_starter/src/rag/vector_store.py) (`sqlite_vector_store.db`) using NumPy matrix dot products.
- **Idempotency**: Chunks are upserted by `chunk_id`. Repeated ingestion leaves chunk counts invariant (29 chunks).

---

## 6. Hybrid Retrieval and Exact Identifier Boosting

Dense vector search alone struggles with exact alphanumeric identifiers (`T1110`, `4625`), while keyword search struggles with conceptual paraphrases. The [`HybridRetriever`](file:///c:/Users/upadh/OneDrive/Desktop/Proj2/ai_security_log_anomaly_project_starter/src/rag/retrieval.py) solves this via:

1. **Dense Semantic Search**: Top 15 candidates by cosine similarity.
2. **Lexical BM25 Search**: Top 15 candidates scored by Okapi BM25 ($k_1=1.5, b=0.75$).
3. **Exact Identifier Recognition**: Regex extraction for ATT&CK techniques (`T\d{4}(\.\d{3})?`) and Windows Event IDs (`4624`, `4625`, `4688`, `4672`).
4. **Reciprocal Rank Fusion (RRF)**:
   $$\text{RRF}(d) = \frac{1}{60 + \text{rank}_{\text{dense}}(d)} + \frac{1}{60 + \text{rank}_{\text{lexical}}(d)} + \text{boost}_{\text{exact}}$$
   where $\text{boost}_{\text{exact}} = 0.05$ and marks candidate with `is_exact_match = True`.
5. **Diversity Deduplication**: Caps chunks at 2 per parent document to prevent a single document from dominating results.

---

## 7. Multi-Stage Relevance Verification Policy

To prevent the vector store from returning nearest neighbors for out-of-scope queries (hallucination resistance), candidate chunks must satisfy at least one calibrated gate:

1. **Exact Identifier Match**: `is_exact_match == True`.
2. **Strong Dual Agreement**: `dense_score >= 0.52` AND `lexical_score >= 6.0`.
3. **High Dense Semantic Confidence**: `dense_score >= 0.60`.
4. **High Lexical Confidence**: `lexical_score >= 9.0`.

If no candidates meet these criteria, the query returns `RetrievalStatus.NO_RESULTS` with an empty result list.

---

## 8. Benchmark Evaluation and Measured Results

The evaluation suite ([`src/rag/evaluation.py`](file:///c:/Users/upadh/OneDrive/Desktop/Proj2/ai_security_log_anomaly_project_starter/src/rag/evaluation.py)) tests 22 ground-truth queries in [`data/knowledge_base/retrieval_eval.jsonl`](file:///c:/Users/upadh/OneDrive/Desktop/Proj2/ai_security_log_anomaly_project_starter/data/knowledge_base/retrieval_eval.jsonl) across 10 categories.

### Measured Performance Summary
Report generated at [`artifacts/knowledge_base/retrieval_eval_report.json`](file:///c:/Users/upadh/OneDrive/Desktop/Proj2/ai_security_log_anomaly_project_starter/artifacts/knowledge_base/retrieval_eval_report.json):

| Metric | Target Threshold | Measured Score | Outcome |
| :--- | :--- | :--- | :--- |
| **Total Benchmark Queries** | $\ge 20$ | **22** | PASS |
| **Answerable Queries** | $\ge 15$ | **18** | PASS |
| **Unanswerable Queries** | $\ge 4$ | **4** | PASS |
| **Recall@5** | $\ge 90.0\%$ | **100.0%** (18/18) | PASS |
| **Precision@5** | $\ge 70.0\%$ | **91.67%** | PASS |
| **Mean Reciprocal Rank (MRR)** | $\ge 0.85$ | **1.00** (18/18 at Rank 1) | PASS |
| **Exact ID Retrieval Success Rate** | $\ge 85.0\%$ | **92.86%** | PASS |
| **No-Answer Rejection Rate** | $\ge 90.0\%$ | **100.0%** (4/4 rejected) | PASS |
| **Source Attribution Validity Rate** | $100.0\%$ | **100.0%** (46/46 valid) | PASS |

---

## 9. Tool Contract Adherence

The subsystem implements `search_knowledge_base` matching [`docs/TOOL_CONTRACTS.md`](file:///c:/Users/upadh/OneDrive/Desktop/Proj2/ai_security_log_anomaly_project_starter/docs/TOOL_CONTRACTS.md):

```python
from src.rag.service import KnowledgeBaseService

service = KnowledgeBaseService()
result = service.search_knowledge_base("T1110", top_k=5)
# Returns: RetrievalResult(query="T1110", status=RetrievalStatus.SUCCESS, results=[...], count=3)
```

Each item in `results` contains:
- `chunk_id`: Stable identifier (e.g., `chk_mitre_attack_ent_00_099f5e7106bc`)
- `source_id`: Manifest reference (`src_mitre_attack_enterprise`)
- `source_title`: Curated title ("MITRE ATT&CK Enterprise Catalog")
- `document_title`: Technique name ("Brute Force (T1110)")
- `source_uri_or_path`: Canonical reference URL or file path
- `source_type`: `mitre_attack_stix`, `sigma_rule`, `markdown_guide`
- `source_version_or_date`: Release tag ("v14.1")
- `heading_path`: Breadcrumb hierarchy
- `content`: Extracted markdown text
- `dense_score`, `dense_rank`: Dense vector metrics
- `lexical_score`, `lexical_rank`: BM25 metrics
- `fused_score`, `fused_rank`: RRF composite score
- `is_exact_match`: Exact identifier indicator

---

## 10. Operational Commands

- **Run Phase 5 Exit Gate**:
  ```bash
  python scripts/run_phase_exit_tests.py --phase 5
  ```
- **Run Subsystem Pytest Suite**:
  ```bash
  pytest tests/test_rag_subsystem.py -v
  ```
- **Re-ingest Knowledge Base**:
  ```bash
  python -c "from src.rag.ingestion import KnowledgeBaseIngestor; KnowledgeBaseIngestor().ingest_all(force_rebuild=True)"
  ```
- **Run Benchmark Evaluation**:
  ```bash
  python -c "from src.rag.service import KnowledgeBaseService; from src.rag.evaluation import RetrievalEvaluator; print(RetrievalEvaluator(KnowledgeBaseService()).evaluate())"
  ```

---

## 11. Known Limitations

1. **Local Daemon Dependency**: Dense embeddings require the local Ollama daemon to be running on `http://localhost:11434` with `embeddinggemma:latest`. Offline unit tests use the deterministic mock provider.
2. **Corpus Size**: The initial curated corpus contains 8 authoritative sources producing 29 chunks. Expanding to thousands of documents in later phases may benefit from an approximate vector index or cross-encoder reranker.
3. **Evaluation Benchmark Breadth**: The benchmark contains 22 source-grounded queries. Future phases may expand to multi-turn conversational evaluation.
