# Limitations and Future Work

This document records the known constraints, open risks, and planned improvements
for the **AI-Powered Security Log Anomaly Detection & Investigation** project.

> [!IMPORTANT]
> This system is a **portfolio/research demonstrator** built on synthetic data.
> It is **not production-ready** and must not be deployed against live organisational
> telemetry without independent security review, data-governance approval, and
> significant hardening.

---

## 1. Data Limitations

### 1.1 Synthetic data only
All training, evaluation, and benchmark data is deterministically generated
(`scripts/seed_dataset.py`). The synthetic windows represent 1-hour behavioural
aggregates and are not derived from real organisational telemetry.

**Impact**: Precision/recall/F1 metrics reported in the evaluation reflect
performance on generated benchmarks. Real-world anomaly coverage is unknown.

**Future work**: Ingest public log datasets (e.g., LANL, CERT Insider Threat
dataset with appropriate clearance, or public PCAP-derived windows) to measure
real-world generalisation.

### 1.2 Feature coverage
The Isolation Forest is trained on 17 numeric behavioural features. Network flow
statistics, endpoint process trees, file-system events, and raw EVTX entries are
not modelled.

**Future work**: Expand feature engineering to include process-ancestry graphs,
DNS query patterns, and file-hash reputation lookups.

### 1.3 No live streaming
The pipeline operates on pre-computed 1-hour windows. There is no real-time
stream-processing integration (Kafka, Kinesis, Splunk HEC, etc.).

**Future work**: Add a streaming ingestion adapter with windowed feature
aggregation.

---

## 2. Model Limitations

### 2.1 Isolation Forest is an unsupervised baseline
The model is not calibrated; its output is a relative anomaly score, not a
probability. High scores indicate deviation from the training normal distribution
but do not confirm malicious activity.

**Impact**: The threshold is set at the 95th percentile of the training normal
distribution, producing an expected ~5% false-positive rate on in-distribution
normal data. Out-of-distribution shifts may produce higher FPR.

**Future work**: Train and compare supervised classifiers (Random Forest, XGBoost)
on labelled data; implement conformal prediction for calibrated uncertainty bands.

### 2.2 Threshold is static
The anomaly threshold is derived once at training time and does not adapt to
concept drift.

**Future work**: Implement sliding-window threshold recalibration or online
learning to handle distribution shift.

### 2.3 No categorical features
`user_role` and `host_type` are excluded from the baseline to avoid arbitrary
ordinal encoding (see ADR-007).

**Future work**: Encode categoricals via target encoding or separate embeddings
and ablate against the baseline.

---

## 3. LLM / Inference Limitations

### 3.1 Inference latency (~180s per investigation)
Local Qwen 3 8B inference on CPU (or CPU+swap) on a Windows consumer machine
takes approximately 150–200 seconds per investigation. This is a fundamental
constraint of running a large model locally without a GPU.

**Impact**: The frontend displays a live elapsed timer and disables the
investigation button during active runs to prevent duplicate submissions.
The backend enforces an `asyncio.Semaphore(1)` to serialise model execution.

**Future work**: Offload to a machine with a dedicated GPU, or implement
quantised 4-bit model variants (GGUF) to reduce latency to ~10–30s.

### 3.2 No model fine-tuning
Qwen 3 8B is used off-the-shelf. It has not been fine-tuned on cybersecurity
investigation reports.

**Future work**: Curate a supervised fine-tuning dataset of analyst
investigation notes and fine-tune or LoRA-adapt the model.

### 3.3 Single model, no ensemble
Only one LLM (Qwen 3 8B) is used. There is no consensus or debate mechanism
between models.

**Future work**: Implement a multi-model debate pattern or use a smaller model
for rapid triage and a larger model for deep investigation.

### 3.4 Structured output is not guaranteed
Although the `ReportValidator` enforces schema compliance after the fact, the
model may produce malformed JSON or refuse to produce a structured report on
certain inputs. In these cases the investigation returns an
`INVALID_MODEL_OUTPUT` status rather than fabricating a result.

---

## 4. RAG Limitations

### 4.1 Static knowledge base
The RAG knowledge base is seeded once from approved sources (MITRE ATT&CK
v14.1, selected Sigma rules, and security guides). It does not automatically
ingest new threat intelligence.

**Future work**: Implement scheduled re-ingestion with integrity verification
when upstream sources publish updates.

### 4.2 Embedding model availability
The system uses `embeddinggemma:latest` (768-d) via Ollama. If Ollama is
unavailable the RAG pipeline returns `NO_RESULTS` rather than a hallucinated
response. However, this degrades investigation quality significantly.

**Future work**: Support a fallback local embedding model (e.g., `all-MiniLM-L6-v2`
via sentence-transformers) that does not require Ollama.

### 4.3 No re-ranking
Retrieved chunks are ranked by Reciprocal Rank Fusion (dense + lexical). No
cross-encoder re-ranker is applied.

**Future work**: Add a lightweight cross-encoder re-ranker to improve
precision@1.

---

## 5. MITRE ATT&CK Limitations

### 5.1 Static catalog version
The MITRE ATT&CK Enterprise catalog is pinned at v14.1. Newer techniques or
sub-techniques added in later versions are not mapped.

**Future work**: Add a version-pinned update workflow and record catalog version
in every alert's MITRE context block.

### 5.2 Conservative mapping
The mapping engine only assigns a technique when strong behavioural evidence is
present. Low-evidence alerts return `INSUFFICIENT_EVIDENCE`. This intentionally
reduces false ATT&CK assignments at the cost of lower technique coverage.

---

## 6. API and Frontend Limitations

### 6.1 Loopback-only binding
The FastAPI backend binds to `127.0.0.1` by default to prevent accidental
network exposure. External access requires a reverse proxy (e.g., Nginx with
mTLS) and appropriate network security controls.

### 6.2 No authentication or authorisation
There is no user authentication, API key validation, or role-based access
control. This is acceptable for a local single-user demonstrator but is a
critical gap for any team deployment.

**Future work**: Implement OAuth 2.0 / OIDC authentication with analyst and
admin roles.

### 6.3 No persistent investigation storage
Investigation results are stored in memory and in local JSON artifact files.
There is no database backend; results are lost on server restart unless
artifact files are preserved.

**Future work**: Integrate a lightweight SQLite or PostgreSQL backend with
migration support.

### 6.4 Single-user concurrency model
The `asyncio.Semaphore(1)` prevents concurrent model invocations but also means
only one analyst can run an AI investigation at a time. On a shared deployment
this would create a queue bottleneck.

**Future work**: Implement a bounded async worker queue with position reporting.

---

## 7. Security and Privacy Limitations

### 7.1 Synthetic data disclosure
All data is labelled as synthetic in the UI, API responses, and documentation.
The system must not be pointed at real organisational logs without a full data
classification, consent, and governance review.

### 7.2 No secrets scanning
The repository does not yet integrate automated secret-scanning (e.g.,
`gitleaks`, `detect-secrets`). Developers must manually ensure `.env` files
are not committed.

**Future work**: Add pre-commit hooks for secret scanning.

### 7.3 No supply-chain integrity verification for Python packages
Python dependencies are not pinned to exact hashes in `pyproject.toml`.

**Future work**: Pin dependencies and generate a `requirements.txt` with
`pip-compile --generate-hashes`.

---

## 8. Evaluation Limitations

### 8.1 Benchmark queries are hand-checked, not crowd-verified
The RAG retrieval benchmark (`data/knowledge_base/retrieval_eval.jsonl`) was
constructed manually and has not been independently validated by domain experts.

### 8.2 No held-out test set
The evaluation uses the same labeled evaluation split used during threshold
selection. A separate, completely held-out test set was not created.

**Future work**: Reserve 20% of anomaly rows as a blind test set from the
outset.

### 8.3 End-to-end LLM evaluation not automated
Full end-to-end LLM investigation evaluation requires ~180s per test case.
The automated evaluation script (`evaluate_structured_output.py`) tests only
the deterministic validation layer; full model output quality is assessed
manually via the dashboard.

---

*Last updated: Phase 10 completion*
