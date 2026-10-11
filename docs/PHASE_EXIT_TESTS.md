# Phase Exit Tests Specification

This document defines the formal exit criteria, commands, and expected outputs for each project phase.

## Phase 0 — Environment Discovery
- **Command**:
  - Verification of Python packages, Ollama daemon and Qwen model candidate.
  - `python scripts/verify_dataset.py`
  - `pytest tests/test_seed_dataset.py`
- **Exit Gate Criteria**:
  - Exact local LLM model tag detected without hallucination.
  - Baseline dataset present and verified.

## Phase 1 — Dataset Validation
- **Command**:
  ```bash
  python scripts/run_phase_exit_tests.py --phase 1
  ```
- **Exit Gate Output**:
  Must output:
  ```text
  PHASE 1: PASS
  ```
- **Exit Gate Criteria**:
  1. `data/security_windows_train_normal.csv` exists and has exactly 12,000 rows.
  2. `data/security_windows_eval_labeled.csv` exists and has exactly 4,000 rows.
  3. `data/dataset_manifest.json` exists with `synthetic: true`, `training_policy: normal_only`, matching row counts.
  4. Exact schema: all 22 required columns present, no extra or missing columns.
  5. Value completeness: zero nulls, NaNs, or empty strings.
  6. Semantic types: integer, float, and string constraints strictly satisfied.
  7. Value ranges: `hour` in `[0, 23]`, `day_of_week` in `[0, 6]`, binary flags in `{0, 1}`, non-negative counts.
  8. Internal consistency: `login_attempts == failed_logins + successful_logins` across 100% of rows.
  9. Weekend consistency: `is_weekend == 1` iff `day_of_week in (5, 6)`.
  10. Label constraints: training contains exclusively label `0` (`normal`); evaluation contains both `0` and `1`.
  11. Negative tests verify validator rejects malformed columns, broken ranges, label leaks, and invalid manifests.

## Phase 2 — Baseline ML
- **Command**:
  ```bash
  python scripts/run_phase_exit_tests.py --phase 2
  ```
- **Exit Gate Output**:
  Must output:
  ```text
  PHASE 2: PASS
  ```
- **Exit Gate Criteria**:
  1. `sklearn` and `joblib` dependencies verified.
  2. Training completes using normal-only data (`data/security_windows_train_normal.csv`).
  3. Strict feature isolation prevents label/metadata leakage.
  4. Preprocessor and Isolation Forest artifacts saved to `artifacts/ml/`.
  5. Saved artifacts load into independent `AnomalyDetector` instance without retraining.
  6. Saved feature schema matches implementation in exact canonical order (17 numeric behavioral features).
  7. Inference executes successfully and produces finite raw and derived anomaly scores for all rows.
  8. Threshold exists, is documented in `threshold.json`, and derived from training-normal distribution percentile.
  9. Deterministic reproducibility test passes (identical thresholds and predictions across independent runs).
  10. Evaluation metrics generated in `metrics.json` with F1 > 0.80.
  11. Schema mismatches and missing artifacts are rejected with controlled errors.

## Phase 3 — Explainable Risk Scoring
- **Command**:
  ```bash
  python scripts/run_phase_exit_tests.py --phase 3
  ```
- **Exit Gate Output**:
  Must output:
  ```text
  PHASE 3: PASS
  ```
- **Exit Gate Criteria**:
  1. Phase 2 dependency is available and verified (`AnomalyDetector` loads valid baseline model, preprocessor, threshold).
  2. Alert schema validates: all 10 required fields present and conform to `SecurityAlert` contract.
  3. Risk scoring is deterministic: repeated evaluations of identical inputs yield identical alert outputs.
  4. Risk score remains strictly bounded within $0.0 - 100.0$.
  5. Score breakdown reconciles with reported risk score within rounding tolerance ($\le 0.01$).
  6. Evidence corresponds directly to actual input fields and observed values without fabrication.
  7. Missing data is handled safely without fabrication (`missing_evidence` status with 0.0 pts).
  8. Severity bands work correctly at all numerical boundaries (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
  9. Configuration is validated and rejects invalid weight sums or corrupted constraints.
  10. Unsupported claims, unverified threat intelligence, and attack labels are not generated.
  11. Integration with actual Phase 2 inference scores real evaluation batches seamlessly.
  12. Negative tests pass for malformed predictions, mismatched window IDs, and invalid types.

## Phase 4 — MITRE ATT&CK Context
- **Command**:
  ```bash
  python scripts/run_phase_exit_tests.py --phase 4
  ```
- **Exit Gate Output**:
  Must output:
  ```text
  PHASE 4: PASS
  ```
- **Exit Gate Criteria**:
  1. Phase 3 dependency is available and verified (`RiskScoringConfig` v1.0.0 loaded).
  2. MITRE source and version metadata are valid (`domain=enterprise-attack`, `attack_version=v14.1`, source hash recorded).
  3. Catalog ingestion parses active techniques and tactics from verified STIX 2.1 fixture.
  4. Exact catalog lookup resolves known technique ID (`T1110` -> "Brute Force").
  5. Unknown technique returns explicit `not_found` status (`T9999`).
  6. Tactic/technique relationships and sub-technique hierarchies are preserved (`subtechnique-of` links).
  7. Mappings require verified behavioral evidence (`failed_logins >= 10` triggers `T1110`).
  8. Unsupported behaviors remain safely unmapped (`INSUFFICIENT_EVIDENCE` or `NOT_MAPPED`).
  9. Source metadata and canonical URLs are returned with all mappings.
  10. Original alert scores (`anomaly_score`, `risk_score`, `severity`) remain strictly unchanged.
  11. Catalog failures are handled safely with controlled exceptions without silent fallback.
  12. Invalid mapping rules targeting nonexistent techniques are rejected.
  13. Deterministic repeatability across independent runs.
  14. Negative tests pass (invalid ID syntax, empty queries, malformed STIX bundles).

## Phase 5 — RAG Knowledge Base
- **Command**:
  ```bash
  python scripts/run_phase_exit_tests.py --phase 5
  ```
- **Exit Gate Output**:
  Must output:
  ```text
  PHASE 5: PASS
  ```
- **Exit Gate Criteria**:
  1. Phase 4 dependency is verified (`MitreConfig` and `enterprise_attack_fixture.json` present).
  2. Approved source ingestion works (all 8 sources in `sources_manifest.json` load with verified SHA-256 digests).
  3. Source provenance is preserved (`index_manifest.json` records hashes, titles, versions, and timestamp).
  4. Structure-aware chunking works (heading hierarchy preserved with breadcrumbs).
  5. Structured ATT&CK objects remain traceable (canonical IDs, names, tactics retained).
  6. Sigma rules retain their meaningful structure (detection logic, conditions, tags, and rule ID preserved atomically).
  7. Invalid and incoherent chunks are rejected (empty, short, and missing-provenance chunks safely rejected).
  8. Chunk IDs are stable (deterministic content-hash IDs across runs).
  9. Embeddings work with the verified configured model (`embeddinggemma:latest` in local Ollama, 768 dimensions).
  10. Index persists across restart (loaded from disk without re-embedding).
  11. Repeated ingestion does not silently duplicate chunks (idempotent upsert preserves invariant chunk count).
  12. Dense retrieval works (returns nearest neighbors with positive similarity).
  13. Lexical retrieval works (BM25 matches exact tokens like `4625`).
  14. Hybrid retrieval works (RRF fusion returns SUCCESS with positive fused scores).
  15. Exact identifiers retrieve the correct source (`T1110` ranks canonical technique at top-1).
  16. Irrelevant/no-answer queries are handled safely (returns `NO_RESULTS` with zero chunks).
  17. Returned chunks include valid source metadata (100% provenance retention).
  18. Evaluation metrics are generated from actual queries (22 diverse benchmark queries).
  19. Retrieval benchmark acceptance criteria are met (Recall@5 $\ge 0.90$, MRR $\ge 0.85$, Exact ID $\ge 0.85$, Rejection $\ge 0.90$, Attribution $= 1.0$).
  20. Adversarial and negative tests pass (empty query and negative top_k return `INVALID_QUERY`).
  21. Serialized results comply with the tool contract (`docs/TOOL_CONTRACTS.md`).

## Phase 6 — Local Qwen 3 8B Security Investigation Engine
- **Command**:
  ```bash
  python scripts/run_phase_exit_tests.py --phase 6
  ```
- **Exit Gate Output**:
  Must output:
  ```text
  PHASE 6: PASS
  ```
- **Exit Gate Criteria**:
  1. Phase 5 dependency is verified (RAG vector store and BM25 index artifacts present).
  2. Local provider health is checked (Ollama reachable at configured base URL).
  3. Installed Qwen 3 8B model is discovered dynamically via `/api/tags` runtime check.
  4. Selected model identity is verified against installed tags.
  5. Local inference works and returns structured response within timeout.
  6. No cloud fallback occurs (strictly local Ollama runtime).
  7. Investigation input schema is validated (`InvestigationInput` preserves alert, ML, risk, MITRE, RAG context).
  8. Prompt includes verified alert context and maintains non-detection / non-fabrication rules.
  9. Retrieved knowledge retains source identifiers (`chunk_id`, `source_id`).
  10. Output parses into the report schema (`InvestigationReport`).
  11. Source citations are verified against actual retrieved chunks (hallucinations stripped).
  12. Severity and risk score remain unchanged (application state strictly enforced).
  13. Unsupported ATT&CK identifiers are rejected or filtered.
  14. Malformed model output is handled safely with explicit `OutputValidationError`.
  15. Provider/model failure paths work (`ProviderUnavailableError` on connection loss).
  16. End-to-end investigation produces a valid, grounded report using the real local model.

## Phase 7 — LangGraph Investigation Agent
- **Test Command**:
  ```powershell
  python scripts/run_phase_exit_tests.py --phase 7
  ```
- **Required Exit Status**:
  ```text
  PHASE 7: PASS
  ```
- **Exit Gate Criteria**:
  1. Phase 6 dependency is verified (InvestigationEngine, ReportValidator, local model runtime).
  2. Graph compiles (LangGraph StateGraph compiled with MemorySaver checkpointer).
  3. Valid investigation reaches a terminal state (status in [SUCCESS, INSUFFICIENT_EVIDENCE]).
  4. Registered tools have valid contracts (search_logs, get_related_events, search_knowledge_base, lookup_attack_technique).
  5. Tools call actual supported services (KnowledgeBaseService, MitreService).
  6. Action selection is validated (unapproved actions rejected with explicit error).
  7. Evidence is preserved correctly (observed evidence attached to final report).
  8. Tool errors remain explicit (malformed inputs return status=ERROR).
  9. No-result and unavailable-source states are distinguished (NO_RESULTS vs SOURCE_UNAVAILABLE).
  10. Maximum iterations are enforced (bounded loop prevention).
  11. Maximum tool calls are enforced (strict tool invocation budget).
  12. Total deadline and call timeouts are handled (TIMEOUT status on deadline expiry).
  13. Repeated unproductive actions are stopped (action history deduplication).
  14. Checkpoint/resume behavior matches implementation (MemorySaver preserves state per thread).
  15. The real local Qwen investigation path works (live Ollama Qwen 3 8B execution).
  16. Final report passes Phase 6 validation (ReportValidator validates output schema and citations).
  17. Original alert severity and score are unchanged (application state strictly preserved).
  18. Execution trace contains actual tool-call results (auditable TraceStep logs).
  19. End-to-end tests pass (complete workflow generates valid report).
  20. Negative tests pass (non-SecurityAlert payload raises ValueError).

## Phase 8 — Backend API
- **Test Command**:
  ```powershell
  python scripts/run_phase_exit_tests.py --phase 8
  ```
- **Required Exit Status**:
  ```text
  PHASE 8: PASS
  ```
- **Exit Gate Criteria**:
  1. Phase 7 dependency is verified (InvestigationWorkflow, ToolRegistry, AgentConfig).
  2. FastAPI application imports (create_app factory imported cleanly).
  3. API startup/configuration works (loopback host 127.0.0.1, port 8000, CORS origins).
  4. GET /health works (process liveness returning {"status": "ok"}).
  5. GET /status/model reflects real provider state (detects qwen3:8b without generation).
  6. GET /alerts returns real repository data (persisted evaluation windows scored via Phase 2-4).
  7. Alert pagination and validation work (422 on negative offset or oversized limit).
  8. GET /alerts/{alert_id} works (full structured alert with risk score, severity, breakdown).
  9. Unknown alert returns 404 (structured ErrorResponse with NOT_FOUND code).
  10. POST /alerts/{alert_id}/investigate calls real application service (triggers LangGraph agent).
  11. Successful investigation response follows report schema (investigation_id, report, trace).
  12. Investigation failures return controlled errors (404 on nonexistent alert, 422 on bad body).
  13. Score/severity/evidence cannot be overwritten by API clients (PUT/PATCH rejected with 405).
  14. Resource limits and timeout behavior are enforced (concurrency semaphore limits parallel LLM runs).
  15. CORS/network binding configuration is safe (loopback-only binding, restricted CORS).
  16. Logging includes request correlation (X-Correlation-ID header propagated).
  17. Persistence behaves correctly if implemented (InvestigationRepository stores runs).
  18. Integration tests pass (real local Qwen 3 8B model executed via FastAPI endpoint).
  19. Negative tests pass (malformed requests return structured error responses).

## Phase 9 — Dashboard (Upcoming)
- Implement analyst investigation dashboard UI and visual evidence graphs.



