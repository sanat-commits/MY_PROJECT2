# Local Qwen 3 8B Security Investigation Engine

## 1. Overview & Architectural Role

The Local Qwen 3 8B Security Investigation Engine integrates a verified local instance of **Qwen 3 8B** (served via local Ollama on Windows) into the detection and analysis pipeline.

### Evidence Hierarchy & Non-Detection Principle
- **Detection & Scoring**: The LLM is **never** the primary detector. Feature extraction, machine learning anomaly detection (Phase 2), explainable risk scoring (Phase 3), MITRE ATT&CK behavior mapping (Phase 4), and cybersecurity knowledge retrieval (Phase 5) are performed deterministically by verified upstream modules.
- **LLM Role**: Qwen 3 8B synthesizes and explains the verified observations, correlates evidence against retrieved MITRE technique documents and Sigma rules, highlights ambiguities or missing telemetry, and suggests actionable, non-autonomous next investigation steps.
- **Probabilities & Verdicts**: Anomaly scores and risk scores are continuous anomaly indicators and heuristic risk weights—they are **not** probabilities of compromise. The LLM distinguishes observed facts from speculative interpretations and uses qualified cybersecurity terminology (`anomalous`, `suspicious`, `consistent with`, `requires investigation`).

```
Security Window (1-hr)
         │
         ▼
Phase 2 — Isolation Forest Anomaly Detection (score, calibrated is_anomaly)
         │
         ▼
Phase 3 — Explainable Risk Scoring Engine (SecurityAlert: severity, risk_score, audit breakdown)
         │
         ▼
Phase 4 — MITRE ATT&CK Mapping (verified technique IDs & tactics)
         │
         ▼
Phase 5 — Hybrid RAG Knowledge Retrieval (dense ChromaDB + lexical BM25, scored chunks)
         │
         ▼
Phase 6 — Local Qwen 3 8B Investigation Engine
         │
         ▼
Validated Investigation Report (deterministic citation verification & state preservation)
```

---

## 2. Local Model Discovery & Configuration

### Runtime Model Discovery
The engine discovers installed local models dynamically via Ollama's local HTTP API (`/api/tags`), preventing hardcoded identifiers or silent cloud fallback:
1. Queries `http://localhost:11434/api/tags` to list installed model tags.
2. Identifies candidates matching `qwen3:8b` (or parameterized variants).
3. Verifies model availability before accepting inference workloads.
4. If Ollama is unreachable or the configured model is absent, raises typed errors (`ProviderUnavailableError`, `ModelNotFoundError`) resulting in an explicit `BLOCKED` state.

### Configuration (`src/llm/config.py`)
Configured through environment variables or defaults:
| Variable | Default | Purpose |
|---|---|---|
| `LLM_PROVIDER` | `ollama` | Provider backend (`ollama` or `mock`) |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Local Ollama HTTP daemon endpoint |
| `OLLAMA_MODEL` | `qwen3:8b` | Verified installed model tag |
| `LLM_TIMEOUT_SECONDS` | `120.0` | Maximum wait time per inference request |
| `LLM_MAX_RETRIES` | `2` | Bounded retries for transient failures |
| `LLM_TEMPERATURE` | `0.0` | Deterministic sampling temperature |
| `LLM_MAX_OUTPUT_TOKENS` | `2048` | Output token generation limit |
| `LLM_CONTEXT_BUDGET_TOKENS` | `4096` | Upper limit for prompt context budgeting |

---

## 3. Provider Abstraction Layer

Implemented in `src/llm/provider.py` and `src/llm/ollama_provider.py`:
- **`LlmProvider`**: Abstract base class requiring `health_check()`, `discover_models()`, and `generate()`.
- **`OllamaLlmProvider`**: Production provider implementing communication with Ollama's `/api/generate` endpoint with `format: "json"`, timeout handling, and typed error raising.
- **`MockLlmProvider`**: Deterministic test fixture providing compliant structured JSON responses for isolated, rapid unit testing without requiring an active LLM daemon.

### Error Handling
- `ProviderUnavailableError`: Local Ollama daemon unreachable or down.
- `ModelNotFoundError`: Specified model tag not present on daemon.
- `RequestTimeoutError`: Inference exceeded configured timeout window.
- `MalformedResponseError`: Ollama daemon returned empty or non-200 response body.

---

## 4. Investigation Input Contract

Defined in `src/llm/schemas.py` as `InvestigationInput`:
- `investigation_id`: Deterministically derived identifier (`inv_<alert_id>_<sha256>`).
- `alert_id`: Immutable ID from Phase 3 `SecurityAlert`.
- `window_id`: Telemetry window reference.
- `risk_score`: Phase 3 calculated risk score (0.0–100.0).
- `severity`: Phase 3 severity enum (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- `score_breakdown`: Itemized score contribution audit.
- `evidence_items`: Observed signals and feature values.
- `mitre_status` & `mitre_candidates`: Verified Phase 4 technique mappings.
- `rag_status` & `rag_chunks`: Verified Phase 5 retrieved chunks with source provenance (`chunk_id`, `source_id`, `source_title`, `source_uri_or_path`, `content`).

---

## 5. Structured Investigation Report Schema

Defined in `src/llm/schemas.py` as `InvestigationReport`:
```json
{
  "investigation_id": "inv_alt_win_exit_001_...",
  "alert_id": "alt_win_exit_001",
  "summary": "Concise summary of observed activity",
  "supplied_severity": "HIGH",
  "supplied_risk_score": 78.5,
  "finding": "SUSPICIOUS_ACTIVITY",
  "observed_evidence": [
    {
      "source_field": "failed_logins",
      "observed_value": 35,
      "context": "35 failed authentication attempts detected"
    }
  ],
  "interpretation": "Interpretation distinguishing observations from possibilities",
  "possible_attack_techniques": ["T1110.001"],
  "uncertainty": "Telemetry limits and unconfirmed hypotheses",
  "recommended_next_steps": [
    "Verify source IP addresses in authentication logs",
    "Check Active Directory account lockout status"
  ],
  "citations": [
    {
      "chunk_id": "chk_mitre_attack_ent_00_099f5e7106bc",
      "source_id": "src_mitre_attack_enterprise",
      "source_title": "MITRE ATT&CK Enterprise Catalog",
      "source_uri_or_path": "https://attack.mitre.org/techniques/T1110"
    }
  ],
  "limitations": [
    "External threat intelligence was unavailable",
    "GeoIP telemetry not present in current log window"
  ]
}
```

### Finding Classifications (`FindingType`)
- `ANOMALOUS_ACTIVITY`: Statistical divergence from normal baseline without clear malicious signature.
- `SUSPICIOUS_ACTIVITY`: Behavioral signals align with attacker tradecraft patterns.
- `POSSIBLE_ATTACK`: Strong convergence of multiple high-risk indicators and matched techniques.
- `INSUFFICIENT_EVIDENCE`: Telemetry insufficient to substantiate attack hypotheses.

---

## 6. Output & Citation Validation

Implemented in `src/llm/output_validation.py` (`ReportValidator`):

1. **JSON Extraction & Schema Parsing**:
   - Strips code-fence backticks and unescaped markdown.
   - Parses into Pydantic schema with strict field typing.

2. **Application State Preservation Guarantee**:
   - The LLM **cannot** alter `alert_id`, `supplied_severity`, or `supplied_risk_score`.
   - The validator automatically overwrites or cross-checks these fields against the verified application input.

3. **Deterministic Citation Verification**:
   - Checks every chunk ID cited by the model against the list of chunks actually supplied in `InvestigationInput.rag_chunks`.
   - Any hallucinated chunk ID not present in the RAG context is **discarded**.
   - Enriches valid citations with authentic provenance metadata (`source_id`, `source_title`, `source_uri_or_path`) directly from the verified input.

---

## 7. Execution & Verification

### Fast Unit & Mock Tests
Run without requiring local Ollama:
```bash
pytest tests/test_llm_investigation.py -k "not test_real_local_qwen_smoke_test" -v
```

### Real Local Qwen 3 8B Smoke Test
Executes real local inference via Ollama:
```bash
pytest tests/test_llm_investigation.py -k "test_real_local_qwen_smoke_test" -v
```

### Phase 6 Exit Gate
Runs comprehensive verification gate:
```bash
python scripts/run_phase_exit_tests.py --phase 6
```
Exit Gate Output:
```
==================================================
Executing Phase 6 Exit Gate: Local Qwen 3 8B Security Investigation Engine
==================================================
[PASS] Phase 5 dependency is verified (RAG vector store artifacts present)
[PASS] local provider health is checked (Provider reachable=True at http://localhost:11434)
[PASS] installed Qwen 3 8B model is discovered (Found candidates in installed models: [... 'qwen3:8b' ...])
[PASS] selected model identity is verified (Configured model: qwen3:8b)
[PASS] local inference works (Model returned in 13.76s: { ... })
[PASS] no cloud fallback occurs (Provider=ollama, BaseURL=http://localhost:11434)
[PASS] investigation input schema is validated (Investigation ID=inv_alt_win_exit_001_...)
[PASS] prompt includes verified alert context (Prompt length=4274 chars, chunks=2)
[PASS] retrieved knowledge retains source identifiers (chunk_id=chk_mitre_attack_ent_00_099f5e7106bc)
[PASS] output parses into the report schema (Finding=FindingType.SUSPICIOUS_ACTIVITY)
[PASS] source citations are verified (Citation attached=chk_mitre_attack_ent_00_099f5e7106bc)
[PASS] severity and risk score remain unchanged (Validator enforced original application state)
[PASS] unsupported ATT&CK identifiers are rejected (Output validated cleanly)
[PASS] malformed model output is handled safely (OutputValidationError cleanly raised)
[PASS] provider/model failure paths work (ProviderUnavailableError cleanly raised on bad endpoint)
[PASS] end-to-end investigation produces a valid report (Report ID=inv_alt_win_exit_001_..., Finding=FindingType.SUSPICIOUS_ACTIVITY)
--------------------------------------------------
All Phase 6 Local Qwen 3 8B exit criteria satisfied.
PHASE 6: PASS
```

---

## 8. Known Limitations
1. **Cold-Start Latency**: Initial loading of `qwen3:8b` (5.22 GB GGUF) into VRAM on Windows can take 60–80 seconds; warm generation takes ~12–15 seconds. Timeout is configured to 120s.
2. **Context Budgeting**: Prompts cap RAG context to top chunks to remain strictly within the 4096-token input window budget.
3. **Structured Repair**: When LLM output fails schema validation, the current implementation records the failure and returns an explicit `INVALID_MODEL_OUTPUT` result without unconstrained retries.
