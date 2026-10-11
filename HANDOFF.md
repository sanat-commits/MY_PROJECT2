# Handoff

Current phase: Phase 10 — COMPLETE (all phases 0–10 done)

Phase 10 status: PASS

### Recent Updates & Bug Fixes
- **Explainable Anomaly Characterization Service**:
  - Implemented reusable, evidence-based behavioral categorization engine (`src/risk_scoring/characterization.py`) that maps verified telemetry features against documented 99th percentile baseline thresholds without mutating ML decision functions, risk scores, or operational severities.
  - Implemented 5 versioned behavioral rules: `RULE_CHAR_OFF_HOURS` (`OFF_HOURS_ACTIVITY`), `RULE_CHAR_FAILED_AUTH` (`REPEATED_FAILED_AUTHENTICATION`), `RULE_CHAR_PROCESS_ACTIVITY` (`UNUSUAL_PROCESS_ACTIVITY`), `RULE_CHAR_NETWORK_ACTIVITY` (`UNUSUAL_NETWORK_ACTIVITY`), and `RULE_CHAR_OUTBOUND_DATA` (`UNUSUAL_OUTBOUND_DATA_ACTIVITY`).
  - Added support for `MULTIPLE_BEHAVIORAL_ANOMALIES` when concurrent rules match, and honest fallback to `UNCLASSIFIED_ANOMALY` when an Isolation Forest outlier does not breach individual univariate baselines.
  - Strict leakage prevention: runtime categorization purges and completely ignores synthetic labels (`label`, `anomaly_type`, `ground_truth`).
  - Attached characterization contract (`AnomalyCharacterization`) to `SecurityAlert` in `src/risk_scoring/schema.py` and `RiskEngine.score_alert()` in `src/risk_scoring/engine.py`.
  - Added backward-compatible loading: older alerts lacking characterization deserialize cleanly with `None` without fabricating historical classifications.
- **Score-Breakdown Consistency Root Cause & Fix**:
  - **Root Cause**: Backend `EvidenceItem` defined `contribution: float` and `comparison_or_rule: str`. Frontend `AlertDetailView.tsx` expected `item.score_contribution` and `item.threshold_or_baseline`. Because `score_contribution` was undefined on backend objects, the frontend fell back via `|| 0` to display `+0.0` alongside explanations stating `contributed 5.00 points`. Additionally, backend `ScoreBreakdown` serialized `ml_anomaly` and `behavioral_components` without a unified `components` array, causing Section B to state "Breakdown components not supplied by backend response".
  - **Fix**: Updated `EvidenceItem` with backward-compatible alias fields (`score_contribution`, `threshold_or_baseline`) synchronized via model validators. Updated `ScoreBreakdown` to automatically populate unified `components` list. Updated frontend `AlertDetailView.tsx` to read `item.contribution ?? item.score_contribution` and render explicit `'Unavailable'` rather than silently replacing missing values with `0.0`.
- **Frontend Dashboard Anomaly Classification Section**:
  - Added dedicated `ANOMALY CLASSIFICATION` card in `AlertDetailView.tsx` displaying primary human-readable category, rule IDs, additional categories, detailed observation analysis, supporting signal table with observed values and baseline conditions, and explicit uncertainty notice.
  - Visually and semantically distinguishes `CHARACTERIZED`, `UNCLASSIFIED`, `INSUFFICIENT_EVIDENCE`, `SERVICE_ERROR`, and `NOT_ANOMALOUS` states.
- **Collapsible RAG Knowledge Citations**: Resolved an issue where clicking knowledge base citations on the Alert Detail page did not reveal content. Ensured the expansion drawer always renders structured metadata (Document title, Source ID, Source path/URL), added accessible keyboard navigation (`Enter`/`Space`), and enriched citation payloads across backend schemas (`ReportCitation`), output validation (`ReportValidator`), and persistent cache (`investigations_cache.json`) with grounded knowledge excerpts (`relevant_text`).
- **Clean Label Formatting**: Removed redundant icon symbols and emojis from KPI cards (Critical, High, Medium, Low, Total Alerts), severity badges, navbar connection badges (API Live/Offline), System Status cards (Backend API Process, Pipeline Readiness, Local Qwen 3 8B), dependency breakdowns, and Alert Detail card headers for a clean, high-readability SOC dashboard appearance.

---

## Phase 10 — Evaluation and Resume Readiness

### Evaluation Results

All four sub-evaluations completed with PASS status (API evaluation requires a
live backend and is documented as optional — see below).

| Sub-evaluation | Status | Key Metrics |
|---|---|---|
| ML Anomaly Detection (Phase 2) | PASS | F1=0.9458, Precision=0.9491, Recall=0.9425, FPR=0.0505, ROC-AUC=0.9896 |
| RAG Retrieval Quality (Phase 5) | PASS | Recall@5=1.0, MRR=1.0, Rejection rate=1.0, Attribution=1.0 |
| Structured Output Validation (Phase 6) | PASS | 6/6 cases, technique stripping, citation verification, field immutability |
| Agent Reliability (Phase 7) | PASS | 10/10 cases, all 4 tool contracts verified, budget limits confirmed |

### New Artifacts

**Evaluation scripts** (all in `scripts/`):
- `evaluate_ml.py` — runs Phase 2 evaluation module, saves to `artifacts/evaluation/ml_metrics.json`
- `evaluate_rag.py` — runs Phase 5 retrieval evaluator, saves to `artifacts/evaluation/rag_metrics.json`
- `evaluate_structured_output.py` — exercises ReportValidator with synthetic fixtures (no Ollama required)
- `evaluate_agent.py` — tests ToolRegistry contracts and AgentConfig budget limits (no Ollama required)
- `evaluate_api.py` — probes live FastAPI endpoints (requires backend running)
- `evaluate_all.py` — orchestrates all evaluations, generates JSON + Markdown report
- `assemble_evaluation_report.py` — lightweight assembler that reads existing artifacts without re-running heavy imports

**Evaluation artifacts** (in `artifacts/evaluation/`):
- `structured_output_metrics.json` — 6/6 PASS
- `agent_metrics.json` — 10/10 PASS
- `evaluation_summary.json` — consolidated cross-phase summary (overall_status=PASS)
- `EVALUATION_REPORT.md` — human-readable Markdown report

**Documentation** (in `docs/`):
- `LIMITATIONS_AND_FUTURE_WORK.md` — comprehensive limitations across data, model, LLM, RAG, API, security, and evaluation
- `RESUME_PROJECT_DESCRIPTION.md` — role-specific resume bullets, architecture diagram, interview talking points

### Phase 10 Exit Gate

```powershell
python scripts/run_phase_exit_tests.py --phase 10
```

Result: **PHASE 10: PASS** (29/29 checks passed)

### Reproducing the Evaluation

```powershell
# Option A: Assemble from existing artifacts (fast, no heavy imports)
python scripts/assemble_evaluation_report.py

# Option B: Re-run structured output and agent evaluations, then assemble
python scripts/evaluate_structured_output.py
python scripts/evaluate_agent.py
python scripts/assemble_evaluation_report.py

# Option C: Full re-run of all evaluations (slow, requires live Ollama for RAG)
python scripts/evaluate_all.py

# Option D: Include live API evaluation (requires backend running)
uvicorn src.api.app:app --host 127.0.0.1 --port 8000 &
python scripts/evaluate_all.py --api --api-base-url http://127.0.0.1:8000
```

---

## Previous Phases Summary

### Phase 9 — Frontend Dashboard

Phase 9 status: PASS

Frontend:
React 19.2.8 with TypeScript 6.0.2, Vite 8.3.4, Lucide React 1.54.0, Vitest 5.0.3, and custom SOC dark design system

Pages implemented:
- **Overview Page** (`src/components/OverviewView.tsx`):
  - Summary KPI cards showing Total Alerts, Critical, High, Medium, and Low severity counts calculated directly from real backend API.
  - Prominent synthetic data disclaimer banner informing analysts that telemetry represents synthetic aggregated 1-hour behavioral windows and that anomalies do not prove compromise.
  - Recent alerts table preview with click-through navigation to detail inspections.
  - Subsystem readiness widget summarizing ML, risk engine, MITRE catalog, RAG store, and Ollama runtime states.
- **Alerts Page** (`src/components/AlertsView.tsx`):
  - Searchable, filterable alerts table querying real backend `GET /alerts` endpoint with server-side pagination (`limit`, `offset`, `severity`).
  - Search bar supporting alert ID, window ID, or MITRE ATT&CK technique filtering.
  - Severity dropdown filter (`ALL`, `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
  - Accessible, text-labeled severity badges with icon distinctions.
  - Robust empty and failure states with retry action.
- **Alert Detail Page** (`src/components/AlertDetailView.tsx`):
  - Summary header showing Alert ID, Window ID, Severity, Risk Score (reconciled out of 100), Anomaly Score, Anomaly Decision, and Creation Timestamp.
  - Observed Evidence Signals table displaying signal name, observed values, baseline thresholds, contribution points, and explanatory text.
  - Phase 3 Risk Score Breakdown panel reconciling component scores with the backend total score.
  - Verified MITRE ATT&CK Context panel showing technique ID, name, tactics, catalog source/version, and mapping reasoning with verified external links.
  - AI Investigation Engine interface with "Investigate with AI" action, duplicate submission prevention (button disabled with spinner during active run), live elapsed time counter, and rendering of validated Phase 7 reports.
- **System Status Page** (`src/components/SystemStatusView.tsx`):
  - Real-time probe queries to `GET /health`, `GET /ready`, and `GET /status/model`.
- **About / Data Source Information Page** (`src/components/AboutView.tsx`):
  - Complete architecture transparency detailing Phases 1–9.

Tests:
- Frontend Vitest: `5 passed (5 test files), 17 passed (17 tests) in 3.25s`
- Phase 9 exit gate: PHASE 9: PASS (21/21 checks)

---

## Known Limitations

- Local CPU inference for Qwen 3 8B on Windows incurs ~180s per investigation. API evaluation requires a live backend and is documented as BLOCKED when unavailable.
- Telemetry data is synthetic aggregated 1-hour behavioral windows, not live event streaming.
- Backend default binding is strictly loopback `127.0.0.1`.
- All evaluation metrics are from synthetic benchmark datasets; real-world performance is unknown.

## Next Phase

None — this is the final planned phase. The project is ready for portfolio presentation.

See `docs/RESUME_PROJECT_DESCRIPTION.md` for resume bullets and interview talking points.
