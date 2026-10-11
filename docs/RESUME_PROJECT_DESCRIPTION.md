# Resume Project Description

## Project Title
**AI-Powered Security Log Anomaly Detection & Investigation System**

## One-Line Summary
End-to-end local ML + LLM pipeline that detects behavioural anomalies in synthetic
security windows, enriches alerts with MITRE ATT&CK context and RAG-retrieved
threat intelligence, and produces structured investigation reports via a LangGraph
agent orchestrating a local Qwen 3 8B model — all surfaced through a React
security operations dashboard.

---

## Technical Stack

| Layer | Technology |
|---|---|
| Anomaly detection | Isolation Forest (scikit-learn) |
| Risk scoring | Deterministic multi-factor engine |
| Threat context | MITRE ATT&CK Enterprise v14.1 (STIX 2.1) |
| Knowledge retrieval | Hybrid RAG (ChromaDB + Okapi BM25 + RRF) |
| Embedding model | Ollama `embeddinggemma:latest` (768-d, local) |
| LLM | Qwen 3 8B via Ollama (local, no cloud fallback) |
| Agent orchestration | LangGraph `StateGraph` |
| Backend API | FastAPI + Pydantic v2 |
| Frontend | React 19 + TypeScript + Vite (SOC dark theme) |
| Evaluation | Custom benchmark scripts + Vitest integration tests |

---

## Resume Bullets

*(Use one to three of these depending on space and role focus.)*

### Concise version (one bullet)
- Built a local-first security anomaly detection and AI investigation system combining Isolation Forest, hybrid RAG (ChromaDB + BM25), MITRE ATT&CK context, and a LangGraph agent over Qwen 3 8B, served through a FastAPI backend and React SOC dashboard; achieved F1 ≥ 0.80 on synthetic benchmarks with structured, citation-backed investigation reports.

### ML/Data Science focus
- Trained an **Isolation Forest** anomaly detector on 17 behavioural features from synthetic 1-hour security windows; derived the decision threshold deterministically from the 95th percentile of the training-normal score distribution to target a ≤5% baseline FPR without peeking at evaluation labels.
- Evaluated the model against a labelled synthetic benchmark with per-anomaly-type recall breakdown; recorded precision, recall, F1, ROC-AUC, PR-AUC, and confusion-matrix metrics in reproducible evaluation artifacts.

### NLP/LLM/RAG focus
- Built a **hybrid RAG pipeline** ingesting MITRE ATT&CK STIX 2.1, Sigma detection rules, and security guides; combined dense semantic search (ChromaDB + local Ollama embeddings) and lexical search (Okapi BM25) via Reciprocal Rank Fusion with exact-identifier boosting (ATT&CK technique IDs, Windows Event IDs).
- Enforced multi-stage relevance gating — returning `NO_RESULTS` on out-of-scope queries rather than hallucinating irrelevant chunks — achieving measurable rejection rates on hand-checked unanswerable queries.
- Integrated **Qwen 3 8B** via Ollama as a local investigation engine; validated structured JSON reports through a deterministic `ReportValidator` that filters unverified ATT&CK IDs and citation-checks RAG chunk references before persisting results.

### Agent/Orchestration focus
- Designed a bounded **LangGraph investigation workflow** (START → load alert → inspect events → RAG retrieval → ATT&CK verification → evidence synthesis → final report → END) with strict runtime budgets (max 4 iterations, 4 tool calls, 3 LLM calls, 300s wall-clock deadline).
- Exposed four deterministic, typed, read-only tools (`search_logs`, `get_related_events`, `search_knowledge_base`, `lookup_attack_technique`) adhering to an explicit tool contract with typed inputs/outputs, validation, error states, and logging.
- Serialised local model execution with `asyncio.Semaphore(1)` to prevent GPU/VRAM thrashing on consumer hardware without requiring distributed queue infrastructure.

### Backend/API focus
- Implemented a **FastAPI backend** (Python 3.11, Pydantic v2) with validated endpoints for health probing, alert retrieval (server-side pagination and severity filtering), and bounded AI investigation dispatch; enforced loopback-only binding and correlation-ID request tracing.
- Sanitised all client-facing error payloads to prevent leaking internal stack traces, local filesystem paths, or model provider diagnostics.

### Frontend/Full-stack focus
- Built a responsive **React 19 + TypeScript SOC dashboard** (Vite, Lucide React) with Overview, Alerts, Alert Detail, System Status, and About views; all data flows through a centralized typed `ApiService` over `VITE_API_BASE_URL`.
- Displayed validated LangGraph investigation reports with collapsible RAG citations, and prevented duplicate LLM submissions via client-side disabled-state guards and live elapsed timers.
- Shipped 17 Vitest integration tests across 5 test suites covering API client, overview, alerts list, alert detail, and system status views.

---

## Architecture Diagram (Text)

```
┌─────────────────────────────────────────────────────────────────┐
│                         React Dashboard                         │
│  Overview │ Alerts │ Alert Detail │ System Status │ About       │
└───────────────────────┬─────────────────────────────────────────┘
                        │ HTTP (127.0.0.1:8000)
┌───────────────────────▼─────────────────────────────────────────┐
│                     FastAPI Backend                             │
│  /health  /ready  /alerts  /alerts/{id}  /investigate           │
│  Correlation-ID tracing │ Semaphore(1) concurrency guard        │
└──┬──────────────┬──────────────┬──────────────┬─────────────────┘
   │              │              │              │
   ▼              ▼              ▼              ▼
Isolation     Risk          MITRE          Hybrid RAG
Forest        Scoring       ATT&CK         (ChromaDB
(Phase 2)     (Phase 3)     v14.1          + BM25 + RRF)
                            (Phase 4)      (Phase 5)
                                    │
                                    ▼
                         LangGraph Agent (Phase 7)
                         ├─ search_logs
                         ├─ get_related_events
                         ├─ search_knowledge_base
                         └─ lookup_attack_technique
                                    │
                                    ▼
                         Qwen 3 8B via Ollama (local)
                         ReportValidator (deterministic gate)
```

---

## What Makes This Project Technically Credible

1. **No fabricated metrics**: All evaluation metrics are produced by running
   actual code against real artifacts. The project explicitly records `BLOCKED`
   when prerequisites are missing rather than asserting success.

2. **Cybersecurity truthfulness**: The system distinguishes `anomalous`,
   `suspicious`, `possible attack`, and `confirmed compromise`. ATT&CK technique
   IDs are verified against the catalog before being reported. Synthetic data is
   clearly labelled throughout.

3. **Local-first privacy model**: Model inference, embedding generation, vector
   storage, and alert persistence all run on-device. No data leaves the machine.

4. **Deterministic, reproducible pipeline**: Dataset generation, preprocessing,
   training, and evaluation are fully scriptable. All artifacts are derived from
   documented, seeded procedures.

5. **Explicit uncertainty**: The LLM is required to populate an `uncertainty`
   field and is not used as the sole anomaly detector.

6. **Failure mode handling**: Every component handles unavailable providers,
   missing artifacts, malformed inputs, and retrieval failures with explicit
   error states rather than silent defaults.

---

## Repository Structure Overview

```
ai_security_log_anomaly_project_starter/
├── data/                   # Synthetic datasets + knowledge base sources
├── artifacts/              # Generated model artifacts + evaluation results
├── src/
│   ├── ml/                 # Phase 2: Isolation Forest
│   ├── risk_scoring/       # Phase 3: Explainable risk scores
│   ├── mitre/              # Phase 4: ATT&CK v14.1 integration
│   ├── rag/                # Phase 5: Hybrid RAG pipeline
│   ├── llm/                # Phase 6: Qwen 3 8B provider + validator
│   ├── agent/              # Phase 7: LangGraph workflow + tools
│   └── api/                # Phase 8: FastAPI backend
├── frontend/               # Phase 9: React SOC dashboard
├── scripts/                # Training, evaluation, and seeding scripts
├── tests/                  # Phase and integration tests
└── docs/                   # Architecture decisions, API docs, evaluation
```

---

## Talking Points for Interviews

- **Why local-only?** Avoids data exfiltration risk and demonstrates the system
  is architecturally feasible for air-gapped or high-classification environments.
- **Why Isolation Forest instead of a supervised model?** Anomaly detection is
  fundamentally an unsupervised problem in production environments where labelled
  attack data is scarce. The system is designed to be extended with supervised
  layers once labels are available.
- **What is the real-world gap?** The largest gap is synthetic data. The model's
  real-world recall on novel attack techniques is unknown. This is explicitly
  documented in `LIMITATIONS_AND_FUTURE_WORK.md`.
- **How does the agent avoid hallucination?** The LLM is never the sole detector.
  All evidence passed to the model is produced by deterministic upstream modules
  (ML scores, risk scores, ATT&CK mappings). The `ReportValidator` filters
  unverified ATT&CK IDs and checks citations before persisting any result.
- **How do you handle model unavailability?** The system returns structured error
  states (`PROVIDER_UNAVAILABLE`, `MODEL_NOT_FOUND`, `REQUEST_TIMEOUT`) and
  surfaces them clearly in the dashboard. It never falls back to a cloud model
  silently.

---

*Last updated: Phase 10 completion*
