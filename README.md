# AI-Powered Security Log Anomaly Detection & Investigation System

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com)
[![React 19](https://img.shields.io/badge/React-19.2+-61DAFB.svg)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-3178C6.svg)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An end-to-end, local-first cybersecurity investigation pipeline and SOC analyst workbench. The system ingests behavioral security log windows, detects anomalies using an unsupervised Isolation Forest baseline, computes deterministic multi-factor risk scores, enriches alerts with MITRE ATT&CK enterprise techniques and hybrid RAG threat intelligence, and orchestrates an AI investigation agent powered by a local Qwen LLM — all surfaced through a dedicated React SOC dashboard.

> [!IMPORTANT]
> **Data Disclaimer**: All security log telemetry in this repository is deterministically generated synthetic data representing 1-hour behavioral windows. It does not represent live enterprise telemetry, real-world breach data, or confirmed system compromise. An anomaly designation indicates behavioral deviation from an established normal baseline and requires analyst verification.

---

## Architecture Overview

```
                      ┌──────────────────────────────────────────────────────────┐
                      │                   React SOC Dashboard                    │
                      │   Overview  │  Alerts  │  Alert Detail  │  System Status  │
                      └────────────────────────────┬─────────────────────────────┘
                                                   │ HTTP (127.0.0.1:8000)
                      ┌────────────────────────────▼─────────────────────────────┐
                      │                      FastAPI Backend                     │
                      │   /health   /ready   /alerts   /alerts/{id}  /investigate │
                      │   Correlation-ID Tracing  │  Semaphore(1) Concurrency    │
                      └──────┬──────────────┬──────────────┬──────────────┬──────┘
                             │              │              │              │
                             ▼              ▼              ▼              ▼
                     Isolation Forest  Risk Scoring   MITRE ATT&CK   Hybrid RAG
                     (17 features)     (0-100 score)  STIX 2.1       (ChromaDB +
                     (scikit-learn)    (Multi-factor) Catalog        BM25 + RRF)
                             │              │              │              │
                             └──────────────┼──────────────┼──────────────┘
                                            ▼
                                  LangGraph Agent State
                                  ├─ search_logs
                                  ├─ get_related_events
                                  ├─ search_knowledge_base
                                  └─ lookup_attack_technique
                                            │
                                            ▼
                                   Local LLM (Qwen via Ollama)
                                   Deterministic Schema & Citation Gate
```

### High-Level Data Flow

1. **Window Aggregation & Feature Extraction**: Behavioral metrics (failed logons, network byte ratios, process counts, off-hours activity) are extracted from 1-hour windows into a 17-dimensional feature vector.
2. **Anomaly Detection**: An unsupervised Isolation Forest flags windows that deviate from the baseline. The decision threshold is derived deterministically from the 95th percentile of the training-normal score distribution.
3. **Deterministic Risk Scoring**: A multi-factor scoring engine calculates an explainable risk score (0–100) and assigns an operational severity tier (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) based on statistical anomaly deviation, privileged account usage, volume spikes, and external communication patterns.
4. **Context Enrichment**:
   - **MITRE ATT&CK**: Mapped to enterprise techniques (e.g., `T1078 Valid Accounts`, `T1048 Exfiltration Over Alternative Protocol`, `T1110 Brute Force`) from a local STIX 2.1 catalog.
   - **Hybrid RAG**: Ingests incident response playbooks and Sigma detection rules, querying via dense semantic search (ChromaDB + local Ollama embeddings) and lexical search (Okapi BM25) fused via Reciprocal Rank Fusion (RRF).
5. **Agentic Investigation**: A bounded LangGraph state machine executes an investigation workflow with strict resource controls (max 4 iterations, 4 tool calls, 3 LLM calls, 300s wall-clock timeout) using four read-only tools.
6. **Local LLM Synthesis & Validation**: The local Qwen 8B model synthesizes evidence into a structured JSON report. A deterministic `ReportValidator` enforces schema compliance, checks RAG citations, and filters unverified ATT&CK technique IDs.
7. **SOC Dashboard**: A React frontend provides real-time visibility into alerts, detailed metric breakdowns, MITRE mappings, knowledge base citations, and live investigation dispatch.

---

## Key Features & Capabilities

- **Local-First & Privacy-Preserving**: Model inference, embedding generation, vector storage, and alert processing execute locally via Ollama. No telemetry or proprietary logs leave the local perimeter.
- **Explainable Multi-Factor Scoring**: No opaque black-box severity assignments. Risk scores provide clear factor breakdowns (e.g., volume anomaly, privilege escalation, external network ratio).
- **Hallucination Prevention**:
  - Exact-identifier boosting for Windows Event IDs and ATT&CK technique IDs.
  - Multi-stage relevance gating that returns explicit empty results rather than generating ungrounded commentary on out-of-scope queries.
  - Mandatory source citation validation matching extracted chunk IDs before reports are approved.
- **Bounded Autonomous Agent**: LangGraph state machine with strict operational boundaries, immutable alert inputs, deterministic tool contracts, and `asyncio.Semaphore(1)` hardware concurrency protection.
- **Recruiter-Ready SOC Interface**: Clean, dark-mode security operations console with keyboard-accessible navigation, live progress tracking for local CPU inference, and structured investigative findings.

---

## Technical Stack

| Component | Technology | Description |
|---|---|---|
| **Anomaly Detection** | scikit-learn, NumPy, pandas | Isolation Forest trained on 17 behavioral features |
| **Risk Engine** | Python 3.11+, Pydantic v2 | Multi-factor deterministic risk calculator and severity classifier |
| **Threat Context** | MITRE ATT&CK Enterprise (STIX 2.1) | Local JSON STIX catalog with rule-based technique mapper |
| **Hybrid RAG** | ChromaDB, rank-bm25, Ollama | Dense semantic vector store + Okapi BM25 with Reciprocal Rank Fusion |
| **Local LLM** | Ollama (`qwen2.5:7b` / `qwen3:8b`) | On-device model synthesis without external API dependencies |
| **Agent Orchestration** | LangGraph, LangChain Core | StateGraph workflow with deterministic execution budget guards |
| **Backend API** | FastAPI, Uvicorn, Pydantic v2 | RESTful service with correlation IDs, error sanitization, and OpenAPI docs |
| **Frontend UI** | React 19, TypeScript, Vite, Lucide | SOC dark theme dashboard with responsive layout and real-time state |
| **Testing** | Pytest, Vitest, Testing Library, Oxlint | End-to-end Python backend test suite and React integration tests |

---

## Project Structure

```
ai_security_log_anomaly_project_starter/
├── config/                  # Risk scoring and system configuration
├── data/                    # Synthetic security datasets, MITRE fixture, knowledge guides
│   ├── knowledge_base/      # Incident response playbooks & Sigma detection rules
│   ├── mitre/               # MITRE ATT&CK STIX 2.1 fixture
│   └── *.csv                # Synthetic normal training and labeled evaluation windows
├── docs/                    # Technical architecture & subsystem documentation
│   ├── API.md               # FastAPI endpoint specifications and schemas
│   ├── DASHBOARD.md         # Frontend component architecture and state flow
│   ├── DATASET_SPEC.md      # Feature definitions and dataset schemas
│   ├── LANGGRAPH_AGENT.md   # Agent state machine, nodes, and tool contracts
│   ├── LIMITATIONS_AND_FUTURE_WORK.md # Constraints, threat caveats, and roadmap
│   ├── MITRE_ATTACK_INTEGRATION.md    # STIX 2.1 mapping specifications
│   ├── ML_BASELINE.md       # Isolation Forest architecture and evaluation
│   ├── OUTPUT_SCHEMA.md     # Pydantic investigation schema contracts
│   ├── RAG_IMPLEMENTATION.md # Hybrid RAG architecture and retrieval metrics
│   ├── RISK_SCORING.md      # Scoring formulas and severity thresholds
│   └── TOOL_CONTRACTS.md    # Agent tool interface contracts and schemas
├── frontend/                # React 19 + TypeScript + Vite SOC dashboard
│   ├── src/components/      # Overview, Alerts, AlertDetail, and SystemStatus views
│   └── src/__tests__/       # Vitest UI integration tests
├── scripts/                 # Deterministic dataset generation, training, and evaluation
├── src/
│   ├── agent/               # LangGraph investigation workflow & agent tools
│   ├── api/                 # FastAPI routes, dependencies, and repository storage
│   ├── data_validation/     # Log schema validation and data integrity checks
│   ├── llm/                 # Ollama provider, prompt construction, and report validation
│   ├── mitre/               # ATT&CK catalog querying and technique mapping rules
│   ├── ml/                  # Feature engineering, model training, and inference
│   ├── rag/                 # Vector store, BM25 indexing, and hybrid retrieval
│   └── risk_scoring/        # Deterministic multi-factor risk calculation engine
└── tests/                   # Comprehensive pytest test suite
```

---

## Setup & Installation

### Prerequisites

- **Python 3.11+**
- **Node.js 18+ & npm**
- **Ollama** installed and running locally ([ollama.com](https://ollama.com))

### 1. Environment Configuration

Clone the repository and create a Python virtual environment:

```bash
git clone https://github.com/your-username/ai-security-log-anomaly.git
cd ai-security-log-anomaly

python -m venv .venv
# On Windows (PowerShell):
.venv\Scripts\Activate.ps1
# On Linux / macOS:
source .venv/bin/activate
```

Install backend dependencies:

```bash
pip install -e .
pip install pytest ruff
```

Copy the environment template:

```bash
cp .env.example .env
```

Review `.env`:
```ini
APP_ENV=development
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=
DATA_DIR=./data
ARTIFACT_DIR=./artifacts
VECTOR_STORE_PROVIDER=chroma
VECTOR_STORE_PATH=./artifacts/vector_store
API_HOST=127.0.0.1
API_PORT=8000
```
*(Leaving `OLLAMA_MODEL` empty enables dynamic runtime discovery of installed Qwen models).*

### 2. Prepare Local AI Models (Ollama)

Pull the required models using the Ollama CLI:

```bash
# LLM for investigation synthesis
ollama pull qwen2.5:7b
# Embedding model for dense RAG retrieval
ollama pull nomic-embed-text
```

### 3. Generate Datasets & Train Artifacts

To deterministically generate synthetic log data and build model artifacts:

```bash
# Seed synthetic security datasets (train and eval)
python scripts/seed_dataset.py

# Train Isolation Forest model baseline
python -m src.ml.train

# Ingest and index hybrid knowledge base
python -m src.rag.ingestion
```

---

## Running the Application

### 1. Start Backend API

```bash
uvicorn src.api.app:create_app --factory --host 127.0.0.1 --port 8000 --reload
```

- API Base URL: `http://127.0.0.1:8000`
- Interactive OpenAPI Docs: `http://127.0.0.1:8000/docs`
- Health check: `http://127.0.0.1:8000/health`
- Subsystem readiness: `http://127.0.0.1:8000/ready`

### 2. Start Frontend SOC Dashboard

In a separate terminal:

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173` in your browser.

---

## Running Tests & Verification

### Backend Tests (pytest)

Run the complete test suite covering data validation, ML inference, risk scoring, MITRE mapping, hybrid RAG, agent orchestration, and FastAPI endpoints:

```bash
pytest
```

Run without invoking the local LLM:
```bash
pytest -k "not test_real_local_qwen"
```

### Frontend Tests & Quality Checks

```bash
cd frontend

# Run Vitest integration test suite
npm test

# Run Oxlint fast linter
npm run lint

# Build production bundle
npm run build
```

### Evaluation Benchmark

To execute reproducible offline benchmark evaluations across ML, RAG, Structured Output, and Agent layers:

```bash
python scripts/evaluate_all.py
```

Results are summarized in `artifacts/evaluation/evaluation_summary.json` and `artifacts/evaluation/EVALUATION_REPORT.md`.

---

## Limitations & Future Work

- **Synthetic Telemetry**: The current pipeline models 1-hour behavioral windows rather than raw Windows Event Log (`.evtx`) streams or raw Sysmon process events. Future iterations aim to test against sanitized public challenge datasets (e.g., LANL, Boss of the SOC).
- **Unsupervised Thresholding**: The Isolation Forest uses a static threshold tuned to the 95th percentile of normal baseline data. Future improvements include adaptive sliding-window calibration to prevent drift.
- **CPU Inference Latency**: Running 8B parameter models on consumer hardware without dedicated GPUs requires ~150–180 seconds per complete investigation. An `asyncio.Semaphore(1)` ensures requests are safely queued.
- Comprehensive technical constraints and future milestones are documented in [docs/LIMITATIONS_AND_FUTURE_WORK.md](docs/LIMITATIONS_AND_FUTURE_WORK.md).

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
