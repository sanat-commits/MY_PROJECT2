# Security Operations Dashboard Documentation (Phase 9)

## 1. Overview & Architecture

The **CYBER SENTINEL** Security Operations Dashboard provides a local-first, interactive analyst interface over the Phase 8 FastAPI backend. It enables security analysts to inspect prioritized behavioral log anomalies, review explainable risk score breakdowns, examine deterministic MITRE ATT&CK technique attributions, launch multi-step LangGraph AI investigations powered by a local Qwen 3 8B model, and inspect source-attributed RAG knowledge citations.

```
+---------------------------------------------------------------------------------+
|                    CYBER SENTINEL SOC Dashboard (React 19 + TypeScript)         |
|  +--------------------+  +--------------------+  +----------------------------+ |
|  |   Overview View    |  |    Alerts View     |  |     System Status View     | |
|  | - Total Alerts     |  | - Severity Filters |  | - API Liveness (/health)   | |
|  | - Critical / High  |  | - Search Window ID |  | - Subsystems (/ready)      | |
|  | - Synthetic Banner |  | - Server Paging    |  | - Local Qwen (/status/model| |
|  +--------------------+  +--------------------+  +----------------------------+ |
|                                     |                                           |
|                                     v                                           |
|                          +--------------------+                                 |
|                          | Alert Detail View  |                                 |
|                          | - Signal Evidence  |                                 |
|                          | - Risk Breakdown   |                                 |
|                          | - ATT&CK Context   |                                 |
|                          +--------------------+                                 |
|                                     |                                           |
|                                     v                                           |
|                          +--------------------+                                 |
|                          | AI Investigation   |                                 |
|                          | - Dispatched Call  |                                 |
|                          | - Qwen Synthesis   |                                 |
|                          | - RAG Citations    |                                 |
|                          +--------------------+                                 |
+---------------------------------------------------------------------------------+
                                      | HTTP REST
                                      v
                      FastAPI Backend (http://127.0.0.1:8000)
```

---

## 2. Technology Stack & Dependencies

- **Framework**: React `19.2.8` with TypeScript `~6.0.2`
- **Build & Dev Tooling**: Vite `8.3.4`
- **Icons**: Lucide React `1.54.0`
- **Testing Framework**: Vitest `5.0.3` with `@testing-library/react` and `jsdom`
- **Styling**: Vanilla CSS Design System with SOC dark theme tokens (`src/index.css`)
- **API Client**: Centralized typed HTTP service (`src/services/api.ts`)

---

## 3. Configuration & Environment Variables

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `VITE_API_BASE_URL` | `http://127.0.0.1:8000` | Target URL for backend FastAPI service. |
| `PORT` | `3000` | Local development server port (configured in `vite.config.ts`). |

*Note: The backend FastAPI application restricts CORS origins strictly to loopback addresses (`http://localhost:3000`, `http://127.0.0.1:3000`, `http://localhost:5173`, `http://127.0.0.1:5173`).*

---

## 4. Setup, Development, & Production Build Commands

All commands are executed from the `frontend/` directory:

### Install Dependencies
```powershell
npm install
```

### Start Development Server
```powershell
npm run dev
```
Accessible at `http://localhost:3000`.

### Run Production Build & Typecheck
```powershell
npm run build
```
Executes `tsc -b && vite build` and outputs optimized assets to `frontend/dist/`.

### Run Frontend Vitest Suite
```powershell
npm test
```
Executes component and API client integration tests in JSDOM environment.

---

## 5. Views & Component Structure

### A. Overview View (`src/components/OverviewView.tsx`)
- **Real Backend Summary Cards**: Displays real-time alert counts partitioned by severity (`TOTAL`, `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) queried directly from `GET /alerts`.
- **Synthetic Data Disclaimer**: Banner stating that telemetry is derived from synthetic 1-hour behavioral windows and that anomaly scores do not constitute proof of compromise.
- **Recent Alerts Table**: Fast click-through into alert detail views.
- **Pipeline Readiness Widget**: Lightweight status pills reflecting upstream readiness.

### B. Alerts View (`src/components/AlertsView.tsx`)
- **Server-Side Pagination**: Queries `GET /alerts?limit={pageSize}&offset={offset}&severity={severity}`.
- **Severity Filtering**: Select between `All`, `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`.
- **Search Filtering**: Client-side filtering by Alert ID, Window ID, or MITRE ATT&CK technique name.
- **Severity Badges**: High-contrast, text-labeled visual badges (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) ensuring accessibility.
- **Empty & Error Handling**: Explicit empty search states, network retry button, and loading spinners.

### C. Alert Detail View (`src/components/AlertDetailView.tsx`)
- **Summary Header**: Displays Alert ID, Window ID, Severity, Risk Score, Anomaly Score, and creation time.
- **Section A: Observed Evidence**: Full signal name, observed value, baseline threshold rule, contribution points, and explanatory text.
- **Section B: Risk Breakdown**: Displays component contributions (ML Anomaly Signal + Behavioral Signal) mathematically reconciling with the total score.
- **Section C: MITRE ATT&CK Context**: Displays technique ID, name, tactics, catalog source/version, and mapping explanation. External link provided only if official STIX URL is present.
- **Section D: AI Investigation**:
  - `Investigate with AI` action button with duplicate submission prevention (disabled while active).
  - Indeterminate progress indicator with real-time elapsed seconds counter.
  - Formatted structured report: Executive Summary, Finding (`SUSPICIOUS_ACTIVITY`, etc.), Observed Evidence, Interpretation (distinguishing observations from hypotheses), Verified ATT&CK techniques, Recommended Next Steps (informational only), Uncertainty & Limitations, and Collapsible RAG Citations with chunk IDs and source paths.

### D. System Status View (`src/components/SystemStatusView.tsx`)
- **Liveness Probe**: `GET /health` (`status: "ok"`).
- **Subsystems Probe**: `GET /ready` verifying `ml_detector`, `risk_engine`, `mitre_catalog`, `rag_knowledge_base`, and `local_llm_runtime`.
- **Model Discovery**: `GET /status/model` reporting configured model (`qwen3:8b`), detected tag, availability (`available`, `unavailable`, `model_not_found`), and last check timestamp.
- **Privacy Assurance**: Diagnostic errors sanitized; never leaks `.env` contents, filesystem paths, or Python stack traces.

### E. About View (`src/components/AboutView.tsx`)
- Outlines the 9-phase architecture, dataset validation rules, Isolation Forest baseline, bounded risk scoring, STIX ATT&CK mapping, Attributable RAG, and LangGraph workflow.
- Highlights cybersecurity truthfulness principles: *"An anomaly is not proof of compromise."*

---

## 6. API Endpoints Used

| Endpoint | HTTP Method | Usage |
| :--- | :--- | :--- |
| `/health` | `GET` | Periodic navbar connectivity check & system status. |
| `/ready` | `GET` | Overview readiness widget & system status dependency breakdown. |
| `/status/model` | `GET` | Model provider status & runtime tag discovery. |
| `/alerts` | `GET` | Overview KPI counts & paginated alerts table with severity filters. |
| `/alerts/{alert_id}` | `GET` | Full alert detail retrieval (evidence, breakdown, MITRE context). |
| `/alerts/{alert_id}/investigate`| `POST` | Triggers LangGraph multi-step investigation against local Qwen 3 8B. |
| `/investigations/{id}` | `GET` | Historical investigation retrieval. |
| `/investigations` | `GET` | Historical investigation listing. |

---

## 7. Known Limitations

1. **Local Inference Latency**: Local CPU inference on Windows for Qwen 3 8B takes ~180s per investigation due to memory swapping between `embeddinggemma:latest` and `qwen3:8b`. The UI accommodates this with real elapsed timers and disabled duplicate buttons.
2. **Synthetic Telemetry**: Windows activity is based on synthetic aggregated 1-hour behavioral windows rather than live ETW/Sysmon hooks.
3. **Loopback Binding**: By default, the API is accessible only from `127.0.0.1`. Deploying across a local network requires configuring reverse proxies and authentication.
