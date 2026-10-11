# Backend API Documentation

## 1. Overview & Architecture

Phase 8 exposes the security detection, risk scoring, MITRE ATT&CK mapping, RAG, and LangGraph investigation pipeline via a production-grade, local-first **FastAPI** (`v0.141.1`) REST API.

The API layer acts as a strictly validated, non-destructive orchestration facade over the existing Phase 2–7 subsystems:

```
                HTTP Client / Dashboard
                          |
                          v
                FastAPI Backend (:8000)
                          |
           +--------------+--------------+
           | Request Tracing (Middleware)|
           | CORS Allowlist & Validation |
           +--------------+--------------+
                          |
                          v
                Application Services
         +----------------+----------------+
         |                |                |
         v                v                v
     ML / Alerts     RAG / MITRE     LangGraph Agent
    (Phases 2 & 3)  (Phases 4 & 5)      (Phase 7)
                                           |
                                           v
                                    Local Qwen 3 8B
                                       (Phase 6)
                          |
                          v
                 Validated Response
```

---

## 2. Server Startup & Network Binding

### Default Local Binding
The server defaults to loopback-only binding (`127.0.0.1`) to ensure local security data is never exposed across the network:

```powershell
uvicorn src.api.app:app --host 127.0.0.1 --port 8000
```

### Environment Variables
| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `API_HOST` | `127.0.0.1` | Network interface to bind to (strictly loopback default). |
| `API_PORT` | `8000` | HTTP port. |
| `CORS_ORIGINS` | `http://localhost:3000,http://127.0.0.1:3000,http://localhost:5173,http://127.0.0.1:5173` | Comma-separated list of allowed frontend web origins. |
| `API_MAX_PAGE_SIZE` | `100` | Maximum page size permitted for list endpoints. |
| `API_DEFAULT_PAGE_SIZE`| `20` | Default page size. |
| `API_INVESTIGATION_CONCURRENCY_LIMIT` | `1` | Max concurrent investigations running against the local LLM. |
| `API_STORAGE_DIR` | `artifacts/api` | Directory for alert and investigation persistence caches. |

Interactive API documentation is accessible at:
- **Swagger UI**: `http://127.0.0.1:8000/docs`
- **ReDoc**: `http://127.0.0.1:8000/redoc`

---

## 3. Endpoints Specification

### A. Health & Readiness Probes

#### `GET /health`
Lightweight process liveness probe. Does not invoke upstream models or databases.

**Response** (`200 OK`):
```json
{
  "status": "ok"
}
```

#### `GET /ready`
Comprehensive readiness probe verifying all upstream dependencies.

**Response** (`200 OK`):
```json
{
  "status": "ready",
  "dependencies": {
    "ml_detector": {
      "status": "ready",
      "message": "Isolation forest model and calibrated threshold loaded",
      "details": {}
    },
    "risk_engine": {
      "status": "ready",
      "message": "Risk scoring configuration verified",
      "details": {}
    },
    "mitre_catalog": {
      "status": "ready",
      "message": "Enterprise ATT&CK catalog cached",
      "details": {}
    },
    "rag_knowledge_base": {
      "status": "ready",
      "message": "Hybrid vector store and BM25 index verified",
      "details": {}
    },
    "local_llm_runtime": {
      "status": "ready",
      "message": "Ollama local daemon responsive",
      "details": {
        "provider": "ollama",
        "base_url": "http://localhost:11434"
      }
    }
  }
}
```

---

### B. Model Status

#### `GET /status/model`
Queries the local LLM runtime via the Phase 6 `OllamaLlmProvider` to discover installed model tags without triggering costly generation requests.

**Response** (`200 OK`):
```json
{
  "provider": "ollama",
  "configured_model": "qwen3:8b",
  "detected_model": "qwen3:8b",
  "availability": "available",
  "last_check": "2026-10-09T07:44:00Z",
  "error_code": null
}
```

---

### C. Alerts

#### `GET /alerts`
Retrieve paginated security alerts from the local alert repository.

**Query Parameters**:
- `limit` (int, default `20`, min `1`, max `100`): Items per page.
- `offset` (int, default `0`, min `0`): Pagination offset.
- `severity` (string, optional): Filter by `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`.
- `is_anomaly` (int, optional): Filter by `1` (anomalous) or `0` (normal).

**Response** (`200 OK`):
```json
{
  "items": [
    {
      "alert_id": "alt_WIN-201436_8db7ccda8a4f",
      "window_id": "WIN-201436",
      "anomaly_score": 0.28,
      "is_anomaly": 1,
      "risk_score": 58.24,
      "severity": "MEDIUM",
      "evidence": [ ... ],
      "score_breakdown": { ... },
      "attack_context": { ... },
      "created_at": "2026-10-09T07:00:00Z"
    }
  ],
  "limit": 20,
  "offset": 0,
  "total": 100
}
```

#### `GET /alerts/{alert_id}`
Retrieve full structured alert details by alert ID.

**Response** (`200 OK`): Returns full `SecurityAlert` / `AlertWithMitreContext` JSON.  
**Error** (`404 NOT FOUND`):
```json
{
  "error": {
    "code": "NOT_FOUND",
    "message": "Security alert 'alt_xyz' was not found in the repository.",
    "correlation_id": "req_8a39c91b72e1",
    "details": null
  }
}
```

---

### D. Investigation

#### `POST /alerts/{alert_id}/investigate`
Executes a multi-step LangGraph investigation using the verified Phase 7 engine and local `qwen3:8b` model.

**Request Body** (optional):
```json
{
  "correlation_id": "corr_analyst_01",
  "thread_id": "thread_custom_chk"
}
```

**Response** (`200 OK`):
```json
{
  "investigation_id": "inv_alt_WIN-201436_8db7ccda8a4f_ee22f2d4",
  "alert_id": "alt_WIN-201436_8db7ccda8a4f",
  "status": "SUCCESS",
  "final_report": {
    "investigation_id": "inv_alt_WIN-201436_8db7ccda8a4f_ee22f2d4",
    "alert_id": "alt_WIN-201436_8db7ccda8a4f",
    "summary": "Observed failed login burst consistent with credential access.",
    "supplied_severity": "MEDIUM",
    "supplied_risk_score": 58.24,
    "finding": "SUSPICIOUS_ACTIVITY",
    "observed_evidence": [ ... ],
    "interpretation": "Elevated authentication failures after hours require verification.",
    "possible_attack_techniques": ["T1110.001"],
    "uncertainty": "Origin IP address telemetry is unverified.",
    "recommended_next_steps": [ ... ],
    "citations": [ ... ]
  },
  "execution_trace_summary": [ ... ],
  "tool_call_count": 1,
  "llm_call_count": 1,
  "iteration_count": 2,
  "elapsed_time": 79.71,
  "warnings": [],
  "failure_reason": null
}
```

#### `GET /investigations/{investigation_id}`
Retrieve completed historical investigation runs from the persistent store.

**Response** (`200 OK`): Formatted `InvestigationResponse`.  
**Error** (`404 NOT FOUND`): If investigation ID does not exist.

#### `GET /investigations`
Retrieve paginated list of all historical investigations recorded in the environment.

---

## 4. Error Handling & Security Privacy

All errors conform to a standardized error container:
```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable description.",
    "correlation_id": "req_8a39c91b72e1",
    "details": null
  }
}
```

### Privacy Protections
1. **Stack Trace Redaction**: Unhandled internal exceptions log detailed diagnostic stack traces server-side while returning generic, sanitized HTTP 500 messages to clients.
2. **Immutable Alert State**: Alert scores and severities cannot be modified by API clients. PUT/PATCH methods on `/alerts/{alert_id}` return HTTP 405 Method Not Allowed.
3. **Local Loopback Default**: Host binds strictly to `127.0.0.1` unless explicitly changed.
4. **Concurrency Semaphore**: Investigations are guarded by `asyncio.Semaphore(1)` to prevent concurrent Qwen requests from crashing local GPU VRAM.

---

## 5. Verification Commands

### Run Unit and API Route Tests
```powershell
pytest tests/test_api.py -v
```

### Run Phase 8 Exit Gate
```powershell
python scripts/run_phase_exit_tests.py --phase 8
```
