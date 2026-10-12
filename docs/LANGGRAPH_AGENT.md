# LangGraph Security Investigation Agent

## 1. Executive Summary & Architecture

Phase 7 evolves the Phase 6 single-shot investigation engine into a bounded, deterministic, multi-step investigation workflow orchestrated via **LangGraph** (`v1.2.14`).

The agent coordinates context enrichment by determining evidence gaps on incoming Phase 3 `SecurityAlert`s, calling registered read-only application tools, evaluating returned evidence, and invoking the local `qwen3:8b` model through the Phase 6 investigation engine to produce a fully validated `InvestigationReport`.

```
               +----------------------+
               |   validate_request   |
               +----------+-----------+
                          |
                          v
               +----------------------+
               |      load_alert      |
               +----------+-----------+
                          |
                          v
        +----->+----------------------+
        |      |   assess_evidence    |<----+
        |      +----------+-----------+     |
        |                 |                 |
        |     [Needs evidence & budget ok]  |
        |                 v                 |
        |      +----------------------+     |
        |      |    dispatch_tool     +-----+
        |      +----------------------+
        |
    [Evidence sufficient OR budget reached]
        |
        v
+-----------------------+
|   run_investigation   |  (Phase 6 Local Qwen 3 8B Engine)
+-----------+-----------+
            |
            v
+-----------------------+
|       finalize        |
+-----------+-----------+
            |
            v
          [END]
```

---

## 2. Cybersecurity Truthfulness & Operational Boundaries

Core operational boundaries and truthfulness principles:
1. **Aggregated Feature Windows Only**: The underlying security telemetry in this project consists of synthetic 1-hour aggregated behavioral windows (`data/synthetic/windows1h_security.csv`). These are **not raw Windows Event Logs (EVTX)** or Sysmon process event sequences. Tools querying this source explicitly return records labeled `record_type: "aggregated_behavioral_window"`.
2. **Immutable Alert Baseline**: The agent never mutates the original alert's `alert_id`, `risk_score`, or `severity`.
3. **Verified Knowledge & ATT&CK Only**: Knowledge retrieval queries the verified Phase 5 hybrid index. ATT&CK lookups query the verified Phase 4 STIX Enterprise ATT&CK catalog. No synthetic techniques or imaginary evidence items are ever fabricated.
4. **Read-Only Non-Destructive Operation**: All registered tools are strictly read-only. No system modifications, active network probing, process termination, account lockout, or external cloud calls occur.

---

## 3. Graph Nodes and Responsibilities

| Node Name | Input State | Output State | Description |
| :--- | :--- | :--- | :--- |
| `validate_request` | `initial_state` | `current_status`, `failure_reason` | Validates that `original_alert` is a valid `SecurityAlert` model. Fails fast on malformed schemas. |
| `load_alert` | `original_alert` | `alert_id`, `observed_evidence`, `attack_context` | Extracts initial evidence components, scoring breakdown, and existing ATT&CK context into the active state. |
| `assess_evidence` | Current state, iteration counts, action history | `decision_history`, `iteration_count`, `current_status` | Evaluates evidence completeness against configured requirements. Checks deadline, max iterations, and tool call limits. Selects the next `ActionDecision` or routes to `run_investigation`. |
| `dispatch_tool` | `decision_history[-1]` | `tool_results`, `tool_call_count`, `retrieval_context`, `attack_context`, `tool_errors` | Executes the approved tool via `ToolRegistry`. Handles execution exceptions, logs execution duration, and attaches evidence to state. |
| `run_investigation`| State with gathered evidence and retrieval context | `final_report`, `llm_call_count`, `current_status` | Invokes the Phase 6 `InvestigationEngine` and local `qwen3:8b` model. Validates output schema and citations via `ReportValidator`. |
| `finalize` | Graph state | `execution_trace`, `duration_seconds`, final `current_status` | Assembles the final `InvestigationResult` payload, compiles performance metrics, and logs trace summary. |

---

## 4. State Schema

Defined in `src/agent/schemas.py`:

```python
class InvestigationState(BaseModel):
    investigation_id: str
    alert_id: str
    original_alert: SecurityAlert
    observed_evidence: list[dict[str, Any]]
    attack_context: dict[str, Any]
    retrieval_context: list[dict[str, Any]]
    tool_results: list[ToolExecutionRecord]
    tool_errors: list[str]
    action_history: list[str]
    decision_history: list[ActionDecision]
    iteration_count: int
    tool_call_count: int
    llm_call_count: int
    started_at: float
    deadline: float
    current_status: AgentStatus
    warnings: list[str]
    final_report: InvestigationReport | None
    failure_reason: str | None
    execution_trace: list[TraceStep]
```

---

## 5. Approved Tool Registry

Every tool conforms to typed input/output contracts in `src/agent/tools.py`:

1. `search_logs`
   - **Parameters**: `query_field: str`, `query_value: Any`, `limit: int = 10`
   - **Returns**: `records: list[dict]`, `record_type: "aggregated_behavioral_window"`, `match_count: int`
   - **Status**: `SUCCESS`, `NO_RESULTS`, `ERROR`
2. `get_related_events`
   - **Parameters**: `window_id: str`, `hour_radius: int = 1`
   - **Returns**: `records: list[dict]`, `target_window_id: str`, `record_type: "aggregated_behavioral_window"`
   - **Status**: `SUCCESS`, `NOT_FOUND`, `ERROR`
3. `search_knowledge_base`
   - **Parameters**: `query: str`, `top_k: int = 3`
   - **Returns**: `chunks: list[dict]` (with `chunk_id`, `source_id`, `title`, `text`)
   - **Status**: `SUCCESS`, `NO_RESULTS`, `ERROR`
4. `lookup_attack_technique`
   - **Parameters**: `technique_id: str`
   - **Returns**: `data: dict` (technique name, description, tactics, detection notes)
   - **Status**: `SUCCESS`, `NOT_FOUND`, `ERROR`

---

## 6. Runtime Limits & Loop Prevention

The agent prevents runaway loops, infinite retries, and unbounded compute through strict guards:

- `max_iterations`: Default `4` iterations maximum.
- `max_tool_calls`: Default `4` tool invocations maximum.
- `max_llm_calls`: Default `3` LLM calls maximum.
- `total_deadline_seconds`: Configurable total investigation wall-clock limit (default `300.0`s).
- `per_call_timeout_seconds`: Timeout per tool/LLM call (default `120.0`s).
- **Loop Prevention**: `action_history` tracking ensures tools with identical queries are not called in endless cycles.
- **Controlled Exhaustion**: If limits or deadlines are exceeded, the agent returns `LIMIT_REACHED` or `TIMEOUT` without crashing.

---

## 7. Checkpointing & State Persistence

LangGraph's native `MemorySaver` checkpointer is integrated:
- Checkpoints are saved per `thread_id` (defaulting to `investigation_id`).
- State updates are safely serialized (Pydantic models are serialized to dictionaries to maintain full `msgpack` compatibility).
- In-memory thread inspection allows retrieving execution history and step resumption.

---

## 8. Agent Statuses

| Status | Meaning |
| :--- | :--- |
| `SUCCESS` | Investigation completed and produced a valid `InvestigationReport`. |
| `INSUFFICIENT_EVIDENCE` | Alert lacked sufficient corroborating signals to reach a conclusion. |
| `LIMIT_REACHED` | Bounded iteration or tool-call limit reached before conclusion. |
| `PROVIDER_UNAVAILABLE` | Local LLM daemon (Ollama) or endpoint is unreachable. |
| `TOOL_ERROR` | A critical tool failed during execution. |
| `INVALID_INPUT` | Input payload failed schema validation. |
| `TIMEOUT` | Investigation wall-clock deadline expired. |
| `INVESTIGATION_ERROR` | Internal unhandled failure in workflow orchestration. |

---

## 9. Measured Performance

Evaluated on local workstation hardware with Ollama running `qwen3:8b` (VRAM: ~4.2GB) and `embeddinggemma:latest` (~680MB):

- **Graph Compilation Latency**: `< 5ms`
- **Unit & Mock Test Suite (10 tests)**: `30.06s`
- **Real Local Qwen End-to-End Investigation (Full Graph Traversal)**:
  - Tool Enrichment (`lookup_attack_technique` + `search_knowledge_base` + `get_related_events`): `~1.8s`
  - Model Memory Allocation / Switching: `~45-55s`
  - Local Qwen 3 8B Synthesis & Report Validation: `~25s`
  - Total E2E Latency: `~74s - 84s`
- **Final Report Quality**: Produced schema-valid `InvestigationReport` with citation to verified RAG chunk IDs and verified ATT&CK `T1110` mapping. Original severity (`HIGH`) and risk score (`65.0`) remained 100% intact.

---

## 10. How to Run

### Running Unit & Integration Tests
```powershell
pytest tests/test_langgraph_agent.py -v
```

### Running the Phase 7 Exit Gate
```powershell
python scripts/run_phase_exit_tests.py --phase 7
```
