# Detailed Project Phases

## Phase 0 — Environment Discovery
- Inspect repo, Python version, package manager and installed dependencies.
- Detect local LLM provider.
- If using Ollama, query its local model list and select/verify an installed Qwen 3 8B candidate.
- Never assume the exact model tag.
- Run dataset generation and validation.
- Record findings in `HANDOFF.md`.

Exit: environment status is known; dataset exists; baseline tests pass.

## Phase 1 — Dataset Validation
- Load synthetic CSVs with Pandas.
- Validate schema/types/ranges/missing values.
- Separate metadata from model features.
- Confirm training set is normal-only.
- Confirm evaluation set contains labeled normal/anomaly rows.
- Generate a small validation report.
- Document that all data is synthetic.

Exit: schema and quality checks pass.

## Phase 2 — Baseline ML
- Train Isolation Forest on training-normal rows only.
- Use behavioral numeric features.
- Fit preprocessing only on training data.
- Score evaluation rows.
- Select the alert threshold from documented validation logic; do not pick an arbitrary magic number.
- Save model + preprocessing artifacts.
- Report precision/recall/F1 against synthetic labels.

Exit: reproducible train/evaluate commands and loadable artifacts.

## Phase 3 — Risk Scoring
- Combine anomaly evidence into a transparent priority/risk score.
- Keep the individual contributors visible.
- Define severity bands.
- Do not call risk score a probability unless calibrated/validated.
- Produce stable alert IDs.

Exit: every alert has anomaly score, risk score, severity and evidence.

## Phase 4 — MITRE ATT&CK Context
- Choose a verified MITRE ATT&CK source/version.
- Store exact source/version.
- Map only supported observed behaviors to real technique/sub-technique IDs.
- Preserve mapping evidence.
- Use “possible” when evidence is incomplete.

Exit: no fabricated technique IDs/mappings.

## Phase 5 — RAG Knowledge Base
- Ingest approved MITRE content plus selected verified Sigma/threat-hunting/security docs.
- Chunk deterministically.
- Embed with a configurable embedding model.
- Store vectors in configurable Chroma/Qdrant/other backend.
- Implement top-k retrieval.
- Return source metadata/citations.
- Handle no-result retrieval safely.

Exit: retrieval tests return relevant chunks with attributable sources.

## Phase 6 — Local Qwen 3 8B
- Implement a provider interface.
- Discover/verify the local Qwen model at startup.
- Create strict structured output schema.
- Prompt with separate sections for observed evidence, ML output, MITRE context, retrieved context and uncertainty.
- Require the model to avoid inventing facts.
- Parse and validate the model response.
- Handle timeouts/unavailable provider clearly.

Required report fields:
summary, severity, observed_evidence, anomaly_interpretation, possible_attack_techniques, uncertainty, recommended_next_steps, citations.

Exit: fixed synthetic alerts reliably produce schema-valid reports.

## Phase 7 — LangGraph Investigation Agent
Graph:
START -> load alert -> inspect related events -> retrieve RAG -> verify MITRE context -> analyze evidence -> decide whether more evidence is needed -> final report -> END.

Minimum tools:
- search_logs
- get_related_events
- search_knowledge_base
- lookup_attack_technique

Optional later:
- lookup_threat_intel

Every tool invocation must be traceable in agent state.

Exit: replayable, traceable investigation workflow.

## Phase 8 — API
Add validated endpoints for:
health, model/provider status, alerts list/detail, analyze alert, investigation result.

Exit: integration tests pass.

## Phase 9 — Dashboard
Views:
- Overview
- Alerts
- Alert details
- Evidence timeline
- MITRE context
- AI report
- RAG citations

Clearly display synthetic/demo status.

Exit: user can select an alert and see evidence -> AI investigation.

## Phase 10 — Evaluation/Resume Readiness
Measure:
- anomaly precision/recall/F1,
- false-positive rate on synthetic normal data,
- inference latency,
- retrieval quality on hand-checked queries,
- structured-output validity,
- tool failure rate,
- agent completion rate.

Prepare architecture diagram, setup docs, evaluation report, screenshots and resume bullets.
