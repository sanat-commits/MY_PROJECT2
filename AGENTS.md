# Antigravity Agent Contract

Correctness, traceability and explicit uncertainty are more important than speed.

## Never hallucinate project state
Before changing code, inspect the repository tree, source/config/tests, `HANDOFF.md`, `PHASES.md`, and `docs/DECISIONS.md`.
Never claim a dependency, endpoint, dataset, model, tool result, threat-intel verdict, MITRE mapping, or file exists unless verified.

## Never hardcode environment-specific values
Do not hardcode secrets, local paths, credentials, hostnames, ports, API keys, model tags, threat verdicts or fabricated evidence.
Use `.env`/configuration.
For Qwen 3 8B, discover the installed local model at runtime and verify it before use. Do not silently fall back to a cloud model.

## Tool contract
Every agent tool must have typed inputs/outputs, validation, explicit error states, logging, and tests.
Tool results are authoritative evidence. The LLM must never fabricate a tool result.
When a tool fails, preserve the failure in agent state.

## Cybersecurity truthfulness
An anomaly is not proof of compromise.
Use `anomalous`, `suspicious`, `possible`, `consistent with`, `requires investigation`.
MITRE ATT&CK IDs must be verified and source-backed.
Synthetic IPs/domains are demo data only.
Threat-intelligence verdicts require a named source and timestamp.

## LLM role
ML/rules detect and score evidence.
The LLM synthesizes evidence, explains it, identifies uncertainty, and proposes investigation steps.
Do not use the LLM as the sole detector.

## RAG
Every chunk must retain source title, URI/path, type, version/date where available, and chunk ID.
Final outputs must cite retrieved source IDs. Never fabricate citations.

## Reproducibility
Dataset generation, preprocessing, training and evaluation must be scriptable and deterministic.
No manual edits to seeded datasets.

## Testing
Every phase needs tests for success, malformed input, missing dependency, unavailable model/provider, tool failure, empty retrieval, and uncertain outputs where applicable.

## Change control
After meaningful changes, update `HANDOFF.md` and `docs/DECISIONS.md` when architecture changes. Record commands/tests and blockers.

## Definition of done
A feature is done only when it works on a clean environment, has tests, handles failure modes, documents configuration, avoids secrets/hardcoded environment values, and the handoff matches implementation.
