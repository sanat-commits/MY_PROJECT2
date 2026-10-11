# Investigation Output Contract

The eventual AI investigation response must be structured and validated before reaching the UI.

Required top-level fields:
- `investigation_id`
- `summary`
- `severity`
- `observed_evidence`
- `anomaly_interpretation`
- `possible_attack_techniques`
- `uncertainty`
- `recommended_next_steps`
- `citations`

Rules:
- Observed evidence must come from tool/data results, not invented text.
- `possible_attack_techniques` must contain only verified ATT&CK identifiers with source metadata.
- `citations` must point to retrieved RAG chunk/source IDs.
- The LLM must distinguish evidence from inference.
- If evidence is insufficient, say so explicitly.
