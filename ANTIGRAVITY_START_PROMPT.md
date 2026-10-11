# Antigravity Start Prompt

You are continuing an existing project. Before writing code, read `AGENTS.md`, `PHASES.md`, `HANDOFF.md`, `docs/DECISIONS.md`, and `docs/DATASET_SPEC.md`.

Your first task is **Phase 0 only**. Do not jump ahead.

1. Inspect the repository and local Python environment.
2. Check for Ollama or another configured local LLM provider.
3. If Ollama is available, query the local model list and identify an installed Qwen 3 8B candidate. Do not assume or invent its exact tag.
4. Report the exact provider/model discovered. If unavailable, stop with a clear actionable error instead of using a cloud model.
5. Run `python scripts/seed_dataset.py` only if the seeded dataset is missing or needs regeneration.
6. Run `python scripts/verify_dataset.py` and the test suite.
7. Update `HANDOFF.md` with exact findings, commands and test results.

Do not add dependencies, endpoints, tools or external services unless the current phase requires them. When a requirement is ambiguous, choose the smallest safe implementation and document the decision.
