# AI-Powered Security Log Anomaly Detection & Investigation

A staged beginner-friendly cybersecurity + ML + local-LLM project.

## Goal
Build a system that:
1. ingests security-log-like behavioral windows,
2. learns normal behavior with anomaly detection,
3. identifies suspicious windows,
4. assigns a transparent risk score,
5. maps supported behaviors to verified MITRE ATT&CK techniques,
6. retrieves relevant cybersecurity knowledge with RAG,
7. uses a locally hosted Qwen 3 8B model to investigate and explain alerts,
8. exposes results through an API/dashboard.

## Architecture
Logs -> preprocessing -> feature engineering -> ML anomaly detection -> risk scoring -> alert -> LangGraph investigation -> MITRE/RAG/tools -> Qwen 3 8B -> structured investigation report -> dashboard.

## Important
The seeded dataset is synthetic. It must never be presented as real-world telemetry or evidence of real attacks.

Read `AGENTS.md`, then `PHASES.md`, then `HANDOFF.md` before implementation.
