"""System prompts and prompt assembly for local Qwen 3 8B investigation."""

import json
from src.llm.schemas import InvestigationInput

SYSTEM_PROMPT_V1 = """You are an expert Cybersecurity Investigation Assistant analyzing security telemetry alerts from an enterprise security monitoring platform.

Your task is to review the provided structured alert, synthesize observed evidence, integrate verified MITRE ATT&CK techniques, leverage retrieved cybersecurity knowledge, and produce a structured, factual investigation report.

CRITICAL INVESTIGATION RULES:
1. EVIDENCE HIERARCHY:
   - Ground Truth Observations: Factual telemetry values recorded in the alert evidence.
   - ML Baseline Score: Statistical anomaly indicator from an Isolation Forest model (NOT an attack probability).
   - Risk Assessment: Priority score (0-100) and severity band (LOW, MEDIUM, HIGH, CRITICAL) calculated deterministically.
   - Verified ATT&CK Context: Officially mapped techniques from the authoritative catalog.
   - Retrieved Knowledge: Chunks from verified Sigma rules, ATT&CK documents, and investigation guides.
   - Model Interpretation: Explanatory hypotheses explaining how evidence relates to possible threat activity.

2. STRICT PRESERVATION OF APPLICATION STATE:
   - You MUST preserve `supplied_severity` and `supplied_risk_score` EXACTLY as given in the alert input. Do not alter, override, or invent new scores.
   - If evidence appears contradictory, discuss the nuance in `uncertainty`, but do not change the supplied severity.

3. NO FABRICATION:
   - Never invent log events, IP addresses, usernames, hosts, file paths, command-line arguments, process names, malware families, or threat actors not present in the input.
   - `possible_attack_techniques`: ONLY list technique IDs (e.g. "T1110") explicitly verified in the "Verified MITRE ATT&CK Context" section. If no techniques were verified or the status is NOT_MAPPED/INSUFFICIENT_EVIDENCE, return an empty array [].
   - `citations`: ONLY cite `chunk_id` values explicitly provided in the "Retrieved Knowledge Base Chunks" section. If no chunks were retrieved or retrieval returned no results, `citations` MUST be an empty array [].

4. EXPLICIT UNCERTAINTY & TERMINOLOGY:
   - An anomaly is NOT proof of an attack or compromise.
   - Use calibrated terminology: "anomalous", "suspicious", "consistent with", "possible", "insufficient evidence", "requires investigation".
   - Under `uncertainty`, explicitly document what cannot be determined from the aggregated telemetry.

5. OUTPUT FORMAT:
   - Respond strictly in JSON format matching the schema below.
   - Do NOT wrap your output in conversational filler or commentary.

6. CONCISENESS & SYNTAX CLOSURE:
   - Keep `summary` to 1-2 focused, factual sentences.
   - Keep `interpretation` to 2-3 clear sentences explaining the observed deviation.
   - In `observed_evidence`, cite 2-3 key observed telemetry signals.
   - Under `recommended_next_steps`, provide 2-3 prioritized action items.
   - Keep `uncertainty` to 1-2 sentences on telemetry boundaries.
   - Ensure you close all JSON braces and brackets completely. Keep output under 450 tokens.

SCHEMA SPECIFICATION:
{
  "investigation_id": string,
  "alert_id": string,
  "summary": string,
  "supplied_severity": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "supplied_risk_score": float,
  "finding": "ANOMALOUS_ACTIVITY" | "SUSPICIOUS_ACTIVITY" | "POSSIBLE_ATTACK" | "INSUFFICIENT_EVIDENCE",
  "observed_evidence": [
    {"field_name": string, "observed_value": any, "description": string}
  ],
  "interpretation": string,
  "possible_attack_techniques": [string],
  "uncertainty": string,
  "recommended_next_steps": [string],
  "citations": [
    {"chunk_id": string, "source_id": string, "source_title": string, "source_uri_or_path": string, "document_title": string}
  ],
  "limitations": [string]
}
"""


def build_investigation_user_prompt(
    inv_input: InvestigationInput,
    max_context_chunks: int = 5,
) -> str:
    """Construct structured user prompt presenting verified alert context and retrieved knowledge."""
    # 1. Alert Summary
    prompt_lines = [
        f"### INVESTIGATION REQUEST: {inv_input.investigation_id}",
        f"- **Alert ID**: {inv_input.alert_id}",
        f"- **Window ID**: {inv_input.window_id}",
        f"- **Created At**: {inv_input.created_at or 'Not recorded'}",
        f"- **Phase 2 Anomaly Score**: {inv_input.anomaly_score:.6f} (is_anomaly={inv_input.is_anomaly})",
        f"- **Phase 3 Risk Score**: {inv_input.risk_score:.2f} / 100.0",
        f"- **Phase 3 Severity**: {inv_input.severity.value}",
        "",
        "### 1. VERIFIED OBSERVED EVIDENCE",
    ]

    if inv_input.evidence_items:
        for ev in inv_input.evidence_items:
            rule = getattr(ev, "comparison_or_rule", getattr(ev, "signal_name", "rule"))
            pts = getattr(ev, "contribution", 0.0)
            prompt_lines.append(
                f"- **{ev.source_field}**: {ev.observed_value} ({rule}) -> {ev.explanation} [+{pts:.2f} pts]"
            )
    else:
        prompt_lines.append("- No positive anomalous behavioral evidence contributors were recorded.")

    prompt_lines.extend([
        "",
        "### 2. RISK SCORE BREAKDOWN",
    ])
    if inv_input.score_breakdown:
        for k, v in inv_input.score_breakdown.items():
            if isinstance(v, (int, float)):
                prompt_lines.append(f"- {k}: {v:.2f} pts")
            elif isinstance(v, dict):
                comp_pts = v.get("contribution", v.get("calculated_points", ""))
                prompt_lines.append(f"- {k}: {comp_pts}")
            else:
                prompt_lines.append(f"- {k}: {v}")
    else:
        prompt_lines.append("- Breakdown details not supplied.")


    # 3. MITRE ATT&CK Context
    prompt_lines.extend([
        "",
        "### 3. VERIFIED MITRE ATT&CK CONTEXT",
        f"- **Mapping Status**: {inv_input.mitre_status or 'NOT_EVALUATED'}",
    ])
    if inv_input.mitre_candidate_techniques:
        for t in inv_input.mitre_candidate_techniques:
            tid = t.get("technique_id", "Unknown")
            tname = t.get("technique_name", "")
            tactics = ", ".join(t.get("tactic_names", []))
            reason = t.get("mapping_reason", "")
            conf = t.get("confidence_level", "")
            prompt_lines.append(
                f"- **{tid} - {tname}**: Tactics=[{tactics}], Confidence={conf}, Reason='{reason}'"
            )
    else:
        prompt_lines.append("- No candidate MITRE ATT&CK techniques were mapped from observed evidence.")

    # 4. Retrieved Knowledge Chunks
    prompt_lines.extend([
        "",
        "### 4. RETRIEVED CYBERSECURITY KNOWLEDGE BASE CHUNKS",
        f"- **Retrieval Status**: {inv_input.rag_status}",
    ])
    selected_chunks = inv_input.rag_chunks[:max_context_chunks]
    if selected_chunks:
        for idx, chunk in enumerate(selected_chunks, start=1):
            cid = chunk.get("chunk_id", "unknown")
            stitle = chunk.get("source_title", "Unknown Source")
            dtitle = chunk.get("document_title", stitle)
            uri = chunk.get("source_uri_or_path", "")
            content = chunk.get("content", "").strip()
            prompt_lines.extend([
                f"--- CHUNK {idx} [chunk_id: {cid}] ---",
                f"Source: {stitle} | Document: {dtitle} | URI: {uri}",
                f"{content}",
                "",
            ])
    else:
        prompt_lines.append("- No relevant knowledge base chunks retrieved (or status is NO_RESULTS).")

    prompt_lines.extend([
        "### INSTRUCTIONS FOR YOUR REPORT",
        "Generate a structured investigation report adhering to the system rules and JSON schema.",
        f"Remember: `alert_id` MUST be '{inv_input.alert_id}', `supplied_severity` MUST be '{inv_input.severity.value}', and `supplied_risk_score` MUST be {inv_input.risk_score}.",
        "Cite only the chunk_id values listed above if relevant, or provide an empty citations list if none apply.",
    ])

    return "\n".join(prompt_lines)
