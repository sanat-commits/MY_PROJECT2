"""Deterministic output validation, cross-checking, and citation verification for investigation reports."""

import json
import re
from typing import Any

from src.llm.schemas import (
    FindingType,
    InvestigationInput,
    InvestigationReport,
    ObservedEvidenceRef,
    ReportCitation,
)
from src.risk_scoring.schema import SeverityLevel


class OutputValidationError(Exception):
    """Raised when model generation fails structural or semantic validation."""
    pass


def extract_json_from_text(raw_text: str) -> str:
    """Extract clean JSON substring from potential markdown fences or commentary."""
    text = raw_text.strip()
    # Check for fenced code blocks
    if "```" in text:
        match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
        if match:
            return match.group(1).strip()
    # Find first { and last }
    first_brace = text.find("{")
    last_brace = text.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        return text[first_brace : last_brace + 1].strip()
    return text


def repair_json_string(s: str) -> str:
    """Attempt to repair truncated or slightly malformed JSON strings."""
    s = s.strip()
    if not s:
        return "{}"

    start_idx = s.find("{")
    if start_idx == -1:
        return s
    s = s[start_idx:]

    # Remove trailing commas before closing braces/brackets
    s = re.sub(r",\s*([\]}])", r"\1", s)

    try:
        json.loads(s)
        return s
    except Exception:
        pass

    in_string = False
    escape = False
    stack: list[str] = []
    repaired_chars: list[str] = []

    for char in s:
        if escape:
            escape = False
            repaired_chars.append(char)
            continue

        if char == "\\":
            escape = True
            repaired_chars.append(char)
            continue

        if char == '"':
            in_string = not in_string
            repaired_chars.append(char)
            continue

        if not in_string:
            if char in "{[":
                stack.append(char)
                repaired_chars.append(char)
            elif char in "}]":
                if stack:
                    matching = "{" if char == "}" else "["
                    if stack[-1] == matching:
                        stack.pop()
                        repaired_chars.append(char)
            else:
                repaired_chars.append(char)
        else:
            repaired_chars.append(char)

    repaired = "".join(repaired_chars)
    if in_string:
        repaired += '"'
    repaired = re.sub(r"[,:\s]+$", "", repaired)

    while stack:
        opener = stack.pop()
        if opener == "{":
            repaired += "}"
        elif opener == "[":
            repaired += "]"

    return repaired


class ReportValidator:
    """Validates LLM outputs against schema, ground-truth alert fields, and retrieval citations."""

    def __init__(self, strict_mode: bool = True):
        self.strict_mode = strict_mode

    def validate(
        self,
        raw_output: str,
        inv_input: InvestigationInput,
        model_metadata: dict[str, Any] | None = None,
    ) -> InvestigationReport:
        """Parse raw model string and perform deterministic cross-verification."""
        cleaned_json = extract_json_from_text(raw_output)
        data = None
        try:
            data = json.loads(cleaned_json)
        except json.JSONDecodeError:
            repaired = repair_json_string(cleaned_json)
            try:
                data = json.loads(repaired)
            except json.JSONDecodeError:
                pass

        if not isinstance(data, dict):
            # Best-effort regex extraction for top-level keys
            data = {}
            summary_m = re.search(r'"summary"\s*:\s*"([^"\\]*(?:\\.[^"\\]*)*)"', raw_output)
            if summary_m:
                data["summary"] = summary_m.group(1)
            finding_m = re.search(r'"finding"\s*:\s*"([^"]+)"', raw_output)
            if finding_m:
                data["finding"] = finding_m.group(1)
            interp_m = re.search(r'"interpretation"\s*:\s*"([^"\\]*(?:\\.[^"\\]*)*)"', raw_output)
            if interp_m:
                data["interpretation"] = interp_m.group(1)
            uncert_m = re.search(r'"uncertainty"\s*:\s*"([^"\\]*(?:\\.[^"\\]*)*)"', raw_output)
            if uncert_m:
                data["uncertainty"] = uncert_m.group(1)

        if not isinstance(data, dict) or not data:
            raise OutputValidationError("Model output could not be parsed as a structured JSON object.")

        # 1. Application-Owned Field Reconciliation
        # Strict enforcement: The application owns the canonical alert state
        alert_id = inv_input.alert_id
        investigation_id = inv_input.investigation_id
        supplied_severity = inv_input.severity
        supplied_risk_score = inv_input.risk_score

        # Check summary
        summary = str(data.get("summary", "")).strip()
        if not summary:
            summary = f"Security investigation for alert {alert_id} on window {inv_input.window_id}."

        # Check finding enum
        raw_finding = str(data.get("finding", "ANOMALOUS_ACTIVITY")).upper().strip()
        try:
            finding = FindingType(raw_finding)
        except ValueError:
            finding = FindingType.ANOMALOUS_ACTIVITY

        # Check interpretation
        interpretation = str(data.get("interpretation", "")).strip()
        if not interpretation:
            interpretation = "Telemetry exhibits abnormal variance requiring analyst review."

        # Check uncertainty
        uncertainty = str(data.get("uncertainty", "")).strip()
        if not uncertainty:
            uncertainty = "Aggregated window telemetry does not confirm malicious intent or active compromise."

        # Check recommended next steps
        raw_steps = data.get("recommended_next_steps", [])
        if isinstance(raw_steps, list):
            next_steps = [str(s).strip() for s in raw_steps if str(s).strip()]
        else:
            next_steps = []
        if not next_steps:
            next_steps = ["Inspect host authentication and process creation logs for the target window."]

        # Check limitations
        raw_limits = data.get("limitations", [])
        if isinstance(raw_limits, list):
            limitations = [str(l).strip() for l in raw_limits if str(l).strip()]
        else:
            limitations = []
        if not limitations:
            limitations = ["Telemetry consists of statistical 1-hour window aggregations without command line details."]

        # 2. Observed Evidence References
        observed_evidence: list[ObservedEvidenceRef] = []
        raw_obs = data.get("observed_evidence", [])
        if isinstance(raw_obs, list):
            for item in raw_obs:
                if isinstance(item, dict) and "field_name" in item:
                    observed_evidence.append(
                        ObservedEvidenceRef(
                            field_name=str(item["field_name"]),
                            observed_value=item.get("observed_value"),
                            description=str(item.get("description", "")),
                        )
                    )
        # Fallback to actual alert evidence items if model emitted empty
        if not observed_evidence and inv_input.evidence_items:
            for ev in inv_input.evidence_items:
                observed_evidence.append(
                    ObservedEvidenceRef(
                        field_name=ev.source_field,
                        observed_value=ev.observed_value,
                        description=ev.explanation,
                    )
                )

        # 3. Verified ATT&CK Technique Validation
        # The model CANNOT invent technique IDs not present in Phase 4 verified context
        allowed_tids = {
            t.get("technique_id")
            for t in inv_input.mitre_candidate_techniques
            if t.get("technique_id")
        }
        raw_tids = data.get("possible_attack_techniques", [])
        verified_tids: list[str] = []
        if isinstance(raw_tids, list):
            for t in raw_tids:
                t_str = str(t).strip().upper()
                if t_str in allowed_tids and t_str not in verified_tids:
                    verified_tids.append(t_str)

        # 4. Citation Validation against Supplied Phase 5 Context
        # Every cited chunk_id MUST exist in the supplied RAG context
        valid_chunks_by_id = {
            c.get("chunk_id"): c
            for c in inv_input.rag_chunks
            if c.get("chunk_id")
        }
        raw_citations = data.get("citations", [])
        verified_citations: list[ReportCitation] = []
        if isinstance(raw_citations, list) and valid_chunks_by_id:
            for cit in raw_citations:
                if isinstance(cit, dict) and "chunk_id" in cit:
                    cid = cit["chunk_id"].strip()
                    if cid in valid_chunks_by_id:
                        real_chunk = valid_chunks_by_id[cid]
                        text = (
                            real_chunk.get("content")
                            or real_chunk.get("relevant_text")
                            or (cit.get("relevant_text") if isinstance(cit, dict) else None)
                        )
                        verified_citations.append(
                            ReportCitation(
                                chunk_id=cid,
                                source_id=real_chunk.get("source_id", "unknown"),
                                source_title=real_chunk.get("source_title", "Unknown Source"),
                                source_uri_or_path=real_chunk.get("source_uri_or_path", ""),
                                document_title=real_chunk.get("document_title"),
                                relevant_text=text,
                                content=text,
                            )
                        )

        # Assemble validated report
        report = InvestigationReport(
            investigation_id=investigation_id,
            alert_id=alert_id,
            summary=summary,
            supplied_severity=supplied_severity,
            supplied_risk_score=supplied_risk_score,
            finding=finding,
            observed_evidence=observed_evidence,
            interpretation=interpretation,
            possible_attack_techniques=verified_tids,
            uncertainty=uncertainty,
            recommended_next_steps=next_steps,
            citations=verified_citations,
            limitations=limitations,
            model_metadata=model_metadata or {},
        )
        return report
