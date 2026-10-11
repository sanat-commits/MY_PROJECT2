"""Deterministic behavior-to-technique mapping rules for Phase 4.

Defines typed rule definitions, evidence requirements, rationales, and limitations.
Strictly maps verified behavioral telemetry evidence to candidate ATT&CK techniques
without relying on synthetic ground truth labels or LLM hallucinations.
"""

from typing import Any, Callable, Dict, List, Optional
from pydantic import BaseModel, Field

from src.mitre.schemas import ConfidenceLevel
from src.risk_scoring.schema import SecurityAlert


class BehaviorMappingRule(BaseModel):
    """Specification for mapping observed alert evidence to a candidate ATT&CK technique."""

    rule_id: str = Field(..., description="Unique rule identifier")
    description: str = Field(..., description="Operational summary of the mapping rule")
    applicable_behavior: str = Field(..., description="Observed system behavior pattern targeted")
    required_evidence_fields: List[str] = Field(
        ..., description="Telemetry field names that must be positively evidenced"
    )
    candidate_technique_id: str = Field(
        ..., description="Candidate MITRE ATT&CK technique ID (must exist in verified catalog)"
    )
    mapping_rationale: str = Field(
        ..., description="Documented justification linking evidence to technique definition"
    )
    confidence_level: ConfidenceLevel = Field(
        ..., description="Base confidence assessment (low, medium, high)"
    )
    limitations: str = Field(
        ..., description="Documented telemetry constraints and explicit uncertainties"
    )
    rule_version: str = Field(default="v1.0.0", description="Semantic rule version")

    def evaluate(self, alert: SecurityAlert) -> Optional[Dict[str, Any]]:
        """Evaluate rule against a SecurityAlert.
        
        Returns a dictionary of matching metadata and supporting evidence if matched, or None.
        Guarantees that:
        - Synthetic labels (anomaly_type, label) are NEVER checked.
        - Only verified positive evidence items in alert.evidence are used.
        - If any required field is missing from positive evidence, returns None.
        """
        # Map source_fields present in positive alert evidence
        evidence_by_field: Dict[str, Any] = {}
        for ev in alert.evidence:
            if ev.contribution > 0.0:
                evidence_by_field[ev.source_field] = ev

        # Verify all required evidence fields are present in positive evidence
        matched_evidence = []
        for req_field in self.required_evidence_fields:
            if req_field not in evidence_by_field:
                return None  # Required evidence not observed
            matched_evidence.append(evidence_by_field[req_field].model_dump())

        # Determine dynamic confidence based on intensity
        confidence = self.confidence_level

        if self.rule_id == "RULE_AUTH_BRUTE_FORCE":
            fl_val = float(evidence_by_field["failed_logins"].observed_value)
            if fl_val >= 25.0:
                confidence = ConfidenceLevel.HIGH
            elif fl_val >= 10.0:
                confidence = ConfidenceLevel.MEDIUM
            else:
                confidence = ConfidenceLevel.LOW

        elif self.rule_id == "RULE_EXFIL_ALTERNATIVE":
            bo_val = float(evidence_by_field["bytes_out_mb"].observed_value)
            if bo_val >= 500.0:
                confidence = ConfidenceLevel.HIGH
            else:
                confidence = ConfidenceLevel.MEDIUM

        elif self.rule_id == "RULE_NETWORK_EGRESS_PROTOCOL":
            ec_val = float(evidence_by_field["external_connections"].observed_value)
            if ec_val >= 50.0:
                confidence = ConfidenceLevel.HIGH
            else:
                confidence = ConfidenceLevel.MEDIUM

        elif self.rule_id == "RULE_EXEC_COMMAND_INTERPRETER":
            rp_val = float(evidence_by_field["rare_process_count"].observed_value)
            if rp_val >= 10.0:
                confidence = ConfidenceLevel.HIGH
            else:
                confidence = ConfidenceLevel.MEDIUM

        return {
            "rule_id": self.rule_id,
            "candidate_technique_id": self.candidate_technique_id,
            "mapping_rationale": self.mapping_rationale,
            "confidence_level": confidence,
            "supporting_evidence": matched_evidence,
            "limitations": self.limitations,
        }


def get_default_mapping_rules() -> List[BehaviorMappingRule]:
    """Return the authoritative, versioned catalog of deterministic behavior-to-technique rules."""
    return [
        BehaviorMappingRule(
            rule_id="RULE_AUTH_BRUTE_FORCE",
            description="Maps authentication failure bursts to T1110 (Brute Force)",
            applicable_behavior="Repeated authentication failures exceeding normal baseline",
            required_evidence_fields=["failed_logins"],
            candidate_technique_id="T1110",
            mapping_rationale=(
                "Authentication failure burst significantly exceeds normal baseline (p99=3.0), "
                "consistent with automated password guessing, credential stuffing, or brute force (T1110)."
            ),
            confidence_level=ConfidenceLevel.MEDIUM,
            limitations=(
                "Aggregated window counts do not reveal targeted user accounts, protocol variants, "
                "or source IP reputation; cannot confirm if brute force attempts succeeded."
            ),
            rule_version="v1.0.0",
        ),
        BehaviorMappingRule(
            rule_id="RULE_PRIV_VALID_ACCOUNTS",
            description="Maps off-hours elevated execution to T1078 (Valid Accounts)",
            applicable_behavior="Privileged actions executed during off-hours schedule",
            required_evidence_fields=["privileged_actions", "after_hours"],
            candidate_technique_id="T1078",
            mapping_rationale=(
                "Elevated administrative actions observed outside scheduled business hours, "
                "consistent with possible abuse or compromise of valid administrative credentials (T1078)."
            ),
            confidence_level=ConfidenceLevel.MEDIUM,
            limitations=(
                "Telemetry aggregates action count only; individual user identities, authorization "
                "tickets, and executed commands are unrecorded."
            ),
            rule_version="v1.0.0",
        ),
        BehaviorMappingRule(
            rule_id="RULE_NETWORK_EGRESS_PROTOCOL",
            description="Maps perimeter egress connection spikes to T1071 (Application Layer Protocol)",
            applicable_behavior="Anomalous perimeter egress network connection frequency",
            required_evidence_fields=["external_connections"],
            candidate_technique_id="T1071",
            mapping_rationale=(
                "Egress perimeter network session count significantly exceeds normal baseline (p99=19.0), "
                "consistent with outbound application layer command and control communication (T1071)."
            ),
            confidence_level=ConfidenceLevel.MEDIUM,
            limitations=(
                "Aggregated counts omit transport protocols (HTTP/HTTPS/DNS), destination IP reputations, "
                "and URI endpoints."
            ),
            rule_version="v1.0.0",
        ),
        BehaviorMappingRule(
            rule_id="RULE_EXFIL_ALTERNATIVE",
            description="Maps outbound data transfer spikes to T1048 (Exfiltration Over Alternative Protocol)",
            applicable_behavior="High-volume outbound data egress spike",
            required_evidence_fields=["bytes_out_mb"],
            candidate_technique_id="T1048",
            mapping_rationale=(
                "Significant spike in outbound network egress volume (MB) exceeding normal baseline (p99=26.9 MB), "
                "consistent with bulk data staging or unauthorized exfiltration (T1048)."
            ),
            confidence_level=ConfidenceLevel.MEDIUM,
            limitations=(
                "Data volume egress does not verify payload content, encryption status, or confirm whether "
                "transferred data was sensitive."
            ),
            rule_version="v1.0.0",
        ),
        BehaviorMappingRule(
            rule_id="RULE_EXEC_COMMAND_INTERPRETER",
            description="Maps rare process execution bursts to T1059 (Command and Scripting Interpreter)",
            applicable_behavior="Burst of atypical binary or system utility executions",
            required_evidence_fields=["rare_process_count"],
            candidate_technique_id="T1059",
            mapping_rationale=(
                "Atypical binary execution frequency exceeds normal baseline (p99=1.0), "
                "consistent with execution of non-standard command or script interpreters (T1059)."
            ),
            confidence_level=ConfidenceLevel.MEDIUM,
            limitations=(
                "Process names, process tree ancestry, command-line arguments, and hashes are unrecorded."
            ),
            rule_version="v1.0.0",
        ),
    ]
