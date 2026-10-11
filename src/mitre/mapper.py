"""Behavior-to-technique mapping engine for Phase 4.

Evaluates SecurityAlert instances against deterministic mapping rules and verifies
all candidates against the official ATT&CK catalog.
"""

from typing import List, Optional, Set
from src.mitre.catalog import AttackCatalog
from src.mitre.mapping_rules import BehaviorMappingRule, get_default_mapping_rules
from src.mitre.schemas import (
    BehaviorMappingResult,
    MappedTechnique,
    MappingStatus,
)
from src.risk_scoring.schema import SecurityAlert


class BehaviorMapper:
    """Evaluates alerts against deterministic mapping rules and links verified catalog techniques."""

    def __init__(
        self,
        catalog: AttackCatalog,
        rules: Optional[List[BehaviorMappingRule]] = None,
    ):
        self.catalog = catalog
        self.rules = rules or get_default_mapping_rules()
        self._validate_rule_catalog()

    def _validate_rule_catalog(self) -> None:
        """Verify that every rule's candidate technique ID exists in the loaded catalog."""
        for rule in self.rules:
            tech = self.catalog.lookup_technique(rule.candidate_technique_id)
            if tech is None:
                raise ValueError(
                    f"Invalid mapping rule '{rule.rule_id}': candidate technique "
                    f"'{rule.candidate_technique_id}' does not exist in verified ATT&CK catalog."
                )

    def map_alert(self, alert: SecurityAlert) -> BehaviorMappingResult:
        """Map an explainable SecurityAlert to verified candidate ATT&CK techniques."""
        if not isinstance(alert, SecurityAlert):
            raise TypeError(f"Expected SecurityAlert instance, got {type(alert)}")

        meta = self.catalog.get_metadata()
        candidates: List[MappedTechnique] = []
        all_tactics: Set[str] = set()
        all_evidence_fields: Set[str] = set()

        # Evaluate rules
        for rule in self.rules:
            eval_res = rule.evaluate(alert)
            if eval_res is not None:
                tech = self.catalog.lookup_technique(rule.candidate_technique_id)
                if tech is not None:
                    tactic_ids = [t.tactic_id for t in tech.tactics]
                    tactic_names = [t.name for t in tech.tactics]
                    for t_name in tactic_names:
                        all_tactics.add(t_name)

                    for ev_dict in eval_res["supporting_evidence"]:
                        all_evidence_fields.add(ev_dict.get("source_field", ""))

                    candidate = MappedTechnique(
                        technique_id=tech.technique_id,
                        technique_name=tech.name,
                        tactic_ids=tactic_ids,
                        tactic_names=tactic_names,
                        mapping_rule_id=rule.rule_id,
                        mapping_reason=eval_res["mapping_rationale"],
                        supporting_evidence=eval_res["supporting_evidence"],
                        confidence_level=eval_res["confidence_level"],
                        source_uri=tech.url,
                        attack_version=meta.attack_version,
                    )
                    candidates.append(candidate)

        # Determine overall mapping status
        if len(candidates) > 0:
            return BehaviorMappingResult(
                mapping_status=MappingStatus.MAPPED,
                candidate_techniques=candidates,
                associated_tactics=sorted(list(all_tactics)),
                unmapped_reason=None,
                supporting_evidence_fields=sorted(list(all_evidence_fields)),
                attack_version=meta.attack_version,
                catalog_source=meta.source_url,
            )

        # No candidate rules matched
        if len(alert.evidence) > 0 or alert.is_anomaly == 1:
            return BehaviorMappingResult(
                mapping_status=MappingStatus.INSUFFICIENT_EVIDENCE,
                candidate_techniques=[],
                associated_tactics=[],
                unmapped_reason=(
                    "Observed behavioral deviations do not provide sufficiently specific telemetry "
                    "to justify a standardized ATT&CK technique mapping."
                ),
                supporting_evidence_fields=[ev.source_field for ev in alert.evidence],
                attack_version=meta.attack_version,
                catalog_source=meta.source_url,
            )
        else:
            return BehaviorMappingResult(
                mapping_status=MappingStatus.NOT_MAPPED,
                candidate_techniques=[],
                associated_tactics=[],
                unmapped_reason="No anomalous behavioral indicators observed; telemetry represents baseline normal operations.",
                supporting_evidence_fields=[],
                attack_version=meta.attack_version,
                catalog_source=meta.source_url,
            )
