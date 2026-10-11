"""Unified MITRE ATT&CK service and agent tool foundation for Phase 4.

Provides standardized lookup, search, tactics queries, and alert enrichment
conforming to the agent tool specifications in docs/TOOL_CONTRACTS.md.
"""

from typing import Any, Dict, List, Optional, Union
from src.mitre.catalog import AttackCatalog
from src.mitre.config import MitreConfig, get_default_mitre_config
from src.mitre.mapper import BehaviorMapper
from src.mitre.schemas import (
    AlertWithMitreContext,
    BehaviorMappingResult,
    CatalogMetadata,
    MappingStatus,
    TechniqueInfo,
)
from src.risk_scoring.schema import SecurityAlert


class MitreService:
    """Unified service providing MITRE ATT&CK catalog queries and alert enrichment."""

    def __init__(
        self,
        config: Optional[MitreConfig] = None,
        catalog: Optional[AttackCatalog] = None,
    ):
        self.config = config or get_default_mitre_config()
        self._catalog = catalog
        self._mapper: Optional[BehaviorMapper] = None

    @property
    def catalog(self) -> AttackCatalog:
        if self._catalog is None:
            self._catalog = AttackCatalog.load(self.config)
        return self._catalog

    @property
    def mapper(self) -> BehaviorMapper:
        if self._mapper is None:
            self._mapper = BehaviorMapper(self.catalog)
        return self._mapper

    def lookup_attack_technique(self, technique_id: str) -> Dict[str, Any]:
        """Query verified ATT&CK technique by ID.
        
        Designed for the lookup_attack_technique agent tool contract (docs/TOOL_CONTRACTS.md).
        Distinguishes:
        - success
        - not_found
        - invalid_input
        - catalog_unavailable
        """
        if not isinstance(technique_id, str) or not technique_id.strip():
            return {
                "status": "invalid_input",
                "error": "Technique ID must be a non-empty string.",
                "data": None,
            }

        try:
            tech = self.catalog.lookup_technique(technique_id)
        except ValueError as e:
            return {
                "status": "invalid_input",
                "error": str(e),
                "data": None,
            }
        except Exception as e:
            return {
                "status": "catalog_unavailable",
                "error": f"Failed to access ATT&CK catalog: {e}",
                "data": None,
            }

        if tech is None:
            return {
                "status": "not_found",
                "message": f"Technique ID '{technique_id.strip().upper()}' was not found in the verified catalog.",
                "data": None,
            }

        meta = self.catalog.get_metadata()
        return {
            "status": "success",
            "data": {
                "technique_id": tech.technique_id,
                "name": tech.name,
                "description": tech.description,
                "is_subtechnique": tech.is_subtechnique,
                "parent_technique_id": tech.parent_technique_id,
                "tactics": [t.model_dump() for t in tech.tactics],
                "platforms": tech.platforms,
                "detection": tech.detection,
                "url": tech.url,
                "source_metadata": {
                    "attack_version": meta.attack_version,
                    "domain": meta.domain,
                    "source_url": meta.source_url,
                },
            },
        }

    def search_attack_techniques(self, query: str, max_results: int = 10) -> List[Dict[str, Any]]:
        """Search techniques by keywords across ID, name, and description."""
        matches = self.catalog.search_techniques(query, max_results=max_results)
        return [m.model_dump() for m in matches]

    def get_technique_tactics(self, technique_id: str) -> List[Dict[str, Any]]:
        """Retrieve associated tactic objectives for a technique ID."""
        tactics = self.catalog.get_technique_tactics(technique_id)
        return [t.model_dump() for t in tactics]

    def map_alert_behavior(self, alert: SecurityAlert) -> BehaviorMappingResult:
        """Map alert evidence to candidate ATT&CK techniques."""
        return self.mapper.map_alert(alert)

    def enrich_alert(self, alert: SecurityAlert) -> AlertWithMitreContext:
        """Enrich a Phase 3 SecurityAlert with ATT&CK context without mutating existing scores."""
        mapping_result = self.map_alert_behavior(alert)
        alert_dict = alert.model_dump()
        alert_dict["attack_context"] = mapping_result
        return AlertWithMitreContext(**alert_dict)


# Functional convenience interfaces
_default_service: Optional[MitreService] = None


def get_mitre_service() -> MitreService:
    global _default_service
    if _default_service is None:
        _default_service = MitreService()
    return _default_service


def lookup_attack_technique(technique_id: str) -> Dict[str, Any]:
    return get_mitre_service().lookup_attack_technique(technique_id)


def map_alert_behavior(alert: SecurityAlert) -> BehaviorMappingResult:
    return get_mitre_service().map_alert_behavior(alert)


def enrich_alert(alert: SecurityAlert) -> AlertWithMitreContext:
    return get_mitre_service().enrich_alert(alert)
