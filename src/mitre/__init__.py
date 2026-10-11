"""Phase 4 — MITRE ATT&CK Context Package.

Provides:
- MitreConfig, get_default_mitre_config
- TacticInfo, TechniqueInfo, CatalogMetadata, MappingStatus, ConfidenceLevel, MappedTechnique, BehaviorMappingResult, AlertWithMitreContext
- MitreIngestor, AttackCatalog, BehaviorMappingRule, BehaviorMapper, MitreService
- lookup_attack_technique, map_alert_behavior, enrich_alert
"""

from src.mitre.config import MitreConfig, get_default_mitre_config
from src.mitre.schemas import (
    TacticInfo,
    TechniqueInfo,
    CatalogMetadata,
    MappingStatus,
    ConfidenceLevel,
    MappedTechnique,
    BehaviorMappingResult,
    AlertWithMitreContext,
)
from src.mitre.ingest import MitreIngestor
from src.mitre.catalog import AttackCatalog
from src.mitre.mapping_rules import (
    BehaviorMappingRule,
    get_default_mapping_rules,
)
from src.mitre.mapper import BehaviorMapper
from src.mitre.service import (
    MitreService,
    lookup_attack_technique,
    map_alert_behavior,
    enrich_alert,
    get_mitre_service,
)

__all__ = [
    "MitreConfig",
    "get_default_mitre_config",
    "TacticInfo",
    "TechniqueInfo",
    "CatalogMetadata",
    "MappingStatus",
    "ConfidenceLevel",
    "MappedTechnique",
    "BehaviorMappingResult",
    "AlertWithMitreContext",
    "MitreIngestor",
    "AttackCatalog",
    "BehaviorMappingRule",
    "get_default_mapping_rules",
    "BehaviorMapper",
    "MitreService",
    "lookup_attack_technique",
    "map_alert_behavior",
    "enrich_alert",
    "get_mitre_service",
]
