"""Catalog access service for verified MITRE ATT&CK techniques and tactics.

Provides exact ID lookup, multi-tactic resolution, keyword search, and metadata retrieval
without fabricating nonexistent records or synthesizing arbitrary IDs.
"""

import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Union

from src.mitre.config import MitreConfig, get_default_mitre_config
from src.mitre.schemas import CatalogMetadata, TacticInfo, TechniqueInfo

TECHNIQUE_ID_REGEX = re.compile(r"^T\d{4}(\.\d{3})?$", re.IGNORECASE)


class AttackCatalog:
    """Production service for querying the verified MITRE ATT&CK technique catalog."""

    def __init__(
        self,
        metadata: CatalogMetadata,
        techniques: Dict[str, TechniqueInfo],
        tactics: Dict[str, TacticInfo],
    ):
        self.metadata = metadata
        self.techniques = techniques
        self.tactics = tactics

    @classmethod
    def load(cls, config: Optional[MitreConfig] = None) -> "AttackCatalog":
        """Load catalog from local cache. Ingests fixture if cache is not yet initialized."""
        cfg = config or get_default_mitre_config()
        catalog_path = cfg.cached_catalog_path

        if not catalog_path.exists():
            # Ingest from fixture/configured source
            from src.mitre.ingest import MitreIngestor

            ingestor = MitreIngestor(cfg)
            ingestor.ingest_and_cache()

        if not catalog_path.exists():
            raise FileNotFoundError(f"MITRE ATT&CK catalog unavailable at {catalog_path}")

        try:
            with open(catalog_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            raise RuntimeError(f"Corrupted or unreadable MITRE ATT&CK catalog at {catalog_path}: {e}")

        meta = CatalogMetadata(**data["metadata"])
        tactics = {k: TacticInfo(**v) for k, v in data.get("tactics", {}).items()}
        techniques = {k: TechniqueInfo(**v) for k, v in data.get("techniques", {}).items()}

        return cls(metadata=meta, techniques=techniques, tactics=tactics)

    def validate_technique_id_syntax(self, technique_id: str) -> str:
        """Validate technique ID format (T#### or T####.###)."""
        if not isinstance(technique_id, str):
            raise TypeError(f"Technique ID must be string, got {type(technique_id)}")

        clean_id = technique_id.strip().upper()
        if not TECHNIQUE_ID_REGEX.match(clean_id):
            raise ValueError(f"Invalid MITRE ATT&CK technique ID format: '{technique_id}' (expected T#### or T####.###)")

        return clean_id

    def lookup_technique(
        self,
        technique_id: str,
        include_deprecated: bool = False,
    ) -> Optional[TechniqueInfo]:
        """Retrieve canonical technique metadata for an exact technique or sub-technique ID.
        
        Returns None if ID is unknown or deprecated/revoked (unless include_deprecated=True).
        """
        clean_id = self.validate_technique_id_syntax(technique_id)
        tech = self.techniques.get(clean_id)
        if tech is None:
            return None

        if not include_deprecated and (tech.deprecated or tech.revoked):
            return None

        return tech

    def get_technique_tactics(self, technique_id: str) -> List[TacticInfo]:
        """Retrieve the associated tactic objectives for a technique."""
        tech = self.lookup_technique(technique_id)
        if tech is None:
            return []
        return tech.tactics

    def search_techniques(
        self,
        query: str,
        max_results: int = 10,
        include_deprecated: bool = False,
    ) -> List[TechniqueInfo]:
        """Search techniques across ID, name, and description. Returns matching canonical objects."""
        if not isinstance(query, str) or not query.strip():
            return []

        q = query.strip().lower()
        results: List[TechniqueInfo] = []

        # 1. Exact ID match gets highest priority
        for t_id, tech in self.techniques.items():
            if not include_deprecated and (tech.deprecated or tech.revoked):
                continue
            if t_id.lower() == q:
                results.append(tech)
                break

        # 2. Name matches
        for t_id, tech in self.techniques.items():
            if not include_deprecated and (tech.deprecated or tech.revoked):
                continue
            if tech in results:
                continue
            if q in tech.name.lower():
                results.append(tech)
                if len(results) >= max_results:
                    return results

        # 3. Description matches
        for t_id, tech in self.techniques.items():
            if not include_deprecated and (tech.deprecated or tech.revoked):
                continue
            if tech in results:
                continue
            if q in tech.description.lower():
                results.append(tech)
                if len(results) >= max_results:
                    return results

        return results

    def get_metadata(self) -> CatalogMetadata:
        """Return provenance and catalog release metadata."""
        return self.metadata
