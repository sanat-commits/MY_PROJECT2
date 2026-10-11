"""Authoritative schema definitions for Phase 4 MITRE ATT&CK Context.

Defines typed Pydantic models for:
- MITRE tactics and techniques (preserving canonical relationships and STIX IDs)
- Catalog provenance and version metadata
- Behavior-to-technique mapping statuses, confidence levels, and candidate technique mappings
- Enriched alert contracts incorporating ATT&CK context without mutating Phase 2/3 scores
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from src.risk_scoring.schema import SecurityAlert


class MappingStatus(str, Enum):
    """Operational status of behavior-to-technique mapping evaluation."""

    MAPPED = "MAPPED"
    NOT_MAPPED = "NOT_MAPPED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    SOURCE_UNAVAILABLE = "SOURCE_UNAVAILABLE"


class ConfidenceLevel(str, Enum):
    """Documented evidence-based mapping confidence heuristic."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class TacticInfo(BaseModel):
    """Canonical MITRE ATT&CK tactic objective."""

    tactic_id: str = Field(..., description="Canonical tactic identifier, e.g., TA0006")
    name: str = Field(..., description="Canonical tactic name, e.g., Credential Access")
    shortname: str = Field(..., description="Shortname key used in kill_chain_phases, e.g., credential-access")
    description: str = Field(default="", description="Tactic description")
    url: str = Field(default="", description="Official ATT&CK tactic documentation URL")


class TechniqueInfo(BaseModel):
    """Canonical MITRE ATT&CK technique or sub-technique representation."""

    technique_id: str = Field(..., description="Canonical technique or sub-technique ID (T#### or T####.###)")
    stix_id: str = Field(..., description="Unique STIX 2.1 identifier (attack-pattern--...)")
    name: str = Field(..., description="Canonical technique name")
    description: str = Field(default="", description="Technique description")
    is_subtechnique: bool = Field(default=False, description="True if object represents a sub-technique")
    parent_technique_id: Optional[str] = Field(None, description="Parent technique ID if sub-technique")
    subtechnique_ids: List[str] = Field(default_factory=list, description="List of sub-technique IDs")
    tactics: List[TacticInfo] = Field(default_factory=list, description="Associated tactic objectives")
    platforms: List[str] = Field(default_factory=list, description="Applicable operating systems/platforms")
    detection: Optional[str] = Field(None, description="Detection guidance if documented in source")
    url: str = Field(default="", description="Official ATT&CK technique documentation URL")
    version: Optional[str] = Field(None, description="Technique object revision version")
    deprecated: bool = Field(default=False, description="True if marked deprecated by MITRE")
    revoked: bool = Field(default=False, description="True if revoked and superseded")


class CatalogMetadata(BaseModel):
    """Provenance and cryptographic verification metadata for the imported ATT&CK catalog."""

    domain: str = Field(..., description="ATT&CK domain name (e.g., enterprise-attack)")
    attack_version: str = Field(..., description="Authoritative release version (e.g., v14.1)")
    source_url: str = Field(..., description="Distribution source URL or file reference")
    retrieved_at: str = Field(..., description="ISO 8601 UTC timestamp of retrieval/ingestion")
    sha256: str = Field(..., description="SHA-256 hash of the ingested STIX bundle")
    technique_count: int = Field(..., description="Total active techniques in catalog")
    subtechnique_count: int = Field(..., description="Total active sub-techniques in catalog")
    tactic_count: int = Field(..., description="Total tactics in catalog")


class MappedTechnique(BaseModel):
    """Specific candidate technique mapped to observed alert evidence."""

    technique_id: str = Field(..., description="Canonical MITRE technique ID (e.g. T1110)")
    technique_name: str = Field(..., description="Canonical technique name")
    tactic_ids: List[str] = Field(default_factory=list, description="Associated tactic IDs (e.g. ['TA0006'])")
    tactic_names: List[str] = Field(default_factory=list, description="Associated tactic names")
    mapping_rule_id: str = Field(..., description="Identifier of the rule that produced this candidate")
    mapping_reason: str = Field(..., description="Factual rationale explaining why evidence supports this candidate")
    supporting_evidence: List[Dict[str, Any]] = Field(
        default_factory=list, description="Actual alert evidence items supporting the mapping"
    )
    confidence_level: ConfidenceLevel = Field(
        ..., description="Documented confidence level based on observable evidence breadth"
    )
    source_uri: str = Field(..., description="Official reference URL for the mapped technique")
    attack_version: str = Field(..., description="ATT&CK catalog release version")


class BehaviorMappingResult(BaseModel):
    """Complete result of behavior-to-technique evaluation for an alert."""

    mapping_status: MappingStatus = Field(..., description="Overall mapping outcome status")
    candidate_techniques: List[MappedTechnique] = Field(
        default_factory=list, description="Candidate techniques supported by verified evidence"
    )
    associated_tactics: List[str] = Field(
        default_factory=list, description="Unique tactic names associated with mapped candidates"
    )
    unmapped_reason: Optional[str] = Field(
        None, description="Documented explanation when no techniques could be mapped"
    )
    supporting_evidence_fields: List[str] = Field(
        default_factory=list, description="Telemetry feature names contributing to the mapping"
    )
    attack_version: str = Field(..., description="MITRE ATT&CK version used for mapping")
    catalog_source: str = Field(..., description="Source reference of the verified catalog")


class AlertWithMitreContext(SecurityAlert):
    """Enriched security alert combining Phase 3 explainable alert with Phase 4 ATT&CK context."""

    attack_context: BehaviorMappingResult = Field(
        ..., description="Standardized MITRE ATT&CK context and behavior mapping"
    )
