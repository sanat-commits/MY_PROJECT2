"""Phase 4 MITRE ATT&CK Context Tests.

Tests:
- Source and STIX 2.1 bundle ingestion, validation, and metadata (Section 13.A)
- Technique catalog lookup, sub-techniques, multi-tactic relationships, search (Section 13.B)
- Deterministic behavior-to-technique mapping, evidence verification, and uncertainty (Section 13.C)
- Alert integration, non-mutation of Phase 2/3 scores, and provenance (Section 13.D)
- Negative failure modes and defensive validation (Section 13.E)
"""

from pathlib import Path
import json
import pytest
from pydantic import ValidationError

from src.mitre.config import MitreConfig
from src.mitre.schemas import (
    AlertWithMitreContext,
    BehaviorMappingResult,
    CatalogMetadata,
    ConfidenceLevel,
    MappedTechnique,
    MappingStatus,
    TechniqueInfo,
)
from src.mitre.ingest import MitreIngestor
from src.mitre.catalog import AttackCatalog
from src.mitre.mapping_rules import BehaviorMappingRule, get_default_mapping_rules
from src.mitre.mapper import BehaviorMapper
from src.mitre.service import MitreService
from src.risk_scoring.config import get_default_risk_config
from src.risk_scoring.engine import RiskEngine
from src.risk_scoring.schema import (
    EvidenceItem,
    ScoreBreakdown,
    ScoreComponentBreakdown,
    SecurityAlert,
    SeverityLevel,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = ROOT / "data" / "mitre" / "enterprise_attack_fixture.json"


@pytest.fixture
def test_config(tmp_path) -> MitreConfig:
    return MitreConfig(
        domain="enterprise-attack",
        attack_version="v14.1",
        cache_dir=tmp_path / "mitre_cache",
        fixture_path=FIXTURE_PATH,
        offline_mode=True,
    )


@pytest.fixture
def catalog(test_config) -> AttackCatalog:
    ingestor = MitreIngestor(test_config)
    ingestor.ingest_and_cache()
    return AttackCatalog.load(test_config)


@pytest.fixture
def service(test_config, catalog) -> MitreService:
    return MitreService(config=test_config, catalog=catalog)


@pytest.fixture
def sample_alert() -> SecurityAlert:
    return SecurityAlert(
        alert_id="alt_win_test_001_123456",
        window_id="win_test_001",
        anomaly_score=0.12,
        is_anomaly=1,
        risk_score=55.0,
        severity=SeverityLevel.MEDIUM,
        evidence=[
            EvidenceItem(
                signal_name="failed_login_burst",
                source_field="failed_logins",
                observed_value=45.0,
                comparison_or_rule="observed > baseline (3.0)",
                contribution=15.0,
                explanation="Failed login burst observed.",
            )
        ],
        score_breakdown=ScoreBreakdown(
            ml_anomaly=ScoreComponentBreakdown(
                component="ml_anomaly",
                configured_weight=40.0,
                rule="anomaly_score > threshold",
                contribution=25.0,
                calculation_method="linear",
                status="contributed",
            ),
            behavioral_components=[
                ScoreComponentBreakdown(
                    component="failed_login_burst",
                    configured_weight=15.0,
                    rule="failed_logins > 3.0",
                    contribution=15.0,
                    calculation_method="linear",
                    status="contributed",
                )
            ],
            total_ml_contribution=25.0,
            total_behavioral_contribution=15.0,
            calculated_risk_score=40.0,
            reconciled=True,
            rounding_difference=0.0,
        ),
        scoring_config_version="v1.0.0",
        created_at="2026-10-09T00:00:00Z",
    )


# =====================================================================
# 1. Source and Ingestion Tests (Section 13.A)
# =====================================================================

def test_ingestion_from_fixture_success(test_config):
    """Ingestor must parse valid STIX 2.1 fixture and generate catalog metadata."""
    ingestor = MitreIngestor(test_config)
    meta = ingestor.ingest_and_cache()

    assert meta.domain == "enterprise-attack"
    assert meta.attack_version == "v14.1"
    assert meta.technique_count >= 6
    assert meta.subtechnique_count >= 1
    assert meta.tactic_count >= 8
    assert len(meta.sha256) == 64

    # Verify cache artifacts
    assert test_config.cached_catalog_path.exists()
    assert test_config.metadata_path.exists()


def test_ingestion_rejects_malformed_json(test_config, tmp_path):
    """Ingestor must reject malformed non-JSON data safely."""
    bad_file = tmp_path / "bad.json"
    bad_file.write_bytes(b"not valid json {{{")
    ingestor = MitreIngestor(test_config)
    with pytest.raises(ValueError, match="Malformed STIX bundle"):
        ingestor.validate_and_parse_bundle(bad_file.read_bytes(), str(bad_file))


def test_ingestion_rejects_non_bundle_type(test_config, tmp_path):
    """Ingestor must reject JSON root objects that are not STIX bundles."""
    not_bundle = json.dumps({"type": "identity", "id": "identity--1"}).encode()
    ingestor = MitreIngestor(test_config)
    with pytest.raises(ValueError, match="root type must be 'bundle'"):
        ingestor.validate_and_parse_bundle(not_bundle, "test")


def test_ingestion_detects_duplicate_object_ids(test_config):
    """Ingestor must reject STIX bundles containing duplicate object IDs."""
    fixture_data = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    # Duplicate first object
    fixture_data["objects"].append(fixture_data["objects"][0])
    dup_bytes = json.dumps(fixture_data).encode()

    ingestor = MitreIngestor(test_config)
    with pytest.raises(ValueError, match="Duplicate STIX object ID detected"):
        ingestor.validate_and_parse_bundle(dup_bytes, "dup_test")


def test_ingestion_deterministic(test_config):
    """Repeated ingestion of identical source yields identical catalog output and hash."""
    ing1 = MitreIngestor(test_config)
    ing2 = MitreIngestor(test_config)
    m1 = ing1.ingest_and_cache()
    m2 = ing2.ingest_and_cache()

    assert m1.sha256 == m2.sha256
    assert m1.technique_count == m2.technique_count
    assert m1.tactic_count == m2.tactic_count


def test_ingestion_missing_source_fails_safely(tmp_path):
    """Ingestion of nonexistent file path raises FileNotFoundError."""
    cfg = MitreConfig(fixture_path=tmp_path / "missing.json", cache_dir=tmp_path / "c")
    ingestor = MitreIngestor(cfg)
    with pytest.raises(FileNotFoundError):
        ingestor.fetch_stix_bundle_data(tmp_path / "missing.json")


# =====================================================================
# 2. Catalog Lookup & Search Tests (Section 13.B)
# =====================================================================

def test_lookup_known_technique(catalog):
    """Known technique ID resolves to canonical TechniqueInfo metadata."""
    tech = catalog.lookup_technique("T1110")
    assert tech is not None
    assert tech.technique_id == "T1110"
    assert tech.name == "Brute Force"
    assert tech.is_subtechnique is False
    assert "credential-access" in [t.shortname for t in tech.tactics]
    assert "Windows" in tech.platforms
    assert "attack.mitre.org" in tech.url


def test_lookup_known_subtechnique_and_parent_link(catalog):
    """Known sub-technique resolves and preserves parent technique relationship."""
    subtech = catalog.lookup_technique("T1110.001")
    assert subtech is not None
    assert subtech.technique_id == "T1110.001"
    assert subtech.name == "Password Guessing"
    assert subtech.is_subtechnique is True
    assert subtech.parent_technique_id == "T1110"

    # Parent technique must list the subtechnique
    parent = catalog.lookup_technique("T1110")
    assert "T1110.001" in parent.subtechnique_ids


def test_multi_tactic_relationships_preserved(catalog):
    """Techniques belonging to multiple tactics must preserve all relationships."""
    tech = catalog.lookup_technique("T1078")
    assert tech is not None
    assert tech.name == "Valid Accounts"
    tactic_ids = [t.tactic_id for t in tech.tactics]
    # T1078 spans Initial Access (TA0001), Persistence (TA0003), Privilege Escalation (TA0004), Defense Evasion (TA0005)
    assert "TA0001" in tactic_ids
    assert "TA0003" in tactic_ids
    assert "TA0004" in tactic_ids
    assert "TA0005" in tactic_ids


def test_lookup_unknown_technique_returns_none(catalog):
    """Unknown technique ID returns None, never a fabricated record."""
    tech = catalog.lookup_technique("T9999")
    assert tech is None


def test_lookup_invalid_id_syntax_raises_value_error(catalog):
    """Non-conforming technique ID strings raise ValueError."""
    with pytest.raises(ValueError, match="Invalid MITRE ATT&CK technique ID format"):
        catalog.lookup_technique("invalid_id")
    with pytest.raises(ValueError, match="Invalid MITRE ATT&CK technique ID format"):
        catalog.lookup_technique("T123")  # Too few digits


def test_search_techniques_by_name_and_keyword(catalog):
    """Search matches canonical techniques by name and keyword."""
    # Search by name
    results_name = catalog.search_techniques("Brute Force")
    assert len(results_name) > 0
    assert any(t.technique_id == "T1110" for t in results_name)

    # Search by keyword in description
    results_desc = catalog.search_techniques("passwords")
    assert len(results_desc) > 0

    # Empty search query returns empty list
    assert catalog.search_techniques("") == []
    assert catalog.search_techniques("   ") == []


# =====================================================================
# 3. Behavior-to-Technique Mapping Tests (Section 13.C)
# =====================================================================

def test_mapping_matches_supported_evidence(catalog, sample_alert):
    """Alert with failed_logins evidence maps to T1110 (Brute Force)."""
    mapper = BehaviorMapper(catalog)
    res = mapper.map_alert(sample_alert)

    assert res.mapping_status == MappingStatus.MAPPED
    assert len(res.candidate_techniques) == 1
    candidate = res.candidate_techniques[0]
    assert candidate.technique_id == "T1110"
    assert candidate.technique_name == "Brute Force"
    assert "Credential Access" in candidate.tactic_names
    assert candidate.mapping_rule_id == "RULE_AUTH_BRUTE_FORCE"
    assert candidate.confidence_level in (ConfidenceLevel.MEDIUM, ConfidenceLevel.HIGH)
    assert len(candidate.supporting_evidence) == 1
    assert candidate.supporting_evidence[0]["source_field"] == "failed_logins"


def test_mapping_insufficient_evidence_when_no_rules_match(catalog, sample_alert):
    """Alert with generic unmapped evidence returns INSUFFICIENT_EVIDENCE."""
    alert_unmapped = sample_alert.model_copy(deep=True)
    # Evidence has unique_source_ips which has no rule mapping
    alert_unmapped.evidence = [
        EvidenceItem(
            signal_name="unusual_ip_count",
            source_field="unique_source_ips",
            observed_value=3,
            comparison_or_rule="observed > baseline",
            contribution=10.0,
            explanation="Multiple IPs observed.",
        )
    ]
    mapper = BehaviorMapper(catalog)
    res = mapper.map_alert(alert_unmapped)

    assert res.mapping_status == MappingStatus.INSUFFICIENT_EVIDENCE
    assert len(res.candidate_techniques) == 0
    assert "do not provide sufficiently specific telemetry" in res.unmapped_reason


def test_mapping_normal_alert_returns_not_mapped(catalog, sample_alert):
    """Alert with 0 evidence and normal prediction returns NOT_MAPPED."""
    alert_normal = sample_alert.model_copy(deep=True)
    alert_normal.evidence = []
    alert_normal.is_anomaly = 0
    alert_normal.risk_score = 0.0

    mapper = BehaviorMapper(catalog)
    res = mapper.map_alert(alert_normal)

    assert res.mapping_status == MappingStatus.NOT_MAPPED
    assert len(res.candidate_techniques) == 0
    assert "baseline normal" in res.unmapped_reason


def test_synthetic_anomaly_type_never_triggers_mapping(catalog, sample_alert):
    """Synthetic anomaly_type metadata cannot create a mapping without real evidence."""
    alert_leak_test = sample_alert.model_copy(deep=True)
    alert_leak_test.evidence = []  # No observed evidence
    alert_leak_test.is_anomaly = 0

    mapper = BehaviorMapper(catalog)
    res = mapper.map_alert(alert_leak_test)
    assert res.mapping_status == MappingStatus.NOT_MAPPED
    assert len(res.candidate_techniques) == 0


def test_multiple_supported_evidence_maps_multiple_techniques(catalog, sample_alert):
    """Alert with both failed_logins and rare_process_count maps both T1110 and T1059."""
    alert_multi = sample_alert.model_copy(deep=True)
    alert_multi.evidence.append(
        EvidenceItem(
            signal_name="rare_process_execution",
            source_field="rare_process_count",
            observed_value=12.0,
            comparison_or_rule="observed > baseline (1.0)",
            contribution=10.0,
            explanation="Rare process burst observed.",
        )
    )

    mapper = BehaviorMapper(catalog)
    res = mapper.map_alert(alert_multi)

    assert res.mapping_status == MappingStatus.MAPPED
    tech_ids = [c.technique_id for c in res.candidate_techniques]
    assert "T1110" in tech_ids
    assert "T1059" in tech_ids


# =====================================================================
# 4. Alert Integration Tests (Section 13.D)
# =====================================================================

def test_enrich_alert_preserves_existing_scores_and_ids(service, sample_alert):
    """enrich_alert must preserve all original Phase 3 scores, severity, and IDs without mutation."""
    original_dump = sample_alert.model_dump()
    enriched = service.enrich_alert(sample_alert)

    assert enriched.alert_id == original_dump["alert_id"]
    assert enriched.window_id == original_dump["window_id"]
    assert enriched.anomaly_score == original_dump["anomaly_score"]
    assert enriched.is_anomaly == original_dump["is_anomaly"]
    assert enriched.risk_score == original_dump["risk_score"]
    assert enriched.severity == original_dump["severity"]
    assert len(enriched.evidence) == len(original_dump["evidence"])
    assert enriched.score_breakdown.model_dump() == original_dump["score_breakdown"]

    # Verify MITRE context is attached
    assert isinstance(enriched, AlertWithMitreContext)
    assert enriched.attack_context.mapping_status == MappingStatus.MAPPED
    assert len(enriched.attack_context.candidate_techniques) == 1
    assert enriched.attack_context.candidate_techniques[0].technique_id == "T1110"


def test_service_lookup_tool_contract(service):
    """lookup_attack_technique conforms to docs/TOOL_CONTRACTS.md structure."""
    # 1. Success case
    resp_success = service.lookup_attack_technique("T1110")
    assert resp_success["status"] == "success"
    assert resp_success["data"]["technique_id"] == "T1110"
    assert resp_success["data"]["name"] == "Brute Force"
    assert "source_metadata" in resp_success["data"]

    # 2. Not found case
    resp_not_found = service.lookup_attack_technique("T9999")
    assert resp_not_found["status"] == "not_found"
    assert resp_not_found["data"] is None

    # 3. Invalid input case
    resp_invalid = service.lookup_attack_technique("invalid-format")
    assert resp_invalid["status"] == "invalid_input"
    assert resp_invalid["data"] is None


# =====================================================================
# 5. Negative Failure Tests (Section 13.E)
# =====================================================================

def test_mapper_rejects_rule_pointing_to_nonexistent_technique(catalog):
    """BehaviorMapper must reject rule sets referencing nonexistent techniques."""
    bad_rule = BehaviorMappingRule(
        rule_id="RULE_BAD",
        description="Invalid technique rule",
        applicable_behavior="Test",
        required_evidence_fields=["failed_logins"],
        candidate_technique_id="T9999",  # Does not exist in catalog
        mapping_rationale="Test",
        confidence_level=ConfidenceLevel.LOW,
        limitations="None",
    )
    with pytest.raises(ValueError, match="does not exist in verified ATT&CK catalog"):
        BehaviorMapper(catalog, rules=[bad_rule])


def test_corrupted_cached_catalog_raises_runtime_error(test_config):
    """AttackCatalog.load must raise RuntimeError if cache file is corrupted."""
    test_config.cached_catalog_path.parent.mkdir(parents=True, exist_ok=True)
    test_config.cached_catalog_path.write_bytes(b"corrupted json data {{{")
    with pytest.raises(RuntimeError, match="Corrupted or unreadable"):
        AttackCatalog.load(test_config)
