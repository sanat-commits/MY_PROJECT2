"""Unit and integration tests for Phase 6 local Qwen 3 8B investigation subsystem."""

import json
from pathlib import Path
import pytest

from src.llm.config import LlmConfig
from src.llm.investigation import InvestigationEngine
from src.llm.ollama_provider import MockLlmProvider, OllamaLlmProvider
from src.llm.output_validation import OutputValidationError, ReportValidator
from src.llm.prompts import SYSTEM_PROMPT_V1, build_investigation_user_prompt
from src.llm.provider import (
    ModelNotFoundError,
    ProviderResponse,
    ProviderUnavailableError,
    RequestTimeoutError,
)
from src.llm.schemas import (
    FindingType,
    InvestigationInput,
    InvestigationReport,
    InvestigationResult,
    InvestigationStatus,
    ObservedEvidenceRef,
    ReportCitation,
)
from src.risk_scoring.schema import (
    EvidenceItem,
    ScoreBreakdown,
    ScoreComponentBreakdown,
    SecurityAlert,
    SeverityLevel,
)


@pytest.fixture
def sample_alert() -> SecurityAlert:
    """Fixture producing a verified Phase 3 SecurityAlert."""
    from src.risk_scoring.config import get_default_risk_config
    from src.risk_scoring.engine import RiskEngine

    risk_engine = RiskEngine(get_default_risk_config())
    pred = {"window_id": "win_test_101", "raw_score": -0.15, "anomaly_score": 0.15, "is_anomaly": 1}
    win = {
        "window_id": "win_test_101",
        "hour": 2,
        "day_of_week": 3,
        "is_weekend": 0,
        "failed_logins": 35,
        "successful_logins": 1,
        "login_attempts": 36,
        "privileged_actions": 0,
        "rare_process_count": 0,
        "external_connections": 5,
        "bytes_out_mb": 10.0,
        "after_hours": 1,
    }
    return risk_engine.score_alert(pred, win)



@pytest.fixture
def sample_rag_chunk():
    return {
        "chunk_id": "chk_mitre_attack_ent_00_099f5e7106bc",
        "source_id": "src_mitre_attack_enterprise",
        "source_title": "MITRE ATT&CK Enterprise Catalog",
        "source_uri_or_path": "https://attack.mitre.org/techniques/T1110",
        "document_title": "Brute Force (T1110)",
        "content": "Adversaries may use brute force attacks to obtain credentials.",
    }


def test_provider_discovery_and_health(sample_alert):
    """Verify provider discovers installed local models and checks health."""
    cfg = LlmConfig.from_env()
    provider = OllamaLlmProvider(cfg)
    assert provider.health_check() is True
    models = provider.discover_models()
    assert any("qwen3:8b" in m or "qwen3" in m for m in models)
    assert provider.model_name == cfg.ollama_model


def test_provider_rejects_missing_model():
    """Verify ModelNotFoundError raised when configured model is absent."""
    cfg = LlmConfig(ollama_model="nonexistent-model-xyz")
    with pytest.raises(ModelNotFoundError):
        OllamaLlmProvider(cfg)


def test_provider_rejects_unreachable_endpoint():
    """Verify ProviderUnavailableError raised when daemon URL is unreachable."""
    cfg = LlmConfig(ollama_base_url="http://localhost:59999")
    with pytest.raises(ProviderUnavailableError):
        OllamaLlmProvider(cfg)


def test_mock_provider_deterministic():
    """Verify MockLlmProvider produces valid JSON reports without network."""
    provider = MockLlmProvider()
    assert provider.health_check() is True
    resp = provider.generate("test prompt")
    assert resp.content
    data = json.loads(resp.content)
    assert data["alert_id"] == "alt_mock_001"
    assert data["supplied_severity"] == "MEDIUM"


def test_investigation_input_assembly(sample_alert, sample_rag_chunk):
    """Verify InvestigationInput preserves all alert and retrieval fields."""
    engine = InvestigationEngine(provider=MockLlmProvider())
    mock_rag_result = type("MockRag", (), {"status": "success", "results": [sample_rag_chunk]})()
    inv_input = engine.create_investigation_input(sample_alert, mock_rag_result)

    assert inv_input.alert_id == sample_alert.alert_id
    assert inv_input.risk_score == sample_alert.risk_score
    assert inv_input.severity == sample_alert.severity
    assert len(inv_input.evidence_items) == len(sample_alert.evidence)
    assert len(inv_input.rag_chunks) == 1
    assert inv_input.rag_chunks[0]["chunk_id"] == sample_rag_chunk["chunk_id"]



def test_prompt_construction_preserves_rules(sample_alert, sample_rag_chunk):
    """Verify user prompt presents alert fields, scores, and RAG context cleanly."""
    engine = InvestigationEngine(provider=MockLlmProvider())
    mock_rag_result = type("MockRag", (), {"status": "success", "results": [sample_rag_chunk]})()
    inv_input = engine.create_investigation_input(sample_alert, mock_rag_result)
    prompt = build_investigation_user_prompt(inv_input)

    assert sample_alert.alert_id in prompt
    assert str(sample_alert.risk_score) in prompt
    assert sample_alert.severity.value in prompt
    assert sample_rag_chunk["chunk_id"] in prompt
    assert "EVIDENCE" in prompt
    assert "RETRIEVED CYBERSECURITY KNOWLEDGE" in prompt


def test_output_validation_accepts_valid_report(sample_alert, sample_rag_chunk):
    """Verify ReportValidator parses valid JSON and attaches verified citations."""
    validator = ReportValidator()
    engine = InvestigationEngine(provider=MockLlmProvider())
    mock_rag_result = type("MockRag", (), {"status": "success", "results": [sample_rag_chunk]})()
    inv_input = engine.create_investigation_input(sample_alert, mock_rag_result)

    raw_json = json.dumps({
        "investigation_id": inv_input.investigation_id,
        "alert_id": sample_alert.alert_id,
        "summary": "Detected brute force attack on host.",
        "supplied_severity": sample_alert.severity.value,
        "supplied_risk_score": sample_alert.risk_score,
        "finding": "SUSPICIOUS_ACTIVITY",
        "observed_evidence": [{"field_name": "failed_logins", "observed_value": 35, "description": "High failed logins"}],
        "interpretation": "Observed failed logins indicate password guessing.",
        "possible_attack_techniques": [],
        "uncertainty": "User account names not recorded in telemetry window.",
        "recommended_next_steps": ["Check event ID 4625"],
        "citations": [{"chunk_id": sample_rag_chunk["chunk_id"]}],
        "limitations": ["Window is 1 hour aggregation"]
    })

    report = validator.validate(raw_json, inv_input)
    assert report.alert_id == sample_alert.alert_id
    assert report.supplied_severity == sample_alert.severity
    assert report.supplied_risk_score == sample_alert.risk_score
    assert len(report.citations) == 1
    assert report.citations[0].chunk_id == sample_rag_chunk["chunk_id"]
    assert report.citations[0].source_title == sample_rag_chunk["source_title"]



def test_output_validation_strictly_preserves_application_state(sample_alert):
    """Verify validator overrides model attempts to mutate severity or risk score."""
    validator = ReportValidator()
    engine = InvestigationEngine(provider=MockLlmProvider())
    inv_input = engine.create_investigation_input(sample_alert)

    # Malicious or confused LLM attempts to rewrite severity to CRITICAL and score to 99.0
    bad_output = json.dumps({
        "investigation_id": inv_input.investigation_id,
        "alert_id": sample_alert.alert_id,
        "summary": "Tampered summary",
        "supplied_severity": "CRITICAL",
        "supplied_risk_score": 99.0,
        "finding": "POSSIBLE_ATTACK",
        "interpretation": "Tampered",
        "uncertainty": "None",
        "recommended_next_steps": ["Do nothing"],
        "citations": [],
        "limitations": []
    })

    report = validator.validate(bad_output, inv_input)
    assert report.supplied_severity == sample_alert.severity  # MEDIUM, not CRITICAL
    assert report.supplied_risk_score == sample_alert.risk_score  # 58.5, not 99.0


def test_output_validation_rejects_hallucinated_citations(sample_alert, sample_rag_chunk):
    """Verify validator strips citations referencing chunk IDs not in RAG context."""
    validator = ReportValidator()
    engine = InvestigationEngine(provider=MockLlmProvider())
    mock_rag_result = type("MockRag", (), {"status": "success", "results": [sample_rag_chunk]})()
    inv_input = engine.create_investigation_input(sample_alert, mock_rag_result)

    output_with_fake_citation = json.dumps({
        "investigation_id": inv_input.investigation_id,
        "alert_id": sample_alert.alert_id,
        "summary": "Summary",
        "supplied_severity": sample_alert.severity.value,
        "supplied_risk_score": sample_alert.risk_score,
        "finding": "SUSPICIOUS_ACTIVITY",

        "interpretation": "Interpretation",
        "uncertainty": "Uncertainty",
        "recommended_next_steps": ["Step 1"],
        "citations": [
            {"chunk_id": "chk_invented_chunk_not_in_rag_12345"},
            {"chunk_id": sample_rag_chunk["chunk_id"]},
        ],
        "limitations": []
    })

    report = validator.validate(output_with_fake_citation, inv_input)
    assert len(report.citations) == 1
    assert report.citations[0].chunk_id == sample_rag_chunk["chunk_id"]


def test_output_validation_rejects_invalid_json(sample_alert):
    """Verify OutputValidationError raised when model output is unparseable."""
    validator = ReportValidator()
    engine = InvestigationEngine(provider=MockLlmProvider())
    inv_input = engine.create_investigation_input(sample_alert)

    with pytest.raises(OutputValidationError):
        validator.validate("Not valid json {unclosed", inv_input)


def test_investigation_engine_with_mock_provider(sample_alert, sample_rag_chunk):
    """Verify InvestigationEngine end-to-end execution with MockLlmProvider."""
    engine = InvestigationEngine(provider=MockLlmProvider())
    mock_rag_result = type("MockRag", (), {"status": "success", "results": [sample_rag_chunk]})()
    res = engine.investigate(sample_alert, mock_rag_result)

    assert res.status == InvestigationStatus.SUCCESS
    assert res.report is not None
    assert res.report.alert_id == sample_alert.alert_id
    assert res.report.supplied_severity == sample_alert.severity
    assert res.report.supplied_risk_score == sample_alert.risk_score


def test_real_local_qwen_smoke_test(sample_alert, sample_rag_chunk):
    """Smoke test invoking the actual local Qwen 3 8B model via Ollama."""
    cfg = LlmConfig.from_env()
    provider = OllamaLlmProvider(cfg)
    engine = InvestigationEngine(config=cfg, provider=provider)

    mock_rag_result = type("MockRag", (), {"status": "success", "results": [sample_rag_chunk]})()
    res = engine.investigate(sample_alert, mock_rag_result)

    assert res.status == InvestigationStatus.SUCCESS, f"Expected SUCCESS, got {res.status}: {res.error_message}"
    assert res.report is not None
    assert res.report.alert_id == sample_alert.alert_id
    assert res.report.supplied_severity == sample_alert.severity
    assert res.report.supplied_risk_score == sample_alert.risk_score
    assert res.report.summary
    assert res.report.interpretation
    assert len(res.report.recommended_next_steps) > 0
    # Citations must only contain valid RAG chunks
    for cit in res.report.citations:
        assert cit.chunk_id == sample_rag_chunk["chunk_id"]
