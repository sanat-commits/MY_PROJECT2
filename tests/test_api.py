"""Comprehensive test suite for Phase 8 Backend API."""

import pytest
from fastapi.testclient import TestClient

from src.api.app import create_app
from src.api.dependencies import (
    get_investigation_workflow,
    get_alert_repository,
    get_investigation_repository,
    get_llm_provider,
    reset_dependencies,
)
from src.agent.workflow import InvestigationWorkflow
from src.agent.config import AgentConfig
from src.agent.schemas import AgentStatus
from src.llm.config import LlmConfig
from src.llm.ollama_provider import MockLlmProvider, OllamaLlmProvider
from src.risk_scoring.config import get_default_risk_config
from src.risk_scoring.engine import RiskEngine
from src.risk_scoring.schema import SecurityAlert, SeverityLevel


@pytest.fixture
def mock_app():
    """Create test application wired to deterministic mock LLM provider."""
    reset_dependencies()
    app = create_app()

    mock_wf = InvestigationWorkflow(
        config=AgentConfig.from_env(),
        llm_config=LlmConfig.from_env(),
        llm_provider=MockLlmProvider(),
    )
    app.dependency_overrides[get_investigation_workflow] = lambda: mock_wf
    app.dependency_overrides[get_llm_provider] = lambda: MockLlmProvider()

    return app


@pytest.fixture
def client(mock_app):
    return TestClient(mock_app)


# -------------------------------------------------------------
# A. Health and Status Tests
# -------------------------------------------------------------

def test_health_endpoint_liveness(client):
    """Verify /health returns lightweight status."""
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}
    assert "X-Correlation-ID" in res.headers


def test_ready_endpoint_dependencies(client):
    """Verify /ready evaluates dependencies without failure."""
    res = client.get("/ready")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] in ["ready", "degraded"]
    assert "dependencies" in data
    deps = data["dependencies"]
    assert "ml_detector" in deps
    assert "risk_engine" in deps
    assert "mitre_catalog" in deps
    assert "rag_knowledge_base" in deps
    assert "local_llm_runtime" in deps


def test_model_status_endpoint(client):
    """Verify /status/model inspects model state without costly generation."""
    res = client.get("/status/model")
    assert res.status_code == 200
    data = res.json()
    assert "provider" in data
    assert "configured_model" in data
    assert "availability" in data
    assert "last_check" in data


# -------------------------------------------------------------
# B. Alert Endpoints & Pagination Tests
# -------------------------------------------------------------

def test_alerts_listing_pagination(client):
    """Verify paginated alert retrieval and boundary enforcement."""
    res = client.get("/alerts?limit=5&offset=0")
    assert res.status_code == 200
    data = res.json()
    assert data["limit"] == 5
    assert data["offset"] == 0
    assert data["total"] >= len(data["items"])
    assert len(data["items"]) <= 5


def test_alerts_invalid_pagination_bounds(client):
    """Verify rejection of negative offset and oversized page limits."""
    # Negative offset
    res_neg = client.get("/alerts?limit=10&offset=-1")
    assert res_neg.status_code == 422
    assert res_neg.json()["error"]["code"] == "VALIDATION_ERROR"

    # Limit = 0
    res_zero = client.get("/alerts?limit=0")
    assert res_zero.status_code == 422

    # Limit exceeding max bound (e.g. 501)
    res_over = client.get("/alerts?limit=501")
    assert res_over.status_code == 422


def test_alerts_severity_filtering(client):
    """Verify filtering alerts by severity level."""
    res = client.get("/alerts?severity=HIGH")
    assert res.status_code == 200
    data = res.json()
    for item in data["items"]:
        assert item["severity"] == "HIGH"


def test_get_single_alert_success(client):
    """Verify retrieving full structured alert details."""
    res_list = client.get("/alerts?limit=1")
    items = res_list.json()["items"]
    assert len(items) > 0
    alert_id = items[0]["alert_id"]

    res_single = client.get(f"/alerts/{alert_id}")
    assert res_single.status_code == 200
    alert = res_single.json()
    assert alert["alert_id"] == alert_id
    assert "risk_score" in alert
    assert "severity" in alert
    assert "evidence" in alert
    assert "score_breakdown" in alert


def test_get_single_alert_not_found(client):
    """Verify 404 response on unknown alert ID."""
    res = client.get("/alerts/alt_nonexistent_999999")
    assert res.status_code == 404
    data = res.json()
    assert data["error"]["code"] == "NOT_FOUND"
    assert "not found" in data["error"]["message"].lower()


# -------------------------------------------------------------
# C. Investigation Endpoints Tests
# -------------------------------------------------------------

def test_investigate_alert_workflow(client):
    """Verify triggering LangGraph investigation produces structured report."""
    res_list = client.get("/alerts?limit=1")
    alert_id = res_list.json()["items"][0]["alert_id"]

    req_payload = {"correlation_id": "corr_test_alpha_01"}
    res_inv = client.post(f"/alerts/{alert_id}/investigate", json=req_payload)
    assert res_inv.status_code == 200
    inv = res_inv.json()

    assert inv["alert_id"] == alert_id
    assert inv["status"] in ["SUCCESS", "INSUFFICIENT_EVIDENCE", "LIMIT_REACHED"]
    assert "investigation_id" in inv
    assert "execution_trace_summary" in inv
    assert len(inv["execution_trace_summary"]) > 0

    # Verify report schema
    if inv["final_report"]:
        assert "finding" in inv["final_report"]
        assert "summary" in inv["final_report"]

    # Verify historical retrieval endpoint
    inv_id = inv["investigation_id"]
    res_hist = client.get(f"/investigations/{inv_id}")
    assert res_hist.status_code == 200
    assert res_hist.json()["investigation_id"] == inv_id


def test_investigate_nonexistent_alert_returns_404(client):
    """Verify 404 when attempting to investigate an unknown alert."""
    res = client.post("/alerts/alt_unknown_xyz/investigate", json={})
    assert res.status_code == 404
    assert res.json()["error"]["code"] == "NOT_FOUND"


def test_get_investigation_not_found(client):
    """Verify 404 on missing historical investigation ID."""
    res = client.get("/investigations/inv_missing_999")
    assert res.status_code == 404
    assert res.json()["error"]["code"] == "NOT_FOUND"


# -------------------------------------------------------------
# D. Tracing, Security, and Error Privacy Tests
# -------------------------------------------------------------

def test_correlation_id_propagation(client):
    """Verify custom correlation ID is propagated in headers and logs."""
    custom_corr = "corr_custom_trace_9876"
    res = client.get("/health", headers={"X-Correlation-ID": custom_corr})
    assert res.status_code == 200
    assert res.headers.get("X-Correlation-ID") == custom_corr


def test_cors_options_preflight(client):
    """Verify CORS preflight OPTIONS request returns permitted headers."""
    res = client.options(
        "/alerts",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert res.status_code == 200
    assert "access-control-allow-origin" in res.headers


# -------------------------------------------------------------
# E. Real Local Qwen Integration Test
# -------------------------------------------------------------

def test_real_local_qwen_api_investigation():
    """Verify end-to-end investigation through API with real local Qwen 3 8B model."""
    from src.api.app import create_app
    from src.llm.config import LlmConfig
    from src.llm.ollama_provider import OllamaLlmProvider

    llm_cfg = LlmConfig.from_env()
    provider = OllamaLlmProvider(llm_cfg)
    if not provider.health_check():
        pytest.skip("Local Ollama daemon unavailable for real model test")

    app = create_app()
    real_client = TestClient(app)

    res_list = real_client.get("/alerts?limit=1")
    assert res_list.status_code == 200
    alert_id = res_list.json()["items"][0]["alert_id"]

    res_inv = real_client.post(f"/alerts/{alert_id}/investigate")
    assert res_inv.status_code == 200
    data = res_inv.json()
    assert data["status"] == "SUCCESS"
    assert data["final_report"] is not None
    assert data["final_report"]["alert_id"] == alert_id
    assert "finding" in data["final_report"]
