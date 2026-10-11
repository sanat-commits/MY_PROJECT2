"""Health and readiness probe endpoints."""

from pathlib import Path
from fastapi import APIRouter, Depends

from src.api.schemas import HealthResponse, ReadinessResponse, DependencyStatus
from src.api.dependencies import get_api_config, get_llm_provider, get_llm_config
from src.api.config import ApiConfig
from src.llm.provider import LlmProvider
from src.llm.config import LlmConfig

router = APIRouter(tags=["System"])


@router.get("/health", response_model=HealthResponse)
def get_health() -> HealthResponse:
    """Lightweight process liveness check."""
    return HealthResponse(status="ok")


@router.get("/ready", response_model=ReadinessResponse)
def get_readiness(
    config: ApiConfig = Depends(get_api_config),
    llm_provider: LlmProvider = Depends(get_llm_provider),
    llm_config: LlmConfig = Depends(get_llm_config),
) -> ReadinessResponse:
    """Readiness probe evaluating the state of critical upstream dependencies."""
    dependencies = {}
    base_dir = config.base_dir

    # 1. Phase 2 ML Artifacts
    ml_model = base_dir / "artifacts" / "ml" / "isolation_forest.joblib"
    ml_thresh = base_dir / "artifacts" / "ml" / "threshold.json"
    ml_ok = ml_model.exists() and ml_thresh.exists()
    dependencies["ml_detector"] = DependencyStatus(
        status="ready" if ml_ok else "not_ready",
        message="Isolation forest model and calibrated threshold loaded" if ml_ok else "ML model artifacts missing",
    )

    # 2. Phase 3 Risk Scoring Configuration
    risk_cfg_file = base_dir / "artifacts" / "risk_scoring" / "risk_scoring_config.json"
    risk_ok = risk_cfg_file.exists()
    dependencies["risk_engine"] = DependencyStatus(
        status="ready" if risk_ok else "not_ready",
        message="Risk scoring configuration verified" if risk_ok else "Risk scoring config missing",
    )

    # 3. Phase 4 MITRE ATT&CK Catalog
    mitre_fix = base_dir / "data" / "mitre" / "enterprise_attack_fixture.json"
    mitre_cache = base_dir / "artifacts" / "mitre" / "catalog.json"
    mitre_ok = mitre_fix.exists() or mitre_cache.exists()
    dependencies["mitre_catalog"] = DependencyStatus(
        status="ready" if mitre_ok else "not_ready",
        message="Enterprise ATT&CK catalog cached" if mitre_ok else "ATT&CK catalog bundle missing",
    )

    # 4. Phase 5 RAG Subsystem
    rag_manifest = base_dir / "artifacts" / "vector_store" / "index_manifest.json"
    rag_ok = rag_manifest.exists()
    dependencies["rag_knowledge_base"] = DependencyStatus(
        status="ready" if rag_ok else "not_ready",
        message="Hybrid vector store and BM25 index verified" if rag_ok else "RAG store index missing",
    )

    # 5. Phase 6 Local LLM Runtime (Ollama)
    llm_health = False
    try:
        llm_health = llm_provider.health_check()
    except Exception:
        llm_health = False

    dependencies["local_llm_runtime"] = DependencyStatus(
        status="ready" if llm_health else "unavailable",
        message="Ollama local daemon responsive" if llm_health else "Ollama endpoint unreachable",
        details={"provider": llm_config.llm_provider, "base_url": llm_config.ollama_base_url},
    )

    overall_ready = all(dep.status == "ready" for dep in dependencies.values())
    status_label = "ready" if overall_ready else "degraded"

    return ReadinessResponse(
        status=status_label,
        dependencies=dependencies,
    )
