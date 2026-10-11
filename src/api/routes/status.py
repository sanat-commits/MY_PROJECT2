"""Model and provider status routes."""

from datetime import datetime, timezone
from fastapi import APIRouter, Depends

from src.api.schemas import ModelStatusResponse
from src.api.dependencies import get_llm_provider, get_llm_config
from src.llm.provider import LlmProvider
from src.llm.config import LlmConfig

router = APIRouter(prefix="/status", tags=["Status"])


@router.get("/model", response_model=ModelStatusResponse)
def get_model_status(
    provider: LlmProvider = Depends(get_llm_provider),
    config: LlmConfig = Depends(get_llm_config),
) -> ModelStatusResponse:
    """Report the current status, reachability, and installed model identity of the local LLM runtime."""
    now_iso = datetime.now(timezone.utc).isoformat()
    configured_model = config.ollama_model

    try:
        is_healthy = provider.health_check()
    except Exception as e:
        return ModelStatusResponse(
            provider=config.llm_provider,
            configured_model=configured_model,
            detected_model=None,
            availability="unavailable",
            last_check=now_iso,
            error_code=f"Daemon connection failed: {e}",
        )

    if not is_healthy:
        return ModelStatusResponse(
            provider=config.llm_provider,
            configured_model=configured_model,
            detected_model=None,
            availability="unavailable",
            last_check=now_iso,
            error_code="Provider health check returned False",
        )

    # Discover installed tags without triggering costly generation
    detected_model = None
    try:
        models = provider.discover_models()
        # Find exact or matching candidate for Qwen 3 8B
        candidates = [m for m in models if "qwen" in m.lower() and "8b" in m.lower()]
        if candidates:
            detected_model = candidates[0]
            avail = "available"
            err = None
        elif configured_model in models:
            detected_model = configured_model
            avail = "available"
            err = None
        else:
            avail = "model_not_found"
            err = f"Configured model '{configured_model}' not found in installed models: {models}"
    except Exception as e:
        avail = "unavailable"
        err = f"Model discovery error: {e}"

    return ModelStatusResponse(
        provider=config.llm_provider,
        configured_model=configured_model,
        detected_model=detected_model,
        availability=avail,
        last_check=now_iso,
        error_code=err,
    )
