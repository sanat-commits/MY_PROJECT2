"""FastAPI dependency providers for application services and repositories."""

import asyncio
from typing import Optional
from fastapi import Request

from src.api.config import ApiConfig
from src.api.repository import AlertRepository, InvestigationRepository
from src.agent.workflow import InvestigationWorkflow
from src.agent.config import AgentConfig
from src.llm.config import LlmConfig
from src.llm.provider import LlmProvider
from src.llm.ollama_provider import OllamaLlmProvider

_config: Optional[ApiConfig] = None
_alert_repo: Optional[AlertRepository] = None
_investigation_repo: Optional[InvestigationRepository] = None
_investigation_workflow: Optional[InvestigationWorkflow] = None
_investigation_semaphore: Optional[asyncio.Semaphore] = None
_llm_provider: Optional[LlmProvider] = None


def get_api_config() -> ApiConfig:
    global _config
    if _config is None:
        _config = ApiConfig.from_env()
    return _config


def get_alert_repository() -> AlertRepository:
    global _alert_repo
    if _alert_repo is None:
        cfg = get_api_config()
        _alert_repo = AlertRepository(storage_dir=cfg.storage_dir, base_dir=cfg.base_dir)
    return _alert_repo


def get_investigation_repository() -> InvestigationRepository:
    global _investigation_repo
    if _investigation_repo is None:
        cfg = get_api_config()
        _investigation_repo = InvestigationRepository(storage_dir=cfg.storage_dir, base_dir=cfg.base_dir)
    return _investigation_repo


def get_llm_config() -> LlmConfig:
    return LlmConfig.from_env()


def get_llm_provider() -> LlmProvider:
    global _llm_provider
    if _llm_provider is None:
        cfg = get_llm_config()
        _llm_provider = OllamaLlmProvider(cfg)
    return _llm_provider


def get_investigation_workflow() -> InvestigationWorkflow:
    global _investigation_workflow
    if _investigation_workflow is None:
        llm_cfg = get_llm_config()
        provider = get_llm_provider()
        agent_cfg = AgentConfig.from_env()
        _investigation_workflow = InvestigationWorkflow(
            config=agent_cfg,
            llm_config=llm_cfg,
            llm_provider=provider,
        )
    return _investigation_workflow


def get_investigation_semaphore() -> asyncio.Semaphore:
    global _investigation_semaphore
    if _investigation_semaphore is None:
        cfg = get_api_config()
        _investigation_semaphore = asyncio.Semaphore(cfg.investigation_concurrency_limit)
    return _investigation_semaphore


def reset_dependencies() -> None:
    """Reset cached singletons (useful in testing suites)."""
    global _config, _alert_repo, _investigation_repo, _investigation_workflow, _investigation_semaphore, _llm_provider
    _config = None
    _alert_repo = None
    _investigation_repo = None
    _investigation_workflow = None
    _investigation_semaphore = None
    _llm_provider = None
