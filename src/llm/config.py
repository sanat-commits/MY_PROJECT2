"""Configuration for the local LLM investigation subsystem."""

import os
from pathlib import Path
from pydantic import BaseModel, Field
from dotenv import load_dotenv

load_dotenv()


class LlmConfig(BaseModel):
    """Validated configuration settings for local Qwen 3 8B LLM investigation."""

    llm_provider: str = Field(
        default_factory=lambda: os.getenv("LLM_PROVIDER", "ollama").lower().strip(),
        description="LLM backend provider ('ollama' or 'mock')",
    )
    ollama_base_url: str = Field(
        default_factory=lambda: os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/"),
        description="Base URL for local Ollama daemon",
    )
    ollama_model: str = Field(
        default_factory=lambda: os.getenv("OLLAMA_MODEL", "qwen3:8b"),
        description="Discovered runtime model tag for Qwen 3 8B",
    )
    timeout_seconds: float = Field(
        default_factory=lambda: float(os.getenv("LLM_TIMEOUT_SECONDS", "120.0")),
        description="HTTP request timeout for local LLM inference",
    )
    max_retries: int = Field(
        default_factory=lambda: int(os.getenv("LLM_MAX_RETRIES", "2")),
        description="Maximum retry attempts on transient or malformed model responses",
    )
    temperature: float = Field(
        default_factory=lambda: float(os.getenv("LLM_TEMPERATURE", "0.0")),
        description="Sampling temperature (0.0 for deterministic, grounded outputs)",
    )
    max_output_tokens: int = Field(
        default_factory=lambda: int(os.getenv("LLM_MAX_OUTPUT_TOKENS", "2048")),
        description="Maximum generation length in tokens",
    )
    prompt_version: str = Field(
        default="v1.0.0",
        description="Version identifier for the investigation system prompt",
    )
    schema_version: str = Field(
        default="v1.0.0",
        description="Version identifier for the investigation report schema",
    )
    max_context_chunks: int = Field(
        default=5,
        description="Maximum number of retrieved RAG chunks passed to the prompt",
    )

    @classmethod
    def from_env(cls, **overrides) -> "LlmConfig":
        """Load configuration respecting environment variables and explicit overrides."""
        return cls(**overrides)


def get_default_llm_config() -> LlmConfig:
    """Retrieve default LLM configuration."""
    return LlmConfig()
