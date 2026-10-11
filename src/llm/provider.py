"""Abstract interface and exception hierarchy for local LLM providers."""

from abc import ABC, abstractmethod
from typing import Any
from pydantic import BaseModel, Field


class LlmError(Exception):
    """Base exception for LLM provider failures."""
    pass


class ProviderUnavailableError(LlmError):
    """Raised when the local LLM daemon or endpoint is unreachable."""
    pass


class ModelNotFoundError(LlmError):
    """Raised when the requested model tag is missing from the local provider."""
    pass


class RequestTimeoutError(LlmError):
    """Raised when inference exceeds configured timeout."""
    pass


class MalformedResponseError(LlmError):
    """Raised when provider returns an unparseable or corrupted payload."""
    pass


class ProviderResponse(BaseModel):
    """Standardized response container returned by an LLM provider."""
    content: str
    model_name: str
    latency_seconds: float
    raw_data: dict[str, Any] = Field(default_factory=dict)


class LlmProvider(ABC):
    """Abstract interface decoupling application investigation logic from LLM runtimes."""

    @abstractmethod
    def generate(
        self,
        prompt: str,
        system_prompt: str | None = None,
        json_format: bool = True,
    ) -> ProviderResponse:
        """Send an inference request and return the raw model generation."""
        raise NotImplementedError

    @abstractmethod
    def health_check(self) -> bool:
        """Verify that the provider daemon is responsive."""
        raise NotImplementedError

    @abstractmethod
    def discover_models(self) -> list[str]:
        """Query provider and enumerate locally installed models."""
        raise NotImplementedError

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Configured model name or tag."""
        raise NotImplementedError
