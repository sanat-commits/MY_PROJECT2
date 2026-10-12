"""Ollama provider implementation for local Qwen 3 8B model inference."""

import json
import os
import time
from typing import Any
import requests

from src.llm.config import LlmConfig
from src.llm.provider import (
    LlmProvider,
    MalformedResponseError,
    ModelNotFoundError,
    ProviderResponse,
    ProviderUnavailableError,
    RequestTimeoutError,
)


class OllamaLlmProvider(LlmProvider):
    """Local Ollama runtime provider for local Qwen 3 8B inference."""

    def __init__(self, config: LlmConfig):
        self.config = config
        self._base_url = config.ollama_base_url.rstrip("/")
        self._model_name = config.ollama_model
        self._verify_availability()

    def _verify_availability(self) -> None:
        """Verify daemon connectivity and model existence on startup."""
        if not self.health_check():
            raise ProviderUnavailableError(
                f"Cannot connect to local Ollama daemon at {self._base_url}. "
                f"Ensure the Ollama service is active."
            )
        installed = self.discover_models()
        matched = any(
            self._model_name == m or self._model_name.split(":")[0] == m.split(":")[0]
            for m in installed
        )
        if not matched:
            raise ModelNotFoundError(
                f"Configured model '{self._model_name}' not found in local Ollama instance. "
                f"Installed models: {installed}. Please run: ollama pull {self._model_name}"
            )

    @property
    def model_name(self) -> str:
        return self._model_name

    def health_check(self) -> bool:
        """Check if Ollama server responds at /api/tags."""
        try:
            r = requests.get(f"{self._base_url}/api/tags", timeout=10.0)
            return r.status_code == 200
        except Exception:
            return False

    def discover_models(self) -> list[str]:
        """Enumerate installed local models."""
        url = f"{self._base_url}/api/tags"
        try:
            r = requests.get(url, timeout=10.0)
            if r.status_code != 200:
                raise ProviderUnavailableError(f"HTTP {r.status_code} querying tags at {url}")
            data = r.json()
            return [m.get("name", "") for m in data.get("models", [])]
        except requests.RequestException as e:
            raise ProviderUnavailableError(f"Failed to query local models: {e}")

    def generate(
        self,
        prompt: str,
        system_prompt: str | None = None,
        json_format: bool = True,
    ) -> ProviderResponse:
        """Send inference request to Ollama with timeout and bounded retry handling."""
        gen_url = f"{self._base_url}/api/generate"
        payload: dict[str, Any] = {
            "model": self._model_name,
            "prompt": prompt,
            "stream": False,
            "think": False,
            "options": {
                "temperature": self.config.temperature,
                "num_predict": self.config.max_output_tokens,
                "num_ctx": 4096,
                "num_thread": min(os.cpu_count() or 8, 14),
            },
        }
        if system_prompt:
            payload["system"] = system_prompt
        if json_format:
            payload["format"] = "json"

        last_error = None
        for attempt in range(1, self.config.max_retries + 1):
            t0 = time.time()
            try:
                resp = requests.post(
                    gen_url,
                    json=payload,
                    timeout=self.config.timeout_seconds,
                )
                latency = time.time() - t0

                if resp.status_code == 404:
                    raise ModelNotFoundError(f"Model '{self._model_name}' not found by Ollama runtime")
                if resp.status_code != 200:
                    raise MalformedResponseError(
                        f"Ollama returned HTTP {resp.status_code}: {resp.text}"
                    )

                data = resp.json()
                content = data.get("response", "").strip()
                if not content:
                    raise MalformedResponseError("Ollama generation returned empty response body")

                return ProviderResponse(
                    content=content,
                    model_name=data.get("model", self._model_name),
                    latency_seconds=round(latency, 3),
                    raw_data=data,
                )

            except requests.Timeout as e:
                last_error = RequestTimeoutError(
                    f"Inference request timed out after {self.config.timeout_seconds}s (attempt {attempt}): {e}"
                )
            except requests.ConnectionError as e:
                last_error = ProviderUnavailableError(
                    f"Connection failed to Ollama daemon at {self._base_url} (attempt {attempt}): {e}"
                )
            except (ModelNotFoundError, MalformedResponseError):
                raise
            except Exception as e:
                last_error = MalformedResponseError(f"Unexpected generation failure (attempt {attempt}): {e}")

            time.sleep(1.0)

        if last_error:
            raise last_error
        raise MalformedResponseError("Generation failed after maximum retries")


class MockLlmProvider(LlmProvider):
    """Deterministic, mock LLM provider for fast unit tests without network or GPU."""

    def __init__(self, model_name: str = "mock-qwen3-8b"):
        self._model_name = model_name

    @property
    def model_name(self) -> str:
        return self._model_name

    def health_check(self) -> bool:
        return True

    def discover_models(self) -> list[str]:
        return [self._model_name]

    def generate(
        self,
        prompt: str,
        system_prompt: str | None = None,
        json_format: bool = True,
    ) -> ProviderResponse:
        # Generate valid mock JSON report matching schema
        mock_output = {
            "investigation_id": "inv_mock_001",
            "alert_id": "alt_mock_001",
            "summary": "Observed significant authentication anomaly with elevated failed login burst.",
            "supplied_severity": "MEDIUM",
            "supplied_risk_score": 45.0,
            "finding": "SUSPICIOUS_ACTIVITY",
            "observed_evidence": [
                {
                    "field_name": "failed_logins",
                    "observed_value": 25,
                    "description": "Burst of 25 failed logins exceeding normal threshold"
                }
            ],
            "interpretation": "The high count of failed authentication attempts indicates automated password guessing.",
            "possible_attack_techniques": ["T1110"],
            "uncertainty": "Telemetry window is aggregated; target user accounts and IP reputation require verification.",
            "recommended_next_steps": [
                "Inspect authentication logs for Event ID 4625 to identify target usernames",
                "Check for subsequent successful logons (Event ID 4624) from the same source IP"
            ],
            "citations": [
                {
                    "chunk_id": "chk_mitre_attack_ent_00_099f5e7106bc",
                    "source_id": "src_mitre_attack_enterprise",
                    "source_title": "MITRE ATT&CK Enterprise Catalog",
                    "source_uri_or_path": "https://attack.mitre.org/techniques/T1110",
                    "document_title": "Brute Force (T1110)"
                }
            ],
            "limitations": [
                "Window telemetry does not record command-line arguments or individual event timestamps"
            ]
        }
        return ProviderResponse(
            content=json.dumps(mock_output),
            model_name=self._model_name,
            latency_seconds=0.05,
            raw_data={"mock": True},
        )


def get_llm_provider(config: LlmConfig) -> LlmProvider:
    """Factory selecting and instantiating the configured LLM provider."""
    provider_type = config.llm_provider.lower().strip()
    if provider_type == "ollama":
        return OllamaLlmProvider(config)
    elif provider_type in ("mock", "test", "deterministic"):
        return MockLlmProvider(model_name=config.ollama_model)
    else:
        raise ValueError(f"Unsupported LLM provider: '{config.llm_provider}'")
