"""Embedding provider abstraction and local model integration."""

from abc import ABC, abstractmethod
import hashlib
import numpy as np
import requests

from src.rag.config import RagConfig


class EmbeddingError(Exception):
    """Base exception for embedding provider failures."""
    pass


class EmbeddingUnavailableError(EmbeddingError):
    """Raised when the configured embedding model or daemon is unreachable."""
    pass


class EmbeddingDimensionMismatchError(EmbeddingError):
    """Raised when returned vector dimension does not match configured expectation."""
    pass


class EmbeddingProvider(ABC):
    """Abstract interface for dense embedding generation."""

    @abstractmethod
    def embed_query(self, text: str) -> list[float]:
        """Embed a single query string into a dense vector."""
        raise NotImplementedError

    @abstractmethod
    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        """Embed a batch of document strings into dense vectors."""
        raise NotImplementedError

    @property
    @abstractmethod
    def dimension(self) -> int:
        """Vector dimensionality produced by this provider."""
        raise NotImplementedError

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Canonical name/tag of the active embedding model."""
        raise NotImplementedError


class OllamaEmbeddingProvider(EmbeddingProvider):
    """Local Ollama-backed embedding provider discovering and verifying models at runtime."""

    def __init__(self, config: RagConfig | None = None):
        self.config = config or RagConfig()
        self._dimension = self.config.embedding_dimension
        self._model_name = self.config.embedding_model
        self._base_url = self.config.ollama_base_url.rstrip("/")
        self._verify_runtime_availability()

    def _verify_runtime_availability(self) -> None:
        """Verify that Ollama daemon is running and configured model is present."""
        tags_url = f"{self._base_url}/api/tags"
        try:
            resp = requests.get(tags_url, timeout=10.0)
            if resp.status_code != 200:
                raise EmbeddingUnavailableError(
                    f"Ollama daemon returned HTTP {resp.status_code} at {tags_url}. "
                    f"Ensure Ollama is running."
                )
            tags_data = resp.json()
            models = [m.get("name", "") for m in tags_data.get("models", [])]
            # Match exact model name or prefix before tag
            matched = any(
                self._model_name == m or self._model_name.split(":")[0] == m.split(":")[0]
                for m in models
            )
            if not matched:
                raise EmbeddingUnavailableError(
                    f"Configured embedding model '{self._model_name}' not found in local Ollama instance. "
                    f"Available models: {models}. Please run: ollama pull {self._model_name}"
                )
        except requests.RequestException as e:
            raise EmbeddingUnavailableError(
                f"Cannot connect to local Ollama daemon at {self._base_url}: {e}. "
                f"Ensure Ollama is started on localhost."
            )

    @property
    def dimension(self) -> int:
        return self._dimension

    @property
    def model_name(self) -> str:
        return self._model_name

    def embed_query(self, text: str) -> list[float]:
        vectors = self.embed_documents([text])
        if not vectors:
            raise EmbeddingError("Embedding generation produced no vector for query")
        return vectors[0]

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []

        embeddings_url = f"{self._base_url}/api/embeddings"
        results: list[list[float]] = []

        for text in texts:
            # Clean and normalize text
            cleaned = text.strip()
            if not cleaned:
                cleaned = "empty text"

            payload = {
                "model": self._model_name,
                "prompt": cleaned,
            }

            try:
                resp = requests.post(
                    embeddings_url,
                    json=payload,
                    timeout=self.config.ollama_timeout_seconds,
                )
                if resp.status_code != 200:
                    raise EmbeddingError(
                        f"Ollama embeddings endpoint returned HTTP {resp.status_code}: {resp.text}"
                    )
                data = resp.json()
                vec = data.get("embedding", [])
                if len(vec) != self._dimension:
                    raise EmbeddingDimensionMismatchError(
                        f"Model '{self._model_name}' produced {len(vec)}-dimensional vector, "
                        f"expected {self._dimension} dimensions."
                    )
                results.append(vec)
            except requests.RequestException as e:
                raise EmbeddingUnavailableError(
                    f"Failed to generate embedding via Ollama: {e}"
                )

        return results


class DeterministicMockEmbeddingProvider(EmbeddingProvider):
    """Deterministic, reproducible offline embedding provider for unit tests."""

    def __init__(self, dimension: int = 768, model_name: str = "mock-embedding-v1"):
        self._dimension = dimension
        self._model_name = model_name

    @property
    def dimension(self) -> int:
        return self._dimension

    @property
    def model_name(self) -> str:
        return self._model_name

    def _hash_to_vector(self, text: str) -> list[float]:
        # Generate pseudo-random vector deterministically seeded from SHA-256 of text
        digest = hashlib.sha256(text.encode("utf-8")).digest()
        seed = int.from_bytes(digest[:4], "big")
        rng = np.random.RandomState(seed)
        vec = rng.randn(self._dimension).astype(np.float32)
        norm = np.linalg.norm(vec)
        if norm > 0:
            vec = vec / norm
        return vec.tolist()

    def embed_query(self, text: str) -> list[float]:
        return self._hash_to_vector(text)

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return [self._hash_to_vector(t) for t in texts]


def get_embedding_provider(config: RagConfig) -> EmbeddingProvider:
    """Factory selecting and validating the configured embedding provider."""
    provider_name = config.embedding_provider.lower().strip()
    if provider_name == "ollama":
        return OllamaEmbeddingProvider(config)
    elif provider_name in ("mock", "test", "deterministic"):
        return DeterministicMockEmbeddingProvider(
            dimension=config.embedding_dimension,
            model_name=config.embedding_model,
        )
    else:
        raise ValueError(f"Unsupported embedding provider: '{config.embedding_provider}'")
