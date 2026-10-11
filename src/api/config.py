"""Configuration for the Backend API layer."""

import os
from pathlib import Path
from typing import List
from pydantic import BaseModel, Field
from dotenv import load_dotenv

load_dotenv()

DEFAULT_ROOT = Path(__file__).resolve().parents[2]


class ApiConfig(BaseModel):
    """Validated configuration settings for the backend FastAPI application."""

    host: str = Field(
        default_factory=lambda: os.getenv("API_HOST", "127.0.0.1"),
        description="Host interface to bind the HTTP server to (defaults to loopback)",
    )
    port: int = Field(
        default_factory=lambda: int(os.getenv("API_PORT", "8000")),
        description="Port number to listen on",
    )
    cors_origins: List[str] = Field(
        default_factory=lambda: [
            origin.strip()
            for origin in os.getenv(
                "CORS_ORIGINS",
                "http://localhost:3000,http://127.0.0.1:3000,http://localhost:5173,http://127.0.0.1:5173",
            ).split(",")
            if origin.strip()
        ],
        description="Allowed CORS origin addresses",
    )
    max_page_size: int = Field(
        default_factory=lambda: int(os.getenv("API_MAX_PAGE_SIZE", "100")),
        ge=1,
        le=500,
        description="Maximum permissible items per page",
    )
    default_page_size: int = Field(
        default_factory=lambda: int(os.getenv("API_DEFAULT_PAGE_SIZE", "20")),
        ge=1,
        le=100,
        description="Default items per page if unprompted",
    )
    investigation_concurrency_limit: int = Field(
        default_factory=lambda: int(os.getenv("API_INVESTIGATION_CONCURRENCY_LIMIT", "1")),
        ge=1,
        description="Maximum concurrent LLM investigations to prevent GPU/RAM saturation",
    )
    storage_dir: Path = Field(
        default_factory=lambda: Path(os.getenv("API_STORAGE_DIR", str(DEFAULT_ROOT / "artifacts" / "api"))),
        description="Directory for persisting alerts and investigation state",
    )
    base_dir: Path = Field(
        default_factory=lambda: DEFAULT_ROOT,
        description="Application base directory",
    )

    @classmethod
    def from_env(cls) -> "ApiConfig":
        return cls()
