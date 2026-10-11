"""Configuration specification for Phase 4 MITRE ATT&CK Context.

Manages upstream source locations, local cache paths, domains, and offline policies.
"""

from pathlib import Path
from typing import Optional, Union
import os
from pydantic import BaseModel, Field
from dotenv import load_dotenv

# Load .env if present
load_dotenv()

ROOT = Path(__file__).resolve().parents[2]


class MitreConfig(BaseModel):
    """Configuration settings for MITRE ATT&CK catalog ingestion, caching, and mapping."""

    domain: str = Field(
        default="enterprise-attack",
        description="The specific MITRE ATT&CK domain being ingested",
    )
    attack_version: str = Field(
        default="v14.1",
        description="Authoritative release version of ATT&CK dataset",
    )
    source_url: str = Field(
        default="https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
        description="Official upstream STIX 2.1 data distribution URL",
    )
    data_dir: Path = Field(
        default_factory=lambda: Path(os.getenv("MITRE_DATA_DIR", str(ROOT / "data" / "mitre"))).resolve()
    )
    cache_dir: Path = Field(
        default_factory=lambda: Path(os.getenv("MITRE_CACHE_DIR", str(ROOT / "artifacts" / "mitre"))).resolve()
    )
    fixture_path: Path = Field(
        default_factory=lambda: Path(
            os.getenv("MITRE_FIXTURE_PATH", str(ROOT / "data" / "mitre" / "enterprise_attack_fixture.json"))
        ).resolve()
    )
    offline_mode: bool = Field(
        default_factory=lambda: os.getenv("MITRE_OFFLINE_MODE", "true").lower() in ("true", "1", "yes"),
        description="When true, uses verified local fixture/cache rather than downloading upstream catalog",
    )

    @property
    def cached_catalog_path(self) -> Path:
        return self.cache_dir / "catalog.json"

    @property
    def metadata_path(self) -> Path:
        return self.cache_dir / "metadata.json"


def get_default_mitre_config() -> MitreConfig:
    """Retrieve default MITRE configuration."""
    return MitreConfig()
