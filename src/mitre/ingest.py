"""Ingestion and parsing component for official MITRE ATT&CK STIX 2.1 datasets.

Validates STIX bundle structure, cryptographic hash, provenance metadata, tactics,
techniques, sub-technique relationships, and deprecation/revocation status.
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import urllib.request

from src.mitre.config import MitreConfig, get_default_mitre_config
from src.mitre.schemas import CatalogMetadata, TacticInfo, TechniqueInfo


class MitreIngestor:
    """Ingests, validates, and transforms official MITRE ATT&CK STIX bundles into indexed catalog models."""

    def __init__(self, config: Optional[MitreConfig] = None):
        self.config = config or get_default_mitre_config()

    def fetch_stix_bundle_data(self, source_path_or_url: Optional[Union[str, Path]] = None) -> Tuple[bytes, str]:
        """Load STIX bundle bytes from a local file, local fixture, or remote URL.
        
        Returns:
            (raw_bytes, source_identifier)
        """
        if source_path_or_url is not None:
            source_str = str(source_path_or_url)
            if source_str.startswith("http://") or source_str.startswith("https://"):
                if self.config.offline_mode:
                    raise RuntimeError("Remote download blocked: MitreConfig.offline_mode is enabled.")
                req = urllib.request.Request(source_str, headers={"User-Agent": "AntigravitySecurityAgent/1.0"})
                with urllib.request.urlopen(req, timeout=30) as resp:
                    return resp.read(), source_str
            else:
                p = Path(source_path_or_url)
                if not p.exists():
                    raise FileNotFoundError(f"Specified STIX source file does not exist: {p}")
                return p.read_bytes(), str(p)

        # Default fallback flow
        if self.config.offline_mode or not self.config.source_url:
            if not self.config.fixture_path.exists():
                raise FileNotFoundError(f"Local MITRE fixture not found at {self.config.fixture_path}")
            return self.config.fixture_path.read_bytes(), str(self.config.fixture_path)
        else:
            try:
                req = urllib.request.Request(
                    self.config.source_url, headers={"User-Agent": "AntigravitySecurityAgent/1.0"}
                )
                with urllib.request.urlopen(req, timeout=30) as resp:
                    return resp.read(), self.config.source_url
            except Exception as e:
                # Fallback to local fixture if available
                if self.config.fixture_path.exists():
                    return self.config.fixture_path.read_bytes(), f"{self.config.fixture_path} (fallback)"
                raise ConnectionError(f"Failed to retrieve MITRE STIX data from upstream {self.config.source_url}: {e}")

    def validate_and_parse_bundle(self, raw_bytes: bytes, source_identifier: str) -> Tuple[Dict[str, Any], CatalogMetadata]:
        """Validate STIX bundle format, prevent duplicates, parse tactics and techniques."""
        if not raw_bytes:
            raise ValueError("STIX bundle data is empty.")

        try:
            bundle = json.loads(raw_bytes.decode("utf-8"))
        except Exception as e:
            raise ValueError(f"Malformed STIX bundle: failed to parse JSON: {e}")

        if not isinstance(bundle, dict):
            raise ValueError(f"Malformed STIX bundle: expected root dict object, got {type(bundle)}")

        if bundle.get("type") != "bundle":
            raise ValueError(f"Malformed STIX bundle: root type must be 'bundle', got '{bundle.get('type')}'")

        objects = bundle.get("objects")
        if not isinstance(objects, list):
            raise ValueError("Malformed STIX bundle: missing or non-list 'objects' array")

        # 1. Duplicate object ID verification
        seen_ids = set()
        for obj in objects:
            if not isinstance(obj, dict):
                continue
            obj_id = obj.get("id")
            if obj_id:
                if obj_id in seen_ids:
                    raise ValueError(f"Duplicate STIX object ID detected in bundle: {obj_id}")
                seen_ids.add(obj_id)

        # 2. Parse Tactics (x-mitre-tactic)
        tactics_by_shortname: Dict[str, TacticInfo] = {}
        tactics_by_id: Dict[str, TacticInfo] = {}

        for obj in objects:
            if obj.get("type") == "x-mitre-tactic":
                t_name = obj.get("name", "")
                shortname = obj.get("x_mitre_shortname", "")
                desc = obj.get("description", "")
                t_id = ""
                t_url = ""
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        t_id = ref.get("external_id", "")
                        t_url = ref.get("url", "")
                        break
                if t_id and shortname:
                    tactic_info = TacticInfo(
                        tactic_id=t_id,
                        name=t_name,
                        shortname=shortname,
                        description=desc,
                        url=t_url,
                    )
                    tactics_by_shortname[shortname] = tactic_info
                    tactics_by_id[t_id] = tactic_info

        # 3. Parse Sub-technique relationships (relationship where relationship_type == 'subtechnique-of')
        # source_ref (subtechnique STIX id) -> target_ref (parent technique STIX id)
        sub_to_parent_stix: Dict[str, str] = {}
        for obj in objects:
            if obj.get("type") == "relationship" and obj.get("relationship_type") == "subtechnique-of":
                s_ref = obj.get("source_ref")
                t_ref = obj.get("target_ref")
                if s_ref and t_ref:
                    sub_to_parent_stix[s_ref] = t_ref

        # 4. Parse Techniques (attack-pattern)
        techniques_by_ext_id: Dict[str, TechniqueInfo] = {}
        stix_id_to_ext_id: Dict[str, str] = {}
        active_tech_count = 0
        active_subtech_count = 0

        # First pass: collect techniques
        raw_tech_list: List[Dict[str, Any]] = []
        for obj in objects:
            if obj.get("type") == "attack-pattern":
                ext_id = ""
                ext_url = ""
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        ext_id = ref.get("external_id", "")
                        ext_url = ref.get("url", "")
                        break
                if not ext_id:
                    continue  # Non-ATT&CK attack pattern

                stix_id_to_ext_id[obj["id"]] = ext_id
                raw_tech_list.append(obj)

        # Second pass: construct TechniqueInfo with relationships
        for obj in raw_tech_list:
            ext_id = ""
            ext_url = ""
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    ext_id = ref.get("external_id", "")
                    ext_url = ref.get("url", "")
                    break

            is_sub = bool(obj.get("x_mitre_is_subtechnique", False))
            is_deprecated = bool(obj.get("x_mitre_deprecated", False))
            is_revoked = bool(obj.get("revoked", False))

            # Associate tactics from kill_chain_phases
            tech_tactics: List[TacticInfo] = []
            for phase in obj.get("kill_chain_phases", []):
                p_name = phase.get("phase_name")
                if p_name and p_name in tactics_by_shortname:
                    tech_tactics.append(tactics_by_shortname[p_name])

            # Resolve parent technique if subtechnique
            parent_tech_id = None
            if is_sub and obj["id"] in sub_to_parent_stix:
                parent_stix = sub_to_parent_stix[obj["id"]]
                parent_tech_id = stix_id_to_ext_id.get(parent_stix)

            tech_info = TechniqueInfo(
                technique_id=ext_id,
                stix_id=obj["id"],
                name=obj.get("name", ""),
                description=obj.get("description", ""),
                is_subtechnique=is_sub,
                parent_technique_id=parent_tech_id,
                subtechnique_ids=[],  # will link below
                tactics=tech_tactics,
                platforms=obj.get("x_mitre_platforms", []),
                detection=obj.get("x_mitre_detection"),
                url=ext_url,
                version=obj.get("x_mitre_version"),
                deprecated=is_deprecated,
                revoked=is_revoked,
            )
            techniques_by_ext_id[ext_id] = tech_info

            if not is_deprecated and not is_revoked:
                if is_sub:
                    active_subtech_count += 1
                else:
                    active_tech_count += 1

        # Link subtechniques to parent
        for ext_id, tech in techniques_by_ext_id.items():
            if tech.is_subtechnique and tech.parent_technique_id:
                parent = techniques_by_ext_id.get(tech.parent_technique_id)
                if parent and ext_id not in parent.subtechnique_ids:
                    parent.subtechnique_ids.append(ext_id)

        # 5. Build metadata
        sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
        retrieval_ts = datetime.now(timezone.utc).isoformat()

        # Check for collection version if present in bundle
        version_str = self.config.attack_version
        for obj in objects:
            if obj.get("type") == "x-mitre-collection" and "x_mitre_version" in obj:
                version_str = f"v{obj['x_mitre_version']}"
                break

        metadata = CatalogMetadata(
            domain=self.config.domain,
            attack_version=version_str,
            source_url=source_identifier,
            retrieved_at=retrieval_ts,
            sha256=sha256_hash,
            technique_count=active_tech_count,
            subtechnique_count=active_subtech_count,
            tactic_count=len(tactics_by_id),
        )

        catalog_data = {
            "metadata": metadata.model_dump(),
            "tactics": {k: v.model_dump() for k, v in tactics_by_id.items()},
            "techniques": {k: v.model_dump() for k, v in techniques_by_ext_id.items()},
        }

        return catalog_data, metadata

    def ingest_and_cache(self, source_path_or_url: Optional[Union[str, Path]] = None) -> CatalogMetadata:
        """Execute full ingestion pipeline, saving serialized catalog and metadata to cache directory."""
        raw_bytes, source_id = self.fetch_stix_bundle_data(source_path_or_url)
        catalog_data, metadata = self.validate_and_parse_bundle(raw_bytes, source_id)

        # Save to cache
        self.config.cache_dir.mkdir(parents=True, exist_ok=True)
        with open(self.config.cached_catalog_path, "w", encoding="utf-8") as f:
            json.dump(catalog_data, f, indent=2)

        with open(self.config.metadata_path, "w", encoding="utf-8") as f:
            json.dump(metadata.model_dump(), f, indent=2)

        return metadata
