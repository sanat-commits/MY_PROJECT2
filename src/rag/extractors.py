"""Document extractors for converting heterogeneous cybersecurity sources into RawDocuments."""

import json
from pathlib import Path
from typing import Any
import yaml

from src.rag.schemas import DocumentType, RawDocument, SourceEntry


class BaseExtractor:
    """Base class for document format extractors."""

    def extract(self, source_entry: SourceEntry, base_dir: Path) -> list[RawDocument]:
        """Extract RawDocuments from the specified source file."""
        raise NotImplementedError


class AttackExtractor(BaseExtractor):
    """Extractor for MITRE ATT&CK STIX 2.1 bundles or parsed catalog JSON."""

    def extract(self, source_entry: SourceEntry, base_dir: Path) -> list[RawDocument]:
        file_path = base_dir / source_entry.canonical_path
        if not file_path.exists():
            raise FileNotFoundError(f"ATT&CK source file not found: {file_path}")

        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        documents: list[RawDocument] = []

        # If data is a STIX bundle
        if data.get("type") == "bundle" and "objects" in data:
            # Map tactics
            tactics_map = {}
            for obj in data["objects"]:
                if obj.get("type") == "x-mitre-tactic":
                    shortname = obj.get("x_mitre_shortname", "")
                    name = obj.get("name", "")
                    ext_id = ""
                    for ref in obj.get("external_references", []):
                        if ref.get("source_name") == "mitre-attack":
                            ext_id = ref.get("external_id", "")
                    if shortname:
                        tactics_map[shortname] = {"id": ext_id, "name": name}

            # Map techniques
            for obj in data["objects"]:
                if obj.get("type") == "attack-pattern" and not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False):
                    technique_id = None
                    url = source_entry.canonical_url
                    for ref in obj.get("external_references", []):
                        if ref.get("source_name") == "mitre-attack":
                            technique_id = ref.get("external_id")
                            url = ref.get("url", url)

                    if not technique_id:
                        continue

                    name = obj.get("name", "")
                    description = obj.get("description", "")
                    platforms = obj.get("x_mitre_platforms", [])
                    data_sources = obj.get("x_mitre_data_sources", [])
                    is_sub = obj.get("x_mitre_is_subtechnique", False)

                    tactic_names = []
                    tactic_ids = []
                    for phase in obj.get("kill_chain_phases", []):
                        if phase.get("kill_chain_name") == "mitre-attack":
                            pname = phase.get("phase_name")
                            if pname in tactics_map:
                                tactic_names.append(tactics_map[pname]["name"])
                                tactic_ids.append(tactics_map[pname]["id"])

                    body = (
                        f"# MITRE ATT&CK Technique: {name} ({technique_id})\n\n"
                        f"- **Type**: {'Sub-technique' if is_sub else 'Technique'}\n"
                        f"- **Tactics**: {', '.join(tactic_names) if tactic_names else 'None'}\n"
                        f"- **Platforms**: {', '.join(platforms) if platforms else 'Generic'}\n"
                        f"- **Data Sources**: {', '.join(data_sources) if data_sources else 'Not specified'}\n"
                        f"- **Reference**: {url}\n\n"
                        f"## Description\n{description}\n"
                    )

                    doc = RawDocument(
                        document_id=f"doc_{source_entry.source_id}_{technique_id.replace('.', '_')}",
                        source_id=source_entry.source_id,
                        title=f"{name} ({technique_id})",
                        content=body,
                        document_type=DocumentType.MITRE_ATTACK_STIX,
                        source_uri_or_path=url,
                        version_or_date=source_entry.version,
                        metadata={
                            "technique_id": technique_id,
                            "name": name,
                            "tactic_ids": tactic_ids,
                            "tactic_names": tactic_names,
                            "platforms": platforms,
                            "is_subtechnique": is_sub,
                        },
                    )
                    documents.append(doc)

        elif "techniques" in data:
            # Loaded from cached catalog.json
            for tid, tinfo in data["techniques"].items():
                name = tinfo.get("name", "")
                desc = tinfo.get("description", "")
                tactics = tinfo.get("tactic_names", [])
                platforms = tinfo.get("platforms", [])
                url = tinfo.get("url", source_entry.canonical_url)

                body = (
                    f"# MITRE ATT&CK Technique: {name} ({tid})\n\n"
                    f"- **Tactics**: {', '.join(tactics)}\n"
                    f"- **Platforms**: {', '.join(platforms)}\n"
                    f"- **Reference**: {url}\n\n"
                    f"## Description\n{desc}\n"
                )
                doc = RawDocument(
                    document_id=f"doc_{source_entry.source_id}_{tid.replace('.', '_')}",
                    source_id=source_entry.source_id,
                    title=f"{name} ({tid})",
                    content=body,
                    document_type=DocumentType.MITRE_ATTACK_STIX,
                    source_uri_or_path=url,
                    version_or_date=source_entry.version,
                    metadata={
                        "technique_id": tid,
                        "name": name,
                        "tactic_ids": tinfo.get("tactic_ids", []),
                        "tactic_names": tactics,
                        "platforms": platforms,
                    },
                )
                documents.append(doc)

        return documents


class SigmaExtractor(BaseExtractor):
    """Extractor for YAML Sigma detection rules."""

    def extract(self, source_entry: SourceEntry, base_dir: Path) -> list[RawDocument]:
        file_path = base_dir / source_entry.canonical_path
        if not file_path.exists():
            raise FileNotFoundError(f"Sigma rule file not found: {file_path}")

        with open(file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not isinstance(data, dict):
            raise ValueError(f"Invalid Sigma rule format in {file_path}: expected dictionary")

        rule_id = str(data.get("id", file_path.stem))
        title = data.get("title", file_path.stem)
        description = data.get("description", "")
        tags = data.get("tags", [])
        detection = data.get("detection", {})
        falsepositives = data.get("falsepositives", [])
        level = data.get("level", "medium")
        logsource = data.get("logsource", {})
        refs = data.get("references", [])

        # Extract attack technique IDs from tags (e.g., attack.t1110)
        attack_tags = []
        for t in tags:
            if t.startswith("attack.t") and len(t) > 8:
                attack_tags.append(t[7:].upper())

        # Format complete rule content
        body = (
            f"# Sigma Detection Rule: {title}\n\n"
            f"- **Rule ID**: {rule_id}\n"
            f"- **Severity Level**: {level.upper()}\n"
            f"- **Log Source**: {json.dumps(logsource)}\n"
            f"- **ATT&CK Tags**: {', '.join(attack_tags) if attack_tags else 'None'}\n"
            f"- **Tags**: {', '.join(tags)}\n\n"
            f"## Description\n{description}\n\n"
            f"## Detection Logic\n```yaml\n{yaml.dump(detection, default_flow_style=False)}```\n\n"
            f"## False Positives\n- " + "\n- ".join(falsepositives if falsepositives else ["None documented"]) + "\n\n"
            f"## References\n- " + "\n- ".join(refs if refs else ["None"]) + "\n"
        )

        doc = RawDocument(
            document_id=f"doc_{source_entry.source_id}_{rule_id}",
            source_id=source_entry.source_id,
            title=title,
            content=body,
            document_type=DocumentType.SIGMA_RULE,
            source_uri_or_path=source_entry.canonical_path,
            version_or_date=source_entry.version,
            metadata={
                "rule_id": rule_id,
                "level": level,
                "tags": tags,
                "attack_technique_ids": attack_tags,
                "logsource": logsource,
            },
        )
        return [doc]


class MarkdownExtractor(BaseExtractor):
    """Extractor for structured markdown cybersecurity guides."""

    def extract(self, source_entry: SourceEntry, base_dir: Path) -> list[RawDocument]:
        file_path = base_dir / source_entry.canonical_path
        if not file_path.exists():
            raise FileNotFoundError(f"Markdown guide file not found: {file_path}")

        content = file_path.read_text(encoding="utf-8")
        if not content.strip():
            raise ValueError(f"Empty markdown guide file: {file_path}")

        # Derive title from first H1 or source title
        title = source_entry.title
        for line in content.splitlines():
            if line.startswith("# "):
                title = line[2:].strip()
                break

        doc = RawDocument(
            document_id=f"doc_{source_entry.source_id}",
            source_id=source_entry.source_id,
            title=title,
            content=content,
            document_type=DocumentType.MARKDOWN_GUIDE,
            source_uri_or_path=source_entry.canonical_path,
            version_or_date=source_entry.version,
            metadata={
                "char_length": len(content),
            },
        )
        return [doc]


def get_extractor_for_type(doc_type: DocumentType) -> BaseExtractor:
    """Factory retrieving appropriate extractor for a document type."""
    if doc_type == DocumentType.MITRE_ATTACK_STIX:
        return AttackExtractor()
    elif doc_type == DocumentType.SIGMA_RULE:
        return SigmaExtractor()
    elif doc_type in (DocumentType.MARKDOWN_GUIDE, DocumentType.PLAIN_TEXT):
        return MarkdownExtractor()
    else:
        raise ValueError(f"Unsupported document type: {doc_type}")
