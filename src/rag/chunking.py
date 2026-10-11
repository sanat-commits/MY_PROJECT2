"""Structure-aware chunking for cybersecurity knowledge documents."""

import hashlib
import re
from typing import Any

from src.rag.config import RagConfig
from src.rag.schemas import DocumentType, KnowledgeChunk, RawDocument


TECHNIQUE_ID_REGEX = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")
EVENT_ID_REGEX = re.compile(r"\b(?:Event\s*ID\s*|EventID:\s*)(\d{4})\b", re.IGNORECASE)


def estimate_token_count(text: str) -> int:
    """Accurately estimate token count for text chunk budgeting."""
    # Heuristic: average 1 token per 3.8 characters for technical/cybersecurity text
    return max(1, int(len(text) / 3.8))


def generate_stable_chunk_id(source_id: str, doc_id: str, content: str, index: int) -> str:
    """Generate deterministic, content-hash-backed chunk identifier."""
    normalized = " ".join(content.strip().split())
    digest = hashlib.sha256(f"{source_id}:{doc_id}:{normalized}".encode("utf-8")).hexdigest()[:12]
    clean_src = source_id.replace("src_", "").replace("-", "_")[:16]
    return f"chk_{clean_src}_{index:02d}_{digest}"


class StructureAwareChunker:
    """Chunks documents while respecting structural boundaries of cybersecurity formats."""

    def __init__(self, config: RagConfig | None = None):
        self.config = config or RagConfig()

    def chunk_document(self, raw_doc: RawDocument, source_title: str) -> list[KnowledgeChunk]:
        """Split a RawDocument into structure-aware, traceable KnowledgeChunks."""
        if raw_doc.document_type == DocumentType.MITRE_ATTACK_STIX:
            return self._chunk_attack_document(raw_doc, source_title)
        elif raw_doc.document_type == DocumentType.SIGMA_RULE:
            return self._chunk_sigma_document(raw_doc, source_title)
        else:
            return self._chunk_markdown_document(raw_doc, source_title)

    def _chunk_attack_document(self, doc: RawDocument, source_title: str) -> list[KnowledgeChunk]:
        """Chunk MITRE ATT&CK technique, splitting long descriptions if necessary."""
        tid = doc.metadata.get("technique_id")
        content = doc.content
        est_tokens = estimate_token_count(content)

        # If it fits within max budget, keep technique intact
        if est_tokens <= self.config.max_chunk_tokens:
            chunk_id = generate_stable_chunk_id(doc.source_id, doc.document_id, content, 0)
            return [
                KnowledgeChunk(
                    chunk_id=chunk_id,
                    source_id=doc.source_id,
                    source_title=source_title,
                    source_uri_or_path=doc.source_uri_or_path,
                    source_type=doc.document_type,
                    source_version_or_date=doc.version_or_date,
                    document_title=doc.title,
                    heading_path=[doc.title],
                    chunk_index=0,
                    content=content,
                    content_hash=hashlib.sha256(content.encode("utf-8")).hexdigest(),
                    token_count=est_tokens,
                    parent_document_id=doc.document_id,
                    technique_id=tid,
                    event_ids=[],
                )
            ]

        # If oversized, split description into paragraphs while repeating metadata header
        header_lines = []
        body_lines = []
        in_description = False
        for line in content.splitlines():
            if line.startswith("## Description"):
                in_description = True
                continue
            if not in_description:
                header_lines.append(line)
            else:
                body_lines.append(line)

        header_prefix = "\n".join(header_lines) + "\n\n"
        chunks: list[KnowledgeChunk] = []
        paragraphs = "\n".join(body_lines).split("\n\n")

        current_para: list[str] = []
        curr_len = 0
        idx = 0

        for para in paragraphs:
            para = para.strip()
            if not para:
                continue
            para_len = estimate_token_count(para)
            if curr_len + para_len > self.config.max_chunk_tokens and current_para:
                chunk_body = header_prefix + f"## Description (Part {idx + 1})\n" + "\n\n".join(current_para)
                chunk_id = generate_stable_chunk_id(doc.source_id, doc.document_id, chunk_body, idx)
                chunks.append(
                    KnowledgeChunk(
                        chunk_id=chunk_id,
                        source_id=doc.source_id,
                        source_title=source_title,
                        source_uri_or_path=doc.source_uri_or_path,
                        source_type=doc.document_type,
                        source_version_or_date=doc.version_or_date,
                        document_title=doc.title,
                        heading_path=[doc.title, f"Description Part {idx + 1}"],
                        chunk_index=idx,
                        content=chunk_body,
                        content_hash=hashlib.sha256(chunk_body.encode("utf-8")).hexdigest(),
                        token_count=estimate_token_count(chunk_body),
                        parent_document_id=doc.document_id,
                        technique_id=tid,
                        event_ids=[],
                    )
                )
                idx += 1
                current_para = [para]
                curr_len = para_len
            else:
                current_para.append(para)
                curr_len += para_len

        if current_para:
            chunk_body = header_prefix + (f"## Description (Part {idx + 1})\n" if idx > 0 else "## Description\n") + "\n\n".join(current_para)
            chunk_id = generate_stable_chunk_id(doc.source_id, doc.document_id, chunk_body, idx)
            chunks.append(
                KnowledgeChunk(
                    chunk_id=chunk_id,
                    source_id=doc.source_id,
                    source_title=source_title,
                    source_uri_or_path=doc.source_uri_or_path,
                    source_type=doc.document_type,
                    source_version_or_date=doc.version_or_date,
                    document_title=doc.title,
                    heading_path=[doc.title, f"Description Part {idx + 1}" if idx > 0 else "Description"],
                    chunk_index=idx,
                    content=chunk_body,
                    content_hash=hashlib.sha256(chunk_body.encode("utf-8")).hexdigest(),
                    token_count=estimate_token_count(chunk_body),
                    parent_document_id=doc.document_id,
                    technique_id=tid,
                    event_ids=[],
                )
            )

        return chunks

    def _chunk_sigma_document(self, doc: RawDocument, source_title: str) -> list[KnowledgeChunk]:
        """Keep complete Sigma rule atomic so detection logic is never divorced from metadata."""
        rule_id = doc.metadata.get("rule_id")
        attack_tids = doc.metadata.get("attack_technique_ids", [])
        primary_tid = attack_tids[0] if attack_tids else None

        # Extract Event IDs if present in text
        event_ids = list(set(EVENT_ID_REGEX.findall(doc.content)))

        chunk_id = generate_stable_chunk_id(doc.source_id, doc.document_id, doc.content, 0)
        return [
            KnowledgeChunk(
                chunk_id=chunk_id,
                source_id=doc.source_id,
                source_title=source_title,
                source_uri_or_path=doc.source_uri_or_path,
                source_type=doc.document_type,
                source_version_or_date=doc.version_or_date,
                document_title=doc.title,
                heading_path=[doc.title],
                chunk_index=0,
                content=doc.content,
                content_hash=hashlib.sha256(doc.content.encode("utf-8")).hexdigest(),
                token_count=estimate_token_count(doc.content),
                parent_document_id=doc.document_id,
                technique_id=primary_tid,
                rule_id=rule_id,
                event_ids=event_ids,
            )
        ]

    def _chunk_markdown_document(self, doc: RawDocument, source_title: str) -> list[KnowledgeChunk]:
        """Heading-aware recursive chunking splitting at H2 and H3 boundaries."""
        chunks: list[KnowledgeChunk] = []
        lines = doc.content.splitlines()

        current_h1 = doc.title
        current_h2 = ""
        current_h3 = ""

        current_section_lines: list[str] = []
        chunk_idx = 0

        def flush_section():
            nonlocal chunk_idx, current_section_lines
            if not current_section_lines:
                return
            body = "\n".join(current_section_lines).strip()
            if not body or len(body) < self.config.min_chunk_chars:
                current_section_lines = []
                return

            heading_path = [current_h1]
            if current_h2:
                heading_path.append(current_h2)
            if current_h3:
                heading_path.append(current_h3)

            # Prepend breadcrumb context if missing in body
            breadcrumb = f"# {' > '.join(heading_path)}\n\n"
            full_chunk_text = breadcrumb + body if not body.startswith("#") else body

            # Extract technique and event IDs from text
            tids = list(set(TECHNIQUE_ID_REGEX.findall(full_chunk_text)))
            eids = list(set(EVENT_ID_REGEX.findall(full_chunk_text)))

            chunk_id = generate_stable_chunk_id(doc.source_id, doc.document_id, full_chunk_text, chunk_idx)
            chunks.append(
                KnowledgeChunk(
                    chunk_id=chunk_id,
                    source_id=doc.source_id,
                    source_title=source_title,
                    source_uri_or_path=doc.source_uri_or_path,
                    source_type=doc.document_type,
                    source_version_or_date=doc.version_or_date,
                    document_title=doc.title,
                    heading_path=heading_path,
                    chunk_index=chunk_idx,
                    content=full_chunk_text,
                    content_hash=hashlib.sha256(full_chunk_text.encode("utf-8")).hexdigest(),
                    token_count=estimate_token_count(full_chunk_text),
                    parent_document_id=doc.document_id,
                    technique_id=tids[0] if tids else None,
                    event_ids=eids,
                )
            )
            chunk_idx += 1
            current_section_lines = []

        for line in lines:
            if line.startswith("# "):
                current_h1 = line[2:].strip()
                continue
            elif line.startswith("## "):
                flush_section()
                current_h2 = line[3:].strip()
                current_h3 = ""
                current_section_lines.append(line)
            elif line.startswith("### "):
                flush_section()
                current_h3 = line[4:].strip()
                current_section_lines.append(line)
            else:
                current_section_lines.append(line)

        flush_section()
        return chunks
