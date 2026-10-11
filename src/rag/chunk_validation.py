"""Quality validation for knowledge base chunks before embedding and indexing."""

from src.rag.config import RagConfig
from src.rag.schemas import ChunkValidationResult, KnowledgeChunk


class ChunkValidator:
    """Validates chunks against quality, provenance, and coherence standards."""

    def __init__(self, config: RagConfig | None = None):
        self.config = config or RagConfig()
        self.rejected_chunks: list[dict[str, str]] = []

    def validate(self, chunk: KnowledgeChunk) -> ChunkValidationResult:
        """Evaluate a KnowledgeChunk against all quality and provenance gates."""
        # 1. Content completeness and non-empty check
        content = chunk.content.strip()
        if not content:
            reason = "Chunk content is empty or contains whitespace only"
            self._record_rejection(chunk, reason)
            return ChunkValidationResult(is_valid=False, rejection_reason=reason)

        if len(content) < self.config.min_chunk_chars:
            reason = f"Chunk length ({len(content)} chars) is below minimum meaningful threshold ({self.config.min_chunk_chars} chars)"
            self._record_rejection(chunk, reason)
            return ChunkValidationResult(is_valid=False, rejection_reason=reason)

        # 2. Maximum token limit check
        if chunk.token_count > self.config.max_chunk_tokens * 2.5:
            reason = f"Chunk token count ({chunk.token_count}) exceeds hard ceiling ({int(self.config.max_chunk_tokens * 2.5)})"
            self._record_rejection(chunk, reason)
            return ChunkValidationResult(is_valid=False, rejection_reason=reason)

        # 3. Mandatory provenance fields
        if not chunk.chunk_id or not chunk.chunk_id.strip():
            reason = "Missing chunk_id identifier"
            self._record_rejection(chunk, reason)
            return ChunkValidationResult(is_valid=False, rejection_reason=reason)

        if not chunk.source_id or not chunk.source_id.strip():
            reason = "Missing source_id provenance field"
            self._record_rejection(chunk, reason)
            return ChunkValidationResult(is_valid=False, rejection_reason=reason)

        if not chunk.source_title or not chunk.source_title.strip():
            reason = "Missing source_title provenance field"
            self._record_rejection(chunk, reason)
            return ChunkValidationResult(is_valid=False, rejection_reason=reason)

        if not chunk.source_uri_or_path or not chunk.source_uri_or_path.strip():
            reason = "Missing source_uri_or_path provenance field"
            self._record_rejection(chunk, reason)
            return ChunkValidationResult(is_valid=False, rejection_reason=reason)

        if not chunk.content_hash or len(chunk.content_hash) < 16:
            reason = "Missing or invalid content_hash cryptographic digest"
            self._record_rejection(chunk, reason)
            return ChunkValidationResult(is_valid=False, rejection_reason=reason)

        if not chunk.parent_document_id:
            reason = "Missing parent_document_id tie-back"
            self._record_rejection(chunk, reason)
            return ChunkValidationResult(is_valid=False, rejection_reason=reason)

        # 4. Incoherent / boilerplate artifacts check
        boilerplate_lines = 0
        total_lines = len(content.splitlines())
        for line in content.splitlines():
            line_str = line.strip().lower()
            if line_str in ("---", "```", "navigation", "cookie policy", "privacy policy", "copyright"):
                boilerplate_lines += 1

        if total_lines > 0 and (boilerplate_lines / total_lines) > 0.6:
            reason = "Chunk consists primarily of boilerplate lines or markup delimiters"
            self._record_rejection(chunk, reason)
            return ChunkValidationResult(is_valid=False, rejection_reason=reason)

        return ChunkValidationResult(is_valid=True)

    def _record_rejection(self, chunk: KnowledgeChunk, reason: str) -> None:
        self.rejected_chunks.append({
            "chunk_id": chunk.chunk_id,
            "source_id": chunk.source_id,
            "reason": reason,
        })
