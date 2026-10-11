"""BM25 Lexical search index for token-level and exact identifier retrieval."""

import json
import math
from pathlib import Path
import re
from typing import Any

from src.rag.schemas import KnowledgeChunk


def tokenize_cybersecurity_text(text: str) -> list[str]:
    """Tokenize text preserving exact identifiers (T1110, Event IDs, filenames, GUIDs)."""
    # Normalize lowercase while retaining dots, dashes, underscores inside identifiers
    tokens = re.findall(r"[a-z0-9_\-\.]+", text.lower())
    # Clean trailing or leading punctuation
    cleaned = []
    for t in tokens:
        stripped = t.strip(".-_")
        if stripped and len(stripped) > 1:
            cleaned.append(stripped)
    return cleaned


class BM25Index:
    """Inverted index implementing Okapi BM25 ranking algorithm."""

    def __init__(self, k1: float = 1.5, b: float = 0.75):
        self.k1 = k1
        self.b = b
        self.doc_count: int = 0
        self.avg_doc_len: float = 0.0
        self.doc_lens: dict[str, int] = {}
        self.term_doc_freqs: dict[str, int] = {}
        self.inverted_index: dict[str, dict[str, int]] = {}  # term -> {doc_id: freq}
        self.chunk_records: dict[str, KnowledgeChunk] = {}

    def build(self, chunks: list[KnowledgeChunk]) -> None:
        """Construct BM25 inverted index from a collection of KnowledgeChunks."""
        self.clear()
        if not chunks:
            return

        self.doc_count = len(chunks)
        total_len = 0

        for chunk in chunks:
            self.chunk_records[chunk.chunk_id] = chunk
            tokens = tokenize_cybersecurity_text(chunk.content)
            doc_len = len(tokens)
            self.doc_lens[chunk.chunk_id] = doc_len
            total_len += doc_len

            term_counts: dict[str, int] = {}
            for t in tokens:
                term_counts[t] = term_counts.get(t, 0) + 1

            for term, count in term_counts.items():
                if term not in self.inverted_index:
                    self.inverted_index[term] = {}
                    self.term_doc_freqs[term] = 0
                self.inverted_index[term][chunk.chunk_id] = count
                self.term_doc_freqs[term] += 1

        self.avg_doc_len = total_len / self.doc_count if self.doc_count > 0 else 0.0

    def search(
        self,
        query: str,
        top_k: int = 15,
        filters: dict[str, Any] | None = None,
    ) -> list[tuple[KnowledgeChunk, float]]:
        """Compute BM25 scores for matching chunks."""
        if self.doc_count == 0:
            return []

        query_tokens = tokenize_cybersecurity_text(query)
        if not query_tokens:
            return []

        scores: dict[str, float] = {}

        for term in query_tokens:
            if term not in self.inverted_index:
                continue

            n_q = self.term_doc_freqs[term]
            # Standard Robertson-Spärck Jones IDF with smoothing
            idf = math.log(1.0 + (self.doc_count - n_q + 0.5) / (n_q + 0.5))

            for doc_id, freq in self.inverted_index[term].items():
                chunk = self.chunk_records.get(doc_id)
                if not chunk:
                    continue

                # Apply metadata filters if supplied
                if filters:
                    skip = False
                    for fk, fv in filters.items():
                        if getattr(chunk, fk, None) != fv and chunk.source_type.value != fv:
                            skip = True
                            break
                    if skip:
                        continue

                doc_len = self.doc_lens.get(doc_id, self.avg_doc_len)
                num = freq * (self.k1 + 1.0)
                denom = freq + self.k1 * (1.0 - self.b + self.b * (doc_len / (self.avg_doc_len or 1.0)))
                tf_score = num / denom

                scores[doc_id] = scores.get(doc_id, 0.0) + (idf * tf_score)

        results = [
            (self.chunk_records[doc_id], score)
            for doc_id, score in scores.items()
            if score > 0.0
        ]
        results.sort(key=lambda x: x[1], reverse=True)
        return results[:top_k]

    def save(self, file_path: Path) -> None:
        """Serialize BM25 index to JSON."""
        file_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "k1": self.k1,
            "b": self.b,
            "doc_count": self.doc_count,
            "avg_doc_len": self.avg_doc_len,
            "doc_lens": self.doc_lens,
            "term_doc_freqs": self.term_doc_freqs,
            "inverted_index": self.inverted_index,
            "chunk_records": {cid: c.model_dump() for cid, c in self.chunk_records.items()},
        }
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    @classmethod
    def load(cls, file_path: Path) -> "BM25Index":
        """Deserialize BM25 index from JSON file."""
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        idx = cls(k1=data.get("k1", 1.5), b=data.get("b", 0.75))
        idx.doc_count = data.get("doc_count", 0)
        idx.avg_doc_len = data.get("avg_doc_len", 0.0)
        idx.doc_lens = data.get("doc_lens", {})
        idx.term_doc_freqs = data.get("term_doc_freqs", {})
        idx.inverted_index = data.get("inverted_index", {})
        idx.chunk_records = {
            cid: KnowledgeChunk.model_validate(cdata)
            for cid, cdata in data.get("chunk_records", {}).items()
        }
        return idx

    def clear(self) -> None:
        """Clear all stored index structures."""
        self.doc_count = 0
        self.avg_doc_len = 0.0
        self.doc_lens.clear()
        self.term_doc_freqs.clear()
        self.inverted_index.clear()
        self.chunk_records.clear()
