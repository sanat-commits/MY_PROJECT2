"""Persistent vector store implementations supporting Chroma and SQLite backends."""

from abc import ABC, abstractmethod
import json
from pathlib import Path
import sqlite3
from typing import Any
import numpy as np

from src.rag.config import RagConfig
from src.rag.schemas import DocumentType, KnowledgeChunk


class VectorStore(ABC):
    """Abstract interface for persistent vector store implementations."""

    @abstractmethod
    def add_chunks(self, chunks: list[KnowledgeChunk], embeddings: list[list[float]]) -> None:
        """Idempotently add or update chunks with dense embedding vectors."""
        raise NotImplementedError

    @abstractmethod
    def search(
        self,
        query_vector: list[float],
        top_k: int = 10,
        filters: dict[str, Any] | None = None,
    ) -> list[tuple[KnowledgeChunk, float]]:
        """Search the vector index returning tuples of (KnowledgeChunk, cosine_similarity)."""
        raise NotImplementedError

    @abstractmethod
    def get_chunk(self, chunk_id: str) -> KnowledgeChunk | None:
        """Retrieve a specific chunk by its chunk_id."""
        raise NotImplementedError

    @abstractmethod
    def count(self) -> int:
        """Total number of unique chunks currently indexed."""
        raise NotImplementedError

    @abstractmethod
    def clear(self) -> None:
        """Reset and remove all indexed chunks."""
        raise NotImplementedError


class ChromaVectorStore(VectorStore):
    """Persistent vector store utilizing ChromaDB."""

    def __init__(self, config: RagConfig):
        import chromadb

        self.config = config
        self.db_path = Path(config.vector_store_path)
        self.db_path.mkdir(parents=True, exist_ok=True)

        self.client = chromadb.PersistentClient(path=str(self.db_path))
        self.collection = self.client.get_or_create_collection(
            name=config.collection_name,
            metadata={"hnsw:space": "cosine"},
        )
        self._chunks_cache: dict[str, KnowledgeChunk] = {}
        self._load_cache()

    def _load_cache(self) -> None:
        """Load stored chunks into in-memory reference cache for fast metadata lookup."""
        cache_file = self.db_path / "chunks_meta.json"
        if cache_file.exists():
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    raw_dict = json.load(f)
                    for cid, cdata in raw_dict.items():
                        self._chunks_cache[cid] = KnowledgeChunk.model_validate(cdata)
            except Exception:
                self._chunks_cache = {}

    def _save_cache(self) -> None:
        cache_file = self.db_path / "chunks_meta.json"
        with open(cache_file, "w", encoding="utf-8") as f:
            json.dump({cid: c.model_dump() for cid, c in self._chunks_cache.items()}, f, indent=2)

    def add_chunks(self, chunks: list[KnowledgeChunk], embeddings: list[list[float]]) -> None:
        if not chunks:
            return

        ids = [c.chunk_id for c in chunks]
        docs = [c.content for c in chunks]
        metadatas = [
            {
                "source_id": c.source_id,
                "source_title": c.source_title,
                "document_title": c.document_title,
                "source_type": c.source_type.value,
                "technique_id": c.technique_id or "",
                "rule_id": c.rule_id or "",
            }
            for c in chunks
        ]

        # Chroma upsert is naturally idempotent
        self.collection.upsert(
            ids=ids,
            embeddings=embeddings,
            documents=docs,
            metadatas=metadatas,
        )

        for chunk in chunks:
            self._chunks_cache[chunk.chunk_id] = chunk
        self._save_cache()

    def search(
        self,
        query_vector: list[float],
        top_k: int = 10,
        filters: dict[str, Any] | None = None,
    ) -> list[tuple[KnowledgeChunk, float]]:
        if self.count() == 0:
            return []

        where_filter = None
        if filters:
            conditions = []
            for k, v in filters.items():
                if v:
                    conditions.append({k: {"$eq": v}})
            if len(conditions) == 1:
                where_filter = conditions[0]
            elif len(conditions) > 1:
                where_filter = {"$and": conditions}

        results = self.collection.query(
            query_embeddings=[query_vector],
            n_results=min(top_k, self.count()),
            where=where_filter,
            include=["documents", "metadatas", "distances"],
        )

        output: list[tuple[KnowledgeChunk, float]] = []
        if not results or not results["ids"] or not results["ids"][0]:
            return output

        ids = results["ids"][0]
        distances = results["distances"][0] if results.get("distances") else [0.0] * len(ids)

        for cid, dist in zip(ids, distances):
            chunk = self._chunks_cache.get(cid)
            if chunk:
                # Cosine distance to similarity: similarity = 1.0 - distance
                sim = max(0.0, 1.0 - dist)
                output.append((chunk, sim))

        return output

    def get_chunk(self, chunk_id: str) -> KnowledgeChunk | None:
        return self._chunks_cache.get(chunk_id)

    def count(self) -> int:
        return self.collection.count()

    def clear(self) -> None:
        self.client.delete_collection(self.config.collection_name)
        self.collection = self.client.get_or_create_collection(
            name=self.config.collection_name,
            metadata={"hnsw:space": "cosine"},
        )
        self._chunks_cache.clear()
        self._save_cache()


class SQLiteVectorStore(VectorStore):
    """Zero-dependency persistent SQLite + NumPy vector store."""

    def __init__(self, config: RagConfig):
        self.config = config
        self.db_path = Path(config.vector_store_path)
        self.db_path.mkdir(parents=True, exist_ok=True)
        self.db_file = self.db_path / "sqlite_vector_store.db"
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_file) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS chunks (
                    chunk_id TEXT PRIMARY KEY,
                    source_id TEXT,
                    source_title TEXT,
                    source_type TEXT,
                    technique_id TEXT,
                    rule_id TEXT,
                    content TEXT,
                    raw_chunk_json TEXT,
                    vector_blob BLOB
                )
            """)
            conn.commit()

    def add_chunks(self, chunks: list[KnowledgeChunk], embeddings: list[list[float]]) -> None:
        if not chunks:
            return

        with sqlite3.connect(self.db_file) as conn:
            for chunk, vec in zip(chunks, embeddings):
                vec_arr = np.array(vec, dtype=np.float32)
                conn.execute("""
                    INSERT OR REPLACE INTO chunks (
                        chunk_id, source_id, source_title, source_type,
                        technique_id, rule_id, content, raw_chunk_json, vector_blob
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    chunk.chunk_id,
                    chunk.source_id,
                    chunk.source_title,
                    chunk.source_type.value,
                    chunk.technique_id or "",
                    chunk.rule_id or "",
                    chunk.content,
                    chunk.model_dump_json(),
                    vec_arr.tobytes(),
                ))
            conn.commit()

    def search(
        self,
        query_vector: list[float],
        top_k: int = 10,
        filters: dict[str, Any] | None = None,
    ) -> list[tuple[KnowledgeChunk, float]]:
        if self.count() == 0:
            return []

        q_vec = np.array(query_vector, dtype=np.float32)
        q_norm = np.linalg.norm(q_vec)
        if q_norm == 0:
            return []

        query = "SELECT chunk_id, raw_chunk_json, vector_blob FROM chunks"
        params = []
        if filters:
            where_clauses = []
            for k, v in filters.items():
                if v:
                    where_clauses.append(f"{k} = ?")
                    params.append(v)
            if where_clauses:
                query += " WHERE " + " AND ".join(where_clauses)

        scores: list[tuple[KnowledgeChunk, float]] = []
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            for row in cursor.fetchall():
                cid, raw_json, blob = row
                chunk_obj = KnowledgeChunk.model_validate_json(raw_json)
                c_vec = np.frombuffer(blob, dtype=np.float32)
                c_norm = np.linalg.norm(c_vec)
                if c_norm > 0:
                    sim = float(np.dot(q_vec, c_vec) / (q_norm * c_norm))
                else:
                    sim = 0.0
                scores.append((chunk_obj, max(0.0, sim)))

        scores.sort(key=lambda x: x[1], reverse=True)
        return scores[:top_k]

    def get_chunk(self, chunk_id: str) -> KnowledgeChunk | None:
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT raw_chunk_json FROM chunks WHERE chunk_id = ?", (chunk_id,))
            row = cursor.fetchone()
            if row:
                return KnowledgeChunk.model_validate_json(row[0])
        return None

    def count(self) -> int:
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM chunks")
            row = cursor.fetchone()
            return row[0] if row else 0

    def clear(self) -> None:
        with sqlite3.connect(self.db_file) as conn:
            conn.execute("DELETE FROM chunks")
            conn.commit()


def get_vector_store(config: RagConfig) -> VectorStore:
    """Factory selecting and instantiating the configured vector store backend."""
    provider = config.vector_store_provider.lower().strip()
    if provider == "chroma":
        return ChromaVectorStore(config)
    elif provider in ("sqlite", "persistent_sqlite"):
        return SQLiteVectorStore(config)
    else:
        raise ValueError(f"Unsupported vector store provider: '{config.vector_store_provider}'")
