"""Tool wrappers conforming to docs/TOOL_CONTRACTS.md and Phase 7 specifications."""

from pathlib import Path
import time
from typing import Any, Dict, List, Optional
import pandas as pd

from src.agent.schemas import ToolExecutionRecord
from src.mitre.service import get_mitre_service
from src.rag.service import KnowledgeBaseService


class ToolRegistry:
    """Provides validated tool execution over existing verified application services."""

    def __init__(self, data_dir: Optional[Path] = None, base_dir: Optional[Path] = None):
        self.base_dir = base_dir or Path.cwd()
        self.data_dir = data_dir or (self.base_dir / "data")
        self._mitre_service = get_mitre_service()
        self._rag_service = KnowledgeBaseService(base_dir=self.base_dir)
        self._window_dataset_cache: Optional[pd.DataFrame] = None

    def _get_windows_dataset(self) -> Optional[pd.DataFrame]:
        """Load aggregated behavioral window records if available."""
        if self._window_dataset_cache is not None:
            return self._window_dataset_cache

        eval_csv = self.data_dir / "security_windows_eval_labeled.csv"
        if eval_csv.exists():
            try:
                self._window_dataset_cache = pd.read_csv(eval_csv)
                return self._window_dataset_cache
            except Exception:
                return None
    def list_tools(self) -> Dict[str, str]:
        """Return registered tools and their descriptions."""
        return {
            "search_logs": "Search existing aggregated behavioral window security records.",
            "get_related_events": "Retrieve temporally adjacent behavioral window records.",
            "search_knowledge_base": "Search verified Phase 5 hybrid RAG cybersecurity knowledge base.",
            "lookup_attack_technique": "Lookup verified Phase 4 MITRE ATT&CK technique by ID.",
        }

    def search_logs(
        self,
        user_role: Optional[str] = None,
        host_type: Optional[str] = None,
        hour: Optional[int] = None,
        is_weekend: Optional[int] = None,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 5,
    ) -> Dict[str, Any]:
        """Search existing security records relevant to the current alert.
        
        Note: The project operates over synthetic 1-hour behavioral windows,
        not raw Windows EVTX logs. This wrapper explicitly tags records as
        'aggregated_behavioral_window' to ensure truthfulness.
        """
        df = self._get_windows_dataset()
        if df is None:
            return {
                "status": "SOURCE_UNAVAILABLE",
                "error": "Aggregated window dataset is not accessible.",
                "record_type": "aggregated_behavioral_window",
                "records": [],
                "count": 0,
            }

        filtered = df.copy()
        if user_role:
            filtered = filtered[filtered["user_role"] == user_role]
        if host_type:
            filtered = filtered[filtered["host_type"] == host_type]
        if hour is not None:
            filtered = filtered[filtered["hour"] == hour]
        if is_weekend is not None:
            filtered = filtered[filtered["is_weekend"] == is_weekend]

        if filters:
            for k, v in filters.items():
                if k in filtered.columns:
                    filtered = filtered[filtered[k] == v]

        sample = filtered.head(limit).to_dict(orient="records")
        return {
            "status": "SUCCESS" if len(sample) > 0 else "NO_RESULTS",
            "record_type": "aggregated_behavioral_window",
            "records": sample,
            "count": len(sample),
            "total_matches": len(filtered),
        }

    def get_related_events(
        self,
        window_id: str,
        hour_radius: int = 1,
    ) -> Dict[str, Any]:
        """Retrieve related records temporally or contextually linked to a window ID."""
        if not window_id or not isinstance(window_id, str):
            return {
                "status": "INVALID_INPUT",
                "error": "window_id must be a non-empty string.",
                "record_type": "aggregated_behavioral_window",
                "related_records": [],
                "count": 0,
            }

        df = self._get_windows_dataset()
        if df is None:
            return {
                "status": "SOURCE_UNAVAILABLE",
                "error": "Underlying telemetry store is not accessible.",
                "record_type": "aggregated_behavioral_window",
                "related_records": [],
                "count": 0,
            }

        target = df[df["window_id"] == window_id]
        if target.empty:
            return {
                "status": "NO_RESULTS",
                "error": f"Window ID '{window_id}' not found.",
                "record_type": "aggregated_behavioral_window",
                "related_records": [],
                "count": 0,
            }

        t_row = target.iloc[0]
        h = t_row["hour"]
        d = t_row["day_of_week"]
        u = t_row["user_role"]

        # Search for temporally adjacent windows for same user role
        related = df[
            (df["user_role"] == u)
            & (df["day_of_week"] == d)
            & (df["hour"].between(max(0, h - hour_radius), min(23, h + hour_radius)))
            & (df["window_id"] != window_id)
        ]

        records = related.head(5).to_dict(orient="records")
        return {
            "status": "SUCCESS" if len(records) > 0 else "NO_RESULTS",
            "record_type": "aggregated_behavioral_window",
            "related_records": records,
            "count": len(records),
        }

    def search_knowledge_base(
        self,
        query: str,
        top_k: int = 2,
    ) -> Dict[str, Any]:
        """Call existing Phase 5 hybrid retrieval service."""
        if not query or not isinstance(query, str) or not query.strip():
            return {
                "status": "INVALID_INPUT",
                "error": "Query must be a non-empty string.",
                "chunks": [],
                "count": 0,
            }

        try:
            res = self._rag_service.search_knowledge_base(query=query.strip(), top_k=top_k)
            chunks_dump = [c.model_dump() for c in res.results]
            return {
                "status": "SUCCESS" if len(chunks_dump) > 0 else "NO_RESULTS",
                "query": query,
                "chunks": chunks_dump,
                "count": len(chunks_dump),
            }
        except Exception as e:
            return {
                "status": "ERROR",
                "error": f"RAG retrieval failure: {e}",
                "chunks": [],
                "count": 0,
            }

    def lookup_attack_technique(
        self,
        technique_id: str,
    ) -> Dict[str, Any]:
        """Call existing Phase 4 MITRE ATT&CK lookup service."""
        if not technique_id or not isinstance(technique_id, str) or not technique_id.strip():
            return {
                "status": "INVALID_INPUT",
                "error": "technique_id must be a non-empty string.",
                "data": None,
            }

        try:
            return self._mitre_service.lookup_attack_technique(technique_id.strip().upper())
        except Exception as e:
            return {
                "status": "ERROR",
                "error": f"MITRE lookup failure: {e}",
                "data": None,
            }

    def execute_tool(
        self,
        tool_name: str,
        parameters: Dict[str, Any],
    ) -> ToolExecutionRecord:
        """Safely execute a registered tool and return an auditable execution record."""
        t0 = time.time()
        start_time = t0

        try:
            if tool_name == "search_logs":
                res = self.search_logs(**parameters)
            elif tool_name == "get_related_events":
                res = self.get_related_events(**parameters)
            elif tool_name == "search_knowledge_base":
                res = self.search_knowledge_base(**parameters)
            elif tool_name == "lookup_attack_technique":
                res = self.lookup_attack_technique(**parameters)
            else:
                duration = time.time() - t0
                return ToolExecutionRecord(
                    tool_name=tool_name,
                    parameters=parameters,
                    status="ERROR",
                    error=f"Unrecognized tool: {tool_name}",
                    started_at=start_time,
                    duration_seconds=duration,
                )
        except Exception as e:
            duration = time.time() - t0
            return ToolExecutionRecord(
                tool_name=tool_name,
                parameters=parameters,
                status="ERROR",
                error=f"Tool parameter or execution error: {e}",
                started_at=start_time,
                duration_seconds=duration,
            )

        duration = time.time() - t0
        raw_status = res.get("status", "SUCCESS")
        status = str(raw_status).upper()
        err = res.get("error")

        return ToolExecutionRecord(
            tool_name=tool_name,
            parameters=parameters,
            status=status,
            data=res,
            error=err,
            started_at=start_time,
            duration_seconds=duration,
        )
