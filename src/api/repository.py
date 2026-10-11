"""Alert and Investigation Repositories for Phase 8 Backend API.

Provides local persistence and query capabilities over verified security alerts
and completed LangGraph investigations.
"""

from pathlib import Path
import json
import logging
from typing import Any, Dict, List, Optional, Tuple, Union
import pandas as pd

from src.risk_scoring.schema import SecurityAlert, SeverityLevel
from src.mitre.schemas import AlertWithMitreContext
from src.agent.schemas import InvestigationResult

logger = logging.getLogger(__name__)


class AlertRepository:
    """Repository managing local storage, indexing, and retrieval of security alerts."""

    def __init__(
        self,
        storage_dir: Optional[Path] = None,
        base_dir: Optional[Path] = None,
        autoload_evaluation: bool = True,
    ):
        self.base_dir = base_dir or Path.cwd()
        self.storage_dir = storage_dir or (self.base_dir / "artifacts" / "api")
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.cache_file = self.storage_dir / "alerts_cache.json"

        self._alerts: Dict[str, Union[SecurityAlert, AlertWithMitreContext]] = {}
        self._loaded: bool = False

        if autoload_evaluation:
            self._ensure_loaded()

    def _ensure_loaded(self) -> None:
        """Load alerts from persistent cache or compute from evaluation dataset."""
        if self._loaded:
            return

        if self.cache_file.exists():
            try:
                with open(self.cache_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for item in data:
                    a_id = item.get("alert_id")
                    if a_id:
                        if "attack_context" in item:
                            self._alerts[a_id] = AlertWithMitreContext(**item)
                        else:
                            self._alerts[a_id] = SecurityAlert(**item)
                self._loaded = True
                logger.info("Loaded %d alerts from %s", len(self._alerts), self.cache_file)
                return
            except Exception as e:
                logger.warning("Failed to load alerts cache from %s: %e. Recomputing...", self.cache_file, e)

        # Compute alerts from evaluation dataset using Phase 2, 3, and 4
        self._seed_from_evaluation()
        self._loaded = True

    def _seed_from_evaluation(self, limit: int = 100) -> None:
        """Score real evaluation windows using Phase 2, Phase 3, and Phase 4 services."""
        eval_csv = self.base_dir / "data" / "security_windows_eval_labeled.csv"
        ml_dir = self.base_dir / "artifacts" / "ml"
        if not eval_csv.exists() or not ml_dir.exists():
            return

        try:
            from src.ml.inference import AnomalyDetector
            from src.risk_scoring.engine import RiskEngine
            from src.risk_scoring.config import get_default_risk_config
            from src.mitre.service import get_mitre_service

            df = pd.read_csv(eval_csv).head(limit)
            detector = AnomalyDetector.load(ml_dir)
            preds = detector.predict(df)

            risk_engine = RiskEngine(get_default_risk_config())
            raw_alerts = risk_engine.score_alerts(preds, df)

            mitre_svc = get_mitre_service()
            for raw_alert in raw_alerts:
                enriched = mitre_svc.enrich_alert(raw_alert)
                self._alerts[enriched.alert_id] = enriched

            self._persist()
            logger.info("Seeded %d alerts from evaluation dataset into repository.", len(self._alerts))
        except Exception as e:
            logger.error("Failed to seed alerts from evaluation dataset: %s", e)

    def _persist(self) -> None:
        """Serialize current alerts collection to disk."""
        try:
            serializable = [
                a.model_dump() if hasattr(a, "model_dump") else a
                for a in self._alerts.values()
            ]
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(serializable, f, indent=2)
        except Exception as e:
            logger.error("Failed to persist alerts cache: %s", e)

    def get(self, alert_id: str) -> Optional[Union[SecurityAlert, AlertWithMitreContext]]:
        """Retrieve an alert by its unique alert_id."""
        self._ensure_loaded()
        return self._alerts.get(alert_id)

    def list(
        self,
        offset: int = 0,
        limit: int = 20,
        severity: Optional[str] = None,
        is_anomaly: Optional[int] = None,
    ) -> Tuple[List[Union[SecurityAlert, AlertWithMitreContext]], int]:
        """Return a filtered, paginated slice of alerts alongside total count."""
        self._ensure_loaded()
        candidates = list(self._alerts.values())

        if severity:
            sev_upper = severity.strip().upper()
            candidates = [
                a for a in candidates
                if (a.severity.value if hasattr(a.severity, "value") else str(a.severity)).upper() == sev_upper
            ]

        if is_anomaly is not None:
            candidates = [a for a in candidates if a.is_anomaly == is_anomaly]

        total = len(candidates)
        start = min(offset, total)
        end = min(offset + limit, total)
        return candidates[start:end], total

    def add(self, alert: Union[SecurityAlert, AlertWithMitreContext]) -> None:
        """Store or update a security alert in the repository."""
        self._ensure_loaded()
        self._alerts[alert.alert_id] = alert
        self._persist()

    def clear(self) -> None:
        """Clear all in-memory alerts (primarily for isolated test fixtures)."""
        self._alerts.clear()
        if self.cache_file.exists():
            try:
                self.cache_file.unlink()
            except Exception:
                pass
        self._loaded = True


class InvestigationRepository:
    """Repository managing persistence and retrieval of LangGraph investigation runs."""

    def __init__(self, storage_dir: Optional[Path] = None, base_dir: Optional[Path] = None):
        self.base_dir = base_dir or Path.cwd()
        self.storage_dir = storage_dir or (self.base_dir / "artifacts" / "api")
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.cache_file = self.storage_dir / "investigations_cache.json"

        self._investigations: Dict[str, InvestigationResult] = {}
        self._load()

    def _load(self) -> None:
        """Load stored investigations from disk."""
        if not self.cache_file.exists():
            return
        try:
            with open(self.cache_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            for item in data:
                inv_id = item.get("investigation_id")
                if inv_id:
                    self._investigations[inv_id] = InvestigationResult(**item)
        except Exception as e:
            logger.warning("Failed to load investigations cache from %s: %s", self.cache_file, e)

    def _persist(self) -> None:
        """Persist current investigations to disk."""
        try:
            serializable = [inv.model_dump() for inv in self._investigations.values()]
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(serializable, f, indent=2)
        except Exception as e:
            logger.error("Failed to persist investigations cache: %s", e)

    def get(self, investigation_id: str) -> Optional[InvestigationResult]:
        """Retrieve an investigation by its ID."""
        return self._investigations.get(investigation_id)

    def save(self, result: InvestigationResult) -> None:
        """Save an investigation result."""
        self._investigations[result.investigation_id] = result
        self._persist()

    def list(self, offset: int = 0, limit: int = 20) -> Tuple[List[InvestigationResult], int]:
        """Return paginated investigations list."""
        all_items = list(self._investigations.values())
        total = len(all_items)
        start = min(offset, total)
        end = min(offset + limit, total)
        return all_items[start:end], total

    def clear(self) -> None:
        """Clear cached investigations."""
        self._investigations.clear()
        if self.cache_file.exists():
            try:
                self.cache_file.unlink()
            except Exception:
                pass
