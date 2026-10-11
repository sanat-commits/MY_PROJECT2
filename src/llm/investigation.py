"""High-level investigation engine orchestrating local LLM analysis over verified alert and RAG context."""

import hashlib
import time
from typing import Any

from src.llm.config import LlmConfig, get_default_llm_config
from src.llm.ollama_provider import get_llm_provider
from src.llm.output_validation import OutputValidationError, ReportValidator
from src.llm.prompts import SYSTEM_PROMPT_V1, build_investigation_user_prompt
from src.llm.provider import (
    LlmProvider,
    ModelNotFoundError,
    ProviderUnavailableError,
    RequestTimeoutError,
)
from src.llm.schemas import (
    InvestigationInput,
    InvestigationReport,
    InvestigationResult,
    InvestigationStatus,
)
from src.risk_scoring.schema import SecurityAlert


class InvestigationEngine:
    """Orchestrates end-to-end investigation of security alerts using local Qwen 3 8B."""

    def __init__(
        self,
        config: LlmConfig | None = None,
        provider: LlmProvider | None = None,
    ):
        self.config = config or get_default_llm_config()
        self.provider = provider or get_llm_provider(self.config)
        self.validator = ReportValidator()

    def create_investigation_input(
        self,
        alert: SecurityAlert,
        retrieval_result: Any | None = None,
        attack_context: dict[str, Any] | None = None,
    ) -> InvestigationInput:
        """Assemble structured InvestigationInput from upstream alert and RAG results."""
        inv_digest = hashlib.sha256(f"{alert.alert_id}:{alert.window_id}".encode("utf-8")).hexdigest()[:8]
        inv_id = f"inv_{alert.alert_id}_{inv_digest}"

        mitre_status = None
        mitre_candidates: list[dict[str, Any]] = []

        # Check MITRE / ATT&CK context from parameter, attack_context, or mitre_context
        m_ctx = attack_context
        if not m_ctx:
            if hasattr(alert, "attack_context") and getattr(alert, "attack_context"):
                m_ctx = getattr(alert, "attack_context")
            elif hasattr(alert, "mitre_context") and getattr(alert, "mitre_context"):
                m_ctx = getattr(alert, "mitre_context")
            elif isinstance(alert, dict):
                m_ctx = alert.get("attack_context") or alert.get("mitre_context")

        if m_ctx:
            mitre_status = getattr(m_ctx, "mapping_status", None) if not isinstance(m_ctx, dict) else m_ctx.get("mapping_status")
            if hasattr(mitre_status, "value"):
                mitre_status = mitre_status.value
            cands = getattr(m_ctx, "candidate_techniques", []) if not isinstance(m_ctx, dict) else m_ctx.get("candidate_techniques", [])
            for c in cands:
                mitre_candidates.append(c.model_dump() if hasattr(c, "model_dump") else dict(c))

        rag_status = "no_results"
        rag_chunks: list[dict[str, Any]] = []
        if retrieval_result:
            if hasattr(retrieval_result, "status"):
                rag_status = retrieval_result.status.value if hasattr(retrieval_result.status, "value") else str(retrieval_result.status)
            if hasattr(retrieval_result, "results"):
                for r in retrieval_result.results:
                    rag_chunks.append(r.model_dump() if hasattr(r, "model_dump") else dict(r))

        score_breakdown = {}
        if alert.score_breakdown:
            if hasattr(alert.score_breakdown, "components"):
                for comp in alert.score_breakdown.components:
                    score_breakdown[comp.component_name] = comp.contribution
            elif hasattr(alert.score_breakdown, "model_dump"):
                score_breakdown = alert.score_breakdown.model_dump()

        return InvestigationInput(
            investigation_id=inv_id,
            alert_id=alert.alert_id,
            window_id=alert.window_id,
            anomaly_score=alert.anomaly_score,
            is_anomaly=alert.is_anomaly,
            risk_score=alert.risk_score,
            severity=alert.severity,
            evidence_items=alert.evidence,
            score_breakdown=score_breakdown,
            mitre_status=mitre_status,
            mitre_candidate_techniques=mitre_candidates,
            rag_chunks=rag_chunks,
            rag_status=rag_status,
            created_at=getattr(alert, "created_at", None),
        )

    def investigate(
        self,
        alert: SecurityAlert,
        retrieval_result: Any | None = None,
        attack_context: dict[str, Any] | None = None,
    ) -> InvestigationResult:
        """Execute local LLM investigation and return validated report."""
        # 1. Input Validation
        if not alert or not alert.alert_id:
            return InvestigationResult(
                status=InvestigationStatus.INVALID_INPUT,
                error_message="Alert object or alert_id is missing or malformed",
            )

        inv_input = self.create_investigation_input(alert, retrieval_result, attack_context=attack_context)
        user_prompt = build_investigation_user_prompt(inv_input, self.config.max_context_chunks)

        # 2. Invoke Local Model
        t0 = time.time()
        try:
            resp = self.provider.generate(
                prompt=user_prompt,
                system_prompt=SYSTEM_PROMPT_V1,
                json_format=True,
            )
        except ProviderUnavailableError as e:
            return InvestigationResult(
                status=InvestigationStatus.PROVIDER_UNAVAILABLE,
                error_message=f"Local LLM provider unreachable: {e}",
                diagnostics={"model": self.provider.model_name},
            )
        except ModelNotFoundError as e:
            return InvestigationResult(
                status=InvestigationStatus.MODEL_NOT_FOUND,
                error_message=f"Model tag not found in local provider: {e}",
                diagnostics={"model": self.provider.model_name},
            )
        except RequestTimeoutError as e:
            return InvestigationResult(
                status=InvestigationStatus.REQUEST_TIMEOUT,
                error_message=f"Model inference timed out: {e}",
                diagnostics={"timeout_seconds": self.config.timeout_seconds},
            )
        except Exception as e:
            return InvestigationResult(
                status=InvestigationStatus.INVESTIGATION_ERROR,
                error_message=f"Unexpected error during model inference: {e}",
            )

        total_latency = time.time() - t0

        # 3. Output Validation & Citation Cross-Checking
        model_metadata = {
            "provider": self.config.llm_provider,
            "model_name": resp.model_name,
            "latency_seconds": resp.latency_seconds,
            "total_investigation_seconds": round(total_latency, 3),
            "prompt_version": self.config.prompt_version,
            "schema_version": self.config.schema_version,
        }

        try:
            report = self.validator.validate(
                raw_output=resp.content,
                inv_input=inv_input,
                model_metadata=model_metadata,
            )
            return InvestigationResult(
                status=InvestigationStatus.SUCCESS,
                report=report,
                diagnostics=model_metadata,
            )
        except OutputValidationError as e:
            return InvestigationResult(
                status=InvestigationStatus.INVALID_MODEL_OUTPUT,
                error_message=f"Model output failed validation: {e}",
                diagnostics={
                    "raw_output": resp.content[:500],
                    **model_metadata,
                },
            )
