"""LangGraph workflow definition, node handlers, and execution graph for Phase 7."""

import hashlib
import time
from typing import Any, Dict, List, Optional

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

from src.agent.config import AgentConfig
from src.agent.schemas import (
    ActionDecision,
    AgentStatus,
    ApprovedAction,
    InvestigationResult,
    InvestigationState,
    ToolExecutionRecord,
    TraceStep,
)
from src.agent.tools import ToolRegistry
from src.llm.config import LlmConfig
from src.llm.investigation import InvestigationEngine
from src.llm.ollama_provider import get_llm_provider
from src.llm.provider import LlmProvider
from src.llm.schemas import InvestigationStatus
from src.risk_scoring.schema import SecurityAlert
from src.mitre.schemas import AlertWithMitreContext


def _parse_alert(alert_data: Any) -> Any:
    """Parse alert input preserving AttackContext and evidence."""
    if isinstance(alert_data, (SecurityAlert, AlertWithMitreContext)):
        return alert_data
    if isinstance(alert_data, dict):
        if "attack_context" in alert_data or "mitre_context" in alert_data:
            try:
                return AlertWithMitreContext(**alert_data)
            except Exception:
                pass
        try:
            return SecurityAlert(**alert_data)
        except Exception:
            return alert_data
    return alert_data


class InvestigationWorkflow:
    """Explicit LangGraph investigation agent orchestrating bounded, attributable security workflows."""

    def __init__(
        self,
        config: Optional[AgentConfig] = None,
        llm_config: Optional[LlmConfig] = None,
        llm_provider: Optional[LlmProvider] = None,
        tool_registry: Optional[ToolRegistry] = None,
    ):
        self.config = config or AgentConfig.from_env()
        self.llm_config = llm_config or LlmConfig.from_env()
        self.provider = llm_provider or get_llm_provider(self.llm_config)
        self.investigation_engine = InvestigationEngine(
            config=self.llm_config, provider=self.provider
        )
        self.tools = tool_registry or ToolRegistry()
        self.checkpointer = MemorySaver() if self.config.use_in_memory_checkpointer else None
        self.graph = self._build_graph()

    def _build_graph(self):
        """Construct explicit StateGraph with validated node transitions."""
        builder = StateGraph(dict)

        builder.add_node("validate_request", self._node_validate_request)
        builder.add_node("load_alert", self._node_load_alert)
        builder.add_node("assess_evidence", self._node_assess_evidence)
        builder.add_node("dispatch_tool", self._node_dispatch_tool)
        builder.add_node("run_investigation", self._node_run_investigation)
        builder.add_node("finalize", self._node_finalize)

        builder.add_edge(START, "validate_request")
        builder.add_edge("validate_request", "load_alert")
        builder.add_edge("load_alert", "assess_evidence")

        builder.add_conditional_edges(
            "assess_evidence",
            self._route_after_assessment,
            {
                "dispatch_tool": "dispatch_tool",
                "run_investigation": "run_investigation",
                "finalize": "finalize",
            },
        )

        builder.add_edge("dispatch_tool", "assess_evidence")
        builder.add_edge("run_investigation", "finalize")
        builder.add_edge("finalize", END)

        if self.checkpointer:
            return builder.compile(checkpointer=self.checkpointer)
        return builder.compile()

    # ---------------------------------------------------------
    # Node Implementations
    # ---------------------------------------------------------

    def _node_validate_request(self, state: dict) -> dict:
        """Validate alert object and establish runtime deadlines."""
        t0 = time.time()
        now = time.time()
        deadline = state.get("deadline", now + self.config.total_deadline_seconds)

        alert_raw = state.get("original_alert")
        if not alert_raw or not isinstance(alert_raw, (SecurityAlert, dict)):
            trace = TraceStep(
                node_name="validate_request",
                timestamp=now,
                duration_seconds=time.time() - t0,
                status="FAILED",
                summary="Validation failed: missing or invalid original_alert",
            )
            return {
                **state,
                "current_status": AgentStatus.INVALID_INPUT,
                "failure_reason": "original_alert is missing or malformed",
                "execution_trace": state.get("execution_trace", []) + [trace.model_dump()],
            }

        trace = TraceStep(
            node_name="validate_request",
            timestamp=now,
            duration_seconds=time.time() - t0,
            status="SUCCESS",
            summary="Validated investigation request and initialized budget limits",
        )
        return {
            **state,
            "deadline": deadline,
            "started_at": state.get("started_at", now),
            "execution_trace": state.get("execution_trace", []) + [trace.model_dump()],
        }

    def _node_load_alert(self, state: dict) -> dict:
        """Extract observed evidence items and verified ATT&CK context from the alert."""
        t0 = time.time()
        orig = state.get("original_alert", {})
        alert = _parse_alert(orig)

        evidence_items = []
        for ev in getattr(alert, "evidence", []):
            evidence_items.append(ev.model_dump() if hasattr(ev, "model_dump") else dict(ev))

        # Check existing Phase 4 attack context
        attack_ctx = {}
        if hasattr(alert, "attack_context") and getattr(alert, "attack_context"):
            ac = getattr(alert, "attack_context")
            attack_ctx = ac.model_dump() if hasattr(ac, "model_dump") else dict(ac)
        elif hasattr(alert, "mitre_context") and getattr(alert, "mitre_context"):
            mc = getattr(alert, "mitre_context")
            attack_ctx = mc.model_dump() if hasattr(mc, "model_dump") else dict(mc)
        elif isinstance(orig, dict):
            raw_ctx = orig.get("attack_context") or orig.get("mitre_context") or {}
            attack_ctx = raw_ctx.model_dump() if hasattr(raw_ctx, "model_dump") else dict(raw_ctx)

        alert_id = getattr(alert, "alert_id", orig.get("alert_id") if isinstance(orig, dict) else "unknown")

        trace = TraceStep(
            node_name="load_alert",
            timestamp=time.time(),
            duration_seconds=time.time() - t0,
            status="SUCCESS",
            summary=f"Loaded {len(evidence_items)} evidence signals from alert {alert_id}",
        )
        return {
            **state,
            "alert_id": alert_id,
            "observed_evidence": evidence_items,
            "attack_context": attack_ctx,
            "execution_trace": state.get("execution_trace", []) + [trace.model_dump()],
        }

    def _node_assess_evidence(self, state: dict) -> dict:
        """Evaluate evidence completeness, budget limits, and select next action."""
        t0 = time.time()
        iterations = state.get("iteration_count", 0) + 1
        tool_count = state.get("tool_call_count", 0)
        now = time.time()

        # Check budget and deadline exhaustion
        if now >= state.get("deadline", now + 1):
            trace = TraceStep(
                node_name="assess_evidence",
                timestamp=now,
                duration_seconds=time.time() - t0,
                status="TIMEOUT",
                summary="Total investigation deadline exceeded.",
            )
            return {
                **state,
                "iteration_count": iterations,
                "current_status": AgentStatus.TIMEOUT,
                "failure_reason": "Global investigation deadline exceeded.",
                "execution_trace": state.get("execution_trace", []) + [trace.model_dump()],
            }

        if iterations > self.config.max_iterations or tool_count >= self.config.max_tool_calls:
            trace = TraceStep(
                node_name="assess_evidence",
                timestamp=now,
                duration_seconds=time.time() - t0,
                status="LIMIT_REACHED",
                summary="Maximum iteration or tool call limit reached.",
            )
            return {
                **state,
                "iteration_count": iterations,
                "current_status": AgentStatus.LIMIT_REACHED,
                "warnings": state.get("warnings", []) + ["Investigation iteration/tool call limit reached."],
                "execution_trace": state.get("execution_trace", []) + [trace.model_dump()],
            }

        # Evidence evaluation logic:
        # 1. Do we have ATT&CK mapping?
        # 2. Do we have RAG knowledge context?
        # 3. Do we have related behavioral telemetry?
        action_history = state.get("action_history", [])
        retrieval_ctx = state.get("retrieval_context", [])
        attack_ctx = state.get("attack_context", {})
        alert = _parse_alert(state.get("original_alert", {}))

        decision: ActionDecision

        # Priority 1: Missing ATT&CK technique details when candidate is indicated
        has_mitre = bool(attack_ctx.get("candidate_techniques") or attack_ctx.get("matched_techniques"))
        if not has_mitre and "lookup_attack_technique" not in action_history:
            # Check if alert summary or evidence suggests brute force
            ev_summary = str(getattr(alert, "summary", "")).lower()
            technique_target = "T1110" if "failed" in ev_summary or "brute" in ev_summary else None
            if technique_target:
                decision = ActionDecision(
                    action=ApprovedAction.LOOKUP_ATTACK_TECHNIQUE,
                    reason=f"Alert evidence suggests credential access; looking up {technique_target} in verified ATT&CK catalog.",
                    parameters={"technique_id": technique_target},
                    expected_information=f"Verified technique metadata for {technique_target}",
                )
            else:
                has_mitre = True  # No target technique indicated

        # Priority 2: Missing RAG cybersecurity knowledge context
        already_searched_kb = any("search_knowledge_base" in a for a in action_history)
        if not retrieval_ctx and not already_searched_kb:
            cands = attack_ctx.get("candidate_techniques", [])
            if cands and isinstance(cands, list) and len(cands) > 0:
                first_c = cands[0] if isinstance(cands[0], dict) else (cands[0].model_dump() if hasattr(cands[0], "model_dump") else dict(cands[0]))
                tid = first_c.get("technique_id", "")
                tname = first_c.get("technique_name", "")
                q = f"{tid} {tname}".strip()
            elif getattr(alert, "evidence", None):
                top_ev = sorted(alert.evidence, key=lambda e: getattr(e, "contribution", 0), reverse=True)
                signals = " ".join(e.signal_name.replace("_", " ") for e in top_ev[:2])
                q = signals or "authentication failed login anomaly"
            else:
                q = "security anomaly behavioral detection"

            decision = ActionDecision(
                action=ApprovedAction.SEARCH_KNOWLEDGE_BASE,
                reason=f"Retrieving guidance and detection patterns for '{q}' from RAG knowledge base.",
                parameters={"query": q, "top_k": 2},
                expected_information="Corroborating technique documentation and Sigma rules",
            )
        # Priority 3: Retrieve temporally related window records if none loaded
        elif not any("get_related_events" in a for a in action_history) and hasattr(alert, "window_id"):
            decision = ActionDecision(
                action=ApprovedAction.GET_RELATED_EVENTS,
                reason="Inspecting temporally adjacent behavioral windows for entity activity patterns.",
                parameters={"window_id": alert.window_id, "hour_radius": 1},
                expected_information="Adjacent 1-hour behavioral windows for context",
            )
        else:
            # Sufficient evidence gathered; proceed to report generation
            decision = ActionDecision(
                action=ApprovedAction.FINALIZE,
                reason="Sufficient alert, ATT&CK, and RAG evidence collected to perform investigation.",
                parameters={},
                expected_information="Validated final report synthesis",
            )

        # Repeated-action detection safeguard
        act_key = f"{decision.action.value}:{str(sorted(decision.parameters.items()))}"
        if act_key in action_history and decision.action != ApprovedAction.FINALIZE:
            decision = ActionDecision(
                action=ApprovedAction.FINALIZE,
                reason="Detected identical repeated action proposal; halting loop to finalize.",
                parameters={},
                expected_information="Prevented unproductive loop",
            )

        trace = TraceStep(
            node_name="assess_evidence",
            timestamp=now,
            duration_seconds=time.time() - t0,
            status="SUCCESS",
            action_requested=decision.action.value,
            action_approved=decision.action.value,
            summary=decision.reason,
        )

        return {
            **state,
            "iteration_count": iterations,
            "action_history": action_history + [act_key],
            "decision_history": state.get("decision_history", []) + [decision],
            "execution_trace": state.get("execution_trace", []) + [trace.model_dump()],
        }

    def _route_after_assessment(self, state: dict) -> str:
        """Route to tool execution, investigation, or termination based on assessment."""
        status = state.get("current_status")
        if status in (AgentStatus.TIMEOUT, AgentStatus.LIMIT_REACHED, AgentStatus.INVALID_INPUT):
            # If we hit limits or timeout, attempt final report if we have basic context, otherwise finalize
            if state.get("retrieval_context"):
                return "run_investigation"
            return "finalize"

        decisions = state.get("decision_history", [])
        if not decisions:
            return "finalize"

        last_decision: ActionDecision = decisions[-1]
        if last_decision.action == ApprovedAction.FINALIZE:
            return "run_investigation"
        return "dispatch_tool"

    def _node_dispatch_tool(self, state: dict) -> dict:
        """Safely execute requested tool through ToolRegistry and record results."""
        t0 = time.time()
        decisions = state.get("decision_history", [])
        if not decisions:
            return state

        decision: ActionDecision = decisions[-1]
        tool_name = decision.action.value
        tool_count = state.get("tool_call_count", 0) + 1

        exec_record: ToolExecutionRecord = self.tools.execute_tool(
            tool_name=tool_name, parameters=decision.parameters
        )

        retrieval_ctx = state.get("retrieval_context", [])
        attack_ctx = state.get("attack_context", {})
        tool_errors = state.get("tool_errors", [])

        if exec_record.status == "SUCCESS" and exec_record.data:
            if tool_name == "search_knowledge_base":
                retrieval_ctx = exec_record.data.get("chunks", [])
            elif tool_name == "lookup_attack_technique":
                attack_ctx = {**attack_ctx, "verified_technique": exec_record.data.get("data")}
        elif exec_record.error:
            tool_errors.append(f"{tool_name}: {exec_record.error}")

        trace = TraceStep(
            node_name="dispatch_tool",
            timestamp=time.time(),
            duration_seconds=time.time() - t0,
            status=exec_record.status,
            action_requested=tool_name,
            action_approved=tool_name,
            summary=f"Executed {tool_name} with status={exec_record.status}",
            metadata={"duration_s": exec_record.duration_seconds},
        )

        return {
            **state,
            "tool_call_count": tool_count,
            "tool_results": state.get("tool_results", []) + [exec_record.model_dump()],
            "retrieval_context": retrieval_ctx,
            "attack_context": attack_ctx,
            "tool_errors": tool_errors,
            "execution_trace": state.get("execution_trace", []) + [trace.model_dump()],
        }

    def _node_run_investigation(self, state: dict) -> dict:
        """Synthesize final investigation report using verified Phase 6 engine."""
        t0 = time.time()
        orig = state.get("original_alert", {})
        alert = _parse_alert(orig)

        # Retrieve chunks and attack context from state
        chunks = state.get("retrieval_context", [])
        attack_ctx = state.get("attack_context", {})
        rag_status = "success" if chunks else "no_results"
        mock_rag_result = type("MockRag", (), {"status": rag_status, "results": chunks})()

        llm_count = state.get("llm_call_count", 0) + 1
        res = self.investigation_engine.investigate(
            alert=alert,
            retrieval_result=mock_rag_result,
            attack_context=attack_ctx,
        )

        trace = TraceStep(
            node_name="run_investigation",
            timestamp=time.time(),
            duration_seconds=time.time() - t0,
            status=res.status.value,
            summary=f"Synthesized report via Phase 6 engine with status={res.status.value}",
        )

        final_status = (
            AgentStatus.SUCCESS
            if res.status == InvestigationStatus.SUCCESS
            else AgentStatus.INVESTIGATION_ERROR
        )

        return {
            **state,
            "llm_call_count": llm_count,
            "final_report": res.report,
            "current_status": final_status,
            "failure_reason": res.error_message,
            "execution_trace": state.get("execution_trace", []) + [trace.model_dump()],
        }

    def _node_finalize(self, state: dict) -> dict:
        """Finalize and seal investigation result."""
        t0 = time.time()
        if state.get("current_status") == AgentStatus.INVALID_INPUT:
            status = AgentStatus.INVALID_INPUT
        elif state.get("final_report") is not None:
            status = state.get("current_status", AgentStatus.SUCCESS)
        elif state.get("current_status") in (AgentStatus.TIMEOUT, AgentStatus.LIMIT_REACHED):
            status = state["current_status"]
        else:
            status = AgentStatus.INSUFFICIENT_EVIDENCE

        trace = TraceStep(
            node_name="finalize",
            timestamp=time.time(),
            duration_seconds=time.time() - t0,
            status="SUCCESS",
            summary=f"Investigation concluded with final status: {status.value}",
        )
        return {
            **state,
            "current_status": status,
            "execution_trace": state.get("execution_trace", []) + [trace.model_dump()],
        }

    # ---------------------------------------------------------
    # Public Runner Interface
    # ---------------------------------------------------------

    def run_investigation(
        self,
        alert: Any,
        thread_id: Optional[str] = None,
    ) -> InvestigationResult:
        """Execute the LangGraph investigation workflow over an alert."""
        t_start = time.time()
        
        # Guard: Validate input is an authentic SecurityAlert
        if not isinstance(alert, (SecurityAlert, dict)):
            inv_id = "inv_invalid_input"
            return InvestigationResult(
                investigation_id=inv_id,
                status=AgentStatus.INVALID_INPUT,
                final_report=None,
                execution_trace=[
                    TraceStep(
                        node_name="validate_request",
                        timestamp=t_start,
                        duration_seconds=0.001,
                        status="INVALID_INPUT",
                        summary="Rejected input: expected SecurityAlert instance or dictionary.",
                    )
                ],
                tool_results_summary=[],
                llm_call_count=0,
                tool_call_count=0,
                iteration_count=0,
                elapsed_time=0.001,
                warnings=[],
                failure_reason="Invalid alert input type",
            )

        alert_id = getattr(alert, "alert_id", alert.get("alert_id") if isinstance(alert, dict) else "unknown")
        inv_digest = hashlib.sha256(
            f"{alert_id}:{getattr(alert, 'window_id', '')}".encode("utf-8")
        ).hexdigest()[:8]
        inv_id = f"inv_{alert_id}_{inv_digest}"

        initial_state = {
            "investigation_id": inv_id,
            "alert_id": alert_id,
            "original_alert": alert.model_dump() if hasattr(alert, "model_dump") else alert,
            "observed_evidence": [],
            "attack_context": {},
            "retrieval_context": [],
            "tool_results": [],
            "tool_errors": [],
            "action_history": [],
            "decision_history": [],
            "iteration_count": 0,
            "tool_call_count": 0,
            "llm_call_count": 0,
            "started_at": t_start,
            "deadline": t_start + self.config.total_deadline_seconds,
            "current_status": AgentStatus.SUCCESS,
            "final_report": None,
            "warnings": [],
            "failure_reason": None,
            "execution_trace": [],
        }

        cfg_run = {"configurable": {"thread_id": thread_id or inv_id}}
        final_state = self.graph.invoke(initial_state, config=cfg_run)

        elapsed = time.time() - t_start
        tool_summaries = [
            {"tool": tr["tool_name"], "status": tr["status"], "duration": tr["duration_seconds"]}
            for tr in final_state.get("tool_results", [])
        ]

        traces = [TraceStep(**t) for t in final_state.get("execution_trace", [])]

        return InvestigationResult(
            investigation_id=inv_id,
            status=final_state.get("current_status", AgentStatus.INVESTIGATION_ERROR),
            alert_id=alert_id,
            final_report=final_state.get("final_report"),
            execution_trace=traces,
            tool_results_summary=tool_summaries,
            llm_call_count=final_state.get("llm_call_count", 0),
            tool_call_count=final_state.get("tool_call_count", 0),
            iteration_count=final_state.get("iteration_count", 0),
            elapsed_time=elapsed,
            warnings=final_state.get("warnings", []),
            failure_reason=final_state.get("failure_reason"),
        )
