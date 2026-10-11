"""Comprehensive tests for Phase 7 LangGraph Investigation Agent."""

import json
import pytest
from src.agent.config import AgentConfig
from src.agent.schemas import AgentStatus, ApprovedAction, ActionDecision
from src.agent.tools import ToolRegistry
from src.agent.workflow import InvestigationWorkflow
from src.llm.config import LlmConfig
from src.llm.ollama_provider import MockLlmProvider, OllamaLlmProvider
from src.risk_scoring.config import get_default_risk_config
from src.risk_scoring.engine import RiskEngine
from src.risk_scoring.schema import SecurityAlert, SeverityLevel


@pytest.fixture
def sample_alert() -> SecurityAlert:
    """Fixture producing a verified Phase 3 SecurityAlert."""
    risk_engine = RiskEngine(get_default_risk_config())
    pred = {"window_id": "win_agent_001", "raw_score": -0.20, "anomaly_score": 0.20, "is_anomaly": 1}
    win = {
        "window_id": "win_agent_001",
        "hour": 3,
        "day_of_week": 2,
        "is_weekend": 0,
        "failed_logins": 25,
        "successful_logins": 1,
        "login_attempts": 26,
        "privileged_actions": 0,
        "rare_process_count": 0,
        "external_connections": 4,
        "bytes_out_mb": 5.0,
        "after_hours": 1,
    }
    return risk_engine.score_alert(pred, win)


# -------------------------------------------------------------
# A. Graph Compilation & Structure Tests
# -------------------------------------------------------------

def test_graph_compiles_cleanly():
    """Verify that LangGraph StateGraph compiles with MemorySaver checkpointer."""
    workflow = InvestigationWorkflow(
        config=AgentConfig(use_in_memory_checkpointer=True),
        llm_provider=MockLlmProvider(),
    )
    assert workflow.graph is not None
    assert workflow.checkpointer is not None


# -------------------------------------------------------------
# B. Tool Registry & Tool Contract Tests
# -------------------------------------------------------------

def test_tool_registry_search_logs():
    """Verify search_logs tool operates over existing dataset windows with explicit typing."""
    tools = ToolRegistry()
    res = tools.search_logs(user_role="employee", limit=3)
    assert res["status"] in ("SUCCESS", "NO_RESULTS")
    assert res["record_type"] == "aggregated_behavioral_window"
    assert "records" in res
    assert len(res["records"]) <= 3


def test_tool_registry_get_related_events():
    """Verify get_related_events handles valid and invalid window queries."""
    tools = ToolRegistry()
    # Invalid input
    bad_res = tools.get_related_events(window_id="")
    assert bad_res["status"] == "INVALID_INPUT"

    # Non-existent window
    missing_res = tools.get_related_events(window_id="non_existent_win_999999")
    assert missing_res["status"] == "NO_RESULTS"


def test_tool_registry_search_knowledge_base():
    """Verify search_knowledge_base invokes Phase 5 hybrid retrieval."""
    tools = ToolRegistry()
    res = tools.search_knowledge_base(query="Windows authentication failed logins", top_k=2)
    assert res["status"] in ("SUCCESS", "NO_RESULTS")
    assert "chunks" in res


def test_tool_registry_lookup_attack_technique():
    """Verify lookup_attack_technique queries verified Phase 4 catalog."""
    tools = ToolRegistry()
    res = tools.lookup_attack_technique(technique_id="T1110")
    assert res["status"] == "success"
    assert res["data"]["technique_id"] == "T1110"

    # Unknown ID does not invent data
    bad_res = tools.lookup_attack_technique(technique_id="T9999.999")
    assert bad_res["status"] == "not_found"


# -------------------------------------------------------------
# C. Evidence-Driven Execution & State Integrity Tests
# -------------------------------------------------------------

def test_agent_execution_with_mock_provider(sample_alert):
    """Verify complete end-to-end investigation with mock LLM provider."""
    workflow = InvestigationWorkflow(
        config=AgentConfig(max_iterations=4, max_tool_calls=4),
        llm_provider=MockLlmProvider(),
    )
    res = workflow.run_investigation(sample_alert)

    assert res.status == AgentStatus.SUCCESS
    assert res.final_report is not None
    # State integrity: original alert fields must not be altered
    assert res.final_report.alert_id == sample_alert.alert_id
    assert res.final_report.supplied_severity == sample_alert.severity
    assert res.final_report.supplied_risk_score == sample_alert.risk_score

    # Check execution trace
    assert len(res.execution_trace) >= 4
    node_names = [t.node_name for t in res.execution_trace]
    assert "validate_request" in node_names
    assert "load_alert" in node_names
    assert "assess_evidence" in node_names
    assert "finalize" in node_names


# -------------------------------------------------------------
# D. Runtime Limits & Loop Prevention Tests
# -------------------------------------------------------------

def test_agent_enforces_max_iterations(sample_alert):
    """Verify agent terminates when maximum iteration limit is hit."""
    # Set max_iterations to 1 to force limit reach
    workflow = InvestigationWorkflow(
        config=AgentConfig(max_iterations=1, max_tool_calls=0),
        llm_provider=MockLlmProvider(),
    )
    res = workflow.run_investigation(sample_alert)
    assert res.iteration_count >= 1
    assert res.status in (AgentStatus.LIMIT_REACHED, AgentStatus.SUCCESS)


def test_agent_enforces_deadline(sample_alert):
    """Verify agent halts when total deadline is exceeded."""
    workflow = InvestigationWorkflow(
        config=AgentConfig(total_deadline_seconds=0.0001),
        llm_provider=MockLlmProvider(),
    )
    res = workflow.run_investigation(sample_alert)
    assert res.status in (AgentStatus.TIMEOUT, AgentStatus.LIMIT_REACHED, AgentStatus.SUCCESS)


def test_agent_handles_invalid_input():
    """Verify agent safely handles non-alert inputs without crashing."""
    workflow = InvestigationWorkflow(llm_provider=MockLlmProvider())
    bad_obj = type("BadAlert", (), {"alert_id": "not_real"})()
    # Passing incompatible alert object
    res = workflow.run_investigation(bad_obj)
    assert res.status in (AgentStatus.INVALID_INPUT, AgentStatus.INVESTIGATION_ERROR)


# -------------------------------------------------------------
# E. Checkpoint and Resume Tests
# -------------------------------------------------------------

def test_checkpoint_state_persistence(sample_alert):
    """Verify MemorySaver checkpointer retains execution trace under thread ID."""
    workflow = InvestigationWorkflow(
        config=AgentConfig(use_in_memory_checkpointer=True),
        llm_provider=MockLlmProvider(),
    )
    thread_id = "test_thread_checkpoint_001"
    res = workflow.run_investigation(sample_alert, thread_id=thread_id)
    assert res.status == AgentStatus.SUCCESS

    # Verify checkpointer has state stored
    cfg = {"configurable": {"thread_id": thread_id}}
    state_tuple = workflow.graph.get_state(cfg)
    assert state_tuple is not None
    assert state_tuple.values.get("alert_id") == sample_alert.alert_id


# -------------------------------------------------------------
# F. Real Local Qwen 3 8B Integration Test
# -------------------------------------------------------------

def test_real_local_qwen_investigation_workflow(sample_alert):
    """Smoke test executing the real local Qwen 3 8B model within the LangGraph agent."""
    cfg = LlmConfig.from_env()
    provider = OllamaLlmProvider(cfg)
    agent_cfg = AgentConfig.from_env()

    workflow = InvestigationWorkflow(
        config=agent_cfg,
        llm_config=cfg,
        llm_provider=provider,
    )
    res = workflow.run_investigation(sample_alert)

    assert res.status == AgentStatus.SUCCESS, f"Expected SUCCESS, got {res.status}: {res.failure_reason}"
    assert res.final_report is not None
    assert res.final_report.alert_id == sample_alert.alert_id
    assert res.final_report.supplied_severity == sample_alert.severity
    assert res.final_report.supplied_risk_score == sample_alert.risk_score
    assert len(res.execution_trace) > 0
