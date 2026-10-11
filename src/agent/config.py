"""Agent configuration and runtime limits for Phase 7 LangGraph Investigation Agent."""

import os
from pydantic import BaseModel, Field


class AgentConfig(BaseModel):
    """Configurable runtime boundaries, timeouts, and iteration limits."""

    max_iterations: int = Field(
        default=4,
        ge=1,
        le=10,
        description="Maximum cycles through the LangGraph assessment/action loop.",
    )
    max_tool_calls: int = Field(
        default=4,
        ge=0,
        le=15,
        description="Maximum total tool executions permitted per investigation.",
    )
    max_llm_calls: int = Field(
        default=3,
        ge=0,
        le=6,
        description="Maximum planning/decision/analysis LLM calls per investigation.",
    )
    total_deadline_seconds: float = Field(
        default=300.0,
        ge=0.0,
        le=900.0,
        description="Global investigation timeout deadline across all nodes.",
    )
    per_call_timeout_seconds: float = Field(
        default=120.0,
        ge=5.0,
        le=600.0,
        description="Per-node or per-call timeout limit.",
    )
    checkpoint_enabled: bool = Field(
        default=True,
        description="Enable persistent or in-memory LangGraph checkpointer.",
    )
    use_in_memory_checkpointer: bool = Field(
        default=True,
        description="Use MemorySaver checkpointer for state transitions.",
    )
    allow_llm_action_selection: bool = Field(
        default=False,
        description="If True, queries Qwen for action decision; if False, uses deterministic evidence assessment to avoid latency bottlenecks.",
    )

    @classmethod
    def from_env(cls) -> "AgentConfig":
        """Load agent configuration from environment variables with safe defaults."""
        return cls(
            max_iterations=int(os.getenv("AGENT_MAX_ITERATIONS", "4")),
            max_tool_calls=int(os.getenv("AGENT_MAX_TOOL_CALLS", "4")),
            max_llm_calls=int(os.getenv("AGENT_MAX_LLM_CALLS", "3")),
            total_deadline_seconds=float(os.getenv("AGENT_TOTAL_DEADLINE_SECONDS", "300.0")),
            per_call_timeout_seconds=float(os.getenv("AGENT_PER_CALL_TIMEOUT_SECONDS", "120.0")),
            checkpoint_enabled=os.getenv("AGENT_CHECKPOINT_ENABLED", "true").lower() in ("true", "1", "yes"),
            use_in_memory_checkpointer=os.getenv("AGENT_USE_IN_MEMORY_CHECKPOINTER", "true").lower() in ("true", "1", "yes"),
            allow_llm_action_selection=os.getenv("AGENT_ALLOW_LLM_ACTION_SELECTION", "false").lower() in ("true", "1", "yes"),
        )
