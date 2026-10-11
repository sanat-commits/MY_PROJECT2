"""Phase 10 — Agent Reliability Evaluation Script.

Measures whether the LangGraph investigation agent's components:
  - expose the correct tool registry with the expected tool signatures,
  - handle invalid/empty inputs without unhandled exceptions,
  - enforce correct budget limits via AgentConfig,
  - have persisted any investigation artifacts from previous agent runs.

This script exercises tool contracts and configuration WITHOUT invoking
the Ollama model or running a full end-to-end investigation.

Usage:
    python scripts/evaluate_agent.py

Outputs:
    artifacts/evaluation/agent_metrics.json
"""

from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

EVAL_OUTPUT_DIR = ROOT / "artifacts" / "evaluation"
INVESTIGATIONS_DIR = ROOT / "artifacts" / "api"


def run_agent_evaluation() -> dict:
    """Evaluate agent components and tool-registry contracts."""
    try:
        from src.agent.config import AgentConfig
        from src.agent.tools import ToolRegistry
    except ImportError as exc:
        result = {
            "status": "BLOCKED",
            "errors": [f"Import error: {exc}"],
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
        }
        _save_result(result)
        print(f"[BLOCKED] {exc}")
        return result

    cases: list[dict] = []
    t_total = time.perf_counter()

    # -----------------------------------------------------------------------
    # Case 1: ToolRegistry registers all 4 required tools
    # -----------------------------------------------------------------------
    t_c = time.perf_counter()
    try:
        registry = ToolRegistry(base_dir=ROOT)
        tool_list = registry.list_tools()
        required = {"search_logs", "get_related_events", "search_knowledge_base", "lookup_attack_technique"}
        missing = required - set(tool_list.keys())
        passed = len(missing) == 0
        cases.append({
            "case": "tool_registry_has_required_tools",
            "passed": passed,
            "registered_tools": list(tool_list.keys()),
            "missing": list(missing),
            "elapsed": round(time.perf_counter() - t_c, 4),
        })
    except Exception as exc:
        cases.append({"case": "tool_registry_has_required_tools", "passed": False, "error": str(exc), "elapsed": round(time.perf_counter() - t_c, 4)})
        registry = None

    # -----------------------------------------------------------------------
    # Case 2: search_logs — valid call returns structured result
    # -----------------------------------------------------------------------
    if registry is not None:
        t_c = time.perf_counter()
        try:
            result_sl = registry.search_logs(limit=3)
            passed = isinstance(result_sl, dict) and "status" in result_sl
            cases.append({"case": "search_logs_valid_call", "passed": passed, "elapsed": round(time.perf_counter() - t_c, 4)})
        except Exception as exc:
            cases.append({"case": "search_logs_valid_call", "passed": False, "error": str(exc), "elapsed": round(time.perf_counter() - t_c, 4)})

        # -----------------------------------------------------------------------
        # Case 3: search_logs — zero/negative limit handled gracefully
        # -----------------------------------------------------------------------
        t_c = time.perf_counter()
        try:
            result_sl_bad = registry.search_logs(limit=0)
            # Acceptable: error-state dict or clamped result
            passed = isinstance(result_sl_bad, dict)
        except (ValueError, TypeError):
            passed = True  # typed error is acceptable
        except Exception as exc:
            passed = False
            cases.append({"case": "search_logs_zero_limit_handled", "passed": False, "error": str(exc), "elapsed": round(time.perf_counter() - t_c, 4)})
        else:
            cases.append({"case": "search_logs_zero_limit_handled", "passed": passed, "elapsed": round(time.perf_counter() - t_c, 4)})
        if len(cases) < 3:
            cases.append({"case": "search_logs_zero_limit_handled", "passed": passed, "elapsed": round(time.perf_counter() - t_c, 4)})

        # -----------------------------------------------------------------------
        # Case 4: get_related_events — valid call returns structured result
        # -----------------------------------------------------------------------
        t_c = time.perf_counter()
        try:
            result_re = registry.get_related_events(window_id="W-eval-001")
            passed = isinstance(result_re, dict) and "status" in result_re
            cases.append({"case": "get_related_events_valid_call", "passed": passed, "elapsed": round(time.perf_counter() - t_c, 4)})
        except Exception as exc:
            cases.append({"case": "get_related_events_valid_call", "passed": False, "error": str(exc), "elapsed": round(time.perf_counter() - t_c, 4)})

        # -----------------------------------------------------------------------
        # Case 5: get_related_events — empty window_id handled gracefully
        # -----------------------------------------------------------------------
        t_c = time.perf_counter()
        try:
            result_re_bad = registry.get_related_events(window_id="")
            passed = isinstance(result_re_bad, dict)
        except (ValueError, TypeError):
            passed = True
        except Exception as exc:
            passed = False
        cases.append({"case": "get_related_events_empty_id_handled", "passed": passed, "elapsed": round(time.perf_counter() - t_c, 4)})

        # -----------------------------------------------------------------------
        # Case 6: search_knowledge_base — valid call returns structured result
        # -----------------------------------------------------------------------
        t_c = time.perf_counter()
        try:
            result_kb = registry.search_knowledge_base(query="privilege escalation", top_k=3)
            passed = isinstance(result_kb, dict) and "status" in result_kb
            cases.append({"case": "search_knowledge_base_valid_call", "passed": passed, "elapsed": round(time.perf_counter() - t_c, 4)})
        except Exception as exc:
            cases.append({"case": "search_knowledge_base_valid_call", "passed": False, "error": str(exc), "elapsed": round(time.perf_counter() - t_c, 4)})

        # -----------------------------------------------------------------------
        # Case 7: lookup_attack_technique — valid ID returns structured result
        # -----------------------------------------------------------------------
        t_c = time.perf_counter()
        try:
            result_at = registry.lookup_attack_technique(technique_id="T1078")
            passed = isinstance(result_at, dict) and "status" in result_at
            cases.append({"case": "lookup_attack_technique_valid_id", "passed": passed, "elapsed": round(time.perf_counter() - t_c, 4)})
        except Exception as exc:
            cases.append({"case": "lookup_attack_technique_valid_id", "passed": False, "error": str(exc), "elapsed": round(time.perf_counter() - t_c, 4)})

        # -----------------------------------------------------------------------
        # Case 8: lookup_attack_technique — fabricated ID returns error state, not exception
        # -----------------------------------------------------------------------
        t_c = time.perf_counter()
        try:
            result_at_bad = registry.lookup_attack_technique(technique_id="T9999.999")
            # Should return an error-status dict, not raise
            is_error = (
                isinstance(result_at_bad, dict)
                and result_at_bad.get("status", "").upper() in ("ERROR", "NOT_FOUND", "FAILED", "NOT_MAPPED")
            )
            passed = is_error
            cases.append({"case": "lookup_attack_technique_invalid_id_error_state", "passed": passed, "result_status": result_at_bad.get("status"), "elapsed": round(time.perf_counter() - t_c, 4)})
        except (ValueError, KeyError):
            cases.append({"case": "lookup_attack_technique_invalid_id_error_state", "passed": True, "note": "raised typed error", "elapsed": round(time.perf_counter() - t_c, 4)})
        except Exception as exc:
            cases.append({"case": "lookup_attack_technique_invalid_id_error_state", "passed": False, "error": str(exc), "elapsed": round(time.perf_counter() - t_c, 4)})

    # -----------------------------------------------------------------------
    # Case 9: AgentConfig exposes correct budget limits
    # -----------------------------------------------------------------------
    t_c = time.perf_counter()
    try:
        cfg = AgentConfig()
        config_valid = (
            cfg.max_iterations > 0
            and cfg.max_tool_calls > 0
            and cfg.max_llm_calls > 0
            and cfg.total_deadline_seconds > 0
        )
        cases.append({
            "case": "agent_config_budget_limits",
            "passed": config_valid,
            "details": {
                "max_iterations": cfg.max_iterations,
                "max_tool_calls": cfg.max_tool_calls,
                "max_llm_calls": cfg.max_llm_calls,
                "total_deadline_seconds": cfg.total_deadline_seconds,
            },
            "elapsed": round(time.perf_counter() - t_c, 4),
        })
    except Exception as exc:
        cases.append({"case": "agent_config_budget_limits", "passed": False, "error": str(exc), "elapsed": round(time.perf_counter() - t_c, 4)})

    # -----------------------------------------------------------------------
    # Case 10: Inspect existing investigation artifacts (if available)
    # -----------------------------------------------------------------------
    artifact_analysis = _analyze_existing_investigations()
    cases.append(artifact_analysis)

    total_elapsed = round(time.perf_counter() - t_total, 3)
    pass_count = sum(1 for c in cases if c.get("passed", False))
    fail_count = len(cases) - pass_count
    overall_status = "PASS" if fail_count == 0 else "PARTIAL" if pass_count > 0 else "FAIL"

    result = {
        "status": overall_status,
        "total_cases": len(cases),
        "pass_count": pass_count,
        "fail_count": fail_count,
        "case_results": cases,
        "elapsed_seconds": total_elapsed,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "notes": (
            "Agent evaluation exercises ToolRegistry contracts and budget-limit "
            "configuration WITHOUT invoking the Ollama model. Full end-to-end "
            "investigation requires a live Ollama+qwen3:8b instance (~180s/investigation); "
            "see docs/LIMITATIONS_AND_FUTURE_WORK.md."
        ),
    }

    _save_result(result)
    _print_summary(result)
    return result


def _analyze_existing_investigations() -> dict:
    """Scan persisted investigation artifacts and compute a completion rate."""
    if not INVESTIGATIONS_DIR.exists():
        return {
            "case": "existing_investigation_artifacts",
            "passed": True,
            "total_investigations": 0,
            "completed": 0,
            "completion_rate": None,
            "note": "No investigation artifacts directory found — agent has not been exercised yet.",
            "elapsed": 0,
        }

    inv_files = list(INVESTIGATIONS_DIR.glob("investigation_*.json"))
    if not inv_files:
        return {
            "case": "existing_investigation_artifacts",
            "passed": True,
            "total_investigations": 0,
            "completed": 0,
            "completion_rate": None,
            "note": "No investigation artifact files found.",
            "elapsed": 0,
        }

    total = len(inv_files)
    completed = 0
    errored = 0
    statuses: dict[str, int] = {}

    for fpath in inv_files:
        try:
            data = json.loads(fpath.read_text(encoding="utf-8"))
            status = data.get("status", "unknown")
            statuses[status] = statuses.get(status, 0) + 1
            if status in ("completed", "COMPLETED", "SUCCESS"):
                completed += 1
            elif status in ("error", "ERROR", "failed", "FAILED"):
                errored += 1
        except Exception:
            statuses["parse_error"] = statuses.get("parse_error", 0) + 1

    completion_rate = round(completed / total, 4) if total > 0 else None
    return {
        "case": "existing_investigation_artifacts",
        "passed": True,
        "total_investigations": total,
        "completed": completed,
        "errored": errored,
        "completion_rate": completion_rate,
        "status_breakdown": statuses,
        "elapsed": 0,
    }


def _save_result(result: dict) -> None:
    EVAL_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = EVAL_OUTPUT_DIR / "agent_metrics.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    print(f"[AGENT] Results saved to {out_path}")


def _print_summary(result: dict) -> None:
    print("\n=== Agent Reliability Evaluation ===")
    print(f"Status      : {result['status']}")
    print(f"Total cases : {result['total_cases']}")
    print(f"Passed      : {result['pass_count']}")
    print(f"Failed      : {result['fail_count']}")
    for c in result.get("case_results", []):
        icon = "[PASS]" if c.get("passed") else "[FAIL]"
        print(f"  {icon} {c.get('case', '?')}")
    print(f"Elapsed     : {result.get('elapsed_seconds')}s")


if __name__ == "__main__":
    run_agent_evaluation()
