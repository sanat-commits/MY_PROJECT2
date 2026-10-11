"""Phase 10 — Structured Output Validation Evaluation Script.

Tests that the Phase 6/7 LLM output validator (ReportValidator) correctly:
  - accepts well-formed investigation reports,
  - fills in sensible defaults for missing optional fields,
  - filters ATT&CK technique IDs not present in the supplied Phase 4 context,
  - verifies citations against supplied RAG chunk IDs.

This test runs WITHOUT the Ollama model — it only exercises the deterministic
ReportValidator layer using synthetic input fixtures.

Usage:
    python scripts/evaluate_structured_output.py

Outputs:
    artifacts/evaluation/structured_output_metrics.json
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


def _make_inv_input(
    extra_techniques: list[str] | None = None,
    extra_chunks: list[dict] | None = None,
) :
    """Build a minimal InvestigationInput fixture."""
    from src.llm.schemas import InvestigationInput
    from src.risk_scoring.schema import SeverityLevel

    return InvestigationInput(
        investigation_id="eval-001",
        alert_id="A-eval-001",
        window_id="W-eval-001",
        anomaly_score=0.72,
        is_anomaly=True,
        risk_score=78.5,
        severity=SeverityLevel.HIGH,
        evidence_items=[],
        score_breakdown={},
        mitre_status="mapped",
        mitre_candidate_techniques=[
            {"technique_id": t} for t in (extra_techniques or ["T1548", "T1078"])
        ],
        rag_chunks=extra_chunks or [
            {
                "chunk_id": "chunk-abc123",
                "source_id": "src-mitre-v14",
                "source_title": "MITRE ATT&CK Enterprise v14",
                "source_uri_or_path": "data/mitre/enterprise-attack.json",
                "document_title": "Privilege Escalation",
            }
        ],
        rag_status="success",
    )


def run_structured_output_evaluation() -> dict:
    """Exercise the deterministic validation gate without running the model."""
    try:
        from src.llm.output_validation import ReportValidator, OutputValidationError
    except ImportError as exc:
        result = {
            "status": "BLOCKED",
            "errors": [f"Import error: {exc}"],
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
        }
        _save_result(result)
        print(f"[BLOCKED] {exc}")
        return result

    validator = ReportValidator(strict_mode=True)

    # --- Test fixtures ---
    VALID_REPORT_RAW = json.dumps({
        "summary": "Elevated privilege escalation behaviour observed in synthetic window W-001.",
        "finding": "ANOMALOUS_ACTIVITY",
        "observed_evidence": [
            {
                "field_name": "privilege_escalation_events",
                "observed_value": 14,
                "description": "Above 99th-percentile threshold.",
            }
        ],
        "interpretation": "The isolation forest scored this window anomalous (score=0.72).",
        "possible_attack_techniques": ["T1548"],
        "uncertainty": "Synthetic data only. An anomaly is not proof of compromise.",
        "recommended_next_steps": ["Review authentication logs."],
        "citations": [{"chunk_id": "chunk-abc123"}],
        "limitations": ["Synthetic data only."],
    })

    MISSING_TECHNIQUES = json.dumps({
        "summary": "Summary present.",
        "finding": "SUSPICIOUS_ACTIVITY",
        "interpretation": "Interpretation present.",
        "uncertainty": "Uncertainty acknowledged.",
        "recommended_next_steps": ["Check logs."],
        # possible_attack_techniques absent — validator should default to []
    })

    FABRICATED_TECHNIQUE = json.dumps({
        "summary": "Summary present.",
        "finding": "POSSIBLE_ATTACK",
        "interpretation": "Interpretation.",
        "uncertainty": "Uncertain.",
        "recommended_next_steps": ["Investigate."],
        "possible_attack_techniques": ["T9999.999"],  # not in mitre_candidate_techniques
    })

    FABRICATED_CITATION = json.dumps({
        "summary": "Summary.",
        "finding": "ANOMALOUS_ACTIVITY",
        "interpretation": "Interpretation.",
        "uncertainty": "Uncertain.",
        "recommended_next_steps": ["Check."],
        "citations": [{"chunk_id": "chunk-FABRICATED-999"}],  # not in rag_chunks
    })

    NOT_JSON = "This is plain English, not JSON at all."

    cases: list[dict] = []
    t0 = time.perf_counter()

    # Case 1: valid report — should parse and produce a report
    t_c = time.perf_counter()
    try:
        inv = _make_inv_input()
        report = validator.validate(VALID_REPORT_RAW, inv)
        passed = (
            report is not None
            and report.summary != ""
            and report.investigation_id == "eval-001"
            and report.alert_id == "A-eval-001"
        )
    except Exception as exc:
        passed = False
        cases.append({"case": "valid_report", "passed": False, "error": str(exc), "elapsed": round(time.perf_counter() - t_c, 4)})
    else:
        cases.append({"case": "valid_report", "passed": passed, "elapsed": round(time.perf_counter() - t_c, 4)})

    # Case 2: missing techniques — should produce report with empty techniques list
    t_c = time.perf_counter()
    try:
        inv = _make_inv_input()
        report = validator.validate(MISSING_TECHNIQUES, inv)
        passed = report is not None and report.possible_attack_techniques == []
    except Exception as exc:
        passed = False
        cases.append({"case": "missing_techniques_defaults_empty", "passed": False, "error": str(exc), "elapsed": round(time.perf_counter() - t_c, 4)})
    else:
        cases.append({"case": "missing_techniques_defaults_empty", "passed": passed, "elapsed": round(time.perf_counter() - t_c, 4)})

    # Case 3: fabricated technique — should be stripped because T9999.999 not in allowed list
    t_c = time.perf_counter()
    try:
        inv = _make_inv_input()  # candidate_techniques = [T1548, T1078]
        report = validator.validate(FABRICATED_TECHNIQUE, inv)
        fabricated_stripped = "T9999.999" not in report.possible_attack_techniques
        passed = fabricated_stripped
    except Exception as exc:
        passed = False
        cases.append({"case": "fabricated_technique_stripped", "passed": False, "error": str(exc), "elapsed": round(time.perf_counter() - t_c, 4)})
    else:
        cases.append({"case": "fabricated_technique_stripped", "passed": passed, "elapsed": round(time.perf_counter() - t_c, 4)})

    # Case 4: fabricated citation — chunk_id not in rag_chunks, so citations should be empty
    t_c = time.perf_counter()
    try:
        inv = _make_inv_input()
        report = validator.validate(FABRICATED_CITATION, inv)
        passed = report.citations == []
    except Exception as exc:
        passed = False
        cases.append({"case": "fabricated_citation_stripped", "passed": False, "error": str(exc), "elapsed": round(time.perf_counter() - t_c, 4)})
    else:
        cases.append({"case": "fabricated_citation_stripped", "passed": passed, "elapsed": round(time.perf_counter() - t_c, 4)})

    # Case 5: non-JSON input — should raise OutputValidationError
    t_c = time.perf_counter()
    try:
        inv = _make_inv_input()
        validator.validate(NOT_JSON, inv)
        passed = False  # should have raised
    except OutputValidationError:
        passed = True
    except Exception as exc:
        passed = False
        cases.append({"case": "non_json_raises_error", "passed": False, "error": str(exc), "elapsed": round(time.perf_counter() - t_c, 4)})
    else:
        cases.append({"case": "non_json_raises_error", "passed": passed, "elapsed": round(time.perf_counter() - t_c, 4)})
    if len(cases) < 5:  # append if not already appended via except
        cases.append({"case": "non_json_raises_error", "passed": passed, "elapsed": round(time.perf_counter() - t_c, 4)})

    # Case 6: application-owned fields preserved (alert_id, investigation_id not mutated)
    t_c = time.perf_counter()
    try:
        inv = _make_inv_input()
        mutating_report = json.dumps({
            "investigation_id": "HACKED-ID",
            "alert_id": "HACKED-ALERT",
            "summary": "Attempt to override application-owned IDs.",
            "finding": "ANOMALOUS_ACTIVITY",
            "interpretation": "Interpretation.",
            "uncertainty": "Uncertain.",
            "recommended_next_steps": ["Check."],
        })
        report = validator.validate(mutating_report, inv)
        passed = (
            report.investigation_id == "eval-001"  # original preserved
            and report.alert_id == "A-eval-001"  # original preserved
        )
    except Exception as exc:
        passed = False
        cases.append({"case": "application_owned_fields_immutable", "passed": False, "error": str(exc), "elapsed": round(time.perf_counter() - t_c, 4)})
    else:
        cases.append({"case": "application_owned_fields_immutable", "passed": passed, "elapsed": round(time.perf_counter() - t_c, 4)})

    elapsed = round(time.perf_counter() - t0, 3)
    pass_count = sum(1 for c in cases if c.get("passed", False))
    fail_count = len(cases) - pass_count
    overall_status = "PASS" if fail_count == 0 else "FAIL"

    result = {
        "status": overall_status,
        "total_cases": len(cases),
        "pass_count": pass_count,
        "fail_count": fail_count,
        "case_results": cases,
        "elapsed_seconds": elapsed,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "notes": (
            "This evaluation tests the deterministic ReportValidator layer only. "
            "The Ollama model is NOT invoked. Schema rejection, technique-ID filtering, "
            "citation verification, and immutability of application-owned fields are "
            "exercised using synthetic fixtures."
        ),
    }

    _save_result(result)
    _print_summary(result)
    return result


def _save_result(result: dict) -> None:
    EVAL_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = EVAL_OUTPUT_DIR / "structured_output_metrics.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    print(f"[STRUCTURED OUTPUT] Results saved to {out_path}")


def _print_summary(result: dict) -> None:
    print("\n=== Structured Output Validation Evaluation ===")
    print(f"Status      : {result['status']}")
    print(f"Total cases : {result['total_cases']}")
    print(f"Passed      : {result['pass_count']}")
    print(f"Failed      : {result['fail_count']}")
    for cr in result.get("case_results", []):
        icon = "PASS" if cr.get("passed") else "FAIL"
        err = f" -- {cr['error']}" if not cr.get("passed") and cr.get("error") else ""
        print(f"  [{icon}] {cr['case']}{err}")
    print(f"Elapsed     : {result.get('elapsed_seconds')}s")


if __name__ == "__main__":
    run_structured_output_evaluation()
