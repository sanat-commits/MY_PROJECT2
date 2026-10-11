"""Phase 10 — API/Frontend Evaluation Script.

Verifies that the FastAPI backend's publicly documented endpoints respond
correctly and within acceptable latency budgets.

Assumes the backend is running on http://127.0.0.1:8000 (default binding).
If the backend is not available, this script records BLOCKED rather than
fabricating success.

Usage:
    python scripts/evaluate_api.py [--base-url http://127.0.0.1:8000]

Outputs:
    artifacts/evaluation/api_metrics.json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

EVAL_OUTPUT_DIR = ROOT / "artifacts" / "evaluation"

# Acceptable response latency in seconds (P95 budget)
LATENCY_BUDGET_SECONDS = 5.0


def run_api_evaluation(base_url: str = "http://127.0.0.1:8000") -> dict:
    """Run API endpoint evaluation against a live backend."""
    try:
        import httpx
    except ImportError:
        result = {
            "status": "BLOCKED",
            "errors": ["httpx not installed — run: pip install httpx"],
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
        }
        _save_result(result)
        print("[BLOCKED] httpx not installed.")
        return result

    # First check if backend is reachable
    try:
        with httpx.Client(timeout=5.0) as client:
            r = client.get(f"{base_url}/health")
            r.raise_for_status()
    except Exception as exc:
        result = {
            "status": "BLOCKED",
            "errors": [
                f"Backend not reachable at {base_url}: {exc}",
                "Start the backend with: uvicorn src.api.app:app --host 127.0.0.1 --port 8000",
            ],
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
        }
        _save_result(result)
        print(f"[BLOCKED] Backend not reachable at {base_url}")
        print("  Start the backend with: uvicorn src.api.app:app --host 127.0.0.1 --port 8000")
        return result

    # Define endpoint test cases
    test_cases = [
        {
            "name": "GET /health",
            "method": "GET",
            "path": "/health",
            "expected_status": 200,
            "expected_keys": ["status"],
        },
        {
            "name": "GET /ready",
            "method": "GET",
            "path": "/ready",
            "expected_status": [200, 503],  # 503 acceptable if subsystems degraded
            "expected_keys": [],
        },
        {
            "name": "GET /status/model",
            "method": "GET",
            "path": "/status/model",
            "expected_status": [200, 503],
            "expected_keys": [],
        },
        {
            "name": "GET /alerts (default pagination)",
            "method": "GET",
            "path": "/alerts",
            "expected_status": 200,
            "expected_keys": ["alerts", "total"],
        },
        {
            "name": "GET /alerts?limit=5&offset=0",
            "method": "GET",
            "path": "/alerts?limit=5&offset=0",
            "expected_status": 200,
            "expected_keys": ["alerts"],
        },
        {
            "name": "GET /alerts?severity=HIGH",
            "method": "GET",
            "path": "/alerts?severity=HIGH",
            "expected_status": 200,
            "expected_keys": ["alerts"],
        },
        {
            "name": "GET /alerts/nonexistent-id (404)",
            "method": "GET",
            "path": "/alerts/nonexistent-alert-id-eval",
            "expected_status": 404,
            "expected_keys": [],
        },
        {
            "name": "GET /investigations (default pagination)",
            "method": "GET",
            "path": "/investigations",
            "expected_status": 200,
            "expected_keys": [],
        },
    ]

    results: list[dict] = []
    latencies: list[float] = []
    pass_count = 0
    fail_count = 0

    t_total = time.perf_counter()
    with httpx.Client(timeout=LATENCY_BUDGET_SECONDS + 5.0, base_url=base_url) as client:
        for tc in test_cases:
            t0 = time.perf_counter()
            try:
                if tc["method"] == "GET":
                    resp = client.get(tc["path"])
                else:
                    resp = client.request(tc["method"], tc["path"])

                latency = round(time.perf_counter() - t0, 4)
                latencies.append(latency)

                expected_statuses = (
                    tc["expected_status"]
                    if isinstance(tc["expected_status"], list)
                    else [tc["expected_status"]]
                )
                status_ok = resp.status_code in expected_statuses
                keys_ok = True
                missing_keys: list[str] = []
                if tc.get("expected_keys"):
                    try:
                        body = resp.json()
                        for key in tc["expected_keys"]:
                            if key not in body:
                                keys_ok = False
                                missing_keys.append(key)
                    except Exception:
                        keys_ok = False
                        missing_keys = ["<json_parse_error>"]

                within_budget = latency <= LATENCY_BUDGET_SECONDS
                passed = status_ok and keys_ok and within_budget

                case_res: dict[str, Any] = {
                    "name": tc["name"],
                    "passed": passed,
                    "http_status": resp.status_code,
                    "expected_status": tc["expected_status"],
                    "status_ok": status_ok,
                    "keys_ok": keys_ok,
                    "latency_seconds": latency,
                    "within_budget": within_budget,
                }
                if missing_keys:
                    case_res["missing_keys"] = missing_keys

            except Exception as exc:
                latency = round(time.perf_counter() - t0, 4)
                latencies.append(latency)
                passed = False
                case_res = {
                    "name": tc["name"],
                    "passed": False,
                    "error": str(exc),
                    "latency_seconds": latency,
                }

            if passed:
                pass_count += 1
            else:
                fail_count += 1

            results.append(case_res)

    total_elapsed = round(time.perf_counter() - t_total, 3)
    avg_latency = round(sum(latencies) / len(latencies), 4) if latencies else None
    p95_latency = round(sorted(latencies)[int(len(latencies) * 0.95)] if len(latencies) >= 2 else (latencies[0] if latencies else 0), 4)

    overall_status = "PASS" if fail_count == 0 else "PARTIAL" if pass_count > 0 else "FAIL"

    result = {
        "status": overall_status,
        "base_url": base_url,
        "total_cases": len(results),
        "pass_count": pass_count,
        "fail_count": fail_count,
        "latency_budget_seconds": LATENCY_BUDGET_SECONDS,
        "avg_latency_seconds": avg_latency,
        "p95_latency_seconds": p95_latency,
        "endpoint_results": results,
        "elapsed_seconds": total_elapsed,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "notes": (
            "Latency budget excludes the POST /alerts/{id}/investigate endpoint "
            "which requires ~180s for local Qwen 3 8B inference. "
            "Investigation endpoint latency is documented in LIMITATIONS_AND_FUTURE_WORK.md."
        ),
    }

    _save_result(result)
    _print_summary(result)
    return result


def _save_result(result: dict) -> None:
    EVAL_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = EVAL_OUTPUT_DIR / "api_metrics.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    print(f"[API] Results saved to {out_path}")


def _print_summary(result: dict) -> None:
    print("\n=== API/Frontend Evaluation Summary ===")
    print(f"Status          : {result['status']}")
    print(f"Total cases     : {result['total_cases']}")
    print(f"Passed          : {result['pass_count']}")
    print(f"Failed          : {result['fail_count']}")
    print(f"Avg latency     : {result.get('avg_latency_seconds')}s")
    print(f"P95 latency     : {result.get('p95_latency_seconds')}s")
    for ep in result.get("endpoint_results", []):
        icon = "✓" if ep["passed"] else "✗"
        lat = ep.get("latency_seconds", "?")
        code = ep.get("http_status", "?")
        print(f"  {icon} {ep['name']} — HTTP {code} ({lat}s)")
    print(f"Elapsed         : {result.get('elapsed_seconds')}s")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate FastAPI backend endpoints.")
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:8000",
        help="Backend base URL (default: http://127.0.0.1:8000)",
    )
    args = parser.parse_args()
    run_api_evaluation(base_url=args.base_url)
