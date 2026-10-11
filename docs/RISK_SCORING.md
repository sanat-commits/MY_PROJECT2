# Explainable Risk Scoring Specification (Phase 3)

> **Cybersecurity Truthfulness Notice**:
> The risk-scoring engine operates on statistical telemetry and synthetic behavioral observation windows. An anomaly is **not** proof of a cyberattack, nor does a risk score represent a calibrated probability of compromise.
> Risk scores are operational prioritization heuristics designed to order SOC analyst attention based on observable deviations from learned baselines and configured risk indicators.

---

## 1. Objective & Role in Architecture

Phase 2 tells us whether a behavioral observation window deviates from normal baseline traffic (`anomaly_score > threshold`).

Phase 3 transforms that statistical prediction into an **explainable, structured security alert** featuring:
- A transparent, bounded priority score ($0.0 \le \text{risk\_score} \le 100.0$),
- Verifiable evidence grounded exclusively in observed input fields,
- An exact mathematical score breakdown reconciling every contribution,
- Configured operational severity classification (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`),
- A critical-alert safeguard preventing uncorroborated single-signal escalation.

Pipeline:
```text
Validated Security Window
          ↓
Phase 2 ML Prediction (Anomaly Score & Binary Decision)
          ↓
Extract Verifiable Evidence (EvidenceExtractor)
          ↓
Evaluate Configured Risk Signals (RiskScoreCalculator)
          ↓
Calculate Bounded Risk Score (Reconciled Score Breakdown)
          ↓
Assign Operational Severity (SeverityClassifier + Safeguard)
          ↓
Generate Structured Alert (SecurityAlert Contract)
```

---

## 2. Distinction Between Detection, Risk, and Severity

In this architecture, detection, risk, and severity are strictly separated:

| Concept | Question Answered | Metric / Type | Meaning |
|---|---|---|---|
| **Anomaly Detection** | *Does this activity deviate from learned normal behavior?* | `anomaly_score` (float), `is_anomaly` (binary) | Distance from Isolation Forest normal hyperplane; statistical outlier identification. |
| **Risk Scoring** | *How should SOC analysts prioritize investigating this activity?* | `risk_score` (float, $0.0 - 100.0$) | Weighted operational synthesis of anomaly intensity and corroborating behavioral indicators. |
| **Severity** | *Which operational response queue should handle this alert?* | `severity` (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) | Prioritization band mapping with safeguarding against uncorroborated escalation. |

**Important**: A high anomaly score does not automatically imply malicious intent, and a low score does not guarantee safety.

---

## 3. Scoring Formula & Component Definitions

The scoring design allocates points across two primary pillars summing to 100.0 points:
1. **Machine Learning Anomaly Signal**: Up to $40.0$ points.
2. **Behavioral Risk Indicators**: Up to $60.0$ points.

### A. Machine Learning Anomaly Component ($W_{\text{ml}} = 40.0$)

The Phase 2 baseline detector produces:
- `raw_score`: `decision_function(X)` (higher is normal, lower anomalous).
- `anomaly_score`: `-raw_score` (higher is anomalous).
- `threshold`: $95.0\text{th}$ percentile of normal training scores ($0.041169$).

Contribution Formula:
- **Nominal Normal** ($\text{anomaly\_score} \le 0.0$):
  $$\text{contribution} = 0.0$$
- **Sub-Threshold Deviation** ($0.0 < \text{anomaly\_score} \le \text{threshold}$):
  $$\text{scale} = 0.25 \times \frac{\text{anomaly\_score}}{\text{threshold}}$$
  $$\text{contribution} = \text{round}(W_{\text{ml}} \times \text{scale}, 2)$$
- **Supra-Threshold Anomaly** ($\text{anomaly\_score} > \text{threshold}$):
  $$\text{excess} = \min\left(1.0, \max\left(0.0, \frac{\text{anomaly\_score} - \text{threshold}}{\text{max\_expected} - \text{threshold}}\right)\right)$$
  $$\text{scale} = 0.25 + 0.75 \times \text{excess}$$
  $$\text{contribution} = \text{round}(W_{\text{ml}} \times \text{scale}, 2)$$
  *(where $\text{max\_expected} = 0.20$ represents the empirical upper ceiling of evaluation anomalies).*

### B. Behavioral Risk Indicators ($W_{\text{behavioral}} = 60.0$)

Each behavioral signal specifies:
- `baseline_threshold`: The $99.0\text{th}$ percentile calculated directly from normal-only training data (`security_windows_train_normal.csv`), ensuring that $99\%$ of normal traffic contributes $0$ points.
- `saturation_threshold`: The empirical point where full weight contribution is attained.

| Signal Name | Source Field | Operator | Baseline ($p_{99}$) | Saturation | Weight | Rationale |
|---|---|---|---|---|---|---|
| `failed_login_burst` | `failed_logins` | `gt` | $3.0$ | $40.0$ | $15.0$ | Authentication stress / repeated failure spike |
| `elevated_privileged_actions` | `privileged_actions` | `gt` | $2.0$ | $10.0$ | $10.0$ | Elevated execution and administrative action burst |
| `rare_process_execution` | `rare_process_count` | `gt` | $1.0$ | $15.0$ | $10.0$ | Atypical binary or command execution |
| `excessive_external_connections` | `external_connections` | `gt` | $19.0$ | $60.0$ | $10.0$ | Egress perimeter connection spike |
| `high_volume_data_egress` | `bytes_out_mb` | `gt` | $26.9$ MB | $1000.0$ MB | $10.0$ | High-volume outbound data transfer |
| `off_hours_activity` | `after_hours` | `eq` | $1.0$ | $1.0$ | $5.0$ | Activity outside approved operational schedule |

For numeric signals (`gt`):
$$\text{scale} = \min\left(1.0, \max\left(0.0, \frac{\text{observed} - \text{baseline}}{\text{saturation} - \text{baseline}}\right)\right) \quad (\text{if observed} > \text{baseline}, \text{else } 0.0)$$
$$\text{contribution} = \text{round}(\text{weight} \times \text{scale}, 2)$$

For exact match signals (`eq`):
$$\text{contribution} = \text{weight} \quad (\text{if observed} == \text{baseline}, \text{else } 0.0)$$

### C. Total Risk Score & Breakdown Reconciliation

$$\text{raw\_total} = \text{contribution}_{\text{ml}} + \sum_{i} \text{contribution}_{\text{behavioral}, i}$$
$$\text{risk\_score} = \text{round}(\min(100.0, \max(0.0, \text{raw\_total})), 2)$$

Every alert generates a `ScoreBreakdown` audit object. The absolute difference between the sum of contributions and `risk_score` is tracked as `rounding_difference`. The score is formally certified as `reconciled` if $\text{rounding\_difference} \le 0.01$.

---

## 4. Severity Bands & Critical-Alert Safeguard

### Severity Bands
Bands are defined in `SeverityBandConfig` as operational prioritization heuristics:
- **`LOW`**: $[0.0, 30.0)$
- **`MEDIUM`**: $[30.0, 60.0)$
- **`HIGH`**: $[60.0, 80.0)$
- **`CRITICAL`**: $[80.0, 100.0]$

Boundary points ($0.0$, $29.99$, $30.0$, $59.99$, $60.0$, $79.99$, $80.0$, $100.0$) are deterministic and map to exactly one severity band.

### Critical-Alert Safeguard
In enterprise Security Operations Centers (SOCs), uncorroborated anomalies must not trigger critical pages without observable behavioral evidence.

- When `critical_safeguard.enabled = True`:
  - An alert with $\text{risk\_score} \ge 80.0$ requires at least `min_corroborating_signals` (default: 1) behavioral evidence signals with positive contribution.
  - If zero corroborating behavioral signals are observed, the alert is automatically downgraded from `CRITICAL` to `HIGH`.
  - The alert records `critical_safeguard_applied = True` and an explanatory `safeguard_note`.

---

## 5. Handling Missing Evidence & Telemetry

When an expected telemetry field is omitted or contains null values in the source observation window:
- Under the default policy (`missing_evidence_policy = "zero_with_audit"`):
  - The component receives $0.0$ contribution points.
  - The component status in `score_breakdown` is explicitly marked as `"missing_evidence"`.
  - The missing field is **never** fabricated, guessed, or treated as normal baseline evidence.
  - The item is excluded from positive `evidence`.
- Under strict mode (`missing_evidence_policy = "strict_raise"`):
  - The evaluator raises a `ValueError` failing validation.

---

## 6. Structured Alert Contract Schema

Each alert conforms to the `SecurityAlert` Pydantic model (`src/risk_scoring/schema.py`):

```json
{
  "alert_id": "alt_win_001_a9f3b81c2d0e",
  "window_id": "win_001",
  "anomaly_score": 0.124512,
  "is_anomaly": 1,
  "risk_score": 52.84,
  "severity": "MEDIUM",
  "evidence": [
    {
      "signal_name": "failed_login_burst",
      "source_field": "failed_logins",
      "observed_value": 45,
      "comparison_or_rule": "observed > baseline_threshold (3.0)",
      "contribution": 15.0,
      "explanation": "Observed failed_logins=45.0 exceeded baseline threshold (3.0); saturation ceiling is 40.0; contributed 15.00 points."
    }
  ],
  "score_breakdown": {
    "ml_anomaly": {
      "component": "ml_isolation_forest_anomaly",
      "source_field": "anomaly_score",
      "observed_value": 0.124512,
      "configured_weight": 40.0,
      "rule": "anomaly_score > threshold (0.0412)",
      "contribution": 25.84,
      "calculation_method": "supra_threshold_saturation_scaling",
      "status": "contributed"
    },
    "behavioral_components": [ ... ],
    "total_ml_contribution": 25.84,
    "total_behavioral_contribution": 27.0,
    "calculated_risk_score": 52.84,
    "reconciled": true,
    "rounding_difference": 0.0
  },
  "scoring_config_version": "v1.0.0",
  "created_at": "2026-10-09T04:00:00Z",
  "raw_model_score": -0.124512,
  "anomaly_threshold": 0.04116906323724265,
  "critical_safeguard_applied": false,
  "safeguard_note": null
}
```

---

## 7. Execution Commands

- **Score Evaluation Set & Generate Summary**:
  ```bash
  python -m src.risk_scoring.engine
  ```
- **Run Phase 3 Pytest Suite**:
  ```bash
  pytest -v tests/test_risk_scoring.py
  ```
- **Execute Phase 3 Exit Gate**:
  ```bash
  python scripts/run_phase_exit_tests.py --phase 3
  ```

---

## 8. Known Limitations

1. **Synthetic Telemetry**: Baseline thresholds ($p_{99}$) and saturation limits are calibrated against synthetic log windows; real organizational telemetry requires periodic re-baselining to account for seasonality.
2. **Heuristic Risk Weights**: Weights ($40\%$ ML, $60\%$ behavioral) reflect documented operational prioritization heuristics, not scientifically calibrated universal probabilities.
3. **No Attack Identification**: A high risk score indicates unusual, high-intensity activity requiring analyst investigation; it is not proof of compromise or evidence of a specific threat actor.
