# Baseline Machine Learning Anomaly Detection (Phase 2)

> **Important Cybersecurity Notice**:
> The baseline detector identifies statistical anomalies in synthetic behavioral telemetry windows. An anomaly is **not** proof of malicious activity, nor is it proof of a confirmed cyber attack. Anomalies indicate deviations from normal baseline behavior that warrant risk scoring and investigation.

---

## 1. Objective & Role in Architecture

In this hybrid security analytics architecture, machine learning performs detection and scoring, while rules and subsequent language models synthesize evidence, provide context, and propose investigation steps.

The Phase 2 baseline detector learns **normal system behavior** from a normal-only training dataset and calculates an anomaly score for unseen behavioral observation windows.

Pipeline:
```text
Validated Training Data (Normal-Only)
        ↓
Feature Selection (17 Numeric Behavioral Features)
        ↓
Preprocessing (Column Alignment & Type Validation)
        ↓
Isolation Forest Training (Unsupervised)
        ↓
Threshold Derivation (95th Percentile of Training Normal Scores)
        ↓
Saved Artifacts (Model, Preprocessor, Threshold, Feature Schema)
        ↓
Inference & Evaluation (Scoring Unseen Windows without Retraining)
```

---

## 2. Model Selection: Isolation Forest

`sklearn.ensemble.IsolationForest` was chosen as the baseline anomaly detection algorithm for several reasons:
- **Unsupervised Anomaly Isolation**: Operates by isolating anomalies rather than profiling normal points with distance metrics. Anomalies are isolated closer to the root of randomized trees because they possess rare feature combinations.
- **Scale Invariance**: Being tree-based, Isolation Forest partitions features using orthogonal splits, making it naturally invariant to monotonic feature transformations. This avoids the necessity of artificial min-max scaling or z-score normalization.
- **Computational Efficiency**: Linear time complexity with low memory footprint, scaling easily to large log volumes.

### Hyperparameters
- `n_estimators`: `100` (100 decision trees)
- `random_state`: `42` (ensures reproducible tree splits)
- `max_samples`: `'auto'` (`min(256, n_samples)`)
- `contamination`: `'auto'` (determines internal offset; our project derives its operational decision threshold externally from the training score distribution)

---

## 3. Selected Feature Set

The baseline model utilizes **17 numeric behavioral features**:

| Feature Name | Type | Behavioral Rationale |
|---|---|---|
| `hour` | int | Identifies off-peak or after-hours system activity. |
| `day_of_week` | int | Captures weekly operational cycles. |
| `is_weekend` | int | Separates business days from weekend workloads. |
| `failed_logins` | int | Direct indicator of authentication stress / brute force. |
| `successful_logins` | int | Establishes baseline login rate for account activity. |
| `login_attempts` | int | Total authentication intensity in the observation window. |
| `unique_source_ips` | int | Flags access from multiple distinct source addresses. |
| `new_source_ip_count` | int | Detects connections from previously unrecorded IP addresses. |
| `privileged_actions` | int | Monitors elevated execution volume (e.g., sudo/admin actions). |
| `file_access_count` | int | Detects bulk file read/write spikes (e.g., exfiltration, sweeps). |
| `process_count` | int | Tracks compute intensity and command activity. |
| `network_connections` | int | Monitors aggregate network session volume. |
| `external_connections` | int | Flags perimeter egress connection counts. |
| `bytes_out_mb` | float | Measures network egress volume to identify potential data staging/leakage. |
| `distinct_destinations` | int | Detects widespread outbound scanning or fan-out communication. |
| `rare_process_count` | int | Counts execution of atypical binaries or system utilities. |
| `after_hours` | int | Explicit indicator of activity outside defined business schedules. |

### Excluded Columns & Leakage Prevention
- `window_id`: Arbitrary record identifier with zero behavioral signal.
- `label`: Binary target (0=normal, 1=anomaly); strictly excluded from training to guarantee unsupervised training and eliminate target leakage.
- `anomaly_type`: Synthetic label metadata; strictly excluded.
- `user_role`, `host_type`: Categorical text fields (`admin`, `employee`, `server`, etc.). Arbitrary integer encoding (e.g., `admin=1, employee=2`) introduces non-existent mathematical order. For the baseline model, pure numeric features are used.

---

## 4. Score Semantics & Threshold Selection

### Score Definitions
- **Raw Score (`raw_score`)**: Computed using scikit-learn's `decision_function(X)`. Higher values represent more normal observations, lower/negative values represent anomalies.
- **Anomaly Score (`anomaly_score`)**: Derived as `-raw_score`. Higher values represent higher abnormality; lower values represent normal behavior.
- **Binary Decision (`is_anomaly`)**:
  $$\text{is\_anomaly} = \begin{cases} 1 & \text{if } \text{anomaly\_score} > \text{threshold} \\ 0 & \text{otherwise} \end{cases}$$

### Threshold Strategy
The threshold is **not** an arbitrary number (such as 0.5) and is **never** chosen using evaluation anomaly labels.
- Derived as the **95th percentile** of the training anomaly score distribution ($p=95.0$).
- Because training data is 100% normal, setting the threshold at the 95th percentile establishes an expected **5% false-positive rate** on baseline normal traffic.
- Measured threshold value: `0.041169`.

---

## 5. Artifacts Produced

Model training produces five self-contained artifacts in `artifacts/ml/`:
1. `preprocessor.joblib`: Fitted `FeaturePreprocessor` ensuring feature schema validation and ordering.
2. `isolation_forest.joblib`: Serialized trained `IsolationForest` estimator.
3. `threshold.json`: Exact threshold value, percentile method, training score distribution statistics, and metadata.
4. `feature_schema.json`: Expected feature names, order, types, and model version.
5. `metrics.json`: Formal evaluation metrics computed against the evaluation dataset.

---

## 6. Measured Evaluation Performance

Evaluated against `data/security_windows_eval_labeled.csv` (4,000 synthetic windows: 2,000 normal, 2,000 anomalous):

| Metric | Measured Value | Description |
|---|---|---|
| **Precision** | `94.91%` (0.9491) | Proportion of flagged anomalies that were true anomalies |
| **Recall** | `94.25%` (0.9425) | Proportion of true anomalies correctly flagged |
| **F1-Score** | `94.58%` (0.9458) | Harmonic mean of precision and recall |
| **Accuracy** | `94.60%` (0.9460) | Overall classification accuracy |
| **False Positive Rate** | `5.05%` (0.0505) | FPR on normal evaluation rows (matches 95% training design) |
| **ROC-AUC** | `0.9896` | Area under ROC curve |
| **PR-AUC** | `0.9883` | Area under Precision-Recall curve |

### Confusion Matrix
- **True Positives (TP)**: 1,885
- **False Positives (FP)**: 101
- **True Negatives (TN)**: 1,899
- **False Negatives (FN)**: 115

### Per-Anomaly Recall Breakdown
- `off_hours_admin_access`: **100.0%** (400 / 400 detected)
- `unusual_external_activity`: **100.0%** (400 / 400 detected)
- `brute_force`: **99.5%** (398 / 400 detected)
- `data_exfiltration_like`: **87.25%** (349 / 400 detected)
- `rare_process_burst`: **84.5%** (338 / 400 detected)
- `normal`: **94.95%** specificity (1,899 / 2,000 recognized as normal)

---

## 7. Execution Commands

- **Train Baseline**:
  ```bash
  python -m src.ml.train
  ```
- **Run Inference on Evaluation Data**:
  ```bash
  python -m src.ml.inference
  ```
- **Run Evaluation & Generate `metrics.json`**:
  ```bash
  python -m src.ml.evaluation
  ```
- **Execute Phase 2 Exit Gate**:
  ```bash
  python scripts/run_phase_exit_tests.py --phase 2
  ```

---

## 8. Known Limitations

1. **Uncalibrated Probabilities**: The derived anomaly score is a continuous distance metric from the Isolation Forest hyperplanes; it is **not** a calibrated probability of compromise.
2. **Synthetic Data**: Features and anomalies represent simulated patterns; real-world environments exhibit non-stationary seasonality and domain-specific noise.
3. **Purely Numeric Modeling**: Categorical features (`user_role`, `host_type`) are omitted in this baseline to avoid artificial ordinal assumptions; future iterations may explore one-hot encoding or target encoding if appropriate.
