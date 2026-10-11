# Synthetic Dataset Specification

This dataset simulates security-behavior windows. It is synthetic and is not real organization telemetry.

## Files
- `security_windows_train_normal.csv`: normal-only training data.
- `security_windows_eval_labeled.csv`: labeled evaluation data.

## Columns
window_id, user_role, host_type, hour, day_of_week, is_weekend, failed_logins, successful_logins, login_attempts, unique_source_ips, new_source_ip_count, privileged_actions, file_access_count, process_count, network_connections, external_connections, bytes_out_mb, distinct_destinations, rare_process_count, after_hours, anomaly_type, label

## Labels
- 0 = synthetic normal
- 1 = synthetic anomaly

## Synthetic anomaly types
- brute_force
- off_hours_admin_access
- unusual_external_activity
- data_exfiltration_like
- rare_process_burst

These names describe generated patterns only. They are not proof of real attacks.

## Modeling
Do not use window_id, anomaly_type or label as model features.
Fit preprocessing/model only on training-normal data to avoid leakage.
