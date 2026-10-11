# Threat Hunting Guide: Authentication Anomalies and Credential Access

## 1. Overview
Adversaries frequently employ credential access techniques (MITRE ATT&CK `TA0006`) to acquire valid user credentials, bypass multifactor authentication, and establish persistence across enterprise systems.

## 2. Attack Patterns and Behavioral Signatures

### Brute Force vs. Password Spraying
- **Brute Force (`T1110.001`)**: Many failed logon attempts against a single target account within a short duration.
  - Telemetry: High count of failed logons (`failed_logins >= 10`) tied to a single username.
  - Consequence: High probability of account lockout (`SubStatus 0xC0000234`).
- **Password Spraying (`T1110.003`)**: A low number of password attempts (e.g., 1-2 attempts) tested against many distinct accounts across an enterprise.
  - Telemetry: Low per-account failure rate but high aggregate failed logins across diverse user IDs.
  - Consequence: Designed specifically to avoid triggering account lockout thresholds.
- **Credential Stuffing (`T1110.004`)**: Automated testing of credential pairs leaked from public breach dumps.
  - Telemetry: Bursts of login attempts from diverse external IP addresses using automated tools.

### Off-Hours Authentication and Geographic Anomalies
- **Off-Hours Logons**: User logons occurring outside established organization business hours (e.g., 22:00 to 05:00 local time or weekends).
- **Service Account Interactive Logons**: Service accounts executing Interactive (`LogonType 2`) or RemoteInteractive (`LogonType 10`) sessions rather than Service (`LogonType 5`) sessions indicate compromised credentials used for interactive hands-on-keyboard access.

## 3. Recommended Investigation Steps
1. Determine the scope of affected accounts (single user vs. directory-wide).
2. Inspect source IP reputation and geographic origin.
3. Check for subsequent successful logon events (`Event ID 4624`) from the offending source IP within 60 minutes of the burst.
4. Verify whether multifactor authentication (MFA) was prompted and completed.
5. If compromise is suspected, initiate immediate password resets and session token revocation.
