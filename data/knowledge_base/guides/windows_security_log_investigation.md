# Windows Security Event Log Investigation Guide

## 1. Overview
The Windows Security Event Log (`Security.evtx`) is the primary source of host-based authentication, authorization, and process tracking telemetry in enterprise Windows environments.

## 2. Key Security Event IDs

### Event ID 4624: An Account Was Successfully Logged On
Event ID 4624 records successful user or computer authentications. Critical investigation fields:
- `LogonType`: Identifies how the logon occurred.
  - `2`: Interactive (local console logon).
  - `3`: Network (SMB, RPC, remote share access, IIS web authentication).
  - `4`: Batch (scheduled tasks).
  - `5`: Service (Windows services starting up).
  - `7`: Unlock (workstation unlocked).
  - `10`: RemoteInteractive (Remote Desktop Protocol / Terminal Services).
- `TargetUserName`: The user account that authenticated.
- `WorkstationName`: Source machine identifier.
- `IpAddress`: Remote source IP address initiating the logon.

### Event ID 4625: An Account Failed to Log On
Event ID 4625 indicates an unsuccessful authentication attempt. Essential status codes:
- `Status 0xC000006D`: Generic logon failure (`STATUS_LOGON_FAILURE`).
- `SubStatus 0xC000006A`: User name is correct, but password was wrong (`STATUS_WRONG_PASSWORD`).
- `SubStatus 0xC0000064`: User name does not exist (`STATUS_NO_SUCH_USER`).
- `SubStatus 0xC0000234`: Account is currently locked out (`STATUS_ACCOUNT_LOCKED_OUT`).
- `SubStatus 0xC0000072`: Account is disabled (`STATUS_ACCOUNT_DISABLED`).

### Event ID 4688: A New Process Has Been Created
Event ID 4688 logs process execution when Audit Process Creation is enabled:
- `NewProcessName`: Full path of the executable being launched.
- `CommandLine`: Full command line with arguments (requires 'Include command line in process creation events' policy).
- `CreatorProcessId` / `ParentProcessName`: Process that spawned the child process.
- `SubjectUserName`: Account context under which the process executed.

### Event ID 4672: Special Privileges Assigned to New Logon
Event ID 4672 triggers whenever a user logs on with administrative privileges:
- Privileges assigned include `SeDebugPrivilege`, `SeBackupPrivilege`, `SeRestorePrivilege`, `SeTakeOwnershipPrivilege`.
- High frequency of Event ID 4672 outside business hours or for non-administrative accounts warrants priority triage.

## 3. Investigation Triage Workflow
1. Identify high-frequency Event ID 4625 bursts to detect automated password guessing.
2. Cross-reference source IP addresses against known external subnets and VPN gateways.
3. Review subsequent Event ID 4624 logons from the same IP to determine if the adversary gained valid credentials.
4. Examine Event ID 4688 process creation trees immediately following successful authentication to detect post-exploitation tools.
