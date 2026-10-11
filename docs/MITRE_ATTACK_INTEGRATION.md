# MITRE ATT&CK Integration Specification

## 1. Overview and Purpose

The goal of Phase 4 is to associate observed behavioral anomalies and security alerts with standardized adversary tactics and techniques defined by the **MITRE ATT&CK Enterprise Framework**.

In Phases 2 and 3, the system detects anomalous telemetry windows via an unsupervised Isolation Forest model and computes an explainable, bounded risk priority score ($0.0 \le \text{risk\_score} \le 100.0$). However, security analysts require standardized adversary context to prioritize investigation workflows, understand possible adversary objectives, and cross-reference detection guidance.

Phase 4 introduces:
1. **Verified ATT&CK Catalog Ingestion & Storage**: Ingestion of authoritative STIX 2.1 Enterprise ATT&CK objects with strict schema validation, duplicate detection, and hash verification.
2. **Technique Catalog Service**: Deterministic, typed lookups (`lookup_attack_technique`), tactic queries (`get_technique_tactics`), and keyword searches (`search_attack_techniques`) matching the tool contract defined in [`docs/TOOL_CONTRACTS.md`](file:///c:/Users/upadh/OneDrive/Desktop/Proj2/ai_security_log_anomaly_project_starter/docs/TOOL_CONTRACTS.md).
3. **Deterministic Behavior-to-Technique Mapping Engine**: Rule-based mapping from verified window evidence to candidate ATT&CK techniques without using an LLM or peeking at synthetic ground-truth labels.
4. **Alert Context Enrichment**: Augmentation of Phase 3 [`SecurityAlert`](file:///c:/Users/upadh/OneDrive/Desktop/Proj2/ai_security_log_anomaly_project_starter/src/risk_scoring/schema.py) objects into [`AlertWithMitreContext`](file:///c:/Users/upadh/OneDrive/Desktop/Proj2/ai_security_log_anomaly_project_starter/src/mitre/schemas.py), strictly preserving original ML anomaly scores, risk scores, severity, and evidence breakdowns.

---

## 2. Core Concepts: Tactics vs. Techniques

Adversary behaviors in MITRE ATT&CK are organized hierarchically:

| Concept | Definition | Example in Catalog |
| :--- | :--- | :--- |
| **Tactic** | The adversary's tactical goal or objective — *why* an action is performed. | `TA0001` (Initial Access), `TA0004` (Privilege Escalation), `TA0006` (Credential Access) |
| **Technique** | The specific method or means used to accomplish an objective — *how* the goal is achieved. | `T1110` (Brute Force), `T1078` (Valid Accounts), `T1059` (Command and Scripting Interpreter) |
| **Sub-technique** | A more specific, granular implementation of a parent technique. | `T1110.001` (Password Guessing) under parent `T1110` |

### Key Structural Invariants
- **Multi-Tactic Relationships**: A single technique may pursue multiple tactics. For example, `T1078` (Valid Accounts) spans Initial Access (`TA0001`), Persistence (`TA0003`), Privilege Escalation (`TA0004`), and Defense Evasion (`TA0005`). The catalog preserves all tactic relationships rather than assuming a 1:1 mapping.
- **Hierarchy Traversal**: Sub-techniques point to exactly one parent technique via a `subtechnique-of` relationship. Ingestion resolves bidirectional references (`parent_technique_id` and `sub_technique_ids`).
- **No Inferred IDs**: Technique identifiers (`T####` or `T####.###`) are never constructed via string formatting or heuristically inferred from names. They must be resolved from the verified source bundle.

---

## 3. Domain Selection and Authoritative Source

### Chosen Domain
**Enterprise ATT&CK (`enterprise-attack`)** was selected because our telemetry captures host and network enterprise security events (logins, privilege escalations, process activity, outbound connections, data volumes). Mobile (`mobile-attack`) and Industrial Control Systems (`ics-attack`) techniques are excluded.

### Authoritative Upstream Source
- **Repository**: `mitre-attack/attack-stix-data` (official MITRE ATT&CK STIX data distribution).
- **URL**: `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json`
- **Release / Version**: MITRE ATT&CK **v14.1** (STIX 2.1 schema).
- **License**: Apache License 2.0 / MITRE Terms of Use.

### Ingestion and Caching Architecture
1. **Verification Before Import**: The raw JSON bundle is checked for required STIX 2.1 envelope fields (`type == "bundle"`, `id`, `objects`). The SHA-256 digest is computed and recorded in metadata.
2. **Object Filtering**:
   - `x-mitre-tactic` objects are extracted into [`TacticInfo`](file:///c:/Users/upadh/OneDrive/Desktop/Proj2/ai_security_log_anomaly_project_starter/src/mitre/schemas.py).
   - `attack-pattern` objects with `source_name == "mitre-attack"` are extracted into [`TechniqueInfo`](file:///c:/Users/upadh/OneDrive/Desktop/Proj2/ai_security_log_anomaly_project_starter/src/mitre/schemas.py).
   - Revoked (`revoked: true`) and deprecated (`x_mitre_deprecated: true`) objects are filtered out from the active catalog by default.
   - `relationship` objects of type `subtechnique-of` link child techniques to parent techniques.
3. **Local Cache**: Ingestion saves the normalized catalog to `artifacts/mitre/catalog.json` and provenance metadata to `artifacts/mitre/metadata.json`.
4. **Startup Efficiency**: The application does not download the catalog on every startup. If a valid cached catalog exists, it is loaded locally. In offline mode (`offline_mode=True`), network calls are disabled.

---

## 4. Catalog Schemas

The catalog layer is defined with typed Pydantic models in [`src/mitre/schemas.py`](file:///c:/Users/upadh/OneDrive/Desktop/Proj2/ai_security_log_anomaly_project_starter/src/mitre/schemas.py):

### `TechniqueInfo`
```python
class TechniqueInfo(BaseModel):
    technique_id: str             # Canonical ID, e.g., 'T1110' or 'T1110.001'
    name: str                     # e.g., 'Brute Force'
    description: str              # Official ATT&CK canonical description
    tactic_ids: list[str]         # e.g., ['TA0006']
    tactic_names: list[str]       # e.g., ['Credential Access']
    platforms: list[str]          # e.g., ['Linux', 'Windows', 'macOS']
    data_sources: list[str]       # e.g., ['Logon Session: Logon Session Creation']
    is_subtechnique: bool
    parent_technique_id: str | None
    sub_technique_ids: list[str]
    url: str                      # Canonical URL on attack.mitre.org
    version: str                  # e.g., 'v14.1'
    is_deprecated: bool = False
    is_revoked: bool = False
```

### `CatalogMetadata`
```python
class CatalogMetadata(BaseModel):
    domain: str                   # 'enterprise-attack'
    attack_version: str           # 'v14.1'
    source_url: str
    source_hash: str              # SHA-256 digest of source content
    retrieved_at: str             # ISO-8601 UTC timestamp
    techniques_count: int
    tactics_count: int
    offline_mode: bool
```

---

## 5. Behavior-to-Technique Mapping Engine

### Separation of Concerns
- **Technique Catalog Lookup**: Read-only queries against verified ATT&CK data by technique ID or query terms.
- **Behavior Mapping**: Inspection of observed alert evidence from telemetry windows to evaluate explicit, deterministic behavioral rules.

### Anti-Leakage and Cybersecurity Truthfulness
1. **No Synthetic Label Leakage**: The synthetic evaluation columns `anomaly_type` and `label` are **strictly prohibited** from driving mapping logic. Rules evaluate only observable telemetry evidence (`failed_logins`, `privileged_actions`, `external_connections`, `bytes_out_mb`, `rare_process_count`).
2. **Missing Telemetry Policy**: A missing evidence field is treated as *unobserved*, never as negative evidence. If a rule requires an unobserved field, the rule does not fire.
3. **No Attack Proof**: An anomaly or behavioral threshold violation does not constitute proof of compromise. Mappings are classified as *candidate techniques consistent with observed behavior*.
4. **No Hallucinated Techniques**: Every candidate technique emitted by a mapping rule must be validated against the active catalog before inclusion in an alert.

### Mapping Rule Specification
Each deterministic rule is modeled by [`BehaviorMappingRule`](file:///c:/Users/upadh/OneDrive/Desktop/Proj2/ai_security_log_anomaly_project_starter/src/mitre/mapping_rules.py):

| Rule ID | Applicable Behavior | Required Fields | Predicate Logic | Target Technique | Default Confidence |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `RULE_AUTH_BRUTE_FORCE` | Authentication Burst | `failed_logins` | `failed_logins >= 10` | `T1110` (Brute Force) | `MEDIUM` |
| `RULE_PRIV_VALID_ACCOUNTS` | High Privileged Usage | `privileged_actions`, `failed_logins` | `privileged_actions >= 3 and failed_logins == 0` | `T1078` (Valid Accounts) | `LOW` |
| `RULE_NETWORK_EGRESS_PROTOCOL` | Excessive External Connections | `external_connections` | `external_connections >= 30` | `T1071` (Application Layer Protocol) | `LOW` |
| `RULE_EXFIL_ALTERNATIVE` | High Volume Egress | `bytes_out_mb` | `bytes_out_mb >= 100.0` | `T1048` (Exfiltration Over Alternative Protocol) | `MEDIUM` |
| `RULE_EXEC_COMMAND_INTERPRETER` | Rare Process Spikes | `rare_process_count` | `rare_process_count >= 5` | `T1059` (Command and Scripting Interpreter) | `LOW` |

### Mapping Statuses
The mapping outcome is typed using [`MappingStatus`](file:///c:/Users/upadh/OneDrive/Desktop/Proj2/ai_security_log_anomaly_project_starter/src/mitre/schemas.py):
- `MAPPED`: One or more supported behavioral rules matched and were verified against the catalog.
- `NOT_MAPPED`: Telemetry was evaluated, but no behavioral anomalies were present.
- `INSUFFICIENT_EVIDENCE`: Telemetry showed slight activity, but lacked the threshold or required fields for a specific mapping.
- `SOURCE_UNAVAILABLE`: Catalog could not be loaded or verified.

### Confidence Semantics
Confidence levels (`LOW`, `MEDIUM`, `HIGH`) represent heuristic evidence strength based on indicator corroboration, not calibrated Bayesian probabilities of an active intrusion:
- `LOW`: Single behavioral indicator with alternative benign explanations (e.g., routine administrative scripts, normal external CDN connections).
- `MEDIUM`: Distinct burst or multi-field corroboration exceeding operational saturation thresholds.
- `HIGH`: Multi-indicator alignment across both authentication and execution telemetry.

---

## 6. Alert Integration

Phase 4 extends the Phase 3 alert contract by producing [`AlertWithMitreContext`](file:///c:/Users/upadh/OneDrive/Desktop/Proj2/ai_security_log_anomaly_project_starter/src/mitre/schemas.py):

```python
class AlertWithMitreContext(SecurityAlert):
    mitre_context: BehaviorMappingResult
```

### Invariants Maintained
- `anomaly_score`: Identical to Phase 2 Isolation Forest prediction.
- `is_anomaly`: Identical to Phase 2 threshold decision.
- `risk_score`: Identical to Phase 3 risk calculation ($0.0 - 100.0$).
- `severity`: Identical to Phase 3 severity classification.
- `evidence`: Preserves original breakdown of contributing items.
- `mitre_context`: Encapsulates mapping status, candidate techniques, associated tactics, supporting evidence references, and ATT&CK release provenance.

---

## 7. Catalog Service API and Tool Contract

The [`MitreService`](file:///c:/Users/upadh/OneDrive/Desktop/Proj2/ai_security_log_anomaly_project_starter/src/mitre/service.py) provides programmatic interfaces adhering to [`docs/TOOL_CONTRACTS.md`](file:///c:/Users/upadh/OneDrive/Desktop/Proj2/ai_security_log_anomaly_project_starter/docs/TOOL_CONTRACTS.md):

```python
# 1. Lookup technique by canonical ID
result = service.lookup_attack_technique("T1110")
# Returns: dict matching tool contract:
# {"status": "success", "technique": {...}} or {"status": "not_found", "message": "..."}

# 2. Search techniques by keyword
matches = service.search_attack_techniques("brute force", max_results=5)

# 3. Retrieve associated tactics
tactics = service.get_technique_tactics("T1078")

# 4. Map alert behavior
mapping_result = service.map_alert_behavior(alert)

# 5. Enrich alert with MITRE context
enriched_alert = service.enrich_alert(alert)
```

---

## 8. Verification and Exit Gate

### Commands
- Run Phase 4 Exit Gate:
  ```bash
  python scripts/run_phase_exit_tests.py --phase 4
  ```
- Run Unit and Integration Tests:
  ```bash
  pytest tests/test_mitre_integration.py -v
  ```
- Run Full Test Suite:
  ```bash
  pytest -v
  ```

### Exit Gate Checks
The Phase 4 gate verifies 14 required behaviors:
1. Phase 3 dependency verified (`RiskScoringConfig` v1.0.0 loaded).
2. MITRE source and version metadata valid (`enterprise-attack`, `v14.1`).
3. STIX 2.1 fixture catalog import parses active techniques and tactics.
4. Exact technique ID lookup resolves (`T1110` -> "Brute Force").
5. Unknown technique returns explicit `not_found` status (`T9999`).
6. Tactic/technique relationships and sub-technique hierarchies preserved.
7. Mappings require supported evidence (`failed_logins >= 10` maps to `T1110`).
8. Unsupported behaviors remain unmapped (`INSUFFICIENT_EVIDENCE`).
9. Source metadata and URLs returned with mappings.
10. Original alert scores (`anomaly_score`, `risk_score`, `severity`) strictly preserved.
11. Catalog failures handled safely with controlled exceptions.
12. Invalid mapping rules targeting nonexistent techniques are rejected.
13. Deterministic repeatability across independent runs.
14. Negative tests pass (invalid ID syntax, empty queries, malformed STIX).

---

## 9. Known Limitations

1. **Aggregated Telemetry vs. Attack Granularity**: The telemetry consists of 1-hour aggregated window statistics. It does not record process command-line arguments, file paths, parent-child process trees, network packet payloads, or user agent headers. Specific adversary sub-techniques cannot be inferred without risk of false precision.
2. **Attribution Boundary**: Technique mappings indicate behavioral alignment with ATT&CK descriptions, not adversary attribution or proof of intrusion.
3. **Fixture Scope**: The offline test fixture contains a verified core subset of Enterprise ATT&CK techniques (`T1110`, `T1110.001`, `T1078`, `T1059`, `T1071`, `T1048`, `T1548`). Production full-catalog deployment can ingest the full 800+ technique STIX distribution.
