/**
 * Core TypeScript definitions for the Security Operations Dashboard.
 * Strictly aligned with backend API contracts from Phase 8.
 */

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export type ClassificationStatus =
  | 'CHARACTERIZED'
  | 'UNCLASSIFIED'
  | 'NOT_ANOMALOUS'
  | 'INSUFFICIENT_EVIDENCE'
  | 'SERVICE_ERROR';

export type AnomalyCategory =
  | 'OFF_HOURS_ACTIVITY'
  | 'REPEATED_FAILED_AUTHENTICATION'
  | 'UNUSUAL_PROCESS_ACTIVITY'
  | 'UNUSUAL_NETWORK_ACTIVITY'
  | 'UNUSUAL_OUTBOUND_DATA_ACTIVITY'
  | 'MULTIPLE_BEHAVIORAL_ANOMALIES'
  | 'UNCLASSIFIED_ANOMALY';

export interface SupportingSignal {
  signal_name: string;
  source_field: string;
  observed_value: number | string | boolean;
  threshold_or_baseline: number | string;
  rule_id: string;
  comparison: string;
  explanation: string;
  contribution_points?: number;
}

export interface AnomalyCharacterization {
  classification_status: ClassificationStatus;
  primary_category: AnomalyCategory;
  additional_categories: AnomalyCategory[];
  summary: string;
  supporting_signals: SupportingSignal[];
  explanation: string;
  uncertainty: string;
  rule_ids: string[];
  characterization_version: string;
}

export interface EvidenceItem {
  signal_name: string;
  source_field?: string;
  observed_value: number | string | boolean;
  comparison_or_rule?: string;
  threshold_or_baseline?: number | string | null;
  contribution?: number;
  score_contribution?: number;
  explanation?: string;
  is_anomaly_contributor?: boolean;
}

export interface ScoreComponent {
  component?: string;
  component_name?: string;
  contribution?: number;
  raw_signal_value?: number | string;
  observed_value?: number | string;
  weight?: number;
  configured_weight?: number;
  rule?: string;
  formula_reference?: string;
}

export interface ScoreBreakdown {
  total_risk_score?: number;
  calculated_risk_score?: number;
  total_ml_contribution?: number;
  total_behavioral_contribution?: number;
  anomaly_signal_contribution?: number;
  behavioral_signal_contribution?: number;
  ml_anomaly?: ScoreComponent;
  behavioral_components?: ScoreComponent[];
  components?: ScoreComponent[];
  calculation_explanation?: string;
  config_version?: string;
  reconciled?: boolean;
}

export interface TechniqueCandidate {
  technique_id: string;
  technique_name: string;
  tactics: string[];
  mapping_reason?: string;
  supporting_evidence?: (string | EvidenceItem | Record<string, unknown>)[];
  confidence?: string;
  catalog_source?: string;
  catalog_version?: string;
  url?: string;
}

export interface MitreContext {
  mapping_status: string; // e.g. "MAPPED", "NOT_MAPPED", "INSUFFICIENT_EVIDENCE"
  candidate_techniques: TechniqueCandidate[];
  evidence_summary?: string;
}

export interface SecurityAlert {
  alert_id: string;
  window_id: string;
  anomaly_score: number;
  is_anomaly: number;
  risk_score: number;
  severity: SeverityLevel;
  evidence: EvidenceItem[];
  score_breakdown?: ScoreBreakdown;
  anomaly_characterization?: AnomalyCharacterization;
  mitre_context?: MitreContext;
  attack_context?: MitreContext;
  created_at?: string;
}

export interface PaginatedAlertsResponse {
  items: SecurityAlert[];
  limit: number;
  offset: number;
  total: number;
}

export interface RagCitation {
  source_title: string;
  source_id: string;
  chunk_id: string;
  source_uri_or_path?: string;
  document_title?: string;
  version_or_date?: string;
  relevant_text?: string;
  content?: string;
}

export interface InvestigationReport {
  investigation_id: string;
  alert_id: string;
  summary: string;
  supplied_severity: SeverityLevel;
  supplied_risk_score: number;
  finding: string; // e.g. "SUSPICIOUS_ACTIVITY", "ANOMALOUS_ACTIVITY", "POSSIBLE_ATTACK", "INSUFFICIENT_EVIDENCE"
  observed_evidence: (string | Record<string, unknown>)[];
  interpretation: string;
  possible_attack_techniques: (string | Record<string, unknown>)[];
  uncertainty?: string;
  recommended_next_steps: (string | Record<string, unknown>)[];
  citations: RagCitation[];
  limitations?: string[];
}

export interface TraceStep {
  node_name: string;
  timestamp: number;
  duration_seconds: number;
  status: string;
  action_requested?: string | null;
  action_approved?: string | null;
  summary: string;
  metadata?: Record<string, unknown>;
}

export interface InvestigationResponse {
  investigation_id: string;
  alert_id: string;
  status: string; // "SUCCESS", "INSUFFICIENT_EVIDENCE", "LIMIT_REACHED", "TIMEOUT", "ERROR"
  final_report?: InvestigationReport | null;
  execution_trace_summary: TraceStep[];
  tool_call_count: number;
  llm_call_count: number;
  iteration_count: number;
  elapsed_time: number;
  warnings: string[];
  failure_reason?: string | null;
}

export interface HealthResponse {
  status: string;
}

export interface DependencyStatus {
  status: string; // "ready", "not_ready", "unavailable"
  message?: string;
  details?: Record<string, unknown>;
}

export interface ReadinessResponse {
  status: string; // "ready", "degraded", "not_ready"
  dependencies: Record<string, DependencyStatus>;
}

export interface ModelStatusResponse {
  provider: string;
  configured_model: string;
  detected_model?: string | null;
  availability: string; // "available", "unavailable", "model_not_found"
  last_check: string;
  error_code?: string | null;
}

export interface ApiErrorDetail {
  code: string;
  message: string;
  correlation_id?: string | null;
  details?: unknown;
}

export interface ApiErrorResponse {
  error: ApiErrorDetail;
}
