import React, { useEffect, useState, useRef } from 'react';
import { api, ApiError } from '../services/api';
import type { SecurityAlert, InvestigationResponse, InvestigationReport } from '../types';
import { SeverityBadge } from './SeverityBadge';
import {
  ArrowLeft,
  Bot,
  Brain,
  Clock,
  ExternalLink,
  ChevronDown,
  ChevronRight,
  AlertCircle,
  HelpCircle,
  Database,
} from 'lucide-react';

interface AlertDetailViewProps {
  alertId: string;
  onBack: () => void;
}

export const AlertDetailView: React.FC<AlertDetailViewProps> = ({ alertId, onBack }) => {
  const [alert, setAlert] = useState<SecurityAlert | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Investigation state
  const [isInvestigating, setIsInvestigating] = useState<boolean>(false);
  const [investigationElapsed, setInvestigationElapsed] = useState<number>(0);
  const [investigationResult, setInvestigationResult] = useState<InvestigationResponse | null>(null);
  const [investigationError, setInvestigationError] = useState<string | null>(null);
  const timerRef = useRef<number | null>(null);

  // Expanded citations map
  const [expandedCitations, setExpandedCitations] = useState<Record<string, boolean>>({});

  const fetchAlert = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getAlert(alertId);
      setAlert(data);

      // Auto-load past completed investigation if one exists with valid report
      try {
        const pastInvs = await api.getInvestigations({ limit: 50 });
        const existing = pastInvs.find((inv) => inv.alert_id === alertId && inv.final_report !== null);
        if (existing) {
          setInvestigationResult(existing);
        }
      } catch {
        // Non-fatal: historical lookup is best-effort
      }
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        setError(`Failed to retrieve alert '${alertId}': ${err.message} (${err.code})`);
      } else {
        setError(`An unexpected error occurred while loading alert '${alertId}'.`);
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlert();
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [alertId]);

  const handleInvestigate = async () => {
    if (!alert || isInvestigating) return;

    setIsInvestigating(true);
    setInvestigationError(null);
    setInvestigationResult(null);
    setInvestigationElapsed(0);

    const startTime = Date.now();
    timerRef.current = window.setInterval(() => {
      setInvestigationElapsed(Math.floor((Date.now() - startTime) / 1000));
    }, 1000);

    try {
      const res = await api.investigateAlert(alert.alert_id);
      if (res.status === 'SUCCESS' && res.final_report) {
        setInvestigationResult(res);
      } else if (res.failure_reason) {
        setInvestigationError(`Investigation returned ${res.status}: ${res.failure_reason}`);
      } else {
        setInvestigationResult(res);
      }
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        setInvestigationError(`Investigation request failed: ${err.message} (${err.code})`);
      } else {
        setInvestigationError('An unexpected network or service error interrupted the investigation.');
      }
    } finally {
      if (timerRef.current) {
        clearInterval(timerRef.current);
        timerRef.current = null;
      }
      setIsInvestigating(false);
    }
  };

  const toggleCitation = (chunkId: string) => {
    setExpandedCitations((prev) => ({
      ...prev,
      [chunkId]: !prev[chunkId],
    }));
  };

  if (loading) {
    return (
      <div style={{ textAlign: 'center', padding: '5rem', color: 'var(--text-muted)' }}>
        <div className="spinner" style={{ margin: '0 auto 1rem', width: '2rem', height: '2rem' }} />
        <div>Loading alert details for {alertId}...</div>
      </div>
    );
  }

  if (error || !alert) {
    return (
      <div>
        <div className="breadcrumb">
          <button className="btn btn-secondary" onClick={onBack} style={{ padding: '0.3rem 0.6rem' }}>
            <ArrowLeft size={14} /> Back to Alerts
          </button>
        </div>
        <div className="banner banner-error" role="alert" style={{ marginTop: '1rem' }}>
          <AlertCircle size={20} />
          <div>
            <strong>Unable to display alert:</strong> {error || 'Alert not found.'}
          </div>
        </div>
      </div>
    );
  }

  const mitreCtx = alert.attack_context || alert.mitre_context;
  const candidate = mitreCtx?.candidate_techniques?.[0];
  const report: InvestigationReport | null = investigationResult?.final_report || null;

  return (
    <div>
      {/* Navigation Breadcrumb */}
      <div className="breadcrumb">
        <button
          className="btn btn-secondary"
          onClick={onBack}
          style={{ padding: '0.35rem 0.75rem', fontSize: '0.8125rem' }}
          aria-label="Return to alerts list"
        >
          <ArrowLeft size={14} />
          <span>Back to Alerts</span>
        </button>
        <span>/</span>
        <span className="mono" style={{ color: 'var(--text-primary)' }}>{alert.alert_id}</span>
      </div>

      {/* Header Bar */}
      <div
        className="card"
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '1.25rem',
          marginBottom: '1.5rem',
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.35rem' }}>
            <h1 className="mono" style={{ fontSize: '1.35rem', fontWeight: 700, color: '#fff' }}>
              {alert.alert_id}
            </h1>
            <SeverityBadge severity={alert.severity} size="md" />
            <span
              className="badge"
              style={{
                background: alert.is_anomaly ? 'rgba(239, 68, 68, 0.15)' : 'rgba(16, 185, 129, 0.15)',
                color: alert.is_anomaly ? '#f87171' : '#34d399',
                border: `1px solid ${alert.is_anomaly ? 'rgba(239, 68, 68, 0.3)' : 'rgba(16, 185, 129, 0.3)'}`,
              }}
            >
              {alert.is_anomaly ? 'ANOMALY DETECTED' : 'NORMAL BEHAVIOR'}
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem', fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
            <div>
              Window ID: <strong className="mono" style={{ color: 'var(--text-primary)' }}>{alert.window_id}</strong>
            </div>
            <div>
              Risk Score:{' '}
              <strong className="mono" style={{ color: '#fff', fontSize: '0.95rem' }}>
                {alert.risk_score.toFixed(2)} / 100.0
              </strong>
            </div>
            <div>
              Anomaly Score: <strong className="mono">{alert.anomaly_score.toFixed(4)}</strong>
            </div>
            {alert.created_at && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                <Clock size={13} />
                <span>{new Date(alert.created_at).toLocaleString()}</span>
              </div>
            )}
          </div>
        </div>

        {/* Investigate Action Button */}
        <div>
          <button
            className="btn btn-action"
            style={{ padding: '0.65rem 1.25rem', fontSize: '0.9rem' }}
            onClick={handleInvestigate}
            disabled={isInvestigating}
            aria-label="Investigate alert with local Qwen AI agent"
          >
            {isInvestigating ? (
              <>
                <div className="spinner" />
                <span>Investigating ({investigationElapsed}s)...</span>
              </>
            ) : (
              <>
                <Brain size={18} />
                <span>Investigate with AI</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* AI Investigation Progress Banner */}
      {isInvestigating && (
        <div className="banner banner-info" role="status" aria-live="polite">
          <Bot size={22} className="spinner" style={{ flexShrink: 0 }} />
          <div>
            <strong>Investigation in progress. Local inference may take some time.</strong>
            <div style={{ fontSize: '0.8125rem', marginTop: '0.25rem' }}>
              Executing multi-step LangGraph workflow with local Qwen 3 8B model via Ollama. Elapsed time:{' '}
              <span className="mono" style={{ fontWeight: 600 }}>{investigationElapsed}s</span>. Please do not close
              this tab.
            </div>
          </div>
        </div>
      )}

      {/* Investigation Error */}
      {investigationError && (
        <div className="banner banner-error" role="alert">
          <AlertCircle size={20} />
          <div>
            <strong>Investigation Error:</strong> {investigationError}
            <div style={{ fontSize: '0.75rem', marginTop: '0.25rem' }}>
              Verify that the local Ollama daemon is running with model <code>qwen3:8b</code> installed.
            </div>
          </div>
        </div>
      )}

      {/* Render AI Investigation Report if available */}
      {investigationResult && (
        <div
          className="card"
          style={{
            marginBottom: '1.5rem',
            border: '1px solid #7c3aed',
            background: 'linear-gradient(180deg, #18152e 0%, var(--bg-card) 100%)',
          }}
        >
          <div className="card-title" style={{ color: '#c084fc', borderBottom: '1px solid rgba(139, 92, 246, 0.2)', paddingBottom: '0.75rem' }}>
            <span>AI INVESTIGATION REPORT</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', fontSize: '0.75rem' }}>
              <span className="mono" style={{ color: 'var(--text-muted)' }}>
                ID: {investigationResult.investigation_id}
              </span>
              <span
                className="badge"
                style={{
                  background:
                    investigationResult.status === 'SUCCESS'
                      ? 'var(--status-ready-bg)'
                      : 'var(--status-degraded-bg)',
                  color:
                    investigationResult.status === 'SUCCESS'
                      ? 'var(--status-ready)'
                      : 'var(--status-degraded)',
                  border: `1px solid ${
                    investigationResult.status === 'SUCCESS'
                      ? 'rgba(16, 185, 129, 0.3)'
                      : 'rgba(245, 158, 11, 0.3)'
                  }`,
                }}
              >
                {investigationResult.status}
              </span>
              <span className="mono" style={{ color: 'var(--text-secondary)' }}>
                {investigationResult.elapsed_time.toFixed(1)}s
              </span>
            </div>
          </div>

          {report ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem', marginTop: '1rem' }}>
              {/* Finding & Summary */}
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                  <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
                    FINDING CLASSIFICATION:
                  </span>
                  <span
                    className="badge"
                    style={{
                      background: 'rgba(239, 68, 68, 0.15)',
                      color: '#f87171',
                      border: '1px solid rgba(239, 68, 68, 0.3)',
                      fontSize: '0.75rem',
                    }}
                  >
                    {report.finding}
                  </span>
                </div>
                <div
                  style={{
                    fontSize: '0.925rem',
                    lineHeight: 1.5,
                    color: '#fff',
                    background: 'var(--bg-tertiary)',
                    padding: '0.875rem 1rem',
                    borderRadius: '6px',
                    borderLeft: '4px solid #8b5cf6',
                  }}
                >
                  {report.summary}
                </div>
              </div>

              {/* Interpretation: Observations vs Hypotheses */}
              <div>
                <h4 style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
                  INTERPRETATION & REASONING:
                </h4>
                <p style={{ fontSize: '0.875rem', color: 'var(--text-primary)', lineHeight: 1.55 }}>
                  {report.interpretation}
                </p>
              </div>

              {/* Observed Evidence signals */}
              {report.observed_evidence?.length > 0 && (
                <div>
                  <h4 style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
                    OBSERVED EVIDENCE CITATIONS:
                  </h4>
                  <ul style={{ paddingLeft: '1.25rem', fontSize: '0.875rem', color: 'var(--text-primary)' }}>
                    {report.observed_evidence.map((ev, i) => {
                      if (typeof ev === 'string') {
                        return (
                          <li key={i} style={{ marginBottom: '0.35rem' }}>
                            {ev}
                          </li>
                        );
                      }
                      const obj = (ev && typeof ev === 'object' ? ev : {}) as Record<string, unknown>;
                      const label = obj.field_name || obj.signal_name;
                      const text = obj.description || obj.explanation || (obj.observed_value !== undefined ? `Value: ${String(obj.observed_value)}` : JSON.stringify(ev));
                      return (
                        <li key={i} style={{ marginBottom: '0.35rem' }}>
                          {Boolean(label) && <strong style={{ color: '#93c5fd' }}>{String(label)}: </strong>}
                          <span>{String(text)}</span>
                        </li>
                      );
                    })}
                  </ul>
                </div>
              )}

              {/* Possible Attack Techniques */}
              {report.possible_attack_techniques && report.possible_attack_techniques.length > 0 && (
                <div>
                  <h4 style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
                    POSSIBLE ATT&CK TECHNIQUES:
                  </h4>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
                    {report.possible_attack_techniques.map((t, i) => (
                      <span
                        key={i}
                        className="badge"
                        style={{
                          background: 'rgba(168, 85, 247, 0.15)',
                          color: '#c084fc',
                          border: '1px solid rgba(168, 85, 247, 0.3)',
                          fontSize: '0.75rem',
                        }}
                      >
                        {typeof t === 'string' ? t : JSON.stringify(t)}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Recommended Next Steps */}
              {report.recommended_next_steps?.length > 0 && (
                <div>
                  <h4 style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
                    RECOMMENDED INVESTIGATION STEPS (INFORMATIONAL):
                  </h4>
                  <ol style={{ paddingLeft: '1.25rem', fontSize: '0.875rem', color: 'var(--text-primary)' }}>
                    {report.recommended_next_steps.map((step, i) => (
                      <li key={i} style={{ marginBottom: '0.35rem' }}>
                        {typeof step === 'string' ? step : JSON.stringify(step)}
                      </li>
                    ))}
                  </ol>
                </div>
              )}

              {/* Uncertainty and Limitations */}
              {report.uncertainty && (
                <div className="banner banner-warning" style={{ marginBottom: 0, padding: '0.75rem 1rem' }}>
                  <HelpCircle size={18} style={{ flexShrink: 0 }} />
                  <div>
                    <strong>Uncertainty & Telemetry Limitations:</strong> {report.uncertainty}
                  </div>
                </div>
              )}

              {/* Report Limitations */}
              {report.limitations && report.limitations.length > 0 && (
                <div style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', background: 'var(--bg-tertiary)', padding: '0.75rem 1rem', borderRadius: '6px' }}>
                  <strong style={{ color: 'var(--text-secondary)', display: 'block', marginBottom: '0.25rem' }}>Report Constraints:</strong>
                  <ul style={{ paddingLeft: '1.25rem', margin: 0 }}>
                    {report.limitations.map((lim, i) => (
                      <li key={i} style={{ marginBottom: '0.2rem' }}>{typeof lim === 'string' ? lim : JSON.stringify(lim)}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* RAG Source Citations */}
              <div>
                <h4 style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.35rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                  <Database size={14} />
                  <span>SUPPORTING RAG KNOWLEDGE SOURCES ({report.citations?.length || 0}):</span>
                </h4>
                {report.citations?.length === 0 ? (
                  <div style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
                    No verified knowledge base citations returned for this investigation query.
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                    {report.citations?.map((cit) => {
                      const isExpanded = !!expandedCitations[cit.chunk_id];
                      const snippet = cit.relevant_text || cit.content;
                      return (
                        <div key={cit.chunk_id} className="citation-card">
                          <div
                            className="citation-header"
                            role="button"
                            tabIndex={0}
                            aria-expanded={isExpanded}
                            style={{ cursor: 'pointer', userSelect: 'none' }}
                            onClick={() => toggleCitation(cit.chunk_id)}
                            onKeyDown={(e) => {
                              if (e.key === 'Enter' || e.key === ' ') {
                                e.preventDefault();
                                toggleCitation(cit.chunk_id);
                              }
                            }}
                          >
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                              {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                              <span>{cit.source_title || 'Knowledge Source'}</span>
                              <span className="mono" style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                                [{cit.chunk_id}]
                              </span>
                            </div>
                            {cit.source_uri_or_path?.startsWith('http') && (
                              <a
                                href={cit.source_uri_or_path}
                                target="_blank"
                                rel="noreferrer"
                                onClick={(e) => e.stopPropagation()}
                                style={{ color: '#60a5fa', display: 'flex', alignItems: 'center', gap: '0.2rem' }}
                              >
                                <span>Ref</span>
                                <ExternalLink size={11} />
                              </a>
                            )}
                          </div>

                          {isExpanded && (
                            <div
                              style={{
                                marginTop: '0.625rem',
                                padding: '0.75rem',
                                background: 'var(--bg-primary)',
                                borderRadius: '6px',
                                border: '1px solid var(--border-subtle)',
                              }}
                            >
                              <div
                                style={{
                                  display: 'grid',
                                  gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
                                  gap: '0.5rem',
                                  marginBottom: snippet ? '0.75rem' : 0,
                                  fontSize: '0.75rem',
                                  paddingBottom: snippet ? '0.5rem' : 0,
                                  borderBottom: snippet ? '1px solid var(--border-subtle)' : 'none',
                                }}
                              >
                                <div>
                                  <span style={{ color: 'var(--text-muted)' }}>Document: </span>
                                  <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>
                                    {cit.document_title || cit.source_title}
                                  </span>
                                </div>
                                <div>
                                  <span style={{ color: 'var(--text-muted)' }}>Source ID: </span>
                                  <span className="mono" style={{ color: 'var(--text-secondary)' }}>
                                    {cit.source_id}
                                  </span>
                                </div>
                                {cit.source_uri_or_path && (
                                  <div style={{ gridColumn: '1 / -1' }}>
                                    <span style={{ color: 'var(--text-muted)' }}>Source Path/URI: </span>
                                    {cit.source_uri_or_path.startsWith('http') ? (
                                      <a
                                        href={cit.source_uri_or_path}
                                        target="_blank"
                                        rel="noreferrer"
                                        style={{ color: '#60a5fa', textDecoration: 'underline' }}
                                      >
                                        {cit.source_uri_or_path}
                                      </a>
                                    ) : (
                                      <span className="mono" style={{ color: 'var(--text-secondary)' }}>
                                        {cit.source_uri_or_path}
                                      </span>
                                    )}
                                  </div>
                                )}
                              </div>

                              {snippet ? (
                                <div>
                                  <div
                                    style={{
                                      fontSize: '0.7rem',
                                      color: 'var(--text-muted)',
                                      marginBottom: '0.35rem',
                                      textTransform: 'uppercase',
                                      letterSpacing: '0.04em',
                                      fontWeight: 600,
                                    }}
                                  >
                                    Grounded Knowledge Base Excerpt:
                                  </div>
                                  <div
                                    className="mono"
                                    style={{
                                      padding: '0.625rem',
                                      background: 'var(--bg-secondary)',
                                      borderRadius: '4px',
                                      fontSize: '0.75rem',
                                      color: 'var(--text-secondary)',
                                      lineHeight: 1.5,
                                      whiteSpace: 'pre-wrap',
                                      border: '1px solid var(--border-subtle)',
                                    }}
                                  >
                                    {snippet}
                                  </div>
                                </div>
                              ) : (
                                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                                  Verified knowledge citation recorded in agent retrieval state.
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div style={{ padding: '1rem', color: 'var(--text-secondary)', fontSize: '0.875rem' }}>
              <strong>Investigation concluded without structured report:</strong>{' '}
              {investigationResult.failure_reason || 'Insufficient corroborating telemetry.'}
            </div>
          )}
        </div>
      )}

      {/* Anomaly Classification Section */}
      {(() => {
        const char = alert.anomaly_characterization;
        const CATEGORY_LABELS: Record<string, string> = {
          OFF_HOURS_ACTIVITY: 'Off-Hours Operational Activity',
          REPEATED_FAILED_AUTHENTICATION: 'Repeated Failed Authentication',
          UNUSUAL_PROCESS_ACTIVITY: 'Unusual Process Execution',
          UNUSUAL_NETWORK_ACTIVITY: 'Unusual External Network Activity',
          UNUSUAL_OUTBOUND_DATA_ACTIVITY: 'Unusual Outbound Data Activity',
          MULTIPLE_BEHAVIORAL_ANOMALIES: 'Multiple Concurrent Behavioral Anomalies',
          UNCLASSIFIED_ANOMALY: 'Unclassified Statistical Anomaly',
        };

        return (
          <div className="card" style={{ marginBottom: '1.5rem', borderLeft: '4px solid #38bdf8' }}>
            <div className="card-title">
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span>ANOMALY CLASSIFICATION</span>
              </div>
              {char ? (
                <span
                  className="badge"
                  style={{
                    background:
                      char.classification_status === 'CHARACTERIZED'
                        ? 'rgba(56, 189, 248, 0.15)'
                        : char.classification_status === 'UNCLASSIFIED'
                        ? 'rgba(245, 158, 11, 0.15)'
                        : char.classification_status === 'INSUFFICIENT_EVIDENCE'
                        ? 'rgba(107, 114, 128, 0.2)'
                        : char.classification_status === 'SERVICE_ERROR'
                        ? 'rgba(239, 68, 68, 0.15)'
                        : 'rgba(16, 185, 129, 0.15)',
                    color:
                      char.classification_status === 'CHARACTERIZED'
                        ? '#38bdf8'
                        : char.classification_status === 'UNCLASSIFIED'
                        ? '#fbbf24'
                        : char.classification_status === 'INSUFFICIENT_EVIDENCE'
                        ? '#9ca3af'
                        : char.classification_status === 'SERVICE_ERROR'
                        ? '#f87171'
                        : '#34d399',
                    border: `1px solid ${
                      char.classification_status === 'CHARACTERIZED'
                        ? 'rgba(56, 189, 248, 0.3)'
                        : char.classification_status === 'UNCLASSIFIED'
                        ? 'rgba(245, 158, 11, 0.3)'
                        : char.classification_status === 'INSUFFICIENT_EVIDENCE'
                        ? 'rgba(107, 114, 128, 0.3)'
                        : char.classification_status === 'SERVICE_ERROR'
                        ? 'rgba(239, 68, 68, 0.3)'
                        : 'rgba(16, 185, 129, 0.3)'
                    }`,
                  }}
                >
                  {char.classification_status}
                </span>
              ) : (
                <span className="badge" style={{ background: 'rgba(107, 114, 128, 0.2)', color: '#9ca3af' }}>
                  CLASSIFICATION UNAVAILABLE
                </span>
              )}
            </div>

            {!char ? (
              <div style={{ color: 'var(--text-muted)', fontSize: '0.875rem', padding: '0.5rem 0' }}>
                Behavioral characterization was not generated for this alert record.
              </div>
            ) : char.classification_status === 'SERVICE_ERROR' ? (
              <div style={{ color: '#f87171', fontSize: '0.875rem', padding: '0.5rem 0' }}>
                <strong>Classification Service Failure:</strong> {char.explanation || char.summary}
              </div>
            ) : char.classification_status === 'INSUFFICIENT_EVIDENCE' ? (
              <div style={{ color: 'var(--text-secondary)', fontSize: '0.875rem', padding: '0.5rem 0' }}>
                <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.25rem' }}>
                  {char.summary}
                </div>
                <div style={{ marginBottom: '0.5rem' }}>{char.explanation}</div>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{char.uncertainty}</div>
              </div>
            ) : char.classification_status === 'NOT_ANOMALOUS' ? (
              <div style={{ color: 'var(--text-secondary)', fontSize: '0.875rem', padding: '0.5rem 0' }}>
                <div style={{ fontWeight: 600, color: '#34d399', marginBottom: '0.25rem' }}>
                  {char.summary}
                </div>
                <div>{char.explanation}</div>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                {/* Primary Category Banner */}
                <div
                  style={{
                    background: 'var(--bg-tertiary)',
                    padding: '1rem',
                    borderRadius: '6px',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.5rem',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', flexWrap: 'wrap' }}>
                      <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                        Primary Behavioral Category:
                      </span>
                      <strong style={{ fontSize: '1rem', color: '#fff' }}>
                        {CATEGORY_LABELS[char.primary_category] || char.primary_category}
                      </strong>
                      <span className="mono" style={{ fontSize: '0.75rem', color: '#38bdf8' }}>
                        ({char.primary_category})
                      </span>
                    </div>

                    {char.rule_ids?.length > 0 && (
                      <div className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        Rules: {char.rule_ids.join(', ')}
                      </div>
                    )}
                  </div>

                  {/* Additional categories if multiple */}
                  {char.additional_categories && char.additional_categories.length > 0 && (
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap', marginTop: '0.25rem' }}>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Additional Categories:</span>
                      {char.additional_categories.map((cat, i) => (
                        <span
                          key={i}
                          className="badge"
                          style={{
                            background: 'rgba(56, 189, 248, 0.1)',
                            color: '#7dd3fc',
                            border: '1px solid rgba(56, 189, 248, 0.25)',
                            fontSize: '0.7rem',
                          }}
                        >
                          {CATEGORY_LABELS[cat] || cat}
                        </span>
                      ))}
                    </div>
                  )}

                  <div style={{ fontSize: '0.875rem', color: 'var(--text-primary)', lineHeight: 1.5, marginTop: '0.25rem' }}>
                    {char.summary}
                  </div>
                </div>

                {/* Detailed Explanation */}
                <div>
                  <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.35rem', textTransform: 'uppercase' }}>
                    Observation Analysis:
                  </div>
                  <div style={{ fontSize: '0.875rem', color: 'var(--text-primary)', lineHeight: 1.55 }}>
                    {char.explanation}
                  </div>
                </div>

                {/* Supporting Signals Table */}
                {char.supporting_signals && char.supporting_signals.length > 0 && (
                  <div>
                    <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.5rem', textTransform: 'uppercase' }}>
                      Supporting Telemetry Signals ({char.supporting_signals.length}):
                    </div>
                    <div className="table-wrapper">
                      <table className="data-table">
                        <thead>
                          <tr>
                            <th>Signal Name</th>
                            <th>Field</th>
                            <th>Observed Value</th>
                            <th>Baseline Condition</th>
                            <th>Rule ID</th>
                            <th>Explanation</th>
                          </tr>
                        </thead>
                        <tbody>
                          {char.supporting_signals.map((sig, idx) => (
                            <tr key={idx}>
                              <td className="mono" style={{ fontWeight: 600, color: '#93c5fd' }}>
                                {sig.signal_name}
                              </td>
                              <td className="mono" style={{ color: 'var(--text-secondary)' }}>
                                {sig.source_field}
                              </td>
                              <td className="mono" style={{ color: '#fff', fontWeight: 700 }}>
                                {String(sig.observed_value)}
                              </td>
                              <td className="mono" style={{ color: 'var(--text-muted)' }}>
                                {sig.comparison} {String(sig.threshold_or_baseline)}
                              </td>
                              <td className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                                {sig.rule_id}
                              </td>
                              <td style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                                {sig.explanation}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {/* Uncertainty and Non-Proof Notice */}
                <div
                  style={{
                    background: 'rgba(255, 255, 255, 0.03)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: '6px',
                    padding: '0.75rem 1rem',
                    fontSize: '0.8rem',
                    color: 'var(--text-muted)',
                    lineHeight: 1.45,
                  }}
                >
                  <strong style={{ color: 'var(--text-secondary)' }}>Uncertainty Notice: </strong>
                  {char.uncertainty}
                  <div style={{ marginTop: '0.25rem', fontSize: '0.7rem' }}>
                    Characterization Version: {char.characterization_version}
                  </div>
                </div>
              </div>
            )}
          </div>
        );
      })()}

      {/* Detailed Analysis Tabs & Sections */}
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1.3fr) minmax(0, 1fr)', gap: '1.25rem', marginBottom: '1.5rem' }}>
        {/* Section A: Evidence Signals */}
        <div className="card">
          <div className="card-title">
            <span>OBSERVED EVIDENCE SIGNALS ({alert.evidence?.length || 0})</span>
          </div>

          {alert.evidence?.length === 0 ? (
            <div style={{ color: 'var(--text-muted)', padding: '1.5rem', textAlign: 'center' }}>
              No individual behavioral anomalies observed in this window.
            </div>
          ) : (
            <div className="table-wrapper">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Signal Name</th>
                    <th>Observed</th>
                    <th>Baseline/Rule</th>
                    <th>Score Contrib</th>
                    <th>Explanation</th>
                  </tr>
                </thead>
                <tbody>
                  {alert.evidence?.map((item, idx) => {
                    const contrib = item.contribution !== undefined ? item.contribution : item.score_contribution;
                    const ruleBaseline = item.comparison_or_rule || item.threshold_or_baseline;
                    const hasContrib = contrib !== null && contrib !== undefined;

                    return (
                      <tr key={idx}>
                        <td className="mono" style={{ fontWeight: 600, color: '#93c5fd' }}>
                          {item.signal_name}
                        </td>
                        <td className="mono" style={{ color: '#fff' }}>
                          {String(item.observed_value)}
                        </td>
                        <td className="mono" style={{ color: 'var(--text-muted)' }}>
                          {ruleBaseline !== null && ruleBaseline !== undefined
                            ? String(ruleBaseline)
                            : 'Unavailable'}
                        </td>
                        <td>
                          {hasContrib ? (
                            <span
                              className="mono"
                              style={{
                                fontWeight: 700,
                                color: Number(contrib) > 0 ? 'var(--sev-high)' : 'var(--text-muted)',
                              }}
                            >
                              +{Number(contrib).toFixed(1)}
                            </span>
                          ) : (
                            <span className="mono" style={{ color: 'var(--text-muted)' }}>
                              Unavailable
                            </span>
                          )}
                        </td>
                        <td style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                          {item.explanation || 'Signal threshold breached'}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Section B: Risk Score Breakdown */}
        <div className="card">
          <div className="card-title">
            <span>PHASE 3 RISK SCORE RECONCILIATION</span>
            <span className="mono" style={{ color: '#fff', fontWeight: 700 }}>
              {alert.risk_score.toFixed(2)} pts
            </span>
          </div>

          <div style={{ marginBottom: '1rem', fontSize: '0.8125rem', color: 'var(--text-secondary)', lineHeight: 1.45 }}>
            {alert.score_breakdown?.calculation_explanation ||
              'Composite risk formula combining Phase 2 Isolation Forest ML anomaly score and Phase 3 behavioral threshold violations.'}
          </div>

          {(() => {
            const components = (alert.score_breakdown?.components && alert.score_breakdown.components.length > 0)
              ? alert.score_breakdown.components
              : (alert.score_breakdown?.ml_anomaly
                  ? [alert.score_breakdown.ml_anomaly, ...(alert.score_breakdown.behavioral_components || [])]
                  : []);

            if (components.length > 0) {
              return (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
                  {components.map((c, i) => {
                    const compName = c.component_name || c.component || 'Component';
                    const formula = c.formula_reference || c.rule || '';
                    const hasContrib = c.contribution !== undefined && c.contribution !== null;

                    return (
                      <div
                        key={i}
                        style={{
                          background: 'var(--bg-tertiary)',
                          padding: '0.65rem 0.85rem',
                          borderRadius: '6px',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                        }}
                      >
                        <div>
                          <div style={{ fontWeight: 600, fontSize: '0.8125rem', color: 'var(--text-primary)' }}>
                            {compName}
                          </div>
                          {formula && (
                            <div className="mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                              {formula}
                            </div>
                          )}
                        </div>
                        <div className="mono" style={{ fontWeight: 700, color: '#38bdf8' }}>
                          {hasContrib ? `+${Number(c.contribution).toFixed(2)}` : 'Unavailable'}
                        </div>
                      </div>
                    );
                  })}
                </div>
              );
            }

            return (
              <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
                Breakdown components unavailable in alert response.
              </div>
            );
          })()}

          {alert.score_breakdown?.config_version && (
            <div style={{ marginTop: '0.875rem', fontSize: '0.7rem', color: 'var(--text-muted)' }} className="mono">
              Scoring Config Version: {alert.score_breakdown.config_version}
            </div>
          )}
        </div>
      </div>

      {/* Section C: Verified MITRE ATT&CK Context */}
      <div className="card">
        <div className="card-title">
          <span>VERIFIED MITRE ATT&CK CONTEXT</span>
          <span
            className="badge"
            style={{
              background:
                mitreCtx?.mapping_status === 'MAPPED'
                  ? 'rgba(168, 85, 247, 0.15)'
                  : 'rgba(107, 114, 128, 0.15)',
              color:
                mitreCtx?.mapping_status === 'MAPPED' ? '#c084fc' : 'var(--text-muted)',
              border: `1px solid ${
                mitreCtx?.mapping_status === 'MAPPED'
                  ? 'rgba(168, 85, 247, 0.3)'
                  : 'rgba(107, 114, 128, 0.3)'
              }`,
            }}
          >
            {mitreCtx?.mapping_status || 'NOT_MAPPED'}
          </span>
        </div>

        {candidate ? (
          <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1.2fr) minmax(0, 1.8fr)', gap: '1.25rem' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                <span className="mono" style={{ fontSize: '1.1rem', fontWeight: 700, color: '#c084fc' }}>
                  {candidate.technique_id}
                </span>
                <span style={{ fontSize: '1rem', fontWeight: 600 }}>{candidate.technique_name}</span>
                {candidate.url && (
                  <a
                    href={candidate.url}
                    target="_blank"
                    rel="noreferrer"
                    style={{ color: '#60a5fa', display: 'flex', alignItems: 'center' }}
                    title="Official MITRE ATT&CK documentation"
                  >
                    <ExternalLink size={14} />
                  </a>
                )}
              </div>

              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem', marginBottom: '0.75rem' }}>
                {candidate.tactics?.map((tac, i) => (
                  <span
                    key={i}
                    className="badge"
                    style={{
                      background: 'rgba(59, 130, 246, 0.12)',
                      color: '#93c5fd',
                      border: '1px solid rgba(59, 130, 246, 0.25)',
                      fontSize: '0.7rem',
                    }}
                  >
                    {tac}
                  </span>
                ))}
              </div>

              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Catalog Source: {candidate.catalog_source || 'MITRE Enterprise ATT&CK'}
                {candidate.catalog_version ? ` (v${candidate.catalog_version})` : ''}
              </div>
            </div>

            <div>
              <div style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.25rem' }}>
                MAPPING REASON:
              </div>
              <p style={{ fontSize: '0.875rem', color: 'var(--text-primary)', lineHeight: 1.5, marginBottom: '0.75rem' }}>
                {candidate.mapping_reason || 'Behavioral threshold violations correspond to known adversary tactics.'}
              </p>

              {candidate.supporting_evidence && candidate.supporting_evidence.length > 0 && (
                <div>
                  <div style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.25rem' }}>
                    SUPPORTING EVIDENCE SIGNALS:
                  </div>
                  <ul style={{ paddingLeft: '1.25rem', fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
                    {candidate.supporting_evidence.map((sig, i) => {
                      if (typeof sig === 'string') {
                        return <li key={i}>{sig}</li>;
                      }
                      if (sig && typeof sig === 'object') {
                        const s = sig as Record<string, unknown>;
                        const label = s.signal_name ? String(s.signal_name) : 'Signal';
                        const detail = s.explanation || s.comparison_or_rule || (s.observed_value !== undefined ? `value: ${String(s.observed_value)}` : '');
                        return (
                          <li key={i} style={{ marginBottom: '0.25rem' }}>
                            <strong style={{ color: '#93c5fd' }}>{label}:</strong>{' '}
                            <span style={{ color: 'var(--text-primary)' }}>{String(detail)}</span>
                          </li>
                        );
                      }
                      return <li key={i}>{String(sig)}</li>;
                    })}
                  </ul>
                </div>
              )}
            </div>
          </div>
        ) : (
          <div style={{ padding: '1rem', color: 'var(--text-muted)', fontSize: '0.875rem' }}>
            {mitreCtx?.mapping_status === 'INSUFFICIENT_EVIDENCE'
              ? 'Telemetry evidence does not meet confidence threshold for ATT&CK technique attribution.'
              : 'No verified MITRE ATT&CK technique was mapped to this alert by the deterministic Phase 4 rule catalog.'}
          </div>
        )}
      </div>
    </div>
  );
};
