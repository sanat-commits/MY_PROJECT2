import React, { useEffect, useState } from 'react';
import { api, ApiError } from '../services/api';
import type { SecurityAlert, ReadinessResponse } from '../types';
import { SeverityBadge } from './SeverityBadge';
import {
  AlertCircle,
  ArrowRight,
  RefreshCw,
  CheckCircle2,
  HelpCircle,
} from 'lucide-react';

interface OverviewViewProps {
  onSelectAlert: (alertId: string) => void;
  onNavigateToAlerts: (severityFilter?: string) => void;
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  onSelectAlert,
  onNavigateToAlerts,
}) => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [totalAlerts, setTotalAlerts] = useState<number>(0);
  const [severityCounts, setSeverityCounts] = useState<{
    CRITICAL: number;
    HIGH: number;
    MEDIUM: number;
    LOW: number;
  }>({ CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 });
  const [recentAlerts, setRecentAlerts] = useState<SecurityAlert[]>([]);
  const [readiness, setReadiness] = useState<ReadinessResponse | null>(null);

  const fetchOverviewData = async () => {
    setLoading(true);
    setError(null);
    try {
      // 1. Fetch alert counts and recent items from real backend API
      // Query with limit=100 to get representative totals from current evaluation batch
      const [allAlertsRes, criticalRes, highRes, mediumRes, lowRes, readyRes] = await Promise.all([
        api.getAlerts({ limit: 10, offset: 0 }),
        api.getAlerts({ severity: 'CRITICAL', limit: 1 }),
        api.getAlerts({ severity: 'HIGH', limit: 1 }),
        api.getAlerts({ severity: 'MEDIUM', limit: 1 }),
        api.getAlerts({ severity: 'LOW', limit: 1 }),
        api.getReadiness().catch(() => null),
      ]);

      setTotalAlerts(allAlertsRes.total);
      setRecentAlerts(allAlertsRes.items);
      setSeverityCounts({
        CRITICAL: criticalRes.total,
        HIGH: highRes.total,
        MEDIUM: mediumRes.total,
        LOW: lowRes.total,
      });
      setReadiness(readyRes);
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        setError(`Failed to load overview data: ${err.message} (${err.code})`);
      } else {
        setError('An unexpected error occurred while communicating with the backend API.');
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchOverviewData();
  }, []);

  return (
    <div>
      {/* Synthetic Data Disclaimer Banner */}
      <div className="banner banner-info" role="region" aria-label="Data Source Notice">
        <HelpCircle size={20} style={{ flexShrink: 0, marginTop: '2px' }} />
        <div>
          <strong>Synthetic Aggregated Behavioral Telemetry Notice:</strong> The alerts and scores shown in this
          dashboard are computed over synthetic 1-hour behavioral windows generated for evaluation.
          <em> An anomaly score indicates unusual behavior, not confirmed compromise.</em> All findings require analyst
          verification.
        </div>
      </div>

      {/* Header bar */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700, letterSpacing: '-0.02em' }}>Security Operations Overview</h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem' }}>
            Real-time status of prioritized log anomalies and automated investigations
          </p>
        </div>
        <button
          className="btn btn-secondary"
          onClick={fetchOverviewData}
          disabled={loading}
          aria-label="Refresh overview data"
        >
          <RefreshCw size={14} className={loading ? 'spinner' : ''} />
          <span>Refresh</span>
        </button>
      </div>

      {error && (
        <div className="banner banner-error" role="alert">
          <AlertCircle size={20} />
          <div>
            <strong>Error connecting to backend:</strong> {error}
          </div>
        </div>
      )}

      {/* Summary KPI Cards */}
      <div className="stat-grid">
        <div
          className="stat-card"
          style={{ cursor: 'pointer', borderLeft: '4px solid #3b82f6' }}
          onClick={() => onNavigateToAlerts()}
          tabIndex={0}
          role="button"
        >
          <div className="card-title">
            <span>TOTAL ALERTS</span>
          </div>
          <div className="stat-val">{loading ? '-' : totalAlerts}</div>
          <div className="stat-desc">All evaluated behavioral windows</div>
        </div>

        <div
          className="stat-card"
          style={{ cursor: 'pointer', borderLeft: '4px solid var(--sev-critical)' }}
          onClick={() => onNavigateToAlerts('CRITICAL')}
          tabIndex={0}
          role="button"
        >
          <div className="card-title">
            <span style={{ color: 'var(--sev-critical)' }}>CRITICAL</span>
          </div>
          <div className="stat-val">{loading ? '-' : severityCounts.CRITICAL}</div>
          <div className="stat-desc">Risk score ≥ 80 with behavioral corroboration</div>
        </div>

        <div
          className="stat-card"
          style={{ cursor: 'pointer', borderLeft: '4px solid var(--sev-high)' }}
          onClick={() => onNavigateToAlerts('HIGH')}
          tabIndex={0}
          role="button"
        >
          <div className="card-title">
            <span style={{ color: 'var(--sev-high)' }}>HIGH</span>
          </div>
          <div className="stat-val">{loading ? '-' : severityCounts.HIGH}</div>
          <div className="stat-desc">Risk score 60 – 79.99</div>
        </div>

        <div
          className="stat-card"
          style={{ cursor: 'pointer', borderLeft: '4px solid var(--sev-medium)' }}
          onClick={() => onNavigateToAlerts('MEDIUM')}
          tabIndex={0}
          role="button"
        >
          <div className="card-title">
            <span style={{ color: 'var(--sev-medium)' }}>MEDIUM</span>
          </div>
          <div className="stat-val">{loading ? '-' : severityCounts.MEDIUM}</div>
          <div className="stat-desc">Risk score 35 – 59.99</div>
        </div>

        <div
          className="stat-card"
          style={{ cursor: 'pointer', borderLeft: '4px solid var(--sev-low)' }}
          onClick={() => onNavigateToAlerts('LOW')}
          tabIndex={0}
          role="button"
        >
          <div className="card-title">
            <span style={{ color: 'var(--sev-low)' }}>LOW</span>
          </div>
          <div className="stat-val">{loading ? '-' : severityCounts.LOW}</div>
          <div className="stat-desc">Risk score &lt; 35</div>
        </div>
      </div>

      {/* Grid: Recent Alerts + System Readiness */}
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 2fr) minmax(0, 1fr)', gap: '1.25rem' }}>
        {/* Recent Alerts Panel */}
        <div className="card">
          <div className="card-title">
            <span>PRIORITIZED ALERTS</span>
            <button
              className="btn btn-secondary"
              style={{ fontSize: '0.75rem', padding: '0.25rem 0.5rem' }}
              onClick={() => onNavigateToAlerts()}
            >
              <span>View All</span>
              <ArrowRight size={12} />
            </button>
          </div>

          {loading ? (
            <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>
              <div className="spinner" style={{ margin: '0 auto 0.5rem' }} />
              Loading alerts from backend...
            </div>
          ) : recentAlerts.length === 0 ? (
            <div style={{ padding: '2.5rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
              <CheckCircle2 size={36} color="var(--status-ready)" style={{ margin: '0 auto 0.75rem' }} />
              <h3 style={{ fontSize: '1rem', fontWeight: 600 }}>No Alerts Available</h3>
              <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                The backend repository currently has 0 recorded alerts. Newly detected behavioral anomalies will appear
                here automatically.
              </p>
            </div>
          ) : (
            <div className="table-wrapper">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Alert ID</th>
                    <th>Severity</th>
                    <th>Risk Score</th>
                    <th>Anomaly</th>
                    <th>Technique</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {recentAlerts.map((alert) => {
                    const tech = (alert.attack_context || alert.mitre_context)?.candidate_techniques?.[0];
                    return (
                      <tr
                        key={alert.alert_id}
                        className="clickable"
                        onClick={() => onSelectAlert(alert.alert_id)}
                      >
                        <td className="mono" style={{ color: '#60a5fa' }}>{alert.alert_id}</td>
                        <td>
                          <SeverityBadge severity={alert.severity} size="sm" />
                        </td>
                        <td>
                          <div style={{ display: 'flex', alignItems: 'center' }}>
                            <div className="risk-bar-container">
                              <div
                                className="risk-bar-fill"
                                style={{
                                  width: `${Math.min(100, alert.risk_score)}%`,
                                  background:
                                    alert.severity === 'CRITICAL'
                                      ? 'var(--sev-critical)'
                                      : alert.severity === 'HIGH'
                                      ? 'var(--sev-high)'
                                      : alert.severity === 'MEDIUM'
                                      ? 'var(--sev-medium)'
                                      : 'var(--sev-low)',
                                }}
                              />
                            </div>
                            <span className="mono">{alert.risk_score.toFixed(1)}</span>
                          </div>
                        </td>
                        <td>
                          <span
                            className="badge"
                            style={{
                              background: alert.is_anomaly ? 'rgba(239, 68, 68, 0.15)' : 'rgba(16, 185, 129, 0.15)',
                              color: alert.is_anomaly ? '#f87171' : '#34d399',
                              border: `1px solid ${alert.is_anomaly ? 'rgba(239, 68, 68, 0.3)' : 'rgba(16, 185, 129, 0.3)'}`,
                            }}
                          >
                            {alert.is_anomaly ? 'ANOMALOUS' : 'NORMAL'}
                          </span>
                        </td>
                        <td className="mono" style={{ fontSize: '0.75rem', color: tech ? '#c084fc' : 'var(--text-muted)' }}>
                          {tech ? `${tech.technique_id} - ${tech.technique_name}` : 'Not mapped'}
                        </td>
                        <td>
                          <button
                            className="btn btn-secondary"
                            style={{ padding: '0.2rem 0.5rem', fontSize: '0.75rem' }}
                            onClick={(e) => {
                              e.stopPropagation();
                              onSelectAlert(alert.alert_id);
                            }}
                          >
                            Inspect
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* System Readiness Quick Card */}
        <div className="card">
          <div className="card-title">
            <span>SUBSYSTEM READINESS</span>
            <span
              className="badge"
              style={{
                background: readiness?.status === 'ready' ? 'var(--status-ready-bg)' : 'var(--status-degraded-bg)',
                color: readiness?.status === 'ready' ? 'var(--status-ready)' : 'var(--status-degraded)',
                border: `1px solid ${readiness?.status === 'ready' ? 'rgba(16, 185, 129, 0.3)' : 'rgba(245, 158, 11, 0.3)'}`,
              }}
            >
              {readiness?.status?.toUpperCase() || 'UNKNOWN'}
            </span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginTop: '0.5rem' }}>
            {readiness?.dependencies ? (
              Object.entries(readiness.dependencies).map(([depKey, dep]) => {
                const isReady = dep.status === 'ready';
                return (
                  <div
                    key={depKey}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '0.5rem 0.75rem',
                      background: 'var(--bg-tertiary)',
                      borderRadius: '6px',
                      fontSize: '0.8125rem',
                    }}
                  >
                    <div>
                      <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                        {depKey.replace(/_/g, ' ').toUpperCase()}
                      </div>
                      <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{dep.message}</div>
                    </div>
                    <span
                      style={{
                        color: isReady ? 'var(--status-ready)' : 'var(--status-error)',
                        fontWeight: 700,
                        fontSize: '0.75rem',
                      }}
                    >
                      {dep.status.toUpperCase()}
                    </span>
                  </div>
                );
              })
            ) : (
              <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
                Readiness check pending or disconnected.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
