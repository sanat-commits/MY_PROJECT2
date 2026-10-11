import React, { useEffect, useState, useMemo } from 'react';
import { api, ApiError } from '../services/api';
import type { SecurityAlert, SeverityLevel } from '../types';
import { SeverityBadge } from './SeverityBadge';
import {
  Search,
  RefreshCw,
  ChevronLeft,
  ChevronRight,
  AlertCircle,
  FileQuestion,
  Filter,
} from 'lucide-react';

interface AlertsViewProps {
  onSelectAlert: (alertId: string) => void;
  initialSeverityFilter?: string;
}

export const AlertsView: React.FC<AlertsViewProps> = ({
  onSelectAlert,
  initialSeverityFilter = '',
}) => {
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Pagination & Filtering state
  const [page, setPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(15);
  const [severityFilter, setSeverityFilter] = useState<string>(initialSeverityFilter);
  const [searchTerm, setSearchTerm] = useState<string>('');

  const fetchAlerts = async () => {
    setLoading(true);
    setError(null);
    try {
      const offset = (page - 1) * pageSize;
      const res = await api.getAlerts({
        limit: pageSize,
        offset,
        severity: (severityFilter || undefined) as SeverityLevel | undefined,
      });
      setAlerts(res.items);
      setTotal(res.total);
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        setError(`${err.message} (${err.code})`);
      } else {
        setError('Failed to fetch security alerts from the backend API.');
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, [page, pageSize, severityFilter]);

  // Client-side search filtering within the paginated batch
  const displayedAlerts = useMemo(() => {
    if (!searchTerm.trim()) return alerts;
    const term = searchTerm.toLowerCase().trim();
    return alerts.filter(
      (a) =>
        a.alert_id.toLowerCase().includes(term) ||
        a.window_id.toLowerCase().includes(term) ||
        a.mitre_context?.candidate_techniques?.some((t) =>
          t.technique_id.toLowerCase().includes(term) || t.technique_name.toLowerCase().includes(term)
        )
    );
  }, [alerts, searchTerm]);

  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700, letterSpacing: '-0.02em' }}>Security Alerts</h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem' }}>
            Behavioral anomaly detections evaluated and scored against baseline telemetry
          </p>
        </div>
        <button
          className="btn btn-secondary"
          onClick={fetchAlerts}
          disabled={loading}
          aria-label="Refresh alerts table"
        >
          <RefreshCw size={14} className={loading ? 'spinner' : ''} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="filter-bar">
        <div className="filter-group">
          {/* Search Box */}
          <div style={{ position: 'relative', minWidth: '280px' }}>
            <Search
              size={15}
              style={{
                position: 'absolute',
                left: '0.75rem',
                top: '50%',
                transform: 'translateY(-50%)',
                color: 'var(--text-muted)',
              }}
            />
            <input
              type="text"
              className="input"
              placeholder="Search by Alert ID, Window ID, or Technique..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{ paddingLeft: '2.25rem', width: '100%' }}
              aria-label="Search alerts"
            />
          </div>

          {/* Severity Filter */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Filter size={15} color="var(--text-muted)" />
            <select
              className="select"
              value={severityFilter}
              onChange={(e) => {
                setSeverityFilter(e.target.value);
                setPage(1); // Reset to page 1 on filter change
              }}
              aria-label="Filter by severity"
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>
        </div>

        {/* Page size selector */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
          <span>Per Page:</span>
          <select
            className="select"
            value={pageSize}
            onChange={(e) => {
              setPageSize(Number(e.target.value));
              setPage(1);
            }}
            style={{ padding: '0.25rem 0.5rem' }}
          >
            <option value={10}>10</option>
            <option value={15}>15</option>
            <option value={25}>25</option>
            <option value={50}>50</option>
          </select>
        </div>
      </div>

      {/* Error state */}
      {error && (
        <div className="banner banner-error" role="alert">
          <AlertCircle size={20} />
          <div>
            <strong>Failed to retrieve alerts:</strong> {error}
          </div>
        </div>
      )}

      {/* Table & Empty States */}
      <div className="table-wrapper">
        <table className="data-table">
          <thead>
            <tr>
              <th>Alert Identifier</th>
              <th>Window ID</th>
              <th>Severity</th>
              <th>Risk Score</th>
              <th>Anomaly Score</th>
              <th>ATT&CK Context</th>
              <th>Created At</th>
              <th style={{ textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={8} style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)' }}>
                  <div className="spinner" style={{ margin: '0 auto 0.75rem' }} />
                  Loading alerts from backend API...
                </td>
              </tr>
            ) : displayedAlerts.length === 0 ? (
              <tr>
                <td colSpan={8} style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)' }}>
                  <FileQuestion size={36} color="var(--text-muted)" style={{ margin: '0 auto 0.5rem' }} />
                  <div style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>
                    {searchTerm ? 'No alerts match your search query.' : 'No alerts recorded in this filter view.'}
                  </div>
                  <div style={{ fontSize: '0.75rem', marginTop: '0.25rem' }}>
                    {searchTerm ? 'Try adjusting your search criteria.' : 'Check back when backend produces additional alert events.'}
                  </div>
                </td>
              </tr>
            ) : (
              displayedAlerts.map((alert) => {
                const mitreCtx = alert.attack_context || alert.mitre_context;
                const candidate = mitreCtx?.candidate_techniques?.[0];
                return (
                  <tr
                    key={alert.alert_id}
                    className="clickable"
                    onClick={() => onSelectAlert(alert.alert_id)}
                  >
                    <td className="mono" style={{ fontWeight: 600, color: '#60a5fa' }}>
                      {alert.alert_id}
                    </td>
                    <td className="mono" style={{ color: 'var(--text-secondary)' }}>
                      {alert.window_id}
                    </td>
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
                        <span className="mono" style={{ fontWeight: 600 }}>{alert.risk_score.toFixed(1)}</span>
                      </div>
                    </td>
                    <td>
                      <span className="mono" style={{ color: alert.is_anomaly ? '#f87171' : 'var(--text-secondary)' }}>
                        {alert.anomaly_score.toFixed(3)}
                      </span>
                    </td>
                    <td>
                      {candidate ? (
                        <span
                          className="mono"
                          style={{
                            fontSize: '0.75rem',
                            padding: '0.15rem 0.4rem',
                            background: 'rgba(168, 85, 247, 0.1)',
                            border: '1px solid rgba(168, 85, 247, 0.25)',
                            borderRadius: '4px',
                            color: '#c084fc',
                          }}
                          title={candidate.mapping_reason || candidate.technique_name}
                        >
                          {candidate.technique_id} ({candidate.technique_name})
                        </span>
                      ) : (
                        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                          {mitreCtx?.mapping_status === 'INSUFFICIENT_EVIDENCE'
                            ? 'Insufficient evidence'
                            : 'Not mapped'}
                        </span>
                      )}
                    </td>
                    <td className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      {alert.created_at ? new Date(alert.created_at).toLocaleString() : 'N/A'}
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <button
                        className="btn btn-secondary"
                        style={{ padding: '0.25rem 0.65rem', fontSize: '0.75rem' }}
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectAlert(alert.alert_id);
                        }}
                      >
                        Details
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>

        {/* Server Pagination Bar */}
        <div className="pagination">
          <div>
            Showing <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{displayedAlerts.length}</span> of{' '}
            <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{total}</span> total alerts
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <span>
              Page <strong style={{ color: 'var(--text-primary)' }}>{page}</strong> of{' '}
              <strong style={{ color: 'var(--text-primary)' }}>{totalPages}</strong>
            </span>
            <button
              className="btn btn-secondary"
              style={{ padding: '0.25rem 0.5rem' }}
              disabled={page <= 1 || loading}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              aria-label="Previous page"
            >
              <ChevronLeft size={16} />
            </button>
            <button
              className="btn btn-secondary"
              style={{ padding: '0.25rem 0.5rem' }}
              disabled={page >= totalPages || loading}
              onClick={() => setPage((p) => p + 1)}
              aria-label="Next page"
            >
              <ChevronRight size={16} />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
