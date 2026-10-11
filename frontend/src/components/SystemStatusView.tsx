import React, { useEffect, useState } from 'react';
import { RefreshCw, AlertCircle } from 'lucide-react';
import { api, ApiError } from '../services/api';
import type { HealthResponse, ReadinessResponse, ModelStatusResponse } from '../types';


export const SystemStatusView: React.FC = () => {
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [readiness, setReadiness] = useState<ReadinessResponse | null>(null);
  const [modelStatus, setModelStatus] = useState<ModelStatusResponse | null>(null);

  const fetchStatus = async () => {
    setLoading(true);
    setError(null);
    try {
      const [h, r, m] = await Promise.all([
        api.getHealth().catch(() => ({ status: 'unavailable' })),
        api.getReadiness().catch(() => ({ status: 'unavailable', dependencies: {} })),
        api.getModelStatus().catch(() => ({
          provider: 'ollama',
          configured_model: 'qwen3:8b',
          availability: 'unavailable',
          last_check: new Date().toISOString(),
          error_code: 'Connection to local runtime failed',
        })),
      ]);
      setHealth(h);
      setReadiness(r);
      setModelStatus(m);
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        setError(`${err.message} (${err.code})`);
      } else {
        setError('Failed to poll system status endpoints.');
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  const getStatusBadge = (statusStr: string) => {
    const s = statusStr.toLowerCase();
    if (s === 'ok' || s === 'ready' || s === 'available') {
      return (
        <span
          className="badge"
          style={{
            background: 'var(--status-ready-bg)',
            color: 'var(--status-ready)',
            border: '1px solid rgba(16, 185, 129, 0.3)',
          }}
        >
          <span>{statusStr.toUpperCase()}</span>
        </span>
      );
    } else if (s === 'degraded') {
      return (
        <span
          className="badge"
          style={{
            background: 'var(--status-degraded-bg)',
            color: 'var(--status-degraded)',
            border: '1px solid rgba(245, 158, 11, 0.3)',
          }}
        >
          <span>DEGRADED</span>
        </span>
      );
    } else {
      return (
        <span
          className="badge"
          style={{
            background: 'var(--status-error-bg)',
            color: 'var(--status-error)',
            border: '1px solid rgba(239, 68, 68, 0.3)',
          }}
        >
          <span>{statusStr.toUpperCase()}</span>
        </span>
      );
    }
  };

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700, letterSpacing: '-0.02em' }}>System & Runtime Status</h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem' }}>
            Health, readiness probes, and local LLM runtime discovery from backend API
          </p>
        </div>
        <button
          className="btn btn-secondary"
          onClick={fetchStatus}
          disabled={loading}
          aria-label="Refresh system status"
        >
          <RefreshCw size={14} className={loading ? 'spinner' : ''} />
          <span>Refresh Status</span>
        </button>
      </div>

      {error && (
        <div className="banner banner-error" role="alert">
          <AlertCircle size={20} />
          <div>
            <strong>Status Check Error:</strong> {error}
          </div>
        </div>
      )}

      {/* Top Cards Grid */}
      <div className="stat-grid" style={{ marginBottom: '1.5rem' }}>
        {/* Backend API Liveness */}
        <div className="stat-card">
          <div className="card-title">
            <span>BACKEND API PROCESS</span>
          </div>
          <div>{getStatusBadge(health?.status || 'unavailable')}</div>
          <div className="stat-desc">FastAPI loopback server probe (/health)</div>
        </div>

        {/* Subsystem Readiness */}
        <div className="stat-card">
          <div className="card-title">
            <span>PIPELINE READINESS</span>
          </div>
          <div>{getStatusBadge(readiness?.status || 'unavailable')}</div>
          <div className="stat-desc">Upstream services & artifacts probe (/ready)</div>
        </div>

        {/* Local Qwen 3 8B Status */}
        <div className="stat-card">
          <div className="card-title">
            <span>LOCAL QWEN 3 8B</span>
          </div>
          <div>{getStatusBadge(modelStatus?.availability || 'unavailable')}</div>
          <div className="stat-desc">Runtime tag discovery (/status/model)</div>
        </div>
      </div>

      {/* Detailed Subsystems Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1.3fr) minmax(0, 1fr)', gap: '1.25rem' }}>
        {/* Subsystem Dependencies */}
        <div className="card">
          <div className="card-title">
            <span>DEPENDENCY HEALTH BREAKDOWN</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.875rem' }}>
            {readiness?.dependencies && Object.keys(readiness.dependencies).length > 0 ? (
              Object.entries(readiness.dependencies).map(([key, dep]) => {
                return (
                  <div
                    key={key}
                    style={{
                      background: 'var(--bg-tertiary)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: '6px',
                      padding: '0.875rem',
                      display: 'flex',
                      alignItems: 'flex-start',
                      justifyContent: 'space-between',
                      gap: '1rem',
                    }}
                  >
                    <div>
                      <div style={{ fontWeight: 600, fontSize: '0.875rem', color: 'var(--text-primary)' }}>
                        {key.replace(/_/g, ' ').toUpperCase()}
                      </div>
                      <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '0.15rem' }}>
                        {dep.message}
                      </div>
                      {dep.details && Object.keys(dep.details).length > 0 && (
                        <div
                          className="mono"
                          style={{
                            fontSize: '0.7rem',
                            color: 'var(--text-muted)',
                            marginTop: '0.35rem',
                          }}
                        >
                          {JSON.stringify(dep.details)}
                        </div>
                      )}
                    </div>
                    <div>{getStatusBadge(dep.status)}</div>
                  </div>
                );
              })
            ) : (
              <div style={{ color: 'var(--text-muted)', padding: '1rem' }}>No dependency statuses available.</div>
            )}
          </div>
        </div>

        {/* Local LLM Model Details */}
        <div className="card">
          <div className="card-title">
            <span>LOCAL LLM PROVIDER DETAILS</span>
          </div>

          {modelStatus ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div
                style={{
                  background: 'var(--bg-tertiary)',
                  padding: '1rem',
                  borderRadius: '6px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.65rem',
                  fontSize: '0.85rem',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Provider Backend:</span>
                  <span className="mono" style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                    {modelStatus.provider.toUpperCase()}
                  </span>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Configured Model:</span>
                  <span className="mono" style={{ fontWeight: 600, color: '#38bdf8' }}>
                    {modelStatus.configured_model}
                  </span>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Detected Runtime Model:</span>
                  <span className="mono" style={{ fontWeight: 600, color: '#c084fc' }}>
                    {modelStatus.detected_model || 'Not discovered'}
                  </span>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Availability:</span>
                  <span>{getStatusBadge(modelStatus.availability)}</span>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Last Check Time:</span>
                  <span className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                    {modelStatus.last_check ? new Date(modelStatus.last_check).toLocaleTimeString() : 'N/A'}
                  </span>
                </div>
              </div>

              {modelStatus.error_code && (
                <div className="banner banner-error" style={{ marginBottom: 0, padding: '0.75rem' }}>
                  <AlertCircle size={16} style={{ flexShrink: 0 }} />
                  <div style={{ fontSize: '0.75rem' }}>
                    <strong>Provider Diagnostic:</strong> {modelStatus.error_code}
                  </div>
                </div>
              )}

              <div style={{ fontSize: '0.775rem', color: 'var(--text-muted)', lineHeight: 1.45 }}>
                Status queries use lightweight Ollama tag inspection (<code>/api/tags</code>) to discover installed
                weights without triggering expensive model evaluation on CPU/GPU.
              </div>
            </div>
          ) : (
            <div style={{ color: 'var(--text-muted)' }}>Model status not available.</div>
          )}
        </div>
      </div>
    </div>
  );
};
