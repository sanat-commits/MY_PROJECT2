import React from 'react';
import { Lock, AlertTriangle } from 'lucide-react';

export const AboutView: React.FC = () => {
  return (
    <div style={{ maxWidth: '960px', margin: '0 auto' }}>
      <div style={{ marginBottom: '1.5rem' }}>
        <h1 style={{ fontSize: '1.5rem', fontWeight: 700, letterSpacing: '-0.02em' }}>
          About CYBER SENTINEL & Architecture
        </h1>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem' }}>
          Local-first AI-assisted security log anomaly detection and structured investigation platform
        </p>
      </div>

      {/* Cyber Truthfulness Notice */}
      <div className="banner banner-warning">
        <AlertTriangle size={24} style={{ flexShrink: 0 }} />
        <div>
          <strong style={{ fontSize: '0.95rem' }}>CYBERSECURITY TRUTHFULNESS & INVESTIGATION PRINCIPLE</strong>
          <p style={{ marginTop: '0.25rem', fontSize: '0.875rem', lineHeight: 1.5 }}>
            <strong>An anomaly is not proof of compromise.</strong> High anomaly scores and elevated risk ratings
            indicate statistical deviation from baseline operational telemetry, not confirmed malicious intrusion.
            The platform categorizes findings strictly into <em>anomalous</em>, <em>suspicious</em>, <em>possible</em>,
            and <em>requires investigation</em> to prevent false certainty.
          </p>
        </div>
      </div>

      {/* Synthetic Data Disclosure */}
      <div className="card" style={{ marginBottom: '1.25rem' }}>
        <div className="card-title">
          <span>TELEMETRY DATA SOURCE DISCLOSURE</span>
        </div>
        <p style={{ fontSize: '0.875rem', color: 'var(--text-primary)', lineHeight: 1.6, marginBottom: '0.75rem' }}>
          This evaluation environment operates over <strong>synthetic, 1-hour aggregated behavioral windows</strong>.
          It does not claim or imply active live monitoring of host operating systems, active EVTX event logs, Sysmon
          streams, or organizational network perimeters.
        </p>
        <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
          All hostnames, user accounts, and observed signal frequencies are generated deterministically for testing and
          calibrated model verification.
        </p>
      </div>

      {/* End-to-End Pipeline Architecture */}
      <div className="card" style={{ marginBottom: '1.25rem' }}>
        <div className="card-title">
          <span>PIPELINE SUBSYSTEMS ARCHITECTURE</span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', marginTop: '0.5rem' }}>
          <div style={{ display: 'flex', gap: '1rem', alignItems: 'flex-start' }}>
            <div
              style={{
                background: 'rgba(59, 130, 246, 0.15)',
                color: '#60a5fa',
                fontWeight: 700,
                fontSize: '0.8rem',
                padding: '0.3rem 0.6rem',
                borderRadius: '4px',
                minWidth: '70px',
                textAlign: 'center',
              }}
            >
              ML CORE
            </div>
            <div>
              <div style={{ fontWeight: 600, fontSize: '0.875rem', color: 'var(--text-primary)' }}>
                Phase 2: Baseline Isolation Forest Anomaly Detection
              </div>
              <div style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
                Trained strictly on normal-only windows using 17 numeric behavioral features. Calibrated operational
                threshold derived deterministically from the 95th percentile baseline score.
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '1rem', alignItems: 'flex-start' }}>
            <div
              style={{
                background: 'rgba(245, 158, 11, 0.15)',
                color: '#f59e0b',
                fontWeight: 700,
                fontSize: '0.8rem',
                padding: '0.3rem 0.6rem',
                borderRadius: '4px',
                minWidth: '70px',
                textAlign: 'center',
              }}
            >
              SCORING
            </div>
            <div>
              <div style={{ fontWeight: 600, fontSize: '0.875rem', color: 'var(--text-primary)' }}>
                Phase 3: Explainable Risk Scoring Engine
              </div>
              <div style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
                Bounded composite risk score (0 to 100) combining ML anomaly signals (40% max) and behavioral baseline
                threshold contributions (60% max). Guarantees mathematical component reconciliation.
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '1rem', alignItems: 'flex-start' }}>
            <div
              style={{
                background: 'rgba(168, 85, 247, 0.15)',
                color: '#c084fc',
                fontWeight: 700,
                fontSize: '0.8rem',
                padding: '0.3rem 0.6rem',
                borderRadius: '4px',
                minWidth: '70px',
                textAlign: 'center',
              }}
            >
              MITRE
            </div>
            <div>
              <div style={{ fontWeight: 600, fontSize: '0.875rem', color: 'var(--text-primary)' }}>
                Phase 4: Deterministic ATT&CK Catalog Mapping
              </div>
              <div style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
                Ingests official STIX 2.1 Enterprise ATT&CK objects (v14.1). Maps observable behavioral telemetry
                to verified technique IDs without LLM hallucination or arbitrary tagging.
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '1rem', alignItems: 'flex-start' }}>
            <div
              style={{
                background: 'rgba(16, 185, 129, 0.15)',
                color: '#10b981',
                fontWeight: 700,
                fontSize: '0.8rem',
                padding: '0.3rem 0.6rem',
                borderRadius: '4px',
                minWidth: '70px',
                textAlign: 'center',
              }}
            >
              RAG
            </div>
            <div>
              <div style={{ fontWeight: 600, fontSize: '0.875rem', color: 'var(--text-primary)' }}>
                Phase 5: Attributable Hybrid Knowledge Base
              </div>
              <div style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
                Combines ChromaDB dense embeddings with Okapi BM25 lexical search via Reciprocal Rank Fusion. Retains
                cryptographic chunk identifiers for strict citation traceability.
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '1rem', alignItems: 'flex-start' }}>
            <div
              style={{
                background: 'rgba(236, 72, 153, 0.15)',
                color: '#ec4899',
                fontWeight: 700,
                fontSize: '0.8rem',
                padding: '0.3rem 0.6rem',
                borderRadius: '4px',
                minWidth: '70px',
                textAlign: 'center',
              }}
            >
              AI AGENT
            </div>
            <div>
              <div style={{ fontWeight: 600, fontSize: '0.875rem', color: 'var(--text-primary)' }}>
                Phases 6 & 7: Local Qwen 3 8B & LangGraph Multi-Step Workflow
              </div>
              <div style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
                Bounded LangGraph state machine orchestrating evidence assessment, tool dispatching, and report
                synthesis using the local Qwen 3 8B model via Ollama. Application state and risk scores remain immutable.
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Security & Privacy Controls */}
      <div className="card">
        <div className="card-title">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Lock size={18} color="#10b981" />
            <span>SECURITY, PRIVACY & LOCAL-FIRST CONTROLS</span>
          </div>
        </div>
        <ul style={{ paddingLeft: '1.25rem', fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
          <li>
            <strong>Loopback Binding:</strong> Backend binds strictly to <code>127.0.0.1</code> to prevent exposing
            telemetry or inference endpoints across local networks.
          </li>
          <li>
            <strong>No Cloud Fallbacks:</strong> LLM inference executes strictly on the local hardware via Ollama. No
            prompts, telemetry, or reports are transmitted to external cloud providers.
          </li>
          <li>
            <strong>Immutable Alert State:</strong> Risk scores, severities, and anomaly predictions cannot be overwritten
            by clients or LLM outputs.
          </li>
          <li>
            <strong>Concurrency Bounds:</strong> AI investigations are serialized with a semaphore to safeguard local GPU/CPU
            memory against exhaustion.
          </li>
        </ul>
      </div>
    </div>
  );
};
