import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { AlertDetailView } from '../components/AlertDetailView';
import { api } from '../services/api';

describe('AlertDetailView', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(api, 'getInvestigations').mockResolvedValue([]);
  });

  const sampleAlert = {
    alert_id: 'alt_WIN-201436_8db7ccda8a4f',
    window_id: 'WIN-201436',
    anomaly_score: 0.28,
    is_anomaly: 1,
    risk_score: 58.24,
    severity: 'MEDIUM' as const,
    evidence: [
      {
        signal_name: 'failed_logins_ratio',
        observed_value: 0.82,
        threshold_or_baseline: 0.15,
        score_contribution: 25.0,
        explanation: 'Elevated ratio of failed authentications',
      },
    ],
    score_breakdown: {
      total_risk_score: 58.24,
      components: [
        {
          component_name: 'ML Anomaly Signal',
          contribution: 23.24,
          formula_reference: 'IsolationForest * 40',
        },
        {
          component_name: 'Failed Logins Ratio',
          contribution: 35.0,
          formula_reference: 'Rule Baseline (p99)',
        },
      ],
      calculation_explanation: 'Composite formula combining ML and behavioral rules.',
      config_version: 'v1.0.0',
    },
    anomaly_characterization: {
      classification_status: 'CHARACTERIZED' as const,
      primary_category: 'REPEATED_FAILED_AUTHENTICATION' as const,
      additional_categories: [],
      summary: 'Repeated failed authentication attempts exceeding normal baseline.',
      supporting_signals: [
        {
          signal_name: 'failed_login_burst',
          source_field: 'failed_logins',
          observed_value: 12.0,
          threshold_or_baseline: 3.0,
          rule_id: 'RULE_CHAR_FAILED_AUTH',
          comparison: '>',
          explanation: 'Authentication failure count of 12 exceeded baseline threshold of 3.0.',
        },
      ],
      explanation: 'Observation window exhibited repeated failed authentication attempts.',
      uncertainty: 'Telemetry anomaly does not constitute proof of compromise.',
      rule_ids: ['RULE_CHAR_FAILED_AUTH'],
      characterization_version: 'v1.0.0',
    },
    mitre_context: {
      mapping_status: 'MAPPED',
      candidate_techniques: [
        {
          technique_id: 'T1110.001',
          technique_name: 'Password Guessing',
          tactics: ['Credential Access'],
          mapping_reason: 'High volume of failed authentications',
          supporting_evidence: ['failed_logins_ratio: 0.82'],
          catalog_source: 'MITRE Enterprise ATT&CK',
          catalog_version: 'v14.1',
          url: 'https://attack.mitre.org/techniques/T1110/001',
        },
      ],
    },
    created_at: '2026-10-09T08:00:00Z',
  };

  it('renders alert summary, evidence, and risk breakdown faithfully', async () => {
    vi.spyOn(api, 'getAlert').mockResolvedValue(sampleAlert);

    render(<AlertDetailView alertId="alt_WIN-201436_8db7ccda8a4f" onBack={vi.fn()} />);

    await waitFor(() => {
      expect(screen.getAllByText('alt_WIN-201436_8db7ccda8a4f').length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText(/58.24 \/ 100.0/i)).toBeTruthy();
      expect(screen.getByText('MEDIUM')).toBeTruthy();
      expect(screen.getByText('failed_logins_ratio')).toBeTruthy();
      expect(screen.getByText('+25.0')).toBeTruthy();
      expect(screen.getByText(/T1110.001/i)).toBeTruthy();
      expect(screen.getByText(/Password Guessing/i)).toBeTruthy();
      expect(screen.getByText('ANOMALY CLASSIFICATION')).toBeTruthy();
      expect(screen.getByText('Repeated Failed Authentication')).toBeTruthy();
    });
  });

  it('renders unclassified anomaly with explanation and uncertainty', async () => {
    const unclassifiedAlert = {
      ...sampleAlert,
      anomaly_characterization: {
        classification_status: 'UNCLASSIFIED' as const,
        primary_category: 'UNCLASSIFIED_ANOMALY' as const,
        additional_categories: [],
        summary: 'Statistical anomaly detected without distinct individual behavioral threshold breaches.',
        supporting_signals: [],
        explanation: 'Isolation Forest identified a statistical outlier based on multidimensional feature distribution.',
        uncertainty: 'Deviation is multidimensional. Manual analyst review is required.',
        rule_ids: [],
        characterization_version: 'v1.0.0',
      },
    };
    vi.spyOn(api, 'getAlert').mockResolvedValue(unclassifiedAlert);

    render(<AlertDetailView alertId="alt_WIN-201436_8db7ccda8a4f" onBack={vi.fn()} />);

    await waitFor(() => {
      expect(screen.getByText('ANOMALY CLASSIFICATION')).toBeTruthy();
      expect(screen.getByText('UNCLASSIFIED')).toBeTruthy();
      expect(screen.getByText(/Statistical anomaly detected without distinct individual behavioral threshold breaches/i)).toBeTruthy();
      expect(screen.getByText(/Manual analyst review is required/i)).toBeTruthy();
    });
  });

  it('triggers AI investigation and renders structured validated report', async () => {
    vi.spyOn(api, 'getAlert').mockResolvedValue(sampleAlert);
    vi.spyOn(api, 'investigateAlert').mockResolvedValue({
      investigation_id: 'inv_alt_WIN_001_chk',
      alert_id: sampleAlert.alert_id,
      status: 'SUCCESS',
      final_report: {
        investigation_id: 'inv_alt_WIN_001_chk',
        alert_id: sampleAlert.alert_id,
        summary: 'Observed failed login burst consistent with credential access.',
        supplied_severity: 'MEDIUM',
        supplied_risk_score: 58.24,
        finding: 'SUSPICIOUS_ACTIVITY',
        observed_evidence: ['Failed authentication ratio 0.82 exceeding baseline'],
        interpretation: 'Pattern indicates automated password guessing attempts.',
        possible_attack_techniques: ['T1110.001'],
        uncertainty: 'Origin IP addresses unverified in synthetic telemetry.',
        recommended_next_steps: ['Inspect source IP logs', 'Enforce MFA lockouts'],
        citations: [
          {
            source_title: 'MITRE ATT&CK T1110',
            source_id: 'mitre_t1110',
            chunk_id: 'chunk_mitre_001',
            source_uri_or_path: 'https://attack.mitre.org/techniques/T1110',
            relevant_text: 'Adversaries may use brute force techniques to attempt access.',
          },
        ],
      },
      execution_trace_summary: [],
      tool_call_count: 1,
      llm_call_count: 1,
      iteration_count: 2,
      elapsed_time: 12.5,
      warnings: [],
      failure_reason: null,
    });

    render(<AlertDetailView alertId="alt_WIN-201436_8db7ccda8a4f" onBack={vi.fn()} />);

    await waitFor(() => {
      expect(screen.getByText(/Investigate with AI/i)).toBeTruthy();
    });

    const investigateBtn = screen.getByRole('button', { name: /Investigate alert with local Qwen AI agent/i });
    fireEvent.click(investigateBtn);

    // Button should be disabled during investigation to prevent duplicate submissions
    expect(investigateBtn.hasAttribute('disabled')).toBe(true);

    await waitFor(() => {
      expect(screen.getByText(/AI INVESTIGATION REPORT/i)).toBeTruthy();
      expect(screen.getByText('SUSPICIOUS_ACTIVITY')).toBeTruthy();
      expect(screen.getByText(/Observed failed login burst consistent with credential access/i)).toBeTruthy();
      expect(screen.getByText(/Uncertainty & Telemetry Limitations/i)).toBeTruthy();
      expect(screen.getByText(/MITRE ATT&CK T1110/i)).toBeTruthy();
    });
  });

  it('prevents accidental duplicate investigation submissions', async () => {
    vi.spyOn(api, 'getAlert').mockResolvedValue(sampleAlert);
    let resolveInvestigate: (val: any) => void;
    const pendingPromise = new Promise((resolve) => {
      resolveInvestigate = resolve;
    });
    vi.spyOn(api, 'investigateAlert').mockReturnValue(pendingPromise as any);

    render(<AlertDetailView alertId="alt_WIN-201436_8db7ccda8a4f" onBack={vi.fn()} />);

    await waitFor(() => {
      expect(screen.getByText(/Investigate with AI/i)).toBeTruthy();
    });

    const investigateBtn = screen.getByRole('button', { name: /Investigate alert with local Qwen AI agent/i });
    fireEvent.click(investigateBtn);

    // Clicking again while investigating should not trigger another call
    fireEvent.click(investigateBtn);
    expect(api.investigateAlert).toHaveBeenCalledTimes(1);

    resolveInvestigate!({
      investigation_id: 'inv_1',
      alert_id: sampleAlert.alert_id,
      status: 'SUCCESS',
      final_report: null,
      execution_trace_summary: [],
      tool_call_count: 0,
      llm_call_count: 0,
      iteration_count: 0,
      elapsed_time: 1.0,
      warnings: [],
    });
  });
});
