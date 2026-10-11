import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { AlertsView } from '../components/AlertsView';
import { api } from '../services/api';

describe('AlertsView', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  const sampleAlerts = [
    {
      alert_id: 'alt_win_001',
      window_id: 'win_101',
      anomaly_score: 0.72,
      is_anomaly: 1,
      risk_score: 88.0,
      severity: 'CRITICAL' as const,
      evidence: [],
      mitre_context: {
        mapping_status: 'MAPPED',
        candidate_techniques: [
          {
            technique_id: 'T1110.001',
            technique_name: 'Password Guessing',
            tactics: ['Credential Access'],
          },
        ],
      },
      created_at: '2026-10-09T08:00:00Z',
    },
    {
      alert_id: 'alt_win_002',
      window_id: 'win_102',
      anomaly_score: 0.35,
      is_anomaly: 0,
      risk_score: 42.0,
      severity: 'MEDIUM' as const,
      evidence: [],
      mitre_context: {
        mapping_status: 'NOT_MAPPED',
        candidate_techniques: [],
      },
      created_at: '2026-10-09T08:05:00Z',
    },
  ];

  it('renders alerts table rows from API data', async () => {
    vi.spyOn(api, 'getAlerts').mockResolvedValue({
      items: sampleAlerts,
      limit: 15,
      offset: 0,
      total: 2,
    });

    render(<AlertsView onSelectAlert={vi.fn()} />);

    await waitFor(() => {
      expect(screen.getByText('alt_win_001')).toBeTruthy();
      expect(screen.getByText('alt_win_002')).toBeTruthy();
      expect(screen.getByText('CRITICAL')).toBeTruthy();
      expect(screen.getByText('MEDIUM')).toBeTruthy();
      expect(screen.getByText(/T1110.001/i)).toBeTruthy();
    });
  });

  it('filters by search input without crashing', async () => {
    vi.spyOn(api, 'getAlerts').mockResolvedValue({
      items: sampleAlerts,
      limit: 15,
      offset: 0,
      total: 2,
    });

    render(<AlertsView onSelectAlert={vi.fn()} />);

    await waitFor(() => {
      expect(screen.getByText('alt_win_001')).toBeTruthy();
    });

    const searchInput = screen.getByLabelText(/Search alerts/i);
    fireEvent.change(searchInput, { target: { value: 'win_001' } });

    expect(screen.getByText('alt_win_001')).toBeTruthy();
    expect(screen.queryByText('alt_win_002')).toBeNull();
  });

  it('displays empty search result state when no match is found', async () => {
    vi.spyOn(api, 'getAlerts').mockResolvedValue({
      items: sampleAlerts,
      limit: 15,
      offset: 0,
      total: 2,
    });

    render(<AlertsView onSelectAlert={vi.fn()} />);

    await waitFor(() => {
      expect(screen.getByText('alt_win_001')).toBeTruthy();
    });

    const searchInput = screen.getByLabelText(/Search alerts/i);
    fireEvent.change(searchInput, { target: { value: 'nonexistent_alert_id' } });

    expect(screen.getByText(/No alerts match your search query/i)).toBeTruthy();
  });

  it('handles clicking row to trigger onSelectAlert', async () => {
    const handleSelect = vi.fn();
    vi.spyOn(api, 'getAlerts').mockResolvedValue({
      items: sampleAlerts,
      limit: 15,
      offset: 0,
      total: 2,
    });

    render(<AlertsView onSelectAlert={handleSelect} />);

    await waitFor(() => {
      expect(screen.getByText('alt_win_001')).toBeTruthy();
    });

    fireEvent.click(screen.getByText('alt_win_001'));
    expect(handleSelect).toHaveBeenCalledWith('alt_win_001');
  });
});
