import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { OverviewView } from '../components/OverviewView';
import { api } from '../services/api';

describe('OverviewView', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('renders synthetic data notice banner', async () => {
    vi.spyOn(api, 'getAlerts').mockResolvedValue({
      items: [],
      limit: 10,
      offset: 0,
      total: 0,
    });
    vi.spyOn(api, 'getReadiness').mockResolvedValue({
      status: 'ready',
      dependencies: {},
    });

    render(<OverviewView onSelectAlert={vi.fn()} onNavigateToAlerts={vi.fn()} />);

    expect(screen.getByText(/Synthetic Aggregated Behavioral Telemetry Notice/i)).toBeTruthy();
    expect(screen.getByText(/An anomaly score indicates unusual behavior, not confirmed compromise/i)).toBeTruthy();
  });

  it('renders summary severity counts calculated from API', async () => {
    vi.spyOn(api, 'getAlerts').mockImplementation(async (params) => {
      if (params?.severity === 'CRITICAL') {
        return { items: [], limit: 1, offset: 0, total: 3 };
      }
      if (params?.severity === 'HIGH') {
        return { items: [], limit: 1, offset: 0, total: 12 };
      }
      if (params?.severity === 'MEDIUM') {
        return { items: [], limit: 1, offset: 0, total: 25 };
      }
      if (params?.severity === 'LOW') {
        return { items: [], limit: 1, offset: 0, total: 60 };
      }
      return {
        items: [
          {
            alert_id: 'alt_test_01',
            window_id: 'win_100',
            anomaly_score: 0.65,
            is_anomaly: 1,
            risk_score: 82.5,
            severity: 'CRITICAL',
            evidence: [],
          },
        ],
        limit: 10,
        offset: 0,
        total: 100,
      };
    });

    vi.spyOn(api, 'getReadiness').mockResolvedValue({
      status: 'ready',
      dependencies: {
        ml_detector: { status: 'ready', message: 'ML model loaded' },
      },
    });

    render(<OverviewView onSelectAlert={vi.fn()} onNavigateToAlerts={vi.fn()} />);

    await waitFor(() => {
      expect(screen.getByText('100')).toBeTruthy(); // Total alerts
      expect(screen.getByText('3')).toBeTruthy();   // Critical alerts
      expect(screen.getByText('12')).toBeTruthy();  // High alerts
      expect(screen.getByText('25')).toBeTruthy();  // Medium alerts
      expect(screen.getByText('60')).toBeTruthy();  // Low alerts
    });

    expect(screen.getByText('alt_test_01')).toBeTruthy();
  });

  it('renders clean empty state when no alerts exist', async () => {
    vi.spyOn(api, 'getAlerts').mockResolvedValue({
      items: [],
      limit: 10,
      offset: 0,
      total: 0,
    });
    vi.spyOn(api, 'getReadiness').mockResolvedValue({
      status: 'ready',
      dependencies: {},
    });

    render(<OverviewView onSelectAlert={vi.fn()} onNavigateToAlerts={vi.fn()} />);

    await waitFor(() => {
      expect(screen.getByText(/No Alerts Available/i)).toBeTruthy();
      expect(screen.getByText(/The backend repository currently has 0 recorded alerts/i)).toBeTruthy();
    });
  });
});
