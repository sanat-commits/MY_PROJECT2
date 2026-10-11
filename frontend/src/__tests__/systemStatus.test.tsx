import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { SystemStatusView } from '../components/SystemStatusView';
import { api } from '../services/api';

describe('SystemStatusView', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('renders health, readiness and model status data from API', async () => {
    vi.spyOn(api, 'getHealth').mockResolvedValue({ status: 'ok' });
    vi.spyOn(api, 'getReadiness').mockResolvedValue({
      status: 'ready',
      dependencies: {
        ml_detector: { status: 'ready', message: 'Isolation forest model loaded' },
        risk_engine: { status: 'ready', message: 'Risk scoring config verified' },
        local_llm_runtime: { status: 'ready', message: 'Ollama local daemon responsive' },
      },
    });
    vi.spyOn(api, 'getModelStatus').mockResolvedValue({
      provider: 'ollama',
      configured_model: 'qwen3:8b',
      detected_model: 'qwen3:8b',
      availability: 'available',
      last_check: '2026-10-09T08:00:00Z',
      error_code: null,
    });

    render(<SystemStatusView />);

    await waitFor(() => {
      expect(screen.getByText('BACKEND API PROCESS')).toBeTruthy();
      expect(screen.getByText('PIPELINE READINESS')).toBeTruthy();
      expect(screen.getByText('LOCAL QWEN 3 8B')).toBeTruthy();
      expect(screen.getByText(/Isolation forest model loaded/i)).toBeTruthy();
      expect(screen.getAllByText('qwen3:8b').length).toBeGreaterThanOrEqual(1);
    });
  });

  it('renders model unavailable state accurately without crashing', async () => {
    vi.spyOn(api, 'getHealth').mockResolvedValue({ status: 'ok' });
    vi.spyOn(api, 'getReadiness').mockResolvedValue({
      status: 'degraded',
      dependencies: {
        local_llm_runtime: { status: 'unavailable', message: 'Ollama daemon unreachable' },
      },
    });
    vi.spyOn(api, 'getModelStatus').mockResolvedValue({
      provider: 'ollama',
      configured_model: 'qwen3:8b',
      detected_model: null,
      availability: 'unavailable',
      last_check: '2026-10-09T08:00:00Z',
      error_code: 'Connection refused on localhost:11434',
    });

    render(<SystemStatusView />);

    await waitFor(() => {
      expect(screen.getByText('DEGRADED')).toBeTruthy();
      expect(screen.getByText(/Connection refused on localhost:11434/i)).toBeTruthy();
    });
  });
});
