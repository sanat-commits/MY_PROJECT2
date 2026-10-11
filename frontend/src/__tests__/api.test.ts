import { describe, it, expect, vi, beforeEach } from 'vitest';
import { api, ApiError } from '../services/api';

describe('ApiService', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('constructs correct base URL', () => {
    expect(api.getBaseUrl()).toBeTruthy();
  });

  it('fetches health status successfully', async () => {
    const mockHealth = { status: 'ok' };
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
      ok: true,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => mockHealth,
    } as Response);

    const res = await api.getHealth();
    expect(res).toEqual(mockHealth);
  });

  it('fetches paginated alerts with query parameters', async () => {
    const mockAlerts = {
      items: [
        {
          alert_id: 'alt_1',
          window_id: 'win_1',
          anomaly_score: 0.8,
          is_anomaly: 1,
          risk_score: 85.0,
          severity: 'CRITICAL',
          evidence: [],
        },
      ],
      limit: 10,
      offset: 0,
      total: 1,
    };

    let requestedUrl = '';
    vi.spyOn(globalThis, 'fetch').mockImplementationOnce(async (url) => {
      requestedUrl = String(url);
      return {
        ok: true,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: async () => mockAlerts,
      } as Response;
    });

    const res = await api.getAlerts({ limit: 10, offset: 0, severity: 'CRITICAL' });
    expect(requestedUrl).toContain('/alerts?limit=10&offset=0&severity=CRITICAL');
    expect(res.total).toBe(1);
    expect(res.items[0].alert_id).toBe('alt_1');
  });

  it('handles structured API error responses gracefully', async () => {
    const errorPayload = {
      error: {
        code: 'NOT_FOUND',
        message: "Security alert 'alt_missing' was not found in the repository.",
        correlation_id: 'req_123',
        details: null,
      },
    };

    vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: false,
      status: 404,
      statusText: 'Not Found',
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => errorPayload,
    } as Response);

    await expect(api.getAlert('alt_missing')).rejects.toThrow(ApiError);

    try {
      await api.getAlert('alt_missing');
    } catch (e: unknown) {
      if (e instanceof ApiError) {
        expect(e.code).toBe('NOT_FOUND');
        expect(e.status).toBe(404);
        expect(e.correlationId).toBe('req_123');
      }
    }
  });

  it('handles network failure with descriptive NetworkError', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValueOnce(new Error('Connection refused'));

    await expect(api.getHealth()).rejects.toThrow('Unable to connect to backend service');
  });
});
