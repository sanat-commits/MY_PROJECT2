/**
 * Centralized API Client for AI Security Operations Dashboard.
 * Interacts with the Phase 8 FastAPI backend.
 */

import type {
  HealthResponse,
  ReadinessResponse,
  ModelStatusResponse,
  PaginatedAlertsResponse,
  SecurityAlert,
  InvestigationResponse,
  ApiErrorResponse,
  SeverityLevel,
} from '../types';

export class ApiError extends Error {
  public code: string;
  public status: number;
  public correlationId?: string | null;
  public details?: unknown;

  constructor(
    message: string,
    status: number,
    code: string = 'API_ERROR',
    correlationId?: string | null,
    details?: unknown
  ) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.correlationId = correlationId;
    this.details = details;
  }
}

class ApiService {
  private baseUrl: string;

  constructor() {
    this.baseUrl = (
      import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000'
    ).replace(/\/+$/, '');
  }

  public getBaseUrl(): string {
    return this.baseUrl;
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;
    const headers = new Headers(options.headers || {});
    if (!headers.has('Accept')) {
      headers.set('Accept', 'application/json');
    }
    if (options.body && !headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json');
    }

    let response: Response;
    try {
      response = await fetch(url, { ...options, headers });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Network request failed';
      throw new ApiError(
        `Unable to connect to backend service at ${this.baseUrl}: ${msg}`,
        0,
        'NETWORK_ERROR'
      );
    }

    const contentType = response.headers.get('content-type') || '';
    const isJson = contentType.includes('application/json');

    if (!response.ok) {
      let errorCode = `HTTP_${response.status}`;
      let errorMessage = `Server returned status ${response.status} ${response.statusText}`;
      let correlationId: string | null = null;
      let details: unknown = null;

      if (isJson) {
        try {
          const errData = (await response.json()) as ApiErrorResponse;
          if (errData && errData.error) {
            errorCode = errData.error.code || errorCode;
            errorMessage = errData.error.message || errorMessage;
            correlationId = errData.error.correlation_id || null;
            details = errData.error.details || null;
          }
        } catch {
          // Fall back to HTTP status message
        }
      } else {
        try {
          const text = await response.text();
          if (text) errorMessage = text;
        } catch {
          // ignore
        }
      }

      throw new ApiError(errorMessage, response.status, errorCode, correlationId, details);
    }

    if (!isJson) {
      return (await response.text()) as unknown as T;
    }

    try {
      return (await response.json()) as T;
    } catch (err: unknown) {
      throw new ApiError(
        `Malformed JSON response from backend: ${err instanceof Error ? err.message : String(err)}`,
        response.status,
        'MALFORMED_RESPONSE'
      );
    }
  }

  // --- Health & Readiness Endpoints ---

  public async getHealth(): Promise<HealthResponse> {
    return this.request<HealthResponse>('/health');
  }

  public async getReadiness(): Promise<ReadinessResponse> {
    return this.request<ReadinessResponse>('/ready');
  }

  public async getModelStatus(): Promise<ModelStatusResponse> {
    return this.request<ModelStatusResponse>('/status/model');
  }

  // --- Alerts Endpoints ---

  public async getAlerts(params: {
    limit?: number;
    offset?: number;
    severity?: SeverityLevel | '';
    is_anomaly?: number;
  } = {}): Promise<PaginatedAlertsResponse> {
    const searchParams = new URLSearchParams();
    if (params.limit !== undefined) searchParams.append('limit', String(params.limit));
    if (params.offset !== undefined) searchParams.append('offset', String(params.offset));
    if (params.severity) searchParams.append('severity', params.severity);
    if (params.is_anomaly !== undefined) searchParams.append('is_anomaly', String(params.is_anomaly));

    const qs = searchParams.toString();
    const endpoint = `/alerts${qs ? `?${qs}` : ''}`;
    return this.request<PaginatedAlertsResponse>(endpoint);
  }

  public async getAlert(alertId: string): Promise<SecurityAlert> {
    return this.request<SecurityAlert>(`/alerts/${encodeURIComponent(alertId)}`);
  }

  // --- Investigation Endpoints ---

  public async investigateAlert(
    alertId: string,
    options: { correlation_id?: string; thread_id?: string } = {}
  ): Promise<InvestigationResponse> {
    return this.request<InvestigationResponse>(
      `/alerts/${encodeURIComponent(alertId)}/investigate`,
      {
        method: 'POST',
        body: JSON.stringify(options),
      }
    );
  }

  public async getInvestigation(investigationId: string): Promise<InvestigationResponse> {
    return this.request<InvestigationResponse>(
      `/investigations/${encodeURIComponent(investigationId)}`
    );
  }

  public async getInvestigations(params: { limit?: number; offset?: number } = {}): Promise<InvestigationResponse[]> {
    const searchParams = new URLSearchParams();
    if (params.limit !== undefined) searchParams.append('limit', String(params.limit));
    if (params.offset !== undefined) searchParams.append('offset', String(params.offset));

    const qs = searchParams.toString();
    return this.request<InvestigationResponse[]>(`/investigations${qs ? `?${qs}` : ''}`);
  }
}

export const api = new ApiService();
