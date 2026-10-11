import { Component } from 'react';
import type { ErrorInfo, ReactNode } from 'react';
import { AlertCircle, RefreshCw } from 'lucide-react';

interface Props {
  children: ReactNode;
  fallbackTitle?: string;
  onReset?: () => void;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('ErrorBoundary caught an unhandled rendering error:', error, errorInfo);
  }

  public handleReset = () => {
    this.setState({ hasError: false, error: null });
    if (this.props.onReset) {
      this.props.onReset();
    }
  };

  public render() {
    if (this.state.hasError) {
      return (
        <div style={{ padding: '2rem 1rem', maxWidth: '800px', margin: '0 auto' }}>
          <div className="card" style={{ border: '1px solid var(--sev-high)', background: 'var(--bg-secondary)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem', color: '#f87171' }}>
              <AlertCircle size={24} />
              <h2 style={{ fontSize: '1.25rem', fontWeight: 600 }}>
                {this.props.fallbackTitle || 'Component Render Error'}
              </h2>
            </div>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem', marginBottom: '1rem', lineHeight: 1.5 }}>
              An unexpected display error occurred while rendering this view. Your session data has been preserved.
            </p>
            {this.state.error && (
              <div
                className="mono"
                style={{
                  background: 'var(--bg-primary)',
                  padding: '0.75rem 1rem',
                  borderRadius: '6px',
                  fontSize: '0.75rem',
                  color: 'var(--text-muted)',
                  marginBottom: '1.25rem',
                  overflowX: 'auto',
                }}
              >
                {this.state.error.message}
              </div>
            )}
            <button className="btn btn-secondary" onClick={this.handleReset} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <RefreshCw size={15} />
              <span>Retry / Return</span>
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
