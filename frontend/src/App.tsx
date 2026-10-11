import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import type { NavTab } from './components/Navbar';
import { OverviewView } from './components/OverviewView';
import { AlertsView } from './components/AlertsView';
import { AlertDetailView } from './components/AlertDetailView';
import { SystemStatusView } from './components/SystemStatusView';
import { AboutView } from './components/AboutView';
import { ErrorBoundary } from './components/ErrorBoundary';
import { api } from './services/api';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<NavTab>('overview');
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [isConnected, setIsConnected] = useState<boolean>(true);

  // Periodic lightweight liveness check
  useEffect(() => {
    const checkConnection = async () => {
      try {
        const res = await api.getHealth();
        setIsConnected(res.status === 'ok');
      } catch {
        setIsConnected(false);
      }
    };

    checkConnection();
    const interval = setInterval(checkConnection, 20000); // 20s poll
    return () => clearInterval(interval);
  }, []);

  const handleSelectTab = (tab: NavTab) => {
    setActiveTab(tab);
    setSelectedAlertId(null);
  };

  const handleSelectAlert = (alertId: string) => {
    setSelectedAlertId(alertId);
  };

  const handleBackToAlerts = () => {
    setSelectedAlertId(null);
    setActiveTab('alerts');
  };

  const handleNavigateToAlertsWithFilter = (filter?: string) => {
    setSeverityFilter(filter || '');
    setSelectedAlertId(null);
    setActiveTab('alerts');
  };

  return (
    <div className="app-container">
      <Navbar
        activeTab={activeTab}
        onSelectTab={handleSelectTab}
        isConnected={isConnected}
      />

      <main className="main-content" id="main-content">
        {selectedAlertId ? (
          <ErrorBoundary
            fallbackTitle="Alert Inspection Error"
            onReset={handleBackToAlerts}
          >
            <AlertDetailView
              alertId={selectedAlertId}
              onBack={handleBackToAlerts}
            />
          </ErrorBoundary>
        ) : (
          <>
            {activeTab === 'overview' && (
              <OverviewView
                onSelectAlert={handleSelectAlert}
                onNavigateToAlerts={handleNavigateToAlertsWithFilter}
              />
            )}
            {activeTab === 'alerts' && (
              <AlertsView
                onSelectAlert={handleSelectAlert}
                initialSeverityFilter={severityFilter}
              />
            )}
            {activeTab === 'status' && <SystemStatusView />}
            {activeTab === 'about' && <AboutView />}
          </>
        )}
      </main>

      {/* Footer */}
      <footer
        style={{
          borderTop: '1px solid var(--border-subtle)',
          padding: '1.25rem 1.5rem',
          textAlign: 'center',
          fontSize: '0.75rem',
          color: 'var(--text-muted)',
          background: 'var(--bg-secondary)',
        }}
      >
        <div style={{ maxWidth: '1440px', margin: '0 auto', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
          <div>
            CYBER SENTINEL &copy; {new Date().getFullYear()} — AI-Powered Security Log Anomaly Detection & Investigation
          </div>
          <div className="mono">
            Backend API: <code>{api.getBaseUrl()}</code> | Local-First Architecture
          </div>
        </div>
      </footer>
    </div>
  );
};

export default App;
