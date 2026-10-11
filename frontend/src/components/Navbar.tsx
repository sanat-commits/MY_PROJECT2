import React from 'react';
import { Shield, Activity, ListFilter, Server, Info } from 'lucide-react';

export type NavTab = 'overview' | 'alerts' | 'status' | 'about';

interface NavbarProps {
  activeTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  isConnected: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  onSelectTab,
  isConnected,
}) => {
  return (
    <header className="app-header">
      <div className="navbar">
        <div className="brand" onClick={() => onSelectTab('overview')} role="button" tabIndex={0}>
          <div className="brand-icon">
            <Shield size={24} color="#3b82f6" />
          </div>
          <div>
            <span>CYBER SENTINEL</span>
            <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem', marginLeft: '0.5rem', fontWeight: 400 }}>
              AI SOC Operations
            </span>
          </div>
        </div>

        <nav className="nav-links" aria-label="Main Navigation">
          <button
            className={`nav-btn ${activeTab === 'overview' ? 'active' : ''}`}
            onClick={() => onSelectTab('overview')}
            aria-current={activeTab === 'overview' ? 'page' : undefined}
          >
            <Activity size={16} />
            <span>Overview</span>
          </button>
          <button
            className={`nav-btn ${activeTab === 'alerts' ? 'active' : ''}`}
            onClick={() => onSelectTab('alerts')}
            aria-current={activeTab === 'alerts' ? 'page' : undefined}
          >
            <ListFilter size={16} />
            <span>Alerts</span>
          </button>
          <button
            className={`nav-btn ${activeTab === 'status' ? 'active' : ''}`}
            onClick={() => onSelectTab('status')}
            aria-current={activeTab === 'status' ? 'page' : undefined}
          >
            <Server size={16} />
            <span>System Status</span>
          </button>
          <button
            className={`nav-btn ${activeTab === 'about' ? 'active' : ''}`}
            onClick={() => onSelectTab('about')}
            aria-current={activeTab === 'about' ? 'page' : undefined}
          >
            <Info size={16} />
            <span>About</span>
          </button>
        </nav>

        <div className="header-badges">
          <span className="badge badge-demo" title="Data source is synthetic aggregated behavioral telemetry windows">
            Synthetic Demo Data
          </span>
          <span
            className={`badge ${isConnected ? 'badge-connected' : 'badge-disconnected'}`}
            title={isConnected ? 'Backend API connection active' : 'Disconnected from backend API'}
          >
            <span>{isConnected ? 'API Live' : 'API Offline'}</span>
          </span>
        </div>
      </div>
    </header>
  );
};
